//! Connection registry (`registry`)
//!
//! Backend connection construction, cleanup, generation tracking, and cancel
//! routing support.
//!
//! Live sockets are owned by `pool::BackendConnection`; this module does not
//! maintain a socket map. `ConnectionRegistry` now tracks only low-frequency
//! per-node generations used to invalidate factories during dynamic node
//! replacement. `CancelRegistry` independently tracks PostgreSQL cancel keys.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::pool::conn::{establish_connection, BackendConnection, ConnError, ConnectTarget};
use crate::pool::pool::{ConnCleaner, ConnFactory, PoolError, DISCARD_ALL_STATEMENT};
use crate::protocol::message::{BackendMessage, FrontendMessage};
use crate::protocol::reader::read_backend_message;
use crate::protocol::writer::{encode_frontend_message, encode_query};

/// Low-frequency node generation tracker. Connections capture the generation
/// of the factory that created them; draining the old pool drops stale
/// connections instead of returning them to a replacement pool.
///
/// Reads (`node_generation`) are lock-free via `ArcSwap`; writes
/// (`remove_by_node`, `allow_node`) are serialized by a `Mutex` that
/// publishes a new snapshot after mutation.
pub struct ConnectionRegistry {
    /// Serializes mutations. The `Mutex` is only held during the infrequent
    /// write operations (node add/remove), never on the query hot path.
    write_lock: Mutex<HashMap<String, u64>>,
    /// Lock-free read snapshot. Updated atomically after each mutation.
    snapshot: ArcSwap<HashMap<String, u64>>,
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self {
            write_lock: Mutex::new(HashMap::new()),
            snapshot: ArcSwap::from_pointee(HashMap::new()),
        }
    }
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current generation for a node. Lock-free hot-path read.
    pub fn node_generation(&self, node_id: &str) -> u64 {
        self.snapshot.load().get(node_id).copied().unwrap_or(0)
    }

    /// Invalidates factories and connections from the current incarnation.
    pub fn remove_by_node(&self, node_id: &str) {
        let mut generations = self.write_lock.lock();
        *generations.entry(node_id.to_string()).or_insert(0) += 1;
        self.snapshot.store(Arc::new(generations.clone()));
    }

    /// Starts a new node incarnation and returns its generation token.
    pub fn allow_node(&self, node_id: &str) -> u64 {
        let mut generations = self.write_lock.lock();
        let generation = generations.entry(node_id.to_string()).or_insert(0);
        *generation += 1;
        let result = *generation;
        self.snapshot.store(Arc::new(generations.clone()));
        result
    }
}

/// `ConnFactory` that establishes and returns a complete backend connection.
pub struct LiveConnFactory {
    pub target: ConnectTarget,
    pub generation: u64,
}

impl ConnFactory for LiveConnFactory {
    async fn create(&self, node_id: &str) -> Result<BackendConnection, PoolError> {
        let (meta, stream) = establish_connection(node_id, &self.target)
            .await
            .map_err(conn_error_to_pool_error)?;
        Ok(BackendConnection::new(meta, stream, self.generation))
    }
}

fn conn_error_to_pool_error(e: ConnError) -> PoolError {
    PoolError::ConnectFailed(e.to_string())
}

/// `ConnCleaner` that operates directly on the socket owned by a pooled
/// `BackendConnection`.
pub struct DiscardAllCleaner {
    /// Query used to validate idle connections. Default: "SELECT 1".
    /// Set to empty string to disable validation.
    pub check_query: String,
}

impl DiscardAllCleaner {
    pub fn new() -> Self {
        DiscardAllCleaner {
            check_query: "SELECT 1".to_string(),
        }
    }

    pub fn with_check_query(mut self, query: String) -> Self {
        self.check_query = query;
        self
    }
}

impl Default for DiscardAllCleaner {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnCleaner for DiscardAllCleaner {
    async fn clean(&self, conn: &mut BackendConnection) -> Result<(), PoolError> {
        let bytes = encode_query(DISCARD_ALL_STATEMENT);
        conn.stream
            .write_all(&bytes)
            .await
            .map_err(|error| PoolError::CleanupFailed(error.to_string()))?;
        conn.stream
            .flush()
            .await
            .map_err(|error| PoolError::CleanupFailed(error.to_string()))?;

        loop {
            match read_backend_message(&mut conn.stream).await {
                Ok(BackendMessage::ReadyForQuery(_)) => break,
                Ok(BackendMessage::ErrorResponse(error)) => {
                    return Err(PoolError::CleanupFailed(
                        error.message().unwrap_or("DISCARD ALL failed").to_string(),
                    ));
                }
                Ok(_) => continue,
                Err(error) => return Err(PoolError::CleanupFailed(error.to_string())),
            }
        }

        conn.current_application_name = None;
        Ok(())
    }

    async fn validate(&self, conn: &mut BackendConnection) -> Result<(), PoolError> {
        if self.check_query.is_empty() {
            return Ok(());
        }

        let bytes = encode_query(&self.check_query);
        conn.stream
            .write_all(&bytes)
            .await
            .map_err(|error| PoolError::CleanupFailed(error.to_string()))?;
        conn.stream
            .flush()
            .await
            .map_err(|error| PoolError::CleanupFailed(error.to_string()))?;

        let mut query_error = None;
        loop {
            match read_backend_message(&mut conn.stream).await {
                Ok(BackendMessage::ReadyForQuery(_)) => break,
                Ok(BackendMessage::ErrorResponse(error)) => {
                    query_error = Some(
                        error
                            .message()
                            .unwrap_or("validation query failed")
                            .to_string(),
                    );
                }
                Ok(_) => continue,
                Err(error) => return Err(PoolError::CleanupFailed(error.to_string())),
            }
        }

        match query_error {
            Some(error) => Err(PoolError::CleanupFailed(error)),
            None => Ok(()),
        }
    }
}

/// Network address of a backend node, used exclusively for opening the
/// brand-new TCP connection a `CancelRequest` must be sent over (per the
/// wire protocol spec, it must never reuse the connection whose query is
/// being cancelled). Kept distinct from `pool::conn::ConnectTarget`, which
/// also carries database/username needed for a full Startup handshake that
/// a CancelRequest does not perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAddress {
    pub host: String,
    pub port: u16,
}

/// The real backend connection a session currently has a query in flight
/// against.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveBackend {
    node_id: String,
    backend_pid: i32,
    secret_key: i32,
    /// Monotonically increasing generation that distinguishes successive
    /// queries on the same session+backend_pid, preventing ABA cancellation.
    generation: u64,
}

/// Implements correct single-instance handling of PostgreSQL `CancelRequest`
/// (Requirements 7.1-7.3).
///
/// Two pieces of state are tracked:
/// - which client session owns a given cancel key -- the `(backend_pid,
///   secret_key)` pair *this proxy* handed the client in its own
///   `BackendKeyData` at Startup time (not the real backend's own key);
/// - which real backend connection (if any) that session currently has a
///   query in flight against.
///
/// `resolve_cancel_target` only returns a forwarding target when both
/// lookups succeed, which gives the correct PostgreSQL semantics: an
/// unknown/stale cancel key is ignored, and a CANCEL that arrives while the
/// target session has no active query in flight is also ignored (there is
/// nothing to cancel, and forwarding it could race with -- and incorrectly
/// cancel -- a later, unrelated query on a reused pooled connection).
#[derive(Default)]
pub struct CancelRegistry {
    /// (proxy-issued backend_pid, secret_key) -> session_id.
    sessions_by_key: Mutex<HashMap<(i32, i32), String>>,
    /// session_id -> the real backend connection it is currently waiting
    /// on a response from, if any.
    active_backends: Mutex<HashMap<String, ActiveBackend>>,
    /// Monotonically increasing counter — each `mark_active` call gets a
    /// unique generation so that `verify_cancel_target` can detect ABA
    /// (same session+pid reused for a different query).
    generation_counter: AtomicU64,
}

impl CancelRegistry {
    pub fn new() -> Self {
        CancelRegistry {
            sessions_by_key: Mutex::new(HashMap::new()),
            active_backends: Mutex::new(HashMap::new()),
            generation_counter: AtomicU64::new(0),
        }
    }

    /// Registers the cancel key issued to a client in its `BackendKeyData`
    /// at Startup time, so a later `CancelRequest` bearing that key can be
    /// attributed to `session_id`.
    pub fn register_session(&self, backend_pid: i32, secret_key: i32, session_id: &str) {
        let mut sessions = self.sessions_by_key.lock();
        sessions.insert((backend_pid, secret_key), session_id.to_string());
    }

    /// Removes a session's cancel-key mapping and any active-backend
    /// record. Must be called when the client connection closes, so a
    /// CANCEL bearing a stale key from a since-closed session is never
    /// forwarded.
    pub fn unregister_session(&self, backend_pid: i32, secret_key: i32) {
        let session_id = {
            let mut sessions = self.sessions_by_key.lock();
            sessions.remove(&(backend_pid, secret_key))
        };
        if let Some(session_id) = session_id {
            let mut active = self.active_backends.lock();
            active.remove(&session_id);
        }
    }

    /// Marks that `session_id` now has a query in flight against the given
    /// real backend connection (identified by the real `node_id` and the
    /// real backend's own `backend_pid`/`secret_key`, as returned by
    /// `establish_connection` -- distinct from the proxy-issued cancel key).
    pub fn mark_active(&self, session_id: &str, node_id: &str, backend_pid: i32, secret_key: i32) {
        let generation = self.generation_counter.fetch_add(1, Ordering::Relaxed);
        let mut active = self.active_backends.lock();
        active.insert(
            session_id.to_string(),
            ActiveBackend {
                node_id: node_id.to_string(),
                backend_pid,
                secret_key,
                generation,
            },
        );
    }

    /// Clears the active-backend record for `session_id` (its in-flight
    /// query has completed, so a CANCEL arriving after this point has
    /// nothing to cancel and must be ignored).
    pub fn clear_active(&self, session_id: &str) {
        let mut active = self.active_backends.lock();
        active.remove(session_id);
    }

    /// Resolves a `CancelRequest`'s `(backend_pid, secret_key)` -- the
    /// proxy-issued cancel key -- to the real backend connection it should
    /// be forwarded to: `(node_id, real_backend_pid, real_secret_key)`.
    /// Returns `None` if the cancel key is unknown, or if the session it
    /// maps to currently has no active query in flight.
    ///
    /// FIX (TOCTOU): Also returns the session_id so the caller can
    /// re-verify the target is still active after establishing the cancel
    /// connection but before sending the cancel bytes.
    pub fn resolve_cancel_target(
        &self,
        backend_pid: i32,
        secret_key: i32,
    ) -> Option<(String, i32, i32, String, u64)> {
        let session_id = {
            let sessions = self.sessions_by_key.lock();
            sessions.get(&(backend_pid, secret_key)).cloned()
        }?;
        let active = self.active_backends.lock();
        active.get(&session_id).map(|a| {
            (
                a.node_id.clone(),
                a.backend_pid,
                a.secret_key,
                session_id.clone(),
                a.generation,
            )
        })
    }

    /// Re-verifies that the given session still has an active query targeting
    /// the specified backend_pid at the expected generation. Returns false if
    /// the target has changed (connection was released/reassigned) or if a
    /// new query has started (ABA scenario).
    pub fn verify_cancel_target(
        &self,
        session_id: &str,
        expected_pid: i32,
        expected_generation: u64,
    ) -> bool {
        let active = self.active_backends.lock();
        active
            .get(session_id)
            .map(|a| a.backend_pid == expected_pid && a.generation == expected_generation)
            .unwrap_or(false)
    }
}

/// Sends a `CancelRequest` to `addr` over a brand-new TCP connection, as
/// required by the wire protocol (a CancelRequest must never be sent over
/// the connection whose query is being cancelled). PostgreSQL does not
/// send any response to a CancelRequest and closes the connection
/// immediately after reading it, so this returns as soon as the request
/// bytes have been written; a failed CANCEL (e.g. the node is unreachable)
/// is not a client-visible error and is left for the caller to log.
pub async fn send_cancel_request(
    addr: &NodeAddress,
    backend_pid: i32,
    secret_key: i32,
) -> Result<(), std::io::Error> {
    send_cancel_request_with_timeout(addr, backend_pid, secret_key, std::time::Duration::ZERO).await
}

/// Send a cancel request with an optional connect timeout.
/// Duration::ZERO means no timeout (wait indefinitely).
pub async fn send_cancel_request_with_timeout(
    addr: &NodeAddress,
    backend_pid: i32,
    secret_key: i32,
    connect_timeout: std::time::Duration,
) -> Result<(), std::io::Error> {
    let connect_fut = TcpStream::connect((addr.host.as_str(), addr.port));
    let mut stream = if connect_timeout.is_zero() {
        connect_fut.await?
    } else {
        tokio::time::timeout(connect_timeout, connect_fut)
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "cancel request connect timed out",
                )
            })??
    };
    let bytes = encode_frontend_message(&FrontendMessage::CancelRequest {
        backend_pid,
        secret_key,
    });
    stream.write_all(&bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::conn::{MaybeTlsStream, PooledConnection};
    use proptest::prelude::*;
    use tokio::net::TcpListener;

    // -----------------------------------------------------------------
    // Property: a CANCEL is forwarded if and only if its key is
    // registered to some session AND that session currently has an
    // active query, in which case it resolves to exactly that session's
    // active backend. Validates: Requirements 7.2, 7.3.
    // -----------------------------------------------------------------
    proptest! {
        #[test]
        fn property_cancel_resolves_iff_key_known_and_session_active(
            backend_pid in 1i32..10_000,
            secret_key in 1i32..10_000,
            session_id in "[a-z0-9]{1,10}",
            has_registration: bool,
            has_active_query: bool,
        ) {
            let registry = CancelRegistry::new();
            if has_registration {
                registry.register_session(backend_pid, secret_key, &session_id);
            }
            if has_active_query {
                registry.mark_active(&session_id, "writer", 1, 2);
            }

            let resolved = registry.resolve_cancel_target(backend_pid, secret_key);
            let expected_forward = has_registration && has_active_query;
            prop_assert_eq!(resolved.is_some(), expected_forward);
            if expected_forward {
                prop_assert_eq!(resolved, Some(("writer".to_string(), 1, 2, session_id.clone(), 0)));
            }
        }
    }

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_fut = TcpStream::connect(addr);
        let (accept_result, connect_result) = tokio::join!(listener.accept(), connect_fut);
        (accept_result.unwrap().0, connect_result.unwrap())
    }

    #[test]
    fn node_generation_advances_when_allowed_and_removed() {
        let registry = ConnectionRegistry::new();
        assert_eq!(registry.node_generation("writer"), 0);
        assert_eq!(registry.allow_node("writer"), 1);
        registry.remove_by_node("writer");
        assert_eq!(registry.node_generation("writer"), 2);
    }

    #[test]
    fn cancel_registry_ignores_unknown_key() {
        let registry = CancelRegistry::new();
        assert_eq!(registry.resolve_cancel_target(1, 2), None);
    }

    #[test]
    fn cancel_registry_ignores_session_with_no_active_query() {
        let registry = CancelRegistry::new();
        registry.register_session(1, 2, "session-a");
        // Known key, but the session has never marked a query active.
        assert_eq!(registry.resolve_cancel_target(1, 2), None);
    }

    #[test]
    fn cancel_registry_resolves_active_query_to_real_backend() {
        let registry = CancelRegistry::new();
        registry.register_session(1, 2, "session-a");
        registry.mark_active("session-a", "writer", 555, 666);

        assert_eq!(
            registry.resolve_cancel_target(1, 2),
            Some(("writer".to_string(), 555, 666, "session-a".to_string(), 0))
        );
    }

    #[test]
    fn cancel_registry_ignores_after_clear_active() {
        let registry = CancelRegistry::new();
        registry.register_session(1, 2, "session-a");
        registry.mark_active("session-a", "writer", 555, 666);
        registry.clear_active("session-a");

        assert_eq!(registry.resolve_cancel_target(1, 2), None);
    }

    #[test]
    fn cancel_registry_ignores_after_unregister_session() {
        let registry = CancelRegistry::new();
        registry.register_session(1, 2, "session-a");
        registry.mark_active("session-a", "writer", 555, 666);
        registry.unregister_session(1, 2);

        assert_eq!(registry.resolve_cancel_target(1, 2), None);
    }

    #[tokio::test]
    async fn send_cancel_request_writes_expected_bytes_to_a_fresh_connection() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let node_addr = NodeAddress {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
        };

        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            socket.read_exact(&mut buf).await.unwrap();
            buf
        });

        send_cancel_request(&node_addr, 4242, 9999).await.unwrap();
        let received = server_task.await.unwrap();

        let expected = encode_frontend_message(&FrontendMessage::CancelRequest {
            backend_pid: 4242,
            secret_key: 9999,
        });
        assert_eq!(received.to_vec(), expected);
    }

    #[tokio::test]
    async fn discard_all_cleaner_sends_query_and_awaits_ready_for_query() {
        use crate::protocol::message::TransactionStatus;
        use tokio::io::AsyncReadExt;

        let (client_side, mut backend_side) = connected_pair().await;
        let cleaner = DiscardAllCleaner::new();
        let mut conn = BackendConnection::new(
            PooledConnection::new("writer", 42, 999),
            MaybeTlsStream::Plain(client_side),
            7,
        );
        conn.current_application_name = Some("client-a".to_string());

        let backend_task = tokio::spawn(async move {
            // Consume whatever bytes the cleaner sent (the DISCARD ALL Query
            // message) without needing to parse them, then reply with
            // ReadyForQuery so `clean` can complete.
            let mut buf = [0u8; 256];
            let _ = backend_side.read(&mut buf).await;

            let ready = crate::protocol::writer::encode_backend_message(
                &BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            );
            backend_side.write_all(&ready).await.unwrap();
        });

        let result = cleaner.clean(&mut conn).await;
        backend_task.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(conn.current_application_name, None);
    }
}
