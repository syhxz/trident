//! Connection registry (`registry`)
//!
//! `pool::PooledConnection` is deliberately metadata-only (node_id,
//! backend_pid, secret_key, pinned, dirty) and does not hold the actual
//! `TcpStream` -- see `pool::conn` module docs. This module provides the
//! glue the Proxy layer needs to associate pooled connection metadata with
//! its live socket:
//!
//! - `ConnectionRegistry`: a map from `(node_id, backend_pid)` to the
//!   underlying `TcpStream`, safe to use because the pool guarantees a given
//!   `PooledConnection` is never handed out to more than one caller at a
//!   time (so `take`/`insert` never race for the same key).
//! - `LiveConnFactory`: a `ConnFactory` that establishes a real physical
//!   connection and registers its socket.
//! - `DiscardAllCleaner`: a `ConnCleaner` that runs `DISCARD ALL` against the
//!   registered socket before a dirty connection is returned to the pool.
//! - `CancelRegistry`: implements correct single-instance handling of
//!   PostgreSQL `CancelRequest` (Requirements 7.1-7.3). It maps the cancel
//!   key a client was issued at Startup time (the `BackendKeyData` this
//!   *proxy* sent it, not the real backend's) to the session that holds
//!   it, and separately tracks which real backend connection (if any) that
//!   session currently has a query in flight against. A `CancelRequest` is
//!   only ever forwarded when both lookups succeed, matching PostgreSQL's
//!   semantics of silently ignoring stale/unknown cancel keys and CANCELs
//!   that arrive when the target session has no active query.
//! - `NodeAddress` + `send_cancel_request`: CANCEL requests must be sent to
//!   the backend over a brand-new TCP connection (never the session's
//!   existing connection), per the wire protocol spec.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::pool::conn::{establish_connection, ConnError, ConnectTarget, MaybeTlsStream, PooledConnection};
use crate::pool::pool::{ConnCleaner, ConnFactory, PoolError, DISCARD_ALL_STATEMENT};
use crate::protocol::message::{BackendMessage, FrontendMessage};
use crate::protocol::reader::read_backend_message;
use crate::protocol::writer::{encode_frontend_message, encode_query};

/// A backend socket wrapped in a `BufReader` to reduce read syscalls.
/// Multiple small protocol messages (BindComplete + CommandComplete +
/// ReadyForQuery) typically arrive in one TCP segment; without buffering,
/// each requires 3 separate `read_exact` syscalls. With an 8KB buffer,
/// a single syscall reads an entire response cycle from the kernel buffer.
///
/// `BufReader<MaybeTlsStream>` implements both `AsyncRead` (buffered) and
/// `AsyncWrite` (passed through directly to the inner stream).
pub type BackendStream = BufReader<MaybeTlsStream>;

const BACKEND_READ_BUF_SIZE: usize = 8 * 1024;

/// Maps `(node_id, backend_pid)` to the live `BackendStream` for that backend
/// connection. Uses a per-node generation counter to prevent stale handlers
/// from re-inserting sockets for nodes that have been dynamically removed
/// and re-added.
#[derive(Default)]
pub struct ConnectionRegistry {
    sockets: Mutex<HashMap<(String, i32), BackendStream>>,
    /// Per-node generation counter. Incremented on each `remove_by_node`.
    /// `allow_node` increments again so the new generation differs from
    /// any in-flight inserts that captured the pre-remove generation.
    /// Inserts carry a generation token and are rejected if it doesn't
    /// match the current generation for that node.
    node_generations: Mutex<HashMap<String, u64>>,
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        ConnectionRegistry {
            sockets: Mutex::new(HashMap::new()),
            node_generations: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the current generation for a node. Callers (ConnFactory)
    /// should capture this at connection-creation time and pass it back
    /// to `insert_with_generation` to ensure stale connections from a
    /// previous generation are rejected.
    pub fn node_generation(&self, node_id: &str) -> u64 {
        let gens = self.node_generations.lock();
        gens.get(node_id).copied().unwrap_or(0)
    }

    pub fn insert(&self, node_id: &str, backend_pid: i32, stream: BackendStream) {
        // Unconditional insert — used by code paths that don't track
        // generations (e.g. legacy or non-passthrough paths). For
        // generation-aware inserts, use `insert_with_generation`.
        let mut sockets = self.sockets.lock();
        sockets.insert((node_id.to_string(), backend_pid), stream);
    }

    /// Generation-aware insert. Rejects the socket if the node's current
    /// generation doesn't match the one captured at connection-creation
    /// time (meaning the node was removed and possibly re-added since).
    pub fn insert_with_generation(
        &self,
        node_id: &str,
        backend_pid: i32,
        stream: BackendStream,
        expected_generation: u64,
    ) {
        let gens = self.node_generations.lock();
        let current_gen = gens.get(node_id).copied().unwrap_or(0);
        if current_gen != expected_generation {
            tracing::debug!(
                node_id,
                backend_pid,
                current_gen,
                expected_generation,
                "rejecting socket insert for stale node generation"
            );
            return;
        }
        let mut sockets = self.sockets.lock();
        sockets.insert((node_id.to_string(), backend_pid), stream);
    }

    /// Wraps a raw `MaybeTlsStream` in a `BufReader` and inserts it into the
    /// registry. Used when a new physical connection is established.
    pub fn insert_raw(&self, node_id: &str, backend_pid: i32, stream: MaybeTlsStream) {
        self.insert(
            node_id,
            backend_pid,
            BufReader::with_capacity(BACKEND_READ_BUF_SIZE, stream),
        );
    }

    /// Generation-aware variant of `insert_raw`. Rejects the socket if the
    /// node's current generation doesn't match the expected generation
    /// (meaning the node was removed since this connection was initiated).
    pub fn insert_raw_with_generation(
        &self,
        node_id: &str,
        backend_pid: i32,
        stream: MaybeTlsStream,
        expected_generation: u64,
    ) {
        self.insert_with_generation(
            node_id,
            backend_pid,
            BufReader::with_capacity(BACKEND_READ_BUF_SIZE, stream),
            expected_generation,
        );
    }

    /// Removes and returns the socket for the given connection identity, if
    /// present. The caller is responsible for reinserting it via `insert`
    /// once finished using it (unless the connection is being discarded).
    pub fn take(&self, node_id: &str, backend_pid: i32) -> Option<BackendStream> {
        let mut sockets = self.sockets.lock();
        sockets.remove(&(node_id.to_string(), backend_pid))
    }

    /// Removes and drops the socket for the given connection identity
    /// (used when a connection is being discarded rather than reused).
    pub fn remove(&self, node_id: &str, backend_pid: i32) {
        let mut sockets = self.sockets.lock();
        sockets.remove(&(node_id.to_string(), backend_pid));
    }

    /// Removes and drops ALL sockets belonging to a given node and marks
    /// the node as removed. Subsequent `insert` calls for this node are
    /// silently rejected, preventing stale in-flight handlers from
    /// re-inserting sockets after a dynamic node removal.
    pub fn remove_by_node(&self, node_id: &str) {
        // Increment generation so any in-flight insert_with_generation
        // calls carrying the old generation are rejected.
        let mut gens = self.node_generations.lock();
        let gen = gens.entry(node_id.to_string()).or_insert(0);
        *gen += 1;
        // Purge all sockets for this node.
        let mut sockets = self.sockets.lock();
        sockets.retain(|(n, _), _| n != node_id);
    }

    /// Re-enables inserts for a node_id. Called when a node is
    /// dynamically (re-)added after having been previously removed.
    /// Increments generation again so stale handlers from the previous
    /// incarnation cannot pollute the re-added node.
    pub fn allow_node(&self, node_id: &str) {
        let mut gens = self.node_generations.lock();
        let gen = gens.entry(node_id.to_string()).or_insert(0);
        *gen += 1;
    }
}

/// `ConnFactory` that establishes a real physical connection to a backend
/// node and registers its socket in a shared `ConnectionRegistry`.
pub struct LiveConnFactory {
    pub target: ConnectTarget,
    pub registry: Arc<ConnectionRegistry>,
    /// The node generation at the time this factory was created. Used to
    /// prevent stale socket insertion after a node removal race: if the
    /// node was removed (generation incremented) while a connection was
    /// being established, the insert will be rejected.
    pub generation: u64,
}

impl ConnFactory for LiveConnFactory {
    async fn create(&self, node_id: &str) -> Result<PooledConnection, PoolError> {
        let (meta, stream) = establish_connection(node_id, &self.target)
            .await
            .map_err(conn_error_to_pool_error)?;
        self.registry.insert_raw_with_generation(
            node_id,
            meta.backend_pid,
            stream,
            self.generation,
        );
        Ok(meta)
    }
}

fn conn_error_to_pool_error(e: ConnError) -> PoolError {
    PoolError::ConnectFailed(e.to_string())
}

/// `ConnCleaner` that runs `DISCARD ALL` against the connection's registered
/// socket before it is returned to the pool's idle queue. Also supports
/// periodic validation of idle connections via a configurable check query.
pub struct DiscardAllCleaner {
    pub registry: Arc<ConnectionRegistry>,
    /// Query used to validate idle connections. Default: "SELECT 1".
    /// Set to empty string to disable validation.
    pub check_query: String,
}

impl DiscardAllCleaner {
    pub fn new(registry: Arc<ConnectionRegistry>) -> Self {
        DiscardAllCleaner {
            registry,
            check_query: "SELECT 1".to_string(),
        }
    }

    pub fn with_check_query(mut self, query: String) -> Self {
        self.check_query = query;
        self
    }
}

impl ConnCleaner for DiscardAllCleaner {
    async fn clean(&self, conn: &PooledConnection) -> Result<(), PoolError> {
        let mut stream = self
            .registry
            .take(&conn.node_id, conn.backend_pid)
            .ok_or_else(|| {
                PoolError::CleanupFailed("connection socket missing from registry".into())
            })?;

        // Capture the node generation before cleaning. If the node is
        // removed while DISCARD ALL is in flight, the generation will
        // advance and we'll drop the socket instead of re-inserting it
        // (preventing stale sockets from polluting a re-added node).
        let gen_before = self.registry.node_generation(&conn.node_id);

        let bytes = encode_query(DISCARD_ALL_STATEMENT);
        if let Err(e) = stream.write_all(&bytes).await {
            return Err(PoolError::CleanupFailed(e.to_string()));
        }
        if let Err(e) = stream.flush().await {
            return Err(PoolError::CleanupFailed(e.to_string()));
        }

        loop {
            match read_backend_message(&mut stream).await {
                Ok(BackendMessage::ReadyForQuery(_)) => break,
                Ok(_) => continue,
                Err(e) => return Err(PoolError::CleanupFailed(e.to_string())),
            }
        }

        self.registry.insert_with_generation(&conn.node_id, conn.backend_pid, stream, gen_before);
        Ok(())
    }

    async fn validate(&self, conn: &PooledConnection) -> Result<(), PoolError> {
        if self.check_query.is_empty() {
            return Ok(());
        }

        let mut stream = self
            .registry
            .take(&conn.node_id, conn.backend_pid)
            .ok_or_else(|| {
                PoolError::CleanupFailed("connection socket missing from registry for validation".into())
            })?;

        let gen_before = self.registry.node_generation(&conn.node_id);

        let bytes = encode_query(&self.check_query);
        if let Err(e) = stream.write_all(&bytes).await {
            // Socket is broken — don't put it back
            return Err(PoolError::CleanupFailed(e.to_string()));
        }
        if let Err(e) = stream.flush().await {
            return Err(PoolError::CleanupFailed(e.to_string()));
        }

        loop {
            match read_backend_message(&mut stream).await {
                Ok(BackendMessage::ReadyForQuery(_)) => break,
                Ok(BackendMessage::ErrorResponse(_)) => {
                    // Query failed but connection might still be usable;
                    // wait for ReadyForQuery before deciding.
                    continue;
                }
                Ok(_) => continue,
                Err(e) => {
                    // Connection is dead
                    return Err(PoolError::CleanupFailed(e.to_string()));
                }
            }
        }

        // Connection alive — put it back only if node wasn't removed
        self.registry.insert_with_generation(&conn.node_id, conn.backend_pid, stream, gen_before);
        Ok(())
    }

    fn discard(&self, conn: &PooledConnection) {
        self.registry.remove(&conn.node_id, conn.backend_pid);
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
}

impl CancelRegistry {
    pub fn new() -> Self {
        CancelRegistry {
            sessions_by_key: Mutex::new(HashMap::new()),
            active_backends: Mutex::new(HashMap::new()),
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
        let mut active = self.active_backends.lock();
        active.insert(
            session_id.to_string(),
            ActiveBackend {
                node_id: node_id.to_string(),
                backend_pid,
                secret_key,
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
    pub fn resolve_cancel_target(&self, backend_pid: i32, secret_key: i32) -> Option<(String, i32, i32)> {
        let session_id = {
            let sessions = self.sessions_by_key.lock();
            sessions.get(&(backend_pid, secret_key)).cloned()
        }?;
        let active = self.active_backends.lock();
        active
            .get(&session_id)
            .map(|a| (a.node_id.clone(), a.backend_pid, a.secret_key))
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
            .map_err(|_| std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "cancel request connect timed out",
            ))??
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
                prop_assert_eq!(resolved, Some(("writer".to_string(), 1, 2)));
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

    #[tokio::test]
    async fn take_returns_previously_inserted_socket() {
        let (a, _b) = connected_pair().await;
        let registry = ConnectionRegistry::new();
        registry.insert_raw("writer", 100, MaybeTlsStream::Plain(a));
        assert!(registry.take("writer", 100).is_some());
        // Second take should find nothing (already removed).
        assert!(registry.take("writer", 100).is_none());
    }

    #[tokio::test]
    async fn remove_drops_socket_without_returning_it() {
        let (a, _b) = connected_pair().await;
        let registry = ConnectionRegistry::new();
        registry.insert_raw("writer", 100, MaybeTlsStream::Plain(a));
        registry.remove("writer", 100);
        assert!(registry.take("writer", 100).is_none());
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
            Some(("writer".to_string(), 555, 666))
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
        let registry = Arc::new(ConnectionRegistry::new());
        registry.insert_raw("writer", 42, MaybeTlsStream::Plain(client_side));

        let cleaner = DiscardAllCleaner::new(registry.clone());
        let conn = PooledConnection::new("writer", 42, 999);

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

        let result = cleaner.clean(&conn).await;
        backend_task.await.unwrap();
        assert!(result.is_ok());
        // Socket should have been reinserted into the registry after cleanup.
        assert!(registry.take("writer", 42).is_some());
    }
}
