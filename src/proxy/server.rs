//! TCP server (`server`)
//!
//! `ProxyServer::run` listens on `listen_addr`, caps the number of
//! concurrently accepted clients at `max_clients`, and spawns one
//! `tokio::task` per accepted connection to run `ConnectionHandler::handle`.
//! A panic inside a per-connection task is caught via the task's
//! `JoinHandle` (which surfaces panics through `JoinError`) and logged
//! without affecting the listener loop or other in-flight connections
//! (Requirement 13.4, 13.5).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use arc_swap::ArcSwap;
use tokio::io::{AsyncRead, AsyncWrite, BufReader, BufWriter, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::config::{ConsistencyLevel, LsnTrackingConfig};
use crate::pool::manager::PoolManager;
use crate::protocol::startup::StartupHandler;
use crate::proxy::client_stats::ClientStats;
use crate::proxy::handler::{ConnectionHandler, QueryLogSettings, RouteFn};
use crate::proxy::registry::{CancelRegistry, ConnectionRegistry, NodeAddress};
use crate::session::lsn::LsnTracker;

/// A client-facing stream that is either plaintext or TLS-encrypted.
/// Unlike `pool::conn::MaybeTlsStream` (which wraps *client*-side TLS for
/// backend connections), this wraps *server*-side TLS for client connections.
#[derive(Debug)]
pub enum ClientStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            ClientStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ClientStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            ClientStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientStream::Plain(s) => Pin::new(s).poll_flush(cx),
            ClientStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            ClientStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Errors that can prevent the server from starting or accepting connections.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("failed to bind listener on {addr}: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to accept incoming connection: {0}")]
    Accept(#[source] std::io::Error),
}

/// The set of dependencies shared (behind `Arc`) across every connection
/// task spawned by `ProxyServer::run`. Bundled into one struct (rather than
/// passed as individual parameters) purely to keep `run`/`spawn_connection`
/// signatures manageable as the shared state has grown to include CANCEL
/// support (Requirements 7.1-7.3) alongside the original routing/pooling
/// dependencies. Cheap to `Clone` since every field is an `Arc`.
pub struct ProxyDeps<RTR, PM, LSN> {
    pub router: Arc<RTR>,
    pub pool_manager: Arc<PM>,
    pub lsn_tracker: Arc<LSN>,
    pub connection_registry: Arc<ConnectionRegistry>,
    pub cancel_registry: Arc<CancelRegistry>,
    pub node_addresses: Arc<ArcSwap<HashMap<String, NodeAddress>>>,
    /// The default consistency level assigned to a session at connection
    /// time (`routing.default_consistency`). Held behind an `ArcSwap`
    /// rather than a plain value so it can be hot-reloaded (see
    /// `trident::reload`): each newly accepted connection reads whatever
    /// value is current at that moment. Already-established sessions are
    /// unaffected (a session's consistency level is fixed once assigned,
    /// same as before this field became hot-reloadable -- clients can
    /// still override it per-session via `SET trident.consistency = ...`
    /// regardless).
    pub default_consistency: Arc<ArcSwap<ConsistencyLevel>>,
    /// Per-client-IP connection accounting (see `proxy::client_stats`
    /// module docs). Cheap, always-on alternative to full query audit
    /// logging for answering "how many connections does each client IP
    /// have". Not optional: unlike `admin`/audit logging, tracking this
    /// costs one `Mutex` lock per accept/disconnect, not per query, so
    /// there is no meaningful "disable" case worth plumbing through.
    pub client_stats: Arc<ClientStats>,
    /// Per-statement query logging / slow-query threshold behavior (see
    /// `handler::QueryLogSettings` docs). Plain `Copy` value, not an
    /// `Arc`/`ArcSwap` -- `config.logging.query_log`/`slow_query` are not
    /// part of the hot-reloadable settings set (see `trident::reload`
    /// module docs for what is/isn't hot-reloadable), so this is fixed
    /// for the lifetime of the process, same as `proxy.listen_addr`.
    pub query_log: QueryLogSettings,
    /// Restart-only LSN acquisition / Aurora write-forwarding strategy.
    pub lsn_tracking: LsnTrackingConfig,
    /// Ring buffer of recent slow queries, shared with the admin console's
    /// `/api/slow-queries` endpoint. Always present; pushes are only a
    /// mutex lock + VecDeque insert on statements that already crossed the
    /// slow-query threshold, so there is no meaningful "disabled" case.
    pub slow_queries: Arc<crate::admin::SlowQueryBuffer>,
    /// Optional TLS acceptor for client-facing encryption. When `Some`,
    /// the server responds `S` to SSLRequest and upgrades the connection
    /// to TLS before proceeding with the startup handshake. When `None`,
    /// SSLRequest is rejected with `N` (plaintext only).
    pub tls_acceptor: Option<Arc<TlsAcceptor>>,
    /// Startup handshake timeout. Zero = disabled.
    pub startup_timeout: std::time::Duration,
    /// Client idle timeout (no messages received). Zero = disabled.
    pub client_idle_timeout: std::time::Duration,
    /// Cancel request TCP connect timeout. Zero = disabled.
    pub cancel_connect_timeout: std::time::Duration,
}

impl<RTR, PM, LSN> Clone for ProxyDeps<RTR, PM, LSN> {
    fn clone(&self) -> Self {
        ProxyDeps {
            router: self.router.clone(),
            pool_manager: self.pool_manager.clone(),
            lsn_tracker: self.lsn_tracker.clone(),
            connection_registry: self.connection_registry.clone(),
            cancel_registry: self.cancel_registry.clone(),
            node_addresses: self.node_addresses.clone(),
            default_consistency: self.default_consistency.clone(),
            client_stats: self.client_stats.clone(),
            query_log: self.query_log,
            lsn_tracking: self.lsn_tracking.clone(),
            slow_queries: self.slow_queries.clone(),
            tls_acceptor: self.tls_acceptor.clone(),
            startup_timeout: self.startup_timeout,
            client_idle_timeout: self.client_idle_timeout,
            cancel_connect_timeout: self.cancel_connect_timeout,
        }
    }
}

/// TCP listener that accepts client connections and dispatches each one to
/// a dedicated `tokio::task` running `ConnectionHandler::handle`.
pub struct ProxyServer {
    pub listen_addr: SocketAddr,
    pub max_clients: usize,
}

impl ProxyServer {
    pub fn new(listen_addr: SocketAddr, max_clients: usize) -> Self {
        ProxyServer {
            listen_addr,
            max_clients,
        }
    }

    /// Binds the listener and runs the accept loop until an unrecoverable
    /// error occurs (e.g. the listener socket itself fails). Each accepted
    /// connection is handled on its own spawned task, so a slow or
    /// misbehaving client never blocks other clients, and a panic inside
    /// one connection's task (surfaced via `JoinHandle::await` as a
    /// `JoinError`) is caught and logged without affecting the accept loop
    /// or any other connection.
    ///
    /// `deps` bundles everything shared (behind `Arc`) across all spawned
    /// connection tasks; `make_startup_handler` produces a fresh
    /// `StartupHandler` instance per connection (most implementations, such
    /// as `TrustStartupHandler`, are cheap to construct and must not be
    /// shared mutably across concurrent connections).
    pub async fn run<RTR, PM, LSN, SH, F>(
        &self,
        deps: ProxyDeps<RTR, PM, LSN>,
        make_startup_handler: F,
    ) -> Result<(), ServerError>
    where
        RTR: RouteFn + Send + Sync + 'static,
        PM: PoolManager + Send + Sync + 'static,
        LSN: LsnTracker + Send + Sync + 'static,
        SH: StartupHandler + Send + 'static,
        F: Fn() -> SH + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .map_err(|source| ServerError::Bind {
                addr: self.listen_addr.to_string(),
                source,
            })?;

        let active_clients = Arc::new(AtomicUsize::new(0));
        let max_clients = self.max_clients;
        let make_startup_handler = Arc::new(make_startup_handler);
        let mut next_session_seq: u64 = 0;

        loop {
            let (stream, peer_addr) = listener.accept().await.map_err(ServerError::Accept)?;

            // Disable Nagle's algorithm: a proxy forwards many small
            // messages (ReadyForQuery is ~6 bytes) and must not introduce
            // 40ms coalescing delays between request-response pairs.
            let _ = stream.set_nodelay(true);

            if active_clients.load(Ordering::SeqCst) >= max_clients {
                // Requirement 12.1 (max_clients): reject new connections
                // once the configured limit is reached, without disrupting
                // already-accepted clients. Politely close the socket.
                drop(stream);
                metrics::counter!("trident_connections_rejected_total").increment(1);
                tracing::warn!(
                    peer = %peer_addr,
                    "rejecting new connection: max_clients limit reached"
                );
                continue;
            }

            next_session_seq += 1;
            let session_id = format!("session-{next_session_seq}-{peer_addr}");

            active_clients.fetch_add(1, Ordering::SeqCst);
            metrics::counter!("trident_connections_accepted_total").increment(1);
            metrics::gauge!("trident_active_connections").set(active_clients.load(Ordering::SeqCst) as f64);

            // Per-client-IP accounting (see `proxy::client_stats`). Only
            // the IP is tracked, not the port, since the port is
            // ephemeral per-connection and would defeat "how many
            // connections does this client have" aggregation.
            let client_ip = peer_addr.ip();
            if deps.client_stats.record_connect(client_ip) {
                metrics::counter!("trident_client_stats_evictions_total").increment(1);
            }
            metrics::gauge!("trident_client_distinct_active_ips")
                .set(deps.client_stats.distinct_active_ip_count() as f64);

            let default_consistency = **deps.default_consistency.load();
            let join_handle = spawn_connection(
                deps.clone(),
                stream,
                make_startup_handler(),
                session_id.clone(),
                default_consistency,
            );

            let active_clients_for_task = active_clients.clone();
            let client_stats_for_task = deps.client_stats.clone();
            tokio::spawn(async move {
                // Awaiting the JoinHandle surfaces a panic inside the
                // connection task as a `JoinError` rather than propagating
                // it, so a bug while handling one client can never crash
                // the proxy process or affect other connections
                // (Requirement 13.4).
                match join_handle.await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        metrics::counter!("trident_connections_errored_total").increment(1);
                        tracing::warn!(session = %session_id, error = %e, "connection handler exited with error");
                    }
                    Err(join_error) => {
                        metrics::counter!("trident_connections_panicked_total").increment(1);
                        tracing::error!(session = %session_id, error = %join_error, "connection handler task panicked");
                    }
                }
                let remaining = active_clients_for_task.fetch_sub(1, Ordering::SeqCst) - 1;
                metrics::gauge!("trident_active_connections").set(remaining as f64);

                client_stats_for_task.record_disconnect(client_ip);
                metrics::gauge!("trident_client_distinct_active_ips")
                    .set(client_stats_for_task.distinct_active_ip_count() as f64);
            });
        }
    }
}

/// Spawns a single connection-handling task and returns its `JoinHandle`.
/// If the handler panics, the panic is captured by `tokio::spawn` and
/// surfaced to the caller as a `JoinError` when the handle is awaited,
/// rather than unwinding into (and terminating) the rest of the process.
pub fn spawn_connection<RTR, PM, LSN, SH>(
    deps: ProxyDeps<RTR, PM, LSN>,
    stream: TcpStream,
    mut startup_handler: SH,
    session_id: String,
    default_consistency: ConsistencyLevel,
) -> tokio::task::JoinHandle<Result<(), crate::proxy::error::ProxyError>>
where
    RTR: RouteFn + Send + Sync + 'static,
    PM: PoolManager + Send + Sync + 'static,
    LSN: LsnTracker + Send + Sync + 'static,
    SH: StartupHandler + Send + 'static,
{
    tokio::spawn(async move {
        // --- Client TLS negotiation ---
        //
        // PostgreSQL clients probe encryption by sending an SSLRequest (8 bytes)
        // before the real StartupMessage. If we have a TLS acceptor configured,
        // respond `S` and upgrade; otherwise respond `N` and continue plaintext.
        //
        // This must happen on the raw TcpStream BEFORE buffering, because the
        // TLS handshake wraps the entire stream.
        //
        // Apply startup_timeout to the TLS negotiation phase. A client that
        // connects but never sends data (or stalls during TLS handshake)
        // should not occupy a slot indefinitely.
        let client_stream = if deps.startup_timeout.is_zero() {
            negotiate_client_tls(stream, deps.tls_acceptor.as_deref()).await?
        } else {
            tokio::time::timeout(deps.startup_timeout, negotiate_client_tls(stream, deps.tls_acceptor.as_deref()))
                .await
                .map_err(|_| crate::proxy::error::ProxyError::Protocol(
                    crate::protocol::ProtocolError::Malformed("startup timeout exceeded during TLS negotiation".into())
                ))??
        };

        // Load the current node address snapshot for this connection's
        // lifetime. Dynamic add/remove updates the ArcSwap, so new
        // connections see the latest addresses. Existing connections use
        // their snapshot (cancel routing to removed nodes is benign).
        let node_addresses_snapshot = deps.node_addresses.load();
        let handler = ConnectionHandler::with_query_log(
            deps.router.as_ref(),
            deps.pool_manager.as_ref(),
            deps.lsn_tracker.as_ref(),
            deps.connection_registry.as_ref(),
            deps.cancel_registry.as_ref(),
            node_addresses_snapshot.as_ref(),
            deps.query_log,
        )
        .with_lsn_tracking(deps.lsn_tracking.clone())
        .with_slow_query_buffer(deps.slow_queries.clone())
        .with_timeouts(deps.cancel_connect_timeout, deps.client_idle_timeout)
        .with_startup_timeout(deps.startup_timeout);
        // Wrap the client socket in BufReader+BufWriter so:
        // - Reads are buffered: multiple small protocol messages (Bind +
        //   Execute + Sync) typically arrive in one TCP segment but would
        //   otherwise require 3 read_exact syscalls each. With an 8KB
        //   buffer, one syscall fills the buffer for many messages.
        // - Writes are buffered: multiple small responses (RowDescription +
        //   DataRow(s) + CommandComplete + ReadyForQuery) are coalesced
        //   into fewer TCP segments. Flushed at each ReadyForQuery boundary.
        let buffered_stream = BufReader::with_capacity(
            8 * 1024,
            BufWriter::with_capacity(32 * 1024, client_stream),
        );
        handler
            .handle(buffered_stream, &mut startup_handler, session_id, default_consistency)
            .await
    })
}

/// Performs the PostgreSQL SSL negotiation on a raw TCP stream.
///
/// The first message from a client may be an SSLRequest (code 80877103).
/// If so, and we have a TLS acceptor, we respond `S` and upgrade.
/// If no TLS acceptor, we respond `N` and continue plaintext.
/// If the first message is NOT an SSLRequest (it's a regular Startup or
/// CancelRequest), we return the stream as-is (the handler will parse it).
///
/// PostgreSQL wire protocol guarantees: SSLRequest is always exactly 8 bytes
/// (4-byte length=8, 4-byte code=80877103). A regular StartupMessage has
/// the same structure but code=196608 (3.0). We peek the first 8 bytes.
async fn negotiate_client_tls(
    mut stream: TcpStream,
    tls_acceptor: Option<&TlsAcceptor>,
) -> Result<ClientStream, crate::proxy::error::ProxyError> {
    use crate::protocol::ProtocolError;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Peek at the first 8 bytes to check if it's an SSLRequest.
    // Use MSG_PEEK so the bytes remain in the kernel buffer for the handler
    // if this is NOT an SSLRequest.
    let mut peek_buf = [0u8; 8];
    let n = stream.peek(&mut peek_buf).await.map_err(|e| {
        crate::proxy::error::ProxyError::Protocol(ProtocolError::Io(e))
    })?;

    if n < 8 {
        // Not enough data for any valid startup packet — let the handler
        // deal with the short read / EOF.
        return Ok(ClientStream::Plain(stream));
    }

    let length = i32::from_be_bytes([peek_buf[0], peek_buf[1], peek_buf[2], peek_buf[3]]);
    let code = i32::from_be_bytes([peek_buf[4], peek_buf[5], peek_buf[6], peek_buf[7]]);

    const SSL_REQUEST_CODE: i32 = 80877103;

    if length == 8 && code == SSL_REQUEST_CODE {
        // Consume the SSLRequest from the stream (we only peeked above)
        let mut discard = [0u8; 8];
        stream.read_exact(&mut discard).await.map_err(|e| {
            crate::proxy::error::ProxyError::Protocol(ProtocolError::Io(e))
        })?;

        if let Some(acceptor) = tls_acceptor {
            // Accept TLS
            stream.write_all(b"S").await.map_err(|e| {
                crate::proxy::error::ProxyError::Protocol(ProtocolError::Io(e))
            })?;

            let tls_stream = acceptor.accept(stream).await.map_err(|e| {
                crate::proxy::error::ProxyError::Protocol(ProtocolError::Io(e))
            })?;

            metrics::counter!("trident_client_tls_connections_total").increment(1);
            Ok(ClientStream::Tls(Box::new(tls_stream)))
        } else {
            // No TLS configured: reject
            stream.write_all(b"N").await.map_err(|e| {
                crate::proxy::error::ProxyError::Protocol(ProtocolError::Io(e))
            })?;
            Ok(ClientStream::Plain(stream))
        }
    } else {
        // Not an SSLRequest — pass through as plaintext
        Ok(ClientStream::Plain(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::WeightedRoundRobin;
    use crate::config::{NodeType, PoolMode};
    use crate::health::BackendNodeSnapshot;
    use crate::parser::classifier::KeywordClassifier;
    use crate::parser::hint::RegexHintParser;
    use crate::parser::pattern::RegexPatternMatcher;
    use crate::pool::conn::PooledConnection;
    use crate::pool::manager::InMemoryPoolManager;
    use crate::pool::pool::{ConnCleaner, ConnFactory, NodePool, PoolError};
    use crate::protocol::message::BackendMessage;
    use crate::protocol::startup::TrustStartupHandler;
    use crate::router::consistency::LsnConsistencyChecker;
    use crate::router::cost::{DefaultCostEstimator, NoOpExplainRunner};
    use crate::router::router::{Router, RouterSettings};
    use crate::session::lsn::InMemoryLsnTracker;
    use std::sync::atomic::AtomicI32;

    struct CountingFactory {
        next_pid: AtomicI32,
    }
    impl ConnFactory for CountingFactory {
        async fn create(&self, node_id: &str) -> Result<PooledConnection, PoolError> {
            let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
            Ok(PooledConnection::new(node_id, pid, pid * 1000))
        }
    }

    struct NoopCleaner;
    impl ConnCleaner for NoopCleaner {
        async fn clean(&self, _conn: &PooledConnection) -> Result<(), PoolError> {
            Ok(())
        }
    }

    type TestRouter = Router<
        KeywordClassifier,
        RegexHintParser,
        LsnConsistencyChecker,
        DefaultCostEstimator<RegexPatternMatcher, NoOpExplainRunner>,
        WeightedRoundRobin,
    >;

    fn make_router() -> TestRouter {
        Router::new(
            KeywordClassifier,
            RegexHintParser,
            LsnConsistencyChecker,
            DefaultCostEstimator::new(RegexPatternMatcher::new(&[]).unwrap(), NoOpExplainRunner),
            WeightedRoundRobin::new(),
            RouterSettings {
                enable_transaction_split: true,
                split_respects_consistency: true,
                enable_hint_routing: true,
                enable_cost_routing: false,
                cost_threshold: 1_000_000.0,
                writer_readable: true,
            },
        )
    }

    fn make_pool_manager() -> InMemoryPoolManager {
        let mut pools: HashMap<String, Box<dyn crate::pool::pool::ConnectionPool>> = HashMap::new();
        pools.insert(
            "writer".to_string(),
            Box::new(NodePool::new(
                "writer",
                PoolMode::Transaction,
                10,
                CountingFactory {
                    next_pid: AtomicI32::new(1),
                },
                NoopCleaner,
            )),
        );
        InMemoryPoolManager::new(pools, || {
            vec![BackendNodeSnapshot {
                node_id: "writer".to_string(),
                node_type: NodeType::Writer,
                healthy: true,
                replay_lsn: 0,
                active_connections: 0,
                weight: 1,
                replication_lag_ms: None,
            }]
        })
    }

    #[tokio::test]
    async fn server_accepts_and_handles_a_connection() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // release the port; ProxyServer will rebind it

        let server = ProxyServer::new(addr, 10);
        let router = Arc::new(make_router());
        let pool_manager = Arc::new(make_pool_manager());
        let lsn_tracker = Arc::new(InMemoryLsnTracker::new());
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let cancel_registry = Arc::new(CancelRegistry::new());
        let node_addresses = Arc::new(ArcSwap::new(Arc::new(HashMap::new())));

        let deps = ProxyDeps {
            router,
            pool_manager,
            lsn_tracker,
            connection_registry,
            cancel_registry,
            node_addresses,
            default_consistency: Arc::new(ArcSwap::new(Arc::new(ConsistencyLevel::Session))),
            client_stats: Arc::new(ClientStats::new()),
            query_log: QueryLogSettings::default(),
            lsn_tracking: LsnTrackingConfig::default(),
            slow_queries: Arc::new(crate::admin::SlowQueryBuffer::new(16)),
            tls_acceptor: None,
            startup_timeout: std::time::Duration::ZERO,
            client_idle_timeout: std::time::Duration::ZERO,
            cancel_connect_timeout: std::time::Duration::from_secs(5),
        };

        let server_task = tokio::spawn({
            let deps = deps.clone();
            async move {
                let _ = server
                    .run(deps, || TrustStartupHandler {
                        backend_pid: 111,
                        secret_key: 222,
                    })
                    .await;
            }
        });

        // Give the listener a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = TcpStream::connect(addr).await.unwrap();

        let mut body = 196_608i32.to_be_bytes().to_vec();
        body.push(0);
        let mut framed = ((body.len() + 4) as i32).to_be_bytes().to_vec();
        framed.extend(body);
        client.write_all(&framed).await.unwrap();

        // Read the complete startup sequence, including ParameterStatus.
        loop {
            let message = crate::protocol::reader::read_backend_message(&mut client)
                .await
                .unwrap();
            if matches!(message, BackendMessage::ReadyForQuery(_)) {
                break;
            }
        }

        server_task.abort();
    }

    #[test]
    fn bind_error_reports_the_offending_address() {
        // We cannot easily force a bind failure portably in a unit test
        // without risking flakiness across CI environments, so this test
        // only exercises the error type's Display formatting.
        let err = ServerError::Bind {
            addr: "0.0.0.0:1".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use"),
        };
        let message = err.to_string();
        assert!(message.contains("0.0.0.0:1"));
    }

    #[allow(dead_code)]
    fn silence_unused_import_backend_message(_m: BackendMessage) {}
}
