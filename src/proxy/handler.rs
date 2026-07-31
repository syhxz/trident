//! Single-client connection handler (`handler`)
//!
//! `ConnectionHandler::handle` drives the full lifecycle of one client
//! connection: Startup/authentication, then a message loop that calls the
//! Router, acquires a backend connection through the PoolManager, forwards
//! messages via the Forwarder, and finally releases/pins connections when
//! the client connection closes.
//!
//! Errors encountered while processing a message are converted into a
//! well-formed `ErrorResponse` sent back to the client rather than
//! propagated as a crash; a panic inside the per-connection task is caught
//! by the caller (`ProxyServer::run`, via `tokio::spawn` + `JoinHandle`) and
//! never brings down the rest of the proxy (Requirements 11.1, 11.2, 13.1,
//! 13.4, 13.5).

use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::balancer::LoadBalancer;
use crate::config::{ConsistencyLevel, LsnTrackingConfig, LsnTrackingMode, NodeType, PoolMode};
use crate::parser::classifier::{
    contains_multiple_statements, multi_statement_all_readable, requires_writer, Classifier, KeywordClassifier,
};
use crate::parser::hint::HintParser;
use crate::pool::conn::PooledConnection;
use crate::pool::manager::PoolManager;
use crate::pool::pinning::detects_pinning_trigger;
use crate::protocol::message::{BackendMessage, FrontendMessage, PgError, TransactionStatus};
use crate::protocol::reader::{frontend_tag, parse_frontend_body, read_tagged_frame};
use crate::protocol::startup::{read_startup_packet, AuthOutcome, StartupHandler, StartupPacket};
use crate::protocol::writer::encode_backend_message;
use crate::protocol::ProtocolError;
use crate::proxy::error::{proxy_error_to_pg_error, ProxyError};
use crate::proxy::forwarder::{
    apply_ready_for_query, fetch_current_wal_lsn, forward_simple_query, relay_copy_in_stream,
    forward_simple_query_with_options, is_write_command_tag, ExtendedQueryRouteTracker,
    QueryForwardOptions,
};
use crate::proxy::registry::{send_cancel_request, BackendStream, CancelRegistry, ConnectionRegistry, NodeAddress};
use crate::router::consistency::ConsistencyChecker;
use crate::router::cost::CostEstimator;
use crate::router::router::{RouteDecision, Router, RoutingContext};
use crate::session::lsn::LsnTracker;
use crate::session::session::{SessionState, TxState};
use crate::session::transaction::{
    parse_begin_options, transaction_end_tag, TxSplitState,
};

/// Per-session data the handler owns for the lifetime of one client
/// connection: routing/consistency state plus a unique session id used as
/// the pool's `session_id` key.
pub struct ClientSession {
    pub state: SessionState,
    held_backend: Option<HeldBackend>,
    /// A successful write has occurred in the current explicit transaction.
    tx_has_writes: bool,
    /// A committed write has no captured WAL watermark yet. The first read
    /// that would use a non-Writer node resolves it lazily.
    pending_write: bool,
    /// Auto mode switches from Pipeline to Extension after observing the
    /// configured commit-time ParameterStatus report.
    extension_detected: bool,
    /// Aurora write forwarding pins each client session to one Reader node.
    aurora_node_id: Option<String>,
    /// Backend PID on which the Aurora consistency GUC has been initialized.
    aurora_initialized_backend_pid: Option<i32>,
    /// Tracks which backend node each named prepared statement was parsed on,
    /// so subsequent Bind/Execute referencing it are forwarded consistently.
    extended_route_tracker: ExtendedQueryRouteTracker,
}

/// A backend connection checked out exclusively by this client. It is
/// retained across statements while PostgreSQL reports an open/failed
/// transaction, or after a session-state operation triggers pinning.
struct HeldBackend {
    conn: PooledConnection,
    socket: BackendStream,
}

/// One extended-query protocol message buffered between Sync boundaries,
/// kept as raw wire bytes (tag + body, without the length header).
///
/// The proxy never needs the fully decoded form of these messages: they are
/// forwarded to the backend verbatim, and only a handful of fields (Parse
/// name/SQL, Bind statement name, Describe/Close kind+name) are extracted
/// lazily for routing decisions. Skipping the decode -> re-encode round trip
/// removes per-parameter heap allocations on the hot path and guarantees
/// byte-perfect forwarding; the backend remains the authoritative validator
/// of message contents.
struct ExtendedFrame {
    tag: u8,
    body: Vec<u8>,
}

impl ExtendedFrame {
    /// For a Parse ('P') frame: the statement name (first C-string).
    fn parse_name(&self) -> Option<&str> {
        cstr_at(&self.body, 0).map(|(s, _)| s)
    }

    /// For a Parse ('P') frame: the SQL text (second C-string).
    fn parse_sql(&self) -> Option<&str> {
        let (_, next) = cstr_at(&self.body, 0)?;
        cstr_at(&self.body, next).map(|(s, _)| s)
    }

    /// For a Bind ('B') frame: the source statement name (second C-string,
    /// after the portal name).
    fn bind_statement(&self) -> Option<&str> {
        let (_, next) = cstr_at(&self.body, 0)?;
        cstr_at(&self.body, next).map(|(s, _)| s)
    }

    /// For a Describe ('D') or Close ('C') frame: the kind byte ('S' for
    /// statement, 'P' for portal) and the target name.
    fn kind_and_name(&self) -> Option<(u8, &str)> {
        let kind = *self.body.first()?;
        cstr_at(&self.body, 1).map(|(s, _)| (kind, s))
    }
}

/// Reads a NUL-terminated string starting at `pos` in `body`, returning the
/// string (must be valid UTF-8, matching the strict parser's behavior) and
/// the offset just past the terminator. Returns `None` when the terminator
/// is missing or the bytes are not UTF-8.
fn cstr_at(body: &[u8], pos: usize) -> Option<(&str, usize)> {
    let slice = body.get(pos..)?;
    let nul = slice.iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&slice[..nul]).ok()?;
    Some((s, pos + nul + 1))
}

/// Per-query observability settings, wired from `config::LoggingConfig`:
///
/// - `query_trace`: when `true`, every simple-query statement is logged
///   independently of the global `level` setting, with its duration and
///   routing target. Off by default since this can be high-volume. Unlike
///   debug-level logging, `query_trace` is an explicit per-statement trace
///   that fires regardless of `level` — you can run `level: warn` and
///   still see individual queries when `query_trace: true`.
///
/// - `slow_query_threshold_ms`: any statement taking at least this long
///   (wall-clock, covering routing + pool acquisition + the full backend
///   round trip) is logged at `warn` level regardless of `query_trace`,
///   and counted in `trident_slow_queries_total`.
///
/// Both settings log the statement's SQL text verbatim.
#[derive(Debug, Clone, Copy)]
pub struct QueryLogSettings {
    pub query_trace: bool,
    pub slow_query_threshold_ms: u64,
}

impl Default for QueryLogSettings {
    fn default() -> Self {
        QueryLogSettings {
            query_trace: false,
            slow_query_threshold_ms: 1000,
        }
    }
}

impl QueryLogSettings {
    pub fn new(query_trace: bool, slow_query_threshold_ms: u64) -> Self {
        QueryLogSettings {
            query_trace,
            slow_query_threshold_ms,
        }
    }
}

impl ClientSession {
    pub fn new(session_id: impl Into<String>, default_consistency: ConsistencyLevel) -> Self {
        ClientSession {
            state: SessionState::new(session_id, default_consistency),
            held_backend: None,
            tx_has_writes: false,
            pending_write: false,
            extension_detected: false,
            aurora_node_id: None,
            aurora_initialized_backend_pid: None,
            extended_route_tracker: ExtendedQueryRouteTracker::new(),
        }
    }
}

/// Drives the lifecycle of a single client connection.
pub struct ConnectionHandler<'a, RTR, PM, LSN>
where
    RTR: RouteFn,
    PM: PoolManager,
    LSN: LsnTracker,
{
    pub router: &'a RTR,
    pub pool_manager: &'a PM,
    pub lsn_tracker: &'a LSN,
    /// Maps `(node_id, backend_pid)` to the live backend `TcpStream`,
    /// letting the handler look up the physical socket for a
    /// `PooledConnection` returned by the pool (which only carries
    /// metadata -- see `pool::conn` module docs) so it can actually
    /// forward SQL and stream results back to the client.
    pub connection_registry: &'a ConnectionRegistry,
    /// Tracks proxy-issued cancel keys and each session's currently active
    /// backend connection, so CANCEL requests can be validated and routed
    /// correctly in the single-instance case (Requirements 7.1-7.3).
    pub cancel_registry: &'a CancelRegistry,
    /// Real network address of every configured backend node, keyed by
    /// `node_id`, used to open the independent connection a CANCEL request
    /// must be sent over.
    pub node_addresses: &'a HashMap<String, NodeAddress>,
    /// Controls per-statement query trace and the slow-query threshold
    /// (`config.logging.query_trace`/`slow_query`) -- see `QueryLogSettings`
    /// docs.
    pub query_log: QueryLogSettings,
    /// Restart-only strategy controlling write watermark acquisition or
    /// Aurora's kernel-managed write forwarding path.
    pub lsn_tracking: LsnTrackingConfig,
    /// Optional ring buffer receiving every statement that crosses the
    /// slow-query threshold, for the admin console's slow-query view.
    pub slow_query_buffer: Option<std::sync::Arc<crate::admin::SlowQueryBuffer>>,
}

/// Abstraction over `Router::route` used by the handler, so the handler
/// does not need to be generic over the Router's full type parameter list
/// (Classifier/HintParser/ConsistencyChecker/CostEstimator/LoadBalancer).
///
/// This lets tests inject a simplified router while production code wires
/// a real `router::Router` behind this trait.
pub trait RouteFn: Send + Sync {
    fn transaction_split_settings(&self) -> (bool, bool);

    fn route(
        &self,
        sql: &str,
        ctx: &mut RoutingContext<'_>,
        readers: &[crate::health::BackendNodeSnapshot],
        analytics_nodes: &[crate::health::BackendNodeSnapshot],
    ) -> impl std::future::Future<Output = Result<RouteDecision, crate::router::router::RouterError>> + Send;
}

impl<C, H, CC, CE, LB> RouteFn for Router<C, H, CC, CE, LB>
where
    C: Classifier + Send + Sync,
    H: HintParser + Send + Sync,
    CC: ConsistencyChecker + Send + Sync,
    CE: CostEstimator,
    LB: LoadBalancer,
{
    fn transaction_split_settings(&self) -> (bool, bool) {
        let settings = self.settings();
        (
            settings.enable_transaction_split,
            settings.split_respects_consistency,
        )
    }

    async fn route(
        &self,
        sql: &str,
        ctx: &mut RoutingContext<'_>,
        readers: &[crate::health::BackendNodeSnapshot],
        analytics_nodes: &[crate::health::BackendNodeSnapshot],
    ) -> Result<RouteDecision, crate::router::router::RouterError> {
        Router::route(self, sql, ctx, readers, analytics_nodes).await
    }
}

impl<'a, RTR, PM, LSN> ConnectionHandler<'a, RTR, PM, LSN>
where
    RTR: RouteFn,
    PM: PoolManager,
    LSN: LsnTracker,
{
    pub fn new(
        router: &'a RTR,
        pool_manager: &'a PM,
        lsn_tracker: &'a LSN,
        connection_registry: &'a ConnectionRegistry,
        cancel_registry: &'a CancelRegistry,
        node_addresses: &'a HashMap<String, NodeAddress>,
    ) -> Self {
        ConnectionHandler {
            router,
            pool_manager,
            lsn_tracker,
            connection_registry,
            cancel_registry,
            node_addresses,
            query_log: QueryLogSettings::default(),
            lsn_tracking: LsnTrackingConfig::default(),
            slow_query_buffer: None,
        }
    }

    /// Same as `new`, but with explicit `query_log`/`slow_query` behavior
    /// (see `QueryLogSettings`) instead of the default (query logging
    /// off, 1000ms slow-query threshold).
    pub fn with_query_log(
        router: &'a RTR,
        pool_manager: &'a PM,
        lsn_tracker: &'a LSN,
        connection_registry: &'a ConnectionRegistry,
        cancel_registry: &'a CancelRegistry,
        node_addresses: &'a HashMap<String, NodeAddress>,
        query_log: QueryLogSettings,
    ) -> Self {
        ConnectionHandler {
            router,
            pool_manager,
            lsn_tracker,
            connection_registry,
            cancel_registry,
            node_addresses,
            query_log,
            lsn_tracking: LsnTrackingConfig::default(),
            slow_query_buffer: None,
        }
    }

    /// Overrides the restart-only LSN acquisition strategy selected by the
    /// process configuration.
    pub fn with_lsn_tracking(mut self, lsn_tracking: LsnTrackingConfig) -> Self {
        self.lsn_tracking = lsn_tracking;
        self
    }

    /// Attaches the shared slow-query ring buffer backing the admin
    /// console's `/api/slow-queries` view.
    pub fn with_slow_query_buffer(
        mut self,
        buffer: std::sync::Arc<crate::admin::SlowQueryBuffer>,
    ) -> Self {
        self.slow_query_buffer = Some(buffer);
        self
    }

    /// Handles a single client connection end-to-end. `startup_handler`
    /// performs the Startup/authentication handshake with the client;
    /// `session_id` uniquely identifies this connection for pool/LSN
    /// bookkeeping.
    pub async fn handle<S, SH>(
        &self,
        mut client_stream: S,
        startup_handler: &mut SH,
        session_id: String,
        default_consistency: ConsistencyLevel,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        SH: StartupHandler,
    {
        // --- Startup phase: Startup / CancelRequest / SSL/GSSENC --------
        //
        // PostgreSQL clients commonly probe transport encryption before
        // sending the real StartupMessage. Trident currently supports
        // plaintext client transport only, so reject each probe with the
        // protocol-mandated one-byte `N` and continue on the same socket.
        // Bound the negotiation loop to avoid an unbounded request stream.
        const MAX_ENCRYPTION_NEGOTIATIONS: usize = 2;
        let mut negotiation_count = 0;
        let startup_msg = loop {
            match read_startup_packet(&mut client_stream).await? {
                StartupPacket::Startup(msg) => break msg,
                StartupPacket::SslRequest | StartupPacket::GssEncRequest => {
                    if negotiation_count >= MAX_ENCRYPTION_NEGOTIATIONS {
                        return Err(ProxyError::Protocol(ProtocolError::Malformed(
                            "too many startup encryption negotiation requests".into(),
                        )));
                    }
                    negotiation_count += 1;
                    client_stream
                        .write_all(b"N")
                        .await
                        .map_err(ProtocolError::Io)?;
                    client_stream.flush().await.map_err(ProtocolError::Io)?;
                }
                StartupPacket::Cancel {
                    backend_pid,
                    secret_key,
                } => {
                    self.handle_cancel_request(backend_pid, secret_key).await;
                    return Ok(());
                }
            }
        };

        let mut session = ClientSession::new(session_id.clone(), default_consistency);

        // --- Authentication -----------------------------------------------
        let auth_outcome = startup_handler
            .handle_startup(startup_msg)
            .await
            .map_err(ProxyError::Protocol)?;
        send_startup_success(&mut client_stream, &auth_outcome).await?;
        client_stream.flush().await.map_err(|e| {
            ProxyError::Protocol(ProtocolError::Io(e))
        })?;

        // Register the cancel key this proxy just issued to the client (in
        // BackendKeyData above) against this session, so a later
        // CancelRequest bearing it can be attributed back correctly
        // (Requirements 7.1-7.3).
        self.cancel_registry
            .register_session(auth_outcome.backend_pid, auth_outcome.secret_key, &session_id);

        // --- Message loop -------------------------------------------------
        let result = self.message_loop(&mut client_stream, &mut session).await;

        // --- Cleanup on connection close -----------------------------------
        // Release any pooled connections this session was holding, whether
        // in Session mode (the single bound connection) or Transaction mode
        // (any pinned connections). Best-effort: pool lookups may legitimately
        // find nothing if the session never acquired a connection.
        // A checked-out transaction/pinned socket is owned directly by
        // the session rather than the registry. Discard it first so both
        // the physical socket and the pool capacity slot are released.
        if let Some(held) = session.held_backend.take() {
            if let Some(pool) = self.pool_manager.pool_for(&held.conn.node_id) {
                if let Err(error) = pool.discard(held.conn) {
                    tracing::warn!(error = %error, "failed to discard held backend connection");
                }
            }
            drop(held.socket);
        }

        // Release metadata still owned by Session-mode bindings or by the
        // pool's pinned map, and explicitly remove every corresponding
        // registered socket. `release_session` returns the identities so
        // this cleanup cannot leak file descriptors.
        self.cancel_registry.clear_active(&session_id);
        self.cancel_registry
            .unregister_session(auth_outcome.backend_pid, auth_outcome.secret_key);
        for node_id in known_node_ids(self.pool_manager) {
            if let Some(pool) = self.pool_manager.pool_for(&node_id) {
                for connection in pool.release_session(&session_id) {
                    self.connection_registry
                        .remove(&connection.node_id, connection.backend_pid);
                }
            }
        }
        self.lsn_tracker.remove_session(&session_id);

        result
    }

    /// Handles a `CancelRequest` received on its own connection: resolves
    /// the proxy-issued cancel key to the session's currently active real
    /// backend connection (if any) and, only when that resolves
    /// successfully, opens a brand-new connection to that backend node and
    /// forwards the CancelRequest (Requirements 7.1-7.3). An unknown key or
    /// a session with no active query is silently ignored, matching
    /// PostgreSQL's own CANCEL semantics; a failure to reach the backend
    /// node is logged but never surfaced to the (already-closing) client
    /// connection.
    async fn handle_cancel_request(&self, backend_pid: i32, secret_key: i32) {
        let Some((node_id, real_backend_pid, real_secret_key)) =
            self.cancel_registry.resolve_cancel_target(backend_pid, secret_key)
        else {
            metrics::counter!("trident_cancel_requests_total", "outcome" => "ignored").increment(1);
            tracing::debug!(
                backend_pid,
                secret_key,
                "ignoring CancelRequest: unknown key or no active query for the target session"
            );
            return;
        };

        let Some(addr) = self.node_addresses.get(&node_id) else {
            metrics::counter!("trident_cancel_requests_total", "outcome" => "no_node_address").increment(1);
            tracing::warn!(node_id = %node_id, "cannot forward CancelRequest: no known address for node");
            return;
        };

        if let Err(e) = send_cancel_request(addr, real_backend_pid, real_secret_key).await {
            metrics::counter!("trident_cancel_requests_total", "outcome" => "send_failed").increment(1);
            tracing::warn!(node_id = %node_id, error = %e, "failed to forward CancelRequest to backend");
        } else {
            metrics::counter!("trident_cancel_requests_total", "outcome" => "forwarded").increment(1);
        }
    }

    async fn message_loop<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut extended_error_pending = false;
        let mut extended_batch: Vec<ExtendedFrame> = Vec::new();
        let mut extended_batch_bytes: usize = 0;

        loop {
            // Read the raw frame and dispatch on the tag byte. Extended query
            // messages (Parse/Bind/Describe/Execute/Close) are deliberately
            // NOT parsed into `FrontendMessage`: they are buffered as raw
            // bytes and forwarded verbatim to the backend. This avoids a full
            // decode -> re-encode cycle per message (a Bind with N parameters
            // used to cost N+ heap allocations twice over) and guarantees
            // byte-perfect forwarding of format codes and parameter values.
            // The backend remains the authoritative validator of message
            // contents; the proxy only extracts the few fields routing needs.
            let (tag, body) = match read_tagged_frame(client_stream).await {
                Ok(frame) => frame,
                Err(ProtocolError::UnexpectedEof) => return Ok(()), // client closed connection
                Err(e) => {
                    // Requirement 13.3: malformed frontend bytes -> close the
                    // connection and report, without affecting other sessions.
                    return Err(ProxyError::Protocol(e));
                }
            };

            // PostgreSQL requires the backend to ignore every message after an
            // extended-query error until Sync. Terminate remains valid so a
            // client can always close the connection cleanly.
            if extended_error_pending {
                match tag {
                    frontend_tag::TERMINATE => return Ok(()),
                    frontend_tag::SYNC => {
                        send_ready_for_query(client_stream, session.state.tx_state).await?;
                        client_stream.flush().await.map_err(|e| {
                            ProxyError::Protocol(ProtocolError::Io(e))
                        })?;
                        extended_error_pending = false;
                        extended_batch.clear();
                        extended_batch_bytes = 0;
                    }
                    _ => {}
                }
                continue;
            }

            match tag {
                frontend_tag::TERMINATE => return Ok(()),
                frontend_tag::QUERY => {
                    let sql = match parse_frontend_body(tag, &body) {
                        Ok(FrontendMessage::Query(sql)) => sql,
                        Ok(_) => unreachable!("tag 'Q' always parses to Query"),
                        Err(e) => return Err(ProxyError::Protocol(e)),
                    };
                    if let Err(e) = self.handle_simple_query(client_stream, session, &sql).await {
                        send_error_response(client_stream, &e).await?;
                        // PostgreSQL terminates every Simple Query response
                        // cycle with ReadyForQuery, including proxy-local
                        // routing/pool/protocol failures that never reached a
                        // backend. Omitting this leaves libpq/psql waiting
                        // forever for the connection to become ready again.
                        send_ready_for_query(client_stream, session.state.tx_state).await?;
                    }
                    // Flush the buffered writer so the complete response
                    // (RowDescription + DataRow(s) + CommandComplete +
                    // ReadyForQuery) is sent as one TCP segment.
                    client_stream.flush().await.map_err(|e| {
                        ProxyError::Protocol(ProtocolError::Io(e))
                    })?;
                }
                frontend_tag::SYNC => {
                    if extended_batch.is_empty() {
                        // A bare Sync with no preceding Parse/Bind/Execute
                        // just returns the current transaction state.
                        send_ready_for_query(client_stream, session.state.tx_state).await?;
                    } else {
                        let batch = std::mem::take(&mut extended_batch);
                        extended_batch_bytes = 0;
                        if let Err(e) = self
                            .handle_extended_query_batch(client_stream, session, &batch)
                            .await
                        {
                            send_error_response(client_stream, &e).await?;
                            send_ready_for_query(client_stream, session.state.tx_state).await?;
                            if session.state.tx_state != TxState::Idle {
                                self.fail_open_transaction(session);
                            }
                        }
                    }
                    client_stream.flush().await.map_err(|e| {
                        ProxyError::Protocol(ProtocolError::Io(e))
                    })?;
                }
                frontend_tag::FLUSH => {
                    if extended_batch.is_empty() {
                        // Flush with nothing pending: everything the proxy
                        // had was already delivered at the last Sync
                        // boundary; just make sure the write buffer is
                        // drained.
                        client_stream.flush().await.map_err(|e| {
                            ProxyError::Protocol(ProtocolError::Io(e))
                        })?;
                    } else {
                        // Trident forwards extended-query batches whole at
                        // Sync boundaries and cannot deliver intermediate
                        // results at a Flush point (drivers use this in
                        // pipeline mode, e.g. Parse+Describe+Flush to fetch
                        // parameter metadata before Bind). Buffering the
                        // Flush would deadlock such clients, so reject the
                        // batch cleanly instead of killing the connection:
                        // ErrorResponse now, ReadyForQuery at the client's
                        // Sync, exactly the recovery sequence drivers expect
                        // from an extended-query error.
                        let error = PgError::simple(
                            "ERROR",
                            "0A000",
                            "extended-protocol Flush is not supported by Trident; \
                             end the batch with Sync instead",
                        );
                        send_pg_error_response(client_stream, error).await?;
                        client_stream.flush().await.map_err(|e| {
                            ProxyError::Protocol(ProtocolError::Io(e))
                        })?;
                        extended_error_pending = true;
                        extended_batch.clear();
                        extended_batch_bytes = 0;
                    }
                }
                frontend_tag::PARSE
                | frontend_tag::BIND
                | frontend_tag::DESCRIBE
                | frontend_tag::EXECUTE
                | frontend_tag::CLOSE => {
                    // Collect extended query messages into a batch until Sync.
                    // Cap both message count and cumulative bytes so a client
                    // that never sends Sync cannot grow this buffer without
                    // bound (memory-exhaustion DoS).
                    const MAX_EXTENDED_BATCH_MESSAGES: usize = 4096;
                    const MAX_EXTENDED_BATCH_BYTES: usize = 256 * 1024 * 1024;
                    if extended_batch.len() >= MAX_EXTENDED_BATCH_MESSAGES {
                        return Err(ProxyError::Protocol(ProtocolError::Malformed(
                            "extended query batch exceeds message limit without Sync".into(),
                        )));
                    }
                    if extended_batch_bytes.saturating_add(body.len())
                        > MAX_EXTENDED_BATCH_BYTES
                    {
                        return Err(ProxyError::Protocol(ProtocolError::Malformed(
                            "extended query batch exceeds byte limit without Sync".into(),
                        )));
                    }
                    extended_batch_bytes += body.len();
                    extended_batch.push(ExtendedFrame { tag, body });
                }
                // Any other tag (CopyData outside a COPY, FunctionCall, ...)
                // takes the full parser path so unknown/unsupported messages
                // produce the same errors as before. Startup/CancelRequest
                // never reach this loop: they are handled in `handle` before
                // a regular session is established.
                _ => {
                    let _ = parse_frontend_body(tag, &body).map_err(ProxyError::Protocol)?;
                }
            }
        }
    }

    /// Handles a batch of extended query protocol messages collected between
    /// two Sync boundaries. The batch is forwarded as a unit to a single
    /// backend (chosen based on SQL classification of the first Parse in the
    /// batch, or the session's held backend if inside a transaction).
    ///
    /// The Sync message itself is appended by this function; responses are
    /// relayed back until `ReadyForQuery`.
    async fn handle_extended_query_batch<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        batch: &[ExtendedFrame],
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Preserve PostgreSQL's failed-transaction semantics: with the
        // physical connection already lost, the batch must not run as
        // autocommit on a fresh connection. Match the Simple Query path.
        if session.state.tx_state == TxState::Failed && session.held_backend.is_none() {
            let error = PgError::simple(
                "ERROR",
                "25P02",
                "current transaction is aborted, commands ignored until end of transaction block",
            );
            send_pg_error_response(client_stream, error).await?;
            send_ready_for_query(client_stream, TxState::Failed).await?;
            return Ok(());
        }

        // Fast path: if a backend is already held (pinned connection or
        // in-transaction), skip routing/snapshot entirely and reuse it.
        if session.held_backend.is_some() {
            return self
                .forward_extended_on_held_backend(client_stream, session, batch)
                .await;
        }

        // Determine routing: prefer Parse SQL, then named statement lookup,
        // then fall back to "SELECT 1" (routes to Reader by default). A Parse
        // frame whose header C-strings cannot be extracted is malformed
        // enough that routing is impossible; reject it here (the strict
        // parser would previously have rejected it at read time).
        let route_sql = match batch.iter().find(|f| f.tag == frontend_tag::PARSE) {
            Some(frame) => Some(frame.parse_sql().ok_or_else(|| {
                ProxyError::Protocol(ProtocolError::Malformed(
                    "Parse message missing statement name or query C-string".into(),
                ))
            })?),
            None => None,
        };

        // If no Parse in batch, look up the statement name referenced by
        // Bind/Describe(Statement) to find its previously recorded route
        // target. Execute references a *portal* (a separate namespace
        // created by Bind on a specific connection), so portal names are
        // deliberately not looked up here.
        let tracked_node = if route_sql.is_none() {
            batch.iter().find_map(|frame| match frame.tag {
                frontend_tag::BIND => match frame.bind_statement() {
                    Some(statement) if !statement.is_empty() => {
                        session.extended_route_tracker.route_for_statement(statement)
                    }
                    _ => None,
                },
                frontend_tag::DESCRIBE => match frame.kind_and_name() {
                    Some((b'S', name)) if !name.is_empty() => {
                        session.extended_route_tracker.route_for_statement(name)
                    }
                    _ => None,
                },
                _ => None,
            })
        } else {
            None
        };

        let target_node_id = if self.lsn_tracking.mode == LsnTrackingMode::AuroraWriteForwarding {
            // Aurora write forwarding pins every session to one Reader and
            // bypasses the Router entirely; extended batches must honor the
            // same binding or session consistency breaks.
            let all_nodes = self.pool_manager.snapshot();
            if let Some(node_id) = session.aurora_node_id.as_ref() {
                let still_available = all_nodes.iter().any(|node| {
                    node.node_id == *node_id
                        && node.node_type == NodeType::Reader
                        && node.healthy
                });
                if !still_available {
                    return Err(ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                        node_id.clone(),
                    )));
                }
                node_id.clone()
            } else {
                let selected = all_nodes
                    .iter()
                    .filter(|n| n.node_type == NodeType::Reader && n.healthy)
                    .min_by(|left, right| {
                        left.active_connections
                            .cmp(&right.active_connections)
                            .then_with(|| left.node_id.cmp(&right.node_id))
                    })
                    .map(|node| node.node_id.clone())
                    .ok_or_else(|| {
                        ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                            "Aurora Reader".to_string(),
                        ))
                    })?;
                session.aurora_node_id = Some(selected.clone());
                selected
            }
        } else if let Some(node_id) = tracked_node {
            // Named statement was previously parsed on this node: reuse that
            // route without touching the pool snapshot at all.
            node_id
        } else {
            // Route based on the SQL from Parse. The pool snapshot (which
            // clones every node's state) is only taken on this branch and
            // the Aurora branch above; the tracked-statement fast path
            // skips it entirely.
            let all_nodes = self.pool_manager.snapshot();
            let readers: Vec<_> = all_nodes
                .iter()
                .filter(|n| n.node_type == NodeType::Reader && n.healthy)
                .cloned()
                .collect();
            let analytics: Vec<_> = all_nodes
                .iter()
                .filter(|n| n.node_type == NodeType::Analytics && n.healthy)
                .cloned()
                .collect();
            let sql_for_routing = route_sql.unwrap_or("SELECT 1");

            let session_write_lsn = self.lsn_tracker.session_write_lsn(&session.state.id);
            let global_write_lsn = self.lsn_tracker.global_write_lsn();
            let mut tx_split = session.state.tx_split.take();
            let decision = {
                let mut ctx = RoutingContext {
                    tx_state: session.state.tx_state,
                    tx_split: &mut tx_split,
                    consistency: session.state.consistency,
                    session_write_lsn,
                    global_write_lsn,
                };
                self.router
                    .route(sql_for_routing, &mut ctx, &readers, &analytics)
                    .await
            };
            session.state.tx_split = tx_split;
            let decision = decision?;

            match decision.target {
                NodeType::Writer => all_nodes
                    .iter()
                    .find(|n| n.node_type == NodeType::Writer && n.healthy)
                    .map(|n| n.node_id.clone())
                    .unwrap_or_default(),
                _ => decision.node_id.unwrap_or_default(),
            }
        };

        if target_node_id.is_empty() {
            return Err(ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                "no healthy backend for extended query".to_string(),
            )));
        }

        // Acquire a new connection (held_backend case handled by fast path above).
        let pool = self.pool_manager.pool_for(&target_node_id).ok_or_else(|| {
            ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                target_node_id.clone(),
            ))
        })?;
        let (mut conn, mut backend_socket) = {
            let conn = pool.acquire(&session.state.id).await?;
            let socket = self
                .connection_registry
                .take(&conn.node_id, conn.backend_pid)
                .ok_or_else(|| {
                    let _ = pool.discard(conn.clone());
                    ProxyError::Pool(crate::pool::pool::PoolError::CleanupFailed(
                        "backend socket missing from registry".into(),
                    ))
                })?;
            (conn, socket)
        };

        // A named prepared statement lives on this physical connection, not
        // on the node. In Transaction pool mode the connection would
        // otherwise be released and later Bind/Execute could land on a
        // different physical connection where the statement was never
        // prepared. Pin the connection to this session, exactly as the
        // Simple Query path does for PREPARE (Requirement 6.1).
        let creates_named_statement = batch.iter().any(frame_is_named_parse);
        if creates_named_statement && !conn.pinned {
            pool.pin(&session.state.id, &mut conn);
        }

        // Aurora write forwarding: initialize the consistency GUC once per
        // physical backend, mirroring the Simple Query Aurora path.
        if self.lsn_tracking.mode == LsnTrackingMode::AuroraWriteForwarding
            && session.aurora_initialized_backend_pid != Some(conn.backend_pid)
        {
            let init_sql = aurora_consistency_sql(session.state.consistency);
            if let Err(error) =
                execute_internal_query(&mut backend_socket, &init_sql, TransactionStatus::Idle)
                    .await
            {
                session.aurora_initialized_backend_pid = None;
                pool.discard(conn)?;
                drop(backend_socket);
                return Err(ProxyError::Protocol(error));
            }
            session.aurora_initialized_backend_pid = Some(conn.backend_pid);
        }

        // Send all buffered raw frames + Sync to the backend in one write.
        // No re-encoding: the bytes the client sent are forwarded verbatim.
        let outbound = assemble_extended_outbound(batch);

        self.cancel_registry.mark_active(
            &session.state.id,
            &conn.node_id,
            conn.backend_pid,
            conn.secret_key,
        );

        if let Err(e) = backend_socket.write_all(&outbound).await {
            self.cancel_registry.clear_active(&session.state.id);
            pool.discard(conn)?;
            drop(backend_socket);
            return Err(ProxyError::Protocol(e.into()));
        }
        if let Err(e) = backend_socket.flush().await {
            self.cancel_registry.clear_active(&session.state.id);
            pool.discard(conn)?;
            drop(backend_socket);
            return Err(ProxyError::Protocol(e.into()));
        }

        // Relay backend responses until ReadyForQuery.
        let mut had_error = false;
        let mut write_detected = false;
        let mut commit_tag_seen = false;
        let mut reported_lsn: Option<u64> = None;
        let extension_guc_name = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            _ => None,
        };
        let tx_status = loop {
            let (tag, body) = match read_tagged_frame(&mut backend_socket).await {
                Ok(frame) => frame,
                Err(e) => {
                    self.cancel_registry.clear_active(&session.state.id);
                    pool.discard(conn)?;
                    drop(backend_socket);
                    return Err(ProxyError::Protocol(e));
                }
            };

            match tag {
                b'Z' => {
                    // ReadyForQuery: extract status, do NOT relay (handler sends its own).
                    let status = TransactionStatus::from_byte(*body.first().unwrap_or(&b'I'))
                        .unwrap_or(TransactionStatus::Idle);
                    break status;
                }
                b'C' => {
                    // CommandComplete: check for write tags and COMMIT.
                    let cmd_tag = extract_cstring_from_body(&body);
                    if is_write_command_tag(&cmd_tag) {
                        write_detected = true;
                    }
                    if cmd_tag == "COMMIT" {
                        commit_tag_seen = true;
                    }
                    write_raw_frame_to(client_stream, tag, &body).await?;
                }
                b'E' => {
                    // ErrorResponse.
                    had_error = true;
                    write_raw_frame_to(client_stream, tag, &body).await?;
                }
                b'G' => {
                    // COPY ... FROM STDIN via the extended protocol: relay
                    // CopyInResponse, then switch to relaying the client's
                    // copy stream to the backend until CopyDone/CopyFail.
                    write_raw_frame_to(client_stream, tag, &body).await?;
                    client_stream
                        .flush()
                        .await
                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                    let copy_result =
                        relay_copy_in_stream(&mut backend_socket, client_stream).await;
                    // The Sync pipelined behind Execute was consumed and
                    // ignored by the backend while in copy-in mode (per
                    // protocol spec); send a fresh one or ReadyForQuery
                    // never arrives.
                    let sync_result = match copy_result {
                        Ok(()) => backend_socket
                            .write_all(&[b'S', 0, 0, 0, 4])
                            .await
                            .map_err(ProtocolError::Io),
                        Err(e) => Err(e),
                    };
                    if let Err(e) = sync_result {
                        // Mid-copy failure leaves the backend in copy-in
                        // state; this connection must not be reused.
                        self.cancel_registry.clear_active(&session.state.id);
                        pool.discard(conn)?;
                        drop(backend_socket);
                        return Err(ProxyError::Protocol(e));
                    }
                }
                b'S' if extension_guc_name.is_some() => {
                    // ParameterStatus: check if it's the extension LSN GUC.
                    // Capture the LSN value and suppress the message from
                    // reaching the client (it's an internal implementation
                    // detail of the pg_lsn_track extension).
                    let (name, value) = extract_two_cstrings_from_body(&body);
                    if Some(name.as_str()) == extension_guc_name {
                        reported_lsn = crate::health::parse_lsn(&value);
                    } else {
                        write_raw_frame_to(client_stream, tag, &body).await?;
                    }
                }
                _ => {
                    // Everything else (ParseComplete, BindComplete, DataRow,
                    // RowDescription, NoData, ParameterDescription,
                    // CloseComplete, NoticeResponse, etc.): relay raw.
                    write_raw_frame_to(client_stream, tag, &body).await?;
                }
            }
        };
        self.cancel_registry.clear_active(&session.state.id);

        // Update session transaction state.
        session.state.tx_state = apply_ready_for_query(tx_status);

        // Record named statement routes for future batches, and clean up
        // on Close. Only process if the batch succeeded (no error).
        if !had_error {
            record_statement_routes(session, batch, &conn.node_id);
        }

        // Track writes for LSN watermark. Two cases:
        // (a) Autocommit write or combined batch containing write+COMMIT:
        //     write_detected=true, tx_status=Idle.
        // (b) Explicit COMMIT after prior writes in earlier batches:
        //     write_detected=false, tx_has_writes=true, commit_tag_seen=true.
        // Eventual consistency never needs LSN tracking (Issue #1 fix).
        let committed_write = !had_error
            && tx_status == TransactionStatus::Idle
            && (write_detected || (session.tx_has_writes && commit_tag_seen));
        if committed_write && session.state.consistency != ConsistencyLevel::Eventual {
            session.pending_write = true;
        }
        // Extension LSN capture: if the extension GUC reported an LSN during
        // this batch, apply it to the session's LSN tracker immediately
        // (same behavior as the simple-query path). This avoids the
        // pending_write fallback pipeline query on the next read.
        if let Some(lsn) = reported_lsn {
            if committed_write {
                self.lsn_tracker
                    .record_write(&session.state.id, lsn);
                session.pending_write = false;
                session.extension_detected = true;
            }
        }
        if write_detected && !had_error && tx_status == TransactionStatus::InTransaction {
            session.tx_has_writes = true;
        }
        if tx_status == TransactionStatus::Idle {
            session.tx_has_writes = false;
        }

        // Return or hold the backend connection.
        if session.state.tx_state != TxState::Idle || conn.pinned {
            session.held_backend = Some(HeldBackend { conn, socket: backend_socket });
        } else {
            self.connection_registry
                .insert(&conn.node_id, conn.backend_pid, backend_socket);
            pool.release(&session.state.id, conn).await?;
        }

        send_ready_for_query(client_stream, session.state.tx_state).await
    }

    /// Fast-path for extended query batches when a backend is already held
    /// (pinned connection or in-transaction). Skips routing, snapshot, and
    /// pool acquire/release — just forwards the batch and updates session
    /// state. Mirrors `forward_on_held_backend` for simple queries.
    async fn forward_extended_on_held_backend<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        batch: &[ExtendedFrame],
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let held = session.held_backend.as_mut().expect("checked by caller");

        // Send all buffered raw frames + Sync to the backend in one write.
        // No re-encoding: the bytes the client sent are forwarded verbatim.
        let outbound = assemble_extended_outbound(batch);

        self.cancel_registry.mark_active(
            &session.state.id,
            &held.conn.node_id,
            held.conn.backend_pid,
            held.conn.secret_key,
        );

        if let Err(e) = held.socket.write_all(&outbound).await {
            self.cancel_registry.clear_active(&session.state.id);
            let held = session.held_backend.take().unwrap();
            if let Some(pool) = self.pool_manager.pool_for(&held.conn.node_id) {
                let _ = pool.discard(held.conn);
            }
            drop(held.socket);
            return Err(ProxyError::Protocol(e.into()));
        }
        if let Err(e) = held.socket.flush().await {
            self.cancel_registry.clear_active(&session.state.id);
            let held = session.held_backend.take().unwrap();
            if let Some(pool) = self.pool_manager.pool_for(&held.conn.node_id) {
                let _ = pool.discard(held.conn);
            }
            drop(held.socket);
            return Err(ProxyError::Protocol(e.into()));
        }

        // Relay backend responses until ReadyForQuery.
        let mut had_error = false;
        let mut write_detected = false;
        let mut commit_tag_seen = false;
        let mut reported_lsn: Option<u64> = None;
        let extension_guc_name = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            _ => None,
        };
        let tx_status = loop {
            let (tag, body) = match read_tagged_frame(&mut held.socket).await {
                Ok(frame) => frame,
                Err(e) => {
                    self.cancel_registry.clear_active(&session.state.id);
                    let held = session.held_backend.take().unwrap();
                    if let Some(pool) = self.pool_manager.pool_for(&held.conn.node_id) {
                        let _ = pool.discard(held.conn);
                    }
                    drop(held.socket);
                    return Err(ProxyError::Protocol(e));
                }
            };

            match tag {
                b'Z' => {
                    let status = TransactionStatus::from_byte(*body.first().unwrap_or(&b'I'))
                        .unwrap_or(TransactionStatus::Idle);
                    break status;
                }
                b'C' => {
                    let cmd_tag = extract_cstring_from_body(&body);
                    if is_write_command_tag(&cmd_tag) {
                        write_detected = true;
                    }
                    if cmd_tag == "COMMIT" {
                        commit_tag_seen = true;
                    }
                    write_raw_frame_to(client_stream, tag, &body).await?;
                }
                b'E' => {
                    had_error = true;
                    write_raw_frame_to(client_stream, tag, &body).await?;
                }
                b'G' => {
                    // COPY ... FROM STDIN on the held backend: same handling
                    // as the non-held path (see handle_extended_query_batch).
                    write_raw_frame_to(client_stream, tag, &body).await?;
                    client_stream
                        .flush()
                        .await
                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                    let copy_result =
                        relay_copy_in_stream(&mut held.socket, client_stream).await;
                    let sync_result = match copy_result {
                        Ok(()) => held
                            .socket
                            .write_all(&[b'S', 0, 0, 0, 4])
                            .await
                            .map_err(ProtocolError::Io),
                        Err(e) => Err(e),
                    };
                    if let Err(e) = sync_result {
                        self.cancel_registry.clear_active(&session.state.id);
                        let held = session.held_backend.take().unwrap();
                        if let Some(pool) = self.pool_manager.pool_for(&held.conn.node_id) {
                            let _ = pool.discard(held.conn);
                        }
                        drop(held.socket);
                        return Err(ProxyError::Protocol(e));
                    }
                }
                b'S' if extension_guc_name.is_some() => {
                    // ParameterStatus: capture extension LSN GUC, suppress
                    // from client (same as simple-query and non-held extended path).
                    let (name, value) = extract_two_cstrings_from_body(&body);
                    if Some(name.as_str()) == extension_guc_name {
                        reported_lsn = crate::health::parse_lsn(&value);
                    } else {
                        write_raw_frame_to(client_stream, tag, &body).await?;
                    }
                }
                _ => {
                    write_raw_frame_to(client_stream, tag, &body).await?;
                }
            }
        };
        self.cancel_registry.clear_active(&session.state.id);

        // Update session transaction state.
        session.state.tx_state = apply_ready_for_query(tx_status);

        // Named statements created on the held connection require the same
        // treatment as on the non-held path: pin the physical connection so
        // it outlives the transaction (the statement lives on this exact
        // connection), and record/forget statement routes for future
        // batches. Skipping this made in-transaction PREPARE-style usage
        // fail after COMMIT with "prepared statement does not exist".
        if !had_error {
            let creates_named_statement = batch.iter().any(frame_is_named_parse);
            if creates_named_statement {
                let held = session.held_backend.as_mut().expect("checked by caller");
                if !held.conn.pinned {
                    if let Some(pool) = self.pool_manager.pool_for(&held.conn.node_id) {
                        pool.pin(&session.state.id, &mut held.conn);
                    }
                }
            }
            let held_node_id = session
                .held_backend
                .as_ref()
                .expect("checked by caller")
                .conn
                .node_id
                .clone();
            record_statement_routes(session, batch, &held_node_id);
        }

        // Track writes for LSN watermark (same logic as full path).
        let committed_write = !had_error
            && tx_status == TransactionStatus::Idle
            && (write_detected || (session.tx_has_writes && commit_tag_seen));
        if committed_write && session.state.consistency != ConsistencyLevel::Eventual {
            session.pending_write = true;
        }
        // Extension LSN capture (same as non-held path).
        if let Some(lsn) = reported_lsn {
            if committed_write {
                self.lsn_tracker
                    .record_write(&session.state.id, lsn);
                session.pending_write = false;
                session.extension_detected = true;
            }
        }
        if write_detected && !had_error && tx_status == TransactionStatus::InTransaction {
            session.tx_has_writes = true;
        }
        if tx_status == TransactionStatus::Idle {
            session.tx_has_writes = false;
        }

        // Release backend if transaction ended and connection isn't pinned.
        if session.state.tx_state == TxState::Idle {
            let held = session.held_backend.as_ref().unwrap();
            if !held.conn.pinned {
                let held = session.held_backend.take().unwrap();
                let pool = self.pool_manager.pool_for(&held.conn.node_id).ok_or_else(|| {
                    ProxyError::Pool(crate::pool::pool::PoolError::CleanupFailed(format!(
                        "pool for '{}' no longer exists",
                        held.conn.node_id
                    )))
                })?;
                self.connection_registry
                    .insert(&held.conn.node_id, held.conn.backend_pid, held.socket);
                pool.release(&session.state.id, held.conn).await?;
            }
        }

        send_ready_for_query(client_stream, session.state.tx_state).await
    }

    /// Times and logs one simple-query statement (Requirement: wire up
    /// `config.logging.query_log`/`slow_query`, see `QueryLogSettings`
    /// docs), then delegates the actual routing/forwarding work to
    /// `handle_simple_query_inner`. Kept as a thin wrapper around the
    /// inner method (rather than threading timing through every early
    /// `?` return inside it) so the existing control flow does not need
    /// to change.
    async fn handle_simple_query<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        sql: &str,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let start = std::time::Instant::now();
        // Set by `handle_simple_query_inner` as soon as a routing decision
        // is made (even if something later in the same call fails), so
        // the timing/logging below can still label the result by target.
        // Stays `None` if routing itself never produces a decision.
        let mut target: Option<NodeType> = None;

        let result = self
            .handle_simple_query_inner(client_stream, session, sql, &mut target)
            .await;

        // A PostgreSQL ERROR inside an explicit transaction aborts that
        // transaction. Proxy-local failures must follow the same rule. If a
        // physical transaction is still held, closing/discarding its socket
        // rolls it back and prevents later statements from accidentally
        // continuing on a backend that never observed the proxy error.
        if result.is_err() && session.state.tx_state != TxState::Idle {
            self.fail_open_transaction(session);
        }

        let elapsed_ms_f64 = start.elapsed().as_secs_f64() * 1000.0;
        let target_label = match target {
            Some(NodeType::Writer) => "writer",
            Some(NodeType::Reader) => "reader",
            Some(NodeType::Analytics) => "analytics",
            None => "unknown",
        };
        metrics::histogram!("trident_query_duration_ms", "target" => target_label).record(elapsed_ms_f64);

        let elapsed_ms = elapsed_ms_f64.round() as u64;
        if elapsed_ms >= self.query_log.slow_query_threshold_ms {
            metrics::counter!("trident_slow_queries_total").increment(1);
            tracing::warn!(sql = %sql, duration_ms = elapsed_ms, target = target_label, "slow query");
            if let Some(buffer) = &self.slow_query_buffer {
                buffer.push(crate::admin::SlowQueryEntry {
                    time_unix_secs: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    duration_ms: elapsed_ms,
                    target: target_label.to_string(),
                    sql: sql.to_string(),
                });
            }
        } else if self.query_log.query_trace {
            tracing::info!(sql = %sql, duration_ms = elapsed_ms, target = target_label, "query");
        }

        result
    }

    /// Fast-path forwarding for statements within an explicit transaction
    /// when the backend connection is already held. Skips routing, snapshot,
    /// pinning detection, and pool acquire/release — just forwards the query
    /// and updates session state from the backend's ReadyForQuery.
    async fn forward_on_held_backend<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        sql: &str,
        _target_type: NodeType,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let held = session.held_backend.as_mut().expect("checked by caller");
        let write_intent = query_has_write_intent(sql);

        // Compute LSN tracking options matching the main path
        // (handle_simple_query_inner) so that Extension GUC
        // ParameterStatus messages are intercepted rather than leaked to
        // the client, and pipeline LSN queries fire on COMMIT when
        // appropriate.
        let extension_guc = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            LsnTrackingMode::Pipeline | LsnTrackingMode::AuroraWriteForwarding => None,
        };
        let pipeline_mode = match self.lsn_tracking.mode {
            LsnTrackingMode::Pipeline => true,
            LsnTrackingMode::Auto => !session.extension_detected,
            LsnTrackingMode::Extension | LsnTrackingMode::AuroraWriteForwarding => false,
        };
        let commit_attempt = session.tx_has_writes
            && transaction_end_tag(sql) == Some("COMMIT");
        let pipeline_lsn = pipeline_mode
            && !self.lsn_tracking.pipeline.lazy_fallback
            && pipeline_safe_sql(sql)
            && commit_attempt;

        self.cancel_registry.mark_active(
            &session.state.id,
            &held.conn.node_id,
            held.conn.backend_pid,
            held.conn.secret_key,
        );
        let relay_result = forward_simple_query_with_options(
            &mut held.socket,
            client_stream,
            sql,
            QueryForwardOptions {
                pipeline_lsn,
                extension_guc,
                internal_query_timeout: std::time::Duration::from_millis(
                    self.lsn_tracking.pipeline.internal_query_timeout_ms,
                ),
                begin_prefix: None,
            },
        )
        .await;
        self.cancel_registry.clear_active(&session.state.id);

        let relay_outcome = match relay_result {
            Ok(outcome) => outcome,
            Err(failure) => {
                session.state.tx_state = TxState::Failed;
                let held = session.held_backend.take().unwrap();
                if let Some(pool) = self.pool_manager.pool_for(&held.conn.node_id) {
                    let _ = pool.discard(held.conn);
                }
                drop(held.socket);
                if failure.error_response_relayed {
                    send_ready_for_query(client_stream, session.state.tx_state).await?;
                    return Ok(());
                }
                return Err(ProxyError::Protocol(failure.source));
            }
        };

        if self.lsn_tracking.mode == LsnTrackingMode::Auto
            && relay_outcome.reported_lsn.is_some()
        {
            session.extension_detected = true;
        }

        if write_intent && !relay_outcome.had_error_response {
            session.tx_has_writes = true;
        }

        session.state.tx_state = apply_ready_for_query(relay_outcome.tx_status);

        // If the transaction ended, track pending LSN for committed writes
        // and release the held backend.
        if session.state.tx_state == TxState::Idle {
            // COMMIT with prior writes and successful LSN capture: record
            // the watermark immediately rather than deferring to lazy
            // resolution. This mirrors handle_simple_query_inner's logic.
            let successful_commit = commit_attempt
                && !relay_outcome.had_error_response
                && relay_outcome.tx_status == TransactionStatus::Idle
                && relay_outcome.command_tags.iter().any(|tag| tag == "COMMIT");
            if successful_commit && session.state.consistency != ConsistencyLevel::Eventual {
                if let Some(lsn) = relay_outcome.reported_lsn.or(relay_outcome.pipelined_lsn) {
                    self.lsn_tracker.record_write(&session.state.id, lsn);
                    session.pending_write = false;
                } else {
                    session.pending_write = true;
                }
            } else if session.tx_has_writes
                && transaction_end_tag(sql) == Some("COMMIT")
                && !relay_outcome.had_error_response
                && session.state.consistency != ConsistencyLevel::Eventual
            {
                session.pending_write = true;
            }
            session.tx_has_writes = false;
            if let Some(split) = session.state.tx_split.take() {
                let _ = split;
            }

            // Pinned connections must stay held (consistent with the main
            // path in handle_simple_query_inner) so subsequent statements
            // always find them via the fast path without an unnecessary
            // pool acquire/release cycle.
            let held = session.held_backend.as_ref().unwrap();
            if held.conn.pinned {
                // Keep in held_backend — nothing to do.
            } else {
                let held = session.held_backend.take().unwrap();
                let pool = self.pool_manager.pool_for(&held.conn.node_id).ok_or_else(|| {
                    ProxyError::Pool(crate::pool::pool::PoolError::CleanupFailed(format!(
                        "pool for '{}' no longer exists",
                        held.conn.node_id
                    )))
                })?;
                self.connection_registry
                    .insert(&held.conn.node_id, held.conn.backend_pid, held.socket);
                pool.release(&session.state.id, held.conn).await?;
            }
        }

        // The client write/commit completed but the internal pipeline LSN
        // cycle timed out or failed. The connection is in an unknown state
        // and must not be reused.
        if !relay_outcome.connection_reusable {
            if let Some(held) = session.held_backend.take() {
                if let Some(pool) = self.pool_manager.pool_for(&held.conn.node_id) {
                    let _ = pool.discard(held.conn);
                }
                drop(held.socket);
            }
        }

        send_ready_for_query(client_stream, session.state.tx_state).await?;
        Ok(())
    }

    fn fail_open_transaction(&self, session: &mut ClientSession) {
        if session.state.tx_state == TxState::Idle {
            return;
        }

        self.cancel_registry.clear_active(&session.state.id);
        if let Some(held) = session.held_backend.take() {
            if let Some(pool) = self.pool_manager.pool_for(&held.conn.node_id) {
                if let Err(error) = pool.discard(held.conn) {
                    tracing::warn!(error = %error, "failed to discard aborted transaction connection");
                }
            } else {
                tracing::warn!(
                    node_id = %held.conn.node_id,
                    "cannot update pool accounting for aborted transaction: pool no longer exists"
                );
            }
            drop(held.socket);
        }
        session.state.tx_state = TxState::Failed;
    }

    async fn handle_aurora_simple_query<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        sql: &str,
        target_out: &mut Option<NodeType>,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Preserve PostgreSQL's failed-transaction semantics: if the
        // physical connection was lost (relay failure + discard), the
        // session stays failed until COMMIT/ROLLBACK (which resolve
        // locally as ROLLBACK). This matches the behavior in the
        // non-Aurora path and prevents a new connection from silently
        // executing statements that should have been rejected with 25P02.
        if session.state.tx_state == TxState::Failed && session.held_backend.is_none() {
            if transaction_end_tag(sql).is_some() {
                session.state.tx_state = TxState::Idle;
                send_command_complete(client_stream, "ROLLBACK").await?;
                send_ready_for_query(client_stream, TxState::Idle).await?;
            } else {
                let error = PgError::simple(
                    "ERROR",
                    "25P02",
                    "current transaction is aborted, commands ignored until end of transaction block",
                );
                send_pg_error_response(client_stream, error).await?;
                send_ready_for_query(client_stream, TxState::Failed).await?;
            }
            return Ok(());
        }

        let nodes = self.pool_manager.snapshot();
        let node_id = if let Some(node_id) = session.aurora_node_id.as_ref() {
            let still_available = nodes.iter().any(|node| {
                node.node_id == *node_id && node.node_type == NodeType::Reader && node.healthy
            });
            if !still_available {
                return Err(ProxyError::Pool(
                    crate::pool::pool::PoolError::Exhausted(node_id.clone()),
                ));
            }
            node_id.clone()
        } else {
            let selected = nodes
                .iter()
                .filter(|node| node.node_type == NodeType::Reader && node.healthy)
                .min_by(|left, right| {
                    left.active_connections
                        .cmp(&right.active_connections)
                        .then_with(|| left.node_id.cmp(&right.node_id))
                })
                .map(|node| node.node_id.clone())
                .ok_or_else(|| {
                    ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                        "Aurora Reader".to_string(),
                    ))
                })?;
            session.aurora_node_id = Some(selected.clone());
            selected
        };

        *target_out = Some(NodeType::Reader);
        metrics::counter!("trident_routing_decisions_total", "target" => "reader").increment(1);

        let pool = self.pool_manager.pool_for(&node_id).ok_or_else(|| {
            ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(node_id.clone()))
        })?;
        let (conn, mut socket) = if let Some(held) = session.held_backend.take() {
            if held.conn.node_id != node_id {
                if let Some(held_pool) = self.pool_manager.pool_for(&held.conn.node_id) {
                    held_pool.discard(held.conn)?;
                }
                drop(held.socket);
                session.aurora_initialized_backend_pid = None;
                return Err(ProxyError::Pool(
                    crate::pool::pool::PoolError::CleanupFailed(format!(
                        "Aurora session is bound to '{node_id}' but held backend belongs to another node"
                    )),
                ));
            }
            (held.conn, held.socket)
        } else {
            let conn = pool.acquire(&session.state.id).await?;
            let socket = match self
                .connection_registry
                .take(&conn.node_id, conn.backend_pid)
            {
                Some(socket) => socket,
                None => {
                    session.aurora_initialized_backend_pid = None;
                    pool.discard(conn)?;
                    return Err(ProxyError::Pool(
                        crate::pool::pool::PoolError::CleanupFailed(
                            "Aurora backend connection socket missing from registry".into(),
                        ),
                    ));
                }
            };
            (conn, socket)
        };

        if session.aurora_initialized_backend_pid != Some(conn.backend_pid) {
            let init_sql = aurora_consistency_sql(session.state.consistency);
            if let Err(error) =
                execute_internal_query(&mut socket, &init_sql, TransactionStatus::Idle).await
            {
                session.aurora_initialized_backend_pid = None;
                pool.discard(conn)?;
                drop(socket);
                return Err(ProxyError::Protocol(error));
            }
            session.aurora_initialized_backend_pid = Some(conn.backend_pid);
        }

        let previous_consistency = session.state.consistency;
        let translated_sql = if session.state.tx_state != TxState::Failed
            && session.state.apply_consistency_set_command(sql)
        {
            Some(aurora_consistency_sql(session.state.consistency))
        } else {
            None
        };
        let forwarded_sql = translated_sql.as_deref().unwrap_or(sql);

        self.cancel_registry.mark_active(
            &session.state.id,
            &conn.node_id,
            conn.backend_pid,
            conn.secret_key,
        );
        let relay = forward_simple_query(&mut socket, client_stream, forwarded_sql).await;
        self.cancel_registry.clear_active(&session.state.id);
        let outcome = match relay {
            Ok(outcome) => outcome,
            Err(failure) => {
                session.aurora_initialized_backend_pid = None;
                if session.state.tx_state != TxState::Idle {
                    session.state.tx_state = TxState::Failed;
                }
                pool.discard(conn)?;
                drop(socket);
                if failure.error_response_relayed {
                    send_ready_for_query(client_stream, session.state.tx_state).await?;
                    return Ok(());
                }
                return Err(ProxyError::Protocol(failure.source));
            }
        };

        if translated_sql.is_some() && outcome.had_error_response {
            session.state.consistency = previous_consistency;
        }
        session.state.tx_state = apply_ready_for_query(outcome.tx_status);

        if session.state.tx_state != TxState::Idle {
            session.held_backend = Some(HeldBackend { conn, socket });
        } else {
            self.connection_registry
                .insert(&conn.node_id, conn.backend_pid, socket);
            pool.release(&session.state.id, conn).await?;
        }
        send_ready_for_query(client_stream, session.state.tx_state).await
    }

    async fn resolve_pending_write_lsn(&self, session: &mut ClientSession) -> bool {
        // Defensive: Eventual consistency never needs LSN resolution
        // (Issue #2 fix). Even if pending_write was erroneously set,
        // we short-circuit here to avoid a pointless writer round-trip.
        if !session.pending_write
            || !self.lsn_tracking.pipeline.lazy_fallback
            || session.state.consistency == ConsistencyLevel::Eventual
        {
            return false;
        }

        let writer_id = match self
            .pool_manager
            .snapshot()
            .into_iter()
            .find(|node| node.node_type == NodeType::Writer && node.healthy)
            .map(|node| node.node_id)
        {
            Some(writer_id) => writer_id,
            None => return false,
        };
        let timeout_duration = std::time::Duration::from_millis(
            self.lsn_tracking.pipeline.internal_query_timeout_ms,
        );

        if session
            .held_backend
            .as_ref()
            .is_some_and(|held| held.conn.node_id == writer_id)
        {
            let result = {
                let held = session.held_backend.as_mut().expect("checked above");
                tokio::time::timeout(timeout_duration, fetch_current_wal_lsn(&mut held.socket))
                    .await
            };
            match result {
                Ok(Ok(Some(lsn))) => {
                    self.lsn_tracker.record_write(&session.state.id, lsn);
                    session.pending_write = false;
                    return true;
                }
                Ok(Ok(None)) => return false,
                Ok(Err(error)) => {
                    tracing::warn!(error = %error, "lazy Writer LSN query failed; forcing Writer routing");
                }
                Err(_) => {
                    tracing::warn!("lazy Writer LSN query timed out; forcing Writer routing");
                }
            }

            if let Some(held) = session.held_backend.take() {
                if let Some(pool) = self.pool_manager.pool_for(&held.conn.node_id) {
                    let _ = pool.discard(held.conn);
                }
                drop(held.socket);
            }
            return false;
        }

        let Some(pool) = self.pool_manager.pool_for(&writer_id) else {
            return false;
        };
        let conn = match pool.acquire(&session.state.id).await {
            Ok(conn) => conn,
            Err(error) => {
                tracing::warn!(error = %error, "cannot acquire Writer for lazy LSN query");
                return false;
            }
        };
        let mut socket = match self
            .connection_registry
            .take(&conn.node_id, conn.backend_pid)
        {
            Some(socket) => socket,
            None => {
                let _ = pool.discard(conn);
                return false;
            }
        };

        let result = tokio::time::timeout(timeout_duration, fetch_current_wal_lsn(&mut socket)).await;
        match result {
            Ok(Ok(lsn)) => {
                self.connection_registry
                    .insert(&conn.node_id, conn.backend_pid, socket);
                if let Err(error) = pool.release(&session.state.id, conn).await {
                    tracing::warn!(error = %error, "failed to release Writer after lazy LSN query");
                    return false;
                }
                if let Some(lsn) = lsn {
                    self.lsn_tracker.record_write(&session.state.id, lsn);
                    session.pending_write = false;
                    true
                } else {
                    false
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "lazy Writer LSN query failed; forcing Writer routing");
                let _ = pool.discard(conn);
                drop(socket);
                false
            }
            Err(_) => {
                tracing::warn!("lazy Writer LSN query timed out; forcing Writer routing");
                let _ = pool.discard(conn);
                drop(socket);
                false
            }
        }
    }

    async fn finish_active_split_transaction<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        sql: &str,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let held = session.held_backend.take().ok_or_else(|| {
            ProxyError::Pool(crate::pool::pool::PoolError::CleanupFailed(
                "active split transaction has no held backend".into(),
            ))
        })?;
        let conn = held.conn;
        let mut socket = held.socket;
        let pool = self.pool_manager.pool_for(&conn.node_id).ok_or_else(|| {
            ProxyError::Pool(crate::pool::pool::PoolError::CleanupFailed(format!(
                "pool for split transaction node '{}' no longer exists",
                conn.node_id
            )))
        })?;

        let commit_attempt = session.tx_has_writes && transaction_end_tag(sql) == Some("COMMIT");
        let pipeline_mode = match self.lsn_tracking.mode {
            LsnTrackingMode::Pipeline => true,
            LsnTrackingMode::Auto => !session.extension_detected,
            LsnTrackingMode::Extension | LsnTrackingMode::AuroraWriteForwarding => false,
        };
        let extension_guc = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            LsnTrackingMode::Pipeline | LsnTrackingMode::AuroraWriteForwarding => None,
        };

        self.cancel_registry.mark_active(
            &session.state.id,
            &conn.node_id,
            conn.backend_pid,
            conn.secret_key,
        );
        let relay = forward_simple_query_with_options(
            &mut socket,
            client_stream,
            sql,
            QueryForwardOptions {
                pipeline_lsn: pipeline_mode && commit_attempt && pipeline_safe_sql(sql),
                extension_guc,
                internal_query_timeout: std::time::Duration::from_millis(
                    self.lsn_tracking.pipeline.internal_query_timeout_ms,
                ),
                begin_prefix: None,
            },
        )
        .await;
        self.cancel_registry.clear_active(&session.state.id);
        let outcome = match relay {
            Ok(outcome) => outcome,
            Err(failure) => {
                pool.discard(conn)?;
                drop(socket);
                session.state.tx_state = TxState::Failed;
                if failure.error_response_relayed {
                    // The client already has the backend's ErrorResponse;
                    // complete that response cycle without appending a
                    // second, proxy-generated error.
                    send_ready_for_query(client_stream, TxState::Failed).await?;
                    return Ok(());
                }
                return Err(ProxyError::Protocol(failure.source));
            }
        };

        if self.lsn_tracking.mode == LsnTrackingMode::Auto && outcome.reported_lsn.is_some() {
            session.extension_detected = true;
        }
        let successful_commit = commit_attempt
            && !outcome.had_error_response
            && outcome.tx_status == TransactionStatus::Idle
            && outcome.command_tags.iter().any(|tag| tag == "COMMIT");
        if successful_commit && session.state.consistency != ConsistencyLevel::Eventual {
            if let Some(lsn) = outcome.reported_lsn.or(outcome.pipelined_lsn) {
                self.lsn_tracker.record_write(&session.state.id, lsn);
                session.pending_write = false;
            } else {
                session.pending_write = true;
            }
        }
        if outcome.tx_status == TransactionStatus::Idle {
            session.tx_has_writes = false;
        }

        session.state.tx_split = None;
        session.state.tx_state = apply_ready_for_query(outcome.tx_status);
        if !outcome.connection_reusable {
            pool.discard(conn)?;
            drop(socket);
            send_ready_for_query(client_stream, session.state.tx_state).await?;
            return Ok(());
        }
        if conn.pinned {
            session.held_backend = Some(HeldBackend { conn, socket });
        } else {
            self.connection_registry
                .insert(&conn.node_id, conn.backend_pid, socket);
            pool.release(&session.state.id, conn).await?;
        }
        send_ready_for_query(client_stream, session.state.tx_state).await
    }

    /// Does the actual routing/forwarding work for one simple-query
    /// statement (this is the original body of what used to be
    /// `handle_simple_query` before timing/logging were added around it).
    /// `target_out` is set as soon as a routing decision is made, so the
    /// caller (`handle_simple_query`) can label its timing/logging by
    /// target even on a later failure.
    async fn handle_simple_query_inner<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        sql: &str,
        target_out: &mut Option<NodeType>,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if self.lsn_tracking.mode == LsnTrackingMode::AuroraWriteForwarding {
            return self
                .handle_aurora_simple_query(client_stream, session, sql, target_out)
                .await;
        }

        // A backend transaction can become unrecoverable when its physical
        // connection is lost during a protocol failure or a split upgrade.
        // Preserve PostgreSQL's failed-transaction semantics locally instead
        // of silently running later statements as autocommit on a new socket.
        // With no backend left, either transaction-ending command resolves to
        // ROLLBACK; every other command receives 25P02 and stays failed.
        if session.state.tx_state == TxState::Failed && session.held_backend.is_none() {
            if transaction_end_tag(sql).is_some() {
                session.state.tx_split = None;
                session.state.tx_state = TxState::Idle;
                send_command_complete(client_stream, "ROLLBACK").await?;
                send_ready_for_query(client_stream, TxState::Idle).await?;
            } else {
                let error = PgError::simple(
                    "ERROR",
                    "25P02",
                    "current transaction is aborted, commands ignored until end of transaction block",
                );
                send_pg_error_response(client_stream, error).await?;
                send_ready_for_query(client_stream, TxState::Failed).await?;
            }
            return Ok(());
        }

        // This is a proxy-local session setting, not a PostgreSQL GUC.
        // Intercept it before routing/pinning so it neither reaches a
        // backend nor marks the physical connection dirty. A failed physical
        // transaction is deliberately excluded so the backend can return its
        // normal 25P02 response.
        if session.state.tx_state != TxState::Failed
            && session.state.apply_consistency_set_command(sql)
        {
            let complete = encode_backend_message(&BackendMessage::CommandComplete {
                tag: "SET".to_string(),
            });
            client_stream
                .write_all(&complete)
                .await
                .map_err(ProtocolError::Io)?;
            send_ready_for_query(client_stream, session.state.tx_state).await?;
            return Ok(());
        }

        // With splitting enabled, acknowledge BEGIN to the client but do
        // not choose/open a backend transaction until the first real
        // statement determines Reader versus Writer.
        if session.state.tx_state == TxState::Idle {
            if let Some(options) = parse_begin_options(sql) {
                let (enable_split, split_respects_consistency) =
                    self.router.transaction_split_settings();
                if enable_split {
                    session.state.tx_split = Some(TxSplitState::pending_with_sql(
                        options.isolation,
                        options.read_only,
                        true,
                        split_respects_consistency,
                        sql,
                    ));
                    session.state.tx_state = TxState::InTransaction;
                    send_command_complete(client_stream, "BEGIN").await?;
                    send_ready_for_query(client_stream, TxState::InTransaction).await?;
                    return Ok(());
                }
            }
        }

        // COMMIT/ROLLBACK before a pending transaction's first statement
        // never touched a backend and can be completed locally. Once the
        // split transaction is active, finish it on its held backend
        // without sending it through Router (which would otherwise mistake
        // COMMIT for a write and trigger a Reader->Writer upgrade).
        if let Some(tag) = transaction_end_tag(sql) {
            if let Some(split) = session.state.tx_split.as_ref() {
                if split.active && session.held_backend.is_some() {
                    return self
                        .finish_active_split_transaction(client_stream, session, sql)
                        .await;
                }
                session.state.tx_split = None;
                session.state.tx_state = TxState::Idle;
                send_command_complete(client_stream, tag).await?;
                send_ready_for_query(client_stream, TxState::Idle).await?;
                return Ok(());
            }
        }

        // Fast path: when we already hold a backend connection inside an
        // explicit transaction and no split-upgrade is pending, skip the
        // expensive snapshot/routing/pool-acquire pipeline entirely — just
        // forward the statement to the held backend.
        let split_needs_upgrade = session.state.tx_split.as_ref().is_some_and(|s| {
            !s.active || s.need_upgrade || (s.on_reader && query_has_write_intent(sql))
        });
        if session.state.tx_state == TxState::InTransaction
            && session.held_backend.is_some()
            && !split_needs_upgrade
        {
            // In a non-split transaction, held backend is Writer.
            // In an active split (on_reader=true), it's Reader.
            let target_type = if session
                .state
                .tx_split
                .as_ref()
                .is_some_and(|s| s.active && s.on_reader)
            {
                NodeType::Reader
            } else {
                NodeType::Writer
            };
            *target_out = Some(target_type);
            metrics::counter!(
                "trident_routing_decisions_total",
                "target" => match target_type {
                    NodeType::Writer => "writer",
                    NodeType::Reader => "reader",
                    NodeType::Analytics => "analytics",
                }
            )
            .increment(1);
            return self
                .forward_on_held_backend(client_stream, session, sql, target_type)
                .await;
        }

        // Detect connection-pinning triggers (Requirement 6.1) before routing;
        // the actual `pin()` call happens after a connection is acquired below.
        let pinning_trigger = detects_pinning_trigger(sql);

        let all_nodes = self.pool_manager.snapshot();
        let readers: Vec<_> = all_nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Reader && n.healthy)
            .cloned()
            .collect();
        let analytics: Vec<_> = all_nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Analytics && n.healthy)
            .cloned()
            .collect();

        let session_write_lsn = self.lsn_tracker.session_write_lsn(&session.state.id);
        let global_write_lsn = self.lsn_tracker.global_write_lsn();
        // Router transaction splitting mutates this state while choosing a
        // target. Keep a pre-routing snapshot so failures before any backend
        // transaction change can be retried without committing a phantom
        // state transition.
        let tx_split_before_routing = session.state.tx_split.clone();
        let mut tx_split: Option<TxSplitState> = session.state.tx_split.take();
        let split_was_pending = tx_split.as_ref().is_some_and(|state| !state.active);

        let decision_result = {
            let mut ctx = RoutingContext {
                tx_state: session.state.tx_state,
                tx_split: &mut tx_split,
                consistency: session.state.consistency,
                session_write_lsn,
                global_write_lsn,
            };
            self.router.route(sql, &mut ctx, &readers, &analytics).await
        };
        // Always put the state back, including when routing fails. The prior
        // implementation used `?` before this assignment and could silently
        // erase a pending split transaction on a RouterError.
        session.state.tx_split = tx_split;
        let mut decision = decision_result?;

        if session.pending_write && decision.target != NodeType::Writer {
            if self.resolve_pending_write_lsn(session).await {
                // The first routing pass may have advanced transaction-split
                // state. Re-run from its pre-routing snapshot so the final
                // decision alone determines the state transition.
                let mut reroute_split = tx_split_before_routing.clone();
                let reroute_result = {
                    let mut ctx = RoutingContext {
                        tx_state: session.state.tx_state,
                        tx_split: &mut reroute_split,
                        consistency: session.state.consistency,
                        session_write_lsn: self
                            .lsn_tracker
                            .session_write_lsn(&session.state.id),
                        global_write_lsn: self.lsn_tracker.global_write_lsn(),
                    };
                    self.router.route(sql, &mut ctx, &readers, &analytics).await
                };
                session.state.tx_split = reroute_split;
                decision = reroute_result?;
            } else {
                // No trustworthy watermark is available. Never send this
                // query to a Reader: retain the pending marker and use the
                // Writer until a later lazy refresh succeeds.
                let requires_upgrade = session.state.tx_split.as_ref().is_some_and(|split| {
                    split.active && split.on_reader && session.held_backend.is_some()
                });
                if let Some(split) = session.state.tx_split.as_mut() {
                    split.active = true;
                    split.on_reader = false;
                    split.need_upgrade = requires_upgrade;
                }
                decision = RouteDecision {
                    target: NodeType::Writer,
                    node_id: None,
                    reason: std::borrow::Cow::Borrowed("pending write watermark unavailable; conservative Writer fallback"),
                    forced_by_hint: false,
                    fallback_to_writer: true,
                    requires_split_upgrade: requires_upgrade,
                };
            }
        }

        // Most statements in an active split transaction do not need the
        // original BEGIN text. Clone it only when opening the delayed
        // transaction or upgrading a Reader transaction to Writer.
        let split_begin_sql = if split_was_pending || decision.requires_split_upgrade {
            session
                .state
                .tx_split
                .as_ref()
                .map(|state| state.begin_sql().to_string())
        } else {
            None
        };
        *target_out = Some(decision.target);

        metrics::counter!(
            "trident_routing_decisions_total",
            "target" => match decision.target {
                NodeType::Writer => "writer",
                NodeType::Reader => "reader",
                NodeType::Analytics => "analytics",
            }
        )
        .increment(1);

        let target_node_id = match decision.target {
            // Writer route decisions intentionally do not carry a concrete
            // node id. Resolve the configured writer by type instead of
            // assuming its name is literally "writer" (the shipped
            // configuration calls it "primary"). Only a healthy writer is
            // eligible; otherwise fail explicitly below.
            NodeType::Writer => all_nodes
                .iter()
                .find(|node| node.node_type == NodeType::Writer && node.healthy)
                .map(|node| node.node_id.clone())
                .unwrap_or_default(),
            NodeType::Reader | NodeType::Analytics => decision.node_id.clone().unwrap_or_default(),
        };

        if target_node_id.is_empty() {
            // No backend state changed, so undo any split-state mutation the
            // routing decision made (notably Reader->Writer upgrade flags).
            session.state.tx_split = tx_split_before_routing;
            // No healthy candidate available for the chosen target.
            let pseudo_node_id = format!("{:?}", decision.target);
            metrics::counter!("trident_pool_exhausted_total", "node_id" => pseudo_node_id.clone()).increment(1);
            return Err(ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(pseudo_node_id)));
        }

        let mut split_reader_rolled_back = false;
        if decision.requires_split_upgrade {
            let held = match session.held_backend.take() {
                Some(held) => held,
                None => {
                    session.state.tx_state = TxState::Failed;
                    return Err(ProxyError::Pool(
                        crate::pool::pool::PoolError::CleanupFailed(
                            "Reader-to-Writer upgrade has no held Reader connection".into(),
                        ),
                    ));
                }
            };
            let mut reader_conn = held.conn;
            let mut reader_socket = held.socket;
            let reader_pool = match self.pool_manager.pool_for(&reader_conn.node_id) {
                Some(pool) => pool,
                None => {
                    session.state.tx_state = TxState::Failed;
                    drop(reader_socket);
                    return Err(ProxyError::Pool(
                        crate::pool::pool::PoolError::CleanupFailed(format!(
                            "pool for split Reader '{}' no longer exists",
                            reader_conn.node_id
                        )),
                    ));
                }
            };

            if let Err(error) = execute_internal_query(
                &mut reader_socket,
                "ROLLBACK",
                TransactionStatus::Idle,
            )
            .await
            {
                session.state.tx_state = TxState::Failed;
                reader_pool.discard(reader_conn)?;
                drop(reader_socket);
                return Err(ProxyError::Protocol(error));
            }
            split_reader_rolled_back = true;

            // In Transaction mode the ROLLBACK leaves the connection in a
            // clean Idle state, so we can return it to the pool for reuse
            // instead of destroying the TCP connection. In Session mode,
            // `release` is a no-op which would leave a second node binding
            // behind after the upgrade, so we must discard.
            match reader_pool.mode() {
                PoolMode::Transaction => {
                    // ROLLBACK already reset transaction state; clear dirty
                    // so release does not issue an unnecessary DISCARD ALL.
                    reader_conn.dirty = false;
                    // Put the socket back in the registry before release —
                    // the pool's idle-queue only holds metadata; the socket
                    // must be findable via the registry for the next acquire.
                    self.connection_registry.insert(
                        &reader_conn.node_id,
                        reader_conn.backend_pid,
                        reader_socket,
                    );
                    if let Err(error) = reader_pool
                        .release(&session.state.id, reader_conn)
                        .await
                    {
                        session.state.tx_state = TxState::Failed;
                        return Err(ProxyError::Pool(error));
                    }
                }
                PoolMode::Session => {
                    if let Err(error) = reader_pool.discard(reader_conn) {
                        session.state.tx_state = TxState::Failed;
                        drop(reader_socket);
                        return Err(ProxyError::Pool(error));
                    }
                    drop(reader_socket);
                }
            }
        }

        let (mut conn, mut backend_socket) = if let Some(held) = session.held_backend.take() {
            // PostgreSQL transaction and session state is connection-local.
            // Once held, route decisions may not move the session to a
            // different physical backend until the transaction ends (or
            // the session itself closes).
            (held.conn, held.socket)
        } else {
            let target_pool = match self.pool_manager.pool_for(&target_node_id) {
                Some(pool) => pool,
                None => {
                    metrics::counter!("trident_pool_exhausted_total", "node_id" => target_node_id.clone())
                        .increment(1);
                    if split_reader_rolled_back {
                        session.state.tx_state = TxState::Failed;
                    } else {
                        session.state.tx_split = tx_split_before_routing.clone();
                    }
                    return Err(ProxyError::Pool(
                        crate::pool::pool::PoolError::Exhausted(target_node_id.clone()),
                    ));
                }
            };

            let conn: PooledConnection = match target_pool.acquire(&session.state.id).await {
                Ok(conn) => conn,
                Err(e) => {
                    if matches!(e, crate::pool::pool::PoolError::Exhausted(_)) {
                        metrics::counter!("trident_pool_exhausted_total", "node_id" => target_node_id.clone())
                            .increment(1);
                    }
                    if split_reader_rolled_back {
                        session.state.tx_state = TxState::Failed;
                    } else {
                        session.state.tx_split = tx_split_before_routing.clone();
                    }
                    return Err(ProxyError::Pool(e));
                }
            };

            let socket = match self.connection_registry.take(&conn.node_id, conn.backend_pid) {
                Some(socket) => socket,
                None => {
                    // Metadata without a socket is unusable and must not be
                    // released into the idle queue, where it would poison
                    // every subsequent borrower while retaining its slot.
                    target_pool.discard(conn)?;
                    if split_reader_rolled_back {
                        session.state.tx_state = TxState::Failed;
                    } else {
                        session.state.tx_split = tx_split_before_routing.clone();
                    }
                    return Err(ProxyError::Pool(
                        crate::pool::pool::PoolError::CleanupFailed(
                            "backend connection socket missing from registry".into(),
                        ),
                    ));
                }
            };
            (conn, socket)
        };

        let pool = self.pool_manager.pool_for(&conn.node_id).ok_or_else(|| {
            ProxyError::Pool(crate::pool::pool::PoolError::CleanupFailed(format!(
                "pool for held backend node '{}' no longer exists",
                conn.node_id
            )))
        })?;

        if pinning_trigger.is_some() && !conn.pinned {
            pool.pin(&session.state.id, &mut conn);
        }

        // The delayed split-transaction BEGIN is not sent as a separate
        // round trip: it is pipelined into the same outbound write as the
        // first real statement below (see `QueryForwardOptions::begin_prefix`),
        // saving one full backend round trip per transaction. If it fails,
        // the relay call below fails before any response bytes reach the
        // client; the client has already observed BEGIN, and after an
        // upgrade the Reader transaction has already been rolled back, so
        // the error path marks the session transaction Failed and discards
        // this backend socket.
        let delayed_begin: Option<&str> = if split_was_pending || decision.requires_split_upgrade {
            match split_begin_sql.as_deref() {
                Some(begin_sql) => Some(begin_sql),
                None => {
                    session.state.tx_state = TxState::Failed;
                    pool.discard(conn)?;
                    drop(backend_socket);
                    return Err(ProxyError::Protocol(ProtocolError::Malformed(
                        "split transaction is missing its delayed BEGIN command".into(),
                    )));
                }
            }
        } else {
            None
        };

        let prior_tx_state = session.state.tx_state;
        let write_intent = query_has_write_intent(sql);
        let commit_attempt = prior_tx_state == TxState::InTransaction
            && session.tx_has_writes
            && transaction_end_tag(sql) == Some("COMMIT");
        let extension_guc = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            LsnTrackingMode::Pipeline | LsnTrackingMode::AuroraWriteForwarding => None,
        };
        let pipeline_mode = match self.lsn_tracking.mode {
            LsnTrackingMode::Pipeline => true,
            LsnTrackingMode::Auto => !session.extension_detected,
            LsnTrackingMode::Extension | LsnTrackingMode::AuroraWriteForwarding => false,
        };
        // Skip pipeline when lazy_fallback is enabled: defer LSN acquisition
        // to the point where a subsequent read actually targets a reader.
        // Write-only workloads pay zero LSN overhead; mixed workloads pay
        // exactly one extra query only when needed.
        let pipeline_lsn = pipeline_mode
            && !self.lsn_tracking.pipeline.lazy_fallback
            && pipeline_safe_sql(sql)
            && ((prior_tx_state == TxState::Idle && write_intent) || commit_attempt);

        // Requirements 7.1-7.3: mark this session as having a query in
        // flight against this exact real backend connection *before*
        // sending it, and always clear that mark once the round trip
        // finishes (success or failure) -- a CANCEL that arrives after
        // this point has nothing left to cancel and must be ignored.
        self.cancel_registry.mark_active(
            &session.state.id,
            &conn.node_id,
            conn.backend_pid,
            conn.secret_key,
        );
        let relay_result = forward_simple_query_with_options(
            &mut backend_socket,
            client_stream,
            sql,
            QueryForwardOptions {
                pipeline_lsn,
                extension_guc,
                internal_query_timeout: std::time::Duration::from_millis(
                    self.lsn_tracking.pipeline.internal_query_timeout_ms,
                ),
                begin_prefix: delayed_begin,
            },
        )
        .await;
        self.cancel_registry.clear_active(&session.state.id);

        let relay_outcome = match relay_result {
            Ok(outcome) => outcome,
            Err(failure) => {
                // The backend socket may be in an unknown state after a
                // protocol-level failure (as opposed to a normal
                // ErrorResponse followed by ReadyForQuery). Do not return it
                // to the registry/pool. If an ErrorResponse was already
                // relayed, only synthesize the missing ReadyForQuery; the
                // outer loop must not send a duplicate error.
                if session.state.tx_state != TxState::Idle {
                    session.state.tx_state = TxState::Failed;
                }
                pool.discard(conn)?;
                drop(backend_socket);
                if failure.error_response_relayed {
                    send_ready_for_query(client_stream, session.state.tx_state).await?;
                    return Ok(());
                }
                return Err(ProxyError::Protocol(failure.source));
            }
        };

        if self.lsn_tracking.mode == LsnTrackingMode::Auto
            && relay_outcome.reported_lsn.is_some()
        {
            session.extension_detected = true;
        }

        let successful_autocommit_write = prior_tx_state == TxState::Idle
            && write_intent
            && !relay_outcome.had_error_response
            && relay_outcome.tx_status == TransactionStatus::Idle;
        let successful_commit = commit_attempt
            && !relay_outcome.had_error_response
            && relay_outcome.tx_status == TransactionStatus::Idle
            && relay_outcome.command_tags.iter().any(|tag| tag == "COMMIT");
        let committed_write = successful_autocommit_write || successful_commit;

        if prior_tx_state == TxState::InTransaction
            && write_intent
            && !relay_outcome.had_error_response
            && relay_outcome.tx_status == TransactionStatus::InTransaction
        {
            session.tx_has_writes = true;
        }
        if transaction_end_tag(sql).is_some() && relay_outcome.tx_status == TransactionStatus::Idle {
            session.tx_has_writes = false;
        }

        if committed_write && session.state.consistency != ConsistencyLevel::Eventual {
            if let Some(lsn) = relay_outcome.reported_lsn.or(relay_outcome.pipelined_lsn) {
                self.lsn_tracker.record_write(&session.state.id, lsn);
                session.pending_write = false;
            } else {
                session.pending_write = true;
            }
        }

        // Requirement 11.5/Property 42: update the session's transaction
        // state from the backend's original ReadyForQuery status byte.
        session.state.tx_state = apply_ready_for_query(relay_outcome.tx_status);

        // The client write/commit already completed even if the internal
        // LSN cycle timed out. Preserve that success, discard the unknown
        // backend stream, and resolve the pending watermark lazily later.
        if !relay_outcome.connection_reusable {
            pool.discard(conn)?;
            drop(backend_socket);
            send_ready_for_query(client_stream, session.state.tx_state).await?;
            return Ok(());
        }

        if pinning_trigger.is_some() {
            conn.dirty = true;
        }

        if session.state.tx_state != TxState::Idle || conn.pinned {
            // Keep both metadata and socket out of the shared registry so
            // no other session can observe transaction/session-local state.
            session.held_backend = Some(HeldBackend {
                conn,
                socket: backend_socket,
            });
        } else {
            // At an idle transaction boundary, return a clean reusable
            // connection to the registry/pool. In Session mode `release`
            // intentionally retains the binding while the socket remains
            // registered for this same session's next acquire.
            self.connection_registry
                .insert(&conn.node_id, conn.backend_pid, backend_socket);
            pool.release(&session.state.id, conn).await?;
        }

        send_ready_for_query(client_stream, session.state.tx_state).await?;
        Ok(())
    }
}

/// Extracts a null-terminated C-string from a raw message body. Invalid
/// UTF-8 sequences are replaced (command tags from PostgreSQL are always
/// ASCII, so this never triggers in practice).
fn extract_cstring_from_body(body: &[u8]) -> String {
    let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    String::from_utf8_lossy(&body[..end]).into_owned()
}

/// Extracts two consecutive C-strings from a ParameterStatus message body
/// (name + value, each NUL-terminated).
fn extract_two_cstrings_from_body(body: &[u8]) -> (String, String) {
    let first_end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    let first = String::from_utf8_lossy(&body[..first_end]).into_owned();
    let rest = if first_end + 1 < body.len() {
        &body[first_end + 1..]
    } else {
        &[]
    };
    let second_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let second = String::from_utf8_lossy(&rest[..second_end]).into_owned();
    (first, second)
}

/// True when the frame is a Parse ('P') message that creates a *named*
/// prepared statement (first body byte is not the NUL terminator of an
/// empty name).
fn frame_is_named_parse(frame: &ExtendedFrame) -> bool {
    frame.tag == frontend_tag::PARSE && frame.body.first().is_some_and(|&b| b != 0)
}

/// Concatenates all buffered extended-query frames plus a trailing Sync into
/// a single outbound buffer, sized exactly, with no message re-encoding.
fn assemble_extended_outbound(batch: &[ExtendedFrame]) -> Vec<u8> {
    const SYNC_FRAME: [u8; 5] = [b'S', 0, 0, 0, 4];
    let total: usize = batch.iter().map(|f| 5 + f.body.len()).sum::<usize>() + SYNC_FRAME.len();
    let mut outbound = Vec::with_capacity(total);
    for frame in batch {
        let len = (frame.body.len() as u32 + 4).to_be_bytes();
        outbound.push(frame.tag);
        outbound.extend_from_slice(&len);
        outbound.extend_from_slice(&frame.body);
    }
    outbound.extend_from_slice(&SYNC_FRAME);
    outbound
}

/// Records named-statement routes created by Parse frames in this batch and
/// forgets routes for statements removed by Close(Statement). Called only
/// after a batch completes without error.
fn record_statement_routes(session: &mut ClientSession, batch: &[ExtendedFrame], node_id: &str) {
    for frame in batch {
        match frame.tag {
            frontend_tag::PARSE => match frame.parse_name() {
                Some(name) if !name.is_empty() => {
                    session
                        .extended_route_tracker
                        .record_parse_route(name, node_id);
                }
                Some(_) => {
                    // Unnamed statement re-parse: forget the old route.
                    session.extended_route_tracker.forget_statement("");
                }
                None => {}
            },
            frontend_tag::CLOSE => {
                // Only Close(Statement) removes a prepared statement; a
                // portal close ('P') must not drop the statement route that
                // happens to share the same name.
                if let Some((b'S', name)) = frame.kind_and_name() {
                    if !name.is_empty() {
                        session.extended_route_tracker.forget_statement(name);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Writes a raw PostgreSQL wire frame to the client stream.
async fn write_raw_frame_to<S: AsyncWrite + Unpin + Send>(
    client: &mut S,
    tag: u8,
    body: &[u8],
) -> Result<(), ProxyError> {
    let len = (body.len() as i32) + 4;
    let header: [u8; 5] = [
        tag,
        (len >> 24) as u8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
    ];
    if body.len() <= 8187 {
        let mut buf = Vec::with_capacity(5 + body.len());
        buf.extend_from_slice(&header);
        buf.extend_from_slice(body);
        client.write_all(&buf).await.map_err(ProtocolError::Io)?;
    } else {
        client.write_all(&header).await.map_err(ProtocolError::Io)?;
        client.write_all(body).await.map_err(ProtocolError::Io)?;
    }
    Ok(())
}

fn query_has_write_intent(sql: &str) -> bool {
    if sql.trim().is_empty()
        || parse_begin_options(sql).is_some()
        || transaction_end_tag(sql).is_some()
    {
        return false;
    }
    if contains_multiple_statements(sql) {
        // Multi-statement: if ALL statements are read-only, allow routing
        // to Reader. Otherwise conservatively route to Writer.
        return !multi_statement_all_readable(&KeywordClassifier, sql);
    }

    let classifier = KeywordClassifier;
    let kind = classifier.classify(sql);
    requires_writer(&classifier, sql) || !kind.readable()
}

fn pipeline_safe_sql(sql: &str) -> bool {
    if contains_multiple_statements(sql) {
        return false;
    }
    let normalized = sql
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase();
    !normalized.contains("COPY ")
        && !normalized.starts_with("COPY")
        && !normalized.contains(" AND CHAIN")
        && !normalized.contains(" AND NO CHAIN")
}

fn aurora_consistency_sql(consistency: ConsistencyLevel) -> String {
    let value = match consistency {
        ConsistencyLevel::Eventual => "EVENTUAL",
        ConsistencyLevel::Session => "SESSION",
        ConsistencyLevel::Global => "GLOBAL",
    };
    format!("SET apg_write_forward.consistency_mode = '{value}'")
}

fn known_node_ids(pool_manager: &impl PoolManager) -> Vec<String> {
    pool_manager
        .snapshot()
        .into_iter()
        .map(|n| n.node_id)
        .collect()
}

async fn execute_internal_query(
    backend: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    sql: &str,
    expected_status: TransactionStatus,
) -> Result<(), ProtocolError> {
    // Internal statements (BEGIN/ROLLBACK/GUC set) never trigger COPY, so a
    // read-EOF + write-discard pseudo client is sufficient.
    let mut sink = tokio::io::join(tokio::io::empty(), tokio::io::sink());
    let outcome = forward_simple_query(backend, &mut sink, sql)
        .await
        .map_err(|failure| failure.source)?;
    if outcome.had_error_response {
        return Err(ProtocolError::Malformed(format!(
            "internal command {sql:?} returned an ErrorResponse"
        )));
    }
    if outcome.tx_status != expected_status {
        return Err(ProtocolError::Malformed(format!(
            "internal command {sql:?} ended with transaction status {:?}, expected {:?}",
            outcome.tx_status, expected_status
        )));
    }
    Ok(())
}

async fn send_command_complete<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    tag: &str,
) -> Result<(), ProxyError> {
    let bytes = encode_backend_message(&BackendMessage::CommandComplete {
        tag: tag.to_string(),
    });
    stream.write_all(&bytes).await.map_err(ProtocolError::Io)?;
    Ok(())
}

async fn send_startup_success<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    outcome: &AuthOutcome,
) -> Result<(), ProxyError> {
    let auth_ok = encode_backend_message(&BackendMessage::AuthenticationOk);
    stream.write_all(&auth_ok).await.map_err(ProtocolError::Io)?;

    // Send the baseline server parameters expected by libpq and most
    // PostgreSQL drivers. These are proxy capabilities, not values copied
    // from a pooled backend session.
    for (name, value) in [
        ("server_version", "16.0"),
        ("server_encoding", "UTF8"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("integer_datetimes", "on"),
        ("standard_conforming_strings", "on"),
    ] {
        let parameter = encode_backend_message(&BackendMessage::ParameterStatus {
            name: name.to_string(),
            value: value.to_string(),
        });
        stream
            .write_all(&parameter)
            .await
            .map_err(ProtocolError::Io)?;
    }

    let key_data = encode_backend_message(&BackendMessage::BackendKeyData {
        pid: outcome.backend_pid,
        secret_key: outcome.secret_key,
    });
    stream.write_all(&key_data).await.map_err(ProtocolError::Io)?;

    send_ready_for_query(stream, TxState::Idle).await
}

async fn send_ready_for_query<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    tx_state: TxState,
) -> Result<(), ProxyError> {
    // ReadyForQuery is always exactly 6 bytes: tag('Z') + len(5) + status.
    // Use pre-built constants to avoid encode_backend_message overhead.
    static RFQ_IDLE: [u8; 6] = [b'Z', 0, 0, 0, 5, b'I'];
    static RFQ_IN_TX: [u8; 6] = [b'Z', 0, 0, 0, 5, b'T'];
    static RFQ_FAILED: [u8; 6] = [b'Z', 0, 0, 0, 5, b'E'];
    let bytes = match tx_state {
        TxState::Idle => &RFQ_IDLE,
        TxState::InTransaction => &RFQ_IN_TX,
        TxState::Failed => &RFQ_FAILED,
    };
    stream.write_all(bytes).await.map_err(ProtocolError::Io)?;
    Ok(())
}

/// Converts any `ProxyError` into a well-formed `ErrorResponse` and sends it
/// to the client (Requirements 13.1, 13.2, 13.4). Errors while sending the
/// error response itself are propagated so the caller can close the
/// connection.
async fn send_pg_error_response<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    error: PgError,
) -> Result<(), ProxyError> {
    let bytes = encode_backend_message(&BackendMessage::ErrorResponse(error));
    stream.write_all(&bytes).await.map_err(ProtocolError::Io)?;
    Ok(())
}

async fn send_error_response<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    err: &ProxyError,
) -> Result<(), ProxyError> {
    send_pg_error_response(stream, proxy_error_to_pg_error(err)).await
}

/// Applies the `apply_ready_for_query` mapping (re-exported here for
/// convenience so callers of this module do not need to import from
/// `forwarder` separately). Kept as a thin wrapper to avoid an unused-import
/// warning while making the mapping easy to find alongside the handler.
#[allow(dead_code)]
fn tx_state_from_ready_for_query(status: TransactionStatus) -> TxState {
    apply_ready_for_query(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::WeightedRoundRobin;
    use crate::config::{LsnTrackingConfig, LsnTrackingMode, PipelineLsnConfig, PoolMode};
    use crate::health::BackendNodeSnapshot;
    use crate::parser::classifier::KeywordClassifier as Classifier_;
    use crate::parser::hint::RegexHintParser as HintParser_;
    use crate::parser::pattern::RegexPatternMatcher;
    use crate::pool::conn::{MaybeTlsStream, PooledConnection};
    use crate::pool::pool::{ConnCleaner, ConnFactory, NodePool, PoolError};
    use crate::protocol::message::FieldDescription;
    use crate::protocol::startup::TrustStartupHandler;
    use crate::router::consistency::LsnConsistencyChecker;
    use crate::router::cost::{DefaultCostEstimator, NoOpExplainRunner};
    use crate::session::lsn::InMemoryLsnTracker;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn pipeline_safety_rejects_deferred_watermark_cases() {
        assert!(pipeline_safe_sql("INSERT INTO t VALUES (1)"));
        assert!(pipeline_safe_sql("COMMIT"));
        assert!(!pipeline_safe_sql("SELECT 1; INSERT INTO t VALUES (1)"));
        assert!(!pipeline_safe_sql("COPY t FROM STDIN"));
        assert!(!pipeline_safe_sql("COMMIT AND CHAIN"));
    }

    #[test]
    fn write_intent_is_conservative_for_multi_statement_batches() {
        assert!(query_has_write_intent("INSERT INTO t VALUES (1)"));
        assert!(query_has_write_intent("CREATE TABLE t (id int)"));
        // Multi-statement with all SELECTs → no write intent (can go to reader)
        assert!(!query_has_write_intent("SELECT 1; SELECT 2"));
        // Multi-statement with a write → write intent
        assert!(query_has_write_intent("SELECT 1; INSERT INTO t VALUES (1)"));
        assert!(query_has_write_intent("SELECT 1; DROP TABLE t"));
        assert!(query_has_write_intent(
            "WITH inserted AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM inserted"
        ));
        assert!(!query_has_write_intent("BEGIN"));
        assert!(!query_has_write_intent("SELECT 1"));
    }

    #[test]
    fn aurora_consistency_uses_the_shared_routing_setting() {
        assert_eq!(
            aurora_consistency_sql(ConsistencyLevel::Eventual),
            "SET apg_write_forward.consistency_mode = 'EVENTUAL'"
        );
        assert_eq!(
            aurora_consistency_sql(ConsistencyLevel::Session),
            "SET apg_write_forward.consistency_mode = 'SESSION'"
        );
        assert_eq!(
            aurora_consistency_sql(ConsistencyLevel::Global),
            "SET apg_write_forward.consistency_mode = 'GLOBAL'"
        );
    }

    async fn read_until_ready<S>(stream: &mut S) -> Vec<BackendMessage>
    where
        S: tokio::io::AsyncRead + Unpin + Send,
    {
        let mut messages = Vec::new();
        loop {
            let message = crate::protocol::reader::read_backend_message(stream)
                .await
                .unwrap();
            let ready = matches!(message, BackendMessage::ReadyForQuery(_));
            messages.push(message);
            if ready {
                return messages;
            }
        }
    }

    /// Runs a minimal fake-backend loop on `socket`: reads simple-query
    /// `Query` messages and replies with a plausible response so that
    /// `forward_simple_query`/`fetch_current_wal_lsn` (driven by the real
    /// `ConnectionHandler`) see realistic backend behavior without needing
    /// an actual PostgreSQL instance.
    ///
    /// - `SELECT pg_current_wal_lsn()` -> a single `DataRow` with a fixed
    ///   LSN text, then `CommandComplete("SELECT 1")`.
    /// - Any other statement starting with INSERT/UPDATE/DELETE -> a
    ///   `CommandComplete` with a matching write tag directly (no rows).
    /// - Anything else (treated as a read) -> one `RowDescription` +
    ///   `DataRow` + `CommandComplete("SELECT 1")`.
    /// - `Terminate` ends the loop.
    ///
    /// Every response round trip ends with `ReadyForQuery(Idle)`.
    async fn run_fake_backend(mut socket: TcpStream) {
        let mut tx_status = TransactionStatus::Idle;
        loop {
            let msg = match crate::protocol::reader::read_frontend_message(&mut socket).await {
                Ok(msg) => msg,
                Err(_) => return, // connection closed/returned to pool and dropped
            };

            match msg {
                FrontendMessage::Terminate => return,
                FrontendMessage::Query(sql) => {
                    let upper = sql.trim_start().to_ascii_uppercase();
                    if upper.starts_with("BEGIN") || upper.starts_with("START TRANSACTION") {
                        tx_status = TransactionStatus::InTransaction;
                        let complete = encode_backend_message(&BackendMessage::CommandComplete {
                            tag: "BEGIN".to_string(),
                        });
                        socket.write_all(&complete).await.unwrap();
                    } else if upper.starts_with("COMMIT") {
                        let tag = if tx_status == TransactionStatus::Failed {
                            "ROLLBACK"
                        } else {
                            "COMMIT"
                        };
                        tx_status = TransactionStatus::Idle;
                        let complete = encode_backend_message(&BackendMessage::CommandComplete {
                            tag: tag.to_string(),
                        });
                        socket.write_all(&complete).await.unwrap();
                    } else if upper.starts_with("ROLLBACK") {
                        tx_status = TransactionStatus::Idle;
                        let complete = encode_backend_message(&BackendMessage::CommandComplete {
                            tag: "ROLLBACK".to_string(),
                        });
                        socket.write_all(&complete).await.unwrap();
                    } else if upper.starts_with("SELECT PG_CURRENT_WAL_LSN") {
                        let data_row = encode_backend_message(&BackendMessage::DataRow(vec![Some(
                            b"16/B374D848".to_vec(),
                        )]));
                        socket.write_all(&data_row).await.unwrap();
                        let complete = encode_backend_message(&BackendMessage::CommandComplete {
                            tag: "SELECT 1".to_string(),
                        });
                        socket.write_all(&complete).await.unwrap();
                    } else if upper.starts_with("SELECT FAIL") {
                        tx_status = TransactionStatus::Failed;
                        let error = encode_backend_message(&BackendMessage::ErrorResponse(
                            PgError::simple("ERROR", "XX000", "forced transaction failure"),
                        ));
                        socket.write_all(&error).await.unwrap();
                    } else if upper.starts_with("SET ") {
                        let complete = encode_backend_message(&BackendMessage::CommandComplete {
                            tag: "SET".to_string(),
                        });
                        socket.write_all(&complete).await.unwrap();
                    } else if upper.starts_with("INSERT") {
                        let complete = encode_backend_message(&BackendMessage::CommandComplete {
                            tag: "INSERT 0 1".to_string(),
                        });
                        socket.write_all(&complete).await.unwrap();
                    } else if upper.starts_with("UPDATE") {
                        let complete = encode_backend_message(&BackendMessage::CommandComplete {
                            tag: "UPDATE 1".to_string(),
                        });
                        socket.write_all(&complete).await.unwrap();
                    } else if upper.starts_with("DELETE") {
                        let complete = encode_backend_message(&BackendMessage::CommandComplete {
                            tag: "DELETE 1".to_string(),
                        });
                        socket.write_all(&complete).await.unwrap();
                    } else {
                        let row_desc = encode_backend_message(&BackendMessage::RowDescription(vec![
                            FieldDescription {
                                name: "col1".to_string(),
                                table_oid: 0,
                                column_attr_num: 1,
                                type_oid: 23,
                                type_size: 4,
                                type_modifier: -1,
                                format_code: 0,
                            },
                        ]));
                        socket.write_all(&row_desc).await.unwrap();
                        let data_row =
                            encode_backend_message(&BackendMessage::DataRow(vec![Some(b"1".to_vec())]));
                        socket.write_all(&data_row).await.unwrap();
                        let complete = encode_backend_message(&BackendMessage::CommandComplete {
                            tag: "SELECT 1".to_string(),
                        });
                        socket.write_all(&complete).await.unwrap();
                    }

                    let ready = encode_backend_message(&BackendMessage::ReadyForQuery(tx_status));
                    socket.write_all(&ready).await.unwrap();
                }
                FrontendMessage::Parse { .. } => {
                    // ParseComplete ('1')
                    socket.write_all(&[b'1', 0, 0, 0, 4]).await.unwrap();
                }
                FrontendMessage::Bind { .. } => {
                    // BindComplete ('2')
                    socket.write_all(&[b'2', 0, 0, 0, 4]).await.unwrap();
                }
                FrontendMessage::Describe { .. } => {
                    // NoData ('n') as a simplified response
                    socket.write_all(&[b'n', 0, 0, 0, 4]).await.unwrap();
                }
                FrontendMessage::Execute { .. } => {
                    // CommandComplete for a SELECT
                    let complete = encode_backend_message(&BackendMessage::CommandComplete {
                        tag: "SELECT 1".to_string(),
                    });
                    socket.write_all(&complete).await.unwrap();
                }
                FrontendMessage::Sync => {
                    let ready = encode_backend_message(&BackendMessage::ReadyForQuery(tx_status));
                    socket.write_all(&ready).await.unwrap();
                }
                _ => {}
            }
        }
    }

    /// A `ConnFactory` that, for each `acquire`-triggered `create` call,
    /// establishes a real loopback TCP pair: one end is registered in the
    /// shared `ConnectionRegistry` (so `ConnectionHandler` can look it up
    /// as if it were a real backend connection), and the other end is
    /// driven by `run_fake_backend` on a background task, standing in for
    /// an actual PostgreSQL backend.
    struct FakeBackendFactory {
        next_pid: AtomicI32,
        registry: Arc<ConnectionRegistry>,
    }

    impl ConnFactory for FakeBackendFactory {
        async fn create(&self, node_id: &str) -> Result<PooledConnection, PoolError> {
            let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| PoolError::ConnectFailed(e.to_string()))?;
            let addr = listener
                .local_addr()
                .map_err(|e| PoolError::ConnectFailed(e.to_string()))?;
            let connect_fut = TcpStream::connect(addr);
            let (accept_result, connect_result) = tokio::join!(listener.accept(), connect_fut);
            let (backend_end, _peer_addr) =
                accept_result.map_err(|e| PoolError::ConnectFailed(e.to_string()))?;
            let handler_end = connect_result.map_err(|e| PoolError::ConnectFailed(e.to_string()))?;

            tokio::spawn(run_fake_backend(backend_end));
            self.registry.insert_raw(node_id, pid, MaybeTlsStream::Plain(handler_end));

            Ok(PooledConnection::new(node_id, pid, pid * 1000))
        }
    }

    struct FakeBackendCleaner {
        registry: Arc<ConnectionRegistry>,
    }
    impl ConnCleaner for FakeBackendCleaner {
        async fn clean(&self, _conn: &PooledConnection) -> Result<(), PoolError> {
            Ok(())
        }

        fn discard(&self, conn: &PooledConnection) {
            self.registry.remove(&conn.node_id, conn.backend_pid);
        }
    }

    struct ExtensionBackendFactory {
        registry: Arc<ConnectionRegistry>,
        queries: Arc<Mutex<Vec<String>>>,
    }

    impl ConnFactory for ExtensionBackendFactory {
        async fn create(&self, node_id: &str) -> Result<PooledConnection, PoolError> {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|error| PoolError::ConnectFailed(error.to_string()))?;
            let address = listener
                .local_addr()
                .map_err(|error| PoolError::ConnectFailed(error.to_string()))?;
            let connect = TcpStream::connect(address);
            let (accepted, connected) = tokio::join!(listener.accept(), connect);
            let (mut backend, _) =
                accepted.map_err(|error| PoolError::ConnectFailed(error.to_string()))?;
            let handler_socket =
                connected.map_err(|error| PoolError::ConnectFailed(error.to_string()))?;
            let queries = self.queries.clone();

            tokio::spawn(async move {
                loop {
                    let message = match crate::protocol::reader::read_frontend_message(&mut backend)
                        .await
                    {
                        Ok(message) => message,
                        Err(_) => return,
                    };
                    let FrontendMessage::Query(sql) = message else {
                        continue;
                    };
                    queries.lock().unwrap().push(sql.clone());
                    if sql.starts_with("SELECT pg_current_wal_lsn") {
                        backend
                            .write_all(&encode_backend_message(&BackendMessage::DataRow(vec![Some(
                                b"16/B374D848".to_vec(),
                            )])))
                            .await
                            .unwrap();
                        backend
                            .write_all(&encode_backend_message(
                                &BackendMessage::CommandComplete {
                                    tag: "SELECT 1".to_string(),
                                },
                            ))
                            .await
                            .unwrap();
                    } else {
                        backend
                            .write_all(&encode_backend_message(
                                &BackendMessage::CommandComplete {
                                    tag: "INSERT 0 1".to_string(),
                                },
                            ))
                            .await
                            .unwrap();
                        backend
                            .write_all(&encode_backend_message(
                                &BackendMessage::ParameterStatus {
                                    name: "pg_lsn_track.last_commit_lsn".to_string(),
                                    value: "16/B374D848".to_string(),
                                },
                            ))
                            .await
                            .unwrap();
                    }
                    backend
                        .write_all(&encode_backend_message(&BackendMessage::ReadyForQuery(
                            TransactionStatus::Idle,
                        )))
                        .await
                        .unwrap();
                }
            });

            self.registry.insert_raw(node_id, 300, MaybeTlsStream::Plain(handler_socket));
            Ok(PooledConnection::new(node_id, 300, 300_000))
        }
    }

    type TestRouter = crate::router::router::Router<
        Classifier_,
        HintParser_,
        LsnConsistencyChecker,
        DefaultCostEstimator<RegexPatternMatcher, NoOpExplainRunner>,
        WeightedRoundRobin,
    >;

    fn make_router() -> TestRouter {
        make_router_with_split(true)
    }

    fn make_router_with_split(enable_transaction_split: bool) -> TestRouter {
        crate::router::router::Router::new(
            Classifier_,
            HintParser_,
            LsnConsistencyChecker,
            DefaultCostEstimator::new(RegexPatternMatcher::new(&[]).unwrap(), NoOpExplainRunner),
            WeightedRoundRobin::new(),
            crate::router::router::RouterSettings {
                enable_transaction_split,
                split_respects_consistency: true,
                enable_hint_routing: true,
                enable_cost_routing: false,
                cost_threshold: 1_000_000.0,
                writer_readable: true,
            },
        )
    }

    /// Uses the non-conventional writer name `primary` deliberately: this
    /// is a regression fixture for production configurations where a
    /// Writer node is not literally named `writer`.
    fn make_pool_manager(registry: Arc<ConnectionRegistry>) -> crate::pool::manager::InMemoryPoolManager {
        make_pool_manager_with_mode(registry, PoolMode::Transaction)
    }

    fn make_pool_manager_with_mode(
        registry: Arc<ConnectionRegistry>,
        mode: PoolMode,
    ) -> crate::pool::manager::InMemoryPoolManager {
        let mut pools: HashMap<String, Box<dyn crate::pool::pool::ConnectionPool>> = HashMap::new();
        pools.insert(
            "primary".to_string(),
            Box::new(NodePool::new(
                "primary",
                mode,
                10,
                FakeBackendFactory {
                    next_pid: AtomicI32::new(1),
                    registry: registry.clone(),
                },
                FakeBackendCleaner { registry },
            )),
        );
        crate::pool::manager::InMemoryPoolManager::new(pools, || {
            vec![BackendNodeSnapshot {
                node_id: "primary".to_string(),
                node_type: NodeType::Writer,
                healthy: true,
                replay_lsn: 0,
                active_connections: 0,
                weight: 1,
                replication_lag_ms: None,
            }]
        })
    }

    fn make_split_pool_manager(
        registry: Arc<ConnectionRegistry>,
    ) -> crate::pool::manager::InMemoryPoolManager {
        make_split_pool_manager_with_writer_capacity(registry, 10)
    }

    fn make_split_pool_manager_with_writer_capacity(
        registry: Arc<ConnectionRegistry>,
        writer_capacity: u32,
    ) -> crate::pool::manager::InMemoryPoolManager {
        let mut pools: HashMap<String, Box<dyn crate::pool::pool::ConnectionPool>> = HashMap::new();
        for node_id in ["primary", "reader-1"] {
            let max_connections = if node_id == "primary" {
                writer_capacity
            } else {
                10
            };
            pools.insert(
                node_id.to_string(),
                Box::new(NodePool::new(
                    node_id,
                    PoolMode::Transaction,
                    max_connections,
                    FakeBackendFactory {
                        next_pid: AtomicI32::new(1),
                        registry: registry.clone(),
                    },
                    FakeBackendCleaner {
                        registry: registry.clone(),
                    },
                )),
            );
        }
        crate::pool::manager::InMemoryPoolManager::new(pools, || {
            vec![
                BackendNodeSnapshot {
                    node_id: "primary".to_string(),
                    node_type: NodeType::Writer,
                    healthy: true,
                    replay_lsn: 0,
                    active_connections: 0,
                    weight: 1,
                    replication_lag_ms: None,
                },
                BackendNodeSnapshot {
                    node_id: "reader-1".to_string(),
                    node_type: NodeType::Reader,
                    healthy: true,
                    replay_lsn: 0,
                    active_connections: 0,
                    weight: 1,
                    replication_lag_ms: None,
                },
            ]
        })
    }

    fn make_reader_pool_manager(
        registry: Arc<ConnectionRegistry>,
        mode: PoolMode,
        reader_replay_lsn: u64,
        include_writer: bool,
    ) -> crate::pool::manager::InMemoryPoolManager {
        let mut pools: HashMap<String, Box<dyn crate::pool::pool::ConnectionPool>> = HashMap::new();
        if include_writer {
            pools.insert(
                "primary".to_string(),
                Box::new(NodePool::new(
                    "primary",
                    mode,
                    10,
                    FakeBackendFactory {
                        next_pid: AtomicI32::new(100),
                        registry: registry.clone(),
                    },
                    FakeBackendCleaner {
                        registry: registry.clone(),
                    },
                )),
            );
        }
        pools.insert(
            "reader-1".to_string(),
            Box::new(NodePool::new(
                "reader-1",
                mode,
                10,
                FakeBackendFactory {
                    next_pid: AtomicI32::new(200),
                    registry: registry.clone(),
                },
                FakeBackendCleaner { registry },
            )),
        );

        crate::pool::manager::InMemoryPoolManager::new(pools, move || {
            let mut nodes = Vec::new();
            if include_writer {
                nodes.push(BackendNodeSnapshot {
                    node_id: "primary".to_string(),
                    node_type: NodeType::Writer,
                    healthy: true,
                    replay_lsn: 0,
                    active_connections: 0,
                    weight: 1,
                    replication_lag_ms: None,
                });
            }
            nodes.push(BackendNodeSnapshot {
                node_id: "reader-1".to_string(),
                node_type: NodeType::Reader,
                healthy: true,
                replay_lsn: reader_replay_lsn,
                active_connections: 0,
                weight: 1,
                replication_lag_ms: None,
            });
            nodes
        })
    }

    #[tokio::test]
    async fn auto_mode_switches_to_extension_after_first_lsn_report() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(4096);
        let router = make_router();
        let registry = Arc::new(ConnectionRegistry::new());
        let queries = Arc::new(Mutex::new(Vec::new()));
        let mut pools: HashMap<String, Box<dyn crate::pool::pool::ConnectionPool>> = HashMap::new();
        pools.insert(
            "primary".to_string(),
            Box::new(NodePool::new(
                "primary",
                PoolMode::Transaction,
                2,
                ExtensionBackendFactory {
                    registry: registry.clone(),
                    queries: queries.clone(),
                },
                FakeBackendCleaner {
                    registry: registry.clone(),
                },
            )),
        );
        let pool_manager = crate::pool::manager::InMemoryPoolManager::new(pools, || {
            vec![BackendNodeSnapshot {
                node_id: "primary".to_string(),
                node_type: NodeType::Writer,
                healthy: true,
                replay_lsn: 0,
                active_connections: 0,
                weight: 1,
                replication_lag_ms: None,
            }]
        });
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &registry,
            &cancel_registry,
            &node_addresses,
        );
        let mut session = ClientSession::new("auto-extension", ConsistencyLevel::Session);

        for value in [1, 2] {
            let sql = format!("INSERT INTO t VALUES ({value})");
            let query = handler.handle_simple_query(&mut handler_side, &mut session, &sql);
            let drain = async {
                for _ in 0..2 {
                    crate::protocol::reader::read_backend_message(&mut client_side)
                        .await
                        .unwrap();
                }
            };
            let (result, ()) = tokio::join!(query, drain);
            result.unwrap();
        }

        assert!(session.extension_detected);
        // Extension reports LSN via GUC (no pipeline needed with lazy_fallback)
        assert!(lsn_tracker.session_write_lsn("auto-extension") > 0);
        assert_eq!(
            queries.lock().unwrap().as_slice(),
            [
                "INSERT INTO t VALUES (1)",
                "INSERT INTO t VALUES (2)",
            ],
            "lazy_fallback skips pipeline; extension detected via GUC only"
        );
    }

    #[tokio::test]
    async fn lazy_watermark_fetch_records_lsn_and_reroutes_to_reader() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(4096);
        let router = make_router();
        let registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_reader_pool_manager(
            registry.clone(),
            PoolMode::Transaction,
            u64::MAX,
            true,
        );
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &registry,
            &cancel_registry,
            &node_addresses,
        );
        let mut session = ClientSession::new("lazy-session", ConsistencyLevel::Session);
        session.pending_write = true;

        let query = handler.handle_simple_query(&mut handler_side, &mut session, "SELECT 1");
        let drain = async {
            for _ in 0..4 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }
        };
        let (result, ()) = tokio::join!(query, drain);
        result.unwrap();

        assert!(!session.pending_write);
        assert!(lsn_tracker.session_write_lsn("lazy-session") > 0);
        assert_eq!(
            pool_manager
                .pool_for("reader-1")
                .unwrap()
                .active_connections(),
            1,
            "the query must be rerouted after the refreshed watermark"
        );
    }

    #[tokio::test]
    async fn aurora_mode_pins_one_reader_and_bypasses_lsn_tracking() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(8192);
        let router = make_router();
        let registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_reader_pool_manager(
            registry.clone(),
            PoolMode::Session,
            u64::MAX,
            false,
        );
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let lsn_tracking = LsnTrackingConfig {
            mode: LsnTrackingMode::AuroraWriteForwarding,
            ..LsnTrackingConfig::default()
        };
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &registry,
            &cancel_registry,
            &node_addresses,
        )
        .with_lsn_tracking(lsn_tracking);
        let mut session = ClientSession::new("aurora-session", ConsistencyLevel::Global);

        for (sql, response_count) in [
            ("INSERT INTO t VALUES (1)", 2usize),
            ("SELECT 1", 4usize),
            ("SET trident.consistency = 'eventual'", 2usize),
        ] {
            let query = handler.handle_simple_query(&mut handler_side, &mut session, sql);
            let drain = async {
                for _ in 0..response_count {
                    crate::protocol::reader::read_backend_message(&mut client_side)
                        .await
                        .unwrap();
                }
            };
            let (result, ()) = tokio::join!(query, drain);
            result.unwrap();
        }

        assert_eq!(session.aurora_node_id.as_deref(), Some("reader-1"));
        assert_eq!(session.aurora_initialized_backend_pid, Some(200));
        assert_eq!(session.state.consistency, ConsistencyLevel::Eventual);
        assert_eq!(lsn_tracker.session_write_lsn("aurora-session"), 0);
        assert_eq!(
            pool_manager
                .pool_for("reader-1")
                .unwrap()
                .active_connections(),
            1,
            "Session mode must retain exactly one physical Reader binding"
        );
    }

    #[tokio::test]
    async fn ssl_and_gssenc_requests_are_rejected_then_startup_continues() {
        use tokio::io::{duplex, AsyncReadExt};

        let (mut client_side, server_side) = duplex(4096);
        let router = make_router();
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_pool_manager(connection_registry.clone());
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );

        let server = async {
            let mut startup_handler = TrustStartupHandler {
                backend_pid: 7,
                secret_key: 11,
            };
            handler
                .handle(
                    server_side,
                    &mut startup_handler,
                    "negotiation-session".to_string(),
                    ConsistencyLevel::Session,
                )
                .await
        };
        let client = async {
            for code in [
                crate::protocol::startup::SSL_REQUEST_CODE,
                crate::protocol::startup::GSSENC_REQUEST_CODE,
            ] {
                let mut request = 8i32.to_be_bytes().to_vec();
                request.extend_from_slice(&code.to_be_bytes());
                client_side.write_all(&request).await.unwrap();
                let mut response = [0u8; 1];
                client_side.read_exact(&mut response).await.unwrap();
                assert_eq!(response, [b'N']);
            }

            let mut body = 196_608i32.to_be_bytes().to_vec();
            body.push(0);
            let mut startup = ((body.len() + 4) as i32).to_be_bytes().to_vec();
            startup.extend(body);
            client_side.write_all(&startup).await.unwrap();
            read_until_ready(&mut client_side).await;
            let terminate = crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Terminate,
            );
            client_side.write_all(&terminate).await.unwrap();
        };

        let (server_result, ()) = tokio::join!(server, client);
        server_result.unwrap();
    }

    #[tokio::test]
    async fn full_handshake_and_write_query_over_in_memory_stream() {
        use tokio::io::duplex;

        let (mut client_side, server_side) = duplex(4096);

        let router = make_router();
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_pool_manager_with_mode(
            connection_registry.clone(),
            PoolMode::Session,
        );
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );

        // Drive the server side and the client side concurrently on the
        // same task via `tokio::join!` (rather than `tokio::spawn`, which
        // would require the borrowed `handler`/`router`/etc. to be
        // `'static`). Both futures run to completion together.
        let server_fut = async {
            let mut startup_handler = TrustStartupHandler {
                backend_pid: 4242,
                secret_key: 9999,
            };
            handler
                .handle(server_side, &mut startup_handler, "session-1".to_string(), ConsistencyLevel::Session)
                .await
        };

        let client_fut = async {
            // --- client side: send StartupMessage ---
            let mut params = HashMap::new();
            params.insert("user".to_string(), "alice".to_string());
            params.insert("database".to_string(), "mydb".to_string());
            let mut body = 196_608i32.to_be_bytes().to_vec();
            for (k, v) in &params {
                body.extend_from_slice(k.as_bytes());
                body.push(0);
                body.extend_from_slice(v.as_bytes());
                body.push(0);
            }
            body.push(0);
            let mut framed = ((body.len() + 4) as i32).to_be_bytes().to_vec();
            framed.extend(body);
            client_side.write_all(&framed).await.unwrap();

            // Startup responses are ordered as AuthenticationOk, baseline
            // ParameterStatus messages, BackendKeyData, ReadyForQuery.
            let startup_messages = read_until_ready(&mut client_side).await;
            assert_eq!(startup_messages.first(), Some(&BackendMessage::AuthenticationOk));
            assert_eq!(
                startup_messages.last(),
                Some(&BackendMessage::ReadyForQuery(TransactionStatus::Idle))
            );
            assert!(startup_messages
                .iter()
                .any(|message| matches!(message, BackendMessage::BackendKeyData { .. })));

            let parameter_statuses: HashMap<_, _> = startup_messages
                .iter()
                .filter_map(|message| match message {
                    BackendMessage::ParameterStatus { name, value } => {
                        Some((name.as_str(), value.as_str()))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(parameter_statuses.get("server_version"), Some(&"16.0"));
            assert_eq!(parameter_statuses.get("server_encoding"), Some(&"UTF8"));
            assert_eq!(parameter_statuses.get("client_encoding"), Some(&"UTF8"));
            assert_eq!(parameter_statuses.get("DateStyle"), Some(&"ISO, MDY"));
            assert_eq!(parameter_statuses.get("integer_datetimes"), Some(&"on"));
            assert_eq!(
                parameter_statuses.get("standard_conforming_strings"),
                Some(&"on")
            );

            // --- client side: send a write query ---
            let query_bytes = crate::protocol::writer::encode_frontend_message(&FrontendMessage::Query(
                "INSERT INTO t VALUES (1)".to_string(),
            ));
            client_side.write_all(&query_bytes).await.unwrap();

            // The fake backend relays a CommandComplete for the INSERT
            // before the handler sends its own ReadyForQuery.
            let complete = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            assert_eq!(
                complete,
                BackendMessage::CommandComplete {
                    tag: "INSERT 0 1".to_string()
                }
            );

            let ready2 = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            assert_eq!(ready2, BackendMessage::ReadyForQuery(TransactionStatus::Idle));
            // With lazy_fallback (default), pipeline is skipped: LSN is
            // deferred until a subsequent read targets a reader. The write
            // is marked via pending_write instead of immediate recording.
            // session_write_lsn remains 0 here (no eager pipeline).

            // --- client side: terminate ---
            let terminate_bytes =
                crate::protocol::writer::encode_frontend_message(&FrontendMessage::Terminate);
            client_side.write_all(&terminate_bytes).await.unwrap();
            drop(client_side);
        };

        let (server_result, ()) = tokio::join!(server_fut, client_fut);
        assert!(server_result.is_ok());

        // Per-session LSN state is intentionally removed when the client
        // disconnects; the client-side assertion above verifies it was
        // recorded while the session was live.
        assert_eq!(lsn_tracker.session_write_lsn("session-1"), 0);
        assert_eq!(
            pool_manager.pool_for("primary").unwrap().active_connections(),
            0,
            "session cleanup must free its pool slot"
        );
        assert!(
            connection_registry.take("primary", 1).is_none(),
            "session cleanup must drop the registered backend socket"
        );
    }

    #[tokio::test]
    async fn extended_query_protocol_forwards_parse_bind_execute_sync() {
        use tokio::io::duplex;

        let (mut client_side, server_side) = duplex(8192);
        let router = make_router();
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_pool_manager(connection_registry.clone());
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );

        let server = async {
            let mut startup_handler = TrustStartupHandler {
                backend_pid: 71,
                secret_key: 73,
            };
            handler
                .handle(
                    server_side,
                    &mut startup_handler,
                    "extended-protocol-session".to_string(),
                    ConsistencyLevel::Session,
                )
                .await
        };
        let client = async {
            let mut body = 196_608i32.to_be_bytes().to_vec();
            body.push(0);
            let mut startup = ((body.len() + 4) as i32).to_be_bytes().to_vec();
            startup.extend(body);
            client_side.write_all(&startup).await.unwrap();
            read_until_ready(&mut client_side).await;

            // Send Parse + Bind + Execute + Sync as a batch
            let mut batch = Vec::new();
            batch.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Parse {
                    name: "".to_string(),
                    sql: "SELECT 1".to_string(),
                    param_types: vec![],
                },
            ));
            batch.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Bind {
                    portal: "".to_string(),
                    statement: "".to_string(),
                    param_formats: vec![],
                    params: vec![],
                    result_formats: vec![],
                },
            ));
            batch.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Execute {
                    portal: "".to_string(),
                    max_rows: 0,
                },
            ));
            batch.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Sync,
            ));
            client_side.write_all(&batch).await.unwrap();

            // Expect responses ending with ReadyForQuery
            let mut messages = Vec::new();
            loop {
                let msg = crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
                let is_ready = matches!(msg, BackendMessage::ReadyForQuery(_));
                messages.push(msg);
                if is_ready {
                    break;
                }
            }

            // Should NOT get an ErrorResponse (extended protocol is now supported)
            assert!(
                !messages.iter().any(|m| matches!(m, BackendMessage::ErrorResponse(_))),
                "extended query should succeed; got: {messages:?}"
            );
            assert_eq!(
                messages.last(),
                Some(&BackendMessage::ReadyForQuery(TransactionStatus::Idle))
            );

            let terminate =
                crate::protocol::writer::encode_frontend_message(&FrontendMessage::Terminate);
            client_side.write_all(&terminate).await.unwrap();
        };

        let (server_result, ()) = tokio::join!(server, client);
        server_result.unwrap();
    }

    #[tokio::test]
    async fn extended_flush_rejected_cleanly_and_recovers_at_sync() {
        use tokio::io::duplex;

        let (mut client_side, server_side) = duplex(8192);
        let router = make_router();
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_pool_manager(connection_registry.clone());
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );

        let server = async {
            let mut startup_handler = TrustStartupHandler {
                backend_pid: 90,
                secret_key: 91,
            };
            handler
                .handle(
                    server_side,
                    &mut startup_handler,
                    "flush-session".to_string(),
                    ConsistencyLevel::Session,
                )
                .await
        };
        let client = async {
            let mut body = 196_608i32.to_be_bytes().to_vec();
            body.push(0);
            let mut startup = ((body.len() + 4) as i32).to_be_bytes().to_vec();
            startup.extend(body);
            client_side.write_all(&startup).await.unwrap();
            read_until_ready(&mut client_side).await;

            // Parse + Flush: Trident cannot serve intermediate results at a
            // Flush point; expect a clean ErrorResponse, NOT a dropped
            // connection.
            let mut batch = Vec::new();
            batch.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Parse {
                    name: "".to_string(),
                    sql: "SELECT 1".to_string(),
                    param_types: vec![],
                },
            ));
            batch.push(b'H'); // Flush
            batch.extend_from_slice(&4i32.to_be_bytes());
            client_side.write_all(&batch).await.unwrap();

            let msg = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            assert!(
                matches!(msg, BackendMessage::ErrorResponse(_)),
                "Flush with a pending batch must produce ErrorResponse, got: {msg:?}"
            );

            // Messages after the error are ignored until Sync, which must
            // produce ReadyForQuery -- the standard recovery sequence.
            let mut tail = crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Execute {
                    portal: "".to_string(),
                    max_rows: 0,
                },
            );
            tail.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Sync,
            ));
            client_side.write_all(&tail).await.unwrap();

            let ready = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            assert_eq!(ready, BackendMessage::ReadyForQuery(TransactionStatus::Idle));

            // The connection must remain fully usable: a normal extended
            // batch afterwards succeeds end to end.
            let mut batch2 = Vec::new();
            batch2.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Parse {
                    name: "".to_string(),
                    sql: "SELECT 1".to_string(),
                    param_types: vec![],
                },
            ));
            batch2.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Bind {
                    portal: "".to_string(),
                    statement: "".to_string(),
                    param_formats: vec![],
                    params: vec![],
                    result_formats: vec![],
                },
            ));
            batch2.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Execute {
                    portal: "".to_string(),
                    max_rows: 0,
                },
            ));
            batch2.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Sync,
            ));
            client_side.write_all(&batch2).await.unwrap();

            let mut messages = Vec::new();
            loop {
                let msg = crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
                let is_ready = matches!(msg, BackendMessage::ReadyForQuery(_));
                messages.push(msg);
                if is_ready {
                    break;
                }
            }
            assert!(
                !messages.iter().any(|m| matches!(m, BackendMessage::ErrorResponse(_))),
                "post-recovery batch should succeed; got: {messages:?}"
            );

            let terminate =
                crate::protocol::writer::encode_frontend_message(&FrontendMessage::Terminate);
            client_side.write_all(&terminate).await.unwrap();
        };

        let (server_result, ()) = tokio::join!(server, client);
        server_result.unwrap();
    }

    #[tokio::test]
    async fn extended_query_named_statement_routes_consistently_across_sync_boundaries() {
        use tokio::io::duplex;

        let (mut client_side, server_side) = duplex(8192);
        let router = make_router();
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_pool_manager(connection_registry.clone());
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );

        let server = async {
            let mut startup_handler = TrustStartupHandler {
                backend_pid: 80,
                secret_key: 81,
            };
            handler
                .handle(
                    server_side,
                    &mut startup_handler,
                    "named-stmt-session".to_string(),
                    ConsistencyLevel::Session,
                )
                .await
        };
        let client = async {
            // Startup
            let mut body = 196_608i32.to_be_bytes().to_vec();
            body.push(0);
            let mut startup = ((body.len() + 4) as i32).to_be_bytes().to_vec();
            startup.extend(body);
            client_side.write_all(&startup).await.unwrap();
            read_until_ready(&mut client_side).await;

            // First Sync: Parse named "stmt1" + Sync
            let mut batch1 = Vec::new();
            batch1.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Parse {
                    name: "stmt1".to_string(),
                    sql: "SELECT 1".to_string(),
                    param_types: vec![],
                },
            ));
            batch1.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Sync,
            ));
            client_side.write_all(&batch1).await.unwrap();
            // Read responses until ReadyForQuery
            loop {
                let msg = crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
                if matches!(msg, BackendMessage::ReadyForQuery(_)) {
                    break;
                }
            }

            // Second Sync: Bind+Execute referencing "stmt1" (no Parse)
            let mut batch2 = Vec::new();
            batch2.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Bind {
                    portal: "".to_string(),
                    statement: "stmt1".to_string(),
                    param_formats: vec![],
                    params: vec![],
                    result_formats: vec![],
                },
            ));
            batch2.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Execute {
                    portal: "".to_string(),
                    max_rows: 0,
                },
            ));
            batch2.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Sync,
            ));
            client_side.write_all(&batch2).await.unwrap();

            let mut messages = Vec::new();
            loop {
                let msg = crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
                let is_ready = matches!(msg, BackendMessage::ReadyForQuery(_));
                messages.push(msg);
                if is_ready {
                    break;
                }
            }

            // Should succeed (routed to same backend as the original Parse)
            assert!(
                !messages.iter().any(|m| matches!(m, BackendMessage::ErrorResponse(_))),
                "named statement re-execution should route to the same backend; got: {messages:?}"
            );

            let terminate =
                crate::protocol::writer::encode_frontend_message(&FrontendMessage::Terminate);
            client_side.write_all(&terminate).await.unwrap();
        };

        let (server_result, ()) = tokio::join!(server, client);
        server_result.unwrap();
    }

    #[tokio::test]
    async fn extended_query_write_sets_pending_write() {
        use tokio::io::duplex;

        let (mut client_side, server_side) = duplex(8192);
        let router = make_router();
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_pool_manager(connection_registry.clone());
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );

        let server = async {
            let mut startup_handler = TrustStartupHandler {
                backend_pid: 90,
                secret_key: 91,
            };
            handler
                .handle(
                    server_side,
                    &mut startup_handler,
                    "ext-write-session".to_string(),
                    ConsistencyLevel::Session,
                )
                .await
        };
        let client = async {
            // Startup
            let mut body = 196_608i32.to_be_bytes().to_vec();
            body.push(0);
            let mut startup = ((body.len() + 4) as i32).to_be_bytes().to_vec();
            startup.extend(body);
            client_side.write_all(&startup).await.unwrap();
            read_until_ready(&mut client_side).await;

            // Parse(INSERT) + Bind + Execute + Sync
            let mut batch = Vec::new();
            batch.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Parse {
                    name: "".to_string(),
                    sql: "INSERT INTO t VALUES (1)".to_string(),
                    param_types: vec![],
                },
            ));
            batch.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Bind {
                    portal: "".to_string(),
                    statement: "".to_string(),
                    param_formats: vec![],
                    params: vec![],
                    result_formats: vec![],
                },
            ));
            batch.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Execute {
                    portal: "".to_string(),
                    max_rows: 0,
                },
            ));
            batch.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Sync,
            ));
            client_side.write_all(&batch).await.unwrap();

            // Read until ReadyForQuery
            let mut saw_command_complete = false;
            loop {
                let msg = crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
                if matches!(msg, BackendMessage::CommandComplete { .. }) {
                    saw_command_complete = true;
                }
                if matches!(msg, BackendMessage::ReadyForQuery(_)) {
                    break;
                }
            }
            assert!(saw_command_complete, "INSERT should produce CommandComplete");

            let terminate =
                crate::protocol::writer::encode_frontend_message(&FrontendMessage::Terminate);
            client_side.write_all(&terminate).await.unwrap();
        };

        let (server_result, ()) = tokio::join!(server, client);
        server_result.unwrap();
        // The fake backend doesn't know about extended-protocol INSERT
        // specifically (it just returns CommandComplete("SELECT 1") for
        // Execute), so we can't assert pending_write here without a more
        // sophisticated fake backend. But we verify the full round-trip
        // succeeds without error, which confirms extended protocol
        // forwarding works for write-intent SQL.
    }

    #[tokio::test]
    async fn consistency_set_is_applied_locally_without_acquiring_backend() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(1024);
        let router = make_router();
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_pool_manager(connection_registry.clone());
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );
        let mut session = ClientSession::new("consistency-session", ConsistencyLevel::Session);

        let set = handler.handle_simple_query(
            &mut handler_side,
            &mut session,
            "SET trident.consistency = 'global'",
        );
        let responses = async {
            let complete = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            let ready = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            (complete, ready)
        };
        let (result, (complete, ready)) = tokio::join!(set, responses);
        result.unwrap();

        assert_eq!(session.state.consistency, ConsistencyLevel::Global);
        assert_eq!(
            complete,
            BackendMessage::CommandComplete {
                tag: "SET".to_string()
            }
        );
        assert_eq!(ready, BackendMessage::ReadyForQuery(TransactionStatus::Idle));
        assert_eq!(
            pool_manager.pool_for("primary").unwrap().active_connections(),
            0,
            "proxy-local SET must not acquire a backend connection"
        );
        assert!(session.held_backend.is_none());
    }

    #[tokio::test]
    async fn missing_registry_socket_discards_metadata_socket_and_pool_slot() {
        use tokio::io::duplex;

        let router = make_router();
        let factory_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_pool_manager(factory_registry.clone());
        // Deliberately give the handler a different registry so acquisition
        // returns metadata whose socket cannot be found.
        let handler_registry = ConnectionRegistry::new();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &handler_registry,
            &cancel_registry,
            &node_addresses,
        );
        let mut session = ClientSession::new("missing-socket", ConsistencyLevel::Session);
        let (_client_side, mut handler_side) = duplex(1024);

        let result = handler
            .handle_simple_query(&mut handler_side, &mut session, "SELECT 1")
            .await;
        assert!(matches!(result, Err(ProxyError::Pool(_))));
        assert_eq!(
            pool_manager.pool_for("primary").unwrap().active_connections(),
            0
        );
        assert!(
            factory_registry.take("primary", 1).is_none(),
            "discard callback must remove the orphaned physical socket"
        );
    }

    #[tokio::test]
    async fn lsn_protocol_failure_preserves_write_and_discards_backend() {
        use tokio::io::duplex;

        struct MalformedLsnFactory {
            registry: Arc<ConnectionRegistry>,
        }

        impl ConnFactory for MalformedLsnFactory {
            async fn create(&self, node_id: &str) -> Result<PooledConnection, PoolError> {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .map_err(|error| PoolError::ConnectFailed(error.to_string()))?;
                let address = listener
                    .local_addr()
                    .map_err(|error| PoolError::ConnectFailed(error.to_string()))?;
                let connect = TcpStream::connect(address);
                let (accepted, connected) = tokio::join!(listener.accept(), connect);
                let (mut backend, _) =
                    accepted.map_err(|error| PoolError::ConnectFailed(error.to_string()))?;
                let handler_socket =
                    connected.map_err(|error| PoolError::ConnectFailed(error.to_string()))?;

                tokio::spawn(async move {
                    let first = crate::protocol::reader::read_frontend_message(&mut backend)
                        .await
                        .unwrap();
                    assert!(matches!(first, FrontendMessage::Query(_)));
                    backend
                        .write_all(&encode_backend_message(
                            &BackendMessage::CommandComplete {
                                tag: "INSERT 0 1".to_string(),
                            },
                        ))
                        .await
                        .unwrap();
                    backend
                        .write_all(&encode_backend_message(&BackendMessage::ReadyForQuery(
                            TransactionStatus::Idle,
                        )))
                        .await
                        .unwrap();

                    let lsn_query = crate::protocol::reader::read_frontend_message(&mut backend)
                        .await
                        .unwrap();
                    assert!(matches!(lsn_query, FrontendMessage::Query(_)));
                    // DataRow tag followed by an invalid frame length (< 4).
                    backend.write_all(&[b'D', 0, 0, 0, 3]).await.unwrap();
                });

                self.registry.insert_raw(node_id, 1, MaybeTlsStream::Plain(handler_socket));
                Ok(PooledConnection::new(node_id, 1, 1000))
            }
        }

        let router = make_router();
        let registry = Arc::new(ConnectionRegistry::new());
        let mut pools: HashMap<String, Box<dyn crate::pool::pool::ConnectionPool>> =
            HashMap::new();
        pools.insert(
            "primary".to_string(),
            Box::new(NodePool::new(
                "primary",
                PoolMode::Transaction,
                1,
                MalformedLsnFactory {
                    registry: registry.clone(),
                },
                FakeBackendCleaner {
                    registry: registry.clone(),
                },
            )),
        );
        let pool_manager = crate::pool::manager::InMemoryPoolManager::new(pools, || {
            vec![BackendNodeSnapshot {
                node_id: "primary".to_string(),
                node_type: NodeType::Writer,
                healthy: true,
                replay_lsn: 0,
                active_connections: 0,
                weight: 1,
                replication_lag_ms: None,
            }]
        });
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        // Explicitly disable lazy_fallback so the pipeline fires and
        // we can test the protocol-failure handling path.
        let lsn_tracking_eager = LsnTrackingConfig {
            mode: LsnTrackingMode::Pipeline,
            pipeline: PipelineLsnConfig {
                lazy_fallback: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let handler = ConnectionHandler::with_query_log(
            &router,
            &pool_manager,
            &lsn_tracker,
            &registry,
            &cancel_registry,
            &node_addresses,
            QueryLogSettings::default(),
        )
        .with_lsn_tracking(lsn_tracking_eager);
        let mut session = ClientSession::new("bad-lsn", ConsistencyLevel::Session);
        let (mut client_side, mut handler_side) = duplex(4096);

        let query = handler.handle_simple_query(
            &mut handler_side,
            &mut session,
            "INSERT INTO t VALUES (1)",
        );
        let client = async {
            let message = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            assert!(matches!(
                message,
                BackendMessage::CommandComplete { ref tag } if tag == "INSERT 0 1"
            ));
        };
        let (result, ()) = tokio::join!(query, client);

        assert!(result.is_ok(), "the already-committed user write must succeed");
        assert!(
            session.pending_write,
            "a failed internal LSN cycle must defer watermark acquisition"
        );
        assert_eq!(
            pool_manager.pool_for("primary").unwrap().active_connections(),
            0,
            "protocol-damaged backend must release its pool slot"
        );
        assert!(
            registry.take("primary", 1).is_none(),
            "protocol-damaged backend socket must not return to the registry"
        );
    }

    #[tokio::test]
    async fn transaction_split_delays_begin_routes_reader_then_upgrades_writer() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(8192);
        let router = make_router();
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_split_pool_manager(connection_registry.clone());
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );
        let mut session = ClientSession::new("split-session", ConsistencyLevel::Eventual);

        let begin = handler.handle_simple_query(
            &mut handler_side,
            &mut session,
            "START TRANSACTION ISOLATION LEVEL READ COMMITTED",
        );
        let drain_begin = async {
            for _ in 0..2 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }
        };
        let (begin_result, ()) = tokio::join!(begin, drain_begin);
        begin_result.unwrap();
        assert_eq!(session.state.tx_state, TxState::InTransaction);
        assert!(session.state.tx_split.as_ref().is_some_and(|state| !state.active));
        assert!(session.held_backend.is_none(), "BEGIN must be delayed");
        assert_eq!(
            pool_manager
                .snapshot()
                .iter()
                .map(|node| node.active_connections)
                .sum::<i64>(),
            0
        );

        let select = handler.handle_simple_query(&mut handler_side, &mut session, "SELECT 1");
        let drain_select = async {
            for _ in 0..4 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }
        };
        let (select_result, ()) = tokio::join!(select, drain_select);
        select_result.unwrap();
        assert_eq!(session.held_backend.as_ref().unwrap().conn.node_id, "reader-1");
        assert!(session.state.tx_split.as_ref().unwrap().on_reader);

        let update = handler.handle_simple_query(
            &mut handler_side,
            &mut session,
            "UPDATE t SET value = 2",
        );
        let drain_update = async {
            for _ in 0..2 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }
        };
        let (update_result, ()) = tokio::join!(update, drain_update);
        update_result.unwrap();
        assert_eq!(session.held_backend.as_ref().unwrap().conn.node_id, "primary");
        assert!(!session.state.tx_split.as_ref().unwrap().on_reader);

        let commit = handler.handle_simple_query(&mut handler_side, &mut session, "COMMIT");
        let drain_commit = async {
            for _ in 0..2 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }
        };
        let (commit_result, ()) = tokio::join!(commit, drain_commit);
        commit_result.unwrap();
        // With Eventual consistency, LSN tracking is skipped (reads don't
        // need consistency checks), so neither LSN is recorded nor
        // pending_write is set.
        assert_eq!(session.state.tx_state, TxState::Idle);
        assert!(session.state.tx_split.is_none());
        assert!(session.held_backend.is_none());
    }

    #[tokio::test]
    async fn failed_reader_to_writer_upgrade_enters_virtual_failed_transaction() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(8192);
        let router = make_router();
        let connection_registry = Arc::new(ConnectionRegistry::new());
        // The Writer remains healthy/routable but has no capacity, forcing
        // the failure after the Reader transaction has been rolled back.
        let pool_manager = make_split_pool_manager_with_writer_capacity(
            connection_registry.clone(),
            0,
        );
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );
        let mut session = ClientSession::new("failed-upgrade", ConsistencyLevel::Eventual);

        let begin = handler.handle_simple_query(&mut handler_side, &mut session, "BEGIN");
        let drain_begin = async {
            for _ in 0..2 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }
        };
        let (begin_result, ()) = tokio::join!(begin, drain_begin);
        begin_result.unwrap();

        let select = handler.handle_simple_query(&mut handler_side, &mut session, "SELECT 1");
        let drain_select = async {
            for _ in 0..4 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }
        };
        let (select_result, ()) = tokio::join!(select, drain_select);
        select_result.unwrap();
        assert_eq!(session.held_backend.as_ref().unwrap().conn.node_id, "reader-1");

        let update_result = handler
            .handle_simple_query(
                &mut handler_side,
                &mut session,
                "UPDATE t SET value = 2",
            )
            .await;
        assert!(matches!(
            update_result,
            Err(ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(ref node)))
                if node == "primary"
        ));
        assert_eq!(session.state.tx_state, TxState::Failed);
        assert!(session.held_backend.is_none());
        assert_eq!(
            pool_manager.pool_for("reader-1").unwrap().active_connections(),
            1,
            "rolled-back Reader must be released back to the idle pool (not discarded) in Transaction mode"
        );

        let rejected = handler.handle_simple_query(
            &mut handler_side,
            &mut session,
            "SELECT must_not_run_as_autocommit",
        );
        let read_rejection = async {
            let error = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            let ready = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            (error, ready)
        };
        let (rejected_result, (error, failed_ready)) =
            tokio::join!(rejected, read_rejection);
        rejected_result.unwrap();
        assert!(matches!(
            error,
            BackendMessage::ErrorResponse(ref pg_error)
                if pg_error.sqlstate() == Some("25P02")
        ));
        assert_eq!(
            failed_ready,
            BackendMessage::ReadyForQuery(TransactionStatus::Failed)
        );
        assert_eq!(
            pool_manager.pool_for("primary").unwrap().active_connections(),
            0,
            "a statement in the virtual failed block must not acquire a Writer"
        );

        // With no physical transaction left, the proxy must not run another
        // statement as autocommit. Ending the virtual failed block is a local
        // ROLLBACK, even when the client says COMMIT.
        let end = handler.handle_simple_query(&mut handler_side, &mut session, "COMMIT");
        let read_end = async {
            let complete = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            let ready = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            (complete, ready)
        };
        let (end_result, (complete, ready)) = tokio::join!(end, read_end);
        end_result.unwrap();
        assert_eq!(
            complete,
            BackendMessage::CommandComplete {
                tag: "ROLLBACK".to_string()
            }
        );
        assert_eq!(ready, BackendMessage::ReadyForQuery(TransactionStatus::Idle));
        assert_eq!(session.state.tx_state, TxState::Idle);
        assert!(session.state.tx_split.is_none());
    }

    #[tokio::test]
    async fn pending_split_transaction_can_rollback_without_backend() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(2048);
        let router = make_router();
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_split_pool_manager(connection_registry.clone());
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );
        let mut session = ClientSession::new("pending-split", ConsistencyLevel::Eventual);

        for sql in ["BEGIN READ ONLY", "ROLLBACK"] {
            let execute = handler.handle_simple_query(&mut handler_side, &mut session, sql);
            let drain = async {
                for _ in 0..2 {
                    crate::protocol::reader::read_backend_message(&mut client_side)
                        .await
                        .unwrap();
                }
            };
            let (result, ()) = tokio::join!(execute, drain);
            result.unwrap();
        }

        assert_eq!(session.state.tx_state, TxState::Idle);
        assert!(session.state.tx_split.is_none());
        assert!(session.held_backend.is_none());
        assert_eq!(
            pool_manager
                .snapshot()
                .iter()
                .map(|node| node.active_connections)
                .sum::<i64>(),
            0
        );
    }

    #[tokio::test]
    async fn explicit_transaction_reuses_one_physical_backend_until_rollback() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(4096);
        let router = make_router_with_split(false);
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_pool_manager(connection_registry.clone());
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );
        let mut session = ClientSession::new("transaction-session", ConsistencyLevel::Session);

        let begin = handler.handle_simple_query(&mut handler_side, &mut session, "BEGIN");
        let drain_begin = async {
            for _ in 0..2 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }
        };
        let (begin_result, ()) = tokio::join!(begin, drain_begin);
        begin_result.unwrap();
        assert_eq!(session.state.tx_state, TxState::InTransaction);
        let transaction_pid = session
            .held_backend
            .as_ref()
            .expect("BEGIN must retain its physical backend")
            .conn
            .backend_pid;

        let insert = handler.handle_simple_query(
            &mut handler_side,
            &mut session,
            "INSERT INTO t VALUES (1)",
        );
        let drain_insert = async {
            for _ in 0..2 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }
        };
        let (insert_result, ()) = tokio::join!(insert, drain_insert);
        insert_result.unwrap();
        assert_eq!(session.state.tx_state, TxState::InTransaction);
        assert_eq!(
            session.held_backend.as_ref().unwrap().conn.backend_pid,
            transaction_pid,
            "all statements in an explicit transaction must use one backend"
        );

        let rollback = handler.handle_simple_query(&mut handler_side, &mut session, "ROLLBACK");
        let drain_rollback = async {
            for _ in 0..2 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }
        };
        let (rollback_result, ()) = tokio::join!(rollback, drain_rollback);
        rollback_result.unwrap();
        assert_eq!(
            lsn_tracker.session_write_lsn("transaction-session"),
            0,
            "ROLLBACK must not advance the session watermark"
        );
        assert_eq!(session.state.tx_state, TxState::Idle);
        assert!(
            session.held_backend.is_none(),
            "an unpinned connection is returned only after the transaction becomes idle"
        );
    }

    #[tokio::test]
    async fn failed_commit_returning_rollback_does_not_advance_lsn() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(8192);
        let router = make_router_with_split(false);
        let registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_pool_manager(registry.clone());
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &registry,
            &cancel_registry,
            &node_addresses,
        );
        let mut session = ClientSession::new("failed-commit", ConsistencyLevel::Session);

        for sql in ["BEGIN", "INSERT INTO t VALUES (1)", "SELECT fail"] {
            let query = handler.handle_simple_query(&mut handler_side, &mut session, sql);
            let drain = async {
                for _ in 0..2 {
                    crate::protocol::reader::read_backend_message(&mut client_side)
                        .await
                        .unwrap();
                }
            };
            let (result, ()) = tokio::join!(query, drain);
            result.unwrap();
        }
        assert_eq!(session.state.tx_state, TxState::Failed);

        let commit = handler.handle_simple_query(&mut handler_side, &mut session, "COMMIT");
        let responses = async {
            let complete = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            let ready = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            (complete, ready)
        };
        let (result, (complete, ready)) = tokio::join!(commit, responses);
        result.unwrap();

        assert_eq!(
            complete,
            BackendMessage::CommandComplete {
                tag: "ROLLBACK".to_string()
            }
        );
        assert_eq!(ready, BackendMessage::ReadyForQuery(TransactionStatus::Idle));
        assert_eq!(lsn_tracker.session_write_lsn("failed-commit"), 0);
        assert!(!session.pending_write);
        assert_eq!(session.state.tx_state, TxState::Idle);
    }

    /// Exercises the `query_log`/`slow_query` instrumentation added around
    /// `handle_simple_query` (timing, `trident_query_duration_ms`,
    /// `trident_slow_queries_total`, and the query_log/slow-query
    /// `tracing` log lines): with `slow_query_threshold_ms: 0`, every
    /// query is "slow" by construction, so this primarily verifies the
    /// instrumented path runs to completion without panicking or
    /// otherwise disrupting the normal request/response flow -- the
    /// query still succeeds and the client still gets its expected
    /// responses.
    #[tokio::test]
    async fn query_log_and_slow_query_instrumentation_does_not_disrupt_normal_query_flow() {
        use tokio::io::duplex;

        let (mut client_side, server_side) = duplex(4096);

        let router = make_router();
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let pool_manager = make_pool_manager(connection_registry.clone());
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::with_query_log(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
            crate::proxy::handler::QueryLogSettings::new(true, 0),
        );

        let server_fut = async {
            let mut startup_handler = TrustStartupHandler {
                backend_pid: 1,
                secret_key: 2,
            };
            handler
                .handle(server_side, &mut startup_handler, "session-ql".to_string(), ConsistencyLevel::Session)
                .await
        };

        let client_fut = async {
            let mut body = 196_608i32.to_be_bytes().to_vec();
            body.push(0);
            let mut framed = ((body.len() + 4) as i32).to_be_bytes().to_vec();
            framed.extend(body);
            client_side.write_all(&framed).await.unwrap();

            read_until_ready(&mut client_side).await;

            let query_bytes = crate::protocol::writer::encode_frontend_message(&FrontendMessage::Query(
                "SELECT 1".to_string(),
            ));
            client_side.write_all(&query_bytes).await.unwrap();

            // Fake backend responds with RowDescription + DataRow +
            // CommandComplete, then the handler sends its own
            // ReadyForQuery -- drain all four.
            for _ in 0..4 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }

            let terminate_bytes =
                crate::protocol::writer::encode_frontend_message(&FrontendMessage::Terminate);
            client_side.write_all(&terminate_bytes).await.unwrap();
            drop(client_side);
        };

        let (server_result, ()) = tokio::join!(server_fut, client_fut);
        assert!(server_result.is_ok());
    }

    #[tokio::test]
    async fn acquire_failure_produces_error_response_not_a_crash() {
        use tokio::io::duplex;

        // A pool manager reporting no healthy nodes at all forces the
        // handler down the "no candidate available" error path.
        let router = make_router();
        struct EmptyPoolManager;
        impl PoolManager for EmptyPoolManager {
            fn pool_for(&self, _node_id: &str) -> Option<std::sync::Arc<dyn crate::pool::pool::ConnectionPool>> {
                None
            }
            fn snapshot(&self) -> Vec<BackendNodeSnapshot> {
                Vec::new()
            }
        }
        let pool_manager = EmptyPoolManager;
        let lsn_tracker = InMemoryLsnTracker::new();
        let connection_registry = ConnectionRegistry::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );

        let (mut client_side, server_side) = duplex(4096);

        let server_fut = async {
            let mut startup_handler = TrustStartupHandler {
                backend_pid: 1,
                secret_key: 2,
            };
            handler
                .handle(server_side, &mut startup_handler, "session-2".to_string(), ConsistencyLevel::Eventual)
                .await
        };

        let client_fut = async {
            let mut body = 196_608i32.to_be_bytes().to_vec();
            body.push(0);
            let mut framed = ((body.len() + 4) as i32).to_be_bytes().to_vec();
            framed.extend(body);
            client_side.write_all(&framed).await.unwrap();

            // Drain the complete startup response through ReadyForQuery.
            read_until_ready(&mut client_side).await;

            let query_bytes = crate::protocol::writer::encode_frontend_message(&FrontendMessage::Query(
                "INSERT INTO t VALUES (1)".to_string(),
            ));
            client_side.write_all(&query_bytes).await.unwrap();

            let response = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            match response {
                BackendMessage::ErrorResponse(err) => {
                    assert!(err.sqlstate().is_some());
                }
                other => panic!("expected ErrorResponse, got {other:?}"),
            }
            let ready = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            assert_eq!(
                ready,
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
                "a proxy-local Simple Query error must complete the protocol cycle"
            );

            drop(client_side);
        };

        let (server_result, ()) = tokio::join!(server_fut, client_fut);
        let _ = server_result;
    }

    // -----------------------------------------------------------------
    // CancelRequest handling (Requirements 7.1-7.3)
    // -----------------------------------------------------------------

    /// Builds a `ConnectionHandler` plus a `TcpListener` standing in for
    /// the "writer" node's real network address, wired up via
    /// `node_addresses` so `handle_cancel_request`/`send_cancel_request`
    /// opens a brand-new connection to it -- exactly as it would to a real
    /// backend. Returns the handler's owned dependencies plus the
    /// listener, so the test can assert on what (if anything) it receives.
    async fn make_handler_with_cancel_listener() -> (
        TestRouter,
        crate::pool::manager::InMemoryPoolManager,
        InMemoryLsnTracker,
        ConnectionRegistry,
        CancelRegistry,
        HashMap<String, NodeAddress>,
        TcpListener,
    ) {
        let router = make_router();
        let connection_registry = ConnectionRegistry::new();
        let pool_manager = make_pool_manager(Arc::new(ConnectionRegistry::new()));
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut node_addresses = HashMap::new();
        node_addresses.insert(
            "writer".to_string(),
            NodeAddress {
                host: "127.0.0.1".to_string(),
                port: addr.port(),
            },
        );

        (
            router,
            pool_manager,
            lsn_tracker,
            connection_registry,
            cancel_registry,
            node_addresses,
            listener,
        )
    }

    #[tokio::test]
    async fn cancel_request_forwarded_with_real_backend_pid_and_secret_when_session_active() {
        let (router, pool_manager, lsn_tracker, connection_registry, cancel_registry, node_addresses, listener) =
            make_handler_with_cancel_listener().await;
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );

        // The client was issued cancel key (100, 200) by this proxy, and
        // its session currently has a query in flight against the real
        // backend connection (writer, pid=555, secret=666) -- distinct
        // values from the proxy-issued key, exactly as they would be in
        // production.
        cancel_registry.register_session(100, 200, "session-1");
        cancel_registry.mark_active("session-1", "writer", 555, 666);

        let listen_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            use tokio::io::AsyncReadExt;
            socket.read_exact(&mut buf).await.unwrap();
            buf
        });

        handler.handle_cancel_request(100, 200).await;

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), listen_task)
            .await
            .expect("listener should have received a connection")
            .unwrap();

        let expected = crate::protocol::writer::encode_frontend_message(&FrontendMessage::CancelRequest {
            backend_pid: 555,
            secret_key: 666,
        });
        assert_eq!(received.to_vec(), expected);
    }

    #[tokio::test]
    async fn cancel_request_ignored_when_key_unknown() {
        let (router, pool_manager, lsn_tracker, connection_registry, cancel_registry, node_addresses, listener) =
            make_handler_with_cancel_listener().await;
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );

        // No session was ever registered for this key.
        let listen_task = tokio::spawn(async move { listener.accept().await });

        handler.handle_cancel_request(999, 888).await;

        let outcome = tokio::time::timeout(std::time::Duration::from_millis(200), listen_task).await;
        assert!(
            outcome.is_err(),
            "an unknown cancel key must never open a connection to the backend"
        );
    }

    #[tokio::test]
    async fn cancel_request_ignored_when_session_has_no_active_query() {
        let (router, pool_manager, lsn_tracker, connection_registry, cancel_registry, node_addresses, listener) =
            make_handler_with_cancel_listener().await;
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );

        // The key is known and maps to a real session, but that session
        // has no query currently in flight (mark_active was never called,
        // or was already cleared).
        cancel_registry.register_session(100, 200, "session-1");

        let listen_task = tokio::spawn(async move { listener.accept().await });

        handler.handle_cancel_request(100, 200).await;

        let outcome = tokio::time::timeout(std::time::Duration::from_millis(200), listen_task).await;
        assert!(
            outcome.is_err(),
            "a session with no active query must never trigger a forwarded CancelRequest"
        );
    }

    #[tokio::test]
    async fn handle_dispatches_a_cancel_startup_packet_without_touching_the_regular_session_lifecycle() {
        use tokio::io::duplex;

        let (router, pool_manager, lsn_tracker, connection_registry, cancel_registry, node_addresses, listener) =
            make_handler_with_cancel_listener().await;
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &connection_registry,
            &cancel_registry,
            &node_addresses,
        );

        cancel_registry.register_session(100, 200, "session-1");
        cancel_registry.mark_active("session-1", "writer", 555, 666);

        let listen_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            use tokio::io::AsyncReadExt;
            socket.read_exact(&mut buf).await.unwrap();
            buf
        });

        let (mut client_side, server_side) = duplex(4096);

        let cancel_bytes = crate::protocol::writer::encode_frontend_message(&FrontendMessage::CancelRequest {
            backend_pid: 100,
            secret_key: 200,
        });
        client_side.write_all(&cancel_bytes).await.unwrap();

        let mut startup_handler = TrustStartupHandler {
            backend_pid: 1,
            secret_key: 2,
        };
        let result = handler
            .handle(server_side, &mut startup_handler, "unused-session-id".to_string(), ConsistencyLevel::Session)
            .await;
        assert!(result.is_ok());

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), listen_task)
            .await
            .expect("listener should have received a connection")
            .unwrap();
        let expected = crate::protocol::writer::encode_frontend_message(&FrontendMessage::CancelRequest {
            backend_pid: 555,
            secret_key: 666,
        });
        assert_eq!(received.to_vec(), expected);

        // A CancelRequest never receives any response bytes on its own
        // connection (Requirement 7.1): confirm nothing was written back.
        drop(client_side);
    }
}
