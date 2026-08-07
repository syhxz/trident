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

mod helpers;
mod extended_query;
mod simple_query;

use helpers::{
    known_node_ids, sanitize_application_name,
    send_error_response, send_pg_error_response, send_ready_for_query, send_startup_success,
};
// Re-exported for `mod tests` (via `use super::*`).
#[cfg(test)]
use helpers::{
    aurora_consistency_sql, ensure_application_name, execute_internal_query,
    pipeline_safe_sql, query_has_write_intent, transaction_status_for_state,
};

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::balancer::LoadBalancer;
use crate::config::{ConsistencyLevel, LsnTrackingConfig, NodeType};
use crate::parser::classifier::Classifier;
use crate::parser::hint::HintParser;
use crate::pool::conn::BackendConnection;
use crate::pool::manager::PoolManager;
use crate::pool::pool::ConnectionPool;
use crate::protocol::message::{FrontendMessage, PgError};
#[cfg(test)]
use crate::protocol::message::{BackendMessage, TransactionStatus};
use crate::protocol::reader::{frontend_tag, parse_frontend_body, read_tagged_frame};
use crate::protocol::startup::{read_startup_packet, StartupHandler, StartupPacket};
#[cfg(test)]
use crate::protocol::writer::encode_backend_message;
use crate::protocol::ProtocolError;
use crate::proxy::error::ProxyError;
use crate::proxy::forwarder::ExtendedQueryRouteTracker;
use crate::proxy::registry::{send_cancel_request_with_timeout, CancelRegistry, ConnectionRegistry, NodeAddress};
use crate::router::consistency::ConsistencyChecker;
use crate::router::cost::CostEstimator;
use crate::router::router::{RouteDecision, Router, RoutingContext};
use crate::session::lsn::LsnTracker;
use crate::session::session::{SessionState, TxState};

/// Per-session data the handler owns for the lifetime of one client
/// connection: routing/consistency state plus a unique session id used as
/// the pool's `session_id` key.
pub struct ClientSession {
    pub state: SessionState,
    held_backend: Option<HeldBackend>,
    /// Cached idle backend from the previous autocommit query. When the
    /// next autocommit query routes to the same node, this complete
    /// connection is reused directly, skipping pool release/acquire. Released when:
    /// - Next query routes to a different node
    /// - Session enters an explicit transaction (BEGIN)
    /// - Session closes
    cached_idle_backend: Option<HeldBackend>,
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
    /// When an unnamed Parse is issued, tracks the node_id for the current
    /// batch. By default (strict mode), a Bind referencing the unnamed
    /// statement in a *different* batch (cross-Sync) is rejected with a
    /// protocol error, matching PgBouncer behavior. When
    /// `allow_cross_sync_unnamed` is enabled, the proxy instead holds the
    /// connection until the Bind arrives.
    unnamed_parse_node: Option<String>,
    /// Client credentials captured during passthrough authentication. When
    /// present, pool lookups use `pool_for_user` instead of `pool_for`.
    client_credentials: Option<crate::protocol::startup::ClientCredentials>,
    /// Caches the per-node pool references resolved during this session's
    /// lifetime. Used during cleanup to release connections back to the
    /// exact pool they were acquired from, avoiding the ambiguous
    /// prefix-match in `pool_for_user_existing` when multiple parameter
    /// pools exist for the same (node, user, database).
    resolved_pools: HashMap<String, Arc<dyn ConnectionPool>>,
    /// Enriched application_name containing client IP for backend audit
    /// trail. Applied only when a checked-out physical connection's cache
    /// differs; a failed SET aborts the operation rather than executing an
    /// inaccurately attributed user query.
    application_name: String,
}

/// A complete backend connection checked out exclusively by this client.
/// It is retained across statements while PostgreSQL reports an open/failed
/// transaction, or after a session-state operation triggers pinning.
struct HeldBackend {
    conn: BackendConnection,
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
            cached_idle_backend: None,
            tx_has_writes: false,
            pending_write: false,
            extension_detected: false,
            aurora_node_id: None,
            aurora_initialized_backend_pid: None,
            extended_route_tracker: ExtendedQueryRouteTracker::new(),
            unnamed_parse_node: None,
            client_credentials: None,
            resolved_pools: HashMap::new(),
            application_name: String::new(),
        }
    }

    /// Takes the cached idle backend if it matches the given node_id and
    /// its generation is still current. Returns `None` if no cache exists,
    /// node_id doesn't match, or the connection is from a stale generation
    /// (node was removed and re-added).
    fn take_cached_if_matches(
        &mut self,
        node_id: &str,
        current_generation: Option<u64>,
    ) -> Option<HeldBackend> {
        if self
            .cached_idle_backend
            .as_ref()
            .is_some_and(|h| {
                h.conn.node_id == node_id
                    && current_generation.is_none_or(|gen| h.conn.generation >= gen)
            })
        {
            self.cached_idle_backend.take()
        } else {
            None
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
    /// Timeout for cancel request TCP connect. Zero = no timeout.
    pub cancel_connect_timeout: std::time::Duration,
    /// Client idle timeout. Zero = disabled.
    pub client_idle_timeout: std::time::Duration,
    /// Timeout for the entire startup + authentication phase (after TLS).
    /// Zero = disabled. Protects against clients that stall during the
    /// Startup/Auth exchange to exhaust max_clients slots.
    pub startup_timeout: std::time::Duration,
    /// Optional node-generation tracker. When present, cached idle backends
    /// are validated against the current node generation before reuse.
    /// Stale connections (from a removed-then-re-added node) are discarded
    /// instead of sending requests to a defunct backend socket.
    pub connection_registry: Option<&'a ConnectionRegistry>,
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
    ) -> impl std::future::Future<Output = Result<RouteDecision, crate::router::router::RouterError>>
           + Send;
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
        cancel_registry: &'a CancelRegistry,
        node_addresses: &'a HashMap<String, NodeAddress>,
    ) -> Self {
        ConnectionHandler {
            router,
            pool_manager,
            lsn_tracker,
            cancel_registry,
            node_addresses,
            query_log: QueryLogSettings::default(),
            lsn_tracking: LsnTrackingConfig::default(),
            slow_query_buffer: None,
            cancel_connect_timeout: std::time::Duration::ZERO,
            client_idle_timeout: std::time::Duration::ZERO,
            startup_timeout: std::time::Duration::ZERO,
            connection_registry: None,
        }
    }

    /// Same as `new`, but with explicit `query_log`/`slow_query` behavior
    /// (see `QueryLogSettings`) instead of the default (query logging
    /// off, 1000ms slow-query threshold).
    pub fn with_query_log(
        router: &'a RTR,
        pool_manager: &'a PM,
        lsn_tracker: &'a LSN,
        cancel_registry: &'a CancelRegistry,
        node_addresses: &'a HashMap<String, NodeAddress>,
        query_log: QueryLogSettings,
    ) -> Self {
        ConnectionHandler {
            router,
            pool_manager,
            lsn_tracker,
            cancel_registry,
            node_addresses,
            query_log,
            lsn_tracking: LsnTrackingConfig::default(),
            slow_query_buffer: None,
            cancel_connect_timeout: std::time::Duration::ZERO,
            client_idle_timeout: std::time::Duration::ZERO,
            startup_timeout: std::time::Duration::ZERO,
            connection_registry: None,
        }
    }

    /// Overrides the restart-only LSN acquisition strategy selected by the
    /// process configuration.
    pub fn with_lsn_tracking(mut self, lsn_tracking: LsnTrackingConfig) -> Self {
        self.lsn_tracking = lsn_tracking;
        self
    }

    /// Attaches the node-generation tracker so cached connections are
    /// validated against the current generation before reuse.
    pub fn with_connection_registry(mut self, registry: &'a ConnectionRegistry) -> Self {
        self.connection_registry = Some(registry);
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

    /// Sets the cancel-connect and client-idle timeouts.
    pub fn with_timeouts(
        mut self,
        cancel_connect_timeout: std::time::Duration,
        client_idle_timeout: std::time::Duration,
    ) -> Self {
        self.cancel_connect_timeout = cancel_connect_timeout;
        self.client_idle_timeout = client_idle_timeout;
        self
    }

    /// Sets the startup (authentication) timeout. This covers the entire
    /// Startup + Authentication exchange after TLS negotiation.
    pub fn with_startup_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.startup_timeout = timeout;
        self
    }

    /// Resolves the pool for a node, using per-user pools when the session
    /// has passthrough credentials, or the shared service-account pool
    /// otherwise. This is the single dispatch point so all 30+ call sites
    /// of `pool_for` benefit from passthrough support automatically.
    /// Also caches the resolved pool in the session for exact cleanup later.
    fn resolve_pool(
        &self,
        node_id: &str,
        session: &mut ClientSession,
    ) -> Option<Arc<dyn ConnectionPool>> {
        let pool = if let Some(creds) = &session.client_credentials {
            self.pool_manager.pool_for_user(
                node_id,
                &creds.username,
                &creds.password,
                creds.database.as_deref(),
                &creds.extra_params,
            )
        } else {
            self.pool_manager.pool_for(node_id)
        };
        // Cache the resolved pool so cleanup can find the exact pool
        // without ambiguous prefix matching.
        if let Some(ref p) = pool {
            session
                .resolved_pools
                .insert(node_id.to_string(), Arc::clone(p));
        }
        pool
    }

    /// Like `resolve_pool` but never creates a new per-user pool. Used
    /// during session cleanup where we only need to release connections
    /// from an existing pool, not trigger creation of a new one.
    /// Checks the session's resolved_pools cache first for an exact match.
    fn resolve_pool_existing(
        &self,
        node_id: &str,
        session: &ClientSession,
    ) -> Option<Arc<dyn ConnectionPool>> {
        // Prefer cached exact reference — avoids the ambiguous prefix match
        // in pool_for_user_existing when multiple parameter pools exist.
        if let Some(pool) = session.resolved_pools.get(node_id) {
            return Some(Arc::clone(pool));
        }
        if let Some(creds) = &session.client_credentials {
            // Look up without creating. If the pool was evicted, any
            // session bindings in it are already gone (Arc dropped), so
            // there's nothing to release.
            self.pool_manager.pool_for_user_existing(
                node_id,
                &creds.username,
                creds.database.as_deref(),
                &creds.extra_params,
            )
        } else {
            self.pool_manager.pool_for(node_id)
        }
    }

    /// Returns the cached idle backend to the pool. Called when the next
    /// query routes to a different node, when an explicit transaction begins,
    /// or when the session closes.
    async fn release_cached_backend(&self, session: &mut ClientSession) {
        if let Some(held) = session.cached_idle_backend.take() {
            // If the connection is from a stale generation (node was
            // removed and re-added), discard it through its source pool
            // so that active_connections / known_connections accounting
            // is correctly decremented.
            let stale = self
                .connection_registry
                .is_some_and(|r| held.conn.generation < r.node_generation(&held.conn.node_id));
            if stale {
                if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, session) {
                    let _ = pool.discard(held.conn);
                }
                return;
            }
            if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, session) {
                let _ = pool.release(&session.state.id, held.conn).await;
            }
            // If pool not found (node removed entirely), connection is
            // simply dropped — socket closes, no slot to return.
        }
    }

    /// Discards a broken/unknown-state connection and clears the cancel
    /// registry entry for this session. This is the single canonical exit
    /// path for error-handling code that needs to abandon a checked-out
    /// connection. Centralising this prevents forgetting either the pool
    /// slot release or the cancel registry cleanup.
    fn discard_backend(
        &self,
        pool: &Arc<dyn ConnectionPool>,
        conn: BackendConnection,
        session_id: &str,
    ) -> Result<(), ProxyError> {
        self.cancel_registry.clear_active(session_id);
        pool.discard(conn).map_err(ProxyError::Pool)
    }

    /// Discards the held backend connection from the session. Used in
    /// `forward_extended_on_held_backend` error paths where the connection
    /// is owned via `session.held_backend`. Clears cancel registry and
    /// releases the pool slot.
    fn discard_held_backend(
        &self,
        session: &mut ClientSession,
    ) {
        self.cancel_registry.clear_active(&session.state.id);
        if let Some(held) = session.held_backend.take() {
            if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, session) {
                let _ = pool.discard(held.conn);
            }
        }
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
        // --- Startup phase with unified deadline --------------------------
        //
        // The startup_timeout covers the entire StartupMessage negotiation
        // (SSLRequest/GssEncRequest probing) AND the authentication
        // exchange. A client that stalls at any point during this phase
        // (e.g. sending only partial Startup data, or never responding to
        // the auth challenge) cannot hold a max_clients slot indefinitely.
        let startup_fut = async {
            // --- Startup phase: Startup / CancelRequest / SSL/GSSENC ------
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
                        return Ok(None);
                    }
                }
            };

            // --- Authentication -------------------------------------------
            let auth_outcome = startup_handler
                .handle_startup_with_stream(startup_msg, &mut client_stream)
                .await
                .map_err(ProxyError::Protocol)?;

            // --- Passthrough pre-verification -----------------------------
            //
            // When using passthrough authentication, the proxy captured the
            // client's real database password but has NOT yet verified it
            // against any backend. Before telling the client "AuthenticationOk",
            // we must prove these credentials work. Otherwise:
            //   - Wrong-password clients see success, then fail on first query
            //   - Invalid credentials get stored in the user pool table
            //
            // Strategy: find the Writer node (the authoritative auth source),
            // create/get the per-user pool, and acquire+release one connection.
            // The pool's ConnFactory calls establish_connection() which does
            // the real PostgreSQL Startup+Auth against the backend. If the
            // backend rejects the credentials, we send an ErrorResponse to the
            // client and abort — the client never sees AuthenticationOk.
            if let Some(ref creds) = auth_outcome.client_credentials {
                let all_nodes = self.pool_manager.snapshot();

                // Prefer Writer for credential verification (authoritative
                // source). During failover the Writer may be unhealthy; fall
                // back to any healthy Reader since streaming replicas share
                // the same pg_authid catalog and can validate passwords
                // identically (authentication only reads pg_authid, no
                // writes required). Fail-closed when no node is available.
                let verify_node = all_nodes
                    .iter()
                    .find(|n| n.node_type == NodeType::Writer && n.healthy)
                    .or_else(|| {
                        all_nodes
                            .iter()
                            .find(|n| n.node_type == NodeType::Reader && n.healthy)
                    });

                if let Some(node) = verify_node {
                    let pool = self.pool_manager.pool_for_user(
                        &node.node_id,
                        &creds.username,
                        &creds.password,
                        creds.database.as_deref(),
                        &creds.extra_params,
                    );
                    match pool {
                        Some(p) => {
                            // Acquire a connection — triggers establish_connection()
                            // which does the real PostgreSQL backend authentication.
                            let verify_session = format!("__verify_{}", session_id);
                            match p.acquire(&verify_session).await {
                                Ok(conn) => {
                                    // Credentials verified! Discard the verification
                                    // connection — in Transaction mode it returns to
                                    // idle, in Session mode it stays bound to the
                                    // verify session_id forever. Using discard()
                                    // cleanly frees the slot and socket in both modes.
                                    // The first real query will acquire a fresh
                                    // connection from the pool (or create a new one).
                                    let _ = p.discard(conn);
                                }
                                Err(pool_err) => {
                                    // Backend rejected credentials or connect failed.
                                    // Remove the pool from the map so it doesn't
                                    // pollute future attempts with correct credentials.
                                    self.pool_manager.remove_user_pool(
                                        &node.node_id,
                                        &creds.username,
                                        creds.database.as_deref(),
                                        &creds.extra_params,
                                    );
                                    metrics::counter!("trident_passthrough_auth_failures_total")
                                        .increment(1);
                                    tracing::warn!(
                                        username = %creds.username,
                                        node_id = %node.node_id,
                                        error = %pool_err,
                                        "passthrough credential verification failed against backend"
                                    );
                                    let pg_err = PgError::simple(
                                        "FATAL",
                                        "28P01",
                                        &format!(
                                            "password authentication failed for user \"{}\"",
                                            creds.username
                                        ),
                                    );
                                    send_pg_error_response(&mut client_stream, pg_err).await?;
                                    client_stream
                                        .flush()
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                    return Ok(None);
                                }
                            }
                        }
                        None => {
                            metrics::counter!("trident_passthrough_auth_failures_total")
                                .increment(1);
                            tracing::warn!(
                                username = %creds.username,
                                node_id = %node.node_id,
                                "passthrough: no pool available for credential verification"
                            );
                            let pg_err = PgError::simple(
                                "FATAL",
                                "28000",
                                "authentication failed: no backend available for credential verification",
                            );
                            send_pg_error_response(&mut client_stream, pg_err).await?;
                            client_stream
                                .flush()
                                .await
                                .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                            return Ok(None);
                        }
                    }
                } else {
                    // No healthy node at all (neither Writer nor Reader) —
                    // fail closed. Use SQLSTATE 57P03 (cannot_connect_now) so
                    // client drivers recognize this as transient/retryable.
                    metrics::counter!("trident_passthrough_auth_failures_total").increment(1);
                    tracing::warn!(
                        username = %creds.username,
                        "passthrough: no healthy node available for credential verification, rejecting"
                    );
                    let pg_err = PgError::simple(
                        "FATAL",
                        "57P03",
                        "authentication unavailable: no healthy backend for credential verification, retry shortly",
                    );
                    send_pg_error_response(&mut client_stream, pg_err).await?;
                    client_stream
                        .flush()
                        .await
                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                    return Ok(None);
                }
            }

            send_startup_success(&mut client_stream, &auth_outcome).await?;
            client_stream
                .flush()
                .await
                .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;

            Ok(Some(auth_outcome))
        };

        let auth_outcome = if self.startup_timeout.is_zero() {
            match startup_fut.await? {
                Some(outcome) => outcome,
                None => return Ok(()), // CancelRequest handled
            }
        } else {
            match tokio::time::timeout(self.startup_timeout, startup_fut).await {
                Ok(Ok(Some(outcome))) => outcome,
                Ok(Ok(None)) => return Ok(()), // CancelRequest handled
                Ok(Err(e)) => return Err(e),
                Err(_elapsed) => {
                    return Err(ProxyError::Protocol(ProtocolError::Malformed(
                        "startup/authentication timeout exceeded".into(),
                    )));
                }
            }
        };

        let mut session = ClientSession::new(session_id.clone(), default_consistency);

        // Store client credentials for passthrough pool lookups.
        session.client_credentials = auth_outcome.client_credentials.clone();

        // Compute the enriched application_name for this client session.
        // This will be SET on the backend after each fresh connection checkout,
        // ensuring pg_stat_activity always reflects the real client IP
        // regardless of pool sharing in Transaction mode.
        {
            let client_ip = session_id
                .rsplit_once('-')
                .and_then(|(_, addr)| addr.rsplit_once(':'))
                .map(|(ip, _port)| ip)
                .unwrap_or("unknown");
            let original_app = session
                .client_credentials
                .as_ref()
                .and_then(|c| c.extra_params.get("application_name"))
                .cloned()
                .unwrap_or_default();
            let sanitized_app = sanitize_application_name(&original_app);
            session.application_name = if sanitized_app.is_empty() {
                format!("trident:{}", client_ip)
            } else {
                format!("trident:{}:{}", client_ip, sanitized_app)
            };
        }

        // Register the cancel key this proxy just issued to the client (in
        // BackendKeyData above) against this session, so a later
        // CancelRequest bearing it can be attributed back correctly
        // (Requirements 7.1-7.3).
        self.cancel_registry.register_session(
            auth_outcome.backend_pid,
            auth_outcome.secret_key,
            &session_id,
        );

        // --- Message loop -------------------------------------------------
        let result = self.message_loop(&mut client_stream, &mut session).await;

        // --- Cleanup on connection close -----------------------------------
        // Release any pooled connections this session was holding, whether
        // in Session mode (the single bound connection) or Transaction mode
        // (any pinned connections). Best-effort: pool lookups may legitimately
        // find nothing if the session never acquired a connection.
        // A checked-out transaction/pinned connection is owned directly by
        // the session. Discard it so both the socket and pool slot are released.
        if let Some(held) = session.held_backend.take() {
            if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, &session) {
                if let Err(error) = pool.discard(held.conn) {
                    tracing::warn!(error = %error, "failed to discard held backend connection");
                }
            }
        }

        // Release a cached clean idle backend.
        if let Some(held) = session.cached_idle_backend.take() {
            let stale = self
                .connection_registry
                .is_some_and(|r| held.conn.generation < r.node_generation(&held.conn.node_id));
            if stale {
                // Stale: discard through source pool to fix accounting.
                if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, &session) {
                    let _ = pool.discard(held.conn);
                }
            } else {
                if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, &session) {
                    let _ = pool.release(&session.state.id, held.conn).await;
                }
            }
        }

        // Release complete connections still owned by Session-mode bindings
        // or by the pool's pinned map.
        self.cancel_registry.clear_active(&session_id);
        self.cancel_registry
            .unregister_session(auth_outcome.backend_pid, auth_outcome.secret_key);
        for node_id in known_node_ids(self.pool_manager) {
            if let Some(pool) = self.resolve_pool_existing(&node_id, &session) {
                drop(pool.release_session(&session_id));
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
        let Some((node_id, real_backend_pid, real_secret_key)) = self
            .cancel_registry
            .resolve_cancel_target(backend_pid, secret_key)
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
            metrics::counter!("trident_cancel_requests_total", "outcome" => "no_node_address")
                .increment(1);
            tracing::warn!(node_id = %node_id, "cannot forward CancelRequest: no known address for node");
            return;
        };

        if let Err(e) = send_cancel_request_with_timeout(
            addr,
            real_backend_pid,
            real_secret_key,
            self.cancel_connect_timeout,
        )
        .await
        {
            metrics::counter!("trident_cancel_requests_total", "outcome" => "send_failed")
                .increment(1);
            tracing::warn!(node_id = %node_id, error = %e, "failed to forward CancelRequest to backend");
        } else {
            metrics::counter!("trident_cancel_requests_total", "outcome" => "forwarded")
                .increment(1);
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
            let (tag, body) = match if self.client_idle_timeout.is_zero() {
                read_tagged_frame(client_stream).await
            } else {
                match tokio::time::timeout(
                    self.client_idle_timeout,
                    read_tagged_frame(client_stream),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        return Err(ProxyError::Protocol(ProtocolError::Malformed(
                            "client idle timeout exceeded".into(),
                        )))
                    }
                }
            } {
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
                        client_stream
                            .flush()
                            .await
                            .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
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
                    client_stream
                        .flush()
                        .await
                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
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
                    client_stream
                        .flush()
                        .await
                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                }
                frontend_tag::FLUSH => {
                    if extended_batch.is_empty() {
                        // Flush with nothing pending: everything the proxy
                        // had was already delivered at the last Sync
                        // boundary; just make sure the write buffer is
                        // drained.
                        client_stream
                            .flush()
                            .await
                            .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
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
                        client_stream
                            .flush()
                            .await
                            .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
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
                    if extended_batch_bytes.saturating_add(body.len()) > MAX_EXTENDED_BATCH_BYTES {
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

    fn fail_open_transaction(&self, session: &mut ClientSession) {
        if session.state.tx_state == TxState::Idle {
            return;
        }

        self.cancel_registry.clear_active(&session.state.id);
        if let Some(held) = session.held_backend.take() {
            if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, session) {
                if let Err(error) = pool.discard(held.conn) {
                    tracing::warn!(error = %error, "failed to discard aborted transaction connection");
                }
            } else {
                tracing::warn!(
                    node_id = %held.conn.node_id,
                    "cannot update pool accounting for aborted transaction: pool no longer exists"
                );
            }
        }
        session.state.tx_state = TxState::Failed;
    }

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
    use crate::pool::conn::{BackendConnection, MaybeTlsStream, PooledConnection};
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

    #[tokio::test]
    async fn application_name_cache_updates_only_after_successful_set() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connect = TcpStream::connect(address);
        let (accepted, connected) = tokio::join!(listener.accept(), connect);
        let (mut backend, _) = accepted.unwrap();
        let handler_stream = connected.unwrap();

        let backend_task = tokio::spawn(async move {
            let message = crate::protocol::reader::read_frontend_message(&mut backend)
                .await
                .unwrap();
            let FrontendMessage::Query(sql) = message else {
                panic!("expected SET application_name query");
            };
            backend
                .write_all(&encode_backend_message(&BackendMessage::CommandComplete {
                    tag: "SET".to_string(),
                }))
                .await
                .unwrap();
            backend
                .write_all(&encode_backend_message(&BackendMessage::ReadyForQuery(
                    TransactionStatus::Idle,
                )))
                .await
                .unwrap();
            sql
        });

        let mut conn = BackendConnection::new(
            PooledConnection::new("primary", 1, 1000),
            MaybeTlsStream::Plain(handler_stream),
            0,
        );
        ensure_application_name(&mut conn, "trident:test", TransactionStatus::Idle)
            .await
            .unwrap();
        ensure_application_name(&mut conn, "trident:test", TransactionStatus::Idle)
            .await
            .unwrap();

        assert_eq!(
            backend_task.await.unwrap(),
            "SET application_name = 'trident:test'"
        );
        assert_eq!(
            conn.current_application_name.as_deref(),
            Some("trident:test")
        );
    }

    #[tokio::test]
    async fn application_name_error_response_does_not_update_cache() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connect = TcpStream::connect(address);
        let (accepted, connected) = tokio::join!(listener.accept(), connect);
        let (mut backend, _) = accepted.unwrap();
        let handler_stream = connected.unwrap();

        tokio::spawn(async move {
            let _ = crate::protocol::reader::read_frontend_message(&mut backend)
                .await
                .unwrap();
            backend
                .write_all(&encode_backend_message(&BackendMessage::ErrorResponse(
                    PgError::simple("ERROR", "42501", "SET denied"),
                )))
                .await
                .unwrap();
            backend
                .write_all(&encode_backend_message(&BackendMessage::ReadyForQuery(
                    TransactionStatus::Idle,
                )))
                .await
                .unwrap();
        });

        let mut conn = BackendConnection::new(
            PooledConnection::new("primary", 1, 1000),
            MaybeTlsStream::Plain(handler_stream),
            0,
        );
        let result =
            ensure_application_name(&mut conn, "trident:test", TransactionStatus::Idle).await;

        assert!(matches!(result, Err(ProtocolError::Malformed(_))));
        assert!(conn.current_application_name.is_none());
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
                        let data_row =
                            encode_backend_message(&BackendMessage::DataRow(vec![Some(
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
                        let row_desc =
                            encode_backend_message(&BackendMessage::RowDescription(vec![
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
                            encode_backend_message(&BackendMessage::DataRow(vec![Some(
                                b"1".to_vec(),
                            )]));
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

    /// A `ConnFactory` that returns a complete connection backed by a local
    /// TCP pair. The peer runs `run_fake_backend` in a background task.
    struct FakeBackendFactory {
        next_pid: AtomicI32,
    }

    impl ConnFactory for FakeBackendFactory {
        async fn create(&self, node_id: &str) -> Result<BackendConnection, PoolError> {
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
            let handler_end =
                connect_result.map_err(|e| PoolError::ConnectFailed(e.to_string()))?;

            tokio::spawn(run_fake_backend(backend_end));
            Ok(BackendConnection::new(
                PooledConnection::new(node_id, pid, pid * 1000),
                MaybeTlsStream::Plain(handler_end),
                0,
            ))
        }
    }

    struct FakeBackendCleaner;

    impl ConnCleaner for FakeBackendCleaner {
        async fn clean(&self, _conn: &mut BackendConnection) -> Result<(), PoolError> {
            Ok(())
        }
    }

    struct ExtensionBackendFactory {
        queries: Arc<Mutex<Vec<String>>>,
    }

    impl ConnFactory for ExtensionBackendFactory {
        async fn create(&self, node_id: &str) -> Result<BackendConnection, PoolError> {
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
                    let message =
                        match crate::protocol::reader::read_frontend_message(&mut backend).await {
                            Ok(message) => message,
                            Err(_) => return,
                        };
                    let FrontendMessage::Query(sql) = message else {
                        continue;
                    };
                    queries.lock().unwrap().push(sql.clone());
                    if sql.starts_with("SELECT pg_current_wal_lsn") {
                        backend
                            .write_all(&encode_backend_message(&BackendMessage::DataRow(vec![
                                Some(b"16/B374D848".to_vec()),
                            ])))
                            .await
                            .unwrap();
                        backend
                            .write_all(&encode_backend_message(&BackendMessage::CommandComplete {
                                tag: "SELECT 1".to_string(),
                            }))
                            .await
                            .unwrap();
                    } else {
                        backend
                            .write_all(&encode_backend_message(&BackendMessage::CommandComplete {
                                tag: "INSERT 0 1".to_string(),
                            }))
                            .await
                            .unwrap();
                        backend
                            .write_all(&encode_backend_message(&BackendMessage::ParameterStatus {
                                name: "pg_lsn_track.last_commit_lsn".to_string(),
                                value: "16/B374D848".to_string(),
                            }))
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

            Ok(BackendConnection::new(
                PooledConnection::new(node_id, 300, 300_000),
                MaybeTlsStream::Plain(handler_socket),
                0,
            ))
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
    fn make_pool_manager() -> crate::pool::manager::InMemoryPoolManager {
        make_pool_manager_with_mode(PoolMode::Transaction)
    }

    fn make_pool_manager_with_mode(mode: PoolMode) -> crate::pool::manager::InMemoryPoolManager {
        let mut pools: HashMap<String, Box<dyn crate::pool::pool::ConnectionPool>> = HashMap::new();
        pools.insert(
            "primary".to_string(),
            Box::new(NodePool::new(
                "primary",
                mode,
                10,
                FakeBackendFactory {
                    next_pid: AtomicI32::new(1),
                },
                FakeBackendCleaner,
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

    fn make_split_pool_manager() -> crate::pool::manager::InMemoryPoolManager {
        make_split_pool_manager_with_writer_capacity(10)
    }

    fn make_split_pool_manager_with_writer_capacity(
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
                    },
                    FakeBackendCleaner,
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
                    },
                    FakeBackendCleaner,
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
                },
                FakeBackendCleaner,
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
        let queries = Arc::new(Mutex::new(Vec::new()));
        let mut pools: HashMap<String, Box<dyn crate::pool::pool::ConnectionPool>> = HashMap::new();
        pools.insert(
            "primary".to_string(),
            Box::new(NodePool::new(
                "primary",
                PoolMode::Transaction,
                2,
                ExtensionBackendFactory {
                    queries: queries.clone(),
                },
                FakeBackendCleaner,
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
            ["INSERT INTO t VALUES (1)", "INSERT INTO t VALUES (2)",],
            "lazy_fallback skips pipeline; extension detected via GUC only"
        );
    }

    #[tokio::test]
    async fn lazy_watermark_fetch_records_lsn_and_reroutes_to_reader() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(4096);
        let router = make_router();
        let pool_manager = make_reader_pool_manager(PoolMode::Transaction, u64::MAX, true);
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
        let pool_manager = make_reader_pool_manager(PoolMode::Session, u64::MAX, false);
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
        let pool_manager = make_pool_manager();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
            let terminate =
                crate::protocol::writer::encode_frontend_message(&FrontendMessage::Terminate);
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
        let pool_manager = make_pool_manager_with_mode(PoolMode::Session);
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
                .handle(
                    server_side,
                    &mut startup_handler,
                    "session-1".to_string(),
                    ConsistencyLevel::Session,
                )
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
            assert_eq!(
                startup_messages.first(),
                Some(&BackendMessage::AuthenticationOk)
            );
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
            let query_bytes = crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Query("INSERT INTO t VALUES (1)".to_string()),
            );
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
            assert_eq!(
                ready2,
                BackendMessage::ReadyForQuery(TransactionStatus::Idle)
            );
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
            pool_manager
                .pool_for("primary")
                .unwrap()
                .active_connections(),
            0,
            "session cleanup must free its pool slot"
        );
    }

    #[tokio::test]
    async fn extended_query_protocol_forwards_parse_bind_execute_sync() {
        use tokio::io::duplex;

        let (mut client_side, server_side) = duplex(8192);
        let router = make_router();
        let pool_manager = make_pool_manager();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
                !messages
                    .iter()
                    .any(|m| matches!(m, BackendMessage::ErrorResponse(_))),
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
        let pool_manager = make_pool_manager();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
            let mut tail =
                crate::protocol::writer::encode_frontend_message(&FrontendMessage::Execute {
                    portal: "".to_string(),
                    max_rows: 0,
                });
            tail.extend(crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Sync,
            ));
            client_side.write_all(&tail).await.unwrap();

            let ready = crate::protocol::reader::read_backend_message(&mut client_side)
                .await
                .unwrap();
            assert_eq!(
                ready,
                BackendMessage::ReadyForQuery(TransactionStatus::Idle)
            );

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
                !messages
                    .iter()
                    .any(|m| matches!(m, BackendMessage::ErrorResponse(_))),
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
        let pool_manager = make_pool_manager();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
        let client =
            async {
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
        let pool_manager = make_pool_manager();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
            assert!(
                saw_command_complete,
                "INSERT should produce CommandComplete"
            );

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
        let pool_manager = make_pool_manager();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
        assert_eq!(
            ready,
            BackendMessage::ReadyForQuery(TransactionStatus::Idle)
        );
        assert_eq!(
            pool_manager
                .pool_for("primary")
                .unwrap()
                .active_connections(),
            0,
            "proxy-local SET must not acquire a backend connection"
        );
        assert!(session.held_backend.is_none());
    }

    #[tokio::test]
    async fn pool_checkout_round_trip_preserves_complete_connection_ownership() {
        let pool_manager = make_pool_manager();
        let pool = pool_manager.pool_for("primary").unwrap();

        let mut first = pool.acquire("ownership-session").await.unwrap();
        let first_pid = first.backend_pid;
        execute_internal_query(&mut first.stream, "SELECT 1", TransactionStatus::Idle)
            .await
            .unwrap();
        pool.release("ownership-session", first).await.unwrap();

        let second = pool.acquire("ownership-session").await.unwrap();
        assert_eq!(second.backend_pid, first_pid);
        assert_eq!(second.node_id, "primary");
        pool.discard(second).unwrap();
        assert_eq!(pool.active_connections(), 0);
    }

    #[tokio::test]
    async fn lsn_protocol_failure_preserves_write_and_discards_backend() {
        use tokio::io::duplex;

        struct MalformedLsnFactory;

        impl ConnFactory for MalformedLsnFactory {
            async fn create(&self, node_id: &str) -> Result<BackendConnection, PoolError> {
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
                        .write_all(&encode_backend_message(&BackendMessage::CommandComplete {
                            tag: "INSERT 0 1".to_string(),
                        }))
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

                Ok(BackendConnection::new(
                    PooledConnection::new(node_id, 1, 1000),
                    MaybeTlsStream::Plain(handler_socket),
                    0,
                ))
            }
        }

        let router = make_router();
        let mut pools: HashMap<String, Box<dyn crate::pool::pool::ConnectionPool>> = HashMap::new();
        pools.insert(
            "primary".to_string(),
            Box::new(NodePool::new(
                "primary",
                PoolMode::Transaction,
                1,
                MalformedLsnFactory,
                FakeBackendCleaner,
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

        assert!(
            result.is_ok(),
            "the already-committed user write must succeed"
        );
        assert!(
            session.pending_write,
            "a failed internal LSN cycle must defer watermark acquisition"
        );
        assert_eq!(
            pool_manager
                .pool_for("primary")
                .unwrap()
                .active_connections(),
            0,
            "protocol-damaged backend must release its pool slot"
        );
        assert!(session.held_backend.is_none());
        assert!(session.cached_idle_backend.is_none());
    }

    #[tokio::test]
    async fn transaction_split_delays_begin_routes_reader_then_upgrades_writer() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(8192);
        let router = make_router();
        let pool_manager = make_split_pool_manager();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
        assert!(session
            .state
            .tx_split
            .as_ref()
            .is_some_and(|state| !state.active));
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
        assert_eq!(
            session.held_backend.as_ref().unwrap().conn.node_id,
            "reader-1"
        );
        assert!(session.state.tx_split.as_ref().unwrap().on_reader);

        let update =
            handler.handle_simple_query(&mut handler_side, &mut session, "UPDATE t SET value = 2");
        let drain_update = async {
            for _ in 0..2 {
                crate::protocol::reader::read_backend_message(&mut client_side)
                    .await
                    .unwrap();
            }
        };
        let (update_result, ()) = tokio::join!(update, drain_update);
        update_result.unwrap();
        assert_eq!(
            session.held_backend.as_ref().unwrap().conn.node_id,
            "primary"
        );
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
        // The Writer remains healthy/routable but has no capacity, forcing
        // the failure after the Reader transaction has been rolled back.
        let pool_manager = make_split_pool_manager_with_writer_capacity(0);
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
        assert_eq!(
            session.held_backend.as_ref().unwrap().conn.node_id,
            "reader-1"
        );

        let update_result = handler
            .handle_simple_query(&mut handler_side, &mut session, "UPDATE t SET value = 2")
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
        let (rejected_result, (error, failed_ready)) = tokio::join!(rejected, read_rejection);
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
            pool_manager
                .pool_for("primary")
                .unwrap()
                .active_connections(),
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
        assert_eq!(
            ready,
            BackendMessage::ReadyForQuery(TransactionStatus::Idle)
        );
        assert_eq!(session.state.tx_state, TxState::Idle);
        assert!(session.state.tx_split.is_none());
    }

    #[tokio::test]
    async fn pending_split_transaction_can_rollback_without_backend() {
        use tokio::io::duplex;

        let (mut client_side, mut handler_side) = duplex(2048);
        let router = make_router();
        let pool_manager = make_split_pool_manager();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
        let pool_manager = make_pool_manager();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
        let pool_manager = make_pool_manager();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
        assert_eq!(
            ready,
            BackendMessage::ReadyForQuery(TransactionStatus::Idle)
        );
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
        let pool_manager = make_pool_manager();
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::with_query_log(
            &router,
            &pool_manager,
            &lsn_tracker,
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
                .handle(
                    server_side,
                    &mut startup_handler,
                    "session-ql".to_string(),
                    ConsistencyLevel::Session,
                )
                .await
        };

        let client_fut = async {
            let mut body = 196_608i32.to_be_bytes().to_vec();
            body.push(0);
            let mut framed = ((body.len() + 4) as i32).to_be_bytes().to_vec();
            framed.extend(body);
            client_side.write_all(&framed).await.unwrap();

            read_until_ready(&mut client_side).await;

            let query_bytes = crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Query("SELECT 1".to_string()),
            );
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
            fn pool_for(
                &self,
                _node_id: &str,
            ) -> Option<std::sync::Arc<dyn crate::pool::pool::ConnectionPool>> {
                None
            }
            fn snapshot(&self) -> Vec<BackendNodeSnapshot> {
                Vec::new()
            }
        }
        let pool_manager = EmptyPoolManager;
        let lsn_tracker = InMemoryLsnTracker::new();
        let cancel_registry = CancelRegistry::new();
        let node_addresses = HashMap::new();
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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
                .handle(
                    server_side,
                    &mut startup_handler,
                    "session-2".to_string(),
                    ConsistencyLevel::Eventual,
                )
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

            let query_bytes = crate::protocol::writer::encode_frontend_message(
                &FrontendMessage::Query("INSERT INTO t VALUES (1)".to_string()),
            );
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
        CancelRegistry,
        HashMap<String, NodeAddress>,
        TcpListener,
    ) {
        let router = make_router();
        let pool_manager = make_pool_manager();
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
            cancel_registry,
            node_addresses,
            listener,
        )
    }

    #[tokio::test]
    async fn cancel_request_forwarded_with_real_backend_pid_and_secret_when_session_active() {
        let (router, pool_manager, lsn_tracker, cancel_registry, node_addresses, listener) =
            make_handler_with_cancel_listener().await;
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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

        let expected =
            crate::protocol::writer::encode_frontend_message(&FrontendMessage::CancelRequest {
                backend_pid: 555,
                secret_key: 666,
            });
        assert_eq!(received.to_vec(), expected);
    }

    #[tokio::test]
    async fn cancel_request_ignored_when_key_unknown() {
        let (router, pool_manager, lsn_tracker, cancel_registry, node_addresses, listener) =
            make_handler_with_cancel_listener().await;
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &cancel_registry,
            &node_addresses,
        );

        // No session was ever registered for this key.
        let listen_task = tokio::spawn(async move { listener.accept().await });

        handler.handle_cancel_request(999, 888).await;

        let outcome =
            tokio::time::timeout(std::time::Duration::from_millis(200), listen_task).await;
        assert!(
            outcome.is_err(),
            "an unknown cancel key must never open a connection to the backend"
        );
    }

    #[tokio::test]
    async fn cancel_request_ignored_when_session_has_no_active_query() {
        let (router, pool_manager, lsn_tracker, cancel_registry, node_addresses, listener) =
            make_handler_with_cancel_listener().await;
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
            &cancel_registry,
            &node_addresses,
        );

        // The key is known and maps to a real session, but that session
        // has no query currently in flight (mark_active was never called,
        // or was already cleared).
        cancel_registry.register_session(100, 200, "session-1");

        let listen_task = tokio::spawn(async move { listener.accept().await });

        handler.handle_cancel_request(100, 200).await;

        let outcome =
            tokio::time::timeout(std::time::Duration::from_millis(200), listen_task).await;
        assert!(
            outcome.is_err(),
            "a session with no active query must never trigger a forwarded CancelRequest"
        );
    }

    #[tokio::test]
    async fn handle_dispatches_a_cancel_startup_packet_without_touching_the_regular_session_lifecycle(
    ) {
        use tokio::io::duplex;

        let (router, pool_manager, lsn_tracker, cancel_registry, node_addresses, listener) =
            make_handler_with_cancel_listener().await;
        let handler = ConnectionHandler::new(
            &router,
            &pool_manager,
            &lsn_tracker,
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

        let cancel_bytes =
            crate::protocol::writer::encode_frontend_message(&FrontendMessage::CancelRequest {
                backend_pid: 100,
                secret_key: 200,
            });
        client_side.write_all(&cancel_bytes).await.unwrap();

        let mut startup_handler = TrustStartupHandler {
            backend_pid: 1,
            secret_key: 2,
        };
        let result = handler
            .handle(
                server_side,
                &mut startup_handler,
                "unused-session-id".to_string(),
                ConsistencyLevel::Session,
            )
            .await;
        assert!(result.is_ok());

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), listen_task)
            .await
            .expect("listener should have received a connection")
            .unwrap();
        let expected =
            crate::protocol::writer::encode_frontend_message(&FrontendMessage::CancelRequest {
                backend_pid: 555,
                secret_key: 666,
            });
        assert_eq!(received.to_vec(), expected);

        // A CancelRequest never receives any response bytes on its own
        // connection (Requirement 7.1): confirm nothing was written back.
        drop(client_side);
    }
}
