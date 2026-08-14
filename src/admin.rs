//! Admin/observability HTTP server (`admin`)
//!
//! A small `axum` server, separate from the PostgreSQL wire-protocol
//! listener (`proxy::server::ProxyServer`), exposing:
//!
//! - `GET /metrics`: a Prometheus text-exposition-format scrape endpoint,
//!   backed by the `metrics` crate's global recorder (installed once via
//!   `install_prometheus_recorder`).
//! - `GET /healthz`: a liveness/readiness probe endpoint. Returns `200 OK`
//!   if the routing snapshot contains at least one healthy Writer node
//!   (the minimum bar for the proxy to be able to serve any traffic at
//!   all), otherwise `503 Service Unavailable` with a short JSON body
//!   explaining why.
//! - `POST /reload`: re-reads the config file from disk and hot-applies
//!   its non-sensitive `routing` settings (see `reload` module docs for
//!   exactly what is/isn't covered). Returns `200 {"status":"reloaded"}`
//!   on success or `500` with an error message on failure (the previous
//!   configuration remains in effect either way). An alternative to
//!   sending `SIGHUP` (see `reload::watch_sighup`) for environments where
//!   sending a Unix signal is inconvenient.
//! - `GET /custom-rules`: lists every currently registered custom
//!   table/function routing rule (see `router::custom_rules`), as a JSON
//!   array of `{"_name":...,"_type":"t"|"f","rw_mode":"w"|"r"}` objects.
//! - `POST /custom-rules`: registers (or overwrites) one rule. Body is a
//!   single `{"_name":...,"_type":"t"|"f","rw_mode":"w"|"r"}` object.
//!   Changes made this way are in-memory only and do NOT persist to the
//!   config file -- they are lost on restart (and on a subsequent config
//!   reload, which replaces the whole rule set from the file -- see
//!   `reload` module docs) unless separately written back to the config
//!   file by the caller.
//! - `DELETE /custom-rules`: removes one rule. Body is
//!   `{"_name":...,"_type":"t"|"f"}` (no `rw_mode` needed). Same
//!   in-memory-only caveat as `POST` above.
//! - `GET /client-stats`: per-client-IP connection accounting (see
//!   `proxy::client_stats` module docs) as a JSON array of
//!   `{"ip":...,"active_connections":...,"total_connections":...,"last_seen_unix_secs":...}`
//!   objects. A lightweight, always-on alternative to full query audit
//!   logging when the goal is just "how many connections does each
//!   client IP have", not the full SQL text of every statement. The
//!   distinct-active-IP count alone is also exposed as a Prometheus gauge
//!   (`trident_client_distinct_active_ips`) via `/metrics`, since that
//!   single number (unlike a per-IP breakdown) is safe to expose as a
//!   Prometheus value without running into per-label-value cardinality
//!   blowup.
//!
//! This endpoint is unauthenticated by design: it is meant to be reachable
//! only from inside a trusted network (a Kubernetes probe, a Prometheus
//! scraper, an internal monitoring agent) and must NOT be exposed on the
//! same listener as client traffic or on a public interface. Bind it to a
//! private address (see `AdminConfig.listen_addr`) and restrict access at
//! the network layer (firewall rules, k8s NetworkPolicy, etc.) if it is
//! reachable from anything less trusted than that.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Json, State, WebSocketUpgrade};
use axum::http::{header, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::config::{LsnTrackingConfig, NodeConfig, NodeType, PoolMode, RoutingConfig, SslMode};
use crate::health::BackendNodeSnapshot;
use crate::proxy::client_stats::ClientStats;
use crate::reload::{reload_from_file, RoutingReloadTarget};
use crate::router::custom_rules::{CustomRoutingRules, RuleTargetKind};

/// Trait for dynamically adding/removing backend nodes at runtime.
/// Implemented by the wiring layer in `main.rs` that coordinates the
/// HealthChecker, PoolManager, and node_addresses map.
#[async_trait::async_trait]
pub trait NodeManager: Send + Sync {
    /// Adds a new backend node. Returns `Ok(())` on success, `Err(msg)`
    /// if validation fails or the node already exists.
    async fn add_node(&self, config: NodeConfig) -> Result<(), String>;

    /// Removes a backend node by name. Returns `Ok(())` on success,
    /// `Err(msg)` if the node does not exist or cannot be removed (e.g.
    /// it is the last writer).
    fn remove_node(&self, node_id: &str) -> Result<(), String>;
}

#[derive(Embed)]
#[folder = "console/"]
struct ConsoleAssets;

/// Ring buffer of recent slow queries for the `/api/slow-queries` endpoint.
pub struct SlowQueryBuffer {
    entries: parking_lot::Mutex<std::collections::VecDeque<SlowQueryEntry>>,
    capacity: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlowQueryEntry {
    pub time_unix_secs: u64,
    pub duration_ms: u64,
    pub target: String,
    pub sql: String,
}

impl SlowQueryBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: parking_lot::Mutex::new(std::collections::VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    pub fn push(&self, entry: SlowQueryEntry) {
        let mut entries = self.entries.lock();
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    pub fn snapshot(&self) -> Vec<SlowQueryEntry> {
        let entries = self.entries.lock();
        entries.iter().rev().cloned().collect()
    }

    /// Number of slow queries recorded at or after `cutoff_unix_secs`.
    /// Entries are stored oldest-to-newest, so scanning from the back stops
    /// at the first entry older than the cutoff. Bounded by the buffer
    /// capacity: if more than `capacity` slow queries land inside the
    /// window, the overflow was evicted and the count is a floor -- at that
    /// volume the exact number is not the interesting signal anyway.
    pub fn count_since(&self, cutoff_unix_secs: u64) -> usize {
        let entries = self.entries.lock();
        entries
            .iter()
            .rev()
            .take_while(|e| e.time_unix_secs >= cutoff_unix_secs)
            .count()
    }
}

/// Broadcast channel for live log streaming via WebSocket.
pub type LogSender = broadcast::Sender<String>;

pub fn create_log_channel() -> (LogSender, broadcast::Receiver<String>) {
    broadcast::channel(1024)
}

/// A `tracing_subscriber` `MakeWriter` that forwards each formatted log
/// line into the live-log broadcast channel backing `/ws/logs`. The fmt
/// layer creates one writer per event and drops it after writing, so the
/// accumulated bytes are sent as one line on drop. Send errors (no
/// connected WebSocket subscribers) are ignored -- streaming is
/// best-effort observability, never a reason to fail or slow logging.
#[derive(Clone)]
pub struct LogBroadcastMakeWriter {
    sender: LogSender,
}

impl LogBroadcastMakeWriter {
    pub fn new(sender: LogSender) -> Self {
        Self { sender }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBroadcastMakeWriter {
    type Writer = LogBroadcastWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogBroadcastWriter {
            sender: self.sender.clone(),
            buf: Vec::new(),
        }
    }
}

pub struct LogBroadcastWriter {
    sender: LogSender,
    buf: Vec<u8>,
}

impl std::io::Write for LogBroadcastWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LogBroadcastWriter {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            let line = String::from_utf8_lossy(&self.buf).trim_end().to_string();
            if !line.is_empty() {
                let _ = self.sender.send(line);
            }
        }
    }
}

/// Errors that can occur while setting up or running the admin server.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("failed to install Prometheus metrics recorder: {0}")]
    RecorderInstall(String),

    #[error("failed to bind admin listener on {addr}: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },

    #[error("admin server error: {0}")]
    Serve(#[source] std::io::Error),
}

/// Installs the `metrics` crate's global recorder backed by a Prometheus
/// exporter and returns a `PrometheusHandle` used to render `/metrics`
/// responses on demand. Must be called at most once per process (the
/// underlying `metrics`/`PrometheusBuilder::install_recorder` global
/// recorder can only be installed once) -- call this before any other
/// code in the process emits a metric via the `metrics` crate's macros,
/// otherwise those early metrics are silently dropped (this matches the
/// `metrics` crate's own documented behavior for calls made before a
/// recorder is installed).
pub fn install_prometheus_recorder() -> Result<PrometheusHandle, AdminError> {
    PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| AdminError::RecorderInstall(e.to_string()))
}

/// Reports whether the proxy has at least the minimum backend
/// availability needed to serve traffic: at least one healthy `Writer`
/// node. This intentionally does not require every configured node (a
/// Reader or Analytics node being down does not make the whole proxy
/// unhealthy, since routing degrades gracefully -- see the Router/health
/// modules), matching how `/healthz` is meant to be used by an external
/// process manager or orchestrator to decide whether to route traffic to,
/// or restart, this instance.
pub fn is_healthy(snapshot: &[BackendNodeSnapshot]) -> bool {
    snapshot
        .iter()
        .any(|n| n.node_type == NodeType::Writer && n.healthy)
}

/// Shared state available to admin route handlers.
struct AdminState {
    prometheus_handle: PrometheusHandle,
    /// Produces the current routing snapshot on demand; typically a
    /// closure wrapping `pool::manager::PoolManager::snapshot` (or
    /// `health::HealthChecker::snapshot` directly).
    snapshot_fn: Box<dyn Fn() -> Vec<BackendNodeSnapshot> + Send + Sync>,
    /// Path to the config file to re-read on `POST /reload`, and the
    /// target it applies the reloaded `routing` section to. `None` if no
    /// reload target was wired up (the route then always reports failure
    /// rather than silently doing nothing).
    reload: Option<(String, Arc<dyn RoutingReloadTarget>)>,
    /// Custom routing rules registry backing `GET`/`POST`/`DELETE
    /// /custom-rules`. `None` disables those routes (they respond `501`),
    /// e.g. if the caller never attached a `CustomRoutingRules` to its
    /// `Router` (see `Router::with_custom_rules`).
    custom_rules: Option<Arc<CustomRoutingRules>>,
    /// Per-client-IP connection accounting backing `GET /client-stats`
    /// (see `proxy::client_stats` module docs). Always present -- unlike
    /// `reload`/`custom_rules`, this has no meaningful "not configured"
    /// state, since `ProxyDeps` always carries a `ClientStats` instance.
    client_stats: Arc<ClientStats>,
    /// Current routing config snapshot for the console's Configure page.
    routing_config: Arc<arc_swap::ArcSwap<RoutingConfig>>,
    /// Current LSN tracking config (restart-only, read-only display).
    lsn_tracking: LsnTrackingConfig,
    /// Maximum pool size per node (for display).
    max_pool_size: u32,
    /// Pool mode (for display).
    pool_mode: PoolMode,
    /// Ring buffer of recent slow queries.
    slow_queries: Arc<SlowQueryBuffer>,
    /// Broadcast sender for live log streaming.
    log_sender: LogSender,
    /// Pool config strings for display (restart-only).
    pool_min_pool_size: u32,
    pool_max_idle_time: String,
    pool_connection_timeout: String,
    pool_max_lifetime: String,
    /// Dynamic node management (add/remove at runtime).
    node_manager: Option<Arc<dyn NodeManager>>,
    /// Bearer token for admin API authentication. `None` = protected
    /// endpoints are disabled (only /metrics, /healthz, and static console
    /// assets remain accessible).
    auth_token: Option<String>,
    /// Dynamic health check interval setter. `None` if not wired up.
    set_check_interval_fn: Option<Box<dyn Fn(Duration) + Send + Sync>>,
    /// Dynamic health check interval getter.
    get_check_interval_fn: Option<Box<dyn Fn() -> Duration + Send + Sync>>,
    /// Serializes config PUT and reload operations to prevent lost updates
    /// from concurrent read-modify-apply sequences (FIX Bug 5a).
    /// Shared with `watch_sighup` so SIGHUP reloads also serialize against
    /// Admin PUT operations.
    config_write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Drains all per-user pools for a given username. Used for credential
    /// revocation (P1). `None` if passthrough mode is not configured.
    drain_user_fn: Option<Box<dyn Fn(&str) -> usize + Send + Sync>>,
}

/// Bearer token authentication middleware. Checks the `Authorization`
/// header against the configured token. Returns 401 if missing/invalid.
/// Uses constant-time comparison to prevent timing side-channel attacks.
///
/// For WebSocket connections (which cannot set custom headers from browser
/// JavaScript), the token may also be provided via the `token` query
/// parameter. Header-based auth takes priority over query parameter.
///
/// Simple percent-decoding for query parameter values (handles %XX escapes
/// and '+' as space). No external crate needed for this limited use case.
fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn auth_middleware(
    state: Arc<AdminState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Reject if no non-empty token is configured (should not reach here,
    // but defense-in-depth against empty-token bypass).
    let expected = match state.auth_token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                r#"{"status":"error","message":"admin auth_token is empty or unconfigured; refusing to authenticate"}"#,
            )
                .into_response();
        }
    };

    // Try Authorization header first, then fall back to query parameter
    // (needed for WebSocket connections from browsers).
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| {
            req.uri().query().and_then(|q| {
                q.split('&').find_map(|pair| {
                    let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                    if k == "token" {
                        Some(percent_decode(v))
                    } else {
                        None
                    }
                })
            })
        })
        .unwrap_or_default();

    // Constant-time comparison to prevent timing attacks
    use subtle::ConstantTimeEq;
    let matches = expected.as_bytes().ct_eq(provided.as_bytes());

    if !bool::from(matches) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            r#"{"status":"error","message":"unauthorized: invalid or missing Bearer token"}"#,
        )
            .into_response();
    }

    next.run(req).await
}

/// Builds the admin `axum::Router` (routes only; binding/serving is done
/// by `run`, kept separate so tests can exercise the routes directly
/// in-process without a real TCP listener).
#[allow(clippy::too_many_arguments)]
fn build_router(
    prometheus_handle: PrometheusHandle,
    snapshot_fn: impl Fn() -> Vec<BackendNodeSnapshot> + Send + Sync + 'static,
    reload: Option<(String, Arc<dyn RoutingReloadTarget>)>,
    custom_rules: Option<Arc<CustomRoutingRules>>,
    client_stats: Arc<ClientStats>,
    routing_config: Arc<arc_swap::ArcSwap<RoutingConfig>>,
    lsn_tracking: LsnTrackingConfig,
    max_pool_size: u32,
    pool_mode: PoolMode,
    slow_queries: Arc<SlowQueryBuffer>,
    log_sender: LogSender,
    pool_min_pool_size: u32,
    pool_max_idle_time: String,
    pool_connection_timeout: String,
    pool_max_lifetime: String,
    node_manager: Option<Arc<dyn NodeManager>>,
    auth_token: Option<String>,
    set_check_interval_fn: Option<Box<dyn Fn(Duration) + Send + Sync>>,
    get_check_interval_fn: Option<Box<dyn Fn() -> Duration + Send + Sync>>,
    config_write_lock: Arc<tokio::sync::Mutex<()>>,
    drain_user_fn: Option<Box<dyn Fn(&str) -> usize + Send + Sync>>,
) -> Router {
    let state = Arc::new(AdminState {
        prometheus_handle,
        snapshot_fn: Box::new(snapshot_fn),
        reload,
        custom_rules,
        client_stats,
        routing_config,
        lsn_tracking,
        max_pool_size,
        pool_mode,
        slow_queries,
        log_sender,
        pool_min_pool_size,
        pool_max_idle_time,
        pool_connection_timeout,
        pool_max_lifetime,
        node_manager,
        auth_token,
        set_check_interval_fn,
        get_check_interval_fn,
        config_write_lock,
        drain_user_fn,
    });

    // Public routes: always accessible (Prometheus scraper, k8s probes, console UI)
    let public_routes = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(healthz_handler))
        .fallback(get(static_handler));

    // Protected routes: require auth token when configured
    let protected_routes = Router::new()
        .route("/reload", post(reload_handler))
        .route(
            "/custom-rules",
            get(list_custom_rules_handler)
                .post(set_custom_rule_handler)
                .delete(delete_custom_rule_handler),
        )
        .route("/client-stats", get(client_stats_handler))
        .route("/api/overview", get(overview_handler))
        .route(
            "/api/nodes",
            get(nodes_handler)
                .post(add_node_handler)
                .delete(remove_node_handler),
        )
        .route("/api/slow-queries", get(slow_queries_handler))
        .route(
            "/api/config",
            get(config_get_handler).put(config_put_handler),
        )
        .route("/api/drain-user", post(drain_user_handler))
        .route("/ws/logs", get(ws_logs_handler));

    if state.auth_token.as_deref().is_some_and(|t| !t.is_empty()) {
        let auth_state = state.clone();
        let protected_routes =
            protected_routes.layer(axum::middleware::from_fn(move |req, next| {
                let state = auth_state.clone();
                auth_middleware(state, req, next)
            }));
        public_routes.merge(protected_routes).with_state(state)
    } else {
        // No auth token configured. Block ALL requests to sensitive protected
        // routes (both read and write). Only /metrics, /healthz, and the
        // static console assets remain accessible without authentication.
        // This prevents accidental information disclosure (SQL logs, node
        // credentials, client IPs) when the admin console is bound to a
        // non-loopback address without a token.
        let protected_routes = protected_routes.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, _next: axum::middleware::Next| {
                async move {
                    let path = req.uri().path().to_string();
                    // Only allow requests that are handled by public_routes
                    // (which are merged separately and don't pass through here).
                    // Any request reaching this middleware is to a protected route.
                    axum::response::IntoResponse::into_response((
                        axum::http::StatusCode::UNAUTHORIZED,
                        axum::Json(serde_json::json!({
                            "status": "error",
                            "message": format!(
                                "admin auth_token not configured; access to {} is disabled. \
                                 Set admin.auth_token in configuration to enable.",
                                path
                            )
                        })),
                    ))
                }
            },
        ));
        public_routes.merge(protected_routes).with_state(state)
    }
}

async fn metrics_handler(State(state): State<Arc<AdminState>>) -> impl IntoResponse {
    (StatusCode::OK, state.prometheus_handle.render())
}

async fn healthz_handler(State(state): State<Arc<AdminState>>) -> impl IntoResponse {
    let snapshot = (state.snapshot_fn)();
    if is_healthy(&snapshot) {
        (StatusCode::OK, r#"{"status":"ok"}"#).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"status":"unavailable","reason":"no healthy writer node"}"#,
        )
            .into_response()
    }
}

async fn reload_handler(State(state): State<Arc<AdminState>>) -> impl IntoResponse {
    let Some((path, target)) = &state.reload else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            r#"{"status":"error","reason":"hot reload is not configured for this instance"}"#,
        )
            .into_response();
    };

    // FIX (Bug 5a): Serialize with config PUT operations.
    let _config_guard = state.config_write_lock.lock().await;

    match reload_from_file(path, target.as_ref()).await {
        Ok(()) => {
            // Note: target.apply() (called inside reload_from_file) already
            // updates the admin routing_config snapshot atomically under its
            // reload_lock. No additional store is needed here.
            (StatusCode::OK, r#"{"status":"reloaded"}"#).into_response()
        }
        Err(e) => {
            let body = format!(r#"{{"status":"error","reason":{:?}}}"#, e.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
        }
    }
}

/// Request/response body for `POST /custom-rules`, matching the
/// `_name`/`_type`/`rw_mode` parameter shape (reusing
/// `router::custom_rules::CustomRuleEntry`'s serde field renames).
type CustomRuleBody = crate::router::custom_rules::CustomRuleEntry;

/// Request body for `DELETE /custom-rules` -- only `_name`/`_type` are
/// needed to identify a rule to remove.
#[derive(Debug, Deserialize)]
struct DeleteCustomRuleBody {
    #[serde(rename = "_name")]
    name: String,
    #[serde(rename = "_type")]
    rule_type: RuleTargetKind,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    status: &'static str,
    reason: String,
}

fn custom_rules_not_configured() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorBody {
            status: "error",
            reason: "custom routing rules are not configured for this instance".to_string(),
        }),
    )
}

async fn list_custom_rules_handler(State(state): State<Arc<AdminState>>) -> impl IntoResponse {
    let Some(rules) = &state.custom_rules else {
        return custom_rules_not_configured().into_response();
    };
    Json(rules.list_rules()).into_response()
}

async fn set_custom_rule_handler(
    State(state): State<Arc<AdminState>>,
    Json(body): Json<CustomRuleBody>,
) -> impl IntoResponse {
    let Some(rules) = &state.custom_rules else {
        return custom_rules_not_configured().into_response();
    };
    if body.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                status: "error",
                reason: "'_name' must not be empty".to_string(),
            }),
        )
            .into_response();
    }
    // FIX (reload race): Serialize with config PUT/reload to prevent
    // concurrent replace_all from overwriting this individual rule change.
    let _config_guard = state.config_write_lock.lock().await;
    rules.set_rule(&body.name, body.rule_type, body.rw_mode);
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "ok", "rule": body})),
    )
        .into_response()
}

async fn delete_custom_rule_handler(
    State(state): State<Arc<AdminState>>,
    Json(body): Json<DeleteCustomRuleBody>,
) -> impl IntoResponse {
    let Some(rules) = &state.custom_rules else {
        return custom_rules_not_configured().into_response();
    };
    // FIX (reload race): Serialize with config PUT/reload.
    let _config_guard = state.config_write_lock.lock().await;
    rules.remove_rule(&body.name, body.rule_type);
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

async fn client_stats_handler(State(state): State<Arc<AdminState>>) -> impl IntoResponse {
    Json(state.client_stats.snapshot()).into_response()
}

// --- New API endpoints for the management console ---

#[derive(Serialize)]
struct OverviewResponse {
    active_connections: usize,
    total_accepted: u64,
    routing_writer: u64,
    routing_reader: u64,
    routing_analytics: u64,
    /// Slow queries observed in the last 60 seconds (from the timestamped
    /// ring buffer), not the process-lifetime total. The overview page shows
    /// real-time health; the cumulative counter remains available as
    /// `trident_slow_queries_total` in `/metrics`.
    slow_queries_1m: usize,
    pool_exhausted: u64,
    healthy: bool,
}

async fn overview_handler(State(state): State<Arc<AdminState>>) -> impl IntoResponse {
    let snapshot = (state.snapshot_fn)();
    let metrics_text = state.prometheus_handle.render();
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let resp = OverviewResponse {
        active_connections: parse_gauge(&metrics_text, "trident_active_connections"),
        total_accepted: parse_counter(&metrics_text, "trident_connections_accepted_total"),
        routing_writer: parse_counter_label(
            &metrics_text,
            "trident_routing_decisions_total",
            "writer",
        ),
        routing_reader: parse_counter_label(
            &metrics_text,
            "trident_routing_decisions_total",
            "reader",
        ),
        routing_analytics: parse_counter_label(
            &metrics_text,
            "trident_routing_decisions_total",
            "analytics",
        ),
        slow_queries_1m: state.slow_queries.count_since(now_unix.saturating_sub(60)),
        pool_exhausted: parse_counter_sum(&metrics_text, "trident_pool_exhausted_total"),
        healthy: is_healthy(&snapshot),
    };
    Json(resp).into_response()
}

fn parse_counter(text: &str, name: &str) -> u64 {
    for line in text.lines() {
        if line.starts_with(name) && !line.starts_with('#') && !line.contains('{') {
            if let Some(val) = line.split_whitespace().last() {
                return val.parse::<f64>().unwrap_or(0.0) as u64;
            }
        }
    }
    0
}

fn parse_counter_label(text: &str, name: &str, label_value: &str) -> u64 {
    let pattern = format!("{name}{{");
    for line in text.lines() {
        if line.starts_with(&pattern) && line.contains(label_value) {
            if let Some(val) = line.split_whitespace().last() {
                return val.parse::<f64>().unwrap_or(0.0) as u64;
            }
        }
    }
    0
}

/// Parses a gauge value from Prometheus metrics text (no labels).
fn parse_gauge(text: &str, name: &str) -> usize {
    for line in text.lines() {
        if line.starts_with(name) && !line.starts_with('#') && !line.contains('{') {
            if let Some(val) = line.split_whitespace().last() {
                return val.parse::<f64>().unwrap_or(0.0) as usize;
            }
        }
    }
    0
}

/// Sums all series of a counter (with or without labels). Handles the case
/// where a counter has per-node_id labels and the overview wants the total.
fn parse_counter_sum(text: &str, name: &str) -> u64 {
    let mut total: f64 = 0.0;
    for line in text.lines() {
        if line.starts_with(name) && !line.starts_with('#') {
            if let Some(val) = line.split_whitespace().last() {
                total += val.parse::<f64>().unwrap_or(0.0);
            }
        }
    }
    total as u64
}

#[derive(Serialize)]
struct NodesResponse {
    nodes: Vec<NodeInfo>,
    max_pool_size: u32,
    pool_mode: String,
}

#[derive(Serialize)]
struct NodeInfo {
    node_id: String,
    node_type: String,
    healthy: bool,
    active_connections: i64,
    replay_lsn: u64,
    weight: u32,
    replication_lag_ms: Option<u64>,
}

async fn nodes_handler(State(state): State<Arc<AdminState>>) -> impl IntoResponse {
    let snapshot = (state.snapshot_fn)();
    let nodes: Vec<NodeInfo> = snapshot
        .iter()
        .map(|n| NodeInfo {
            node_id: n.node_id.clone(),
            node_type: format!("{:?}", n.node_type).to_lowercase(),
            healthy: n.healthy,
            active_connections: n.active_connections,
            replay_lsn: n.replay_lsn,
            weight: n.weight,
            replication_lag_ms: n.replication_lag_ms,
        })
        .collect();
    Json(NodesResponse {
        nodes,
        max_pool_size: state.max_pool_size,
        pool_mode: format!("{:?}", state.pool_mode).to_lowercase(),
    })
    .into_response()
}

// --- Dynamic node management (POST /api/nodes, DELETE /api/nodes) ---

#[derive(Deserialize)]
struct AddNodeRequest {
    name: String,
    host: String,
    port: Option<u16>,
    #[serde(rename = "type")]
    node_type: String,
    weight: Option<u32>,
    database: String,
    username: String,
    password: Option<String>,
    ssl_mode: Option<String>,
}

#[derive(Deserialize)]
struct RemoveNodeRequest {
    name: String,
}

async fn add_node_handler(
    State(state): State<Arc<AdminState>>,
    Json(body): Json<AddNodeRequest>,
) -> impl IntoResponse {
    let Some(ref nm) = state.node_manager else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(
                serde_json::json!({"status": "error", "message": "node management not available"}),
            ),
        )
            .into_response();
    };

    let node_type = match body.node_type.as_str() {
        "writer" => NodeType::Writer,
        "reader" => NodeType::Reader,
        "analytics" => NodeType::Analytics,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status": "error", "message": format!("invalid node type: '{other}'. Must be writer, reader, or analytics")})),
            ).into_response();
        }
    };

    // Input validation: node name must be non-empty, alphanumeric + hyphens/underscores, max 64 chars
    if body.name.is_empty() || body.name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"status": "error", "message": "node name must be 1-64 characters"})),
        ).into_response();
    }
    if !body
        .name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"status": "error", "message": "node name must contain only alphanumeric characters, hyphens, and underscores"})),
        ).into_response();
    }

    // Host validation: must not be empty, no whitespace or control characters
    if body.host.is_empty()
        || body.host.len() > 253
        || body.host.chars().any(|c| c.is_control() || c == ' ')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"status": "error", "message": "invalid host: must be 1-253 characters, no whitespace or control characters"})),
        ).into_response();
    }

    let ssl_mode = match body.ssl_mode.as_deref().unwrap_or("disable") {
        "disable" => SslMode::Disable,
        "prefer" => SslMode::Prefer,
        "require" => SslMode::Require,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status": "error", "message": format!("invalid ssl_mode: '{other}'. Must be disable, prefer, or require")})),
            ).into_response();
        }
    };

    let config = NodeConfig {
        name: body.name.clone(),
        host: body.host,
        port: body.port.unwrap_or(5432),
        node_type,
        weight: body.weight.unwrap_or(1),
        database: body.database,
        username: body.username,
        password: body.password,
        ssl_mode,
    };

    match nm.add_node(config).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ok", "node": body.name})),
        )
            .into_response(),
        Err(msg) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"status": "error", "message": msg})),
        )
            .into_response(),
    }
}

async fn remove_node_handler(
    State(state): State<Arc<AdminState>>,
    Json(body): Json<RemoveNodeRequest>,
) -> impl IntoResponse {
    let Some(ref nm) = state.node_manager else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(
                serde_json::json!({"status": "error", "message": "node management not available"}),
            ),
        )
            .into_response();
    };

    match nm.remove_node(&body.name) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ok", "node": body.name})),
        )
            .into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"status": "error", "message": msg})),
        )
            .into_response(),
    }
}

/// Request body for `POST /api/drain-user`.
#[derive(Deserialize)]
struct DrainUserRequest {
    username: String,
}

/// Drains (terminates and removes) all per-user connection pools belonging
/// to the specified username. Used for credential revocation: after a
/// password reset or user disable in PostgreSQL, this endpoint ensures no
/// idle connections authenticated with the old credentials remain pooled.
///
/// Returns the number of pools drained. In-flight queries on checked-out
/// connections are NOT interrupted — they complete naturally, but the
/// connection is discarded (not returned to the pool) upon release.
async fn drain_user_handler(
    State(state): State<Arc<AdminState>>,
    Json(body): Json<DrainUserRequest>,
) -> impl IntoResponse {
    let Some(ref drain_fn) = state.drain_user_fn else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({
                "status": "error",
                "message": "per-user pool draining not available (passthrough mode not configured)"
            })),
        )
            .into_response();
    };

    if body.username.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "message": "username must not be empty"
            })),
        )
            .into_response();
    }

    let drained = drain_fn(&body.username);
    tracing::info!(
        username = %body.username,
        pools_drained = drained,
        "drained per-user pools for credential revocation"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "username": body.username,
            "pools_drained": drained
        })),
    )
        .into_response()
}

async fn slow_queries_handler(
    State(state): State<Arc<AdminState>>,
    axum::extract::Query(params): axum::extract::Query<PaginationParams>,
) -> impl IntoResponse {
    let all = state.slow_queries.snapshot();
    let total = all.len();
    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(50).clamp(1, 200);
    let start = (page - 1) * per_page;
    let items: Vec<_> = all.into_iter().skip(start).take(per_page).collect();
    Json(PaginatedResponse {
        items,
        total,
        page,
        per_page,
        total_pages: total.div_ceil(per_page),
    })
    .into_response()
}

#[derive(Deserialize)]
struct PaginationParams {
    page: Option<usize>,
    per_page: Option<usize>,
}

#[derive(Serialize)]
struct PaginatedResponse<T: Serialize> {
    items: Vec<T>,
    total: usize,
    page: usize,
    per_page: usize,
    total_pages: usize,
}

#[derive(Serialize)]
struct ConfigResponse {
    default_consistency: String,
    enable_transaction_split: bool,
    split_respects_consistency: bool,
    enable_hint_routing: bool,
    enable_cost_routing: bool,
    cost_threshold: f64,
    writer_readable: bool,
    max_replication_lag_ms: u64,
    lsn_mode: String,
    pipeline_internal_query_timeout_ms: u64,
    pipeline_lazy_fallback: bool,
    extension_guc_name: String,
    pool_mode: String,
    pool_max_pool_size: u32,
    pool_min_pool_size: u32,
    pool_max_idle_time: String,
    pool_connection_timeout: String,
    pool_max_lifetime: String,
    health_check_interval_ms: u64,
}

async fn config_get_handler(State(state): State<Arc<AdminState>>) -> impl IntoResponse {
    let routing = state.routing_config.load();
    let resp = ConfigResponse {
        default_consistency: format!("{:?}", routing.default_consistency).to_lowercase(),
        enable_transaction_split: routing.enable_transaction_split,
        split_respects_consistency: routing.split_respects_consistency,
        enable_hint_routing: routing.enable_hint_routing,
        enable_cost_routing: routing.enable_cost_routing,
        cost_threshold: routing.cost_threshold,
        writer_readable: routing.writer_readable,
        max_replication_lag_ms: routing.max_replication_lag_ms,
        lsn_mode: format!("{:?}", state.lsn_tracking.mode).to_lowercase(),
        pipeline_internal_query_timeout_ms: state.lsn_tracking.pipeline.internal_query_timeout_ms,
        pipeline_lazy_fallback: state.lsn_tracking.pipeline.lazy_fallback,
        extension_guc_name: state.lsn_tracking.extension.guc_name.clone(),
        pool_mode: format!("{:?}", state.pool_mode).to_lowercase(),
        pool_max_pool_size: state.max_pool_size,
        pool_min_pool_size: state.pool_min_pool_size,
        pool_max_idle_time: state.pool_max_idle_time.clone(),
        pool_connection_timeout: state.pool_connection_timeout.clone(),
        pool_max_lifetime: state.pool_max_lifetime.clone(),
        health_check_interval_ms: state
            .get_check_interval_fn
            .as_ref()
            .map(|f| f().as_millis() as u64)
            .unwrap_or(0),
    };
    Json(resp).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigPutBody {
    default_consistency: Option<String>,
    enable_transaction_split: Option<bool>,
    split_respects_consistency: Option<bool>,
    enable_hint_routing: Option<bool>,
    enable_cost_routing: Option<bool>,
    cost_threshold: Option<f64>,
    writer_readable: Option<bool>,
    /// Accepted for wire compatibility but not hot-applicable: the health
    /// checker's replication-lag threshold is fixed at construction time.
    /// The handler rejects an attempt to *change* it rather than
    /// pretending the change applied.
    max_replication_lag_ms: Option<u64>,
    /// Dynamically adjustable health check interval in milliseconds.
    health_check_interval_ms: Option<u64>,
}

/// Applies the edited routing parameters from the console directly to the
/// running configuration (via the same `RoutingReloadTarget` that
/// `SIGHUP`/`POST /reload` use), then refreshes the cached snapshot so
/// subsequent `GET /api/config` calls reflect the change.
///
/// The change is runtime-only: it is NOT written back to the config file,
/// so a later file-based reload or a process restart reverts it. The
/// response body says so explicitly rather than implying persistence.
async fn config_put_handler(
    State(state): State<Arc<AdminState>>,
    Json(body): Json<ConfigPutBody>,
) -> impl IntoResponse {
    let Some((_, target)) = &state.reload else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            r#"{"status":"error","reason":"hot reload is not configured"}"#.to_string(),
        )
            .into_response();
    };

    // FIX (Bug 5a): Serialize the entire read-modify-apply sequence to
    // prevent concurrent PUTs from building on the same stale base and
    // losing each other's updates.
    let _config_guard = state.config_write_lock.lock().await;

    let current = state.routing_config.load();
    let mut new_routing = (**current).clone();

    if let Some(value) = &body.default_consistency {
        new_routing.default_consistency = match value.as_str() {
            "eventual" => crate::config::ConsistencyLevel::Eventual,
            "session" => crate::config::ConsistencyLevel::Session,
            "global" => crate::config::ConsistencyLevel::Global,
            other => {
                let reason = format!(
                    r#"{{"status":"error","reason":"invalid default_consistency '{other}': expected eventual|session|global"}}"#
                );
                return (StatusCode::BAD_REQUEST, reason).into_response();
            }
        };
    }
    if let Some(v) = body.enable_transaction_split {
        new_routing.enable_transaction_split = v;
    }
    if let Some(v) = body.split_respects_consistency {
        new_routing.split_respects_consistency = v;
    }
    if let Some(v) = body.enable_hint_routing {
        new_routing.enable_hint_routing = v;
    }
    if let Some(v) = body.enable_cost_routing {
        new_routing.enable_cost_routing = v;
    }
    if let Some(v) = body.cost_threshold {
        if !v.is_finite() || v < 0.0 {
            return (
                StatusCode::BAD_REQUEST,
                r#"{"status":"error","reason":"cost_threshold must be a non-negative finite number"}"#
                    .to_string(),
            )
                .into_response();
        }
        new_routing.cost_threshold = v;
    }
    if let Some(v) = body.writer_readable {
        new_routing.writer_readable = v;
    }
    if let Some(v) = body.max_replication_lag_ms {
        if v != new_routing.max_replication_lag_ms {
            return (
                StatusCode::BAD_REQUEST,
                r#"{"status":"error","reason":"max_replication_lag_ms cannot be changed at runtime; edit the config file and restart"}"#
                    .to_string(),
            )
                .into_response();
        }
    }

    // FIX: Validate health_check_interval_ms early but defer application
    // until after target.apply() succeeds, to avoid partial-commit state
    // where interval is changed but routing config fails to apply.
    let pending_health_interval_ms = if let Some(ms) = body.health_check_interval_ms {
        if ms < 100 {
            return (
                StatusCode::BAD_REQUEST,
                r#"{"status":"error","reason":"health_check_interval_ms must be >= 100"}"#
                    .to_string(),
            )
                .into_response();
        }
        Some(ms)
    } else {
        None
    };

    // Preserve the *live* custom rule set: rules may have been added or
    // removed through the admin API since startup, and `apply` replaces
    // the whole set from the RoutingConfig it is given. Passing the stale
    // startup snapshot here would silently wipe those runtime changes.
    if let Some(rules) = &state.custom_rules {
        new_routing.custom_rules = rules.list_rules();
    }

    match target.apply(&new_routing) {
        Ok(()) => {
            // Apply health interval only after routing config succeeds.
            if let Some(ms) = pending_health_interval_ms {
                if let Some(ref setter) = state.set_check_interval_fn {
                    setter(Duration::from_millis(ms));
                }
            }
            // Note: target.apply() already updates the admin routing_config
            // snapshot inside its reload_lock, ensuring atomicity with
            // respect to concurrent PUT/reload operations. No additional
            // store is needed here (doing so outside the lock would race
            // with concurrent operations — FIX Bug 5a).
            (
                StatusCode::OK,
                r#"{"status":"applied","note":"runtime-only change; not persisted to the config file. A file reload (SIGHUP / POST /reload) or restart reverts it."}"#
                    .to_string(),
            )
                .into_response()
        }
        Err(e) => {
            let body = format!(r#"{{"status":"error","reason":{:?}}}"#, e);
            (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
        }
    }
}

async fn ws_logs_handler(
    State(state): State<Arc<AdminState>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let rx = state.log_sender.subscribe();
    ws.on_upgrade(move |socket| handle_log_socket(socket, rx))
}

async fn handle_log_socket(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(line) => {
                        if socket.send(Message::Text(line)).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => return,
                    _ => {}
                }
            }
        }
    }
}

async fn static_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match ConsoleAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime.as_ref())],
                content.data.into_owned(),
            )
                .into_response()
        }
        None => {
            // SPA fallback: serve index.html for unrecognized paths
            match ConsoleAssets::get("index.html") {
                Some(content) => (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/html")],
                    content.data.into_owned(),
                )
                    .into_response(),
                None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
            }
        }
    }
}

/// Binds `listen_addr` and serves the admin routes until the process
/// exits or an unrecoverable error occurs. Intended to be run as a
/// background `tokio::task` alongside `ProxyServer::run`.
///
/// `reload` optionally wires up `POST /reload` to re-read the config file
/// at the given path and hot-apply its `routing` section to the given
/// `RoutingReloadTarget`; pass `None` to leave `/reload` returning `501
/// Not Implemented` (e.g. if the caller only wants to use `SIGHUP`-based
/// reload via `reload::watch_sighup` instead).
///
/// `custom_rules` optionally wires up `GET`/`POST`/`DELETE /custom-rules`
/// against the given shared registry; pass `None` to leave those routes
/// returning `501 Not Implemented`.
///
/// `client_stats` backs `GET /client-stats`; always required (see
/// `AdminState.client_stats` docs).
///
/// Binds the admin TCP listener at startup so that binding failures are
/// detected before the proxy reports "started". Call this during init,
/// then pass the listener to `run`.
pub async fn bind_admin_listener(
    listen_addr: SocketAddr,
) -> Result<tokio::net::TcpListener, AdminError> {
    tokio::net::TcpListener::bind(listen_addr)
        .await
        .map_err(|source| AdminError::Bind {
            addr: listen_addr.to_string(),
            source,
        })
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    listener: tokio::net::TcpListener,
    prometheus_handle: PrometheusHandle,
    snapshot_fn: impl Fn() -> Vec<BackendNodeSnapshot> + Send + Sync + 'static,
    reload: Option<(String, Arc<dyn RoutingReloadTarget>)>,
    custom_rules: Option<Arc<CustomRoutingRules>>,
    client_stats: Arc<ClientStats>,
    routing_config: Arc<arc_swap::ArcSwap<RoutingConfig>>,
    lsn_tracking: LsnTrackingConfig,
    max_pool_size: u32,
    pool_mode: PoolMode,
    slow_queries: Arc<SlowQueryBuffer>,
    log_sender: LogSender,
    pool_min_pool_size: u32,
    pool_max_idle_time: String,
    pool_connection_timeout: String,
    pool_max_lifetime: String,
    node_manager: Option<Arc<dyn NodeManager>>,
    auth_token: Option<String>,
    check_interval_setter: Option<Box<dyn Fn(Duration) + Send + Sync>>,
    check_interval_getter: Option<Box<dyn Fn() -> Duration + Send + Sync>>,
    config_write_lock: Arc<tokio::sync::Mutex<()>>,
    drain_user_fn: Option<Box<dyn Fn(&str) -> usize + Send + Sync>>,
) -> Result<(), AdminError> {
    let app = build_router(
        prometheus_handle,
        snapshot_fn,
        reload,
        custom_rules,
        client_stats,
        routing_config,
        lsn_tracking,
        max_pool_size,
        pool_mode,
        slow_queries,
        log_sender,
        pool_min_pool_size,
        pool_max_idle_time,
        pool_connection_timeout,
        pool_max_lifetime,
        node_manager,
        auth_token,
        check_interval_setter,
        check_interval_getter,
        config_write_lock,
        drain_user_fn,
    );

    let local_addr = listener.local_addr().map_err(|source| AdminError::Bind {
        addr: "unknown".to_string(),
        source,
    })?;
    tracing::info!(addr = %local_addr, "admin console listening");
    axum::serve(listener, app).await.map_err(AdminError::Serve)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use tower::ServiceExt;

    fn snapshot_with(healthy_writer: bool, healthy_reader: bool) -> Vec<BackendNodeSnapshot> {
        vec![
            BackendNodeSnapshot {
                node_id: "writer".to_string(),
                node_type: NodeType::Writer,
                healthy: healthy_writer,
                replay_lsn: 0,
                active_connections: 0,
                weight: 1,
                replication_lag_ms: None,
            },
            BackendNodeSnapshot {
                node_id: "reader-1".to_string(),
                node_type: NodeType::Reader,
                healthy: healthy_reader,
                replay_lsn: 0,
                active_connections: 0,
                weight: 1,
                replication_lag_ms: None,
            },
        ]
    }

    // -----------------------------------------------------------------
    // is_healthy: pure logic, no HTTP involved
    // -----------------------------------------------------------------

    #[test]
    fn healthy_writer_present_is_healthy_regardless_of_reader_state() {
        assert!(is_healthy(&snapshot_with(true, true)));
        assert!(is_healthy(&snapshot_with(true, false)));
    }

    #[test]
    fn unhealthy_writer_is_unhealthy_even_if_reader_is_up() {
        assert!(!is_healthy(&snapshot_with(false, true)));
    }

    #[test]
    fn empty_snapshot_is_unhealthy() {
        assert!(!is_healthy(&[]));
    }

    #[test]
    fn only_healthy_readers_no_writer_is_unhealthy() {
        let snapshot = vec![BackendNodeSnapshot {
            node_id: "reader-1".to_string(),
            node_type: NodeType::Reader,
            healthy: true,
            replay_lsn: 0,
            active_connections: 0,
            weight: 1,
            replication_lag_ms: None,
        }];
        assert!(!is_healthy(&snapshot));
    }

    // -----------------------------------------------------------------
    // HTTP handlers, exercised in-process via tower::ServiceExt::oneshot
    // (no real TCP listener needed).
    // -----------------------------------------------------------------

    fn make_default_test_extras() -> (
        Arc<arc_swap::ArcSwap<crate::config::RoutingConfig>>,
        LsnTrackingConfig,
        Arc<SlowQueryBuffer>,
        LogSender,
    ) {
        let routing = crate::config::RoutingConfig {
            default_consistency: crate::config::ConsistencyLevel::Session,
            load_balance_strategy: crate::config::LoadBalanceStrategy::WeightedRoundRobin,
            enable_transaction_split: true,
            split_respects_consistency: true,
            enable_hint_routing: true,
            enable_cost_routing: false,
            cost_threshold: 50000.0,
            analytics_patterns: vec![],
            writer_readable: true,
            max_replication_lag_ms: 1000,
            custom_rules: vec![],
        };
        let routing_config = Arc::new(arc_swap::ArcSwap::new(Arc::new(routing)));
        let lsn_tracking = LsnTrackingConfig::default();
        let slow_queries = Arc::new(SlowQueryBuffer::new(100));
        let (log_sender, _) = create_log_channel();
        (routing_config, lsn_tracking, slow_queries, log_sender)
    }

    fn test_router(healthy: bool) -> Router {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let (routing_config, lsn_tracking, slow_queries, log_sender) = make_default_test_extras();

        build_router(
            handle,
            move || snapshot_with(healthy, true),
            None,
            None,
            Arc::new(ClientStats::new()),
            routing_config,
            lsn_tracking,
            50,
            PoolMode::Transaction,
            slow_queries,
            log_sender,
            5,
            "5m".to_string(),
            "5s".to_string(),
            "30m".to_string(),
            None,                                  // node_manager
            Some("test-token".to_string()),        // auth_token
            None,                                  // check_interval_setter
            None,                                  // check_interval_getter
            Arc::new(tokio::sync::Mutex::new(())), // config_write_lock
            None,                                  // drain_user_fn
        )
    }

    #[tokio::test]
    async fn healthz_returns_200_when_healthy() {
        let app = test_router(true);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8(body.to_vec()).unwrap().contains("\"ok\""));
    }

    #[tokio::test]
    async fn healthz_returns_503_when_unhealthy() {
        let app = test_router(false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8(body.to_vec())
            .unwrap()
            .contains("unavailable"));
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_200_with_text_body() {
        let app = test_router(true);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // Body should at least be valid text (Prometheus exposition
        // format), even with zero metrics recorded yet.
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8(body.to_vec()).is_ok());
    }

    // -----------------------------------------------------------------
    // /reload
    // -----------------------------------------------------------------

    struct NoopReloadTarget;
    impl RoutingReloadTarget for NoopReloadTarget {
        fn apply(&self, _routing: &crate::config::RoutingConfig) -> Result<(), String> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn reload_returns_501_when_not_configured() {
        let app = test_router(true);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reload")
                    .header("Authorization", "Bearer test-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn reload_returns_200_on_successful_reload() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "trident-admin-reload-test-{}.yaml",
            std::process::id()
        ));
        std::fs::write(
            &path,
            "proxy:\n  listen_addr: \"0.0.0.0:6432\"\n  max_clients: 10\n\
             nodes:\n  - name: primary\n    host: 127.0.0.1\n    port: 5432\n    type: writer\n    weight: 1\n    database: mydb\n    username: proxy_user\n    password: secret\n\
             routing:\n  default_consistency: session\n  load_balance_strategy: weighted_round_robin\n  enable_transaction_split: true\n  split_respects_consistency: true\n  enable_hint_routing: true\n  enable_cost_routing: false\n  cost_threshold: 1.0\n  analytics_patterns: []\n  writer_readable: true\n  max_replication_lag_ms: 1000\n\
             pool:\n  mode: transaction\n  max_pool_size: 10\n  min_pool_size: 1\n  max_idle_time: 5m\n  connection_timeout: 5s\n  max_lifetime: 30m\n\
             health:\n  check_interval: 3s\n  check_timeout: 2s\n  max_retries: 3\n\
             logging:\n  level: info\n  query_trace: false\n  slow_query: 1000\n",
        )
        .unwrap();

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let target: Arc<dyn RoutingReloadTarget> = Arc::new(NoopReloadTarget);
        let (routing_config, lsn_tracking, slow_queries, log_sender) = make_default_test_extras();
        let app = build_router(
            handle,
            || snapshot_with(true, true),
            Some((path.to_str().unwrap().to_string(), target)),
            None,
            Arc::new(ClientStats::new()),
            routing_config,
            lsn_tracking,
            50,
            PoolMode::Transaction,
            slow_queries,
            log_sender,
            5,
            "5m".to_string(),
            "5s".to_string(),
            "30m".to_string(),
            None,                                  // node_manager
            Some("test-token".to_string()),        // auth_token
            None,                                  // check_interval_setter
            None,                                  // check_interval_getter
            Arc::new(tokio::sync::Mutex::new(())), // config_write_lock
            None,                                  // drain_user_fn
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reload")
                    .header("Authorization", "Bearer test-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let _ = std::fs::remove_file(&path);
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn reload_returns_500_when_config_file_is_invalid() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let target: Arc<dyn RoutingReloadTarget> = Arc::new(NoopReloadTarget);
        let (routing_config, lsn_tracking, slow_queries, log_sender) = make_default_test_extras();
        let app = build_router(
            handle,
            || snapshot_with(true, true),
            Some(("/nonexistent/trident-admin-reload.yaml".to_string(), target)),
            None,
            Arc::new(ClientStats::new()),
            routing_config,
            lsn_tracking,
            50,
            PoolMode::Transaction,
            slow_queries,
            log_sender,
            5,
            "5m".to_string(),
            "5s".to_string(),
            "30m".to_string(),
            None,                                  // node_manager
            Some("test-token".to_string()),        // auth_token
            None,                                  // check_interval_setter
            None,                                  // check_interval_getter
            Arc::new(tokio::sync::Mutex::new(())), // config_write_lock
            None,                                  // drain_user_fn
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reload")
                    .header("Authorization", "Bearer test-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------
    // /custom-rules
    // -----------------------------------------------------------------

    use crate::router::custom_rules::RwMode;

    fn router_with_custom_rules(rules: Arc<CustomRoutingRules>) -> Router {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let (routing_config, lsn_tracking, slow_queries, log_sender) = make_default_test_extras();
        build_router(
            handle,
            || snapshot_with(true, true),
            None,
            Some(rules),
            Arc::new(ClientStats::new()),
            routing_config,
            lsn_tracking,
            50,
            PoolMode::Transaction,
            slow_queries,
            log_sender,
            5,
            "5m".to_string(),
            "5s".to_string(),
            "30m".to_string(),
            None,                                  // node_manager
            Some("test-token".to_string()),        // auth_token
            None,                                  // check_interval_setter
            None,                                  // check_interval_getter
            Arc::new(tokio::sync::Mutex::new(())), // config_write_lock
            None,                                  // drain_user_fn
        )
    }

    #[tokio::test]
    async fn custom_rules_routes_return_501_when_not_configured() {
        let app = test_router(true);

        for (method, body) in [
            ("GET", axum::body::Body::empty()),
            (
                "POST",
                axum::body::Body::from(r#"{"_name":"t1","_type":"t","rw_mode":"w"}"#),
            ),
            (
                "DELETE",
                axum::body::Body::from(r#"{"_name":"t1","_type":"t"}"#),
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/custom-rules")
                        .header("content-type", "application/json")
                        .header("Authorization", "Bearer test-token")
                        .body(body)
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NOT_IMPLEMENTED,
                "method {method}"
            );
        }
    }

    #[tokio::test]
    async fn post_custom_rule_registers_it_and_get_lists_it() {
        let rules = Arc::new(CustomRoutingRules::new());
        let app = router_with_custom_rules(rules.clone());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/custom-rules")
                    .header("Authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"_name":"sensitive_table","_type":"t","rw_mode":"w"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Reflected immediately in the shared registry (no restart/reload
        // needed), and via the GET listing endpoint.
        assert!(rules
            .forces_writer("SELECT * FROM sensitive_table")
            .is_some());

        let list_response = app
            .oneshot(
                Request::builder()
                    .uri("/custom-rules")
                    .header("Authorization", "Bearer test-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let body = to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("sensitive_table"));
    }

    #[tokio::test]
    async fn delete_custom_rule_removes_it() {
        let rules = Arc::new(CustomRoutingRules::new());
        rules.set_rule("t1", RuleTargetKind::Table, RwMode::Writer);
        let app = router_with_custom_rules(rules.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/custom-rules")
                    .header("Authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"_name":"t1","_type":"t"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(rules.forces_writer("SELECT * FROM t1"), None);
    }

    #[tokio::test]
    async fn post_custom_rule_rejects_empty_name() {
        let rules = Arc::new(CustomRoutingRules::new());
        let app = router_with_custom_rules(rules);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/custom-rules")
                    .header("Authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"_name":"","_type":"t","rw_mode":"w"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------
    // /client-stats
    // -----------------------------------------------------------------

    fn router_with_client_stats(client_stats: Arc<ClientStats>) -> Router {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let (routing_config, lsn_tracking, slow_queries, log_sender) = make_default_test_extras();
        build_router(
            handle,
            || snapshot_with(true, true),
            None,
            None,
            client_stats,
            routing_config,
            lsn_tracking,
            50,
            PoolMode::Transaction,
            slow_queries,
            log_sender,
            5,
            "5m".to_string(),
            "5s".to_string(),
            "30m".to_string(),
            None,                                  // node_manager
            Some("test-token".to_string()),        // auth_token
            None,                                  // check_interval_setter
            None,                                  // check_interval_getter
            Arc::new(tokio::sync::Mutex::new(())), // config_write_lock
            None,                                  // drain_user_fn
        )
    }

    #[tokio::test]
    async fn client_stats_reflects_recorded_connections() {
        let stats = Arc::new(ClientStats::new());
        stats.record_connect("127.0.0.1".parse().unwrap());
        stats.record_connect("127.0.0.1".parse().unwrap());
        let app = router_with_client_stats(stats);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/client-stats")
                    .header("Authorization", "Bearer test-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("127.0.0.1"));
        assert!(text.contains(r#""total_connections":2"#));
        assert!(text.contains(r#""active_connections":2"#));
    }

    #[tokio::test]
    async fn client_stats_is_empty_json_array_with_no_connections() {
        let app = router_with_client_stats(Arc::new(ClientStats::new()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/client-stats")
                    .header("Authorization", "Bearer test-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), "[]");
    }
}
