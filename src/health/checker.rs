//! Health checker (`checker`)
//!
//! Periodically performs a TCP connectivity check, a `SELECT 1` query
//! verification, and a `pg_is_in_recovery()` status check against each
//! backend node, and collects the replay LSN and replication lag for
//! Reader nodes. Decides healthy/unhealthy state transitions according to
//! the "3 consecutive failures/successes" rule, and decides whether a node
//! is excluded from the routing candidate set based on a replication-lag
//! threshold.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::{NodeType, SslMode};
use crate::pool::conn::MaybeTlsStream;
use crate::protocol::auth::authenticate_backend;
use crate::protocol::message::{BackendMessage, StartupMessage};
use crate::protocol::reader::read_backend_message;
use crate::protocol::writer::encode_query;

/// A snapshot of a backend node's runtime state, for use by the
/// Router/Balancer.
#[derive(Debug, Clone, PartialEq)]
pub struct BackendNodeSnapshot {
    pub node_id: String,
    pub node_type: NodeType,
    pub healthy: bool,
    pub replay_lsn: u64,
    pub active_connections: i64,
    pub weight: u32,
    pub replication_lag_ms: Option<u64>,
}

/// The raw result of a single health check (contains no state-transition
/// decision; only reports the facts observed during this check).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HealthCheckResult {
    /// Whether the TCP connection was established successfully
    pub tcp_reachable: bool,
    /// Whether `SELECT 1` executed successfully and returned the expected result
    pub select_1_ok: bool,
    /// The return value of `pg_is_in_recovery()` (`None` means it could
    /// not be obtained, e.g. connection or query failure)
    pub is_in_recovery: Option<bool>,
    /// The Reader node's replay LSN (`None` means not applicable or
    /// could not be obtained)
    pub replay_lsn: Option<u64>,
    /// The Writer node's current WAL LSN (`pg_current_wal_lsn()`).
    /// Used to compute LSN-based replication lag for Reader nodes.
    pub current_wal_lsn: Option<u64>,
    /// The Reader node's replication lag (milliseconds)
    pub replication_lag_ms: Option<u64>,
    /// Whether this check is treated as a failure due to timing out
    pub timed_out: bool,
}

impl HealthCheckResult {
    /// Whether this check is considered an overall "success" (used as
    /// input to the consecutive-3-failures/successes state machine).
    ///
    /// See Requirement 9.1, 9.5: only counts as success when TCP is
    /// reachable, `SELECT 1` succeeds, and it did not time out.
    pub fn is_success(&self) -> bool {
        !self.timed_out && self.tcp_reachable && self.select_1_ok
    }

    /// Role-aware success check. In addition to the basic connectivity
    /// checks, verifies that the node's `pg_is_in_recovery()` status
    /// matches its configured role:
    /// - Writer: must NOT be in recovery (`is_in_recovery == false`)
    /// - Reader: must be in recovery (`is_in_recovery == true`)
    /// - Analytics: no additional role constraint
    ///
    /// If `is_in_recovery` could not be obtained (e.g. the query failed),
    /// this falls back to the basic `is_success()` check — connectivity
    /// success without role confirmation is still better than false negative.
    pub fn is_success_for_role(&self, node_type: NodeType) -> bool {
        if !self.is_success() {
            return false;
        }
        match (node_type, self.is_in_recovery) {
            // Writer must NOT be a standby — require explicit confirmation
            (NodeType::Writer, Some(true)) => false,
            // Writer with unknown recovery state: fail-closed to prevent
            // routing writes to a standby that hasn't been confirmed as primary.
            (NodeType::Writer, None) => false,
            // Reader must be in recovery
            (NodeType::Reader, Some(false)) => false,
            // Reader/Analytics with unknown state or correct state: accept
            _ => true,
        }
    }
}

// ---------------------------------------------------------------------
// Health state transitions (the "3 consecutive" rule) -- pure logic, no
// I/O involved, easy to property-test.
// ---------------------------------------------------------------------

const CONSECUTIVE_THRESHOLD: u32 = 3;

/// A single node's health state machine: decides the healthy <-> unhealthy
/// transition based on the number of consecutive successes/failures.
///
/// See Property 35: transitions from healthy to unhealthy only after N
/// consecutive failures (configurable, default 3); transitions from
/// unhealthy to healthy only after N consecutive successes; an
/// opposite-outcome result resets the corresponding counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthStateMachine {
    healthy: bool,
    consecutive_failures: u32,
    consecutive_successes: u32,
    threshold: u32,
}

impl Default for HealthStateMachine {
    fn default() -> Self {
        // The initial state is assumed to be healthy (included in the
        // candidate set by default before the first check).
        HealthStateMachine {
            healthy: true,
            consecutive_failures: 0,
            consecutive_successes: 0,
            threshold: CONSECUTIVE_THRESHOLD,
        }
    }
}

impl HealthStateMachine {
    pub fn new(initially_healthy: bool) -> Self {
        HealthStateMachine {
            healthy: initially_healthy,
            consecutive_failures: 0,
            consecutive_successes: 0,
            threshold: CONSECUTIVE_THRESHOLD,
        }
    }

    /// Creates a state machine with a custom threshold for transitions.
    pub fn with_threshold(initially_healthy: bool, threshold: u32) -> Self {
        let threshold = if threshold == 0 { CONSECUTIVE_THRESHOLD } else { threshold };
        HealthStateMachine {
            healthy: initially_healthy,
            consecutive_failures: 0,
            consecutive_successes: 0,
            threshold,
        }
    }

    pub fn healthy(&self) -> bool {
        self.healthy
    }

    /// Feeds in one check result (success/failure), updating internal
    /// counters and switching state when the condition is met.
    pub fn observe(&mut self, success: bool) {
        if success {
            self.consecutive_failures = 0;
            self.consecutive_successes += 1;
            if !self.healthy && self.consecutive_successes >= self.threshold {
                self.healthy = true;
            }
        } else {
            self.consecutive_successes = 0;
            self.consecutive_failures += 1;
            if self.healthy && self.consecutive_failures >= self.threshold {
                self.healthy = false;
            }
        }
    }
}

/// Determines whether a Reader node should be excluded from the routing
/// candidate set due to replication lag exceeding the threshold.
///
/// See Property 36: excluded if and only if `lag_ms > max_replication_lag_ms`.
/// When `lag_ms = None` (no lag data collected), conservatively does not
/// exclude (returns `false`); the caller combines this with the healthy
/// state for the overall decision.
pub fn is_excluded_by_replication_lag(lag_ms: Option<u64>, max_replication_lag_ms: u64) -> bool {
    match lag_ms {
        Some(lag) => lag > max_replication_lag_ms,
        None => false,
    }
}

// ---------------------------------------------------------------------
// The actual probing logic (TCP + PostgreSQL Wire Protocol)
// ---------------------------------------------------------------------

/// Abstract interface for running a single probe against a backend node.
/// The real implementation is based on TCP + Wire Protocol; unit/property
/// tests can inject a mock implementation to avoid depending on a real
/// PostgreSQL instance.
pub trait HealthProbe: Send + Sync {
    fn probe(
        &self,
        node_type: NodeType,
    ) -> impl std::future::Future<Output = HealthCheckResult> + Send;
}

/// Backend node connection info (the probe target)
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: Option<String>,
    pub ssl_mode: SslMode,
}

/// Default probe implementation based on a real TCP connection + the
/// PostgreSQL Wire Protocol. Cleartext, MD5 and SCRAM-SHA-256 backend
/// authentication are supported using the node's configured password.
pub struct WireProtocolHealthProbe {
    pub target: ProbeTarget,
    /// When true, the probe uses Aurora-native functions
    /// (`aurora_replica_status()`) to obtain LSN values instead of
    /// community PostgreSQL WAL functions.
    pub aurora_native: bool,
}

impl HealthProbe for WireProtocolHealthProbe {
    async fn probe(&self, node_type: NodeType) -> HealthCheckResult {
        let mut result = HealthCheckResult::default();

        let tcp_stream = match TcpStream::connect((self.target.host.as_str(), self.target.port)).await
        {
            Ok(s) => s,
            Err(_) => return result, // tcp_reachable = false (default value)
        };
        result.tcp_reachable = true;

        let mut stream = match upgrade_probe_stream(tcp_stream, &self.target).await {
            Ok(s) => s,
            Err(_) => return result,
        };

        if perform_startup(&mut stream, &self.target).await.is_err() {
            return result;
        }

        if let Ok(true) = run_select_1(&mut stream).await {
            result.select_1_ok = true;
        } else {
            return result;
        }

        if let Ok(Some(in_recovery)) = query_is_in_recovery(&mut stream).await {
            result.is_in_recovery = Some(in_recovery);
        }

        if node_type == NodeType::Writer {
            if self.aurora_native {
                if let Ok(Some(lsn)) = query_aurora_durable_lsn(&mut stream).await {
                    result.current_wal_lsn = Some(lsn);
                }
            } else if let Ok(Some(lsn)) = query_current_wal_lsn(&mut stream).await {
                result.current_wal_lsn = Some(lsn);
            }
        } else if node_type == NodeType::Reader {
            if self.aurora_native {
                if let Ok((lsn, lag)) = query_aurora_reader_status(&mut stream).await {
                    result.replay_lsn = lsn;
                    result.replication_lag_ms = lag;
                }
            } else {
                if let Ok(Some(lsn)) = query_replay_lsn(&mut stream).await {
                    result.replay_lsn = Some(lsn);
                }
                if let Ok(Some(lag)) = query_replication_lag_ms(&mut stream).await {
                    result.replication_lag_ms = Some(lag);
                }
            }
        }

        result
    }
}

/// Performs SSL negotiation on a health probe connection, mirroring the
/// logic in `pool::conn::establish_connection` for consistency.
async fn upgrade_probe_stream(
    mut tcp_stream: TcpStream,
    target: &ProbeTarget,
) -> Result<MaybeTlsStream, ()> {
    use tokio::io::AsyncReadExt;

    match target.ssl_mode {
        SslMode::Disable => Ok(MaybeTlsStream::Plain(tcp_stream)),
        SslMode::Prefer | SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull => {
            // Send SSLRequest (8 bytes: length=8, code=80877103)
            let msg: [u8; 8] = [
                0x00, 0x00, 0x00, 0x08,
                0x04, 0xd2, 0x16, 0x2f,
            ];
            tcp_stream.write_all(&msg).await.map_err(|_| ())?;

            let mut buf = [0u8; 1];
            tcp_stream.read_exact(&mut buf).await.map_err(|_| ())?;

            match buf[0] {
                b'S' => {
                    // Reuse the same TLS upgrade logic from pool::conn
                    use std::sync::Arc;
                    use tokio_rustls::TlsConnector;

                    let config = match target.ssl_mode {
                        SslMode::VerifyCa | SslMode::VerifyFull => {
                            // Use system root certs for verification
                            let mut root_store = rustls::RootCertStore::empty();
                            let native_certs = rustls_native_certs::load_native_certs();
                            for cert in native_certs.certs {
                                let _ = root_store.add(cert);
                            }
                            if target.ssl_mode == SslMode::VerifyFull {
                                rustls::ClientConfig::builder()
                                    .with_root_certificates(root_store)
                                    .with_no_client_auth()
                            } else {
                                // verify-ca: verify chain but not hostname.
                                // Use the same CaOnlyVerifier as the pool
                                // connections to get consistent behavior.
                                let verifier = Arc::new(
                                    crate::pool::conn::CaOnlyVerifier {
                                        roots: Arc::new(root_store),
                                    },
                                );
                                rustls::ClientConfig::builder()
                                    .dangerous()
                                    .with_custom_certificate_verifier(verifier)
                                    .with_no_client_auth()
                            }
                        }
                        _ => {
                            // require/prefer: no verification
                            rustls::ClientConfig::builder()
                                .dangerous()
                                .with_custom_certificate_verifier(Arc::new(
                                    crate::pool::conn::NoVerifier,
                                ))
                                .with_no_client_auth()
                        }
                    };
                    let connector = TlsConnector::from(Arc::new(config));

                    let server_name =
                        rustls::pki_types::ServerName::try_from(target.host.clone())
                            .map_err(|_| ())?;

                    let tls_stream = connector
                        .connect(server_name, tcp_stream)
                        .await
                        .map_err(|_| ())?;
                    Ok(MaybeTlsStream::Tls(Box::new(tls_stream)))
                }
                b'N' => {
                    if target.ssl_mode != SslMode::Prefer {
                        return Err(());
                    }
                    Ok(MaybeTlsStream::Plain(tcp_stream))
                }
                _ => Err(()),
            }
        }
    }
}

async fn perform_startup<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    target: &ProbeTarget,
) -> Result<(), ()> {
    let mut params = HashMap::new();
    params.insert("user".to_string(), target.username.clone());
    params.insert("database".to_string(), target.database.clone());
    let startup = StartupMessage {
        protocol_version: 196_608, // 3.0
        params,
    };

    let mut body = startup.protocol_version.to_be_bytes().to_vec();
    for (k, v) in &startup.params {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut framed = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    framed.extend(body);
    stream.write_all(&framed).await.map_err(|_| ())?;
    stream.flush().await.map_err(|_| ())?;
    authenticate_backend(stream, &target.username, target.password.as_deref())
        .await
        .map_err(|_| ())?;

    // Authentication is complete. Consume startup status messages until
    // ReadyForQuery; any further authentication request is a protocol
    // error and must not be silently ignored.
    loop {
        match read_backend_message(stream).await {
            Ok(BackendMessage::ReadyForQuery(_)) => return Ok(()),
            Ok(BackendMessage::ParameterStatus { .. })
            | Ok(BackendMessage::BackendKeyData { .. }) => continue,
            Ok(BackendMessage::ErrorResponse(_)) => return Err(()),
            Ok(_) => return Err(()),
            Err(_) => return Err(()),
        }
    }
}

/// Sends a simple query and collects the text value of the first row's
/// first column (if any), reading until `ReadyForQuery`.
async fn run_simple_query_first_column<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    sql: &str,
) -> Result<Option<String>, ()> {
    let bytes = encode_query(sql);
    stream.write_all(&bytes).await.map_err(|_| ())?;
    stream.flush().await.map_err(|_| ())?;

    let mut first_value: Option<String> = None;
    let mut saw_error = false;
    loop {
        match read_backend_message(stream).await {
            Ok(BackendMessage::DataRow(cols)) => {
                if first_value.is_none() {
                    if let Some(Some(bytes)) = cols.first() {
                        first_value = String::from_utf8(bytes.clone()).ok();
                    }
                }
            }
            Ok(BackendMessage::ErrorResponse(_)) => saw_error = true,
            Ok(BackendMessage::ReadyForQuery(_)) => break,
            Ok(_) => continue,
            Err(_) => return Err(()),
        }
    }

    if saw_error {
        Ok(None)
    } else {
        Ok(first_value)
    }
}

async fn run_select_1<S: AsyncRead + AsyncWrite + Unpin + Send>(stream: &mut S) -> Result<bool, ()> {
    let value = run_simple_query_first_column(stream, "SELECT 1").await?;
    Ok(value.as_deref() == Some("1"))
}

async fn query_is_in_recovery<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
) -> Result<Option<bool>, ()> {
    let value = run_simple_query_first_column(stream, "SELECT pg_is_in_recovery()").await?;
    Ok(value.map(|v| v == "t" || v.eq_ignore_ascii_case("true")))
}

async fn query_replay_lsn<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
) -> Result<Option<u64>, ()> {
    let value = run_simple_query_first_column(stream, "SELECT pg_last_wal_replay_lsn()").await?;
    Ok(value.and_then(|v| parse_lsn(&v)))
}

async fn query_current_wal_lsn<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
) -> Result<Option<u64>, ()> {
    let value = run_simple_query_first_column(stream, "SELECT pg_current_wal_lsn()").await?;
    Ok(value.and_then(|v| parse_lsn(&v)))
}

async fn query_replication_lag_ms<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
) -> Result<Option<u64>, ()> {
    let value = run_simple_query_first_column(
        stream,
        "SELECT COALESCE(EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())) * 1000, 0)",
    )
    .await?;
    Ok(value.and_then(|v| v.parse::<f64>().ok()).map(|ms| ms.max(0.0) as u64))
}

/// Queries the Writer's durable LSN from Aurora's `aurora_replica_status()`
/// system function. The Writer row is identified by `session_id = 'MASTER_SESSION_ID'`.
/// Returns the LSN in the same `u64` format used throughout the codebase
/// (parsed from Aurora's hex `X/YYYYYYYY` representation).
async fn query_aurora_durable_lsn<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
) -> Result<Option<u64>, ()> {
    let value = run_simple_query_first_column(
        stream,
        "SELECT durable_lsn FROM aurora_replica_status() WHERE session_id = 'MASTER_SESSION_ID'",
    )
    .await?;
    Ok(value.and_then(|v| parse_lsn(&v)))
}

/// Queries this Reader's current_read_lsn and replica_lag_in_msec from
/// Aurora's `aurora_replica_status()` in a single query to minimize
/// health check overhead.
async fn query_aurora_reader_status<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
) -> Result<(Option<u64>, Option<u64>), ()> {
    let query_bytes = crate::protocol::writer::encode_query(
        "SELECT current_read_lsn, replica_lag_in_msec FROM aurora_replica_status() WHERE server_id = aurora_db_instance_identifier()"
    );
    stream.write_all(&query_bytes).await.map_err(|_| ())?;
    stream.flush().await.map_err(|_| ())?;

    let mut lsn: Option<u64> = None;
    let mut lag_ms: Option<u64> = None;
    loop {
        match crate::protocol::reader::read_backend_message(stream).await {
            Ok(crate::protocol::message::BackendMessage::DataRow(cols)) => {
                if let Some(Some(bytes)) = cols.first() {
                    lsn = String::from_utf8(bytes.clone()).ok().and_then(|v| parse_lsn(&v));
                }
                if let Some(Some(bytes)) = cols.get(1) {
                    lag_ms = String::from_utf8(bytes.clone())
                        .ok()
                        .and_then(|v| v.trim().parse::<u64>().ok());
                }
            }
            Ok(crate::protocol::message::BackendMessage::ReadyForQuery(_)) => break,
            Ok(_) => continue,
            Err(_) => return Err(()),
        }
    }
    Ok((lsn, lag_ms))
}

/// Parses a PostgreSQL LSN text representation into a `u64`.
/// Supports two formats:
/// - Standard PostgreSQL: `"16/B374D848"` (hex/hex)
/// - Aurora numeric: `"576765581"` (plain decimal integer)
/// Returns `None` for unparseable input or the zero LSN.
pub fn parse_lsn(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    if let Some((hi, lo)) = trimmed.split_once('/') {
        // Standard PostgreSQL LSN format: hex/hex
        let hi = u64::from_str_radix(hi, 16).ok()?;
        let lo = u64::from_str_radix(lo, 16).ok()?;
        let lsn = (hi << 32) | lo;
        if lsn == 0 { None } else { Some(lsn) }
    } else {
        // Aurora numeric format: plain decimal integer
        let lsn = trimmed.parse::<u64>().ok()?;
        if lsn == 0 { None } else { Some(lsn) }
    }
}

// ---------------------------------------------------------------------
// HealthChecker: chains together probing + the state machine, maintaining
// a snapshot per node.
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TrackedNode {
    node_type: NodeType,
    weight: u32,
    state: HealthStateMachine,
    last_replay_lsn: u64,
    /// Writer: last known `pg_current_wal_lsn()` value.
    last_current_wal_lsn: u64,
    last_replication_lag_ms: Option<u64>,
    /// Monotonically increasing incarnation counter; incremented each time
    /// a node with this ID is added. Allows rejecting stale probe results
    /// from a previous incarnation after remove/re-add.
    generation: u64,
}

/// Health checker: manages the health state and LSN/lag snapshots of a
/// set of backend nodes.
pub struct HealthChecker<P: HealthProbe> {
    probes: RwLock<HashMap<String, Arc<P>>>,
    max_replication_lag_ms: u64,
    /// Configured threshold for consecutive failures/successes before
    /// transitioning health state. Used for dynamically added nodes.
    health_threshold: u32,
    nodes: Mutex<HashMap<String, TrackedNode>>,
    check_timeout: Duration,
    /// Cached snapshot updated after each health-check cycle. Reads are
    /// lock-free (just an atomic pointer load), avoiding the per-query
    /// mutex contention that `nodes.lock()` would introduce on the hot path.
    cached_snapshot: ArcSwap<Vec<BackendNodeSnapshot>>,
    /// Optional LSN tracker reference. When set, the health checker
    /// advances `global_write_lsn` on every successful Writer probe,
    /// ensuring the global watermark stays current even when individual
    /// sessions never resolve their `pending_write` LSN.
    lsn_tracker: Option<Arc<dyn crate::session::lsn::LsnTracker>>,
    /// Dynamically adjustable check interval in milliseconds.
    check_interval_ms: std::sync::atomic::AtomicU64,
}

impl<P: HealthProbe> HealthChecker<P> {
    pub fn new(
        node_probes: Vec<(String, NodeType, u32, P)>,
        max_replication_lag_ms: u64,
        check_timeout: Duration,
    ) -> Self {
        Self::with_max_retries(node_probes, max_replication_lag_ms, check_timeout, CONSECUTIVE_THRESHOLD)
    }

    /// Creates a HealthChecker with a custom `max_retries` threshold for
    /// the consecutive-failure/success state machine. This is the value
    /// from `health.max_retries` in the configuration file.
    pub fn with_max_retries(
        node_probes: Vec<(String, NodeType, u32, P)>,
        max_replication_lag_ms: u64,
        check_timeout: Duration,
        max_retries: u32,
    ) -> Self {
        let threshold = if max_retries == 0 { CONSECUTIVE_THRESHOLD } else { max_retries };
        let mut probes = HashMap::new();
        let mut nodes = HashMap::new();
        for (node_id, node_type, weight, probe) in node_probes {
            probes.insert(node_id.clone(), Arc::new(probe));
            nodes.insert(
                node_id,
                TrackedNode {
                    node_type,
                    weight,
                    state: HealthStateMachine::with_threshold(true, threshold),
                    last_replay_lsn: 0,
                    last_current_wal_lsn: 0,
                    last_replication_lag_ms: None,
                    generation: 1,
                },
            );
        }
        let initial_snapshot: Vec<BackendNodeSnapshot> = nodes
            .iter()
            .map(|(node_id, node)| BackendNodeSnapshot {
                node_id: node_id.clone(),
                node_type: node.node_type,
                healthy: node.state.healthy(),
                replay_lsn: 0,
                active_connections: 0,
                weight: node.weight,
                replication_lag_ms: None,
            })
            .collect();
        HealthChecker {
            probes: RwLock::new(probes),
            max_replication_lag_ms,
            health_threshold: threshold,
            nodes: Mutex::new(nodes),
            check_timeout,
            cached_snapshot: ArcSwap::new(Arc::new(initial_snapshot)),
            lsn_tracker: None,
            check_interval_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Sets the LSN tracker reference. When configured, the health checker
    /// will advance `global_write_lsn` on every successful Writer probe,
    /// closing the Global consistency gap under `lazy_fallback: true`.
    pub fn set_lsn_tracker(&mut self, tracker: Arc<dyn crate::session::lsn::LsnTracker>) {
        self.lsn_tracker = Some(tracker);
    }

    /// Runs a single check against one node: probing plus applying the
    /// timeout rule, returning the raw result of this check. Does not
    /// modify the node's routing availability state (only reports the
    /// result); the state transition is decided by the caller (typically
    /// `run`) according to the "3 consecutive failures/successes" rule.
    pub async fn check_once(&self, node_id: &str) -> Option<HealthCheckResult> {
        let node_type = {
            let nodes = self.nodes.lock();
            nodes.get(node_id)?.node_type
        };
        let probe = {
            let probes = self.probes.read();
            probes.get(node_id)?.clone()
        };

        let result = match timeout(self.check_timeout, probe.probe(node_type)).await {
            Ok(result) => result,
            Err(_) => HealthCheckResult {
                timed_out: true,
                ..Default::default()
            },
        };
        Some(result)
    }

    fn apply_result(&self, node_id: &str, probe_generation: u64, result: HealthCheckResult) {
        let node_type = {
            let nodes = self.nodes.lock();
            nodes.get(node_id).map(|n| n.node_type)
        };

        // Use role-aware success check when we know the node type
        let success = match node_type {
            Some(nt) => result.is_success_for_role(nt),
            None => result.is_success(),
        };

        metrics::counter!(
            "trident_health_checks_total",
            "node_id" => node_id.to_string(),
            "result" => if success { "success" } else { "failure" }
        )
        .increment(1);

        let mut nodes = self.nodes.lock();
        if let Some(node) = nodes.get_mut(node_id) {
            // Reject stale probe results from a previous incarnation.
            // After remove/re-add the node's generation advances; an
            // in-flight probe from the old address must not update the
            // new node's health state.
            if node.generation != probe_generation {
                tracing::debug!(
                    node_id,
                    probe_generation,
                    current_generation = node.generation,
                    "discarding stale health probe result (generation mismatch)"
                );
                return;
            }
            let was_healthy = node.state.healthy();
            node.state.observe(success);
            let is_healthy_now = node.state.healthy();
            if was_healthy != is_healthy_now {
                metrics::counter!(
                    "trident_health_transitions_total",
                    "node_id" => node_id.to_string(),
                    "to" => if is_healthy_now { "healthy" } else { "unhealthy" }
                )
                .increment(1);
                tracing::info!(node_id, healthy = is_healthy_now, "backend node health state changed");
            }
            if let Some(lsn) = result.replay_lsn {
                node.last_replay_lsn = lsn;
            }
            if let Some(lsn) = result.current_wal_lsn {
                node.last_current_wal_lsn = lsn;
                // Advance the global write LSN floor from the Writer's
                // actual WAL position. This closes the Global consistency
                // staleness gap: even if sessions with pending_write never
                // resolve their LSN (lazy_fallback optimization), the
                // health checker periodically brings the global watermark
                // up to the Writer's true position.
                if node.node_type == NodeType::Writer {
                    if let Some(ref tracker) = self.lsn_tracker {
                        tracker.advance_global_lsn(lsn);
                    }
                }
            }
            node.last_replication_lag_ms = result.replication_lag_ms;
        }
    }

    /// Runs a single check and feeds the result into this node's health
    /// state machine, updating its snapshot.
    pub async fn check_and_update(&self, node_id: &str) {
        let generation = {
            let nodes = self.nodes.lock();
            match nodes.get(node_id) {
                Some(n) => n.generation,
                None => return,
            }
        };
        let Some(result) = self.check_once(node_id).await else {
            return;
        };
        self.apply_result(node_id, generation, result);
        self.refresh_cached_snapshot();
    }

    /// Probes every configured node concurrently and applies each result as
    /// soon as it completes. Probe handles are Arc-backed, so no state lock is
    /// held while network I/O is in flight.
    pub async fn check_all_and_update(&self)
    where
        P: 'static,
    {
        let checks: Vec<_> = {
            let nodes = self.nodes.lock();
            let probes = self.probes.read();
            probes
                .iter()
                .filter_map(|(node_id, probe)| {
                    nodes
                        .get(node_id)
                        .map(|node| (node_id.clone(), node.node_type, node.generation, Arc::clone(probe)))
                })
                .collect()
        };

        let mut tasks = tokio::task::JoinSet::new();
        for (node_id, node_type, generation, probe) in checks {
            let check_timeout = self.check_timeout;
            tasks.spawn(async move {
                let result = match timeout(check_timeout, probe.probe(node_type)).await {
                    Ok(result) => result,
                    Err(_) => HealthCheckResult {
                        timed_out: true,
                        ..Default::default()
                    },
                };
                (node_id, generation, result)
            });
        }

        while let Some(completed) = tasks.join_next().await {
            match completed {
                Ok((node_id, generation, result)) => self.apply_result(&node_id, generation, result),
                Err(error) => {
                    tracing::error!(%error, "backend health-check task failed");
                }
            }
        }
        self.refresh_cached_snapshot();
    }

    /// Rebuilds the cached snapshot from the current node state.
    fn refresh_cached_snapshot(&self) {
        let nodes = self.nodes.lock();

        // Collect the maximum writer WAL LSN across all writer nodes.
        let writer_wal_lsn: u64 = nodes
            .values()
            .filter(|n| n.node_type == NodeType::Writer)
            .map(|n| n.last_current_wal_lsn)
            .max()
            .unwrap_or(0);

        let snap: Vec<BackendNodeSnapshot> = nodes
            .iter()
            .map(|(node_id, node)| {
                // Compute LSN-based lag for Reader nodes. If the writer
                // LSN is known (non-zero) and the reader has reported a
                // replay LSN, use the byte difference. This is immune to
                // the "idle writer" false-positive that plagues the
                // timestamp-based approach.
                let effective_lag_ms = if node.node_type == NodeType::Reader {
                    if writer_wal_lsn > 0 && node.last_replay_lsn > 0 {
                        let lsn_diff = writer_wal_lsn.saturating_sub(node.last_replay_lsn);
                        if lsn_diff == 0 {
                            // LSN fully caught up — override any stale
                            // timestamp-based lag value.
                            Some(0)
                        } else {
                            // Use the timestamp-based lag if available
                            // (it gives a time dimension), but cap it: if
                            // LSN diff is tiny (< 16 MB) and timestamp lag
                            // is huge, it means the writer has been idle
                            // and the timestamp is misleading — use 0.
                            let lsn_lag_threshold = 16 * 1024 * 1024; // 16 MB
                            if lsn_diff < lsn_lag_threshold {
                                // Small LSN gap — likely just idle writer,
                                // not real lag.
                                Some(0)
                            } else {
                                // Genuine lag — use the timestamp value if
                                // available (from Aurora's replica_lag_in_msec
                                // or PostgreSQL's replication lag query).
                                node.last_replication_lag_ms
                            }
                        }
                    } else {
                        // No writer LSN data yet — fall back to timestamp
                        node.last_replication_lag_ms
                    }
                } else {
                    None
                };

                let excluded_by_lag = node.node_type == NodeType::Reader
                    && is_excluded_by_replication_lag(
                        effective_lag_ms,
                        self.max_replication_lag_ms,
                    );
                BackendNodeSnapshot {
                    node_id: node_id.clone(),
                    node_type: node.node_type,
                    healthy: node.state.healthy() && !excluded_by_lag,
                    replay_lsn: node.last_replay_lsn,
                    active_connections: 0,
                    weight: node.weight,
                    replication_lag_ms: effective_lag_ms,
                }
            })
            .collect();
        drop(nodes);
        self.cached_snapshot.store(Arc::new(snap));
    }

    /// Runs continuously at the configured interval, periodically
    /// updating the health state of all nodes in parallel.
    pub async fn run(&self, interval: Duration)
    where
        P: 'static,
    {
        // Defense-in-depth: config validation should reject zero, but if
        // a zero duration somehow reaches here, use a safe fallback to
        // avoid tokio::time::interval panic.
        let safe_interval = if interval.is_zero() {
            tracing::error!(
                "health check interval is zero (should have been caught by config validation), \
                 falling back to 3s"
            );
            Duration::from_secs(3)
        } else {
            interval
        };
        // Store the initial interval for dynamic adjustment.
        self.check_interval_ms.store(
            safe_interval.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        let mut ticker = tokio::time::interval(safe_interval);
        loop {
            ticker.tick().await;
            self.check_all_and_update().await;
            // Check if the interval was dynamically adjusted.
            let current_ms = self.check_interval_ms.load(std::sync::atomic::Ordering::Relaxed);
            let current_period = Duration::from_millis(current_ms);
            if current_period != ticker.period() && !current_period.is_zero() {
                ticker = tokio::time::interval(current_period);
                // Consume the immediate first tick so we don't double-fire.
                ticker.tick().await;
                tracing::info!(
                    new_interval_ms = current_ms,
                    "health check interval dynamically adjusted"
                );
            }
        }
    }

    /// Dynamically adjusts the health check interval at runtime.
    /// Takes effect after the current check cycle completes.
    pub fn set_check_interval(&self, interval: Duration) {
        let ms = interval.as_millis() as u64;
        if ms > 0 {
            self.check_interval_ms.store(ms, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Returns the current health check interval.
    pub fn check_interval(&self) -> Duration {
        Duration::from_millis(
            self.check_interval_ms.load(std::sync::atomic::Ordering::Relaxed)
        )
    }

    /// Aggregates the current snapshot of all nodes, for use by the
    /// Router/Balancer. Uses the lock-free cached snapshot (updated after
    /// each health-check cycle) to avoid mutex contention on the per-query
    /// hot path.
    pub fn snapshot(&self) -> Vec<BackendNodeSnapshot> {
        (**self.cached_snapshot.load()).clone()
    }

    /// Dynamically adds a new node to the health checker at runtime.
    /// The node starts in unhealthy state until the first successful probe.
    /// Returns `false` if a node with the same `node_id` already exists.
    pub fn add_node(&self, node_id: String, node_type: NodeType, weight: u32, probe: P) -> bool {
        let mut nodes = self.nodes.lock();
        if nodes.contains_key(&node_id) {
            return false;
        }
        // Hold both locks to ensure nodes and probes are updated atomically.
        // This prevents an intermediate state where a node exists without
        // its probe (or vice versa) visible to the health-check loop.
        let mut probes = self.probes.write();
        // Determine generation: if a previous incarnation existed, we would
        // have already removed it, but compute a safe generation in case of
        // rapid add/remove/add cycles where snapshot data persists.
        let gen = nodes
            .values()
            .map(|n| n.generation)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        nodes.insert(
            node_id.clone(),
            TrackedNode {
                node_type,
                weight,
                state: HealthStateMachine::with_threshold(false, self.health_threshold),
                last_replay_lsn: 0,
                last_current_wal_lsn: 0,
                last_replication_lag_ms: None,
                generation: gen,
            },
        );
        probes.insert(node_id.clone(), Arc::new(probe));
        drop(probes);
        drop(nodes);

        self.refresh_cached_snapshot();
        tracing::info!(node_id = %node_id, generation = gen, "dynamically added node to health checker");
        true
    }

    /// Dynamically removes a node from the health checker at runtime.
    /// Returns `false` if the node does not exist.
    /// If `prevent_last_writer` is true, refuses to remove the node if it
    /// is the only remaining Writer.
    pub fn remove_node(&self, node_id: &str) -> bool {
        self.remove_node_checked(node_id, false).is_ok()
    }

    /// Removes a node with an optional last-writer safety check.
    /// Returns `Err(reason)` if the node cannot be removed.
    pub fn remove_node_checked(&self, node_id: &str, prevent_last_writer: bool) -> Result<(), &'static str> {
        let mut nodes = self.nodes.lock();

        if !nodes.contains_key(node_id) {
            return Err("node does not exist");
        }

        if prevent_last_writer {
            let target_type = nodes.get(node_id).map(|n| n.node_type);
            if target_type == Some(NodeType::Writer) {
                let writer_count = nodes.values().filter(|n| n.node_type == NodeType::Writer).count();
                if writer_count <= 1 {
                    return Err("cannot remove the last writer node");
                }
            }
        }

        // Hold both locks to ensure nodes and probes are removed atomically.
        let mut probes = self.probes.write();
        nodes.remove(node_id);
        probes.remove(node_id);
        drop(probes);
        drop(nodes);

        self.refresh_cached_snapshot();
        tracing::info!(node_id, "dynamically removed node from health checker");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -----------------------------------------------------------------
    // Property 35: health state transitions strictly follow the
    // consecutive-3 rule
    // Validates: Requirements 9.2, 9.3
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_35_transitions_follow_consecutive_three_rule(
            results in prop::collection::vec(any::<bool>(), 0..200)
        ) {
            let mut machine = HealthStateMachine::new(true);
            let mut consecutive_failures = 0u32;
            let mut consecutive_successes = 0u32;

            for success in results {
                let was_healthy = machine.healthy();
                machine.observe(success);

                if success {
                    consecutive_failures = 0;
                    consecutive_successes += 1;
                } else {
                    consecutive_successes = 0;
                    consecutive_failures += 1;
                }

                if was_healthy {
                    // Can only become unhealthy once consecutive failures
                    // reach 3; otherwise it must remain healthy.
                    if consecutive_failures >= 3 {
                        prop_assert!(!machine.healthy());
                    } else {
                        prop_assert!(machine.healthy());
                    }
                } else {
                    // Can only become healthy once consecutive successes
                    // reach 3; otherwise it must remain unhealthy.
                    if consecutive_successes >= 3 {
                        prop_assert!(machine.healthy());
                    } else {
                        prop_assert!(!machine.healthy());
                    }
                }
            }
        }

        // -----------------------------------------------------------------
        // Property 36: the replication-lag exclusion decision matches the
        // threshold exactly
        // Validates: Requirements 9.4
        // -----------------------------------------------------------------
        #[test]
        fn property_36_lag_exclusion_matches_threshold(
            lag in 0u64..100_000, threshold in 0u64..100_000,
        ) {
            let excluded = is_excluded_by_replication_lag(Some(lag), threshold);
            prop_assert_eq!(excluded, lag > threshold);
        }

        #[test]
        fn property_36_missing_lag_never_excludes(threshold in 0u64..100_000) {
            prop_assert!(!is_excluded_by_replication_lag(None, threshold));
        }
    }

    // -----------------------------------------------------------------
    // Unit tests
    // -----------------------------------------------------------------

    #[test]
    fn three_consecutive_failures_marks_unhealthy() {
        let mut machine = HealthStateMachine::new(true);
        machine.observe(false);
        assert!(machine.healthy());
        machine.observe(false);
        assert!(machine.healthy());
        machine.observe(false);
        assert!(!machine.healthy());
    }

    #[test]
    fn a_single_success_resets_failure_count() {
        let mut machine = HealthStateMachine::new(true);
        machine.observe(false);
        machine.observe(false);
        machine.observe(true); // resets the failure counter
        machine.observe(false);
        machine.observe(false);
        assert!(machine.healthy()); // still hasn't reached 3 consecutive failures
    }

    #[test]
    fn three_consecutive_successes_restores_healthy() {
        let mut machine = HealthStateMachine::new(false);
        machine.observe(true);
        assert!(!machine.healthy());
        machine.observe(true);
        assert!(!machine.healthy());
        machine.observe(true);
        assert!(machine.healthy());
    }

    #[test]
    fn lsn_parsing_handles_typical_format() {
        assert_eq!(parse_lsn("16/B374D848"), Some((0x16u64 << 32) | 0xB374D848));
        assert_eq!(parse_lsn("0/0"), None); // zero LSN is treated as unset
        assert_eq!(parse_lsn("0/1"), Some(1)); // non-zero is valid
        assert_eq!(parse_lsn("not-an-lsn"), None);
    }

    #[test]
    fn health_check_result_success_requires_all_conditions() {
        let mut result = HealthCheckResult::default();
        assert!(!result.is_success());

        result.tcp_reachable = true;
        result.select_1_ok = true;
        assert!(result.is_success());

        result.timed_out = true;
        assert!(!result.is_success());
    }

    // Mock probe used to test HealthChecker orchestration without real I/O.
    struct MockProbe {
        result: HealthCheckResult,
    }

    impl HealthProbe for MockProbe {
        async fn probe(&self, _node_type: NodeType) -> HealthCheckResult {
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn health_checker_updates_snapshot_after_check() {
        let healthy_result = HealthCheckResult {
            tcp_reachable: true,
            select_1_ok: true,
            is_in_recovery: Some(true),
            replay_lsn: Some(100),
            current_wal_lsn: None,
            replication_lag_ms: Some(50),
            timed_out: false,
        };
        let checker = HealthChecker::new(
            vec![(
                "reader-1".to_string(),
                NodeType::Reader,
                5,
                MockProbe {
                    result: healthy_result,
                },
            )],
            1000,
            Duration::from_secs(1),
        );

        checker.check_and_update("reader-1").await;
        let snapshot = checker.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].replay_lsn, 100);
        assert_eq!(snapshot[0].replication_lag_ms, Some(50));
        // A single successful check is not enough to change from the
        // initial healthy=true state; it should still be healthy.
        assert!(snapshot[0].healthy);
    }

    #[tokio::test]
    async fn health_checker_excludes_node_exceeding_replication_lag() {
        let laggy_result = HealthCheckResult {
            tcp_reachable: true,
            select_1_ok: true,
            is_in_recovery: Some(true),
            replay_lsn: Some(100),
            current_wal_lsn: None,
            replication_lag_ms: Some(5000),
            timed_out: false,
        };
        let checker = HealthChecker::new(
            vec![(
                "reader-1".to_string(),
                NodeType::Reader,
                5,
                MockProbe {
                    result: laggy_result,
                },
            )],
            1000, // max_replication_lag_ms
            Duration::from_secs(1),
        );

        checker.check_and_update("reader-1").await;
        let snapshot = checker.snapshot();
        assert!(!snapshot[0].healthy); // excluded from the candidate set
    }

    #[tokio::test]
    async fn health_checker_marks_unhealthy_after_three_failures() {
        let failing_result = HealthCheckResult::default(); // tcp_reachable = false
        let checker = HealthChecker::new(
            vec![(
                "writer".to_string(),
                NodeType::Writer,
                1,
                MockProbe {
                    result: failing_result,
                },
            )],
            1000,
            Duration::from_secs(1),
        );

        for _ in 0..3 {
            checker.check_and_update("writer").await;
        }
        let snapshot = checker.snapshot();
        assert!(!snapshot[0].healthy);
    }

    #[tokio::test]
    async fn all_nodes_in_a_health_round_are_probed_concurrently() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        #[derive(Clone)]
        struct ConcurrentProbe {
            active: Arc<AtomicUsize>,
            max_active: Arc<AtomicUsize>,
        }

        impl HealthProbe for ConcurrentProbe {
            async fn probe(&self, _node_type: NodeType) -> HealthCheckResult {
                let active = self.active.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                self.max_active.fetch_max(active, AtomicOrdering::SeqCst);
                tokio::time::sleep(Duration::from_millis(30)).await;
                self.active.fetch_sub(1, AtomicOrdering::SeqCst);
                HealthCheckResult {
                    tcp_reachable: true,
                    select_1_ok: true,
                    ..Default::default()
                }
            }
        }

        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let probe = ConcurrentProbe {
            active,
            max_active: max_active.clone(),
        };
        let checker = HealthChecker::new(
            ["writer", "reader-1", "reader-2"]
                .into_iter()
                .map(|node_id| (node_id.to_string(), NodeType::Writer, 1, probe.clone()))
                .collect(),
            1000,
            Duration::from_secs(1),
        );

        checker.check_all_and_update().await;
        assert_eq!(
            max_active.load(AtomicOrdering::SeqCst),
            3,
            "all node probes should overlap within one health-check round"
        );
    }

    #[tokio::test]
    async fn check_once_times_out_when_probe_never_completes() {
        struct SlowProbe;
        impl HealthProbe for SlowProbe {
            async fn probe(&self, _node_type: NodeType) -> HealthCheckResult {
                tokio::time::sleep(Duration::from_secs(10)).await;
                HealthCheckResult::default()
            }
        }

        let checker = HealthChecker::new(
            vec![(
                "slow".to_string(),
                NodeType::Writer,
                1,
                SlowProbe,
            )],
            1000,
            Duration::from_millis(50),
        );

        let result = checker.check_once("slow").await.unwrap();
        assert!(result.timed_out);
        assert!(!result.is_success());
    }

    #[tokio::test]
    async fn health_checker_advances_global_lsn_from_writer_probe() {
        use crate::session::lsn::{InMemoryLsnTracker, LsnTracker};

        let tracker = Arc::new(InMemoryLsnTracker::new());
        assert_eq!(tracker.global_write_lsn(), 0);

        // Simulate a Writer probe that returns a WAL LSN
        let writer_lsn = (0x16u64 << 32) | 0xB374D848;
        let probe_result = HealthCheckResult {
            tcp_reachable: true,
            select_1_ok: true,
            is_in_recovery: Some(false),
            current_wal_lsn: Some(writer_lsn),
            replay_lsn: None,
            replication_lag_ms: None,
            timed_out: false,
        };

        let mut checker = HealthChecker::new(
            vec![(
                "writer".to_string(),
                NodeType::Writer,
                1,
                MockProbe { result: probe_result },
            )],
            1000,
            Duration::from_secs(1),
        );
        checker.set_lsn_tracker(tracker.clone());

        // Before any checks, global is 0
        assert_eq!(tracker.global_write_lsn(), 0);

        // After a health check, global should advance to the Writer's WAL LSN
        checker.check_and_update("writer").await;
        assert_eq!(tracker.global_write_lsn(), writer_lsn);

        // A session that writes at a lower LSN does not decrease global
        tracker.record_write("session-a", 100);
        assert_eq!(tracker.global_write_lsn(), writer_lsn);

        // A higher Writer LSN in a subsequent check advances global further
        let higher_lsn = writer_lsn + 1000;
        // Directly call apply_result to simulate a new probe
        checker.apply_result("writer", 1, HealthCheckResult {
            tcp_reachable: true,
            select_1_ok: true,
            is_in_recovery: Some(false),
            current_wal_lsn: Some(higher_lsn),
            replay_lsn: None,
            replication_lag_ms: None,
            timed_out: false,
        });
        assert_eq!(tracker.global_write_lsn(), higher_lsn);
    }
}
