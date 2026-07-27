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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;

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
}

// ---------------------------------------------------------------------
// Health state transitions (the "3 consecutive" rule) -- pure logic, no
// I/O involved, easy to property-test.
// ---------------------------------------------------------------------

const CONSECUTIVE_THRESHOLD: u32 = 3;

/// A single node's health state machine: decides the healthy <-> unhealthy
/// transition based on the number of consecutive successes/failures.
///
/// See Property 35: transitions from healthy to unhealthy only after 3
/// consecutive failures; transitions from unhealthy to healthy only after
/// 3 consecutive successes; an opposite-outcome result resets the
/// corresponding counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthStateMachine {
    healthy: bool,
    consecutive_failures: u32,
    consecutive_successes: u32,
}

impl Default for HealthStateMachine {
    fn default() -> Self {
        // The initial state is assumed to be healthy (included in the
        // candidate set by default before the first check).
        HealthStateMachine {
            healthy: true,
            consecutive_failures: 0,
            consecutive_successes: 0,
        }
    }
}

impl HealthStateMachine {
    pub fn new(initially_healthy: bool) -> Self {
        HealthStateMachine {
            healthy: initially_healthy,
            consecutive_failures: 0,
            consecutive_successes: 0,
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
            if !self.healthy && self.consecutive_successes >= CONSECUTIVE_THRESHOLD {
                self.healthy = true;
            }
        } else {
            self.consecutive_successes = 0;
            self.consecutive_failures += 1;
            if self.healthy && self.consecutive_failures >= CONSECUTIVE_THRESHOLD {
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

        if node_type == NodeType::Reader {
            if let Ok(Some(lsn)) = query_replay_lsn(&mut stream).await {
                result.replay_lsn = Some(lsn);
            }
            if let Ok(Some(lag)) = query_replication_lag_ms(&mut stream).await {
                result.replication_lag_ms = Some(lag);
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
        SslMode::Prefer | SslMode::Require => {
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

                    let config = rustls::ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(
                            crate::pool::conn::NoVerifier,
                        ))
                        .with_no_client_auth();
                    let connector = TlsConnector::from(Arc::new(config));

                    let server_name =
                        rustls::pki_types::ServerName::try_from(target.host.clone())
                            .map_err(|_| ())?;

                    let tls_stream = connector
                        .connect(server_name, tcp_stream)
                        .await
                        .map_err(|_| ())?;
                    Ok(MaybeTlsStream::Tls(tls_stream))
                }
                b'N' => {
                    if target.ssl_mode == SslMode::Require {
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

/// Parses a PostgreSQL LSN text representation (e.g. `"16/B374D848"`) into
/// a `u64`.
pub fn parse_lsn(text: &str) -> Option<u64> {
    let (hi, lo) = text.split_once('/')?;
    let hi = u64::from_str_radix(hi, 16).ok()?;
    let lo = u64::from_str_radix(lo, 16).ok()?;
    Some((hi << 32) | lo)
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
    last_replication_lag_ms: Option<u64>,
}

/// Health checker: manages the health state and LSN/lag snapshots of a
/// set of backend nodes.
pub struct HealthChecker<P: HealthProbe> {
    probes: HashMap<String, Arc<P>>,
    max_replication_lag_ms: u64,
    nodes: Mutex<HashMap<String, TrackedNode>>,
    check_timeout: Duration,
    /// Cached snapshot updated after each health-check cycle. Reads are
    /// lock-free (just an atomic pointer load), avoiding the per-query
    /// mutex contention that `nodes.lock()` would introduce on the hot path.
    cached_snapshot: ArcSwap<Vec<BackendNodeSnapshot>>,
}

impl<P: HealthProbe> HealthChecker<P> {
    pub fn new(
        node_probes: Vec<(String, NodeType, u32, P)>,
        max_replication_lag_ms: u64,
        check_timeout: Duration,
    ) -> Self {
        let mut probes = HashMap::new();
        let mut nodes = HashMap::new();
        for (node_id, node_type, weight, probe) in node_probes {
            probes.insert(node_id.clone(), Arc::new(probe));
            nodes.insert(
                node_id,
                TrackedNode {
                    node_type,
                    weight,
                    state: HealthStateMachine::default(),
                    last_replay_lsn: 0,
                    last_replication_lag_ms: None,
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
            probes,
            max_replication_lag_ms,
            nodes: Mutex::new(nodes),
            check_timeout,
            cached_snapshot: ArcSwap::new(Arc::new(initial_snapshot)),
        }
    }

    /// Runs a single check against one node: probing plus applying the
    /// timeout rule, returning the raw result of this check. Does not
    /// modify the node's routing availability state (only reports the
    /// result); the state transition is decided by the caller (typically
    /// `run`) according to the "3 consecutive failures/successes" rule.
    pub async fn check_once(&self, node_id: &str) -> Option<HealthCheckResult> {
        let node_type = {
            let nodes = self.nodes.lock().expect("nodes lock poisoned");
            nodes.get(node_id)?.node_type
        };
        let probe = self.probes.get(node_id)?;

        let result = match timeout(self.check_timeout, probe.probe(node_type)).await {
            Ok(result) => result,
            Err(_) => HealthCheckResult {
                timed_out: true,
                ..Default::default()
            },
        };
        Some(result)
    }

    fn apply_result(&self, node_id: &str, result: HealthCheckResult) {
        metrics::counter!(
            "trident_health_checks_total",
            "node_id" => node_id.to_string(),
            "result" => if result.is_success() { "success" } else { "failure" }
        )
        .increment(1);

        let mut nodes = self.nodes.lock().expect("nodes lock poisoned");
        if let Some(node) = nodes.get_mut(node_id) {
            let was_healthy = node.state.healthy();
            node.state.observe(result.is_success());
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
            node.last_replication_lag_ms = result.replication_lag_ms;
        }
    }

    /// Runs a single check and feeds the result into this node's health
    /// state machine, updating its snapshot.
    pub async fn check_and_update(&self, node_id: &str) {
        let Some(result) = self.check_once(node_id).await else {
            return;
        };
        self.apply_result(node_id, result);
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
            let nodes = self.nodes.lock().expect("nodes lock poisoned");
            self.probes
                .iter()
                .filter_map(|(node_id, probe)| {
                    nodes
                        .get(node_id)
                        .map(|node| (node_id.clone(), node.node_type, Arc::clone(probe)))
                })
                .collect()
        };

        let mut tasks = tokio::task::JoinSet::new();
        for (node_id, node_type, probe) in checks {
            let check_timeout = self.check_timeout;
            tasks.spawn(async move {
                let result = match timeout(check_timeout, probe.probe(node_type)).await {
                    Ok(result) => result,
                    Err(_) => HealthCheckResult {
                        timed_out: true,
                        ..Default::default()
                    },
                };
                (node_id, result)
            });
        }

        while let Some(completed) = tasks.join_next().await {
            match completed {
                Ok((node_id, result)) => self.apply_result(&node_id, result),
                Err(error) => {
                    tracing::error!(%error, "backend health-check task failed");
                }
            }
        }
        self.refresh_cached_snapshot();
    }

    /// Rebuilds the cached snapshot from the current node state.
    fn refresh_cached_snapshot(&self) {
        let nodes = self.nodes.lock().expect("nodes lock poisoned");
        let snap: Vec<BackendNodeSnapshot> = nodes
            .iter()
            .map(|(node_id, node)| {
                let excluded_by_lag = node.node_type == NodeType::Reader
                    && is_excluded_by_replication_lag(
                        node.last_replication_lag_ms,
                        self.max_replication_lag_ms,
                    );
                BackendNodeSnapshot {
                    node_id: node_id.clone(),
                    node_type: node.node_type,
                    healthy: node.state.healthy() && !excluded_by_lag,
                    replay_lsn: node.last_replay_lsn,
                    active_connections: 0,
                    weight: node.weight,
                    replication_lag_ms: node.last_replication_lag_ms,
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
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            self.check_all_and_update().await;
        }
    }

    /// Aggregates the current snapshot of all nodes, for use by the
    /// Router/Balancer. Uses the lock-free cached snapshot (updated after
    /// each health-check cycle) to avoid mutex contention on the per-query
    /// hot path.
    pub fn snapshot(&self) -> Vec<BackendNodeSnapshot> {
        (**self.cached_snapshot.load()).clone()
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
        assert_eq!(parse_lsn("0/0"), Some(0));
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
}
