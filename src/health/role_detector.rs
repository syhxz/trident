//! Role detection abstraction for auto-role nodes.
//!
//! This module defines the `RoleDetector` trait and its implementations:
//! - `ProbeRoleDetector`: built-in, uses `pg_is_in_recovery()` from the
//!   health probe results (default, zero-config).
//! - `PatroniRoleDetector`: queries Patroni REST API for authoritative leader.
//! - `RepmgrRoleDetector`: queries repmgr metadata tables via existing connections.
//!
//! The health checker uses the configured detector to determine effective
//! roles for `type: auto` nodes. The probe detector is implicit (no
//! configuration needed); external detectors are activated by the
//! `role_source` config block.

use std::collections::HashMap;
use std::time::Duration;

use crate::config::{NodeType, RoleDetectionMode, RoleSourceConfig, SslMode};

/// Result of a role detection query: maps node_id -> detected effective role.
/// Nodes not present in the map could not be determined (should be treated
/// as fail-closed by the caller).
pub type RoleMap = HashMap<String, NodeType>;

/// Abstraction for determining the effective role of auto-configured nodes.
///
/// Implementations must be Send + Sync for use from the health checker's
/// async context.
#[allow(clippy::type_complexity)]
pub trait RoleDetector: Send + Sync {
    /// Returns the detection mode this detector implements.
    fn mode(&self) -> RoleDetectionMode;

    /// Queries the authority source and returns a mapping of node_id to
    /// its detected role. Returns `Err` if the source is unreachable or
    /// returns inconsistent data (caller should fail-closed).
    fn detect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<RoleMap, RoleDetectionError>> + Send + '_>,
    >;
}

/// Errors from role detection.
#[derive(Debug, thiserror::Error)]
pub enum RoleDetectionError {
    #[error("external role source unreachable: {0}")]
    Unreachable(String),

    #[error("external role source returned no leader")]
    NoLeader,

    #[error("external role source returned inconsistent data: {0}")]
    Inconsistent(String),
}

/// Built-in probe-based role detection. This is a no-op detector because
/// probe mode uses `pg_is_in_recovery()` results directly from health
/// check probes (handled inline in `HealthChecker::apply_result`).
///
/// This struct exists to satisfy the trait interface for uniformity but
/// its `detect()` method should never actually be called in probe mode.
pub struct ProbeRoleDetector;

impl RoleDetector for ProbeRoleDetector {
    fn mode(&self) -> RoleDetectionMode {
        RoleDetectionMode::Probe
    }

    fn detect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<RoleMap, RoleDetectionError>> + Send + '_>,
    > {
        Box::pin(async { Ok(HashMap::new()) })
    }
}

// =========================================================================
// Patroni REST API adapter
// =========================================================================

/// Patroni REST API response for GET /cluster.
#[derive(Debug, serde::Deserialize)]
struct PatroniClusterResponse {
    members: Vec<PatroniMember>,
}

/// A single member in the Patroni cluster response.
#[derive(Debug, serde::Deserialize)]
struct PatroniMember {
    /// Member name (typically the hostname or pod name).
    name: String,
    /// Role as reported by Patroni: "leader", "replica", "sync_standby", etc.
    role: String,
    /// Host address of this member (may include port as "host:port").
    #[serde(default)]
    host: Option<String>,
    /// Port of this member's PostgreSQL instance.
    #[serde(default)]
    port: Option<u16>,
    /// Current state: "running", "stopped", etc.
    #[serde(default)]
    state: Option<String>,
}

/// Patroni REST API-based role detection.
///
/// Queries configured Patroni endpoints (`GET /cluster`) to determine the
/// authoritative cluster leader. Falls back through the endpoint list on
/// failure. The response JSON contains a `members` array; the member with
/// `role: "leader"` (or `"master"`) is the primary.
///
/// Node mapping: maps `(host, port)` from Patroni members to Trident
/// node IDs configured at startup.
pub struct PatroniRoleDetector {
    /// Patroni REST API endpoint URLs (e.g. `http://host:8008`).
    pub endpoints: Vec<String>,
    /// Mapping: "(host:port)" -> Trident node_id.
    /// Built from node configuration at startup.
    pub node_mapping: HashMap<String, String>,
    /// HTTP client (shared, connection-pooled).
    client: reqwest::Client,
}

impl PatroniRoleDetector {
    /// Creates a new PatroniRoleDetector.
    ///
    /// `endpoints`: list of Patroni REST API URLs.
    /// `node_mapping`: maps "host:port" strings to Trident node IDs.
    pub fn new(endpoints: Vec<String>, node_mapping: HashMap<String, String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(2)
            .build()
            .unwrap_or_default();
        PatroniRoleDetector {
            endpoints,
            node_mapping,
            client,
        }
    }

    /// Resolves a Patroni member to a Trident node_id by matching
    /// host:port against the configured node_mapping.
    fn resolve_member(&self, member: &PatroniMember) -> Option<String> {
        // Try host:port from the member response.
        if let (Some(host), Some(port)) = (&member.host, member.port) {
            let key = format!("{}:{}", host, port);
            if let Some(node_id) = self.node_mapping.get(&key) {
                return Some(node_id.clone());
            }
        }
        // Fallback: try matching by member name directly (some setups
        // configure Patroni member names to match Trident node names).
        if self.node_mapping.values().any(|v| v == &member.name) {
            return Some(member.name.clone());
        }
        None
    }
}

impl RoleDetector for PatroniRoleDetector {
    fn mode(&self) -> RoleDetectionMode {
        RoleDetectionMode::Patroni
    }

    fn detect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<RoleMap, RoleDetectionError>> + Send + '_>,
    > {
        Box::pin(async {
            let mut last_error = String::new();

            // Try each endpoint in order; first success wins.
            for endpoint in &self.endpoints {
                let url = format!("{}/cluster", endpoint.trim_end_matches('/'));
                let response = match self.client.get(&url).send().await {
                    Ok(resp) => resp,
                    Err(e) => {
                        last_error = format!("{}: {}", url, e);
                        tracing::debug!(endpoint = %url, error = %e, "Patroni endpoint unreachable, trying next");
                        continue;
                    }
                };

                if !response.status().is_success() {
                    last_error = format!("{}: HTTP {}", url, response.status());
                    tracing::debug!(endpoint = %url, status = %response.status(), "Patroni endpoint returned non-2xx");
                    continue;
                }

                let cluster: PatroniClusterResponse = match response.json().await {
                    Ok(c) => c,
                    Err(e) => {
                        last_error = format!("{}: failed to parse response: {}", url, e);
                        tracing::debug!(endpoint = %url, error = %e, "Failed to parse Patroni cluster response");
                        continue;
                    }
                };

                // Find the leader among members.
                let mut role_map = RoleMap::new();
                let mut found_leader = false;

                for member in &cluster.members {
                    // Skip members not in "running" state if state is reported.
                    if let Some(ref state) = member.state {
                        if state != "running" && state != "streaming" {
                            continue;
                        }
                    }

                    let Some(node_id) = self.resolve_member(member) else {
                        tracing::debug!(
                            member_name = %member.name,
                            member_host = ?member.host,
                            member_port = ?member.port,
                            "Patroni member could not be mapped to a Trident node"
                        );
                        continue;
                    };

                    let is_leader = member.role == "leader"
                        || member.role == "master"
                        || member.role == "primary";

                    if is_leader {
                        role_map.insert(node_id, NodeType::Writer);
                        found_leader = true;
                    } else {
                        role_map.insert(node_id, NodeType::Reader);
                    }
                }

                if !found_leader {
                    tracing::warn!(
                        endpoint = %url,
                        members = cluster.members.len(),
                        "Patroni cluster has no leader among running members"
                    );
                    return Err(RoleDetectionError::NoLeader);
                }

                tracing::debug!(
                    endpoint = %url,
                    mapped_nodes = role_map.len(),
                    "Patroni role detection successful"
                );
                return Ok(role_map);
            }

            // All endpoints failed.
            Err(RoleDetectionError::Unreachable(format!(
                "all Patroni endpoints failed; last error: {}",
                last_error
            )))
        })
    }
}

// =========================================================================
// repmgr metadata adapter
// =========================================================================

/// Connection info for a node used by the repmgr detector to connect and
/// query metadata.
#[derive(Debug, Clone)]
pub struct RepmgrNodeInfo {
    pub node_id: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: Option<String>,
    pub ssl_mode: SslMode,
}

/// repmgr metadata-based role detection.
///
/// Queries the `repmgr.nodes` view combined with `pg_is_in_recovery()`
/// to determine which node is the primary. Uses the Wire Protocol to
/// connect to one of the configured nodes and run the detection query.
///
/// The query strategy:
/// 1. Connect to any accessible auto node.
/// 2. Query `SELECT n.node_name, n.type, n.active, n.conninfo
///          FROM repmgr.nodes n WHERE n.active = true`
/// 3. Cross-reference with `pg_is_in_recovery()` to confirm.
///
/// Since repmgr stores its metadata in a regular PostgreSQL table
/// replicated to all nodes, any node can answer this query.
pub struct RepmgrRoleDetector {
    /// Connection info for each auto node (used to connect and query).
    pub nodes: Vec<RepmgrNodeInfo>,
    /// Mapping from repmgr node_name -> Trident node_id.
    /// Built at startup from config: typically node_name matches the
    /// Trident node name, or is mapped by host:port.
    pub node_mapping: HashMap<String, String>,
}

impl RepmgrRoleDetector {
    /// Creates a new RepmgrRoleDetector.
    pub fn new(nodes: Vec<RepmgrNodeInfo>, node_mapping: HashMap<String, String>) -> Self {
        RepmgrRoleDetector {
            nodes,
            node_mapping,
        }
    }

    /// Connects to one of the configured nodes and runs a detection query.
    /// Returns the raw result rows.
    async fn query_repmgr_nodes(&self) -> Result<Vec<(String, String)>, RoleDetectionError> {
        use tokio::net::TcpStream;

        // We query repmgr.nodes for the list of active cluster members and
        // their declared type. repmgr maintains a 'type' column ('primary'
        // or 'standby') that is updated during failover/switchover events.
        // We also fetch each node's conninfo for host:port mapping.
        //
        // Note: We connect to each node in turn until one succeeds. The
        // node we connect to provides its LOCAL view of the repmgr metadata
        // (replicated to all standbys). This is authoritative enough when
        // combined with the built-in probe's pg_is_in_recovery() as a
        // cross-check.
        let query = "SELECT node_name, type FROM repmgr.nodes WHERE active = true";

        let mut last_error = String::new();

        for node_info in &self.nodes {
            // Try to connect and query this node.
            let tcp_stream = match TcpStream::connect((node_info.host.as_str(), node_info.port)).await {
                Ok(s) => s,
                Err(e) => {
                    last_error = format!("{}:{}: connect failed: {}", node_info.host, node_info.port, e);
                    continue;
                }
            };

            let target = crate::health::checker::ProbeTarget {
                host: node_info.host.clone(),
                port: node_info.port,
                database: node_info.database.clone(),
                username: node_info.username.clone(),
                password: node_info.password.clone(),
                ssl_mode: node_info.ssl_mode,
            };

            let mut stream = match crate::health::checker::upgrade_probe_stream(tcp_stream, &target).await {
                Ok(s) => s,
                Err(_) => {
                    last_error = format!("{}:{}: TLS upgrade failed", node_info.host, node_info.port);
                    continue;
                }
            };

            if crate::health::checker::perform_startup(&mut stream, &target).await.is_err() {
                last_error = format!("{}:{}: startup/auth failed", node_info.host, node_info.port);
                continue;
            }

            // Run the query and collect results.
            match self.run_repmgr_query(&mut stream, query).await {
                Ok(rows) => return Ok(rows),
                Err(e) => {
                    last_error = format!("{}:{}: query failed: {}", node_info.host, node_info.port, e);
                    continue;
                }
            }
        }

        Err(RoleDetectionError::Unreachable(format!(
            "all repmgr nodes unreachable; last error: {}",
            last_error
        )))
    }

    /// Executes the repmgr detection query and returns (node_name, live_role) pairs.
    async fn run_repmgr_query<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>(
        &self,
        stream: &mut S,
        sql: &str,
    ) -> Result<Vec<(String, String)>, String> {
        use tokio::io::AsyncWriteExt;

        let bytes = crate::protocol::writer::encode_query(sql);
        stream.write_all(&bytes).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut rows: Vec<(String, String)> = Vec::new();
        let mut saw_error = false;

        loop {
            match crate::protocol::reader::read_backend_message(stream).await {
                Ok(crate::protocol::message::BackendMessage::DataRow(cols)) => {
                    let node_name = cols
                        .first()
                        .and_then(|c| c.as_ref())
                        .and_then(|b| String::from_utf8(b.clone()).ok())
                        .unwrap_or_default();
                    let live_role = cols
                        .get(1)
                        .and_then(|c| c.as_ref())
                        .and_then(|b| String::from_utf8(b.clone()).ok())
                        .unwrap_or_default();
                    if !node_name.is_empty() {
                        rows.push((node_name, live_role));
                    }
                }
                Ok(crate::protocol::message::BackendMessage::ErrorResponse(_)) => {
                    saw_error = true;
                }
                Ok(crate::protocol::message::BackendMessage::ReadyForQuery(_)) => break,
                Ok(_) => continue,
                Err(_) => return Err("connection lost during query".to_string()),
            }
        }

        if saw_error {
            return Err("repmgr query returned error (repmgr extension may not be installed)".to_string());
        }

        Ok(rows)
    }
}

impl RoleDetector for RepmgrRoleDetector {
    fn mode(&self) -> RoleDetectionMode {
        RoleDetectionMode::Repmgr
    }

    fn detect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<RoleMap, RoleDetectionError>> + Send + '_>,
    > {
        Box::pin(async {
            // Query repmgr.nodes from any accessible node in the cluster.
            // The 'type' column in repmgr.nodes is maintained by repmgr
            // during failover/switchover operations and reflects the
            // authoritative cluster topology.
            let rows = self.query_repmgr_nodes().await?;

            if rows.is_empty() {
                return Err(RoleDetectionError::NoLeader);
            }

            let mut role_map = RoleMap::new();
            let mut found_primary = false;

            for (node_name, node_type) in &rows {
                // Map repmgr node_name to Trident node_id.
                let node_id = self
                    .node_mapping
                    .get(node_name)
                    .cloned()
                    .unwrap_or_else(|| node_name.clone());

                let role = if node_type == "primary" {
                    found_primary = true;
                    NodeType::Writer
                } else {
                    // "standby", "witness", etc. → Reader
                    NodeType::Reader
                };

                role_map.insert(node_id, role);
            }

            if !found_primary {
                // No node with type='primary' found in repmgr metadata.
                // This indicates a failover is in progress or the metadata
                // is stale. Fail-closed.
                tracing::warn!(
                    "repmgr detection: no node with type='primary' found in repmgr.nodes"
                );
                return Err(RoleDetectionError::NoLeader);
            }

            tracing::debug!(
                mapped_nodes = role_map.len(),
                "repmgr role detection successful"
            );
            Ok(role_map)
        })
    }
}

// =========================================================================
// Factory
// =========================================================================

/// Node info tuple for creating role detectors:
/// `(node_id, host, port, database, username, password, ssl_mode)`.
pub type AutoNodeInfo = (String, String, u16, String, String, Option<String>, SslMode);

/// Factory function to create the appropriate role detector based on config.
///
/// For `Patroni` mode, the caller must supply `auto_nodes` so the detector
/// can build a host:port -> node_id mapping. For `Repmgr` mode, the caller
/// supplies node connection info.
pub fn create_role_detector(
    role_source: Option<&RoleSourceConfig>,
    auto_nodes: &[AutoNodeInfo],
) -> Box<dyn RoleDetector> {
    match role_source {
        None => Box::new(ProbeRoleDetector),
        Some(source) => match source.mode() {
            RoleDetectionMode::Probe => Box::new(ProbeRoleDetector),
            RoleDetectionMode::Patroni => {
                let endpoints = source.patroni.clone().unwrap_or_default();
                // Build node_mapping: "host:port" -> node_id
                let mut node_mapping = HashMap::new();
                for (node_id, host, port, _db, _user, _pass, _ssl) in auto_nodes {
                    let key = format!("{}:{}", host, port);
                    node_mapping.insert(key, node_id.clone());
                    // Also map by node_id directly (in case Patroni uses
                    // the same name as our node_id).
                    node_mapping.insert(node_id.clone(), node_id.clone());
                }
                Box::new(PatroniRoleDetector::new(endpoints, node_mapping))
            }
            RoleDetectionMode::Repmgr => {
                let nodes: Vec<RepmgrNodeInfo> = auto_nodes
                    .iter()
                    .map(|(node_id, host, port, db, user, pass, ssl)| RepmgrNodeInfo {
                        node_id: node_id.clone(),
                        host: host.clone(),
                        port: *port,
                        database: db.clone(),
                        username: user.clone(),
                        password: pass.clone(),
                        ssl_mode: *ssl,
                    })
                    .collect();
                // Build node_mapping: node_id -> node_id (identity; repmgr
                // node_name is typically the same as the Trident node name).
                let node_mapping: HashMap<String, String> = auto_nodes
                    .iter()
                    .map(|(node_id, ..)| (node_id.clone(), node_id.clone()))
                    .collect();
                Box::new(RepmgrRoleDetector::new(nodes, node_mapping))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_detector_returns_empty_map() {
        let detector = ProbeRoleDetector;
        assert_eq!(detector.mode(), RoleDetectionMode::Probe);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(detector.detect());
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn patroni_detector_resolves_member_by_host_port() {
        let mut node_mapping = HashMap::new();
        node_mapping.insert("10.0.1.10:5432".to_string(), "node1".to_string());
        node_mapping.insert("10.0.1.11:5432".to_string(), "node2".to_string());

        let detector = PatroniRoleDetector::new(
            vec!["http://localhost:8008".to_string()],
            node_mapping,
        );

        let member = PatroniMember {
            name: "pg-instance-1".to_string(),
            role: "leader".to_string(),
            host: Some("10.0.1.10".to_string()),
            port: Some(5432),
            state: Some("running".to_string()),
        };

        assert_eq!(detector.resolve_member(&member), Some("node1".to_string()));
    }

    #[test]
    fn patroni_detector_resolves_member_by_name_fallback() {
        let mut node_mapping = HashMap::new();
        // Map by name directly (Patroni member name == Trident node_id).
        node_mapping.insert("node1".to_string(), "node1".to_string());

        let detector = PatroniRoleDetector::new(
            vec!["http://localhost:8008".to_string()],
            node_mapping,
        );

        let member = PatroniMember {
            name: "node1".to_string(),
            role: "replica".to_string(),
            host: Some("unknown-host".to_string()),
            port: Some(9999),
            state: Some("running".to_string()),
        };

        assert_eq!(detector.resolve_member(&member), Some("node1".to_string()));
    }

    #[test]
    fn create_role_detector_returns_probe_for_none() {
        let detector = create_role_detector(None, &[]);
        assert_eq!(detector.mode(), RoleDetectionMode::Probe);
    }

    #[test]
    fn create_role_detector_returns_patroni() {
        let source = RoleSourceConfig {
            patroni: Some(vec!["http://host:8008".to_string()]),
            repmgr: None,
        };
        let auto_nodes = vec![(
            "node1".to_string(),
            "10.0.1.10".to_string(),
            5432u16,
            "mydb".to_string(),
            "user".to_string(),
            Some("pass".to_string()),
            SslMode::Disable,
        )];
        let detector = create_role_detector(Some(&source), &auto_nodes);
        assert_eq!(detector.mode(), RoleDetectionMode::Patroni);
    }

    #[test]
    fn create_role_detector_returns_repmgr() {
        let source = RoleSourceConfig {
            patroni: None,
            repmgr: Some(serde_json::Value::Object(Default::default())),
        };
        let auto_nodes = vec![(
            "node1".to_string(),
            "10.0.1.10".to_string(),
            5432u16,
            "mydb".to_string(),
            "user".to_string(),
            Some("pass".to_string()),
            SslMode::Disable,
        )];
        let detector = create_role_detector(Some(&source), &auto_nodes);
        assert_eq!(detector.mode(), RoleDetectionMode::Repmgr);
    }
}
