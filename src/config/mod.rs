//! Configuration module (`config`)
//!
//! Handles parsing and validation of the YAML configuration file, and
//! defines `AppConfig` and its sub-structures.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

mod pgpass;

pub use pgpass::PgPassError;

/// Backend node type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    Writer,
    Reader,
    Analytics,
}

/// Backend SSL/TLS mode for connections from Trident to PostgreSQL nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SslMode {
    /// No SSL negotiation; connect in plaintext only.
    #[default]
    Disable,
    /// Attempt SSL; fall back to plaintext if the server declines (`N`).
    Prefer,
    /// SSL is mandatory; fail if the server declines.
    Require,
}

/// Consistency level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyLevel {
    Eventual,
    Session,
    Global,
}

/// How Trident obtains and propagates the last write LSN for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LsnTrackingMode {
    #[default]
    Auto,
    Pipeline,
    Extension,
    AuroraWriteForwarding,
}

/// LSN tracking settings for Trident's internal query pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PipelineLsnConfig {
    #[serde(default = "default_internal_query_timeout_ms")]
    pub internal_query_timeout_ms: u64,
    #[serde(default = "default_true")]
    pub lazy_fallback: bool,
}

impl Default for PipelineLsnConfig {
    fn default() -> Self {
        Self {
            internal_query_timeout_ms: default_internal_query_timeout_ms(),
            lazy_fallback: true,
        }
    }
}

fn default_internal_query_timeout_ms() -> u64 {
    100
}

fn default_true() -> bool {
    true
}

/// LSN tracking settings for the PostgreSQL extension integration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExtensionLsnConfig {
    #[serde(default = "default_lsn_guc_name")]
    pub guc_name: String,
}

impl Default for ExtensionLsnConfig {
    fn default() -> Self {
        Self {
            guc_name: default_lsn_guc_name(),
        }
    }
}

fn default_lsn_guc_name() -> String {
    "pg_lsn_track.last_commit_lsn".to_string()
}

/// LSN tracking configuration. Every field defaults so existing YAML files
/// that predate LSN tracking continue to deserialize unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct LsnTrackingConfig {
    #[serde(default)]
    pub mode: LsnTrackingMode,
    #[serde(default)]
    pub pipeline: PipelineLsnConfig,
    #[serde(default)]
    pub extension: ExtensionLsnConfig,
}

/// Load balancing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    WeightedRoundRobin,
    LeastConnections,
}

/// Connection pool mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolMode {
    Session,
    Transaction,
}

/// Client-facing authentication mode.
///
/// - `Trust`: no authentication (development/testing only). Any client can
///   connect without credentials.
/// - `Md5`: proxy verifies client credentials against a local auth_file
///   using PostgreSQL MD5 password protocol. The proxy still uses the
///   configured service account when connecting to backends (no credential
///   passthrough). This is the PgBouncer "auth_file" model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    Trust,
    Md5,
    #[serde(rename = "scram-sha-256")]
    ScramSha256,
}

fn default_client_auth() -> ClientAuthMode {
    ClientAuthMode::Trust
}

/// Proxy listener configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub max_clients: usize,
    /// Client authentication mode. Default: "trust" (no auth, dev only).
    /// "md5": proxy verifies client credentials via auth_file, then uses
    /// the configured service account for backend connections.
    #[serde(default = "default_client_auth")]
    pub client_auth: ClientAuthMode,
    /// Path to the auth file (PgBouncer userlist.txt format) when
    /// client_auth is "md5". Each line: "username" "password_or_md5hash".
    /// Ignored when client_auth is "trust".
    #[serde(default)]
    pub auth_file: Option<String>,
    /// Maximum time to wait for a client to complete the startup/auth
    /// handshake (including TLS negotiation). Prevents slow/stuck clients
    /// from occupying a connection slot indefinitely. Default: "30s".
    #[serde(default = "default_startup_timeout")]
    pub startup_timeout: String,
    /// Maximum time a fully-authenticated client connection can remain
    /// idle (no messages received) before being forcibly closed.
    /// Default: "0" (disabled — application connection pools routinely
    /// hold idle connections for minutes/hours, which is normal).
    #[serde(default = "default_client_idle_timeout")]
    pub client_idle_timeout: String,
    /// Timeout for establishing a TCP connection to the backend when
    /// forwarding a CancelRequest. CancelRequest uses a fresh connection
    /// per the protocol spec; this bounds how long that connect() call
    /// can block. Default: "5s".
    #[serde(default = "default_cancel_connect_timeout")]
    pub cancel_connect_timeout: String,
    /// Path to the TLS certificate file (PEM format) for client-facing
    /// encryption. When both `tls_cert` and `tls_key` are set, the proxy
    /// accepts SSLRequest from clients and upgrades to TLS. When unset,
    /// SSLRequest is rejected with `N` (plaintext only).
    #[serde(default)]
    pub tls_cert: Option<String>,
    /// Path to the TLS private key file (PEM format) for client-facing
    /// encryption. Must be set together with `tls_cert`.
    #[serde(default)]
    pub tls_key: Option<String>,
}

fn default_startup_timeout() -> String {
    "30s".to_string()
}

fn default_client_idle_timeout() -> String {
    "0".to_string()
}

fn default_cancel_connect_timeout() -> String {
    "5s".to_string()
}

/// Backend node configuration
///
/// `password` is optional and supports two ways to avoid storing a secret
/// in plaintext directly in this file:
/// - `${ENV_VAR}` placeholder syntax: resolved against the process
///   environment by `AppConfig::load_from_file` before validation runs.
/// - Omitted entirely: resolved from a `.pgpass`-format file (see
///   `config::pgpass`) by host/port/database/username, following the same
///   `PGPASSFILE` env var / `~/.pgpass` lookup order libpq uses.
///
/// If neither resolves to a value, `AppConfig::load_from_file` fails with
/// `ConfigError::MissingPassword` rather than silently proceeding with an
/// empty password.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct NodeConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(rename = "type")]
    pub node_type: NodeType,
    pub weight: u32,
    pub database: String,
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
    /// Backend SSL mode. Supported values:
    /// - `disable` (default): plaintext only, no SSL negotiation.
    /// - `prefer`: attempt SSL; fall back to plaintext if the server
    ///   declines.
    /// - `require`: SSL is mandatory; fail if the server declines.
    #[serde(default)]
    pub ssl_mode: SslMode,
}

/// Routing-related configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RoutingConfig {
    pub default_consistency: ConsistencyLevel,
    pub load_balance_strategy: LoadBalanceStrategy,
    pub enable_transaction_split: bool,
    pub split_respects_consistency: bool,
    pub enable_hint_routing: bool,
    pub enable_cost_routing: bool,
    pub cost_threshold: f64,
    #[serde(default)]
    pub analytics_patterns: Vec<String>,
    pub writer_readable: bool,
    pub max_replication_lag_ms: u64,
    /// Custom per-table/per-function routing overrides (see
    /// `router::custom_rules`). Empty by default -- omitted from a config
    /// file entirely, routing behaves exactly as before this feature
    /// existed. See `router::custom_rules::CustomRuleEntry` for the field
    /// meanings (`_name`/`_type`/`rw_mode`).
    #[serde(default)]
    pub custom_rules: Vec<crate::router::custom_rules::CustomRuleEntry>,
}

/// Connection pool configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PoolConfig {
    pub mode: PoolMode,
    pub max_pool_size: u32,
    pub min_pool_size: u32,
    pub max_idle_time: String,
    pub connection_timeout: String,
    pub max_lifetime: String,
}

/// Health check configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct HealthConfig {
    pub check_interval: String,
    pub check_timeout: String,
    pub max_retries: u32,
}

/// How the file logger decides when to start a new file. See
/// `trident::logging` for the concrete rotation/retention behavior of
/// each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogRotation {
    /// Roll over once per day at local midnight. Files are named
    /// `{file_prefix}.YYYY-MM-DD`. Simple and predictable by calendar
    /// date, but an unusually chatty day produces one correspondingly
    /// large file -- there is no per-file size cap with this option.
    Daily,
    /// Roll over once per hour. Files are named
    /// `{file_prefix}.YYYY-MM-DD-HH`.
    Hourly,
    /// Roll over whenever the current file reaches `max_file_size_mb`.
    /// Files are named `{file_prefix}.1`, `{file_prefix}.2`, etc. (not by
    /// date). Use this if you need a hard cap on individual file size
    /// regardless of how much log volume a given day produces.
    SizeBased,
}

/// Logging configuration
///
/// `dir` controls where logs go:
/// - `None` (or omitted from the config file, the default): logs go to
///   stdout only, exactly as before this field existed -- no behavior
///   change for existing configs.
/// - `Some(path)`: logs are additionally written to a rolling file under
///   `path` (see `trident::logging`), using the `rotation` strategy.
///   `max_files` is passed directly to logroller. With Trident's
///   uncompressed logs, daily/hourly count the current date-stamped file in
///   that limit; size-based rotation keeps that many numbered archives plus
///   one separate active file. Older files are deleted automatically, and
///   pruning happens continuously (checked on every rotation, not just once
///   at process startup).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    #[serde(alias = "query_log")]
    pub query_trace: bool,
    pub slow_query: u64,
    #[serde(default)]
    pub dir: Option<String>,
    #[serde(default = "default_log_file_prefix")]
    pub file_prefix: String,
    #[serde(default = "default_log_max_files")]
    pub max_files: usize,
    #[serde(default = "default_log_rotation")]
    pub rotation: LogRotation,
    /// Only consulted when `rotation: size_based`. A single log file is
    /// rotated once it reaches this size.
    #[serde(default = "default_log_max_file_size_mb")]
    pub max_file_size_mb: u64,
}

fn default_log_file_prefix() -> String {
    "trident.log".to_string()
}

fn default_log_max_files() -> usize {
    14
}

fn default_log_rotation() -> LogRotation {
    LogRotation::Daily
}

fn default_log_max_file_size_mb() -> u64 {
    100
}

/// Admin/observability HTTP server configuration (`/metrics`, `/healthz`).
/// See `trident::admin` module docs -- this endpoint is unauthenticated,
/// so `listen_addr` should be bound to a private/internal address only.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AdminConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_listen_addr")]
    pub listen_addr: String,
    /// Optional Bearer token for admin API authentication. If set, all
    /// requests (except GET /metrics and GET /healthz) must include an
    /// `Authorization: Bearer <token>` header. Supports `${ENV_VAR}`
    /// placeholders (same as node passwords).
    #[serde(default)]
    pub auth_token: Option<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        AdminConfig {
            enabled: false,
            listen_addr: default_admin_listen_addr(),
            auth_token: None,
        }
    }
}

fn default_admin_listen_addr() -> String {
    "127.0.0.1:9090".to_string()
}

/// Top-level application configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AppConfig {
    pub proxy: ProxyConfig,
    pub nodes: Vec<NodeConfig>,
    pub routing: RoutingConfig,
    pub pool: PoolConfig,
    pub health: HealthConfig,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub lsn_tracking: LsnTrackingConfig,
}

/// Configuration loading/validation error
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse YAML config: {0}")]
    Parse(#[from] serde_yaml::Error),

    #[error("no writer node found: at least one node with type 'writer' is required")]
    MissingWriterNode,

    #[error("duplicate node name found: '{0}'")]
    DuplicateNodeName(String),

    #[error("invalid analytics pattern '{pattern}': {reason}")]
    InvalidAnalyticsPattern { pattern: String, reason: String },

    #[error(
        "invalid pool size configuration: max_pool_size ({max}) must be >= min_pool_size ({min})"
    )]
    InvalidPoolSize { max: u32, min: u32 },

    #[error("invalid listen_addr '{0}': expected 'host:port' format")]
    InvalidListenAddr(String),

    #[error("failed to resolve password placeholder for node '{node}': {source}")]
    PasswordSubstitution {
        node: String,
        #[source]
        source: PgPassError,
    },

    #[error(
        "node '{node}' has no password configured: set 'password' directly (plaintext or \
         ${{ENV_VAR}} placeholder), or omit it and add a matching entry to a .pgpass file \
         (see PGPASSFILE / ~/.pgpass)"
    )]
    MissingPassword { node: String },

    #[error("invalid custom routing rule: {0}")]
    InvalidCustomRule(String),

    #[error(
        "invalid LSN tracking pipeline timeout: internal_query_timeout_ms must be greater than 0"
    )]
    InvalidLsnPipelineTimeout,

    #[error("invalid LSN tracking extension configuration: guc_name must not be empty")]
    InvalidLsnExtensionGucName,

    #[error("Aurora write forwarding LSN tracking requires pool.mode to be 'session'")]
    AuroraWriteForwardingRequiresSessionPool,

    #[error("Aurora write forwarding LSN tracking requires at least one node with type 'reader'")]
    AuroraWriteForwardingRequiresReader,

    #[error("configuration validation error: {0}")]
    Validation(String),
}

impl AppConfig {
    /// Validates the configuration; see the "Validation rules" section in
    /// design.md.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // At least one Writer node must be present.
        if !self.nodes.iter().any(|n| n.node_type == NodeType::Writer) {
            return Err(ConfigError::MissingWriterNode);
        }

        // Node names must be unique.
        let mut seen = std::collections::HashSet::new();
        for node in &self.nodes {
            if !seen.insert(node.name.as_str()) {
                return Err(ConfigError::DuplicateNodeName(node.name.clone()));
            }
        }

        // All analytics_patterns must be valid regular expressions.
        for pattern in &self.routing.analytics_patterns {
            if let Err(e) = regex::Regex::new(pattern) {
                return Err(ConfigError::InvalidAnalyticsPattern {
                    pattern: pattern.clone(),
                    reason: e.to_string(),
                });
            }
        }

        // Custom routing rules must reference a non-empty name.
        for rule in &self.routing.custom_rules {
            if rule.name.trim().is_empty() {
                return Err(ConfigError::InvalidCustomRule(
                    "custom_rules entry has an empty '_name'".to_string(),
                ));
            }
        }

        // LSN tracking sub-configurations are validated even when their mode
        // is selected automatically, so a later restart cannot activate an
        // invalid fallback configuration.
        if self.lsn_tracking.pipeline.internal_query_timeout_ms == 0 {
            return Err(ConfigError::InvalidLsnPipelineTimeout);
        }
        if self.lsn_tracking.extension.guc_name.trim().is_empty() {
            return Err(ConfigError::InvalidLsnExtensionGucName);
        }

        // Explicit Aurora write forwarding relies on backend session state
        // and needs a Reader target. Auto mode does not assert these
        // requirements because it cannot confirm Aurora solely from a GUC.
        if self.lsn_tracking.mode == LsnTrackingMode::AuroraWriteForwarding {
            if self.pool.mode != PoolMode::Session {
                return Err(ConfigError::AuroraWriteForwardingRequiresSessionPool);
            }
            if !self.nodes.iter().any(|n| n.node_type == NodeType::Reader) {
                return Err(ConfigError::AuroraWriteForwardingRequiresReader);
            }
        }

        // max_pool_size must be >= min_pool_size.
        if self.pool.max_pool_size < self.pool.min_pool_size {
            return Err(ConfigError::InvalidPoolSize {
                max: self.pool.max_pool_size,
                min: self.pool.min_pool_size,
            });
        }

        // Reject zero values that would cause failures or tight loops.
        if self.pool.max_pool_size == 0 {
            return Err(ConfigError::Validation(
                "pool.max_pool_size must be > 0".to_string(),
            ));
        }
        if self.proxy.max_clients == 0 {
            return Err(ConfigError::Validation(
                "proxy.max_clients must be > 0".to_string(),
            ));
        }

        // Validate cost_threshold is non-negative and finite.
        if self.routing.cost_threshold < 0.0 || !self.routing.cost_threshold.is_finite() {
            return Err(ConfigError::Validation(
                "routing.cost_threshold must be non-negative and finite".to_string(),
            ));
        }

        // listen_addr must be a valid host:port.
        if !is_valid_host_port(&self.proxy.listen_addr) {
            return Err(ConfigError::InvalidListenAddr(
                self.proxy.listen_addr.clone(),
            ));
        }

        Ok(())
    }

    /// Loads and parses YAML from a file path into an `AppConfig`,
    /// resolves each node's password (see `NodeConfig::password` and the
    /// `config::pgpass` module) and running validation immediately after.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<AppConfig, ConfigError> {
        let path_ref = path.as_ref();
        let contents = fs::read_to_string(path_ref).map_err(|source| ConfigError::Io {
            path: path_ref.display().to_string(),
            source,
        })?;
        let mut config: AppConfig = serde_yaml::from_str(&contents)?;
        config.resolve_passwords()?;
        config.validate()?;
        Ok(config)
    }

    /// Resolves each node's effective password in place:
    /// - if `password` is set and contains `${ENV_VAR}` placeholders,
    ///   substitutes them from the process environment;
    /// - if `password` is unset, looks it up from a `.pgpass`-format file
    ///   keyed by `(host, port, database, username)`;
    /// - fails with `ConfigError::MissingPassword` if neither resolves to
    ///   a value (an empty-string password is never silently assumed).
    fn resolve_passwords(&mut self) -> Result<(), ConfigError> {
        for node in &mut self.nodes {
            let resolved = match &node.password {
                Some(raw) => Some(pgpass::substitute_env_placeholders(raw).map_err(|source| {
                    ConfigError::PasswordSubstitution {
                        node: node.name.clone(),
                        source,
                    }
                })?),
                None => pgpass::resolve_password_from_pgpass(
                    &node.host,
                    node.port,
                    &node.database,
                    &node.username,
                )
                .map_err(|source| ConfigError::PasswordSubstitution {
                    node: node.name.clone(),
                    source,
                })?,
            };

            node.password = Some(resolved.ok_or_else(|| ConfigError::MissingPassword {
                node: node.name.clone(),
            })?);
        }
        Ok(())
    }
}

/// Checks whether a string conforms to the `host:port` format:
/// - must contain at least one `:` separator
/// - the host part must be non-empty
/// - the port part must be a valid `u16` value
fn is_valid_host_port(addr: &str) -> bool {
    match addr.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ---------------------------------------------------------------------
    // Test helper: builds a valid baseline configuration that individual
    // test cases can mutate fields on top of.
    // ---------------------------------------------------------------------

    fn sample_node(name: &str, node_type: NodeType) -> NodeConfig {
        NodeConfig {
            name: name.to_string(),
            host: "127.0.0.1".to_string(),
            port: 5432,
            node_type,
            weight: 1,
            database: "mydb".to_string(),
            username: "proxy_user".to_string(),
            password: Some("secret".to_string()),
            ssl_mode: SslMode::default(),
        }
    }

    fn valid_config() -> AppConfig {
        AppConfig {
            proxy: ProxyConfig {
                listen_addr: "0.0.0.0:6432".to_string(),
                max_clients: 2000,
                client_auth: ClientAuthMode::Trust,
                auth_file: None,
                startup_timeout: "30s".to_string(),
                client_idle_timeout: "0".to_string(),
                cancel_connect_timeout: "5s".to_string(),
                tls_cert: None,
                tls_key: None,
            },
            nodes: vec![
                sample_node("primary", NodeType::Writer),
                sample_node("reader-1", NodeType::Reader),
            ],
            routing: RoutingConfig {
                default_consistency: ConsistencyLevel::Session,
                load_balance_strategy: LoadBalanceStrategy::WeightedRoundRobin,
                enable_transaction_split: true,
                split_respects_consistency: true,
                enable_hint_routing: true,
                enable_cost_routing: true,
                cost_threshold: 50000.0,
                analytics_patterns: vec!["SELECT.*FROM\\s+fact_.*".to_string()],
                writer_readable: true,
                max_replication_lag_ms: 1000,
                custom_rules: Vec::new(),
            },
            pool: PoolConfig {
                mode: PoolMode::Transaction,
                max_pool_size: 50,
                min_pool_size: 5,
                max_idle_time: "5m".to_string(),
                connection_timeout: "5s".to_string(),
                max_lifetime: "30m".to_string(),
            },
            health: HealthConfig {
                check_interval: "3s".to_string(),
                check_timeout: "2s".to_string(),
                max_retries: 3,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                query_trace: false,
                slow_query: 1000,
                dir: None,
                file_prefix: "trident.log".to_string(),
                max_files: 14,
                rotation: LogRotation::Daily,
                max_file_size_mb: 100,
            },
            admin: AdminConfig::default(),
            lsn_tracking: LsnTrackingConfig::default(),
        }
    }

    // ---------------------------------------------------------------------
    // Property 43: config file serialize/deserialize round trip is consistent
    // Validates: Requirements 12.1
    // ---------------------------------------------------------------------

    fn node_type_strategy() -> impl Strategy<Value = NodeType> {
        prop_oneof![
            Just(NodeType::Writer),
            Just(NodeType::Reader),
            Just(NodeType::Analytics),
        ]
    }

    fn consistency_strategy() -> impl Strategy<Value = ConsistencyLevel> {
        prop_oneof![
            Just(ConsistencyLevel::Eventual),
            Just(ConsistencyLevel::Session),
            Just(ConsistencyLevel::Global),
        ]
    }

    fn lb_strategy_strategy() -> impl Strategy<Value = LoadBalanceStrategy> {
        prop_oneof![
            Just(LoadBalanceStrategy::WeightedRoundRobin),
            Just(LoadBalanceStrategy::LeastConnections),
        ]
    }

    fn pool_mode_strategy() -> impl Strategy<Value = PoolMode> {
        prop_oneof![Just(PoolMode::Session), Just(PoolMode::Transaction)]
    }

    // Generates an arbitrary but structurally valid AppConfig instance
    // (field values are arbitrary, but the overall structure is legal).
    fn app_config_strategy() -> impl Strategy<Value = AppConfig> {
        (
            "[a-z][a-z0-9_]{0,15}",
            1u16..65535,
            node_type_strategy(),
            1u32..100,
            consistency_strategy(),
            lb_strategy_strategy(),
            any::<bool>(),
            any::<bool>(),
            0f64..1_000_000.0,
            pool_mode_strategy(),
            5u32..200,
            0u32..5,
        )
            .prop_map(
                |(
                    node_name,
                    port,
                    node_type,
                    weight,
                    consistency,
                    lb_strategy,
                    enable_split,
                    enable_cost,
                    cost_threshold,
                    pool_mode,
                    max_pool,
                    min_pool,
                )| {
                    let mut cfg = valid_config();
                    cfg.nodes = vec![
                        sample_node("writer-base", NodeType::Writer),
                        NodeConfig {
                            name: node_name,
                            host: "10.0.0.1".to_string(),
                            port,
                            node_type,
                            weight,
                            database: "db".to_string(),
                            username: "user".to_string(),
                            password: Some("pw".to_string()),
                            ssl_mode: SslMode::default(),
                        },
                    ];
                    cfg.routing.default_consistency = consistency;
                    cfg.routing.load_balance_strategy = lb_strategy;
                    cfg.routing.enable_transaction_split = enable_split;
                    cfg.routing.enable_cost_routing = enable_cost;
                    cfg.routing.cost_threshold = cost_threshold;
                    cfg.pool.mode = pool_mode;
                    cfg.pool.max_pool_size = max_pool;
                    cfg.pool.min_pool_size = min_pool.min(max_pool);
                    cfg
                },
            )
    }

    proptest! {
        #[test]
        fn property_43_serde_roundtrip(cfg in app_config_strategy()) {
            let yaml = serde_yaml::to_string(&cfg).expect("serialize should succeed");
            let round_tripped: AppConfig =
                serde_yaml::from_str(&yaml).expect("deserialize should succeed");
            prop_assert_eq!(cfg, round_tripped);
        }

        // -----------------------------------------------------------------
        // Property 44: a config missing a Writer node must be rejected
        // Validates: Requirements 12.2
        // -----------------------------------------------------------------
        #[test]
        fn property_44_missing_writer_rejected(
            node_types in prop::collection::vec(
                prop_oneof![Just(NodeType::Reader), Just(NodeType::Analytics)],
                1..5,
            )
        ) {
            let mut cfg = valid_config();
            cfg.nodes = node_types
                .into_iter()
                .enumerate()
                .map(|(i, nt)| sample_node(&format!("node-{i}"), nt))
                .collect();
            prop_assert!(matches!(cfg.validate(), Err(ConfigError::MissingWriterNode)));
        }

        // -----------------------------------------------------------------
        // Property 45: a config with duplicate node names must be rejected
        // Validates: Requirements 12.3
        // -----------------------------------------------------------------
        #[test]
        fn property_45_duplicate_node_name_rejected(dup_name in "[a-z][a-z0-9_]{0,10}") {
            let mut cfg = valid_config();
            cfg.nodes = vec![
                sample_node(&dup_name, NodeType::Writer),
                sample_node(&dup_name, NodeType::Reader),
            ];
            prop_assert!(matches!(
                cfg.validate(),
                Err(ConfigError::DuplicateNodeName(_))
            ));
        }

        // -----------------------------------------------------------------
        // Property 46: a config containing an invalid regex pattern must
        // be rejected
        // Validates: Requirements 12.4
        // -----------------------------------------------------------------
        #[test]
        fn property_46_invalid_regex_pattern_rejected(bad_pattern in "\\(\\(\\(unclosed") {
            let mut cfg = valid_config();
            cfg.routing.analytics_patterns = vec![bad_pattern];
            let is_invalid_pattern_err =
                matches!(cfg.validate(), Err(ConfigError::InvalidAnalyticsPattern { .. }));
            prop_assert!(is_invalid_pattern_err);
        }

        // -----------------------------------------------------------------
        // Property 47: a contradictory pool size configuration must be
        // rejected
        // Validates: Requirements 12.5
        // -----------------------------------------------------------------
        #[test]
        fn property_47_pool_size_contradiction(max in 0u32..200, min in 0u32..200) {
            let mut cfg = valid_config();
            cfg.pool.max_pool_size = max;
            cfg.pool.min_pool_size = min;
            let result = cfg.validate();
            if max < min {
                let is_invalid_pool_size_err =
                    matches!(result, Err(ConfigError::InvalidPoolSize { .. }));
                prop_assert!(is_invalid_pool_size_err);
            } else {
                prop_assert!(result.is_ok());
            }
        }

        // -----------------------------------------------------------------
        // Property 48: an invalid listen address format must be rejected
        // Validates: Requirements 12.6
        // -----------------------------------------------------------------
        #[test]
        fn property_48_invalid_listen_addr_rejected(host in "[a-z0-9.]{1,20}", port in 0u32..70000) {
            let mut cfg = valid_config();
            cfg.proxy.listen_addr = format!("{host}:{port}");
            let result = cfg.validate();
            if port <= u16::MAX as u32 {
                prop_assert!(result.is_ok());
            } else {
                prop_assert!(matches!(result, Err(ConfigError::InvalidListenAddr(_))));
            }
        }

        #[test]
        fn property_48_missing_colon_rejected(addr in "[a-z0-9]{1,20}") {
            let mut cfg = valid_config();
            cfg.proxy.listen_addr = addr;
            prop_assert!(matches!(
                cfg.validate(),
                Err(ConfigError::InvalidListenAddr(_))
            ));
        }
    }

    // ---------------------------------------------------------------------
    // 2.3 Config module unit tests
    // Validates: Requirements 12.1
    // ---------------------------------------------------------------------

    #[test]
    fn loads_example_config_yaml_successfully() {
        // Use the repository root's example config.yaml to verify the
        // successful-load scenario. The example now sources each node's
        // password from a "${ENV_VAR}" placeholder (see NodeConfig's
        // docs), so this test provides those env vars itself.
        for var in [
            "TRIDENT_PRIMARY_PASSWORD",
            "TRIDENT_READER1_PASSWORD",
            "TRIDENT_READER2_PASSWORD",
            "TRIDENT_ANALYTICS1_PASSWORD",
        ] {
            std::env::set_var(var, "test-password");
        }

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(manifest_dir).join("config.yaml");
        let config = AppConfig::load_from_file(&path).expect("example config should load");

        for var in [
            "TRIDENT_PRIMARY_PASSWORD",
            "TRIDENT_READER1_PASSWORD",
            "TRIDENT_READER2_PASSWORD",
            "TRIDENT_ANALYTICS1_PASSWORD",
        ] {
            std::env::remove_var(var);
        }

        assert_eq!(config.proxy.listen_addr, "0.0.0.0:6432");
        assert!(config.nodes.iter().any(|n| n.node_type == NodeType::Writer));
        assert_eq!(config.pool.mode, PoolMode::Transaction);
        assert_eq!(config.nodes[0].password, Some("test-password".to_string()));
    }

    #[test]
    fn load_from_file_missing_file_returns_io_error() {
        let result = AppConfig::load_from_file("/nonexistent/path/does-not-exist.yaml");
        assert!(matches!(result, Err(ConfigError::Io { .. })));
    }

    #[test]
    fn load_from_file_invalid_yaml_syntax_returns_parse_error() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "trident-invalid-config-{}.yaml",
            std::process::id()
        ));
        fs::write(&path, "proxy: [unclosed").unwrap();

        let result = AppConfig::load_from_file(&path);
        let _ = fs::remove_file(&path);

        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn valid_config_passes_validation() {
        assert!(valid_config().validate().is_ok());
    }

    #[test]
    fn lsn_tracking_defaults_are_backward_compatible() {
        let yaml = minimal_yaml(
            "    password: plain-secret\n",
            "127.0.0.1",
            5432,
            "mydb",
            "proxy_user",
        );
        let parsed: AppConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(parsed.lsn_tracking.mode, LsnTrackingMode::Auto);
        assert_eq!(
            parsed.lsn_tracking.pipeline,
            PipelineLsnConfig {
                internal_query_timeout_ms: 100,
                lazy_fallback: true,
            }
        );
        assert_eq!(
            parsed.lsn_tracking.extension.guc_name,
            "pg_lsn_track.last_commit_lsn"
        );
    }

    #[test]
    fn lsn_tracking_modes_use_snake_case_yaml_names() {
        for (yaml_name, expected) in [
            ("auto", LsnTrackingMode::Auto),
            ("pipeline", LsnTrackingMode::Pipeline),
            ("extension", LsnTrackingMode::Extension),
            (
                "aurora_write_forwarding",
                LsnTrackingMode::AuroraWriteForwarding,
            ),
        ] {
            let parsed: LsnTrackingMode = serde_yaml::from_str(yaml_name).unwrap();
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn invalid_lsn_tracking_subconfigs_are_rejected() {
        let mut cfg = valid_config();
        cfg.lsn_tracking.pipeline.internal_query_timeout_ms = 0;
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidLsnPipelineTimeout)
        ));

        cfg.lsn_tracking.pipeline.internal_query_timeout_ms = 100;
        cfg.lsn_tracking.extension.guc_name = "  ".to_string();
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidLsnExtensionGucName)
        ));
    }

    #[test]
    fn explicit_aurora_write_forwarding_requires_session_pool_and_reader() {
        let mut cfg = valid_config();
        cfg.lsn_tracking.mode = LsnTrackingMode::AuroraWriteForwarding;
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::AuroraWriteForwardingRequiresSessionPool)
        ));

        cfg.pool.mode = PoolMode::Session;
        cfg.nodes.retain(|node| node.node_type != NodeType::Reader);
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::AuroraWriteForwardingRequiresReader)
        ));

        cfg.nodes.push(sample_node("reader-1", NodeType::Reader));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn missing_writer_rule_precedes_explicit_aurora_validation() {
        let mut cfg = valid_config();
        cfg.lsn_tracking.mode = LsnTrackingMode::AuroraWriteForwarding;
        cfg.pool.mode = PoolMode::Session;
        cfg.nodes.retain(|node| node.node_type == NodeType::Reader);
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::MissingWriterNode)
        ));
    }

    #[test]
    fn is_valid_host_port_accepts_common_formats() {
        assert!(is_valid_host_port("0.0.0.0:6432"));
        assert!(is_valid_host_port("localhost:5432"));
        assert!(is_valid_host_port("::1:5432"));
    }

    #[test]
    fn is_valid_host_port_rejects_malformed_input() {
        assert!(!is_valid_host_port("no-port-here"));
        assert!(!is_valid_host_port(":5432")); // empty host
        assert!(!is_valid_host_port("host:not-a-port"));
        assert!(!is_valid_host_port("host:99999")); // out of u16 range
    }

    // ---------------------------------------------------------------------
    // custom_rules
    // ---------------------------------------------------------------------

    #[test]
    fn custom_rules_defaults_to_empty_when_omitted_from_yaml() {
        let yaml = minimal_yaml(
            "    password: plain-secret\n",
            "127.0.0.1",
            5432,
            "mydb",
            "proxy_user",
        );
        let path = write_temp_yaml(&yaml, "customrules-omitted");
        let config = AppConfig::load_from_file(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert!(config.routing.custom_rules.is_empty());
    }

    #[test]
    fn custom_rules_parses_from_yaml() {
        use crate::router::custom_rules::{RuleTargetKind, RwMode};

        let mut cfg = valid_config();
        cfg.routing.custom_rules = vec![
            crate::router::custom_rules::CustomRuleEntry {
                name: "sensitive_table".to_string(),
                rule_type: RuleTargetKind::Table,
                rw_mode: RwMode::Writer,
            },
            crate::router::custom_rules::CustomRuleEntry {
                name: "my_func".to_string(),
                rule_type: RuleTargetKind::Function,
                rw_mode: RwMode::Reader,
            },
        ];

        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let round_tripped: AppConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(round_tripped.routing.custom_rules, cfg.routing.custom_rules);
    }

    #[test]
    fn custom_rule_with_empty_name_is_rejected() {
        use crate::router::custom_rules::{RuleTargetKind, RwMode};

        let mut cfg = valid_config();
        cfg.routing.custom_rules = vec![crate::router::custom_rules::CustomRuleEntry {
            name: "".to_string(),
            rule_type: RuleTargetKind::Table,
            rw_mode: RwMode::Writer,
        }];
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidCustomRule(_))
        ));
    }

    // ---------------------------------------------------------------------
    // Password resolution: plaintext / ${ENV_VAR} / .pgpass / missing
    // ---------------------------------------------------------------------

    /// Minimal single-node YAML config, with a `{password_line}` template
    /// slot so individual tests can plug in a password field (or omit it
    /// entirely) without repeating the whole document.
    fn minimal_yaml(
        password_line: &str,
        host: &str,
        port: u16,
        database: &str,
        username: &str,
    ) -> String {
        format!(
            "proxy:\n  listen_addr: \"0.0.0.0:6432\"\n  max_clients: 10\n\
             nodes:\n  - name: primary\n    host: {host}\n    port: {port}\n    type: writer\n    weight: 1\n    database: {database}\n    username: {username}\n{password_line}\
             routing:\n  default_consistency: session\n  load_balance_strategy: weighted_round_robin\n  enable_transaction_split: true\n  split_respects_consistency: true\n  enable_hint_routing: true\n  enable_cost_routing: false\n  cost_threshold: 1000.0\n  analytics_patterns: []\n  writer_readable: true\n  max_replication_lag_ms: 1000\n\
             pool:\n  mode: transaction\n  max_pool_size: 10\n  min_pool_size: 1\n  max_idle_time: 5m\n  connection_timeout: 5s\n  max_lifetime: 30m\n\
             health:\n  check_interval: 3s\n  check_timeout: 2s\n  max_retries: 3\n\
             logging:\n  level: info\n  query_trace: false\n  slow_query: 1000\n"
        )
    }

    fn write_temp_yaml(contents: &str, suffix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "trident-test-config-{}-{}.yaml",
            std::process::id(),
            suffix
        ));
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn load_from_file_resolves_plaintext_password_unchanged() {
        let yaml = minimal_yaml(
            "    password: plain-secret\n",
            "127.0.0.1",
            5432,
            "mydb",
            "proxy_user",
        );
        let path = write_temp_yaml(&yaml, "plaintext");

        let config = AppConfig::load_from_file(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(config.nodes[0].password, Some("plain-secret".to_string()));
    }

    #[test]
    fn load_from_file_substitutes_env_var_placeholder_in_password() {
        std::env::set_var("TRIDENT_TEST_CFG_PW", "env-secret");
        let yaml = minimal_yaml(
            "    password: \"${TRIDENT_TEST_CFG_PW}\"\n",
            "127.0.0.1",
            5432,
            "mydb",
            "proxy_user",
        );
        let path = write_temp_yaml(&yaml, "envvar");

        let config = AppConfig::load_from_file(&path).unwrap();
        std::env::remove_var("TRIDENT_TEST_CFG_PW");
        let _ = fs::remove_file(&path);

        assert_eq!(config.nodes[0].password, Some("env-secret".to_string()));
    }

    #[test]
    fn load_from_file_falls_back_to_pgpass_when_password_omitted() {
        let pgpass_path = write_temp_yaml(
            "127.0.0.1:5432:mydb:proxy_user:pgpass-secret\n",
            "pgpassfile",
        );
        std::env::set_var("PGPASSFILE", &pgpass_path);

        let yaml = minimal_yaml("", "127.0.0.1", 5432, "mydb", "proxy_user");
        let path = write_temp_yaml(&yaml, "nopassword");

        let config = AppConfig::load_from_file(&path).unwrap();
        std::env::remove_var("PGPASSFILE");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&pgpass_path);

        assert_eq!(config.nodes[0].password, Some("pgpass-secret".to_string()));
    }

    #[test]
    fn load_from_file_fails_when_no_password_source_resolves() {
        let missing_pgpass = std::env::temp_dir().join(format!(
            "trident-test-missing-pgpass-{}.conf",
            std::process::id()
        ));
        let _ = fs::remove_file(&missing_pgpass);
        std::env::set_var("PGPASSFILE", &missing_pgpass);

        let yaml = minimal_yaml("", "127.0.0.1", 5432, "mydb", "proxy_user");
        let path = write_temp_yaml(&yaml, "missingpw");

        let result = AppConfig::load_from_file(&path);
        std::env::remove_var("PGPASSFILE");
        let _ = fs::remove_file(&path);

        assert!(matches!(result, Err(ConfigError::MissingPassword { .. })));
    }

    #[test]
    fn load_from_file_fails_when_referenced_env_var_is_unset() {
        std::env::remove_var("TRIDENT_TEST_CFG_PW_UNSET");
        let yaml = minimal_yaml(
            "    password: \"${TRIDENT_TEST_CFG_PW_UNSET}\"\n",
            "127.0.0.1",
            5432,
            "mydb",
            "proxy_user",
        );
        let path = write_temp_yaml(&yaml, "envunset");

        let result = AppConfig::load_from_file(&path);
        let _ = fs::remove_file(&path);

        assert!(matches!(
            result,
            Err(ConfigError::PasswordSubstitution { .. })
        ));
    }
}
