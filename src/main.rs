//! Trident: PostgreSQL intelligent read/write splitting proxy
//!
//! Startup flow: load and validate configuration -> initialize the
//! PoolManager and HealthChecker (as a background task) -> start the
//! ProxyServer.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use trident::admin;
use trident::balancer::ConfiguredLoadBalancer;
use trident::config::AppConfig;
use trident::health::{HealthChecker, ProbeTarget, WireProtocolHealthProbe};
use trident::logging;
use trident::parser::classifier::KeywordClassifier;
use trident::parser::hint::RegexHintParser;
use trident::parser::pattern::RegexPatternMatcher;
use trident::pool::conn::ConnectTarget;
use trident::pool::manager::InMemoryPoolManager;
use trident::pool::pool::{ConnectionPool, NodePool, NodePoolSettings, PoolError};
use trident::pool::PoolManager;
use trident::protocol::startup::TrustStartupHandler;
use trident::proxy::registry::{CancelRegistry, ConnectionRegistry, DiscardAllCleaner, LiveConnFactory, NodeAddress};
use trident::proxy::server::{ProxyDeps, ProxyServer};
use trident::router::consistency::LsnConsistencyChecker;
use trident::router::cost::{DefaultCostEstimator, PoolExplainRunner};
use trident::router::router::{Router, RouterSettings};
use trident::session::lsn::InMemoryLsnTracker;

extern crate rustls;

const CONFIG_PATH_ENV_VAR: &str = "TRIDENT_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "config.yaml";

/// The concrete `Router` type this binary wires up, spelled out once here
/// so `RouterReloadTarget` below can name it.
type AppRouter = Router<
    KeywordClassifier,
    RegexHintParser,
    LsnConsistencyChecker,
    DefaultCostEstimator<Arc<RegexPatternMatcher>, PoolExplainRunner>,
    ConfiguredLoadBalancer,
>;

/// Bridges the concrete types this binary wires up (`AppRouter`, the
/// shared `RegexPatternMatcher`, and the `default_consistency` handle) to
/// the `reload::RoutingReloadTarget` trait, so `reload::watch_sighup`/
/// `admin`'s `/reload` route don't need to know about any of them
/// concretely.
struct RouterReloadTarget {
    router: Arc<AppRouter>,
    pattern_matcher: Arc<RegexPatternMatcher>,
    custom_rules: Arc<trident::router::custom_rules::CustomRoutingRules>,
    default_consistency: Arc<arc_swap::ArcSwap<trident::config::ConsistencyLevel>>,
}

impl trident::reload::RoutingReloadTarget for RouterReloadTarget {
    fn apply(&self, routing: &trident::config::RoutingConfig) -> Result<(), String> {
        // Apply the pattern set first: if it fails to compile (should not
        // happen, since `AppConfig::validate` already checked it), leave
        // the patterns, custom rules, settings, and consistency all
        // untouched rather than applying a half-updated configuration.
        self.pattern_matcher
            .update_patterns(&routing.analytics_patterns)
            .map_err(|e| format!("failed to recompile analytics_patterns: {e}"))?;

        // custom_rules has no failure mode of its own (no compilation
        // step), so it is safe to apply unconditionally once the pattern
        // update above has succeeded.
        self.custom_rules.replace_all(&routing.custom_rules);

        self.router.update_settings(RouterSettings {
            enable_transaction_split: routing.enable_transaction_split,
            split_respects_consistency: routing.split_respects_consistency,
            enable_hint_routing: routing.enable_hint_routing,
            enable_cost_routing: routing.enable_cost_routing,
            cost_threshold: routing.cost_threshold,
            writer_readable: routing.writer_readable,
        });

        self.default_consistency
            .store(Arc::new(routing.default_consistency));

        Ok(())
    }
}

#[tokio::main]
async fn main() {
    // Install the ring crypto provider for rustls (required for backend TLS).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Logging cannot be initialized before the config is loaded (its
    // settings come from `config.logging`), so a config-load failure is
    // reported via eprintln! rather than through `tracing`.
    let config_path =
        std::env::var(CONFIG_PATH_ENV_VAR).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());

    let config = match AppConfig::load_from_file(&config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("failed to load configuration from '{config_path}': {e}");
            std::process::exit(1);
        }
    };

    // The live-log broadcast channel must exist before the tracing
    // subscriber is installed so its forwarding layer can be attached.
    // Only wired into the subscriber when the admin console is enabled --
    // otherwise every log line would be formatted a second time for a
    // stream nobody can subscribe to.
    let (log_sender, _log_rx) = trident::admin::create_log_channel();
    let broadcast_for_logging = if config.admin.enabled {
        Some(log_sender.clone())
    } else {
        None
    };

    // `_logging_guard` must stay alive for the rest of the process: if
    // file logging is enabled (config.logging.dir), dropping it stops the
    // background thread that flushes buffered log lines to disk.
    let _logging_guard = match logging::init_with_broadcast(&config.logging, broadcast_for_logging)
    {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("failed to initialize logging: {e}");
            std::process::exit(1);
        }
    };

    // Must be installed before any code in the process emits a metric via
    // the `metrics` crate's macros (see `admin::install_prometheus_recorder`
    // docs) -- done here, right after logging, before the health checker or
    // proxy server (both of which emit metrics) start.
    let prometheus_handle = match admin::install_prometheus_recorder() {
        Ok(handle) => handle,
        Err(e) => {
            tracing::error!(error = %e, "failed to install Prometheus metrics recorder");
            std::process::exit(1);
        }
    };

    if let Err(e) = run(config_path, config, prometheus_handle, log_sender).await {
        tracing::error!(error = %e, "trident exited with error");
        std::process::exit(1);
    }
}

#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error("invalid listen_addr '{0}': {1}")]
    InvalidListenAddr(String, std::net::AddrParseError),

    #[error("invalid admin.listen_addr '{0}': {1}")]
    InvalidAdminListenAddr(String, std::net::AddrParseError),

    #[error("failed to prewarm connection pool for node '{node}': {source}")]
    PoolWarmup { node: String, source: PoolError },

    #[error("server error: {0}")]
    Server(#[from] trident::proxy::server::ServerError),
}

async fn run(
    config_path: String,
    config: AppConfig,
    prometheus_handle: metrics_exporter_prometheus::PrometheusHandle,
    log_sender: trident::admin::LogSender,
) -> Result<(), StartupError> {
    let listen_addr: SocketAddr = config
        .proxy
        .listen_addr
        .parse()
        .map_err(|e| StartupError::InvalidListenAddr(config.proxy.listen_addr.clone(), e))?;

    // --- Health checker: one WireProtocolHealthProbe per configured node ---
    let node_probes = config
        .nodes
        .iter()
        .map(|node| {
            let probe = WireProtocolHealthProbe {
                target: ProbeTarget {
                    host: node.host.clone(),
                    port: node.port,
                    database: node.database.clone(),
                    username: node.username.clone(),
                    password: node.password.clone(),
                    ssl_mode: node.ssl_mode,
                },
            };
            (node.name.clone(), node.node_type, node.weight, probe)
        })
        .collect::<Vec<_>>();

    let check_timeout = parse_duration_or(&config.health.check_timeout, Duration::from_secs(2));
    let check_interval = parse_duration_or(&config.health.check_interval, Duration::from_secs(3));

    let health_checker = Arc::new(HealthChecker::new(
        node_probes,
        config.routing.max_replication_lag_ms,
        check_timeout,
    ));

    // Run health checks in the background for the lifetime of the process.
    let health_checker_bg = health_checker.clone();
    tokio::spawn(async move {
        health_checker_bg.run(check_interval).await;
    });

    // Admin server address is resolved now (so a bad `admin.listen_addr`
    // fails startup fast, alongside `proxy.listen_addr`), but the server
    // itself is spawned further down once the router/pattern-matcher/
    // default_consistency handles it needs for `POST /reload` exist.
    let admin_listen_addr: Option<SocketAddr> = if config.admin.enabled {
        Some(
            config
                .admin
                .listen_addr
                .parse()
                .map_err(|e| StartupError::InvalidAdminListenAddr(config.admin.listen_addr.clone(), e))?,
        )
    } else {
        None
    };

    // --- Connection pools: one NodePool per configured node ---
    let registry = Arc::new(ConnectionRegistry::new());
    let mut pools: HashMap<String, Box<dyn ConnectionPool>> = HashMap::new();
    let mut node_addresses: HashMap<String, NodeAddress> = HashMap::new();
    let pool_settings = NodePoolSettings {
        min_pool_size: config.pool.min_pool_size,
        connection_timeout: parse_duration_or(
            &config.pool.connection_timeout,
            Duration::from_secs(5),
        ),
        max_idle_time: parse_duration_or(&config.pool.max_idle_time, Duration::from_secs(5 * 60)),
        max_lifetime: parse_duration_or(&config.pool.max_lifetime, Duration::from_secs(30 * 60)),
    };
    for node in &config.nodes {
        let target = ConnectTarget {
            host: node.host.clone(),
            port: node.port,
            database: node.database.clone(),
            username: node.username.clone(),
            password: node.password.clone(),
            ssl_mode: node.ssl_mode,
        };
        let factory = LiveConnFactory {
            target,
            registry: registry.clone(),
        };
        let cleaner = DiscardAllCleaner {
            registry: registry.clone(),
        };
        let pool = NodePool::with_settings(
            node.name.clone(),
            config.pool.mode,
            config.pool.max_pool_size,
            pool_settings,
            factory,
            cleaner,
        );
        pool.warm_up()
            .await
            .map_err(|source| StartupError::PoolWarmup {
                node: node.name.clone(),
                source,
            })?;
        pools.insert(node.name.clone(), Box::new(pool));
        // Recorded so a CancelRequest can be forwarded to this node over a
        // brand-new connection (Requirements 7.1-7.3); see
        // `proxy::registry::CancelRegistry`.
        node_addresses.insert(
            node.name.clone(),
            NodeAddress {
                host: node.host.clone(),
                port: node.port,
            },
        );
    }
    let node_addresses = Arc::new(node_addresses);
    let cancel_registry = Arc::new(CancelRegistry::new());

    let health_checker_for_snapshot = health_checker.clone();
    let pool_manager = Arc::new(InMemoryPoolManager::new(pools, move || {
        health_checker_for_snapshot.snapshot()
    }));

    // --- Router ---
    //
    // `pattern_matcher` is kept as its own `Arc` (rather than moved
    // entirely into the cost estimator) so `reload` can hot-swap its
    // compiled regex set later via `RegexPatternMatcher::update_patterns`;
    // `DefaultCostEstimator` holds a clone of the same `Arc`, so both see
    // the same live pattern set (see `parser::pattern`'s blanket
    // `PatternMatcher` impl for `Arc<T>`).
    let pattern_matcher = Arc::new(
        RegexPatternMatcher::new(&config.routing.analytics_patterns)
            .expect("analytics_patterns already validated by AppConfig::validate"),
    );
    // `custom_rules` (see `router::custom_rules`) is likewise kept as its
    // own `Arc`, both so `reload` can atomically replace the whole rule
    // set and so the admin API (POST /custom-rules) can manage individual
    // rules live, independent of a config-file reload.
    let custom_rules = Arc::new(trident::router::custom_rules::CustomRoutingRules::new());
    custom_rules.replace_all(&config.routing.custom_rules);

    // Build the EXPLAIN runner: pick the first reader (or writer as
    // fallback) to run EXPLAIN queries against for cost estimation.
    let explain_node = config
        .nodes
        .iter()
        .find(|n| n.node_type == trident::config::NodeType::Reader)
        .or_else(|| config.nodes.iter().find(|n| n.node_type == trident::config::NodeType::Writer))
        .expect("at least one reader or writer node must be configured");
    let explain_target = ConnectTarget {
        host: explain_node.host.clone(),
        port: explain_node.port,
        database: explain_node.database.clone(),
        username: explain_node.username.clone(),
        password: explain_node.password.clone(),
        ssl_mode: explain_node.ssl_mode,
    };
    let explain_runner = PoolExplainRunner::new(explain_target);

    let router = Arc::new(
        Router::new(
            KeywordClassifier,
            RegexHintParser,
            LsnConsistencyChecker,
            DefaultCostEstimator::new(pattern_matcher.clone(), explain_runner),
            ConfiguredLoadBalancer::from_strategy(config.routing.load_balance_strategy),
            RouterSettings {
                enable_transaction_split: config.routing.enable_transaction_split,
                split_respects_consistency: config.routing.split_respects_consistency,
                enable_hint_routing: config.routing.enable_hint_routing,
                enable_cost_routing: config.routing.enable_cost_routing,
                cost_threshold: config.routing.cost_threshold,
                writer_readable: config.routing.writer_readable,
            },
        )
        .with_custom_rules(custom_rules.clone()),
    );

    let lsn_tracker = Arc::new(InMemoryLsnTracker::new());

    // --- Proxy server ---
    let server = ProxyServer::new(listen_addr, config.proxy.max_clients);
    let next_backend_pid = Arc::new(AtomicI32::new(1));

    let default_consistency = Arc::new(arc_swap::ArcSwap::new(Arc::new(config.routing.default_consistency)));
    let client_stats = Arc::new(trident::proxy::client_stats::ClientStats::new());
    let query_log = trident::proxy::handler::QueryLogSettings::new(config.logging.query_trace, config.logging.slow_query);
    let slow_queries = Arc::new(trident::admin::SlowQueryBuffer::new(500));

    let deps = ProxyDeps {
        router: router.clone(),
        pool_manager: pool_manager.clone(),
        lsn_tracker,
        connection_registry: registry,
        cancel_registry,
        node_addresses,
        default_consistency: default_consistency.clone(),
        client_stats: client_stats.clone(),
        query_log,
        lsn_tracking: config.lsn_tracking.clone(),
        slow_queries: slow_queries.clone(),
    };

    // --- Background task: per-node connection pool / replication lag
    // gauges (trident_pool_active_connections, trident_pool_max_size,
    // trident_node_replication_lag_ms). `active_connections` itself is
    // already tracked live at zero cost by each `NodePool`; this task
    // just periodically renders that (plus the health checker's
    // replication-lag data) into Prometheus gauges for `/metrics`, so it
    // does not need to run anywhere near as often as a query -- once per
    // health-check interval is already more than fresh enough for
    // dashboards/alerting.
    {
        let pool_manager_for_metrics = pool_manager.clone();
        let interval = check_interval;
        let max_pool_size = config.pool.max_pool_size;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let snapshot = pool_manager_for_metrics.snapshot();
                trident::pool::emit_pool_metrics(&snapshot, max_pool_size);
            }
        });
    }

    // --- Hot reload: SIGHUP re-reads the config file and applies the
    // subset of settings considered safe to change without a restart
    // (Router settings, analytics_patterns, default_consistency) -- see
    // `trident::reload` and DEPLOYMENT.md's hot-reload section.
    let reload_target: Arc<dyn trident::reload::RoutingReloadTarget> = Arc::new(RouterReloadTarget {
        router: router.clone(),
        pattern_matcher,
        custom_rules: custom_rules.clone(),
        default_consistency: default_consistency.clone(),
    });
    tokio::spawn(trident::reload::watch_sighup(
        config_path.clone(),
        reload_target.clone(),
    ));

    // --- Admin/observability server: /metrics + /healthz + /reload
    // (optional) ---
    //
    // Bound to a separate listener from the PostgreSQL wire-protocol
    // proxy (config.proxy.listen_addr); disabled by default (see
    // `AdminConfig::default`) since it is unauthenticated -- see
    // `admin` module docs. `/healthz` reports healthy based on the same
    // health-check snapshot the router/pool manager use; `/reload`
    // reuses the same hot-reload target `SIGHUP` uses above.
    if let Some(admin_listen_addr) = admin_listen_addr {
        let admin_snapshot_source = pool_manager.clone();
        let config_path_for_admin = config_path.clone();
        let custom_rules_for_admin = custom_rules.clone();
        let client_stats_for_admin = client_stats.clone();
        let routing_config_snapshot = Arc::new(arc_swap::ArcSwap::new(Arc::new(config.routing.clone())));
        let lsn_tracking_for_admin = config.lsn_tracking.clone();
        let max_pool_size_for_admin = config.pool.max_pool_size;
        let pool_mode_for_admin = config.pool.mode;
        let slow_queries_for_admin = slow_queries.clone();
        let log_sender_for_admin = log_sender.clone();
        let pool_min_size_admin = config.pool.min_pool_size;
        let pool_max_idle_admin = config.pool.max_idle_time.clone();
        let pool_conn_timeout_admin = config.pool.connection_timeout.clone();
        let pool_max_lifetime_admin = config.pool.max_lifetime.clone();
        tokio::spawn(async move {
            if let Err(e) = admin::run(
                admin_listen_addr,
                prometheus_handle,
                move || admin_snapshot_source.snapshot(),
                Some((config_path_for_admin, reload_target)),
                Some(custom_rules_for_admin),
                client_stats_for_admin,
                routing_config_snapshot,
                lsn_tracking_for_admin,
                max_pool_size_for_admin,
                pool_mode_for_admin,
                slow_queries_for_admin,
                log_sender_for_admin,
                pool_min_size_admin,
                pool_max_idle_admin,
                pool_conn_timeout_admin,
                pool_max_lifetime_admin,
            )
            .await
            {
                tracing::error!(error = %e, "admin server exited with error");
            }
        });
    }

    server
        .run(deps, move || {
            let pid = next_backend_pid.fetch_add(1, Ordering::SeqCst);
            TrustStartupHandler {
                backend_pid: pid,
                secret_key: generate_cancel_secret(),
            }
        })
        .await?;

    Ok(())
}

/// PostgreSQL cancel keys are bearer secrets. Generate the full 32-bit value
/// independently from the public proxy PID so clients cannot predict another
/// session's key from an observed BackendKeyData message.
fn generate_cancel_secret() -> i32 {
    rand::random::<i32>()
}

/// Parses a short human-readable duration string like `"5m"`, `"2s"`,
/// `"30ms"` into a `std::time::Duration`, falling back to `default` if the
/// string cannot be parsed. Supported suffixes: `ms`, `s`, `m`, `h`.
fn parse_duration_or(value: &str, default: Duration) -> Duration {
    parse_duration(value).unwrap_or(default)
}

fn parse_duration(value: &str) -> Option<Duration> {
    let value = value.trim();
    let (number_part, suffix) = if let Some(stripped) = value.strip_suffix("ms") {
        (stripped, "ms")
    } else if let Some(stripped) = value.strip_suffix('s') {
        (stripped, "s")
    } else if let Some(stripped) = value.strip_suffix('m') {
        (stripped, "m")
    } else {
        let stripped = value.strip_suffix('h')?;
        (stripped, "h")
    };

    let number: u64 = number_part.trim().parse().ok()?;
    match suffix {
        "ms" => Some(Duration::from_millis(number)),
        "s" => Some(Duration::from_secs(number)),
        "m" => Some(Duration::from_secs(number * 60)),
        "h" => Some(Duration::from_secs(number * 3600)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_secrets_are_not_derived_from_backend_pid() {
        let pid = 42;
        let secrets: std::collections::HashSet<_> =
            (0..64).map(|_| generate_cancel_secret()).collect();
        assert!(secrets.len() > 1, "cancel secret generator must not be constant");
        assert!(
            secrets.iter().any(|secret| *secret != pid * 1000),
            "cancel secrets must not use the former predictable PID formula"
        );
    }

    #[test]
    fn parse_duration_handles_all_supported_suffixes() {
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("3s"), Some(Duration::from_secs(3)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
    }

    #[test]
    fn parse_duration_rejects_unknown_suffix() {
        assert_eq!(parse_duration("5x"), None);
        assert_eq!(parse_duration("bogus"), None);
    }

    #[test]
    fn parse_duration_or_falls_back_to_default() {
        let default = Duration::from_secs(42);
        assert_eq!(parse_duration_or("not-a-duration", default), default);
    }
}
