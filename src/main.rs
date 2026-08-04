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
    /// Admin console's routing config snapshot — updated on reload so
    /// `GET /api/config` reflects the current state even after SIGHUP.
    admin_routing_config: Option<Arc<arc_swap::ArcSwap<trident::config::RoutingConfig>>>,
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

        // Sync the admin console's config snapshot so /api/config shows
        // the reloaded values regardless of whether the reload was
        // triggered by SIGHUP or POST /reload.
        if let Some(ref snapshot) = self.admin_routing_config {
            snapshot.store(Arc::new(routing.clone()));
        }

        Ok(())
    }
}

/// Coordinates dynamic node addition/removal across the HealthChecker,
/// PoolManager, and ConnectionRegistry at runtime.
struct LiveNodeManager {
    health_checker: Arc<HealthChecker<WireProtocolHealthProbe>>,
    pool_manager: Arc<InMemoryPoolManager>,
    connection_registry: Arc<ConnectionRegistry>,
    node_addresses: Arc<arc_swap::ArcSwap<HashMap<String, NodeAddress>>>,
    pool_mode: trident::config::PoolMode,
    max_pool_size: u32,
    pool_settings: NodePoolSettings,
}

#[async_trait::async_trait]
impl admin::NodeManager for LiveNodeManager {
    async fn add_node(&self, config: trident::config::NodeConfig) -> Result<(), String> {
        // Allow inserts for this node (in case it was previously removed
        // and the registry is blocking re-insertion).
        self.connection_registry.allow_node(&config.name);

        // Validate: check connectivity first
        let probe = WireProtocolHealthProbe {
            target: ProbeTarget {
                host: config.host.clone(),
                port: config.port,
                database: config.database.clone(),
                username: config.username.clone(),
                password: config.password.clone(),
                ssl_mode: config.ssl_mode,
            },
        };

        // Add to health checker (starts as unhealthy)
        if !self.health_checker.add_node(
            config.name.clone(),
            config.node_type,
            config.weight,
            probe,
        ) {
            return Err(format!("node '{}' already exists", config.name));
        }

        // Create and warm up the connection pool
        let target = ConnectTarget {
            host: config.host.clone(),
            port: config.port,
            database: config.database.clone(),
            username: config.username.clone(),
            password: config.password.clone(),
            ssl_mode: config.ssl_mode,
            extra_startup_params: HashMap::new(),
        };
        let factory = LiveConnFactory {
            target,
            registry: self.connection_registry.clone(),
        };
        let cleaner = DiscardAllCleaner::new(self.connection_registry.clone());
        let pool = NodePool::with_settings(
            config.name.clone(),
            self.pool_mode,
            self.max_pool_size,
            self.pool_settings,
            factory,
            cleaner,
        );

        if let Err(e) = pool.warm_up().await {
            // Rollback: remove from health checker and clean up any sockets
            // that were registered during the partial warm-up.
            self.health_checker.remove_node(&config.name);
            self.connection_registry.remove_by_node(&config.name);
            return Err(format!("failed to warm up pool for '{}': {}", config.name, e));
        }

        // Add pool to manager
        if !self.pool_manager.add_pool(config.name.clone(), Box::new(pool)) {
            // Should not happen since we checked health_checker first,
            // but handle gracefully. Clean up registered sockets too.
            self.health_checker.remove_node(&config.name);
            self.connection_registry.remove_by_node(&config.name);
            return Err(format!("node '{}' pool already exists", config.name));
        }

        // Update cancel-routing address table so CancelRequest for queries
        // on this new node can be forwarded correctly.
        self.node_addresses.rcu(|current| {
            let mut new_map = (**current).clone();
            new_map.insert(
                config.name.clone(),
                NodeAddress {
                    host: config.host.clone(),
                    port: config.port,
                },
            );
            Arc::new(new_map)
        });

        // Notify passthrough factory of the new node so per-user pools
        // can be created for it.
        self.pool_manager.notify_node_added(
            &config.name,
            &config.host,
            config.port,
            &config.database,
            config.ssl_mode,
        );

        tracing::info!(node = %config.name, node_type = ?config.node_type, host = %config.host, "dynamically added backend node");
        Ok(())
    }

    fn remove_node(&self, node_id: &str) -> Result<(), String> {
        // Atomically check last-writer protection and remove under the
        // health checker's internal lock — prevents concurrent removes
        // from both passing the writer count check.
        self.health_checker
            .remove_node_checked(node_id, true)
            .map_err(|e| e.to_string())?;

        // Remove from pool manager (existing connections drain naturally
        // as Arc references are dropped by in-flight handlers)
        self.pool_manager.remove_pool(node_id);

        // Remove from cancel-routing address table
        let node_id_owned = node_id.to_string();
        self.node_addresses.rcu(|current| {
            let mut new_map = (**current).clone();
            new_map.remove(&node_id_owned);
            Arc::new(new_map)
        });

        // Drain idle sockets for this node from the connection registry
        // to prevent FD leaks. In-flight connections will be discarded
        // naturally when their handler completes.
        self.connection_registry.remove_by_node(node_id);

        tracing::info!(node = %node_id, "dynamically removed backend node");
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

    #[error("client TLS configuration error: {0}")]
    ClientTls(String),

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

    let health_checker = Arc::new(HealthChecker::with_max_retries(
        node_probes,
        config.routing.max_replication_lag_ms,
        check_timeout,
        config.health.max_retries,
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
        acquire_timeout: parse_duration_or(
            config.pool.acquire_timeout.as_deref().unwrap_or("0s"),
            Duration::ZERO,
        ),
        leak_detection_threshold: parse_duration_or(
            config.pool.leak_detection_threshold.as_deref().unwrap_or("0s"),
            Duration::ZERO,
        ),
    };
    for node in &config.nodes {
        let target = ConnectTarget {
            host: node.host.clone(),
            port: node.port,
            database: node.database.clone(),
            username: node.username.clone(),
            password: node.password.clone(),
            ssl_mode: node.ssl_mode,
            extra_startup_params: HashMap::new(),
        };
        let factory = LiveConnFactory {
            target,
            registry: registry.clone(),
        };
        let cleaner = DiscardAllCleaner::new(registry.clone());
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
    let node_addresses = Arc::new(arc_swap::ArcSwap::new(Arc::new(node_addresses)));
    let cancel_registry = Arc::new(CancelRegistry::new());

    let health_checker_for_snapshot = health_checker.clone();
    let mut pool_manager = InMemoryPoolManager::new(pools, move || {
        health_checker_for_snapshot.snapshot()
    });

    // --- Passthrough mode: install UserPoolFactory ---
    if config.proxy.client_auth == trident::config::ClientAuthMode::Passthrough {
        use trident::pool::manager::UserPoolFactory;
        use trident::pool::NodeConfigUpdater;

        /// Factory that creates per-user connection pools with real
        /// backend authentication using the client's credentials.
        struct LiveUserPoolFactory {
            /// Node addresses: node_id -> (host, port, database, ssl_mode).
            /// Wrapped in ArcSwap so dynamic add/remove_node can update it.
            node_configs: Arc<arc_swap::ArcSwap<HashMap<String, NodeConnInfo>>>,
            registry: Arc<ConnectionRegistry>,
            pool_mode: trident::config::PoolMode,
            max_pool_size: u32,
            pool_settings: NodePoolSettings,
        }

        #[derive(Clone)]
        struct NodeConnInfo {
            host: String,
            port: u16,
            database: String,
            ssl_mode: trident::config::SslMode,
        }

        impl UserPoolFactory for LiveUserPoolFactory {
            fn create_pool(
                &self,
                node_id: &str,
                username: &str,
                password: &str,
                database: Option<&str>,
                extra_params: &HashMap<String, String>,
            ) -> Option<Box<dyn ConnectionPool>> {
                let configs = self.node_configs.load();
                let node_info = configs.get(node_id)?;
                let target = ConnectTarget {
                    host: node_info.host.clone(),
                    port: node_info.port,
                    // Use client-specified database if provided, otherwise
                    // fall back to the node's configured default.
                    database: database
                        .filter(|d| !d.is_empty())
                        .unwrap_or(&node_info.database)
                        .to_string(),
                    username: username.to_string(),
                    password: Some(password.to_string()),
                    ssl_mode: node_info.ssl_mode,
                    extra_startup_params: extra_params.clone(),
                };
                let factory = LiveConnFactory {
                    target,
                    registry: self.registry.clone(),
                };
                let cleaner = DiscardAllCleaner::new(self.registry.clone());
                // Per-user pools use min_pool_size=0 (no prewarming since
                // we cannot predict which users will connect) and a smaller
                // max_pool_size to prevent total connection explosion.
                let user_settings = NodePoolSettings {
                    min_pool_size: 0,
                    ..self.pool_settings
                };
                let pool = NodePool::with_settings(
                    node_id,
                    self.pool_mode,
                    self.max_pool_size,
                    user_settings,
                    factory,
                    cleaner,
                );
                Some(Box::new(pool))
            }
        }

        /// Implements NodeConfigUpdater by updating the ArcSwap of node configs.
        struct LiveNodeConfigUpdater {
            node_configs: Arc<arc_swap::ArcSwap<HashMap<String, NodeConnInfo>>>,
        }

        impl NodeConfigUpdater for LiveNodeConfigUpdater {
            fn add_node(&self, node_id: &str, host: &str, port: u16, database: &str, ssl_mode: trident::config::SslMode) {
                self.node_configs.rcu(|current| {
                    let mut new_map = (**current).clone();
                    new_map.insert(node_id.to_string(), NodeConnInfo {
                        host: host.to_string(),
                        port,
                        database: database.to_string(),
                        ssl_mode,
                    });
                    Arc::new(new_map)
                });
            }

            fn remove_node(&self, node_id: &str) {
                self.node_configs.rcu(|current| {
                    let mut new_map = (**current).clone();
                    new_map.remove(node_id);
                    Arc::new(new_map)
                });
            }
        }

        let mut node_configs_map = HashMap::new();
        for node in &config.nodes {
            node_configs_map.insert(node.name.clone(), NodeConnInfo {
                host: node.host.clone(),
                port: node.port,
                database: node.database.clone(),
                ssl_mode: node.ssl_mode,
            });
        }
        let passthrough_node_configs = Arc::new(arc_swap::ArcSwap::new(Arc::new(node_configs_map)));

        pool_manager.set_user_pool_factory(Box::new(LiveUserPoolFactory {
            node_configs: passthrough_node_configs.clone(),
            registry: registry.clone(),
            pool_mode: config.pool.mode,
            max_pool_size: config.pool.max_pool_size,
            pool_settings,
        }));

        pool_manager.set_node_config_updater(Arc::new(LiveNodeConfigUpdater {
            node_configs: passthrough_node_configs,
        }));

        tracing::info!("credential passthrough mode enabled: per-user pools will be created on demand");
    }

    pool_manager.set_connection_registry(registry.clone());
    pool_manager.set_user_pool_limits(config.pool.max_user_pools);
    let pool_manager = Arc::new(pool_manager);

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
        extra_startup_params: HashMap::new(),
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

    // --- Client TLS setup ---
    let tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>> =
        match (&config.proxy.tls_cert, &config.proxy.tls_key) {
            (Some(cert_path), Some(key_path)) => {
                let certs = load_certs(cert_path).map_err(|e| {
                    StartupError::ClientTls(
                        format!("failed to load TLS cert '{}': {}", cert_path, e),
                    )
                })?;
                let key = load_private_key(key_path).map_err(|e| {
                    StartupError::ClientTls(
                        format!("failed to load TLS key '{}': {}", key_path, e),
                    )
                })?;

                let tls_config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| {
                        StartupError::ClientTls(
                            format!("TLS config error: {}", e),
                        )
                    })?;

                tracing::info!(cert = %cert_path, key = %key_path, "client TLS enabled");
                Some(Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config))))
            }
            (None, None) => None,
            _ => {
                tracing::error!("proxy.tls_cert and proxy.tls_key must both be set or both be unset");
                std::process::exit(1);
            }
        };

    let deps = ProxyDeps {
        router: router.clone(),
        pool_manager: pool_manager.clone(),
        lsn_tracker,
        connection_registry: registry.clone(),
        cancel_registry,
        node_addresses: node_addresses.clone(),
        default_consistency: default_consistency.clone(),
        client_stats: client_stats.clone(),
        query_log,
        lsn_tracking: config.lsn_tracking.clone(),
        slow_queries: slow_queries.clone(),
        tls_acceptor,
        startup_timeout: parse_duration_or(&config.proxy.startup_timeout, Duration::from_secs(30)),
        client_idle_timeout: parse_duration_or(&config.proxy.client_idle_timeout, Duration::ZERO),
        cancel_connect_timeout: parse_duration_or(&config.proxy.cancel_connect_timeout, Duration::from_secs(5)),
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

    // --- Per-user pool idle eviction (passthrough mode) ---
    // Evicts per-user pools that have been idle for longer than
    // max_idle_time (same as pool.max_idle_time). Runs every 60s.
    // Also emits per-user pool metrics on each tick.
    if config.proxy.client_auth == trident::config::ClientAuthMode::Passthrough {
        let pool_manager_for_eviction = pool_manager.clone();
        let eviction_max_idle = parse_duration_or(&config.pool.max_idle_time, Duration::from_secs(300));
        let max_user_pools_cfg = config.pool.max_user_pools;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            // Emit static config limit once at startup
            metrics::gauge!("trident_user_pools_max").set(max_user_pools_cfg as f64);
            loop {
                ticker.tick().await;
                let evicted = pool_manager_for_eviction.evict_idle_user_pools(eviction_max_idle);
                let current_pools = pool_manager_for_eviction.user_pool_count();
                metrics::gauge!("trident_user_pools_total").set(current_pools as f64);
                if evicted > 0 {
                    metrics::counter!("trident_user_pools_evicted_total").increment(evicted as u64);
                    tracing::info!(evicted, remaining = current_pools, "evicted idle per-user pools");
                }
            }
        });
    }

    // --- Idle connection validation task ---
    // Periodically validates idle connections in each node pool by executing
    // the configured check_query. Dead connections are discarded so clients
    // never hit a stale socket.
    {
        let idle_check_interval = parse_duration_or(&config.pool.idle_check_interval, Duration::from_secs(30));
        if !idle_check_interval.is_zero() {
            let pool_manager_for_validation = pool_manager.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(idle_check_interval);
                ticker.tick().await; // skip the immediate first tick
                loop {
                    ticker.tick().await;
                    let snapshot = pool_manager_for_validation.snapshot();
                    for node in &snapshot {
                        if let Some(pool) = pool_manager_for_validation.pool_for(&node.node_id) {
                            let discarded = pool.validate_idle().await;
                            if discarded > 0 {
                                tracing::debug!(
                                    node_id = %node.node_id,
                                    discarded,
                                    "idle connection validation discarded stale connections"
                                );
                            }
                        }
                    }
                }
            });
        }
    }

    // --- Hot reload: SIGHUP re-reads the config file and applies the
    // subset of settings considered safe to change without a restart
    // (Router settings, analytics_patterns, default_consistency) -- see
    // `trident::reload` and DEPLOYMENT.md's hot-reload section.
    let routing_config_snapshot = Arc::new(arc_swap::ArcSwap::new(Arc::new(config.routing.clone())));
    let reload_target: Arc<dyn trident::reload::RoutingReloadTarget> = Arc::new(RouterReloadTarget {
        router: router.clone(),
        pattern_matcher,
        custom_rules: custom_rules.clone(),
        default_consistency: default_consistency.clone(),
        admin_routing_config: Some(routing_config_snapshot.clone()),
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
        let node_manager: Arc<dyn admin::NodeManager> = Arc::new(LiveNodeManager {
            health_checker: health_checker.clone(),
            pool_manager: pool_manager.clone(),
            connection_registry: registry.clone(),
            node_addresses: node_addresses.clone(),
            pool_mode: config.pool.mode,
            max_pool_size: config.pool.max_pool_size,
            pool_settings,
        });
        let admin_snapshot_source = pool_manager.clone();
        let config_path_for_admin = config_path.clone();
        let custom_rules_for_admin = custom_rules.clone();
        let client_stats_for_admin = client_stats.clone();
        let routing_config_for_admin = routing_config_snapshot.clone();
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
                routing_config_for_admin,
                lsn_tracking_for_admin,
                max_pool_size_for_admin,
                pool_mode_for_admin,
                slow_queries_for_admin,
                log_sender_for_admin,
                pool_min_size_admin,
                pool_max_idle_admin,
                pool_conn_timeout_admin,
                pool_max_lifetime_admin,
                Some(node_manager),
                config.admin.auth_token.clone(),
            )
            .await
            {
                tracing::error!(error = %e, "admin server exited with error");
            }
        });
    }

    // SECURITY WARNING: Trust authentication accepts any client without
    // credentials. This is suitable only for development/testing. In
    // production, restrict network access (VPC/firewall) or implement
    // proper client authentication (SCRAM-SHA-256).
    if config.proxy.client_auth == trident::config::ClientAuthMode::Trust
        && config.proxy.listen_addr.starts_with("0.0.0.0")
    {
        tracing::warn!(
            "⚠️  SECURITY: proxy listens on 0.0.0.0 with trust authentication. \
             Any network-reachable client can connect without credentials. \
             Ensure network-level access controls (VPC, security groups, firewall) \
             are in place for production deployments."
        );
    }

    match config.proxy.client_auth {
        trident::config::ClientAuthMode::Trust => {
            server
                .run(deps, move || {
                    let pid = next_backend_pid.fetch_add(1, Ordering::SeqCst);
                    TrustStartupHandler {
                        backend_pid: pid,
                        secret_key: generate_cancel_secret(),
                    }
                })
                .await?;
        }
        trident::config::ClientAuthMode::Md5 => {
            use trident::protocol::startup::{parse_auth_file, Md5PasswordStartupHandler};

            let auth_file_path = config.proxy.auth_file.as_deref().unwrap_or("userlist.txt");
            let auth_file_content = std::fs::read_to_string(auth_file_path).map_err(|e| {
                StartupError::InvalidAdminListenAddr(
                    format!("failed to read auth_file '{}': {}", auth_file_path, e),
                    e.to_string().parse::<std::net::SocketAddr>().unwrap_err(),
                )
            });
            let credentials = match auth_file_content {
                Ok(content) => Arc::new(parse_auth_file(&content)),
                Err(_) => {
                    tracing::error!(
                        path = %auth_file_path,
                        "failed to read auth_file for md5 client authentication"
                    );
                    std::process::exit(1);
                }
            };
            tracing::info!(
                users = credentials.len(),
                path = %auth_file_path,
                "loaded client auth credentials (md5 mode)"
            );

            let credentials_for_factory = credentials.clone();
            server
                .run(deps, move || {
                    let pid = next_backend_pid.fetch_add(1, Ordering::SeqCst);
                    Md5PasswordStartupHandler {
                        backend_pid: pid,
                        secret_key: generate_cancel_secret(),
                        credentials: credentials_for_factory.clone(),
                    }
                })
                .await?;
        }
        trident::config::ClientAuthMode::ScramSha256 => {
            use trident::protocol::startup::{parse_auth_file, ScramStartupHandler};

            let auth_file_path = config.proxy.auth_file.as_deref().unwrap_or("userlist.txt");
            let auth_file_content = std::fs::read_to_string(auth_file_path).map_err(|e| {
                StartupError::InvalidAdminListenAddr(
                    format!("failed to read auth_file '{}': {}", auth_file_path, e),
                    e.to_string().parse::<std::net::SocketAddr>().unwrap_err(),
                )
            });
            let credentials = match auth_file_content {
                Ok(content) => Arc::new(parse_auth_file(&content)),
                Err(_) => {
                    tracing::error!(
                        path = %auth_file_path,
                        "failed to read auth_file for scram-sha-256 client authentication"
                    );
                    std::process::exit(1);
                }
            };
            tracing::info!(
                users = credentials.len(),
                path = %auth_file_path,
                "loaded client auth credentials (scram-sha-256 mode)"
            );

            let credentials_for_factory = credentials.clone();
            server
                .run(deps, move || {
                    let pid = next_backend_pid.fetch_add(1, Ordering::SeqCst);
                    ScramStartupHandler {
                        backend_pid: pid,
                        secret_key: generate_cancel_secret(),
                        credentials: credentials_for_factory.clone(),
                    }
                })
                .await?;
        }
        trident::config::ClientAuthMode::Passthrough => {
            use trident::protocol::startup::PassthroughStartupHandler;

            server
                .run(deps, move || {
                    let pid = next_backend_pid.fetch_add(1, Ordering::SeqCst);
                    PassthroughStartupHandler {
                        backend_pid: pid,
                        secret_key: generate_cancel_secret(),
                    }
                })
                .await?;
        }
    }

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
/// Logs a warning when falling back so configuration typos are visible.
fn parse_duration_or(value: &str, default: Duration) -> Duration {
    match parse_duration(value) {
        Some(d) => d,
        None => {
            if !value.is_empty() && value != "0" {
                tracing::warn!(
                    value = %value,
                    default_ms = default.as_millis() as u64,
                    "failed to parse duration, using default"
                );
            }
            default
        }
    }
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
        "m" => Some(Duration::from_secs(number.checked_mul(60)?)),
        "h" => Some(Duration::from_secs(number.checked_mul(3600)?)),
        _ => None,
    }
}

/// Loads PEM-encoded certificates from a file.
fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open: {e}"))?;
    let mut reader = std::io::BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs: {e}"))?;
    if certs.is_empty() {
        return Err("no certificates found in file".to_string());
    }
    Ok(certs)
}

/// Loads the first PEM-encoded private key from a file.
fn load_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open: {e}"))?;
    let mut reader = std::io::BufReader::new(file);
    loop {
        match rustls_pemfile::read_one(&mut reader).map_err(|e| format!("parse key: {e}"))? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
            }
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
            }
            Some(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(rustls::pki_types::PrivateKeyDer::Sec1(key));
            }
            Some(_) => continue, // skip non-key items (certs, etc.)
            None => return Err("no private key found in file".to_string()),
        }
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
