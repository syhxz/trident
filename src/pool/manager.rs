//! Global pool manager (`manager`)
//!
//! Implements the `PoolManager` trait: `pool_for` (looks up a pool by
//! node name) and `snapshot` (aggregates every node's
//! `BackendNodeSnapshot`, for use by the Router/Balancer). Cooperates
//! with the Health module: health-check results are injected via a
//! health-snapshot source and merged with the `active_connections`
//! maintained by this module into the final snapshot.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::health::BackendNodeSnapshot;
use crate::pool::pool::ConnectionPool;

/// Global connection pool manager interface.
pub trait PoolManager: Send + Sync {
    /// Looks up the connection pool for a node by name; returns `None` if
    /// the node does not exist.
    fn pool_for(&self, node_id: &str) -> Option<Arc<dyn ConnectionPool>>;

    /// Looks up (or lazily creates) a connection pool for a specific
    /// (node, user) pair. Used in passthrough authentication mode where
    /// each database user gets its own pool of backend connections
    /// authenticated with their credentials.
    ///
    /// Default: delegates to `pool_for` (service-account mode ignores the
    /// user identity and shares one pool per node across all clients).
    fn pool_for_user(
        &self,
        node_id: &str,
        _username: &str,
        _password: &str,
        _database: Option<&str>,
        _extra_params: &HashMap<String, String>,
    ) -> Option<Arc<dyn ConnectionPool>> {
        self.pool_for(node_id)
    }

    /// Aggregates the `BackendNodeSnapshot` for every node (including the
    /// health state, replay LSN, and replication lag produced by the
    /// Health module, plus the `active_connections` maintained by this
    /// manager), for use by the Router/Balancer.
    fn snapshot(&self) -> Vec<BackendNodeSnapshot>;

    /// Looks up an existing per-user pool without creating one. Returns
    /// `None` if no pool exists for this (node, user, database) triple.
    /// Used during session cleanup to avoid creating pools needlessly.
    fn pool_for_user_existing(
        &self,
        node_id: &str,
        _username: &str,
        _database: Option<&str>,
    ) -> Option<Arc<dyn ConnectionPool>> {
        self.pool_for(node_id)
    }

    /// Removes a per-user pool (e.g. after credential verification failure).
    /// No-op if no matching pool exists.
    fn remove_user_pool(
        &self,
        _node_id: &str,
        _username: &str,
        _database: Option<&str>,
        _extra_params: &HashMap<String, String>,
    ) {}
}

/// Factory trait for creating per-user connection pools. Implemented by
/// the application layer (main.rs) which has access to the node addresses,
/// registry, SSL config, and pool settings needed to construct a real pool.
pub trait UserPoolFactory: Send + Sync {
    /// Creates a new `ConnectionPool` for the given (node, user, password, database).
    /// `extra_params` are additional startup parameters from the client
    /// (e.g. `application_name`, `options`) to forward to the backend.
    /// Called lazily the first time a user connects through a node.
    fn create_pool(
        &self,
        node_id: &str,
        username: &str,
        password: &str,
        database: Option<&str>,
        extra_params: &HashMap<String, String>,
    ) -> Option<Box<dyn ConnectionPool>>;
}

/// Default `PoolManager` implementation based on an in-memory `HashMap`.
///
/// Stores each node's pool as an `Arc<dyn ConnectionPool>`, allowing
/// dynamic addition/removal of nodes at runtime via atomic swap.
///
/// When a `UserPoolFactory` is installed (via `set_user_pool_factory`),
/// `pool_for_user` creates per-user pools on demand for credential
/// passthrough mode. Without a factory, `pool_for_user` delegates to
/// `pool_for` (service-account mode).
pub struct InMemoryPoolManager {
    pools: ArcSwap<HashMap<String, Arc<dyn ConnectionPool>>>,
    /// The data source providing the latest health-check snapshot
    /// (excluding `active_connections`); typically a closure wrapping
    /// `health::HealthChecker::snapshot`.
    health_snapshots: Box<dyn Fn() -> Vec<BackendNodeSnapshot> + Send + Sync>,
    /// Optional factory for per-user pools (passthrough mode).
    user_pool_factory: Option<Box<dyn UserPoolFactory + Send + Sync>>,
    /// Per-user pools: key = "node_id\0username\0database", value = (pool, last_access_time).
    user_pools: parking_lot::Mutex<HashMap<String, UserPoolEntry>>,
    /// Callback to notify the factory when a node is added/removed,
    /// so it can update its internal node address map.
    node_config_updater: Option<Arc<dyn NodeConfigUpdater + Send + Sync>>,
    /// Maximum number of per-user pools allowed across all nodes. Prevents
    /// resource exhaustion from a large number of distinct users. When
    /// reached, new pool creation is refused (returns None from pool_for_user).
    /// 0 = unlimited.
    max_user_pools: usize,
    /// Maximum total backend connections across ALL per-user pools. Prevents
    /// unbounded FD/memory consumption even when individual pool sizes are small.
    /// 0 = unlimited.
    max_user_connections: u32,
    /// Optional reference to the connection registry, used to close sockets
    /// when pools are evicted or removed. Without this, eviction only drops
    /// pool metadata while sockets linger in the registry.
    connection_registry: Option<Arc<crate::proxy::registry::ConnectionRegistry>>,
}

/// Allows the pool manager to notify the UserPoolFactory of node changes.
pub trait NodeConfigUpdater: Send + Sync {
    fn add_node(&self, node_id: &str, host: &str, port: u16, database: &str, ssl_mode: crate::config::SslMode);
    fn remove_node(&self, node_id: &str);
}

/// Entry in the per-user pool map, tracking last access for idle eviction.
struct UserPoolEntry {
    pool: Arc<dyn ConnectionPool>,
    last_access: std::time::Instant,
    /// HMAC-SHA-256 fingerprint of the password used to create this pool.
    /// If a new request arrives with a different password (user changed
    /// their credentials), the old pool is replaced — but only if the
    /// cooldown period has passed (to prevent DoS via rapid
    /// password-mismatch requests).
    password_hash: [u8; 32],
    /// Earliest time at which this pool may be replaced due to a password
    /// change. Prevents an attacker from repeatedly destroying a pool with
    /// wrong passwords. Reset after each successful replacement.
    replace_cooldown_until: std::time::Instant,
}

/// Minimum interval between pool replacements due to password changes.
/// Within this window, mismatched passwords are silently ignored (the
/// existing pool is returned). This prevents a DoS attack where an
/// attacker sends wrong passwords to force pool destruction.
const POOL_REPLACE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

/// Computes a keyed HMAC-SHA-256 of the password for credential fingerprinting.
/// This IS security-relevant: it controls whether a pool authenticated with
/// one password is handed to a client presenting a different password.
/// Uses a per-process random key (generated at startup) to prevent offline
/// precomputation attacks. Comparison should be constant-time (see
/// `password_hash_eq`).
fn hash_password(password: &str) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::sync::OnceLock;

    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    let key = KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).expect("failed to generate random key for password hashing");
        k
    });

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is always valid");
    mac.update(password.as_bytes());
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Constant-time comparison of two password hashes.
fn password_hash_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Whitelist of startup parameters that affect connection session state
/// and should distinguish separate pools. Parameters not in this list are
/// ignored for key purposes (they'll still be forwarded to the backend but
/// won't force a separate pool).
const POOL_KEY_PARAMS: &[&str] = &[
    "options",
    "search_path",
    "timezone",
    "datestyle",
    "intervalstyle",
    "client_encoding",
    "standard_conforming_strings",
];

/// Produces a deterministic, compact string from connection-affecting
/// startup parameters for use as part of the pool key.
fn normalize_extra_params_key(params: &HashMap<String, String>) -> String {
    let mut relevant: Vec<(&str, &str)> = params
        .iter()
        .filter(|(k, _)| POOL_KEY_PARAMS.contains(&k.to_lowercase().as_str()))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    relevant.sort_by_key(|(k, _)| *k);
    if relevant.is_empty() {
        String::new()
    } else {
        relevant
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl InMemoryPoolManager {
    pub fn new(
        pools: HashMap<String, Box<dyn ConnectionPool>>,
        health_snapshots: impl Fn() -> Vec<BackendNodeSnapshot> + Send + Sync + 'static,
    ) -> Self {
        let arc_pools: HashMap<String, Arc<dyn ConnectionPool>> = pools
            .into_iter()
            .map(|(k, v)| (k, Arc::from(v)))
            .collect();
        InMemoryPoolManager {
            pools: ArcSwap::new(Arc::new(arc_pools)),
            health_snapshots: Box::new(health_snapshots),
            user_pool_factory: None,
            user_pools: parking_lot::Mutex::new(HashMap::new()),
            node_config_updater: None,
            max_user_pools: 0,
            max_user_connections: 0,
            connection_registry: None,
        }
    }

    /// Sets the global limits for per-user pools. `max_pools` limits the
    /// number of distinct (node, user, database) pools; `max_connections`
    /// limits the total backend connections across all user pools.
    /// Either value of 0 means unlimited.
    pub fn set_user_pool_limits(&mut self, max_pools: usize, max_connections: u32) {
        self.max_user_pools = max_pools;
        self.max_user_connections = max_connections;
    }

    /// Sets the connection registry reference so eviction can close
    /// the physical sockets associated with removed pools.
    pub fn set_connection_registry(&mut self, registry: Arc<crate::proxy::registry::ConnectionRegistry>) {
        self.connection_registry = Some(registry);
    }

    /// Returns the total number of backend connections across all per-user pools.
    fn total_user_connections(&self, pools: &HashMap<String, UserPoolEntry>) -> i64 {
        pools.values().map(|e| e.pool.active_connections()).sum()
    }

    /// Installs a `UserPoolFactory` to enable per-user pool creation
    /// (passthrough credential mode). Once set, `pool_for_user` will
    /// lazily create pools for each unique (node, user) pair.
    pub fn set_user_pool_factory(
        &mut self,
        factory: Box<dyn UserPoolFactory + Send + Sync>,
    ) {
        self.user_pool_factory = Some(factory);
    }

    /// Installs a `NodeConfigUpdater` that gets called when nodes are
    /// dynamically added/removed, so the UserPoolFactory can update its
    /// internal node address map.
    pub fn set_node_config_updater(
        &mut self,
        updater: Arc<dyn NodeConfigUpdater + Send + Sync>,
    ) {
        self.node_config_updater = Some(updater);
    }

    /// Evicts per-user pools that have not been accessed for longer than
    /// `max_idle`. Only pools with connections actively checked out by
    /// clients are kept regardless of idle time — a pool whose physical
    /// connections are ALL sitting in the idle queue is eligible for
    /// eviction once `max_idle` expires.
    ///
    /// Returns the number of pools evicted. Intended to be called
    /// periodically from a background task (e.g. once per minute).
    pub fn evict_idle_user_pools(&self, max_idle: std::time::Duration) -> usize {
        let now = std::time::Instant::now();
        let mut pools = self.user_pools.lock();
        let before = pools.len();
        let registry = self.connection_registry.as_ref();
        pools.retain(|key, entry| {
            let idle_duration = now.duration_since(entry.last_access);
            if idle_duration < max_idle {
                return true; // Recently accessed — keep
            }
            // Check if any connections are truly in use (checked out by
            // a client, not just idle in the pool). A pool whose only
            // connections are idle can be safely evicted.
            let total = entry.pool.active_connections();
            let idle_conns = entry.pool.idle_connections();
            let checked_out = total - idle_conns;
            if checked_out > 0 {
                return true; // Still has checked-out connections — keep
            }
            // Evicting: close all physical sockets in the registry that
            // belong to this pool, so FDs are actually freed.
            if let Some(reg) = registry {
                // Extract node_id from key (format: "node_id\0user\0db\0params")
                let node_id = key.split('\0').next().unwrap_or("");
                for pid in entry.pool.known_pids() {
                    reg.remove(node_id, pid);
                }
            }
            false // evict
        });
        before - pools.len()
    }

    /// Returns the current number of per-user pools (for metrics/admin).
    pub fn user_pool_count(&self) -> usize {
        self.user_pools.lock().len()
    }

    /// Returns the total backend connections across all per-user pools.
    pub fn user_connection_count(&self) -> i64 {
        let pools = self.user_pools.lock();
        self.total_user_connections(&pools)
    }

    /// Dynamically adds a new pool for a node. Returns `false` if the
    /// node already has a pool registered.
    pub fn add_pool(&self, node_id: String, pool: Box<dyn ConnectionPool>) -> bool {
        let pool_arc: Arc<dyn ConnectionPool> = Arc::from(pool);
        let mut added = false;
        self.pools.rcu(|current| {
            if current.contains_key(&node_id) {
                added = false;
                Arc::clone(current)
            } else {
                added = true;
                let mut new_pools = (**current).clone();
                new_pools.insert(node_id.clone(), Arc::clone(&pool_arc));
                Arc::new(new_pools)
            }
        });
        added
    }

    /// Notifies the node config updater (if any) that a node was added.
    /// Call this after `add_pool` with the node's connection info.
    pub fn notify_node_added(
        &self,
        node_id: &str,
        host: &str,
        port: u16,
        database: &str,
        ssl_mode: crate::config::SslMode,
    ) {
        if let Some(updater) = &self.node_config_updater {
            updater.add_node(node_id, host, port, database, ssl_mode);
        }
    }

    /// Dynamically removes a node's pool. Returns `false` if the node
    /// does not exist. The pool (and its connections) remain alive until
    /// all existing Arc references are dropped.
    pub fn remove_pool(&self, node_id: &str) -> bool {
        let mut removed = false;
        self.pools.rcu(|current| {
            if !current.contains_key(node_id) {
                removed = false;
                Arc::clone(current)
            } else {
                removed = true;
                let mut new_pools = (**current).clone();
                new_pools.remove(node_id);
                Arc::new(new_pools)
            }
        });
        // Also remove any per-user pools for this node
        if removed {
            let prefix = format!("{}\0", node_id);
            let mut user_pools = self.user_pools.lock();
            user_pools.retain(|k, _| !k.starts_with(&prefix));
            // Notify factory so it won't try to create pools for this node
            if let Some(updater) = &self.node_config_updater {
                updater.remove_node(node_id);
            }
        }
        removed
    }
}

impl PoolManager for InMemoryPoolManager {
    fn pool_for(&self, node_id: &str) -> Option<Arc<dyn ConnectionPool>> {
        let pools = self.pools.load();
        pools.get(node_id).cloned()
    }

    fn pool_for_user(
        &self,
        node_id: &str,
        username: &str,
        password: &str,
        database: Option<&str>,
        extra_params: &HashMap<String, String>,
    ) -> Option<Arc<dyn ConnectionPool>> {
        let factory = match &self.user_pool_factory {
            Some(f) => f,
            None => return self.pool_for(node_id),
        };

        // Check that the node exists (either in the base pools or known to
        // the factory). This prevents phantom pool creation for dynamically
        // removed nodes.
        self.pools.load().get(node_id)?;

        // Key includes database so the same user connecting to different
        // databases gets separate pools (each pool's connections target one
        // specific database). Also includes connection-affecting startup
        // parameters so different options/search_path/TimeZone sessions
        // don't share a pool whose connections have different settings.
        let db = database.unwrap_or("");
        let params_key = normalize_extra_params_key(extra_params);
        let key = format!("{}\0{}\0{}\0{}", node_id, username, db, params_key);
        let now = std::time::Instant::now();
        let pw_hash = hash_password(password);

        // Fast path: pool already exists
        {
            let mut pools = self.user_pools.lock();
            if let Some(entry) = pools.get_mut(&key) {
                if password_hash_eq(&entry.password_hash, &pw_hash) {
                    // Same password — reuse pool
                    entry.last_access = now;
                    return Some(Arc::clone(&entry.pool));
                }
                // Password mismatch detected. Only replace the pool if the
                // cooldown period has passed. This prevents a DoS where an
                // attacker sends wrong passwords to repeatedly destroy pools.
                if now < entry.replace_cooldown_until {
                    // Within cooldown — do NOT return the pool to a client
                    // with the wrong password. They'll get a pool-exhausted
                    // error, which is safer than giving them access to
                    // authenticated connections. The pool stays intact for
                    // clients with the correct password.
                    tracing::warn!(
                        node_id,
                        username,
                        "password mismatch within cooldown, rejecting"
                    );
                    return None;
                }
                // Cooldown expired — allow replacement
                tracing::info!(
                    node_id,
                    username,
                    "password change detected, replacing per-user pool"
                );
                pools.remove(&key);
            }
        }

        // Enforce global user pool limits before creating a new pool.
        // This prevents resource exhaustion from a large number of distinct
        // users each creating their own pool and connections.
        {
            let pools = self.user_pools.lock();
            if self.max_user_pools > 0 && pools.len() >= self.max_user_pools {
                tracing::warn!(
                    node_id,
                    username,
                    max_user_pools = self.max_user_pools,
                    current = pools.len(),
                    "global user pool limit reached, rejecting new pool creation"
                );
                metrics::counter!("trident_user_pool_rejected_total", "reason" => "max_pools").increment(1);
                return None;
            }
            if self.max_user_connections > 0 {
                let total_conns = self.total_user_connections(&pools);
                if total_conns >= self.max_user_connections as i64 {
                    tracing::warn!(
                        node_id,
                        username,
                        max_user_connections = self.max_user_connections,
                        current = total_conns,
                        "global user connection limit reached, rejecting new pool creation"
                    );
                    metrics::counter!("trident_user_pool_rejected_total", "reason" => "max_connections").increment(1);
                    return None;
                }
            }
        }

        // Slow path: create a new pool for this (node, user) pair.
        // Pool creation happens outside the lock to avoid holding it during
        // potentially slow network operations (connecting to backend).
        let new_pool = factory.create_pool(node_id, username, password, database, extra_params)?;
        let pool_arc: Arc<dyn ConnectionPool> = Arc::from(new_pool);

        let mut pools = self.user_pools.lock();
        // Double-check: another task may have created it concurrently.
        // If so, we MUST verify the password hash matches — otherwise a
        // request with the wrong password could piggyback on a pool
        // created by a request with the correct password (auth bypass).
        if let Some(existing) = pools.get_mut(&key) {
            if password_hash_eq(&existing.password_hash, &pw_hash) {
                // Same password — reuse the existing pool (our freshly
                // created one will be dropped).
                existing.last_access = now;
                return Some(Arc::clone(&existing.pool));
            }
            // Password mismatch: another concurrent request created a pool
            // with a different password. Do NOT return it. Respect cooldown.
            if now < existing.replace_cooldown_until {
                tracing::warn!(
                    node_id,
                    username,
                    "concurrent pool creation race with password mismatch, rejecting (cooldown active)"
                );
                return None;
            }
            // Cooldown expired — replace with our pool (ours has the newer password)
            tracing::info!(
                node_id,
                username,
                "concurrent pool race: replacing pool with new credentials"
            );
            *existing = UserPoolEntry {
                pool: Arc::clone(&pool_arc),
                last_access: now,
                password_hash: pw_hash,
                replace_cooldown_until: now + POOL_REPLACE_COOLDOWN,
            };
            return Some(Arc::clone(&pool_arc));
        }

        // No existing entry — insert ours.
        pools.insert(key, UserPoolEntry {
            pool: Arc::clone(&pool_arc),
            last_access: now,
            password_hash: pw_hash,
            replace_cooldown_until: now + POOL_REPLACE_COOLDOWN,
        });
        Some(pool_arc)
    }

    fn pool_for_user_existing(
        &self,
        node_id: &str,
        username: &str,
        database: Option<&str>,
    ) -> Option<Arc<dyn ConnectionPool>> {
        if self.user_pool_factory.is_none() {
            return self.pool_for(node_id);
        }
        let db = database.unwrap_or("");
        // The key format is "node_id\0username\0db\0params". Since we don't
        // have extra_params during cleanup, match by the common prefix.
        // Multiple pools may exist for the same (node, user, db) with
        // different params; return the first match (during cleanup we only
        // need to find the pool to release a connection from).
        let prefix = format!("{}\0{}\0{}\0", node_id, username, db);
        let pools = self.user_pools.lock();
        pools.iter()
            .find(|(k, _)| k.starts_with(&prefix))
            .map(|(_, entry)| Arc::clone(&entry.pool))
    }

    fn remove_user_pool(
        &self,
        node_id: &str,
        username: &str,
        database: Option<&str>,
        extra_params: &HashMap<String, String>,
    ) {
        if self.user_pool_factory.is_none() {
            return;
        }
        let db = database.unwrap_or("");
        let params_key = normalize_extra_params_key(extra_params);
        let key = format!("{}\0{}\0{}\0{}", node_id, username, db, params_key);
        let mut pools = self.user_pools.lock();
        pools.remove(&key);
    }

    fn snapshot(&self) -> Vec<BackendNodeSnapshot> {
        let pools = self.pools.load();
        let user_pools = self.user_pools.lock();

        (self.health_snapshots)()
            .into_iter()
            .map(|mut snap| {
                // Base pool connections (service-account, used for health checks)
                if let Some(pool) = pools.get(&snap.node_id) {
                    snap.active_connections = pool.active_connections();
                }
                // Add per-user pool connections for this node
                if self.user_pool_factory.is_some() {
                    let prefix = format!("{}\0", snap.node_id);
                    let user_active: i64 = user_pools
                        .iter()
                        .filter(|(k, _)| k.starts_with(&prefix))
                        .map(|(_, entry)| entry.pool.active_connections())
                        .sum();
                    snap.active_connections = user_active;
                }
                snap
            })
            .collect()
    }
}

/// Emits per-node Prometheus gauges for connection-pool utilization
/// (`trident_pool_active_connections`, `trident_pool_max_size`) and, when
/// known, replication lag (`trident_node_replication_lag_ms`), based on a
/// `BackendNodeSnapshot` list (typically `PoolManager::snapshot`'s
/// output).
///
/// `max_pool_size` is the same for every node today (`config.pool` is a
/// single global setting applied to every `NodePool`, not per-node -- see
/// `main::run`), so it is taken as one shared value here rather than
/// per-node.
///
/// Intended to be called periodically from a background task (see
/// `main::run`), not from any per-query code path -- unlike
/// `active_connections` itself (already tracked live, at zero extra cost,
/// by `NodePool`), computing/exporting this as a gauge on every query
/// would be needless overhead for a value that only needs to be
/// reasonably fresh (e.g. every few seconds) for dashboards/alerting.
pub fn emit_pool_metrics(snapshot: &[BackendNodeSnapshot], max_pool_size: u32) {
    for node in snapshot {
        metrics::gauge!("trident_pool_active_connections", "node_id" => node.node_id.clone())
            .set(node.active_connections as f64);
        metrics::gauge!("trident_pool_max_size", "node_id" => node.node_id.clone()).set(max_pool_size as f64);
        if let Some(lag_ms) = node.replication_lag_ms {
            metrics::gauge!("trident_node_replication_lag_ms", "node_id" => node.node_id.clone())
                .set(lag_ms as f64);
        }
    }
}

// Credential passthrough pool manager is now integrated directly into
// `InMemoryPoolManager` via `set_user_pool_factory`. See `pool_for_user`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NodeType, PoolMode};
    use crate::pool::conn::PooledConnection;
    use crate::pool::pool::{ConnCleaner, ConnFactory, NodePool, PoolError};
    use std::sync::atomic::{AtomicI32, Ordering};

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

    fn make_pool(node_id: &str) -> Box<dyn ConnectionPool> {
        Box::new(NodePool::new(
            node_id,
            PoolMode::Transaction,
            10,
            CountingFactory {
                next_pid: AtomicI32::new(1),
            },
            NoopCleaner,
        ))
    }

    #[test]
    fn pool_for_returns_none_for_unknown_node() {
        let manager = InMemoryPoolManager::new(HashMap::new(), Vec::new);
        assert!(manager.pool_for("does-not-exist").is_none());
    }

    #[tokio::test]
    async fn pool_for_returns_registered_pool() {
        let mut pools: HashMap<String, Box<dyn ConnectionPool>> = HashMap::new();
        pools.insert("reader-1".to_string(), make_pool("reader-1"));
        let manager = InMemoryPoolManager::new(pools, Vec::new);

        let pool = manager.pool_for("reader-1").expect("pool should exist");
        let _conn = pool.acquire("s1").await.unwrap();
        assert_eq!(pool.active_connections(), 1);
    }

    #[test]
    fn emit_pool_metrics_does_not_panic_for_nodes_with_and_without_lag() {
        // No Prometheus recorder is installed in this test process (only
        // `main` installs the process-global one), so `metrics::gauge!`
        // falls back to a no-op recorder -- this test only exercises that
        // `emit_pool_metrics` never panics regardless of whether
        // `replication_lag_ms` is present, not the rendered output.
        let snapshot = vec![
            BackendNodeSnapshot {
                node_id: "writer".to_string(),
                node_type: NodeType::Writer,
                healthy: true,
                replay_lsn: 0,
                active_connections: 3,
                weight: 1,
                replication_lag_ms: None,
            },
            BackendNodeSnapshot {
                node_id: "reader-1".to_string(),
                node_type: NodeType::Reader,
                healthy: true,
                replay_lsn: 100,
                active_connections: 7,
                weight: 1,
                replication_lag_ms: Some(42),
            },
        ];
        emit_pool_metrics(&snapshot, 10);
    }

    #[tokio::test]
    async fn snapshot_merges_health_data_with_active_connections() {
        let mut pools: HashMap<String, Box<dyn ConnectionPool>> = HashMap::new();
        pools.insert("reader-1".to_string(), make_pool("reader-1"));
        let manager = InMemoryPoolManager::new(pools, || {
            vec![BackendNodeSnapshot {
                node_id: "reader-1".to_string(),
                node_type: NodeType::Reader,
                healthy: true,
                replay_lsn: 12345,
                active_connections: 0, // should be overwritten by the pool's real value
                weight: 5,
                replication_lag_ms: Some(10),
            }]
        });

        let pool = manager.pool_for("reader-1").unwrap();
        let _c1 = pool.acquire("s1").await.unwrap();
        let _c2 = pool.acquire("s2").await.unwrap();

        let snapshot = manager.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].node_id, "reader-1");
        assert_eq!(snapshot[0].replay_lsn, 12345);
        assert_eq!(snapshot[0].active_connections, 2);
        assert!(snapshot[0].healthy);
    }
}
