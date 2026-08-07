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
    /// `None` if no pool exists for this (node, user, database, params)
    /// combination. Used during session cleanup to avoid creating pools
    /// needlessly.
    fn pool_for_user_existing(
        &self,
        node_id: &str,
        _username: &str,
        _database: Option<&str>,
        _extra_params: &HashMap<String, String>,
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
    /// Tracks in-flight pool creations that have passed the limit check but
    /// haven't yet inserted into user_pools. Used to prevent concurrent
    /// bypass of max_user_pools.
    pending_pool_creates: std::sync::atomic::AtomicUsize,
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

/// Parameters excluded from the pool key because they are per-client
/// metadata that doesn't affect backend session state for query execution.
/// `application_name` is set per-checkout via SET and reset on release.
const POOL_KEY_EXCLUDED_PARAMS: &[&str] = &["application_name"];

/// Produces a deterministic, unambiguous string from connection-affecting
/// startup parameters for use as part of the pool key.
///
/// All forwarded parameters participate in the key (except those in
/// `POOL_KEY_EXCLUDED_PARAMS`). This ensures that any parameter that
/// affects backend session state produces a distinct pool identity.
///
/// Uses canonical lowercase for keys and length-prefixed encoding to
/// prevent structural collisions (values containing `,` or `=` cannot
/// produce false key matches).
fn normalize_extra_params_key(params: &HashMap<String, String>) -> String {
    let mut relevant: Vec<(String, &str)> = params
        .iter()
        .filter(|(k, _)| !POOL_KEY_EXCLUDED_PARAMS.contains(&k.to_lowercase().as_str()))
        .map(|(k, v)| (k.to_lowercase(), v.as_str()))
        .collect();
    relevant.sort_by(|(a, _), (b, _)| a.cmp(b));
    if relevant.is_empty() {
        String::new()
    } else {
        // Length-prefixed encoding: "klen:key:vlen:value|..."
        // This is unambiguous regardless of key/value content.
        relevant
            .iter()
            .map(|(k, v)| format!("{}:{}:{}:{}", k.len(), k, v.len(), v))
            .collect::<Vec<_>>()
            .join("|")
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
            pending_pool_creates: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Sets the global limit for per-user pools. `max_pools` limits the
    /// number of distinct (node, user, database) pools.
    /// Value of 0 means unlimited.
    pub fn set_user_pool_limits(&mut self, max_pools: usize) {
        self.max_user_pools = max_pools;
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
        pools.retain(|_key, entry| {
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
            // Dropping the pool drops every idle BackendConnection and closes
            // its socket. Checked-out connections keep the pool alive via Arc.
            false // evict
        });
        before - pools.len()
    }

    /// Returns the current number of per-user pools (for metrics/admin).
    pub fn user_pool_count(&self) -> usize {
        self.user_pools.lock().len()
    }

    /// Validates idle connections in all per-user pools. Returns the total
    /// number of stale connections discarded across all pools.
    pub async fn validate_idle_user_pools(&self) -> usize {
        // Collect pool Arcs under the lock, then validate outside it
        // to avoid holding the mutex across await points.
        let pool_arcs: Vec<Arc<dyn ConnectionPool>> = {
            let pools = self.user_pools.lock();
            pools.values().map(|entry| Arc::clone(&entry.pool)).collect()
        };
        let mut total_discarded = 0;
        for pool in pool_arcs {
            total_discarded += pool.validate_idle().await;
        }
        total_discarded
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
        // Drain the base pool before removal so in-flight acquires are
        // rejected while existing checked-out connections finish naturally.
        // Capture the Arc pointer so the RCU closure only removes this
        // exact incarnation (prevents ABA if a new pool with the same
        // node_id was added concurrently).
        let old_pool = {
            let current = self.pools.load();
            current.get(node_id).cloned()
        };
        let old_ptr = old_pool.as_ref().map(|p| Arc::as_ptr(p) as *const () as usize);
        if let Some(pool) = &old_pool {
            pool.drain();
        }

        let mut removed = false;
        self.pools.rcu(|current| {
            match (current.get(node_id), old_ptr) {
                (Some(existing), Some(expected_ptr))
                    if Arc::as_ptr(existing) as *const () as usize == expected_ptr =>
                {
                    removed = true;
                    let mut new_pools = (**current).clone();
                    new_pools.remove(node_id);
                    Arc::new(new_pools)
                }
                _ => {
                    // Node doesn't exist or is a different incarnation — no-op.
                    removed = false;
                    Arc::clone(current)
                }
            }
        });
        // Also drain and remove any per-user pools for this node
        if removed {
            let prefix = format!("{}\0", node_id);
            let mut user_pools = self.user_pools.lock();
            // Drain all per-user pools for this node before removing them
            for (k, entry) in user_pools.iter() {
                if k.starts_with(&prefix) {
                    entry.pool.drain();
                }
            }
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
        // removed nodes. We also capture the base pool pointer identity to
        // detect ABA scenarios (node removed and re-added with same name).
        let base_pool_ptr = {
            let pools = self.pools.load();
            let base = pools.get(node_id)?;
            Arc::as_ptr(base) as *const () as usize
        };

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

        // Fast path: pool already exists.
        // Also enforce max_user_pools atomically within the same lock scope
        // to prevent concurrent bypass of the limit.
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
                // Cooldown expired — allow replacement. Drain the old pool
                // so in-flight sessions can finish but no new connections
                // are handed out from it.
                tracing::info!(
                    node_id,
                    username,
                    "password change detected, replacing per-user pool"
                );
                if let Some(old_entry) = pools.remove(&key) {
                    old_entry.pool.drain();
                }
                // Replacement creation also reserves an in-flight slot so
                // pending accounting cannot underflow and concurrent creates
                // cannot bypass the global cap.
                self.pending_pool_creates
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            } else {
                // New pool needed — check limit while still holding the lock.
                // Include pending (in-flight) creations in the count to
                // prevent concurrent requests from all passing the check.
                let effective_count = pools.len()
                    + self.pending_pool_creates.load(std::sync::atomic::Ordering::SeqCst);
                if self.max_user_pools > 0 && effective_count >= self.max_user_pools {
                    tracing::warn!(
                        node_id,
                        username,
                        max_user_pools = self.max_user_pools,
                        current = pools.len(),
                        pending = effective_count - pools.len(),
                        "global user pool limit reached, rejecting new pool creation"
                    );
                    metrics::counter!("trident_user_pool_rejected_total", "reason" => "max_pools").increment(1);
                    return None;
                }
                // Reserve a slot by incrementing the pending counter.
                self.pending_pool_creates.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        // Slow path: create a new pool for this (node, user) pair.
        // Pool creation happens outside the lock to avoid holding it during
        // potentially slow network operations (connecting to backend).
        // Always decrement pending counter when done (success or failure).
        let new_pool = match factory.create_pool(node_id, username, password, database, extra_params) {
            Some(pool) => pool,
            None => {
                self.pending_pool_creates.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                return None;
            }
        };
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
                self.pending_pool_creates
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
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
                self.pending_pool_creates
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                return None;
            }
            // Cooldown expired — replace with our pool (ours has the newer password)
            tracing::info!(
                node_id,
                username,
                "concurrent pool race: replacing pool with new credentials"
            );
            // Drain the old pool before replacing
            existing.pool.drain();
            *existing = UserPoolEntry {
                pool: Arc::clone(&pool_arc),
                last_access: now,
                password_hash: pw_hash,
                replace_cooldown_until: now + POOL_REPLACE_COOLDOWN,
            };
            self.pending_pool_creates
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return Some(Arc::clone(&pool_arc));
        }

        // Re-check that the node still exists and is the same incarnation
        // (same Arc pointer) — it may have been removed and re-added
        // concurrently (ABA) between the initial check and pool creation.
        // Without this, a user pool created against the old node's address
        // could be inserted into the new node's namespace.
        let still_same = self.pools.load().get(node_id)
            .is_some_and(|p| Arc::as_ptr(p) as *const () as usize == base_pool_ptr);
        if !still_same {
            pool_arc.drain();
            self.pending_pool_creates
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return None;
        }

        // No existing entry — insert ours.
        pools.insert(key, UserPoolEntry {
            pool: Arc::clone(&pool_arc),
            last_access: now,
            password_hash: pw_hash,
            replace_cooldown_until: now + POOL_REPLACE_COOLDOWN,
        });
        self.pending_pool_creates
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        Some(pool_arc)
    }

    fn pool_for_user_existing(
        &self,
        node_id: &str,
        username: &str,
        database: Option<&str>,
        extra_params: &HashMap<String, String>,
    ) -> Option<Arc<dyn ConnectionPool>> {
        if self.user_pool_factory.is_none() {
            return self.pool_for(node_id);
        }
        let db = database.unwrap_or("");
        let params_key = normalize_extra_params_key(extra_params);
        let key = format!("{}\0{}\0{}\0{}", node_id, username, db, params_key);
        let pools = self.user_pools.lock();
        // Exact key lookup first — this is the correct pool identity.
        if let Some(entry) = pools.get(&key) {
            return Some(Arc::clone(&entry.pool));
        }
        // If extra_params is empty (caller didn't have them), fall back to
        // prefix match as a best-effort for backward compatibility.
        if extra_params.is_empty() {
            let prefix = format!("{}\0{}\0{}\0", node_id, username, db);
            return pools.iter()
                .find(|(k, _)| k.starts_with(&prefix))
                .map(|(_, entry)| Arc::clone(&entry.pool));
        }
        None
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
        if let Some(old_entry) = pools.remove(&key) {
            // Draining prevents new checkouts; dropping the final pool Arc
            // drops all idle BackendConnections and closes their sockets.
            old_entry.pool.drain();
        }
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
                    snap.active_connections += user_active;
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
    use crate::pool::conn::{test_utils::mock_backend_connection, BackendConnection};
    use crate::pool::pool::{ConnCleaner, ConnFactory, NodePool, PoolError};
    use std::sync::atomic::{AtomicI32, Ordering};

    struct CountingFactory {
        next_pid: AtomicI32,
    }

    impl ConnFactory for CountingFactory {
        async fn create(&self, node_id: &str) -> Result<BackendConnection, PoolError> {
            let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
            Ok(mock_backend_connection(node_id, pid).await)
        }
    }

    struct NoopCleaner;
    impl ConnCleaner for NoopCleaner {
        async fn clean(&self, _conn: &mut BackendConnection) -> Result<(), PoolError> {
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
