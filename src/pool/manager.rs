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

    /// Aggregates the `BackendNodeSnapshot` for every node (including the
    /// health state, replay LSN, and replication lag produced by the
    /// Health module, plus the `active_connections` maintained by this
    /// manager), for use by the Router/Balancer.
    fn snapshot(&self) -> Vec<BackendNodeSnapshot>;
}

/// Default `PoolManager` implementation based on an in-memory `HashMap`.
///
/// Stores each node's pool as an `Arc<dyn ConnectionPool>`, allowing
/// dynamic addition/removal of nodes at runtime via atomic swap.
pub struct InMemoryPoolManager {
    pools: ArcSwap<HashMap<String, Arc<dyn ConnectionPool>>>,
    /// The data source providing the latest health-check snapshot
    /// (excluding `active_connections`); typically a closure wrapping
    /// `health::HealthChecker::snapshot`.
    health_snapshots: Box<dyn Fn() -> Vec<BackendNodeSnapshot> + Send + Sync>,
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
        }
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
        removed
    }
}

impl PoolManager for InMemoryPoolManager {
    fn pool_for(&self, node_id: &str) -> Option<Arc<dyn ConnectionPool>> {
        let pools = self.pools.load();
        pools.get(node_id).cloned()
    }

    fn snapshot(&self) -> Vec<BackendNodeSnapshot> {
        let pools = self.pools.load();
        (self.health_snapshots)()
            .into_iter()
            .map(|mut snap| {
                if let Some(pool) = pools.get(&snap.node_id) {
                    snap.active_connections = pool.active_connections();
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
