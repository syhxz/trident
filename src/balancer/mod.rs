//! Load balancing module (`balancer`)
//!
//! Selects a target node from a set of candidates according to a strategy
//! (weighted round robin / least connections).

pub mod least_conn;
pub mod weighted_rr;

pub use least_conn::LeastConnections;
pub use weighted_rr::WeightedRoundRobin;

/// The minimal set of information about a load-balancing candidate node.
///
/// In design.md, `LoadBalancer::select` accepts the `health` module's
/// `BackendNodeSnapshot`; however, per the task dependency order, the
/// `balancer` module (task 7) is implemented before the `health` module
/// (task 10), and is meant to remain a pure-logic module with no external
/// dependencies. So a lightweight struct containing only the fields
/// needed for the load-balancing decision is defined here; before calling
/// `LoadBalancer::select`, the Router layer maps `BackendNodeSnapshot` to
/// `NodeCandidate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCandidate {
    pub node_id: String,
    pub weight: u32,
    pub active_connections: i64,
}

pub trait LoadBalancer: Send + Sync {
    /// Selects a target node from the candidates; returns `None` if the
    /// candidate set is empty.
    fn select(&self, candidates: &[NodeCandidate]) -> Option<String>;
}

/// Enum-dispatch wrapper selecting between the two configured load-balancing
/// strategies (`LoadBalanceStrategy` in `config`), so the Router can be
/// instantiated with a single concrete `LoadBalancer` type regardless of
/// which strategy the operator chose at startup.
pub enum ConfiguredLoadBalancer {
    WeightedRoundRobin(WeightedRoundRobin),
    LeastConnections(LeastConnections),
}

impl LoadBalancer for ConfiguredLoadBalancer {
    fn select(&self, candidates: &[NodeCandidate]) -> Option<String> {
        match self {
            ConfiguredLoadBalancer::WeightedRoundRobin(lb) => lb.select(candidates),
            ConfiguredLoadBalancer::LeastConnections(lb) => lb.select(candidates),
        }
    }
}

impl ConfiguredLoadBalancer {
    pub fn from_strategy(strategy: crate::config::LoadBalanceStrategy) -> Self {
        match strategy {
            crate::config::LoadBalanceStrategy::WeightedRoundRobin => {
                ConfiguredLoadBalancer::WeightedRoundRobin(WeightedRoundRobin::new())
            }
            crate::config::LoadBalanceStrategy::LeastConnections => {
                ConfiguredLoadBalancer::LeastConnections(LeastConnections)
            }
        }
    }
}

#[cfg(test)]
mod configured_load_balancer_tests {
    use super::*;
    use crate::config::LoadBalanceStrategy;

    #[test]
    fn from_strategy_dispatches_to_weighted_round_robin() {
        let lb = ConfiguredLoadBalancer::from_strategy(LoadBalanceStrategy::WeightedRoundRobin);
        let candidates = vec![NodeCandidate {
            node_id: "n1".to_string(),
            weight: 1,
            active_connections: 0,
        }];
        assert_eq!(lb.select(&candidates), Some("n1".to_string()));
    }

    #[test]
    fn from_strategy_dispatches_to_least_connections() {
        let lb = ConfiguredLoadBalancer::from_strategy(LoadBalanceStrategy::LeastConnections);
        let candidates = vec![NodeCandidate {
            node_id: "n1".to_string(),
            weight: 1,
            active_connections: 0,
        }];
        assert_eq!(lb.select(&candidates), Some("n1".to_string()));
    }
}
