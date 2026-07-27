//! Least connections strategy (`least_conn`)
//!
//! Selects the candidate node with the smallest `active_connections / weight`
//! value.

use crate::balancer::{LoadBalancer, NodeCandidate};

/// Least-connections load balancer. Holds no extra state; computed
/// on-the-fly from the candidate snapshot passed in on each call.
#[derive(Debug, Default, Clone, Copy)]
pub struct LeastConnections;

impl LoadBalancer for LeastConnections {
    fn select(&self, candidates: &[NodeCandidate]) -> Option<String> {
        candidates
            .iter()
            .min_by(|a, b| {
                effective_load(a)
                    .partial_cmp(&effective_load(b))
                    .expect("effective_load should never be NaN for weight > 0")
            })
            .map(|c| c.node_id.clone())
    }
}

/// `active_connections / weight`; `weight` should always be > 0 (guaranteed
/// by config validation).
fn effective_load(candidate: &NodeCandidate) -> f64 {
    candidate.active_connections as f64 / candidate.weight.max(1) as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn candidate(id: &str, active_connections: i64, weight: u32) -> NodeCandidate {
        NodeCandidate {
            node_id: id.to_string(),
            weight,
            active_connections,
        }
    }

    // -----------------------------------------------------------------
    // Property 33: the least-connections strategy always selects the node
    // with the smallest load ratio
    // Validates: Requirements 8.2
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_33_selects_node_with_minimal_effective_load(
            candidates in prop::collection::vec(
                (1i64..1000, 1u32..50),
                1..10,
            )
        ) {
            let nodes: Vec<NodeCandidate> = candidates
                .into_iter()
                .enumerate()
                .map(|(i, (conns, weight))| candidate(&format!("n{i}"), conns, weight))
                .collect();

            let lb = LeastConnections;
            let selected_id = lb.select(&nodes).expect("non-empty candidates");
            let selected = nodes.iter().find(|c| c.node_id == selected_id).unwrap();
            let selected_load = effective_load(selected);

            for other in &nodes {
                prop_assert!(selected_load <= effective_load(other) + 1e-9);
            }
        }

        // -----------------------------------------------------------------
        // Property 34: the load balancer returns no selection when the
        // candidate set is empty
        // Validates: Requirements 8.3
        // -----------------------------------------------------------------
        #[test]
        fn property_34_empty_candidates_returns_none(_unused in 0..1) {
            let lb = LeastConnections;
            prop_assert_eq!(lb.select(&[]), None);
        }
    }

    #[test]
    fn prefers_lower_connections_at_equal_weight() {
        let lb = LeastConnections;
        let candidates = vec![candidate("busy", 10, 1), candidate("idle", 1, 1)];
        assert_eq!(lb.select(&candidates), Some("idle".to_string()));
    }

    #[test]
    fn higher_weight_absorbs_more_connections() {
        let lb = LeastConnections;
        // n1: 8/4=2.0, n2: 3/1=3.0 -> n1 should win despite more raw connections
        let candidates = vec![candidate("n1", 8, 4), candidate("n2", 3, 1)];
        assert_eq!(lb.select(&candidates), Some("n1".to_string()));
    }

    #[test]
    fn zero_active_connections_is_valid_minimum() {
        let lb = LeastConnections;
        let candidates = vec![candidate("n1", 0, 1), candidate("n2", 5, 1)];
        assert_eq!(lb.select(&candidates), Some("n1".to_string()));
    }
}
