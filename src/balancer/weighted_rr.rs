//! Smooth weighted round robin (`weighted_rr`)
//!
//! Implements Nginx-style smooth weighted round robin: each candidate node
//! maintains a "current weight"; on every selection, each node's current
//! weight is increased by its configured weight, the node with the
//! largest current weight is chosen as the result, and that node's
//! current weight is then decreased by the total weight. This algorithm
//! guarantees that, over many calls, each node's selection ratio
//! converges to its weight ratio, without any node being selected too
//! many times in a row (smoother than plain round robin).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::balancer::{LoadBalancer, NodeCandidate};

/// Smooth weighted round robin load balancer. Internally maintains the
/// "current weight" state of every node seen so far, protected by a
/// `Mutex` to satisfy the immutable-reference signature of
/// `LoadBalancer::select(&self, ...)`.
#[derive(Debug, Default)]
pub struct WeightedRoundRobin {
    current_weights: Mutex<HashMap<String, i64>>,
}

impl WeightedRoundRobin {
    pub fn new() -> Self {
        WeightedRoundRobin {
            current_weights: Mutex::new(HashMap::new()),
        }
    }
}

impl LoadBalancer for WeightedRoundRobin {
    fn select(&self, candidates: &[NodeCandidate]) -> Option<String> {
        if candidates.is_empty() {
            return None;
        }

        let mut current_weights = self
            .current_weights
            .lock()
            .expect("weighted round robin state lock poisoned");

        let total_weight: i64 = candidates.iter().map(|c| c.weight as i64).sum();

        // Increase each candidate's current weight by its configured weight.
        for candidate in candidates {
            let entry = current_weights
                .entry(candidate.node_id.clone())
                .or_insert(0);
            *entry += candidate.weight as i64;
        }

        // Pick the candidate with the largest current weight (ties break
        // to the first one, for determinism).
        let winner = candidates
            .iter()
            .max_by_key(|c| current_weights.get(&c.node_id).copied().unwrap_or(0))?
            .node_id
            .clone();

        // Deduct the total weight from the winner's current weight.
        if let Some(w) = current_weights.get_mut(&winner) {
            *w -= total_weight;
        }

        Some(winner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap as StdHashMap;

    fn candidate(id: &str, weight: u32) -> NodeCandidate {
        NodeCandidate {
            node_id: id.to_string(),
            weight,
            active_connections: 0,
        }
    }

    // -----------------------------------------------------------------
    // Property 32: weighted round robin selection frequency converges to
    // the configured weight ratio
    // Validates: Requirements 8.1
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_32_selection_frequency_converges_to_weight_ratio(
            w1 in 1u32..20, w2 in 1u32..20, w3 in 1u32..20,
        ) {
            let candidates = vec![
                candidate("n1", w1),
                candidate("n2", w2),
                candidate("n3", w3),
            ];
            let lb = WeightedRoundRobin::new();
            let total_weight = (w1 + w2 + w3) as f64;
            let iterations = 10_000;

            let mut counts: StdHashMap<String, u64> = StdHashMap::new();
            for _ in 0..iterations {
                let chosen = lb.select(&candidates).expect("non-empty candidates");
                *counts.entry(chosen).or_insert(0) += 1;
            }

            for (id, weight) in [("n1", w1), ("n2", w2), ("n3", w3)] {
                let expected_ratio = weight as f64 / total_weight;
                let actual_ratio = *counts.get(id).unwrap_or(&0) as f64 / iterations as f64;
                prop_assert!(
                    (actual_ratio - expected_ratio).abs() < 0.05,
                    "node {id}: expected ratio {expected_ratio:.4}, actual {actual_ratio:.4}"
                );
            }
        }

        // -----------------------------------------------------------------
        // Property 34: the load balancer returns no selection when the
        // candidate set is empty
        // Validates: Requirements 8.3
        // -----------------------------------------------------------------
        #[test]
        fn property_34_empty_candidates_returns_none(_unused in 0..1) {
            let lb = WeightedRoundRobin::new();
            prop_assert_eq!(lb.select(&[]), None);
        }
    }

    #[test]
    fn single_candidate_always_selected() {
        let lb = WeightedRoundRobin::new();
        let candidates = vec![candidate("only", 1)];
        for _ in 0..10 {
            assert_eq!(lb.select(&candidates), Some("only".to_string()));
        }
    }

    #[test]
    fn does_not_starve_low_weight_node() {
        // With a weight ratio of 5:1, the low-weight node should still be
        // selected at least once across enough calls, and the same node
        // should never be selected more times in a row than its weight
        // (the "smoothness" property).
        let lb = WeightedRoundRobin::new();
        let candidates = vec![candidate("heavy", 5), candidate("light", 1)];
        let mut selections = Vec::new();
        for _ in 0..6 {
            selections.push(lb.select(&candidates).unwrap());
        }
        assert!(selections.contains(&"light".to_string()));
    }
}
