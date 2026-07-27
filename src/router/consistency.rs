//! Consistency checker (`consistency`)
//!
//! Determines, given a consistency level and LSN thresholds, which candidate
//! Reader nodes are eligible to serve a query. See design.md section 5 and
//! Requirements 3.3-3.7.

use crate::config::ConsistencyLevel;
use crate::health::BackendNodeSnapshot;

/// Checks candidate Reader nodes against a given consistency level.
pub trait ConsistencyChecker {
    /// Returns the node ids of readers eligible under the given consistency
    /// level and LSN thresholds.
    fn eligible_readers(
        &self,
        level: ConsistencyLevel,
        session_write_lsn: u64,
        global_write_lsn: u64,
        readers: &[BackendNodeSnapshot],
    ) -> Vec<String>;
}

/// Default `ConsistencyChecker` implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct LsnConsistencyChecker;

impl ConsistencyChecker for LsnConsistencyChecker {
    fn eligible_readers(
        &self,
        level: ConsistencyLevel,
        session_write_lsn: u64,
        global_write_lsn: u64,
        readers: &[BackendNodeSnapshot],
    ) -> Vec<String> {
        match level {
            // Eventual consistency: return all candidates, no LSN filtering.
            ConsistencyLevel::Eventual => readers.iter().map(|r| r.node_id.clone()).collect(),
            ConsistencyLevel::Session => readers
                .iter()
                .filter(|r| r.replay_lsn >= session_write_lsn)
                .map(|r| r.node_id.clone())
                .collect(),
            ConsistencyLevel::Global => readers
                .iter()
                .filter(|r| r.replay_lsn >= global_write_lsn)
                .map(|r| r.node_id.clone())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeType;
    use proptest::prelude::*;

    fn reader(node_id: &str, replay_lsn: u64) -> BackendNodeSnapshot {
        BackendNodeSnapshot {
            node_id: node_id.to_string(),
            node_type: NodeType::Reader,
            healthy: true,
            replay_lsn,
            active_connections: 0,
            weight: 1,
            replication_lag_ms: None,
        }
    }

    fn readers_strategy() -> impl Strategy<Value = Vec<(String, u64)>> {
        prop::collection::vec((0u64..1_000_000, 0u64..1_000_000), 0..10).prop_map(|pairs| {
            pairs
                .into_iter()
                .enumerate()
                .map(|(i, (lsn, _))| (format!("reader-{i}"), lsn))
                .collect()
        })
    }

    // -----------------------------------------------------------------
    // Property 11: Eventual consistency never filters candidate readers
    // Validates: Requirements 3.3
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_11_eventual_returns_all_candidates(
            readers in readers_strategy(),
            session_lsn in 0u64..1_000_000,
            global_lsn in 0u64..1_000_000,
        ) {
            let snapshots: Vec<BackendNodeSnapshot> = readers
                .iter()
                .map(|(id, lsn)| reader(id, *lsn))
                .collect();
            let checker = LsnConsistencyChecker;
            let eligible = checker.eligible_readers(
                ConsistencyLevel::Eventual,
                session_lsn,
                global_lsn,
                &snapshots,
            );
            prop_assert_eq!(eligible.len(), snapshots.len());
            for snap in &snapshots {
                prop_assert!(eligible.contains(&snap.node_id));
            }
        }

        // -----------------------------------------------------------------
        // Property 12: Session/Global consistency filtering is exact
        // Validates: Requirements 3.4, 3.5
        // -----------------------------------------------------------------
        #[test]
        fn property_12_session_filtering_is_exact(
            readers in readers_strategy(),
            session_lsn in 0u64..1_000_000,
            global_lsn in 0u64..1_000_000,
        ) {
            let snapshots: Vec<BackendNodeSnapshot> = readers
                .iter()
                .map(|(id, lsn)| reader(id, *lsn))
                .collect();
            let checker = LsnConsistencyChecker;

            let eligible_session = checker.eligible_readers(
                ConsistencyLevel::Session,
                session_lsn,
                global_lsn,
                &snapshots,
            );
            let expected_session: Vec<String> = snapshots
                .iter()
                .filter(|s| s.replay_lsn >= session_lsn)
                .map(|s| s.node_id.clone())
                .collect();
            prop_assert_eq!(
                eligible_session.iter().collect::<std::collections::HashSet<_>>(),
                expected_session.iter().collect::<std::collections::HashSet<_>>()
            );

            let eligible_global = checker.eligible_readers(
                ConsistencyLevel::Global,
                session_lsn,
                global_lsn,
                &snapshots,
            );
            let expected_global: Vec<String> = snapshots
                .iter()
                .filter(|s| s.replay_lsn >= global_lsn)
                .map(|s| s.node_id.clone())
                .collect();
            prop_assert_eq!(
                eligible_global.iter().collect::<std::collections::HashSet<_>>(),
                expected_global.iter().collect::<std::collections::HashSet<_>>()
            );
        }
    }

    // -----------------------------------------------------------------
    // Unit tests
    // -----------------------------------------------------------------

    #[test]
    fn empty_candidates_returns_empty_for_any_level() {
        let checker = LsnConsistencyChecker;
        for level in [
            ConsistencyLevel::Eventual,
            ConsistencyLevel::Session,
            ConsistencyLevel::Global,
        ] {
            assert!(checker.eligible_readers(level, 100, 200, &[]).is_empty());
        }
    }

    #[test]
    fn session_level_excludes_lagging_readers() {
        let checker = LsnConsistencyChecker;
        let readers = vec![reader("r1", 50), reader("r2", 150)];
        let eligible = checker.eligible_readers(ConsistencyLevel::Session, 100, 100, &readers);
        assert_eq!(eligible, vec!["r2".to_string()]);
    }

    #[test]
    fn global_level_excludes_lagging_readers() {
        let checker = LsnConsistencyChecker;
        let readers = vec![reader("r1", 50), reader("r2", 300)];
        let eligible = checker.eligible_readers(ConsistencyLevel::Global, 100, 200, &readers);
        assert_eq!(eligible, vec!["r2".to_string()]);
    }
}
