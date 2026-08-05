//! LSN tracking (`lsn`)
//!
//! Maintains each session's write LSN (Session_Write_LSN) and the global
//! write LSN (Global_Write_LSN).
//!
//! ## Global LSN staleness (by design)
//!
//! The `global_write_lsn` is only advanced when a session's write LSN is
//! actually resolved (either via pipeline, extension GUC, or lazy
//! resolution). Under `lazy_fallback: true`, a session that writes and
//! never subsequently reads from a reader will never resolve its pending
//! LSN, meaning `global_write_lsn` can lag behind the true WAL position.
//!
//! This is acceptable because:
//! - **Session consistency** uses only `session_write_lsn`, unaffected.
//! - **Global consistency** is conservative: a stale (lower) global LSN
//!   means readers need to have replayed *less*, not more — it may allow
//!   a slightly stale read but never violates monotonic-read guarantees
//!   for the writer session itself.
//! - The alternative (eagerly resolving every write's LSN) would defeat
//!   the purpose of `lazy_fallback` and re-introduce the overhead that
//!   the optimization was designed to eliminate.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::Mutex;

pub trait LsnTracker: Send + Sync {
    /// Called after a Writer write operation completes, to update the
    /// session and global write LSNs.
    fn record_write(&self, session_id: &str, lsn: u64);

    fn remove_session(&self, session_id: &str);

    fn session_write_lsn(&self, session_id: &str) -> u64;

    fn global_write_lsn(&self) -> u64;
}

/// Default `LsnTracker` implementation based on an in-memory `HashMap` plus
/// an atomic variable.
#[derive(Debug, Default)]
pub struct InMemoryLsnTracker {
    session_lsn: Mutex<HashMap<String, u64>>,
    global_lsn: AtomicU64,
}

impl InMemoryLsnTracker {
    pub fn new() -> Self {
        InMemoryLsnTracker {
            session_lsn: Mutex::new(HashMap::new()),
            global_lsn: AtomicU64::new(0),
        }
    }
}

impl LsnTracker for InMemoryLsnTracker {
    fn record_write(&self, session_id: &str, lsn: u64) {
        {
            let mut map = self.session_lsn.lock();
            let entry = map.entry(session_id.to_string()).or_insert(0);
            if lsn > *entry {
                *entry = lsn;
            }
        }

        // Monotonically advance the global LSN to at least `lsn` (a CAS
        // loop, safe under concurrent writes).
        let mut current = self.global_lsn.load(Ordering::SeqCst);
        while lsn > current {
            match self.global_lsn.compare_exchange(
                current,
                lsn,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    fn remove_session(&self, session_id: &str) {
        self.session_lsn
            .lock()
            .remove(session_id);
    }

    fn session_write_lsn(&self, session_id: &str) -> u64 {
        self.session_lsn
            .lock()
            .get(session_id)
            .copied()
            .unwrap_or(0)
    }

    fn global_write_lsn(&self) -> u64 {
        self.global_lsn.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap as StdHashMap;

    // -----------------------------------------------------------------
    // Property 9: the session write LSN is monotonically non-decreasing
    // Validates: Requirements 3.1
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_9_session_write_lsn_monotonic(lsns in prop::collection::vec(0u64..1_000_000, 1..50)) {
            let tracker = InMemoryLsnTracker::new();
            let mut prev = 0u64;
            for lsn in lsns {
                tracker.record_write("session-1", lsn);
                let current = tracker.session_write_lsn("session-1");
                prop_assert!(current >= prev);
                prev = current;
            }
        }

        // -----------------------------------------------------------------
        // Property 10: the global write LSN is never less than the
        // maximum of all session write LSNs
        // Validates: Requirements 3.2
        // -----------------------------------------------------------------
        #[test]
        fn property_10_global_lsn_at_least_max_of_sessions(
            events in prop::collection::vec((0usize..5, 0u64..1_000_000), 1..80)
        ) {
            let tracker = InMemoryLsnTracker::new();
            let mut known: StdHashMap<usize, u64> = StdHashMap::new();

            for (session_idx, lsn) in events {
                let session_id = format!("session-{session_idx}");
                tracker.record_write(&session_id, lsn);

                let entry = known.entry(session_idx).or_insert(0);
                if lsn > *entry {
                    *entry = lsn;
                }

                let max_known = known.values().copied().max().unwrap_or(0);
                prop_assert!(tracker.global_write_lsn() >= max_known);
            }
        }
    }

    #[test]
    fn unknown_session_defaults_to_zero() {
        let tracker = InMemoryLsnTracker::new();
        assert_eq!(tracker.session_write_lsn("never-seen"), 0);
        assert_eq!(tracker.global_write_lsn(), 0);
    }

    #[test]
    fn multiple_sessions_tracked_independently() {
        let tracker = InMemoryLsnTracker::new();
        tracker.record_write("a", 100);
        tracker.record_write("b", 50);
        assert_eq!(tracker.session_write_lsn("a"), 100);
        assert_eq!(tracker.session_write_lsn("b"), 50);
        assert_eq!(tracker.global_write_lsn(), 100);
    }

    #[test]
    fn out_of_order_writes_do_not_decrease_lsn() {
        let tracker = InMemoryLsnTracker::new();
        tracker.record_write("a", 100);
        tracker.record_write("a", 50); // an older LSN arrives
        assert_eq!(tracker.session_write_lsn("a"), 100);
        assert_eq!(tracker.global_write_lsn(), 100);
    }
}
