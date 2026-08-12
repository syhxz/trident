//! LSN tracking (`lsn`)
//!
//! Maintains each session's write LSN (Session_Write_LSN) and the global
//! write LSN (Global_Write_LSN).
//!
//! ## Global LSN staleness mitigation
//!
//! The `global_write_lsn` is advanced from two sources:
//! 1. Session LSN resolution (pipeline, extension GUC, or lazy resolution)
//! 2. Health checker Writer probes (`advance_global_lsn`)
//!
//! The health checker periodically queries the Writer's actual WAL position
//! and advances the global floor. This ensures that even under
//! `lazy_fallback: true`, where a write-only session may never resolve its
//! pending LSN, the global watermark stays within one health-check interval
//! of the Writer's true position.
//!
//! **Bounded staleness**: Global consistency reads may see data up to
//! `health.check_interval` old (typically 3s) rather than unbounded
//! staleness. This is a practical trade-off: strict linearizability would
//! require eagerly resolving every write's LSN, defeating the purpose of
//! `lazy_fallback`.

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

    /// Advances the global write LSN to at least `lsn` without associating
    /// it with any session. Used by the health checker to keep the global
    /// watermark current based on the Writer's actual WAL position,
    /// preventing staleness when sessions with `pending_write` never
    /// resolve their LSN (the "lazy_fallback Global consistency gap").
    fn advance_global_lsn(&self, lsn: u64);

    /// Resets the global write LSN to `lsn`, even if it is lower than the
    /// current value. Used when a Writer failover or timeline switch is
    /// detected — the new Writer may have a lower LSN than the old one.
    /// Without this, Global consistency reads would block forever waiting
    /// for the new Writer to reach the old watermark.
    fn reset_global_lsn(&self, lsn: u64);
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

    fn advance_global_lsn(&self, lsn: u64) {
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

    fn reset_global_lsn(&self, lsn: u64) {
        self.global_lsn.store(lsn, Ordering::SeqCst);
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

    #[test]
    fn advance_global_lsn_raises_floor_without_session() {
        let tracker = InMemoryLsnTracker::new();
        assert_eq!(tracker.global_write_lsn(), 0);

        // Advance global to 500 (simulates health checker observing Writer WAL)
        tracker.advance_global_lsn(500);
        assert_eq!(tracker.global_write_lsn(), 500);

        // A session write at a lower LSN does not decrease global
        tracker.record_write("a", 200);
        assert_eq!(tracker.global_write_lsn(), 500);
        assert_eq!(tracker.session_write_lsn("a"), 200);

        // A session write above the floor advances global further
        tracker.record_write("b", 700);
        assert_eq!(tracker.global_write_lsn(), 700);

        // advance_global_lsn below current is a no-op
        tracker.advance_global_lsn(300);
        assert_eq!(tracker.global_write_lsn(), 700);
    }
}
