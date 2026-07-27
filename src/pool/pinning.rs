//! Connection pinning detection (`pinning`)
//!
//! Detects the set of operations that trigger pinning: `PREPARE`,
//! `DECLARE ... CURSOR` (holdable), `LISTEN`, `CREATE TEMP TABLE`,
//! `pg_advisory_lock()`, the `COPY` sub-protocol, messages exceeding
//! 16MB, and non-`LOCAL` `SET` commands.
//!
//! See design.md section 7.3 and Requirement 6.1 / Property 28.
//!
//! Note: this module only performs the pure-logic decision of "whether
//! pinning is triggered"; it does not directly depend on the `parser`
//! module's `SqlKind` (to avoid a circular dependency between modules,
//! and because the pinning triggers and SQL read/write classification are
//! two independent, orthogonal dimensions). Instead, it decides directly
//! from the SQL text / message size.

use std::sync::OnceLock;

use regex::Regex;

/// The specific reason a connection was pinned, for logging/debugging use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinningTrigger {
    Prepare,
    HoldableCursor,
    Listen,
    CreateTempTable,
    AdvisoryLock,
    Copy,
    LargeMessage,
    NonLocalSet,
    SequenceUsage,
}

fn prepare_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)^\s*PREPARE\b").unwrap())
}

fn declare_cursor_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Holdable cursor: either explicit WITH HOLD, or still treated as
    // requiring pinning by default (simplified handling: any
    // DECLARE ... CURSOR is treated as a trigger, because a cursor
    // without HOLD closes by default at transaction end, but its state
    // is still bound to the backend connection, so in Transaction mode it
    // still needs pinning to keep the cursor usable).
    RE.get_or_init(|| Regex::new(r"(?is)^\s*DECLARE\b.*\bCURSOR\b").unwrap())
}

fn listen_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)^\s*LISTEN\b").unwrap())
}

fn create_temp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)^\s*CREATE\s+(TEMP|TEMPORARY)\s+TABLE\b").unwrap()
    })
}

fn advisory_lock_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)\bpg_advisory_lock\w*\s*\(").unwrap())
}

fn copy_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)^\s*COPY\b").unwrap())
}

fn set_local_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)^\s*SET\s+LOCAL\b").unwrap())
}

fn set_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)^\s*SET\b").unwrap())
}

fn sequence_usage_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)\b(nextval|setval)\s*\(").unwrap())
}

/// Messages larger than this many bytes are treated as "large messages",
/// triggering pinning (see design.md section 7.3).
pub const LARGE_MESSAGE_THRESHOLD_BYTES: usize = 16 * 1024 * 1024; // 16MiB

/// Determines whether connection pinning is triggered based on SQL text,
/// returning the specific trigger reason (if multiple match, returns the
/// highest-priority/first match; callers only need to know "whether
/// pinning is required").
pub fn detects_pinning_trigger(sql: &str) -> Option<PinningTrigger> {
    // Fast path: determine the first keyword to skip irrelevant prefix-based
    // regexes. Most hot-path queries are SELECTs which can never match
    // PREPARE/DECLARE/LISTEN/CREATE TEMP/COPY/SET patterns.
    let trimmed = sql.trim_start();
    let first_kw_end = trimmed
        .bytes()
        .position(|b| !b.is_ascii_alphabetic())
        .unwrap_or(trimmed.len());
    let starts_with_select_like = first_kw_end >= 4 && {
        let kw = &trimmed[..first_kw_end];
        kw.eq_ignore_ascii_case("SELECT")
            || kw.eq_ignore_ascii_case("SHOW")
            || kw.eq_ignore_ascii_case("EXPLAIN")
    };

    if !starts_with_select_like {
        // Full check for statement types that could trigger pinning
        if prepare_re().is_match(sql) {
            return Some(PinningTrigger::Prepare);
        }
        if declare_cursor_re().is_match(sql) {
            return Some(PinningTrigger::HoldableCursor);
        }
        if listen_re().is_match(sql) {
            return Some(PinningTrigger::Listen);
        }
        if create_temp_re().is_match(sql) {
            return Some(PinningTrigger::CreateTempTable);
        }
        if copy_re().is_match(sql) {
            return Some(PinningTrigger::Copy);
        }
        if set_re().is_match(sql) && !set_local_re().is_match(sql) {
            return Some(PinningTrigger::NonLocalSet);
        }
    }

    // Body-scanning patterns apply regardless of the leading keyword
    // (e.g. SELECT nextval(...), SELECT pg_advisory_lock(...))
    if advisory_lock_re().is_match(sql) {
        return Some(PinningTrigger::AdvisoryLock);
    }
    if sequence_usage_re().is_match(sql) {
        return Some(PinningTrigger::SequenceUsage);
    }
    None
}

/// Determines whether pinning is triggered based on message body size
/// (large messages; see design.md section 7.3).
pub fn detects_large_message(message_len_bytes: usize) -> Option<PinningTrigger> {
    if message_len_bytes > LARGE_MESSAGE_THRESHOLD_BYTES {
        Some(PinningTrigger::LargeMessage)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -----------------------------------------------------------------
    // Property 28: an operation from the trigger set always marks the
    // connection as pinned
    // Validates: Requirements 6.1
    // -----------------------------------------------------------------

    fn pinning_statement_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("PREPARE stmt1 AS SELECT 1".to_string()),
            Just("prepare stmt1 (int) as select $1".to_string()),
            Just("DECLARE c1 CURSOR FOR SELECT * FROM t".to_string()),
            Just("DECLARE c1 CURSOR WITH HOLD FOR SELECT * FROM t".to_string()),
            Just("LISTEN channel1".to_string()),
            Just("CREATE TEMP TABLE t1 (id int)".to_string()),
            Just("CREATE TEMPORARY TABLE t1 (id int)".to_string()),
            Just("SELECT pg_advisory_lock(1)".to_string()),
            Just("SELECT pg_advisory_lock_shared(1, 2)".to_string()),
            Just("COPY t FROM STDIN".to_string()),
            Just("COPY t TO STDOUT".to_string()),
            Just("SELECT nextval('seq1')".to_string()),
            Just("SELECT setval('seq1', 100)".to_string()),
            Just("SET search_path = public".to_string()),
        ]
    }

    proptest! {
        #[test]
        fn property_28_pinning_triggers_detected(sql in pinning_statement_strategy()) {
            prop_assert!(detects_pinning_trigger(&sql).is_some());
        }

        #[test]
        fn property_28_large_message_triggers_pinning(
            size in (LARGE_MESSAGE_THRESHOLD_BYTES + 1)..(LARGE_MESSAGE_THRESHOLD_BYTES + 1000),
        ) {
            prop_assert!(detects_large_message(size).is_some());
        }

        #[test]
        fn property_28_small_message_does_not_trigger_pinning(
            size in 0usize..LARGE_MESSAGE_THRESHOLD_BYTES,
        ) {
            prop_assert!(detects_large_message(size).is_none());
        }
    }

    // -----------------------------------------------------------------
    // Unit tests: regular statements that should not trigger pinning
    // -----------------------------------------------------------------

    #[test]
    fn plain_select_does_not_trigger_pinning() {
        assert!(detects_pinning_trigger("SELECT * FROM t WHERE id = 1").is_none());
    }

    #[test]
    fn plain_insert_does_not_trigger_pinning() {
        assert!(detects_pinning_trigger("INSERT INTO t VALUES (1)").is_none());
    }

    #[test]
    fn set_local_does_not_trigger_pinning() {
        assert!(detects_pinning_trigger("SET LOCAL statement_timeout = 5000").is_none());
    }

    #[test]
    fn create_regular_table_does_not_trigger_pinning() {
        assert!(detects_pinning_trigger("CREATE TABLE t (id int)").is_none());
    }
}
