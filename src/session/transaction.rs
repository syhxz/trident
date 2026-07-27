//! Transaction-split state machine (`transaction`)
//!
//! Decides whether a read-only transaction is routed to a Reader and when
//! it must be upgraded to the Writer. See design.md chapter 6,
//! "Transaction Splitting".

use crate::session::session::IsolationLevel;

/// The read/write kind of a single statement within a transaction (used by
/// the Tx_Split_Engine's decision logic; kept decoupled from
/// `parser::SqlKind` so the `session` module does not depend on the
/// `parser` module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    Read,
    Write,
}

/// The routing action returned by `route_statement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxRouteAction {
    /// Route to the Reader_Node (staying in, or entering for the first
    /// time, TX_READING).
    RouteToReader,
    /// Route to the Writer_Node (staying in TX_WRITING/locked state, or
    /// deciding for the first time to route the whole transaction to the
    /// Writer).
    RouteToWriter,
    /// Upgrade from Reader to Writer: the caller must, in order:
    /// 1) send `ROLLBACK` to the current Reader_Node;
    /// 2) acquire a connection from the Writer_Node's pool and send `BEGIN`;
    /// 3) send the current write operation to the Writer_Node.
    UpgradeReaderToWriter,
}

/// Parsed options from `BEGIN` / `START TRANSACTION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeginOptions {
    pub isolation: IsolationLevel,
    pub read_only: bool,
}

/// Transaction-split state (one instance per explicit transaction).
#[derive(Debug, Clone)]
pub struct TxSplitState {
    /// Whether the first statement has already been processed (i.e. has
    /// left the "pending" phase).
    pub active: bool,
    /// Whether the transaction is currently routed to the Reader_Node
    /// (only meaningful when `active = true`).
    pub on_reader: bool,
    /// Whether the previous `route_statement` call triggered a
    /// read->write upgrade (for the caller's observation/logging use).
    pub need_upgrade: bool,
    pub isolation: IsolationLevel,

    read_only: bool,
    enable_split: bool,
    split_respects_consistency: bool,
    begin_sql: String,
}

impl TxSplitState {
    /// Creates a "pending" state: `BEGIN` has arrived but has not yet been
    /// sent to any backend, awaiting the first statement.
    ///
    /// See Requirement 4.1.
    pub fn pending(
        isolation: IsolationLevel,
        read_only: bool,
        enable_split: bool,
        split_respects_consistency: bool,
    ) -> Self {
        Self::pending_with_sql(
            isolation,
            read_only,
            enable_split,
            split_respects_consistency,
            canonical_begin_sql(isolation, read_only),
        )
    }

    /// Creates a pending state while preserving the exact BEGIN text that
    /// must later be replayed to the selected backend.
    pub fn pending_with_sql(
        isolation: IsolationLevel,
        read_only: bool,
        enable_split: bool,
        split_respects_consistency: bool,
        begin_sql: impl Into<String>,
    ) -> Self {
        TxSplitState {
            active: false,
            on_reader: false,
            need_upgrade: false,
            isolation,
            read_only,
            enable_split,
            split_respects_consistency,
            begin_sql: begin_sql.into(),
        }
    }

    pub fn begin_sql(&self) -> &str {
        &self.begin_sql
    }
}

/// Parses a top-level `BEGIN` or `START TRANSACTION` command. PostgreSQL's
/// option order is flexible, so isolation/read-only flags are detected in
/// normalized whitespace rather than by one rigid prefix.
pub fn parse_begin_options(sql: &str) -> Option<BeginOptions> {
    let normalized = normalize_transaction_sql(sql);
    if !(normalized == "BEGIN"
        || normalized.starts_with("BEGIN ")
        || normalized == "START TRANSACTION"
        || normalized.starts_with("START TRANSACTION "))
    {
        return None;
    }

    let isolation = if normalized.contains("ISOLATION LEVEL SERIALIZABLE") {
        IsolationLevel::Serializable
    } else if normalized.contains("ISOLATION LEVEL REPEATABLE READ") {
        IsolationLevel::RepeatableRead
    } else {
        IsolationLevel::ReadCommitted
    };
    Some(BeginOptions {
        isolation,
        read_only: normalized.contains("READ ONLY"),
    })
}

/// Returns the PostgreSQL completion tag for a command that ends the whole
/// transaction. `ROLLBACK TO [SAVEPOINT]` is deliberately excluded.
pub fn transaction_end_tag(sql: &str) -> Option<&'static str> {
    let normalized = normalize_transaction_sql(sql);
    if normalized == "COMMIT"
        || normalized == "COMMIT WORK"
        || normalized == "COMMIT TRANSACTION"
        || normalized == "END"
        || normalized == "END WORK"
        || normalized == "END TRANSACTION"
    {
        Some("COMMIT")
    } else if normalized == "ROLLBACK"
        || normalized == "ROLLBACK WORK"
        || normalized == "ROLLBACK TRANSACTION"
        || normalized == "ABORT"
        || normalized == "ABORT WORK"
        || normalized == "ABORT TRANSACTION"
    {
        Some("ROLLBACK")
    } else {
        None
    }
}

fn normalize_transaction_sql(sql: &str) -> String {
    sql.trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}

fn canonical_begin_sql(isolation: IsolationLevel, read_only: bool) -> String {
    let isolation = match isolation {
        IsolationLevel::ReadCommitted => "READ COMMITTED",
        IsolationLevel::RepeatableRead => "REPEATABLE READ",
        IsolationLevel::Serializable => "SERIALIZABLE",
    };
    format!(
        "BEGIN ISOLATION LEVEL {isolation} {}",
        if read_only { "READ ONLY" } else { "READ WRITE" }
    )
}

/// Pure-logic implementation of the transaction-split state machine (no
/// I/O; does not hold a connection).
pub struct TxSplitEngine;

impl TxSplitEngine {
    /// Processes the next statement in the transaction (possibly the
    /// first), returning a routing action and updating `state`.
    ///
    /// `consistency_check` is a lazily-evaluated consistency-check
    /// closure, only invoked when actually needed for the decision.
    pub fn route_statement(
        state: &mut TxSplitState,
        stmt: StatementKind,
        consistency_check: impl FnOnce() -> bool,
    ) -> TxRouteAction {
        state.need_upgrade = false;

        // An initial decision has already been made: the transaction is
        // either in TX_READING or already locked to the Writer
        // (TX_WRITING / consistency check failed / non-split scenario).
        if state.active {
            if state.on_reader {
                // TX_READING: a write operation triggers an upgrade to the
                // Writer (Requirement 4.5).
                if stmt == StatementKind::Write {
                    state.on_reader = false;
                    state.need_upgrade = true;
                    return TxRouteAction::UpgradeReaderToWriter;
                }
                return TxRouteAction::RouteToReader;
            }
            // TX_WRITING or already locked: all subsequent statements
            // (including read-only SELECTs) stay on the Writer
            // (Requirement 4.6, Property 20).
            return TxRouteAction::RouteToWriter;
        }

        // No initial decision has been made yet: this call is for the
        // transaction's first statement.

        // Requirement 4.9 / Property 23: with transaction splitting
        // disabled, every statement of any explicit transaction routes to
        // the Writer_Node (highest priority, overriding the READ ONLY and
        // isolation-level checks below).
        if !state.enable_split {
            state.active = true;
            state.on_reader = false;
            return TxRouteAction::RouteToWriter;
        }

        // Requirement 4.8 / Property 22: a transaction declared READ ONLY
        // (any isolation level) routes entirely to the Reader if the
        // consistency check passes, otherwise entirely to the Writer.
        if state.read_only {
            state.active = true;
            if consistency_check() {
                state.on_reader = true;
                return TxRouteAction::RouteToReader;
            }
            state.on_reader = false;
            return TxRouteAction::RouteToWriter;
        }

        // Requirement 4.7 / Property 21: a non-read-only REPEATABLE READ /
        // SERIALIZABLE transaction is never split; it routes entirely to
        // the Writer.
        if state.isolation != IsolationLevel::ReadCommitted {
            state.active = true;
            state.on_reader = false;
            return TxRouteAction::RouteToWriter;
        }

        // READ COMMITTED with splitting enabled: decide based on the kind
        // of the first statement.
        //
        // NOTE (Issue #4 — "wasteful" routing, accepted by design):
        // When `split_respects_consistency = true` and the consistency
        // check fails, the initial read will be routed to the Writer
        // instead of a Reader. This means the transaction-split
        // optimization yields no benefit for that particular transaction.
        // This is intentional: correctness (honoring session/global LSN
        // consistency) takes priority over the split optimization.
        // The "waste" is limited to one extra Router decision per
        // transaction that falls into this case — the actual query still
        // executes correctly on the Writer. Disabling this via
        // `split_respects_consistency = false` trades consistency for
        // maximum reader utilization (appropriate only for Eventual).
        match stmt {
            StatementKind::Write => {
                // Requirement 4.4 / Property 18: a write-first transaction
                // routes entirely to the Writer.
                state.active = true;
                state.on_reader = false;
                TxRouteAction::RouteToWriter
            }
            StatementKind::Read => {
                state.active = true;
                let passes = if state.split_respects_consistency {
                    consistency_check()
                } else {
                    true
                };
                if passes {
                    // Requirement 4.2 / Property 16
                    state.on_reader = true;
                    TxRouteAction::RouteToReader
                } else {
                    // Requirement 4.3 / Property 17: the consistency check
                    // failed, so the whole transaction routes to the
                    // Writer, and splitting is never attempted again.
                    state.on_reader = false;
                    TxRouteAction::RouteToWriter
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn isolation_strategy() -> impl Strategy<Value = IsolationLevel> {
        prop_oneof![
            Just(IsolationLevel::ReadCommitted),
            Just(IsolationLevel::RepeatableRead),
            Just(IsolationLevel::Serializable),
        ]
    }

    fn statement_kind_strategy() -> impl Strategy<Value = StatementKind> {
        prop_oneof![Just(StatementKind::Read), Just(StatementKind::Write)]
    }

    // -----------------------------------------------------------------
    // Property 16: a read-first transaction splits to the Reader when the
    // consistency check passes
    // Validates: Requirements 4.2
    // -----------------------------------------------------------------
    proptest! {
        #[test]
        fn property_16_read_start_splits_to_reader_when_consistent(_unused in 0..1) {
            let mut state = TxSplitState::pending(IsolationLevel::ReadCommitted, false, true, true);
            let action = TxSplitEngine::route_statement(&mut state, StatementKind::Read, || true);
            prop_assert_eq!(action, TxRouteAction::RouteToReader);
            prop_assert!(state.active);
            prop_assert!(state.on_reader);
        }

        // -----------------------------------------------------------------
        // Property 17: if a read-first transaction fails the consistency
        // check, the whole transaction routes to the Writer and splitting
        // is never attempted again
        // Validates: Requirements 4.3
        // -----------------------------------------------------------------
        #[test]
        fn property_17_read_start_falls_back_to_writer_forever(
            subsequent in prop::collection::vec(statement_kind_strategy(), 0..10)
        ) {
            let mut state = TxSplitState::pending(IsolationLevel::ReadCommitted, false, true, true);
            let action = TxSplitEngine::route_statement(&mut state, StatementKind::Read, || false);
            prop_assert_eq!(action, TxRouteAction::RouteToWriter);

            for stmt in subsequent {
                let action = TxSplitEngine::route_statement(&mut state, stmt, || true);
                prop_assert_eq!(action, TxRouteAction::RouteToWriter);
            }
        }

        // -----------------------------------------------------------------
        // Property 18: a write-first transaction routes entirely to the
        // Writer
        // Validates: Requirements 4.4
        // -----------------------------------------------------------------
        #[test]
        fn property_18_write_start_routes_to_writer(_unused in 0..1) {
            let mut state = TxSplitState::pending(IsolationLevel::ReadCommitted, false, true, true);
            let action = TxSplitEngine::route_statement(&mut state, StatementKind::Write, || true);
            prop_assert_eq!(action, TxRouteAction::RouteToWriter);
            prop_assert!(state.active);
            prop_assert!(!state.on_reader);
        }

        // -----------------------------------------------------------------
        // Property 19: the read-then-write upgrade follows the correct
        // operation order
        // Validates: Requirements 4.5
        // -----------------------------------------------------------------
        #[test]
        fn property_19_read_then_write_upgrades(
            reads_before in 0usize..5,
        ) {
            let mut state = TxSplitState::pending(IsolationLevel::ReadCommitted, false, true, true);
            let first = TxSplitEngine::route_statement(&mut state, StatementKind::Read, || true);
            prop_assert_eq!(first, TxRouteAction::RouteToReader);

            for _ in 0..reads_before {
                let action = TxSplitEngine::route_statement(&mut state, StatementKind::Read, || true);
                prop_assert_eq!(action, TxRouteAction::RouteToReader);
            }

            let upgrade = TxSplitEngine::route_statement(&mut state, StatementKind::Write, || true);
            prop_assert_eq!(upgrade, TxRouteAction::UpgradeReaderToWriter);
            prop_assert!(state.active);
            prop_assert!(!state.on_reader);
        }

        // -----------------------------------------------------------------
        // Property 20: once upgraded to the Writer, a transaction never
        // reverts to the Reader
        // Validates: Requirements 4.6
        // -----------------------------------------------------------------
        #[test]
        fn property_20_never_reverts_to_reader_after_upgrade(
            subsequent in prop::collection::vec(statement_kind_strategy(), 0..10)
        ) {
            let mut state = TxSplitState::pending(IsolationLevel::ReadCommitted, false, true, true);
            TxSplitEngine::route_statement(&mut state, StatementKind::Read, || true);
            TxSplitEngine::route_statement(&mut state, StatementKind::Write, || true);

            for stmt in subsequent {
                let action = TxSplitEngine::route_statement(&mut state, stmt, || true);
                prop_assert_eq!(action, TxRouteAction::RouteToWriter);
            }
        }

        // -----------------------------------------------------------------
        // Property 21: a non-read-only RR/Serializable transaction routes
        // entirely to the Writer
        // Validates: Requirements 4.7
        // -----------------------------------------------------------------
        #[test]
        fn property_21_non_readonly_rr_serializable_routes_writer(
            isolation in prop_oneof![Just(IsolationLevel::RepeatableRead), Just(IsolationLevel::Serializable)],
            stmts in prop::collection::vec(statement_kind_strategy(), 1..10),
        ) {
            let mut state = TxSplitState::pending(isolation, false, true, true);
            for stmt in stmts {
                let action = TxSplitEngine::route_statement(&mut state, stmt, || true);
                prop_assert_eq!(action, TxRouteAction::RouteToWriter);
            }
        }

        // -----------------------------------------------------------------
        // Property 22: a READ ONLY transaction routes entirely to the
        // Reader when the consistency check passes
        // Validates: Requirements 4.8
        // -----------------------------------------------------------------
        #[test]
        fn property_22_read_only_tx_routes_reader_when_consistent(
            isolation in isolation_strategy(),
            reads in prop::collection::vec(Just(StatementKind::Read), 1..10),
        ) {
            let mut state = TxSplitState::pending(isolation, true, true, true);
            for stmt in reads {
                let action = TxSplitEngine::route_statement(&mut state, stmt, || true);
                prop_assert_eq!(action, TxRouteAction::RouteToReader);
            }
        }

        // -----------------------------------------------------------------
        // Property 23: with transaction splitting disabled, every explicit
        // transaction routes entirely to the Writer
        // Validates: Requirements 4.9
        // -----------------------------------------------------------------
        #[test]
        fn property_23_split_disabled_always_writer(
            isolation in isolation_strategy(),
            read_only in any::<bool>(),
            stmts in prop::collection::vec(statement_kind_strategy(), 1..10),
        ) {
            let mut state = TxSplitState::pending(isolation, read_only, false, true);
            for stmt in stmts {
                let action = TxSplitEngine::route_statement(&mut state, stmt, || true);
                prop_assert_eq!(action, TxRouteAction::RouteToWriter);
            }
        }
    }

    // -----------------------------------------------------------------
    // Unit tests
    // -----------------------------------------------------------------

    #[test]
    fn parses_begin_and_start_transaction_options() {
        assert_eq!(
            parse_begin_options("BEGIN"),
            Some(BeginOptions {
                isolation: IsolationLevel::ReadCommitted,
                read_only: false,
            })
        );
        assert_eq!(
            parse_begin_options(
                "start   transaction read only, isolation level repeatable read;"
            ),
            Some(BeginOptions {
                isolation: IsolationLevel::RepeatableRead,
                read_only: true,
            })
        );
        assert_eq!(
            parse_begin_options("BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE"),
            Some(BeginOptions {
                isolation: IsolationLevel::Serializable,
                read_only: false,
            })
        );
        assert_eq!(parse_begin_options("SELECT 'BEGIN'"), None);
    }

    #[test]
    fn transaction_end_parser_excludes_rollback_to_savepoint() {
        assert_eq!(transaction_end_tag("COMMIT WORK;"), Some("COMMIT"));
        assert_eq!(transaction_end_tag("ABORT"), Some("ROLLBACK"));
        assert_eq!(transaction_end_tag("ROLLBACK TO SAVEPOINT s1"), None);
    }

    #[test]
    fn begin_creates_pending_state_not_yet_active() {
        // Requirement 4.1: once BEGIN arrives, routing is delayed until
        // the first statement arrives.
        let state = TxSplitState::pending(IsolationLevel::ReadCommitted, false, true, true);
        assert!(!state.active);
        assert!(!state.on_reader);
    }

    #[test]
    fn split_respects_consistency_false_skips_consistency_check() {
        let mut state = TxSplitState::pending(IsolationLevel::ReadCommitted, false, true, false);
        // Even though the consistency-check closure returns false, since
        // split_respects_consistency=false it should route directly to
        // the Reader.
        let action = TxSplitEngine::route_statement(&mut state, StatementKind::Read, || false);
        assert_eq!(action, TxRouteAction::RouteToReader);
    }

    #[test]
    fn read_only_consistency_failure_routes_writer() {
        let mut state = TxSplitState::pending(IsolationLevel::RepeatableRead, true, true, true);
        let action = TxSplitEngine::route_statement(&mut state, StatementKind::Read, || false);
        assert_eq!(action, TxRouteAction::RouteToWriter);
        assert!(state.active);
        assert!(!state.on_reader);
    }
}
