//! Session state (`session`)
//!
//! Defines `SessionState`, `TxState`, and `IsolationLevel`, and implements
//! the logic for updating a session's consistency level in response to a
//! `SET trident.consistency = ...` command.

use std::collections::HashMap;

use crate::config::ConsistencyLevel;
use crate::session::transaction::TxSplitState;

/// Session transaction state (mapped from PostgreSQL's `ReadyForQuery`
/// status byte I/T/E).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxState {
    Idle,
    InTransaction,
    Failed,
}

impl TxState {
    /// Maps the status byte carried by `ReadyForQuery` ('I'/'T'/'E') to a
    /// `TxState`.
    ///
    /// See Property 42: `I->Idle`, `T->InTransaction`, `E->Failed`.
    pub fn from_ready_for_query_byte(byte: u8) -> Option<TxState> {
        match byte {
            b'I' => Some(TxState::Idle),
            b'T' => Some(TxState::InTransaction),
            b'E' => Some(TxState::Failed),
            _ => None,
        }
    }
}

/// Transaction isolation level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

/// Client session state
#[derive(Debug, Clone)]
pub struct SessionState {
    pub id: String,
    pub consistency: ConsistencyLevel,
    pub last_write_lsn: u64,
    pub tx_state: TxState,
    pub tx_split: Option<TxSplitState>,
    pub session_params: HashMap<String, String>,
    pub prepared_stmts: HashMap<String, String>,
}

impl SessionState {
    pub fn new(id: impl Into<String>, default_consistency: ConsistencyLevel) -> Self {
        SessionState {
            id: id.into(),
            consistency: default_consistency,
            last_write_lsn: 0,
            tx_state: TxState::Idle,
            tx_split: None,
            session_params: HashMap::new(),
            prepared_stmts: HashMap::new(),
        }
    }

    /// Handles a `SET trident.consistency = '<value>'` command: on
    /// success, updates the session's consistency level and returns
    /// `true`; if the command is not a consistency-setting command or the
    /// value is invalid, returns `false` and leaves the state unchanged.
    ///
    /// See Requirement 3.8 / Property 15.
    pub fn apply_consistency_set_command(&mut self, sql: &str) -> bool {
        match parse_consistency_set_command(sql) {
            Some(level) => {
                self.consistency = level;
                true
            }
            None => false,
        }
    }
}

/// Parses `SET trident.consistency = '<value>'` (case-insensitive, with
/// single/double quotes or no quotes allowed), returning the parsed
/// consistency level; returns `None` if it doesn't match.
fn parse_consistency_set_command(sql: &str) -> Option<ConsistencyLevel> {
    let trimmed = sql.trim();
    let lower = trimmed.to_ascii_lowercase();
    let prefix = "set trident.consistency";
    if !lower.starts_with(prefix) {
        return None;
    }

    let rest = trimmed[prefix.len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim();
    let value = rest
        .trim_end_matches(';')
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .to_ascii_lowercase();

    match value.as_str() {
        "eventual" => Some(ConsistencyLevel::Eventual),
        "session" => Some(ConsistencyLevel::Session),
        "global" => Some(ConsistencyLevel::Global),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -----------------------------------------------------------------
    // Property 15: a consistency-level SET command correctly updates
    // session state
    // Validates: Requirements 3.8
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_15_consistency_set_updates_session(
            level_kw in prop_oneof![Just("eventual"), Just("session"), Just("global")],
            quote in prop_oneof![Just(""), Just("'"), Just("\"")],
        ) {
            let mut session = SessionState::new("s1", ConsistencyLevel::Session);
            let sql = format!("SET trident.consistency = {quote}{level_kw}{quote}");
            let applied = session.apply_consistency_set_command(&sql);
            prop_assert!(applied);

            let expected = match level_kw {
                "eventual" => ConsistencyLevel::Eventual,
                "session" => ConsistencyLevel::Session,
                "global" => ConsistencyLevel::Global,
                _ => unreachable!(),
            };
            prop_assert_eq!(session.consistency, expected);
        }
    }

    // -----------------------------------------------------------------
    // Property 42: the ReadyForQuery status byte deterministically maps to
    // the session transaction state
    // Validates: Requirements 11.5
    // -----------------------------------------------------------------

    #[test]
    fn ready_for_query_byte_mapping() {
        assert_eq!(TxState::from_ready_for_query_byte(b'I'), Some(TxState::Idle));
        assert_eq!(
            TxState::from_ready_for_query_byte(b'T'),
            Some(TxState::InTransaction)
        );
        assert_eq!(
            TxState::from_ready_for_query_byte(b'E'),
            Some(TxState::Failed)
        );
        assert_eq!(TxState::from_ready_for_query_byte(b'X'), None);
    }

    #[test]
    fn irrelevant_set_command_does_not_change_consistency() {
        let mut session = SessionState::new("s1", ConsistencyLevel::Session);
        let applied = session.apply_consistency_set_command("SET search_path = public");
        assert!(!applied);
        assert_eq!(session.consistency, ConsistencyLevel::Session);
    }

    #[test]
    fn invalid_consistency_value_does_not_change_consistency() {
        let mut session = SessionState::new("s1", ConsistencyLevel::Session);
        let applied = session.apply_consistency_set_command("SET trident.consistency = 'strong'");
        assert!(!applied);
        assert_eq!(session.consistency, ConsistencyLevel::Session);
    }

    #[test]
    fn case_insensitive_set_command() {
        let mut session = SessionState::new("s1", ConsistencyLevel::Session);
        let applied = session.apply_consistency_set_command("set TRIDENT.CONSISTENCY = 'GLOBAL'");
        assert!(applied);
        assert_eq!(session.consistency, ConsistencyLevel::Global);
    }
}
