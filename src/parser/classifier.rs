//! SQL classifier (`classifier`)
//!
//! Performs lightweight classification of SQL text based on
//! keyword/regex matching; does not build a full AST, and never executes
//! or accesses the database.

use once_cell_lite::Lazy;
use regex::Regex;

/// SQL statement classification result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlKind {
    /// Plain SELECT, no side effects
    Select,
    /// SELECT ... FOR UPDATE / FOR SHARE
    SelectForUpdate,
    /// INSERT/UPDATE/DELETE/MERGE/COPY FROM
    Write,
    /// CREATE/ALTER/DROP/TRUNCATE
    Ddl,
    /// LOCK TABLE / non-LOCAL SET
    LockOrSession,
    /// SHOW / EXPLAIN (non-ANALYZE)
    ShowOrExplain,
    Other,
}

impl SqlKind {
    /// Whether this classification requires routing to the Writer_Node
    /// (see Requirement 1.1).
    pub fn requires_writer(&self) -> bool {
        matches!(
            self,
            SqlKind::Write | SqlKind::Ddl | SqlKind::LockOrSession | SqlKind::SelectForUpdate
        )
    }

    /// Whether this classification can be routed to the Reader_Node (see
    /// Requirement 1.2).
    pub fn readable(&self) -> bool {
        matches!(self, SqlKind::Select | SqlKind::ShowOrExplain)
    }
}

pub trait Classifier {
    /// Classifies SQL text; never executes it or accesses the database.
    fn classify(&self, sql: &str) -> SqlKind;

    /// Detects whether a function call with side effects
    /// (nextval/setval/pg_advisory_lock/lo_* etc.) is present.
    fn has_write_function_call(&self, sql: &str) -> bool;
}

/// Default classifier implementation based on keyword and regex matching.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeywordClassifier;

// A minimal lazy-singleton helper to avoid recompiling regexes on every
// call (equivalent to `once_cell::sync::Lazy`; implemented inline here to
// avoid pulling in the extra `once_cell` dependency).
mod once_cell_lite {
    use std::sync::OnceLock;

    pub struct Lazy<T> {
        cell: OnceLock<T>,
        init: fn() -> T,
    }

    impl<T> Lazy<T> {
        pub const fn new(init: fn() -> T) -> Self {
            Lazy {
                cell: OnceLock::new(),
                init,
            }
        }
    }

    impl<T> std::ops::Deref for Lazy<T> {
        type Target = T;
        fn deref(&self) -> &T {
            self.cell.get_or_init(self.init)
        }
    }
}

static FOR_UPDATE_OR_SHARE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?is)\bFOR\s+(UPDATE|SHARE)\b").unwrap());

static SET_LOCAL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)^SET\s+LOCAL\b").unwrap());

static COPY_FROM: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)^COPY\b.*\bFROM\b").unwrap());

static EXPLAIN_ANALYZE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)^EXPLAIN\b.*\bANALYZE\b").unwrap());

static WRITE_FUNCTION_CALL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)\b(nextval|setval|pg_advisory_lock\w*|lo_[a-z_]+)\s*\(").unwrap()
});

/// Trims leading/trailing whitespace from SQL text and skips leading
/// comment blocks (`/* ... */` and `-- ...` line comments), so keyword
/// matching can locate the true start of the statement.
fn skip_leading_comments_and_whitespace(sql: &str) -> &str {
    let mut rest = sql;
    loop {
        let trimmed = rest.trim_start();
        if let Some(stripped) = trimmed.strip_prefix("/*") {
            if let Some(end) = stripped.find("*/") {
                rest = &stripped[end + 2..];
                continue;
            } else {
                // Unclosed comment: treat as having no classifiable body.
                return "";
            }
        } else if let Some(stripped) = trimmed.strip_prefix("--") {
            if let Some(end) = stripped.find('\n') {
                rest = &stripped[end + 1..];
                continue;
            } else {
                return "";
            }
        } else {
            return trimmed;
        }
    }
}

/// Conservatively detects more than one top-level statement in a Simple
/// Query message. Semicolons inside quoted strings/identifiers, nested block
/// comments, line comments, dollar-quoted bodies, or parentheses do not split
/// a statement. Multiple statements are routed as one unit to the Writer so a
/// read-looking first statement cannot hide a later write.
pub fn contains_multiple_statements(sql: &str) -> bool {
    let bytes = sql.as_bytes();
    let mut index = 0;
    let mut paren_depth = 0u32;
    let mut completed_statements = 0u32;
    let mut statement_has_content = false;

    while index < bytes.len() {
        match bytes[index] {
            b'\'' => {
                statement_has_content = true;
                index += 1;
                while index < bytes.len() {
                    match bytes[index] {
                        b'\\' if index + 1 < bytes.len() => index += 2,
                        b'\'' if index + 1 < bytes.len() && bytes[index + 1] == b'\'' => {
                            index += 2;
                        }
                        b'\'' => {
                            index += 1;
                            break;
                        }
                        _ => index += 1,
                    }
                }
            }
            b'"' => {
                statement_has_content = true;
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == b'"' {
                        if index + 1 < bytes.len() && bytes[index + 1] == b'"' {
                            index += 2;
                        } else {
                            index += 1;
                            break;
                        }
                    } else {
                        index += 1;
                    }
                }
            }
            b'-' if index + 1 < bytes.len() && bytes[index + 1] == b'-' => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if index + 1 < bytes.len() && bytes[index + 1] == b'*' => {
                index += 2;
                let mut comment_depth = 1u32;
                while index < bytes.len() && comment_depth > 0 {
                    if index + 1 < bytes.len()
                        && bytes[index] == b'/'
                        && bytes[index + 1] == b'*'
                    {
                        comment_depth += 1;
                        index += 2;
                    } else if index + 1 < bytes.len()
                        && bytes[index] == b'*'
                        && bytes[index + 1] == b'/'
                    {
                        comment_depth -= 1;
                        index += 2;
                    } else {
                        index += 1;
                    }
                }
            }
            b'$' => {
                let tag_end = (index + 1..bytes.len()).find(|&position| bytes[position] == b'$');
                let delimiter_len = tag_end.and_then(|end| {
                    let tag = &bytes[index + 1..end];
                    let valid = tag.is_empty()
                        || ((tag[0].is_ascii_alphabetic() || tag[0] == b'_')
                            && tag[1..]
                                .iter()
                                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_'));
                    valid.then_some(end - index + 1)
                });

                if let Some(delimiter_len) = delimiter_len {
                    statement_has_content = true;
                    let delimiter = &bytes[index..index + delimiter_len];
                    index += delimiter_len;
                    while index + delimiter_len <= bytes.len() {
                        if &bytes[index..index + delimiter_len] == delimiter {
                            index += delimiter_len;
                            break;
                        }
                        index += 1;
                    }
                } else {
                    statement_has_content = true;
                    index += 1;
                }
            }
            b'(' => {
                statement_has_content = true;
                paren_depth += 1;
                index += 1;
            }
            b')' => {
                statement_has_content = true;
                paren_depth = paren_depth.saturating_sub(1);
                index += 1;
            }
            b';' if paren_depth == 0 => {
                if statement_has_content {
                    completed_statements += 1;
                    if completed_statements >= 2 {
                        return true;
                    }
                    statement_has_content = false;
                }
                index += 1;
            }
            byte if byte.is_ascii_whitespace() => index += 1,
            _ => {
                statement_has_content = true;
                index += 1;
            }
        }
    }

    completed_statements + u32::from(statement_has_content) > 1
}

impl Classifier for KeywordClassifier {
    fn classify(&self, sql: &str) -> SqlKind {
        let body = skip_leading_comments_and_whitespace(sql);
        if body.is_empty() {
            return SqlKind::Other;
        }

        // Take the first keyword (delimited by whitespace/parentheses) for
        // coarse-grained classification.
        let first_word: String = body
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect::<String>()
            .to_ascii_uppercase();

        match first_word.as_str() {
            "INSERT" | "UPDATE" | "DELETE" | "MERGE" => SqlKind::Write,
            "CREATE" | "ALTER" | "DROP" | "TRUNCATE" => SqlKind::Ddl,
            "COPY" => {
                if COPY_FROM.is_match(body) {
                    SqlKind::Write
                } else {
                    SqlKind::Other
                }
            }
            "LOCK" => SqlKind::LockOrSession,
            "SET" => {
                if SET_LOCAL.is_match(body) {
                    SqlKind::Other
                } else {
                    SqlKind::LockOrSession
                }
            }
            "SELECT" => {
                if FOR_UPDATE_OR_SHARE.is_match(body) {
                    SqlKind::SelectForUpdate
                } else {
                    SqlKind::Select
                }
            }
            "SHOW" => SqlKind::ShowOrExplain,
            "EXPLAIN" => {
                if EXPLAIN_ANALYZE.is_match(body) {
                    SqlKind::Other
                } else {
                    SqlKind::ShowOrExplain
                }
            }
            _ => SqlKind::Other,
        }
    }

    fn has_write_function_call(&self, sql: &str) -> bool {
        WRITE_FUNCTION_CALL.is_match(sql)
    }
}

/// Combines the results of `classify` and `has_write_function_call` to
/// determine whether this statement must be routed to the Writer_Node
/// (see Requirement 1.1, 1.3).
pub fn requires_writer(classifier: &impl Classifier, sql: &str) -> bool {
    classifier.classify(sql).requires_writer() || classifier.has_write_function_call(sql)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn classifier() -> KeywordClassifier {
        KeywordClassifier
    }

    // -----------------------------------------------------------------
    // Property 1: write statements are always classified for Writer routing
    // Validates: Requirements 1.1
    // -----------------------------------------------------------------

    fn writer_statement_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("INSERT INTO t VALUES (1)".to_string()),
            Just("insert into t values (1)".to_string()),
            Just("UPDATE t SET a = 1".to_string()),
            Just("  DELETE FROM t WHERE id = 1".to_string()),
            Just("MERGE INTO t USING s ON t.id = s.id".to_string()),
            Just("CREATE TABLE t (id int)".to_string()),
            Just("ALTER TABLE t ADD COLUMN c int".to_string()),
            Just("DROP TABLE t".to_string()),
            Just("TRUNCATE TABLE t".to_string()),
            Just("LOCK TABLE t IN EXCLUSIVE MODE".to_string()),
            Just("COPY t FROM STDIN".to_string()),
            Just("SELECT * FROM t WHERE id = 1 FOR UPDATE".to_string()),
            Just("SELECT * FROM t WHERE id = 1 FOR SHARE".to_string()),
            Just("select * from t for update".to_string()),
        ]
    }

    proptest! {
        #[test]
        fn property_1_write_statements_require_writer(sql in writer_statement_strategy()) {
            let c = classifier();
            prop_assert!(c.classify(&sql).requires_writer());
        }

        // -----------------------------------------------------------------
        // Property 2: read-only statements are always classified as
        // Reader-routable
        // Validates: Requirements 1.2
        // -----------------------------------------------------------------
        #[test]
        fn property_2_readonly_statements_are_readable(sql in prop_oneof![
            Just("SELECT * FROM t WHERE id = 1".to_string()),
            Just("select count(*) from t".to_string()),
            Just("SHOW search_path".to_string()),
            Just("EXPLAIN SELECT * FROM t".to_string()),
            Just("explain select 1".to_string()),
        ]) {
            let c = classifier();
            prop_assert!(c.classify(&sql).readable());
        }

        // -----------------------------------------------------------------
        // Property 3: a write function call overrides the classification
        // of an outer SELECT shell
        // Validates: Requirements 1.3
        // -----------------------------------------------------------------
        #[test]
        fn property_3_write_function_call_forces_writer(
            func in prop_oneof![
                Just("nextval"), Just("setval"), Just("pg_advisory_lock"),
                Just("pg_advisory_lock_shared"), Just("lo_import"), Just("lo_export"),
            ],
            arg in "[a-zA-Z0-9_'()]{0,10}",
            suffix in "[a-zA-Z0-9_, ]{0,20}",
        ) {
            let sql = format!("SELECT {func}({arg}) {suffix}");
            let c = classifier();
            prop_assert!(requires_writer(&c, &sql));
        }

        // -----------------------------------------------------------------
        // Property 4: a non-LOCAL SET command is always classified as
        // affecting session state
        // Validates: Requirements 1.4
        // -----------------------------------------------------------------
        #[test]
        fn property_4_non_local_set_is_session_state(
            param in "[a-zA-Z_][a-zA-Z0-9_.]{0,15}",
            value in "[a-zA-Z0-9_']{1,10}",
        ) {
            let sql = format!("SET {param} = {value}");
            let c = classifier();
            prop_assert_eq!(c.classify(&sql), SqlKind::LockOrSession);
        }

        #[test]
        fn property_4_set_local_is_not_session_state(
            param in "[a-zA-Z_][a-zA-Z0-9_.]{0,15}",
            value in "[a-zA-Z0-9_']{1,10}",
        ) {
            let sql = format!("SET LOCAL {param} = {value}");
            let c = classifier();
            prop_assert_ne!(c.classify(&sql), SqlKind::LockOrSession);
        }

        // -----------------------------------------------------------------
        // Property 5: classification is deterministic
        // Validates: Requirements 1.5
        // -----------------------------------------------------------------
        #[test]
        fn property_5_classification_is_deterministic(sql in ".{0,80}") {
            let c = classifier();
            let first = c.classify(&sql);
            let second = c.classify(&sql);
            prop_assert_eq!(first, second);
        }
    }

    // -----------------------------------------------------------------
    // Unit tests: boundary inputs
    // -----------------------------------------------------------------

    #[test]
    fn empty_string_classifies_as_other() {
        assert_eq!(classifier().classify(""), SqlKind::Other);
    }

    #[test]
    fn only_comment_classifies_as_other() {
        assert_eq!(classifier().classify("/* just a comment */"), SqlKind::Other);
    }

    #[test]
    fn leading_comment_is_skipped_for_classification() {
        assert_eq!(
            classifier().classify("/* leading comment */ SELECT 1"),
            SqlKind::Select
        );
    }

    #[test]
    fn copy_to_is_not_classified_as_write() {
        assert_ne!(classifier().classify("COPY t TO STDOUT"), SqlKind::Write);
    }

    #[test]
    fn explain_analyze_is_not_show_or_explain() {
        assert_ne!(
            classifier().classify("EXPLAIN ANALYZE SELECT 1"),
            SqlKind::ShowOrExplain
        );
    }

    #[test]
    fn top_level_multiple_statements_are_detected() {
        assert!(contains_multiple_statements(
            "SELECT 1; INSERT INTO t VALUES (1)"
        ));
        assert!(contains_multiple_statements("; SELECT 1; ; SELECT 2;"));
        assert!(contains_multiple_statements(
            "SELECT 1; -- separator comment\n UPDATE t SET value = 2"
        ));
    }

    #[test]
    fn semicolons_in_sql_constructs_do_not_create_false_multiple_statements() {
        for sql in [
            "SELECT ';'",
            "SELECT 'it''s;still one'",
            "SELECT E'escaped\\';still one'",
            "SELECT \"semi;colon\" FROM t",
            "SELECT 1 /* outer ; /* nested ; */ still comment ; */",
            "SELECT 1 -- comment ;\n",
            "DO $$ BEGIN RAISE NOTICE 'a;b'; END $$",
            "DO $body$ BEGIN PERFORM ';'; END $body$",
            "SELECT (1 /* ; */ + 2)",
            "SELECT 1; -- trailing comment only",
        ] {
            assert!(
                !contains_multiple_statements(sql),
                "unexpectedly classified as multiple statements: {sql}"
            );
        }
    }
}
