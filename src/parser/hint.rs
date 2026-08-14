//! Hint parser (`hint`)
//!
//! Parses routing hints found in leading SQL comments, such as
//! `/*+ ROUTE_TO_WRITER */` and `/*+ CONSISTENCY(session) */`.

use std::sync::OnceLock;

use regex::Regex;

use crate::config::ConsistencyLevel;

/// Hint parsing result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteHint {
    ForceWriter,
    ForceReader,
    ForceAnalytics,
    Consistency(ConsistencyLevel),
    None,
}

pub trait HintParser {
    /// Parses a hint from a leading SQL comment, e.g. /*+ ROUTE_TO_WRITER */
    fn parse_hint(&self, sql: &str) -> RouteHint;
}

fn hint_comment_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)/\*\+\s*(.*?)\s*\*/").unwrap())
}

fn consistency_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)^CONSISTENCY\s*\(\s*(EVENTUAL|SESSION|GLOBAL)\s*\)$").unwrap()
    })
}

/// Extracts the leading comment/whitespace prefix of a SQL statement,
/// stopping before the first non-comment, non-whitespace character.
/// This prevents hint injection via string literals or identifiers.
fn leading_comment_prefix(sql: &str) -> &str {
    let bytes = sql.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        // Skip whitespace
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // Block comment: /* ... */
        if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < len {
                if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }
        // Line comment: -- ...
        if i + 1 < len && bytes[i] == b'-' && bytes[i + 1] == b'-' {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Non-comment, non-whitespace character reached — this is where
        // the real SQL statement starts.
        break;
    }
    &sql[..i]
}

/// Default hint parser implementation based on regex matching
#[derive(Debug, Default, Clone, Copy)]
pub struct RegexHintParser;

impl HintParser for RegexHintParser {
    fn parse_hint(&self, sql: &str) -> RouteHint {
        // Only search for hints in the leading comments/whitespace prefix,
        // not in SQL string literals or other body content. This prevents
        // a string like '/*+ ROUTE_TO_READER */' inside an UPDATE from
        // being misinterpreted as a routing hint.
        let prefix = leading_comment_prefix(sql);
        let Some(caps) = hint_comment_regex().captures(prefix) else {
            return RouteHint::None;
        };
        let inner = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
        let upper = inner.to_ascii_uppercase();

        match upper.as_str() {
            "ROUTE_TO_WRITER" => RouteHint::ForceWriter,
            "ROUTE_TO_READER" => RouteHint::ForceReader,
            "ROUTE_TO_ANALYTICS" => RouteHint::ForceAnalytics,
            _ => {
                if let Some(caps) = consistency_regex().captures(&upper) {
                    match caps.get(1).map(|m| m.as_str()) {
                        Some("EVENTUAL") => RouteHint::Consistency(ConsistencyLevel::Eventual),
                        Some("SESSION") => RouteHint::Consistency(ConsistencyLevel::Session),
                        Some("GLOBAL") => RouteHint::Consistency(ConsistencyLevel::Global),
                        _ => RouteHint::None,
                    }
                } else {
                    RouteHint::None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn parser() -> RegexHintParser {
        RegexHintParser
    }

    // -----------------------------------------------------------------
    // Property 6: a forced-routing hint takes effect and skips the
    // consistency check
    // Validates: Requirements 2.1, 2.2, 2.3
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_6_force_route_hints_recognized(
            hint_kw in prop_oneof![
                Just("ROUTE_TO_WRITER"), Just("ROUTE_TO_READER"), Just("ROUTE_TO_ANALYTICS"),
            ],
            prefix in "[ \t\n]{0,10}",
            suffix in "[a-zA-Z0-9 =*]{0,20}",
        ) {
            // Hints must only be recognized in leading whitespace/comments,
            // not after SQL body content has begun. Use whitespace-only
            // prefix to test valid leading hint placement.
            let sql = format!("{prefix}/*+ {hint_kw} */ {suffix}");
            let p = parser();
            let hint = p.parse_hint(&sql);
            let expected = match hint_kw {
                "ROUTE_TO_WRITER" => RouteHint::ForceWriter,
                "ROUTE_TO_READER" => RouteHint::ForceReader,
                "ROUTE_TO_ANALYTICS" => RouteHint::ForceAnalytics,
                _ => unreachable!(),
            };
            prop_assert_eq!(hint, expected);
        }

        // -----------------------------------------------------------------
        // Property 7: a consistency hint overrides the session's default
        // consistency level
        // Validates: Requirements 2.4
        // -----------------------------------------------------------------
        #[test]
        fn property_7_consistency_hint_parsed(
            level_kw in prop_oneof![Just("eventual"), Just("session"), Just("global")],
        ) {
            let sql = format!("/*+ CONSISTENCY({level_kw}) */ SELECT 1");
            let p = parser();
            let hint = p.parse_hint(&sql);
            let expected_level = match level_kw {
                "eventual" => ConsistencyLevel::Eventual,
                "session" => ConsistencyLevel::Session,
                "global" => ConsistencyLevel::Global,
                _ => unreachable!(),
            };
            prop_assert_eq!(hint, RouteHint::Consistency(expected_level));
        }

        // -----------------------------------------------------------------
        // Property 8: malformed hint syntax falls back to no hint
        // Validates: Requirements 2.5
        // -----------------------------------------------------------------
        #[test]
        fn property_8_malformed_hint_syntax_returns_none(
            garbage in "[a-zA-Z0-9_ ]{1,20}",
        ) {
            // A misspelled or unrecognized keyword (avoiding real hint keywords).
            prop_assume!(!garbage.to_ascii_uppercase().contains("ROUTE_TO"));
            prop_assume!(!garbage.to_ascii_uppercase().contains("CONSISTENCY"));
            let sql = format!("/*+ {garbage} */ SELECT 1");
            let p = parser();
            prop_assert_eq!(p.parse_hint(&sql), RouteHint::None);
        }
    }

    // -----------------------------------------------------------------
    // Unit tests: boundary cases
    // -----------------------------------------------------------------

    #[test]
    fn no_hint_comment_returns_none() {
        assert_eq!(parser().parse_hint("SELECT 1"), RouteHint::None);
    }

    #[test]
    fn plain_comment_without_plus_returns_none() {
        assert_eq!(
            parser().parse_hint("/* ROUTE_TO_WRITER */ SELECT 1"),
            RouteHint::None
        );
    }

    #[test]
    fn unbalanced_parens_in_consistency_returns_none() {
        assert_eq!(
            parser().parse_hint("/*+ CONSISTENCY(session */ SELECT 1"),
            RouteHint::None
        );
    }

    #[test]
    fn unknown_consistency_value_returns_none() {
        assert_eq!(
            parser().parse_hint("/*+ CONSISTENCY(strong) */ SELECT 1"),
            RouteHint::None
        );
    }

    #[test]
    fn case_insensitive_hint_keyword() {
        assert_eq!(
            parser().parse_hint("/*+ route_to_writer */ SELECT 1"),
            RouteHint::ForceWriter
        );
    }

    #[test]
    fn hint_inside_sql_body_is_ignored() {
        // A hint appearing after a non-comment keyword (inside the SQL body)
        // must NOT be treated as a routing hint — this prevents injection
        // via string literals like UPDATE t SET x = '/*+ ROUTE_TO_READER */'.
        assert_eq!(
            parser().parse_hint("UPDATE t SET x = '/*+ ROUTE_TO_READER */'"),
            RouteHint::None
        );
        assert_eq!(
            parser().parse_hint("SELECT /*+ ROUTE_TO_WRITER */ 1"),
            RouteHint::None
        );
    }

    #[test]
    fn hint_after_leading_comment_is_recognized() {
        // A hint that follows other leading comments/whitespace is valid.
        assert_eq!(
            parser().parse_hint("-- setup\n/*+ ROUTE_TO_READER */ SELECT 1"),
            RouteHint::ForceReader
        );
        assert_eq!(
            parser().parse_hint("/* pre */ /*+ ROUTE_TO_WRITER */ SELECT 1"),
            RouteHint::ForceWriter
        );
    }
}
