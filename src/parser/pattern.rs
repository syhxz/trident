//! Analytics pattern matcher (`pattern`)
//!
//! Determines whether SQL matches an analytics-query pattern, based on a
//! user-configured list of regular expressions.

use std::sync::Arc;

use arc_swap::ArcSwap;
use regex::Regex;

pub trait PatternMatcher {
    /// Determines whether this is an analytics query, based on
    /// user-configured regex patterns.
    fn matches_analytics_pattern(&self, sql: &str) -> bool;
}

/// Blanket impl so an `Arc<M>` can be used anywhere an owned `M:
/// PatternMatcher` is expected (e.g. as `DefaultCostEstimator`'s
/// `pattern_matcher` field), letting callers keep a shared `Arc` handle
/// for hot-reloading (`RegexPatternMatcher::update_patterns`) alongside
/// the copy embedded in the estimator/router.
impl<T: PatternMatcher + ?Sized> PatternMatcher for Arc<T> {
    fn matches_analytics_pattern(&self, sql: &str) -> bool {
        (**self).matches_analytics_pattern(sql)
    }
}

/// Default pattern matcher implementation based on a set of precompiled
/// regular expressions.
///
/// All patterns are validated and compiled at construction time; invalid
/// regexes should already be rejected during config loading (the `config`
/// module), so this type assumes the patterns passed in are already valid
/// (construction failure returns a `regex::Error`).
///
/// The compiled pattern list is held behind an `ArcSwap` so
/// `routing.analytics_patterns` can be hot-reloaded via `update_patterns`
/// without needing `&mut self` -- see `trident::reload`.
pub struct RegexPatternMatcher {
    patterns: ArcSwap<Vec<Regex>>,
}

impl Clone for RegexPatternMatcher {
    fn clone(&self) -> Self {
        RegexPatternMatcher {
            patterns: ArcSwap::new(self.patterns.load_full()),
        }
    }
}

impl std::fmt::Debug for RegexPatternMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegexPatternMatcher")
            .field("pattern_count", &self.patterns.load().len())
            .finish()
    }
}

impl RegexPatternMatcher {
    pub fn new(patterns: &[String]) -> Result<Self, regex::Error> {
        let compiled = compile_patterns(patterns)?;
        Ok(RegexPatternMatcher {
            patterns: ArcSwap::new(Arc::new(compiled)),
        })
    }

    /// Atomically replaces the pattern set with a newly compiled one.
    /// Returns an error (leaving the previous patterns in effect) if any
    /// pattern fails to compile, rather than partially applying the
    /// update -- config validation should already reject invalid patterns
    /// before this is ever called (see `config::AppConfig::validate`),
    /// this is a defense-in-depth check.
    pub fn update_patterns(&self, patterns: &[String]) -> Result<(), regex::Error> {
        let compiled = compile_patterns(patterns)?;
        self.patterns.store(Arc::new(compiled));
        Ok(())
    }
}

fn compile_patterns(patterns: &[String]) -> Result<Vec<Regex>, regex::Error> {
    patterns.iter().map(|p| Regex::new(p)).collect()
}

impl PatternMatcher for RegexPatternMatcher {
    fn matches_analytics_pattern(&self, sql: &str) -> bool {
        self.patterns.load().iter().any(|re| re.is_match(sql))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -----------------------------------------------------------------
    // Property 37 (the match determination itself; the actual routing
    // integration happens in the Router module)
    // Validates: Requirements 10.1
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_37_matching_sql_is_detected(
            table_prefix in prop_oneof![Just("fact_"), Just("dim_"), Just("dw_")],
            table_suffix in "[a-z_]{1,10}",
        ) {
            let matcher = RegexPatternMatcher::new(&[
                r"SELECT.*FROM\s+(fact_|dim_|dw_)".to_string(),
            ]).unwrap();
            let sql = format!("SELECT * FROM {table_prefix}{table_suffix}");
            prop_assert!(matcher.matches_analytics_pattern(&sql));
        }

        #[test]
        fn property_37_non_matching_sql_is_not_detected(
            table in "[a-z_]{1,10}",
        ) {
            prop_assume!(!table.starts_with("fact_") && !table.starts_with("dim_") && !table.starts_with("dw_"));
            let matcher = RegexPatternMatcher::new(&[
                r"SELECT.*FROM\s+(fact_|dim_|dw_)".to_string(),
            ]).unwrap();
            let sql = format!("SELECT * FROM {table}");
            prop_assert!(!matcher.matches_analytics_pattern(&sql));
        }
    }

    #[test]
    fn empty_pattern_list_never_matches() {
        let matcher = RegexPatternMatcher::new(&[]).unwrap();
        assert!(!matcher.matches_analytics_pattern("SELECT * FROM fact_sales"));
    }

    #[test]
    fn multiple_patterns_any_match_suffices() {
        let matcher = RegexPatternMatcher::new(&[
            r"GROUP BY.*HAVING".to_string(),
            r"OVER\s*\(".to_string(),
        ])
        .unwrap();
        assert!(matcher.matches_analytics_pattern("SELECT a, count(*) FROM t GROUP BY a HAVING count(*) > 1"));
        assert!(matcher.matches_analytics_pattern("SELECT rank() OVER (ORDER BY a) FROM t"));
        assert!(!matcher.matches_analytics_pattern("SELECT * FROM t"));
    }

    #[test]
    fn invalid_regex_returns_error() {
        let result = RegexPatternMatcher::new(&["(unclosed".to_string()]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------
    // update_patterns: hot-reload support
    // -----------------------------------------------------------------

    #[test]
    fn update_patterns_takes_effect_immediately() {
        let matcher = RegexPatternMatcher::new(&[r"FROM\s+fact_".to_string()]).unwrap();
        assert!(matcher.matches_analytics_pattern("SELECT * FROM fact_sales"));
        assert!(!matcher.matches_analytics_pattern("SELECT * FROM dim_customers"));

        matcher
            .update_patterns(&[r"FROM\s+dim_".to_string()])
            .unwrap();

        assert!(!matcher.matches_analytics_pattern("SELECT * FROM fact_sales"));
        assert!(matcher.matches_analytics_pattern("SELECT * FROM dim_customers"));
    }

    #[test]
    fn update_patterns_rejects_invalid_regex_and_keeps_previous() {
        let matcher = RegexPatternMatcher::new(&[r"FROM\s+fact_".to_string()]).unwrap();
        let result = matcher.update_patterns(&["(unclosed".to_string()]);
        assert!(result.is_err());
        // Previous, still-valid pattern set remains in effect.
        assert!(matcher.matches_analytics_pattern("SELECT * FROM fact_sales"));
    }
}
