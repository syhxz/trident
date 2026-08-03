//! Cost-based routing (`cost`)
//!
//! Estimates whether a SQL statement is expensive enough to warrant routing
//! to the Analytics node, either by matching configured analytics patterns
//! or by estimating the query cost via EXPLAIN. Routing decisions are cached
//! per normalized query template to avoid repeated EXPLAIN calls.
//! See design.md section 10 and Requirements 10.1-10.5.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::parser::pattern::PatternMatcher;
use crate::pool::conn::{establish_connection, ConnectTarget, MaybeTlsStream};
use crate::protocol::message::BackendMessage;
use crate::protocol::reader::read_backend_message;
use crate::protocol::writer::encode_query;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CostEstimationError {
    #[error("failed to estimate cost via EXPLAIN: {0}")]
    ExplainFailed(String),
}

/// Estimates the execution cost of a SQL statement, for use in deciding
/// whether it should be routed to the Analytics node. A statement matching
/// a configured analytics pattern is reported with a cost of
/// `f64::INFINITY`, guaranteeing it exceeds any finite `cost_threshold`
/// (Requirement 10.1). Otherwise the cost comes from an EXPLAIN-based
/// estimation, cached per normalized query template (Requirement 10.4).
///
/// Declared with `#[async_trait]` so it remains object-safe and can be held
/// as `Box<dyn CostEstimator>` inside the `Router`.
#[async_trait]
pub trait CostEstimator: Send + Sync {
    async fn estimate_cost(&self, sql: &str) -> Result<f64, CostEstimationError>;
}

/// A pluggable backend used to run `EXPLAIN` against a real (or mocked)
/// connection and extract the estimated cost.
pub trait ExplainRunner: Send + Sync {
    fn explain_cost(
        &self,
        sql: &str,
    ) -> impl std::future::Future<Output = Result<f64, CostEstimationError>> + Send;
}

/// An `ExplainRunner` that never actually issues `EXPLAIN` and always
/// reports a cost of `0.0`. This is a placeholder wiring for deployments
/// that rely solely on analytics pattern matching (Requirement 10.1) and
/// Hint-based routing rather than EXPLAIN-based cost estimation
/// (Requirement 10.2); a full implementation would borrow a Writer/Reader
/// connection from the pool, issue `EXPLAIN (FORMAT JSON) <sql>`, and parse
/// the plan's top-level `Total Cost`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpExplainRunner;

impl ExplainRunner for NoOpExplainRunner {
    async fn explain_cost(&self, _sql: &str) -> Result<f64, CostEstimationError> {
        Ok(0.0)
    }
}

/// An `ExplainRunner` that maintains a dedicated connection to a backend
/// node and issues `EXPLAIN (FORMAT JSON) <sql>` to obtain the real query
/// plan cost. The connection is lazily established on first use and
/// reconnected on failure.
///
/// This runner uses a Mutex-protected connection to serialize EXPLAIN
/// calls, which is acceptable because:
/// 1. EXPLAIN results are cached per normalized template by the outer
///    `DefaultCostEstimator`, so each unique query pattern hits this only once.
/// 2. EXPLAIN itself is fast (planning only, no execution).
pub struct PoolExplainRunner {
    target: ConnectTarget,
    conn: tokio::sync::Mutex<Option<MaybeTlsStream>>,
    /// Timeout for individual EXPLAIN queries to prevent blocking the
    /// routing pipeline on a slow/hung backend.
    timeout: std::time::Duration,
}

impl PoolExplainRunner {
    pub fn new(target: ConnectTarget) -> Self {
        PoolExplainRunner {
            target,
            conn: tokio::sync::Mutex::new(None),
            timeout: std::time::Duration::from_millis(500),
        }
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn get_or_connect(&self, guard: &mut Option<MaybeTlsStream>) -> Result<(), CostEstimationError> {
        if guard.is_some() {
            return Ok(());
        }
        let (_meta, stream) = establish_connection("_explain", &self.target)
            .await
            .map_err(|e| CostEstimationError::ExplainFailed(format!("connect: {e}")))?;
        *guard = Some(stream);
        Ok(())
    }
}

impl ExplainRunner for PoolExplainRunner {
    async fn explain_cost(&self, sql: &str) -> Result<f64, CostEstimationError> {
        let mut guard = self.conn.lock().await;

        // Ensure we have a connection (lazy init or reconnect)
        if let Err(e) = self.get_or_connect(&mut guard).await {
            *guard = None;
            return Err(e);
        }

        let stream = guard.as_mut().unwrap();

        // Try standard EXPLAIN first
        let explain_sql = format!("EXPLAIN (FORMAT JSON) {sql}");
        let result = tokio::time::timeout(
            self.timeout,
            run_explain_query(stream, &explain_sql),
        )
        .await;

        match result {
            Ok(Ok(cost)) => Ok(cost),
            Ok(Err(_)) => {
                // Standard EXPLAIN failed (e.g. parameterized query with $1).
                // Reconnect and try GENERIC_PLAN (PostgreSQL 16+).
                *guard = None;
                if let Err(e) = self.get_or_connect(&mut guard).await {
                    *guard = None;
                    return Err(e);
                }
                let stream = guard.as_mut().unwrap();
                let generic_sql = format!("EXPLAIN (GENERIC_PLAN, FORMAT JSON) {sql}");
                let result = tokio::time::timeout(
                    self.timeout,
                    run_explain_query(stream, &generic_sql),
                )
                .await;

                match result {
                    Ok(Ok(cost)) => Ok(cost),
                    Ok(Err(e)) => {
                        *guard = None;
                        Err(e)
                    }
                    Err(_timeout) => {
                        *guard = None;
                        Err(CostEstimationError::ExplainFailed("EXPLAIN GENERIC_PLAN timed out".into()))
                    }
                }
            }
            Err(_timeout) => {
                *guard = None;
                Err(CostEstimationError::ExplainFailed("EXPLAIN timed out".into()))
            }
        }
    }
}

/// Sends an EXPLAIN query on an existing connection and parses the total
/// cost from the JSON plan output.
async fn run_explain_query<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    explain_sql: &str,
) -> Result<f64, CostEstimationError> {
    let bytes = encode_query(explain_sql);
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| CostEstimationError::ExplainFailed(format!("write: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| CostEstimationError::ExplainFailed(format!("flush: {e}")))?;

    let mut plan_text = String::new();
    let mut saw_error = false;
    let mut error_msg = String::new();

    loop {
        match read_backend_message(stream).await {
            Ok(BackendMessage::DataRow(cols)) => {
                if let Some(Some(bytes)) = cols.first() {
                    if let Ok(s) = std::str::from_utf8(bytes) {
                        plan_text.push_str(s);
                    }
                }
            }
            Ok(BackendMessage::ErrorResponse(fields)) => {
                saw_error = true;
                error_msg = fields
                    .message()
                    .unwrap_or("unknown error")
                    .to_string();
            }
            Ok(BackendMessage::ReadyForQuery(_)) => break,
            Ok(_) => continue,
            Err(e) => {
                return Err(CostEstimationError::ExplainFailed(format!("read: {e}")));
            }
        }
    }

    if saw_error {
        return Err(CostEstimationError::ExplainFailed(error_msg));
    }

    parse_total_cost(&plan_text)
}

/// Parses the "Total Cost" from PostgreSQL's EXPLAIN (FORMAT JSON) output.
/// The JSON structure is: `[{"Plan": {"Total Cost": <number>, ...}, ...}]`
fn parse_total_cost(json_text: &str) -> Result<f64, CostEstimationError> {
    // Simple extraction without pulling in a JSON dependency: find
    // "Total Cost" and extract the following number.
    // The format is stable across PostgreSQL versions.
    let needle = "Total Cost";
    let pos = json_text
        .find(needle)
        .ok_or_else(|| CostEstimationError::ExplainFailed(
            format!("'Total Cost' not found in EXPLAIN output: {}", &json_text[..json_text.len().min(200)])
        ))?;

    // After "Total Cost" we expect: `": <number>`
    let after = &json_text[pos + needle.len()..];
    // Skip `": ` or `" : `
    let num_start = after
        .find(|c: char| c.is_ascii_digit() || c == '.')
        .ok_or_else(|| CostEstimationError::ExplainFailed(
            "could not find cost number after 'Total Cost'".into()
        ))?;
    let num_str = &after[num_start..];
    let num_end = num_str
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != 'e' && c != 'E' && c != '+' && c != '-')
        .unwrap_or(num_str.len());
    let cost_str = &num_str[..num_end];

    cost_str
        .parse::<f64>()
        .map_err(|e| CostEstimationError::ExplainFailed(format!("parse cost '{cost_str}': {e}")))
}

/// Normalizes a SQL statement into a "query template" by stripping literal
/// values, so that structurally identical queries with different parameter
/// values share the same cached cost estimation.
///
/// This is a lightweight normalization (not a full parser): it replaces
/// single-quoted string literals and numeric literals with a placeholder.
pub fn normalize_query_template(sql: &str) -> String {
    let mut result = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    let mut pending_space = false;

    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            pending_space = !result.is_empty();
            continue;
        }

        if pending_space {
            result.push(' ');
            pending_space = false;
        }

        if c == '\'' {
            // Skip a single-quoted string literal, handling '' as an escaped quote.
            result.push('?');
            loop {
                match chars.next() {
                    Some('\'') => {
                        if chars.peek() == Some(&'\'') {
                            chars.next(); // escaped quote, keep consuming the literal
                            continue;
                        }
                        break;
                    }
                    Some(_) => continue,
                    None => break,
                }
            }
        } else if c.is_ascii_digit() {
            result.push('?');
            while let Some(&next) = chars.peek() {
                if next.is_ascii_digit() || next == '.' {
                    chars.next();
                } else {
                    break;
                }
            }
        } else {
            result.push(c.to_ascii_uppercase());
        }
    }

    result
}

const MAX_COST_CACHE_ENTRIES: usize = 10_000;

/// Default `CostEstimator` implementation: matches configured analytics
/// patterns first (cheap, returns `f64::INFINITY`), falling back to
/// EXPLAIN-based cost estimation (expensive) only when no pattern matches.
/// EXPLAIN-derived costs are cached per normalized query template. The cache
/// is capped to prevent unique ad-hoc queries from growing process memory
/// without bound.
pub struct DefaultCostEstimator<M: PatternMatcher + Send + Sync, E: ExplainRunner> {
    pattern_matcher: M,
    explain_runner: E,
    cache: Mutex<HashMap<String, f64>>,
}

impl<M: PatternMatcher + Send + Sync, E: ExplainRunner> DefaultCostEstimator<M, E> {
    pub fn new(pattern_matcher: M, explain_runner: E) -> Self {
        DefaultCostEstimator {
            pattern_matcher,
            explain_runner,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Number of distinct query templates currently cached (test/introspection helper).
    pub fn cache_len(&self) -> usize {
        self.cache.lock().expect("cost cache lock poisoned").len()
    }
}

#[async_trait]
impl<M: PatternMatcher + Send + Sync, E: ExplainRunner> CostEstimator for DefaultCostEstimator<M, E> {
    async fn estimate_cost(&self, sql: &str) -> Result<f64, CostEstimationError> {
        // Requirement 10.1: pattern match takes priority and short-circuits EXPLAIN.
        if self.pattern_matcher.matches_analytics_pattern(sql) {
            return Ok(f64::INFINITY);
        }

        // Requirement 10.4: reuse a cached decision for the same query template.
        let template = normalize_query_template(sql);
        {
            let cache = self.cache.lock().expect("cost cache lock poisoned");
            if let Some(cost) = cache.get(&template) {
                return Ok(*cost);
            }
        }

        // Requirement 10.2: fall back to EXPLAIN-based cost estimation.
        let cost = self.explain_runner.explain_cost(sql).await?;

        let mut cache = self.cache.lock().expect("cost cache lock poisoned");
        if cache.len() < MAX_COST_CACHE_ENTRIES {
            cache.entry(template).or_insert(cost);
        }
        Ok(cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::pattern::RegexPatternMatcher;
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// An `ExplainRunner` that returns a fixed cost and counts invocations,
    /// used to verify cache reuse (Property 39).
    struct CountingExplainRunner {
        cost: f64,
        calls: Arc<AtomicU32>,
    }

    impl ExplainRunner for CountingExplainRunner {
        async fn explain_cost(&self, _sql: &str) -> Result<f64, CostEstimationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.cost)
        }
    }

    fn no_patterns_matcher() -> RegexPatternMatcher {
        RegexPatternMatcher::new(&[]).unwrap()
    }

    // -----------------------------------------------------------------
    // Property 37: analytics-pattern-matching queries always report a cost
    // above any finite threshold (routing to Analytics is decided by the
    // Router, but the estimator must guarantee the sentinel cost here).
    // Validates: Requirements 10.1
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_37_pattern_match_reports_infinite_cost(
            table_prefix in prop_oneof![Just("fact_"), Just("dim_"), Just("dw_")],
            table_suffix in "[a-z_]{1,10}",
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(AtomicU32::new(0));
            let matcher = RegexPatternMatcher::new(&[
                r"SELECT.*FROM\s+(fact_|dim_|dw_)".to_string(),
            ]).unwrap();
            let estimator = DefaultCostEstimator::new(
                matcher,
                CountingExplainRunner { cost: 0.0, calls: calls.clone() },
            );
            let sql = format!("SELECT * FROM {table_prefix}{table_suffix}");
            let cost = rt.block_on(estimator.estimate_cost(&sql)).unwrap();
            prop_assert_eq!(cost, f64::INFINITY);
            prop_assert_eq!(calls.load(Ordering::SeqCst), 0);
        }

        // -----------------------------------------------------------------
        // Property 39: identical query templates reuse the cached decision
        // Validates: Requirements 10.4
        // -----------------------------------------------------------------
        #[test]
        fn property_39_identical_template_uses_cache(
            id1 in 1i64..1000, id2 in 1i64..1000,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(AtomicU32::new(0));
            let estimator = DefaultCostEstimator::new(
                no_patterns_matcher(),
                CountingExplainRunner { cost: 100.0, calls: calls.clone() },
            );

            let sql1 = format!("SELECT * FROM t WHERE id = {id1}");
            let sql2 = format!("SELECT * FROM t WHERE id = {id2}");

            rt.block_on(estimator.estimate_cost(&sql1)).unwrap();
            rt.block_on(estimator.estimate_cost(&sql2)).unwrap();

            // Both normalize to the same template "SELECT * FROM T WHERE ID = ?",
            // so EXPLAIN should have been invoked exactly once.
            prop_assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    // -----------------------------------------------------------------
    // Unit tests
    // -----------------------------------------------------------------

    #[test]
    fn normalize_strips_numeric_and_string_literals() {
        assert_eq!(
            normalize_query_template("select * from t where id = 42"),
            "SELECT * FROM T WHERE ID = ?"
        );
        assert_eq!(
            normalize_query_template("SELECT * FROM t WHERE name = 'alice'"),
            "SELECT * FROM T WHERE NAME = ?"
        );
    }

    #[test]
    fn normalize_handles_escaped_quotes_in_string_literal() {
        assert_eq!(
            normalize_query_template("SELECT * FROM t WHERE name = 'o''brien'"),
            "SELECT * FROM T WHERE NAME = ?"
        );
    }

    #[tokio::test]
    async fn pattern_match_short_circuits_explain() {
        let calls = Arc::new(AtomicU32::new(0));
        let matcher = RegexPatternMatcher::new(&[r"FROM\s+fact_".to_string()]).unwrap();
        let estimator = DefaultCostEstimator::new(
            matcher,
            CountingExplainRunner {
                cost: 0.0,
                calls: calls.clone(),
            },
        );

        let cost = estimator.estimate_cost("SELECT * FROM fact_sales").await.unwrap();
        assert_eq!(cost, f64::INFINITY);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn explain_failure_propagates_as_error() {
        struct FailingRunner;
        impl ExplainRunner for FailingRunner {
            async fn explain_cost(&self, _sql: &str) -> Result<f64, CostEstimationError> {
                Err(CostEstimationError::ExplainFailed("backend down".into()))
            }
        }

        let estimator = DefaultCostEstimator::new(no_patterns_matcher(), FailingRunner);
        let result = estimator.estimate_cost("SELECT * FROM t").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cache_len_reflects_distinct_templates() {
        let calls = Arc::new(AtomicU32::new(0));
        let estimator = DefaultCostEstimator::new(
            no_patterns_matcher(),
            CountingExplainRunner {
                cost: 10.0,
                calls: calls.clone(),
            },
        );

        estimator.estimate_cost("SELECT * FROM t WHERE id = 1").await.unwrap();
        estimator.estimate_cost("SELECT * FROM t WHERE id = 2").await.unwrap();
        estimator.estimate_cost("SELECT * FROM u WHERE id = 3").await.unwrap();

        assert_eq!(estimator.cache_len(), 2); // "t" and "u" templates
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn noop_explain_runner_always_reports_zero_cost() {
        let runner = NoOpExplainRunner;
        assert_eq!(runner.explain_cost("SELECT * FROM t").await.unwrap(), 0.0);
    }
}
