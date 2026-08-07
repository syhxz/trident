//! Core router (`router`)
//!
//! Combines hint parsing, transaction state (including the transaction split
//! state machine), SQL classification, write-function detection, cost-based
//! routing, and consistency checking to produce a final `RouteDecision`.
//! See design.md section "Router module" and Requirements 1.1-1.5, 2.1-2.5,
//! 3.1-3.8, 4.1-4.10, 8.4, 10.1-10.5.
//!
//! CANCEL request validation (Requirements 7.1-7.3) is handled by
//! `proxy::registry::CancelRegistry`, not here: it requires tracking live
//! session/connection state that belongs to the Proxy layer, not the
//! stateless routing decisions made by this module.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::balancer::{LoadBalancer, NodeCandidate};
use crate::config::{ConsistencyLevel, NodeType};
use crate::health::BackendNodeSnapshot;
use crate::parser::classifier::{contains_multiple_statements, multi_statement_all_readable, Classifier};
use crate::parser::hint::{HintParser, RouteHint};
use crate::router::consistency::ConsistencyChecker;
use crate::router::cost::CostEstimator;
use crate::router::custom_rules::CustomRoutingRules;
use crate::session::session::TxState;
use crate::session::transaction::{StatementKind, TxRouteAction, TxSplitEngine, TxSplitState};

/// Final routing decision produced by `Router::route`.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteDecision {
    pub target: NodeType,
    /// The specific node selected (filled in by the Balancer for
    /// Reader/Analytics targets); `None` when the target is Writer or when
    /// no healthy candidate was available.
    pub node_id: Option<String>,
    /// Human-readable routing reason, for logging/debugging.
    pub reason: Cow<'static, str>,
    pub forced_by_hint: bool,
    /// Set when routing fell back to Writer because no Reader satisfied the
    /// consistency check.
    pub fallback_to_writer: bool,
    /// Set when a transaction-split upgrade (Reader -> Writer) is required;
    /// the caller must issue ROLLBACK on the Reader before proceeding.
    pub requires_split_upgrade: bool,
}

impl RouteDecision {
    fn writer(reason: impl Into<Cow<'static, str>>) -> Self {
        RouteDecision {
            target: NodeType::Writer,
            node_id: None,
            reason: reason.into(),
            forced_by_hint: false,
            fallback_to_writer: false,
            requires_split_upgrade: false,
        }
    }

    fn writer_fallback(reason: impl Into<Cow<'static, str>>) -> Self {
        RouteDecision {
            target: NodeType::Writer,
            node_id: None,
            reason: reason.into(),
            forced_by_hint: false,
            fallback_to_writer: true,
            requires_split_upgrade: false,
        }
    }

    fn writer_upgrade(reason: impl Into<Cow<'static, str>>) -> Self {
        RouteDecision {
            target: NodeType::Writer,
            node_id: None,
            reason: reason.into(),
            forced_by_hint: false,
            fallback_to_writer: false,
            requires_split_upgrade: true,
        }
    }

    fn forced(target: NodeType, node_id: Option<String>, reason: impl Into<Cow<'static, str>>) -> Self {
        RouteDecision {
            target,
            node_id,
            reason: reason.into(),
            forced_by_hint: true,
            fallback_to_writer: false,
            requires_split_upgrade: false,
        }
    }

    fn selected(target: NodeType, node_id: Option<String>, reason: impl Into<Cow<'static, str>>) -> Self {
        RouteDecision {
            target,
            node_id,
            reason: reason.into(),
            forced_by_hint: false,
            fallback_to_writer: false,
            requires_split_upgrade: false,
        }
    }
}

/// Routing errors surfaced to the caller.
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("cost estimation failed: {0}")]
    CostEstimation(#[from] crate::router::cost::CostEstimationError),

    #[error("no Reader satisfies the requested consistency level and Writer reads are disabled")]
    NoReadableNode,
}

/// The minimal session-facing state the router needs to make a decision.
/// This intentionally borrows fields rather than requiring the full
/// `SessionState` type, keeping `Router` decoupled from session-internal
/// bookkeeping not relevant to routing.
pub struct RoutingContext<'a> {
    pub tx_state: TxState,
    pub tx_split: &'a mut Option<TxSplitState>,
    pub consistency: ConsistencyLevel,
    pub session_write_lsn: u64,
    pub global_write_lsn: u64,
}

/// Configuration flags affecting routing behavior (mirrors relevant fields
/// of `RoutingConfig`).
///
/// These are exactly the fields considered safe to hot-reload without a
/// restart (see `trident::reload` and DEPLOYMENT.md's hot-reload section):
/// none of them affect the shape of any long-lived resource (TCP listener,
/// connection pool, backend socket) -- they only change how the *next*
/// routing decision is made.
#[derive(Debug, Clone, Copy)]
pub struct RouterSettings {
    pub enable_transaction_split: bool,
    pub split_respects_consistency: bool,
    pub enable_hint_routing: bool,
    pub enable_cost_routing: bool,
    pub cost_threshold: f64,
    pub writer_readable: bool,
}

/// Core router: combines all signals to produce a `RouteDecision`.
///
/// `settings` is held behind an `ArcSwap` (rather than a plain field) so
/// it can be hot-reloaded via `update_settings` while the `Router` itself
/// stays behind a single long-lived `Arc` shared across every connection
/// task -- see `trident::reload`.
pub struct Router<C, H, CC, CE, LB>
where
    C: Classifier + Send + Sync,
    H: HintParser + Send + Sync,
    CC: ConsistencyChecker + Send + Sync,
    CE: CostEstimator,
    LB: LoadBalancer,
{
    classifier: C,
    hint_parser: H,
    consistency_checker: CC,
    cost_estimator: CE,
    load_balancer: LB,
    settings: ArcSwap<RouterSettings>,
    /// Optional custom table/function routing rules (see
    /// `router::custom_rules`). `None` (the default via `Router::new`,
    /// unchanged from before this feature existed) means no such rules
    /// are checked at all -- attach one via `with_custom_rules` to opt in.
    custom_rules: Option<Arc<CustomRoutingRules>>,
}

impl<C, H, CC, CE, LB> Router<C, H, CC, CE, LB>
where
    C: Classifier + Send + Sync,
    H: HintParser + Send + Sync,
    CC: ConsistencyChecker + Send + Sync,
    CE: CostEstimator,
    LB: LoadBalancer,
{
    pub fn new(
        classifier: C,
        hint_parser: H,
        consistency_checker: CC,
        cost_estimator: CE,
        load_balancer: LB,
        settings: RouterSettings,
    ) -> Self {
        Router {
            classifier,
            hint_parser,
            consistency_checker,
            cost_estimator,
            load_balancer,
            settings: ArcSwap::new(Arc::new(settings)),
            custom_rules: None,
        }
    }

    /// Attaches a shared `CustomRoutingRules` registry, whose writer-only
    /// rules are then consulted on every `route` call (see `route`'s
    /// "Step 3.5" below). The same `Arc<CustomRoutingRules>` can be handed
    /// out elsewhere (e.g. to an admin API for dynamic rule management)
    /// to manage the rule set live, independent of the `Router`.
    pub fn with_custom_rules(mut self, custom_rules: Arc<CustomRoutingRules>) -> Self {
        self.custom_rules = Some(custom_rules);
        self
    }

    /// Returns the currently effective settings (a cheap, lock-free read).
    pub fn settings(&self) -> RouterSettings {
        **self.settings.load()
    }

    /// Atomically replaces the effective settings, taking effect for every
    /// `route` call that starts after this returns (in-flight calls that
    /// already loaded the previous settings are unaffected -- there is no
    /// tearing, but also no retroactive effect on a decision already in
    /// progress). Safe to call concurrently with `route` from any number
    /// of connection tasks, and requires no `&mut self` since `ArcSwap`
    /// provides the necessary synchronization internally.
    pub fn update_settings(&self, settings: RouterSettings) {
        self.settings.store(Arc::new(settings));
    }

    /// Runs the consistency check for an autocommit read query and returns
    /// `true` if at least one eligible Reader remains among `readers`.
    fn consistency_passes(
        &self,
        consistency: ConsistencyLevel,
        session_write_lsn: u64,
        global_write_lsn: u64,
        readers: &[BackendNodeSnapshot],
    ) -> Vec<String> {
        self.consistency_checker.eligible_readers(
            consistency,
            session_write_lsn,
            global_write_lsn,
            readers,
        )
    }

    fn select_all_candidates(&self, nodes: &[BackendNodeSnapshot]) -> Option<String> {
        let candidates: Vec<NodeCandidate> = nodes
            .iter()
            .map(|n| NodeCandidate {
                node_id: n.node_id.clone(),
                weight: n.weight,
                active_connections: n.active_connections,
            })
            .collect();
        self.load_balancer.select(&candidates)
    }

    fn select_from_candidates(
        &self,
        node_ids: &[String],
        all_nodes: &[BackendNodeSnapshot],
    ) -> Option<String> {
        // Linear membership checks are cheaper for the normal small-node
        // case. Use a set for larger topologies to avoid O(nodes * eligible)
        // filtering when consistency leaves many Readers eligible.
        const LINEAR_MEMBERSHIP_LIMIT: usize = 8;
        let candidates: Vec<NodeCandidate> = if node_ids.len() <= LINEAR_MEMBERSHIP_LIMIT {
            all_nodes
                .iter()
                .filter(|n| node_ids.contains(&n.node_id))
                .map(|n| NodeCandidate {
                    node_id: n.node_id.clone(),
                    weight: n.weight,
                    active_connections: n.active_connections,
                })
                .collect()
        } else {
            let node_ids: HashSet<&str> = node_ids.iter().map(String::as_str).collect();
            all_nodes
                .iter()
                .filter(|n| node_ids.contains(n.node_id.as_str()))
                .map(|n| NodeCandidate {
                    node_id: n.node_id.clone(),
                    weight: n.weight,
                    active_connections: n.active_connections,
                })
                .collect()
        };
        self.load_balancer.select(&candidates)
    }

    /// Core routing entry point.
    ///
    /// `readers` and `analytics_nodes` should contain only nodes currently
    /// marked healthy (Requirement 9.6 excludes unhealthy nodes upstream, in
    /// the PoolManager/HealthChecker snapshot pipeline; the Router assumes
    /// its input candidate lists are already health-filtered).
    pub async fn route(
        &self,
        sql: &str,
        ctx: &mut RoutingContext<'_>,
        readers: &[BackendNodeSnapshot],
        analytics_nodes: &[BackendNodeSnapshot],
        writers: &[BackendNodeSnapshot],
    ) -> Result<RouteDecision, RouterError> {
        // Loaded once per `route` call so every step below observes a
        // single consistent snapshot of settings, even if `update_settings`
        // is called concurrently by another task partway through.
        let settings = self.settings.load();

        // A Simple Query frame may contain multiple SQL statements. If ALL
        // statements are read-only, allow routing to Reader. Otherwise
        // conservatively route to Writer. This safety rule intentionally
        // takes precedence over Reader hints for mixed-intent batches.
        if contains_multiple_statements(sql)
            && !multi_statement_all_readable(&self.classifier, sql)
        {
            return Ok(RouteDecision::writer(
                "multiple statements with write intent in one simple-query message",
            ));
        }

        // Step 1: Hint parsing (Requirements 2.1-2.5). A forced-route hint
        // takes priority over everything else and skips consistency checks.
        if settings.enable_hint_routing {
            match self.hint_parser.parse_hint(sql) {
                RouteHint::ForceWriter => {
                    return Ok(RouteDecision::forced(NodeType::Writer, None, "hint: ROUTE_TO_WRITER"));
                }
                RouteHint::ForceReader => {
                    let node_id = self.select_all_candidates(readers);
                    return Ok(RouteDecision::forced(NodeType::Reader, node_id, "hint: ROUTE_TO_READER"));
                }
                RouteHint::ForceAnalytics => {
                    let node_id = self.select_all_candidates(analytics_nodes);
                    return Ok(RouteDecision::forced(
                        NodeType::Analytics,
                        node_id,
                        "hint: ROUTE_TO_ANALYTICS",
                    ));
                }
                RouteHint::Consistency(level) => {
                    ctx.consistency = level;
                    // fall through: consistency hint only overrides the level,
                    // routing continues through the normal pipeline below.
                }
                RouteHint::None => {}
            }
        }

        // Step 2: Transaction state check (Requirements 3.7, 4.1-4.10). If
        // the session is inside an explicit transaction, delegate entirely
        // to the transaction-split state machine and skip both SQL
        // classification-driven writer routing and consistency checks
        // (Requirement 3.7 / Property 14).
        if ctx.tx_state == TxState::InTransaction {
            if let Some(tx_split) = ctx.tx_split.as_mut() {
                let stmt_kind = if self.classifier.classify(sql).requires_writer()
                    || self.classifier.has_write_function_call(sql)
                {
                    StatementKind::Write
                } else {
                    StatementKind::Read
                };

                let consistency = ctx.consistency;
                let session_write_lsn = ctx.session_write_lsn;
                let global_write_lsn = ctx.global_write_lsn;

                let action = TxSplitEngine::route_statement(tx_split, stmt_kind, || {
                    !self
                        .consistency_checker
                        .eligible_readers(consistency, session_write_lsn, global_write_lsn, readers)
                        .is_empty()
                });

                return Ok(match action {
                    TxRouteAction::RouteToReader => {
                        let node_id = self.select_all_candidates(readers);
                        RouteDecision::selected(NodeType::Reader, node_id, "transaction split: TX_READING")
                    }
                    TxRouteAction::RouteToWriter => {
                        RouteDecision::writer("transaction split: routed to Writer")
                    }
                    TxRouteAction::UpgradeReaderToWriter => {
                        RouteDecision::writer_upgrade(
                            "transaction split: upgrading from Reader to Writer",
                        )
                    }
                });
            }
            // No tx_split state tracked (transaction splitting effectively
            // disabled for this session): explicit transactions go to Writer.
            return Ok(RouteDecision::writer("explicit transaction, no split tracking"));
        }

        // Step 3-4: SQL classification and write-function detection
        // (Requirements 1.1, 1.3).
        let sql_kind = self.classifier.classify(sql);
        if sql_kind.requires_writer() || self.classifier.has_write_function_call(sql) {
            return Ok(RouteDecision::writer("write statement or write function call"));
        }

        if !sql_kind.readable() {
            // Statements not recognized as clearly read-only (Requirement
            // 1.2 only covers plain SELECT/SHOW/EXPLAIN) are conservatively
            // routed to Writer.
            return Ok(RouteDecision::writer("unclassified statement, defaulting to Writer"));
        }

        // Step 4.5: Custom table/function routing rules (see
        // `router::custom_rules`). Only checked for statements that would
        // otherwise be Reader-eligible at this point -- a custom rule can
        // only ever *add* a writer-only restriction on top of the normal
        // pipeline, never force a write statement to become readable.
        if let Some(custom_rules) = &self.custom_rules {
            if let Some(reason) = custom_rules.forces_writer(sql) {
                return Ok(RouteDecision::writer(reason));
            }
        }

        // Step 5: Cost-based routing to Analytics (Requirements 10.1-10.5).
        if settings.enable_cost_routing {
            // Cost estimation failure (e.g. unsupported SQL syntax, connection
            // issues) is non-fatal: treat as cost=0 (below threshold) and let
            // the query proceed to a Reader via the normal consistency path.
            let cost = self.cost_estimator.estimate_cost(sql).await.unwrap_or_else(|e| {
                let truncated: String = sql.chars().take(80).collect();
                tracing::debug!(error = %e, sql = %truncated, "cost estimation failed, skipping cost routing");
                0.0
            });
            if cost > settings.cost_threshold {
                let node_id = self.select_all_candidates(analytics_nodes);
                return Ok(RouteDecision::selected(
                    NodeType::Analytics,
                    node_id,
                    "cost-based routing: exceeds cost_threshold",
                ));
            }
        }

        // Step 6: Consistency check for autocommit reads (Requirements 3.3-3.6).
        let eligible = self.consistency_passes(
            ctx.consistency,
            ctx.session_write_lsn,
            ctx.global_write_lsn,
            readers,
        );
        if eligible.is_empty() {
            if settings.writer_readable {
                return Ok(RouteDecision::writer_fallback(
                    "no reader satisfies consistency requirement",
                ));
            }
            return Err(RouterError::NoReadableNode);
        }

        // Step 7: Load-balanced selection among eligible readers (and
        // writer when writer_readable is enabled).
        if settings.writer_readable {
            // Include writer(s) in the candidate pool for load balancing.
            let mut all_candidates: Vec<NodeCandidate> = eligible
                .iter()
                .filter_map(|id| readers.iter().find(|n| &n.node_id == id))
                .map(|n| NodeCandidate {
                    node_id: n.node_id.clone(),
                    weight: n.weight,
                    active_connections: n.active_connections,
                })
                .collect();
            for w in writers {
                all_candidates.push(NodeCandidate {
                    node_id: w.node_id.clone(),
                    weight: w.weight,
                    active_connections: w.active_connections,
                });
            }
            if let Some(node_id) = self.load_balancer.select(&all_candidates) {
                // Check if the selected node is a writer
                if writers.iter().any(|w| w.node_id == node_id) {
                    return Ok(RouteDecision::writer("autocommit read, writer selected by load balancer"));
                }
                return Ok(RouteDecision::selected(NodeType::Reader, Some(node_id), "autocommit read, consistency satisfied"));
            }
        }

        let node_id = self.select_from_candidates(&eligible, readers);
        Ok(RouteDecision::selected(NodeType::Reader, node_id, "autocommit read, consistency satisfied"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::WeightedRoundRobin;
    use crate::parser::classifier::KeywordClassifier;
    use crate::parser::hint::RegexHintParser;
    use crate::parser::pattern::RegexPatternMatcher;
    use crate::router::consistency::LsnConsistencyChecker;
    use crate::router::cost::{CostEstimationError, DefaultCostEstimator, ExplainRunner};
    use crate::session::session::IsolationLevel;
    use proptest::prelude::*;

    struct FixedCostRunner {
        cost: f64,
    }
    impl ExplainRunner for FixedCostRunner {
        async fn explain_cost(&self, _sql: &str) -> Result<f64, CostEstimationError> {
            Ok(self.cost)
        }
    }

    type TestRouter = Router<
        KeywordClassifier,
        RegexHintParser,
        LsnConsistencyChecker,
        DefaultCostEstimator<RegexPatternMatcher, FixedCostRunner>,
        WeightedRoundRobin,
    >;

    fn make_router(settings: RouterSettings, cost: f64, patterns: &[String]) -> TestRouter {
        Router::new(
            KeywordClassifier,
            RegexHintParser,
            LsnConsistencyChecker,
            DefaultCostEstimator::new(
                RegexPatternMatcher::new(patterns).unwrap(),
                FixedCostRunner { cost },
            ),
            WeightedRoundRobin::new(),
            settings,
        )
    }

    fn default_settings() -> RouterSettings {
        RouterSettings {
            enable_transaction_split: true,
            split_respects_consistency: true,
            enable_hint_routing: true,
            enable_cost_routing: true,
            cost_threshold: 50_000.0,
            writer_readable: true,
        }
    }

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

    fn idle_ctx(consistency: ConsistencyLevel) -> (Option<TxSplitState>, ConsistencyLevel) {
        (None, consistency)
    }

    // -----------------------------------------------------------------
    // Integration-level unit tests (task 13.7): cross-cutting priority checks
    // Validates: Requirements 2.1, 2.2, 2.3, 3.7
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn hint_priority_over_consistency_check() {
        // Even with no readers available to satisfy consistency, a
        // ROUTE_TO_READER hint must still force Reader without triggering a
        // consistency-driven Writer fallback.
        let router = make_router(default_settings(), 0.0, &[]);
        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Global,
            session_write_lsn: 1000,
            global_write_lsn: 1000,
        };
        let readers = vec![reader("r1", 0)]; // far behind, would fail Global check
        let decision = router
            .route("/*+ ROUTE_TO_READER */ SELECT 1", &mut ctx, &readers, &[], &[])
            .await
            .unwrap();
        assert_eq!(decision.target, NodeType::Reader);
        assert!(decision.forced_by_hint);
        assert!(!decision.fallback_to_writer);
    }

    #[tokio::test]
    async fn transaction_state_priority_over_sql_classification() {
        // Inside an explicit transaction with split disabled (no tx_split
        // tracked), even a plain read-only SELECT must go to Writer.
        let router = make_router(default_settings(), 0.0, &[]);
        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::InTransaction,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Eventual,
            session_write_lsn: 0,
            global_write_lsn: 0,
        };
        let decision = router.route("SELECT 1", &mut ctx, &[], &[], &[]).await.unwrap();
        assert_eq!(decision.target, NodeType::Writer);
    }

    #[tokio::test]
    async fn explicit_transaction_skips_consistency_check() {
        // Requirement 3.7 / Property 14: statements inside an explicit
        // transaction never trigger fallback_to_writer due to a consistency
        // failure -- the transaction-split engine handles routing instead.
        let router = make_router(default_settings(), 0.0, &[]);
        let mut tx_split = Some(TxSplitState::pending(
            IsolationLevel::ReadCommitted,
            false,
            true,
            true,
        ));
        let mut ctx = RoutingContext {
            tx_state: TxState::InTransaction,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Global,
            session_write_lsn: 1000,
            global_write_lsn: 1000,
        };
        // No readers satisfy the (very strict) consistency requirement, but
        // the decision must never set fallback_to_writer=true.
        let decision = router.route("SELECT 1", &mut ctx, &[], &[], &[]).await.unwrap();
        assert!(!decision.fallback_to_writer);
    }

    #[tokio::test]
    async fn custom_rule_forces_writer_for_an_otherwise_readable_query() {
        use crate::router::custom_rules::{CustomRoutingRules, RuleTargetKind, RwMode};

        let custom_rules = std::sync::Arc::new(CustomRoutingRules::new());
        custom_rules.set_rule("sensitive_table", RuleTargetKind::Table, RwMode::Writer);
        let router = make_router(default_settings(), 0.0, &[]).with_custom_rules(custom_rules);

        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Eventual,
            session_write_lsn: 0,
            global_write_lsn: 0,
        };
        let readers = vec![reader("r1", 0)];
        let decision = router
            .route("SELECT * FROM sensitive_table", &mut ctx, &readers, &[], &[])
            .await
            .unwrap();
        assert_eq!(decision.target, NodeType::Writer);
        assert!(!decision.forced_by_hint);
        assert!(!decision.fallback_to_writer);
    }

    #[tokio::test]
    async fn custom_rule_does_not_affect_unrelated_queries() {
        use crate::router::custom_rules::{CustomRoutingRules, RuleTargetKind, RwMode};

        let custom_rules = std::sync::Arc::new(CustomRoutingRules::new());
        custom_rules.set_rule("sensitive_table", RuleTargetKind::Table, RwMode::Writer);
        let router = make_router(default_settings(), 0.0, &[]).with_custom_rules(custom_rules);

        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Eventual,
            session_write_lsn: 0,
            global_write_lsn: 0,
        };
        let readers = vec![reader("r1", 0)];
        let decision = router
            .route("SELECT * FROM unrelated_table", &mut ctx, &readers, &[], &[])
            .await
            .unwrap();
        assert_eq!(decision.target, NodeType::Reader);
    }

    #[tokio::test]
    async fn hint_still_takes_priority_over_a_custom_writer_only_rule() {
        use crate::router::custom_rules::{CustomRoutingRules, RuleTargetKind, RwMode};

        let custom_rules = std::sync::Arc::new(CustomRoutingRules::new());
        custom_rules.set_rule("sensitive_table", RuleTargetKind::Table, RwMode::Writer);
        let router = make_router(default_settings(), 0.0, &[]).with_custom_rules(custom_rules);

        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Eventual,
            session_write_lsn: 0,
            global_write_lsn: 0,
        };
        let readers = vec![reader("r1", 0)];
        let decision = router
            .route(
                "/*+ ROUTE_TO_READER */ SELECT * FROM sensitive_table",
                &mut ctx,
                &readers,
                &[], &[],
            )
            .await
            .unwrap();
        assert_eq!(decision.target, NodeType::Reader);
        assert!(decision.forced_by_hint);
    }

    #[tokio::test]
    async fn writer_readable_false_rejects_read_when_no_reader_is_eligible() {
        let mut settings = default_settings();
        settings.writer_readable = false;
        let router = make_router(settings, 0.0, &[]);
        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Global,
            session_write_lsn: 100,
            global_write_lsn: 100,
        };
        let readers = vec![reader("lagging-reader", 1)];
        let result = router.route("SELECT 1", &mut ctx, &readers, &[], &[]).await;
        assert!(matches!(result, Err(RouterError::NoReadableNode)));
    }

    #[tokio::test]
    async fn writer_readable_true_falls_back_when_no_reader_is_eligible() {
        let router = make_router(default_settings(), 0.0, &[]);
        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Global,
            session_write_lsn: 100,
            global_write_lsn: 100,
        };
        let readers = vec![reader("lagging-reader", 1)];
        let decision = router
            .route("SELECT 1", &mut ctx, &readers, &[], &[])
            .await
            .unwrap();
        assert_eq!(decision.target, NodeType::Writer);
        assert!(decision.fallback_to_writer);
    }

    #[tokio::test]
    async fn write_statement_always_routes_to_writer() {
        let router = make_router(default_settings(), 0.0, &[]);
        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Eventual,
            session_write_lsn: 0,
            global_write_lsn: 0,
        };
        let decision = router
            .route("INSERT INTO t VALUES (1)", &mut ctx, &[], &[], &[])
            .await
            .unwrap();
        assert_eq!(decision.target, NodeType::Writer);
    }

    #[tokio::test]
    async fn multiple_statements_force_writer_even_when_first_is_read_and_hint_requests_reader() {
        let router = make_router(default_settings(), 0.0, &[]);
        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Eventual,
            session_write_lsn: 0,
            global_write_lsn: 0,
        };
        let readers = vec![reader("r1", 0)];
        let decision = router
            .route(
                "/*+ ROUTE_TO_READER */ SELECT 1; INSERT INTO t VALUES (1)",
                &mut ctx,
                &readers,
                &[],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(decision.target, NodeType::Writer);
        assert!(!decision.forced_by_hint);
        assert!(decision.reason.contains("multiple statements"));
    }

    #[tokio::test]
    async fn update_settings_takes_effect_on_the_next_route_call() {
        // enable_hint_routing starts true, so the hint forces Reader...
        let router = make_router(default_settings(), 0.0, &[]);
        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Eventual,
            session_write_lsn: 0,
            global_write_lsn: 0,
        };
        let readers = vec![reader("r1", 0)];
        let decision = router
            .route("/*+ ROUTE_TO_READER */ SELECT 1", &mut ctx, &readers, &[], &[])
            .await
            .unwrap();
        assert_eq!(decision.target, NodeType::Reader);

        // ... until hot-reloaded with hint routing disabled, at which
        // point the very next call must ignore the hint (classified as a
        // plain autocommit read here, Eventual consistency always has an
        // eligible reader).
        let mut settings = default_settings();
        settings.enable_hint_routing = false;
        router.update_settings(settings);

        let mut tx_split2 = None;
        let mut ctx2 = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split2,
            consistency: ConsistencyLevel::Eventual,
            session_write_lsn: 0,
            global_write_lsn: 0,
        };
        let decision2 = router
            .route("/*+ ROUTE_TO_READER */ SELECT 1", &mut ctx2, &readers, &[], &[])
            .await
            .unwrap();
        assert!(!decision2.forced_by_hint);
        assert_eq!(decision2.target, NodeType::Reader); // still Reader, but via the normal autocommit-read path
    }

    #[test]
    fn settings_reflects_the_current_effective_configuration() {
        let router = make_router(default_settings(), 0.0, &[]);
        assert!(router.settings().enable_hint_routing);

        let mut updated = default_settings();
        updated.enable_hint_routing = false;
        updated.cost_threshold = 12345.0;
        router.update_settings(updated);

        let observed = router.settings();
        assert!(!observed.enable_hint_routing);
        assert_eq!(observed.cost_threshold, 12345.0);
    }

    #[tokio::test]
    async fn autocommit_read_falls_back_to_writer_when_no_reader_eligible() {
        let router = make_router(default_settings(), 0.0, &[]);
        let mut tx_split = None;
        let (_, consistency) = idle_ctx(ConsistencyLevel::Session);
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency,
            session_write_lsn: 1000,
            global_write_lsn: 1000,
        };
        let readers = vec![reader("r1", 0)];
        let decision = router.route("SELECT 1", &mut ctx, &readers, &[], &[]).await.unwrap();
        assert_eq!(decision.target, NodeType::Writer);
        assert!(decision.fallback_to_writer);
    }

    #[tokio::test]
    async fn autocommit_read_routes_to_reader_when_eligible() {
        let router = make_router(default_settings(), 0.0, &[]);
        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Session,
            session_write_lsn: 100,
            global_write_lsn: 100,
        };
        let readers = vec![reader("r1", 200)];
        let decision = router.route("SELECT 1", &mut ctx, &readers, &[], &[]).await.unwrap();
        assert_eq!(decision.target, NodeType::Reader);
        assert_eq!(decision.node_id, Some("r1".to_string()));
    }

    #[tokio::test]
    async fn cost_based_routing_to_analytics() {
        let router = make_router(default_settings(), 100_000.0, &[]);
        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Eventual,
            session_write_lsn: 0,
            global_write_lsn: 0,
        };
        let analytics = vec![BackendNodeSnapshot {
            node_id: "an1".to_string(),
            node_type: NodeType::Analytics,
            healthy: true,
            replay_lsn: 0,
            active_connections: 0,
            weight: 1,
            replication_lag_ms: None,
        }];
        let decision = router
            .route("SELECT * FROM huge_table", &mut ctx, &[], &analytics, &[])
            .await
            .unwrap();
        assert_eq!(decision.target, NodeType::Analytics);
    }

    #[tokio::test]
    async fn cost_routing_disabled_never_routes_to_analytics() {
        let mut settings = default_settings();
        settings.enable_cost_routing = false;
        let router = make_router(settings, 1_000_000.0, &[]);
        let mut tx_split = None;
        let mut ctx = RoutingContext {
            tx_state: TxState::Idle,
            tx_split: &mut tx_split,
            consistency: ConsistencyLevel::Eventual,
            session_write_lsn: 0,
            global_write_lsn: 0,
        };
        let analytics = vec![BackendNodeSnapshot {
            node_id: "an1".to_string(),
            node_type: NodeType::Analytics,
            healthy: true,
            replay_lsn: 0,
            active_connections: 0,
            weight: 1,
            replication_lag_ms: None,
        }];
        let decision = router
            .route("SELECT * FROM huge_table", &mut ctx, &[], &analytics, &[])
            .await
            .unwrap();
        assert_ne!(decision.target, NodeType::Analytics);
    }

    // -----------------------------------------------------------------
    // Property 13: a failed consistency check always falls back to Writer
    // Validates: Requirements 3.6
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_13_consistency_failure_falls_back_to_writer(
            level in prop_oneof![Just(ConsistencyLevel::Session), Just(ConsistencyLevel::Global)],
            session_write_lsn in 100u64..1000,
            global_write_lsn in 100u64..1000,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let router = make_router(default_settings(), 0.0, &[]);
            let mut tx_split = None;
            let mut ctx = RoutingContext {
                tx_state: TxState::Idle,
                tx_split: &mut tx_split,
                consistency: level,
                session_write_lsn,
                global_write_lsn,
            };
            // Reader lags behind both thresholds -> no eligible reader.
            let readers = vec![reader("r1", 0)];
            let decision = rt.block_on(router.route("SELECT 1", &mut ctx, &readers, &[], &[])).unwrap();
            prop_assert_eq!(decision.target, NodeType::Writer);
            prop_assert!(decision.fallback_to_writer);
        }
    }

    // Property 31 (CANCEL request forwarded iff the connection mapping
    // still matches the requesting session) is now covered by
    // `proxy::registry::CancelRegistry` tests -- see
    // `property_cancel_resolves_iff_key_known_and_session_active` in
    // `src/proxy/registry.rs`, since that module now owns this logic.
}
