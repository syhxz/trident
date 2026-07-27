//! Router module (`router`)
//!
//! Combines hints, transaction state, SQL classification, cost estimation,
//! and consistency checking to produce routing decisions.

pub mod consistency;
pub mod cost;
pub mod custom_rules;
pub mod router;

pub use consistency::{ConsistencyChecker, LsnConsistencyChecker};
pub use cost::{CostEstimationError, CostEstimator, DefaultCostEstimator, ExplainRunner};
pub use custom_rules::{CustomRoutingRules, CustomRuleEntry, RuleTargetKind, RwMode};
pub use router::{Router, RouteDecision, RouterError, RouterSettings, RoutingContext};
