//! Health check module (`health`)
//!
//! Periodically checks backend node reachability, replication lag, and
//! LSN, deciding when nodes should be excluded or restored.

pub mod checker;
pub mod role_detector;

pub use checker::{
    is_excluded_by_replication_lag, parse_lsn, BackendNodeSnapshot, HealthCheckResult,
    HealthChecker, HealthProbe, HealthStateMachine, ProbeTarget, WireProtocolHealthProbe,
};
pub use role_detector::{
    create_role_detector, AutoNodeInfo, PatroniRoleDetector, ProbeRoleDetector, RepmgrNodeInfo,
    RepmgrRoleDetector, RoleDetectionError, RoleDetector, RoleMap,
};
