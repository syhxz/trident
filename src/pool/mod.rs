//! Connection pool module (`pool`)
//!
//! Handles establishing backend connections, pool management, connection
//! pinning, and cleanup-before-return logic.

pub mod conn;
pub mod manager;
pub mod pinning;
pub mod pool;

pub use conn::{establish_connection, ConnectTarget, ConnError, MaybeTlsStream, PooledConnection};
pub use manager::{emit_pool_metrics, InMemoryPoolManager, PoolManager};
pub use pinning::{detects_pinning_trigger, PinningTrigger};
pub use pool::{
    ConnCleaner, ConnFactory, ConnectionPool, NodePool, PoolError, DISCARD_ALL_STATEMENT,
    PRECISE_RESET_STATEMENTS,
};
