#![allow(clippy::module_inception)]
//! Session and transaction state module (`session`)
//!
//! Maintains, per client connection, the consistency level, LSN, the
//! transaction state machine, and the transaction-split state.

pub mod lsn;
pub mod session;
pub mod transaction;

pub use lsn::{InMemoryLsnTracker, LsnTracker};
pub use session::{IsolationLevel, SessionState, TxState};
pub use transaction::{StatementKind, TxRouteAction, TxSplitEngine, TxSplitState};
