//! Proxy service layer (`proxy`)
//!
//! Ties together the protocol, router, pool, session, and health modules
//! into a runnable PostgreSQL wire-protocol proxy server.

pub mod client_stats;
pub mod error;
pub mod forwarder;
pub mod handler;
pub mod registry;
pub mod server;

pub use client_stats::{ClientStats, ClientStatsEntry};
pub use error::{proxy_error_to_pg_error, ProxyError};
pub use forwarder::{
    apply_ready_for_query, is_write_command_tag, maybe_record_write_lsn, ExtendedQueryRouteTracker,
};
pub use handler::{ClientSession, ConnectionHandler, QueryLogSettings, RouteFn};
pub use registry::{
    send_cancel_request, CancelRegistry, ConnectionRegistry, DiscardAllCleaner, LiveConnFactory,
    NodeAddress,
};
pub use server::{ProxyDeps, ProxyServer};
