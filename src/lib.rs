//! Trident: PostgreSQL intelligent read/write splitting proxy (library)
//!
//! This crate is organized as a library + binary: `lib.rs` re-exports all
//! modules, for use by both `main.rs` and the integration tests under
//! `tests/`.

pub mod admin;
pub mod balancer;
pub mod config;
pub mod health;
pub mod logging;
pub mod parser;
pub mod pool;
pub mod protocol;
pub mod proxy;
pub mod reload;
pub mod router;
pub mod session;
