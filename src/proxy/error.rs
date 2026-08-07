//! Proxy-level error handling (`error`)
//!
//! Maps internal errors (failed backend acquisition, protocol errors,
//! router errors, panics) to well-formed PostgreSQL `ErrorResponse`
//! messages that can be sent back to the client without ever leaking
//! internal Rust panic details. See Requirements 13.1, 13.4, 13.5 and
//! Property 49.

use crate::pool::pool::PoolError;
use crate::protocol::message::PgError;
use crate::protocol::ProtocolError;
use crate::router::router::RouterError;

/// Top-level proxy error type covering everything that can go wrong while
/// handling a single client connection.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("pool error: {0}")]
    Pool(#[from] PoolError),

    #[error("router error: {0}")]
    Router(#[from] RouterError),

    #[error("connection handler task panicked: {0}")]
    Panic(String),

    /// A backend ErrorResponse was already forwarded to the client before
    /// the connection failed. The outer message loop must NOT send another
    /// ErrorResponse; it should only send ReadyForQuery and update state.
    #[error("backend error already relayed: {0}")]
    BackendErrorAlreadyRelayed(Box<ProxyError>),
}

/// Converts a `ProxyError` into a well-formed `PgError` (SQLSTATE + message)
/// suitable for sending to the client as an `ErrorResponse`. Never panics
/// and never leaks raw Rust panic payloads verbatim -- panic messages are
/// wrapped in a generic "internal error" envelope (Requirement 13.4/13.5).
///
/// SQLSTATE codes follow the PostgreSQL error codes table where a
/// reasonably close match exists; otherwise a generic internal-error code
/// is used.
pub fn proxy_error_to_pg_error(err: &ProxyError) -> PgError {
    let (sqlstate, message) = match err {
        ProxyError::Pool(PoolError::Exhausted(node)) => (
            "53300", // too_many_connections
            format!("connection pool exhausted for node '{node}'"),
        ),
        ProxyError::Pool(PoolError::AcquireTimeout {
            node_id,
            timeout_ms,
        }) => (
            "53300", // too_many_connections
            format!("timed out after {timeout_ms} ms waiting for an available connection for node '{node_id}'"),
        ),
        ProxyError::Pool(PoolError::ConnectFailed(reason)) => (
            "08001", // sqlclient_unable_to_establish_sqlconnection
            format!("failed to connect to backend: {reason}"),
        ),
        ProxyError::Pool(PoolError::ConnectTimeout {
            node_id,
            timeout_ms,
        }) => (
            "08001", // sqlclient_unable_to_establish_sqlconnection
            format!("timed out after {timeout_ms} ms connecting to backend node '{node_id}'"),
        ),
        ProxyError::Pool(PoolError::CleanupFailed(reason)) => (
            "58000", // system_error
            format!("failed to prepare backend connection for reuse: {reason}"),
        ),
        ProxyError::Pool(PoolError::NodeMismatch) => (
            "XX000", // internal_error
            "internal error: connection/node mismatch".to_string(),
        ),
        ProxyError::Protocol(ProtocolError::UnexpectedEof) => (
            "08006", // connection_failure
            "connection closed unexpectedly".to_string(),
        ),
        ProxyError::Protocol(other) => ("08P01", format!("protocol error: {other}")),
        ProxyError::Router(RouterError::CostEstimation(reason)) => (
            "XX000",
            format!("failed to determine query route: {reason}"),
        ),
        ProxyError::Router(RouterError::NoReadableNode) => (
            "57P03", // cannot_connect_now / no eligible serving node
            "no readable backend satisfies the requested consistency level".to_string(),
        ),
        ProxyError::Panic(_) => (
            "XX000",
            "internal error: the proxy encountered an unexpected condition while processing this request".to_string(),
        ),
        ProxyError::BackendErrorAlreadyRelayed(inner) => {
            // This variant should normally never be converted to a PgError
            // (the outer loop skips sending an error), but handle it
            // gracefully by delegating to the wrapped inner error.
            return proxy_error_to_pg_error(inner);
        }
    };

    PgError::simple("ERROR", sqlstate, &message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -----------------------------------------------------------------
    // Property 49: backend connection acquisition failures always produce
    // a well-formed PostgreSQL error response (non-empty SQLSTATE and
    // message; the proxy process must not crash -- verified here by the
    // absence of panics across arbitrary error variants).
    // Validates: Requirements 13.1
    // -----------------------------------------------------------------

    fn pool_error_strategy() -> impl Strategy<Value = PoolError> {
        prop_oneof![
            "[a-z-]{1,10}".prop_map(PoolError::Exhausted),
            "[a-z ]{1,20}".prop_map(PoolError::ConnectFailed),
            Just(PoolError::ConnectTimeout {
                node_id: "writer".to_string(),
                timeout_ms: 5,
            }),
            "[a-z ]{1,20}".prop_map(PoolError::CleanupFailed),
            Just(PoolError::NodeMismatch),
        ]
    }

    proptest! {
        #[test]
        fn property_49_pool_errors_produce_well_formed_error_response(err in pool_error_strategy()) {
            let proxy_err = ProxyError::Pool(err);
            let pg_err = proxy_error_to_pg_error(&proxy_err);

            let sqlstate = pg_err.sqlstate().unwrap_or_default();
            prop_assert_eq!(sqlstate.len(), 5, "SQLSTATE must be exactly 5 characters");
            prop_assert!(sqlstate.chars().all(|c| c.is_ascii_alphanumeric()));
            prop_assert!(pg_err.message().is_some());
            prop_assert!(!pg_err.message().unwrap().is_empty());
        }

        #[test]
        fn property_49_panic_messages_never_leak_raw_payload(panic_msg in "[a-zA-Z0-9 ]{8,200}") {
            let proxy_err = ProxyError::Panic(panic_msg.clone());
            let pg_err = proxy_error_to_pg_error(&proxy_err);
            let message = pg_err.message().unwrap_or_default();
            // The response must be the fixed, generic envelope text -- never a
            // function of the raw panic payload. Checking exact equality
            // (rather than "does not contain the payload") also rules out the
            // panic message being interleaved with or appended to the
            // envelope in some other way.
            prop_assert_eq!(
                message,
                "internal error: the proxy encountered an unexpected condition while processing this request"
            );
            // Belt-and-suspenders: for payloads long/varied enough to be
            // distinguishable from the fixed envelope's own wording, the
            // envelope must not happen to embed them either.
            prop_assert!(!message.contains(&panic_msg));
            prop_assert_eq!(pg_err.sqlstate(), Some("XX000"));
        }
    }

    // -----------------------------------------------------------------
    // Unit tests
    // -----------------------------------------------------------------

    #[test]
    fn exhausted_pool_maps_to_too_many_connections() {
        let err = ProxyError::Pool(PoolError::Exhausted("writer".to_string()));
        let pg_err = proxy_error_to_pg_error(&err);
        assert_eq!(pg_err.sqlstate(), Some("53300"));
        assert!(pg_err.message().unwrap().contains("writer"));
    }

    #[test]
    fn connect_failed_maps_to_connection_exception() {
        let err = ProxyError::Pool(PoolError::ConnectFailed("timeout".to_string()));
        let pg_err = proxy_error_to_pg_error(&err);
        assert_eq!(pg_err.sqlstate(), Some("08001"));
    }

    #[test]
    fn no_readable_node_maps_to_cannot_connect_now() {
        let err = ProxyError::Router(RouterError::NoReadableNode);
        let pg_err = proxy_error_to_pg_error(&err);
        assert_eq!(pg_err.sqlstate(), Some("57P03"));
        assert!(pg_err.message().unwrap().contains("no readable backend"));
    }

    #[test]
    fn unexpected_eof_maps_to_connection_failure() {
        let err = ProxyError::Protocol(ProtocolError::UnexpectedEof);
        let pg_err = proxy_error_to_pg_error(&err);
        assert_eq!(pg_err.sqlstate(), Some("08006"));
    }
}
