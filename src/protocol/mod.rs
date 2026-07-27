//! Protocol module (`protocol`)
//!
//! Handles parsing and encoding of PostgreSQL Wire Protocol messages, and
//! Startup/authentication handling.

mod cursor;
pub mod auth;
pub mod message;
pub mod reader;
pub mod startup;
pub mod writer;

pub use message::{
    BackendMessage, DescribeKind, FieldDescription, FrontendMessage, PgError, StartupMessage,
    TransactionStatus,
};
pub use reader::{read_backend_message, read_frontend_message, MessageReader, TokioMessageReader};
pub use startup::{read_startup_packet, AuthOutcome, StartupHandler, StartupPacket, TrustStartupHandler};
pub use writer::{
    encode_backend_message, encode_frontend_message, encode_password_message,
    encode_sasl_initial_response, encode_sasl_response, MessageWriter, TokioMessageWriter,
};

/// Protocol-layer error: covers I/O failures as well as structured parsing
/// errors for malformed/truncated messages.
///
/// All parsing functions must return one of this error's variants when
/// encountering an invalid byte stream, rather than panicking or looping
/// forever (see Requirement 13.3 / Property 51).
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("connection closed before a complete message could be read")]
    UnexpectedEof,

    #[error("invalid or unrecognized message type byte: {0:#x}")]
    InvalidMessageType(u8),

    #[error("invalid message length: {0}")]
    InvalidLength(i32),

    #[error("message body contains invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("malformed message: {0}")]
    Malformed(String),
}
