//! PostgreSQL Wire Protocol message type definitions (`message`)
//!
//! See <https://www.postgresql.org/docs/current/protocol-message-formats.html>

use std::collections::HashMap;

/// `StartupMessage`: the first message a client sends when opening a
/// connection (has no type byte).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupMessage {
    pub protocol_version: i32,
    /// Parameter key/value pairs (e.g. `user`, `database`,
    /// `application_name`, etc.)
    pub params: HashMap<String, String>,
}

/// The kind of target identified in a `Describe` message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescribeKind {
    Statement,
    Portal,
}

/// Frontend (client -> proxy) message
#[derive(Debug, Clone, PartialEq)]
pub enum FrontendMessage {
    Startup(StartupMessage),
    /// Simple query protocol
    Query(String),
    Parse {
        name: String,
        sql: String,
        param_types: Vec<i32>,
    },
    Bind {
        portal: String,
        statement: String,
        /// Parameter format codes exactly as sent by the client (0=text,
        /// 1=binary). Must be preserved verbatim when re-encoding for the
        /// backend: rewriting them (e.g. forcing text) corrupts
        /// binary-format parameters sent by drivers like pgx/JDBC.
        param_formats: Vec<i16>,
        params: Vec<Option<Vec<u8>>>,
        /// Result format codes exactly as sent by the client.
        result_formats: Vec<i16>,
    },
    Describe {
        kind: DescribeKind,
        name: String,
    },
    Execute {
        portal: String,
        max_rows: i32,
    },
    Close {
        kind: DescribeKind,
        name: String,
    },
    Sync,
    CancelRequest {
        backend_pid: i32,
        secret_key: i32,
    },
    Terminate,
}

/// Field description (per-column metadata in `RowDescription`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescription {
    pub name: String,
    pub table_oid: i32,
    pub column_attr_num: i16,
    pub type_oid: i32,
    pub type_size: i16,
    pub type_modifier: i32,
    pub format_code: i16,
}

/// The set of fields in a PostgreSQL error/notice response (kept as-is so
/// that forwarding never mutates them).
///
/// An ordered list of `(code_byte, value)` pairs preserves field order and
/// original byte content, which lets Property 50 (error responses are
/// forwarded verbatim) verify "content is exactly identical".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PgError {
    pub fields: Vec<(u8, String)>,
}

impl PgError {
    /// Convenience accessor for common fields (independent of field order).
    pub fn field(&self, code: u8) -> Option<&str> {
        self.fields
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_str())
    }

    pub fn sqlstate(&self) -> Option<&str> {
        self.field(b'C')
    }

    pub fn message(&self) -> Option<&str> {
        self.field(b'M')
    }

    /// Constructs a simple error containing only the three common
    /// fields Severity/SQLSTATE/Message, letting the Proxy layer produce
    /// a valid `ErrorResponse` for internal error scenarios.
    pub fn simple(severity: &str, sqlstate: &str, message: &str) -> Self {
        PgError {
            fields: vec![
                (b'S', severity.to_string()),
                (b'C', sqlstate.to_string()),
                (b'M', message.to_string()),
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    Idle,
    InTransaction,
    Failed,
}

impl TransactionStatus {
    pub fn to_byte(self) -> u8 {
        match self {
            TransactionStatus::Idle => b'I',
            TransactionStatus::InTransaction => b'T',
            TransactionStatus::Failed => b'E',
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'I' => Some(TransactionStatus::Idle),
            b'T' => Some(TransactionStatus::InTransaction),
            b'E' => Some(TransactionStatus::Failed),
            _ => None,
        }
    }
}

/// Backend (backend server -> proxy) message
#[derive(Debug, Clone, PartialEq)]
pub enum BackendMessage {
    AuthenticationOk,
    AuthenticationCleartextPassword,
    AuthenticationMd5Password {
        salt: [u8; 4],
    },
    AuthenticationSasl {
        mechanisms: Vec<String>,
    },
    AuthenticationSaslContinue(Vec<u8>),
    AuthenticationSaslFinal(Vec<u8>),
    ParameterStatus {
        name: String,
        value: String,
    },
    BackendKeyData {
        pid: i32,
        secret_key: i32,
    },
    ReadyForQuery(TransactionStatus),
    RowDescription(Vec<FieldDescription>),
    DataRow(Vec<Option<Vec<u8>>>),
    CommandComplete {
        tag: String,
    },
    ErrorResponse(PgError),
    NoticeResponse(PgError),
    /// Extended query protocol: response to Parse
    ParseComplete,
    /// Extended query protocol: response to Bind
    BindComplete,
    /// Extended query protocol: response to Close
    CloseComplete,
    /// Extended query protocol: Describe response when no rows will be returned
    NoData,
    /// Extended query protocol: parameter type information
    ParameterDescription(Vec<i32>),
}
