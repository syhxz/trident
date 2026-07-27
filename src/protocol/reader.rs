//! Message reader (`reader`)
//!
//! Parses simple query protocol (`Query`) and extended query protocol
//! (`Parse`/`Bind`/`Describe`/`Execute`/`Sync`) message frames. Returns a
//! structured error for malformed/truncated byte streams, and never
//! panics (Requirement 13.3 / Property 51).
//!
//! Design notes: parsing logic is split into two layers --
//! 1. Pure functions `parse_frontend_body` / `parse_backend_body`: accept
//!    already-read, complete message-body bytes, involve no I/O, and can
//!    be used directly in property tests (robustness against arbitrary
//!    byte sequences).
//! 2. `async` wrapper functions: read the type byte + length prefix +
//!    message body via `tokio::io::AsyncRead`, then hand off to the pure
//!    functions above to complete parsing.

use tokio::io::{AsyncRead, AsyncReadExt};

use super::cursor::ByteReader;
use super::message::{BackendMessage, DescribeKind, FieldDescription, FrontendMessage, PgError, TransactionStatus};
use super::ProtocolError;

/// Frontend message type bytes
pub(crate) mod frontend_tag {
    pub const QUERY: u8 = b'Q';
    pub const PARSE: u8 = b'P';
    pub const BIND: u8 = b'B';
    pub const CLOSE: u8 = b'C';
    pub const DESCRIBE: u8 = b'D';
    pub const EXECUTE: u8 = b'E';
    pub const SYNC: u8 = b'S';
    pub const TERMINATE: u8 = b'X';
    pub const FLUSH: u8 = b'H';
}

/// Backend message type bytes
mod backend_tag {
    pub const AUTHENTICATION: u8 = b'R';
    pub const PARAMETER_STATUS: u8 = b'S';
    pub const BACKEND_KEY_DATA: u8 = b'K';
    pub const READY_FOR_QUERY: u8 = b'Z';
    pub const ROW_DESCRIPTION: u8 = b'T';
    pub const DATA_ROW: u8 = b'D';
    pub const COMMAND_COMPLETE: u8 = b'C';
    pub const ERROR_RESPONSE: u8 = b'E';
    pub const NOTICE_RESPONSE: u8 = b'N';
}

/// Parses a single frontend message body (excludes the type byte and the
/// length prefix).
///
/// `msg_type` is the message type byte; `body` is all the remaining bytes
/// of the message (already sliced out by the caller according to the
/// length prefix).
pub fn parse_frontend_body(msg_type: u8, body: &[u8]) -> Result<FrontendMessage, ProtocolError> {
    let mut r = ByteReader::new(body);
    let msg = match msg_type {
        frontend_tag::QUERY => {
            let sql = r.read_cstring()?;
            FrontendMessage::Query(sql)
        }
        frontend_tag::PARSE => {
            let name = r.read_cstring()?;
            let sql = r.read_cstring()?;
            let num_params = r.read_i16()?;
            if num_params < 0 {
                return Err(ProtocolError::Malformed(
                    "negative parameter count in Parse message".into(),
                ));
            }
            let mut param_types = Vec::with_capacity(num_params as usize);
            for _ in 0..num_params {
                param_types.push(r.read_i32()?);
            }
            FrontendMessage::Parse {
                name,
                sql,
                param_types,
            }
        }
        frontend_tag::BIND => {
            let portal = r.read_cstring()?;
            let statement = r.read_cstring()?;

            let num_param_formats = r.read_i16()?;
            if num_param_formats < 0 {
                return Err(ProtocolError::Malformed(
                    "negative parameter format count in Bind message".into(),
                ));
            }
            let mut param_formats = Vec::with_capacity(num_param_formats as usize);
            for _ in 0..num_param_formats {
                param_formats.push(r.read_i16()?);
            }

            let num_params = r.read_i16()?;
            if num_params < 0 {
                return Err(ProtocolError::Malformed(
                    "negative parameter count in Bind message".into(),
                ));
            }
            let mut params = Vec::with_capacity(num_params as usize);
            for _ in 0..num_params {
                params.push(r.read_len_prefixed_nullable()?);
            }

            let num_result_formats = r.read_i16()?;
            if num_result_formats < 0 {
                return Err(ProtocolError::Malformed(
                    "negative result format count in Bind message".into(),
                ));
            }
            let mut result_formats = Vec::with_capacity(num_result_formats as usize);
            for _ in 0..num_result_formats {
                result_formats.push(r.read_i16()?);
            }

            FrontendMessage::Bind {
                portal,
                statement,
                param_formats,
                params,
                result_formats,
            }
        }
        frontend_tag::DESCRIBE => {
            let kind_byte = r.read_u8()?;
            let kind = match kind_byte {
                b'S' => DescribeKind::Statement,
                b'P' => DescribeKind::Portal,
                other => {
                    return Err(ProtocolError::Malformed(format!(
                        "invalid Describe kind byte: {other:#x}"
                    )))
                }
            };
            let name = r.read_cstring()?;
            FrontendMessage::Describe { kind, name }
        }
        frontend_tag::EXECUTE => {
            let portal = r.read_cstring()?;
            let max_rows = r.read_i32()?;
            FrontendMessage::Execute { portal, max_rows }
        }
        frontend_tag::CLOSE => {
            let kind_byte = r.read_u8()?;
            let kind = match kind_byte {
                b'S' => DescribeKind::Statement,
                b'P' => DescribeKind::Portal,
                other => {
                    return Err(ProtocolError::Malformed(format!(
                        "invalid Close kind byte: {other:#x}"
                    )))
                }
            };
            let name = r.read_cstring()?;
            FrontendMessage::Close { kind, name }
        }
        frontend_tag::SYNC => FrontendMessage::Sync,
        frontend_tag::TERMINATE => FrontendMessage::Terminate,
        other => return Err(ProtocolError::InvalidMessageType(other)),
    };

    r.expect_exhausted()?;
    Ok(msg)
}

/// Parses a single backend message body (excludes the type byte and the
/// length prefix).
pub fn parse_backend_body(msg_type: u8, body: &[u8]) -> Result<BackendMessage, ProtocolError> {
    let mut r = ByteReader::new(body);
    let msg = match msg_type {
        backend_tag::AUTHENTICATION => {
            let code = r.read_i32()?;
            match code {
                0 => BackendMessage::AuthenticationOk,
                3 => BackendMessage::AuthenticationCleartextPassword,
                5 => {
                    let salt = r.read_bytes(4)?;
                    BackendMessage::AuthenticationMd5Password {
                        salt: [salt[0], salt[1], salt[2], salt[3]],
                    }
                }
                10 => {
                    let mut mechanisms = Vec::new();
                    loop {
                        if r.remaining() == 0 {
                            return Err(ProtocolError::Malformed(
                                "SASL mechanism list is missing its terminator".into(),
                            ));
                        }
                        let mechanism = r.read_cstring()?;
                        if mechanism.is_empty() {
                            break;
                        }
                        mechanisms.push(mechanism);
                    }
                    BackendMessage::AuthenticationSasl { mechanisms }
                }
                11 => {
                    let data = r.read_bytes(r.remaining())?.to_vec();
                    BackendMessage::AuthenticationSaslContinue(data)
                }
                12 => {
                    let data = r.read_bytes(r.remaining())?.to_vec();
                    BackendMessage::AuthenticationSaslFinal(data)
                }
                other => {
                    return Err(ProtocolError::Malformed(format!(
                        "unsupported authentication request code: {other}"
                    )))
                }
            }
        }
        backend_tag::PARAMETER_STATUS => {
            let name = r.read_cstring()?;
            let value = r.read_cstring()?;
            BackendMessage::ParameterStatus { name, value }
        }
        backend_tag::BACKEND_KEY_DATA => {
            let pid = r.read_i32()?;
            let secret_key = r.read_i32()?;
            BackendMessage::BackendKeyData { pid, secret_key }
        }
        backend_tag::READY_FOR_QUERY => {
            let status_byte = r.read_u8()?;
            let status = TransactionStatus::from_byte(status_byte).ok_or_else(|| {
                ProtocolError::Malformed(format!(
                    "invalid transaction status byte: {status_byte:#x}"
                ))
            })?;
            BackendMessage::ReadyForQuery(status)
        }
        backend_tag::ROW_DESCRIPTION => {
            let num_fields = r.read_i16()?;
            if num_fields < 0 {
                return Err(ProtocolError::Malformed(
                    "negative field count in RowDescription".into(),
                ));
            }
            let mut fields = Vec::with_capacity(num_fields as usize);
            for _ in 0..num_fields {
                let name = r.read_cstring()?;
                let table_oid = r.read_i32()?;
                let column_attr_num = r.read_i16()?;
                let type_oid = r.read_i32()?;
                let type_size = r.read_i16()?;
                let type_modifier = r.read_i32()?;
                let format_code = r.read_i16()?;
                fields.push(FieldDescription {
                    name,
                    table_oid,
                    column_attr_num,
                    type_oid,
                    type_size,
                    type_modifier,
                    format_code,
                });
            }
            BackendMessage::RowDescription(fields)
        }
        backend_tag::DATA_ROW => {
            let num_cols = r.read_i16()?;
            if num_cols < 0 {
                return Err(ProtocolError::Malformed(
                    "negative column count in DataRow".into(),
                ));
            }
            let mut cols = Vec::with_capacity(num_cols as usize);
            for _ in 0..num_cols {
                cols.push(r.read_len_prefixed_nullable()?);
            }
            BackendMessage::DataRow(cols)
        }
        backend_tag::COMMAND_COMPLETE => {
            let tag = r.read_cstring()?;
            BackendMessage::CommandComplete { tag }
        }
        backend_tag::ERROR_RESPONSE => BackendMessage::ErrorResponse(parse_pg_error_fields(&mut r)?),
        backend_tag::NOTICE_RESPONSE => {
            BackendMessage::NoticeResponse(parse_pg_error_fields(&mut r)?)
        }
        b'1' => BackendMessage::ParseComplete,
        b'2' => BackendMessage::BindComplete,
        b'3' => BackendMessage::CloseComplete,
        b'n' => BackendMessage::NoData,
        b't' => {
            let num_params = r.read_i16()?;
            let mut params = Vec::with_capacity(num_params.max(0) as usize);
            for _ in 0..num_params.max(0) {
                params.push(r.read_i32()?);
            }
            BackendMessage::ParameterDescription(params)
        }
        other => return Err(ProtocolError::InvalidMessageType(other)),
    };

    r.expect_exhausted()?;
    Ok(msg)
}

/// Parses the field sequence found in `ErrorResponse`/`NoticeResponse`,
/// laid out as `(code_byte, cstring)*` and terminated by a single `\0`.
fn parse_pg_error_fields(r: &mut ByteReader<'_>) -> Result<PgError, ProtocolError> {
    let mut fields = Vec::new();
    loop {
        let code = r.read_u8()?;
        if code == 0 {
            break;
        }
        let value = r.read_cstring()?;
        fields.push((code, value));
    }
    Ok(PgError { fields })
}

/// Asynchronously reads one complete frontend/backend message frame
pub trait MessageReader {
    fn read_frontend(
        &mut self,
    ) -> impl std::future::Future<Output = Result<FrontendMessage, ProtocolError>> + Send;

    fn read_backend(
        &mut self,
    ) -> impl std::future::Future<Output = Result<BackendMessage, ProtocolError>> + Send;
}

/// Common logic for reading a "type byte + int32 length prefix (including
/// its own 4 bytes) + message body" frame, returning the message type
/// byte and the message body bytes.
pub(crate) async fn read_tagged_frame<R: AsyncRead + Unpin + Send>(
    stream: &mut R,
) -> Result<(u8, Vec<u8>), ProtocolError> {
    let mut tag_buf = [0u8; 1];
    match stream.read_exact(&mut tag_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ProtocolError::UnexpectedEof)
        }
        Err(e) => return Err(ProtocolError::Io(e)),
    }

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(map_eof)?;
    let total_len = i32::from_be_bytes(len_buf);

    // The length prefix includes its own 4 bytes, so the message body
    // length = total_len - 4; an invalid (<4) or excessively large length
    // is treated as malformed, and is never used to allocate unbounded
    // memory or loop forever.
    if total_len < 4 {
        return Err(ProtocolError::InvalidLength(total_len));
    }
    const MAX_MESSAGE_BODY_LEN: i32 = 256 * 1024 * 1024; // 256MiB cap, defensive guard
    let body_len = total_len - 4;
    if body_len > MAX_MESSAGE_BODY_LEN {
        return Err(ProtocolError::InvalidLength(total_len));
    }

    let mut body = vec![0u8; body_len as usize];
    stream.read_exact(&mut body).await.map_err(map_eof)?;
    Ok((tag_buf[0], body))
}

fn map_eof(e: std::io::Error) -> ProtocolError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        ProtocolError::UnexpectedEof
    } else {
        ProtocolError::Io(e)
    }
}

/// Reads one frontend message from any `AsyncRead` stream.
pub async fn read_frontend_message<R: AsyncRead + Unpin + Send>(
    stream: &mut R,
) -> Result<FrontendMessage, ProtocolError> {
    let (tag, body) = read_tagged_frame(stream).await?;
    parse_frontend_body(tag, &body)
}

/// Reads one backend message from any `AsyncRead` stream.
pub async fn read_backend_message<R: AsyncRead + Unpin + Send>(
    stream: &mut R,
) -> Result<BackendMessage, ProtocolError> {
    let (tag, body) = read_tagged_frame(stream).await?;
    parse_backend_body(tag, &body)
}

/// Default `MessageReader` implementation backed by an underlying
/// `AsyncRead + AsyncWrite` stream.
pub struct TokioMessageReader<S> {
    pub stream: S,
}

impl<S> TokioMessageReader<S> {
    pub fn new(stream: S) -> Self {
        TokioMessageReader { stream }
    }
}

impl<S: AsyncRead + Unpin + Send> MessageReader for TokioMessageReader<S> {
    async fn read_frontend(&mut self) -> Result<FrontendMessage, ProtocolError> {
        read_frontend_message(&mut self.stream).await
    }

    async fn read_backend(&mut self) -> Result<BackendMessage, ProtocolError> {
        read_backend_message(&mut self.stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -----------------------------------------------------------------
    // Property 51: malformed client messages never crash the parser
    // Validates: Requirements 13.3
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_51_arbitrary_frontend_body_never_panics(
            msg_type in any::<u8>(),
            body in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            // Parsing an arbitrary byte sequence should never panic;
            // success or failure are both acceptable outcomes -- the only
            // unacceptable outcome is a panic or an infinite loop (proven
            // here simply by returning within finite time).
            let _ = parse_frontend_body(msg_type, &body);
        }

        #[test]
        fn property_51_arbitrary_backend_body_never_panics(
            msg_type in any::<u8>(),
            body in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            let _ = parse_backend_body(msg_type, &body);
        }

        #[test]
        fn property_51_truncated_cstring_never_panics(
            msg_type in prop_oneof![Just(b'Q'), Just(b'P')],
            partial in prop::collection::vec(1u8..255, 0..32), // no 0 byte -> missing terminator
        ) {
            let _ = parse_frontend_body(msg_type, &partial);
        }
    }

    // -----------------------------------------------------------------
    // Unit tests: concrete message parsing
    // -----------------------------------------------------------------

    fn cstring_bytes(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    #[test]
    fn parses_simple_query() {
        let body = cstring_bytes("SELECT 1");
        let msg = parse_frontend_body(b'Q', &body).unwrap();
        assert_eq!(msg, FrontendMessage::Query("SELECT 1".to_string()));
    }

    #[test]
    fn parses_sync_and_terminate_with_empty_body() {
        assert_eq!(parse_frontend_body(b'S', &[]).unwrap(), FrontendMessage::Sync);
        assert_eq!(
            parse_frontend_body(b'X', &[]).unwrap(),
            FrontendMessage::Terminate
        );
    }

    #[test]
    fn parses_parse_message_with_params() {
        let mut body = cstring_bytes("stmt1");
        body.extend(cstring_bytes("SELECT $1"));
        body.extend(1i16.to_be_bytes()); // num_params
        body.extend(23i32.to_be_bytes()); // int4 oid
        let msg = parse_frontend_body(b'P', &body).unwrap();
        assert_eq!(
            msg,
            FrontendMessage::Parse {
                name: "stmt1".to_string(),
                sql: "SELECT $1".to_string(),
                param_types: vec![23],
            }
        );
    }

    #[test]
    fn parses_execute_message() {
        let mut body = cstring_bytes("portal1");
        body.extend(0i32.to_be_bytes());
        let msg = parse_frontend_body(b'E', &body).unwrap();
        assert_eq!(
            msg,
            FrontendMessage::Execute {
                portal: "portal1".to_string(),
                max_rows: 0,
            }
        );
    }

    #[test]
    fn invalid_message_type_returns_error_not_panic() {
        let result = parse_frontend_body(0xFF, &[]);
        assert!(matches!(result, Err(ProtocolError::InvalidMessageType(0xFF))));
    }

    #[test]
    fn truncated_query_missing_terminator_returns_error() {
        let result = parse_frontend_body(b'Q', b"SELECT 1");
        assert!(result.is_err());
    }

    #[test]
    fn trailing_bytes_after_sync_is_malformed() {
        let result = parse_frontend_body(b'S', &[1, 2, 3]);
        assert!(matches!(result, Err(ProtocolError::Malformed(_))));
    }

    #[test]
    fn parses_ready_for_query() {
        let msg = parse_backend_body(b'Z', b"I").unwrap();
        assert_eq!(msg, BackendMessage::ReadyForQuery(TransactionStatus::Idle));
    }

    #[test]
    fn parses_error_response_fields() {
        let mut body = Vec::new();
        body.push(b'S');
        body.extend(cstring_bytes("ERROR"));
        body.push(b'C');
        body.extend(cstring_bytes("42601"));
        body.push(b'M');
        body.extend(cstring_bytes("syntax error"));
        body.push(0);

        let msg = parse_backend_body(b'E', &body).unwrap();
        match msg {
            BackendMessage::ErrorResponse(err) => {
                assert_eq!(err.sqlstate(), Some("42601"));
                assert_eq!(err.message(), Some("syntax error"));
            }
            _ => panic!("expected ErrorResponse"),
        }
    }

    #[tokio::test]
    async fn async_read_frontend_query_roundtrip() {
        let sql = "SELECT * FROM t";
        let mut body = cstring_bytes(sql);
        let total_len = (body.len() + 4) as i32;
        let mut framed = vec![b'Q'];
        framed.extend(total_len.to_be_bytes());
        framed.append(&mut body);

        let mut cursor = std::io::Cursor::new(framed);
        let msg = read_frontend_message(&mut cursor).await.unwrap();
        assert_eq!(msg, FrontendMessage::Query(sql.to_string()));
    }

    #[tokio::test]
    async fn async_read_reports_eof_on_empty_stream() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let result = read_frontend_message(&mut cursor).await;
        assert!(matches!(result, Err(ProtocolError::UnexpectedEof)));
    }

    #[tokio::test]
    async fn async_read_reports_error_on_truncated_stream() {
        // Declares a message-body length, but the actual byte stream is truncated.
        let framed = vec![b'Q', 0, 0, 0, 20, b'S', b'E'];
        let mut cursor = std::io::Cursor::new(framed);
        let result = read_frontend_message(&mut cursor).await;
        assert!(result.is_err());
    }

    #[test]
    fn negative_length_prefix_is_rejected() {
        // Directly tests read_tagged_frame's length validation logic
        // (triggered indirectly via the async wrapper function).
        let framed: Vec<u8> = vec![b'Q', 0xFF, 0xFF, 0xFF, 0xFF]; // length = -1
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            let mut cursor = std::io::Cursor::new(framed);
            read_frontend_message(&mut cursor).await
        });
        assert!(matches!(result, Err(ProtocolError::InvalidLength(-1))));
    }
}
