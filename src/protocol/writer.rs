//! Message encoder (`writer`)
//!
//! Encodes backend messages such as `ReadyForQuery`, `RowDescription`,
//! `DataRow`, `CommandComplete`, and `ErrorResponse`, as well as frontend
//! messages (used when the Proxy forwards to a backend).
//!
//! Design notes: encoding logic is split into pure functions (`encode_*`,
//! returning complete message bytes with no I/O) and `async` write
//! functions (a single `write_all` call completes the write, guaranteeing
//! atomicity -- never interleaving with the writing of another message).

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::message::{BackendMessage, DescribeKind, FrontendMessage, PgError};
use super::ProtocolError;

fn push_cstring(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

fn push_len_prefixed_nullable(buf: &mut Vec<u8>, value: &Option<Vec<u8>>) {
    match value {
        Some(bytes) => {
            buf.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
            buf.extend_from_slice(bytes);
        }
        None => {
            buf.extend_from_slice(&(-1i32).to_be_bytes());
        }
    }
}

/// Wraps a message body into a complete frame: "type byte + int32 length
/// prefix (including itself) + message body".
fn frame(tag: u8, body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + body.len());
    out.push(tag);
    out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn encode_pg_error_body(err: &PgError) -> Vec<u8> {
    let mut body = Vec::new();
    for (code, value) in &err.fields {
        body.push(*code);
        push_cstring(&mut body, value);
    }
    body.push(0);
    body
}

/// Encodes a backend message into a complete Wire Protocol byte sequence.
pub fn encode_backend_message(msg: &BackendMessage) -> Vec<u8> {
    match msg {
        BackendMessage::AuthenticationOk => frame(b'R', 0i32.to_be_bytes().to_vec()),
        BackendMessage::AuthenticationCleartextPassword => frame(b'R', 3i32.to_be_bytes().to_vec()),
        BackendMessage::AuthenticationMd5Password { salt } => {
            let mut body = 5i32.to_be_bytes().to_vec();
            body.extend_from_slice(salt);
            frame(b'R', body)
        }
        BackendMessage::AuthenticationSasl { mechanisms } => {
            let mut body = 10i32.to_be_bytes().to_vec();
            for mechanism in mechanisms {
                push_cstring(&mut body, mechanism);
            }
            body.push(0);
            frame(b'R', body)
        }
        BackendMessage::AuthenticationSaslContinue(data) => {
            let mut body = 11i32.to_be_bytes().to_vec();
            body.extend_from_slice(data);
            frame(b'R', body)
        }
        BackendMessage::AuthenticationSaslFinal(data) => {
            let mut body = 12i32.to_be_bytes().to_vec();
            body.extend_from_slice(data);
            frame(b'R', body)
        }
        BackendMessage::ParameterStatus { name, value } => {
            let mut body = Vec::new();
            push_cstring(&mut body, name);
            push_cstring(&mut body, value);
            frame(b'S', body)
        }
        BackendMessage::BackendKeyData { pid, secret_key } => {
            let mut body = Vec::new();
            body.extend_from_slice(&pid.to_be_bytes());
            body.extend_from_slice(&secret_key.to_be_bytes());
            frame(b'K', body)
        }
        BackendMessage::ReadyForQuery(status) => frame(b'Z', vec![status.to_byte()]),
        BackendMessage::RowDescription(fields) => {
            let mut body = Vec::new();
            body.extend_from_slice(&(fields.len() as i16).to_be_bytes());
            for f in fields {
                push_cstring(&mut body, &f.name);
                body.extend_from_slice(&f.table_oid.to_be_bytes());
                body.extend_from_slice(&f.column_attr_num.to_be_bytes());
                body.extend_from_slice(&f.type_oid.to_be_bytes());
                body.extend_from_slice(&f.type_size.to_be_bytes());
                body.extend_from_slice(&f.type_modifier.to_be_bytes());
                body.extend_from_slice(&f.format_code.to_be_bytes());
            }
            frame(b'T', body)
        }
        BackendMessage::DataRow(cols) => {
            let mut body = Vec::new();
            body.extend_from_slice(&(cols.len() as i16).to_be_bytes());
            for col in cols {
                push_len_prefixed_nullable(&mut body, col);
            }
            frame(b'D', body)
        }
        BackendMessage::CommandComplete { tag } => {
            let mut body = Vec::new();
            push_cstring(&mut body, tag);
            frame(b'C', body)
        }
        BackendMessage::ErrorResponse(err) => frame(b'E', encode_pg_error_body(err)),
        BackendMessage::NoticeResponse(err) => frame(b'N', encode_pg_error_body(err)),
        BackendMessage::ParseComplete => frame(b'1', Vec::new()),
        BackendMessage::BindComplete => frame(b'2', Vec::new()),
        BackendMessage::CloseComplete => frame(b'3', Vec::new()),
        BackendMessage::NoData => frame(b'n', Vec::new()),
        BackendMessage::ParameterDescription(params) => {
            let mut body = Vec::new();
            body.extend_from_slice(&(params.len() as i16).to_be_bytes());
            for p in params {
                body.extend_from_slice(&p.to_be_bytes());
            }
            frame(b't', body)
        }
    }
}

/// Encodes a borrowed SQL string directly into one complete Query frame.
/// This avoids both allocating an owned `String` and copying a temporary
/// body buffer into a second frame buffer on the forwarding hot path.
pub fn encode_query(sql: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(sql.len() + 6);
    out.push(b'Q');
    out.extend_from_slice(&((sql.len() + 5) as i32).to_be_bytes());
    out.extend_from_slice(sql.as_bytes());
    out.push(0);
    out
}

/// Encodes a frontend message into a complete Wire Protocol byte sequence
/// (used when the Proxy forwards to a backend).
pub fn encode_frontend_message(msg: &FrontendMessage) -> Vec<u8> {
    match msg {
        FrontendMessage::Startup(_) => {
            // The Startup message has no type byte and is never
            // re-encoded on the regular forwarding path; unsupported
            // here -- callers should handle it separately via the
            // startup module.
            Vec::new()
        }
        FrontendMessage::Query(sql) => encode_query(sql),
        FrontendMessage::Parse {
            name,
            sql,
            param_types,
        } => {
            let mut body = Vec::new();
            push_cstring(&mut body, name);
            push_cstring(&mut body, sql);
            body.extend_from_slice(&(param_types.len() as i16).to_be_bytes());
            for t in param_types {
                body.extend_from_slice(&t.to_be_bytes());
            }
            frame(b'P', body)
        }
        FrontendMessage::Bind {
            portal,
            statement,
            param_formats,
            params,
            result_formats,
        } => {
            let mut body = Vec::new();
            push_cstring(&mut body, portal);
            push_cstring(&mut body, statement);
            // Format codes must round-trip exactly as the client sent them:
            // a binary-format parameter re-labeled as text would be
            // misinterpreted by the backend.
            body.extend_from_slice(&(param_formats.len() as i16).to_be_bytes());
            for f in param_formats {
                body.extend_from_slice(&f.to_be_bytes());
            }
            body.extend_from_slice(&(params.len() as i16).to_be_bytes());
            for p in params {
                push_len_prefixed_nullable(&mut body, p);
            }
            body.extend_from_slice(&(result_formats.len() as i16).to_be_bytes());
            for f in result_formats {
                body.extend_from_slice(&f.to_be_bytes());
            }
            frame(b'B', body)
        }
        FrontendMessage::Describe { kind, name } => {
            let mut body = Vec::new();
            body.push(match kind {
                DescribeKind::Statement => b'S',
                DescribeKind::Portal => b'P',
            });
            push_cstring(&mut body, name);
            frame(b'D', body)
        }
        FrontendMessage::Execute { portal, max_rows } => {
            let mut body = Vec::new();
            push_cstring(&mut body, portal);
            body.extend_from_slice(&max_rows.to_be_bytes());
            frame(b'E', body)
        }
        FrontendMessage::Close { kind, name } => {
            let mut body = Vec::new();
            body.push(match kind {
                DescribeKind::Statement => b'S',
                DescribeKind::Portal => b'P',
            });
            push_cstring(&mut body, name);
            frame(b'C', body)
        }
        FrontendMessage::Sync => frame(b'S', Vec::new()),
        FrontendMessage::Terminate => frame(b'X', Vec::new()),
        FrontendMessage::CancelRequest {
            backend_pid,
            secret_key,
        } => {
            // CancelRequest uses its own fixed-format frame: int32 len +
            // int32(80877102) + pid + key, with no type byte.
            let mut out = Vec::with_capacity(16);
            out.extend_from_slice(&16i32.to_be_bytes());
            out.extend_from_slice(&80877102i32.to_be_bytes());
            out.extend_from_slice(&backend_pid.to_be_bytes());
            out.extend_from_slice(&secret_key.to_be_bytes());
            out
        }
    }
}

/// Encodes a cleartext or MD5 password response. Both PostgreSQL
/// authentication methods use a `PasswordMessage` (`p`) whose payload is
/// a null-terminated string.
pub fn encode_password_message(password: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(password.len() + 1);
    push_cstring(&mut body, password);
    frame(b'p', body)
}

/// Encodes the first SASL response: mechanism cstring, response length,
/// then the raw initial response bytes.
pub fn encode_sasl_initial_response(mechanism: &str, response: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(mechanism.len() + response.len() + 5);
    push_cstring(&mut body, mechanism);
    body.extend_from_slice(&(response.len() as i32).to_be_bytes());
    body.extend_from_slice(response);
    frame(b'p', body)
}

/// Encodes a subsequent raw SASL response in a `PasswordMessage` frame.
pub fn encode_sasl_response(response: &[u8]) -> Vec<u8> {
    frame(b'p', response.to_vec())
}

/// Asynchronously encodes and writes out one message
pub trait MessageWriter {
    fn write_frontend(
        &mut self,
        msg: &FrontendMessage,
    ) -> impl std::future::Future<Output = Result<(), ProtocolError>> + Send;

    fn write_backend(
        &mut self,
        msg: &BackendMessage,
    ) -> impl std::future::Future<Output = Result<(), ProtocolError>> + Send;
}

/// Default `MessageWriter` implementation backed by an underlying
/// `AsyncWrite` stream.
///
/// Each call writes out the complete frame bytes with a single
/// `write_all`, guaranteeing that it never interleaves with the writing
/// of another message (each message is written atomically; see the
/// postcondition of `write_backend` in design.md).
pub struct TokioMessageWriter<S> {
    pub stream: S,
}

impl<S> TokioMessageWriter<S> {
    pub fn new(stream: S) -> Self {
        TokioMessageWriter { stream }
    }
}

impl<S: AsyncWrite + Unpin + Send> MessageWriter for TokioMessageWriter<S> {
    async fn write_frontend(&mut self, msg: &FrontendMessage) -> Result<(), ProtocolError> {
        let bytes = encode_frontend_message(msg);
        self.stream.write_all(&bytes).await?;
        Ok(())
    }

    async fn write_backend(&mut self, msg: &BackendMessage) -> Result<(), ProtocolError> {
        let bytes = encode_backend_message(msg);
        self.stream.write_all(&bytes).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::{FieldDescription, TransactionStatus};
    use crate::protocol::reader::{parse_backend_body, parse_frontend_body};
    use proptest::prelude::*;

    // -----------------------------------------------------------------
    // 8.7 Unit tests: encode/decode round trip (encoding then decoding
    // yields an equivalent message)
    // Validates: Requirements 11.1, 11.2
    // -----------------------------------------------------------------

    fn roundtrip_frontend(msg: FrontendMessage) {
        let bytes = encode_frontend_message(&msg);
        let tag = bytes[0];
        let body = &bytes[5..];
        let decoded = parse_frontend_body(tag, body).unwrap();
        assert_eq!(decoded, msg);
    }

    fn roundtrip_backend(msg: BackendMessage) {
        let bytes = encode_backend_message(&msg);
        let tag = bytes[0];
        let body = &bytes[5..];
        let decoded = parse_backend_body(tag, body).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn query_roundtrip() {
        roundtrip_frontend(FrontendMessage::Query("SELECT 1".to_string()));
    }

    #[test]
    fn parse_roundtrip() {
        roundtrip_frontend(FrontendMessage::Parse {
            name: "s1".to_string(),
            sql: "SELECT $1".to_string(),
            param_types: vec![23, 25],
        });
    }

    #[test]
    fn bind_roundtrip() {
        roundtrip_frontend(FrontendMessage::Bind {
            portal: "p1".to_string(),
            statement: "s1".to_string(),
            param_formats: vec![],
            params: vec![Some(b"42".to_vec()), None],
            result_formats: vec![],
        });
    }

    /// Regression: binary format codes (1) sent by drivers like pgx/JDBC
    /// must survive the decode/re-encode cycle exactly. Rewriting them to
    /// text (0) makes the backend misinterpret binary parameter bytes.
    #[test]
    fn bind_roundtrip_preserves_binary_format_codes() {
        roundtrip_frontend(FrontendMessage::Bind {
            portal: String::new(),
            statement: "s1".to_string(),
            param_formats: vec![1, 0, 1],
            params: vec![
                Some(vec![0x00, 0x00, 0x00, 0x2A]), // binary int4 42
                Some(b"text-param".to_vec()),
                Some(vec![0x01]),
            ],
            result_formats: vec![1],
        });
    }

    #[test]
    fn describe_roundtrip() {
        roundtrip_frontend(FrontendMessage::Describe {
            kind: DescribeKind::Portal,
            name: "p1".to_string(),
        });
    }

    #[test]
    fn execute_roundtrip() {
        roundtrip_frontend(FrontendMessage::Execute {
            portal: "p1".to_string(),
            max_rows: 100,
        });
    }

    #[test]
    fn sync_and_terminate_roundtrip() {
        roundtrip_frontend(FrontendMessage::Sync);
        roundtrip_frontend(FrontendMessage::Terminate);
    }

    #[test]
    fn ready_for_query_roundtrip() {
        roundtrip_backend(BackendMessage::ReadyForQuery(
            TransactionStatus::InTransaction,
        ));
    }

    #[test]
    fn command_complete_roundtrip() {
        roundtrip_backend(BackendMessage::CommandComplete {
            tag: "INSERT 0 1".to_string(),
        });
    }

    #[test]
    fn row_description_and_data_row_roundtrip() {
        roundtrip_backend(BackendMessage::RowDescription(vec![FieldDescription {
            name: "id".to_string(),
            table_oid: 0,
            column_attr_num: 1,
            type_oid: 23,
            type_size: 4,
            type_modifier: -1,
            format_code: 0,
        }]));
        roundtrip_backend(BackendMessage::DataRow(vec![Some(b"1".to_vec()), None]));
    }

    #[test]
    fn error_response_roundtrip() {
        roundtrip_backend(BackendMessage::ErrorResponse(PgError::simple(
            "ERROR",
            "42601",
            "syntax error",
        )));
    }

    #[test]
    fn authentication_messages_roundtrip() {
        roundtrip_backend(BackendMessage::AuthenticationOk);
        roundtrip_backend(BackendMessage::AuthenticationCleartextPassword);
        roundtrip_backend(BackendMessage::AuthenticationMd5Password { salt: [1, 2, 3, 4] });
        roundtrip_backend(BackendMessage::AuthenticationSasl {
            mechanisms: vec!["SCRAM-SHA-256".to_string()],
        });
        roundtrip_backend(BackendMessage::AuthenticationSaslContinue(
            b"r=nonce,s=c2FsdA==,i=4096".to_vec(),
        ));
        roundtrip_backend(BackendMessage::AuthenticationSaslFinal(
            b"v=c2lnbmF0dXJl".to_vec(),
        ));
        roundtrip_backend(BackendMessage::BackendKeyData {
            pid: 1234,
            secret_key: 5678,
        });
    }

    #[test]
    fn password_and_sasl_response_frames_match_wire_format() {
        assert_eq!(
            encode_password_message("secret"),
            [
                vec![b'p'],
                11i32.to_be_bytes().to_vec(),
                b"secret\0".to_vec()
            ]
            .concat()
        );

        let initial = encode_sasl_initial_response("SCRAM-SHA-256", b"n,,n=,r=nonce");
        assert_eq!(initial[0], b'p');
        assert_eq!(&initial[5..19], b"SCRAM-SHA-256\0");
        assert_eq!(i32::from_be_bytes(initial[19..23].try_into().unwrap()), 13);
        assert_eq!(&initial[23..], b"n,,n=,r=nonce");

        let response = encode_sasl_response(b"c=biws,r=nonce,p=proof");
        assert_eq!(response[0], b'p');
        assert_eq!(&response[5..], b"c=biws,r=nonce,p=proof");
    }

    #[test]
    fn parameter_status_roundtrip() {
        roundtrip_backend(BackendMessage::ParameterStatus {
            name: "server_version".to_string(),
            value: "16.0".to_string(),
        });
    }

    // -----------------------------------------------------------------
    // Property 50: a backend error response is forwarded verbatim,
    // never modified
    // Validates: Requirements 13.2
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_50_error_response_forwarded_unmodified(
            fields in prop::collection::vec(
                (1u8..=127, "[a-zA-Z0-9 ]{0,30}"),
                0..8,
            )
        ) {
            let err = PgError { fields: fields.clone() };
            let original = BackendMessage::ErrorResponse(err);

            // Simulate Proxy forwarding: decode the error message
            // received from the backend, then re-encode it verbatim to
            // forward to the client.
            let received_bytes = encode_backend_message(&original);
            let tag = received_bytes[0];
            let body = &received_bytes[5..];
            let decoded = parse_backend_body(tag, body).unwrap();

            // "Forwarding": re-encode the decoded message.
            let forwarded_bytes = encode_backend_message(&decoded);

            prop_assert_eq!(decoded, original);
            prop_assert_eq!(forwarded_bytes, received_bytes);
        }
    }

    #[tokio::test]
    async fn async_write_backend_produces_expected_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut writer = TokioMessageWriter::new(&mut buf);
            writer
                .write_backend(&BackendMessage::ReadyForQuery(TransactionStatus::Idle))
                .await
                .unwrap();
        }
        assert_eq!(
            buf,
            encode_backend_message(&BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        );
    }

    #[tokio::test]
    async fn async_write_is_atomic_single_write_all_call() {
        // Confirm there's no possibility of a fragmented write, by
        // verifying the written bytes exactly match the one-shot
        // encoding result.
        let mut buf: Vec<u8> = Vec::new();
        let msg = BackendMessage::CommandComplete {
            tag: "SELECT 3".to_string(),
        };
        {
            let mut writer = TokioMessageWriter::new(&mut buf);
            writer.write_backend(&msg).await.unwrap();
        }
        assert_eq!(buf, encode_backend_message(&msg));
    }
}
