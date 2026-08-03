//! Startup/authentication handling (`startup`)
//!
//! Parses the client's `StartupMessage`, and performs authentication with
//! the backend on the client's behalf.
//!
//! `StartupMessage`'s frame format differs from regular messages: there is
//! no type byte, just `int32 length prefix (including itself) + int32
//! protocol version + a list of key/value cstring pairs terminated by
//! \0\0`. Special case: when the protocol version is `80877102`
//! (`CancelRequest`) or `80877103` (`SSLRequest`), the message format
//! differs and must be handled separately.

use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::cursor::ByteReader;
use super::message::{FrontendMessage, StartupMessage};
use super::ProtocolError;

pub const CANCEL_REQUEST_CODE: i32 = 80877102;
pub const SSL_REQUEST_CODE: i32 = 80877103;
pub const GSSENC_REQUEST_CODE: i32 = 80877104;

/// The raw packet read during the Startup phase, distinguishing between a
/// regular Startup, a CancelRequest, and an SSLRequest.
#[derive(Debug, Clone, PartialEq)]
pub enum StartupPacket {
    Startup(StartupMessage),
    Cancel { backend_pid: i32, secret_key: i32 },
    SslRequest,
    GssEncRequest,
}

/// Parses the Startup-phase message body (excluding the length prefix
/// itself, i.e. all bytes immediately following it).
pub fn parse_startup_body(body: &[u8]) -> Result<StartupPacket, ProtocolError> {
    let mut r = ByteReader::new(body);
    let code = r.read_i32()?;

    if code == CANCEL_REQUEST_CODE {
        let backend_pid = r.read_i32()?;
        let secret_key = r.read_i32()?;
        r.expect_exhausted()?;
        return Ok(StartupPacket::Cancel {
            backend_pid,
            secret_key,
        });
    }

    if code == SSL_REQUEST_CODE {
        r.expect_exhausted()?;
        return Ok(StartupPacket::SslRequest);
    }

    if code == GSSENC_REQUEST_CODE {
        r.expect_exhausted()?;
        return Ok(StartupPacket::GssEncRequest);
    }

    // Regular StartupMessage: the protocol version is followed by
    // key/value cstring pairs, terminated by an empty string.
    let mut params = HashMap::new();
    loop {
        if r.remaining() == 0 {
            return Err(ProtocolError::Malformed(
                "startup message missing terminating null byte".into(),
            ));
        }
        let key = r.read_cstring()?;
        if key.is_empty() {
            break;
        }
        let value = r.read_cstring()?;
        params.insert(key, value);
    }
    r.expect_exhausted()?;

    Ok(StartupPacket::Startup(StartupMessage {
        protocol_version: code,
        params,
    }))
}

/// Reads one complete Startup-phase packet (length prefix + message body)
/// from any `AsyncRead` stream.
pub async fn read_startup_packet<R: AsyncRead + Unpin + Send>(
    stream: &mut R,
) -> Result<StartupPacket, ProtocolError> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ProtocolError::UnexpectedEof)
        }
        Err(e) => return Err(ProtocolError::Io(e)),
    }
    let total_len = i32::from_be_bytes(len_buf);
    if total_len < 4 {
        return Err(ProtocolError::InvalidLength(total_len));
    }
    const MAX_STARTUP_LEN: i32 = 10 * 1024 * 1024; // 10MiB cap, defensive guard
    let body_len = total_len - 4;
    if body_len > MAX_STARTUP_LEN {
        return Err(ProtocolError::InvalidLength(total_len));
    }

    let mut body = vec![0u8; body_len as usize];
    stream.read_exact(&mut body).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ProtocolError::UnexpectedEof
        } else {
            ProtocolError::Io(e)
        }
    })?;

    parse_startup_body(&body)
}

/// Startup/authentication result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOutcome {
    pub backend_pid: i32,
    pub secret_key: i32,
}

/// Startup/authentication flow handling.
///
/// Two levels of auth are supported:
/// - `handle_startup`: returns immediately (trust mode, or when auth is
///   performed externally).
/// - `handle_startup_with_stream`: given a mutable reference to the client
///   stream, can perform multi-round-trip auth (MD5, SCRAM). Default
///   implementation delegates to `handle_startup` (trust mode).
///
/// Implementations that need to send AuthenticationRequest / receive
/// PasswordMessage should override `handle_startup_with_stream`.
pub trait StartupHandler {
    fn handle_startup(
        &mut self,
        msg: StartupMessage,
    ) -> impl std::future::Future<Output = Result<AuthOutcome, ProtocolError>> + Send;

    /// Auth with stream access for challenge-response protocols.
    /// Default: delegates to handle_startup (no challenge-response).
    fn handle_startup_with_stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>(
        &mut self,
        msg: StartupMessage,
        _stream: &mut S,
    ) -> impl std::future::Future<Output = Result<AuthOutcome, ProtocolError>> + Send {
        self.handle_startup(msg)
    }
}

/// A "trust auth" implementation for test/development use only: performs
/// no real password verification and simply returns a fixed
/// `AuthOutcome`. Production environments should replace this with a
/// full implementation of an authentication method matching the backend
/// (e.g. scram-sha-256).
#[derive(Debug, Clone, Copy)]
pub struct TrustStartupHandler {
    pub backend_pid: i32,
    pub secret_key: i32,
}

impl StartupHandler for TrustStartupHandler {
    async fn handle_startup(&mut self, _msg: StartupMessage) -> Result<AuthOutcome, ProtocolError> {
        Ok(AuthOutcome {
            backend_pid: self.backend_pid,
            secret_key: self.secret_key,
        })
    }
}

/// MD5 password auth handler: validates client credentials against a local
/// password file (PgBouncer-style `userlist.txt`). The proxy verifies the
/// client's identity, then continues to use the configured service account
/// when connecting to the backend. This provides client-side access control
/// without requiring end-to-end credential passthrough.
///
/// Auth file format (one entry per line):
///   "username" "md5<hash>"
/// or
///   "username" "plaintext_password"
///
/// The MD5 hash follows PostgreSQL convention: md5(password + username).
pub struct Md5PasswordStartupHandler {
    pub backend_pid: i32,
    pub secret_key: i32,
    /// username -> password (plaintext or md5-hashed)
    pub credentials: std::sync::Arc<std::collections::HashMap<String, String>>,
}

impl StartupHandler for Md5PasswordStartupHandler {
    async fn handle_startup(&mut self, _msg: StartupMessage) -> Result<AuthOutcome, ProtocolError> {
        // This path should not be called directly; use handle_startup_with_stream.
        Err(ProtocolError::Malformed(
            "MD5 auth requires stream access; internal error".into(),
        ))
    }

    async fn handle_startup_with_stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>(
        &mut self,
        msg: StartupMessage,
        stream: &mut S,
    ) -> Result<AuthOutcome, ProtocolError> {
        use md5::Md5;
        use sha2::Digest; // for Md5::new() / update / finalize (md5 re-exports digest trait)
        use tokio::io::AsyncWriteExt;

        let username = msg
            .params
            .get("user")
            .cloned()
            .unwrap_or_default();

        let expected_password = self
            .credentials
            .get(&username)
            .ok_or_else(|| {
                ProtocolError::Malformed(format!("unknown user: {}", username))
            })?
            .clone();

        // Send AuthenticationMD5Password with a random 4-byte salt
        let salt: [u8; 4] = rand::random();
        let mut auth_msg = Vec::with_capacity(13);
        // type 'R'
        auth_msg.push(b'R');
        // length: 4 (len) + 4 (auth type) + 4 (salt) = 12
        auth_msg.extend_from_slice(&12i32.to_be_bytes());
        // AuthType = 5 (MD5Password)
        auth_msg.extend_from_slice(&5i32.to_be_bytes());
        auth_msg.extend_from_slice(&salt);

        stream
            .write_all(&auth_msg)
            .await
            .map_err(ProtocolError::Io)?;
        stream.flush().await.map_err(ProtocolError::Io)?;

        // Read PasswordMessage ('p')
        let (tag, body) = crate::protocol::reader::read_tagged_frame(stream).await?;
        if tag != b'p' {
            return Err(ProtocolError::Malformed(format!(
                "expected PasswordMessage ('p'), got '{}'",
                tag as char
            )));
        }

        // Extract the password C-string from body
        let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
        let client_response = std::str::from_utf8(&body[..end])
            .map_err(|_| ProtocolError::Malformed("password is not valid UTF-8".into()))?;

        // Compute expected MD5 response:
        // PostgreSQL MD5 auth: client sends "md5" + hex(md5(hex(md5(password+user)) + salt))
        let inner_hash = if expected_password.starts_with("md5") && expected_password.len() == 35 {
            // Already stored as md5 hash
            expected_password.clone()
        } else {
            // Plaintext: compute md5(password + username)
            let mut hasher = Md5::new();
            hasher.update(expected_password.as_bytes());
            hasher.update(username.as_bytes());
            let result = hasher.finalize();
            format!("md5{:x}", result)
        };

        // Outer hash: md5(inner_hash_hex_without_prefix + salt_bytes)
        let inner_hex = &inner_hash[3..]; // strip "md5" prefix
        let mut hasher = Md5::new();
        hasher.update(inner_hex.as_bytes());
        hasher.update(&salt);
        let outer_result = hasher.finalize();
        let expected_response = format!("md5{:x}", outer_result);

        // Constant-time comparison to prevent timing side-channel attacks.
        // An attacker sending many auth attempts could otherwise infer the
        // correct hash prefix from response-time differences.
        let match_ok = client_response.as_bytes().len() == expected_response.as_bytes().len()
            && subtle::ConstantTimeEq::ct_eq(
                client_response.as_bytes(),
                expected_response.as_bytes(),
            )
            .into();

        if !match_ok {
            return Err(ProtocolError::Malformed(
                "password authentication failed".into(),
            ));
        }

        Ok(AuthOutcome {
            backend_pid: self.backend_pid,
            secret_key: self.secret_key,
        })
    }
}

/// Parses an auth file in PgBouncer userlist.txt format:
///   "username" "password_or_md5hash"
/// Returns a map of username -> password/hash.
pub fn parse_auth_file(content: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Format: "user" "password" — find quoted strings
        let mut quoted = Vec::new();
        let mut in_quote = false;
        let mut current = String::new();
        for ch in line.chars() {
            if ch == '"' {
                if in_quote {
                    quoted.push(current.clone());
                    current.clear();
                }
                in_quote = !in_quote;
            } else if in_quote {
                current.push(ch);
            }
        }
        if quoted.len() >= 2 {
            map.insert(quoted[0].clone(), quoted[1].clone());
        }
    }
    map
}

/// Converts `StartupPacket::Startup` into `FrontendMessage::Startup`, for
/// use by a higher-level unified message-processing pipeline.
impl From<StartupMessage> for FrontendMessage {
    fn from(msg: StartupMessage) -> Self {
        FrontendMessage::Startup(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cstring_bytes(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    fn build_startup_body(version: i32, params: &[(&str, &str)]) -> Vec<u8> {
        let mut body = version.to_be_bytes().to_vec();
        for (k, v) in params {
            body.extend(cstring_bytes(k));
            body.extend(cstring_bytes(v));
        }
        body.push(0); // terminator
        body
    }

    // -----------------------------------------------------------------
    // 8.7 Unit tests: parsing Startup message parameters
    // Validates: Requirements 11.1
    // -----------------------------------------------------------------

    #[test]
    fn parses_startup_message_params() {
        let body = build_startup_body(196608, &[("user", "alice"), ("database", "mydb")]);
        let packet = parse_startup_body(&body).unwrap();
        match packet {
            StartupPacket::Startup(msg) => {
                assert_eq!(msg.protocol_version, 196608);
                assert_eq!(msg.params.get("user"), Some(&"alice".to_string()));
                assert_eq!(msg.params.get("database"), Some(&"mydb".to_string()));
            }
            other => panic!("expected Startup packet, got {other:?}"),
        }
    }

    #[test]
    fn parses_cancel_request() {
        let mut body = CANCEL_REQUEST_CODE.to_be_bytes().to_vec();
        body.extend(1234i32.to_be_bytes());
        body.extend(5678i32.to_be_bytes());
        let packet = parse_startup_body(&body).unwrap();
        assert_eq!(
            packet,
            StartupPacket::Cancel {
                backend_pid: 1234,
                secret_key: 5678,
            }
        );
    }

    #[test]
    fn parses_ssl_request() {
        let body = SSL_REQUEST_CODE.to_be_bytes().to_vec();
        let packet = parse_startup_body(&body).unwrap();
        assert_eq!(packet, StartupPacket::SslRequest);
    }

    #[test]
    fn parses_gssenc_request() {
        let body = GSSENC_REQUEST_CODE.to_be_bytes().to_vec();
        let packet = parse_startup_body(&body).unwrap();
        assert_eq!(packet, StartupPacket::GssEncRequest);
    }

    #[test]
    fn empty_params_startup_message() {
        let body = build_startup_body(196608, &[]);
        let packet = parse_startup_body(&body).unwrap();
        match packet {
            StartupPacket::Startup(msg) => assert!(msg.params.is_empty()),
            other => panic!("expected Startup packet, got {other:?}"),
        }
    }

    #[test]
    fn missing_terminator_is_malformed() {
        let mut body = 196608i32.to_be_bytes().to_vec();
        body.extend(cstring_bytes("user"));
        body.extend(cstring_bytes("alice"));
        // Deliberately omit the terminating empty byte.
        let result = parse_startup_body(&body);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn async_read_startup_packet_roundtrip() {
        let body = build_startup_body(196608, &[("user", "bob")]);
        let mut framed = ((body.len() + 4) as i32).to_be_bytes().to_vec();
        framed.extend(body);

        let mut cursor = std::io::Cursor::new(framed);
        let packet = read_startup_packet(&mut cursor).await.unwrap();
        match packet {
            StartupPacket::Startup(msg) => {
                assert_eq!(msg.params.get("user"), Some(&"bob".to_string()));
            }
            other => panic!("expected Startup packet, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn trust_handler_returns_fixed_outcome() {
        let mut handler = TrustStartupHandler {
            backend_pid: 42,
            secret_key: 99,
        };
        let msg = StartupMessage {
            protocol_version: 196608,
            params: HashMap::new(),
        };
        let outcome = handler.handle_startup(msg).await.unwrap();
        assert_eq!(
            outcome,
            AuthOutcome {
                backend_pid: 42,
                secret_key: 99,
            }
        );
    }

    // -----------------------------------------------------------------
    // Robustness: malformed Startup packets never panic (in the same
    // spirit as Property 51)
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn arbitrary_startup_body_never_panics(body in prop::collection::vec(any::<u8>(), 0..128)) {
            let _ = parse_startup_body(&body);
        }
    }
}
