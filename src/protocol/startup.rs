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
    const MAX_STARTUP_LEN: i32 = 64 * 1024; // 64KiB cap for pre-auth startup messages
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
    /// When passthrough mode is active, the client's credentials are
    /// captured here so the proxy can use them to authenticate against
    /// backend nodes on behalf of this client session.
    pub client_credentials: Option<ClientCredentials>,
}

/// Client credentials captured during passthrough authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientCredentials {
    pub username: String,
    pub password: String,
    /// Database name from the client's StartupMessage. In passthrough mode,
    /// backend connections should use this database instead of the node's
    /// default.
    pub database: Option<String>,
    /// Extra startup parameters from the client's StartupMessage (e.g.
    /// `application_name`, `options`, `search_path`, `TimeZone`,
    /// `client_encoding`). These are forwarded to the backend when
    /// establishing per-user connections, preserving JDBC/libpq driver
    /// behavior.
    pub extra_params: HashMap<String, String>,
}

impl std::fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("database", &self.database)
            .field("extra_params", &self.extra_params)
            .finish()
    }
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
    fn handle_startup_with_stream<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    >(
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
            client_credentials: None,
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

    async fn handle_startup_with_stream<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    >(
        &mut self,
        msg: StartupMessage,
        stream: &mut S,
    ) -> Result<AuthOutcome, ProtocolError> {
        use md5::Md5;
        use sha2::Digest; // for Md5::new() / update / finalize (md5 re-exports digest trait)
        use tokio::io::AsyncWriteExt;

        let username = msg.params.get("user").cloned().unwrap_or_default();

        let expected_password = self
            .credentials
            .get(&username)
            .ok_or_else(|| ProtocolError::Malformed(format!("unknown user: {}", username)))?
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
        let (tag, body) = crate::protocol::reader::read_tagged_frame_bounded(
            stream,
            crate::protocol::reader::MAX_AUTH_MESSAGE_BODY_LEN,
        )
        .await?;
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
        hasher.update(salt);
        let outer_result = hasher.finalize();
        let expected_response = format!("md5{:x}", outer_result);

        // Constant-time comparison to prevent timing side-channel attacks.
        // An attacker sending many auth attempts could otherwise infer the
        // correct hash prefix from response-time differences.
        let match_ok = client_response.len() == expected_response.len()
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
            client_credentials: None,
        })
    }
}

/// SCRAM-SHA-256 server-side authentication handler. Validates client
/// credentials against stored SCRAM verifiers (salt + StoredKey + ServerKey)
/// loaded from an auth_file. The proxy verifies the client's identity,
/// then continues to use the configured service account for backend
/// connections.
///
/// Auth file format for SCRAM entries:
///   "username" "SCRAM-SHA-256$iterations:base64salt$base64StoredKey:base64ServerKey"
///
/// You can generate a verifier using PostgreSQL:
///   SELECT rolpassword FROM pg_authid WHERE rolname = 'user';
///
/// Plaintext passwords in the auth_file are also supported: the handler
/// will derive the verifier on-the-fly using PBKDF2 with 4096 iterations.
pub struct ScramStartupHandler {
    pub backend_pid: i32,
    pub secret_key: i32,
    /// username -> password or SCRAM verifier string
    pub credentials: std::sync::Arc<std::collections::HashMap<String, String>>,
}

/// Parsed SCRAM verifier components.
struct ScramVerifier {
    iterations: u32,
    salt: Vec<u8>,
    stored_key: [u8; 32],
    server_key: [u8; 32],
}

impl ScramVerifier {
    /// Parse a PostgreSQL-format SCRAM verifier:
    /// `SCRAM-SHA-256$iterations:base64salt$base64StoredKey:base64ServerKey`
    fn parse(s: &str) -> Option<Self> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;

        let s = s.strip_prefix("SCRAM-SHA-256$")?;
        let (iter_salt, keys) = s.split_once('$')?;
        let (iter_str, salt_b64) = iter_salt.split_once(':')?;
        let (stored_key_b64, server_key_b64) = keys.split_once(':')?;

        let iterations: u32 = iter_str.parse().ok()?;
        let salt = B64.decode(salt_b64).ok()?;
        let stored_key_bytes = B64.decode(stored_key_b64).ok()?;
        let server_key_bytes = B64.decode(server_key_b64).ok()?;

        if stored_key_bytes.len() != 32 || server_key_bytes.len() != 32 {
            return None;
        }

        let mut stored_key = [0u8; 32];
        let mut server_key = [0u8; 32];
        stored_key.copy_from_slice(&stored_key_bytes);
        server_key.copy_from_slice(&server_key_bytes);

        Some(ScramVerifier {
            iterations,
            salt,
            stored_key,
            server_key,
        })
    }

    /// Derive a verifier from a plaintext password.
    fn from_password(password: &str) -> Self {
        use sha2::{Digest, Sha256};

        let iterations = 4096u32;
        let mut salt_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut salt_bytes);
        let salt = salt_bytes.to_vec();

        let normalized = stringprep::saslprep(password)
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| password.to_string());

        let mut salted_password = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(
            normalized.as_bytes(),
            &salt,
            iterations,
            &mut salted_password,
        );

        let client_key = Self::hmac(&salted_password, b"Client Key");
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();
        let server_key = Self::hmac(&salted_password, b"Server Key");

        ScramVerifier {
            iterations,
            salt,
            stored_key,
            server_key,
        }
    }

    fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

impl StartupHandler for ScramStartupHandler {
    async fn handle_startup(&mut self, _msg: StartupMessage) -> Result<AuthOutcome, ProtocolError> {
        Err(ProtocolError::Malformed(
            "SCRAM auth requires stream access; internal error".into(),
        ))
    }

    async fn handle_startup_with_stream<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    >(
        &mut self,
        msg: StartupMessage,
        stream: &mut S,
    ) -> Result<AuthOutcome, ProtocolError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;

        let username = msg.params.get("user").cloned().unwrap_or_default();

        let credential = self
            .credentials
            .get(&username)
            .ok_or_else(|| ProtocolError::Malformed(format!("unknown user: {}", username)))?
            .clone();

        // Parse or derive the SCRAM verifier. When deriving from a plaintext
        // password, PBKDF2 is CPU-intensive and must not block the Tokio
        // worker thread. Use spawn_blocking to offload it.
        let verifier = if credential.starts_with("SCRAM-SHA-256$") {
            ScramVerifier::parse(&credential).ok_or_else(|| {
                ProtocolError::Malformed("invalid SCRAM verifier format in auth_file".into())
            })?
        } else {
            let cred_clone = credential.clone();
            tokio::task::spawn_blocking(move || ScramVerifier::from_password(&cred_clone))
                .await
                .map_err(|e| ProtocolError::Malformed(format!("SCRAM derivation failed: {}", e)))?
        };

        // Step 1: Send AuthenticationSASL (offer SCRAM-SHA-256)
        let mechanism = b"SCRAM-SHA-256\0";
        let body_len = 4 + mechanism.len() + 1; // auth_type(4) + mechanism + list terminator
        let mut auth_sasl = Vec::with_capacity(1 + 4 + body_len);
        auth_sasl.push(b'R');
        auth_sasl.extend_from_slice(&((body_len + 4) as i32).to_be_bytes());
        auth_sasl.extend_from_slice(&10i32.to_be_bytes()); // AuthenticationSASL = 10
        auth_sasl.extend_from_slice(mechanism);
        auth_sasl.push(0); // mechanism list terminator

        stream
            .write_all(&auth_sasl)
            .await
            .map_err(ProtocolError::Io)?;
        stream.flush().await.map_err(ProtocolError::Io)?;

        // Step 2: Receive SASLInitialResponse (client-first-message)
        let (tag, body) = crate::protocol::reader::read_tagged_frame_bounded(
            stream,
            crate::protocol::reader::MAX_AUTH_MESSAGE_BODY_LEN,
        )
        .await?;
        if tag != b'p' {
            return Err(ProtocolError::Malformed(format!(
                "expected SASLInitialResponse ('p'), got '{}'",
                tag as char
            )));
        }

        // Parse: mechanism\0 + int32(data_len) + data
        let mech_end = body.iter().position(|&b| b == 0).ok_or_else(|| {
            ProtocolError::Malformed("SASLInitialResponse missing mechanism terminator".into())
        })?;
        // Validate the mechanism is SCRAM-SHA-256
        let mechanism = std::str::from_utf8(&body[..mech_end]).map_err(|_| {
            ProtocolError::Malformed("SASLInitialResponse mechanism is not UTF-8".into())
        })?;
        if mechanism != "SCRAM-SHA-256" {
            return Err(ProtocolError::Malformed(format!(
                "unsupported SASL mechanism '{}', only SCRAM-SHA-256 is supported",
                mechanism
            )));
        }
        let rest = &body[mech_end + 1..];
        if rest.len() < 4 {
            return Err(ProtocolError::Malformed(
                "SASLInitialResponse too short".into(),
            ));
        }
        let data_len_i32 = i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
        if data_len_i32 < 0 {
            return Err(ProtocolError::Malformed(
                "SASLInitialResponse has negative data length".into(),
            ));
        }
        let data_len = data_len_i32 as usize;
        let total_len = 4usize.checked_add(data_len).ok_or_else(|| {
            ProtocolError::Malformed("SASLInitialResponse data length overflow".into())
        })?;
        if rest.len() < total_len {
            return Err(ProtocolError::Malformed(
                "SASLInitialResponse data truncated".into(),
            ));
        }
        if rest.len() != total_len {
            return Err(ProtocolError::Malformed(
                "SASLInitialResponse has trailing data after SASL payload".into(),
            ));
        }
        let client_first = std::str::from_utf8(&rest[4..4 + data_len])
            .map_err(|_| ProtocolError::Malformed("client-first-message is not UTF-8".into()))?;

        // Parse "n,,<client_first_bare>" where client_first_bare = "n=,r=<nonce>"
        let client_first_bare = client_first.strip_prefix("n,,").ok_or_else(|| {
            ProtocolError::Malformed("client-first-message must start with 'n,,'".into())
        })?;

        let client_nonce = client_first_bare
            .split(',')
            .find_map(|part| part.strip_prefix("r="))
            .ok_or_else(|| {
                ProtocolError::Malformed("client-first-message missing 'r=' nonce".into())
            })?;

        // Generate server nonce
        let mut server_nonce_bytes = [0u8; 18];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut server_nonce_bytes);
        let combined_nonce = format!("{}{}", client_nonce, B64.encode(server_nonce_bytes));

        // Step 3: Send AuthenticationSASLContinue (server-first-message)
        let server_first = format!(
            "r={},s={},i={}",
            combined_nonce,
            B64.encode(&verifier.salt),
            verifier.iterations,
        );

        let sfm_body_len = 4 + server_first.len(); // auth_type(4) + data
        let mut sasl_continue = Vec::with_capacity(1 + 4 + sfm_body_len);
        sasl_continue.push(b'R');
        sasl_continue.extend_from_slice(&((sfm_body_len + 4) as i32).to_be_bytes());
        sasl_continue.extend_from_slice(&11i32.to_be_bytes()); // AuthSASLContinue = 11
        sasl_continue.extend_from_slice(server_first.as_bytes());

        stream
            .write_all(&sasl_continue)
            .await
            .map_err(ProtocolError::Io)?;
        stream.flush().await.map_err(ProtocolError::Io)?;

        // Step 4: Receive SASLResponse (client-final-message)
        let (tag, body) = crate::protocol::reader::read_tagged_frame_bounded(
            stream,
            crate::protocol::reader::MAX_AUTH_MESSAGE_BODY_LEN,
        )
        .await?;
        if tag != b'p' {
            return Err(ProtocolError::Malformed(format!(
                "expected SASLResponse ('p'), got '{}'",
                tag as char
            )));
        }
        let client_final = std::str::from_utf8(&body)
            .map_err(|_| ProtocolError::Malformed("client-final-message is not UTF-8".into()))?;
        let client_final = client_final.trim_end_matches('\0');

        // Validate channel binding: must be "c=biws" (base64 of "n,,")
        // for the no-channel-binding case (gs2-header = "n,,").
        let channel_binding = client_final
            .split(',')
            .find_map(|part| part.strip_prefix("c="))
            .ok_or_else(|| {
                ProtocolError::Malformed("client-final-message missing channel binding 'c='".into())
            })?;
        if channel_binding != "biws" {
            return Err(ProtocolError::Malformed(
                "client-final-message channel binding must be 'biws' (no channel binding)".into(),
            ));
        }

        // Validate nonce: client-final's "r=" must equal the combined_nonce
        // we sent in server-first-message.
        let final_nonce = client_final
            .split(',')
            .find_map(|part| part.strip_prefix("r="))
            .ok_or_else(|| {
                ProtocolError::Malformed("client-final-message missing nonce 'r='".into())
            })?;
        if final_nonce != combined_nonce {
            return Err(ProtocolError::Malformed(
                "client-final-message nonce does not match server combined nonce".into(),
            ));
        }

        // Extract proof
        let proof_b64 = client_final
            .split(',')
            .find_map(|part| part.strip_prefix("p="))
            .ok_or_else(|| ProtocolError::Malformed("client-final-message missing proof".into()))?;
        let client_proof = B64
            .decode(proof_b64)
            .map_err(|_| ProtocolError::Malformed("invalid base64 proof".into()))?;
        if client_proof.len() != 32 {
            return Err(ProtocolError::Malformed("proof must be 32 bytes".into()));
        }

        // Build auth_message
        let client_final_without_proof = client_final
            .rsplit_once(",p=")
            .map(|(prefix, _)| prefix)
            .ok_or_else(|| ProtocolError::Malformed("cannot split client-final at proof".into()))?;

        let auth_message = format!(
            "{},{},{}",
            client_first_bare, server_first, client_final_without_proof
        );

        // Verify: ClientSignature = HMAC(StoredKey, AuthMessage)
        let client_signature = ScramVerifier::hmac(&verifier.stored_key, auth_message.as_bytes());

        // Recover ClientKey = ClientProof XOR ClientSignature
        let mut recovered_client_key = [0u8; 32];
        for i in 0..32 {
            recovered_client_key[i] = client_proof[i] ^ client_signature[i];
        }

        // H(recovered_client_key) must equal StoredKey
        let recovered_stored_key: [u8; 32] = Sha256::digest(recovered_client_key).into();

        let keys_match: bool =
            subtle::ConstantTimeEq::ct_eq(&recovered_stored_key[..], &verifier.stored_key[..])
                .into();

        if !keys_match {
            return Err(ProtocolError::Malformed(
                "SCRAM authentication failed".into(),
            ));
        }

        // Step 5: Send AuthenticationSASLFinal (server-final-message)
        let server_signature = ScramVerifier::hmac(&verifier.server_key, auth_message.as_bytes());
        let server_final_msg = format!("v={}", B64.encode(server_signature));

        let sfinal_body_len = 4 + server_final_msg.len();
        let mut sasl_final = Vec::with_capacity(1 + 4 + sfinal_body_len);
        sasl_final.push(b'R');
        sasl_final.extend_from_slice(&((sfinal_body_len + 4) as i32).to_be_bytes());
        sasl_final.extend_from_slice(&12i32.to_be_bytes()); // AuthSASLFinal = 12
        sasl_final.extend_from_slice(server_final_msg.as_bytes());

        stream
            .write_all(&sasl_final)
            .await
            .map_err(ProtocolError::Io)?;
        stream.flush().await.map_err(ProtocolError::Io)?;

        Ok(AuthOutcome {
            backend_pid: self.backend_pid,
            secret_key: self.secret_key,
            client_credentials: None,
        })
    }
}

/// Passthrough authentication handler: captures the client's cleartext
/// password and stores it in `AuthOutcome::client_credentials` so the proxy
/// can use it to authenticate against backend PostgreSQL nodes. The proxy
/// does NOT verify the password locally — the real authentication happens
/// when the proxy opens a backend connection using the client's credentials.
///
/// This enables the credential passthrough model where each
/// client retains its database-level identity, RBAC, and audit trail.
///
/// The handler sends an AuthenticationCleartextPassword challenge to the
/// client, receives the password, and stores both username and password
/// for later use by the pool layer.
pub struct PassthroughStartupHandler {
    pub backend_pid: i32,
    pub secret_key: i32,
}

impl StartupHandler for PassthroughStartupHandler {
    async fn handle_startup(&mut self, _msg: StartupMessage) -> Result<AuthOutcome, ProtocolError> {
        Err(ProtocolError::Malformed(
            "Passthrough auth requires stream access; internal error".into(),
        ))
    }

    async fn handle_startup_with_stream<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    >(
        &mut self,
        msg: StartupMessage,
        stream: &mut S,
    ) -> Result<AuthOutcome, ProtocolError> {
        use tokio::io::AsyncWriteExt;

        let username = msg.params.get("user").cloned().unwrap_or_default();

        if username.is_empty() {
            return Err(ProtocolError::Malformed(
                "passthrough auth requires a 'user' parameter in StartupMessage".into(),
            ));
        }

        // Send AuthenticationCleartextPassword (type=3)
        let mut auth_msg = Vec::with_capacity(9);
        auth_msg.push(b'R');
        // length: 4 (len field) + 4 (auth type) = 8
        auth_msg.extend_from_slice(&8i32.to_be_bytes());
        // AuthType = 3 (CleartextPassword)
        auth_msg.extend_from_slice(&3i32.to_be_bytes());

        stream
            .write_all(&auth_msg)
            .await
            .map_err(ProtocolError::Io)?;
        stream.flush().await.map_err(ProtocolError::Io)?;

        // Read PasswordMessage ('p')
        let (tag, body) = crate::protocol::reader::read_tagged_frame_bounded(
            stream,
            crate::protocol::reader::MAX_AUTH_MESSAGE_BODY_LEN,
        )
        .await?;
        if tag != b'p' {
            return Err(ProtocolError::Malformed(format!(
                "expected PasswordMessage ('p'), got '{}'",
                tag as char
            )));
        }

        // Extract the password C-string from body
        let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
        let password = std::str::from_utf8(&body[..end])
            .map_err(|_| ProtocolError::Malformed("password is not valid UTF-8".into()))?
            .to_string();

        if password.is_empty() {
            return Err(ProtocolError::Malformed(
                "passthrough auth received empty password".into(),
            ));
        }

        Ok(AuthOutcome {
            backend_pid: self.backend_pid,
            secret_key: self.secret_key,
            client_credentials: Some(ClientCredentials {
                username: username.clone(),
                password,
                database: msg.params.get("database").cloned(),
                extra_params: msg
                    .params
                    .into_iter()
                    .filter(|(k, _)| k != "user" && k != "database")
                    .collect(),
            }),
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
                client_credentials: None,
            }
        );
    }

    // -----------------------------------------------------------------
    // Robustness: malformed Startup packets never panic (in the same
    // spirit as Property 51)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn passthrough_handler_captures_credentials() {
        let mut handler = PassthroughStartupHandler {
            backend_pid: 10,
            secret_key: 20,
        };
        let mut params = HashMap::new();
        params.insert("user".to_string(), "app_user".to_string());
        let msg = StartupMessage {
            protocol_version: 196608,
            params,
        };

        // Simulate: handler sends AuthCleartextPassword, client replies.
        // We use an in-memory buffer:
        // - handler writes auth request (R + len + type=3) to the stream
        // - then reads password message ('p' + len + "secret\0")
        //
        // Build the stream: pre-fill with the password response the handler
        // will read, and capture what it writes.
        let password_msg = {
            let mut buf = Vec::new();
            buf.push(b'p');
            let password_with_nul = b"my_secret\0";
            let len = (4 + password_with_nul.len()) as i32;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(password_with_nul);
            buf
        };

        // Use a duplex stream: one side for reading (handler reads password),
        // one for writing (handler writes auth challenge).
        let (client_side, server_side) = tokio::io::duplex(1024);
        let (mut client_read, mut client_write) = tokio::io::split(client_side);

        // Spawn a task that writes the password message after reading the
        // auth challenge from the handler.
        let client_task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // Read the AuthenticationCleartextPassword message (9 bytes: R + 8 + 3)
            let mut auth_challenge = [0u8; 9];
            client_read.read_exact(&mut auth_challenge).await.unwrap();
            assert_eq!(auth_challenge[0], b'R');
            // Write password response
            client_write.write_all(&password_msg).await.unwrap();
            client_write.flush().await.unwrap();
        });

        let mut server_stream = server_side;
        let outcome = handler
            .handle_startup_with_stream(msg, &mut server_stream)
            .await
            .unwrap();

        client_task.await.unwrap();

        assert_eq!(outcome.backend_pid, 10);
        assert_eq!(outcome.secret_key, 20);
        let creds = outcome.client_credentials.unwrap();
        assert_eq!(creds.username, "app_user");
        assert_eq!(creds.password, "my_secret");
    }

    proptest! {
        #[test]
        fn arbitrary_startup_body_never_panics(body in prop::collection::vec(any::<u8>(), 0..128)) {
            let _ = parse_startup_body(&body);
        }
    }
}
