//! PostgreSQL backend password authentication.
//!
//! Implements the client side of CleartextPassword, MD5Password and
//! SASL/SCRAM-SHA-256. The proxy and health checker share this state
//! machine so both accept exactly the same backend authentication modes.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::message::BackendMessage;
use super::reader::read_backend_message;
use super::writer::{
    encode_password_message, encode_sasl_initial_response, encode_sasl_response,
};
use super::ProtocolError;

type HmacSha256 = Hmac<Sha256>;
const SCRAM_SHA_256: &str = "SCRAM-SHA-256";
/// Defensive upper bound for a server-provided SCRAM verifier cost.
/// PostgreSQL currently generates verifiers with 4096 iterations. Accepting
/// substantially more preserves compatibility with hardened deployments,
/// while preventing a malicious or compromised backend from pinning a Tokio
/// worker indefinitely with an attacker-controlled PBKDF2 count.
const MAX_SCRAM_ITERATIONS: u32 = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum BackendAuthError {
    #[error("backend authentication requires a password, but none was configured")]
    MissingPassword,

    #[error("backend rejected authentication: {0}")]
    Rejected(String),

    #[error("backend offered no supported SASL mechanism: {0:?}")]
    UnsupportedSaslMechanisms(Vec<String>),

    #[error("invalid SCRAM server message: {0}")]
    InvalidScramMessage(String),

    #[error("SCRAM server signature verification failed")]
    InvalidServerSignature,

    #[error("unexpected backend message during authentication: {0:?}")]
    UnexpectedMessage(BackendMessage),

    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Completes backend authentication after the StartupMessage has been
/// sent. Returns only after AuthenticationOk; startup ParameterStatus,
/// BackendKeyData and ReadyForQuery remain for the caller to consume.
pub async fn authenticate_backend<S>(
    stream: &mut S,
    username: &str,
    password: Option<&str>,
) -> Result<(), BackendAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        match read_backend_message(stream).await? {
            BackendMessage::AuthenticationOk => return Ok(()),
            BackendMessage::AuthenticationCleartextPassword => {
                let password = password.ok_or(BackendAuthError::MissingPassword)?;
                stream.write_all(&encode_password_message(password)).await?;
                stream.flush().await?;
            }
            BackendMessage::AuthenticationMd5Password { salt } => {
                let password = password.ok_or(BackendAuthError::MissingPassword)?;
                let response = postgres_md5_password(username, password, salt);
                stream.write_all(&encode_password_message(&response)).await?;
                stream.flush().await?;
            }
            BackendMessage::AuthenticationSasl { mechanisms } => {
                let password = password.ok_or(BackendAuthError::MissingPassword)?;
                if !mechanisms.iter().any(|m| m == SCRAM_SHA_256) {
                    return Err(BackendAuthError::UnsupportedSaslMechanisms(mechanisms));
                }

                let mut scram = ScramSha256Client::new(password);
                let initial = scram.initial_message();
                stream
                    .write_all(&encode_sasl_initial_response(SCRAM_SHA_256, initial.as_bytes()))
                    .await?;
                stream.flush().await?;

                let server_first = match read_backend_message(stream).await? {
                    BackendMessage::AuthenticationSaslContinue(data) => data,
                    BackendMessage::ErrorResponse(error) => {
                        return Err(BackendAuthError::Rejected(error_message(&error)))
                    }
                    message => return Err(BackendAuthError::UnexpectedMessage(message)),
                };
                let server_first = std::str::from_utf8(&server_first).map_err(|_| {
                    BackendAuthError::InvalidScramMessage(
                        "server-first-message is not valid UTF-8".into(),
                    )
                })?;
                let client_final = scram.handle_server_first(server_first)?;
                stream
                    .write_all(&encode_sasl_response(client_final.as_bytes()))
                    .await?;
                stream.flush().await?;

                let server_final = match read_backend_message(stream).await? {
                    BackendMessage::AuthenticationSaslFinal(data) => data,
                    BackendMessage::ErrorResponse(error) => {
                        return Err(BackendAuthError::Rejected(error_message(&error)))
                    }
                    message => return Err(BackendAuthError::UnexpectedMessage(message)),
                };
                let server_final = std::str::from_utf8(&server_final).map_err(|_| {
                    BackendAuthError::InvalidScramMessage(
                        "server-final-message is not valid UTF-8".into(),
                    )
                })?;
                scram.verify_server_final(server_final)?;
            }
            BackendMessage::ErrorResponse(error) => {
                return Err(BackendAuthError::Rejected(error_message(&error)))
            }
            message => return Err(BackendAuthError::UnexpectedMessage(message)),
        }
    }
}

fn error_message(error: &super::message::PgError) -> String {
    error.message().unwrap_or("unknown authentication error").to_string()
}

/// PostgreSQL's legacy MD5 response:
/// `"md5" + md5(hex(md5(password + username)) + four_byte_salt)`.
pub fn postgres_md5_password(username: &str, password: &str, salt: [u8; 4]) -> String {
    let mut first = Md5::new();
    first.update(password.as_bytes());
    first.update(username.as_bytes());
    let first_hex = hex_lower(&first.finalize());

    let mut second = Md5::new();
    second.update(first_hex.as_bytes());
    second.update(salt);
    format!("md5{}", hex_lower(&second.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

struct ScramSha256Client {
    password: String,
    nonce: String,
    client_first_bare: String,
    server_key: Option<[u8; 32]>,
    auth_message: Option<String>,
}

impl ScramSha256Client {
    fn new(password: &str) -> Self {
        let mut nonce_bytes = [0u8; 18];
        rand::rng().fill_bytes(&mut nonce_bytes);
        Self::with_nonce(password, BASE64.encode(nonce_bytes))
    }

    fn with_nonce(password: &str, nonce: String) -> Self {
        let client_first_bare = format!("n=,r={nonce}");
        ScramSha256Client {
            password: password.to_string(),
            nonce,
            client_first_bare,
            server_key: None,
            auth_message: None,
        }
    }

    fn initial_message(&self) -> String {
        format!("n,,{}", self.client_first_bare)
    }

    fn handle_server_first(
        &mut self,
        server_first: &str,
    ) -> Result<String, BackendAuthError> {
        let attributes = parse_scram_attributes(server_first)?;
        if attributes.iter().any(|(key, _)| *key == 'm') {
            return Err(BackendAuthError::InvalidScramMessage(
                "unsupported mandatory SCRAM extension".into(),
            ));
        }
        let combined_nonce = required_attribute(&attributes, 'r')?;
        if !combined_nonce.starts_with(&self.nonce) || combined_nonce.len() <= self.nonce.len() {
            return Err(BackendAuthError::InvalidScramMessage(
                "server nonce does not extend the client nonce".into(),
            ));
        }
        let salt = BASE64.decode(required_attribute(&attributes, 's')?).map_err(|_| {
            BackendAuthError::InvalidScramMessage("invalid base64 salt".into())
        })?;
        let iterations: u32 = required_attribute(&attributes, 'i')?
            .parse()
            .map_err(|_| BackendAuthError::InvalidScramMessage("invalid iteration count".into()))?;
        if iterations == 0 {
            return Err(BackendAuthError::InvalidScramMessage(
                "iteration count must be positive".into(),
            ));
        }
        if iterations > MAX_SCRAM_ITERATIONS {
            return Err(BackendAuthError::InvalidScramMessage(format!(
                "iteration count exceeds supported maximum of {MAX_SCRAM_ITERATIONS}"
            )));
        }

        // PostgreSQL applies SASLprep when possible and falls back to the
        // original UTF-8 password when normalization rejects it.
        let normalized = stringprep::saslprep(&self.password)
            .map(|value| value.into_owned())
            .unwrap_or_else(|_| self.password.clone());
        let mut salted_password = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            normalized.as_bytes(),
            &salt,
            iterations,
            &mut salted_password,
        );

        let client_key = hmac_sha256(&salted_password, b"Client Key")?;
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();
        let client_final_without_proof = format!("c=biws,r={combined_nonce}");
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_without_proof
        );
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes())?;
        let mut proof = [0u8; 32];
        for index in 0..proof.len() {
            proof[index] = client_key[index] ^ client_signature[index];
        }

        self.server_key = Some(hmac_sha256(&salted_password, b"Server Key")?);
        self.auth_message = Some(auth_message);
        Ok(format!(
            "{},p={}",
            client_final_without_proof,
            BASE64.encode(proof)
        ))
    }

    fn verify_server_final(&self, server_final: &str) -> Result<(), BackendAuthError> {
        let attributes = parse_scram_attributes(server_final)?;
        if let Some((_, message)) = attributes.iter().find(|(key, _)| *key == 'e') {
            return Err(BackendAuthError::Rejected((*message).to_string()));
        }
        let signature = BASE64
            .decode(required_attribute(&attributes, 'v')?)
            .map_err(|_| {
                BackendAuthError::InvalidScramMessage(
                    "invalid base64 server signature".into(),
                )
            })?;
        let server_key = self.server_key.ok_or_else(|| {
            BackendAuthError::InvalidScramMessage(
                "server-final-message arrived before server-first-message".into(),
            )
        })?;
        let auth_message = self.auth_message.as_ref().ok_or_else(|| {
            BackendAuthError::InvalidScramMessage("missing SCRAM authentication transcript".into())
        })?;
        let mut mac = HmacSha256::new_from_slice(&server_key)
            .map_err(|_| BackendAuthError::InvalidScramMessage("invalid HMAC key".into()))?;
        mac.update(auth_message.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| BackendAuthError::InvalidServerSignature)
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], BackendAuthError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| BackendAuthError::InvalidScramMessage("invalid HMAC key".into()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn parse_scram_attributes(input: &str) -> Result<Vec<(char, &str)>, BackendAuthError> {
    let mut attributes = Vec::new();
    for part in input.split(',') {
        let (key, value) = part.split_once('=').ok_or_else(|| {
            BackendAuthError::InvalidScramMessage("attribute is missing '='".into())
        })?;
        let mut chars = key.chars();
        let key = chars.next().filter(|_| chars.next().is_none()).ok_or_else(|| {
            BackendAuthError::InvalidScramMessage("attribute name must be one character".into())
        })?;
        if attributes.iter().any(|(existing, _)| *existing == key) {
            return Err(BackendAuthError::InvalidScramMessage(format!(
                "duplicate SCRAM attribute '{key}'"
            )));
        }
        attributes.push((key, value));
    }
    Ok(attributes)
}

fn required_attribute<'a>(
    attributes: &[(char, &'a str)],
    key: char,
) -> Result<&'a str, BackendAuthError> {
    attributes
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| *value)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            BackendAuthError::InvalidScramMessage(format!(
                "missing SCRAM attribute '{key}'"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_password_matches_postgresql_documented_algorithm() {
        // Independently generated with PostgreSQL's two-stage MD5 formula.
        assert_eq!(
            postgres_md5_password("user", "password", [1, 2, 3, 4]),
            "md5a3576f1ae039b8996bc4fc2720f9c71a"
        );
    }

    #[test]
    fn scram_rejects_server_nonce_that_does_not_extend_client_nonce() {
        let mut client = ScramSha256Client::with_nonce("pencil", "clientnonce".into());
        let error = client
            .handle_server_first("r=othernonce,s=c2FsdA==,i=4096")
            .unwrap_err();
        assert!(error.to_string().contains("server nonce"));
    }

    #[test]
    fn scram_rejects_duplicate_attributes() {
        let error = parse_scram_attributes("r=one,r=two,s=c2FsdA==,i=4096").unwrap_err();
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn scram_rejects_excessive_iteration_count_before_running_pbkdf2() {
        let mut client = ScramSha256Client::with_nonce("pencil", "clientnonce".into());
        let server_first = format!(
            "r=clientnonce-server,s=c2FsdA==,i={}",
            MAX_SCRAM_ITERATIONS + 1
        );
        let error = client.handle_server_first(&server_first).unwrap_err();
        assert!(error.to_string().contains("exceeds supported maximum"));
    }
}
