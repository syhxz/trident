//! Backend connection wrapper (`conn`)
//!
//! Defines `PooledConnection` metadata, and the logic for establishing a
//! physical connection to a backend node and completing authentication.
//!
//! Note: `PooledConnection` (consistent with design.md) contains only the
//! connection's logical metadata (`node_id`/`backend_pid`/`secret_key`/
//! `pinned`/`dirty`) and does not hold the actual `TcpStream`.
//! `establish_connection` establishes the real physical connection and
//! completes the authentication handshake, then returns the connection
//! metadata and the underlying socket separately; the layer above
//! (Proxy/Handler, see task 15) is responsible for associating the two
//! for actual message forwarding.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::config::SslMode;
use crate::protocol::auth::authenticate_backend;
use crate::protocol::message::{BackendMessage, StartupMessage};
use crate::protocol::reader::read_backend_message;
use crate::protocol::writer::encode_query;

/// A stream that is either a plain TCP connection or a TLS-wrapped one.
/// Implements `AsyncRead + AsyncWrite` so it can be used transparently
/// in place of a bare `TcpStream` throughout the proxy pipeline.
#[derive(Debug)]
pub enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Logical metadata for a single backend connection in a Transaction/Session pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PooledConnection {
    pub node_id: String,
    pub backend_pid: i32,
    pub secret_key: i32,
    pub pinned: bool,
    pub dirty: bool,
    /// Creation time is carried with metadata clones so max_lifetime still
    /// applies after a connection has been checked out and returned.
    pub(crate) created_at: Instant,
    /// Set only while the connection is in a reusable idle queue. Checked-out
    /// and session-pinned connections are never expired underneath a client.
    pub(crate) idle_since: Option<Instant>,
}

impl PooledConnection {
    pub fn new(node_id: impl Into<String>, backend_pid: i32, secret_key: i32) -> Self {
        PooledConnection {
            node_id: node_id.into(),
            backend_pid,
            secret_key,
            pinned: false,
            dirty: false,
            created_at: Instant::now(),
            idle_since: None,
        }
    }
}

/// Target node information needed to establish a physical connection.
#[derive(Debug, Clone)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: Option<String>,
    pub ssl_mode: SslMode,
}

/// Physical connection establishment error
#[derive(Debug, thiserror::Error)]
pub enum ConnError {
    #[error("failed to connect to backend node: {0}")]
    Io(#[from] std::io::Error),

    #[error("backend authentication/startup failed: {0}")]
    AuthFailed(String),

    #[error("backend did not send BackendKeyData before ReadyForQuery")]
    MissingBackendKeyData,
}

/// Establishes a physical TCP connection to a backend node, completes the
/// Startup/authentication handshake, and returns the connection metadata
/// along with the underlying socket.
///
/// If `target.ssl_mode` is `Prefer` or `Require`, an SSLRequest is sent
/// before the Startup message. On acceptance (`S`), the connection is
/// upgraded to TLS. On rejection (`N`), `Prefer` falls back to plaintext
/// while `Require` returns an error.
///
/// See Requirement 5.1, 5.2: a connection obtained from the connection
/// pool must be a usable, already-authenticated connection.
pub async fn establish_connection(
    node_id: &str,
    target: &ConnectTarget,
) -> Result<(PooledConnection, MaybeTlsStream), ConnError> {
    tracing::debug!(node_id, host = %target.host, ssl_mode = ?target.ssl_mode, "establishing connection");
    let mut tcp_stream = TcpStream::connect((target.host.as_str(), target.port)).await?;
    // Disable Nagle: proxy-to-backend messages are small and latency-sensitive.
    let _ = tcp_stream.set_nodelay(true);
    tracing::debug!(node_id, "TCP connected");

    // --- SSL negotiation ---
    let mut stream = match target.ssl_mode {
        SslMode::Disable => MaybeTlsStream::Plain(tcp_stream),
        SslMode::Prefer | SslMode::Require => {
            send_ssl_request(&mut tcp_stream).await?;
            tracing::debug!(node_id, "SSLRequest sent");
            let response = read_ssl_response(&mut tcp_stream).await?;
            tracing::debug!(node_id, response = %format!("{}", response as char), "SSL response received");
            match response {
                b'S' => {
                    // Server accepts SSL -- perform TLS handshake
                    let tls_stream = upgrade_to_tls(tcp_stream, &target.host).await?;
                    tracing::debug!(node_id, "TLS handshake complete");
                    MaybeTlsStream::Tls(tls_stream)
                }
                b'N' => {
                    // Server declines SSL
                    if target.ssl_mode == SslMode::Require {
                        return Err(ConnError::AuthFailed(
                            "server does not support SSL but ssl_mode=require".to_string(),
                        ));
                    }
                    // ssl_mode=prefer: fall back to plaintext
                    MaybeTlsStream::Plain(tcp_stream)
                }
                other => {
                    return Err(ConnError::AuthFailed(format!(
                        "unexpected SSL response byte from server: 0x{:02x}",
                        other
                    )));
                }
            }
        }
    };

    let mut params = HashMap::new();
    params.insert("user".to_string(), target.username.clone());
    params.insert("database".to_string(), target.database.clone());
    let startup = StartupMessage {
        protocol_version: 196_608, // 3.0
        params,
    };
    send_startup(&mut stream, &startup).await?;
    tracing::debug!(node_id, "startup message sent, starting auth");
    authenticate_backend(
        &mut stream,
        &target.username,
        target.password.as_deref(),
    )
    .await
    .map_err(|error| ConnError::AuthFailed(error.to_string()))?;

    let mut backend_pid = None;
    let mut secret_key = None;
    loop {
        match read_backend_message(&mut stream).await {
            Ok(BackendMessage::BackendKeyData { pid, secret_key: key }) => {
                backend_pid = Some(pid);
                secret_key = Some(key);
            }
            Ok(BackendMessage::ReadyForQuery(_)) => break,
            Ok(BackendMessage::ParameterStatus { .. }) => continue,
            Ok(BackendMessage::ErrorResponse(err)) => {
                return Err(ConnError::AuthFailed(
                    err.message().unwrap_or("unknown error").to_string(),
                ))
            }
            Ok(_) => continue,
            Err(e) => return Err(ConnError::AuthFailed(e.to_string())),
        }
    }

    let (pid, key) = match (backend_pid, secret_key) {
        (Some(pid), Some(key)) => (pid, key),
        _ => return Err(ConnError::MissingBackendKeyData),
    };

    Ok((PooledConnection::new(node_id, pid, key), stream))
}

/// Sends the 8-byte SSLRequest message (length=8, code=80877103).
async fn send_ssl_request(stream: &mut TcpStream) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;
    // SSLRequest: int32 length (8) + int32 code (80877103)
    let msg: [u8; 8] = [
        0x00, 0x00, 0x00, 0x08, // length = 8
        0x04, 0xd2, 0x16, 0x2f, // 80877103
    ];
    stream.write_all(&msg).await
}

/// Reads the single-byte SSL response from the server (`S` or `N`).
async fn read_ssl_response(stream: &mut TcpStream) -> Result<u8, ConnError> {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).await?;
    Ok(buf[0])
}

/// Upgrades a plain TCP connection to TLS using rustls.
/// Note: `ssl_mode=require` and `ssl_mode=prefer` in PostgreSQL semantics
/// do NOT verify the server certificate (like libpq). Only `verify-ca` and
/// `verify-full` do, which are not yet implemented here. We use a custom
/// certificate verifier that accepts any server certificate.
async fn upgrade_to_tls(
    tcp_stream: TcpStream,
    host: &str,
) -> Result<TlsStream<TcpStream>, ConnError> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| ConnError::AuthFailed(format!("invalid TLS server name '{}': {}", host, e)))?;

    connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| ConnError::AuthFailed(format!("TLS handshake failed: {}", e)))
}

/// A TLS certificate verifier that accepts any server certificate.
/// This matches the behavior of PostgreSQL's `sslmode=require` which
/// encrypts the connection but does not verify the server's identity.
#[derive(Debug)]
pub struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

async fn send_startup(
    stream: &mut MaybeTlsStream,
    startup: &StartupMessage,
) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;

    let mut body = startup.protocol_version.to_be_bytes().to_vec();
    for (k, v) in &startup.params {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut framed = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    framed.extend(body);
    stream.write_all(&framed).await?;
    stream.flush().await
}

/// Convenience helper: sends a given `Query` message over an already
/// established physical connection (kept for reference by `conn` module
/// internal tests or Health-probe reuse logic; not currently used on the
/// pool's main code path).
#[allow(dead_code)]
async fn send_query(stream: &mut MaybeTlsStream, sql: &str) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;
    let bytes = encode_query(sql);
    stream.write_all(&bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pooled_connection_starts_clean_and_unpinned() {
        let conn = PooledConnection::new("writer", 100, 200);
        assert!(!conn.pinned);
        assert!(!conn.dirty);
        assert_eq!(conn.node_id, "writer");
        assert_eq!(conn.backend_pid, 100);
        assert_eq!(conn.secret_key, 200);
    }
}
