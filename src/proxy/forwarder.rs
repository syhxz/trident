//! Message forwarder (`forwarder`)
//!
//! Bidirectional message relay between a client and a backend connection.
//! Large result sets are forwarded message-by-message (streaming) rather
//! than being buffered in full, since `read_backend_message` /
//! `write_backend` operate one PostgreSQL wire message at a time.
//!
//! Also tracks:
//! - the routing target decided at `Parse` time for a named prepared
//!   statement, so that later `Bind`/`Execute` messages referencing that
//!   statement are forwarded to the same backend (Requirements 11.3, 11.4);
//! - LSN updates triggered by a write statement's `CommandComplete`
//!   (Requirement 3.1, 11.6);
//! - session transaction-state updates driven by `ReadyForQuery`
//!   (Requirement 11.5).

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
#[cfg(test)]
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::protocol::message::{BackendMessage, TransactionStatus};
use crate::protocol::reader::{read_backend_message, read_tagged_frame};
use crate::protocol::writer::encode_query;
#[cfg(test)]
use crate::protocol::writer::encode_backend_message;
use crate::protocol::ProtocolError;
use crate::session::lsn::LsnTracker;
use crate::session::session::TxState;

/// Tracks the routing target chosen at `Parse` time for each named prepared
/// statement within a session, ensuring `Bind`/`Execute` referencing that
/// statement name are forwarded consistently (Property 41).
#[derive(Debug, Default)]
pub struct ExtendedQueryRouteTracker {
    /// statement name -> node_id chosen when the statement was parsed.
    routes: HashMap<String, String>,
}

impl ExtendedQueryRouteTracker {
    pub fn new() -> Self {
        ExtendedQueryRouteTracker {
            routes: HashMap::new(),
        }
    }

    /// Records the routing target decided when a `Parse` message for
    /// `statement_name` was processed.
    pub fn record_parse_route(&mut self, statement_name: &str, node_id: &str) {
        self.routes
            .insert(statement_name.to_string(), node_id.to_string());
    }

    /// Returns the node id that a `Bind`/`Execute` referencing
    /// `statement_name` must be forwarded to, if a `Parse` was previously
    /// recorded for that name.
    pub fn route_for_statement(&self, statement_name: &str) -> Option<String> {
        self.routes.get(statement_name).cloned()
    }

    /// Removes a statement's recorded route (e.g. on `DEALLOCATE` or when
    /// the unnamed statement is re-parsed).
    pub fn forget_statement(&mut self, statement_name: &str) {
        self.routes.remove(statement_name);
    }
}

/// Applies a `ReadyForQuery` message to update the session's transaction
/// state, following the fixed mapping I->Idle, T->InTransaction, E->Failed
/// (Requirement 11.5 / Property 42).
pub fn apply_ready_for_query(status: TransactionStatus) -> TxState {
    match status {
        TransactionStatus::Idle => TxState::Idle,
        TransactionStatus::InTransaction => TxState::InTransaction,
        TransactionStatus::Failed => TxState::Failed,
    }
}

/// Determines whether a `CommandComplete` command tag corresponds to a
/// write operation whose LSN should be tracked (Requirement 11.6). This is
/// a conservative textual check against PostgreSQL's standard command tags
/// (`INSERT`, `UPDATE`, `DELETE`, `MERGE`, `COPY`).
pub fn is_write_command_tag(tag: &str) -> bool {
    let first_word = tag
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    matches!(first_word.as_str(), "INSERT" | "UPDATE" | "DELETE" | "MERGE" | "COPY")
}

/// Given a backend message and the LSN observed for the just-completed
/// write (if any), updates the session's write LSN. Returns `true` if an
/// update was applied.
///
/// `lsn_for_write` is a callback that yields the LSN to record for a write
/// command (e.g. obtained via a follow-up `SELECT pg_current_wal_lsn()`
/// issued by the caller after seeing `CommandComplete`); this function only
/// decides *whether* to record it based on the command tag.
pub fn maybe_record_write_lsn(
    msg: &BackendMessage,
    session_id: &str,
    lsn: u64,
    tracker: &dyn LsnTracker,
) -> bool {
    if let BackendMessage::CommandComplete { tag } = msg {
        if is_write_command_tag(tag) {
            tracker.record_write(session_id, lsn);
            return true;
        }
    }
    false
}

/// Outcome of relaying one simple-query round trip between a backend
/// connection and the client: the final transaction status reported by the
/// backend's `ReadyForQuery`, and the command tags of any write statements
/// that completed (used to decide whether a follow-up LSN fetch is needed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryRelayOutcome {
    pub tx_status: TransactionStatus,
    pub write_command_tags: Vec<String>,
    /// Every successful command tag from the client query cycle. This is
    /// used to distinguish a real COMMIT from PostgreSQL's ROLLBACK response
    /// when COMMIT is issued in an already-failed transaction.
    pub command_tags: Vec<String>,
    pub had_error_response: bool,
    /// Commit LSN reported by an extension through a configured
    /// ParameterStatus message during the client query cycle.
    pub reported_lsn: Option<u64>,
    /// Post-commit WAL watermark obtained from the optional second Query
    /// frame sent in the same outbound batch.
    pub pipelined_lsn: Option<u64>,
    pub pipeline_attempted: bool,
    /// False when the internal pipeline response timed out or the backend
    /// stream became unreadable and must not be reused.
    pub connection_reusable: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct QueryForwardOptions<'a> {
    pub pipeline_lsn: bool,
    pub extension_guc: Option<&'a str>,
    pub internal_query_timeout: Duration,
    /// Transaction-opening statement (a validated BEGIN variant) pipelined
    /// in the same outbound write as the main query, saving one full
    /// backend round trip when a delayed split-transaction BEGIN must be
    /// replayed before its first real statement. The BEGIN response cycle
    /// is consumed by the proxy (the client already received a synthesized
    /// BEGIN acknowledgment) and must end in transaction status `T`;
    /// anything else fails the relay before any client-visible bytes are
    /// written.
    pub begin_prefix: Option<&'a str>,
}

impl Default for QueryForwardOptions<'_> {
    fn default() -> Self {
        Self {
            pipeline_lsn: false,
            extension_guc: None,
            internal_query_timeout: Duration::from_millis(100),
            begin_prefix: None,
        }
    }
}

/// A protocol/I/O failure while relaying a Simple Query. The flag lets the
/// handler avoid synthesizing a second ErrorResponse when the backend's own
/// ErrorResponse was already delivered before the stream failed while
/// waiting for ReadyForQuery.
#[derive(Debug)]
pub struct QueryRelayError {
    pub source: ProtocolError,
    pub error_response_relayed: bool,
}

/// Sends `sql` as a simple-query `Query` message to the backend connection
/// and streams every response message it produces back to the client one
/// message at a time (no whole-result-set buffering), until the backend's
/// `ReadyForQuery` is observed. `ReadyForQuery` itself is *not* relayed here
/// -- the caller is expected to send its own `ReadyForQuery` to the client
/// after updating session state, so the two stay consistent (see
/// `proxy::handler::handle_simple_query`).
///
/// This implements the client<->backend forwarding described in
/// Requirements 3.1, 11.5, 11.6: `RowDescription`/`DataRow` are streamed
/// through untouched, `CommandComplete` for a write statement is recorded
/// so the caller can update `Session_Write_LSN`, and the transaction status
/// byte from `ReadyForQuery` is returned for the caller to apply via
/// `apply_ready_for_query`.
pub async fn forward_simple_query<B, C>(
    backend: &mut B,
    client: &mut C,
    sql: &str,
) -> Result<QueryRelayOutcome, QueryRelayError>
where
    B: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
    C: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
{
    forward_simple_query_with_options(backend, client, sql, QueryForwardOptions::default()).await
}

/// Relays one client Simple Query cycle and optionally queues a second,
/// proxy-internal WAL query in the same outbound batch. PostgreSQL processes
/// the second Query only after the first cycle's ReadyForQuery, so the sampled
/// WAL position is post-commit for an autocommit write or a successful COMMIT.
///
/// Performance: uses zero-copy relay for messages that don't require
/// inspection (DataRow, RowDescription, NoticeResponse, etc.). Only
/// ReadyForQuery, CommandComplete, ParameterStatus, and ErrorResponse are
/// parsed; all others are forwarded as raw wire bytes without decode/re-encode.
pub async fn forward_simple_query_with_options<B, C>(
    backend: &mut B,
    client: &mut C,
    sql: &str,
    options: QueryForwardOptions<'_>,
) -> Result<QueryRelayOutcome, QueryRelayError>
where
    B: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
    C: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut query_bytes = match options.begin_prefix {
        Some(begin_sql) => {
            let mut bytes = encode_query(begin_sql);
            bytes.extend_from_slice(&encode_query(sql));
            bytes
        }
        None => encode_query(sql),
    };
    if options.pipeline_lsn {
        query_bytes.extend_from_slice(&encode_query("SELECT pg_current_wal_lsn()"));
    }
    backend
        .write_all(&query_bytes)
        .await
        .map_err(|source| QueryRelayError {
            source: source.into(),
            error_response_relayed: false,
        })?;
    backend.flush().await.map_err(|source| QueryRelayError {
        source: source.into(),
        error_response_relayed: false,
    })?;

    // Consume the pipelined BEGIN's response cycle before relaying the main
    // statement. Nothing from this cycle reaches the client: the proxy
    // already acknowledged BEGIN locally when the split transaction was
    // opened. A canonical BEGIN on a healthy connection cannot realistically
    // fail; if it somehow does, the caller discards this backend socket, so
    // the already-pipelined main statement's response is never consumed and
    // the connection is never reused in an inconsistent state.
    if options.begin_prefix.is_some() {
        loop {
            let (tag, body) = read_tagged_frame(backend)
                .await
                .map_err(|source| QueryRelayError {
                    source,
                    error_response_relayed: false,
                })?;
            match tag {
                b'Z' => {
                    if body.len() != 1 {
                        return Err(QueryRelayError {
                            source: ProtocolError::Malformed(
                                "ReadyForQuery body length is not 1".into(),
                            ),
                            error_response_relayed: false,
                        });
                    }
                    let status = TransactionStatus::from_byte(body[0]);
                    if status != Some(TransactionStatus::InTransaction) {
                        return Err(QueryRelayError {
                            source: ProtocolError::Malformed(
                                "pipelined BEGIN did not open a transaction".into(),
                            ),
                            error_response_relayed: false,
                        });
                    }
                    break;
                }
                b'E' => {
                    return Err(QueryRelayError {
                        source: ProtocolError::Malformed(
                            "pipelined BEGIN was rejected by the backend".into(),
                        ),
                        error_response_relayed: false,
                    });
                }
                // CommandComplete("BEGIN"), NoticeResponse, ParameterStatus:
                // suppressed, the client saw a synthesized BEGIN already.
                _ => {}
            }
        }
    }

    let mut write_command_tags = Vec::new();
    let mut command_tags = Vec::new();
    let mut error_response_relayed = false;
    let mut reported_lsn = None;

    // Message type bytes that require full parsing (everything else is
    // zero-copy relayed as raw bytes).
    const TAG_READY_FOR_QUERY: u8 = b'Z';
    const TAG_COMMAND_COMPLETE: u8 = b'C';
    const TAG_PARAMETER_STATUS: u8 = b'S';
    const TAG_ERROR_RESPONSE: u8 = b'E';
    const TAG_COPY_IN_RESPONSE: u8 = b'G';

    let tx_status = loop {
        let (tag, body) =
            read_tagged_frame(backend)
                .await
                .map_err(|source| QueryRelayError {
                    source,
                    error_response_relayed,
                })?;

        match tag {
            TAG_READY_FOR_QUERY => {
                // Terminal message: extract transaction status, do NOT relay.
                // Strict validation: body must be exactly 1 byte of I/T/E.
                if body.len() != 1 {
                    return Err(QueryRelayError {
                        source: ProtocolError::Malformed(
                            "ReadyForQuery body length is not 1".into(),
                        ),
                        error_response_relayed,
                    });
                }
                let status = match TransactionStatus::from_byte(body[0]) {
                    Some(s) => s,
                    None => {
                        return Err(QueryRelayError {
                            source: ProtocolError::Malformed(
                                format!("ReadyForQuery invalid status byte: 0x{:02x}", body[0]),
                            ),
                            error_response_relayed,
                        });
                    }
                };
                break status;
            }
            TAG_COMMAND_COMPLETE => {
                // Extract the command tag (C-string in body) for write detection.
                let tag_str = extract_cstring(&body);
                command_tags.push(tag_str.clone());
                if is_write_command_tag(&tag_str) {
                    write_command_tags.push(tag_str);
                }
                // Relay the raw frame to client.
                write_raw_frame(client, TAG_COMMAND_COMPLETE, &body)
                    .await
                    .map_err(|source| QueryRelayError {
                        source,
                        error_response_relayed,
                    })?;
            }
            TAG_PARAMETER_STATUS if options.extension_guc.is_some() => {
                // Check if this is the extension LSN GUC we're watching.
                // Zero-copy: compare the GUC name directly in the raw body
                // bytes (body format is: name\0value\0) without allocating
                // Strings unless we actually need the value.
                let guc = options.extension_guc.unwrap();
                let guc_bytes = guc.as_bytes();
                let is_our_guc = body.len() > guc_bytes.len()
                    && &body[..guc_bytes.len()] == guc_bytes
                    && body[guc_bytes.len()] == 0;
                if is_our_guc {
                    // Extract just the value (after name\0)
                    let value_start = guc_bytes.len() + 1;
                    let value_end = body[value_start..]
                        .iter()
                        .position(|&b| b == 0)
                        .map(|p| value_start + p)
                        .unwrap_or(body.len());
                    let value_str = std::str::from_utf8(&body[value_start..value_end])
                        .unwrap_or("");
                    reported_lsn = crate::health::parse_lsn(value_str);
                    // Suppress this message from the client.
                } else {
                    // Not our GUC — relay raw.
                    write_raw_frame(client, TAG_PARAMETER_STATUS, &body)
                        .await
                        .map_err(|source| QueryRelayError {
                            source,
                            error_response_relayed,
                        })?;
                }
            }
            TAG_ERROR_RESPONSE => {
                error_response_relayed = true;
                write_raw_frame(client, TAG_ERROR_RESPONSE, &body)
                    .await
                    .map_err(|source| QueryRelayError {
                        source,
                        error_response_relayed,
                    })?;
            }
            TAG_COPY_IN_RESPONSE => {
                // COPY ... FROM STDIN: the backend now waits for CopyData
                // from the client, so the proxy must switch to reading the
                // client until the copy stream ends. Without this, both
                // sides block forever (the client waits for CopyInResponse
                // stuck in the proxy's write buffer while the proxy waits
                // for backend messages that will never come).
                write_raw_frame(client, tag, &body)
                    .await
                    .map_err(|source| QueryRelayError {
                        source,
                        error_response_relayed,
                    })?;
                client.flush().await.map_err(|source| QueryRelayError {
                    source: ProtocolError::Io(source),
                    error_response_relayed,
                })?;
                relay_copy_in_stream(backend, client)
                    .await
                    .map_err(|source| QueryRelayError {
                        source,
                        error_response_relayed,
                    })?;
                // Fall through: the backend responds with CommandComplete
                // (or ErrorResponse) and the relay loop continues normally.
            }
            _ => {
                // Zero-copy relay: DataRow, RowDescription, NoticeResponse,
                // and any other message type — forward raw bytes directly.
                write_raw_frame(client, tag, &body)
                    .await
                    .map_err(|source| QueryRelayError {
                        source,
                        error_response_relayed,
                    })?;
            }
        }
    };

    let (pipelined_lsn, connection_reusable) = if options.pipeline_lsn {
        match timeout(options.internal_query_timeout, drain_internal_lsn_query(backend)).await {
            Ok(Ok(lsn)) => (lsn, true),
            Ok(Err(_)) | Err(_) => (None, false),
        }
    } else {
        (None, true)
    };

    Ok(QueryRelayOutcome {
        tx_status,
        write_command_tags,
        command_tags,
        had_error_response: error_response_relayed,
        reported_lsn,
        pipelined_lsn,
        pipeline_attempted: options.pipeline_lsn,
        connection_reusable,
    })
}

/// Relays a client's copy-in data stream (after the backend announced
/// `CopyInResponse`) to the backend, frame by frame, until the client ends
/// the copy with CopyDone (`c`) or CopyFail (`f`). Frames are forwarded as
/// raw bytes with no buffering of the whole stream. Any other message type
/// the client sends mid-copy is also forwarded verbatim: PostgreSQL itself
/// defines the error semantics (Flush/Sync are ignored during copy-in;
/// other types make the backend fail the COPY), so the proxy does not
/// second-guess it.
pub(crate) async fn relay_copy_in_stream<B, C>(
    backend: &mut B,
    client: &mut C,
) -> Result<(), ProtocolError>
where
    B: AsyncWrite + Unpin + Send,
    C: tokio::io::AsyncRead + Unpin + Send,
{
    const TAG_COPY_DONE: u8 = b'c';
    const TAG_COPY_FAIL: u8 = b'f';
    loop {
        let (tag, body) = read_tagged_frame(client).await?;
        write_raw_frame(backend, tag, &body).await?;
        if tag == TAG_COPY_DONE || tag == TAG_COPY_FAIL {
            backend.flush().await.map_err(ProtocolError::Io)?;
            return Ok(());
        }
        backend.flush().await.map_err(ProtocolError::Io)?;
    }
}

/// Writes a raw PostgreSQL wire frame (tag + length-prefix + body) to the
/// client without any intermediate parsing or re-encoding.
#[inline]
async fn write_raw_frame<C: AsyncWrite + Unpin + Send>(
    client: &mut C,
    tag: u8,
    body: &[u8],
) -> Result<(), ProtocolError> {
    let body_len = body.len();
    debug_assert!(
        body_len <= (i32::MAX - 4) as usize,
        "message body exceeds PostgreSQL protocol limit"
    );
    let len = (body_len as i32) + 4;
    let header: [u8; 5] = [
        tag,
        (len >> 24) as u8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
    ];
    // For small messages (≤ 8KB - 5 bytes header), combine header + body
    // into a single write_all call to reduce syscall overhead. The BufWriter
    // layer coalesces further, but avoiding the second write_all eliminates
    // an await point and potential partial flush for messages that fit in a
    // small stack buffer.
    if body.len() <= 8187 {
        let mut buf = Vec::with_capacity(5 + body.len());
        buf.extend_from_slice(&header);
        buf.extend_from_slice(body);
        client.write_all(&buf).await?;
    } else {
        client.write_all(&header).await?;
        client.write_all(body).await?;
    }
    Ok(())
}

/// Extracts the first C-string (null-terminated) from a message body.
/// Returns an empty string if body is empty or has no null terminator.
#[inline]
fn extract_cstring(body: &[u8]) -> String {
    match body.iter().position(|&b| b == 0) {
        Some(pos) => String::from_utf8_lossy(&body[..pos]).into_owned(),
        None => String::from_utf8_lossy(body).into_owned(),
    }
}

async fn drain_internal_lsn_query<B>(
    backend: &mut B,
) -> Result<Option<u64>, ProtocolError>
where
    B: tokio::io::AsyncRead + Unpin + Send,
{
    let mut lsn = None;
    let mut saw_error = false;
    loop {
        match read_backend_message(backend).await? {
            BackendMessage::DataRow(columns) if !saw_error => {
                if let Some(Some(value)) = columns.first() {
                    if let Ok(value) = std::str::from_utf8(value) {
                        lsn = crate::health::parse_lsn(value);
                    }
                }
            }
            BackendMessage::ErrorResponse(_) => saw_error = true,
            BackendMessage::ReadyForQuery(_) => {
                return Ok(if saw_error { None } else { lsn });
            }
            _ => {}
        }
    }
}


/// Issues `SELECT pg_current_wal_lsn()` against the backend (a Writer node)
/// as a follow-up round trip after a write statement completes, and parses
/// the returned LSN text (e.g. `"16/B374D848"`) into a `u64`. Returns `Ok(None)`
/// if the backend reported an error or the result could not be parsed,
/// rather than failing the whole request over a best-effort LSN refresh
/// (Requirement 3.1).
pub async fn fetch_current_wal_lsn<B>(backend: &mut B) -> Result<Option<u64>, ProtocolError>
where
    B: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
{
    let query_bytes = encode_query("SELECT pg_current_wal_lsn()");
    backend.write_all(&query_bytes).await?;
    backend.flush().await?;

    let mut lsn_text: Option<String> = None;
    loop {
        match read_backend_message(backend).await? {
            BackendMessage::DataRow(cols) => {
                if let Some(Some(bytes)) = cols.first() {
                    lsn_text = String::from_utf8(bytes.clone()).ok();
                }
            }
            BackendMessage::ReadyForQuery(_) => break,
            _ => continue,
        }
    }

    Ok(lsn_text.and_then(|text| crate::health::parse_lsn(&text)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::{FieldDescription, FrontendMessage, PgError};
    use crate::session::lsn::InMemoryLsnTracker;
    use proptest::prelude::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_fut = TcpStream::connect(addr);
        let (accept_result, connect_result) = tokio::join!(listener.accept(), connect_fut);
        (accept_result.unwrap().0, connect_result.unwrap())
    }

    // -----------------------------------------------------------------
    // Property 41: extended-query routing target stays consistent after
    // being decided at Parse time.
    // Validates: Requirements 11.3, 11.4
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_41_bind_execute_reuse_parse_time_route(
            statement_name in "[a-z][a-z0-9_]{0,10}",
            node_id in "[a-z][a-z0-9_-]{0,10}",
            lookups in 1usize..10,
        ) {
            let mut tracker = ExtendedQueryRouteTracker::new();
            tracker.record_parse_route(&statement_name, &node_id);

            for _ in 0..lookups {
                let route = tracker.route_for_statement(&statement_name);
                prop_assert_eq!(route, Some(node_id.clone()));
            }
        }

        #[test]
        fn property_41_unknown_statement_has_no_route(name in "[a-z][a-z0-9_]{0,10}") {
            let tracker = ExtendedQueryRouteTracker::new();
            prop_assert_eq!(tracker.route_for_statement(&name), None);
        }

        // -----------------------------------------------------------------
        // Property 42: ReadyForQuery status byte deterministically maps to
        // session transaction state.
        // Validates: Requirements 11.5
        // -----------------------------------------------------------------
        #[test]
        fn property_42_ready_for_query_mapping(
            status in prop_oneof![
                Just(TransactionStatus::Idle),
                Just(TransactionStatus::InTransaction),
                Just(TransactionStatus::Failed),
            ]
        ) {
            let tx_state = apply_ready_for_query(status);
            let expected = match status {
                TransactionStatus::Idle => TxState::Idle,
                TransactionStatus::InTransaction => TxState::InTransaction,
                TransactionStatus::Failed => TxState::Failed,
            };
            prop_assert_eq!(tx_state, expected);
        }
    }

    // -----------------------------------------------------------------
    // Unit tests
    // -----------------------------------------------------------------

    #[test]
    fn forget_statement_removes_recorded_route() {
        let mut tracker = ExtendedQueryRouteTracker::new();
        tracker.record_parse_route("stmt1", "writer");
        assert_eq!(tracker.route_for_statement("stmt1"), Some("writer".to_string()));
        tracker.forget_statement("stmt1");
        assert_eq!(tracker.route_for_statement("stmt1"), None);
    }

    #[test]
    fn re_parsing_a_statement_overwrites_its_route() {
        let mut tracker = ExtendedQueryRouteTracker::new();
        tracker.record_parse_route("stmt1", "writer");
        tracker.record_parse_route("stmt1", "reader-1");
        assert_eq!(tracker.route_for_statement("stmt1"), Some("reader-1".to_string()));
    }

    #[test]
    fn write_command_tags_are_recognized() {
        assert!(is_write_command_tag("INSERT 0 1"));
        assert!(is_write_command_tag("UPDATE 3"));
        assert!(is_write_command_tag("DELETE 1"));
        assert!(is_write_command_tag("COPY 100"));
        assert!(!is_write_command_tag("SELECT 5"));
        assert!(!is_write_command_tag("SHOW"));
    }

    #[test]
    fn maybe_record_write_lsn_only_triggers_on_write_tags() {
        let tracker = InMemoryLsnTracker::new();

        let write_msg = BackendMessage::CommandComplete {
            tag: "INSERT 0 1".to_string(),
        };
        assert!(maybe_record_write_lsn(&write_msg, "s1", 500, &tracker));
        assert_eq!(tracker.session_write_lsn("s1"), 500);

        let read_msg = BackendMessage::CommandComplete {
            tag: "SELECT 3".to_string(),
        };
        assert!(!maybe_record_write_lsn(&read_msg, "s1", 999, &tracker));
        assert_eq!(tracker.session_write_lsn("s1"), 500); // unchanged
    }

    // -----------------------------------------------------------------
    // forward_simple_query: streams RowDescription/DataRow/CommandComplete
    // to the client and stops at (without relaying) ReadyForQuery.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn forward_simple_query_relays_result_set_and_stops_before_ready_for_query() {
        // Two independent TCP pairs: one simulates the backend connection
        // (`backend_conn` is what `forward_simple_query` writes/reads
        // through), the other simulates the client connection
        // (`client_conn` is the `client` sink passed to
        // `forward_simple_query`; `client_observer` is used by the test to
        // read back what was relayed to the "client").
        let (mut backend_conn, mut fake_backend) = connected_pair().await;
        let (mut client_conn, mut client_observer) = connected_pair().await;

        let backend_task = tokio::spawn(async move {
            // Drain the incoming simple-query Query message sent by
            // forward_simple_query.
            let _query = crate::protocol::reader::read_frontend_message(&mut fake_backend)
                .await
                .unwrap();

            let row_desc = encode_backend_message(&BackendMessage::RowDescription(vec![FieldDescription {
                name: "col1".to_string(),
                table_oid: 0,
                column_attr_num: 1,
                type_oid: 23,
                type_size: 4,
                type_modifier: -1,
                format_code: 0,
            }]));
            fake_backend.write_all(&row_desc).await.unwrap();

            let data_row = encode_backend_message(&BackendMessage::DataRow(vec![Some(b"42".to_vec())]));
            fake_backend.write_all(&data_row).await.unwrap();

            let complete = encode_backend_message(&BackendMessage::CommandComplete {
                tag: "SELECT 1".to_string(),
            });
            fake_backend.write_all(&complete).await.unwrap();

            let ready = encode_backend_message(&BackendMessage::ReadyForQuery(TransactionStatus::Idle));
            fake_backend.write_all(&ready).await.unwrap();
        });

        let outcome = forward_simple_query(&mut backend_conn, &mut client_conn, "SELECT 42")
            .await
            .unwrap();
        backend_task.await.unwrap();

        assert_eq!(outcome.tx_status, TransactionStatus::Idle);
        assert!(outcome.write_command_tags.is_empty());

        // The client side should have received RowDescription, DataRow,
        // and CommandComplete -- but NOT ReadyForQuery (the caller sends
        // its own).
        let msg1 = read_backend_message(&mut client_observer).await.unwrap();
        assert!(matches!(msg1, BackendMessage::RowDescription(_)));
        let msg2 = read_backend_message(&mut client_observer).await.unwrap();
        assert_eq!(msg2, BackendMessage::DataRow(vec![Some(b"42".to_vec())]));
        let msg3 = read_backend_message(&mut client_observer).await.unwrap();
        assert_eq!(
            msg3,
            BackendMessage::CommandComplete {
                tag: "SELECT 1".to_string()
            }
        );

        // Confirm nothing further (specifically not ReadyForQuery) was sent
        // by closing the write half and checking for EOF.
        drop(client_conn);
        let mut buf = [0u8; 16];
        let n = client_observer.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "no further bytes (e.g. ReadyForQuery) should have been relayed");
    }

    #[tokio::test]
    async fn forward_simple_query_relays_copy_in_stream() {
        let (mut backend_conn, mut fake_backend) = connected_pair().await;
        let (mut client_conn, mut client_remote) = connected_pair().await;

        fn raw_frame(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut f = vec![tag];
            f.extend_from_slice(&((body.len() as u32 + 4).to_be_bytes()));
            f.extend_from_slice(body);
            f
        }

        let backend_task = tokio::spawn(async move {
            let _query = crate::protocol::reader::read_frontend_message(&mut fake_backend)
                .await
                .unwrap();

            // CopyInResponse: overall format 0 (text), 2 columns, both text.
            let copy_in_body = [0u8, 0, 2, 0, 0, 0, 0];
            fake_backend
                .write_all(&raw_frame(b'G', &copy_in_body))
                .await
                .unwrap();

            // Expect two CopyData frames then CopyDone from the proxy.
            let mut copy_rows = Vec::new();
            loop {
                let (tag, body) =
                    crate::protocol::reader::read_tagged_frame(&mut fake_backend)
                        .await
                        .unwrap();
                match tag {
                    b'd' => copy_rows.push(body),
                    b'c' => break,
                    other => panic!("unexpected frame during copy-in: {other:#x}"),
                }
            }
            assert_eq!(copy_rows, vec![b"1\tfoo\n".to_vec(), b"2\tbar\n".to_vec()]);

            let complete = encode_backend_message(&BackendMessage::CommandComplete {
                tag: "COPY 2".to_string(),
            });
            fake_backend.write_all(&complete).await.unwrap();
            let ready =
                encode_backend_message(&BackendMessage::ReadyForQuery(TransactionStatus::Idle));
            fake_backend.write_all(&ready).await.unwrap();
        });

        // The "driver" side: waits for CopyInResponse, streams rows, ends
        // the copy, then reads CommandComplete.
        let client_task = tokio::spawn(async move {
            let (tag, _body) = crate::protocol::reader::read_tagged_frame(&mut client_remote)
                .await
                .unwrap();
            assert_eq!(tag, b'G', "client must receive CopyInResponse");

            client_remote
                .write_all(&raw_frame(b'd', b"1\tfoo\n"))
                .await
                .unwrap();
            client_remote
                .write_all(&raw_frame(b'd', b"2\tbar\n"))
                .await
                .unwrap();
            client_remote.write_all(&raw_frame(b'c', &[])).await.unwrap();

            let msg = read_backend_message(&mut client_remote).await.unwrap();
            assert_eq!(
                msg,
                BackendMessage::CommandComplete {
                    tag: "COPY 2".to_string()
                }
            );
        });

        let outcome =
            forward_simple_query(&mut backend_conn, &mut client_conn, "COPY t FROM STDIN")
                .await
                .unwrap();
        backend_task.await.unwrap();
        client_task.await.unwrap();

        assert_eq!(outcome.tx_status, TransactionStatus::Idle);
        // COPY is a write: the command tag must be tracked for LSN purposes.
        assert_eq!(outcome.write_command_tags, vec!["COPY 2".to_string()]);
        assert!(!outcome.had_error_response);
    }

    #[tokio::test]
    async fn forward_simple_query_tracks_write_command_tags() {
        let (mut backend_conn, mut fake_backend) = connected_pair().await;
        let (mut client_conn, _client_observer) = connected_pair().await;

        let backend_task = tokio::spawn(async move {
            let _query = crate::protocol::reader::read_frontend_message(&mut fake_backend)
                .await
                .unwrap();

            let complete = encode_backend_message(&BackendMessage::CommandComplete {
                tag: "INSERT 0 1".to_string(),
            });
            fake_backend.write_all(&complete).await.unwrap();

            let ready = encode_backend_message(&BackendMessage::ReadyForQuery(TransactionStatus::Idle));
            fake_backend.write_all(&ready).await.unwrap();
        });

        let outcome = forward_simple_query(&mut backend_conn, &mut client_conn, "INSERT INTO t VALUES (1)")
            .await
            .unwrap();
        backend_task.await.unwrap();

        assert_eq!(outcome.write_command_tags, vec!["INSERT 0 1".to_string()]);
    }

    #[tokio::test]
    async fn forward_simple_query_relays_error_response() {
        let (mut backend_conn, mut fake_backend) = connected_pair().await;
        let (mut client_conn, mut client_observer) = connected_pair().await;

        let backend_task = tokio::spawn(async move {
            let _query = crate::protocol::reader::read_frontend_message(&mut fake_backend)
                .await
                .unwrap();

            let error = encode_backend_message(&BackendMessage::ErrorResponse(PgError::simple(
                "ERROR",
                "42601",
                "syntax error",
            )));
            fake_backend.write_all(&error).await.unwrap();

            let ready = encode_backend_message(&BackendMessage::ReadyForQuery(TransactionStatus::Failed));
            fake_backend.write_all(&ready).await.unwrap();
        });

        let outcome = forward_simple_query(&mut backend_conn, &mut client_conn, "SELECT invalid")
            .await
            .unwrap();
        backend_task.await.unwrap();

        assert_eq!(outcome.tx_status, TransactionStatus::Failed);

        let relayed = read_backend_message(&mut client_observer).await.unwrap();
        match relayed {
            BackendMessage::ErrorResponse(err) => {
                assert_eq!(err.sqlstate(), Some("42601"));
            }
            other => panic!("expected ErrorResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_failure_records_when_backend_error_was_already_sent() {
        let (mut backend_conn, mut fake_backend) = connected_pair().await;
        let (mut client_conn, mut client_observer) = connected_pair().await;

        let backend_task = tokio::spawn(async move {
            let _query = crate::protocol::reader::read_frontend_message(&mut fake_backend)
                .await
                .unwrap();
            let error = encode_backend_message(&BackendMessage::ErrorResponse(PgError::simple(
                "ERROR",
                "42601",
                "syntax error",
            )));
            fake_backend.write_all(&error).await.unwrap();
            // Invalid frame length while the relay is waiting for the final
            // ReadyForQuery.
            fake_backend.write_all(&[b'Z', 0, 0, 0, 3]).await.unwrap();
        });

        let failure = forward_simple_query(&mut backend_conn, &mut client_conn, "SELECT invalid")
            .await
            .unwrap_err();
        backend_task.await.unwrap();
        assert!(failure.error_response_relayed);
        assert!(matches!(failure.source, ProtocolError::InvalidLength(3)));

        let relayed = read_backend_message(&mut client_observer).await.unwrap();
        assert!(matches!(relayed, BackendMessage::ErrorResponse(_)));
    }

    #[tokio::test]
    async fn pipelined_lsn_uses_two_query_frames_and_hides_internal_cycle() {
        let (mut backend_conn, mut fake_backend) = connected_pair().await;
        let (mut client_conn, mut client_observer) = connected_pair().await;

        let backend_task = tokio::spawn(async move {
            let first = crate::protocol::reader::read_frontend_message(&mut fake_backend)
                .await
                .unwrap();
            let second = crate::protocol::reader::read_frontend_message(&mut fake_backend)
                .await
                .unwrap();
            assert_eq!(
                first,
                FrontendMessage::Query("INSERT INTO t VALUES (1)".to_string())
            );
            assert_eq!(
                second,
                FrontendMessage::Query("SELECT pg_current_wal_lsn()".to_string())
            );

            for message in [
                BackendMessage::CommandComplete {
                    tag: "INSERT 0 1".to_string(),
                },
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
                BackendMessage::DataRow(vec![Some(b"16/B374D848".to_vec())]),
                BackendMessage::CommandComplete {
                    tag: "SELECT 1".to_string(),
                },
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ] {
                fake_backend
                    .write_all(&encode_backend_message(&message))
                    .await
                    .unwrap();
            }
        });

        let outcome = forward_simple_query_with_options(
            &mut backend_conn,
            &mut client_conn,
            "INSERT INTO t VALUES (1)",
            QueryForwardOptions {
                pipeline_lsn: true,
                ..QueryForwardOptions::default()
            },
        )
        .await
        .unwrap();
        backend_task.await.unwrap();

        assert!(outcome.pipeline_attempted);
        assert!(outcome.connection_reusable);
        assert_eq!(outcome.pipelined_lsn, Some((0x16u64 << 32) | 0xB374D848));
        assert_eq!(
            read_backend_message(&mut client_observer).await.unwrap(),
            BackendMessage::CommandComplete {
                tag: "INSERT 0 1".to_string()
            }
        );
        drop(client_conn);
        let mut byte = [0u8; 1];
        assert_eq!(client_observer.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn extension_parameter_status_is_captured_and_not_relayed() {
        let (mut backend_conn, mut fake_backend) = connected_pair().await;
        let (mut client_conn, mut client_observer) = connected_pair().await;

        let backend_task = tokio::spawn(async move {
            let _ = crate::protocol::reader::read_frontend_message(&mut fake_backend)
                .await
                .unwrap();
            for message in [
                BackendMessage::CommandComplete {
                    tag: "INSERT 0 1".to_string(),
                },
                BackendMessage::ParameterStatus {
                    name: "lsn_tracker.last_lsn".to_string(),
                    value: "16/B374D848".to_string(),
                },
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ] {
                fake_backend
                    .write_all(&encode_backend_message(&message))
                    .await
                    .unwrap();
            }
        });

        let outcome = forward_simple_query_with_options(
            &mut backend_conn,
            &mut client_conn,
            "INSERT INTO t VALUES (1)",
            QueryForwardOptions {
                extension_guc: Some("lsn_tracker.last_lsn"),
                ..QueryForwardOptions::default()
            },
        )
        .await
        .unwrap();
        backend_task.await.unwrap();

        assert_eq!(outcome.reported_lsn, Some((0x16u64 << 32) | 0xB374D848));
        assert_eq!(
            read_backend_message(&mut client_observer).await.unwrap(),
            BackendMessage::CommandComplete {
                tag: "INSERT 0 1".to_string()
            }
        );
        drop(client_conn);
        let mut byte = [0u8; 1];
        assert_eq!(client_observer.read(&mut byte).await.unwrap(), 0);
    }

    // -----------------------------------------------------------------
    // fetch_current_wal_lsn
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn fetch_current_wal_lsn_parses_backend_response() {
        let (mut backend_conn, mut fake_backend) = connected_pair().await;

        let backend_task = tokio::spawn(async move {
            let _query = crate::protocol::reader::read_frontend_message(&mut fake_backend)
                .await
                .unwrap();

            let data_row =
                encode_backend_message(&BackendMessage::DataRow(vec![Some(b"16/B374D848".to_vec())]));
            fake_backend.write_all(&data_row).await.unwrap();

            let complete = encode_backend_message(&BackendMessage::CommandComplete {
                tag: "SELECT 1".to_string(),
            });
            fake_backend.write_all(&complete).await.unwrap();

            let ready = encode_backend_message(&BackendMessage::ReadyForQuery(TransactionStatus::Idle));
            fake_backend.write_all(&ready).await.unwrap();
        });

        let lsn = fetch_current_wal_lsn(&mut backend_conn).await.unwrap();
        backend_task.await.unwrap();

        assert_eq!(lsn, Some((0x16u64 << 32) | 0xB374D848));
    }

    #[tokio::test]
    async fn fetch_current_wal_lsn_returns_none_on_backend_error() {
        let (mut backend_conn, mut fake_backend) = connected_pair().await;

        let backend_task = tokio::spawn(async move {
            let _query = crate::protocol::reader::read_frontend_message(&mut fake_backend)
                .await
                .unwrap();

            let error = encode_backend_message(&BackendMessage::ErrorResponse(PgError::simple(
                "ERROR",
                "58000",
                "backend unavailable",
            )));
            fake_backend.write_all(&error).await.unwrap();

            let ready = encode_backend_message(&BackendMessage::ReadyForQuery(TransactionStatus::Idle));
            fake_backend.write_all(&ready).await.unwrap();
        });

        let lsn = fetch_current_wal_lsn(&mut backend_conn).await.unwrap();
        backend_task.await.unwrap();

        assert_eq!(lsn, None);
    }
}
