//! Free helper functions used across the handler submodules.
//!
//! Extracted from the monolithic `handler.rs` to improve compile-time
//! incremental boundaries and make the module easier to navigate.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::config::ConsistencyLevel;
use crate::parser::classifier::{
    contains_multiple_statements, multi_statement_all_readable, requires_writer, Classifier,
    KeywordClassifier,
};
use crate::pool::conn::BackendConnection;
use crate::pool::manager::PoolManager;
use crate::protocol::message::{BackendMessage, PgError, TransactionStatus};
use crate::protocol::reader::frontend_tag;
use crate::protocol::startup::AuthOutcome;
use crate::protocol::writer::encode_backend_message;
use crate::protocol::ProtocolError;
use crate::proxy::error::{proxy_error_to_pg_error, ProxyError};
use crate::proxy::forwarder::{apply_ready_for_query, forward_simple_query};
use crate::session::session::TxState;
use crate::session::transaction::{parse_begin_options, transaction_end_tag};

use super::{cstr_at, ClientSession, ExtendedFrame};

// ---------------------------------------------------------------------------
// Body parsing helpers
// ---------------------------------------------------------------------------

/// Extracts a null-terminated C-string from a raw message body.
pub(super) fn extract_cstring_from_body(body: &[u8]) -> String {
    let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    String::from_utf8_lossy(&body[..end]).into_owned()
}

/// Extracts two consecutive C-strings from a ParameterStatus message body.
pub(super) fn extract_two_cstrings_from_body(body: &[u8]) -> (String, String) {
    let first_end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    let first = String::from_utf8_lossy(&body[..first_end]).into_owned();
    let rest = if first_end + 1 < body.len() {
        &body[first_end + 1..]
    } else {
        &[]
    };
    let second_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let second = String::from_utf8_lossy(&rest[..second_end]).into_owned();
    (first, second)
}

// ---------------------------------------------------------------------------
// Extended query frame helpers
// ---------------------------------------------------------------------------

/// True when the frame is a Parse ('P') that creates a *named* statement.
pub(super) fn frame_is_named_parse(frame: &ExtendedFrame) -> bool {
    frame.tag == frontend_tag::PARSE && frame.body.first().is_some_and(|&b| b != 0)
}

/// Concatenates buffered extended-query frames plus a trailing Sync.
pub(super) fn assemble_extended_outbound(batch: &[ExtendedFrame]) -> Vec<u8> {
    const SYNC_FRAME: [u8; 5] = [b'S', 0, 0, 0, 4];
    let total: usize = batch.iter().map(|f| 5 + f.body.len()).sum::<usize>() + SYNC_FRAME.len();
    let mut outbound = Vec::with_capacity(total);
    for frame in batch {
        let len = (frame.body.len() as u32 + 4).to_be_bytes();
        outbound.push(frame.tag);
        outbound.extend_from_slice(&len);
        outbound.extend_from_slice(&frame.body);
    }
    outbound.extend_from_slice(&SYNC_FRAME);
    outbound
}

/// Computes the response interleaving schedule for mixed batches where some
/// frames are handled locally (skipped) and some are forwarded to the backend.
///
/// Returns a `Vec` indexed by "forwarded frame position" (0-based). Each
/// entry contains the synthetic response bytes that must be emitted *before*
/// relaying the response for that forwarded frame. An additional trailing
/// element holds synthetics that come after ALL forwarded frames.
///
/// The length of the returned Vec is `forwarded_count + 1`.
pub(super) fn compute_synthetic_schedule(batch: &[ExtendedFrame], skip: &[usize]) -> Vec<Vec<u8>> {
    // Count forwarded frames.
    let forwarded_count = batch.len() - skip.len();
    // We need forwarded_count + 1 slots: slot[k] = "emit before k-th forwarded
    // frame's response", slot[forwarded_count] = "emit after all forwarded".
    let mut schedule: Vec<Vec<u8>> = vec![Vec::new(); forwarded_count + 1];

    // Walk original batch in order, tracking which forwarded position we're at.
    let mut forwarded_pos: usize = 0;
    for (i, frame) in batch.iter().enumerate() {
        if skip.contains(&i) {
            // This frame is skipped → generate synthetic response bytes and
            // place them in the current forwarded_pos slot (i.e. "before the
            // next forwarded frame's response").
            let synthetic = match frame.tag {
                tag if tag == frontend_tag::PARSE => {
                    // ParseComplete
                    vec![b'1', 0, 0, 0, 4]
                }
                tag if tag == frontend_tag::BIND => {
                    // BindComplete
                    vec![b'2', 0, 0, 0, 4]
                }
                tag if tag == frontend_tag::EXECUTE => {
                    // CommandComplete "SET"
                    crate::protocol::writer::encode_backend_message(
                        &crate::protocol::message::BackendMessage::CommandComplete {
                            tag: "SET".to_string(),
                        },
                    )
                }
                tag if tag == frontend_tag::DESCRIBE => {
                    // Describe for a virtual SET object:
                    // Describe(S): ParameterDescription (0 params) + NoData
                    // Describe(P): NoData
                    let mut bytes = Vec::new();
                    if let Some((kind, _)) = frame.kind_and_name() {
                        if kind == b'S' {
                            // ParameterDescription: tag 't', len 6, 0 params
                            bytes.extend_from_slice(&[b't', 0, 0, 0, 6, 0, 0]);
                        }
                    }
                    // NoData
                    bytes.extend_from_slice(&[b'n', 0, 0, 0, 4]);
                    bytes
                }
                tag if tag == frontend_tag::CLOSE => {
                    // CloseComplete
                    vec![b'3', 0, 0, 0, 4]
                }
                _ => Vec::new(),
            };
            if !synthetic.is_empty() {
                schedule[forwarded_pos].extend_from_slice(&synthetic);
            }
        } else {
            forwarded_pos += 1;
        }
    }

    schedule
}

/// Like `assemble_extended_outbound` but skips frames at the specified indices.
pub(super) fn assemble_extended_outbound_filtered(batch: &[ExtendedFrame], skip: &[usize]) -> Vec<u8> {
    const SYNC_FRAME: [u8; 5] = [b'S', 0, 0, 0, 4];
    let total: usize = batch.iter().enumerate()
        .filter(|(i, _)| !skip.contains(i))
        .map(|(_, f)| 5 + f.body.len())
        .sum::<usize>() + SYNC_FRAME.len();
    let mut outbound = Vec::with_capacity(total);
    for (i, frame) in batch.iter().enumerate() {
        if skip.contains(&i) {
            continue;
        }
        let len = (frame.body.len() as u32 + 4).to_be_bytes();
        outbound.push(frame.tag);
        outbound.extend_from_slice(&len);
        outbound.extend_from_slice(&frame.body);
    }
    outbound.extend_from_slice(&SYNC_FRAME);
    outbound
}

/// Records named-statement routes and forgets closed ones.
/// `skip_indices` are frames that were handled locally (e.g. local SET)
/// and never forwarded to the backend — recording routes for these would
/// create phantom statement references on nodes that never received Parse.
pub(super) fn record_statement_routes(
    session: &mut ClientSession,
    batch: &[ExtendedFrame],
    node_id: &str,
    skip_indices: &[usize],
) {
    use crate::parser::classifier::{Classifier, KeywordClassifier};
    let classifier = KeywordClassifier;
    for (i, frame) in batch.iter().enumerate() {
        if skip_indices.contains(&i) {
            continue;
        }
        match frame.tag {
            frontend_tag::PARSE => match frame.parse_name() {
                Some(name) if !name.is_empty() => {
                    session
                        .extended_route_tracker
                        .record_parse_route(name, node_id);
                    // FIX: Track whether this statement's SQL contains
                    // write function calls (setval, lo_create, etc.) so
                    // cross-Sync Execute-only batches can correctly seed
                    // write_detected even when CommandComplete is "SELECT".
                    if let Some(sql) = frame.parse_sql() {
                        if classifier.has_write_function_call(sql) {
                            session.write_function_stmts.insert(name.to_string());
                        } else {
                            session.write_function_stmts.remove(name);
                        }
                    }
                }
                Some(_) => {
                    session.extended_route_tracker.forget_statement("");
                }
                None => {}
            },
            frontend_tag::CLOSE => {
                if let Some((kind, name)) = frame.kind_and_name() {
                    match kind {
                        b'S' => {
                            if !name.is_empty() {
                                session.extended_route_tracker.forget_statement(name);
                                // FIX (Bug 4): Clean up virtual prepared statement
                                // caches when a statement is explicitly closed.
                                session.state.prepared_stmts.remove(name);
                                session.local_set_stmts.remove(name);
                                session.write_function_stmts.remove(name);
                            } else {
                                session.unnamed_parse_node = None;
                            }
                        }
                        b'P' => {
                            // Clean up virtual portal cache for local SET portals.
                            session.local_set_portals.remove(name);
                            session.write_function_portals.remove(name);
                        }
                        _ => {}
                    }
                }
            }
            frontend_tag::BIND => {
                // Track portals bound to write-function statements so
                // Execute-only batches can seed write_detected correctly.
                if let Some(stmt_name) = frame.bind_statement() {
                    if let Some(portal_name) = frame.bind_portal() {
                        if session.write_function_stmts.contains(stmt_name) {
                            session.write_function_portals.insert(portal_name.to_string());
                        } else {
                            // Rebinding a portal to a non-write stmt clears it.
                            session.write_function_portals.remove(portal_name);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Tracks unnamed Parse/Bind for cross-Sync routing.
pub(super) fn update_unnamed_parse_tracking(
    session: &mut ClientSession,
    batch: &[ExtendedFrame],
    node_id: &str,
) {
    let has_unnamed_parse = batch.iter().any(|frame| {
        frame.tag == frontend_tag::PARSE && frame.body.first().is_some_and(|&b| b == 0)
    });
    let has_unnamed_bind = batch.iter().any(|frame| {
        frame.tag == frontend_tag::BIND && {
            if let Some((_, next)) = cstr_at(&frame.body, 0) {
                frame.body.get(next) == Some(&0)
            } else {
                false
            }
        }
    });

    if has_unnamed_parse {
        if has_unnamed_bind {
            session.unnamed_parse_node = None;
        } else {
            session.unnamed_parse_node = Some(node_id.to_string());
        }
    } else if has_unnamed_bind {
        session.unnamed_parse_node = None;
    }
}

// ---------------------------------------------------------------------------
// Wire protocol writing
// ---------------------------------------------------------------------------

/// Writes a raw PostgreSQL wire frame to the client stream.
pub(super) async fn write_raw_frame_to<S: AsyncWrite + Unpin + Send>(
    client: &mut S,
    tag: u8,
    body: &[u8],
) -> Result<(), ProxyError> {
    let len = (body.len() as i32) + 4;
    let header: [u8; 5] = [
        tag,
        (len >> 24) as u8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
    ];
    if body.len() <= 8187 {
        let mut buf = Vec::with_capacity(5 + body.len());
        buf.extend_from_slice(&header);
        buf.extend_from_slice(body);
        client.write_all(&buf).await.map_err(ProtocolError::Io)?;
    } else {
        client.write_all(&header).await.map_err(ProtocolError::Io)?;
        client.write_all(body).await.map_err(ProtocolError::Io)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Query classification
// ---------------------------------------------------------------------------

pub(super) fn query_has_write_intent(sql: &str) -> bool {
    if sql.trim().is_empty()
        || parse_begin_options(sql).is_some()
        || transaction_end_tag(sql).is_some()
    {
        return false;
    }
    if contains_multiple_statements(sql) {
        return !multi_statement_all_readable(&KeywordClassifier, sql);
    }

    let classifier = KeywordClassifier;
    let kind = classifier.classify(sql);
    requires_writer(&classifier, sql) || !kind.readable()
}

pub(super) fn pipeline_safe_sql(sql: &str) -> bool {
    if contains_multiple_statements(sql) {
        return false;
    }
    let normalized = sql
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase();
    !normalized.contains("COPY ")
        && !normalized.starts_with("COPY")
        && !normalized.contains(" AND CHAIN")
        && !normalized.contains(" AND NO CHAIN")
}

// ---------------------------------------------------------------------------
// Miscellaneous
// ---------------------------------------------------------------------------

pub(super) fn sanitize_application_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_alphanumeric() || " _-.:@[]()/#".contains(*c))
        .take(128)
        .collect()
}

pub(super) fn aurora_consistency_sql(consistency: ConsistencyLevel) -> String {
    let value = match consistency {
        ConsistencyLevel::Eventual => "EVENTUAL",
        ConsistencyLevel::Session => "SESSION",
        ConsistencyLevel::Global => "GLOBAL",
    };
    format!("SET apg_write_forward.consistency_mode = '{value}'")
}

pub(super) fn known_node_ids(pool_manager: &impl PoolManager) -> Vec<String> {
    pool_manager
        .snapshot()
        .into_iter()
        .map(|n| n.node_id)
        .collect()
}

pub(super) fn transaction_status_for_state(state: TxState) -> TransactionStatus {
    match state {
        TxState::Idle => TransactionStatus::Idle,
        TxState::InTransaction => TransactionStatus::InTransaction,
        TxState::Failed => TransactionStatus::Failed,
    }
}

pub(super) async fn ensure_application_name(
    conn: &mut BackendConnection,
    desired: &str,
    expected_status: TransactionStatus,
) -> Result<(), ProtocolError> {
    if desired.is_empty() || conn.current_application_name.as_deref() == Some(desired) {
        return Ok(());
    }

    let sql = format!("SET application_name = '{}'", desired.replace('\'', "''"));
    let mut sink = tokio::io::join(tokio::io::empty(), tokio::io::sink());
    let outcome = forward_simple_query(&mut conn.stream, &mut sink, &sql)
        .await
        .map_err(|failure| failure.source)?;
    if outcome.had_error_response {
        return Err(ProtocolError::Malformed(
            "SET application_name returned an ErrorResponse".into(),
        ));
    }
    if outcome.tx_status != expected_status {
        return Err(ProtocolError::Malformed(format!(
            "SET application_name ended with transaction status {:?}, expected {:?}",
            outcome.tx_status, expected_status
        )));
    }
    conn.current_application_name = Some(desired.to_string());
    Ok(())
}

pub(super) async fn execute_internal_query(
    backend: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    sql: &str,
    expected_status: TransactionStatus,
) -> Result<(), ProtocolError> {
    let mut sink = tokio::io::join(tokio::io::empty(), tokio::io::sink());
    let outcome = forward_simple_query(backend, &mut sink, sql)
        .await
        .map_err(|failure| failure.source)?;
    if outcome.had_error_response {
        return Err(ProtocolError::Malformed(format!(
            "internal command {sql:?} returned an ErrorResponse"
        )));
    }
    if outcome.tx_status != expected_status {
        return Err(ProtocolError::Malformed(format!(
            "internal command {sql:?} ended with transaction status {:?}, expected {:?}",
            outcome.tx_status, expected_status
        )));
    }
    Ok(())
}

pub(super) async fn send_command_complete<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    tag: &str,
) -> Result<(), ProxyError> {
    let bytes = encode_backend_message(&BackendMessage::CommandComplete {
        tag: tag.to_string(),
    });
    stream.write_all(&bytes).await.map_err(ProtocolError::Io)?;
    Ok(())
}

pub(super) async fn send_startup_success<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    outcome: &AuthOutcome,
) -> Result<(), ProxyError> {
    let auth_ok = encode_backend_message(&BackendMessage::AuthenticationOk);
    stream
        .write_all(&auth_ok)
        .await
        .map_err(ProtocolError::Io)?;

    for (name, value) in [
        ("server_version", "16.0"),
        ("server_encoding", "UTF8"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("integer_datetimes", "on"),
        ("standard_conforming_strings", "on"),
    ] {
        let parameter = encode_backend_message(&BackendMessage::ParameterStatus {
            name: name.to_string(),
            value: value.to_string(),
        });
        stream
            .write_all(&parameter)
            .await
            .map_err(ProtocolError::Io)?;
    }

    let key_data = encode_backend_message(&BackendMessage::BackendKeyData {
        pid: outcome.backend_pid,
        secret_key: outcome.secret_key,
    });
    stream
        .write_all(&key_data)
        .await
        .map_err(ProtocolError::Io)?;

    send_ready_for_query(stream, TxState::Idle).await
}

pub(super) async fn send_ready_for_query<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    tx_state: TxState,
) -> Result<(), ProxyError> {
    static RFQ_IDLE: [u8; 6] = [b'Z', 0, 0, 0, 5, b'I'];
    static RFQ_IN_TX: [u8; 6] = [b'Z', 0, 0, 0, 5, b'T'];
    static RFQ_FAILED: [u8; 6] = [b'Z', 0, 0, 0, 5, b'E'];
    let bytes = match tx_state {
        TxState::Idle => &RFQ_IDLE,
        TxState::InTransaction => &RFQ_IN_TX,
        TxState::Failed => &RFQ_FAILED,
    };
    stream.write_all(bytes).await.map_err(ProtocolError::Io)?;
    Ok(())
}

pub(super) async fn send_pg_error_response<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    error: PgError,
) -> Result<(), ProxyError> {
    let bytes = encode_backend_message(&BackendMessage::ErrorResponse(error));
    stream.write_all(&bytes).await.map_err(ProtocolError::Io)?;
    Ok(())
}

pub(super) async fn send_error_response<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    err: &ProxyError,
) -> Result<(), ProxyError> {
    send_pg_error_response(stream, proxy_error_to_pg_error(err)).await
}

#[allow(dead_code)]
pub(super) fn tx_state_from_ready_for_query(status: TransactionStatus) -> TxState {
    apply_ready_for_query(status)
}
