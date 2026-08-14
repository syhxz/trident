//! Extended query protocol handling.
//!
//! Contains `handle_extended_query_batch` and `forward_extended_on_held_backend`,
//! which process Parse/Bind/Execute/Sync message batches.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::config::{ConsistencyLevel, LsnTrackingMode, NodeType};
use crate::parser::classifier::{requires_writer, Classifier, KeywordClassifier};
use crate::pool::pinning::detects_pinning_trigger;
use crate::protocol::message::{PgError, TransactionStatus};
use crate::protocol::reader::{frontend_tag, read_tagged_frame};
use crate::protocol::ProtocolError;
use crate::proxy::error::ProxyError;
use crate::proxy::forwarder::{
    apply_ready_for_query, is_write_command_tag, relay_copy_in_stream_with_timeout,
};
use crate::router::router::RoutingContext;
use crate::session::session::TxState;

use super::helpers::{
    assemble_extended_outbound, aurora_consistency_sql, ensure_application_name,
    execute_internal_query, extract_cstring_from_body, extract_two_cstrings_from_body,
    frame_is_named_parse, record_statement_routes, send_pg_error_response, send_ready_for_query,
    transaction_status_for_state, update_unnamed_parse_tracking, write_raw_frame_to,
};
use super::{ClientSession, ConnectionHandler, ExtendedFrame, HeldBackend, OwnedConn, RouteFn};
use crate::pool::manager::PoolManager;
use crate::session::lsn::LsnTracker;

impl<'a, RTR, PM, LSN> ConnectionHandler<'a, RTR, PM, LSN>
where
    RTR: RouteFn,
    PM: PoolManager,
    LSN: LsnTracker,
{
    /// Handles a batch of extended query protocol messages collected between
    /// two Sync boundaries. The batch is forwarded as a unit to a single
    /// backend (chosen based on SQL classification of the first Parse in the
    /// batch, or the session's held backend if inside a transaction).
    ///
    /// The Sync message itself is appended by this function; responses are
    /// relayed back until `ReadyForQuery`.
    pub(super) async fn handle_extended_query_batch<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        batch: &[ExtendedFrame],
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Preserve PostgreSQL's failed-transaction semantics: with the
        // physical connection already lost, the batch must not run as
        // autocommit on a fresh connection. Match the Simple Query path.
        //
        // FIX (Bug 2): Allow ROLLBACK/COMMIT through to reset the Failed
        // state, matching the Simple Query path's recovery logic.
        //  (a) Verify Bind references the same statement name as the Parse
        //      that contains the COMMIT/ROLLBACK SQL.
        //  (b) COMMIT in Failed state must report as ROLLBACK (PostgreSQL
        //      semantics: COMMIT inside a failed transaction rolls back).
        //  (c) Support cross-Sync: when no Parse is in the batch but Bind
        //      references a previously prepared COMMIT/ROLLBACK statement,
        //      use `prepared_stmts` cache to resolve the SQL.
        if session.state.tx_state == TxState::Failed && session.held_backend.is_none() {
            // Step 0: Check for Execute-only batch referencing a previously
            // bound virtual portal (cross-Sync Execute after Parse+Bind).
            let execute_only_match = if !batch.iter().any(|f| f.tag == frontend_tag::PARSE)
                && !batch.iter().any(|f| f.tag == frontend_tag::BIND)
            {
                batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::EXECUTE)
                    .find_map(|f| {
                        f.execute_portal().and_then(|p| {
                            session
                                .failed_state_portals
                                .get(p)
                                .copied()
                                .map(|tag| (p.to_string(), tag))
                        })
                    })
            } else {
                None
            };

            if let Some((virtual_portal_name, tag)) = execute_only_match {
                // Execute-only batch for a virtual COMMIT/ROLLBACK portal.
                let effective_tag = if tag == "COMMIT" { "ROLLBACK" } else { tag };
                session.state.tx_state = TxState::Idle;
                session.state.tx_split = None;
                session.tx_has_writes = false;
                session.failed_state_portals.clear();

                // FIX (Bug 4): Process ALL frames in the batch, not just the
                // first matching Execute. In Failed state, non-txn-end frames
                // should receive ErrorResponse (25P02). The virtual portal
                // Execute gets CommandComplete.
                for frame in batch.iter() {
                    match frame.tag {
                        tag_byte if tag_byte == frontend_tag::EXECUTE => {
                            let is_virtual = frame
                                .execute_portal()
                                .is_some_and(|p| p == virtual_portal_name);
                            if is_virtual {
                                let cmd = crate::protocol::writer::encode_backend_message(
                                    &crate::protocol::message::BackendMessage::CommandComplete {
                                        tag: effective_tag.to_string(),
                                    },
                                );
                                client_stream
                                    .write_all(&cmd)
                                    .await
                                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                            } else {
                                // Other Executes in same batch were in Failed
                                // state — they would have been rejected.
                                let error = PgError::simple(
                                    "ERROR",
                                    "25P02",
                                    "current transaction is aborted, commands ignored until end of transaction block",
                                );
                                send_pg_error_response(client_stream, error).await?;
                            }
                        }
                        tag_byte if tag_byte == frontend_tag::DESCRIBE => {
                            // Describe in Execute-only batch (no Parse/Bind):
                            // would have gotten 25P02 in Failed state.
                            let error = PgError::simple(
                                "ERROR",
                                "25P02",
                                "current transaction is aborted, commands ignored until end of transaction block",
                            );
                            send_pg_error_response(client_stream, error).await?;
                        }
                        tag_byte if tag_byte == frontend_tag::CLOSE => {
                            // Close in Failed state: PostgreSQL actually
                            // processes Close even in Failed state, returning
                            // CloseComplete. Synthesize it.
                            let close_complete = [b'3', 0, 0, 0, 4];
                            client_stream
                                .write_all(&close_complete)
                                .await
                                .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                        }
                        _ => {}
                    }
                }
                // FIX (Bug 1): Always send RFQ — this function is only
                // called when a Sync message triggers the batch.
                send_ready_for_query(client_stream, TxState::Idle).await?;
                return Ok(());
            }

            // Step 1: Find transaction-ending SQL, either from a Parse in
            // this batch or from the prepared_stmts cache via Bind.
            let mut txn_end_tag: Option<&'static str> = None;
            let mut txn_parse_stmt_name: Option<&str> = None;

            // Check Parse frames in this batch for COMMIT/ROLLBACK.
            for frame in batch.iter().filter(|f| f.tag == frontend_tag::PARSE) {
                if let Some(sql) = frame.parse_sql() {
                    if let Some(tag) = crate::session::transaction::transaction_end_tag(sql) {
                        txn_end_tag = Some(tag);
                        txn_parse_stmt_name = frame.parse_name();
                        // Record in prepared_stmts cache for cross-Sync support.
                        if let Some(name) = frame.parse_name() {
                            if !name.is_empty() {
                                session
                                    .state
                                    .prepared_stmts
                                    .insert(name.to_string(), sql.to_string());
                            }
                        }
                        break;
                    }
                }
            }

            // (c) Cross-Sync: no Parse with COMMIT/ROLLBACK in this batch,
            // but Bind may reference a previously prepared statement.
            if txn_end_tag.is_none() {
                for frame in batch.iter().filter(|f| f.tag == frontend_tag::BIND) {
                    if let Some(stmt_name) = frame.bind_statement() {
                        if let Some(cached_sql) = session.state.prepared_stmts.get(stmt_name) {
                            if let Some(tag) =
                                crate::session::transaction::transaction_end_tag(cached_sql)
                            {
                                txn_end_tag = Some(tag);
                                txn_parse_stmt_name = Some(stmt_name);
                                break;
                            }
                        }
                    }
                }
            }

            if let Some(tag) = txn_end_tag {
                // (a) Verify Bind references the correct statement.
                let has_matching_bind = txn_parse_stmt_name.is_some_and(|stmt_name| {
                    batch.iter().any(|f| {
                        f.tag == frontend_tag::BIND && f.bind_statement() == Some(stmt_name)
                    })
                });

                // Find the portal created by the matching Bind.
                let txn_portal_name = txn_parse_stmt_name.and_then(|stmt_name| {
                    batch
                        .iter()
                        .filter(|f| {
                            f.tag == frontend_tag::BIND && f.bind_statement() == Some(stmt_name)
                        })
                        .find_map(|f| f.bind_portal())
                });

                // Verify Execute references the correct portal.
                let has_matching_execute = txn_portal_name.is_some_and(|portal| {
                    batch.iter().any(|f| {
                        f.tag == frontend_tag::EXECUTE && f.execute_portal() == Some(portal)
                    })
                });

                if has_matching_bind && has_matching_execute {
                    // (b) COMMIT in Failed state becomes ROLLBACK.
                    let effective_tag = if tag == "COMMIT" { "ROLLBACK" } else { tag };

                    // Full execution cycle: reset to Idle.
                    session.state.tx_state = TxState::Idle;
                    session.state.tx_split = None;
                    session.tx_has_writes = false;
                    session.failed_state_portals.clear();

                    // FIX: Process ALL frames in the batch to produce the
                    // correct response sequence. In Failed state, non-txn-end
                    // frames get 25P02 ErrorResponse; the txn-end Parse/Bind/
                    // Execute get ParseComplete/BindComplete/CommandComplete.
                    let txn_stmt = txn_parse_stmt_name.unwrap_or("");
                    let txn_portal = txn_portal_name.unwrap_or("");
                    for frame in batch.iter() {
                        match frame.tag {
                            tag_byte if tag_byte == frontend_tag::PARSE => {
                                let is_txn_parse = frame.parse_name().unwrap_or("") == txn_stmt
                                    && frame
                                        .parse_sql()
                                        .and_then(crate::session::transaction::transaction_end_tag)
                                        .is_some();
                                if is_txn_parse {
                                    let pc = [b'1', 0, 0, 0, 4];
                                    client_stream
                                        .write_all(&pc)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                } else {
                                    // Non-txn Parse in Failed state: 25P02.
                                    let error = PgError::simple(
                                        "ERROR", "25P02",
                                        "current transaction is aborted, commands ignored until end of transaction block",
                                    );
                                    send_pg_error_response(client_stream, error).await?;
                                }
                            }
                            tag_byte if tag_byte == frontend_tag::BIND => {
                                let is_txn_bind = frame.bind_statement() == Some(txn_stmt);
                                if is_txn_bind {
                                    let bc = [b'2', 0, 0, 0, 4];
                                    client_stream
                                        .write_all(&bc)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                } else {
                                    let error = PgError::simple(
                                        "ERROR", "25P02",
                                        "current transaction is aborted, commands ignored until end of transaction block",
                                    );
                                    send_pg_error_response(client_stream, error).await?;
                                }
                            }
                            tag_byte if tag_byte == frontend_tag::EXECUTE => {
                                let is_txn_exec = frame.execute_portal() == Some(txn_portal);
                                if is_txn_exec {
                                    let cmd = crate::protocol::writer::encode_backend_message(
                                        &crate::protocol::message::BackendMessage::CommandComplete {
                                            tag: effective_tag.to_string(),
                                        },
                                    );
                                    client_stream
                                        .write_all(&cmd)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                } else {
                                    let error = PgError::simple(
                                        "ERROR", "25P02",
                                        "current transaction is aborted, commands ignored until end of transaction block",
                                    );
                                    send_pg_error_response(client_stream, error).await?;
                                }
                            }
                            tag_byte if tag_byte == frontend_tag::DESCRIBE => {
                                let error = PgError::simple(
                                    "ERROR", "25P02",
                                    "current transaction is aborted, commands ignored until end of transaction block",
                                );
                                send_pg_error_response(client_stream, error).await?;
                            }
                            tag_byte if tag_byte == frontend_tag::CLOSE => {
                                // PostgreSQL processes Close even in Failed state.
                                let cc = [b'3', 0, 0, 0, 4];
                                client_stream
                                    .write_all(&cc)
                                    .await
                                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                            }
                            _ => {}
                        }
                    }
                    send_ready_for_query(client_stream, TxState::Idle).await?;
                    return Ok(());
                } else if has_matching_bind && !has_matching_execute {
                    // Parse+Bind without Execute: the client is preparing
                    // and binding but not yet executing. Return
                    // ParseComplete + BindComplete without changing tx state.
                    // Record the portal for cross-Sync Execute-only support.
                    if let Some(portal) = txn_portal_name {
                        session.failed_state_portals.insert(portal.to_string(), tag);
                    }
                    let has_parse_in_batch = batch.iter().any(|f| f.tag == frontend_tag::PARSE);
                    if has_parse_in_batch {
                        let parse_complete = [b'1', 0, 0, 0, 4];
                        client_stream
                            .write_all(&parse_complete)
                            .await
                            .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                    }
                    let bind_complete = [b'2', 0, 0, 0, 4];
                    client_stream
                        .write_all(&bind_complete)
                        .await
                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                    // FIX (Bug 1): Always send RFQ — this function is only
                    // called when a Sync message triggers the batch.
                    send_ready_for_query(client_stream, TxState::Failed).await?;
                    return Ok(());
                } else if !has_matching_bind && !has_matching_execute {
                    // Parse-only (no Bind/Execute): client is preparing
                    // the statement but not executing yet. Record it and
                    // return ParseComplete.
                    // FIX (Bug 1): Always send RFQ — this function is only
                    // called when a Sync message triggers the batch.
                    let parse_complete = [b'1', 0, 0, 0, 4];
                    client_stream
                        .write_all(&parse_complete)
                        .await
                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                    send_ready_for_query(client_stream, TxState::Failed).await?;
                    return Ok(());
                }
                // If Bind is present but references a different statement,
                // fall through to the 25P02 error below.
            }

            let error = PgError::simple(
                "ERROR",
                "25P02",
                "current transaction is aborted, commands ignored until end of transaction block",
            );
            send_pg_error_response(client_stream, error).await?;
            send_ready_for_query(client_stream, TxState::Failed).await?;
            return Ok(());
        }

        // FIX (Bug 3): Cross-Sync support for proxy-local SET commands.
        // If a Bind references a statement previously recorded in
        // `local_set_stmts` (from a prior Parse-only batch), handle it
        // locally without forwarding to the backend.
        // Only intercept if ALL Bind frames in this batch reference local
        // set stmts — if mixed, fall through to normal processing.
        //
        // Also handle:
        // - Describe('S', name) for local SET statements → synthetic response
        // - Execute-only referencing a previously bound local SET portal
        if !batch.iter().any(|f| f.tag == frontend_tag::PARSE) {
            // Check for Execute-only batch referencing a local SET portal
            // (from a prior Bind-only batch).
            if !batch.iter().any(|f| f.tag == frontend_tag::BIND) {
                // FIX (P1 swallow): Only intercept if ALL Execute frames
                // reference local SET portals. If any Execute targets a
                // non-local portal (bound on the backend in a prior Sync),
                // we must fall through so it reaches the backend.
                let all_execs_local =
                    batch
                        .iter()
                        .filter(|f| f.tag == frontend_tag::EXECUTE)
                        .all(|f| {
                            f.execute_portal()
                                .is_some_and(|p| session.local_set_portals.contains_key(p))
                        });
                let local_exec = if all_execs_local {
                    batch
                        .iter()
                        .filter(|f| f.tag == frontend_tag::EXECUTE)
                        .find_map(|f| {
                            f.execute_portal().and_then(|p| {
                                session
                                    .local_set_portals
                                    .get(p)
                                    .cloned()
                                    .map(|sql| (p.to_string(), sql))
                            })
                        })
                } else {
                    None
                };
                if let Some((portal_name, sql)) = local_exec {
                    // Apply the SET and respond to all frames in batch.
                    session.state.apply_consistency_set_command(&sql);
                    for frame in batch.iter() {
                        match frame.tag {
                            tag if tag == frontend_tag::EXECUTE => {
                                let is_local =
                                    frame.execute_portal().is_some_and(|p| p == portal_name);
                                if is_local {
                                    let cmd_complete = crate::protocol::writer::encode_backend_message(
                                        &crate::protocol::message::BackendMessage::CommandComplete {
                                            tag: "SET".to_string(),
                                        },
                                    );
                                    client_stream
                                        .write_all(&cmd_complete)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                } else {
                                    // Non-local Execute in same batch: error
                                    // (should not happen in well-formed usage).
                                    let error =
                                        PgError::simple("ERROR", "34000", "portal does not exist");
                                    send_pg_error_response(client_stream, error).await?;
                                }
                            }
                            tag if tag == frontend_tag::DESCRIBE => {
                                // Describe('P', portal) for the local SET portal.
                                // SET produces no rows: NoData.
                                let no_data = [b'n', 0, 0, 0, 4];
                                client_stream
                                    .write_all(&no_data)
                                    .await
                                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                            }
                            tag if tag == frontend_tag::CLOSE => {
                                // Close the virtual portal.
                                if let Some((kind, name)) = frame.kind_and_name() {
                                    if kind == b'P' {
                                        session.local_set_portals.remove(name);
                                    }
                                }
                                let close_complete = [b'3', 0, 0, 0, 4];
                                client_stream
                                    .write_all(&close_complete)
                                    .await
                                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                            }
                            _ => {}
                        }
                    }
                    send_ready_for_query(client_stream, session.state.tx_state).await?;
                    return Ok(());
                }
            }

            // Handle Describe('S', stmt_name) for local SET statements.
            // Must come before the Bind check since a batch could be
            // Describe-only.
            let describe_local = batch
                .iter()
                .filter(|f| f.tag == frontend_tag::DESCRIBE)
                .all(|f| {
                    f.kind_and_name().is_some_and(|(kind, name)| {
                        kind == b'S' && session.local_set_stmts.contains_key(name)
                    })
                });
            let has_only_describe_and_close = describe_local
                && !batch.iter().any(|f| f.tag == frontend_tag::BIND)
                && !batch.iter().any(|f| f.tag == frontend_tag::EXECUTE)
                && batch.iter().any(|f| f.tag == frontend_tag::DESCRIBE);
            if has_only_describe_and_close {
                // Respond to each frame in the batch.
                for frame in batch.iter() {
                    match frame.tag {
                        tag if tag == frontend_tag::DESCRIBE => {
                            // SET has no parameters and no result columns.
                            // ParameterDescription (0 params) + NoData.
                            let param_desc = [b't', 0, 0, 0, 6, 0, 0]; // tag + len(6) + 0 params
                            let no_data = [b'n', 0, 0, 0, 4];
                            client_stream
                                .write_all(&param_desc)
                                .await
                                .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                            client_stream
                                .write_all(&no_data)
                                .await
                                .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                        }
                        tag if tag == frontend_tag::CLOSE => {
                            if let Some((kind, name)) = frame.kind_and_name() {
                                if kind == b'S' {
                                    session.local_set_stmts.remove(name);
                                } else if kind == b'P' {
                                    session.local_set_portals.remove(name);
                                }
                            }
                            let close_complete = [b'3', 0, 0, 0, 4];
                            client_stream
                                .write_all(&close_complete)
                                .await
                                .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                        }
                        _ => {}
                    }
                }
                send_ready_for_query(client_stream, session.state.tx_state).await?;
                return Ok(());
            }

            let all_binds_are_local =
                batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::BIND)
                    .all(|f| {
                        f.bind_statement()
                            .is_some_and(|name| session.local_set_stmts.contains_key(name))
                    });
            let local_set_sql = if all_binds_are_local {
                batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::BIND)
                    .find_map(|f| {
                        f.bind_statement()
                            .and_then(|stmt_name| session.local_set_stmts.get(stmt_name).cloned())
                    })
            } else {
                None
            };
            if let Some(sql) = local_set_sql {
                // Find the portal name created by this Bind.
                let bind_portal = batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::BIND)
                    .find_map(|f| {
                        f.bind_statement().and_then(|stmt_name| {
                            if session.local_set_stmts.contains_key(stmt_name) {
                                f.bind_portal()
                            } else {
                                None
                            }
                        })
                    });
                // Collect all local SET portal names for Execute matching.
                let local_portal_names: Vec<&str> = batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::BIND)
                    .filter_map(|f| {
                        f.bind_statement().and_then(|stmt_name| {
                            if session.local_set_stmts.contains_key(stmt_name) {
                                f.bind_portal()
                            } else {
                                None
                            }
                        })
                    })
                    .collect();
                // Check if Execute references the portal.
                let has_execute = bind_portal.is_some_and(|portal| {
                    batch.iter().any(|f| {
                        f.tag == frontend_tag::EXECUTE && f.execute_portal() == Some(portal)
                    })
                });
                // FIX (P1 swallow): Verify ALL Execute frames reference
                // local SET portals. Cross-Sync Execute for a non-local
                // portal must not be swallowed.
                let all_executes_are_local = batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::EXECUTE)
                    .all(|f| {
                        f.execute_portal().is_some_and(|p| {
                            local_portal_names.contains(&p)
                                || session.local_set_portals.contains_key(p)
                        })
                    });
                if has_execute && all_executes_are_local {
                    // Full Bind+Execute: apply ALL local SET commands in
                    // order (FIX issue B: previously only the first was
                    // applied when multiple Binds referenced different SET
                    // statements in the same cross-Sync batch).
                    // Build a map: portal_name -> SQL for this batch's Binds.
                    let portal_to_sql: Vec<(&str, String)> = batch
                        .iter()
                        .filter(|f| f.tag == frontend_tag::BIND)
                        .filter_map(|f| {
                            f.bind_statement().and_then(|stmt_name| {
                                session
                                    .local_set_stmts
                                    .get(stmt_name)
                                    .map(|sql| (f.bind_portal().unwrap_or(""), sql.clone()))
                            })
                        })
                        .collect();
                    // FIX: Iterate ALL frames in the batch to generate
                    // correct responses for Describe/Close that may
                    // accompany Bind+Execute in a cross-Sync batch.
                    for frame in batch.iter() {
                        match frame.tag {
                            tag if tag == frontend_tag::BIND => {
                                let bind_complete = [b'2', 0, 0, 0, 4];
                                client_stream
                                    .write_all(&bind_complete)
                                    .await
                                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                            }
                            tag if tag == frontend_tag::DESCRIBE => {
                                // Describe(P): NoData (SET produces no result)
                                // Describe(S): ParameterDescription + NoData
                                if let Some((kind, _)) = frame.kind_and_name() {
                                    if kind == b'S' {
                                        let param_desc = [b't', 0, 0, 0, 6, 0, 0];
                                        client_stream.write_all(&param_desc).await.map_err(
                                            |e| ProxyError::Protocol(ProtocolError::Io(e)),
                                        )?;
                                    }
                                }
                                let no_data = [b'n', 0, 0, 0, 4];
                                client_stream
                                    .write_all(&no_data)
                                    .await
                                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                            }
                            tag if tag == frontend_tag::EXECUTE => {
                                // Apply the SET for this specific Execute's
                                // portal (in order) so multiple SETs take
                                // effect sequentially.
                                if let Some(portal) = frame.execute_portal() {
                                    if let Some((_, set_sql)) =
                                        portal_to_sql.iter().find(|(p, _)| *p == portal)
                                    {
                                        session.state.apply_consistency_set_command(set_sql);
                                    }
                                }
                                let cmd_complete = crate::protocol::writer::encode_backend_message(
                                    &crate::protocol::message::BackendMessage::CommandComplete {
                                        tag: "SET".to_string(),
                                    },
                                );
                                client_stream
                                    .write_all(&cmd_complete)
                                    .await
                                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                            }
                            tag if tag == frontend_tag::CLOSE => {
                                if let Some((kind, name)) = frame.kind_and_name() {
                                    if kind == b'S' {
                                        session.local_set_stmts.remove(name);
                                    } else if kind == b'P' {
                                        session.local_set_portals.remove(name);
                                    }
                                }
                                let close_complete = [b'3', 0, 0, 0, 4];
                                client_stream
                                    .write_all(&close_complete)
                                    .await
                                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                            }
                            _ => {}
                        }
                    }
                    send_ready_for_query(client_stream, session.state.tx_state).await?;
                    return Ok(());
                } else if !has_execute {
                    // Bind-only (no Execute): respond with BindComplete.
                    // FIX (Bug 4): Record the portal so a later Execute-only
                    // batch can resolve it locally.
                    if let Some(portal) = bind_portal {
                        session
                            .local_set_portals
                            .insert(portal.to_string(), sql.clone());
                    }
                    let bind_complete = [b'2', 0, 0, 0, 4];
                    client_stream
                        .write_all(&bind_complete)
                        .await
                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                    send_ready_for_query(client_stream, session.state.tx_state).await?;
                    return Ok(());
                }
                // else: has_execute && !all_executes_are_local — mixed batch
                // with non-local Execute. Fall through to normal processing.
            }
        }

        // Fast path: if a backend is already held (pinned connection or
        // in-transaction), skip routing/snapshot entirely and reuse it.
        //
        // But first: intercept proxy-local SET trident.consistency even on
        // the held path — this GUC must never reach the backend.
        //
        // FIX (Bug 2): In multi-Parse batches on the held path, collect
        // indices of SET-related frames for filtered forwarding.
        let mut held_set_skip_indices: Vec<usize> = Vec::new();
        // FIX (Bug 3): Collect pending SET commands to apply only after
        // the batch succeeds (no backend error).
        let mut pending_set_commands: Vec<String> = Vec::new();
        if session.held_backend.is_some() {
            // FIX (P1 stmts invalidation): Invalidate local_set_stmts entries
            // when a non-SET Parse in this batch reuses the same statement name.
            for frame in batch.iter().filter(|f| f.tag == frontend_tag::PARSE) {
                if let Some(sql) = frame.parse_sql() {
                    if !session.state.is_consistency_set_command(sql) {
                        if let Some(name) = frame.parse_name() {
                            if !name.is_empty() {
                                session.local_set_stmts.remove(name);
                            }
                        }
                    }
                }
            }
            // Collect ALL SET consistency Parse frames (not just the first).
            let set_parse_frames: Vec<_> = batch
                .iter()
                .enumerate()
                .filter(|(_, f)| f.tag == frontend_tag::PARSE)
                .filter(|(_, f)| {
                    f.parse_sql()
                        .map(|s| session.state.is_consistency_set_command(s))
                        .unwrap_or(false)
                })
                .map(|(i, f)| (i, f.parse_sql().unwrap(), f.parse_name().unwrap_or("")))
                .collect();

            if !set_parse_frames.is_empty() {
                let set_stmt_names: Vec<&str> =
                    set_parse_frames.iter().map(|(_, _, name)| *name).collect();
                let first_sql = set_parse_frames[0].1;
                let first_stmt_name = set_parse_frames[0].2;

                // Find all portals bound to SET statements.
                let set_portal_names: Vec<&str> = batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::BIND)
                    .filter(|f| {
                        f.bind_statement()
                            .map(|s| set_stmt_names.contains(&s))
                            .unwrap_or(false)
                    })
                    .filter_map(|f| f.bind_portal())
                    .collect();

                let has_matching_bind = batch.iter().any(|f| {
                    f.tag == frontend_tag::BIND && f.bind_statement() == Some(first_stmt_name)
                });

                let set_portal_name = batch
                    .iter()
                    .filter(|f| {
                        f.tag == frontend_tag::BIND && f.bind_statement() == Some(first_stmt_name)
                    })
                    .find_map(|f| f.bind_portal());

                let has_matching_execute = set_portal_name.is_some_and(|portal| {
                    batch.iter().any(|f| {
                        f.tag == frontend_tag::EXECUTE && f.execute_portal() == Some(portal)
                    })
                });

                let parse_count = batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::PARSE)
                    .count();

                // FIX (P1 swallow): Before taking the pure-local fast path,
                // verify that ALL Bind/Execute/Describe frames in the batch
                // belong to the SET statement. If there are non-SET frames
                // (e.g. Bind/Execute referencing a previously prepared real
                // query via cross-Sync portal reuse), we must NOT return
                // early — those frames need to reach the backend.
                let all_binds_are_set =
                    batch
                        .iter()
                        .filter(|f| f.tag == frontend_tag::BIND)
                        .all(|f| {
                            f.bind_statement()
                                .map(|s| set_stmt_names.contains(&s))
                                .unwrap_or(false)
                        });
                let all_executes_are_set = batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::EXECUTE)
                    .all(|f| {
                        f.execute_portal()
                            .map(|p| set_portal_names.contains(&p))
                            .unwrap_or(false)
                    });
                let batch_is_pure_set = all_binds_are_set && all_executes_are_set;

                if parse_count <= 1 {
                    if has_matching_bind && has_matching_execute && batch_is_pure_set {
                        // Full Parse+Bind+Execute for the SET and NO other
                        // operations in the batch: apply and respond locally.
                        session.state.apply_consistency_set_command(first_sql);
                        // FIX: Iterate ALL frames to handle Describe/Close.
                        for frame in batch.iter() {
                            match frame.tag {
                                tag if tag == frontend_tag::PARSE => {
                                    let parse_complete = [b'1', 0, 0, 0, 4];
                                    client_stream
                                        .write_all(&parse_complete)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                }
                                tag if tag == frontend_tag::BIND => {
                                    let bind_complete = [b'2', 0, 0, 0, 4];
                                    client_stream
                                        .write_all(&bind_complete)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                }
                                tag if tag == frontend_tag::DESCRIBE => {
                                    if let Some((kind, _)) = frame.kind_and_name() {
                                        if kind == b'S' {
                                            let param_desc = [b't', 0, 0, 0, 6, 0, 0];
                                            client_stream.write_all(&param_desc).await.map_err(
                                                |e| ProxyError::Protocol(ProtocolError::Io(e)),
                                            )?;
                                        }
                                    }
                                    let no_data = [b'n', 0, 0, 0, 4];
                                    client_stream
                                        .write_all(&no_data)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                }
                                tag if tag == frontend_tag::EXECUTE => {
                                    use crate::protocol::message::BackendMessage;
                                    use crate::protocol::writer::encode_backend_message;
                                    let cmd_complete =
                                        encode_backend_message(&BackendMessage::CommandComplete {
                                            tag: "SET".to_string(),
                                        });
                                    client_stream
                                        .write_all(&cmd_complete)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                }
                                tag if tag == frontend_tag::CLOSE => {
                                    if let Some((kind, name)) = frame.kind_and_name() {
                                        if kind == b'S' {
                                            session.local_set_stmts.remove(name);
                                        } else if kind == b'P' {
                                            session.local_set_portals.remove(name);
                                        }
                                    }
                                    let close_complete = [b'3', 0, 0, 0, 4];
                                    client_stream
                                        .write_all(&close_complete)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                }
                                _ => {}
                            }
                        }
                        send_ready_for_query(client_stream, session.state.tx_state).await?;
                        return Ok(());
                    } else if has_matching_bind && has_matching_execute && !batch_is_pure_set {
                        // SET has full Parse+Bind+Execute but the batch also
                        // contains non-SET operations (cross-Sync portal
                        // reuse). Fall through to multi-Parse filtering path
                        // to filter SET frames and forward the rest.
                        pending_set_commands.push(first_sql.to_string());
                        for (i, frame) in batch.iter().enumerate() {
                            let should_skip = match frame.tag {
                                tag if tag == frontend_tag::PARSE => frame
                                    .parse_sql()
                                    .map(|s| session.state.is_consistency_set_command(s))
                                    .unwrap_or(false),
                                tag if tag == frontend_tag::BIND => frame
                                    .bind_statement()
                                    .map(|s| set_stmt_names.contains(&s))
                                    .unwrap_or(false),
                                tag if tag == frontend_tag::EXECUTE => frame
                                    .execute_portal()
                                    .map(|p| set_portal_names.contains(&p))
                                    .unwrap_or(false),
                                tag if tag == frontend_tag::DESCRIBE => {
                                    frame.kind_and_name().is_some_and(|(kind, name)| {
                                        (kind == b'S' && set_stmt_names.contains(&name))
                                            || (kind == b'P' && set_portal_names.contains(&name))
                                    })
                                }
                                tag if tag == frontend_tag::CLOSE => {
                                    frame.kind_and_name().is_some_and(|(kind, name)| {
                                        (kind == b'S' && set_stmt_names.contains(&name))
                                            || (kind == b'P' && set_portal_names.contains(&name))
                                    })
                                }
                                _ => false,
                            };
                            if should_skip {
                                held_set_skip_indices.push(i);
                            }
                        }
                        // Fall through to forward remaining batch to held backend.
                    } else if !has_matching_bind {
                        // Parse-only: don't apply yet. Return ParseComplete.
                        // FIX (Bug 1/3): Always send RFQ. Also record virtual
                        // prepared statement for cross-Sync support.
                        if !first_stmt_name.is_empty() {
                            session
                                .local_set_stmts
                                .insert(first_stmt_name.to_string(), first_sql.to_string());
                        }
                        let parse_complete = [b'1', 0, 0, 0, 4];
                        client_stream
                            .write_all(&parse_complete)
                            .await
                            .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                        send_ready_for_query(client_stream, session.state.tx_state).await?;
                        return Ok(());
                    }
                    // Bind references a DIFFERENT statement than the SET Parse →
                    // do NOT intercept, fall through to forward to backend.
                } else {
                    // Multi-Parse pipeline batch: collect SET commands to
                    // apply AFTER the batch succeeds (FIX Bug 3). If a
                    // preceding statement in the batch errors, we must NOT
                    // have modified session state.
                    for &(_, sql, sname) in &set_parse_frames {
                        let has_bind = batch.iter().any(|f| {
                            f.tag == frontend_tag::BIND && f.bind_statement() == Some(sname)
                        });
                        let portal = batch
                            .iter()
                            .filter(|f| {
                                f.tag == frontend_tag::BIND && f.bind_statement() == Some(sname)
                            })
                            .find_map(|f| f.bind_portal());
                        let has_exec = portal.is_some_and(|p| {
                            batch.iter().any(|f| {
                                f.tag == frontend_tag::EXECUTE && f.execute_portal() == Some(p)
                            })
                        });
                        if has_bind && has_exec {
                            pending_set_commands.push(sql.to_string());
                        }
                    }
                    // Collect indices of ALL SET-related frames.
                    // FIX: Position-aware matching for unnamed statements.
                    let mut held_current_unnamed_is_set = false;
                    let mut held_current_unnamed_portal_is_set = false;
                    for (i, frame) in batch.iter().enumerate() {
                        let should_skip = match frame.tag {
                            tag if tag == frontend_tag::PARSE => {
                                let is_set = frame
                                    .parse_sql()
                                    .map(|s| session.state.is_consistency_set_command(s))
                                    .unwrap_or(false);
                                let name = frame.parse_name().unwrap_or("");
                                if name.is_empty() {
                                    held_current_unnamed_is_set = is_set;
                                }
                                is_set
                            }
                            tag if tag == frontend_tag::BIND => {
                                let stmt = frame.bind_statement().unwrap_or("");
                                let is_set_bind = if stmt.is_empty() {
                                    held_current_unnamed_is_set
                                } else {
                                    set_stmt_names.contains(&stmt)
                                };
                                let portal = frame.bind_portal().unwrap_or("");
                                if portal.is_empty() {
                                    held_current_unnamed_portal_is_set = is_set_bind;
                                }
                                is_set_bind
                            }
                            tag if tag == frontend_tag::EXECUTE => {
                                let portal = frame.execute_portal().unwrap_or("");
                                if portal.is_empty() {
                                    held_current_unnamed_portal_is_set
                                } else {
                                    set_portal_names.contains(&portal)
                                }
                            }
                            // FIX (P1 Describe/Close): Also filter Describe and
                            // Close that reference virtual SET objects so they
                            // don't reach the backend (which doesn't know them).
                            tag if tag == frontend_tag::DESCRIBE => {
                                frame.kind_and_name().is_some_and(|(kind, name)| {
                                    if name.is_empty() {
                                        (kind == b'S' && held_current_unnamed_is_set)
                                            || (kind == b'P' && held_current_unnamed_portal_is_set)
                                    } else {
                                        (kind == b'S' && set_stmt_names.contains(&name))
                                            || (kind == b'P' && set_portal_names.contains(&name))
                                    }
                                })
                            }
                            tag if tag == frontend_tag::CLOSE => {
                                frame.kind_and_name().is_some_and(|(kind, name)| {
                                    if name.is_empty() {
                                        (kind == b'S' && held_current_unnamed_is_set)
                                            || (kind == b'P' && held_current_unnamed_portal_is_set)
                                    } else {
                                        (kind == b'S' && set_stmt_names.contains(&name))
                                            || (kind == b'P' && set_portal_names.contains(&name))
                                    }
                                })
                            }
                            _ => false,
                        };
                        if should_skip {
                            held_set_skip_indices.push(i);
                        }
                    }

                    // FIX: If ALL frames were SET-related, handle entirely
                    // locally without forwarding to the held backend.
                    if held_set_skip_indices.len() == batch.len() {
                        // No backend interaction — apply SET commands immediately
                        // (no error is possible from a preceding statement).
                        for cmd in &pending_set_commands {
                            session.state.apply_consistency_set_command(cmd);
                        }
                        use super::helpers::compute_synthetic_schedule;
                        let schedule = compute_synthetic_schedule(batch, &held_set_skip_indices);
                        if !schedule[0].is_empty() {
                            client_stream
                                .write_all(&schedule[0])
                                .await
                                .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                        }
                        send_ready_for_query(client_stream, session.state.tx_state).await?;
                        return Ok(());
                    }
                    // Fall through to forward remaining batch to held backend.
                }
            }
        }

        // FIX (Bug 2): Before forwarding, check if there is a pending
        // deferred BEGIN (tx_split state is pending but not yet active).
        // When a session has a pinned connection and a new explicit
        // transaction was started via Simple Query (which sets tx_split to
        // pending and tx_state to InTransaction without sending BEGIN to
        // the backend), the Extended Query batch that follows must first
        // issue the deferred BEGIN on the held backend. Without this, the
        // statements execute outside any transaction on the backend, which
        // is a semantic correctness violation.
        if session.held_backend.is_some() {
            // Inject deferred BEGIN if needed.
            if let Some(ref split) = session.state.tx_split {
                if !split.active {
                    let begin_sql = split.begin_sql().to_string();
                    let held = session.held_backend.as_mut().expect("checked above");
                    // FIX (Bug 4): Use execute_internal_query which properly
                    // validates ErrorResponse and confirms the final transaction
                    // status is InTransaction. The previous manual loop ignored
                    // errors and unconditionally marked the split as active.
                    if let Err(error) = execute_internal_query(
                        &mut held.conn.stream,
                        &begin_sql,
                        TransactionStatus::InTransaction,
                    )
                    .await
                    {
                        // BEGIN failed — the backend is not in a transaction.
                        // Mark session as Failed and discard the held backend.
                        session.state.tx_state = TxState::Failed;
                        let mut held = session.held_backend.take().unwrap();
                        if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, session)
                        {
                            let _ = pool.discard(held.conn.take());
                        }
                        return Err(ProxyError::Protocol(error));
                    }
                    // Mark the split as active now that BEGIN succeeded.
                    // Determine on_reader by checking if the held node is a writer.
                    let held_node_id = session
                        .held_backend
                        .as_ref()
                        .expect("checked above")
                        .conn
                        .node_id
                        .clone();
                    let is_writer = self
                        .pool_manager
                        .snapshot()
                        .iter()
                        .any(|n| n.node_id == held_node_id && n.node_type == NodeType::Writer);
                    if let Some(ref mut s) = session.state.tx_split {
                        s.active = true;
                        s.on_reader = !is_writer;
                    }
                }
            }

            // FIX (Bug 2): If the held backend is a Reader and this batch
            // contains a write operation, we cannot forward it there. Release
            // the Reader and fall through to the normal routing path which
            // will select a Writer.
            let held = session.held_backend.as_ref().expect("checked above");
            let held_is_reader = self
                .pool_manager
                .snapshot()
                .iter()
                .any(|n| n.node_id == held.conn.node_id && n.node_type == NodeType::Reader);
            if held_is_reader {
                let batch_has_write = batch.iter().any(|frame| {
                    if frame.tag == frontend_tag::PARSE {
                        if let Some(sql) = frame.parse_sql() {
                            // Skip proxy-local SET consistency commands — they
                            // are filtered out before forwarding and should not
                            // trigger a Reader→Writer upgrade.
                            if session.state.is_consistency_set_command(sql) {
                                return false;
                            }
                            // COMMIT/ROLLBACK are classified as SqlKind::Other
                            // (not readable), but they MUST NOT trigger a
                            // Reader→Writer upgrade. They should complete on
                            // the current Reader to end the transaction there.
                            if crate::session::transaction::transaction_end_tag(sql).is_some() {
                                return false;
                            }
                            let kind = KeywordClassifier.classify(sql);
                            return requires_writer(&KeywordClassifier, sql) || !kind.readable();
                        }
                    }
                    false
                });
                if batch_has_write {
                    // Reader→Writer upgrade: follow the contract documented in
                    // transaction.rs — ROLLBACK Reader, then BEGIN Writer.
                    let mut held = session.held_backend.take().unwrap();
                    let reader_node_id = held.conn.node_id.clone();
                    let reader_pool = match self.resolve_pool_existing(&reader_node_id, session) {
                        Some(pool) => pool,
                        None => {
                            // Pool disappeared — connection will be dropped,
                            // but we cannot safely continue the transaction.
                            session.state.tx_state = TxState::Failed;
                            return Err(ProxyError::Pool(
                                crate::pool::pool::PoolError::CleanupFailed(format!(
                                    "pool for split Reader '{}' no longer exists",
                                    reader_node_id
                                )),
                            ));
                        }
                    };

                    // (1) Send ROLLBACK to the Reader so it leaves the
                    // transaction state cleanly before being returned/discarded.
                    if let Err(error) = execute_internal_query(
                        &mut held.conn.stream,
                        "ROLLBACK",
                        TransactionStatus::Idle,
                    )
                    .await
                    {
                        // ROLLBACK failed — discard the connection.
                        let _ = reader_pool.discard(held.conn.take());
                        session.state.tx_state = TxState::Failed;
                        return Err(ProxyError::Protocol(error));
                    }

                    // (2) Release or discard the Reader connection.
                    {
                        use crate::config::PoolMode;
                        match reader_pool.mode() {
                            PoolMode::Transaction => {
                                held.conn.dirty = false;
                                reader_pool
                                    .release(&session.state.id, held.conn.take())
                                    .await?;
                            }
                            PoolMode::Session => {
                                let _ = reader_pool.discard(held.conn.take());
                            }
                        }
                    }

                    // (3) Update tx_split state: mark upgrade needed so the
                    // downstream code will issue BEGIN on the Writer.
                    if let Some(ref mut s) = session.state.tx_split {
                        s.on_reader = false;
                        s.need_upgrade = true;
                    }
                    // Fall through to the normal routing path below.
                }
            }

            if session.held_backend.is_some() {
                return self
                    .forward_extended_on_held_backend(
                        client_stream,
                        session,
                        batch,
                        &held_set_skip_indices,
                        &pending_set_commands,
                    )
                    .await;
            }
        }

        // Determine routing: prefer Parse SQL, then named statement lookup,
        // then fall back to "SELECT 1" (routes to Reader by default). A Parse
        // frame whose header C-strings cannot be extracted is malformed
        // enough that routing is impossible; reject it here (the strict
        // parser would previously have rejected it at read time).
        //
        // FIX: Check ALL Parse messages in the batch. If any Parse requires
        // a Writer (via SQL classification or routing hint), the entire
        // batch must be routed to the Writer. This prevents a batch like
        // [Parse(SELECT), Parse(INSERT)] from being sent to a Reader.
        // Additionally, if any Parse carries a ForceWriter routing hint,
        // that takes priority. If there are conflicting force-route hints
        // (ForceWriter vs ForceReader), Writer wins for safety.
        let mut route_sql: Option<&str> = None;
        let mut force_writer = false;
        // FIX (Bug 6): Separate flag for SQL that semantically produces
        // writes vs. routing hints that merely direct traffic to Writer.
        // Only `sql_is_write` should seed `write_detected` for LSN tracking;
        // a ForceWriter hint on a SELECT should not create a fake write
        // watermark that forces subsequent reads to Writer.
        let mut sql_is_write = false;
        let classifier = KeywordClassifier;
        let hint_parser = crate::parser::hint::RegexHintParser;
        use crate::parser::hint::{HintParser as _, RouteHint};
        for frame in batch.iter().filter(|f| f.tag == frontend_tag::PARSE) {
            let sql = frame.parse_sql().ok_or_else(|| {
                ProxyError::Protocol(ProtocolError::Malformed(
                    "Parse message missing statement name or query C-string".into(),
                ))
            })?;
            // FIX (Bug 2): Skip proxy-local SET consistency commands in the
            // routing decision — they will be filtered out before forwarding
            // and should not influence routing or write detection.
            if session.state.is_consistency_set_command(sql) {
                continue;
            }
            // FIX (P1 stmts invalidation): If a non-SET Parse reuses a
            // statement name that was previously recorded as a virtual local
            // SET statement, invalidate it. Otherwise the stale virtual entry
            // could hijack a later Bind/Execute referencing the same name,
            // causing real operations to be swallowed.
            if let Some(stmt_name) = frame.parse_name() {
                if !stmt_name.is_empty() {
                    session.local_set_stmts.remove(stmt_name);
                }
            }
            if route_sql.is_none() {
                route_sql = Some(sql);
            }
            // Check SQL classification: anything that explicitly requires
            // Writer OR anything not classified as readable (e.g. DO $$,
            // CALL, WITH...INSERT) must go to Writer. This mirrors the
            // Router's own logic which sends !readable() to Writer.
            if !force_writer {
                let kind = classifier.classify(sql);
                if requires_writer(&classifier, sql) || !kind.readable() {
                    route_sql = Some(sql);
                    force_writer = true;
                    // FIX (Bug 5): Only seed sql_is_write when this Parse
                    // has a matching Bind in the batch (i.e. it will actually
                    // execute). Parse-only (preparation without execution)
                    // should not create a write watermark.
                    let stmt_name = frame.parse_name().unwrap_or("");
                    let has_bind = batch.iter().any(|f| {
                        f.tag == frontend_tag::BIND && f.bind_statement() == Some(stmt_name)
                    });
                    if has_bind {
                        sql_is_write = true;
                    }
                }
            }
            // Check routing hints — ForceWriter wins over ForceReader.
            // When ForceWriter is triggered, route_sql is set to that SQL
            // so the Router receives the hint. When ForceReader is triggered
            // (and no Writer is needed), route_sql is set to the ForceReader
            // SQL so the Router picks it up.
            if !force_writer {
                let hint = hint_parser.parse_hint(sql);
                match hint {
                    RouteHint::ForceWriter => {
                        route_sql = Some(sql);
                        force_writer = true;
                        // Note: sql_is_write is NOT set here — a routing
                        // hint does not imply the query produces writes.
                    }
                    RouteHint::ForceReader
                        if !requires_writer(&classifier, route_sql.unwrap_or("")) =>
                    {
                        // Only set route_sql to ForceReader SQL if we haven't
                        // already committed to a Writer-bound SQL.
                        route_sql = Some(sql);
                    }
                    RouteHint::ForceAnalytics
                        if !requires_writer(&classifier, route_sql.unwrap_or("")) =>
                    {
                        // FIX: Propagate ForceAnalytics hint so the Router
                        // can pick it up. Same precedence as ForceReader.
                        route_sql = Some(sql);
                    }
                    RouteHint::Consistency(level) => {
                        // FIX: Apply consistency hint from any Parse in the
                        // batch to the session for routing this batch. The
                        // Router will use session.state.consistency which is
                        // overridden per-query by the hint in the SQL passed
                        // to route(). Setting route_sql ensures the Router
                        // sees the hint.
                        if route_sql.is_none()
                            || !requires_writer(&classifier, route_sql.unwrap_or(""))
                        {
                            route_sql = Some(sql);
                        }
                        let _ = level; // Router parses the hint itself
                    }
                    _ => {}
                }
            }
            // FIX (Bug 5): Check custom routing rules for each Parse in the
            // batch, not just the final sql passed to Router::route(). A
            // custom rule that forces writer for "SELECT * FROM sensitive_table"
            // must not be bypassed simply because a later Parse in the batch
            // (e.g. "SELECT 1") overwrites route_sql.
            if !force_writer {
                if let Some(custom_rules) = self.router.custom_rules() {
                    if custom_rules.forces_writer(sql).is_some() {
                        route_sql = Some(sql);
                        force_writer = true;
                        // Custom rules forcing writer doesn't necessarily mean
                        // the SQL produces writes (it may be a sensitive read).
                        // Do NOT set sql_is_write here.
                    }
                }
            }
        }

        // Intercept `SET trident.consistency = '...'` in extended protocol.
        // Like the simple query path, this is a proxy-local setting that
        // should not reach the backend. However, per PostgreSQL extended
        // protocol semantics, Parse only creates a prepared statement and
        // does NOT execute it. The SET should only take effect when the
        // batch includes a matching Bind + Execute cycle.
        //
        // FIX (Bug 1): Verify Bind/Execute reference the SET Parse's
        // statement name and portal, not an unrelated statement. Also,
        // Parse-only should NOT return RFQ unless there's a Sync.
        //
        // FIX (Bug 2): In multi-Parse batches, collect indices of SET-related
        // frames to filter them out before forwarding to backend.
        let mut set_frame_skip_indices: Vec<usize> = Vec::new();
        // FIX (Bug 3): Collect pending SET commands to apply only after
        // the batch succeeds (no backend error).
        let mut pending_set_commands_nonheld: Vec<String> = Vec::new();
        // Collect ALL SET consistency Parse frames (not just the first).
        // A batch may contain multiple SET commands; we must filter all of
        // them and their corresponding Bind/Execute frames.
        let set_parse_frames: Vec<_> = batch
            .iter()
            .enumerate()
            .filter(|(_, f)| f.tag == frontend_tag::PARSE)
            .filter(|(_, f)| {
                f.parse_sql()
                    .map(|s| session.state.is_consistency_set_command(s))
                    .unwrap_or(false)
            })
            .map(|(i, f)| (i, f.parse_sql().unwrap(), f.parse_name().unwrap_or("")))
            .collect();

        if !set_parse_frames.is_empty() {
            // Collect all SET statement names for Bind matching.
            let set_stmt_names: Vec<&str> =
                set_parse_frames.iter().map(|(_, _, name)| *name).collect();

            // For the single-SET, single-Parse path we still need the
            // first SET's info for backward-compatible behavior.
            let first_sql = set_parse_frames[0].1;
            let first_stmt_name = set_parse_frames[0].2;

            if session.state.tx_state != TxState::Failed {
                // Find all portals bound to SET statements.
                let set_portal_names: Vec<&str> = batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::BIND)
                    .filter(|f| {
                        f.bind_statement()
                            .map(|s| set_stmt_names.contains(&s))
                            .unwrap_or(false)
                    })
                    .filter_map(|f| f.bind_portal())
                    .collect();

                // Check if there's at least one matching Bind+Execute for the first SET.
                let has_matching_bind = batch.iter().any(|f| {
                    f.tag == frontend_tag::BIND && f.bind_statement() == Some(first_stmt_name)
                });
                let set_portal_name = batch
                    .iter()
                    .filter(|f| {
                        f.tag == frontend_tag::BIND && f.bind_statement() == Some(first_stmt_name)
                    })
                    .find_map(|f| f.bind_portal());
                let has_matching_execute = set_portal_name.is_some_and(|portal| {
                    batch.iter().any(|f| {
                        f.tag == frontend_tag::EXECUTE && f.execute_portal() == Some(portal)
                    })
                });

                let parse_count = batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::PARSE)
                    .count();

                // FIX (P1 swallow): Before taking the pure-local fast path,
                // verify that ALL Bind/Execute frames in the batch belong to
                // SET statements. Cross-Sync portal reuse can place non-SET
                // Bind/Execute in the same batch as a SET Parse.
                let all_binds_are_set_nonheld = batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::BIND)
                    .all(|f| {
                        f.bind_statement()
                            .map(|s| set_stmt_names.contains(&s))
                            .unwrap_or(false)
                    });
                let all_executes_are_set_nonheld = batch
                    .iter()
                    .filter(|f| f.tag == frontend_tag::EXECUTE)
                    .all(|f| {
                        f.execute_portal()
                            .map(|p| set_portal_names.contains(&p))
                            .unwrap_or(false)
                    });
                let batch_is_pure_set_nonheld =
                    all_binds_are_set_nonheld && all_executes_are_set_nonheld;

                if parse_count <= 1 {
                    if has_matching_bind && has_matching_execute && batch_is_pure_set_nonheld {
                        // Full Parse+Bind+Execute cycle for the SET and NO
                        // other operations: apply and return synthetic response.
                        session.state.apply_consistency_set_command(first_sql);
                        // FIX: Iterate ALL frames in the batch to generate
                        // correct responses for Describe/Close that may
                        // accompany Parse+Bind+Execute.
                        for frame in batch.iter() {
                            match frame.tag {
                                tag if tag == frontend_tag::PARSE => {
                                    let parse_complete = [b'1', 0, 0, 0, 4];
                                    client_stream
                                        .write_all(&parse_complete)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                }
                                tag if tag == frontend_tag::BIND => {
                                    let bind_complete = [b'2', 0, 0, 0, 4];
                                    client_stream
                                        .write_all(&bind_complete)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                }
                                tag if tag == frontend_tag::DESCRIBE => {
                                    // Describe(S): ParameterDescription + NoData
                                    // Describe(P): NoData (SET has no result columns)
                                    if let Some((kind, _)) = frame.kind_and_name() {
                                        if kind == b'S' {
                                            let param_desc = [b't', 0, 0, 0, 6, 0, 0];
                                            client_stream.write_all(&param_desc).await.map_err(
                                                |e| ProxyError::Protocol(ProtocolError::Io(e)),
                                            )?;
                                        }
                                    }
                                    let no_data = [b'n', 0, 0, 0, 4];
                                    client_stream
                                        .write_all(&no_data)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                }
                                tag if tag == frontend_tag::EXECUTE => {
                                    use crate::protocol::message::BackendMessage;
                                    use crate::protocol::writer::encode_backend_message;
                                    let cmd_complete =
                                        encode_backend_message(&BackendMessage::CommandComplete {
                                            tag: "SET".to_string(),
                                        });
                                    client_stream
                                        .write_all(&cmd_complete)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                }
                                tag if tag == frontend_tag::CLOSE => {
                                    if let Some((kind, name)) = frame.kind_and_name() {
                                        if kind == b'S' {
                                            session.local_set_stmts.remove(name);
                                        } else if kind == b'P' {
                                            session.local_set_portals.remove(name);
                                        }
                                    }
                                    let close_complete = [b'3', 0, 0, 0, 4];
                                    client_stream
                                        .write_all(&close_complete)
                                        .await
                                        .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                                }
                                _ => {}
                            }
                        }
                        send_ready_for_query(client_stream, session.state.tx_state).await?;
                        return Ok(());
                    } else if has_matching_bind
                        && has_matching_execute
                        && !batch_is_pure_set_nonheld
                    {
                        // SET has full Parse+Bind+Execute but the batch also
                        // contains non-SET operations (cross-Sync portal
                        // reuse). Fall through to multi-Parse filtering path.
                        pending_set_commands_nonheld.push(first_sql.to_string());
                        for (i, frame) in batch.iter().enumerate() {
                            let should_skip = match frame.tag {
                                tag if tag == frontend_tag::PARSE => frame
                                    .parse_sql()
                                    .map(|s| session.state.is_consistency_set_command(s))
                                    .unwrap_or(false),
                                tag if tag == frontend_tag::BIND => frame
                                    .bind_statement()
                                    .map(|s| set_stmt_names.contains(&s))
                                    .unwrap_or(false),
                                tag if tag == frontend_tag::EXECUTE => frame
                                    .execute_portal()
                                    .map(|p| set_portal_names.contains(&p))
                                    .unwrap_or(false),
                                tag if tag == frontend_tag::DESCRIBE => {
                                    frame.kind_and_name().is_some_and(|(kind, name)| {
                                        (kind == b'S' && set_stmt_names.contains(&name))
                                            || (kind == b'P' && set_portal_names.contains(&name))
                                    })
                                }
                                tag if tag == frontend_tag::CLOSE => {
                                    frame.kind_and_name().is_some_and(|(kind, name)| {
                                        (kind == b'S' && set_stmt_names.contains(&name))
                                            || (kind == b'P' && set_portal_names.contains(&name))
                                    })
                                }
                                _ => false,
                            };
                            if should_skip {
                                set_frame_skip_indices.push(i);
                            }
                        }
                        // Fall through to normal routing with filtered batch.
                    } else if !has_matching_bind {
                        // Parse-only (no matching Bind): client is only
                        // preparing the statement. Return ParseComplete only.
                        // FIX (Bug 1/3): Always send RFQ. Also record virtual
                        // prepared statement for cross-Sync support.
                        if !first_stmt_name.is_empty() {
                            session
                                .local_set_stmts
                                .insert(first_stmt_name.to_string(), first_sql.to_string());
                        }
                        let parse_complete = [b'1', 0, 0, 0, 4];
                        client_stream
                            .write_all(&parse_complete)
                            .await
                            .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                        send_ready_for_query(client_stream, session.state.tx_state).await?;
                        return Ok(());
                    }
                    // Bind references a DIFFERENT statement → do NOT intercept.
                    // Fall through to normal routing.
                } else {
                    // Multi-Parse pipeline batch: collect SET commands to
                    // apply AFTER the batch succeeds (FIX Bug 3).
                    for &(_, sql, sname) in &set_parse_frames {
                        let has_bind = batch.iter().any(|f| {
                            f.tag == frontend_tag::BIND && f.bind_statement() == Some(sname)
                        });
                        let portal = batch
                            .iter()
                            .filter(|f| {
                                f.tag == frontend_tag::BIND && f.bind_statement() == Some(sname)
                            })
                            .find_map(|f| f.bind_portal());
                        let has_exec = portal.is_some_and(|p| {
                            batch.iter().any(|f| {
                                f.tag == frontend_tag::EXECUTE && f.execute_portal() == Some(p)
                            })
                        });
                        if has_bind && has_exec {
                            pending_set_commands_nonheld.push(sql.to_string());
                        }
                    }
                    // Collect indices of ALL SET-related frames (Parse, Bind,
                    // Execute, Describe, Close) so they can be filtered out
                    // before forwarding.
                    // FIX: Use position-aware matching for unnamed statements.
                    // When multiple Parse frames share the unnamed statement
                    // name "", a Bind("") belongs to the most recent Parse("")
                    // that precedes it, not to all Parse("") frames.
                    // Track the "current" Parse at each position: as we scan
                    // forward, record whether the active unnamed stmt is SET.
                    let mut current_unnamed_is_set = false;
                    // Track unnamed portal: inherits SET-ness from the Bind
                    // that created it.
                    let mut current_unnamed_portal_is_set = false;
                    for (i, frame) in batch.iter().enumerate() {
                        let should_skip = match frame.tag {
                            tag if tag == frontend_tag::PARSE => {
                                let is_set = frame
                                    .parse_sql()
                                    .map(|s| session.state.is_consistency_set_command(s))
                                    .unwrap_or(false);
                                // Update tracking for unnamed stmt.
                                let name = frame.parse_name().unwrap_or("");
                                if name.is_empty() {
                                    current_unnamed_is_set = is_set;
                                }
                                is_set
                            }
                            tag if tag == frontend_tag::BIND => {
                                let stmt = frame.bind_statement().unwrap_or("");
                                let is_set_bind = if stmt.is_empty() {
                                    // Unnamed: belongs to SET only if the
                                    // most recent unnamed Parse was SET.
                                    current_unnamed_is_set
                                } else {
                                    set_stmt_names.contains(&stmt)
                                };
                                // Track unnamed portal state.
                                let portal = frame.bind_portal().unwrap_or("");
                                if portal.is_empty() {
                                    current_unnamed_portal_is_set = is_set_bind;
                                }
                                is_set_bind
                            }
                            tag if tag == frontend_tag::EXECUTE => {
                                let portal = frame.execute_portal().unwrap_or("");
                                if portal.is_empty() {
                                    current_unnamed_portal_is_set
                                } else {
                                    set_portal_names.contains(&portal)
                                }
                            }
                            // FIX (P1 Describe/Close): Also filter Describe and
                            // Close that reference virtual SET objects so they
                            // don't reach the backend (which doesn't know them).
                            tag if tag == frontend_tag::DESCRIBE => {
                                frame.kind_and_name().is_some_and(|(kind, name)| {
                                    if name.is_empty() {
                                        (kind == b'S' && current_unnamed_is_set)
                                            || (kind == b'P' && current_unnamed_portal_is_set)
                                    } else {
                                        (kind == b'S' && set_stmt_names.contains(&name))
                                            || (kind == b'P' && set_portal_names.contains(&name))
                                    }
                                })
                            }
                            tag if tag == frontend_tag::CLOSE => {
                                frame.kind_and_name().is_some_and(|(kind, name)| {
                                    if name.is_empty() {
                                        (kind == b'S' && current_unnamed_is_set)
                                            || (kind == b'P' && current_unnamed_portal_is_set)
                                    } else {
                                        (kind == b'S' && set_stmt_names.contains(&name))
                                            || (kind == b'P' && set_portal_names.contains(&name))
                                    }
                                })
                            }
                            _ => false,
                        };
                        if should_skip {
                            set_frame_skip_indices.push(i);
                        }
                    }
                    // Find the next non-SET parse SQL for routing.
                    // FIX (Bug 2): Only override route_sql if the initial
                    // batch scan did NOT already determine that a Writer is
                    // required. Otherwise a batch like [Parse(SELECT),
                    // Parse(INSERT), Parse(SET)] would have route_sql reset
                    // to the SELECT, causing the INSERT to be routed to a
                    // Reader.
                    if !force_writer {
                        route_sql = batch
                            .iter()
                            .filter(|f| f.tag == frontend_tag::PARSE)
                            .filter_map(|f| f.parse_sql())
                            .find(|s| !session.state.is_consistency_set_command(s));
                        // Re-check sql_is_write for the new route_sql (in case
                        // the non-SET SQL is a write, seed write_detected later).
                        if let Some(new_sql) = route_sql {
                            if requires_writer(&classifier, new_sql) {
                                sql_is_write = true;
                            }
                        }
                    }

                    // FIX: If ALL frames in the batch were SET-related (no
                    // remaining forwarded frames), handle entirely locally.
                    // No need to acquire a backend connection.
                    if set_frame_skip_indices.len() == batch.len() {
                        // No backend interaction — apply SET commands immediately
                        // (no error is possible from a preceding statement).
                        for cmd in &pending_set_commands_nonheld {
                            session.state.apply_consistency_set_command(cmd);
                        }
                        use super::helpers::compute_synthetic_schedule;
                        let schedule = compute_synthetic_schedule(batch, &set_frame_skip_indices);
                        // schedule[0] contains all synthetic responses (since
                        // forwarded_count=0, there's only one slot).
                        if !schedule[0].is_empty() {
                            client_stream
                                .write_all(&schedule[0])
                                .await
                                .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                        }
                        send_ready_for_query(client_stream, session.state.tx_state).await?;
                        return Ok(());
                    }
                }
            }
        }

        // If no Parse in batch, look up the statement name referenced by
        // Bind/Describe(Statement) to find its previously recorded route
        // target. Execute references a *portal* (a separate namespace
        // created by Bind on a specific connection), so portal names are
        // deliberately not looked up here.
        //
        // FIX: Cross-Sync unnamed statement references are rejected by
        // default (PgBouncer behavior). The unnamed statement only exists
        // on the physical connection that executed the Parse; without
        // pinning that connection, a cross-Sync Bind("") would land on a
        // different backend. Rather than degrading transaction pooling to
        // session pooling (which would happen if we pinned on every
        // parameterized query), we return a protocol error. Well-behaved
        // drivers always send Parse+Bind+Execute in the same batch.
        let tracked_node = if route_sql.is_none() {
            // Check if this batch references the unnamed statement cross-Sync
            let references_unnamed_cross_sync = batch.iter().any(|frame| match frame.tag {
                frontend_tag::BIND => {
                    matches!(frame.bind_statement(), Some(stmt) if stmt.is_empty())
                }
                frontend_tag::DESCRIBE => {
                    matches!(frame.kind_and_name(), Some((b'S', name)) if name.is_empty())
                }
                _ => false,
            });

            if references_unnamed_cross_sync && session.unnamed_parse_node.is_some() {
                // Reject: unnamed statement Bind/Describe arrived in a
                // different batch from its Parse. This is unsupported in
                // transaction pooling mode (same as PgBouncer).
                return Err(ProxyError::Protocol(ProtocolError::Malformed(
                    "unnamed prepared statement cannot be referenced across Sync \
                     boundaries in transaction pooling mode. Ensure Parse, Bind, \
                     and Execute for unnamed statements are sent in the same message batch."
                        .into(),
                )));
            }

            // Named statement lookup
            batch.iter().find_map(|frame| match frame.tag {
                frontend_tag::BIND => match frame.bind_statement() {
                    Some(statement) if !statement.is_empty() => session
                        .extended_route_tracker
                        .route_for_statement(statement),
                    _ => None,
                },
                frontend_tag::DESCRIBE => match frame.kind_and_name() {
                    Some((b'S', name)) if !name.is_empty() => {
                        session.extended_route_tracker.route_for_statement(name)
                    }
                    _ => None,
                },
                _ => None,
            })
        } else {
            None
        };

        let (target_node_id, deferred_begin_sql) = if self.lsn_tracking.mode
            == LsnTrackingMode::AuroraWriteForwarding
        {
            // Aurora write forwarding pins every session to one Reader and
            // bypasses the Router entirely; extended batches must honor the
            // same binding or session consistency breaks.
            let all_nodes = self.pool_manager.snapshot();
            if let Some(node_id) = session.aurora_node_id.as_ref() {
                let still_available = all_nodes.iter().any(|node| {
                    node.node_id == *node_id && node.node_type == NodeType::Reader && node.healthy
                });
                if !still_available {
                    return Err(ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                        node_id.clone(),
                    )));
                }
                (node_id.clone(), None)
            } else {
                let selected = all_nodes
                    .iter()
                    .filter(|n| n.node_type == NodeType::Reader && n.healthy)
                    .min_by(|left, right| {
                        left.active_connections
                            .cmp(&right.active_connections)
                            .then_with(|| left.node_id.cmp(&right.node_id))
                    })
                    .map(|node| node.node_id.clone())
                    .ok_or_else(|| {
                        ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                            "Aurora Reader".to_string(),
                        ))
                    })?;
                session.aurora_node_id = Some(selected.clone());
                (selected, None)
            }
        } else if let Some(node_id) = tracked_node {
            // Named statement was previously parsed on this node: reuse that
            // route without touching the pool snapshot at all.
            //
            // FIX (Bug 1): The tracked_node fast path must still enforce
            // pending_write protection. If pending_write is set and the
            // tracked node is not a Writer, force routing to the Writer to
            // preserve session consistency guarantees. Without this check,
            // a Bind/Execute referencing a previously-parsed SELECT on a
            // Reader would bypass the pending_write guard entirely.
            let effective_node_id = if session.pending_write
                && session.state.consistency != ConsistencyLevel::Eventual
            {
                // Check if tracked node is a Reader by consulting the pool snapshot.
                let is_reader = self
                    .pool_manager
                    .snapshot()
                    .iter()
                    .any(|n| n.node_id == node_id && n.node_type != NodeType::Writer);
                if is_reader {
                    // Override to Writer.
                    self.pool_manager
                        .snapshot()
                        .iter()
                        .find(|n| n.node_type == NodeType::Writer && n.healthy)
                        .map(|n| n.node_id.clone())
                        .unwrap_or(node_id.clone())
                } else {
                    node_id
                }
            } else {
                node_id
            };

            // If a split transaction is pending, capture the deferred BEGIN.
            let begin = if session.state.tx_split.as_ref().is_some_and(|s| !s.active) {
                session
                    .state
                    .tx_split
                    .as_ref()
                    .map(|s| s.begin_sql().to_string())
            } else {
                None
            };
            (effective_node_id, begin)
        } else {
            // Route based on the SQL from Parse. The pool snapshot (which
            // clones every node's state) is only taken on this branch and
            // the Aurora branch above; the tracked-statement fast path
            // skips it entirely.
            let all_nodes = self.pool_manager.snapshot();
            let readers: Vec<_> = all_nodes
                .iter()
                .filter(|n| n.node_type == NodeType::Reader && n.healthy)
                .cloned()
                .collect();
            let analytics: Vec<_> = all_nodes
                .iter()
                .filter(|n| n.node_type == NodeType::Analytics && n.healthy)
                .cloned()
                .collect();
            let writers: Vec<_> = all_nodes
                .iter()
                .filter(|n| n.node_type == NodeType::Writer && n.healthy)
                .cloned()
                .collect();
            let sql_for_routing = route_sql.unwrap_or("SELECT 1");

            let session_write_lsn = self.lsn_tracker.session_write_lsn(&session.state.id);
            let global_write_lsn = self.lsn_tracker.global_write_lsn();
            let mut tx_split = session.state.tx_split.take();
            let split_was_pending = tx_split.as_ref().is_some_and(|state| !state.active);
            // Capture whether the held_backend fast-path already requested
            // an upgrade (need_upgrade=true) before the Router resets it.
            let pre_route_need_upgrade = tx_split.as_ref().is_some_and(|s| s.need_upgrade);
            let decision = {
                let mut ctx = RoutingContext {
                    tx_state: session.state.tx_state,
                    tx_split: &mut tx_split,
                    consistency: session.state.consistency,
                    session_write_lsn,
                    global_write_lsn,
                };
                self.router
                    .route(sql_for_routing, &mut ctx, &readers, &analytics, &writers)
                    .await
            };
            session.state.tx_split = tx_split;
            let mut decision = decision?;

            // Consistency protection: if a prior write is pending LSN
            // resolution and this read would go to a Reader, force it to
            // Writer (same logic as simple_query path). We skip the full
            // resolve_pending_write_lsn pipeline here because the extended
            // path does not have access to a spare backend for the internal
            // LSN query; instead, conservatively route to Writer until the
            // next simple-query cycle can resolve the watermark.
            if session.pending_write && decision.target != NodeType::Writer {
                decision.target = NodeType::Writer;
                decision.node_id = None;
                decision.fallback_to_writer = true;
                decision.reason = std::borrow::Cow::Borrowed(
                    "pending_write: forcing to Writer until LSN is resolved",
                );
            }

            // Capture deferred BEGIN SQL for split transactions that have
            // not yet opened a real backend transaction.
            let needs_begin =
                split_was_pending || decision.requires_split_upgrade || pre_route_need_upgrade;
            let deferred_begin_sql = if needs_begin {
                session
                    .state
                    .tx_split
                    .as_ref()
                    .map(|state| state.begin_sql().to_string())
            } else {
                None
            };

            let node_id = match decision.target {
                NodeType::Writer => all_nodes
                    .iter()
                    .find(|n| n.node_type == NodeType::Writer && n.healthy)
                    .map(|n| n.node_id.clone())
                    .unwrap_or_default(),
                _ => decision.node_id.unwrap_or_default(),
            };
            (node_id, deferred_begin_sql)
        };

        if target_node_id.is_empty() {
            return Err(ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                "no healthy backend for extended query".to_string(),
            )));
        }

        // Acquire a new connection (held_backend case handled by fast path above).
        let pool = self.resolve_pool(&target_node_id, session).ok_or_else(|| {
            ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                target_node_id.clone(),
            ))
        })?;
        let current_gen = self
            .connection_registry
            .map(|r| r.node_generation(&target_node_id));
        let mut conn = if let Some(mut cached) =
            session.take_cached_if_matches(&target_node_id, current_gen)
        {
            // Fast path: reuse the complete cached connection.
            cached.conn.take()
        } else {
            // Release any cached connection to a different node (or stale generation).
            self.release_cached_backend(session).await;
            pool.acquire(&session.state.id).await?
        };

        // Apply the audit label only when this physical connection's cache
        // differs. This standalone internal cycle runs only on cache misses;
        // unlike pipelining it guarantees the user batch is never executed
        // when the label could not be applied accurately.
        if let Err(error) = ensure_application_name(
            &mut conn,
            &session.application_name,
            TransactionStatus::Idle,
        )
        .await
        {
            pool.discard(conn)?;
            return Err(ProxyError::Protocol(error));
        }

        // A named prepared statement lives on this physical connection, not
        // on the node. In Transaction pool mode the connection would
        // otherwise be released and later Bind/Execute could land on a
        // different physical connection where the statement was never
        // prepared. Pin the connection to this session, exactly as the
        // Simple Query path does for PREPARE (Requirement 6.1).
        let creates_named_statement = batch.iter().any(frame_is_named_parse);
        if creates_named_statement && !conn.pinned {
            pool.pin(&session.state.id, &mut conn);
        }

        // Detect connection-pinning triggers in ALL Parse SQL within this
        // batch (not just named statements). This mirrors the simple-query
        // path's `detects_pinning_trigger()` call. Without this, extended
        // protocol SET search_path, LISTEN, CREATE TEMP TABLE, advisory
        // locks etc. would return the connection to the shared pool without
        // DISCARD ALL, leaking session state to other clients.
        let batch_pinning_trigger = batch.iter().find_map(|frame| {
            if frame.tag == frontend_tag::PARSE {
                frame.parse_sql().and_then(|sql| {
                    // Skip proxy-local SET consistency — it never reaches the
                    // backend and must not pin the connection unnecessarily.
                    if session.state.is_consistency_set_command(sql) {
                        return None;
                    }
                    detects_pinning_trigger(sql)
                })
            } else {
                None
            }
        });
        if batch_pinning_trigger.is_some() {
            conn.dirty = true;
            if !conn.pinned {
                pool.pin(&session.state.id, &mut conn);
            }
        }

        // Aurora write forwarding: initialize the consistency GUC once per
        // physical backend, mirroring the Simple Query Aurora path.
        if self.lsn_tracking.mode == LsnTrackingMode::AuroraWriteForwarding
            && session.aurora_initialized_backend_pid != Some(conn.backend_pid)
        {
            let init_sql = aurora_consistency_sql(session.state.consistency);
            if let Err(error) =
                execute_internal_query(&mut conn.stream, &init_sql, TransactionStatus::Idle).await
            {
                session.aurora_initialized_backend_pid = None;
                pool.discard(conn)?;
                return Err(ProxyError::Protocol(error));
            }
            session.aurora_initialized_backend_pid = Some(conn.backend_pid);
        }

        // Send the deferred BEGIN if this is the first statement in a
        // split transaction. The simple query path pipelines BEGIN before
        // the user SQL; here we must issue it as a separate internal query
        // because the extended protocol batch is forwarded verbatim and
        // cannot be prepended with a simple-query message.
        if let Some(ref begin_sql) = deferred_begin_sql {
            if let Err(error) = execute_internal_query(
                &mut conn.stream,
                begin_sql,
                TransactionStatus::InTransaction,
            )
            .await
            {
                pool.discard(conn)?;
                return Err(ProxyError::Protocol(error));
            }
            // FIX (Bug 5): Mark tx_split as active after successfully
            // sending BEGIN. Without this, the next batch entering the held
            // path would see `!split.active` and send BEGIN again.
            if let Some(ref mut s) = session.state.tx_split {
                s.active = true;
                let is_writer = self
                    .pool_manager
                    .snapshot()
                    .iter()
                    .any(|n| n.node_id == target_node_id && n.node_type == NodeType::Writer);
                s.on_reader = !is_writer;
            }
        }

        // Send all buffered raw frames + Sync to the backend in one write.
        // No re-encoding: the bytes the client sent are forwarded verbatim.
        //
        // FIX: If multi-Parse batch had SET frames, compute an interleaving
        // schedule so synthetic responses are emitted at the correct position
        // relative to backend responses (preserving protocol ordering).
        let synthetic_schedule = if !set_frame_skip_indices.is_empty() {
            use super::helpers::compute_synthetic_schedule;
            Some(compute_synthetic_schedule(batch, &set_frame_skip_indices))
        } else {
            None
        };
        let outbound = if set_frame_skip_indices.is_empty() {
            assemble_extended_outbound(batch)
        } else {
            use super::helpers::assemble_extended_outbound_filtered;
            assemble_extended_outbound_filtered(batch, &set_frame_skip_indices)
        };

        self.cancel_registry.mark_active(
            &session.state.id,
            &conn.node_id,
            conn.backend_pid,
            conn.secret_key,
        );

        // Emit any synthetic responses that precede all forwarded frames.
        if let Some(ref schedule) = synthetic_schedule {
            if !schedule[0].is_empty() {
                client_stream
                    .write_all(&schedule[0])
                    .await
                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
            }
        }

        if let Err(e) = conn.stream.write_all(&outbound).await {
            self.discard_backend(&pool, conn, &session.state.id)?;
            return Err(ProxyError::Protocol(e.into()));
        }
        if let Err(e) = conn.stream.flush().await {
            self.discard_backend(&pool, conn, &session.state.id)?;
            return Err(ProxyError::Protocol(e.into()));
        }

        // Relay backend responses until ReadyForQuery.
        let mut had_error = false;
        // FIX (Bug 6): Only pre-seed write_detected when the SQL is
        // semantically a write (e.g. SELECT setval(), SELECT lo_create()).
        // A ForceWriter routing hint on a pure SELECT must NOT create a
        // fake write watermark — it only affects routing, not LSN tracking.
        let mut write_detected = sql_is_write;
        // FIX: For cross-Sync batches (no Parse), also seed write_detected
        // if a Bind references a named statement known to contain write
        // function calls (setval, lo_create, etc.) whose CommandComplete
        // would only say "SELECT 1".
        if !write_detected {
            write_detected = batch.iter().any(|f| {
                f.tag == frontend_tag::BIND
                    && f.bind_statement()
                        .is_some_and(|stmt| session.write_function_stmts.contains(stmt))
            });
        }
        // FIX: For Execute-only batches (no Parse, no Bind), seed
        // write_detected if an Execute references a portal previously
        // bound to a write-function statement.
        if !write_detected {
            write_detected = batch.iter().any(|f| {
                f.tag == frontend_tag::EXECUTE
                    && f.execute_portal()
                        .is_some_and(|p| session.write_function_portals.contains(p))
            });
        }
        let mut commit_tag_seen = false;
        let mut reported_lsn: Option<u64> = None;
        let extension_guc_name = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            _ => None,
        };

        // Build the expected response-boundary sequence for forwarded frames
        // so we can inject synthetics at the correct positions.
        // Each forwarded frame type has a "terminating" response message:
        //   Parse('P')    → ParseComplete('1')
        //   Bind('B')     → BindComplete('2')
        //   Execute('E')  → CommandComplete('C') | EmptyQueryResponse('I') | PortalSuspended('s')
        //   Describe('D') → RowDescription('T') | NoData('n') | ParameterDescription('t' followed by 'T'/'n')
        //   Close('C')    → CloseComplete('3')
        // After an ErrorResponse, the backend skips remaining frames until
        // Sync, so we stop tracking boundaries on error.
        let forwarded_frame_tags: Vec<u8> = if synthetic_schedule.is_some() {
            batch
                .iter()
                .enumerate()
                .filter(|(i, _)| !set_frame_skip_indices.contains(i))
                .map(|(_, f)| f.tag)
                .collect()
        } else {
            Vec::new()
        };
        // Track which forwarded frame's response we're currently receiving.
        // Incremented when we see the boundary message for the current frame.
        let mut forwarded_response_idx: usize = 0;
        // For Describe frames, ParameterDescription is followed by
        // RowDescription or NoData — we need to wait for the second message.
        let mut _describe_awaiting_row_desc = false;

        let tx_status = loop {
            let (tag, body) = match read_tagged_frame(&mut conn.stream).await {
                Ok(frame) => frame,
                Err(e) => {
                    self.discard_backend(&pool, conn, &session.state.id)?;
                    // If we already forwarded a backend ErrorResponse to the
                    // client, wrap the error so the outer loop does not send
                    // a duplicate ErrorResponse.
                    let err = ProxyError::Protocol(e);
                    if had_error {
                        return Err(ProxyError::BackendErrorAlreadyRelayed(Box::new(err)));
                    }
                    return Err(err);
                }
            };

            match tag {
                b'Z' => {
                    // ReadyForQuery: extract status, do NOT relay (handler sends its own).
                    // Reject malformed ReadyForQuery (body must be exactly 1 byte
                    // containing I/T/E). Invalid bytes previously degraded to Idle,
                    // which could return a connection in unknown state to the pool.
                    if body.len() != 1 {
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(ProxyError::Protocol(ProtocolError::Malformed(
                            "ReadyForQuery body length is not 1".into(),
                        )));
                    }
                    let status = match TransactionStatus::from_byte(body[0]) {
                        Some(s) => s,
                        None => {
                            self.discard_backend(&pool, conn, &session.state.id)?;
                            return Err(ProxyError::Protocol(ProtocolError::Malformed(format!(
                                "ReadyForQuery invalid status byte: 0x{:02x}",
                                body[0]
                            ))));
                        }
                    };
                    break status;
                }
                b'C' => {
                    // CommandComplete: check for write tags and COMMIT.
                    let cmd_tag = extract_cstring_from_body(&body);
                    if is_write_command_tag(&cmd_tag) {
                        write_detected = true;
                    }
                    if cmd_tag == "COMMIT" {
                        commit_tag_seen = true;
                    }
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(e);
                    }
                    // CommandComplete is a boundary for Execute frames.
                    if !had_error {
                        if let Some(&cur_tag) = forwarded_frame_tags.get(forwarded_response_idx) {
                            if cur_tag == frontend_tag::EXECUTE {
                                forwarded_response_idx += 1;
                                if let Some(ref schedule) = synthetic_schedule {
                                    if let Some(syn) = schedule.get(forwarded_response_idx) {
                                        if !syn.is_empty() {
                                            client_stream.write_all(syn).await.map_err(|e| {
                                                ProxyError::Protocol(ProtocolError::Io(e))
                                            })?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                b'E' => {
                    // ErrorResponse: after this, backend skips remaining
                    // frames until Sync. Stop boundary tracking.
                    had_error = true;
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(e);
                    }
                    // On error, all remaining synthetics (if any) are
                    // effectively cancelled — the client will see RFQ('E')
                    // next and knows the batch failed. Move idx to end.
                    if synthetic_schedule.is_some() {
                        forwarded_response_idx = forwarded_frame_tags.len();
                    }
                }
                b'G' => {
                    // COPY ... FROM STDIN via the extended protocol: relay
                    // CopyInResponse, then switch to relaying the client's
                    // copy stream to the backend until CopyDone/CopyFail.
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(e);
                    }
                    if let Err(e) = client_stream.flush().await {
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(ProxyError::Protocol(ProtocolError::Io(e)));
                    }
                    let copy_result = relay_copy_in_stream_with_timeout(
                        &mut conn.stream,
                        client_stream,
                        self.client_idle_timeout,
                    )
                    .await;
                    // The Sync pipelined behind Execute was consumed and
                    // ignored by the backend while in copy-in mode (per
                    // protocol spec); send a fresh one or ReadyForQuery
                    // never arrives.
                    let sync_result = match copy_result {
                        Ok(()) => conn
                            .stream
                            .write_all(&[b'S', 0, 0, 0, 4])
                            .await
                            .map_err(ProtocolError::Io),
                        Err(e) => Err(e),
                    };
                    if let Err(e) = sync_result {
                        // Mid-copy failure leaves the backend in copy-in
                        // state; this connection must not be reused.
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(ProxyError::Protocol(e));
                    }
                }
                b'S' if extension_guc_name.is_some() => {
                    // ParameterStatus: check if it's the extension LSN GUC.
                    // Capture the LSN value and suppress the message from
                    // reaching the client (it's an internal implementation
                    // detail of the pg_lsn_track extension).
                    let (name, value) = extract_two_cstrings_from_body(&body);
                    if Some(name.as_str()) == extension_guc_name {
                        reported_lsn = crate::health::parse_lsn(&value);
                    } else if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(e);
                    }
                }
                b'I' => {
                    // EmptyQueryResponse: boundary for Execute (empty query string).
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(e);
                    }
                    if !had_error {
                        if let Some(&cur_tag) = forwarded_frame_tags.get(forwarded_response_idx) {
                            if cur_tag == frontend_tag::EXECUTE {
                                forwarded_response_idx += 1;
                                if let Some(ref schedule) = synthetic_schedule {
                                    if let Some(syn) = schedule.get(forwarded_response_idx) {
                                        if !syn.is_empty() {
                                            client_stream.write_all(syn).await.map_err(|e| {
                                                ProxyError::Protocol(ProtocolError::Io(e))
                                            })?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                b's' => {
                    // PortalSuspended: boundary for Execute (max rows reached).
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(e);
                    }
                    if !had_error {
                        if let Some(&cur_tag) = forwarded_frame_tags.get(forwarded_response_idx) {
                            if cur_tag == frontend_tag::EXECUTE {
                                forwarded_response_idx += 1;
                                if let Some(ref schedule) = synthetic_schedule {
                                    if let Some(syn) = schedule.get(forwarded_response_idx) {
                                        if !syn.is_empty() {
                                            client_stream.write_all(syn).await.map_err(|e| {
                                                ProxyError::Protocol(ProtocolError::Io(e))
                                            })?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {
                    // Everything else (ParseComplete, BindComplete, DataRow,
                    // RowDescription, NoData, ParameterDescription,
                    // CloseComplete, NoticeResponse, etc.): relay raw.
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(e);
                    }
                    // Check boundary conditions for non-Execute frames.
                    if !had_error && synthetic_schedule.is_some() {
                        if let Some(&cur_tag) = forwarded_frame_tags.get(forwarded_response_idx) {
                            let is_boundary = match tag {
                                b'1' => cur_tag == frontend_tag::PARSE, // ParseComplete
                                b'2' => cur_tag == frontend_tag::BIND,  // BindComplete
                                b'3' => cur_tag == frontend_tag::CLOSE, // CloseComplete
                                b'T' => {
                                    // RowDescription: boundary for Describe
                                    // (either Statement or Portal). Also
                                    // concludes ParameterDescription sequence.
                                    _describe_awaiting_row_desc = false;
                                    cur_tag == frontend_tag::DESCRIBE
                                }
                                b'n' => {
                                    // NoData: boundary for Describe when the
                                    // statement has no result columns.
                                    _describe_awaiting_row_desc = false;
                                    cur_tag == frontend_tag::DESCRIBE
                                }
                                b't' => {
                                    // ParameterDescription: for Describe('S'),
                                    // this precedes RowDescription/NoData.
                                    // NOT a boundary by itself.
                                    _describe_awaiting_row_desc = true;
                                    false
                                }
                                _ => false,
                            };
                            if is_boundary {
                                forwarded_response_idx += 1;
                                if let Some(ref schedule) = synthetic_schedule {
                                    if let Some(syn) = schedule.get(forwarded_response_idx) {
                                        if !syn.is_empty() {
                                            client_stream.write_all(syn).await.map_err(|e| {
                                                ProxyError::Protocol(ProtocolError::Io(e))
                                            })?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };
        self.cancel_registry.clear_active(&session.state.id);

        // Update session transaction state.
        session.state.tx_state = apply_ready_for_query(tx_status);

        // FIX (Bug 3): Apply deferred SET commands only if the batch
        // succeeded. If any preceding statement errored, the SET was never
        // truly executed, so session state must remain unchanged.
        if !had_error {
            for cmd in &pending_set_commands_nonheld {
                session.state.apply_consistency_set_command(cmd);
            }
        }

        // Record named statement routes for future batches, and clean up
        // on Close. Only process if the batch succeeded (no error).
        if !had_error {
            record_statement_routes(session, batch, &conn.node_id, &set_frame_skip_indices);
            // Track unnamed Parse: if this batch contained a Parse with an
            // empty name, record the node so subsequent Bind("") across
            // Sync boundaries can find the correct physical connection.
            update_unnamed_parse_tracking(session, batch, &conn.node_id);
        }

        // Track writes for LSN watermark. Two cases:
        // (a) Autocommit write or combined batch containing write+COMMIT:
        //     write_detected=true, tx_status=Idle.
        // (b) Explicit COMMIT after prior writes in earlier batches:
        //     write_detected=false, tx_has_writes=true, commit_tag_seen=true.
        // Eventual consistency never needs LSN tracking (Issue #1 fix).
        let committed_write = !had_error
            && tx_status == TransactionStatus::Idle
            && (write_detected || (session.tx_has_writes && commit_tag_seen));
        if committed_write && session.state.consistency != ConsistencyLevel::Eventual {
            session.pending_write = true;
        }
        // Extension LSN capture: if the extension GUC reported an LSN during
        // this batch, apply it to the session's LSN tracker immediately
        // (same behavior as the simple-query path). This avoids the
        // pending_write fallback pipeline query on the next read.
        if let Some(lsn) = reported_lsn {
            if committed_write {
                self.lsn_tracker.record_write(&session.state.id, lsn);
                session.pending_write = false;
                session.extension_detected = true;
            }
        }
        if write_detected && !had_error && tx_status == TransactionStatus::InTransaction {
            session.tx_has_writes = true;
        }
        if tx_status == TransactionStatus::Idle {
            session.tx_has_writes = false;
        }
        if batch_pinning_trigger.is_some() && !had_error {
            conn.current_application_name = None;
        }

        // Return or hold the backend connection.
        if session.state.tx_state != TxState::Idle || conn.pinned {
            session.held_backend = Some(HeldBackend {
                conn: OwnedConn::new(conn, Some(Arc::clone(&pool))),
                source_pool: Some(Arc::clone(&pool)),
            });
        } else if conn.dirty {
            // Dirty connections cannot be cached — release runs the cleaner.
            pool.release(&session.state.id, conn).await?;
        } else {
            // Cache for reuse by the next query in this session.
            session.cached_idle_backend = Some(HeldBackend {
                conn: OwnedConn::new(conn, Some(Arc::clone(&pool))),
                source_pool: Some(Arc::clone(&pool)),
            });
        }

        send_ready_for_query(client_stream, session.state.tx_state).await
    }

    /// Fast-path for extended query batches when a backend is already held
    /// (pinned connection or in-transaction). Skips routing, snapshot, and
    /// pool acquire/release — just forwards the batch and updates session
    /// state. Mirrors `forward_on_held_backend` for simple queries.
    async fn forward_extended_on_held_backend<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        batch: &[ExtendedFrame],
        set_skip_indices: &[usize],
        pending_set_commands: &[String],
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let expected_status = transaction_status_for_state(session.state.tx_state);
        let appname_result = {
            let held = session.held_backend.as_mut().expect("checked by caller");
            ensure_application_name(&mut held.conn, &session.application_name, expected_status)
                .await
        };
        if let Err(error) = appname_result {
            let mut held = session.held_backend.take().expect("checked by caller");
            if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, session) {
                let _ = pool.discard(held.conn.take());
            }
            return Err(ProxyError::Protocol(error));
        }

        let held = session.held_backend.as_mut().expect("checked by caller");

        // Send all buffered raw frames + Sync to the backend in one write.
        // No re-encoding: the bytes the client sent are forwarded verbatim.
        //
        // FIX: If multi-Parse batch had SET frames, compute an interleaving
        // schedule so synthetic responses are emitted at the correct position
        // relative to backend responses (preserving protocol ordering).
        let synthetic_schedule = if !set_skip_indices.is_empty() {
            use super::helpers::compute_synthetic_schedule;
            Some(compute_synthetic_schedule(batch, set_skip_indices))
        } else {
            None
        };
        let outbound = if set_skip_indices.is_empty() {
            assemble_extended_outbound(batch)
        } else {
            use super::helpers::assemble_extended_outbound_filtered;
            assemble_extended_outbound_filtered(batch, set_skip_indices)
        };

        self.cancel_registry.mark_active(
            &session.state.id,
            &held.conn.node_id,
            held.conn.backend_pid,
            held.conn.secret_key,
        );

        // Emit any synthetic responses that precede all forwarded frames.
        if let Some(ref schedule) = synthetic_schedule {
            if !schedule[0].is_empty() {
                client_stream
                    .write_all(&schedule[0])
                    .await
                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
            }
        }

        if let Err(e) = held.conn.stream.write_all(&outbound).await {
            self.discard_held_backend(session);
            return Err(ProxyError::Protocol(e.into()));
        }
        if let Err(e) = held.conn.stream.flush().await {
            self.discard_held_backend(session);
            return Err(ProxyError::Protocol(e.into()));
        }

        // Relay backend responses until ReadyForQuery.
        let mut had_error = false;
        // Pre-detect write function calls (setval, lo_*, etc.) in Parse SQL
        // so pending_write is correctly recorded even when CommandComplete
        // just says "SELECT 1". Mirrors the non-held path's force_writer
        // initialization.
        // FIX (Bug 5): Only count Parse frames that have a matching
        // Bind+Execute in this batch — Parse-only (preparation without
        // execution) should not seed write_detected.
        let mut write_detected = batch
            .iter()
            .enumerate()
            .filter(|(i, _)| !set_skip_indices.contains(i))
            .any(|(_, frame)| {
                if frame.tag == frontend_tag::PARSE {
                    if let Some(sql) = frame.parse_sql() {
                        if !requires_writer(&KeywordClassifier, sql) {
                            return false;
                        }
                        // Check if there's a matching Bind+Execute for this Parse.
                        let stmt_name = frame.parse_name().unwrap_or("");
                        let has_bind = batch.iter().any(|f| {
                            f.tag == frontend_tag::BIND && f.bind_statement() == Some(stmt_name)
                        });
                        return has_bind;
                    }
                }
                false
            });
        // FIX: Also check write_function_stmts for cross-Sync batches.
        if !write_detected {
            write_detected = batch.iter().any(|f| {
                f.tag == frontend_tag::BIND
                    && f.bind_statement()
                        .is_some_and(|stmt| session.write_function_stmts.contains(stmt))
            });
        }
        // FIX: For Execute-only batches, check write_function_portals.
        if !write_detected {
            write_detected = batch.iter().any(|f| {
                f.tag == frontend_tag::EXECUTE
                    && f.execute_portal()
                        .is_some_and(|p| session.write_function_portals.contains(p))
            });
        }
        let mut commit_tag_seen = false;
        let mut reported_lsn: Option<u64> = None;
        let extension_guc_name = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            _ => None,
        };

        // Build expected response-boundary sequence for forwarded frames.
        let forwarded_frame_tags: Vec<u8> = if synthetic_schedule.is_some() {
            batch
                .iter()
                .enumerate()
                .filter(|(i, _)| !set_skip_indices.contains(i))
                .map(|(_, f)| f.tag)
                .collect()
        } else {
            Vec::new()
        };
        let mut forwarded_response_idx: usize = 0;
        let mut _describe_awaiting_row_desc = false;

        let tx_status = loop {
            let (tag, body) = match read_tagged_frame(&mut held.conn.stream).await {
                Ok(frame) => frame,
                Err(e) => {
                    self.discard_held_backend(session);
                    let err = ProxyError::Protocol(e);
                    if had_error {
                        return Err(ProxyError::BackendErrorAlreadyRelayed(Box::new(err)));
                    }
                    return Err(err);
                }
            };

            match tag {
                b'Z' => {
                    // Strict ReadyForQuery validation (same as non-held path).
                    if body.len() != 1 {
                        self.discard_held_backend(session);
                        return Err(ProxyError::Protocol(ProtocolError::Malformed(
                            "ReadyForQuery body length is not 1".into(),
                        )));
                    }
                    let status = match TransactionStatus::from_byte(body[0]) {
                        Some(s) => s,
                        None => {
                            self.discard_held_backend(session);
                            return Err(ProxyError::Protocol(ProtocolError::Malformed(format!(
                                "ReadyForQuery invalid status byte: 0x{:02x}",
                                body[0]
                            ))));
                        }
                    };
                    break status;
                }
                b'C' => {
                    let cmd_tag = extract_cstring_from_body(&body);
                    if is_write_command_tag(&cmd_tag) {
                        write_detected = true;
                    }
                    if cmd_tag == "COMMIT" {
                        commit_tag_seen = true;
                    }
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_held_backend(session);
                        return Err(e);
                    }
                    // CommandComplete is a boundary for Execute frames.
                    if !had_error {
                        if let Some(&cur_tag) = forwarded_frame_tags.get(forwarded_response_idx) {
                            if cur_tag == frontend_tag::EXECUTE {
                                forwarded_response_idx += 1;
                                if let Some(ref schedule) = synthetic_schedule {
                                    if let Some(syn) = schedule.get(forwarded_response_idx) {
                                        if !syn.is_empty() {
                                            client_stream.write_all(syn).await.map_err(|e| {
                                                ProxyError::Protocol(ProtocolError::Io(e))
                                            })?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                b'E' => {
                    had_error = true;
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_held_backend(session);
                        return Err(e);
                    }
                    if synthetic_schedule.is_some() {
                        forwarded_response_idx = forwarded_frame_tags.len();
                    }
                }
                b'G' => {
                    // COPY ... FROM STDIN on the held backend: same handling
                    // as the non-held path (see handle_extended_query_batch).
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_held_backend(session);
                        return Err(e);
                    }
                    if let Err(e) = client_stream.flush().await {
                        self.discard_held_backend(session);
                        return Err(ProxyError::Protocol(ProtocolError::Io(e)));
                    }
                    let copy_result = relay_copy_in_stream_with_timeout(
                        &mut held.conn.stream,
                        client_stream,
                        self.client_idle_timeout,
                    )
                    .await;
                    let sync_result = match copy_result {
                        Ok(()) => held
                            .conn
                            .stream
                            .write_all(&[b'S', 0, 0, 0, 4])
                            .await
                            .map_err(ProtocolError::Io),
                        Err(e) => Err(e),
                    };
                    if let Err(e) = sync_result {
                        self.discard_held_backend(session);
                        return Err(ProxyError::Protocol(e));
                    }
                }
                b'S' if extension_guc_name.is_some() => {
                    // ParameterStatus: capture extension LSN GUC, suppress
                    // from client (same as simple-query and non-held extended path).
                    let (name, value) = extract_two_cstrings_from_body(&body);
                    if Some(name.as_str()) == extension_guc_name {
                        reported_lsn = crate::health::parse_lsn(&value);
                    } else if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_held_backend(session);
                        return Err(e);
                    }
                }
                b'I' => {
                    // EmptyQueryResponse: boundary for Execute.
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_held_backend(session);
                        return Err(e);
                    }
                    if !had_error {
                        if let Some(&cur_tag) = forwarded_frame_tags.get(forwarded_response_idx) {
                            if cur_tag == frontend_tag::EXECUTE {
                                forwarded_response_idx += 1;
                                if let Some(ref schedule) = synthetic_schedule {
                                    if let Some(syn) = schedule.get(forwarded_response_idx) {
                                        if !syn.is_empty() {
                                            client_stream.write_all(syn).await.map_err(|e| {
                                                ProxyError::Protocol(ProtocolError::Io(e))
                                            })?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                b's' => {
                    // PortalSuspended: boundary for Execute.
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_held_backend(session);
                        return Err(e);
                    }
                    if !had_error {
                        if let Some(&cur_tag) = forwarded_frame_tags.get(forwarded_response_idx) {
                            if cur_tag == frontend_tag::EXECUTE {
                                forwarded_response_idx += 1;
                                if let Some(ref schedule) = synthetic_schedule {
                                    if let Some(syn) = schedule.get(forwarded_response_idx) {
                                        if !syn.is_empty() {
                                            client_stream.write_all(syn).await.map_err(|e| {
                                                ProxyError::Protocol(ProtocolError::Io(e))
                                            })?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_held_backend(session);
                        return Err(e);
                    }
                    // Check boundary conditions for non-Execute frames.
                    if !had_error && synthetic_schedule.is_some() {
                        if let Some(&cur_tag) = forwarded_frame_tags.get(forwarded_response_idx) {
                            let is_boundary = match tag {
                                b'1' => cur_tag == frontend_tag::PARSE,
                                b'2' => cur_tag == frontend_tag::BIND,
                                b'3' => cur_tag == frontend_tag::CLOSE,
                                b'T' => {
                                    _describe_awaiting_row_desc = false;
                                    cur_tag == frontend_tag::DESCRIBE
                                }
                                b'n' => {
                                    _describe_awaiting_row_desc = false;
                                    cur_tag == frontend_tag::DESCRIBE
                                }
                                b't' => {
                                    _describe_awaiting_row_desc = true;
                                    false
                                }
                                _ => false,
                            };
                            if is_boundary {
                                forwarded_response_idx += 1;
                                if let Some(ref schedule) = synthetic_schedule {
                                    if let Some(syn) = schedule.get(forwarded_response_idx) {
                                        if !syn.is_empty() {
                                            client_stream.write_all(syn).await.map_err(|e| {
                                                ProxyError::Protocol(ProtocolError::Io(e))
                                            })?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };
        self.cancel_registry.clear_active(&session.state.id);

        // Update session transaction state.
        session.state.tx_state = apply_ready_for_query(tx_status);

        // FIX (Bug 3): Apply deferred SET commands only if the batch
        // succeeded. If any preceding statement errored, the SET was never
        // truly executed, so session state must remain unchanged.
        if !had_error {
            for cmd in pending_set_commands {
                session.state.apply_consistency_set_command(cmd);
            }
        }

        // Named statements created on the held connection require the same
        // treatment as on the non-held path: pin the physical connection so
        // it outlives the transaction (the statement lives on this exact
        // connection), and record/forget statement routes for future
        // batches. Skipping this made in-transaction PREPARE-style usage
        // fail after COMMIT with "prepared statement does not exist".
        if !had_error {
            let creates_named_statement = batch.iter().any(frame_is_named_parse);
            // Also detect pinning triggers in Parse SQL (SET, LISTEN, etc.)
            let batch_pinning_trigger = batch.iter().find_map(|frame| {
                if frame.tag == frontend_tag::PARSE {
                    frame.parse_sql().and_then(detects_pinning_trigger)
                } else {
                    None
                }
            });
            if creates_named_statement || batch_pinning_trigger.is_some() {
                let held = session.held_backend.as_mut().expect("checked by caller");
                if batch_pinning_trigger.is_some() {
                    held.conn.dirty = true;
                    held.conn.current_application_name = None;
                }
                if !held.conn.pinned {
                    let node_id = held.conn.node_id.clone();
                    if let Some(pool) = self.resolve_pool_existing(&node_id, session) {
                        let held = session.held_backend.as_mut().expect("checked");
                        pool.pin(&session.state.id, &mut held.conn);
                    }
                }
            }
            let held_node_id = session
                .held_backend
                .as_ref()
                .expect("checked by caller")
                .conn
                .node_id
                .clone();
            record_statement_routes(session, batch, &held_node_id, set_skip_indices);
            update_unnamed_parse_tracking(session, batch, &held_node_id);
        }

        // Track writes for LSN watermark (same logic as full path).
        let committed_write = !had_error
            && tx_status == TransactionStatus::Idle
            && (write_detected || (session.tx_has_writes && commit_tag_seen));
        if committed_write && session.state.consistency != ConsistencyLevel::Eventual {
            session.pending_write = true;
        }
        // Extension LSN capture (same as non-held path).
        if let Some(lsn) = reported_lsn {
            if committed_write {
                self.lsn_tracker.record_write(&session.state.id, lsn);
                session.pending_write = false;
                session.extension_detected = true;
            }
        }
        if write_detected && !had_error && tx_status == TransactionStatus::InTransaction {
            session.tx_has_writes = true;
        }
        if tx_status == TransactionStatus::Idle {
            session.tx_has_writes = false;
        }

        // Release backend if transaction ended and connection isn't pinned.
        if session.state.tx_state == TxState::Idle {
            let held = session.held_backend.as_ref().unwrap();
            if !held.conn.pinned {
                let mut held = session.held_backend.take().unwrap();
                // Keep unnamed_parse_node set: the unnamed statement was
                // parsed on this connection which is now returning to the
                // pool. A cross-Sync Bind("") must be rejected since a
                // different connection may be acquired next time.
                let pool = self
                    .resolve_pool_existing(&held.conn.node_id, session)
                    .ok_or_else(|| {
                        ProxyError::Pool(crate::pool::pool::PoolError::CleanupFailed(format!(
                            "pool for '{}' no longer exists",
                            held.conn.node_id
                        )))
                    })?;
                pool.release(&session.state.id, held.conn.take()).await?;
            }
        }

        send_ready_for_query(client_stream, session.state.tx_state).await
    }
}
