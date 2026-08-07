//! Extended query protocol handling.
//!
//! Contains `handle_extended_query_batch` and `forward_extended_on_held_backend`,
//! which process Parse/Bind/Execute/Sync message batches.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::config::{ConsistencyLevel, LsnTrackingMode, NodeType};
use crate::parser::classifier::{requires_writer, KeywordClassifier};
use crate::pool::pinning::detects_pinning_trigger;
use crate::protocol::message::{PgError, TransactionStatus};
use crate::protocol::reader::{frontend_tag, read_tagged_frame};
use crate::protocol::ProtocolError;
use crate::proxy::error::ProxyError;
use crate::proxy::forwarder::{apply_ready_for_query, is_write_command_tag, relay_copy_in_stream_with_timeout};
use crate::router::router::RoutingContext;
use crate::session::session::TxState;

use super::helpers::{
    assemble_extended_outbound, aurora_consistency_sql, ensure_application_name,
    execute_internal_query, extract_cstring_from_body, extract_two_cstrings_from_body,
    frame_is_named_parse, record_statement_routes, send_pg_error_response, send_ready_for_query,
    transaction_status_for_state, update_unnamed_parse_tracking, write_raw_frame_to,
};
use super::{ClientSession, ConnectionHandler, ExtendedFrame, HeldBackend, RouteFn};
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
        if session.state.tx_state == TxState::Failed && session.held_backend.is_none() {
            let error = PgError::simple(
                "ERROR",
                "25P02",
                "current transaction is aborted, commands ignored until end of transaction block",
            );
            send_pg_error_response(client_stream, error).await?;
            send_ready_for_query(client_stream, TxState::Failed).await?;
            return Ok(());
        }

        // Fast path: if a backend is already held (pinned connection or
        // in-transaction), skip routing/snapshot entirely and reuse it.
        if session.held_backend.is_some() {
            return self
                .forward_extended_on_held_backend(client_stream, session, batch)
                .await;
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
        let classifier = KeywordClassifier;
        let hint_parser = crate::parser::hint::RegexHintParser;
        use crate::parser::hint::{HintParser as _, RouteHint};
        for frame in batch.iter().filter(|f| f.tag == frontend_tag::PARSE) {
            let sql = frame.parse_sql().ok_or_else(|| {
                ProxyError::Protocol(ProtocolError::Malformed(
                    "Parse message missing statement name or query C-string".into(),
                ))
            })?;
            if route_sql.is_none() {
                route_sql = Some(sql);
            }
            // Check SQL classification
            if requires_writer(&classifier, sql) {
                route_sql = Some(sql);
                force_writer = true;
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
                    }
                    RouteHint::ForceReader
                        if !requires_writer(&classifier, route_sql.unwrap_or("")) =>
                    {
                        // Only set route_sql to ForceReader SQL if we haven't
                        // already committed to a Writer-bound SQL.
                        route_sql = Some(sql);
                    }
                    _ => {}
                }
            }
        }

        // Intercept `SET trident.consistency = '...'` in extended protocol.
        // Like the simple query path, this is a proxy-local setting that
        // should not reach the backend. If the only Parse SQL in the batch
        // is a consistency SET, handle it locally and return synthetic
        // ParseComplete + BindComplete + CommandComplete + ReadyForQuery.
        if let Some(sql) = route_sql {
            if session.state.tx_state != TxState::Failed
                && session.state.apply_consistency_set_command(sql)
            {
                use crate::protocol::writer::encode_backend_message;
                use crate::protocol::message::BackendMessage;
                // Send ParseComplete ('1'), BindComplete ('2'), CommandComplete, RFQ
                let parse_complete = [b'1', 0, 0, 0, 4];
                let bind_complete = [b'2', 0, 0, 0, 4];
                let cmd_complete = encode_backend_message(&BackendMessage::CommandComplete {
                    tag: "SET".to_string(),
                });
                client_stream.write_all(&parse_complete).await
                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                client_stream.write_all(&bind_complete).await
                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                client_stream.write_all(&cmd_complete).await
                    .map_err(|e| ProxyError::Protocol(ProtocolError::Io(e)))?;
                send_ready_for_query(client_stream, session.state.tx_state).await?;
                return Ok(());
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

        let (target_node_id, deferred_begin_sql) = if self.lsn_tracking.mode == LsnTrackingMode::AuroraWriteForwarding {
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
            // If a split transaction is pending, capture the deferred BEGIN.
            let begin = if session.state.tx_split.as_ref().is_some_and(|s| !s.active) {
                session.state.tx_split.as_ref().map(|s| s.begin_sql().to_string())
            } else {
                None
            };
            (node_id, begin)
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
            let deferred_begin_sql = if split_was_pending || decision.requires_split_upgrade {
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
        let current_gen = self.connection_registry.map(|r| r.node_generation(&target_node_id));
        let mut conn = if let Some(cached) = session.take_cached_if_matches(&target_node_id, current_gen) {
            // Fast path: reuse the complete cached connection.
            cached.conn
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
                frame.parse_sql().and_then(detects_pinning_trigger)
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
        }

        // Send all buffered raw frames + Sync to the backend in one write.
        // No re-encoding: the bytes the client sent are forwarded verbatim.
        let outbound = assemble_extended_outbound(batch);

        self.cancel_registry.mark_active(
            &session.state.id,
            &conn.node_id,
            conn.backend_pid,
            conn.secret_key,
        );

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
        let mut write_detected = false;
        let mut commit_tag_seen = false;
        let mut reported_lsn: Option<u64> = None;
        let extension_guc_name = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            _ => None,
        };
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
                }
                b'E' => {
                    // ErrorResponse.
                    had_error = true;
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(e);
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
                    ).await;
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
                _ => {
                    // Everything else (ParseComplete, BindComplete, DataRow,
                    // RowDescription, NoData, ParameterDescription,
                    // CloseComplete, NoticeResponse, etc.): relay raw.
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_backend(&pool, conn, &session.state.id)?;
                        return Err(e);
                    }
                }
            }
        };
        self.cancel_registry.clear_active(&session.state.id);

        // Update session transaction state.
        session.state.tx_state = apply_ready_for_query(tx_status);

        // Record named statement routes for future batches, and clean up
        // on Close. Only process if the batch succeeded (no error).
        if !had_error {
            record_statement_routes(session, batch, &conn.node_id);
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
            session.held_backend = Some(HeldBackend { conn, source_pool: Some(Arc::clone(&pool)) });
        } else if conn.dirty {
            // Dirty connections cannot be cached — release runs the cleaner.
            pool.release(&session.state.id, conn).await?;
        } else {
            // Cache for reuse by the next query in this session.
            session.cached_idle_backend = Some(HeldBackend { conn, source_pool: Some(Arc::clone(&pool)) });
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
            let held = session.held_backend.take().expect("checked by caller");
            if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, session) {
                let _ = pool.discard(held.conn);
            }
            return Err(ProxyError::Protocol(error));
        }

        let held = session.held_backend.as_mut().expect("checked by caller");

        // Send all buffered raw frames + Sync to the backend in one write.
        // No re-encoding: the bytes the client sent are forwarded verbatim.
        let outbound = assemble_extended_outbound(batch);

        self.cancel_registry.mark_active(
            &session.state.id,
            &held.conn.node_id,
            held.conn.backend_pid,
            held.conn.secret_key,
        );

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
        let mut write_detected = false;
        let mut commit_tag_seen = false;
        let mut reported_lsn: Option<u64> = None;
        let extension_guc_name = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            _ => None,
        };
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
                }
                b'E' => {
                    had_error = true;
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_held_backend(session);
                        return Err(e);
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
                    let copy_result =
                        relay_copy_in_stream_with_timeout(
                            &mut held.conn.stream,
                            client_stream,
                            self.client_idle_timeout,
                        ).await;
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
                _ => {
                    if let Err(e) = write_raw_frame_to(client_stream, tag, &body).await {
                        self.discard_held_backend(session);
                        return Err(e);
                    }
                }
            }
        };
        self.cancel_registry.clear_active(&session.state.id);

        // Update session transaction state.
        session.state.tx_state = apply_ready_for_query(tx_status);

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
            record_statement_routes(session, batch, &held_node_id);
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
                let held = session.held_backend.take().unwrap();
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
                pool.release(&session.state.id, held.conn).await?;
            }
        }

        send_ready_for_query(client_stream, session.state.tx_state).await
    }
}
