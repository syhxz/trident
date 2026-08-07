//! Simple query protocol handling.
//!
//! Contains `handle_simple_query`, `handle_simple_query_inner`,
//! `forward_on_held_backend`, `handle_aurora_simple_query`,
//! `resolve_pending_write_lsn`, and `finish_active_split_transaction`.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::config::{ConsistencyLevel, LsnTrackingMode, NodeType, PoolMode};
use crate::pool::pinning::detects_pinning_trigger;
use crate::protocol::message::{BackendMessage, PgError, TransactionStatus};
use crate::protocol::writer::encode_backend_message;
use crate::protocol::ProtocolError;
use crate::proxy::error::ProxyError;
use crate::proxy::forwarder::{
    apply_ready_for_query, fetch_current_wal_lsn, forward_simple_query,
    forward_simple_query_with_options, QueryForwardOptions,
};
use crate::router::router::{RouteDecision, RoutingContext};
use crate::session::session::TxState;
use crate::session::transaction::{parse_begin_options, transaction_end_tag, TxSplitState};

use super::helpers::{
    aurora_consistency_sql, ensure_application_name, execute_internal_query, pipeline_safe_sql,
    query_has_write_intent, send_command_complete, send_pg_error_response, send_ready_for_query,
    transaction_status_for_state,
};
use super::{ClientSession, ConnectionHandler, HeldBackend, RouteFn};
use crate::pool::manager::PoolManager;
use crate::session::lsn::LsnTracker;

impl<'a, RTR, PM, LSN> ConnectionHandler<'a, RTR, PM, LSN>
where
    RTR: RouteFn,
    PM: PoolManager,
    LSN: LsnTracker,
{
    /// Times and logs one simple-query statement (Requirement: wire up
    /// `config.logging.query_trace`/`slow_query`, see `QueryLogSettings`
    /// docs), then delegates the actual routing/forwarding work to
    /// `handle_simple_query_inner`. Kept as a thin wrapper around the
    /// inner method (rather than threading timing through every early
    /// `?` return inside it) so the existing control flow does not need
    /// to change.
    pub(super) async fn handle_simple_query<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        sql: &str,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let start = std::time::Instant::now();
        // Set by `handle_simple_query_inner` as soon as a routing decision
        // is made (even if something later in the same call fails), so
        // the timing/logging below can still label the result by target.
        // Stays `None` if routing itself never produces a decision.
        let mut target: Option<NodeType> = None;

        let result = self
            .handle_simple_query_inner(client_stream, session, sql, &mut target)
            .await;

        // A PostgreSQL ERROR inside an explicit transaction aborts that
        // transaction. Proxy-local failures must follow the same rule. If a
        // physical transaction is still held, closing/discarding its socket
        // rolls it back and prevents later statements from accidentally
        // continuing on a backend that never observed the proxy error.
        if result.is_err() && session.state.tx_state != TxState::Idle {
            self.fail_open_transaction(session);
        }

        let elapsed_ms_f64 = start.elapsed().as_secs_f64() * 1000.0;
        let target_label = match target {
            Some(NodeType::Writer) => "writer",
            Some(NodeType::Reader) => "reader",
            Some(NodeType::Analytics) => "analytics",
            None => "unknown",
        };
        metrics::histogram!("trident_query_duration_ms", "target" => target_label)
            .record(elapsed_ms_f64);

        let elapsed_ms = elapsed_ms_f64.round() as u64;
        if elapsed_ms >= self.query_log.slow_query_threshold_ms {
            metrics::counter!("trident_slow_queries_total").increment(1);
            tracing::warn!(sql = %sql, duration_ms = elapsed_ms, target = target_label, "slow query");
            if let Some(buffer) = &self.slow_query_buffer {
                buffer.push(crate::admin::SlowQueryEntry {
                    time_unix_secs: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    duration_ms: elapsed_ms,
                    target: target_label.to_string(),
                    sql: sql.to_string(),
                });
            }
        } else if self.query_log.query_trace {
            tracing::info!(sql = %sql, duration_ms = elapsed_ms, target = target_label, "query");
        }

        result
    }

    /// Fast-path forwarding for statements within an explicit transaction
    /// when the backend connection is already held. Skips routing, snapshot,
    /// pinning detection, and pool acquire/release — just forwards the query
    /// and updates session state from the backend's ReadyForQuery.
    async fn forward_on_held_backend<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        sql: &str,
        _target_type: NodeType,
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
        let write_intent = query_has_write_intent(sql);

        // Compute LSN tracking options matching the main path
        // (handle_simple_query_inner) so that Extension GUC
        // ParameterStatus messages are intercepted rather than leaked to
        // the client, and pipeline LSN queries fire on COMMIT when
        // appropriate.
        let extension_guc = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            LsnTrackingMode::Pipeline | LsnTrackingMode::AuroraWriteForwarding => None,
        };
        let pipeline_mode = match self.lsn_tracking.mode {
            LsnTrackingMode::Pipeline => true,
            LsnTrackingMode::Auto => !session.extension_detected,
            LsnTrackingMode::Extension | LsnTrackingMode::AuroraWriteForwarding => false,
        };
        let commit_attempt = session.tx_has_writes && transaction_end_tag(sql) == Some("COMMIT");
        let pipeline_lsn = pipeline_mode
            && !self.lsn_tracking.pipeline.lazy_fallback
            && pipeline_safe_sql(sql)
            && commit_attempt;

        self.cancel_registry.mark_active(
            &session.state.id,
            &held.conn.node_id,
            held.conn.backend_pid,
            held.conn.secret_key,
        );
        let relay_result = forward_simple_query_with_options(
            &mut held.conn.stream,
            client_stream,
            sql,
            QueryForwardOptions {
                pipeline_lsn,
                extension_guc,
                internal_query_timeout: std::time::Duration::from_millis(
                    self.lsn_tracking.pipeline.internal_query_timeout_ms,
                ),
                begin_prefix: None,
                appname_prefix: None,
            },
        )
        .await;
        self.cancel_registry.clear_active(&session.state.id);

        let relay_outcome = match relay_result {
            Ok(outcome) => outcome,
            Err(failure) => {
                session.state.tx_state = TxState::Failed;
                let held = session.held_backend.take().unwrap();
                if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, session) {
                    let _ = pool.discard(held.conn);
                }
                if failure.error_response_relayed {
                    send_ready_for_query(client_stream, session.state.tx_state).await?;
                    return Ok(());
                }
                return Err(ProxyError::Protocol(failure.source));
            }
        };

        if self.lsn_tracking.mode == LsnTrackingMode::Auto && relay_outcome.reported_lsn.is_some() {
            session.extension_detected = true;
        }

        if detects_pinning_trigger(sql).is_some() && !relay_outcome.had_error_response {
            if let Some(held) = session.held_backend.as_mut() {
                held.conn.current_application_name = None;
            }
        }

        if write_intent && !relay_outcome.had_error_response {
            session.tx_has_writes = true;
        }

        session.state.tx_state = apply_ready_for_query(relay_outcome.tx_status);

        // If the transaction ended, track pending LSN for committed writes
        // and release the held backend.
        if session.state.tx_state == TxState::Idle {
            // COMMIT with prior writes and successful LSN capture: record
            // the watermark immediately rather than deferring to lazy
            // resolution. This mirrors handle_simple_query_inner's logic.
            let successful_commit = commit_attempt
                && !relay_outcome.had_error_response
                && relay_outcome.tx_status == TransactionStatus::Idle
                && relay_outcome.command_tags.iter().any(|tag| tag == "COMMIT");
            if successful_commit && session.state.consistency != ConsistencyLevel::Eventual {
                if let Some(lsn) = relay_outcome.reported_lsn.or(relay_outcome.pipelined_lsn) {
                    self.lsn_tracker.record_write(&session.state.id, lsn);
                    session.pending_write = false;
                } else {
                    session.pending_write = true;
                }
            } else if session.tx_has_writes
                && transaction_end_tag(sql) == Some("COMMIT")
                && !relay_outcome.had_error_response
                && session.state.consistency != ConsistencyLevel::Eventual
            {
                session.pending_write = true;
            }
            session.tx_has_writes = false;
            if let Some(split) = session.state.tx_split.take() {
                let _ = split;
            }

            // Pinned connections must stay held (consistent with the main
            // path in handle_simple_query_inner) so subsequent statements
            // always find them via the fast path without an unnecessary
            // pool acquire/release cycle.
            let held = session.held_backend.as_ref().unwrap();
            if held.conn.pinned {
                // Keep in held_backend — nothing to do.
            } else {
                let held = session.held_backend.take().unwrap();
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

        // The client write/commit completed but the internal pipeline LSN
        // cycle timed out or failed. The connection is in an unknown state
        // and must not be reused.
        if !relay_outcome.connection_reusable {
            if let Some(held) = session.held_backend.take() {
                if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, session) {
                    let _ = pool.discard(held.conn);
                }
            }
        }

        send_ready_for_query(client_stream, session.state.tx_state).await?;
        Ok(())
    }

    async fn handle_aurora_simple_query<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        sql: &str,
        target_out: &mut Option<NodeType>,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Preserve PostgreSQL's failed-transaction semantics: if the
        // physical connection was lost (relay failure + discard), the
        // session stays failed until COMMIT/ROLLBACK (which resolve
        // locally as ROLLBACK). This matches the behavior in the
        // non-Aurora path and prevents a new connection from silently
        // executing statements that should have been rejected with 25P02.
        if session.state.tx_state == TxState::Failed && session.held_backend.is_none() {
            if transaction_end_tag(sql).is_some() {
                session.state.tx_state = TxState::Idle;
                send_command_complete(client_stream, "ROLLBACK").await?;
                send_ready_for_query(client_stream, TxState::Idle).await?;
            } else {
                let error = PgError::simple(
                    "ERROR",
                    "25P02",
                    "current transaction is aborted, commands ignored until end of transaction block",
                );
                send_pg_error_response(client_stream, error).await?;
                send_ready_for_query(client_stream, TxState::Failed).await?;
            }
            return Ok(());
        }

        let nodes = self.pool_manager.snapshot();
        let node_id = if let Some(node_id) = session.aurora_node_id.as_ref() {
            let still_available = nodes.iter().any(|node| {
                node.node_id == *node_id && node.node_type == NodeType::Reader && node.healthy
            });
            if !still_available {
                return Err(ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                    node_id.clone(),
                )));
            }
            node_id.clone()
        } else {
            let selected = nodes
                .iter()
                .filter(|node| node.node_type == NodeType::Reader && node.healthy)
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
            selected
        };

        *target_out = Some(NodeType::Reader);
        metrics::counter!("trident_routing_decisions_total", "target" => "reader").increment(1);

        let pool = self.resolve_pool(&node_id, session).ok_or_else(|| {
            ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(node_id.clone()))
        })?;
        let (mut conn, backend_status) = if let Some(held) = session.held_backend.take() {
            if held.conn.node_id != node_id {
                if let Some(held_pool) = self.resolve_pool_existing(&held.conn.node_id, session) {
                    held_pool.discard(held.conn)?;
                }
                session.aurora_initialized_backend_pid = None;
                return Err(ProxyError::Pool(
                    crate::pool::pool::PoolError::CleanupFailed(format!(
                        "Aurora session is bound to '{node_id}' but held backend belongs to another node"
                    )),
                ));
            }
            (
                held.conn,
                transaction_status_for_state(session.state.tx_state),
            )
        } else {
            (
                pool.acquire(&session.state.id).await?,
                TransactionStatus::Idle,
            )
        };

        if let Err(error) =
            ensure_application_name(&mut conn, &session.application_name, backend_status).await
        {
            session.aurora_initialized_backend_pid = None;
            pool.discard(conn)?;
            return Err(ProxyError::Protocol(error));
        }

        if session.aurora_initialized_backend_pid != Some(conn.backend_pid) {
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

        let previous_consistency = session.state.consistency;
        let translated_sql = if session.state.tx_state != TxState::Failed
            && session.state.apply_consistency_set_command(sql)
        {
            Some(aurora_consistency_sql(session.state.consistency))
        } else {
            None
        };
        let forwarded_sql = translated_sql.as_deref().unwrap_or(sql);

        self.cancel_registry.mark_active(
            &session.state.id,
            &conn.node_id,
            conn.backend_pid,
            conn.secret_key,
        );
        let relay = forward_simple_query(&mut conn.stream, client_stream, forwarded_sql).await;
        self.cancel_registry.clear_active(&session.state.id);
        let outcome = match relay {
            Ok(outcome) => outcome,
            Err(failure) => {
                session.aurora_initialized_backend_pid = None;
                if session.state.tx_state != TxState::Idle {
                    session.state.tx_state = TxState::Failed;
                }
                pool.discard(conn)?;
                if failure.error_response_relayed {
                    send_ready_for_query(client_stream, session.state.tx_state).await?;
                    return Ok(());
                }
                return Err(ProxyError::Protocol(failure.source));
            }
        };

        if translated_sql.is_some() && outcome.had_error_response {
            session.state.consistency = previous_consistency;
        }
        if translated_sql.is_none()
            && detects_pinning_trigger(sql).is_some()
            && !outcome.had_error_response
        {
            conn.dirty = true;
            conn.current_application_name = None;
            if !conn.pinned {
                pool.pin(&session.state.id, &mut conn);
            }
        }
        session.state.tx_state = apply_ready_for_query(outcome.tx_status);

        if session.state.tx_state != TxState::Idle || conn.pinned {
            session.held_backend = Some(HeldBackend { conn });
        } else {
            pool.release(&session.state.id, conn).await?;
        }
        send_ready_for_query(client_stream, session.state.tx_state).await
    }

    async fn resolve_pending_write_lsn(&self, session: &mut ClientSession) -> bool {
        // Defensive: Eventual consistency never needs LSN resolution
        // (Issue #2 fix). Even if pending_write was erroneously set,
        // we short-circuit here to avoid a pointless writer round-trip.
        if !session.pending_write
            || !self.lsn_tracking.pipeline.lazy_fallback
            || session.state.consistency == ConsistencyLevel::Eventual
        {
            return false;
        }

        let writer_id = match self
            .pool_manager
            .snapshot()
            .into_iter()
            .find(|node| node.node_type == NodeType::Writer && node.healthy)
            .map(|node| node.node_id)
        {
            Some(writer_id) => writer_id,
            None => return false,
        };
        let timeout_duration =
            std::time::Duration::from_millis(self.lsn_tracking.pipeline.internal_query_timeout_ms);

        if session
            .held_backend
            .as_ref()
            .is_some_and(|held| held.conn.node_id == writer_id)
        {
            let appname_result = {
                let held = session.held_backend.as_mut().expect("checked above");
                ensure_application_name(
                    &mut held.conn,
                    &session.application_name,
                    transaction_status_for_state(session.state.tx_state),
                )
                .await
            };
            if let Err(error) = appname_result {
                tracing::warn!(error = %error, "cannot set application_name for held lazy LSN query");
                if let Some(held) = session.held_backend.take() {
                    if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, session) {
                        let _ = pool.discard(held.conn);
                    }
                }
                return false;
            }

            let result = {
                let held = session.held_backend.as_mut().expect("checked above");
                tokio::time::timeout(
                    timeout_duration,
                    fetch_current_wal_lsn(&mut held.conn.stream),
                )
                .await
            };
            match result {
                Ok(Ok(Some(lsn))) => {
                    self.lsn_tracker.record_write(&session.state.id, lsn);
                    session.pending_write = false;
                    return true;
                }
                Ok(Ok(None)) => return false,
                Ok(Err(error)) => {
                    tracing::warn!(error = %error, "lazy Writer LSN query failed; forcing Writer routing");
                }
                Err(_) => {
                    tracing::warn!("lazy Writer LSN query timed out; forcing Writer routing");
                }
            }

            if let Some(held) = session.held_backend.take() {
                if let Some(pool) = self.resolve_pool_existing(&held.conn.node_id, session) {
                    let _ = pool.discard(held.conn);
                }
            }
            return false;
        }

        let Some(pool) = self.resolve_pool(&writer_id, session) else {
            return false;
        };
        let mut conn = match pool.acquire(&session.state.id).await {
            Ok(conn) => conn,
            Err(error) => {
                tracing::warn!(error = %error, "cannot acquire Writer for lazy LSN query");
                return false;
            }
        };
        if let Err(error) = ensure_application_name(
            &mut conn,
            &session.application_name,
            TransactionStatus::Idle,
        )
        .await
        {
            tracing::warn!(error = %error, "cannot set application_name for lazy LSN query");
            let _ = pool.discard(conn);
            return false;
        }

        let result =
            tokio::time::timeout(timeout_duration, fetch_current_wal_lsn(&mut conn.stream)).await;
        match result {
            Ok(Ok(lsn)) => {
                if let Err(error) = pool.release(&session.state.id, conn).await {
                    tracing::warn!(error = %error, "failed to release Writer after lazy LSN query");
                    return false;
                }
                if let Some(lsn) = lsn {
                    self.lsn_tracker.record_write(&session.state.id, lsn);
                    session.pending_write = false;
                    true
                } else {
                    false
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "lazy Writer LSN query failed; forcing Writer routing");
                let _ = pool.discard(conn);
                false
            }
            Err(_) => {
                tracing::warn!("lazy Writer LSN query timed out; forcing Writer routing");
                let _ = pool.discard(conn);
                false
            }
        }
    }

    async fn finish_active_split_transaction<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        sql: &str,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let held = session.held_backend.take().ok_or_else(|| {
            ProxyError::Pool(crate::pool::pool::PoolError::CleanupFailed(
                "active split transaction has no held backend".into(),
            ))
        })?;
        let mut conn = held.conn;
        let pool = self
            .resolve_pool_existing(&conn.node_id, session)
            .ok_or_else(|| {
                ProxyError::Pool(crate::pool::pool::PoolError::CleanupFailed(format!(
                    "pool for split transaction node '{}' no longer exists",
                    conn.node_id
                )))
            })?;

        let commit_attempt = session.tx_has_writes && transaction_end_tag(sql) == Some("COMMIT");
        let pipeline_mode = match self.lsn_tracking.mode {
            LsnTrackingMode::Pipeline => true,
            LsnTrackingMode::Auto => !session.extension_detected,
            LsnTrackingMode::Extension | LsnTrackingMode::AuroraWriteForwarding => false,
        };
        let extension_guc = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            LsnTrackingMode::Pipeline | LsnTrackingMode::AuroraWriteForwarding => None,
        };

        self.cancel_registry.mark_active(
            &session.state.id,
            &conn.node_id,
            conn.backend_pid,
            conn.secret_key,
        );
        let relay = forward_simple_query_with_options(
            &mut conn.stream,
            client_stream,
            sql,
            QueryForwardOptions {
                pipeline_lsn: pipeline_mode && commit_attempt && pipeline_safe_sql(sql),
                extension_guc,
                internal_query_timeout: std::time::Duration::from_millis(
                    self.lsn_tracking.pipeline.internal_query_timeout_ms,
                ),
                begin_prefix: None,
                appname_prefix: None,
            },
        )
        .await;
        self.cancel_registry.clear_active(&session.state.id);
        let outcome = match relay {
            Ok(outcome) => outcome,
            Err(failure) => {
                pool.discard(conn)?;
                session.state.tx_state = TxState::Failed;
                if failure.error_response_relayed {
                    // The client already has the backend's ErrorResponse;
                    // complete that response cycle without appending a
                    // second, proxy-generated error.
                    send_ready_for_query(client_stream, TxState::Failed).await?;
                    return Ok(());
                }
                return Err(ProxyError::Protocol(failure.source));
            }
        };

        if self.lsn_tracking.mode == LsnTrackingMode::Auto && outcome.reported_lsn.is_some() {
            session.extension_detected = true;
        }
        let successful_commit = commit_attempt
            && !outcome.had_error_response
            && outcome.tx_status == TransactionStatus::Idle
            && outcome.command_tags.iter().any(|tag| tag == "COMMIT");
        if successful_commit && session.state.consistency != ConsistencyLevel::Eventual {
            if let Some(lsn) = outcome.reported_lsn.or(outcome.pipelined_lsn) {
                self.lsn_tracker.record_write(&session.state.id, lsn);
                session.pending_write = false;
            } else {
                session.pending_write = true;
            }
        }
        if outcome.tx_status == TransactionStatus::Idle {
            session.tx_has_writes = false;
        }

        session.state.tx_split = None;
        session.state.tx_state = apply_ready_for_query(outcome.tx_status);
        if !outcome.connection_reusable {
            pool.discard(conn)?;
            send_ready_for_query(client_stream, session.state.tx_state).await?;
            return Ok(());
        }
        if conn.pinned {
            session.held_backend = Some(HeldBackend { conn });
        } else {
            pool.release(&session.state.id, conn).await?;
        }
        send_ready_for_query(client_stream, session.state.tx_state).await
    }

    /// Does the actual routing/forwarding work for one simple-query
    /// statement (this is the original body of what used to be
    /// `handle_simple_query` before timing/logging were added around it).
    /// `target_out` is set as soon as a routing decision is made, so the
    /// caller (`handle_simple_query`) can label its timing/logging by
    /// target even on a later failure.
    async fn handle_simple_query_inner<S>(
        &self,
        client_stream: &mut S,
        session: &mut ClientSession,
        sql: &str,
        target_out: &mut Option<NodeType>,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if self.lsn_tracking.mode == LsnTrackingMode::AuroraWriteForwarding {
            return self
                .handle_aurora_simple_query(client_stream, session, sql, target_out)
                .await;
        }

        // A backend transaction can become unrecoverable when its physical
        // connection is lost during a protocol failure or a split upgrade.
        // Preserve PostgreSQL's failed-transaction semantics locally instead
        // of silently running later statements as autocommit on a new socket.
        // With no backend left, either transaction-ending command resolves to
        // ROLLBACK; every other command receives 25P02 and stays failed.
        if session.state.tx_state == TxState::Failed && session.held_backend.is_none() {
            if transaction_end_tag(sql).is_some() {
                session.state.tx_split = None;
                session.state.tx_state = TxState::Idle;
                send_command_complete(client_stream, "ROLLBACK").await?;
                send_ready_for_query(client_stream, TxState::Idle).await?;
            } else {
                let error = PgError::simple(
                    "ERROR",
                    "25P02",
                    "current transaction is aborted, commands ignored until end of transaction block",
                );
                send_pg_error_response(client_stream, error).await?;
                send_ready_for_query(client_stream, TxState::Failed).await?;
            }
            return Ok(());
        }

        // This is a proxy-local session setting, not a PostgreSQL GUC.
        // Intercept it before routing/pinning so it neither reaches a
        // backend nor marks the physical connection dirty. A failed physical
        // transaction is deliberately excluded so the backend can return its
        // normal 25P02 response.
        if session.state.tx_state != TxState::Failed
            && session.state.apply_consistency_set_command(sql)
        {
            let complete = encode_backend_message(&BackendMessage::CommandComplete {
                tag: "SET".to_string(),
            });
            client_stream
                .write_all(&complete)
                .await
                .map_err(ProtocolError::Io)?;
            send_ready_for_query(client_stream, session.state.tx_state).await?;
            return Ok(());
        }

        // With splitting enabled, acknowledge BEGIN to the client but do
        // not choose/open a backend transaction until the first real
        // statement determines Reader versus Writer.
        if session.state.tx_state == TxState::Idle {
            if let Some(options) = parse_begin_options(sql) {
                let (enable_split, split_respects_consistency) =
                    self.router.transaction_split_settings();
                if enable_split {
                    session.state.tx_split = Some(TxSplitState::pending_with_sql(
                        options.isolation,
                        options.read_only,
                        true,
                        split_respects_consistency,
                        sql,
                    ));
                    session.state.tx_state = TxState::InTransaction;
                    send_command_complete(client_stream, "BEGIN").await?;
                    send_ready_for_query(client_stream, TxState::InTransaction).await?;
                    return Ok(());
                }
            }
        }

        // COMMIT/ROLLBACK before a pending transaction's first statement
        // never touched a backend and can be completed locally. Once the
        // split transaction is active, finish it on its held backend
        // without sending it through Router (which would otherwise mistake
        // COMMIT for a write and trigger a Reader->Writer upgrade).
        if let Some(tag) = transaction_end_tag(sql) {
            if let Some(split) = session.state.tx_split.as_ref() {
                if split.active && session.held_backend.is_some() {
                    return self
                        .finish_active_split_transaction(client_stream, session, sql)
                        .await;
                }
                session.state.tx_split = None;
                session.state.tx_state = TxState::Idle;
                send_command_complete(client_stream, tag).await?;
                send_ready_for_query(client_stream, TxState::Idle).await?;
                return Ok(());
            }
        }

        // Fast path: when we already hold a backend connection inside an
        // explicit transaction and no split-upgrade is pending, skip the
        // expensive snapshot/routing/pool-acquire pipeline entirely — just
        // forward the statement to the held backend.
        let split_needs_upgrade = session.state.tx_split.as_ref().is_some_and(|s| {
            !s.active || s.need_upgrade || (s.on_reader && query_has_write_intent(sql))
        });
        if session.state.tx_state == TxState::InTransaction
            && session.held_backend.is_some()
            && !split_needs_upgrade
        {
            // In a non-split transaction, held backend is Writer.
            // In an active split (on_reader=true), it's Reader.
            let target_type = if session
                .state
                .tx_split
                .as_ref()
                .is_some_and(|s| s.active && s.on_reader)
            {
                NodeType::Reader
            } else {
                NodeType::Writer
            };
            *target_out = Some(target_type);
            metrics::counter!(
                "trident_routing_decisions_total",
                "target" => match target_type {
                    NodeType::Writer => "writer",
                    NodeType::Reader => "reader",
                    NodeType::Analytics => "analytics",
                }
            )
            .increment(1);
            return self
                .forward_on_held_backend(client_stream, session, sql, target_type)
                .await;
        }

        // Detect connection-pinning triggers (Requirement 6.1) before routing;
        // the actual `pin()` call happens after a connection is acquired below.
        let pinning_trigger = detects_pinning_trigger(sql);

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

        let session_write_lsn = self.lsn_tracker.session_write_lsn(&session.state.id);
        let global_write_lsn = self.lsn_tracker.global_write_lsn();
        // Router transaction splitting mutates this state while choosing a
        // target. Keep a pre-routing snapshot so failures before any backend
        // transaction change can be retried without committing a phantom
        // state transition.
        let tx_split_before_routing = session.state.tx_split.clone();
        let mut tx_split: Option<TxSplitState> = session.state.tx_split.take();
        let split_was_pending = tx_split.as_ref().is_some_and(|state| !state.active);

        let decision_result = {
            let mut ctx = RoutingContext {
                tx_state: session.state.tx_state,
                tx_split: &mut tx_split,
                consistency: session.state.consistency,
                session_write_lsn,
                global_write_lsn,
            };
            self.router.route(sql, &mut ctx, &readers, &analytics, &writers).await
        };
        // Always put the state back, including when routing fails. The prior
        // implementation used `?` before this assignment and could silently
        // erase a pending split transaction on a RouterError.
        session.state.tx_split = tx_split;
        let mut decision = decision_result?;

        if session.pending_write && decision.target != NodeType::Writer {
            if self.resolve_pending_write_lsn(session).await {
                // The first routing pass may have advanced transaction-split
                // state. Re-run from its pre-routing snapshot so the final
                // decision alone determines the state transition.
                let mut reroute_split = tx_split_before_routing.clone();
                let reroute_result = {
                    let mut ctx = RoutingContext {
                        tx_state: session.state.tx_state,
                        tx_split: &mut reroute_split,
                        consistency: session.state.consistency,
                        session_write_lsn: self.lsn_tracker.session_write_lsn(&session.state.id),
                        global_write_lsn: self.lsn_tracker.global_write_lsn(),
                    };
                    self.router.route(sql, &mut ctx, &readers, &analytics, &writers).await
                };
                session.state.tx_split = reroute_split;
                decision = reroute_result?;
            } else {
                // No trustworthy watermark is available. Never send this
                // query to a Reader: retain the pending marker and use the
                // Writer until a later lazy refresh succeeds.
                let requires_upgrade = session.state.tx_split.as_ref().is_some_and(|split| {
                    split.active && split.on_reader && session.held_backend.is_some()
                });
                if let Some(split) = session.state.tx_split.as_mut() {
                    split.active = true;
                    split.on_reader = false;
                    split.need_upgrade = requires_upgrade;
                }
                decision = RouteDecision {
                    target: NodeType::Writer,
                    node_id: None,
                    reason: std::borrow::Cow::Borrowed(
                        "pending write watermark unavailable; conservative Writer fallback",
                    ),
                    forced_by_hint: false,
                    fallback_to_writer: true,
                    requires_split_upgrade: requires_upgrade,
                };
            }
        }

        // Most statements in an active split transaction do not need the
        // original BEGIN text. Clone it only when opening the delayed
        // transaction or upgrading a Reader transaction to Writer.
        let split_begin_sql = if split_was_pending || decision.requires_split_upgrade {
            session
                .state
                .tx_split
                .as_ref()
                .map(|state| state.begin_sql().to_string())
        } else {
            None
        };
        *target_out = Some(decision.target);

        metrics::counter!(
            "trident_routing_decisions_total",
            "target" => match decision.target {
                NodeType::Writer => "writer",
                NodeType::Reader => "reader",
                NodeType::Analytics => "analytics",
            }
        )
        .increment(1);

        let target_node_id = match decision.target {
            // Writer route decisions intentionally do not carry a concrete
            // node id. Resolve the configured writer by type instead of
            // assuming its name is literally "writer" (the shipped
            // configuration calls it "primary"). Only a healthy writer is
            // eligible; otherwise fail explicitly below.
            NodeType::Writer => all_nodes
                .iter()
                .find(|node| node.node_type == NodeType::Writer && node.healthy)
                .map(|node| node.node_id.clone())
                .unwrap_or_default(),
            NodeType::Reader | NodeType::Analytics => decision.node_id.clone().unwrap_or_default(),
        };

        if target_node_id.is_empty() {
            // No backend state changed, so undo any split-state mutation the
            // routing decision made (notably Reader->Writer upgrade flags).
            session.state.tx_split = tx_split_before_routing;
            // No healthy candidate available for the chosen target.
            let pseudo_node_id = format!("{:?}", decision.target);
            metrics::counter!("trident_pool_exhausted_total", "node_id" => pseudo_node_id.clone())
                .increment(1);
            return Err(ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                pseudo_node_id,
            )));
        }

        let mut split_reader_rolled_back = false;
        if decision.requires_split_upgrade {
            let held = match session.held_backend.take() {
                Some(held) => held,
                None => {
                    session.state.tx_state = TxState::Failed;
                    return Err(ProxyError::Pool(
                        crate::pool::pool::PoolError::CleanupFailed(
                            "Reader-to-Writer upgrade has no held Reader connection".into(),
                        ),
                    ));
                }
            };
            let mut reader_conn = held.conn;
            let reader_pool = match self.resolve_pool_existing(&reader_conn.node_id, session) {
                Some(pool) => pool,
                None => {
                    session.state.tx_state = TxState::Failed;
                    return Err(ProxyError::Pool(
                        crate::pool::pool::PoolError::CleanupFailed(format!(
                            "pool for split Reader '{}' no longer exists",
                            reader_conn.node_id
                        )),
                    ));
                }
            };

            if let Err(error) =
                execute_internal_query(&mut reader_conn.stream, "ROLLBACK", TransactionStatus::Idle)
                    .await
            {
                session.state.tx_state = TxState::Failed;
                reader_pool.discard(reader_conn)?;
                return Err(ProxyError::Protocol(error));
            }
            split_reader_rolled_back = true;

            // In Transaction mode the ROLLBACK leaves the connection in a
            // clean Idle state, so return the complete connection for reuse.
            // In Session mode this Reader binding must be discarded because
            // the transaction is moving to a different backend.
            match reader_pool.mode() {
                PoolMode::Transaction => {
                    reader_conn.dirty = false;
                    if let Err(error) = reader_pool.release(&session.state.id, reader_conn).await {
                        session.state.tx_state = TxState::Failed;
                        return Err(ProxyError::Pool(error));
                    }
                }
                PoolMode::Session => {
                    if let Err(error) = reader_pool.discard(reader_conn) {
                        session.state.tx_state = TxState::Failed;
                        return Err(ProxyError::Pool(error));
                    }
                }
            }
        }

        let current_gen = self.connection_registry.map(|r| r.node_generation(&target_node_id));
        let mut conn = if let Some(held) = session.held_backend.take() {
            // PostgreSQL transaction and session state is connection-local.
            held.conn
        } else if let Some(cached) = session.take_cached_if_matches(&target_node_id, current_gen) {
            // Fast path: reuse the complete cached idle connection.
            cached.conn
        } else {
            self.release_cached_backend(session).await;

            let target_pool = match self.resolve_pool(&target_node_id, session) {
                Some(pool) => pool,
                None => {
                    metrics::counter!("trident_pool_exhausted_total", "node_id" => target_node_id.clone())
                        .increment(1);
                    if split_reader_rolled_back {
                        session.state.tx_state = TxState::Failed;
                    } else {
                        session.state.tx_split = tx_split_before_routing.clone();
                    }
                    return Err(ProxyError::Pool(crate::pool::pool::PoolError::Exhausted(
                        target_node_id.clone(),
                    )));
                }
            };

            match target_pool.acquire(&session.state.id).await {
                Ok(conn) => conn,
                Err(e) => {
                    if matches!(e, crate::pool::pool::PoolError::Exhausted(_)) {
                        metrics::counter!("trident_pool_exhausted_total", "node_id" => target_node_id.clone())
                            .increment(1);
                    }
                    if split_reader_rolled_back {
                        session.state.tx_state = TxState::Failed;
                    } else {
                        session.state.tx_split = tx_split_before_routing.clone();
                    }
                    return Err(ProxyError::Pool(e));
                }
            }
        };

        let pool = self
            .resolve_pool_existing(&conn.node_id, session)
            .ok_or_else(|| {
                ProxyError::Pool(crate::pool::pool::PoolError::CleanupFailed(format!(
                    "pool for held backend node '{}' no longer exists",
                    conn.node_id
                )))
            })?;

        // QueryForwardOptions does not expose whether an appname prefix
        // succeeded independently of the user query. Use a standalone
        // internal cycle so the per-connection cache is updated only after
        // SET is confirmed successful.
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

        if pinning_trigger.is_some() && !conn.pinned {
            pool.pin(&session.state.id, &mut conn);
        }

        // The delayed split-transaction BEGIN is not sent as a separate
        // round trip: it is pipelined into the same outbound write as the
        // first real statement below (see `QueryForwardOptions::begin_prefix`),
        // saving one full backend round trip per transaction. If it fails,
        // the relay call below fails before any response bytes reach the
        // client; the client has already observed BEGIN, and after an
        // upgrade the Reader transaction has already been rolled back, so
        // the error path marks the session transaction Failed and discards
        // this backend socket.
        let delayed_begin: Option<&str> = if split_was_pending || decision.requires_split_upgrade {
            match split_begin_sql.as_deref() {
                Some(begin_sql) => Some(begin_sql),
                None => {
                    session.state.tx_state = TxState::Failed;
                    pool.discard(conn)?;
                    return Err(ProxyError::Protocol(ProtocolError::Malformed(
                        "split transaction is missing its delayed BEGIN command".into(),
                    )));
                }
            }
        } else {
            None
        };

        let prior_tx_state = session.state.tx_state;
        let write_intent = query_has_write_intent(sql);
        let commit_attempt = prior_tx_state == TxState::InTransaction
            && session.tx_has_writes
            && transaction_end_tag(sql) == Some("COMMIT");
        let extension_guc = match self.lsn_tracking.mode {
            LsnTrackingMode::Extension | LsnTrackingMode::Auto => {
                Some(self.lsn_tracking.extension.guc_name.as_str())
            }
            LsnTrackingMode::Pipeline | LsnTrackingMode::AuroraWriteForwarding => None,
        };
        let pipeline_mode = match self.lsn_tracking.mode {
            LsnTrackingMode::Pipeline => true,
            LsnTrackingMode::Auto => !session.extension_detected,
            LsnTrackingMode::Extension | LsnTrackingMode::AuroraWriteForwarding => false,
        };
        // Skip pipeline when lazy_fallback is enabled: defer LSN acquisition
        // to the point where a subsequent read actually targets a reader.
        // Write-only workloads pay zero LSN overhead; mixed workloads pay
        // exactly one extra query only when needed.
        let pipeline_lsn = pipeline_mode
            && !self.lsn_tracking.pipeline.lazy_fallback
            && pipeline_safe_sql(sql)
            && ((prior_tx_state == TxState::Idle && write_intent) || commit_attempt);

        // Requirements 7.1-7.3: mark this session as having a query in
        // flight against this exact real backend connection *before*
        // sending it, and always clear that mark once the round trip
        // finishes (success or failure) -- a CANCEL that arrives after
        // this point has nothing left to cancel and must be ignored.
        self.cancel_registry.mark_active(
            &session.state.id,
            &conn.node_id,
            conn.backend_pid,
            conn.secret_key,
        );
        let relay_result = forward_simple_query_with_options(
            &mut conn.stream,
            client_stream,
            sql,
            QueryForwardOptions {
                pipeline_lsn,
                extension_guc,
                internal_query_timeout: std::time::Duration::from_millis(
                    self.lsn_tracking.pipeline.internal_query_timeout_ms,
                ),
                begin_prefix: delayed_begin,
                appname_prefix: None,
            },
        )
        .await;
        self.cancel_registry.clear_active(&session.state.id);

        let relay_outcome = match relay_result {
            Ok(outcome) => outcome,
            Err(failure) => {
                // The backend socket may be in an unknown state after a
                // protocol-level failure (as opposed to a normal
                // ErrorResponse followed by ReadyForQuery). Do not return it
                // to the pool. If an ErrorResponse was already relayed, only synthesize the missing ReadyForQuery; the
                // outer loop must not send a duplicate error.
                if session.state.tx_state != TxState::Idle {
                    session.state.tx_state = TxState::Failed;
                }
                pool.discard(conn)?;
                if failure.error_response_relayed {
                    send_ready_for_query(client_stream, session.state.tx_state).await?;
                    return Ok(());
                }
                return Err(ProxyError::Protocol(failure.source));
            }
        };

        if self.lsn_tracking.mode == LsnTrackingMode::Auto && relay_outcome.reported_lsn.is_some() {
            session.extension_detected = true;
        }

        let successful_autocommit_write = prior_tx_state == TxState::Idle
            && write_intent
            && !relay_outcome.had_error_response
            && relay_outcome.tx_status == TransactionStatus::Idle;
        let successful_commit = commit_attempt
            && !relay_outcome.had_error_response
            && relay_outcome.tx_status == TransactionStatus::Idle
            && relay_outcome.command_tags.iter().any(|tag| tag == "COMMIT");
        let committed_write = successful_autocommit_write || successful_commit;

        if prior_tx_state == TxState::InTransaction
            && write_intent
            && !relay_outcome.had_error_response
            && relay_outcome.tx_status == TransactionStatus::InTransaction
        {
            session.tx_has_writes = true;
        }
        if transaction_end_tag(sql).is_some() && relay_outcome.tx_status == TransactionStatus::Idle
        {
            session.tx_has_writes = false;
        }

        if committed_write && session.state.consistency != ConsistencyLevel::Eventual {
            if let Some(lsn) = relay_outcome.reported_lsn.or(relay_outcome.pipelined_lsn) {
                self.lsn_tracker.record_write(&session.state.id, lsn);
                session.pending_write = false;
            } else {
                session.pending_write = true;
            }
        }

        // Requirement 11.5/Property 42: update the session's transaction
        // state from the backend's original ReadyForQuery status byte.
        session.state.tx_state = apply_ready_for_query(relay_outcome.tx_status);

        // The client write/commit already completed even if the internal
        // LSN cycle timed out. Preserve that success, discard the unknown
        // backend stream, and resolve the pending watermark lazily later.
        if !relay_outcome.connection_reusable {
            pool.discard(conn)?;
            send_ready_for_query(client_stream, session.state.tx_state).await?;
            return Ok(());
        }

        if pinning_trigger.is_some() {
            conn.dirty = true;
            if !relay_outcome.had_error_response {
                conn.current_application_name = None;
            }
        }

        if session.state.tx_state != TxState::Idle || conn.pinned {
            session.held_backend = Some(HeldBackend { conn });
        } else if conn.dirty {
            // Dirty connections cannot be cached; release runs the cleaner.
            pool.release(&session.state.id, conn).await?;
        } else {
            // Cache the complete clean idle connection for same-node reuse.
            session.cached_idle_backend = Some(HeldBackend { conn });
        }

        send_ready_for_query(client_stream, session.state.tx_state).await?;
        Ok(())
    }
}
