//! Single-node connection pool (`pool`)
//!
//! Implements the `ConnectionPool` trait:
//! - Session mode: `acquire` always returns the same bound backend
//!   connection for the same session (`session_id`), until that session
//!   calls `release_session`.
//! - Transaction mode: `acquire` borrows a connection from the idle queue
//!   (creating a new one if the queue is empty and `max_pool_size` has not
//!   been reached); `release` returns an unpinned connection (cleaning it
//!   first if dirty).
//!
//! The pool owns complete `BackendConnection` values. Metadata and sockets
//! move together through idle, session-bound, and pinned queues, while an
//! injected `ConnFactory` establishes connections and `ConnCleaner` resets
//! or validates their sockets.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::time::timeout;

use crate::config::PoolMode;
use crate::pool::conn::BackendConnection;

/// Connection pool error
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PoolError {
    #[error("connection pool for node '{0}' is exhausted (max_pool_size reached)")]
    Exhausted(String),

    #[error("timed out after {timeout_ms} ms waiting for an available connection for node '{node_id}'")]
    AcquireTimeout { node_id: String, timeout_ms: u128 },

    #[error("failed to establish new backend connection: {0}")]
    ConnectFailed(String),

    #[error("timed out after {timeout_ms} ms establishing a backend connection for node '{node_id}'")]
    ConnectTimeout { node_id: String, timeout_ms: u128 },

    #[error("failed to clean dirty connection before returning to pool: {0}")]
    CleanupFailed(String),

    #[error("released connection does not belong to this pool (node mismatch)")]
    NodeMismatch,
}

/// Abstract factory for establishing new backend connections, called by
/// `NodePool` whenever a new connection is needed. Production
/// implementations should call `conn::establish_connection`; tests can
/// inject an I/O-free mock.
pub trait ConnFactory: Send + Sync {
    fn create(
        &self,
        node_id: &str,
    ) -> impl std::future::Future<Output = Result<BackendConnection, PoolError>> + Send;
}

/// Abstract interface for cleaning a "dirty" connection (equivalent to
/// `DISCARD ALL` or a precise-reset combination).
pub trait ConnCleaner: Send + Sync {
    fn clean(
        &self,
        conn: &mut BackendConnection,
    ) -> impl std::future::Future<Output = Result<(), PoolError>> + Send;

    /// Validates that an idle connection is still usable by executing a
    /// lightweight query (configured via `pool.check_query`). Called
    /// periodically by the background idle-connection probe task.
    /// Returns Ok(()) if the connection is alive; Err if it should be
    /// discarded. The default always returns Ok (no validation).
    fn validate(
        &self,
        _conn: &mut BackendConnection,
    ) -> impl std::future::Future<Output = Result<(), PoolError>> + Send {
        async { Ok(()) }
    }

    /// Records an explicit discard for observability or custom cleanup.
    /// Dropping `BackendConnection` always closes its owned socket, so the
    /// default implementation requires no external resource registry.
    fn discard(&self, _conn: &BackendConnection) {}
}

/// `DISCARD ALL`: the brute-force reset approach, completing all cleanup
/// in a single statement.
pub const DISCARD_ALL_STATEMENT: &str = "DISCARD ALL";

/// Precise reset combination: reduces unnecessary round trips by only
/// resetting state that actually changed. The order follows design.md
/// section 7.5: reset parameters first, then release statements/cursors/
/// listeners, and finally reset the role.
pub const PRECISE_RESET_STATEMENTS: &[&str] = &[
    "RESET ALL",
    "DEALLOCATE ALL",
    "CLOSE ALL",
    "UNLISTEN *",
    "SET SESSION AUTHORIZATION DEFAULT",
];

/// Asynchronous connection pool interface.
///
/// Uses `#[async_trait]` rather than a native `impl Future` return, so
/// this trait remains object-safe and can be returned by
/// `PoolManager::pool_for` as `&dyn ConnectionPool` (see design.md's
/// `PoolManager` interface).
#[async_trait]
pub trait ConnectionPool: Send + Sync {
    /// Returns the pool mode (Transaction or Session) for this pool.
    fn mode(&self) -> PoolMode;

    /// Acquires a usable connection.
    ///
    /// - Session mode: `session_id` identifies the client connection;
    ///   `acquire` moves its bound connection out for exclusive use and
    ///   `release` moves the same connection back into the binding.
    /// - Transaction mode: `session_id` is only used to track pinned
    ///   connections per session for a later `pin` call; each `acquire`
    ///   may return any idle connection in the pool.
    async fn acquire(&self, session_id: &str) -> Result<BackendConnection, PoolError>;

    /// Called when a transaction/statement ends. Transaction mode returns
    /// unpinned connections to the reusable idle queue; Session mode moves
    /// the complete connection back into its session binding.
    async fn release(&self, session_id: &str, conn: BackendConnection) -> Result<(), PoolError>;

    /// Marks the connection as pinned and records the session it belongs
    /// to, for `release_session` to release later. After this, no
    /// `release(session_id, conn)` call will place it back in the
    /// reusable queue.
    fn pin(&self, session_id: &str, conn: &mut BackendConnection);

    /// Permanently removes a broken/unknown-state connection from the
    /// pool and frees its capacity slot. Unlike `release`, this never
    /// cleans or returns the connection to the idle queue.
    fn discard(&self, conn: BackendConnection) -> Result<(), PoolError>;

    /// Called when a session ends. Removes and returns every connection
    /// still recorded for the session. Dropping the returned values closes
    /// their sockets.
    fn release_session(&self, session_id: &str) -> Vec<BackendConnection>;

    /// The current number of active connections (used for load balancing
    /// and capacity monitoring). Includes idle, checked-out, session-bound,
    /// and pinned connections — i.e. every physical connection the pool owns.
    fn active_connections(&self) -> i64;

    /// The number of connections currently sitting idle in the pool.
    /// `active_connections() - idle_connections()` gives the number of
    /// connections actively in use by clients. Used by the eviction logic
    /// to determine if a pool is truly unused (all connections idle, none
    /// checked out).
    fn idle_connections(&self) -> i64 {
        0
    }

    /// Returns the backend PIDs of all connections known to this pool.
    /// Retained for diagnostics and status reporting.
    fn known_pids(&self) -> Vec<i32> {
        Vec::new()
    }

    /// Validates all idle connections and discards dead ones. Returns
    /// the number discarded. Called periodically by a background task.
    async fn validate_idle(&self) -> usize {
        0
    }

    /// Puts the pool into draining mode: new acquires are rejected,
    /// existing connections continue until released. Used during dynamic
    /// node removal to gracefully wind down in-flight work.
    fn drain(&self) {}
}

/// Runtime controls for a single node pool. Durations are applied lazily
/// when a connection is created or removed from the reusable idle queue;
/// checked-out and pinned connections are never interrupted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodePoolSettings {
    pub min_pool_size: u32,
    pub connection_timeout: Duration,
    pub max_idle_time: Duration,
    pub max_lifetime: Duration,
    /// Maximum time to wait for a connection when the pool is exhausted.
    /// 0 = no waiting (immediate rejection, legacy behavior). Default: 5s.
    pub acquire_timeout: Duration,
    /// Maximum time a connection may be checked out before a warning is
    /// emitted (connection leak detection). 0 = disabled. Default: 0.
    pub leak_detection_threshold: Duration,
}

impl Default for NodePoolSettings {
    fn default() -> Self {
        NodePoolSettings {
            min_pool_size: 0,
            connection_timeout: Duration::from_secs(5),
            max_idle_time: Duration::from_secs(5 * 60),
            max_lifetime: Duration::from_secs(30 * 60),
            acquire_timeout: Duration::ZERO,
            leak_detection_threshold: Duration::ZERO,
        }
    }
}

/// RAII guard for a reserved pool slot. If dropped without calling `defuse()`,
/// it releases the slot back, preventing leaks on async cancellation.
struct SlotGuard<'a> {
    active_connections: &'a AtomicU32,
    release_notify: &'a tokio::sync::Notify,
    armed: bool,
}

impl<'a> SlotGuard<'a> {
    /// Disarm the guard, taking ownership of the reserved slot.
    fn defuse(&mut self) {
        self.armed = false;
    }
}

impl<'a> Drop for SlotGuard<'a> {
    fn drop(&mut self) {
        if self.armed {
            self.active_connections.fetch_sub(1, Ordering::SeqCst);
            self.release_notify.notify_one();
        }
    }
}

/// RAII guard for a connection that has been removed from the idle queue for
/// validation or cleaning. If the async future is cancelled (dropped) before
/// the connection is returned to idle or explicitly discarded, the guard
/// ensures the slot is released from `known_connections` and the counter is
/// decremented, preventing capacity leaks.
struct KnownSlotGuard<'a> {
    known_connections: &'a Mutex<HashSet<(i32, i32)>>,
    active_connections: &'a AtomicU32,
    release_notify: &'a tokio::sync::Notify,
    key: (i32, i32),
    armed: bool,
}

impl<'a> KnownSlotGuard<'a> {
    fn defuse(&mut self) {
        self.armed = false;
    }
}

impl<'a> Drop for KnownSlotGuard<'a> {
    fn drop(&mut self) {
        if self.armed {
            let removed = self.known_connections.lock().remove(&self.key);
            if removed {
                self.active_connections.fetch_sub(1, Ordering::SeqCst);
                self.release_notify.notify_one();
            }
        }
    }
}

/// Default `ConnectionPool` implementation: manages the connection pool
/// for a single backend node.
pub struct NodePool<F: ConnFactory, C: ConnCleaner> {
    node_id: String,
    mode: PoolMode,
    max_pool_size: AtomicU32,
    settings: NodePoolSettings,
    factory: F,
    cleaner: C,

    idle: Mutex<VecDeque<BackendConnection>>,
    active_connections: AtomicU32,
    /// Composite identity (backend_pid, secret_key) of connections currently
    /// owned by this pool. Using both fields prevents PID-reuse collisions
    /// from incorrectly affecting another connection's slot accounting.
    known_connections: Mutex<HashSet<(i32, i32)>>,

    /// Session mode: session ID -> complete connection while it is between
    /// statements. `acquire` moves it out and `release` moves it back.
    session_bindings: Mutex<HashMap<String, BackendConnection>>,
    /// Session IDs with a connection currently checked out. A client session
    /// is processed serially by the handler; this guard prevents accidental
    /// concurrent acquires from creating a second physical connection.
    session_checkouts: Mutex<HashSet<String>>,
    /// Transaction mode: session ID -> the set of connections that
    /// session has pinned and not yet released.
    pinned_by_session: Mutex<HashMap<String, Vec<BackendConnection>>>,
    /// Notifies waiting acquirers when a connection is released back to
    /// the idle queue (wait queue support).
    release_notify: tokio::sync::Notify,
    /// Tracks checkout timestamps for leak detection. Only populated when
    /// `settings.leak_detection_threshold > 0`.
    checkout_times: Mutex<HashMap<(i32, i32), Instant>>,
    /// Flag to indicate the pool is draining (no new acquires allowed).
    draining: std::sync::atomic::AtomicBool,
}

impl<F: ConnFactory, C: ConnCleaner> NodePool<F, C> {
    pub fn new(
        node_id: impl Into<String>,
        mode: PoolMode,
        max_pool_size: u32,
        factory: F,
        cleaner: C,
    ) -> Self {
        Self::with_settings(
            node_id,
            mode,
            max_pool_size,
            NodePoolSettings::default(),
            factory,
            cleaner,
        )
    }

    pub fn with_settings(
        node_id: impl Into<String>,
        mode: PoolMode,
        max_pool_size: u32,
        settings: NodePoolSettings,
        factory: F,
        cleaner: C,
    ) -> Self {
        NodePool {
            node_id: node_id.into(),
            mode,
            max_pool_size: AtomicU32::new(max_pool_size),
            settings,
            factory,
            cleaner,
            idle: Mutex::new(VecDeque::new()),
            active_connections: AtomicU32::new(0),
            known_connections: Mutex::new(HashSet::new()),
            session_bindings: Mutex::new(HashMap::new()),
            session_checkouts: Mutex::new(HashSet::new()),
            pinned_by_session: Mutex::new(HashMap::new()),
            release_notify: tokio::sync::Notify::new(),
            checkout_times: Mutex::new(HashMap::new()),
            draining: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Atomically attempts to "reserve a slot" for a new connection: only
    /// when `active_connections < max_pool_size` does it increment the
    /// counter and return `true`; otherwise leaves state unchanged and
    /// returns `false`.
    ///
    /// Uses a CAS loop to guarantee Requirement 5.5 (active connections
    /// never exceed max_pool_size) holds even under concurrency.
    fn try_reserve_slot(&self) -> bool {
        let max = self.max_pool_size.load(Ordering::SeqCst);
        let mut current = self.active_connections.load(Ordering::SeqCst);
        loop {
            if current >= max {
                return false;
            }
            match self.active_connections.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn release_slot(&self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }

    /// RAII guard that ensures a reserved slot is released if the future
    /// holding it is cancelled (dropped). Call `defuse()` to take ownership
    /// of the slot without releasing it.
    fn reserve_slot_guard(&self) -> SlotGuard<'_> {
        SlotGuard {
            active_connections: &self.active_connections,
            release_notify: &self.release_notify,
            armed: true,
        }
    }

    fn register_connection(&self, conn: &BackendConnection) {
        self.known_connections
            .lock()
            .insert((conn.backend_pid, conn.secret_key));
    }

    async fn create_reserved_connection(&self) -> Result<BackendConnection, PoolError> {
        // The caller has already reserved a slot via try_reserve_slot().
        // Use a guard to ensure the slot is released if this future is
        // cancelled (dropped) before we return the connection.
        let mut guard = self.reserve_slot_guard();
        match timeout(
            self.settings.connection_timeout,
            self.factory.create(&self.node_id),
        )
        .await
        {
            Ok(Ok(conn)) => {
                if self.draining.load(Ordering::SeqCst) {
                    self.cleaner.discard(&conn);
                    // Guard will release slot on drop.
                    return Err(PoolError::Exhausted(format!(
                        "{} (draining)",
                        self.node_id
                    )));
                }
                self.register_connection(&conn);
                metrics::counter!("trident_pool_connections_established_total", "node_id" => self.node_id.clone()).increment(1);
                // Connection created successfully — defuse the guard so
                // the slot remains reserved (owned by the connection).
                guard.defuse();
                Ok(conn)
            }
            Ok(Err(error)) => {
                // Guard releases slot on drop.
                Err(error)
            }
            Err(_) => {
                // Guard releases slot on drop.
                Err(PoolError::ConnectTimeout {
                    node_id: self.node_id.clone(),
                    timeout_ms: self.settings.connection_timeout.as_millis(),
                })
            }
        }
    }

    fn is_expired(&self, conn: &BackendConnection, now: Instant) -> bool {
        now.saturating_duration_since(conn.created_at) >= self.settings.max_lifetime
            || conn.idle_since.is_some_and(|idle_since| {
                now.saturating_duration_since(idle_since) >= self.settings.max_idle_time
            })
    }

    /// Returns the next non-expired idle connection. Expired complete
    /// connections are permanently discarded before trying the next entry.
    fn take_reusable_idle(&self) -> Option<BackendConnection> {
        loop {
            let candidate = self
                .idle
                .lock()
                .pop_front();
            let mut conn = candidate?;
            if self.is_expired(&conn, Instant::now()) {
                self.cleaner.discard(&conn);
                self.release_known_slot(&conn);
                continue;
            }
            conn.idle_since = None;
            return Some(conn);
        }
    }

    /// Validates all idle connections by executing the check query against
    /// each. Connections that fail validation are discarded and their
    /// slots freed. Returns the number of connections discarded.
    ///
    /// Called periodically by a background task (e.g. every 30s). This
    /// ensures stale connections (silently closed by the backend, killed
    /// by a firewall, or broken by a network blip) are detected and
    /// removed *before* a client query hits them.
    pub async fn validate_idle_connections(&self) -> usize {
        // Determine how many idle connections to validate this round.
        // Take them one at a time to minimize the window where the idle
        // queue appears empty to concurrent acquires.
        let count = self.idle.lock().len();
        let mut discarded = 0;

        for _ in 0..count {
            let conn = { self.idle.lock().pop_front() };
            let mut conn = match conn {
                Some(c) => c,
                None => break, // queue drained by concurrent acquires
            };

            if self.is_expired(&conn, Instant::now()) {
                self.cleaner.discard(&conn);
                self.release_known_slot(&conn);
                discarded += 1;
                continue;
            }

            // Cancellation safety: arm a KnownSlotGuard so that if the
            // validate future is cancelled, the slot is automatically
            // released from known_connections and the counter decremented.
            let mut slot_guard = KnownSlotGuard {
                known_connections: &self.known_connections,
                active_connections: &self.active_connections,
                release_notify: &self.release_notify,
                key: (conn.backend_pid, conn.secret_key),
                armed: true,
            };

            let validate_result = self.cleaner.validate(&mut conn).await;

            match validate_result {
                Ok(()) => {
                    // Defuse guard — we handle the connection ourselves.
                    slot_guard.defuse();
                    // Re-check draining: if drain() was called while we
                    // were awaiting the validation query, discard instead
                    // of re-inserting into the idle queue.
                    if self.draining.load(Ordering::SeqCst) {
                        self.cleaner.discard(&conn);
                        self.release_known_slot(&conn);
                        discarded += 1;
                    } else {
                        // Connection is alive — put it back at the end
                        conn.idle_since = Some(Instant::now());
                        self.idle.lock().push_back(conn);
                        // Wake one waiter that may have missed this connection
                        // while it was temporarily removed for validation.
                        self.release_notify.notify_one();
                    }
                }
                Err(_) => {
                    // Defuse guard — we discard explicitly.
                    slot_guard.defuse();
                    // Connection is dead — discard it
                    self.cleaner.discard(&conn);
                    self.release_known_slot(&conn);
                    discarded += 1;
                }
            }
        }

        if discarded > 0 {
            // Notify waiters that slots freed up
            self.release_notify.notify_waiters();
            metrics::counter!(
                "trident_pool_idle_validation_discarded_total",
                "node_id" => self.node_id.clone()
            ).increment(discarded as u64);
        }
        discarded
    }

    /// Establishes reusable idle connections up to `min_pool_size`.
    /// Production calls this before accepting clients, so startup honors the
    /// configured floor rather than waiting for the first query burst.
    pub async fn warm_up(&self) -> Result<(), PoolError> {
        while self.active_connections.load(Ordering::SeqCst) < self.settings.min_pool_size {
            if !self.try_reserve_slot() {
                return Err(PoolError::Exhausted(self.node_id.clone()));
            }
            let mut conn = self.create_reserved_connection().await?;
            conn.idle_since = Some(Instant::now());
            self.idle
                .lock()
                .push_back(conn);
        }
        Ok(())
    }

    fn release_known_slot(&self, conn: &BackendConnection) -> bool {
        let removed = self
            .known_connections
            .lock()
            .remove(&(conn.backend_pid, conn.secret_key));
        if removed {
            self.release_slot();
        }
        removed
    }

    fn forget_metadata(&self, conn: &BackendConnection) {
        self.idle
            .lock()
            .retain(|candidate| candidate.backend_pid != conn.backend_pid);
        self.session_bindings
            .lock()
            .retain(|_, candidate| candidate.backend_pid != conn.backend_pid);
        let mut pinned = self
            .pinned_by_session
            .lock();
        pinned.retain(|_, connections| {
            connections.retain(|candidate| candidate.backend_pid != conn.backend_pid);
            !connections.is_empty()
        });
    }

    async fn acquire_session_mode(&self, session_id: &str) -> Result<BackendConnection, PoolError> {
        if self.draining.load(Ordering::SeqCst) {
            return Err(PoolError::Exhausted(format!("{} (draining)", self.node_id)));
        }

        if let Some(conn) = self.session_bindings.lock().remove(session_id) {
            self.session_checkouts.lock().insert(session_id.to_string());
            self.record_checkout(&conn);
            return Ok(conn);
        }

        {
            let mut checkouts = self.session_checkouts.lock();
            if !checkouts.insert(session_id.to_string()) {
                return Err(PoolError::Exhausted(format!(
                    "{} (session already has a checked-out connection)",
                    self.node_id
                )));
            }
        }

        let result = if let Some(conn) = self.take_reusable_idle() {
            Ok(conn)
        } else if self.try_reserve_slot() {
            self.create_reserved_connection().await
        } else {
            Err(PoolError::Exhausted(self.node_id.clone()))
        };

        match result {
            Ok(conn) => {
                self.record_checkout(&conn);
                Ok(conn)
            }
            Err(error) => {
                self.session_checkouts.lock().remove(session_id);
                Err(error)
            }
        }
    }

    async fn acquire_transaction_mode(&self, session_id: &str) -> Result<BackendConnection, PoolError> {
        // Check draining state
        if self.draining.load(Ordering::SeqCst) {
            return Err(PoolError::Exhausted(format!("{} (draining)", self.node_id)));
        }

        // Fast path: return a pinned connection for this session
        {
            let mut pinned = self.pinned_by_session.lock();
            let mut remove_entry = false;
            let connection = pinned.get_mut(session_id).and_then(|connections| {
                let connection = connections.pop();
                remove_entry = connections.is_empty();
                connection
            });
            if remove_entry {
                pinned.remove(session_id);
            }
            if let Some(connection) = connection {
                self.record_checkout(&connection);
                return Ok(connection);
            }
        }

        // Try idle queue first
        if let Some(conn) = self.take_reusable_idle() {
            self.record_checkout(&conn);
            return Ok(conn);
        }

        // Try to create a new connection
        if self.try_reserve_slot() {
            let conn = self.create_reserved_connection().await?;
            self.record_checkout(&conn);
            return Ok(conn);
        }

        // Pool exhausted — wait for a connection to be released
        if self.settings.acquire_timeout.is_zero() {
            return Err(PoolError::Exhausted(self.node_id.clone()));
        }

        let deadline = Instant::now() + self.settings.acquire_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(PoolError::AcquireTimeout {
                    node_id: self.node_id.clone(),
                    timeout_ms: self.settings.acquire_timeout.as_millis(),
                });
            }

            // Register the waiter BEFORE re-checking idle/capacity to close
            // the lost-wakeup window: if a release happens between our check
            // and the await, the notification is captured by this future.
            let notified = self.release_notify.notified();
            tokio::pin!(notified);

            // Re-check after registering — a slot may have become available.
            if let Some(conn) = self.take_reusable_idle() {
                self.record_checkout(&conn);
                return Ok(conn);
            }
            if self.try_reserve_slot() {
                let conn = self.create_reserved_connection().await?;
                self.record_checkout(&conn);
                return Ok(conn);
            }

            // Wait for a release notification or timeout
            match tokio::time::timeout(remaining, notified).await {
                Ok(()) => {
                    if self.draining.load(Ordering::SeqCst) {
                        return Err(PoolError::Exhausted(format!(
                            "{} (draining)",
                            self.node_id
                        )));
                    }
                    // Something was released — try again
                    if let Some(conn) = self.take_reusable_idle() {
                        self.record_checkout(&conn);
                        return Ok(conn);
                    }
                    if self.try_reserve_slot() {
                        let conn = self.create_reserved_connection().await?;
                        self.record_checkout(&conn);
                        return Ok(conn);
                    }
                    // Another waiter got it first, loop again
                }
                Err(_) => {
                    return Err(PoolError::AcquireTimeout {
                        node_id: self.node_id.clone(),
                        timeout_ms: self.settings.acquire_timeout.as_millis(),
                    });
                }
            }
        }
    }

    /// Records the checkout time for leak detection and increments the
    /// pool checkout counter (used to derive connection reuse ratio).
    fn record_checkout(&self, conn: &BackendConnection) {
        metrics::counter!("trident_pool_checkouts_total", "node_id" => self.node_id.clone()).increment(1);
        if !self.settings.leak_detection_threshold.is_zero() {
            self.checkout_times.lock().insert((conn.backend_pid, conn.secret_key), Instant::now());
        }
    }

    /// Clears checkout tracking and warns if the connection was held too long.
    fn clear_checkout(&self, conn: &BackendConnection) {
        if !self.settings.leak_detection_threshold.is_zero() {
            if let Some(checkout_time) = self.checkout_times.lock().remove(&(conn.backend_pid, conn.secret_key)) {
                let held_duration = Instant::now().duration_since(checkout_time);
                if held_duration >= self.settings.leak_detection_threshold {
                    tracing::warn!(
                        node_id = %self.node_id,
                        backend_pid = conn.backend_pid,
                        held_ms = held_duration.as_millis() as u64,
                        threshold_ms = self.settings.leak_detection_threshold.as_millis() as u64,
                        "potential connection leak detected: connection held longer than threshold"
                    );
                    metrics::counter!("trident_pool_leak_detections_total", "node_id" => self.node_id.clone()).increment(1);
                }
            }
        }
    }

    /// Dynamically resizes the pool's maximum connection count. Takes
    /// effect immediately for new acquire calls. Existing connections
    /// beyond the new limit are not forcibly closed — they drain naturally.
    pub fn resize(&self, new_max: u32) {
        let old = self.max_pool_size.swap(new_max, Ordering::SeqCst);
        if new_max > old {
            // More capacity available — wake waiting acquirers
            self.release_notify.notify_waiters();
        }
        tracing::info!(
            node_id = %self.node_id,
            old_max = old,
            new_max = new_max,
            "pool resized"
        );
    }

    /// Puts the pool into draining mode: new acquires are rejected,
    /// existing connections continue until released.
    pub fn drain(&self) {
        self.draining.store(true, Ordering::SeqCst);
        self.release_notify.notify_waiters();
        tracing::info!(node_id = %self.node_id, "pool entering drain mode");
    }

    /// Takes the pool out of draining mode.
    pub fn undrain(&self) {
        self.draining.store(false, Ordering::SeqCst);
    }

    async fn release_transaction_mode(
        &self,
        session_id: &str,
        mut conn: BackendConnection,
    ) -> Result<(), PoolError> {
        if conn.node_id != self.node_id {
            return Err(PoolError::NodeMismatch);
        }

        // Clear leak detection tracking
        self.clear_checkout(&conn);

        if self.draining.load(Ordering::SeqCst) {
            self.cleaner.discard(&conn);
            self.release_known_slot(&conn);
            self.release_notify.notify_waiters();
            return Ok(());
        }

        if conn.pinned {
            let mut pinned = self.pinned_by_session.lock();
            pinned.entry(session_id.to_string()).or_default().push(conn);
            return Ok(());
        }

        if conn.dirty {
            // Cancellation safety: arm a KnownSlotGuard so that if the
            // clean future is cancelled, the slot is released.
            let mut slot_guard = KnownSlotGuard {
                known_connections: &self.known_connections,
                active_connections: &self.active_connections,
                release_notify: &self.release_notify,
                key: (conn.backend_pid, conn.secret_key),
                armed: true,
            };

            let clean_result = self.cleaner.clean(&mut conn).await;
            // Defuse the guard — from here we handle the slot explicitly.
            slot_guard.defuse();
            match clean_result {
                Ok(()) => {
                    conn.dirty = false;
                    // Re-check draining after async clean: drain() may have
                    // been called while we were awaiting the DISCARD ALL.
                    if self.draining.load(Ordering::SeqCst) {
                        self.cleaner.discard(&conn);
                        self.release_known_slot(&conn);
                        self.release_notify.notify_waiters();
                        return Ok(());
                    }
                }
                Err(e) => {
                    // Cleanup failed: for safety, discard this connection
                    // rather than returning one that may still be in an
                    // unknown state, freeing its slot for a future new
                    // connection.
                    self.cleaner.discard(&conn);
                    self.release_known_slot(&conn);
                    // Notify waiters that a slot freed up
                    self.release_notify.notify_one();
                    return Err(e);
                }
            }
        }

        conn.idle_since = Some(Instant::now());
        self.idle.lock().push_back(conn);
        // Notify one waiting acquirer that a connection is available
        self.release_notify.notify_one();
        Ok(())
    }
}

#[async_trait]
impl<F: ConnFactory, C: ConnCleaner> ConnectionPool for NodePool<F, C> {
    fn mode(&self) -> PoolMode {
        self.mode
    }

    async fn acquire(&self, session_id: &str) -> Result<BackendConnection, PoolError> {
        match self.mode {
            PoolMode::Session => self.acquire_session_mode(session_id).await,
            PoolMode::Transaction => self.acquire_transaction_mode(session_id).await,
        }
    }

    async fn release(&self, session_id: &str, conn: BackendConnection) -> Result<(), PoolError> {
        match self.mode {
            PoolMode::Session => {
                if conn.node_id != self.node_id {
                    return Err(PoolError::NodeMismatch);
                }
                self.clear_checkout(&conn);
                self.session_checkouts.lock().remove(session_id);
                if self.draining.load(Ordering::SeqCst) {
                    self.cleaner.discard(&conn);
                    self.release_known_slot(&conn);
                    self.release_notify.notify_waiters();
                } else {
                    self.session_bindings
                        .lock()
                        .insert(session_id.to_string(), conn);
                }
                Ok(())
            }
            PoolMode::Transaction => self.release_transaction_mode(session_id, conn).await,
        }
    }

    fn pin(&self, _session_id: &str, conn: &mut BackendConnection) {
        conn.pinned = true;
    }

    fn discard(&self, conn: BackendConnection) -> Result<(), PoolError> {
        if conn.node_id != self.node_id {
            return Err(PoolError::NodeMismatch);
        }
        self.clear_checkout(&conn);
        self.forget_metadata(&conn);
        self.cleaner.discard(&conn);
        self.release_known_slot(&conn);
        // Slot freed — notify a waiting acquirer
        self.release_notify.notify_one();
        Ok(())
    }

    fn release_session(&self, session_id: &str) -> Vec<BackendConnection> {
        let connections = match self.mode {
            PoolMode::Session => {
                let mut bindings = self.session_bindings.lock();
                bindings.remove(session_id).into_iter().collect()
            }
            PoolMode::Transaction => {
                let mut pinned = self.pinned_by_session.lock();
                pinned.remove(session_id).unwrap_or_default()
            }
        };
        for connection in &connections {
            self.release_known_slot(connection);
        }
        if !connections.is_empty() {
            self.release_notify.notify_waiters();
        }
        self.session_checkouts.lock().remove(session_id);
        connections
    }

    fn active_connections(&self) -> i64 {
        self.active_connections.load(Ordering::SeqCst) as i64
    }

    fn idle_connections(&self) -> i64 {
        self.idle.lock().len() as i64
    }

    fn known_pids(&self) -> Vec<i32> {
        self.known_connections.lock().iter().map(|(pid, _)| *pid).collect()
    }

    async fn validate_idle(&self) -> usize {
        self.validate_idle_connections().await
    }

    fn drain(&self) {
        NodePool::drain(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::conn::test_utils::mock_backend_connection;
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicI32, AtomicU32 as StdAtomicU32};
    use std::sync::Arc;

    /// An I/O-free test connection factory: each call produces an
    /// incrementing `backend_pid`.
    struct CountingFactory {
        next_pid: AtomicI32,
        fail: bool,
    }

    impl CountingFactory {
        fn new() -> Self {
            CountingFactory {
                next_pid: AtomicI32::new(1),
                fail: false,
            }
        }
    }

    impl ConnFactory for CountingFactory {
        async fn create(&self, node_id: &str) -> Result<BackendConnection, PoolError> {
            if self.fail {
                return Err(PoolError::ConnectFailed("mock failure".into()));
            }
            let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
            Ok(mock_backend_connection(node_id, pid).await)
        }
    }

    /// A test cleaner that records the number of times it was invoked.
    #[derive(Clone)]
    struct CountingCleaner {
        clean_calls: Arc<StdAtomicU32>,
        discard_calls: Arc<StdAtomicU32>,
    }

    impl CountingCleaner {
        fn new() -> Self {
            CountingCleaner {
                clean_calls: Arc::new(StdAtomicU32::new(0)),
                discard_calls: Arc::new(StdAtomicU32::new(0)),
            }
        }

        fn call_count(&self) -> u32 {
            self.clean_calls.load(Ordering::SeqCst)
        }

        fn discard_count(&self) -> u32 {
            self.discard_calls.load(Ordering::SeqCst)
        }
    }

    impl ConnCleaner for CountingCleaner {
        async fn clean(&self, _conn: &mut BackendConnection) -> Result<(), PoolError> {
            self.clean_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn discard(&self, _conn: &BackendConnection) {
            self.discard_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn session_pool(max: u32) -> NodePool<CountingFactory, CountingCleaner> {
        NodePool::new("writer", PoolMode::Session, max, CountingFactory::new(), CountingCleaner::new())
    }

    fn transaction_pool(max: u32) -> NodePool<CountingFactory, CountingCleaner> {
        NodePool::new("writer", PoolMode::Transaction, max, CountingFactory::new(), CountingCleaner::new())
    }

    // -----------------------------------------------------------------
    // Property 24: in Session mode, the same client connection always
    // reuses the same backend connection
    // Validates: Requirements 5.1
    // -----------------------------------------------------------------

    proptest! {
        #[test]
        fn property_24_session_mode_reuses_same_connection(acquire_count in 1usize..20) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let pool = session_pool(10);
                let first = pool.acquire("session-1").await.unwrap();
                let first_pid = first.backend_pid;
                let first_node = first.node_id.clone();
                pool.release("session-1", first).await.unwrap();
                for _ in 0..acquire_count {
                    let again = pool.acquire("session-1").await.unwrap();
                    prop_assert_eq!(&again.node_id, &first_node);
                    prop_assert_eq!(again.backend_pid, first_pid);
                    pool.release("session-1", again).await.unwrap();
                }
                Ok(())
            })?;
        }

        // -----------------------------------------------------------------
        // Property 25: in Transaction mode, an unpinned connection can be
        // reused after being released
        // Validates: Requirements 5.2
        // -----------------------------------------------------------------
        #[test]
        fn property_25_transaction_mode_reuses_unpinned_connection(_unused in 0..1) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let pool = transaction_pool(10);
                let conn = pool.acquire("session-1").await.unwrap();
                let pid = conn.backend_pid;
                pool.release("session-1", conn).await.unwrap();

                let reacquired = pool.acquire("session-2").await.unwrap();
                prop_assert_eq!(reacquired.backend_pid, pid);
                Ok(())
            })?;
        }

        // -----------------------------------------------------------------
        // Property 26: after a connection is released, its dirty state is
        // correctly reset, and cleanup runs only when necessary
        // Validates: Requirements 5.3, 5.4
        // -----------------------------------------------------------------
        #[test]
        fn property_26_dirty_reset_and_conditional_cleanup(was_dirty in any::<bool>()) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let cleaner = CountingCleaner::new();
                let pool = NodePool::new(
                    "writer",
                    PoolMode::Transaction,
                    10,
                    CountingFactory::new(),
                    cleaner.clone(),
                );

                let mut conn = pool.acquire("s1").await.unwrap();
                conn.dirty = was_dirty;
                pool.release("s1", conn).await.unwrap();

                let reacquired = pool.acquire("s2").await.unwrap();
                prop_assert!(!reacquired.dirty);

                if was_dirty {
                    prop_assert_eq!(cleaner.call_count(), 1);
                } else {
                    prop_assert_eq!(cleaner.call_count(), 0);
                }
                Ok(())
            })?;
        }

        // -----------------------------------------------------------------
        // Property 27: the number of active connections never exceeds a
        // node's configured max pool size
        // Validates: Requirements 5.5
        // -----------------------------------------------------------------
        #[test]
        fn property_27_active_connections_never_exceed_max(
            max_pool_size in 1u32..10,
            acquire_attempts in 1usize..30,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let pool = transaction_pool(max_pool_size);
                let mut held = Vec::new();
                for i in 0..acquire_attempts {
                    match pool.acquire(&format!("s{i}")).await {
                        Ok(conn) => held.push(conn),
                        Err(PoolError::Exhausted(_)) => {}
                        Err(e) => return Err(TestCaseError::fail(format!("unexpected error: {e}"))),
                    }
                    prop_assert!(pool.active_connections() as u32 <= max_pool_size);
                }
                Ok(())
            })?;
        }

        // -----------------------------------------------------------------
        // Property 29: a pinned connection never enters the reusable
        // queue when released
        // Validates: Requirements 6.2
        // -----------------------------------------------------------------
        #[test]
        fn property_29_pinned_connection_never_reused(num_extra_acquires in 1usize..10) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let pool = transaction_pool(100);
                let mut conn = pool.acquire("s1").await.unwrap();
                let pinned_pid = conn.backend_pid;
                pool.pin("s1", &mut conn);
                pool.release("s1", conn).await.unwrap();

                // No matter how many acquire/release cycles happen
                // afterward, the pinned connection's backend_pid should
                // never reappear in any acquire result.
                for i in 0..num_extra_acquires {
                    let session_id = format!("s-extra-{i}");
                    let c = pool.acquire(&session_id).await.unwrap();
                    prop_assert_ne!(c.backend_pid, pinned_pid);
                    pool.release(&session_id, c).await.unwrap();
                }
                Ok(())
            })?;
        }

        // -----------------------------------------------------------------
        // Property 30: a pinned connection is reacquired only by its owner,
        // and ending that session releases it.
        // Validates: Requirements 6.2, 6.3
        // -----------------------------------------------------------------
        #[test]
        fn property_30_session_reacquires_then_releases_pinned_connection(
            reacquire_count in 1usize..8,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let pool = transaction_pool(10);
                let mut conn = pool.acquire("s1").await.unwrap();
                let pinned_pid = conn.backend_pid;
                pool.pin("s1", &mut conn);
                pool.release("s1", conn).await.unwrap();

                for _ in 0..reacquire_count {
                    let conn = pool.acquire("s1").await.unwrap();
                    prop_assert_eq!(conn.backend_pid, pinned_pid);
                    pool.release("s1", conn).await.unwrap();
                }
                prop_assert_eq!(pool.active_connections(), 1);

                let released = pool.release_session("s1");
                prop_assert_eq!(released.len(), 1);
                prop_assert_eq!(released[0].backend_pid, pinned_pid);
                prop_assert_eq!(pool.active_connections(), 0);
                Ok(())
            })?;
        }
    }

    // -----------------------------------------------------------------
    // 11.7 Unit tests
    // -----------------------------------------------------------------

    #[test]
    fn discard_all_statement_is_correct() {
        assert_eq!(DISCARD_ALL_STATEMENT, "DISCARD ALL");
    }

    #[test]
    fn precise_reset_statements_cover_expected_operations() {
        assert!(PRECISE_RESET_STATEMENTS.contains(&"RESET ALL"));
        assert!(PRECISE_RESET_STATEMENTS.contains(&"DEALLOCATE ALL"));
        assert!(PRECISE_RESET_STATEMENTS.contains(&"CLOSE ALL"));
        assert!(PRECISE_RESET_STATEMENTS.contains(&"UNLISTEN *"));
        assert!(PRECISE_RESET_STATEMENTS.contains(&"SET SESSION AUTHORIZATION DEFAULT"));
    }

    #[tokio::test]
    async fn acquire_returns_exhausted_error_when_pool_is_full() {
        let pool = transaction_pool(2);
        let _c1 = pool.acquire("s1").await.unwrap();
        let _c2 = pool.acquire("s2").await.unwrap();
        let result = pool.acquire("s3").await;
        assert!(matches!(result, Err(PoolError::Exhausted(ref n)) if n == "writer"));
    }

    #[tokio::test]
    async fn session_mode_release_restores_binding_until_session_ends() {
        let pool = session_pool(1);
        let conn = pool.acquire("s1").await.unwrap();
        pool.release("s1", conn).await.unwrap();
        // Release moves the complete connection back into the session binding.
        let again = pool.acquire("s1").await.unwrap();
        assert_eq!(again.backend_pid, 1);
        assert_eq!(pool.active_connections(), 1);
    }

    #[tokio::test]
    async fn concurrent_session_acquire_is_rejected_until_connection_is_released() {
        let cleaner = CountingCleaner::new();
        let pool = session_pool(1);

        let first = pool.acquire("same-session").await.unwrap();
        let concurrent = pool.acquire("same-session").await;
        assert!(matches!(concurrent, Err(PoolError::Exhausted(_))));
        assert_eq!(cleaner.discard_count(), 0);
        assert_eq!(pool.active_connections(), 1);

        let pid = first.backend_pid;
        pool.release("same-session", first).await.unwrap();
        let again = pool.acquire("same-session").await.unwrap();
        assert_eq!(again.backend_pid, pid);
        pool.release("same-session", again).await.unwrap();

        let released = pool.release_session("same-session");
        assert_eq!(released.len(), 1);
        assert_eq!(pool.active_connections(), 0);
        assert!(!pool.session_checkouts.lock().contains("same-session"));
    }

    #[tokio::test]
    async fn release_session_frees_session_mode_slot() {
        let pool = session_pool(1);
        let conn = pool.acquire("s1").await.unwrap();
        assert_eq!(pool.active_connections(), 1);
        pool.release("s1", conn).await.unwrap();
        let released = pool.release_session("s1");
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].backend_pid, 1);
        assert_eq!(pool.active_connections(), 0);

        // Once the slot is freed, a new connection can be established for
        // a new session.
        let conn2 = pool.acquire("s2").await.unwrap();
        assert_eq!(conn2.backend_pid, 2);
    }

    #[tokio::test]
    async fn pinned_connection_not_returned_to_idle_queue() {
        let pool = transaction_pool(5);
        let mut conn = pool.acquire("s1").await.unwrap();
        pool.pin("s1", &mut conn);
        assert!(conn.pinned);
        pool.release("s1", conn).await.unwrap();

        // No reusable idle connection in the pool (the pinned connection
        // was never enqueued), so a new connection must be established.
        let next = pool.acquire("s2").await.unwrap();
        assert_eq!(next.backend_pid, 2); // not the pinned pid=1
    }

    #[tokio::test]
    async fn release_session_frees_pinned_transaction_connections() {
        let pool = transaction_pool(2);
        let mut conn = pool.acquire("s1").await.unwrap();
        pool.pin("s1", &mut conn);
        pool.release("s1", conn).await.unwrap();
        assert_eq!(pool.active_connections(), 1);

        let released = pool.release_session("s1");
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].backend_pid, 1);
        assert_eq!(pool.active_connections(), 0);
    }

    #[tokio::test]
    async fn discard_frees_slot_and_never_returns_connection_to_idle_queue() {
        let pool = transaction_pool(1);
        let conn = pool.acquire("s1").await.unwrap();
        let discarded_pid = conn.backend_pid;
        pool.discard(conn).unwrap();
        assert_eq!(pool.active_connections(), 0);
        assert!(!pool.known_pids().contains(&discarded_pid));

        let replacement = pool.acquire("s2").await.unwrap();
        assert_eq!(replacement.backend_pid, 2);
    }

    #[tokio::test]
    async fn connection_creation_timeout_frees_reserved_slot() {
        struct SlowFactory;
        impl ConnFactory for SlowFactory {
            async fn create(&self, node_id: &str) -> Result<BackendConnection, PoolError> {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(mock_backend_connection(node_id, 1).await)
            }
        }

        let pool = NodePool::with_settings(
            "writer",
            PoolMode::Transaction,
            1,
            NodePoolSettings {
                connection_timeout: Duration::from_millis(5),
                ..NodePoolSettings::default()
            },
            SlowFactory,
            CountingCleaner::new(),
        );

        let result = pool.acquire("s1").await;
        assert!(matches!(
            result,
            Err(PoolError::ConnectTimeout {
                ref node_id,
                timeout_ms: 5
            }) if node_id == "writer"
        ));
        assert_eq!(pool.active_connections(), 0);
    }

    #[tokio::test]
    async fn warm_up_creates_configured_minimum_idle_connections() {
        let pool = NodePool::with_settings(
            "writer",
            PoolMode::Transaction,
            5,
            NodePoolSettings {
                min_pool_size: 3,
                ..NodePoolSettings::default()
            },
            CountingFactory::new(),
            CountingCleaner::new(),
        );

        pool.warm_up().await.unwrap();
        assert_eq!(pool.active_connections(), 3);
        assert_eq!(pool.idle.lock().len(), 3);

        let first = pool.acquire("s1").await.unwrap();
        let second = pool.acquire("s2").await.unwrap();
        let third = pool.acquire("s3").await.unwrap();
        assert_eq!(
            [first.backend_pid, second.backend_pid, third.backend_pid],
            [1, 2, 3]
        );
        assert_eq!(pool.active_connections(), 3);
    }

    #[tokio::test]
    async fn expired_idle_connection_is_discarded_before_reuse() {
        let cleaner = CountingCleaner::new();
        let pool = NodePool::with_settings(
            "writer",
            PoolMode::Transaction,
            2,
            NodePoolSettings {
                max_idle_time: Duration::from_secs(1),
                max_lifetime: Duration::from_secs(60),
                ..NodePoolSettings::default()
            },
            CountingFactory::new(),
            cleaner.clone(),
        );

        let conn = pool.acquire("s1").await.unwrap();
        pool.release("s1", conn).await.unwrap();
        pool.idle.lock().front_mut().unwrap().idle_since =
            Some(Instant::now() - Duration::from_secs(2));

        let replacement = pool.acquire("s2").await.unwrap();
        assert_eq!(replacement.backend_pid, 2);
        assert_eq!(cleaner.discard_count(), 1);
        assert_eq!(pool.active_connections(), 1);
    }

    #[tokio::test]
    async fn over_lifetime_idle_connection_is_discarded_before_reuse() {
        let cleaner = CountingCleaner::new();
        let pool = NodePool::with_settings(
            "writer",
            PoolMode::Transaction,
            2,
            NodePoolSettings {
                max_idle_time: Duration::from_secs(60),
                max_lifetime: Duration::from_secs(1),
                ..NodePoolSettings::default()
            },
            CountingFactory::new(),
            cleaner.clone(),
        );

        let mut conn = pool.acquire("s1").await.unwrap();
        conn.created_at = Instant::now() - Duration::from_secs(2);
        pool.release("s1", conn).await.unwrap();

        let replacement = pool.acquire("s2").await.unwrap();
        assert_eq!(replacement.backend_pid, 2);
        assert_eq!(cleaner.discard_count(), 1);
        assert_eq!(pool.active_connections(), 1);
    }

    #[tokio::test]
    async fn draining_pool_discards_released_connection_instead_of_requeueing_it() {
        let cleaner = CountingCleaner::new();
        let pool = NodePool::new(
            "writer",
            PoolMode::Transaction,
            1,
            CountingFactory::new(),
            cleaner.clone(),
        );
        let conn = pool.acquire("s1").await.unwrap();

        pool.drain();
        pool.release("s1", conn).await.unwrap();

        assert_eq!(pool.active_connections(), 0);
        assert_eq!(pool.idle_connections(), 0);
        assert_eq!(cleaner.discard_count(), 1);
        assert!(matches!(
            pool.acquire("s2").await,
            Err(PoolError::Exhausted(ref node)) if node.contains("draining")
        ));
    }

    #[tokio::test]
    async fn drain_wakes_waiting_acquirer() {
        let pool = Arc::new(NodePool::with_settings(
            "writer",
            PoolMode::Transaction,
            1,
            NodePoolSettings {
                acquire_timeout: Duration::from_secs(5),
                ..NodePoolSettings::default()
            },
            CountingFactory::new(),
            CountingCleaner::new(),
        ));
        let held = pool.acquire("s1").await.unwrap();
        let waiting_pool = Arc::clone(&pool);
        let waiter = tokio::spawn(async move { waiting_pool.acquire("s2").await });
        tokio::time::sleep(Duration::from_millis(10)).await;

        pool.drain();
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("drain must wake the waiter")
            .unwrap();

        assert!(matches!(
            result,
            Err(PoolError::Exhausted(ref node)) if node.contains("draining")
        ));
        pool.release("s1", held).await.unwrap();
        assert_eq!(pool.active_connections(), 0);
    }

    #[tokio::test]
    async fn cleanup_failure_drops_connection_and_frees_slot() {
        struct FailingCleaner;
        impl ConnCleaner for FailingCleaner {
            async fn clean(&self, _conn: &mut BackendConnection) -> Result<(), PoolError> {
                Err(PoolError::CleanupFailed("boom".into()))
            }
        }

        let pool = NodePool::new(
            "writer",
            PoolMode::Transaction,
            5,
            CountingFactory::new(),
            FailingCleaner,
        );
        let mut conn = pool.acquire("s1").await.unwrap();
        conn.dirty = true;
        let result = pool.release("s1", conn).await;
        assert!(matches!(result, Err(PoolError::CleanupFailed(_))));
        assert_eq!(pool.active_connections(), 0); // the slot was freed and the connection was discarded
    }
}
