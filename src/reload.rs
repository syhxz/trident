//! Hot reload for non-sensitive configuration (`reload`)
//!
//! Re-reads the config file from disk and applies only the subset of
//! settings considered safe to change without restarting the process (see
//! `RoutingReloadTarget` and DEPLOYMENT.md's hot-reload section):
//! `routing.enable_hint_routing`, `routing.enable_cost_routing`,
//! `routing.cost_threshold`, `routing.writer_readable`,
//! `routing.analytics_patterns`, and `routing.default_consistency`.
//!
//! Explicitly OUT of scope for hot reload (require a restart): anything
//! that would need tearing down and rebuilding a long-lived resource --
//! `proxy.listen_addr`, `nodes` (backend addresses/credentials), `pool.*`
//! (connection pool sizing/mode), `admin.*`. A reload request never
//! touches these, even if they changed in the file on disk.
//!
//! Two trigger mechanisms are provided:
//! - `watch_sighup`: reloads on receiving `SIGHUP` (the traditional Unix
//!   convention for "re-read your config", e.g. `kill -HUP <pid>` or
//!   `systemctl reload trident`).
//! - `admin::run`'s `POST /reload` route (see `admin` module) calls
//!   `reload_from_file` directly, for environments where sending a signal
//!   is inconvenient (e.g. some container runtimes).
//!
//! Both mechanisms share the same `reload_from_file` function, so they
//! always apply identical validation and produce identical results.

use std::sync::Arc;

use crate::config::{AppConfig, ConfigError, RoutingConfig};

/// Implemented by whatever in the running process needs to react to a
/// successfully reloaded config's `routing` section. `main.rs` implements
/// this for a small struct bundling the concrete `Router`,
/// `RegexPatternMatcher`, and `default_consistency` handle it constructed
/// at startup; kept as a trait (rather than reload.rs depending on the
/// concrete `Router<...>` generic type directly) so this module does not
/// need to know about the router's full type parameter list.
pub trait RoutingReloadTarget: Send + Sync {
    /// Applies the new routing configuration. Returns `Err` if any part of
    /// the update itself fails (e.g. a regex that somehow fails to
    /// recompile despite passing `AppConfig::validate`); implementations
    /// should apply as much as possible before returning an error rather
    /// than leaving things in an inconsistent partial state where
    /// avoidable.
    fn apply(&self, routing: &RoutingConfig) -> Result<(), String>;
}

/// Errors that can occur while reloading.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error("failed to load or validate config: {0}")]
    Config(#[from] ConfigError),

    #[error("failed to apply reloaded routing config: {0}")]
    Apply(String),
}

/// Re-reads and validates the config file at `path`, then applies its
/// `routing` section to `target`. The rest of the freshly loaded config
/// (nodes, pool, proxy, admin, logging) is intentionally discarded --
/// changing those requires a restart (see module docs).
///
/// Reuses `AppConfig::load_from_file`, so a syntactically invalid file, a
/// file that fails `AppConfig::validate` (e.g. a bad regex in
/// `analytics_patterns`), or an unresolvable password placeholder/`.pgpass`
/// lookup all cause this to return `Err` *without* calling
/// `target.apply` -- a bad reload attempt never partially applies or
/// disturbs the currently running configuration.
pub async fn reload_from_file(
    path: &str,
    target: &dyn RoutingReloadTarget,
) -> Result<(), ReloadError> {
    // `AppConfig::load_from_file` does blocking file I/O; run it on a
    // blocking-friendly thread so a slow/contended filesystem never stalls
    // the async runtime's worker threads.
    let path_owned = path.to_string();
    let config: AppConfig =
        tokio::task::spawn_blocking(move || AppConfig::load_from_file(&path_owned))
            .await
            .map_err(|e| ReloadError::Apply(format!("reload task panicked: {e}")))??;

    target.apply(&config.routing).map_err(ReloadError::Apply)?;

    Ok(())
}

/// Listens for `SIGHUP` and calls `reload_from_file` each time one is
/// received, logging the outcome. Runs until the process exits (intended
/// to be spawned as a background `tokio::task`); never returns early on a
/// failed reload -- the process keeps running with its last-known-good
/// configuration and will try again on the next `SIGHUP`.
///
/// No-op (logs a warning once and returns) on platforms without Unix
/// signals; `SIGHUP` is a Unix-specific mechanism, matching the `systemctl
/// reload` convention documented in `deploy/systemd/README.md`.
///
/// `config_write_lock`: if provided, serializes SIGHUP reloads against
/// Admin PUT/POST config operations so concurrent updates don't lose each
/// other's changes.
#[cfg(unix)]
pub async fn watch_sighup(
    path: String,
    target: Arc<dyn RoutingReloadTarget>,
    config_write_lock: Option<Arc<tokio::sync::Mutex<()>>>,
) {
    let mut signal = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to install SIGHUP handler; hot reload via signal disabled");
            return;
        }
    };

    loop {
        signal.recv().await;
        tracing::info!(path = %path, "received SIGHUP, reloading routing configuration");
        // FIX (reload race): Hold config_write_lock during SIGHUP reload
        // to prevent interleaving with Admin PUT operations.
        let _guard = if let Some(ref lock) = config_write_lock {
            Some(lock.lock().await)
        } else {
            None
        };
        match reload_from_file(&path, target.as_ref()).await {
            Ok(()) => tracing::info!("routing configuration reloaded successfully"),
            Err(e) => {
                tracing::warn!(error = %e, "routing configuration reload failed; keeping previous configuration")
            }
        }
    }
}

#[cfg(not(unix))]
pub async fn watch_sighup(
    _path: String,
    _target: Arc<dyn RoutingReloadTarget>,
    _config_write_lock: Option<Arc<tokio::sync::Mutex<()>>>,
) {
    tracing::warn!("SIGHUP-based hot reload is only supported on Unix; use the admin POST /reload endpoint instead");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct RecordingTarget {
        applied: Mutex<Vec<RoutingConfig>>,
        fail_next: AtomicUsize,
    }

    impl RecordingTarget {
        fn new() -> Self {
            RecordingTarget {
                applied: Mutex::new(Vec::new()),
                fail_next: AtomicUsize::new(0),
            }
        }
    }

    impl RoutingReloadTarget for RecordingTarget {
        fn apply(&self, routing: &RoutingConfig) -> Result<(), String> {
            if self.fail_next.load(Ordering::SeqCst) > 0 {
                self.fail_next.fetch_sub(1, Ordering::SeqCst);
                return Err("simulated apply failure".to_string());
            }
            self.applied.lock().unwrap().push(routing.clone());
            Ok(())
        }
    }

    fn write_minimal_config(cost_threshold: f64) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "trident-reload-test-{}-{}.yaml",
            std::process::id(),
            cost_threshold as u64
        ));
        let yaml = format!(
            "proxy:\n  listen_addr: \"0.0.0.0:6432\"\n  max_clients: 10\n\
             nodes:\n  - name: primary\n    host: 127.0.0.1\n    port: 5432\n    type: writer\n    weight: 1\n    database: mydb\n    username: proxy_user\n    password: secret\n\
             routing:\n  default_consistency: session\n  load_balance_strategy: weighted_round_robin\n  enable_transaction_split: true\n  split_respects_consistency: true\n  enable_hint_routing: true\n  enable_cost_routing: true\n  cost_threshold: {cost_threshold}\n  analytics_patterns: []\n  writer_readable: true\n  max_replication_lag_ms: 1000\n\
             pool:\n  mode: transaction\n  max_pool_size: 10\n  min_pool_size: 1\n  max_idle_time: 5m\n  connection_timeout: 5s\n  max_lifetime: 30m\n\
             health:\n  check_interval: 3s\n  check_timeout: 2s\n  max_retries: 3\n\
             logging:\n  level: info\n  query_trace: false\n  slow_query: 1000\n"
        );
        std::fs::write(&path, yaml).unwrap();
        path
    }

    #[tokio::test]
    async fn reload_from_file_applies_routing_section() {
        let path = write_minimal_config(42.0);
        let target = RecordingTarget::new();

        let result = reload_from_file(path.to_str().unwrap(), &target).await;
        let _ = std::fs::remove_file(&path);

        assert!(result.is_ok());
        let applied = target.applied.lock().unwrap();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].cost_threshold, 42.0);
    }

    #[tokio::test]
    async fn reload_from_file_never_calls_apply_when_config_is_invalid() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "trident-reload-invalid-{}.yaml",
            std::process::id()
        ));
        std::fs::write(&path, "not: [valid").unwrap();
        let target = RecordingTarget::new();

        let result = reload_from_file(path.to_str().unwrap(), &target).await;
        let _ = std::fs::remove_file(&path);

        assert!(matches!(result, Err(ReloadError::Config(_))));
        assert!(target.applied.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reload_from_file_missing_file_returns_config_error() {
        let target = RecordingTarget::new();
        let result = reload_from_file("/nonexistent/trident-reload-missing.yaml", &target).await;
        assert!(matches!(result, Err(ReloadError::Config(_))));
        assert!(target.applied.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reload_from_file_propagates_apply_failure() {
        let path = write_minimal_config(1.0);
        let target = RecordingTarget::new();
        target.fail_next.store(1, Ordering::SeqCst);

        let result = reload_from_file(path.to_str().unwrap(), &target).await;
        let _ = std::fs::remove_file(&path);

        assert!(matches!(result, Err(ReloadError::Apply(_))));
    }

    #[tokio::test]
    async fn repeated_reloads_apply_each_new_value() {
        let target = RecordingTarget::new();

        let path1 = write_minimal_config(10.0);
        reload_from_file(path1.to_str().unwrap(), &target)
            .await
            .unwrap();
        let _ = std::fs::remove_file(&path1);

        let path2 = write_minimal_config(20.0);
        reload_from_file(path2.to_str().unwrap(), &target)
            .await
            .unwrap();
        let _ = std::fs::remove_file(&path2);

        let applied = target.applied.lock().unwrap();
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0].cost_threshold, 10.0);
        assert_eq!(applied[1].cost_threshold, 20.0);
    }
}
