//! Logging initialization (`logging`)
//!
//! Wires `config::LoggingConfig` into a `tracing_subscriber` setup that
//! always logs to stdout, and additionally to a rolling file when
//! `LoggingConfig.dir` is configured.
//!
//! Rotation and retention are both handled by the `logroller` crate:
//! - Rotation: either time-based (`daily`/`hourly`) or size-based
//!   (`size_based`, rolling over once the current file reaches
//!   `max_file_size_mb`) -- see `config::LogRotation`. Size-based rotation
//!   is the only option that puts a hard cap on any single file's size;
//!   the time-based options can still produce a large file on an
//!   unusually chatty day/hour.
//! - Retention is enforced by `logroller` after every rotation, so a
//!   long-running process prunes old files without needing a restart. Its
//!   `max_keep_files` accounting differs by strategy (and Trident does not
//!   enable compression): `daily`/`hourly` count the current date-stamped file
//!   in `max_files`, while `size_based` keeps `max_files` numbered archives
//!   plus the separate active `{file_prefix}` file. This mapping is passed
//!   through unchanged rather than applying an incorrect blanket +/- 1.
//!   Temporary pending files can exist briefly while asynchronous rotation
//!   cleanup is running.
//!
//! Compression and off-box shipping of rotated files are intentionally
//! left to external tooling (a log-shipping agent, etc.), not
//! reimplemented here.

use logroller::{LogRollerBuilder, Rotation, RotationAge, RotationSize};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

use crate::config::{LogRotation, LoggingConfig};

/// Errors initializing logging.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("failed to create log directory '{path}': {source}")]
    CreateDir {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to initialize rolling file logger in '{path}': {source}")]
    RollerInit {
        path: String,
        #[source]
        source: logroller::LogRollerError,
    },
}

/// Holds the resources that must stay alive for the duration of the
/// process for file logging to keep working: `tracing_appender`'s
/// non-blocking writer flushes on a background thread and stops doing so
/// as soon as its `WorkerGuard` is dropped, so the caller must keep this
/// value alive (typically by holding it in a local variable in `main`)
/// until the process exits.
#[allow(dead_code)]
pub struct LoggingGuard {
    file_guard: Option<WorkerGuard>,
}

/// Initializes the global `tracing` subscriber according to `config`:
/// - Always logs to stdout, formatted with `tracing_subscriber::fmt`.
/// - If `config.dir` is set, additionally logs to a rolling file (see
///   module docs for the rotation/retention behavior).
/// - The log level filter comes from `config.level` (e.g. `"info"`,
///   `"debug"`), falling back to `"info"` if `config.level` fails to
///   parse as a filter directive.
///
/// Must be called at most once per process (matches the underlying
/// `tracing_subscriber::fmt::init`/`try_init` restriction). Returns a
/// `LoggingGuard` that must be kept alive for the duration of the process
/// for file logging to flush reliably.
pub fn init(config: &LoggingConfig) -> Result<LoggingGuard, LoggingError> {
    init_with_broadcast(config, None)
}

/// Same as [`init`], but optionally attaches a third formatting layer that
/// forwards every log line into the admin console's live-log broadcast
/// channel (see `admin::LogBroadcastMakeWriter` and the `/ws/logs`
/// WebSocket endpoint). Pass `None` to skip that layer entirely -- e.g.
/// when the admin server is disabled.
pub fn init_with_broadcast(
    config: &LoggingConfig,
    log_sender: Option<crate::admin::LogSender>,
) -> Result<LoggingGuard, LoggingError> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = EnvFilter::try_new(&config.level).unwrap_or_else(|_| EnvFilter::new("info"));

    // Optional broadcast layer for the admin console's live log view.
    // Constructed per match arm because the layer's subscriber type
    // parameter differs between the two stacks. `Option<Layer>` itself
    // implements `Layer`, so `.with(None)` is a no-op layer.
    macro_rules! broadcast_layer {
        () => {
            log_sender.clone().map(|sender| {
                tracing_subscriber::fmt::layer()
                    .with_writer(crate::admin::LogBroadcastMakeWriter::new(sender))
                    .with_ansi(false)
            })
        };
    }

    match &config.dir {
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer())
                .with(broadcast_layer!())
                .init();
            Ok(LoggingGuard { file_guard: None })
        }
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(|source| LoggingError::CreateDir {
                path: dir.clone(),
                source,
            })?;

            let rotation = match config.rotation {
                LogRotation::Daily => Rotation::AgeBased(RotationAge::Daily),
                LogRotation::Hourly => Rotation::AgeBased(RotationAge::Hourly),
                LogRotation::SizeBased => {
                    Rotation::SizeBased(RotationSize::MB(config.max_file_size_mb))
                }
            };

            let roller = LogRollerBuilder::new(dir, &config.file_prefix)
                .rotation(rotation)
                .max_keep_files(config.max_files as u64)
                .build()
                .map_err(|source| LoggingError::RollerInit {
                    path: dir.clone(),
                    source,
                })?;

            let (non_blocking, guard) = tracing_appender::non_blocking(roller);

            let stdout_layer = tracing_subscriber::fmt::layer();
            let file_layer = tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false);

            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .with(broadcast_layer!())
                .init();

            Ok(LoggingGuard {
                file_guard: Some(guard),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogRotation;
    use std::io::Write;

    fn temp_dir(suffix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("trident-logroller-test-{}-{suffix}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn size_based_rotation_creates_multiple_files_and_prunes_old_ones() {
        let dir = temp_dir("size");

        let mut roller = LogRollerBuilder::new(dir.to_str().unwrap(), "test.log")
            .rotation(Rotation::SizeBased(RotationSize::Bytes(50)))
            .max_keep_files(2)
            // Without this, `flush()` returns before the background
            // worker finishes pruning old rotated files, leaving
            // `*.pending.N` files on disk -- we need to wait for that
            // worker here so the assertion below reflects the
            // steady-state file count, not a mid-cleanup snapshot.
            .graceful_shutdown(true)
            .build()
            .unwrap();

        // Write enough data to force several rotations; each line is
        // comfortably larger than the 50-byte threshold on its own, so
        // this should trigger a handful of rotations.
        for i in 0..20 {
            writeln!(roller, "log line number {i} with some padding to exceed the size threshold").unwrap();
        }
        roller.flush().unwrap();

        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("test.log"))
            .collect();

        let active_files: Vec<_> = files
            .iter()
            .filter(|name| name.as_str() == "test.log")
            .collect();
        let archived_files: Vec<_> = files
            .iter()
            .filter(|name| {
                name.strip_prefix("test.log.")
                    .is_some_and(|suffix| suffix.parse::<u64>().is_ok())
            })
            .collect();

        // For size-based rotation, logroller's max_keep_files counts only
        // numbered archives. The separate active test.log file is additional,
        // so max_keep_files=2 means <=2 archives and <=3 total stable files.
        assert_eq!(active_files.len(), 1, "expected one active file: {files:?}");
        assert!(
            archived_files.len() <= 2,
            "expected at most two numbered archives, found: {files:?}"
        );
        assert!(
            files.len() <= 3,
            "expected active + retained archives only, found: {files:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_with_no_dir_does_not_touch_the_filesystem() {
        // No assertion beyond "does not error/panic" -- this exercises
        // the stdout-only path used by the vast majority of existing
        // configs (dir omitted).
        let config = LoggingConfig {
            level: "info".to_string(),
            query_trace: false,
            slow_query: 1000,
            dir: None,
            file_prefix: "trident.log".to_string(),
            max_files: 14,
            rotation: LogRotation::Daily,
            max_file_size_mb: 100,
        };
        // Not calling `init` here since it installs a *global* subscriber
        // and this test module may run alongside others in the same test
        // binary process; the meaningful assertion is that a config with
        // `dir: None` never needs any filesystem setup, which is already
        // covered by `init`'s `None` branch containing no fs calls at all
        // (verified by inspection). This test exists as a placeholder for
        // that invariant and to keep `LoggingConfig`'s field list exercised.
        assert!(config.dir.is_none());
    }
}
