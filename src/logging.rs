//! Tracing subscriber initialisation.
//!
//! Two layers: a compact console writer (stderr, human-readable) and a
//! JSON daily-rolling file writer. No hot-reload — Rust-Poc has no
//! external config source that would benefit from it. See
//! `sdh-fleet-client/src/logging.rs` for the full hot-reload variant
//! when that is needed.
//!
//! # Log directory resolution
//!
//! Resolved in this order, first match wins:
//!
//! 1. The `RUST_POC_LOG_DIR` environment variable, if set.
//! 2. `<directory containing the executable>/logs/`.
//! 3. The literal string `logs` (relative to the current working
//!    directory) — last-resort fallback when `std::env::current_exe`
//!    fails, which is rare (sandbox / dangling symlink scenarios).
//!
//! Same algorithm as `sdh-fleet-client/src/logging.rs`. The env var
//! name was renamed to match this workspace.
//!
//! # Filtering
//!
//! Reads `RUST_LOG` (e.g. `RUST_LOG=rust_poc=debug`) and falls back to
//! `INFO` when the variable is unset. Invalid directives are dropped
//! silently (`from_env_lossy`) rather than panicking on startup.
//!
//! # Return value
//!
//! Returns a `WorkerGuard` that the caller MUST keep alive for the
//! whole duration of the program (typically stored in a `_log_guard`
//! local in `main`). When the guard is dropped, the non-blocking file
//! writer's background thread shuts down — any pending log lines still
//! in the channel are lost.

use std::fs;
use std::path::PathBuf;

use tracing::info;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Name of the env var that overrides the log directory. Public so
/// tests and operational docs can reference it by symbol rather than
/// string-literal.
pub const LOG_DIR_ENV_VAR: &str = "RUST_POC_LOG_DIR";

/// File prefix before the rolling-date suffix. tracing-appender will
/// produce e.g. `rust-poc.log.2026-05-20`.
pub const LOG_FILE_PREFIX: &str = "rust-poc.log";

/// Installs the global tracing subscriber and returns the file
/// appender's worker guard.
///
/// The returned guard is itself `#[must_use]` (upstream contract in
/// `tracing-appender`), so we don't re-mark this function — the caller
/// gets the right diagnostic from the type alone.
///
/// Panics-by-design: if the registry has already been installed, this
/// call fails. That's intentional — the global subscriber is a
/// process-wide singleton and double-init is always a bug.
pub fn init() -> WorkerGuard {
    let log_dir = resolve_log_dir();

    // Best-effort create. tracing-appender will surface any real
    // failure on the first write (silently dropped, as is its policy
    // for non-blocking appenders). Mirrors the "logging is best-effort"
    // posture documented in `sdh-fleet-client/README.md`.
    let _ = fs::create_dir_all(&log_dir);

    let file_appender = tracing_appender::rolling::daily(&log_dir, LOG_FILE_PREFIX);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking);

    let console_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_writer(std::io::stderr);

    let env_filter = EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .with(console_layer)
        .init();

    info!(
        log_dir = %log_dir.display(),
        log_file_prefix = LOG_FILE_PREFIX,
        version = env!("CARGO_PKG_VERSION"),
        "logging initialised"
    );

    guard
}

fn resolve_log_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(LOG_DIR_ENV_VAR) {
        return PathBuf::from(dir);
    }

    // Fall back to <exe-dir>/logs/ then to ./logs/ if even
    // `current_exe()` fails (sandbox, weird symlink — rare).
    std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(std::path::Path::parent)
        .map_or_else(|| PathBuf::from("logs"), |p| p.join("logs"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both scenarios live in a single test because cargo runs unit
    /// tests in parallel by default. Mutating `RUST_POC_LOG_DIR` from
    /// two separate tests would race — one test's `set_var` could be
    /// observed by the other test's `resolve_log_dir` call. Splitting
    /// would require a `Mutex` or `--test-threads=1`; merging is
    /// simpler and just as informative.
    ///
    /// In Rust 2024, `set_var` / `remove_var` are marked `unsafe`
    /// because the underlying libc calls are not thread-safe with
    /// respect to readers in other threads. We accept that risk here
    /// because this is the only test in the crate that touches that
    /// specific variable, and we restore the previous state on exit.
    #[test]
    fn resolve_log_dir_priority_chain() {
        let previous = std::env::var(LOG_DIR_ENV_VAR).ok();

        // --- (1) env var wins when set --------------------------------
        // SAFETY: see test-level doc comment.
        unsafe {
            std::env::set_var(LOG_DIR_ENV_VAR, "C:/some/explicit/path");
        }
        assert_eq!(
            resolve_log_dir(),
            PathBuf::from("C:/some/explicit/path"),
            "env var should override every fallback",
        );

        // --- (2) fallback to <exe-dir>/logs when env var unset --------
        // SAFETY: see test-level doc comment.
        unsafe {
            std::env::remove_var(LOG_DIR_ENV_VAR);
        }
        let resolved = resolve_log_dir();
        assert_eq!(
            resolved.file_name().and_then(|s| s.to_str()),
            Some("logs"),
            "fallback path must end in 'logs'",
        );

        // Restore prior state for any code that runs after this test.
        // SAFETY: see test-level doc comment.
        unsafe {
            if let Some(v) = previous {
                std::env::set_var(LOG_DIR_ENV_VAR, v);
            }
        }
    }
}
