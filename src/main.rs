//! `collect-config` — runs a Lua collector script against the local host.
//!
//! Root binary of the workspace. Loads `collectors/<script_name>`,
//! executes its global `collect()` function in a sandboxed mlua VM
//! with the full `host.*` table from `rust-poc-lua`, and prints the
//! returned JSON object to stdout.
//!
//! Same role as `sdh-fleet-client/src/main.rs` once the fleet path is
//! reduced to its collector loop: read script, sandbox, dispatch,
//! serialise. No NATS, no transport — the trigger is a CLI invocation.
//!
//! ## Usage
//!
//! ```text
//! cargo run -- general.lua
//! cargo run -- general.lua some-perimeter
//! ```
//!
//! Logs and progress go to stderr (plus a JSON daily-rolling file under
//! the resolved log directory — see the `logging` module). Only the
//! JSON result goes to stdout, so the binary is pipe-friendly:
//!
//! ```text
//! cargo run --quiet -- general.lua > config.json
//! cargo run --quiet -- general.lua | jq '.machine_name'
//! ```
//!
//! ## Per-run output file
//!
//! Each successful run also writes the same JSON to a per-run file
//! `<script_stem>_<hostname>_YYYYMMDDhhmmss_fff.json` (local wall-clock,
//! 18-char timestamp: 14 chars `YYYYMMDDhhmmss` + `_` + 3-digit
//! millisecond suffix, to keep two runs in the same second from
//! colliding) next to the rolling log. Example:
//! `general_E00AVDDWDEV0271_20260520120140_837.json`. The file is a
//! best-effort audit trail — a failure to write it warns on stderr and
//! the rest of the run still succeeds (the stdout JSON is the primary
//! contract).
//!
//! ## Exit codes
//!
//! - `0` — success
//! - `1` — Lua runtime error (script error, missing file at run time, timeout)
//! - `2` — cannot read hostname
//! - `3` — cannot serialize Lua output to JSON
//! - `4` — script path escapes the `collectors/` directory (path traversal rejected)

mod logging;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use rust_poc_lua::InternalRuntime;

// `#[tokio::main]` expands to a synchronous `main` that constructs a
// multi-thread runtime and blocks on the async body below. `multi_thread`
// is required because `InternalRuntime::run` calls `spawn_blocking`, and
// a `current_thread` runtime can't schedule blocking tasks.
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    // `_log_guard` must stay alive for the whole program. When it is
    // dropped, the non-blocking file writer's worker thread shuts down
    // and any pending log lines still in its channel are lost. Same
    // invariant as `sdh-fleet-client/src/main.rs::_log_guard`.
    //
    // `log_dir` is captured here (rather than re-resolved later) so
    // the per-run JSON dump file lands in the SAME directory as the
    // rolling log even if RUST_POC_LOG_DIR changes mid-run.
    let (_log_guard, log_dir) = logging::init();

    let args: Vec<String> = std::env::args().collect();
    let script = args.get(1).cloned().unwrap_or_else(|| "general.lua".into());
    let perimeter = args.get(2).map(String::as_str);

    let cache_dir = PathBuf::from("collectors");

    // Reject any script path that would escape ./collectors/ before we
    // hand the string to InternalRuntime::run. The engine itself
    // (verbatim port from sdh-fleet-client) trusts its caller — the
    // trust boundary for user input lives here.
    if let Err(e) = resolve_script_path(&cache_dir, &script) {
        eprintln!("collect-config: {e}");
        return ExitCode::from(4);
    }

    // `hostname::get` is the cross-platform way to read the machine
    // name (GetComputerNameW on Windows, gethostname() on Unix). The
    // runtime exposes it to Lua scripts as `host.env("SDH_HOSTNAME")`.
    let hostname = match hostname::get() {
        Ok(h) => h.to_string_lossy().into_owned(),
        Err(e) => {
            eprintln!("collect-config: cannot read hostname: {e}");
            return ExitCode::from(2);
        }
    };

    let runtime = InternalRuntime::new(
        cache_dir,
        hostname.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
    );

    eprintln!(
        "collect-config: running {script} (perimeter={})",
        perimeter.unwrap_or("<none>")
    );

    match runtime
        .run(&script, perimeter, Duration::from_secs(30))
        .await
    {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(json) => {
                write_output_file(&log_dir, &script, &hostname, &json);
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("collect-config: serialize output: {e}");
                ExitCode::from(3)
            }
        },
        Err(e) => {
            eprintln!("collect-config: {e}");
            ExitCode::from(1)
        }
    }
}

/// Writes `json` to a per-run audit file under `log_dir`. Best-effort:
/// any I/O failure is downgraded to a `tracing::warn!` so the stdout
/// JSON contract (the primary deliverable) is preserved.
///
/// File name format: `<script_stem>_<hostname>_YYYYMMDDhhmmss_fff.json`,
/// e.g. `general_E00AVDDWDEV0271_20260520120140_837.json`. Local
/// wall-clock is used so the file name sorts naturally for an admin
/// in the same timezone as the machine.
fn write_output_file(log_dir: &Path, script: &str, hostname: &str, json: &str) {
    let timestamp = chrono::Local::now().format("%Y%m%d%H%M%S_%3f").to_string();
    let file_name = output_file_name(script, hostname, &timestamp);
    let out_path = log_dir.join(&file_name);

    match std::fs::write(&out_path, json) {
        Ok(()) => tracing::info!(path = %out_path.display(), "wrote JSON output file"),
        Err(e) => tracing::warn!(
            path = %out_path.display(),
            error = %e,
            "failed to write JSON output file (stdout JSON still emitted)"
        ),
    }
}

/// Builds the per-run output file name from its three constituents.
///
/// `Path::file_stem` strips the LAST extension, so `general.lua` becomes
/// `general` and `subdir/general.lua` becomes `general`. A script
/// without an extension (e.g. `general`) is used as-is. Pure function
/// — separated out so `#[cfg(test)]` can pin the exact string format
/// without touching the clock or the filesystem.
///
/// # Known gap — basename collisions across subdirectories
///
/// Because only the basename's stem is kept, two scripts with the same
/// file name in different subdirs of `collectors/` (e.g.
/// `collectors/rd/general.lua` and `collectors/mns/general.lua`) would
/// generate the SAME output file name within the same millisecond
/// window and the second run would silently overwrite the first.
/// `collectors/` is intentionally flat today so this gap is dormant.
/// When the layout grows subdirs, fold a sanitised relative path
/// segment (e.g. `rd_general`, `mns_general`) into the stem.
fn output_file_name(script: &str, hostname: &str, timestamp: &str) -> String {
    let stem = Path::new(script)
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(script);
    format!("{stem}_{hostname}_{timestamp}.json")
}

/// Resolves `script` against `cache_dir` and guarantees the result stays
/// strictly inside the canonicalised `cache_dir`. Returns the canonical
/// script path on success.
///
/// `Path::join` has a well-known footgun: when the joined component is
/// an absolute path, it REPLACES the base instead of appending to it.
/// A naive `cache_dir.join(script)` would therefore let an attacker
/// pass `C:\Windows\System32\anything.lua` and the runtime would
/// happily read it. Canonicalising both sides and asserting the
/// `starts_with` invariant closes that loophole as well as the more
/// classic `../../escape.lua` pattern.
fn resolve_script_path(cache_dir: &Path, script: &str) -> Result<PathBuf, String> {
    let cache_root = cache_dir
        .canonicalize()
        .map_err(|e| format!("cannot canonicalize {}: {e}", cache_dir.display()))?;

    let candidate = cache_dir
        .join(script)
        .canonicalize()
        .map_err(|e| format!("cannot resolve script path {script}: {e}"))?;

    if !candidate.starts_with(&cache_root) {
        return Err(format!(
            "script path {script} escapes {}",
            cache_dir.display()
        ));
    }

    Ok(candidate)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // These tests rely on the workspace shipping `collectors/general.lua`
    // and a `Cargo.toml` at the package root, both tracked in git.
    // `cargo test` runs from the package root, so the relative paths
    // below resolve.

    #[test]
    fn accepts_a_script_inside_the_cache_directory() {
        let result = resolve_script_path(Path::new("collectors"), "general.lua");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn rejects_parent_directory_traversal() {
        let result = resolve_script_path(Path::new("collectors"), "../Cargo.toml");
        assert!(
            result.is_err(),
            "expected Err for ../Cargo.toml, got {result:?}"
        );
    }

    #[test]
    fn rejects_an_absolute_path_outside_the_cache() {
        // CWD/Cargo.toml exists but lives outside ./collectors. The
        // canonicalize step succeeds; the starts_with check is what
        // must reject the candidate.
        let absolute = std::env::current_dir().unwrap().join("Cargo.toml");
        let result = resolve_script_path(Path::new("collectors"), absolute.to_str().unwrap());
        assert!(
            result.is_err(),
            "expected Err for {absolute:?}, got {result:?}"
        );
    }

    // ---- output_file_name --------------------------------------------------
    //
    // Pure function, decoupled from chrono. The timestamp is passed in
    // as a &str so the test can pin the exact byte sequence the user
    // requested in the spec (see commit history / chat).

    #[test]
    fn output_file_name_strips_the_lua_extension() {
        assert_eq!(
            output_file_name("general.lua", "E00AVDDWDEV0271", "20260520120140_837"),
            "general_E00AVDDWDEV0271_20260520120140_837.json"
        );
    }

    #[test]
    fn output_file_name_strips_directory_components() {
        // `Path::file_stem` returns just the basename's stem, so the
        // optional subdir prefix the user could type as the script arg
        // (e.g. `subdir/general.lua`) does not leak into the output
        // file name.
        assert_eq!(
            output_file_name("subdir/general.lua", "HOST", "TS"),
            "general_HOST_TS.json"
        );
    }

    #[test]
    fn output_file_name_handles_a_script_with_no_extension() {
        assert_eq!(
            output_file_name("general", "HOST", "TS"),
            "general_HOST_TS.json"
        );
    }

    #[test]
    fn output_file_name_strips_only_the_last_extension() {
        // Edge case: `general.lua.bak` -> stem is `general.lua`. The
        // user explicitly types this name; preserving everything up
        // to the final dot is the principle of least surprise.
        assert_eq!(
            output_file_name("general.lua.bak", "HOST", "TS"),
            "general.lua_HOST_TS.json"
        );
    }
}
