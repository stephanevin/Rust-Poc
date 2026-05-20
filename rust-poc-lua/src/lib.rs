//! In-process Lua 5.4 collector runtime + 17 `host.*` bindings.
//!
//! This crate is **Windows-only** (real impl). On every other target
//! (Linux dev/CI, macOS until macOS host bindings exist) it compiles to
//! a thin stub that always errors — the fleet-client dispatcher can call
//! [`InternalRuntime::run`] without its own `cfg(target_os)` branch.
//!
//! ## Wire contract
//!
//! The 17 `host.*` Lua bindings (see `HOST_API` in the sdh-fleet-client/contracts crate)
//! are the source of truth. The runtime module here MUST stay in lockstep —
//! every change to `HOST_API` requires a matching change in `host.rs` and
//! a regenerated `host-api.json` (the portal's Monaco editor depends on
//! the JSON; the CI drift gate enforces it).

/// Failures from the Lua collector runtime.
///
/// Single-variant — every failure (file read, sandbox install, script
/// compile/run, timeout, JSON conversion) returns the same diagnose-friendly
/// shape. The caller maps this into its broader error vocabulary.
#[derive(Debug, thiserror::Error)]
#[error("lua collector: {0}")]
pub struct LuaError(pub String);

#[cfg(windows)]
mod ad;
#[cfg(windows)]
mod eventlog;
#[cfg(windows)]
mod host;
#[cfg(windows)]
mod net;
#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod runtime;
#[cfg(windows)]
mod sandbox;
#[cfg(windows)]
mod winver;
#[cfg(windows)]
mod wmi;

#[cfg(windows)]
pub use runtime::InternalRuntime;

/// Linux/macOS/other-target stub.
///
/// Same surface as the Windows real impl so the collector dispatcher
/// doesn't need a `cfg(target_os)` branch at the call site. Every method
/// returns [`LuaError`] — the actual VM and host bindings live behind
/// `#[cfg(windows)]` because `mlua` plus the WMI/Registry/ADSI bindings
/// only make sense on Windows today.
#[cfg(not(windows))]
pub struct InternalRuntime;

#[cfg(not(windows))]
impl InternalRuntime {
    #[must_use]
    pub fn new(_cache_dir: std::path::PathBuf, _hostname: String, _client_version: String) -> Self {
        Self
    }

    /// # Errors
    ///
    /// Always returns [`LuaError`] — the Lua runtime is Windows-only.
    // Async signature mirrors the Windows real impl so the dispatcher
    // can `.await` the call without `cfg(target_os)` branching.
    #[allow(clippy::unused_async)]
    pub async fn run(
        &self,
        _entry_path: &str,
        _perimeter: Option<&str>,
        _timeout: std::time::Duration,
    ) -> Result<serde_json::Value, LuaError> {
        Err(LuaError(
            "lua runtime is not available on this target".into(),
        ))
    }
}
