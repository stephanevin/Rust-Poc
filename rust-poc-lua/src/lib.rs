//! In-process Lua 5.4 collector runtime + 45 `host.*` bindings.
//!
//! This crate is **Windows-only** (real impl). On every other target
//! (Linux dev/CI, macOS until macOS host bindings exist) it compiles to
//! a thin stub that always errors — the fleet-client dispatcher can call
//! [`InternalRuntime::run`] without its own `cfg(target_os)` branch.
//!
//! ## Wire contract
//!
//! 17 of the 25 `host.*` bindings are a verbatim port of `HOST_API` in
//! the upstream `sdh-fleet-client/contracts` crate; the runtime here
//! MUST stay in lockstep with those — every change to `HOST_API` requires
//! a matching change in `host.rs` and a regenerated `host-api.json` (the
//! portal's Monaco editor depends on the JSON; the CI drift gate enforces
//! it). The remaining seven are deliberate additions: three hostname
//! variants (`host.netbios_name()`, `host.host_name()`, `host.fqdn()` in
//! [`hostname`], deviation #6) and four AD computer-object attributes
//! (`host.ad_computer_sam()`, `host.ad_computer_dn()`,
//! `host.ad_computer_cn()`, `host.ad_computer_site()` in [`adcomputer`],
//! deviation #7). See `CLAUDE.md` § *Deviations* for rationale.

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
// `hostname` is the deviation #6 module — added on top of the verbatim
// port to expose `host.netbios_name()`, `host.host_name()`, and
// `host.fqdn()` (machine-name variants via GetComputerNameExW).
#[cfg(windows)]
mod hostname;
// `adcomputer` is the deviation #7 module — AD computer-object attributes
// via GetComputerObjectNameW and DsGetSiteNameW, with GP registry fallback.
#[cfg(windows)]
mod adcomputer;
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
// `wts` exposes `host.terminal_sessions()` via WTSEnumerateSessionsW +
// WTSQuerySessionInformationW — mirrors TerminalSessionService from
// ComplianceApp/components.
#[cfg(windows)]
mod wts;
// `well_known_wnf_name` mirrors WellKnownWnfName.cs (Windows 24H2).
// Catalogue of 1 497 WNF state-name constants; consumed by `wnf`.
#[cfg(windows)]
mod well_known_wnf_name;
// `wnf` exposes host bindings backed by the Windows Notification Facility.
#[cfg(windows)]
mod wnf;
// `gpo` exposes host bindings for Group Policy Object lists and GP extension
// status, reading from the Group Policy registry State / Status hives.
#[cfg(windows)]
mod gpo;
// `tls` exposes host.tls_cipher_suites() via BCryptEnumContextFunctions —
// returns the effective Schannel cipher suite list (local + GP merged).
#[cfg(windows)]
mod tls;
// `regional` exposes host bindings for regional/locale information:
// user and system UI language, user and system locale, keyboard layouts.
// Mirrors the 6 C# transformers in DataTransformers/Regional via Win32 NLS APIs.
#[cfg(windows)]
mod regional;
// `accounts` exposes host bindings for the Accounts section of ComplianceApp:
// user profiles (registry ProfileList), local user accounts (NetUserEnum +
// NetUserGetInfo level 4), and local group members (NetLocalGroupGetMembers
// level 2).  Deviations #19–#21.
#[cfg(windows)]
mod accounts;
// `software` exposes host bindings for the Software sub-category of ComplianceApp:
// installed software (registry Uninstall + WTS per-user), Windows services
// (Win32 SC APIs), browser extensions (Chromium prefs + manifests), and IDE
// extensions (VS Code-family extensions.json + package.json). Deviations #22–#25.
#[cfg(windows)]
mod software;

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
