//! In-process Lua 5.4 collector runtime + 58 `host.*` bindings.
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
// `setup_history` is the deviation #16 module — renamed from the upstream
// `eventlog.rs`, which never actually touched the Event Log API (it only
// reads `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` and the
// `HKLM\SYSTEM\Setup\Source OS *` subkeys to derive `install_date`).  The
// real Event Log wrapper lives in `evt.rs` (deviation #10); keeping the
// old name would conflate the two modules.
#[cfg(windows)]
mod host;
#[cfg(windows)]
mod setup_history;
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
// `updates` exposes host bindings for the System Updates sub-category of
// ComplianceApp using WUA COM interfaces directly (IUpdateServiceManager2,
// ISystemInformation, IUpdateInstaller, IUpdateSession3) and WMI Root\ccm
// for SCCM-targeted updates. Deviations #26–#31.
#[cfg(windows)]
mod updates;
// `evt` is the Windows Event Log wrapper (EvtQuery + EvtRender) feeding
// `bitlocker.rs` recovery-key event queries (events 783, 845, 864, 775).
// Deviation #32.
#[cfg(windows)]
mod evt;
// `bitlocker` exposes the six BitLocker host bindings (volume status via
// Win32_EncryptableVolume + GetConversionStatus, key protector IDs and
// DRA thumbprints via WMI ExecMethod, FVE policy via registry value
// enumeration, recovery-key escrow + rotation via the BitLocker event
// log). Deviations #33–#37.
#[cfg(windows)]
mod bitlocker;
// `credentialguard` exposes the single host.credential_guard_status()
// binding, reading Win32_DeviceGuard from root\Microsoft\Windows\DeviceGuard
// and deriving two convenience booleans. Deviation #38.
#[cfg(windows)]
mod credentialguard;
// `cloud` exposes the 6 Cloud category bindings (AzureAD join status + MDM/
// Intune enrollment + MDM sync) via NetGetAadJoinInformation, WMI root\CIMV2\mdm,
// the Local Machine cert store, and event log 208/209 pairing. Deviation #39.
#[cfg(windows)]
mod cloud;
// `ep` exposes 2 Endpoint Protection bindings: all AV products registered with
// Windows Security Center (ROOT\SecurityCenter2\AntiVirusProduct + ProductState
// bitmask decode) and Windows Defender runtime status
// (ROOT\Microsoft\Windows\Defender\MSFT_MpComputerStatus). Deviation #40.
#[cfg(windows)]
mod ep;
// `firewall` exposes 3 Firewall bindings: Security Center firewall products
// (ROOT\SecurityCenter2\FirewallProduct + ProductState bitmask decode),
// Windows Defender Firewall status (root\StandardCimv2 MSFT_NetConnectionProfile +
// MSFT_NetFirewallProfile), and HNetCfg.FwProducts COM enumeration
// (INetFwProducts / INetFwProduct2 → RuleCategories). Deviation #42.
#[cfg(windows)]
mod firewall;
// `laps` exposes host.laps_state(): the Windows/Legacy LAPS posture (policy
// channel, backup directory, DLL presence, GP extension, max password age)
// via registry reads + System32 DLL probes. Mirrors the LAPS transformers in
// ComplianceApp (Security.cs). Deviation #44.
#[cfg(windows)]
mod laps;
// `sentinelone` exposes 3 SentinelOne EDR bindings: agent status via COM
// IDispatch late-binding (SentinelHelper.GetAgentStatusJSON), installation
// paths (Program Files\SentinelOne recursive exe search), and the newest
// SentinelOne/Operational #104 CommSdk event. Mirrors the SentinelOne data
// service in ComplianceApp (EDR/SentinelOne/SentinelOne.cs). Deviation #45.
#[cfg(windows)]
mod sentinelone;
// `cyberark` exposes 6 CyberArk EPM (legacy Viewfinity) bindings: the `vfpd`
// kernel driver status via the Service Control Manager, plus 5 values from
// HKLM\SOFTWARE\Viewfinity\Agent (version, last policy update, set id,
// dispatcher url, registered at). Mirrors the CyberArk EPM region of the
// Security data service in ComplianceApp (Security.cs). Deviation #46.
#[cfg(windows)]
mod cyberark;
// `sccm` exposes 9 SCCM (Configuration Manager) client-health bindings: six
// WMI reads against root\ccm and children (client version, assigned site via
// the SMS_Client.GetAssignedSite class method, current management point, MP
// list last-update date, inventory action status, installed-component status)
// plus three read-only reads of the ccmeval health report XML
// (C:\Windows\CCM\CcmEvalReport.xml — never regenerated). Mirrors the SCCM
// data service in ComplianceApp (SCCM.cs). Deviation #47.
#[cfg(windows)]
mod sccm;
// `wfp_known_guids` holds three lazily-initialised `HashMap<GUID, &str>` maps
// (layer GUIDs 110+, sublayer GUIDs 17+, condition field GUIDs ~100).
// Consumed by `wfp_conditions` and `wfp` for human-readable enrichment.
// Deviation #43.
#[cfg(windows)]
mod wfp_known_guids;
// `wfp_conditions` parses raw `FWPM_FILTER_CONDITION0[]` arrays into the
// intermediate `WfpCondition` type and serialises them as a JSON array
// (`conditions_json`) or a compact Unicode-symbol string (`format_compact`).
// Deviation #43.
#[cfg(windows)]
mod wfp_conditions;
// `wfp` provides two RAII types (`WfpEngine`, `WfpMemoryGuard`), the
// `WfpEnrichedFilter` / `WfpState` structs, `enumerate_wfp_state()` (six
// Win32 enumeration APIs), and `wfp_net_events()` (ephemeral engine +
// FwpmNetEventEnum2). Deviation #43.
#[cfg(windows)]
mod wfp;
// `wfp_pipeline` ports `WfpFilterPipeline.cs`: ALE filter, shadowing logic,
// deduplication grouping, and the two views `wfp_sublayer_details` /
// `wfp_firewall_view`. Deviation #43.
#[cfg(windows)]
mod wfp_pipeline;

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
