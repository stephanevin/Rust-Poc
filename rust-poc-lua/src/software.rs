//! Software host bindings for the **Software** sub-category of `ComplianceApp`.
//!
//! Four `pub(super)` functions mirror `DataTransformers/OperatingSystem/`,
//! `DataTransformers/Browser/`, and `DataTransformers/IDE/`:
//!
//! | Function | C# Transformer | Source |
//! |---|---|---|
//! | [`os_software_installed`] | `OSSoftwareInstalled.cs` | Registry `Uninstall` keys (machine + WTS per-user) |
//! | [`os_services`] | `OSServices.cs` | Win32 Service Control Manager |
//! | [`browser_extensions_installed`] | `BrowserExtensionsInstalled.cs` | Chromium `manifest.json` + `Preferences` |
//! | [`ide_extensions_installed`] | `IdeExtensionsInstalled.cs` | `extensions.json` + `package.json` |
//!
//! ## Deviation #22 — `os_software_installed` machine + WTS only
//!
//! `ComplianceApp` adds a snapshot/persistence layer (WTS active sessions →
//! copy HKU hives to HKLM for future runs). We skip the persistence entirely
//! and read per-user software live from `HKEY_USERS\{SID}\…\Uninstall` for
//! sessions that are **currently Active** according to `WTSEnumerateSessionsW`.
//!
//! ## Deviation #23 — `os_services` uses Win32 SC APIs, not WMI
//!
//! `Win32_Service` via WMI carries COM/marshalling overhead. The SC Manager
//! APIs (`OpenSCManagerW` + `EnumServicesStatusExW` + `QueryServiceConfigW` +
//! `QueryServiceConfig2W`) are lighter and return identical data.

// Win32 out-params follow the &mut-local pattern used throughout this crate.
#![allow(clippy::borrow_as_ptr, clippy::ref_as_ptr)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde_json::{Value, json};

use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATE, ENUM_SERVICE_STATUS_PROCESSW, ENUM_SERVICE_TYPE,
    EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfig2W, QueryServiceConfigW, SC_ENUM_TYPE, SC_HANDLE, SERVICE_CONFIG,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_DELAYED_AUTO_START_INFO,
};
use windows::core::PCWSTR;

// --- Service Control Manager constants not exposed as typed consts in 0.62 --

const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
const SERVICE_QUERY_CONFIG: u32 = 0x0001;
/// Win32 services (own-process + shared-process). Matches `Win32_Service` WMI.
const SERVICE_WIN32: u32 = 0x0000_0030;
const SERVICE_STATE_ALL: u32 = 0x0000_0003;

// --- Registry paths -----------------------------------------------------------

const UNINSTALL_64: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
const UNINSTALL_32: &str = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

// --- Shared time helpers ------------------------------------------------------

/// Converts a `SystemTime` to an ISO 8601 UTC string, or `None` on overflow.
fn systime_to_iso8601(t: std::time::SystemTime) -> Option<String> {
    let unix_secs = i64::try_from(t.duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()?;
    // FILETIME ticks = (unix_secs + EPOCH_DIFF) * 10_000_000
    // EPOCH_DIFF: seconds between 1601-01-01 and 1970-01-01
    let ticks = unix_secs
        .checked_add(11_644_473_600)?
        .checked_mul(10_000_000)?;
    super::winver::filetime_to_iso8601(ticks)
}

/// Converts a Unix timestamp in **milliseconds** (e.g. VS Code `installedTimestamp`)
/// to an ISO 8601 UTC string.
fn unix_ms_to_iso8601(ms: i64) -> Option<String> {
    if ms <= 0 {
        return None;
    }
    let ticks = (ms / 1000)
        .checked_add(11_644_473_600)?
        .checked_mul(10_000_000)?;
    super::winver::filetime_to_iso8601(ticks)
}

/// Converts a Unix timestamp in **fractional seconds** (Chromium `active_time`)
/// to an ISO 8601 UTC string.
fn unix_fsecs_to_iso8601(secs: f64) -> Option<String> {
    if secs <= 0.0 {
        return None;
    }
    // Truncation is intentional: sub-second precision is irrelevant for timestamps.
    #[allow(clippy::cast_possible_truncation)]
    let ticks = (secs as i64)
        .checked_add(11_644_473_600)?
        .checked_mul(10_000_000)?;
    super::winver::filetime_to_iso8601(ticks)
}

// =============================================================================
// Section 1 — os_software_installed
// =============================================================================

/// Tries to extract a product-code GUID from an `UninstallString` or registry
/// subkey name. Looks for the last `{...}` block of exactly 38 characters.
fn extract_software_code(uninstall_string: Option<&str>, key_name: &str) -> Option<String> {
    let try_guid = |s: &str| -> Option<String> {
        let start = s.rfind('{')?;
        let rest = &s[start..];
        if rest.len() >= 38 && rest.as_bytes().get(37) == Some(&b'}') {
            Some(rest[..38].to_string())
        } else {
            None
        }
    };
    if let Some(s) = uninstall_string
        && let Some(g) = try_guid(s)
    {
        return Some(g);
    }
    // Fallback: the subkey name itself is sometimes the GUID.
    if key_name.starts_with('{') && key_name.len() == 38 && key_name.ends_with('}') {
        return Some(key_name.to_string());
    }
    None
}

/// Converts an `InstallDate` registry value in `yyyyMMdd` format to
/// `"yyyy-MM-ddT00:00:00Z"`, or `None` when the value is absent or malformed.
fn parse_install_date(s: &str) -> Option<String> {
    if s.len() != 8 {
        return None;
    }
    let year = &s[0..4];
    let month = &s[4..6];
    let day = &s[6..8];
    let _y: u16 = year.parse().ok()?;
    let m: u8 = month.parse().ok()?;
    let d: u8 = day.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(format!("{year}-{month}-{day}T00:00:00Z"))
}

/// Reads all sub-keys under `{hive}\{base_key}` and maps them to software
/// entries with the given `context`. Skips sub-keys without a `DisplayName`.
///
/// The second element of the returned tuple distinguishes:
/// - `Ok(())`  — the hive opened (with zero or more entries), **or** the
///   key path is absent (a per-user hive for a profile that installed
///   nothing is a normal case);
/// - `Err(msg)` — `RegOpenKeyExW` failed for any other reason (access
///   denied, etc.).  `os_software_installed` aggregates these so the
///   operator sees `os_software_installed:registry` in `host.errors()`
///   instead of silently getting an empty (or partial) array.
fn read_uninstall_entries(
    hive: &str,
    base_key: &str,
    context: &str,
) -> (Vec<Value>, Result<(), String>) {
    let sub_keys = match super::registry::try_subkey_names(hive, base_key) {
        Ok(v) => v,
        Err(e) => return (Vec::new(), Err(e)),
    };
    let mut rows = Vec::with_capacity(sub_keys.len());

    for sub in &sub_keys {
        let full = format!("{base_key}\\{sub}");

        let display_name = match super::registry::read(hive, &full, "DisplayName") {
            Ok(Some(Value::String(s))) if !s.is_empty() => s,
            _ => continue,
        };

        let publisher = match super::registry::read(hive, &full, "Publisher") {
            Ok(Some(Value::String(s))) => Some(s),
            _ => None,
        };
        let version = match super::registry::read(hive, &full, "DisplayVersion") {
            Ok(Some(Value::String(s))) => Some(s),
            _ => None,
        };
        let install_date = super::registry::read(hive, &full, "InstallDate")
            .ok()
            .flatten()
            .as_ref()
            .and_then(|v| v.as_str())
            .and_then(parse_install_date);

        let system_component = matches!(
            super::registry::read(hive, &full, "SystemComponent"),
            Ok(Some(Value::Number(ref n))) if n.as_u64() == Some(1)
        );

        let uninstall_string = match super::registry::read(hive, &full, "UninstallString") {
            Ok(Some(Value::String(s))) => Some(s),
            _ => None,
        };
        let software_code = extract_software_code(uninstall_string.as_deref(), sub);

        rows.push(json!({
            "context":          context,
            "system_component": system_component,
            "publisher":        publisher,
            "display_name":     display_name,
            "version":          version,
            "install_date":     install_date,
            "software_code":    software_code,
        }));
    }

    (rows, Ok(()))
}

/// Deduplicates Uninstall registry rows by
/// `(context, publisher, display_name, version, software_code)`.
///
/// When two rows share the same key, the **non**-`system_component` entry
/// wins (mirrors `ComplianceApp`'s pickier MSI/EXE rule).  Insertion
/// order is preserved among kept entries — `os_software_installed`
/// reorders deterministically afterwards.
///
/// ## Strong-identifier guard
///
/// A row only participates in deduplication when **at least one** of
/// `publisher`, `version`, or `software_code` is non-empty.  Without
/// this guard, two genuinely distinct apps that happen to share a
/// `display_name` and lack every optional field would map to the same
/// `(context, "", display_name, "", "")` key and silently collapse —
/// silent data loss.  Weak-identity rows therefore each occupy their
/// own slot in the output.
///
/// Extracted from [`os_software_installed`] so the rule can be exercised
/// by unit tests without touching the registry.
fn deduplicate_software(rows: Vec<Value>) -> Vec<Value> {
    let mut seen: HashMap<(String, String, String, String, String), usize> = HashMap::new();
    let mut deduped: Vec<Value> = Vec::new();

    for row in rows {
        let publisher = row["publisher"].as_str().unwrap_or("");
        let version = row["version"].as_str().unwrap_or("");
        let software_code = row["software_code"].as_str().unwrap_or("");

        // Strong-identifier guard: rows with zero optional metadata are
        // never merged.  See doc-comment above.
        if publisher.is_empty() && version.is_empty() && software_code.is_empty() {
            deduped.push(row);
            continue;
        }

        let key = (
            row["context"].as_str().unwrap_or("").to_string(),
            publisher.to_string(),
            row["display_name"].as_str().unwrap_or("").to_string(),
            version.to_string(),
            software_code.to_string(),
        );
        let is_sys = row["system_component"].as_bool().unwrap_or(false);

        if let Some(&idx) = seen.get(&key) {
            // Replace existing entry only when the new one is NOT a system component.
            if !is_sys && deduped[idx]["system_component"].as_bool().unwrap_or(false) {
                deduped[idx] = row;
            }
        } else {
            seen.insert(key, deduped.len());
            deduped.push(row);
        }
    }

    deduped
}

/// Returns all installed software from the Windows Uninstall registry keys.
///
/// Machine-context entries come from `HKLM\…\Uninstall` (64-bit and 32-bit).
/// Per-user entries are read from `HKEY_USERS\{SID}\…\Uninstall` for every
/// **Active** domain session reported by `WTSEnumerateSessionsW`.
///
/// Mirrors `OSSoftwareInstalled.cs` + `OperatingSystem.GetSoftwareInstalled()`.
///
/// # Examples
///
/// ```ignore
/// let (apps, wts_err, registry_err) = os_software_installed();
/// // apps:        [{"context": "Machine", "display_name": "Git", ...}, ...]
/// // wts_err:     None | Some("WTSEnumerateSessionsW failed: ...")
/// // registry_err: None | Some("HKLM\\…\\Uninstall: RegOpenKeyExW(...) failed ...")
/// ```
///
/// # Errors (second and third elements)
///
/// The second element is `Some(message)` when `WTSEnumerateSessionsW`
/// fails — record it under `"os_software_installed:wts"` so the operator
/// knows that per-user software is absent, not merely empty.
///
/// The third element is `Some(message)` when **at least one** HKLM
/// Uninstall hive could not be opened for a reason other than absence
/// (i.e. the operator likely lacks read permission or the registry is
/// inaccessible) — record it under `"os_software_installed:registry"`.
/// HKU failures are intentionally absorbed: a profile without a loaded
/// hive is a normal best-effort case, not an operator-actionable error.
#[must_use = "callers must record the WTS / registry diagnostics in host.errors()"]
pub(super) fn os_software_installed() -> (Vec<Value>, Option<String>, Option<String>) {
    let mut all: Vec<Value> = Vec::new();
    let mut registry_errors: Vec<String> = Vec::new();

    // Machine-context (always present on healthy installs).
    let (rows64, err64) = read_uninstall_entries("HKLM", UNINSTALL_64, "Machine");
    all.extend(rows64);
    if let Err(e) = err64 {
        registry_errors.push(format!("HKLM\\{UNINSTALL_64}: {e}"));
    }
    let (rows32, err32) = read_uninstall_entries("HKLM", UNINSTALL_32, "Machine");
    all.extend(rows32);
    if let Err(e) = err32 {
        registry_errors.push(format!("HKLM\\{UNINSTALL_32}: {e}"));
    }

    let registry_err = if registry_errors.is_empty() {
        None
    } else {
        Some(registry_errors.join("; "))
    };

    // Per-user context: live WTS sessions only (no persistence).  HKU
    // open failures are intentionally absorbed — a profile without a
    // loaded hive is a normal case, not an operator-actionable error.
    let wts_err = match super::wts::active_domain_sessions() {
        Ok(sessions) => {
            for (sid, nt_account) in sessions {
                let key64 = format!("{sid}\\{UNINSTALL_64}");
                let key32 = format!("{sid}\\{UNINSTALL_32}");
                let (r64, _) = read_uninstall_entries("HKU", &key64, &nt_account);
                let (r32, _) = read_uninstall_entries("HKU", &key32, &nt_account);
                all.extend(r64);
                all.extend(r32);
            }
            None
        }
        Err(e) => Some(e),
    };

    let mut deduped = deduplicate_software(all);

    // Sort: context ordinal ("Machine" < SID strings), then display_name ASC.
    deduped.sort_by(|a, b| {
        let ca = a["context"].as_str().unwrap_or("");
        let cb = b["context"].as_str().unwrap_or("");
        ca.cmp(cb).then_with(|| {
            let da = a["display_name"].as_str().unwrap_or("").to_lowercase();
            let db = b["display_name"].as_str().unwrap_or("").to_lowercase();
            da.cmp(&db)
        })
    });

    (deduped, wts_err, registry_err)
}

// =============================================================================
// Section 2 — os_services
// =============================================================================

/// RAII guard for a Win32 `SC_HANDLE`.
///
/// Calls `CloseServiceHandle` on drop — same pattern as `NetBuf` in
/// `accounts.rs`. See [Rust Book ch. 15.3](https://doc.rust-lang.org/book/ch15-03-drop.html).
///
/// `pub(crate)` so sibling modules (e.g. `cyberark`, deviation #46) can reuse
/// the SC Manager teardown instead of duplicating the `unsafe` Drop.
pub(crate) struct ScHandle(pub(crate) SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            // SAFETY: `self.0` is a valid SC_HANDLE returned by OpenSCManagerW
            // or OpenServiceW. CloseServiceHandle is idempotent on valid handles.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

/// Maps a Win32 `dwStartType` (`SERVICE_START_TYPE`) to its string label.
///
/// Values mirror `ServiceStartMode` in `Win32_Service` WMI / `QUERY_SERVICE_CONFIGW`.
fn start_mode_label(t: u32) -> &'static str {
    match t {
        0 => "Boot",
        1 => "System",
        2 => "Auto",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    }
}

/// Maps a Win32 `dwCurrentState` (`SERVICE_STATUS_CURRENT_STATE`) to its string label.
///
/// `pub(crate)` so `cyberark::driver_status` (deviation #46) emits labels
/// identical to `host.os_services()`.
pub(crate) fn service_state_label(s: u32) -> &'static str {
    match s {
        1 => "Stopped",
        2 => "StartPending",
        3 => "StopPending",
        4 => "Running",
        5 => "ContinuePending",
        6 => "PausePending",
        7 => "Paused",
        _ => "Unknown",
    }
}

/// Converts a null-terminated UTF-16 pointer to a `String`. Returns an empty
/// string for null pointers.
///
/// # Safety
///
/// `ptr` must be null or point to a null-terminated UTF-16 sequence that
/// remains valid for the duration of this call.
unsafe fn pwstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // Walking to the NUL terminator is the only way to determine length.
    // In practice strings are bounded by MAX_PATH (260) or service name limits.
    #[allow(clippy::maybe_infinite_iter)]
    let len = (0..).take_while(|&i| unsafe { *ptr.add(i) != 0 }).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Returns all Windows services as an array of JSON objects.
///
/// Each entry mirrors `WindowsServiceRow` from `ComplianceApp`:
/// - `display_name`, `name` — display and short service name
/// - `start_mode`           — `"Auto"`, `"Manual"`, `"Disabled"`, etc.
/// - `delayed_auto_start`   — `bool`
/// - `state`                — `"Running"`, `"Stopped"`, etc.
/// - `start_name`           — service account (e.g. `"LocalSystem"`)
/// - `path_name`            — binary path / command line
///
/// Uses Win32 SC Manager APIs instead of WMI for lower overhead.
///
/// The second element of the returned tuple is the count of services
/// for which `OpenServiceW` failed (typically: the service was removed
/// between the enumeration and the per-service open).  Those rows are
/// emitted with `start_mode`, `path_name` and `start_name` set to
/// `null` — the caller records `os_services:partial` so the operator
/// knows that some config fields are missing rather than empty.
///
/// # Errors
///
/// Returns a descriptive `String` when `OpenSCManagerW` itself fails
/// (the all-or-nothing failure that means we got zero services).
///
/// # Examples
///
/// ```ignore
/// let (svcs, partial) = os_services()?;
/// // svcs:    [{"display_name": "Windows Update", "state": "Running", ...}, ...]
/// // partial: 0 on a quiescent machine; > 0 when services were removed mid-enum
/// ```
#[allow(clippy::too_many_lines)]
pub(super) fn os_services() -> Result<(Vec<Value>, u32), String> {
    // Open Service Control Manager with enumerate access.
    // SAFETY: null PCWSTR is valid for the local machine / default database.
    let hsc =
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) }
            .map_err(|e| format!("OpenSCManagerW failed: {e}"))?;
    let _hsc = ScHandle(hsc);

    // First call: determine required buffer size (null buffer → ERROR_MORE_DATA).
    let mut needed: u32 = 0;
    let mut returned: u32 = 0;
    // SAFETY: None<&mut [u8]> is the documented sizing probe (null ptr, 0 size).
    unsafe {
        let _ = EnumServicesStatusExW(
            hsc,
            SC_ENUM_TYPE(0), // SC_ENUM_PROCESS_INFO = 0
            ENUM_SERVICE_TYPE(SERVICE_WIN32),
            ENUM_SERVICE_STATE(SERVICE_STATE_ALL),
            None,
            &mut needed,
            &mut returned,
            None,
            PCWSTR::null(),
        );
    }

    if needed == 0 {
        return Ok((Vec::new(), 0));
    }

    // Second call: fill buffer with all service entries.
    let mut buf = vec![0u8; needed as usize];
    // SAFETY: `buf` has `needed` bytes as reported by the sizing probe.
    unsafe {
        EnumServicesStatusExW(
            hsc,
            SC_ENUM_TYPE(0),
            ENUM_SERVICE_TYPE(SERVICE_WIN32),
            ENUM_SERVICE_STATE(SERVICE_STATE_ALL),
            Some(&mut buf),
            &mut needed,
            &mut returned,
            None,
            PCWSTR::null(),
        )
    }
    .map_err(|e| format!("EnumServicesStatusExW failed: {e}"))?;

    // Cast buffer to array of ENUM_SERVICE_STATUS_PROCESSW.
    // SAFETY: EnumServicesStatusExW with SC_ENUM_PROCESS_INFO fills the buffer
    // as a packed array of ENUM_SERVICE_STATUS_PROCESSW structs; `returned` is
    // the element count. The lpServiceName / lpDisplayName pointers in each
    // struct point into the trailing string data within `buf`.
    #[allow(clippy::cast_ptr_alignment)]
    let entries = unsafe {
        std::slice::from_raw_parts(
            buf.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
            returned as usize,
        )
    };

    let mut rows: Vec<Value> = Vec::with_capacity(returned as usize);
    let mut partial_skips: u32 = 0;

    for entry in entries {
        // SAFETY: lpServiceName/lpDisplayName are valid null-terminated UTF-16
        // strings within `buf` for the lifetime of this loop.
        let short_name = unsafe { pwstr_to_string(entry.lpServiceName.as_ptr().cast_const()) };
        let display_name = unsafe { pwstr_to_string(entry.lpDisplayName.as_ptr().cast_const()) };
        let state = service_state_label(entry.ServiceStatusProcess.dwCurrentState.0);

        // Open the individual service for config queries.
        let hsvc_result = unsafe { OpenServiceW(hsc, entry.lpServiceName, SERVICE_QUERY_CONFIG) };
        let Ok(hsvc_raw) = hsvc_result else {
            // Service may have been removed since enumeration; emit partial
            // row and count it so the caller can surface `os_services:partial`.
            partial_skips = partial_skips.saturating_add(1);
            rows.push(json!({
                "display_name":      display_name,
                "start_mode":        Value::Null,
                "delayed_auto_start": false,
                "state":             state,
                "start_name":        Value::Null,
                "path_name":         Value::Null,
                "name":              short_name,
            }));
            continue;
        };
        let _hsvc = ScHandle(hsvc_raw);

        // QueryServiceConfigW — two-call pattern.
        let mut cfg_needed: u32 = 0;
        // SAFETY: null buffer / 0 size is the documented sizing probe.
        unsafe {
            let _ = QueryServiceConfigW(hsvc_raw, None, 0, &mut cfg_needed);
        }

        let (start_mode, path_name, start_name) = if cfg_needed > 0 {
            let mut cfg_buf = vec![0u8; cfg_needed as usize];
            let ok = unsafe {
                #[allow(clippy::cast_ptr_alignment)]
                QueryServiceConfigW(
                    hsvc_raw,
                    Some(cfg_buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
                    cfg_needed,
                    &mut cfg_needed,
                )
            };
            if ok.is_ok() {
                // SAFETY: QueryServiceConfigW fills cfg_buf as QUERY_SERVICE_CONFIGW;
                // all pointer fields point into the trailing string data within cfg_buf.
                #[allow(clippy::cast_ptr_alignment)]
                let cfg = unsafe { &*cfg_buf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
                (
                    start_mode_label(cfg.dwStartType.0),
                    unsafe { pwstr_to_string(cfg.lpBinaryPathName.as_ptr().cast_const()) },
                    unsafe { pwstr_to_string(cfg.lpServiceStartName.as_ptr().cast_const()) },
                )
            } else {
                ("Unknown", String::new(), String::new())
            }
        } else {
            ("Unknown", String::new(), String::new())
        };

        // QueryServiceConfig2W for delayed auto-start.
        let mut delayed_info = SERVICE_DELAYED_AUTO_START_INFO::default();
        let delayed_auto_start = unsafe {
            // SAFETY: `delayed_info` is a correctly-sized local; the slice
            // covers exactly `size_of::<SERVICE_DELAYED_AUTO_START_INFO>` bytes.
            let buf = std::slice::from_raw_parts_mut(
                std::ptr::from_mut(&mut delayed_info).cast::<u8>(),
                std::mem::size_of::<SERVICE_DELAYED_AUTO_START_INFO>(),
            );
            let mut bytes_out: u32 = 0;
            QueryServiceConfig2W(
                hsvc_raw,
                SERVICE_CONFIG(SERVICE_CONFIG_DELAYED_AUTO_START_INFO.0),
                Some(buf),
                &mut bytes_out,
            )
        }
        .is_ok()
            && delayed_info.fDelayedAutostart.as_bool();

        rows.push(json!({
            "display_name":       display_name,
            "start_mode":         start_mode,
            "delayed_auto_start": delayed_auto_start,
            "state":              state,
            "start_name":         start_name,
            "path_name":          path_name,
            "name":               short_name,
        }));
    }

    rows.sort_by(|a, b| {
        let da = a["display_name"].as_str().unwrap_or("").to_lowercase();
        let db = b["display_name"].as_str().unwrap_or("").to_lowercase();
        da.cmp(&db)
    });

    Ok((rows, partial_skips))
}

// =============================================================================
// Section 3 — browser_extensions_installed
// =============================================================================

/// Maps a Chromium `ManifestLocation` integer to its canonical enum label.
///
/// Values are taken from `extensions/common/manifest.h` in the Chromium source
/// tree (stable since Chrome 58 / Edge 18). Unknown codes are rendered as
/// `"Unknown(<n>)"`.
fn manifest_location_label(code: i64) -> String {
    match code {
        0 => "InvalidLocation".to_string(),
        1 => "Internal".to_string(),
        2 => "ExternalPref".to_string(),
        3 => "ExternalRegistry".to_string(),
        4 => "Unpacked".to_string(),
        5 => "Component".to_string(),
        6 => "ExternalPrefDownload".to_string(),
        7 => "ExternalRegistryDownload".to_string(),
        8 => "ExternalPolicy".to_string(),
        9 => "ExternalPolicyDownload".to_string(),
        10 => "CommandLine".to_string(),
        11 => "ExternalComponent".to_string(),
        n => format!("Unknown({n})"),
    }
}

/// Per-extension settings extracted from Chromium `Preferences` /
/// `Secure Preferences`. All fields default to "safe" values when absent.
#[derive(Default)]
struct ExtensionPrefs {
    enabled: bool,
    location: String,
    disable_reasons: i64,
    blocklist_state: i64,
    creation_flags: i64,
    acknowledged: bool,
    granted_api_permissions: String,
    granted_host_permissions: String,
}

impl ExtensionPrefs {
    fn default_enabled() -> Self {
        Self {
            enabled: true,
            location: manifest_location_label(0),
            ..Default::default()
        }
    }
}

/// Parses a single `extensions.settings.<id>` JSON object into `ExtensionPrefs`.
fn parse_single_prefs(obj: &serde_json::Value) -> ExtensionPrefs {
    let enabled = obj.get("state").and_then(Value::as_i64) != Some(0);

    let location =
        manifest_location_label(obj.get("location").and_then(Value::as_i64).unwrap_or(0));

    let disable_reasons = if let Some(v) = obj.get("disable_reasons") {
        if let Some(n) = v.as_i64() {
            n
        } else if let Some(arr) = v.as_array() {
            arr.iter()
                .filter_map(Value::as_i64)
                .filter(|&n| n > 0)
                .fold(0i64, |acc, n| acc | n)
        } else {
            0
        }
    } else {
        0
    };

    let blocklist_state = obj
        .get("blocklist_state")
        .or_else(|| obj.get("blacklist_state"))
        .and_then(Value::as_i64)
        .unwrap_or(0);

    let creation_flags = obj
        .get("creation_flags")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    let acknowledged = [
        "ack_external",
        "ack_settings_overridden",
        "ack_ntp_overridden",
        "ack_search_provider_overridden",
    ]
    .iter()
    .any(|k| obj.get(*k).and_then(Value::as_bool).unwrap_or(false))
        || obj
            .get("ack_prompt_count")
            .and_then(Value::as_i64)
            .is_some_and(|n| n > 0);

    let (granted_api_permissions, granted_host_permissions) =
        if let Some(gp) = obj.get("granted_permissions").and_then(Value::as_object) {
            let api = extract_json_string_array(gp.get("api"));
            let explicit = extract_json_string_array(gp.get("explicit_host"));
            let scriptable = extract_json_string_array(gp.get("scriptable_host"));
            let host = merge_dedup_strings(&explicit, &scriptable);
            (api, host)
        } else {
            (String::new(), String::new())
        };

    ExtensionPrefs {
        enabled,
        location,
        disable_reasons,
        blocklist_state,
        creation_flags,
        acknowledged,
        granted_api_permissions,
        granted_host_permissions,
    }
}

/// Parses `Preferences` and `Secure Preferences` files into a per-extension
/// map. `Secure Preferences` wins on duplicate extension IDs.
fn parse_chromium_preferences(
    prefs: Option<&str>,
    secure_prefs: Option<&str>,
) -> HashMap<String, ExtensionPrefs> {
    let mut map: HashMap<String, ExtensionPrefs> = HashMap::new();

    for content in [prefs, secure_prefs].into_iter().flatten() {
        let Ok(doc) = serde_json::from_str::<Value>(content) else {
            continue;
        };
        let Some(settings) = doc
            .get("extensions")
            .and_then(|e| e.get("settings"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        for (id, ext_obj) in settings {
            map.insert(id.clone(), parse_single_prefs(ext_obj));
        }
    }

    map
}

/// Reads `Local State` JSON and extracts the `active_time` (Unix seconds) per
/// browser-profile name. Returns empty map on any error.
fn local_state_activity_map(user_data_path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let path = user_data_path.join("Local State");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return map;
    };
    let Ok(doc) = serde_json::from_str::<Value>(&content) else {
        return map;
    };
    let Some(info_cache) = doc
        .pointer("/profile/info_cache")
        .and_then(Value::as_object)
    else {
        return map;
    };
    for (profile_name, entry) in info_cache {
        if let Some(ts) = entry
            .get("active_time")
            .and_then(Value::as_f64)
            .filter(|&v| v > 0.0)
            .and_then(unix_fsecs_to_iso8601)
        {
            map.insert(profile_name.clone(), ts);
        }
    }
    map
}

/// Tries to resolve a Chromium NLS placeholder `__MSG_<key>__` using the
/// `_locales/en/messages.json` file in `version_path`.
fn resolve_chromium_locale(value: &str, version_path: &Path) -> String {
    if !value.starts_with("__MSG_") || !value.ends_with("__") {
        return value.to_string();
    }
    let key = &value[6..value.len() - 2];
    let locales_path = version_path
        .join("_locales")
        .join("en")
        .join("messages.json");
    let Ok(content) = std::fs::read_to_string(&locales_path) else {
        return value.to_string();
    };
    let Ok(doc) = serde_json::from_str::<Value>(&content) else {
        return value.to_string();
    };
    let Some(obj) = doc.as_object() else {
        return value.to_string();
    };
    for (k, v) in obj {
        if k.eq_ignore_ascii_case(key)
            && let Some(msg) = v.get("message").and_then(Value::as_str)
        {
            return msg.to_string();
        }
    }
    value.to_string()
}

/// Details parsed from `manifest.json` in a Chromium extension version folder.
struct ExtensionDetails {
    version: String,
    name: String,
    description: String,
    manifest_version: i64,
    permissions: String,
    host_permissions: String,
    optional_permissions: String,
    optional_host_permissions: String,
    update_url: String,
    background_type: String,
    content_script_matches: String,
    content_security_policy: String,
}

/// Parses `manifest.json` from an extension version directory.
/// Returns `None` when the file is absent or unparseable.
fn get_extension_details(version_path: &Path) -> Option<ExtensionDetails> {
    let manifest_path = version_path.join("manifest.json");
    let content = std::fs::read_to_string(&manifest_path).ok()?;
    let doc: Value = serde_json::from_str(&content).ok()?;

    let version = doc
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let raw_name = doc
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let raw_desc = doc
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let name = resolve_chromium_locale(&raw_name, version_path);
    let description = resolve_chromium_locale(&raw_desc, version_path);
    let manifest_version = doc
        .get("manifest_version")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let update_url = doc
        .get("update_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let permissions = extract_json_string_array(doc.get("permissions"));
    let host_permissions = extract_json_string_array(doc.get("host_permissions"));
    let optional_permissions = extract_json_string_array(doc.get("optional_permissions"));
    let optional_host_permissions = extract_json_string_array(doc.get("optional_host_permissions"));

    let background_type = if let Some(bg) = doc.get("background") {
        if bg.get("service_worker").is_some() {
            "service_worker"
        } else if bg.get("scripts").is_some() {
            "persistent_scripts"
        } else if bg.get("page").is_some() {
            "persistent_page"
        } else {
            "unknown"
        }
    } else {
        "none"
    }
    .to_string();

    let content_script_matches =
        if let Some(arr) = doc.get("content_scripts").and_then(Value::as_array) {
            let mut matches: Vec<String> = arr
                .iter()
                .filter_map(|cs| cs.get("matches").and_then(Value::as_array))
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            matches.dedup();
            matches.join(", ")
        } else {
            String::new()
        };

    let content_security_policy = if let Some(csp) = doc.get("content_security_policy") {
        if let Some(s) = csp.as_str() {
            s.to_string()
        } else {
            csp.get("extension_pages")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        }
    } else {
        String::new()
    };

    Some(ExtensionDetails {
        version,
        name,
        description,
        manifest_version,
        permissions,
        host_permissions,
        optional_permissions,
        optional_host_permissions,
        update_url,
        background_type,
        content_script_matches,
        content_security_policy,
    })
}

/// Compares two Chromium extension version strings (e.g. `"1.2.3.4"`) by
/// splitting on `.` and comparing each component numerically. Falls back to
/// lexicographic comparison for non-numeric components.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse =
        |s: &str| -> Vec<u64> { s.split('.').filter_map(|p| p.parse::<u64>().ok()).collect() };
    parse(a).cmp(&parse(b))
}

/// Returns the path of the **highest-versioned** sub-directory inside
/// `ext_dir` (a Chromium extension root), or `None` when the directory is
/// empty or unreadable.
///
/// Chromium names version folders by their version string (`"1.2.3.4"`).
/// During an update, two version folders coexist briefly; we always emit the
/// latest to avoid duplicate rows and stale metadata.
fn latest_version_dir(ext_dir: &Path) -> Option<PathBuf> {
    let entries: Vec<(PathBuf, String)> = std::fs::read_dir(ext_dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .filter_map(|p| {
            let name = p.file_name()?.to_str()?.to_string();
            Some((p, name))
        })
        .collect();

    entries
        .into_iter()
        .max_by(|(_, a), (_, b)| compare_versions(a, b))
        .map(|(path, _)| path)
}

/// Browser definitions: (name, relative path from `ProfileImagePath`).
const BROWSERS: &[(&str, &str)] = &[
    ("Edge", r"AppData\Local\Microsoft\Edge\User Data"),
    ("Chrome", r"AppData\Local\Google\Chrome\User Data"),
    (
        "Brave",
        r"AppData\Local\BraveSoftware\Brave-Browser\User Data",
    ),
    ("Vivaldi", r"AppData\Local\Vivaldi\User Data"),
    ("Arc", r"AppData\Local\Arc\User Data"),
    ("Opera", r"AppData\Roaming\Opera Software\Opera Stable"),
    (
        "Opera GX",
        r"AppData\Roaming\Opera Software\Opera GX Stable",
    ),
];

/// Returns all browser extensions installed for all users, matching the full
/// `ComplianceApp` output (28 fields per extension).
///
/// Mirrors `BrowserExtensionsInstalled.cs` + `General.GetBrowserExtension()` +
/// `ChromiumPreferencesParser.cs`.
///
/// # Examples
///
/// ```ignore
/// let (exts, err) = browser_extensions_installed();
/// // exts: [{"browser": "Edge", "name": "uBlock Origin", ...}, ...]
/// // err:  None | Some("RegOpenKeyExW(HKLM\\…\\ProfileList) failed ...")
/// ```
///
/// # Errors (second element)
///
/// `Some(message)` when the profile enumeration itself failed (HKLM
/// `ProfileList` inaccessible).  Per-profile / per-file errors are
/// **intentionally absorbed**: a single missing `manifest.json` or
/// unreadable `Preferences` would otherwise produce dozens of error
/// rows under a healthy machine.  The convention is "best-effort with
/// a single fundamental-failure key" — record under
/// `"browser_extensions_installed"` in `host.errors()`.
#[must_use = "callers must record the ProfileList diagnostic in host.errors()"]
#[allow(clippy::too_many_lines)]
pub(super) fn browser_extensions_installed() -> (Vec<Value>, Option<String>) {
    let (profiles, profile_err) = match super::accounts::try_profile_list() {
        Ok(p) => (p, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let mut rows: Vec<Value> = Vec::new();

    for (sid, nt_account, profile_path) in &profiles {
        let user_profile = if nt_account.is_empty() {
            sid.as_str()
        } else {
            nt_account.as_str()
        };

        for (browser_name, rel_path) in BROWSERS {
            let user_data = profile_path.join(rel_path);
            if !user_data.is_dir() {
                continue;
            }

            let activity_map = local_state_activity_map(&user_data);

            // Detect profile folders. Opera/Opera GX place Extensions directly
            // under their app folder, so there is no Default/Profile* sub-dir.
            let profile_folders: Vec<PathBuf> = if user_data.join("Extensions").is_dir() {
                vec![user_data.clone()]
            } else {
                let Ok(entries) = std::fs::read_dir(&user_data) else {
                    continue;
                };
                entries
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.is_dir())
                    .filter(|p| {
                        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        name.eq_ignore_ascii_case("Default")
                            || name.to_ascii_uppercase().starts_with("PROFILE")
                    })
                    .collect()
            };

            for profile_folder in &profile_folders {
                let browser_profile = profile_folder
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();

                let last_activity = activity_map.get(&browser_profile).cloned();

                let ext_root = profile_folder.join("Extensions");
                if !ext_root.is_dir() {
                    continue;
                }

                // Load Preferences once per browser profile (may be multi-MB).
                let prefs_text = try_read(&profile_folder.join("Preferences"));
                let secure_prefs_text = try_read(&profile_folder.join("Secure Preferences"));
                let prefs_map =
                    parse_chromium_preferences(prefs_text.as_deref(), secure_prefs_text.as_deref());

                let Ok(ext_dirs) = std::fs::read_dir(&ext_root) else {
                    continue;
                };

                for ext_entry in ext_dirs.filter_map(Result::ok) {
                    let ext_path = ext_entry.path();
                    if !ext_path.is_dir() {
                        continue;
                    }
                    let ext_id = ext_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();
                    if ext_id.eq_ignore_ascii_case("temp") {
                        continue;
                    }

                    let install_date = std::fs::metadata(&ext_path)
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(systime_to_iso8601);

                    let prefs =
                        prefs_map
                            .get(&ext_id)
                            .map_or_else(ExtensionPrefs::default_enabled, |p| ExtensionPrefs {
                                enabled: p.enabled,
                                location: p.location.clone(),
                                disable_reasons: p.disable_reasons,
                                blocklist_state: p.blocklist_state,
                                creation_flags: p.creation_flags,
                                acknowledged: p.acknowledged,
                                granted_api_permissions: p.granted_api_permissions.clone(),
                                granted_host_permissions: p.granted_host_permissions.clone(),
                            });

                    // Use only the highest-versioned sub-folder to avoid
                    // duplicate rows when two versions coexist during an update.
                    let Some(ver_path) = latest_version_dir(&ext_path) else {
                        continue;
                    };
                    let Some(details) = get_extension_details(&ver_path) else {
                        continue;
                    };

                    let has_metadata = ver_path.join("_metadata").is_dir();
                    let has_verified = ver_path
                        .join("_metadata")
                        .join("verified_contents.json")
                        .is_file();

                    let active_perms =
                        merge_dedup_strings(&details.permissions, &details.host_permissions);
                    let optional_perms = merge_dedup_strings(
                        &details.optional_permissions,
                        &details.optional_host_permissions,
                    );

                    rows.push(json!({
                        "browser":                      browser_name,
                        "sid":                          sid,
                        "user_profile":                 user_profile,
                        "profile_image_path":           profile_path.to_string_lossy(),
                        "browser_profile":              browser_profile,
                        "last_browser_profile_activity": last_activity,
                        "extension_id":                 ext_id,
                        "name":                         details.name,
                        "version":                      details.version,
                        "manifest_version":             details.manifest_version,
                        "description":                  details.description,
                        "enabled":                      prefs.enabled,
                        "active_permissions":           active_perms,
                        "optional_permissions":         optional_perms,
                        "update_url":                   details.update_url,
                        "install_date":                 install_date,
                        "has_metadata_folder":          has_metadata,
                        "has_verified_contents":        has_verified,
                        "background_type":              details.background_type,
                        "content_script_matches":       details.content_script_matches,
                        "content_security_policy":      details.content_security_policy,
                        "location":                     prefs.location,
                        "disable_reasons":              prefs.disable_reasons,
                        "blocklist_state":              prefs.blocklist_state,
                        "creation_flags":               prefs.creation_flags,
                        "acknowledged":                 prefs.acknowledged,
                        "granted_api_permissions":      prefs.granted_api_permissions,
                        "granted_host_permissions":     prefs.granted_host_permissions,
                    }));
                }
            }
        }
    }

    // Deterministic output: (browser, user_profile, browser_profile, extension_id) ASC.
    rows.sort_by(|a, b| {
        let key = |v: &Value| {
            (
                v["browser"].as_str().unwrap_or("").to_lowercase(),
                v["user_profile"].as_str().unwrap_or("").to_lowercase(),
                v["browser_profile"].as_str().unwrap_or("").to_lowercase(),
                v["extension_id"].as_str().unwrap_or("").to_lowercase(),
            )
        };
        key(a).cmp(&key(b))
    });

    (rows, profile_err)
}

// =============================================================================
// Section 4 — ide_extensions_installed
// =============================================================================

/// Entry from `extensions.json` (VS Code / Cursor / etc.).
struct IdeRegistryEntry {
    installed_timestamp_ms: i64,
    source: String,
    publisher_display_name: String,
}

/// Parses `extensions.json` at the root of an IDE extensions folder.
/// Returns a map keyed by `identifier.id` (case-insensitive).
fn read_extensions_registry(path: &Path) -> HashMap<String, IdeRegistryEntry> {
    let mut map = HashMap::new();
    let Ok(content) = std::fs::read_to_string(path) else {
        return map;
    };
    let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&content) else {
        return map;
    };
    for entry in &arr {
        let Some(id) = entry
            .pointer("/identifier/id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let meta = entry.get("metadata");
        let timestamp = meta
            .and_then(|m| m.get("installedTimestamp"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let source = meta
            .and_then(|m| m.get("source"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let publisher_display_name = meta
            .and_then(|m| m.get("publisherDisplayName"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        map.insert(
            id.to_lowercase(),
            IdeRegistryEntry {
                installed_timestamp_ms: timestamp,
                source,
                publisher_display_name,
            },
        );
    }
    map
}

/// Returns `true` if `value` is a VS Code NLS placeholder like `%key%`.
fn is_nls_placeholder(value: Option<&str>) -> bool {
    matches!(value, Some(s) if s.len() > 2 && s.starts_with('%') && s.ends_with('%'))
}

/// Loads a VS Code NLS bundle file (flat `{key: string}` JSON) into a map.
fn load_nls_bundle(path: &Path) -> Option<HashMap<String, String>> {
    let content = std::fs::read_to_string(path).ok()?;
    let Value::Object(obj) = serde_json::from_str::<Value>(&content).ok()? else {
        return None;
    };
    Some(
        obj.into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.to_lowercase(), s.to_string())))
            .collect(),
    )
}

/// Resolves a VS Code NLS placeholder `%key%` using `nls`. Returns the
/// original string when it is not a placeholder or the key is not found.
fn resolve_nls<'a>(value: &'a str, nls: &HashMap<String, String>) -> std::borrow::Cow<'a, str> {
    if !is_nls_placeholder(Some(value)) {
        return std::borrow::Cow::Borrowed(value);
    }
    let key = value[1..value.len() - 1].to_lowercase();
    match nls.get(&key) {
        Some(resolved) => std::borrow::Cow::Owned(resolved.clone()),
        None => std::borrow::Cow::Borrowed(value),
    }
}

/// Parses the package name + optional version from an extension folder name
/// like `publisher.name-1.2.3`. The last `-` followed by a digit is the
/// version delimiter.
fn parse_extension_folder_name(name: &str) -> (String, Option<String>) {
    if let Some(dash) = name.rfind('-') {
        let after = &name[dash + 1..];
        if after.starts_with(|c: char| c.is_ascii_digit()) {
            return (name[..dash].to_string(), Some(after.to_string()));
        }
    }
    (name.to_string(), None)
}

/// IDE definitions: (display name, relative path from `ProfileImagePath`).
const IDES: &[(&str, &str)] = &[
    ("VSCode", r".vscode\extensions"),
    ("VSCode Insiders", r".vscode-insiders\extensions"),
    ("Cursor", r".cursor\extensions"),
    ("Windsurf", r".windsurf\extensions"),
    ("VSCodium", r".vscode-oss\extensions"),
    ("Antigravity", r".antigravity\extensions"),
];

/// Returns all IDE extensions installed for all users, matching the full
/// `ComplianceApp` output (18 fields per extension).
///
/// Mirrors `IdeExtensionsInstalled.cs` + `General.GetIdeExtensions()`.
///
/// # Examples
///
/// ```ignore
/// let (exts, err) = ide_extensions_installed();
/// // exts: [{"ide": "VSCode", "name": "Rust Analyzer", ...}, ...]
/// // err:  None | Some("RegOpenKeyExW(HKLM\\…\\ProfileList) failed ...")
/// ```
///
/// # Errors (second element)
///
/// Same semantics as [`browser_extensions_installed`]: `Some(message)`
/// only when the profile enumeration itself failed.  Per-file / per-IDE
/// errors are intentionally absorbed to keep noise low.  Record under
/// `"ide_extensions_installed"` in `host.errors()`.
#[must_use = "callers must record the ProfileList diagnostic in host.errors()"]
#[allow(clippy::too_many_lines)]
pub(super) fn ide_extensions_installed() -> (Vec<Value>, Option<String>) {
    let (profiles, profile_err) = match super::accounts::try_profile_list() {
        Ok(p) => (p, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let mut rows: Vec<Value> = Vec::new();

    for (sid, nt_account, profile_path) in &profiles {
        let user_profile = if nt_account.is_empty() {
            sid.as_str()
        } else {
            nt_account.as_str()
        };

        for (ide_name, rel_path) in IDES {
            let ext_root = profile_path.join(rel_path);
            if !ext_root.is_dir() {
                continue;
            }

            let registry_map = read_extensions_registry(&ext_root.join("extensions.json"));

            let Ok(ext_dirs) = std::fs::read_dir(&ext_root) else {
                continue;
            };

            for entry in ext_dirs.filter_map(Result::ok) {
                let folder = entry.path();
                if !folder.is_dir() {
                    continue;
                }
                let folder_name = folder
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();
                if folder_name.eq_ignore_ascii_case(".obsolete") {
                    continue;
                }

                let last_modified = std::fs::metadata(&folder)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(systime_to_iso8601);

                let pkg_path = folder.join("package.json");
                let pkg = try_read_package_json(&pkg_path, &folder);

                let (extension_id, name, publisher, version) = if let Some(ref p) = pkg {
                    let id = match (p.publisher.as_deref(), p.name.as_deref()) {
                        (Some(pub_), Some(n)) if !pub_.is_empty() && !n.is_empty() => {
                            format!("{pub_}.{n}")
                        }
                        _ => folder_name.clone(),
                    };
                    let nm = p
                        .display_name
                        .as_deref()
                        .or(p.name.as_deref())
                        .unwrap_or(&folder_name)
                        .to_string();
                    let pub_ = p.publisher.as_deref().unwrap_or("").to_string();
                    let ver = p.version.as_deref().unwrap_or("").to_string();
                    (id, nm, pub_, ver)
                } else {
                    let (id, ver) = parse_extension_folder_name(&folder_name);
                    (id.clone(), id, String::new(), ver.unwrap_or_default())
                };

                let reg_key = extension_id.to_lowercase();
                let reg = registry_map.get(&reg_key);

                let publisher = if publisher.is_empty() {
                    reg.map(|r| r.publisher_display_name.clone())
                        .unwrap_or_default()
                } else {
                    publisher
                };
                let publisher_display_name = reg
                    .map(|r| r.publisher_display_name.clone())
                    .unwrap_or_default();
                let source = reg.map(|r| r.source.clone()).unwrap_or_default();

                let install_date = reg
                    .filter(|r| r.installed_timestamp_ms > 0)
                    .and_then(|r| unix_ms_to_iso8601(r.installed_timestamp_ms));

                let description = pkg
                    .as_ref()
                    .and_then(|p| p.description.clone())
                    .unwrap_or_default();
                let categories = pkg
                    .as_ref()
                    .and_then(|p| p.categories.clone())
                    .unwrap_or_default();
                let engine_vscode = pkg
                    .as_ref()
                    .and_then(|p| p.engine_vscode.clone())
                    .unwrap_or_default();
                let wildcard_activation = pkg.as_ref().is_some_and(|p| p.wildcard_activation);
                let post_install_script = pkg.as_ref().is_some_and(|p| p.post_install_script);
                let dependency_count = pkg.as_ref().map_or(0, |p| p.dependency_count);

                rows.push(json!({
                    "ide":                  ide_name,
                    "sid":                  sid,
                    "user_profile":         user_profile,
                    "profile_image_path":   profile_path.to_string_lossy(),
                    "extension_id":         extension_id,
                    "name":                 name,
                    "publisher":            publisher,
                    "publisher_display_name": publisher_display_name,
                    "version":              version,
                    "description":          description,
                    "categories":           categories,
                    "engine_vscode":        engine_vscode,
                    "source":               source,
                    "install_date":         install_date,
                    "last_modified":        last_modified,
                    "wildcard_activation":  wildcard_activation,
                    "post_install_script":  post_install_script,
                    "dependency_count":     dependency_count,
                }));
            }
        }
    }

    // Deterministic output: (ide, user_profile, extension_id) ASC.
    rows.sort_by(|a, b| {
        let key = |v: &Value| {
            (
                v["ide"].as_str().unwrap_or("").to_lowercase(),
                v["user_profile"].as_str().unwrap_or("").to_lowercase(),
                v["extension_id"].as_str().unwrap_or("").to_lowercase(),
            )
        };
        key(a).cmp(&key(b))
    });

    (rows, profile_err)
}

/// Parsed fields from a VS Code extension's `package.json`.
struct IdePackageJson {
    name: Option<String>,
    display_name: Option<String>,
    publisher: Option<String>,
    version: Option<String>,
    description: Option<String>,
    categories: Option<String>,
    engine_vscode: Option<String>,
    wildcard_activation: bool,
    post_install_script: bool,
    dependency_count: u32,
}

/// Reads and parses `package.json`, resolving NLS placeholders.
fn try_read_package_json(path: &Path, ext_dir: &Path) -> Option<IdePackageJson> {
    let content = std::fs::read_to_string(path).ok()?;
    let doc: Value = serde_json::from_str(&content).ok()?;

    let name = doc.get("name").and_then(Value::as_str).map(str::to_string);
    let mut display_name = doc
        .get("displayName")
        .and_then(Value::as_str)
        .map(str::to_string);
    let publisher = doc
        .get("publisher")
        .and_then(Value::as_str)
        .map(str::to_string);
    let version = doc
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut description = doc
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_string);

    // Resolve NLS placeholders.
    if is_nls_placeholder(display_name.as_deref()) || is_nls_placeholder(description.as_deref()) {
        let nls = load_nls_bundle(&ext_dir.join("package.nls.json"))
            .or_else(|| load_nls_bundle(&ext_dir.join("package.nls.en.json")))
            .or_else(|| load_nls_bundle(&ext_dir.join("package.nls.en-us.json")));
        if let Some(ref nls_map) = nls {
            if let Some(ref dn) = display_name.clone() {
                display_name = Some(resolve_nls(dn, nls_map).into_owned());
            }
            if let Some(ref desc) = description.clone() {
                description = Some(resolve_nls(desc, nls_map).into_owned());
            }
        }
    }

    let categories = doc.get("categories").and_then(Value::as_array).map(|arr| {
        arr.iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    });

    let engine_vscode = doc
        .pointer("/engines/vscode")
        .and_then(Value::as_str)
        .map(|s| s.trim_start_matches(['^', '~']).to_string());

    let wildcard_activation = doc
        .get("activationEvents")
        .and_then(Value::as_array)
        .is_some_and(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .any(|e| e == "*" || e == "onStartupFinished")
        });

    let post_install_script = doc
        .get("scripts")
        .and_then(Value::as_object)
        .is_some_and(|s| s.contains_key("postinstall") || s.contains_key("install"));

    let dep_count = doc
        .get("dependencies")
        .and_then(Value::as_object)
        .map_or(0, |m| u32::try_from(m.len()).unwrap_or(0))
        + doc
            .get("extensionDependencies")
            .and_then(Value::as_array)
            .map_or(0, |a| u32::try_from(a.len()).unwrap_or(0));

    Some(IdePackageJson {
        name,
        display_name,
        publisher,
        version,
        description,
        categories,
        engine_vscode,
        wildcard_activation,
        post_install_script,
        dependency_count: dep_count,
    })
}

// =============================================================================
// Shared string helpers
// =============================================================================

/// Joins a JSON array of strings into a `", "`-delimited `String`.
/// Returns an empty string when the property is absent or not an array.
fn extract_json_string_array(val: Option<&Value>) -> String {
    val.and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

/// Merges two `", "`-delimited strings, deduplicating entries
/// (case-insensitive).
fn merge_dedup_strings(a: &str, b: &str) -> String {
    if b.is_empty() {
        return a.to_string();
    }
    if a.is_empty() {
        return b.to_string();
    }
    let mut seen: Vec<String> = Vec::new();
    for item in a.split(", ").chain(b.split(", ")) {
        let trimmed = item.trim().to_string();
        if !trimmed.is_empty() && !seen.iter().any(|s| s.eq_ignore_ascii_case(&trimmed)) {
            seen.push(trimmed);
        }
    }
    seen.join(", ")
}

/// Reads a file to a `String`, returning `None` on any I/O error.
fn try_read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- extract_software_code -----------------------------------------------

    #[test]
    fn guid_extracted_from_uninstall_string() {
        let s = r"MsiExec.exe /X{1D8E6291-B0D5-35EC-8441-6616F567A0F7}";
        assert_eq!(
            extract_software_code(Some(s), "some-key"),
            Some("{1D8E6291-B0D5-35EC-8441-6616F567A0F7}".to_string())
        );
    }

    #[test]
    fn guid_fallback_to_key_name() {
        assert_eq!(
            extract_software_code(None, "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"),
            Some("{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}".to_string())
        );
    }

    #[test]
    fn no_guid_returns_none() {
        assert_eq!(extract_software_code(None, "SomeRandomKey"), None);
        assert_eq!(extract_software_code(Some("notepad.exe"), "notepad"), None);
    }

    #[test]
    fn guid_too_short_not_extracted() {
        // 37 chars including braces — one short of the required 38.
        assert_eq!(
            extract_software_code(Some("{1D8E6291-B0D5-35EC-8441-6616F567A0F}"), "k"),
            None
        );
    }

    // --- parse_install_date --------------------------------------------------

    #[test]
    fn valid_install_date_converted() {
        assert_eq!(
            parse_install_date("20240315"),
            Some("2024-03-15T00:00:00Z".to_string())
        );
    }

    #[test]
    fn invalid_month_returns_none() {
        assert_eq!(parse_install_date("20241315"), None);
    }

    #[test]
    fn invalid_day_returns_none() {
        assert_eq!(parse_install_date("20240132"), None);
    }

    #[test]
    fn wrong_length_returns_none() {
        assert_eq!(parse_install_date("2024031"), None);
        assert_eq!(parse_install_date("202403150"), None);
        assert_eq!(parse_install_date(""), None);
    }

    // --- manifest_location_label ---------------------------------------------

    #[test]
    fn known_location_codes_map_to_labels() {
        assert_eq!(manifest_location_label(0), "InvalidLocation");
        assert_eq!(manifest_location_label(1), "Internal");
        assert_eq!(manifest_location_label(8), "ExternalPolicy");
        assert_eq!(manifest_location_label(11), "ExternalComponent");
    }

    #[test]
    fn unknown_location_code_formatted() {
        assert_eq!(manifest_location_label(99), "Unknown(99)");
        assert_eq!(manifest_location_label(-1), "Unknown(-1)");
    }

    // --- merge_dedup_strings -------------------------------------------------

    #[test]
    fn merge_dedup_strings_basic() {
        assert_eq!(merge_dedup_strings("a, b", "b, c"), "a, b, c");
    }

    #[test]
    fn merge_dedup_case_insensitive() {
        assert_eq!(merge_dedup_strings("Storage", "storage"), "Storage");
    }

    #[test]
    fn merge_dedup_empty_a() {
        assert_eq!(merge_dedup_strings("", "x, y"), "x, y");
    }

    #[test]
    fn merge_dedup_empty_b() {
        assert_eq!(merge_dedup_strings("x, y", ""), "x, y");
    }

    // --- parse_extension_folder_name -----------------------------------------

    #[test]
    fn folder_name_with_version() {
        let (id, ver) = parse_extension_folder_name("rust-lang.rust-analyzer-0.3.2");
        assert_eq!(id, "rust-lang.rust-analyzer");
        assert_eq!(ver, Some("0.3.2".to_string()));
    }

    #[test]
    fn folder_name_no_version() {
        let (id, ver) = parse_extension_folder_name("no-version-here");
        assert_eq!(id, "no-version-here");
        assert_eq!(ver, None);
    }

    #[test]
    fn folder_name_multiple_dashes_picks_last_numeric() {
        // Hyphens in the publisher/name part must not be confused with the
        // version delimiter.
        let (id, ver) = parse_extension_folder_name("ms-python.python-2024.6.0");
        assert_eq!(id, "ms-python.python");
        assert_eq!(ver, Some("2024.6.0".to_string()));
    }

    // --- is_nls_placeholder --------------------------------------------------

    #[test]
    fn nls_placeholder_detected() {
        assert!(is_nls_placeholder(Some("%extensionName%")));
        assert!(is_nls_placeholder(Some("%description%")));
    }

    #[test]
    fn non_placeholder_not_detected() {
        assert!(!is_nls_placeholder(Some("Rust Analyzer")));
        assert!(!is_nls_placeholder(Some("")));
        assert!(!is_nls_placeholder(None));
        // Single % on each side but empty key.
        assert!(!is_nls_placeholder(Some("%%")));
    }

    // --- compare_versions ----------------------------------------------------

    #[test]
    fn version_comparison_numeric() {
        use std::cmp::Ordering;
        assert_eq!(compare_versions("1.2.3", "1.2.4"), Ordering::Less);
        assert_eq!(compare_versions("2.0.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("10.0.0", "9.0.0"), Ordering::Greater);
    }

    // --- parse_single_prefs --------------------------------------------------

    #[test]
    fn prefs_state_zero_disables_extension() {
        let obj = serde_json::json!({"state": 0});
        assert!(!parse_single_prefs(&obj).enabled);
    }

    #[test]
    fn prefs_state_one_enables_extension() {
        let obj = serde_json::json!({"state": 1});
        assert!(parse_single_prefs(&obj).enabled);
    }

    #[test]
    fn prefs_missing_state_defaults_to_enabled() {
        let obj = serde_json::json!({});
        assert!(parse_single_prefs(&obj).enabled);
    }

    #[test]
    fn prefs_disable_reasons_array_ored() {
        // Individual disable-reason bits should be OR-combined.
        let obj = serde_json::json!({"disable_reasons": [1, 4, 8]});
        assert_eq!(parse_single_prefs(&obj).disable_reasons, 1 | 4 | 8);
    }

    #[test]
    fn prefs_ack_prompt_count_positive_sets_acknowledged() {
        let obj = serde_json::json!({"ack_prompt_count": 2});
        assert!(parse_single_prefs(&obj).acknowledged);
    }

    #[test]
    fn prefs_ack_prompt_count_zero_does_not_set_acknowledged() {
        let obj = serde_json::json!({"ack_prompt_count": 0});
        assert!(!parse_single_prefs(&obj).acknowledged);
    }

    // --- deduplicate_software ------------------------------------------------
    //
    // The rule mirrors ComplianceApp's behaviour:
    //   - Same (context, publisher, display_name, version, software_code) ⇒ same entity.
    //   - When duplicated, prefer the row where system_component == false.
    //   - Otherwise, keep the first one seen (insertion order is stable).
    //
    // These tests exercise the rule in isolation — no registry access, no Win32.

    fn row(
        context: &str,
        publisher: &str,
        display_name: &str,
        version: &str,
        software_code: &str,
        system_component: bool,
    ) -> Value {
        serde_json::json!({
            "context":          context,
            "publisher":        publisher,
            "display_name":     display_name,
            "version":          version,
            "software_code":    software_code,
            "system_component": system_component,
        })
    }

    #[test]
    fn dedup_prefers_non_system_component_on_collision() {
        // Same key, system_component differs ⇒ the false-flagged one wins.
        let sys = row("Machine", "Acme", "Foo", "1.0", "{GUID}", true);
        let user = row("Machine", "Acme", "Foo", "1.0", "{GUID}", false);

        // Try both orders: outcome must be identical because the rule is
        // "non-system wins" regardless of which one was seen first.
        let out_a = deduplicate_software(vec![sys.clone(), user.clone()]);
        let out_b = deduplicate_software(vec![user.clone(), sys.clone()]);

        assert_eq!(out_a.len(), 1);
        assert_eq!(out_b.len(), 1);
        assert_eq!(out_a[0]["system_component"], Value::Bool(false));
        assert_eq!(out_b[0]["system_component"], Value::Bool(false));
    }

    #[test]
    fn dedup_distinct_keys_all_kept() {
        // Different software_code ⇒ distinct entities, both kept.
        let a = row("Machine", "Acme", "Foo", "1.0", "{GUID-A}", false);
        let b = row("Machine", "Acme", "Foo", "1.0", "{GUID-B}", false);

        let out = deduplicate_software(vec![a, b]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn dedup_same_flag_preserves_first_seen() {
        // Same key, both system_component == true ⇒ keep the first, drop the second.
        let first = row("Machine", "Acme", "Foo", "1.0", "{GUID}", true);
        let mut second = row("Machine", "Acme", "Foo", "1.0", "{GUID}", true);
        // Sentinel field to distinguish the two rows beyond their dedup key.
        second["sentinel"] = Value::String("second".into());

        let out = deduplicate_software(vec![first, second]);
        assert_eq!(out.len(), 1);
        // The kept row is the first one ⇒ no `sentinel` field.
        assert!(out[0].get("sentinel").is_none());
    }

    #[test]
    fn dedup_both_non_system_preserves_first_seen() {
        // Symmetric case to the previous one: both system_component == false
        // ⇒ keep the first, drop the second.  The "non-system wins" rule does
        // not flip behaviour when neither row is a system component.
        let first = row("Machine", "Acme", "Foo", "1.0", "{GUID}", false);
        let mut second = row("Machine", "Acme", "Foo", "1.0", "{GUID}", false);
        second["sentinel"] = Value::String("second".into());

        let out = deduplicate_software(vec![first, second]);
        assert_eq!(out.len(), 1);
        assert!(out[0].get("sentinel").is_none());
    }

    #[test]
    fn dedup_context_distinguishes_machine_from_user() {
        // Same software in Machine vs per-user SID context ⇒ both kept,
        // because `context` is part of the dedup key.
        let machine = row("Machine", "Acme", "Foo", "1.0", "{GUID}", false);
        let user = row("S-1-5-21-…", "Acme", "Foo", "1.0", "{GUID}", false);

        let out = deduplicate_software(vec![machine, user]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn dedup_weak_identity_rows_never_collapse() {
        // Two rows with the same display_name but ALL optional fields
        // empty — without the strong-identifier guard they would map to
        // `(Machine, "", "Foo", "", "")` and collapse into one, dropping
        // genuinely distinct data.  The guard keeps both.
        let a = row("Machine", "", "Foo", "", "", false);
        let b = row("Machine", "", "Foo", "", "", false);

        let out = deduplicate_software(vec![a, b]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn dedup_partial_identity_still_collapses() {
        // Symmetric sanity check: a single non-empty optional field is
        // enough to pass the strong-identifier guard, so the normal
        // dedup rule applies.  Here only `version` is non-empty.
        let a = row("Machine", "", "Foo", "1.0", "", true);
        let b = row("Machine", "", "Foo", "1.0", "", false);

        let out = deduplicate_software(vec![a, b]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["system_component"], Value::Bool(false));
    }
}
