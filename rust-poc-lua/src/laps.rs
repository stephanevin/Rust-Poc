//! LAPS (Local Administrator Password Solution) configuration probe.
//!
//! Exposes [`laps_state`] — a single snapshot of the host's LAPS posture,
//! covering both the legacy Microsoft LAPS (`AdmPwd` CSE) and the modern
//! Windows LAPS (CSP / GPO / local config) channels.
//!
//! Mirrors the LAPS transformers in `ComplianceApp` (`Security.cs`,
//! `DataTransformers/LAPS/*.cs`).  Unlike the WFP runtime there is **no
//! per-run cache**: every field is an independent registry read or
//! `Path::exists` probe, all cheap and side-effect free, so the binding
//! recomputes on each call.
//!
//! ## Deviation #44
//!
//! `auto_laps_mode` emits `"Not Installed"` when neither LAPS channel is
//! detected, where the C# code emits the enum `AutoLapsState.Unknown`
//! (`"Unknown"`).  The `Win10-Laptop.json` parent test is
//! `AutoLapsMode != "Not Installed"`, which the C# string `"Unknown"`
//! always passes — so a host without LAPS is falsely reported compliant.
//! Emitting `"Not Installed"` makes the test behave as the definition
//! author intended.  See `CLAUDE.md` § *Deviations*.

use serde_json::{Value, json};

use super::registry;

// ---------------------------------------------------------------------------
// Registry locations (mirror RegistryResources.resx in ComplianceApp)
// ---------------------------------------------------------------------------

/// Legacy `AdmPwd` CSE Group Policy extension key.  Its mere *existence*
/// signals the legacy LAPS client-side extension is registered.
const LEGACY_CSE_KEY: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}";

/// Modern Windows LAPS — MDM/Intune CSP channel.
const CSP_KEY: &str = r"Software\Microsoft\Policies\LAPS";
/// Modern Windows LAPS — Group Policy channel.
const GPO_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Policies\LAPS";
/// Modern Windows LAPS — local configuration channel.
const LOCAL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\LAPS\Config";
/// Legacy Microsoft LAPS (`AdmPwd`) policy key.
const LEGACY_ADMPWD_KEY: &str = r"SOFTWARE\Policies\Microsoft Services\AdmPwd";

/// Value name used by all three modern channels for the backup target.
const BACKUP_DIRECTORY_VALUE: &str = "BackupDirectory";
/// Value name used by the legacy `AdmPwd` channel as its enable flag.
const ADMPWD_ENABLED_VALUE: &str = "AdmPwdEnabled";
/// Value name for the max password age — identical across all channels
/// (`WindowsLAPSMaxPwdAgeValue` and `LegacyLAPSMaxPwdAgeValue` both resolve
/// to `PasswordAgeDays` in `RegistryResources.resx`).
const PASSWORD_AGE_DAYS_VALUE: &str = "PasswordAgeDays";

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Builds the LAPS posture snapshot.
///
/// Infallible by construction: each probe degrades to a safe default
/// (`"None"` / `"Disabled"` / `false` / `null`) rather than returning an
/// error, so the caller never has to record anything in `host.errors()`.
pub(super) fn laps_state() -> Value {
    let legacy_present = legacy_cse_key_exists();
    let dll_found = windows_laps_dlls_found();
    let policy = read_laps_policy();

    json!({
        "auto_laps_mode":              auto_laps_mode_from(legacy_present, dll_found),
        "windows_laps_dll_state":      if dll_found { "Found" } else { "NotFound" },
        "laps_policy":                 policy,
        "laps_backup_directory":       read_backup_directory(policy),
        "legacy_gp_extension_present": legacy_present,
        "max_pwd_age_days":            read_max_pwd_age(policy),
    })
}

// ---------------------------------------------------------------------------
// Pure decision logic (unit-tested without touching the registry)
// ---------------------------------------------------------------------------

/// Resolves the overall LAPS mode.  Legacy takes priority over Windows
/// LAPS — same ordering as `AutoLapsMode.cs` in `ComplianceApp`.
///
/// Deviation #44: returns `"Not Installed"` (not `"Unknown"`) when neither
/// channel is detected.
fn auto_laps_mode_from(legacy_present: bool, dll_found: bool) -> &'static str {
    if legacy_present {
        "Legacy"
    } else if dll_found {
        "Windows"
    } else {
        "Not Installed"
    }
}

/// Maps a modern `BackupDirectory` raw value to its label.
/// Mirrors `Security.cs::ReadModernLapsBackupDirectory`.
fn modern_backup_directory_from(raw: Option<&str>) -> &'static str {
    match raw {
        Some("1") => "MicrosoftEntra",
        Some("2") => "ActiveDirectory",
        _ => "Disabled",
    }
}

/// Maps the legacy `AdmPwdEnabled` raw value to its label.
/// Mirrors `Security.cs::ReadLegacyLapsBackupDirectory`.
fn legacy_backup_directory_from(raw: Option<&str>) -> &'static str {
    match raw {
        Some("1") => "ActiveDirectoryLegacy",
        _ => "Disabled",
    }
}

// ---------------------------------------------------------------------------
// Registry / filesystem probes
// ---------------------------------------------------------------------------

/// `true` when the legacy `AdmPwd` CSE Group Policy extension key exists.
/// Mirrors `Security.cs::GetLegacyLapsGpExtensionPresent`
/// (`_registry.GetKey(...) is not null`).
fn legacy_cse_key_exists() -> bool {
    registry::key_exists("HKLM", LEGACY_CSE_KEY)
}

/// `true` only when **both** Windows LAPS DLLs are present in `System32`.
/// Mirrors `Security.cs::GetWindowsLapsDllExists` — the check short-circuits
/// to `false` on the first missing DLL.
fn windows_laps_dlls_found() -> bool {
    // Environment.SystemDirectory is %SystemRoot%\System32; fall back to the
    // canonical path if the env var is somehow absent.
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let system32 = std::path::Path::new(&system_root).join("System32");
    system32.join("laps.dll").exists() && system32.join("lapscsp.dll").exists()
}

/// Maps an active [`read_laps_policy`] label to its registry key path.
fn policy_registry_key(policy: &str) -> Option<&'static str> {
    match policy {
        "CSP" => Some(CSP_KEY),
        "GroupPolicy" => Some(GPO_KEY),
        "LocalConfiguration" => Some(LOCAL_KEY),
        "LegacyMicrosoftLaps" => Some(LEGACY_ADMPWD_KEY),
        _ => None,
    }
}

/// Detects which LAPS policy channel is *configured* (presence of the value,
/// not its semantic).  Mirrors `Security.cs::GetLapsPolicy` — first match in
/// the cascade wins; a legacy `AdmPwdEnabled = 0` still counts as present.
fn read_laps_policy() -> &'static str {
    const CASCADE: [(&str, &str, &str); 4] = [
        (CSP_KEY, BACKUP_DIRECTORY_VALUE, "CSP"),
        (GPO_KEY, BACKUP_DIRECTORY_VALUE, "GroupPolicy"),
        (LOCAL_KEY, BACKUP_DIRECTORY_VALUE, "LocalConfiguration"),
        (LEGACY_ADMPWD_KEY, ADMPWD_ENABLED_VALUE, "LegacyMicrosoftLaps"),
    ];
    for (key, value, label) in CASCADE {
        if registry_value(key, value).is_some() {
            return label;
        }
    }
    "None"
}

/// Resolves the backup directory label for the active policy channel.
/// Mirrors `Security.cs::GetLapsBackupDirectory`.
fn read_backup_directory(policy: &str) -> &'static str {
    let Some(key) = policy_registry_key(policy) else {
        return "Disabled";
    };
    if policy == "LegacyMicrosoftLaps" {
        legacy_backup_directory_from(
            registry_value_string(key, ADMPWD_ENABLED_VALUE).as_deref(),
        )
    } else {
        modern_backup_directory_from(
            registry_value_string(key, BACKUP_DIRECTORY_VALUE).as_deref(),
        )
    }
}

/// Reads `PasswordAgeDays` from the active policy channel's key.
/// Mirrors `Security.cs::GetLapsMaxPasswordAge`.
fn read_max_pwd_age(policy: &str) -> Option<u32> {
    policy_registry_key(policy)
        .and_then(|key| registry_value_u32(key, PASSWORD_AGE_DAYS_VALUE))
}

/// Reads a decoded registry value from `HKLM`, swallowing open/read errors.
fn registry_value(key: &str, value: &str) -> Option<Value> {
    registry::read("HKLM", key, value).ok().flatten()
}

/// Reads a registry value and normalises it to a comparable string via the
/// shared [`registry::as_string`] coercion (a `REG_DWORD` `1` and a `REG_SZ`
/// `"1"` both become `"1"`, matching the C# `GetValue(...)?.ToString()`).
fn registry_value_string(key: &str, value: &str) -> Option<String> {
    registry::as_string(registry_value(key, value)?)
}

/// Reads a registry value and parses it as `u32` (DWORD or decimal string).
fn registry_value_u32(key: &str, value: &str) -> Option<u32> {
    match registry_value(key, value)? {
        Value::Number(n) => n.as_u64().and_then(|v| u32::try_from(v).ok()),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        auto_laps_mode_from, legacy_backup_directory_from, modern_backup_directory_from,
    };

    /// Deviation #44: no LAPS channel detected → "Not Installed", not the
    /// C# "Unknown".  This is the load-bearing test for the deviation.
    #[test]
    fn auto_laps_mode_none_detected_is_not_installed() {
        assert_eq!(auto_laps_mode_from(false, false), "Not Installed");
    }

    /// Legacy takes priority over Windows LAPS even when both are present.
    #[test]
    fn auto_laps_mode_legacy_wins_over_windows() {
        assert_eq!(auto_laps_mode_from(true, true), "Legacy");
        assert_eq!(auto_laps_mode_from(true, false), "Legacy");
    }

    /// Windows LAPS reported only when the legacy CSE is absent.
    #[test]
    fn auto_laps_mode_windows_when_only_dlls_found() {
        assert_eq!(auto_laps_mode_from(false, true), "Windows");
    }

    #[test]
    fn modern_backup_directory_mapping() {
        assert_eq!(modern_backup_directory_from(Some("1")), "MicrosoftEntra");
        assert_eq!(modern_backup_directory_from(Some("2")), "ActiveDirectory");
        assert_eq!(modern_backup_directory_from(Some("0")), "Disabled");
        assert_eq!(modern_backup_directory_from(None), "Disabled");
    }

    #[test]
    fn legacy_backup_directory_mapping() {
        assert_eq!(
            legacy_backup_directory_from(Some("1")),
            "ActiveDirectoryLegacy"
        );
        assert_eq!(legacy_backup_directory_from(Some("0")), "Disabled");
        assert_eq!(legacy_backup_directory_from(None), "Disabled");
    }
}
