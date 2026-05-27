//! BitLocker host bindings — six functions backed by WMI method calls
//! against `Win32_EncryptableVolume`, registry FVE policy enumeration,
//! and the BitLocker management event log.
//!
//! ## Mirror in `ComplianceApp`
//!
//! - `Components.Windows/BitLocker/Services/BitLockerService.cs`
//! - `Components.Windows/BitLocker/BitLockerExtensions.cs`
//! - `ComplianceService/Data/BitLocker/BitLocker.cs`
//! - `ComplianceApp/DataTransformers/BitLocker/*.cs`
//!
//! All five `BitLocker` transformer outputs map onto a binding here:
//!
//! | Transformer                              | Binding                              |
//! |------------------------------------------|--------------------------------------|
//! | `BitlockerStatus`                        | `volume_status` (ConversionStatus)   |
//! | `BitLockerEncryptionPercentage`          | `volume_status` (EncryptionPercentage)|
//! | `BitLockerRecoveryKeyStatus`             | `key_protector_ids` + `escrowed_protector_ids` (composed in Lua) |
//! | `BitLockerRecoveryKeyADBackupSummary`    | `escrowed_protector_ids(783)`        |
//! | `BitLockerRecoveryKeyAzureADBackupSummary`| `escrowed_protector_ids(845)`       |
//! | `BitLockerRecoveryKeyRotation`           | `recovery_key_rotation_executed`     |
//! | `BitLockerDRACertThumbPrints`            | `dra_thumbprints`                    |
//! | `BitLockerPolicy`                        | `policy_state`                       |

// Module-wide lints:
// - `doc_markdown` silenced because doc comments reference product names
//   ("BitLocker", "DRA", "Credential Guard") and C# types in prose.
// - `too_many_lines` left at default — `volume_status` is small.
#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wmi::Variant;

use super::evt;
use super::registry;
use super::wmi::Wmi;

/// WMI namespace hosting the `Win32_EncryptableVolume` class.
pub(super) const BITLOCKER_NS: &str = r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption";

/// Class on which all instance methods are invoked.
const VOLUME_CLASS: &str = "Win32_EncryptableVolume";

/// `Microsoft-Windows-BitLocker/BitLocker Management` event log channel
/// — same constant as `DataService.BitLockerLog` in `ComplianceApp`.
pub(super) const BITLOCKER_LOG: &str = "Microsoft-Windows-BitLocker/BitLocker Management";

/// Provider name attached to every event written by the BitLocker
/// management subsystem.  Passed to `evt::query_events` as the
/// `Provider[@Name='…']` XPath predicate — same shape PowerShell uses
/// for `Get-WinEvent -FilterHashtable @{ProviderName='X'; Id=N}`, and
/// the predicate the Event Log service can match through its
/// per-provider index (see `evt.rs` module doc).
const BITLOCKER_PROVIDER: &str = "Microsoft-Windows-BitLocker-API";

/// FVE registry policy key — mirror of `RegistryResources.FVEKey`.
const FVE_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\FVE";

/// Enforcement value names that, when present under `FVE_POLICY_KEY`,
/// indicate an actual BitLocker policy is in effect.  List is verbatim
/// from `BitLocker.cs::_enforcementFveValues`.
const FVE_ENFORCEMENT_VALUES: &[&str] = &[
    "EncryptionMethodWithXtsOs",
    "EncryptionMethodWithXtsFdv",
    "EncryptionMethodWithXtsRdv",
    "EncryptionMethod",
    "UseAdvancedStartup",
    "UseTPM",
    "EnableBDEWithNoTPM",
    "OSRecovery",
];

// ---------------------------------------------------------------------------
// Marker classes for wmi-rs `exec_instance_method::<Class, Out>`
// ---------------------------------------------------------------------------
//
// The `Class` generic on `WMIConnection::exec_instance_method` is used by
// `wmi-rs` to look up the method signature on the WMI provider.  Only the
// type name (as exposed to serde via `#[serde(rename = "…")]` or the bare
// identifier) is read — the struct never sees an instance.  Unit structs
// with a manual `Deserialize` impl satisfy the `DeserializeOwned` bound at
// near-zero cost.

#[derive(Debug, Clone, Copy, Deserialize)]
#[allow(non_camel_case_types)]
struct Win32_EncryptableVolume;

// ---------------------------------------------------------------------------
// Input / output structs for the three WMI methods we call
// ---------------------------------------------------------------------------

/// `GetConversionStatus` input parameters.
#[derive(Debug, Clone, Copy, Serialize)]
#[allow(non_snake_case)]
struct GetConversionStatusIn {
    PrecisionFactor: u32,
}

/// `GetConversionStatus` output parameters.  All values that BitLocker
/// guarantees on a successful call.  `EncryptionPercentage` and
/// `WipingPercentage` arrive scaled by `10 ^ PrecisionFactor` (mirrors
/// the C# extension method).
#[derive(Debug, Clone, Deserialize)]
#[allow(non_snake_case)]
struct GetConversionStatusOut {
    ReturnValue: u32,
    ConversionStatus: u32,
    EncryptionPercentage: u32,
    EncryptionFlags: u32,
    WipingStatus: u32,
    WipingPercentage: u32,
}

/// `GetKeyProtectors` input parameters.
#[derive(Debug, Clone, Copy, Serialize)]
#[allow(non_snake_case)]
struct GetKeyProtectorsIn {
    KeyProtectorType: u32,
}

/// `GetKeyProtectors` output parameters.  `VolumeKeyProtectorID` is a
/// string array on the WMI side; serde maps it to `Vec<String>`.
#[derive(Debug, Clone, Deserialize)]
#[allow(non_snake_case)]
struct GetKeyProtectorsOut {
    ReturnValue: u32,
    VolumeKeyProtectorID: Vec<String>,
}

/// `GetKeyProtectorCertificate` input parameters.
#[derive(Debug, Clone, Serialize)]
#[allow(non_snake_case)]
struct GetKeyProtectorCertificateIn {
    VolumeKeyProtectorID: String,
}

/// `GetKeyProtectorCertificate` output parameters.
#[derive(Debug, Clone, Deserialize)]
#[allow(non_snake_case)]
struct GetKeyProtectorCertificateOut {
    ReturnValue: u32,
    #[serde(default)]
    CertThumbprint: Option<String>,
}

// ---------------------------------------------------------------------------
// Volume status — Win32_EncryptableVolume + GetConversionStatus
// ---------------------------------------------------------------------------

/// Returns the BitLocker status of the volume mounted at `mount_point`
/// (e.g. `"C:"`).
///
/// Returns `Ok(None)` when no `Win32_EncryptableVolume` row matches the
/// drive letter — the volume is not BitLocker-aware (FAT32, ReFS, …).
/// Returns `Err(_)` for WMI failures (namespace absent, access denied,
/// method execution failed).
pub(super) fn volume_status(wmi: &mut Wmi, mount_point: &str) -> Result<Option<Value>, String> {
    let escaped = mount_point.replace('\'', "''");
    let row = wmi.query_filtered_first_ns(
        BITLOCKER_NS,
        VOLUME_CLASS,
        &format!("DriveLetter='{escaped}'"),
    )?;
    let Some(row) = row else {
        return Ok(None);
    };

    // Read the three scalar properties WMI populates on every row.
    let drive_letter = variant_str(row.get("DriveLetter"));
    let encryption_method = variant_u32(row.get("EncryptionMethod"));
    let protection_status = variant_u32(row.get("ProtectionStatus"));
    let device_id = variant_str(row.get("DeviceID")).unwrap_or_default();

    // GetConversionStatus is a per-instance method; build the WMI object
    // path the same way `WMIConnection::exec_instance_method` expects it
    // — single-quoted string value, doubling any inner single quote.
    let path = build_volume_path(&device_id);
    let wmi_conn = wmi.connection_ns(BITLOCKER_NS)?;
    let status: GetConversionStatusOut = wmi_conn
        .exec_instance_method::<Win32_EncryptableVolume, _>(
            &path,
            "GetConversionStatus",
            GetConversionStatusIn { PrecisionFactor: 1 },
        )
        .map_err(|e| format!("GetConversionStatus({mount_point}): {e}"))?;

    if status.ReturnValue != 0 {
        return Err(format!(
            "GetConversionStatus({mount_point}) returned {}",
            status.ReturnValue
        ));
    }

    // PrecisionFactor=1 → percentages are tenths (scale ÷10 to recover
    // the human-facing value, same as the C# `Math.Pow(10, factor)`
    // adjustment in `BitLockerExtensions.GetVolumeStatus`).
    let encryption_pct = f64::from(status.EncryptionPercentage) / 10.0;
    let wiping_pct = f64::from(status.WipingPercentage) / 10.0;

    Ok(Some(json!({
        "drive_letter":           drive_letter,
        "encryption_method":      encryption_method,
        "protection_status":      protection_status,
        "conversion_status":      status.ConversionStatus,
        "encryption_percentage":  encryption_pct,
        "encryption_flags":       status.EncryptionFlags,
        "wiping_status":          status.WipingStatus,
        "wiping_percentage":      wiping_pct,
    })))
}

// ---------------------------------------------------------------------------
// Key protectors — GetKeyProtectors + GetKeyProtectorCertificate
// ---------------------------------------------------------------------------

/// Returns the IDs of the key protectors of the given type
/// (e.g. `3 = NumericPassword`, `7 = PublicKey/DRA`) on the volume
/// mounted at `mount_point`.
///
/// Returns `Ok(vec![])` when the volume has no protectors of that type
/// or is not BitLocker-aware (no matching `Win32_EncryptableVolume`
/// row).  Returns `Err(_)` only on hard WMI failures.
pub(super) fn key_protector_ids(
    wmi: &mut Wmi,
    mount_point: &str,
    protector_type: u32,
) -> Result<Vec<String>, String> {
    let Some(path) = volume_path(wmi, mount_point)? else {
        return Ok(Vec::new());
    };

    let wmi_conn = wmi.connection_ns(BITLOCKER_NS)?;
    let out: GetKeyProtectorsOut = wmi_conn
        .exec_instance_method::<Win32_EncryptableVolume, _>(
            &path,
            "GetKeyProtectors",
            GetKeyProtectorsIn {
                KeyProtectorType: protector_type,
            },
        )
        .map_err(|e| format!("GetKeyProtectors({mount_point}, type={protector_type}): {e}"))?;

    if out.ReturnValue != 0 {
        return Err(format!(
            "GetKeyProtectors({mount_point}, type={protector_type}) returned {}",
            out.ReturnValue
        ));
    }

    // Mirror `DataService.GetBitLockerRecoveryKeyProtectorIds()` — the C#
    // implementation lowercases every ID so the intersection with the
    // escrowed IDs (also lowercased) is case-insensitive.
    Ok(out
        .VolumeKeyProtectorID
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect())
}

/// Returns the DRA certificate thumbprints associated with the volume
/// mounted at `mount_point`.
///
/// Composes `GetKeyProtectors(KeyProtectorType=7)` (PublicKey) followed
/// by a `GetKeyProtectorCertificate` call per ID.  Missing or empty
/// `CertThumbprint` entries are filtered out so the returned vector
/// only contains usable thumbprints.
pub(super) fn dra_thumbprints(wmi: &mut Wmi, mount_point: &str) -> Result<Vec<String>, String> {
    // Type 7 = PublicKey (DRA) — see `KeyProtectorType` enum in
    // `Components.Windows.BitLocker.Models.BitLockerEnums.cs`.
    let ids = key_protector_ids(wmi, mount_point, 7)?;
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let Some(path) = volume_path(wmi, mount_point)? else {
        return Ok(Vec::new());
    };

    let wmi_conn = wmi.connection_ns(BITLOCKER_NS)?;
    let mut thumbs = Vec::with_capacity(ids.len());
    for id in ids {
        let out: GetKeyProtectorCertificateOut = wmi_conn
            .exec_instance_method::<Win32_EncryptableVolume, _>(
                &path,
                "GetKeyProtectorCertificate",
                GetKeyProtectorCertificateIn {
                    VolumeKeyProtectorID: id.clone(),
                },
            )
            .map_err(|e| format!("GetKeyProtectorCertificate({id}): {e}"))?;

        if out.ReturnValue == 0
            && let Some(t) = out.CertThumbprint
            && !t.is_empty()
        {
            thumbs.push(t);
        }
        // Non-zero ReturnValue / missing CertThumbprint silently skip —
        // mirrors the C# `OfType<string>()` filter in `GetBitLockerDraCertThumbPrints`.
    }
    Ok(thumbs)
}

// ---------------------------------------------------------------------------
// Policy state — FVE registry enumeration
// ---------------------------------------------------------------------------

/// Returns the BitLocker policy state derived from
/// `HKLM\SOFTWARE\Policies\Microsoft\FVE`:
///
/// - `"Enabled"` when at least one of the eight enforcement value names
///   is present.
/// - `"MissingRegistryKey"` when the key exists but no enforcement
///   value is present, **or** when the key is absent altogether (same
///   collapsing the C# `BitLockerPolicy` transformer applies — see
///   `BitLockerPolicyState.cs`).
///
/// Returns `Err(_)` for unexpected registry failures (access denied,
/// hive corruption).
pub(super) fn policy_state() -> Result<&'static str, String> {
    let names = registry::enum_value_names("HKLM", FVE_POLICY_KEY)?;
    let has_enforcement = names.iter().any(|n| {
        FVE_ENFORCEMENT_VALUES
            .iter()
            .any(|enf| n.eq_ignore_ascii_case(enf))
    });
    Ok(if has_enforcement {
        "Enabled"
    } else {
        "MissingRegistryKey"
    })
}

// ---------------------------------------------------------------------------
// Recovery-key event log queries — escrow + rotation
// ---------------------------------------------------------------------------

/// Returns the lowercased `ProtectorGUID` of every event with `event_id`
/// in the BitLocker management channel.
///
/// Used by `BitLockerRecoveryKeyADBackupSummary` (event 783) and
/// `BitLockerRecoveryKeyAzureADBackupSummary` (event 845) — both
/// transformers consume the same shape (`string[]?`).
///
/// IDs are lowercased to match the casing of
/// `host.bitlocker_key_protector_ids(...)` so intersection in Lua is
/// case-insensitive without any extra normalisation step.
pub(super) fn escrowed_protector_ids(event_id: u32) -> Result<Vec<String>, String> {
    let events = evt::query_events(BITLOCKER_LOG, event_id, Some(BITLOCKER_PROVIDER), None, false)?;
    Ok(events
        .into_iter()
        .filter_map(|ev| ev.event_data.get("ProtectorGUID").map(|g| g.to_lowercase()))
        .collect())
}

/// Returns `Some(true)` if the recovery key has been rotated since
/// boot, `Some(false)` if a rotation was attempted but the matching
/// `ProtectorType=0x3` (NumericPassword) event was not observed,
/// and `Some(None)` (`Ok(None)`) when no rotation event has fired at
/// all since boot.
///
/// Faithful port of `BitLockerService.RecoveryKeyRotationFromEventsExecuted`
/// — same three-state result and same one-minute lookback window
/// (`rotationDate - 1 minute → present` for the 775 search).
pub(super) fn recovery_key_rotation_executed() -> Result<Option<bool>, String> {
    // --- Step 1: derive a lower bound on "since last boot" -------------
    // ShutdownTime is the last clean shutdown's FILETIME.  Using it as a
    // lower bound is the same approximation `BitLockerService` makes in
    // C#: `DateTime.FromFileTime(shutdownTime)` is treated as "last boot
    // time", which is wrong in the strict sense (it's the previous
    // shutdown) but correct for the comparison we need — any rotation
    // event after the last shutdown happened during the current uptime.
    let Some(buf) = registry::read_binary(
        "HKLM",
        r"SYSTEM\CurrentControlSet\Control\Windows",
        "ShutdownTime",
    ) else {
        // Missing ShutdownTime → mirror C# `null` → no rotation observed.
        return Ok(None);
    };
    if buf.len() < 8 {
        return Ok(None);
    }
    let mut ticks_bytes = [0u8; 8];
    ticks_bytes.copy_from_slice(&buf[..8]);
    let filetime_ticks = i64::from_le_bytes(ticks_bytes);

    let Some(since) = super::winver::filetime_to_iso8601(filetime_ticks) else {
        return Ok(None);
    };

    // --- Step 2: most recent rotation event (864) ----------------------
    let rotation_events = evt::query_events(BITLOCKER_LOG, 864, Some(BITLOCKER_PROVIDER), Some(&since), true)?;
    let Some(rotation) = rotation_events.into_iter().next() else {
        // No rotation event since last boot → mirror C# `null`.
        return Ok(None);
    };
    if rotation.time_created.is_empty() {
        return Ok(Some(false));
    }

    // --- Step 3: scan 775 events around rotation_time - 1 min ---------
    // Subtract 60 s from the rotation timestamp to mirror the C# guard
    // window (clock skew between BitLocker provider writes).  If the
    // subtraction overflows or fails to parse, fall back to `since`
    // (the boot-time lower bound) which is strictly looser — never
    // tighter — so no rotation event is excluded by mistake.
    let lookback = subtract_seconds_iso8601(&rotation.time_created, 60).unwrap_or(since);
    let bitlocker_events = evt::query_events(BITLOCKER_LOG, 775, Some(BITLOCKER_PROVIDER), Some(&lookback), true)?;
    let found = bitlocker_events
        .iter()
        .any(|ev| ev.event_data.get("ProtectorType").map(String::as_str) == Some("0x3"));
    Ok(Some(found))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Looks up the WMI `__PATH`-style object reference for a volume.
fn volume_path(wmi: &mut Wmi, mount_point: &str) -> Result<Option<String>, String> {
    let escaped = mount_point.replace('\'', "''");
    let row = wmi.query_filtered_first_ns(
        BITLOCKER_NS,
        VOLUME_CLASS,
        &format!("DriveLetter='{escaped}'"),
    )?;
    Ok(row.and_then(|r| variant_str(r.get("DeviceID")).map(|d| build_volume_path(&d))))
}

/// Builds the WMI object path `Win32_EncryptableVolume.DeviceID="<id>"`
/// — relative form, namespace is supplied by the active connection.
fn build_volume_path(device_id: &str) -> String {
    // DeviceID for `Win32_EncryptableVolume` looks like
    // `\\?\Volume{GUID}\` — every backslash must be doubled in the WMI
    // path so the parser sees a literal backslash inside the quoted
    // value, and every literal quote (none in practice) doubled too.
    let escaped: String = device_id
        .chars()
        .flat_map(|c| {
            let pair: [Option<char>; 2] = match c {
                '\\' => [Some('\\'), Some('\\')],
                '"' => [Some('\\'), Some('"')],
                other => [Some(other), None],
            };
            pair.into_iter().flatten()
        })
        .collect();
    format!("{VOLUME_CLASS}.DeviceID=\"{escaped}\"")
}

/// Extracts a `String` from a WMI `Variant` field, or `None` if absent
/// or of the wrong type.
fn variant_str(v: Option<&Variant>) -> Option<String> {
    match v? {
        Variant::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Extracts a `u32` from a WMI `Variant` field, or `None` if absent
/// or of an incompatible type.  Accepts both `UI4` (unsigned) and `I4`
/// (signed) for robustness across WMI providers.
fn variant_u32(v: Option<&Variant>) -> Option<u32> {
    match v? {
        Variant::UI4(n) => Some(*n),
        Variant::I4(n) => u32::try_from(*n).ok(),
        Variant::UI2(n) => Some(u32::from(*n)),
        Variant::I2(n) => u32::try_from(*n).ok(),
        _ => None,
    }
}

/// Subtracts `secs` seconds from an ISO 8601 timestamp string and
/// returns the result in `YYYY-MM-DDTHH:MM:SSZ` form.
///
/// Accepts the variable-precision shape that `EvtRender` emits
/// (e.g. `"2024-01-15T10:30:00.1234567Z"`); fractional seconds are
/// truncated.  Returns `None` for unparseable inputs.
fn subtract_seconds_iso8601(iso: &str, secs: u32) -> Option<String> {
    // Pattern: YYYY-MM-DDTHH:MM:SS[.fractional]Z
    let bytes = iso.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let year: i64 = std::str::from_utf8(&bytes[0..4]).ok()?.parse().ok()?;
    let month: u32 = std::str::from_utf8(&bytes[5..7]).ok()?.parse().ok()?;
    let day: u32 = std::str::from_utf8(&bytes[8..10]).ok()?.parse().ok()?;
    let hour: u32 = std::str::from_utf8(&bytes[11..13]).ok()?.parse().ok()?;
    let minute: u32 = std::str::from_utf8(&bytes[14..16]).ok()?.parse().ok()?;
    let second: u32 = std::str::from_utf8(&bytes[17..19]).ok()?.parse().ok()?;

    // Convert to Unix seconds via days-since-1970 (Howard Hinnant
    // `days_from_civil` — exact for the proleptic Gregorian calendar,
    // same algorithm used in reverse by `winver::filetime_to_iso8601`).
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = if shifted_year >= 0 {
        shifted_year
    } else {
        shifted_year - 399
    } / 400;
    let yoe = u64::try_from(shifted_year - era * 400).ok()?;
    let m_u32 = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * u64::from(m_u32) + 2) / 5 + u64::from(day) - 1;
    let day_of_era = yoe * 365 + yoe / 4 - yoe / 100 + day_of_year;
    let days = era * 146_097 + i64::try_from(day_of_era).ok()? - 719_468;

    let total_secs = days.checked_mul(86_400)?
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second);
    let target = total_secs.checked_sub(i64::from(secs))?;
    if target < 0 {
        return None;
    }

    // And back to civil date.
    let day_count = target.div_euclid(86_400);
    let time_secs = target.rem_euclid(86_400);
    let h = u32::try_from(time_secs / 3_600).ok()?;
    let mi = u32::try_from((time_secs / 60) % 60).ok()?;
    let s = u32::try_from(time_secs % 60).ok()?;

    let zb = day_count + 719_468;
    let era_back = if zb >= 0 { zb } else { zb - 146_096 } / 146_097;
    let day_of_era_back = zb - era_back * 146_097;
    let yoe_back = (day_of_era_back
        - day_of_era_back / 1_460
        + day_of_era_back / 36_524
        - day_of_era_back / 146_096)
        / 365;
    let year_offset = yoe_back + era_back * 400;
    let day_of_year_back = day_of_era_back - (365 * yoe_back + yoe_back / 4 - yoe_back / 100);
    let month_offset = (5 * day_of_year_back + 2) / 153;
    let day_back = u32::try_from(day_of_year_back - (153 * month_offset + 2) / 5 + 1).ok()?;
    let month_back = u32::try_from(if month_offset < 10 {
        month_offset + 3
    } else {
        month_offset - 9
    })
    .ok()?;
    let year_back = i32::try_from(if month_back <= 2 {
        year_offset + 1
    } else {
        year_offset
    })
    .ok()?;

    Some(format!(
        "{year_back:04}-{month_back:02}-{day_back:02}T{h:02}:{mi:02}:{s:02}Z"
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{build_volume_path, subtract_seconds_iso8601};

    #[test]
    fn build_volume_path_doubles_backslashes() {
        let path = build_volume_path(r"\\?\Volume{abc-123}\");
        assert_eq!(
            path,
            r#"Win32_EncryptableVolume.DeviceID="\\\\?\\Volume{abc-123}\\""#
        );
    }

    #[test]
    fn subtract_60_seconds_within_minute_boundary() {
        assert_eq!(
            subtract_seconds_iso8601("2024-01-15T10:30:30Z", 60),
            Some("2024-01-15T10:29:30Z".to_string())
        );
    }

    #[test]
    fn subtract_60_seconds_crosses_hour_boundary() {
        assert_eq!(
            subtract_seconds_iso8601("2024-01-15T10:00:30Z", 60),
            Some("2024-01-15T09:59:30Z".to_string())
        );
    }

    #[test]
    fn subtract_60_seconds_crosses_day_boundary() {
        assert_eq!(
            subtract_seconds_iso8601("2024-01-15T00:00:30Z", 60),
            Some("2024-01-14T23:59:30Z".to_string())
        );
    }

    #[test]
    fn subtract_handles_fractional_seconds() {
        // Fractional part is truncated, not added; we still subtract from
        // the second-truncated form.
        assert_eq!(
            subtract_seconds_iso8601("2024-01-15T10:30:30.1234567Z", 60),
            Some("2024-01-15T10:29:30Z".to_string())
        );
    }

    #[test]
    fn subtract_unparseable_returns_none() {
        assert_eq!(subtract_seconds_iso8601("not a date", 60), None);
    }
}
