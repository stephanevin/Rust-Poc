//! Credential Guard / Device Guard status — `Win32_DeviceGuard` WMI query.
//!
//! Mirrors `ComplianceApp.Shared.DTOs.CredentialGuardStatus.Create(...)`:
//! reads the 13 raw properties of `Win32_DeviceGuard` in the
//! `root\Microsoft\Windows\DeviceGuard` namespace, dedupes the array
//! fields, and derives two convenience booleans
//! (`is_credential_guard_configured`, `is_credential_guard_running`)
//! that mirror `SecurityServicesConfigured.Contains(1u)` and
//! `SecurityServicesRunning.Contains(1u)`.
//!
//! ## Why these convenience booleans live in Rust
//!
//! The C# DTO already exposes them and three transformers
//! (`CredentialGuardStatus`, `CredentialGuardServices`,
//! `CredentialGuardVirtualization`) consume the raw arrays differently.
//! Doing the `Contains(1)` test in Rust keeps the Lua collector lean —
//! the script just checks a boolean instead of iterating a u32 array
//! itself, while the raw arrays remain available for any future
//! transformer that needs them.

// Doc comments mention product names like "Credential Guard" and
// "Device Guard" in prose; `doc_markdown` flags those without backticks.
#![allow(clippy::doc_markdown)]

use std::collections::BTreeSet;

use serde_json::{Value, json};
use wmi::Variant;

use super::wmi::Wmi;

/// WMI namespace exposing `Win32_DeviceGuard`.  Note: case matters on
/// some Windows builds — `root\Microsoft\Windows\DeviceGuard` is the
/// documented form.
pub(super) const DEVICE_GUARD_NS: &str = r"root\Microsoft\Windows\DeviceGuard";

/// WMI class queried for the status.  Exactly one instance exists on
/// any supported Windows 10/11 build.
const DEVICE_GUARD_CLASS: &str = "Win32_DeviceGuard";

/// Maps `SecurityServicesConfigured` / `SecurityServicesRunning` codes
/// to the English labels used by `CredentialGuardResources.resx` in the
/// ComplianceApp.  Building this array in Rust (rather than in the Lua
/// collector) is what guarantees an **empty** services list serialises
/// as a JSON `[]` instead of a `{}` — mlua's `to_value` tags the table
/// with the `__mlua_serde_array` metatable that `from_value` reads back
/// to preserve array-ness across the Lua round trip, even when the
/// table is empty.  A label built in Lua would lose that marker.
fn service_label(code: u64) -> &'static str {
    match code {
        0 => "No services running",
        1 => "Credential Guard is running",
        2 => "HVCI is running",
        3 => "System Guard Secure Launch is running",
        4 => "SMM Firmware Measurement is running",
        5 => "Kernel-mode Hardware-enforced Stack Protection is running",
        6 => "Kernel-mode Hardware-enforced Stack Protection is running in Audit mode",
        7 => "Hypervisor-Enforced Paging Translation is running",
        _ => "Unknown",
    }
}

/// Builds a JSON string array out of a `SecurityServices*` code array.
/// Returns `Some([])` when the input array is empty (preserving the
/// "no services" signal as a JSON `[]`).  Returns `None` when the input
/// is absent or not an array (so the binding can emit `null` rather
/// than an empty list, mirroring "we don't know").
fn services_labels(v: Option<&Value>) -> Option<Vec<String>> {
    let arr = v?.as_array()?;
    Some(
        arr.iter()
            .filter_map(Value::as_u64)
            .map(|code| service_label(code).to_string())
            .collect(),
    )
}

/// Returns the `Win32_DeviceGuard` row as a JSON object, with arrays
/// deduplicated and the two `is_credential_guard_*` booleans appended.
///
/// Returns `Ok(None)` when the namespace exists but the class returns
/// no rows (unusual: a documented zero-row outcome on Server SKUs with
/// the DG feature uninstalled).  Returns `Err(_)` for any WMI failure.
pub(super) fn status(wmi: &mut Wmi) -> Result<Option<Value>, String> {
    let rows = wmi.query_all_ns(DEVICE_GUARD_NS, DEVICE_GUARD_CLASS)?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };

    // Pull the source object as-is so we can layer the derived fields
    // on top.  serde_json::Value is the JSON shape `host.wmi_all` would
    // hand to Lua — same property names, same casing.
    let Value::Object(mut obj) = row else {
        return Ok(None);
    };

    let configured = u32_array_contains_one(obj.get("SecurityServicesConfigured"));
    let running = u32_array_contains_one(obj.get("SecurityServicesRunning"));

    // De-duplicate array fields (mirrors `Distinct()` in the C# factory).
    for key in [
        "RequiredSecurityProperties",
        "AvailableSecurityProperties",
        "SecurityServicesConfigured",
        "SecurityServicesRunning",
        "VirtualMachineIsolationProperties",
        "SecurityFeaturesEnabled",
    ] {
        if let Some(v) = obj.get_mut(key) {
            dedupe_u32_array_in_place(v);
        }
    }

    // Append the two derived booleans under snake_case names so the Lua
    // collector reads them consistently with the rest of the binding
    // surface.  The original PascalCase WMI fields stay alongside.
    obj.insert("is_credential_guard_configured".to_string(), json!(configured));
    obj.insert("is_credential_guard_running".to_string(), json!(running));

    // Labelled mirrors of the two SecurityServices* arrays, built in
    // Rust so empty arrays survive the Lua round trip as JSON `[]`.
    // Keys are snake_case to match the derived booleans above.
    let configured_labels = services_labels(obj.get("SecurityServicesConfigured"));
    let running_labels = services_labels(obj.get("SecurityServicesRunning"));
    if let Some(labels) = configured_labels {
        obj.insert(
            "security_services_configured_labels".to_string(),
            Value::Array(labels.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(labels) = running_labels {
        obj.insert(
            "security_services_running_labels".to_string(),
            Value::Array(labels.into_iter().map(Value::String).collect()),
        );
    }

    Ok(Some(Value::Object(obj)))
}

/// Returns `true` when `v` is a JSON array containing the integer `1`
/// (in any of the small-int forms `serde_json` might produce from a WMI
/// `UInt32` row).  Anything else (absent, non-array, empty) is `false`.
fn u32_array_contains_one(v: Option<&Value>) -> bool {
    v.and_then(Value::as_array)
        .is_some_and(|arr| arr.iter().any(|e| e.as_u64() == Some(1)))
}

/// De-duplicates a JSON array of integers in place, preserving the
/// first-occurrence order — same semantics as `IEnumerable.Distinct()`
/// in the C# factory (`CredentialGuardStatus.Create`).  The seen-set is
/// a `BTreeSet<u64>` because the value domain is small (single-digit
/// codes for security services / VBS properties) so an O(log n) lookup
/// is cache-friendly and avoids a `HashSet`'s `Hash` overhead.
fn dedupe_u32_array_in_place(v: &mut Value) {
    if let Value::Array(arr) = v {
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut dedup: Vec<Value> = Vec::with_capacity(arr.len());
        for item in arr.drain(..) {
            if let Some(n) = item.as_u64() {
                if seen.insert(n) {
                    dedup.push(Value::from(n));
                }
            } else {
                // Preserve non-integer items as-is so we don't lose data
                // if WMI ever returns mixed types.  In practice these
                // arrays are pure u32.
                dedup.push(item);
            }
        }
        *arr = dedup;
    }
}

#[allow(dead_code)]
fn variant_u32(v: Option<&Variant>) -> Option<u32> {
    match v? {
        Variant::UI4(n) => Some(*n),
        Variant::I4(n) => u32::try_from(*n).ok(),
        Variant::UI2(n) => Some(u32::from(*n)),
        Variant::I2(n) => u32::try_from(*n).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{dedupe_u32_array_in_place, service_label, services_labels, u32_array_contains_one};

    #[test]
    fn detects_one_in_array() {
        let v = json!([0u32, 1u32, 2u32]);
        assert!(u32_array_contains_one(Some(&v)));
    }

    #[test]
    fn one_absent_from_array() {
        let v = json!([0u32, 2u32]);
        assert!(!u32_array_contains_one(Some(&v)));
    }

    #[test]
    fn missing_value_is_false() {
        assert!(!u32_array_contains_one(None));
    }

    #[test]
    fn non_array_value_is_false() {
        let v = json!(1u32);
        assert!(!u32_array_contains_one(Some(&v)));
    }

    #[test]
    fn dedupe_preserves_first_occurrence_order() {
        // Same semantics as C# `IEnumerable.Distinct()` — [3,1,2,1,3]
        // collapses to [3,1,2], NOT to [1,2,3].  Sorting would diverge
        // from the C# factory output for any consumer that relies on
        // ordinal positions (none exist today, but mirroring the C#
        // behaviour keeps the JSON output byte-identical when both
        // implementations run side by side).
        let mut v = json!([3u32, 1u32, 2u32, 1u32, 3u32]);
        dedupe_u32_array_in_place(&mut v);
        assert_eq!(v, json!([3u32, 1u32, 2u32]));
    }

    #[test]
    fn dedupe_empty_remains_empty() {
        let mut v: Value = json!([]);
        dedupe_u32_array_in_place(&mut v);
        assert_eq!(v, json!([]));
    }

    #[test]
    fn service_label_known_codes() {
        assert_eq!(service_label(1), "Credential Guard is running");
        assert_eq!(service_label(2), "HVCI is running");
    }

    #[test]
    fn service_label_unknown_code() {
        assert_eq!(service_label(99), "Unknown");
    }

    #[test]
    fn services_labels_empty_array_stays_empty_vec() {
        let v = json!([]);
        let labels = services_labels(Some(&v));
        assert_eq!(labels, Some(vec![]));
    }

    #[test]
    fn services_labels_absent_value_returns_none() {
        assert_eq!(services_labels(None), None);
    }

    #[test]
    fn services_labels_maps_known_codes_in_order() {
        let v = json!([1u32, 2u32]);
        assert_eq!(
            services_labels(Some(&v)),
            Some(vec![
                "Credential Guard is running".to_string(),
                "HVCI is running".to_string(),
            ])
        );
    }
}
