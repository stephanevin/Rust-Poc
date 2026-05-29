//! Thin registry read wrapper for host bindings.

// `RegOpenKeyExW` / `RegQueryValueExW` take several `*mut` out-params we pass
// as `&mut local`. Rewriting those call sites with explicit `from_mut` is
// noisier and no safer than the surrounding `unsafe` block.
#![allow(clippy::borrow_as_ptr, clippy::ref_as_ptr)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, REG_DWORD, REG_EXPAND_SZ,
    REG_MULTI_SZ, REG_QWORD, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW, RegEnumValueW,
    RegOpenKeyExW, RegQueryValueExW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use serde_json::Value;

pub(super) fn read(hive: &str, key: &str, value: &str) -> Result<Option<Value>, String> {
    let root: HKEY = match hive {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        other => return Err(format!("unsupported hive: {other}")),
    };

    // Open sub-key.
    let mut hkey = HKEY::default();
    let key_w: HSTRING = key.into();
    // SAFETY: HSTRING lives for the call; HKEY is written by the API on success.
    unsafe {
        let r = RegOpenKeyExW(root, PCWSTR(key_w.as_ptr()), None, KEY_READ, &mut hkey);
        if r.is_err() {
            // Missing key is a normal "no value" case, not a hard error.
            return Ok(None);
        }
    }

    // Query value size + type.
    let value_w: HSTRING = value.into();
    let mut value_type = REG_VALUE_TYPE::default();
    let mut data_size: u32 = 0;
    let result_val: Option<Value> = unsafe {
        let r = RegQueryValueExW(
            hkey,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut value_type),
            None,
            Some(&mut data_size),
        );
        if r.is_err() || data_size == 0 {
            let _ = RegCloseKey(hkey);
            return Ok(None);
        }
        let mut buf = vec![0u8; data_size as usize];
        let r = RegQueryValueExW(
            hkey,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut value_type),
            Some(buf.as_mut_ptr()),
            Some(&mut data_size),
        );
        let _ = RegCloseKey(hkey);
        if r.is_err() {
            return Ok(None);
        }
        buf.truncate(data_size as usize);
        decode(value_type, &buf)
    };

    Ok(result_val)
}

/// Coerces a decoded registry [`Value`] into a comparable string: a
/// `REG_DWORD` `1` and a `REG_SZ` `"1"` both become `"1"`, matching the C#
/// `GetValue(...)?.ToString()` behaviour. Non-scalar types (`REG_MULTI_SZ`
/// arrays, …) yield `None`.
///
/// Pure (no registry access), so it is unit-testable and shared by the LAPS
/// (deviation #44) and `CyberArk` EPM (deviation #46) bindings.
pub(super) fn as_string(value: Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Returns `true` when the registry key exists and can be opened for
/// reading, `false` when it is absent or cannot be opened for any reason.
///
/// Only the *presence* of the key matters — no value is read.  Mirrors the
/// C# existence probe `_registry.GetKey(path) is not null` used by
/// `Security.cs::GetLegacyLapsGpExtensionPresent` (deviation #44).
pub(super) fn key_exists(hive: &str, key: &str) -> bool {
    let root: HKEY = match hive {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        _ => return false,
    };

    let mut hkey = HKEY::default();
    let key_w: HSTRING = key.into();
    // SAFETY: HSTRING outlives the call; KEY_READ is non-destructive.
    let r = unsafe { RegOpenKeyExW(root, PCWSTR(key_w.as_ptr()), None, KEY_READ, &mut hkey) };
    if r.is_ok() {
        // SAFETY: hkey was opened successfully; RegCloseKey never fails for
        // a handle returned by RegOpenKeyExW.
        unsafe {
            let _ = RegCloseKey(hkey);
        }
    }
    r.is_ok()
}

/// Returns the names of all direct subkeys of `key` in `hive`.
/// Returns an empty `Vec` when the key is absent, has no subkeys, or
/// could not be opened for any other reason — failures are absorbed
/// silently to keep the call site simple.
///
/// **Most callers should keep using this function.**  Use
/// [`try_subkey_names`] only when you need to distinguish "key absent"
/// from "open failed" (e.g. to record a diagnostic).
pub(super) fn subkey_names(hive: &str, key: &str) -> Vec<String> {
    try_subkey_names(hive, key).unwrap_or_default()
}

/// Variant of [`subkey_names`] that distinguishes "key absent" from
/// "open failed".
///
/// - `Ok(vec![])` — the key opens with no subkeys, **or** the key path
///   does not exist (`ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND`).
///   Both outcomes look identical to the caller of [`subkey_names`].
/// - `Ok(vec![...])` — subkeys enumerated successfully.
/// - `Err(_)` — `RegOpenKeyExW` failed for any other reason (access
///   denied, registry corruption, etc.).  The error message embeds the
///   hive, the key path, and the raw Win32 status code so the caller
///   can record it under `host.errors()` for the operator.
///
/// Currently used by `software::os_software_installed` to surface the
/// (rare but real) case where the `HKLM\…\Uninstall` hive cannot be
/// opened — otherwise the binding would emit an empty array with no
/// trace of the failure.
pub(super) fn try_subkey_names(hive: &str, key: &str) -> Result<Vec<String>, String> {
    let root: HKEY = match hive {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        other => return Err(format!("unsupported hive: {other}")),
    };

    let mut hkey = HKEY::default();
    let key_w: HSTRING = key.into();
    // SAFETY: HSTRING lives for the call; KEY_READ is a non-destructive flag.
    let r = unsafe { RegOpenKeyExW(root, PCWSTR(key_w.as_ptr()), None, KEY_READ, &mut hkey) };
    if r == ERROR_FILE_NOT_FOUND || r == ERROR_PATH_NOT_FOUND {
        // Missing key is a normal outcome (e.g. a per-user uninstall hive
        // for a profile that never installed anything).
        return Ok(Vec::new());
    }
    if r.is_err() {
        return Err(format!(
            "RegOpenKeyExW({hive}\\{key}) failed with WIN32_ERROR({})",
            r.0
        ));
    }

    let mut names = Vec::new();
    // Registry key names are at most 255 characters (+ NUL).  256 fits in u32.
    let mut name_buf = vec![0u16; 256];
    let buf_capacity: u32 = 256;
    for idx in 0_u32.. {
        let mut name_len = buf_capacity;
        // SAFETY: hkey is valid; name_buf outlives the call; we pass its
        // length so the API cannot write past the end.
        let r = unsafe {
            RegEnumKeyExW(
                hkey,
                idx,
                Some(PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
                None,
                Some(PWSTR::null()),
                None,
                None,
            )
        };
        if !r.is_ok() {
            // Covers ERROR_NO_MORE_ITEMS (259) and any unexpected error.
            break;
        }
        let name = OsString::from_wide(&name_buf[..name_len as usize])
            .to_string_lossy()
            .into_owned();
        names.push(name);
    }

    // SAFETY: hkey was opened successfully; RegCloseKey never fails for a
    // handle returned by RegOpenKeyExW.
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    Ok(names)
}

/// Returns the names of every direct value under `key` in `hive`.
///
/// Mirrors [`subkey_names`] but for value-name enumeration via
/// `RegEnumValueW`.  Used by `bitlocker::policy_state` to detect whether
/// any of the eight FVE enforcement values are present under
/// `HKLM\SOFTWARE\Policies\Microsoft\FVE` — the same test that
/// `BitLocker.cs::GetFVEStatus` performs in `ComplianceApp` via
/// `RegistryKey.GetValueNames()`.
///
/// Returns `Ok(vec![])` when the key is absent (normal "no policy
/// configured" case) and `Err(_)` for any other Win32 failure
/// (access denied, registry corruption, …) — same calling contract
/// as [`try_subkey_names`].
pub(super) fn enum_value_names(hive: &str, key: &str) -> Result<Vec<String>, String> {
    let root: HKEY = match hive {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        other => return Err(format!("unsupported hive: {other}")),
    };

    let mut hkey = HKEY::default();
    let key_w: HSTRING = key.into();
    // SAFETY: HSTRING outlives the call; KEY_READ is non-destructive.
    let r = unsafe { RegOpenKeyExW(root, PCWSTR(key_w.as_ptr()), None, KEY_READ, &mut hkey) };
    if r == ERROR_FILE_NOT_FOUND || r == ERROR_PATH_NOT_FOUND {
        return Ok(Vec::new());
    }
    if r.is_err() {
        return Err(format!(
            "RegOpenKeyExW({hive}\\{key}) failed with WIN32_ERROR({})",
            r.0
        ));
    }

    let mut names = Vec::new();
    // Registry value names are at most 16383 chars per MSDN — sized to a
    // comfortable 1024 (FVE policy uses ≤ 32-char names; same upper bound
    // as the equivalent `RegistryKey.GetValueNames` allocation in .NET).
    let mut name_buf = vec![0u16; 1024];
    let buf_capacity: u32 = 1024;
    for idx in 0_u32.. {
        let mut name_len = buf_capacity;
        // SAFETY: hkey is valid; name_buf outlives the call; name_len is
        // passed by reference so the API cannot overflow.
        let r = unsafe {
            RegEnumValueW(
                hkey,
                idx,
                Some(PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
                None,
                None,
                None,
                None,
            )
        };
        if r.is_err() {
            // ERROR_NO_MORE_ITEMS (259) at end-of-iteration; any other
            // error is benign at this stage — we already returned the
            // names we successfully enumerated.
            break;
        }
        let name = OsString::from_wide(&name_buf[..name_len as usize])
            .to_string_lossy()
            .into_owned();
        names.push(name);
    }

    // SAFETY: hkey opened by RegOpenKeyExW; RegCloseKey never fails.
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    Ok(names)
}

/// Reads a `REG_BINARY` (or any) value as raw bytes.
///
/// Used by `bitlocker::recovery_key_rotation_executed` to read the
/// 8-byte `FILETIME` stored as `REG_BINARY` under
/// `HKLM\SYSTEM\CurrentControlSet\Control\Windows\ShutdownTime` — the
/// same value the C# helper `LastKeyRotationEvent` reads via
/// `RegistryKey.GetValue(...) is byte[]`.
///
/// Returns `None` when the key or value is absent; returns the raw
/// byte buffer otherwise (regardless of registry type).
pub(super) fn read_binary(hive: &str, key: &str, value: &str) -> Option<Vec<u8>> {
    let root: HKEY = match hive {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        _ => return None,
    };

    let mut hkey = HKEY::default();
    let key_w: HSTRING = key.into();
    // SAFETY: HSTRING outlives the call.
    let r = unsafe { RegOpenKeyExW(root, PCWSTR(key_w.as_ptr()), None, KEY_READ, &mut hkey) };
    if r.is_err() {
        return None;
    }

    let value_w: HSTRING = value.into();
    let mut value_type = REG_VALUE_TYPE::default();
    let mut data_size: u32 = 0;
    // SAFETY: probe call with buffer=None to learn the size.
    let r = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut value_type),
            None,
            Some(&mut data_size),
        )
    };
    if r.is_err() || data_size == 0 {
        // SAFETY: handle was opened above.
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        return None;
    }

    let mut buf = vec![0u8; data_size as usize];
    // SAFETY: buf has data_size bytes; the API writes at most that many.
    let r = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut value_type),
            Some(buf.as_mut_ptr()),
            Some(&mut data_size),
        )
    };
    // SAFETY: handle opened above; closing is the documented contract.
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if r.is_err() {
        return None;
    }
    buf.truncate(data_size as usize);
    Some(buf)
}

fn decode(t: REG_VALUE_TYPE, buf: &[u8]) -> Option<Value> {
    match t {
        REG_SZ | REG_EXPAND_SZ => Some(Value::String(utf16_to_string(buf))),
        REG_MULTI_SZ => {
            let s = utf16_to_string(buf);
            let items: Vec<Value> = s
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(|s| Value::String(s.to_string()))
                .collect();
            Some(Value::Array(items))
        }
        REG_DWORD if buf.len() >= 4 => {
            let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            Some(Value::from(n))
        }
        REG_QWORD if buf.len() >= 8 => {
            let n = u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            Some(Value::from(n))
        }
        _ => None,
    }
}

fn utf16_to_string(buf: &[u8]) -> String {
    // buf length is bytes; chunk into u16 LE words. Trim trailing NULs.
    let words: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0 || buf.len() > 2) // keep nulls inside MULTI_SZ
        .collect();
    let s: OsString = OsString::from_wide(&words);
    s.to_string_lossy().trim_end_matches('\0').to_string()
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{as_string, enum_value_names, key_exists, try_subkey_names};

    /// `as_string`: `REG_SZ` passes through, numbers (`REG_DWORD`/`REG_QWORD`)
    /// stringify, and non-scalar types collapse to `None`.
    #[test]
    fn as_string_coerces_scalars_only() {
        assert_eq!(as_string(json!("23.4.1.7")), Some("23.4.1.7".to_string()));
        assert_eq!(as_string(json!(1u32)), Some("1".to_string()));
        assert_eq!(as_string(json!(42u64)), Some("42".to_string()));
        assert_eq!(as_string(json!(true)), None);
        assert_eq!(as_string(json!(["a", "b"])), None);
        assert_eq!(as_string(Value::Null), None);
    }

    /// `HKLM\SOFTWARE` exists on every Windows install — happy path.
    #[test]
    fn key_exists_true_for_well_known_key() {
        assert!(key_exists("HKLM", "SOFTWARE"));
    }

    /// A crafted-absent key must be reported as not existing.
    #[test]
    fn key_exists_false_for_absent_key() {
        assert!(!key_exists(
            "HKLM",
            r"SOFTWARE\This-Key-Does-Not-Exist-rust-poc-laps-54321"
        ));
    }

    /// An unsupported hive collapses to `false` (no panic, no error).
    #[test]
    fn key_exists_false_for_unsupported_hive() {
        assert!(!key_exists("BOGUS_HIVE", "anything"));
    }

    /// `HKLM\SOFTWARE` exists on every Windows install and has many
    /// subkeys — happy path.
    #[test]
    fn try_subkey_names_existing_hive_returns_non_empty() {
        // let-else avoids the workspace-wide clippy::expect_used ban
        // while still producing a clear panic message on failure.
        let Ok(names) = try_subkey_names("HKLM", "SOFTWARE") else {
            panic!("HKLM\\SOFTWARE should always open on a healthy Windows install");
        };
        assert!(
            !names.is_empty(),
            "HKLM\\SOFTWARE always has subkeys (Microsoft, Classes, …)"
        );
    }

    /// A key path crafted to be absent must collapse to `Ok(vec![])` — the
    /// `ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND` branch.  This is
    /// the load-bearing distinction for `software::os_software_installed`:
    /// "key not there" must not become an operator-visible error.
    #[test]
    fn try_subkey_names_absent_key_returns_empty_ok() {
        let result = try_subkey_names("HKLM", r"SOFTWARE\This-Key-Does-Not-Exist-rust-poc-12345");
        assert_eq!(result, Ok(Vec::new()));
    }

    /// An unsupported hive string is an `Err`, not an empty vec — callers
    /// that misuse the API get a diagnostic instead of silent emptiness.
    #[test]
    fn try_subkey_names_unsupported_hive_returns_err() {
        let result = try_subkey_names("BOGUS_HIVE", "anything");
        assert!(matches!(result, Err(ref msg) if msg.contains("BOGUS_HIVE")));
    }

    /// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` is present on
    /// every Windows install and exposes well-known values such as
    /// `CurrentBuild`, `ProductName`, `EditionID` — happy path for
    /// `enum_value_names`.
    #[test]
    fn enum_value_names_returns_non_empty_for_well_known_key() {
        let Ok(names) = enum_value_names("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        else {
            panic!("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion must open");
        };
        assert!(
            !names.is_empty(),
            "CurrentVersion always has values (ProductName, CurrentBuild, …)"
        );
    }

    /// Absent key collapses to `Ok(vec![])` — mirrors the
    /// `try_subkey_names_absent_key_returns_empty_ok` contract.
    #[test]
    fn enum_value_names_absent_key_returns_empty_ok() {
        let result =
            enum_value_names("HKLM", r"SOFTWARE\This-Key-Does-Not-Exist-rust-poc-fvepolicy-9876");
        assert_eq!(result, Ok(Vec::new()));
    }

    /// Unsupported hive → diagnostic Err, not silent empty.
    #[test]
    fn enum_value_names_unsupported_hive_returns_err() {
        let result = enum_value_names("BOGUS_HIVE", "anything");
        assert!(matches!(result, Err(ref msg) if msg.contains("BOGUS_HIVE")));
    }
}
