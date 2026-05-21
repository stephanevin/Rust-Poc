//! Thin registry read wrapper for host bindings.

// `RegOpenKeyExW` / `RegQueryValueExW` take several `*mut` out-params we pass
// as `&mut local`. Rewriting those call sites with explicit `from_mut` is
// noisier and no safer than the surrounding `unsafe` block.
#![allow(clippy::borrow_as_ptr, clippy::ref_as_ptr)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_QWORD, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use serde_json::Value;

pub(super) fn read(hive: &str, key: &str, value: &str) -> Result<Option<Value>, String> {
    let root: HKEY = match hive {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
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

/// Returns the names of all direct subkeys of `key` in `hive`.
/// Returns an empty `Vec` when the key is absent or has no subkeys.
pub(super) fn subkey_names(hive: &str, key: &str) -> Vec<String> {
    let root: HKEY = match hive {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        _ => return Vec::new(),
    };

    let mut hkey = HKEY::default();
    let key_w: HSTRING = key.into();
    // SAFETY: HSTRING lives for the call; KEY_READ is a non-destructive flag.
    let opened =
        unsafe { RegOpenKeyExW(root, PCWSTR(key_w.as_ptr()), None, KEY_READ, &mut hkey).is_ok() };
    if !opened {
        return Vec::new();
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
    names
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
