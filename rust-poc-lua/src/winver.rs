//! `RtlGetVersion` + `GetFirmwareType` + coarse product classification.

// Both `RtlGetVersion` and `GetFirmwareType` take `*mut` out-params we pass
// as `&mut local`. The `borrow_as_ptr` rewrite doesn't add safety.
#![allow(clippy::borrow_as_ptr, clippy::ref_as_ptr)]

use serde_json::{Value, json};
use windows::Wdk::System::SystemServices::RtlGetVersion;
use windows::Win32::System::SystemInformation::{FIRMWARE_TYPE, GetFirmwareType, OSVERSIONINFOW};

// Win32 firmware-type enum values. The `windows` crate exposes the newtype
// `FIRMWARE_TYPE` but not individual constants at this path, so we mint
// them locally — they're stable values from the Windows SDK header
// `minwinbase.h`.
const FIRMWARE_TYPE_BIOS: FIRMWARE_TYPE = FIRMWARE_TYPE(1);
const FIRMWARE_TYPE_UEFI: FIRMWARE_TYPE = FIRMWARE_TYPE(2);

/// Returns `{major, minor, build}` as a JSON object. UBR is read from the
/// registry by the caller.
pub(super) fn rtl_get_version() -> Value {
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: u32::try_from(std::mem::size_of::<OSVERSIONINFOW>()).unwrap_or(0),
        ..Default::default()
    };
    // SAFETY: API writes into the struct through a raw pointer.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status.is_err() {
        return Value::Null;
    }
    json!({
        "major": info.dwMajorVersion,
        "minor": info.dwMinorVersion,
        "build": info.dwBuildNumber,
    })
}

/// Returns `"UEFI"`, `"BIOS"`, or `None`.
pub(super) fn firmware_type() -> Option<&'static str> {
    let mut ft = FIRMWARE_TYPE::default();
    // SAFETY: writes a single newtype-wrapped value.
    let ok = unsafe { GetFirmwareType(&mut ft) };
    if ok.is_err() {
        return None;
    }
    if ft == FIRMWARE_TYPE_UEFI {
        Some("UEFI")
    } else if ft == FIRMWARE_TYPE_BIOS {
        Some("BIOS")
    } else {
        None
    }
}
