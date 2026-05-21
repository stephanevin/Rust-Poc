//! `RtlGetVersion` + `GetFirmwareType` + `GetProductInfo` + boot-time via
//! `NtQuerySystemInformation(SystemTimeOfDayInformation)`.

// All Win32/NT out-params are passed as `&mut local`. The `borrow_as_ptr`
// rewrite doesn't add safety.
#![allow(clippy::borrow_as_ptr, clippy::ref_as_ptr)]

use serde_json::{Value, json};
use windows::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemTimeOfDayInformation,
};
use windows::Wdk::System::SystemServices::RtlGetVersion;
use windows::Win32::System::SystemInformation::{
    FIRMWARE_TYPE, GetFirmwareType, GetProductInfo, OS_PRODUCT_TYPE, OSVERSIONINFOW,
};

// SYSTEM_TIMEOFDAY_INFORMATION is not exposed as a typed struct in windows-rs
// 0.62 — we define it locally.  Layout from `wdm.h` / `ntddk.h`:
//
//   LARGE_INTEGER BootTime         offset  0  (i64 / 100-ns FILETIME ticks from 1601-01-01)
//   LARGE_INTEGER CurrentTime      offset  8
//   LARGE_INTEGER TimeZoneBias     offset 16
//   ULONG         TimeZoneId       offset 24
//   ULONG         Reserved         offset 28
//   ULONGLONG     BootTimeBias     offset 32
//   ULONGLONG     SleepTimeBias    offset 40  (total: 48 bytes)
//
// We represent each LARGE_INTEGER as `i64` (its `QuadPart` union member) —
// same size (8) and alignment (8), so the C layout is preserved exactly.
#[repr(C)]
struct SystemTimeOfDayInfo {
    boot_time: i64,
    current_time: i64,
    time_zone_bias: i64,
    time_zone_id: u32,
    reserved: u32,
    boot_time_bias: u64,
    sleep_time_bias: u64,
}

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

/// Returns the OS product type from `GetProductInfo()`.
///
/// Mirrors `DataService.GetOSProduct()` from `ComplianceApp`, which calls
/// `GetProductInfo(major, minor, sp_major, sp_minor, &product_type)`.
/// The returned `u32` is the `PRODUCT_*` constant from `winnt.h`
/// (e.g. `4` = `PRODUCT_ENTERPRISE`, `48` = `PRODUCT_PROFESSIONAL`).
///
/// Returns `None` when `RtlGetVersion` fails or the API returns an
/// unusable value (`0` = indeterminate).
pub(super) fn product_sku() -> Option<u32> {
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: u32::try_from(std::mem::size_of::<OSVERSIONINFOW>()).unwrap_or(0),
        ..Default::default()
    };
    // SAFETY: API writes into the struct through a raw pointer.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status.is_err() {
        return None;
    }

    let mut product_type = OS_PRODUCT_TYPE(0);
    // SAFETY: `product_type` is a valid aligned newtype; GetProductInfo always
    // succeeds on Windows Vista+ given valid major/minor version values.
    let ok = unsafe {
        GetProductInfo(
            info.dwMajorVersion,
            info.dwMinorVersion,
            0, // SP major — always 0 on Windows 10+
            0, // SP minor
            &mut product_type,
        )
    };
    if ok.as_bool() && product_type.0 != 0 {
        Some(product_type.0)
    } else {
        None
    }
}

/// Converts a Windows FILETIME value (100-nanosecond ticks since
/// 1601-01-01 00:00:00 UTC) to an ISO 8601 datetime string
/// (`"YYYY-MM-DDTHH:MM:SSZ"`).
///
/// Returns `None` when `ticks` is zero, negative, or before the Unix epoch
/// (would require a date before 1970-01-01, which is valid FILETIME but
/// irrelevant for boot times on any Windows version).
///
/// No external crate dependency: the calendar arithmetic is from the
/// [Howard Hinnant civil-from-days algorithm](https://howardhinnant.github.io/date_algorithms.html#civil_from_days),
/// which is exact for the proleptic Gregorian calendar.
pub(crate) fn filetime_to_iso8601(ticks: i64) -> Option<String> {
    // 100-ns ticks between 1601-01-01 (FILETIME epoch) and 1970-01-01 (Unix).
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
    if ticks <= 0 {
        return None;
    }
    let unix_ticks = ticks.checked_sub(EPOCH_DIFF)?;
    if unix_ticks < 0 {
        return None;
    }
    let unix_secs = unix_ticks / 10_000_000;

    let sec = u32::try_from(unix_secs % 60).ok()?;
    let min = u32::try_from((unix_secs / 60) % 60).ok()?;
    let hour = u32::try_from((unix_secs / 3_600) % 24).ok()?;
    let days = unix_secs / 86_400; // days since 1970-01-01

    // Civil (Gregorian) date from day count — Howard Hinnant algorithm.
    // Shifts the epoch to 0000-03-01 so leap-year handling is uniform.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day of era [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).ok()?;
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).ok()?;
    let year = i32::try_from(if month <= 2 { y + 1 } else { y }).ok()?;

    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z"
    ))
}

/// Returns the last boot-up time as an ISO 8601 UTC string
/// (e.g. `"2026-05-21T08:14:32Z"`).
///
/// Uses `NtQuerySystemInformation(SystemTimeOfDayInformation)` — the kernel
/// source that `Win32_OperatingSystem.LastBootUpTime` (used by `ComplianceApp`)
/// reads internally. Unlike `GetTickCount64`, this timestamp correctly
/// accounts for time spent in sleep/hibernation.
///
/// Returns `None` when the NT call fails or the timestamp cannot be converted.
pub(super) fn last_boot_up_time() -> Option<String> {
    let mut info = SystemTimeOfDayInfo {
        boot_time: 0,
        current_time: 0,
        time_zone_bias: 0,
        time_zone_id: 0,
        reserved: 0,
        boot_time_bias: 0,
        sleep_time_bias: 0,
    };
    let size = u32::try_from(std::mem::size_of::<SystemTimeOfDayInfo>()).ok()?;
    let mut return_length: u32 = 0;

    // SAFETY: `info` is a repr(C) struct whose layout matches
    // SYSTEM_TIMEOFDAY_INFORMATION exactly; `size` is its byte length.
    // NtQuerySystemInformation fills `info` and writes the actual byte
    // count into `return_length`.
    let status = unsafe {
        NtQuerySystemInformation(
            SystemTimeOfDayInformation,
            std::ptr::addr_of_mut!(info).cast(),
            size,
            &mut return_length,
        )
    };
    if status.is_err() {
        return None;
    }

    filetime_to_iso8601(info.boot_time)
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

#[cfg(test)]
mod tests {
    use super::filetime_to_iso8601;

    // Known FILETIME vectors computed independently:
    //   Python: datetime.datetime(y,m,d,h,mi,s, tzinfo=datetime.timezone.utc)
    //           → int((dt - datetime.datetime(1601,1,1,tzinfo=datetime.timezone.utc)).total_seconds() * 10_000_000)
    //
    // Guard against regression in the Howard Hinnant civil_from_days port.

    #[test]
    fn unix_epoch_is_known_filetime() {
        // 1970-01-01T00:00:00Z  →  116_444_736_000_000_000 ticks
        assert_eq!(
            filetime_to_iso8601(116_444_736_000_000_000),
            Some("1970-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn known_datetime_roundtrips() {
        // 2026-05-21T10:30:00Z
        // unix_secs = 1_779_359_400
        // filetime  = 1_779_359_400 × 10_000_000 + 116_444_736_000_000_000
        //           = 134_238_330_000_000_000
        assert_eq!(
            filetime_to_iso8601(134_238_330_000_000_000),
            Some("2026-05-21T10:30:00Z".to_string())
        );
    }

    #[test]
    fn leap_day_roundtrips() {
        // 2000-02-29T12:00:00Z — leap day in a century-divisible year
        // unix_secs = 951_825_600
        // filetime  = 951_825_600 × 10_000_000 + 116_444_736_000_000_000
        //           = 125_962_992_000_000_000
        assert_eq!(
            filetime_to_iso8601(125_962_992_000_000_000),
            Some("2000-02-29T12:00:00Z".to_string())
        );
    }

    #[test]
    fn y2038_boundary_roundtrips() {
        // 2038-01-19T03:14:07Z — last second representable in i32 unix time
        // unix_secs = 2_147_483_647
        // filetime  = 2_147_483_647 × 10_000_000 + 116_444_736_000_000_000
        //           = 137_919_572_470_000_000
        assert_eq!(
            filetime_to_iso8601(137_919_572_470_000_000),
            Some("2038-01-19T03:14:07Z".to_string())
        );
    }

    #[test]
    fn zero_returns_none() {
        assert_eq!(filetime_to_iso8601(0), None);
    }

    #[test]
    fn negative_returns_none() {
        assert_eq!(filetime_to_iso8601(-1), None);
    }

    #[test]
    fn pre_unix_epoch_returns_none() {
        // 1969-12-31T23:59:59Z — one second before Unix epoch
        // filetime = 116_444_735_990_000_000
        assert_eq!(filetime_to_iso8601(116_444_735_990_000_000), None);
    }
}
