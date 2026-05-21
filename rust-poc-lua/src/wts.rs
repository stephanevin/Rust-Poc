//! Windows Terminal Services (WTS) session enumeration.
//!
//! Wraps `WTSEnumerateSessionsW` + `WTSQuerySessionInformationW` from
//! `Wtsapi32.dll` — the same Win32 path taken by `Wtsapi32.GetSessions()`
//! in `ComplianceApp/components/Components.Windows/Win32Api/Wtsapi32.cs`.

// All Win32 out-params are `*mut T`; passing `&mut local` is the idiomatic
// Rust form and adding `addr_of_mut!` wrapping would obscure the intent.
#![allow(clippy::borrow_as_ptr, clippy::ref_as_ptr)]
//!
//! Output shape per session (mirrors `TerminalSessionDto` from ComplianceApp):
//! - `session_id`   — `WTS_SESSION_INFOW.SessionId` (`u32`)
//! - `station_name` — `WTS_SESSION_INFOW.pWinStationName` (e.g. `"Console"`, `"RDP-Tcp#0"`)
//! - `state`        — `WTS_CONNECTSTATE_CLASS` as string (e.g. `"Active"`, `"Disconnected"`)
//! - `user`         — `"DOMAIN\User"` assembled from `WTSUserName` + `WTSDomainName`, or `null`
//! - `sid`          — SID string (`"S-1-5-…"`) via `LookupAccountNameW`, or `null` on failure

use serde_json::{Value, json};
use windows::Win32::System::RemoteDesktop::{
    WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW,
    WTS_CONNECTSTATE_CLASS, WTS_INFO_CLASS, WTS_SESSION_INFOW,
};
use windows::core::PWSTR;

// WTS_INFO_CLASS constants not individually re-exported at a stable path in
// windows-rs 0.62; constructed from their numeric SDK values (stable).
const WTS_USER_NAME: WTS_INFO_CLASS = WTS_INFO_CLASS(5);
const WTS_DOMAIN_NAME: WTS_INFO_CLASS = WTS_INFO_CLASS(7);

/// Maps `WTS_CONNECTSTATE_CLASS` to its string representation.
///
/// Mirrors `WTS_CONNECTSTATE_CLASS.ToString()` from `ComplianceApp`
/// (enum member names correspond 1-to-1 with the underlying integer values).
fn state_label(state: WTS_CONNECTSTATE_CLASS) -> &'static str {
    match state.0 {
        0 => "Active",
        1 => "Connected",
        2 => "ConnectQuery",
        3 => "Shadow",
        4 => "Disconnected",
        5 => "Idle",
        6 => "Listen",
        7 => "Reset",
        8 => "Down",
        9 => "Init",
        _ => "Unknown",
    }
}

/// Queries a single string property for a WTS session and frees the buffer
/// before returning.
///
/// Returns `None` when the query fails or the buffer contains only the NUL
/// terminator (≤ 2 bytes — same guard as the C# reference:
/// `bytesReturned <= sizeof(char)`).
fn query_session_string(session_id: u32, info_class: WTS_INFO_CLASS) -> Option<String> {
    let mut buf = PWSTR(std::ptr::null_mut());
    let mut bytes: u32 = 0;
    // SAFETY: hServer = None → local machine. `buf` receives an opaque WTS
    // buffer that must be released with `WTSFreeMemory`.
    let ok = unsafe {
        WTSQuerySessionInformationW(None, session_id, info_class, &mut buf, &mut bytes)
    };
    // bytes <= 2: only the UTF-16 NUL terminator → effectively empty.
    if ok.is_err() || bytes <= 2 {
        return None;
    }
    // SAFETY: WTSQuerySessionInformationW filled `buf` with a valid
    // null-terminated UTF-16 string for the requested info class.
    let s = unsafe { buf.to_string() }.ok().filter(|s| !s.is_empty());
    // SAFETY: `buf` was allocated by WTSQuerySessionInformationW;
    // WTSFreeMemory is the documented release mechanism.
    unsafe { WTSFreeMemory(buf.0.cast()) };
    s
}

/// Attempts to resolve a `DOMAIN\User` account name to its SID string.
///
/// Mirrors `Wtsapi32.ResolveSid()` from `ComplianceApp`. For any interactively
/// logged-on user the name→SID mapping is cached in the local LSA at logon
/// time, so `LookupAccountNameW` succeeds without a domain controller.
///
/// Returns `None` on any failure (unknown account, marshalling error, etc.).
fn resolve_sid(account: &str) -> Option<String> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::core::{HSTRING, PCWSTR};

    let name = HSTRING::from(account);
    let mut sid_size: u32 = 0;
    let mut domain_size: u32 = 0;
    let mut sid_use = SID_NAME_USE::default();

    // First call: sizes only. Returns Err(ERROR_INSUFFICIENT_BUFFER);
    // we only care that sid_size is now nonzero.
    // SAFETY: null PSID and null PWSTR are valid for a size-probing call.
    unsafe {
        let _ = LookupAccountNameW(
            PCWSTR::null(),
            &name,
            None,
            &mut sid_size,
            Some(PWSTR::null()),
            &mut domain_size,
            &mut sid_use,
        );
    }
    if sid_size == 0 {
        return None;
    }

    let mut sid_buf = vec![0u8; sid_size as usize];
    let sid_ptr = PSID(sid_buf.as_mut_ptr().cast());
    let mut domain_buf = vec![0u16; domain_size as usize];

    // SAFETY: `sid_ptr` points to a valid buffer of `sid_size` bytes;
    // `domain_buf` has capacity for `domain_size` UTF-16 code units.
    let ok = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            &name,
            Some(sid_ptr),
            &mut sid_size,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_size,
            &mut sid_use,
        )
    };
    if ok.is_err() {
        return None;
    }

    let mut str_sid = PWSTR::null();
    // SAFETY: `sid_ptr` was filled by a successful LookupAccountNameW call
    // and is a valid SID; `str_sid` receives a LocalAlloc'd string.
    let ok = unsafe { ConvertSidToStringSidW(sid_ptr, &mut str_sid) };
    if ok.is_err() {
        return None;
    }

    // SAFETY: ConvertSidToStringSidW filled `str_sid` with a valid UTF-16
    // null-terminated string allocated with LocalAlloc.
    let result = unsafe { str_sid.to_string() }.ok();
    // SAFETY: `str_sid` was allocated by ConvertSidToStringSidW (LocalAlloc);
    // LocalFree is the documented release mechanism.
    unsafe { LocalFree(Some(HLOCAL(str_sid.0.cast()))) };
    result
}

/// Returns all WTS sessions on the local machine as a JSON array.
///
/// An empty `Vec` (not an error) is returned when enumeration succeeds but
/// there are no sessions — unusual in practice since session 0 (Services)
/// is always present.
///
/// # Errors
/// Returns a descriptive `String` when `WTSEnumerateSessionsW` fails,
/// including the Win32 error code for diagnostics.
pub(super) fn sessions() -> Result<Vec<Value>, String> {
    let mut p_sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count: u32 = 0;

    // SAFETY: hServer = None → local server. `p_sessions` receives an array
    // of `count` WTS_SESSION_INFOW structs allocated by WTSAPI; it must be
    // released with WTSFreeMemory after use.
    let ok =
        unsafe { WTSEnumerateSessionsW(None, 0, 1, &mut p_sessions, &mut count) };
    if ok.is_err() {
        // SAFETY: GetLastError is always safe to call immediately after a
        // failed Win32 API.
        let code = unsafe { windows::Win32::Foundation::GetLastError() }.0;
        return Err(format!("WTSEnumerateSessionsW failed: Win32 error {code}"));
    }

    let mut rows: Vec<Value> = Vec::with_capacity(count as usize);

    for i in 0..count {
        // SAFETY: `p_sessions` points to a contiguous array of `count`
        // WTS_SESSION_INFOW structs; index `i` is within bounds.
        let info = unsafe { &*p_sessions.add(i as usize) };

        let session_id = info.SessionId;

        // SAFETY: `pWinStationName` is a UTF-16 string pointer owned by the
        // WTS buffer (valid until WTSFreeMemory is called below).
        let station_name: Option<String> = unsafe { info.pWinStationName.to_string() }
            .ok()
            .filter(|s| !s.is_empty());

        let state = state_label(info.State);

        let user_name = query_session_string(session_id, WTS_USER_NAME);
        let domain_name = query_session_string(session_id, WTS_DOMAIN_NAME);

        let user: Option<String> = user_name.map(|u| match &domain_name {
            Some(d) if !d.is_empty() => format!("{d}\\{u}"),
            _ => u,
        });

        let sid: Option<String> = user.as_deref().and_then(resolve_sid);

        rows.push(json!({
            "session_id":   session_id,
            "station_name": station_name,
            "state":        state,
            "user":         user,
            "sid":          sid,
        }));
    }

    // SAFETY: `p_sessions` was allocated by WTSEnumerateSessionsW;
    // WTSFreeMemory is the documented release mechanism.
    unsafe { WTSFreeMemory(p_sessions.cast()) };

    Ok(rows)
}
