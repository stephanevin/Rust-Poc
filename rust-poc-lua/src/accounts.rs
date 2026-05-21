//! Windows Accounts host bindings.
//!
//! Three `pub(super)` functions mirror the Accounts section of `ComplianceApp`:
//!
//! | Function | C# Transformer | Win32 source |
//! |---|---|---|
//! | [`user_profiles`] | `UserProfiles.cs` | Registry `ProfileList\*` + `LookupAccountSidW` |
//! | [`local_user_accounts`] | `LocalAccountsUsers.cs` | `NetUserEnum(level=0)` + `NetUserGetInfo(level=4)` |
//! | [`local_group_members`] | `LocalAccountsAdminMembers.cs` / `LocalAccountsRdpMembers.cs` | `LookupAccountSidW` + `NetLocalGroupGetMembers(level=2)` |
//!
//! ## Two-call pattern (Win32 `NetAPI`)
//!
//! `NetUserEnum` and `NetLocalGroupGetMembers` are called once with
//! `MAX_PREFERRED_LENGTH` (`0xFFFF_FFFF`): the API allocates as much memory as
//! it needs and writes the pointer into the caller-supplied out-param. The RAII
//! [`NetBuf`] guard ensures `NetApiBufferFree` fires on every code path
//! (success, early return, panic). See
//! [Rust Book ch. 15.3](https://doc.rust-lang.org/book/ch15-03-drop.html) for
//! the `Drop` idiom.
//!
//! ## Why `NetUserGetInfo(level=4)` and not `level=3`
//!
//! `USER_INFO_4` (Windows XP+) adds `usri4_user_sid: PSID` — the account SID
//! embedded directly in the struct, removing the need for a separate
//! `LookupAccountNameW` call. `USER_INFO_3` only carries `usri3_user_id: DWORD`
//! (the relative identifier, not the full SID). MSDN: *"The `USER_INFO_4`
//! structure supersedes `USER_INFO_3` on Windows XP and later."*

// Registry & Win32 out-params are passed as `&mut local` — the alternative
// `addr_of_mut!` wrapping adds noise without improving safety inside these
// `unsafe` blocks.
#![allow(clippy::borrow_as_ptr, clippy::ref_as_ptr)]

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_MEMBERS_INFO_2, NET_USER_ENUM_FILTER_FLAGS, NetApiBufferFree,
    NetLocalGroupGetMembers, NetUserEnum, NetUserGetInfo, USER_INFO_0, USER_INFO_4,
};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};
use windows::core::{HSTRING, PCWSTR, PWSTR};

// --- SDK constants not individually re-exported by windows-rs 0.62 -------

/// Enumerate standard (interactive) user accounts only. Excludes computer
/// accounts, interdomain trust accounts, and workstation trust accounts.
const FILTER_NORMAL_ACCOUNT: NET_USER_ENUM_FILTER_FLAGS = NET_USER_ENUM_FILTER_FLAGS(0x0002);

/// Instruct `NetAPI` to allocate as much memory as needed.
const MAX_PREFERRED_LENGTH: u32 = 0xFFFF_FFFF;

// `USER_ACCOUNT_FLAGS` bit constants (stable Win32 SDK values).
const UF_ACCOUNTDISABLE: u32 = 0x0002;
const UF_LOCKOUT: u32 = 0x0010;
const UF_PASSWD_NOTREQD: u32 = 0x0020;
const UF_PASSWD_CANT_CHANGE: u32 = 0x0040;
const UF_DONT_EXPIRE_PASSWD: u32 = 0x0001_0000;

// System account SIDs that appear in ProfileList but own no real home
// directory.  Matches the filter applied by ComplianceApp's `UserProfiles.cs`.
const SYSTEM_SIDS: [&str; 3] = ["S-1-5-18", "S-1-5-19", "S-1-5-20"];

// --- RAII guard for NetAPI-allocated buffers -----------------------------

/// Owns a raw byte buffer allocated by a `NetAPI` function and calls
/// `NetApiBufferFree` in `Drop`, guaranteeing the buffer is always released
/// even on early returns or panics.
struct NetBuf(*mut u8);

impl Drop for NetBuf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by a NetAPI function (NetUserEnum,
            // NetUserGetInfo, NetLocalGroupGetMembers).  `NetApiBufferFree` is
            // the documented, and only, release mechanism for these buffers.
            unsafe {
                NetApiBufferFree(Some(self.0.cast()));
            }
        }
    }
}


// --- Internal helpers ----------------------------------------------------

/// Helper: reads a DWORD registry value and returns it as `u32`.
fn read_u32(hive: &str, key: &str, value: &str) -> Option<u32> {
    match super::registry::read(hive, key, value) {
        Ok(Some(Value::Number(n))) => n.as_u64().and_then(|v| u32::try_from(v).ok()),
        _ => None,
    }
}

/// Helper: reads a `REG_SZ` / `REG_EXPAND_SZ` registry value as a String.
fn read_str(hive: &str, key: &str, value: &str) -> Option<String> {
    match super::registry::read(hive, key, value) {
        Ok(Some(Value::String(s))) => Some(s),
        _ => None,
    }
}

/// Converts a Windows FILETIME stored as two DWORD (high word + low word)
/// registry values into an ISO 8601 UTC string.
///
/// Returns `None` when either DWORD is absent or the combined value is zero
/// (i.e. the timestamp was never recorded).
///
/// The combination is done in `u64` to avoid signed-integer overflow when the
/// high DWORD has bit 31 set (≥ `0x8000_0000`), then narrowed to `i64` before
/// passing to `filetime_to_iso8601`. All representable FILETIME values for
/// real-world dates fit in `i64` (max year ≈ 30 000).
fn dword_filetime_to_iso(high: Option<u32>, low: Option<u32>) -> Option<String> {
    let ticks_u64 = (u64::from(high?) << 32) | u64::from(low?);
    let ticks = i64::try_from(ticks_u64).ok()?;
    super::winver::filetime_to_iso8601(ticks)
}

/// Converts a `NetAPI` Unix timestamp (`u32` seconds since 1970-01-01) to an
/// ISO 8601 UTC string.
///
/// Returns `None` for the two sentinel values used by the `NetAPI`:
/// - `0`           — the time is unknown / has never occurred.
/// - `0xFFFF_FFFF` — the value is "unlimited" or "never" (used for expiry).
fn unix_u32_to_iso(secs: u32) -> Option<String> {
    // FILETIME epoch is 1601-01-01; Unix epoch is 1970-01-01.
    // Offset = 11_644_473_600 seconds.
    const EPOCH_DIFF: i64 = 11_644_473_600;

    if secs == 0 || secs == 0xFFFF_FFFF {
        return None;
    }
    let filetime_secs = i64::from(secs).checked_add(EPOCH_DIFF)?;
    let ticks = filetime_secs.checked_mul(10_000_000)?;
    super::winver::filetime_to_iso8601(ticks)
}

/// Returns the current time as Unix seconds (`u32`), or `None` on the
/// (extremely unlikely) overflow past year 2106.
fn now_unix_secs() -> Option<u32> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u32::try_from(d.as_secs()).ok())
}

/// Converts a `PSID` to its canonical string representation (`"S-1-5-..."`).
///
/// # Safety
///
/// `sid` must be a valid, fully-initialized SID that remains live for the
/// duration of this call.  The `LocalAlloc`'d output buffer from
/// `ConvertSidToStringSidW` is freed before returning.
unsafe fn psid_to_string(sid: PSID) -> Option<String> {
    if sid.is_invalid() {
        return None;
    }
    let mut str_sid = PWSTR::null();
    // SAFETY: `sid` is a valid SID per the caller's contract; `str_sid`
    // receives a LocalAlloc'd NUL-terminated UTF-16 string.
    if unsafe { ConvertSidToStringSidW(sid, &mut str_sid) }.is_err() {
        return None;
    }
    // SAFETY: filled by ConvertSidToStringSidW with a valid UTF-16 string.
    let result = unsafe { str_sid.to_string() }.ok();
    // SAFETY: `str_sid` was allocated by ConvertSidToStringSidW via LocalAlloc;
    // LocalFree is the documented release mechanism.
    unsafe { LocalFree(Some(HLOCAL(str_sid.0.cast()))) };
    result
}

/// Resolves a SID string (e.g. `"S-1-5-21-..."`) to a `"DOMAIN\\Name"`
/// account name via `ConvertStringSidToSidW` + `LookupAccountSidW`.
///
/// Returns `None` when the SID is malformed or does not map to any account
/// (deleted user, unknown SID, etc.).
fn sid_string_to_nt_account(sid_str: &str) -> Option<String> {
    let sid_h = HSTRING::from(sid_str);
    let mut psid = PSID::default();
    // SAFETY: `sid_h` is a valid NUL-terminated UTF-16 string; `psid` receives
    // a LocalAlloc'd SID on success.
    let ok = unsafe { ConvertStringSidToSidW(PCWSTR(sid_h.as_ptr()), &mut psid) };
    if ok.is_err() || psid.is_invalid() {
        return None;
    }
    let result = lookup_sid_name(psid);
    // SAFETY: `psid` was allocated by ConvertStringSidToSidW (LocalAlloc).
    unsafe { LocalFree(Some(HLOCAL(psid.0.cast()))) };
    result
}

/// Calls `LookupAccountSidW` for an already-allocated `PSID` and returns
/// `"DOMAIN\\Name"`, or `None` on any failure.
///
/// Uses the two-call sizing pattern: first call with null buffers to obtain
/// required lengths, second call with correctly-sized buffers.
fn lookup_sid_name(psid: PSID) -> Option<String> {
    let mut name_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut sid_use = SID_NAME_USE::default();

    // Size-probe: pass None for both output buffers.  The API returns
    // ERROR_INSUFFICIENT_BUFFER but writes the required lengths.
    // SAFETY: PSID is valid; null output pointers are explicitly documented
    // as accepted for the probe call.
    unsafe {
        let _ = LookupAccountSidW(
            PCWSTR::null(),
            psid,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut sid_use,
        );
    }
    if name_len == 0 {
        return None;
    }

    let mut name_buf = vec![0u16; name_len as usize];
    let mut domain_buf = vec![0u16; domain_len as usize];

    // SAFETY: buffers have the lengths demanded by the probe call.
    let ok = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            psid,
            Some(PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if ok.is_err() {
        return None;
    }

    // After a successful call, `name_len` / `domain_len` are the character
    // counts *excluding* the NUL terminator.
    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);

    if name.is_empty() {
        None
    } else if domain.is_empty() {
        Some(name)
    } else {
        Some(format!("{domain}\\{name}"))
    }
}

/// Maps a `SID_NAME_USE` integer to its human-readable label.
///
/// Values mirror the `SidType` enum in `ComplianceApp` and the Win32 SDK
/// `SID_NAME_USE` enumeration (winnt.h).
///
/// The SDK value 8 (`SidTypeUnknown`) and any out-of-range code both map to
/// `"Unknown"` — they are handled by the wildcard arm since they produce the
/// same output.
fn sid_name_use_label(code: i32) -> &'static str {
    match code {
        1 => "User",
        2 => "Group",
        3 => "Domain",
        4 => "Alias",
        5 => "WellKnownGroup",
        6 => "DeletedAccount",
        7 => "Invalid",
        9 => "Computer",
        10 => "Label",
        11 => "LogonSession",
        _ => "Unknown",
    }
}

// --- Shared helpers (pub(crate)) -----------------------------------------

/// Expands `%VARNAME%` placeholders in a Windows registry path string.
///
/// Delegates to [`std::env::var`], which calls `GetEnvironmentVariableW` on
/// Windows — the lookup is therefore **case-insensitive** (`%systemroot%` and
/// `%SystemRoot%` both resolve).  Unknown variable names are left unexpanded.
/// Returns the original string unchanged when it contains no `%` characters
/// (fast path).
fn expand_env_vars(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let mut result = s.to_string();
    // Guard against infinite loops on pathological inputs (nested / unclosed).
    for _ in 0..16 {
        let Some(start) = result.find('%') else { break };
        let after = &result[start + 1..];
        let Some(rel_end) = after.find('%') else { break };
        let var_name = &after[..rel_end];
        if var_name.is_empty() {
            break;
        }
        match std::env::var(var_name) {
            Ok(value) => {
                let placeholder = format!("%{var_name}%");
                result = result.replacen(&placeholder, &value, 1);
            }
            Err(_) => break,
        }
    }
    result
}

/// Returns all domain user profiles registered in
/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
/// as `(sid, nt_account, profile_image_path)` tuples.
///
/// Filters out well-known system SIDs (`S-1-5-18/19/20`) and entries without
/// a `ProfileImagePath`.  This is the minimal profile data consumed by
/// `software::browser_extensions_installed` and `software::ide_extensions_installed`.
///
/// Returns an empty `Vec` when the key is absent.
pub(crate) fn profile_list() -> Vec<(String, String, std::path::PathBuf)> {
    const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    let sids = super::registry::subkey_names("HKLM", PROFILE_LIST);
    let mut result = Vec::with_capacity(sids.len());

    for sid in &sids {
        if SYSTEM_SIDS.contains(&sid.as_str()) {
            continue;
        }
        let key = format!("{PROFILE_LIST}\\{sid}");
        let Some(path_str) = read_str("HKLM", &key, "ProfileImagePath") else {
            continue;
        };
        let nt_account = sid_string_to_nt_account(sid).unwrap_or_default();
        let expanded = expand_env_vars(&path_str);
        result.push((sid.clone(), nt_account, std::path::PathBuf::from(expanded)));
    }

    result
}

// --- Public bindings -----------------------------------------------------

/// Returns all Windows user profiles registered in
/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`.
///
/// Each entry mirrors `UserProfileDto` from `ComplianceApp`:
/// - `sid`                       — SID string (subkey name)
/// - `nt_account`                — `"DOMAIN\\Name"` resolved via `LookupAccountSidW`, or `null`
/// - `profile_image_path`        — raw `ProfileImagePath` value (may contain `%systemroot%`)
/// - `local_profile_load_time`   — ISO 8601 UTC string, or `null` if not recorded
/// - `local_profile_unload_time` — ISO 8601 UTC string, or `null` if not recorded
///
/// System accounts (`S-1-5-18`, `S-1-5-19`, `S-1-5-20`) and entries without
/// a `ProfileImagePath` are silently excluded — same filter as `UserProfiles.cs`.
///
/// Returns an empty `Vec` when the key is absent (e.g. fresh container image).
///
/// # Examples
///
/// ```ignore
/// let profiles = user_profiles();
/// // [{"sid": "S-1-5-21-...", "nt_account": "DOMAIN\\Alice", ...}, ...]
/// ```
#[must_use]
pub(super) fn user_profiles() -> Vec<Value> {
    const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    let sids = super::registry::subkey_names("HKLM", PROFILE_LIST);
    let mut result = Vec::with_capacity(sids.len());

    for sid in &sids {
        // Skip well-known system accounts that have no real home directory.
        if SYSTEM_SIDS.contains(&sid.as_str()) {
            continue;
        }

        let key = format!("{PROFILE_LIST}\\{sid}");

        let Some(profile_image_path) = read_str("HKLM", &key, "ProfileImagePath") else {
            // Boot-tracking entries have no ProfileImagePath — skip them.
            continue;
        };

        let nt_account = sid_string_to_nt_account(sid);

        let load_high = read_u32("HKLM", &key, "LocalProfileLoadTimeHigh");
        let load_low = read_u32("HKLM", &key, "LocalProfileLoadTimeLow");
        let unload_high = read_u32("HKLM", &key, "LocalProfileUnloadTimeHigh");
        let unload_low = read_u32("HKLM", &key, "LocalProfileUnloadTimeLow");

        result.push(json!({
            "sid":                       sid,
            "nt_account":                nt_account,
            "profile_image_path":        profile_image_path,
            "local_profile_load_time":   dword_filetime_to_iso(load_high, load_low),
            "local_profile_unload_time": dword_filetime_to_iso(unload_high, unload_low),
        }));
    }

    result
}

/// Returns local user accounts on the machine via `NetUserEnum(level=0)` +
/// `NetUserGetInfo(level=4)`.
///
/// Each entry mirrors `LocalUserAccountDto` from `ComplianceApp`:
/// - `name`                     — account name (e.g. `"Administrator"`)
/// - `full_name`                — display name (may be empty)
/// - `description`              — user comment / description
/// - `domain`                   — machine hostname (all local accounts belong to the machine domain)
/// - `sid`                      — `"S-1-5-21-..."` from `usri4_user_sid` (direct PSID, no extra lookup)
/// - `disabled`                 — `UF_ACCOUNTDISABLE` flag
/// - `lockout`                  — `UF_LOCKOUT` flag
/// - `password_not_required`    — `UF_PASSWD_NOTREQD` flag
/// - `password_never_expires`   — `UF_DONT_EXPIRE_PASSWD` flag
/// - `user_cannot_change_password` — `UF_PASSWD_CANT_CHANGE` flag
/// - `password_expires`         — `usri4_password_expired != 0`
/// - `bad_logon_count`          — `usri4_bad_pw_count`
/// - `last_logon`               — ISO 8601 UTC, or `null` (0 = never / unknown)
/// - `account_expiration_date`  — ISO 8601 UTC, or `null` (0xFFFFFFFF = never)
/// - `last_password_set`        — ISO 8601 UTC derived from `now − usri4_password_age`
///
/// **Omitted vs. C# reference**: `AccountLockoutTime` and `LastBadPasswordAttempt`
/// require the SAM API (no official windows-rs bindings); `PasswordChangeable`
/// is WMI-specific.  All three are out of scope for this Win32-only binding.
///
/// Returns an empty `Vec` on `NetUserEnum` failure (error is propagated to the
/// caller, not silently swallowed — the caller records it in `host.errors()`).
///
/// # Errors
///
/// Returns a descriptive `String` when `NetUserEnum` fails.
#[must_use = "caller must surface errors via host.errors()"]
pub(super) fn local_user_accounts() -> Result<Vec<Value>, String> {
    let mut buf_ptr: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    // SAFETY: servername = PCWSTR::null() → local machine.  `buf_ptr`
    // receives a NetAPI-allocated array of `entries_read` USER_INFO_0 structs
    // that must be freed with `NetApiBufferFree`.
    let rc = unsafe {
        NetUserEnum(
            PCWSTR::null(),
            0,
            FILTER_NORMAL_ACCOUNT,
            &raw mut buf_ptr,
            MAX_PREFERRED_LENGTH,
            &raw mut entries_read,
            &raw mut total_entries,
            None,
        )
    };
    if rc != 0 {
        // rc may be a NERR_* code or a Win32 error (e.g. ERROR_ACCESS_DENIED = 5).
        return Err(format!("NetUserEnum failed: error code {rc}"));
    }

    // Guard takes ownership; NetApiBufferFree fires when `_enum_buf` drops.
    let _enum_buf = NetBuf(buf_ptr);

    // Determine the machine hostname for the `domain` field (all local accounts
    // belong to the machine's own "domain", i.e. the NetBIOS machine name).
    let machine_name = super::hostname::netbios_name().unwrap_or_else(|_| String::new());

    let mut result = Vec::with_capacity(entries_read as usize);

    for i in 0..entries_read {
        // SAFETY: `buf_ptr` points to a contiguous array of `entries_read`
        // USER_INFO_0 structs; index `i` is within bounds.  NetAPI guarantees
        // the buffer is suitably aligned for USER_INFO_0.
        #[allow(clippy::cast_ptr_alignment)]
        let info0 = unsafe { &*(buf_ptr.cast::<USER_INFO_0>().add(i as usize)) };

        // SAFETY: `usri0_name` is a valid NUL-terminated UTF-16 string owned
        // by the NetAPI buffer (valid until `_enum_buf` drops below).
        let name: String = match unsafe { info0.usri0_name.to_string() } {
            Ok(s) if !s.is_empty() => s,
            _ => continue,
        };

        // Fetch level-4 detail for this specific user.
        let mut detail_ptr: *mut u8 = std::ptr::null_mut();
        let username_h = HSTRING::from(name.as_str());
        // SAFETY: servername null → local machine; username_h is a valid
        // wide string; detail_ptr receives a USER_INFO_4 struct on success.
        let rc4 = unsafe {
            NetUserGetInfo(
                PCWSTR::null(),
                PCWSTR(username_h.as_ptr()),
                4,
                &raw mut detail_ptr,
            )
        };
        if rc4 != 0 || detail_ptr.is_null() {
            tracing::warn!(
                user = %name,
                error_code = rc4,
                "NetUserGetInfo(level=4) failed — user omitted from local_user_accounts"
            );
            continue;
        }
        let _detail_buf = NetBuf(detail_ptr);

        // SAFETY: detail_ptr is non-null and the API guarantees a valid
        // USER_INFO_4 struct at this address for a successful level-4 query.
        // NetAPI guarantees the buffer is suitably aligned for USER_INFO_4.
        #[allow(clippy::cast_ptr_alignment)]
        let ui4 = unsafe { &*(detail_ptr.cast::<USER_INFO_4>()) };

        let flags = ui4.usri4_flags.0;
        let disabled = flags & UF_ACCOUNTDISABLE != 0;
        let lockout = flags & UF_LOCKOUT != 0;
        let pwd_notreq = flags & UF_PASSWD_NOTREQD != 0;
        let no_expire = flags & UF_DONT_EXPIRE_PASSWD != 0;
        let cant_change = flags & UF_PASSWD_CANT_CHANGE != 0;

        let full_name = unsafe { ui4.usri4_full_name.to_string() }
            .ok()
            .filter(|s| !s.is_empty());
        let description = unsafe { ui4.usri4_comment.to_string() }
            .ok()
            .filter(|s| !s.is_empty());

        // SAFETY: `usri4_user_sid` is a valid PSID embedded in the
        // USER_INFO_4 struct, valid until `_detail_buf` drops.
        let sid = unsafe { psid_to_string(ui4.usri4_user_sid) };

        let last_logon = unix_u32_to_iso(ui4.usri4_last_logon);
        let account_expiration_date = unix_u32_to_iso(ui4.usri4_acct_expires);

        // `password_age` is seconds since the password was last changed.
        // Subtract from current time to derive an absolute timestamp.
        let last_password_set = now_unix_secs()
            .and_then(|now| now.checked_sub(ui4.usri4_password_age))
            .and_then(unix_u32_to_iso);

        result.push(json!({
            "name":                         name,
            "full_name":                    full_name,
            "description":                  description,
            "domain":                       machine_name,
            "sid":                          sid,
            "disabled":                     disabled,
            "lockout":                      lockout,
            "password_not_required":        pwd_notreq,
            "password_never_expires":       no_expire,
            "user_cannot_change_password":  cant_change,
            "password_expires":             ui4.usri4_password_expired != 0,
            "bad_logon_count":              ui4.usri4_bad_pw_count,
            "last_logon":                   last_logon,
            "account_expiration_date":      account_expiration_date,
            "last_password_set":            last_password_set,
        }));
    }

    Ok(result)
}

/// Returns members of the local group identified by `group_sid` (a SID string
/// such as `"S-1-5-32-544"` for Administrators or `"S-1-5-32-555"` for
/// Remote Desktop Users).
///
/// Steps:
/// 1. `ConvertStringSidToSidW` → binary SID of the group.
/// 2. `LookupAccountSidW` → group name (e.g. `"Administrators"`).
/// 3. `NetLocalGroupGetMembers(level=2)` → `LOCALGROUP_MEMBERS_INFO_2[]`.
///
/// Each entry mirrors `LocalGroupMemberDto` from `ComplianceApp`:
/// - `name`          — account name from `lgrmi2_domainandname` (part after `\`)
/// - `domain`        — domain part (part before `\`)
/// - `caption`       — full `"DOMAIN\\Name"` string from the API
/// - `sid`           — `"S-1-5-..."` from `lgrmi2_sid` via `ConvertSidToStringSidW`
/// - `sid_type`      — `lgrmi2_sidusage` as string (`"User"`, `"Group"`, `"Alias"`, …)
/// - `local_account` — `true` when `domain` matches the local machine name
///
/// **Omitted vs. C# reference**: `description` and `status` require an extra
/// `NetUserGetInfo(level=1)` call per member; omitted for this `PoC`.
///
/// Returns an empty `Vec` when the group has no members or `group_sid` cannot
/// be resolved to a group name.
///
/// # Errors
///
/// Returns a descriptive `String` when `NetLocalGroupGetMembers` fails.
#[must_use = "caller must surface errors via host.errors()"]
pub(super) fn local_group_members(group_sid: &str) -> Result<Vec<Value>, String> {
    // Step 1 + 2: SID string → group name.
    let group_name = match sid_string_to_nt_account(group_sid) {
        Some(qualified) => {
            // LookupAccountSidW returns "DOMAIN\Name"; we only want the name
            // part for NetLocalGroupGetMembers.
            if let Some(pos) = qualified.find('\\') {
                qualified[pos + 1..].to_string()
            } else {
                qualified
            }
        }
        None => {
            return Err(format!(
                "local_group_members: cannot resolve group SID {group_sid}"
            ));
        }
    };

    let machine_name = super::hostname::netbios_name().unwrap_or_else(|_| String::new());

    let group_h = HSTRING::from(group_name.as_str());
    let mut buf_ptr: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    // SAFETY: servername = PCWSTR::null() → local machine.  `buf_ptr`
    // receives a NetAPI-allocated array of `entries_read`
    // LOCALGROUP_MEMBERS_INFO_2 structs on success.
    let rc = unsafe {
        NetLocalGroupGetMembers(
            PCWSTR::null(),
            PCWSTR(group_h.as_ptr()),
            2,
            &raw mut buf_ptr,
            MAX_PREFERRED_LENGTH,
            &raw mut entries_read,
            &raw mut total_entries,
            None,
        )
    };
    if rc != 0 {
        return Err(format!(
            // rc may be a NERR_* code or a Win32 error (e.g. ERROR_ACCESS_DENIED = 5).
            "NetLocalGroupGetMembers({group_name}) failed: error code {rc}"
        ));
    }

    let _members_buf = NetBuf(buf_ptr);
    let mut result = Vec::with_capacity(entries_read as usize);

    for i in 0..entries_read {
        // SAFETY: `buf_ptr` points to a contiguous array of `entries_read`
        // LOCALGROUP_MEMBERS_INFO_2 structs; index `i` is within bounds.
        // NetAPI guarantees the buffer is suitably aligned for
        // LOCALGROUP_MEMBERS_INFO_2.
        #[allow(clippy::cast_ptr_alignment)]
        let m = unsafe { &*(buf_ptr.cast::<LOCALGROUP_MEMBERS_INFO_2>().add(i as usize)) };

        // `lgrmi2_domainandname` is "DOMAIN\Name" or just "Name" (e.g. for
        // built-in accounts that have no domain prefix).
        let caption: Option<String> = unsafe { m.lgrmi2_domainandname.to_string() }
            .ok()
            .filter(|s| !s.is_empty());

        let (domain, name) = match &caption {
            Some(c) => {
                if let Some(pos) = c.find('\\') {
                    (Some(c[..pos].to_string()), c[pos + 1..].to_string())
                } else {
                    (None, c.clone())
                }
            }
            None => (None, String::new()),
        };

        // SAFETY: `lgrmi2_sid` is a valid PSID embedded in the
        // LOCALGROUP_MEMBERS_INFO_2 struct, valid until `_members_buf` drops.
        let sid = unsafe { psid_to_string(m.lgrmi2_sid) };

        let sid_type = sid_name_use_label(m.lgrmi2_sidusage.0);

        let local_account = domain
            .as_deref()
            .is_some_and(|d| d.eq_ignore_ascii_case(&machine_name));

        result.push(json!({
            "name":          name,
            "domain":        domain,
            "caption":       caption,
            "sid":           sid,
            "sid_type":      sid_type,
            "local_account": local_account,
        }));
    }

    Ok(result)
}
