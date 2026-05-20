//! Active Directory computer-object attributes via Win32 security APIs.
//!
//! Exposes four functions, each resolving a different AD attribute of the
//! local computer account:
//!
//! | Function             | Win32 source                                           | Example (domain-joined)                            |
//! |----------------------|--------------------------------------------------------|----------------------------------------------------|
//! | [`sam_name`]         | `GetComputerObjectNameW(NameSamCompatible)`            | `PHARMA\E00AVDDWDEV0271$`                          |
//! | [`distinguished_name`] | `GetComputerObjectNameW(NameFullyQualifiedDN)`       | `CN=E00AVDDWDEV0271,OU=WAAS,...,DC=com`            |
//! | [`canonical_name`]   | `GetComputerObjectNameW(NameCanonical)`                | `pharma.aventis.com/ZZ NGDC EMEA/.../...`          |
//! | [`site_name`]        | `DsGetSiteNameW`                                       | `IE-AZU02`                                         |
//!
//! ## Fault tolerance (two-tier, mirrors `ActiveDirectory.cs` in `ComplianceApp`)
//!
//! **Tier 1 — Win32 cache**: `GetComputerObjectNameW` and `DsGetSiteNameW`
//! read from Netlogon's local cache. No network call is required as long as
//! the machine authenticated to a DC at some point in the current or a
//! previous session. On a workgroup machine or before the first Netlogon
//! authentication, both APIs fail with `ERROR_NONE_MAPPED` or equivalent.
//!
//! **Tier 2 — GP State Machine registry**: for [`distinguished_name`] and
//! [`site_name`] only (the C# has no registry fallback for SAM or CN either).
//! Group Policy writes the computer DN and site name into:
//! `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine`
//! — values `Distinguished-Name` and `Site-Name`. These survive reboots and
//! network disconnections, and are available as long as at least one GP cycle
//! ran since domain join.
//!
//! **Tier 3 — LDAP (`DirectorySearcher`)**: intentionally absent. The C#
//! uses this as an intermediate fallback but it requires an active LDAP
//! network connection. Consistent with the rest of this crate, any
//! unavailability beyond the local cache produces `nil` + an entry in
//! `host.errors()`.
//!
//! ## Deviation from upstream
//!
//! This module is a **deviation** from the verbatim port of
//! `sdh-fleet-client/lua/` — upstream does not expose these bindings.
//! See `CLAUDE.md` § *Deviations* #7 for rationale and re-sync guidance.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
use windows::Win32::Networking::ActiveDirectory::DsGetSiteNameW;
use windows::Win32::Security::Authentication::Identity::{
    EXTENDED_NAME_FORMAT, GetComputerObjectNameW, NameCanonical, NameFullyQualifiedDN,
    NameSamCompatible,
};
use windows::core::{PCWSTR, PWSTR};

/// Two-call sizing pattern for `GetComputerObjectNameW`, parameterised by
/// `format`.
///
/// Unlike `GetComputerNameExW` (which writes into a caller-supplied buffer),
/// `GetComputerObjectNameW` follows the same documented convention:
///
/// 1. First call with `None` buffer — returns `false` (buffer too small) and
///    writes the required character count (including trailing NUL) into
///    `nSize`.
/// 2. Allocate `Vec<u16>` of that length and call again. On success `nSize`
///    is updated to the character count **without** the NUL.
///
/// Requires Netlogon's local cache to be populated. Fails with
/// `ERROR_NONE_MAPPED` on workgroup machines or before the first
/// DC authentication.
fn get_object_name(format: EXTENDED_NAME_FORMAT) -> Result<String, String> {
    let mut size: u32 = 0;

    // SAFETY: sizing probe with NULL buffer is the documented way to learn
    // the required length. The function returns `false` and writes the
    // required size (including NUL) into `size`. `&raw mut size` avoids the
    // strict aliasing footgun flagged by `clippy::borrow_as_ptr` at FFI
    // boundaries (same rationale as in hostname.rs).
    unsafe {
        let _ = GetComputerObjectNameW(format, None, &raw mut size);
    }

    if size == 0 {
        return Err(format!(
            "GetComputerObjectNameW({format:?}): sizing probe returned size=0 \
             (machine may not be domain-joined)"
        ));
    }

    let mut buf = vec![0u16; size as usize];

    // SAFETY: `buf` holds exactly `size` WCHARs as reported by the sizing
    // probe. On success `size` is overwritten with the length WITHOUT the
    // trailing NUL — truncate before decoding.
    let ok = unsafe {
        GetComputerObjectNameW(format, Some(PWSTR(buf.as_mut_ptr())), &raw mut size)
    };
    if !ok {
        // SAFETY: called immediately after the failed Win32 function, on the
        // same thread, so `from_thread()` captures the correct last-error.
        return Err(format!(
            "GetComputerObjectNameW({format:?}): {}",
            windows::core::Error::from_thread()
        ));
    }

    buf.truncate(size as usize);
    // Unlike GetComputerNameExW (which reports the count *without* the NUL
    // on success), GetComputerObjectNameW may report the count *including*
    // the NUL. Strip any trailing NUL defensively so callers get a clean
    // string regardless of which convention the runtime uses.
    while buf.last() == Some(&0u16) {
        buf.pop();
    }
    OsString::from_wide(&buf)
        .into_string()
        .map_err(|_| format!("GetComputerObjectNameW({format:?}): result is not valid UTF-8"))
}

/// Reads a string value from the Group Policy State Machine registry key.
///
/// The key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine`
/// is written by the GP client during every GP cycle and persists across
/// reboots and network disconnections. On workgroup machines (or before the
/// first GP cycle) the key does not exist — this function returns `Err` in
/// that case.
fn gp_state_machine(value_name: &str) -> Result<String, String> {
    const KEY: &str =
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine";
    match super::registry::read("HKLM", KEY, value_name) {
        Ok(Some(serde_json::Value::String(s))) => Ok(s),
        Ok(_) => Err(format!(
            "GP State Machine registry: {value_name} absent or not a string"
        )),
        Err(e) => Err(format!("GP State Machine registry: {e}")),
    }
}

/// Returns the `SAM`-compatible name of the local computer account.
///
/// Format: `DOMAIN\COMPUTERNAME$` (e.g. `PHARMA\E00AVDDWDEV0271$`).
/// Backed by `GetComputerObjectNameW(NameSamCompatible)`. No registry
/// fallback — same policy as the C# reference implementation.
pub(super) fn sam_name() -> Result<String, String> {
    get_object_name(NameSamCompatible)
}

/// Returns the LDAP distinguished name of the local computer account.
///
/// Format: `CN=<name>,OU=<ou>,...,DC=<domain>` (e.g.
/// `CN=E00AVDDWDEV0271,OU=WAAS,OU=FRCE,DC=pharma,DC=aventis,DC=com`).
///
/// Falls back to the Group Policy State Machine registry key
/// (`Distinguished-Name`) when `GetComputerObjectNameW` is unavailable
/// (e.g. Netlogon not yet authenticated). Mirrors the C# fallback chain
/// in `ActiveDirectory.cs`.
pub(super) fn distinguished_name() -> Result<String, String> {
    get_object_name(NameFullyQualifiedDN)
        .or_else(|_| gp_state_machine("Distinguished-Name"))
}

/// Returns the canonical name of the local computer account.
///
/// Format: `<domain>/<ou-path>/<name>` (e.g.
/// `pharma.aventis.com/ZZ NGDC EMEA/Computers/.../E00AVDDWDEV0271`).
/// No registry fallback — same policy as the C# reference implementation.
pub(super) fn canonical_name() -> Result<String, String> {
    get_object_name(NameCanonical)
}

/// Returns the Active Directory site of the local computer.
///
/// Backed by `DsGetSiteNameW`, which queries Netlogon's site cache —
/// no network call required if the cache is warm. Falls back to the
/// Group Policy State Machine registry key (`Site-Name`) when
/// `DsGetSiteNameW` fails (e.g. Netlogon stopped or site not yet cached).
pub(super) fn site_name() -> Result<String, String> {
    ds_get_site_name().or_else(|_| gp_state_machine("Site-Name"))
}

/// Inner implementation for [`site_name`] using `DsGetSiteNameW`.
///
/// Unlike `GetComputerObjectNameW`, `DsGetSiteNameW` allocates its output
/// buffer internally (via the network management heap). The caller must free
/// it with `NetApiBufferFree` after copying the string — see the `SAFETY:`
/// comments below.
fn ds_get_site_name() -> Result<String, String> {
    let mut ptr = PWSTR::null();

    // SAFETY: `PCWSTR::null()` requests site info for the local computer
    // (documented: NULL ComputerName = local). On success the API allocates
    // a buffer and writes its address into `ptr`. `&raw mut ptr` avoids the
    // aliasing footgun (same rationale as hostname.rs).
    WIN32_ERROR(unsafe { DsGetSiteNameW(PCWSTR::null(), &raw mut ptr) })
        .ok()
        .map_err(|e| format!("DsGetSiteNameW: {e}"))?;

    // SAFETY: On success `ptr` is a valid, NUL-terminated UTF-16 string
    // allocated by the API. `as_wide()` walks to the NUL and returns a
    // slice — we copy it into a Rust String before freeing.
    let wide = unsafe { ptr.as_wide() };
    let result = OsString::from_wide(wide)
        .into_string()
        .map_err(|_| "DsGetSiteNameW: result is not valid UTF-8".to_string());

    // SAFETY: `ptr` was allocated by `DsGetSiteNameW` via the network
    // management heap and must be freed with `NetApiBufferFree` on **every**
    // exit path from a successful API call — including when the UTF-8
    // conversion above fails. We collect `result` first so the free happens
    // unconditionally before we return. Cast `*mut u16` → `*const c_void` is
    // alignment-safe: `NetApiBufferFree` only needs the pointer value.
    unsafe { NetApiBufferFree(Some(ptr.0.cast())) };

    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // All four functions are smoke-tested for linkage and panic-safety.
    // The exact values depend on the runner's domain membership, so we
    // assert only the structural invariants that hold universally:
    //   - Ok(s) => non-empty string satisfying format constraints
    //   - Err(_) => workgroup / Netlogon not cached — acceptable

    #[test]
    fn sam_name_smoke() {
        if let Ok(s) = sam_name() {
            assert!(!s.is_empty(), "SAM name must not be empty");
            assert!(s.contains('\\'), "SAM name must contain a backslash: {s:?}");
            assert!(s.ends_with('$'), "computer SAM name must end with '$': {s:?}");
        }
        // Err(_) => workgroup machine or Netlogon not cached — linkage verified
    }

    #[test]
    fn distinguished_name_smoke() {
        if let Ok(s) = distinguished_name() {
            assert!(!s.is_empty(), "DN must not be empty");
            assert!(
                s.to_uppercase().contains("DC="),
                "DN must contain at least one DC component: {s:?}"
            );
        }
        // Err(_) => no GP cycle yet or workgroup — linkage verified
    }

    #[test]
    fn canonical_name_smoke() {
        if let Ok(s) = canonical_name() {
            assert!(!s.is_empty(), "canonical name must not be empty");
            assert!(
                s.contains('/'),
                "canonical name must contain a '/' separator: {s:?}"
            );
        }
        // Err(_) => workgroup machine — linkage verified
    }

    #[test]
    fn site_name_smoke() {
        if let Ok(s) = site_name() {
            assert!(!s.is_empty(), "site name must not be empty");
        }
        // Err(_) => workgroup or no site configured — linkage verified
    }
}
