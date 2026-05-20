//! Windows machine-name variants via `GetComputerNameExW`.
//!
//! Exposes three functions, each resolving a different name format:
//!
//! | Function       | Win32 constant                  | Example (domain-joined)      | .NET / cmd equivalent                       |
//! |----------------|----------------------------------|------------------------------|---------------------------------------------|
//! | `netbios_name` | `ComputerNameNetBIOS`           | `E00AVDDWDEV0271`            | `Environment.MachineName`, `%COMPUTERNAME%` |
//! | `dns_hostname` | `ComputerNameDnsHostname`       | `E00AVDDWDEV0271`            | `IPGlobalProperties.HostName`, `hostname`   |
//! | `dns_fqdn`     | `ComputerNameDnsFullyQualified` | `E00AVDDWDEV0271.sanofi.com` | `Dns.GetHostEntry("").HostName`             |
//!
//! ## Non-`Physical*` variants
//!
//! All three use the **non-`Physical*`** Win32 constants, matching the
//! behaviour of `IPGlobalProperties.GetIPGlobalProperties().HostName` in
//! .NET, which calls `gethostname()` → `ComputerNameDnsHostname`
//! (non-Physical) under the hood. The `Physical*` variants diverge on
//! Windows Failover Cluster nodes where `SetComputerNameEx` overrides the
//! logical name; on standard endpoints (laptops, desktops, AVD, RDS VMs)
//! the two variants return identical strings.
//!
//! ## Invariants
//!
//! - **`NetBIOS` name**: ≤ 15 characters, ASCII uppercase. Frozen at boot;
//!   a rename via Settings takes effect only after reboot.
//! - **DNS hostname**: no dots. Updated immediately when the computer is
//!   renamed — no reboot required.
//! - **FQDN**: `<hostname>[.<dns_domain>]`. Equals `dns_hostname()` on
//!   workgroup machines; carries the AD domain suffix when domain-joined.
//!
//! ## Deviation from upstream
//!
//! This module is a **deviation** from the verbatim port of
//! `sdh-fleet-client/lua/` — upstream does not expose these bindings today.
//! See `CLAUDE.md` § *Deviations from a strict verbatim copy* for the
//! rationale and re-sync guidance.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows::Win32::System::SystemInformation::{
    COMPUTER_NAME_FORMAT, ComputerNameDnsFullyQualified, ComputerNameDnsHostname,
    ComputerNameNetBIOS, GetComputerNameExW,
};
use windows::core::PWSTR;

/// Core two-call sizing pattern for `GetComputerNameExW`, parameterised by
/// `format`.
///
/// 1. First call with `None` buffer — documented to fail with
///    `ERROR_MORE_DATA` and write the required length (WCHARs, **including**
///    the trailing NUL) into `nSize`.
/// 2. Allocate a `Vec<u16>` of exactly that length and call again.
///    On success `nSize` is updated to the length **without** the NUL —
///    that is what we truncate to before decoding.
///
/// Decoded with `OsString::from_wide` (UTF-16 → OS string) then
/// `.into_string()` (→ UTF-8). Any unpaired surrogate surfaces as an error
/// rather than a silent replacement — better for an audit trail.
fn get_computer_name(format: COMPUTER_NAME_FORMAT) -> Result<String, String> {
    let mut size: u32 = 0;

    // SAFETY: the sizing probe with NULL buffer is the documented way to
    // learn the required length. The Result is intentionally ignored — the
    // API contract is to FAIL here; the useful info is in the out-parameter
    // `size`. `&raw mut size` (Rust 1.82+) takes a raw pointer without an
    // intermediate `&mut` reference, avoiding the strict aliasing footgun
    // that `clippy::borrow_as_ptr` flags at FFI boundaries.
    unsafe {
        let _ = GetComputerNameExW(format, None, &raw mut size);
    }

    if size == 0 {
        return Err(format!(
            "GetComputerNameExW({format:?}): sizing probe returned size=0"
        ));
    }

    let mut buf = vec![0u16; size as usize];

    // SAFETY: `buf` holds exactly `size` WCHARs as reported by the sizing
    // probe. On success `size` is overwritten with the length WITHOUT the
    // trailing NUL — we truncate to that value before decoding. Same
    // `&raw mut size` rationale as the sizing probe above.
    unsafe {
        GetComputerNameExW(format, Some(PWSTR(buf.as_mut_ptr())), &raw mut size)
    }
    .map_err(|e| format!("GetComputerNameExW({format:?}): {e}"))?;

    buf.truncate(size as usize);
    OsString::from_wide(&buf)
        .into_string()
        .map_err(|_| format!("GetComputerNameExW({format:?}): result is not valid UTF-8"))
}

/// Returns the `NetBIOS` name of the local computer.
///
/// Backed by `ComputerNameNetBIOS`. At most 15 characters, ASCII uppercase.
/// Same value as `%COMPUTERNAME%` and `Environment.MachineName` in .NET.
pub(super) fn netbios_name() -> Result<String, String> {
    get_computer_name(ComputerNameNetBIOS)
}

/// Returns the DNS-style local hostname of the computer.
///
/// Backed by `ComputerNameDnsHostname`. No dots. Equivalent to
/// `IPGlobalProperties.GetIPGlobalProperties().HostName` in .NET, which
/// calls `gethostname()` → `ComputerNameDnsHostname` under the hood.
pub(super) fn dns_hostname() -> Result<String, String> {
    get_computer_name(ComputerNameDnsHostname)
}

/// Returns the fully-qualified domain name (`FQDN`) of the local computer.
///
/// Backed by `ComputerNameDnsFullyQualified`. Format:
/// `<hostname>[.<dns_domain>]`. On workgroup machines this equals
/// `dns_hostname()`; on domain-joined machines it carries the AD DNS
/// suffix (e.g. `E00AVDDWDEV0271.sanofi.com`).
pub(super) fn dns_fqdn() -> Result<String, String> {
    get_computer_name(ComputerNameDnsFullyQualified)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // The FFI is non-deterministic (depends on the runner's machine config)
    // so we assert universal invariants rather than pinning a specific value.
    // Running under `cargo test` also smoke-tests the linkage end-to-end.

    #[test]
    fn netbios_name_is_non_empty_and_short_ascii() {
        let name = netbios_name().unwrap();
        assert!(!name.is_empty(), "NetBIOS name must not be empty");
        assert!(
            name.len() <= 15,
            "NetBIOS name must be at most 15 chars, got {name:?} ({})",
            name.len()
        );
        assert!(name.is_ascii(), "NetBIOS name must be ASCII, got {name:?}");
    }

    #[test]
    fn dns_hostname_is_non_empty_and_has_no_dot() {
        let h = dns_hostname().unwrap();
        assert!(!h.is_empty(), "DNS hostname must not be empty");
        assert!(
            !h.contains('.'),
            "DNS hostname must not contain a dot (that is the FQDN), got {h:?}"
        );
        assert!(
            h.chars().all(|c| !c.is_control()),
            "DNS hostname must not contain control characters, got {h:?}"
        );
    }

    #[test]
    fn fqdn_starts_with_dns_hostname() {
        let hostname = dns_hostname().unwrap();
        let fqdn = dns_fqdn().unwrap();
        assert!(!fqdn.is_empty(), "FQDN must not be empty");
        assert!(
            fqdn.to_lowercase().starts_with(&hostname.to_lowercase()),
            "FQDN must start with the DNS hostname; hostname={hostname:?} fqdn={fqdn:?}"
        );
    }
}
