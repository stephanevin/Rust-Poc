//! CyberArk EPM (legacy Viewfinity) host bindings — deviation #46.
//!
//! Six stateless bindings mirroring the CyberArk EPM region of
//! `ComplianceService/Data/Security/Security.cs`, covering the 6 items of the
//! Privileged Account Management (PAM) category in `Win10-Laptop.json`. Two
//! Windows mechanisms, no WMI / no COM:
//!
//! - [`driver_status`] — the `vfpd` kernel driver (Viewfinity Privilege
//!   Driver) status via the Service Control Manager. The C# uses
//!   `ServiceController.GetDevices()` and maps a missing driver to
//!   `ServiceStatus.None`; we open the named service directly
//!   (`OpenServiceW` + `QueryServiceStatus`) and return `"None"` when it does
//!   not exist.
//! - [`version`] / [`id`] / [`dispatcher_url`] / [`registered_at`] /
//!   [`last_policy_update`] — five values under the single registry key
//!   `HKLM\SOFTWARE\Viewfinity\Agent`.
//!
//! ## Deviation #46 — design notes
//!
//! 1. **Targeted query, not enumeration.** `host.os_services()`
//!    (`software.rs`) enumerates only `SERVICE_WIN32` and never kernel
//!    drivers. Rather than widen that enumeration, [`driver_status`] opens the
//!    `vfpd` service by name. It reuses `software::ScHandle` (RAII close) and
//!    `software::service_state_label` so the status strings are identical to
//!    `os_services`.
//! 2. **Dates in UTC Zulu.** `LastPolicyUpdateTime` is a `REG_QWORD` FILETIME.
//!    [`last_policy_update`] converts it via `winver::filetime_to_iso8601`,
//!    which interprets the tick as UTC and emits `…Z`. This matches
//!    ComplianceApp's gRPC wire contract (`Timestamp.FromDateTime(dt
//!    .ToUniversalTime())`) and the rest of the crate; the bare C#
//!    `DateTime.FromFileTime` produces local time, but the same instant
//!    travels over the wire as UTC.
//! 3. **`version` / `registered_at` are passed through verbatim.** The C#
//!    parses `Version` into a `System.Version` and emits its `ToString()`; we
//!    keep the raw string (identical output, no parse failure path).
//!    `RegisteredAt` is a raw string the C# never parses as a date.
//!
//! ## Failure semantics
//!
//! - [`driver_status`] returns `Ok("None")` when the driver is not installed
//!   (`ERROR_SERVICE_DOES_NOT_EXIST`); any other SC Manager failure is a real
//!   `Err` recorded under `cyberark:driver_status`.
//! - The five registry reads are infallible (the `laps.rs` posture): a missing
//!   key / value / type mismatch degrades to `None`, never an error.

// `doc_markdown`: product names ("CyberArk", "Viewfinity") and Win32 idents
// trip the lint even when backticked elsewhere.
#![allow(clippy::doc_markdown)]

use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
use windows::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, SERVICE_STATUS,
};
use windows::core::{PCWSTR, w};

use super::registry;
use super::software::{ScHandle, service_state_label};

/// Registry key holding the EPM agent metadata (legacy Viewfinity path).
const VIEWFINITY_AGENT_KEY: &str = r"SOFTWARE\Viewfinity\Agent";

// SC Manager access rights — not exposed as typed consts in windows 0.62
// (same situation as `software.rs`).
const SC_MANAGER_CONNECT: u32 = 0x0001;
const SERVICE_QUERY_STATUS: u32 = 0x0004;

/// Kernel driver name registered by CyberArk EPM (legacy Viewfinity).
const DRIVER_NAME: PCWSTR = w!("vfpd");

// ---------------------------------------------------------------------------
// 1. SC Manager — vfpd driver status
// ---------------------------------------------------------------------------

/// `host.cyber_ark_epm_driver_status()` — current state of the `vfpd` kernel
/// driver.
///
/// Returns `Ok("None")` when the driver is absent (mirrors the C#
/// `ServiceStatus.None`), `Ok(<state>)` for an installed driver, and `Err`
/// only on a genuine SC Manager failure.
pub(super) fn driver_status() -> Result<String, String> {
    // SAFETY: null name/database → the local machine's active SCM database.
    let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
        .map_err(|e| format!("OpenSCManagerW: {e}"))?;
    let _scm = ScHandle(scm);

    // SAFETY: `scm` is a valid SCM handle; DRIVER_NAME is a NUL-terminated
    // wide-string literal.
    let svc = match unsafe { OpenServiceW(scm, DRIVER_NAME, SERVICE_QUERY_STATUS) } {
        Ok(h) => h,
        // Driver not installed — ServiceStatus.None in the C# mirror.
        Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => {
            return Ok("None".to_string());
        }
        Err(e) => return Err(format!("OpenServiceW(vfpd): {e}")),
    };
    let _svc = ScHandle(svc);

    let mut status = SERVICE_STATUS::default();
    // SAFETY: `svc` was opened with SERVICE_QUERY_STATUS; `status` is a
    // writable SERVICE_STATUS the callee fills in.
    unsafe { QueryServiceStatus(svc, &raw mut status) }
        .map_err(|e| format!("QueryServiceStatus(vfpd): {e}"))?;

    Ok(service_state_label(status.dwCurrentState.0).to_string())
}

// ---------------------------------------------------------------------------
// 2. Registry — HKLM\SOFTWARE\Viewfinity\Agent
// ---------------------------------------------------------------------------

/// Reads a string-ish value from the Viewfinity Agent key, swallowing
/// open/read errors to `None` and coercing scalars via the shared
/// [`registry::as_string`].
fn reg_string(value: &str) -> Option<String> {
    registry::as_string(
        registry::read("HKLM", VIEWFINITY_AGENT_KEY, value)
            .ok()
            .flatten()?,
    )
}

/// `host.cyber_ark_epm_version()` — `Version` value (raw string passthrough).
pub(super) fn version() -> Option<String> {
    reg_string("Version")
}

/// `host.cyber_ark_epm_id()` — `SetID` value.
pub(super) fn id() -> Option<String> {
    reg_string("SetID")
}

/// `host.cyber_ark_epm_dispatcher_url()` — `DispatcherURL` value.
pub(super) fn dispatcher_url() -> Option<String> {
    reg_string("DispatcherURL")
}

/// `host.cyber_ark_epm_registered_at()` — `RegisteredAt` value (raw string,
/// never parsed as a date, matching the C#).
pub(super) fn registered_at() -> Option<String> {
    reg_string("RegisteredAt")
}

/// Converts a `REG_QWORD` FILETIME tick to an ISO 8601 UTC (`…Z`) string.
/// Pure wrapper around `winver::filetime_to_iso8601` so it is testable.
fn ticks_to_iso(ticks: u64) -> Option<String> {
    super::winver::filetime_to_iso8601(i64::try_from(ticks).ok()?)
}

/// `host.cyber_ark_epm_last_policy_update()` — `LastPolicyUpdateTime`
/// (`REG_QWORD` FILETIME) as an ISO 8601 UTC string.
pub(super) fn last_policy_update() -> Option<String> {
    let ticks = registry::read("HKLM", VIEWFINITY_AGENT_KEY, "LastPolicyUpdateTime")
        .ok()
        .flatten()?
        .as_u64()?;
    ticks_to_iso(ticks)
}

// ---------------------------------------------------------------------------
// Tests — pure helpers (no SC Manager / no registry)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::ticks_to_iso;

    /// A known FILETIME tick converts to its UTC Zulu instant; 0 → None.
    #[test]
    fn ticks_to_iso_converts_known_filetime() {
        // 2024-01-15T10:30:00Z == 133497882000000000 ticks since 1601-01-01.
        assert_eq!(
            ticks_to_iso(133_497_882_000_000_000),
            Some("2024-01-15T10:30:00Z".to_string())
        );
        // Zero / pre-Unix ticks are rejected by winver::filetime_to_iso8601.
        assert_eq!(ticks_to_iso(0), None);
    }
}
