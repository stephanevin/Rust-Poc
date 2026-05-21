//! Host bindings backed by the Windows Notification Facility (WNF).
//!
//! WNF is a registrationless pub/sub mechanism in `ntdll.dll` that has no
//! documented Win32 surface. We access it through the [`wnf`] crate, which
//! provides safe abstractions over `NtQueryWnfStateData` and friends.
//!
//! Well-known state names come from [`super::well_known_wnf_name`], which
//! mirrors `WellKnownWnfName.cs` from `ComplianceApp`.

use wnf::BorrowedState;

use super::well_known_wnf_name::WNF_USO_REBOOT_REQUIRED;

/// Returns whether the Update Session Orchestrator (USO) requires a reboot.
///
/// Mirrors `DataService.GetUsoRebootRequired()` from `ComplianceApp`, which
/// reads the same WNF state via `NtQueryWnfStateData`. The raw DWORD value
/// is `> 0` when USO has flagged a reboot as required.
///
/// Returns `None` when the WNF state cannot be read (e.g. on a hardened
/// system that denies access to this state) or when the payload is too short.
///
/// # Examples
///
/// ```ignore
/// // In a normal post-update session: Some(true)
/// // On a freshly booted system:      Some(false)
/// // On a restricted VM:              None
/// let reboot = uso_reboot_required();
/// ```
pub(super) fn uso_reboot_required() -> Option<bool> {
    BorrowedState::<u32>::from_state_name(WNF_USO_REBOOT_REQUIRED)
        .get()
        .ok()
        .map(|dword| dword > 0)
}
