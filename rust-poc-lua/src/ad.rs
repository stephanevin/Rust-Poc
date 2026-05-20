//! Best-effort AD mail lookup via ADSI (IADs COM interface).
//!
//! Non-domain-joined machines or timeouts return None without surfacing an
//! error. The Lua-facing binding uses `tokio::time::timeout` from the caller
//! side, so this module just does the blocking COM call.

use std::time::Duration;

/// Synchronous LDAP mail lookup with a user-supplied overall timeout.
/// Returns `Ok(None)` on any recoverable failure — missing AD, timeout,
/// no mail attribute set, etc.
// Signature keeps the error arm for phase 2 (real IADs COM calls will surface
// COM HRESULTs). Caller already handles `Err` by recording into `host.errors()`.
#[allow(clippy::unnecessary_wraps)]
pub(super) fn current_user_mail_blocking(timeout: Duration) -> Result<Option<String>, String> {
    // Spawn a background thread so we can enforce the timeout on code that
    // happens to hang inside COM.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = lookup();
        let _ = tx.send(r);
    });

    match rx.recv_timeout(timeout) {
        Ok(r) => Ok(r),
        Err(_) => Ok(None), // timed out
    }
}

fn lookup() -> Option<String> {
    // The simplest approach is to shell out to an LDAP query via the
    // Active Directory Services Interface (ADSI). Full COM implementation
    // would be large; for the PoC we just probe USERDNSDOMAIN and fall back
    // to None if lookup fails. Domain-joined machines with USERDNSDOMAIN
    // set typically have this queryable; Phase 2 can expand via IADs COM
    // if needed.
    let _ = std::env::var("USERDNSDOMAIN").ok()?;
    // TODO(phase-2): real IADs::get("mail") via windows::Win32::System::Ole.
    None
}
