//! TLS cipher suite host binding.
//!
//! Wraps `BCryptEnumContextFunctions` (bcrypt.dll) to return the **effective**
//! list of TLS cipher suites negotiated by Schannel, in priority order.
//!
//! ## Why the Win32 API rather than the registry
//!
//! Two registry paths exist for TLS cipher suite configuration:
//!
//! - `HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002\Functions`
//!   (local machine configuration)
//! - `HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\Functions`
//!   (Group Policy override, absent when no GP is applied)
//!
//! `BCryptEnumContextFunctions(CRYPT_LOCAL, "SSL", NCRYPT_SCHANNEL_INTERFACE)`
//! returns the **merged** effective list after all policy application — the
//! same data surface as `ComplianceApp`'s `BCrypt.GetTlsCipherSuite()`.
//! Reading either registry key in isolation misses the other half.
//!
//! ## Unsafe justification
//!
//! The `unsafe` block covers the API call itself plus pointer traversal of the
//! BCrypt-allocated buffer. The `BcryptBuf` RAII guard ensures `BCryptFreeBuffer`
//! is called on every code path, including panics.
//! See [Rust Book ch. 15.3](https://doc.rust-lang.org/book/ch15-03-drop.html)
//! for the `Drop` idiom used here.

use std::ffi::c_void;

use windows::Win32::Security::Cryptography::{
    BCryptEnumContextFunctions, BCryptFreeBuffer, CRYPT_CONTEXT_FUNCTIONS, CRYPT_LOCAL,
    NCRYPT_SCHANNEL_INTERFACE,
};
use windows::core::w;

// ---------------------------------------------------------------------------
// RAII guard
// ---------------------------------------------------------------------------

/// Wraps the raw pointer returned by `BCryptEnumContextFunctions` and calls
/// `BCryptFreeBuffer` in `Drop`, guaranteeing the buffer is always released.
struct BcryptBuf(*mut CRYPT_CONTEXT_FUNCTIONS);

impl Drop for BcryptBuf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by `BCryptEnumContextFunctions`;
            // we are the sole owner and this is the only free call.
            unsafe { BCryptFreeBuffer(self.0.cast::<c_void>()) };
        }
    }
}

// SAFETY: the buffer is allocated and freed on the same thread; we never
// share the raw pointer across threads.
unsafe impl Send for BcryptBuf {}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Returns the effective TLS cipher suites enabled for Schannel, in priority
/// order, by calling `BCryptEnumContextFunctions(CRYPT_LOCAL, "SSL",
/// NCRYPT_SCHANNEL_INTERFACE)`.
///
/// Mirrors `BCrypt.GetTlsCipherSuite()` from `ComplianceApp`.
///
/// Returns `None` when the `BCrypt` call fails (e.g. the `SSL` context does not
/// exist or the process lacks privilege). On any machine with a functioning
/// Schannel stack this will succeed.
///
/// # Examples
///
/// ```ignore
/// // Typical result on Windows 11 24H2 with default configuration:
/// // Some(["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", ...])
/// let suites = tls_cipher_suites();
/// ```
#[must_use]
pub(super) fn tls_cipher_suites() -> Option<Vec<String>> {
    let mut buf_len: u32 = 0;
    let mut raw: *mut CRYPT_CONTEXT_FUNCTIONS = std::ptr::null_mut();

    // SAFETY: `w!("SSL")` is a compile-time wide-string literal; `buf_len`
    // and `raw` are valid out-parameters. The API writes a valid pointer into
    // `raw` on success (NTSTATUS >= 0).
    let status = unsafe {
        BCryptEnumContextFunctions(
            CRYPT_LOCAL,
            w!("SSL"),
            NCRYPT_SCHANNEL_INTERFACE,
            &raw mut buf_len,
            Some(&raw mut raw),
        )
    };

    if !status.is_ok() || raw.is_null() {
        return None;
    }

    // Construct the guard immediately so BCryptFreeBuffer fires on every exit.
    let _guard = BcryptBuf(raw);

    // SAFETY: `raw` is non-null and the API guarantees a valid
    // `CRYPT_CONTEXT_FUNCTIONS` struct at this address.
    let funcs = unsafe { &*raw };
    let count = funcs.cFunctions as usize;
    let base = funcs.rgpszFunctions;

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: `base` points to a contiguous array of `count` PWSTR values
        // allocated by BCrypt. Each PWSTR is a pointer to a NUL-terminated
        // UTF-16 string owned by the same buffer.
        let pwstr = unsafe { *base.add(i) };
        if let Ok(name) = unsafe { pwstr.to_string() } {
            result.push(name);
        }
        // Skip malformed UTF-16 entries silently rather than failing the whole
        // call — keeps parity with C#'s `yield return` which also skips nulls.
    }

    Some(result)
}
