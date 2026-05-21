//! Regional information host bindings.
//!
//! Exposes four Win32 API calls that mirror five of the six C# transformers in
//! `DataTransformers/Regional` (`KbLayout.cs` was dead code in `ComplianceApp`
//! and is intentionally omitted):
//!
//! | C# class | Win32 API | Binding |
//! |---|---|---|
//! | `MuiLang` / `UserDefaultLanguage` | `GetUserDefaultUILanguage` + `LCIDToLocaleName` | `user_ui_language` |
//! | `CurrentCulture` | `GetUserDefaultLocaleName` | `user_locale` |
//! | `SystemDefaultLanguage` | `GetSystemDefaultUILanguage` + `LCIDToLocaleName` | `system_ui_language` |
//! | `SystemCulture` | `GetSystemDefaultLocaleName` | `system_locale` |
//!
//! ## BCP-47 instead of English names
//!
//! `UserDefaultLanguage` and `SystemDefaultLanguage` in C# return an English
//! display name (e.g. `"French (France)"`) via `CultureInfo.EnglishName`.  In
//! Rust we return the BCP-47 tag directly (`"fr-FR"`) — more machine-readable
//! and fully round-trippable.  The English name is available via
//! `GetLocaleInfoEx(locale, LOCALE_SENGLISHDISPLAYNAME)` if needed later.
//!
//! ## Token-sensitive caveat
//!
//! When the process runs as `LocalSystem` (service), `GetUserDefault*` returns
//! the locale of the `.DEFAULT` hive, **not** the interactive user's locale.
//! This is identical to the C# behaviour documented on `IWinAPI` as
//! "Token-sensitive".  To retrieve the interactive user's locale from a
//! service context, the process would need to impersonate the user token and
//! read from the user's registry hive — out of scope here.
//!
//! ## Unsafe justification
//!
//! Every `unsafe` block in this file is a thin call to a documented Win32
//! NLS API.  All buffers are stack-allocated arrays of `u16`; no raw
//! pointers are retained across calls.  See
//! [Rust Book ch. 19.1](https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html)
//! for the `unsafe` block semantics used here.

use windows::Win32::Globalization::{
    GetSystemDefaultLocaleName, GetSystemDefaultUILanguage, GetUserDefaultLocaleName,
    GetUserDefaultUILanguage, LCIDToLocaleName,
};

// Windows NLS maximum locale name length (including NUL terminator).
// Defined as LOCALE_NAME_MAX_LENGTH = 85 in winnls.h.
const LOCALE_NAME_MAX_LENGTH: usize = 85;

// ---------------------------------------------------------------------------
// Private helper
// ---------------------------------------------------------------------------

/// Converts a `LANGID` (16-bit Windows language identifier) to a BCP-47 locale
/// name string (e.g. `1036` → `"fr-FR"`) via `LCIDToLocaleName`.
///
/// The LCID for a given LANGID with default sort order is simply the LANGID
/// zero-extended to 32 bits — `MAKELCID(langid, SORT_DEFAULT)` where
/// `SORT_DEFAULT = 0`.
///
/// Returns `None` if `LCIDToLocaleName` returns 0 or a negative value (unknown LANGID).
fn langid_to_locale_name(langid: u16) -> Option<String> {
    // MAKELCID(langid, SORT_DEFAULT=0) — zero-extend, no bit manipulation needed.
    let lcid = u32::from(langid);

    let mut buf = [0u16; LOCALE_NAME_MAX_LENGTH];
    // SAFETY: buf is a valid stack-allocated slice of the correct size.
    // LCIDToLocaleName writes a NUL-terminated wide string into it.
    let len = unsafe { LCIDToLocaleName(lcid, Some(&mut buf), 0) };

    // len > 0 on success (includes NUL terminator); 0 or negative on failure.
    let len = usize::try_from(len)
        .ok()
        .filter(|&n| n > 0)?
        .saturating_sub(1);
    Some(String::from_utf16_lossy(&buf[..len]))
}

/// Converts a stack buffer of `u16` filled by a `GetXxxLocaleName` call into
/// a `String`, given the char count returned by the API (includes NUL terminator).
fn locale_buf_to_string(buf: &[u16; LOCALE_NAME_MAX_LENGTH], len: i32) -> Option<String> {
    // len > 0 on success (includes NUL); 0 on failure (locale not found).
    let len = usize::try_from(len)
        .ok()
        .filter(|&n| n > 0)?
        .saturating_sub(1);
    Some(String::from_utf16_lossy(&buf[..len]))
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Returns the BCP-47 UI language of the current user (e.g. `"fr-FR"`).
///
/// Uses `GetUserDefaultUILanguage()` (LANGID) then `LCIDToLocaleName`.
/// This is the language Windows uses for menus and dialogs — it may differ
/// from `user_locale()` which controls date/number formatting.
///
/// **Token-sensitive**: when running as `LocalSystem`, returns the `.DEFAULT`
/// hive language, not the interactive user's language.
///
/// Mirrors `MuiLang.cs` and `UserDefaultLanguage.cs` from `ComplianceApp`
/// (both read the same underlying LANGID; we return BCP-47 rather than the
/// English display name returned by C#'s `CultureInfo.EnglishName`).
///
/// # Examples
///
/// ```ignore
/// assert!(user_ui_language().is_some()); // e.g. Some("fr-FR")
/// ```
#[must_use]
pub(super) fn user_ui_language() -> Option<String> {
    // SAFETY: GetUserDefaultUILanguage() has no preconditions and always
    // returns a valid LANGID (fallback to LANG_NEUTRAL on unexpected error).
    let langid = unsafe { GetUserDefaultUILanguage() };
    langid_to_locale_name(langid)
}

/// Returns the BCP-47 UI language of the OS installation (e.g. `"en-US"`).
///
/// Uses `GetSystemDefaultUILanguage()` — the language installed with Windows,
/// independent of any user customisation and of the process token.
///
/// Mirrors `SystemDefaultLanguage.cs` from `ComplianceApp` (BCP-47 instead of
/// English display name).
///
/// # Examples
///
/// ```ignore
/// assert!(system_ui_language().is_some()); // e.g. Some("en-US")
/// ```
#[must_use]
pub(super) fn system_ui_language() -> Option<String> {
    // SAFETY: same as user_ui_language — no preconditions.
    let langid = unsafe { GetSystemDefaultUILanguage() };
    langid_to_locale_name(langid)
}

/// Returns the BCP-47 regional locale of the current user (e.g. `"fr-CH"`).
///
/// Uses `GetUserDefaultLocaleName()` — controls date/time/number formatting,
/// which can differ from the UI language (`user_ui_language()`).
///
/// **Token-sensitive**: see module-level docs.
///
/// Mirrors `CurrentCulture.cs` from `ComplianceApp`.
///
/// # Examples
///
/// ```ignore
/// assert!(user_locale().is_some()); // e.g. Some("fr-CH")
/// ```
#[must_use]
pub(super) fn user_locale() -> Option<String> {
    let mut buf = [0u16; LOCALE_NAME_MAX_LENGTH];
    // SAFETY: buf is a valid stack slice of LOCALE_NAME_MAX_LENGTH chars.
    let len = unsafe { GetUserDefaultLocaleName(&mut buf) };
    locale_buf_to_string(&buf, len)
}

/// Returns the BCP-47 system-wide regional locale (e.g. `"en-US"`).
///
/// Uses `GetSystemDefaultLocaleName()` — the locale set at OS installation
/// time, used by system processes.  Token-independent.
///
/// Mirrors `SystemCulture.cs` from `ComplianceApp`.
///
/// # Examples
///
/// ```ignore
/// assert!(system_locale().is_some()); // e.g. Some("en-US")
/// ```
#[must_use]
pub(super) fn system_locale() -> Option<String> {
    let mut buf = [0u16; LOCALE_NAME_MAX_LENGTH];
    // SAFETY: same as user_locale.
    let len = unsafe { GetSystemDefaultLocaleName(&mut buf) };
    locale_buf_to_string(&buf, len)
}
