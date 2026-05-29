//! SentinelOne EDR host bindings — deviation #45.
//!
//! Three bindings covering the 15 SentinelOne items of the EDR category in
//! `Win10-Laptop.json`, mirroring `ComplianceService/Data/EDR/SentinelOne/SentinelOne.cs`:
//!
//! - [`agent_status`] — COM **IDispatch late-binding** against the
//!   `SentinelHelper` ProgID (`GetAgentStatusJSON()`), feeding the 13
//!   agent-status fields.  This is the first late-bound COM call in the
//!   crate: every other COM consumer (WMI, WUA, `HNetCfg.FwProducts`) uses
//!   an early-bound, typed `windows-rs` interface.  `SentinelHelper` ships
//!   no type library we can bind against, so we go through `IDispatch`
//!   (`CLSIDFromProgID` + `CoCreateInstance` + `GetIDsOfNames` + `Invoke`)
//!   exactly as the C# `dynamic agent = Activator.CreateInstance(...)` does.
//! - [`paths`] — `%ProgramFiles%[(x86)]\SentinelOne` discovery + recursive
//!   search for every `SentinelCtl.exe` / `sentinelAgent.exe`.
//! - [`comm_sdk`] — newest `SentinelOne/Operational` event #104, exposing
//!   its `CommSdkMessage` data value and timestamp.
//!
//! ## Deviation #45 — design notes
//!
//! 1. **`paths()` returns arrays, not `LastOrDefault()`.** The C#
//!    `GetSentinelOneFindCtlPath` / `GetSentinelOneFindAgentPath` run
//!    `Directory.GetFiles(..., AllDirectories).LastOrDefault()` and keep a
//!    single path.  The path itself is never a compliance value — it only
//!    feeds an existence test (`ctlPath != null`).  Returning the full
//!    `Vec<String>` is therefore lossless for the compliance semantics
//!    (`!is_empty()` is identical to `!= null`), drops the arbitrary
//!    "pick the lexicographically last" rule, and is strictly more
//!    diagnostic (multiple / versioned installs become visible).
//! 2. **`agent_found` derives from `agent_paths`, not the folder.** The C#
//!    `SentinelOneAgentFound` transformer tests
//!    `GetSentinelOneFindFolderPath() != null` (folder presence) despite
//!    being labelled "Agent Executable".  We test for an actual
//!    `sentinelAgent.exe` (`#agent_paths > 0`), which is what the label
//!    promises.  The Lua collector makes this choice; this module merely
//!    exposes both the folder and the executable lists.
//! 3. **COM IDispatch late-binding** is a new Rust concept for the crate —
//!    see `CLAUDE.md` § *New Rust concepts*.
//!
//! ## Failure semantics
//!
//! - [`agent_status`] returns `Ok(None)` **silently** when the
//!   `SentinelHelper` ProgID is not registered (`CLSIDFromProgID` fails) —
//!   that is the normal "SentinelOne not installed" state, not an error.
//!   Any failure *after* the CLSID resolves (instantiation, `Invoke`, JSON
//!   parse) is a real error and surfaces as `Err`.
//! - [`paths`] is infallible: missing folders / unreadable directories
//!   degrade to empty arrays.
//! - [`comm_sdk`] swallows every Event Log failure to `None`, matching the
//!   C# catch-all (`GetSentinelOneCommSdkMessage` returns `null` on any
//!   exception).  The channel only exists when SentinelOne is installed, so
//!   a missing channel is the dominant non-error case.

// `doc_markdown` is silenced module-wide: the prose repeatedly mentions
// product names ("SentinelOne") and Win32/.NET identifiers
// (`LastOrDefault`, …) that trip the lint even when backticked elsewhere.
// `borrow_as_ptr` / `ref_as_ptr`: the IDispatch FFI takes `*const` / `*mut`
// out-params we pass as `&`/`&mut` locals — same idiom as `evt.rs`.
#![allow(clippy::doc_markdown, clippy::borrow_as_ptr, clippy::ref_as_ptr)]

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};
use windows::Win32::Globalization::LOCALE_USER_DEFAULT;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, CLSCTX_LOCAL_SERVER, CLSIDFromProgID, COINIT_MULTITHREADED,
    CoCreateInstance, CoInitializeEx, DISPATCH_METHOD, DISPPARAMS, IDispatch,
};
use windows::Win32::System::Variant::{VARIANT, VT_BSTR, VariantClear};
use windows::core::{GUID, w};

use super::evt;

// ---------------------------------------------------------------------------
// 1. COM IDispatch — agent status
// ---------------------------------------------------------------------------

/// Maximum directory recursion depth for the executable search.
///
/// The real SentinelOne layout nests the agent binaries at most a few
/// levels below `…\SentinelOne` (a per-version sub-folder + a `bin`-like
/// directory).  A depth bound keeps a pathological junction loop or a
/// symlink cycle from turning the recursive walk into an unbounded scan;
/// 8 is comfortably deeper than any observed install while staying cheap.
const MAX_SEARCH_DEPTH: usize = 8;

/// `IDispatch` projection of the JSON returned by
/// `SentinelHelper.GetAgentStatusJSON()`.
///
/// The COM payload uses kebab-case keys (`active-threats-present`, …).
/// `rename_all = "kebab-case"` maps most of them mechanically; the lone
/// exception is `mgmt-url`, which kebab-case would render as
/// `management-url`.  Dates (`agent-install-time`, `last-seen`) arrive as
/// offset-aware ISO 8601 strings (e.g. `2026-05-29T11:15:25.000+00:00`).
/// They are canonicalised to Zulu (`…Z`) by [`normalize_utc_iso8601`] so the
/// representation matches ComplianceApp's wire contract (the gRPC layer emits
/// `Timestamp.FromDateTime(dt.ToUniversalTime())`, i.e. UTC `Z`) and the rest
/// of this crate (`updates`, `winver`, `eventlog` all emit `…Z`).
///
/// Every field is `#[serde(default)]` (via `Option`) so a producer that
/// adds or omits a field never breaks deserialization — the same
/// forward-compatibility posture as the wire types in `contracts/`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
struct AgentStatus {
    active_threats_present: Option<bool>,
    agent_id: Option<String>,
    agent_install_time: Option<String>,
    agent_ppl: Option<bool>,
    agent_running: Option<bool>,
    agent_version: Option<String>,
    detection_mode: Option<String>,
    enforcing_security: Option<bool>,
    last_seen: Option<String>,
    #[serde(rename = "mgmt-url")]
    management_url: Option<String>,
    reboot_reasons: Option<Vec<String>>,
    self_protection_enabled: Option<bool>,
    site: Option<String>,
}

/// Ensures COM is initialised as MTA on the current thread.
///
/// `CoInitializeEx` returns `S_FALSE` when COM is already initialised in
/// the same apartment — `.ok()` treats any non-negative HRESULT as success.
/// Identical to the helper in [`updates`](super::updates) / [`firewall`](super::firewall).
fn ensure_com() -> Result<(), String> {
    // SAFETY: no preconditions; CoInitializeEx is always safe to call.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
        .ok()
        .map_err(|e| format!("COM init: {e}"))
}

/// Reads a `VT_BSTR` VARIANT into an owned `String`.
///
/// Returns `None` when the VARIANT holds any other type — the caller
/// treats that as a malformed response.
///
/// # Safety
///
/// `var` must be a valid VARIANT (here, the out-param freshly written by
/// `IDispatch::Invoke`).  We read `vt` before touching the union and only
/// dereference `bstrVal` when `vt == VT_BSTR`.
unsafe fn variant_bstr_to_string(var: &VARIANT) -> Option<String> {
    unsafe {
        if var.Anonymous.Anonymous.vt == VT_BSTR {
            // bstrVal is a ManuallyDrop<BSTR>; deref to borrow the BSTR.
            Some((*var.Anonymous.Anonymous.Anonymous.bstrVal).to_string())
        } else {
            None
        }
    }
}

/// Calls `SentinelHelper.GetAgentStatusJSON()` via COM IDispatch and
/// returns the parsed, snake-case-keyed status object.
///
/// `Ok(None)` means SentinelOne is not installed (ProgID unregistered).
/// `Err` means SentinelOne *is* present but the call failed.
pub(super) fn agent_status() -> Result<Option<Value>, String> {
    ensure_com()?;

    // CLSIDFromProgID failing is the SentinelOne-not-installed signal —
    // silent None, never an error.
    // SAFETY: w!() yields a valid NUL-terminated wide string literal.
    let Ok(clsid) = (unsafe { CLSIDFromProgID(w!("SentinelHelper")) }) else {
        return Ok(None);
    };

    // SAFETY: COM is initialised; clsid was just resolved by CLSIDFromProgID.
    let dispatch: IDispatch =
        unsafe { CoCreateInstance(&clsid, None, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER) }
            .map_err(|e| format!("CoCreateInstance(SentinelHelper): {e}"))?;

    // IID_NULL — the documented `riid` reserved value for both GetIDsOfNames
    // and Invoke (an all-zero GUID).
    let iid_null = GUID::zeroed();

    // Resolve the method's DISPID; the name array has a single entry.
    let names = [w!("GetAgentStatusJSON")];
    let mut dispid: i32 = 0;
    // SAFETY: `names` outlives the call and holds exactly `cnames` (1)
    // valid wide-string pointers; `dispid` is a writable i32.
    unsafe {
        dispatch.GetIDsOfNames(&iid_null, names.as_ptr(), 1, LOCALE_USER_DEFAULT, &mut dispid)
    }
    .map_err(|e| format!("GetIDsOfNames(GetAgentStatusJSON): {e}"))?;

    // Invoke with no arguments; collect the BSTR return value.
    let params = DISPPARAMS::default();
    let mut result = VARIANT::default();
    // SAFETY: `params` is an empty, zero-initialised DISPPARAMS; `result`
    // is a writable VARIANT the callee fills in.
    let invoke = unsafe {
        dispatch.Invoke(
            dispid,
            &iid_null,
            LOCALE_USER_DEFAULT,
            DISPATCH_METHOD,
            &params,
            Some(&mut result),
            None,
            None,
        )
    };

    let parsed = invoke
        .map_err(|e| format!("Invoke(GetAgentStatusJSON): {e}"))
        .and_then(|()| {
            // SAFETY: `result` was just written by a successful Invoke.
            unsafe { variant_bstr_to_string(&result) }
                .ok_or_else(|| "GetAgentStatusJSON returned a non-string VARIANT".to_string())
        })
        .and_then(|jsonstr| parse_agent_status(&jsonstr));

    // The returned VARIANT owns a BSTR allocation; release it whether or
    // not extraction succeeded.
    // SAFETY: `result` is a valid VARIANT produced by Invoke (or the
    // zero-initialised default when Invoke failed); VariantClear handles both.
    unsafe {
        let _ = VariantClear(&mut result);
    }

    parsed.map(Some)
}

/// Parses the raw `GetAgentStatusJSON` payload into the snake-case JSON
/// object exposed to Lua.  Pure (no COM) so it is unit-testable.
fn parse_agent_status(jsonstr: &str) -> Result<Value, String> {
    let status: AgentStatus =
        serde_json::from_str(jsonstr).map_err(|e| format!("parse agent status JSON: {e}"))?;
    Ok(agent_status_to_json(&status))
}

/// Canonicalises an ISO 8601 timestamp to Zulu (`…Z`) **only when it is
/// unambiguously UTC** — i.e. it already ends with `Z`, or carries a zero
/// offset (`+00:00` / `-00:00`).  A zero-offset suffix is replaced with `Z`;
/// anything else (a non-zero offset, or a zone-less local time) is returned
/// verbatim.
///
/// This deliberately performs **no time-zone arithmetic**: converting a
/// `+02:00` instant to UTC would require date math the crate otherwise avoids
/// (no `chrono` / `time` dependency).  SentinelOne reports `+00:00` in
/// practice, so the common path is a pure suffix rewrite; the rare non-UTC
/// offset stays a valid, unambiguous instant — just not in Zulu form.
fn normalize_utc_iso8601(ts: &str) -> String {
    let ts = ts.trim();
    if ts.ends_with('Z') {
        return ts.to_string();
    }
    for zero_offset in ["+00:00", "-00:00"] {
        if let Some(prefix) = ts.strip_suffix(zero_offset) {
            return format!("{prefix}Z");
        }
    }
    ts.to_string()
}

/// Serialises an [`AgentStatus`] into the snake-case-keyed object the Lua
/// collector consumes.  Keys are alphabetically ordered (the project-wide
/// `BTreeMap`-backed `json!` invariant, see `CLAUDE.md` § *JSON key ordering*).
fn agent_status_to_json(s: &AgentStatus) -> Value {
    json!({
        "active_threats_present":  s.active_threats_present,
        "agent_id":                s.agent_id,
        "agent_install_time":      s.agent_install_time.as_deref().map(normalize_utc_iso8601),
        "agent_ppl":               s.agent_ppl,
        "agent_running":           s.agent_running,
        "agent_version":           s.agent_version,
        "detection_mode":          s.detection_mode,
        "enforcing_security":      s.enforcing_security,
        "last_seen":               s.last_seen.as_deref().map(normalize_utc_iso8601),
        "management_url":          s.management_url,
        "reboot_reasons":          s.reboot_reasons,
        "self_protection_enabled": s.self_protection_enabled,
        "site":                    s.site,
    })
}

// ---------------------------------------------------------------------------
// 2. Filesystem — installation paths
// ---------------------------------------------------------------------------

/// Resolves the SentinelOne installation folder, preferring 64-bit
/// `%ProgramFiles%\SentinelOne` over `%ProgramFiles(x86)%\SentinelOne`.
/// Mirrors `GetSentinelOneFindFolderPath`.
fn find_folder() -> Option<PathBuf> {
    for var in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Ok(base) = std::env::var(var) {
            let candidate = Path::new(&base).join("SentinelOne");
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Collects every file named `file_name` (case-insensitive) under `root`,
/// recursing up to `max_depth` directory levels.
///
/// Emulates `Directory.GetFiles(root, file_name, AllDirectories)` but
/// returns **all** matches instead of `.LastOrDefault()`.  Unreadable
/// sub-directories are skipped silently — a permission error on one branch
/// must not abort the whole walk.  Order is filesystem-dependent (the
/// caller only cares about presence, not ordering).
fn find_files_recursive(root: &Path, file_name: &str, max_depth: usize) -> Vec<String> {
    let mut out = Vec::new();
    collect_files(root, file_name, max_depth, &mut out);
    out
}

/// Depth-bounded DFS helper for [`find_files_recursive`].
fn collect_files(dir: &Path, file_name: &str, depth_left: usize, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        // `file_type()` avoids a `metadata()` traversal through symlinks.
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if ft.is_dir() {
            if depth_left > 0 {
                collect_files(&path, file_name, depth_left - 1, out);
            }
            continue;
        }
        if entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.eq_ignore_ascii_case(file_name))
            && let Some(s) = path.to_str()
        {
            out.push(s.to_string());
        }
    }
}

/// `host.sentinel_one_paths()` — installation folder + every agent / control
/// executable found beneath it.
///
/// Infallible: a missing folder or unreadable directory yields `null`
/// folder / empty arrays.  The Lua collector derives both the parent
/// `SentinelOneStatus` (non-empty `ctl_paths`) and `AgentFound` (non-empty
/// `agent_paths`) from these lists.
pub(super) fn paths() -> Value {
    let folder = find_folder();
    let (ctl_paths, agent_paths) = folder.as_deref().map_or_else(
        || (Vec::new(), Vec::new()),
        |f| {
            (
                find_files_recursive(f, "SentinelCtl.exe", MAX_SEARCH_DEPTH),
                find_files_recursive(f, "sentinelAgent.exe", MAX_SEARCH_DEPTH),
            )
        },
    );

    json!({
        "folder":      folder.as_ref().and_then(|p| p.to_str()),
        "ctl_paths":   ctl_paths,
        "agent_paths": agent_paths,
    })
}

// ---------------------------------------------------------------------------
// 3. Event Log — CommSdk message
// ---------------------------------------------------------------------------

/// `host.sentinel_one_comm_sdk()` — newest `SentinelOne/Operational`
/// event #104, exposing its `CommSdkMessage` data value and timestamp.
///
/// Returns `None` on any Event Log failure (channel absent, no matching
/// event, render error) — matching the C# catch-all in
/// `GetSentinelOneCommSdkMessage` / `GetSentinelOneCommSdkMessageDate`.
pub(super) fn comm_sdk() -> Option<Value> {
    // newestToOldest: true → descending, so the first record is the latest.
    let records = evt::query_events("SentinelOne/Operational", 104, None, None, true).ok()?;
    let first = records.into_iter().next()?;
    Some(json!({
        "message": first.event_data.get("CommSdkMessage"),
        "date":    first.time_created,
    }))
}

// ---------------------------------------------------------------------------
// Tests — pure helpers (no COM / no filesystem)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{find_files_recursive, normalize_utc_iso8601, parse_agent_status};

    /// Full kebab-case payload (including the irregular `mgmt-url`) maps to
    /// the snake-case object, with the offset-form `last-seen` canonicalised
    /// to Zulu and the already-Zulu `agent-install-time` left untouched.
    #[test]
    fn parse_agent_status_maps_all_fields() {
        let raw = r#"{
            "active-threats-present": false,
            "agent-id": "abc-123",
            "agent-install-time": "2024-01-15T10:30:00Z",
            "agent-ppl": true,
            "agent-running": true,
            "agent-version": "23.4.2.1",
            "detection-mode": "Protect",
            "enforcing-security": true,
            "last-seen": "2026-05-29T08:00:00.000+00:00",
            "mgmt-url": "https://example.sentinelone.net",
            "reboot-reasons": ["pending-update"],
            "self-protection-enabled": true,
            "site": "EMEA"
        }"#;
        let v = parse_agent_status(raw).expect("valid JSON");
        assert_eq!(v["active_threats_present"], false);
        assert_eq!(v["agent_id"], "abc-123");
        assert_eq!(v["agent_install_time"], "2024-01-15T10:30:00Z");
        assert_eq!(v["agent_ppl"], true);
        assert_eq!(v["agent_running"], true);
        assert_eq!(v["agent_version"], "23.4.2.1");
        assert_eq!(v["detection_mode"], "Protect");
        assert_eq!(v["enforcing_security"], true);
        // +00:00 offset canonicalised to Zulu; fractional seconds preserved.
        assert_eq!(v["last_seen"], "2026-05-29T08:00:00.000Z");
        // mgmt-url → management_url (the one non-mechanical rename).
        assert_eq!(v["management_url"], "https://example.sentinelone.net");
        assert_eq!(v["reboot_reasons"][0], "pending-update");
        assert_eq!(v["self_protection_enabled"], true);
        assert_eq!(v["site"], "EMEA");
    }

    /// Unknown / missing fields are tolerated: a partial payload deserializes
    /// (forward-compatibility), unknown keys are ignored, absent keys become null.
    #[test]
    fn parse_agent_status_is_forward_compatible() {
        let raw = r#"{"agent-running": true, "unknown-future-field": 42}"#;
        let v = parse_agent_status(raw).expect("partial JSON");
        assert_eq!(v["agent_running"], true);
        assert!(v["agent_id"].is_null());
        assert!(v["site"].is_null());
        // The unknown key must not leak into the snake-case output.
        assert!(v.get("unknown_future_field").is_none());
    }

    /// Malformed JSON surfaces as an error (SentinelOne present but broken),
    /// never a silent empty object.
    #[test]
    fn parse_agent_status_rejects_garbage() {
        assert!(parse_agent_status("not json").is_err());
    }

    /// Zulu canonicalisation: zero-offset forms collapse to `Z`; already-Zulu
    /// and non-UTC offsets / zone-less strings pass through unchanged (no
    /// time-zone arithmetic).
    #[test]
    fn normalize_utc_iso8601_canonicalises_zero_offset_only() {
        // Already Zulu — untouched.
        assert_eq!(normalize_utc_iso8601("2026-05-29T08:00:00Z"), "2026-05-29T08:00:00Z");
        // +00:00 / -00:00 → Z, fractional seconds preserved.
        assert_eq!(
            normalize_utc_iso8601("2026-05-29T11:15:25.000+00:00"),
            "2026-05-29T11:15:25.000Z"
        );
        assert_eq!(normalize_utc_iso8601("2026-05-29T11:15:25-00:00"), "2026-05-29T11:15:25Z");
        // Non-UTC offset — left verbatim (still an unambiguous instant).
        assert_eq!(
            normalize_utc_iso8601("2026-05-29T13:15:25+02:00"),
            "2026-05-29T13:15:25+02:00"
        );
        // Zone-less local time — left verbatim.
        assert_eq!(normalize_utc_iso8601("2026-05-29T11:15:25"), "2026-05-29T11:15:25");
    }

    /// Recursive search finds nested matches case-insensitively and returns
    /// every occurrence (array semantics, not LastOrDefault).
    #[test]
    fn find_files_recursive_collects_all_case_insensitive() {
        let tmp = std::env::temp_dir().join(format!("s1_test_{}", std::process::id()));
        let nested = tmp.join("22.1.1").join("bin");
        std::fs::create_dir_all(&nested).expect("create temp dirs");
        // Two matches at different depths + a non-match.
        std::fs::write(tmp.join("SentinelCtl.exe"), b"x").expect("write top");
        std::fs::write(nested.join("sentinelctl.exe"), b"x").expect("write nested");
        std::fs::write(nested.join("other.exe"), b"x").expect("write other");

        let found = find_files_recursive(&tmp, "SentinelCtl.exe", 8);
        assert_eq!(found.len(), 2, "both case variants at both depths");

        // Depth bound: 0 levels means top-level only.
        let shallow = find_files_recursive(&tmp, "SentinelCtl.exe", 0);
        assert_eq!(shallow.len(), 1, "depth 0 sees only the top-level file");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
