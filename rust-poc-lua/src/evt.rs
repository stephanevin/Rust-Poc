//! Windows Event Log (EvtQuery / EvtRender) queries with structured XML
//! extraction.
//!
//! Generic consumers of this module:
//! - `bitlocker.rs` — reads `Microsoft-Windows-BitLocker/BitLocker Management`
//!   for backup and key-rotation events.
//! - `cloud.rs` — reads MDM-Admin and MDM-Sync channels for sync status events
//!   (pairs EventID 208/209 via `system_attrs["ProcessID"]`/`["ThreadID"]`).
//!
//! ## Design
//!
//! We use `EvtRender(EvtRenderEventXml)` and a minimal XML scanner.
//! The alternative — `EvtCreateRenderContext` + `EvtRenderEventValues` —
//! is faster but requires hard-coding every value path up front; the XML
//! route keeps the binding generic over `<Data Name="X">Y</Data>` shapes
//! and remains plenty fast for the small number of events these channels
//! typically accumulate (< 50–100 lifetime entries per channel).
//!
//! ## Mirror in `ComplianceApp`
//!
//! `Components.Windows.EventLog.EventLogService.GetEvents` /
//! `GetEventsByDate` (`components/Components.Windows/EventLog/`).  Same
//! XPath template `*[System[(EventID=N) and TimeCreated[@SystemTime>='...']]]`,
//! same `<Data Name="X">` extraction via `EventRecord.GetEventData(name)`.
//!
//! ## `Provider[@Name]` predicate — perf optimisation
//!
//! When `query_events` receives a non-`None` `provider`, the XPath
//! gains a `Provider[@Name='X']` predicate as its **first** clause.
//! This is the same shape that
//! `Get-WinEvent -FilterHashtable @{ProviderName='X'; Id=N}` builds
//! under the hood: PowerShell wraps it in a `<QueryList>` XML envelope,
//! but the inner XPath is identical.  The Event Log service maintains
//! a per-Provider index in every `.evtx` file, so adding this clause
//! lets it skip directly to the matching events instead of scanning
//! the channel — a meaningful speed-up on shared channels and
//! harmless on dedicated ones.

// All Win32/EvtAPI out-params are passed as `&mut local` — matches the
// idiom used in `wts.rs`, `registry.rs`, etc.  `doc_markdown` is also
// silenced module-wide because the prose mentions Win32 identifiers
// (`EvtQuery`, `EvtRender`, …) and product names ("BitLocker") that
// trip the lint even when backticked elsewhere.
#![allow(clippy::borrow_as_ptr, clippy::ref_as_ptr, clippy::doc_markdown)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use tracing::debug;
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
    EvtRender, EvtRenderEventXml,
};
use windows::core::PCWSTR;

/// One event extracted from a channel.
#[derive(Debug, Clone)]
pub(super) struct EventRecord {
    /// `<TimeCreated SystemTime="...">` attribute as raw ISO 8601
    /// (e.g. `"2024-01-15T10:30:00.1234567Z"`).  Kept verbatim — the
    /// fractional-second precision varies by provider and we leave any
    /// downstream normalisation to the caller.
    pub time_created: String,
    /// Raw attributes collected from every child element of `<System>`,
    /// keyed by attribute name (e.g. `"ProcessID"`, `"ThreadID"`,
    /// `"ActivityID"`, `"UserID"`, `"Name"`, `"Guid"`, …).
    ///
    /// Values are stored as raw strings — the caller is responsible for
    /// parsing to any required numeric or structured type.  This keeps
    /// `evt.rs` free of consumer-specific knowledge (e.g. MDM needs
    /// `ProcessID`/`ThreadID` as `u32` for sync-event pairing; BitLocker
    /// never reads these fields at all).
    pub system_attrs: HashMap<String, String>,
    /// `<EventData>/<Data Name="X">Y</Data>` pairs.  Empty when the
    /// event has no named user-data.
    pub event_data: HashMap<String, String>,
}

/// Queries `channel` for events matching `event_id`, optionally
/// restricted to a single Provider name.
///
/// - `provider` — optional `<Provider Name="X">` filter.  When `Some`,
///   the XPath predicate becomes
///   `Provider[@Name='X'] and (EventID=N) [and …]`.  Useful to avoid
///   cross-provider matches on shared channels (`Application`,
///   `System`); harmless on dedicated channels.
/// - `since` — optional ISO 8601 lower bound on `TimeCreated`.
/// - `descending` — when `true`, returns events newest-first
///   (`EvtQueryReverseDirection`).  Used by consumers that only need
///   the most recent matching event (e.g. key-rotation checks).
///
/// Returns `Ok(vec![])` when the channel exists but has no matching
/// events.  Returns `Err` only on `EvtQuery` failures (channel does not
/// exist, access denied, malformed query) — the caller records the
/// diagnostic.
pub(super) fn query_events(
    channel: &str,
    event_id: u32,
    provider: Option<&str>,
    since: Option<&str>,
    descending: bool,
) -> Result<Vec<EventRecord>, String> {
    // Mirror of `Components.Windows/EventLog/Services/EventLogService.cs::GetEvents`
    // — XPath is `*[System[(EventID=N) [and TimeCreated[@SystemTime>='X']]]]`,
    // optionally prefixed with a `Provider[@Name='X']` predicate.
    let mut predicates: Vec<String> = Vec::with_capacity(3);
    if let Some(name) = provider {
        // XPath 1.0: attribute values use single quotes; the provider
        // name is a fixed identifier (no apostrophes), so no escaping.
        predicates.push(format!("Provider[@Name='{name}']"));
    }
    predicates.push(format!("(EventID={event_id})"));
    if let Some(s) = since {
        predicates.push(format!("TimeCreated[@SystemTime>='{s}']"));
    }
    let query_str = format!("*[System[{}]]", predicates.join(" and "));

    let channel_w = utf16_z(channel);
    let query_w = utf16_z(&query_str);

    let mut flags = EvtQueryChannelPath.0;
    if descending {
        flags |= EvtQueryReverseDirection.0;
    }

    // SAFETY: both wide buffers outlive the call; passing None for the
    // session selects the local computer; the returned handle is closed
    // below via EvtClose.
    let handle: EVT_HANDLE = unsafe {
        EvtQuery(
            None,
            PCWSTR(channel_w.as_ptr()),
            PCWSTR(query_w.as_ptr()),
            flags,
        )
    }
    .map_err(|e| format!("EvtQuery({channel}, ID={event_id}): {e}"))?;

    let result = collect_events(handle);

    // SAFETY: handle was returned by a successful EvtQuery — EvtClose is
    // the documented release mechanism and is idempotent w.r.t. errors.
    unsafe {
        let _ = EvtClose(handle);
    }

    // Single boundary trace: query string + outcome.  Enough to diagnose
    // a future "zero events but we expected some" bug without flooding
    // the log on a successful run.
    match &result {
        Ok(records) => debug!(
            channel,
            event_id,
            query = %query_str,
            returned = records.len(),
            "EvtQuery completed"
        ),
        Err(e) => debug!(channel, event_id, query = %query_str, error = %e, "EvtQuery failed"),
    }
    result
}

/// Drains the query into a `Vec<EventRecord>`, batching `EvtNext` calls.
///
/// `EvtNext` in windows-rs 0.62 takes `&mut [isize]` (the raw value
/// behind `EVT_HANDLE`'s `repr(transparent)` newtype), so the local
/// buffer is `[isize; BATCH]` and each entry is wrapped into
/// `EVT_HANDLE(raw)` on the consumer side.
fn collect_events(query_handle: EVT_HANDLE) -> Result<Vec<EventRecord>, String> {
    const BATCH: usize = 16;
    let mut records = Vec::new();

    loop {
        let mut raw_handles: [isize; BATCH] = [0; BATCH];
        let mut returned: u32 = 0;
        // SAFETY: raw_handles is BATCH * size_of::<isize>() bytes; the
        // API writes at most BATCH handles and reports the count via
        // `returned`.  Timeout=INFINITE; flags=0 (default).
        let ok = unsafe { EvtNext(query_handle, &mut raw_handles, u32::MAX, 0, &mut returned) };

        match ok {
            Err(e) if e.code() == ERROR_NO_MORE_ITEMS.into() => break,
            Err(e) => return Err(format!("EvtNext: {e}")),
            Ok(()) => {}
        }
        if returned == 0 {
            break;
        }

        let take = (returned as usize).min(BATCH);
        for &raw in &raw_handles[..take] {
            let ev = EVT_HANDLE(raw);
            if let Some(rec) = render_event(ev) {
                records.push(rec);
            }
            // Silent render-failure is acceptable here: a single
            // malformed event must not abort the batch.  The caller's
            // boundary trace (`returned = records.len()`) lets the
            // operator detect a wholesale parser regression — if
            // raw count diverges from kept count systematically, the
            // bug is in `render_event`/`parse_event_xml`, not the
            // query.

            // SAFETY: `raw` was just returned by EvtNext; EVT_HANDLE
            // wraps it transparently, so EvtClose receives the same
            // value the kernel handed us.
            unsafe {
                let _ = EvtClose(ev);
            }
        }
    }

    Ok(records)
}

/// Renders one event handle via `EvtRender(EvtRenderEventXml)` and
/// parses the result.
///
/// Returns `None` silently when rendering fails — a single malformed
/// event must not abort the whole iteration.
fn render_event(event: EVT_HANDLE) -> Option<EventRecord> {
    // Step 1: size probe.  Per MSDN, calling with a zero-sized buffer
    // returns ERROR_INSUFFICIENT_BUFFER and writes the required byte
    // count into `buffer_used`.
    let mut buffer_used: u32 = 0;
    let mut property_count: u32 = 0;
    // SAFETY: buffer=None + buffersize=0 is the documented size-probe
    // form for EvtRender.
    let _ = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut buffer_used,
            &mut property_count,
        )
    };
    if buffer_used == 0 {
        return None;
    }

    // Step 2: allocate u16 buffer (EvtRender writes UTF-16 LE).
    // `buffer_used` is bytes; round up to u16 count and add 1 to keep
    // room for an explicit trailing NUL in pathological cases.
    let u16_capacity = (buffer_used as usize).div_ceil(2) + 1;
    let mut buf: Vec<u16> = vec![0u16; u16_capacity];
    let buf_bytes = u32::try_from(buf.len() * 2).ok()?;

    // SAFETY: buf is a u16 vec; EvtRender writes a UTF-16 LE string
    // whose size in bytes never exceeds `buf_bytes` (we sized it from
    // the probe + slack).
    let ok = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            buf_bytes,
            Some(buf.as_mut_ptr().cast()),
            &mut buffer_used,
            &mut property_count,
        )
    };
    if ok.is_err() {
        return None;
    }

    // EvtRender writes a NUL-terminated UTF-16 string and `buffer_used`
    // bytes INCLUDES the terminator.  Convert byte count → u16 count
    // and trim trailing NULs defensively.
    let u16_count = (buffer_used as usize) / 2;
    let trimmed_slice = &buf[..u16_count];
    let xml = OsString::from_wide(trimmed_slice)
        .to_string_lossy()
        .trim_end_matches('\0')
        .to_string();

    Some(parse_event_xml(&xml))
}

// ---------------------------------------------------------------------------
// Minimal XML scanner — extracts TimeCreated@SystemTime, System child
// element attributes, and EventData/Data[@Name] values.
// ---------------------------------------------------------------------------

/// Parses an `EvtRenderEventXml` payload into an `EventRecord`.
///
/// Three extractions:
/// - `<TimeCreated SystemTime="..." …/>` (inside `<System>`) → `time_created`
/// - all attributes on every child element of `<System>` (flattened by
///   attribute name) → `system_attrs`
/// - every `<Data Name="X">Y</Data>` inside `<EventData>` → `event_data`
///
/// The scanner is deliberately ad-hoc — pulling in `quick-xml` would
/// add a runtime dependency for what is, structurally, a handful of
/// well-known patterns emitted by a small set of Microsoft providers.
fn parse_event_xml(xml: &str) -> EventRecord {
    let time_created = extract_attribute(xml, "TimeCreated", "SystemTime").unwrap_or_default();
    let system_attrs = extract_system_attrs(xml);
    let event_data = extract_event_data(xml);
    EventRecord {
        time_created,
        system_attrs,
        event_data,
    }
}

/// Collects all attributes from every child element of `<System>` into a
/// flat map keyed by attribute name.
///
/// Attribute values are stored verbatim as `String` — callers parse them
/// to the required type (e.g. `s.parse::<u32>().ok()` for numeric fields).
///
/// Accepts both `"` and `'` as the quoting character (same rationale as
/// [`extract_attribute`] and [`extract_event_data`]).
fn extract_system_attrs(xml: &str) -> HashMap<String, String> {
    let Some(sys_start) = xml.find("<System") else {
        return HashMap::new();
    };
    let after_sys = &xml[sys_start..];
    let Some(sys_end) = after_sys.find("</System>") else {
        return HashMap::new();
    };

    let mut out = HashMap::new();
    let mut rest = &after_sys[..sys_end];
    while let Some(lt) = rest.find('<') {
        rest = &rest[lt + 1..];
        // Skip closing tags (</…) and XML declarations (<!…).
        if matches!(rest.as_bytes().first(), Some(b'/' | b'!') | None) {
            continue;
        }
        let Some(gt) = rest.find('>') else {
            break;
        };
        let tag_body = &rest[..gt];
        if let Some(attr_start) = tag_body.find(|c: char| c.is_ascii_whitespace()) {
            scan_attrs_into(&tag_body[attr_start..], &mut out);
        }
        rest = &rest[gt + 1..];
    }
    out
}

/// Scans the attribute section of an opening tag (the text between the tag
/// name and the closing `>`) and inserts every `name=QUOTE…QUOTE` pair into
/// `out`.  Accepts both `"` and `'` as the quoting character.
///
/// Values are stored as raw strings; parsing (e.g. to `u32`) is left to the
/// caller.  This function is a pure string scanner and never allocates beyond
/// the entries it inserts into `out`.
fn scan_attrs_into(src: &str, out: &mut HashMap<String, String>) {
    let mut rest = src;
    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.starts_with('/') {
            break;
        }
        let name_end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != ':' && c != '-')
            .unwrap_or(rest.len());
        if name_end == 0 {
            rest = rest.get(1..).unwrap_or_default();
            continue;
        }
        let name = &rest[..name_end];
        let after_name = rest[name_end..].trim_start();
        let Some(after_eq) = after_name.strip_prefix('=') else {
            // No `=` after the name — malformed attribute (e.g. bare token
            // like `disabled` or XML tronqué).  Advance `rest` past the name
            // so the outer loop makes forward progress and does not spin.
            rest = &rest[name_end..];
            continue;
        };
        let after_eq_trimmed = after_eq.trim_start();
        match parse_quoted_value(after_eq_trimmed) {
            Some((value, remainder)) => {
                out.insert(name.to_string(), value.to_string());
                rest = remainder;
            }
            None if after_eq_trimmed.starts_with(['"', '\'']) => break,
            None => {
                // Unquoted value — advance one byte past `=` and keep scanning.
                rest = after_eq.get(1..).unwrap_or_default();
            }
        }
    }
}

/// Parses `QUOTE value QUOTE` at the start of `src` and returns the inner
/// value plus the remainder after the closing quote.  Accepts `"` and `'`
/// symmetrically — shared by [`scan_attrs_into`] and [`extract_quoted_value`].
fn parse_quoted_value(src: &str) -> Option<(&str, &str)> {
    let mut chars = src.chars();
    let quote = chars.next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let inner = &src[quote.len_utf8()..];
    let end = inner.find(quote)?;
    let value = &inner[..end];
    let remainder = &inner[end + quote.len_utf8()..];
    Some((value, remainder))
}

/// Finds `<tag ... attr=QUOTE value QUOTE ...>` and returns the value.
///
/// Accepts **both** `"` and `'` as the quoting character: the XML 1.0
/// spec [§3.1] explicitly allows either delimiter, and `EvtRender` in
/// fact emits attributes single-quoted (`Name='X'`) on Windows 10+ —
/// the same shape PowerShell's `EventLogRecord.ToXml()` returns.
/// Previous implementations of this function only matched `"`,
/// silently dropping every BitLocker event attribute on the floor.
///
/// Returns `None` when the tag is absent or no matching attribute is
/// found.  Does not normalise XML entity references inside the value
/// (BitLocker events don't contain any).
fn extract_attribute(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_needle = format!("<{tag}");
    let tag_start = xml.find(&tag_needle)?;
    // Limit search to the tag's open: from `<TimeCreated` to the next `>`.
    let after_tag = &xml[tag_start..];
    let tag_end = after_tag.find('>')?;
    let tag_open = &after_tag[..tag_end];

    extract_quoted_value(tag_open, attr)
}

/// Extracts every `<Data Name=QUOTE X QUOTE>Y</Data>` pair inside
/// `<EventData>`.  Accepts either quote style on the `Name` attribute
/// (same rationale as [`extract_attribute`]).
///
/// Handles both shapes XML allows for an element with no children:
/// - **paired**: `<Data Name='X'>Y</Data>` — value is `Y`.
/// - **self-closing**: `<Data Name='X'/>` — value is the empty string.
///
/// The self-closing detection matters even though BitLocker never emits
/// that shape today: without it, the scanner would consume the *next*
/// `<Data>`'s content as the self-closed Data's value, silently
/// corrupting two entries at once.
///
/// Entity references in the value (`&amp;`, `&lt;`, `&apos;`, `&quot;`,
/// `&gt;`) are returned **as-is**, without decoding.  None of the BitLocker
/// payloads contain entity-encoded characters (GUIDs and drive letters
/// only), so this is a deliberate non-feature — adding a decode pass
/// would surface as a behaviour change for any future caller.
fn extract_event_data(xml: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(block_start) = xml.find("<EventData") else {
        return out;
    };
    let after_open = &xml[block_start..];
    let Some(close_idx) = after_open.find("</EventData>") else {
        return out;
    };
    let block = &after_open[..close_idx];

    let mut rest = block;
    let data_open = "<Data";
    while let Some(rel) = rest.find(data_open) {
        // Must be followed by whitespace or `>` so we don't match a
        // hypothetical `<DataSibling>` tag.  In practice EvtRender only
        // ever emits `<Data ` (space) or `<Data>`, but a defensive
        // check keeps the scanner robust.
        let after_prefix_pos = rel + data_open.len();
        let next_byte = rest.as_bytes().get(after_prefix_pos).copied();
        if !matches!(next_byte, Some(b' ' | b'>')) {
            // Skip past this false match and try again.
            rest = &rest[after_prefix_pos..];
            continue;
        }

        let tag_rest = &rest[after_prefix_pos..];
        let Some(gt) = tag_rest.find('>') else { break };
        let tag_attrs_raw = &tag_rest[..gt];
        // Self-closing tags end with `/` (modulo trailing whitespace).
        let trimmed = tag_attrs_raw.trim_end();
        let is_self_closing = trimmed.ends_with('/');
        // Strip the trailing `/` so `extract_quoted_value` doesn't see it.
        let tag_attrs = if is_self_closing {
            trimmed.trim_end_matches('/').trim_end()
        } else {
            tag_attrs_raw
        };

        let name = extract_quoted_value(tag_attrs, "Name");
        // `<Data>` without a `Name` attribute is positional and gets
        // silently skipped — matches the C# `EventRecord.GetEventData(name)`
        // behaviour which only addresses named items.

        if is_self_closing {
            if let Some(n) = name {
                out.insert(n, String::new());
            }
            rest = &tag_rest[gt + 1..];
        } else {
            let after_gt = &tag_rest[gt + 1..];
            let Some(close_data) = after_gt.find("</Data>") else {
                break;
            };
            let value = &after_gt[..close_data];
            if let Some(n) = name {
                out.insert(n, value.to_string());
            }
            rest = &after_gt[close_data + "</Data>".len()..];
        }
    }
    out
}

/// Locates `attr=QUOTE…QUOTE` in `haystack` and returns the contents
/// between the matching pair of quotes.  Accepts `"` and `'` symmetrically.
///
/// The match is **anchored on its left**: the `attr` token must be
/// preceded by either the start of the haystack or whitespace.  This
/// prevents `OtherName=…` from matching a query for `Name`, a trap
/// that any naive `find(format!("{attr}="))` falls into.
///
/// Used by [`extract_attribute`] and [`extract_event_data`]; kept as a
/// shared helper so the dual-quote rule lives in exactly one place.
fn extract_quoted_value(haystack: &str, attr: &str) -> Option<String> {
    let attr_eq = format!("{attr}=");
    let mut search_start = 0usize;
    // Walk over every occurrence of `attr=` and accept the first one
    // whose left neighbour is start-of-string or ASCII whitespace.
    let after_eq_start = loop {
        let rel = haystack[search_start..].find(&attr_eq)?;
        let pos = search_start + rel;
        let anchored = pos == 0
            || haystack
                .as_bytes()
                .get(pos - 1)
                .is_some_and(u8::is_ascii_whitespace);
        if anchored {
            break pos + attr_eq.len();
        }
        // Advance past this false match and try again.  Adding 1 is
        // enough: even if `attr_eq` itself contains a recursive
        // sub-match, the next iteration's `find` will locate it.
        search_start = pos + 1;
    };
    let after_eq = &haystack[after_eq_start..];
    parse_quoted_value(after_eq).map(|(value, _)| value.to_string())
}

/// Converts a Rust `&str` to a NUL-terminated UTF-16 wide buffer
/// suitable for passing as `PCWSTR(ptr)` to Win32 APIs.
fn utf16_z(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

// ---------------------------------------------------------------------------
// Tests — pure XML-parser unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{extract_attribute, extract_event_data, extract_quoted_value, parse_event_xml};

    /// Real-world BitLocker management event 783, as emitted by
    /// `EvtRender(EvtRenderEventXml)` — single-quoted attribute values
    /// throughout.  This is the EXACT shape returned on a domain-joined
    /// Windows 11 endpoint (captured via PowerShell `.ToXml()`, which
    /// returns the same XML bytes EvtRender writes).  Pin it as a
    /// regression test: the previous scanner only matched double quotes
    /// and silently dropped every BitLocker `<Data>` payload on the
    /// floor.
    const SAMPLE_REAL_BITLOCKER_783: &str = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-BitLocker-API' Guid='{5d674230-ca9f-11da-a94d-0800200c9a66}'/><EventID>783</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2026-04-20T08:43:22.2251580Z'/><EventRecordID>435</EventRecordID><Correlation ActivityID='{2cae86c5-ef1e-41dc-8d87-e3f9fbe8e8bf}'/><Execution ProcessID='4728' ThreadID='3228'/><Channel>Microsoft-Windows-BitLocker/BitLocker Management</Channel><Computer>EMEAaTTn8so0m9S.clients.pharma.aventis.com</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='IdentificationGUID'>{5e45b5f0-de5c-4998-82b7-f3673dae4ac9}</Data><Data Name='VolumeName'>\\?\\Volume{720dbf56-26db-40ec-b3a2-24fd3de76909}</Data><Data Name='VolumeMountPoint'>C:</Data><Data Name='ProtectorGUID'>{85a34f7b-7471-4a77-ae0a-85c72d4cb378}</Data></EventData></Event>";

    /// Same content, but with the historic double-quote shape — must
    /// still parse identically.  XML 1.0 §3.1 allows either delimiter.
    const SAMPLE_DOUBLE_QUOTED: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-BitLocker-API"/>
    <EventID>845</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2024-01-15T10:30:00.1234567Z"/>
  </System>
  <EventData>
    <Data Name="ProtectorGUID">{abc-123-def}</Data>
    <Data Name="VolumeMountPoint">C:</Data>
  </EventData>
</Event>"#;

    #[test]
    fn extracts_time_created_double_quoted() {
        let t = extract_attribute(SAMPLE_DOUBLE_QUOTED, "TimeCreated", "SystemTime");
        assert_eq!(t.as_deref(), Some("2024-01-15T10:30:00.1234567Z"));
    }

    /// Regression — EvtRender emits single quotes; the previous scanner
    /// only looked for double quotes and returned `None` here.
    #[test]
    fn extracts_time_created_single_quoted_real_bitlocker() {
        let t = extract_attribute(SAMPLE_REAL_BITLOCKER_783, "TimeCreated", "SystemTime");
        assert_eq!(t.as_deref(), Some("2026-04-20T08:43:22.2251580Z"));
    }

    #[test]
    fn extracts_named_event_data_double_quoted() {
        let d = extract_event_data(SAMPLE_DOUBLE_QUOTED);
        assert_eq!(d.get("ProtectorGUID").map(String::as_str), Some("{abc-123-def}"));
        assert_eq!(d.get("VolumeMountPoint").map(String::as_str), Some("C:"));
        assert_eq!(d.len(), 2);
    }

    /// Regression — the bug that explains every zero count in the
    /// `_debug.bitlocker_recovery_key` block on the test machine.
    /// `ProtectorGUID` must come out matching the exact value seen in
    /// the captured XML, not `None` and not empty string.
    #[test]
    fn extracts_named_event_data_single_quoted_real_bitlocker() {
        let d = extract_event_data(SAMPLE_REAL_BITLOCKER_783);
        assert_eq!(
            d.get("ProtectorGUID").map(String::as_str),
            Some("{85a34f7b-7471-4a77-ae0a-85c72d4cb378}")
        );
        assert_eq!(d.get("VolumeMountPoint").map(String::as_str), Some("C:"));
        assert_eq!(
            d.get("IdentificationGUID").map(String::as_str),
            Some("{5e45b5f0-de5c-4998-82b7-f3673dae4ac9}")
        );
        assert_eq!(d.len(), 4);
    }

    #[test]
    fn parses_full_event_double_quoted() {
        let rec = parse_event_xml(SAMPLE_DOUBLE_QUOTED);
        assert_eq!(rec.time_created, "2024-01-15T10:30:00.1234567Z");
        assert_eq!(rec.event_data.len(), 2);
        // SAMPLE_DOUBLE_QUOTED has no <Execution> tag — ProcessID/ThreadID absent.
        assert!(!rec.system_attrs.contains_key("ProcessID"));
        assert!(!rec.system_attrs.contains_key("ThreadID"));
    }

    /// Regression — `SAMPLE_REAL_BITLOCKER_783` contains
    /// `<Execution ProcessID='4728' ThreadID='3228'/>` (single-quoted).
    /// The scanner must extract both as raw strings into `system_attrs`.
    #[test]
    fn parses_full_event_single_quoted_real_bitlocker() {
        let rec = parse_event_xml(SAMPLE_REAL_BITLOCKER_783);
        assert_eq!(rec.time_created, "2026-04-20T08:43:22.2251580Z");
        assert_eq!(rec.event_data.len(), 4);
        assert_eq!(
            rec.event_data.get("ProtectorGUID").map(String::as_str),
            Some("{85a34f7b-7471-4a77-ae0a-85c72d4cb378}")
        );
        assert_eq!(rec.system_attrs.get("ProcessID").map(String::as_str), Some("4728"));
        assert_eq!(rec.system_attrs.get("ThreadID").map(String::as_str), Some("3228"));
    }

    /// `<Execution ProcessID="…" ThreadID="…"/>` with double-quoted
    /// attributes (also valid per XML 1.0 §3.1).
    #[test]
    fn parses_execution_attributes_double_quoted() {
        let xml = r#"<Event><System><TimeCreated SystemTime="2024-01-15T10:30:00Z"/><Execution ProcessID="1000" ThreadID="2000"/></System><EventData></EventData></Event>"#;
        let rec = parse_event_xml(xml);
        assert_eq!(rec.system_attrs.get("ProcessID").map(String::as_str), Some("1000"));
        assert_eq!(rec.system_attrs.get("ThreadID").map(String::as_str), Some("2000"));
    }

    /// Non-numeric `ProcessID` and empty `ThreadID` — stored verbatim in
    /// `system_attrs`.  The caller (e.g. `cloud.rs`) is responsible for
    /// `.parse::<u32>().ok()` and will naturally get `None` for non-numeric
    /// values.
    #[test]
    fn parses_execution_raw_strings_stored_verbatim() {
        let xml = "<Event><System><Execution ProcessID='abc' ThreadID=''/></System></Event>";
        let rec = parse_event_xml(xml);
        assert_eq!(rec.system_attrs.get("ProcessID").map(String::as_str), Some("abc"));
        assert_eq!(rec.system_attrs.get("ThreadID").map(String::as_str), Some(""));
    }

    /// An event with no `<EventData>` block — common for events that
    /// carry only `<System>` metadata.
    #[test]
    fn missing_event_data_returns_empty_map() {
        let xml = r#"<Event><System><TimeCreated SystemTime="2024-01-15T10:30:00Z"/></System></Event>"#;
        let rec = parse_event_xml(xml);
        assert_eq!(rec.time_created, "2024-01-15T10:30:00Z");
        assert!(rec.event_data.is_empty());
        // No <Execution> tag → ProcessID absent from system_attrs.
        assert!(!rec.system_attrs.contains_key("ProcessID"));
    }

    /// A bare `<Data>` element without `Name="..."` must be ignored —
    /// some legacy events emit positional `<Data>` children.
    #[test]
    fn unnamed_data_is_ignored() {
        let xml = r#"<Event><EventData><Data>positional</Data><Data Name="Keyed">v</Data></EventData></Event>"#;
        let rec = parse_event_xml(xml);
        assert_eq!(rec.event_data.len(), 1);
        assert_eq!(rec.event_data.get("Keyed").map(String::as_str), Some("v"));
    }

    /// Mixed-quote edge case: an event that mixes `'` and `"` on
    /// different attributes inside the same tag.  Never observed in
    /// practice, but the dual-quote logic should handle it without
    /// crashing — each attribute matches its own opening quote.
    #[test]
    fn mixed_quote_styles_within_same_tag() {
        let xml = r#"<Event><System><TimeCreated SystemTime='2024-01-15T10:30:00Z' Foo="bar"/></System></Event>"#;
        let t = extract_attribute(xml, "TimeCreated", "SystemTime");
        assert_eq!(t.as_deref(), Some("2024-01-15T10:30:00Z"));
        let f = extract_attribute(xml, "TimeCreated", "Foo");
        assert_eq!(f.as_deref(), Some("bar"));
    }

    // ----------------------------------------------------------------
    // Regression / defensive tests for the latent XML-scanner pitfalls
    // ----------------------------------------------------------------
    //
    // BitLocker's EvtRender output never exercises most of these shapes
    // today (always paired tags with content, no entity references),
    // but `extract_event_data` is a generic scanner shared by any future
    // event consumer.  Each test pins one rule so the scanner can be
    // refactored without silently regressing.

    /// Self-closing `<Data Name='X'/>` must produce `X → ""` and **not**
    /// consume the next `<Data>`'s content as its value.
    ///
    /// Before the dedicated self-closing branch was added, the scanner
    /// looked unconditionally for the next `</Data>` after `>`, so a
    /// self-closed entry stole the subsequent entry's value and dropped
    /// the subsequent entry's key.  This test would have caught that.
    #[test]
    fn self_closing_data_does_not_steal_next_value() {
        let xml = "<Event><EventData><Data Name='X'/><Data Name='Y'>val</Data></EventData></Event>";
        let d = extract_event_data(xml);
        assert_eq!(d.get("X").map(String::as_str), Some(""));
        assert_eq!(d.get("Y").map(String::as_str), Some("val"));
        assert_eq!(d.len(), 2);
    }

    /// Self-closing with trailing whitespace before `/` must still be
    /// detected: `<Data Name='X' />` is legal XML.
    #[test]
    fn self_closing_data_tolerates_whitespace_before_slash() {
        let xml = "<Event><EventData><Data Name='X' /><Data Name='Y'>val</Data></EventData></Event>";
        let d = extract_event_data(xml);
        assert_eq!(d.get("X").map(String::as_str), Some(""));
        assert_eq!(d.get("Y").map(String::as_str), Some("val"));
    }

    /// Paired `<Data Name='X'></Data>` (empty content) must produce
    /// `X → ""`, distinct from "key absent".
    #[test]
    fn empty_paired_data_value_yields_empty_string() {
        let xml = "<Event><EventData><Data Name='X'></Data></EventData></Event>";
        let d = extract_event_data(xml);
        assert_eq!(d.get("X").map(String::as_str), Some(""));
        assert_eq!(d.len(), 1);
    }

    /// Entity references in the value are returned **verbatim**, no
    /// decoding.  Documents the deliberate non-feature: BitLocker
    /// payloads (GUIDs, drive letters) never contain entities, so
    /// adding a decode pass would be surface-bloat.  If a future
    /// consumer needs decoded text, decode on its side, not here.
    #[test]
    fn entity_references_returned_verbatim() {
        let xml =
            "<Event><EventData><Data Name='X'>foo &amp; bar &lt;baz&gt;</Data></EventData></Event>";
        let d = extract_event_data(xml);
        assert_eq!(
            d.get("X").map(String::as_str),
            Some("foo &amp; bar &lt;baz&gt;")
        );
    }

    /// An attribute value can legally contain the *other* quote
    /// character (single inside double, double inside single).
    /// `extract_quoted_value` matches the OPENING quote — must not
    /// be fooled by the inner alternate-quote.
    #[test]
    fn attribute_value_can_contain_other_quote_char() {
        let xml = r#"<Event><System><Provider Name="contains 'single' inside"/></System></Event>"#;
        let n = extract_attribute(xml, "Provider", "Name");
        assert_eq!(n.as_deref(), Some("contains 'single' inside"));
    }

    /// `<Data` must be followed by ` ` or `>`.  A look-alike tag
    /// (`<DataXxx>`) must not be parsed as a `<Data>` entry.
    /// Defensive — Microsoft has never emitted such a tag, but the
    /// scanner now refuses it so future schema drift fails loudly
    /// instead of silently mis-parsing.
    #[test]
    fn data_lookalike_tag_is_not_parsed() {
        let xml = "<Event><EventData><DataSibling Name='X'>nope</DataSibling><Data Name='Y'>yes</Data></EventData></Event>";
        let d = extract_event_data(xml);
        assert_eq!(d.get("Y").map(String::as_str), Some("yes"));
        assert_eq!(d.get("X"), None);
        assert_eq!(d.len(), 1);
    }

    /// `<Data>` without a `Name` attribute (positional) is ignored —
    /// previously tested above; this pin re-states the rule next to
    /// the named-data tests for clarity.
    #[test]
    fn positional_data_without_name_attribute_is_skipped() {
        let xml = "<Event><EventData><Data>positional</Data><Data Name='K'>v</Data></EventData></Event>";
        let d = extract_event_data(xml);
        assert_eq!(d.len(), 1);
        assert_eq!(d.get("K").map(String::as_str), Some("v"));
    }

    /// Malformed XML (no closing `</EventData>`) must not panic — the
    /// scanner gives up cleanly and returns the empty map.  Defense
    /// against truncated event renders.
    #[test]
    fn missing_event_data_close_returns_empty_without_panic() {
        let xml = "<Event><EventData><Data Name='X'>truncated";
        let d = extract_event_data(xml);
        assert!(d.is_empty());
    }

    /// Malformed XML (no closing `>` after `<Data `) must not panic.
    #[test]
    fn unterminated_data_tag_returns_partial_without_panic() {
        let xml = "<Event><EventData><Data Name='X' </EventData></Event>";
        // The scanner finds `<Data Name='X' ` followed by `</EventData>`
        // (no `>` inside the EventData span before the close), so it
        // breaks out of the loop cleanly.  The exact map content is
        // less important than the "no panic" guarantee.
        let _ = extract_event_data(xml);
    }

    /// A bare attribute *name* with no `=` (e.g. HTML-style boolean or
    /// truncated XML) must **not** spin the scanner indefinitely.
    ///
    /// Before the fix, `scan_attrs_into` hit `continue` without advancing
    /// `rest` when `strip_prefix('=')` failed, causing an infinite loop on
    /// any malformed event XML.  This test would hang forever under the bug.
    #[test]
    fn scan_attrs_into_bare_name_without_equals_does_not_loop() {
        let xml = "<Event><System><Execution disabled ProcessID='4728'/></System></Event>";
        let rec = parse_event_xml(xml);
        // `disabled` has no `=` → must be skipped; `ProcessID` must still be extracted.
        assert_eq!(rec.system_attrs.get("ProcessID").map(String::as_str), Some("4728"));
    }

    // ----------------------------------------------------------------
    // Direct unit tests for `extract_quoted_value`
    // ----------------------------------------------------------------
    //
    // The dual-quote rule is small enough that exhaustive coverage is
    // cheap and unambiguous — pin every branch.

    #[test]
    fn quoted_value_single_quotes() {
        assert_eq!(
            extract_quoted_value("Name='X' Other='Y'", "Name").as_deref(),
            Some("X")
        );
    }

    #[test]
    fn quoted_value_double_quotes() {
        assert_eq!(
            extract_quoted_value(r#"Name="X" Other="Y""#, "Name").as_deref(),
            Some("X")
        );
    }

    #[test]
    fn quoted_value_empty_string() {
        assert_eq!(extract_quoted_value("Name=''", "Name").as_deref(), Some(""));
        assert_eq!(extract_quoted_value(r#"Name="""#, "Name").as_deref(), Some(""));
    }

    /// Unquoted attribute value is illegal XML but must not produce a
    /// false-positive — return `None` so the caller knows the input is
    /// malformed and can record an error.
    #[test]
    fn quoted_value_unquoted_returns_none() {
        assert_eq!(extract_quoted_value("Name=X", "Name"), None);
    }

    #[test]
    fn quoted_value_missing_attribute_returns_none() {
        assert_eq!(extract_quoted_value("Other='X'", "Name"), None);
    }

    /// No closing quote → `None`, not partial extraction.  Better to
    /// report missing than to return a value that overflows into the
    /// next attribute.
    #[test]
    fn quoted_value_no_closing_quote_returns_none() {
        assert_eq!(extract_quoted_value("Name='unterminated", "Name"), None);
    }

    /// The match must respect attribute *name boundaries*:
    /// `OtherName='X'` must not match a query for `Name`.  Without the
    /// left-anchor in `extract_quoted_value`, `find("Name=")` would
    /// hit `OtherName=` first and return its value instead.
    #[test]
    fn quoted_value_anchors_on_attribute_name_boundary() {
        assert_eq!(
            extract_quoted_value("OtherName='X' Name='Y'", "Name").as_deref(),
            Some("Y")
        );
    }

    /// Boundary check also works when the target attribute is the
    /// FIRST one in the haystack (no whitespace to its left, just
    /// start-of-string).
    #[test]
    fn quoted_value_anchors_at_start_of_string() {
        assert_eq!(
            extract_quoted_value("Name='Y' OtherName='X'", "Name").as_deref(),
            Some("Y")
        );
    }

    /// And when the haystack has *only* the suffix-look-alike (no real
    /// match) — return `None` rather than the look-alike's value.
    #[test]
    fn quoted_value_returns_none_when_only_lookalike_present() {
        assert_eq!(extract_quoted_value("OtherName='X'", "Name"), None);
    }
}
