//! SCCM (Configuration Manager) client health host bindings — deviation #47.
//!
//! Nine bindings mirroring the "SCCM" category of `Win10-Laptop.json`, backed
//! by `ComplianceService/Data/SCCM/SCCM.cs`. Two mechanisms, no process
//! launch:
//!
//! - Six WMI reads against the ConfigMgr client namespaces (`root\ccm` and
//!   children), including one class-method call ([`site_code`]).
//! - Three read-only reads of the ccmeval health report XML, sharing a
//!   memoised cache on `HostState` ([`read_health_report`]).
//!
//! ## Deviation #47 — design notes
//!
//! 1. **Read-only ccmeval.** `SCCM.cs::GetSccmHealthCheck` launches
//!    `ccmeval.exe` and waits up to 5 minutes when the report is missing or
//!    stale. A collector must not spawn processes, so [`read_health_report`]
//!    only parses an existing `C:\Windows\CCM\CcmEvalReport.xml`; an absent
//!    report degrades to `None` (never launches the evaluator).
//! 2. **`client_version` passthrough.** The C# parses the value into a
//!    `System.Version`; we emit the raw `SMS_Client.ClientVersion` string
//!    (identical output, no parse failure path) — same posture as
//!    `cyberark::version`.
//! 3. **`site_code` via WMI class method.** `GetSiteCode` calls the static
//!    `SMS_Client.GetAssignedSite` method (`exec_class_method`), not a query.
//!    No registry fallback — the method is the faithful source.
//! 4. **CIM datetimes -> UTC Zulu.** `SMS_MPListEx.LastUpdateTime` and the
//!    `InventoryActionStatus` dates are WMI DMTF strings
//!    (`yyyyMMddHHmmss.ffffff±UUU`); [`dmtf_to_iso8601`] converts them to
//!    `...Z`, consistent with the gRPC wire contract and the rest of the
//!    crate. The XML `EvaluationTime` is already ISO 8601 Zulu and is passed
//!    through.
//! 5. **No display derivation.** The C# `SccmClientStatus` transformer maps a
//!    `Passed` summary to the localized "Client Healthy" label; we emit the
//!    raw `<Summary>` text and leave the label to the UI (posture of #45/#46).
//!
//! ## Failure semantics
//!
//! - The six WMI bindings record their failure under `sccm:<name>` and return
//!   `nil`/`[]` (handled by the generic `host.rs` WMI helpers).
//! - The three health bindings share one cache; an init failure is recorded
//!   once under `sccm:health_report`. An absent report file is not an error.

// Product/identifier names (SCCM, ccmeval, WMI class names) trip doc_markdown
// in prose; backticking each occurrence hurts readability.
#![allow(clippy::doc_markdown)]

use std::collections::HashMap;

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use serde::Deserialize;
use serde_json::{Value, json};

use super::wmi::Wmi;

/// ConfigMgr client root namespace.
const CCM_NS: &str = r"root\ccm";
/// Location services namespace (management-point list).
const LOCSVC_NS: &str = r"root\ccm\LocationServices";
/// Inventory agent namespace.
const INVAGT_NS: &str = r"root\ccm\InvAgt";
/// Machine policy namespace (component enable/disable config).
const POLICY_NS: &str = r"root\ccm\Policy\Machine";
/// ccmeval client-health report (read-only; never regenerated here).
const CCM_EVAL_REPORT: &str = r"C:\Windows\CCM\CcmEvalReport.xml";

// ---------------------------------------------------------------------------
// WMI marker + output structs for exec_class_method
// ---------------------------------------------------------------------------
//
// Same idiom as `bitlocker.rs`: the `Class` generic is only used by wmi-rs to
// resolve the method signature on the provider — the unit struct never sees an
// instance. The `Out` struct is deserialized from the method's out-params;
// unknown extras (e.g. `ReturnValue`) are ignored by serde.

#[derive(Deserialize)]
#[allow(non_camel_case_types)]
struct SMS_Client;

/// `GetAssignedSite` output parameters — only `sSiteCode` is needed.
#[derive(Deserialize)]
struct GetAssignedSiteOut {
    #[serde(rename = "sSiteCode")]
    s_site_code: Option<String>,
}

// ---------------------------------------------------------------------------
// 1. WMI bindings (root\ccm and children)
// ---------------------------------------------------------------------------

/// `host.sccm_client_version()` — `SMS_Client.ClientVersion`, raw passthrough.
pub(super) fn client_version(wmi: &mut Wmi) -> Result<Option<Value>, String> {
    wmi.query_first_ns(CCM_NS, "SMS_Client", "ClientVersion")
}

/// `host.sccm_site_code()` — assigned site via the `SMS_Client.GetAssignedSite`
/// class method (no input parameters).
pub(super) fn site_code(wmi: &mut Wmi) -> Result<Option<Value>, String> {
    let conn = wmi.connection_ns(CCM_NS)?;
    let out: GetAssignedSiteOut = conn
        .exec_class_method::<SMS_Client, _>("GetAssignedSite", ())
        .map_err(|e| format!("SMS_Client.GetAssignedSite: {e}"))?;
    Ok(out.s_site_code.map(Value::String))
}

/// `host.sccm_current_management_point()` — `SMS_Authority.CurrentManagementPoint`.
pub(super) fn current_management_point(wmi: &mut Wmi) -> Result<Option<Value>, String> {
    wmi.query_first_ns(CCM_NS, "SMS_Authority", "CurrentManagementPoint")
}

/// `host.sccm_mp_last_update_date()` — `SMS_MPListEx.LastUpdateTime`
/// (DMTF) converted to ISO 8601 UTC.
pub(super) fn mp_last_update_date(wmi: &mut Wmi) -> Result<Option<Value>, String> {
    Ok(wmi
        .query_first_ns(LOCSVC_NS, "SMS_MPListEx", "LastUpdateTime")?
        .as_ref()
        .and_then(Value::as_str)
        .and_then(dmtf_to_iso8601)
        .map(Value::String))
}

/// `host.sccm_inventory_status()` — one row per `InventoryActionStatus`
/// instance: type (GUID -> name), report versions, and the two cycle dates
/// (DMTF -> UTC).
pub(super) fn inventory_status(wmi: &mut Wmi) -> Result<Vec<Value>, String> {
    let rows = wmi.query_all_ns(INVAGT_NS, "InventoryActionStatus")?;
    Ok(rows
        .iter()
        .map(|r| {
            let date = |key| obj_string(r, key).as_deref().and_then(dmtf_to_iso8601);
            json!({
                "inventory_type": inventory_name(obj_string(r, "InventoryActionID").as_deref()),
                "last_major_report_version": obj_string(r, "LastMajorReportVersion"),
                "last_minor_report_version": obj_string(r, "LastMinorReportVersion"),
                "last_cycle_started_date": date("LastCycleStartedDate"),
                "last_report_date": date("LastReportDate"),
            })
        })
        .collect())
}

/// `host.sccm_component_status()` — `CCM_InstalledComponent` joined with the
/// per-component `CCM_ComponentClientConfig.Enabled` flag, sorted by display
/// name. Status is `Enabled`/`Disabled` when a config row exists, else
/// `Installed`.
pub(super) fn component_status(wmi: &mut Wmi) -> Result<Vec<Value>, String> {
    let components = wmi.query_all_ns(CCM_NS, "CCM_InstalledComponent")?;
    let configs = wmi.query_all_ns(POLICY_NS, "CCM_ComponentClientConfig")?;

    // Filter Rust-side (mirrors the C# `ComponentName IS NOT NULL AND Enabled
    // IS NOT NULL` WQL predicate) and index by component name.
    let mut enabled_by_name: HashMap<String, bool> = HashMap::new();
    for c in &configs {
        if let (Some(name), Some(enabled)) = (
            obj_string(c, "ComponentName"),
            c.get("Enabled").and_then(Value::as_bool),
        ) {
            enabled_by_name.insert(name, enabled);
        }
    }

    let mut rows: Vec<Value> = components
        .iter()
        .map(|c| {
            let status = match enabled_by_name.get(obj_string(c, "Name").as_deref().unwrap_or("")) {
                Some(true) => "Enabled",
                Some(false) => "Disabled",
                None => "Installed",
            };
            json!({
                "component": obj_string(c, "DisplayName"),
                "version": obj_string(c, "Version"),
                "status": status,
            })
        })
        .collect();

    rows.sort_by(|a, b| {
        a.get("component")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(b.get("component").and_then(Value::as_str).unwrap_or(""))
    });
    Ok(rows)
}

/// Coerces a WMI object property to a comparable string (`SZ` passthrough,
/// numbers stringified) — mirrors the C# `?.Value?.ToString()`.
fn obj_string(v: &Value, key: &str) -> Option<String> {
    match v.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

/// Maps an `InventoryActionID` GUID to its human-readable name; unknown IDs
/// pass through, a missing ID becomes `Unknown` (verbatim from the C#).
fn inventory_name(action_id: Option<&str>) -> String {
    match action_id {
        None => "Unknown",
        Some("{00000000-0000-0000-0000-000000000001}") => "Hardware Inventory",
        Some("{00000000-0000-0000-0000-000000000002}") => "Software Inventory",
        Some("{00000000-0000-0000-0000-000000000003}") => "Discovery",
        Some("{00000000-0000-0000-0000-000000000010}") => "Software File Collection",
        Some("{00000000-0000-0000-0000-000000000011}") => "IDMIF Collection",
        Some(other) => other,
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// 2. DMTF datetime -> ISO 8601 UTC
// ---------------------------------------------------------------------------

/// Converts a WMI DMTF datetime (`yyyyMMddHHmmss.ffffff±UUU`, where `±UUU` is
/// the UTC offset in minutes) to an ISO 8601 UTC string (`...Z`). Returns
/// `None` for malformed or zero-filled values (mirrors the C# `TryParseExact`
/// returning null).
///
/// Computes a Unix-second count from the civil fields (Howard Hinnant
/// `days_from_civil`), applies the offset, then reuses
/// [`super::winver::filetime_to_iso8601`] for the calendar formatting.
fn dmtf_to_iso8601(dmtf: &str) -> Option<String> {
    if dmtf.len() < 14 {
        return None;
    }
    let num = |a: usize, b: usize| dmtf.get(a..b)?.parse::<i64>().ok();
    let year = num(0, 4)?;
    let month = num(4, 6)?;
    let day = num(6, 8)?;
    let hour = num(8, 10)?;
    let minute = num(10, 12)?;
    let second = num(12, 14)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }

    let local_secs =
        days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;

    // Full DMTF (>= 25 chars) carries the signed UTC offset in minutes at
    // position 21 (after `.ffffff`); shorter strings are treated as UTC.
    let offset_minutes = if dmtf.len() >= 25 {
        dmtf.get(21..)?.parse::<i64>().ok()?
    } else {
        0
    };
    let utc_secs = local_secs - offset_minutes * 60;
    if utc_secs < 0 {
        return None;
    }

    let ticks = utc_secs
        .checked_mul(10_000_000)?
        .checked_add(116_444_736_000_000_000)?;
    super::winver::filetime_to_iso8601(ticks)
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Howard Hinnant
/// `days_from_civil`, the inverse of the algorithm in `winver.rs`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------------------------------------------------------------------
// 3. ccmeval health report (read-only XML)
// ---------------------------------------------------------------------------

/// One `<HealthCheck>` row of the ccmeval report.
pub(super) struct HealthEntry {
    pub description: String,
    pub health_check_text: String,
}

/// Parsed `CcmEvalReport.xml` (the ccmeval client-health evaluator output).
pub(super) struct SccmHealthReport {
    pub summary_text: Option<String>,
    pub evaluation_time: Option<String>,
    pub entries: Vec<HealthEntry>,
}

/// Reads and parses `C:\Windows\CCM\CcmEvalReport.xml` if it exists. Returns
/// `Ok(None)` when the file is absent (machine not managed / never evaluated),
/// `Err` only on a genuine read failure (e.g. access denied). Never launches
/// `ccmeval.exe` (deviation #47.1).
pub(super) fn read_health_report() -> Result<Option<SccmHealthReport>, String> {
    match std::fs::read_to_string(CCM_EVAL_REPORT) {
        Ok(xml) => Ok(Some(parse_health_report(&xml))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {CCM_EVAL_REPORT}: {e}")),
    }
}

/// Pull-parses the ccmeval report: the single `<Summary>` element (its inner
/// text plus the `EvaluationTime` attribute) and the flat list of
/// `<HealthCheck>` elements (each a `Description` attribute plus inner text).
/// Tolerant — a malformed tail returns whatever was parsed so far.
fn parse_health_report(xml: &str) -> SccmHealthReport {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut summary_text = None;
    let mut evaluation_time = None;
    let mut entries: Vec<HealthEntry> = Vec::new();

    let mut in_summary = false;
    // (description, accumulated text) for the HealthCheck currently being read.
    let mut pending: Option<(String, String)> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => match e.local_name().as_ref() {
                b"Summary" => {
                    evaluation_time = attr_value(&e, b"EvaluationTime").and_then(non_empty);
                    in_summary = true;
                }
                b"HealthCheck" => {
                    pending = Some((
                        attr_value(&e, b"Description").unwrap_or_default(),
                        String::new(),
                    ));
                }
                _ => {}
            },
            Ok(Event::Empty(e)) => match e.local_name().as_ref() {
                b"Summary" => {
                    evaluation_time = attr_value(&e, b"EvaluationTime").and_then(non_empty);
                }
                b"HealthCheck" => entries.push(HealthEntry {
                    description: attr_value(&e, b"Description").unwrap_or_default(),
                    health_check_text: String::new(),
                }),
                _ => {}
            },
            Ok(Event::Text(t)) => {
                // Accumulate rather than assign: entity references split an
                // element's content into several Text events, so a single `=`
                // would keep only the last chunk.  `trim_text(true)` already
                // strips pretty-print indentation, so an empty chunk carries no
                // content — skipping it keeps `summary_text` at `None` for an
                // empty <Summary> instead of materialising `Some("")`.
                let text = t.decode().unwrap_or_default();
                if !text.is_empty() {
                    if in_summary {
                        summary_text.get_or_insert_with(String::new).push_str(&text);
                    } else if let Some((_, slot)) = pending.as_mut() {
                        slot.push_str(&text);
                    }
                }
            }
            Ok(Event::End(e)) => match e.local_name().as_ref() {
                b"Summary" => in_summary = false,
                b"HealthCheck" => {
                    if let Some((description, health_check_text)) = pending.take() {
                        entries.push(HealthEntry {
                            description,
                            health_check_text,
                        });
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }

    SccmHealthReport {
        summary_text,
        evaluation_time,
        entries,
    }
}

/// Decodes and unescapes an element attribute to an owned `String`.
fn attr_value(e: &BytesStart, name: &[u8]) -> Option<String> {
    e.try_get_attribute(name).ok().flatten().and_then(|a| {
        a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .ok()
            .map(std::borrow::Cow::into_owned)
    })
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

// ---------------------------------------------------------------------------
// Tests — pure helpers (no WMI / no filesystem)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{dmtf_to_iso8601, parse_health_report};

    /// DMTF with zero offset converts straight to the same wall-clock UTC.
    #[test]
    fn dmtf_zero_offset() {
        assert_eq!(
            dmtf_to_iso8601("20260521103000.000000+000").as_deref(),
            Some("2026-05-21T10:30:00Z")
        );
    }

    /// A +120-minute offset is subtracted to reach UTC (local 12:30 -> 10:30Z).
    #[test]
    fn dmtf_positive_offset_to_utc() {
        assert_eq!(
            dmtf_to_iso8601("20260521123000.000000+120").as_deref(),
            Some("2026-05-21T10:30:00Z")
        );
    }

    /// Zero-filled and truncated values are rejected (C# TryParseExact null).
    #[test]
    fn dmtf_malformed_is_none() {
        assert_eq!(dmtf_to_iso8601("00000000000000.000000+000"), None);
        assert_eq!(dmtf_to_iso8601("2026"), None);
        assert_eq!(dmtf_to_iso8601(""), None);
    }

    /// Full report: summary text + evaluation time + two health-check rows.
    #[test]
    fn parse_full_report() {
        let xml = r#"<ClientHealthReport>
            <Summary EvaluationTime="2026-04-21T16:03:11Z" Version="1.2">Passed</Summary>
            <HealthChecks>
                <HealthCheck ID="x" Description="Verify BITS exists." ResultCode="0">Passed</HealthCheck>
                <HealthCheck ID="y" Description="WMI repository integrity test.">Not Applicable</HealthCheck>
            </HealthChecks>
        </ClientHealthReport>"#;

        let report = parse_health_report(xml);
        assert_eq!(report.summary_text.as_deref(), Some("Passed"));
        assert_eq!(
            report.evaluation_time.as_deref(),
            Some("2026-04-21T16:03:11Z")
        );
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].description, "Verify BITS exists.");
        assert_eq!(report.entries[0].health_check_text, "Passed");
        assert_eq!(
            report.entries[1].description,
            "WMI repository integrity test."
        );
        assert_eq!(report.entries[1].health_check_text, "Not Applicable");
    }

    /// Empty input yields an empty report, not a panic.
    #[test]
    fn parse_empty_report() {
        let report = parse_health_report("");
        assert!(report.summary_text.is_none());
        assert!(report.evaluation_time.is_none());
        assert!(report.entries.is_empty());
    }

    /// A `<Summary>` with no text stays `None` (the empty-chunk guard prevents
    /// the text accumulator from materialising `Some("")`), while the
    /// `EvaluationTime` attribute is still captured.
    #[test]
    fn parse_empty_summary_text_stays_none() {
        let xml = r#"<ClientHealthReport>
            <Summary EvaluationTime="2026-01-01T00:00:00Z"></Summary>
        </ClientHealthReport>"#;
        let report = parse_health_report(xml);
        assert!(report.summary_text.is_none());
        assert_eq!(
            report.evaluation_time.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
    }
}
