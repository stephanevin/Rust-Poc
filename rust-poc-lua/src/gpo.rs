//! Group Policy host bindings — pure registry reads.
//!
//! All data originates from the Windows GP State / Status registry hives,
//! which `gpsvc.dll` populates after every policy refresh. No live Win32
//! API call (`GetAppliedGPOListW` / `ProcessGroupPolicy`) is made here;
//! that API exists in `windows::Win32::System::GroupPolicy` but its
//! `GROUP_POLICY_OBJECTW` struct does not expose the `AccessDenied` /
//! `WQLFilterPass` / `GPO-Disabled` values needed to determine `Filtering`.
//!
//! Three public functions are exposed to `host.rs`:
//!
//! - [`computer_gpos`] — Machine context GPO list
//! - [`user_gpos`]     — All non-Machine contexts (`AllUsers` / headless mode)
//! - [`gp_extensions_status`] — Core engine + per-extension status

use serde_json::{Value, json};

use super::registry;
use super::winver::filetime_to_iso8601;

// ---------------------------------------------------------------------------
// Registry root constants
// ---------------------------------------------------------------------------

const GP_STATE_ROOT: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State";

const GP_STATUS_EXTENSIONS: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Status\GPExtensions";

const WINLOGON_GP_EXTENSIONS: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions";

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Returns the GPOs applied to the Machine context, sorted by
/// `Filtering ASC, LinkOrder ASC` — Applied GPOs surface first.
///
/// Each entry is a JSON object:
/// `{context, link_order, gpo_name, gpo_id, filtering, scope_of_management, revision}`
///
/// Returns `None` only when the GP State key is entirely absent
/// (non-domain-joined machines, or GP never applied).
#[must_use]
pub(super) fn computer_gpos() -> Option<Vec<Value>> {
    gpo_list_for_context("Machine", /*include_loopback_field*/ false)
}

/// Returns the GPOs applied to all user contexts (headless / `AllUsers` mode).
///
/// Mirrors `DataService.GetGpoList("AllUsers")` — iterates every non-Machine
/// sub-key under `Group Policy\State`, which corresponds to one entry per SID
/// that has had GP applied in the current session.
///
/// Each entry is a JSON object:
/// `{context, link_order, gpo_name, gpo_id, filtering, scope_of_management, revision, is_loopback}`
///
/// Returns `None` only when the GP State key is entirely absent.
#[must_use]
pub(super) fn user_gpos() -> Option<Vec<Value>> {
    let contexts = registry::subkey_names("HKLM", GP_STATE_ROOT);
    if contexts.is_empty() {
        return None;
    }

    let mut all: Vec<Value> = Vec::new();
    for ctx in &contexts {
        if ctx == "Machine" {
            continue;
        }
        let mut entries =
            gpo_list_for_context(ctx, /*include_loopback_field*/ true).unwrap_or_default();
        all.append(&mut entries);
    }

    // Sort by Filtering ASC, LinkOrder ASC (same ordering as AdUserGpos.cs).
    all.sort_by(|a, b| {
        let fa = a["filtering"].as_str().unwrap_or("");
        let fb = b["filtering"].as_str().unwrap_or("");
        let la = a["link_order"].as_i64().unwrap_or(0);
        let lb = b["link_order"].as_i64().unwrap_or(0);
        fa.cmp(fb).then_with(|| la.cmp(&lb))
    });

    Some(all)
}

/// Returns the status of every Group Policy client-side extension (CSE).
///
/// The list always starts with the Core GPO Engine entry
/// (`{00000000-0000-0000-0000-000000000000}`), whose timestamp is stored as a
/// FILETIME split across `startTimeHi` / `startTimeLo` DWORD values.
/// The remaining extensions use a compact `LastPolicyTime` DWORD (minutes
/// since 1980-01-01 00:00 UTC).
///
/// Each entry is: `{id, name, status, last_policy_time}`.
///
/// Returns `None` only when the core extension key is missing (GP never ran).
#[must_use]
pub(super) fn gp_extensions_status() -> Option<Vec<Value>> {
    let core_guid = "{00000000-0000-0000-0000-000000000000}";
    let extension_list_key = format!(r"{GP_STATE_ROOT}\Machine\Extension-List");
    let core_key = format!(r"{extension_list_key}\{core_guid}");

    // Gate on the key's existence (not on a specific value), so the function
    // succeeds even if the `Status` DWORD happens to be absent.
    let core_present = registry::subkey_names("HKLM", &extension_list_key)
        .iter()
        .any(|s| s.eq_ignore_ascii_case(core_guid));
    if !core_present {
        return None;
    }

    let core_status = read_status_string("HKLM", &core_key);
    let core_time = read_core_filetime(&core_key);

    let mut result = vec![json!({
        "id":               core_guid,
        "name":             extension_name(core_guid),
        "status":           core_status,
        "last_policy_time": core_time,
    })];

    // Remaining extensions under Group Policy\Status\GPExtensions.
    // Skip the core GUID if it appears here as well (defensive deduplication).
    for guid in registry::subkey_names("HKLM", GP_STATUS_EXTENSIONS) {
        if guid.eq_ignore_ascii_case(core_guid) {
            continue;
        }
        let ext_key = format!(r"{GP_STATUS_EXTENSIONS}\{guid}");

        let status = read_status_string("HKLM", &ext_key);

        let last_policy_time = registry::read("HKLM", &ext_key, "LastPolicyTime")
            .ok()
            .flatten()
            .and_then(|v| v.as_u64())
            .and_then(minutes_since_1980_to_iso8601);

        result.push(json!({
            "id":               guid,
            "name":             extension_name(&guid),
            "status":           status,
            "last_policy_time": last_policy_time,
        }));
    }

    Some(result)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Builds the GPO list for a single context (e.g. "Machine" or a user SID).
///
/// `include_loopback_field` should be `false` for the machine binding
/// (matches `AdComputerGpoRow`, which drops `IsLoopback`) and `true` for the
/// user binding (matches `AdUserGpoRow`).
fn gpo_list_for_context(context: &str, include_loopback_field: bool) -> Option<Vec<Value>> {
    // Build the GP link table first (needed to resolve LinkOrder).
    let mut gp_links: Vec<GpLink> = Vec::new();

    for (list_name, loopback_flag) in [("GPLink-List", 0i64), ("Loopback-GPLink-List", 1i64)] {
        let list_key = format!(r"{GP_STATE_ROOT}\{context}\{list_name}");
        for link_id_hex in registry::subkey_names("HKLM", &list_key) {
            let link_key = format!(r"{list_key}\{link_id_hex}");
            let id = i64::from_str_radix(&link_id_hex, 16).unwrap_or(0);
            let ds_path = read_string("HKLM", &link_key, "DsPath");
            let som = read_string("HKLM", &link_key, "SOM");
            gp_links.push(GpLink {
                id,
                ds_path,
                som,
                is_loopback: loopback_flag,
            });
        }
    }

    // Now collect GPO entries.
    let mut entries: Vec<Value> = Vec::new();

    for (list_name, loopback_flag) in [("GPO-List", 0i64), ("Loopback-GPO-List", 1i64)] {
        let list_key = format!(r"{GP_STATE_ROOT}\{context}\{list_name}");
        for gpo_key_name in registry::subkey_names("HKLM", &list_key) {
            let gpo_key = format!(r"{list_key}\{gpo_key_name}");

            let som_raw = read_string("HKLM", &gpo_key, "SOM");
            let som = normalize_som(&som_raw);

            let gpo_id = read_string("HKLM", &gpo_key, "GPOID");
            let display_name = read_string("HKLM", &gpo_key, "DisplayName");

            let version = read_u32("HKLM", &gpo_key, "Version").unwrap_or(0);
            let revision = format_revision(version);

            let access_denied = read_u32("HKLM", &gpo_key, "AccessDenied").unwrap_or(0);
            let gpo_disabled = read_u32("HKLM", &gpo_key, "GPO-Disabled").unwrap_or(0);
            let wql_filter_pass = read_u32("HKLM", &gpo_key, "WQLFilterPass").unwrap_or(0);
            let filtering = resolve_filtering(access_denied, gpo_disabled, wql_filter_pass);

            let link_order = resolve_link_order(&gp_links, loopback_flag, &som, &gpo_id);

            if include_loopback_field {
                entries.push(json!({
                    "context":             context,
                    "link_order":          link_order,
                    "gpo_name":            display_name,
                    "gpo_id":              gpo_id,
                    "filtering":           filtering,
                    "scope_of_management": som,
                    "revision":            revision,
                    "is_loopback":         loopback_flag != 0,
                }));
            } else {
                entries.push(json!({
                    "context":             context,
                    "link_order":          link_order,
                    "gpo_name":            display_name,
                    "gpo_id":              gpo_id,
                    "filtering":           filtering,
                    "scope_of_management": som,
                    "revision":            revision,
                }));
            }
        }
    }

    if entries.is_empty() && gp_links.is_empty() {
        // Context key may exist but be empty — treat as absent.
        return None;
    }

    // Sort by Filtering ASC, LinkOrder ASC (same ordering as AdComputerGpos.cs).
    entries.sort_by(|a, b| {
        let fa = a["filtering"].as_str().unwrap_or("");
        let fb = b["filtering"].as_str().unwrap_or("");
        let la = a["link_order"].as_i64().unwrap_or(0);
        let lb = b["link_order"].as_i64().unwrap_or(0);
        fa.cmp(fb).then_with(|| la.cmp(&lb))
    });

    Some(entries)
}

/// Mirrors the C# `switch` that determines `Filtering` from three DWORDs.
///
/// ```text
/// AccessDenied == 0 && GPO-Disabled != 0  → "Disabled"
/// AccessDenied == 0 && WQLFilterPass == 1 → "Applied"
/// AccessDenied == 0                       → "Denied (WMI Filter)"
/// AccessDenied != 0                       → "Denied (Security)"
/// ```
fn resolve_filtering(access_denied: u32, gpo_disabled: u32, wql_filter_pass: u32) -> &'static str {
    match access_denied {
        0 if gpo_disabled != 0 => "Disabled",
        0 if wql_filter_pass == 1 => "Applied",
        0 => "Denied (WMI Filter)",
        _ => "Denied (Security)",
    }
}

/// Decodes the registry `Version` DWORD into "AD (N), SYSVOL (N)".
///
/// The upper 16 bits are the AD version; the lower 16 bits are the SYSVOL
/// version — same encoding as `gpt.ini` on the SYSVOL share.
fn format_revision(version: u32) -> String {
    let ad = version >> 16;
    let sysvol = version & 0xFFFF;
    format!("AD ({ad}), SYSVOL ({sysvol})")
}

struct GpLink {
    id: i64,
    ds_path: String,
    som: String,
    is_loopback: i64,
}

/// Finds the `LinkOrder` integer for a GPO by scanning the pre-built link
/// table, mirroring `DataService.ResolveLinkOrder`.
///
/// Local-scoped GPOs (SOM == "Local") match on SOM + loopback only.
/// Domain-scoped GPOs additionally require the `DsPath` to start with
/// `cn={gpo_id},cn=policies,cn=system,DC` (case-insensitive).
fn resolve_link_order(links: &[GpLink], is_loopback: i64, som: &str, gpo_id: &str) -> i64 {
    let is_local = som.eq_ignore_ascii_case("Local");
    let ds_path_prefix = format!("cn={gpo_id},cn=policies,cn=system,DC");

    for link in links {
        if link.is_loopback != is_loopback {
            continue;
        }
        if link.som != som {
            continue;
        }
        if !is_local
            && !link
                .ds_path
                .to_ascii_lowercase()
                .starts_with(&ds_path_prefix.to_ascii_lowercase())
        {
            continue;
        }
        return link.id;
    }
    0
}

/// Reads the Core GPO Engine timestamp from the split DWORD `startTimeHi` /
/// `startTimeLo` pair and converts it to an ISO 8601 string.
fn read_core_filetime(core_key: &str) -> Option<String> {
    let hi = i64::from(read_u32("HKLM", core_key, "startTimeHi")?);
    let lo = i64::from(read_u32("HKLM", core_key, "startTimeLo")?);
    let ticks = (hi << 32) | lo;
    filetime_to_iso8601(ticks)
}

/// Converts minutes since 1980-01-01 00:00 UTC to an ISO 8601 UTC string,
/// routing through `filetime_to_iso8601` to avoid duplicating calendar math.
///
/// `1980-01-01T00:00:00Z` = Unix timestamp `315_532_800`.
/// We convert to FILETIME ticks: `(unix_secs + 11_644_473_600) * 10_000_000`.
fn minutes_since_1980_to_iso8601(minutes: u64) -> Option<String> {
    // 1980-01-01T00:00:00Z as a Unix timestamp (seconds since 1970-01-01).
    const BASE_UNIX: i64 = 315_532_800;
    // Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch (1970-01-01).
    const FILETIME_EPOCH_DIFF: i64 = 11_644_473_600;

    let secs = i64::try_from(minutes).ok()?.checked_mul(60)?;
    let unix_secs = BASE_UNIX.checked_add(secs)?;
    let filetime_secs = unix_secs.checked_add(FILETIME_EPOCH_DIFF)?;
    let ticks = filetime_secs.checked_mul(10_000_000)?;
    filetime_to_iso8601(ticks)
}

/// Returns the display name of a GP extension GUID, falling back to a
/// registry lookup when not in the static map.
fn extension_name(guid: &str) -> String {
    let upper = guid.to_ascii_uppercase();
    if let Some(&name) = EXTENSION_NAME_MAP.get(upper.as_str()) {
        return name.to_string();
    }
    // Fallback: Winlogon\GPExtensions\{guid} default value (empty value name = "").
    let key = format!(r"{WINLOGON_GP_EXTENSIONS}\{guid}");
    registry::read("HKLM", &key, "")
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| guid.to_string())
}

// ---------------------------------------------------------------------------
// Typed registry read helpers
// ---------------------------------------------------------------------------

fn read_string(hive: &str, key: &str, value: &str) -> String {
    registry::read(hive, key, value)
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

fn read_u32(hive: &str, key: &str, value: &str) -> Option<u32> {
    registry::read(hive, key, value)
        .ok()
        .flatten()
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok())
}

/// Extracts the GP extension `Status` DWORD as a decimal string.
///
/// Uses explicit type arms to avoid `serde_json::Value::to_string()`, which
/// would wrap string values in extra JSON quotation marks.
fn read_status_string(hive: &str, key: &str) -> Option<String> {
    registry::read(hive, key, "Status")
        .ok()
        .flatten()
        .map(|v| {
            if let Some(n) = v.as_u64() {
                n.to_string()
            } else if let Some(s) = v.as_str() {
                s.to_string()
            } else {
                v.to_string()
            }
        })
}

/// Strips the `LDAP://` scheme prefix (case-insensitive) from a SOM path.
///
/// In practice Windows always writes `LDAP://` in uppercase, but the
/// case-insensitive check is defensive and costs nothing.
fn normalize_som(raw: &str) -> String {
    if raw.len() >= 7 && raw[..7].eq_ignore_ascii_case("LDAP://") {
        raw[7..].to_string()
    } else {
        raw.to_string()
    }
}

// ---------------------------------------------------------------------------
// Static extension name map — mirrors DataService._extensionMapping (C#)
// ---------------------------------------------------------------------------

/// Well-known GP client-side extension GUIDs (uppercase) mapped to human-readable names.
/// Source: `DataService._extensionMapping` in `ComplianceService`.
static EXTENSION_NAME_MAP: std::sync::LazyLock<
    std::collections::HashMap<&'static str, &'static str>,
> = std::sync::LazyLock::new(|| {
    std::collections::HashMap::from([
        ("{00000000-0000-0000-0000-000000000000}", "Core GPO Engine"),
        (
            "{0E28E245-9368-4853-AD84-6DA3BA35BB75}",
            "Preference Environment",
        ),
        (
            "{17D89FEC-5C44-4972-B12D-241CAEF74509}",
            "Preference Local Users and Groups",
        ),
        (
            "{1A6364EB-776B-4120-ADE1-B63A406A76B5}",
            "Preference Device Settings",
        ),
        (
            "{25537BA6-77A8-11D2-9B6C-0000F8080861}",
            "Folder Redirection",
        ),
        (
            "{3060E8CE-7020-11D2-842D-00C04FA372D4}",
            "Remote Installation Services",
        ),
        ("{35378EAC-683F-11D2-A89A-00C04FBBCFA2}", "Registry"),
        (
            "{3610EDA5-77EF-11D2-8DC5-00C04FA31A66}",
            "Microsoft Disk Quota",
        ),
        (
            "{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}",
            "Preference Network Options",
        ),
        ("{42B5FAAE-6536-11D2-AE5A-0000F87571E3}", "Scripts"),
        (
            "{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}",
            "Internet Explorer Zonemapping",
        ),
        (
            "{5794DAFD-BE60-433F-88A2-1A31939AC01F}",
            "Preference Drive Maps",
        ),
        (
            "{6232C319-91AC-4931-9385-E70C2B099F0E}",
            "Preference Folders",
        ),
        (
            "{6A4C88C6-C502-4F74-8F60-2CB23EDC24E2}",
            "Preference Network Shares",
        ),
        (
            "{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}",
            "Preference Files",
        ),
        (
            "{728EE579-943C-4519-9EF7-AB56765798ED}",
            "Preference Data Sources",
        ),
        (
            "{74EE6C03-5363-4554-B161-627540339CAB}",
            "Preference Ini Files",
        ),
        (
            "{7B849A69-220F-451E-B3FE-2CB811AF94AE}",
            "Internet Explorer User Accelerators",
        ),
        ("{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", "Security"),
        (
            "{8A28E2C5-8D06-49A4-A08C-632DAA493E17}",
            "Deployed Printer Connections",
        ),
        (
            "{91FBB303-0CD5-4055-BF42-E512A681B325}",
            "Preference Services",
        ),
        (
            "{A3F3E39B-5D83-4940-B954-28315B82F0A8}",
            "Preference Folder Options",
        ),
        (
            "{AADCED64-746C-4633-A97C-D61349046527}",
            "Preference Scheduled Tasks",
        ),
        (
            "{B087BE9D-ED37-454F-AF9C-04291E351182}",
            "Preference Registry",
        ),
        (
            "{B587E2B1-4D59-4E7E-AED9-22B9DF11D053}",
            "802.3 Group Policy",
        ),
        (
            "{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}",
            "Preference Printers",
        ),
        (
            "{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}",
            "Preference Shortcuts",
        ),
        (
            "{C631DF4C-088F-4156-B058-4375F0853CD8}",
            "Microsoft Offline Files",
        ),
        (
            "{C6DC5466-785A-11D2-84D0-00C04FB169F7}",
            "Software Installation",
        ),
        (
            "{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}",
            "Internet Explorer Machine Accelerators",
        ),
        ("{D76B9641-3288-4F75-942D-087DE603E3EA}", "AdmPwd (LAPS)"),
        ("{E437BC1C-AA7D-11D2-A382-00C04F991E27}", "IP Security"),
        (
            "{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}",
            "Preference Internet Settings",
        ),
        (
            "{E4F48E54-F38D-4884-BFB9-D4D2E5729C18}",
            "Preference Start Menu Settings",
        ),
        (
            "{E5094040-C46C-4115-B030-04FB2E545B00}",
            "Preference Regional Options",
        ),
        (
            "{E62688F0-25FD-4C90-BFF5-F508B9D2E31F}",
            "Preference Power Options",
        ),
        (
            "{F312195E-3D9D-447A-A3F5-08DFFA24735E}",
            "VirtualizationBasedSecurity GPO (DeviceGuard / CredentialGuard)",
        ),
        (
            "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}",
            "Audit Policy Configuration",
        ),
        (
            "{F9C77450-3A41-477E-9310-9ACD617BD9E3}",
            "Group Policy Applications",
        ),
        (
            "{FB2CA36D-0B40-4307-821B-A13B252DE56C}",
            "Enterprise QoS",
        ),
    ])
});

// ---------------------------------------------------------------------------
// Unit tests (no registry access — pure logic only)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- resolve_filtering ---------------------------------------------------

    #[test]
    fn filtering_applied() {
        assert_eq!(resolve_filtering(0, 0, 1), "Applied");
    }

    #[test]
    fn filtering_disabled() {
        // GPO-Disabled wins over WQLFilterPass when AccessDenied == 0.
        assert_eq!(resolve_filtering(0, 1, 1), "Disabled");
        assert_eq!(resolve_filtering(0, 5, 0), "Disabled");
    }

    #[test]
    fn filtering_denied_wmi() {
        // AccessDenied == 0, GPO-Disabled == 0, WQLFilterPass != 1.
        assert_eq!(resolve_filtering(0, 0, 0), "Denied (WMI Filter)");
        assert_eq!(resolve_filtering(0, 0, 2), "Denied (WMI Filter)");
    }

    #[test]
    fn filtering_denied_security() {
        assert_eq!(resolve_filtering(1, 0, 1), "Denied (Security)");
        assert_eq!(resolve_filtering(u32::MAX, 0, 0), "Denied (Security)");
    }

    // --- format_revision -----------------------------------------------------

    #[test]
    fn revision_splits_hi_lo() {
        // Version DWORD: upper 16 = AD, lower 16 = SYSVOL.
        assert_eq!(format_revision(0x0002_0003), "AD (2), SYSVOL (3)");
        // Default Domain Policy example: 0x0286_0286 = AD(646), SYSVOL(646).
        assert_eq!(format_revision(0x0286_0286), "AD (646), SYSVOL (646)");
        assert_eq!(format_revision(0), "AD (0), SYSVOL (0)");
    }

    // --- normalize_som -------------------------------------------------------

    #[test]
    fn normalize_strips_ldap_prefix() {
        assert_eq!(
            normalize_som("LDAP://OU=Workstations,DC=corp,DC=local"),
            "OU=Workstations,DC=corp,DC=local"
        );
    }

    #[test]
    fn normalize_strips_lowercase_ldap() {
        assert_eq!(
            normalize_som("ldap://OU=Test,DC=corp"),
            "OU=Test,DC=corp"
        );
    }

    #[test]
    fn normalize_leaves_local_unchanged() {
        assert_eq!(normalize_som("Local"), "Local");
    }

    #[test]
    fn normalize_leaves_plain_dn_unchanged() {
        assert_eq!(
            normalize_som("OU=Workstations,DC=corp,DC=local"),
            "OU=Workstations,DC=corp,DC=local"
        );
    }

    // --- minutes_since_1980_to_iso8601 ---------------------------------------

    #[test]
    fn minutes_epoch_1980() {
        // 0 minutes after 1980-01-01 → "1980-01-01T00:00:00Z".
        assert_eq!(
            minutes_since_1980_to_iso8601(0).as_deref(),
            Some("1980-01-01T00:00:00Z")
        );
    }

    #[test]
    fn minutes_known_value() {
        // 1 minute = 60 s after 1980-01-01 → "1980-01-01T00:01:00Z".
        assert_eq!(
            minutes_since_1980_to_iso8601(1).as_deref(),
            Some("1980-01-01T00:01:00Z")
        );
    }

    #[test]
    fn minutes_one_day() {
        // 1440 minutes = 1 day → "1980-01-02T00:00:00Z".
        assert_eq!(
            minutes_since_1980_to_iso8601(1440).as_deref(),
            Some("1980-01-02T00:00:00Z")
        );
    }

    // --- resolve_link_order --------------------------------------------------

    #[test]
    fn link_order_local_match() {
        let links = vec![GpLink {
            id: 42,
            ds_path: String::new(),
            som: "Local".to_string(),
            is_loopback: 0,
        }];
        assert_eq!(resolve_link_order(&links, 0, "Local", "any-id"), 42);
    }

    #[test]
    fn link_order_domain_match() {
        let gpo_id = "6AC1786C-016F-11D2-945F-00C04fB984F9";
        let links = vec![GpLink {
            id: 3,
            ds_path: format!(
                "cn={gpo_id},cn=policies,cn=system,DC=corp,DC=local"
            ),
            som: "DC=corp,DC=local".to_string(),
            is_loopback: 0,
        }];
        assert_eq!(
            resolve_link_order(&links, 0, "DC=corp,DC=local", gpo_id),
            3
        );
    }

    #[test]
    fn link_order_no_match_returns_zero() {
        let links: Vec<GpLink> = Vec::new();
        assert_eq!(resolve_link_order(&links, 0, "DC=corp", "any"), 0);
    }

    #[test]
    fn link_order_loopback_flag_mismatch() {
        let links = vec![GpLink {
            id: 7,
            ds_path: String::new(),
            som: "Local".to_string(),
            is_loopback: 1, // loopback
        }];
        // Requesting non-loopback → no match.
        assert_eq!(resolve_link_order(&links, 0, "Local", "any"), 0);
    }
}
