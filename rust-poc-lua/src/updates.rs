//! Windows Update Agent (WUA) host bindings — System Updates sub-category.
//!
//! All six `ComplianceApp` `Win10-Laptop.json` transformers for System Updates
//! are ported faithfully using WUA COM interfaces directly (deviations #26–#31).
//!
//! ## COM threading
//!
//! Every function calls [`ensure_com`] at entry, which calls
//! `CoInitializeEx(COINIT_MULTITHREADED)`.  The call is idempotent — if COM is
//! already initialized on the same thread (e.g. because `Wmi::new()` ran first)
//! the call returns `S_FALSE` (0x1 ≥ 0), which `.ok()` treats as success.  WUA
//! COM objects are free-threaded and work with MTA.
//!
//! ## Per-run shared caches
//!
//! Two heavy operations are mutualised across bindings via lazy-init caches
//! held on `HostState`:
//!
//! - [`UpdatesCache`] — one offline WUA search (`build_offline_payload`)
//!   feeds `updates_windows_updates` (full JSON list).  Since the
//!   `updates_sccm_updates` refactor (`SccmUpdate.cs`-strict DTO), the
//!   cache is no longer shared with #31, which now runs its own
//!   independent quad-source merge.  The cache stays useful when the
//!   single consumer needs to be re-queried in a future call site.
//! - [`default_au_service`] — one `IUpdateServiceManager2::Services`
//!   enumeration feeds both `updates_is_managed` and `updates_managed_by`.
//!
//! ## Deviations from `ComplianceApp`
//!
//! | # | Binding | Notes |
//! |---|---|---|
//! | 26 | `updates_is_managed` | Faithful WUA COM port; returns `"Managed"\|"Unmanaged"\|null` (string, not C# enum); shares `au_service` cache with #27 |
//! | 27 | `updates_managed_by` | Faithful WUA COM port; shares `au_service` cache with #26 |
//! | 28 | `updates_reboot_required` | Faithful WUA COM port via `ISystemInformation` |
//! | 29 | `updates_reboot_required_before_installation` | Faithful WUA COM port via `IUpdateInstaller` |
//! | 30 | `updates_windows_updates` | Faithful port; no 90 s `CancellationToken` timeout; sole consumer of the offline WUA search cache |
//! | 31 | `updates_sccm_updates` | 4-source merge faithful to `Updates.cs::GetSccmUpdates`: CCM_UpdateStatus (pivot) + CCM_TargetedUpdateEx1 + CCM_StateMsg + WUA online QueryHistory; DTO strict 1:1 with `SccmUpdate.cs` (9 fields) |

#![allow(clippy::too_many_lines)]

use std::collections::HashMap;
use std::thread::sleep;
use std::time::Duration;

use serde_json::{Value, json};
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
};
use windows::Win32::System::UpdateAgent::{
    ISearchResult, IStringCollection, ISystemInformation, IUpdate, IUpdate2, IUpdate3,
    IUpdateCollection, IUpdateHistoryEntry, IUpdateInstaller, IUpdateSearcher, IUpdateSearcher3,
    IUpdateService, IUpdateService2, IUpdateServiceCollection, IUpdateServiceManager2,
    IUpdateSession, IUpdateSession3, SystemInformation, UpdateInstaller, UpdateServiceManager,
    UpdateSession,
};
use windows::Win32::System::Wmi::WBEM_E_INVALID_NAMESPACE;
use windows::core::{BSTR, Interface};
use wmi::{COMLibrary, Variant, WMIConnection, WMIError};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Ensures COM is initialized as MTA on the current thread.
///
/// `CoInitializeEx` returns `S_FALSE` (`HRESULT(1)`) when COM is already
/// initialized in the same apartment — `.ok()` treats any non-negative
/// HRESULT as success.
fn ensure_com() -> Result<(), String> {
    // SAFETY: no preconditions; CoInitializeEx is always safe to call.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
        .ok()
        .map_err(|e| format!("COM init: {e}"))
}

/// Drains an `IStringCollection` into a `Vec<String>`, ignoring per-item errors.
fn string_collection_to_vec(coll: &IStringCollection) -> Vec<String> {
    // SAFETY: all WUA COM calls are safe when called on a valid interface pointer.
    let count = unsafe { coll.Count() }.unwrap_or(0);
    (0..count)
        .filter_map(|i| unsafe { coll.get_Item(i) }.ok().map(|b| b.to_string()))
        .collect()
}

/// Converts an OLE Automation `DATE` (`f64`, days since 1899-12-30) to an
/// ISO 8601 UTC string using the existing `winver::filetime_to_iso8601` helper.
///
/// Returns `None` for the zero sentinel (unset date), any date before the
/// Unix epoch (1970-01-01), or any non-finite value (NaN / ±∞).
fn ole_date_to_iso8601(date: f64) -> Option<String> {
    // Fix #5: a non-finite DATE from WUA must not silently become 1970-01-01
    // via the `(NaN as i64) == 0` lossy cast.
    if !date.is_finite() {
        return None;
    }
    if date == 0.0 {
        return None;
    }
    // OLE epoch: 1899-12-30.  Unix epoch (1970-01-01) = OLE date 25_569.0.
    let unix_secs = (date - 25_569.0) * 86_400.0;
    if unix_secs < 0.0 {
        return None;
    }
    // Convert to 100-ns FILETIME ticks (from 1601-01-01).
    #[allow(clippy::cast_possible_truncation)]
    let filetime_ticks = (unix_secs as i64)
        .checked_add(11_644_473_600)?
        .checked_mul(10_000_000)?;
    super::winver::filetime_to_iso8601(filetime_ticks)
}

// ---------------------------------------------------------------------------
// CCM WMI row helpers
// ---------------------------------------------------------------------------

/// Permissive `?.Value?.ToString()` mirror of the C#
/// `GetStringProp(CimInstance, name)` helper in `Updates.cs`.
///
/// Used on columns that **are** typed as strings in the schema but
/// where the CCM provider occasionally returns a boxed scalar
/// (`Superseded` is a notorious offender).  Returns `None` only when
/// the property is genuinely missing or null; otherwise stringifies
/// the variant using a small, stable mapping.
//
// `clippy::match_same_arms` would coalesce the UI1..I8 arms because
// their bodies (`Some(n.to_string())`) are textually identical — but
// the bound `n` has a different type in each arm so they can't be
// `|`-merged.  Allowed locally; the expanded form is far more readable
// than a `match { … }` with a single catch-all that obscures intent.
#[allow(clippy::match_same_arms)]
fn ccm_str_permissive(row: &HashMap<String, Variant>, key: &str) -> Option<String> {
    match row.get(key)? {
        Variant::Null | Variant::Empty => None,
        Variant::String(s) => Some(s.clone()),
        // `.ToString()` on a CLR bool produces "True" / "False" — matters
        // here because the C# transformer compares the *stringified* value
        // against `"1"` (see `Updates.cs:609`).  Returning "True" would
        // never equal "1", which is exactly the behaviour we want when a
        // provider drifts away from the documented string-typed column.
        Variant::Bool(b) => Some(if *b { "True".to_string() } else { "False".to_string() }),
        Variant::UI1(n) => Some(n.to_string()),
        Variant::UI2(n) => Some(n.to_string()),
        Variant::UI4(n) => Some(n.to_string()),
        Variant::UI8(n) => Some(n.to_string()),
        Variant::I1(n) => Some(n.to_string()),
        Variant::I2(n) => Some(n.to_string()),
        Variant::I4(n) => Some(n.to_string()),
        Variant::I8(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Strict `?.Value as string` mirror of the C# `GetStringValue` helper.
///
/// Returns `Some` **only** when the variant is an actual `Variant::String`.
/// Used on columns where a non-string value would silently corrupt
/// downstream substring matching (`UpdateId`, `TopicID`) or GUID resolution
/// (`UpdateClassification`).
fn ccm_str_strict(row: &HashMap<String, Variant>, key: &str) -> Option<String> {
    match row.get(key)? {
        Variant::String(s) => Some(s.clone()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// SCCM pure helpers (no I/O, fully unit-testable)
// ---------------------------------------------------------------------------

/// `OperationResultCode::orcSucceeded` raw value, mirroring the C#
/// `(int)OperationResultCode.orcSucceeded` cast in `Updates.cs:613`.
/// `windows-rs` exposes the enum as a newtype around `i32`; we keep the
/// integer locally so the SCCM merge function can stay pure (no
/// dependency on `windows-rs` types just for a constant).
const OPERATION_RESULT_SUCCEEDED: i32 = 2;

/// `UpdateClassification` GUID → display label.  Verbatim copy of
/// `UpdateClassification._classificationMapping` in
/// [`Updates.cs:453-468`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ff357803(v=vs.85)).
///
/// Keys are uppercase to match the C# `.ToUpper()` normalization before
/// lookup ; [`classification_from_guid`] applies the same uppercase
/// transform on incoming GUIDs.
static CLASSIFICATION_MAPPING: &[(&str, &str)] = &[
    ("5C9376AB-8CE6-464A-B136-22113DD69801", "Application"),
    ("434DE588-ED14-48F5-8EED-A15E09A991F6", "Connectors"),
    ("E6CF1350-C01B-414D-A61F-263D14D133B4", "Critical Updates"),
    ("E0789628-CE08-4437-BE74-2495B842F43B", "Definition Updates"),
    ("E140075D-8433-45C3-AD87-E72345B36078", "Developer Kits"),
    ("B54E7D24-7ADD-428F-8B75-90A396FA584F", "Feature Packs"),
    ("9511D615-35B2-47BB-927F-F73D8E9260BB", "Guidance"),
    ("0FA1201D-4330-4FA8-8AE9-B877473B6441", "Security Updates"),
    ("68C5B0A3-D1A6-4553-AE49-01D3A7827828", "Service Packs"),
    ("B4832BD8-E735-4761-8DAF-37F882276DAB", "Tools"),
    ("28BC880E-0592-4CBF-8F95-C79B17911D5F", "Update Rollups"),
    ("CD5FFD1E-E932-4E3A-BF74-18BF0B1BBD83", "Updates"),
    ("3689BDC8-B205-4AF4-8D4A-A63924C5E9D5", "Feature Updates"),
];

/// GUID → human label, falling back to the raw GUID when unknown.
/// Mirrors `UpdateClassification.FromGUID(guid)` exactly: returns the
/// label when matched, otherwise the input string verbatim (preserving
/// the caller's casing so a downstream consumer can still grep it).
fn classification_from_guid(guid: &str) -> String {
    let upper = guid.to_ascii_uppercase();
    CLASSIFICATION_MAPPING
        .iter()
        .find_map(|(k, v)| (*k == upper.as_str()).then_some((*v).to_string()))
        .unwrap_or_else(|| guid.to_string())
}

/// `long.TryParse` mirror.  Returns `0` on `None`, empty, whitespace,
/// or any non-integer input — matching the C# `if (long.TryParse(…,
/// out var article)) articleId = article;` pattern where `articleId`
/// stays at its `0` initializer when parsing fails.
fn parse_article_id(article: Option<&str>) -> i64 {
    article
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
}

/// ASCII-only case-insensitive substring match.  Mirrors the C#
/// `ContainsId(string?, string)` helper which uses
/// `StringComparison.OrdinalIgnoreCase`.
///
/// Safe to use ASCII-only because every value passed through here is
/// a CCM UpdateID-shaped string (GUID, hex digits, dashes, braces) —
/// no Unicode in practice.  Returns `false` when `haystack` is `None`
/// or doesn't contain the needle.
fn contains_id_ci(haystack: Option<&str>, needle: &str) -> bool {
    haystack.is_some_and(|h| h.to_ascii_lowercase().contains(&needle.to_ascii_lowercase()))
}

/// Derives `(installed, required)` from a CCM `StateID` string and a
/// pre-evaluated history-succeeded flag.  Exactly mirrors lines 612-614
/// of `Updates.cs`:
///
/// ```text
/// installed = (stateId == "3") || (hasHistory && h.ResultCode == orcSucceeded)
/// required  = (stateId == "2")
/// ```
fn compute_state_flags(state_id: Option<&str>, history_succeeded: bool) -> (bool, bool) {
    let installed = state_id == Some("3") || history_succeeded;
    let required = state_id == Some("2");
    (installed, required)
}

// ---------------------------------------------------------------------------
// AU service lookup (shared by `updates_is_managed` + `updates_managed_by`)
// ---------------------------------------------------------------------------

/// Finds the default AU service and returns `(is_managed, name)`.
///
/// Returns `Ok(None)` when no service reports `IsDefaultAUService == true`.
/// The result is cached for the duration of a run by
/// `HostState::ensure_au_service()` (see `host.rs`) so the same
/// service-collection enumeration is not repeated for both
/// `updates_is_managed` (#26) and `updates_managed_by` (#27); init
/// failures are memoised in `AuServiceState::Failed` and surfaced once
/// under the canonical key `ERR_KEY_AU_SERVICE`.
pub(super) fn default_au_service() -> Result<Option<(bool, String)>, String> {
    ensure_com()?;
    // SAFETY: CoCreateInstance is always safe when COM is initialized.
    let mgr: IUpdateServiceManager2 =
        unsafe { CoCreateInstance(&UpdateServiceManager, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| format!("UpdateServiceManager CoCreateInstance: {e}"))?;

    let services: IUpdateServiceCollection =
        unsafe { mgr.Services() }.map_err(|e| format!("IUpdateServiceManager2::Services: {e}"))?;

    let count =
        unsafe { services.Count() }.map_err(|e| format!("IUpdateServiceCollection::Count: {e}"))?;

    for i in 0..count {
        let svc: IUpdateService = unsafe { services.get_Item(i) }
            .map_err(|e| format!("IUpdateServiceCollection::get_Item({i}): {e}"))?;

        // IsDefaultAUService is on IUpdateService2 in windows-rs 0.62.
        let is_default = svc
            .cast::<IUpdateService2>()
            .ok()
            .and_then(|s2| unsafe { s2.IsDefaultAUService() }.ok())
            .is_some_and(VARIANT_BOOL::as_bool);

        if is_default {
            let is_managed = unsafe { svc.IsManaged() }
                .map_err(|e| format!("IUpdateService::IsManaged: {e}"))?
                .as_bool();
            let name = unsafe { svc.Name() }
                .map_err(|e| format!("IUpdateService::Name: {e}"))?
                .to_string();
            return Ok(Some((is_managed, name)));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// WUA offline payload (shared by `updates_windows_updates` + `updates_sccm_updates`)
// ---------------------------------------------------------------------------

/// Runs an offline WUA search and returns the resulting update collection.
///
/// Sets `Online = false` (no network calls to Microsoft) and identifies the
/// collector as `"rust-poc-lua"` in WUA audit logs via `SetClientApplicationID`.
fn wua_offline_collection(session: &IUpdateSession3) -> Result<IUpdateCollection, String> {
    let searcher: IUpdateSearcher3 = unsafe { session.CreateUpdateSearcher() }
        .map_err(|e| format!("IUpdateSession3::CreateUpdateSearcher: {e}"))?
        .cast::<IUpdateSearcher3>()
        .map_err(|e| format!("cast IUpdateSearcher → IUpdateSearcher3: {e}"))?;

    // VARIANT_BOOL implements From<bool>; false.into() == VARIANT_BOOL(0) (offline).
    unsafe { searcher.SetOnline(false.into()) }
        .map_err(|e| format!("IUpdateSearcher3::SetOnline: {e}"))?;

    unsafe { searcher.SetClientApplicationID(&BSTR::from("rust-poc-lua")) }
        .map_err(|e| format!("IUpdateSearcher3::SetClientApplicationID: {e}"))?;

    let result: ISearchResult =
        unsafe { searcher.Search(&BSTR::from("IsInstalled=1 OR IsInstalled=0")) }
            .map_err(|e| format!("IUpdateSearcher3::Search: {e}"))?;

    unsafe { result.Updates() }.map_err(|e| format!("ISearchResult::Updates: {e}"))
}

/// Single-pass snapshot of every WUA `IUpdate` field consumed by
/// `host.updates_windows_updates()`.
///
/// Populated once per update by [`extract_update`].  Until the SCCM
/// pipeline refactor this struct also fed an `UpdateID → WuaMeta`
/// index used by `host.updates_sccm_updates()`; the new SCCM path is
/// source-independent (`CCM_UpdateStatus` + WUA online `QueryHistory`)
/// and no longer shares this snapshot, so the duplicated fields
/// documented here as "shared" are now JSON-only.
struct ExtractedUpdate {
    // --- Identity (one Identity() COM read) ---
    update_id: Option<String>,
    revision_number: Option<i32>,

    // --- Used in the JSON output of `updates_windows_updates` ---
    title: Option<String>,
    article_ids: Vec<String>,
    category: Option<String>,
    msrc_severity: Option<String>,
    reboot_required: Option<bool>,
    cve_ids: Vec<String>,
    last_deployment_change_time: Option<String>,
    is_installed: Option<bool>,
    is_downloaded: Option<bool>,
    is_hidden: Option<bool>,
    is_uninstallable: Option<bool>,
    is_present: Option<bool>,
    update_type: &'static str,
    security_bulletin_ids: Vec<String>,
    installation_reboot_behavior: Option<i32>,
    recommended_cpu_speed: i32,
    recommended_hard_disk_space: i32,
    recommended_memory: i32,
}

/// Extracts every relevant field from an `IUpdate` COM object in a
/// single COM pass.
///
/// Each `IUpdate` getter is called **at most once**.  The two interface
/// casts (`IUpdate2` and `IUpdate3`) are performed once each, and their
/// respective getters are batched on the resulting pointer.
///
/// Gracefully skips any individual field that fails — a missing
/// property never aborts the whole iteration.
fn extract_update(update: &IUpdate) -> ExtractedUpdate {
    // SAFETY for every `unsafe` block below: each call dereferences a
    // valid `IUpdate` (or derived) interface pointer obtained from the
    // WUA collection, which the COM runtime keeps alive for the
    // lifetime of the `update` reference.

    // Identity: one Identity() COM read feeds both UpdateID and RevisionNumber.
    let (update_id, revision_number) =
        unsafe { update.Identity() }
            .ok()
            .map_or((None, None), |id| {
                let uid = unsafe { id.UpdateID() }.ok().map(|b| b.to_string());
                let rev = unsafe { id.RevisionNumber() }.ok();
                (uid, rev)
            });

    let title = unsafe { update.Title() }.ok().map(|b| b.to_string());

    let article_ids = unsafe { update.KBArticleIDs() }
        .ok()
        .map(|c| string_collection_to_vec(&c))
        .unwrap_or_default();

    let category: Option<String> = unsafe { update.Categories() }.ok().and_then(|cats| {
        let count = unsafe { cats.Count() }.ok()?;
        if count > 0 {
            unsafe { cats.get_Item(0) }
                .ok()
                .and_then(|cat| unsafe { cat.Name() }.ok().map(|n| n.to_string()))
        } else {
            None
        }
    });

    let last_deployment_change_time = unsafe { update.LastDeploymentChangeTime() }
        .ok()
        .and_then(ole_date_to_iso8601);

    let is_installed = unsafe { update.IsInstalled() }
        .ok()
        .map(VARIANT_BOOL::as_bool);
    let is_downloaded = unsafe { update.IsDownloaded() }
        .ok()
        .map(VARIANT_BOOL::as_bool);
    let is_hidden = unsafe { update.IsHidden() }.ok().map(VARIANT_BOOL::as_bool);
    let is_uninstallable = unsafe { update.IsUninstallable() }
        .ok()
        .map(VARIANT_BOOL::as_bool);

    // IUpdate2: IsPresent and RebootRequired — one cast, two getters.
    let (is_present, reboot_required) = update.cast::<IUpdate2>().ok().map_or((None, None), |u2| {
        let ip = unsafe { u2.IsPresent() }.ok().map(VARIANT_BOOL::as_bool);
        let rr = unsafe { u2.RebootRequired() }
            .ok()
            .map(VARIANT_BOOL::as_bool);
        (ip, rr)
    });

    let update_type = unsafe { update.Type() }
        .ok()
        .map_or("Unknown", |t| match t.0 {
            1 => "Software",
            2 => "Driver",
            _ => "Unknown",
        });

    let msrc_severity = unsafe { update.MsrcSeverity() }
        .ok()
        .map(|b| b.to_string())
        .filter(|s| !s.is_empty());

    let security_bulletin_ids = unsafe { update.SecurityBulletinIDs() }
        .ok()
        .map(|c| string_collection_to_vec(&c))
        .unwrap_or_default();

    // IUpdate3: CveIDs — one cast, one getter.
    let cve_ids: Vec<String> = update
        .cast::<IUpdate3>()
        .ok()
        .and_then(|u3| unsafe { u3.CveIDs() }.ok())
        .map(|c| string_collection_to_vec(&c))
        .unwrap_or_default();

    let installation_reboot_behavior = unsafe { update.InstallationBehavior() }
        .ok()
        .and_then(|beh| unsafe { beh.RebootBehavior() }.ok().map(|rb| rb.0));

    // RecommendedCpuSpeed / HardDiskSpace / Memory are on IUpdate directly.
    // For non-driver updates the WUA COM object returns 0.
    let recommended_cpu_speed = unsafe { update.RecommendedCpuSpeed() }.unwrap_or(0);
    let recommended_hard_disk_space = unsafe { update.RecommendedHardDiskSpace() }.unwrap_or(0);
    let recommended_memory = unsafe { update.RecommendedMemory() }.unwrap_or(0);

    ExtractedUpdate {
        update_id,
        revision_number,
        title,
        article_ids,
        category,
        msrc_severity,
        reboot_required,
        cve_ids,
        last_deployment_change_time,
        is_installed,
        is_downloaded,
        is_hidden,
        is_uninstallable,
        is_present,
        update_type,
        security_bulletin_ids,
        installation_reboot_behavior,
        recommended_cpu_speed,
        recommended_hard_disk_space,
        recommended_memory,
    }
}

/// Serialises an [`ExtractedUpdate`] into the JSON `Value` shape
/// expected by `host.updates_windows_updates()`.  Zero COM calls — the
/// view holds an owned copy of every field already.
fn extracted_to_json(v: &ExtractedUpdate) -> Value {
    json!({
        "title":                       v.title,
        "article_ids":                 v.article_ids,
        "category":                    v.category,
        "update_id":                   v.update_id,
        "revision_number":             v.revision_number,
        "last_deployment_change_time": v.last_deployment_change_time,
        "is_installed":                v.is_installed,
        "is_downloaded":               v.is_downloaded,
        "is_hidden":                   v.is_hidden,
        "is_present":                  v.is_present,
        "is_uninstallable":            v.is_uninstallable,
        "update_type":                 v.update_type,
        "msrc_severity":               v.msrc_severity,
        "security_bulletin_ids":       v.security_bulletin_ids,
        "cve_ids":                     v.cve_ids,
        "reboot_required":             v.reboot_required,
        "installation_reboot_behavior": v.installation_reboot_behavior,
        "recommended_cpu_speed":       v.recommended_cpu_speed,
        "recommended_hard_disk_space": v.recommended_hard_disk_space,
        "recommended_memory":          v.recommended_memory,
    })
}

/// In-memory cache populated once per `runtime.run()` by [`build_offline_payload`].
///
/// Sole consumer is `host.updates_windows_updates()`.  Before the SCCM
/// pipeline refactor (`SccmUpdate.cs`-strict DTO), this cache also held
/// an `UpdateID → WuaMeta` index used to enrich CCM rows; the new SCCM
/// path is faithful to `Updates.cs::GetSccmUpdates` and sources its data
/// from `CCM_UpdateStatus` + WUA online `QueryHistory` exclusively, so
/// the index has been removed.
pub(super) struct UpdatesCache {
    /// Full per-update JSON, in WUA collection order.
    pub windows_updates: Vec<Value>,
    /// Number of WUA collection items skipped during the build
    /// (`get_Item` failure).  Exposed as a partial-result warning when > 0.
    pub wua_skips: u32,
}

/// Builds the [`UpdatesCache`] from one offline WUA search.
///
/// Single pass over the collection, one JSON entry per update.  This is
/// the single most expensive call in the System Updates group; cached on
/// `HostState` for the duration of a run.
pub(super) fn build_offline_payload() -> Result<UpdatesCache, String> {
    ensure_com()?;
    // SAFETY: CoCreateInstance is always safe when COM is initialized.
    let session: IUpdateSession3 =
        unsafe { CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| format!("UpdateSession CoCreateInstance: {e}"))?;

    let collection = wua_offline_collection(&session)?;
    let count =
        unsafe { collection.Count() }.map_err(|e| format!("IUpdateCollection::Count: {e}"))?;

    let cap = usize::try_from(count).unwrap_or(0);
    let mut windows_updates: Vec<Value> = Vec::with_capacity(cap);
    let mut wua_skips: u32 = 0;

    for i in 0..count {
        let Ok(update) = (unsafe { collection.get_Item(i) }) else {
            wua_skips = wua_skips.saturating_add(1);
            continue;
        };

        // Single COM pass: ~18 getters per update fed into one struct
        // then serialised to JSON.  Until the SCCM refactor this loop
        // also produced an UpdateID-keyed index; with that gone the
        // hot path is simply JSON-only.
        let view = extract_update(&update);
        windows_updates.push(extracted_to_json(&view));
    }

    Ok(UpdatesCache {
        windows_updates,
        wua_skips,
    })
}

// ---------------------------------------------------------------------------
// Public bindings — they consume the caches above, host.rs orchestrates
// ---------------------------------------------------------------------------

/// `host.updates_reboot_required()` — deviation #28.
///
/// Returns `true` when WUA reports that a reboot is required before further
/// updates can be checked or applied.  Uses `ISystemInformation::RebootRequired`.
///
/// Faithful port of the `ComplianceApp` `UpdatesRebootRequired` transformer:
/// `WUApiLib.SystemInformation().RebootRequired`.
pub(super) fn updates_reboot_required() -> Result<bool, String> {
    ensure_com()?;
    let si: ISystemInformation =
        unsafe { CoCreateInstance(&SystemInformation, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| format!("SystemInformation CoCreateInstance: {e}"))?;

    unsafe { si.RebootRequired() }
        .map(VARIANT_BOOL::as_bool)
        .map_err(|e| format!("ISystemInformation::RebootRequired: {e}"))
}

/// `host.updates_reboot_required_before_installation()` — deviation #29.
///
/// Returns `true` when a reboot is required before additional updates can be
/// installed (i.e. a previous installation left a pending reboot).  Uses
/// `IUpdateInstaller::RebootRequiredBeforeInstallation`.
///
/// Faithful port of the `ComplianceApp` `UpdatesRebootRequiredBeforeInstallation`
/// transformer: `new UpdateInstaller().RebootRequiredBeforeInstallation`.
pub(super) fn updates_reboot_required_before_installation() -> Result<bool, String> {
    ensure_com()?;
    let installer: IUpdateInstaller =
        unsafe { CoCreateInstance(&UpdateInstaller, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| format!("UpdateInstaller CoCreateInstance: {e}"))?;

    unsafe { installer.RebootRequiredBeforeInstallation() }
        .map(VARIANT_BOOL::as_bool)
        .map_err(|e| format!("IUpdateInstaller::RebootRequiredBeforeInstallation: {e}"))
}

// ---------------------------------------------------------------------------
// SCCM updates pipeline — deviation #31
// ---------------------------------------------------------------------------
//
// Faithful Rust port of `ComplianceApp/.../Updates.cs::GetSccmUpdates`.
//
// Four sources merged on a `CCM_UpdateStatus.UniqueId` pivot:
// 1. `Root\ccm\SoftwareUpdates\UpdatesStore::CCM_UpdateStatus`
//    — primary pivot; provides UniqueId, Article, Title, UpdateClassification.
// 2. `Root\ccm\SoftwareUpdates\DeploymentAgent::CCM_TargetedUpdateEx1`
//    — provides Superseded; joined via case-insensitive substring match
//    of `UpdateId.Contains(uniqueId)`.
// 3. `Root\ccm\StateMsg::CCM_StateMsg`
//    — filtered to `TopicType == "500"` (Software Updates); provides
//    StateID (installed=3, required=2); joined via substring match of
//    `TopicID.Contains(uniqueId)`.
// 4. WUA **online** `IUpdateSearcher::QueryHistory(0, total)`
//    — provides install Date + ResultCode for the `Installed` derivation
//    and the `InstallDate` field.
//
// DTO is strict 1:1 with `SccmUpdate.cs` — 9 fields, snake_case:
// article_id, category, install_date, installed, required, superseded,
// targeted, title, update_id.  No `cve_ids` / `msrc_severity` /
// `reboot_required` — those live on `host.updates_windows_updates()`.

/// Projection of a `CCM_TargetedUpdateEx1` row.
#[derive(Debug, Clone)]
struct CcmTargeted {
    /// Strict: `null` if not a String variant (would corrupt substring match).
    update_id: Option<String>,
    /// Permissive: stringified for the `== "1"` comparison.
    superseded: Option<String>,
}

/// Projection of a `CCM_StateMsg` row.  `TopicType` is already filtered to
/// `"500"` at fetch time, so it doesn't need to be carried here.
#[derive(Debug, Clone)]
struct CcmStateMsg {
    /// Strict: `null` if not a String variant.
    topic_id: Option<String>,
    /// Permissive stringified value.
    state_id: Option<String>,
}

/// Projection of a `CCM_UpdateStatus` row.
#[derive(Debug, Clone)]
struct CcmUpdateStore {
    /// Pivot key.  Permissive stringification matches C# `GetStringProp`.
    unique_id: Option<String>,
    /// Permissive stringification (numeric in practice).
    article: Option<String>,
    /// Permissive stringification.
    title: Option<String>,
    /// Strict: must be a String for [`classification_from_guid`] to be meaningful.
    classification: Option<String>,
}

/// Pre-evaluated WUA `IUpdateHistoryEntry` projection.  `succeeded`
/// captures the `ResultCode == orcSucceeded` test once so the merge
/// function stays pure (no dependency on `windows-rs` types).
#[derive(Debug, Clone, Copy)]
struct WuaHistory {
    /// OLE DATE (UTC days since 1899-12-30) ; `None` when the WUA call
    /// returned an unset value (`0.0`) or a non-finite double.
    date: Option<f64>,
    succeeded: bool,
}

/// 1:1 port of `ComplianceApp.Shared.DTOs.Updates.SccmUpdate`.  Snake-case
/// at the field level (Lua / JSON convention), nine fields in canonical order.
///
/// `struct_excessive_bools` is silenced locally: the four flags
/// (`installed`, `required`, `targeted`, `superseded`) are mandated by
/// the C# DTO and a bitfield refactor would break the 1:1 mapping that
/// is the whole point of the port.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SccmUpdate {
    article_id: i64,
    category: Option<String>,
    title: Option<String>,
    update_id: Option<String>,
    installed: bool,
    required: bool,
    targeted: bool,
    superseded: bool,
    /// ISO 8601 UTC string (e.g. `"2024-04-09T14:23:11Z"`); `None` when
    /// no WUA history entry exists for this `UniqueId`.
    install_date: Option<String>,
}

// --- WMI fetchers ------------------------------------------------------

/// Returns `Ok(vec![])` for `WBEM_E_INVALID_NAMESPACE` (namespace absent
/// is the dominant non-managed-endpoint case), propagates every other
/// `WMIError` as a flattened `String`.
fn open_ccm_namespace(
    com: COMLibrary,
    namespace: &str,
) -> Result<Option<WMIConnection>, String> {
    match WMIConnection::with_namespace_path(namespace, com) {
        Ok(c) => Ok(Some(c)),
        Err(WMIError::HResultError { hres }) if hres == WBEM_E_INVALID_NAMESPACE.0 => Ok(None),
        Err(e) => Err(format!("WMI {namespace} connect: {e}")),
    }
}

/// Reads `Root\ccm\SoftwareUpdates\UpdatesStore::CCM_UpdateStatus`.
///
/// **`SELECT col, col, …` rather than `SELECT *`.** Several CCM
/// schemas embed CIM objects (e.g. `Status`, `Categories`,
/// `EnforcementDeadline`) that the `wmi` crate's `Variant` enum
/// cannot deserialize — even when we never touch them, `SELECT *`
/// would fail the whole row with
/// `WMIError::InvalidDeserializationVariantError`. Projecting only
/// the four fields actually consumed by [`merge_sccm_updates`]
/// sidesteps the issue entirely and keeps the WBEM cursor cheap.
fn fetch_ccm_update_store(com: COMLibrary) -> Result<Vec<CcmUpdateStore>, String> {
    let Some(conn) = open_ccm_namespace(com, r"Root\ccm\SoftwareUpdates\UpdatesStore")? else {
        return Ok(Vec::new());
    };
    let rows: Vec<HashMap<String, Variant>> = conn
        .raw_query("SELECT UniqueId, Article, Title, UpdateClassification FROM CCM_UpdateStatus")
        .map_err(|e| format!("CCM_UpdateStatus query: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|row| CcmUpdateStore {
            unique_id: ccm_str_permissive(&row, "UniqueId"),
            article: ccm_str_permissive(&row, "Article"),
            title: ccm_str_permissive(&row, "Title"),
            // Strict: UpdateClassification is documented as a string GUID;
            // if a provider drifts to a numeric we want None rather than
            // pass garbage to classification_from_guid.
            classification: ccm_str_strict(&row, "UpdateClassification"),
        })
        .collect())
}

/// Reads `Root\ccm\SoftwareUpdates\DeploymentAgent::CCM_TargetedUpdateEx1`.
///
/// Same `SELECT col, col` discipline as [`fetch_ccm_update_store`] —
/// some `CCM_TargetedUpdate*` schemas have `ScopedTypes` / Reference
/// properties that trip the `wmi` crate's variant deserializer.
fn fetch_ccm_targeted(com: COMLibrary) -> Result<Vec<CcmTargeted>, String> {
    let Some(conn) = open_ccm_namespace(com, r"Root\ccm\SoftwareUpdates\DeploymentAgent")? else {
        return Ok(Vec::new());
    };
    let rows: Vec<HashMap<String, Variant>> = conn
        .raw_query("SELECT UpdateId, Superseded FROM CCM_TargetedUpdateEx1")
        .map_err(|e| format!("CCM_TargetedUpdateEx1 query: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|row| CcmTargeted {
            // Strict: UpdateId is used in a substring match against
            // uniqueId; only a real string value can yield a meaningful
            // ContainsId result.
            update_id: ccm_str_strict(&row, "UpdateId"),
            superseded: ccm_str_permissive(&row, "Superseded"),
        })
        .collect())
}

/// Reads `Root\ccm\StateMsg::CCM_StateMsg`, **already filtered** to
/// `TopicType == "500"` (Software Updates topics).  Mirrors the C#
/// `.Where(s => string.Equals(s.TopicType, "500", StringComparison.Ordinal))`
/// filter applied right after fetch.
fn fetch_ccm_state_msg(com: COMLibrary) -> Result<Vec<CcmStateMsg>, String> {
    let Some(conn) = open_ccm_namespace(com, r"Root\ccm\StateMsg")? else {
        return Ok(Vec::new());
    };
    // Same SELECT-columns discipline (see [`fetch_ccm_update_store`]).
    // We need `TopicType` only for the in-Rust filter — it isn't carried
    // into the projection struct.
    let rows: Vec<HashMap<String, Variant>> = conn
        .raw_query("SELECT TopicType, TopicID, StateID FROM CCM_StateMsg")
        .map_err(|e| format!("CCM_StateMsg query: {e}"))?;
    Ok(rows
        .into_iter()
        .filter(|row| ccm_str_permissive(row, "TopicType").as_deref() == Some("500"))
        .map(|row| CcmStateMsg {
            // Strict: TopicID feeds a substring match against uniqueId.
            topic_id: ccm_str_strict(&row, "TopicID"),
            state_id: ccm_str_permissive(&row, "StateID"),
        })
        .collect())
}

// --- WUA online history ------------------------------------------------

/// Maximum retry attempts when the WUA COM session/searcher creation
/// fails with a transient HRESULT.  Mirrors the C# `MAX_RETRY_ATTEMPTS`
/// constant (3) — WUA is known to return `RPC_E_SERVERCALL_RETRYLATER`
/// when the service is briefly busy.
const WUA_MAX_RETRY_ATTEMPTS: u32 = 3;

/// Pulls every `IUpdateHistoryEntry`, indexed by
/// `UpdateIdentity.UpdateID` (lowercase, matching the C#
/// `StringComparer.OrdinalIgnoreCase` dictionary).
///
/// **Online flag.** The C# sets `searcher.Online = true` before
/// `QueryHistory` — but the call reads `%windir%\SoftwareDistribution`
/// locally, no WSUS round-trip.  We preserve the flag for parity even
/// though it's a no-op for this method.
///
/// Returns `Ok(empty_map)` on a definitive failure (after retries
/// exhausted) so the caller can keep merging CCM data without
/// `InstallDate`.  Individual entry-level errors are skipped, matching
/// the C# `catch (COMException ex) { _logger.LogDebug(...) }` pattern.
fn fetch_wua_history() -> Result<HashMap<String, WuaHistory>, String> {
    ensure_com()?;
    // Retry loop around the IUpdateSession + searcher creation.  Once
    // we have a working searcher, the QueryHistory call itself is
    // treated as terminal (success or empty-map on failure).
    //
    // `last_err` is initialised with a sentinel and is guaranteed to be
    // overwritten on every iteration that does not short-circuit out via
    // `Ok(map)`.  Using `String` (not `Option<String>`) eliminates the
    // dead `unwrap_or_else` fallback the previous shape required.
    let mut last_err = String::from("WUA QueryHistory retry loop did not run");
    for attempt in 1..=WUA_MAX_RETRY_ATTEMPTS {
        match build_wua_history() {
            Ok(map) => return Ok(map),
            Err(e) => {
                last_err = e;
                if attempt < WUA_MAX_RETRY_ATTEMPTS {
                    // 100, 200, 300 ms backoff — same shape as the C#
                    // `Thread.Sleep(100 * attempt)`.
                    sleep(Duration::from_millis(u64::from(100 * attempt)));
                }
            }
        }
    }
    // Soft-fail: bubble the last error up; the orchestrator demotes it
    // to "empty history" and lets SCCM merging proceed.
    Err(last_err)
}

/// One attempt at building the WUA history map.  Split from
/// [`fetch_wua_history`] so the retry loop stays readable.
fn build_wua_history() -> Result<HashMap<String, WuaHistory>, String> {
    // SAFETY: ensure_com() in the caller already initialised COM.
    let session: IUpdateSession =
        unsafe { CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| format!("UpdateSession CoCreateInstance: {e}"))?;
    let searcher: IUpdateSearcher = unsafe { session.CreateUpdateSearcher() }
        .map_err(|e| format!("IUpdateSession::CreateUpdateSearcher: {e}"))?;
    // SetOnline(true) for parity with the C# — see fn-level doc.
    unsafe { searcher.SetOnline(true.into()) }
        .map_err(|e| format!("IUpdateSearcher::SetOnline(true): {e}"))?;

    let total = unsafe { searcher.GetTotalHistoryCount() }
        .map_err(|e| format!("IUpdateSearcher::GetTotalHistoryCount: {e}"))?;
    if total <= 0 {
        return Ok(HashMap::new());
    }

    let coll = unsafe { searcher.QueryHistory(0, total) }
        .map_err(|e| format!("IUpdateSearcher::QueryHistory: {e}"))?;
    let count = unsafe { coll.Count() }
        .map_err(|e| format!("IUpdateHistoryEntryCollection::Count: {e}"))?;
    let cap = usize::try_from(count).unwrap_or(0);
    let mut map: HashMap<String, WuaHistory> = HashMap::with_capacity(cap);
    for i in 0..count {
        // Per-entry errors are silently dropped, like the C# debug-log
        // catch.  The history is best-effort enrichment.
        let Ok(entry) = (unsafe { coll.get_Item(i) }) else {
            continue;
        };
        if let Some((key, hist)) = extract_history_entry(&entry) {
            // C# uses OrdinalIgnoreCase + "latest wins on duplicate
            // UpdateID" (`if (!historyById.TryGetValue(hId, out var
            // prev) || hDate > prev.Date)`).  We replicate via lowercase
            // keys + max-by-date upsert.
            let lower = key.to_ascii_lowercase();
            match map.get(&lower) {
                Some(existing) if existing.date >= hist.date => {}
                _ => {
                    map.insert(lower, hist);
                }
            }
        }
    }
    Ok(map)
}

/// Reads `(UpdateID, WuaHistory)` from a single history entry.  Returns
/// `None` when either the `UpdateID` or the date can't be retrieved.
fn extract_history_entry(entry: &IUpdateHistoryEntry) -> Option<(String, WuaHistory)> {
    let id = unsafe { entry.UpdateIdentity() }.ok()?;
    let update_id = unsafe { id.UpdateID() }.ok()?.to_string();
    if update_id.is_empty() {
        return None;
    }
    let date = unsafe { entry.Date() }.ok();
    let result_code = unsafe { entry.ResultCode() }.ok().map_or(0, |rc| rc.0);
    Some((
        update_id,
        WuaHistory {
            // Normalise `0.0` and non-finite to None right here so the
            // merge function only deals with valid OLE DATEs.
            date: date.filter(|d| d.is_finite() && *d != 0.0),
            succeeded: result_code == OPERATION_RESULT_SUCCEEDED,
        },
    ))
}

// --- Pure merge --------------------------------------------------------

/// Pure: combines the four pre-fetched data sources into the canonical
/// `SccmUpdate` list.  No I/O, no COM — fully unit-testable.
///
/// Algorithmic mirror of `Updates.cs::GetSccmUpdates` lines 596-662.
/// `history` keys are expected to be lowercase (`OrdinalIgnoreCase`
/// equivalent on ASCII-only GUIDs).
fn merge_sccm_updates(
    store: &[CcmUpdateStore],
    targeted: &[CcmTargeted],
    state_msgs: &[CcmStateMsg],
    history: &HashMap<String, WuaHistory>,
) -> Vec<SccmUpdate> {
    // `Vec` + `iter_mut().find` instead of `IndexMap` to avoid a new
    // dependency.  N (typical CCM_UpdateStatus row count) is < 1000 and
    // the duplicate-uniqueId case is rare ; linear-scan stays sub-ms.
    let mut out: Vec<(String /* uid lowercase */, SccmUpdate)> = Vec::with_capacity(store.len());

    for entry in store {
        let Some(uid) = entry.unique_id.as_deref() else {
            continue;
        };
        if uid.trim().is_empty() {
            continue;
        }

        let uid_lower = uid.to_ascii_lowercase();
        let h = history.get(&uid_lower).copied();
        let has_history = h.is_some();

        let targeted_row = targeted
            .iter()
            .find(|tr| contains_id_ci(tr.update_id.as_deref(), uid));
        let is_superseded = targeted_row
            .and_then(|tr| tr.superseded.as_deref())
            .is_some_and(|s| s == "1");

        let st = state_msgs
            .iter()
            .find(|sr| contains_id_ci(sr.topic_id.as_deref(), uid));
        let (installed, required) = compute_state_flags(
            st.and_then(|s| s.state_id.as_deref()),
            h.is_some_and(|h| h.succeeded),
        );

        // M1 — `|| has_history` is intentional and faithful to the C#
        // (`Updates.cs::GetSccmUpdates`, see plan DTO row for `targeted`).
        // Degraded-mode parity: when WUA `QueryHistory` fails and
        // `has_history` is uniformly false, this collapses to
        // `targeted_row.is_some()`, exactly matching the C# behaviour
        // when `historyCol == null`.  Do NOT remove this disjunction
        // without re-verifying against the upstream C#.
        let targeted_flag = targeted_row.is_some() || has_history;
        let article_id = parse_article_id(entry.article.as_deref());
        let category = entry.classification.as_deref().map(classification_from_guid);
        let install_date = h.and_then(|h| h.date).and_then(ole_date_to_iso8601);
        let title = entry.title.clone();

        let new = SccmUpdate {
            article_id,
            category,
            title,
            update_id: Some(uid.to_string()),
            installed,
            required,
            targeted: targeted_flag,
            superseded: is_superseded,
            install_date,
        };

        if let Some((_, existing)) = out.iter_mut().find(|(k, _)| *k == uid_lower) {
            // Faithful port of the C# `byId[uniqueId] = existing with { … }`
            // merge rules (`Updates.cs::GetSccmUpdates`).  Each rule is
            // conservative: existing data wins unless the new data is
            // strictly more informative.
            //
            // `install_date`: `Option<String>` has the right `Ord` for free
            // — `None < Some(_)`, and ISO 8601 UTC `Some` values compare
            // lexicographically (the format is fixed-width `YYYY-MM-DDTHH:MM:SSZ`
            // so lexicographic order = temporal order).  So the desired
            // "max wins, None loses" rule reduces to a single `>` check.
            if new.install_date > existing.install_date {
                existing.install_date = new.install_date;
            }
            if existing.article_id == 0 && new.article_id != 0 {
                existing.article_id = new.article_id;
            }
            if existing.category.is_none() {
                existing.category = new.category;
            }
            if existing.title.is_none() {
                existing.title = new.title;
            }
            existing.installed = existing.installed || new.installed;
            existing.required = existing.required || new.required;
            existing.targeted = existing.targeted || new.targeted;
            existing.superseded = existing.superseded || new.superseded;
        } else {
            out.push((uid_lower, new));
        }
    }

    out.into_iter().map(|(_, v)| v).collect()
}

// --- Sort comparator ---------------------------------------------------

/// 5-key cascading comparator mirroring the C# LINQ chain:
/// `.OrderBy(u => u.InstallDate is null) .ThenByDescending(u => u.InstallDate)
///  .ThenBy(u => u.ArticleID) .ThenBy(u => u.Title, Ordinal)
///  .ThenBy(u => u.UpdateID, Ordinal)`.
///
/// ISO 8601 ZULU strings are lexicographically comparable so the date
/// ordering reduces to a `String` cmp.
fn compare_sccm_update_ordering(a: &SccmUpdate, b: &SccmUpdate) -> std::cmp::Ordering {
    a.install_date
        .is_none()
        .cmp(&b.install_date.is_none())
        .then_with(|| b.install_date.cmp(&a.install_date))
        .then_with(|| a.article_id.cmp(&b.article_id))
        .then_with(|| a.title.cmp(&b.title))
        .then_with(|| a.update_id.cmp(&b.update_id))
}

// --- JSON serialisation -----------------------------------------------

/// Serialises an `SccmUpdate` into the 9-key JSON object specified by
/// `SccmUpdate.cs`.
///
/// **Output key order** is alphabetical: `article_id, category,
/// install_date, installed, required, superseded, targeted, title,
/// update_id`.  This is **not** guaranteed by the `json!` macro alone —
/// `json!` produces a `serde_json::Map<String, Value>` whose backing
/// store is `BTreeMap` by default.  The alphabetical ordering is a
/// project-wide invariant documented in `CLAUDE.md` § "JSON key
/// ordering".
///
/// If `serde_json/preserve_order` is ever enabled (it currently is not),
/// the `Map` backing switches to `IndexMap` (insertion order) and the
/// alphabetical guarantee evaporates.  The literal key order in the
/// `json!` block below is **also** alphabetical so the output stays
/// stable under either backing — belt and suspenders.
fn sccm_update_to_json(u: SccmUpdate) -> Value {
    // Destructure to actually consume the owned fields — without it,
    // `json!` would clone every String/Option<String> through serde
    // and clippy::needless_pass_by_value would (correctly) complain.
    let SccmUpdate {
        article_id,
        category,
        title,
        update_id,
        installed,
        required,
        targeted,
        superseded,
        install_date,
    } = u;
    json!({
        "article_id":   article_id,
        "category":     category,
        "install_date": install_date,
        "installed":    installed,
        "required":     required,
        "superseded":   superseded,
        "targeted":     targeted,
        "title":        title,
        "update_id":    update_id,
    })
}

/// `host.updates_sccm_updates()` — deviation #31.
///
/// Faithful Rust port of `Updates.cs::GetSccmUpdates`.  See module-level
/// section "SCCM updates pipeline" for the architecture.  DTO is strict
/// 1:1 with `SccmUpdate.cs` (9 fields, `snake_case`).
///
/// Failure semantics:
/// - `WBEM_E_INVALID_NAMESPACE` on the primary `CCM_UpdateStatus`
///   namespace → silently returns `[]` (no SCCM agent on this machine).
/// - Same on the secondary namespaces (`DeploymentAgent`, `StateMsg`)
///   → continue with an empty slice for that source.  This is rare in
///   practice (if `UpdatesStore` exists the others usually exist too)
///   but it keeps `host.updates_sccm_updates()` robust against partial
///   SCCM installations.
/// - WUA online history failure (after 3 retries) → continues with an
///   empty history map ; `install_date` will be `null` and `installed`
///   relies solely on the `CCM_StateMsg` `StateID == "3"` path.
/// - Any other WMI error propagates as `Err` so the caller can record
///   it in `host.errors()`.
pub(super) fn updates_sccm_updates() -> Result<Vec<Value>, String> {
    ensure_com()?;
    // SAFETY: ensure_com() above guarantees COM is initialized on this thread.
    let com = unsafe { COMLibrary::assume_initialized() };

    // Source 1 — pivot.  If the UpdatesStore namespace is absent we have
    // no SCCM agent at all, so the only reasonable answer is `[]`.
    let store = fetch_ccm_update_store(com)?;
    if store.is_empty() {
        return Ok(Vec::new());
    }

    // Sources 2 & 3 — lookup tables.  Independent INVALID_NAMESPACE
    // handling in each fetcher means a partial SCCM install degrades
    // gracefully to "no superseded info" / "no state info" rather than
    // crashing the whole binding.
    let targeted = fetch_ccm_targeted(com)?;
    let state_msgs = fetch_ccm_state_msg(com)?;

    // Source 4 — WUA online history.  Errors are demoted to an empty
    // map (with the caller logging via the recorded host.errors() entry
    // in `host.rs`).  Mirrors the C# `catch (COMException) { ... break;
    // }` that lets the merge continue with `historyCol = null`.
    let history = fetch_wua_history().unwrap_or_default();

    // Merge → filter `Targeted == true` → sort.  Order matters: the
    // filter removes ~50% of rows on a typical managed endpoint so it
    // saves the comparator some work.
    let mut merged = merge_sccm_updates(&store, &targeted, &state_msgs, &history);
    merged.retain(|u| u.targeted);
    merged.sort_by(compare_sccm_update_ordering);

    Ok(merged.into_iter().map(sccm_update_to_json).collect())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
// `doc_markdown` keeps flagging the numeric literals in the test docstrings
// (e.g. `25_568.0`, `10_957`) as if they were Rust identifiers needing
// backticks.  They are arithmetic vectors used to justify each test, not
// code references — backticking every number would hurt readability.
#[allow(clippy::doc_markdown)]
mod tests {
    use super::ole_date_to_iso8601;

    /// OLE DATE = 0.0 is the "unset / no value" sentinel.
    #[test]
    fn zero_sentinel_returns_none() {
        assert_eq!(ole_date_to_iso8601(0.0), None);
    }

    /// Dates before the Unix epoch (1970-01-01) must be rejected.
    ///
    /// OLE 25_568.0 = 1969-12-31T00:00:00Z (one day before epoch).
    /// unix_secs = (25_568.0 − 25_569.0) × 86_400.0 = −86_400.0 < 0 → None.
    #[test]
    fn pre_epoch_date_returns_none() {
        assert_eq!(ole_date_to_iso8601(25_568.0), None);
    }

    /// OLE 25_569.0 = 1970-01-01T00:00:00Z (Unix epoch boundary).
    ///
    /// unix_secs = 0.0 → filetime_ticks = 116_444_736_000_000_000 (the same
    /// value already validated by `winver::tests`).
    #[test]
    fn unix_epoch_exactly() {
        assert_eq!(
            ole_date_to_iso8601(25_569.0),
            Some("1970-01-01T00:00:00Z".to_string())
        );
    }

    /// OLE 36_526.0 = 2000-01-01T00:00:00Z (Y2K boundary).
    ///
    /// Days from 1970-01-01 to 2000-01-01 = 30 × 365 + 7 leap days = 10_957.
    /// unix_secs = 10_957 × 86_400 = 946_684_800. OLE = 10_957 + 25_569 = 36_526.
    #[test]
    fn y2k_midnight() {
        assert_eq!(
            ole_date_to_iso8601(36_526.0),
            Some("2000-01-01T00:00:00Z".to_string())
        );
    }

    /// OLE 36_892.0 = 2001-01-01T00:00:00Z.
    ///
    /// 2000 was a leap year (366 days): 36_526 + 366 = 36_892.
    /// unix_secs = 946_684_800 + 366 × 86_400 = 978_307_200.
    #[test]
    fn year_after_y2k_midnight() {
        assert_eq!(
            ole_date_to_iso8601(36_892.0),
            Some("2001-01-01T00:00:00Z".to_string())
        );
    }

    /// Non-finite IEEE-754 doubles (NaN, ±∞) must short-circuit to `None`,
    /// not slip through the lossy `(NaN as i64) == 0` cast and produce a
    /// bogus 1970-01-01.
    #[test]
    fn non_finite_returns_none() {
        assert_eq!(ole_date_to_iso8601(f64::NAN), None);
        assert_eq!(ole_date_to_iso8601(f64::INFINITY), None);
        assert_eq!(ole_date_to_iso8601(f64::NEG_INFINITY), None);
    }

    // -----------------------------------------------------------------
    // SCCM pure helpers — deviation #31
    // -----------------------------------------------------------------

    use super::{
        CcmStateMsg, CcmTargeted, CcmUpdateStore, SccmUpdate, WuaHistory, classification_from_guid,
        compare_sccm_update_ordering, compute_state_flags, contains_id_ci, merge_sccm_updates,
        parse_article_id,
    };
    use std::collections::HashMap;

    // --- classification_from_guid ------------------------------------

    /// Known GUID resolves to its canonical label.  Picks the
    /// "Security Updates" mapping because the GUID begins with `0`
    /// which makes the uppercase normalization more visible.
    #[test]
    fn classification_known_guid_maps_to_label() {
        assert_eq!(
            classification_from_guid("0FA1201D-4330-4FA8-8AE9-B877473B6441"),
            "Security Updates"
        );
    }

    /// C# does `.ToUpper()` before lookup; mixed/lower case must match.
    #[test]
    fn classification_uppercase_normalization() {
        assert_eq!(
            classification_from_guid("0fa1201d-4330-4fa8-8ae9-b877473b6441"),
            "Security Updates"
        );
        assert_eq!(
            classification_from_guid("0Fa1201D-4330-4Fa8-8aE9-b877473B6441"),
            "Security Updates"
        );
    }

    /// Unknown GUID is returned verbatim (with the caller's original
    /// casing — the C# returns `guid` not `guid.ToUpper()` on miss).
    #[test]
    fn classification_unknown_guid_returns_input() {
        let unknown = "AAAAAAAA-1111-2222-3333-444444444444";
        assert_eq!(classification_from_guid(unknown), unknown);
        // Lower-case input also comes back unchanged on miss.
        let lower = "aaaaaaaa-1111-2222-3333-444444444444";
        assert_eq!(classification_from_guid(lower), lower);
    }

    // --- parse_article_id --------------------------------------------

    #[test]
    fn parse_article_id_valid_number() {
        assert_eq!(parse_article_id(Some("5034441")), 5_034_441);
    }

    /// `long.TryParse(s.Trim(), …)` accepts surrounding whitespace.
    #[test]
    fn parse_article_id_with_whitespace() {
        assert_eq!(parse_article_id(Some("  123  ")), 123);
    }

    #[test]
    fn parse_article_id_empty_or_none() {
        assert_eq!(parse_article_id(None), 0);
        assert_eq!(parse_article_id(Some("")), 0);
        assert_eq!(parse_article_id(Some("   ")), 0);
    }

    /// `long.TryParse` is strict — "KB5034441" is *not* parseable.
    /// The C# code path keeps `articleId = 0` when parsing fails.
    #[test]
    fn parse_article_id_non_numeric() {
        assert_eq!(parse_article_id(Some("KB5034441")), 0);
        assert_eq!(parse_article_id(Some("123abc")), 0);
    }

    // --- contains_id_ci ----------------------------------------------

    /// Substring match across case boundary: a wrapped UpdateId
    /// containing the UniqueId in lowercase still finds it via the
    /// `OrdinalIgnoreCase` semantics.
    #[test]
    fn contains_id_ci_substring_match() {
        assert!(contains_id_ci(
            Some("{0fa1201d-4330-4fa8-8ae9-b877473b6441}_update_x"),
            "0FA1201D-4330-4FA8-8AE9-B877473B6441",
        ));
        assert!(contains_id_ci(
            Some("PREFIX_AAAA-BBBB-CCCC_SUFFIX"),
            "aaaa-bbbb-cccc",
        ));
    }

    #[test]
    fn contains_id_ci_no_match_returns_false() {
        assert!(!contains_id_ci(Some("nothing-to-see"), "absent"));
    }

    #[test]
    fn contains_id_ci_handles_none_haystack() {
        assert!(!contains_id_ci(None, "any-needle"));
    }

    // --- compute_state_flags -----------------------------------------

    /// `StateID == "3"` → installed, not required.
    #[test]
    fn compute_state_flags_state_3_is_installed() {
        assert_eq!(compute_state_flags(Some("3"), false), (true, false));
    }

    /// `StateID == "2"` → required, not installed.
    #[test]
    fn compute_state_flags_state_2_is_required() {
        assert_eq!(compute_state_flags(Some("2"), false), (false, true));
    }

    /// No StateID but WUA history reports orcSucceeded → installed=true.
    #[test]
    fn compute_state_flags_history_success_falls_through() {
        assert_eq!(compute_state_flags(None, true), (true, false));
    }

    /// Unknown StateID with no history → both flags false.
    #[test]
    fn compute_state_flags_unknown_state() {
        assert_eq!(compute_state_flags(Some("99"), false), (false, false));
        assert_eq!(compute_state_flags(None, false), (false, false));
    }

    // --- compare_sccm_update_ordering --------------------------------

    fn dto(install_date: Option<&str>, article_id: i64, title: Option<&str>, uid: &str) -> SccmUpdate {
        SccmUpdate {
            article_id,
            category: None,
            title: title.map(str::to_string),
            update_id: Some(uid.to_string()),
            installed: false,
            required: false,
            targeted: true,
            superseded: false,
            install_date: install_date.map(str::to_string),
        }
    }

    /// `InstallDate is null` rows go after `InstallDate` is set rows.
    #[test]
    fn compare_sort_install_date_nulls_last() {
        let with = dto(Some("2024-01-01T00:00:00Z"), 100, Some("x"), "a");
        let without = dto(None, 100, Some("x"), "a");
        // Equal article_id+title+uid, only install_date diverges → null is greater.
        assert_eq!(
            compare_sccm_update_ordering(&with, &without),
            std::cmp::Ordering::Less,
        );
    }

    /// Among non-null InstallDate, more recent first (descending).
    #[test]
    fn compare_sort_install_date_desc() {
        let older = dto(Some("2024-01-01T00:00:00Z"), 100, Some("x"), "a");
        let newer = dto(Some("2024-12-01T00:00:00Z"), 100, Some("x"), "a");
        assert_eq!(
            compare_sccm_update_ordering(&newer, &older),
            std::cmp::Ordering::Less,
        );
    }

    /// Same InstallDate → tie-break on ArticleID ascending.
    #[test]
    fn compare_sort_then_by_article_id() {
        let a = dto(Some("2024-01-01T00:00:00Z"), 100, Some("x"), "a");
        let b = dto(Some("2024-01-01T00:00:00Z"), 200, Some("x"), "a");
        assert_eq!(
            compare_sccm_update_ordering(&a, &b),
            std::cmp::Ordering::Less,
        );
    }

    /// Last two tie-breakers: Title then UpdateID (both ordinal ASC).
    #[test]
    fn compare_sort_then_by_title_and_update_id() {
        let a = dto(Some("2024-01-01T00:00:00Z"), 100, Some("aaa"), "u1");
        let b = dto(Some("2024-01-01T00:00:00Z"), 100, Some("bbb"), "u1");
        assert_eq!(
            compare_sccm_update_ordering(&a, &b),
            std::cmp::Ordering::Less,
        );
        let c = dto(Some("2024-01-01T00:00:00Z"), 100, Some("aaa"), "u0");
        let d = dto(Some("2024-01-01T00:00:00Z"), 100, Some("aaa"), "u1");
        assert_eq!(
            compare_sccm_update_ordering(&c, &d),
            std::cmp::Ordering::Less,
        );
    }

    // --- merge_sccm_updates ------------------------------------------

    /// Full fixture: 1 store row + 1 targeted row + 1 state-msg row + 1
    /// history entry → exactly one `SccmUpdate` with every field populated.
    /// The Y2K date (`36_526.0`) round-trips to `2000-01-01T00:00:00Z`
    /// (see `y2k_midnight` test above for the arithmetic).
    #[test]
    fn merge_simple_pipeline_produces_expected_dto() {
        let uid = "0FA1201D-4330-4FA8-8AE9-B877473B6441";
        let store = vec![CcmUpdateStore {
            unique_id: Some(uid.to_string()),
            article: Some("5034441".to_string()),
            title: Some("Cumulative Update KB5034441".to_string()),
            classification: Some(uid.to_string()),
        }];
        let targeted = vec![CcmTargeted {
            update_id: Some(format!("wrapper-{uid}-suffix")),
            superseded: Some("1".to_string()),
        }];
        let state_msgs = vec![CcmStateMsg {
            topic_id: Some(format!("topic[{uid}]")),
            state_id: Some("3".to_string()),
        }];
        let mut history: HashMap<String, WuaHistory> = HashMap::new();
        history.insert(
            uid.to_ascii_lowercase(),
            WuaHistory {
                date: Some(36_526.0),
                succeeded: true,
            },
        );

        let out = merge_sccm_updates(&store, &targeted, &state_msgs, &history);
        assert_eq!(out.len(), 1);
        let u = &out[0];
        assert_eq!(u.article_id, 5_034_441);
        assert_eq!(u.category.as_deref(), Some("Security Updates"));
        assert_eq!(u.title.as_deref(), Some("Cumulative Update KB5034441"));
        assert_eq!(u.update_id.as_deref(), Some(uid));
        assert!(u.installed);
        assert!(!u.required);
        assert!(u.targeted);
        assert!(u.superseded);
        assert_eq!(u.install_date.as_deref(), Some("2000-01-01T00:00:00Z"));
    }

    /// Store rows without a `UniqueId` (null or whitespace) are skipped.
    /// Mirrors C# `if (string.IsNullOrWhiteSpace(uniqueId)) continue;`.
    #[test]
    fn merge_skips_store_entries_without_unique_id() {
        let store = vec![
            CcmUpdateStore {
                unique_id: None,
                article: Some("100".to_string()),
                title: Some("Null UID".to_string()),
                classification: None,
            },
            CcmUpdateStore {
                unique_id: Some("   ".to_string()),
                article: Some("200".to_string()),
                title: Some("Whitespace UID".to_string()),
                classification: None,
            },
            CcmUpdateStore {
                unique_id: Some("ABC-DEF".to_string()),
                article: Some("300".to_string()),
                title: Some("Valid".to_string()),
                classification: None,
            },
        ];
        let out = merge_sccm_updates(&store, &[], &[], &HashMap::new());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].article_id, 300);
        assert_eq!(out[0].title.as_deref(), Some("Valid"));
    }

    /// Duplicate UniqueIds across store rows merge per C#: first wins
    /// for nullable fields, `||` for booleans, max for InstallDate,
    /// "0 → non-zero" upgrade for ArticleID.
    #[test]
    fn merge_duplicate_unique_id_applies_merge_rules() {
        let uid = "DUPL-ID";
        let store = vec![
            CcmUpdateStore {
                unique_id: Some(uid.to_string()),
                article: Some("0".to_string()),
                title: None,
                classification: None,
            },
            CcmUpdateStore {
                unique_id: Some(uid.to_string()),
                article: Some("999".to_string()),
                title: Some("from second row".to_string()),
                classification: Some("0FA1201D-4330-4FA8-8AE9-B877473B6441".to_string()),
            },
        ];
        let targeted = vec![CcmTargeted {
            update_id: Some(uid.to_string()),
            superseded: Some("1".to_string()),
        }];
        let state_msgs = vec![CcmStateMsg {
            topic_id: Some(uid.to_string()),
            state_id: Some("2".to_string()),
        }];
        let out = merge_sccm_updates(&store, &targeted, &state_msgs, &HashMap::new());
        assert_eq!(out.len(), 1);
        let u = &out[0];
        // Article: 0 → 999 (upgrade rule applied)
        assert_eq!(u.article_id, 999);
        // Title: None → Some(...) (first-or-second fill rule)
        assert_eq!(u.title.as_deref(), Some("from second row"));
        // Category: same fill rule.
        assert_eq!(u.category.as_deref(), Some("Security Updates"));
        // Booleans: required from both rows (StateID==2) → OR-merged true.
        assert!(u.required);
        // Superseded from both rows → true.
        assert!(u.superseded);
        // Targeted from both rows → true.
        assert!(u.targeted);
        // No history → not installed.
        assert!(!u.installed);
        // No history → install_date None.
        assert!(u.install_date.is_none());
    }

    /// The `targeted.UpdateId.Contains(uniqueId)` substring match is
    /// case-insensitive — a lowercase `uniqueId` must still match an
    /// uppercase `UpdateId` wrapper.
    #[test]
    fn merge_targeted_substring_match_case_insensitive() {
        let uid = "abc-def-1234"; // lowercase pivot
        let store = vec![CcmUpdateStore {
            unique_id: Some(uid.to_string()),
            article: Some("1".to_string()),
            title: Some("t".to_string()),
            classification: None,
        }];
        // Targeted wraps the same id in uppercase + extra prefix.
        let targeted = vec![CcmTargeted {
            update_id: Some("WRAPPER:ABC-DEF-1234:END".to_string()),
            superseded: Some("1".to_string()),
        }];
        let out = merge_sccm_updates(&store, &targeted, &[], &HashMap::new());
        assert_eq!(out.len(), 1);
        assert!(out[0].superseded, "superseded should be picked up despite case mismatch");
        assert!(out[0].targeted, "targeted should be true via targetedRow presence");
    }
}
