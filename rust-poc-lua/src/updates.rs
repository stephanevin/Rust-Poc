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
//!   feeds both `updates_windows_updates` (full JSON list) and
//!   `updates_sccm_updates` (`UpdateID → WuaMeta` join index).  Without the
//!   cache, each binding would re-run the offline search, doubling the most
//!   expensive call on a typical run (~1-2 s per search on 500+ updates).
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
//! | 30 | `updates_windows_updates` | Faithful port; no 90 s `CancellationToken` timeout; shares offline WUA search with #31 |
//! | 31 | `updates_sccm_updates` | WMI `Root\ccm` + 1 offline WUA search for join; empty when SCCM absent |

#![allow(clippy::too_many_lines)]

use std::collections::HashMap;

use serde_json::{Value, json};
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
};
use windows::Win32::System::UpdateAgent::{
    ISearchResult, IStringCollection, ISystemInformation, IUpdate, IUpdate2, IUpdate3,
    IUpdateCollection, IUpdateInstaller, IUpdateSearcher3, IUpdateService, IUpdateService2,
    IUpdateServiceCollection, IUpdateServiceManager2, IUpdateSession3, SystemInformation,
    UpdateInstaller, UpdateServiceManager, UpdateSession,
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

/// Extracts a `String` field from a CCM WMI result row.
fn ccm_str(row: &HashMap<String, Variant>, key: &str) -> Option<String> {
    match row.get(key)? {
        Variant::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Extracts a `u32` field from a CCM WMI result row.
///
/// Accepts both `UI4` (unsigned) and `I4` (signed) variants because CCM
/// providers are inconsistent about numeric types across Windows versions.
fn ccm_u32(row: &HashMap<String, Variant>, key: &str) -> Option<u32> {
    match row.get(key)? {
        Variant::UI4(n) => Some(*n),
        Variant::I4(n) => u32::try_from(*n).ok(),
        _ => None,
    }
}

/// Extracts a `bool` field from a CCM WMI result row.
fn ccm_bool(row: &HashMap<String, Variant>, key: &str) -> Option<bool> {
    match row.get(key)? {
        Variant::Bool(b) => Some(*b),
        _ => None,
    }
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

/// Single-pass snapshot of every WUA `IUpdate` field consumed by either
/// `host.updates_windows_updates()` (full JSON) or
/// `host.updates_sccm_updates()` (SCCM join via [`WuaMeta`]).
///
/// Populated once per update by [`extract_update`].  Replaces the
/// previous `extract_identity` + `update_to_json` + ad-hoc `WuaMeta`
/// extraction trio, which read the same six fields twice via COM
/// (`Title`, `KBArticleIDs`, `Categories`, `MsrcSeverity`,
/// `RebootRequired` through `IUpdate2`, `CveIDs` through `IUpdate3`).
/// The redundancy was wasting ~22 % of the COM round-trips on a typical
/// 500-update endpoint — see the perf note in [`build_offline_payload`].
struct ExtractedUpdate {
    // --- Identity (one Identity() COM read, two consumers) ---
    update_id: Option<String>,
    revision_number: Option<i32>,

    // --- Shared between JSON serialisation and WuaMeta ---
    title: Option<String>,
    article_ids: Vec<String>,
    category: Option<String>,
    msrc_severity: Option<String>,
    reboot_required: Option<bool>,
    cve_ids: Vec<String>,

    // --- JSON-only ---
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

/// Consumes an [`ExtractedUpdate`] into the trimmed [`WuaMeta`] view
/// used by the SCCM join.  Zero COM calls; every `String` / `Vec<String>`
/// is moved out, not cloned.
fn extracted_into_wua_meta(v: ExtractedUpdate) -> WuaMeta {
    WuaMeta {
        title: v.title,
        article_ids: v.article_ids,
        msrc_severity: v.msrc_severity,
        category: v.category,
        reboot_required: v.reboot_required.unwrap_or(false),
        cve_ids: v.cve_ids,
    }
}

/// Minimal WUA metadata used for SCCM enrichment (join key: `UpdateID`).
pub(super) struct WuaMeta {
    pub title: Option<String>,
    pub article_ids: Vec<String>,
    pub msrc_severity: Option<String>,
    pub category: Option<String>,
    pub reboot_required: bool,
    pub cve_ids: Vec<String>,
}

/// In-memory cache populated once per `runtime.run()` by [`build_offline_payload`].
///
/// `windows_updates` is consumed by `host.updates_windows_updates()` and
/// `index` is consumed by `host.updates_sccm_updates()`.  Both are produced
/// from a **single** offline WUA search — the most expensive call in the
/// System Updates group — so two consumers share the cost.
pub(super) struct UpdatesCache {
    /// Full per-update JSON, in WUA collection order.
    pub windows_updates: Vec<Value>,
    /// `UpdateID → WuaMeta` for SCCM correlation.  Empty `UpdateID`s are
    /// intentionally not indexed (fix #8: would collide on `""`).
    pub index: HashMap<String, WuaMeta>,
    /// Number of WUA collection items skipped during the build (no
    /// `UpdateID` or `get_Item` failure).  Exposed as a partial-result
    /// warning when > 0.
    pub wua_skips: u32,
}

/// Builds the [`UpdatesCache`] from one offline WUA search.
///
/// A single pass over the collection produces both the full JSON list (for
/// `updates_windows_updates`) and the `UpdateID → WuaMeta` index (for
/// `updates_sccm_updates`).  This is the single most expensive call in the
/// System Updates group; cached on `HostState` for the duration of a run.
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
    let mut index: HashMap<String, WuaMeta> = HashMap::with_capacity(cap);
    let mut wua_skips: u32 = 0;

    for i in 0..count {
        let Ok(update) = (unsafe { collection.get_Item(i) }) else {
            wua_skips = wua_skips.saturating_add(1);
            continue;
        };

        // Single COM pass: ~18 getters per update, fed into one struct
        // that is then borrowed for the JSON view and moved into WuaMeta.
        // Replaces an older two-pass design which re-read `Title`,
        // `KBArticleIDs`, `Categories`, `MsrcSeverity`, `RebootRequired`
        // and `CveIDs` from COM a second time for the SCCM join — at
        // ~500 updates that was ~3 000 redundant cross-process calls.
        let view = extract_update(&update);

        // The full JSON keeps every item, even ones without a usable
        // UpdateID — they remain visible in `updates_windows_updates`.
        windows_updates.push(extracted_to_json(&view));

        // Fix #8: do not insert empty UpdateID into the index; otherwise
        // multiple ID-less updates would collide on key `""` and the join
        // would attach the last one's metadata to every CCM row whose
        // UpdateID is also missing.
        match view.update_id.as_deref() {
            Some(id) if !id.is_empty() => {
                // Clone the ~38-char UpdateID for the HashMap key; the
                // rest of `view` is moved into the WuaMeta value, so no
                // String/Vec gets cloned.
                let key = id.to_string();
                index.insert(key, extracted_into_wua_meta(view));
            }
            _ => {
                wua_skips = wua_skips.saturating_add(1);
            }
        }
    }

    Ok(UpdatesCache {
        windows_updates,
        index,
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

/// `host.updates_sccm_updates()` — deviation #31.
///
/// Queries WMI `Root\ccm\SoftwareUpdates\DeploymentAgent` for
/// `CCM_TargetedUpdateEx1` (SCCM-targeted updates on this machine), then
/// enriches each entry with WUA metadata from the shared cache.
///
/// ## CCM connect failure modes (fix #3)
///
/// - `WBEM_E_INVALID_NAMESPACE` → no SCCM agent installed → `Ok([])`
///   (the dominant case on non-managed endpoints).
/// - Any other HRESULT (access denied, WMI service stopped, …)
///   → propagate as `Err`; the caller records it.
///
/// ## Per-field fallback when `cache_index` is `None`
///
/// `cache_index` is `Some(_)` when [`build_offline_payload`] succeeded,
/// `None` when it failed.  In the latter case the caller (the
/// `install_updates_bindings` orchestrator in `host.rs`) is responsible
/// for recording the cache-init diagnostic under its canonical error
/// key — this module is intentionally agnostic to the exact key string.
/// Field-by-field behaviour:
///
/// | Field | With cache | Without cache (`None`) |
/// |---|---|---|
/// | `update_id`       | CCM `UpdateID`                            | CCM `UpdateID` |
/// | `installed`       | derived from CCM `UpdateState == 10`      | same |
/// | `required`        | CCM `Required`                            | same |
/// | `targeted`        | always `true` (presence in CCM means it)  | same |
/// | `superseded`      | CCM `Superseded`                          | same |
/// | `title`           | WUA title, falls back to CCM `Title`      | CCM `Title` or `""` |
/// | `article_ids`     | from WUA                                  | `[]` |
/// | `cve_ids`         | from WUA                                  | `[]` |
/// | `msrc_severity`   | from WUA (may be `null` if not classified) | `null` |
/// | `category`        | from WUA                                  | `null` |
/// | `reboot_required` | from WUA                                  | `null` |
pub(super) fn updates_sccm_updates(
    cache_index: Option<&HashMap<String, WuaMeta>>,
) -> Result<Vec<Value>, String> {
    ensure_com()?;

    // --- Step 1: WMI CCM connect ---------------------------------------
    // SAFETY: ensure_com() above guarantees COM is initialized on this thread.
    let com = unsafe { COMLibrary::assume_initialized() };
    let conn = match WMIConnection::with_namespace_path(
        r"Root\ccm\SoftwareUpdates\DeploymentAgent",
        com,
    ) {
        Ok(c) => c,
        // Namespace absent → no SCCM agent → silently return [] (fix #3).
        Err(WMIError::HResultError { hres }) if hres == WBEM_E_INVALID_NAMESPACE.0 => {
            return Ok(Vec::new());
        }
        // Any other failure (access denied, WMI service down, …) propagates.
        Err(e) => return Err(format!(r"WMI Root\ccm connect: {e}")),
    };

    // --- Step 2: WMI CCM query -----------------------------------------
    // Fix #1: propagate query failure instead of swallowing it.  Even with
    // the namespace present, the query may fail (provider misbehaving,
    // class missing on older agents); the caller turns this into a recorded
    // error rather than a misleading empty result.
    let ccm_rows: Vec<HashMap<String, Variant>> = conn
        .raw_query("SELECT * FROM CCM_TargetedUpdateEx1")
        .map_err(|e| format!("CCM_TargetedUpdateEx1 query: {e}"))?;

    if ccm_rows.is_empty() {
        return Ok(Vec::new());
    }

    // --- Step 3: join CCM rows with the shared WUA index ----------------
    let mut results = Vec::with_capacity(ccm_rows.len());
    for row in &ccm_rows {
        let update_id = ccm_str(row, "UpdateID").unwrap_or_default();
        let update_state = ccm_u32(row, "UpdateState").unwrap_or(0);
        // State 10 = Installed in the CCM state machine.
        let installed = update_state == 10;

        // Fix #8: never look up an empty UpdateID — the index doesn't
        // contain it, but the explicit guard documents intent.
        let meta = if update_id.is_empty() {
            None
        } else {
            cache_index.and_then(|idx| idx.get(&update_id))
        };

        let title = meta
            .and_then(|m| m.title.clone())
            .or_else(|| ccm_str(row, "Title"))
            .unwrap_or_default();

        let article_ids = meta.map(|m| m.article_ids.clone()).unwrap_or_default();

        results.push(json!({
            "update_id":       update_id,
            "title":           title,
            "article_ids":     article_ids,
            "installed":       installed,
            "required":        ccm_bool(row, "Required"),
            "targeted":        true,
            "superseded":      ccm_bool(row, "Superseded"),
            "msrc_severity":   meta.and_then(|m| m.msrc_severity.clone()),
            "category":        meta.and_then(|m| m.category.clone()),
            "reboot_required": meta.map(|m| m.reboot_required),
            "cve_ids":         meta.map(|m| m.cve_ids.clone()).unwrap_or_default(),
        }));
    }

    Ok(results)
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
}
