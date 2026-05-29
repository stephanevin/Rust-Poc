//! Installs the `host` global table — the single surface exposed to Lua
//! collector scripts.
//!
//! Every binding is fallible but never raises a Lua error: failures are
//! recorded into an internal `errors` table and the binding returns `nil`.
//! Lua scripts call `host.errors()` at the end of a run to retrieve the
//! `{field: reason}` map to attach under `_errors` in the output.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use mlua::{
    AnyUserData, Lua, LuaSerdeExt, Result as LuaResult, Table, UserData, UserDataMethods, Value,
};

use super::{
    accounts, ad, bitlocker, cloud, credentialguard, cyberark, ep, firewall, gpo, laps, net,
    regional, registry, sccm, sentinelone, software, tls, updates, wfp, wfp_pipeline, winver,
    wmi::Wmi, wnf, wts,
};

/// Canonical `host.errors()` key for any failure of
/// [`updates::build_offline_payload`].  Centralised here so both
/// `updates_windows_updates` and `updates_sccm_updates` surface the
/// same diagnostic regardless of which one triggered the init.
const ERR_KEY_WUA_CACHE_INIT: &str = "updates:wua_cache_init";

/// Canonical `host.errors()` key for any failure of
/// [`updates::default_au_service`].  Symmetric to
/// [`ERR_KEY_WUA_CACHE_INIT`]: both `updates_is_managed` and
/// `updates_managed_by` surface the same diagnostic regardless of which
/// one triggered the init.
const ERR_KEY_AU_SERVICE: &str = "updates:au_service";

/// Canonical `host.errors()` key for any failure of
/// [`wfp::enumerate_wfp_state`].  All three WFP bindings surface the same
/// diagnostic to avoid duplicating the expensive init error.
const ERR_KEY_WFP_CACHE_INIT: &str = "wfp:cache_init";

/// Canonical `host.errors()` key for any failure of
/// [`sccm::read_health_report`].  The three ccmeval-backed bindings
/// (`sccm_client_status`, `sccm_client_status_date`, `sccm_health_check`)
/// share one cache, so a read/parse failure surfaces under this single key
/// regardless of which binding triggered the init.
const ERR_KEY_SCCM_HEALTH: &str = "sccm:health_report";

/// Tri-state cache for the shared WUA offline payload.
///
/// `Option<UpdatesCache>` would only distinguish "not initialised" from
/// "initialised", so any binding hitting an init failure would silently
/// retry the expensive `build_offline_payload()` on the next call.  The
/// `Failed` variant memoises that the first attempt failed and short-
/// circuits subsequent calls — see `HostState::ensure_updates_cache`.
pub(super) enum UpdatesCacheState {
    NotInit,
    Ready(updates::UpdatesCache),
    Failed,
}

impl UpdatesCacheState {
    /// Returns the payload only in the [`Ready`](Self::Ready) state.
    ///
    /// Both [`NotInit`](Self::NotInit) and [`Failed`](Self::Failed) map
    /// to `None`.  The method itself is infallible and side-effect free
    /// — it does **not** trigger initialisation; call
    /// [`HostState::ensure_updates_cache`] to transition out of
    /// `NotInit`.
    fn ready(&self) -> Option<&updates::UpdatesCache> {
        match self {
            Self::Ready(c) => Some(c),
            Self::NotInit | Self::Failed => None,
        }
    }
}

/// Tri-state cache for the default WUA Automatic Updates service lookup.
///
/// Structurally identical to [`UpdatesCacheState`] (see its doc for the
/// full rationale): the previous `Option<Option<(bool, String)>>` shape
/// could only distinguish "not initialised" from "initialised", so a
/// failed [`updates::default_au_service`] call was retried on every
/// subsequent binding hit and could record one error key per binding.
/// The [`Failed`](Self::Failed) variant memoises that the first attempt
/// failed and short-circuits all later calls — see
/// [`HostState::ensure_au_service`].
///
/// The inner `Option<(bool, String)>` of [`Ready`](Self::Ready) carries
/// its own meaning: `None` is the valid "no service reported
/// `IsDefaultAUService`" outcome, distinct from an init failure.
pub(super) enum AuServiceState {
    NotInit,
    Ready(Option<(bool, String)>),
    Failed,
}

/// Tri-state cache for the WFP enriched state (layers, sublayers, providers,
/// provider contexts, callouts, and enriched filters).
///
/// Mirrors the pattern of [`UpdatesCacheState`]: the expensive
/// `enumerate_wfp_state()` call is executed at most once per run, and any
/// init failure is memoised so the other two WFP bindings do not retry.
pub(super) enum WfpCacheState {
    NotInit,
    Ready(wfp::WfpState),
    Failed,
}

/// Tri-state cache for the ccmeval client-health report.
///
/// Mirrors [`UpdatesCacheState`]: the report file is read and parsed at most
/// once per run, shared by the three health bindings. The inner
/// `Option<SccmHealthReport>` of [`Ready`](Self::Ready) distinguishes "file
/// absent" (`Ready(None)` — machine not managed / never evaluated, not an
/// error) from "parsed" (`Ready(Some(..))`). [`Failed`](Self::Failed)
/// memoises a genuine read failure so it is not retried.
pub(super) enum SccmHealthState {
    NotInit,
    Ready(Option<sccm::SccmHealthReport>),
    Failed,
}

/// Per-run mutable state passed into binding closures. Lua is !Send, so
/// this lives on the blocking thread that owns the Lua VM.
pub(super) struct HostState {
    pub hostname: String,
    pub client_version: String,
    pub perimeter: Option<String>,
    pub wmi: Option<Wmi>,
    /// One-shot cache of the WUA offline payload, populated lazily on the
    /// first `host.updates_windows_updates()` call.  Mirrors the
    /// `wmi: Option<Wmi>` pattern above — the offline search is the
    /// heaviest call in the System Updates group (~1-2 s on 500+
    /// updates) and would be re-run on every consumer call without
    /// memoisation.  Init failures are memoised (`Failed`) so the
    /// expensive call is never retried within the same run.
    ///
    /// Note: before the SCCM #31 refactor this cache also fed
    /// `host.updates_sccm_updates()`.  The new SCCM pipeline is
    /// source-independent (`CCM_UpdateStatus` pivot + WUA online
    /// `QueryHistory`) so #30 is now the sole consumer.
    pub updates_cache: UpdatesCacheState,
    /// Cache of the default Automatic Updates service lookup, populated
    /// lazily on the first `host.updates_is_managed()` or
    /// `host.updates_managed_by()` call.  Mirrors `updates_cache`: a
    /// single enumeration shared by both bindings, with init failures
    /// memoised in [`AuServiceState::Failed`] to avoid repeated COM
    /// round-trips.
    pub au_service: AuServiceState,
    /// Cache of the full WFP enriched state (layers, sublayers, providers,
    /// provider contexts, callouts, filters), populated lazily on the first
    /// WFP binding call.  All three bindings share the same `WfpState`; init
    /// failures are memoised so the expensive enumeration is never retried
    /// within the same run.
    pub wfp_cache: WfpCacheState,
    /// Cache of the ccmeval client-health report, populated lazily on the
    /// first SCCM health binding call.  The report XML is read and parsed at
    /// most once per run; an absent file is the valid `Ready(None)` outcome,
    /// a read failure is memoised in [`SccmHealthState::Failed`].
    pub sccm_health: SccmHealthState,
    pub errors: HashMap<String, String>,
}

impl HostState {
    pub(super) fn new(hostname: String, client_version: String, perimeter: Option<String>) -> Self {
        Self {
            hostname,
            client_version,
            perimeter,
            wmi: None,
            updates_cache: UpdatesCacheState::NotInit,
            au_service: AuServiceState::NotInit,
            wfp_cache: WfpCacheState::NotInit,
            sccm_health: SccmHealthState::NotInit,
            errors: HashMap::new(),
        }
    }

    /// Records a binding failure in the in-memory error table consumed by
    /// `host.errors()` (and surfaced to the Lua collector as `_errors`)
    /// AND emits a `tracing::warn!` event so the same failure also ends
    /// up in the rolling JSON log file under `RUST_POC_LOG_DIR`.
    ///
    /// Why both:
    ///
    /// * The `_errors` table in the JSON output is the contract for the
    ///   downstream consumer (a collector that read `result._errors`
    ///   parses individual binding failures).
    /// * But that table sits inside a large JSON payload that ops teams
    ///   rarely inspect when a run "succeeds" (exit code 0).  Without
    ///   the `tracing::warn!`, a silent failure such as
    ///   `updates_sccm_updates` returning `WBEM_E_ACCESS_DENIED` after a
    ///   5 s DCOM negotiation looks identical to a successful "no SCCM
    ///   on this host" run — same exit code, same shape, no log line.
    ///   The `warn!` here closes that observability gap: every recorded
    ///   error produces exactly one structured log line, regardless of
    ///   whether the calling binding chooses to surface a partial value
    ///   to Lua or returns `Nil`.
    ///
    /// `field` is treated as the structured `binding` field so log
    /// aggregators can group by binding name without parsing the
    /// message.
    fn record_error(&mut self, field: &str, reason: String) {
        tracing::warn!(binding = %field, error = %reason, "binding failed");
        self.errors.insert(field.to_string(), reason);
    }

    fn wmi(&mut self) -> Result<&mut Wmi, String> {
        if self.wmi.is_none() {
            self.wmi = Some(Wmi::new()?);
        }
        self.wmi
            .as_mut()
            .ok_or_else(|| "wmi: unreachable — initialized above".to_string())
    }

    /// Lazy-init accessor for the WUA offline payload.
    ///
    /// First call performs the expensive offline search and stores the
    /// payload; subsequent calls hand out the cached value.  On failure,
    /// the state moves to [`UpdatesCacheState::Failed`] (no retry) and a
    /// single canonical diagnostic is recorded under
    /// [`ERR_KEY_WUA_CACHE_INIT`] — only `updates_windows_updates`
    /// surfaces this key today (since the SCCM #31 refactor, that path
    /// no longer touches the offline cache).  Returns `None` for both
    /// `NotInit` (post-failure path: should never happen, we just
    /// transitioned to `Failed`) and `Failed`.
    fn ensure_updates_cache(&mut self) -> Option<&updates::UpdatesCache> {
        if matches!(self.updates_cache, UpdatesCacheState::NotInit) {
            match updates::build_offline_payload() {
                Ok(c) => self.updates_cache = UpdatesCacheState::Ready(c),
                Err(e) => {
                    self.updates_cache = UpdatesCacheState::Failed;
                    // Defensive first-wins guard: unreachable today
                    // because `Failed` memoisation short-circuits any
                    // second visit to this branch, but kept on purpose
                    // — if the state machine ever grows a retry path,
                    // this preserves the original diagnostic.  The
                    // `contains_key(&str)` lookup uses HashMap's
                    // `Borrow<str>` impl so the canonical key is only
                    // allocated when actually inserted (no wasted
                    // `String::from` on the no-op path).
                    if !self.errors.contains_key(ERR_KEY_WUA_CACHE_INIT) {
                        self.errors.insert(ERR_KEY_WUA_CACHE_INIT.to_string(), e);
                    }
                }
            }
        }
        self.updates_cache.ready()
    }

    /// Lazy-init accessor for the default AU service.
    ///
    /// Mirrors [`Self::ensure_updates_cache`] one-for-one:
    /// - first call performs the COM enumeration and caches the outcome;
    /// - subsequent calls hand out the cached value;
    /// - on failure the state moves to [`AuServiceState::Failed`] (no
    ///   retry) and a single canonical diagnostic is recorded under
    ///   [`ERR_KEY_AU_SERVICE`] — `updates_is_managed` and
    ///   `updates_managed_by` then surface the same key regardless of
    ///   which one triggered the init.
    ///
    /// Returns `Some(&(is_managed, name))` only when a default service was
    /// found.  All three other outcomes (`NotInit` post-failure — should
    /// not happen, `Ready(None)`, `Failed`) collapse to `None` because
    /// the caller only needs to distinguish "data available" from "not";
    /// the error path is already recorded.
    fn ensure_au_service(&mut self) -> Option<&(bool, String)> {
        if matches!(self.au_service, AuServiceState::NotInit) {
            match updates::default_au_service() {
                Ok(v) => self.au_service = AuServiceState::Ready(v),
                Err(e) => {
                    self.au_service = AuServiceState::Failed;
                    // Defensive first-wins guard; see ensure_updates_cache
                    // for the full rationale.
                    if !self.errors.contains_key(ERR_KEY_AU_SERVICE) {
                        self.errors.insert(ERR_KEY_AU_SERVICE.to_string(), e);
                    }
                }
            }
        }
        match &self.au_service {
            AuServiceState::Ready(Some(v)) => Some(v),
            AuServiceState::Ready(None) | AuServiceState::NotInit | AuServiceState::Failed => None,
        }
    }

    /// Lazy-init accessor for the WFP enriched state.
    ///
    /// The enumeration is performed at most once per run. Any init failure
    /// is memoised in [`WfpCacheState::Failed`] so the three WFP bindings
    /// never retry the expensive Win32 enumeration calls.  A single
    /// canonical error is recorded under [`ERR_KEY_WFP_CACHE_INIT`].
    fn ensure_wfp_state(&mut self) -> Option<&wfp::WfpState> {
        if matches!(self.wfp_cache, WfpCacheState::NotInit) {
            match wfp::enumerate_wfp_state() {
                Ok(s) => self.wfp_cache = WfpCacheState::Ready(s),
                Err(e) => {
                    self.wfp_cache = WfpCacheState::Failed;
                    if !self.errors.contains_key(ERR_KEY_WFP_CACHE_INIT) {
                        self.errors.insert(ERR_KEY_WFP_CACHE_INIT.to_string(), e);
                    }
                }
            }
        }
        match &self.wfp_cache {
            WfpCacheState::Ready(s) => Some(s),
            WfpCacheState::NotInit | WfpCacheState::Failed => None,
        }
    }

    /// Lazy-init accessor for the ccmeval client-health report.
    ///
    /// The report XML is read and parsed at most once per run, shared by the
    /// three SCCM health bindings.  An absent report file is the valid
    /// `Ready(None)` outcome (machine not managed); a genuine read failure is
    /// memoised in [`SccmHealthState::Failed`] and recorded once under
    /// [`ERR_KEY_SCCM_HEALTH`].  Never launches `ccmeval.exe` (deviation #47).
    fn ensure_sccm_health(&mut self) -> Option<&sccm::SccmHealthReport> {
        if matches!(self.sccm_health, SccmHealthState::NotInit) {
            match sccm::read_health_report() {
                Ok(report) => self.sccm_health = SccmHealthState::Ready(report),
                Err(e) => {
                    self.sccm_health = SccmHealthState::Failed;
                    if !self.errors.contains_key(ERR_KEY_SCCM_HEALTH) {
                        self.errors.insert(ERR_KEY_SCCM_HEALTH.to_string(), e);
                    }
                }
            }
        }
        match &self.sccm_health {
            SccmHealthState::Ready(report) => report.as_ref(),
            SccmHealthState::NotInit | SccmHealthState::Failed => None,
        }
    }
}

/// Shared handle to `HostState`. We wrap in `Rc<RefCell<..>>` so every Lua
/// binding can borrow it mutably without cloning state around.
type HostRef = Rc<RefCell<HostState>>;

/// `UserData` wrapper lets us store the `HostRef` inside the Lua registry
/// and keep it alive for the VM's lifetime. The inner Rc is never read
/// back from Lua — merely holding it in the registry keeps it alive.
struct HostHandle(#[allow(dead_code)] HostRef);
impl UserData for HostHandle {
    fn add_methods<M: UserDataMethods<Self>>(_: &mut M) {}
}

pub(super) fn install(
    lua: &Lua,
    hostname: &str,
    client_version: &str,
    perimeter: Option<&str>,
) -> LuaResult<HostRef> {
    let state = Rc::new(RefCell::new(HostState::new(
        hostname.to_string(),
        client_version.to_string(),
        perimeter.map(str::to_string),
    )));

    // Store a strong reference in the registry so the HostState outlives
    // individual function calls even if Lua drops its globals.
    let handle: AnyUserData = lua.create_any_userdata(HostHandle(state.clone()))?;
    lua.set_named_registry_value("sdh_host_handle", handle)?;

    let host = lua.create_table()?;

    install_scalars(lua, &host, &state)?;
    install_wmi_bindings(lua, &host, &state)?;
    install_registry_bindings(lua, &host, &state)?;
    install_winver_bindings(lua, &host, &state)?;
    install_net_bindings(lua, &host, &state)?;
    install_hostname_bindings(lua, &host, &state)?;
    install_ad_bindings(lua, &host, &state)?;
    install_ad_computer_bindings(lua, &host, &state)?;
    install_setup_history(lua, &host)?;
    install_wnf_bindings(lua, &host, &state)?;
    install_gpo_bindings(lua, &host, &state)?;
    install_tls_bindings(lua, &host, &state)?;
    install_regional_bindings(lua, &host, &state)?;
    install_accounts_bindings(lua, &host, &state)?;
    install_software_bindings(lua, &host, &state)?;
    install_updates_bindings(lua, &host, &state)?;
    install_cloud_bindings(lua, &host, &state)?;
    install_hardening_bindings(lua, &host, &state)?;
    install_ep_bindings(lua, &host, &state)?;
    install_firewall_bindings(lua, &host, &state)?;
    install_wfp_bindings(lua, &host, &state)?;
    install_laps_bindings(lua, &host)?;
    install_sentinelone_bindings(lua, &host, &state)?;
    install_cyberark_bindings(lua, &host, &state)?;
    install_sccm_bindings(lua, &host, &state)?;
    install_composites(lua, &host, &state)?;
    install_errors(lua, &host, &state)?;

    lua.globals().set("host", host)?;
    Ok(state)
}

// --- simple scalars ---------------------------------------------------

fn install_scalars(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    {
        let s = state.clone();
        host.set(
            "env",
            lua.create_function(move |_, name: String| -> LuaResult<Option<String>> {
                // Special-cased injected env vars take priority so the
                // script gets a consistent view regardless of process env.
                let st = s.borrow();
                if let Some(v) = match name.as_str() {
                    "SDH_HOSTNAME" => Some(st.hostname.clone()),
                    "SDH_CLIENT_VERSION" => Some(st.client_version.clone()),
                    "SDH_PERIMETER" => st.perimeter.clone(),
                    _ => None,
                } {
                    return Ok(Some(v));
                }
                Ok(std::env::var(&name).ok())
            })?,
        )?;
    }

    host.set(
        "now_iso8601",
        lua.create_function(|lua, ()| {
            let v = &super::setup_history::install_info()["install_date"];
            lua.to_value(v)
        })?,
    )?;

    Ok(())
}

// --- WMI bindings -----------------------------------------------------

fn install_wmi_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    {
        let s = state.clone();
        host.set(
            "wmi_query",
            lua.create_function(move |lua, (class, property): (String, String)| {
                let mut st = s.borrow_mut();
                let field = format!("wmi:{class}.{property}");
                let res = match st.wmi() {
                    Ok(wmi) => wmi.query_first(&class, &property),
                    Err(e) => Err(e),
                };
                match res {
                    Ok(Some(v)) => lua.to_value(&v),
                    Ok(None) => Ok(Value::Nil),
                    Err(e) => {
                        st.record_error(&field, e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    {
        let s = state.clone();
        host.set(
            "wmi_all",
            lua.create_function(move |lua, class: String| {
                let mut st = s.borrow_mut();
                let field = format!("wmi_all:{class}");
                let res = match st.wmi() {
                    Ok(wmi) => wmi.query_all(&class),
                    Err(e) => Err(e),
                };
                match res {
                    Ok(rows) => lua.to_value(&serde_json::Value::Array(rows)),
                    Err(e) => {
                        st.record_error(&field, e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    Ok(())
}

// --- Registry ---------------------------------------------------------

fn install_registry_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    {
        let s = state.clone();
        host.set(
            "registry_read",
            lua.create_function(move |lua, (hive, key, value): (String, String, String)| {
                let mut st = s.borrow_mut();
                let field = format!("registry:{hive}/{key}/{value}");
                match registry::read(&hive, &key, &value) {
                    Ok(Some(v)) => lua.to_value(&v),
                    Ok(None) => Ok(Value::Nil),
                    Err(e) => {
                        st.record_error(&field, e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    Ok(())
}

// --- Windows version --------------------------------------------------

fn install_winver_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    host.set(
        "rtl_get_version",
        lua.create_function(|lua, ()| lua.to_value(&winver::rtl_get_version()))?,
    )?;

    host.set(
        "get_firmware_type",
        lua.create_function(|_, ()| Ok(winver::firmware_type().map(str::to_string)))?,
    )?;

    host.set(
        "os_sku",
        lua.create_function(|_, ()| Ok(winver::product_sku()))?,
    )?;

    {
        let s = state.clone();
        host.set(
            "os_last_boot_up_time",
            lua.create_function(move |_, ()| {
                if let Some(ts) = winver::last_boot_up_time() {
                    Ok(Some(ts))
                } else {
                    s.borrow_mut().record_error(
                        "os_last_boot_up_time",
                        "NtQuerySystemInformation(SystemTimeOfDayInformation) returned no value"
                            .to_string(),
                    );
                    Ok(None)
                }
            })?,
        )?;
    }

    Ok(())
}

// --- Networking -------------------------------------------------------

fn install_net_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    {
        let s = state.clone();
        host.set(
            "net_interfaces",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match net::interfaces() {
                    Ok(ifs) => lua.to_value(&serde_json::Value::Array(ifs)),
                    Err(e) => {
                        st.record_error("net_interfaces", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    Ok(())
}

// --- Hostname (NetBIOS / DNS hostname / FQDN) -------------------------
//
// Deviation #6 from the verbatim upstream port: these three bindings are
// not in `sdh-fleet-client/lua/host.rs` yet. They expose the three
// standard Windows machine-name variants so collectors can surface
// whichever granularity they need. See `super::hostname` for the Win32
// backing constants, invariants, and the non-Physical rationale.

/// Registers a binding that calls a fallible string getter.
///
/// On success the Lua function returns the string; on failure it returns
/// `nil` and records the error in `host.errors()`.
///
/// `name` must be `'static` so it can be captured into the `'static`
/// closure that `lua.create_function` requires. `f` is a bare function
/// pointer (`fn`, not `Fn`) — sufficient because each getter is a named
/// free function, not a closure that captures state.
///
/// Reused by [`install_hostname_bindings`] and [`install_ad_computer_bindings`].
fn bind_hostname(
    lua: &Lua,
    host: &Table,
    state: &HostRef,
    name: &'static str,
    f: fn() -> Result<String, String>,
) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        name,
        lua.create_function(move |_, ()| {
            let mut st = s.borrow_mut();
            match f() {
                Ok(v) => Ok(Some(v)),
                Err(e) => {
                    st.record_error(name, e);
                    Ok(None)
                }
            }
        })?,
    )
}

fn install_hostname_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    bind_hostname(
        lua,
        host,
        state,
        "netbios_name",
        super::hostname::netbios_name,
    )?;
    bind_hostname(lua, host, state, "host_name", super::hostname::dns_hostname)?;
    bind_hostname(lua, host, state, "fqdn", super::hostname::dns_fqdn)?;
    Ok(())
}

fn install_ad_computer_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    bind_hostname(
        lua,
        host,
        state,
        "ad_computer_sam",
        super::adcomputer::sam_name,
    )?;
    bind_hostname(
        lua,
        host,
        state,
        "ad_computer_dn",
        super::adcomputer::distinguished_name,
    )?;
    bind_hostname(
        lua,
        host,
        state,
        "ad_computer_cn",
        super::adcomputer::canonical_name,
    )?;
    bind_hostname(
        lua,
        host,
        state,
        "ad_computer_site",
        super::adcomputer::site_name,
    )?;
    // UPN of the current user — exposed as `mail_address` because the UPN
    // (user@domain.com) is the best offline proxy for the Exchange `mail`
    // LDAP attribute. See adcomputer::user_upn() doc for the UPN ≠ mail caveat.
    bind_hostname(
        lua,
        host,
        state,
        "mail_address",
        super::adcomputer::user_upn,
    )?;
    Ok(())
}

// --- AD (best-effort) -------------------------------------------------

fn install_ad_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    {
        let s = state.clone();
        host.set(
            "adsi_user_mail",
            lua.create_function(move |_, timeout_s: u64| {
                let mut st = s.borrow_mut();
                match ad::current_user_mail_blocking(Duration::from_secs(timeout_s.max(1))) {
                    Ok(v) => Ok(v),
                    Err(e) => {
                        st.record_error("adsi_user_mail", e);
                        Ok(None)
                    }
                }
            })?,
        )?;
    }

    Ok(())
}

// --- Setup history ----------------------------------------------------

fn install_setup_history(lua: &Lua, host: &Table) -> LuaResult<()> {
    host.set(
        "setup_history",
        lua.create_function(|lua, ()| lua.to_value(&super::setup_history::install_info()))?,
    )?;

    Ok(())
}

// --- Windows Notification Facility (WNF) --------------------------------

fn install_wnf_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "uso_reboot_required",
        lua.create_function(move |_, ()| {
            if let Some(v) = wnf::uso_reboot_required() {
                Ok(Some(v))
            } else {
                s.borrow_mut().record_error(
                    "uso_reboot_required",
                    "WNF_USO_REBOOT_REQUIRED state could not be read".to_string(),
                );
                Ok(None)
            }
        })?,
    )?;

    Ok(())
}

// --- Group Policy (GPO) ------------------------------------------------

fn install_gpo_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.ad_computer_gpos()
    {
        let s = state.clone();
        host.set(
            "ad_computer_gpos",
            lua.create_function(move |lua, ()| {
                if let Some(rows) = gpo::computer_gpos() {
                    lua.to_value(&serde_json::Value::Array(rows))
                } else {
                    s.borrow_mut().record_error(
                        "ad_computer_gpos",
                        "No Machine GPOs found in Group Policy State registry (GP not applied or machine not domain-joined)".to_string(),
                    );
                    Ok(mlua::Value::Nil)
                }
            })?,
        )?;
    }

    // host.ad_user_gpos()
    {
        let s = state.clone();
        host.set(
            "ad_user_gpos",
            lua.create_function(move |lua, ()| {
                if let Some(rows) = gpo::user_gpos() {
                    lua.to_value(&serde_json::Value::Array(rows))
                } else {
                    s.borrow_mut().record_error(
                        "ad_user_gpos",
                        "Group Policy State registry key absent (GP never applied on this machine)"
                            .to_string(),
                    );
                    Ok(mlua::Value::Nil)
                }
            })?,
        )?;
    }

    // host.gp_extensions_status()
    {
        let s = state.clone();
        host.set(
            "gp_extensions_status",
            lua.create_function(move |lua, ()| {
                if let Some(rows) = gpo::gp_extensions_status() {
                    lua.to_value(&serde_json::Value::Array(rows))
                } else {
                    s.borrow_mut().record_error(
                        "gp_extensions_status",
                        "Core GP extension key absent (GP never applied on this machine)"
                            .to_string(),
                    );
                    Ok(mlua::Value::Nil)
                }
            })?,
        )?;
    }

    Ok(())
}

// --- TLS (Schannel cipher suites) --------------------------------------

fn install_tls_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "tls_cipher_suites",
        lua.create_function(move |lua, ()| {
            if let Some(suites) = tls::tls_cipher_suites() {
                let arr: Vec<serde_json::Value> =
                    suites.into_iter().map(serde_json::Value::String).collect();
                lua.to_value(&serde_json::Value::Array(arr))
            } else {
                s.borrow_mut().record_error(
                    "tls_cipher_suites",
                    "BCryptEnumContextFunctions(CRYPT_LOCAL, SSL, NCRYPT_SCHANNEL_INTERFACE) failed".to_string(),
                );
                Ok(mlua::Value::Nil)
            }
        })?,
    )?;
    Ok(())
}

// --- Regional (locale / UI language) ----------------------------------

fn install_regional_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.user_ui_language() — BCP-47 UI language of the current user.
    // Mirrors MuiLang.cs / UserDefaultLanguage.cs (BCP-47 instead of English name).
    {
        let s = state.clone();
        host.set(
            "user_ui_language",
            lua.create_function(move |_, ()| {
                if let Some(v) = regional::user_ui_language() {
                    Ok(Some(v))
                } else {
                    s.borrow_mut().record_error(
                        "user_ui_language",
                        "GetUserDefaultUILanguage / LCIDToLocaleName returned no value".to_string(),
                    );
                    Ok(None)
                }
            })?,
        )?;
    }

    // host.system_ui_language() — BCP-47 UI language of the OS installation.
    // Mirrors SystemDefaultLanguage.cs.
    {
        let s = state.clone();
        host.set(
            "system_ui_language",
            lua.create_function(move |_, ()| {
                if let Some(v) = regional::system_ui_language() {
                    Ok(Some(v))
                } else {
                    s.borrow_mut().record_error(
                        "system_ui_language",
                        "GetSystemDefaultUILanguage / LCIDToLocaleName returned no value"
                            .to_string(),
                    );
                    Ok(None)
                }
            })?,
        )?;
    }

    // host.user_locale() — BCP-47 regional locale of the current user.
    // Mirrors CurrentCulture.cs.
    {
        let s = state.clone();
        host.set(
            "user_locale",
            lua.create_function(move |_, ()| {
                if let Some(v) = regional::user_locale() {
                    Ok(Some(v))
                } else {
                    s.borrow_mut().record_error(
                        "user_locale",
                        "GetUserDefaultLocaleName returned no value".to_string(),
                    );
                    Ok(None)
                }
            })?,
        )?;
    }

    // host.system_locale() — BCP-47 system-wide regional locale.
    // Mirrors SystemCulture.cs.
    {
        let s = state.clone();
        host.set(
            "system_locale",
            lua.create_function(move |_, ()| {
                if let Some(v) = regional::system_locale() {
                    Ok(Some(v))
                } else {
                    s.borrow_mut().record_error(
                        "system_locale",
                        "GetSystemDefaultLocaleName returned no value".to_string(),
                    );
                    Ok(None)
                }
            })?,
        )?;
    }

    Ok(())
}

// --- Accounts (user profiles / local users / group members) -----------

fn install_accounts_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.user_profiles() — registry ProfileList + LookupAccountSidW.
    // Mirrors UserProfiles.cs from ComplianceApp DataTransformers/Accounts.
    // Always returns an array (empty when ProfileList key is absent or
    // open-failed); fundamental failures surface under "user_profiles"
    // in host.errors() — symmetric with browser_extensions_installed /
    // ide_extensions_installed (all three read the same HKLM ProfileList).
    {
        let s = state.clone();
        host.set(
            "user_profiles",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                let (rows, err) = accounts::user_profiles();
                if let Some(e) = err {
                    st.record_error("user_profiles", e);
                }
                lua.to_value(&serde_json::Value::Array(rows))
            })?,
        )?;
    }

    // host.local_user_accounts() — NetUserEnum(0) + NetUserGetInfo(4).
    // Mirrors LocalAccountsUsers.cs.
    {
        let s = state.clone();
        host.set(
            "local_user_accounts",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match accounts::local_user_accounts() {
                    Ok(rows) => lua.to_value(&serde_json::Value::Array(rows)),
                    Err(e) => {
                        st.record_error("local_user_accounts", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.local_group_members(sid) — LookupAccountSidW + NetLocalGroupGetMembers(2).
    // Mirrors LocalAccountsAdminMembers.cs (S-1-5-32-544) and
    // LocalAccountsRdpMembers.cs (S-1-5-32-555) — same binding, different SID.
    {
        let s = state.clone();
        host.set(
            "local_group_members",
            lua.create_function(move |lua, group_sid: String| {
                let mut st = s.borrow_mut();
                match accounts::local_group_members(&group_sid) {
                    Ok(rows) => lua.to_value(&serde_json::Value::Array(rows)),
                    Err(e) => {
                        st.record_error(&format!("local_group_members:{group_sid}"), e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    Ok(())
}

/// Serializes a `serde_json::Value` to a Lua value, falling back to
/// `nil` and recording a `<binding>:serialize` diagnostic if the mlua
/// conversion itself fails.
///
/// `lua.to_value` is normally infallible for `serde_json` shapes the
/// crate produces, but in principle it can propagate an mlua error
/// (allocator failure, unsupported value type, etc.).  Without this
/// helper the error would unwind through `collect()` with no entry in
/// `host.errors()`, violating the workspace contract documented in the
/// header of `collectors/softwares.lua` ("a binding never raises a Lua
/// error").  Used by every binding that emits an array via
/// `serde_json::Value::Array`.
///
/// The helper is infallible by design — callers wrap the return value
/// in `Ok(...)` at their `LuaResult<Value>` boundary.
fn lua_to_value_or_nil(
    lua: &Lua,
    st: &mut HostState,
    binding: &str,
    value: &serde_json::Value,
) -> Value {
    match lua.to_value(value) {
        Ok(v) => v,
        Err(e) => {
            st.record_error(&format!("{binding}:serialize"), e.to_string());
            Value::Nil
        }
    }
}

/// Installs a zero-arg `host.*` binding backed by a WMI query that returns
/// a JSON array wrapped in `serde_json::Value::Array`.
fn bind_wmi_json_array(
    lua: &Lua,
    host: &Table,
    state: &HostRef,
    name: &'static str,
    error_key: &'static str,
    f: fn(&mut super::wmi::Wmi) -> Result<Vec<serde_json::Value>, String>,
) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        name,
        lua.create_function(move |lua, ()| {
            let mut st = s.borrow_mut();
            let res = match st.wmi() {
                Ok(wmi) => f(wmi).map(serde_json::Value::Array),
                Err(e) => Err(e),
            };
            match res {
                Ok(v) => Ok(lua_to_value_or_nil(lua, &mut st, error_key, &v)),
                Err(e) => {
                    st.record_error(error_key, e);
                    Ok(Value::Nil)
                }
            }
        })?,
    )
}

/// Installs a zero-arg `host.*` binding backed by a WMI query that returns
/// an optional JSON object (`Ok(None)` → Lua `nil`).
fn bind_wmi_json_option(
    lua: &Lua,
    host: &Table,
    state: &HostRef,
    name: &'static str,
    error_key: &'static str,
    f: fn(&mut super::wmi::Wmi) -> Result<Option<serde_json::Value>, String>,
) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        name,
        lua.create_function(move |lua, ()| {
            let mut st = s.borrow_mut();
            let res = match st.wmi() {
                Ok(wmi) => f(wmi),
                Err(e) => Err(e),
            };
            match res {
                Ok(Some(v)) => Ok(lua_to_value_or_nil(lua, &mut st, error_key, &v)),
                Ok(None) => Ok(Value::Nil),
                Err(e) => {
                    st.record_error(error_key, e);
                    Ok(Value::Nil)
                }
            }
        })?,
    )
}

fn install_software_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.os_software_installed() — HKLM Uninstall registry + WTS per-user.
    // Mirrors OSSoftwareInstalled.cs + OperatingSystem.GetSoftwareInstalled().
    // Best-effort: machine-level software comes through even when the WTS
    // enumeration fails or when an HKLM uninstall hive cannot be opened.
    // Failures are surfaced under distinct keys so the operator can tell
    // which slice of the data is missing:
    //   - "os_software_installed:wts"       → per-user entries absent
    //   - "os_software_installed:registry"  → at least one HKLM Uninstall
    //                                         hive failed to open (rare;
    //                                         usually access denied)
    //   - "os_software_installed:serialize" → mlua serialization failure
    //                                         (theoretical safety net)
    {
        let s = state.clone();
        host.set(
            "os_software_installed",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                let (rows, wts_err, registry_err) = software::os_software_installed();
                if let Some(e) = wts_err {
                    st.record_error("os_software_installed:wts", e);
                }
                if let Some(e) = registry_err {
                    st.record_error("os_software_installed:registry", e);
                }
                let value = serde_json::Value::Array(rows);
                Ok(lua_to_value_or_nil(
                    lua,
                    &mut st,
                    "os_software_installed",
                    &value,
                ))
            })?,
        )?;
    }

    // host.os_services() — Win32 Service Control Manager APIs.
    // Mirrors OSServices.cs + OperatingSystem.GetOSServices().
    // All-or-nothing on OpenSCManagerW failure (nil + "os_services").
    // Per-service OpenServiceW failures emit a partial row and bump a
    // counter surfaced under "os_services:partial".
    {
        let s = state.clone();
        host.set(
            "os_services",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match software::os_services() {
                    Ok((rows, partial_skips)) => {
                        if partial_skips > 0 {
                            st.record_error(
                                "os_services:partial",
                                format!(
                                    "{partial_skips} service(s) had OpenServiceW failures \
                                     (start_mode, path_name, start_name are null in those rows)"
                                ),
                            );
                        }
                        let value = serde_json::Value::Array(rows);
                        Ok(lua_to_value_or_nil(lua, &mut st, "os_services", &value))
                    }
                    Err(e) => {
                        st.record_error("os_services", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.browser_extensions_installed() — Chromium Preferences + manifests.
    // Mirrors BrowserExtensionsInstalled.cs + General.GetBrowserExtension().
    // Best-effort: per-profile / per-file failures are absorbed (a single
    // unreadable manifest would otherwise produce a flood of error rows).
    // Only a fundamental failure (HKLM ProfileList inaccessible) is
    // surfaced under "browser_extensions_installed" in host.errors().
    {
        let s = state.clone();
        host.set(
            "browser_extensions_installed",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                let (rows, err) = software::browser_extensions_installed();
                if let Some(e) = err {
                    st.record_error("browser_extensions_installed", e);
                }
                let value = serde_json::Value::Array(rows);
                Ok(lua_to_value_or_nil(
                    lua,
                    &mut st,
                    "browser_extensions_installed",
                    &value,
                ))
            })?,
        )?;
    }

    // host.ide_extensions_installed() — extensions.json + package.json.
    // Mirrors IdeExtensionsInstalled.cs + General.GetIdeExtensions().
    // Same best-effort policy as browser_extensions_installed above.
    {
        let s = state.clone();
        host.set(
            "ide_extensions_installed",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                let (rows, err) = software::ide_extensions_installed();
                if let Some(e) = err {
                    st.record_error("ide_extensions_installed", e);
                }
                let value = serde_json::Value::Array(rows);
                Ok(lua_to_value_or_nil(
                    lua,
                    &mut st,
                    "ide_extensions_installed",
                    &value,
                ))
            })?,
        )?;
    }

    Ok(())
}

// --- System Updates (WUA COM) -----------------------------------------

#[allow(clippy::too_many_lines)]
fn install_updates_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.updates_is_managed() — WUA IUpdateServiceManager2 → IsDefaultAUService → IsManaged.
    // Mirrors UpdatesIsManaged.cs (ComplianceApp). Deviation #26.
    // Shares the `au_service` cache with updates_managed_by (#27): the
    // expensive service-collection enumeration runs once per run, and
    // init failures are surfaced under the canonical key
    // `ERR_KEY_AU_SERVICE` (no per-binding key).
    {
        let s = state.clone();
        host.set(
            "updates_is_managed",
            lua.create_function(move |_, ()| {
                let mut st = s.borrow_mut();
                Ok(st
                    .ensure_au_service()
                    .map(|(managed, _)| if *managed { "Managed" } else { "Unmanaged" }.to_string()))
            })?,
        )?;
    }

    // host.updates_managed_by() — WUA IUpdateServiceManager2 → IsDefaultAUService → Name.
    // Mirrors UpdatesManagedBy.cs. Deviation #27.  Shares au_service cache with #26.
    {
        let s = state.clone();
        host.set(
            "updates_managed_by",
            lua.create_function(move |_, ()| {
                let mut st = s.borrow_mut();
                Ok(st.ensure_au_service().map(|(_, name)| name.clone()))
            })?,
        )?;
    }

    // host.updates_reboot_required() — WUA ISystemInformation::RebootRequired.
    // Mirrors UpdatesRebootRequired.cs. Deviation #28.
    {
        let s = state.clone();
        host.set(
            "updates_reboot_required",
            lua.create_function(move |_, ()| {
                let mut st = s.borrow_mut();
                match updates::updates_reboot_required() {
                    Ok(v) => Ok(Some(v)),
                    Err(e) => {
                        st.record_error("updates_reboot_required", e);
                        Ok(None)
                    }
                }
            })?,
        )?;
    }

    // host.updates_reboot_required_before_installation() — WUA IUpdateInstaller.
    // Mirrors UpdatesRebootRequiredBeforeInstallation.cs. Deviation #29.
    {
        let s = state.clone();
        host.set(
            "updates_reboot_required_before_installation",
            lua.create_function(move |_, ()| {
                let mut st = s.borrow_mut();
                match updates::updates_reboot_required_before_installation() {
                    Ok(v) => Ok(Some(v)),
                    Err(e) => {
                        st.record_error("updates_reboot_required_before_installation", e);
                        Ok(None)
                    }
                }
            })?,
        )?;
    }

    // host.updates_windows_updates() — WUA IUpdateSession3 offline search.
    // Mirrors UpdatesWindowsUpdates.cs. Deviation #30.
    // Shares the offline-search cache with updates_sccm_updates (#31).
    {
        let s = state.clone();
        host.set(
            "updates_windows_updates",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                // Extract owned values from the cache so the borrow ends before
                // we call record_error (which needs &mut self again).  The clone
                // of `windows_updates` is intentional: this binding is documented
                // as idempotent — calling it twice in the same run must yield
                // identical owned data both times, not move the cache out.  On
                // a realistic endpoint (500 updates × 20 JSON fields ≈ a few MB)
                // the clone is dominated by the WUA search cost we just saved.
                let payload = st
                    .ensure_updates_cache()
                    .map(|c| (c.wua_skips, c.windows_updates.clone()));
                match payload {
                    Some((skips, rows)) => {
                        if skips > 0 {
                            st.record_error(
                                "updates_windows_updates:partial",
                                format!(
                                    "{skips} WUA update(s) skipped (missing UpdateID or get_Item failure)"
                                ),
                            );
                        }
                        let value = serde_json::Value::Array(rows);
                        Ok(lua_to_value_or_nil(lua, &mut st, "updates_windows_updates", &value))
                    }
                    // Cache init failed: ensure_updates_cache already recorded
                    // the diagnostic under `ERR_KEY_WUA_CACHE_INIT`.  No need
                    // to add a binding-specific key.
                    None => Ok(Value::Nil),
                }
            })?,
        )?;
    }

    // host.updates_sccm_updates() — quad-source merge faithful to
    // Updates.cs::GetSccmUpdates (deviation #31). DTO is strict 1:1 with
    // SccmUpdate.cs.  No longer shares the `updates_cache` with #30 — the
    // SCCM path runs its own CCM_UpdateStatus pivot + WUA online
    // QueryHistory.
    {
        let s = state.clone();
        host.set(
            "updates_sccm_updates",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                let result = updates::updates_sccm_updates();
                match result {
                    Ok(rows) => {
                        let value = serde_json::Value::Array(rows);
                        Ok(lua_to_value_or_nil(
                            lua,
                            &mut st,
                            "updates_sccm_updates",
                            &value,
                        ))
                    }
                    Err(e) => {
                        st.record_error("updates_sccm_updates", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    Ok(())
}

// --- Cloud (Azure AD + MDM/Intune) ------------------------------------
//
// Deviation #39 (see CLAUDE.md):
// - host.azure_ad_joined_status()  — NetGetAadJoinInformation + cert validity
// - host.azure_ad_device_id()      — pszDeviceId from DSREG_JOIN_INFO
// - host.mdm_status()              — WMI root\CIMV2\mdm + cert validity
// - host.mdm_device_id()           — cert Subject CN
// - host.mdm_co_management_flags() — registry DWORD
// - host.mdm_sync_status()         — event log 208/209 pairing
//
// All six bindings respect the workspace contract: never raise, record
// failures into host.errors(), return nil on failure.
#[allow(clippy::too_many_lines)]
fn install_cloud_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.azure_ad_joined_status() → "On" | "Off" | "CertificateIsNotValid" | nil
    {
        let s = state.clone();
        host.set(
            "azure_ad_joined_status",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match cloud::azure_ad_joined_status() {
                    Ok(v) => Ok(Value::String(lua.create_string(v)?)),
                    Err(e) => {
                        st.record_error("azure_ad_joined_status", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.azure_ad_device_id() → string? (device GUID from DSREG_JOIN_INFO.pszDeviceId)
    {
        let s = state.clone();
        host.set(
            "azure_ad_device_id",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match cloud::azure_ad_device_id() {
                    Ok(Some(v)) => Ok(Value::String(lua.create_string(&v)?)),
                    Ok(None) => Ok(Value::Nil),
                    Err(e) => {
                        st.record_error("azure_ad_device_id", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.mdm_status() → "On" | "Off" | "CertificateIsNotValid" | nil
    {
        let s = state.clone();
        host.set(
            "mdm_status",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                let res = match st.wmi() {
                    Ok(wmi) => cloud::mdm_status(wmi),
                    Err(e) => Err(e),
                };
                match res {
                    Ok(v) => Ok(Value::String(lua.create_string(v)?)),
                    Err(e) => {
                        st.record_error("mdm_status", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.mdm_device_id() → string? (CN subject of MDM provisioning cert)
    {
        let s = state.clone();
        host.set(
            "mdm_device_id",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                let res = match st.wmi() {
                    Ok(wmi) => cloud::mdm_device_id(wmi),
                    Err(e) => Err(e),
                };
                match res {
                    Ok(Some(v)) => Ok(Value::String(lua.create_string(&v)?)),
                    Ok(None) => Ok(Value::Nil),
                    Err(e) => {
                        st.record_error("mdm_device_id", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.mdm_co_management_flags() → string? (ConfigInfo DWORD as decimal)
    // No error recording needed: the function is infallible (absent key → None).
    host.set(
        "mdm_co_management_flags",
        lua.create_function(move |lua, ()| match cloud::mdm_co_management_flags() {
            Some(v) => Ok(Value::String(lua.create_string(&v)?)),
            None => Ok(Value::Nil),
        })?,
    )?;

    // host.mdm_sync_status() → { last_sync_date?, last_success_sync_date?,
    //                             last_sync_result? }?
    {
        let s = state.clone();
        host.set(
            "mdm_sync_status",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match cloud::mdm_sync_status() {
                    Some(sync) => match serde_json::to_value(&sync) {
                        Ok(v) => Ok(lua_to_value_or_nil(lua, &mut st, "mdm_sync_status", &v)),
                        Err(e) => {
                            st.record_error("mdm_sync_status:serialize", e.to_string());
                            Ok(Value::Nil)
                        }
                    },
                    None => Ok(Value::Nil),
                }
            })?,
        )?;
    }

    Ok(())
}

// --- Hardening (BitLocker + Credential Guard) -------------------------
//
// Deviations #32 – #38 (see CLAUDE.md):
// - #32: evt.rs — Windows Event Log wrapper (EvtQuery + EvtRender) used
//        by BitLocker recovery-key event queries.
// - #33: host.bitlocker_volume_status(mount_point)
// - #34: host.bitlocker_key_protector_ids(mount_point, protector_type)
// - #35: host.bitlocker_dra_thumbprints(mount_point)
// - #36: host.bitlocker_policy()
// - #37: host.bitlocker_escrowed_protector_ids(event_id)
//        + host.bitlocker_recovery_key_rotation_executed()
// - #38: host.credential_guard_status()
//
// All seven bindings respect the workspace contract: never raise, record
// failures into host.errors(), return nil on failure.
#[allow(clippy::too_many_lines)]
fn install_hardening_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.bitlocker_volume_status(mount_point) — Win32_EncryptableVolume
    // + GetConversionStatus.  Mirrors `BitlockerStatus` + `BitLockerEncryptionPercentage`.
    {
        let s = state.clone();
        host.set(
            "bitlocker_volume_status",
            lua.create_function(move |lua, mount_point: String| {
                let mut st = s.borrow_mut();
                let field = format!("bitlocker_volume_status:{mount_point}");
                let res = match st.wmi() {
                    Ok(wmi) => bitlocker::volume_status(wmi, &mount_point),
                    Err(e) => Err(e),
                };
                match res {
                    Ok(Some(v)) => Ok(lua_to_value_or_nil(lua, &mut st, &field, &v)),
                    Ok(None) => Ok(Value::Nil),
                    Err(e) => {
                        st.record_error(&field, e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.bitlocker_key_protector_ids(mount_point, protector_type)
    // — GetKeyProtectors method.  protector_type: 3=NumericPassword, 7=PublicKey/DRA.
    {
        let s = state.clone();
        host.set(
            "bitlocker_key_protector_ids",
            lua.create_function(move |lua, (mount_point, protector_type): (String, u32)| {
                let mut st = s.borrow_mut();
                let field = format!("bitlocker_key_protector_ids:{mount_point}:{protector_type}");
                let res = match st.wmi() {
                    Ok(wmi) => bitlocker::key_protector_ids(wmi, &mount_point, protector_type),
                    Err(e) => Err(e),
                };
                match res {
                    Ok(ids) => {
                        let arr: Vec<serde_json::Value> =
                            ids.into_iter().map(serde_json::Value::String).collect();
                        let value = serde_json::Value::Array(arr);
                        Ok(lua_to_value_or_nil(lua, &mut st, &field, &value))
                    }
                    Err(e) => {
                        st.record_error(&field, e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.bitlocker_dra_thumbprints(mount_point) — GetKeyProtectors(7) + GetKeyProtectorCertificate.
    // Mirrors `BitLockerDRACertThumbPrints`.
    {
        let s = state.clone();
        host.set(
            "bitlocker_dra_thumbprints",
            lua.create_function(move |lua, mount_point: String| {
                let mut st = s.borrow_mut();
                let field = format!("bitlocker_dra_thumbprints:{mount_point}");
                let res = match st.wmi() {
                    Ok(wmi) => bitlocker::dra_thumbprints(wmi, &mount_point),
                    Err(e) => Err(e),
                };
                match res {
                    Ok(thumbs) => {
                        let arr: Vec<serde_json::Value> =
                            thumbs.into_iter().map(serde_json::Value::String).collect();
                        let value = serde_json::Value::Array(arr);
                        Ok(lua_to_value_or_nil(lua, &mut st, &field, &value))
                    }
                    Err(e) => {
                        st.record_error(&field, e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.bitlocker_policy() — `HKLM\SOFTWARE\Policies\Microsoft\FVE` value names.
    // Mirrors `BitLockerPolicy`.
    {
        let s = state.clone();
        host.set(
            "bitlocker_policy",
            lua.create_function(move |_, ()| {
                let mut st = s.borrow_mut();
                match bitlocker::policy_state() {
                    Ok(label) => Ok(Some(label.to_string())),
                    Err(e) => {
                        st.record_error("bitlocker_policy", e);
                        Ok(None)
                    }
                }
            })?,
        )?;
    }

    // host.bitlocker_escrowed_protector_ids(event_id) — BitLocker Management channel.
    // Mirrors `BitLockerRecoveryKeyADBackupSummary` (id=783) + `BitLockerRecoveryKeyAzureADBackupSummary` (id=845).
    {
        let s = state.clone();
        host.set(
            "bitlocker_escrowed_protector_ids",
            lua.create_function(move |lua, event_id: u32| {
                let mut st = s.borrow_mut();
                let field = format!("bitlocker_escrowed_protector_ids:{event_id}");
                match bitlocker::escrowed_protector_ids(event_id) {
                    Ok(ids) => {
                        let arr: Vec<serde_json::Value> =
                            ids.into_iter().map(serde_json::Value::String).collect();
                        let value = serde_json::Value::Array(arr);
                        Ok(lua_to_value_or_nil(lua, &mut st, &field, &value))
                    }
                    Err(e) => {
                        st.record_error(&field, e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.bitlocker_recovery_key_rotation_executed() — ShutdownTime + events 864/775.
    // Mirrors `BitLockerService.RecoveryKeyRotationFromEventsExecuted`.
    // Three-state: nil = never rotated, true = rotation executed, false = pending.
    {
        let s = state.clone();
        host.set(
            "bitlocker_recovery_key_rotation_executed",
            lua.create_function(move |_, ()| {
                let mut st = s.borrow_mut();
                match bitlocker::recovery_key_rotation_executed() {
                    Ok(v) => Ok(v),
                    Err(e) => {
                        st.record_error("bitlocker_recovery_key_rotation_executed", e);
                        Ok(None)
                    }
                }
            })?,
        )?;
    }

    // host.credential_guard_status() — Win32_DeviceGuard in root\Microsoft\Windows\DeviceGuard.
    // Mirrors `CredentialGuardStatus.Create` from `ComplianceApp.Shared`.
    {
        let s = state.clone();
        host.set(
            "credential_guard_status",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                let res = match st.wmi() {
                    Ok(wmi) => credentialguard::status(wmi),
                    Err(e) => Err(e),
                };
                match res {
                    Ok(Some(v)) => Ok(lua_to_value_or_nil(
                        lua,
                        &mut st,
                        "credential_guard_status",
                        &v,
                    )),
                    Ok(None) => Ok(Value::Nil),
                    Err(e) => {
                        st.record_error("credential_guard_status", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    Ok(())
}

// --- Endpoint Protection (EP) — deviation #40 -------------------------

fn install_ep_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.security_center_av_products() — WMI ROOT\SecurityCenter2\AntiVirusProduct.
    // Returns every AV product registered with Windows Security Center, with decoded
    // ProductState bitmask.  Lua filters by name for the specific product it needs.
    // Mirrors SentinelOne.cs + AntiVirusEnums.cs from ComplianceApp.
    bind_wmi_json_array(
        lua,
        host,
        state,
        "security_center_av_products",
        "ep:security_center_av_products",
        ep::security_center_av_products,
    )?;

    // host.windows_defender_status() — WMI ROOT\Microsoft\Windows\Defender\MSFT_MpComputerStatus.
    // Returns Defender runtime fields in WMI PascalCase (AMServiceEnabled,
    // AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, ProductStatus…).
    // Returns nil when Defender is absent or WMI query fails.
    // Mirrors WindowsDefender.cs from ComplianceApp.
    bind_wmi_json_option(
        lua,
        host,
        state,
        "windows_defender_status",
        "ep:windows_defender_status",
        ep::windows_defender_status,
    )?;

    Ok(())
}

fn install_firewall_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.security_center_firewall_products() — WMI ROOT\SecurityCenter2\FirewallProduct.
    // Returns every firewall product registered with Windows Security Center, with decoded
    // ProductState bitmask (Status + Owner nibbles).  ProductState layout is bit-for-bit
    // identical to AntiVirusProduct (FirewallEnums.cs mirrors AntiVirusEnums.cs).
    // Lua filters by name for the specific product it needs (e.g. "Sentinel Firewall").
    // Mirrors Firewall.cs::GetSecurityCenterFirewallProducts.
    bind_wmi_json_array(
        lua,
        host,
        state,
        "security_center_firewall_products",
        "fw:sc2_products",
        firewall::security_center_firewall_products,
    )?;

    // host.windows_defender_firewall_status() — WMI root\StandardCimv2.
    // Two queries: MSFT_NetConnectionProfile → current profile name, and
    // MSFT_NetFirewallProfile → enabled state per Domain/Private/Public profile.
    // Returns {current_profile, status, domain_state, private_state, public_state}.
    // Mirrors Firewall.cs::GetWindowsDefenderFirewallStatus.
    {
        let s = state.clone();
        host.set(
            "windows_defender_firewall_status",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match st.wmi() {
                    Ok(wmi) => match firewall::windows_defender_firewall_status(wmi) {
                        Ok(v) => Ok(lua_to_value_or_nil(lua, &mut st, "fw:wd_status", &v)),
                        Err(e) => {
                            st.record_error("fw:wd_status", e);
                            Ok(Value::Nil)
                        }
                    },
                    Err(e) => {
                        st.record_error("fw:wd_status", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.net_fw_products() — COM HNetCfg.FwProducts (INetFwProducts / INetFwProduct2).
    // Enumerates products registered with Windows Firewall and their RuleCategories
    // (0=BootTime, 1=Stealth, 2=Firewall, 3=ConSec).  Lua derives per-category owners.
    // Includes 5-attempt retry on transient COM failures.
    // Mirrors Firewall.cs::GetNetFwProducts.
    {
        let s = state.clone();
        host.set(
            "net_fw_products",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match firewall::net_fw_products() {
                    Ok(rows) => {
                        let value = serde_json::Value::Array(rows);
                        Ok(lua_to_value_or_nil(
                            lua,
                            &mut st,
                            "fw:net_fw_products",
                            &value,
                        ))
                    }
                    Err(e) => {
                        st.record_error("fw:net_fw_products", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    Ok(())
}

// --- WFP bindings (deviation #43) -----------------------------------

fn install_wfp_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.wfp_sublayer_details() — all enriched WFP filters grouped by
    // sublayer, sorted sublayer_weight DESC inside each group
    // layer_name ASC / effective_weight_numeric DESC.
    // Mirrors WfpSubLayerDetails.cs.
    {
        let s = state.clone();
        host.set(
            "wfp_sublayer_details",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match st.ensure_wfp_state() {
                    Some(wfp_state) => {
                        let value = wfp_pipeline::wfp_sublayer_details(&wfp_state.filters);
                        lua.to_value(&value).map_err(|e| {
                            mlua::Error::runtime(format!("wfp_sublayer_details serialize: {e}"))
                        })
                    }
                    None => Ok(Value::Nil),
                }
            })?,
        )?;
    }

    // host.wfp_firewall_view() — ALE-filtered, shadowed, deduplicated
    // firewall view.  Three pipeline steps: ALE filter → shadowing → dedup.
    // Mirrors WfpFirewallView.cs + WfpFilterPipeline.cs.
    {
        let s = state.clone();
        host.set(
            "wfp_firewall_view",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match st.ensure_wfp_state() {
                    Some(wfp_state) => {
                        let value = wfp_pipeline::wfp_firewall_view(&wfp_state.filters);
                        lua.to_value(&value).map_err(|e| {
                            mlua::Error::runtime(format!("wfp_firewall_view serialize: {e}"))
                        })
                    }
                    None => Ok(Value::Nil),
                }
            })?,
        )?;
    }

    // host.wfp_net_events() — most-recent WFP network events (up to 1000),
    // sorted timestamp DESC.  Opens an ephemeral engine and enumerates via
    // FwpmNetEventEnum2; enriches each event from the shared WfpState.
    // Mirrors WfpNetEvents.cs.  On FWP_NET_EVENTS_DISABLED returns [] silently
    // (collection being off is a normal state, not an error).  Any other Win32
    // failure returns [] and records the error under "wfp:net_events".
    // Does NOT poison the WfpState cache.
    //
    // Borrow note: `ensure_wfp_state()` returns `Option<&WfpState>` tied to
    // `st`.  We resolve the reference inside a block so the borrow is dropped
    // before the `Err` arm tries to call `st.record_error(...)`.
    {
        let s = state.clone();
        host.set(
            "wfp_net_events",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                // Separate the borrow of `st` (via `ensure_wfp_state`) from
                // the potential mutable borrow in `record_error`.  `wfp_result`
                // is an owned `Option<Result<…>>`, so the `wfp_state` borrow
                // ends before the `Err` arm calls `st.record_error`.
                let wfp_result = st.ensure_wfp_state().map(wfp::wfp_net_events);
                match wfp_result {
                    None => Ok(Value::Nil),
                    Some(Ok(value)) => lua.to_value(&value).map_err(|e| {
                        mlua::Error::runtime(format!("wfp_net_events serialize: {e}"))
                    }),
                    Some(Err(e)) => {
                        st.record_error("wfp:net_events", e);
                        let empty = serde_json::json!([]);
                        lua.to_value(&empty).map_err(|e2| {
                            mlua::Error::runtime(format!("wfp_net_events empty serialize: {e2}"))
                        })
                    }
                }
            })?,
        )?;
    }

    Ok(())
}

// --- LAPS bindings (deviation #44) -----------------------------------

fn install_laps_bindings(lua: &Lua, host: &Table) -> LuaResult<()> {
    // host.laps_state() — Windows / Legacy LAPS configuration snapshot.
    //
    // Stateless: each field is an independent registry read or File::exists
    // probe (all cheap, side-effect free), so there is no per-run cache like
    // WFP's WfpState.  Mirrors the LAPS transformers in ComplianceApp
    // (Security.cs + DataTransformers/LAPS/*.cs):
    //   - auto_laps_mode              ← GetLegacyLapsGpExtensionPresent + GetWindowsLapsDllExists
    //   - windows_laps_dll_state      ← GetWindowsLapsDllExists
    //   - laps_policy                 ← GetLapsPolicy (4-key presence cascade)
    //   - laps_backup_directory       ← GetLapsBackupDirectory
    //   - legacy_gp_extension_present ← GetLegacyLapsGpExtensionPresent
    //   - max_pwd_age_days            ← GetLapsMaxPasswordAge
    //
    // Deviation #44: auto_laps_mode emits "Not Installed" (not the C#
    // "Unknown") when no LAPS implementation is detected, so the
    // Win10-Laptop.json `AutoLapsMode != "Not Installed"` parent test
    // behaves as intended.  laps_state() is infallible — every probe
    // degrades to a safe default, so nothing is ever recorded in
    // host.errors().
    host.set(
        "laps_state",
        lua.create_function(|lua, ()| {
            lua.to_value(&laps::laps_state())
                .map_err(|e| mlua::Error::runtime(format!("laps_state serialize: {e}")))
        })?,
    )?;

    Ok(())
}

// --- SentinelOne EDR bindings (deviation #45) ------------------------

fn install_sentinelone_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.sentinel_one_agent_status() — COM IDispatch late-binding against
    // the SentinelHelper ProgID (GetAgentStatusJSON).  Returns the 13 agent
    // fields (snake_case) or nil.  Mirrors GetSentinelOneAgentStatusFromJson.
    //
    // ProgID absent → SentinelOne not installed → nil, SILENT (not an error).
    // Any failure after the CLSID resolves (instantiation / Invoke / JSON
    // parse) is a real error recorded under "s1:agent_status".
    {
        let s = state.clone();
        host.set(
            "sentinel_one_agent_status",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match sentinelone::agent_status() {
                    Ok(Some(v)) => Ok(lua_to_value_or_nil(lua, &mut st, "s1:agent_status", &v)),
                    Ok(None) => Ok(Value::Nil),
                    Err(e) => {
                        st.record_error("s1:agent_status", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // host.sentinel_one_paths() — {folder, ctl_paths[], agent_paths[]}.
    // Infallible: missing folder → null folder + empty arrays.  The Lua
    // collector derives the parent SentinelOneStatus (non-empty ctl_paths)
    // and AgentFound (non-empty agent_paths) from these lists.
    // Mirrors GetSentinelOneFindFolderPath / FindCtlPath / FindAgentPath.
    {
        let s = state.clone();
        host.set(
            "sentinel_one_paths",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                let value = sentinelone::paths();
                Ok(lua_to_value_or_nil(lua, &mut st, "s1:paths", &value))
            })?,
        )?;
    }

    // host.sentinel_one_comm_sdk() — newest SentinelOne/Operational #104
    // event ({message, date}) or nil.  Swallows every Event Log failure to
    // nil (channel absent is the dominant non-SentinelOne case), matching
    // the C# catch-all.  Mirrors GetSentinelOneCommSdkMessage(+Date).
    {
        let s = state.clone();
        host.set(
            "sentinel_one_comm_sdk",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match sentinelone::comm_sdk() {
                    Some(v) => Ok(lua_to_value_or_nil(lua, &mut st, "s1:comm_sdk", &v)),
                    None => Ok(Value::Nil),
                }
            })?,
        )?;
    }

    Ok(())
}

// --- CyberArk EPM (Viewfinity) bindings (deviation #46) ----------------

// Registers one infallible CyberArk registry binding: an Option<String> from
// HKLM\SOFTWARE\Viewfinity\Agent that degrades to nil on absence. `f` is a bare
// function pointer (no captured state) — same idiom as bind_hostname. No host
// error is ever recorded: read failures already collapse to None inside
// cyberark, and serializing a scalar string/nil cannot fail.
fn install_cyberark_reg(
    lua: &Lua,
    host: &Table,
    name: &'static str,
    f: fn() -> Option<String>,
) -> LuaResult<()> {
    host.set(
        name,
        lua.create_function(move |lua, ()| {
            let value = f().map_or(serde_json::Value::Null, serde_json::Value::String);
            Ok(lua.to_value(&value).unwrap_or(Value::Nil))
        })?,
    )?;
    Ok(())
}

fn install_cyberark_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // host.cyber_ark_epm_driver_status() — vfpd kernel driver state via the SC
    // Manager.  "None" when the driver is absent (mirrors ServiceStatus.None);
    // a real SC Manager failure is recorded under "cyberark:driver_status".
    {
        let s = state.clone();
        host.set(
            "cyber_ark_epm_driver_status",
            lua.create_function(move |lua, ()| {
                let mut st = s.borrow_mut();
                match cyberark::driver_status() {
                    Ok(label) => Ok(lua_to_value_or_nil(
                        lua,
                        &mut st,
                        "cyberark:driver_status",
                        &serde_json::Value::String(label),
                    )),
                    Err(e) => {
                        st.record_error("cyberark:driver_status", e);
                        Ok(Value::Nil)
                    }
                }
            })?,
        )?;
    }

    // Five infallible registry reads from HKLM\SOFTWARE\Viewfinity\Agent.
    install_cyberark_reg(lua, host, "cyber_ark_epm_version", cyberark::version)?;
    install_cyberark_reg(lua, host, "cyber_ark_epm_id", cyberark::id)?;
    install_cyberark_reg(
        lua,
        host,
        "cyber_ark_epm_dispatcher_url",
        cyberark::dispatcher_url,
    )?;
    install_cyberark_reg(
        lua,
        host,
        "cyber_ark_epm_registered_at",
        cyberark::registered_at,
    )?;
    install_cyberark_reg(
        lua,
        host,
        "cyber_ark_epm_last_policy_update",
        cyberark::last_policy_update,
    )?;

    Ok(())
}

// --- SCCM client health bindings (deviation #47) -----------------------

// Installs one ccmeval-backed `host.*` binding that maps the shared
// SccmHealthReport cache to an optional JSON value.  `f` extracts an owned
// value from the report (cloned so the &report borrow is released before the
// &mut st reborrow in lua_to_value_or_nil).  A missing report (file absent /
// read failure already recorded under ERR_KEY_SCCM_HEALTH) yields nil.
fn install_sccm_health(
    lua: &Lua,
    host: &Table,
    state: &HostRef,
    name: &'static str,
    f: fn(&sccm::SccmHealthReport) -> Option<serde_json::Value>,
) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        name,
        lua.create_function(move |lua, ()| {
            let mut st = s.borrow_mut();
            match st.ensure_sccm_health().and_then(f) {
                Some(v) => Ok(lua_to_value_or_nil(lua, &mut st, ERR_KEY_SCCM_HEALTH, &v)),
                None => Ok(Value::Nil),
            }
        })?,
    )?;
    Ok(())
}

fn install_sccm_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    // Six WMI reads (root\ccm and children) — reuse the generic helpers.
    bind_wmi_json_option(
        lua,
        host,
        state,
        "sccm_client_version",
        "sccm:client_version",
        sccm::client_version,
    )?;
    bind_wmi_json_option(
        lua,
        host,
        state,
        "sccm_site_code",
        "sccm:site_code",
        sccm::site_code,
    )?;
    bind_wmi_json_option(
        lua,
        host,
        state,
        "sccm_current_management_point",
        "sccm:current_management_point",
        sccm::current_management_point,
    )?;
    bind_wmi_json_option(
        lua,
        host,
        state,
        "sccm_mp_last_update_date",
        "sccm:mp_last_update",
        sccm::mp_last_update_date,
    )?;
    bind_wmi_json_array(
        lua,
        host,
        state,
        "sccm_inventory_status",
        "sccm:inventory_status",
        sccm::inventory_status,
    )?;
    bind_wmi_json_array(
        lua,
        host,
        state,
        "sccm_component_status",
        "sccm:component_status",
        sccm::component_status,
    )?;

    // Three read-only ccmeval health bindings sharing the SccmHealthReport
    // cache.  Raw emission: the "Passed" -> "Client Healthy" label is left to
    // the UI (deviation #47.5).
    install_sccm_health(lua, host, state, "sccm_client_status", |r| {
        r.summary_text.clone().map(serde_json::Value::String)
    })?;
    install_sccm_health(lua, host, state, "sccm_client_status_date", |r| {
        r.evaluation_time.clone().map(serde_json::Value::String)
    })?;
    install_sccm_health(lua, host, state, "sccm_health_check", |r| {
        Some(serde_json::Value::Array(
            r.entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "description": e.description,
                        "health_check_text": e.health_check_text,
                    })
                })
                .collect(),
        ))
    })?;

    Ok(())
}

// --- Convenience composites (keep the Lua script lean) ----------------

fn install_composites(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    bind_cpu_details(lua, host, state)?;
    bind_ram_total(lua, host, state)?;
    bind_disk_size(lua, host, state)?;
    bind_motherboard_details(lua, host, state)?;
    bind_bios_details(lua, host, state)?;
    bind_desktop_resolution(lua, host, state)?;
    bind_chassis_type(lua, host, state)?;
    bind_virtual_machine(lua, host, state)?;
    bind_virtualization_capability(lua, host, state)?;
    bind_terminal_sessions(lua, host, state)?;
    Ok(())
}

fn bind_cpu_details(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "cpu_details",
        lua.create_function(move |_, ()| {
            let mut st = s.borrow_mut();
            let res = st.wmi().and_then(|wmi| {
                let name = wmi
                    .query_first("Win32_Processor", "Name")?
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                let socket = wmi
                    .query_first("Win32_Processor", "SocketDesignation")?
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                Ok(if socket.is_empty() {
                    name
                } else {
                    format!("{name} ({socket})")
                })
            });
            match res {
                Ok(s) if !s.is_empty() => Ok(Some(s)),
                Ok(_) => Ok(None),
                Err(e) => {
                    st.record_error("cpu_details", e);
                    Ok(None)
                }
            }
        })?,
    )
}

fn bind_ram_total(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "ram_total",
        lua.create_function(move |_, ()| {
            let mut st = s.borrow_mut();
            let res = st.wmi().and_then(|wmi| {
                let rows = wmi.query_all("Win32_PhysicalMemory")?;
                let mut total: u64 = 0;
                for r in &rows {
                    if let Some(c) = r.get("Capacity").and_then(|v| {
                        v.as_u64()
                            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                    }) {
                        total = total.saturating_add(c);
                    }
                }
                Ok(total)
            });
            match res {
                Ok(0) => Ok(None),
                Ok(v) => Ok(Some(v)),
                Err(e) => {
                    st.record_error("ram_total", e);
                    Ok(None)
                }
            }
        })?,
    )
}

fn bind_disk_size(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "disk_size",
        lua.create_function(move |_, (_target, property): (String, String)| {
            // For the PoC we read the system drive via env var SystemDrive.
            let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
            let mut st = s.borrow_mut();
            let res = st.wmi().and_then(|wmi| {
                let rows = wmi.query_all("Win32_LogicalDisk")?;
                for r in rows {
                    let device = r
                        .get("DeviceID")
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_default();
                    if device.eq_ignore_ascii_case(&drive) {
                        let v = r.get(&property).and_then(|v| {
                            v.as_u64()
                                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                        });
                        return Ok(v);
                    }
                }
                Ok(None)
            });
            match res {
                Ok(v) => Ok(v),
                Err(e) => {
                    st.record_error(&format!("disk_size:{property}"), e);
                    Ok(None)
                }
            }
        })?,
    )
}

fn bind_motherboard_details(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "motherboard_details",
        lua.create_function(move |_, ()| {
            let mut st = s.borrow_mut();
            let res = st.wmi().and_then(|wmi| {
                let model = wmi
                    .query_first("Win32_ComputerSystem", "Model")?
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                let family = wmi
                    .query_first("Win32_ComputerSystem", "SystemFamily")?
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                Ok(match (family.is_empty(), model.is_empty()) {
                    (true, true) => String::new(),
                    (true, false) => model,
                    (false, true) => family,
                    (false, false) => format!("{family} ({model})"),
                })
            });
            match res {
                Ok(s) if !s.is_empty() => Ok(Some(s)),
                Ok(_) => Ok(None),
                Err(e) => {
                    st.record_error("motherboard_details", e);
                    Ok(None)
                }
            }
        })?,
    )
}

fn bind_bios_details(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "bios_details",
        lua.create_function(move |_, ()| {
            let mut st = s.borrow_mut();
            let res = st.wmi().and_then(|wmi| {
                let bios_version = wmi
                    .query_first("Win32_BIOS", "BIOSVersion")?
                    .map(|v| match v {
                        serde_json::Value::Array(a) => a
                            .into_iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect::<Vec<_>>()
                            .join(" / "),
                        serde_json::Value::String(s) => s,
                        _ => String::new(),
                    })
                    .unwrap_or_default();
                let firmware = super::winver::firmware_type().unwrap_or("?");
                Ok(format!("{bios_version} ({firmware})"))
            });
            match res {
                Ok(s) if !s.is_empty() && !s.starts_with(" (") => Ok(Some(s)),
                Ok(_) => Ok(None),
                Err(e) => {
                    st.record_error("bios_details", e);
                    Ok(None)
                }
            }
        })?,
    )
}

fn bind_desktop_resolution(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "desktop_resolution",
        lua.create_function(move |_, ()| {
            let mut st = s.borrow_mut();
            let res = st.wmi().and_then(|wmi| {
                let h = wmi
                    .query_first("Win32_VideoController", "CurrentHorizontalResolution")?
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let w = wmi
                    .query_first("Win32_VideoController", "CurrentVerticalResolution")?
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let r = wmi
                    .query_first("Win32_VideoController", "CurrentRefreshRate")?
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                Ok(if h == 0 || w == 0 {
                    String::new()
                } else {
                    format!("{h}x{w} @ {r}Hz")
                })
            });
            match res {
                Ok(s) if !s.is_empty() => Ok(Some(s)),
                Ok(_) => Ok(None),
                Err(e) => {
                    st.record_error("desktop_resolution", e);
                    Ok(None)
                }
            }
        })?,
    )
}

/// Translates a raw SMBIOS System Enclosure Type code (SMBIOS spec 3.x, §7.4)
/// into a human-readable label.  Codes 1–36 are defined; anything outside
/// that range falls through to `"Unknown"`.
fn chassis_type_str(code: u32) -> &'static str {
    match code {
        1 => "Other",
        3 => "Desktop",
        4 => "Low Profile Desktop",
        5 => "Pizza Box",
        6 => "Mini Tower",
        7 => "Tower",
        8 => "Portable",
        9 => "Laptop",
        10 => "Notebook",
        11 => "Handheld",
        12 => "Docking Station",
        13 => "All-in-One",
        14 => "Sub-Notebook",
        15 => "Space-Saving",
        16 => "Lunch Box",
        17 => "Main Server Chassis",
        18 => "Expansion Chassis",
        19 => "Sub-Chassis",
        20 => "Bus Expansion Chassis",
        21 => "Peripheral Chassis",
        22 => "RAID Chassis",
        23 => "Rack Mount Chassis",
        24 => "Sealed-Case PC",
        25 => "Multi-System Chassis",
        26 => "Compact PCI",
        27 => "AdvancedTCA",
        28 => "Blade",
        29 => "Blade Enclosure",
        30 => "Tablet",
        31 => "Convertible",
        32 => "Detachable",
        33 => "IoT Gateway",
        34 => "Embedded PC",
        35 => "Mini PC",
        36 => "Stick PC",
        _ => "Unknown",
    }
}

/// Exposes `host.chassis_type()` → `{code: number, label: string} | nil`.
///
/// Reads `Win32_SystemEnclosure.ChassisTypes[0]` (SMBIOS Type-3 field) and
/// returns a two-field table:
/// - `code`  — raw SMBIOS type code (e.g. `9`)
/// - `label` — human-readable label (e.g. `"Laptop"`)
///
/// Returning both lets Lua scripts display the label while still being able
/// to branch on the numeric code (e.g. group codes 8/9/10/14 as "portable").
/// Returns `nil` when WMI fails or `ChassisTypes` is absent (error recorded
/// in `host.errors()` on WMI failure; silent `nil` when the property is
/// simply not present — consistent with other composite bindings).
fn bind_chassis_type(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "chassis_type",
        lua.create_function(move |lua, ()| {
            let mut st = s.borrow_mut();
            let res = st.wmi().and_then(|wmi| {
                let v = wmi.query_first("Win32_SystemEnclosure", "ChassisTypes")?;
                // ChassisTypes is an array of uint16; take the first element.
                // SMBIOS codes are in 1–36, so the u64→u32 cast is lossless;
                // we use try_from rather than `as` to satisfy pedantic clippy.
                // Returns Ok(None) — not an invented "Unknown" — when the
                // property is absent so the Lua binding returns nil instead of
                // a fabricated value.
                let code = v
                    .as_ref()
                    .and_then(serde_json::Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok());
                Ok(code.map(|c| (c, chassis_type_str(c))))
            });
            match res {
                Ok(Some((code, label))) => {
                    let t = lua.create_table()?;
                    t.set("code", code)?;
                    t.set("label", label)?;
                    Ok(Some(t))
                }
                Ok(None) => Ok(None),
                Err(e) => {
                    st.record_error("chassis_type", e);
                    Ok(None)
                }
            }
        })?,
    )
}

/// Exposes `host.virtual_machine()` → `bool`.
///
/// Detection uses two layers:
///
/// **Primary — WMI `Win32_ComputerSystem.Model`.**
/// Hyper-V VMs expose `"Virtual Machine"`, `VMware` exposes a model containing
/// `"VMware"`, `VirtualBox` `"VirtualBox"`, QEMU/KVM `"QEMU"`.  This correctly
/// returns `false` for physical Windows 11 machines that have Hyper-V active
/// for VBS/Credential Guard — they carry a real hardware model string.
///
/// **Fallback — CPUID leaf 1 ECX bit 31 + vendor string.**
/// When WMI is unavailable, the hypervisor-present bit is tested.  If set,
/// the vendor leaf (`0x40000000`) is read: any vendor other than
/// `"Microsoft Hv"` is a non-Microsoft hypervisor and guarantees a VM.
/// `"Microsoft Hv"` is deliberately ignored in the fallback because Windows
/// with VBS reports it even on physical hardware — the WMI model check is
/// the authoritative discriminator for that case.
///
/// On non-x86_64 targets the function always returns `false`.
fn bind_virtual_machine(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "virtual_machine",
        lua.create_function(move |_, ()| {
            let mut st = s.borrow_mut();
            Ok(detect_virtual_machine(&mut st))
        })?,
    )
}

fn detect_virtual_machine(st: &mut HostState) -> bool {
    // --- Layer 1: WMI model string ----------------------------------------
    // Win32_ComputerSystem.Model is already cached if motherboard_details ran.
    let model = st
        .wmi()
        .ok()
        .and_then(|wmi| wmi.query_first("Win32_ComputerSystem", "Model").ok())
        .flatten()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();

    if model == "Virtual Machine"       // Hyper-V guest
        || model.contains("VMware")     // VMware Workstation / ESXi
        || model.contains("VirtualBox") // Oracle VirtualBox
        || model.contains("QEMU")
    // KVM / QEMU
    {
        return true;
    }

    // --- Layer 2: CPUID (offline fallback) ---------------------------------
    // Bit 31 of CPUID(1).ECX = hypervisor-present bit.
    // Vendor string from CPUID(0x40000000): non-"Microsoft Hv" vendors are
    // unambiguously VMs.  "Microsoft Hv" is skipped here because VBS on
    // physical hardware also reports it — Layer 1 is the tie-breaker for
    // that case.
    #[cfg(target_arch = "x86_64")]
    {
        // CPUID is always available on x86_64 — the ISA mandates it.
        let leaf1 = std::arch::x86_64::__cpuid(1);
        if (leaf1.ecx >> 31) & 1 == 1 {
            let vendor_leaf = std::arch::x86_64::__cpuid(0x4000_0000);
            let mut bytes = [0u8; 12];
            bytes[0..4].copy_from_slice(&vendor_leaf.ebx.to_le_bytes());
            bytes[4..8].copy_from_slice(&vendor_leaf.ecx.to_le_bytes());
            bytes[8..12].copy_from_slice(&vendor_leaf.edx.to_le_bytes());
            if std::str::from_utf8(&bytes).is_ok_and(|s| s != "Microsoft Hv") {
                return true;
            }
        }
    }

    false
}

/// Exposes `host.virtualization_capability()` → `bool?`.
///
/// Faithful Rust port of
/// `ComplianceApp/DataTransformers/BIOS/Virtualization.cs`:
///
/// ```text
/// (VMMonitorModeExtensions == Supported
///  && VirtualizationFirmwareEnabled == Enabled)
/// || HypervisorPresent == Present
/// ```
///
/// Three WMI properties from two cached classes:
/// - `Win32_Processor.VMMonitorModeExtensions` — CPU supports Intel
///   VT-x / AMD-V virtualization extensions.
/// - `Win32_Processor.VirtualizationFirmwareEnabled` — BIOS/UEFI has
///   actually turned the extensions on (a CPU can support them while
///   the firmware leaves them off).
/// - `Win32_ComputerSystem.HypervisorPresent` — a hypervisor is
///   running on this machine (either Hyper-V/VBS on the host, or this
///   host is itself a guest VM).
///
/// **Semantic vs `host.virtual_machine()` — these answer two distinct
/// questions:**
///
/// | Binding | Question | Backend |
/// |---|---|---|
/// | `host.virtual_machine()` | "Am I running INSIDE a VM?" | WMI `Win32_ComputerSystem.Model` + CPUID hypervisor-vendor leaf |
/// | `host.virtualization_capability()` | "CAN this host do virtualization, and/or is it doing it already?" | WMI three-property formula above |
///
/// The latter is the precondition exposed by
/// `Win10-Laptop.json → "Virtualization"` for VBS / Credential Guard /
/// WSL2.  A physical laptop with Hyper-V hosting Credential Guard
/// answers `false` to the first and `true` to the second; a guest VM
/// answers `true` to both.
///
/// Missing WMI properties degrade to `false`, mirroring the C#
/// nullable-state semantics (`nullable_enum == specific_value` is
/// always `false` when the nullable is null).  Returns `nil` to Lua
/// only on a hard WMI failure (COM init, namespace unreachable), at
/// which point the failure is also recorded into `host.errors()`.
fn bind_virtualization_capability(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "virtualization_capability",
        lua.create_function(move |_, ()| {
            let mut st = s.borrow_mut();
            match detect_virtualization_capability(&mut st) {
                Ok(v) => Ok(Some(v)),
                Err(e) => {
                    st.record_error("virtualization_capability", e);
                    Ok::<Option<bool>, _>(None)
                }
            }
        })?,
    )
}

fn detect_virtualization_capability(st: &mut HostState) -> Result<bool, String> {
    let wmi = st.wmi()?;
    let vmm = wmi
        .query_first("Win32_Processor", "VMMonitorModeExtensions")?
        .and_then(|v| v.as_bool());
    let firmware = wmi
        .query_first("Win32_Processor", "VirtualizationFirmwareEnabled")?
        .and_then(|v| v.as_bool());
    let hypervisor = wmi
        .query_first("Win32_ComputerSystem", "HypervisorPresent")?
        .and_then(|v| v.as_bool());
    Ok(compute_virtualization_capability(vmm, firmware, hypervisor))
}

/// Pure formula, extracted for unit testing without a live WMI stack.
///
/// Each `Option::unwrap_or(false)` is the Rust equivalent of the C#
/// `nullable_enum_state == specific_state` comparison, which returns
/// `false` when the nullable side is `null` — i.e. a missing WMI
/// property never satisfies the formula by accident.
fn compute_virtualization_capability(
    vmm: Option<bool>,
    firmware: Option<bool>,
    hypervisor: Option<bool>,
) -> bool {
    (vmm.unwrap_or(false) && firmware.unwrap_or(false)) || hypervisor.unwrap_or(false)
}

/// Exposes `host.terminal_sessions()` → `array<{session_id, station_name, state, user, sid}> | nil`.
///
/// Lists all WTS sessions on the local machine via `WTSEnumerateSessionsW` +
/// `WTSQuerySessionInformationW` — the same Win32 path taken by
/// `TerminalSessionService` in `ComplianceApp`'s `components` library.
///
/// Each element mirrors `TerminalSessionDto` from `ComplianceApp`:
/// - `session_id`   — `u32` (e.g. `1`)
/// - `station_name` — station name string (e.g. `"Console"`, `"RDP-Tcp#0"`)
/// - `state`        — `WTS_CONNECTSTATE_CLASS` as string (e.g. `"Active"`, `"Disconnected"`)
/// - `user`         — `"DOMAIN\User"` or `null` when no user is associated
/// - `sid`          — SID string (`"S-1-5-…"`) via `LookupAccountNameW`, or `null`
///
/// Returns `nil` and records an error when `WTSEnumerateSessionsW` fails.
/// Returns an empty array (not `nil`) when enumeration succeeds but the
/// machine reports no sessions.
fn bind_terminal_sessions(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    let s = state.clone();
    host.set(
        "terminal_sessions",
        lua.create_function(move |lua, ()| {
            let mut st = s.borrow_mut();
            match wts::sessions() {
                Ok(rows) => lua.to_value(&serde_json::Value::Array(rows)),
                Err(e) => {
                    st.record_error("terminal_sessions", e);
                    Ok(Value::Nil)
                }
            }
        })?,
    )
}

// --- errors() ---------------------------------------------------------

fn install_errors(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    {
        let s = state.clone();
        host.set(
            "errors",
            lua.create_function(move |lua, ()| {
                let st = s.borrow();
                let t = lua.create_table()?;
                for (k, v) in &st.errors {
                    t.set(k.as_str(), v.as_str())?;
                }
                Ok(t)
            })?,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::compute_virtualization_capability;

    // Truth-table coverage for the `Virtualization.cs` formula.
    //
    // Each Option::unwrap_or(false) mirrors the C# nullable-enum vs
    // specific-state `==` comparison, which is false on null.  The
    // tests pin that semantic so a refactor of the formula cannot
    // silently start returning true on missing WMI data.
    #[test]
    fn formula_false_when_all_inputs_are_none() {
        assert!(!compute_virtualization_capability(None, None, None));
    }

    #[test]
    fn formula_true_on_hypervisor_present_alone() {
        // Common case on a Windows 11 laptop with VBS active: VBS itself
        // forces HypervisorPresent=true regardless of firmware reporting.
        assert!(compute_virtualization_capability(
            Some(false),
            Some(false),
            Some(true)
        ));
    }

    #[test]
    fn formula_true_when_cpu_and_firmware_both_enabled() {
        // Bare-metal machine with VT-x supported AND BIOS flag on,
        // even if no hypervisor is loaded yet.
        assert!(compute_virtualization_capability(
            Some(true),
            Some(true),
            Some(false)
        ));
    }

    #[test]
    fn formula_false_when_cpu_supports_but_firmware_off() {
        // CPU is capable but the BIOS toggle is off and no hypervisor
        // is running — explicitly a NOT-virtualization state in the
        // ComplianceApp transformer.
        assert!(!compute_virtualization_capability(
            Some(true),
            Some(false),
            Some(false)
        ));
    }

    #[test]
    fn formula_false_when_firmware_on_but_cpu_not_supported() {
        assert!(!compute_virtualization_capability(
            Some(false),
            Some(true),
            Some(false)
        ));
    }

    #[test]
    fn formula_treats_missing_cpu_field_as_false_branch() {
        // VMMonitorModeExtensions is null but VirtualizationFirmwareEnabled
        // is true and hypervisor absent → no virtualization claimed.
        // Mirrors `null == Supported` being false in C#.
        assert!(!compute_virtualization_capability(
            None,
            Some(true),
            Some(false)
        ));
    }

    #[test]
    fn formula_missing_hypervisor_does_not_block_cpu_path() {
        // CPU + firmware path is sufficient; missing hypervisor is fine.
        assert!(compute_virtualization_capability(
            Some(true),
            Some(true),
            None
        ));
    }

    #[test]
    fn formula_missing_cpu_path_does_not_block_hypervisor_path() {
        // Either path is independently sufficient — hypervisor wins.
        assert!(compute_virtualization_capability(None, None, Some(true)));
    }
}
