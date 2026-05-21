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

use super::{ad, net, registry, winver, wmi::Wmi};

/// Per-run mutable state passed into binding closures. Lua is !Send, so
/// this lives on the blocking thread that owns the Lua VM.
pub(super) struct HostState {
    pub hostname: String,
    pub client_version: String,
    pub perimeter: Option<String>,
    pub wmi: Option<Wmi>,
    pub errors: HashMap<String, String>,
}

impl HostState {
    pub(super) fn new(hostname: String, client_version: String, perimeter: Option<String>) -> Self {
        Self {
            hostname,
            client_version,
            perimeter,
            wmi: None,
            errors: HashMap::new(),
        }
    }

    fn record_error(&mut self, field: &str, reason: String) {
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
    install_winver_bindings(lua, &host)?;
    install_net_bindings(lua, &host, &state)?;
    install_hostname_bindings(lua, &host, &state)?;
    install_ad_bindings(lua, &host, &state)?;
    install_ad_computer_bindings(lua, &host, &state)?;
    install_setup_history(lua, &host)?;
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
            let v = &super::eventlog::install_info()["install_date"];
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

fn install_winver_bindings(lua: &Lua, host: &Table) -> LuaResult<()> {
    host.set(
        "rtl_get_version",
        lua.create_function(|lua, ()| lua.to_value(&winver::rtl_get_version()))?,
    )?;

    host.set(
        "get_firmware_type",
        lua.create_function(|_, ()| Ok(winver::firmware_type().map(str::to_string)))?,
    )?;

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
    bind_hostname(lua, host, state, "netbios_name", super::hostname::netbios_name)?;
    bind_hostname(lua, host, state, "host_name",    super::hostname::dns_hostname)?;
    bind_hostname(lua, host, state, "fqdn",         super::hostname::dns_fqdn)?;
    Ok(())
}

fn install_ad_computer_bindings(lua: &Lua, host: &Table, state: &HostRef) -> LuaResult<()> {
    bind_hostname(lua, host, state, "ad_computer_sam",  super::adcomputer::sam_name)?;
    bind_hostname(lua, host, state, "ad_computer_dn",   super::adcomputer::distinguished_name)?;
    bind_hostname(lua, host, state, "ad_computer_cn",   super::adcomputer::canonical_name)?;
    bind_hostname(lua, host, state, "ad_computer_site", super::adcomputer::site_name)?;
    // UPN of the current user — exposed as `mail_address` because the UPN
    // (user@domain.com) is the best offline proxy for the Exchange `mail`
    // LDAP attribute. See adcomputer::user_upn() doc for the UPN ≠ mail caveat.
    bind_hostname(lua, host, state, "mail_address",     super::adcomputer::user_upn)?;
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
        lua.create_function(|lua, ()| lua.to_value(&super::eventlog::install_info()))?,
    )?;

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
        || model.contains("QEMU")       // KVM / QEMU
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
