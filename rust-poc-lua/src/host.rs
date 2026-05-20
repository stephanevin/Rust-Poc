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
    install_ad_bindings(lua, &host, &state)?;
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
