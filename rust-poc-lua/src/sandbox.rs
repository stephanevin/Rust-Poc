//! Strips unsafe globals from a Lua environment, leaving only what the
//! collector actually needs. Never exposes filesystem, process, or module
//! loading APIs.

use mlua::{Lua, Nil, Result as LuaResult};

pub(super) fn harden(lua: &Lua) -> LuaResult<()> {
    // Capture a monotonic start time now so `os.clock()` can report elapsed
    // seconds since the VM was hardened — matching the intent of the Lua
    // standard library's `os.clock()` (CPU/wall time since process start).
    // If we wrote `Instant::now().elapsed()` *inside* the closure instead,
    // every call would measure the time from a freshly created instant (≈ 0).
    let start = std::time::Instant::now();
    let g = lua.globals();

    // Remove dangerous or FS-escape-prone APIs entirely.
    for name in [
        "io",
        "os",
        "dofile",
        "loadfile",
        "load",
        "loadstring",
        "require",
        "package",
        "debug",
        "collectgarbage",
    ] {
        g.set(name, Nil)?;
    }

    // Install a minimal `os` table with time-only access.
    let os_table = lua.create_table()?;
    os_table.set(
        "time",
        // FIXME(rust-poc-lua-vs-upstream): clippy::map_unwrap_or fires on
        // .map(...).unwrap_or(0) under Rust 1.95 + pedantic. The verbatim
        // upstream `sdh-fleet-client/lua/src/sandbox.rs` has the same
        // pattern; reporting upstream so this `#[allow]` can be dropped
        // once the upstream sandbox is refactored to `.map_or(0, ...)`.
        #[allow(clippy::map_unwrap_or)]
        lua.create_function(|_, ()| {
            Ok(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                .unwrap_or(0))
        })?,
    )?;
    os_table.set(
        "clock",
        lua.create_function(move |_, ()| Ok(start.elapsed().as_secs_f64()))?,
    )?;
    g.set("os", os_table)?;

    Ok(())
}
