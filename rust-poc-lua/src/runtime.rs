//! In-process Lua 5.4 runtime for fleet collectors.
//!
//! Each `InternalRuntime::run()` spins up a fresh `mlua::Lua` on a blocking
//! thread, installs the sandbox + `host` table, evaluates the entry script,
//! calls its global `collect()` function, and converts the returned Lua
//! table to a `serde_json::Value`. The VM is dropped at the end of the
//! run — no persistent state between ticks.
//!
//! Every operation is bounded by a single wall-clock timeout provided by
//! the caller. If the script blocks (infinite loop, slow WMI call, etc.),
//! the tokio task is aborted and the run fails with `LuaError`.

use std::path::PathBuf;
use std::time::Duration;

use mlua::{Lua, LuaSerdeExt};
use serde_json::Value;

use crate::{LuaError, host, sandbox};

pub struct InternalRuntime {
    cache_dir: PathBuf,
    hostname: String,
    client_version: String,
}

impl InternalRuntime {
    #[must_use]
    pub fn new(cache_dir: PathBuf, hostname: String, client_version: String) -> Self {
        Self {
            cache_dir,
            hostname,
            client_version,
        }
    }

    /// Loads the Lua script from `<cache_dir>/<entry_path>` and calls its
    /// global `collect()` function. Returns the result as a JSON object.
    ///
    /// # Errors
    ///
    /// Returns [`LuaError`] on load/compile errors, runtime errors inside
    /// the script, timeout, or a non-object return value.
    pub async fn run(
        &self,
        entry_path: &str,
        perimeter: Option<&str>,
        timeout: Duration,
    ) -> Result<Value, LuaError> {
        let full_path = self.cache_dir.join(entry_path);
        let hostname = self.hostname.clone();
        let version = self.client_version.clone();
        let perim = perimeter.map(str::to_string);
        let script_name = entry_path.to_string();

        let script = tokio::fs::read_to_string(&full_path)
            .await
            .map_err(|e| LuaError(format!("read {path}: {e}", path = full_path.display())))?;

        // mlua::Lua is !Send, so run on a blocking thread. Wrap the join
        // handle in `timeout` so we enforce the wall-clock bound.
        let join = tokio::task::spawn_blocking(move || -> Result<Value, String> {
            let lua = Lua::new();
            sandbox::harden(&lua).map_err(|e| format!("sandbox: {e}"))?;
            let _state = host::install(&lua, &hostname, &version, perim.as_deref())
                .map_err(|e| format!("host install: {e}"))?;
            lua.load(&script)
                .set_name(&script_name)
                .exec()
                .map_err(|e| format!("lua load: {e}"))?;
            let collect: mlua::Function = lua
                .globals()
                .get("collect")
                .map_err(|e| format!("collect() not defined: {e}"))?;
            let result: mlua::Value = collect
                .call(())
                .map_err(|e| format!("collect() runtime: {e}"))?;
            let v: Value = lua
                .from_value(result)
                .map_err(|e| format!("table->json: {e}"))?;
            Ok(v)
        });

        match tokio::time::timeout(timeout, join).await {
            Ok(Ok(Ok(v))) if v.is_object() => Ok(v),
            Ok(Ok(Ok(_))) => Err(LuaError("lua returned non-object".into())),
            Ok(Ok(Err(e))) => Err(LuaError(e)),
            Ok(Err(join_err)) => Err(LuaError(format!("join: {join_err}"))),
            Err(_) => Err(LuaError(format!("timeout after {}s", timeout.as_secs()))),
        }
    }
}
