//! `collect-config` — runs a Lua collector script against the local host.
//!
//! Loads `collectors/<script_name>`, executes its global `collect()`
//! function in a sandboxed mlua VM with the full `host.*` table from
//! `rust-poc-lua`, and prints the returned JSON object to stdout.
//!
//! ## Usage
//!
//! ```text
//! cargo run --bin collect-config -- general.lua
//! cargo run --bin collect-config -- general.lua some-perimeter
//! ```
//!
//! Logs and errors go to stderr; the JSON output is the only thing on
//! stdout, so it can be piped into `jq` or redirected to a file:
//!
//! ```text
//! cargo run --bin collect-config -- general.lua > config.json
//! cargo run --bin collect-config -- general.lua | jq '.machine_name'
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use rust_poc_lua::InternalRuntime;

// `#[tokio::main]` expands to a synchronous `main` that constructs a
// multi-thread runtime and blocks on the async body below. `multi_thread`
// is required because `InternalRuntime::run` calls `spawn_blocking`, and
// a `current_thread` runtime can't schedule blocking tasks.
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let script = args.get(1).cloned().unwrap_or_else(|| "general.lua".into());
    let perimeter = args.get(2).map(String::as_str);

    let cache_dir = PathBuf::from("collectors");

    // `hostname::get` is the cross-platform way to read the machine
    // name (GetComputerNameW on Windows, gethostname() on Unix). The
    // runtime exposes it to Lua scripts as `host.env("SDH_HOSTNAME")`.
    let hostname = match hostname::get() {
        Ok(h) => h.to_string_lossy().into_owned(),
        Err(e) => {
            eprintln!("collect-config: cannot read hostname: {e}");
            return ExitCode::from(2);
        }
    };

    let runtime = InternalRuntime::new(cache_dir, hostname, env!("CARGO_PKG_VERSION").to_string());

    eprintln!(
        "collect-config: running {script} (perimeter={})",
        perimeter.unwrap_or("<none>")
    );

    match runtime
        .run(&script, perimeter, Duration::from_secs(30))
        .await
    {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("collect-config: serialize output: {e}");
                ExitCode::from(3)
            }
        },
        Err(e) => {
            eprintln!("collect-config: {e}");
            ExitCode::from(1)
        }
    }
}
