# CLAUDE.md — Rust-Poc

Personal Rust learning workspace. This file primes any AI coding agent
(Claude Code, Cursor, Copilot, Codex, Aider, …) with the conventions
inherited from `sdh-fleet/sdh-fleet-client`, so changes here look and
feel like changes there.

## Pedagogical context

This repository exists for learning. The owner has 20+ years of C# and
PowerShell experience but is new to Rust. When making changes:

- Prefer **idiomatic, readable** solutions over clever ones. The owner
  needs to be able to read the code six months later and understand it.
- When introducing a new concept (lifetimes, trait objects, async,
  custom derives, macros, `unsafe`, etc.), **call it out** in the
  response so the owner knows what to study next.
- When a problem has multiple legitimate solutions, briefly state the
  trade-off rather than silently picking one.
- Do NOT auto-correct unidiomatic code without explaining why it was
  unidiomatic — the owner learns more from the explanation than from
  receiving a polished diff.
- Reference relevant chapters of the official Rust Book
  (<https://doc.rust-lang.org/book/>) when introducing a new concept,
  if you remember which chapter covers it.

## Commands

```bash
cargo check --workspace --all-targets        # Type-check everything (~1s, used dozens of times per session)
cargo clippy --workspace --all-targets -- -D warnings  # Lint, warnings as errors
cargo fmt --all                              # Format to rustfmt defaults
cargo test --workspace                       # Unit + integration + doc tests
cargo run                                    # Build + execute collect-config on ./collectors/general.lua
cargo run -- general.lua some-perimeter      # Pass script + perimeter args explicitly
cargo build --release                        # Optimised final binary in target/release/collect-config.exe
```

```powershell
# Build the Windows installer EXE (Inno Setup). Reads the version from
# Cargo.toml, stages target/release/collect-config.exe + collectors/
# into ./publish/, signs the binary, then compiles
# Setup/CollectConfigSetup.iss into Setup/Output/CollectConfigSetup-<v>.exe.
.\publish-innosetup.ps1                      # signed (requires SDH_SIGN_THUMBPRINT + cert in store)
.\publish-innosetup.ps1 -SkipSign            # local dev iteration, unsigned EXE
.\publish-innosetup.ps1 -SkipBuild           # rebuild only the EXE (publish/ already populated)
```

Note: `cargo run` at the workspace root launches `collect-config`
thanks to the `default-run = "collect-config"` key in the root
`Cargo.toml`. The workspace currently exposes a **single** binary
(`collect-config`, produced from `src/main.rs` via a `[[bin]]` block
that pins the artifact name independently of the package name).
`default-run` is also future-proofing — adding a second binary later
keeps `cargo run` deterministic.

**Anti-regression note — DO NOT REWRITE THIS BLOCK CASUALLY.** This
note has already been silently overwritten twice by AI agents
reformatting the section. If you are about to delete or rewrite the
preceding paragraph, the `default-run` key in `Cargo.toml`, or the
`[[bin]] name = "collect-config"` line that pins the artifact name,
you must justify the change in your commit message — otherwise
restore them verbatim.

The pinned toolchain (Rust 1.95.0 + clippy + rustfmt) lives in
`rust-toolchain.toml` — rustup picks it up automatically on the first
`cargo` invocation in this directory.

## Architecture

Three sibling crates in one workspace, modelled on the cross-boundary
structure of `sdh-fleet-client`:

| Crate | Role | Mirror in sdh-fleet-client |
|---|---|---|
| **`rust-poc-contracts`** (`contracts/`) | Placeholder crate for cross-workspace wire types. Currently empty after the Hello World types were retired — kept to preserve the "types live in `contracts/`" invariant for future additions. | `sdh-fleet-client/contracts/` |
| **`rust-poc-lua`** (`rust-poc-lua/`) | In-process Lua 5.4 collector runtime + 51 `host.*` bindings (WMI, registry, networking, ADSI, hostname variants, WTS, NT kernel, WNF, GPO, TLS, regional, accounts, software, system updates). Windows-only real impl + cross-target stub. | `sdh-fleet-client/lua/` (verbatim port, see [Lua collector runtime](#lua-collector-runtime)) |
| **`rust-poc`** (root + `src/main.rs`) | Composer — installs the tracing subscriber, validates the CLI script path, drives `rust-poc-lua::InternalRuntime::run`. Ships the `collect-config` binary. | `sdh-fleet-client/src/main.rs` + `sdh-fleet-client/src/logging.rs` |

### Architectural rules

- **`contracts/` is the only place a cross-crate type lives.** Never
  define a struct or enum directly in the root bin or in
  `rust-poc-lua/` if it's meant to cross a process boundary — extend
  `contracts/` and let the others import. Even with the crate
  currently empty, the invariant stands. Same rule as in
  `sdh-fleet-client/contracts/`.
- **`contracts/` keeps runtime deps minimal.** `serde` + `serde_json`
  are always-on (they are de-facto stdlib for any wire type). Anything
  heavier — `schemars`, `tokio`, `reqwest` — goes behind a feature
  flag if it ever returns, exactly like
  `sdh-fleet-client/contracts/Cargo.toml`.
- **The root bin is a composer, not a place for logic.** It owns the
  CLI surface (arg parsing, exit codes, stdout vs stderr discipline)
  and the logging stack; everything else lives in a sibling crate.
  When the script-loading or sandbox logic needs to evolve, it
  evolves in `rust-poc-lua/`, not in `src/main.rs`.

### Wire-format discipline

Rules for any struct or enum added to `contracts/` that crosses a
process boundary (JSON file on disk, HTTP body, log payload, …). They
were enforced on the original Hello World types and stay in force for
whatever lands next:

- **Always derive `Serialize` + `Deserialize`.** Even if a type is
  internal today, the derive is cheap and lets the type become wire-
  visible later without a breaking change.
- **Never use `#[serde(deny_unknown_fields)]`.** A producer that adds
  a new field must not break a consumer that hasn't learned about it
  yet. The default serde behaviour (silently ignore unknown fields)
  is the forward-compatibility contract.
- **Optional fields use `Option<T>` + `#[serde(default,
  skip_serializing_if = "Option::is_none")]`.** This keeps the wire
  format clean (no `"field": null` noise) AND lets legacy payloads
  without the field parse cleanly.
- **Enum variants serialize to lowercase by default**
  (`#[serde(rename_all = "lowercase")]`). Tagged unions use
  `#[serde(tag = "type", rename_all = "snake_case")]` when needed —
  same convention as `sdh-fleet-client/contracts/src/agent.rs`.

Round-trip tests are the cheapest defence against accidental wire
breakage — pin the exact JSON string with `assert_eq!`. Reintroduce
that pattern as soon as a non-trivial type lands.

### JSON key ordering

`serde_json/preserve_order` is **not** enabled. `serde_json::Map` uses
its default `BTreeMap` backing, which sorts keys alphabetically.

This is the deliberately chosen trade-off: `preserve_order` switches
to `IndexMap` (insertion order), but Lua 5.4 does **not** guarantee
stable iteration order for hash tables with more than ~15 entries. The
`general.lua` table has ~28 entries, so `preserve_order` would produce
Lua-hash order (effectively random) rather than source order — worse
than alphabetical for human inspection. Alphabetical order at least
lets the reader `Ctrl+F` predictably.

If a strict source-order guarantee ever becomes necessary, the correct
approach is to use an ordered Lua table (array of `{key, value}` pairs)
and convert it on the Rust side — not `preserve_order` alone.

## Logging

Tracing stack mirrored from `sdh-fleet-client/src/logging.rs`, minus
the hot-reload machinery (no remote config source means no reason to
swap filters at runtime). See `src/logging.rs` for the init and
`rust-poc-lua/src/*.rs` for the `debug!` / `info!` call-sites that
surface during a collector run.

### Layers

- **Console** (stderr, compact): human-readable during development.
- **File** (JSON, daily-rolling): machine-readable, one event per
  line, queryable with `jq`.

Both layers share a single `EnvFilter` that defaults to `INFO` and is
overridden by `RUST_LOG` (e.g. `RUST_LOG=rust_poc_lua=debug` to see
every `host.*` binding call from the collector).

### Log directory resolution (priority order)

1. `RUST_POC_LOG_DIR` env var, if set. **This is the operator's
   escape hatch.** On this developer's machine it should be set to
   `C:\SMSLogs` system-wide:
   ```powershell
   [System.Environment]::SetEnvironmentVariable(
       'RUST_POC_LOG_DIR', 'C:\SMSLogs', 'User')
   ```
   (then reopen the terminal so the variable is picked up).
2. `<directory containing the executable>/logs/` — what production
   builds use by default. For `cargo run`, this resolves to
   `target/debug/logs/` or `target/release/logs/`.
3. `./logs/` relative to the current working directory — last-resort
   fallback when `std::env::current_exe()` fails (rare).

The resolver itself does **not** validate writability — it just picks
the path. `tracing-appender` is best-effort and silently drops events
if the directory turns out to be unwritable, same posture as
`sdh-fleet-client`.

### Call-site discipline

- `info!(field = value, "human message")` — never interpolate the
  field into the message string. Structured fields stay queryable.
- `%expr` for `Display`, `?expr` for `Debug` formatting of a field.
- Crates that do work (`rust-poc-lua/`) depend on `tracing` only, not
  on `tracing-subscriber`. Macros expand to no-ops when no subscriber
  is installed, which keeps unit tests free of any setup boilerplate.
- `logging::init()` returns `(WorkerGuard, PathBuf)`. The root binary
  destructures it as `let (_log_guard, log_dir) = logging::init();`:
  - `_log_guard` must live for the whole program. Dropping it kills
    the non-blocking writer's worker thread and silently loses any
    pending log lines.
  - `log_dir` is the resolved log directory, captured once so the
    binary can colocate other per-run artefacts (e.g. the JSON dump
    that `write_output_file` produces) without re-resolving
    `RUST_POC_LOG_DIR`. A second `resolve_log_dir()` call could
    observe a different value if the env var changed between calls
    — a TOCTOU we sidestep by returning the path from `init()`.

## Lua collector runtime

The `rust-poc-lua/` crate is a **verbatim port** of
`sdh-fleet-client/lua/` from the sibling repo
(`C:\Users\Vin\source\repos\sdh\sdh-fleet\sdh-fleet-client\lua\`). The
goal is pedagogical — read and run the production code line-for-line
instead of re-implementing a subset, so future upgrades flow naturally
from the upstream crate via a `Copy-Item`.

Same file names, same module boundaries, same comments. The only
intentional deviations from a strict `cp -r` are documented below.

### Source layout (mirrors upstream)

```
rust-poc-lua/src/
├── lib.rs          # Public API + non-Windows stub
├── runtime.rs      # InternalRuntime::run — async, tokio::spawn_blocking + timeout
├── sandbox.rs      # Strips io/dofile/require/etc. globals
├── host.rs         # 51 `host.*` bindings + HostState (Rc<RefCell<..>>)
├── wmi.rs          # COMLibrary + WMIConnection + per-class cache
├── registry.rs     # RegOpenKeyExW + RegQueryValueExW + REG_* decode
├── net.rs          # GetAdaptersAddresses + IPv4 enumeration
├── hostname.rs     # GetComputerNameExW — 3 variants (deviation #6, not in upstream)
├── adcomputer.rs   # GetComputerObjectNameW + DsGetSiteNameW + GetUserNameExW — 5 AD attrs (deviation #7, not in upstream)
├── winver.rs       # RtlGetVersion + GetFirmwareType
├── eventlog.rs     # Install date (registry-derived ISO 8601)
├── updates.rs      # WUA COM bindings (IUpdateSession3, ISystemInformation, …) + WMI Root\ccm — deviations #26–#31
└── ad.rs           # ADSI mail lookup stub (phase 2 in upstream)
```

### The 51 `host.*` bindings exposed to Lua

| Binding | Backend | Surface |
|---|---|---|
| `host.env(name)` | `std::env::var` + injected `SDH_HOSTNAME` / `SDH_CLIENT_VERSION` / `SDH_PERIMETER` | `string?` |
| `host.now_iso8601()` | `eventlog::install_info()["install_date"]` | `string?` |
| `host.wmi_query(class, prop)` | `WMIConnection::raw_query` (cached per class) | `any?` |
| `host.wmi_all(class)` | `WMIConnection::raw_query` | `array<object>?` |
| `host.registry_read(hive, key, value)` | `RegOpenKeyExW` + decode (SZ / DWORD / QWORD / MULTI_SZ) | `string \| number \| array?` |
| `host.rtl_get_version()` | `RtlGetVersion` | `{major, minor, build}?` |
| `host.get_firmware_type()` | `GetFirmwareType` | `"UEFI" \| "BIOS" \| nil` |
| `host.net_interfaces()` | `GetAdaptersAddresses` (loopback filtered) | `array<{name, ipv4[]}>?` |
| `host.netbios_name()` **(deviation #6)** | `GetComputerNameExW(ComputerNameNetBIOS)` | `string?` |
| `host.host_name()` **(deviation #6)** | `GetComputerNameExW(ComputerNameDnsHostname)` | `string?` |
| `host.fqdn()` **(deviation #6)** | `GetComputerNameExW(ComputerNameDnsFullyQualified)` | `string?` |
| `host.adsi_user_mail(timeout_s)` | ADSI stub (returns nil unless USERDNSDOMAIN is set) | `string?` |
| `host.ad_computer_sam()` **(deviation #7)** | `GetComputerObjectNameW(NameSamCompatible)` | `string?` |
| `host.ad_computer_dn()` **(deviation #7)** | `GetComputerObjectNameW(NameFullyQualifiedDN)` + GP registry fallback | `string?` |
| `host.ad_computer_cn()` **(deviation #7)** | `GetComputerObjectNameW(NameCanonical)` | `string?` |
| `host.ad_computer_site()` **(deviation #7)** | `DsGetSiteNameW` + GP registry fallback | `string?` |
| `host.mail_address()` **(deviation #7)** | `GetUserNameExW(NameUserPrincipal)` — UPN, offline proxy for `mail` LDAP attr | `string?` |
| `host.setup_history()` | `eventlog::install_info` | `{install_date, history[]}` |
| `host.cpu_details()` | WMI `Win32_Processor.Name + SocketDesignation` | `string?` |
| `host.ram_total()` | WMI `Win32_PhysicalMemory.Capacity` (summed) | `number?` |
| `host.disk_size(target, property)` | WMI `Win32_LogicalDisk` filtered by `%SystemDrive%` | `number?` |
| `host.motherboard_details()` | WMI `Win32_ComputerSystem.Model + SystemFamily` | `string?` |
| `host.bios_details()` | WMI `Win32_BIOS.BIOSVersion` + `winver::firmware_type` | `string?` |
| `host.desktop_resolution()` | WMI `Win32_VideoController.{Current*Resolution, RefreshRate}` | `string?` |
| `host.chassis_type()` **(deviation #8)** | WMI `Win32_SystemEnclosure.ChassisTypes[0]` → SMBIOS code + label | `{code: number, label: string}?` |
| `host.virtual_machine()` **(deviation #8)** | CPUID leaf 1 ECX bit 31 (`std::arch::x86_64::__cpuid`) | `bool` |
| `host.terminal_sessions()` **(deviation #9)** | WTS `WTSEnumerateSessionsW` + `WTSQuerySessionInformationW` + `LookupAccountNameW` | `array<{session_id, station_name, state, user, sid}>?` |
| `host.os_last_boot_up_time()` | `NtQuerySystemInformation(SystemTimeOfDayInformation).BootTime` → ISO 8601 UTC | `string?` |
| `host.uso_reboot_required()` **(deviation #10)** | `NtQueryWnfStateData(WNF_USO_REBOOT_REQUIRED)` via [`wnf`](https://docs.rs/wnf) crate — DWORD > 0 → true | `bool?` |
| `host.ad_computer_gpos()` **(deviation #11)** | Registry `Group Policy\State\Machine\GPO-List` + `GPLink-List` — mirrors `AdComputerGpos.cs` | `array<{context, link_order, gpo_name, gpo_id, filtering, scope_of_management, revision}>?` |
| `host.ad_user_gpos()` **(deviation #12)** | Registry `Group Policy\State\{SID}\GPO-List` (all non-Machine contexts) — mirrors `AdUserGpos.cs` | `array<{context, link_order, gpo_name, gpo_id, filtering, scope_of_management, revision, is_loopback}>?` |
| `host.gp_extensions_status()` **(deviation #13)** | Registry `Group Policy\State\Machine\Extension-List` + `Group Policy\Status\GPExtensions` — mirrors `GpExtensionsStatus.cs` | `array<{id, name, status, last_policy_time}>?` |
| `host.tls_cipher_suites()` **(deviation #14)** | `BCryptEnumContextFunctions(CRYPT_LOCAL, "SSL", NCRYPT_SCHANNEL_INTERFACE)` — effective Schannel cipher suite list (local + GP merged), mirrors `OSTlsCipherSuite.cs` / `BCrypt.cs` | `array<string>?` |
| `host.user_ui_language()` **(deviation #15)** | `GetUserDefaultUILanguage()` → `LCIDToLocaleName` — BCP-47 UI language of the current user (token-sensitive); mirrors `MuiLang.cs` / `UserDefaultLanguage.cs` | `string?` |
| `host.system_ui_language()` **(deviation #16)** | `GetSystemDefaultUILanguage()` → `LCIDToLocaleName` — BCP-47 UI language of the OS installation (token-independent); mirrors `SystemDefaultLanguage.cs` | `string?` |
| `host.user_locale()` **(deviation #17)** | `GetUserDefaultLocaleName()` — BCP-47 regional locale (date/number format) of the current user (token-sensitive); mirrors `CurrentCulture.cs` | `string?` |
| `host.system_locale()` **(deviation #18)** | `GetSystemDefaultLocaleName()` — BCP-47 system-wide regional locale (token-independent); mirrors `SystemCulture.cs` | `string?` |
| `host.user_profiles()` **(deviation #19)** | Registry `ProfileList\*` + `LookupAccountSidW` — Windows user profiles with SID, NTAccount, path, load/unload FILETIME; mirrors `UserProfiles.cs` | `array<{sid, nt_account, profile_image_path, local_profile_load_time?, local_profile_unload_time?}>` |
| `host.local_user_accounts()` **(deviation #20)** | `NetUserEnum(level=0)` + `NetUserGetInfo(level=4)` — local accounts with flags, timestamps, SID from `usri4_user_sid`; mirrors `LocalAccountsUsers.cs` | `array<{name, full_name, description, domain, sid, disabled, lockout, …}>?` |
| `host.local_group_members(sid)` **(deviation #21)** | `LookupAccountSidW` (group name) + `NetLocalGroupGetMembers(level=2)` + `ConvertSidToStringSidW` (members); mirrors `LocalAccountsAdminMembers.cs` / `LocalAccountsRdpMembers.cs` | `array<{name, domain, caption, sid, sid_type: string, local_account}>?` |
| `host.os_software_installed()` **(deviation #22)** | Registry `Uninstall\*` (HKLM 64-bit + WOW6432Node) + `HKEY_USERS\{SID}\…\Uninstall` for **Active** WTS domain sessions; deduplicates on `(context, publisher, display_name, version, software_code)`, no HKLM persistence snapshot; mirrors `OSSoftwareInstalled.cs` | `array<{context, system_component, publisher, display_name, version, install_date, software_code}>` |
| `host.os_services()` **(deviation #23)** | Win32 SC Manager APIs (`OpenSCManagerW` + `EnumServicesStatusExW` + `QueryServiceConfigW` + `QueryServiceConfig2W`) instead of WMI `Win32_Service` — lower overhead, no COM marshalling; mirrors `OSServices.cs` | `array<{display_name, start_mode, delayed_auto_start, state, start_name, path_name, name}>?` |
| `host.browser_extensions_installed()` **(deviation #24)** | Chromium `Preferences` + `Secure Preferences` parsed as `ChromiumPreferencesParser`; 7 browsers (Edge, Chrome, Brave, Vivaldi, Arc, Opera, Opera GX); `_locales/en/messages.json` NLS resolution; mirrors `BrowserExtensionsInstalled.cs` + `ChromiumPreferencesParser.cs` | `array<{browser, sid, user_profile, …28 fields}>` |
| `host.ide_extensions_installed()` **(deviation #25)** | VS Code-family (VSCode, Insiders, Cursor, Windsurf, VSCodium, Antigravity); `extensions.json` registry + `package.json` + `package.nls*.json` NLS resolution; mirrors `IdeExtensionsInstalled.cs` | `array<{ide, sid, user_profile, …18 fields}>` |
| `host.updates_is_managed()` **(deviation #26)** | WUA COM `IUpdateServiceManager2::Services` → `IsDefaultAUService` → `IsManaged`; mirrors `UpdatesIsManaged.cs`; shares `HostState::au_service` cache with #27 | `"Managed" \| "Unmanaged" \| nil` |
| `host.updates_managed_by()` **(deviation #27)** | WUA COM `IUpdateServiceManager2::Services` → `IsDefaultAUService` → `Name`; mirrors `UpdatesManagedBy.cs`; shares `HostState::au_service` cache with #26 | `string?` |
| `host.updates_reboot_required()` **(deviation #28)** | WUA COM `ISystemInformation::RebootRequired`; mirrors `UpdatesRebootRequired.cs` | `bool?` |
| `host.updates_reboot_required_before_installation()` **(deviation #29)** | WUA COM `IUpdateInstaller::RebootRequiredBeforeInstallation`; mirrors `UpdatesRebootRequiredBeforeInstallation.cs` | `bool?` |
| `host.updates_windows_updates()` **(deviation #30)** | WUA COM `IUpdateSession3` → `IUpdateSearcher3` offline search (`"IsInstalled=1 OR IsInstalled=0"`); mirrors `UpdatesWindowsUpdates.cs`; no 90 s timeout thread; shares `HostState::updates_cache` with #31 (one offline search, two consumers) | `array<{title, article_ids, category, update_id, …20 fields}>?` |
| `host.updates_sccm_updates()` **(deviation #31)** | WMI `Root\ccm\SoftwareUpdates\DeploymentAgent::CCM_TargetedUpdateEx1` joined in-memory against the shared `HostState::updates_cache` index (no second offline search); mirrors `UpdatesSccmUpdates.cs`; returns `[]` when no SCCM agent (`WBEM_E_INVALID_NAMESPACE`) | `array<{update_id, title, article_ids, installed, …11 fields}>` |
| `host.errors()` | Internal `HashMap<String, String>` accumulated by other bindings | `table<string, string>` |

Bindings never raise — failures are recorded into `host.errors()` and
the binding returns `nil`. The Lua script attaches the final
`host.errors()` map as `_errors` in its output for the operator to
inspect.

### `collect-config` CLI

```powershell
# Run the bundled general.lua collector against the local host
cargo run

# Optional script + perimeter arguments (perimeter surfaces as
# host.env("SDH_PERIMETER"))
cargo run -- general.lua some-perimeter

# Pipe-friendly: only the JSON goes to stdout, logs/progress to stderr
cargo run --quiet > config.json
cargo run --quiet | jq '.machine_name'
```

The binary lives at `src/main.rs` and is produced as
`target/debug/collect-config.exe`. It installs the tracing subscriber,
validates the script path via `resolve_script_path` (canonicalise +
`starts_with` to refuse traversal), constructs an `InternalRuntime`,
calls `runtime.run(...)` with a 30s wall-clock timeout, and pretty-
prints the returned JSON. Logs and progress go to stderr; only the
JSON goes to stdout.

Exit codes: `0` success, `1` Lua runtime error (script error or
timeout), `2` cannot read hostname, `3` cannot serialize output, `4`
script path escapes the `collectors/` directory (path traversal
rejected by `resolve_script_path`).

### Deviations from a strict verbatim copy

There are exactly **fourteen** points where copying upstream byte-for-byte
would not compile or would not match the surface this PoC needs to
expose. Each one is documented inline at the touch site so a future
re-sync is mechanical.

1. **`rust-poc-lua/Cargo.toml` — package name**
   `name = "sdh-fleet-lua"` → `name = "rust-poc-lua"`.

2. **`rust-poc-lua/Cargo.toml` — lints policy**
   The upstream local `[lints.clippy] pedantic = ...` block is replaced
   by `[lints] workspace = true`. The workspace policy in the root
   `Cargo.toml` is byte-identical (`pedantic` + `unwrap_used` +
   `expect_used` at `warn`) — just attached one level up instead of
   inline.

3. **`rust-poc-lua/Cargo.toml` — tokio `fs` feature**
   `tokio` gains the `fs` feature because `runtime.rs` uses
   `tokio::fs::read_to_string`. In the sdh-fleet-client workspace this
   compiles because another crate's tokio dep activates `fs` and Cargo
   unifies features across the workspace. Adding `fs` explicitly here
   keeps `cargo check -p rust-poc-lua` working in isolation.

4. **`rust-poc-lua/src/lib.rs` — broken intra-doc link**
   Upstream references `[`sdh_fleet_contracts::host_api::HOST_API`]`
   (rustdoc link). The `sdh-fleet-contracts` crate doesn't exist here,
   so the link would fail to resolve and break `cargo doc`. Replaced
   with a plain prose reference (with backticks around `HOST_API` so
   `clippy::doc_markdown` stays quiet).

5. **`rust-poc-lua/src/sandbox.rs` — `#[allow(clippy::map_unwrap_or)]`**
   Rust 1.95 + `pedantic` warns on `.map(<f>).unwrap_or(<a>)` and
   suggests `.map_or(<a>, <f>)`. Upstream has the same pattern but its
   CI doesn't gate on this lint yet, so the warning slipped through.
   Added a targeted `#[allow]` (with a FIXME comment) instead of
   refactoring, so a future `Copy-Item` from upstream stays a one-liner
   diff. Drop the `#[allow]` once upstream refactors the closure.

6. **`rust-poc-lua/src/hostname.rs` + `install_hostname_bindings` in
   `host.rs` — three additional hostname bindings.**
   Upstream exposes 17 `host.*` bindings; this PoC exposes 29. The
   three extra bindings all call `GetComputerNameExW` with a different
   `COMPUTER_NAME_FORMAT` constant (non-`Physical*` variants — parité
   avec `IPGlobalProperties.HostName` de .NET, voir ci-dessous) :
   - `host.netbios_name()` — `ComputerNameNetBIOS` (≤ 15 chars, ASCII
     uppercase). Equivalent à `%COMPUTERNAME%` / `Environment.MachineName`.
   - `host.host_name()` — `ComputerNameDnsHostname` (no dots). Même
     valeur que `IPGlobalProperties.HostName`. Diffère de `netbios_name`
     sur les machines renommées ou avec un `DnsHostName` GPO override.
   - `host.fqdn()` — `ComputerNameDnsFullyQualified`. Egal à `host_name`
     hors domaine; porte le suffixe AD (e.g. `.sanofi.com`) sur les
     machines domain-joined.
   All three use **non-`Physical*`** constants to match .NET semantics.
   On standard Sanofi endpoints (no Failover Cluster) the Physical and
   non-Physical variants return identical strings. On a Windows Failover
   Cluster node `Physical*` would give the physical node name; the
   current non-Physical choice gives the logical/cluster name — matching
   what `IPGlobalProperties.HostName` returns. This decision is a
   deliberate trade-off: revert by swapping to `ComputerNamePhysical*`
   in `hostname.rs` if cluster deployments emerge.
   Re-sync impact: if upstream eventually adds equivalent bindings,
   align names + signatures and drop this deviation. Until then, every
   upstream `Copy-Item` MUST preserve `hostname.rs` and the
   `install_hostname_bindings` call in `host.rs`.

7. **`rust-poc-lua/src/adcomputer.rs` + `install_ad_computer_bindings`
   in `host.rs` — four AD computer-object bindings.**
   Mirrors `ActiveDirectory.cs` from the ComplianceApp; not in
   upstream. Exposes AD attributes of the local computer account via
   `GetComputerObjectNameW` (`Win32_Security_Authentication_Identity`)
   and `DsGetSiteNameW` (`Win32_Networking_ActiveDirectory`):
   - `host.ad_computer_sam()` — `NameSamCompatible`
     (e.g. `PHARMA\E00AVDDWDEV0271$`).
   - `host.ad_computer_dn()` — `NameFullyQualifiedDN`
     (e.g. `CN=E00AVDDWDEV0271,OU=WAAS,...,DC=com`).
     Falls back to `HKLM\...\Group Policy\State\Machine\Distinguished-Name`
     when Netlogon is not cached.
   - `host.ad_computer_cn()` — `NameCanonical`
     (e.g. `pharma.aventis.com/ZZ NGDC EMEA/.../E00AVDDWDEV0271`).
   - `host.ad_computer_site()` — `DsGetSiteNameW`
     (e.g. `IE-AZU02`).
     Falls back to `HKLM\...\Group Policy\State\Machine\Site-Name`
     when `DsGetSiteNameW` fails.
   All four return `nil` on workgroup machines or before the first GP
   cycle, and record the failure in `host.errors()`. The LDAP
   (`DirectorySearcher`) level present in the C# reference is
   intentionally absent — it requires an active network connection,
   inconsistent with offline-first resilience.
   Re-sync impact: add `adcomputer.rs` to the upstream crate and drop
   this deviation if the fleet-client eventually needs these fields.
   Until then, `Copy-Item` MUST preserve `adcomputer.rs` and the
   `install_ad_computer_bindings` call in `host.rs`.

8. **`rust-poc-lua/src/host.rs` — two hardware enrichment bindings.**
   Not in upstream. Added as composite bindings inside
   `install_composites()`:
   - `host.chassis_type()` — reads `Win32_SystemEnclosure.ChassisTypes[0]`
     (SMBIOS Type-3 code) and translates it to a human-readable label
     via the `chassis_type_str()` match table (codes 1–36, SMBIOS 3.x
     spec §7.4). Returns `nil` on WMI failure.
   - `host.virtual_machine()` — issues a single CPUID instruction
     (`std::arch::x86_64::__cpuid(1)`) and tests ECX bit 31 (the
     hypervisor-present bit, mandatory by the x86 hypervisor discovery
     protocol). Returns `true` on Hyper-V, VMware, VirtualBox, KVM;
     `false` on bare metal or any non-x86_64 target. Requires no COM
     initialisation and works when WMI is unavailable.
   Re-sync impact: `Copy-Item` of `host.rs` MUST preserve
   `bind_chassis_type`, `bind_virtual_machine`, `chassis_type_str`, and
   their calls inside `install_composites`.

9. **`rust-poc-lua/src/updates.rs` + `install_updates_bindings` in
   `host.rs` — six System Updates bindings.**
   Not in upstream. Uses WUA COM interfaces directly (`IUpdateServiceManager2`,
   `ISystemInformation`, `IUpdateInstaller`, `IUpdateSession3`) matching the
   ComplianceApp implementation. Requires feature `Win32_System_UpdateAgent` in
   `rust-poc-lua/Cargo.toml`.
   - `host.updates_is_managed()` — déviation #26. Returns `"Managed"` /
     `"Unmanaged"` / `nil`. Type differs from the C# `UpdateManagementState` enum.
   - `host.updates_managed_by()` — déviation #27. Name of default AU service.
   - `host.updates_reboot_required()` — déviation #28. `ISystemInformation::RebootRequired`.
   - `host.updates_reboot_required_before_installation()` — déviation #29.
     `IUpdateInstaller::RebootRequiredBeforeInstallation`.
   - `host.updates_windows_updates()` — déviation #30. Faithful offline WUA
     search; no 90 s `CancellationToken` timeout thread (synchronous; `spawn_blocking`
     provides isolation).
   - `host.updates_sccm_updates()` — déviation #31. WMI `Root\ccm` + WUA
     offline bulk search for in-memory join (no N individual searches). Returns
     `[]` when SCCM agent is absent (`WBEM_E_INVALID_NAMESPACE`); propagates any
     other WMI/CCM failure into `host.errors()`.

   **Per-run caches on `HostState`** — two lazy-init fields mirror the
   existing `wmi: Option<Wmi>` pattern, both shaped as tri-state enums
   so init failures are memoised (no expensive retry) and surfaced
   under a single canonical error key:
   - `updates_cache: UpdatesCacheState` (`NotInit | Ready(UpdatesCache)
     | Failed`) — one offline WUA search builds both the full update
     list (#30) and the `UpdateID → WuaMeta` join index (#31).  Halves
     the most expensive call when both bindings are consumed in the
     same run.  Init failures are recorded once under the canonical key
     `ERR_KEY_WUA_CACHE_INIT = "updates:wua_cache_init"`; SCCM rows
     still come through with `null` enrichment.
   - `au_service: AuServiceState` (`NotInit | Ready(Option<(bool,
     String)>) | Failed`) — one `IUpdateServiceManager2::Services`
     enumeration feeds both #26 and #27.  The inner `Option` of `Ready`
     distinguishes "no default AU service registered" (`Ready(None)`)
     from "service found" (`Ready(Some((managed, name)))`).  Init
     failures are recorded once under
     `ERR_KEY_AU_SERVICE = "updates:au_service"`.

   Re-sync impact: `Copy-Item` of `host.rs` MUST preserve `updates.rs`,
   the `install_updates_bindings` call, both `HostState` cache fields,
   their tri-state enums, and their accessor methods
   (`ensure_updates_cache()`, `ensure_au_service()`).

Everything else — module names, function bodies, comments, doc
strings, `#[allow(...)]` decorations, `SAFETY:` annotations — is
byte-identical to upstream.

### Re-syncing a file after an upstream change

```powershell
# Diff a single file against upstream
git diff --no-index `
  C:\Users\Vin\source\repos\sdh\sdh-fleet\sdh-fleet-client\lua\src\host.rs `
  C:\Users\Vin\source\repos\Rust-Poc\rust-poc-lua\src\host.rs

# Overwrite a single file with upstream (safe for everything EXCEPT lib.rs)
Copy-Item -Force `
  C:\Users\Vin\source\repos\sdh\sdh-fleet\sdh-fleet-client\lua\src\host.rs `
  C:\Users\Vin\source\repos\Rust-Poc\rust-poc-lua\src\host.rs

# lib.rs needs hand-merging because of deviation #4 (the broken doc-link
# would come back). The other 9 files are all safe to overwrite.
```

After a re-sync: `cargo check -p rust-poc-lua` + `cargo clippy -p
rust-poc-lua` + `cargo run -- general.lua`.

### New Rust concepts surfaced by this crate

Things that don't appear elsewhere in the workspace and are worth
studying when the crate's source rolls past:

- **`async fn` + `tokio::task::spawn_blocking` + `tokio::time::timeout`**
  — `mlua::Lua` is `!Send`, so the VM has to live on a blocking thread.
  The wall-clock bound is enforced by wrapping the `JoinHandle` in
  `timeout`. (Tokio docs, Book §16 on async.)
- **`Rc<RefCell<HostState>>`** in `host.rs` — every Lua binding closure
  needs a mutable handle to the same `HostState`. Shared ownership +
  interior mutability is the idiom. (Book §15.5.)
- **`#[cfg(windows)]`** at the module level in `lib.rs` — the real
  implementation only compiles on Windows; other targets get a stub
  with the same public surface. (Reference: conditional compilation.)
- **FFI to Win32** via the `windows` crate — `unsafe { ... }` blocks
  with `// SAFETY:` justifications in `registry.rs`, `net.rs`,
  `winver.rs`. (Book §19.1 on unsafe Rust.)
- **COM/WMI** via the `wmi` crate — `COMLibrary::new` initialises COM,
  `WMIConnection::raw_query` runs typed-via-serde queries against
  `root\cimv2`.
- **mlua public traits** — `IntoLua` / `FromLua` / `LuaSerdeExt::to_value`
  / `Function::call` / `lua.create_function`. Closures captured into
  bindings need `'static` lifetimes, hence the `Rc` clones.
- **Sandboxing Lua by global removal** — `lua.globals().set(name, Nil)`
  in `sandbox.rs`. Cheap, declarative, no `unsafe` needed.
- **Vendored C deps** — `mlua` feature `vendored` builds Lua 5.4 from
  C sources at compile time. First build is slow (~30s+); incremental
  builds are normal.
- **`fn` pointer as parameter** — `bind_hostname` in `host.rs` takes
  `f: fn() -> Result<String, String>`. A bare function pointer (`fn`)
  is cheaper than a trait object (`Box<dyn Fn>`) or a generic bound
  (`<F: Fn>`) when every call site passes a named free function with no
  captured state. The compiler can inline through it; no heap allocation.
- **Parameterised FFI** — `get_computer_name(format: COMPUTER_NAME_FORMAT)`
  in `hostname.rs` factors the two-call sizing pattern once; three
  one-liner wrappers delegate to it. This keeps the `unsafe` surface
  to a single site, reducing audit scope. `COMPUTER_NAME_FORMAT` is a
  Rust newtype in `windows-rs`, not a raw `u32` — the compiler rejects
  passing an untyped integer, encoding the invariant at the type level.
- **`BTreeMap` vs `IndexMap`** — `serde_json::Map` defaults to `BTreeMap`
  (alphabetical key order, O(log n) lookup). The `preserve_order` feature
  would switch it to `IndexMap` (insertion order, O(1) hash lookup), but
  this only helps when the producer also controls key order — which Lua
  5.4 hash tables do not guarantee for large tables. Alphabetical is
  chosen deliberately here. (See also: `indexmap` crate.)

### Known stubs left intentionally incomplete

- `ad::current_user_mail_blocking` — always returns `None` even on
  domain-joined machines. Phase 2 in upstream too. Real impl needs
  `IADs::Get("mail")` via `windows::Win32::System::Ole`.
- `eventlog::install_info().history` — always `[]`. Real impl needs
  `EvtQuery` + `EvtRender` to parse the Setup event log.

Both stubs are documented in their source files. They surface as `null`
or `[]` in the JSON output, never as errors.

## Installer (Inno Setup)

The Windows installer lives in `Setup/` and is modelled on
[`sdh-complianceapp/Setup/`](../../sdh-complianceapp/Setup/) (~5x smaller
because Rust-Poc has no service, no perimeter wizard, no legacy MSI
bridge, no JSON patching). See [`Setup/README.md`](Setup/README.md) for
the full design notes.

### Files involved

| Path | Role |
|---|---|
| `Setup/CollectConfigSetup.iss` | Inno Setup script — `[Setup]`, `[Files]`, `[Registry]`, `[Dirs]`, `[Icons]`, `[InstallDelete]`, `[UninstallDelete]`. Pinned `MyAppId` GUID. |
| `Setup/Output/` | Generated `CollectConfigSetup-<Version>.exe`. Gitignored. |
| `publish-innosetup.ps1` | Orchestrator: `cargo build --release` → stage to `./publish/` → sign binary (pass #1) → ISCC → sign EXE + uninstaller (pass #2) → `Get-AuthenticodeSignature` sanity check. |
| `publish/` | Staging folder (Rust analogue of `dotnet publish`). Gitignored. |

### Critical invariants (do not regress)

- **`MyAppId = {848231EB-C945-463F-9DEC-E90E12B4781D}` is frozen forever.**
  Once an installer ships with this GUID, changing it breaks the
  Inno-to-Inno upgrade chain (new install creates a parallel ARP entry
  instead of upgrading). NEVER reuse the compliance app's
  `{CA9A7A52-9076-42BB-95F0-FD2B3A374210}` or any other shipped GUID.
- **Two-pass signing.** Sign `publish\collect-config.exe` BEFORE ISCC
  embeds it in the LZMA payload (pass #1, via `Invoke-SignFile`), then
  let ISCC sign the final EXE + embedded uninstaller (pass #2, via the
  `/Ssdh=<wrapper.cmd> $f` mechanism). Skipping pass #1 ships an
  unsigned binary inside a signed installer — passes SmartScreen on
  install but trips AppLocker / WDAC at first launch.
- **Signing wrapper is a `.cmd` file, NOT `/Ssdh="signtool sign ..."`
  directly.** PowerShell 5.1's native arg quoting is broken when an
  arg contains both spaces and embedded double quotes. The `.cmd`
  wrapper takes `$f` as `%1` and re-quotes in batch rules. See the
  inline comment in `publish-innosetup.ps1` for the full rationale.
- **`#ifdef SIGN` gates BOTH `SignTool=sdh` and `SignedUninstaller=yes`
  in the `.iss`.** Without the gate, an unsigned compile (passing
  `-SkipSign`) would fail with "SignTool 'sdh' not defined" because
  ISCC strictly requires that any `SignTool=<name>` reference be
  matched by a `/S<name>=...` command-line definition. The wrapper
  conditionally passes `/DSIGN=1`.
- **`HKLM\...\Environment\RUST_POC_LOG_DIR = C:\SMSLogs`** is set by
  `[Registry]` to override the default `<exe-dir>\logs` fallback
  (which would need admin write for every log line under Program
  Files). Coordinated with `LOG_DIR_ENV_VAR` in `src/logging.rs`
  (priority #1).
- **`C:\SMSLogs` is `uninsneveruninstall`.** Shared folder with other
  Sanofi tools; do not nuke it on uninstall.

### When to extend

The single `.iss` stays in `Setup/` as long as it remains readable
(~150 lines today). Split into `Setup/Scripts/*.iss` modules à la
compliance app when:

- A Pascal `[Code]` block emerges (scheduled task creator, ARP rename
  per perimeter, custom wizard page).
- The `.iss` crosses ~250 lines.
- A bridge to a previous installer format is needed (currently N/A).

Each module gets `#include "Scripts\<Module>.iss"` from
`[Code]` in the main `.iss`. Forward-declare any function called from
the main script — Pascal scoping does not see ahead.

## Code quality

The workspace inherits the same lint policy as `sdh-fleet-client`:

- `clippy::pedantic` at `warn` level
- `clippy::unwrap_used` at `warn`
- `clippy::expect_used` at `warn`
- The gate is `cargo clippy -- -D warnings` → zero warnings

Rules derived from the lints:

- **No `unwrap()` or `expect()` in production code paths.** Use `?`
  and `Result<T, E>`. When `expect` is genuinely justified
  (infallible-by-construction, unrecoverable startup), add
  `#[allow(clippy::expect_used)]` directly on the call with a comment
  explaining the invariant.
- **No `panic!()`** in library code. `unreachable!()` is acceptable
  for states the type system can't yet rule out, but prefer encoding
  the impossibility in the types when feasible.
- **Tests live inline** in each module under `#[cfg(test)] mod tests`,
  one block per file. A parallel `tests/` directory is reserved for
  integration tests that exercise multiple crates together — none
  exist yet.
- **Doc-tests are welcome.** Examples in `///` blocks compile and run
  under `cargo test`; they double as a free correctness gate for the
  public API.
- **Public APIs must have a doc comment** (`///`) explaining intent
  and at least one `# Examples` section once the API stabilises.

## Conventions

- **Module visibility**: prefer `pub(crate)` over `pub` unless the
  item is genuinely part of the crate's public surface. Every `pub` is
  a commitment that breaks downstream code if changed.
- **Constructors**: name them `new` if there is only one; name them
  descriptively (`from_str`, `with_capacity`, `from_iter`) when the
  caller needs to pick between several.
- **String types**: take `impl Into<String>` in constructors that
  store the value; take `&str` for read-only parameters; return owned
  `String` only when the function genuinely produces a new one.
- **Derives**: `Debug, Clone, Copy, PartialEq, Eq, Hash` in that
  canonical order on the same line. Serde derives go on their own
  line below.
- **Imports**: grouped as std → external crates → workspace crates →
  same-crate, separated by blank lines. `rustfmt` does NOT enforce
  this — keep it manual.
- **`#[must_use]`** on any constructor or pure function whose returned
  value is the entire point of calling it.

## Critical thinking

The owner explicitly wants AI agents to act as senior dev partners,
not yes-machines. For any non-trivial suggestion:

1. **Challenge the assumption** behind the request when one is in play.
2. **Offer a counter-argument** when the proposed direction has a
   recognised downside.
3. **Stress-test against edge cases** — `Option::None`, empty input,
   integer overflow, surrogate pairs in UTF-8, concurrent access.
4. **Suggest alternatives** when a modern Rust idiom applies.
5. **Prioritise truth over agreement.** If the request leads to a bad
   design, say so and explain why before implementing.

Example: if the owner asks "just add `unwrap()` here to make the test
pass", the right response is to explain why `unwrap` is a smell, show
the `Result`-propagating alternative, and only fall back to an
explicit `#[allow(clippy::unwrap_used)]` if the owner confirms after
seeing the alternative.

## Engineering practices

- **Run locally before committing.** Always run `cargo test` and
  `cargo clippy -- -D warnings` before staging changes. This is the
  same discipline as `sdh-fleet-client` (see its own CLAUDE.md).
- **Never commit unless explicitly asked.** Commits are free to author
  locally; the owner decides when to actually run `git commit`. The
  same applies to `git push` once a remote is configured.
- **Commit messages**: one-line subject in imperative mood ("Add
  network-share collector"), optional blank line + body explaining
  the *why*, not the *what*. Match the style of
  `sdh-fleet/sdh-fleet-client` commit history.
- **Branch policy**: `main` is the default. Feature branches are
  optional for this learning repo.
- **Preserve prior fixes when editing existing sections.** Before
  rewriting a block in `CLAUDE.md`, the root `Cargo.toml`, or the
  Commands section, read the section fully and preserve `Note:`
  paragraphs, the `default-run` key, `required-features` clauses,
  feature-gate comments, and inline `FIXME(...)` annotations. The
  `cargo run` note and `default-run` have each been silently
  regressed once already (commits `6add5f1` and a later CLAUDE.md
  rewrite). If you delete an existing comment block, justify it in
  the commit message; otherwise restore it.

## Language

Code, comments, commit messages, doc strings, file names: **English**.
Chat conversations between the owner and any AI agent: **French**.

This matches the owner's global Cursor rule and the `language-
conventions.mdc` rule from the parent workspace.

## When the owner asks "why does this not compile?"

The single most common interaction with this repo will be the owner
hitting a borrow-checker, lifetime, or trait-bound error. The
appropriate response shape is:

1. **State what the compiler is telling you** in plain language (the
   diagnostic itself is good but jargon-heavy).
2. **Explain the underlying rule** that the compiler is enforcing
   (move semantics, exclusive vs shared borrow, lifetime extension,
   orphan rule, etc.).
3. **Show the smallest fix** that respects the rule rather than
   side-steps it (`.clone()` everywhere is rarely the right answer).
4. **Point at the relevant Book chapter** for the owner's follow-up
   reading.

Do not just paste a working version. The point is for the owner to
internalise the rule, not to copy your patch.
