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
| **`rust-poc-lua`** (`rust-poc-lua/`) | In-process Lua 5.4 collector runtime + 82 `host.*` bindings (WMI, registry, networking, ADSI, hostname variants, WTS, NT kernel, WNF, GPO, TLS, regional, accounts, software, system updates, BitLocker, Credential Guard, Event Log, Cloud/AzureAD+MDM, EP/AV, firewall, WFP, LAPS, SentinelOne EDR, CyberArk EPM). Windows-only real impl + cross-target stub. | `sdh-fleet-client/lua/` (verbatim port, see [Lua collector runtime](#lua-collector-runtime)) |
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
├── lib.rs              # Public API + non-Windows stub
├── runtime.rs          # InternalRuntime::run — async, tokio::spawn_blocking + timeout
├── sandbox.rs          # Strips io/dofile/require/etc. globals
├── host.rs             # 64 `host.*` bindings + HostState (Rc<RefCell<..>>)
├── wmi.rs              # COMLibrary + per-namespace cache (root\cimv2, root\ccm, FVE, DeviceGuard)
├── registry.rs         # RegOpenKeyExW + RegQueryValueExW + RegEnumValueW + REG_* decode (incl. binary) + as_string scalar coercion (shared by laps + cyberark)
├── net.rs              # GetAdaptersAddresses + IPv4 enumeration
├── hostname.rs         # GetComputerNameExW — 3 variants (deviation #6, not in upstream)
├── adcomputer.rs       # GetComputerObjectNameW + DsGetSiteNameW + GetUserNameExW — 5 AD attrs (deviation #7, not in upstream)
├── winver.rs           # RtlGetVersion + GetFirmwareType
├── setup_history.rs    # OS setup history + install date — deviation #16, renamed from upstream `eventlog.rs` (which never touched the Event Log API), enriched with `MigrationScope` upgrade-chain walk
├── updates.rs          # WUA COM bindings (IUpdateSession3, ISystemInformation, …) + WMI Root\ccm — deviations #26–#31
├── evt.rs              # EvtQuery + EvtNext + EvtRender wrapper — deviation #10, not in upstream
├── bitlocker.rs        # Win32_EncryptableVolume + ExecMethod + recovery-key events — deviation #10/#32-#37, not in upstream
├── credentialguard.rs  # Win32_DeviceGuard + derived booleans — deviation #10/#38, not in upstream
├── cloud.rs            # NetGetAadJoinInformation + WMI root\CIMV2\mdm + cert store + event 208/209 — deviation #39, not in upstream
├── ep.rs               # ROOT\SecurityCenter2\AntiVirusProduct + ProductState decode + ROOT\Microsoft\Windows\Defender\MSFT_MpComputerStatus — deviation #40, not in upstream
├── firewall.rs         # ROOT\SecurityCenter2\FirewallProduct + root\StandardCimv2 MSFT_NetFirewallProfile/NetConnectionProfile + COM HNetCfg.FwProducts (INetFwProduct2) — deviation #42, not in upstream
├── wfp_known_guids.rs  # OnceLock<HashMap<GUID,&str>> for 110+ layer, 17+ sublayer, ~100 condition-field GUIDs — deviation #43
├── wfp_conditions.rs   # FWP_CONDITION_VALUE0 parser → WfpCondition; conditions_json() + format_compact() — deviation #43
├── wfp.rs              # WfpEngine RAII, WfpMemoryGuard RAII, enumerate_wfp_state() (6 Win32 enums), wfp_net_events() — deviation #43
├── wfp_pipeline.rs     # Port of WfpFilterPipeline.cs — ALE filter, shadowing, dedup, wfp_sublayer_details(), wfp_firewall_view() — deviation #43
├── laps.rs             # Windows/Legacy LAPS posture — registry policy cascade + System32 DLL probes; laps_state() — deviation #44, not in upstream
├── sentinelone.rs      # SentinelOne EDR — COM IDispatch late-binding (SentinelHelper.GetAgentStatusJSON) + Program Files exe search + Operational #104 CommSdk event — deviation #45, not in upstream
├── cyberark.rs         # CyberArk EPM (legacy Viewfinity) — vfpd kernel driver status (SC Manager) + HKLM\SOFTWARE\Viewfinity\Agent registry reads — deviation #46, not in upstream
└── ad.rs               # ADSI mail lookup stub (phase 2 in upstream)
```

### The 82 `host.*` bindings exposed to Lua

| Binding | Backend | Surface |
|---|---|---|
| `host.env(name)` | `std::env::var` + injected `SDH_HOSTNAME` / `SDH_CLIENT_VERSION` / `SDH_PERIMETER` | `string?` |
| `host.now_iso8601()` | `setup_history::install_info()["install_date"]` | `string?` |
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
| `host.setup_history()` **(deviation #16)** | `setup_history::install_info` — registry walk over `HKLM\SYSTEM\Setup\Source*` subkeys + `MigrationScope` chain resolution | `{install_date, history[]}` |
| `host.cpu_details()` | WMI `Win32_Processor.Name + SocketDesignation` | `string?` |
| `host.ram_total()` | WMI `Win32_PhysicalMemory.Capacity` (summed) | `number?` |
| `host.disk_size(target, property)` | WMI `Win32_LogicalDisk` filtered by `%SystemDrive%` | `number?` |
| `host.motherboard_details()` | WMI `Win32_ComputerSystem.Model + SystemFamily` | `string?` |
| `host.bios_details()` | WMI `Win32_BIOS.BIOSVersion` + `winver::firmware_type` | `string?` |
| `host.desktop_resolution()` | WMI `Win32_VideoController.{Current*Resolution, RefreshRate}` | `string?` |
| `host.chassis_type()` **(deviation #8)** | WMI `Win32_SystemEnclosure.ChassisTypes[0]` → SMBIOS code + label | `{code: number, label: string}?` |
| `host.virtual_machine()` **(deviation #8)** | CPUID leaf 1 ECX bit 31 (`std::arch::x86_64::__cpuid`) | `bool` |
| `host.virtualization_capability()` **(deviation #8)** | `(Win32_Processor.VMMonitorModeExtensions && Win32_Processor.VirtualizationFirmwareEnabled) || Win32_ComputerSystem.HypervisorPresent`; mirrors `Virtualization.cs`. Distinct from `virtual_machine()` — answers "can this host virtualize?" not "am I a VM?" | `bool?` |
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
| `host.updates_windows_updates()` **(deviation #30)** | WUA COM `IUpdateSession3` → `IUpdateSearcher3` offline search (`"IsInstalled=1 OR IsInstalled=0"`); mirrors `UpdatesWindowsUpdates.cs`; no 90 s timeout thread; sole consumer of `HostState::updates_cache` since the #31 refactor | `array<{title, article_ids, category, update_id, …20 fields}>?` |
| `host.updates_sccm_updates()` **(deviation #31)** | 4-source merge faithful to `Updates.cs::GetSccmUpdates`: WMI `Root\ccm\SoftwareUpdates\UpdatesStore::CCM_UpdateStatus` (pivot) + `…\DeploymentAgent::CCM_TargetedUpdateEx1` (substring lookup on `UpdateId`) + `Root\ccm\StateMsg::CCM_StateMsg` (filtered `TopicType=="500"`, substring lookup on `TopicID`) + WUA online `IUpdateSearcher::QueryHistory(0, total)` (install date + `ResultCode==orcSucceeded`); DTO is strict 1:1 with `SccmUpdate.cs` (9 fields). Returns `[]` when SCCM absent (`WBEM_E_INVALID_NAMESPACE` on `UpdatesStore`); WUA history failure (3 retries) degrades to empty history with `install_date=null` | `array<{article_id, category, install_date, installed, required, superseded, targeted, title, update_id}>` |
| `host.bitlocker_volume_status(mount_point)` **(deviation #33)** | WMI `Win32_EncryptableVolume WHERE DriveLetter='<mp>'` in `root\CIMV2\Security\MicrosoftVolumeEncryption` + `ExecMethod("GetConversionStatus", PrecisionFactor=1)`; mirrors `BitlockerStatus.cs` + `BitLockerEncryptionPercentage.cs` | `{drive_letter, encryption_method, protection_status, conversion_status, encryption_percentage, encryption_flags, wiping_status, wiping_percentage}?` |
| `host.bitlocker_key_protector_ids(mount_point, type)` **(deviation #34)** | WMI `ExecMethod("GetKeyProtectors", KeyProtectorType=<type>)`; types per `KeyProtectorType` enum (3=NumericPassword, 7=PublicKey/DRA); IDs lowercased to match escrow casing | `array<string>?` |
| `host.bitlocker_dra_thumbprints(mount_point)` **(deviation #35)** | `GetKeyProtectors(7)` + per-ID `ExecMethod("GetKeyProtectorCertificate")` → `CertThumbprint`; mirrors `BitLockerDRACertThumbPrints.cs` | `array<string>?` |
| `host.bitlocker_policy()` **(deviation #36)** | Registry `HKLM\SOFTWARE\Policies\Microsoft\FVE` value-name enumeration against 8 enforcement names (`EncryptionMethodWithXtsOs`, `UseTPM`, …); mirrors `BitLockerPolicy.cs` / `DataService.GetFVEStatus` | `"Enabled" \| "MissingRegistryKey" \| nil` |
| `host.bitlocker_escrowed_protector_ids(event_id)` **(deviation #37a)** | `EvtQuery + EvtRender` on `Microsoft-Windows-BitLocker/BitLocker Management` for `event_id` (783=AD, 845=AzureAD); lowercased `ProtectorGUID` values; mirrors `BitLockerService.EscrowedRecoveryKeyProtectorIdsFromEvents` | `array<string>?` |
| `host.bitlocker_recovery_key_rotation_executed()` **(deviation #37b)** | Registry `ShutdownTime` (FILETIME) + events 864 (rotation) and 775 (key event, `ProtectorType=0x3`); three-state: `true`=rotation completed, `false`=in progress, `nil`=never rotated. Mirrors `BitLockerService.RecoveryKeyRotationFromEventsExecuted` | `bool?` |
| `host.credential_guard_status()` **(deviation #38)** | WMI `Win32_DeviceGuard` in `root\Microsoft\Windows\DeviceGuard`; full 13-field row + two derived booleans (`is_credential_guard_configured`, `is_credential_guard_running`) computed in Rust mirroring `CredentialGuardStatus.Create` from `ComplianceApp.Shared` | `{...13 fields + 2 derived booleans}?` |
| `host.azure_ad_joined_status()` **(deviation #39)** | `NetGetAadJoinInformation(NULL)` → `joinType` check + `validate_cert_context(pJoinCertificate)`; strictly better than C# registry+cert approach (cert embedded in struct, no secondary store lookup); mirrors `AzureAdJoinedStatus.cs` | `"On" \| "Off" \| "CertificateIsNotValid" \| nil` |
| `host.azure_ad_device_id()` **(deviation #39)** | Same `NetGetAadJoinInformation` call → `pszDeviceId` (GUID string, no Subject-strip needed); mirrors `AzureAdDeviceId.cs` | `string?` |
| `host.mdm_status()` **(deviation #39)** | WMI `root\CIMV2\mdm::MDM_MgmtAuthority.ProvisionedCertThumbprint` → `cert_in_lm_my` → `validate_cert_context`; `WBEM_E_INVALID_NAMESPACE` → `"Off"`; mirrors `MdmStatus.cs` | `"On" \| "Off" \| "CertificateIsNotValid" \| nil` |
| `host.mdm_device_id()` **(deviation #39)** | Same WMI thumbprint → `CertGetNameStringW(CERT_NAME_SIMPLE_DISPLAY_TYPE)` → strip `"CN="`; mirrors `MdmDeviceId.cs` | `string?` |
| `host.mdm_co_management_flags()` **(deviation #39)** | Registry `HKLM\SOFTWARE\Microsoft\DeviceManageabilityCSP\Provider\WMI_Bridge_Server\ConfigInfo` (DWORD → decimal string); `None` when key absent; mirrors `MdmCoManagementFlags.cs` | `string?` |
| `host.mdm_sync_status()` **(deviation #39)** | EventID 208 (start; `Message1`=enrollment ID) × EventID 209 (end; `HRESULT`) paired by `(ProcessID, ThreadID)` from `<Execution …/>`, filtered on `CurrentEnrollmentId` registry value; mirrors `LastMdmSync{Date,Result,SuccessDate}.cs` | `{last_sync_date?, last_success_sync_date?, last_sync_result?}?` |
| `host.security_center_av_products()` **(deviation #40)** | WMI `ROOT\SecurityCenter2\AntiVirusProduct` `SELECT *`; decodes `ProductState` bitmask (status / signatures / owner) from `AntiVirusEnums.cs`; returns all products — Lua script filters by `name` (e.g. `"Sentinel Agent"` for SentinelOne); mirrors `SentinelOne.cs` + `AntiVirusEnums.cs` from ComplianceApp | `array<{name, state, signatures, owner, path?, product_state_raw}>` |
| `host.windows_defender_status()` **(deviation #40)** | WMI `ROOT\Microsoft\Windows\Defender\MSFT_MpComputerStatus` `SELECT *`; returns the single-row status object in WMI PascalCase (`AMServiceEnabled`, `AMRunningMode`, `AntivirusEnabled`, `RealTimeProtectionEnabled`, `ProductStatus`, …); `nil` when Defender absent / namespace unreachable; mirrors `WindowsDefender.cs::GetWindowsDefenderStatusFromCim()` | `{AMServiceEnabled, AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, ProductStatus, …}?` |
| `host.security_center_firewall_products()` **(deviation #42)** | WMI `ROOT\SecurityCenter2\FirewallProduct` `SELECT *`; decodes `ProductState` bitmask (status / owner) from `FirewallEnums.cs` (bit-for-bit copy of `AntiVirusEnums.cs`; no `SignatureStatus` nibble); ghost entries (empty `displayName`) dropped; mirrors `Firewall.cs::GetSecurityCenterFirewallProducts` | `array<{name, state, owner, path?, product_state_raw}>` |
| `host.windows_defender_firewall_status()` **(deviation #42)** | WMI `root\StandardCimv2` — `MSFT_NetConnectionProfile.NetworkCategory` → active profile name (`"Domain"\|"Private"\|"Public"`, fallback `"Public"` off-network); `MSFT_NetFirewallProfile.Enabled` per profile; mirrors `Firewall.cs::GetWindowsDefenderFirewallStatus` | `{current_profile, status, domain_state, private_state, public_state}?` |
| `host.net_fw_products()` **(deviation #42)** | COM `HNetCfg.FwProducts` (`CoCreateInstance(NetFwProducts)` → `INetFwProducts` → `INetFwProduct2`); 5-attempt retry; `RuleCategories` SAFEARRAY extracted from `VARIANT`; Lua derives per-category owners; mirrors `Firewall.cs::GetNetFwProducts` | `array<{name, path?, rule_categories: array<u32>}>` |
| `host.wfp_sublayer_details()` **(deviation #43)** | All WFP filters grouped by sublayer, sorted `sublayer_weight DESC` per group then `layer_name ASC / effective_weight DESC`; enriched with provider/layer/sublayer names; shares `WfpState` cache with #43 siblings; mirrors `WfpSubLayerDetails.cs` | `array<{sublayer_key, sublayer_name, total_filters, weight, wfp_filter_details[]}>` — fields named so that `sublayer_*` sorts before the large `wfp_filter_details` array under serde_json BTreeMap ordering |
| `host.wfp_firewall_view()` **(deviation #43)** | ALE-filtered + shadowed + deduplicated firewall view; three pipeline steps from `WfpFilterPipeline.cs`; compact Unicode-symbol condition strings; sorted by direction / sublayer weight / effective weight; mirrors `WfpFirewallView.cs` | `array<{order_id, direction, name, provider_name, layer_name_normalized, sublayer_name, action, has_clear_action_right, conditions, conditions_json, variant_details[]}>` |
| `host.wfp_net_events()` **(deviation #43)** | Up to 1 000 recent WFP net events via `FwpmNetEventEnum2` using an **ephemeral** engine; enriched from the shared `WfpState` cache (`filter_index`, `layer_id_index`); sorted timestamp DESC; `layerId < 200` heuristic omitted (intentional deviation); mirrors `WfpNetEvents.cs` | `array<{timestamp, direction, event_type, protocol_name, local_address, local_port, remote_address, remote_port, app_id, filter_id, filter_name, sublayer_name}>` |
| `host.laps_state()` **(deviation #44)** | Windows/Legacy LAPS posture in one stateless call: legacy AdmPwd CSE key existence + System32 `laps.dll`/`lapscsp.dll` probes + 4-key policy cascade (`BackupDirectory`/`AdmPwdEnabled` presence) + `PasswordAgeDays`; mirrors `Security.cs` LAPS transformers; `auto_laps_mode` emits `"Not Installed"` (not C#'s `"Unknown"`) when no LAPS detected | `{auto_laps_mode, windows_laps_dll_state, laps_policy, laps_backup_directory, legacy_gp_extension_present, max_pwd_age_days}` |
| `host.sentinel_one_agent_status()` **(deviation #45)** | COM **IDispatch late-binding** against the `SentinelHelper` ProgID (`CLSIDFromProgID` + `CoCreateInstance` + `GetIDsOfNames` + `Invoke` → `GetAgentStatusJSON`); deserializes the kebab-case JSON, re-emits snake_case; `nil` (silent) when ProgID unregistered; mirrors `SentinelOne.cs::GetSentinelOneAgentStatusFromJson` | `{active_threats_present, agent_id, agent_install_time, agent_ppl, agent_running, agent_version, detection_mode, enforcing_security, last_seen, management_url, reboot_reasons, self_protection_enabled, site}?` |
| `host.sentinel_one_paths()` **(deviation #45)** | `%ProgramFiles%[(x86)]\SentinelOne` discovery + bounded recursive search; returns **all** `SentinelCtl.exe` / `sentinelAgent.exe` matches (arrays, not C#'s `LastOrDefault`); mirrors `GetSentinelOneFindFolderPath`/`FindCtlPath`/`FindAgentPath` | `{folder: string?, ctl_paths: [string], agent_paths: [string]}` |
| `host.sentinel_one_comm_sdk()` **(deviation #45)** | Newest `SentinelOne/Operational` event #104 via `evt::query_events`; exposes `CommSdkMessage` + timestamp; `nil` on any Event Log failure (channel-absent = SentinelOne-not-installed); mirrors `GetSentinelOneCommSdkMessage(+Date)` | `{message: string?, date: string}?` |
| `host.cyber_ark_epm_driver_status()` **(deviation #46)** | `vfpd` kernel driver state via SC Manager (`OpenServiceW` + `QueryServiceStatus`, reusing `software::service_state_label`); `"None"` when the driver is absent (= C# `ServiceStatus.None`); real SCM failure → `nil` + `cyberark:driver_status`; mirrors `Security.cs::GetCyberArkEpmDriverStatus` | `"Running" \| "Stopped" \| ... \| "None" \| "Unknown"`? |
| `host.cyber_ark_epm_version()` **(deviation #46)** | `HKLM\SOFTWARE\Viewfinity\Agent` → `Version` (raw string passthrough, no `Version::parse`); mirrors `GetCyberArkEpmVersion` | `string?` |
| `host.cyber_ark_epm_id()` **(deviation #46)** | Same key → `SetID`; mirrors `GetCyberArkEpmId` | `string?` |
| `host.cyber_ark_epm_dispatcher_url()` **(deviation #46)** | Same key → `DispatcherURL`; mirrors `GetCyberArkEpmDispatcherUrl` | `string?` |
| `host.cyber_ark_epm_registered_at()` **(deviation #46)** | Same key → `RegisteredAt` (raw string, never date-parsed, = C#); mirrors `GetCyberArkEpmRegisteredAt` | `string?` |
| `host.cyber_ark_epm_last_policy_update()` **(deviation #46)** | Same key → `LastPolicyUpdateTime` (`REG_QWORD` FILETIME) → `winver::filetime_to_iso8601` (UTC Zulu); mirrors `GetCyberArkEpmLastPolicyUpdate` | `string?` |
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

# Pipe-friendly: JSON goes to stdout WHEN stdout is not a TTY
# (i.e. piped or redirected). Interactive terminals get a silent
# stdout; the per-run audit file under <log_dir> is the canonical
# artefact in that case — its path is announced on stderr via the
# tracing `info!` line "wrote JSON output file".
cargo run --quiet > config.json                # stdout is a file → JSON written
cargo run --quiet | jq '.machine_name'         # stdout is a pipe → JSON written
cargo run -- general.lua                       # stdout is a TTY  → silent stdout
```

The binary lives at `src/main.rs` and is produced as
`target/debug/collect-config.exe`. It installs the tracing subscriber,
validates the script path via `resolve_script_path` (canonicalise +
`starts_with` to refuse traversal), constructs an `InternalRuntime`,
calls `runtime.run(...)` with a 30s wall-clock timeout, and pretty-
prints the returned JSON. Logs and progress go to stderr; the JSON
goes to stdout only when stdout is not a terminal (TTY detection via
[`std::io::IsTerminal`], stable since Rust 1.70).

Exit codes: `0` success, `1` Lua runtime error (script error or
timeout), `2` cannot read hostname, `3` cannot serialize output, `4`
script path escapes the `collectors/` directory (path traversal
rejected by `resolve_script_path`).

### Deviations from a strict verbatim copy

There are exactly **eighteen** points where copying upstream byte-for-byte
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

8. **`rust-poc-lua/src/host.rs` — three hardware enrichment bindings.**
   Not in upstream. Added as composite bindings inside
   `install_composites()`:
   - `host.chassis_type()` — reads `Win32_SystemEnclosure.ChassisTypes[0]`
     (SMBIOS Type-3 code) and translates it to a human-readable label
     via the `chassis_type_str()` match table (codes 1–36, SMBIOS 3.x
     spec §7.4). Returns `nil` on WMI failure.
   - `host.virtual_machine()` — answers "am I running INSIDE a VM?".
     Primary signal: WMI `Win32_ComputerSystem.Model` against a small
     allow-list (`"Virtual Machine"`, `"VMware"`, `"VirtualBox"`,
     `"QEMU"`). Fallback: CPUID leaf 1 ECX bit 31 (hypervisor-present)
     plus the vendor leaf at `0x40000000` to filter out `"Microsoft Hv"`
     (which Windows reports on bare metal whenever VBS is active).
     Returns `false` on any non-x86_64 target. Requires no COM
     initialisation when the fallback fires.
   - `host.virtualization_capability()` — answers a different question:
     "CAN this host virtualize (or is it already doing so)?".  Faithful
     port of `ComplianceApp/DataTransformers/BIOS/Virtualization.cs`:
     `(Win32_Processor.VMMonitorModeExtensions
       && Win32_Processor.VirtualizationFirmwareEnabled)
      || Win32_ComputerSystem.HypervisorPresent`.
     Missing WMI properties degrade to `false` per the C# nullable-state
     semantics (`null_enum == specific_state` is always false).  Returns
     `nil` only on a hard WMI failure (COM init / namespace unreachable),
     in which case the failure is also surfaced via `host.errors()`.
     The pure formula (`compute_virtualization_capability`) is extracted
     to enable truth-table unit testing without a live WMI stack.
   **Why both `virtual_machine` and `virtualization_capability`?** They
   answer two orthogonal questions that the `Win10-Laptop.json` schema
   exposes as separate fields:
   - A physical laptop hosting Credential Guard answers `false` to
     `virtual_machine()` and `true` to `virtualization_capability()`.
   - A Hyper-V guest answers `true` to both.
   - An old BIOS-disabled bare-metal machine answers `false` to both.
   Re-sync impact: `Copy-Item` of `host.rs` MUST preserve
   `bind_chassis_type`, `bind_virtual_machine`,
   `bind_virtualization_capability`, the pure
   `compute_virtualization_capability` helper, `chassis_type_str`, the
   `#[cfg(test)] mod tests` block in `host.rs`, and the matching calls
   inside `install_composites`.

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
     provides isolation).  Sole consumer of `HostState::updates_cache`
     since the #31 refactor.
   - `host.updates_sccm_updates()` — déviation #31. **4-source merge
     faithful to `Updates.cs::GetSccmUpdates`**, replacing the older
     "WUA offline cache join" approach which suffered from massive
     `UpdateID` cache misses (only ~10% of CCM rows had a matching WUA
     entry).  Sources:
     - `Root\ccm\SoftwareUpdates\UpdatesStore::CCM_UpdateStatus` —
       primary pivot (`UniqueId`, `Article`, `Title`,
       `UpdateClassification`).
     - `Root\ccm\SoftwareUpdates\DeploymentAgent::CCM_TargetedUpdateEx1` —
       provides `Superseded`, joined via case-insensitive substring
       match of `UpdateId.Contains(uniqueId)`.
     - `Root\ccm\StateMsg::CCM_StateMsg` — filtered `TopicType=="500"`
       (Software Updates topics); provides `StateID` (3=installed,
       2=required), joined via substring match of
       `TopicID.Contains(uniqueId)`.
     - WUA online `IUpdateSearcher::QueryHistory(0, total)` — provides
       install `Date` (OLE DATE → ISO 8601 UTC) and
       `ResultCode==orcSucceeded`; 3-retry loop with 100/200/300 ms
       backoff (mirrors C# `MAX_RETRY_ATTEMPTS`). On final failure the
       merge continues with empty history (`install_date=null`).
     - **DTO is strict 1:1 with `SccmUpdate.cs`**: 9 snake-case fields
       (`article_id`, `category`, `install_date`, `installed`,
       `required`, `superseded`, `targeted`, `title`, `update_id`).
       The previous 11-field shape with `cve_ids` / `msrc_severity` /
       `reboot_required` was retired; those signals remain available
       per OS-level update through `host.updates_windows_updates()`.
     - Final filter: `WHERE Targeted == true`. Final sort:
       `install_date` nulls last, then DESC, then `article_id` ASC,
       then `title` ordinal, then `update_id` ordinal.
     - `UpdateClassification` GUID → human label uses a 13-entry
       mapping verbatim from `Updates.cs:453-468`
       ([WUA classification GUIDs reference](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ff357803(v=vs.85))).
     - The duplicate-`UniqueId` merge rules (`||` for booleans,
       max for `install_date`, `0→non-zero` for `article_id`, first-fill
       for nullable strings) mirror `Updates.cs:646-660` exactly.
     - Returns `[]` when SCCM absent (`WBEM_E_INVALID_NAMESPACE` on
       `Root\ccm\SoftwareUpdates\UpdatesStore`). Each secondary
       namespace tolerates its own `INVALID_NAMESPACE` independently
       and degrades to "no superseded info" / "no state info" rather
       than aborting.

   **Per-run caches on `HostState`** — two lazy-init fields mirror the
   existing `wmi: Option<Wmi>` pattern, both shaped as tri-state enums
   so init failures are memoised (no expensive retry) and surfaced
   under a single canonical error key:
   - `updates_cache: UpdatesCacheState` (`NotInit | Ready(UpdatesCache)
     | Failed`) — one offline WUA search builds the full update list
     consumed by #30. Before the #31 refactor this cache also held an
     `UpdateID → WuaMeta` index for the SCCM join; that index has been
     removed, the SCCM path is now source-independent. Init failures
     recorded once under `ERR_KEY_WUA_CACHE_INIT = "updates:wua_cache_init"`.
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

10. **`rust-poc-lua/src/bitlocker.rs` + `credentialguard.rs` + `evt.rs`
    + `install_hardening_bindings` in `host.rs` — seven hardening
    bindings.**
    Not in upstream. Implements the BitLocker + Credential Guard
    sub-trees of `Win10-Laptop.json` by mirroring `BitLockerService.cs`,
    `BitlockerStatus.cs`, `BitLockerEncryptionPercentage.cs`,
    `BitLockerPolicy.cs`, `BitLockerDRACertThumbPrints.cs`, the seven
    `DataTransformers/BitLocker/*.cs` files, and the `Bios.cs`
    Credential Guard helper. Requires features `Win32_System_EventLog`
    and `Win32_System_Registry` in `rust-poc-lua/Cargo.toml`.

    - `host.bitlocker_volume_status(mount_point)` — déviation #32. WMI
      `Win32_EncryptableVolume` in `root\CIMV2\Security\MicrosoftVolumeEncryption`
      + `ExecMethod("GetConversionStatus", PrecisionFactor=1)`. Returns
      `nil` on absent volume (e.g. running off a non-BitLocker drive).
      Encryption percentage and conversion status come from the same
      `ExecMethod` call — `Win32_EncryptableVolume` does **not** expose
      them as plain properties (the C# transformer does the same
      ExecMethod dance, see `BitLockerEncryptionPercentage.cs`).
    - `host.bitlocker_key_protector_ids(mount_point, type)` — déviation #33.
      WMI `ExecMethod("GetKeyProtectors", KeyProtectorType=<n>)`. IDs are
      lowercased to canonicalise against event-log payloads (which
      historically use lowercase GUIDs).
    - `host.bitlocker_dra_thumbprints(mount_point)` — déviation #34.
      Composes #33 with type=7 + per-ID
      `ExecMethod("GetKeyProtectorCertificate")` → `CertThumbprint`.
    - `host.bitlocker_policy()` — déviation #35. Registry value-name
      enumeration over `HKLM\SOFTWARE\Policies\Microsoft\FVE` against
      an 8-entry whitelist; returns `"Enabled"` if any present,
      `"MissingRegistryKey"` otherwise.
    - `host.bitlocker_escrowed_protector_ids(event_id)` — déviation #36.
      `EvtQuery + EvtRender` on `Microsoft-Windows-BitLocker/BitLocker Management`
      for a given event ID (783=AD backup, 845=Azure AD backup).
    - `host.bitlocker_recovery_key_rotation_executed()` — déviation #37.
      Three-state: registry `ShutdownTime` (FILETIME) → boot time →
      event 864 (rotation since boot) + event 775 (`ProtectorType=0x3`
      near rotation time). Returns `true`=rotation completed since
      boot, `false`=rotation in progress (864 fired but no matching
      775), `nil`=never rotated.
    - `host.credential_guard_status()` — déviation #38. WMI
      `Win32_DeviceGuard` in `root\Microsoft\Windows\DeviceGuard` →
      13 fields verbatim + two derived booleans
      (`is_credential_guard_configured`, `is_credential_guard_running`)
      computed in Rust to mirror `CredentialGuardStatus.Create` in
      `ComplianceApp.Shared`.

    **Cross-cutting extensions to existing modules:**
    - `wmi.rs` — single-namespace cache replaced by per-namespace cache
      (`HashMap<namespace, (WMIConnection, HashMap<class, Vec<Row>>)>`).
      Backwards-compatible — `query_first` / `query_all` keep
      `root\cimv2` default. New methods `query_first_ns`,
      `query_all_ns`, `query_filtered_first_ns`, plus a connection
      accessor that lets callers invoke `exec_instance_method`
      directly (the `wmi` crate 0.17 exposes ExecMethod without raw
      COM).
    - `registry.rs` — new `enum_value_names(hive, key)` via
      `RegEnumValueW` + new `read_binary(hive, key, value)` for the
      `ShutdownTime` FILETIME read.
    - `evt.rs` — new module wrapping `EvtQuery + EvtNext + EvtRender`.
      Uses the **XML rendering path** (`EvtRenderEventXml`) plus an
      ad-hoc string scanner for `<TimeCreated SystemTime='…'>` and
      `<Data Name='X'>Y</Data>`. The alternative
      `EvtCreateRenderContext + EvtRenderEventValues` is faster but
      requires pre-declaring every value path; for the < 100 events a
      machine emits on the BitLocker channel, the XML path is plenty
      fast and stays generic over future schema drift. XPath template:
      `*[System[Provider[@Name='X'] and (EventID=N) and TimeCreated[@SystemTime>='ISO']]]`
      — the `Provider[@Name]` predicate is the same shape PowerShell
      builds for `Get-WinEvent -FilterHashtable @{ProviderName='X'; Id=N}`
      (functionally a no-op on dedicated channels like BitLocker
      Management, but useful template for shared channels).

      **PITFALL — `EvtRender` emits single-quoted attribute values**
      (`Name='X'`), not double-quoted, on Windows 10+. PowerShell's
      `EventLogRecord.ToXml()` returns the same XML bytes. Any custom
      XML scanner MUST accept both `'` and `"` delimiters (XML 1.0
      §3.1). The original scanner only handled `"` and silently
      dropped every BitLocker `<Data>` payload on the floor —
      `bitlocker_escrowed_protector_ids` returned empty arrays even
      when events existed. See the regression tests
      `evt::tests::*_single_quoted_real_bitlocker` which pin the
      exact byte-for-byte XML returned on a domain-joined endpoint.
      A second latent bug surfaced during the same fix —
      `<Data Name='X'/>` self-closing form stealing the next entry's
      content — also pinned via
      `evt::tests::self_closing_data_does_not_steal_next_value`.

    Re-sync impact: `Copy-Item` of `host.rs` MUST preserve
    `install_hardening_bindings` and its call from `install_all()`,
    plus `bitlocker.rs`, `credentialguard.rs`, `evt.rs`, the
    per-namespace cache in `wmi.rs`, `enum_value_names` /
    `read_binary` in `registry.rs`, and the `Win32_System_EventLog`
    feature in `Cargo.toml`.

11. **`rust-poc-lua/src/setup_history.rs` (renamed from `eventlog.rs`)
    + `registry::subkey_names` / `try_subkey_names` extension.**
    Three related changes that together form deviation #16:

    - **(a) Module rename.** Upstream ships
      `sdh-fleet-client/lua/src/eventlog.rs`, a name chosen in
      anticipation of a phase-2 implementation that would parse the
      Setup event log via `EvtQuery` + `EvtRender`. That phase never
      landed upstream — `eventlog.rs` only ever read the registry —
      and in this PoC the real Event Log wrapper now lives in
      `evt.rs` (deviation #10). Coexisting `eventlog.rs` and `evt.rs`
      made the module names actively misleading, so `eventlog.rs` is
      renamed to `setup_history.rs` to match what the module actually
      does (mirror of `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
      + `HKLM\SYSTEM\Setup\Source*` subkeys).
    - **(b) Enriched body.** The upstream `install_info()` is a one-
      shot read of the `InstallDate` DWORD plus a stubbed empty
      `history` array. The rust-poc-lua version walks the
      `Source OS (Updated on …)` subkeys, sorts by `InstallDate`
      ascending, and derives the canonical install date through a
      `MigrationScope` chain-resolution algorithm (see the
      module-level doc + the `derive_install_date` doc + the
      `#[cfg(test)] mod tests` block with five truth-table cases).
      Empirical convention: `MigrationScope == "5"` marks an entry
      that has been overwritten by a later in-place upgrade; `""`
      (or absent) marks the live or chain-terminating entry. Pinned
      against a 23H2 → 24H2 upgrade observed on the workspace
      owner's machine.
    - **(c) `registry.rs` extension.** The walk requires
      `RegEnumKeyExW`, which upstream's `registry.rs` does not expose
      (it only has `RegQueryValueExW` + `RegEnumValueW`). Two new
      functions are added: `subkey_names(hive, key) -> Vec<String>`
      (returns `[]` on any error — convenient for the registry-walk
      callsite) and `try_subkey_names(hive, key) -> Result<Vec<String>,
      String>` (distinguishes "key absent" from "permission denied"
      for the unit tests). Same shape as the `try_*` / non-`try_*`
      pair pattern used elsewhere in `registry.rs`.

    Re-sync impact: `Copy-Item` of `eventlog.rs` from upstream would
    **silently regress** the `MigrationScope` chain-resolution logic
    (and break compilation — the file no longer exists under that
    name). Before any future re-sync, decide whether to (i)
    upstream the rename + enrichment, or (ii) preserve
    `setup_history.rs` locally and skip the `eventlog.rs` Copy-Item
    step. `Copy-Item` of `registry.rs` from upstream MUST preserve
    `subkey_names` / `try_subkey_names` and the imports
    (`RegEnumKeyExW`) they pull in, alongside the already-documented
    `enum_value_names` / `read_binary` (deviation #10).

12. **`rust-poc-lua/src/cloud.rs` + `install_cloud_bindings` in
    `host.rs` + `evt.rs` extension — six Cloud category bindings.**
    Not in upstream. Implements the Cloud sub-tree of `Win10-Laptop.json`
    (AzureAD join status and MDM/Intune enrollment). Deviation #39.

    - `host.azure_ad_joined_status()` + `host.azure_ad_device_id()` —
      Use `NetGetAadJoinInformation` (`netapi32.dll`) instead of the
      C# approach (registry subkeys + separate cert-store lookup).
      This is strictly better: `DSREG_JOIN_INFO.pJoinCertificate`
      delivers the cert directly so no `CertOpenStore` call is needed
      for AzureAD, and `pszDeviceId` is the raw GUID string so no
      `Subject.Replace("CN=", "")` parsing is needed. `joinType` is
      `DSREG_DEVICE_JOIN` (1) or `DSREG_WORKPLACE_JOIN` (2); anything
      else maps to `"Off"`. `NetFreeAadJoinInformation` is called in
      all paths via an RAII guard (`AadInfoGuard`).
    - `host.mdm_status()` + `host.mdm_device_id()` — WMI
      `root\CIMV2\mdm::MDM_MgmtAuthority.ProvisionedCertThumbprint`
      → `cert_in_lm_my` → `CertFindCertificateInStore(CERT_FIND_SHA1_HASH)`.
      `IsDeviceRegisteredWithManagement` (MDMRegistration.h) was
      evaluated but rejected: it returns a `bool` only, cannot
      distinguish `"On"` from `"CertificateIsNotValid"`.
      `CertOpenStore` uses `CERT_STORE_PROV_SYSTEM` + the
      `CERT_SYSTEM_STORE_LOCAL_MACHINE` flag — NOT `CertOpenSystemStoreW`
      (which opens the Current User store). Thumbprint is hex-decoded
      to a 20-byte SHA-1 hash blob.
    - `host.mdm_co_management_flags()` — Registry DWORD; infallible
      (absent key → `None`).
    - `host.mdm_sync_status()` — EventID 208 (sync start; `Message1`
      = enrollment ID; `ProcessID` + `ThreadID` from `<Execution …/>`)
      paired with EventID 209 (sync end; `HRESULT`) across both MDM
      channels. Pairing key is `(ProcessID, ThreadID)` read from
      `EventRecord::system_attrs` and parsed to `u32` inside
      `mdm_sync_status`. Filtered on
      `HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Logger::CurrentEnrollmentId`.
      Returns the most recent pair plus the most recent successful pair
      (HRESULT top bit clear).

    **Deviation #12a — `evt.rs` generic `system_attrs`:** `EventRecord`
    exposes a flat `system_attrs: HashMap<String, String>` that collects
    all attributes from every child element of `<System>` (e.g.
    `"ProcessID"`, `"ThreadID"`, `"ActivityID"`, `"UserID"`). Values are
    raw strings; callers parse them to the required type. This replaces
    the former approach of storing typed `process_id: Option<u32>` /
    `thread_id: Option<u32>` fields — those were MDM-specific knowledge
    that did not belong in the generic `evt.rs` module. `cloud.rs` does
    `.system_attrs.get("ProcessID").and_then(|s| s.parse::<u32>().ok())`
    at the two pairing call sites. Non-breaking — `bitlocker.rs` never
    read those fields and continues to read only `time_created` and
    `event_data`.

    **No new Cargo features.** `Win32_Security_Cryptography` (TLS,
    deviation #14) covers all cert-store APIs. `Win32_NetworkManagement_NetManagement`
    (accounts, deviation #19) already covers `netapi32.dll`. Both were
    present before this deviation.

    Re-sync impact: `Copy-Item` of `host.rs` MUST preserve
    `cloud.rs`, the `install_cloud_bindings` call in `install()`, and
    the `system_attrs` field in `evt.rs::EventRecord` together with
    `extract_system_attrs` + `scan_attrs_into`.

13. **`rust-poc-lua/src/ep.rs` + `install_ep_bindings` in
    `host.rs` + `mod ep` in `lib.rs` — two Endpoint Protection bindings.**
    Not in upstream. Implements the EP sub-tree of `Win10-Laptop.json`
    (SentinelOne + Windows Defender) without SEP (excluded). Deviation #40.

    - `host.security_center_av_products()` — `SELECT * FROM AntiVirusProduct`
      in `ROOT\SecurityCenter2`.  Each row's `ProductState` u32 bitmask is
      decoded into three human-readable sub-fields following
      `AntiVirusEnums.cs` from ComplianceApp:
      - `state` (`"On"` / `"Off"` / `"Snoozed"` / `"Expired"`) from bits
        12-15 (mask `0x0000_F000`).
      - `signatures` (`"UpToDate"` / `"OutOfDate"`) from bits 4-7 (mask
        `0x0000_00F0`; zero = up-to-date).
      - `owner` (`"Microsoft"` / `"ThirdParty"`) from bits 8-11 (mask
        `0x0000_0F00`; `0x0100` = Microsoft).
      Returns all products; the Lua script filters by `name` for the
      specific product it needs (e.g. `"Sentinel Agent"` for SentinelOne).
      An empty array is a valid result.

    - `host.windows_defender_status()` — `SELECT * FROM MSFT_MpComputerStatus`
      in `ROOT\Microsoft\Windows\Defender`.  Returns the single-row object
      with WMI PascalCase property names as-is (no field renaming), for
      direct mapping to the six `WindowsDefender*` fields in
      `Win10-Laptop.json` (`AMServiceEnabled`, `AMRunningMode`,
      `AMProductVersion`, `AntivirusEnabled`, `RealTimeProtectionEnabled`,
      `ProductStatus`).  Returns `nil` when the namespace is absent (Server
      SKUs with Defender uninstalled) or the class returns no rows (Defender
      fully disabled by GPO or replaced by a third-party AV).

    **Win32 vs WMI rationale.** WSCAPI (`IWSCProductList` / `IWscProduct`
    in `wscapi.dll`) is the public Win32 alternative to querying
    `root\SecurityCenter2`.  However, those COM interfaces are absent from
    `windows-rs` 0.62 — `Win32::System::Antimalware` only covers AMSI
    (`IAmsiStream`, `AmsiScanBuffer`…), not the product-status query
    surface.  For Windows Defender, no public Win32 API exists for
    `MSFT_MpComputerStatus`; the `MpClient.dll` COM interface is
    undocumented.  WMI is therefore the only correct choice for both
    bindings, matching the ComplianceApp implementation.

    **No new Cargo features.** `Win32_System_Com` (already present for WMI
    init) covers all COM initialisation needed for both namespaces.
    `ensure_ns` in `wmi.rs` handles per-namespace connection caching
    transparently — no new `HostState` cache fields.

    Re-sync impact: `Copy-Item` of `host.rs` MUST preserve `ep.rs`, the
    `install_ep_bindings` call in `install()`, and the `ep` module
    declaration in `lib.rs`.

14. **`rust-poc-lua/src/firewall.rs` + `install_firewall_bindings` in
    `host.rs` + `mod firewall` in `lib.rs` — three Firewall bindings.**
    Not in upstream.  Implements the Firewall sub-tree of `Win10-Laptop.json`
    (minus `WfpFirewallView`, deferred to deviation #43).  Deviation #42.

    - **#42a `host.security_center_firewall_products()`** — `SELECT * FROM FirewallProduct`
      in `ROOT\SecurityCenter2`.  `FirewallEnums.cs` defines `FW_ProductStatus` as
      a bit-for-bit copy of `AV_ProductStatus` from `AntiVirusEnums.cs`; only the
      `Status` (bits 12-15) and `Owner` (bits 8-11) nibbles are decoded (the
      `SignatureStatus` nibble is absent in `FirewallEnums.cs`).  Ghost entries with
      an empty `displayName` are dropped.  The Lua script filters by `name` for
      `"Sentinel Firewall"` (mirrors `SentinelOneFirewallStatus.cs`).

    - **#42b `host.windows_defender_firewall_status()`** — Two `root\StandardCimv2`
      queries:
      - `MSFT_NetConnectionProfile.NetworkCategory` (uint32: 0=Public, 1=Private,
        2=Domain) → `current_profile` string.  Fallback `"Public"` when the machine
        has no active network connection (no rows returned) — documented invariant in
        `Firewall.cs` L.196.
      - `MSFT_NetFirewallProfile` — all rows; matched by `Name` field (case-insensitive)
        for Domain / Private / Public; `Enabled` uint16 (0=Off, 1=On) decoded to
        `"Off"` / `"On"` / `"Unknown"`.
      Returns `{current_profile, status, domain_state, private_state, public_state}`.
      Mirrors `Firewall.cs::GetWindowsDefenderFirewallStatus`.

    - **#42c `host.net_fw_products()`** — COM `HNetCfg.FwProducts` via
      `CoCreateInstance(&NetFwProducts, …, CLSCTX_INPROC_SERVER)` → `INetFwProducts`.
      Includes a 5-attempt retry loop (1 s intervals) for transient COM init failures
      during Windows Firewall service start-up — mirrors `Firewall.cs` L.33–79.
      Per-product: `Item(i)` returns `INetFwProduct`; QI to `INetFwProduct2` to access
      `RuleCategories`.  The `RuleCategories` property returns a `VARIANT` wrapping a
      `SAFEARRAY` of `VT_I4` (OLE type `VT_ARRAY|VT_I4 = 8195`).  Extraction via
      `SafeArrayGetLBound` / `SafeArrayGetUBound` / `SafeArrayGetElement` (all from
      `Win32::System::Ole`; already a Cargo feature).  Category IDs: 0=BootTime,
      1=Stealth, 2=Firewall, 3=ConSec — numeric values match the C#
      `NET_FW_RULE_CATEGORY` enum.  The Lua `fw_category_owner(cat_id)` helper maps
      each ID to the registered product name, defaulting to `"Windows Defender Firewall"`
      when no product claims the category.
      Requires new Cargo feature `Win32_NetworkManagement_WindowsFirewall`.
      Mirrors `Firewall.cs::GetNetFwProducts`.

    Re-sync impact: `Copy-Item` of `host.rs` MUST preserve `firewall.rs`, the
    `install_firewall_bindings` call in `install()`, and the `firewall` module
    declaration in `lib.rs`.

15. **`rust-poc-lua/src/wfp*.rs` + `install_wfp_bindings` in `host.rs` +
    `WfpCacheState` on `HostState` — three WFP Lua bindings.**
    Not in upstream.  Implements `WfpSubLayerDetails.cs`, `WfpFirewallView.cs`,
    and `WfpNetEvents.cs` from ComplianceApp with full logic fidelity (snake_case
    field names, same enrichment, deduplication, and condition formatting).
    Deviation #43.

    **Four new modules:**

    - **`wfp_known_guids.rs`** — three `OnceLock<HashMap<GUID, &str>>` for 110+
      layer GUIDs, 17+ sublayer GUIDs, and ~100 condition-field GUIDs.  GUIDs from
      `WfpKnownGuids.cs` (Windows SDK headers `fwpmu.h`, 10.0.26100.0).

    - **`wfp_conditions.rs`** — intermediate `WfpCondition` type; parses
      `FWP_CONDITION_VALUE0` union for all `FWP_DATA_TYPE` variants (inline scalars,
      heap-pointer scalars, `BYTE_BLOB`, `SID`, security-descriptor, masks, ranges);
      produces JSON array (`conditions_json`) and compact Unicode-symbol string
      (`format_compact`).

    - **`wfp.rs`** — `WfpEngine(HANDLE)` RAII (`FwpmEngineClose0`);
      `WfpMemoryGuard` RAII (`FwpmFreeMemory0`); `enumerate_wfp_state()` (six Win32
      enumeration APIs at batch 1000/1000/1000/1000/1000/10000); `WfpEnrichedFilter`
      + `WfpState` cached structs; `wfp_net_events()` using an ephemeral engine +
      `FwpmNetEventEnum2(1000)`.  Custom FILETIME→ISO 8601 UTC via Howard Hinnant's
      civil-date algorithm (no external crate).

    - **`wfp_pipeline.rs`** — port of `WfpFilterPipeline.cs`:
      `filter_ale_filters` (ALE layer keep-list, sublayer exclusions, action
      exclusions, SentinelOne name filter); `compute_shadowing` (tri-sort +
      shadowing mark); `deduplicate_filters` (group by 5-tuple key, representative
      by max `effective_weight_numeric`); `normalize_layer_name` (strips `_V4`/`_V6`
      suffix for dedup key only); `wfp_sublayer_details` + `wfp_firewall_view`.

    **`HostState` additions:**
    - `WfpCacheState` tri-state enum (`NotInit | Ready(WfpState) | Failed`).
    - `wfp_cache: WfpCacheState` field, initialised `NotInit`.
    - `ensure_wfp_state() -> Option<&WfpState>` accessor (same memo pattern as
      `ensure_updates_cache`); memoises failures under
      `ERR_KEY_WFP_CACHE_INIT = "wfp:cache_init"`.

    **Intentional deviation from ComplianceApp:**  `wfp_net_events` omits the
    `layerId < 200` heuristic guard (ComplianceApp adds it to filter corrupted
    event data but it silently drops events from third-party/dynamic layers).

    Requires new Cargo feature `Win32_NetworkManagement_WindowsFilteringPlatform`.

    Re-sync impact: `Copy-Item` of `host.rs` MUST preserve all four `wfp*` module
    declarations in `lib.rs`, the `install_wfp_bindings` call in `install()`, and
    the `WfpCacheState` + `wfp_cache` additions to `HostState`.

16. **`rust-poc-lua/src/laps.rs` + `install_laps_bindings` in `host.rs` —
    one LAPS posture binding.**
    Not in upstream.  Mirrors the LAPS transformers in ComplianceApp
    (`Security.cs` + `DataTransformers/LAPS/*.cs`).  Exposes a single
    `host.laps_state()` that returns the whole Windows/Legacy LAPS posture in
    one stateless call (no per-run cache — every field is a cheap registry
    read or `Path::exists` probe):
    - `auto_laps_mode` — `"Legacy"` (legacy AdmPwd CSE key present) /
      `"Windows"` (both `System32\laps.dll` + `lapscsp.dll` present) /
      `"Not Installed"` (neither).  Legacy wins over Windows, same ordering
      as `AutoLapsMode.cs`.
    - `windows_laps_dll_state` — `"Found"` (both DLLs) / `"NotFound"`.
    - `laps_policy` — 4-key presence cascade (CSP → GPO → local → legacy
      AdmPwd); first match wins; mirrors `GetLapsPolicy`.
    - `laps_backup_directory` — `BackupDirectory` (`"1"`→`MicrosoftEntra`,
      `"2"`→`ActiveDirectory`) or legacy `AdmPwdEnabled` (`"1"`→
      `ActiveDirectoryLegacy`); else `Disabled`.
    - `legacy_gp_extension_present` — bool; existence of the AdmPwd CSE GP
      extension key `{D76B9641-3288-4f75-942D-087DE603E3EA}`.
    - `max_pwd_age_days` — `PasswordAgeDays` on the active channel's key.

    The `LocalAdminPasswordDate` field of `Win10-Laptop.json` is **not** a
    binding — `collectors/agents.lua` derives it from
    `host.local_user_accounts()` (deviation #20) by selecting the built-in
    Administrator (SID ending `-500`) and reading its `last_password_set`.

    **Intentional deviation from ComplianceApp:** `auto_laps_mode` emits
    `"Not Installed"` where the C# `AutoLapsState.Unknown` serialises to
    `"Unknown"`.  The `Win10-Laptop.json` parent test is
    `AutoLapsMode != "Not Installed"`, which the string `"Unknown"` always
    passes — so a host without LAPS is falsely reported compliant in C#.
    Emitting `"Not Installed"` makes the test behave as intended.

    Adds `pub(super) fn registry::key_exists(hive, key) -> bool` (existence
    probe, no value read) to `registry.rs`.  No new Cargo feature
    (`Win32_System_Registry` already present; DLL probes use `std::path`).

    Re-sync impact: `Copy-Item` of `host.rs` MUST preserve the `laps` module
    declaration in `lib.rs`, the `install_laps_bindings` call in `install()`,
    and `registry::key_exists`.

17. **`rust-poc-lua/src/sentinelone.rs` + `install_sentinelone_bindings` in
    `host.rs` — three SentinelOne EDR bindings (deviation #45).**
    Not in upstream.  Mirrors `ComplianceService/Data/EDR/SentinelOne/SentinelOne.cs`.
    Covers the 15 SentinelOne items of the EDR category in `Win10-Laptop.json`
    via three sources, each a stateless call (no per-run `HostState` cache):
    - `host.sentinel_one_agent_status()` — COM **IDispatch late-binding**
      against the `SentinelHelper` ProgID, calling `GetAgentStatusJSON()` and
      returning the 13 agent fields (snake_case).  This is the **first
      late-bound COM call in the crate**; every other COM consumer (WMI, WUA,
      `HNetCfg.FwProducts`) is early-bound against a typed `windows-rs`
      interface.  `SentinelHelper` ships no type library, so we go through
      `IDispatch` exactly as the C# `dynamic agent = Activator.CreateInstance(...)`.
    - `host.sentinel_one_paths()` — `{folder, ctl_paths[], agent_paths[]}`.
    - `host.sentinel_one_comm_sdk()` — newest `SentinelOne/Operational` #104
      event (`CommSdkMessage` + timestamp) via `evt::query_events`.

    `collectors/agents.lua` derives the parent `SentinelOneStatus`
    (`#ctl_paths > 0 and agent_status ~= nil`) and the 15 item keys from these
    three calls, plus one diagnostic path list (`sentinel_one_agent_paths`).
    `ctl_paths` is returned by the binding (the parent test needs it) but not
    re-exposed in the output — it lives in the same folder as `agent_paths`
    and its presence is already encoded in `sentinel_one_status`.

    **Intentional deviations from ComplianceApp:**
    - **`paths()` returns arrays, not `LastOrDefault()`.** The C#
      `GetSentinelOneFindCtlPath`/`FindAgentPath` keep a single path via
      `Directory.GetFiles(..., AllDirectories).LastOrDefault()`.  The path is
      never a compliance value (only an existence test), so returning the full
      `Vec` is lossless for the semantics (`!is_empty()` ≡ `!= null`), drops the
      arbitrary "last" rule, and is more diagnostic (versioned installs visible).
    - **`agent_found` tests `sentinelAgent.exe`, not the folder.** The C#
      `SentinelOneAgentFound` transformer tests `GetSentinelOneFindFolderPath()
      != null` (folder presence) despite its "Agent Executable" label; the Lua
      collector tests `#agent_paths > 0` to match the label.
    - **Dates canonicalised to Zulu.** `GetAgentStatusJSON` returns
      `agent-install-time`/`last-seen` as offset-aware ISO 8601
      (e.g. `2026-05-29T11:15:25.000+00:00`).  `normalize_utc_iso8601` rewrites a
      zero-offset suffix (`+00:00`/`-00:00`) to `Z`, matching ComplianceApp's wire
      contract (`Timestamp.FromDateTime(dt.ToUniversalTime())`, UTC) and the rest
      of this crate (`updates`/`winver`/`eventlog` emit `…Z`).  No time-zone
      arithmetic: a non-zero offset stays verbatim (never observed from
      SentinelOne, which reports `+00:00`).

    No new Cargo feature: IDispatch needs `Win32_System_Com` +
    `Win32_System_Ole` + `Win32_System_Variant`, all already enabled.

    Re-sync impact: `Copy-Item` of `host.rs` MUST preserve the `sentinelone`
    module declaration in `lib.rs` and the `install_sentinelone_bindings` call
    in `install()`.

18. **`rust-poc-lua/src/cyberark.rs` + `install_cyberark_bindings` in
    `host.rs` — six CyberArk EPM (legacy Viewfinity) bindings (deviation #46).**
    Not in upstream.  Mirrors the CyberArk EPM region of
    `ComplianceService/Data/Security/Security.cs`.  Covers the 6 items of the
    Privileged Account Management (PAM) category in `Win10-Laptop.json` via two
    Windows mechanisms (no WMI / no COM):
    - `host.cyber_ark_epm_driver_status()` — the `vfpd` kernel driver status.
      The C# uses `ServiceController.GetDevices()`; we open the named service
      directly (`OpenSCManagerW` + `OpenServiceW("vfpd", SERVICE_QUERY_STATUS)`
      + `QueryServiceStatus`).  `ERROR_SERVICE_DOES_NOT_EXIST` → `"None"`
      (= C# `ServiceStatus.None`); other SCM failures → `nil` +
      `cyberark:driver_status`.  Reuses `software::ScHandle` (RAII close) and
      `software::service_state_label` (both made `pub(crate)`).
    - `host.cyber_ark_epm_version()` / `_id()` / `_dispatcher_url()` /
      `_registered_at()` / `_last_policy_update()` — five reads from the single
      key `HKLM\SOFTWARE\Viewfinity\Agent` (`Version`, `SetID`, `DispatcherURL`,
      `RegisteredAt`, `LastPolicyUpdateTime`).  All infallible (the `laps.rs`
      posture): a missing key/value degrades to `nil`, never an error.  The
      four string reads coerce via the shared `registry::as_string(Value)`
      helper (see below); `_last_policy_update` reads the `REG_QWORD` directly.

    **Intentional deviations from ComplianceApp:**
    - **Dates in UTC Zulu.** `LastPolicyUpdateTime` (`REG_QWORD` FILETIME) goes
      through `winver::filetime_to_iso8601` → `…Z`.  Aligned with the gRPC wire
      contract (`Timestamp.FromDateTime(dt.ToUniversalTime())`) and the rest of
      the crate; the bare C# `DateTime.FromFileTime` is local but the same
      instant travels over the wire as UTC.
    - **`version` passed through verbatim** (no `Version::parse`; identical
      output to the wire `Version.ToString()`).
    - **Targeted query, not enumeration** — `OpenServiceW`+`QueryServiceStatus`
      on the named driver rather than the C# device-list scan.
    - **Binding name ≠ output key** for two items: `host.cyber_ark_epm_version()`
      → `cyber_ark_epm_agent_version`, `host.cyber_ark_epm_last_policy_update()`
      → `cyber_ark_epm_last_policy_update_date` (the `Agent`/`Date` suffixes in
      the JSON `Name`s).

    No new Cargo feature: SC Manager needs `Win32_System_Services` +
    `Win32_Foundation`, both already enabled.

    **Shared scalar coercion — `registry::as_string(Value) -> Option<String>`.**
    The "`REG_DWORD` `1` and `REG_SZ` `"1"` both become `"1"`" rule (C#
    `GetValue(...)?.ToString()`) lives once in `registry.rs`, next to the
    `decode` that produces those `Value`s.  Both the CyberArk reads
    (`cyberark::reg_string`) and the LAPS reads (`laps::registry_value_string`,
    deviation #44) delegate to it — the previous `coerce_reg_string` (cyberark)
    and the inline `match` (laps) were conceptual duplicates and were removed.
    It takes `Value` **by value** so the `String` case moves instead of cloning.

    Re-sync impact: `Copy-Item` of `host.rs` MUST preserve the `cyberark`
    module declaration in `lib.rs`, the `install_cyberark_bindings` call in
    `install()`, and the `pub(crate)` visibility of `software::ScHandle` /
    `software::service_state_label`.  `Copy-Item` of `registry.rs` from
    upstream MUST preserve the `as_string` helper (upstream has no equivalent
    yet, so it is a hand-merge point like `enum_value_names` / `read_binary`).

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
# would come back). The other files are safe to overwrite (host.rs also
# needs hand-merging to preserve the wfp_cache and ensure_wfp_state additions).
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
- **COM IDispatch late-binding** — `sentinelone.rs` (deviation #45) calls a
  COM object that ships no type library, so it cannot be early-bound against a
  typed `windows-rs` interface like every other COM consumer in the crate.
  The flow mirrors a C# `dynamic`/`Activator.CreateInstance` call:
  `CLSIDFromProgID("SentinelHelper")` → `CoCreateInstance` to `IDispatch` →
  `GetIDsOfNames("GetAgentStatusJSON")` to resolve the method's `DISPID` →
  `IDispatch::Invoke(DISPATCH_METHOD)` with an empty `DISPPARAMS` → read the
  returned `VT_BSTR` `VARIANT` (`var.Anonymous.Anonymous.Anonymous.bstrVal`,
  cleared with `VariantClear`). `Invoke` is feature-gated behind
  `Win32_System_Ole` + `Win32_System_Variant`. (Reference: OLE Automation /
  `IDispatch`.)
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
- `setup_history::install_info().history` — populated by walking the
  `HKLM\SYSTEM\Setup\Source*` registry subkeys. The upstream
  `eventlog::install_info()` returns `[]` here; the rust-poc-lua port
  enriches it (see deviation #16). A future `EvtQuery` + `EvtRender`
  pass against the Setup event log could add per-upgrade events that
  the registry-derived history misses (e.g. failed upgrades that left
  no `Source OS *` subkey).

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
