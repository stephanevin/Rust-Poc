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
cargo check --workspace --all-targets    # Type-check everything (~1s, used dozens of times per session)
cargo clippy --workspace --all-targets -- -D warnings  # Lint, warnings as errors
cargo fmt                                # Format to rustfmt defaults
cargo test --workspace                   # Unit + integration + doc tests
cargo run -p rust-poc                    # Build + execute the root binary
cargo build --release                    # Optimised final binary in target/release/

# Regenerate JSON schemas under contracts/generated/schemas/. Run after
# any change to a struct or enum in contracts/. Same workflow as
# sdh-fleet-client/contracts.
cargo run -p rust-poc-contracts --bin gen-schemas --features schema
```

Note: `cargo run` at the workspace root launches `rust-poc` thanks to
the `default-run = "rust-poc"` key in the root `Cargo.toml`. The
workspace exposes **three** binaries: `rust-poc` (default), `collect-
config` (`src/bin/collect-config.rs`), and `gen-schemas` (gated behind
the `schema` feature in `contracts/`). Non-default binaries must be
invoked explicitly via `--bin <name>` or `-p <crate> --bin <name>`.

**Anti-regression note — DO NOT REWRITE THIS BLOCK CASUALLY.** This
note has already been silently overwritten twice by AI agents
reformatting the section. If you are about to delete or rewrite the
preceding paragraph, the `default-run` key in `Cargo.toml`, or the
binary list above, you must justify the change in your commit
message — otherwise restore them verbatim.

The pinned toolchain (Rust 1.95.0 + clippy + rustfmt) lives in
`rust-toolchain.toml` — rustup picks it up automatically on the first
`cargo` invocation in this directory.

## Architecture

Four sibling crates in one workspace, modelled on the cross-boundary
structure of `sdh-fleet-client`:

| Crate | Role | Mirror in sdh-fleet-client |
|---|---|---|
| **`rust-poc-contracts`** (`contracts/`) | Shared types only. No runtime deps beyond serde, no I/O. | `sdh-fleet-client/contracts/` |
| **`rust-poc-greeter`** (`greeter/`) | `Greeter` trait + concrete implementations. Emits `debug!` events; depends on `tracing` (not `tracing-subscriber`). | `sdh-fleet-client/service/src/handler.rs` |
| **`rust-poc-lua`** (`rust-poc-lua/`) | In-process Lua 5.4 collector runtime + 17 `host.*` bindings (WMI, registry, networking, ADSI). Windows-only real impl + cross-target stub. | `sdh-fleet-client/lua/` (verbatim port, see [Lua collector runtime](#lua-collector-runtime)) |
| **`rust-poc`** (root + `src/main.rs` + `src/bin/collect-config.rs`) | Composer — dispatches into greeter impls, installs the tracing subscriber, and exposes the `collect-config` CLI that drives `rust-poc-lua`. | `sdh-fleet-client/src/main.rs` + `src/logging.rs` |

### Architectural rules

- **`contracts/` is the only place a cross-crate type lives.** Never
  duplicate a struct or enum into `greeter/` or the root bin — extend
  `contracts/` and let the others import. This mirrors the same rule
  in `sdh-fleet-client/contracts/`.
- **`contracts/` keeps runtime deps minimal.** `serde` + `serde_json`
  are always-on (they are de-facto stdlib for any wire type). Anything
  heavier — `schemars`, `tokio`, `reqwest` — goes behind a feature
  flag, exactly like `sdh-fleet-client/contracts/Cargo.toml`.
- **`greeter/` exposes behaviour through a trait, never concrete
  types.** The root bin must depend on `Greeter`, not on
  `EnglishGreeter` directly, in any non-trivial dispatch logic.
- **The root bin is a composer, not a place for logic.** New behaviour
  goes in `greeter/` (or a new sibling crate); `main.rs` only wires
  things together.

### Wire-format discipline

Every struct or enum in `contracts/` that crosses a process boundary
(JSON file on disk, HTTP body, log payload, …) follows these rules:

- **Always derive `Serialize` + `Deserialize`.** Even if a type is
  internal today, the derive is cheap and lets the type become wire-
  visible later without a breaking change.
- **Never use `#[serde(deny_unknown_fields)]`.** A producer that adds a
  new field must not break a consumer that hasn't learned about it yet.
  The default serde behaviour (silently ignore unknown fields) is the
  forward-compatibility contract.
- **Optional fields use `Option<T>` + `#[serde(default,
  skip_serializing_if = "Option::is_none")]`.** This keeps the wire
  format clean (no `"nickname": null` noise) AND lets legacy payloads
  without the field parse cleanly.
- **Enum variants serialize to lowercase by default**
  (`#[serde(rename_all = "lowercase")]`). Tagged unions use
  `#[serde(tag = "type", rename_all = "snake_case")]` when needed —
  same convention as `sdh-fleet-client/contracts/src/agent.rs`.
- **JSON Schema is generated, not hand-written.** Schemas live in
  `contracts/generated/schemas/` and are produced by `cargo run -p
  rust-poc-contracts --bin gen-schemas --features schema`. Re-run after
  any struct change and commit the diff.

Round-trip tests are the cheapest defence against accidental wire
breakage — pin the exact JSON string with `assert_eq!`. Several
examples live in `contracts/src/lib.rs::tests`.

## Logging

Tracing stack mirrored from `sdh-fleet-client/src/logging.rs`, minus
the hot-reload machinery (no remote config source means no reason to
swap filters at runtime). See `src/logging.rs` for the init, plus
inline `info!` / `debug!` calls in `src/main.rs` and
`greeter/src/lib.rs` for the call-site idioms.

### Layers

- **Console** (stderr, compact): human-readable during development.
- **File** (JSON, daily-rolling): machine-readable, one event per
  line, queryable with `jq`.

Both layers share a single `EnvFilter` that defaults to `INFO` and is
overridden by `RUST_LOG` (e.g. `RUST_LOG=rust_poc_greeter=debug`).

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
- Crates that do work (`greeter/`) depend on `tracing` only, not on
  `tracing-subscriber`. Macros expand to no-ops when no subscriber is
  installed, which keeps unit tests free of any setup boilerplate.
- The root binary owns the `WorkerGuard` returned by `logging::init()`
  in a `_log_guard` local that must live for the whole program.
  Dropping it kills the non-blocking writer's worker thread and
  silently loses any pending log lines.

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
├── host.rs         # 17 `host.*` bindings + HostState (Rc<RefCell<..>>)
├── wmi.rs          # COMLibrary + WMIConnection + per-class cache
├── registry.rs     # RegOpenKeyExW + RegQueryValueExW + REG_* decode
├── net.rs          # GetAdaptersAddresses + IPv4 enumeration
├── winver.rs       # RtlGetVersion + GetFirmwareType
├── eventlog.rs     # Install date (registry-derived ISO 8601)
└── ad.rs           # ADSI mail lookup stub (phase 2 in upstream)
```

### The 17 `host.*` bindings exposed to Lua

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
| `host.adsi_user_mail(timeout_s)` | ADSI stub (returns nil unless USERDNSDOMAIN is set) | `string?` |
| `host.setup_history()` | `eventlog::install_info` | `{install_date, history[]}` |
| `host.cpu_details()` | WMI `Win32_Processor.Name + SocketDesignation` | `string?` |
| `host.ram_total()` | WMI `Win32_PhysicalMemory.Capacity` (summed) | `number?` |
| `host.disk_size(target, property)` | WMI `Win32_LogicalDisk` filtered by `%SystemDrive%` | `number?` |
| `host.motherboard_details()` | WMI `Win32_ComputerSystem.Model + SystemFamily` | `string?` |
| `host.bios_details()` | WMI `Win32_BIOS.BIOSVersion` + `winver::firmware_type` | `string?` |
| `host.desktop_resolution()` | WMI `Win32_VideoController.{Current*Resolution, RefreshRate}` | `string?` |
| `host.errors()` | Internal `HashMap<String, String>` accumulated by other bindings | `table<string, string>` |

Bindings never raise — failures are recorded into `host.errors()` and
the binding returns `nil`. The Lua script attaches the final
`host.errors()` map as `_errors` in its output for the operator to
inspect.

### `collect-config` CLI

```powershell
# Run the bundled general.lua collector against the local host
cargo run --bin collect-config -- general.lua

# Optional perimeter argument (surfaces as host.env("SDH_PERIMETER"))
cargo run --bin collect-config -- general.lua some-perimeter

# stdout-only JSON, suitable for piping
cargo run --quiet --bin collect-config -- general.lua > config.json
cargo run --quiet --bin collect-config -- general.lua | jq '.machine_name'
```

The binary lives at `src/bin/collect-config.rs`. It loads
`collectors/<script_name>` (the cache dir is hard-coded to
`./collectors`), constructs an `InternalRuntime`, calls
`runtime.run(...)` with a 30s wall-clock timeout, and pretty-prints the
returned JSON. Logs and progress go to stderr; only the JSON goes to
stdout.

Exit codes: `0` success, `1` Lua runtime error (script error or
timeout), `2` cannot read hostname, `3` cannot serialize output, `4`
script path escapes the `collectors/` directory (path traversal
rejected by `resolve_script_path`).

### Deviations from a strict verbatim copy

There are exactly **five** points where copying upstream byte-for-byte
won't compile. Each one is documented inline at the touch site so a
future re-sync is mechanical.

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
rust-poc-lua` + `cargo run --bin collect-config -- general.lua`.

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

### Known stubs left intentionally incomplete

- `ad::current_user_mail_blocking` — always returns `None` even on
  domain-joined machines. Phase 2 in upstream too. Real impl needs
  `IADs::Get("mail")` via `windows::Win32::System::Ole`.
- `eventlog::install_info().history` — always `[]`. Real impl needs
  `EvtQuery` + `EvtRender` to parse the Setup event log.

Both stubs are documented in their source files. They surface as `null`
or `[]` in the JSON output, never as errors.

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
  Spanish greeter"), optional blank line + body explaining the *why*,
  not the *what*. Match the style of `sdh-fleet/sdh-fleet-client`
  commit history.
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
