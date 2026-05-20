# Setup (Inno Setup installer)

Inno Setup-based installer for the `collect-config` CLI. Modelled on
[`sdh-complianceapp/Setup/`](../../sdh-complianceapp/Setup/) but ~5x
smaller because Rust-Poc has no Windows service, no perimeter wizard,
no legacy MSI bridge, and no JSON patching to do at install time.

## Why Inno Setup

Same rationale as the compliance app: BSD-style licence, no commercial
restriction, mature enterprise tooling (used by Cursor, VSCode, Git
for Windows, Audacity, OBS Studio, …). The detailed comparison with WiX
lives in [`sdh-complianceapp/Setup/README.md`](../../sdh-complianceapp/Setup/README.md);
no point duplicating it here.

## Build

```powershell
# from the repo root
.\publish-innosetup.ps1                  # version read from Cargo.toml, signed
.\publish-innosetup.ps1 -SkipSign        # local dev iteration, unsigned EXE
.\publish-innosetup.ps1 -SkipBuild       # rebuild only the EXE (publish/ already staged)
.\publish-innosetup.ps1 -ProductVersion 0.2.0   # override version
```

Output: `Setup/Output/CollectConfigSetup-<Version>.exe`.

### Direct ISCC invocation (no wrapper)

When iterating on `CollectConfigSetup.iss` alone with `publish/` already
populated:

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DMyAppVersion=0.1.0 Setup\CollectConfigSetup.iss
```

Drop `/DMyAppVersion=...` to fall back to the `0.0.0` default baked into
the script.

## Layout

```text
Setup/
├── CollectConfigSetup.iss   # main script (~150 lines)
├── README.md                # this file
└── Output/                  # generated EXE (gitignored)
```

There is no `Scripts/` subfolder yet — the single `.iss` is short
enough to stay readable. We will split into modules à la
`sdh-complianceapp/Setup/Scripts/` once we cross ~250 lines or add a
multi-step Pascal `[Code]` block (e.g. a scheduled task creator, an
ARP rename, a per-perimeter wizard).

## What the installer does

- Installs `collect-config.exe` and `collectors\*` under
  `C:\Program Files\Sanofi\CollectConfig\`.
- Requires admin privileges (`PrivilegesRequired=admin`).
- Pre-cleans `{app}\*` before file copy so removed/renamed files from a
  previous version do not linger.
- Sets `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\RUST_POC_LOG_DIR`
  to `C:\SMSLogs` so `logging::resolve_log_dir()` picks the shared
  Sanofi logs folder (priority #1 in `src/logging.rs`) instead of
  falling back to `{app}\logs` (which would need admin write access at
  runtime).
- Pre-creates `C:\SMSLogs` with `uninsneveruninstall` (shared folder,
  do not remove on uninstall).

  > **ACL caveat.** Inno's `[Dirs]` creates the folder with permissions
  > **inherited from `C:\`**. On a managed Sanofi endpoint (SOE), the
  > folder either already exists (provisioned by GPO / image) or
  > inherits ACLs that let standard users write — same posture as the
  > existing `C:\SMSLOGS` usage in `sdh-complianceapp`. On a vanilla
  > test VM (e.g. a fresh dev sandbox), verify post-install that the
  > current user can write to `C:\SMSLogs`; if not, `collect-config`'s
  > best-effort logging will silently drop log lines AND the per-run
  > JSON dump (the `tracing::warn!` is visible on stderr but does not
  > break the run). Adding an explicit `[Code]` section to grant
  > `Users:M` would close the gap, but is deliberately omitted today
  > to mirror the compliance app's posture exactly.
- Creates one Start menu shortcut: a cmd shell already `cd`'d into
  `{app}`, ready for the user to type `collect-config general.lua`.
  This is the only sensible shortcut for a CLI tool — launching the
  `.exe` directly would flash a window and exit.
- Signs the final EXE and its embedded uninstaller via signtool when
  `/DSIGN=1` is passed (the wrapper does this by default; opt out with
  `-SkipSign`).

## What it does NOT do (deliberately)

- **No Windows service** — `collect-config` is a one-shot CLI.
- **No scheduled task** — install only deposits the binary. The
  scheduling mechanism is the operator's choice (Task Scheduler, SCCM,
  Intune, ManageEngine, …). We will revisit if a built-in schedule
  becomes a requirement.
- **No JSON patching** — no `appsettings.json` equivalent; the CLI
  takes its config from CLI args and env vars.
- **No legacy MSI bridge** — there is no previous MSI version of
  `collect-config` to migrate from.
- **No perimeter wizard** — the perimeter is a CLI arg, not an install-
  time decision.

## Signing

Same pattern as `sdh-complianceapp/publish-all-innosetup.ps1`:

1. Resolve the thumbprint from `-SignThumbprint`, then
   `$env:SDH_SIGN_THUMBPRINT` (Process), then User scope, then Machine
   scope.
2. Validate: 40-or-64 hex chars, certificate present in
   `Cert:\CurrentUser\My` or `Cert:\LocalMachine\My`, not expired,
   private key accessible.
3. **Pass #1** — sign `publish\collect-config.exe` directly with
   `signtool.exe sign /sha1 <thumb> /fd sha256 /tr <url> /td sha256`.
   Must happen before ISCC compresses the file into the installer
   payload (you cannot re-sign an embedded binary after the fact).
4. **Pass #2** — ISCC invokes a per-build `.cmd` wrapper via
   `/Ssdh=<wrapper> $f` (registered as the `sdh` SignTool referenced
   by `SignTool=sdh` in the `.iss`). Inno calls it once for the final
   `CollectConfigSetup-<Version>.exe` and once for the embedded
   `unins000.exe` (because of `SignedUninstaller=yes`).
5. Sanity check the produced EXE with `Get-AuthenticodeSignature` and
   abort if `Status -ne 'Valid'`.

The `.cmd` wrapper exists because PowerShell 5.1's native argument
quoting is famously broken when an argument contains both spaces and
embedded double quotes (signtool's path has spaces under Program Files;
`$f` must stay quoted for installer paths with spaces). The wrapper
takes `$f` as `%1` and re-quotes everything in batch rules. See the
inline comment in `publish-innosetup.ps1` for the full rationale.

## The `MyAppId` GUID

`{848231EB-C945-463F-9DEC-E90E12B4781D}` is the Inno Setup identifier
**dedicated to CollectConfig**. NEVER reuse the compliance app's
`{CA9A7A52-9076-42BB-95F0-FD2B3A374210}` (or any other shipped GUID).
Sharing the AppId would make the two products think they are
upgrades / downgrades of each other — install one and you uninstall
the other from ARP. Once an installer ships with this GUID, it is
frozen forever.
