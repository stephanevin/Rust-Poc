; =============================================================================
; CollectConfigSetup.iss
; Inno Setup script for the Rust-Poc collect-config CLI.
;
; Modelled on sdh-complianceapp/Setup/ComplianceSetup.iss but ~5x smaller
; because the Rust PoC has no service, no perimeter wizard, no legacy MSI
; bridge, and no JSON patching to do at install time.
;
; Build:
;   ISCC.exe /DMyAppVersion=0.1.0 CollectConfigSetup.iss
;
; Or via the wrapper:
;   .\publish-innosetup.ps1
;
; Output: ./Output/CollectConfigSetup-<Version>.exe
; =============================================================================

#define MyAppName       "CollectConfig"
#define MyAppPublisher  "Sanofi"
#define MyAppExe        "collect-config.exe"
#define StagingDir      "..\publish"

; AppId is the Inno Setup-specific stable identifier. NEVER change this
; once shipped: doing so breaks the upgrade chain (a new install would
; refuse to overwrite the previous one and would create a parallel ARP
; entry). The double opening brace is required so Inno does not parse
; the value as a constant. This GUID is dedicated to CollectConfig and
; must NEVER be confused with the ComplianceApp AppId.
#define MyAppId         "{{848231EB-C945-463F-9DEC-E90E12B4781D}"

; Version is injected by publish-innosetup.ps1 via /DMyAppVersion=...
; Default kept here for direct ISCC invocations during local debugging.
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoDescription=CollectConfig Installer
DefaultDirName={autopf64}\{#MyAppPublisher}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableDirPage=auto
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
OutputDir=Output
OutputBaseFilename=CollectConfigSetup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExe}
UninstallDisplayName={#MyAppName}

; Authenticode signing.
;
;   - SignTool=sdh: invokes the "sdh" tool defined at compile time via
;     ISCC /Ssdh=<wrapper.cmd> $f (see publish-innosetup.ps1). Inno calls
;     it once for the final EXE and once for the embedded uninstaller
;     (because of SignedUninstaller=yes below).
;   - SignedUninstaller=yes: the uninstaller binary is generated AT COMPILE
;     TIME, so it must be signed at compile time too. Without this directive,
;     unins000.exe ships unsigned and triggers a SmartScreen warning when
;     users uninstall the product.
;
; Both directives are gated by #ifdef SIGN. The orchestrator passes
; /DSIGN to ISCC only when signing is enabled. Without this gate, an
; unsigned compile (e.g. -SkipSign for local dev) would FAIL with
; "Value of [Setup] section directive 'SignTool' is invalid" because
; ISCC strictly requires that any SignTool=<name> reference be matched
; by a /S<name>=... command-line definition.
#ifdef SIGN
SignTool=sdh
SignedUninstaller=yes
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; The Rust binary is a statically-linked single .exe (no .dll companions
; thanks to MSVC's CRT-static link mode in --release). One Source line
; covers everything we ship from the binary side.
Source: "{#StagingDir}\{#MyAppExe}"; DestDir: "{app}"; \
  Flags: ignoreversion restartreplace uninsrestartdelete

; Collector scripts. recursesubdirs/createallsubdirs preserves any nested
; layout if collectors/ grows subfolders. ignoreversion forces overwrite
; on upgrade (Lua scripts have no version metadata).
Source: "{#StagingDir}\collectors\*"; DestDir: "{app}\collectors"; \
  Flags: recursesubdirs createallsubdirs ignoreversion

[Registry]
; Set RUST_POC_LOG_DIR machine-wide so logging::resolve_log_dir() picks
; the SMSLogs folder (priority #1 in src/logging.rs) instead of falling
; back to <exe-dir>\logs (which under Program Files would require admin
; for every log write — a problem when collect-config eventually runs as
; a non-elevated user via a scheduled task).
;
; Flags:
;   - preservestringtype : keep REG_EXPAND_SZ (matches the surrounding
;     entries in the Environment key; mixing REG_SZ in there is benign
;     but inconsistent).
;   - uninsdeletevalue : remove the value on uninstall. We do NOT use
;     uninsdeletekey because the parent Environment key is system-wide
;     and shared with hundreds of unrelated variables.
;
; The WM_SETTINGCHANGE broadcast that propagates the new value to
; already-running processes is NOT triggered by Inno. Existing shells
; and services keep their stale environment until next launch. Code that
; needs the variable on first install must therefore be spawned by
; setup itself (not the case here — collect-config is launched manually
; or by a scheduled task created later) OR after a reboot / re-login.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
  ValueType: expandsz; ValueName: "RUST_POC_LOG_DIR"; ValueData: "C:\SMSLogs"; \
  Flags: preservestringtype uninsdeletevalue

[Dirs]
; Pre-create the log directory so the first run of collect-config does
; not have to (the std::fs::create_dir_all in logging.rs is best-effort
; — a failure would silently drop file logs). Permissions inherit from
; the parent C:\ ACL, which gives Users read access; collect-config
; running as SYSTEM via a future scheduled task can write here.
Name: "C:\SMSLogs"; Flags: uninsneveruninstall

[Icons]
; Open a cmd shell already cd'd into the install dir so the user can
; type "collect-config general.lua" without prefixing the path. This
; is the only sensible "shortcut" for a CLI tool -- launching the .exe
; directly from the Start menu would flash a window and exit (it reads
; positional args from the CLI, not an interactive prompt).
;
; The "echo" line is intentional: it prints a header so the operator
; knows what they just opened, AND it lists the available collectors
; in the same view. We do NOT call the binary with `--help` because
; the binary has no `--help` flag (the CLI is positional only:
; `collect-config <script> [perimeter]`). Adding a fake `--help`
; invocation here would just print an error and pollute the shell.
Name: "{group}\{#MyAppName} (command prompt)"; \
  Filename: "{cmd}"; \
  Parameters: "/k cd /d ""{app}"" && echo CollectConfig {#MyAppVersion} && echo. && echo Usage: collect-config ^<script^> [perimeter] && echo Available collectors: && dir /b collectors\*.lua && echo."; \
  WorkingDir: "{app}"; \
  Comment: "Open a command prompt in the CollectConfig install directory."

[InstallDelete]
; Pre-clean: wipe {app}\* before file copy so renamed / removed files
; from previous versions do not linger. Same rationale as
; sdh-complianceapp/Setup/ComplianceSetup.iss (much shorter here: no
; perimeter resources to worry about).
;
; Using "{app}\*" keeps the install dir itself in place so [Files] does
; not have to recreate it.
Type: filesandordirs; Name: "{app}\*"

[UninstallDelete]
; Purge anything Inno did not track in [Files] — e.g. log files written
; by collect-config under {app}\logs\ if RUST_POC_LOG_DIR is ever unset
; and the fallback kicks in. Safe for Program Files (no user data).
;
; C:\SMSLogs is intentionally NOT removed on uninstall: it is shared
; with other Sanofi tools (compliance app, fleet client, …) and may
; contain operational logs the admin wants to preserve. The
; "uninsneveruninstall" flag on the [Dirs] entry encodes this contract.
Type: filesandordirs; Name: "{app}"
; If we were the only Sanofi product, drop the empty parent folder too.
Type: dirifempty; Name: "{autopf64}\{#MyAppPublisher}"
