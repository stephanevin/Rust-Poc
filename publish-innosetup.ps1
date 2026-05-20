<#
.SYNOPSIS
    Builds collect-config in release mode, stages it into ./publish/, then
    compiles the CollectConfig EXE via Inno Setup (with optional signing).

.DESCRIPTION
    Sole installer build pipeline for Rust-Poc. Modelled on
    sdh-complianceapp/publish-all-innosetup.ps1 but adapted for Rust:

      1. cargo build --release --bin collect-config
      2. Stage target/release/collect-config.exe + collectors/*  ->  ./publish/
         (the Rust analogue of `dotnet publish` -- cargo has no built-in
         publish step, so we materialise the deployment layout by hand)
      3. Sign collect-config.exe in-place under ./publish/ (pass #1)
      4. ISCC.exe compiles Setup/CollectConfigSetup.iss, embedding the
         signed binary into the installer payload and (when /DSIGN is
         passed) signing the final EXE + uninstaller as pass #2.
      5. Sanity-check the produced EXE has a valid Authenticode signature.

    The two-pass signing pattern matters because LZMA-compressed payloads
    inside the EXE are NOT individually re-signable after the fact -- any
    binary that ships embedded must be signed before ISCC consumes it.
    For Rust-Poc this is currently a single .exe (statically linked), but
    keeping the pattern is what lets us add a future bundled .dll without
    a code change.

.PARAMETER ProductVersion
    Version stamped into the EXE (AppVersion in [Setup] and
    OutputBaseFilename). Defaults to the `version = "..."` line in
    /Cargo.toml (single source of truth for the product version). Override
    only for ad-hoc builds where the EXE version must differ from the
    binary (rare).

.PARAMETER SkipBuild
    Skip `cargo build`. Useful when iterating on the .iss script alone
    with a ./publish/ folder already populated from a previous run.

.PARAMETER SkipSign
    Skip Authenticode signing of the binary AND the final installer EXE.
    Local dev iterations only -- every artefact shipped to customers
    MUST be signed.

.PARAMETER SignThumbprint
    SHA-1 thumbprint of the code-signing certificate to use. Defaults to
    the SDH_SIGN_THUMBPRINT user environment variable (same convention
    as sdh-complianceapp). The certificate must already be imported into
    Cert:\CurrentUser\My (one-time setup via Import-PfxCertificate); the
    private key is then protected by Windows DPAPI scoped to the current
    user, so no .pfx password is needed at build time.

.PARAMETER TimestampUrl
    RFC 3161 timestamp authority. A timestamped signature stays valid
    past the certificate's expiration date -- non-negotiable for shipped
    binaries.

.EXAMPLE
    .\publish-innosetup.ps1
    .\publish-innosetup.ps1 -ProductVersion 0.2.0
    .\publish-innosetup.ps1 -SkipBuild           # rebuild only the EXE
    .\publish-innosetup.ps1 -SkipSign            # local dev, no signing
#>

[CmdletBinding()]
param(
    [string]$ProductVersion,
    [switch]$SkipBuild,
    [switch]$SkipSign,
    [string]$SignThumbprint = $env:SDH_SIGN_THUMBPRINT,
    [string]$TimestampUrl   = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$root         = $PSScriptRoot
$cargoToml    = Join-Path $root 'Cargo.toml'
$collectors   = Join-Path $root 'collectors'
$releaseExe   = Join-Path $root 'target\release\collect-config.exe'
$publishDir   = Join-Path $root 'publish'
$publishExe   = Join-Path $publishDir 'collect-config.exe'
$issScript    = Join-Path $root 'Setup\CollectConfigSetup.iss'

# -----------------------------------------------------------------------------
# Version resolution
#
# Cargo.toml is the single source of truth for the product version, same role
# as Directory.Build.props in the .NET world. We read it with a simple regex
# rather than pulling in a TOML parser dependency -- the file is small and
# the `version = "x.y.z"` line is canonical.
# -----------------------------------------------------------------------------
$versionSource = '-ProductVersion parameter'
if (-not $ProductVersion) {
    if (-not (Test-Path -LiteralPath $cargoToml)) {
        throw "Cargo.toml not found at $cargoToml and no -ProductVersion was provided."
    }
    # Scope the search to the [package] section ONLY. A naive "first
    # version = ..." match would silently pick up the wrong line if a
    # future [workspace.package] block (or any other section with a
    # version key) is added above [package]. We anchor on `[package]`
    # and stop at the next section header `[...]` to keep the match
    # locked to the right TOML table.
    $cargoContent = Get-Content -LiteralPath $cargoToml -Raw
    $packageMatch = [regex]::Match(
        $cargoContent,
        '(?ms)^\[package\]\s*$(?<body>.*?)(?=^\[|\z)'
    )
    if (-not $packageMatch.Success) {
        throw "No [package] section found in $cargoToml. Pass -ProductVersion explicitly."
    }
    $versionMatch = [regex]::Match(
        $packageMatch.Groups['body'].Value,
        '(?m)^\s*version\s*=\s*"([^"]+)"'
    )
    if (-not $versionMatch.Success) {
        throw "No `version = `"...`"` line in the [package] section of $cargoToml. Pass -ProductVersion explicitly."
    }
    $ProductVersion = $versionMatch.Groups[1].Value
    $versionSource  = 'Cargo.toml [package].version'
}

# -----------------------------------------------------------------------------
# Tool discovery
# -----------------------------------------------------------------------------
function Find-Iscc {
    $candidates = @(
        (Get-Command 'ISCC.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source),
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles         'Inno Setup 6\ISCC.exe')
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    return $null
}

function Find-SignTool {
    $onPath = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Source
    if ($onPath) { return $onPath }

    $sdkRoots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path $env:ProgramFiles         'Windows Kits\10\bin')
    )
    $archPriority = @('x64', 'arm64', 'x86')

    foreach ($root in $sdkRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($arch in $archPriority) {
            $candidates = Get-ChildItem -LiteralPath $root -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -like "*\$arch\signtool.exe" } |
                ForEach-Object {
                    $versionDir = $_.Directory.Parent.Name
                    $parsed = $null
                    if ([version]::TryParse($versionDir, [ref]$parsed)) {
                        [pscustomobject]@{ Path = $_.FullName; Version = $parsed }
                    }
                }
            $found = $candidates | Sort-Object Version -Descending | Select-Object -First 1 -ExpandProperty Path
            if ($found) { return $found }
        }
    }
    return $null
}

function Invoke-SignFile {
    param(
        [Parameter(Mandatory)] [string] $SignTool,
        [Parameter(Mandatory)] [string] $Thumbprint,
        [Parameter(Mandatory)] [string] $TimestampUrl,
        [Parameter(Mandatory)] [string] $File
    )
    # SHA-256 across the board: /fd sha256 (file digest) and /td sha256
    # (timestamp digest). RFC 3161 timestamp via /tr is what makes the
    # signature outlive the certificate.
    $signArgs = @(
        'sign',
        '/sha1', $Thumbprint,
        '/fd',   'sha256',
        '/tr',   $TimestampUrl,
        '/td',   'sha256',
        $File
    )
    & $SignTool @signArgs
    if ($LASTEXITCODE -ne 0) { throw "signtool failed on $File (exit $LASTEXITCODE)." }
}

# -----------------------------------------------------------------------------
# Pre-flight validation
#
# Run all "fast and certain to fail" checks BEFORE the (slow) cargo build.
# Catching a bad config here saves the user ~30 seconds per wrong run.
# -----------------------------------------------------------------------------
Write-Host "CollectConfig - Inno Setup publish orchestrator" -ForegroundColor Yellow
Write-Host "  Product version : $ProductVersion (source: $versionSource)"
Write-Host "  Repo root       : $root"
Write-Host ""
Write-Host "==> Pre-flight validation" -ForegroundColor Cyan

$iscc = Find-Iscc
if (-not $iscc) {
    throw "ISCC.exe (Inno Setup Compiler) not found. Install Inno Setup 6 first:`n" +
          "    winget install JRSoftware.InnoSetup`n" +
          "or add ISCC.exe to PATH."
}
Write-Host "    ISCC       : $iscc"

$signTool    = $null
$certInStore = $null
if (-not $SkipSign) {
    # Thumbprint resolution: param/env (Process) -> User scope -> Machine scope.
    # The Process scope was already populated by the default parameter value
    # binding $env:SDH_SIGN_THUMBPRINT at parse time, so we only need the
    # User/Machine fallbacks here.
    if ([string]::IsNullOrWhiteSpace($SignThumbprint)) {
        $userScope = [Environment]::GetEnvironmentVariable('SDH_SIGN_THUMBPRINT', 'User')
        if (-not [string]::IsNullOrWhiteSpace($userScope)) {
            $SignThumbprint = $userScope
            $env:SDH_SIGN_THUMBPRINT = $SignThumbprint
            Write-Host "    (using SDH_SIGN_THUMBPRINT from User scope - current session was stale)" -ForegroundColor DarkYellow
        }
    }
    if ([string]::IsNullOrWhiteSpace($SignThumbprint)) {
        $machineScope = [Environment]::GetEnvironmentVariable('SDH_SIGN_THUMBPRINT', 'Machine')
        if (-not [string]::IsNullOrWhiteSpace($machineScope)) {
            $SignThumbprint = $machineScope
            $env:SDH_SIGN_THUMBPRINT = $SignThumbprint
            Write-Host "    (using SDH_SIGN_THUMBPRINT from Machine scope)" -ForegroundColor DarkYellow
        }
    }
    if ([string]::IsNullOrWhiteSpace($SignThumbprint)) {
        throw "Signing thumbprint not provided. Either:`n" +
              "  - Set the SDH_SIGN_THUMBPRINT user environment variable, or`n" +
              "  - Pass -SignThumbprint <hex>, or`n" +
              "  - Pass -SkipSign for local dev iterations.`n" +
              "Import the .p12 once with Import-PfxCertificate -CertStoreLocation Cert:\CurrentUser\My."
    }

    # Accept SHA-1 (40 hex) or SHA-256 (64 hex) thumbprint, normalise to
    # uppercase hex without separators. Guards against the classic
    # copy-paste of the literal "<thumbprint>" placeholder.
    $cleanThumb = ($SignThumbprint -replace '[\s:]', '').ToUpperInvariant()
    if ($cleanThumb -notmatch '^[0-9A-F]{40}([0-9A-F]{24})?$') {
        throw "Invalid signing thumbprint '$SignThumbprint'. Expected 40 hex characters (SHA-1) or 64 (SHA-256)."
    }
    $SignThumbprint = $cleanThumb

    $signTool = Find-SignTool
    if (-not $signTool) {
        throw "signtool.exe not found. Install the Windows 10/11 SDK or add signtool.exe to PATH.`n" +
              "    winget install Microsoft.WindowsSDK.10.0.26100"
    }

    $certInStore = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $SignThumbprint }
    $certScope = 'CurrentUser'
    if (-not $certInStore) {
        $certInStore = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $SignThumbprint }
        if ($certInStore) { $certScope = 'LocalMachine' }
    }
    if (-not $certInStore) {
        throw "Certificate with thumbprint '$SignThumbprint' not found in Cert:\CurrentUser\My or Cert:\LocalMachine\My."
    }
    if ($certInStore.NotAfter -lt (Get-Date)) {
        throw "Certificate '$SignThumbprint' expired on $($certInStore.NotAfter). Renew it before signing."
    }
    if (-not $certInStore.HasPrivateKey) {
        throw "Certificate '$SignThumbprint' is in the store but its private key is not accessible from this account."
    }

    Write-Host "    SignTool   : $signTool"
    Write-Host "    Cert       : $($certInStore.Subject)"
    Write-Host "    Store      : Cert:\$certScope\My"
    Write-Host "    Thumbprint : $SignThumbprint"
    Write-Host "    Expires    : $($certInStore.NotAfter)"
    Write-Host "    Timestamp  : $TimestampUrl"

    if ($certInStore.NotAfter -lt (Get-Date).AddDays(30)) {
        Write-Host "    WARNING: signing certificate expires in less than 30 days." -ForegroundColor Yellow
    }
} else {
    Write-Host "    Signing    : DISABLED (-SkipSign)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------
if (-not $SkipBuild) {
    Write-Host ""
    Write-Host "==> cargo build --release --bin collect-config" -ForegroundColor Cyan
    & cargo build --release --bin collect-config
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)." }
    Write-Host "    OK" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  Skipping cargo build (-SkipBuild)" -ForegroundColor DarkYellow
}

if (-not (Test-Path -LiteralPath $releaseExe)) {
    throw "Expected release artefact missing: $releaseExe. Drop -SkipBuild and re-run."
}

# -----------------------------------------------------------------------------
# Staging
#
# Materialise the deployment layout under ./publish/. Equivalent to a
# `dotnet publish` step in the .NET world -- cargo has no built-in
# concept of a publish folder, so we do it by hand.
#
# We wipe ./publish/ entirely before copy so a previous staging with
# leftover files (e.g. a collector renamed since last build) cannot
# leak into the new installer.
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "==> Staging into ./publish/" -ForegroundColor Cyan
if (Test-Path -LiteralPath $publishDir) {
    Remove-Item -LiteralPath $publishDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

Copy-Item -LiteralPath $releaseExe -Destination $publishExe -Force
Copy-Item -LiteralPath $collectors -Destination (Join-Path $publishDir 'collectors') -Recurse -Force

Write-Host "    collect-config.exe  $((Get-Item $publishExe).Length) bytes"
Write-Host "    collectors\         $((Get-ChildItem (Join-Path $publishDir 'collectors') -File).Count) file(s)"

# -----------------------------------------------------------------------------
# Signing pass #1: sign collect-config.exe inside ./publish/ BEFORE ISCC
# embeds it into the LZMA-compressed payload. Signing it after the fact
# is impossible (the bytes are inside the installer).
# -----------------------------------------------------------------------------
if (-not $SkipSign) {
    Write-Host ""
    Write-Host "==> Signing collect-config.exe" -ForegroundColor Cyan
    Invoke-SignFile -SignTool $signTool -Thumbprint $SignThumbprint `
                    -TimestampUrl $TimestampUrl -File $publishExe
    Write-Host "    OK" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# Inno Setup compilation + signing pass #2 (in-ISCC)
#
# /Qp      : quiet but print progress
# /DMyAppVersion=<v> : inject the version into [Setup] AppVersion + OutputBaseFilename
# /DSIGN=1 : activates the #ifdef SIGN block in the .iss (SignTool=sdh +
#            SignedUninstaller=yes). Without this, ISCC compiles an unsigned EXE.
# /Ssdh=<wrapper.cmd> $f : registers the "sdh" SignTool referenced by
#            SignTool=sdh in the .iss. Inno invokes the wrapper once for
#            the final EXE and once for the embedded uninstaller, replacing
#            $f with the path to sign.
#
# Why a .cmd wrapper instead of inlining signtool into /Ssdh=:
#   PowerShell 5.1's native arg quoting cannot reliably forward an
#   argument that contains BOTH spaces AND embedded double quotes
#   (signtool path has spaces under Program Files; $f must stay quoted
#   for files with spaces). The classic symptom is ISCC seeing the
#   second word of the SignTool command as a second script filename
#   and aborting with "You may not specify more than one script
#   filename." The generated .cmd takes $f as %1 and re-quotes
#   internally using batch rules. No round-trip through PS arg parsing.
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "==> Building EXE (Inno Setup)" -ForegroundColor Cyan
Write-Host "    Script: $issScript"

$isccArgs    = @('/Qp', "/DMyAppVersion=$ProductVersion")
$wrapperPath = $null
if (-not $SkipSign) {
    $isccArgs += '/DSIGN=1'
    $wrapperPath = Join-Path $env:TEMP ("collect-config-innosetup-signtool-{0}-{1}.cmd" -f $PID, ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $wrapperBody = @"
@echo off
set "ST=$signTool"
set "TH=$SignThumbprint"
set "TS=$TimestampUrl"
"%ST%" sign /sha1 "%TH%" /fd sha256 /tr "%TS%" /td sha256 "%~1"
"@
    [System.IO.File]::WriteAllText($wrapperPath, $wrapperBody, [System.Text.Encoding]::ASCII)
    # Inno tokenises /Ssdh= on space: wrapper path = executable, "$f" = its single argument.
    $isccArgs += "/Ssdh=$wrapperPath `$f"
}
$isccArgs += $issScript

try {
    & $iscc @isccArgs
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed (exit $LASTEXITCODE)." }
}
finally {
    if ($wrapperPath -and (Test-Path -LiteralPath $wrapperPath)) {
        Remove-Item -LiteralPath $wrapperPath -ErrorAction SilentlyContinue
    }
}

$exePath = Join-Path $root "Setup\Output\CollectConfigSetup-$ProductVersion.exe"
Write-Host "    OK -> $exePath" -ForegroundColor Green

# -----------------------------------------------------------------------------
# Sanity check: re-read the produced EXE and verify its Authenticode
# signature. Catches the silent failure mode where ISCC's SignTool
# invocation succeeded exit-code-wise but for some reason did not
# actually attach a signature (wrong $f escaping signing a sibling, etc).
# -----------------------------------------------------------------------------
if (-not $SkipSign) {
    $sig = Get-AuthenticodeSignature -FilePath $exePath
    if ($sig.Status -ne 'Valid') {
        throw "Final EXE has an invalid Authenticode status: $($sig.Status) - $($sig.StatusMessage)"
    }
    Write-Host "    Signature  : $($sig.Status) (signed by $($sig.SignerCertificate.Subject))" -ForegroundColor Green
}

Write-Host ""
Write-Host "Installer built successfully." -ForegroundColor Green
