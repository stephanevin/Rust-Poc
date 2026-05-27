-- Hardening collector — BitLocker + Credential Guard subset of the
-- "OS Security" section of Win10-Laptop.json.
--
-- Mirrors these ComplianceApp data transformers:
--
--   BitlockerStatus.cs               → bitlocker_status
--   BitLockerEncryptionPercentage.cs → bitlocker_encryption_percentage
--   BitLockerPolicy.cs               → bitlocker_policy
--   BitLockerRecoveryKeyStatus.cs    → bitlocker_recovery_key_status
--   BitLockerRecoveryKeyADBackupSummary.cs       → bitlocker_recovery_key_ad_backup_summary
--   BitLockerRecoveryKeyAzureADBackupSummary.cs  → bitlocker_recovery_key_azure_ad_backup_summary
--   BitLockerRecoveryKeyRotation.cs  → bitlocker_recovery_key_rotation
--   BitLockerDRACertThumbPrints.cs   → bitlocker_dra_cert_thumbprints
--   CredentialGuardStatus.cs         → credential_guard_status        (bool? — HVCI running)
--   CredentialGuardServices.cs       → credential_guard_services      (array<string>?)
--   CredentialGuardVirtualization.cs → credential_guard_virtualization ("Disabled"/"Enabled"/"Running")
--   SecureBootStatus.cs              → secure_boot_status              (registry only — no dedicated binding)
--   Virtualization.cs                → virtualization                (host.virtualization_capability())
--
-- The OSHardening sub-category (`WorkflowName: "OSHardening"`) is served by the
-- WorkflowEngine, not by the collector — intentionally out of scope.

-- ---------------------------------------------------------------------------
-- Local helpers — pure mapping tables, no I/O.
-- ---------------------------------------------------------------------------

-- Win32_EncryptableVolume::GetConversionStatus output ConversionStatus codes.
-- Source: ConversionStatus enum in Components.Windows.BitLocker.Models.BitLockerEnums.cs.
local CONVERSION_STATUS = {
  [0] = "FullyDecrypted",
  [1] = "FullyEncrypted",
  [2] = "EncryptionInProgress",
  [3] = "DecryptionInProgress",
  [4] = "EncryptionPaused",
  [5] = "DecryptionPaused",
}

-- Win32_DeviceGuard.VirtualizationBasedSecurityStatus codes.
-- Source: ComplianceApp.Shared.Enums.CredentialGuard.VirtualizationBasedSecurityStatus.
local VBS_STATUS = {
  [0] = "Disabled",
  [1] = "Enabled",
  [2] = "Running",
}

-- Returns the English label for a ConversionStatus code, or nil for unknown
-- (matching BitLockerStatus.Unknown semantics — the test value compares
-- against the literal "FullyEncrypted").
local function conversion_status_label(code)
  return CONVERSION_STATUS[code]
end

-- Returns the English label for a VBS status code, or "Unknown".
local function vbs_status_label(code)
  return VBS_STATUS[code] or "Unknown"
end

-- NOTE: SecurityServicesRunning codes → English labels are mapped in
-- Rust (`credentialguard::service_label`) and exposed as a JSON array
-- field on `host.credential_guard_status()`. Building the array in Rust
-- is what guarantees the "no services running" case serialises as `[]`
-- rather than `{}` — mlua's array metatable marker is set on `to_value`
-- and read back on `from_value`, but only for arrays constructed Rust-
-- side. A Lua-built table loses the marker and an empty one becomes a
-- JSON object.

-- BitLockerRecoveryKeyStatus.cs returns:
--   - nil   when there are no NumericPassword protectors (no recovery key at all)
--   - true  when the count of escrowed IDs (in either AD or AzureAD) matches
--           the count of NumericPassword protectors
--   - false otherwise
local function recovery_key_status(protector_ids, ad_ids, aad_ids)
  if protector_ids == nil or #protector_ids == 0 then
    return nil
  end
  local n = #protector_ids
  -- Intersect escrowed IDs with protector IDs (case-insensitive — but
  -- both sides have already been lowercased by the Rust bindings).
  local function intersect_count(haystack)
    if haystack == nil then return 0 end
    local seen = {}
    for _, id in ipairs(protector_ids) do seen[id] = true end
    local n_match = 0
    for _, id in ipairs(haystack) do
      if seen[id] then n_match = n_match + 1 end
    end
    return n_match
  end
  return intersect_count(ad_ids) == n or intersect_count(aad_ids) == n
end

-- BitLockerRecoveryKeyADBackupSummary.cs / AzureADBackupSummary.cs return one
-- of three English strings.  `escrow_label` is "AD" or "AzureAD".
local function backup_summary(protector_ids, escrowed_ids, escrow_label)
  if protector_ids == nil or #protector_ids == 0 then
    return "No RecoveryPassword protector detected."
  end
  if escrowed_ids == nil then escrowed_ids = {} end
  -- Same intersection logic as recovery_key_status above — duplicated
  -- here so the function stays self-contained and the comparisons are
  -- explicit at the call site.
  local seen = {}
  for _, id in ipairs(protector_ids) do seen[id] = true end
  local n_match = 0
  for _, id in ipairs(escrowed_ids) do
    if seen[id] then n_match = n_match + 1 end
  end
  if n_match == #protector_ids then
    return "RecoveryKey(s) escrowed in " .. escrow_label
  end
  return "No " .. escrow_label .. " backup event found for a RecoveryKey"
end

-- BitLockerRecoveryKeyRotation.cs maps three states to English strings:
--   true  → "RotationComplete"
--   false → "RotationInProgress"
--   nil   → "None"
local function rotation_label(executed)
  if executed == true then return "RotationComplete" end
  if executed == false then return "RotationInProgress" end
  return "None"
end

-- ---------------------------------------------------------------------------
-- Entry point invoked by InternalRuntime::run.
-- ---------------------------------------------------------------------------

function collect()
  ------------------------------------------------------------------
  -- Secure Boot (registry only — no dedicated binding).
  -- HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled.
  -- Same path SecureBootStatus.cs reads in ComplianceApp.
  ------------------------------------------------------------------
  local sb_raw = host.registry_read(
    "HKLM",
    [[SYSTEM\CurrentControlSet\Control\SecureBoot\State]],
    "UEFISecureBootEnabled"
  )
  local secure_boot_status = nil
  if sb_raw == 1 then secure_boot_status = "Enabled"
  elseif sb_raw == 0 then secure_boot_status = "Disabled" end

  ------------------------------------------------------------------
  -- BitLocker volume status (C:) — single WMI ExecMethod.
  ------------------------------------------------------------------
  local vol = host.bitlocker_volume_status("C:")
  local bitlocker_status = nil
  local bitlocker_encryption_percentage = nil
  if type(vol) == "table" then
    bitlocker_status = conversion_status_label(vol.conversion_status)
    bitlocker_encryption_percentage = vol.encryption_percentage
  end

  ------------------------------------------------------------------
  -- BitLocker recovery key composition.
  -- 3 = KeyProtectorType.NumericPassword (per BitLockerEnums.cs).
  -- 783 = AD backup event; 845 = AzureAD backup event.
  ------------------------------------------------------------------
  local recovery_ids  = host.bitlocker_key_protector_ids("C:", 3)
  local ad_escrowed   = host.bitlocker_escrowed_protector_ids(783)
  local aad_escrowed  = host.bitlocker_escrowed_protector_ids(845)

  local bitlocker_recovery_key_status = recovery_key_status(recovery_ids, ad_escrowed, aad_escrowed)
  local bitlocker_recovery_key_ad_backup_summary       = backup_summary(recovery_ids, ad_escrowed,  "AD")
  local bitlocker_recovery_key_azure_ad_backup_summary = backup_summary(recovery_ids, aad_escrowed, "AzureAD")
  local bitlocker_recovery_key_rotation = rotation_label(host.bitlocker_recovery_key_rotation_executed())

  ------------------------------------------------------------------
  -- Credential Guard — Win32_DeviceGuard.
  ------------------------------------------------------------------
  local cg = host.credential_guard_status()
  local credential_guard_status         = nil  -- raw bool? (HVCI running)
  local credential_guard_services       = nil  -- array<string>?
  local credential_guard_virtualization = "Unknown"
  if type(cg) == "table" then
    -- CredentialGuardStatus.cs returns `s?.SecurityServicesRunning.Any(ssr => ssr == 2u)`
    -- i.e. true when HVCI (code 2) is running.  We mirror that bool
    -- semantics, not the higher-level Credential Guard configured/running
    -- booleans the DTO also exposes.
    if cg.SecurityServicesRunning ~= nil then
      credential_guard_status = false
      for _, code in ipairs(cg.SecurityServicesRunning) do
        if code == 2 then credential_guard_status = true; break end
      end
    end
    credential_guard_services       = cg.security_services_running_labels
    credential_guard_virtualization = vbs_status_label(cg.VirtualizationBasedSecurityStatus)
  end

  ------------------------------------------------------------------
  -- Assemble result.  Key names follow the snake_case convention
  -- already used by general.lua and accounts.lua.
  ------------------------------------------------------------------
  local result = {
    -- BitLocker (`Hard Disk Encryption (BitLocker)` category in Win10-Laptop.json).
    bitlocker_status                              = bitlocker_status,
    bitlocker_encryption_percentage               = bitlocker_encryption_percentage,
    bitlocker_policy                              = host.bitlocker_policy(),
    bitlocker_recovery_key_status                 = bitlocker_recovery_key_status,
    bitlocker_recovery_key_ad_backup_summary      = bitlocker_recovery_key_ad_backup_summary,
    bitlocker_recovery_key_azure_ad_backup_summary= bitlocker_recovery_key_azure_ad_backup_summary,
    bitlocker_recovery_key_rotation               = bitlocker_recovery_key_rotation,
    bitlocker_dra_cert_thumbprints                = host.bitlocker_dra_thumbprints("C:"),

    -- Credential Guard (`Credential Guard` category).
    credential_guard_status                       = credential_guard_status,
    credential_guard_services                     = credential_guard_services,
    credential_guard_virtualization               = credential_guard_virtualization,

    -- Shared by both categories.
    -- `virtualization` mirrors ComplianceApp/DataTransformers/BIOS/Virtualization.cs:
    -- (VMMonitorModeExtensions && VirtualizationFirmwareEnabled) || HypervisorPresent.
    -- It answers "can this host do virtualization?" — NOT "is this host a VM?"
    -- (that question belongs to `host.virtual_machine()`, exposed by general.lua).
    secure_boot_status                            = secure_boot_status,
    virtualization                                = host.virtualization_capability(),
  }

  -- Attach _errors only when at least one binding failed (keeps the
  -- payload clean for a healthy run).  Same idiom as the other collectors.
  local errs = host.errors()
  local has_errs = false
  for _ in pairs(errs) do has_errs = true; break end
  if has_errs then result._errors = errs end

  return result
end
