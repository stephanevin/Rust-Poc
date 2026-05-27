-- Agents category collector — Cloud (AzureAD / MDM) + Endpoint Protection (EP).
--
-- Mirrors the "Agents" tab of Win10-Laptop.json (deviation #39 + #40):
--
-- Cloud (deviation #39):
--   AzureAdJoinedStatus.cs    → azure_ad_joined_status    ("On"/"Off"/"CertificateIsNotValid")
--   AzureAdDeviceId.cs        → azure_ad_device_id        (string?)
--   MdmStatus.cs              → mdm_status                ("On"/"Off"/"CertificateIsNotValid")
--   MdmDeviceId.cs            → mdm_device_id             (string?)
--   MdmCoManagementFlags.cs   → mdm_co_management_flags   (string? — DWORD as decimal)
--   LastMdmSyncDate.cs        → mdm_last_sync_date         (ISO 8601 UTC string?)
--   LastMdmSyncResult.cs      → mdm_last_sync_result       (HRESULT string?)
--   LastMdmSyncSuccessDate.cs → mdm_last_sync_success_date (ISO 8601 UTC string?)
--
-- Endpoint Protection — AV (deviation #40):
--   SentinelOneAntiVirusStatus.cs  → sentinel_one_anti_virus_status  (AV_ProductStatus:  "On"/"Off"/…)
--   SentinelOneUpToDate.cs         → sentinel_one_up_to_date         (AV_SignatureStatus: "UpToDate"/"OutOfDate")
--   WindowsDefender*.cs            → windows_defender            (6 fields from MSFT_MpComputerStatus)
--
-- Both SentinelOne transformers read ROOT\SecurityCenter2\AntiVirusProduct WHERE
-- displayName = 'Sentinel Agent', then decode the productState bitmask exactly
-- as AntiVirusEnums.cs (done in ep.rs).  security_center_av_products is kept as
-- a diagnostic field exposing all registered AV products.
--
-- Run via:
--   cargo run -- agents.lua
-- or:
--   cargo run -- agents.lua <perimeter>

function collect()
  local mdm_sync = host.mdm_sync_status()

  -- SentinelOne AV status — mirrors SentinelOneAntiVirusStatus.cs +
  -- SentinelOneUpToDate.cs which both call
  -- GetSentinelOneSecurityCenterAntiVirusProduct() (WHERE displayName =
  -- 'Sentinel Agent') and decode the productState bitmask via
  -- AV_ProductStatus / AV_SignatureStatus enums.
  -- ep.rs does the same bitmask decode; we just filter here.
  local sc_av = host.security_center_av_products() or {}
  local sentinel_one = nil
  for _, p in ipairs(sc_av) do
    if p.name == "Sentinel Agent" then sentinel_one = p; break end
  end

  -- Windows Defender — keep only the 6 fields that Win10-Laptop.json
  -- exposes under WindowsDefender* items.  The raw MSFT_MpComputerStatus
  -- row has ~55 properties; the others are not part of the definition.
  local wd_fields = {
    "AMServiceEnabled",
    "AMRunningMode",
    "AMProductVersion",
    "AntivirusEnabled",
    "RealTimeProtectionEnabled",
    "ProductStatus",
  }
  local wd_raw = host.windows_defender_status()
  local windows_defender = nil
  if wd_raw then
    windows_defender = {}
    for _, key in ipairs(wd_fields) do
      windows_defender[key] = wd_raw[key]
    end
  end

  return {
    -- Cloud — AzureAD join status + MDM/Intune enrollment.
    azure_ad_joined_status     = host.azure_ad_joined_status(),
    azure_ad_device_id         = host.azure_ad_device_id(),
    mdm_status                 = host.mdm_status(),
    mdm_device_id              = host.mdm_device_id(),
    mdm_co_management_flags    = host.mdm_co_management_flags(),
    mdm_last_sync_date         = mdm_sync and mdm_sync.last_sync_date,
    mdm_last_sync_result       = mdm_sync and mdm_sync.last_sync_result,
    mdm_last_sync_success_date = mdm_sync and mdm_sync.last_success_sync_date,

    -- SentinelOne AV (from ROOT\SecurityCenter2, WHERE displayName = 'Sentinel Agent').
    -- snake_case mirrors the existing convention (azure_ad_joined_status → AzureAdJoinedStatus, …).
    -- nil when SentinelOne is not installed or not registered with Security Center.
    sentinel_one_anti_virus_status = sentinel_one and sentinel_one.state,
    sentinel_one_up_to_date        = sentinel_one and sentinel_one.signatures,

    -- Windows Defender (from ROOT\Microsoft\Windows\Defender\MSFT_MpComputerStatus).
    -- Field names match Win10-Laptop.json WindowsDefender* items.
    windows_defender = windows_defender,

    -- Diagnostic: all Security Center AV products (ghost entries filtered in ep.rs).
    security_center_av_products = sc_av,

    _errors = host.errors(),
  }
end
