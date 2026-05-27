-- Cloud category collector — AzureAD join status, MDM/Intune enrollment,
-- co-management flags, and MDM sync status.
--
-- Mirrors these ComplianceApp data transformers (deviation #39):
--
--   AzureAdJoinedStatus.cs   → azure_ad_joined_status   ("On"/"Off"/"CertificateIsNotValid")
--   AzureAdDeviceId.cs       → azure_ad_device_id       (string?)
--   MdmStatus.cs             → mdm_status               ("On"/"Off"/"CertificateIsNotValid")
--   MdmDeviceId.cs           → mdm_device_id            (string?)
--   MdmCoManagementFlags.cs  → mdm_co_management_flags  (string? — DWORD as decimal)
--   LastMdmSyncDate.cs       → last_mdm_sync_date       (ISO 8601 UTC string?)
--   LastMdmSyncResult.cs     → last_mdm_sync_result     (HRESULT string?)
--   LastMdmSyncSuccessDate.cs→ last_mdm_sync_success_date (ISO 8601 UTC string?)
--
-- Run via:
--   cargo run -- agents.lua
-- or:
--   cargo run -- agents.lua <perimeter>

function collect()
  local mdm_sync = host.mdm_sync_status()
  return {
    azure_ad_joined_status     = host.azure_ad_joined_status(),
    azure_ad_device_id         = host.azure_ad_device_id(),
    mdm_status                 = host.mdm_status(),
    mdm_device_id              = host.mdm_device_id(),
    mdm_co_management_flags    = host.mdm_co_management_flags(),
    last_mdm_sync_date         = mdm_sync and mdm_sync.last_sync_date,
    last_mdm_sync_result       = mdm_sync and mdm_sync.last_sync_result,
    last_mdm_sync_success_date = mdm_sync and mdm_sync.last_success_sync_date,
    _errors = host.errors(),
  }
end
