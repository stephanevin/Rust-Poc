-- Agents category collector — Cloud (AzureAD / MDM) + Endpoint Protection (EP)
--                              + Firewall (FW) + WFP.
--
-- Mirrors the "Agents" tab of Win10-Laptop.json (deviation #39 + #40 + #42 + #43):
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
-- Firewall (deviation #42):
--   SentinelOneFirewallStatus.cs           → sentinel_one_firewall_status
--   WindowsDefenderFirewallStatus.cs       → windows_defender_firewall_status
--   WindowsDefenderFirewallCurrentProfile  → windows_defender_firewall_current_profile
--   WindowsDefenderFirewallDomainState     → windows_defender_firewall_domain_state
--   WindowsDefenderFirewallPrivateState    → windows_defender_firewall_private_state
--   WindowsDefenderFirewallPublicState     → windows_defender_firewall_public_state
--   FirewallRuleCategoryBootTime           → firewall_rule_category_boot_time
--   FirewallRuleCategoryFirewall           → firewall_rule_category_firewall
--   FirewallRuleCategoryStealth            → firewall_rule_category_stealth
--   FirewallRuleCategoryConSec             → firewall_rule_category_con_sec
--
-- WFP (deviation #43):
--   WfpSubLayerDetails.cs → wfp_sublayer_details (sublayer groups, all filters)
--   WfpFirewallView.cs    → wfp_firewall_view    (ALE-filtered, shadowed, deduped)
--   WfpNetEvents.cs       → wfp_net_events       (latest 1000 net events, timestamp DESC)
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

  -- Windows Defender AV — keep only the 6 fields that Win10-Laptop.json
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

  -- Firewall (FW) — deviation #42 -------------------------------------------
  -- SentinelOne firewall — mirrors SentinelOneFirewallStatus.cs which reads
  -- ROOT\SecurityCenter2\FirewallProduct WHERE displayName = 'Sentinel Firewall'
  -- and decodes the productState bitmask via FW_ProductStatus enum (same layout
  -- as AV_ProductStatus in AntiVirusEnums.cs — done in firewall.rs).
  local sc_fw = host.security_center_firewall_products() or {}
  local sentinel_fw = nil
  for _, p in ipairs(sc_fw) do
    if p.name == "Sentinel Firewall" then sentinel_fw = p; break end
  end

  -- Windows Defender Firewall — MSFT_NetConnectionProfile + MSFT_NetFirewallProfile
  -- (root\StandardCimv2).  Provides current_profile + per-profile Enabled states.
  local wdfw = host.windows_defender_firewall_status()

  -- HNetCfg.FwProducts — COM enumeration of products registered with Windows
  -- Firewall and their RuleCategories arrays (INetFwProduct2).
  -- fw_category_owner(cat_id) returns the display name(s) of the product(s)
  -- owning that category, or "Windows Defender Firewall" when none is registered
  -- (the default owner for unclaimed categories — mirrors Firewall.cs semantics).
  local fw_products = host.net_fw_products() or {}
  local function fw_category_owner(cat_id)
    local names = {}
    for _, p in ipairs(fw_products) do
      for _, c in ipairs(p.rule_categories or {}) do
        if c == cat_id then names[#names + 1] = p.name; break end
      end
    end
    return #names == 0 and "Windows Defender Firewall" or table.concat(names, "\n")
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

    -- Windows Defender AV (from ROOT\Microsoft\Windows\Defender\MSFT_MpComputerStatus).
    -- Field names match Win10-Laptop.json WindowsDefender* items.
    windows_defender = windows_defender,

    -- Diagnostic: all Security Center AV products (ghost entries filtered in ep.rs).
    security_center_av_products = sc_av,

    -- Firewall — SentinelOne (from ROOT\SecurityCenter2\FirewallProduct).
    -- nil when Sentinel Firewall is not installed or not registered with Security Center.
    sentinel_one_firewall_status = sentinel_fw and sentinel_fw.state,

    -- Firewall — Windows Defender profile states (root\StandardCimv2).
    windows_defender_firewall_status         = wdfw and wdfw.status,
    windows_defender_firewall_current_profile = wdfw and wdfw.current_profile,
    windows_defender_firewall_domain_state   = wdfw and wdfw.domain_state,
    windows_defender_firewall_private_state  = wdfw and wdfw.private_state,
    windows_defender_firewall_public_state   = wdfw and wdfw.public_state,

    -- Firewall — rule category owners (HNetCfg.FwProducts via INetFwProduct2::RuleCategories).
    -- Values mirror FirewallRuleCategory* items in Win10-Laptop.json.
    firewall_rule_category_boot_time = fw_category_owner(0),
    firewall_rule_category_stealth   = fw_category_owner(1),
    firewall_rule_category_firewall  = fw_category_owner(2),
    firewall_rule_category_con_sec   = fw_category_owner(3),

    -- Diagnostic: all Security Center firewall products (ghost entries filtered in firewall.rs).
    security_center_firewall_products = sc_fw,

    -- WFP (deviation #43) — all three consume the shared WfpState cache
    -- (enumerate_wfp_state is called at most once per run).
    wfp_sublayer_details = host.wfp_sublayer_details(),
    wfp_firewall_view    = host.wfp_firewall_view(),
    wfp_net_events       = host.wfp_net_events(),

    _errors = host.errors(),
  }
end
