-- Agents category collector — Cloud (AzureAD / MDM) + Endpoint Protection (EP)
--                              + Firewall (FW) + WFP + LAPS + SentinelOne EDR
--                              + CyberArk EPM (PAM).
--
-- Mirrors the "Agents" tab of Win10-Laptop.json (deviation #39 + #40 + #42 + #43 + #44 + #45 + #46):
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
-- LAPS (deviation #44):
--   AutoLapsMode.cs                → auto_laps_mode             ("Not Installed"/"Legacy"/"Windows")
--   WindowsLapsBackupDirectory.cs  → windows_laps_backup_dir    ("Disabled"/"MicrosoftEntra"/"ActiveDirectory"/"ActiveDirectoryLegacy")
--   WindowsLapsPolicy.cs           → windows_laps_policy        ("None"/"CSP"/"GroupPolicy"/"LocalConfiguration"/"LegacyMicrosoftLaps")
--   WindowsLapsDllLocation.cs      → windows_laps_dll_location  ("Found"/"NotFound")
--   LegacyLapsGpExtension.cs       → legacy_laps_gp_extension   (bool)
--   LocalAdminPasswordDate.cs      → local_admin_password_date  (ISO 8601 UTC string?; built-in Administrator SID *-500)
--   WindowsLapsMaxPwdAge.cs        → windows_laps_max_pwd_age   (int? days)
--
-- All six host.laps_state() fields come from one stateless call (registry +
-- System32 DLL probes); local_admin_password_date is derived from
-- host.local_user_accounts() (deviation #20).
--
-- SentinelOne EDR (deviation #45):
--   SentinelOneStatus.cs               → sentinel_one_status                  (bool: SentinelCtl.exe present AND COM status available)
--   SentinelOneAgentFound.cs           → sentinel_one_agent_found            ("Found"/"NotFound" — tests sentinelAgent.exe, see deviation #45.2)
--   SentinelOneAgentRunning.cs         → sentinel_one_agent_running          (bool?)
--   SentinelOneAgentVersion.cs         → sentinel_one_agent_version          (string?)
--   SentinelOneEnforcingSecurity.cs    → sentinel_one_enforcing_security     (bool?)
--   SentinelOneManagementUrl.cs        → sentinel_one_management_url         (string?)
--   SentinelOneLastSeenDate.cs         → sentinel_one_last_seen_date         (ISO 8601 string?)
--   SentinelOneActiveThreatsPresent.cs → sentinel_one_active_threats_present ("Yes"/"No")
--   SentinelOneAgentId.cs              → sentinel_one_agent_id               (string?)
--   SentinelOneAgentInstallTime.cs     → sentinel_one_agent_install_time     (ISO 8601 string?)
--   SentinelOneAgentPpl.cs             → sentinel_one_agent_ppl              (bool?)
--   SentinelOneCommSdkMessage.cs       → sentinel_one_comm_sdk_message       (string?)
--   SentinelOneCommSdkMessageDate.cs   → sentinel_one_comm_sdk_message_date  (ISO 8601 string?)
--   SentinelOneDetectionMode.cs        → sentinel_one_detection_mode         (string?)
--   SentinelOneSelfProtectionEnabled.cs→ sentinel_one_self_protection_enabled(bool?)
--   SentinelOneSite.cs                 → sentinel_one_site                   (string?)
--
-- The 13 agent fields come from one COM IDispatch call (host.sentinel_one_agent_status());
-- the parent + agent_found from host.sentinel_one_paths(); the CommSdk pair from
-- host.sentinel_one_comm_sdk().  sentinel_one_agent_paths is exposed as a
-- diagnostic enrichment (full sentinelAgent.exe list, beyond the 15 C# items).
--
-- CyberArk EPM / PAM (deviation #46):
--   CyberArkEpmDriverStatus.cs         → cyber_ark_epm_driver_status           ("Running"/"Stopped"/.../"None")
--   CyberArkEpmAgentVersion.cs         → cyber_ark_epm_agent_version           (string?)
--   CyberArkEpmDispatcherUrl.cs        → cyber_ark_epm_dispatcher_url          (string?)
--   CyberArkEpmId.cs                   → cyber_ark_epm_id                      (string?)
--   CyberArkEpmLastPolicyUpdateDate.cs → cyber_ark_epm_last_policy_update_date (ISO 8601 UTC string?)
--   CyberArkEpmRegisteredAt.cs         → cyber_ark_epm_registered_at           (string?)
--
-- driver_status comes from the vfpd kernel driver via the SC Manager
-- (host.cyber_ark_epm_driver_status()); the other 5 are registry reads from
-- HKLM\SOFTWARE\Viewfinity\Agent.  Raw emission: a missing EPM install yields
-- "None" + nil values, so no RemoveWhen-style derivation is needed.
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

  -- LAPS (deviation #44) -----------------------------------------------------
  -- host.laps_state() returns the whole LAPS posture in one stateless call.
  -- local_admin_password_date is derived from host.local_user_accounts()
  -- (deviation #20): the built-in Administrator is the account whose SID ends
  -- in "-500" — same selector as Security.cs (PrincipalContext.Machine +
  -- Sid.Value.EndsWith("-500")). last_password_set is already ISO 8601 UTC.
  local laps = host.laps_state()
  local local_admin_password_date = nil
  local accounts = host.local_user_accounts()
  if accounts then
    for _, acc in ipairs(accounts) do
      if acc.sid and acc.sid:sub(-4) == "-500" then
        local_admin_password_date = acc.last_password_set
        break
      end
    end
  end

  -- SentinelOne EDR (deviation #45) ------------------------------------------
  -- Three sources: COM IDispatch agent status, filesystem paths, Event Log.
  local s1 = host.sentinel_one_agent_status()  -- table|nil (13 fields, COM)
  local s1_paths = host.sentinel_one_paths()   -- {folder, ctl_paths[], agent_paths[]}
  local s1_comm = host.sentinel_one_comm_sdk() -- {message, date}|nil

  -- ctl present ≡ GetSentinelOneFindCtlPath() != null; agent present ≡
  -- sentinelAgent.exe found (deviation #45.2: the C# AgentFound tests the
  -- folder, we test the executable to match its "Agent Executable" label).
  local s1_ctl_found = s1_paths and #s1_paths.ctl_paths > 0
  local s1_agent_found = s1_paths and #s1_paths.agent_paths > 0
  -- Parent SentinelOneStatus: SentinelCtl.exe present AND COM status available.
  local s1_installed = s1_ctl_found and (s1 ~= nil) or false

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

    -- LAPS (deviation #44) — one stateless host.laps_state() call + the
    -- built-in Administrator password date from host.local_user_accounts().
    auto_laps_mode             = laps and laps.auto_laps_mode,
    windows_laps_backup_dir    = laps and laps.laps_backup_directory,
    windows_laps_policy        = laps and laps.laps_policy,
    windows_laps_dll_location  = laps and laps.windows_laps_dll_state,
    legacy_laps_gp_extension   = laps and laps.legacy_gp_extension_present,
    local_admin_password_date  = local_admin_password_date,
    windows_laps_max_pwd_age   = laps and laps.max_pwd_age_days,

    -- SentinelOne EDR (deviation #45) — 15 C# items + 2 diagnostic path lists.
    sentinel_one_status                  = s1_installed,
    sentinel_one_agent_found             = s1_agent_found and "Found" or "NotFound",
    sentinel_one_agent_running           = s1 and s1.agent_running,
    sentinel_one_agent_version           = s1 and s1.agent_version,
    sentinel_one_enforcing_security      = s1 and s1.enforcing_security,
    sentinel_one_management_url          = s1 and s1.management_url,
    sentinel_one_last_seen_date          = s1 and s1.last_seen,
    -- C# maps null/false → "No" when the agent status is present (only nil
    -- when SentinelOne itself is absent), so test `== true` explicitly.
    sentinel_one_active_threats_present  = s1 and (s1.active_threats_present == true and "Yes" or "No"),
    sentinel_one_agent_id                = s1 and s1.agent_id,
    sentinel_one_agent_install_time      = s1 and s1.agent_install_time,
    sentinel_one_agent_ppl               = s1 and s1.agent_ppl,
    sentinel_one_comm_sdk_message        = s1_comm and s1_comm.message,
    sentinel_one_comm_sdk_message_date   = s1_comm and s1_comm.date,
    sentinel_one_detection_mode          = s1 and s1.detection_mode,
    sentinel_one_self_protection_enabled = s1 and s1.self_protection_enabled,
    sentinel_one_site                    = s1 and s1.site,

    -- Diagnostic enrichment (beyond the 15 C# items): every sentinelAgent.exe
    -- found (location + version of each install). ctl_paths is intentionally
    -- not exposed — same folder as agent_paths, and SentinelCtl.exe presence
    -- is already encoded in sentinel_one_status.
    sentinel_one_agent_paths             = s1_paths and s1_paths.agent_paths or {},

    -- CyberArk EPM / PAM (deviation #46) — 6 stateless bindings. driver_status
    -- comes from the vfpd kernel driver (SC Manager); the rest are registry
    -- reads. Raw emission: "None" + nil values when EPM is not installed.
    cyber_ark_epm_driver_status           = host.cyber_ark_epm_driver_status(),
    cyber_ark_epm_agent_version           = host.cyber_ark_epm_version(),
    cyber_ark_epm_dispatcher_url          = host.cyber_ark_epm_dispatcher_url(),
    cyber_ark_epm_id                      = host.cyber_ark_epm_id(),
    cyber_ark_epm_last_policy_update_date = host.cyber_ark_epm_last_policy_update(),
    cyber_ark_epm_registered_at           = host.cyber_ark_epm_registered_at(),

    _errors = host.errors(),
  }
end
