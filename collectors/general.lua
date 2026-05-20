-- Default fleet collector: gathers the 25 General-section items defined
-- in sdh-complianceapp/ComplianceApp/Resources/Definitions/Win10-Laptop.json.
--
-- The sdh-client Lua runtime sandboxes the environment; only the `host`
-- table is available for I/O. Any per-field failure is recorded into
-- host.errors() and the field is set to nil in the output.

local function dotnet_version_from_release(release)
  if not release then return nil end
  if     release >= 533320 then return "4.8.1"
  elseif release >= 528040 then return "4.8"
  elseif release >= 461808 then return "4.7.2"
  elseif release >= 461308 then return "4.7.1"
  elseif release >= 460798 then return "4.7"
  elseif release >= 394802 then return "4.6.2"
  elseif release >= 394254 then return "4.6.1"
  elseif release >= 393295 then return "4.6"
  elseif release >= 378675 then return "4.5.1"
  elseif release >= 378389 then return "4.5"
  else return nil end
end

local function os_product_name(ver)
  if not ver then return nil end
  -- We don't call GetProductInfo here; RtlGetVersion in the host binding
  -- returns {major, minor, build} and we classify coarsely. Phase 2 can
  -- add the full GetProductInfo enum if DS needs it.
  if     ver.major == 10 and ver.build >= 22000 then return "Windows 11"
  elseif ver.major == 10 then return "Windows 10"
  elseif ver.major == 6 and ver.minor == 3 then return "Windows 8.1"
  elseif ver.major == 6 and ver.minor == 2 then return "Windows 8"
  elseif ver.major == 6 and ver.minor == 1 then return "Windows 7"
  else return string.format("Windows %d.%d", ver.major or 0, ver.minor or 0) end
end

local function flatten_ips(interfaces)
  local out = {}
  if not interfaces then return out end
  for _, iface in ipairs(interfaces) do
    local list = iface.ipv4
    if list then
      for _, addr in ipairs(list) do out[#out + 1] = addr end
    end
  end
  return out
end

function collect()
  local ver = host.rtl_get_version()
  local setup = host.setup_history() or {}
  local pending = host.registry_read(
    "HKLM",
    [[SYSTEM\CurrentControlSet\Control\Session Manager]],
    "PendingFileRenameOperations"
  )
  local ubr = host.registry_read(
    "HKLM",
    [[SOFTWARE\Microsoft\Windows NT\CurrentVersion]],
    "UBR"
  )
  local release = host.registry_read(
    "HKLM",
    [[SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full]],
    "Release"
  )

  local os_version_str = nil
  if ver then
    os_version_str = string.format(
      "%d.%d.%d.%d",
      ver.major or 0, ver.minor or 0, ver.build or 0, ubr or 0
    )
  end

  local pending_count = 0
  if type(pending) == "table" then pending_count = #pending end

  local result = {
    -- Session Info
    machine_name             = host.env("COMPUTERNAME"),
    user_name                = host.env("USERNAME"),
    logon_domain             = host.env("USERDOMAIN"),
    mail_address             = host.adsi_user_mail(15),
    ip_addresses             = flatten_ips(host.net_interfaces()),
    desktop_resolution       = host.desktop_resolution(),
    ca_definitions           = "Win10-Laptop",
    ca_version               = host.env("SDH_CLIENT_VERSION"),
    ca_perimeter             = host.env("SDH_PERIMETER"),
    dotnet_framework_version = dotnet_version_from_release(release),

    -- Hardware
    cpu_details              = host.cpu_details(),
    disk_size_bytes          = host.disk_size("system", "Size"),
    disk_size_free_bytes     = host.disk_size("system", "FreeSpace"),
    ram_bytes                = host.ram_total(),
    motherboard_details      = host.motherboard_details(),
    bios_details             = host.bios_details(),
    serial_number            = host.wmi_query("Win32_BIOS", "SerialNumber"),

    -- Operating System
    os_product                = os_product_name(ver),
    os_sku                    = ver and ver.build or nil,
    os_caption                = host.wmi_query("Win32_OperatingSystem", "Caption"),
    os_display_version        = host.registry_read(
      "HKLM",
      [[SOFTWARE\Microsoft\Windows NT\CurrentVersion]],
      "DisplayVersion"
    ),
    os_version                = os_version_str,
    os_install_date           = setup.install_date,
    os_setup_snapshot_history = setup.history or {},
    os_file_rename_pending    = pending_count > 0,
  }

  local errs = host.errors()
  -- Only attach _errors if there were any — keeps the payload clean.
  local has_errs = false
  for _ in pairs(errs) do has_errs = true; break end
  if has_errs then result._errors = errs end

  return result
end
