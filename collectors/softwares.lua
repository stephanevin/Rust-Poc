-- Softwares collector: mirrors the Software sub-category of ComplianceApp
-- (Win10-Laptop.json lines 1008-1031, category "Software").
--
-- os_software_installed    <- OSSoftwareInstalled.cs   (HKLM Uninstall + WTS per-user HKU)
-- os_services              <- OSServices.cs            (Win32 SC Manager, no WMI)
-- browser_extensions       <- BrowserExtensionsInstalled.cs (Chromium prefs + manifests)
-- ide_extensions           <- IdeExtensionsInstalled.cs    (extensions.json + package.json)

function collect()
  local result = {
    software_installed    = host.os_software_installed(),
    services     = host.os_services(),
    browser_extensions  = host.browser_extensions_installed(),
    ide_extensions      = host.ide_extensions_installed(),
  }

  local errs = host.errors()
  local has_errs = false
  for _ in pairs(errs) do has_errs = true; break end
  if has_errs then result._errors = errs end

  return result
end
