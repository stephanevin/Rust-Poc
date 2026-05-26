-- Softwares + System Updates collector: mirrors the Software and System
-- Updates sub-categories of ComplianceApp (Win10-Laptop.json).
--
-- Contract — every binding follows the workspace-wide rule:
--   * On success: returns its value (array, scalar, table).
--   * On failure: returns `nil` and records the cause in `host.errors()`.
--   * A binding NEVER raises a Lua error; the script need not pcall.
--
-- Two failure-shape conventions coexist (by design, not by accident):
--
--   * All-or-nothing bindings (one source → one outcome):
--     `os_services`, `is_managed`, `managed_by`, `reboot_required`,
--     `reboot_required_before_installation`, `windows_updates`,
--     `sccm_updates`.  Failure ⇒ `nil` + error key.
--
--   * Multi-source best-effort bindings (many sources, partial success
--     is the common case): `os_software_installed`,
--     `browser_extensions_installed`, `ide_extensions_installed`.
--     Failure ⇒ `[]` (possibly partial) + one or more error keys with
--     a suffix indicating which slice is missing (`:wts`, `:registry`,
--     `:partial`, …).  The operator distinguishes "nothing installed"
--     from "I couldn't read X" via `_errors`, not via `nil`.
--
-- Backing sources:
--   os_software_installed    <- OSSoftwareInstalled.cs   (HKLM Uninstall + WTS per-user HKU)
--   os_services              <- OSServices.cs            (Win32 SC Manager, no WMI)
--   browser_extensions       <- BrowserExtensionsInstalled.cs (Chromium prefs + manifests)
--   ide_extensions           <- IdeExtensionsInstalled.cs    (extensions.json + package.json)
--
-- System Updates bindings (deviations #26-#31, see CLAUDE.md):
--   is_managed, managed_by               <- IUpdateServiceManager2 (WUA COM)
--   reboot_required                      <- ISystemInformation (WUA COM)
--   reboot_required_before_installation  <- IUpdateInstaller (WUA COM)
--   windows_updates                      <- IUpdateSession3 offline search (WUA COM)
--   sccm_updates                         <- WMI Root\ccm + WUA offline join

function collect()
  local result = {
    -- Software
    software_installed  = host.os_software_installed(),
    services            = host.os_services(),
    browser_extensions  = host.browser_extensions_installed(),
    ide_extensions      = host.ide_extensions_installed(),

    -- System Updates
    is_managed                          = host.updates_is_managed(),
    managed_by                          = host.updates_managed_by(),
    reboot_required                     = host.updates_reboot_required(),
    reboot_required_before_installation = host.updates_reboot_required_before_installation(),
    windows_updates                     = host.updates_windows_updates(),
    sccm_updates                        = host.updates_sccm_updates(),
  }

  -- `host.errors()` always returns a table; `next(t)` is the idiomatic
  -- Lua "is this table non-empty?" probe (returns the first key or nil).
  local errs = host.errors()
  if next(errs) ~= nil then result._errors = errs end

  return result
end
