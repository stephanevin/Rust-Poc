-- Accounts collector: mirrors the Accounts section of ComplianceApp.
--
-- user_profiles  ← UserProfiles.cs       (registry ProfileList + LookupAccountSidW)
-- local_users    ← LocalAccountsUsers.cs (NetUserEnum(0) + NetUserGetInfo(4) per user)
-- admin_members  ← LocalAccountsAdminMembers.cs  (S-1-5-32-544, Administrators)
-- rdp_members    ← LocalAccountsRdpMembers.cs    (S-1-5-32-555, Remote Desktop Users)

function collect()
  local result = {
    user_profiles = host.user_profiles(),
    local_users   = host.local_user_accounts(),
    admin_members = host.local_group_members("S-1-5-32-544"),
    rdp_members   = host.local_group_members("S-1-5-32-555"),
  }

  local errs = host.errors()
  local has_errs = false
  for _ in pairs(errs) do has_errs = true; break end
  if has_errs then result._errors = errs end

  return result
end
