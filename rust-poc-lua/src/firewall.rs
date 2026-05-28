//! Firewall host bindings — deviation #42.
//!
//! Three bindings covering the Firewall sub-category of `Win10-Laptop.json`
//! (minus `WfpFirewallView`, deferred to deviation #43):
//!
//! - [`security_center_firewall_products`] — WMI `ROOT\SecurityCenter2\FirewallProduct`:
//!   same `ProductState` bitmask as `AntiVirusProduct` (see [`ep.rs`](super::ep));
//!   `FirewallEnums.cs` mirrors `AntiVirusEnums.cs` bit-for-bit.
//!
//! - [`windows_defender_firewall_status`] — WMI `root\StandardCimv2`:
//!   `MSFT_NetConnectionProfile` (current network profile) +
//!   `MSFT_NetFirewallProfile` (enabled state per Domain / Private / Public profile).
//!   Mirrors `Firewall.cs::GetWindowsDefenderFirewallStatus`.
//!
//! - [`net_fw_products`] — COM `HNetCfg.FwProducts` (`INetFwProducts` /
//!   `INetFwProduct2`): enumerates products registered with Windows Firewall
//!   and their `RuleCategories` array so the Lua script can derive which product
//!   owns each rule category (0=BootTime, 1=Stealth, 2=Firewall, 3=ConSec).
//!   Mirrors `Firewall.cs::GetNetFwProducts`.
//!
//! ## Mirror in `ComplianceApp`
//!
//! - `ComplianceService\Data\Firewall\Firewall.cs` — all three backends.
//! - `components\src\…\WMI\Enums\FirewallEnums.cs` — `FW_ProductStatus`
//!   bitmask constants (bit-for-bit copy of `AntiVirusEnums.cs`).

use std::thread::sleep;
use std::time::Duration;

use serde_json::{Value, json};
use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwProduct, INetFwProducts, NetFwProducts};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, SAFEARRAY,
};
use windows::Win32::System::Ole::{SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound};
use windows::Win32::System::Variant::{VT_ARRAY, VT_I4, VT_UI4, VT_VARIANT, VariantClear, VARIANT};

use super::wmi::Wmi;

// --- WMI namespaces / class names -----------------------------------------

/// WMI namespace for Windows Security Center (same as `ep.rs`).
const NS_SC2: &str = r"ROOT\SecurityCenter2";
/// WMI namespace for standard CIM v2 (firewall profiles + connection profiles).
const NS_STDCIMV2: &str = r"root\StandardCimv2";
/// WMI class for firewall products registered with Security Center.
const CLASS_FW_PRODUCT: &str = "FirewallProduct";
/// WMI class for Windows Defender Firewall per-profile state (Domain / Private / Public).
const CLASS_FW_PROFILE: &str = "MSFT_NetFirewallProfile";
/// WMI class for the current network connection profile.
const CLASS_CONN_PROFILE: &str = "MSFT_NetConnectionProfile";

// --- ProductState bitmask constants (from FirewallEnums.cs) ---------------
//
// `FW_ProductStatus` is bit-for-bit identical to `AV_ProductStatus` in
// `AntiVirusEnums.cs` (confirmed by comparison of both files).
//
// Layout (low 16 bits of the raw u32):
//   FW_ProductStatus  bits 12-15  mask 0x0000_F000
//   FW_ProductOwner   bits  8-11  mask 0x0000_0F00
//   (signature bits 4-7 are absent from FirewallEnums.cs; unused for FW products)

const MASK_STATUS: u32 = 0x0000_F000;
const STATUS_ON: u32 = 0x0000_1000;
const STATUS_SNOOZED: u32 = 0x0000_2000;
const STATUS_EXPIRED: u32 = 0x0000_3000;

const MASK_OWNER: u32 = 0x0000_0F00;
const OWNER_MICROSOFT: u32 = 0x0000_0100;

/// Decodes the `FW_ProductStatus` sub-field of a raw `ProductState` u32.
fn fw_state(product_state: u32) -> &'static str {
    match product_state & MASK_STATUS {
        STATUS_ON => "On",
        STATUS_SNOOZED => "Snoozed",
        STATUS_EXPIRED => "Expired",
        _ => "Off", // 0x0000 = Off; any unrecognised code falls back here
    }
}

/// Decodes the `FW_ProductOwner` sub-field of a raw `ProductState` u32.
fn fw_owner(product_state: u32) -> &'static str {
    if product_state & MASK_OWNER == OWNER_MICROSOFT {
        "Microsoft"
    } else {
        "ThirdParty"
    }
}

// ---------------------------------------------------------------------------
// Binding 42a — `security_center_firewall_products`
// ---------------------------------------------------------------------------

/// Queries `ROOT\SecurityCenter2\FirewallProduct` and returns every registered
/// firewall product with its decoded `ProductState`.
///
/// The `ProductState` bitmask is bit-for-bit identical to the `AV_ProductStatus`
/// bitmask decoded in [`ep::security_center_av_products`](super::ep::security_center_av_products).
/// Only `Status` and `Owner` nibbles are decoded — `FirewallEnums.cs` omits the
/// `SignatureStatus` nibble present in `AntiVirusEnums.cs`.
///
/// Ghost entries with an empty `displayName` are silently dropped (same invariant
/// as the AV binding — Security Center occasionally registers stale zero-state
/// entries after partial uninstalls).
///
/// Each entry contains:
///
/// | Field | Type | Description |
/// |---|---|---|
/// | `name` | `string` | `displayName` |
/// | `state` | `string` | `"On"` \| `"Off"` \| `"Snoozed"` \| `"Expired"` |
/// | `owner` | `string` | `"Microsoft"` \| `"ThirdParty"` |
/// | `path` | `string?` | `pathToSignedProductExe` |
/// | `product_state_raw` | `number` | Raw `productState` for diagnostics |
///
/// Returns `Err` on WMI connection or query failure.
pub(super) fn security_center_firewall_products(wmi: &mut Wmi) -> Result<Vec<Value>, String> {
    let rows = wmi.query_all_ns(NS_SC2, CLASS_FW_PRODUCT)?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let Value::Object(mut obj) = row else {
                return None;
            };
            // FirewallProduct properties are camelCase — same convention as
            // AntiVirusProduct (not PascalCase like Win32_* classes).
            let name = obj
                .get("displayName")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)?;
            let raw_state = obj
                .get("productState")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(0);
            let path = obj.remove("pathToSignedProductExe");
            Some(json!({
                "name":              name,
                "state":             fw_state(raw_state),
                "owner":             fw_owner(raw_state),
                "path":              path,
                "product_state_raw": raw_state,
            }))
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Binding 42b — `windows_defender_firewall_status`
// ---------------------------------------------------------------------------

/// Maps `MSFT_NetConnectionProfile.NetworkCategory` (u32) to a profile name.
///
/// Mirrors the `NetworkCategory` WMI enum from `Firewall.cs`:
/// - `0` → `"Public"` (default when the machine is off-network — no active profile)
/// - `1` → `"Private"`
/// - `2` → `"Domain"`
fn network_category_str(cat: u64) -> &'static str {
    match cat {
        1 => "Private",
        2 => "Domain",
        _ => "Public", // 0 = Public; any unrecognised value defaults to Public
    }
}

/// Maps `MSFT_NetFirewallProfile.Enabled` (u16) to a state string.
///
/// - `1` → `"On"`
/// - `0` → `"Off"`
/// - missing / unexpected → `"Unknown"`
fn fw_profile_enabled_str(v: Option<&Value>) -> &'static str {
    match v.and_then(Value::as_u64) {
        Some(1) => "On",
        Some(0) => "Off",
        _ => "Unknown",
    }
}

/// Looks up `MSFT_NetFirewallProfile.Enabled` for a named profile.
///
/// `name` comparison is case-insensitive — WMI providers are inconsistent
/// about capitalisation on some localised Windows builds.
fn fw_profile_enabled_for(rows: &[Value], name: &str) -> &'static str {
    for row in rows {
        if let Value::Object(obj) = row
            && obj
                .get("Name")
                .and_then(Value::as_str)
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
        {
            return fw_profile_enabled_str(obj.get("Enabled"));
        }
    }
    "Unknown"
}

/// Reads Windows Defender Firewall status from `root\StandardCimv2`.
///
/// Two WMI queries feed the result:
///
/// 1. `MSFT_NetConnectionProfile` — the first row's `NetworkCategory` u32
///    determines the active profile name (`"Domain"` / `"Private"` / `"Public"`).
///    Falls back to `"Public"` when the machine has no active network connection
///    (class returns no rows) — documented invariant in `Firewall.cs` L.196.
///
/// 2. `MSFT_NetFirewallProfile` — all rows enumerated; matched by `Name` for
///    each of the three profiles.  `Enabled` field: `1 = On`, `0 = Off`.
///
/// Returns a JSON object:
///
/// | Field | Type | Description |
/// |---|---|---|
/// | `current_profile` | `string` | `"Domain"` \| `"Private"` \| `"Public"` |
/// | `status` | `string` | Defender state for the active profile |
/// | `domain_state` | `string` | `"On"` \| `"Off"` \| `"Unknown"` |
/// | `private_state` | `string` | `"On"` \| `"Off"` \| `"Unknown"` |
/// | `public_state` | `string` | `"On"` \| `"Off"` \| `"Unknown"` |
///
/// Returns `Err` on WMI connection or query failure.
pub(super) fn windows_defender_firewall_status(wmi: &mut Wmi) -> Result<Value, String> {
    // --- Step 1: active network profile ------------------------------------
    let conn_rows = wmi.query_all_ns(NS_STDCIMV2, CLASS_CONN_PROFILE)?;
    let current_profile = conn_rows
        .first()
        .and_then(|row| {
            if let Value::Object(obj) = row {
                obj.get("NetworkCategory").and_then(Value::as_u64)
            } else {
                None
            }
        })
        .map_or("Public", network_category_str);

    // --- Step 2: per-profile Enabled states --------------------------------
    let fw_rows = wmi.query_all_ns(NS_STDCIMV2, CLASS_FW_PROFILE)?;

    let domain_state = fw_profile_enabled_for(&fw_rows, "Domain");
    let private_state = fw_profile_enabled_for(&fw_rows, "Private");
    let public_state = fw_profile_enabled_for(&fw_rows, "Public");

    let status = match current_profile {
        "Domain" => domain_state,
        "Private" => private_state,
        _ => public_state,
    };

    Ok(json!({
        "current_profile": current_profile,
        "status":          status,
        "domain_state":    domain_state,
        "private_state":   private_state,
        "public_state":    public_state,
    }))
}

// ---------------------------------------------------------------------------
// Binding 42c — `net_fw_products`
// ---------------------------------------------------------------------------

/// Ensures COM is initialised as MTA on the current thread.
///
/// `CoInitializeEx` returns `S_FALSE` (`HRESULT(1)`) when COM is already
/// initialised in the same apartment — `.ok()` treats any non-negative
/// HRESULT as success.
fn ensure_com() -> Result<(), String> {
    // SAFETY: no preconditions; CoInitializeEx is always safe to call.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
        .ok()
        .map_err(|e| format!("COM init: {e}"))
}

/// Extracts a scalar `u32` from a single-element `VARIANT`.
///
/// `INetFwProduct::RuleCategories` returns category IDs as `VT_I4`; some
/// providers wrap each element in an outer `VT_VARIANT` (`VT_ARRAY | VT_VARIANT`).
fn variant_scalar_u32(var: &VARIANT) -> Option<u32> {
    // SAFETY: `var` is a valid VARIANT; we read `vt` before touching the union.
    unsafe {
        match var.Anonymous.Anonymous.vt {
            VT_I4 => u32::try_from(var.Anonymous.Anonymous.Anonymous.lVal).ok(),
            VT_UI4 => Some(var.Anonymous.Anonymous.Anonymous.ulVal),
            _ => None,
        }
    }
}

/// Reads one element from a `SAFEARRAY` bounded by `[lb, ub]` at 1-based index `i`.
fn safearray_element_i32(psa: *const SAFEARRAY, i: i32) -> Option<u32> {
    let mut val = 0i32;
    // SAFETY: `psa` is non-null; `val` matches `VT_I4`; `i` is within bounds.
    unsafe {
        SafeArrayGetElement(psa, std::ptr::addr_of!(i), std::ptr::addr_of_mut!(val).cast())
            .ok()
            .and_then(|()| u32::try_from(val).ok())
    }
}

/// Reads one `VARIANT` element from a `VT_ARRAY | VT_VARIANT` SAFEARRAY.
///
/// `SafeArrayGetElement` copies the element; the copy must be cleared with
/// `VariantClear` before returning.
fn safearray_element_variant_u32(psa: *const SAFEARRAY, i: i32) -> Option<u32> {
    let mut elem = VARIANT::default();
    // SAFETY: `psa` is non-null; `elem` is a correctly sized VARIANT buffer.
    let extracted = unsafe {
        SafeArrayGetElement(psa, std::ptr::addr_of!(i), std::ptr::addr_of_mut!(elem).cast())
            .ok()
            .and_then(|()| variant_scalar_u32(&elem))
    };
    // SAFETY: `elem` is a copy produced by `SafeArrayGetElement` and must be freed.
    let _ = unsafe { VariantClear(std::ptr::addr_of_mut!(elem)) };
    extracted
}

#[derive(Clone, Copy)]
enum ElementKind {
    I4,
    Variant,
}

/// Extracts a `Vec<u32>` from a `VARIANT` that wraps a `SAFEARRAY` of category IDs.
///
/// Handles both shapes returned by `INetFwProduct::RuleCategories` on real hosts:
///
/// - `VT_ARRAY | VT_I4` (8195) — bare `i32` elements.
/// - `VT_ARRAY | VT_VARIANT` (8204) — each element is a `VARIANT` containing `VT_I4`.
///
/// Returns an empty `Vec` when the outer type is unrecognised, the `SAFEARRAY`
/// pointer is null, or any `SafeArrayGet*` call fails.
fn variant_safearray_i4(var: &VARIANT) -> Vec<u32> {
    // SAFETY: Reading VARIANT union fields is safe when `var` is a valid
    // COM-owned VARIANT (returned from `INetFwProduct::RuleCategories`).
    // We inspect `vt` before dereferencing the SAFEARRAY pointer.
    unsafe {
        let vt = var.Anonymous.Anonymous.vt;
        let element_kind = match vt {
            t if t == VT_ARRAY | VT_I4 => ElementKind::I4,
            t if t == VT_ARRAY | VT_VARIANT => ElementKind::Variant,
            _ => {
                tracing::debug!(vt = vt.0, "RuleCategories: unrecognised VARIANT type");
                return vec![];
            }
        };

        let psa = var.Anonymous.Anonymous.Anonymous.parray;
        if psa.is_null() {
            tracing::debug!(vt = vt.0, "RuleCategories: SAFEARRAY pointer is null");
            return vec![];
        }
        // SafeArrayGetLBound/UBound take *const SAFEARRAY; psa is *mut.
        let psa_const = psa.cast_const();
        let Ok(lb) = SafeArrayGetLBound(psa_const, 1) else {
            return vec![];
        };
        let Ok(ub) = SafeArrayGetUBound(psa_const, 1) else {
            return vec![];
        };

        (lb..=ub)
            .filter_map(|i| match element_kind {
                ElementKind::I4 => safearray_element_i32(psa_const, i),
                ElementKind::Variant => safearray_element_variant_u32(psa_const, i),
            })
            .collect()
    }
}

/// Maximum `CoCreateInstance(NetFwProducts)` attempts before giving up.
/// Mirrors the retry budget in `Firewall.cs` L.33–79.
const NET_FW_PRODUCTS_MAX_ATTEMPTS: u32 = 5;

/// Creates `INetFwProducts` with a retry loop for transient COM failures
/// during Windows Firewall service start-up.
fn co_create_net_fw_products() -> Result<INetFwProducts, String> {
    ensure_com()?;

    let mut last_err = String::new();
    for attempt in 0..NET_FW_PRODUCTS_MAX_ATTEMPTS {
        // SAFETY: `NetFwProducts` is a registered COM class; safe after `ensure_com`.
        match unsafe { CoCreateInstance(&NetFwProducts, None, CLSCTX_INPROC_SERVER) } {
            Ok(products) => return Ok(products),
            Err(e) => {
                last_err = format!("CoCreateInstance(NetFwProducts): {e}");
                if attempt + 1 < NET_FW_PRODUCTS_MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1));
                }
            }
        }
    }
    Err(last_err)
}

/// Enumerates products registered with the Windows Firewall via
/// `HNetCfg.FwProducts` (`INetFwProducts` / `INetFwProduct`).
///
/// `INetFwProducts::Item` returns `INetFwProduct` (IID `71881699`).  On current
/// Windows builds this interface's vtable already includes `RuleCategories`; a
/// separate `QueryInterface` to `INetFwProduct2` is not required in practice.
/// The subtle failure mode is the `RuleCategories` return type: COM automation
/// delivers `VT_ARRAY | VT_VARIANT` (8204), not `VT_ARRAY | VT_I4` (8195).
///
/// Includes a retry loop (up to 5 attempts, 1 s apart) to handle transient COM
/// failures during Windows Firewall service start-up.
/// Mirrors `Firewall.cs::GetNetFwProducts`.
///
/// Each entry in the returned array contains:
///
/// | Field | Type | Description |
/// |---|---|---|
/// | `name` | `string` | `INetFwProduct::DisplayName` |
/// | `path` | `string?` | `INetFwProduct::PathToSignedProductExe` |
/// | `rule_categories` | `array<u32>` | `INetFwProduct::RuleCategories` — 0=BootTime, 1=Stealth, 2=Firewall, 3=ConSec |
///
/// Returns `Err` on persistent COM failure (all 5 attempts exhausted) or
/// `INetFwProducts::Count` failure.  Per-item property failures are non-fatal:
/// the affected product is silently skipped.
pub(super) fn net_fw_products() -> Result<Vec<Value>, String> {
    let products = co_create_net_fw_products()?;

    // SAFETY: `INetFwProducts::Count` is a const property getter; safe to call
    // on a valid interface pointer.
    let count =
        unsafe { products.Count() }.map_err(|e| format!("INetFwProducts::Count: {e}"))?;

    tracing::debug!(count, "INetFwProducts::Count");

    let mut out = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for i in 0..count {
        // SAFETY: `Item` is safe to call with a valid 0-based index on `INetFwProducts`.
        let product: INetFwProduct = match unsafe { products.Item(i) } {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(i, error = %e, "INetFwProducts::Item failed, skipping");
                continue;
            }
        };

        // SAFETY: all property getters are safe to call on a valid `INetFwProduct`.
        let name = unsafe { product.DisplayName() }
            .map(|b| b.to_string())
            .unwrap_or_default();

        let path = unsafe { product.PathToSignedProductExe() }
            .map(|b| b.to_string())
            .ok();

        let categories = match unsafe { product.RuleCategories() } {
            Ok(v) => variant_safearray_i4(&v),
            Err(e) => {
                tracing::warn!(i, name = %name, error = %e, "INetFwProduct::RuleCategories failed");
                vec![]
            }
        };

        out.push(json!({
            "name":             name,
            "path":             path,
            "rule_categories":  categories,
        }));
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        fw_owner, fw_profile_enabled_for, fw_profile_enabled_str, fw_state, network_category_str,
    };
    use serde_json::{Value, json};

    #[test]
    fn fw_state_decodes_status_nibbles() {
        assert_eq!(fw_state(0x0000_1000), "On");
        assert_eq!(fw_state(0x0000_0000), "Off");
        assert_eq!(fw_state(0x0000_2000), "Snoozed");
        assert_eq!(fw_state(0x0000_3000), "Expired");
        assert_eq!(fw_state(0x0000_F000), "Off"); // unrecognised code → Off
        assert_eq!(fw_state(0x0000_1100), "On"); // owner bits ignored
    }

    #[test]
    fn fw_owner_decodes_owner_nibble() {
        assert_eq!(fw_owner(0x0000_1000), "ThirdParty");
        assert_eq!(fw_owner(0x0000_1100), "Microsoft");
    }

    #[test]
    fn network_category_maps_correctly() {
        assert_eq!(network_category_str(0), "Public");
        assert_eq!(network_category_str(1), "Private");
        assert_eq!(network_category_str(2), "Domain");
        assert_eq!(network_category_str(99), "Public"); // fallback
    }

    #[test]
    fn fw_profile_enabled_maps_correctly() {
        assert_eq!(fw_profile_enabled_str(Some(&Value::from(1u64))), "On");
        assert_eq!(fw_profile_enabled_str(Some(&Value::from(0u64))), "Off");
        assert_eq!(fw_profile_enabled_str(None), "Unknown");
        assert_eq!(fw_profile_enabled_str(Some(&Value::from(2u64))), "Unknown");
    }

    #[test]
    fn fw_profile_enabled_for_matches_case_insensitively() {
        let rows = vec![
            json!({"Name": "domain", "Enabled": 1}),
            json!({"Name": "Private", "Enabled": 0}),
        ];
        assert_eq!(fw_profile_enabled_for(&rows, "Domain"), "On");
        assert_eq!(fw_profile_enabled_for(&rows, "private"), "Off");
        assert_eq!(fw_profile_enabled_for(&rows, "Public"), "Unknown");
    }
}
