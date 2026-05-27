//! Endpoint Protection (EP) bindings — Security Center AV products and
//! Windows Defender status.
//!
//! ## Security Center (`root\SecurityCenter2`)
//!
//! [`security_center_av_products`] enumerates all AV products registered
//! with Windows Security Center, decodes the `ProductState` bitmask into
//! human-readable status, signature, and owner strings, and returns the
//! full list.  The Lua script filters by `name` for the specific product
//! it needs (e.g. `"Sentinel Agent"` for `SentinelOne`).
//!
//! ## Windows Defender (`root\Microsoft\Windows\Defender`)
//!
//! [`windows_defender_status`] reads `MSFT_MpComputerStatus` — the same
//! class that PowerShell's `Get-MpComputerStatus` surfaces.  Returns
//! `Ok(None)` when the class returns no rows (Defender disabled or
//! replaced by a third-party AV).  Returns `Err` on any other WMI
//! failure, which the caller records in `host.errors()`.
//!
//! ## Mirror in `ComplianceApp`
//!
//! - `ComplianceService\Data\AntiVirus\SentinelOne.cs` — Security Center
//!   `AntiVirusProduct` query used for `SentinelOne` status.
//! - `ComplianceService\Data\AntiVirus\WindowsDefender.cs` —
//!   `GetWindowsDefenderStatusFromCim()` reads `MSFT_MpComputerStatus`.
//! - `components\src\Components.Windows\WMI\Enums\AntiVirusEnums.cs` —
//!   `ProductState` bitmask constants mirrored in this module.
//!
//! ## Win32 vs WMI
//!
//! WSCAPI (`IWSCProductList` / `IWscProduct`) is the Win32 alternative to
//! querying `root\SecurityCenter2`, but those COM interfaces are not
//! exposed by `windows-rs` 0.62 — `Win32::System::Antimalware` covers
//! AMSI only.  WMI is therefore used for both bindings, matching the
//! compliance app.  Deviation #40.

use serde_json::{Value, json};

use super::wmi::Wmi;

/// WMI namespace for Windows Security Center product registration.
const NS_SC2: &str = r"ROOT\SecurityCenter2";
/// WMI namespace for Windows Defender / Microsoft Defender Antivirus.
const NS_DEFENDER: &str = r"ROOT\Microsoft\Windows\Defender";

/// WMI class exposing registered antivirus products (Security Center 2).
const CLASS_AV: &str = "AntiVirusProduct";
/// WMI class exposing the Defender runtime status singleton.
const CLASS_MP: &str = "MSFT_MpComputerStatus";

// --- ProductState bitmask constants (from AntiVirusEnums.cs) ----------
//
// The raw `ProductState` u32 from WMI packs three sub-fields in the
// low 16 bits:
//
//   AV_ProductStatus   bits 12-15  mask 0x0000_F000
//   AV_ProductOwner    bits  8-11  mask 0x0000_0F00
//   AV_SignatureStatus bits  4- 7  mask 0x0000_00F0
//
// Values below are the masked constants from AntiVirusEnums.cs.

const MASK_STATUS: u32 = 0x0000_F000;
const STATUS_ON: u32 = 0x0000_1000;
const STATUS_SNOOZED: u32 = 0x0000_2000;
const STATUS_EXPIRED: u32 = 0x0000_3000;
// STATUS_OFF = 0x0000_0000 — handled by the wildcard arm in av_state().

const MASK_SIGNATURES: u32 = 0x0000_00F0;
// SIGNATURES_UP_TO_DATE = 0x0000_0000 — tested as zero in av_signatures().
// Any non-zero value in bits 4-7 means OutOfDate.

const MASK_OWNER: u32 = 0x0000_0F00;
const OWNER_MICROSOFT: u32 = 0x0000_0100;
// OWNER_THIRD_PARTY = 0x0000_0000 — tested as not-Microsoft in av_owner().

/// Decodes the `AV_ProductStatus` sub-field of a raw `ProductState` u32.
fn av_state(product_state: u32) -> &'static str {
    match product_state & MASK_STATUS {
        STATUS_ON => "On",
        STATUS_SNOOZED => "Snoozed",
        STATUS_EXPIRED => "Expired",
        _ => "Off", // 0x0000 = Off; any unrecognised code falls back here
    }
}

/// Decodes the `AV_SignatureStatus` sub-field of a raw `ProductState` u32.
fn av_signatures(product_state: u32) -> &'static str {
    if product_state & MASK_SIGNATURES == 0 {
        "UpToDate"
    } else {
        "OutOfDate"
    }
}

/// Decodes the `AV_ProductOwner` sub-field of a raw `ProductState` u32.
fn av_owner(product_state: u32) -> &'static str {
    if product_state & MASK_OWNER == OWNER_MICROSOFT {
        "Microsoft"
    } else {
        "ThirdParty"
    }
}

/// Queries `ROOT\SecurityCenter2\AntiVirusProduct` and returns every
/// registered AV product with its decoded `ProductState`.
///
/// Each entry in the returned array contains:
///
/// | Field | Type | Description |
/// |---|---|---|
/// | `name` | `string` | `displayName` (e.g. `"Sentinel Agent"`, `"Windows Defender"`) |
/// | `state` | `string` | `"On"` \| `"Off"` \| `"Snoozed"` \| `"Expired"` |
/// | `signatures` | `string` | `"UpToDate"` \| `"OutOfDate"` |
/// | `owner` | `string` | `"Microsoft"` \| `"ThirdParty"` |
/// | `path` | `string?` | `pathToSignedProductExe` (may be `null`) |
/// | `product_state_raw` | `number` | Raw `productState` for diagnostics |
///
/// Returns `Err` on WMI connection or query failure.  An empty `Vec` is
/// a valid result — no AV product registered with Security Center.
pub(super) fn security_center_av_products(wmi: &mut Wmi) -> Result<Vec<Value>, String> {
    let rows = wmi.query_all_ns(NS_SC2, CLASS_AV)?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let Value::Object(mut obj) = row else {
                return None;
            };
            // AntiVirusProduct properties are camelCase (unlike Win32_*
            // classes which use PascalCase).  The wmi crate preserves the
            // exact casing returned by WMI, so we must match it here.
            let name = obj
                .get("displayName")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .map(str::to_string)?;
            // Security Center sometimes registers ghost entries with an
            // empty displayName and productState = 0 after an AV product
            // is partially uninstalled.  Drop them here so callers always
            // receive a clean list of real products.
            // productState comes back as a JSON number; truncate to u32
            // via try_from to satisfy clippy::cast_possible_truncation.
            let raw_state = obj
                .get("productState")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(0);
            let path = obj.remove("pathToSignedProductExe");
            Some(json!({
                "name":              name,
                "state":             av_state(raw_state),
                "signatures":        av_signatures(raw_state),
                "owner":             av_owner(raw_state),
                "path":              path,
                "product_state_raw": raw_state,
            }))
        })
        .collect())
}

/// Reads the first `MSFT_MpComputerStatus` row from
/// `ROOT\Microsoft\Windows\Defender` and returns it as a JSON object.
///
/// The returned object contains WMI property names in their original
/// `PascalCase` (e.g. `AMServiceEnabled`, `AMRunningMode`,
/// `AntivirusEnabled`, `RealTimeProtectionEnabled`, `ProductStatus`).
///
/// Returns `Ok(None)` when the namespace exists but the class returns no
/// rows (Defender fully disabled, replaced by a third-party AV, or the
/// WMI provider is not registered).  Returns `Err` on any WMI connection
/// or query failure (e.g. namespace absent on some Server SKUs).
pub(super) fn windows_defender_status(wmi: &mut Wmi) -> Result<Option<Value>, String> {
    let rows = wmi.query_all_ns(NS_DEFENDER, CLASS_MP)?;
    Ok(rows.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::{av_owner, av_signatures, av_state};

    #[test]
    fn av_state_decodes_status_nibbles() {
        assert_eq!(av_state(0x0000_1000), "On");
        assert_eq!(av_state(0x0000_0000), "Off");
        assert_eq!(av_state(0x0000_2000), "Snoozed");
        assert_eq!(av_state(0x0000_3000), "Expired");
        assert_eq!(av_state(0x0000_F000), "Off"); // undocumented status code
        assert_eq!(av_state(0x0000_1110), "On"); // owner + signature bits ignored
    }

    #[test]
    fn av_signatures_decodes_signature_nibbles() {
        assert_eq!(av_signatures(0x0000_1000), "UpToDate");
        assert_eq!(av_signatures(0x0000_1010), "OutOfDate");
    }

    #[test]
    fn av_owner_decodes_owner_nibble() {
        assert_eq!(av_owner(0x0000_1000), "ThirdParty");
        assert_eq!(av_owner(0x0000_1100), "Microsoft");
    }

    #[test]
    fn product_state_realistic_values() {
        // Expired + OutOfDate — fields decode independently from one raw u32.
        let ps = 0x0000_3010;
        assert_eq!(av_state(ps), "Expired");
        assert_eq!(av_signatures(ps), "OutOfDate");
        assert_eq!(av_owner(ps), "ThirdParty");

        // Windows Defender-style: On + Microsoft + UpToDate.
        let ps = 0x0000_1100;
        assert_eq!(av_state(ps), "On");
        assert_eq!(av_signatures(ps), "UpToDate");
        assert_eq!(av_owner(ps), "Microsoft");
    }
}
