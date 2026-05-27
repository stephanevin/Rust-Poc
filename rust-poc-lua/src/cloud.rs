//! Cloud category bindings — Azure AD join status and MDM/Intune enrollment.
//!
//! Mirrors `ComplianceApp/DataTransformers/Cloud/` and the
//! `Cloud.cs` data transformer.  Implements deviation #39.
//!
//! ## AzureAD bindings
//!
//! Uses `NetGetAadJoinInformation` — a dedicated Win32 API that is strictly
//! better than the C# registry+cert approach: the returned struct embeds the
//! join certificate directly (`pJoinCertificate`) so no secondary cert-store
//! lookup is needed, and the device ID is a plain string (`pszDeviceId`),
//! eliminating the `CN=`-strip that the C# Subject-parsing performs.
//!
//! ## MDM bindings
//!
//! Uses WMI `root\CIMV2\mdm::MDM_MgmtAuthority.ProvisionedCertThumbprint`,
//! then validates the cert in the Local Machine `MY` store — matching
//! `Cloud.cs::GetMdmStatus` / `GetMdmDeviceId` faithfully.
//! `IsDeviceRegisteredWithManagement` (MDMRegistration.h) was evaluated but
//! rejected: it only returns a `bool` and cannot distinguish `"On"` from
//! `"CertificateIsNotValid"`.
//!
//! ## MDM sync bindings
//!
//! Pairs EventID 208 (sync start; `Message1` = enrollment ID) with
//! EventID 209 (sync end; `HRESULT` = result) via `(ProcessID, ThreadID)`
//! parsed from `EventRecord::system_attrs` (populated by `evt.rs` from
//! `<Execution …/>`) — exact port of `Cloud.cs::ComputeLastMdmSyncStatus`.

// `doc_markdown` is silenced: prose references Win32/COM identifiers, product
// names, and registry paths that the lint would flag as bare identifiers.
#![allow(clippy::doc_markdown)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows::Win32::Foundation::FILETIME;
use windows::Win32::NetworkManagement::NetManagement::{
    DSREG_DEVICE_JOIN, DSREG_JOIN_INFO, DSREG_WORKPLACE_JOIN, NetFreeAadJoinInformation,
    NetGetAadJoinInformation,
};
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_SHA1_HASH, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_OPEN_STORE_FLAGS,
    CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_SYSTEM, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_INTEGER_BLOB, HCERTSTORE, PKCS_7_ASN_ENCODING,
    X509_ASN_ENCODING, CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
    CertGetNameStringW, CertOpenStore,
};
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows::core::PCSTR;

use super::evt;
use super::registry;
use super::wmi::Wmi;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MDM_NS: &str = r"root\CIMV2\mdm";
const MDM_CLASS: &str = "MDM_MgmtAuthority";
const MDM_CERT_PROP: &str = "ProvisionedCertThumbprint";

const MDM_CHANNEL_ADMIN: &str =
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin";
const MDM_CHANNEL_SYNC: &str =
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Sync";

const MDM_LOGGER_KEY: &str = r"SOFTWARE\Microsoft\Provisioning\OMADM\Logger";
const MDM_ENROLLMENT_ID_VALUE: &str = "CurrentEnrollmentId";

const MDM_CO_MGMT_KEY: &str =
    r"SOFTWARE\Microsoft\DeviceManageabilityCSP\Provider\WMI_Bridge_Server";
const MDM_CO_MGMT_VALUE: &str = "ConfigInfo";

// ---------------------------------------------------------------------------
// Public output type
// ---------------------------------------------------------------------------

/// Aggregated MDM sync result returned by `host.mdm_sync_status()`.
///
/// All three fields are optional: the event log may have no completed sync
/// record, or no enrollment ID may be registered.
// Field names mirror the ComplianceApp data model (LastMdmSyncDate, etc.)
// and all share the `last` prefix intentionally — suppressing the lint
// preserves round-trip fidelity with the wire format.
#[allow(clippy::struct_field_names)]
#[derive(Debug, serde::Serialize)]
pub(super) struct MdmSyncStatus {
    pub last_sync_date: Option<String>,
    pub last_success_sync_date: Option<String>,
    pub last_sync_result: Option<String>,
}

// ---------------------------------------------------------------------------
// Azure AD bindings
// ---------------------------------------------------------------------------

/// Returns the Azure AD join status of the device.
///
/// - `"On"` — joined and certificate is temporally valid.
/// - `"Off"` — not joined, or `NetGetAadJoinInformation` returned null ptr.
/// - `"CertificateIsNotValid"` — joined but the embedded cert is expired or
///   not yet valid.
pub(super) fn azure_ad_joined_status() -> Result<&'static str, String> {
    let ptr = call_net_get_aad()?;
    if ptr.is_null() {
        return Ok("Off");
    }
    // Guard ensures NetFreeAadJoinInformation is called on every path.
    let _guard = AadInfoGuard(ptr);
    // SAFETY: ptr is non-null and freshly returned by a successful
    // NetGetAadJoinInformation; the guard keeps the allocation alive.
    let info = unsafe { &*ptr };
    if info.joinType != DSREG_DEVICE_JOIN && info.joinType != DSREG_WORKPLACE_JOIN {
        return Ok("Off");
    }
    if info.pJoinCertificate.is_null() {
        return Ok("Off");
    }
    Ok(validate_cert_context(info.pJoinCertificate))
}

/// Returns the Azure AD device ID (GUID string), or `None` when not joined.
pub(super) fn azure_ad_device_id() -> Result<Option<String>, String> {
    let ptr = call_net_get_aad()?;
    if ptr.is_null() {
        return Ok(None);
    }
    let _guard = AadInfoGuard(ptr);
    // SAFETY: ptr is non-null and held alive by the guard.
    let info = unsafe { &*ptr };
    if info.joinType != DSREG_DEVICE_JOIN && info.joinType != DSREG_WORKPLACE_JOIN {
        return Ok(None);
    }
    if info.pszDeviceId.is_null() {
        return Ok(None);
    }
    // SAFETY: pszDeviceId is a null-terminated wide string allocated by
    // NetGetAadJoinInformation and freed by NetFreeAadJoinInformation (via the
    // guard).  as_wide() reads up to the first null terminator.
    let wide = unsafe { info.pszDeviceId.as_wide() };
    if wide.is_empty() {
        return Ok(None);
    }
    Ok(Some(OsString::from_wide(wide).to_string_lossy().into_owned()))
}

/// Calls `NetGetAadJoinInformation(NULL)` for the current device.
///
/// Returns `Ok(null)` on S_OK with no join info (device not joined),
/// `Ok(ptr)` when joined, `Err` on a genuine Win32 failure.
fn call_net_get_aad() -> Result<*mut DSREG_JOIN_INFO, String> {
    // SAFETY: PCWSTR::null() selects the current device's AAD tenant.
    // On success the returned pointer is heap-allocated by netapi32 and must
    // be freed with NetFreeAadJoinInformation.
    unsafe { NetGetAadJoinInformation(windows::core::PCWSTR::null()) }
        .map_err(|e| format!("NetGetAadJoinInformation: {e}"))
}

// ---------------------------------------------------------------------------
// MDM bindings
// ---------------------------------------------------------------------------

/// Returns the MDM enrollment status of the device.
///
/// - `"On"` — enrolled and provisioning certificate is valid.
/// - `"Off"` — not enrolled, or WMI namespace absent (MDM agent not installed).
/// - `"CertificateIsNotValid"` — enrolled but provisioning cert is expired.
pub(super) fn mdm_status(wmi: &mut Wmi) -> Result<&'static str, String> {
    let Some(thumbprint) = mdm_thumbprint(wmi)? else {
        return Ok("Off");
    };
    match cert_in_lm_my(&thumbprint)? {
        None => Ok("Off"),
        Some(guard) => Ok(validate_cert_context(guard.ptr())),
    }
}

/// Returns the MDM device ID extracted from the provisioning certificate
/// subject (`CN=<device-id>`), or `None` when not enrolled.
pub(super) fn mdm_device_id(wmi: &mut Wmi) -> Result<Option<String>, String> {
    let Some(thumbprint) = mdm_thumbprint(wmi)? else {
        return Ok(None);
    };
    let Some(guard) = cert_in_lm_my(&thumbprint)? else {
        return Ok(None);
    };
    // Size probe: passing `None` for the buffer returns the required u16 count
    // including the null terminator.
    let len =
        // SAFETY: guard.ptr() is non-null and valid for the lifetime of `guard`.
        unsafe { CertGetNameStringW(guard.ptr(), CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
    if len <= 1 {
        return Ok(None);
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: buf has exactly `len` u16 elements, matching what the size probe
    // reported; guard.ptr() is still valid.
    unsafe {
        CertGetNameStringW(
            guard.ptr(),
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut buf),
        );
    }
    // buf[..len-1] is the name without the trailing null terminator.
    let name = OsString::from_wide(&buf[..len as usize - 1])
        .to_string_lossy()
        .into_owned();
    // Strip the "CN=" prefix emitted by CERT_NAME_SIMPLE_DISPLAY_TYPE.
    Ok(Some(name.strip_prefix("CN=").unwrap_or(&name).to_owned()))
}

/// Returns the MDM co-management flags as a decimal string, or `None` when
/// the registry key is absent (co-management is not configured).
pub(super) fn mdm_co_management_flags() -> Option<String> {
    match registry::read("HKLM", MDM_CO_MGMT_KEY, MDM_CO_MGMT_VALUE) {
        Ok(Some(v)) => v.as_u64().map(|n| n.to_string()),
        Ok(None) | Err(_) => None,
    }
}

/// Returns aggregated MDM sync status derived from Windows event log 208/209
/// pairs, filtered by the current enrollment ID, or `None` when no enrollment
/// ID is registered or when no paired sync events exist.
pub(super) fn mdm_sync_status() -> Option<MdmSyncStatus> {
    // Without a current enrollment ID we cannot attribute events to the active
    // enrollment — return None rather than stale data from a previous enrolment.
    let enrollment_id =
        match registry::read("HKLM", MDM_LOGGER_KEY, MDM_ENROLLMENT_ID_VALUE) {
            Ok(Some(v)) => match v.as_str().map(str::to_owned) {
                Some(s) if !s.is_empty() => s,
                _ => return None,
            },
            _ => return None,
        };

    // Collect start (208) and end (209) events from both channels.
    let start_events = collect_from_channels(208);
    let end_events = collect_from_channels(209);

    // Build a (process_id, thread_id) → end-event index for fast pairing.
    // If several end events share the same (pid, tid), we keep the first one
    // returned by the channel (which is the most recent, since we query in
    // reverse order).
    let mut end_map: HashMap<(u32, u32), &evt::EventRecord> = HashMap::new();
    for ev in &end_events {
        let pid = ev.system_attrs.get("ProcessID").and_then(|s| s.parse::<u32>().ok());
        let tid = ev.system_attrs.get("ThreadID").and_then(|s| s.parse::<u32>().ok());
        if let (Some(pid), Some(tid)) = (pid, tid) {
            end_map.entry((pid, tid)).or_insert(ev);
        }
    }

    // Pair each start event whose Message1 matches our enrollment ID with its
    // corresponding end event.
    let mut pairs: Vec<(String, String)> = Vec::new(); // (end_time_iso, hresult_str)
    for start in &start_events {
        let msg1 = start.event_data.get("Message1").map_or("", String::as_str);
        if !msg1.eq_ignore_ascii_case(&enrollment_id) {
            continue;
        }
        let pid = start.system_attrs.get("ProcessID").and_then(|s| s.parse::<u32>().ok());
        let tid = start.system_attrs.get("ThreadID").and_then(|s| s.parse::<u32>().ok());
        let Some((pid, tid)) = pid.zip(tid) else {
            continue;
        };
        let Some(end_ev) = end_map.get(&(pid, tid)) else {
            continue;
        };
        let hresult = end_ev
            .event_data
            .get("HRESULT")
            .cloned()
            .unwrap_or_default();
        pairs.push((end_ev.time_created.clone(), hresult));
    }

    if pairs.is_empty() {
        return Some(MdmSyncStatus {
            last_sync_date: None,
            last_success_sync_date: None,
            last_sync_result: None,
        });
    }

    // Sort descending by end_time — ISO 8601 sorts lexicographically.
    pairs.sort_by(|a, b| b.0.cmp(&a.0));

    let last_sync_date = Some(pairs[0].0.clone());
    let last_sync_result = Some(pairs[0].1.clone());
    // A sync succeeded when the HRESULT top bit (failure bit) is clear.
    let last_success_sync_date = pairs
        .iter()
        .find(|(_, hr)| hresult_succeeded(hr))
        .map(|(t, _)| t.clone());

    Some(MdmSyncStatus {
        last_sync_date,
        last_success_sync_date,
        last_sync_result,
    })
}

/// Returns `true` when the HRESULT string represents a successful result
/// (i.e., the Win32 "severity" bit is 0).  Accepts both decimal and
/// `0x…` hexadecimal strings as emitted by the event log.
fn hresult_succeeded(hr: &str) -> bool {
    let hr = hr.trim();
    if hr.is_empty() {
        return true; // absence of an error field is treated as success
    }
    let parsed = if let Some(hex) = hr.strip_prefix("0x").or_else(|| hr.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        hr.parse::<u32>().ok()
    };
    // HRESULT success: top bit (bit 31) clear.
    parsed.is_some_and(|v| v & 0x8000_0000 == 0)
}

/// Queries both MDM event log channels for `event_id` (descending order so
/// the most recent events come first).  Errors from individual channels are
/// silently ignored — if a channel doesn't exist we simply get no events.
fn collect_from_channels(event_id: u32) -> Vec<evt::EventRecord> {
    let mut records = Vec::new();
    if let Ok(evts) = evt::query_events(MDM_CHANNEL_ADMIN, event_id, None, None, true) {
        records.extend(evts);
    }
    if let Ok(evts) = evt::query_events(MDM_CHANNEL_SYNC, event_id, None, None, true) {
        records.extend(evts);
    }
    records
}

/// Queries WMI for the MDM provisioning certificate thumbprint.
///
/// Returns `Ok(None)` when not enrolled or when the MDM namespace is absent.
/// Returns `Err` only on unexpected WMI failures.
fn mdm_thumbprint(wmi: &mut Wmi) -> Result<Option<String>, String> {
    match wmi.query_first_ns(MDM_NS, MDM_CLASS, MDM_CERT_PROP) {
        Ok(Some(v)) => {
            let s = v
                .as_str()
                .map(str::to_owned)
                .or_else(|| if v.is_null() { None } else { Some(v.to_string()) });
            Ok(s.filter(|t| !t.is_empty()))
        }
        Ok(None) => Ok(None),
        Err(e) => {
            // WBEM_E_INVALID_NAMESPACE (0x8004100C) means the MDM agent is
            // not installed — treat the same as "not enrolled".
            if e.contains("INVALID_NAMESPACE") || e.contains("8004100C") {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------

/// RAII guard for an `HCERTSTORE`.
struct CertStoreGuard(HCERTSTORE);

impl Drop for CertStoreGuard {
    fn drop(&mut self) {
        // SAFETY: self.0 was returned by a successful CertOpenStore call;
        // flag 0 allows active certificate contexts to remain valid until
        // their own guards drop.
        unsafe {
            let _ = CertCloseStore(Some(self.0), 0);
        }
    }
}

/// RAII guard for a `*const CERT_CONTEXT`.
struct CertCtxGuard(*const CERT_CONTEXT);

impl CertCtxGuard {
    fn ptr(&self) -> *const CERT_CONTEXT {
        self.0
    }
}

impl Drop for CertCtxGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 was returned by CertFindCertificateInStore;
            // CertFreeCertificateContext is the documented release mechanism.
            unsafe {
                let _ = CertFreeCertificateContext(Some(self.0));
            }
        }
    }
}

/// RAII guard that calls `NetFreeAadJoinInformation` on drop.
struct AadInfoGuard(*mut DSREG_JOIN_INFO);

impl Drop for AadInfoGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 was returned by a successful
            // NetGetAadJoinInformation call.
            unsafe {
                NetFreeAadJoinInformation(Some(self.0.cast_const()));
            }
        }
    }
}

/// Opens the `LocalMachine\MY` certificate store and finds the certificate
/// identified by `thumbprint` (40-char hex-encoded SHA-1 hash).
///
/// Returns `Ok(None)` when the certificate is not found.  Returns `Err` on
/// Win32 failure opening the store.
///
/// Mirrors `new X509Store(StoreName.My, StoreLocation.LocalMachine)` in C#.
fn cert_in_lm_my(thumbprint: &str) -> Result<Option<CertCtxGuard>, String> {
    let mut hash_bytes = decode_thumbprint(thumbprint)?;

    // Open the Local Machine MY store (read-only).
    // CERT_STORE_PROV_SYSTEM (10) is passed as a small-integer PCSTR constant
    // per the Win32 convention for numeric provider IDs.  crypt32.dll checks
    // for this sentinel range before dereferencing the pointer.
    let store_name_w: Vec<u16> = "MY\0".encode_utf16().collect();
    // SAFETY: CERT_STORE_PROV_SYSTEM as usize is a sentinel value, not a real
    // pointer.  store_name_w lives for the duration of CertOpenStore.
    let store = unsafe {
        CertOpenStore(
            PCSTR(CERT_STORE_PROV_SYSTEM as usize as *const u8),
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_LOCAL_MACHINE) | CERT_STORE_READONLY_FLAG,
            Some(store_name_w.as_ptr().cast()),
        )
    }
    .map_err(|e| format!("CertOpenStore(LM\\MY): {e}"))?;

    let _store_guard = CertStoreGuard(store);

    let blob = CRYPT_INTEGER_BLOB {
        cbData: 20,
        pbData: hash_bytes.as_mut_ptr(),
    };

    // SAFETY: store is valid and alive (held by _store_guard); blob lives on
    // the stack for the entire duration of the call.
    let ctx = unsafe {
        CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SHA1_HASH,
            Some(
                std::ptr::addr_of!(blob).cast::<std::ffi::c_void>(),
            ),
            None,
        )
    };

    if ctx.is_null() {
        Ok(None)
    } else {
        Ok(Some(CertCtxGuard(ctx)))
    }
}

/// Validates that a `CERT_CONTEXT` is temporally valid (NotBefore ≤ now ≤ NotAfter).
///
/// Returns `"On"` when valid, `"CertificateIsNotValid"` otherwise.
fn validate_cert_context(ctx: *const CERT_CONTEXT) -> &'static str {
    // SAFETY: ctx is non-null and was returned by a Win32 API that guarantees
    // a fully initialised CERT_CONTEXT with a valid pCertInfo pointer.
    let cert_info = unsafe { &*(*ctx).pCertInfo };
    let not_before = filetime_to_u64(cert_info.NotBefore);
    let not_after = filetime_to_u64(cert_info.NotAfter);
    // SAFETY: GetSystemTimeAsFileTime has no preconditions (always safe).
    let now = filetime_to_u64(unsafe { GetSystemTimeAsFileTime() });
    if now >= not_before && now <= not_after {
        "On"
    } else {
        "CertificateIsNotValid"
    }
}

/// Packs a `FILETIME` into a comparable `u64` (100-nanosecond intervals since
/// 1601-01-01 UTC).
fn filetime_to_u64(ft: FILETIME) -> u64 {
    (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
}

/// Decodes a hex-encoded SHA-1 thumbprint string to a 20-byte array.
///
/// Tolerates spaces, hyphens, and colons as separators (stripped before
/// decoding).  Returns `Err` when the cleaned hex length is not 40.
fn decode_thumbprint(thumbprint: &str) -> Result<[u8; 20], String> {
    let clean: String = thumbprint
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect();
    if clean.len() != 40 {
        return Err(format!(
            "thumbprint must be 40 hex chars, got {} (input: {thumbprint:?})",
            clean.len()
        ));
    }
    let mut out = [0u8; 20];
    for (i, pair) in clean.as_bytes().chunks_exact(2).enumerate() {
        out[i] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(out)
}

/// Converts one ASCII hex nibble byte to its `u8` value.
fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex nibble: 0x{b:02x}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{decode_thumbprint, hresult_succeeded};

    #[test]
    fn thumbprint_valid_lowercase() {
        let t = "a" .repeat(40);
        assert!(decode_thumbprint(&t).is_ok());
    }

    #[test]
    fn thumbprint_valid_uppercase() {
        let t = "A".repeat(40);
        assert!(decode_thumbprint(&t).is_ok());
    }

    #[test]
    fn thumbprint_wrong_length_returns_err() {
        assert!(decode_thumbprint("deadbeef").is_err());
    }

    #[test]
    fn thumbprint_strips_spaces() {
        // 20 "aa " triples → "aa aa aa … aa" trimmed = 40 hex chars + spaces.
        let spaced = "aa ".repeat(20).trim().to_owned();
        assert!(decode_thumbprint(&spaced).is_ok());
    }

    #[test]
    fn hresult_success_zero() {
        assert!(hresult_succeeded("0x00000000"));
        assert!(hresult_succeeded("0"));
        assert!(hresult_succeeded(""));
    }

    #[test]
    fn hresult_failure_high_bit() {
        assert!(!hresult_succeeded("0x80070005")); // E_ACCESSDENIED
        assert!(!hresult_succeeded("0x80004005")); // E_FAIL
    }

    #[test]
    fn hresult_decimal_success() {
        assert!(hresult_succeeded("200"));
    }
}
