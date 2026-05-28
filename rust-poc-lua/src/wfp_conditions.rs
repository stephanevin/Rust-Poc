//! WFP filter condition parsing.
//!
//! Mirrors `WfpService.GetFilterConditionsJson` and
//! `WfpFilterPipeline.FormatFilterLogicCompact` from `ComplianceApp`.
//!
//! ## Key concepts
//!
//! * `FWP_CONDITION_VALUE0` is a discriminated union tagged by `FWP_DATA_TYPE`.
//!   Scalars `UINT8/16/32` are stored **inline** in the union (low bytes of a
//!   pointer-sized field); `UINT64/INT64/DOUBLE` are stored as **pointers to
//!   heap-allocated values** — a null-check before dereference is mandatory.
//! * Compound types (`BYTE_BLOB`, `SID`, masks, ranges) are also pointers.
//! * `parse_conditions` is `unsafe` because it dereferences raw Win32 pointers.

use std::fmt::Write as FmtWrite;

use serde_json::{Value, json};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_BLOB, FWPM_FILTER_CONDITION0,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
};
use windows::Win32::Security::{OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
use windows::core::PWSTR;

use super::wfp_known_guids::condition_field_guid_names;

// ---------------------------------------------------------------------------
// Intermediate type
// ---------------------------------------------------------------------------

/// Parsed representation of a single `FWPM_FILTER_CONDITION0`.
pub(super) struct WfpCondition {
    pub field_key: String,
    pub match_type: String,
    pub value: ConditionValue,
}

/// All value variants produced by `FWP_CONDITION_VALUE0`.
pub(super) enum ConditionValue {
    Empty,
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    ByteArray16(String),
    ByteBlob {
        as_string: Option<String>,
        hex: Option<String>,
    },
    Sid(String),
    SecurityDescriptor(String),
    V4AddrMask {
        addr: String,
        mask: String,
    },
    V6AddrMask {
        addr: String,
        prefix_length: u8,
    },
    Range {
        low: Box<ConditionValue>,
        high: Box<ConditionValue>,
    },
    Unknown(u32),
    Error(String),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parses `count` `FWPM_FILTER_CONDITION0` structs starting at `ptr`.
///
/// # Safety
///
/// `ptr` must point to a valid contiguous array of at least `count`
/// `FWPM_FILTER_CONDITION0` structs whose embedded pointers are valid WFP
/// heap allocations.  This invariant is guaranteed by the WFP engine when
/// the caller holds an open `HANDLE` to the engine and uses the buffer
/// returned by `FwpmFilterEnum0`.
pub(super) unsafe fn parse_conditions(
    ptr: *const FWPM_FILTER_CONDITION0,
    count: u32,
) -> Vec<WfpCondition> {
    if ptr.is_null() || count == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        // SAFETY: caller guarantees a valid array of `count` elements.
        let cond = unsafe { &*ptr.add(i) };

        let field_key = condition_field_guid_names()
            .get(&cond.fieldKey)
            .map_or_else(
                || format!("{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
                    cond.fieldKey.data1, cond.fieldKey.data2, cond.fieldKey.data3,
                    cond.fieldKey.data4[0], cond.fieldKey.data4[1],
                    cond.fieldKey.data4[2], cond.fieldKey.data4[3],
                    cond.fieldKey.data4[4], cond.fieldKey.data4[5],
                    cond.fieldKey.data4[6], cond.fieldKey.data4[7]),
                |s| (*s).to_string(),
            );

        let match_type = match_type_name(cond.matchType.0.cast_unsigned());
        // SAFETY: all pointer variants are null-checked inside the helper.
        let value = unsafe { parse_condition_value(&cond.conditionValue) };

        out.push(WfpCondition {
            field_key,
            match_type,
            value,
        });
    }
    out
}

/// Serialises conditions to a JSON array string, e.g.
/// `[{"fieldKey":"IP_PROTOCOL","matchType":"EQUAL","conditionValue":{"type":"UINT8","value":6}}]`.
///
/// Returns `"[]"` for an empty slice.
pub(super) fn conditions_json(conds: &[WfpCondition]) -> String {
    if conds.is_empty() {
        return "[]".to_string();
    }
    let arr: Vec<Value> = conds
        .iter()
        .map(|c| {
            json!({
                "fieldKey": c.field_key,
                "matchType": c.match_type,
                "conditionValue": condition_value_to_json(&c.value),
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
}

/// Formats conditions as a compact human-readable string, e.g.
/// `"PROTOCOL='TCP' & LOCAL_PORT='443'"`.
///
/// Returns `"ANY"` for an empty slice.
pub(super) fn format_compact(conds: &[WfpCondition]) -> String {
    if conds.is_empty() {
        return "ANY".to_string();
    }

    // Group by field_key preserving order of first occurrence.
    let mut seen_keys: Vec<&str> = Vec::new();
    let mut groups: std::collections::HashMap<&str, Vec<&WfpCondition>> =
        std::collections::HashMap::new();
    for c in conds {
        let key = c.field_key.as_str();
        if !groups.contains_key(key) {
            seen_keys.push(key);
        }
        groups.entry(key).or_default().push(c);
    }

    let parts: Vec<String> = seen_keys
        .iter()
        .map(|k| {
            let group = &groups[k];
            let short_key = k.replace("ALE_", "").replace("IP_", "");

            if group.len() == 1 {
                let c = group[0];
                let sym = match_symbol(&c.match_type);
                let val = format_compact_value(&c.value, k);
                let val = val.replace("FWP_CONDITION_", "").replace("FLAG_IS_", "");
                format!("{short_key}{sym}'{val}'")
            } else {
                let vals: Vec<String> = group
                    .iter()
                    .map(|c| {
                        let v = format_compact_value(&c.value, k);
                        v.replace("FWP_CONDITION_", "").replace("FLAG_IS_", "")
                    })
                    .collect();
                format!("{short_key} \u{2208} {{{}}}", vals.join(","))
            }
        })
        .collect();

    parts.join(" & ")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn match_type_name(t: u32) -> String {
    match t {
        0 => "EQUAL",
        1 => "GREATER",
        2 => "LESS",
        3 => "GREATER_OR_EQUAL",
        4 => "LESS_OR_EQUAL",
        5 => "RANGE",
        6 => "FLAGS_ALL_SET",
        7 => "FLAGS_ANY_SET",
        8 => "FLAGS_NONE_SET",
        9 => "EQUAL_CASE_INSENSITIVE",
        10 => "NOT_EQUAL",
        11 => "PREFIX",
        12 => "NOT_PREFIX",
        _ => return format!("FWP_MATCH_UNKNOWN_{t}"),
    }
    .to_string()
}

fn match_symbol(match_type: &str) -> &'static str {
    match match_type {
        "NOT_EQUAL" => "\u{2260}",
        "GREATER" => ">",
        "LESS" => "<",
        "GREATER_OR_EQUAL" => "\u{2265}",
        "LESS_OR_EQUAL" => "\u{2264}",
        "RANGE" => " \u{2208} ",
        "FLAGS_ALL_SET" => " has ",
        "FLAGS_ANY_SET" => " has-any ",
        "FLAGS_NONE_SET" => " has-none ",
        "PREFIX" => "~",
        "NOT_PREFIX" => "!~",
        "EQUAL_CASE_INSENSITIVE" => "\u{2248}",
        _ => "=",
    }
}

/// Converts a big-endian u32 IP address to dotted-decimal notation.
fn u32_to_ipv4(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

/// Converts a 16-byte IPv6 address to lowercase colon-separated notation
/// (no compression; mirrors `BytesToIPv6` in `ComplianceApp`).
fn bytes_to_ipv6(bytes: &[u8; 16]) -> String {
    let segs: Vec<String> = (0..8)
        .map(|i| format!("{:x}", u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]])))
        .collect();
    segs.join(":")
}

/// Parses a `FWP_CONDITION_VALUE0` union into a [`ConditionValue`].
///
/// # Safety
///
/// All pointer variants are null-checked before dereferencing.
unsafe fn parse_condition_value(
    v: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0,
) -> ConditionValue {
    let type_discriminant = v.r#type.0;

    match type_discriminant {
        0 => ConditionValue::Empty,

        // --- inline scalars ---
        1 => ConditionValue::Uint8(unsafe { v.Anonymous.uint8 }),
        2 => ConditionValue::Uint16(unsafe { v.Anonymous.uint16 }),
        3 => ConditionValue::Uint32(unsafe { v.Anonymous.uint32 }),

        // --- heap-pointer scalars ---
        4 => {
            let ptr = unsafe { v.Anonymous.uint64 };
            let val = if ptr.is_null() { 0u64 } else { unsafe { *ptr } };
            ConditionValue::Uint64(val)
        }

        // --- BYTE_ARRAY16 → IPv6 ---
        11 => {
            let ptr = unsafe { v.Anonymous.byteArray16 };
            if ptr.is_null() {
                ConditionValue::ByteArray16("::".to_string())
            } else {
                let bytes = unsafe { (*ptr).byteArray16 };
                ConditionValue::ByteArray16(bytes_to_ipv6(&bytes))
            }
        }

        // --- BYTE_BLOB → UTF-16 or hex ---
        12 => unsafe { parse_byte_blob(v.Anonymous.byteBlob) },

        // --- SID ---
        13 => unsafe { parse_sid(v.Anonymous.sid.cast()) },

        // --- SECURITY_DESCRIPTOR (stored as FWP_BYTE_BLOB) ---
        14 => unsafe { parse_security_descriptor(v.Anonymous.sd) },

        // --- FWP_V4_ADDR_AND_MASK ---
        256 => {
            let ptr = unsafe { v.Anonymous.v4AddrMask };
            if ptr.is_null() {
                ConditionValue::V4AddrMask {
                    addr: "0.0.0.0".to_string(),
                    mask: "0.0.0.0".to_string(),
                }
            } else {
                let m = unsafe { *ptr };
                ConditionValue::V4AddrMask {
                    addr: u32_to_ipv4(m.addr),
                    mask: u32_to_ipv4(m.mask),
                }
            }
        }

        // --- FWP_V6_ADDR_AND_MASK ---
        257 => {
            let ptr = unsafe { v.Anonymous.v6AddrMask };
            if ptr.is_null() {
                ConditionValue::V6AddrMask {
                    addr: "::".to_string(),
                    prefix_length: 0,
                }
            } else {
                let m = unsafe { *ptr };
                ConditionValue::V6AddrMask {
                    addr: bytes_to_ipv6(&m.addr),
                    prefix_length: m.prefixLength,
                }
            }
        }

        // --- FWP_RANGE0 ---
        258 => {
            let ptr = unsafe { v.Anonymous.rangeValue };
            if ptr.is_null() {
                ConditionValue::Error("RANGE: null pointer".to_string())
            } else {
                let r = unsafe { &*ptr };
                let low = unsafe { parse_range_value(&r.valueLow) };
                let high = unsafe { parse_range_value(&r.valueHigh) };
                ConditionValue::Range {
                    low: Box::new(low),
                    high: Box::new(high),
                }
            }
        }

        #[allow(clippy::cast_sign_loss)]
        other => ConditionValue::Unknown(other as u32),
    }
}

/// Parses a `FWP_VALUE0` (used inside `FWP_RANGE0`) into a simple
/// [`ConditionValue`], handling only the types `ComplianceApp`'s
/// `GetSimpleValue` handles.
unsafe fn parse_range_value(
    v: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0,
) -> ConditionValue {
    let type_discriminant = v.r#type.0;
    match type_discriminant {
        1 => ConditionValue::Uint8(unsafe { v.Anonymous.uint8 }),
        2 => ConditionValue::Uint16(unsafe { v.Anonymous.uint16 }),
        3 => ConditionValue::Uint32(unsafe { v.Anonymous.uint32 }),
        4 => {
            let ptr = unsafe { v.Anonymous.uint64 };
            let val = if ptr.is_null() { 0u64 } else { unsafe { *ptr } };
            ConditionValue::Uint64(val)
        }
        11 => {
            let ptr = unsafe { v.Anonymous.byteArray16 };
            if ptr.is_null() {
                ConditionValue::ByteArray16("::".to_string())
            } else {
                let bytes = unsafe { (*ptr).byteArray16 };
                ConditionValue::ByteArray16(bytes_to_ipv6(&bytes))
            }
        }
        #[allow(clippy::cast_sign_loss)]
        other => ConditionValue::Unknown(other as u32),
    }
}

unsafe fn parse_byte_blob(ptr: *mut FWP_BYTE_BLOB) -> ConditionValue {
    if ptr.is_null() {
        return ConditionValue::ByteBlob {
            as_string: None,
            hex: None,
        };
    }
    let blob = unsafe { *ptr };
    if blob.size == 0 || blob.data.is_null() || blob.size >= 4096 {
        return ConditionValue::ByteBlob {
            as_string: None,
            hex: None,
        };
    }

    let bytes = unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) };

    // Attempt UTF-16 decode (ALE_APP_ID is typically a UTF-16 file path).
    // SAFETY: blob.data is u8*; reinterpreting as u16* requires the pointer to
    // be 2-byte aligned; WFP heap allocations are at least 8-byte aligned in
    // practice. The alignment violation is a false positive for this FFI pattern.
    #[allow(clippy::cast_ptr_alignment)]
    if blob.size % 2 == 0 {
        let u16_len = blob.size as usize / 2;
        let u16_slice: &[u16] =
            unsafe { std::slice::from_raw_parts(blob.data.cast::<u16>(), u16_len) };
        let trimmed: Vec<u16> = u16_slice.iter().copied().take_while(|&c| c != 0).collect();
        if !trimmed.is_empty()
            && let Ok(s) = String::from_utf16(&trimmed)
            && !s.is_empty()
            && s.chars().all(|c| !c.is_control() || c == '\n')
        {
            return ConditionValue::ByteBlob {
                as_string: Some(s),
                hex: None,
            };
        }
    }

    let hex = bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    });
    ConditionValue::ByteBlob {
        as_string: None,
        hex: Some(hex),
    }
}

unsafe fn parse_sid(ptr: *const std::ffi::c_void) -> ConditionValue {
    if ptr.is_null() {
        return ConditionValue::Sid("NULL".to_string());
    }
    // SAFETY: caller guarantees ptr is a valid SID.
    let mut sid_str_ptr = PWSTR::null();
    let ok = unsafe {
        ConvertSidToStringSidW(
            // SAFETY: ptr is a valid SID — null-checked above.
            PSID(ptr.cast_mut()),
            &raw mut sid_str_ptr,
        )
    };
    if ok.is_ok() && !sid_str_ptr.is_null() {
        let s = unsafe { sid_str_ptr.to_string() }.unwrap_or_else(|_| "INVALID".to_string());
        unsafe { LocalFree(Some(HLOCAL(sid_str_ptr.0.cast()))) };
        return ConditionValue::Sid(s);
    }
    ConditionValue::Sid("PARSE_ERROR".to_string())
}

unsafe fn parse_security_descriptor(ptr: *mut FWP_BYTE_BLOB) -> ConditionValue {
    if ptr.is_null() {
        return ConditionValue::SecurityDescriptor(String::new());
    }
    let blob = unsafe { *ptr };
    if blob.size == 0 || blob.data.is_null() {
        return ConditionValue::SecurityDescriptor("EMPTY".to_string());
    }
    // DACL | SACL | OWNER | GROUP bits (flags 0x1 | 0x2 | 0x4 | 0x8 = 0xF)
    let mut sddl_ptr = PWSTR::null();
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(blob.data.cast()),
            1,                               // SDDL_REVISION_1
            OBJECT_SECURITY_INFORMATION(15), // DACL | SACL | OWNER | GROUP
            &raw mut sddl_ptr,
            None,
        )
    };
    if ok.is_ok() && !sddl_ptr.is_null() {
        let s = unsafe { sddl_ptr.to_string() }.unwrap_or_else(|_| "INVALID".to_string());
        unsafe { LocalFree(Some(HLOCAL(sddl_ptr.0.cast()))) };
        return ConditionValue::SecurityDescriptor(s);
    }
    ConditionValue::SecurityDescriptor("PARSE_ERROR".to_string())
}

// ---------------------------------------------------------------------------
// JSON serialisation
// ---------------------------------------------------------------------------

fn condition_value_to_json(v: &ConditionValue) -> Value {
    match v {
        ConditionValue::Empty => json!({"type": "EMPTY"}),
        ConditionValue::Uint8(n) => json!({"type": "UINT8", "value": n}),
        ConditionValue::Uint16(n) => json!({"type": "UINT16", "value": n}),
        ConditionValue::Uint32(n) => json!({"type": "UINT32", "value": n}),
        ConditionValue::Uint64(n) => json!({"type": "UINT64", "value": n}),
        ConditionValue::ByteArray16(s) => json!({"type": "BYTE_ARRAY16", "value": s}),
        ConditionValue::ByteBlob {
            as_string: Some(s), ..
        } => {
            json!({"type": "BYTE_BLOB", "asString": s})
        }
        ConditionValue::ByteBlob { hex: Some(h), .. } => {
            json!({"type": "BYTE_BLOB", "hex": h})
        }
        ConditionValue::ByteBlob { .. } => json!({"type": "BYTE_BLOB"}),
        ConditionValue::Sid(s) => json!({"type": "SID", "sid": s}),
        ConditionValue::SecurityDescriptor(s) => {
            json!({"type": "SECURITY_DESCRIPTOR", "sd": s})
        }
        ConditionValue::V4AddrMask { addr, mask } => {
            json!({"type": "V4_ADDR_MASK", "addr": addr, "mask": mask})
        }
        ConditionValue::V6AddrMask {
            addr,
            prefix_length,
        } => {
            json!({"type": "V6_ADDR_MASK", "addr": addr, "prefixLength": prefix_length})
        }
        ConditionValue::Range { low, high } => json!({
            "type": "RANGE",
            "valueLow": condition_value_to_json(low),
            "valueHigh": condition_value_to_json(high),
        }),
        ConditionValue::Unknown(t) => json!({"type": format!("UNKNOWN_{t}")}),
        ConditionValue::Error(e) => json!({"error": e}),
    }
}

// ---------------------------------------------------------------------------
// Compact formatting helpers
// ---------------------------------------------------------------------------

fn format_compact_value(v: &ConditionValue, field_key: &str) -> String {
    match v {
        ConditionValue::Empty => "EMPTY".to_string(),
        ConditionValue::Uint8(n) => {
            if field_key == "IP_PROTOCOL" {
                protocol_name(i32::from(*n)).to_string()
            } else {
                n.to_string()
            }
        }
        ConditionValue::Uint16(n) => n.to_string(),
        ConditionValue::Uint32(n) => format_uint32_value(field_key, *n),
        ConditionValue::Uint64(n) => n.to_string(),
        ConditionValue::ByteArray16(s)
        | ConditionValue::ByteBlob {
            as_string: Some(s), ..
        }
        | ConditionValue::Sid(s) => s.clone(),
        ConditionValue::ByteBlob { hex: Some(h), .. } => h.clone(),
        ConditionValue::ByteBlob { .. } => "BLOB".to_string(),
        ConditionValue::SecurityDescriptor(s) => {
            // Extract the first principal from SDDL as a hint
            s.chars().take(40).collect::<String>()
        }
        ConditionValue::V4AddrMask { addr, mask } => {
            let cidr = mask_to_cidr_v4(mask);
            if cidr == 32 {
                addr.clone()
            } else {
                format!("{addr}/{cidr}")
            }
        }
        ConditionValue::V6AddrMask {
            addr,
            prefix_length,
        } => {
            if *prefix_length == 128 {
                simplify_ipv6(addr)
            } else {
                format!("{}/{}", simplify_ipv6(addr), prefix_length)
            }
        }
        ConditionValue::Range { low, high } => {
            format!(
                "{}-{}",
                format_compact_value(low, field_key),
                format_compact_value(high, field_key)
            )
        }
        ConditionValue::Unknown(t) => format!("UNKNOWN_{t}"),
        ConditionValue::Error(e) => format!("ERR:{e}"),
    }
}

fn format_uint32_value(field_key: &str, value: u32) -> String {
    match field_key {
        "ORIGINAL_ICMP_TYPE" | "ICMP_TYPE" => icmp_type_name(value).to_string(),
        "COMPARTMENT_ID" => {
            if value == 0 {
                format!("HOST_{value}")
            } else {
                format!("VM/CONTAINER_{value}")
            }
        }
        _ if field_key.contains("PROFILE_ID") => network_profile_name(value).to_string(),
        _ if field_key.contains("INTERFACE_TYPE") => interface_type_name(value).to_string(),
        _ if field_key.contains("TUNNEL_TYPE") => tunnel_type_name(value).to_string(),
        _ => value.to_string(),
    }
}

fn protocol_name(proto: i32) -> &'static str {
    match proto {
        0 => "HOPOPTS",
        1 => "ICMP",
        2 => "IGMP",
        3 => "GGP",
        4 => "IPV4",
        5 => "ST",
        6 => "TCP",
        7 => "CBT",
        8 => "EGP",
        9 => "IGP",
        12 => "PUP",
        17 => "UDP",
        22 => "IDP",
        27 => "RDP",
        41 => "IPV6",
        43 => "ROUTING",
        44 => "FRAGMENT",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPV6",
        59 => "NONE",
        60 => "DSTOPTS",
        77 => "ND",
        78 => "ICLFXBM",
        103 => "PIM",
        113 => "PGM",
        115 => "L2TP",
        132 => "SCTP",
        255 => "RAW",
        _ => "UNKNOWN",
    }
}

fn icmp_type_name(t: u32) -> &'static str {
    match t {
        0 => "Echo Reply",
        3 => "Dest Unreachable",
        8 => "Echo Request",
        11 => "TTL Exceeded",
        _ => "ICMP",
    }
}

fn network_profile_name(v: u32) -> &'static str {
    match v {
        1 => "PUBLIC",
        2 => "PRIVATE",
        4 => "DOMAIN",
        _ => "UNKNOWN",
    }
}

fn interface_type_name(v: u32) -> &'static str {
    match v {
        1 => "IF_TYPE_OTHER",
        6 => "ETHERNET_CSMACD",
        71 => "IEEE80211",
        131 => "TUNNEL",
        _ => "UNKNOWN",
    }
}

fn tunnel_type_name(v: u32) -> &'static str {
    match v {
        0 => "DIRECT",
        1 => "6TO4",
        2 => "ISATAP",
        3 => "TEREDO",
        4 => "IPHTTPS",
        _ => "UNKNOWN",
    }
}

/// Converts a dotted-decimal mask to CIDR prefix length.
fn mask_to_cidr_v4(mask: &str) -> u32 {
    let octets: Vec<u32> = mask
        .split('.')
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();
    if octets.len() != 4 {
        return 0;
    }
    let bits = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    bits.count_ones()
}

/// Minimal IPv6 simplification: collapse longest run of zero groups.
fn simplify_ipv6(addr: &str) -> String {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 8 {
        return addr.to_string();
    }
    // Find longest run of "0" or "0000" groups
    let zeroes: Vec<bool> = parts.iter().map(|p| *p == "0" || *p == "0000").collect();
    let mut best_start = 0;
    let mut best_len = 0;
    let mut cur_start = 0;
    let mut cur_len = 0;
    for (i, &z) in zeroes.iter().enumerate() {
        if z {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_len = cur_len;
                best_start = cur_start;
            }
        } else {
            cur_len = 0;
        }
    }

    if best_len < 2 {
        return addr.to_string();
    }

    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if i == best_start {
            out.push_str("::");
            i += best_len;
        } else {
            let seg: u16 = u16::from_str_radix(parts[i], 16).unwrap_or(0);
            if !out.is_empty() && !out.ends_with("::") {
                out.push(':');
            }
            write!(out, "{seg:x}").ok();
            i += 1;
        }
    }
    out
}
