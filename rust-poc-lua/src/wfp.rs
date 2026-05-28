//! WFP (Windows Filtering Platform) enumeration.
//!
//! Provides:
//! - [`WfpEngine`] — RAII handle over `FwpmEngineOpen0 / FwpmEngineClose0`.
//! - [`WfpMemoryGuard`] — RAII wrapper for WFP-allocated enumeration buffers
//!   freed via `FwpmFreeMemory0`.
//! - [`enumerate_wfp_state`] — opens the WFP engine, enumerates all six
//!   object types, and returns an enriched [`WfpState`].
//! - [`wfp_net_events`] — enumerates the live network event log using a
//!   **separate** ephemeral engine (the cached engine is not reused so that
//!   the net-events query sees the most recent data).
//! - [`get_layer_direction`] — shared direction resolver used by both this
//!   module and `wfp_pipeline.rs`.

// All Win32 enumeration APIs use the same pattern:
//   FwpmXxxCreateEnumHandle0(engine, None, &mut handle)   → &raw mut is pedantically preferred
//   &mut entries as *mut *mut c_void as *mut *mut *mut T  → .cast() is preferred
//   for i in 0..(count as isize)                         → may wrap on 32-bit (not a concern for WFP counts)
//   *(entries as *mut *mut T).add(i as usize)            → cast_sign_loss (i is always non-negative)
// These are inherent properties of Win32 FFI — suppressed at the module level rather than
// per-call-site to keep the WFP enumeration code readable.
#![allow(
    clippy::borrow_as_ptr,            // &mut x in Win32 calls; &raw mut is equivalent and verbose
    clippy::ptr_as_ptr,               // *mut T as *mut U in enum buffer casts
    clippy::cast_possible_wrap,       // count as isize in loop bounds (WFP counts << isize::MAX)
    clippy::cast_sign_loss,           // i as usize / .0 as u32 (values are always non-negative)
    clippy::cast_lossless,            // u8/u32 as u64/i32 — infallible but pedantic
    clippy::cast_possible_truncation, // i64 as u32 in civil-date algorithm (values in range)
    clippy::unnecessary_wraps,        // secondary enum_* helpers always return Ok(vec) on failure; kept as Result for symmetry
    clippy::too_many_lines,           // wfp_net_events (111 lines) — dense but coherent
    clippy::items_after_statements,   // const OFFSET inside filetime_to_iso8601
    clippy::manual_is_multiple_of,    // blob.size % 2 == 0 — intention is clearer than is_multiple_of
    clippy::if_not_else,              // one GUID-zeroed check
    clippy::cast_ptr_alignment,       // *mut u8 → *mut u16 reinterpretation in read_byte_blob_utf16
    clippy::many_single_char_names,   // single-letter vars in Howard Hinnant's civil-date algorithm
    clippy::ref_as_ptr,               // &mut entries as *mut *mut c_void in WFP enum buffer casts
)]

use std::collections::HashMap;
use std::ffi::c_void;

use serde_json::{Value, json};
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_IP_VERSION_V4, FWP_IP_VERSION_V6, FWPM_CALLOUT0, FWPM_FILTER0, FWPM_LAYER0,
    FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_NET_EVENT2,
    FWPM_PROVIDER_CONTEXT0, FWPM_PROVIDER0, FWPM_SUBLAYER0, FwpmCalloutCreateEnumHandle0,
    FwpmCalloutDestroyEnumHandle0, FwpmCalloutEnum0, FwpmEngineClose0, FwpmEngineOpen0,
    FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmLayerCreateEnumHandle0, FwpmLayerDestroyEnumHandle0, FwpmLayerEnum0,
    FwpmNetEventCreateEnumHandle0, FwpmNetEventDestroyEnumHandle0, FwpmNetEventEnum2,
    FwpmProviderContextCreateEnumHandle0, FwpmProviderContextDestroyEnumHandle0,
    FwpmProviderContextEnum0, FwpmProviderCreateEnumHandle0, FwpmProviderDestroyEnumHandle0,
    FwpmProviderEnum0, FwpmSubLayerCreateEnumHandle0, FwpmSubLayerDestroyEnumHandle0,
    FwpmSubLayerEnum0,
};
use windows::core::GUID;

use super::wfp_conditions::{WfpCondition, parse_conditions};
use super::wfp_known_guids::{layer_guid_names, sublayer_guid_names};

// ---------------------------------------------------------------------------
// Error code constants
// ---------------------------------------------------------------------------

/// `FWP_E_NET_EVENTS_DISABLED` — returned when net-event collection is off.
const FWP_E_NET_EVENTS_DISABLED: u32 = 0x8032_0013;

// ---------------------------------------------------------------------------
// RAII: engine handle
// ---------------------------------------------------------------------------

/// RAII wrapper around a `FWPM` engine `HANDLE`.
pub(super) struct WfpEngine(HANDLE);

impl WfpEngine {
    fn handle(&self) -> HANDLE {
        self.0
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: valid open handle obtained from FwpmEngineOpen0.
            unsafe {
                let _ = FwpmEngineClose0(self.0);
            }
        }
    }
}

/// Opens a WFP engine session.  Returns `Err(message)` on failure.
pub(super) fn open_engine() -> Result<WfpEngine, String> {
    let mut handle = HANDLE::default();
    let hr = unsafe {
        FwpmEngineOpen0(
            windows::core::PCWSTR::null(),
            0xFFFF_FFFF, // RPC_C_AUTHN_WINNT
            None,
            None,
            &mut handle,
        )
    };
    if hr != 0 {
        return Err(format!("FwpmEngineOpen0 failed: 0x{hr:08X}"));
    }
    Ok(WfpEngine(handle))
}

// ---------------------------------------------------------------------------
// RAII: enumeration buffer
// ---------------------------------------------------------------------------

/// RAII wrapper that calls `FwpmFreeMemory0` on the contained WFP buffer.
///
/// Holds a `*mut c_void` (the base pointer of a WFP-allocated object array).
/// `FwpmFreeMemory0` takes `*mut *mut c_void`, so we store the pointer here and
/// pass `addr_of_mut!(self.ptr)` on drop — the WFP engine then zeroes the slot.
pub(super) struct WfpMemoryGuard(*mut c_void);

impl WfpMemoryGuard {
    fn new(ptr: *mut c_void) -> Self {
        Self(ptr)
    }
}

impl Drop for WfpMemoryGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: ptr was obtained from a WFP enumeration API.
            unsafe {
                FwpmFreeMemory0(std::ptr::addr_of_mut!(self.0));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Enriched types
// ---------------------------------------------------------------------------

/// All fields needed by `wfp_sublayer_details`, `wfp_firewall_view`, and
/// `wfp_net_events`.  Built once during [`enumerate_wfp_state`] and cached in
/// `HostState::wfp_cache`.
// `filter_key`, `flags`, `provider_key`, and `layer_key` are preserved for
// data-model completeness (mirroring the ComplianceApp WfpFilter shape) and
// future consumers; not all are read by the current three views.
#[allow(dead_code)]
pub(super) struct WfpEnrichedFilter {
    pub filter_id: u64,
    pub filter_key: String,
    pub name: String,
    pub flags: u32,
    pub provider_key: String,
    pub provider_name: String,
    pub layer_key: String,
    pub layer_id: u16,
    pub layer_name: String,
    pub sublayer_key: String,
    pub sublayer_name: String,
    pub sublayer_weight: u16,
    pub effective_weight_numeric: u64,
    pub effective_weight: String,
    pub conditions: Vec<WfpCondition>,
    pub action: String,
    pub is_boottime: bool,
    pub has_clear_action_right: bool,
    pub provider_context_data_buffer_hex: String,
}

/// Cached output of [`enumerate_wfp_state`].
pub(super) struct WfpState {
    pub filters: Vec<WfpEnrichedFilter>,
    /// `filter_id → (filter_name, sublayer_name)` — used by `wfp_net_events`.
    pub filter_index: HashMap<u64, (String, String)>,
    /// `layer_id → layer_name` — used by `wfp_net_events` for direction lookup.
    pub layer_id_index: HashMap<u16, String>,
}

// ---------------------------------------------------------------------------
// Direction helper (shared with wfp_pipeline.rs)
// ---------------------------------------------------------------------------

/// Maps a WFP layer name to a firewall traffic direction.
///
/// Mirrors `WfpFilterPipeline.GetLayerDirection` in `ComplianceApp`.
pub(super) fn get_layer_direction(layer_name: &str) -> &'static str {
    if layer_name.starts_with("ALE_AUTH_LISTEN")
        || layer_name.starts_with("ALE_AUTH_RECV_ACCEPT")
        || layer_name.starts_with("INBOUND_")
    {
        "Inbound"
    } else if layer_name.starts_with("ALE_AUTH_CONNECT")
        || layer_name.starts_with("ALE_CONNECT_REDIRECT")
        || layer_name.starts_with("OUTBOUND_")
    {
        "Outbound"
    } else if layer_name.starts_with("ALE_RESOURCE_ASSIGNMENT")
        || layer_name.starts_with("ALE_RESOURCE_RELEASE")
        || layer_name.starts_with("ALE_BIND_REDIRECT")
        || layer_name.starts_with("ALE_FLOW_ESTABLISHED")
        || layer_name.starts_with("ALE_ENDPOINT_CLOSURE")
        || layer_name.starts_with("DATAGRAM_DATA_")
        || layer_name.starts_with("STREAM_V")
        || layer_name.starts_with("STREAM_PACKET_")
    {
        "Both"
    } else {
        "Unknown"
    }
}

// ---------------------------------------------------------------------------
// Main enumeration
// ---------------------------------------------------------------------------

/// Opens a WFP engine session, enumerates layers, sublayers, providers,
/// provider contexts, callouts and filters (up to 10 000 filters, 1 000
/// others), enriches the filters, and builds the per-run lookup indexes.
///
/// Returns `Err(message)` on any WFP API failure.
pub(super) fn enumerate_wfp_state() -> Result<WfpState, String> {
    let engine = open_engine()?;

    let layers = enum_layers(&engine)?;
    let sublayers = enum_sublayers(&engine)?;
    let providers = enum_providers(&engine)?;
    let provider_contexts = enum_provider_contexts(&engine)?;
    // Callouts enumerated but not used in the three views — kept for future.
    let _callouts = enum_callouts(&engine)?;
    let raw_filters = enum_raw_filters(&engine)?;

    // Build lookup tables
    let layer_map: HashMap<GUID, (u16, String)> = layers
        .iter()
        .map(|(guid, id, name)| (*guid, (*id, name.clone())))
        .collect();
    let sublayer_map: HashMap<GUID, (String, u16)> = sublayers
        .iter()
        .map(|(guid, name, weight)| (*guid, (name.clone(), *weight)))
        .collect();
    let provider_map: HashMap<GUID, String> = providers
        .iter()
        .map(|(guid, name)| (*guid, name.clone()))
        .collect();
    let ctx_map: HashMap<GUID, String> = provider_contexts
        .iter()
        .map(|(guid, hex)| (*guid, hex.clone()))
        .collect();

    // layer_id_index for net-events direction
    let layer_id_index: HashMap<u16, String> = layer_map
        .values()
        .map(|(id, name)| (*id, name.clone()))
        .collect();

    // Enrich filters
    let mut filters = Vec::with_capacity(raw_filters.len());
    for rf in raw_filters {
        let (layer_id, layer_name) = layer_map
            .get(&rf.layer_key)
            .cloned()
            .unwrap_or((9999, "Unknown".to_string()));
        let (sublayer_name, sublayer_weight) = sublayer_map
            .get(&rf.sublayer_key)
            .cloned()
            .unwrap_or(("Unknown".to_string(), 0));
        let provider_name = provider_map
            .get(&rf.provider_key)
            .cloned()
            .unwrap_or_default();
        let ctx_hex = rf
            .provider_context_key
            .as_ref()
            .and_then(|k| ctx_map.get(k).cloned())
            .unwrap_or_default();

        let is_boottime = rf.flags & 0x0002 != 0;
        let has_clear_action_right = rf.flags & 0x0008 != 0;

        filters.push(WfpEnrichedFilter {
            filter_id: rf.filter_id,
            filter_key: guid_to_string(&rf.filter_key),
            name: rf.name,
            flags: rf.flags,
            provider_key: guid_to_string(&rf.provider_key),
            provider_name,
            layer_key: guid_to_string(&rf.layer_key),
            layer_id,
            layer_name,
            sublayer_key: guid_to_string(&rf.sublayer_key),
            sublayer_name,
            sublayer_weight,
            effective_weight: format!("0x{:X}", rf.effective_weight_numeric),
            effective_weight_numeric: rf.effective_weight_numeric,
            conditions: rf.conditions,
            action: rf.action,
            is_boottime,
            has_clear_action_right,
            provider_context_data_buffer_hex: ctx_hex,
        });
    }

    let filter_index: HashMap<u64, (String, String)> = filters
        .iter()
        .map(|f| (f.filter_id, (f.name.clone(), f.sublayer_name.clone())))
        .collect();

    Ok(WfpState {
        filters,
        filter_index,
        layer_id_index,
    })
}

// ---------------------------------------------------------------------------
// Net events
// ---------------------------------------------------------------------------

/// Enumerates WFP net events using a **separate ephemeral engine** (so the
/// query reflects the most recent events regardless of when the cached
/// `WfpState` was built).
///
/// Returns `Ok(json_array)` with up to 1 000 events sorted by timestamp DESC,
/// or `Err(msg)` on any Win32 failure.
///
/// The special `FWP_E_NET_EVENTS_DISABLED` code produces `Ok(json!([]))` —
/// collection being off is a normal operator choice, not an error; no entry is
/// written to `host.errors()` for that specific code.
///
/// Deviation from `ComplianceApp`: the `layerId < 200` heuristic guard is
/// intentionally omitted — see `CLAUDE.md` deviation #43.
pub(super) fn wfp_net_events(state: &WfpState) -> Result<Value, String> {
    let engine = open_engine().map_err(|e| format!("FwpmEngineOpen0 (net-events): {e}"))?;

    let mut enum_handle = HANDLE::default();
    let hr = unsafe { FwpmNetEventCreateEnumHandle0(engine.handle(), None, &mut enum_handle) };
    if hr != 0 {
        return Err(format!("FwpmNetEventCreateEnumHandle0: 0x{hr:08X}"));
    }

    let mut entries_raw: *mut c_void = std::ptr::null_mut();
    let mut count: u32 = 0;

    let hr = unsafe {
        FwpmNetEventEnum2(
            engine.handle(),
            enum_handle,
            1000,
            &mut entries_raw as *mut *mut c_void as *mut *mut *mut FWPM_NET_EVENT2,
            &mut count,
        )
    };

    unsafe {
        let _ = FwpmNetEventDestroyEnumHandle0(engine.handle(), enum_handle);
    }

    if hr == FWP_E_NET_EVENTS_DISABLED {
        // Not an error — net event collection is simply off.  Return empty
        // array rather than poisoning the WfpState cache or propagating Err.
        return Ok(json!([]));
    }
    if hr != 0 {
        return Err(format!("FwpmNetEventEnum2: 0x{hr:08X}"));
    }

    let _guard = WfpMemoryGuard::new(entries_raw);

    let mut rows: Vec<(String, Value)> = Vec::with_capacity(count as usize);

    for i in 0..(count as isize) {
        // SAFETY: WFP guarantees `count` valid pointers in the array.
        let event_ptr: *mut FWPM_NET_EVENT2 =
            unsafe { *(entries_raw as *mut *mut FWPM_NET_EVENT2).add(i as usize) };
        if event_ptr.is_null() {
            continue;
        }
        let evt = unsafe { &*event_ptr };

        let ts = filetime_to_iso8601(evt.header.timeStamp);
        let event_type_str = net_event_type_name(evt.r#type.0 as u32);
        let proto = protocol_name(evt.header.ipProtocol as i32);

        let (local_addr, remote_addr) = if evt.header.ipVersion == FWP_IP_VERSION_V4 {
            (
                u32_to_ipv4(unsafe { evt.header.Anonymous1.localAddrV4 }),
                u32_to_ipv4(unsafe { evt.header.Anonymous2.remoteAddrV4 }),
            )
        } else if evt.header.ipVersion == FWP_IP_VERSION_V6 {
            (
                bytes_to_ipv6(unsafe { &evt.header.Anonymous1.localAddrV6.byteArray16 }),
                bytes_to_ipv6(unsafe { &evt.header.Anonymous2.remoteAddrV6.byteArray16 }),
            )
        } else {
            (String::new(), String::new())
        };

        let app_id = read_byte_blob_utf16(&evt.header.appId);

        // Classify drop / allow: extract filter_id + layer_id
        let (filter_id, _layer_id, filter_name, sublayer_name, direction) = if evt.r#type
            == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP
            || evt.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW
        {
            let drop_ptr = unsafe { evt.Anonymous.classifyDrop };
            if drop_ptr.is_null() {
                (None, None, None, None, None)
            } else {
                let drop = unsafe { &*drop_ptr };
                let fid = drop.filterId;
                let lid = drop.layerId;
                if fid > 0 && lid > 0 {
                    let (fname, sname) = state.filter_index.get(&fid).cloned().unwrap_or_default();
                    let layer_name = state.layer_id_index.get(&lid).map_or("", String::as_str);
                    let dir = get_layer_direction(layer_name);
                    (Some(fid), Some(lid), Some(fname), Some(sname), Some(dir))
                } else {
                    (None, None, None, None, None)
                }
            }
        } else {
            (None, None, None, None, None)
        };

        let row = json!({
            "timestamp": ts,
            "direction": direction,
            "event_type": event_type_str,
            "protocol_name": proto,
            "local_address": local_addr,
            "local_port": evt.header.localPort,
            "remote_address": remote_addr,
            "remote_port": evt.header.remotePort,
            "app_id": app_id,
            "filter_id": filter_id,
            "filter_name": filter_name,
            "sublayer_name": sublayer_name,
        });

        rows.push((ts, row));
    }

    // Sort by timestamp DESC (lexicographic ISO 8601 sort is correct)
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(Value::Array(rows.into_iter().map(|(_, v)| v).collect()))
}

// ---------------------------------------------------------------------------
// Per-type enumeration helpers
// ---------------------------------------------------------------------------

struct RawFilter {
    filter_id: u64,
    filter_key: GUID,
    name: String,
    flags: u32,
    provider_key: GUID,
    layer_key: GUID,
    sublayer_key: GUID,
    effective_weight_numeric: u64,
    conditions: Vec<WfpCondition>,
    action: String,
    provider_context_key: Option<GUID>,
}

fn enum_layers(engine: &WfpEngine) -> Result<Vec<(GUID, u16, String)>, String> {
    let mut enum_handle = HANDLE::default();
    if unsafe { FwpmLayerCreateEnumHandle0(engine.handle(), None, &mut enum_handle) } != 0 {
        return Ok(Vec::new());
    }
    let _dh = EnumHandleGuard(engine.handle(), enum_handle, |e, h| unsafe {
        let _ = FwpmLayerDestroyEnumHandle0(e, h);
    });

    let mut entries: *mut c_void = std::ptr::null_mut();
    let mut count: u32 = 0;
    if unsafe {
        FwpmLayerEnum0(
            engine.handle(),
            enum_handle,
            1000,
            &mut entries as *mut *mut c_void as *mut *mut *mut FWPM_LAYER0,
            &mut count,
        )
    } != 0
    {
        return Ok(Vec::new());
    }
    let _guard = WfpMemoryGuard::new(entries);

    let mut out = Vec::with_capacity(count as usize);
    for i in 0..(count as isize) {
        let ptr: *mut FWPM_LAYER0 = unsafe { *(entries as *mut *mut FWPM_LAYER0).add(i as usize) };
        if ptr.is_null() {
            continue;
        }
        let layer = unsafe { &*ptr };

        let name = layer_guid_names().get(&layer.layerKey).map_or_else(
            || pwstr_to_string(layer.displayData.name),
            |s| (*s).to_string(),
        );
        out.push((layer.layerKey, layer.layerId, name));
    }
    Ok(out)
}

fn enum_sublayers(engine: &WfpEngine) -> Result<Vec<(GUID, String, u16)>, String> {
    let mut enum_handle = HANDLE::default();
    if unsafe { FwpmSubLayerCreateEnumHandle0(engine.handle(), None, &mut enum_handle) } != 0 {
        return Ok(Vec::new());
    }
    let _dh = EnumHandleGuard(engine.handle(), enum_handle, |e, h| unsafe {
        let _ = FwpmSubLayerDestroyEnumHandle0(e, h);
    });

    let mut entries: *mut c_void = std::ptr::null_mut();
    let mut count: u32 = 0;
    if unsafe {
        FwpmSubLayerEnum0(
            engine.handle(),
            enum_handle,
            1000,
            &mut entries as *mut *mut c_void as *mut *mut *mut FWPM_SUBLAYER0,
            &mut count,
        )
    } != 0
    {
        return Ok(Vec::new());
    }
    let _guard = WfpMemoryGuard::new(entries);

    let mut out = Vec::with_capacity(count as usize);
    for i in 0..(count as isize) {
        let ptr: *mut FWPM_SUBLAYER0 =
            unsafe { *(entries as *mut *mut FWPM_SUBLAYER0).add(i as usize) };
        if ptr.is_null() {
            continue;
        }
        let sl = unsafe { &*ptr };

        let name = sublayer_guid_names().get(&sl.subLayerKey).map_or_else(
            || pwstr_to_string(sl.displayData.name),
            |s| (*s).to_string(),
        );
        out.push((sl.subLayerKey, name, sl.weight));
    }
    Ok(out)
}

fn enum_providers(engine: &WfpEngine) -> Result<Vec<(GUID, String)>, String> {
    let mut enum_handle = HANDLE::default();
    if unsafe { FwpmProviderCreateEnumHandle0(engine.handle(), None, &mut enum_handle) } != 0 {
        return Ok(Vec::new());
    }
    let _dh = EnumHandleGuard(engine.handle(), enum_handle, |e, h| unsafe {
        let _ = FwpmProviderDestroyEnumHandle0(e, h);
    });

    let mut entries: *mut c_void = std::ptr::null_mut();
    let mut count: u32 = 0;
    if unsafe {
        FwpmProviderEnum0(
            engine.handle(),
            enum_handle,
            1000,
            &mut entries as *mut *mut c_void as *mut *mut *mut FWPM_PROVIDER0,
            &mut count,
        )
    } != 0
    {
        return Ok(Vec::new());
    }
    let _guard = WfpMemoryGuard::new(entries);

    let mut out = Vec::with_capacity(count as usize);
    for i in 0..(count as isize) {
        let ptr: *mut FWPM_PROVIDER0 =
            unsafe { *(entries as *mut *mut FWPM_PROVIDER0).add(i as usize) };
        if ptr.is_null() {
            continue;
        }
        let p = unsafe { &*ptr };
        out.push((p.providerKey, pwstr_to_string(p.displayData.name)));
    }
    Ok(out)
}

/// Returns `HashMap<providerContextKey, data_buffer_hex>`.
/// Only `GENERAL_CONTEXT` (type 8) entries populate the hex field.
fn enum_provider_contexts(engine: &WfpEngine) -> Result<Vec<(GUID, String)>, String> {
    let mut enum_handle = HANDLE::default();
    if unsafe { FwpmProviderContextCreateEnumHandle0(engine.handle(), None, &mut enum_handle) } != 0
    {
        return Ok(Vec::new());
    }
    let _dh = EnumHandleGuard(engine.handle(), enum_handle, |e, h| unsafe {
        let _ = FwpmProviderContextDestroyEnumHandle0(e, h);
    });

    let mut entries: *mut c_void = std::ptr::null_mut();
    let mut count: u32 = 0;
    if unsafe {
        FwpmProviderContextEnum0(
            engine.handle(),
            enum_handle,
            1000,
            &mut entries as *mut *mut c_void as *mut *mut *mut FWPM_PROVIDER_CONTEXT0,
            &mut count,
        )
    } != 0
    {
        return Ok(Vec::new());
    }
    let _guard = WfpMemoryGuard::new(entries);

    let mut out = Vec::with_capacity(count as usize);
    for i in 0..(count as isize) {
        let ptr: *mut FWPM_PROVIDER_CONTEXT0 =
            unsafe { *(entries as *mut *mut FWPM_PROVIDER_CONTEXT0).add(i as usize) };
        if ptr.is_null() {
            continue;
        }
        let ctx = unsafe { &*ptr };

        let hex = if ctx.r#type.0 as u32 == 8 {
            // GENERAL_CONTEXT — read dataBuffer as FWP_BYTE_BLOB
            let buf_ptr = unsafe { ctx.Anonymous.dataBuffer };
            if buf_ptr.is_null() {
                String::new()
            } else {
                let blob = unsafe { &*buf_ptr };
                if blob.size > 0 && !blob.data.is_null() && blob.size < 1_048_576 {
                    let bytes =
                        unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) };
                    bytes_to_hex(bytes)
                } else {
                    String::new()
                }
            }
        } else {
            String::new()
        };

        out.push((ctx.providerContextKey, hex));
    }
    Ok(out)
}

fn enum_callouts(engine: &WfpEngine) -> Result<Vec<GUID>, String> {
    let mut enum_handle = HANDLE::default();
    if unsafe { FwpmCalloutCreateEnumHandle0(engine.handle(), None, &mut enum_handle) } != 0 {
        return Ok(Vec::new());
    }
    let _dh = EnumHandleGuard(engine.handle(), enum_handle, |e, h| unsafe {
        let _ = FwpmCalloutDestroyEnumHandle0(e, h);
    });

    let mut entries: *mut c_void = std::ptr::null_mut();
    let mut count: u32 = 0;
    if unsafe {
        FwpmCalloutEnum0(
            engine.handle(),
            enum_handle,
            1000,
            &mut entries as *mut *mut c_void as *mut *mut *mut FWPM_CALLOUT0,
            &mut count,
        )
    } != 0
    {
        return Ok(Vec::new());
    }
    let _guard = WfpMemoryGuard::new(entries);

    let mut out = Vec::with_capacity(count as usize);
    for i in 0..(count as isize) {
        let ptr: *mut FWPM_CALLOUT0 =
            unsafe { *(entries as *mut *mut FWPM_CALLOUT0).add(i as usize) };
        if ptr.is_null() {
            continue;
        }
        out.push(unsafe { (*ptr).calloutKey });
    }
    Ok(out)
}

fn enum_raw_filters(engine: &WfpEngine) -> Result<Vec<RawFilter>, String> {
    let mut enum_handle = HANDLE::default();
    let hr =
        unsafe { FwpmFilterCreateEnumHandle0(engine.handle(), None, &mut enum_handle) };
    if hr != 0 {
        return Err(format!("FwpmFilterCreateEnumHandle0 failed: 0x{hr:08X}"));
    }
    let _dh = EnumHandleGuard(engine.handle(), enum_handle, |e, h| unsafe {
        let _ = FwpmFilterDestroyEnumHandle0(e, h);
    });

    let mut entries: *mut c_void = std::ptr::null_mut();
    let mut count: u32 = 0;
    let hr = unsafe {
        FwpmFilterEnum0(
            engine.handle(),
            enum_handle,
            10_000,
            &mut entries as *mut *mut c_void as *mut *mut *mut FWPM_FILTER0,
            &mut count,
        )
    };
    if hr != 0 {
        return Err(format!("FwpmFilterEnum0 failed: 0x{hr:08X}"));
    }
    let _guard = WfpMemoryGuard::new(entries);

    let mut out = Vec::with_capacity(count as usize);
    for i in 0..(count as isize) {
        let ptr: *mut FWPM_FILTER0 =
            unsafe { *(entries as *mut *mut FWPM_FILTER0).add(i as usize) };
        if ptr.is_null() {
            continue;
        }
        let f = unsafe { &*ptr };

        let name = pwstr_to_string(f.displayData.name);
        let flags = f.flags.0;

        let conditions = if f.numFilterConditions > 0 && !f.filterCondition.is_null() {
            // SAFETY: WFP guarantees a valid condition array.
            unsafe { parse_conditions(f.filterCondition, f.numFilterConditions) }
        } else {
            Vec::new()
        };

        let action_type = f.action.r#type.0 & 0x0F;
        let action = match action_type {
            1 => "BLOCK".to_string(),
            2 => "PERMIT".to_string(),
            3 => "CALLOUT_TERMINATING".to_string(),
            4 => "CALLOUT_INSPECTION".to_string(),
            5 => "CALLOUT_UNKNOWN".to_string(),
            _ => format!("UNKNOWN_{action_type:X}"),
        };

        let effective_weight_numeric = get_weight_numeric(&f.effectiveWeight);

        // providerKey is a pointer to GUID, null if no provider
        let provider_key = if f.providerKey.is_null() {
            GUID::zeroed()
        } else {
            unsafe { *f.providerKey }
        };

        // providerContextKey is in a union — only valid when the filter has a
        // provider context. Check via the HAS_PROVIDER_CONTEXT flag (0x0004).
        let provider_context_key = if flags & 0x0004 != 0 {
            let key = unsafe { f.Anonymous.providerContextKey };
            if key != GUID::zeroed() {
                Some(key)
            } else {
                None
            }
        } else {
            None
        };

        out.push(RawFilter {
            filter_id: f.filterId,
            filter_key: f.filterKey,
            name,
            flags,
            provider_key,
            layer_key: f.layerKey,
            sublayer_key: f.subLayerKey,
            effective_weight_numeric,
            conditions,
            action,
            provider_context_key,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Small RAII for enum handles
// ---------------------------------------------------------------------------

struct EnumHandleGuard<F: Fn(HANDLE, HANDLE)>(HANDLE, HANDLE, F);

impl<F: Fn(HANDLE, HANDLE)> Drop for EnumHandleGuard<F> {
    fn drop(&mut self) {
        (self.2)(self.0, self.1);
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

fn guid_to_string(g: &GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
    )
}

fn pwstr_to_string(p: windows::core::PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { p.to_string() }.unwrap_or_default()
}

fn get_weight_numeric(
    weight: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0,
) -> u64 {
    match weight.r#type.0 {
        1 => (unsafe { weight.Anonymous.uint8 }) as u64,
        4 => {
            let ptr = unsafe { weight.Anonymous.uint64 };
            if ptr.is_null() { 0 } else { unsafe { *ptr } }
        }
        _ => 0,
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as FmtWrite;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn u32_to_ipv4(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

fn bytes_to_ipv6(bytes: &[u8; 16]) -> String {
    let segs: Vec<String> = (0..8)
        .map(|i| format!("{:x}", u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]])))
        .collect();
    segs.join(":")
}

fn read_byte_blob_utf16(
    blob: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB,
) -> String {
    if blob.size == 0 || blob.data.is_null() || blob.size >= 4096 {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) };
    if blob.size % 2 == 0 {
        let u16_slice: &[u16] =
            unsafe { std::slice::from_raw_parts(blob.data.cast::<u16>(), blob.size as usize / 2) };
        let trimmed: Vec<u16> = u16_slice.iter().copied().take_while(|&c| c != 0).collect();
        if let Ok(s) = String::from_utf16(&trimmed) {
            return s;
        }
    }
    // Fallback: raw byte string
    String::from_utf8_lossy(bytes).into_owned()
}

/// Converts a Windows FILETIME to `"yyyy-MM-ddTHH:mm:ss.fffZ"` UTC.
///
/// FILETIME = 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
fn filetime_to_iso8601(ft: FILETIME) -> String {
    let ft_u64 = (ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64;
    const OFFSET: u64 = 116_444_736_000_000_000; // 100-ns from 1601-01-01 to 1970-01-01
    if ft_u64 < OFFSET {
        return String::new();
    }
    let ms_since_epoch = (ft_u64 - OFFSET) / 10_000;
    let secs = ms_since_epoch / 1_000;
    let ms = ms_since_epoch % 1_000;
    let (y, mo, d, h, min, s) = epoch_secs_to_datetime(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{min:02}:{s:02}.{ms:03}Z")
}

/// Civil date from Unix epoch seconds.
/// Uses the algorithm from <https://howardhinnant.github.io/date_algorithms.html>.
fn epoch_secs_to_datetime(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let time_of_day = secs % 86_400;
    let h = time_of_day / 3600;
    let min = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Civil date from days since Unix epoch (2000-03-01 = day 11017 after epoch)
    let z = days + 719_468;
    let era: i64 = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h as u32, min as u32, s as u32)
}

fn net_event_type_name(t: u32) -> &'static str {
    match t {
        0 => "IKEEXT_MM_FAILURE",
        1 => "IKEEXT_QM_FAILURE",
        2 => "IKEEXT_EM_FAILURE",
        3 => "CLASSIFY_DROP",
        4 => "IPSEC_KERNEL_DROP",
        5 => "IKEEXT_EM_FAILURE2",
        6 => "CLASSIFY_ALLOW",
        7 => "CAPABILITY_DROP",
        8 => "CAPABILITY_ALLOW",
        9 => "CLASSIFY_DROP_MAC",
        10 => "LPM_PACKET_ARRIVAL",
        _ => "UNKNOWN",
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
