//! WFP filter pipeline — port of `WfpFilterPipeline.cs` and the two view
//! transformers (`WfpSubLayerDetails.cs`, `WfpFirewallView.cs`).
//!
//! ## Pipeline for `wfp_firewall_view`
//!
//! 1. **`filter_ale_filters`** — keep only `ALE_AUTH_LISTEN_V`\*/`ALE_AUTH_CONNECT_V`\*/
//!    `ALE_AUTH_RECV_ACCEPT_V`\* layers, drop `_DISCARD` layers, `TEREDO` /
//!    `MPSSVC_APP_ISOLATION` / `MPSSVC_WSH` sublayers, `CALLOUT_INSPECTION` actions,
//!    and filters whose names contain `"SentinelOne built-in rule -"`.
//! 2. **`compute_shadowing`** — sort by `layer_id ASC → sublayer_weight DESC →
//!    effective_weight_numeric DESC`; mark `is_ignored` on any filter that is
//!    shadowed by a preceding filter with the same `(layer_name, sublayer_name,
//!    is_boottime)` that has zero conditions and a terminal action.
//! 3. **`deduplicate_filters`** — group non-ignored filters by
//!    `(name, normalize_layer_name(layer_name), sublayer_name, action,
//!    conditions_json)`, pick the representative with the highest
//!    `effective_weight_numeric`, then sort groups and assign 1-based `order_id`.

use std::cmp::Reverse;
use std::collections::HashMap;

use serde_json::{Value, json};

use super::wfp::WfpEnrichedFilter;
use super::wfp::get_layer_direction;
use super::wfp_conditions::{conditions_json, format_compact};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// `wfp_sublayer_details` binding: groups all WFP filters by sublayer,
/// sorted by sublayer weight DESC.
///
/// Mirrors `WfpSubLayerDetails.cs`.
pub(super) fn wfp_sublayer_details(filters: &[WfpEnrichedFilter]) -> Value {
    // Group by (sublayer_key, sublayer_name, sublayer_weight)
    type GroupKey = (String, String, u16);
    let mut groups: HashMap<GroupKey, Vec<&WfpEnrichedFilter>> = HashMap::new();

    for f in filters {
        let key = (
            f.sublayer_key.clone(),
            f.sublayer_name.clone(),
            f.sublayer_weight,
        );
        groups.entry(key).or_default().push(f);
    }

    let mut group_list: Vec<(GroupKey, Vec<&WfpEnrichedFilter>)> = groups.into_iter().collect();

    // Sort groups by sublayer_weight DESC
    group_list.sort_by_key(|g| Reverse(g.0.2));

    let rows: Vec<Value> = group_list
        .iter_mut()
        .map(|((sublayer_key, sublayer_name, weight), group)| {
            // Sort within group: layer_name ASC then effective_weight DESC
            group.sort_by(|a, b| {
                a.layer_name
                    .cmp(&b.layer_name)
                    .then_with(|| b.effective_weight_numeric.cmp(&a.effective_weight_numeric))
            });

            let wfp_filter_details: Vec<Value> = group
                .iter()
                .map(|f| {
                    json!({
                        "filter_id": f.filter_id,
                        "name": f.name,
                        "effective_weight": f.effective_weight,
                        "provider_name": f.provider_name,
                        "layer_name": f.layer_name,
                        "action": f.action,
                        "is_boottime": f.is_boottime,
                        "has_clear_action_right": f.has_clear_action_right,
                        "conditions": format_compact(&f.conditions),
                    })
                })
                .collect();

            // Field order after BTreeMap alphabetical sort:
            //   sublayer_key → sublayer_name → total_filters → weight → wfp_filter_details
            // The sublayer identifying fields are therefore always visible before the
            // (potentially long) filter array — mirroring ComplianceApp's intent of
            // SubLayerName-first layout.
            json!({
                "sublayer_key": sublayer_key,
                "sublayer_name": sublayer_name,
                "total_filters": group.len(),
                "weight": weight,
                "wfp_filter_details": wfp_filter_details,
            })
        })
        .collect();

    Value::Array(rows)
}

/// `wfp_firewall_view` binding: ALE-filtered, shadow-computed, deduplicated
/// view of WFP filters.
///
/// Mirrors `WfpFirewallView.cs` + `WfpFilterPipeline.cs`.
pub(super) fn wfp_firewall_view(filters: &[WfpEnrichedFilter]) -> Value {
    let ale = filter_ale_filters(filters);
    let ordered = compute_shadowing(ale);
    let deduped = deduplicate_filters(&ordered);
    Value::Array(deduped)
}

// ---------------------------------------------------------------------------
// Pipeline step 1: filter ALE
// ---------------------------------------------------------------------------

fn filter_ale_filters(filters: &[WfpEnrichedFilter]) -> Vec<&WfpEnrichedFilter> {
    filters
        .iter()
        .filter(|f| {
            !f.name
                .to_lowercase()
                .contains("sentinelone built-in rule -")
        })
        .filter(|f| {
            let ln = f.layer_name.as_str();
            ln.contains("ALE_AUTH_LISTEN_V")
                || ln.contains("ALE_AUTH_CONNECT_V")
                || ln.contains("ALE_AUTH_RECV_ACCEPT_V")
        })
        .filter(|f| !f.layer_name.contains("_DISCARD"))
        .filter(|f| {
            let sn = f.sublayer_name.as_str();
            !sn.contains("TEREDO")
                && !sn.contains("MPSSVC_APP_ISOLATION")
                && !sn.contains("MPSSVC_WSH")
        })
        .filter(|f| !f.action.contains("CALLOUT_INSPECTION"))
        .collect()
}

// ---------------------------------------------------------------------------
// Pipeline step 2: compute shadowing
// ---------------------------------------------------------------------------

struct ArbitratedFilter<'a> {
    filter: &'a WfpEnrichedFilter,
    is_ignored: bool,
    conditions_compact: String,
    conditions_json_str: String,
}

fn compute_shadowing(mut ale: Vec<&WfpEnrichedFilter>) -> Vec<ArbitratedFilter<'_>> {
    // Sort: layer_id ASC → sublayer_weight DESC → effective_weight_numeric DESC
    ale.sort_by(|a, b| {
        a.layer_id
            .cmp(&b.layer_id)
            .then_with(|| b.sublayer_weight.cmp(&a.sublayer_weight))
            .then_with(|| b.effective_weight_numeric.cmp(&a.effective_weight_numeric))
    });

    let mut result: Vec<ArbitratedFilter<'_>> = ale
        .iter()
        .map(|f| ArbitratedFilter {
            filter: f,
            is_ignored: false,
            conditions_compact: format_compact(&f.conditions),
            conditions_json_str: conditions_json(&f.conditions),
        })
        .collect();

    // Mark shadowed filters
    for current in 0..result.len() {
        for prev in 0..current {
            if result[prev].is_ignored {
                continue;
            }
            let p = result[prev].filter;
            let c = result[current].filter;
            if p.layer_name != c.layer_name {
                continue;
            }
            if p.sublayer_name != c.sublayer_name {
                continue;
            }
            if p.is_boottime != c.is_boottime {
                continue;
            }
            if !p.conditions.is_empty() {
                continue;
            }

            let is_terminal = p.action.contains("PERMIT")
                || p.action.contains("BLOCK")
                || p.action.contains("CALLOUT_TERMINATING")
                || p.action.contains("CALLOUT_UNKNOWN");
            if !is_terminal {
                continue;
            }

            result[current].is_ignored = true;
            break;
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Pipeline step 3: deduplicate
// ---------------------------------------------------------------------------

fn deduplicate_filters(ordered: &[ArbitratedFilter<'_>]) -> Vec<Value> {
    // Key: (name, normalized_layer, sublayer_name, action, conditions_json)
    type DedupeKey = (String, String, String, String, String);

    let mut groups: Vec<(DedupeKey, Vec<&ArbitratedFilter<'_>>)> = Vec::new();
    let mut key_index: HashMap<DedupeKey, usize> = HashMap::new();

    for af in ordered.iter().filter(|x| !x.is_ignored) {
        let key = (
            af.filter.name.clone(),
            normalize_layer_name(&af.filter.layer_name),
            af.filter.sublayer_name.clone(),
            af.filter.action.clone(),
            af.conditions_json_str.clone(),
        );
        let idx = key_index.entry(key.clone()).or_insert_with(|| {
            let i = groups.len();
            groups.push((key.clone(), Vec::new()));
            i
        });
        groups[*idx].1.push(af);
    }

    // Build output rows
    let mut rows: Vec<(u32, u16, u64, Value)> = groups
        .iter()
        .map(|((name, layer_norm, sublayer_name, action, conds_json_str), group)| {
            // Representative = max effective_weight_numeric.
            // `group` is always non-empty (we only create a group when the
            // first element is inserted), so `max_by_key` cannot return None.
            // We use `unwrap_or_else(|| group[0])` as a statically-safe
            // fallback that preserves this invariant without `expect`.
            let rep = group
                .iter()
                .max_by_key(|af| af.filter.effective_weight_numeric)
                .unwrap_or_else(|| &group[0]);

            let direction = get_layer_direction(&rep.filter.layer_name);
            let dir_order = direction_order(direction);
            let sub_weight = rep.filter.sublayer_weight;
            let eff_weight = group
                .iter()
                .map(|af| af.filter.effective_weight_numeric)
                .max()
                .unwrap_or(0);

            let variant_details: Vec<Value> = group
                .iter()
                .map(|af| {
                    json!({
                        "filter_id": af.filter.filter_id,
                        "layer_name": af.filter.layer_name,
                        "is_boottime": af.filter.is_boottime,
                        "provider_context_data_buffer_hex": af.filter.provider_context_data_buffer_hex,
                    })
                })
                .collect();

            let row = json!({
                "order_id": Value::Null, // placeholder; filled below
                "direction": direction,
                "name": name,
                "provider_name": rep.filter.provider_name,
                "layer_name_normalized": layer_norm,
                "sublayer_name": sublayer_name,
                "action": action,
                "has_clear_action_right": rep.filter.has_clear_action_right,
                "conditions": rep.conditions_compact,
                "conditions_json": conds_json_str,
                "variant_details": variant_details,
            });

            (dir_order, sub_weight, eff_weight, row)
        })
        .collect();

    // Sort: direction_order ASC → sublayer_weight DESC → effective_weight DESC
    rows.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| b.2.cmp(&a.2))
    });

    // Assign 1-based order_id
    rows.into_iter()
        .enumerate()
        .map(|(i, (_, _, _, mut row))| {
            row["order_id"] = json!(i as u64 + 1);
            row
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strips the `_V4`, `_V6`, ` V4`, ` V6` (or lowercase) suffix from a layer name.
/// Regex equivalent: `[_ ]?v[46]\b` (case-insensitive).
///
/// All known WFP layer names use the 3-char `_Vx` form; the bare `Vx` fallback
/// handles any hypothetical unseparated case.
fn normalize_layer_name(name: &str) -> String {
    let lower = name.to_lowercase();
    let len = lower.len();
    if len >= 3 {
        let tail = &lower[len - 3..];
        if tail == "_v4" || tail == "_v6" || tail == " v4" || tail == " v6" {
            return name[..len - 3].to_string();
        }
    }
    if len >= 2 {
        let tail = &lower[len - 2..];
        if tail == "v4" || tail == "v6" {
            return name[..len - 2].to_string();
        }
    }
    name.to_string()
}

fn direction_order(direction: &str) -> u32 {
    match direction {
        "Inbound" => 0,
        "Both" => 1,
        "Outbound" => 2,
        _ => 3,
    }
}
