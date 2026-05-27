//! Per-run WMI connection + helpers used by host bindings.
//!
//! Originally single-namespace (`root\cimv2`), extended to a
//! per-namespace cache to support BitLocker
//! (`root\CIMV2\Security\MicrosoftVolumeEncryption`) and Credential
//! Guard (`root\Microsoft\Windows\DeviceGuard`).  Each namespace owns
//! its `WMIConnection` and a `class → rows` cache so repeat lookups
//! within a single collector run cost one query each.

// Product names like "BitLocker" and "Credential Guard" are flagged by
// `doc_markdown` as bare-identifier mentions in prose.  Backticking
// every occurrence hurts readability without adding precision, so the
// lint is silenced at module scope — same posture as `updates.rs`.
#![allow(clippy::doc_markdown)]

use serde_json::{Map, Value};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use wmi::{COMLibrary, Variant, WMIConnection};

/// Default WMI namespace — same as `WMIConnection::new(com)`.
pub(super) const DEFAULT_NS: &str = r"ROOT\CIMV2";

/// One WMI connection plus a per-class result cache.
struct NamespaceState {
    conn: WMIConnection,
    /// `class → SELECT * FROM <class>` rows.  Populated lazily.
    cache: HashMap<String, Vec<HashMap<String, Variant>>>,
}

/// Lazy-initialized WMI handles held for the duration of a single
/// collector run.  Caches connections **and** unfiltered queries per
/// namespace; filtered queries (`WHERE …`) bypass the cache because the
/// filter varies per call site.
pub(super) struct Wmi {
    com: COMLibrary,
    namespaces: HashMap<String, NamespaceState>,
}

impl Wmi {
    /// Opens the default `ROOT\CIMV2` connection eagerly so the first
    /// `host.wmi_*` call from Lua does not pay COM-init latency.  Extra
    /// namespaces are opened on demand by [`ensure_ns`].
    pub(super) fn new() -> Result<Self, String> {
        let com = COMLibrary::new().map_err(|e| format!("com init: {e}"))?;
        let conn = WMIConnection::new(com).map_err(|e| format!("wmi connect: {e}"))?;
        let mut namespaces = HashMap::new();
        namespaces.insert(
            DEFAULT_NS.to_string(),
            NamespaceState {
                conn,
                cache: HashMap::new(),
            },
        );
        Ok(Self { com, namespaces })
    }

    /// Opens (or returns the cached connection for) the given namespace.
    ///
    /// `COMLibrary` is `Copy`, so the marker is duplicated cheaply for
    /// each new namespace.  The connection itself is what's expensive
    /// (one DCOM round-trip).
    fn ensure_ns(&mut self, namespace: &str) -> Result<&mut NamespaceState, String> {
        if let Entry::Vacant(slot) = self.namespaces.entry(namespace.to_string()) {
            let conn = WMIConnection::with_namespace_path(namespace, self.com)
                .map_err(|e| format!("wmi connect {namespace}: {e}"))?;
            slot.insert(NamespaceState {
                conn,
                cache: HashMap::new(),
            });
        }
        self.namespaces
            .get_mut(namespace)
            .ok_or_else(|| format!("internal: namespace {namespace} missing after insert"))
    }

    /// Borrow the bare `WMIConnection` for a namespace.
    ///
    /// Used by `bitlocker.rs` to call
    /// [`WMIConnection::exec_instance_method`], which needs a typed
    /// `Class` generic and bypasses the per-class cache (method calls
    /// mutate state, caching their results would be wrong).
    pub(super) fn connection_ns(&mut self, namespace: &str) -> Result<&WMIConnection, String> {
        Ok(&self.ensure_ns(namespace)?.conn)
    }

    /// Lazy `SELECT * FROM <class>` cached per (namespace, class).
    fn rows_ns(
        &mut self,
        namespace: &str,
        class: &str,
    ) -> Result<&[HashMap<String, Variant>], String> {
        let state = self.ensure_ns(namespace)?;
        if !state.cache.contains_key(class) {
            let query = format!("SELECT * FROM {class}");
            let rows: Vec<HashMap<String, Variant>> = state
                .conn
                .raw_query(&query)
                .map_err(|e| format!("wmi query {namespace}::{class}: {e}"))?;
            state.cache.insert(class.to_string(), rows);
        }
        Ok(state.cache.get(class).map_or(&[], Vec::as_slice))
    }

    /// Returns the property of the first row in `root\cimv2`, converted
    /// to JSON.  Back-compat shim for call sites that pre-date the
    /// per-namespace cache.
    pub(super) fn query_first(
        &mut self,
        class: &str,
        property: &str,
    ) -> Result<Option<Value>, String> {
        self.query_first_ns(DEFAULT_NS, class, property)
    }

    /// Returns the property of the first row of `<namespace>.<class>`.
    pub(super) fn query_first_ns(
        &mut self,
        namespace: &str,
        class: &str,
        property: &str,
    ) -> Result<Option<Value>, String> {
        let rows = self.rows_ns(namespace, class)?;
        Ok(rows
            .first()
            .and_then(|r| r.get(property))
            .map(variant_to_json))
    }

    /// Returns every row of `root\cimv2.<class>` as a JSON object.
    pub(super) fn query_all(&mut self, class: &str) -> Result<Vec<Value>, String> {
        self.query_all_ns(DEFAULT_NS, class)
    }

    /// Returns every row of `<namespace>.<class>` as a JSON object.
    pub(super) fn query_all_ns(
        &mut self,
        namespace: &str,
        class: &str,
    ) -> Result<Vec<Value>, String> {
        let rows = self.rows_ns(namespace, class)?;
        Ok(rows
            .iter()
            .map(|r| {
                let mut obj = Map::new();
                for (k, v) in r {
                    obj.insert(k.clone(), variant_to_json(v));
                }
                Value::Object(obj)
            })
            .collect())
    }

    /// Runs `SELECT * FROM <class> WHERE <where_clause>` and returns the
    /// first matching row as the raw `HashMap<String, Variant>` (the
    /// caller typically needs `Variant` access for keys like `DeviceID`
    /// that get composed into a WMI object path for `ExecMethod`).
    ///
    /// Bypasses the cache — every distinct filter would otherwise blow
    /// the cache up indefinitely.  Use [`query_first_ns`] when the
    /// whole `SELECT * FROM <class>` is OK to cache.
    pub(super) fn query_filtered_first_ns(
        &mut self,
        namespace: &str,
        class: &str,
        where_clause: &str,
    ) -> Result<Option<HashMap<String, Variant>>, String> {
        let state = self.ensure_ns(namespace)?;
        let q = format!("SELECT * FROM {class} WHERE {where_clause}");
        let rows: Vec<HashMap<String, Variant>> = state
            .conn
            .raw_query(&q)
            .map_err(|e| format!("wmi query {namespace}::{class} WHERE {where_clause}: {e}"))?;
        Ok(rows.into_iter().next())
    }
}

fn variant_to_json(v: &Variant) -> Value {
    match v {
        Variant::Null | Variant::Empty => Value::Null,
        Variant::String(s) => Value::String(s.clone()),
        Variant::Bool(b) => Value::Bool(*b),
        Variant::UI1(n) => Value::from(*n),
        Variant::UI2(n) => Value::from(*n),
        Variant::UI4(n) => Value::from(*n),
        Variant::UI8(n) => Value::from(*n),
        Variant::I1(n) => Value::from(*n),
        Variant::I2(n) => Value::from(*n),
        Variant::I4(n) => Value::from(*n),
        Variant::I8(n) => Value::from(*n),
        Variant::R4(f) => {
            serde_json::Number::from_f64(f64::from(*f)).map_or(Value::Null, Value::Number)
        }
        Variant::R8(f) => serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number),
        Variant::Array(arr) => Value::Array(arr.iter().map(variant_to_json).collect()),
        other => Value::String(format!("{other:?}")),
    }
}
