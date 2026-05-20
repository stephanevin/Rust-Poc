//! Per-run WMI connection + helpers used by host bindings.

use serde_json::{Map, Value};
use std::collections::HashMap;
use wmi::{COMLibrary, Variant, WMIConnection};

/// Lazy-initialized WMI handle held for the duration of a single collector
/// run. One WMI query per class, results cached by class name.
pub(super) struct Wmi {
    _com: COMLibrary,
    conn: WMIConnection,
    cache: HashMap<String, Vec<HashMap<String, Variant>>>,
}

impl Wmi {
    pub(super) fn new() -> Result<Self, String> {
        let com = COMLibrary::new().map_err(|e| format!("com init: {e}"))?;
        let conn = WMIConnection::new(com).map_err(|e| format!("wmi connect: {e}"))?;
        Ok(Self {
            _com: com,
            conn,
            cache: HashMap::new(),
        })
    }

    fn rows(&mut self, class: &str) -> Result<&[HashMap<String, Variant>], String> {
        if !self.cache.contains_key(class) {
            let query = format!("SELECT * FROM {class}");
            let results: Vec<HashMap<String, Variant>> = self
                .conn
                .raw_query(&query)
                .map_err(|e| format!("wmi query {class}: {e}"))?;
            self.cache.insert(class.to_string(), results);
        }
        Ok(self.cache.get(class).map_or(&[], Vec::as_slice))
    }

    /// Returns the property of the first row, converted to JSON.
    pub(super) fn query_first(
        &mut self,
        class: &str,
        property: &str,
    ) -> Result<Option<Value>, String> {
        let rows = self.rows(class)?;
        Ok(rows
            .first()
            .and_then(|r| r.get(property))
            .map(variant_to_json))
    }

    /// Returns every row as a JSON object (all properties).
    pub(super) fn query_all(&mut self, class: &str) -> Result<Vec<Value>, String> {
        let rows = self.rows(class)?;
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
