//! Workspace-wide data types.
//!
//! Mirrors the role of `sdh-fleet-client/contracts/`: holds the pure
//! data structures that other crates exchange. No async, no I/O, no
//! third-party runtime dependencies beyond `serde` + `serde_json`.
//!
//! # Wire discipline
//!
//! Unknown JSON fields are silently ignored on deserialize — `serde`'s
//! default behaviour. We deliberately never use
//! `#[serde(deny_unknown_fields)]`: any future field added by a producer
//! must be tolerated by every existing consumer. This is the same
//! "ignore bits, never drift" rule documented in
//! `sdh-fleet-client/contracts/src/lib.rs`.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// Language a greeting should be rendered in.
///
/// JSON form is the lowercase variant name: `"english"` or `"french"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Language {
    English,
    French,
}

/// A request to greet someone in a specific language.
///
/// # JSON wire format
///
/// Without nickname:
/// ```json
/// {"name": "Alice", "language": "english"}
/// ```
///
/// With nickname:
/// ```json
/// {"name": "Robert", "language": "french", "nickname": "Bob"}
/// ```
///
/// `nickname` is omitted entirely from the serialized output when
/// `None`, and absent fields default to `None` on deserialize — so a
/// legacy payload that pre-dates the `nickname` addition still parses
/// cleanly. This is the same `Option` + `skip_serializing_if` pattern
/// used throughout `sdh-fleet-client/contracts/src/fleet_settings.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Greeting {
    pub name: String,
    pub language: Language,

    /// Optional informal name. When present, greeter implementations
    /// use it in place of `name`. When absent, falls back to `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
}

impl Greeting {
    /// Constructor without a nickname — the common case.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_poc_contracts::{Greeting, Language};
    ///
    /// let g = Greeting::new("Alice", Language::English);
    /// assert_eq!(g.name, "Alice");
    /// assert_eq!(g.nickname, None);
    /// ```
    #[must_use]
    pub fn new(name: impl Into<String>, language: Language) -> Self {
        Self {
            name: name.into(),
            language,
            nickname: None,
        }
    }

    /// Constructor with a nickname.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_poc_contracts::{Greeting, Language};
    ///
    /// let g = Greeting::with_nickname("Robert", Language::French, "Bob");
    /// assert_eq!(g.nickname.as_deref(), Some("Bob"));
    /// ```
    #[must_use]
    pub fn with_nickname(
        name: impl Into<String>,
        language: Language,
        nickname: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            language,
            nickname: Some(nickname.into()),
        }
    }

    /// Returns the preferred display name — nickname when set, real
    /// name otherwise.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.nickname.as_deref().unwrap_or(&self.name)
    }
}

#[cfg(test)]
// Tests routinely .unwrap() on infallible-by-construction values
// (e.g. serializing a struct that has no failure mode). Allowing this
// lint inside the test module keeps the production gate strict while
// the test code stays readable.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_string_literal() {
        let g = Greeting::new("Alice", Language::English);
        assert_eq!(g.name, "Alice");
        assert_eq!(g.language, Language::English);
        assert_eq!(g.nickname, None);
    }

    #[test]
    fn with_nickname_sets_the_optional_field() {
        let g = Greeting::with_nickname("Robert", Language::French, "Bob");
        assert_eq!(g.nickname.as_deref(), Some("Bob"));
    }

    #[test]
    fn display_name_prefers_nickname_when_set() {
        let g = Greeting::with_nickname("Robert", Language::French, "Bob");
        assert_eq!(g.display_name(), "Bob");
    }

    #[test]
    fn display_name_falls_back_to_name_when_nickname_absent() {
        let g = Greeting::new("Alice", Language::English);
        assert_eq!(g.display_name(), "Alice");
    }

    // --- serde wire-format tests ---------------------------------------

    #[test]
    fn language_serializes_lowercase() {
        let json = serde_json::to_string(&Language::English).unwrap();
        assert_eq!(json, r#""english""#);
    }

    #[test]
    fn greeting_without_nickname_omits_the_field() {
        let g = Greeting::new("Alice", Language::English);
        let json = serde_json::to_string(&g).unwrap();
        assert_eq!(json, r#"{"name":"Alice","language":"english"}"#);
    }

    #[test]
    fn greeting_with_nickname_includes_the_field() {
        let g = Greeting::with_nickname("Robert", Language::French, "Bob");
        let json = serde_json::to_string(&g).unwrap();
        assert_eq!(
            json,
            r#"{"name":"Robert","language":"french","nickname":"Bob"}"#
        );
    }

    #[test]
    fn legacy_payload_without_nickname_field_deserializes_to_none() {
        let raw = r#"{"name":"Charlie","language":"english"}"#;
        let g: Greeting = serde_json::from_str(raw).unwrap();
        assert_eq!(g.name, "Charlie");
        assert_eq!(g.language, Language::English);
        assert_eq!(g.nickname, None);
    }

    #[test]
    fn unknown_fields_are_silently_ignored() {
        // The wire-discipline invariant: never use `deny_unknown_fields`
        // on cross-process types. Producers must be free to add fields
        // that older consumers haven't learned about yet.
        let raw = r#"{"name":"Eve","language":"english","future_field":42}"#;
        let g: Greeting = serde_json::from_str(raw).unwrap();
        assert_eq!(g.name, "Eve");
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let original = Greeting::with_nickname("Dave", Language::French, "Davy");
        let json = serde_json::to_string(&original).unwrap();
        let parsed: Greeting = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }
}
