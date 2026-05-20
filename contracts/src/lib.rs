//! Workspace-wide data types.
//!
//! Mirrors the role of `sdh-fleet-client/contracts/`: holds the pure
//! data structures that other crates exchange. No async, no I/O, no
//! third-party runtime dependencies — anything added here ends up in
//! every other crate of the workspace.

/// Language a greeting should be rendered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    French,
}

/// A request to greet someone in a specific language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    pub name: String,
    pub language: Language,
}

impl Greeting {
    /// Convenience constructor accepting anything that converts into a
    /// `String` (string literals, `&str`, owned `String`, …).
    #[must_use]
    pub fn new(name: impl Into<String>, language: Language) -> Self {
        Self {
            name: name.into(),
            language,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_string_literal() {
        let g = Greeting::new("Alice", Language::English);
        assert_eq!(g.name, "Alice");
        assert_eq!(g.language, Language::English);
    }

    #[test]
    fn new_accepts_owned_string() {
        let owned = String::from("Bob");
        let g = Greeting::new(owned, Language::French);
        assert_eq!(g.name, "Bob");
    }
}
