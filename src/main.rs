//! Root binary — composes the workspace crates into a runnable program.
//!
//! Same role as `sdh-fleet-client/src/main.rs`: pulls in types from
//! `contracts/`, dispatches into trait implementations from `greeter/`,
//! and produces the user-visible output.
//!
//! In addition to plain greetings, this binary demonstrates the
//! contracts crate's `serde` round-trip: JSON → struct → dispatch →
//! string. Same shape as the NATS payload path in
//! `sdh-fleet-client/service/src/handler.rs`, just without the
//! transport layer.

use rust_poc_contracts::{Greeting, Language};
use rust_poc_greeter::{EnglishGreeter, FrenchGreeter, Greeter};

// `main` returns a `Result` so the `?` operator can propagate
// `serde_json` errors. Idiomatic Rust 2024 entry-point and the
// canonical alternative to littering the code with `.unwrap()`.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- in-memory greetings, built from typed constructors -----------
    let greetings = [
        Greeting::new("World", Language::English),
        Greeting::with_nickname("Robert", Language::English, "Bob"),
        Greeting::new("Monde", Language::French),
    ];

    for greeting in &greetings {
        let json = serde_json::to_string(greeting)?;
        println!("{json:<70}  →  {}", greet(greeting));
    }

    // --- payload arriving from "the wire", parsed back into a struct --
    // The unknown `future_field` is silently ignored, demonstrating the
    // forward-compatibility invariant described in
    // `contracts/src/lib.rs`.
    let raw = r#"{"name":"Eve","language":"french","future_field":42}"#;
    let parsed: Greeting = serde_json::from_str(raw)?;
    println!("\nParsed from wire: {parsed:?}");
    println!("Dispatched      : {}", greet(&parsed));

    Ok(())
}

/// Dispatch a greeting to the right `Greeter` implementation.
///
/// Equivalent role to the `match task.action` dispatch in
/// `sdh-fleet-client/service/src/agent/dispatch.rs` — pick the concrete
/// handler at runtime based on a discriminant in the input.
fn greet(greeting: &Greeting) -> String {
    match greeting.language {
        Language::English => EnglishGreeter.greet(greeting),
        Language::French => FrenchGreeter.greet(greeting),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_picks_english_for_english_language() {
        let g = Greeting::new("Alice", Language::English);
        assert_eq!(greet(&g), "Hello, Alice!");
    }

    #[test]
    fn dispatch_picks_french_for_french_language() {
        let g = Greeting::new("Alice", Language::French);
        assert_eq!(greet(&g), "Bonjour, Alice !");
    }

    #[test]
    fn dispatch_works_with_a_greeting_parsed_from_json() {
        let raw = r#"{"name":"Alice","language":"french"}"#;
        let parsed: Greeting = serde_json::from_str(raw).unwrap();
        assert_eq!(greet(&parsed), "Bonjour, Alice !");
    }
}
