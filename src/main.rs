//! Root binary — composes the workspace crates into a runnable program.
//!
//! Same role as `sdh-fleet-client/src/main.rs`: pulls in types from
//! `contracts/`, dispatches into trait implementations from `greeter/`,
//! and produces the user-visible output.
//!
//! In addition to plain greetings, this binary demonstrates the
//! contracts crate's `serde` round-trip and the workspace logging
//! stack: every dispatch emits a structured `info!` event that is
//! mirrored to a compact console writer (stderr) and a JSON file
//! writer under the log directory (see `logging` module).

mod logging;

use rust_poc_contracts::{Greeting, Language};
use rust_poc_greeter::{EnglishGreeter, FrenchGreeter, Greeter};
use tracing::{debug, info};

// `main` returns a `Result` so the `?` operator can propagate
// `serde_json` errors. Idiomatic Rust 2024 entry-point and the
// canonical alternative to littering the code with `.unwrap()`.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `_log_guard` must stay alive for the whole program. When it is
    // dropped, the non-blocking file writer's worker thread shuts
    // down and any pending log lines still in its channel are lost.
    // Same invariant as `sdh-fleet-client/src/main.rs::_log_guard`.
    let _log_guard = logging::init();

    let greetings = [
        Greeting::new("World", Language::English),
        Greeting::with_nickname("Robert", Language::English, "Bob"),
        Greeting::new("Monde", Language::French),
    ];

    for greeting in &greetings {
        let json = serde_json::to_string(greeting)?;
        let output = greet(greeting);

        // Structured event — `name`, `language`, etc. become first-class
        // JSON fields in the file sink, queryable with `jq` or any log
        // aggregator. Don't interpolate them into the message string;
        // keep the message a fixed human-readable label.
        info!(
            name = greeting.name,
            language = ?greeting.language,
            nickname = ?greeting.nickname,
            "greeting dispatched"
        );

        // User-facing stdout output is separate from operational
        // logging — same separation as a real CLI where stdout is the
        // contract and logs are diagnostics.
        println!("{json:<70}  ->  {output}");
    }

    // Demonstrate parsing a payload from "the wire" — unknown fields
    // are silently dropped (see contracts/src/lib.rs invariants).
    let raw = r#"{"name":"Eve","language":"french","future_field":42}"#;
    let parsed: Greeting = serde_json::from_str(raw)?;
    debug!(?parsed, "parsed payload from wire");

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
