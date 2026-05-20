//! Root binary — composes the workspace crates into a runnable program.
//!
//! Same role as `sdh-fleet-client/src/main.rs`: pulls in types from
//! `contracts/`, dispatches into trait implementations from `greeter/`,
//! and produces the user-visible output.

use rust_poc_contracts::{Greeting, Language};
use rust_poc_greeter::{EnglishGreeter, FrenchGreeter, Greeter};

fn main() {
    let greetings = [
        Greeting::new("World", Language::English),
        Greeting::new("Monde", Language::French),
    ];

    for greeting in &greetings {
        println!("{}", greet(greeting));
    }
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
}
