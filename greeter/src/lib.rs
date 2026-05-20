//! `Greeter` trait + concrete per-language implementations.
//!
//! Mirrors the role of `sdh-fleet-client/service/src/handler.rs`:
//! defines a single behavioural trait, ships several zero-state
//! implementations, and lets the binary pick the right one at runtime.

use rust_poc_contracts::Greeting;

/// Anything that knows how to turn a `Greeting` into a user-facing
/// string. Zero-state by design — implementations are unit structs so
/// the binary can hold them without lifetime constraints.
pub trait Greeter {
    fn greet(&self, greeting: &Greeting) -> String;
}

/// English-language greeter: `Hello, {display_name}!`.
///
/// Uses `Greeting::display_name()` which prefers the nickname when set,
/// otherwise falls back to the formal `name`.
pub struct EnglishGreeter;

impl Greeter for EnglishGreeter {
    fn greet(&self, greeting: &Greeting) -> String {
        format!("Hello, {}!", greeting.display_name())
    }
}

/// French-language greeter: `Bonjour, {display_name} !`.
pub struct FrenchGreeter;

impl Greeter for FrenchGreeter {
    fn greet(&self, greeting: &Greeting) -> String {
        format!("Bonjour, {} !", greeting.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_poc_contracts::Language;

    #[test]
    fn english_greeter_outputs_hello_with_name() {
        let g = Greeting::new("World", Language::English);
        assert_eq!(EnglishGreeter.greet(&g), "Hello, World!");
    }

    #[test]
    fn french_greeter_outputs_bonjour_with_name() {
        let g = Greeting::new("Monde", Language::French);
        assert_eq!(FrenchGreeter.greet(&g), "Bonjour, Monde !");
    }

    #[test]
    fn greeter_prefers_nickname_when_present() {
        let g = Greeting::with_nickname("Robert", Language::English, "Bob");
        assert_eq!(EnglishGreeter.greet(&g), "Hello, Bob!");
    }

    #[test]
    fn greeters_ignore_the_language_field_their_caller_picked_them_for() {
        // The `language` discriminant is the caller's dispatch signal;
        // a `Greeter` impl trusts that the caller picked the right one
        // and never inspects it. This test pins that contract.
        let g = Greeting::new("Charlie", Language::French);
        assert_eq!(EnglishGreeter.greet(&g), "Hello, Charlie!");
    }
}
