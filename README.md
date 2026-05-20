# Rust-Poc

Workspace Rust personnel — premier "Hello World" structuré sur le même squelette que [`sdh-fleet-client`](https://github.com/sanofi/sdh) (en plus petit).

Objectif : apprendre les idiomes Rust (workspace multi-crates, trait + impls, tests intégrés, clippy pedantic) sans la complexité d'un projet réel (async, NATS, cross-platform).

## Structure

```
Rust-Poc/
├── Cargo.toml              # Workspace root + crate binaire `rust-poc`
├── rust-toolchain.toml     # Pin Rust 1.95.0 + clippy + rustfmt
├── src/main.rs             # Binaire — compose contracts + greeter
├── contracts/              # Types partagés (Greeting, Language)
│   ├── Cargo.toml
│   └── src/lib.rs
└── greeter/                # Trait Greeter + EnglishGreeter / FrenchGreeter
    ├── Cargo.toml
    └── src/lib.rs
```

## Mapping vers `sdh-fleet-client`

| Pattern `sdh-fleet-client` | Équivalent ici |
|---|---|
| Workspace multi-crates avec `default-members` | Idem |
| `contracts/` — types purs, zéro runtime dep | `contracts/` — `Greeting` + enum `Language` |
| `service/src/handler.rs` — trait `TaskHandler` + impls | `greeter/src/lib.rs` — trait `Greeter` + impls |
| `service/src/agent/dispatch.rs` — `match task.action` | `src/main.rs::greet()` — `match greeting.language` |
| `[workspace.lints.clippy]` pedantic | Idem |
| Tests inline dans chaque module (`#[cfg(test)] mod tests`) | Idem |

## Commandes

```powershell
# Compile sans linker (rapide — type-check)
cargo check

# Compile + lance les tests de toutes les crates
cargo test

# Compile + execute le binaire
cargo run

# Lint pedantique (zero warning attendu)
cargo clippy -- -W clippy::pedantic

# Formate tout le code aux conventions Rust officielles
cargo fmt

# Compile en release (optimisations + binaire final)
cargo build --release
```

## Resultat attendu de `cargo run`

```
Hello, World!
Bonjour, Monde !
```

## Notes pour la suite

Les prochaines etapes naturelles pour enrichir ce POC sans casser le pattern :

- Ajouter une 3e crate `greeter-async` qui implemente `Greeter` via `tokio::time::sleep` pour decouvrir l'async-await
- Faire que `Greeting` derive `serde::{Serialize, Deserialize}` pour decouvrir la serialisation JSON
- Ajouter une crate `cli` avec `clap` pour parser des arguments en ligne de commande
- Introduire un module de gestion d'erreur avec `thiserror` et `Result<T, E>`
- Ajouter un test d'integration sous `tests/` au niveau workspace
