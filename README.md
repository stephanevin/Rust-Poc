# Rust-Poc

Workspace Rust personnel — collecteur Lua in-process modélisé sur [`sdh-fleet-client`](https://github.com/sanofi/sdh) (en plus petit, sans NATS, sans transport).

Objectif : apprendre les idiomes Rust (workspace multi-crates, FFI Windows, sandbox Lua, async/tokio, clippy pedantic) sur un cas concret — exécuter un script `general.lua` dans une VM mlua durcie qui appelle WMI / Registry / ADSI via `rust-poc-lua`, et imprimer le résultat en JSON sur stdout.

> **AI coding agents**: read [`CLAUDE.md`](CLAUDE.md) first. It defines the
> conventions, lint policy, and the "act as a senior dev partner" guidance
> inherited from `sdh-fleet-client`. [`AGENTS.md`](AGENTS.md) points to the
> same file for tools that look there.

## Structure

```
Rust-Poc/
├── Cargo.toml                  # Workspace root + crate binaire `rust-poc`
├── rust-toolchain.toml         # Pin Rust 1.95.0 + clippy + rustfmt
├── publish-innosetup.ps1       # Orchestrateur build → stage → sign → ISCC
├── src/
│   ├── main.rs                 # Binaire `collect-config` — entry point
│   └── logging.rs              # Stack tracing (console stderr + JSON file)
├── collectors/
│   └── general.lua             # Script collector exécuté par défaut
├── contracts/                  # Placeholder pour de futurs wire-types
│   ├── Cargo.toml
│   └── src/lib.rs
├── rust-poc-lua/               # Runtime mlua + bindings host.* (WMI, Registry, AD, ...)
│   ├── Cargo.toml
│   └── src/                    # runtime.rs, host.rs, sandbox.rs, ad.rs, wmi.rs, ...
└── Setup/                      # Installeur Inno Setup
    ├── CollectConfigSetup.iss  # Script principal (~150 lignes)
    └── README.md               # Design notes, signing, GUID dédié
```

## Mapping vers `sdh-fleet-client`

| Pattern `sdh-fleet-client` | Équivalent ici |
|---|---|
| Workspace multi-crates avec `default-members` | Idem |
| `contracts/` — types purs, zéro runtime dep | `contracts/` — placeholder pour wire-types futurs |
| `lua/` — runtime mlua + bindings host.* | `rust-poc-lua/` — **port verbatim** (cf. CLAUDE.md § Deviations) |
| `service/src/main.rs` — composer | `src/main.rs` — composer (args → runtime → JSON) |
| `[workspace.lints.clippy]` pedantic | Idem |
| Tests inline dans chaque module (`#[cfg(test)] mod tests`) | Idem |

## Commandes

```powershell
# Compile sans linker (rapide — type-check)
cargo check

# Compile + lance les tests de toutes les crates
cargo test

# Compile + execute le collecteur sur ./collectors/general.lua
cargo run

# Avec un script ou un perimetre explicite
cargo run -- general.lua some-perimeter

# Pipe-friendly : seul le JSON va sur stdout, le reste sur stderr
cargo run --quiet > config.json
cargo run --quiet | jq '.machine_name'

# Lint pedantique (zero warning attendu)
cargo clippy --workspace --all-targets -- -D warnings

# Formate tout le code aux conventions Rust officielles
cargo fmt --all

# Compile en release (optimisations + binaire final)
cargo build --release
```

## Installeur Windows

```powershell
# Build complet — version lue depuis Cargo.toml, .exe signé Authenticode
.\publish-innosetup.ps1

# Itération locale sans signature (SmartScreen va râler, OK pour les tests)
.\publish-innosetup.ps1 -SkipSign

# Rebuild de l'EXE uniquement (publish/ déjà peuplé d'un run précédent)
.\publish-innosetup.ps1 -SkipBuild
```

Sortie : `Setup/Output/CollectConfigSetup-<Version>.exe` — installeur Inno
Setup modélisé sur [`sdh-complianceapp/Setup/`](../sdh-complianceapp/Setup/),
en plus simple (pas de service Windows, pas de wizard, pas de bridge MSI).
Détails de design + ce que l'installeur fait/ne fait pas : voir
[`Setup/README.md`](Setup/README.md).

Prérequis (validés en pre-flight par le script) :

- **Inno Setup 6** sur le PATH ou sous `Program Files (x86)` (`winget install JRSoftware.InnoSetup`).
- **Windows SDK** pour `signtool.exe` (`winget install Microsoft.WindowsSDK.10.0.26100`) — seulement si signature.
- **Certificat code-signing** importé dans `Cert:\CurrentUser\My`, thumbprint dans `$env:SDH_SIGN_THUMBPRINT` — seulement si signature.

## Resultat attendu de `cargo run`

```json
{
  "bios_details": "...",
  "cpu_details": "...",
  "disk_size_bytes": 135771664384,
  "machine_name": "E00AVDDWDEV0271",
  "os_caption": "Microsoft Windows 11 Enterprise",
  "os_version": "10.0.26100.8246",
  ...
}
```

Sur stderr, en parallèle : la ligne de progression `collect-config: running general.lua (...)` et les logs `tracing` (niveau INFO par défaut, ajustable via `RUST_LOG`).

## Notes pour la suite

Les prochaines etapes naturelles pour enrichir ce POC :

- Ajouter un trait `Collector` dans `contracts/` + plusieurs implementations (pour faire revivre le pattern trait+dispatch demontre dans l'historique git)
- Ajouter une crate `cli` avec `clap` pour remplacer le parsing positional des args dans `main.rs`
- Introduire un module de gestion d'erreur avec `thiserror` pour exposer des variants typees au lieu de la `LuaError(String)` actuelle
- Ajouter un test d'integration sous `tests/` au niveau workspace
- Implementer le port macOS de `rust-poc-lua` (actuellement stub `#[cfg(not(windows))]`)
