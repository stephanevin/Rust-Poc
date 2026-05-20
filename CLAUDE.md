# CLAUDE.md — Rust-Poc

Personal Rust learning workspace. This file primes any AI coding agent
(Claude Code, Cursor, Copilot, Codex, Aider, …) with the conventions
inherited from `sdh-fleet/sdh-fleet-client`, so changes here look and
feel like changes there.

## Pedagogical context

This repository exists for learning. The owner has 20+ years of C# and
PowerShell experience but is new to Rust. When making changes:

- Prefer **idiomatic, readable** solutions over clever ones. The owner
  needs to be able to read the code six months later and understand it.
- When introducing a new concept (lifetimes, trait objects, async,
  custom derives, macros, `unsafe`, etc.), **call it out** in the
  response so the owner knows what to study next.
- When a problem has multiple legitimate solutions, briefly state the
  trade-off rather than silently picking one.
- Do NOT auto-correct unidiomatic code without explaining why it was
  unidiomatic — the owner learns more from the explanation than from
  receiving a polished diff.
- Reference relevant chapters of the official Rust Book
  (<https://doc.rust-lang.org/book/>) when introducing a new concept,
  if you remember which chapter covers it.

## Commands

```bash
cargo check --workspace --all-targets    # Type-check everything (~1s, used dozens of times per session)
cargo clippy --workspace --all-targets -- -D warnings  # Lint, warnings as errors
cargo fmt                                # Format to rustfmt defaults
cargo test --workspace                   # Unit + integration + doc tests
cargo run -p rust-poc                    # Build + execute the root binary
cargo build --release                    # Optimised final binary in target/release/

# Regenerate JSON schemas under contracts/generated/schemas/. Run after
# any change to a struct or enum in contracts/. Same workflow as
# sdh-fleet-client/contracts.
cargo run -p rust-poc-contracts --bin gen-schemas --features schema
```

Note: `cargo run` at the workspace root launches `rust-poc` thanks to
the `default-run = "rust-poc"` key in the root `Cargo.toml`. The
schema generator is **not** the default — it lives in `contracts/`
and is gated behind the `schema` feature, so it must be invoked
explicitly via `cargo run -p rust-poc-contracts --bin gen-schemas
--features schema`.

The pinned toolchain (Rust 1.95.0 + clippy + rustfmt) lives in
`rust-toolchain.toml` — rustup picks it up automatically on the first
`cargo` invocation in this directory.

## Architecture

Three sibling crates in one workspace, modelled on the cross-boundary
structure of `sdh-fleet-client`:

| Crate | Role | Mirror in sdh-fleet-client |
|---|---|---|
| **`rust-poc-contracts`** (`contracts/`) | Shared types only. No runtime deps, no I/O. | `sdh-fleet-client/contracts/` |
| **`rust-poc-greeter`** (`greeter/`) | `Greeter` trait + concrete implementations. | `sdh-fleet-client/service/src/handler.rs` |
| **`rust-poc`** (root + `src/main.rs`) | Composer — dispatches into greeter impls based on a discriminant in the input. | `sdh-fleet-client/src/main.rs` |

### Architectural rules

- **`contracts/` is the only place a cross-crate type lives.** Never
  duplicate a struct or enum into `greeter/` or the root bin — extend
  `contracts/` and let the others import. This mirrors the same rule
  in `sdh-fleet-client/contracts/`.
- **`contracts/` keeps runtime deps minimal.** `serde` + `serde_json`
  are always-on (they are de-facto stdlib for any wire type). Anything
  heavier — `schemars`, `tokio`, `reqwest` — goes behind a feature
  flag, exactly like `sdh-fleet-client/contracts/Cargo.toml`.
- **`greeter/` exposes behaviour through a trait, never concrete
  types.** The root bin must depend on `Greeter`, not on
  `EnglishGreeter` directly, in any non-trivial dispatch logic.
- **The root bin is a composer, not a place for logic.** New behaviour
  goes in `greeter/` (or a new sibling crate); `main.rs` only wires
  things together.

### Wire-format discipline

Every struct or enum in `contracts/` that crosses a process boundary
(JSON file on disk, HTTP body, log payload, …) follows these rules:

- **Always derive `Serialize` + `Deserialize`.** Even if a type is
  internal today, the derive is cheap and lets the type become wire-
  visible later without a breaking change.
- **Never use `#[serde(deny_unknown_fields)]`.** A producer that adds a
  new field must not break a consumer that hasn't learned about it yet.
  The default serde behaviour (silently ignore unknown fields) is the
  forward-compatibility contract.
- **Optional fields use `Option<T>` + `#[serde(default,
  skip_serializing_if = "Option::is_none")]`.** This keeps the wire
  format clean (no `"nickname": null` noise) AND lets legacy payloads
  without the field parse cleanly.
- **Enum variants serialize to lowercase by default**
  (`#[serde(rename_all = "lowercase")]`). Tagged unions use
  `#[serde(tag = "type", rename_all = "snake_case")]` when needed —
  same convention as `sdh-fleet-client/contracts/src/agent.rs`.
- **JSON Schema is generated, not hand-written.** Schemas live in
  `contracts/generated/schemas/` and are produced by `cargo run -p
  rust-poc-contracts --bin gen-schemas --features schema`. Re-run after
  any struct change and commit the diff.

Round-trip tests are the cheapest defence against accidental wire
breakage — pin the exact JSON string with `assert_eq!`. Several
examples live in `contracts/src/lib.rs::tests`.

## Code quality

The workspace inherits the same lint policy as `sdh-fleet-client`:

- `clippy::pedantic` at `warn` level
- `clippy::unwrap_used` at `warn`
- `clippy::expect_used` at `warn`
- The gate is `cargo clippy -- -D warnings` → zero warnings

Rules derived from the lints:

- **No `unwrap()` or `expect()` in production code paths.** Use `?`
  and `Result<T, E>`. When `expect` is genuinely justified
  (infallible-by-construction, unrecoverable startup), add
  `#[allow(clippy::expect_used)]` directly on the call with a comment
  explaining the invariant.
- **No `panic!()`** in library code. `unreachable!()` is acceptable
  for states the type system can't yet rule out, but prefer encoding
  the impossibility in the types when feasible.
- **Tests live inline** in each module under `#[cfg(test)] mod tests`,
  one block per file. A parallel `tests/` directory is reserved for
  integration tests that exercise multiple crates together — none
  exist yet.
- **Doc-tests are welcome.** Examples in `///` blocks compile and run
  under `cargo test`; they double as a free correctness gate for the
  public API.
- **Public APIs must have a doc comment** (`///`) explaining intent
  and at least one `# Examples` section once the API stabilises.

## Conventions

- **Module visibility**: prefer `pub(crate)` over `pub` unless the
  item is genuinely part of the crate's public surface. Every `pub` is
  a commitment that breaks downstream code if changed.
- **Constructors**: name them `new` if there is only one; name them
  descriptively (`from_str`, `with_capacity`, `from_iter`) when the
  caller needs to pick between several.
- **String types**: take `impl Into<String>` in constructors that
  store the value; take `&str` for read-only parameters; return owned
  `String` only when the function genuinely produces a new one.
- **Derives**: `Debug, Clone, Copy, PartialEq, Eq, Hash` in that
  canonical order on the same line. Serde derives go on their own
  line below.
- **Imports**: grouped as std → external crates → workspace crates →
  same-crate, separated by blank lines. `rustfmt` does NOT enforce
  this — keep it manual.
- **`#[must_use]`** on any constructor or pure function whose returned
  value is the entire point of calling it.

## Critical thinking

The owner explicitly wants AI agents to act as senior dev partners,
not yes-machines. For any non-trivial suggestion:

1. **Challenge the assumption** behind the request when one is in play.
2. **Offer a counter-argument** when the proposed direction has a
   recognised downside.
3. **Stress-test against edge cases** — `Option::None`, empty input,
   integer overflow, surrogate pairs in UTF-8, concurrent access.
4. **Suggest alternatives** when a modern Rust idiom applies.
5. **Prioritise truth over agreement.** If the request leads to a bad
   design, say so and explain why before implementing.

Example: if the owner asks "just add `unwrap()` here to make the test
pass", the right response is to explain why `unwrap` is a smell, show
the `Result`-propagating alternative, and only fall back to an
explicit `#[allow(clippy::unwrap_used)]` if the owner confirms after
seeing the alternative.

## Engineering practices

- **Run locally before committing.** Always run `cargo test` and
  `cargo clippy -- -D warnings` before staging changes. This is the
  same discipline as `sdh-fleet-client` (see its own CLAUDE.md).
- **Never commit unless explicitly asked.** Commits are free to author
  locally; the owner decides when to actually run `git commit`. The
  same applies to `git push` once a remote is configured.
- **Commit messages**: one-line subject in imperative mood ("Add
  Spanish greeter"), optional blank line + body explaining the *why*,
  not the *what*. Match the style of `sdh-fleet/sdh-fleet-client`
  commit history.
- **Branch policy**: `main` is the default. Feature branches are
  optional for this learning repo.

## Language

Code, comments, commit messages, doc strings, file names: **English**.
Chat conversations between the owner and any AI agent: **French**.

This matches the owner's global Cursor rule and the `language-
conventions.mdc` rule from the parent workspace.

## When the owner asks "why does this not compile?"

The single most common interaction with this repo will be the owner
hitting a borrow-checker, lifetime, or trait-bound error. The
appropriate response shape is:

1. **State what the compiler is telling you** in plain language (the
   diagnostic itself is good but jargon-heavy).
2. **Explain the underlying rule** that the compiler is enforcing
   (move semantics, exclusive vs shared borrow, lifetime extension,
   orphan rule, etc.).
3. **Show the smallest fix** that respects the rule rather than
   side-steps it (`.clone()` everywhere is rarely the right answer).
4. **Point at the relevant Book chapter** for the owner's follow-up
   reading.

Do not just paste a working version. The point is for the owner to
internalise the rule, not to copy your patch.
