//! Placeholder crate for cross-workspace data types.
//!
//! Currently empty: the original `Greeting` / `Language` types from
//! the Hello World era were removed when `collect-config` took over the
//! root binary. The crate is kept to preserve the workspace shape
//! (cross-crate types live in `contracts/`, never in the binary or in
//! `rust-poc-lua/`) and to give future Lua-collector wire types a
//! natural home — same role as `sdh-fleet-client/contracts/`.
//!
//! # Wire discipline (still in force for future additions)
//!
//! Unknown JSON fields are silently ignored on deserialize — `serde`'s
//! default behaviour. We deliberately never use
//! `#[serde(deny_unknown_fields)]`: any future field added by a
//! producer must be tolerated by every existing consumer. This is the
//! same "ignore bits, never drift" rule documented in
//! `sdh-fleet-client/contracts/src/lib.rs`.
