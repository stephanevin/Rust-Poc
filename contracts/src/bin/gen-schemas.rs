//! Emits JSON Schema files for every wire type under `generated/schemas/`.
//!
//! Run manually from the workspace root:
//!
//! ```bash
//! cargo run -p rust-poc-contracts --bin gen-schemas --features schema
//! ```
//!
//! The output directory is `contracts/generated/schemas/` relative to
//! the contracts crate root. Files are pretty-printed + deterministic
//! so `git diff` is stable across re-runs on the same struct
//! definitions.
//!
//! Mirrors the role of
//! `sdh-fleet-client/contracts/src/bin/gen-schemas.rs` — same macro
//! pattern, same drift-friendly output format.

// One-shot tool: fail loud on IO errors rather than complicating the
// signature with `Result` plumbing nobody will read.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use rust_poc_contracts::{Greeting, Language};
use schemars::schema_for;

fn main() {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("generated")
        .join("schemas");
    fs::create_dir_all(&out_dir).expect("create schemas output dir");

    let mut count = 0_usize;

    macro_rules! emit {
        ($ty:ty) => {{
            let pretty = serde_json::to_string_pretty(&schema_for!($ty))
                .expect("serialize schema to pretty JSON");
            let path = out_dir.join(concat!(stringify!($ty), ".json"));
            fs::write(&path, format!("{pretty}\n")).expect("write schema file");
            println!("wrote {}", path.display());
            count += 1;
        }};
    }

    emit!(Greeting);
    emit!(Language);

    println!("emitted {count} schemas to {}", out_dir.display());
}
