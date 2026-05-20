//! OS setup history + install date.
//!
//! Phase 1 derives `install_date` from the `InstallDate` DWORD under
//! `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (Unix timestamp).
//! The per-upgrade snapshot history from the Setup event log is deferred
//! to phase 2 — that API requires `EvtQuery` + `EvtRender` + `XPath` parsing
//! and the `PoC` doesn't need the timeline yet.

use serde_json::{Value, json};

use super::registry;

pub(super) fn install_info() -> Value {
    let install_date = registry::read(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "InstallDate",
    )
    .ok()
    .flatten()
    .and_then(|v| v.as_u64())
    .map(|ts| {
        // Format as ISO 8601 UTC for the data science team.
        let secs = i64::try_from(ts).unwrap_or(0);
        format_unix_seconds(secs)
    });

    json!({
        "install_date": install_date,
        "history": Value::Array(vec![]),
    })
}

fn format_unix_seconds(secs: i64) -> String {
    // Minimal ISO 8601 without dragging in chrono.
    // Algorithm from Howard Hinnant's date library (civil_from_days).
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, rem) = (secs_of_day / 3600, secs_of_day % 3600);
    let (mm, ss) = (rem / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

// Howard Hinnant's civil_from_days uses mixed-sign arithmetic with intervals
// that are provably bounded by construction (see comments). The casts between
// `i64`/`u64`/`i32`/`u32` are part of the published algorithm and documented
// by their bounds; they are not data-loss hazards for any plausible input.
#[allow(
    clippy::many_single_char_names,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}
