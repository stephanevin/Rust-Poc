//! OS setup history + install date.
//!
//! Mirrors `WindowsSetupService` from ComplianceApp/ComplianceService/Services:
//!
//! 1. Read the **current** OS snapshot from
//!    `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
//! 2. Enumerate subkeys of `HKLM\SYSTEM\Setup` whose names start with
//!    `"Source"` — Windows creates one per in-place upgrade, named
//!    `"Source OS (Updated on …)"`.  Read the same field set from each.
//! 3. Drop entries whose `InstallDate == 0` (invalid/absent).
//! 4. Sort ascending by `InstallDate`.
//! 5. Derive `install_date` via `GetInstallDate()` logic: walk from the
//!    newest snapshot backward; return the install date of the first snapshot
//!    whose *predecessor* has `MigrationScope != "5"`.  Falls back to the
//!    oldest snapshot when all predecessors carry scope "5" or only one entry
//!    exists.

use serde_json::{Value, json};

use super::registry;

// ---------------------------------------------------------------------------
// Internal snapshot type
// ---------------------------------------------------------------------------

struct Snapshot {
    /// Raw Unix epoch seconds — used for sorting only.
    timestamp: u64,
    /// ISO 8601 UTC string for the JSON output.
    install_date: String,
    edition_id: String,
    display_version: String,
    major_version: String,
    minor_version: String,
    build_number: String,
    /// UBR (Update Build Revision) serialised as a string to match the C# DTO.
    release: String,
    migration_scope: String,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Returns `{ install_date: string?, history: Snapshot[] }`.
///
/// `install_date` uses the `GetInstallDate()` heuristic (see module doc).
/// `history` is sorted ascending so index 0 is the oldest upgrade step.
pub(super) fn install_info() -> Value {
    const CURRENT_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    const SETUP_KEY: &str = r"SYSTEM\Setup";

    // Collect: current snapshot first (prepended), then source OS subkeys.
    let main = read_snapshot(CURRENT_KEY);

    let mut all: Vec<Snapshot> = registry::subkey_names("HKLM", SETUP_KEY)
        .into_iter()
        .filter(|name| {
            // Case-insensitive prefix match to mirror C# OrdinalIgnoreCase.
            name.get(..6)
                .is_some_and(|p| p.eq_ignore_ascii_case("Source"))
        })
        .filter_map(|name| read_snapshot(&format!(r"{SETUP_KEY}\{name}")))
        .collect();

    if let Some(m) = main {
        all.insert(0, m);
    }

    // Filter + sort — invalid entries (timestamp 0) were already filtered by
    // read_snapshot, but keep the retain for explicitness.
    all.retain(|s| s.timestamp != 0);
    all.sort_by_key(|s| s.timestamp);

    let install_date = derive_install_date(&all);

    let history: Vec<Value> = all
        .iter()
        .map(|s| {
            json!({
                "install_date":    s.install_date,
                "edition_id":      s.edition_id,
                "display_version": s.display_version,
                "major_version":   s.major_version,
                "minor_version":   s.minor_version,
                "build_number":    s.build_number,
                "release":         s.release,
                "migration_scope": s.migration_scope,
            })
        })
        .collect();

    json!({
        "install_date": install_date,
        "history":      history,
    })
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Reads one setup snapshot from `HKLM\<key>`.
/// Returns `None` when `InstallDate` is absent or zero.
fn read_snapshot(key: &str) -> Option<Snapshot> {
    let timestamp = read_u64(key, "InstallDate");
    if timestamp == 0 {
        return None;
    }
    let secs = i64::try_from(timestamp).unwrap_or(0);

    Some(Snapshot {
        timestamp,
        install_date: format_unix_seconds(secs),
        edition_id: read_str(key, "EditionID"),
        display_version: read_str(key, "DisplayVersion"),
        major_version: read_u64(key, "CurrentMajorVersionNumber").to_string(),
        minor_version: read_u64(key, "CurrentMinorVersionNumber").to_string(),
        build_number: read_str(key, "CurrentBuild"),
        release: read_u64(key, "UBR").to_string(),
        migration_scope: read_str(key, "MigrationScope"),
    })
}

/// `WindowsSetupService.GetInstallDate()` logic.
///
/// History is sorted ascending.  Walk backward from the newest entry.
/// Stop at index `i` when `history[i-1].migration_scope != "5"` — that
/// transition marks the boundary between an upgrade (scope 5) and a fresh
/// install, so `history[i].install_date` is the answer.
///
/// Falls back to `history[0].install_date` when all predecessors carry
/// scope "5", or there is only a single entry.
fn derive_install_date(sorted_asc: &[Snapshot]) -> Option<String> {
    if sorted_asc.is_empty() {
        return None;
    }
    for i in (1..sorted_asc.len()).rev() {
        if sorted_asc[i - 1].migration_scope != "5" {
            return Some(sorted_asc[i].install_date.clone());
        }
    }
    Some(sorted_asc[0].install_date.clone())
}

fn read_str(key: &str, name: &str) -> String {
    registry::read("HKLM", key, name)
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn read_u64(key: &str, name: &str) -> u64 {
    registry::read("HKLM", key, name)
        .ok()
        .flatten()
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0)
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
