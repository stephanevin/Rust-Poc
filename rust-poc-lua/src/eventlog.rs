//! OS setup history + install date.
//!
//! Pipeline:
//!
//! 1. Read the **current** OS snapshot from
//!    `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
//! 2. Enumerate subkeys of `HKLM\SYSTEM\Setup` whose names start with
//!    `"Source"` — Windows creates one per in-place upgrade, named
//!    `"Source OS (Updated on …)"`.  Read the same field set from each.
//! 3. Drop entries whose `InstallDate == 0` (invalid/absent).
//! 4. Sort ascending by `InstallDate`.
//! 5. Derive `install_date` via [`derive_install_date`] (see its doc).
//!
//! ## `MigrationScope` convention (as observed on real machines)
//!
//! Windows Setup writes `MigrationScope = "5"` on the snapshot that has been
//! *overwritten* by a later in-place upgrade.  The snapshot is then moved to
//! a `Source OS (Updated on …)` subkey under `HKLM\SYSTEM\Setup`.  The
//! current OS — sitting in `CurrentVersion` — therefore always carries
//! `MigrationScope = ""` (or the value is absent), because nothing has been
//! upgraded *over* it yet.
//!
//! This is the opposite of what an earlier port assumed (`"5"` on the
//! upgraded-*to* OS).  The implementation here matches empirical data
//! collected on the workspace owner's machine (23H2 → 24H2 with `"5"` on the
//! 23H2 historical entry and `""` on the live 24H2 entry).

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
/// `install_date` is computed by [`derive_install_date`] (see its doc and
/// the module-level `MigrationScope` convention section).
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

/// Derives the OS install date from an ascending-sorted snapshot history.
///
/// The newest entry (last element) is the live OS; its `MigrationScope` is
/// ignored — by construction it is `""` on a healthy machine.  We walk
/// backward through older entries:
///
/// - `MigrationScope == "5"` → the entry was overwritten by an in-place
///   upgrade.  The chain extends one step further back; keep walking.
/// - `MigrationScope != "5"` (typically `""`, but any non-`"5"` value, e.g.
///   `"1"`, qualifies) → the upgrade chain breaks here.  This older entry
///   was not the predecessor of a contiguous upgrade chain leading up to
///   the current OS.  Return the install date of the entry one step
///   *newer* (the last snapshot still inside the chain).
///
/// If every older entry carries `"5"`, the chain reaches the oldest entry
/// and its install date wins.
///
/// Edge cases:
///
/// - Empty history → `None`.
/// - Single entry → that entry's install date (loop is empty, fallback).
///
/// Example walks (`sorted_asc` shown as `[oldest … newest]`):
///
/// | Input                                       | Result            |
/// |---------------------------------------------|-------------------|
/// | `[(T100, "5"), (T200, "")]`                 | `T100` (chain reaches oldest) |
/// | `[(T100, "5"), (T200, "5"), (T300, "")]`    | `T100`            |
/// | `[(T100, "1"), (T200, "5"), (T300, "")]`    | `T200` (chain breaks at "1") |
/// | `[(T100, ""), (T200, "")]`                  | `T200` (no chain — last reimage wins) |
fn derive_install_date(sorted_asc: &[Snapshot]) -> Option<String> {
    if sorted_asc.is_empty() {
        return None;
    }
    // `(0..0).rev()` is empty, so the single-entry case naturally falls
    // through to the `sorted_asc[0]` fallback below — no special-case needed.
    for i in (0..sorted_asc.len() - 1).rev() {
        if sorted_asc[i].migration_scope != "5" {
            return Some(sorted_asc[i + 1].install_date.clone());
        }
    }
    Some(sorted_asc[0].install_date.clone())
}

fn read_str(key: &str, name: &str) -> String {
    registry::read("HKLM", key, name)
        .ok()
        .flatten()
        .and_then(|v| {
            // REG_SZ / REG_EXPAND_SZ → String; REG_DWORD / REG_QWORD → decimal
            // string.  Mirrors C# `GetValue(...).ToString()` which works on any
            // boxed type, including numeric ones (MigrationScope is a REG_DWORD
            // on some machines).
            v.as_str().map(str::to_string)
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{Snapshot, derive_install_date};

    fn snap(timestamp: u64, migration_scope: &str) -> Snapshot {
        Snapshot {
            timestamp,
            install_date: format!("T{timestamp}"),
            edition_id: String::new(),
            display_version: String::new(),
            major_version: String::new(),
            minor_version: String::new(),
            build_number: String::new(),
            release: String::new(),
            migration_scope: migration_scope.to_string(),
        }
    }

    // Empty history → None.
    #[test]
    fn empty_returns_none() {
        assert_eq!(derive_install_date(&[]), None);
    }

    // Only one snapshot present (current OS).  No history to walk, so the
    // OS's own install_date is the install date.  The scope of the sole
    // entry is irrelevant — it is the "newest" entry whose scope is ignored.
    #[test]
    fn single_entry_returns_its_date() {
        let history = vec![snap(100, "")];
        assert_eq!(derive_install_date(&history).as_deref(), Some("T100"));
    }

    // Real machine observed in this workspace (23H2 → 24H2):
    //   sorted_asc[0] = 23H2 historical entry, scope="5" (overwritten by upgrade)
    //   sorted_asc[1] = 24H2 current OS,        scope=""  (live, scope ignored)
    // Expected: the 23H2 install_date — the upgrade chain reaches the oldest
    // entry, which becomes the canonical install date.
    #[test]
    fn real_machine_one_upgrade_returns_oldest() {
        let history = vec![snap(100, "5"), snap(200, "")];
        assert_eq!(derive_install_date(&history).as_deref(), Some("T100"));
    }

    // Fictional but plausible: 22H2 → 23H2 → 24H2, all in-place upgrades.
    //   sorted_asc[0] = 22H2, scope="5" (overwritten)
    //   sorted_asc[1] = 23H2, scope="5" (overwritten)
    //   sorted_asc[2] = 24H2, scope=""  (current, ignored)
    // Expected: 22H2 — the chain extends back through every "5" to the
    // oldest snapshot.
    #[test]
    fn chain_of_upgrades_returns_oldest() {
        let history = vec![snap(100, "5"), snap(200, "5"), snap(300, "")];
        assert_eq!(derive_install_date(&history).as_deref(), Some("T100"));
    }

    // Fictional case where the chain breaks on a non-"5" predecessor:
    //   sorted_asc[0] = 22H2, scope="1" (NOT overwritten by 23H2 — different
    //                                    relationship, e.g. a side-by-side
    //                                    install fragment kept around)
    //   sorted_asc[1] = 23H2, scope="5" (overwritten by 24H2)
    //   sorted_asc[2] = 24H2, scope=""  (current, ignored)
    // Expected: 23H2 — walking back from 24H2 we step into 23H2 (chain
    // continues), then into 22H2 with scope="1" which breaks the chain, so
    // we return the install_date of the last entry still inside the chain,
    // i.e. 23H2.
    #[test]
    fn chain_breaks_on_non_five_returns_next_younger() {
        let history = vec![snap(100, "1"), snap(200, "5"), snap(300, "")];
        assert_eq!(derive_install_date(&history).as_deref(), Some("T200"));
    }

    // Two entries, neither carrying "5".  No upgrade chain exists between
    // them — the older entry is leftover state (e.g. a clean reimage that
    // somehow preserved a Source OS fragment without flagging it).
    // Expected: the newest entry's install_date — the most recent clean
    // install is the canonical install date.
    #[test]
    fn clean_reimage_without_upgrade_chain_returns_newest() {
        let history = vec![snap(100, ""), snap(200, "")];
        assert_eq!(derive_install_date(&history).as_deref(), Some("T200"));
    }
}
