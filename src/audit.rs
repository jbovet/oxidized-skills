//! Audit orchestration.
//!
//! The [`run_audit`] function is the main entry-point for running a full
//! security audit on a skill directory. It loads all enabled
//! [`Scanner`](crate::scanners::Scanner) implementations, executes them in
//! parallel via [rayon], collects results, applies suppression rules, and
//! produces a final [`AuditReport`].

use crate::config::{self, Config};
use crate::finding::{AuditReport, ScanResult};
use crate::scanners;
use rayon::prelude::*;
use std::path::Path;

/// Runs a complete security audit on a skill directory.
///
/// # Pipeline
///
/// 1. Loads every registered [`Scanner`](crate::scanners::Scanner).
/// 2. Filters down to those enabled in [`Config::scanners`](crate::config::Config::scanners).
/// 3. Runs the active scanners **in parallel** using [rayon].
///    Scanners whose external tool is missing are recorded as *skipped*.
/// 4. Loads [suppression rules](crate::config::load_suppressions) from the
///    skill directory.
/// 5. Assembles the final [`AuditReport`].
///
/// # Examples
///
/// ```rust,no_run
/// use std::path::Path;
/// use oxidized_skills::{audit, config::Config};
///
/// let config = Config::load(None).unwrap();
/// let report = audit::run_audit(Path::new("./my-skill"), &config);
///
/// std::process::exit(if report.passed { 0 } else { 1 });
/// ```
pub fn run_audit(path: &Path, config: &Config) -> AuditReport {
    let all = scanners::all_scanners();

    let active: Vec<_> = all
        .into_iter()
        .filter(|s| config.is_scanner_enabled(s.name()))
        .collect();

    let results: Vec<ScanResult> = active
        .par_iter()
        .map(|scanner| {
            if scanner.is_available() {
                scanner.scan(path, config)
            } else {
                ScanResult::skipped(
                    scanner.name(),
                    &format!("{} not found on PATH", scanner.name()),
                )
            }
        })
        .collect();

    let suppressions = config::load_suppressions(path);
    let skill_name = extract_skill_name(path);

    AuditReport::from_results(&skill_name, results, &suppressions, config.strict.enabled)
}

/// Extracts the skill name from a directory path.
///
/// Returns the last path component or `"unknown"` when the path has no
/// file-name segment (e.g., `/`).
fn extract_skill_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
