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
use colored::Colorize;
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

    let n_active = all
        .iter()
        .filter(|s| config.is_scanner_enabled(s.name()))
        .count();
    let n_disabled = all.len() - n_active;

    // Progress header to stderr so it never pollutes --format json/sarif output.
    if n_disabled > 0 {
        eprintln!(
            "{}",
            format!(
                "Running {} scanner{}… ({} disabled)",
                n_active,
                if n_active == 1 { "" } else { "s" },
                n_disabled
            )
            .dimmed()
        );
    } else {
        eprintln!(
            "{}",
            format!(
                "Running {} scanner{}…",
                n_active,
                if n_active == 1 { "" } else { "s" }
            )
            .dimmed()
        );
    }

    // Run all scanners in parallel (rayon preserves collection order).
    // Disabled scanners return immediately as skipped results so they still
    // appear in the report with a distinct "disabled in config" reason.
    let results: Vec<ScanResult> = all
        .par_iter()
        .map(|scanner| {
            if !config.is_scanner_enabled(scanner.name()) {
                ScanResult::skipped(scanner.name(), "disabled in config")
            } else if scanner.is_available() {
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
