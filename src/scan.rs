//! Scan orchestration.
//!
//! The [`run_scan`] function is the main entry-point for running a full
//! security scan on a skill or agent directory. It selects the appropriate
//! scanner set based on [`ScanMode`], executes them in parallel via [rayon],
//! collects results, applies suppression rules, and produces a final
//! [`ScanReport`].

use crate::config::{self, Config};
use crate::finding::{ScanReport, ScanResult};
use crate::scanners;
use colored::Colorize;
use rayon::prelude::*;
use std::path::Path;

/// Selects which scanner set and report context to use for a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Scan a skill directory (looks for `SKILL.md`, uses [`skill_scanners`](scanners::skill_scanners)).
    Skill,
    /// Scan an agent directory (looks for `AGENT.md`, uses [`agent_scanners`](scanners::agent_scanners)).
    Agent,
}

/// Runs a complete security scan on a skill or agent directory.
///
/// # Pipeline
///
/// 1. Selects the scanner set for `mode` ([`skill_scanners`](scanners::skill_scanners)
///    or [`agent_scanners`](scanners::agent_scanners)).
/// 2. Filters down to those enabled in [`Config::scanners`](crate::config::Config::scanners).
/// 3. Runs the active scanners **in parallel** using [rayon].
///    Scanners whose external tool is missing are recorded as *skipped*.
/// 4. Loads [suppression rules](crate::config::load_suppressions) from the
///    target directory.
/// 5. Assembles the final [`ScanReport`].
///
/// # Examples
///
/// ```rust,no_run
/// use std::path::Path;
/// use oxidized_agentic_audit::{scan::{self, ScanMode}, config::Config};
///
/// let config = Config::load(None).unwrap();
/// let report = scan::run_scan(Path::new("./my-skill"), &config, ScanMode::Skill);
///
/// std::process::exit(if report.passed { 0 } else { 1 });
/// ```
pub fn run_scan(path: &Path, config: &Config, mode: ScanMode) -> ScanReport {
    let all = match mode {
        ScanMode::Skill => scanners::skill_scanners(),
        ScanMode::Agent => scanners::agent_scanners(),
    };

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

    ScanReport::from_results(&skill_name, results, &suppressions, config.strict.enabled)
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
