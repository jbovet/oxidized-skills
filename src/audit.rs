use crate::config::{self, Config};
use crate::finding::{AuditReport, ScanResult};
use crate::scanners;
use rayon::prelude::*;
use std::path::Path;

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

fn extract_skill_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
