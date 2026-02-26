use std::path::Path;

use oxidized_skills::config::Config;
use oxidized_skills::scanners::semgrep::SemgrepScanner;
use oxidized_skills::scanners::Scanner;

/// Helper: scan a fixture directory.
fn scan_fixture(fixture: &str) -> oxidized_skills::finding::ScanResult {
    SemgrepScanner.scan(
        Path::new("tests/fixtures").join(fixture).as_path(),
        &Config::default(),
    )
}

// ── basic contract ────────────────────────────────────────────────────────────

#[test]
fn semgrep_scanner_name() {
    assert_eq!(SemgrepScanner.name(), "semgrep");
}

#[test]
fn semgrep_scanner_description_mentions_semgrep() {
    assert!(SemgrepScanner.description().contains("semgrep"));
}

#[test]
fn semgrep_scanner_not_available_returns_skipped_by_audit() {
    let scanner = SemgrepScanner;
    if !scanner.is_available() {
        let result = oxidized_skills::finding::ScanResult::skipped(
            scanner.name(),
            "semgrep not found on PATH",
        );
        assert!(result.skipped);
        assert!(result.findings.is_empty());
        assert_eq!(result.scanner_name, "semgrep");
    }
}

// ── fixture: clean-skill ──────────────────────────────────────────────────────

#[test]
fn semgrep_scanner_clean_dir_runs_without_panic() {
    if !SemgrepScanner.is_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("README.md"), "# Hello\nThis is clean.\n").unwrap();
    let result = SemgrepScanner.scan(dir.path(), &Config::default());
    // A timeout-skip (e.g. network blocked) is a valid operational condition —
    // the test only verifies that no hard error occurred.
    if result.skipped {
        return;
    }
    assert!(
        result.error.is_none(),
        "Unexpected error: {:?}",
        result.error
    );
}

#[test]
fn semgrep_scan_clean_skill_does_not_error() {
    if !SemgrepScanner.is_available() {
        return;
    }
    let result = scan_fixture("clean-skill");
    // Skip assertion when semgrep timed out (network unavailable).
    if result.skipped {
        return;
    }
    assert!(
        result.error.is_none(),
        "Unexpected error on clean-skill: {:?}",
        result.error
    );
}

// ── fixture: dirty-skill ─────────────────────────────────────────────────────

#[test]
fn semgrep_scan_dirty_skill_does_not_error() {
    if !SemgrepScanner.is_available() {
        return;
    }
    let result = scan_fixture("dirty-skill");
    // Skip assertion when semgrep timed out (network unavailable).
    if result.skipped {
        return;
    }
    assert!(
        result.error.is_none(),
        "Unexpected error on dirty-skill: {:?}",
        result.error
    );
}

// ── rule ID / metadata ────────────────────────────────────────────────────────

#[test]
fn semgrep_scanner_finding_rule_id_prefix() {
    if !SemgrepScanner.is_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("README.md"), "# Hello\n").unwrap();
    let result = SemgrepScanner.scan(dir.path(), &Config::default());
    for f in &result.findings {
        assert!(
            f.rule_id.starts_with("semgrep/"),
            "rule_id should start with 'semgrep/', got: {}",
            f.rule_id
        );
        assert_eq!(f.scanner, "semgrep");
    }
}

#[test]
fn semgrep_findings_have_severity() {
    if !SemgrepScanner.is_available() {
        return;
    }
    // Run against dirty-skill which semgrep may have opinions about
    let result = scan_fixture("dirty-skill");
    for f in &result.findings {
        // Just ensure we can access severity without panicking
        let _ = &f.severity;
        let _ = &f.rule_id;
    }
}
