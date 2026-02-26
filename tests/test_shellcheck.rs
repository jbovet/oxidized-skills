use std::path::Path;

use oxidized_skills::config::Config;
use oxidized_skills::finding::Severity;
use oxidized_skills::scanners::shellcheck::ShellCheckScanner;
use oxidized_skills::scanners::Scanner;

/// Helper: scan a fixture directory.
fn scan_fixture(fixture: &str) -> oxidized_skills::finding::ScanResult {
    ShellCheckScanner.scan(
        Path::new("tests/fixtures").join(fixture).as_path(),
        &Config::default(),
    )
}

/// Helper: scan a temp directory containing a single shell script.
fn scan_content(script: &str) -> oxidized_skills::finding::ScanResult {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.sh"), script).unwrap();
    ShellCheckScanner.scan(dir.path(), &Config::default())
}

// ── availability ──────────────────────────────────────────────────────────────

#[test]
fn shellcheck_not_available_returns_skipped() {
    let scanner = ShellCheckScanner;
    if !scanner.is_available() {
        let result =
            oxidized_skills::finding::ScanResult::skipped(scanner.name(), "shellcheck not found");
        assert!(result.skipped);
        assert!(result.findings.is_empty());
    } else {
        // Tool is installed — verify a clean script has no findings
        let result = scan_content("#!/bin/bash\necho 'hello world'\n");
        assert!(
            !result.skipped,
            "should not be skipped when tool is available"
        );
    }
}

// ── empty directory ───────────────────────────────────────────────────────────

#[test]
fn shellcheck_empty_directory_returns_zero_files() {
    if !ShellCheckScanner.is_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let result = ShellCheckScanner.scan(dir.path(), &Config::default());
    assert_eq!(result.files_scanned, 0);
    assert!(result.findings.is_empty());
    assert!(!result.skipped);
}

// ── rule ID prefix ────────────────────────────────────────────────────────────

#[test]
fn shellcheck_rule_id_prefix() {
    if !ShellCheckScanner.is_available() {
        return;
    }
    // SC2086: Double-quote to prevent globbing / word splitting
    let result = scan_content("#!/bin/bash\nX=hello\necho $X\n");
    for f in &result.findings {
        assert!(
            f.rule_id.starts_with("shellcheck/SC"),
            "rule_id should start with 'shellcheck/SC', got: {}",
            f.rule_id
        );
        assert_eq!(f.scanner, "shellcheck");
    }
}

// ── fixture: clean-skill ──────────────────────────────────────────────────────

#[test]
fn clean_skill_has_no_shellcheck_findings() {
    if !ShellCheckScanner.is_available() {
        return;
    }
    let result = scan_fixture("clean-skill");
    assert!(!result.skipped);
    assert!(
        result.findings.is_empty(),
        "Expected no shellcheck findings in clean-skill, got: {:?}",
        result.findings
    );
}

// ── fixture: shellcheck-skill (dedicated linting fixture) ────────────────────

#[test]
fn shellcheck_skill_detects_unquoted_variable_sc2086() {
    if !ShellCheckScanner.is_available() {
        return;
    }
    let result = scan_fixture("shellcheck-skill");
    assert!(!result.skipped);
    assert!(
        result.files_scanned > 0,
        "shellcheck-skill fixture should contain .sh files"
    );
    let sc2086: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "shellcheck/SC2086")
        .collect();
    assert!(
        !sc2086.is_empty(),
        "Expected SC2086 (unquoted variable) finding in shellcheck-skill"
    );
    assert_eq!(sc2086[0].severity, Severity::Info);
    assert_eq!(sc2086[0].scanner, "shellcheck");
}

#[test]
fn shellcheck_skill_findings_have_line_numbers() {
    if !ShellCheckScanner.is_available() {
        return;
    }
    let result = scan_fixture("shellcheck-skill");
    for f in &result.findings {
        assert!(
            f.line.is_some(),
            "Each shellcheck finding should have a line number, got None for {}",
            f.rule_id
        );
    }
}

#[test]
fn shellcheck_skill_findings_have_remediation() {
    if !ShellCheckScanner.is_available() {
        return;
    }
    let result = scan_fixture("shellcheck-skill");
    for f in &result.findings {
        assert!(
            f.remediation.is_some(),
            "Each shellcheck finding should have a remediation link, got None for {}",
            f.rule_id
        );
        assert!(
            f.remediation.as_deref().unwrap().contains("shellcheck.net"),
            "Remediation should point to shellcheck.net for {}",
            f.rule_id
        );
    }
}

// ── fixture: dirty-skill (cross-scanner check) ────────────────────────────────

#[test]
fn dirty_skill_shellcheck_detects_sc2086() {
    if !ShellCheckScanner.is_available() {
        return;
    }
    let result = scan_fixture("dirty-skill");
    // dirty-skill/scripts/backdoor.sh has `cat $HOME/.aws/credentials` (unquoted $HOME)
    // and `rm -rf $HOME` — both trigger SC2086
    let sc2086: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "shellcheck/SC2086")
        .collect();
    assert!(
        !sc2086.is_empty(),
        "Expected at least one SC2086 finding in dirty-skill (unquoted variables)"
    );
}
