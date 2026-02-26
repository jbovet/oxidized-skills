use std::path::PathBuf;

use oxidized_skills::config::Suppression;
use oxidized_skills::finding::{AuditReport, Finding, ScanResult, Severity};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_finding(file: &str) -> Finding {
    Finding {
        rule_id: "bash/CAT-H1".to_string(),
        message: "outbound HTTP".to_string(),
        severity: Severity::Warning,
        file: Some(PathBuf::from(file)),
        line: Some(5),
        column: None,
        scanner: "bash_patterns".to_string(),
        snippet: None,
        suppressed: false,
        suppression_reason: None,
        remediation: None,
    }
}

fn make_suppression(file: &str) -> Suppression {
    Suppression {
        rule: "bash/CAT-H1".to_string(),
        file: file.to_string(),
        lines: None,
        reason: "approved".to_string(),
        ticket: None,
    }
}

fn build_report(finding: Finding, suppression: Suppression) -> AuditReport {
    let result = ScanResult {
        scanner_name: "bash_patterns".to_string(),
        findings: vec![finding],
        files_scanned: 1,
        skipped: false,
        skip_reason: None,
        error: None,
        duration_ms: 0,
    };
    AuditReport::from_results("test-skill", vec![result], &[suppression], false)
}

// --- Positive cases: suppression SHOULD match ---

#[test]
fn suppression_matches_exact_filename() {
    let report = build_report(
        make_finding("/path/to/scripts/test.sh"),
        make_suppression("test.sh"),
    );
    assert!(
        report.findings.is_empty(),
        "Suppression for 'test.sh' should match finding in '/path/to/scripts/test.sh'"
    );
    assert_eq!(report.suppressed.len(), 1);
}

#[test]
fn suppression_matches_multicomponent_suffix() {
    let report = build_report(
        make_finding("/path/to/scripts/test.sh"),
        make_suppression("scripts/test.sh"),
    );
    assert!(
        report.findings.is_empty(),
        "Suppression for 'scripts/test.sh' should match the full path"
    );
}

// --- Negative cases: suppression must NOT match ---

#[test]
fn suppression_does_not_match_filename_with_same_suffix() {
    // Old string ends_with bug: "maltest.sh".ends_with("test.sh") == true.
    // Path::ends_with checks component boundaries, so this must NOT match.
    let report = build_report(
        make_finding("/path/to/scripts/maltest.sh"),
        make_suppression("test.sh"),
    );
    assert!(
        !report.findings.is_empty(),
        "Suppression for 'test.sh' must NOT match 'maltest.sh'"
    );
    assert!(report.suppressed.is_empty());
}

#[test]
fn suppression_does_not_match_different_directory() {
    let report = build_report(
        make_finding("/path/to/other/test.sh"),
        make_suppression("scripts/test.sh"),
    );
    assert!(
        !report.findings.is_empty(),
        "Suppression for 'scripts/test.sh' must NOT match 'other/test.sh'"
    );
}

// ---------------------------------------------------------------------------
// Fix #6: inverted line ranges must not silently suppress nothing
// ---------------------------------------------------------------------------

fn make_finding_at_line(file: &str, line: usize) -> Finding {
    Finding {
        rule_id: "bash/CAT-H1".to_string(),
        message: "outbound HTTP".to_string(),
        severity: Severity::Warning,
        file: Some(PathBuf::from(file)),
        line: Some(line),
        column: None,
        scanner: "bash_patterns".to_string(),
        snippet: None,
        suppressed: false,
        suppression_reason: None,
        remediation: None,
    }
}

#[test]
fn inverted_line_range_does_not_suppress_finding() {
    // Suppression with "100-50" is an inverted range — should be rejected, not match everything.
    let suppression = Suppression {
        rule: "bash/CAT-H1".to_string(),
        file: "test.sh".to_string(),
        lines: Some("100-50".to_string()),
        reason: "test".to_string(),
        ticket: None,
    };
    let result = ScanResult {
        scanner_name: "bash_patterns".to_string(),
        findings: vec![make_finding_at_line("/path/to/test.sh", 75)],
        files_scanned: 1,
        skipped: false,
        skip_reason: None,
        error: None,
        duration_ms: 0,
    };
    let report = AuditReport::from_results("test-skill", vec![result], &[suppression], false);
    assert!(
        !report.findings.is_empty(),
        "Inverted line range '100-50' must not suppress finding at line 75"
    );
    assert!(report.suppressed.is_empty());
}

#[test]
fn valid_line_range_suppresses_finding_within_range() {
    let suppression = Suppression {
        rule: "bash/CAT-H1".to_string(),
        file: "test.sh".to_string(),
        lines: Some("50-100".to_string()),
        reason: "approved".to_string(),
        ticket: None,
    };
    let result = ScanResult {
        scanner_name: "bash_patterns".to_string(),
        findings: vec![make_finding_at_line("/path/to/test.sh", 75)],
        files_scanned: 1,
        skipped: false,
        skip_reason: None,
        error: None,
        duration_ms: 0,
    };
    let report = AuditReport::from_results("test-skill", vec![result], &[suppression], false);
    assert!(
        report.findings.is_empty(),
        "Valid range '50-100' should suppress finding at line 75"
    );
    assert_eq!(report.suppressed.len(), 1);
}
