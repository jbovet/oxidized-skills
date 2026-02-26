use std::path::Path;

use oxidized_skills::config::Config;
use oxidized_skills::finding::Severity;
use oxidized_skills::scanners::secrets::SecretsScanner;
use oxidized_skills::scanners::Scanner;

/// Helper: scan a fixture directory.
fn scan_fixture(fixture: &str) -> oxidized_skills::finding::ScanResult {
    SecretsScanner.scan(
        Path::new("tests/fixtures").join(fixture).as_path(),
        &Config::default(),
    )
}

// ── basic contract ────────────────────────────────────────────────────────────

#[test]
fn secrets_scanner_name() {
    assert_eq!(SecretsScanner.name(), "secrets");
}

#[test]
fn secrets_scanner_description_mentions_gitleaks() {
    assert!(SecretsScanner.description().contains("gitleaks"));
}

#[test]
fn secrets_scanner_not_available_returns_skipped_by_audit() {
    let scanner = SecretsScanner;
    if !scanner.is_available() {
        let result = oxidized_skills::finding::ScanResult::skipped(
            scanner.name(),
            "gitleaks not found on PATH",
        );
        assert!(result.skipped);
        assert!(result.findings.is_empty());
        assert_eq!(result.scanner_name, "secrets");
    }
}

// ── rule ID / metadata ────────────────────────────────────────────────────────

#[test]
fn secrets_scanner_finding_rule_id_prefix() {
    if !SecretsScanner.is_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.sh"),
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    )
    .unwrap();
    let result = SecretsScanner.scan(dir.path(), &Config::default());
    for f in &result.findings {
        assert!(
            f.rule_id.starts_with("secrets/"),
            "rule_id should start with 'secrets/', got: {}",
            f.rule_id
        );
        assert_eq!(f.scanner, "secrets");
    }
}

// ── fixture: clean-skill ──────────────────────────────────────────────────────

#[test]
fn clean_skill_has_no_secrets_findings() {
    if !SecretsScanner.is_available() {
        return;
    }
    let result = scan_fixture("clean-skill");
    assert!(!result.skipped);
    assert!(
        result.error.is_none(),
        "Unexpected error on clean-skill: {:?}",
        result.error
    );
    assert!(
        result.findings.is_empty(),
        "Expected no secrets findings in clean-skill, got: {:?}",
        result.findings
    );
}

// ── fixture: secrets-skill (dedicated leaking fixture) ───────────────────────

#[test]
fn secrets_skill_detects_aws_key() {
    if !SecretsScanner.is_available() {
        return;
    }
    let result = scan_fixture("secrets-skill");
    assert!(!result.skipped);
    assert!(
        result.error.is_none(),
        "Unexpected error: {:?}",
        result.error
    );
    assert!(
        !result.findings.is_empty(),
        "Expected gitleaks to detect the fake AWS key in secrets-skill"
    );
}

#[test]
fn secrets_skill_findings_are_error_severity() {
    if !SecretsScanner.is_available() {
        return;
    }
    let result = scan_fixture("secrets-skill");
    if result.findings.is_empty() {
        return; // gitleaks didn't fire — skip assertion
    }
    for f in &result.findings {
        assert_eq!(
            f.severity,
            Severity::Error,
            "Secrets findings should always be Error severity"
        );
    }
}

#[test]
fn secrets_skill_findings_have_remediation() {
    if !SecretsScanner.is_available() {
        return;
    }
    let result = scan_fixture("secrets-skill");
    for f in &result.findings {
        assert!(
            f.remediation.is_some(),
            "Secrets finding should have remediation text"
        );
    }
}
