use oxidized_skills::config::Config;
use oxidized_skills::output;
use oxidized_skills::output::OutputFormat;
use std::path::Path;

fn get_dirty_report() -> oxidized_skills::finding::AuditReport {
    let config = Config::default();
    oxidized_skills::audit::run_audit(Path::new("tests/fixtures/dirty-skill"), &config)
}

fn get_clean_report() -> oxidized_skills::finding::AuditReport {
    let config = Config::default();
    oxidized_skills::audit::run_audit(Path::new("tests/fixtures/clean-skill"), &config)
}

#[test]
fn json_output_is_valid() {
    let report = get_dirty_report();
    let json = output::format_report(&report, &OutputFormat::Json);

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");
    assert!(parsed["skill"].is_string());
    assert!(parsed["findings"].is_array());
    assert!(parsed["summary"]["errors"].is_number());
    assert!(!parsed["passed"].as_bool().unwrap());
}

#[test]
fn json_clean_skill_passes() {
    let report = get_clean_report();
    let json = output::format_report(&report, &OutputFormat::Json);

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");
    assert!(parsed["passed"].as_bool().unwrap());
}

#[test]
fn sarif_output_is_valid() {
    let report = get_dirty_report();
    let sarif = output::format_report(&report, &OutputFormat::Sarif);

    let parsed: serde_json::Value =
        serde_json::from_str(&sarif).expect("SARIF JSON should be valid");
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["runs"].is_array());
    assert!(parsed["runs"][0]["tool"]["driver"]["name"] == "oxidized-skills");
    assert!(parsed["runs"][0]["results"].is_array());
}

#[test]
fn pretty_output_contains_findings() {
    let report = get_dirty_report();
    let pretty = output::format_report(&report, &OutputFormat::Pretty);

    assert!(pretty.contains("dirty-skill"));
    assert!(pretty.contains("FAIL") || pretty.contains("ERROR"));
}

#[test]
fn pretty_output_clean_passes() {
    let report = get_clean_report();
    let pretty = output::format_report(&report, &OutputFormat::Pretty);

    assert!(pretty.contains("clean-skill"));
    assert!(pretty.contains("PASS"));
}

#[test]
fn json_contains_severity_levels() {
    let report = get_dirty_report();
    let json = output::format_report(&report, &OutputFormat::Json);

    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let findings = parsed["findings"].as_array().unwrap();

    let has_error = findings.iter().any(|f| f["severity"] == "error");
    let has_warning = findings.iter().any(|f| f["severity"] == "warning");

    assert!(has_error, "Should have at least one error finding");
    assert!(has_warning, "Should have at least one warning finding");
}
