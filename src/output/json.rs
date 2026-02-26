use crate::finding::AuditReport;

#[derive(serde::Serialize)]
struct JsonOutput<'a> {
    skill: &'a str,
    version: &'a Option<String>,
    audit_timestamp: &'a str,
    status: &'a crate::finding::AuditStatus,
    risk_level: &'a crate::finding::RiskLevel,
    passed: bool,
    summary: Summary,
    findings: &'a [crate::finding::Finding],
    suppressed: &'a [crate::finding::Finding],
}

#[derive(serde::Serialize)]
struct Summary {
    errors: usize,
    warnings: usize,
    info: usize,
    suppressed: usize,
}

pub fn format(report: &AuditReport) -> String {
    let output = JsonOutput {
        skill: &report.skill,
        version: &report.version,
        audit_timestamp: &report.audit_timestamp,
        status: &report.status,
        risk_level: &report.risk_level,
        passed: report.passed,
        summary: {
            // Single pass over findings instead of three separate iterations.
            let (errors, warnings, info) = report.count_by_severity();
            Summary {
                errors,
                warnings,
                info,
                suppressed: report.suppressed.len(),
            }
        },
        findings: &report.findings,
        suppressed: &report.suppressed,
    };

    serde_json::to_string_pretty(&output).expect("JSON serialization failed")
}
