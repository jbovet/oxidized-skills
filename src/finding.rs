use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
            Severity::Info => write!(f, "info"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub message: String,
    pub severity: Severity,
    pub file: Option<PathBuf>,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub scanner: String,
    pub snippet: Option<String>,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct ScanResult {
    pub scanner_name: String,
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub skipped: bool,
    pub skip_reason: Option<String>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

impl ScanResult {
    pub fn skipped(name: &str, reason: &str) -> Self {
        ScanResult {
            scanner_name: name.to_string(),
            findings: vec![],
            files_scanned: 0,
            skipped: true,
            skip_reason: Some(reason.to_string()),
            error: None,
            duration_ms: 0,
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct AuditReport {
    pub skill: String,
    pub version: Option<String>,
    pub audit_timestamp: String,
    pub status: AuditStatus,
    pub risk_level: RiskLevel,
    pub files_scanned: usize,
    pub scanner_results: Vec<ScanResult>,
    pub findings: Vec<Finding>,
    pub suppressed: Vec<Finding>,
    pub passed: bool,
}

impl AuditReport {
    pub fn from_results(
        skill: &str,
        results: Vec<ScanResult>,
        suppressions: &[crate::config::Suppression],
        strict: bool,
    ) -> Self {
        let files_scanned: usize = results.iter().map(|r| r.files_scanned).sum();

        let mut active = Vec::new();
        let mut suppressed = Vec::new();

        for result in &results {
            for finding in &result.findings {
                if finding.suppressed {
                    suppressed.push(finding.clone());
                } else if let Some(s) = find_suppression(finding, suppressions) {
                    // Single call — avoids traversing the suppression list twice
                    // (once for the boolean check, once to retrieve the reason).
                    let mut f = finding.clone();
                    f.suppressed = true;
                    f.suppression_reason = Some(s.reason.clone());
                    suppressed.push(f);
                } else {
                    active.push(finding.clone());
                }
            }
        }

        let status = compute_status(&active, strict);
        let risk_level = compute_risk_level(&active);
        let passed = matches!(status, AuditStatus::Passed);

        AuditReport {
            skill: skill.to_string(),
            version: None,
            audit_timestamp: chrono::Utc::now().to_rfc3339(),
            status,
            risk_level,
            files_scanned,
            scanner_results: results,
            findings: active,
            suppressed,
            passed,
        }
    }

    pub fn error_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count()
    }

    pub fn info_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count()
    }

    /// Count errors, warnings, and info findings in a single pass.
    ///
    /// Returns `(errors, warnings, info)`. Prefer this over calling
    /// `error_count()` + `warning_count()` + `info_count()` separately when
    /// all three values are needed at the same time (e.g. JSON output).
    pub fn count_by_severity(&self) -> (usize, usize, usize) {
        self.findings
            .iter()
            .fold((0, 0, 0), |(e, w, i), f| match f.severity {
                Severity::Error => (e + 1, w, i),
                Severity::Warning => (e, w + 1, i),
                Severity::Info => (e, w, i + 1),
            })
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditStatus {
    Passed,
    Warning,
    Failed,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

fn compute_status(findings: &[Finding], strict: bool) -> AuditStatus {
    // Single pass: track both flags simultaneously.
    let (has_errors, has_warnings) =
        findings
            .iter()
            .fold((false, false), |(e, w), f| match f.severity {
                Severity::Error => (true, w),
                Severity::Warning => (e, true),
                Severity::Info => (e, w),
            });

    if has_errors {
        AuditStatus::Failed
    } else if has_warnings {
        if strict {
            AuditStatus::Failed
        } else {
            AuditStatus::Warning
        }
    } else {
        AuditStatus::Passed
    }
}

fn compute_risk_level(findings: &[Finding]) -> RiskLevel {
    // Single pass: collect all three flags at once.
    let (has_rce_or_backdoor, has_errors, has_warnings) =
        findings
            .iter()
            .fold((false, false, false), |(rce, err, warn), f| {
                let is_rce = f.severity == Severity::Error
                    && (f.rule_id.starts_with("bash/CAT-A")
                        || f.rule_id.starts_with("bash/CAT-D")
                        || f.rule_id.starts_with("prompt/"));
                (
                    rce || is_rce,
                    err || f.severity == Severity::Error,
                    warn || f.severity == Severity::Warning,
                )
            });

    if has_rce_or_backdoor {
        RiskLevel::Critical
    } else if has_errors {
        RiskLevel::High
    } else if has_warnings {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn find_suppression<'a>(
    finding: &Finding,
    suppressions: &'a [crate::config::Suppression],
) -> Option<&'a crate::config::Suppression> {
    suppressions.iter().find(|s| {
        if s.rule != finding.rule_id {
            return false;
        }
        // Use Path::ends_with so that a suppression for "test.sh" matches
        // "/path/to/test.sh" but NOT "/path/to/maltest.sh".  A raw string
        // ends_with check fails this: "maltest.sh".ends_with("test.sh") is true.
        //
        // When the finding has no file path, the file check cannot be satisfied
        // unless the suppression also has an empty file field (wildcard).
        // Falling through unconditionally when file is None would let any
        // rule-only suppression suppress across all file-less findings.
        match &finding.file {
            Some(file) => {
                if !file.ends_with(std::path::Path::new(&s.file)) {
                    return false;
                }
            }
            None => {
                // Only allow suppression when the suppression entry does not
                // target a specific file (empty string acts as a wildcard).
                if !s.file.is_empty() {
                    return false;
                }
            }
        }
        if let (Some(ref lines), Some(line)) = (&s.lines, finding.line) {
            match parse_line_range(lines) {
                Some((start, end)) if line >= start && line <= end => {}
                // Range is either invalid (None) or the line is outside the range —
                // either way the suppression does not apply.
                _ => return false,
            }
        }
        true
    })
}

fn parse_line_range(lines: &str) -> Option<(usize, usize)> {
    let parts: Vec<&str> = lines.split('-').collect();
    if parts.len() == 2 {
        let start = parts[0].parse().ok()?;
        let end = parts[1].parse().ok()?;
        if start > end {
            return None;
        }
        Some((start, end))
    } else if parts.len() == 1 {
        let line = parts[0].parse().ok()?;
        Some((line, line))
    } else {
        None
    }
}
