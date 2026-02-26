use crate::config::Config;
use crate::finding::{Finding, ScanResult, Severity};
use crate::scanners::{collect_files, which_exists, RuleInfo, Scanner};
use std::path::Path;
use std::time::Instant;

/// ShellCheck scanner wrapper.
///
/// Finds `.sh` and `.bash` files and runs `shellcheck -f json` on each,
/// mapping shellcheck severity levels to our `Severity` enum.
pub struct ShellCheckScanner;

impl Scanner for ShellCheckScanner {
    fn name(&self) -> &'static str {
        "shellcheck"
    }

    fn description(&self) -> &'static str {
        "Shell script linting via shellcheck (external tool)"
    }

    fn is_available(&self) -> bool {
        which_exists("shellcheck")
    }

    fn scan(&self, path: &Path, _config: &Config) -> ScanResult {
        let start = Instant::now();
        let files = collect_files(path, &["sh", "bash"]);

        if files.is_empty() {
            return ScanResult {
                scanner_name: self.name().to_string(),
                findings: vec![],
                files_scanned: 0,
                skipped: false,
                skip_reason: None,
                error: None,
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }

        let mut findings = Vec::new();
        let mut error_msg: Option<String> = None;

        for file in &files {
            let output = match std::process::Command::new("shellcheck")
                .arg("-f")
                .arg("json")
                .arg("--severity=style")
                .arg(file)
                .output()
            {
                Ok(o) => o,
                Err(e) => {
                    error_msg = Some(format!("Failed to run shellcheck: {}", e));
                    continue;
                }
            };

            // shellcheck exits non-zero when it finds issues; that is expected.
            // We only treat a completely failed spawn as an error (handled above).
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim().is_empty() {
                continue;
            }

            let items: Vec<serde_json::Value> = match serde_json::from_str(&stdout) {
                Ok(v) => v,
                Err(e) => {
                    error_msg = Some(format!("Failed to parse shellcheck JSON: {}", e));
                    continue;
                }
            };

            for item in items {
                let severity = match item["level"].as_str().unwrap_or("warning") {
                    "error" => Severity::Error,
                    "warning" => Severity::Warning,
                    _ => Severity::Info,
                };

                // All real shellcheck codes are ≥ 1000; a missing or zero code
                // means the JSON is malformed.  Skip rather than emit SC0.
                let Some(code) = item["code"].as_u64().filter(|&c| c > 0) else {
                    continue;
                };
                let rule_id = format!("shellcheck/SC{}", code);
                let message = item["message"]
                    .as_str()
                    .unwrap_or("shellcheck finding")
                    .to_string();
                let line = item["line"].as_u64().map(|l| l as usize);
                let column = item["column"].as_u64().map(|c| c as usize);

                findings.push(Finding {
                    rule_id,
                    message,
                    severity,
                    file: Some(file.clone()),
                    line,
                    column,
                    scanner: self.name().to_string(),
                    snippet: item["fix"]["replacements"][0]["replacement"]
                        .as_str()
                        .map(|s| s.to_string()),
                    suppressed: false,
                    suppression_reason: None,
                    remediation: Some(format!("See https://www.shellcheck.net/wiki/SC{}", code)),
                });
            }
        }

        ScanResult {
            scanner_name: self.name().to_string(),
            findings,
            files_scanned: files.len(),
            skipped: false,
            skip_reason: None,
            error: error_msg,
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }
}

pub fn rules() -> Vec<RuleInfo> {
    vec![
        RuleInfo {
            id: "shellcheck/SC2086",
            severity: "info",
            scanner: "shellcheck",
            message: "Double quote to prevent globbing and word splitting",
            remediation: "See https://www.shellcheck.net/wiki/SC2086",
        },
        RuleInfo {
            id: "shellcheck/SC2046",
            severity: "warning",
            scanner: "shellcheck",
            message: "Quote this to prevent word splitting",
            remediation: "See https://www.shellcheck.net/wiki/SC2046",
        },
        RuleInfo {
            id: "shellcheck/SC2006",
            severity: "warning",
            scanner: "shellcheck",
            message: "Use $(...) instead of legacy `...`",
            remediation: "See https://www.shellcheck.net/wiki/SC2006",
        },
        RuleInfo {
            id: "shellcheck/SC2039",
            severity: "warning",
            scanner: "shellcheck",
            message: "In POSIX sh, something is undefined",
            remediation: "See https://www.shellcheck.net/wiki/SC2039",
        },
        RuleInfo {
            id: "shellcheck/SC2059",
            severity: "info",
            scanner: "shellcheck",
            message: "Don't use variables in the printf format string",
            remediation: "See https://www.shellcheck.net/wiki/SC2059",
        },
    ]
}
