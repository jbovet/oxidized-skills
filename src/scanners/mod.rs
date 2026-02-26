pub mod bash_patterns;
pub mod frontmatter;
pub mod package_install;
pub mod prompt;
pub mod secrets;
pub mod semgrep;
pub mod shellcheck;

use crate::config::Config;
use crate::finding::ScanResult;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn is_available(&self) -> bool;
    fn scan(&self, path: &Path, config: &Config) -> ScanResult;
}

pub fn all_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(prompt::PromptScanner),
        Box::new(bash_patterns::BashPatternScanner),
        Box::new(package_install::PackageInstallScanner),
        Box::new(frontmatter::FrontmatterScanner),
        Box::new(shellcheck::ShellCheckScanner),
        Box::new(secrets::SecretsScanner),
        Box::new(semgrep::SemgrepScanner),
    ]
}

pub fn collect_files(path: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if extensions.contains(&ext_str.as_str()) {
                files.push(path.to_path_buf());
            }
        }
    }
    files
}

pub fn which_exists(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path).any(|dir| {
                let candidate = dir.join(cmd);
                if !candidate.is_file() {
                    return false;
                }
                // Also verify the file is executable; a non-executable binary on
                // PATH would appear available but fail at runtime.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::metadata(&candidate)
                        .map(|m| m.permissions().mode() & 0o111 != 0)
                        .unwrap_or(false)
                }
                #[cfg(not(unix))]
                {
                    true
                }
            })
        })
        .unwrap_or(false)
}

pub fn is_suppressed_inline(line: &str) -> bool {
    // Only treat a suppression marker as valid when it appears as a trailing
    // shell comment (at or near end-of-line), not when it is embedded inside a
    // string literal such as: echo "# audit:ignore" | bash
    // The regex requires the marker to be preceded by optional whitespace and
    // to end at the line boundary (after optional trailing whitespace).
    static RE_INLINE_SUPPRESS: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)\s*#\s*(audit|oxidized-skills):ignore\s*$").unwrap()
    });
    RE_INLINE_SUPPRESS.is_match(line)
}

/// Information about a rule for list-rules and explain commands
pub struct RuleInfo {
    pub id: &'static str,
    pub severity: &'static str,
    pub scanner: &'static str,
    pub message: &'static str,
    pub remediation: &'static str,
}

pub fn all_rules() -> Vec<RuleInfo> {
    let mut rules = Vec::new();
    rules.extend(bash_patterns::rules());
    rules.extend(prompt::rules());
    rules.extend(package_install::rules());
    rules.extend(frontmatter::rules());
    rules.extend(shellcheck::rules());
    rules.extend(secrets::rules());
    rules.extend(semgrep::rules());
    rules
}
