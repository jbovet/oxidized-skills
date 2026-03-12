//! # oxidized-agentic-audit
//!
//! Security auditing framework for AI agent skills.
//!
//! `oxidized-agentic-audit` scans skill directories for security vulnerabilities including
//! prompt injection, dangerous bash patterns, exposed secrets, unsafe package
//! installations, and more. It runs multiple scanners in parallel and produces
//! reports in human-readable, JSON, or [SARIF] formats.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use std::path::Path;
//! use oxidized_agentic_audit::{scan::{self, ScanMode}, config::Config, output};
//!
//! let config = Config::load(None).expect("failed to load config");
//! let report = scan::run_scan(Path::new("./my-skill"), &config, ScanMode::Skill);
//!
//! if report.passed {
//!     println!("Scan passed!");
//! } else {
//!     let text = output::format_report(&report, &output::OutputFormat::Pretty);
//!     print!("{text}");
//! }
//! ```
//!
//! ## Architecture
//!
//! The crate is organized around a pipeline:
//!
//! 1. **[`config`]** — load and validate configuration from TOML files.
//! 2. **[`scanners`]** — pluggable [`scanners::Scanner`] trait with built-in
//!    implementations (prompt, bash patterns, secrets, shellcheck, semgrep, …).
//! 3. **[`scan`]** — orchestrate scanners in parallel and collect results.
//! 4. **[`finding`]** — core data types ([`finding::Finding`], [`finding::ScanReport`]).
//! 5. **[`output`]** — format reports as pretty text, JSON, or SARIF.
//!
//! ## Scanners
//!
//! | Scanner | External tool | Description |
//! |---------|--------------|-------------|
//! | `prompt` | — | Prompt injection pattern detection |
//! | `bash_patterns` | — | Dangerous bash anti-patterns (Categories A–H) |
//! | `typescript_patterns` | — | Dangerous TypeScript/JavaScript patterns (Categories A–H) |
//! | `package_install` | — | Unsafe package installation patterns |
//! | `frontmatter` | — | SKILL.md frontmatter validation |
//! | `shellcheck` | [shellcheck] | Shell script linting |
//! | `secrets` | [gitleaks] | Secret and credential scanning |
//! | `semgrep` | [semgrep] | Static analysis |
//!
//! [SARIF]: https://sarifweb.azurewebsites.net/
//! [shellcheck]: https://www.shellcheck.net/
//! [gitleaks]: https://github.com/gitleaks/gitleaks
//! [semgrep]: https://semgrep.dev/

pub mod config;
pub mod finding;
pub mod output;
pub mod scan;
pub mod scanners;
