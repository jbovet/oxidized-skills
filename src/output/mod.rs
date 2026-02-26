//! Output formatting for audit reports.
//!
//! Three formats are supported:
//!
//! | Format | Module | Use case |
//! |--------|--------|----------|
//! | [`Pretty`](OutputFormat::Pretty) | [`pretty`] | Terminal / human review |
//! | [`Json`](OutputFormat::Json)     | [`json`]   | Automation / scripting  |
//! | [`Sarif`](OutputFormat::Sarif)   | [`sarif`]  | CI/CD integration       |
//!
//! Use [`format_report`] to render an [`AuditReport`] in any of the above
//! formats.

pub mod json;
pub mod pretty;
pub mod sarif;

use crate::finding::AuditReport;

/// Supported output formats for audit reports.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable colored text with summary tables.
    Pretty,
    /// Machine-readable JSON.
    Json,
    /// [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) for CI/CD tool integration.
    Sarif,
}

/// Formats an [`AuditReport`] in the requested [`OutputFormat`].
///
/// # Examples
///
/// ```rust,no_run
/// use oxidized_skills::output::{format_report, OutputFormat};
/// # use oxidized_skills::finding::AuditReport;
/// # fn example(report: &AuditReport) {
/// let json = format_report(report, &OutputFormat::Json);
/// println!("{json}");
/// # }
/// ```
pub fn format_report(report: &AuditReport, format: &OutputFormat) -> String {
    match format {
        OutputFormat::Pretty => pretty::format(report),
        OutputFormat::Json => json::format(report),
        OutputFormat::Sarif => sarif::format(report),
    }
}
