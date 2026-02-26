pub mod json;
pub mod pretty;
pub mod sarif;

use crate::finding::AuditReport;

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
    Sarif,
}

pub fn format_report(report: &AuditReport, format: &OutputFormat) -> String {
    match format {
        OutputFormat::Pretty => pretty::format(report),
        OutputFormat::Json => json::format(report),
        OutputFormat::Sarif => sarif::format(report),
    }
}
