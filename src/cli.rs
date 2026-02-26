use clap::{Parser, Subcommand};
use oxidized_skills::output::OutputFormat;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "oxidized-skills",
    version,
    about = "Security auditing for AI agent skills"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Audit a skill directory for security issues
    Audit {
        /// Path to the skill directory
        path: PathBuf,

        /// Output format
        #[arg(long, short, default_value = "pretty", value_enum)]
        format: OutputFormat,

        /// Write output to file instead of stdout
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Treat warnings as errors
        #[arg(long)]
        strict: bool,

        /// Custom config file path
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Audit all skill directories inside a collection directory
    #[command(name = "audit-all")]
    AuditAll {
        /// Path to a directory containing multiple skill subdirectories
        path: PathBuf,

        /// Output format
        #[arg(long, short, default_value = "pretty", value_enum)]
        format: OutputFormat,

        /// Treat warnings as errors
        #[arg(long)]
        strict: bool,

        /// Custom config file path
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Check which external tools are available
    CheckTools,

    /// List all built-in rules with descriptions
    ListRules,

    /// Show full explanation for a rule
    Explain {
        /// Rule ID (e.g., "bash/CAT-A1")
        rule_id: String,
    },
}
