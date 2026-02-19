mod commands;
mod git;
mod report;
mod runner;
mod util;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use tempfile::Builder as TempBuilder;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum OutputFormat {
    Summary,
    Raw,
    Tsv,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BenchKind {
    NodeAlloc,
    Read,
    ReadBackptr,
    Write,
}

impl BenchKind {
    fn as_arg(self) -> &'static str {
        match self {
            Self::NodeAlloc => "node-alloc",
            Self::Read => "read",
            Self::ReadBackptr => "read-backptr",
            Self::Write => "write",
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "marf-bench",
    about = "Run marf-alloc benches in the current tree or compare revisions via temporary worktrees"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Run(commands::run::RunArgs),
    Bench(commands::bench::BenchArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => commands::run::run_command(args),
        Commands::Bench(args) => commands::bench::run_command(args),
    }
}
