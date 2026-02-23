mod commands;
mod git;
mod report;
mod runner;
mod util;

use std::panic;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use tempfile::Builder as TempBuilder;

use crate::git::current_repo_root;
use crate::runner::cleanup_stale_marf_bench_worktrees;

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
    Write,
}

impl BenchKind {
    fn as_arg(self) -> &'static str {
        match self {
            Self::NodeAlloc => "node-alloc",
            Self::Read => "read",
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
    Clean(commands::clean::CleanArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    install_cleanup_hooks(current_repo_root().ok())?;
    match cli.command {
        Commands::Run(args) => commands::run::run_command(args),
        Commands::Bench(args) => commands::bench::run_command(args),
        Commands::Clean(args) => commands::clean::run_command(args),
    }
}

fn install_cleanup_hooks(repo_root: Option<PathBuf>) -> Result<()> {
    let Some(repo_root) = repo_root else {
        return Ok(());
    };

    let cleaned = Arc::new(AtomicBool::new(false));

    {
        let repo_root = repo_root.clone();
        let cleaned = Arc::clone(&cleaned);
        ctrlc::set_handler(move || {
            if !cleaned.swap(true, Ordering::SeqCst) {
                let _ = cleanup_stale_marf_bench_worktrees(&repo_root);
            }
            std::process::exit(130);
        })?;
    }

    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        if !cleaned.swap(true, Ordering::SeqCst) {
            let _ = cleanup_stale_marf_bench_worktrees(&repo_root);
        }
        previous_hook(panic_info);
    }));

    Ok(())
}
