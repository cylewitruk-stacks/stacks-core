use anyhow::Result;
use clap::Args;

use crate::git::{current_repo_root, resolve_base_revision, verify_revision};
use crate::report::{print_comparison, print_single_run};
use crate::runner::Runner;
use crate::util::log;
use crate::{BenchKind, OutputFormat};

#[derive(Debug, Args)]
pub(crate) struct BenchArgs {
    #[arg(
        long,
        help = "Baseline git revision (commit/branch/tag); enables comparison mode. Special value: 'staged' uses current index snapshot"
    )]
    base: Option<String>,

    #[arg(
        long,
        requires = "base",
        help = "Target git revision (commit/branch/tag) for comparison mode (defaults to current working tree)"
    )]
    target: Option<String>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    output_format: OutputFormat,

    #[command(flatten)]
    selection: BenchSelection,
}

#[derive(Debug, Args)]
pub(crate) struct BenchSelection {
    #[arg(
        long,
        help = "Run all benches (default when no bench flags are given)",
        conflicts_with_all = ["node_alloc", "read", "read_backptr", "write"]
    )]
    all: bool,

    #[arg(long, help = "Run node-alloc")]
    node_alloc: bool,

    #[arg(long, help = "Run read")]
    read: bool,

    #[arg(long, help = "Run read-backptr")]
    read_backptr: bool,

    #[arg(long, help = "Run write")]
    write: bool,
}

pub(crate) fn run_command(args: BenchArgs) -> Result<()> {
    let benches = selected_benches(&args.selection);
    let repo_root = current_repo_root()?;
    let mut runner = Runner::new(repo_root.clone())?;

    if let Some(base) = &args.base {
        let (base_revision, base_display) = resolve_base_revision(&repo_root, base)?;
        if let Some(target) = &args.target {
            verify_revision(&repo_root, target)?;
        }

        let base_label = format!("base:{base_display}");
        let base_rows = runner.run_revision_via_worktree(
            &base_label,
            &base_revision,
            &benches,
            args.output_format,
        )?;

        let (target_label, target_rows) = if let Some(target) = &args.target {
            let target_label = format!("target:{target}");
            let rows = runner.run_revision_via_worktree(
                &target_label,
                target,
                &benches,
                args.output_format,
            )?;
            (target_label, rows)
        } else {
            let target_label = "target:current-working-tree".to_string();
            let rows = runner.run_current_tree(&target_label, &benches, args.output_format)?;
            (target_label, rows)
        };

        print_comparison(
            args.output_format,
            &base_label,
            &target_label,
            &base_rows,
            &target_rows,
        );
    } else {
        let rows = runner.run_current_tree("current-working-tree", &benches, args.output_format)?;
        print_single_run(args.output_format, &rows);
    }

    log("Done");
    Ok(())
}

pub(crate) fn selected_benches(selection: &BenchSelection) -> Vec<BenchKind> {
    let explicit = selection.all
        || selection.node_alloc
        || selection.read
        || selection.read_backptr
        || selection.write;
    if !explicit || selection.all {
        return vec![
            BenchKind::NodeAlloc,
            BenchKind::Read,
            BenchKind::ReadBackptr,
            BenchKind::Write,
        ];
    }

    let mut benches = Vec::new();
    if selection.node_alloc {
        benches.push(BenchKind::NodeAlloc);
    }
    if selection.read {
        benches.push(BenchKind::Read);
    }
    if selection.read_backptr {
        benches.push(BenchKind::ReadBackptr);
    }
    if selection.write {
        benches.push(BenchKind::Write);
    }
    benches
}
