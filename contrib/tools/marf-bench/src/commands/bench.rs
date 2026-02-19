use anyhow::Result;
use clap::Args;

use crate::OutputFormat;
use crate::commands::bench_target::BenchTarget;
use crate::git::{current_repo_root, resolve_base_revision, verify_revision};
use crate::report::{print_comparison, print_single_run};
use crate::runner::Runner;
use crate::util::log;

#[derive(Debug, Args)]
pub(crate) struct BenchArgs {
    #[arg(
        long,
        global = true,
        help = "Baseline git revision (commit/branch/tag); enables comparison mode. Special value: 'staged' uses current index snapshot"
    )]
    base: Option<String>,

    #[arg(
        long = "target",
        global = true,
        requires = "base",
        help = "Target git revision (commit/branch/tag) for comparison mode (defaults to current working tree)"
    )]
    target_revision: Option<String>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    output_format: OutputFormat,

    #[command(subcommand)]
    target: BenchTarget,
}

pub(crate) fn run_command(args: BenchArgs) -> Result<()> {
    let requests = args.target.into_requests();
    let repo_root = current_repo_root()?;
    let mut runner = Runner::new(repo_root.clone())?;

    if let Some(base) = &args.base {
        let (base_revision, base_display) = resolve_base_revision(&repo_root, base)?;
        if let Some(target) = &args.target_revision {
            verify_revision(&repo_root, target)?;
        }

        let base_label = format!("base:{base_display}");
        let base_rows = runner.run_revision_via_worktree(
            &base_label,
            &base_revision,
            &requests,
            args.output_format,
        )?;

        let (target_label, target_rows) = if let Some(target) = &args.target_revision {
            let target_label = format!("target:{target}");
            let rows = runner.run_revision_via_worktree(
                &target_label,
                target,
                &requests,
                args.output_format,
            )?;
            (target_label, rows)
        } else {
            let target_label = "target:current-working-tree".to_string();
            let rows = runner.run_current_tree(&target_label, &requests, args.output_format)?;
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
        let rows =
            runner.run_current_tree("current-working-tree", &requests, args.output_format)?;
        print_single_run(args.output_format, &rows);
    }

    log("Done");
    Ok(())
}
