use anyhow::{Result, bail};
use clap::Args;

use crate::OutputFormat;
use crate::commands::bench_target::BenchTarget;
use crate::git::{current_repo_root, resolve_base_revision, verify_revision};
use crate::report::{print_comparison, print_repeated_comparison_stats, print_single_run};
use crate::runner::Runner;
use crate::util::log;

#[derive(Debug, Args)]
pub(crate) struct BenchArgs {
    #[arg(
        long,
        global = true,
        help = "Baseline git revision (commit/branch/tag); enables comparison mode. Special values: 'staged', 'merge-base:<upstream-ref>'"
    )]
    base: Option<String>,

    #[arg(
        long = "target",
        global = true,
        help = "Target git revision (commit/branch/tag) for comparison mode (defaults to current working tree)"
    )]
    target_revision: Option<String>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    output_format: OutputFormat,

    #[arg(
        long,
        global = true,
        help = "Repeat full base/target benchmark comparison N times and emit repeat statistics"
    )]
    repeats: Option<usize>,

    #[arg(
        long,
        global = true,
        default_value_t = 30.0,
        help = "High-jitter threshold for repeat confidence summary spread in percentage points"
    )]
    repeat_jitter_threshold: f64,

    #[command(subcommand)]
    target: BenchTarget,
}

pub(crate) fn run_command(args: BenchArgs) -> Result<()> {
    let requests = args.target.into_requests();
    let repo_root = current_repo_root()?;
    let repeats = args.repeats.unwrap_or(1);

    if repeats == 0 {
        bail!("--repeats must be >= 1");
    }
    if !args.repeat_jitter_threshold.is_finite() || args.repeat_jitter_threshold < 0.0 {
        bail!("--repeat-jitter-threshold must be a finite value >= 0");
    }

    let resolved_base = if let Some(base) = &args.base {
        Some(resolve_base_revision(&repo_root, base)?)
    } else {
        None
    };

    if resolved_base.is_none() && args.target_revision.is_some() {
        bail!("--target requires --base");
    }

    if resolved_base.is_none() && args.repeats.is_some() {
        bail!("--repeats requires --base");
    }

    if let Some((base_revision, base_display)) = resolved_base {
        if let Some(target) = &args.target_revision {
            verify_revision(&repo_root, target)?;
        }

        let base_label = format!("base:{base_display}");
        let target_label = if let Some(target) = &args.target_revision {
            format!("target:{target}")
        } else {
            "target:current-working-tree".to_string()
        };

        let mut repeated_rows = Vec::with_capacity(repeats);
        let mut runner = Runner::new(repo_root.clone())?;

        for repeat_ix in 0..repeats {
            if repeats > 1 {
                log(&format!("Repeat {}/{}", repeat_ix + 1, repeats));
            }
            let base_rows = runner.run_revision_via_worktree(
                &base_label,
                &base_revision,
                &requests,
                args.output_format,
            )?;

            let target_rows = if let Some(target) = &args.target_revision {
                runner.run_revision_via_worktree(
                    &target_label,
                    target,
                    &requests,
                    args.output_format,
                )?
            } else {
                runner.run_current_tree(&target_label, &requests, args.output_format)?
            };

            repeated_rows.push((base_rows, target_rows));
        }

        let (base_rows, target_rows) = repeated_rows
            .first()
            .expect("repeats should always produce at least one row set");

        print_comparison(
            args.output_format,
            &base_label,
            &target_label,
            base_rows,
            target_rows,
        );

        if args.repeats.is_some() {
            print_repeated_comparison_stats(
                args.output_format,
                &base_label,
                &target_label,
                &repeated_rows,
                args.repeat_jitter_threshold,
            );
        }
    } else {
        let mut runner = Runner::new(repo_root.clone())?;
        let rows =
            runner.run_current_tree("current-working-tree", &requests, args.output_format)?;
        print_single_run(args.output_format, &rows);
    }

    log("Done");
    Ok(())
}
