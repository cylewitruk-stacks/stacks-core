use anyhow::Result;
use clap::Args;

use crate::OutputFormat;
use crate::commands::bench_target::BenchTarget;
use crate::git::current_repo_root;
use crate::report::print_single_run;
use crate::runner::Runner;
use crate::util::log;

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    output_format: OutputFormat,

    #[command(subcommand)]
    target: BenchTarget,
}

pub fn run_command(args: RunArgs) -> Result<()> {
    let repo_root = current_repo_root()?;
    let mut runner = Runner::new(repo_root.clone(), false)?;
    let requests = args.target.into_requests();
    let rows = runner.run_benches(
        "current-working-tree",
        &repo_root,
        &requests,
        args.output_format,
    )?;
    print_single_run(args.output_format, &rows);
    log("Done");
    Ok(())
}
