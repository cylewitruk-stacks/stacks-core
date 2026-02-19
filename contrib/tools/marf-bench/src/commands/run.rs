use anyhow::Result;
use clap::Args;

use crate::OutputFormat;
use crate::commands::bench::{BenchSelection, selected_benches};
use crate::git::current_repo_root;
use crate::report::print_single_run;
use crate::runner::Runner;
use crate::util::log;

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    output_format: OutputFormat,

    #[command(flatten)]
    selection: BenchSelection,
}

pub(crate) fn run_command(args: RunArgs) -> Result<()> {
    let repo_root = current_repo_root()?;
    let runner = Runner::new(repo_root.clone())?;
    let benches = selected_benches(&args.selection);
    let rows = runner.run_benches(
        "current-working-tree",
        &repo_root,
        &benches,
        args.output_format,
    )?;
    print_single_run(args.output_format, &rows);
    log("Done");
    Ok(())
}
