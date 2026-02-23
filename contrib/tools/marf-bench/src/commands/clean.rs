use anyhow::Result;
use clap::Args;

use crate::git::current_repo_root;
use crate::runner::{
    cached_keep_worktrees_root_if_exists, cleanup_cached_keep_worktrees,
    cleanup_orphan_temp_worktree_dirs, cleanup_stale_marf_bench_worktrees,
    list_orphan_temp_worktree_dirs, list_stale_marf_bench_worktrees,
};
use crate::util::log;

#[derive(Debug, Args)]
pub struct CleanArgs {
    #[arg(long, help = "Show what would be removed without deleting anything")]
    dry_run: bool,
}

pub fn run_command(args: CleanArgs) -> Result<()> {
    let repo_root = current_repo_root()?;

    if args.dry_run {
        let stale_worktrees = list_stale_marf_bench_worktrees(&repo_root)?;
        let cached_root = cached_keep_worktrees_root_if_exists(&repo_root);
        let orphan_temp_dirs = list_orphan_temp_worktree_dirs()?;

        for path in &stale_worktrees {
            log(&format!(
                "[dry-run] would remove stale worktree: {}",
                path.display()
            ));
        }
        if let Some(path) = &cached_root {
            log(&format!(
                "[dry-run] would remove cached keep-worktrees root: {}",
                path.display()
            ));
        }
        for path in &orphan_temp_dirs {
            log(&format!(
                "[dry-run] would remove orphan temp marf-bench dir: {}",
                path.display()
            ));
        }

        log(&format!(
            "Dry-run complete (stale_worktrees={}, cached_keep_root_present={}, orphan_temp_dirs={})",
            stale_worktrees.len(),
            cached_root.is_some(),
            orphan_temp_dirs.len()
        ));
        return Ok(());
    }

    cleanup_stale_marf_bench_worktrees(&repo_root)?;
    let removed_cache_root = cleanup_cached_keep_worktrees(&repo_root)?;
    let removed_orphan_temp_dirs = cleanup_orphan_temp_worktree_dirs()?;

    log(&format!(
        "Clean complete (removed_cache_root={removed_cache_root}, removed_orphan_temp_dirs={removed_orphan_temp_dirs})"
    ));

    Ok(())
}
