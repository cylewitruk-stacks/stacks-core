# marf-bench-runner

`marf-bench-runner` compares `marf-alloc` benchmark results across revisions using temporary git worktrees.

This document explains the git operations it performs, what they change (or do not change), and how cleanup works.

## Quick start

- Compare a known commit to your current working tree:
  - `cargo marf-bench bench --base c8a06adfc2c9c33ee858766a971eb36845e81499 --read`
- Compare staged snapshot to your current working tree:
  - `cargo marf-bench bench --base staged --read`
- Compare two named revisions (branch/tag/commit):
  - `cargo marf-bench bench --base master --target v3.0.0.0.0 --read-backptr`
- Run everything with machine-readable output:
  - `cargo marf-bench bench --base staged --all --output-format tsv`

## High-level lifecycle

For `bench` runs, the runner does the following:

1. Resolve the base/target revisions.
2. Create temporary detached worktree(s) for revision-based runs.
3. Overlay benchmark sources into those worktrees.
4. Build and run benchmarks.
5. Remove temporary worktrees.

If `--target` is omitted, target defaults to the current working tree (no worktree creation needed for target).

## Revision modes

## Regular revision (e.g. `--base <commit|branch|tag>`)

- Validation: `git rev-parse --verify <rev>^{commit}`
- Execution worktree: `git worktree add --detach <tmp-path> <rev>`

`<rev>` may be any git name that resolves to a commit, including:

- commit hash
- local branch name
- remote-tracking branch name (for example `origin/master`)
- tag name

Impact:

- Does not move your current branch or `HEAD`.
- Does not modify your index/staging area.
- Creates a temporary worktree directory plus corresponding metadata in `.git/worktrees/`.

Examples:

- Commit hash vs current working tree:
  - `cargo marf-bench bench --base c8a06adfc2c9c33ee858766a971eb36845e81499 --read`
- Branch vs current working tree:
  - `cargo marf-bench bench --base master --read-backptr`
- Tag vs branch:
  - `cargo marf-bench bench --base v3.0.0.0.0 --target master --write`
- Remote branch vs local branch:
  - `cargo marf-bench bench --base origin/master --target feat/marf-tweaks --read`

## Staged snapshot mode (`--base staged`)

`staged` is a special base selector for comparing:

- **base** = current index (staged content)
- **target** = current working tree (unless `--target` is supplied)

Internally it runs:

1. `git write-tree`
   - Creates a tree object from your current index state.
2. `git commit-tree <tree> [-p HEAD] -m "marf-bench staged snapshot"`
   - Creates a commit object pointing to that tree.
   - No branch/tag/ref is updated.
3. `git worktree add --detach <tmp-path> <ephemeral-commit>`
   - Benchmarks run in this detached temporary worktree.

Impact:

- No branch movement.
- No ref updates.
- No staging changes.
- No modifications to your current checkout files.

Notes:

- The commit/tree objects created by `commit-tree`/`write-tree` are typically unreachable (no ref points to them).
- Unreachable objects are cleaned by normal git garbage collection (`git gc`) over time.

Examples:

- Staged snapshot vs current working tree:
  - `cargo marf-bench bench --base staged --read`
- Staged snapshot vs explicit target branch:
  - `cargo marf-bench bench --base staged --target master --read-backptr`
- Staged snapshot with all benches in TSV output:
  - `cargo marf-bench bench --base staged --all --output-format tsv`

## Overlay behavior

Inside each temporary worktree, the runner copies the benchmark harness files from your current checkout into `stackslib/benches/marf-alloc/` before building.

This ensures benchmark source consistency across compared revisions.

Impact:

- Only affects temporary worktree filesystem contents.
- Does not modify files in your active checkout.

## Cleanup behavior

The runner tracks created worktrees and removes them on process teardown:

- `git worktree remove --force <tmp-path>`

This is triggered in `Drop` cleanup for the runner object.

Temporary worktree roots are created with the `tempfile` crate in your platform temp directory
(for example `/tmp` on Linux, `/var/folders/...` on macOS, `%TEMP%` on Windows).

If the process exits normally, these temporary directories are removed by the runner cleanup.
If the process crashes, the OS temp area lifecycle usually cleans up old temp files/directories
over time, and you can also remove leftovers manually using the recovery commands below.

## Failure/interrupt recovery

If the process is interrupted (panic/kill/crash), temporary state can remain.

Safe cleanup commands:

- Remove stale worktree metadata/dirs:
  - `git worktree prune`
- Inspect worktrees:
  - `git worktree list`
- Optional object cleanup (later, not required immediately):
  - `git gc`

Examples:

- Clean up stale worktree metadata after an interrupted run:
  - `git worktree prune`
- Verify no temporary worktrees remain:
  - `git worktree list`
- Force object cleanup when you want to prune unreachable staged-snapshot objects sooner:
  - `git gc`

## Safety summary

Operations are designed to be non-destructive to your active development state:

- No branch switching in your current checkout.
- No reset/checkout/stash on your working tree.
- No index mutation by the runner.
- Temporary worktree isolation for revision runs.

The only persistent artifacts are normal git objects (including temporary unreachable objects in `staged` mode), which are garbage-collected by git.
