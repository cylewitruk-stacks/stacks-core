# marf-bench-runner

`marf-bench-runner` compares `marf-alloc` benchmark results across revisions using temporary git worktrees.

This document explains the git operations it performs, what they change (or do not change), and how cleanup works.

## Quick start

- Compare a known commit to your current working tree:
  - `cargo marf-bench bench --base c8a06adfc2c9c33ee858766a971eb36845e81499 read`
- Compare staged snapshot to your current working tree:
  - `cargo marf-bench bench --base staged read`
- Compare branch base via `--base` keyword (explicit upstream ref):
  - `cargo marf-bench bench --base merge-base:upstream/develop read`
- Compare two named revisions (branch/tag/commit):
  - `cargo marf-bench bench --base master --target v3.0.0.0.0 read --chain-len 2048 --depths 256,768,1536,2047 --keys-per-block 0`
- Run proofed read benchmark separately:
  - `cargo marf-bench bench --base staged read --proofs`
- Run everything with machine-readable output:
  - `cargo marf-bench bench --base staged --output-format tsv all`
- Run repeated comparisons and emit median/min/max repeat stats:
  - `cargo marf-bench bench --base merge-base:upstream/develop --repeats 5 write --rounds 10 --iters 200 --write-depths 32,512,1024 --key-updates 25`
- A/B write benchmark checkpoint behavior (bench-only hack):
  - `cargo marf-bench bench --base merge-base:upstream/develop write --rounds 10 --iters 200 --write-depths 1024 --key-updates 25 --sqlite-wal-autocheckpoint 0`
- Tune high-jitter detection threshold for repeat confidence summary:
  - `cargo marf-bench bench --base merge-base:upstream/develop --repeats 5 --repeat-jitter-threshold 40 write --rounds 10 --iters 200 --write-depths 32,512,1024 --key-updates 25`
- Override benchmark loop controls from CLI:
  - `cargo marf-bench bench --base staged read --iters 400000 --rounds 4`
- Override read-shape and write-search controls from CLI:
  - `cargo marf-bench run read --chain-len 1024 --depths 64,256,768 --cache-strategies noop,node256 --keys-per-block 7`
  - `cargo marf-bench run write --iters 20000 --write-depths 1024 --key-updates 25 --rounds 4 --key-search-max-tries 500000`
- Run write across a depth distribution in one invocation:
  - `cargo marf-bench run write --iters 20000 --write-depths 1,64,256,1024 --key-updates 25 --rounds 4 --key-search-max-tries 500000`

## Command shape

- `run`: `cargo marf-bench run [--output-format <summary|raw|tsv>] <all|node-alloc|read|write> [bench-specific options]`
- `bench`: `cargo marf-bench bench [--base <rev|staged|merge-base:<upstream-ref>>] [--target <rev>] [--repeats <N>] [--repeat-jitter-threshold <PCT>] [--output-format <summary|raw|tsv>] <all|node-alloc|read|write> [bench-specific options]`

Notes:

- Global `bench` options (`--base`, `--target`, `--output-format`) come before the bench subcommand.
- `--base` also accepts keywords: `staged`, `merge-base:<upstream-ref>`.
- `merge-base` keyword requires an explicit upstream ref suffix (no default remote/ref).
- `--target` requires `--base`.
- `--repeats` requires `--base`; when set, marf-bench runs full base/target comparisons N times and appends repeat statistics.
- `--repeat-jitter-threshold` sets the spread threshold (percentage points) for classifying high-jitter rows in repeat confidence output; default is `30`.
- Repeat confidence classifies a row as high-jitter when total-ms repeat deltas straddle both signs (`min < 0 < max`) and spread exceeds threshold.
- Bench-specific options (`--iters`, `--rounds`, etc.) come after the bench subcommand.

## Benchmark parameter flags

Bench-specific options are accepted on the bench target subcommands and are forwarded to `marf-alloc` subprocess env vars:

- `--iters <N>` sets `ITERS`
- `--rounds <N>` sets `ROUNDS`
- `--chain-len <N>` sets `CHAIN_LEN`
- `--proofs` sets `READ_PROOFS=1` (uses `MARF::get_with_proof`)
- `--keys-per-block <N>` sets `KEYS_PER_BLOCK` (additional noise/bulk keys per fixture block)
- `--depths <CSV>` sets `DEPTHS`
- `--cache-strategies <CSV>` sets `CACHE_STRATEGIES`
- `--write-depths <CSV>` sets `WRITE_DEPTHS` (write parent-chain depth distribution)
- `--key-updates <N>` sets `KEY_UPDATES` (write update share in percent, `0..=100`)
- `--sqlite-wal-autocheckpoint <N>` sets `SQLITE_WAL_AUTOCHECKPOINT` (write benchmark only; page threshold for SQLite WAL auto-checkpoint, `0` disables auto-checkpoint)
- `--key-search-max-tries <N>` sets `KEY_SEARCH_MAX_TRIES`

Read fixture semantics:

- Exactly one measured depth key is inserted per block.
- `KEYS_PER_BLOCK` controls additional non-measured noise/bulk keys inserted alongside it.
- Total fixture keys per block = `1 + KEYS_PER_BLOCK`.

These flags are useful for automation since callers can avoid command-specific env var conditionals.

## Raw output notes

When `--output-format raw` (or `MARF_ALLOC_OUTPUT=raw`) is used, `read`
bench `result` lines include:

- `variant=get`
- `variant=get-with-proof`

This allows direct side-by-side comparison of plain reads and proofed reads within the same depth/strategy case.

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
  - `cargo marf-bench bench --base c8a06adfc2c9c33ee858766a971eb36845e81499 read`
- Branch vs current working tree:
  - `cargo marf-bench bench --base master read --chain-len 2048 --depths 256,768,1536,2047 --keys-per-block 0`
- Tag vs branch:
  - `cargo marf-bench bench --base v3.0.0.0.0 --target master write`
- Remote branch vs local branch:
  - `cargo marf-bench bench --base origin/master --target feat/marf-tweaks read`

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
  - `cargo marf-bench bench --base staged read`
- Staged snapshot vs explicit target branch:
  - `cargo marf-bench bench --base staged --target master read --chain-len 2048 --depths 256,768,1536,2047 --keys-per-block 0`
- Staged snapshot with all benches in TSV output:
  - `cargo marf-bench bench --base staged --output-format tsv all`

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
On startup, marf-bench also performs a stale-worktree sweep for prior marf-bench temp worktrees.
On `Ctrl-C` and panic paths, marf-bench proactively runs the same cleanup before exiting.
If the process is forcibly terminated (`SIGKILL`, power loss), the OS temp area lifecycle usually
cleans up old temp files/directories over time, and you can also remove leftovers manually using
the recovery commands below.

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
