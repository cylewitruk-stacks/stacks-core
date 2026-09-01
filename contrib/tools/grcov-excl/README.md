# grcov-excl

Fences test-only code off from the code coverage report.

## Why

Test code is compiled into a crate's own test binary and instrumented like any
other code, so an inline `#[cfg(test)] mod tests { .. }` shows up in the
coverage report as thousands of fully-covered lines. grcov's `--ignore` globs
can only drop whole files, so anything test-only that shares a file with
production code has to be fenced off with markers instead:

```rust
#[cfg(test)] // GRCOV_EXCL_START
mod tests {
    // ..
}
// GRCOV_EXCL_STOP
```

CI passes the matching `--excl-start` / `--excl-stop` (and `--excl-br-*`) flags
in [`.github/actions/run-tests/action.yml`](../../../.github/actions/run-tests/action.yml).

## Nothing is committed

The markers are not in the source tree. CI runs `--fix` in the coverage job,
just before grcov reads the files, and the modified working copy is thrown away
with the runner.

That works because markers are **appended to lines that already exist** rather
than inserted on lines of their own. Line numbers therefore match the source the
tests were compiled from, so:

- the fix can run *after* the build — the coverage map still lines up;
- Coveralls renders per-line coverage against the right lines of the committed
  source;
- there is nothing in the repository that can drift out of sync with the code,
  so no CI job is needed to police it.

Nothing being committed also means nothing gets reviewed, so `--fix` has to
prove its own work. It asserts the line count is unchanged, re-parses every file
it touched, and then re-derives the intended exclusions from the parse tree and
compares them against what grcov will actually exclude — in both directions. A
region left counted fails the job, and so does a fence that reaches too far,
including one opened by the marker text appearing in a string or comment
somewhere in production code. Blank lines are the one permitted difference,
since llvm-cov never attributes a counter to one.

It also prints its totals, so a sudden move in how much is being fenced off is
visible in the job log. Those are physical source lines, blanks and comments
included — not the instrumented lines grcov reports — so read them as a tripwire,
not as a coverage figure.

## Usage

```bash
# Report every test-only region grcov would still count (exit 1 if any)
cargo run --manifest-path contrib/tools/grcov-excl/Cargo.toml -- --root .

# Write the markers, as CI does
cargo run --manifest-path contrib/tools/grcov-excl/Cargo.toml -- --root . --fix
```

`--fix` edits your working tree in place. The result still compiles — the
markers are only trailing comments — but you almost certainly want
`git restore -- '*.rs'` afterwards.

## What counts as test-only

Two things mark an item as existing only in test builds.

The first is a **test harness attribute** — `#[test]`, `#[rstest]`, `#[bench]`,
their qualified forms such as `#[tokio::test]`, and rstest_reuse's `#[template]`
and `#[apply(..)]`. These need no `cfg`: rustc only builds them under `--test`.
A bare `#[test] fn` sitting outside any `#[cfg(test)] mod` is easy to miss and
is counted as fully-covered production code if it is not excluded.

The second is a **`cfg` predicate** that is test-only, meaning it evaluates to
false with `test` and `feature = "testing"` both off and every other flag left
unknown. That covers
`cfg(test)`, `cfg(any(test, feature = "testing"))` and combinations such as
`cfg(all(any(test, feature = "testing"), not(feature = "wasm-deterministic")))`,
while leaving `cfg(not(test))` and `cfg(any(feature = "bech32_std", test))`
alone.

Items are located with `syn`, so regions are exact spans rather than brace
guesses. `use` and `mod name;` declarations are skipped — llvm-cov never
attributes a counter to them. Everything else is marked, including `static`s
with closure initializers and types whose `derive`s expand to real code.

Whole files reached only through a test-only `mod name;` — and their submodules
in turn — get an unterminated marker on their first item, which excludes the
file to its end. A declaration inherits the gate of an enclosing inline module,
so `#[cfg(test)] mod support { mod helpers; }` pulls in `helpers` even though
the inner declaration carries no attribute of its own.

Resolving a declaration to its file accounts for two things beyond the obvious
`foo.rs` → `foo/`. Each enclosing inline module adds a directory level. And a
crate root is not always named `lib.rs` here — `libcommon.rs`, `libclarity.rs`,
`libsigner.rs` and `libstackerdb.rs` are all roots — so roots are worked out
from the Cargo manifests rather than guessed from the file name: `[lib] path`
and `[[bin]]` entries, plus the targets Cargo discovers on its own (`src/lib.rs`,
`src/main.rs`, `src/bin/*.rs`, `src/bin/*/main.rs`), honouring `autolib` and
`autobins`. An explicit `[lib] path` replaces `src/lib.rs` rather than adding to
it. Guessing would be worse than useless: choosing the wrong base directory can
resolve to an unrelated file and mark the whole of it test-only, which nothing
downstream would catch.

Manifests are found by walking the tree, not by asking Cargo, so packages held
outside the workspace — the `fuzz` crates, the tools under `contrib/` — are
covered too.

A test-only declaration that resolves to nothing is an error rather than a
silent skip — it would mean a test module quietly staying in the report. The
exception is a declaration whose `cfg` is not certain to be active in the
coverage build, such as `#[cfg(all(test, feature = "extra"))] mod extra_tests;`.
`cfg` stripping happens before modules are loaded, so that is valid Rust with no
file behind it, and it is passed over rather than treated as an error.

## Placement rules

The stop marker goes on the line *after* the region, never on its last line.
grcov ends a region *before* marking the stop line, so a marker on the region's
closing brace would leave that brace counted; the first line past the region is
production code that should stay counted, which is exactly what belongs there.
When only blank lines follow, the region is left open to the end of the file.

## Ignore globs

Files grcov drops entirely are listed in
[`.github/grcov/ignore-globs.txt`](../../../.github/grcov/ignore-globs.txt),
read both by this tool and by the CI coverage step so the two agree on which
files the report covers.

Note that globset drops the empty branch of a brace alternate: `**/test{,s}/**`
matches `tests/` but never `test/`. Spell both forms out.
