// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Keeps grcov's coverage-exclusion markers in sync with the code they guard.
//!
//! Test code compiled into a crate's own test binary is instrumented like any
//! other code, so an inline `#[cfg(test)] mod tests { .. }` shows up in the
//! coverage report as thousands of fully-covered lines. grcov's `--ignore`
//! globs can only drop whole files, so anything test-only that shares a file
//! with production code has to be fenced off with markers instead.
//!
//! This tool finds every test-only region, checks that grcov would exclude it,
//! and (with `--fix`) writes the markers that make that true.
//!
//! Markers are appended to lines that already exist, never inserted on lines of
//! their own, so line numbers are untouched. That is what lets CI run `--fix`
//! after the build, against the working copy grcov is about to read, instead of
//! committing markers to the repository where they would drift.

mod filter;
mod gate;
mod scan;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::{fs, process};

use anyhow::{Context, Result};
use clap::Parser;
use globset::{Glob, GlobSet, GlobSetBuilder};

use filter::Excluded;
use scan::Scan;

#[derive(Parser)]
#[command(
    about = "Check or repair grcov coverage-exclusion markers around test-only code",
    long_about = None,
)]
struct Args {
    /// Insert the missing markers instead of only reporting them.
    #[arg(long)]
    fix: bool,

    /// Repository root to scan.
    #[arg(long, default_value = ".")]
    root: PathBuf,

    /// File listing the globs grcov drops from the report.
    #[arg(long, default_value = ".github/grcov/ignore-globs.txt")]
    ignore_globs: PathBuf,

    /// Marker that opens an excluded region.
    #[arg(long, default_value = "GRCOV_EXCL_START")]
    marker_start: String,

    /// Marker that closes an excluded region.
    #[arg(long, default_value = "GRCOV_EXCL_STOP")]
    marker_stop: String,
}

/// Why a file failed the check, and what `--fix` would do about it.
enum Violation {
    /// A test-only region grcov would still count.
    Region {
        start: usize,
        end: usize,
        kind: &'static str,
        gate: String,
    },
    /// A file reached only through `#[cfg(test)] mod ..;` whose contents grcov
    /// would still count. Needs one unterminated marker above the first item.
    WholeFile { first_item_line: usize },
    /// Markers already cover part of the region. Overlapping regions can't be
    /// repaired mechanically without risking a mis-nested fence.
    Partial {
        start: usize,
        end: usize,
        kind: &'static str,
    },
}

struct SourceFile {
    rel: PathBuf,
    src: String,
    scan: Scan,
}

fn main() {
    if let Err(e) = run(Args::parse()) {
        eprintln!("error: {e:#}");
        process::exit(2);
    }
}

fn run(args: Args) -> Result<()> {
    let ignore = load_globs(&args.root.join(&args.ignore_globs))?;
    let mut files = collect_files(&args.root, &ignore)?;
    let whole_file = test_only_module_files(&args.root, &files, &ignore);

    let mut violations: BTreeMap<PathBuf, Vec<Violation>> = BTreeMap::new();
    for file in &files {
        let found = check_file(file, &whole_file, &args);
        if !found.is_empty() {
            violations.insert(file.rel.clone(), found);
        }
    }

    if violations.is_empty() {
        // Nothing is under-excluded, but that says nothing about the other
        // direction: a stray or over-wide fence could still be hiding
        // production code. On an already-marked tree this is the only check
        // that runs, so it has to run here too.
        verify_all(&files, &whole_file, &args)?;
        println!(
            "grcov-excl: {} files scanned, all test-only code is excluded and nothing else is",
            files.len()
        );
        return Ok(());
    }

    if !args.fix {
        report(&violations);
        process::exit(1);
    }

    let mut fixed = 0usize;
    for (rel, found) in &violations {
        if found.iter().any(|v| matches!(v, Violation::Partial { .. })) {
            continue;
        }
        let file = files.iter_mut().find(|f| f.rel == *rel).expect("scanned");
        file.src = apply(&file.src, found, &args);
        fs::write(args.root.join(rel), &file.src)
            .with_context(|| format!("writing {}", rel.display()))?;
        fixed += 1;
        println!("fixed {} ({} regions)", rel.display(), found.len());
    }

    // Re-derive everything from the rewritten sources and prove the result is
    // right in both directions: no test-only region left counted, and -- just as
    // important, since nothing is committed for a human to review -- no
    // production line excluded that should not be.
    let files = collect_files(&args.root, &ignore)?;
    let whole_file = test_only_module_files(&args.root, &files, &ignore);
    verify_all(&files, &whole_file, &args)?;

    // Print the totals: a sudden move in these is the signal that something
    // changed in what gets excluded. These are physical source lines, blanks and
    // comments included -- not the instrumented lines grcov ends up reporting --
    // so they are a tripwire, not a coverage figure.
    let (mut total, mut fenced) = (0usize, 0usize);
    for file in &files {
        let flags = Excluded::compute(&file.src, &args.marker_start, &args.marker_stop);
        let lines = file.src.split('\n').count();
        total += lines;
        fenced += (1..=lines).filter(|n| flags.line(*n)).count();
    }
    println!(
        "grcov-excl: rewrote {fixed} files; fenced off {fenced} of {total} source lines \
         ({:.1}%) across {} candidate files",
        100.0 * fenced as f64 / total as f64,
        files.len()
    );
    Ok(())
}

/// Fail unless every file is excluded exactly as intended.
fn verify_all(files: &[SourceFile], whole_file: &BTreeSet<PathBuf>, args: &Args) -> Result<()> {
    let mismatches: Vec<String> = files
        .iter()
        .filter_map(|f| verify_exact(f, whole_file, args))
        .collect();
    if mismatches.is_empty() {
        return Ok(());
    }
    for mismatch in &mismatches {
        eprintln!("{mismatch}");
    }
    anyhow::bail!(
        "{} files were not excluded exactly as intended",
        mismatches.len()
    )
}

/// Compare what grcov will exclude against what it should exclude, and describe
/// the difference if they disagree.
///
/// `check_file` only asks whether each known region sits inside a fence, so it
/// is blind to a fence that reaches too far — a misplaced marker, or the marker
/// text turning up in a string or comment somewhere in production code. This is
/// the check that closes that side, and it derives what *should* be excluded
/// from the parse tree rather than from the markers.
///
/// Excluding a blank line is not counted as a difference: llvm-cov never
/// attributes a counter to one, and a region that runs to the end of the file
/// necessarily swallows the trailing newline.
fn verify_exact(file: &SourceFile, whole_file: &BTreeSet<PathBuf>, args: &Args) -> Option<String> {
    let lines: Vec<&str> = file.src.split('\n').collect();
    let flags = Excluded::compute(&file.src, &args.marker_start, &args.marker_stop);
    let actual: BTreeSet<usize> = (1..=lines.len()).filter(|n| flags.line(*n)).collect();
    let expected = expected_excluded(file, whole_file, lines.len());

    let over: Vec<usize> = actual
        .difference(&expected)
        .copied()
        .filter(|n| !lines[n - 1].trim().is_empty())
        .collect();
    let under: Vec<usize> = expected.difference(&actual).copied().collect();
    if over.is_empty() && under.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    if !over.is_empty() {
        parts.push(format!(
            "{} production lines wrongly excluded ({})",
            over.len(),
            as_ranges(&over)
        ));
    }
    if !under.is_empty() {
        parts.push(format!(
            "{} test-only lines still counted ({})",
            under.len(),
            as_ranges(&under)
        ));
    }
    Some(format!("{}: {}", file.rel.display(), parts.join("; ")))
}

/// The lines that should end up excluded: the test-only regions, and nothing
/// else. Derived from the parse tree, independently of any marker in the file.
fn expected_excluded(
    file: &SourceFile,
    whole_file: &BTreeSet<PathBuf>,
    line_count: usize,
) -> BTreeSet<usize> {
    if whole_file.contains(&file.rel) {
        return match file.scan.first_item_line {
            Some(first) => (first..=line_count).collect(),
            None => BTreeSet::new(),
        };
    }
    let lines: Vec<String> = file.src.split('\n').map(str::to_string).collect();
    let spans = file
        .scan
        .regions
        .iter()
        .map(|r| Span {
            start: r.start,
            end: r.end,
        })
        .collect();
    merge_spans(spans, &lines)
        .into_iter()
        .flat_map(|s| s.start..=s.end)
        .collect()
}

/// Render sorted line numbers compactly, e.g. `12-19, 44`.
fn as_ranges(lines: &[usize]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut iter = lines.iter().copied().peekable();
    while let Some(start) = iter.next() {
        let mut end = start;
        while iter.peek() == Some(&(end + 1)) {
            end = iter.next().expect("peeked");
        }
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        if out.len() == 5 && iter.peek().is_some() {
            out.push("..".to_string());
            break;
        }
    }
    out.join(", ")
}

fn check_file(file: &SourceFile, whole_file: &BTreeSet<PathBuf>, args: &Args) -> Vec<Violation> {
    let excluded = Excluded::compute(&file.src, &args.marker_start, &args.marker_stop);

    if whole_file.contains(&file.rel) {
        // Every item must fall inside the file-wide region; the licence header
        // above the first item carries no instrumentation either way.
        let Some(first_item_line) = file.scan.first_item_line else {
            return Vec::new();
        };
        return if excluded.line(first_item_line) {
            Vec::new()
        } else {
            vec![Violation::WholeFile { first_item_line }]
        };
    }

    file.scan
        .regions
        .iter()
        .filter_map(|r| {
            if excluded.range(r.start, r.end) {
                None
            } else if excluded.none_of(r.start, r.end) {
                Some(Violation::Region {
                    start: r.start,
                    end: r.end,
                    kind: r.kind,
                    gate: r.gate.clone(),
                })
            } else {
                Some(Violation::Partial {
                    start: r.start,
                    end: r.end,
                    kind: r.kind,
                })
            }
        })
        .collect()
}

/// Rewrite `src` so that grcov excludes every region in `violations`.
///
/// Markers are appended to lines that already exist rather than inserted on
/// lines of their own. That keeps every line number identical to the source the
/// compiler saw, which is what lets this run *after* the build — grcov reads
/// the file only to match marker text, so the coverage map still lines up, and
/// Coveralls still renders against the right lines of the committed source.
fn apply(src: &str, violations: &[Violation], args: &Args) -> String {
    let mut lines: Vec<String> = src.split('\n').map(str::to_string).collect();
    let line_count = lines.len();

    if let [Violation::WholeFile { first_item_line }] = violations {
        // No stop marker: an unterminated region runs to the end of the file.
        mark(&mut lines, *first_item_line, &args.marker_start);
    } else {
        let spans = violations
            .iter()
            .filter_map(|v| match v {
                Violation::Region { start, end, .. } => Some(Span {
                    start: *start,
                    end: *end,
                }),
                _ => None,
            })
            .collect();

        for span in merge_spans(spans, &lines) {
            mark(&mut lines, span.start, &args.marker_start);
            // The stop marker goes on the line *after* the region. grcov treats
            // the stop line as outside the region, and the first line past the
            // region is production code that has to stay counted. When only
            // blank lines follow, leave the region open to the end of the file
            // rather than consuming the trailing newline to hold a marker that
            // would exclude nothing.
            if lines[span.end..].iter().any(|l| !l.trim().is_empty()) {
                mark(&mut lines, span.end + 1, &args.marker_stop);
            }
        }
    }

    assert_eq!(
        lines.len(),
        line_count,
        "marker placement must not change the line count"
    );
    lines.join("\n")
}

/// Append a marker to an existing line, replacing it outright if it is blank.
fn mark(lines: &mut [String], line: usize, marker: &str) {
    let text = &mut lines[line - 1];
    if text.contains(marker) {
        return;
    }
    if text.trim().is_empty() {
        *text = format!("// {marker}");
    } else {
        text.push_str(&format!(" // {marker}"));
    }
}

struct Span {
    start: usize,
    end: usize,
}

/// Fuse spans separated only by blank lines and comments, so a run of adjacent
/// `#[cfg(test)]` helpers gets one fence rather than one per item. Only blank
/// and comment lines may be absorbed, so no live code is swept into a region.
fn merge_spans(spans: Vec<Span>, lines: &[String]) -> Vec<Span> {
    let mut merged: Vec<Span> = Vec::new();
    for span in spans {
        match merged.last_mut() {
            Some(prev)
                if ((prev.end + 1)..span.start).all(|n| {
                    let line = lines[n - 1].trim();
                    line.is_empty() || line.starts_with("//")
                }) =>
            {
                prev.end = span.end;
            }
            _ => merged.push(span),
        }
    }
    merged
}

/// Files that exist only to hold test code, reached through a test-only
/// `mod ..;` declaration, plus everything those files declare in turn.
fn test_only_module_files(
    root: &Path,
    files: &[SourceFile],
    ignore: &GlobSet,
) -> BTreeSet<PathBuf> {
    let by_path: BTreeMap<&Path, &SourceFile> =
        files.iter().map(|f| (f.rel.as_path(), f)).collect();

    let mut queue: VecDeque<PathBuf> = VecDeque::new();
    let mut found = BTreeSet::new();

    for file in files {
        for decl in file.scan.mod_decls.iter().filter(|d| d.test_only) {
            if let Some(target) = resolve_mod(root, &file.rel, &decl.name, decl.path.as_deref()) {
                queue.push_back(target);
            }
        }
    }

    // Submodules of a test-only module are test-only too, whatever they are
    // gated on, so walk the whole subtree.
    while let Some(target) = queue.pop_front() {
        if ignore.is_match(&target) || !found.insert(target.clone()) {
            continue;
        }
        let Some(file) = by_path.get(target.as_path()) else {
            continue;
        };
        for decl in &file.scan.mod_decls {
            if let Some(child) = resolve_mod(root, &target, &decl.name, decl.path.as_deref()) {
                queue.push_back(child);
            }
        }
    }
    found
}

/// Map a `mod name;` declaration to the file that holds its body.
fn resolve_mod(root: &Path, parent: &Path, name: &str, path: Option<&str>) -> Option<PathBuf> {
    let dir = parent.parent()?;
    // `foo.rs` keeps its children in `foo/`; `mod.rs`, `lib.rs` and `main.rs`
    // keep theirs alongside them.
    let child_dir = match parent.file_stem()?.to_str()? {
        "mod" | "lib" | "main" => dir.to_path_buf(),
        stem => dir.join(stem),
    };

    let candidates = match path {
        Some(p) => vec![child_dir.join(p), dir.join(p)],
        None => vec![
            child_dir.join(format!("{name}.rs")),
            child_dir.join(name).join("mod.rs"),
        ],
    };
    candidates.into_iter().find(|c| root.join(c).is_file())
}

fn collect_files(root: &Path, ignore: &GlobSet) -> Result<Vec<SourceFile>> {
    let mut files = Vec::new();
    for entry in ignore::WalkBuilder::new(root).build() {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap_or(path).to_path_buf();
        if ignore.is_match(&rel) {
            continue;
        }
        let src = fs::read_to_string(path).with_context(|| format!("reading {}", rel.display()))?;
        let parsed = syn::parse_file(&src).with_context(|| format!("parsing {}", rel.display()))?;
        files.push(SourceFile {
            rel,
            scan: scan::scan(&parsed),
            src,
        });
    }
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(files)
}

fn load_globs(path: &Path) -> Result<GlobSet> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut builder = GlobSetBuilder::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        builder.add(Glob::new(line).with_context(|| format!("bad glob {line:?}"))?);
    }
    Ok(builder.build()?)
}

fn report(violations: &BTreeMap<PathBuf, Vec<Violation>>) {
    let mut regions = 0usize;
    for (rel, found) in violations {
        for violation in found {
            regions += 1;
            match violation {
                Violation::Region {
                    start,
                    end,
                    kind,
                    gate,
                } => eprintln!(
                    "{}:{start}-{end}: test-only {kind} ({gate}) is counted toward coverage",
                    rel.display()
                ),
                Violation::WholeFile { first_item_line } => eprintln!(
                    "{}:{first_item_line}: whole file is test-only but is counted toward coverage",
                    rel.display()
                ),
                Violation::Partial { start, end, kind } => eprintln!(
                    "{}:{start}-{end}: test-only {kind} is only partly excluded; fix by hand",
                    rel.display()
                ),
            }
        }
    }
    eprintln!(
        "\n{regions} unexcluded test-only regions in {} files",
        violations.len()
    );
    eprintln!("run `cargo run --manifest-path contrib/tools/grcov-excl/Cargo.toml -- --fix`");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Args {
        Args::parse_from(["grcov-excl"])
    }

    fn region(start: usize, end: usize) -> Violation {
        Violation::Region {
            start,
            end,
            kind: "fn",
            gate: "cfg(test)".to_string(),
        }
    }

    /// The invariant the whole CI-side approach rests on.
    fn assert_line_neutral(before: &str, after: &str) {
        assert_eq!(
            before.split('\n').count(),
            after.split('\n').count(),
            "line count changed:\n--- before ---\n{before}\n--- after ---\n{after}"
        );
    }

    #[test]
    fn markers_are_appended_never_inserted() {
        let src = "fn prod() {}\n\n#[cfg(test)]\nfn helper() {}\n\nfn after() {}\n";
        let out = apply(src, &[region(3, 4)], &args());
        assert_line_neutral(src, &out);
        // The blank line after the region becomes the stop marker rather than
        // gaining one, which is what keeps the line count identical.
        assert_eq!(
            out,
            "fn prod() {}\n\n#[cfg(test)] // GRCOV_EXCL_START\nfn helper() {}\n\
             // GRCOV_EXCL_STOP\nfn after() {}\n"
        );
    }

    #[test]
    fn the_stop_marker_lands_past_the_region_so_the_last_line_stays_excluded() {
        let src = "#[cfg(test)]\nfn helper() {\n}\nfn after() {}\n";
        let out = apply(src, &[region(1, 3)], &args());
        let flags = Excluded::compute(&out, "GRCOV_EXCL_START", "GRCOV_EXCL_STOP");
        assert!(flags.range(1, 3), "the whole region must be excluded");
        assert!(!flags.line(4), "production code after it must not be");
    }

    #[test]
    fn a_region_reaching_the_end_of_the_file_needs_no_stop_marker() {
        // Marking the trailing blank would consume the file's final newline for
        // a marker that excludes nothing.
        let src = "fn prod() {}\n#[cfg(test)]\nmod t {}\n";
        let out = apply(src, &[region(2, 3)], &args());
        assert_line_neutral(src, &out);
        assert!(
            out.ends_with("mod t {}\n"),
            "trailing newline preserved: {out:?}"
        );
        let flags = Excluded::compute(&out, "GRCOV_EXCL_START", "GRCOV_EXCL_STOP");
        assert!(flags.range(2, 3));
        assert!(!flags.line(1));
    }

    #[test]
    fn a_blank_line_is_replaced_rather_than_appended_to() {
        let src = "#[cfg(test)]\nfn f() {}\n\nfn after() {}\n";
        let out = apply(src, &[region(1, 2)], &args());
        assert_line_neutral(src, &out);
        assert_eq!(out.split('\n').nth(2), Some("// GRCOV_EXCL_STOP"));
    }

    #[test]
    fn applying_twice_changes_nothing() {
        let src = "fn prod() {}\n\n#[cfg(test)]\nfn helper() {}\n\nfn after() {}\n";
        let once = apply(src, &[region(3, 4)], &args());
        let twice = apply(&once, &[region(3, 4)], &args());
        assert_eq!(once, twice);
    }

    #[test]
    fn whole_file_exclusion_opens_a_region_that_is_never_closed() {
        let src = "// licence\n\nuse std::fmt;\n\nfn helper() {}\n";
        let out = apply(src, &[Violation::WholeFile { first_item_line: 3 }], &args());
        assert_line_neutral(src, &out);
        let flags = Excluded::compute(&out, "GRCOV_EXCL_START", "GRCOV_EXCL_STOP");
        assert!(!flags.line(2), "the licence header is not excluded");
        assert!(flags.range(3, 5), "everything from the first item is");
    }

    #[test]
    fn adjacent_regions_merge_across_blanks_and_comments_but_not_across_code() {
        let lines: Vec<String> = ["a", "b", "", "// note", "c", "d", "prod();", "e"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let spans = vec![
            Span { start: 1, end: 2 },
            Span { start: 5, end: 6 },
            Span { start: 8, end: 8 },
        ];
        let merged = merge_spans(spans, &lines);
        assert_eq!(merged.len(), 2, "only the code gap blocks a merge");
        assert_eq!((merged[0].start, merged[0].end), (1, 6));
        assert_eq!((merged[1].start, merged[1].end), (8, 8));
    }

    #[test]
    fn module_paths_resolve_relative_to_the_owning_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        for rel in [
            "src/lib.rs",
            "src/sibling.rs",
            "src/parent.rs",
            "src/parent/child.rs",
            "src/parent/dir_child/mod.rs",
        ] {
            let path = root.join(rel);
            fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir");
            fs::write(&path, "").expect("write");
        }

        // `lib.rs` keeps its children alongside it ..
        assert_eq!(
            resolve_mod(root, Path::new("src/lib.rs"), "sibling", None),
            Some(PathBuf::from("src/sibling.rs"))
        );
        // .. while `parent.rs` keeps its children in `parent/`, as a file ..
        assert_eq!(
            resolve_mod(root, Path::new("src/parent.rs"), "child", None),
            Some(PathBuf::from("src/parent/child.rs"))
        );
        // .. or as a directory module.
        assert_eq!(
            resolve_mod(root, Path::new("src/parent.rs"), "dir_child", None),
            Some(PathBuf::from("src/parent/dir_child/mod.rs"))
        );
        // A `#[path = ".."]` override wins.
        assert_eq!(
            resolve_mod(root, Path::new("src/lib.rs"), "renamed", Some("sibling.rs")),
            Some(PathBuf::from("src/sibling.rs"))
        );
        assert_eq!(
            resolve_mod(root, Path::new("src/lib.rs"), "absent", None),
            None
        );
    }

    fn source_file(src: &str) -> SourceFile {
        let parsed = syn::parse_file(src).expect("parses");
        SourceFile {
            rel: PathBuf::from("candidate.rs"),
            scan: scan::scan(&parsed),
            src: src.to_string(),
        }
    }

    fn verify(src: &str) -> Option<String> {
        verify_exact(&source_file(src), &BTreeSet::new(), &args())
    }

    #[test]
    fn a_correctly_fenced_file_verifies() {
        let src = "fn prod() {}\n\n#[cfg(test)]\nfn helper() {}\n\nfn after() {}\n";
        let fenced = apply(src, &[region(3, 4)], &args());
        assert_eq!(verify(&fenced), None, "{fenced}");
    }

    #[test]
    fn a_stray_fence_in_production_code_is_rejected() {
        // Nothing here is test-only, so nothing may be excluded -- but the
        // marker text in a comment opens a region that runs to end of file.
        let src = "fn a() {}\n// mentions GRCOV_EXCL_START in passing\nfn b() {}\n";
        let complaint = verify(src).expect("stray fence must be rejected");
        assert!(
            complaint.contains("production lines wrongly excluded"),
            "{complaint}"
        );
    }

    #[test]
    fn an_over_wide_fence_is_rejected() {
        // The region is covered, so `check_file` is satisfied, but the fence
        // swallows the production function below it.
        let src = "#[cfg(test)] // GRCOV_EXCL_START\nfn helper() {}\nfn prod() {}\n                   // GRCOV_EXCL_STOP\nfn after() {}\n";
        let file = source_file(src);
        assert!(
            check_file(&file, &BTreeSet::new(), &args()).is_empty(),
            "check_file alone cannot see this"
        );
        let complaint = verify(src).expect("over-wide fence must be rejected");
        assert!(complaint.contains("wrongly excluded (3)"), "{complaint}");
    }

    #[test]
    fn a_fence_that_stops_too_early_is_rejected() {
        let src =
            "#[cfg(test)] // GRCOV_EXCL_START\nmod t {\n// GRCOV_EXCL_STOP\n}\nfn after() {}\n";
        let complaint = verify(src).expect("truncated fence must be rejected");
        assert!(
            complaint.contains("test-only lines still counted"),
            "{complaint}"
        );
    }

    #[test]
    fn line_numbers_render_as_compact_ranges() {
        assert_eq!(as_ranges(&[1, 2, 3, 7, 9, 10]), "1-3, 7, 9-10");
        assert_eq!(as_ranges(&[4]), "4");
        assert_eq!(as_ranges(&[1, 3, 5, 7, 9, 11, 13]), "1, 3, 5, 7, 9, ..");
    }
}
