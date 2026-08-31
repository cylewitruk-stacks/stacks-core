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

//! Mirror of grcov's line-exclusion filter (`grcov/src/file_filter.rs`).
//!
//! Kept deliberately faithful so that what this tool considers excluded is
//! exactly what grcov drops from the report:
//!
//! - a start marker begins a region and is itself excluded;
//! - a stop marker ends the region and is itself *not* excluded;
//! - regions do not nest — the first stop closes the region;
//! - a region with no matching stop runs to the end of the file.

/// Per-line exclusion flags, indexed by `line number - 1`.
pub struct Excluded(Vec<bool>);

impl Excluded {
    pub fn compute(src: &str, start_marker: &str, stop_marker: &str) -> Self {
        let mut ignoring = false;
        Self(
            src.split('\n')
                .map(|line| {
                    let line = line.strip_suffix('\r').unwrap_or(line);
                    if ignoring && line.contains(stop_marker) {
                        ignoring = false;
                    } else if !ignoring && line.contains(start_marker) {
                        ignoring = true;
                    }
                    ignoring
                })
                .collect(),
        )
    }

    pub fn line(&self, line: usize) -> bool {
        self.0.get(line - 1).copied().unwrap_or(false)
    }

    /// Whether every line in the inclusive range is excluded.
    pub fn range(&self, start: usize, end: usize) -> bool {
        (start..=end).all(|n| self.line(n))
    }

    /// Whether no line in the inclusive range is excluded.
    pub fn none_of(&self, start: usize, end: usize) -> bool {
        (start..=end).all(|n| !self.line(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn excluded_lines(src: &str) -> Vec<usize> {
        let flags = Excluded::compute(src, "START", "STOP");
        (1..=src.split('\n').count())
            .filter(|n| flags.line(*n))
            .collect()
    }

    #[test]
    fn start_line_is_inside_the_region_and_stop_line_is_outside() {
        // This asymmetry is grcov's, and it is why the stop marker belongs on
        // the line *after* a region rather than on its last line.
        let src = "a\nb START\nc\nd STOP\ne";
        assert_eq!(excluded_lines(src), vec![2, 3]);
    }

    #[test]
    fn an_unterminated_region_runs_to_the_end_of_the_file() {
        let src = "a\nb START\nc\nd";
        assert_eq!(excluded_lines(src), vec![2, 3, 4]);
    }

    #[test]
    fn regions_do_not_nest_so_the_first_stop_closes_the_region() {
        let src = "a\nSTART\nSTART\nSTOP\nd\nSTOP\ng";
        assert_eq!(excluded_lines(src), vec![2, 3]);
    }

    #[test]
    fn a_stop_without_an_open_region_does_nothing() {
        let src = "a\nSTOP\nc";
        assert!(excluded_lines(src).is_empty());
    }

    #[test]
    fn markers_are_matched_anywhere_on_the_line() {
        let src = "code(); // START\nx\n} // STOP\nafter";
        assert_eq!(excluded_lines(src), vec![1, 2]);
    }

    #[test]
    fn carriage_returns_do_not_defeat_matching() {
        let src = "a\r\nSTART\r\nb\r\nSTOP\r\nc";
        assert_eq!(excluded_lines(src), vec![2, 3]);
    }

    #[test]
    fn range_helpers_agree_with_per_line_flags() {
        let flags = Excluded::compute("a\nSTART\nb\nSTOP\nc", "START", "STOP");
        assert!(flags.range(2, 3));
        assert!(!flags.range(2, 4));
        assert!(flags.none_of(4, 5));
        assert!(!flags.none_of(3, 4));
    }
}
