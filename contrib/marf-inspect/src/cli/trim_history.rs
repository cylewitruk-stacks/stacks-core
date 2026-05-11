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

//! Operator subcommand: destructively trim per-level FullHistory history
//! blobs.
//!
//! This is the first marf-inspect subcommand that mutates the DB, so it
//! deliberately bypasses the read-only [`crate::cli::CliCtx`] and opens
//! its own writable [`MARF`] via [`MARF::from_path`]. The other
//! subcommands stay read-only.
//!
//! See `.docs/full-history-history-blob-design.md` §10.2 for the trim
//! contract; the library helpers
//! [`trim_history_blob_for_level`] /
//! [`trim_history_blobs_for_all_present`] enforce the §10.2 ordering
//! (publish-window SQL flip → best-effort unlink). This subcommand is a
//! narrow wrapper that selects a single level by id or every
//! `'present'` level, runs the helper, and prints the resulting
//! [`HistoryBlobTrimReport`].

use std::path::Path;

use clap::Args;
use stacks_common::types::chainstate::StacksBlockId;
use stackslib::chainstate::stacks::index::marf::{MARF, MARFOpenOpts};
use stackslib::chainstate::stacks::index::squash::{
    HistoryBlobTrimReport, trim_history_blob_for_level, trim_history_blobs_for_all_present,
};
use stackslib::chainstate::stacks::index::storage::TrieHashCalculationMode;

#[derive(Args)]
pub struct TrimHistoryArgs {
    /// Trim the history blob for a single squash level by id. Mutually
    /// exclusive with `--all`. Fails if the level's
    /// `history_blob_state` is `'never_written'`. Idempotent if
    /// `'trimmed'`: counted under `already_trimmed`; any leftover file
    /// from a prior partial trim is reaped.
    #[arg(long, value_name = "LEVEL_ID", conflicts_with = "all")]
    pub level: Option<u32>,

    /// Trim every squash level whose `history_blob_state` is
    /// currently `'present'`. Each per-level trim is independently
    /// transactional: a mid-batch crash leaves any already-trimmed
    /// levels durably trimmed; rerunning resumes with the remaining
    /// `'present'` levels.
    #[arg(long, conflicts_with = "level")]
    pub all: bool,
}

pub fn exec(db_path: &Path, args: TrimHistoryArgs) {
    if args.level.is_none() && !args.all {
        eprintln!("error: must specify either --level <ID> or --all");
        std::process::exit(2);
    }

    let db_path_str = db_path.to_string_lossy().to_string();

    // marf-inspect operates on the MARF sqlite path directly. The
    // library helpers require a full writable handle because the SQL
    // flip runs inside the publish_squash quiesce window — a plain
    // rusqlite::Connection isn't enough.
    //
    // `auto_recovery=false` keeps the open path from running
    // canonical-sensitive recovery; this tool isn't a chainstate
    // coordinator and shouldn't speculatively publish/discard pending
    // squash plans. Byte-level recovery (torn hot-tail truncation,
    // stale tmp-file sweep, history blob reconcile) still runs at
    // open time and is exactly what we want before a trim pass.
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&db_path_str, open_opts).unwrap_or_else(|e| {
        eprintln!("failed to open MARF at {db_path_str}: {e:?}");
        std::process::exit(1);
    });

    eprintln!(
        "marf-inspect trim-history: opening MARF at {db_path_str}. \
         WARNING: this destructively trims FullHistory history-blob files. \
         Trimmed levels cannot serve at-block reads against squashed history \
         without a resync. SQL is the source of truth; best-effort unlink \
         follows."
    );

    let report = if args.all {
        trim_history_blobs_for_all_present(&mut marf).unwrap_or_else(|e| {
            eprintln!("trim-history --all failed: {e:?}");
            std::process::exit(1);
        })
    } else {
        let mut report = HistoryBlobTrimReport::default();
        let level_id = args.level.expect("guarded above");
        trim_history_blob_for_level(&mut marf, level_id, &mut report).unwrap_or_else(|e| {
            eprintln!("trim-history --level {level_id} failed: {e:?}");
            std::process::exit(1);
        });
        report
    };

    print_report(&report);

    // Non-zero exit if any per-level SQL flip failed. Unlink failures
    // are operator-noticeable but not fatal: SQL says `'trimmed'`, so
    // the read path is correct, and startup reconcile reaps the
    // orphan.
    if report.trim_failures > 0 {
        std::process::exit(1);
    }
}

fn print_report(r: &HistoryBlobTrimReport) {
    let bytes = r.bytes_freed_estimate;
    let (display_value, display_unit) = if bytes >= (1u64 << 30) {
        (bytes as f64 / (1u64 << 30) as f64, "GB")
    } else if bytes >= (1u64 << 20) {
        (bytes as f64 / (1u64 << 20) as f64, "MB")
    } else if bytes >= (1u64 << 10) {
        (bytes as f64 / (1u64 << 10) as f64, "KB")
    } else {
        (bytes as f64, "B")
    };

    println!("trim-history report:");
    println!("  levels_trimmed       : {}", r.levels_trimmed);
    println!("  already_trimmed      : {}", r.already_trimmed);
    println!("  trim_failures        : {}", r.trim_failures);
    println!("  unlink_failures      : {}", r.unlink_failures);
    println!("  bytes_freed_estimate : {bytes} ({display_value:.2} {display_unit})");
}
