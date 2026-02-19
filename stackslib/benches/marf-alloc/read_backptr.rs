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

//! Focused MARF::get benchmark tuned for deep backpointer walking.
//!
//! In `MARF_ALLOC_OUTPUT=raw`, this emits line-oriented `config` and `result`
//! records per round/case. Unified summary rows are emitted by `main.rs`.

use std::collections::HashMap;
use std::hint::black_box;
use std::time::Instant;

use blockstack_lib::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use blockstack_lib::chainstate::stacks::index::storage::TrieHashCalculationMode;
use blockstack_lib::chainstate::stacks::index::{ClarityMarfTrieId, MARFValue};
use stacks_common::types::chainstate::StacksBlockId;
use tempfile::TempDir;

use crate::allocator::{reset_stats, snapshot, Snapshot};
use crate::utils::{
    block_id, has_help_flag, parse_csv_string_env, parse_csv_u32_env, parse_u32_env,
    parse_usize_env,
};
use crate::{OutputMode, Summary};

const DEFAULT_CHAIN_LEN: u32 = 2048;
const DEFAULT_READ_ITERS: usize = 200_000;
const DEFAULT_READ_ROUNDS: usize = 2;
const DEFAULT_DEPTHS: [u32; 4] = [256, 768, 1536, 2047];
const DEFAULT_CACHE_STRATEGIES: [&str; 2] = ["noop", "node256"];

#[derive(Clone, Copy, Default)]
struct CaseAggregate {
    total_ms: f64,
    alloc_calls: u64,
    alloc_bytes: u64,
}

struct CaseMeasurement {
    elapsed_ms: f64,
    snapshot: Snapshot,
}

struct MarfReadFixture {
    marf: MARF<StacksBlockId>,
    tip: StacksBlockId,
    tip_height: u32,
    _db_dir: TempDir,
}

#[rustfmt::skip]
fn print_usage(args: &[String]) {
    if has_help_flag(args) {
        let default_depths = DEFAULT_DEPTHS
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let default_cache_strategies = DEFAULT_CACHE_STRATEGIES.join(",");

        println!("read-backptr: focused MARF::get backpointer-walk benchmark");
        println!();
        println!("Environment variables:");
        println!("  BACKPTR_CHAIN_LEN   blocks in fixture; must be > max depth [default: {DEFAULT_CHAIN_LEN}]");
        println!("  BACKPTR_READ_ITERS  reads per measured case [default: {DEFAULT_READ_ITERS}]");
        println!("  BACKPTR_READ_ROUNDS independent repetitions per case [default: {DEFAULT_READ_ROUNDS}]");
        println!("  BACKPTR_DEPTHS      comma-separated depths [default: {default_depths}]");
        println!("                      Example: BACKPTR_DEPTHS=128,512,1024");
        println!("  BACKPTR_CACHE_STRATEGIES comma-separated cache strategies [default: {default_cache_strategies}]");
        println!("  MARF_ALLOC_OUTPUT   output mode [default: summary]");
        println!("                      'summary': unified summary lines only");
        println!("                      'raw': config/result lines + unified summary lines");
        println!();
        println!("Output lines:");
        println!("  config  Effective benchmark settings");
        println!("  result  Per-round measurement: strategy/depth/time + alloc totals + per-op metrics");
        println!("  summary Unified summary lines emitted by marf-alloc main");
    }
}

fn depth_key(height: u32) -> String {
    format!("depth:{height:08x}")
}

fn key_for_depth_from_tip(tip_height: u32, depth: u32) -> String {
    assert!(depth < tip_height);
    depth_key(tip_height - depth)
}

fn make_fixture(cache_strategy: &str, chain_len: u32) -> MarfReadFixture {
    let db_dir = tempfile::Builder::new()
        .prefix(&format!("marf-read-backptr-{cache_strategy}-"))
        .tempdir()
        .expect("failed to create MARF read-backptr benchmark dir");
    let db_path = db_dir.path().join("marf-read-backptr.sqlite");
    let db_path_str = db_path
        .to_str()
        .expect("failed to convert MARF read-backptr benchmark path to UTF-8")
        .to_string();
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, cache_strategy, true);
    let mut writer_marf = MARF::from_path(&db_path_str, open_opts.clone())
        .expect("failed to open MARF for read-backptr fixture build");

    let mut parent = StacksBlockId::sentinel();
    let mut tip = parent.clone();

    for height in 1..=chain_len {
        let next = block_id(height);

        let mut tx = writer_marf
            .begin_tx()
            .expect("failed to begin tx while building read-backptr fixture");
        tx.begin(&parent, &next)
            .expect("failed to begin block extension while building read-backptr fixture");

        let keys = vec![depth_key(height)];
        let values = vec![MARFValue::from(height)];

        tx.insert_batch(&keys, values)
            .expect("failed to insert fixture keys");
        tx.commit()
            .expect("failed to commit block while building read-backptr fixture");

        parent = next.clone();
        tip = next;
    }

    drop(writer_marf);
    let marf = MARF::from_path(&db_path_str, open_opts)
        .expect("failed to reopen persisted MARF for read-backptr benchmark");

    MarfReadFixture {
        marf,
        tip,
        tip_height: chain_len,
        _db_dir: db_dir,
    }
}

fn measure_get_case(fixture: &mut MarfReadFixture, key: &str, iters: usize) -> CaseMeasurement {
    reset_stats();
    let start = Instant::now();
    for _ in 0..iters {
        black_box(
            fixture
                .marf
                .get(&fixture.tip, key)
                .expect("MARF::get failed in read-backptr benchmark"),
        );
    }
    CaseMeasurement {
        elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
        snapshot: snapshot(),
    }
}

pub fn run(args: &[String], output_mode: OutputMode) -> Option<Summary> {
    if has_help_flag(args) {
        print_usage(args);
        return None;
    }

    let chain_len = parse_u32_env("BACKPTR_CHAIN_LEN", DEFAULT_CHAIN_LEN);
    let iters = parse_usize_env("BACKPTR_READ_ITERS", DEFAULT_READ_ITERS);
    let rounds = parse_usize_env("BACKPTR_READ_ROUNDS", DEFAULT_READ_ROUNDS);
    let depths = parse_csv_u32_env("BACKPTR_DEPTHS", &DEFAULT_DEPTHS);
    let cache_strategies =
        parse_csv_string_env("BACKPTR_CACHE_STRATEGIES", &DEFAULT_CACHE_STRATEGIES);

    assert!(iters > 0, "BACKPTR_READ_ITERS must be > 0");
    assert!(rounds > 0, "BACKPTR_READ_ROUNDS must be > 0");

    let max_depth = *depths.iter().max().expect("depth list must not be empty");
    assert!(
        chain_len > max_depth,
        "BACKPTR_CHAIN_LEN ({chain_len}) must be greater than max depth ({max_depth})"
    );

    if output_mode.is_raw() {
        println!(
            "config\tchain_len={chain_len}\tread_iters={iters}\tread_rounds={rounds}\tdepths={depths:?}\tstrategies={cache_strategies:?}"
        );
    }

    let mut results: HashMap<(String, u32), CaseAggregate> = HashMap::new();

    for round in 1..=rounds {
        for strategy in &cache_strategies {
            let mut fixture = make_fixture(strategy, chain_len);

            for &depth in &depths {
                let key = key_for_depth_from_tip(fixture.tip_height, depth);
                let measurement = measure_get_case(&mut fixture, &key, iters);
                let elapsed_ms = measurement.elapsed_ms;
                let us_per_op = (elapsed_ms * 1000.0) / (iters as f64);
                let alloc_calls_per_op = (measurement.snapshot.alloc_calls as f64) / (iters as f64);
                let alloc_bytes_per_op = (measurement.snapshot.alloc_bytes as f64) / (iters as f64);

                if output_mode.is_raw() {
                    println!(
                        "result\tround={round}\tstrategy={strategy}\tdepth={depth}\telapsed_ms={elapsed_ms:.3}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}\tdealloc_calls={}\tdealloc_bytes={}\tus_per_op={us_per_op:.6}\talloc_calls_per_op={alloc_calls_per_op:.6}\talloc_bytes_per_op={alloc_bytes_per_op:.6}",
                        measurement.snapshot.alloc_calls,
                        measurement.snapshot.alloc_bytes,
                        measurement.snapshot.realloc_calls,
                        measurement.snapshot.dealloc_calls,
                        measurement.snapshot.dealloc_bytes,
                    );
                }

                let agg = results.entry((strategy.to_string(), depth)).or_default();
                agg.total_ms += elapsed_ms;
                agg.alloc_calls += measurement.snapshot.alloc_calls;
                agg.alloc_bytes += measurement.snapshot.alloc_bytes;
            }
        }
    }

    let mut summary = Summary::new("read-backptr", cache_strategies.len() * depths.len());
    for strategy in &cache_strategies {
        for &depth in &depths {
            let key = (strategy.to_string(), depth);
            let case = results
                .get(&key)
                .expect("missing case samples while summarizing read-backptr benchmark");
            summary.push_line(
                format!("{strategy}/depth={depth}"),
                case.total_ms,
                case.alloc_calls,
                case.alloc_bytes,
            );
        }
    }

    Some(summary)
}
