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

//! Read-heavy MARF timing benchmark focused on `MARF::get` backpointer walks.
//!
//! Output format is line-oriented and parse-friendly:
//! - `config\t...`: effective configuration for this run.
//! - `result\t...`: one measured case for one round/strategy/depth, including
//!   time and allocation counters.
//! - `summary\t...`: aggregate over rounds per strategy/depth.
//! Run `read --help` for user-facing configuration details.

use std::collections::HashMap;
use std::hint::black_box;
use std::time::Instant;

use blockstack_lib::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use blockstack_lib::chainstate::stacks::index::storage::TrieHashCalculationMode;
use blockstack_lib::chainstate::stacks::index::{ClarityMarfTrieId, MARFValue};
use stacks_common::types::chainstate::StacksBlockId;
use tempfile::TempDir;

use crate::allocator::{reset_stats, snapshot, Snapshot};

const DEFAULT_CHAIN_LEN: u32 = 512;
const DEFAULT_READ_ITERS: usize = 200_000;
const DEFAULT_READ_ROUNDS: usize = 2;
const DEFAULT_KEYS_PER_BLOCK: u32 = 4;
const DEFAULT_DEPTHS: [u32; 4] = [32, 128, 256, 511];
const DEFAULT_CACHE_STRATEGIES: [&str; 2] = ["noop", "node256"];

#[derive(Clone, Copy)]
struct CaseSample {
    us_per_op: f64,
    alloc_calls_per_op: f64,
    alloc_bytes_per_op: f64,
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

fn parse_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

fn parse_u32_env(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(default)
}

fn parse_depths_env(name: &str, default: &[u32]) -> Vec<u32> {
    let Some(raw) = std::env::var(name).ok() else {
        return default.to_vec();
    };
    let parsed: Vec<u32> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u32>()
                .unwrap_or_else(|_| panic!("invalid {name} entry: '{s}'"))
        })
        .collect();
    assert!(
        !parsed.is_empty(),
        "{name} must contain at least one integer depth"
    );
    parsed
}

fn parse_cache_strategies_env(name: &str, default: &[&str]) -> Vec<String> {
    let Some(raw) = std::env::var(name).ok() else {
        return default.iter().map(|s| (*s).to_string()).collect();
    };
    let parsed: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    assert!(
        !parsed.is_empty(),
        "{name} must contain at least one cache strategy"
    );
    parsed
}

#[rustfmt::skip]
fn print_usage(args: &[String]) {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        let default_depths = DEFAULT_DEPTHS
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let default_cache_strategies = DEFAULT_CACHE_STRATEGIES.join(",");

        println!("read: MARF::get backpointer read benchmark");
        println!();
        println!("Environment variables:");
        println!("  CHAIN_LEN   blocks in fixture; must be > max depth [default: {DEFAULT_CHAIN_LEN}]");
        println!("              Higher values increase fixture construction time and temporary DB size");
        println!("  READ_ITERS  reads per measured case [default: {DEFAULT_READ_ITERS}]");
        println!("              Higher values reduce measurement noise but increase runtime linearly");
        println!("              Affects elapsed_ms/alloc totals directly; per-op metrics remain normalized");
        println!("  READ_ROUNDS (default 2) independent repetitions per case");
        println!("              Higher values improve stability estimates (summary min/max)");
        println!("  KEYS_PER_BLOCK number of keys inserted per fixture block [default: {DEFAULT_KEYS_PER_BLOCK}]");
        println!("              Must be >= 1; higher values make each fixture block denser");
        println!("  DEPTHS      comma-separated depths [default: {default_depths}]");
        println!("              Example: DEPTHS=16,64,255");
        println!("  CACHE_STRATEGIES comma-separated MARF cache strategies [default: {default_cache_strategies}]");
        println!("              Example: CACHE_STRATEGIES=noop,node256,everything");
        println!();
        println!("Output lines:");
        println!("  config  Effective benchmark settings");
        println!("  result  Per-round measurement: strategy/depth/time + alloc totals + per-op metrics");
        println!("  summary Aggregated per strategy/depth over all rounds (time + per-op alloc)");
        return;
    }
}

fn block_id(seed: u32) -> StacksBlockId {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&seed.to_be_bytes());
    StacksBlockId::from(bytes)
}

fn depth_key(height: u32) -> String {
    format!("depth:{height:08x}")
}

fn key_for_depth_from_tip(tip_height: u32, depth: u32) -> String {
    assert!(depth < tip_height);
    depth_key(tip_height - depth)
}

fn make_fixture(cache_strategy: &str, chain_len: u32, keys_per_block: u32) -> MarfReadFixture {
    let db_dir = tempfile::Builder::new()
        .prefix(&format!("marf-read-profile-{cache_strategy}-"))
        .tempdir()
        .expect("failed to create MARF read benchmark dir");
    let db_path = db_dir.path().join("marf-read.sqlite");
    let db_path_str = db_path
        .to_str()
        .expect("failed to convert MARF read benchmark path to UTF-8");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, cache_strategy, true);
    let mut marf =
        MARF::from_path(db_path_str, open_opts).expect("failed to open MARF for read profile");

    let mut parent = StacksBlockId::sentinel();
    let mut tip = parent.clone();

    for height in 1..=chain_len {
        let next = block_id(height);

        let mut tx = marf
            .begin_tx()
            .expect("failed to begin tx while building read profile fixture");
        tx.begin(&parent, &next)
            .expect("failed to begin block extension while building read profile fixture");

        let mut keys = Vec::with_capacity(keys_per_block as usize);
        let mut values = Vec::with_capacity(keys_per_block as usize);

        keys.push(depth_key(height));
        values.push(MARFValue::from(height));

        for noise_ix in 0..(keys_per_block - 1) {
            keys.push(format!("noise:{height:08x}:{noise_ix:02x}"));
            values.push(MARFValue::from(
                height.wrapping_mul(97).wrapping_add(noise_ix + 1),
            ));
        }

        tx.insert_batch(&keys, values)
            .expect("failed to insert fixture keys");
        tx.commit()
            .expect("failed to commit block while building read profile fixture");

        parent = next.clone();
        tip = next;
    }

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
                .expect("MARF::get failed in read profile"),
        );
    }
    CaseMeasurement {
        elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
        snapshot: snapshot(),
    }
}

fn average(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / (values.len() as f64)
}

pub fn run(args: &[String]) {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_usage(args);
        return;
    }

    let chain_len = parse_u32_env("CHAIN_LEN", DEFAULT_CHAIN_LEN);
    let iters = parse_usize_env("READ_ITERS", DEFAULT_READ_ITERS);
    let rounds = parse_usize_env("READ_ROUNDS", DEFAULT_READ_ROUNDS);
    let keys_per_block = parse_u32_env("KEYS_PER_BLOCK", DEFAULT_KEYS_PER_BLOCK);
    let depths = parse_depths_env("DEPTHS", &DEFAULT_DEPTHS);
    let cache_strategies =
        parse_cache_strategies_env("CACHE_STRATEGIES", &DEFAULT_CACHE_STRATEGIES);

    assert!(iters > 0, "READ_ITERS must be > 0");
    assert!(rounds > 0, "READ_ROUNDS must be > 0");
    assert!(keys_per_block > 0, "KEYS_PER_BLOCK must be >= 1");

    let max_depth = *depths.iter().max().expect("depth list must not be empty");
    assert!(
        chain_len > max_depth,
        "CHAIN_LEN ({chain_len}) must be greater than max depth ({max_depth})"
    );

    println!(
        "config\tchain_len={chain_len}\tread_iters={iters}\tread_rounds={rounds}\tkeys_per_block={keys_per_block}\tdepths={depths:?}\tstrategies={cache_strategies:?}"
    );

    let mut results: HashMap<(String, u32), Vec<CaseSample>> = HashMap::new();

    for round in 1..=rounds {
        for strategy in &cache_strategies {
            let mut fixture = make_fixture(strategy, chain_len, keys_per_block);

            for &depth in &depths {
                let key = key_for_depth_from_tip(fixture.tip_height, depth);
                let measurement = measure_get_case(&mut fixture, &key, iters);
                let elapsed_ms = measurement.elapsed_ms;
                let us_per_op = (elapsed_ms * 1000.0) / (iters as f64);
                let alloc_calls_per_op = (measurement.snapshot.alloc_calls as f64) / (iters as f64);
                let alloc_bytes_per_op = (measurement.snapshot.alloc_bytes as f64) / (iters as f64);

                println!(
                    "result\tround={round}\tstrategy={strategy}\tdepth={depth}\telapsed_ms={elapsed_ms:.3}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}\tdealloc_calls={}\tdealloc_bytes={}\tus_per_op={us_per_op:.6}\talloc_calls_per_op={alloc_calls_per_op:.6}\talloc_bytes_per_op={alloc_bytes_per_op:.6}",
                    measurement.snapshot.alloc_calls,
                    measurement.snapshot.alloc_bytes,
                    measurement.snapshot.realloc_calls,
                    measurement.snapshot.dealloc_calls,
                    measurement.snapshot.dealloc_bytes,
                );

                results
                    .entry((strategy.to_string(), depth))
                    .or_default()
                    .push(CaseSample {
                        us_per_op,
                        alloc_calls_per_op,
                        alloc_bytes_per_op,
                    });
            }
        }
    }

    println!(
        "summary\tstrategy\tdepth\tavg_us_per_op\tmin_us_per_op\tmax_us_per_op\tavg_alloc_calls_per_op\tavg_alloc_bytes_per_op"
    );
    for strategy in &cache_strategies {
        for &depth in &depths {
            let key = (strategy.to_string(), depth);
            let case = results
                .get(&key)
                .expect("missing case samples while summarizing read profile");
            let us: Vec<f64> = case.iter().map(|s| s.us_per_op).collect();
            let alloc_calls: Vec<f64> = case.iter().map(|s| s.alloc_calls_per_op).collect();
            let alloc_bytes: Vec<f64> = case.iter().map(|s| s.alloc_bytes_per_op).collect();
            let avg = average(&us);
            let min = us.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = us.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let avg_alloc_calls = average(&alloc_calls);
            let avg_alloc_bytes = average(&alloc_bytes);
            println!(
                "summary\t{strategy}\t{depth}\t{avg:.6}\t{min:.6}\t{max:.6}\t{avg_alloc_calls:.6}\t{avg_alloc_bytes:.6}"
            );
        }
    }
}
