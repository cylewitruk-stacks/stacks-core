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

//! Write-heavy MARF profiling benchmark focused on a controlled block-write workflow.
//!
//! Each run measures per-step timing and allocation counters for:
//! - beginning a new trie extension (`begin_block`),
//! - deterministic node-growth insert phases up through `Node256` promotion,
//! - `seal()`, and
//! - flush/commit to disk (`commit_flush`).
//!
//! Output format is line-oriented and parse-friendly:
//! - `config\t...`: effective benchmark configuration.
//! - `keys\t...`: metadata about the generated key set used to force promotions.
//! - `result\t...`: per-round/per-step timing and allocation totals + per-item rates.
//! - `summary\t...`: aggregate per strategy/step over all rounds.
//!
//! Environment variables:
//! - `WRITE_ROUNDS` (default `2`): number of independent workflow repetitions.
//! - `KEY_SEARCH_MAX_TRIES` (default `200000`): max key candidates to try when
//!   searching for a hash bucket that yields enough distinct branches.

use std::collections::HashMap;
use std::hint::black_box;
use std::time::Instant;

use blockstack_lib::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use blockstack_lib::chainstate::stacks::index::storage::TrieHashCalculationMode;
use blockstack_lib::chainstate::stacks::index::{
    ClarityMarfTrieId, Error as IndexError, MARFValue,
};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use tempfile::TempDir;

use crate::allocator::{reset_stats, snapshot, Snapshot};

const DEFAULT_WRITE_ROUNDS: usize = 2;
const DEFAULT_KEY_SEARCH_MAX_TRIES: usize = 200_000;
const REQUIRED_BRANCHES: usize = 49;
const WRITE_CACHE_STRATEGIES: [&str; 2] = ["noop", "node256"];

#[derive(Clone, Copy)]
struct StepSample {
    us_per_item: f64,
    alloc_calls_per_item: f64,
    alloc_bytes_per_item: f64,
}

struct StepMeasurement {
    elapsed_ms: f64,
    snapshot: Snapshot,
}

#[derive(Clone, Copy)]
struct InsertStep {
    name: &'static str,
    start: usize,
    end: usize,
}

const INSERT_STEPS: [InsertStep; 8] = [
    InsertStep {
        name: "insert_first_leaf",
        start: 0,
        end: 1,
    },
    InsertStep {
        name: "split_leaf_to_node4",
        start: 1,
        end: 2,
    },
    InsertStep {
        name: "fill_node4_to_capacity",
        start: 2,
        end: 4,
    },
    InsertStep {
        name: "promote_node4_to_node16",
        start: 4,
        end: 5,
    },
    InsertStep {
        name: "fill_node16_to_capacity",
        start: 5,
        end: 16,
    },
    InsertStep {
        name: "promote_node16_to_node48",
        start: 16,
        end: 17,
    },
    InsertStep {
        name: "fill_node48_to_capacity",
        start: 17,
        end: 48,
    },
    InsertStep {
        name: "promote_node48_to_node256",
        start: 48,
        end: 49,
    },
];

const STEP_ORDER: [&str; 11] = [
    "begin_block",
    "insert_first_leaf",
    "split_leaf_to_node4",
    "fill_node4_to_capacity",
    "promote_node4_to_node16",
    "fill_node16_to_capacity",
    "promote_node16_to_node48",
    "fill_node48_to_capacity",
    "promote_node48_to_node256",
    "seal",
    "commit_flush",
];

struct PromotionKeys {
    keys: Vec<String>,
    shared_first_byte: u8,
    search_tries: usize,
}

fn parse_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

#[rustfmt::skip]
fn print_usage(args: &[String]) {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!("write: step-wise MARF write workflow profiler");
        println!();
        println!("Environment variables:");
        println!("  WRITE_ROUNDS          (default {DEFAULT_WRITE_ROUNDS}) independent rounds per strategy"
        );
        println!(
            "  KEY_SEARCH_MAX_TRIES  (default {DEFAULT_KEY_SEARCH_MAX_TRIES}) max key candidates when searching for promotion-driving keys"
        );
        println!();
        println!("Output lines:");
        println!("  config   Effective configuration");
        println!("  keys     Metadata about generated key set used to drive node promotions");
        println!(
            "  result   Per-round/per-step elapsed time and allocation totals + per-item rates"
        );
        println!("  summary  Aggregated per strategy/step over all rounds");
        return;
    }
}

fn measure_step<R, F>(f: F) -> Result<StepMeasurement, IndexError>
where
    F: FnOnce() -> Result<R, IndexError>,
{
    reset_stats();
    let start = Instant::now();
    let out = f()?;
    black_box(out);
    Ok(StepMeasurement {
        elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
        snapshot: snapshot(),
    })
}

fn average(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / (values.len() as f64)
}

fn block_id(seed: u32) -> StacksBlockId {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&seed.to_be_bytes());
    StacksBlockId::from(bytes)
}

fn make_values(start: u32, count: usize) -> Vec<MARFValue> {
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        values.push(MARFValue::from(
            start.wrapping_add(i as u32).wrapping_add(1),
        ));
    }
    values
}

fn make_marf(cache_strategy: &str) -> (TempDir, MARF<StacksBlockId>) {
    let db_dir = tempfile::Builder::new()
        .prefix(&format!("marf-write-profile-{cache_strategy}-"))
        .tempdir()
        .expect("failed to create MARF write benchmark dir");
    let db_path = db_dir.path().join("marf-write.sqlite");
    let db_path_str = db_path
        .to_str()
        .expect("failed to convert MARF write benchmark path to UTF-8");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, cache_strategy, true);
    let marf = MARF::from_path(db_path_str, open_opts).expect("failed to open MARF write profile");
    (db_dir, marf)
}

fn initialize_parent_block(
    marf: &mut MARF<StacksBlockId>,
    parent_block: &StacksBlockId,
) -> Result<(), IndexError> {
    let mut tx = marf.begin_tx()?;
    tx.begin(&StacksBlockId::sentinel(), parent_block)?;

    // Bootstrap with one write so the measured block extends a non-empty parent trie.
    let keys = vec!["bootstrap:parent".to_string()];
    let values = vec![MARFValue::from(1)];
    tx.insert_batch(&keys, values)?;
    tx.commit()?;
    Ok(())
}

fn find_promotion_keys(seed_prefix: &str, max_tries: usize) -> PromotionKeys {
    let mut buckets: Vec<HashMap<u8, String>> = (0..256).map(|_| HashMap::new()).collect();

    for i in 0..max_tries {
        let key = format!("{seed_prefix}:{i:08x}");
        let hash = TrieHash::from_key(&key);
        let bytes = hash.as_bytes();

        let first = bytes[0] as usize;
        let second = bytes[1];
        let bucket = &mut buckets[first];
        bucket.entry(second).or_insert(key);

        if bucket.len() >= REQUIRED_BRANCHES {
            let mut pairs: Vec<(u8, String)> =
                bucket.iter().map(|(&chr, k)| (chr, k.clone())).collect();
            pairs.sort_by_key(|(chr, _)| *chr);
            pairs.truncate(REQUIRED_BRANCHES);

            return PromotionKeys {
                keys: pairs.into_iter().map(|(_, key)| key).collect(),
                shared_first_byte: first as u8,
                search_tries: i + 1,
            };
        }
    }

    panic!(
        "failed to find {} promotion-driving keys within KEY_SEARCH_MAX_TRIES={max_tries}",
        REQUIRED_BRANCHES
    );
}

fn run_workflow() -> Result<(), IndexError> {
    let rounds = parse_usize_env("WRITE_ROUNDS", DEFAULT_WRITE_ROUNDS);
    let max_tries = parse_usize_env("KEY_SEARCH_MAX_TRIES", DEFAULT_KEY_SEARCH_MAX_TRIES);

    assert!(rounds > 0, "WRITE_ROUNDS must be > 0");
    assert!(max_tries > 0, "KEY_SEARCH_MAX_TRIES must be > 0");

    println!(
        "config\twrite_rounds={rounds}\tkey_search_max_tries={max_tries}\trequired_branches={REQUIRED_BRANCHES}\tstrategies={WRITE_CACHE_STRATEGIES:?}"
    );

    let mut results: HashMap<(String, String), Vec<StepSample>> = HashMap::new();

    for round in 1..=rounds {
        for (strategy_idx, strategy) in WRITE_CACHE_STRATEGIES.into_iter().enumerate() {
            let (_db_dir, mut marf) = make_marf(strategy);

            let base_seed = 1_000_000u32
                .wrapping_add((round as u32).wrapping_mul(100))
                .wrapping_add((strategy_idx as u32).wrapping_mul(2));
            let parent_block = block_id(base_seed);
            let next_block = block_id(base_seed.wrapping_add(1));

            initialize_parent_block(&mut marf, &parent_block)?;

            let promotion_keys =
                find_promotion_keys(&format!("write-profile:{strategy}:{round}"), max_tries);
            println!(
                "keys\tround={round}\tstrategy={strategy}\tshared_first_byte={}\tsearch_tries={}\tkey_count={}",
                promotion_keys.shared_first_byte,
                promotion_keys.search_tries,
                promotion_keys.keys.len()
            );

            let mut tx = marf.begin_tx()?;

            let begin_measurement = measure_step(|| tx.begin(&parent_block, &next_block))?;
            emit_result_and_store(
                &mut results,
                round,
                strategy,
                "begin_block",
                1,
                begin_measurement,
            );

            let mut value_cursor = 10_000u32;
            for step in INSERT_STEPS {
                let keys = &promotion_keys.keys[step.start..step.end];
                let values = make_values(value_cursor, keys.len());
                value_cursor = value_cursor.wrapping_add(keys.len() as u32);

                let measurement = measure_step(|| tx.insert_batch(keys, values))?;
                emit_result_and_store(
                    &mut results,
                    round,
                    strategy,
                    step.name,
                    keys.len(),
                    measurement,
                );
            }

            let seal_measurement = measure_step(|| tx.seal())?;
            emit_result_and_store(&mut results, round, strategy, "seal", 1, seal_measurement);

            let commit_measurement = measure_step(|| tx.commit())?;
            emit_result_and_store(
                &mut results,
                round,
                strategy,
                "commit_flush",
                1,
                commit_measurement,
            );
        }
    }

    println!(
        "summary\tstrategy\tstep\tavg_us_per_item\tmin_us_per_item\tmax_us_per_item\tavg_alloc_calls_per_item\tavg_alloc_bytes_per_item"
    );
    for strategy in WRITE_CACHE_STRATEGIES {
        for step in STEP_ORDER {
            let key = (strategy.to_string(), step.to_string());
            let samples = results
                .get(&key)
                .expect("missing step samples while summarizing write profile");

            let us: Vec<f64> = samples.iter().map(|s| s.us_per_item).collect();
            let alloc_calls: Vec<f64> = samples.iter().map(|s| s.alloc_calls_per_item).collect();
            let alloc_bytes: Vec<f64> = samples.iter().map(|s| s.alloc_bytes_per_item).collect();

            let avg_us = average(&us);
            let min_us = us.iter().cloned().fold(f64::INFINITY, f64::min);
            let max_us = us.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let avg_alloc_calls = average(&alloc_calls);
            let avg_alloc_bytes = average(&alloc_bytes);

            println!(
                "summary\t{strategy}\t{step}\t{avg_us:.6}\t{min_us:.6}\t{max_us:.6}\t{avg_alloc_calls:.6}\t{avg_alloc_bytes:.6}"
            );
        }
    }

    Ok(())
}

fn emit_result_and_store(
    results: &mut HashMap<(String, String), Vec<StepSample>>,
    round: usize,
    strategy: &str,
    step: &str,
    items: usize,
    measurement: StepMeasurement,
) {
    let elapsed_ms = measurement.elapsed_ms;
    let us_per_item = (elapsed_ms * 1000.0) / (items as f64);
    let alloc_calls_per_item = (measurement.snapshot.alloc_calls as f64) / (items as f64);
    let alloc_bytes_per_item = (measurement.snapshot.alloc_bytes as f64) / (items as f64);

    println!(
        "result\tround={round}\tstrategy={strategy}\tstep={step}\titems={items}\telapsed_ms={elapsed_ms:.3}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}\tdealloc_calls={}\tdealloc_bytes={}\tus_per_item={us_per_item:.6}\talloc_calls_per_item={alloc_calls_per_item:.6}\talloc_bytes_per_item={alloc_bytes_per_item:.6}",
        measurement.snapshot.alloc_calls,
        measurement.snapshot.alloc_bytes,
        measurement.snapshot.realloc_calls,
        measurement.snapshot.dealloc_calls,
        measurement.snapshot.dealloc_bytes,
    );

    results
        .entry((strategy.to_string(), step.to_string()))
        .or_default()
        .push(StepSample {
            us_per_item,
            alloc_calls_per_item,
            alloc_bytes_per_item,
        });
}

pub fn run(args: &[String]) {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_usage(args);
        return;
    }
    run_workflow().expect("marf_write_profile failed");
}
