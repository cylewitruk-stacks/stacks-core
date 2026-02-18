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

use std::collections::HashMap;
use std::hint::black_box;

use blockstack_lib::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use blockstack_lib::chainstate::stacks::index::storage::TrieHashCalculationMode;
use blockstack_lib::chainstate::stacks::index::{ClarityMarfTrieId, MARFValue, TrieMerkleProof};
use criterion::{criterion_group, BatchSize, Criterion};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use tempfile::TempDir;

use super::common::{block_id, configured_criterion, make_batch};

const CHAIN_LEN: u32 = 192;
const DEPTHS: [u32; 3] = [1, 8, 64];
const BACKPTR_CHAIN_LEN: u32 = 512;
const BACKPTR_DEPTHS: [u32; 4] = [32, 128, 256, 511];
const KEYS_PER_BLOCK: u32 = 4;
const CACHE_STRATEGIES: [&str; 2] = ["noop", "everything"];
const INSERT_BATCH_SIZE: u32 = 64;

struct MarfApiFixture {
    _tmpdir: TempDir,
    marf: MARF<StacksBlockId>,
    tip: StacksBlockId,
    tip_height: u32,
}

fn depth_key(height: u32) -> String {
    format!("depth:{height:08x}")
}

fn key_for_depth_from_tip(tip_height: u32, depth: u32) -> String {
    assert!(depth < tip_height);
    depth_key(tip_height - depth)
}

fn make_write_batch(prefix: &str, count: u32) -> (Vec<String>, Vec<MARFValue>) {
    make_batch(prefix, 0, count, 0)
}

fn make_fixture(cache_strategy: &str, chain_len: u32) -> MarfApiFixture {
    let tmpdir = tempfile::tempdir().expect("failed to create temp dir for marf_api fixture");
    let db_path = tmpdir.path().join("marf-api.sqlite");
    let db_path_str = db_path
        .to_str()
        .expect("failed to convert marf_api fixture path to UTF-8")
        .to_string();

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, cache_strategy, true);
    let mut marf =
        MARF::from_path(&db_path_str, open_opts).expect("failed to open MARF for marf_api fixture");

    let mut parent = StacksBlockId::sentinel();
    let mut tip = parent.clone();

    for height in 1..=chain_len {
        let next = block_id(height);

        let mut tx = marf
            .begin_tx()
            .expect("failed to begin tx while building marf_api fixture");
        tx.begin(&parent, &next)
            .expect("failed to begin block extension in marf_api fixture");

        let mut keys = Vec::with_capacity(KEYS_PER_BLOCK as usize);
        let mut values = Vec::with_capacity(KEYS_PER_BLOCK as usize);

        keys.push(depth_key(height));
        values.push(MARFValue::from(height));

        for noise_ix in 0..(KEYS_PER_BLOCK - 1) {
            keys.push(format!("noise:{height:08x}:{noise_ix:02x}"));
            values.push(MARFValue::from(
                height.wrapping_mul(97).wrapping_add(noise_ix + 1),
            ));
        }

        tx.insert_batch(&keys, values)
            .expect("failed to insert fixture keys");
        tx.commit()
            .expect("failed to commit block while building marf_api fixture");

        parent = next.clone();
        tip = next;
    }

    MarfApiFixture {
        _tmpdir: tmpdir,
        marf,
        tip,
        tip_height: chain_len,
    }
}

fn build_root_to_block_map(
    marf: &mut MARF<StacksBlockId>,
    tip: &StacksBlockId,
) -> HashMap<TrieHash, StacksBlockId> {
    let tip_height = marf
        .get_block_height(tip, tip)
        .expect("failed to get tip height for root map")
        .expect("tip height unexpectedly missing");

    let mut root_to_block = HashMap::with_capacity((tip_height + 1) as usize);
    for height in 0..=tip_height {
        let block = marf
            .get_block_at_height(height, tip)
            .expect("failed to get block at height for root map")
            .expect("block at height unexpectedly missing while building root map");
        let root_hash = marf
            .get_root_hash_at(&block)
            .expect("failed to get root hash while building root map");
        root_to_block.insert(root_hash, block);
    }

    root_to_block
}

fn bench_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("marf_api/get");

    for strategy in CACHE_STRATEGIES {
        for depth in DEPTHS {
            let mut fixture = make_fixture(strategy, CHAIN_LEN);
            let key = key_for_depth_from_tip(fixture.tip_height, depth);

            group.bench_function(format!("{strategy}/existing_tip/depth_{depth}"), move |b| {
                b.iter(|| {
                    let out = fixture
                        .marf
                        .get(&fixture.tip, &key)
                        .expect("marf_api/get existing query failed");
                    black_box(out);
                });
            });
        }

        {
            let mut fixture = make_fixture(strategy, CHAIN_LEN);
            let key = "missing:00000000".to_string();
            group.bench_function(format!("{strategy}/missing_tip"), move |b| {
                b.iter(|| {
                    let out = fixture
                        .marf
                        .get(&fixture.tip, &key)
                        .expect("marf_api/get missing query failed");
                    black_box(out);
                });
            });
        }
    }

    group.finish();
}

fn bench_get_backptr_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("marf_api/get_backptr_heavy");

    for strategy in CACHE_STRATEGIES {
        for depth in BACKPTR_DEPTHS {
            let mut fixture = make_fixture(strategy, BACKPTR_CHAIN_LEN);
            let key = key_for_depth_from_tip(fixture.tip_height, depth);

            group.bench_function(format!("{strategy}/depth_{depth}"), move |b| {
                b.iter(|| {
                    let out = fixture
                        .marf
                        .get(&fixture.tip, &key)
                        .expect("marf_api/get_backptr_heavy query failed");
                    black_box(out);
                });
            });
        }
    }

    group.finish();
}

fn bench_get_with_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("marf_api/get_with_proof");

    for strategy in CACHE_STRATEGIES {
        for depth in DEPTHS {
            let mut fixture = make_fixture(strategy, CHAIN_LEN);
            let key = key_for_depth_from_tip(fixture.tip_height, depth);

            group.bench_function(format!("{strategy}/existing_tip/depth_{depth}"), move |b| {
                b.iter(|| {
                    let out = fixture
                        .marf
                        .get_with_proof(&fixture.tip, &key)
                        .expect("marf_api/get_with_proof query failed");
                    black_box(out);
                });
            });
        }
    }

    group.finish();
}

fn bench_proof_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("marf_api/proof_verify");

    for strategy in CACHE_STRATEGIES {
        for depth in DEPTHS {
            let mut fixture = make_fixture(strategy, CHAIN_LEN);
            let key = key_for_depth_from_tip(fixture.tip_height, depth);
            let path = TrieHash::from_key(&key);
            let root_hash = fixture
                .marf
                .get_root_hash_at(&fixture.tip)
                .expect("failed to get tip root hash for verify bench");
            let root_to_block = build_root_to_block_map(&mut fixture.marf, &fixture.tip);

            let (value, proof): (MARFValue, TrieMerkleProof<StacksBlockId>) = fixture
                .marf
                .get_with_proof(&fixture.tip, &key)
                .expect("failed to generate proof for verify bench")
                .expect("expected value/proof pair for verify bench");

            assert!(proof.verify(&path, &value, &root_hash, &root_to_block));

            group.bench_function(format!("{strategy}/depth_{depth}"), move |b| {
                b.iter(|| {
                    let out = proof.verify(&path, &value, &root_hash, &root_to_block);
                    black_box(out);
                });
            });
        }
    }

    group.finish();
}

fn bench_insert_batch_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("marf_api/insert_batch_commit");

    for strategy in CACHE_STRATEGIES {
        let (keys, value_template) = make_write_batch("write", INSERT_BATCH_SIZE);
        let next_block_seed = 10_000_000u32;

        group.bench_function(format!("{strategy}/batch_{INSERT_BATCH_SIZE}"), move |b| {
            b.iter_batched(
                || make_fixture(strategy, CHAIN_LEN),
                |mut fixture| {
                    let parent = fixture.tip.clone();
                    let next = block_id(next_block_seed);

                    let mut values = value_template.clone();
                    values[0] = MARFValue::from(next_block_seed.wrapping_add(1));

                    let mut tx = fixture
                        .marf
                        .begin_tx()
                        .expect("failed to start marf_api insert tx");
                    tx.begin(&parent, &next)
                        .expect("failed to begin marf_api insert extension");
                    tx.insert_batch(&keys, values)
                        .expect("failed to insert marf_api write batch");
                    let root_hash = tx.seal().expect("failed to seal marf_api write batch");
                    black_box(root_hash);
                    tx.commit().expect("failed to commit marf_api write batch");

                    fixture.tip = next;
                    fixture.tip_height = fixture.tip_height.wrapping_add(1);
                    black_box((&fixture.tip, fixture.tip_height));
                },
                BatchSize::PerIteration,
            );
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = configured_criterion();
    targets =
        bench_get,
        bench_get_backptr_heavy,
        bench_get_with_proof,
        bench_proof_verify,
        bench_insert_batch_commit
}
