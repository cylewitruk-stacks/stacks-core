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
use criterion::{criterion_group, Criterion};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use tempfile::TempDir;

use super::common::{block_id, configured_criterion};

const CHAIN_LEN: u32 = 192;
const DEPTHS: [u32; 3] = [1, 8, 64];
const KEYS_PER_BLOCK: u32 = 4;
const CACHE_STRATEGIES: [&str; 2] = ["noop", "everything"];

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

criterion_group! {
    name = benches;
    config = configured_criterion();
    targets = bench_proof_verify
}
