// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use stacks_common::types::chainstate::StacksBlockId;

use crate::chainstate::stacks::index::marf::{
    MARFOpenOpts, MarfConnection, BLOCK_HASH_TO_HEIGHT_MAPPING_KEY,
    BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, MARF, OWN_BLOCK_HEIGHT_KEY,
};
use crate::chainstate::stacks::index::node::{
    clear_backptr, TrieLeafSquashed, TrieNode, TrieNodeID, TrieNodeType,
};
use crate::chainstate::stacks::index::squash::{
    collect_history, squash_to_path, SquashInfo, SquashMode, SquashTrailer, SQUASH_FOOTER_SIZE,
};
use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
use crate::chainstate::stacks::index::{bits, ClarityMarfTrieId, MARFValue};
use crate::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};

/// Create a fresh, unique test directory immune to the `$TMPDIR` race caused
/// by `post_migrate_vacuum` (which temporarily mutates `$TMPDIR` to the DB's
/// parent directory during SQLite VACUUM). Using a fixed base path avoids
/// inheriting the mutated `$TMPDIR` that `tempfile::tempdir()` would use.
fn fresh_test_dir(test_name: &str) -> String {
    let dir = format!("/tmp/stacks-squash-tests/{test_name}");
    if std::fs::metadata(&dir).is_ok() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// Test 1: TrieLeafSquashed serialization round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_leaf_squashed_serialization() {
    let path_bytes = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    let entries = vec![
        (100, MARFValue([0xAAu8; 40])),
        (50, MARFValue([0xBBu8; 40])),
        (10, MARFValue([0xCCu8; 40])),
    ];

    let original = TrieLeafSquashed::new(&path_bytes, entries).unwrap();

    // Serialize
    let mut buf = Vec::new();
    original
        .write_bytes(&mut buf)
        .expect("write_bytes should succeed");

    // Verify serialized length matches byte_len()
    assert_eq!(
        buf.len(),
        original.byte_len(),
        "serialized length should match byte_len()"
    );

    // Deserialize
    let mut deserialized = TrieLeafSquashed::empty();
    let consumed = deserialized
        .load_from_slice(&buf)
        .expect("load_from_slice should succeed");

    assert_eq!(
        consumed,
        buf.len(),
        "load_from_slice should consume exactly the serialized bytes"
    );

    // Verify equality
    assert_eq!(
        original, deserialized,
        "round-tripped TrieLeafSquashed should equal original"
    );

    // Verify the ID byte is correct
    assert_eq!(buf[0], TrieNodeID::LeafSquashed as u8);

    // Verify individual entries survived the round-trip
    assert_eq!(deserialized.entries.len(), 3);
    assert_eq!(deserialized.entries[0].0, 100);
    assert_eq!(deserialized.entries[0].1, MARFValue([0xAAu8; 40]));
    assert_eq!(deserialized.entries[1].0, 50);
    assert_eq!(deserialized.entries[1].1, MARFValue([0xBBu8; 40]));
    assert_eq!(deserialized.entries[2].0, 10);
    assert_eq!(deserialized.entries[2].1, MARFValue([0xCCu8; 40]));
}

#[test]
fn test_leaf_squashed_serialization_single_entry() {
    let path_bytes = [0xFFu8; 32];
    let entries = vec![(42, MARFValue([0x11u8; 40]))];
    let original = TrieLeafSquashed::new(&path_bytes, entries).unwrap();

    let mut buf = Vec::new();
    original.write_bytes(&mut buf).unwrap();

    let mut deserialized = TrieLeafSquashed::empty();
    let consumed = deserialized.load_from_slice(&buf).unwrap();

    assert_eq!(consumed, buf.len());
    assert_eq!(original, deserialized);
}

// ---------------------------------------------------------------------------
// Test 2: value_at_height lookup
// ---------------------------------------------------------------------------

#[test]
fn test_value_at_height() {
    // Entries sorted descending by height (as required by TrieLeafSquashed).
    let entries = vec![
        (100, MARFValue([0xAAu8; 40])), // tip
        (50, MARFValue([0xBBu8; 40])),
        (10, MARFValue([0xCCu8; 40])),
    ];

    let leaf = TrieLeafSquashed::new(&[0u8; 32], entries).unwrap();

    // At or after the tip height -> tip value
    assert_eq!(
        leaf.value_at_height(100),
        Some(&MARFValue([0xAAu8; 40])),
        "height 100 should return tip value"
    );
    assert_eq!(
        leaf.value_at_height(200),
        Some(&MARFValue([0xAAu8; 40])),
        "height 200 (above tip) should return tip value"
    );

    // Between 50 and 100 -> value at height 50
    assert_eq!(
        leaf.value_at_height(99),
        Some(&MARFValue([0xBBu8; 40])),
        "height 99 should return value at height 50"
    );
    assert_eq!(
        leaf.value_at_height(50),
        Some(&MARFValue([0xBBu8; 40])),
        "height 50 should return value at height 50"
    );
    assert_eq!(
        leaf.value_at_height(75),
        Some(&MARFValue([0xBBu8; 40])),
        "height 75 should return value at height 50"
    );

    // Between 10 and 50 -> value at height 10
    assert_eq!(
        leaf.value_at_height(49),
        Some(&MARFValue([0xCCu8; 40])),
        "height 49 should return value at height 10"
    );
    assert_eq!(
        leaf.value_at_height(10),
        Some(&MARFValue([0xCCu8; 40])),
        "height 10 should return value at height 10"
    );
    assert_eq!(
        leaf.value_at_height(30),
        Some(&MARFValue([0xCCu8; 40])),
        "height 30 should return value at height 10"
    );

    // Before the earliest entry -> None
    assert_eq!(
        leaf.value_at_height(9),
        None,
        "height 9 should return None (before earliest entry)"
    );
    assert_eq!(
        leaf.value_at_height(0),
        None,
        "height 0 should return None (before earliest entry)"
    );
}

#[test]
fn test_value_at_height_single_entry() {
    let entries = vec![(0, MARFValue([0x11u8; 40]))];
    let leaf = TrieLeafSquashed::new(&[0u8; 32], entries).unwrap();

    // At height 0 -> the value
    assert_eq!(leaf.value_at_height(0), Some(&MARFValue([0x11u8; 40])));

    // Above height 0 -> the value (latest transition at or before)
    assert_eq!(leaf.value_at_height(999), Some(&MARFValue([0x11u8; 40])));
}

#[test]
fn test_tip_value() {
    let entries = vec![
        (100, MARFValue([0xAAu8; 40])),
        (50, MARFValue([0xBBu8; 40])),
    ];
    let leaf = TrieLeafSquashed::new(&[0u8; 32], entries).unwrap();

    assert_eq!(
        leaf.tip_value().unwrap(),
        &MARFValue([0xAAu8; 40]),
        "tip_value() should return entries[0]"
    );
}

// ---------------------------------------------------------------------------
// Test 3: SquashTrailer serialization round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_trailer_serialization() {
    let root_hashes = vec![
        TrieHash([0x01u8; 32]),
        TrieHash([0x02u8; 32]),
        TrieHash([0x03u8; 32]),
    ];
    let block_hashes: Vec<[u8; 32]> = vec![[0xA1u8; 32], [0xA2u8; 32], [0xA3u8; 32]];

    // Build sorted entries
    let mut sorted_block_entries: Vec<([u8; 32], u32)> = block_hashes
        .iter()
        .enumerate()
        .map(|(i, bhh)| (*bhh, i as u32))
        .collect();
    sorted_block_entries.sort_by_key(|(bhh, _)| *bhh);

    let trailer = SquashTrailer {
        info: SquashInfo {
            mode: SquashMode::TipOnly,
            level_id: 0,
            min_height: 0,
            max_height: 2,
            archival_root: TrieHash([0xFFu8; 32]),
            squash_root: TrieHash([0xEEu8; 32]),
        },
        root_hashes: root_hashes.clone(),
        block_hashes: block_hashes.clone(),
        sorted_block_entries: sorted_block_entries.clone(),
    };

    // Serialize the trailer body
    let mut buf = Vec::new();
    let body_len = trailer.write_to(&mut buf).expect("write_to should succeed");
    assert!(body_len > 0, "trailer body should be non-empty");
    assert_eq!(buf.len(), body_len as usize);

    // Append footer (simulating a real blob layout)
    let trailer_offset = 1000u64; // arbitrary blob offset
    SquashTrailer::write_footer(&mut buf, trailer_offset).expect("write_footer should succeed");

    // Read footer back from the combined buffer
    // For footer reading, we need the last SQUASH_FOOTER_SIZE bytes
    let full_blob_len = 1000 + buf.len(); // pretend there are 1000 bytes of blob before
    let mut full_blob = vec![0u8; 1000];
    full_blob.extend_from_slice(&buf);

    let read_offset = SquashTrailer::read_footer(&full_blob);
    assert_eq!(
        read_offset,
        Some(trailer_offset),
        "read_footer should return the original trailer offset"
    );

    // Deserialize the trailer body
    let trailer_bytes = &full_blob[trailer_offset as usize..full_blob.len() - SQUASH_FOOTER_SIZE];
    let deserialized = SquashTrailer::read_from(trailer_bytes).expect("read_from should succeed");

    // Verify SquashInfo fields
    assert_eq!(deserialized.info.mode, SquashMode::TipOnly);
    assert_eq!(deserialized.info.level_id, 0);
    assert_eq!(deserialized.info.min_height, 0);
    assert_eq!(deserialized.info.max_height, 2);
    assert_eq!(deserialized.info.archival_root, TrieHash([0xFFu8; 32]));
    assert_eq!(deserialized.info.squash_root, TrieHash([0xEEu8; 32]));

    // Verify height_count
    assert_eq!(
        deserialized.info.height_count(),
        3,
        "height_count should be max_height - min_height + 1"
    );

    // Verify root hashes
    assert_eq!(deserialized.root_hashes, root_hashes);

    // Verify block hashes
    assert_eq!(deserialized.block_hashes, block_hashes);

    // Verify sorted block entries
    assert_eq!(deserialized.sorted_block_entries, sorted_block_entries);

    // Verify O(1) lookups
    assert_eq!(deserialized.root_hash_at(0), Some(&TrieHash([0x01u8; 32])));
    assert_eq!(deserialized.root_hash_at(1), Some(&TrieHash([0x02u8; 32])));
    assert_eq!(deserialized.root_hash_at(2), Some(&TrieHash([0x03u8; 32])));
    assert_eq!(deserialized.root_hash_at(3), None, "out of range");

    assert_eq!(deserialized.block_hash_at(0), Some(&[0xA1u8; 32]));
    assert_eq!(deserialized.block_hash_at(2), Some(&[0xA3u8; 32]));
    assert_eq!(deserialized.block_hash_at(3), None);

    // Verify contains_height
    assert!(deserialized.contains_height(0));
    assert!(deserialized.contains_height(1));
    assert!(deserialized.contains_height(2));
    assert!(!deserialized.contains_height(3));

    // Verify O(log N) block hash -> height lookup
    assert_eq!(deserialized.height_of_block(&[0xA1u8; 32]), Some(0));
    assert_eq!(deserialized.height_of_block(&[0xA2u8; 32]), Some(1));
    assert_eq!(deserialized.height_of_block(&[0xA3u8; 32]), Some(2));
    assert_eq!(
        deserialized.height_of_block(&[0x00u8; 32]),
        None,
        "non-existent block hash"
    );
}

#[test]
fn test_trailer_serialization_full_history_mode() {
    let trailer = SquashTrailer {
        info: SquashInfo {
            mode: SquashMode::FullHistory,
            level_id: 7,
            min_height: 100,
            max_height: 105,
            archival_root: TrieHash([0x11u8; 32]),
            squash_root: TrieHash([0x22u8; 32]),
        },
        root_hashes: (100..=105).map(|i| TrieHash([i as u8; 32])).collect(),
        block_hashes: (100..=105).map(|i| [i as u8; 32]).collect(),
        sorted_block_entries: {
            let mut entries: Vec<([u8; 32], u32)> =
                (100..=105).map(|i| ([i as u8; 32], i)).collect();
            entries.sort_by_key(|(bhh, _)| *bhh);
            entries
        },
    };

    let mut buf = Vec::new();
    trailer.write_to(&mut buf).unwrap();

    let deserialized = SquashTrailer::read_from(&buf).unwrap();
    assert_eq!(deserialized.info.mode, SquashMode::FullHistory);
    assert_eq!(deserialized.info.level_id, 7);
    assert_eq!(deserialized.info.min_height, 100);
    assert_eq!(deserialized.info.max_height, 105);
    assert_eq!(deserialized.info.height_count(), 6);
    assert_eq!(deserialized.root_hashes.len(), 6);
    assert_eq!(deserialized.block_hashes.len(), 6);
    assert_eq!(deserialized.sorted_block_entries.len(), 6);
}

#[test]
fn test_trailer_footer_not_present() {
    // An empty buffer has no footer
    assert_eq!(SquashTrailer::read_footer(&[]), None);

    // A buffer shorter than SQUASH_FOOTER_SIZE has no footer
    assert_eq!(SquashTrailer::read_footer(&[0u8; 4]), None);

    // A buffer of the right size but wrong magic has no footer
    let mut fake_footer = vec![0u8; SQUASH_FOOTER_SIZE];
    fake_footer[8..12].copy_from_slice(b"NOPE");
    assert_eq!(SquashTrailer::read_footer(&fake_footer), None);
}

#[test]
fn test_squash_mode_from_u8() {
    assert_eq!(SquashMode::from_u8(0), Some(SquashMode::TipOnly));
    assert_eq!(SquashMode::from_u8(1), Some(SquashMode::FullHistory));
    assert_eq!(SquashMode::from_u8(2), None);
    assert_eq!(SquashMode::from_u8(255), None);
}

// ---------------------------------------------------------------------------
// Test 4: squash_to_path integration test (base level, TipOnly)
// ---------------------------------------------------------------------------

/// Helper: create a file-backed MARF with a chain of blocks, each inserting
/// a few key-value pairs. Returns the MARF, the list of block hashes, and
/// the expected (key -> value) state at the tip.
fn setup_squash_source_marf(
    path: &str,
    num_blocks: usize,
    keys_per_block: usize,
) -> (
    MARF<StacksBlockId>,
    Vec<StacksBlockId>,
    HashMap<String, MARFValue>,
) {
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(path, open_opts).unwrap();

    assert!(num_blocks > 0, "need at least one block");

    // Generate unique block hashes
    let blocks: Vec<StacksBlockId> = (0..num_blocks)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    let mut expected_tip_state: HashMap<String, MARFValue> = HashMap::new();

    // Block at height 0
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();

    // Insert initial keys at block 0
    for j in 0..keys_per_block {
        let key = format!("key_{j}");
        let val = MARFValue::from_value(&format!("val_{j}_at_0"));
        marf.insert(&key, val.clone()).unwrap();
        expected_tip_state.insert(key, val);
    }

    // Also insert a "shared_key" that will be updated every block
    let shared_val = MARFValue::from_value("shared_at_0");
    marf.insert("shared_key", shared_val.clone()).unwrap();
    expected_tip_state.insert("shared_key".to_string(), shared_val);

    marf.seal().unwrap();
    marf.commit().unwrap();

    // Subsequent blocks
    for i in 1..num_blocks {
        marf.begin(&blocks[i - 1], &blocks[i]).unwrap();

        // Insert new keys unique to this block
        for j in 0..keys_per_block {
            let key_index = i * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{i}"));
            marf.insert(&key, val.clone()).unwrap();
            expected_tip_state.insert(key, val);
        }

        // Update shared_key at every block
        let shared_val = MARFValue::from_value(&format!("shared_at_{i}"));
        marf.insert("shared_key", shared_val.clone()).unwrap();
        expected_tip_state.insert("shared_key".to_string(), shared_val);

        marf.seal().unwrap();
        marf.commit().unwrap();
    }

    (marf, blocks, expected_tip_state)
}

#[test]
fn test_squash_base_level_tip_only() {
    let test_dir = fresh_test_dir("test_squash_base_level_tip_only");

    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let num_blocks = 5;
    let keys_per_block = 3;

    // Build the source MARF
    let (src_marf, blocks, expected_tip_state) =
        setup_squash_source_marf(&src_path, num_blocks, keys_per_block);
    drop(src_marf);

    let max_height = (num_blocks - 1) as u32;

    // Run the squash pipeline
    let stats =
        squash_to_path::<StacksBlockId>(&src_path, &dst_path, SquashMode::TipOnly, max_height)
            .expect("squash_to_path should succeed");

    // Basic stats sanity
    assert!(
        stats.nodes_collected > 0,
        "should have collected some nodes"
    );
    assert!(
        stats.leaves_collected > 0,
        "should have collected some leaves"
    );
    assert!(stats.blob_bytes > 0, "blob should be non-empty");
    assert!(stats.trailer_bytes > 0, "trailer should be non-empty");

    // Open the destination MARF and verify all tip-state keys are readable
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    let tip_block = &blocks[num_blocks - 1];

    for (key, expected_value) in &expected_tip_state {
        let result = dst_marf
            .get(tip_block, key)
            .unwrap_or_else(|e| panic!("Failed to get key '{key}' from squashed MARF: {e}"));
        assert_eq!(
            result,
            Some(expected_value.clone()),
            "key '{key}' should have the expected value in squashed MARF"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 5: incremental squash (Level 0 + Level 1, TipOnly)
// ---------------------------------------------------------------------------

#[test]
fn test_squash_incremental_basic() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let test_dir = fresh_test_dir("test_squash_incremental_basic");

    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let l0_blocks = 5;
    let l1_blocks = 5;
    let keys_per_block = 3;

    // Phase 1: Build source MARF with blocks 0..=4 and squash to Level 0
    let (src_marf, blocks_l0, _) = setup_squash_source_marf(&src_path, l0_blocks, keys_per_block);
    drop(src_marf);

    let l0_max = (l0_blocks - 1) as u32;
    let l0_stats =
        squash_to_path::<StacksBlockId>(&src_path, &dst_path, SquashMode::TipOnly, l0_max)
            .expect("Level 0 squash should succeed");
    assert!(l0_stats.nodes_collected > 0);

    // Phase 2: Open the squashed MARF and commit more blocks (5..=9)
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    let mut blocks_l1: Vec<StacksBlockId> = Vec::new();
    let mut expected_tip_state: HashMap<String, MARFValue> = HashMap::new();

    // First, collect all existing tip-state keys from Level 0 range
    let l0_tip = &blocks_l0[l0_blocks - 1];
    for j in 0..(l0_blocks * keys_per_block) {
        let key = format!("key_{j}");
        let val = dst_marf.get(l0_tip, &key).unwrap();
        if let Some(v) = val {
            expected_tip_state.insert(key, v);
        }
    }
    // shared_key from Level 0
    if let Some(v) = dst_marf.get(l0_tip, "shared_key").unwrap() {
        expected_tip_state.insert("shared_key".to_string(), v);
    }

    // Commit new blocks on top of Level 0
    let prev_tip = blocks_l0[l0_blocks - 1].clone();
    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((block_num as u32) + 1).to_be_bytes());
        let block_hash = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 { &prev_tip } else { &blocks_l1[i - 1] };
        dst_marf.begin(parent, &block_hash).unwrap();

        // New keys unique to this block
        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            dst_marf.insert(&key, val.clone()).unwrap();
            expected_tip_state.insert(key, val);
        }

        // Update shared_key
        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        dst_marf.insert("shared_key", shared_val.clone()).unwrap();
        expected_tip_state.insert("shared_key".to_string(), shared_val);

        dst_marf.seal().unwrap();
        dst_marf.commit().unwrap();
        blocks_l1.push(block_hash);
    }

    // Close the MARF before incremental squash
    drop(dst_marf);

    // Phase 3: Run incremental squash for blocks 5..=9
    let l1_min = l0_blocks as u32;
    let l1_max = (l0_blocks + l1_blocks - 1) as u32;
    let l1_stats = squash_level_incremental::<StacksBlockId>(
        &dst_path,
        SquashMode::TipOnly,
        l1_min,
        l1_max,
        false,
    )
    .expect("Incremental squash should succeed");

    assert!(
        l1_stats.nodes_collected > 0,
        "should have collected some nodes"
    );
    assert!(
        l1_stats.leaves_collected > 0,
        "should have collected some leaves"
    );

    // Phase 4: Reopen and verify ALL keys are readable at the tip
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    let final_tip = &blocks_l1[l1_blocks - 1];

    for (key, expected_value) in &expected_tip_state {
        let result = dst_marf
            .get(final_tip, key)
            .unwrap_or_else(|e| panic!("Failed to get key '{key}' after incremental squash: {e}"));
        assert_eq!(
            result,
            Some(expected_value.clone()),
            "key '{key}' should have the expected value after incremental squash"
        );
    }

    // Verify both levels are registered
    let levels =
        crate::chainstate::stacks::index::trie_sql::read_squash_levels(dst_marf.sqlite_conn())
            .unwrap();
    assert_eq!(levels.len(), 2, "should have 2 squash levels");
    assert_eq!(levels[0].level_id, 0);
    assert_eq!(levels[0].min_height, 0);
    assert_eq!(levels[0].max_height, l0_max);
    assert_eq!(levels[1].level_id, 1);
    assert_eq!(levels[1].min_height, l1_min);
    assert_eq!(levels[1].max_height, l1_max);
}

// ---------------------------------------------------------------------------
// Test 6: cross-level reads and proof gating after incremental squash
// ---------------------------------------------------------------------------

#[test]
fn test_squash_incremental_cross_level_reads_and_proofs() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;
    use crate::chainstate::stacks::index::Error;

    let test_dir = fresh_test_dir("test_squash_incremental_cross_level_reads_and_proofs");

    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let l0_blocks = 3;
    let l1_blocks = 3;
    let keys_per_block = 2;

    // Build source, squash Level 0
    let (src_marf, blocks_l0, _) = setup_squash_source_marf(&src_path, l0_blocks, keys_per_block);
    drop(src_marf);

    let l0_max = (l0_blocks - 1) as u32;
    squash_to_path::<StacksBlockId>(&src_path, &dst_path, SquashMode::TipOnly, l0_max)
        .expect("Level 0 squash");

    // Commit Level 1 blocks
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    let mut blocks_l1: Vec<StacksBlockId> = Vec::new();
    let prev_tip = blocks_l0[l0_blocks - 1].clone();
    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((block_num as u32) + 1).to_be_bytes());
        let block_hash = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 { &prev_tip } else { &blocks_l1[i - 1] };
        dst_marf.begin(parent, &block_hash).unwrap();

        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            dst_marf.insert(&key, val).unwrap();
        }
        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        dst_marf.insert("shared_key", shared_val).unwrap();

        dst_marf.seal().unwrap();
        dst_marf.commit().unwrap();
        blocks_l1.push(block_hash);
    }
    drop(dst_marf);

    // Incremental squash Level 1
    let l1_min = l0_blocks as u32;
    let l1_max = (l0_blocks + l1_blocks - 1) as u32;
    squash_level_incremental::<StacksBlockId>(
        &dst_path,
        SquashMode::TipOnly,
        l1_min,
        l1_max,
        false,
    )
    .expect("Level 1 squash");

    // Reopen and test
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    // --- Historical reads within Level 0 range ---
    let l0_block_0 = &blocks_l0[0];
    let result = dst_marf.get(l0_block_0, "key_0").unwrap();
    assert!(
        result.is_some(),
        "key_0 should be readable at block 0 (Level 0 range)"
    );

    let l0_block_1 = &blocks_l0[1];
    let result = dst_marf.get(l0_block_1, "shared_key").unwrap();
    assert!(
        result.is_some(),
        "shared_key should be readable at block 1 (Level 0 range)"
    );

    // --- Historical reads within Level 1 range ---
    let l1_block_0 = &blocks_l1[0];
    let result = dst_marf.get(l1_block_0, "shared_key").unwrap();
    assert!(
        result.is_some(),
        "shared_key should be readable at first Level 1 block"
    );

    // A key from Level 0 should still be readable via Level 1 tip
    let l1_tip = &blocks_l1[l1_blocks - 1];
    let result = dst_marf.get(l1_tip, "key_0").unwrap();
    assert!(
        result.is_some(),
        "key_0 (from Level 0) should be readable at Level 1 tip"
    );

    // --- Proof gating: proofs should error for blocks in either squash range ---
    let proof_result = dst_marf.get_with_proof(l0_block_0, "key_0");
    match proof_result {
        Err(Error::NotSupportedError(_)) => {}
        other => panic!("Expected NotSupportedError for proof in Level 0 range, got: {other:?}"),
    }

    let proof_result = dst_marf.get_with_proof(l1_block_0, "shared_key");
    match proof_result {
        Err(Error::NotSupportedError(_)) => {}
        other => panic!("Expected NotSupportedError for proof in Level 1 range, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 7: post-incremental-squash COW extension
// ---------------------------------------------------------------------------

#[test]
fn test_squash_post_incremental_extension() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let test_dir = fresh_test_dir("test_squash_post_incremental_extension");

    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let l0_blocks = 3;
    let l1_blocks = 3;
    let keys_per_block = 2;

    // Build source, squash Level 0
    let (src_marf, blocks_l0, _) = setup_squash_source_marf(&src_path, l0_blocks, keys_per_block);
    drop(src_marf);

    let l0_max = (l0_blocks - 1) as u32;
    squash_to_path::<StacksBlockId>(&src_path, &dst_path, SquashMode::TipOnly, l0_max)
        .expect("Level 0 squash");

    // Commit Level 1 blocks and squash
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    let mut blocks_l1: Vec<StacksBlockId> = Vec::new();
    let prev_tip = blocks_l0[l0_blocks - 1].clone();
    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((block_num as u32) + 1).to_be_bytes());
        let block_hash = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 { &prev_tip } else { &blocks_l1[i - 1] };
        dst_marf.begin(parent, &block_hash).unwrap();
        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            dst_marf.insert(&key, val).unwrap();
        }
        dst_marf.seal().unwrap();
        dst_marf.commit().unwrap();
        blocks_l1.push(block_hash);
    }
    drop(dst_marf);

    let l1_min = l0_blocks as u32;
    let l1_max = (l0_blocks + l1_blocks - 1) as u32;
    squash_level_incremental::<StacksBlockId>(
        &dst_path,
        SquashMode::TipOnly,
        l1_min,
        l1_max,
        false,
    )
    .expect("Level 1 squash");

    // Commit NEW blocks AFTER both squash levels (post-squash extension via COW)
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    let l1_tip = blocks_l1[l1_blocks - 1].clone();
    let ext_blocks = 3;
    let mut ext_block_hashes: Vec<StacksBlockId> = Vec::new();
    let mut expected_ext_state: HashMap<String, MARFValue> = HashMap::new();

    for i in 0..ext_blocks {
        let block_num = l0_blocks + l1_blocks + i;
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((block_num as u32) + 1).to_be_bytes());
        let block_hash = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 {
            &l1_tip
        } else {
            &ext_block_hashes[i - 1]
        };
        dst_marf.begin(parent, &block_hash).unwrap();

        let key = format!("ext_key_{block_num}");
        let val = MARFValue::from_value(&format!("ext_val_{block_num}"));
        dst_marf.insert(&key, val.clone()).unwrap();
        expected_ext_state.insert(key, val);

        let shared_val = MARFValue::from_value(&format!("shared_ext_{block_num}"));
        dst_marf.insert("shared_key", shared_val.clone()).unwrap();
        expected_ext_state.insert("shared_key".to_string(), shared_val);

        dst_marf.seal().unwrap();
        dst_marf.commit().unwrap();
        ext_block_hashes.push(block_hash);
    }

    let ext_tip = &ext_block_hashes[ext_blocks - 1];

    // Verify all extension keys
    for (key, expected_value) in &expected_ext_state {
        let result = dst_marf
            .get(ext_tip, key)
            .unwrap_or_else(|e| panic!("Failed to get ext key '{key}': {e}"));
        assert_eq!(
            result,
            Some(expected_value.clone()),
            "ext key '{key}' should be correct at extension tip"
        );
    }

    // Verify Level 0 keys are still readable via cross-level backptrs
    let result = dst_marf.get(ext_tip, "key_0").unwrap();
    assert!(
        result.is_some(),
        "key_0 (Level 0) should be readable at extension tip"
    );
}

// ---------------------------------------------------------------------------
// Test 8: incremental squash with reclaim (dead blob space reclamation)
// ---------------------------------------------------------------------------

#[test]
fn test_squash_incremental_reclaim() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let test_dir = fresh_test_dir("test_squash_incremental_reclaim");

    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let l0_blocks = 5;
    let l1_blocks = 5;
    let keys_per_block = 3;

    // Phase 1: Build source MARF and squash to Level 0
    let (src_marf, blocks_l0, _) = setup_squash_source_marf(&src_path, l0_blocks, keys_per_block);
    drop(src_marf);

    let l0_max = (l0_blocks - 1) as u32;
    squash_to_path::<StacksBlockId>(&src_path, &dst_path, SquashMode::TipOnly, l0_max)
        .expect("Level 0 squash");

    // Phase 2: Commit more blocks (5..=9) on the squashed MARF
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    let mut blocks_l1: Vec<StacksBlockId> = Vec::new();
    let mut expected_tip_state: HashMap<String, MARFValue> = HashMap::new();

    // Collect existing tip state from Level 0
    let l0_tip = &blocks_l0[l0_blocks - 1];
    for j in 0..(l0_blocks * keys_per_block) {
        let key = format!("key_{j}");
        if let Some(v) = dst_marf.get(l0_tip, &key).unwrap() {
            expected_tip_state.insert(key, v);
        }
    }
    if let Some(v) = dst_marf.get(l0_tip, "shared_key").unwrap() {
        expected_tip_state.insert("shared_key".to_string(), v);
    }

    let prev_tip = blocks_l0[l0_blocks - 1].clone();
    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((block_num as u32) + 1).to_be_bytes());
        let block_hash = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 { &prev_tip } else { &blocks_l1[i - 1] };
        dst_marf.begin(parent, &block_hash).unwrap();

        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            dst_marf.insert(&key, val.clone()).unwrap();
            expected_tip_state.insert(key, val);
        }

        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        dst_marf.insert("shared_key", shared_val.clone()).unwrap();
        expected_tip_state.insert("shared_key".to_string(), shared_val);

        dst_marf.seal().unwrap();
        dst_marf.commit().unwrap();
        blocks_l1.push(block_hash);
    }
    drop(dst_marf);

    // Record blob file size BEFORE reclaim
    let blobs_path = format!("{dst_path}.blobs");
    let size_before = std::fs::metadata(&blobs_path)
        .expect("blobs file should exist")
        .len();

    // Phase 3: Incremental squash WITH reclaim
    let l1_min = l0_blocks as u32;
    let l1_max = (l0_blocks + l1_blocks - 1) as u32;
    let l1_stats = squash_level_incremental::<StacksBlockId>(
        &dst_path,
        SquashMode::TipOnly,
        l1_min,
        l1_max,
        true, // reclaim!
    )
    .expect("Incremental squash with reclaim should succeed");

    assert!(l1_stats.nodes_collected > 0);

    // Verify blob file shrank (dead per-block blobs were reclaimed)
    let size_after = std::fs::metadata(&blobs_path)
        .expect("blobs file should exist after reclaim")
        .len();
    assert!(
        size_after < size_before,
        "Blob file should have shrunk after reclaim: before={size_before}, after={size_after}"
    );

    // Phase 4: Reopen and verify ALL keys are readable at the tip
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();
    let final_tip = &blocks_l1[l1_blocks - 1];

    for (key, expected_value) in &expected_tip_state {
        let result = dst_marf
            .get(final_tip, key)
            .unwrap_or_else(|e| panic!("Failed to get key '{key}' after reclaim squash: {e}"));
        assert_eq!(
            result,
            Some(expected_value.clone()),
            "key '{key}' should have expected value after reclaim squash"
        );
    }

    // Verify both squash levels are registered with correct offsets
    let levels =
        crate::chainstate::stacks::index::trie_sql::read_squash_levels(dst_marf.sqlite_conn())
            .unwrap();
    assert_eq!(levels.len(), 2, "should have 2 squash levels");
    assert_eq!(levels[0].level_id, 0);

    // Level 1 blob should start right after Level 0 (no dead gap)
    let l0_end = levels[0].blob_offset + levels[0].blob_length;
    assert_eq!(
        levels[1].blob_offset, l0_end,
        "Level 1 blob should start at end of Level 0 (no dead space)"
    );

    // Blob file should be exactly L0 + L1 with no waste
    assert_eq!(
        size_after,
        levels[1].blob_offset + levels[1].blob_length,
        "Blob file size should equal end of Level 1 blob"
    );
}

// ---------------------------------------------------------------------------
// Test 9: L0 bootstrap via squash_level_incremental with min_height=0
// ---------------------------------------------------------------------------

#[test]
fn test_squash_incremental_l0_bootstrap() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let num_blocks = 8u32;
    let dir = fresh_test_dir("test_squash_incremental_l0_bootstrap");
    let src_path = format!("{dir}/marf.sqlite");

    // Build a MARF with num_blocks blocks
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();

    let mut block_hashes: Vec<StacksBlockId> = vec![];
    let mut expected_state: std::collections::HashMap<String, MARFValue> =
        std::collections::HashMap::new();

    for i in 0..num_blocks {
        let block_hash = StacksBlockId::from_bytes(&[i as u8; 32]).unwrap();
        let parent = if i == 0 {
            StacksBlockId::sentinel()
        } else {
            block_hashes[i as usize - 1].clone()
        };
        marf.begin(&parent, &block_hash).unwrap();

        let key = format!("key_{i}");
        let val = MARFValue::from_value(&format!("val_{i}"));
        marf.insert(&key, val.clone()).unwrap();
        expected_state.insert(key, val);

        // Shared key to exercise backpointer resolution
        let shared_val = MARFValue::from_value(&format!("shared_{i}"));
        marf.insert("shared", shared_val.clone()).unwrap();
        expected_state.insert("shared".to_string(), shared_val);

        marf.seal().unwrap();
        marf.commit().unwrap();
        block_hashes.push(block_hash);
    }
    drop(marf);

    // L0 bootstrap: squash_level_incremental with min_height=0 (no prior levels)
    let stats = squash_level_incremental::<StacksBlockId>(
        &src_path,
        SquashMode::TipOnly,
        0,
        num_blocks - 1,
        false,
    )
    .unwrap();

    assert!(stats.nodes_collected > 0, "should collect nodes");
    assert!(stats.leaves_collected > 0, "should collect leaves");

    // Reopen and verify all keys at the tip
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();
    let tip = block_hashes[num_blocks as usize - 1].clone();
    for (key, expected_value) in &expected_state {
        let result = marf
            .get(&tip, key)
            .unwrap_or_else(|e| panic!("Failed to get key '{key}' after L0 bootstrap: {e}"));
        assert_eq!(
            result,
            Some(expected_value.clone()),
            "key '{key}' should have correct value after L0 bootstrap"
        );
    }

    // Verify squash level metadata
    let levels =
        crate::chainstate::stacks::index::trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1, "should have exactly 1 squash level (L0)");
    assert_eq!(levels[0].level_id, 0);
    assert_eq!(levels[0].min_height, 0);
    assert_eq!(levels[0].max_height, num_blocks - 1);

    // Now extend with more blocks and do an incremental L1 squash
    let l1_start = num_blocks;
    let l1_count = 4u32;
    for i in 0..l1_count {
        let block_num = l1_start + i;
        let block_hash = StacksBlockId::from_bytes(&[block_num as u8; 32]).unwrap();
        let parent = if i == 0 {
            tip.clone()
        } else {
            block_hashes.last().unwrap().clone()
        };
        marf.begin(&parent, &block_hash).unwrap();
        let key = format!("key_{block_num}");
        let val = MARFValue::from_value(&format!("val_{block_num}"));
        marf.insert(&key, val.clone()).unwrap();
        expected_state.insert(key, val);
        marf.seal().unwrap();
        marf.commit().unwrap();
        block_hashes.push(block_hash);
    }
    drop(marf);

    // L1 incremental squash
    let stats = squash_level_incremental::<StacksBlockId>(
        &src_path,
        SquashMode::TipOnly,
        num_blocks,
        num_blocks + l1_count - 1,
        false,
    )
    .unwrap();
    assert!(stats.nodes_collected > 0);

    // Verify all keys still readable at the new tip
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts).unwrap();
    let new_tip = &block_hashes[block_hashes.len() - 1];
    for (key, expected_value) in &expected_state {
        let result = marf
            .get(new_tip, key)
            .unwrap_or_else(|e| panic!("Failed to get key '{key}' after L1: {e}"));
        assert_eq!(
            result,
            Some(expected_value.clone()),
            "key '{key}' should be correct after L1 on top of L0 bootstrap"
        );
    }

    let levels =
        crate::chainstate::stacks::index::trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 2, "should have 2 levels after L1");
    assert_eq!(levels[1].min_height, num_blocks);
    assert_eq!(levels[1].max_height, num_blocks + l1_count - 1);
}

// ---------------------------------------------------------------------------
// Test 10: refresh_after_squash — live handle sees external squash results
// ---------------------------------------------------------------------------

#[test]
fn test_refresh_after_external_squash() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let num_blocks = 6u32;
    let dir = fresh_test_dir("test_refresh_after_external_squash");
    let marf_path = format!("{dir}/marf.sqlite");

    // Build a MARF with blocks
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts.clone()).unwrap();
    let mut block_hashes: Vec<StacksBlockId> = vec![];

    for i in 0..num_blocks {
        let mut bytes = [0u8; 32];
        bytes[0] = i as u8;
        bytes[1] = 0xAA;
        let block_hash = StacksBlockId::from_bytes(&bytes).unwrap();
        let parent = if i == 0 {
            StacksBlockId::sentinel()
        } else {
            block_hashes[i as usize - 1].clone()
        };
        marf.begin(&parent, &block_hash).unwrap();
        let key = format!("key_{i}");
        let val = MARFValue::from_value(&format!("val_{i}"));
        marf.insert(&key, val).unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
        block_hashes.push(block_hash);
    }

    // Verify: no squash levels before squash
    assert!(
        marf.storage.data.squash_levels.is_empty(),
        "No squash levels before squash"
    );

    // External squash through a SEPARATE handle (simulates what maybe_squash does)
    let stats = squash_level_incremental::<StacksBlockId>(
        &marf_path,
        SquashMode::TipOnly,
        0,
        num_blocks - 1,
        false,
    )
    .unwrap();
    assert!(stats.nodes_collected > 0);

    // The live handle still has stale metadata
    assert!(
        marf.storage.data.squash_levels.is_empty(),
        "Live handle should still have no squash levels (stale)"
    );

    // Refresh the live handle
    marf.refresh_after_squash().unwrap();

    // Now the live handle should see the squash level
    assert_eq!(
        marf.storage.data.squash_levels.len(),
        1,
        "After refresh, should see 1 squash level"
    );
    assert_eq!(
        marf.storage.data.squash_block_index.len(),
        num_blocks as usize,
        "squash_block_index should have all blocks"
    );

    // After refresh, the currently-open block context must have been
    // invalidated (reset to sentinel) so reads re-resolve through
    // squash metadata.
    assert_eq!(
        marf.storage.data.cur_block,
        StacksBlockId::sentinel(),
        "cur_block should be sentinel after refresh (context invalidated)"
    );
    assert!(
        marf.storage.data.cur_block_trie_offset.is_none(),
        "cur_block_trie_offset should be None after refresh"
    );

    // And reads should work through the live handle.
    // The fact that reads succeed *after* cur_block was reset to sentinel
    // proves that open_block re-resolved through the freshly-loaded squash
    // metadata (squash_block_index).
    let tip = &block_hashes[num_blocks as usize - 1];
    for i in 0..num_blocks {
        let key = format!("key_{i}");
        let result = marf.get(tip, &key).unwrap();
        assert!(
            result.is_some(),
            "key '{key}' should be readable through live handle after refresh"
        );
    }
}

/// Verify that per-block root hashes are preserved after squash.
///
/// Before the fix for the squash root-hash bug, all blocks inside a squash level would
/// return the *tip's* root hash (since they all share the same blob). The MARF
/// skip-list (geometric series of ancestor root hashes) relies on each block having its
/// own distinct root hash, so collapsing them causes the next block's sealed root to be
/// wrong — producing a state root mismatch.
///
/// This test:
/// 1. Builds a MARF with 10 blocks (enough for a multi-level skip-list).
/// 2. Records per-block root hashes before squash.
/// 3. Squashes and reopens.
/// 4. Verifies every per-block root hash still matches.
/// 5. Extends with a new block and verifies its root hash matches a reference MARF that
///    was never squashed.
#[test]
fn test_squash_preserves_per_block_root_hashes() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let test_dir = fresh_test_dir("test_squash_preserves_per_block_root_hashes");

    let src_path = format!("{test_dir}/source.sqlite");
    let ref_path = format!("{test_dir}/reference.sqlite");

    let num_blocks: usize = 10;
    let keys_per_block: usize = 3;

    // -- Build source MARF --
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();

    let blocks: Vec<StacksBlockId> = (0..num_blocks)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Block 0
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    for j in 0..keys_per_block {
        let key = format!("key_{j}");
        let val = MARFValue::from_value(&format!("val_{j}_at_0"));
        marf.insert(&key, val).unwrap();
    }
    marf.seal().unwrap();
    marf.commit().unwrap();

    // Blocks 1..N
    for i in 1..num_blocks {
        marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
        for j in 0..keys_per_block {
            let key_index = i * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{i}"));
            marf.insert(&key, val).unwrap();
        }
        // Update a shared key every block so tries diverge
        let shared_val = MARFValue::from_value(&format!("shared_at_{i}"));
        marf.insert("shared_key", shared_val).unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
    }

    // -- Record pre-squash root hashes --
    let mut pre_squash_roots: Vec<TrieHash> = Vec::new();
    for block in &blocks {
        let root = marf.get_root_hash_at(block).unwrap();
        pre_squash_roots.push(root);
    }

    // Verify roots are not all the same (sanity check)
    assert!(
        pre_squash_roots.windows(2).any(|w| w[0] != w[1]),
        "pre-squash root hashes should not all be identical"
    );

    drop(marf);

    // -- Build reference (unsquashed) copy for the extension test --
    std::fs::copy(format!("{src_path}"), format!("{ref_path}")).unwrap();
    std::fs::copy(format!("{src_path}.blobs"), format!("{ref_path}.blobs")).unwrap();

    // -- Squash --
    let tip_height = (num_blocks - 1) as u32;
    squash_level_incremental::<StacksBlockId>(&src_path, SquashMode::TipOnly, 0, tip_height, false)
        .expect("squash should succeed");

    // -- Reopen and verify per-block root hashes --
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();

    for (i, block) in blocks.iter().enumerate() {
        let post_squash_root = marf.get_root_hash_at(block).unwrap();
        assert_eq!(
            post_squash_root, pre_squash_roots[i],
            "root hash for block {i} should match after squash"
        );
    }

    // -- Extend with a new block post-squash --
    let mut ext_bytes = [0u8; 32];
    ext_bytes[28..32].copy_from_slice(&((num_blocks as u32) + 1).to_be_bytes());
    let ext_block = StacksBlockId::from_bytes(&ext_bytes).unwrap();

    let tip = &blocks[num_blocks - 1];
    marf.begin(tip, &ext_block).unwrap();
    let ext_key = "post_squash_key";
    let ext_val = MARFValue::from_value("post_squash_val");
    marf.insert(ext_key, ext_val.clone()).unwrap();
    let squashed_ext_root = marf.seal().unwrap();
    marf.commit().unwrap();

    // -- Do the same extension on the reference (unsquashed) MARF --
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts).unwrap();
    ref_marf.begin(tip, &ext_block).unwrap();
    ref_marf.insert(ext_key, ext_val).unwrap();
    let ref_ext_root = ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();

    // Debug: compare root hashes of all blocks including extension
    eprintln!("--- Root hash comparison ---");
    for (i, block) in blocks.iter().enumerate() {
        let sq = marf.get_root_hash_at(block).unwrap();
        let rf = ref_marf.get_root_hash_at(block).unwrap();
        let marker = if sq == rf { "OK" } else { "MISMATCH" };
        eprintln!("  block {i}: sq={sq} rf={rf} {marker}");
    }
    let sq_ext = marf.get_root_hash_at(&ext_block).unwrap();
    let rf_ext = ref_marf.get_root_hash_at(&ext_block).unwrap();
    eprintln!(
        "  ext block: sq={sq_ext} rf={rf_ext} {}",
        if sq_ext == rf_ext { "OK" } else { "MISMATCH" }
    );

    assert_eq!(
        squashed_ext_root, ref_ext_root,
        "root hash of post-squash extension block must match unsquashed reference"
    );
}

// ---------------------------------------------------------------------------
// Test: COW write whose parent is in a reclaimed L1 squash level.
//
// Reproduces the exact failure mode where `open_block_known_id` is called
// during backpointer traversal on a block whose per-block blob was truncated
// by reclaim.  Without the squash-context restoration in
// `open_block_known_id_impl`, this would panic or produce corrupted reads.
//
// Sequence:
//   1. Build 5 blocks → L0 squash (no reclaim)
//   2. Build 5 more blocks → L1 squash WITH reclaim (truncates old blobs)
//   3. Extend from the L1 tip with a new block, inserting + updating keys
//   4. Verify commit succeeds and all keys (L0-era, L1-era, extension) readable
// ---------------------------------------------------------------------------

#[test]
fn test_cow_write_through_reclaimed_parent() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_cow_write_through_reclaimed_parent");
    let sq_path = format!("{dir}/squashed.sqlite");

    let l0_blocks: usize = 5;
    let l1_blocks: usize = 5;
    let keys_per_block: usize = 3;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    // ── Phase 1: Build L0 blocks and squash ──
    let (src_marf, l0_block_hashes, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (l0_blocks - 1) as u32,
        false, // L0: no reclaim
    )
    .expect("L0 squash");

    // ── Phase 2: Build L1 blocks on top of squashed L0 ──
    let mut marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut all_blocks = l0_block_hashes.clone();
    let prev_tip = l0_block_hashes.last().unwrap().clone();

    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((block_num as u32) + 1).to_be_bytes());
        let block_hash = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 {
            &prev_tip
        } else {
            all_blocks.last().unwrap()
        };
        marf.begin(parent, &block_hash).unwrap();

        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            marf.insert(&key, val).unwrap();
        }

        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        marf.insert("shared_key", shared_val).unwrap();

        marf.seal().unwrap();
        marf.commit().unwrap();
        all_blocks.push(block_hash);
    }
    drop(marf);

    // ── Phase 3: L1 reclaim squash — truncates L0 per-block blobs ──
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        l0_blocks as u32,
        (l0_blocks + l1_blocks - 1) as u32,
        true, // reclaim!
    )
    .expect("L1 reclaim squash");

    // ── Phase 4: Extend from the reclaimed L1 tip ──
    let mut marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let reclaimed_parent = all_blocks.last().unwrap().clone();

    let ext_bytes = {
        let mut b = [0u8; 32];
        b[0] = 0xEE;
        b[31] = 0xFF;
        b
    };
    let ext_block = StacksBlockId::from_bytes(&ext_bytes).unwrap();

    marf.begin(&reclaimed_parent, &ext_block).unwrap();

    // Write a new key — COW walks back through the reclaimed parent via open_block_known_id.
    let ext_key = "ext_key_through_reclaim";
    let ext_val = MARFValue::from_value("ext_val_through_reclaim");
    marf.insert(ext_key, ext_val.clone()).unwrap();

    // Update the shared key to force deeper backpointer traversal into L0-era blocks.
    let shared_ext = MARFValue::from_value("shared_ext_reclaim");
    marf.insert("shared_key", shared_ext.clone()).unwrap();

    // Seal and commit — this is where the production failure occurred (state root mismatch).
    let ext_root = marf.seal().unwrap();
    marf.commit().unwrap();

    // ── Phase 5: Verify all keys are readable at the extension tip ──

    // Extension keys
    let read_ext = marf.get(&ext_block, ext_key).unwrap();
    assert_eq!(read_ext, Some(ext_val), "extension key should be readable");
    let read_shared = marf.get(&ext_block, "shared_key").unwrap();
    assert_eq!(
        read_shared,
        Some(shared_ext),
        "shared key updated in extension should be readable"
    );

    // L1-era keys (parent range was reclaimed)
    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let result = marf.get(&ext_block, &key).unwrap_or_else(|e| {
                panic!("Failed to read L1-era key '{key}' at extension tip: {e}")
            });
            assert!(
                result.is_some(),
                "L1-era key '{key}' should be readable at extension tip"
            );
        }
    }

    // L0-era keys (original blobs truncated by reclaim, served from squash blob)
    for j in 0..(l0_blocks * keys_per_block) {
        let key = format!("key_{j}");
        let result = marf
            .get(&ext_block, &key)
            .unwrap_or_else(|e| panic!("Failed to read L0-era key '{key}' at extension tip: {e}"));
        assert!(
            result.is_some(),
            "L0-era key '{key}' should be readable at extension tip"
        );
    }

    // Root hash should be consistent with get_root_hash_at
    let stored_root = marf.get_root_hash_at(&ext_block).unwrap();
    assert_eq!(
        ext_root, stored_root,
        "seal() root hash should match get_root_hash_at()"
    );
}

// ---------------------------------------------------------------------------
// Regression: L1 reclaim squash + extend must match unsquashed reference.
//
// This is the core regression for the production failure at block 173,000.
// The first squash (L0) is append-only and preserves per-block blobs, so COW
// works correctly. The second squash (L1) with reclaim=true destroys per-block
// blobs and redirects reads to the merged squash blob.
//
// The control test (no-reclaim variant) passes, isolating the bug to the
// reclaim/redirect path specifically. The mechanism is believed to involve COW
// reading resolved pointers from the merged squash blob and producing wrong
// backpointer targets, but this test proves the symptom: extending a block
// after L1 reclaim squash produces a different root hash than the same
// extension on an unsquashed MARF built from identical data.
//
// To expose this we build two identical MARFs, squash one (L0 + L1 reclaim),
// then extend both with the same block+keys. The root hashes must match.
// ---------------------------------------------------------------------------

#[test]
fn test_l1_reclaim_squash_extend_matches_unsquashed_reference() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_l1_reclaim_squash_extend_matches_unsquashed_reference");

    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    // Use enough blocks and keys to guarantee intermediate (non-leaf) nodes
    // with backpointers that span multiple blocks within each level.
    let l0_blocks: usize = 8;
    let l1_blocks: usize = 8;
    let keys_per_block: usize = 6;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    // ── Helper: deterministic block hash from index ──
    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // ── Phase 1: Build L0 blocks in the squashable MARF ──
    let (src_marf, l0_blocks_vec, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);

    // L0 squash (in-place, no reclaim — append-only since no prior levels)
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (l0_blocks - 1) as u32,
        true, // reclaim=true, but existing_levels is empty so actually_reclaimed=false
    )
    .expect("L0 squash");

    // ── Phase 2: Build L1 blocks on top of squashed L0 ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut all_blocks = l0_blocks_vec.clone();

    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let block_hash = make_block(block_num);
        let parent = all_blocks.last().unwrap().clone();

        sq_marf.begin(&parent, &block_hash).unwrap();

        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            sq_marf.insert(&key, val).unwrap();
        }

        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        sq_marf.insert("shared_key", shared_val).unwrap();

        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        all_blocks.push(block_hash);
    }

    // Record root hashes for every block BEFORE the L1 squash (these are
    // the canonical reference values).
    let mut pre_l1_roots: Vec<TrieHash> = Vec::new();
    for block in &all_blocks {
        pre_l1_roots.push(sq_marf.get_root_hash_at(block).unwrap());
    }

    drop(sq_marf);

    // ── Phase 3: L1 reclaim squash — this destroys per-block blobs ──
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        l0_blocks as u32,
        (l0_blocks + l1_blocks - 1) as u32,
        true, // reclaim!
    )
    .expect("L1 reclaim squash");

    // ── Phase 4: Build the unsquashed reference MARF with identical data ──
    let (ref_marf, ref_l0, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let block_hash = make_block(block_num);
        let parent = if i == 0 {
            ref_l0.last().unwrap().clone()
        } else {
            make_block(block_num - 1)
        };

        ref_marf.begin(&parent, &block_hash).unwrap();

        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            ref_marf.insert(&key, val).unwrap();
        }

        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        ref_marf.insert("shared_key", shared_val).unwrap();

        ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();
    }

    // Sanity: root hashes of the reference MARF at every block must match
    // the pre-L1-squash roots (they were built from the same data).
    for (i, block) in all_blocks.iter().enumerate() {
        let ref_root = ref_marf.get_root_hash_at(block).unwrap();
        assert_eq!(
            ref_root, pre_l1_roots[i],
            "reference MARF root at block {i} should match pre-L1-squash root"
        );
    }

    // ── Phase 5: Extend BOTH MARFs with an identical new block ──
    let ext_block = {
        let mut b = [0u8; 32];
        b[0] = 0xEE;
        b[31] = 0xFF;
        StacksBlockId::from_bytes(&b).unwrap()
    };
    let l1_tip = all_blocks.last().unwrap().clone();

    // Extension keys — enough to exercise multiple trie paths
    let ext_keys: Vec<(String, MARFValue)> = (0..keys_per_block)
        .map(|j| {
            (
                format!("ext_key_{j}"),
                MARFValue::from_value(&format!("ext_val_{j}")),
            )
        })
        .collect();

    // Extend squashed MARF
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.begin(&l1_tip, &ext_block).unwrap();
    for (k, v) in &ext_keys {
        sq_marf.insert(k, v.clone()).unwrap();
    }
    sq_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let sq_ext_root = sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();

    // Extend reference MARF
    ref_marf.begin(&l1_tip, &ext_block).unwrap();
    for (k, v) in &ext_keys {
        ref_marf.insert(k, v.clone()).unwrap();
    }
    ref_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let ref_ext_root = ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();

    // ── Phase 6: The critical assertion ──
    eprintln!("--- L1 reclaim regression: root hash comparison ---");
    eprintln!("  squashed ext root: {sq_ext_root}");
    eprintln!("  reference ext root: {ref_ext_root}");

    assert_eq!(
        sq_ext_root, ref_ext_root,
        "REGRESSION: root hash of block extended after L1 reclaim squash \
         must match unsquashed reference. A mismatch means COW backpointer \
         targets were corrupted by the squash blob's resolved pointers."
    );

    // Also verify data readability
    for (k, v) in &ext_keys {
        let sq_val = sq_marf.get(&ext_block, k).unwrap();
        let ref_val = ref_marf.get(&ext_block, k).unwrap();
        assert_eq!(sq_val, Some(v.clone()), "squashed ext key '{k}' readable");
        assert_eq!(ref_val, Some(v.clone()), "reference ext key '{k}' readable");
    }
}

// ---------------------------------------------------------------------------
// Regression: L1 non-reclaim squash + extend must match unsquashed reference.
//
// This is a companion to the reclaim test above. When reclaim=false, per-block
// blobs are preserved and reads_redirected=false, so COW should still work
// correctly.  This test serves as a control: if it passes but the reclaim
// variant fails, the bug is specifically in the reclaim/redirect path.
// ---------------------------------------------------------------------------

#[test]
fn test_l1_no_reclaim_squash_extend_matches_unsquashed_reference() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_l1_no_reclaim_squash_extend_matches_unsquashed_reference");

    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let l0_blocks: usize = 8;
    let l1_blocks: usize = 8;
    let keys_per_block: usize = 6;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // ── Build L0, squash, build L1 (same as reclaim test) ──
    let (src_marf, l0_blocks_vec, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (l0_blocks - 1) as u32,
        false,
    )
    .expect("L0 squash");

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut all_blocks = l0_blocks_vec.clone();

    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let block_hash = make_block(block_num);
        let parent = all_blocks.last().unwrap().clone();

        sq_marf.begin(&parent, &block_hash).unwrap();

        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            sq_marf.insert(&key, val).unwrap();
        }

        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        sq_marf.insert("shared_key", shared_val).unwrap();

        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        all_blocks.push(block_hash);
    }
    drop(sq_marf);

    // L1 squash WITHOUT reclaim
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        l0_blocks as u32,
        (l0_blocks + l1_blocks - 1) as u32,
        false, // no reclaim
    )
    .expect("L1 no-reclaim squash");

    // ── Build identical unsquashed reference ──
    let (ref_marf, ref_l0, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let block_hash = make_block(block_num);
        let parent = if i == 0 {
            ref_l0.last().unwrap().clone()
        } else {
            make_block(block_num - 1)
        };

        ref_marf.begin(&parent, &block_hash).unwrap();

        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            ref_marf.insert(&key, val).unwrap();
        }

        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        ref_marf.insert("shared_key", shared_val).unwrap();

        ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();
    }

    // ── Extend both ──
    let ext_block = {
        let mut b = [0u8; 32];
        b[0] = 0xEE;
        b[31] = 0xFF;
        StacksBlockId::from_bytes(&b).unwrap()
    };
    let l1_tip = all_blocks.last().unwrap().clone();

    let ext_keys: Vec<(String, MARFValue)> = (0..keys_per_block)
        .map(|j| {
            (
                format!("ext_key_{j}"),
                MARFValue::from_value(&format!("ext_val_{j}")),
            )
        })
        .collect();

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.begin(&l1_tip, &ext_block).unwrap();
    for (k, v) in &ext_keys {
        sq_marf.insert(k, v.clone()).unwrap();
    }
    sq_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let sq_ext_root = sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();

    ref_marf.begin(&l1_tip, &ext_block).unwrap();
    for (k, v) in &ext_keys {
        ref_marf.insert(k, v.clone()).unwrap();
    }
    ref_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let ref_ext_root = ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();

    eprintln!("--- L1 no-reclaim regression: root hash comparison ---");
    eprintln!("  squashed ext root: {sq_ext_root}");
    eprintln!("  reference ext root: {ref_ext_root}");

    assert_eq!(
        sq_ext_root, ref_ext_root,
        "root hash of block extended after L1 no-reclaim squash \
         must match unsquashed reference (control test)"
    );
}

// ---------------------------------------------------------------------------
// Regression: Multiple extensions after L1 reclaim squash.
//
// The production bug manifested as the node getting stuck *permanently* — every
// subsequent block after the squash failed with a state root mismatch. This
// test verifies that multiple blocks can be extended after L1 reclaim squash
// and that each one's root hash matches the unsquashed reference.
// ---------------------------------------------------------------------------

#[test]
fn test_l1_reclaim_squash_multi_extend_matches_unsquashed_reference() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_l1_reclaim_squash_multi_extend_matches_unsquashed_reference");

    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let l0_blocks: usize = 5;
    let l1_blocks: usize = 5;
    let keys_per_block: usize = 4;
    let ext_blocks: usize = 5;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // ── Build and squash (L0 + L1 reclaim) ──
    let (src_marf, l0_blocks_vec, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (l0_blocks - 1) as u32,
        true,
    )
    .expect("L0 squash");

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut all_blocks = l0_blocks_vec.clone();

    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let block_hash = make_block(block_num);
        let parent = all_blocks.last().unwrap().clone();

        sq_marf.begin(&parent, &block_hash).unwrap();
        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            sq_marf.insert(&key, val).unwrap();
        }
        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        sq_marf.insert("shared_key", shared_val).unwrap();
        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        all_blocks.push(block_hash);
    }
    drop(sq_marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        l0_blocks as u32,
        (l0_blocks + l1_blocks - 1) as u32,
        true,
    )
    .expect("L1 reclaim squash");

    // ── Build identical unsquashed reference ──
    let (ref_marf, ref_l0, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let block_hash = make_block(block_num);
        let parent = if i == 0 {
            ref_l0.last().unwrap().clone()
        } else {
            make_block(block_num - 1)
        };
        ref_marf.begin(&parent, &block_hash).unwrap();
        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            ref_marf.insert(&key, val).unwrap();
        }
        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        ref_marf.insert("shared_key", shared_val).unwrap();
        ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();
    }

    // ── Extend both with multiple blocks ──
    let total_pre = l0_blocks + l1_blocks;

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut sq_parent = all_blocks.last().unwrap().clone();

    for e in 0..ext_blocks {
        let block_num = total_pre + e;
        let block_hash = make_block(block_num);

        // Squashed
        sq_marf.begin(&sq_parent, &block_hash).unwrap();
        for j in 0..keys_per_block {
            let key = format!("ext_key_{block_num}_{j}");
            let val = MARFValue::from_value(&format!("ext_val_{block_num}_{j}"));
            sq_marf.insert(&key, val).unwrap();
        }
        sq_marf
            .insert(
                "shared_key",
                MARFValue::from_value(&format!("shared_ext_{block_num}")),
            )
            .unwrap();
        let sq_root = sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();

        // Reference
        let ref_parent = if e == 0 {
            make_block(total_pre - 1)
        } else {
            make_block(block_num - 1)
        };
        ref_marf.begin(&ref_parent, &block_hash).unwrap();
        for j in 0..keys_per_block {
            let key = format!("ext_key_{block_num}_{j}");
            let val = MARFValue::from_value(&format!("ext_val_{block_num}_{j}"));
            ref_marf.insert(&key, val).unwrap();
        }
        ref_marf
            .insert(
                "shared_key",
                MARFValue::from_value(&format!("shared_ext_{block_num}")),
            )
            .unwrap();
        let ref_root = ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();

        eprintln!(
            "ext block {e} (height {block_num}): sq={sq_root} ref={ref_root} {}",
            if sq_root == ref_root {
                "OK"
            } else {
                "MISMATCH"
            }
        );

        assert_eq!(
            sq_root, ref_root,
            "REGRESSION: extension block {e} (height {block_num}) root hash mismatch \
             after L1 reclaim squash"
        );

        sq_parent = block_hash;
    }
}

// ---------------------------------------------------------------------------
// L0 reclaim regression tests.
//
// With Approach A (preserved backpointers), L0 reclaim is now safe: the squash
// blob preserves intra-level backpointer provenance, COW skips existing
// backpointers, and consensus hashing uses real ancestor block hashes.
//
// These tests verify that L0 reclaim squash + extend produces the same root
// hashes as an unsquashed reference MARF, covering:
//   1. Single-block extension after L0 reclaim
//   2. Multi-block extension after L0 reclaim
//   3. Heavy updates (repeated writes to older keys, not just new inserts)
// ---------------------------------------------------------------------------

#[test]
fn test_l0_reclaim_squash_extend_matches_unsquashed_reference() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_l0_reclaim_squash_extend_matches_unsquashed_reference");

    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let l0_blocks: usize = 10;
    let keys_per_block: usize = 6;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    // ── Build L0 blocks in both MARFs ──
    let (src_marf, l0_blocks_vec, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);

    let (ref_marf, _, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);

    // ── L0 squash with reclaim ──
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (l0_blocks - 1) as u32,
        true, // L0 reclaim!
    )
    .expect("L0 reclaim squash");

    // ── Extend both MARFs with an identical new block ──
    let ext_block = {
        let mut b = [0u8; 32];
        b[0] = 0xEE;
        b[31] = 0xFF;
        StacksBlockId::from_bytes(&b).unwrap()
    };
    let l0_tip = l0_blocks_vec.last().unwrap().clone();

    let ext_keys: Vec<(String, MARFValue)> = (0..keys_per_block)
        .map(|j| {
            (
                format!("ext_key_{j}"),
                MARFValue::from_value(&format!("ext_val_{j}")),
            )
        })
        .collect();

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.begin(&l0_tip, &ext_block).unwrap();
    for (k, v) in &ext_keys {
        sq_marf.insert(k, v.clone()).unwrap();
    }
    sq_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let sq_ext_root = sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();

    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();
    ref_marf.begin(&l0_tip, &ext_block).unwrap();
    for (k, v) in &ext_keys {
        ref_marf.insert(k, v.clone()).unwrap();
    }
    ref_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let ref_ext_root = ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();

    eprintln!("--- L0 reclaim regression: root hash comparison ---");
    eprintln!("  squashed ext root: {sq_ext_root}");
    eprintln!("  reference ext root: {ref_ext_root}");

    assert_eq!(
        sq_ext_root, ref_ext_root,
        "REGRESSION: root hash of block extended after L0 reclaim squash \
         must match unsquashed reference"
    );

    // Verify data readability
    for (k, v) in &ext_keys {
        let sq_val = sq_marf.get(&ext_block, k).unwrap();
        let ref_val = ref_marf.get(&ext_block, k).unwrap();
        assert_eq!(sq_val, Some(v.clone()), "squashed ext key '{k}' readable");
        assert_eq!(ref_val, Some(v.clone()), "reference ext key '{k}' readable");
    }
}

#[test]
fn test_l0_reclaim_squash_multi_extend_matches_unsquashed_reference() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_l0_reclaim_squash_multi_extend_matches_unsquashed_reference");

    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let l0_blocks: usize = 8;
    let keys_per_block: usize = 5;
    let ext_blocks: usize = 5;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // ── Build and squash L0 ──
    let (src_marf, l0_blocks_vec, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);

    let (ref_marf, _, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (l0_blocks - 1) as u32,
        true, // L0 reclaim!
    )
    .expect("L0 reclaim squash");

    // ── Extend both with multiple blocks ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    let mut sq_parent = l0_blocks_vec.last().unwrap().clone();
    let mut ref_parent = sq_parent.clone();

    for e in 0..ext_blocks {
        let block_num = l0_blocks + e;
        let block_hash = make_block(block_num);

        sq_marf.begin(&sq_parent, &block_hash).unwrap();
        for j in 0..keys_per_block {
            let key = format!("ext_key_{block_num}_{j}");
            let val = MARFValue::from_value(&format!("ext_val_{block_num}_{j}"));
            sq_marf.insert(&key, val).unwrap();
        }
        sq_marf
            .insert(
                "shared_key",
                MARFValue::from_value(&format!("shared_ext_{block_num}")),
            )
            .unwrap();
        let sq_root = sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();

        ref_marf.begin(&ref_parent, &block_hash).unwrap();
        for j in 0..keys_per_block {
            let key = format!("ext_key_{block_num}_{j}");
            let val = MARFValue::from_value(&format!("ext_val_{block_num}_{j}"));
            ref_marf.insert(&key, val).unwrap();
        }
        ref_marf
            .insert(
                "shared_key",
                MARFValue::from_value(&format!("shared_ext_{block_num}")),
            )
            .unwrap();
        let ref_root = ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();

        eprintln!(
            "L0 reclaim ext block {e} (height {block_num}): sq={sq_root} ref={ref_root} {}",
            if sq_root == ref_root {
                "OK"
            } else {
                "MISMATCH"
            }
        );

        assert_eq!(
            sq_root, ref_root,
            "REGRESSION: extension block {e} (height {block_num}) root hash mismatch \
             after L0 reclaim squash"
        );

        sq_parent = block_hash.clone();
        ref_parent = block_hash;
    }
}

#[test]
fn test_l0_reclaim_squash_heavy_updates_matches_unsquashed_reference() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_l0_reclaim_squash_heavy_updates_matches_unsquashed_reference");

    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    // Use fewer blocks but more keys, and repeatedly update existing keys.
    let l0_blocks: usize = 6;
    let keys_per_block: usize = 4;
    let ext_blocks: usize = 5;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // ── Build L0 in both MARFs ──
    let (src_marf, l0_blocks_vec, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);

    let (ref_marf, _, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);

    // ── L0 reclaim squash ──
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (l0_blocks - 1) as u32,
        true,
    )
    .expect("L0 reclaim squash");

    // ── Extend both with blocks that heavily update old keys ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    let mut sq_parent = l0_blocks_vec.last().unwrap().clone();
    let mut ref_parent = sq_parent.clone();

    // Total keys inserted during L0: keys_per_block * l0_blocks unique keys + "shared_key"
    // We'll update older keys from earlier L0 blocks, not just insert new ones.
    let total_l0_keys = keys_per_block * l0_blocks;

    for e in 0..ext_blocks {
        let block_num = l0_blocks + e;
        let block_hash = make_block(block_num);

        sq_marf.begin(&sq_parent, &block_hash).unwrap();
        ref_marf.begin(&ref_parent, &block_hash).unwrap();

        // Insert some new keys
        for j in 0..2 {
            let key = format!("ext_key_{block_num}_{j}");
            let val = MARFValue::from_value(&format!("ext_val_{block_num}_{j}"));
            sq_marf.insert(&key, val.clone()).unwrap();
            ref_marf.insert(&key, val).unwrap();
        }

        // Update several old keys from the L0 range — forces COW to walk back
        // through the squash blob and copy nodes with preserved backpointers.
        for j in 0..keys_per_block {
            let old_key_index = (e * keys_per_block + j) % total_l0_keys;
            let key = format!("key_{old_key_index}");
            let val = MARFValue::from_value(&format!("updated_{old_key_index}_at_{block_num}"));
            sq_marf.insert(&key, val.clone()).unwrap();
            ref_marf.insert(&key, val).unwrap();
        }

        // Update shared_key
        let shared_val = MARFValue::from_value(&format!("shared_ext_{block_num}"));
        sq_marf.insert("shared_key", shared_val.clone()).unwrap();
        ref_marf.insert("shared_key", shared_val).unwrap();

        let sq_root = sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        let ref_root = ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();

        eprintln!(
            "L0 reclaim heavy ext {e} (height {block_num}): sq={sq_root} ref={ref_root} {}",
            if sq_root == ref_root {
                "OK"
            } else {
                "MISMATCH"
            }
        );

        assert_eq!(
            sq_root, ref_root,
            "REGRESSION: heavy-update extension block {e} (height {block_num}) root hash \
             mismatch after L0 reclaim squash"
        );

        sq_parent = block_hash.clone();
        ref_parent = block_hash;
    }

    // Verify older keys are still readable from the squash blob
    let tip = make_block(l0_blocks + ext_blocks - 1);
    for j in 0..total_l0_keys {
        let key = format!("key_{j}");
        let sq_val = sq_marf.get(&tip, &key).unwrap();
        let ref_val = ref_marf.get(&tip, &key).unwrap();
        assert_eq!(
            sq_val, ref_val,
            "key '{key}' should match between squashed and reference at tip"
        );
    }
}

#[test]
fn test_l0_reclaim_squash_long_horizon_heavy_updates_matches_unsquashed_reference() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir(
        "test_l0_reclaim_squash_long_horizon_heavy_updates_matches_unsquashed_reference",
    );

    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    // Keep the base shape modest so the test stays tractable, but extend far
    // enough to exercise long-horizon ancestor/root-hash behavior after L0
    // reclaim.  This is meant to approximate the live failure mode where the
    // node advanced many blocks after squash before diverging.
    let l0_blocks: usize = 6;
    let keys_per_block: usize = 4;
    let ext_blocks: usize = 192;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0xA11CE55Eu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let (src_marf, l0_blocks_vec, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);

    let (ref_marf, _, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (l0_blocks - 1) as u32,
        true,
    )
    .expect("L0 reclaim squash");

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    let mut sq_parent = l0_blocks_vec.last().unwrap().clone();
    let mut ref_parent = sq_parent.clone();

    let total_l0_keys = l0_blocks * keys_per_block;

    for e in 0..ext_blocks {
        let block_num = l0_blocks + e;
        let block_hash = make_block(block_num);

        sq_marf.begin(&sq_parent, &block_hash).unwrap();
        ref_marf.begin(&ref_parent, &block_hash).unwrap();

        // Insert a couple of fresh keys per block so we keep extending the
        // trie as well as revisiting older structure.
        for j in 0..2 {
            let key = format!("long_ext_key_{block_num}_{j}");
            let val = MARFValue::from_value(&format!("long_ext_val_{block_num}_{j}"));
            sq_marf.insert(&key, val.clone()).unwrap();
            ref_marf.insert(&key, val).unwrap();
        }

        // Repeatedly update older keys from the original L0 range so COW has to
        // walk back through reclaimed state instead of only touching newly-added
        // descendants.
        for k in 0..std::cmp::min(total_l0_keys, 6) {
            let old_key_idx = (e * 3 + k * 7) % total_l0_keys;
            let old_key = format!("key_{old_key_idx}");
            let old_val = MARFValue::from_value(&format!("rehydrated_{block_num}_{old_key_idx}"));
            sq_marf.insert(&old_key, old_val.clone()).unwrap();
            ref_marf.insert(&old_key, old_val).unwrap();
        }

        // Also keep mutating the shared key, which tends to force reuse of the
        // same hot path across many descendants.
        let shared_val = MARFValue::from_value(&format!("shared_long_{block_num}"));
        sq_marf.insert("shared_key", shared_val.clone()).unwrap();
        ref_marf.insert("shared_key", shared_val).unwrap();

        let sq_root = sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();

        let ref_root = ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();

        assert_eq!(
            sq_root, ref_root,
            "long-horizon L0 reclaim mismatch at extension block {e} (height {block_num})"
        );

        // Periodically re-read the just-committed root through the storage path
        // as a second sanity check.
        if e % 16 == 0 {
            let sq_stored = sq_marf.get_root_hash_at(&block_hash).unwrap();
            let ref_stored = ref_marf.get_root_hash_at(&block_hash).unwrap();
            assert_eq!(
                sq_stored, ref_stored,
                "stored root mismatch at extension block {e} (height {block_num})"
            );
        }

        sq_parent = block_hash.clone();
        ref_parent = block_hash;
    }
}

#[test]
fn test_l0_reclaim_squash_long_horizon_historical_reads_match_unsquashed_reference() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir(
        "test_l0_reclaim_squash_long_horizon_historical_reads_match_unsquashed_reference",
    );

    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let l0_blocks: usize = 6;
    let keys_per_block: usize = 4;
    let ext_blocks: usize = 192;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0xB10C0A7Eu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let (src_marf, l0_blocks_vec, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);

    let (ref_marf, _, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (l0_blocks - 1) as u32,
        true,
    )
    .expect("L0 reclaim squash");

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    let mut sq_parent = l0_blocks_vec.last().unwrap().clone();
    let mut ref_parent = sq_parent.clone();
    let mut chain: Vec<StacksBlockId> = l0_blocks_vec.clone();

    let total_l0_keys = l0_blocks * keys_per_block;

    for e in 0..ext_blocks {
        let block_num = l0_blocks + e;
        let block_hash = make_block(block_num);

        sq_marf.begin(&sq_parent, &block_hash).unwrap();
        ref_marf.begin(&ref_parent, &block_hash).unwrap();

        let new_key = format!("hist_ext_key_{block_num}");
        let new_val = MARFValue::from_value(&format!("hist_ext_val_{block_num}"));
        sq_marf.insert(&new_key, new_val.clone()).unwrap();
        ref_marf.insert(&new_key, new_val).unwrap();

        let old_key_idx = (e * 5) % total_l0_keys;
        let old_key = format!("key_{old_key_idx}");
        let old_val = MARFValue::from_value(&format!("hist_refresh_{block_num}_{old_key_idx}"));
        sq_marf.insert(&old_key, old_val.clone()).unwrap();
        ref_marf.insert(&old_key, old_val).unwrap();

        let shared_val = MARFValue::from_value(&format!("shared_hist_{block_num}"));
        sq_marf.insert("shared_key", shared_val.clone()).unwrap();
        ref_marf.insert("shared_key", shared_val).unwrap();

        let sq_root = sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        let ref_root = ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();
        assert_eq!(
            sq_root, ref_root,
            "historical-read setup diverged at height {block_num}"
        );

        chain.push(block_hash.clone());
        sq_parent = block_hash.clone();
        ref_parent = block_hash;
    }

    // Probe a spread of historical heights, including old L0-era tips and much
    // later descendants, and compare both root and key reads against the
    // unsquashed reference.
    let sample_heights = [
        0usize,
        1,
        3,
        5,
        6,
        7,
        15,
        31,
        63,
        95,
        127,
        159,
        191,
        chain.len() - 1,
    ];

    for height in sample_heights {
        let block = chain[height].clone();

        let sq_root = sq_marf.get_root_hash_at(&block).unwrap();
        let ref_root = ref_marf.get_root_hash_at(&block).unwrap();
        assert_eq!(
            sq_root, ref_root,
            "root mismatch at sampled historical height {height}"
        );

        // Heights within the squash range (0..l0_blocks) are served from the
        // TipOnly squash blob, which collapses all leaf values to the tip-of-
        // range value.  Leaf value equality is only meaningful for heights
        // above the squash range, where per-block blobs hold the real data.
        // Root hashes still match at all heights (stored in the squash trailer).
        if height >= l0_blocks {
            // shared_key exists across the whole chain and changes every block
            // after the base history, so it is a good probe for historical reads.
            let sq_shared = sq_marf.get(&block, "shared_key").unwrap();
            let ref_shared = ref_marf.get(&block, "shared_key").unwrap();
            assert_eq!(
                sq_shared, ref_shared,
                "shared_key historical read mismatch at sampled height {height}"
            );

            // Probe a representative old L0-era key as well, since those are
            // served from the reclaimed L0 squash blob after the first squash.
            let key = format!("key_{}", height % total_l0_keys);
            let sq_old = sq_marf.get(&block, &key).unwrap();
            let ref_old = ref_marf.get(&block, &key).unwrap();
            assert_eq!(
                sq_old, ref_old,
                "old-key historical read mismatch for '{key}' at sampled height {height}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: build a linear canonical chain with committed fork blocks.
//
// Creates `num_blocks` canonical blocks, then at `fork_point` (index into
// block list) creates `num_fork_blocks` side-branch blocks.  All blocks —
// canonical and fork — are committed as unconfirmed=0 and written to the
// external .blobs file.  The fork blocks share a common parent in the
// canonical chain but are NOT ancestors of the canonical tip, so
// `get_block_at_height` from the tip will never reach them.
// ---------------------------------------------------------------------------
fn setup_marf_with_fork_blocks(
    path: &str,
    num_blocks: usize,
    keys_per_block: usize,
    fork_point: usize,
    num_fork_blocks: usize,
) -> (MARF<StacksBlockId>, Vec<StacksBlockId>, Vec<StacksBlockId>) {
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(path, open_opts).unwrap();

    assert!(num_blocks > 0, "need at least one block");
    assert!(
        fork_point < num_blocks,
        "fork_point must be within canonical chain"
    );

    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let make_fork_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0xFFu8; 32]; // distinct prefix to avoid collision
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // Build canonical chain
    let blocks: Vec<StacksBlockId> = (0..num_blocks).map(&make_block).collect();

    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    for j in 0..keys_per_block {
        let key = format!("key_{j}");
        let val = MARFValue::from_value(&format!("val_{j}_at_0"));
        marf.insert(&key, val).unwrap();
    }
    let shared_val = MARFValue::from_value("shared_at_0");
    marf.insert("shared_key", shared_val).unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    for i in 1..num_blocks {
        marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
        for j in 0..keys_per_block {
            let key_index = i * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{i}"));
            marf.insert(&key, val).unwrap();
        }
        let shared_val = MARFValue::from_value(&format!("shared_at_{i}"));
        marf.insert("shared_key", shared_val).unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
    }

    // Create fork blocks branching off blocks[fork_point].
    // Each fork block extends the previous fork block (a short side chain).
    let fork_blocks: Vec<StacksBlockId> = (0..num_fork_blocks).map(&make_fork_block).collect();

    for i in 0..num_fork_blocks {
        let parent = if i == 0 {
            blocks[fork_point].clone()
        } else {
            fork_blocks[i - 1].clone()
        };
        marf.begin(&parent, &fork_blocks[i]).unwrap();

        // Insert some unique keys on the fork branch
        for j in 0..keys_per_block {
            let key = format!("fork_key_{i}_{j}");
            let val = MARFValue::from_value(&format!("fork_val_{i}_{j}"));
            marf.insert(&key, val).unwrap();
        }
        marf.insert(
            "shared_key",
            MARFValue::from_value(&format!("fork_shared_{i}")),
        )
        .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
    }

    (marf, blocks, fork_blocks)
}

// ---------------------------------------------------------------------------
// Orphaned fork blocks: L0 reclaim prunes non-canonical refs and succeeds.
//
// When the MARF contains committed (unconfirmed=0) blocks from an abandoned
// fork, their blobs exist in the .blobs file.  L0 reclaim's truncation zone
// covers the entire file (from_offset=0).  Before Approach A's prune step,
// validate_truncation_zone would reject these rows — this is the production
// failure observed at height 172,000:
//   "Live marf_data row for block 65549a... references offset ... but is not
//    being superseded"
//
// The prune step zeroes external_offset/external_length for these non-canonical
// rows, allowing truncation to proceed.  This is intentional fork-state
// pruning: those fork trie blobs become permanently unreadable.
//
// This test verifies:
//   1. Fork blocks initially have external blob refs
//   2. L0 reclaim succeeds (prune fires before validation)
//   3. Fork block refs are zeroed after reclaim
//   4. Root hash matches unsquashed reference
// ---------------------------------------------------------------------------

#[test]
fn test_l0_reclaim_prunes_fork_blocks_and_succeeds() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_l0_reclaim_prunes_fork_blocks_and_succeeds");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let num_blocks: usize = 8;
    let keys_per_block: usize = 4;
    let fork_point: usize = 3;
    let num_fork_blocks: usize = 2;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    // ── Build squash MARF with fork blocks ──
    let (marf, canonical_blocks, fork_blocks) = setup_marf_with_fork_blocks(
        &sq_path,
        num_blocks,
        keys_per_block,
        fork_point,
        num_fork_blocks,
    );
    drop(marf);

    // ── Build identical reference MARF (no forks) ──
    let (ref_marf, _, _) = setup_squash_source_marf(&ref_path, num_blocks, keys_per_block);
    drop(ref_marf);

    // Verify fork blocks have external blob refs before squash.
    {
        use rusqlite::Connection;
        let db = Connection::open(format!("{sq_path}")).unwrap();
        for fb in &fork_blocks {
            let length: i64 = db
                .query_row(
                    "SELECT external_length FROM marf_data WHERE block_hash = ?1",
                    rusqlite::params![format!("{fb}")],
                    |row| row.get(0),
                )
                .unwrap();
            eprintln!("Pre-squash fork block {fb}: external_length={length}");
            assert!(length > 0, "Fork block should have blob data before squash");
        }
    }

    // L0 reclaim — should succeed because prune zeroes fork block refs first.
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (num_blocks - 1) as u32,
        true, // reclaim
    )
    .expect("L0 reclaim should succeed after pruning orphaned fork block refs");

    eprintln!("--- L0 reclaim succeeded after pruning fork block refs ---");

    // Verify fork block refs were zeroed by the prune.
    {
        use rusqlite::Connection;
        let db = Connection::open(format!("{sq_path}")).unwrap();
        for fb in &fork_blocks {
            let (offset, length): (i64, i64) = db
                .query_row(
                    "SELECT external_offset, external_length FROM marf_data WHERE block_hash = ?1",
                    rusqlite::params![format!("{fb}")],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            eprintln!("Post-squash fork block {fb}: offset={offset}, length={length}");
            assert_eq!(
                (offset, length),
                (0, 0),
                "Fork block {fb} external refs should be zeroed after prune"
            );
        }
    }

    // ── Extend both MARFs and compare root hashes ──
    let ext_block = {
        let mut b = [0u8; 32];
        b[0] = 0xEE;
        b[31] = 0xFF;
        StacksBlockId::from_bytes(&b).unwrap()
    };
    let tip = canonical_blocks.last().unwrap().clone();

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.begin(&tip, &ext_block).unwrap();
    for j in 0..keys_per_block {
        let key = format!("ext_key_{j}");
        let val = MARFValue::from_value(&format!("ext_val_{j}"));
        sq_marf.insert(&key, val).unwrap();
    }
    sq_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let sq_ext_root = sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();

    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();
    ref_marf.begin(&tip, &ext_block).unwrap();
    for j in 0..keys_per_block {
        let key = format!("ext_key_{j}");
        let val = MARFValue::from_value(&format!("ext_val_{j}"));
        ref_marf.insert(&key, val).unwrap();
    }
    ref_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let ref_ext_root = ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();

    eprintln!("--- L0 reclaim + fork prune: root hash comparison ---");
    eprintln!("  squashed ext root: {sq_ext_root}");
    eprintln!("  reference ext root: {ref_ext_root}");

    assert_eq!(
        sq_ext_root, ref_ext_root,
        "L0 reclaim with pruned fork blocks: root hash must match unsquashed reference"
    );
}

// ---------------------------------------------------------------------------
// Orphaned fork blocks: L1+ reclaim is unaffected.
//
// Fork block blobs are written during the initial sequential blob export at
// offsets BELOW any squash level blob.  When L1+ reclaim truncates from
// (L0_offset + L0_length), all fork block offsets are below that boundary
// and do not trigger validate_truncation_zone.
//
// This test proves that L1+ reclaim works correctly even when non-canonical
// fork blocks exist in the blob file.
// ---------------------------------------------------------------------------

#[test]
fn test_l1_reclaim_succeeds_with_orphaned_fork_blocks() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_l1_reclaim_succeeds_with_orphaned_fork_blocks");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let l0_blocks: usize = 8;
    let l1_blocks: usize = 6;
    let keys_per_block: usize = 4;
    let fork_point: usize = 3;
    let num_fork_blocks: usize = 2;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // ── Phase 1: Build L0 blocks WITH fork blocks ──
    let (marf, l0_blocks_vec, fork_blocks) = setup_marf_with_fork_blocks(
        &sq_path,
        l0_blocks,
        keys_per_block,
        fork_point,
        num_fork_blocks,
    );
    drop(marf);

    // L0 squash — append-only (no reclaim, since L0 with fork rows would fail).
    // In the recommended production flow, L0 is always append-only.
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (l0_blocks - 1) as u32,
        false, // append-only
    )
    .expect("L0 append-only squash should succeed despite fork blocks");

    // ── Phase 2: Build L1 blocks on top of squashed L0 ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut all_blocks = l0_blocks_vec.clone();

    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let block_hash = make_block(block_num);
        let parent = all_blocks.last().unwrap().clone();

        sq_marf.begin(&parent, &block_hash).unwrap();
        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            sq_marf.insert(&key, val).unwrap();
        }
        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        sq_marf.insert("shared_key", shared_val).unwrap();
        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        all_blocks.push(block_hash);
    }
    drop(sq_marf);

    // Verify fork blocks still have external blob refs pointing into the
    // original per-block region (below the L0 squash blob offset).
    {
        use rusqlite::Connection;

        use crate::chainstate::stacks::index::trie_sql;
        let db = Connection::open(format!("{sq_path}")).unwrap();
        let levels = trie_sql::read_squash_levels(&db).unwrap();
        let l0_level = &levels[0];
        let l0_start = l0_level.blob_offset;

        for fb in &fork_blocks {
            let (offset, length): (i64, i64) = db
                .query_row(
                    "SELECT external_offset, external_length FROM marf_data WHERE block_hash = ?1",
                    rusqlite::params![format!("{fb}")],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            eprintln!("Fork block {fb}: offset={offset}, length={length}, L0 starts at {l0_start}");
            assert!(
                (offset as u64) < l0_start,
                "Fork block blob at offset {offset} should be below L0 blob offset {l0_start}"
            );
        }
    }

    // ── Phase 3: L1 reclaim squash — should succeed despite fork blocks ──
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        l0_blocks as u32,
        (l0_blocks + l1_blocks - 1) as u32,
        true, // reclaim!
    )
    .expect("L1 reclaim squash should succeed even with orphaned fork blocks");

    eprintln!("--- L1 reclaim succeeded with orphaned fork blocks present ---");

    // ── Phase 4: Build reference MARF (no squash, no forks) and verify ──
    let (ref_marf, ref_l0, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let block_hash = make_block(block_num);
        let parent = if i == 0 {
            ref_l0.last().unwrap().clone()
        } else {
            make_block(block_num - 1)
        };
        ref_marf.begin(&parent, &block_hash).unwrap();
        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            ref_marf.insert(&key, val).unwrap();
        }
        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        ref_marf.insert("shared_key", shared_val).unwrap();
        ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();
    }

    // ── Phase 5: Extend both and compare root hashes ──
    let ext_block = {
        let mut b = [0u8; 32];
        b[0] = 0xEE;
        b[31] = 0xFF;
        StacksBlockId::from_bytes(&b).unwrap()
    };
    let l1_tip = all_blocks.last().unwrap().clone();

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.begin(&l1_tip, &ext_block).unwrap();
    for j in 0..keys_per_block {
        let key = format!("ext_key_{j}");
        let val = MARFValue::from_value(&format!("ext_val_{j}"));
        sq_marf.insert(&key, val).unwrap();
    }
    sq_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let sq_ext_root = sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();

    ref_marf.begin(&l1_tip, &ext_block).unwrap();
    for j in 0..keys_per_block {
        let key = format!("ext_key_{j}");
        let val = MARFValue::from_value(&format!("ext_val_{j}"));
        ref_marf.insert(&key, val).unwrap();
    }
    ref_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let ref_ext_root = ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();

    eprintln!("--- L1 reclaim + fork blocks: root hash comparison ---");
    eprintln!("  squashed ext root: {sq_ext_root}");
    eprintln!("  reference ext root: {ref_ext_root}");

    assert_eq!(
        sq_ext_root, ref_ext_root,
        "L1 reclaim with orphaned fork blocks: root hash must match unsquashed reference"
    );
}

// ---------------------------------------------------------------------------
// Orphaned fork blocks in L1 range: L1 reclaim prunes and succeeds.
//
// Fork blocks committed during the L1 block range have blobs appended to the
// .blobs file AFTER the L0 squash blob, placing them in L1's truncation zone.
// Without the prune step, validate_truncation_zone would reject these rows.
//
// This test verifies:
//   1. Fork block blobs are at offsets above the L0 squash blob
//   2. L1 reclaim succeeds (prune fires before validation)
//   3. Fork block refs are zeroed after reclaim
//   4. Root hash matches unsquashed reference
// ---------------------------------------------------------------------------

#[test]
fn test_l1_reclaim_prunes_fork_blocks_in_l1_range() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_l1_reclaim_prunes_fork_blocks_in_l1_range");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let l0_blocks: usize = 6;
    let l1_blocks: usize = 6;
    let keys_per_block: usize = 4;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let make_fork_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0xFFu8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // ── Phase 1: Build L0 blocks (no forks), L0 append-only squash ──
    let (src_marf, l0_blocks_vec, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (l0_blocks - 1) as u32,
        false, // append-only L0
    )
    .expect("L0 append-only squash");

    // ── Phase 2: Build L1 canonical blocks + fork blocks in L1 range ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut all_blocks = l0_blocks_vec.clone();

    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let block_hash = make_block(block_num);
        let parent = all_blocks.last().unwrap().clone();

        sq_marf.begin(&parent, &block_hash).unwrap();
        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            sq_marf.insert(&key, val).unwrap();
        }
        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        sq_marf.insert("shared_key", shared_val).unwrap();
        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        all_blocks.push(block_hash);
    }

    // Commit fork blocks branching off the second L1 block.
    let fork_parent_idx = 1;
    let fork_parent = all_blocks[l0_blocks + fork_parent_idx].clone();
    let num_fork_blocks: usize = 2;
    let fork_blocks: Vec<StacksBlockId> = (0..num_fork_blocks).map(&make_fork_block).collect();

    for i in 0..num_fork_blocks {
        let parent = if i == 0 {
            fork_parent.clone()
        } else {
            fork_blocks[i - 1].clone()
        };
        sq_marf.begin(&parent, &fork_blocks[i]).unwrap();
        for j in 0..keys_per_block {
            let key = format!("l1_fork_key_{i}_{j}");
            let val = MARFValue::from_value(&format!("l1_fork_val_{i}_{j}"));
            sq_marf.insert(&key, val).unwrap();
        }
        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
    }
    drop(sq_marf);

    // Verify fork block blobs are in the L1 truncation zone.
    {
        use rusqlite::Connection;

        use crate::chainstate::stacks::index::trie_sql;
        let db = Connection::open(format!("{sq_path}")).unwrap();
        let levels = trie_sql::read_squash_levels(&db).unwrap();
        let l0_level = &levels[0];
        let l0_end = l0_level.blob_offset + l0_level.blob_length;

        for fb in &fork_blocks {
            let (offset, length): (i64, i64) = db
                .query_row(
                    "SELECT external_offset, external_length FROM marf_data WHERE block_hash = ?1",
                    rusqlite::params![format!("{fb}")],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            eprintln!(
                "Pre-reclaim L1-range fork block {fb}: offset={offset}, length={length}, \
                 L0 ends at {l0_end} (in truncation zone: {})",
                (offset as u64) >= l0_end
            );
            assert!(
                (offset as u64) >= l0_end,
                "Fork block committed during L1 range should be at offset ({offset}) >= L0 end ({l0_end})"
            );
        }
    }

    // ── Phase 3: L1 reclaim — should succeed because prune fires first ──
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        l0_blocks as u32,
        (l0_blocks + l1_blocks - 1) as u32,
        true, // reclaim!
    )
    .expect("L1 reclaim should succeed after pruning fork blocks in L1 range");

    eprintln!("--- L1 reclaim succeeded after pruning fork blocks in L1 range ---");

    // Verify fork block refs were zeroed.
    {
        use rusqlite::Connection;
        let db = Connection::open(format!("{sq_path}")).unwrap();
        for fb in &fork_blocks {
            let (offset, length): (i64, i64) = db
                .query_row(
                    "SELECT external_offset, external_length FROM marf_data WHERE block_hash = ?1",
                    rusqlite::params![format!("{fb}")],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            eprintln!("Post-reclaim fork block {fb}: offset={offset}, length={length}");
            assert_eq!(
                (offset, length),
                (0, 0),
                "Fork block {fb} external refs should be zeroed after prune"
            );
        }
    }

    // ── Phase 4: Build reference MARF and verify root hashes ──
    let (ref_marf, ref_l0, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let block_hash = make_block(block_num);
        let parent = if i == 0 {
            ref_l0.last().unwrap().clone()
        } else {
            make_block(block_num - 1)
        };
        ref_marf.begin(&parent, &block_hash).unwrap();
        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            ref_marf.insert(&key, val).unwrap();
        }
        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        ref_marf.insert("shared_key", shared_val).unwrap();
        ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();
    }

    let ext_block = {
        let mut b = [0u8; 32];
        b[0] = 0xEE;
        b[31] = 0xFF;
        StacksBlockId::from_bytes(&b).unwrap()
    };
    let l1_tip = all_blocks.last().unwrap().clone();

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.begin(&l1_tip, &ext_block).unwrap();
    for j in 0..keys_per_block {
        let key = format!("ext_key_{j}");
        let val = MARFValue::from_value(&format!("ext_val_{j}"));
        sq_marf.insert(&key, val).unwrap();
    }
    sq_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let sq_ext_root = sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();

    ref_marf.begin(&l1_tip, &ext_block).unwrap();
    for j in 0..keys_per_block {
        let key = format!("ext_key_{j}");
        let val = MARFValue::from_value(&format!("ext_val_{j}"));
        ref_marf.insert(&key, val).unwrap();
    }
    ref_marf
        .insert("shared_key", MARFValue::from_value("shared_ext"))
        .unwrap();
    let ref_ext_root = ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();

    eprintln!("--- L1 reclaim + fork prune: root hash comparison ---");
    eprintln!("  squashed ext root: {sq_ext_root}");
    eprintln!("  reference ext root: {ref_ext_root}");

    assert_eq!(
        sq_ext_root, ref_ext_root,
        "L1 reclaim with pruned L1-range fork blocks: root hash must match unsquashed reference"
    );
}

// ===========================================================================
// Squash blob size limit — checked arithmetic, stub levels, DFS classification
// ===========================================================================

#[test]
fn test_checked_offset_add_overflow() {
    use crate::chainstate::stacks::index::squash::checked_offset_add;

    // Normal addition should succeed
    assert_eq!(checked_offset_add(100, 200).unwrap(), 300);
    assert_eq!(checked_offset_add(0, 0).unwrap(), 0);

    // u32 overflow should fail
    let result = checked_offset_add(u32::MAX, 1);
    assert!(result.is_err(), "u32 overflow should return error");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("overflow"),
        "error should mention overflow: {err_msg}"
    );

    // Exceeding MAX_SQUASH_NODE_REGION_SIZE should fail (even without u32 overflow)
    use crate::chainstate::stacks::index::squash::MAX_SQUASH_NODE_REGION_SIZE;
    let just_under = MAX_SQUASH_NODE_REGION_SIZE as u32;
    let result = checked_offset_add(just_under, 1);
    assert!(
        result.is_err(),
        "exceeding MAX_SQUASH_NODE_REGION_SIZE should return error"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("MAX_SQUASH_NODE_REGION_SIZE"),
        "error should mention cap: {err_msg}"
    );

    // Exactly at the cap should succeed (cap is exclusive — the check is >)
    let at_cap = MAX_SQUASH_NODE_REGION_SIZE as u32;
    let result = checked_offset_add(at_cap - 1, 1);
    assert_eq!(result.unwrap(), at_cap);
}

#[test]
fn test_stub_level_creation_and_loading() {
    use crate::chainstate::stacks::index::squash::create_stub_level;
    use crate::chainstate::stacks::index::trie_sql;

    let test_dir = fresh_test_dir("test_stub_level_creation_and_loading");
    let marf_path = format!("{test_dir}/marf.sqlite");

    // Build a MARF with a few blocks so there's per-block blob data.
    let num_blocks = 5;
    let (src_marf, blocks, _expected) = setup_squash_source_marf(&marf_path, num_blocks, 3);
    drop(src_marf);

    // Record blob file size before stub creation.
    let blobs_path = format!("{marf_path}.blobs");
    let blob_size_before = std::fs::metadata(&blobs_path).unwrap().len();
    assert!(blob_size_before > 0, "per-block blobs should exist");

    // Create a stub level covering the full range.
    create_stub_level::<StacksBlockId>(&marf_path, 0, (num_blocks - 1) as u32)
        .expect("create_stub_level should succeed");

    // Blob file should be unchanged (no blob data written for the stub).
    let blob_size_after = std::fs::metadata(&blobs_path).unwrap().len();
    assert_eq!(
        blob_size_before, blob_size_after,
        "stub should not write any blob data"
    );

    // Verify the SQL row.
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts).unwrap();
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1);
    assert_eq!(levels[0].level_id, 0);
    assert_eq!(levels[0].min_height, 0);
    assert_eq!(levels[0].max_height, (num_blocks - 1) as u32);
    assert_eq!(levels[0].blob_length, 0, "stub should have blob_length=0");
    assert_eq!(
        levels[0].blob_offset, blob_size_before,
        "stub blob_offset should be the end of existing blob data"
    );
    assert!(!levels[0].reads_redirected);

    // Verify that squash_block_index has NO entries from the stub
    // (blocks in the stub range should NOT be indexed).
    assert!(
        marf.storage.data.squash_block_index.is_empty(),
        "squash_block_index should be empty for a stub-only MARF"
    );

    // Verify that reads still work via original per-block blobs.
    let tip = &blocks[num_blocks - 1];
    let val = marf.get(tip, "key_0").unwrap();
    assert!(
        val.is_some(),
        "key_0 should be readable from stub-range block"
    );
}

#[test]
fn test_squash_after_stub_with_reclaim() {
    use crate::chainstate::stacks::index::squash::{create_stub_level, squash_level_incremental};

    let test_dir = fresh_test_dir("test_squash_after_stub_with_reclaim");
    let marf_path = format!("{test_dir}/marf.sqlite");

    let l0_blocks = 5;
    let keys_per_block = 3;

    // Phase 1: Build MARF and create a stub level for blocks 0..4.
    let (src_marf, blocks_l0, _) = setup_squash_source_marf(&marf_path, l0_blocks, keys_per_block);
    drop(src_marf);

    create_stub_level::<StacksBlockId>(&marf_path, 0, (l0_blocks - 1) as u32)
        .expect("create_stub_level");

    // Phase 2: Add more blocks (5..=9) on the MARF that now has a stub.
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts).unwrap();

    let l1_blocks = 5;
    let mut blocks_l1: Vec<StacksBlockId> = Vec::new();
    let mut expected: HashMap<String, MARFValue> = HashMap::new();

    // Collect existing state from the stub range tip.
    let l0_tip = &blocks_l0[l0_blocks - 1];
    for j in 0..(l0_blocks * keys_per_block) {
        let key = format!("key_{j}");
        if let Some(v) = marf.get(l0_tip, &key).unwrap() {
            expected.insert(key, v);
        }
    }
    if let Some(v) = marf.get(l0_tip, "shared_key").unwrap() {
        expected.insert("shared_key".to_string(), v);
    }

    let prev_tip = blocks_l0[l0_blocks - 1].clone();
    for i in 0..l1_blocks {
        let block_num = l0_blocks + i;
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((block_num as u32) + 1).to_be_bytes());
        let block_hash = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 { &prev_tip } else { &blocks_l1[i - 1] };
        marf.begin(parent, &block_hash).unwrap();

        for j in 0..keys_per_block {
            let key_index = block_num * keys_per_block + j;
            let key = format!("key_{key_index}");
            let val = MARFValue::from_value(&format!("val_{key_index}_at_{block_num}"));
            marf.insert(&key, val.clone()).unwrap();
            expected.insert(key, val);
        }

        let shared_val = MARFValue::from_value(&format!("shared_at_{block_num}"));
        marf.insert("shared_key", shared_val.clone()).unwrap();
        expected.insert("shared_key".to_string(), shared_val);

        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks_l1.push(block_hash);
    }
    drop(marf);

    // Record blob file size before the real squash.
    let blobs_path = format!("{marf_path}.blobs");
    let size_before = std::fs::metadata(&blobs_path).unwrap().len();

    // Phase 3: Incremental squash with reclaim for L1 range (5..=9).
    let l1_min = l0_blocks as u32;
    let l1_max = (l0_blocks + l1_blocks - 1) as u32;
    let stats = squash_level_incremental::<StacksBlockId>(
        &marf_path,
        SquashMode::TipOnly,
        l1_min,
        l1_max,
        true, // reclaim
    )
    .expect("incremental squash after stub should succeed");

    assert!(stats.nodes_collected > 0);

    // The blob file should have been modified (new level blob written at file_end).
    let size_after = std::fs::metadata(&blobs_path).unwrap().len();
    // With reclaim, the file is truncated to end of the new level blob.
    // But the stub's per-block data (before blob_offset) must be preserved.
    // We can't easily assert size_after < size_before here because the new
    // level blob may be larger than the L1 per-block blobs. What we CAN
    // verify is that reads work correctly.

    // Phase 4: Reopen and verify all keys are readable.
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts).unwrap();
    let final_tip = &blocks_l1[l1_blocks - 1];

    for (key, expected_value) in &expected {
        let result = marf
            .get(final_tip, key)
            .unwrap_or_else(|e| panic!("failed to get key '{key}' after stub + squash: {e}"));
        assert_eq!(
            result,
            Some(expected_value.clone()),
            "key '{key}' should have expected value after stub + squash + reclaim"
        );
    }

    // Verify two levels exist: stub (level 0) + real (level 1).
    let levels =
        crate::chainstate::stacks::index::trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 2, "should have stub + real level");
    assert_eq!(levels[0].blob_length, 0, "level 0 should be stub");
    assert!(levels[1].blob_length > 0, "level 1 should be real");

    // The real level's blob_offset should be >= the stub's blob_offset
    // (i.e., after all per-block data).
    assert!(
        levels[1].blob_offset >= levels[0].blob_offset,
        "real level blob should be at or after stub's blob_offset boundary"
    );
}

#[test]
fn test_reclaim_after_stub_preserves_per_block_data() {
    use crate::chainstate::stacks::index::squash::{create_stub_level, squash_level_incremental};

    let test_dir = fresh_test_dir("test_reclaim_after_stub_preserves_per_block");
    let marf_path = format!("{test_dir}/marf.sqlite");

    // Build 10 blocks, stub the first 5, squash 5..=9 with reclaim.
    let total_blocks = 10;
    let stub_max = 4u32;
    let (src_marf, blocks, _) = setup_squash_source_marf(&marf_path, total_blocks, 2);
    drop(src_marf);

    create_stub_level::<StacksBlockId>(&marf_path, 0, stub_max).expect("create_stub_level");

    let stats = squash_level_incremental::<StacksBlockId>(
        &marf_path,
        SquashMode::TipOnly,
        stub_max + 1,
        (total_blocks - 1) as u32,
        true,
    )
    .expect("squash after stub");

    assert!(stats.nodes_collected > 0);

    // Reopen and verify reads from BOTH ranges work:
    // - Stub range (0..=4): reads from original per-block blobs
    // - Real level (5..=9): reads from squash blob
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts).unwrap();
    let tip = &blocks[total_blocks - 1];

    // Keys from block 0 should still be readable (stub range, per-block blobs).
    let val = marf.get(tip, "key_0").unwrap();
    assert!(
        val.is_some(),
        "key_0 from stub range should be readable after reclaim"
    );

    // Keys from block 9 should be readable (real squash level).
    let key_from_l1 = format!("key_{}", 9 * 2); // block 9, first key
    let val = marf.get(tip, &key_from_l1).unwrap();
    assert!(
        val.is_some(),
        "key from real level should be readable after reclaim"
    );

    // Shared key should reflect the latest write.
    let shared = marf.get(tip, "shared_key").unwrap();
    assert!(shared.is_some());
}

#[test]
fn test_late_enablement_stub_threshold() {
    use crate::chainstate::stacks::index::squash::{create_stub_level, STUB_THRESHOLD};
    use crate::chainstate::stacks::index::trie_sql;

    // This test verifies the threshold arithmetic, not the full maybe_squash
    // integration (which requires StacksChainState setup). We verify that
    // the detection condition works correctly.

    // Simulate: no existing levels, tip_height = 60_000, min = 0
    let tip_height: u32 = 60_000;
    let min_height: u32 = 0;
    let block_count = (tip_height as u64) - (min_height as u64) + 1;

    // block_count = 60_001 > STUB_THRESHOLD (50_000) → should stub
    assert!(
        min_height == 0 && block_count > STUB_THRESHOLD,
        "60,001 blocks should exceed STUB_THRESHOLD={STUB_THRESHOLD}"
    );

    // Simulate: existing levels present, min > 0 → should NOT stub
    let min_with_levels: u32 = 1001;
    let block_count_with_levels = (tip_height as u64) - (min_with_levels as u64) + 1;
    assert!(
        !(min_with_levels == 0 && block_count_with_levels > STUB_THRESHOLD),
        "should not stub when prior levels exist (min > 0)"
    );

    // Simulate: no levels but range is small (tip=100) → should NOT stub
    let small_tip: u32 = 100;
    let small_count = (small_tip as u64) - (0u64) + 1;
    assert!(
        !(0 == 0 && small_count > STUB_THRESHOLD),
        "should not stub when range is under threshold"
    );

    // Actually create a stub and verify it satisfies the contiguity
    // precondition for a subsequent squash.
    let test_dir = fresh_test_dir("test_late_enablement_stub_threshold");
    let marf_path = format!("{test_dir}/marf.sqlite");

    let num_blocks = 10;
    let (src_marf, _blocks, _) = setup_squash_source_marf(&marf_path, num_blocks, 2);
    drop(src_marf);

    create_stub_level::<StacksBlockId>(&marf_path, 0, (num_blocks - 1) as u32)
        .expect("stub creation");

    // After stub, squash_min_height_for_marf would return stub.max_height + 1.
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts).unwrap();
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1);
    let next_min = levels.last().unwrap().max_height + 1;
    assert_eq!(
        next_min, num_blocks as u32,
        "next squash should start at stub.max_height + 1"
    );

    // Calling create_stub_level again should fail — levels already exist.
    drop(marf);
    let err = create_stub_level::<StacksBlockId>(&marf_path, 0, (num_blocks - 1) as u32)
        .expect_err("second stub creation should fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("already exist"),
        "error should mention existing levels: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Phase 1: History collection tests
// ---------------------------------------------------------------------------

/// Test that `collect_history` correctly reconstructs key hashes via path
/// accumulation and that the reconstructed hashes match `TrieHash::from_key`.
#[test]
fn test_collect_history_path_reconstruction() {
    let test_dir = fresh_test_dir("test_collect_history_path_reconstruction");
    let src_path = format!("{test_dir}/source.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();

    let blocks: Vec<StacksBlockId> = (0..3)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Block 0: write key_a, key_b
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    marf.insert("key_a", MARFValue::from_value("a_at_0"))
        .unwrap();
    marf.insert("key_b", MARFValue::from_value("b_at_0"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    // Block 1: write key_a again (different value), key_c new
    marf.begin(&blocks[0], &blocks[1]).unwrap();
    marf.insert("key_a", MARFValue::from_value("a_at_1"))
        .unwrap();
    marf.insert("key_c", MARFValue::from_value("c_at_1"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    // Block 2: write key_b again (different value)
    marf.begin(&blocks[1], &blocks[2]).unwrap();
    marf.insert("key_b", MARFValue::from_value("b_at_2"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    let history = collect_history(&mut marf, &blocks, 0, 2).unwrap();

    // Verify key_a: written at block 0 and 1 with different values
    let key_a_hash = TrieHash::from_key("key_a");
    let key_a_entries = history
        .get(&key_a_hash)
        .expect("key_a should be in history");
    assert_eq!(key_a_entries.len(), 2, "key_a should have 2 transitions");
    assert_eq!(key_a_entries[0].0, 0, "key_a first write at height 0");
    assert_eq!(key_a_entries[0].1, MARFValue::from_value("a_at_0"));
    assert_eq!(key_a_entries[1].0, 1, "key_a second write at height 1");
    assert_eq!(key_a_entries[1].1, MARFValue::from_value("a_at_1"));

    // Verify key_b: written at block 0 and 2 with different values
    let key_b_hash = TrieHash::from_key("key_b");
    let key_b_entries = history
        .get(&key_b_hash)
        .expect("key_b should be in history");
    assert_eq!(key_b_entries.len(), 2, "key_b should have 2 transitions");
    assert_eq!(key_b_entries[0].0, 0);
    assert_eq!(key_b_entries[0].1, MARFValue::from_value("b_at_0"));
    assert_eq!(key_b_entries[1].0, 2);
    assert_eq!(key_b_entries[1].1, MARFValue::from_value("b_at_2"));

    // Verify key_c: written only at block 1
    let key_c_hash = TrieHash::from_key("key_c");
    let key_c_entries = history
        .get(&key_c_hash)
        .expect("key_c should be in history");
    assert_eq!(key_c_entries.len(), 1, "key_c should have 1 transition");
    assert_eq!(key_c_entries[0].0, 1);
    assert_eq!(key_c_entries[0].1, MARFValue::from_value("c_at_1"));
}

/// Test that `OWN_BLOCK_HEIGHT_KEY` is excluded from the history map.
#[test]
fn test_collect_history_filters_own_block_height_key() {
    let test_dir = fresh_test_dir("test_collect_history_filters_own_block_height");
    let src_path = format!("{test_dir}/source.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts).unwrap();

    let blocks: Vec<StacksBlockId> = (0..3)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Create 3 blocks with a user key
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    marf.insert("user_key", MARFValue::from_value("val_0"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    marf.begin(&blocks[0], &blocks[1]).unwrap();
    marf.insert("user_key", MARFValue::from_value("val_1"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    marf.begin(&blocks[1], &blocks[2]).unwrap();
    marf.insert("user_key", MARFValue::from_value("val_2"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    let history = collect_history(&mut marf, &blocks, 0, 2).unwrap();

    // OWN_BLOCK_HEIGHT_KEY is written internally at every block — verify it's filtered.
    let own_key_hash = TrieHash::from_key(OWN_BLOCK_HEIGHT_KEY);
    assert!(
        !history.contains_key(&own_key_hash),
        "OWN_BLOCK_HEIGHT_KEY should be filtered from history"
    );

    // The user key should be present.
    let user_key_hash = TrieHash::from_key("user_key");
    assert!(
        history.contains_key(&user_key_hash),
        "user_key should be in history"
    );
}

/// Test that structural rewrites (promote_leaf_to_node4) are deduplicated:
/// if a key is COW-copied into a block with the same value (structural rewrite),
/// it should NOT produce an extra history entry.
#[test]
fn test_collect_history_dedup_structural_rewrites() {
    let test_dir = fresh_test_dir("test_collect_history_dedup_structural_rewrites");
    let src_path = format!("{test_dir}/source.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts).unwrap();

    let blocks: Vec<StacksBlockId> = (0..5)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Block 0: write key_x
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    marf.insert("key_x", MARFValue::from_value("x_val"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    // Blocks 1-4: write different keys that share a prefix with key_x.
    // This may trigger promote_leaf_to_node4 which COW-copies key_x's leaf
    // with the same value. The dedup filter should collapse these.
    for i in 1..5 {
        marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
        // Write a new key that could share prefix structure with key_x
        let new_key = format!("key_x_{i}");
        marf.insert(&new_key, MARFValue::from_value(&format!("new_val_{i}")))
            .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
    }

    let history = collect_history(&mut marf, &blocks, 0, 4).unwrap();

    // key_x was written once at block 0 and never changed. Even if it was
    // structurally rewritten (COW-copied), the dedup filter should collapse
    // it to a single entry.
    let key_x_hash = TrieHash::from_key("key_x");
    let key_x_entries = history
        .get(&key_x_hash)
        .expect("key_x should be in history");
    assert_eq!(
        key_x_entries.len(),
        1,
        "key_x should have exactly 1 transition (dedup filtered structural rewrites), got {}",
        key_x_entries.len()
    );
    assert_eq!(
        key_x_entries[0].0, 0,
        "key_x only real write was at height 0"
    );
    assert_eq!(key_x_entries[0].1, MARFValue::from_value("x_val"));
}

/// Test that the history map entries are sorted ascending by height.
#[test]
fn test_collect_history_ascending_sort() {
    let test_dir = fresh_test_dir("test_collect_history_ascending_sort");
    let src_path = format!("{test_dir}/source.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts).unwrap();

    let num_blocks = 10;
    let blocks: Vec<StacksBlockId> = (0..num_blocks)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Write "hot_key" at every block with a different value
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    marf.insert("hot_key", MARFValue::from_value("hot_val_0"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    for i in 1..num_blocks {
        marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
        marf.insert("hot_key", MARFValue::from_value(&format!("hot_val_{i}")))
            .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
    }

    let history = collect_history(&mut marf, &blocks, 0, (num_blocks - 1) as u32).unwrap();

    let hot_key_hash = TrieHash::from_key("hot_key");
    let entries = history
        .get(&hot_key_hash)
        .expect("hot_key should be in history");
    assert_eq!(
        entries.len(),
        num_blocks,
        "hot_key should have {num_blocks} transitions"
    );

    // Verify ascending sort
    for i in 1..entries.len() {
        assert!(
            entries[i].0 > entries[i - 1].0,
            "entries should be sorted ascending by height: {} > {} failed",
            entries[i].0,
            entries[i - 1].0
        );
    }
}

/// Test TrieLeafSquashed::new entry count guard.
#[test]
fn test_leaf_squashed_entry_count_guard() {
    let path_bytes = [0u8; 32];

    // MAX_ENTRIES should succeed
    let max_entries: Vec<(u32, MARFValue)> = (0..TrieLeafSquashed::MAX_ENTRIES as u32)
        .rev()
        .map(|h| (h, MARFValue([0x11u8; 40])))
        .collect();
    assert!(
        TrieLeafSquashed::new(&path_bytes, max_entries).is_ok(),
        "MAX_ENTRIES entries should be accepted"
    );

    // MAX_ENTRIES + 1 should fail
    let over_entries: Vec<(u32, MARFValue)> = (0..=(TrieLeafSquashed::MAX_ENTRIES as u32))
        .rev()
        .map(|h| (h, MARFValue([0x22u8; 40])))
        .collect();
    let err = TrieLeafSquashed::new(&path_bytes, over_entries);
    assert!(err.is_err(), "MAX_ENTRIES + 1 entries should be rejected");
}

/// Regression test for `BLOCK_*` mapping keys.
///
/// `set_block_heights` writes each `BLOCK_HEIGHT_TO_HASH_MAPPING_KEY::{h}`
/// and `BLOCK_HASH_TO_HEIGHT_MAPPING_KEY::{bhh}` twice on the canonical
/// chain (once for the current block, once to re-confirm the previous
/// block's entry) with identical values. The value-equality dedup in
/// `collect_history` must collapse these double-writes to a single
/// history transition per key.
#[test]
fn test_collect_history_block_star_dedup() {
    let test_dir = fresh_test_dir("test_collect_history_block_star_dedup");
    let src_path = format!("{test_dir}/source.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts).unwrap();

    let num_blocks: usize = 5;
    let blocks: Vec<StacksBlockId> = (0..num_blocks)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Create blocks with a user key so the trie has user content too.
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    marf.insert("user_key", MARFValue::from_value("u0"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    for i in 1..num_blocks {
        marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
        marf.insert("user_key", MARFValue::from_value(&format!("u{i}")))
            .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
    }

    let history = collect_history(&mut marf, &blocks, 0, (num_blocks - 1) as u32).unwrap();

    // Check every BLOCK_HEIGHT_TO_HASH key: each should have exactly 1
    // transition after dedup (the re-confirmation write is value-identical).
    for h in 0..num_blocks {
        let key = format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{h}");
        let key_hash = TrieHash::from_key(&key);
        if let Some(entries) = history.get(&key_hash) {
            assert_eq!(
                entries.len(),
                1,
                "BLOCK_HEIGHT_TO_HASH key at height {h} should dedup to 1 transition, got {}",
                entries.len()
            );
        }
        // A key might not appear if it was only written at a height outside
        // the range, or if both writes landed in the same block (height 0).
    }

    // Check every BLOCK_HASH_TO_HEIGHT key similarly.
    for block in &blocks {
        let key = format!("{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{block}");
        let key_hash = TrieHash::from_key(&key);
        if let Some(entries) = history.get(&key_hash) {
            assert_eq!(
                entries.len(),
                1,
                "BLOCK_HASH_TO_HEIGHT key for {block} should dedup to 1 transition, got {}",
                entries.len()
            );
        }
    }

    // Verify OWN_BLOCK_HEIGHT_KEY is still filtered out.
    let own_key_hash = TrieHash::from_key(OWN_BLOCK_HEIGHT_KEY);
    assert!(
        !history.contains_key(&own_key_hash),
        "OWN_BLOCK_HEIGHT_KEY should be filtered from history"
    );
}

/// Benchmark: measure `collect_history` wall-clock time at representative
/// block counts. Run with `--ignored --nocapture` to see output.
///
/// This is an `#[ignore]`d test rather than a criterion bench because
/// stackslib does not depend on criterion and the test is too expensive
/// for CI.
#[test]
#[ignore]
fn bench_collect_history_wall_clock() {
    use std::time::Instant;

    // Representative block counts — small enough to run locally,
    // large enough to measure.
    let block_counts: &[usize] = &[100, 500, 1000];
    // Keys per block: a realistic mix of hot (every-block) and cold keys.
    let keys_per_block = 20;

    for &num_blocks in block_counts {
        let test_dir = fresh_test_dir(&format!("bench_collect_history_{num_blocks}"));
        let src_path = format!("{test_dir}/source.sqlite");

        let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
        let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts).unwrap();

        let blocks: Vec<StacksBlockId> = (0..num_blocks)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
                StacksBlockId::from_bytes(&bytes).unwrap()
            })
            .collect();

        // Populate: write `keys_per_block` keys per block.
        // Half are "hot" (updated every block), half are "cold" (written once).
        let hot_count = keys_per_block / 2;
        let cold_count = keys_per_block - hot_count;

        let setup_start = Instant::now();
        for (idx, block) in blocks.iter().enumerate() {
            let parent = if idx == 0 {
                StacksBlockId::sentinel()
            } else {
                blocks[idx - 1].clone()
            };
            marf.begin(&parent, block).unwrap();
            // Hot keys: same key names, value changes each block.
            for k in 0..hot_count {
                let key = format!("hot_key_{k:04}");
                let val = MARFValue::from_value(&format!("h{k}_{idx}"));
                marf.insert(&key, val).unwrap();
            }
            // Cold keys: unique key name per block.
            for k in 0..cold_count {
                let key = format!("cold_key_{idx:06}_{k:04}");
                let val = MARFValue::from_value(&format!("c{k}_{idx}"));
                marf.insert(&key, val).unwrap();
            }
            marf.seal().unwrap();
            marf.commit().unwrap();
        }
        let setup_elapsed = setup_start.elapsed();

        // Measure history collection.
        let collect_start = Instant::now();
        let history = collect_history(&mut marf, &blocks, 0, (num_blocks - 1) as u32).unwrap();
        let collect_elapsed = collect_start.elapsed();

        let total_entries: usize = history.values().map(|v| v.len()).sum();

        // Print stats — visible with --nocapture.
        eprintln!(
            "blocks={num_blocks:>5}  keys={}  entries={}  setup={:.2?}  collect={:.2?}",
            history.len(),
            total_entries,
            setup_elapsed,
            collect_elapsed,
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 2: FullHistory blob write tests
// ---------------------------------------------------------------------------

/// Basic end-to-end test: squash with FullHistory mode, verify stats,
/// tip reads, and trailer mode.
#[test]
fn test_squash_full_history_basic() {
    let test_dir = fresh_test_dir("test_squash_full_history_basic");
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let num_blocks = 5;
    let keys_per_block = 3;

    let (marf, blocks, expected_tip_state) =
        setup_squash_source_marf(&src_path, num_blocks, keys_per_block);
    drop(marf);

    let stats = squash_to_path::<StacksBlockId>(
        &src_path,
        &dst_path,
        SquashMode::FullHistory,
        (num_blocks - 1) as u32,
    )
    .expect("squash_to_path with FullHistory should succeed");

    // The setup writes "shared_key" at every block with a different value.
    // That's num_blocks transitions → TrieLeafSquashed should be emitted.
    assert!(
        stats.leaves_squashed > 0,
        "FullHistory squash should produce at least one TrieLeafSquashed, got 0"
    );

    // Verify tip reads still work
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();
    let tip_block = &blocks[num_blocks - 1];

    for (key, expected_value) in &expected_tip_state {
        let result = dst_marf
            .get(tip_block, key)
            .unwrap_or_else(|e| panic!("Failed to get key '{key}' from squashed MARF: {e}"));
        assert_eq!(
            result,
            Some(expected_value.clone()),
            "key '{key}' should have the expected value in FullHistory squashed MARF"
        );
    }

    // Verify the trailer has FullHistory mode
    let levels =
        crate::chainstate::stacks::index::trie_sql::read_squash_levels(dst_marf.sqlite_conn())
            .unwrap();
    assert_eq!(levels.len(), 1, "should have exactly 1 squash level");
    assert_eq!(levels[0].min_height, 0);
    assert_eq!(levels[0].max_height, (num_blocks - 1) as u32);

    // Read the trailer from the blob to verify mode
    let blob_path = format!("{dst_path}.blobs");
    let blob_bytes = std::fs::read(&blob_path).expect("should read blob file");
    let blob_offset = levels[0].blob_offset as usize;
    let blob_end = blob_offset + levels[0].blob_length as usize;
    let blob_slice = &blob_bytes[blob_offset..blob_end];

    let footer_offset =
        SquashTrailer::read_footer(blob_slice).expect("should find trailer footer in blob");
    let trailer_end = blob_slice.len() - SQUASH_FOOTER_SIZE;
    let trailer = SquashTrailer::read_from(&blob_slice[footer_offset as usize..trailer_end])
        .expect("should parse trailer");

    assert_eq!(
        trailer.info.mode,
        SquashMode::FullHistory,
        "trailer mode should be FullHistory"
    );
}

/// Verify the blob actually contains TrieLeafSquashed nodes for multi-
/// transition keys and TrieLeaf for single-write keys. Scans the raw
/// blob and decodes each node to check its type and entry contents.
#[test]
fn test_squash_full_history_blob_contains_leaf_squashed() {
    let test_dir = fresh_test_dir("test_squash_full_history_blob_leaf_squashed");
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();

    let num_blocks = 4;
    let blocks: Vec<StacksBlockId> = (0..num_blocks)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Block 0: write hot_key and cold_key
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    marf.insert("hot_key", MARFValue::from_value("hot_0"))
        .unwrap();
    marf.insert("cold_key", MARFValue::from_value("cold_0"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    // Blocks 1-3: update hot_key each block, cold_key stays the same
    for i in 1..num_blocks {
        marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
        marf.insert("hot_key", MARFValue::from_value(&format!("hot_{i}")))
            .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
    }
    drop(marf);

    let stats = squash_to_path::<StacksBlockId>(
        &src_path,
        &dst_path,
        SquashMode::FullHistory,
        (num_blocks - 1) as u32,
    )
    .expect("squash with FullHistory should succeed");

    assert!(
        stats.leaves_squashed > 0,
        "should have replaced at least 1 leaf with TrieLeafSquashed"
    );

    // Scan the blob to find TrieLeafSquashed nodes
    let blob_path = format!("{dst_path}.blobs");
    let blob_bytes = std::fs::read(&blob_path).expect("should read blob file");

    let dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();
    let levels =
        crate::chainstate::stacks::index::trie_sql::read_squash_levels(dst_marf.sqlite_conn())
            .unwrap();
    drop(dst_marf);

    let blob_start = levels[0].blob_offset as usize;

    // Read the trailer to find where nodes end (trailer_offset is relative to blob start)
    let blob_end = blob_start + levels[0].blob_length as usize;
    let blob_slice = &blob_bytes[blob_start..blob_end];
    let trailer_offset =
        SquashTrailer::read_footer(blob_slice).expect("should find trailer footer") as usize;

    // Scan sequential nodes: skip header (36 bytes), each node is hash(32) + body
    let header_size = 36usize;
    let mut pos = header_size;
    let nodes_end = trailer_offset;

    let mut leaf_squashed_count = 0usize;
    let mut plain_leaf_count = 0usize;
    let mut internal_count = 0usize;

    while pos < nodes_end {
        // Read hash
        if pos + TRIEHASH_ENCODED_SIZE > nodes_end {
            break;
        }
        let body_start = pos + TRIEHASH_ENCODED_SIZE;
        if body_start >= nodes_end {
            break;
        }
        let node_body = &blob_slice[body_start..nodes_end];

        // Decode node type from body
        let node_id_byte = node_body[0];
        let node_id = clear_backptr(node_id_byte) & 0x3f;
        let (node, consumed) = bits::decode_nodetype_from_slice_at_head(node_body, node_id)
            .unwrap_or_else(|e| panic!("Failed to decode node at blob offset {pos}: {e}"));

        let total_node_size = TRIEHASH_ENCODED_SIZE + consumed;

        match &node {
            TrieNodeType::LeafSquashed(sq) => {
                leaf_squashed_count += 1;
                // Verify entries are sorted descending by height
                for w in sq.entries.windows(2) {
                    assert!(
                        w[0].0 > w[1].0,
                        "TrieLeafSquashed entries should be sorted descending: {} > {} failed",
                        w[0].0,
                        w[1].0
                    );
                }
                // Verify exact (height, value) contents for hot_key.
                // hot_key was written at blocks 0-3 with values "hot_0" .. "hot_3",
                // so we expect 4 entries in descending height order.
                assert_eq!(
                    sq.entries.len(),
                    num_blocks,
                    "TrieLeafSquashed should have exactly {num_blocks} entries for hot_key"
                );
                for (idx, &(height, ref value)) in sq.entries.iter().enumerate() {
                    let expected_height = (num_blocks - 1 - idx) as u32;
                    let expected_value = MARFValue::from_value(&format!("hot_{expected_height}"));
                    assert_eq!(
                        height, expected_height,
                        "entry[{idx}] height: expected {expected_height}, got {height}"
                    );
                    assert_eq!(
                        *value, expected_value,
                        "entry[{idx}] value mismatch at height {height}"
                    );
                }
            }
            TrieNodeType::Leaf(_) => {
                plain_leaf_count += 1;
            }
            _ => {
                internal_count += 1;
            }
        }

        pos += total_node_size;
    }

    assert!(
        leaf_squashed_count > 0,
        "blob should contain at least one TrieLeafSquashed node"
    );
    assert!(
        plain_leaf_count > 0,
        "blob should contain at least one plain TrieLeaf node (cold_key or internal keys)"
    );

    eprintln!(
        "Blob scan: {} LeafSquashed, {} Leaf, {} internal",
        leaf_squashed_count, plain_leaf_count, internal_count
    );
}

/// Verify that squashing with FullHistory produces the same root hashes
/// as TipOnly (the Merkle hash model is identical — hash covers tip value only).
#[test]
fn test_squash_full_history_root_hashes_match_tip_only() {
    let test_dir = fresh_test_dir("test_squash_full_history_roots_match");
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_tip = format!("{test_dir}/squashed_tip.sqlite");
    let dst_full = format!("{test_dir}/squashed_full.sqlite");

    let num_blocks = 5;
    let keys_per_block = 3;

    let (marf, blocks, _) = setup_squash_source_marf(&src_path, num_blocks, keys_per_block);
    drop(marf);

    let max_height = (num_blocks - 1) as u32;

    // Squash with TipOnly
    squash_to_path::<StacksBlockId>(&src_path, &dst_tip, SquashMode::TipOnly, max_height)
        .expect("TipOnly squash should succeed");

    // Squash with FullHistory
    squash_to_path::<StacksBlockId>(&src_path, &dst_full, SquashMode::FullHistory, max_height)
        .expect("FullHistory squash should succeed");

    // Compare root hashes at every height
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut tip_marf = MARF::<StacksBlockId>::from_path(&dst_tip, open_opts.clone()).unwrap();
    let mut full_marf = MARF::<StacksBlockId>::from_path(&dst_full, open_opts).unwrap();

    for block in &blocks {
        let tip_root = tip_marf.get_root_hash_at(block).unwrap();
        let full_root = full_marf.get_root_hash_at(block).unwrap();
        assert_eq!(
            tip_root, full_root,
            "Root hash mismatch at block {block}: TipOnly={tip_root} FullHistory={full_root}"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 3: Read path integration tests
// ---------------------------------------------------------------------------

/// Open a FullHistory squash blob at various historical block hashes and
/// verify that `marf.get(historical_block, key)` returns the correct
/// point-in-time value for multi-transition keys.
#[test]
fn test_full_history_read_at_historical_heights() {
    let test_dir = fresh_test_dir("test_full_history_read_historical");
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();

    let num_blocks = 6;
    let blocks: Vec<StacksBlockId> = (0..num_blocks)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Block 0: write hot_key and cold_key
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    marf.insert("hot_key", MARFValue::from_value("hot_v0"))
        .unwrap();
    marf.insert("cold_key", MARFValue::from_value("cold_v0"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    // Blocks 1..5: update hot_key each block, cold_key stays the same
    for i in 1..num_blocks {
        marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
        marf.insert("hot_key", MARFValue::from_value(&format!("hot_v{i}")))
            .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
    }

    // Capture the expected values from the unsquashed MARF at each block
    let mut expected: Vec<(MARFValue, MARFValue)> = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let hot = marf
            .get(block, "hot_key")
            .unwrap()
            .unwrap_or_else(|| panic!("hot_key should exist at block {i}"));
        let cold = marf
            .get(block, "cold_key")
            .unwrap()
            .unwrap_or_else(|| panic!("cold_key should exist at block {i}"));
        expected.push((hot, cold));
    }
    drop(marf);

    // Squash with FullHistory
    squash_to_path::<StacksBlockId>(
        &src_path,
        &dst_path,
        SquashMode::FullHistory,
        (num_blocks - 1) as u32,
    )
    .expect("squash should succeed");

    // Open the squashed MARF and verify historical reads
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    for (i, block) in blocks.iter().enumerate() {
        let hot = dst_marf
            .get(block, "hot_key")
            .unwrap()
            .unwrap_or_else(|| panic!("hot_key should exist at block {i} in squashed MARF"));
        let cold = dst_marf
            .get(block, "cold_key")
            .unwrap()
            .unwrap_or_else(|| panic!("cold_key should exist at block {i} in squashed MARF"));

        assert_eq!(
            hot, expected[i].0,
            "hot_key mismatch at block {i}: got {hot:?}, expected {:?}",
            expected[i].0
        );
        assert_eq!(
            cold, expected[i].1,
            "cold_key mismatch at block {i}: got {cold:?}, expected {:?}",
            expected[i].1
        );
    }
}

/// Verify that `value_at_height` returns `None` for pre-first-write heights,
/// which propagates as `Ok(None)` (NotFoundError → None) through `marf.get`.
#[test]
fn test_full_history_read_before_first_write_returns_none() {
    let test_dir = fresh_test_dir("test_full_history_read_before_write");
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();

    let num_blocks = 4;
    let blocks: Vec<StacksBlockId> = (0..num_blocks)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Block 0: write early_key only
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    marf.insert("early_key", MARFValue::from_value("early_v0"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    // Block 1: no new keys
    marf.begin(&blocks[0], &blocks[1]).unwrap();
    marf.insert("early_key", MARFValue::from_value("early_v1"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    // Block 2: write late_key for the first time
    marf.begin(&blocks[1], &blocks[2]).unwrap();
    marf.insert("late_key", MARFValue::from_value("late_v2"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    // Block 3: update late_key
    marf.begin(&blocks[2], &blocks[3]).unwrap();
    marf.insert("late_key", MARFValue::from_value("late_v3"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();
    drop(marf);

    // Squash with FullHistory
    squash_to_path::<StacksBlockId>(
        &src_path,
        &dst_path,
        SquashMode::FullHistory,
        (num_blocks - 1) as u32,
    )
    .expect("squash should succeed");

    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    // late_key should not exist at blocks 0 and 1 (before it was written)
    assert_eq!(
        dst_marf.get(&blocks[0], "late_key").unwrap(),
        None,
        "late_key should not exist at block 0"
    );
    assert_eq!(
        dst_marf.get(&blocks[1], "late_key").unwrap(),
        None,
        "late_key should not exist at block 1"
    );

    // late_key should exist at blocks 2 and 3
    assert_eq!(
        dst_marf.get(&blocks[2], "late_key").unwrap(),
        Some(MARFValue::from_value("late_v2")),
        "late_key should be late_v2 at block 2"
    );
    assert_eq!(
        dst_marf.get(&blocks[3], "late_key").unwrap(),
        Some(MARFValue::from_value("late_v3")),
        "late_key should be late_v3 at block 3"
    );
}

/// Verify that tip reads through a FullHistory squash blob still return
/// the tip value (not a historical value) even though the underlying leaf
/// is a TrieLeafSquashed.
#[test]
fn test_full_history_tip_reads_return_tip_value() {
    let test_dir = fresh_test_dir("test_full_history_tip_reads");
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let num_blocks = 5;
    let keys_per_block = 3;

    let (marf, blocks, expected_tip_state) =
        setup_squash_source_marf(&src_path, num_blocks, keys_per_block);
    drop(marf);

    let max_height = (num_blocks - 1) as u32;
    squash_to_path::<StacksBlockId>(&src_path, &dst_path, SquashMode::FullHistory, max_height)
        .expect("squash should succeed");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut dst_marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();
    let tip_block = &blocks[num_blocks - 1];

    // Tip reads should return the tip value
    for (key, expected_value) in &expected_tip_state {
        let result = dst_marf
            .get(tip_block, key)
            .unwrap_or_else(|e| panic!("Failed to get key '{key}': {e}"));
        assert_eq!(
            result,
            Some(expected_value.clone()),
            "tip read for '{key}' should match expected tip value"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 4: Incremental squash with FullHistory
// ---------------------------------------------------------------------------

/// Two-level incremental squash with FullHistory: build L0 (blocks 0..4),
/// squash L0, add L1 blocks (5..9) that update a hot key each block,
/// squash L1 with FullHistory, verify historical reads across both levels.
#[test]
fn test_incremental_full_history_basic() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let test_dir = fresh_test_dir("test_incremental_full_history_basic");
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let l0_blocks: usize = 5;
    let l1_blocks: usize = 5;
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    // ── Build source MARF with L0 blocks ──
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();

    for i in 0..(l0_blocks + l1_blocks) {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[i - 1].clone()
        };
        marf.begin(&parent, &bh).unwrap();
        // hot_key updated every block
        marf.insert("hot_key", MARFValue::from_value(&format!("hot_v{i}")))
            .unwrap();
        // cold_key written only at block 0
        if i == 0 {
            marf.insert("cold_key", MARFValue::from_value("cold_v0"))
                .unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }

    // Capture expected values from unsquashed MARF at every block
    let mut expected_hot: Vec<MARFValue> = Vec::new();
    let mut expected_cold: Vec<Option<MARFValue>> = Vec::new();
    for block in &blocks {
        expected_hot.push(marf.get(block, "hot_key").unwrap().unwrap());
        expected_cold.push(marf.get(block, "cold_key").unwrap());
    }
    drop(marf);

    // ── Squash L0 (blocks 0..4) with FullHistory ──
    squash_to_path::<StacksBlockId>(
        &src_path,
        &dst_path,
        SquashMode::FullHistory,
        (l0_blocks - 1) as u32,
    )
    .expect("L0 squash should succeed");

    // ── Commit L1 blocks onto squashed MARF ──
    // The L1 blocks are already in the source; we need them in the dst.
    // Simpler approach: copy the source before any squash, then squash in-place.
    // But setup_squash_source_marf writes to src_path. Let's use the already-
    // squashed dst and write L1 blocks on top of it. Since we already wrote all
    // blocks to the source, we need a different approach.
    //
    // Actually, let's re-approach: build all blocks in src, squash L0 to dst,
    // then for L1 we need the blocks in the dst file. The simplest way is:
    // build L0 blocks, squash L0, open squashed, commit L1 blocks, close, squash L1.

    // Let's redo this with two-phase write.
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();

    // Write L0 blocks
    for i in 0..l0_blocks {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[i - 1].clone()
        };
        marf.begin(&parent, &bh).unwrap();
        marf.insert("hot_key", MARFValue::from_value(&format!("hot_v{i}")))
            .unwrap();
        if i == 0 {
            marf.insert("cold_key", MARFValue::from_value("cold_v0"))
                .unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }
    drop(marf);

    // Squash L0 to dst
    squash_to_path::<StacksBlockId>(
        &src_path,
        &dst_path,
        SquashMode::FullHistory,
        (l0_blocks - 1) as u32,
    )
    .expect("L0 squash should succeed");

    // Write L1 blocks onto squashed dst
    let mut marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts.clone()).unwrap();
    for i in l0_blocks..(l0_blocks + l1_blocks) {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = blocks[i - 1].clone();
        marf.begin(&parent, &bh).unwrap();
        marf.insert("hot_key", MARFValue::from_value(&format!("hot_v{i}")))
            .unwrap();
        // cold_key not written in L1: inherited from L0
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }

    // Capture expected values before squash
    let mut expected_hot: Vec<MARFValue> = Vec::new();
    let mut expected_cold: Vec<Option<MARFValue>> = Vec::new();
    for block in &blocks {
        expected_hot.push(marf.get(block, "hot_key").unwrap().unwrap());
        expected_cold.push(marf.get(block, "cold_key").unwrap());
    }
    drop(marf);

    // Squash L1 incrementally with FullHistory
    let l1_stats = squash_level_incremental::<StacksBlockId>(
        &dst_path,
        SquashMode::FullHistory,
        l0_blocks as u32,
        (l0_blocks + l1_blocks - 1) as u32,
        false,
    )
    .expect("L1 incremental squash should succeed");

    assert!(l1_stats.nodes_collected > 0);
    assert!(
        l1_stats.leaves_squashed > 0,
        "hot_key should produce a TrieLeafSquashed"
    );

    // ── Verify historical reads across both levels ──
    let mut marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    for (i, block) in blocks.iter().enumerate() {
        let hot = marf
            .get(block, "hot_key")
            .unwrap()
            .unwrap_or_else(|| panic!("hot_key should exist at block {i}"));
        assert_eq!(hot, expected_hot[i], "hot_key mismatch at block {i}");

        let cold = marf.get(block, "cold_key").unwrap();
        assert_eq!(cold, expected_cold[i], "cold_key mismatch at block {i}");
    }

    // Verify two squash levels registered
    let levels =
        crate::chainstate::stacks::index::trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 2);
    assert_eq!(levels[0].min_height, 0);
    assert_eq!(levels[0].max_height, (l0_blocks - 1) as u32);
    assert_eq!(levels[1].min_height, l0_blocks as u32);
    assert_eq!(levels[1].max_height, (l0_blocks + l1_blocks - 1) as u32);
}

/// Verify baseline inheritance: a key written only in L0 is inherited by L1.
/// After incremental FullHistory squash of L1, reading the key at L1 heights
/// should return the L0 tip value (via the synthetic baseline entry).
#[test]
fn test_incremental_full_history_baseline_inheritance() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let test_dir = fresh_test_dir("test_incr_fh_baseline_inherit");
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let l0_blocks: usize = 3;
    let l1_blocks: usize = 3;
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    // Write L0 blocks: key_a written at block 0, updated at block 2
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();

    for i in 0..l0_blocks {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[i - 1].clone()
        };
        marf.begin(&parent, &bh).unwrap();
        if i == 0 {
            marf.insert("key_a", MARFValue::from_value("a_v0")).unwrap();
        }
        if i == 2 {
            marf.insert("key_a", MARFValue::from_value("a_v2")).unwrap();
        }
        // key_b written only at block 1
        if i == 1 {
            marf.insert("key_b", MARFValue::from_value("b_v1")).unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }
    drop(marf);

    // Squash L0 to dst with FullHistory
    squash_to_path::<StacksBlockId>(
        &src_path,
        &dst_path,
        SquashMode::FullHistory,
        (l0_blocks - 1) as u32,
    )
    .expect("L0 squash should succeed");

    // Write L1 blocks onto squashed dst: key_c is new, key_a and key_b are NOT updated
    let mut marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts.clone()).unwrap();

    for i in l0_blocks..(l0_blocks + l1_blocks) {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = blocks[i - 1].clone();
        marf.begin(&parent, &bh).unwrap();
        // Only key_c is written in L1
        marf.insert("key_c", MARFValue::from_value(&format!("c_v{i}")))
            .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }

    // Capture expected values before squash
    let l1_tip = &blocks[l0_blocks + l1_blocks - 1];
    let expected_a_at_tip = marf.get(l1_tip, "key_a").unwrap();
    let expected_b_at_tip = marf.get(l1_tip, "key_b").unwrap();
    drop(marf);

    // Squash L1 incrementally with FullHistory
    let l1_stats = squash_level_incremental::<StacksBlockId>(
        &dst_path,
        SquashMode::FullHistory,
        l0_blocks as u32,
        (l0_blocks + l1_blocks - 1) as u32,
        false,
    )
    .expect("L1 incremental squash should succeed");

    // key_a and key_b are inherited from L0 and never updated in L1, so they
    // should NOT be promoted to TrieLeafSquashed. Only key_c (which has real
    // transitions across L1 blocks) should be squashed.
    assert_eq!(
        l1_stats.leaves_squashed, 1,
        "only key_c should be squashed; inherited-only keys must stay as plain TrieLeaf"
    );

    // Verify reads
    let mut marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    // key_a and key_b should be readable at all L1 heights with inherited L0 values
    for i in l0_blocks..(l0_blocks + l1_blocks) {
        let a_val = marf.get(&blocks[i], "key_a").unwrap();
        assert_eq!(
            a_val, expected_a_at_tip,
            "key_a should be inherited at L1 block {i}"
        );

        let b_val = marf.get(&blocks[i], "key_b").unwrap();
        assert_eq!(
            b_val, expected_b_at_tip,
            "key_b should be inherited at L1 block {i}"
        );
    }

    // key_c should be readable with its L1 values
    for i in l0_blocks..(l0_blocks + l1_blocks) {
        let c_val = marf.get(&blocks[i], "key_c").unwrap();
        assert!(c_val.is_some(), "key_c should exist at block {i}");
    }

    // key_a should still be readable at L0 heights via L0 squash level
    let a_at_0 = marf.get(&blocks[0], "key_a").unwrap();
    assert_eq!(
        a_at_0,
        Some(MARFValue::from_value("a_v0")),
        "key_a at block 0 should have original value"
    );
    let a_at_2 = marf.get(&blocks[2], "key_a").unwrap();
    assert_eq!(
        a_at_2,
        Some(MARFValue::from_value("a_v2")),
        "key_a at block 2 should have updated value"
    );
}

/// Two-level incremental squash with FullHistory and `reclaim = true`.
/// Verifies that blob space is reclaimed and historical reads still work
/// across both levels after the L1 blob overwrites dead L1 per-block data.
#[test]
fn test_incremental_full_history_reclaim() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let test_dir = fresh_test_dir("test_incr_fh_reclaim");
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let l0_blocks: usize = 4;
    let l1_blocks: usize = 4;
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    // Build L0 blocks
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();

    for i in 0..l0_blocks {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[i - 1].clone()
        };
        marf.begin(&parent, &bh).unwrap();
        marf.insert("hot_key", MARFValue::from_value(&format!("hot_v{i}")))
            .unwrap();
        if i == 0 {
            marf.insert("cold_key", MARFValue::from_value("cold_v0"))
                .unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }
    drop(marf);

    // Squash L0 to dst with FullHistory
    squash_to_path::<StacksBlockId>(
        &src_path,
        &dst_path,
        SquashMode::FullHistory,
        (l0_blocks - 1) as u32,
    )
    .expect("L0 squash should succeed");

    // Write L1 blocks onto squashed dst
    let mut marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts.clone()).unwrap();
    for i in l0_blocks..(l0_blocks + l1_blocks) {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = blocks[i - 1].clone();
        marf.begin(&parent, &bh).unwrap();
        marf.insert("hot_key", MARFValue::from_value(&format!("hot_v{i}")))
            .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }

    // Capture expected values before squash
    let mut expected_hot: Vec<MARFValue> = Vec::new();
    let mut expected_cold: Vec<Option<MARFValue>> = Vec::new();
    for block in &blocks {
        expected_hot.push(marf.get(block, "hot_key").unwrap().unwrap());
        expected_cold.push(marf.get(block, "cold_key").unwrap());
    }
    drop(marf);

    // Squash L1 incrementally with FullHistory + reclaim
    let l1_stats = squash_level_incremental::<StacksBlockId>(
        &dst_path,
        SquashMode::FullHistory,
        l0_blocks as u32,
        (l0_blocks + l1_blocks - 1) as u32,
        true, // reclaim
    )
    .expect("L1 incremental squash with reclaim should succeed");

    assert!(l1_stats.nodes_collected > 0);
    assert!(l1_stats.leaves_squashed > 0, "hot_key should be squashed");

    // Verify historical reads across both levels after reclaim
    let mut marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    for (i, block) in blocks.iter().enumerate() {
        let hot = marf
            .get(block, "hot_key")
            .unwrap()
            .unwrap_or_else(|| panic!("hot_key should exist at block {i}"));
        assert_eq!(hot, expected_hot[i], "hot_key mismatch at block {i}");

        let cold = marf.get(block, "cold_key").unwrap();
        assert_eq!(cold, expected_cold[i], "cold_key mismatch at block {i}");
    }

    // Verify both levels registered with reclaim flag on L1
    let levels =
        crate::chainstate::stacks::index::trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 2);
    assert!(
        levels[1].reads_redirected,
        "L1 should have reads_redirected set when reclaim=true"
    );
}

/// Regression test for baseline coverage when a key is inherited across the
/// level boundary, structurally rewritten with the same value inside L1, and
/// then changed later in L1. The baseline entry must still be present so that
/// `value_at_height` covers heights at the start of the L1 range.
#[test]
fn test_incremental_full_history_baseline_with_later_transition() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let test_dir = fresh_test_dir("test_incr_fh_baseline_later");
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let l0_blocks: usize = 3; // heights 0..2
    let l1_blocks: usize = 4; // heights 3..6
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    // ── Build L0: write key_x = "xv0" at block 0 ──
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();

    for i in 0..l0_blocks {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = if i == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[i - 1].clone()
        };
        marf.begin(&parent, &bh).unwrap();
        if i == 0 {
            marf.insert("key_x", MARFValue::from_value("xv0")).unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }
    drop(marf);

    // ── Squash L0 with FullHistory ──
    squash_to_path::<StacksBlockId>(
        &src_path,
        &dst_path,
        SquashMode::FullHistory,
        (l0_blocks - 1) as u32,
    )
    .expect("L0 squash should succeed");

    // ── Write L1 blocks on squashed dst ──
    // Block 3 (min_height): re-insert key_x with same value "xv0"
    // Block 4: no write to key_x
    // Block 5: change key_x to "xv5"
    // Block 6: no write to key_x
    let mut marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts.clone()).unwrap();

    for i in l0_blocks..(l0_blocks + l1_blocks) {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();

        let parent = blocks[i - 1].clone();
        marf.begin(&parent, &bh).unwrap();
        if i == l0_blocks {
            // structural rewrite with same inherited value
            marf.insert("key_x", MARFValue::from_value("xv0")).unwrap();
        }
        if i == l0_blocks + 2 {
            // actual value change
            marf.insert("key_x", MARFValue::from_value("xv5")).unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }

    // Capture expected values from the unsquashed MARF
    let mut expected: Vec<MARFValue> = Vec::new();
    for block in &blocks {
        expected.push(marf.get(block, "key_x").unwrap().unwrap());
    }
    drop(marf);

    // ── Squash L1 incrementally with FullHistory ──
    squash_level_incremental::<StacksBlockId>(
        &dst_path,
        SquashMode::FullHistory,
        l0_blocks as u32,
        (l0_blocks + l1_blocks - 1) as u32,
        false,
    )
    .expect("L1 incremental squash should succeed");

    // ── Verify reads at every height ──
    let mut marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    for (i, block) in blocks.iter().enumerate() {
        let val = marf
            .get(block, "key_x")
            .unwrap()
            .unwrap_or_else(|| panic!("key_x should exist at block {i}"));
        assert_eq!(
            val, expected[i],
            "key_x mismatch at block {i}: got {val:?}, expected {:?}",
            expected[i]
        );
    }

    // Specifically: blocks at the start of L1 (before the height-5 change)
    // must return "xv0", not None.
    assert_eq!(
        marf.get(&blocks[l0_blocks], "key_x").unwrap().unwrap(),
        MARFValue::from_value("xv0"),
        "key_x at L1 min_height should return inherited value"
    );
    assert_eq!(
        marf.get(&blocks[l0_blocks + 1], "key_x").unwrap().unwrap(),
        MARFValue::from_value("xv0"),
        "key_x at min_height+1 should return inherited value"
    );
    assert_eq!(
        marf.get(&blocks[l0_blocks + 2], "key_x").unwrap().unwrap(),
        MARFValue::from_value("xv5"),
        "key_x at change height should return new value"
    );
}

// ---------------------------------------------------------------------------
// Phase 5 Test: get_with_proof in squash range → NotSupportedError
// ---------------------------------------------------------------------------

#[test]
fn test_get_with_proof_in_squash_range_returns_error() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;
    use crate::chainstate::stacks::index::Error;

    let test_dir = fresh_test_dir("test_get_with_proof_squash_range");
    let marf_path = format!("{test_dir}/marf.sqlite");

    let num_blocks = 10;
    let keys_per_block = 3;

    // Build the source MARF
    let (marf, blocks, _expected) =
        setup_squash_source_marf(&marf_path, num_blocks, keys_per_block);
    drop(marf);

    let max_height = (num_blocks - 1) as u32;

    // Squash with TipOnly (simplest case)
    let _stats = squash_level_incremental::<StacksBlockId>(
        &marf_path,
        SquashMode::TipOnly,
        0,
        max_height,
        true,
    )
    .expect("squash should succeed");

    // Re-open the MARF (squash levels are loaded on open)
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts).unwrap();

    // A block within the squash range should be rejected for proofs
    let squashed_block = &blocks[3]; // well within 0..max_height
    let result = marf.get_with_proof(squashed_block, "shared_key");
    match result {
        Err(Error::NotSupportedError(_)) => {} // expected
        other => {
            panic!("Expected NotSupportedError for get_with_proof in squash range, got: {other:?}")
        }
    }

    // The tip block itself (max_height) should also be in the squash range
    let tip_block = &blocks[num_blocks - 1];
    let result2 = marf.get_with_proof(tip_block, "shared_key");
    match result2 {
        Err(Error::NotSupportedError(_)) => {} // expected
        other => panic!(
            "Expected NotSupportedError for get_with_proof at tip in squash range, got: {other:?}"
        ),
    }

    // Normal get (without proof) should still work
    let val = marf
        .get(tip_block, "shared_key")
        .expect("get without proof should succeed")
        .expect("shared_key should exist");
    assert_eq!(
        val,
        MARFValue::from_value(&format!("shared_at_{}", num_blocks - 1)),
    );
}

// ---------------------------------------------------------------------------
// Phase 5 Test: End-to-end FullHistory squash + historical reads
// ---------------------------------------------------------------------------

#[test]
fn test_full_history_squash_end_to_end() {
    use crate::chainstate::stacks::index::squash::squash_to_path;

    let test_dir = fresh_test_dir("test_full_history_squash_e2e");
    let src_path = format!("{test_dir}/source.sqlite");
    let dst_path = format!("{test_dir}/squashed.sqlite");

    let num_blocks: usize = 10;

    // Build a MARF where "key_a" is updated at every block (simulating a hot
    // key that `at-block` might reference historically) and "key_b" is written
    // once and never updated (cold key).
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&src_path, open_opts.clone()).unwrap();

    let blocks: Vec<StacksBlockId> = (0..num_blocks)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Block 0: key_a and key_b
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    marf.insert("key_a", MARFValue::from_value("a_v0")).unwrap();
    marf.insert("key_b", MARFValue::from_value("b_v0")).unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    // Blocks 1-9: update key_a each block, key_b stays the same
    for i in 1..num_blocks {
        marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
        marf.insert("key_a", MARFValue::from_value(&format!("a_v{i}")))
            .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
    }

    // Capture expected values from the unsquashed MARF
    let mut expected_a: Vec<MARFValue> = Vec::new();
    let mut expected_b: Vec<MARFValue> = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let a = marf
            .get(block, "key_a")
            .unwrap_or_else(|e| panic!("get key_a at block {i} failed: {e}"))
            .unwrap_or_else(|| panic!("key_a should exist at block {i}"));
        let b = marf
            .get(block, "key_b")
            .unwrap_or_else(|e| panic!("get key_b at block {i} failed: {e}"))
            .unwrap_or_else(|| panic!("key_b should exist at block {i}"));
        expected_a.push(a);
        expected_b.push(b);
    }
    drop(marf);

    let max_height = (num_blocks - 1) as u32;

    // Squash with FullHistory
    let stats =
        squash_to_path::<StacksBlockId>(&src_path, &dst_path, SquashMode::FullHistory, max_height)
            .expect("FullHistory squash should succeed");
    assert!(stats.nodes_collected > 0);

    // Re-open the squashed MARF and verify historical reads
    let mut marf = MARF::<StacksBlockId>::from_path(&dst_path, open_opts).unwrap();

    for (i, block) in blocks.iter().enumerate() {
        let a = marf
            .get(block, "key_a")
            .unwrap_or_else(|e| panic!("get key_a at block {i} failed: {e}"))
            .unwrap_or_else(|| panic!("key_a should exist at block {i} in squashed MARF"));
        let b = marf
            .get(block, "key_b")
            .unwrap_or_else(|e| panic!("get key_b at block {i} failed: {e}"))
            .unwrap_or_else(|| panic!("key_b should exist at block {i} in squashed MARF"));

        assert_eq!(
            a, expected_a[i],
            "key_a at block {i}: squashed value should match unsquashed"
        );
        assert_eq!(
            b, expected_b[i],
            "key_b at block {i}: squashed value should match unsquashed"
        );
    }

    // Verify each block has a distinct key_a value (it's updated every block)
    for i in 1..num_blocks {
        assert_ne!(
            expected_a[i - 1],
            expected_a[i],
            "key_a values should differ between blocks {}/{i}",
            i - 1
        );
    }

    // Verify key_b is the same across all blocks
    for i in 1..num_blocks {
        assert_eq!(
            expected_b[0], expected_b[i],
            "key_b should be the same at all blocks"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 6, Item 1: post-squash COW correctly flattens LeafSquashed → Leaf
// ---------------------------------------------------------------------------

/// After a FullHistory squash, extending the MARF with a new block that
/// writes to a key currently stored as `TrieLeafSquashed` should:
///   - Produce a plain `TrieLeaf` in the new block's trie (COW flattening).
///   - Return the new value when read at the new tip.
///   - Still return correct historical values when read at old squashed blocks.
#[test]
fn test_cow_flattens_leaf_squashed_to_leaf() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let test_dir = fresh_test_dir("test_cow_flattens_leaf_squashed_to_leaf");
    let marf_path = format!("{test_dir}/marf.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
    let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts.clone()).unwrap();

    let num_blocks: usize = 6;
    let blocks: Vec<StacksBlockId> = (0..num_blocks)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Build blocks 0..=5, writing "hot_key" every block
    marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
    marf.insert("hot_key", MARFValue::from_value("hot_v0"))
        .unwrap();
    marf.insert("cold_key", MARFValue::from_value("cold_v0"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    for i in 1..num_blocks {
        marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
        marf.insert("hot_key", MARFValue::from_value(&format!("hot_v{i}")))
            .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
    }

    // Capture expected historical values from the unsquashed MARF
    let expected_hot: Vec<MARFValue> = (0..num_blocks)
        .map(|i| {
            marf.get(&blocks[i], "hot_key")
                .unwrap()
                .unwrap_or_else(|| panic!("hot_key should exist at block {i}"))
        })
        .collect();
    drop(marf);

    // Squash blocks 0..=5 with FullHistory (produces TrieLeafSquashed for hot_key)
    let max_height = (num_blocks - 1) as u32;
    let stats = squash_level_incremental::<StacksBlockId>(
        &marf_path,
        SquashMode::FullHistory,
        0,
        max_height,
        true, // reclaim
    )
    .expect("FullHistory squash should succeed");
    assert!(
        stats.leaves_squashed > 0,
        "should have at least one TrieLeafSquashed"
    );

    // --- COW extension: new block 6 writes to hot_key ---
    let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts.clone()).unwrap();

    let mut ext_bytes = [0u8; 32];
    ext_bytes[28..32].copy_from_slice(&((num_blocks as u32) + 1).to_be_bytes());
    let ext_block = StacksBlockId::from_bytes(&ext_bytes).unwrap();

    marf.begin(&blocks[num_blocks - 1], &ext_block).unwrap();
    marf.insert("hot_key", MARFValue::from_value("hot_v_ext"))
        .unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();

    // Read the new tip — should return the extended value
    let tip_val = marf
        .get(&ext_block, "hot_key")
        .expect("get should succeed")
        .expect("hot_key should exist at ext_block");
    assert_eq!(
        tip_val,
        MARFValue::from_value("hot_v_ext"),
        "COW-flattened tip should return the new value"
    );

    // Read cold_key at the new tip — should still return the original value
    let cold_val = marf
        .get(&ext_block, "cold_key")
        .expect("get should succeed")
        .expect("cold_key should exist at ext_block");
    assert_eq!(
        cold_val,
        MARFValue::from_value("cold_v0"),
        "cold_key should be unchanged after extension"
    );

    // Historical reads within the squashed range should still work
    for i in 0..num_blocks {
        let val = marf
            .get(&blocks[i], "hot_key")
            .expect("get should succeed")
            .unwrap_or_else(|| panic!("hot_key should exist at block {i}"));
        assert_eq!(
            val, expected_hot[i],
            "historical hot_key at block {i} should match after COW extension"
        );
    }

    // --- Node-type inspection: the extension block's per-block trie
    //     must contain only plain TrieLeaf nodes (no TrieLeafSquashed).
    //     This proves that COW flattening converted the squashed leaf. ---
    {
        use crate::chainstate::stacks::index::trie_sql;

        let block_id = trie_sql::get_block_identifier(marf.sqlite_conn(), &ext_block)
            .expect("extension block should have a block_id");
        let (offset, length) =
            trie_sql::get_external_trie_offset_length(marf.sqlite_conn(), block_id)
                .expect("extension block should have external blob metadata");

        let blob_path = format!("{marf_path}.blobs");
        let all_bytes = std::fs::read(&blob_path).expect("should read blob file");
        let trie_bytes = &all_bytes[offset as usize..(offset + length) as usize];

        // Per-block trie layout: [parent_hash(32)][block_id(4)] then
        // sequential [node_hash(32)][node_body(variable)] entries.
        let header_size = TRIEHASH_ENCODED_SIZE + 4;
        let mut pos = header_size;
        let end = trie_bytes.len();
        let mut leaf_squashed_count = 0usize;
        let mut plain_leaf_count = 0usize;

        while pos < end {
            if pos + TRIEHASH_ENCODED_SIZE > end {
                break;
            }
            let body_start = pos + TRIEHASH_ENCODED_SIZE;
            if body_start >= end {
                break;
            }
            let node_body = &trie_bytes[body_start..end];
            let node_id_byte = node_body[0];
            let node_id = clear_backptr(node_id_byte) & 0x3f;
            let (node, consumed) = bits::decode_nodetype_from_slice_at_head(node_body, node_id)
                .unwrap_or_else(|e| panic!("Failed to decode node at offset {pos}: {e}"));
            match &node {
                TrieNodeType::LeafSquashed(_) => leaf_squashed_count += 1,
                TrieNodeType::Leaf(_) => plain_leaf_count += 1,
                _ => {}
            }
            pos = body_start + consumed;
        }

        assert_eq!(
            leaf_squashed_count, 0,
            "extension block trie must not contain any TrieLeafSquashed nodes \
             (COW should flatten them to TrieLeaf)"
        );
        assert!(
            plain_leaf_count > 0,
            "extension block trie should contain at least one plain TrieLeaf"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 6, Item 2: mixed stack — FullHistory L0 + TipOnly L1
// ---------------------------------------------------------------------------

/// Simulates the steady-state for a `TipOnly`-configured node that
/// replayed pre-3.4 blocks with `FullHistory`. Lower level uses
/// `FullHistory`; upper level uses `TipOnly`. Verifies:
///   - Historical reads into the FullHistory range return correct
///     point-in-time values.
///   - Tip reads across both levels return the correct final values.
#[test]
fn test_mixed_stack_full_history_l0_tip_only_l1() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let test_dir = fresh_test_dir("test_mixed_stack_full_history_l0_tip_only_l1");
    let marf_path = format!("{test_dir}/marf.sqlite");
    // Separate unsquashed reference MARF for capturing expected values
    let ref_path = format!("{test_dir}/reference.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let l0_blocks: usize = 6;
    let l1_blocks: usize = 4;
    let total_blocks = l0_blocks + l1_blocks;

    let blocks: Vec<StacksBlockId> = (0..total_blocks)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // ---- Phase 1: Build L0 blocks in both MARFs (main + reference) ----
    let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    // Block 0
    for m in [&mut marf, &mut ref_marf] {
        m.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
        m.insert("hot_key", MARFValue::from_value("hot_v0"))
            .unwrap();
        m.insert("cold_key", MARFValue::from_value("cold_v0"))
            .unwrap();
        m.seal().unwrap();
        m.commit().unwrap();
    }

    // Blocks 1..l0_blocks-1
    for i in 1..l0_blocks {
        for m in [&mut marf, &mut ref_marf] {
            m.begin(&blocks[i - 1], &blocks[i]).unwrap();
            m.insert("hot_key", MARFValue::from_value(&format!("hot_v{i}")))
                .unwrap();
            m.seal().unwrap();
            m.commit().unwrap();
        }
    }

    // Capture L0 expected values from the reference
    let expected_hot_l0: Vec<MARFValue> = (0..l0_blocks)
        .map(|i| {
            ref_marf
                .get(&blocks[i], "hot_key")
                .unwrap()
                .unwrap_or_else(|| panic!("hot_key should exist at block {i}"))
        })
        .collect();
    let expected_cold_l0: Vec<MARFValue> = (0..l0_blocks)
        .map(|i| {
            ref_marf
                .get(&blocks[i], "cold_key")
                .unwrap()
                .unwrap_or_else(|| panic!("cold_key should exist at block {i}"))
        })
        .collect();

    drop(marf);

    // ---- Phase 2: Squash L0 with FullHistory ----
    let l0_max = (l0_blocks - 1) as u32;
    let l0_stats = squash_level_incremental::<StacksBlockId>(
        &marf_path,
        SquashMode::FullHistory,
        0,
        l0_max,
        true, // reclaim per-block blobs
    )
    .expect("L0 FullHistory squash should succeed");
    assert!(
        l0_stats.leaves_squashed > 0,
        "L0 FullHistory should produce TrieLeafSquashed nodes"
    );

    // ---- Phase 3: Extend with L1 blocks (on top of squashed L0) ----
    let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts.clone()).unwrap();

    for i in l0_blocks..total_blocks {
        for m in [&mut marf, &mut ref_marf] {
            m.begin(&blocks[i - 1], &blocks[i]).unwrap();
            m.insert("hot_key", MARFValue::from_value(&format!("hot_v{i}")))
                .unwrap();
            m.seal().unwrap();
            m.commit().unwrap();
        }
    }

    // Capture full expected values from the reference
    let expected_hot: Vec<MARFValue> = (0..total_blocks)
        .map(|i| {
            ref_marf
                .get(&blocks[i], "hot_key")
                .unwrap()
                .unwrap_or_else(|| panic!("hot_key should exist at block {i}"))
        })
        .collect();
    let expected_cold: Vec<MARFValue> = (0..total_blocks)
        .map(|i| {
            ref_marf
                .get(&blocks[i], "cold_key")
                .unwrap()
                .unwrap_or_else(|| panic!("cold_key should exist at block {i}"))
        })
        .collect();
    drop(ref_marf);
    drop(marf);

    // Sanity: L0 expected values should match
    assert_eq!(&expected_hot[..l0_blocks], &expected_hot_l0[..]);
    assert_eq!(&expected_cold[..l0_blocks], &expected_cold_l0[..]);

    // ---- Phase 4: Squash L1 with TipOnly ----
    let l1_min = l0_blocks as u32;
    let l1_max = (total_blocks - 1) as u32;
    let l1_stats = squash_level_incremental::<StacksBlockId>(
        &marf_path,
        SquashMode::TipOnly,
        l1_min,
        l1_max,
        false,
    )
    .expect("L1 TipOnly squash should succeed");
    assert!(l1_stats.nodes_collected > 0);

    // --- Verify the two levels are registered with correct modes ---
    let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts.clone()).unwrap();
    let levels =
        crate::chainstate::stacks::index::trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 2, "should have 2 squash levels");
    assert_eq!(levels[0].min_height, 0);
    assert_eq!(levels[0].max_height, l0_max);
    assert_eq!(levels[1].min_height, l1_min);
    assert_eq!(levels[1].max_height, l1_max);

    // Read the L0 trailer to verify it's FullHistory
    let blob_path = format!("{marf_path}.blobs");
    let blob_bytes = std::fs::read(&blob_path).expect("should read blob file");
    let l0_offset = levels[0].blob_offset as usize;
    let l0_end = l0_offset + levels[0].blob_length as usize;
    let l0_slice = &blob_bytes[l0_offset..l0_end];
    let l0_footer = SquashTrailer::read_footer(l0_slice).expect("should find L0 trailer footer");
    let l0_trailer_end = l0_slice.len() - SQUASH_FOOTER_SIZE;
    let l0_trailer = SquashTrailer::read_from(&l0_slice[l0_footer as usize..l0_trailer_end])
        .expect("should parse L0 trailer");
    assert_eq!(
        l0_trailer.info.mode,
        SquashMode::FullHistory,
        "L0 trailer mode should be FullHistory"
    );

    // Read the L1 trailer to verify it's TipOnly
    let l1_offset = levels[1].blob_offset as usize;
    let l1_end = l1_offset + levels[1].blob_length as usize;
    let l1_slice = &blob_bytes[l1_offset..l1_end];
    let l1_footer = SquashTrailer::read_footer(l1_slice).expect("should find L1 trailer footer");
    let l1_trailer_end = l1_slice.len() - SQUASH_FOOTER_SIZE;
    let l1_trailer = SquashTrailer::read_from(&l1_slice[l1_footer as usize..l1_trailer_end])
        .expect("should parse L1 trailer");
    assert_eq!(
        l1_trailer.info.mode,
        SquashMode::TipOnly,
        "L1 trailer mode should be TipOnly"
    );

    // --- Verify historical reads into the FullHistory L0 range ---
    for i in 0..l0_blocks {
        let hot = marf
            .get(&blocks[i], "hot_key")
            .unwrap_or_else(|e| panic!("get hot_key at block {i} failed: {e}"))
            .unwrap_or_else(|| panic!("hot_key should exist at block {i}"));
        let cold = marf
            .get(&blocks[i], "cold_key")
            .unwrap_or_else(|e| panic!("get cold_key at block {i} failed: {e}"))
            .unwrap_or_else(|| panic!("cold_key should exist at block {i}"));

        assert_eq!(
            hot, expected_hot[i],
            "hot_key at block {i} (L0/FullHistory) should match unsquashed"
        );
        assert_eq!(
            cold, expected_cold[i],
            "cold_key at block {i} (L0/FullHistory) should match unsquashed"
        );
    }

    // --- Verify intermediate L1 reads after TipOnly squash ---
    // TipOnly preserves the full trie structure with separate per-block
    // leaf nodes (unlike FullHistory which merges them into
    // TrieLeafSquashed). Reads at intermediate L1 blocks should still
    // return the correct historical values, matching the unsquashed
    // reference MARF.
    for i in l0_blocks..total_blocks {
        let hot = marf
            .get(&blocks[i], "hot_key")
            .unwrap_or_else(|e| panic!("get hot_key at L1 block {i} failed: {e}"))
            .unwrap_or_else(|| panic!("hot_key should exist at L1 block {i}"));
        let cold = marf
            .get(&blocks[i], "cold_key")
            .unwrap_or_else(|e| panic!("get cold_key at L1 block {i} failed: {e}"))
            .unwrap_or_else(|| panic!("cold_key should exist at L1 block {i}"));

        assert_eq!(
            hot, expected_hot[i],
            "hot_key at L1 block {i} (TipOnly) should match unsquashed reference"
        );
        assert_eq!(
            cold, expected_cold[i],
            "cold_key at L1 block {i} (TipOnly) should match unsquashed reference"
        );
    }

    // --- Verify tip read across both levels ---
    let tip = &blocks[total_blocks - 1];
    let tip_hot = marf
        .get(tip, "hot_key")
        .expect("get hot_key at tip should succeed")
        .expect("hot_key should exist at tip");
    let tip_cold = marf
        .get(tip, "cold_key")
        .expect("get cold_key at tip should succeed")
        .expect("cold_key should exist at tip");

    assert_eq!(
        tip_hot,
        expected_hot[total_blocks - 1],
        "hot_key at tip should match unsquashed"
    );
    assert_eq!(
        tip_cold,
        expected_cold[total_blocks - 1],
        "cold_key at tip should match unsquashed"
    );
}

// ---------------------------------------------------------------------------
// Phase 6, Item 3: benchmark — FullHistory tip-read overhead
// ---------------------------------------------------------------------------

/// Measure tip-read performance for `TrieLeafSquashed` nodes with varying
/// entry counts. This documents the baseline for future lazy-decode
/// optimization. Not a correctness test — it asserts only that reads
/// succeed and prints timing information.
#[test]
fn test_full_history_tip_read_benchmark() {
    use std::time::Instant;

    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let test_dir = fresh_test_dir("test_full_history_tip_read_benchmark");

    // Test with varying block counts to produce different entry counts
    for &num_blocks in &[10usize, 50, 200] {
        let marf_path = format!("{test_dir}/bench_{num_blocks}.sqlite");

        let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
        let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts.clone()).unwrap();

        let blocks: Vec<StacksBlockId> = (0..num_blocks)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
                StacksBlockId::from_bytes(&bytes).unwrap()
            })
            .collect();

        // Write hot_key every block
        marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
        marf.insert("hot_key", MARFValue::from_value("hot_v0"))
            .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();

        for i in 1..num_blocks {
            marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
            marf.insert("hot_key", MARFValue::from_value(&format!("hot_v{i}")))
                .unwrap();
            marf.seal().unwrap();
            marf.commit().unwrap();
        }
        drop(marf);

        // Squash with FullHistory
        let max_height = (num_blocks - 1) as u32;
        squash_level_incremental::<StacksBlockId>(
            &marf_path,
            SquashMode::FullHistory,
            0,
            max_height,
            true,
        )
        .expect("FullHistory squash should succeed");

        // Benchmark: 1000 tip reads
        let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts.clone()).unwrap();
        let tip = &blocks[num_blocks - 1];
        let iterations = 1000;

        let start = Instant::now();
        for _ in 0..iterations {
            let val = marf
                .get(tip, "hot_key")
                .expect("get should succeed")
                .expect("hot_key should exist");
            // Black-box the value to prevent optimizing away the read
            std::hint::black_box(&val);
        }
        let elapsed = start.elapsed();

        eprintln!(
            "FullHistory tip-read benchmark: entries={num_blocks}, \
             iterations={iterations}, total={elapsed:?}, \
             per_read={:?}",
            elapsed / iterations as u32
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 6, Item 4: FullHistory squash with oversized node region
// ---------------------------------------------------------------------------

/// Verify that `checked_offset_add` correctly rejects oversized squash
/// blobs.  We cannot practically generate a 3.5 GiB blob in a test, so
/// we test the guard function directly with boundary values. The
/// existing `test_checked_offset_add_overflow` covers the arithmetic;
/// this test verifies the error message is actionable.
#[test]
fn test_squash_blob_size_limit_error_message() {
    use crate::chainstate::stacks::index::squash::{
        checked_offset_add, MAX_SQUASH_NODE_REGION_SIZE,
    };

    // Just above the cap → CorruptionError with an actionable message
    let over = MAX_SQUASH_NODE_REGION_SIZE as u32;
    let err = checked_offset_add(over, 1)
        .expect_err("should fail when exceeding MAX_SQUASH_NODE_REGION_SIZE");

    match &err {
        crate::chainstate::stacks::index::Error::CorruptionError(msg) => {
            assert!(
                msg.contains("MAX_SQUASH_NODE_REGION_SIZE"),
                "error should reference the cap constant: {msg}"
            );
            assert!(
                msg.contains(&MAX_SQUASH_NODE_REGION_SIZE.to_string()),
                "error should include the cap value: {msg}"
            );
        }
        other => panic!("expected CorruptionError, got {other:?}"),
    }

    // Pure u32 overflow (separate path) → mentions "overflow"
    let err = checked_offset_add(u32::MAX, 1).expect_err("should fail on u32 overflow");
    match &err {
        crate::chainstate::stacks::index::Error::CorruptionError(msg) => {
            assert!(
                msg.contains("overflow"),
                "error should mention overflow: {msg}"
            );
        }
        other => panic!("expected CorruptionError, got {other:?}"),
    }

    // Boundary: exactly at cap should succeed
    let at_cap = MAX_SQUASH_NODE_REGION_SIZE as u32;
    assert_eq!(
        checked_offset_add(at_cap - 1, 1).unwrap(),
        at_cap,
        "exactly at cap should succeed"
    );

    // Boundary: one above should fail
    assert!(
        checked_offset_add(at_cap, 1).is_err(),
        "one above cap should fail"
    );
}
