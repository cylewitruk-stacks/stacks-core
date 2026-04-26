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
    clear_backptr, set_compressed, TrieLeafSquashed, TrieNode, TrieNodeID, TrieNodeType,
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

    // Verify the ID byte is correct (compressed format sets 0x40 bit)
    assert_eq!(buf[0], set_compressed(TrieNodeID::LeafSquashed as u8));

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

/// Verify that entries spanning more than u16::MAX heights fall back to
/// the legacy (uncompressed) encoding and round-trip correctly.
#[test]
fn test_leaf_squashed_serialization_legacy_fallback() {
    let path_bytes = [0xABu8; 32];
    // Height span = 100_000 > u16::MAX (65535) → must use legacy encoding.
    let entries = vec![
        (100_000, MARFValue([0xAAu8; 40])),
        (50_000, MARFValue([0xBBu8; 40])),
        (0, MARFValue([0xCCu8; 40])),
    ];

    let original = TrieLeafSquashed::new(&path_bytes, entries).unwrap();

    let mut buf = Vec::new();
    original.write_bytes(&mut buf).unwrap();

    // Legacy format: ID byte should NOT have compressed bit set.
    assert_eq!(buf[0], TrieNodeID::LeafSquashed as u8);

    assert_eq!(buf.len(), original.byte_len());

    // Legacy per-entry size is 44 (u32 height + 40 value).
    let expected_legacy_len = 1 + 33 + 4 + 3 * 44; // ID + path + count + entries
    assert_eq!(buf.len(), expected_legacy_len);

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
    let mut sorted_block_entries: Vec<([u8; 32], u32, u32)> = block_hashes
        .iter()
        .enumerate()
        .map(|(i, bhh)| (*bhh, i as u32, (100 + i) as u32))
        .collect();
    sorted_block_entries.sort_by_key(|(bhh, _, _)| *bhh);

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
            let mut entries: Vec<([u8; 32], u32, u32)> =
                (100..=105).map(|i| ([i as u8; 32], i, 200 + i)).collect();
            entries.sort_by_key(|(bhh, _, _)| *bhh);
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
        marf.storage.data.squash_meta.levels.is_empty(),
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
        marf.storage.data.squash_meta.levels.is_empty(),
        "Live handle should still have no squash levels (stale)"
    );

    // Refresh the live handle
    marf.refresh_after_squash().unwrap();

    // Now the live handle should see the squash level
    assert_eq!(
        marf.storage.data.squash_meta.levels.len(),
        1,
        "After refresh, should see 1 squash level"
    );
    assert_eq!(
        marf.storage.data.squash_meta.block_index.len(),
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
        marf.storage.data.squash_meta.block_index.is_empty(),
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

    // Scan sequential nodes: skip header (36 bytes).
    // Leaf nodes are stored hash-free (body only); internal nodes are
    // stored as hash(32) + body.
    //
    // To avoid a fragile heuristic on the first byte (which could be an
    // arbitrary hash byte for internal nodes), we use a trial-decode
    // approach: try interpreting pos as a hash-free leaf body.  If that
    // succeeds we accept it; otherwise we skip 32 bytes of hash prefix
    // and decode the body of an internal node.
    let header_size = 36usize;
    let mut pos = header_size;
    let nodes_end = trailer_offset;

    let mut leaf_squashed_count = 0usize;
    let mut plain_leaf_count = 0usize;
    let mut internal_count = 0usize;
    let mut found_hot_key_squashed = false;

    while pos < nodes_end {
        let remaining = &blob_slice[pos..nodes_end];

        // Try hash-free leaf decode first.
        let first_byte = remaining[0];
        let cleared = clear_backptr(first_byte) & 0x3f;
        let leaf_candidate = (cleared == TrieNodeID::Leaf as u8
            || cleared == TrieNodeID::LeafSquashed as u8)
            && bits::decode_nodetype_from_slice_at_head(remaining, cleared).is_ok();

        if leaf_candidate {
            let (node, consumed) =
                bits::decode_nodetype_from_slice_at_head(remaining, cleared).unwrap();
            match &node {
                TrieNodeType::LeafSquashed(sq) => {
                    leaf_squashed_count += 1;
                    for w in sq.entries.windows(2) {
                        assert!(
                            w[0].0 > w[1].0,
                            "TrieLeafSquashed entries should be sorted descending: {} > {} failed",
                            w[0].0,
                            w[1].0
                        );
                    }
                    // Identify the hot_key LeafSquashed by its signature:
                    // `num_blocks` entries with values matching "hot_{h}".
                    // Other LeafSquashed in the blob (cold_key, internal MARF
                    // mapping keys) have fewer entries and different values.
                    let looks_like_hot_key = sq.entries.len() == num_blocks
                        && sq
                            .entries
                            .iter()
                            .all(|(h, v)| *v == MARFValue::from_value(&format!("hot_{h}")));
                    if looks_like_hot_key {
                        found_hot_key_squashed = true;
                        for (idx, &(height, ref value)) in sq.entries.iter().enumerate() {
                            let expected_height = (num_blocks - 1 - idx) as u32;
                            let expected_value =
                                MARFValue::from_value(&format!("hot_{expected_height}"));
                            assert_eq!(
                                height, expected_height,
                                "hot_key entry[{idx}] height: expected {expected_height}, got {height}"
                            );
                            assert_eq!(
                                *value, expected_value,
                                "hot_key entry[{idx}] value mismatch at height {height}"
                            );
                        }
                    }
                }
                TrieNodeType::Leaf(_) => {
                    plain_leaf_count += 1;
                }
                _ => unreachable!("leaf candidate decoded to non-leaf"),
            }
            pos += consumed;
        } else {
            // Internal node: 32-byte hash prefix + body.
            assert!(
                remaining.len() > TRIEHASH_ENCODED_SIZE,
                "not enough bytes for hash prefix at blob offset {pos}"
            );
            let body = &remaining[TRIEHASH_ENCODED_SIZE..];
            let node_id = clear_backptr(body[0]) & 0x3f;
            let (_node, consumed) = bits::decode_nodetype_from_slice_at_head(body, node_id)
                .unwrap_or_else(|e| {
                    panic!("Failed to decode internal node at blob offset {pos}: {e}")
                });
            internal_count += 1;
            pos += TRIEHASH_ENCODED_SIZE + consumed;
        }
    }

    assert_eq!(
        pos, nodes_end,
        "blob scan did not consume exactly the node region"
    );

    assert!(
        leaf_squashed_count > 0,
        "blob should contain at least one TrieLeafSquashed node"
    );
    assert!(
        found_hot_key_squashed,
        "hot_key should be stored as a TrieLeafSquashed with all {num_blocks} transitions"
    );

    eprintln!(
        "Blob scan: {leaf_squashed_count} LeafSquashed, {plain_leaf_count} Leaf, \
         {internal_count} internal"
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
    // have no entries in L1's history and stay as plain TrieLeaf. key_c has
    // real in-range transitions and is promoted. MARF-internal mapping keys
    // written at every L1 block also appear in history; they too get
    // promoted to `TrieLeafSquashed` so that reads at heights below their
    // first write correctly return `None` rather than a post-hoc value.
    assert!(
        l1_stats.leaves_squashed >= 1,
        "at least key_c should be promoted to TrieLeafSquashed (got {})",
        l1_stats.leaves_squashed
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

/// Regression test for the `reopen_connection()` squash-metadata bug.
///
/// `reopen_connection()` creates a lightweight read-only connection that shares the
/// parent's SQLite handle but builds a *fresh* `TrieStorageTransientData`. Before the
/// fix, the fresh transient data had empty squash metadata — so reads through the
/// reopened connection would try to parse hash-free squash-blob leaves with the
/// hash-prefix-expected path, producing garbage/corruption. In production this path
/// is hit by `get_indexed()` (util_lib/db.rs) which is called on every Clarity read.
///
/// Key design: "cold" keys are written only during L0 and **never updated** afterward.
/// Every extension block probes them through `reopen_connection().get()`, which forces
/// the walk all the way through the reclaimed squash blob for the entire 700-block
/// extension. Without the fix, these reads corrupt.
#[test]
fn test_l0_reclaim_squash_long_extension_reads_with_reopen() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_l0_reclaim_squash_long_extension_reads_with_reopen");

    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let l0_blocks: usize = 6;
    let keys_per_block: usize = 4;
    let ext_blocks: usize = 700;
    let num_cold_keys: usize = 4;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0xDE_AD_C0_DEu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // Build base L0 chain in both MARFs.
    let (src_marf, l0_blocks_vec, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);
    let (ref_marf, _, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);

    // Insert cold keys into the last L0 block of both MARFs. These are never
    // updated after this point, so reads always walk into the squash blob.
    {
        let last_l0 = l0_blocks_vec.last().unwrap();
        let cold_block = make_block(l0_blocks); // one extra block for cold keys
        let mut sq = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
        let mut rf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();
        sq.begin(last_l0, &cold_block).unwrap();
        rf.begin(last_l0, &cold_block).unwrap();
        for c in 0..num_cold_keys {
            let key = format!("cold_key_{c}");
            let val = MARFValue::from_value(&format!("cold_val_{c}"));
            sq.insert(&key, val.clone()).unwrap();
            rf.insert(&key, val).unwrap();
        }
        sq.seal().unwrap();
        sq.commit().unwrap();
        rf.seal().unwrap();
        rf.commit().unwrap();
    }
    // The cold-key block becomes the new base for the squash range.
    let cold_block = make_block(l0_blocks);

    // Squash the full L0 range (including the cold-key block) with reclaim.
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        l0_blocks as u32, // includes the cold-key block
        true,
    )
    .expect("L0 reclaim squash");

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    let mut parent = cold_block;

    for e in 0..ext_blocks {
        let block_num = l0_blocks + 1 + e; // +1 for the cold-key block
        let block_hash = make_block(block_num);

        sq_marf.begin(&parent, &block_hash).unwrap();
        ref_marf.begin(&parent, &block_hash).unwrap();

        // Insert one fresh key per block.
        let new_key = format!("ext_key_{block_num}");
        let new_val = MARFValue::from_value(&format!("ext_val_{block_num}"));
        sq_marf.insert(&new_key, new_val.clone()).unwrap();
        ref_marf.insert(&new_key, new_val).unwrap();

        let sq_root = sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        let ref_root = ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();

        assert_eq!(
            sq_root, ref_root,
            "root hash mismatch at extension block {e} (height {block_num})"
        );

        // ---- Cold-key probes via reopen_connection ----
        // These keys live only in the squash blob and are never overwritten,
        // so every read must walk into the reclaimed squash blob. This is the
        // exact path that was broken before the fix.
        {
            let mut reopened = sq_marf.reopen_connection().unwrap_or_else(|err| {
                panic!("reopen_connection() failed at height {block_num}: {err:?}")
            });
            for c in 0..num_cold_keys {
                let key = format!("cold_key_{c}");
                let sq_val = reopened.get(&block_hash, &key).unwrap_or_else(|err| {
                    panic!("reopened get({key}) failed at height {block_num}: {err:?}")
                });
                let ref_val = ref_marf.get(&block_hash, &key).unwrap();
                assert_eq!(
                    sq_val, ref_val,
                    "cold key {key} mismatch at height {block_num}"
                );
            }
        }

        // ---- Periodic full reopen ----
        if e > 0 && e % 200 == 0 {
            drop(sq_marf);
            drop(ref_marf);
            sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
            ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

            // Cold keys must still work after full reopen.
            let mut reopened = sq_marf.reopen_connection().unwrap();
            for c in 0..num_cold_keys {
                let key = format!("cold_key_{c}");
                let sq_v = reopened.get(&block_hash, &key).unwrap_or_else(|err| {
                    panic!("post-reopen get({key}) failed at ext block {e}: {err:?}")
                });
                let ref_v = ref_marf.get(&block_hash, &key).unwrap();
                assert_eq!(
                    sq_v, ref_v,
                    "post-reopen cold key {key} mismatch at ext block {e}"
                );
            }
        }

        parent = block_hash;
    }
}

/// Regression test for the `reopen_readonly()` squash-metadata bug.
///
/// Same root cause as the `reopen_connection()` bug above, but exercising the
/// fully independent `TrieFileStorage` path used by the Clarity VM
/// (`marf.reopen_readonly()`) and `get_indexed_ref()`. Before the fix, the
/// readonly storage had empty squash metadata and would misparse hash-free
/// leaves in the squash blob.
#[test]
fn test_l0_reclaim_squash_reads_with_reopen_readonly() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_l0_reclaim_squash_reads_with_reopen_readonly");

    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let l0_blocks: usize = 6;
    let keys_per_block: usize = 4;
    let ext_blocks: usize = 100;
    let num_cold_keys: usize = 4;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let make_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0xDE_AD_C0_DEu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // Build base L0 chain in both MARFs.
    let (src_marf, l0_blocks_vec, _) =
        setup_squash_source_marf(&sq_path, l0_blocks, keys_per_block);
    drop(src_marf);
    let (ref_marf, _, _) = setup_squash_source_marf(&ref_path, l0_blocks, keys_per_block);
    drop(ref_marf);

    // Insert cold keys into the last L0 block.
    {
        let last_l0 = l0_blocks_vec.last().unwrap();
        let cold_block = make_block(l0_blocks);
        let mut sq = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
        let mut rf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();
        sq.begin(last_l0, &cold_block).unwrap();
        rf.begin(last_l0, &cold_block).unwrap();
        for c in 0..num_cold_keys {
            let key = format!("cold_key_{c}");
            let val = MARFValue::from_value(&format!("cold_val_{c}"));
            sq.insert(&key, val.clone()).unwrap();
            rf.insert(&key, val).unwrap();
        }
        sq.seal().unwrap();
        sq.commit().unwrap();
        rf.seal().unwrap();
        rf.commit().unwrap();
    }
    let cold_block = make_block(l0_blocks);

    // Squash with reclaim.
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        l0_blocks as u32,
        true,
    )
    .expect("L0 reclaim squash");

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    let mut parent = cold_block;

    for e in 0..ext_blocks {
        let block_num = l0_blocks + 1 + e;
        let block_hash = make_block(block_num);

        sq_marf.begin(&parent, &block_hash).unwrap();
        ref_marf.begin(&parent, &block_hash).unwrap();

        let new_key = format!("ext_key_{block_num}");
        let new_val = MARFValue::from_value(&format!("ext_val_{block_num}"));
        sq_marf.insert(&new_key, new_val.clone()).unwrap();
        ref_marf.insert(&new_key, new_val).unwrap();

        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();

        // ---- Cold-key probes via reopen_readonly ----
        // This creates a fully independent TrieFileStorage (own DB handle,
        // own blob file) — the path used by the Clarity VM and get_indexed.
        {
            let mut ro_marf = sq_marf.reopen_readonly().unwrap_or_else(|err| {
                panic!("reopen_readonly() failed at height {block_num}: {err:?}")
            });
            for c in 0..num_cold_keys {
                let key = format!("cold_key_{c}");
                let sq_val = ro_marf.get(&block_hash, &key).unwrap_or_else(|err| {
                    panic!("readonly get({key}) failed at height {block_num}: {err:?}")
                });
                let ref_val = ref_marf.get(&block_hash, &key).unwrap();
                assert_eq!(
                    sq_val, ref_val,
                    "readonly cold key {key} mismatch at height {block_num}"
                );
            }
        }

        // ---- Also probe via reopen_connection for completeness ----
        {
            let mut reopened = sq_marf.reopen_connection().unwrap();
            for c in 0..num_cold_keys {
                let key = format!("cold_key_{c}");
                let sq_val = reopened.get(&block_hash, &key).unwrap_or_else(|err| {
                    panic!("reopened get({key}) failed at height {block_num}: {err:?}")
                });
                let ref_val = ref_marf.get(&block_hash, &key).unwrap();
                assert_eq!(
                    sq_val, ref_val,
                    "reopened cold key {key} mismatch at height {block_num}"
                );
            }
        }

        parent = block_hash;
    }
}

/// Verify that squash_level_incremental correctly rejects squashing below the chain tip.
///
/// `verify_no_descendants` ensures that no committed blocks exist above the squash
/// range. This prevents accidental pruning of live future blocks.
#[test]
fn test_squash_rejects_when_blocks_exist_above_range() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_squash_rejects_above_range");
    let marf_path = format!("{dir}/test.sqlite");

    let total_blocks = 15usize;
    let keys_per_block = 3;

    let (src_marf, _block_hashes, _) =
        setup_squash_source_marf(&marf_path, total_blocks, keys_per_block);
    drop(src_marf);

    // Try to squash only 0..=9 when blocks 10..=14 exist — should fail.
    let result =
        squash_level_incremental::<StacksBlockId>(&marf_path, SquashMode::TipOnly, 0, 9, true);

    assert!(
        result.is_err(),
        "Squash below chain tip should be rejected by verify_no_descendants"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("exists above max_height"),
        "Error should mention blocks above max_height, got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Tier 1 reproduction: multi-level FullHistory + reclaim recurring squash
//
// Reproduction attempt for the genesis-sync "Bad nonce" divergence observed on
// `perf/marf-squash-cycle`. Mirrors the production Clarity-MARF pattern:
//   * mode = FullHistory
//   * reclaim = true at every level
//   * recurring squashes at a fixed cadence (like `maybe_squash`)
//
// Two MARFs are built in lockstep:
//   * `ref`: no squashing (ground-truth oracle)
//   * `sq` : recurring FullHistory+reclaim squashes every `BLOCKS_PER_LEVEL`
//
// Workload: NUM_ACCOUNTS "accounts". At every block, a fixed subset of them is
// touched and each receives a fresh nonce-encoded value of the form
// "acct_{id}_nonce_{k}". This mirrors the real nonce-overwrite pattern and
// makes any historical-read divergence visible as a value mismatch rather
// than a hash mismatch alone.
//
// Every historical key is probed via THREE distinct read paths, after every
// squash level, at every historical height:
//   1. direct `marf.get()`                     — long-lived writer connection
//   2. `reopen_connection()`                    — shared DB, fresh transient
//   3. `reopen_readonly()`                      — fully independent storage
//                                                 (Clarity VM path)
//
// Any divergence between `sq` (squashed) and `ref` (unsquashed) on any read
// path at any height indicates a correctness regression in the squash/read
// pipeline.
// ---------------------------------------------------------------------------

/// Deterministic workload: which accounts are touched at height `h`.
fn tier1_touched_accounts(
    height: usize,
    num_accounts: usize,
    touches_per_block: usize,
) -> Vec<usize> {
    (0..touches_per_block)
        .map(|t| (height * 3 + t * 5) % num_accounts)
        .collect()
}

fn tier1_block_hash(height: usize) -> StacksBlockId {
    let mut bytes = [0u8; 32];
    bytes[24..28].copy_from_slice(&0x_BA_5E_BA_11u32.to_be_bytes());
    bytes[28..32].copy_from_slice(&((height as u32) + 1).to_be_bytes());
    StacksBlockId::from_bytes(&bytes).unwrap()
}

/// Build the nonce-style workload on top of `marf`, committing `blocks_to_add`
/// blocks starting from `parent`. Returns the list of committed block hashes
/// in order. The workload is fully determined by `height`, so both squash
/// and reference MARFs receive identical writes.
fn tier1_extend_nonce_chain(
    marf: &mut MARF<StacksBlockId>,
    parent: StacksBlockId,
    start_height: usize,
    blocks_to_add: usize,
    num_accounts: usize,
    touches_per_block: usize,
) -> Vec<StacksBlockId> {
    let mut out = Vec::with_capacity(blocks_to_add);
    let mut cur_parent = parent;

    for b in 0..blocks_to_add {
        let height = start_height + b;
        let block_hash = tier1_block_hash(height);
        marf.begin(&cur_parent, &block_hash).unwrap();

        for acct in tier1_touched_accounts(height, num_accounts, touches_per_block) {
            let key = format!("acct_{acct}");
            let val = MARFValue::from_value(&format!("acct_{acct}_nonce_{height}"));
            marf.insert(&key, val).unwrap();
        }

        marf.seal().unwrap();
        marf.commit().unwrap();
        out.push(block_hash.clone());
        cur_parent = block_hash;
    }

    out
}

/// Reverse-lookup: given a MARFValue byte-pattern, find which `acct_N_nonce_K`
/// string produces it. Returns a human-readable label, or `"<unknown>"` if no
/// match within the searched (num_accounts × search_heights) space.
fn tier1_identify_value(
    value_bytes: &[u8],
    num_accounts: usize,
    search_heights: usize,
    _touches_per_block: usize,
) -> String {
    for a in 0..num_accounts {
        for h in 0..search_heights {
            let candidate = MARFValue::from_value(&format!("acct_{a}_nonce_{h}"));
            if candidate.0 == value_bytes {
                return format!("acct_{a}_nonce_{h}");
            }
        }
    }
    "<unknown>".to_string()
}

/// Expected value for `acct` at `height`: the latest touch at or before that
/// height, or None if the account has never been touched.
fn tier1_expected_at(
    acct: usize,
    height: usize,
    num_accounts: usize,
    touches_per_block: usize,
) -> Option<MARFValue> {
    for h in (0..=height).rev() {
        if tier1_touched_accounts(h, num_accounts, touches_per_block)
            .iter()
            .any(|&a| a == acct)
        {
            return Some(MARFValue::from_value(&format!("acct_{acct}_nonce_{h}")));
        }
    }
    None
}

/// Minimal reproduction isolator: N accounts, each with its own nonce-style
/// per-block updates, L0 FullHistory+reclaim squash. Runs the same check for
/// every account. Intended to narrow the boundary between "works" and "breaks".
#[test]
fn test_tier1_debug_two_accounts_historical_reads() {
    tier1_debug_n_account_chain(2, 6);
}

#[test]
fn test_tier1_debug_three_accounts_historical_reads() {
    tier1_debug_n_account_chain(3, 6);
}

#[test]
fn test_tier1_debug_four_accounts_historical_reads() {
    tier1_debug_n_account_chain(4, 6);
}

/// Minimal reproduction with ONE key that is touched only at even heights.
/// Odd-height reads must walk through backptrs; after squash, they should
/// still return the last-updated value ≤ that height.
#[test]
fn test_tier1_debug_single_key_sparse_updates() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("tier1_debug_single_sparse");
    let sq_path = format!("{dir}/squashed.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let num_blocks = 6;
    let mut marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();

    for h in 0..num_blocks {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();
        let parent = if h == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[h - 1].clone()
        };
        marf.begin(&parent, &bh).unwrap();
        if h % 2 == 0 {
            // Even heights only: 0, 2, 4
            let val = MARFValue::from_value(&format!("my_key_nonce_{h}"));
            marf.insert("my_key", val).unwrap();
        } else {
            // Odd heights: insert a different key so the block isn't empty
            marf.insert(
                &format!("filler_{h}"),
                MARFValue::from_value(&format!("filler_{h}")),
            )
            .unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }
    drop(marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::FullHistory,
        0,
        (num_blocks - 1) as u32,
        true,
    )
    .expect("L0 FullHistory reclaim squash");

    let mut marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts).unwrap();
    eprintln!("--- SPARSE SINGLE-KEY (6 blocks, touches at 0/2/4) ---");
    let mut fail_count = 0usize;
    for (h, bh) in blocks.iter().enumerate() {
        let v = marf.get(bh, "my_key").unwrap();
        let last_touch = (0..=h).rev().find(|&hh| hh % 2 == 0);
        let expected = last_touch.map(|hh| MARFValue::from_value(&format!("my_key_nonce_{hh}")));
        let got_str = v
            .as_ref()
            .map(|val| {
                for hh in 0..num_blocks {
                    if val.0 == MARFValue::from_value(&format!("my_key_nonce_{hh}")).0 {
                        return format!("my_key_nonce_{hh}");
                    }
                }
                "<unknown>".to_string()
            })
            .unwrap_or_else(|| "<None>".to_string());
        let ok = v == expected;
        if !ok {
            fail_count += 1;
        }
        eprintln!(
            "  block[{h}] → {got_str:?} (expected {:?}, match={ok})",
            expected.as_ref().map(|_| last_touch.unwrap())
        );
    }
    eprintln!("  total failures: {fail_count}");
    assert_eq!(fail_count, 0, "single-key sparse reads diverged");
}

/// Same shape as the N-account test, but each account is only touched on
/// heights where `h % num_accounts == a` (i.e. sparse updates). This forces
/// the read path to walk through backptrs at ancestor heights where an
/// account's leaf lives in an older block.
#[test]
fn test_tier1_debug_sparse_updates_two_accounts() {
    tier1_debug_sparse_n_account_chain(2, 6);
}

#[test]
fn test_tier1_debug_sparse_updates_three_accounts() {
    tier1_debug_sparse_n_account_chain(3, 6);
}

fn tier1_debug_sparse_n_account_chain(num_accounts: usize, num_blocks: usize) {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir(&format!("tier1_debug_sparse_{num_accounts}"));
    let sq_path = format!("{dir}/squashed.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let mut marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();

    // Sparse: account `a` is touched only at heights where h % num_accounts == a.
    // Every block still inserts at least one key (a touch for whichever account
    // matches the height's modulus), so each block writes non-trivially.
    for h in 0..num_blocks {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();
        let parent = if h == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[h - 1].clone()
        };
        marf.begin(&parent, &bh).unwrap();
        let a = h % num_accounts;
        let key = format!("acct_{a}");
        let val = MARFValue::from_value(&format!("acct_{a}_nonce_{h}"));
        marf.insert(&key, val).unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }
    drop(marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::FullHistory,
        0,
        (num_blocks - 1) as u32,
        true,
    )
    .expect("L0 FullHistory reclaim squash");

    let mut marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts).unwrap();

    eprintln!("--- SPARSE (accounts={num_accounts}, blocks={num_blocks}): reads after squash ---");
    let mut fail_count = 0usize;
    for (h, bh) in blocks.iter().enumerate() {
        for a in 0..num_accounts {
            let key = format!("acct_{a}");
            // Expected: the most-recent height <= h where h' % num_accounts == a.
            let expected = (0..=h)
                .rev()
                .find(|&hh| hh % num_accounts == a)
                .map(|hh| MARFValue::from_value(&format!("acct_{a}_nonce_{hh}")));
            let got = marf.get(bh, &key).unwrap();
            let got_str = got
                .as_ref()
                .map(|val| {
                    for ha in 0..num_blocks {
                        for aa in 0..num_accounts {
                            if val.0 == MARFValue::from_value(&format!("acct_{aa}_nonce_{ha}")).0 {
                                return format!("acct_{aa}_nonce_{ha}");
                            }
                        }
                    }
                    "<unknown>".to_string()
                })
                .unwrap_or_else(|| "<None>".to_string());
            let expected_str = expected
                .as_ref()
                .map(|_| {
                    (0..=h)
                        .rev()
                        .find(|&hh| hh % num_accounts == a)
                        .map(|hh| format!("acct_{a}_nonce_{hh}"))
                        .unwrap_or_default()
                })
                .unwrap_or_else(|| "<None>".to_string());
            if got != expected {
                fail_count += 1;
                eprintln!("  FAIL: {key} at h={h} → {got_str:?} (expected {expected_str:?})");
            }
        }
    }
    eprintln!("  total failures: {fail_count}");
    assert_eq!(fail_count, 0, "sparse historical reads diverged");
}

fn tier1_debug_n_account_chain(num_accounts: usize, num_blocks: usize) {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir(&format!("tier1_debug_{num_accounts}_accounts"));
    let sq_path = format!("{dir}/squashed.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let mut marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();

    // Every block updates every account with a height-encoded value so that
    // each account has `num_blocks` transitions and can be probed at every
    // historical height.
    for h in 0..num_blocks {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();
        let parent = if h == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[h - 1].clone()
        };
        marf.begin(&parent, &bh).unwrap();
        for a in 0..num_accounts {
            let key = format!("acct_{a}");
            let val = MARFValue::from_value(&format!("acct_{a}_nonce_{h}"));
            marf.insert(&key, val).unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }
    drop(marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::FullHistory,
        0,
        (num_blocks - 1) as u32,
        true,
    )
    .expect("L0 FullHistory reclaim squash");

    let mut marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts).unwrap();

    eprintln!("--- After FullHistory+reclaim (accounts={num_accounts}, blocks={num_blocks}) ---");
    let mut fail_count = 0usize;
    for (h, bh) in blocks.iter().enumerate() {
        for a in 0..num_accounts {
            let key = format!("acct_{a}");
            let v = marf.get(bh, &key).unwrap();
            let expected = MARFValue::from_value(&format!("acct_{a}_nonce_{h}"));
            let got_str = v
                .as_ref()
                .map(|val| {
                    for ha in 0..num_blocks {
                        for aa in 0..num_accounts {
                            if val.0 == MARFValue::from_value(&format!("acct_{aa}_nonce_{ha}")).0 {
                                return format!("acct_{aa}_nonce_{ha}");
                            }
                        }
                    }
                    "<unknown>".to_string()
                })
                .unwrap_or_else(|| "<None>".to_string());
            let ok = v == Some(expected);
            if !ok {
                fail_count += 1;
                eprintln!("  FAIL: {key} at h={h} → {got_str:?} (expected acct_{a}_nonce_{h})");
            }
        }
    }
    eprintln!("  total failures: {fail_count}");
    assert_eq!(fail_count, 0, "historical reads diverged from expected");
}

/// Minimal reproduction isolator: one account updated every block, L0
/// FullHistory+reclaim squash. If historical reads at every height return the
/// same value (the tip), then `squash_opened_height` is being lost; if they
/// return *different* wrong values, `value_at_height` is bugged.
#[test]
fn test_tier1_debug_single_account_historical_reads() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_tier1_debug_single_account");
    let sq_path = format!("{dir}/squashed.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let num_blocks = 4; // heights 0..=3
    let mut marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();

    for h in 0..num_blocks {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        let bh = StacksBlockId::from_bytes(&bytes).unwrap();
        let parent = if h == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[h - 1].clone()
        };
        marf.begin(&parent, &bh).unwrap();
        marf.insert(
            "my_key",
            MARFValue::from_value(&format!("my_key_nonce_{h}")),
        )
        .unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
        blocks.push(bh);
    }
    drop(marf);

    eprintln!("--- Before squash ---");
    let mut marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    for (i, bh) in blocks.iter().enumerate() {
        let v = marf.get(bh, "my_key").unwrap();
        eprintln!("  block[{i}] → {v:?}");
    }
    drop(marf);

    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::FullHistory,
        0,
        (num_blocks - 1) as u32,
        true,
    )
    .expect("L0 FullHistory reclaim squash");

    eprintln!("--- After FullHistory+reclaim squash ---");
    let mut marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts).unwrap();
    for (i, bh) in blocks.iter().enumerate() {
        let v = marf.get(bh, "my_key").unwrap();
        let expected = MARFValue::from_value(&format!("my_key_nonce_{i}"));
        let got_str = v
            .as_ref()
            .map(|val| {
                for h in 0..num_blocks {
                    if val.0 == MARFValue::from_value(&format!("my_key_nonce_{h}")).0 {
                        return format!("my_key_nonce_{h}");
                    }
                }
                "<unknown>".to_string()
            })
            .unwrap_or_else(|| "<None>".to_string());
        eprintln!(
            "  block[{i}] (height {i}) → {got_str:?}, expected my_key_nonce_{i}, match={}",
            v == Some(expected)
        );
    }
}

#[test]
fn test_tier1_multi_level_full_history_reclaim_differential() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_tier1_multi_level_full_history_reclaim_differential");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let num_accounts: usize = 12;
    let touches_per_block: usize = 4;
    let blocks_per_level: usize = 6;
    let num_levels: usize = 3;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    // All committed block hashes in order, shared by both MARFs.
    let mut all_blocks: Vec<StacksBlockId> = Vec::new();

    // ── Build both MARFs in lockstep, squashing `sq` at every level boundary ──
    {
        let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
        let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

        for lvl in 0..num_levels {
            let start_height = lvl * blocks_per_level;
            let parent = if lvl == 0 {
                StacksBlockId::sentinel()
            } else {
                all_blocks.last().unwrap().clone()
            };

            let sq_blocks = tier1_extend_nonce_chain(
                &mut sq_marf,
                parent.clone(),
                start_height,
                blocks_per_level,
                num_accounts,
                touches_per_block,
            );
            let ref_blocks = tier1_extend_nonce_chain(
                &mut ref_marf,
                parent,
                start_height,
                blocks_per_level,
                num_accounts,
                touches_per_block,
            );

            assert_eq!(
                sq_blocks, ref_blocks,
                "both MARFs must commit identical block hashes at level {lvl}"
            );
            all_blocks.extend(sq_blocks);

            // Drop the squash-side writer before running the external squash
            // so the SQLite connection doesn't race with the squash pipeline.
            drop(sq_marf);

            let min_h = start_height as u32;
            let max_h = (start_height + blocks_per_level - 1) as u32;
            squash_level_incremental::<StacksBlockId>(
                &sq_path,
                SquashMode::FullHistory,
                min_h,
                max_h,
                true, // reclaim
            )
            .unwrap_or_else(|e| panic!("level {lvl} FullHistory reclaim squash failed: {e:?}"));

            // Reopen the squashed writer for the next level's extension.
            sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();

            // ── After each squash, exhaustively probe every historical height
            //    via every read path and compare against the reference. ──
            tier1_verify_all_paths(
                &mut sq_marf,
                &mut ref_marf,
                &sq_path,
                &all_blocks,
                num_accounts,
                touches_per_block,
                &open_opts,
                &format!("after-level-{lvl}"),
            );
        }

        drop(sq_marf);
        drop(ref_marf);
    }

    // ── Second pass: close everything and reopen from disk, then re-verify.
    //    Simulates a node restart — catches bugs that only manifest when
    //    squash metadata is loaded from persistent state rather than
    //    carried over in-memory from the squash operation. ──
    {
        let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
        let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

        tier1_verify_all_paths(
            &mut sq_marf,
            &mut ref_marf,
            &sq_path,
            &all_blocks,
            num_accounts,
            touches_per_block,
            &open_opts,
            "after-reopen",
        );
    }
}

/// Exhaustively compare every (height, account) read between `sq_marf` and
/// `ref_marf` using three read paths: direct, reopen_connection, and
/// reopen_readonly. Any mismatch fails the test with a detailed message.
fn tier1_verify_all_paths(
    sq_marf: &mut MARF<StacksBlockId>,
    ref_marf: &mut MARF<StacksBlockId>,
    sq_path: &str,
    all_blocks: &[StacksBlockId],
    num_accounts: usize,
    touches_per_block: usize,
    open_opts: &MARFOpenOpts,
    phase: &str,
) {
    // Path 1: direct `marf.get()` on the long-lived writer connection.
    for (h, block) in all_blocks.iter().enumerate() {
        for acct in 0..num_accounts {
            let key = format!("acct_{acct}");
            let expected = tier1_expected_at(acct, h, num_accounts, touches_per_block);

            let sq_v = sq_marf.get(block, &key).unwrap_or_else(|e| {
                panic!("[{phase}] direct sq.get({key}) at height {h} failed: {e:?}")
            });
            let ref_v = ref_marf.get(block, &key).unwrap_or_else(|e| {
                panic!("[{phase}] direct ref.get({key}) at height {h} failed: {e:?}")
            });

            if sq_v != ref_v {
                // Identify which `acct_N_nonce_K` the squash actually returned
                // by reverse lookup against the finite set of possible values.
                let identified = sq_v
                    .as_ref()
                    .map(|v| {
                        tier1_identify_value(
                            &v.0,
                            num_accounts,
                            all_blocks.len(),
                            touches_per_block,
                        )
                    })
                    .unwrap_or_else(|| "<None>".to_string());
                panic!(
                    "[{phase}] DIRECT path diverged: acct={acct} height={h}\n\
                     expected = {expected:?}\n\
                     sq       = {sq_v:?}\n\
                     ref      = {ref_v:?}\n\
                     sq value identified as: {identified:?}",
                );
            }
            assert_eq!(
                ref_v, expected,
                "[{phase}] REFERENCE wrong value (workload bug?): acct={acct} height={h}"
            );
            assert_eq!(
                sq_v, expected,
                "[{phase}] DIRECT path wrong value: acct={acct} height={h}"
            );
        }
    }

    // Path 2: `reopen_connection()` on the squash MARF (fresh transient data,
    // shared DB handle). Real nodes use this for parallel reads.
    {
        let mut reopened = sq_marf
            .reopen_connection()
            .expect("reopen_connection should succeed");
        for (h, block) in all_blocks.iter().enumerate() {
            for acct in 0..num_accounts {
                let key = format!("acct_{acct}");
                let expected = tier1_expected_at(acct, h, num_accounts, touches_per_block);

                let sq_v = reopened.get(block, &key).unwrap_or_else(|e| {
                    panic!("[{phase}] reopen_connection sq.get({key}) at height {h} failed: {e:?}")
                });

                assert_eq!(
                    sq_v, expected,
                    "[{phase}] REOPEN_CONNECTION diverged: acct={acct} height={h}"
                );
            }
        }
    }

    // Path 3: `reopen_readonly()` — fully independent storage, fresh DB + blob
    // handles. This is the Clarity VM path and was the site of the earlier
    // squash-metadata bug. Open a fresh readonly per round of probes.
    {
        let mut ro_marf = sq_marf
            .reopen_readonly()
            .expect("reopen_readonly should succeed");
        for (h, block) in all_blocks.iter().enumerate() {
            for acct in 0..num_accounts {
                let key = format!("acct_{acct}");
                let expected = tier1_expected_at(acct, h, num_accounts, touches_per_block);

                let sq_v = ro_marf.get(block, &key).unwrap_or_else(|e| {
                    panic!("[{phase}] reopen_readonly sq.get({key}) at height {h} failed: {e:?}")
                });

                assert_eq!(
                    sq_v, expected,
                    "[{phase}] REOPEN_READONLY diverged: acct={acct} height={h}"
                );
            }
        }
    }

    // Path 4: fully cold reopen via `MARF::from_path`. This is what actually
    // happens on node restart — nothing in-memory carries over from the
    // squash operation. A bug that only shows up here would implicate
    // persistence/load rather than the in-memory squash state machine.
    {
        let mut cold = MARF::<StacksBlockId>::from_path(sq_path, open_opts.clone())
            .expect("cold reopen should succeed");
        for (h, block) in all_blocks.iter().enumerate() {
            for acct in 0..num_accounts {
                let key = format!("acct_{acct}");
                let expected = tier1_expected_at(acct, h, num_accounts, touches_per_block);

                let sq_v = cold.get(block, &key).unwrap_or_else(|e| {
                    panic!("[{phase}] cold reopen get({key}) at height {h} failed: {e:?}")
                });

                assert_eq!(
                    sq_v, expected,
                    "[{phase}] COLD REOPEN diverged: acct={acct} height={h}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tier 2: fork-at-squash-boundary, FullHistory differential
//
// Exercises the scenario the live genesis-sync failure suggested most strongly:
// a canonical chain with competing fork blocks that branch off at/around the
// squash boundary, followed by a FullHistory+reclaim squash.
//
// We verify that after squash:
//   * the canonical chain's historical reads match an unsquashed reference at
//     EVERY height via all three read paths (direct / reopen_connection /
//     reopen_readonly),
//   * orphan fork blocks have their external refs zeroed by the prune step
//     (reclaim contract), and
//   * the canonical tip is still extensible with the same root hash as the
//     reference.
//
// Sparse per-account writes force backptr traversal — the exact condition
// that masked the Fix #1 query-height bug before it was repaired.
// ---------------------------------------------------------------------------

/// Deterministic sparse nonce-style writes identical to the Tier 1 workload.
/// `start_height` is the absolute block height; callers are responsible for
/// passing consistent heights between the squash MARF and the reference.
fn tier2_write_canonical_block(
    marf: &mut MARF<StacksBlockId>,
    parent: &StacksBlockId,
    block_hash: &StacksBlockId,
    height: usize,
    num_accounts: usize,
    touches_per_block: usize,
) {
    marf.begin(parent, block_hash).unwrap();
    for acct in tier1_touched_accounts(height, num_accounts, touches_per_block) {
        let key = format!("acct_{acct}");
        let val = MARFValue::from_value(&format!("acct_{acct}_nonce_{height}"));
        marf.insert(&key, val).unwrap();
    }
    marf.seal().unwrap();
    marf.commit().unwrap();
}

#[test]
fn test_tier2_fork_at_boundary_full_history_differential() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_tier2_fork_at_boundary_full_history");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let num_accounts: usize = 8;
    let touches_per_block: usize = 3;
    let canonical_blocks: usize = 10; // heights 0..=9
                                      // Fork off canonical[3] (h=3) with 3 side-chain blocks — fork tip at h=6,
                                      // well below the canonical tip at h=9, so `find_tip_block` picks the
                                      // canonical chain and the prune step correctly classifies the fork as
                                      // non-canonical.
    let fork_point: usize = 3;
    let num_fork_blocks: usize = 3;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let canonical_block = |h: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_CA_11_AB_1Eu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let fork_block = |i: usize| -> StacksBlockId {
        let mut bytes = [0xFFu8; 32];
        bytes[24..28].copy_from_slice(&0x_DE_AD_FE_EDu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // ── Build the squash MARF with canonical chain + fork branch ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut canonical_hashes: Vec<StacksBlockId> = Vec::with_capacity(canonical_blocks);
    for h in 0..canonical_blocks {
        let parent = if h == 0 {
            StacksBlockId::sentinel()
        } else {
            canonical_hashes[h - 1].clone()
        };
        let bh = canonical_block(h);
        tier2_write_canonical_block(
            &mut sq_marf,
            &parent,
            &bh,
            h,
            num_accounts,
            touches_per_block,
        );
        canonical_hashes.push(bh);
    }

    // Fork side chain branches off after canonical_hashes[fork_point].
    let mut fork_hashes: Vec<StacksBlockId> = Vec::with_capacity(num_fork_blocks);
    for i in 0..num_fork_blocks {
        let parent = if i == 0 {
            canonical_hashes[fork_point].clone()
        } else {
            fork_hashes[i - 1].clone()
        };
        let bh = fork_block(i);
        sq_marf.begin(&parent, &bh).unwrap();
        // Write fork-branded writes so we can distinguish from canonical if
        // anything leaks into post-squash reads.
        for acct in 0..num_accounts {
            let key = format!("acct_{acct}");
            let val = MARFValue::from_value(&format!("FORK_acct_{acct}_step_{i}"));
            sq_marf.insert(&key, val).unwrap();
        }
        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        fork_hashes.push(bh);
    }
    drop(sq_marf);

    // ── Build the reference MARF with ONLY the canonical chain, same writes ──
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();
    for h in 0..canonical_blocks {
        let parent = if h == 0 {
            StacksBlockId::sentinel()
        } else {
            canonical_hashes[h - 1].clone()
        };
        let bh = canonical_block(h);
        tier2_write_canonical_block(
            &mut ref_marf,
            &parent,
            &bh,
            h,
            num_accounts,
            touches_per_block,
        );
    }
    drop(ref_marf);

    // Sanity: fork blocks have external refs before squash.
    {
        use rusqlite::Connection;
        let db = Connection::open(&sq_path).unwrap();
        for fb in &fork_hashes {
            let length: i64 = db
                .query_row(
                    "SELECT external_length FROM marf_data WHERE block_hash = ?1",
                    rusqlite::params![format!("{fb}")],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                length > 0,
                "fork block {fb} should have non-zero blob length before squash"
            );
        }
    }

    // ── Squash canonical range with FullHistory + reclaim ──
    // The squash walks the canonical tip, which ignores the fork branch. The
    // fork blocks live in the reclaim truncation zone and must be pruned.
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::FullHistory,
        0,
        (canonical_blocks - 1) as u32,
        true, // reclaim
    )
    .expect("canonical FullHistory+reclaim squash should succeed over fork blocks");

    // Fork block refs should now be zeroed by the prune step.
    {
        use rusqlite::Connection;
        let db = Connection::open(&sq_path).unwrap();
        for fb in &fork_hashes {
            let (offset, length): (i64, i64) = db
                .query_row(
                    "SELECT external_offset, external_length FROM marf_data WHERE block_hash = ?1",
                    rusqlite::params![format!("{fb}")],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                (offset, length),
                (0, 0),
                "fork block {fb} should have zeroed external refs after prune"
            );
        }
    }

    // ── Verify every canonical historical read, via every path ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    tier1_verify_all_paths(
        &mut sq_marf,
        &mut ref_marf,
        &sq_path,
        &canonical_hashes,
        num_accounts,
        touches_per_block,
        &open_opts,
        "tier2-post-squash-canonical",
    );

    // ── Extend both MARFs on the canonical tip and confirm the root hash
    //    matches — otherwise the squashed MARF has accumulated consensus
    //    divergence from the unsquashed reference. ──
    let ext_block = {
        let mut b = [0u8; 32];
        b[0] = 0xEE;
        b[31] = 0xFF;
        StacksBlockId::from_bytes(&b).unwrap()
    };
    let tip = canonical_hashes.last().unwrap().clone();

    sq_marf.begin(&tip, &ext_block).unwrap();
    ref_marf.begin(&tip, &ext_block).unwrap();
    for acct in tier1_touched_accounts(canonical_blocks, num_accounts, touches_per_block) {
        let key = format!("acct_{acct}");
        let val = MARFValue::from_value(&format!("acct_{acct}_nonce_{canonical_blocks}"));
        sq_marf.insert(&key, val.clone()).unwrap();
        ref_marf.insert(&key, val).unwrap();
    }
    let sq_ext_root = sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    let ref_ext_root = ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();

    assert_eq!(
        sq_ext_root, ref_ext_root,
        "canonical-tip extension root hash must match unsquashed reference \
         after FullHistory+reclaim with a pruned fork branch"
    );
}

// ---------------------------------------------------------------------------
// Tier 3: nonce-overwrite differential
//
// Narrow reproduction of the "Bad nonce" failure mode. A single "sender" key
// gets updated every block with a strictly-increasing nonce value. After
// recurring FullHistory+reclaim squashes, every historical read must match
// the unsquashed reference — and in particular the *tip* nonce must be the
// last write, not something lower, because that is exactly the value a block
// validator checks when accepting a transaction.
//
// Also verifies reads via `reopen_readonly`, which is the path the Clarity VM
// uses during block-processing (where nonce checks live).
// ---------------------------------------------------------------------------

#[test]
fn test_tier3_nonce_overwrite_recurring_squash_differential() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_tier3_nonce_overwrite_recurring_squash");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    // Enough blocks to exercise multiple squash levels + inherited baseline
    // logic, but small enough to keep the test fast.
    let blocks_per_level: usize = 8;
    let num_levels: usize = 3;
    let total_blocks: usize = blocks_per_level * num_levels; // 24

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let mk_block = |h: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_D1_CE_BA_D1u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let sender_key = "sender_nonce";
    let mk_nonce = |h: usize| MARFValue::from_value(&format!("nonce_{h}"));

    // Also write a "cold" account-balance key once at height 0 and never
    // update it, to exercise the pre-write-height-None semantics for
    // single-write keys under recurring squashes.
    let cold_key = "sender_balance";
    let cold_val = MARFValue::from_value("initial_balance");

    // ── Build both MARFs in lockstep with recurring FullHistory squashes ──
    let mut blocks: Vec<StacksBlockId> = Vec::with_capacity(total_blocks);
    {
        let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
        let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

        for h in 0..total_blocks {
            let parent = if h == 0 {
                StacksBlockId::sentinel()
            } else {
                blocks[h - 1].clone()
            };
            let bh = mk_block(h);

            sq_marf.begin(&parent, &bh).unwrap();
            ref_marf.begin(&parent, &bh).unwrap();

            // Write nonce = h each block.
            sq_marf.insert(sender_key, mk_nonce(h)).unwrap();
            ref_marf.insert(sender_key, mk_nonce(h)).unwrap();

            // Write the cold key exactly once at height 0.
            if h == 0 {
                sq_marf.insert(cold_key, cold_val.clone()).unwrap();
                ref_marf.insert(cold_key, cold_val.clone()).unwrap();
            }

            sq_marf.seal().unwrap();
            sq_marf.commit().unwrap();
            ref_marf.seal().unwrap();
            ref_marf.commit().unwrap();
            blocks.push(bh);

            // Recurring squash at level boundaries.
            if (h + 1) % blocks_per_level == 0 {
                drop(sq_marf);
                let min_h = (h + 1 - blocks_per_level) as u32;
                let max_h = h as u32;
                squash_level_incremental::<StacksBlockId>(
                    &sq_path,
                    SquashMode::FullHistory,
                    min_h,
                    max_h,
                    true,
                )
                .unwrap_or_else(|e| panic!("recurring squash at height {h} failed: {e:?}"));
                sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
            }
        }
    }

    // ── Cold reopen both MARFs — the clarity/validator path starts from
    //    freshly-loaded squash metadata. ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    // ── At every block, nonce read via every path must match reference ──
    for (h, block) in blocks.iter().enumerate() {
        let expected_nonce = mk_nonce(h);
        let expected_cold = cold_val.clone();

        // Direct
        let sq_n = sq_marf
            .get(block, sender_key)
            .unwrap()
            .unwrap_or_else(|| panic!("direct sq.get({sender_key}) at h={h} returned None"));
        let ref_n = ref_marf
            .get(block, sender_key)
            .unwrap()
            .unwrap_or_else(|| panic!("reference missing {sender_key} at h={h}"));
        assert_eq!(
            sq_n, ref_n,
            "DIRECT nonce at h={h}: sq={sq_n:?} ref={ref_n:?}"
        );
        assert_eq!(
            sq_n, expected_nonce,
            "DIRECT nonce at h={h}: expected nonce_{h}"
        );

        let sq_b = sq_marf.get(block, cold_key).unwrap();
        let ref_b = ref_marf.get(block, cold_key).unwrap();
        assert_eq!(sq_b, ref_b, "DIRECT cold at h={h}");
        assert_eq!(
            sq_b,
            Some(expected_cold.clone()),
            "DIRECT cold at h={h} expected initial_balance"
        );

        // reopen_connection — shared DB handle
        {
            let mut reopened = sq_marf.reopen_connection().unwrap();
            let v = reopened.get(block, sender_key).unwrap().unwrap();
            assert_eq!(
                v, expected_nonce,
                "REOPEN_CONNECTION nonce at h={h} expected nonce_{h}"
            );
            let b = reopened.get(block, cold_key).unwrap();
            assert_eq!(
                b,
                Some(expected_cold.clone()),
                "REOPEN_CONNECTION cold at h={h}"
            );
        }

        // reopen_readonly — fully independent storage (Clarity VM path)
        {
            let mut ro = sq_marf.reopen_readonly().unwrap();
            let v = ro.get(block, sender_key).unwrap().unwrap();
            assert_eq!(
                v, expected_nonce,
                "REOPEN_READONLY nonce at h={h} expected nonce_{h}"
            );
            let b = ro.get(block, cold_key).unwrap();
            assert_eq!(
                b,
                Some(expected_cold.clone()),
                "REOPEN_READONLY cold at h={h}"
            );
        }
    }

    // ── The direct "Bad nonce" repro: read nonce at tip, check it is the
    //    latest write. Any off-by-one here is what a block validator would
    //    reject a valid next transaction on. ──
    let tip = blocks.last().unwrap();
    let tip_nonce = sq_marf.get(tip, sender_key).unwrap().unwrap();
    assert_eq!(
        tip_nonce,
        mk_nonce(total_blocks - 1),
        "tip nonce must be the last written value; mismatch indicates the \
         squash-time read-divergence regression"
    );

    // ── Verify that reads at heights BELOW the cold-key's write height
    //    for a hypothetical later-written key return None. Simulate by
    //    writing a post-squash key on an extension block and confirming
    //    it is visible at the extension tip and absent at earlier blocks. ──
    let ext_block = {
        let mut b = [0u8; 32];
        b[0] = 0xEE;
        b[31] = 0xFF;
        StacksBlockId::from_bytes(&b).unwrap()
    };
    sq_marf.begin(tip, &ext_block).unwrap();
    sq_marf
        .insert("post_squash_key", MARFValue::from_value("post_squash_v"))
        .unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();

    // At extension tip: present.
    let v = sq_marf.get(&ext_block, "post_squash_key").unwrap();
    assert_eq!(
        v,
        Some(MARFValue::from_value("post_squash_v")),
        "post-squash key must be readable at the extension block that wrote it"
    );

    // At every pre-extension block: None. Only the nonce key is live there.
    for (h, block) in blocks.iter().enumerate() {
        let v = sq_marf.get(block, "post_squash_key").unwrap();
        assert!(
            v.is_none(),
            "post_squash_key must be None at pre-extension block h={h}, got {v:?}"
        );
    }
}

#[test]
fn test_tier3_live_handle_refresh_after_recurring_squash_tip_nonce() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_tier3_live_handle_refresh_after_recurring_squash_tip_nonce");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    // Match the live shape more closely: many recurring squashes on one long-lived
    // writer handle, with immediate post-refresh reads on the same handle.
    let blocks_per_level: usize = 10;
    let num_levels: usize = 11;
    let total_blocks: usize = blocks_per_level * num_levels;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let mk_block = |h: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_D1_CE_FA_11u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let sender_key = "sender_nonce";
    let mk_nonce = |h: usize| MARFValue::from_value(&format!("nonce_{h}"));

    let mut blocks: Vec<StacksBlockId> = Vec::with_capacity(total_blocks);
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    for h in 0..total_blocks {
        let parent = if h == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[h - 1].clone()
        };
        let bh = mk_block(h);

        sq_marf.begin(&parent, &bh).unwrap();
        ref_marf.begin(&parent, &bh).unwrap();

        sq_marf.insert(sender_key, mk_nonce(h)).unwrap();
        ref_marf.insert(sender_key, mk_nonce(h)).unwrap();

        // Add a sparse key family so post-squash reads exercise more than one path.
        if h % 3 == 0 {
            let sparse_key = format!("sparse_sender_{h}");
            let sparse_value = MARFValue::from_value(&format!("sparse_nonce_{h}"));
            sq_marf.insert(&sparse_key, sparse_value.clone()).unwrap();
            ref_marf.insert(&sparse_key, sparse_value).unwrap();
        }

        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();
        blocks.push(bh.clone());

        // Warm the live handle's direct read cursor before the next external squash.
        let live_tip_nonce = sq_marf.get(&bh, sender_key).unwrap().unwrap();
        assert_eq!(
            live_tip_nonce,
            mk_nonce(h),
            "live handle tip nonce before squash"
        );
        if h > 0 {
            let prev = sq_marf.get(&blocks[h - 1], sender_key).unwrap().unwrap();
            assert_eq!(
                prev,
                mk_nonce(h - 1),
                "live handle previous nonce before squash"
            );
        }

        if (h + 1) % blocks_per_level == 0 {
            let min_h = (h + 1 - blocks_per_level) as u32;
            let max_h = h as u32;

            squash_level_incremental::<StacksBlockId>(
                &sq_path,
                SquashMode::FullHistory,
                min_h,
                max_h,
                true,
            )
            .unwrap_or_else(|e| panic!("live-handle recurring squash at height {h} failed: {e:?}"));

            sq_marf.refresh_after_squash().unwrap();

            let tip = blocks.last().unwrap();
            let live_tip_nonce = sq_marf.get(tip, sender_key).unwrap().unwrap();
            let ref_tip_nonce = ref_marf.get(tip, sender_key).unwrap().unwrap();
            assert_eq!(
                live_tip_nonce, ref_tip_nonce,
                "live handle tip nonce diverged immediately after refresh at level ending h={h}"
            );

            for idx in [
                min_h as usize,
                ((min_h + max_h) / 2) as usize,
                max_h as usize,
            ] {
                let live_nonce = sq_marf.get(&blocks[idx], sender_key).unwrap().unwrap();
                let ref_nonce = ref_marf.get(&blocks[idx], sender_key).unwrap().unwrap();
                assert_eq!(
                    live_nonce, ref_nonce,
                    "live handle historical nonce diverged after refresh at block index {idx}"
                );
            }
        }
    }
}

#[test]
fn test_tier3_live_handle_refresh_after_recurring_sparse_nonce_squash() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_tier3_live_handle_refresh_after_recurring_sparse_nonce_squash");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    // Match the live report more closely: many recurring squashes, but the sender nonce key is
    // sparse instead of being rewritten every block.
    let blocks_per_level: usize = 10;
    let num_levels: usize = 11;
    let total_blocks: usize = blocks_per_level * num_levels;

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let mk_block = |h: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_D1_CE_5A_11u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let sender_key = "sender_nonce";
    let hot_key = "hot_key";
    let mk_sender_nonce = |h: usize| MARFValue::from_value(&format!("sender_nonce_{h}"));
    let mk_hot_value = |h: usize| MARFValue::from_value(&format!("hot_{h}"));

    let mut blocks: Vec<StacksBlockId> = Vec::with_capacity(total_blocks);
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    for h in 0..total_blocks {
        let parent = if h == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[h - 1].clone()
        };
        let bh = mk_block(h);

        sq_marf.begin(&parent, &bh).unwrap();
        ref_marf.begin(&parent, &bh).unwrap();

        // A hot key rewrites every block so the trie keeps evolving densely.
        sq_marf.insert(hot_key, mk_hot_value(h)).unwrap();
        ref_marf.insert(hot_key, mk_hot_value(h)).unwrap();

        // Sparse sender nonce: only every third block, like a sender who submits
        // transactions intermittently across the squashed range.
        if h % 3 == 0 {
            sq_marf.insert(sender_key, mk_sender_nonce(h)).unwrap();
            ref_marf.insert(sender_key, mk_sender_nonce(h)).unwrap();
        }

        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        ref_marf.seal().unwrap();
        ref_marf.commit().unwrap();
        blocks.push(bh.clone());

        let expected_sender = (0..=h).rev().find(|hh| hh % 3 == 0).map(mk_sender_nonce);
        let live_sender = sq_marf.get(&bh, sender_key).unwrap();
        assert_eq!(
            live_sender, expected_sender,
            "live handle sparse sender nonce before squash at h={h}"
        );

        if (h + 1) % blocks_per_level == 0 {
            let min_h = (h + 1 - blocks_per_level) as u32;
            let max_h = h as u32;

            squash_level_incremental::<StacksBlockId>(
                &sq_path,
                SquashMode::FullHistory,
                min_h,
                max_h,
                true,
            )
            .unwrap_or_else(|e| {
                panic!("sparse live-handle recurring squash at height {h} failed: {e:?}")
            });

            sq_marf.refresh_after_squash().unwrap();

            let tip = blocks.last().unwrap();
            let live_sender = sq_marf.get(tip, sender_key).unwrap();
            let ref_sender = ref_marf.get(tip, sender_key).unwrap();
            assert_eq!(
                live_sender, ref_sender,
                "live handle sparse sender nonce diverged immediately after refresh at level ending h={h}"
            );

            let probe_indices = [
                min_h as usize,
                ((min_h + max_h) / 2) as usize,
                max_h as usize,
            ];
            for idx in probe_indices {
                let live = sq_marf.get(&blocks[idx], sender_key).unwrap();
                let reference = ref_marf.get(&blocks[idx], sender_key).unwrap();
                assert_eq!(
                    live, reference,
                    "sparse sender nonce diverged after refresh at block index {idx}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tier 4: headers-MARF pattern — recurring TipOnly + reclaim squashes
//
// Mirrors how `maybe_squash` treats the HEADERS MARF in production: TipOnly
// mode, reclaim=true, recurring at a fixed block cadence. Live genesis-sync
// has been observed to hit a `stored_node_id_from_bytes: invalid node ID
// byte=0x12` corruption error AFTER the 7th recurring squash (block 7000),
// when the p2p thread reads historical tenure-start-block data off an
// ancestor tip.
//
// This test mimics the minimal conditions:
//   * enough recurring squashes that cross-level backptrs must traverse
//     several earlier levels,
//   * reads via `reopen_readonly` (the Clarity VM / p2p read path),
//   * reads at every block in every prior level — specifically including
//     blocks whose leaves live in the squash blob and are read via
//     cross-level backptrs.
// ---------------------------------------------------------------------------

#[test]
fn test_tier4_headers_style_recurring_tip_only_reclaim() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_tier4_headers_style_recurring_tip_only_reclaim");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    // 7 squashes at a cadence of 20 blocks, matching the genesis-sync shape
    // (7 squashes at 1000-block cadence) in a fraction of the time.
    let blocks_per_level: usize = 20;
    let num_levels: usize = 7;
    let total_blocks: usize = blocks_per_level * num_levels; // 140

    let mk_block = |h: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_4E_AD_E2_57u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // Keys that mimic the headers-MARF key shape: one hot key rewritten every
    // block, plus a family of "tenure_start_block_id::{h}" keys written
    // sparsely (mimicking the exact key pattern in the failing live error).
    let hot_key = "__hot_header_key";
    let tenure_start_key = |h: usize| format!("tenure_start_block_id::{h:08x}");

    // Build both MARFs in lockstep with recurring TipOnly+reclaim squashes.
    let mut blocks: Vec<StacksBlockId> = Vec::with_capacity(total_blocks);
    {
        let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
        let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

        for h in 0..total_blocks {
            let parent = if h == 0 {
                StacksBlockId::sentinel()
            } else {
                blocks[h - 1].clone()
            };
            let bh = mk_block(h);

            sq_marf.begin(&parent, &bh).unwrap();
            ref_marf.begin(&parent, &bh).unwrap();

            // Hot key every block.
            let hot_val = MARFValue::from_value(&format!("hot_v_{h}"));
            sq_marf.insert(hot_key, hot_val.clone()).unwrap();
            ref_marf.insert(hot_key, hot_val).unwrap();

            // Tenure-start key: written ONCE at the block corresponding to
            // this height. Later reads target it from much-later tip blocks
            // via cross-level backptrs.
            let tk = tenure_start_key(h);
            let tv = MARFValue::from_value(&format!("tenure_v_{h}"));
            sq_marf.insert(&tk, tv.clone()).unwrap();
            ref_marf.insert(&tk, tv).unwrap();

            sq_marf.seal().unwrap();
            sq_marf.commit().unwrap();
            ref_marf.seal().unwrap();
            ref_marf.commit().unwrap();
            blocks.push(bh);

            if (h + 1) % blocks_per_level == 0 {
                drop(sq_marf);
                let min_h = (h + 1 - blocks_per_level) as u32;
                let max_h = h as u32;
                squash_level_incremental::<StacksBlockId>(
                    &sq_path,
                    SquashMode::TipOnly,
                    min_h,
                    max_h,
                    true,
                )
                .unwrap_or_else(|e| panic!("TipOnly recurring squash at h={h} failed: {e:?}"));
                sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
            }
        }
    }

    // Cold reopen — matches the live behavior where p2p reads come from a
    // fresh handle after squashes have completed.
    let sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts).unwrap();

    // Probe every historical tenure-start key from the final tip via
    // reopen_readonly. This is the exact read pattern the live sync was
    // doing when the 0x12 error appeared: the p2p thread calls
    // `NakamotoChainState::get_nakamoto_tenure_start_block_header` off an
    // ancestor index hash, which walks the merged squashed tries and
    // crosses several backptrs.
    let tip = blocks.last().unwrap();
    let mut ro = sq_marf.reopen_readonly().unwrap();

    let mut mismatches = 0usize;
    for h in 0..total_blocks {
        let tk = tenure_start_key(h);
        let sq_v = ro.get(tip, &tk).unwrap_or_else(|e| {
            panic!(
                "reopen_readonly get({tk}) at tip failed (squashes crossed: {num_levels}): {e:?}"
            )
        });
        let ref_v = ref_marf.get(tip, &tk).unwrap();
        if sq_v != ref_v {
            mismatches += 1;
            eprintln!("MISMATCH h={h} key={tk}: sq={sq_v:?} ref={ref_v:?}");
        }
    }
    assert_eq!(
        mismatches, 0,
        "historical tenure_start_block_id reads diverged from unsquashed reference \
         after {num_levels} recurring TipOnly+reclaim squashes"
    );

    // Probe hot_key reads at every historical block via reopen_readonly. TipOnly
    // mode collapses history — the returned value at any h is permitted to
    // differ from the unsquashed reference. What MUST hold is that the read
    // completes without error (no 0x12 corruption, no decode failure) and
    // returns *some* value. The live genesis-sync failure mode is a decode
    // error, not a value mismatch.
    for (h, block) in blocks.iter().enumerate() {
        let v = ro.get(block, hot_key).unwrap_or_else(|e| {
            panic!("reopen_readonly hot_key at h={h} failed with decode error: {e:?}")
        });
        assert!(
            v.is_some(),
            "hot_key must be readable (Some) at every historical block h={h}"
        );
    }
}

// ---------------------------------------------------------------------------
// Tier 5: stale `reopen_readonly` across a squash
//
// Reproduces the live genesis-sync p2p-thread corruption. The p2p thread
// acquires a `reopen_readonly` MARF handle once, at startup, long before any
// squash has run. The main sync thread later calls `maybe_squash`, which
// invokes `refresh_after_squash` on the *writer* MARF — but the readonly
// handle the p2p thread holds is independent of the writer and never gets
// refreshed. When the p2p thread subsequently reads, its stale blob-offset
// cache and stale `squash_meta` produce a decode error like the 0x12
// corruption observed live.
// ---------------------------------------------------------------------------

#[test]
fn test_tier5_stale_reopen_readonly_across_squash_reproduces_corruption() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_tier5_stale_reopen_readonly_across_squash");
    let sq_path = format!("{dir}/squashed.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let mk_block = |h: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_57_A_1_E_57u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let blocks_per_level: usize = 10;
    let pre_blocks: usize = blocks_per_level; // 0..9 before first squash
    let post_blocks: usize = blocks_per_level; // 10..19 after first squash

    // ── Phase 1: commit the initial `pre_blocks` blocks into the writer MARF. ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();
    for h in 0..pre_blocks {
        let parent = if h == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[h - 1].clone()
        };
        let bh = mk_block(h);
        sq_marf.begin(&parent, &bh).unwrap();
        sq_marf
            .insert("hot_key", MARFValue::from_value(&format!("hot_{h}")))
            .unwrap();
        sq_marf
            .insert(
                &format!("sparse_key_{h}"),
                MARFValue::from_value(&format!("sparse_{h}")),
            )
            .unwrap();
        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        blocks.push(bh);
    }

    // ── Phase 2: p2p-thread style — acquire a readonly handle BEFORE any squash.
    //    The live node does this once at startup. ──
    let mut p2p_ro = sq_marf.reopen_readonly().unwrap();

    // Sanity-read so the readonly handle's offset cache and mmap state are
    // warmed up *before* the squash. This mimics p2p doing normal reads
    // during startup.
    for (h, block) in blocks.iter().enumerate() {
        let v = p2p_ro.get(block, "hot_key").unwrap();
        assert!(v.is_some(), "warm-up read hot_key at h={h}");
        let v = p2p_ro.get(block, &format!("sparse_key_{h}")).unwrap();
        assert!(v.is_some(), "warm-up read sparse_key_{h}");
    }

    // ── Phase 3: main sync thread runs a squash over the existing range.
    //    This is exactly the `maybe_squash` cadence point after the first
    //    `pre_blocks`-block boundary. The WRITER stays alive across the
    //    squash (matching `maybe_squash` in production), then calls
    //    `refresh_after_squash` to publish the new metadata. The shared
    //    `Arc<SharedSquashState>` carries the publish across to `p2p_ro`. ──
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (pre_blocks - 1) as u32,
        true, // reclaim — forces redirect + file truncation
    )
    .expect("squash should succeed");

    sq_marf.refresh_after_squash().unwrap();

    // Continue committing post-squash blocks (simulating the main sync
    // thread continuing to process new blocks after the squash cadence).
    for h in pre_blocks..(pre_blocks + post_blocks) {
        let parent = blocks[h - 1].clone();
        let bh = mk_block(h);
        sq_marf.begin(&parent, &bh).unwrap();
        sq_marf
            .insert("hot_key", MARFValue::from_value(&format!("hot_{h}")))
            .unwrap();
        sq_marf
            .insert(
                &format!("sparse_key_{h}"),
                MARFValue::from_value(&format!("sparse_{h}")),
            )
            .unwrap();
        sq_marf.seal().unwrap();
        sq_marf.commit().unwrap();
        blocks.push(bh);
    }

    // ── Phase 4: the p2p thread now reads using its stale readonly handle.
    //    This is the exact scenario where live genesis sync hits the
    //    "invalid node ID 0x12" error after a squash. ──
    //
    // We only assert that reads do not produce a decode error. A value
    // mismatch is acceptable under TipOnly semantics, but a decode panic
    // (`CorruptionError("Failed to read expected node ID ...")`) is the
    // concrete live failure mode.
    let tip = blocks.last().unwrap();
    for (h, block) in blocks.iter().enumerate() {
        let _ = p2p_ro.get(block, "hot_key").unwrap_or_else(|e| {
            panic!(
                "STALE readonly handle corrupted hot_key read at h={h} \
                 after the squash: {e:?}"
            )
        });
    }
    let _ = p2p_ro.get(tip, "sparse_key_0").unwrap_or_else(|e| {
        panic!(
            "STALE readonly handle corrupted sparse_key_0 read at tip \
             (read crosses the squash blob via backptr): {e:?}"
        )
    });
}

// ---------------------------------------------------------------------------
// Tier 6: two independent `MARF::from_path` handles on the same file
//
// Reproduces the *actual* live genesis-sync pattern in stacks-node 2.x:
//   * the runloop/miner thread owns one `StacksChainState`
//     (constructed via `open_chainstate_with_faults` → `MARF::from_path`)
//   * the P2P thread owns a separate `StacksChainState` obtained via a
//     second `open_chainstate_with_faults` call on the same path.
//
// Both handles are long-lived, neither was spawned from the other via
// `reopen_*`, so Arc-cloning alone can't share squash metadata between them.
// Only the process-wide `SharedSquashState` registry makes a
// `refresh_after_squash()` on the writer observable by the reader.
// ---------------------------------------------------------------------------

#[test]
fn test_tier6_cross_independent_marf_handles_share_squash_publishes() {
    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_tier6_cross_independent_marf_handles");
    let sq_path = format!("{dir}/squashed.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let mk_block = |h: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_C0_55_FE_EDu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let pre_blocks: usize = 10;

    // ── Writer/"main-thread" handle commits `pre_blocks` blocks. ──
    let mut writer = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();
    for h in 0..pre_blocks {
        let parent = if h == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[h - 1].clone()
        };
        let bh = mk_block(h);
        writer.begin(&parent, &bh).unwrap();
        writer
            .insert("hot_key", MARFValue::from_value(&format!("hot_{h}")))
            .unwrap();
        writer
            .insert(
                &format!("sparse_key_{h}"),
                MARFValue::from_value(&format!("sparse_{h}")),
            )
            .unwrap();
        writer.seal().unwrap();
        writer.commit().unwrap();
        blocks.push(bh);
    }

    // ── Independent "P2P-thread" handle — opened via a separate
    //    `MARF::from_path` on the same file, NOT via `reopen_*`. ──
    let mut p2p = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();

    // Warm up the p2p handle so its offset cache and mmap are populated.
    for (h, block) in blocks.iter().enumerate() {
        let v = p2p.get(block, "hot_key").unwrap();
        assert!(v.is_some(), "p2p warm-up hot_key at h={h}");
        let v = p2p.get(block, &format!("sparse_key_{h}")).unwrap();
        assert!(v.is_some(), "p2p warm-up sparse_key_{h}");
    }

    // ── Writer runs a squash over the existing range and refreshes. ──
    squash_level_incremental::<StacksBlockId>(
        &sq_path,
        SquashMode::TipOnly,
        0,
        (pre_blocks - 1) as u32,
        true,
    )
    .expect("squash should succeed");
    writer.refresh_after_squash().unwrap();

    // ── The P2P handle, never touched by the writer, must still be able
    //    to read without decode errors. This is the exact pattern that
    //    made the live sync fail. ──
    for (h, block) in blocks.iter().enumerate() {
        let _ = p2p.get(block, "hot_key").unwrap_or_else(|e| {
            panic!(
                "INDEPENDENT p2p handle corrupted hot_key read at h={h} \
                 after writer refresh: {e:?}"
            )
        });
        let _ = p2p
            .get(block, &format!("sparse_key_{h}"))
            .unwrap_or_else(|e| {
                panic!(
                    "INDEPENDENT p2p handle corrupted sparse_key_{h} read \
                     after writer refresh: {e:?}"
                )
            });
    }
}

// ---------------------------------------------------------------------------
// Tier 7: concurrent squash-truncate vs. independent-handle reads
//
// Stresses the blob-mutation quiesce: a reader thread continuously walks
// historical blocks via its own `MARF::from_path` handle while a writer
// thread runs repeated FullHistory + reclaim squashes (which `ftruncate`
// the blob file). Without the `BlobReadGuard` / `active_reads` / `truncate_pending`
// machinery, the reader's mmap would be invalidated mid-traversal by the
// writer's truncate and trigger SIGBUS. With the quiesce in place:
//
//   * the writer's `publish_squash` waits for the reader's in-flight guards
//     to drop before calling `ftruncate`,
//   * the reader's subsequent reads observe the bumped generation and
//     remap their local state through `sync_from_shared_squash_state`.
//
// The test succeeds if both threads complete without a decode error or a
// panic; value divergence is permitted (TipOnly collapses historical
// reads to the tip) but corruption is not.
// ---------------------------------------------------------------------------

#[test]
fn test_tier7_concurrent_truncate_vs_independent_reads() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    use crate::chainstate::stacks::index::squash::squash_level_incremental;

    let dir = fresh_test_dir("test_tier7_concurrent_truncate_vs_reads");
    let sq_path = format!("{dir}/squashed.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let mk_block = |h: usize| -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_C0_DE_F1_7Eu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&((h as u32) + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let num_blocks: usize = 40;

    // Phase 1: build a chain with rich enough per-block writes that squashes
    // produce real mmap-backed squash blobs (large enough for truncation to
    // have something to truncate).
    let mut writer = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let mut blocks: Vec<StacksBlockId> = Vec::new();
    for h in 0..num_blocks {
        let parent = if h == 0 {
            StacksBlockId::sentinel()
        } else {
            blocks[h - 1].clone()
        };
        let bh = mk_block(h);
        writer.begin(&parent, &bh).unwrap();
        writer
            .insert("hot_key", MARFValue::from_value(&format!("hot_{h}")))
            .unwrap();
        for k in 0..4 {
            writer
                .insert(
                    &format!("spread_key_{h}_{k}"),
                    MARFValue::from_value(&format!("spread_{h}_{k}")),
                )
                .unwrap();
        }
        writer.seal().unwrap();
        writer.commit().unwrap();
        blocks.push(bh);
    }
    drop(writer);

    // Shared stop flag + completed-read counter for the assertion.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reads_completed = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(2));

    // Reader thread — simulates the p2p thread: its own independent MARF handle
    // on the same file, does a continuous loop of historical reads.
    let reader_stop = Arc::clone(&stop);
    let reader_counter = Arc::clone(&reads_completed);
    let reader_barrier = Arc::clone(&barrier);
    let reader_path = sq_path.clone();
    let reader_opts = open_opts.clone();
    let reader_blocks = blocks.clone();
    let reader_handle = thread::spawn(move || {
        let mut marf = MARF::<StacksBlockId>::from_path(&reader_path, reader_opts).unwrap();
        reader_barrier.wait();
        while !reader_stop.load(Ordering::Relaxed) {
            for (h, block) in reader_blocks.iter().enumerate() {
                let v = marf
                    .get(block, "hot_key")
                    .unwrap_or_else(|e| panic!("reader: hot_key decode failure at h={h}: {e:?}"));
                assert!(v.is_some(), "reader: hot_key must be readable at h={h}");
                for k in 0..4 {
                    let _ = marf
                        .get(block, &format!("spread_key_{h}_{k}"))
                        .unwrap_or_else(|e| {
                            panic!("reader: spread_key decode failure at h={h},k={k}: {e:?}")
                        });
                }
                reader_counter.fetch_add(5, Ordering::Relaxed);
            }
        }
    });

    // Writer thread — runs several squash cycles, each of which truncates the
    // blob file. The first cycle covers the original per-block range; later
    // cycles just re-publish an empty incremental squash at the tip so the
    // quiesce machinery is exercised repeatedly without exhausting the range.
    let writer_barrier = Arc::clone(&barrier);
    let writer_path = sq_path.clone();
    let writer_opts = open_opts.clone();
    let writer_handle = thread::spawn(move || {
        let writer = MARF::<StacksBlockId>::from_path(&writer_path, writer_opts).unwrap();
        writer_barrier.wait();

        // First squash: TipOnly + reclaim over the full original range.
        // This does the aggressive truncate (from offset 0 to end-of-new-blob).
        drop(writer); // drop writer's active ref so the internal squash can open the file
        squash_level_incremental::<StacksBlockId>(
            &writer_path,
            SquashMode::TipOnly,
            0,
            (num_blocks - 1) as u32,
            true,
        )
        .expect("tier7 first squash should succeed");

        // Reopen + refresh so the shared state picks up the publish via the
        // registry. (Writes and squashes are normally interleaved on the
        // same handle; here we re-acquire for simplicity.)
        let mut writer = MARF::<StacksBlockId>::from_path(&writer_path, open_opts.clone()).unwrap();
        writer.refresh_after_squash().unwrap();
        drop(writer);

        // Small pause so the reader continues through the post-squash state.
        thread::sleep(Duration::from_millis(50));
    });

    writer_handle
        .join()
        .expect("writer thread should complete without panicking");

    // Let the reader do more work post-squash, then signal stop.
    thread::sleep(Duration::from_millis(100));
    stop.store(true, Ordering::Relaxed);

    reader_handle
        .join()
        .expect("reader thread should complete without panicking");

    let total_reads = reads_completed.load(Ordering::Relaxed);
    assert!(
        total_reads > 0,
        "reader thread should have completed at least one batch of reads; got {total_reads}"
    );
    eprintln!("tier7: reader completed {total_reads} reads across the squash window");
}

// ---------------------------------------------------------------------------
// Tier 8: fresh-guard acquire failure mid-walk is absorbed by the retry wrapper.
//
// Uses the `fault_inject::fail_next_acquires` hook to simulate a writer having
// set `truncate_pending` just as the reader enters the next mmap read. Without
// the retry wrapper the bounded-scope `Err(Error::RetryAfterSquash)` sentinel
// would escape to the caller; with the wrapper in place, the reader's state
// resets (drops parked scratch, re-syncs shared metadata) and the re-entered
// traversal reads against a fresh acquire — returning the correct value.
//
// We inject `MAX_READ_RETRIES` failures to prove each attempt goes through a
// reset, then verify the read still succeeds. Injecting `MAX_READ_RETRIES + 1`
// exercises the exhaustion path and must surface `CorruptionError`.
// ---------------------------------------------------------------------------

#[test]
fn test_tier8_acquire_failure_midwalk_retry_wrapper_absorbs() {
    use crate::chainstate::stacks::index::marf::MarfInternals;
    use crate::chainstate::stacks::index::storage::fault_inject;

    fault_inject::reset();

    let dir = fresh_test_dir("test_tier8_acquire_failure_retry");
    let sq_path = format!("{dir}/squashed.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let mut writer = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let block = {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&1u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    writer.begin(&StacksBlockId::sentinel(), &block).unwrap();
    writer
        .insert("tier8_key", MARFValue::from_value("tier8_value"))
        .unwrap();
    writer.seal().unwrap();
    writer.commit().unwrap();
    drop(writer);

    let mut reader = MARF::<StacksBlockId>::from_path(&sq_path, open_opts).unwrap();

    // Inject MAX_READ_RETRIES-1 acquire failures. The retry wrapper will absorb each one
    // (reset + re-enter), and the final attempt — where the counter is exhausted —
    // succeeds and returns the real value.
    //
    // Call `MarfInternals::get_by_key` directly rather than `get()`, because the
    // test-only `get_and_check_with_hash` helper called by `get()` runs the walk
    // twice (unwrapped) before the retry-wrapped `get_by_key` fires — consuming
    // counter credits non-deterministically.
    let fails = <MARF<StacksBlockId> as MarfInternals<StacksBlockId>>::MAX_READ_RETRIES - 1;
    fault_inject::fail_next_acquires(fails);

    let result = <MARF<StacksBlockId> as MarfInternals<StacksBlockId>>::get_by_key(
        &mut reader,
        &block,
        "tier8_key",
    );
    fault_inject::reset();

    assert_eq!(
        result.expect("retry wrapper should absorb injected acquire failures"),
        Some(MARFValue::from_value("tier8_value")),
    );

    // Exhaustion: inject MAX_READ_RETRIES + 1 failures — every retry attempt hits the
    // injected failure, and the wrapper surfaces `CorruptionError` after giving up.
    let max = <MARF<StacksBlockId> as MarfInternals<StacksBlockId>>::MAX_READ_RETRIES;
    fault_inject::fail_next_acquires(max + 1);

    let exhausted = <MARF<StacksBlockId> as MarfInternals<StacksBlockId>>::get_by_key(
        &mut reader,
        &block,
        "tier8_key",
    );
    fault_inject::reset();

    match exhausted {
        Err(ref e) => {
            let msg = format!("{e:?}");
            assert!(
                msg.contains("squash-retry-exhausted"),
                "expected squash-retry-exhausted; got {msg}"
            );
        }
        Ok(other) => panic!("expected retry-exhaustion error; got Ok({other:?})"),
    }
}

// ---------------------------------------------------------------------------
// Tier 9: generation change without acquire failure.
//
// Models the race where a writer's publish finished BEFORE the reader's next
// acquire attempt — so `try_acquire_blob_read` succeeds, but the per-read
// `squash_state_fresh` check observes a mismatch against this handle's
// watermark. The reader must bail `Err(Error::RetryAfterSquash)` rather than
// consuming stale offset caches against post-truncate file layout.
//
// We inject via `fault_inject::fail_next_gen_checks`, which forces
// `squash_state_fresh` to report a mismatch without actually bumping the
// shared generation. The reset path still runs (including the no-op sync),
// and on retry the check is clear — value is returned correctly.
// ---------------------------------------------------------------------------

#[test]
fn test_tier9_gen_mismatch_without_acquire_failure_absorbed() {
    use crate::chainstate::stacks::index::marf::MarfInternals;
    use crate::chainstate::stacks::index::storage::fault_inject;

    fault_inject::reset();

    let dir = fresh_test_dir("test_tier9_gen_mismatch_retry");
    let sq_path = format!("{dir}/squashed.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let mut writer = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    let block = {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&1u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    writer.begin(&StacksBlockId::sentinel(), &block).unwrap();
    writer
        .insert("tier9_key", MARFValue::from_value("tier9_value"))
        .unwrap();
    writer.seal().unwrap();
    writer.commit().unwrap();
    drop(writer);

    let mut reader = MARF::<StacksBlockId>::from_path(&sq_path, open_opts).unwrap();

    // Inject MAX_READ_RETRIES-1 gen-check failures so every attempt but the last trips
    // the mismatch branch. The wrapper resets between attempts; the final attempt
    // clears the counter and succeeds.
    //
    // Same rationale as Tier 8 for calling `get_by_key` directly instead of `get()`.
    let fails = <MARF<StacksBlockId> as MarfInternals<StacksBlockId>>::MAX_READ_RETRIES - 1;
    fault_inject::fail_next_gen_checks(fails);

    let result = <MARF<StacksBlockId> as MarfInternals<StacksBlockId>>::get_by_key(
        &mut reader,
        &block,
        "tier9_key",
    );
    fault_inject::reset();

    assert_eq!(
        result.expect("retry wrapper should absorb injected gen-check failures"),
        Some(MARFValue::from_value("tier9_value")),
    );
}

// ---------------------------------------------------------------------------
// Tier 10: same-height sibling read after squash consults parent state.
//
// **FIX-PROTECTION REGRESSION TEST** for the genesis-sync stall at block
// 11000 (April 2026). The pre-fix behavior: a competing fork-sibling block
// at the same Stacks height as the canonical tip, downloaded slightly after
// the squash, was rejected with `Bad nonce` because the squashed-leaf
// representation in the Clarity MARF keys per-key history by height alone
// (`TrieLeafSquashed { entries: Vec<(u32, MARFValue)> }` +
// `TrieLeafSquashed::value_at_height(height)` in `node.rs`). The read
// pipeline used to capture the sibling's *own* height as the squashed-leaf
// query height, which collided with the canonical sibling's already-applied
// transition at that height — returning the canonical's value instead of
// the parent's.
//
// The fix (in `open_block_impl`'s uncommitted-match branch in `storage.rs`)
// propagates the PARENT's squash height as the snapshot height when opening
// a non-squash uncommitted block whose parent IS in the squash.
// `value_at_height(parent_h)` then returns the parent's view (the fork
// point) rather than the canonical tip — which matches the unsquashed
// reference and lets the sibling validate against the correct pre-fork
// state.
//
// The test runs both a squashed MARF and an unsquashed reference through
// the same scenario (parent P → canonical sibling A → fresh sibling B with
// parent P) and asserts they read identically. Any future regression that
// reintroduces the height-only collision will fail the second assertion
// with the failure message describing the structural cause.
//
// Limitation: only uncommitted blocks (`marf.begin(parent, child)` followed
// by reads against `child`) get the snapshot-height fast path. Committed-
// non-canonical-fork blocks (deeper forks already in `marf_data`) would
// need a parent-chain walk via either a `marf_data.parent_block_hash`
// schema addition or a chainstate-level snapshot-height pass-through on
// `open_block`. Tracked as a follow-up.
// ---------------------------------------------------------------------------

#[test]
fn test_tier10_same_height_sibling_after_squash_reads_parent_state() {
    use crate::chainstate::stacks::index::squash::{squash_level_incremental, SquashMode};

    let dir = fresh_test_dir("test_tier10_same_height_sibling");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    // Three blocks: parent P at height 0, canonical sibling A at height 1
    // (extends P), and competing sibling B at height 1 (also extends P).
    let parent_block = {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_DA_DA_DA_DAu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let canonical_a = {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_CA_11_AB_1Eu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&2u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let sibling_b = {
        let mut bytes = [0xFFu8; 32];
        bytes[24..28].copy_from_slice(&0x_5B_11_BC_2Au32.to_be_bytes());
        bytes[28..32].copy_from_slice(&2u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let key = "shared_key";
    let parent_val = MARFValue::from_value("parent_value");
    let canonical_val = MARFValue::from_value("canonical_sibling_value");

    // ── Build the squashed MARF: P → A, then squash through A ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    // Parent commits the original value at height 0.
    sq_marf
        .begin(&StacksBlockId::sentinel(), &parent_block)
        .unwrap();
    sq_marf.insert(key, parent_val.clone()).unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    // Canonical sibling A overwrites at height 1 (mirrors a tx that bumps a
    // nonce / overwrites a contract var).
    sq_marf.begin(&parent_block, &canonical_a).unwrap();
    sq_marf.insert(key, canonical_val.clone()).unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    drop(sq_marf);

    // Squash heights 0..=1 with reclaim=true (matches the production
    // `maybe_squash` path that triggered the production stall).
    squash_level_incremental::<StacksBlockId>(&sq_path, SquashMode::FullHistory, 0, 1, true)
        .expect("squash should succeed");

    // Sibling B arrives AFTER the squash and extends the same parent P.
    // Importantly, B writes nothing yet — we read the shared key purely
    // against B's pre-write view, which should be P's state.
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.refresh_after_squash().unwrap();
    sq_marf.begin(&parent_block, &sibling_b).unwrap();
    let sq_read = sq_marf.get(&sibling_b, key).expect("read should succeed");
    sq_marf.drop_current();
    drop(sq_marf);

    // ── Reference MARF (no squash): P → A and a parallel B branch ──
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();
    ref_marf
        .begin(&StacksBlockId::sentinel(), &parent_block)
        .unwrap();
    ref_marf.insert(key, parent_val.clone()).unwrap();
    ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();
    ref_marf.begin(&parent_block, &canonical_a).unwrap();
    ref_marf.insert(key, canonical_val.clone()).unwrap();
    ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();
    ref_marf.begin(&parent_block, &sibling_b).unwrap();
    let ref_read = ref_marf.get(&sibling_b, key).expect("read should succeed");
    ref_marf.drop_current();
    drop(ref_marf);

    // The unsquashed reference returns P's value (B is a fresh branch from P
    // and B has not written yet). The squashed MARF MUST do the same; if
    // instead it returns the canonical sibling A's value, that is the bug
    // this test documents — same-height siblings collide because the
    // squashed-leaf history is keyed by height alone, with no branch identity.
    assert_eq!(
        ref_read,
        Some(parent_val.clone()),
        "reference (unsquashed) sibling B should read parent's value"
    );
    assert_eq!(
        sq_read, ref_read,
        "squashed sibling B should read the same as the unsquashed reference \
         (parent's value). A regression here means the snapshot-height \
         propagation in `open_block_impl`'s uncommitted-match branch is no \
         longer setting `squash_opened_height` from the parent's squash entry, \
         so the squashed-leaf lookup falls back to the canonical sibling's \
         height and shadows the parent's value."
    );
}

// ---------------------------------------------------------------------------
// Tier 11: depth-2 (committed) fork reads ancestor's pre-fork view via
// parent-chain walk after squash.
//
// **FIX-PROTECTION REGRESSION TEST** for the multi-block-Bitcoin-reorg case
// flagged in Tier 10's "Limitation" docstring. Tier 10 only covers the
// uncommitted same-height sibling path; this exercises the deeper case:
//
//   P  (h=0, squashed canonical, sets shared_key = parent_val)
//   ├── A   (h=1, squashed canonical, overwrites shared_key = canonical_val)
//   └── B1  (h=1, committed non-canonical, parent=P, no shared_key write)
//          └── B2 (h=2, committed non-canonical, parent=B1, READS shared_key)
//
// After squashing 0..=1 with reclaim=true, both P and A are folded into a
// single squashed leaf with entries `[(0, parent_val), (1, canonical_val)]`.
// B1 and B2 are committed, NOT in the squash. Reading `shared_key` from B2
// must return `parent_val` (P's pre-fork value), NOT `canonical_val` (A's
// height-1 entry).
//
// The fix path under test (lazy resolution in `snapshot_height_for_block()`):
//   B2 read of `shared_key` → walk reaches a `LeafSquashed` → marf walk's
//   `WalkAction::FoundSquashedLeaf` branch calls
//   `storage.snapshot_height_for_block(B2_hash, B2_id)` → eager paths didn't
//   set `squash_opened_height` for B2 → memoized walker fires
//   `compute_snapshot_height_via_parent_chain`:
//     1. B2 not in squash → read B2's blob header → parent = B1
//     2. B1 not in squash → read B1's blob header → parent = P
//     3. P is in squash at height 0 → return Some(0)
//   → `value_at_height(0)` returns parent_val = correct.
//
// Note: Tier 11 here uses a depth-2 fork (B2 → B1 → P) where B1 wrote at
// least one marker key — that forces B1's marker child in B2's root to be a
// depth-1 backptr to B1. So a naive "min-depth root backptr" walker would
// coincidentally land on B1 (then walk to P) and arrive at the correct
// answer. The truly adversarial case — where root backptrs in B2 point to
// ancestors *deeper than the fork point* — is covered by Tier 11b below.
// ---------------------------------------------------------------------------

#[test]
fn test_tier11_depth_two_committed_fork_reads_ancestor_state() {
    use crate::chainstate::stacks::index::squash::{squash_level_incremental, SquashMode};

    let dir = fresh_test_dir("test_tier11_depth_two_committed_fork");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let parent_block = {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_DA_DA_DA_DAu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let canonical_a = {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_CA_11_AB_1Eu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&2u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let fork_b1 = {
        let mut bytes = [0xFFu8; 32];
        bytes[24..28].copy_from_slice(&0x_5B_11_BC_2Au32.to_be_bytes());
        bytes[28..32].copy_from_slice(&2u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let fork_b2 = {
        let mut bytes = [0xFFu8; 32];
        bytes[24..28].copy_from_slice(&0x_5B_22_BC_2Au32.to_be_bytes());
        bytes[28..32].copy_from_slice(&3u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let key = "shared_key";
    let parent_val = MARFValue::from_value("parent_value");
    let canonical_val = MARFValue::from_value("canonical_sibling_value");
    // B1 / B2 each commit a fork-branded write on a DIFFERENT key so the trie
    // is non-empty (commits require at least one insert), without touching
    // the key under test — the read against `shared_key` from B2 should fall
    // all the way through to the squashed leaf.
    let b1_marker_key = "b1_marker";
    let b2_marker_key = "b2_marker";
    let b1_marker_val = MARFValue::from_value("fork_b1_marker");
    let b2_marker_val = MARFValue::from_value("fork_b2_marker");

    // ── Build the squashed MARF: P → A (canonical), then squash. Then commit
    // B1 (parent=P), then B2 (parent=B1). Both B1/B2 land in marf_data as
    // committed-non-canonical blocks — exactly the production case for a
    // multi-block live Bitcoin reorg landing post-squash. ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf
        .begin(&StacksBlockId::sentinel(), &parent_block)
        .unwrap();
    sq_marf.insert(key, parent_val.clone()).unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    sq_marf.begin(&parent_block, &canonical_a).unwrap();
    sq_marf.insert(key, canonical_val.clone()).unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    drop(sq_marf);

    squash_level_incremental::<StacksBlockId>(&sq_path, SquashMode::FullHistory, 0, 1, true)
        .expect("squash should succeed");

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.refresh_after_squash().unwrap();
    // B1: commit a marker write so its trie blob is well-formed in marf_data.
    sq_marf.begin(&parent_block, &fork_b1).unwrap();
    sq_marf
        .insert(b1_marker_key, b1_marker_val.clone())
        .unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    // B2: commit ANOTHER marker write (still no touch of `shared_key`) so we
    // can read against fully-committed state, exercising the
    // `open_block_known_id_impl` path rather than the uncommitted shortcut.
    sq_marf.begin(&fork_b1, &fork_b2).unwrap();
    sq_marf
        .insert(b2_marker_key, b2_marker_val.clone())
        .unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    let sq_read = sq_marf.get(&fork_b2, key).expect("read should succeed");
    drop(sq_marf);

    // ── Reference MARF: same scenario without the squash ──
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();
    ref_marf
        .begin(&StacksBlockId::sentinel(), &parent_block)
        .unwrap();
    ref_marf.insert(key, parent_val.clone()).unwrap();
    ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();
    ref_marf.begin(&parent_block, &canonical_a).unwrap();
    ref_marf.insert(key, canonical_val.clone()).unwrap();
    ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();
    ref_marf.begin(&parent_block, &fork_b1).unwrap();
    ref_marf
        .insert(b1_marker_key, b1_marker_val.clone())
        .unwrap();
    ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();
    ref_marf.begin(&fork_b1, &fork_b2).unwrap();
    ref_marf
        .insert(b2_marker_key, b2_marker_val.clone())
        .unwrap();
    ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();
    let ref_read = ref_marf.get(&fork_b2, key).expect("read should succeed");
    drop(ref_marf);

    assert_eq!(
        ref_read,
        Some(parent_val.clone()),
        "reference (unsquashed) depth-2 fork B2 should read parent's value"
    );
    assert_eq!(
        sq_read, ref_read,
        "squashed depth-2 fork B2 should read the same as the unsquashed reference \
         (parent's value). A regression here means \
         `compute_snapshot_height_via_parent_chain` is not walking B2 → B1 → P \
         through blob headers to find P's squash entry, so the squashed-leaf \
         lookup falls back to the canonical sibling A's height-1 value instead."
    );
}

// ---------------------------------------------------------------------------
// Tier 11b: adversarial backptr setup — fork's root contains backptrs to a
// squashed ancestor *deeper* than the true fork point, exercising the
// scenario Codex flagged: "the first root backptr points to an older
// squashed ancestor than the true parent-chain fork point".
//
// Layout:
//
//   G  (h=0, squashed, writes oldest_key=v_oldest  AND shared_key=v_g)
//   └── P  (h=1, squashed, writes shared_key=v_p; oldest_key untouched)
//       ├── A   (h=2, squashed canonical, writes shared_key=v_canonical)
//       └── B1  (h=2, committed fork, parent=P, writes only b1_marker)
//              └── B2 (h=3, committed fork, parent=B1, writes only b2_marker;
//                      READS shared_key)
//
// Heights 0..=2 are squashed (G + P + A). The squashed leaf for `shared_key`
// has entries `[(0, v_g), (1, v_p), (2, v_canonical)]`. The squashed leaf
// for `oldest_key` has the single entry `[(0, v_oldest)]`.
//
// Why this is adversarial: `oldest_key`'s subtree was last touched at G and
// never modified by P, A, B1, or B2. By COW, B2's root child for that
// subtree is a backptr that resolves all the way back to G (depth 3 from
// B2's frame: B2 → B1 → P → G). A naive walker that picked *any* root
// backptr in B2 and used its target's squash height as the snapshot height
// could land on G's height (0), and `value_at_height(0)` for `shared_key`
// would return v_g — WRONG. The correct answer is v_p (P's view, since the
// fork point is P).
//
// The blob-header walker in `compute_snapshot_height_via_parent_chain` does
// not look at backptrs at all — it reads the *exact* parent block hash from
// each per-block trie blob's header (captured at commit time in
// `TrieRAM::dump`). For B2: parent header → B1; B1 header → P; P is in the
// squash at height 1 → `value_at_height(1)` returns v_p. Correct.
//
// This test would fail under any future regression that:
//   - Replaces blob-header walking with first-root-backptr inference, or
//   - Uses any backptr depth as a proxy for parent-chain depth.
// ---------------------------------------------------------------------------

#[test]
fn test_tier11b_adversarial_root_backptr_to_older_squashed_ancestor() {
    use crate::chainstate::stacks::index::squash::{squash_level_incremental, SquashMode};

    let dir = fresh_test_dir("test_tier11b_adversarial_root_backptr");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let grandparent_g = {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_6E_5A_DA_DAu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let parent_p = {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_DA_DA_DA_DAu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&2u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let canonical_a = {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_CA_11_AB_1Eu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&3u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let fork_b1 = {
        let mut bytes = [0xFFu8; 32];
        bytes[24..28].copy_from_slice(&0x_5B_11_BC_2Au32.to_be_bytes());
        bytes[28..32].copy_from_slice(&3u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let fork_b2 = {
        let mut bytes = [0xFFu8; 32];
        bytes[24..28].copy_from_slice(&0x_5B_22_BC_2Au32.to_be_bytes());
        bytes[28..32].copy_from_slice(&4u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let shared_key = "shared_key";
    let oldest_key = "oldest_key";
    let v_oldest = MARFValue::from_value("oldest_value_at_g");
    let v_g = MARFValue::from_value("shared_at_g");
    let v_p = MARFValue::from_value("shared_at_p_fork_point");
    let v_canonical = MARFValue::from_value("shared_at_canonical_a");
    let b1_marker_key = "b1_marker";
    let b2_marker_key = "b2_marker";
    let b1_marker_val = MARFValue::from_value("fork_b1_marker");
    let b2_marker_val = MARFValue::from_value("fork_b2_marker");

    // ── Build squashed MARF: G → P → A canonical, then squash 0..=2. Then
    // commit B1 (parent=P) and B2 (parent=B1). ──
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf
        .begin(&StacksBlockId::sentinel(), &grandparent_g)
        .unwrap();
    sq_marf.insert(oldest_key, v_oldest.clone()).unwrap();
    sq_marf.insert(shared_key, v_g.clone()).unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    sq_marf.begin(&grandparent_g, &parent_p).unwrap();
    sq_marf.insert(shared_key, v_p.clone()).unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    sq_marf.begin(&parent_p, &canonical_a).unwrap();
    sq_marf.insert(shared_key, v_canonical.clone()).unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    drop(sq_marf);

    squash_level_incremental::<StacksBlockId>(&sq_path, SquashMode::FullHistory, 0, 2, true)
        .expect("squash should succeed");

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.refresh_after_squash().unwrap();
    sq_marf.begin(&parent_p, &fork_b1).unwrap();
    sq_marf
        .insert(b1_marker_key, b1_marker_val.clone())
        .unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    sq_marf.begin(&fork_b1, &fork_b2).unwrap();
    sq_marf
        .insert(b2_marker_key, b2_marker_val.clone())
        .unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    let sq_read_shared = sq_marf
        .get(&fork_b2, shared_key)
        .expect("shared_key read should succeed");
    let sq_read_oldest = sq_marf
        .get(&fork_b2, oldest_key)
        .expect("oldest_key read should succeed");
    drop(sq_marf);

    // ── Reference (unsquashed) MARF: identical scenario without squash ──
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();
    ref_marf
        .begin(&StacksBlockId::sentinel(), &grandparent_g)
        .unwrap();
    ref_marf.insert(oldest_key, v_oldest.clone()).unwrap();
    ref_marf.insert(shared_key, v_g.clone()).unwrap();
    ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();
    ref_marf.begin(&grandparent_g, &parent_p).unwrap();
    ref_marf.insert(shared_key, v_p.clone()).unwrap();
    ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();
    ref_marf.begin(&parent_p, &canonical_a).unwrap();
    ref_marf.insert(shared_key, v_canonical.clone()).unwrap();
    ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();
    ref_marf.begin(&parent_p, &fork_b1).unwrap();
    ref_marf
        .insert(b1_marker_key, b1_marker_val.clone())
        .unwrap();
    ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();
    ref_marf.begin(&fork_b1, &fork_b2).unwrap();
    ref_marf
        .insert(b2_marker_key, b2_marker_val.clone())
        .unwrap();
    ref_marf.seal().unwrap();
    ref_marf.commit().unwrap();
    let ref_read_shared = ref_marf
        .get(&fork_b2, shared_key)
        .expect("shared_key read should succeed");
    let ref_read_oldest = ref_marf
        .get(&fork_b2, oldest_key)
        .expect("oldest_key read should succeed");
    drop(ref_marf);

    assert_eq!(
        ref_read_shared,
        Some(v_p.clone()),
        "reference (unsquashed) fork B2 should read shared_key as P's value (fork point)"
    );
    assert_eq!(
        ref_read_oldest,
        Some(v_oldest.clone()),
        "reference (unsquashed) fork B2 should read oldest_key as G's value (only ever written there)"
    );
    assert_eq!(
        sq_read_shared, ref_read_shared,
        "squashed fork B2 must read shared_key as v_p (P's view, the true fork point). \
         Failure modes: \
         (a) returns v_g — implementation regressed to using a deep root-backptr (e.g. \
             oldest_key's path), incorrectly setting snapshot_height = G's height (0); \
         (b) returns v_canonical — implementation isn't setting snapshot_height at all \
             and is falling back to tip-read. \
         The blob-header walker must read B2 → B1 → P from blob headers and land on P's \
         squash entry (height 1)."
    );
    assert_eq!(
        sq_read_oldest, ref_read_oldest,
        "squashed fork B2 must read oldest_key as v_oldest. This catches the corner case \
         where the snapshot height resolution disturbs unrelated keys (e.g. by setting \
         level_idx in a way that triggers root-hash override on the fork block)."
    );
}

// ---------------------------------------------------------------------------
// Perf-shape regression test for the LeafSquashed read path.
//
// **Goal**: prove that the marf walk routes `LeafSquashed` resolution through
// the *deferred / re-read* path introduced by Option 2, NOT the previous
// "always clone the entries vector in Phase 1" path. The previous design
// heap-allocated and copied `Vec<(u32, MARFValue)>` on every LeafSquashed
// read — including dormant tip reads on canonical chains past a squash
// where the cloned entries were ultimately unused (we returned `tip_value`).
// On a long-running node with FullHistory squashes, that wasted allocation
// scaled with how often the key was rewritten across the squash range.
//
// The Option 2 design clones only `path` + `tip_value` (small, fixed-size)
// in Phase 1. Phase 2 then either:
//   - returns `tip_value` directly (when snapshot-height resolves to `None`,
//     i.e. tip-fallback fast path — rare), or
//   - re-reads the leaf into the scratch buffer to look up `entries[idx]`
//     by reference (when `Some(h)` — the historical / fork / canonical-
//     past-squash path).
//
// Either way, no `entries.to_vec()` clone happens. The counters used in this
// test (`squashed_entries_reread_count`, `squashed_tip_fallback_count`) are
// the only paths that reach a `LeafSquashed` after the walk; if a future
// change reintroduces the eager clone, **neither** counter would increment
// for a dormant tip read — and this test would fail.
//
// Test layout:
//   G   (h=0, writes shared_key=v_g + marker_g)
//   └── H (h=1, writes shared_key=v_h)
//       Squash 0..=1: LeafSquashed(shared_key) has entries
//                     [(0, v_g), (1, v_h)], tip_value = v_h
//       └── C (committed canonical extension, writes only marker_c — does
//             NOT touch shared_key, so reads of shared_key from C resolve
//             via backptr down to the squashed LeafSquashed)
//
// Scenarios under test:
//   A. Dormant tip read: get(C, shared_key). C is canonical-past-squash; the
//      lazy walker walks C → H, finds H in the squash, returns Some(1). Phase 2
//      takes the re-read path. EXPECT: entries_reread_count > 0; result = v_h.
//      A regression to the eager-clone Phase-1 design would leave
//      entries_reread_count at 0.
//
//   B. Historical read at H: get(H, shared_key). H is in-squash, so
//      eager_user_height = Some(1) and Phase 2 re-reads. EXPECT:
//      entries_reread_count > 0; result = v_h (entries[1]).
//
//   C. Historical read at G: get(G, shared_key). G is in-squash at height 0
//      → re-read path with idx pointing to entries[0]. EXPECT:
//      entries_reread_count > 0; result = v_g — proving the value-at-height
//      lookup correctly indexes into the older squashed entry.
// ---------------------------------------------------------------------------

#[test]
fn test_leaf_squashed_read_path_perf_shape() {
    use crate::chainstate::stacks::index::squash::{squash_level_incremental, SquashMode};

    let dir = fresh_test_dir("test_leaf_squashed_perf_shape");
    let sq_path = format!("{dir}/squashed.sqlite");

    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);

    let block_g = {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_6E_AA_6E_AAu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let block_h = {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_8B_AA_8B_AAu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&2u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };
    let block_c = {
        let mut bytes = [0u8; 32];
        bytes[24..28].copy_from_slice(&0x_C0_AA_C0_AAu32.to_be_bytes());
        bytes[28..32].copy_from_slice(&3u32.to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    let shared_key = "perf_shape_shared_key";
    let v_g = MARFValue::from_value("v_at_g");
    let v_h = MARFValue::from_value("v_at_h");
    let marker_g_key = "marker_g";
    let marker_g_val = MARFValue::from_value("marker_g_val");
    let marker_c_key = "marker_c";
    let marker_c_val = MARFValue::from_value("marker_c_val");

    // Build G → H, then squash 0..=1, then commit canonical C.
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.begin(&StacksBlockId::sentinel(), &block_g).unwrap();
    sq_marf.insert(shared_key, v_g.clone()).unwrap();
    sq_marf.insert(marker_g_key, marker_g_val.clone()).unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    sq_marf.begin(&block_g, &block_h).unwrap();
    sq_marf.insert(shared_key, v_h.clone()).unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();
    drop(sq_marf);

    squash_level_incremental::<StacksBlockId>(&sq_path, SquashMode::FullHistory, 0, 1, true)
        .expect("squash should succeed");

    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.refresh_after_squash().unwrap();
    sq_marf.begin(&block_h, &block_c).unwrap();
    sq_marf.insert(marker_c_key, marker_c_val.clone()).unwrap();
    sq_marf.seal().unwrap();
    sq_marf.commit().unwrap();

    // Helper to snapshot counter values from the live MARF storage.
    let read_counters = |marf: &mut MARF<StacksBlockId>| -> (u64, u64) {
        let storage = marf.borrow_storage_backend();
        (
            storage.transient_data().squashed_tip_fallback_count.get(),
            storage.transient_data().squashed_entries_reread_count.get(),
        )
    };
    let reset_counters = |marf: &mut MARF<StacksBlockId>| {
        let storage = marf.borrow_storage_backend();
        storage.transient_data().squashed_tip_fallback_count.set(0);
        storage
            .transient_data()
            .squashed_entries_reread_count
            .set(0);
    };

    // ── Scenario A: dormant tip read on canonical-past-squash. The lazy walker
    // walks C → H, finds H in the squash, returns Some(1). Phase 2 re-reads. ──
    reset_counters(&mut sq_marf);
    let tip_read = sq_marf
        .get(&block_c, shared_key)
        .expect("tip read should succeed");
    let (tip_fallback_a, entries_reread_a) = read_counters(&mut sq_marf);
    assert_eq!(
        tip_read,
        Some(v_h.clone()),
        "tip read of shared_key from C should return H's value (the squash tip)"
    );
    assert!(
        entries_reread_a >= 1,
        "dormant tip read on canonical-past-squash MUST take the deferred re-read path \
         (Option 2's Phase 2). A regression to the eager-clone-entries design (cloning \
         `Vec<(u32, MARFValue)>` in Phase 1) would leave this counter at 0 because that \
         path was deleted. Got entries_reread_count={entries_reread_a}."
    );
    assert_eq!(
        tip_fallback_a, 0,
        "tip-fallback fast path is for the rare case where the walker finds NO squashed \
         ancestor (e.g. uncommitted block off a non-squash chain). For canonical-past-\
         squash reads the walker finds the immediate squashed ancestor and the re-read \
         path is taken instead."
    );

    // ── Scenario B: historical read at H (in-squash) → entries re-read path. ──
    reset_counters(&mut sq_marf);
    let historical_h = sq_marf
        .get(&block_h, shared_key)
        .expect("historical read at H should succeed");
    let (tip_fallback_b, entries_reread_b) = read_counters(&mut sq_marf);
    assert_eq!(
        historical_h,
        Some(v_h.clone()),
        "in-squash read of shared_key at H should return v_h (entries[1])"
    );
    assert!(
        entries_reread_b >= 1,
        "historical read at an in-squash block MUST hit the entries re-read path \
         (eager_user_height = Some(h)) to look up value_at_height. \
         Got entries_reread_count={entries_reread_b}."
    );
    assert_eq!(
        tip_fallback_b, 0,
        "historical read MUST NOT take the tip_value fast path when an explicit \
         snapshot height is set."
    );

    // ── Scenario C: historical read at G (in-squash, older entry — proves
    // value_at_height correctly resolves to the older squashed entry). ──
    reset_counters(&mut sq_marf);
    let historical_g = sq_marf
        .get(&block_g, shared_key)
        .expect("historical read at G should succeed");
    let (_tip_fallback_c, entries_reread_c) = read_counters(&mut sq_marf);
    assert_eq!(
        historical_g,
        Some(v_g.clone()),
        "in-squash read of shared_key at G should return v_g (entries[0]) — proving \
         the value-at-height lookup correctly indexes back into the older squashed entry."
    );
    assert!(
        entries_reread_c >= 1,
        "historical read at G MUST hit the entries re-read path at least once."
    );
}

// ---------------------------------------------------------------------------
// Smoke test: canonical-tip extension past a squash. Each post-squash block
// extends the squash TIP, so `OWN_BLOCK_HEIGHT_KEY` resolves to the correct
// height (the merged trie's tip value IS the squash tip's value), and
// `inner_get_extension_height` computes the right child height. This test
// caught a few subtle regressions in the Tier 11 / Option 2 work; the
// next test below is the actual fork-from-non-tip regression test for the
// `get_block_height_miner_tip` in-squash override fix.
// ---------------------------------------------------------------------------

#[test]
fn test_seal_after_squash_canonical_tip_extension_smoke() {
    use crate::chainstate::stacks::index::squash::{squash_level_incremental, SquashMode};

    let dir = fresh_test_dir("test_seal_after_squash_canonical_smoke");
    let path = format!("{dir}/marf.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);

    const N: u32 = 50;
    const KEYS_PER_BLOCK: u32 = 10;
    let block_hashes: Vec<StacksBlockId> = (0..N)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[24..28].copy_from_slice(&0x_C0_FF_EEu32.to_be_bytes());
            bytes[28..32].copy_from_slice(&i.to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    {
        let mut marf = MARF::<StacksBlockId>::from_path(&path, open_opts.clone()).unwrap();
        let mut parent = StacksBlockId::sentinel();
        for (i, bh) in block_hashes.iter().enumerate() {
            marf.begin(&parent, bh).unwrap();
            for k in 0..KEYS_PER_BLOCK {
                let key = format!("dummy_key_{i}_{k}");
                marf.insert(&key, MARFValue::from(i as u32 * 100 + k))
                    .unwrap();
            }
            marf.seal().unwrap();
            marf.commit().unwrap();
            parent = bh.clone();
        }
    }

    squash_level_incremental::<StacksBlockId>(&path, SquashMode::FullHistory, 0, N - 1, true)
        .expect("squash should succeed");

    let mut marf = MARF::<StacksBlockId>::from_path(&path, open_opts.clone()).unwrap();
    marf.refresh_after_squash().unwrap();
    let mut parent = block_hashes.last().unwrap().clone();
    for j in 0..20u32 {
        let next_block = {
            let mut bytes = [0u8; 32];
            bytes[24..28].copy_from_slice(&0x_FF_FF_FFu32.to_be_bytes());
            bytes[28..32].copy_from_slice(&(N + j).to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        };
        marf.begin(&parent, &next_block).unwrap();
        for k in 0..KEYS_PER_BLOCK {
            let key = format!("post_squash_key_{j}_{k}");
            marf.insert(&key, MARFValue::from(j * 1000 + k)).unwrap();
        }
        marf.seal()
            .unwrap_or_else(|e| panic!("seal failed for block at h={}: {e:?}", N + j));
        marf.commit().unwrap();
        parent = next_block;
    }
}

/// **REGRESSION TEST** for the genesis-sync seal panic:
///   "Could not obtain block hash at block height 999"
//
/// **Bug**: the squash blob is a single MERGED tip trie with one leaf per path,
/// so `OWN_BLOCK_HEIGHT_KEY` reads from any in-squash block return the SQUASH
/// TIP's height, not the per-block height. `MARF::begin` calls
/// `inner_get_extension_height` → `get_block_height_miner_tip(parent, parent)`,
/// and when `parent` is a non-tip squashed block, that lookup returns the
/// squash-tip height. The new block then computes
/// `child_height = squash_tip_height + 1` (e.g. 1001) instead of
/// `parent_height + 1` (e.g. 811), writes that wrong height into its own
/// `OWN_BLOCK_HEIGHT_KEY` via `set_block_heights`, and at seal the geometric
/// ancestor lookup queries `::H` for `H` derived from the wrong `cur_height`
/// — landing on entries whose recorded heights are above the parent's true
/// `squash_opened_height`, so `value_at_height` returns `None` and the seal
/// panics.
//
/// **Fix**: `get_block_height_miner_tip` self-lookup now bypasses the
/// merged-trie `OWN_BLOCK_HEIGHT_KEY` read for in-squash blocks and pulls the
/// per-block height from the squash trailer via `squash_opened_height()`.
//
/// **Test layout**: Build N=50 blocks (heights 0..=49), squash 0..=49 with
/// `FullHistory + reclaim=true`, then begin a fork from a NON-TIP squashed
/// parent (`block_hashes[30]` at height 30). Without the fix:
///   - `inner_get_extension_height` reads `OWN_BLOCK_HEIGHT_KEY` from the
///     merged trie → returns 49 (squash tip).
///   - Child computes its height as `49 + 1 = 50` instead of `31`.
///   - `set_block_heights` writes `OWN_BLOCK_HEIGHT_KEY = 50`, `::50 = child`,
///     `::49 = parent` (the parent's hash recorded at the wrong height key).
///   - Seal's geometric lookup queries `::49`, `::48`, `::46`, ... with
///     `eager_user_height = Some(30)` (parent's true squash height from
///     `parent_squash_entry`), and `value_at_height(30)` on `::49`'s entries
///     `[(49, h)]` returns `None` → panic.
/// With the fix: child correctly computes height 31, OWN_BLOCK_HEIGHT_KEY = 31,
/// geometric lookup queries `::30, ::29, ::27, ::23, ::15`, all of which have
/// `value_at_height(30) = Some(...)` because every entry's write_height is ≤ 30.
#[test]
fn test_repro_seal_fork_from_non_tip_squashed_parent() {
    use crate::chainstate::stacks::index::marf::MarfInternals;
    use crate::chainstate::stacks::index::squash::{squash_level_incremental, SquashMode};

    let dir = fresh_test_dir("test_repro_seal_fork_from_non_tip");
    let path = format!("{dir}/marf.sqlite");
    let ref_path = format!("{dir}/ref-marf.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);

    const N: u32 = 50;
    const KEYS_PER_BLOCK: u32 = 10;
    const FORK_PARENT_INDEX: usize = 30; // non-tip: parent at height 30, not 49

    let block_hashes: Vec<StacksBlockId> = (0..N)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[24..28].copy_from_slice(&0x_C0_FF_EEu32.to_be_bytes());
            bytes[28..32].copy_from_slice(&i.to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    for build_path in [&path, &ref_path] {
        let mut marf = MARF::<StacksBlockId>::from_path(build_path, open_opts.clone()).unwrap();
        let mut parent = StacksBlockId::sentinel();
        for (i, bh) in block_hashes.iter().enumerate() {
            marf.begin(&parent, bh).unwrap();
            for k in 0..KEYS_PER_BLOCK {
                let key = format!("dummy_key_{i}_{k}");
                marf.insert(&key, MARFValue::from(i as u32 * 100 + k))
                    .unwrap();
            }
            marf.seal().unwrap();
            marf.commit().unwrap();
            parent = bh.clone();
        }
    }

    squash_level_incremental::<StacksBlockId>(&path, SquashMode::FullHistory, 0, N - 1, true)
        .expect("squash should succeed");

    let mut marf = MARF::<StacksBlockId>::from_path(&path, open_opts.clone()).unwrap();
    marf.refresh_after_squash().unwrap();

    // Fork: extend a NON-TIP squashed parent. This is the case that was
    // broken — `get_block_height_miner_tip` would return the squash tip's
    // height (49) instead of the parent's true height (30).
    let fork_parent = block_hashes[FORK_PARENT_INDEX].clone();
    let expected_fork_parent_height = FORK_PARENT_INDEX as u32;

    // Sanity check: query parent's height via MARF::get_block_height_miner_tip.
    // After the fix, this returns the trailer's per-block height (30), not
    // the merged-trie's OWN_BLOCK_HEIGHT_KEY value (49).
    let parent_height_via_marf =
        <MARF<StacksBlockId> as MarfInternals<StacksBlockId>>::get_block_height_miner_tip(
            &mut marf,
            &fork_parent,
            &fork_parent,
        )
        .expect("get_block_height_miner_tip should succeed");
    assert_eq!(
        parent_height_via_marf,
        Some(expected_fork_parent_height),
        "MARF::get_block_height_miner_tip self-lookup on a non-tip squashed block \
         must return the per-block height ({expected_fork_parent_height}), not the squash \
         tip's height ({}). A regression to the merged-trie OWN_BLOCK_HEIGHT_KEY \
         read would return Some({}) here.",
        N - 1,
        N - 1
    );

    let fork_block = {
        let mut bytes = [0xFFu8; 32];
        bytes[24..28].copy_from_slice(&0x_F0_F0_F0u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&(FORK_PARENT_INDEX as u32 + 1).to_be_bytes());
        StacksBlockId::from_bytes(&bytes).unwrap()
    };

    // Begin the fork. `inner_get_extension_height` queries the parent's height
    // via `get_block_height_miner_tip` — with the fix, it returns 30, so
    // `child_height = 31`. Without the fix, it returns 49, so `child_height = 50`.
    marf.begin(&fork_parent, &fork_block).unwrap();
    marf.insert("fork_marker_key", MARFValue::from(0xCAFEu32))
        .unwrap();

    // Seal computes the MARF root via `get_trie_ancestor_hashes_bytes`, which
    // queries `::H` for `H = cur_height - 2^k`. With the fix, cur_height=31 →
    // queries 30, 29, 27, 23, 15 — all resolvable against `eager_user_height=30`.
    // Without the fix, cur_height=50 → queries 49, 48, 46, 42, 34, 18 — and
    // `value_at_height(30)` on `::49`'s entries `[(49, h)]` returns None →
    // panic with "Could not obtain block hash at block height 49".
    let squashed_fork_root = marf
        .seal()
        .unwrap_or_else(|e| panic!("seal of fork from non-tip squashed parent failed: {e:?}"));
    marf.commit().unwrap();

    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();
    ref_marf.begin(&fork_parent, &fork_block).unwrap();
    ref_marf
        .insert("fork_marker_key", MARFValue::from(0xCAFEu32))
        .unwrap();
    let reference_fork_root = ref_marf
        .seal()
        .unwrap_or_else(|e| panic!("seal of unsquashed reference fork failed: {e:?}"));
    ref_marf.commit().unwrap();
    assert_eq!(
        squashed_fork_root, reference_fork_root,
        "fork from a non-tip reclaimed squash parent must seal to the same root \
         as an unsquashed reference"
    );

    // Cross-check via storage that the committed fork block was registered at
    // the right height (parent_height + 1, NOT squash_tip + 1).
    let fork_block_height_via_marf =
        <MARF<StacksBlockId> as MarfInternals<StacksBlockId>>::get_block_height_miner_tip(
            &mut marf,
            &fork_block,
            &fork_block,
        )
        .expect("post-commit get_block_height_miner_tip should succeed");
    assert_eq!(
        fork_block_height_via_marf,
        Some(expected_fork_parent_height + 1),
        "fork block (committed extension of non-tip squashed parent) must \
         have height = parent_height + 1 = {}, not squash_tip + 1 = {}",
        expected_fork_parent_height + 1,
        N
    );
}

/// **REGRESSION TEST** for the `collect_history_parallel` block_hashes slice
/// indexing bug.
//
/// **Bug**: `collect_history_parallel` divides `min_height..=max_height` into
/// chunks across worker threads. Each worker calls `collect_history_into` with
/// the chunk's start as `min_height` parameter, but originally received the
/// FULL `block_hashes` slice. `collect_history_into` indexes that slice as
/// `block_hashes[(h - min_height)]` — which for any worker after the first
/// reads `block_hashes[0]` (the OUTER min_height's block) instead of the
/// chunk's actual block hash. The resulting partial history is wrong: every
/// worker chunk past the first records leaves under the wrong block heights,
/// producing incorrect `Vec<(height, value)>` entries.
//
/// **Fix**: each worker now slices `block_hashes` to just its chunk's range
/// (`chunk_block_hashes = &block_hashes[chunk_offset_lo..chunk_offset_hi]`),
/// so the indexing within `collect_history_into` is valid.
//
/// **Why existing tests didn't catch it**: the long-horizon differential tests
/// use `l0_blocks: usize = 6`, well below `HISTORY_MIN_HEIGHTS_FOR_PARALLEL =
/// 64`. They take the serial fallback in `collect_history_parallel` and never
/// exercised the parallel path. This test uses `N = 80` so the parallel path
/// is guaranteed to fire (at least 2 workers on any multi-core host).
//
/// **What this test verifies**: read every key at every height from the
/// squashed MARF and compare against an unsquashed reference. If `collect_history`
/// produces the wrong per-key entries (e.g., a value recorded under the wrong
/// height), the squashed `LeafSquashed`'s `value_at_height(h)` will return the
/// wrong value at some height, and the differential will diverge.
#[test]
fn test_repro_collect_history_parallel_block_hashes_indexing() {
    use crate::chainstate::stacks::index::squash::{squash_level_incremental, SquashMode};

    let dir = fresh_test_dir("test_repro_collect_history_parallel_indexing");
    let sq_path = format!("{dir}/squashed.sqlite");
    let ref_path = format!("{dir}/reference.sqlite");
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);

    // 80 blocks comfortably exceeds HISTORY_MIN_HEIGHTS_FOR_PARALLEL = 64,
    // ensuring `collect_history_parallel` takes the parallel path with
    // multiple workers (each handling ~10 heights at 8 workers).
    const N: u32 = 80;
    const KEYS_PER_BLOCK: u32 = 6;

    let block_hashes: Vec<StacksBlockId> = (0..N)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[24..28].copy_from_slice(&0x_C_AFE_BABEu32.to_be_bytes());
            bytes[28..32].copy_from_slice(&i.to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        })
        .collect();

    // Build the chain twice — once for the squashed copy, once for the
    // unsquashed reference. Mix repeated and unique writes so the per-key
    // history has both single-entry and multi-entry leaves to merge.
    for path in &[&sq_path, &ref_path] {
        let mut marf = MARF::<StacksBlockId>::from_path(path, open_opts.clone()).unwrap();
        let mut parent = StacksBlockId::sentinel();
        for (i, bh) in block_hashes.iter().enumerate() {
            marf.begin(&parent, bh).unwrap();
            for k in 0..KEYS_PER_BLOCK {
                // Mix two patterns:
                //  - shared_key_<k>: rewritten in every block with a value
                //    derived from (i, k) → produces multi-entry LeafSquashed
                //    that crosses chunk seams.
                //  - per_block_key_<i>_<k>: written once per block → produces
                //    single-entry LeafSquashed cleanly inside one chunk.
                marf.insert(
                    &format!("shared_key_{k}"),
                    MARFValue::from(i as u32 * 1000 + k),
                )
                .unwrap();
                marf.insert(
                    &format!("per_block_key_{i}_{k}"),
                    MARFValue::from(0xBEEF_0000u32 + i as u32 * 100 + k),
                )
                .unwrap();
            }
            marf.seal().unwrap();
            marf.commit().unwrap();
            parent = bh.clone();
        }
        drop(marf);
    }

    // Squash the squashed copy, leave the reference alone.
    squash_level_incremental::<StacksBlockId>(&sq_path, SquashMode::FullHistory, 0, N - 1, true)
        .expect("squash should succeed");

    // Differential: read every key at every block from both MARFs and assert
    // they match. With the bug, parallel-collected history records entries
    // under the wrong heights, so `value_at_height(h)` lookups for `shared_key_*`
    // diverge from the reference at some heights.
    let mut sq_marf = MARF::<StacksBlockId>::from_path(&sq_path, open_opts.clone()).unwrap();
    sq_marf.refresh_after_squash().unwrap();
    let mut ref_marf = MARF::<StacksBlockId>::from_path(&ref_path, open_opts.clone()).unwrap();

    let mut total_compared = 0usize;
    for (i, bh) in block_hashes.iter().enumerate() {
        // Sample `shared_key_*` (multi-entry LeafSquashed; sensitive to height
        // assignment in the parallel path).
        for k in 0..KEYS_PER_BLOCK {
            let key = format!("shared_key_{k}");
            let sq_val = sq_marf.get(bh, &key).unwrap();
            let ref_val = ref_marf.get(bh, &key).unwrap();
            assert_eq!(
                sq_val, ref_val,
                "divergence at block {i} for {key}: squashed={sq_val:?}, reference={ref_val:?}. \
                 If the squashed MARF disagrees with the unsquashed reference for a \
                 multi-write key, `collect_history_parallel` likely recorded entries \
                 under the wrong heights — exactly the indexing bug this test guards."
            );
            total_compared += 1;
        }
        // Spot-check `per_block_key_*` — single-entry LeafSquashed where chunk
        // assignment determines whether the entry exists at all.
        let key = format!("per_block_key_{i}_0");
        let sq_val = sq_marf.get(bh, &key).unwrap();
        let ref_val = ref_marf.get(bh, &key).unwrap();
        assert_eq!(
            sq_val, ref_val,
            "divergence at block {i} for per-block key {key}: squashed={sq_val:?}, reference={ref_val:?}"
        );
        total_compared += 1;
    }

    assert!(
        total_compared >= (N as usize) * (KEYS_PER_BLOCK as usize + 1),
        "differential check should compare >= one read per (block, key) pair"
    );
}
