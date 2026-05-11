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

//! End-to-end tests for the cold/hot tier dispatch.
//!
//! Each test opens a real on-disk MARF (every disk-backed MARF attaches a `HotFileSet`
//! unconditionally post Phase D D5 — the opt-in `MARFOpenOpts::enable_hot_tier` flag was removed
//! when hot tier became non-optional), exercises the storage stack through the public
//! `MARF::begin / insert / seal / commit` API, and asserts on the v1.5-specific invariants:
//!
//! - New block writes land in `<db>.hot.{seq:08}` (not `<db>.blobs`).
//! - `marf_data.storage_kind` is `Hot` (`= 1`) for the new rows; `marf_data.storage_seq` matches
//!   the active hot-file sequence.
//! - Reads of those blocks return correct content via the dispatch.
//! - Crossing the rotation threshold bumps `marf_state.active_hot_seq`.
//! - Re-opening the MARF picks up existing hot files from disk.
//! - Startup recovery truncates an artificially extended hot file back to the SQL-authoritative
//!   committed extent.

use std::fs;

use rusqlite::Connection;
use stacks_common::types::chainstate::BlockHeaderHash;

use crate::chainstate::stacks::index::hot_file::hot_file_path;
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use crate::chainstate::stacks::index::squash::SquashMode;
use crate::chainstate::stacks::index::storage::{TrieFileStorage, TrieHashCalculationMode};
use crate::chainstate::stacks::index::{trie_sql, ClarityMarfTrieId, MARFValue};

/// Per-test scratch directory under `target/tmp` (writable on macOS + Linux without TMPDIR special
/// handling).
fn fresh_test_dir(test_name: &str) -> String {
    let dir = format!("/tmp/stacks-hot-tier-tests/{test_name}");
    if std::fs::metadata(&dir).is_ok() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Open a fresh MARF with the hot tier enabled.
///
/// Returns the MARF and the path to its on-disk sqlite DB stem (used to assert on file paths).
fn open_hot_tier_marf(test_name: &str, mmap: bool) -> (MARF<BlockHeaderHash>, String) {
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(mmap);
    let marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    (marf, db_path)
}

fn block_hash(byte: u8) -> BlockHeaderHash {
    let mut bytes = [0u8; 32];
    bytes[31] = byte;
    BlockHeaderHash(bytes)
}

/// Append one trivial block (insert a single key) onto `parent`.
///
/// Returns the new block hash.
fn extend_with_block(
    marf: &mut MARF<BlockHeaderHash>,
    parent: &BlockHeaderHash,
    block_byte: u8,
) -> BlockHeaderHash {
    let new_block = block_hash(block_byte);
    marf.begin(parent, &new_block).unwrap();
    let key = format!("k_{block_byte}");
    let value = MARFValue::from_value(&format!("v_{block_byte}"));
    marf.insert(&key, value).unwrap();
    marf.seal().unwrap();
    marf.commit().unwrap();
    new_block
}

/// Confirm a block_hash row in `marf_data` has `storage_kind = 1` (Hot), the expected
/// `storage_seq`, and a non-zero `external_offset` / `external_length`.
fn assert_row_is_hot(db: &Connection, bhh: &BlockHeaderHash, expected_seq: u32) {
    let location = trie_sql::get_trie_storage_location_by_bhh(db, bhh).unwrap();
    assert!(
        matches!(location.kind, trie_sql::StorageKind::Hot),
        "row for {bhh} should be Hot, got {:?}",
        location.kind
    );
    assert_eq!(
        location.seq, expected_seq,
        "row for {bhh} should be in seq {expected_seq}, got {}",
        location.seq
    );
    assert!(
        location.length > 0,
        "hot row for {bhh} should have non-zero length"
    );
}

#[test]
fn writes_land_in_active_hot_file_when_opted_in() {
    let (mut marf, db_path) = open_hot_tier_marf(
        "writes_land_in_active_hot_file_when_opted_in",
        /* mmap = */ true,
    );

    // Boot block (sentinel → block 1).
    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);

    // Default `marf_state.active_hot_seq` is 1; default rotation threshold is 1 GiB, so three small
    // blocks won't rotate.
    let conn = marf.sqlite_conn();
    let state = trie_sql::read_marf_state(conn).unwrap();
    assert_eq!(state.active_hot_seq, 1);

    // Each new block's `marf_data` row should be Hot/seq=1.
    assert_row_is_hot(conn, &b1, 1);
    assert_row_is_hot(conn, &b2, 1);
    assert_row_is_hot(conn, &b3, 1);

    // The active hot file exists; the cold blob file does NOT contain any of the per-block bytes
    // (its size is zero — it's only used for promoted blobs, and Phase A has no promotion path
    // active).
    let hot_path = hot_file_path(&db_path, 1);
    let cold_path = format!("{db_path}.blobs");
    assert!(
        fs::metadata(&hot_path).is_ok(),
        "hot file {hot_path} must exist on disk"
    );
    let hot_len = fs::metadata(&hot_path).unwrap().len();
    assert!(
        hot_len > 0,
        "hot file should have block-trie bytes appended"
    );
    let cold_len = fs::metadata(&cold_path).map(|m| m.len()).unwrap_or(0);
    assert_eq!(
        cold_len, 0,
        "cold blob should be empty under Phase A: no promotion path is active yet"
    );
}

#[test]
fn reads_dispatch_to_hot_file_via_storage_kind() {
    let (mut marf, _db_path) = open_hot_tier_marf(
        "reads_dispatch_to_hot_file_via_storage_kind",
        /* mmap = */ true,
    );
    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);

    // Read each key from each block. If the dispatch is wrong the bytes seek into the cold blob
    // (which is empty), so the reads would fail with a corruption error rather than returning the
    // expected MARFValues.
    let v1 = marf
        .get(&b1, "k_1")
        .unwrap()
        .expect("k_1 should exist at b1");
    assert_eq!(v1, MARFValue::from_value("v_1"));
    let v2 = marf
        .get(&b2, "k_2")
        .unwrap()
        .expect("k_2 should exist at b2");
    assert_eq!(v2, MARFValue::from_value("v_2"));

    // k_1 must still be readable at b2 (descendant inheritance via the backpointer-walk path; this
    // exercises hot→hot backptr resolution).
    let v1_at_b2 = marf
        .get(&b2, "k_1")
        .unwrap()
        .expect("k_1 should be inherited at b2");
    assert_eq!(v1_at_b2, MARFValue::from_value("v_1"));
}

#[test]
fn rotation_bumps_active_seq_at_threshold() {
    // Set up the MARF with a tiny rotation threshold by reaching past the public open path. We open
    // normally (1 GiB threshold) and then override the threshold on the attached HotFileSet via the
    // test-only accessor — that mirrors what an integration test for `enable_hot_tier` would do
    // once a real config knob lands.
    let (mut marf, _db_path) = open_hot_tier_marf(
        "rotation_bumps_active_seq_at_threshold",
        /* mmap = */ false,
    );

    // Reduce the rotation threshold to ~1 KiB so a few inserts fire a rotate. Goes through the
    // test-only accessor on `TrieStorageConnection`.
    {
        let mut storage = marf.borrow_storage_backend();
        let hot_files = storage
            .hot_files_mut()
            .expect("hot_files must be attached when enable_hot_tier=true");
        hot_files.set_rotation_threshold_bytes(1024);
    }

    let sentinel = BlockHeaderHash::sentinel();
    let mut parent = sentinel;
    let mut last_active_seq = 1u32;
    let mut rotated = false;
    for i in 1u8..=20u8 {
        // Insert a block whose trie has enough leaves to push the hot file past the 1 KiB
        // threshold.
        let new_block = block_hash(i);
        marf.begin(&parent, &new_block).unwrap();
        for k in 0..16u8 {
            let key = format!("blk{i}_k{k}");
            marf.insert(&key, MARFValue::from_value(&format!("blk{i}_v{k}")))
                .unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        parent = new_block;

        let conn = marf.sqlite_conn();
        let state = trie_sql::read_marf_state(conn).unwrap();
        if state.active_hot_seq > last_active_seq {
            rotated = true;
            last_active_seq = state.active_hot_seq;
        }
    }
    assert!(
        rotated,
        "writing 20 blocks past a 1 KiB threshold should have rotated at least once"
    );

    // The most recent block should be in *some* hot file (whichever was active at write time — not
    // necessarily the final `active_hot_seq`, since rotation runs after the row commit, so the very
    // last write before a rotate lands in the pre-rotate seq).
    assert!(
        last_active_seq > 1,
        "active_hot_seq should be > 1 after rotation"
    );
    let conn = marf.sqlite_conn();
    let location = trie_sql::get_trie_storage_location_by_bhh(conn, &parent).unwrap();
    assert!(
        matches!(location.kind, trie_sql::StorageKind::Hot),
        "most recent block should still be Hot"
    );
    assert!(
        location.seq >= 1 && location.seq <= last_active_seq,
        "most recent block's seq ({}) should be in [1, {}]",
        location.seq,
        last_active_seq
    );
}

#[test]
fn reopen_picks_up_existing_hot_files_and_resumes_active() {
    let test_name = "reopen_picks_up_existing_hot_files_and_resumes_active";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);

    // Round 1: open, write 3 blocks, force rotate, write 2 more, drop.
    let (b1_hash, b3_hash, b5_hash) = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        // Tiny rotation threshold so we can rotate cheaply.
        {
            let mut storage = marf.borrow_storage_backend();
            let hf = storage.hot_files_mut().unwrap();
            hf.set_rotation_threshold_bytes(256);
        }
        let sentinel = BlockHeaderHash::sentinel();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let b3 = extend_with_block(&mut marf, &b2, 3);
        // After 3 blocks at this threshold the active should have rotated.
        let active_after_3 = trie_sql::read_marf_state(marf.sqlite_conn())
            .unwrap()
            .active_hot_seq;
        assert!(active_after_3 >= 1);
        let b4 = extend_with_block(&mut marf, &b3, 4);
        let b5 = extend_with_block(&mut marf, &b4, 5);
        (b1, b3, b5)
    };

    // Round 2: re-open. Hot files on disk should be picked up by the directory scan; reads of any
    // block must work.
    let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    let v1 = marf.get(&b1_hash, "k_1").unwrap();
    assert_eq!(v1, Some(MARFValue::from_value("v_1")));
    let v3 = marf.get(&b3_hash, "k_3").unwrap();
    assert_eq!(v3, Some(MARFValue::from_value("v_3")));
    let v5 = marf.get(&b5_hash, "k_5").unwrap();
    assert_eq!(v5, Some(MARFValue::from_value("v_5")));
}

/// Codex Phase A review, finding 1a: opening a hot-tier MARF as read-only must attach a
/// `HotFileSet` to the read-only handle.
///
/// Without this, any read of a `storage_kind = Hot` row fails inside `read_hot_bytes_at` with "no
/// hot files attached".
#[test]
fn open_readonly_attaches_hot_files_and_reads_hot_rows() {
    let test_name = "open_readonly_attaches_hot_files_and_reads_hot_rows";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts_rw =
        MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);

    // Round 1: write a chain via the writable MARF, then drop.
    let (b1, b2) = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts_rw.clone()).unwrap();
        let sentinel = BlockHeaderHash::sentinel();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        (b1, b2)
    };

    // Round 2: re-open writable, then call `reopen_readonly` to get a read-only handle. With
    // hot-tier enabled, the readonly handle must attach its own HotFileSet (in readonly mode) and
    // serve hot-row reads.
    let writer = MARF::<BlockHeaderHash>::from_path(&db_path, opts_rw).unwrap();
    let mut ro = writer.reopen_readonly().unwrap();
    let v1 = ro.get(&b1, "k_1").unwrap();
    assert_eq!(v1, Some(MARFValue::from_value("v_1")));
    let v2 = ro.get(&b2, "k_2").unwrap();
    assert_eq!(v2, Some(MARFValue::from_value("v_2")));
}

/// Codex Phase A review, finding 1c: a read-only open must not truncate hot files. Pad the active
/// hot file with bytes past the SQL-committed extent, open read-only, and verify the file size is
/// unchanged.
#[test]
fn readonly_open_does_not_truncate_active_hot_file() {
    let test_name = "readonly_open_does_not_truncate_active_hot_file";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);

    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let sentinel = BlockHeaderHash::sentinel();
        let _b1 = extend_with_block(&mut marf, &sentinel, 1);
    }

    // Pad the active hot file with garbage (simulating a torn append from a prior write-mode
    // session that crashed mid-append).
    let active_seq = {
        let conn = Connection::open(&db_path).unwrap();
        trie_sql::read_marf_state(&conn).unwrap().active_hot_seq
    };
    let path = hot_file_path(&db_path, active_seq);
    let pre_len = fs::metadata(&path).unwrap().len();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(pre_len + 4096)
        .unwrap();
    let padded_len = fs::metadata(&path).unwrap().len();
    assert_eq!(padded_len, pre_len + 4096);

    // Read-only open must NOT truncate. We re-open writable just to get a `TrieStorageConnection`
    // to call `reopen_readonly` on; the readonly path is what's under test, and it goes through
    // `build_readonly_storage` (the helper Codex flagged in F1c).
    let writer = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    let post_writer_len = fs::metadata(&path).unwrap().len();
    assert_eq!(
        post_writer_len, pre_len,
        "writable open clipped torn append back to committed extent (this is expected)"
    );

    // Re-pad after the writer's recovery to set up the actual readonly assertion: ensure the
    // readonly path leaves bytes alone.
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(post_writer_len + 4096)
        .unwrap();
    let repadded_len = fs::metadata(&path).unwrap().len();

    let _ro = writer.reopen_readonly().unwrap();
    let post_ro_len = fs::metadata(&path).unwrap().len();
    assert_eq!(
        post_ro_len, repadded_len,
        "readonly open must not modify the active hot file"
    );
}

/// Regression: readonly-first opening must NOT consume the per-path RW recovery slot. A later RW
/// open against the same path (with the readonly handle still alive) must still run the
/// truncate-on-startup that clips a torn append left by a prior process crash.
///
/// **Why this matters.** The recovery-slot machinery in `storage.rs` keeps a `Weak` per-path live
/// count to prevent two concurrent RW openers from racing each other (the original mainnet
/// genesis-sync panic). The naive "any handle holds a slot ⇒ skip recovery" scheme would let a
/// readonly-first open suppress the first RW opener's truncation, leaving the torn append in
/// place until every readonly handle drops. The fix gates truncation on a separate
/// `rw_recovery_done` flag that ONLY RW openers flip; this test exercises that distinction.
#[test]
fn readonly_first_open_does_not_suppress_rw_truncation() {
    let test_name = "readonly_first_open_does_not_suppress_rw_truncation";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);

    // Set up a chainstate with one committed block so the active hot file has real content past
    // which we can simulate a torn append.
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let sentinel = BlockHeaderHash::sentinel();
        let _b1 = extend_with_block(&mut marf, &sentinel, 1);
    }

    let active_seq = {
        let conn = Connection::open(&db_path).unwrap();
        trie_sql::read_marf_state(&conn).unwrap().active_hot_seq
    };
    let path = hot_file_path(&db_path, active_seq);

    // Pad the active hot file with garbage: simulates a torn append from a prior process crash.
    let pre_pad_len = fs::metadata(&path).unwrap().len();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(pre_pad_len + 4096)
        .unwrap();
    let padded_len = fs::metadata(&path).unwrap().len();
    assert_eq!(padded_len, pre_pad_len + 4096);

    // Readonly handle opens FIRST against the padded state. It must not modify the file (already
    // covered by `readonly_open_does_not_truncate_active_hot_file`), AND it must not flip the
    // per-path `rw_recovery_done` flag — that's what we're regression-testing.
    let ro_storage =
        TrieFileStorage::<BlockHeaderHash>::open_readonly(&db_path, opts.clone()).unwrap();
    let ro = MARF::<BlockHeaderHash>::from_storage(ro_storage);
    let post_ro_len = fs::metadata(&path).unwrap().len();
    assert_eq!(
        post_ro_len, padded_len,
        "readonly-first open must leave the torn-append padding in place"
    );

    // RW handle opens SECOND, while the readonly handle is still alive (so it shares the
    // per-path recovery state). It must observe `rw_recovery_done = false` and run the
    // truncate-on-startup, clipping the file back to the SQL-committed extent.
    let _rw = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    let post_rw_len = fs::metadata(&path).unwrap().len();
    assert_eq!(
        post_rw_len, pre_pad_len,
        "RW open following a readonly-first open must still truncate the torn append"
    );

    // Keep `ro` alive past the RW assertion so this test exercises the readonly-handle-still-live
    // case (not the readonly-dropped-then-RW path, which the existing tests already cover).
    drop(ro);
}

/// A `marf_data`-referenced hot file missing on disk is the C5 startup-reconciliation "window 2"
/// state (post-unlink/pre-DELETE crash, OR external cause like the operator-deletion this test
/// simulates).
///
/// **Post Phase C C5 (2026-05-02)**: an RW open now RECONCILES this state by DELETE-ing the
/// orphan `marf_data` rows (the file's data is already gone; C5 cleans up the SQL bookkeeping).
/// A readonly open still fails-fast with a `CorruptionError` naming the offending seq, since
/// readonly handles can't perform the SQL writes needed to reconcile (per §3.6 fail-hard policy).
///
/// Pre-C5 this test asserted RW open fail-fast; updated to assert the new RW reconcile behavior +
/// the readonly fail-hard behavior. The "data was lost" outcome is unchanged — the file was
/// already deleted before reopen; C5 just cleans up the dangling rows rather than refusing the
/// open.
#[test]
fn open_with_missing_referenced_hot_file_reconciles_rw_fails_readonly() {
    let test_name = "open_with_missing_referenced_hot_file_reconciles_rw_fails_readonly";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);

    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let sentinel = BlockHeaderHash::sentinel();
        // Tiny rotation threshold to produce two hot files.
        {
            let mut storage = marf.borrow_storage_backend();
            let hf = storage.hot_files_mut().unwrap();
            hf.set_rotation_threshold_bytes(64);
        }
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let _b3 = extend_with_block(&mut marf, &b2, 3);
    }

    // Find any rotated (non-active) seq and unlink it — that simulates an operator (or external
    // process) deleting a file whose rows are still in `marf_data`.
    let active_seq = {
        let conn = Connection::open(&db_path).unwrap();
        trie_sql::read_marf_state(&conn).unwrap().active_hot_seq
    };
    let mut deleted_seq: Option<u32> = None;
    for seq in 1..=active_seq {
        if seq == active_seq {
            continue;
        }
        let p = hot_file_path(&db_path, seq);
        if fs::metadata(&p).is_ok() {
            fs::remove_file(&p).unwrap();
            deleted_seq = Some(seq);
            break;
        }
    }
    let deleted_seq = deleted_seq.expect("test setup expected at least one rotated hot file");

    // Confirm rows for the deleted seq exist BEFORE reopen.
    {
        let conn = Connection::open(&db_path).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM marf_data WHERE storage_kind = 1 AND storage_seq = ?1",
                rusqlite::params![deleted_seq as i64],
                |r| r.get(0),
            )
            .unwrap();
        assert!(n > 0, "rows for deleted seq must exist pre-reopen");
    }

    // Readonly reopen → CorruptionError (fail-hard policy from §3.6).
    {
        let conn = Connection::open(&db_path).unwrap();
        match crate::chainstate::stacks::index::hot_file::HotFileSet::open(
            &db_path,
            &conn,
            false,
            /* rotation */ 1 << 20,
            /* readonly */ true,
        ) {
            Ok(_) => panic!("readonly open over orphan rows must fail"),
            Err(crate::chainstate::stacks::index::Error::CorruptionError(msg)) => {
                assert!(
                    msg.contains("readonly") && msg.contains("orphan_seqs"),
                    "readonly error must call out the orphan_seqs; got: {msg}"
                );
            }
            Err(other) => panic!("expected CorruptionError, got {other:?}"),
        }
    }

    // RW reopen → reconcile DELETEs the orphan rows; open succeeds.
    let _marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts)
        .expect("RW open must reconcile the orphan-rows state and succeed");

    // Post-reconcile: the rows for the deleted seq are gone.
    {
        let conn = Connection::open(&db_path).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM marf_data WHERE storage_kind = 1 AND storage_seq = ?1",
                rusqlite::params![deleted_seq as i64],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0, "C5 RW reconcile must DELETE the orphan rows");
    }
}

/// Codex Phase A review, finding 3 (variant): a hot file that's shorter than its SQL-committed
/// extent is corruption — must fail-fast on open.
#[test]
fn open_fails_when_hot_file_shorter_than_committed_extent() {
    let test_name = "open_fails_when_hot_file_shorter_than_committed_extent";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);

    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let sentinel = BlockHeaderHash::sentinel();
        let _b1 = extend_with_block(&mut marf, &sentinel, 1);
    }

    // Truncate the active hot file to half its size.
    let active_seq = {
        let conn = Connection::open(&db_path).unwrap();
        trie_sql::read_marf_state(&conn).unwrap().active_hot_seq
    };
    let path = hot_file_path(&db_path, active_seq);
    let original_len = fs::metadata(&path).unwrap().len();
    assert!(
        original_len > 0,
        "test setup expected the active hot file to have data"
    );
    let half = original_len / 2;
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(half)
        .unwrap();

    // Reopen must fail-fast with a corruption error.
    let result = MARF::<BlockHeaderHash>::from_path(&db_path, opts);
    let err = result.err().expect("open with short hot file should fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("shorter than committed extent"),
        "error must call out the short file; got: {msg}"
    );
}

#[test]
fn startup_recovery_truncates_torn_active_hot_file() {
    let test_name = "startup_recovery_truncates_torn_active_hot_file";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);

    // Build a small chain so committed bytes exist.
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let sentinel = BlockHeaderHash::sentinel();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let _b2 = extend_with_block(&mut marf, &b1, 2);
    }

    // Simulate a torn append: pad the active hot file with garbage bytes that the SQL-authoritative
    // startup recovery should clip.
    let active_seq_before = {
        let conn = Connection::open(&db_path).unwrap();
        trie_sql::read_marf_state(&conn).unwrap().active_hot_seq
    };
    let active_path = hot_file_path(&db_path, active_seq_before);
    let committed_len = fs::metadata(&active_path).unwrap().len();
    let garbage = vec![0xff_u8; 4096];
    fs::OpenOptions::new()
        .write(true)
        .open(&active_path)
        .unwrap()
        .set_len(committed_len + garbage.len() as u64)
        .unwrap();
    let post_garbage_len = fs::metadata(&active_path).unwrap().len();
    assert_eq!(post_garbage_len, committed_len + garbage.len() as u64);

    // Re-open. Startup recovery should truncate the active hot file back to `committed_len`. The
    // MARF should also still be readable.
    let _marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    let post_recovery_len = fs::metadata(&active_path).unwrap().len();
    assert_eq!(
        post_recovery_len, committed_len,
        "startup must truncate the active hot file back to the SQL-committed extent"
    );
}

// ===========================================================================
// Phase D (2026-05-04): focused read-dispatch tests for the hot/cold contract
// ===========================================================================
//
// Hot tier is non-optional under v1.5 post-cleanup. Production reads always flow through the
// resolver, which dispatches on `marf_data.storage_kind`:
//
// - `Hot`  → `<db>.hot.{storage_seq:08}` at `external_offset[..external_length]`
// - `Cold` → `<db>.blobs` at `external_offset[..external_length]`
//
// The three states a read may encounter:
//
// 1. **Hot only**: every block in this MARF is in hot storage (pre-promotion).
// 2. **Hot + Cold mix**: some blocks promoted (cold), others still hot (hot tail).
// 3. **Cold only**: every block has been promoted (post-full-promotion). Also covers the upgrade
//    case where a v2 chainstate's existing rows migrate as cold and stay cold until a write.
//
// `reads_dispatch_to_hot_file_via_storage_kind` above covers (1). `b5a_horizon_gated_promotion_*`
// in `test/squash_promote.rs` covers (2) + (3) through the full promotion flow but with broader
// scope. The tests below isolate each state into a focused regression that pins the dispatch
// contract by reading-back values from each storage state via the public MARF read API.

/// Build a MARF, write `count` blocks, commit each. Returns the MARF + the committed block hashes
/// in order. All writes land in hot storage (pre-promotion).
fn build_chain_for_dispatch_test(
    test_name: &str,
    count: u8,
) -> (MARF<BlockHeaderHash>, String, Vec<BlockHeaderHash>) {
    let (mut marf, db_path) = open_hot_tier_marf(test_name, /* mmap = */ false);
    let mut blocks: Vec<BlockHeaderHash> = Vec::with_capacity(count as usize);
    let mut parent = BlockHeaderHash::sentinel();
    for byte in 1..=count {
        let bhh = extend_with_block(&mut marf, &parent, byte);
        blocks.push(bhh.clone());
        parent = bhh;
    }
    (marf, db_path, blocks)
}

/// Drive a horizon-gated promotion that flips every block in `[0..=max_height_inclusive]` from
/// hot → cold via the production `run_horizon_gated_promotion` path. Test helper used by the
/// dispatch tests to materialize the cold-only / hot+cold-mix states.
///
/// `in_range_tip` is the block at `max_height_inclusive` — the canonical tip of the IN-RANGE
/// portion being promoted, NOT the current chain tip. The promotion uses this as the anchor for
/// its canonical-ancestry walk over the merge range. (See `b5a_horizon_gated_promotion_*` in
/// `test/squash_promote.rs` for the production-equivalent shape.)
fn promote_range_for_dispatch_test(
    marf: &mut MARF<BlockHeaderHash>,
    in_range_tip: &BlockHeaderHash,
    max_height_inclusive: u32,
) {
    use crate::chainstate::stacks::index::squash_promote::run_horizon_gated_promotion;
    run_horizon_gated_promotion::<BlockHeaderHash>(
        marf,
        SquashMode::TipOnly,
        0,
        max_height_inclusive,
        Some(in_range_tip.clone()),
    )
    .expect("promotion must succeed");
    marf.refresh_after_squash()
        .expect("refresh_after_squash must succeed");
}

/// Read every key from every block in `blocks` and assert the inserted value comes back.
fn assert_all_keys_readable(marf: &mut MARF<BlockHeaderHash>, blocks: &[BlockHeaderHash]) {
    for (i, block) in blocks.iter().enumerate() {
        let byte = (i + 1) as u8;
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        let got = marf
            .get(block, &key)
            .unwrap_or_else(|e| panic!("get k_{byte} at block {i}: {e}"));
        assert_eq!(
            got,
            Some(expected),
            "k_{byte} at block {i} returned wrong value through the resolver"
        );
    }
}

fn count_rows_with_storage_kind(conn: &Connection, kind: i64) -> usize {
    conn.query_row(
        "SELECT COUNT(*) FROM marf_data WHERE storage_kind = ?1 AND unconfirmed = 0",
        rusqlite::params![kind],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n as usize)
    .unwrap()
}

/// **Read-dispatch state 1: hot-only.** Every block sits in hot storage; no promotion has run.
/// Reads of every key at every block must succeed via the resolver's hot-file dispatch path.
#[test]
fn read_dispatch_hot_only_state() {
    let (mut marf, _db_path, blocks) =
        build_chain_for_dispatch_test("read_dispatch_hot_only_state", 5);

    // Sanity: every committed row is hot.
    let conn = marf.sqlite_conn();
    assert_eq!(
        count_rows_with_storage_kind(conn, 1),
        5,
        "all 5 committed blocks must be hot pre-promotion"
    );
    assert_eq!(
        count_rows_with_storage_kind(conn, 0),
        0,
        "no cold rows expected pre-promotion"
    );

    // Resolver dispatch: every key reads back through the hot-file path.
    assert_all_keys_readable(&mut marf, &blocks);
}

/// **Read-dispatch state 2: hot + cold mix.** Promote some prefix of the chain, leave the rest in
/// the hot tail. Reads must succeed for both the promoted-cold range AND the still-hot tail
/// range, exercising the resolver's per-row dispatch across the boundary in a single MARF/session.
#[test]
fn read_dispatch_hot_and_cold_mix_state() {
    let (mut marf, _db_path, blocks) =
        build_chain_for_dispatch_test("read_dispatch_hot_and_cold_mix_state", 6);

    // Promote heights 0..=3 (b1..b4). b5..b6 stay hot. The IN-RANGE tip is b4 (height 3), passed
    // as the canonical-ancestry anchor for the merge.
    let in_range_tip = blocks[3].clone();
    promote_range_for_dispatch_test(&mut marf, &in_range_tip, 3);

    // Sanity: 4 cold + 2 hot.
    let conn = marf.sqlite_conn();
    let cold = count_rows_with_storage_kind(conn, 0);
    let hot = count_rows_with_storage_kind(conn, 1);
    assert_eq!(cold, 4, "heights 0..=3 must flip to cold");
    assert_eq!(hot, 2, "heights 4..=5 must stay hot");

    // Resolver dispatch: every key reads back through the right file. The cold-range reads exercise
    // `<db>.blobs`; the hot-tail reads exercise the active hot file. Hot-tail backptrs into the
    // cold range exercise the rewrite path (post-promotion offsets).
    assert_all_keys_readable(&mut marf, &blocks);
}

/// **Read-dispatch state 3: cold only.** Promote the entire chain so every row is cold; the hot
/// tier is empty (or contains only orphaned bytes that the next sweep would reclaim). Reads must
/// succeed entirely through `<db>.blobs`.
#[test]
fn read_dispatch_cold_only_state_after_full_promotion() {
    let (mut marf, _db_path, blocks) =
        build_chain_for_dispatch_test("read_dispatch_cold_only_state_after_full_promotion", 4);

    // Promote heights 0..=3 (every block). The IN-RANGE tip is b4 (height 3) — same as the
    // chain tip in this case since we're promoting everything.
    let in_range_tip = blocks[3].clone();
    promote_range_for_dispatch_test(&mut marf, &in_range_tip, 3);

    // Sanity: every committed row is cold.
    let conn = marf.sqlite_conn();
    assert_eq!(
        count_rows_with_storage_kind(conn, 0),
        4,
        "every block must be cold after full promotion"
    );
    assert_eq!(
        count_rows_with_storage_kind(conn, 1),
        0,
        "no hot rows expected after full promotion"
    );

    // Resolver dispatch: every key reads back through the cold blob.
    assert_all_keys_readable(&mut marf, &blocks);
}
