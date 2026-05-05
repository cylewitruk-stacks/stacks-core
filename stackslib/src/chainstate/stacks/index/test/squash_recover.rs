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

//! Integration tests for the Phase B promotion recovery state machine.
//!
//! Each test synthesizes a plan file + on-disk state representing one
//! row of the crash-point matrix from
//! `.docs/squashing-v1.5-phase-b.md` §7.1, then runs
//! `recover_pending_promotions` and asserts the terminal state matches
//! the expected behavior:
//!
//! - **Commit path**: cold blob and sidecar both verify, rewrite plan
//!   replays, SQL transaction commits, plan file is removed.
//! - **Abandon path**: cold blob or sidecar fails verification, plan
//!   file is removed, `marf_state.promotion_in_progress` is cleared,
//!   no SQL changes to in-range rows.
//! - **Idempotent replay**: re-running recovery against an
//!   already-committed plan (or a partially-applied plan) reaches the
//!   same terminal state without errors.
//! - **Hard failure**: a plan with corrupt witness bytes or undecodable
//!   header fails the open with a clear error.
//! - **Readonly fail-hard**: a readonly handle with any pending plan
//!   refuses to open (vs. silently ignoring, which would let a
//!   mid-swap state appear as wrong-but-readable bytes).

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use rusqlite::{params, Connection};
use stacks_common::types::chainstate::BlockHeaderHash;

use crate::chainstate::stacks::index::hot_file::HotFileSet;
use crate::chainstate::stacks::index::squash_plan::{
    plan_file_path, sha512_256_of, write_plan_file_atomic, InRangeBlock, PlanHeader, RewriteEntry,
    SquashPlan, TranslationMap,
};
use crate::chainstate::stacks::index::squash_recover::{
    cold_blob_path_for_tests, recover_pending_promotions, write_cold_blob_at,
};
use crate::chainstate::stacks::index::trie_sql;

/// Per-test scratch directory under `/tmp` (writable on macOS + Linux
/// without TMPDIR special handling). Mirrors the
/// `test/hot_tier.rs::fresh_test_dir` pattern.
fn fresh_test_dir(test_name: &str) -> PathBuf {
    let dir = PathBuf::from(format!("/tmp/stacks-squash-recover-tests/{test_name}"));
    if std::fs::metadata(&dir).is_ok() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Build a fresh on-disk MARF DB at v5 schema and return its db_path
/// + an opened SQLite connection.
fn fresh_v5_db(test_name: &str) -> (String, Connection) {
    let dir = fresh_test_dir(test_name);
    let db_path = dir.join("marf.sqlite");
    let mut conn = Connection::open(&db_path).unwrap();
    trie_sql::create_tables_if_needed(&mut conn).unwrap();
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut conn).unwrap();
    (db_path.to_str().unwrap().to_string(), conn)
}

/// Open a HotFileSet rooted at `db_path` with mmap disabled (tests run
/// fast without it; mmap-vs-pread is exercised separately in
/// `test/hot_tier.rs`).
fn open_hot_files(db_path: &str, db: &Connection) -> HotFileSet {
    HotFileSet::open(
        db_path,
        db,
        /* mmap */ false,
        1 << 20,
        /* readonly */ false,
    )
    .unwrap()
}

/// Insert a hot `marf_data` row for an in-range block so the SQL UPDATE
/// during recovery's commit transaction has something to update.
/// Returns the assigned `block_id`.
fn insert_hot_marf_data_row(
    conn: &Connection,
    block_hash: &BlockHeaderHash,
    storage_seq: u32,
    external_offset: u64,
    external_length: u64,
) -> u32 {
    // Use the inline-blob INSERT shape, then UPDATE with the
    // hot-tier columns. The schema's NOT NULL on `data` means we
    // need *some* bytes there even though hot rows don't use the
    // inline blob.
    conn.execute(
        "INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length, storage_kind, storage_seq) \
         VALUES (?1, ?2, 0, ?3, ?4, 1, ?5)",
        params![
            block_hash,
            &[] as &[u8],
            external_offset as i64,
            external_length as i64,
            storage_seq as i64,
        ],
    )
    .unwrap();
    conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ?1",
        params![block_hash],
        |r| r.get::<_, i64>(0),
    )
    .unwrap() as u32
}

/// Set `marf_state.promotion_in_progress` to `level_id` (and optionally
/// reservation fields) so we can verify recovery clears them.
fn set_promotion_in_progress(conn: &Connection, level_id: u32, offset: u64, length: u64) {
    conn.execute(
        "UPDATE marf_state SET promotion_in_progress = ?1, \
         promotion_reserved_offset = ?2, promotion_reserved_length = ?3 WHERE id = 1",
        params![level_id as i64, offset as i64, length as i64],
    )
    .unwrap();
}

/// Verify the in-flight promotion state has been cleared (all NULL).
fn assert_promotion_state_cleared(conn: &Connection) {
    let state = trie_sql::read_marf_state(conn).unwrap();
    assert_eq!(state.promotion_in_progress, None, "in_progress not cleared");
    assert_eq!(
        state.promotion_reserved_offset, None,
        "reserved_offset not cleared"
    );
    assert_eq!(
        state.promotion_reserved_length, None,
        "reserved_length not cleared"
    );
}

/// Build a minimal SquashPlan + populate the on-disk state required for
/// it to verify successfully. Returns the plan, the path it was written
/// to, the cold-blob path, and the sidecar path.
fn build_committable_plan_setup(
    db_path: &str,
    conn: &Connection,
    hot_files: &mut HotFileSet,
    level_id: u32,
) -> (SquashPlan, PathBuf, PathBuf, PathBuf) {
    // The plan promotes 2 in-range blocks (block_hashes 0xAA, 0xBB),
    // both currently routed as hot (storage_kind = 1, storage_seq = 1)
    // with arbitrary hot extents.
    let bhh_a = BlockHeaderHash([0xaa; 32]);
    let bhh_b = BlockHeaderHash([0xbb; 32]);
    let block_id_a = insert_hot_marf_data_row(conn, &bhh_a, 1, 100, 50);
    let block_id_b = insert_hot_marf_data_row(conn, &bhh_b, 1, 200, 60);

    // Append some hot-file bytes so the rewrite-plan witnesses match
    // what's on disk. Build two ptr fields' worth of bytes.
    let pre_bytes_a: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let pre_bytes_b: [u8; 4] = [0x55, 0x66, 0x77, 0x88];
    let post_bytes_a: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
    let post_bytes_b: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    // Write a 64-byte hot file payload with our pre-bytes at specific
    // offsets (10 and 30).
    let mut hot_payload = vec![0u8; 64];
    hot_payload[10..14].copy_from_slice(&pre_bytes_a);
    hot_payload[30..34].copy_from_slice(&pre_bytes_b);
    let (active_seq, hot_offset_base) = hot_files.append_to_active(&hot_payload).unwrap();
    assert_eq!(active_seq, 1);
    assert_eq!(hot_offset_base, 0);

    // Write a cold-blob region. Recovery will hash this and compare
    // to the plan header's cold_blob_hash.
    let cold_blob_path = cold_blob_path_for_tests(db_path);
    let cold_offset: u64 = 4096;
    let cold_payload: Vec<u8> = (0..256u32).map(|i| (i & 0xff) as u8).collect();
    write_cold_blob_at(&cold_blob_path, cold_offset, &cold_payload).unwrap();
    let cold_hash = sha512_256_of(&cold_payload);

    // Write a sidecar file. Recovery will hash this and compare.
    let sidecar_payload = b"sidecar bytes for test recovery".to_vec();
    let sidecar_name = format!("marf.sqlite-blob-{cold_offset:016x}.dat");
    let parent = PathBuf::from(db_path).parent().unwrap().to_path_buf();
    let sidecar_path = parent.join(&sidecar_name);
    fs::write(&sidecar_path, &sidecar_payload).unwrap();
    let sidecar_hash = sha512_256_of(&sidecar_payload);

    // Construct the plan: 2 blocks, 2 rewrite entries (one per
    // pre_bytes location in the hot file).
    let translation_map = TranslationMap {
        by_block: {
            let mut m = std::collections::HashMap::new();
            m.insert(block_id_a, BTreeMap::from([(50u32, 4096u32 + 10)]));
            m.insert(block_id_b, BTreeMap::from([(70u32, 4096u32 + 30)]));
            m
        },
    };
    let plan = SquashPlan {
        header: PlanHeader {
            level_id,
            min_height: 0,
            max_height: 1,
            tip_at_scan_start: 5,
            cold_blob_offset: cold_offset,
            cold_blob_length: cold_payload.len() as u64,
            cold_blob_hash: cold_hash,
            sidecar_path: sidecar_name.clone(),
            sidecar_hash,
            reads_redirected: true,
            root_sidecar_present: true,
            root_sidecar_trimmed: false,
            orphan_split_offset: 0,
            published_max_block_id: block_id_b,
        },
        in_range_blocks: vec![
            InRangeBlock {
                block_hash: [0xaa; 32],
                block_id: block_id_a,
            },
            InRangeBlock {
                block_hash: [0xbb; 32],
                block_id: block_id_b,
            },
        ],
        translation_map,
        rewrite_plan: vec![
            RewriteEntry {
                hot_file_seq: 1,
                file_offset: 10,
                pre_bytes: pre_bytes_a,
                post_bytes: post_bytes_a,
            },
            RewriteEntry {
                hot_file_seq: 1,
                file_offset: 30,
                pre_bytes: pre_bytes_b,
                post_bytes: post_bytes_b,
            },
        ],
    };

    let plan_path = PathBuf::from(plan_file_path(db_path, level_id));
    write_plan_file_atomic(&plan_path, &plan).unwrap();

    // Mark the promotion as in-flight so we can verify it gets cleared.
    set_promotion_in_progress(conn, level_id, cold_offset, cold_payload.len() as u64);

    (plan, plan_path, cold_blob_path, sidecar_path)
}

/// Read 4 bytes at `(seq=1, offset)` from the active hot file.
fn read_hot_4(hot_files: &HotFileSet, offset: u64) -> [u8; 4] {
    let mut buf = [0u8; 4];
    hot_files.read_at(1, &mut buf, offset).unwrap();
    buf
}

// ===========================================================================
// No-plan baseline
// ===========================================================================

#[test]
fn recovery_no_plans_is_a_noop() {
    let (db_path, mut conn) = fresh_v5_db("recovery_no_plans_is_a_noop");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let stats = recover_pending_promotions::<BlockHeaderHash>(
        &mut conn,
        &db_path,
        &mut hot_files,
        /* readonly */ false,
    )
    .unwrap();
    assert_eq!(stats.plans_discovered, 0);
    assert_eq!(stats.plans_committed, 0);
    assert_eq!(stats.plans_abandoned, 0);
    assert_eq!(stats.rewrites_applied, 0);
    assert_eq!(stats.rewrites_skipped, 0);
}

#[test]
fn recovery_clears_stale_promotion_lock_when_no_plan_present() {
    // Models the "crash after set_promotion_in_progress, before plan-file
    // fsync" window. Without the stale-lock fix in
    // `recover_pending_promotions`, the lock would persist forever and
    // permanently single-flight-block the MARF.
    let (db_path, mut conn) = fresh_v5_db("recovery_clears_stale_lock");
    let mut hot_files = open_hot_files(&db_path, &conn);

    // Pretend the prior process set the lock then crashed before any plan
    // file got fsynced.
    set_promotion_in_progress(
        &conn, /* level_id */ 42, /* offset */ 4096, /* length */ 256,
    );
    let pre = trie_sql::read_marf_state(&conn).unwrap();
    assert_eq!(pre.promotion_in_progress, Some(42));

    let stats =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();
    assert_eq!(stats.plans_discovered, 0);
    assert_eq!(stats.plans_committed, 0);
    assert_eq!(stats.plans_abandoned, 0);

    // Critical: the stale lock must be cleared so the next cadence tick
    // can spawn a fresh promotion.
    assert_promotion_state_cleared(&conn);
}

#[test]
fn recovery_readonly_does_not_clear_stale_promotion_lock() {
    // Symmetric to the previous test: a readonly handle must not mutate
    // SQL state, even when it would be "obviously" safe to clear the
    // lock. The writer's RW open will handle it.
    let (db_path, mut conn) = fresh_v5_db("recovery_readonly_no_clear_stale");
    let mut hot_files = open_hot_files(&db_path, &conn);

    set_promotion_in_progress(&conn, 99, 8192, 1024);

    let stats = recover_pending_promotions::<BlockHeaderHash>(
        &mut conn,
        &db_path,
        &mut hot_files,
        /* readonly */ true,
    )
    .unwrap();
    assert_eq!(stats.plans_discovered, 0);

    // Lock must still be set — readonly never mutates.
    let post = trie_sql::read_marf_state(&conn).unwrap();
    assert_eq!(post.promotion_in_progress, Some(99));
}

// ===========================================================================
// Commit path: clean plan replays end-to-end.
// ===========================================================================

#[test]
fn recovery_commits_clean_plan_and_publishes_level_row() {
    let (db_path, mut conn) = fresh_v5_db("recovery_commits_clean_plan");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let (plan, plan_path, _cold_blob_path, _sidecar_path) =
        build_committable_plan_setup(&db_path, &conn, &mut hot_files, 7);

    let stats =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();

    assert_eq!(stats.plans_discovered, 1);
    assert_eq!(stats.plans_committed, 1);
    assert_eq!(stats.plans_abandoned, 0);
    assert_eq!(stats.rewrites_applied, 2);
    assert_eq!(stats.rewrites_skipped, 0);

    // Hot file bytes were rewritten to post_bytes.
    assert_eq!(read_hot_4(&hot_files, 10), [0xaa, 0xbb, 0xcc, 0xdd]);
    assert_eq!(read_hot_4(&hot_files, 30), [0xde, 0xad, 0xbe, 0xef]);

    // Plan file was removed.
    assert!(
        !plan_path.exists(),
        "plan file should be removed after commit"
    );

    // marf_squash_levels has the row.
    let levels = trie_sql::read_squash_levels(&conn).unwrap();
    assert_eq!(levels.len(), 1, "expected exactly one published level");
    assert_eq!(levels[0].level_id, 7);
    assert_eq!(levels[0].blob_offset, plan.header.cold_blob_offset);
    assert_eq!(levels[0].blob_length, plan.header.cold_blob_length);

    // marf_data rows are now cold (storage_kind = 0) and point at the
    // merged blob.
    for in_range in &plan.in_range_blocks {
        let bhh = BlockHeaderHash(in_range.block_hash);
        let row = conn
            .query_row(
                "SELECT external_offset, external_length, storage_kind, storage_seq \
                 FROM marf_data WHERE block_hash = ?1",
                params![&bhh],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)? as u64,
                        r.get::<_, i64>(1)? as u64,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row.0, plan.header.cold_blob_offset);
        assert_eq!(row.1, plan.header.cold_blob_length);
        assert_eq!(row.2, 0, "storage_kind should be Cold post-promotion");
        assert_eq!(row.3, 0, "storage_seq should be 0 post-promotion");
    }

    // Promotion in-flight state cleared.
    assert_promotion_state_cleared(&conn);
}

// ===========================================================================
// Idempotent replay: running recovery again is a no-op (no plan file)
// ===========================================================================

#[test]
fn recovery_re_run_after_commit_is_a_noop() {
    let (db_path, mut conn) = fresh_v5_db("recovery_re_run_after_commit");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let _setup = build_committable_plan_setup(&db_path, &conn, &mut hot_files, 1);
    let _first =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();
    let second =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();
    assert_eq!(second.plans_discovered, 0);
    assert_eq!(second.plans_committed, 0);
}

// ===========================================================================
// Idempotent replay: re-encoded plan with already-applied bytes skips
// (simulates "crash after SQL commit, before plan-file unlink")
// ===========================================================================

#[test]
fn recovery_skips_already_applied_rewrites() {
    let (db_path, mut conn) = fresh_v5_db("recovery_skips_already_applied");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let (plan, plan_path, _, _) = build_committable_plan_setup(&db_path, &conn, &mut hot_files, 9);

    // Manually pwrite the post_bytes — simulates the swap finishing
    // its rewrites before the crash.
    for entry in &plan.rewrite_plan {
        hot_files
            .pwrite_ptr_field(entry.hot_file_seq, entry.file_offset, entry.post_bytes)
            .unwrap();
    }

    // Plan file is still present (the unlink hadn't happened yet).
    assert!(plan_path.exists());

    let stats =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();
    assert_eq!(stats.plans_committed, 1);
    assert_eq!(stats.rewrites_applied, 0, "no fresh writes");
    assert_eq!(
        stats.rewrites_skipped, 2,
        "both entries were already in post-state"
    );

    // Plan file is removed; level row inserted.
    assert!(!plan_path.exists());
    assert_eq!(trie_sql::read_squash_levels(&conn).unwrap().len(), 1);
}

// ===========================================================================
// Mid-rewrite recovery: one entry applied, one not (simulates a crash
// between two pwrites)
// ===========================================================================

#[test]
fn recovery_handles_partially_applied_rewrites() {
    let (db_path, mut conn) = fresh_v5_db("recovery_partial_rewrites");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let (plan, plan_path, _, _) = build_committable_plan_setup(&db_path, &conn, &mut hot_files, 11);

    // Apply only the first entry's pwrite (simulate mid-swap crash).
    let first = &plan.rewrite_plan[0];
    hot_files
        .pwrite_ptr_field(first.hot_file_seq, first.file_offset, first.post_bytes)
        .unwrap();

    let stats =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();
    assert_eq!(stats.plans_committed, 1);
    assert_eq!(stats.rewrites_applied, 1, "one fresh write");
    assert_eq!(stats.rewrites_skipped, 1, "one was already applied");
    assert!(!plan_path.exists());
}

// ===========================================================================
// Abandon path: cold-blob hash mismatch.
// ===========================================================================

#[test]
fn recovery_abandons_plan_on_cold_blob_hash_mismatch() {
    let (db_path, mut conn) = fresh_v5_db("recovery_abandons_cold_mismatch");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let (plan, plan_path, cold_blob_path, _) =
        build_committable_plan_setup(&db_path, &conn, &mut hot_files, 3);

    // Corrupt the cold blob: flip a byte in the recorded region. Hash
    // will no longer match plan.header.cold_blob_hash.
    {
        use std::os::unix::fs::FileExt;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cold_blob_path)
            .unwrap();
        let bad = [0xff_u8; 1];
        f.write_at(&bad, plan.header.cold_blob_offset + 5).unwrap();
    }

    let stats =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();
    assert_eq!(stats.plans_committed, 0);
    assert_eq!(stats.plans_abandoned, 1);

    // No level row published; plan file removed; in-flight state cleared.
    assert!(!plan_path.exists());
    assert_eq!(trie_sql::read_squash_levels(&conn).unwrap().len(), 0);
    assert_promotion_state_cleared(&conn);

    // marf_data rows are still hot (no SQL UPDATE happened).
    let bhh_a = BlockHeaderHash([0xaa; 32]);
    let kind: i64 = conn
        .query_row(
            "SELECT storage_kind FROM marf_data WHERE block_hash = ?1",
            params![&bhh_a],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kind, 1, "row should remain Hot since plan was abandoned");
}

// ===========================================================================
// Abandon path: cold blob too short.
// ===========================================================================

#[test]
fn recovery_abandons_plan_when_cold_blob_too_short() {
    let (db_path, mut conn) = fresh_v5_db("recovery_abandons_cold_short");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let (plan, plan_path, cold_blob_path, _) =
        build_committable_plan_setup(&db_path, &conn, &mut hot_files, 4);

    // Truncate the cold blob to before the plan's reserved region.
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&cold_blob_path)
        .unwrap();
    f.set_len(plan.header.cold_blob_offset).unwrap();

    let stats =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();
    assert_eq!(stats.plans_abandoned, 1);
    assert!(!plan_path.exists());
    assert_promotion_state_cleared(&conn);
}

// ===========================================================================
// Abandon path: cold blob completely missing.
// ===========================================================================

#[test]
fn recovery_abandons_plan_when_cold_blob_missing() {
    let (db_path, mut conn) = fresh_v5_db("recovery_abandons_cold_missing");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let (_plan, plan_path, cold_blob_path, _) =
        build_committable_plan_setup(&db_path, &conn, &mut hot_files, 5);

    fs::remove_file(&cold_blob_path).unwrap();

    let stats =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();
    assert_eq!(stats.plans_abandoned, 1);
    assert!(!plan_path.exists());
}

// ===========================================================================
// Abandon path: sidecar missing.
// ===========================================================================

#[test]
fn recovery_abandons_plan_when_sidecar_missing() {
    let (db_path, mut conn) = fresh_v5_db("recovery_abandons_sidecar_missing");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let (_plan, plan_path, _, sidecar_path) =
        build_committable_plan_setup(&db_path, &conn, &mut hot_files, 6);

    fs::remove_file(&sidecar_path).unwrap();

    let stats =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();
    assert_eq!(stats.plans_abandoned, 1);
    assert!(!plan_path.exists());
}

// ===========================================================================
// Hard failure: corrupt plan file (bad magic).
// ===========================================================================

#[test]
fn recovery_fails_on_undecodable_plan_file() {
    let (db_path, mut conn) = fresh_v5_db("recovery_fails_undecodable");
    let mut hot_files = open_hot_files(&db_path, &conn);
    // Write a junk file at the plan path. Won't decode → hard error.
    let plan_path = PathBuf::from(plan_file_path(&db_path, 99));
    fs::write(&plan_path, b"garbage that is not a valid plan").unwrap();

    let err =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .expect_err("should fail to decode");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("failed to decode plan file"),
        "unexpected error: {msg}",
    );
}

// ===========================================================================
// Hard failure: rewrite witness mismatch.
// ===========================================================================

#[test]
fn recovery_fails_on_corrupt_witness_bytes() {
    let (db_path, mut conn) = fresh_v5_db("recovery_fails_witness");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let (plan, _plan_path, _, _) =
        build_committable_plan_setup(&db_path, &conn, &mut hot_files, 13);

    // Stomp the first ptr-field with arbitrary bytes that match neither
    // pre_bytes nor post_bytes.
    let first = &plan.rewrite_plan[0];
    hot_files
        .pwrite_ptr_field(
            first.hot_file_seq,
            first.file_offset,
            [0x00, 0x00, 0x00, 0x00],
        )
        .unwrap();

    let err =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .expect_err("should fail on witness mismatch");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("neither pre nor post bytes"),
        "unexpected error: {msg}",
    );
}

// ===========================================================================
// Readonly fail-hard: pending plan present.
// ===========================================================================

#[test]
fn recovery_readonly_fails_hard_on_pending_plan() {
    let (db_path, mut conn) = fresh_v5_db("recovery_readonly_fails_hard");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let (_plan, plan_path, _, _) =
        build_committable_plan_setup(&db_path, &conn, &mut hot_files, 17);

    let err = recover_pending_promotions::<BlockHeaderHash>(
        &mut conn,
        &db_path,
        &mut hot_files,
        /* readonly */ true,
    )
    .expect_err("readonly with pending plan must fail hard");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("readonly open: pending squash promotion"),
        "unexpected error: {msg}",
    );
    // Plan file must still exist — readonly never deletes anything.
    assert!(plan_path.exists());
}

#[test]
fn recovery_readonly_succeeds_when_no_plans() {
    let (db_path, mut conn) = fresh_v5_db("recovery_readonly_no_plans");
    let mut hot_files = open_hot_files(&db_path, &conn);
    let stats = recover_pending_promotions::<BlockHeaderHash>(
        &mut conn,
        &db_path,
        &mut hot_files,
        /* readonly */ true,
    )
    .unwrap();
    assert_eq!(stats.plans_discovered, 0);
    assert_eq!(stats.cold_tail_truncated_bytes, 0);
}

// ===========================================================================
// Cold-tail truncation: clips bytes past `get_external_blobs_length()`.
// ===========================================================================

#[test]
fn recovery_truncates_uncommitted_cold_tail() {
    let (db_path, mut conn) = fresh_v5_db("recovery_truncates_cold_tail");
    let mut hot_files = open_hot_files(&db_path, &conn);

    // Write a cold blob with extra trailing bytes past any committed
    // extent. With no level rows and no cold marf_data rows,
    // `get_external_blobs_length()` returns 0, so the recovery should
    // truncate the file to 0 bytes.
    let cold_blob_path = cold_blob_path_for_tests(&db_path);
    write_cold_blob_at(&cold_blob_path, 0, &[0xab; 1024]).unwrap();
    assert_eq!(
        std::fs::metadata(&cold_blob_path).unwrap().len(),
        1024,
        "pre-recovery cold blob should be 1024 bytes",
    );

    let stats =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();
    assert_eq!(stats.cold_tail_truncated_bytes, 1024);
    assert_eq!(
        std::fs::metadata(&cold_blob_path).unwrap().len(),
        0,
        "cold blob should be empty after truncation",
    );
}

#[test]
fn recovery_does_not_truncate_when_within_committed_extent() {
    let (db_path, mut conn) = fresh_v5_db("recovery_no_truncate_when_in_extent");
    let mut hot_files = open_hot_files(&db_path, &conn);

    // Populate a cold marf_data row at offset 0..1024 — that's the
    // committed extent. Cold blob has the same 1024 bytes.
    let cold_blob_path = cold_blob_path_for_tests(&db_path);
    write_cold_blob_at(&cold_blob_path, 0, &[0xcd; 1024]).unwrap();
    let bhh = BlockHeaderHash([0xee; 32]);
    conn.execute(
        "INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length, storage_kind, storage_seq) \
         VALUES (?1, ?2, 0, 0, 1024, 0, 0)",
        params![&bhh, &[] as &[u8]],
    )
    .unwrap();

    let stats =
        recover_pending_promotions::<BlockHeaderHash>(&mut conn, &db_path, &mut hot_files, false)
            .unwrap();
    assert_eq!(stats.cold_tail_truncated_bytes, 0);
    assert_eq!(std::fs::metadata(&cold_blob_path).unwrap().len(), 1024);
}
