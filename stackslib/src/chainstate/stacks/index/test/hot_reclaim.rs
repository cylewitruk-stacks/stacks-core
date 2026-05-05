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

//! Phase C C6 integration tests for the hot-reclaim sweep.
//!
//! Per-slice unit tests for `sweep_unlinkable_hot_files` live in
//! `chainstate::stacks::index::hot_reclaim::tests` and exercise the loop against small synthetic
//! fixtures (3-file scenarios). These C6 tests scale the same loop up to many candidates to pin
//! the load-bearing acceptance criterion from
//! [.docs/squashing-v1.5.md §11](../../../../../.docs/squashing-v1.5.md): a long-running
//! write/promote/sweep cycle converges to a bounded set of hot files.
//!
//! **Scope note**: these tests construct a realistic post-promotion candidate distribution
//! synthetically (rotated hot files with marf_data rows wired up to mimic the post-promotion +
//! pre-sweep state), rather than driving real MARF promotions in a loop. Real-MARF multi-round
//! promotion against a single live MARF handle needs cross-level-backptr book-keeping that the
//! current `run_horizon_gated_promotion`/`_at_path` test entry points don't fully wire for the
//! N-round case (the rehash pass fails to resolve cross-level backptr targets that span prior
//! promotion levels). The end-to-end real-promotion convergence test is left as a Phase D
//! follow-up; these synthetic-scale tests are sufficient to demonstrate the per-sweep convergence
//! property the §11 risk note hangs on.

use std::collections::HashMap;

use rusqlite::Connection;
use stacks_common::types::chainstate::BlockHeaderHash;

use crate::chainstate::stacks::index::hot_file::{hot_file_path, HotFileSet};
use crate::chainstate::stacks::index::hot_reclaim::{
    sweep_unlinkable_hot_files, SweepStats, DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
};
use crate::chainstate::stacks::index::{trie_sql, Error};

fn fresh_v5_db(test_name: &str) -> (std::path::PathBuf, Connection) {
    let dir = std::env::temp_dir()
        .join("stacks-hot-reclaim-c6")
        .join(test_name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("marf.sqlite");
    let mut conn = Connection::open(&db_path).unwrap();
    trie_sql::create_tables_if_needed(&mut conn).unwrap();
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut conn).unwrap();
    (db_path, conn)
}

fn bhh(byte: u8) -> BlockHeaderHash {
    let mut bytes = [0u8; 32];
    bytes[31] = byte;
    BlockHeaderHash(bytes)
}

/// Append a synthetic blob (32B parent_hash + 4B zero-id + payload) to the active hot file. Returns
/// `(seq, offset, length)` for the matching `marf_data` row.
fn append_blob(set: &mut HotFileSet, parent: &BlockHeaderHash, pad: usize) -> (u32, u64, u64) {
    let mut blob = Vec::with_capacity(32 + 4 + pad);
    blob.extend_from_slice(parent.as_ref());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend(std::iter::repeat(0u8).take(pad));
    let len = blob.len() as u64;
    let (seq, offset) = set.append_to_active(&blob).unwrap();
    (seq, offset, len)
}

fn insert_hot_row(
    conn: &Connection,
    block_hash: &BlockHeaderHash,
    seq: u32,
    offset: u64,
    length: u64,
) {
    conn.execute(
        "INSERT INTO marf_data \
         (block_hash, data, unconfirmed, external_offset, external_length, \
          storage_kind, storage_seq) \
         VALUES (?1, x'', 0, ?2, ?3, 1, ?4)",
        rusqlite::params![block_hash, offset as i64, length as i64, seq as i64],
    )
    .unwrap();
}

fn count_hot_files_on_disk(db_path: &std::path::Path) -> usize {
    let parent = db_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let stem = db_path.file_name().and_then(|s| s.to_str()).unwrap();
    let prefix = format!("{stem}.hot.");
    let Ok(entries) = std::fs::read_dir(&parent) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with(&prefix))
                .unwrap_or(false)
        })
        .count()
}

fn build_set_with_n_rotated_files(set: &mut HotFileSet, conn: &Connection, n: usize) -> Vec<u32> {
    set.set_rotation_threshold_bytes(64);
    let mut seqs = Vec::with_capacity(n);
    for _ in 0..n {
        let (s, _, _) = append_blob(set, &BlockHeaderHash([0u8; 32]), 0);
        // Force rotation explicitly so each blob lands in its own seq, regardless of
        // should_rotate's exact byte threshold.
        set.rotate(conn).unwrap();
        seqs.push(s);
    }
    seqs
}

/// **C6 acceptance test, all-reclaimable case** (per
/// [phase-c §3.7](../../../../../.docs/squashing-v1.5-phase-c.md) +
/// [squashing-v1.5.md §11](../../../../../.docs/squashing-v1.5.md)): a single sweep call drains
/// a backlog of N rotated files where every one is fully promoted (zero `marf_data` rows). All
/// N get unlinked; only the active file remains. Demonstrates that
/// `sweep_unlinkable_hot_files` converges in a single call against a realistic post-promotion
/// distribution, NOT N sweep cycles.
#[test]
fn c6_sweep_drains_full_backlog_of_promoted_files_in_one_call() {
    const N_BACKLOG: usize = 30;

    let (db_path, conn) = fresh_v5_db("c6_sweep_drains_full_backlog_of_promoted_files_in_one_call");
    let stem = db_path.to_str().unwrap();
    let mut set = HotFileSet::open(stem, &conn, false, 64, false).unwrap();

    // Build N_BACKLOG rotated files. None have marf_data rows referencing them — mirrors the
    // "every block in this file got promoted to cold" steady state.
    let backlog_seqs = build_set_with_n_rotated_files(&mut set, &conn, N_BACKLOG);
    let active_seq_pre = set.active_seq();
    assert_eq!(
        count_hot_files_on_disk(&db_path),
        N_BACKLOG + 1,
        "pre-sweep: {N_BACKLOG} backlog + active file"
    );

    // Sweep with empty canonical chain + no horizon: every candidate is "all-promoted, no rows" →
    // tentative Unlinkable → empty closure → C3 unlinks each.
    let canonical: HashMap<u32, BlockHeaderHash> = HashMap::new();
    let stats = sweep_unlinkable_hot_files(
        &mut set,
        &conn,
        &canonical,
        None,
        |_: &BlockHeaderHash| -> Result<Option<u32>, Error> { Ok(None) },
        DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
    )
    .expect("sweep must not error");

    assert_eq!(
        stats.files_unlinked as usize, N_BACKLOG,
        "every backlog file must be unlinked in one sweep call"
    );
    assert_eq!(stats.rows_deleted, 0, "no rows existed → none deleted");
    assert_eq!(stats.files_blocked_by_closure, 0);
    assert_eq!(stats.files_retained_by_classifier, 0);
    assert_eq!(stats.files_deferred_for_quiesce, 0);
    assert_eq!(
        count_hot_files_on_disk(&db_path),
        1,
        "post-sweep: only active file remains"
    );
    // The active seq stayed put — the test never wrote new data to it.
    assert_eq!(set.active_seq(), active_seq_pre);
    // Verify backlog seqs are completely gone from the set.
    for s in &backlog_seqs {
        assert!(!std::path::Path::new(&hot_file_path(stem, *s)).exists());
        assert!(set.iter().all(|(seq, _)| seq != *s));
    }
}

/// **C6 acceptance test, mixed-distribution + apply-phase early-stop**: 30 rotated files where
/// the oldest 28 are reclaimable but file 29 holds a canonical row. §7.4 oldest-first ordering
/// + apply-phase early-stop means files 1..28 get unlinked AND the walk stops at file 29 — file
/// 30 stays despite being reclaimable. Final hot count: file 29, file 30, active = 3 files.
///
/// This demonstrates the bounded-convergence property in a less-trivial distribution: even with
/// a large backlog of reclaimable files and a single canonical-bearing file in the middle, the
/// hot-file count after one sweep is O(retained-canonical-files + 1).
#[test]
fn c6_sweep_drains_backlog_then_stops_at_canonical_holder() {
    const N_RECLAIMABLE_BEFORE: usize = 28;
    const N_RECLAIMABLE_AFTER: usize = 1;
    const N_TOTAL_ROTATED: usize = N_RECLAIMABLE_BEFORE + 1 + N_RECLAIMABLE_AFTER;

    let (db_path, conn) = fresh_v5_db("c6_sweep_drains_backlog_then_stops_at_canonical_holder");
    let stem = db_path.to_str().unwrap();
    let mut set = HotFileSet::open(stem, &conn, false, 64, false).unwrap();

    let seqs = build_set_with_n_rotated_files(&mut set, &conn, N_TOTAL_ROTATED);
    let canonical_holder_seq = seqs[N_RECLAIMABLE_BEFORE]; // 1-indexed-from-zero: position 28 (file 29)

    // Insert one canonical row for the holder file. This makes its tentative verdict
    // NotUnlinkable.
    let bhh_canon = bhh(7);
    // Find a valid offset/length within the holder file. Each blob is 32+4=36 bytes; offset 0 +
    // length 36 lines up.
    insert_hot_row(&conn, &bhh_canon, canonical_holder_seq, 0, 36);

    let canonical: HashMap<u32, BlockHeaderHash> = [(10, bhh_canon.clone())].into_iter().collect();
    let height_lookup = |b: &BlockHeaderHash| -> Result<Option<u32>, Error> {
        if *b == bhh_canon {
            Ok(Some(10))
        } else {
            Ok(None)
        }
    };

    let stats = sweep_unlinkable_hot_files(
        &mut set,
        &conn,
        &canonical,
        Some(20),
        height_lookup,
        DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
    )
    .expect("sweep must not error");

    assert_eq!(
        stats.files_unlinked as usize, N_RECLAIMABLE_BEFORE,
        "every reclaimable file BEFORE the canonical holder must be unlinked"
    );
    assert_eq!(
        stats.files_retained_by_classifier, 1,
        "canonical holder triggers apply-phase early-stop"
    );
    assert_eq!(stats.files_blocked_by_closure, 0);
    // File AFTER the canonical holder is reclaimable but the early-stop prevents reaching it.
    let final_count = count_hot_files_on_disk(&db_path);
    assert_eq!(
        final_count,
        N_RECLAIMABLE_AFTER + 1 + 1, // after-canonical + canonical + active
        "post-sweep hot count = retained-after + canonical-holder + active = {}",
        N_RECLAIMABLE_AFTER + 2
    );

    // Pin the EXACT boundary, not just aggregate counts (Codex 2026-05-02): every pre-holder seq
    // must be unlinked, the holder seq must remain, and every post-holder seq must remain too. A
    // bug that unlinked the wrong reclaimable file (e.g. a post-holder one) while leaving an
    // earlier reclaimable file behind would satisfy the aggregate counts above but fail here.
    for (idx, &seq) in seqs.iter().enumerate() {
        let exists = std::path::Path::new(&hot_file_path(stem, seq)).exists();
        if idx < N_RECLAIMABLE_BEFORE {
            assert!(
                !exists,
                "pre-holder seq[{idx}]={seq} must be unlinked (file at boundary not respected)"
            );
        } else {
            assert!(
                exists,
                "holder + post-holder seq[{idx}]={seq} must remain on disk (early-stop not honored)"
            );
        }
    }
}

/// **C6 acceptance test, idempotence on second sweep**: running the sweep twice in a row produces
/// no further changes on the second call. Pins the property that sweep is a fixed-point operation
/// once it has converged.
#[test]
fn c6_second_sweep_is_a_no_op_after_convergence() {
    const N: usize = 15;

    let (db_path, conn) = fresh_v5_db("c6_second_sweep_is_a_no_op_after_convergence");
    let stem = db_path.to_str().unwrap();
    let mut set = HotFileSet::open(stem, &conn, false, 64, false).unwrap();

    let _seqs = build_set_with_n_rotated_files(&mut set, &conn, N);

    let canonical: HashMap<u32, BlockHeaderHash> = HashMap::new();
    let height_lookup = |_: &BlockHeaderHash| -> Result<Option<u32>, Error> { Ok(None) };

    let stats_first = sweep_unlinkable_hot_files(
        &mut set,
        &conn,
        &canonical,
        None,
        height_lookup,
        DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
    )
    .unwrap();
    assert_eq!(stats_first.files_unlinked as usize, N);

    // Second sweep call against the same (now-converged) state.
    let stats_second = sweep_unlinkable_hot_files(
        &mut set,
        &conn,
        &canonical,
        None,
        |_: &BlockHeaderHash| -> Result<Option<u32>, Error> { Ok(None) },
        DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
    )
    .unwrap();
    assert_eq!(
        stats_second,
        SweepStats::default(),
        "converged-state second sweep must produce no observable work"
    );
    assert_eq!(count_hot_files_on_disk(&db_path), 1);
}
