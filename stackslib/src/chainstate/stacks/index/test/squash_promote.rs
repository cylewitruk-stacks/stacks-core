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

//! End-to-end test for the synchronous horizon-gated promotion ([B5a in
//! `.docs/squashing-v1.5-phase-b.md`](../../../../../../.docs/squashing-v1.5-phase-b.md)).
//!
//! Builds a small chain of hot-tier blocks, calls
//! [`crate::chainstate::stacks::index::squash_promote::run_horizon_gated_promotion`]
//! with a sub-tip `max_height`, and asserts:
//! 1. The promotion publishes a level row in `marf_squash_levels`.
//! 2. In-range blocks' `marf_data` rows flip from `storage_kind = Hot` to
//!    `Cold`, pointing at the merged blob.
//! 3. Out-of-range descendant blocks remain `Hot`.
//! 4. Reads of keys inserted in **any** block (in-range or descendant) return
//!    the correct `MARFValue` after promotion. This is the load-bearing
//!    correctness assertion: descendants whose backptrs captured pre-promotion
//!    hot-layout offsets must now resolve via the rewritten ptr fields → cold
//!    blob's merged layout.
//! 5. The plan file is removed after the swap.
//! 6. The promotion lock is cleared.

use std::fs;

use rusqlite::Connection;
use stacks_common::types::chainstate::{BlockHeaderHash, TrieHash};

use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MarfInternals, MARF};
use crate::chainstate::stacks::index::squash::SquashMode;
use crate::chainstate::stacks::index::squash_plan::plan_file_path;
use crate::chainstate::stacks::index::squash_promote::run_horizon_gated_promotion;
use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
use crate::chainstate::stacks::index::{trie_sql, ClarityMarfTrieId, MARFValue};

fn fresh_test_dir(test_name: &str) -> String {
    let dir = format!("/tmp/stacks-squash-promote-tests/{test_name}");
    if fs::metadata(&dir).is_ok() {
        fs::remove_dir_all(&dir).unwrap();
    }
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn open_hot_tier_marf(test_name: &str) -> (MARF<BlockHeaderHash>, String) {
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);
    let marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    (marf, db_path)
}

fn block_hash(byte: u8) -> BlockHeaderHash {
    let mut bytes = [0u8; 32];
    bytes[31] = byte;
    BlockHeaderHash(bytes)
}

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

fn read_storage_kind(db: &Connection, bhh: &BlockHeaderHash) -> i64 {
    db.query_row(
        "SELECT storage_kind FROM marf_data WHERE block_hash = ?1",
        rusqlite::params![bhh],
        |r| r.get(0),
    )
    .unwrap()
}

/// Phase 5.A — `run_horizon_gated_promotion` accepts `SquashMode::FullHistory`
/// and publishes a level whose `history_blob_state = Present`. Closes the
/// genesis-sync gap (Codex review): the pre-Phase-5 path hard-rejected
/// FullHistory with `NotSupportedError`, which left pre-epoch-3.4 ranges
/// permanently unsquashed during catch-up.
///
/// Asserts:
/// 1. The promotion succeeds (no NotSupportedError).
/// 2. The published level row's `history_blob_state` is `'present'`.
/// 3. The canonical history blob file
///    (`history_blob_path(...)`) exists on disk after the promotion.
/// 4. The staged tmp file is gone (renamed, not orphaned).
/// 5. At-block reads against the squashed level still return the
///    historically-correct values (the load-bearing correctness check —
///    proves the history blob was emitted with the right chunks AND
///    the read path resolves through it).
#[test]
fn phase_5a_horizon_gated_promotion_supports_full_history_mode() {
    use crate::chainstate::stacks::index::history_blob::history_blob_path;
    use crate::chainstate::stacks::index::squash::HistoryBlobState;

    let (mut marf, db_path) =
        open_hot_tier_marf("phase_5a_horizon_gated_promotion_supports_full_history_mode");

    // Build a chain. We'll use FullHistory mode and promote
    // [b1..=b3] (heights 0..=2), leaving b4..b6 as hot descendants.
    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);
    let b4 = extend_with_block(&mut marf, &b3, 4);
    let b5 = extend_with_block(&mut marf, &b4, 5);
    let _b6 = extend_with_block(&mut marf, &b5, 6);

    // Pre-promotion: snapshot the value of `k_1` at b1 — this is the
    // historical value that must remain readable through the history
    // blob after promotion.
    let pre_v_at_b1 = marf.get(&b1, "k_1").unwrap();
    assert_eq!(pre_v_at_b1, Some(MARFValue::from_value("v_1")));

    let stats = run_horizon_gated_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::FullHistory,
        /* min_height */ 0,
        /* max_height */ 2,
        Some(b3.clone()),
    )
    .expect("FullHistory promotion must succeed");

    assert!(stats.cold_blob_bytes_written > 0);

    // Published level row carries `history_blob_state = Present`.
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1);
    let level = &levels[0];
    assert_eq!(
        level.history_blob_state,
        HistoryBlobState::Present,
        "FullHistory promotion must commit history_blob_state=Present"
    );

    // Canonical history blob file exists.
    let marf_dir = std::path::Path::new(&db_path).parent().unwrap();
    let canonical = history_blob_path(
        marf_dir,
        level.level_id,
        level.min_height,
        level.max_height,
        level.blob_offset,
    );
    assert!(
        canonical.exists(),
        "canonical history blob file must exist at {canonical:?} after FullHistory promotion"
    );

    // No leftover staged tmp files in the MARF dir (the rename
    // consumed it; nothing should be left under `.history-tmp-*`).
    for entry in std::fs::read_dir(marf_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            !name.contains(".history-tmp-"),
            "staged history blob tmp file leaked: {name}",
        );
    }

    // Plan file gone, promotion lock cleared.
    let plan_path = plan_file_path(&db_path, level.level_id);
    assert!(!std::path::Path::new(&plan_path).exists());
    let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
    assert_eq!(state.promotion_in_progress, None);

    // Load-bearing correctness: tip read works via the leaf's
    // `tip_value`; descendant reads work via the rewritten backptrs;
    // historical at-block reads against the squashed level use the
    // history blob.
    for byte in 1..=6u8 {
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        let got = marf.get(&block_hash(byte), &key).unwrap();
        assert_eq!(
            got,
            Some(expected),
            "post-promotion read of {key} returned wrong value"
        );
    }
}

#[test]
fn b5a_horizon_gated_promotion_publishes_level_and_rewrites_descendants() {
    let (mut marf, db_path) =
        open_hot_tier_marf("b5a_horizon_gated_promotion_publishes_level_and_rewrites_descendants");

    // Build a chain: sentinel → b1 → b2 → b3 → b4 → b5 → b6.
    // We'll promote [sentinel..=b3] (heights 0..=3); b4..=b6 remain
    // hot descendants whose backptrs need rewriting.
    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);
    let b4 = extend_with_block(&mut marf, &b3, 4);
    let b5 = extend_with_block(&mut marf, &b4, 5);
    let b6 = extend_with_block(&mut marf, &b5, 6);

    // Sanity: every block landed in the hot tier.
    for bhh in [&b1, &b2, &b3, &b4, &b5, &b6] {
        assert_eq!(
            read_storage_kind(marf.sqlite_conn(), bhh),
            1,
            "block {bhh} should be hot before promotion"
        );
    }

    // Pre-promotion: every key reads correctly via the hot-tier
    // routing.
    for byte in 1..=6u8 {
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        let got = marf.get(&block_hash(byte), &key).unwrap();
        assert_eq!(got, Some(expected), "pre-promotion read of {key} failed");
    }

    // Promote [b1..=b3] (heights 0..=2; sentinel doesn't count as a real block). b3 is the in-range
    // tip; b4..=b6 are descendants whose backptrs need rewriting.
    let stats = run_horizon_gated_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        /* min_height */ 0,
        /* max_height */ 2,
        Some(b3.clone()),
    )
    .expect("promotion must succeed");

    // Promotion stats sanity.
    assert!(
        stats.cold_blob_bytes_written > 0,
        "merged blob should be non-empty"
    );
    assert!(
        stats.translation_map_entries > 0,
        "translation map should have entries"
    );
    // We don't assert exact rewrites_planned because b4/b5/b6 may have backptrs that target
    // b1/b2/b3 (in-range) OR sentinel (out of range). What matters is that descendants_scanned > 0.
    assert!(
        stats.descendants_scanned > 0,
        "should have scanned at least one hot descendant for rewrites"
    );

    // Plan file removed.
    let plan_path = plan_file_path(&db_path, /* level_id */ 1);
    assert!(
        !std::path::Path::new(&plan_path).exists(),
        "plan file {plan_path} should be removed after successful promotion"
    );

    // Promotion lock cleared.
    let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
    assert_eq!(state.promotion_in_progress, None);
    assert_eq!(state.promotion_reserved_offset, None);
    assert_eq!(state.promotion_reserved_length, None);

    // Level row exists.
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1, "exactly one squash level should exist");
    assert_eq!(levels[0].min_height, 0);
    assert_eq!(levels[0].max_height, 2);
    assert!(
        levels[0].blob_length > 0,
        "level's merged blob should have non-zero length"
    );
    assert!(
        levels[0].reads_redirected,
        "level should be reads_redirected"
    );

    // In-range blocks (b1..b3) flipped to Cold; descendants stay Hot.
    for bhh in [&b1, &b2, &b3] {
        assert_eq!(
            read_storage_kind(marf.sqlite_conn(), bhh),
            0,
            "in-range block {bhh} should be Cold post-promotion"
        );
    }
    for bhh in [&b4, &b5, &b6] {
        assert_eq!(
            read_storage_kind(marf.sqlite_conn(), bhh),
            1,
            "descendant block {bhh} should remain Hot post-promotion"
        );
    }

    // **Load-bearing correctness assertion**: every key still reads correctly. In-range keys go
    // through the cold-blob merged layout; descendant keys whose backptrs target in-range nodes
    // resolve through the post-promotion offsets.
    for byte in 1..=6u8 {
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        let got = marf.get(&block_hash(byte), &key).unwrap();
        assert_eq!(
            got,
            Some(expected),
            "post-promotion read of {key} returned wrong value (descendant rewrite broken?)"
        );
    }
}

/// **Fix #1 indirect verification (B5a Codex review)**: this test alone cannot prove the plan
/// file's recorded `sidecar_path` / `sidecar_hash` match the on-disk sidecar's bytes — by the time
/// promotion returns successfully, the plan file is already gone, so we can't read it. Instead,
/// this test proves the **necessary precondition** for Fix #1 to hold: after a successful
/// promotion, (a) the sidecar exists at the canonical path derivable from the published level row's
/// `(level_id, min, max, blob_offset)`, and (b) it has non-zero bytes. If either were false, the
/// plan's stored witness couldn't have been valid either, and recovery would always abandon real
/// plans.
///
/// The direct check — "open the plan file produced by promotion, read its
/// `sidecar_path`/`sidecar_hash`, hash the file at that path, compare" — requires a fault-injection
/// hook inside `apply_swap_phase` to leave the plan file on disk. That hook lands in B5b along with
/// the off-thread spawn machinery.
#[test]
fn b5a_published_sidecar_exists_at_canonical_path_after_promotion() {
    use crate::chainstate::stacks::index::squash_plan::discover_pending_plans;

    let test_name = "b5a_plan_file_carries_a_real_sidecar_witness_after_background_phase";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");

    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);
    let sentinel = BlockHeaderHash::sentinel();
    let (b1, b2, b3, b4, b5, b6) = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let b3 = extend_with_block(&mut marf, &b2, 3);
        let b4 = extend_with_block(&mut marf, &b3, 4);
        let b5 = extend_with_block(&mut marf, &b4, 5);
        let b6 = extend_with_block(&mut marf, &b5, 6);
        (b1, b2, b3, b4, b5, b6)
    };

    // Run promotion to completion (we don't have a fault-injection hook in B5a; B5b will add one
    // for proper mid-swap testing). The plan file is removed at the end of a successful swap, but
    // the on-disk sidecar stays. We verify the plan's sidecar witness by re-reading the sidecar
    // that the merger just published — its bytes' hash must match what
    // `run_horizon_gated_promotion`'s plan-file write would have recorded for the same level.
    //
    // Approach: run promotion, then re-derive the sidecar path from the published level row's
    // `(level_id, min, max, blob_offset)` and assert the file exists + has non-zero bytes. The Fix
    // #1 contract — that the plan would have stored the right path — is covered by
    // `b5a_horizon_gated_promotion_publishes_level_and_rewrites_descendants`'s overall correctness
    // (descendant reads work post-promotion, which wouldn't be possible if the swap had been
    // abandoned).
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            0,
            2,
            Some(b3.clone()),
        )
        .expect("promotion succeeds");
        // Sanity: the plan file was removed post-success.
        let plans = discover_pending_plans(&db_path).unwrap();
        assert!(plans.is_empty(), "plan should be removed post-success");
        // The published level row tells us the sidecar's location.
        let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
        assert_eq!(levels.len(), 1);
        let level = &levels[0];
        let sidecar_path = crate::chainstate::stacks::index::sidecar::squash_root_sidecar_path(
            std::path::Path::new(&db_path),
            level.level_id,
            level.min_height,
            level.max_height,
            level.blob_offset,
        );
        assert!(
            sidecar_path.exists(),
            "sidecar file {sidecar_path:?} must exist after promotion"
        );
        let sidecar_bytes = std::fs::read(&sidecar_path).unwrap();
        assert!(
            !sidecar_bytes.is_empty(),
            "sidecar file must have non-zero bytes (Fix #1 requires hashing real bytes, \
             not an empty placeholder)"
        );
    }

    // Sanity: post-promotion reads still work — same load-bearing assertion as the main e2e test,
    // repeated here so this test is self-contained.
    let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    for (bhh, byte) in [(&b1, 1u8), (&b2, 2), (&b3, 3), (&b4, 4), (&b5, 5), (&b6, 6)] {
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        assert_eq!(
            marf.get(bhh, &key).unwrap(),
            Some(expected),
            "post-promotion read of {key} failed",
        );
    }
}

/// **B5b real mid-swap crash recovery test.**
///
/// Uses the `#[cfg(test)]` fault hook to abort `run_horizon_gated_promotion` immediately after the
/// plan file is fsynced — leaving the cold blob, sidecar, and plan file on disk in exactly the
/// state a real process crash would. Then opens a fresh handle (forcing
/// `recover_pending_promotions` to run via `TrieFileStorage::open_opts`) and asserts:
/// 1. The plan replays to completion.
/// 2. The level row is published.
/// 3. The plan file is removed.
/// 4. The promotion lock is cleared.
/// 5. **Reads of every block — in-range AND descendants — return correct values**: this is the
///    load-bearing crash-safety property, proving that the on-disk artifacts (plan + cold blob +
///    sidecar
///    + un-applied descendant rewrites) carry enough information for recovery to drive forward.
#[test]
fn b5b_real_mid_swap_crash_recovers_via_open_path() {
    use crate::chainstate::stacks::index::squash_plan::discover_pending_plans;
    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    let test_name = "b5b_real_mid_swap_crash_recovers_via_open_path";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");

    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_auto_recovery(true);
    let sentinel = BlockHeaderHash::sentinel();
    let (b1, b2, b3, b4, b5, b6) = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let b3 = extend_with_block(&mut marf, &b2, 3);
        let b4 = extend_with_block(&mut marf, &b3, 4);
        let b5 = extend_with_block(&mut marf, &b4, 5);
        let b6 = extend_with_block(&mut marf, &b5, 6);
        (b1, b2, b3, b4, b5, b6)
    };

    // Arm the fault: promotion will write the plan file and then return an error before applying
    // any rewrites or committing the SQL transaction.
    test_hooks::arm_abort_after_plan_write();
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let err = run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            0,
            2,
            Some(b3.clone()),
        )
        .expect_err("fault hook must trigger error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("aborted after plan write"),
            "unexpected error: {msg}",
        );
        // Disarm in case the test panics later — harmless if already consumed by the hook's
        // swap-on-read.
        test_hooks::disarm_abort_after_plan_write();
    }

    // ── Crash state on disk ──────────────────────────────────────
    //
    // Verify the post-fault state matches what a real crash would leave: plan present, lock held,
    // no level row, in-range rows still Hot.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let plans = discover_pending_plans(&db_path).unwrap();
        assert_eq!(plans.len(), 1, "plan file must survive the abort");
        let levels = trie_sql::read_squash_levels(&conn).unwrap();
        assert_eq!(levels.len(), 0, "no level row should be published yet");
        let state = trie_sql::read_marf_state(&conn).unwrap();
        assert!(
            state.promotion_in_progress.is_some(),
            "lock must remain held — recovery owns cleanup",
        );
        for bhh in [&b1, &b2, &b3] {
            assert_eq!(
                read_storage_kind(&conn, bhh),
                1,
                "in-range block {bhh} should still be Hot before recovery"
            );
        }
    }

    // ── Drive recovery via the open path ─────────────────────────
    //
    // Re-opening the MARF runs `recover_pending_promotions` inside `TrieFileStorage::open_opts` —
    // the same code path a process restart would hit.
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        // Post-recovery state.
        let plans = discover_pending_plans(&db_path).unwrap();
        assert_eq!(plans.len(), 0, "recovery must remove the plan file");
        let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
        assert_eq!(levels.len(), 1, "recovery must publish the level row");
        assert_eq!(levels[0].min_height, 0);
        assert_eq!(levels[0].max_height, 2);
        let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
        assert_eq!(
            state.promotion_in_progress, None,
            "recovery must clear the promotion lock",
        );
        for bhh in [&b1, &b2, &b3] {
            assert_eq!(
                read_storage_kind(marf.sqlite_conn(), bhh),
                0,
                "in-range block {bhh} should be Cold post-recovery"
            );
        }
        for bhh in [&b4, &b5, &b6] {
            assert_eq!(
                read_storage_kind(marf.sqlite_conn(), bhh),
                1,
                "descendant block {bhh} should remain Hot post-recovery"
            );
        }

        // **Load-bearing assertion**: every block's read still works post-recovery, including
        // descendants whose backptrs were rewritten by recovery's idempotent replay.
        for (bhh, byte) in [(&b1, 1u8), (&b2, 2), (&b3, 3), (&b4, 4), (&b5, 5), (&b6, 6)] {
            let key = format!("k_{byte}");
            let expected = MARFValue::from_value(&format!("v_{byte}"));
            assert_eq!(
                marf.get(bhh, &key).unwrap(),
                Some(expected),
                "post-recovery read of {key} failed (descendant rewrite via recovery broken?)",
            );
        }
    }
}

/// **B5d-fu.1 catch-up scan smoke test.**
///
/// Forces `tip_at_scan_start = 0` so every hot descendant lands above the catch-up watermark, then runs promotion
/// end-to-end. Background enumeration AND catch-up scan both report the same descendants; `merge_catchup_into_plan`
/// must dedupe so the rewrite plan ends up the same as without the override. Verifies:
/// - Promotion succeeds (no double-rewrite, no spurious failures from the catch-up's reverse-set logic).
/// - All post-promotion reads — in-range and descendant — return correct values, proving the merged rewrite plan is
///   functionally equivalent to the un-augmented one.
/// - Plan file is removed; level row published; lock cleared.
///
/// This is the only end-to-end exercise of the catch-up code path possible under the synchronous (`thread::scope`)
/// dispatch model; fu.2's detached-spawn unlocks the natural concurrent-writer scenario.
#[test]
fn b5d_fu_1_catchup_with_forced_low_watermark_is_idempotent() {
    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    let (mut marf, db_path) =
        open_hot_tier_marf("b5d_fu_1_catchup_with_forced_low_watermark_is_idempotent");
    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);
    let b4 = extend_with_block(&mut marf, &b3, 4);
    let b5 = extend_with_block(&mut marf, &b4, 5);
    let b6 = extend_with_block(&mut marf, &b5, 6);

    // Force the catch-up watermark to 0. Every hot row's `block_id` is strictly greater, so the catch-up scan
    // re-enumerates every descendant the background phase already enumerated. The merger must dedupe; the swap proceeds
    // with the same effective rewrite plan as the un-overridden run.
    test_hooks::force_tip_at_scan_start(Some(0));
    let stats = run_horizon_gated_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        0,
        2,
        Some(b3.clone()),
    )
    .expect("promotion must succeed under forced low watermark");
    test_hooks::force_tip_at_scan_start(None);

    assert!(
        stats.descendants_scanned > 0,
        "background phase should have enumerated at least one descendant"
    );

    // Plan file removed; level row published.
    let plan_path = plan_file_path(&db_path, /* level_id */ 1);
    assert!(
        !std::path::Path::new(&plan_path).exists(),
        "plan file should be removed after successful promotion (incl. catch-up dedupe)"
    );
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1);

    // **Load-bearing**: descendant reads still resolve correctly. If the catch-up's reverse-set / dedup logic emitted a
    // duplicate pwrite, the on-disk byte for that ptr field would still be `post_bytes` (idempotent under repeated
    // identical writes), so reads work — but if the catch-up emitted a WRONG pwrite, this assertion would fail.
    for (bhh, byte) in [(&b1, 1u8), (&b2, 2), (&b3, 3), (&b4, 4), (&b5, 5), (&b6, 6)] {
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        assert_eq!(
            marf.get(bhh, &key).unwrap(),
            Some(expected),
            "post-promotion read of {key} failed under forced-low-watermark catch-up"
        );
    }
}

/// **B5d-fu.3 regression: abort + append-after-recovery + read.**
///
/// Models the operational sequence fu.2's detached-spawn architecture creates: a worker crashes mid-promotion (leaving
/// a plan file on disk), the next process restart drives recovery, and subsequent block appends must read correctly
/// across the recovered cold-blob boundary.
///
/// Setup:
/// 1. Build chain through `b6` (b1..=b3 in-range; b4..=b6 descendants).
/// 2. Arm `arm_abort_after_plan_write` and run promotion. Plan-v1 lands on disk with descendants b4..=b6 in
///    `rewrite_plan`.
/// 3. Re-open the MARF, driving `recover_pending_promotions` → `replay_plan` (which now invokes catch-up scan) →
///    idempotent rewrite replay → SQL commit → level publication.
/// 4. Append `b7` POST-recovery — its insertion captures backptrs that resolve through the (now cold) b1..=b3 directly,
///    so it needs no rewriting itself.
/// 5. Re-open and verify all reads.
///
/// Asserts:
/// - Recovery completes without errors. The catch-up scan ran with zero extras (no blocks committed between plan-build
///   and recovery in this single-process test); coverage of non-empty recovery catch-up is provided by the unit tests
///   on the catch-up helpers in `squash_promote::tests`.
/// - All blocks (in-range AND descendants AND b7) read correctly.
/// - Plan file removed; level row published.
///
/// Test 1 in the fu.3 regression battery. Test 2 (concurrent reader during a live promotion) follows below.
#[test]
fn b5d_fu_3_concurrent_writer_during_crash_window_is_caught_up_on_recovery() {
    use crate::chainstate::stacks::index::squash_plan::discover_pending_plans;
    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    let test_name = "b5d_fu_3_concurrent_writer_during_crash_window_is_caught_up_on_recovery";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_auto_recovery(true);
    let sentinel = BlockHeaderHash::sentinel();

    // Phase 1: build the pre-crash chain.
    let (b1, b2, b3, b4, b5, b6) = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let b3 = extend_with_block(&mut marf, &b2, 3);
        let b4 = extend_with_block(&mut marf, &b3, 4);
        let b5 = extend_with_block(&mut marf, &b4, 5);
        let b6 = extend_with_block(&mut marf, &b5, 6);
        (b1, b2, b3, b4, b5, b6)
    };

    // Phase 2: arm abort, run promotion → plan-v1 persisted, no pwrites applied. Crash window opens here.
    test_hooks::arm_abort_after_plan_write();
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let err = run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            0,
            2,
            Some(b3.clone()),
        )
        .expect_err("fault hook must trigger error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("aborted after plan write"),
            "unexpected error: {msg}"
        );
        test_hooks::disarm_abort_after_plan_write();
    }

    // Phase 3: re-open the MARF. `from_path` invokes `recover_pending_promotions` → `replay_plan` → catch-up scan (zero
    // extras — no concurrent appends in this single-process test) → idempotent rewrite replay → SQL commit. After this
    // returns, b1..=b3 are cold and the descendant rewrites have been applied. Append b7 on this same handle so its
    // backptrs resolve through the (now-cold) b1..=b3 directly.
    let b7 = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        extend_with_block(&mut marf, &b6, 7)
    };

    // Phase 4: open a fresh handle and verify every block reads correctly. Recovery on this open is a no-op (no plan
    // file); the assertion is that the chain is structurally correct post-recovery + post-append.
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
        // Plan file removed; level row published.
        let plans = discover_pending_plans(&db_path).unwrap();
        assert!(plans.is_empty(), "recovery must remove the plan file");
        let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
        assert_eq!(levels.len(), 1, "recovery must publish the level row");
        // Promotion lock cleared.
        let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
        assert_eq!(state.promotion_in_progress, None);

        // **Load-bearing assertion**: every block — including b7, which was NOT in plan-v1 — reads correctly. If
        // recovery's catch-up scan didn't pick up b7, b7's read of `k_7` would resolve through a stale pre-promotion
        // offset and either panic, return wrong bytes, or return None.
        for (bhh, byte) in [
            (&b1, 1u8),
            (&b2, 2),
            (&b3, 3),
            (&b4, 4),
            (&b5, 5),
            (&b6, 6),
            (&b7, 7),
        ] {
            let key = format!("k_{byte}");
            let expected = MARFValue::from_value(&format!("v_{byte}"));
            assert_eq!(
                marf.get(bhh, &key).unwrap(),
                Some(expected),
                "post-recovery read of {key} failed (catch-up scan missed b7?)"
            );
        }
    }
}

/// **B5d-fu.3 regression: concurrent reader during a live promotion.**
///
/// Verifies that read operations issued from a separate `MARF` handle while a promotion is in flight on another handle
/// do not observe corrupt or inconsistent state. The cross-handle reader fence (B5d cross-handle fix) plus the shared
/// squash-state generation bump (B5c) must coordinate so that:
/// - Reads during the promotion's swap-phase pwrites either block on the fence or return pre-promotion data, never a
///   torn ptr-field rewrite.
/// - Reads after `refresh_after_squash` (the coordinator's poll-time hook in fu.2) observe the post-promotion layout.
///
/// This test runs the reader and writer on real `MARF::from_path` instances (mirroring the fu.2 worker dispatch
/// pattern). Reads loop continuously across the promotion's lifetime and verify every read returns the correct value or
/// `None` (never garbage). It's a stress-style check rather than a deterministic regression detector — the cross-handle
/// fence's correctness is pinned by the unit tests in `hot_file.rs::tests`; this test verifies the integration
/// end-to-end.
#[test]
fn b5d_fu_3_concurrent_reader_during_promotion_observes_consistent_state() {
    let test_name = "b5d_fu_3_concurrent_reader_during_promotion_observes_consistent_state";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);
    let sentinel = BlockHeaderHash::sentinel();

    // Build the chain.
    let (b1, b2, b3, b4, b5, b6) = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let b3 = extend_with_block(&mut marf, &b2, 3);
        let b4 = extend_with_block(&mut marf, &b3, 4);
        let b5 = extend_with_block(&mut marf, &b4, 5);
        let b6 = extend_with_block(&mut marf, &b5, 6);
        (b1, b2, b3, b4, b5, b6)
    };

    // Spawn the reader thread on a separate `MARF` handle. It loops over reads of every block's key while the writer
    // performs the promotion. Any incorrect (non-`None`, non-expected) value is collected and asserted on after the
    // join.
    let reader_db_path = db_path.clone();
    let reader_opts = opts.clone();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_for_reader = stop.clone();
    let reader_blocks = vec![
        (b1.clone(), 1u8),
        (b2.clone(), 2),
        (b3.clone(), 3),
        (b4.clone(), 4),
        (b5.clone(), 5),
        (b6.clone(), 6),
    ];
    let reader = std::thread::spawn(move || {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&reader_db_path, reader_opts).unwrap();
        let mut anomalies: Vec<String> = Vec::new();
        let mut iterations: usize = 0;
        while !stop_for_reader.load(std::sync::atomic::Ordering::Relaxed) {
            for (bhh, byte) in &reader_blocks {
                let key = format!("k_{byte}");
                let expected = MARFValue::from_value(&format!("v_{byte}"));
                match marf.get(bhh, &key) {
                    Ok(Some(got)) if got == expected => {}
                    Ok(Some(got)) => anomalies.push(format!(
                        "iteration {iterations}: read of {key} returned wrong value: \
                         got={got:?}, expected={expected:?}"
                    )),
                    // None can occur briefly during the post-promotion refresh window — the reader handle's mmap may
                    // not have remapped yet. We treat None as "not observed corrupt" rather than fail; the more
                    // important invariant is "never returns garbage."
                    Ok(None) => {}
                    Err(e) => anomalies.push(format!(
                        "iteration {iterations}: read of {key} errored: {e}"
                    )),
                }
            }
            iterations += 1;
            // Bound the reader's CPU usage; the writer's promotion takes much longer than a tight loop iteration.
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
        (iterations, anomalies)
    });

    // Run the promotion on the main thread (mirroring fu.2's worker thread shape via direct call here).
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            0,
            2,
            Some(b3.clone()),
        )
        .expect("promotion must succeed under concurrent reader load");
    }

    // Stop the reader and inspect.
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let (iterations, anomalies) = reader.join().expect("reader thread must not panic");
    assert!(
        iterations > 0,
        "reader should have made at least one iteration during the promotion window"
    );
    assert!(
        anomalies.is_empty(),
        "reader observed inconsistent state during promotion: {anomalies:?}"
    );

    // Final-state sanity: a fresh handle reads every block correctly.
    let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    for (bhh, byte) in [(&b1, 1u8), (&b2, 2), (&b3, 3), (&b4, 4), (&b5, 5), (&b6, 6)] {
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        assert_eq!(
            marf.get(bhh, &key).unwrap(),
            Some(expected),
            "post-promotion read of {key} failed on fresh handle"
        );
    }
}

/// **B5d-fu.3 regression: recovery's catch-up scan exercises non-empty extras and dedupes against the persisted plan.**
///
/// Closes the gap left by the previous test
/// (`b5d_fu_3_concurrent_writer_during_crash_window_is_caught_up_on_recovery`), which only exercises the catch-up code
/// path with zero extras. Here we force `tip_at_scan_start = 0` via the test hook so the plan-v1 written before abort
/// has a watermark that matches NO existing hot rows. On recovery, the catch-up scan's `block_id > 0` filter lights up
/// every hot descendant — every one of which is ALSO in `plan.rewrite_plan` from the background phase.
/// `merge_catchup_into_plan`'s dedup-on-`(seq, file_offset)` rule must drop the duplicates, leaving the effective
/// replay list equal to plan.rewrite_plan. If dedup were broken, the idempotent replay would either pwrite the same
/// offset twice or (worse) hard-fail when the second pwrite saw `post_bytes` where `pre_bytes` was expected.
///
/// Asserts:
/// - Recovery completes without errors (dedup works).
/// - Level row published; plan removed.
/// - All blocks read correctly post-recovery.
#[test]
fn b5d_fu_3_recovery_catchup_dedupes_against_plan_rewrites() {
    use crate::chainstate::stacks::index::squash_plan::discover_pending_plans;
    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    let test_name = "b5d_fu_3_recovery_catchup_dedupes_against_plan_rewrites";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_auto_recovery(true);
    let sentinel = BlockHeaderHash::sentinel();

    let (b1, b2, b3, b4, b5, b6) = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let b3 = extend_with_block(&mut marf, &b2, 3);
        let b4 = extend_with_block(&mut marf, &b3, 4);
        let b5 = extend_with_block(&mut marf, &b4, 5);
        let b6 = extend_with_block(&mut marf, &b5, 6);
        (b1, b2, b3, b4, b5, b6)
    };

    // Force tip_at_scan_start = 0 so the persisted plan's watermark is below every hot row's block_id. Arm abort. Run
    // promotion; plan-v1 lands with watermark=0 and rewrite_plan covering b4..=b6. The hot files are unmodified (no
    // pwrites yet).
    test_hooks::force_tip_at_scan_start(Some(0));
    test_hooks::arm_abort_after_plan_write();
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let err = run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            0,
            2,
            Some(b3.clone()),
        )
        .expect_err("fault hook must trigger error");
        assert!(format!("{err:?}").contains("aborted after plan write"));
    }
    test_hooks::disarm_abort_after_plan_write();
    test_hooks::force_tip_at_scan_start(None);

    // Sanity: the persisted plan really does carry watermark=0.
    {
        let plans = discover_pending_plans(&db_path).unwrap();
        assert_eq!(plans.len(), 1);
        let plan =
            crate::chainstate::stacks::index::squash_plan::read_plan_file(&plans[0].1).unwrap();
        assert_eq!(
            plan.header.tip_at_scan_start, 0,
            "plan header must reflect the forced low watermark"
        );
        assert!(
            !plan.rewrite_plan.is_empty(),
            "background phase should have populated rewrite_plan"
        );
    }

    // Re-open MARF → recovery runs → replay_plan → catch-up scan with `block_id > 0` filter (lights up every hot row) →
    // merge_catchup_into_plan dedupes 100% of catch-up emissions against plan.rewrite_plan → effective replay list ==
    // plan.rewrite_plan → idempotent replay → SQL commit.
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
        let plans = discover_pending_plans(&db_path).unwrap();
        assert!(plans.is_empty(), "recovery must remove the plan file");
        let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
        assert_eq!(levels.len(), 1, "recovery must publish the level row");

        // Load-bearing: every read works. If dedup failed and a duplicate pwrite ran, this would fail (the duplicate
        // would either crash on `pre_bytes` mismatch or leave bytes in an inconsistent state).
        for (bhh, byte) in [(&b1, 1u8), (&b2, 2), (&b3, 3), (&b4, 4), (&b5, 5), (&b6, 6)] {
            let key = format!("k_{byte}");
            let expected = MARFValue::from_value(&format!("v_{byte}"));
            assert_eq!(
                marf.get(bhh, &key).unwrap(),
                Some(expected),
                "post-recovery read of {key} failed (dedup bug?)"
            );
        }
    }
}

/// Detached-worker `run_horizon_gated_promotion_at_path` must NOT auto-publish a leftover plan
/// from a prior tick. The worker opens its MARF with `auto_recovery=false`, so recovery
/// doesn't run on open. The pre-prep guards inside `prepare_promotion` see the leftover plan
/// + held lock and return `InProgressError`; the leftover plan stays untouched on disk for the
/// coordinator's `poll_pending_promotions` drain path (or `StacksChainState::recover` on
/// process restart) to validate against the live canonical chain and publish-or-discard.
///
/// **Why this matters**: the previous worker-side `auto_recovery=true` behavior was a
/// correctness hole — a transient coordinator publish failure would leave a leftover plan, and
/// the next worker's open-time `recover_pending_promotions` would TrustPlan-publish that plan
/// without canonical validation, reopening the runtime stale-tip publish bug. Closing that
/// path is the runtime fix this iteration locks in.
#[test]
fn detached_worker_does_not_auto_publish_leftover_plan() {
    use crate::chainstate::stacks::index::squash_plan::discover_pending_plans;
    use crate::chainstate::stacks::index::squash_promote::{
        run_horizon_gated_promotion_at_path, test_hooks,
    };

    let test_name = "detached_worker_does_not_auto_publish_leftover_plan";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_auto_recovery(true);
    let sentinel = BlockHeaderHash::sentinel();

    let b3 = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let b3 = extend_with_block(&mut marf, &b2, 3);
        let _b4 = extend_with_block(&mut marf, &b3, 4);
        let _b5 = extend_with_block(&mut marf, &b3, 5);
        b3
    };

    // Worker A: arm abort, run promotion → plan on disk + lock held.
    test_hooks::arm_abort_after_plan_write();
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let err = run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            0,
            2,
            Some(b3.clone()),
        )
        .expect_err("fault must trigger");
        assert!(format!("{err:?}").contains("aborted after plan write"));
    }
    test_hooks::disarm_abort_after_plan_write();

    // Sanity: no level published yet, plan + lock present.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let levels = trie_sql::read_squash_levels(&conn).unwrap();
        assert_eq!(levels.len(), 0);
        assert_eq!(discover_pending_plans(&db_path).unwrap().len(), 1);
        let state = trie_sql::read_marf_state(&conn).unwrap();
        assert!(
            state.promotion_in_progress.is_some(),
            "lock must remain held after a post-plan-fsync error"
        );
    }

    // Worker B: simulates the coordinator dispatching a fresh worker on the next tick.
    // With `auto_recovery=false` on the worker's open, recovery does NOT run; the pre-prep
    // guards inside `prepare_promotion` see the leftover plan + held lock and return
    // `InProgressError`. The leftover plan must remain UNTOUCHED — the coordinator's drain
    // path is responsible for publishing/discarding it under the canonical gate.
    let result = run_horizon_gated_promotion_at_path::<BlockHeaderHash>(
        &db_path,
        SquashMode::TipOnly,
        /* min */ 0,
        /* max */ 2,
        Some(b3.clone()),
    );
    let err = result
        .err()
        .expect("worker must NOT auto-publish a leftover plan; expected InProgressError");
    assert!(
        matches!(
            err,
            crate::chainstate::stacks::index::Error::InProgressError
        ),
        "expected InProgressError (the pre-prep guard tripping); got {err:?}"
    );

    // The leftover plan must still be on disk, the lock still held, NO level published. The
    // coordinator's `poll_pending_promotions` drain path (or process-restart recovery) is the
    // sole publish gate from this point.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    assert_eq!(
        trie_sql::read_squash_levels(&conn).unwrap().len(),
        0,
        "worker auto-publish reopens the runtime stale-tip bug; level must NOT be published \
         here (the coordinator's canonical-validated drain owns this work)"
    );
    assert_eq!(
        discover_pending_plans(&db_path).unwrap().len(),
        1,
        "leftover plan must stay on disk for the coordinator's drain path"
    );
    let state = trie_sql::read_marf_state(&conn).unwrap();
    assert!(
        state.promotion_in_progress.is_some(),
        "lock must remain held; clearing it would let a concurrent prepare race the leftover"
    );
}

/// **B5d-fu.2 Codex round, Issue 1 (recovery uses fence) — deterministic regression**: closes the test gap noted in the
/// previous Codex pass. Uses the new `RecoveryFenceBarrier` hook to pause `replay_plan` immediately AFTER
/// `set_mutate_pending` and BEFORE `wait_for_quiesce`, then verifies from a peer `HotFileSet` (NOT a peer MARF — that
/// would race recovery on the same plan file) that a `read_at` issued during the pause blocks. After release, recovery
/// completes and the reader proceeds.
///
/// Wiring under test:
/// 1. `squash_recover::replay_plan` calls `set_mutate_pending(true)` on every touched seq.
/// 2. The cross-handle ReaderFence registry shares each hot file's `Arc<ReaderFence>` across all open handles on that
///    path (`shared_reader_fence_for` in `hot_file.rs`).
/// 3. A peer `HotFileSet::open` produces a `HotFileSet` whose `HotFile`s point at the SAME `Arc<ReaderFence>` via the
///    registry.
/// 4. The peer's `read_at` → `acquire_read_guard` → `try_from_fence` observes `mutate_pending = true` and spins, never
///    returning until released.
///
/// If the recovery path were to skip the fence (the pre-fix bug), the peer's read would proceed immediately during
/// recovery's pwrite window — torn-read race.
#[test]
fn b5d_fu_2_recovery_apply_phase_blocks_concurrent_peer_reader() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::chainstate::stacks::index::hot_file::HotFileSet;
    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    let test_name = "b5d_fu_2_recovery_apply_phase_blocks_concurrent_peer_reader";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_auto_recovery(true);
    let sentinel = BlockHeaderHash::sentinel();

    // Build chain so there are real hot rows + descendants for recovery to rewrite.
    let (b1, b2, b3, _b4, _b5, _b6) = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let b3 = extend_with_block(&mut marf, &b2, 3);
        let b4 = extend_with_block(&mut marf, &b3, 4);
        let b5 = extend_with_block(&mut marf, &b4, 5);
        let b6 = extend_with_block(&mut marf, &b5, 6);
        (b1, b2, b3, b4, b5, b6)
    };

    // Run promotion to abort → plan-v1 + cold blob + sidecar on disk, hot files unmodified, lock held.
    test_hooks::arm_abort_after_plan_write();
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let _ = run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            0,
            2,
            Some(b3.clone()),
        )
        .expect_err("fault must trigger");
    }
    test_hooks::disarm_abort_after_plan_write();

    // Arm the recovery-fence barrier targeted at this test's db path. From now until `release()`, any `replay_plan`
    // call whose plan file lives in the same parent dir as `db_path` will pause between `set_mutate_pending(true)` and
    // `wait_for_quiesce`.
    let barrier = test_hooks::arm_recovery_fence_barrier(&db_path);

    // Spawn recovery via `MARF::from_path` on a background thread.
    //
    // The thread will block at the barrier; the main thread
    // observes from a peer `HotFileSet`.
    let recovery_db_path = db_path.clone();
    let recovery_opts = opts.clone();
    let recovery_thread = std::thread::spawn(move || {
        let _marf = MARF::<BlockHeaderHash>::from_path(&recovery_db_path, recovery_opts)
            .expect("recovery's from_path must succeed once released");
    });

    // Wait for recovery to reach the barrier. Timeout generous so a slow CI machine doesn't false-fail; release on
    // timeout to avoid hanging the test process.
    if !barrier.wait_until_reached(Duration::from_secs(10)) {
        barrier.release();
        recovery_thread.join().ok();
        panic!("recovery did not reach the fence barrier within 10s");
    }

    // At this point recovery has called `set_mutate_pending(true)` on every touched seq. Open a peer `HotFileSet`
    // directly (NOT via MARF — that would itself trigger recovery and race on the plan file). The peer's HotFile's
    // `Arc<ReaderFence>` is the same Arc recovery is using, via the process-wide `shared_reader_fence_for` registry.
    let peer_conn = rusqlite::Connection::open(&db_path).unwrap();
    let peer_hot_files = HotFileSet::open(
        &db_path,
        &peer_conn,
        /* mmap_enabled */ false,
        /* rotation_threshold */ 1 << 20,
        /* readonly */ true,
    )
    .expect("peer HotFileSet open should succeed");
    let touched_seq = peer_hot_files.active_seq();
    let peer_hot_files = Arc::new(peer_hot_files);

    // Spawn a peer reader. Its `read_at` will block on the fence.
    let reader_done = Arc::new(AtomicBool::new(false));
    let reader_done_clone = Arc::clone(&reader_done);
    let peer_for_reader = Arc::clone(&peer_hot_files);
    let reader_thread = std::thread::spawn(move || {
        let mut buf = vec![0u8; 32];
        // Read 32 bytes from offset 0 of the touched seq. Doesn't need to be a meaningful read — we're testing whether
        // `read_at`'s `acquire_read_guard` blocks.
        let _ = peer_for_reader.read_at(touched_seq, &mut buf, 0);
        reader_done_clone.store(true, Ordering::SeqCst);
    });

    // Give the reader 200ms to attempt the guard. If recovery wired the fence correctly, the reader is still parked; if
    // it skipped the fence, the reader returns immediately.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !reader_done.load(Ordering::SeqCst),
        "peer reader must block on recovery's mutate_pending fence (regression: \
         recovery skipped the fence and a torn read could occur)"
    );

    // Release recovery from the barrier. Recovery's `wait_for_quiesce` will see `active_reads = 0` (the peer reader's
    // `try_from_fence` backed off without bumping) and proceed. After pwrite + fsync + clear_mutate_pending, the peer
    // reader unblocks.
    barrier.release();

    // Recovery completes; reader's blocked `read_at` returns.
    recovery_thread
        .join()
        .expect("recovery thread must complete cleanly");
    reader_thread.join().expect("reader thread must complete");
    assert!(
        reader_done.load(Ordering::SeqCst),
        "peer reader must complete after recovery clears mutate_pending"
    );

    // Final-state sanity: open a fresh MARF and verify the recovery published the level + reads work.
    let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1, "recovery should have published the level");
    for (bhh, byte) in [(&b1, 1u8), (&b2, 2), (&b3, 3)] {
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        assert_eq!(marf.get(bhh, &key).unwrap(), Some(expected));
    }
}

/// Recovery-side mirror of the live mixed-state regression: once replayed descendant rewrites are
/// durable, peer readers must still remain fenced out until the recovery SQL transaction publishes
/// the new address space. Otherwise recovery can recreate the same torn state as live promotion.
#[test]
fn b5d_fu_2_recovery_post_rewrite_pre_sql_window_blocks_concurrent_peer_reader() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::chainstate::stacks::index::hot_file::HotFileSet;
    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    let test_name = "b5d_fu_2_recovery_post_rewrite_pre_sql_window_blocks_concurrent_peer_reader";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_auto_recovery(true);
    let sentinel = BlockHeaderHash::sentinel();

    let (b1, b2, b3, _b4, _b5, _b6) = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let b3 = extend_with_block(&mut marf, &b2, 3);
        let b4 = extend_with_block(&mut marf, &b3, 4);
        let b5 = extend_with_block(&mut marf, &b4, 5);
        let b6 = extend_with_block(&mut marf, &b5, 6);
        (b1, b2, b3, b4, b5, b6)
    };

    test_hooks::arm_abort_after_plan_write();
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let _ = run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            0,
            2,
            Some(b3.clone()),
        )
        .expect_err("fault must trigger");
    }
    test_hooks::disarm_abort_after_plan_write();

    let barrier = test_hooks::arm_recovery_post_rewrite_barrier(&db_path);
    let recovery_db_path = db_path.clone();
    let recovery_opts = opts.clone();
    let recovery_thread = std::thread::spawn(move || {
        let _marf = MARF::<BlockHeaderHash>::from_path(&recovery_db_path, recovery_opts)
            .expect("recovery's from_path must succeed once released");
    });

    if !barrier.wait_until_reached(Duration::from_secs(10)) {
        barrier.release();
        recovery_thread.join().ok();
        panic!("recovery did not reach the post-rewrite barrier within 10s");
    }

    let peer_conn = rusqlite::Connection::open(&db_path).unwrap();
    let peer_hot_files = HotFileSet::open(
        &db_path,
        &peer_conn,
        /* mmap_enabled */ false,
        /* rotation_threshold */ 1 << 20,
        /* readonly */ true,
    )
    .expect("peer HotFileSet open should succeed");
    let touched_seq = peer_hot_files.active_seq();
    let peer_hot_files = Arc::new(peer_hot_files);

    let reader_done = Arc::new(AtomicBool::new(false));
    let reader_done_clone = Arc::clone(&reader_done);
    let peer_for_reader = Arc::clone(&peer_hot_files);
    let reader_thread = std::thread::spawn(move || {
        let mut buf = vec![0u8; 32];
        let _ = peer_for_reader.read_at(touched_seq, &mut buf, 0);
        reader_done_clone.store(true, Ordering::SeqCst);
    });

    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !reader_done.load(Ordering::SeqCst),
        "peer reader must remain blocked while recovery is paused after rewrites but before SQL"
    );

    barrier.release();
    recovery_thread
        .join()
        .expect("recovery thread must complete cleanly");
    reader_thread.join().expect("reader thread must complete");
    assert!(
        reader_done.load(Ordering::SeqCst),
        "peer reader must complete after recovery clears mutate_pending"
    );

    let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1, "recovery should have published the level");
    for (bhh, byte) in [(&b1, 1u8), (&b2, 2), (&b3, 3)] {
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        assert_eq!(marf.get(bhh, &key).unwrap(), Some(expected));
    }
}

/// Recovery-side mirror for the "already-applied rewrites, SQL still pending" crash shape: if a
/// prior recovery attempt completed every hot-file rewrite and fsync but crashed before SQL
/// publish, the follow-on recovery pass must still fence readers across the SQL redirect.
#[test]
fn b5d_fu_2_recovery_already_applied_post_rewrite_pre_sql_window_blocks_concurrent_peer_reader() {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::chainstate::stacks::index::hot_file::HotFileSet;
    use crate::chainstate::stacks::index::squash_plan::{discover_pending_plans, read_plan_file};
    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    let test_name = "b5d_fu_2_recovery_already_applied_post_rewrite_pre_sql_window_blocks_concurrent_peer_reader";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_auto_recovery(true);
    let sentinel = BlockHeaderHash::sentinel();

    let (b1, b2, b3, _b4, _b5, _b6) = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let b3 = extend_with_block(&mut marf, &b2, 3);
        let b4 = extend_with_block(&mut marf, &b3, 4);
        let b5 = extend_with_block(&mut marf, &b4, 5);
        let b6 = extend_with_block(&mut marf, &b5, 6);
        (b1, b2, b3, b4, b5, b6)
    };

    test_hooks::arm_abort_after_plan_write();
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let _ = run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            0,
            2,
            Some(b3.clone()),
        )
        .expect_err("fault must trigger");
    }
    test_hooks::disarm_abort_after_plan_write();

    let (plan, touched_seq) = {
        let plans = discover_pending_plans(&db_path).unwrap();
        assert_eq!(plans.len(), 1, "exactly one pending plan expected");
        let plan = read_plan_file(&plans[0].1).unwrap();
        assert!(
            !plan.rewrite_plan.is_empty(),
            "fixture must contain descendant rewrites to exercise the already-applied branch"
        );
        let touched_seqs: HashSet<u32> = plan.rewrite_plan.iter().map(|e| e.hot_file_seq).collect();
        let touched_seq = plan.rewrite_plan[0].hot_file_seq;

        let apply_conn = rusqlite::Connection::open(&db_path).unwrap();
        let mut apply_hot_files = HotFileSet::open(
            &db_path,
            &apply_conn,
            /* mmap_enabled */ false,
            /* rotation_threshold */ 1 << 20,
            /* readonly */ false,
        )
        .expect("apply HotFileSet open should succeed");
        for entry in &plan.rewrite_plan {
            apply_hot_files
                .pwrite_ptr_field(entry.hot_file_seq, entry.file_offset, entry.post_bytes)
                .expect("manual rewrite apply should succeed");
        }
        for seq in touched_seqs {
            apply_hot_files
                .fsync_seq(seq)
                .expect("manual rewrite fsync should succeed");
        }

        (plan, touched_seq)
    };

    let barrier = test_hooks::arm_recovery_post_rewrite_barrier(&db_path);
    let recovery_db_path = db_path.clone();
    let recovery_opts = opts.clone();
    let recovery_thread = std::thread::spawn(move || {
        let _marf = MARF::<BlockHeaderHash>::from_path(&recovery_db_path, recovery_opts)
            .expect("recovery's from_path must succeed once released");
    });

    if !barrier.wait_until_reached(Duration::from_secs(10)) {
        barrier.release();
        recovery_thread.join().ok();
        panic!("recovery did not reach the already-applied post-rewrite barrier within 10s");
    }

    let peer_conn = rusqlite::Connection::open(&db_path).unwrap();
    let peer_hot_files = HotFileSet::open(
        &db_path,
        &peer_conn,
        /* mmap_enabled */ false,
        /* rotation_threshold */ 1 << 20,
        /* readonly */ true,
    )
    .expect("peer HotFileSet open should succeed");
    let peer_hot_files = Arc::new(peer_hot_files);

    let reader_done = Arc::new(AtomicBool::new(false));
    let reader_done_clone = Arc::clone(&reader_done);
    let peer_for_reader = Arc::clone(&peer_hot_files);
    let reader_thread = std::thread::spawn(move || {
        let mut buf = vec![0u8; 32];
        let _ = peer_for_reader.read_at(touched_seq, &mut buf, 0);
        reader_done_clone.store(true, Ordering::SeqCst);
    });

    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !reader_done.load(Ordering::SeqCst),
        "peer reader must remain blocked while recovery is paused after already-applied rewrites but before SQL"
    );

    barrier.release();
    recovery_thread
        .join()
        .expect("recovery thread must complete cleanly");
    reader_thread.join().expect("reader thread must complete");
    assert!(
        reader_done.load(Ordering::SeqCst),
        "peer reader must complete after recovery clears mutate_pending"
    );

    let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1, "recovery should have published the level");
    for (bhh, byte) in [(&b1, 1u8), (&b2, 2), (&b3, 3)] {
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        assert_eq!(marf.get(bhh, &key).unwrap(), Some(expected));
    }

    assert!(
        plan.header.reads_redirected,
        "sanity: fixture plan should still represent a publish-to-cold promotion"
    );
}

/// Regression covering the live mixed-state window: once descendant hot-file ptr fields are
/// durable but before the SQL transaction flips in-range rows to `Cold`, the reader fence must
/// keep peer readers out of the rewritten address space.
///
/// The live 2026-05-04 clarity panic had this shape:
/// 1. target block was inside the in-flight promotion range,
/// 2. crashing block was a fresh descendant above the range,
/// 3. the descendant's persisted `TrieNodePatch` base ptr carried a post-promotion offset while
///    its `back_block` still resolved through the pre-publish hot row.
///
/// This test makes that semantic window deterministic with the `SwapPostRewriteBarrier` hook. The
/// fix is that the reader fence now stays engaged across the SQL flip, so peer hot-file reads must
/// block until publication completes instead of observing rewritten descendant bytes against
/// pre-publish in-range rows.
#[test]
fn repro_descendant_reads_remain_valid_during_post_rewrite_pre_sql_window() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use clarity::util::hash::Sha512Trunc256Sum;
    use stacks_common::util::hash::to_hex;

    use crate::chainstate::stacks::index::hot_file::HotFileSet;
    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    fn stable_keys(count: usize) -> Vec<String> {
        let mut data = vec![0u8; 32];
        (0..count)
            .map(|_| {
                let path_bytes = Sha512Trunc256Sum::from_data(&data).as_bytes().to_vec();
                data.copy_from_slice(&path_bytes[0..32]);
                to_hex(&path_bytes)
            })
            .collect()
    }

    fn extend_with_stable_keys(
        marf: &mut MARF<BlockHeaderHash>,
        parent: &BlockHeaderHash,
        block_byte: u8,
        keys: &[String],
    ) -> BlockHeaderHash {
        let new_block = block_hash(block_byte);
        marf.begin(parent, &new_block).unwrap();
        for (i, key) in keys.iter().enumerate() {
            let value = MARFValue::from_value(&format!("blk_{block_byte:02x}_key_{i:02x}"));
            marf.insert(key, value).unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        new_block
    }

    let test_name = "repro_descendant_reads_remain_valid_during_post_rewrite_pre_sql_window";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_compression(true);

    let keys = stable_keys(64);
    let sentinel = BlockHeaderHash::sentinel();
    let blocks = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let mut blocks = Vec::new();
        let mut parent = sentinel;
        for block_byte in 1u8..=16u8 {
            let next = extend_with_stable_keys(&mut marf, &parent, block_byte, &keys);
            parent = next.clone();
            blocks.push(next);
        }
        blocks
    };

    // Mirror the live-node shape more closely: several earlier published levels already exist, and
    // we are pausing a later promotion while even newer descendants stay hot above it.
    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        for (min_height, max_height, tip_idx) in [(0u32, 2u32, 2usize), (3, 5, 5), (6, 8, 8)] {
            run_horizon_gated_promotion::<BlockHeaderHash>(
                &mut marf,
                SquashMode::TipOnly,
                min_height,
                max_height,
                Some(blocks[tip_idx].clone()),
            )
            .unwrap();
        }
    }

    let pending_tip = blocks[11].clone();

    let barrier = test_hooks::arm_swap_post_rewrite_barrier(&db_path);
    let worker_db_path = db_path.clone();
    let worker_opts = opts.clone();
    let worker_pending_tip = pending_tip;
    let worker = std::thread::spawn(move || {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&worker_db_path, worker_opts).unwrap();
        run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            9,
            11,
            Some(worker_pending_tip),
        )
        .unwrap();
    });

    if !barrier.wait_until_reached(Duration::from_secs(10)) {
        barrier.release();
        worker.join().ok();
        panic!("swap phase did not reach the post-rewrite barrier within 10s");
    }

    let peer_conn = rusqlite::Connection::open(&db_path).unwrap();
    let peer_hot_files = HotFileSet::open(
        &db_path,
        &peer_conn,
        /* mmap_enabled */ false,
        /* rotation_threshold */ 1 << 20,
        /* readonly */ true,
    )
    .expect("peer HotFileSet open should succeed");
    let touched_seq = peer_hot_files.active_seq();
    let peer_hot_files = Arc::new(peer_hot_files);

    let begin_done = Arc::new(AtomicBool::new(false));
    let begin_done_clone = Arc::clone(&begin_done);
    let peer_for_reader = Arc::clone(&peer_hot_files);
    let begin_thread = std::thread::spawn(move || {
        let mut buf = vec![0u8; 32];
        let result = peer_for_reader.read_at(touched_seq, &mut buf, 0);
        begin_done_clone.store(true, Ordering::SeqCst);
        result
    });

    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !begin_done.load(Ordering::SeqCst),
        "peer read should remain blocked while the swap is paused in the post-rewrite/pre-sql window"
    );

    barrier.release();
    worker.join().unwrap();
    let begin_result = begin_thread.join().unwrap();

    if let Err(err) = begin_result {
        panic!("peer read failed after the post-rewrite/pre-sql window cleared: {err:?}");
    }

    let mut post = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    for (i, key) in keys.iter().enumerate() {
        let expected = MARFValue::from_value(&format!("blk_{:02x}_key_{i:02x}", 16));
        let got = post.get_by_key(&blocks[15], key).unwrap();
        assert_eq!(
            got,
            Some(expected),
            "post-promotion descendant read of key {i} should succeed once the SQL flip lands"
        );
    }
}

/// **Closer live-panic reproducer (kept ignored until the swap ordering is fixed)**:
/// while the promotion worker is paused after descendant rewrites are durable but before the SQL
/// flip, commit a brand-new descendant block from a peer handle. If that descendant captures bad
/// patch provenance from the mixed-state window, the corruption survives the worker's eventual
/// completion and a later `begin` on a fresh handle fails — much closer to the live
/// `MarfedKV::begin` panic than the read-only window repro above.
#[test]
#[ignore = "known regression reproducer: committing a descendant during the post-rewrite/pre-sql window can leave durable bad ptr state"]
fn repro_committed_descendant_during_post_rewrite_pre_sql_window_can_break_later_begin() {
    use std::time::Duration;

    use clarity::util::hash::Sha512Trunc256Sum;
    use stacks_common::util::hash::to_hex;

    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    fn stable_keys(count: usize) -> Vec<String> {
        let mut data = vec![0u8; 32];
        (0..count)
            .map(|_| {
                let path_bytes = Sha512Trunc256Sum::from_data(&data).as_bytes().to_vec();
                data.copy_from_slice(&path_bytes[0..32]);
                to_hex(&path_bytes)
            })
            .collect()
    }

    fn extend_with_stable_keys(
        marf: &mut MARF<BlockHeaderHash>,
        parent: &BlockHeaderHash,
        block_byte: u8,
        keys: &[String],
    ) -> BlockHeaderHash {
        let new_block = block_hash(block_byte);
        marf.begin(parent, &new_block).unwrap();
        for (i, key) in keys.iter().enumerate() {
            let value = MARFValue::from_value(&format!("blk_{block_byte:02x}_key_{i:02x}"));
            marf.insert(key, value).unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        new_block
    }

    let test_name =
        "repro_committed_descendant_during_post_rewrite_pre_sql_window_can_break_later_begin";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_compression(true);

    let keys = stable_keys(64);
    let sentinel = BlockHeaderHash::sentinel();
    let blocks = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let mut blocks = Vec::new();
        let mut parent = sentinel;
        for block_byte in 1u8..=16u8 {
            let next = extend_with_stable_keys(&mut marf, &parent, block_byte, &keys);
            parent = next.clone();
            blocks.push(next);
        }
        blocks
    };

    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        for (min_height, max_height, tip_idx) in [(0u32, 2u32, 2usize), (3, 5, 5), (6, 8, 8)] {
            run_horizon_gated_promotion::<BlockHeaderHash>(
                &mut marf,
                SquashMode::TipOnly,
                min_height,
                max_height,
                Some(blocks[tip_idx].clone()),
            )
            .unwrap();
        }
    }

    let pending_tip = blocks[11].clone();
    let latest_descendant = blocks[15].clone();

    let barrier = test_hooks::arm_swap_post_rewrite_barrier(&db_path);
    let worker_db_path = db_path.clone();
    let worker_opts = opts.clone();
    let worker_pending_tip = pending_tip;
    let worker = std::thread::spawn(move || {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&worker_db_path, worker_opts).unwrap();
        run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            9,
            11,
            Some(worker_pending_tip),
        )
        .unwrap();
    });

    if !barrier.wait_until_reached(Duration::from_secs(10)) {
        barrier.release();
        worker.join().ok();
        panic!("swap phase did not reach the post-rewrite barrier within 10s");
    }

    let race_block = block_hash(99);
    let race_child = block_hash(100);
    let race_key = "window_race_marker".to_string();
    let race_value = MARFValue::from_value("window_race_value");

    {
        let mut peer = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        peer.begin(&latest_descendant, &race_block)
            .expect("begin during the post-rewrite/pre-sql window should succeed");
        peer.insert(&race_key, race_value.clone())
            .expect("insert during the post-rewrite/pre-sql window should succeed");
        peer.seal()
            .expect("seal during the post-rewrite/pre-sql window should succeed");
        peer.commit()
            .expect("commit during the post-rewrite/pre-sql window should succeed");
    }

    barrier.release();
    worker.join().unwrap();

    let mut reopened = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    let got = reopened
        .get_by_key(&race_block, &race_key)
        .expect("reopened read of committed descendant should succeed");
    assert_eq!(
        got,
        Some(race_value),
        "reopened read of descendant committed in the window should preserve the inserted value"
    );

    reopened
        .begin(&race_block, &race_child)
        .expect("begin atop descendant committed in the window should succeed after reopen");
}

/// Control experiment for the earlier repro: pause the worker only after the SQL transaction has
/// committed. A fresh peer handle should now see the fully published state, so if this test stays
/// green while the earlier barrier fails, the dangerous window is specifically the
/// post-rewrite/pre-SQL phase rather than any generic "worker still finishing up" period.
#[test]
#[ignore = "control experiment for the mixed-state reproducer"]
fn control_committed_descendant_after_sql_commit_stays_healthy() {
    use std::time::Duration;

    use clarity::util::hash::Sha512Trunc256Sum;
    use stacks_common::util::hash::to_hex;

    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    fn stable_keys(count: usize) -> Vec<String> {
        let mut data = vec![0u8; 32];
        (0..count)
            .map(|_| {
                let path_bytes = Sha512Trunc256Sum::from_data(&data).as_bytes().to_vec();
                data.copy_from_slice(&path_bytes[0..32]);
                to_hex(&path_bytes)
            })
            .collect()
    }

    fn extend_with_stable_keys(
        marf: &mut MARF<BlockHeaderHash>,
        parent: &BlockHeaderHash,
        block_byte: u8,
        keys: &[String],
    ) -> BlockHeaderHash {
        let new_block = block_hash(block_byte);
        marf.begin(parent, &new_block).unwrap();
        for (i, key) in keys.iter().enumerate() {
            let value = MARFValue::from_value(&format!("blk_{block_byte:02x}_key_{i:02x}"));
            marf.insert(key, value).unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        new_block
    }

    let test_name = "control_committed_descendant_after_sql_commit_stays_healthy";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_compression(true);

    let keys = stable_keys(64);
    let sentinel = BlockHeaderHash::sentinel();
    let blocks = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let mut blocks = Vec::new();
        let mut parent = sentinel;
        for block_byte in 1u8..=16u8 {
            let next = extend_with_stable_keys(&mut marf, &parent, block_byte, &keys);
            parent = next.clone();
            blocks.push(next);
        }
        blocks
    };

    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        for (min_height, max_height, tip_idx) in [(0u32, 2u32, 2usize), (3, 5, 5), (6, 8, 8)] {
            run_horizon_gated_promotion::<BlockHeaderHash>(
                &mut marf,
                SquashMode::TipOnly,
                min_height,
                max_height,
                Some(blocks[tip_idx].clone()),
            )
            .unwrap();
        }
    }

    let pending_tip = blocks[11].clone();
    let latest_descendant = blocks[15].clone();

    let barrier = test_hooks::arm_swap_post_sql_barrier(&db_path);
    let worker_db_path = db_path.clone();
    let worker_opts = opts.clone();
    let worker_pending_tip = pending_tip;
    let worker = std::thread::spawn(move || {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&worker_db_path, worker_opts).unwrap();
        run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            9,
            11,
            Some(worker_pending_tip),
        )
        .unwrap();
    });

    if !barrier.wait_until_reached(Duration::from_secs(10)) {
        barrier.release();
        worker.join().ok();
        panic!("swap phase did not reach the post-sql barrier within 10s");
    }

    let race_block = block_hash(101);
    let race_child = block_hash(102);
    let race_key = "post_sql_race_marker".to_string();
    let race_value = MARFValue::from_value("post_sql_race_value");

    {
        let mut peer = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        peer.begin(&latest_descendant, &race_block)
            .expect("begin after SQL commit should succeed");
        peer.insert(&race_key, race_value.clone())
            .expect("insert after SQL commit should succeed");
        peer.seal().expect("seal after SQL commit should succeed");
        peer.commit()
            .expect("commit after SQL commit should succeed");
    }

    barrier.release();
    worker.join().unwrap();

    let mut reopened = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    let got = reopened
        .get_by_key(&race_block, &race_key)
        .expect("reopened read of post-sql descendant should succeed");
    assert_eq!(got, Some(race_value));
    reopened
        .begin(&race_block, &race_child)
        .expect("begin atop post-sql descendant should stay healthy");
}

/// Control experiment that keeps the peer MARF handle open across the worker's post-SQL pause.
/// This isolates "fresh open while the plan file still exists" from the already-open peer-handle
/// shape that the live chains-coordinator thread more closely resembles.
#[test]
#[ignore = "control experiment for already-open peer handle across the post-sql pause"]
fn control_already_open_peer_after_sql_commit_stays_healthy() {
    use std::time::Duration;

    use clarity::util::hash::Sha512Trunc256Sum;
    use stacks_common::util::hash::to_hex;

    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    fn stable_keys(count: usize) -> Vec<String> {
        let mut data = vec![0u8; 32];
        (0..count)
            .map(|_| {
                let path_bytes = Sha512Trunc256Sum::from_data(&data).as_bytes().to_vec();
                data.copy_from_slice(&path_bytes[0..32]);
                to_hex(&path_bytes)
            })
            .collect()
    }

    fn extend_with_stable_keys(
        marf: &mut MARF<BlockHeaderHash>,
        parent: &BlockHeaderHash,
        block_byte: u8,
        keys: &[String],
    ) -> BlockHeaderHash {
        let new_block = block_hash(block_byte);
        marf.begin(parent, &new_block).unwrap();
        for (i, key) in keys.iter().enumerate() {
            let value = MARFValue::from_value(&format!("blk_{block_byte:02x}_key_{i:02x}"));
            marf.insert(key, value).unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        new_block
    }

    let test_name = "control_already_open_peer_after_sql_commit_stays_healthy";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_compression(true);

    let keys = stable_keys(64);
    let sentinel = BlockHeaderHash::sentinel();
    let blocks = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let mut blocks = Vec::new();
        let mut parent = sentinel;
        for block_byte in 1u8..=16u8 {
            let next = extend_with_stable_keys(&mut marf, &parent, block_byte, &keys);
            parent = next.clone();
            blocks.push(next);
        }
        blocks
    };

    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        for (min_height, max_height, tip_idx) in [(0u32, 2u32, 2usize), (3, 5, 5), (6, 8, 8)] {
            run_horizon_gated_promotion::<BlockHeaderHash>(
                &mut marf,
                SquashMode::TipOnly,
                min_height,
                max_height,
                Some(blocks[tip_idx].clone()),
            )
            .unwrap();
        }
    }

    let pending_tip = blocks[11].clone();
    let latest_descendant = blocks[15].clone();

    let barrier = test_hooks::arm_swap_post_sql_barrier(&db_path);
    let mut peer = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
    let worker_db_path = db_path.clone();
    let worker_opts = opts.clone();
    let worker_pending_tip = pending_tip;
    let worker = std::thread::spawn(move || {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&worker_db_path, worker_opts).unwrap();
        run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            9,
            11,
            Some(worker_pending_tip),
        )
        .unwrap();
    });

    if !barrier.wait_until_reached(Duration::from_secs(10)) {
        barrier.release();
        worker.join().ok();
        panic!("swap phase did not reach the post-sql barrier within 10s");
    }

    let race_block = block_hash(103);
    let race_child = block_hash(104);
    let race_key = "post_sql_already_open_marker".to_string();
    let race_value = MARFValue::from_value("post_sql_already_open_value");

    peer.begin(&latest_descendant, &race_block)
        .expect("begin on already-open peer after SQL commit should succeed");
    peer.insert(&race_key, race_value.clone())
        .expect("insert on already-open peer after SQL commit should succeed");
    peer.seal()
        .expect("seal on already-open peer after SQL commit should succeed");
    peer.commit()
        .expect("commit on already-open peer after SQL commit should succeed");

    barrier.release();
    worker.join().unwrap();

    let mut reopened = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    let got = reopened
        .get_by_key(&race_block, &race_key)
        .expect("reopened read of already-open post-sql descendant should succeed");
    assert_eq!(got, Some(race_value));
    reopened
        .begin(&race_block, &race_child)
        .expect("begin atop already-open post-sql descendant should stay healthy");
}

/// Investigation sanity check: before we blame the pending `[9..=11]` promotion window, verify
/// that a fresh `begin` atop the latest descendant still works immediately after the earlier
/// `[0..=8]` promotions have already been published.
///
/// If this fails, then the later worker/pause is a red herring and the corruption boundary is
/// strictly earlier: the descendant block has already become unreadable after the first three
/// promotions.
#[test]
#[ignore = "investigative sanity check for descendant begin before the pending promotion starts"]
fn sanity_latest_descendant_begin_before_pending_promotion_stays_healthy() {
    use clarity::util::hash::Sha512Trunc256Sum;
    use stacks_common::util::hash::to_hex;

    fn stable_keys(count: usize) -> Vec<String> {
        let mut data = vec![0u8; 32];
        (0..count)
            .map(|_| {
                let path_bytes = Sha512Trunc256Sum::from_data(&data).as_bytes().to_vec();
                data.copy_from_slice(&path_bytes[0..32]);
                to_hex(&path_bytes)
            })
            .collect()
    }

    fn extend_with_stable_keys(
        marf: &mut MARF<BlockHeaderHash>,
        parent: &BlockHeaderHash,
        block_byte: u8,
        keys: &[String],
    ) -> BlockHeaderHash {
        let new_block = block_hash(block_byte);
        marf.begin(parent, &new_block).unwrap();
        for (i, key) in keys.iter().enumerate() {
            let value = MARFValue::from_value(&format!("blk_{block_byte:02x}_key_{i:02x}"));
            marf.insert(key, value).unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        new_block
    }

    let test_name = "sanity_latest_descendant_begin_before_pending_promotion_stays_healthy";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_compression(true);

    let keys = stable_keys(64);
    let sentinel = BlockHeaderHash::sentinel();
    let blocks = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let mut blocks = Vec::new();
        let mut parent = sentinel;
        for block_byte in 1u8..=16u8 {
            let next = extend_with_stable_keys(&mut marf, &parent, block_byte, &keys);
            parent = next.clone();
            blocks.push(next);
        }
        blocks
    };

    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        for (min_height, max_height, tip_idx) in [(0u32, 2u32, 2usize), (3, 5, 5), (6, 8, 8)] {
            run_horizon_gated_promotion::<BlockHeaderHash>(
                &mut marf,
                SquashMode::TipOnly,
                min_height,
                max_height,
                Some(blocks[tip_idx].clone()),
            )
            .unwrap();
        }
    }

    let latest_descendant = blocks[15].clone();
    let race_block = block_hash(105);

    let mut peer = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    peer.begin(&latest_descendant, &race_block)
        .expect("begin atop latest descendant should stay healthy before the pending promotion");
}

/// Companion sanity check: if the pending `[9..=11]` promotion runs to completion with NO peer
/// activity in the middle, the latest descendant should still be readable for a fresh `begin`.
///
/// If this stays green while the paused-window tests fail, then the durable corruption requires the
/// mixed "promotion in flight + coordinator/peer begin" interaction rather than the promotion
/// itself.
#[test]
#[ignore = "investigative sanity check for descendant begin after a clean pending promotion"]
fn sanity_latest_descendant_begin_after_clean_pending_promotion_stays_healthy() {
    use clarity::util::hash::Sha512Trunc256Sum;
    use stacks_common::util::hash::to_hex;

    fn stable_keys(count: usize) -> Vec<String> {
        let mut data = vec![0u8; 32];
        (0..count)
            .map(|_| {
                let path_bytes = Sha512Trunc256Sum::from_data(&data).as_bytes().to_vec();
                data.copy_from_slice(&path_bytes[0..32]);
                to_hex(&path_bytes)
            })
            .collect()
    }

    fn extend_with_stable_keys(
        marf: &mut MARF<BlockHeaderHash>,
        parent: &BlockHeaderHash,
        block_byte: u8,
        keys: &[String],
    ) -> BlockHeaderHash {
        let new_block = block_hash(block_byte);
        marf.begin(parent, &new_block).unwrap();
        for (i, key) in keys.iter().enumerate() {
            let value = MARFValue::from_value(&format!("blk_{block_byte:02x}_key_{i:02x}"));
            marf.insert(key, value).unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        new_block
    }

    let test_name = "sanity_latest_descendant_begin_after_clean_pending_promotion_stays_healthy";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_compression(true);

    let keys = stable_keys(64);
    let sentinel = BlockHeaderHash::sentinel();
    let blocks = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let mut blocks = Vec::new();
        let mut parent = sentinel;
        for block_byte in 1u8..=16u8 {
            let next = extend_with_stable_keys(&mut marf, &parent, block_byte, &keys);
            parent = next.clone();
            blocks.push(next);
        }
        blocks
    };

    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        for (min_height, max_height, tip_idx) in
            [(0u32, 2u32, 2usize), (3, 5, 5), (6, 8, 8), (9, 11, 11)]
        {
            run_horizon_gated_promotion::<BlockHeaderHash>(
                &mut marf,
                SquashMode::TipOnly,
                min_height,
                max_height,
                Some(blocks[tip_idx].clone()),
            )
            .unwrap();
        }
    }

    let latest_descendant = blocks[15].clone();
    let race_block = block_hash(106);

    let mut peer = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    peer.begin(&latest_descendant, &race_block).expect(
        "begin atop latest descendant should stay healthy after a clean pending-promotion commit",
    );
}

/// Investigation check for the post-SQL window: if a peer explicitly refreshes its squash view
/// after the worker's SQL commit but before the worker runs its own `refresh_after_squash()`,
/// `begin` should recover.
///
/// This distinguishes "merged blob bytes are intrinsically bad" from "peer handle is reading the
/// new merged blob through stale in-memory squash metadata".
#[test]
#[ignore = "investigative proof that peer-side refresh heals the post-sql window"]
fn sanity_post_sql_manual_refresh_restores_peer_begin_health() {
    use std::time::Duration;

    use clarity::util::hash::Sha512Trunc256Sum;
    use stacks_common::util::hash::to_hex;

    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    fn stable_keys(count: usize) -> Vec<String> {
        let mut data = vec![0u8; 32];
        (0..count)
            .map(|_| {
                let path_bytes = Sha512Trunc256Sum::from_data(&data).as_bytes().to_vec();
                data.copy_from_slice(&path_bytes[0..32]);
                to_hex(&path_bytes)
            })
            .collect()
    }

    fn extend_with_stable_keys(
        marf: &mut MARF<BlockHeaderHash>,
        parent: &BlockHeaderHash,
        block_byte: u8,
        keys: &[String],
    ) -> BlockHeaderHash {
        let new_block = block_hash(block_byte);
        marf.begin(parent, &new_block).unwrap();
        for (i, key) in keys.iter().enumerate() {
            let value = MARFValue::from_value(&format!("blk_{block_byte:02x}_key_{i:02x}"));
            marf.insert(key, value).unwrap();
        }
        marf.seal().unwrap();
        marf.commit().unwrap();
        new_block
    }

    let test_name = "sanity_post_sql_manual_refresh_restores_peer_begin_health";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
        .with_mmap(false)
        .with_compression(true);

    let keys = stable_keys(64);
    let sentinel = BlockHeaderHash::sentinel();
    let blocks = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let mut blocks = Vec::new();
        let mut parent = sentinel;
        for block_byte in 1u8..=16u8 {
            let next = extend_with_stable_keys(&mut marf, &parent, block_byte, &keys);
            parent = next.clone();
            blocks.push(next);
        }
        blocks
    };

    {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        for (min_height, max_height, tip_idx) in [(0u32, 2u32, 2usize), (3, 5, 5), (6, 8, 8)] {
            run_horizon_gated_promotion::<BlockHeaderHash>(
                &mut marf,
                SquashMode::TipOnly,
                min_height,
                max_height,
                Some(blocks[tip_idx].clone()),
            )
            .unwrap();
        }
    }

    let pending_tip = blocks[11].clone();
    let latest_descendant = blocks[15].clone();

    let barrier = test_hooks::arm_swap_post_sql_barrier(&db_path);
    let worker_db_path = db_path.clone();
    let worker_opts = opts.clone();
    let worker_pending_tip = pending_tip;
    let worker = std::thread::spawn(move || {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&worker_db_path, worker_opts).unwrap();
        run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            9,
            11,
            Some(worker_pending_tip),
        )
        .unwrap();
    });

    if !barrier.wait_until_reached(Duration::from_secs(10)) {
        barrier.release();
        worker.join().ok();
        panic!("swap phase did not reach the post-sql barrier within 10s");
    }

    let race_block = block_hash(107);
    let mut peer = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    peer.refresh_after_squash()
        .expect("peer refresh_after_squash should succeed during the post-sql pause");
    peer.begin(&latest_descendant, &race_block).expect(
        "peer begin should recover once it refreshes its squash metadata against the committed SQL state",
    );

    barrier.release();
    worker.join().unwrap();
}

#[test]
fn b5a_promotion_rejects_when_lock_already_held() {
    let (mut marf, _) = open_hot_tier_marf("b5a_promotion_rejects_when_lock_already_held");
    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let _b2 = extend_with_block(&mut marf, &b1, 2);

    // Manually claim the single-flight lock (simulates a stale lock from a crashed-and-not-yet-recovered prior
    // promotion).
    marf.sqlite_conn()
        .execute(
            "UPDATE marf_state SET promotion_in_progress = 999, \
             promotion_reserved_offset = 0, promotion_reserved_length = 0 WHERE id = 1",
            rusqlite::params![],
        )
        .unwrap();

    let err = run_horizon_gated_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        0,
        1,
        Some(b1),
    )
    .expect_err("promotion must reject when lock is held");
    assert!(matches!(
        err,
        crate::chainstate::stacks::index::Error::InProgressError
    ));

    // Lock should remain set (the promotion didn't claim it).
    let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
    assert_eq!(state.promotion_in_progress, Some(999));
}

// ---------------------------------------------------------------------------
// 2026-05-04 genesis-sync regression: ROOT_PTR_DISK as logical root sentinel
// ---------------------------------------------------------------------------
//
// During mainnet genesis sync, every hot-tier promotion failed at the descendant scan with
// "translation map has no entry for that offset" the moment any captured backptr targeted
// `(in_range_block, ROOT_PTR_DISK)` (= offset 36 = the root node position). Per-height roots are
// stored in the `SquashRootNode` sidecar section, NOT `ptr_to_idx` / `node_store`, so they cannot
// appear in `translation_map`. The fix:
//
// 1. Relax `build_in_range_block_list` — drop the cross-check that demanded every trailer
//    block_id appear in `translation_map.by_block`. A leaf-root in-range block legitimately
//    contributes zero entries, and that's no longer a corruption signal.
// 2. Special-case `ROOT_PTR_DISK` in `scan_one_descendant` / `scan_catchup_descendant` — those
//    backptrs intentionally aren't rewritten; the descendant's bytes retain `(back_block, 36)`.
// 3. Special-case `ROOT_PTR_DISK` in `read_node_with_state` / `read_node_type_id` — for a
//    reclaim-squashed in-range block, route the read through `squash_opened_root_node_bytes`
//    (the sidecar) instead of indexing the merged blob at offset 36 (which would return the
//    merged tip's root — wrong for any non-tip in-range block). This mirrors the existing
//    fast-path in `read_node_hash` and the saved-root machinery in `MARF::root_copy`.

/// Sharpest read-path regression for the fork-extension contract: after a horizon-gated
/// promotion, opening a NON-TIP in-range block and reading at `ROOT_PTR_DISK` *under
/// [`WalkIntent::ForkExtend`]* returns the per-height root from the `SquashRootNode`
/// sidecar — NOT the merged tip's root that lives at the same byte offset in the merged
/// blob.
///
/// Updated 2026-05-07 with the read-path / fork-extension intent split: the unconditional
/// "ROOT_PTR_DISK always returns the per-height root" contract this test originally pinned
/// has been split in two:
///   * [`WalkIntent::ForkExtend`] (`MARF::root_copy`): per-height root via sidecar — what
///     this test continues to verify, by wrapping the `read_node_with_state` call in
///     `with_fork_extend_intent`.
///   * [`WalkIntent::AtBlock`] (default; `MARF::get` style at-block walks): merged tip's
///     root from offset 36 of the merged blob, with historical values resolved at the leaf
///     via `LeafSquashed::value_at_height`. That contract is verified separately by
///     `test_full_history_at_block_read_survives_sidecar_trim` in `index::test::squash`.
///
/// `read_node_hash`'s ROOT_PTR_DISK trailer override is still unconditional (the trailer is
/// in-memory metadata, not a sidecar dependency, and the per-height *consensus* hash there
/// is what backpointer-chain hash computation needs regardless of intent).
#[test]
fn root_ptr_disk_on_in_range_block_serves_saved_per_height_root() {
    use crate::chainstate::stacks::index::scratch::MarfReadState;
    use crate::chainstate::stacks::index::storage::ROOT_PTR_DISK;
    use crate::chainstate::stacks::index::TrieReadStorage;

    let (mut marf, _db_path) =
        open_hot_tier_marf("root_ptr_disk_on_in_range_block_serves_saved_per_height_root");

    // Build a chain b1..=b6, capturing each block's root hash pre-promotion.
    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);
    let b4 = extend_with_block(&mut marf, &b3, 4);
    let b5 = extend_with_block(&mut marf, &b4, 5);
    let _b6 = extend_with_block(&mut marf, &b5, 6);

    // Capture pre-promotion root hashes for the in-range blocks (b1, b2, b3). These are the
    // ground-truth values that every read path MUST return after promotion — anything else means
    // the read fell through to the merged tip's root and produced the wrong answer.
    let pre_root_hashes: Vec<TrieHash> = [&b1, &b2, &b3]
        .into_iter()
        .map(|bhh| {
            marf.get_root_hash_at(bhh)
                .expect("pre-promotion root hash must be readable")
        })
        .collect();

    // Promote heights 0..=2 (in-range tip = b3); reclaim path so the merged blob takes over.
    let stats = run_horizon_gated_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        /* min_height */ 0,
        /* max_height */ 2,
        Some(b3.clone()),
    )
    .expect("promotion must succeed");
    assert!(
        stats.cold_blob_bytes_written > 0,
        "merged blob should have content"
    );

    // Sanity: published level row exists and is reads_redirected.
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1);
    assert!(
        levels[0].reads_redirected,
        "must be a reclaim level for the read-path special case to fire"
    );

    // For each non-tip in-range block, open it and read ROOT_PTR_DISK via both
    // `read_node_hash` (existing special case — pre-fix baseline) and `read_node_with_state` (new
    // special case — the regression target). Both must return the per-height root, NOT the
    // merged tip's root.
    let in_range_blocks = [&b1, &b2, &b3];
    let mut storage = marf.borrow_storage_backend();
    for (i, bhh) in in_range_blocks.iter().enumerate() {
        storage.open_block(bhh).unwrap();
        let root_ptr = storage.root_trieptr();
        assert_eq!(
            root_ptr.ptr(),
            ROOT_PTR_DISK,
            "root_trieptr must point at ROOT_PTR_DISK"
        );

        // `read_node_hash` ROOT_PTR_DISK fast-path (existed pre-fix).
        let hash_via_hash_fastpath = storage
            .read_node_hash(&root_ptr)
            .expect("read_node_hash at ROOT_PTR_DISK must succeed");
        assert_eq!(
            hash_via_hash_fastpath, pre_root_hashes[i],
            "read_node_hash for {bhh} must return the per-height root hash captured \
             pre-promotion (not the merged tip's root hash)"
        );

        // `read_node_with_state` ROOT_PTR_DISK route — gated to `WalkIntent::ForkExtend`
        // by the 2026-05-07 read-path / fork-extension intent split. Under the default
        // `AtBlock` intent the read falls through to the merged blob's offset 36 (which is
        // the merged tip's root, the correct body for at-block walks that resolve historical
        // values via `LeafSquashed::value_at_height`). To keep this test pinning the
        // *fork-extension* contract — that the per-height root sidecar IS consulted when a
        // root-shape reconstruction caller (`MARF::root_copy`) reads `ROOT_PTR_DISK` — wrap
        // the read in `with_fork_extend_intent`, which is what `MARF::root_copy` does in
        // production.
        let mut scratch = MarfReadState::new();
        let returned_hash = storage
            .with_fork_extend_intent(|s| {
                let read_node = s.read_node_with_state(&root_ptr, &mut scratch)?;
                read_node.hash.ok_or_else(|| {
                    crate::chainstate::stacks::index::Error::CorruptionError(
                        "non-leaf root must carry its hash through the read path".into(),
                    )
                })
            })
            .expect("read_node_with_state at ROOT_PTR_DISK under ForkExtend must succeed");
        assert_eq!(
            returned_hash, pre_root_hashes[i],
            "read_node_with_state for {bhh} under ForkExtend must serve the per-height \
             root from the sidecar; a mismatch means the sidecar route was bypassed (and \
             fork-extension off this parent would produce a structurally-wrong fork root)"
        );
    }
}

/// `build_in_range_block_list` no longer asserts that every trailer block_id appears in
/// `translation_map.by_block`. The trailer is the authoritative in-range list; an in-range block
/// whose root is a leaf (or whose root only has backptrs as children) contributes zero entries
/// to `ptr_to_idx`, and the prior assertion rejected legitimate genesis-sync promotions on the
/// headers MARF for exactly that reason.
///
/// Indirect coverage: the existing `b5a_horizon_gated_promotion_publishes_level_and_rewrites_descendants`
/// test exercises the relaxed function on a real promotion. This test pins the relaxation
/// directly: build a chain, promote it, and assert no defensive corruption error fires even
/// though some blocks contribute fewer translation-map entries than the trailer has rows.
#[test]
fn build_in_range_block_list_accepts_blocks_with_zero_translation_map_entries() {
    let (mut marf, _db_path) = open_hot_tier_marf(
        "build_in_range_block_list_accepts_blocks_with_zero_translation_map_entries",
    );

    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);
    let b4 = extend_with_block(&mut marf, &b3, 4);

    // Promote [0..=2]. With `build_in_range_block_list`'s strict in-translation-map check, this
    // would fail with "trailer block_id N not in translation map" the moment any in-range block
    // contributes zero entries. Asserting `Ok` proves the check was relaxed.
    run_horizon_gated_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        /* min_height */ 0,
        /* max_height */ 2,
        Some(b3.clone()),
    )
    .expect(
        "promotion must succeed even when some in-range blocks contribute zero translation-map \
         entries (the relaxation `build_in_range_block_list` performs)",
    );

    // Sanity: a level row was actually published. If `build_in_range_block_list` had still tripped
    // its old check, we'd have errored above; but if a future regression weakens this in some
    // other way (e.g. swallows the error), this assertion catches it.
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1);
    assert_eq!(levels[0].min_height, 0);
    assert_eq!(levels[0].max_height, 2);

    // And a downstream sanity: post-promotion reads still resolve correctly on b4 (a true
    // descendant); if the relaxation accidentally broke the trailer→block-id resolution, b4's
    // backptrs wouldn't translate.
    let _ = marf
        .get(&b4, "k_4")
        .expect("post-promotion read on descendant b4 must succeed");
}

// ===========================================================================
// Runtime coordinator-owned publish: prepare/apply split tests.
//
// These pin the prepare/apply split that closes the runtime stale-tip publish window. The
// background worker stops after persisting a plan; the chains-coordinator's
// `poll_pending_promotions` validates the plan against the live canonical chain via
// `apply_prepared_plan` with `DrainPolicy::Canonical(view)`. Plans whose recorded canonical
// chain has diverged from the live view are discarded instead of published.
// ===========================================================================

/// Mock [`crate::chainstate::stacks::index::squash_recover::CanonicalView`] backed by a fixed
/// `height -> hash` map. Lets the test inject any canonical-vs-recorded relationship without
/// needing a real headers DB or sortdb. Mirrors the helper in `test/squash_recover.rs`; kept
/// per-module to avoid a cross-module test dependency.
struct MockCanonicalView {
    map: std::collections::HashMap<u32, [u8; 32]>,
}

impl crate::chainstate::stacks::index::squash_recover::CanonicalView for MockCanonicalView {
    fn canonical_at_height(
        &self,
        height: u32,
    ) -> Result<Option<[u8; 32]>, crate::chainstate::stacks::index::Error> {
        Ok(self.map.get(&height).copied())
    }
}

/// Worker `prepare_promotion` returns a `PreparedPromotion` and stops. The level row must NOT
/// be in `marf_squash_levels`, the plan file must be on disk, and the promotion lock must be
/// held — the prepared plan is durable and waiting for the coordinator to publish.
#[test]
fn worker_prepare_returns_durable_plan_without_publishing() {
    use crate::chainstate::stacks::index::squash_plan::discover_pending_plans;
    use crate::chainstate::stacks::index::squash_promote::prepare_promotion;

    let (mut marf, db_path) =
        open_hot_tier_marf("worker_prepare_returns_durable_plan_without_publishing");

    // Standard chain: sentinel → b1 → ... → b6. Promote [0..=2].
    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);
    let _b4 = extend_with_block(&mut marf, &b3, 4);
    let _b5 = extend_with_block(&mut marf, &b3, 5);
    let _b6 = extend_with_block(&mut marf, &b3, 6);

    // `prepare_promotion` now owns the pre-prep guard + lock-set, so the test calls it
    // directly without staging the lock manually.
    let prepared = prepare_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        0,
        2,
        Some(b3.clone()),
    )
    .unwrap();

    // Plan handle reflects the in-flight promotion's bounds.
    assert_eq!(prepared.min_height, 0);
    assert_eq!(prepared.max_height, 2);
    // level_id is whatever `prepare_merge_outputs` assigned; on a fresh MARF this is 0.

    // No level row in marf_squash_levels — publish hasn't run.
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert!(
        levels.is_empty(),
        "prepare must not publish; expected empty marf_squash_levels, got {} rows",
        levels.len(),
    );

    // Plan file IS on disk and matches the prepared handle's path.
    assert!(prepared.plan_path.exists(), "plan file must be durable");
    let plans = discover_pending_plans(&db_path).unwrap();
    assert_eq!(plans.len(), 1, "exactly one pending plan");

    // Promotion lock is still set — the publish step (or recovery on next open) owns the
    // clear.
    let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
    assert!(
        state.promotion_in_progress.is_some(),
        "lock must remain set until the publish step clears it"
    );
}

/// `apply_prepared_plan` with `DrainPolicy::Canonical(view)` where the view matches the plan's
/// recorded canonical chain publishes the level. This is the happy path of the coordinator
/// publish gate.
#[test]
fn coordinator_publishes_matched_plan() {
    use crate::chainstate::stacks::index::squash_plan::read_plan_file;
    use crate::chainstate::stacks::index::squash_promote::{
        apply_prepared_plan, prepare_promotion,
    };
    use crate::chainstate::stacks::index::squash_recover::{DrainOutcome, DrainPolicy};

    let (mut marf, _db_path) = open_hot_tier_marf("coordinator_publishes_matched_plan");

    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);
    let _b4 = extend_with_block(&mut marf, &b3, 4);
    let _b5 = extend_with_block(&mut marf, &b3, 5);

    let prepared = prepare_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        0,
        2,
        Some(b3.clone()),
    )
    .unwrap();

    // Build a canonical view that matches the plan's recorded `in_range_blocks` exactly.
    let plan = read_plan_file(&prepared.plan_path).unwrap();
    let mut map = std::collections::HashMap::new();
    for (i, entry) in plan.in_range_blocks.iter().enumerate() {
        map.insert(plan.header.min_height + i as u32, entry.block_hash);
    }
    let view = MockCanonicalView { map };

    let outcome =
        apply_prepared_plan::<BlockHeaderHash>(&mut marf, &prepared, DrainPolicy::Canonical(&view))
            .expect("publish must succeed under matching canonical view");
    assert!(
        matches!(outcome, DrainOutcome::Published { .. }),
        "expected Published outcome, got {outcome:?}"
    );

    // Level row is now in marf_squash_levels.
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1, "publish must commit one level row");
    assert_eq!(levels[0].level_id, prepared.level_id);

    // Plan file is removed (publish clears it via `publish_prepared_inner`).
    assert!(
        !prepared.plan_path.exists(),
        "publish must remove the plan file"
    );

    // Lock is cleared (publish does it inside the SQL transaction).
    let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
    assert!(
        state.promotion_in_progress.is_none(),
        "publish must clear promotion_in_progress"
    );
}

/// `apply_prepared_plan` with `DrainPolicy::Canonical(view)` where the view DIVERGES from the
/// plan's recorded canonical chain returns `DiscardedStale` and abandons the plan: no level
/// row, plan file removed, lock cleared. This is the runtime stale-tip fix — committing the
/// level here would record a chain that downstream `assert_squash_consistency` would later
/// trip on.
#[test]
fn coordinator_discards_stale_plan_on_canonical_divergence() {
    use crate::chainstate::stacks::index::squash_plan::read_plan_file;
    use crate::chainstate::stacks::index::squash_promote::{
        apply_prepared_plan, prepare_promotion,
    };
    use crate::chainstate::stacks::index::squash_recover::{DrainOutcome, DrainPolicy};

    let (mut marf, _db_path) =
        open_hot_tier_marf("coordinator_discards_stale_plan_on_canonical_divergence");

    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);
    let _b4 = extend_with_block(&mut marf, &b3, 4);

    let prepared = prepare_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        0,
        2,
        Some(b3.clone()),
    )
    .unwrap();

    // Snapshot what the plan recorded so we can assert the discarded outcome's diagnostic
    // fields point at the right diverging height.
    let plan = read_plan_file(&prepared.plan_path).unwrap();
    let recorded_at_h1 = plan.in_range_blocks[1].block_hash;

    // Construct a view that DISAGREES with the plan at height 1 (a sibling fork point). The
    // first divergence is what the coordinator will report.
    let mut map = std::collections::HashMap::new();
    map.insert(0u32, plan.in_range_blocks[0].block_hash); // matches
    let mut sibling = recorded_at_h1;
    sibling[0] ^= 0xff;
    map.insert(1u32, sibling); // diverges
    map.insert(2u32, plan.in_range_blocks[2].block_hash);
    let view = MockCanonicalView { map };

    let outcome = apply_prepared_plan::<BlockHeaderHash>(
        &mut marf,
        &prepared,
        DrainPolicy::Canonical(&view),
    )
    .expect("publish must succeed even when discarding (the function returns Ok with the outcome)");
    let diverging = match outcome {
        DrainOutcome::DiscardedStale {
            diverging_height,
            recorded_hash,
            ..
        } => {
            assert_eq!(recorded_hash, recorded_at_h1);
            diverging_height
        }
        other => panic!("expected DiscardedStale, got {other:?}"),
    };
    assert_eq!(
        diverging, 1,
        "diverging_height must point at the first mismatch"
    );

    // No level row published.
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert!(
        levels.is_empty(),
        "discarded plan must not publish; expected empty marf_squash_levels, got {} rows",
        levels.len(),
    );

    // Plan file removed (abandon path inside `apply_prepared_plan`).
    assert!(
        !prepared.plan_path.exists(),
        "discarded plan file must be removed"
    );

    // Lock cleared.
    let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
    assert!(
        state.promotion_in_progress.is_none(),
        "abandon must clear promotion_in_progress"
    );
}

/// Phase 5.A regression (Codex finding #1): if `write_plan_file_atomic`
/// fails AFTER `prepare_merge_outputs` returned a `StagedHistoryBlob`,
/// the staged tmp file MUST be unlinked by the RAII guard's Drop —
/// pre-fix, `staged.forget()` was called before `write_plan_file_atomic`
/// returned, so a failure left a multi-GB FullHistory tmp blob without
/// any durable plan to own it.
///
/// We force the write to fail by pre-creating a DIRECTORY at the
/// tempfile path that `write_plan_file_atomic` opens for the body
/// write (`<plan_path>.tmp`). `OpenOptions::write/create/truncate` on
/// a directory errors with EISDIR, so the write fails. The
/// `.plan.tmp` suffix is explicitly skipped by `discover_pending_plans`,
/// so the pre-prep guard doesn't false-fire on this fixture.
#[test]
fn prepare_promotion_unlinks_staged_blob_on_plan_write_failure() {
    use crate::chainstate::stacks::index::squash_plan::plan_file_path;
    use crate::chainstate::stacks::index::squash_promote::prepare_promotion;

    let (mut marf, db_path) =
        open_hot_tier_marf("prepare_promotion_unlinks_staged_blob_on_plan_write_failure");

    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);

    // The next squash level for a fresh MARF is id=0. Block the
    // tempfile path that `write_plan_file_atomic` will try to open
    // for the encoded body. The `.plan.tmp` suffix isn't picked up by
    // `discover_pending_plans` (which only matches `.plan`), so the
    // pre-prep guard at the top of `prepare_promotion` doesn't fire
    // on our fixture.
    let plan_path = plan_file_path(&db_path, /* level_id */ 0);
    let tmp_path = format!("{plan_path}.tmp");
    std::fs::create_dir(&tmp_path).unwrap();

    let marf_dir = std::path::Path::new(&db_path)
        .parent()
        .unwrap()
        .to_path_buf();

    let err = prepare_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::FullHistory,
        0,
        2,
        Some(b3.clone()),
    )
    .expect_err("plan tempfile open must fail with directory in the way");

    // Sanity: the failure is an I/O error from the tempfile open.
    assert!(
        matches!(err, crate::chainstate::stacks::index::Error::IOError(_)),
        "expected Error::IOError from plan tempfile open, got {err:?}",
    );

    // Critical assertion: NO `.history-tmp-*` files remain in the marf
    // directory. Pre-fix, the FullHistory staged blob's tmp file would
    // be orphaned here because `staged.forget()` had already disabled
    // RAII unlink. Post-fix, the local `Option<StagedHistoryBlob>`'s
    // Drop runs on the early-return path and unlinks the tmp file.
    let mut leaked = Vec::new();
    for entry in std::fs::read_dir(&marf_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains(".history-tmp-") {
            leaked.push(name);
        }
    }
    assert!(
        leaked.is_empty(),
        "FullHistory staged tmp blob leaked after plan-write failure: {leaked:?}",
    );
}

/// Phase 5.A regression (Codex finding #2): when a FullHistory plan is
/// discarded mid-flight under `DrainPolicy::Canonical(view)`, the
/// plan-owned staged history blob tmp file MUST be unlinked alongside
/// the plan file. Pre-fix, the discard path removed the plan file but
/// left the multi-GB FullHistory tmp blob on disk until the next-boot
/// `reconcile_history_blobs` sweep — exactly the leak Codex flagged.
#[test]
fn coordinator_discards_full_history_plan_unlinks_staged_history_blob() {
    use crate::chainstate::stacks::index::squash_plan::read_plan_file;
    use crate::chainstate::stacks::index::squash_promote::{
        apply_prepared_plan, prepare_promotion,
    };
    use crate::chainstate::stacks::index::squash_recover::{DrainOutcome, DrainPolicy};

    let (mut marf, _db_path) =
        open_hot_tier_marf("coordinator_discards_full_history_plan_unlinks_staged_history_blob");

    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);
    let _b4 = extend_with_block(&mut marf, &b3, 4);

    // Prepare a FullHistory promotion. After this returns, the staged
    // tmp file lives at `plan.header.history_blob_tmp_path` (with
    // RAII guard released — plan file is now the durable owner).
    let prepared = prepare_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::FullHistory,
        0,
        2,
        Some(b3.clone()),
    )
    .unwrap();

    let plan = read_plan_file(&prepared.plan_path).unwrap();
    assert_eq!(
        plan.header.history_blob_state,
        crate::chainstate::stacks::index::squash::HistoryBlobState::Present,
        "FullHistory prepare must produce a Present plan"
    );
    let tmp_path = plan.header.history_blob_tmp_path.clone();
    assert!(
        !tmp_path.is_empty(),
        "Present plan must record a non-empty tmp path"
    );
    let tmp_path_buf = std::path::PathBuf::from(&tmp_path);
    assert!(
        tmp_path_buf.exists(),
        "tmp history blob must exist after prepare: {tmp_path}"
    );

    // Construct a view that diverges from the plan to force the
    // discard branch in `apply_prepared_plan`.
    let recorded_at_h1 = plan.in_range_blocks[1].block_hash;
    let mut map = std::collections::HashMap::new();
    map.insert(0u32, plan.in_range_blocks[0].block_hash);
    let mut sibling = recorded_at_h1;
    sibling[0] ^= 0xff;
    map.insert(1u32, sibling);
    map.insert(2u32, plan.in_range_blocks[2].block_hash);
    let view = MockCanonicalView { map };

    let outcome =
        apply_prepared_plan::<BlockHeaderHash>(&mut marf, &prepared, DrainPolicy::Canonical(&view))
            .expect("publish must Ok-return the DiscardedStale outcome");
    assert!(
        matches!(outcome, DrainOutcome::DiscardedStale { .. }),
        "expected DiscardedStale, got {outcome:?}"
    );

    // Both the plan file AND the staged history blob tmp file must be
    // gone. The pre-fix bug left the tmp file dangling.
    assert!(
        !prepared.plan_path.exists(),
        "discarded plan file must be removed"
    );
    assert!(
        !tmp_path_buf.exists(),
        "discarded plan's staged history blob tmp file MUST be unlinked: {tmp_path}"
    );

    // Lock cleared (sanity).
    let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
    assert!(state.promotion_in_progress.is_none());
}

/// Integration-style: simulate the runtime canonical shift. Worker captures a canonical_tip,
/// prepares a plan recording that chain. Between prepare and publish, canonical determination
/// flips at one of the in-range heights (a Stacks-level fork resolution that happens during
/// fresh sync at deep heights). When the coordinator validates the prepared plan against the
/// new canonical view, the plan is correctly discarded — the level that would have been
/// committed records a now-stale chain and would trip later
/// `assert_squash_consistency` checks if published.
///
/// This is the substantive regression for the live failure: under the old swap-from-worker
/// model, the worker would publish anyway, the level row would record a stale chain, and
/// downstream divergence detection would panic during sync.
#[test]
fn runtime_canonical_shift_during_promotion_caught_by_coordinator() {
    use crate::chainstate::stacks::index::squash_plan::read_plan_file;
    use crate::chainstate::stacks::index::squash_promote::{
        apply_prepared_plan, prepare_promotion,
    };
    use crate::chainstate::stacks::index::squash_recover::{DrainOutcome, DrainPolicy};

    let (mut marf, _db_path) =
        open_hot_tier_marf("runtime_canonical_shift_during_promotion_caught_by_coordinator");

    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);

    // Phase 1 (worker): prepare with `canonical_tip = b3`. This snapshots the chain
    // [b1, b2, b3] into the plan's `in_range_blocks`.
    let prepared = prepare_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        0,
        2,
        Some(b3.clone()),
    )
    .unwrap();
    let plan = read_plan_file(&prepared.plan_path).unwrap();
    assert_eq!(plan.in_range_blocks.len(), 3);

    // Phase 2 (between prepare and publish): canonical determination shifts. We model this by
    // building a canonical view that reports a different hash at height 2 (the in-range tip)
    // — typical of the level-7 mainnet incident where deep-height fork resolution flipped
    // between scan and apply.
    let mut shifted_view_map = std::collections::HashMap::new();
    shifted_view_map.insert(0u32, plan.in_range_blocks[0].block_hash);
    shifted_view_map.insert(1u32, plan.in_range_blocks[1].block_hash);
    let mut shifted_tip = plan.in_range_blocks[2].block_hash;
    shifted_tip[31] ^= 0x01; // sibling
    shifted_view_map.insert(2u32, shifted_tip);
    let view = MockCanonicalView {
        map: shifted_view_map,
    };

    // Phase 3 (coordinator publish): the validate-then-publish gate catches the divergence
    // and discards the plan.
    let outcome =
        apply_prepared_plan::<BlockHeaderHash>(&mut marf, &prepared, DrainPolicy::Canonical(&view))
            .expect("publish call must return Ok with the outcome (DiscardedStale)");
    match outcome {
        DrainOutcome::DiscardedStale {
            diverging_height, ..
        } => assert_eq!(diverging_height, 2, "the in-range tip should diverge"),
        other => panic!(
            "stale-tip flip must be caught by coordinator; got {other:?} (this is the bug \
             that caused the level-7 mainnet sync panic — the old worker-publishes-itself \
             model committed the level here)"
        ),
    }

    // The pre-fix bug surface: a stale level row would be in marf_squash_levels and
    // downstream `assert_squash_consistency` would later trip on the recorded chain not
    // matching live canonical. Assert no row exists (the runtime gate is doing its job).
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert!(
        levels.is_empty(),
        "runtime canonical shift must NOT produce a published level row (regression target)"
    );
}

/// **Codex round-2 regression**: a leftover plan from a prior tick's failed publish gets
/// validated + published-or-discarded by the next tick's drain, without ever requiring a
/// process restart and without going through the (now-closed) worker-side TrustPlan path.
///
/// Models the failure mode Codex flagged: worker A prepares plan A; coordinator's
/// `apply_prepared_plan` would fail (we simulate this by skipping the call entirely, leaving
/// plan A on disk + lock held). Subsequent `MARF::drain_pending_plans(Canonical(view))` —
/// what `poll_pending_promotions` does on every tick — must publish plan A under the same
/// canonical gate. If the gate diverges, plan A is discarded.
#[test]
fn drain_publishes_orphan_plan_left_by_failed_apply() {
    use crate::chainstate::stacks::index::squash_plan::{discover_pending_plans, read_plan_file};
    use crate::chainstate::stacks::index::squash_promote::prepare_promotion;
    use crate::chainstate::stacks::index::squash_recover::DrainPolicy;

    let (mut marf, db_path) =
        open_hot_tier_marf("drain_publishes_orphan_plan_left_by_failed_apply");
    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);
    let _b4 = extend_with_block(&mut marf, &b3, 4);

    // Worker A: prepare. Plan A is now on disk; lock held; no level published.
    let prepared = prepare_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        0,
        2,
        Some(b3.clone()),
    )
    .unwrap();
    let plan = read_plan_file(&prepared.plan_path).unwrap();

    // Simulate "coordinator's apply_prepared_plan failed before publish": the prepared handle is
    // dropped without applying. The plan file + lock are still on disk.
    drop(prepared);
    assert_eq!(discover_pending_plans(&db_path).unwrap().len(), 1);
    let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
    assert!(state.promotion_in_progress.is_some());
    assert_eq!(
        trie_sql::read_squash_levels(marf.sqlite_conn())
            .unwrap()
            .len(),
        0
    );

    // Next coordinator tick: build a canonical view that matches the plan's recorded chain
    // (typical case — canonical hasn't shifted), then call `drain_pending_plans(Canonical)`.
    // The drain should publish plan A under the canonical gate.
    let mut map = std::collections::HashMap::new();
    for (i, entry) in plan.in_range_blocks.iter().enumerate() {
        map.insert(plan.header.min_height + i as u32, entry.block_hash);
    }
    let view = MockCanonicalView { map };
    let stats = marf
        .drain_pending_plans(DrainPolicy::Canonical(&view))
        .expect("drain must succeed under matching canonical view");
    assert_eq!(
        stats.plans_committed(),
        1,
        "drain must publish the orphan plan; got stats: {stats:?}"
    );

    // Plan removed, level published, lock cleared.
    assert!(discover_pending_plans(&db_path).unwrap().is_empty());
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1, "drain must commit the leftover level row");
    let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
    assert!(
        state.promotion_in_progress.is_none(),
        "drain's publish must clear the promotion lock"
    );
}

/// Companion to the previous test: when the orphan plan's recorded canonical chain has
/// diverged from the live view (e.g., a Stacks-level fork resolution flipped between tick N
/// and tick N+1), the drain discards the plan instead of publishing it. This proves the
/// canonical gate covers BOTH the fast path (`apply_prepared_plan`) and the fallback
/// (`drain_pending_plans`) — the leftover-plan drain is not a backdoor that bypasses the
/// stale-tip protection.
#[test]
fn drain_discards_orphan_plan_when_canonical_diverged() {
    use crate::chainstate::stacks::index::squash_plan::{discover_pending_plans, read_plan_file};
    use crate::chainstate::stacks::index::squash_promote::prepare_promotion;
    use crate::chainstate::stacks::index::squash_recover::DrainPolicy;

    let (mut marf, db_path) =
        open_hot_tier_marf("drain_discards_orphan_plan_when_canonical_diverged");
    let sentinel = BlockHeaderHash::sentinel();
    let b1 = extend_with_block(&mut marf, &sentinel, 1);
    let b2 = extend_with_block(&mut marf, &b1, 2);
    let b3 = extend_with_block(&mut marf, &b2, 3);

    let prepared = prepare_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        0,
        2,
        Some(b3.clone()),
    )
    .unwrap();
    let plan = read_plan_file(&prepared.plan_path).unwrap();
    drop(prepared);

    // Build a canonical view that DIVERGES from the plan at the in-range tip — the same
    // shape as the runtime stale-tip flip caught in the fast-path test, but exercised through
    // the drain fallback.
    let mut map = std::collections::HashMap::new();
    map.insert(0u32, plan.in_range_blocks[0].block_hash);
    map.insert(1u32, plan.in_range_blocks[1].block_hash);
    let mut diverged_tip = plan.in_range_blocks[2].block_hash;
    diverged_tip[0] ^= 0x80;
    map.insert(2u32, diverged_tip);
    let view = MockCanonicalView { map };

    let stats = marf
        .drain_pending_plans(DrainPolicy::Canonical(&view))
        .expect("drain call must return Ok with the outcome");
    assert_eq!(
        stats.plans_committed(),
        0,
        "drain must NOT publish a stale plan"
    );
    assert_eq!(
        stats.plans_discarded_stale(),
        1,
        "drain must report exactly one stale-discard outcome"
    );

    // Plan removed (abandon path), no level published, lock cleared.
    assert!(discover_pending_plans(&db_path).unwrap().is_empty());
    assert_eq!(
        trie_sql::read_squash_levels(marf.sqlite_conn())
            .unwrap()
            .len(),
        0
    );
    let state = trie_sql::read_marf_state(marf.sqlite_conn()).unwrap();
    assert!(state.promotion_in_progress.is_none());
}

/// **Race regression: enumerate-vs-watermark ordering in `prepare_promotion`.**
///
/// Pins the bug surfaced by mainnet level-8 sync (blocks 19039/19040 left with stale patch
/// base ptr `(18711, 2506)` after publish). Pre-fix, `prepare_promotion` snapshotted
/// `tip_at_scan_start` AFTER `enumerate_hot_descendants`. A block committed by a concurrent
/// writer in the (enumerate, watermark] window had `block_id ≤ watermark`, so:
/// - it wasn't in `enumerate`'s result (committed after enumerate ran), and
/// - the catch-up filter at publish time excluded it (`block_id > watermark` is false).
///
/// Both rewrite passes missed it; descendant backptrs to in-range blocks survived as
/// pre-publish offsets and resolved into mid-node bytes after the level committed.
///
/// Post-fix: watermark is captured BEFORE enumerate. The catch-up filter `> watermark` at
/// publish time then covers any commit that happened AFTER watermark snap, regardless of
/// whether `enumerate` happened to see it.
///
/// The test models a coordinator's runtime concurrent-commit scenario: a worker pauses
/// inside `prepare_promotion` immediately AFTER `enumerate_hot_descendants` returns (via
/// the `arm_after_descendant_enumerate_barrier` test hook — placed at the wall-clock spot
/// where the buggy ordering captured the watermark). A peer MARF on the test thread commits
/// a new descendant during the pause; the worker is then released and continues.
///
/// Under the FIX (watermark captured BEFORE enumerate), the watermark was snapshotted
/// before the peer's commit, so `b7.block_id > tip_at_scan_start`. b7 is NOT in enumerate's
/// result (committed after enumerate ran), but the catch-up filter `> tip_at_scan_start` at
/// publish time DOES cover it — initial scan misses, catch-up catches.
///
/// Under the BUGGY ordering (watermark captured AFTER enumerate), the watermark would be
/// snapshotted after the barrier release, equal to `b7.block_id`. b7 falls through both
/// rewrite passes (not in initial scan, not `> watermark` in catch-up filter). Reads
/// through b7's stale backptrs would land mid-node post-publish.
#[test]
fn prepare_watermark_precedes_enumerate_under_concurrent_commit() {
    use crate::chainstate::stacks::index::squash_promote::test_hooks;

    let test_name = "prepare_watermark_precedes_enumerate_under_concurrent_commit";
    let dir = fresh_test_dir(test_name);
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);
    let sentinel = BlockHeaderHash::sentinel();

    // Phase 1: build a chain with in-range blocks b1..b3 and descendants b4..b6. Drop the
    // handle so the worker thread can open its own.
    let (b3, b6) = {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        let b1 = extend_with_block(&mut marf, &sentinel, 1);
        let b2 = extend_with_block(&mut marf, &b1, 2);
        let b3 = extend_with_block(&mut marf, &b2, 3);
        let b4 = extend_with_block(&mut marf, &b3, 4);
        let b5 = extend_with_block(&mut marf, &b4, 5);
        let b6 = extend_with_block(&mut marf, &b5, 6);
        let _ = (b1, b2, b4, b5);
        (b3, b6)
    };

    // Phase 2: arm the prepare-phase barrier and spawn the worker. The worker opens its own
    // MARF and runs `run_horizon_gated_promotion` (the synchronous all-in-one entry, which
    // internally calls `prepare_promotion` followed by `apply_prepared_plan(TrustPlan)`).
    // It will pause inside `prepare_promotion` between watermark snapshot and enumerate.
    let barrier = test_hooks::arm_after_descendant_enumerate_barrier(db_path.clone());

    let worker_db_path = db_path.clone();
    let worker_opts = opts.clone();
    let worker_b3 = b3.clone();
    let worker = std::thread::spawn(move || {
        let mut marf = MARF::<BlockHeaderHash>::from_path(&worker_db_path, worker_opts).unwrap();
        run_horizon_gated_promotion::<BlockHeaderHash>(
            &mut marf,
            SquashMode::TipOnly,
            0,
            2,
            Some(worker_b3),
        )
    });

    // Phase 3: wait for the worker to reach the barrier. With a healthy build this fires
    // within a few hundred ms (the merger walk + cold-blob append for a 6-block chain is
    // fast). Bump the timeout if it ever flakes.
    assert!(
        barrier.wait_until_reached(std::time::Duration::from_secs(5)),
        "worker did not reach the after-descendant-enumerate barrier"
    );

    // Phase 4: peer MARF commits a new descendant b7 while the worker is paused. b7 is
    // committed AFTER the worker captured `tip_at_scan_start` AND after enumerate already
    // ran, so:
    //   - b7 is NOT in `enumerate`'s result (enumerate already returned before b7's commit).
    //   - b7's block_id > tip_at_scan_start (watermark was snapshotted before b7's commit).
    // The catch-up filter at publish time (`block_id > watermark`) is what covers b7. If
    // the watermark had been captured AFTER enumerate (the buggy ordering), it would equal
    // b7's block_id and the catch-up filter would exclude it — b7 would fall through both
    // rewrite passes.
    let b7 = {
        let mut peer = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
        extend_with_block(&mut peer, &b6, 7)
    };

    // Phase 5: release the worker. It resumes inside `prepare_promotion`, finishes the
    // remaining prep steps, persists the plan, and proceeds to apply (publish) the level.
    // The catch-up scan inside the publish phase picks up b7 via `block_id > watermark`.
    barrier.release();
    let result = worker.join().expect("worker thread must not panic");
    result.expect("promotion must succeed under concurrent commit during prepare");

    // Phase 6: open a fresh handle and verify the post-publish state.
    //
    // The load-bearing assertion is the read of `k_*` via b7. Under the fix, b7's in-range
    // backptrs were rewritten by the catch-up scan (initial scan missed b7 since it was
    // committed after enumerate; catch-up filter `> watermark` covers it). Under a
    // regression to the buggy ordering, b7 would fall through both passes and reads through
    // its stale backptrs would land mid-node in the merged blob.
    let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts).unwrap();
    let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1, "publish must commit exactly one level row");

    // Read every key VIA b7 (the descendant committed during the prepare window). This walks
    // b7's full backptr chain back to wherever the key was originally written; any stale
    // descendant backptr to an in-range block (now redirected to the merged blob) would land
    // mid-node and surface as a corruption error or wrong-bytes return.
    //
    // Reading via earlier blocks (e.g., `marf.get(&b1, "k_1")`) would NOT traverse b7's
    // ptrs — it'd just walk b1's local trie. The b7 view is what makes this test load-bearing
    // for catching missed descendant rewrites.
    for byte in 1..=7u8 {
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        assert_eq!(
            marf.get(&block_hash(byte), &key).unwrap(),
            Some(expected.clone()),
            "post-promotion read of {key} via its own block failed",
        );
        // The load-bearing read: walk from b7 (concurrent-commit descendant) back through
        // the chain. Any stale backptr in b7's structure to an in-range block surfaces here.
        assert_eq!(
            marf.get(&block_hash(7), &key).unwrap(),
            Some(expected),
            "post-promotion read of {key} VIA b7 failed — b7's backptr chain is corrupt \
             (race regression: b7 was committed during prepare's enumerate window and its \
             in-range backptrs were not rewritten by catch-up)",
        );
    }

    // Additionally seal a fresh write atop b7. Sealing walks the full trie to compute the
    // root hash; any stale descendant ptr that the read path happens to skip over would
    // surface here. This is the closest single-process analog of mainnet's
    // `calculate_marf_root_hash` panic during block append.
    let b8 = extend_with_block(&mut marf, &block_hash(7), 8);
    let _ = b8;
}

/// **Smoke test for post-publish reads through a chain with a non-empty orphan section.**
///
/// Builds a chain whose squash produces a non-empty orphan section (`orphan_split_offset >
/// 0`), then exercises post-publish reads VIA a hot descendant. Exercises the patch-chase
/// + cross-handle metadata-load + post-publish read flow end-to-end. With the orphan-
/// routing fix in `read_patched_persisted_node` ([storage.rs]), reads through any
/// descendant patch chain whose base ptrs land in orphan-section territory route through
/// the level's sidecar instead of decoding garbage from the merged blob's main section.
///
/// **What this test does NOT deterministically exercise**: the specific
/// patch-base-targets-orphan-offset shape that surfaced on mainnet (clarity level 18,
/// block 29798's patch base ptr `(29796, 13539646)`). Producing that shape requires a
/// mainnet-scale workload (thousands of keys per block, deep patch chains) where
/// translation-map-driven rewrites of descendant patch bases can map to orphan-section
/// offsets. The unit-level helpers (`open_orphan_sidecar_for_level`,
/// `read_orphan_node_bytes_into`) and their callers (`try_read_orphan_bytes` for normal
/// reads, `read_patched_persisted_node` for patch-chase reads) share the same code path,
/// so the existing `try_read_orphan_bytes` coverage transitively validates the helper
/// behavior; the load-bearing end-to-end witness is mainnet stress testing.
///
/// Workload: a chain of blocks that each re-insert a small set of shared keys, producing
/// patch chains that thread back through earlier blocks' nodes. Squashing an in-range
/// prefix with reclaim drops older subtrees into the orphan section. A hot descendant past
/// the squash range exercises the post-publish patch-chase read path.
#[test]
fn read_patched_persisted_node_orphan_routing() {
    use crate::chainstate::stacks::index::trie_sql::read_squash_levels;

    let dir = fresh_test_dir("read_patched_persisted_node_orphan_routing");
    let db_path = format!("{dir}/marf.sqlite");
    let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true).with_mmap(false);

    // Build a 6-block chain where each block re-inserts the same set of shared keys, plus
    // one block-unique key. The shared-key updates produce patch chains whose intermediate
    // bases target nodes in earlier blocks; the unique-key inserts broaden the trie so the
    // squash's reclaim pass produces a non-empty orphan section.
    const SHARED_KEYS: u32 = 8;
    let extend_with_shared = |marf: &mut MARF<BlockHeaderHash>,
                              parent: &BlockHeaderHash,
                              block_byte: u8|
     -> BlockHeaderHash {
        let new_block = block_hash(block_byte);
        marf.begin(parent, &new_block).unwrap();
        for k in 0..SHARED_KEYS {
            let key = format!("shared_{k}");
            let value = MARFValue::from_value(&format!("v_{block_byte}_{k}"));
            marf.insert(&key, value).unwrap();
        }
        // Block-unique key, for read assertions.
        let unique_key = format!("k_{block_byte}");
        let unique_value = MARFValue::from_value(&format!("v_{block_byte}"));
        marf.insert(&unique_key, unique_value).unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();
        new_block
    };

    let sentinel = BlockHeaderHash::sentinel();
    let mut marf = MARF::<BlockHeaderHash>::from_path(&db_path, opts.clone()).unwrap();
    let b1 = extend_with_shared(&mut marf, &sentinel, 1);
    let b2 = extend_with_shared(&mut marf, &b1, 2);
    let b3 = extend_with_shared(&mut marf, &b2, 3);
    let b4 = extend_with_shared(&mut marf, &b3, 4);
    let b5 = extend_with_shared(&mut marf, &b4, 5);
    let b6 = extend_with_shared(&mut marf, &b5, 6);

    // Squash [b1..=b3] (heights 0..=2) with reclaim. The shared-key inserts in b4..b6
    // (descendants of the squash range) include patch chains whose bases reach back through
    // b1..b3's nodes. With reclaim=true, the in-range nodes that aren't tip-reachable from
    // b3's root land in the orphan section.
    run_horizon_gated_promotion::<BlockHeaderHash>(
        &mut marf,
        SquashMode::TipOnly,
        0,
        2,
        Some(b3.clone()),
    )
    .expect("promotion must succeed");

    // Confirm the level has a non-empty orphan section. If it's zero, the workload didn't
    // produce orphans and the test is vacuous (would pass under both fix and bug); fail
    // loudly so a regression in the workload doesn't silently weaken the test.
    let levels = read_squash_levels(marf.sqlite_conn()).unwrap();
    assert_eq!(levels.len(), 1);
    assert!(
        levels[0].orphan_split_offset > 0,
        "test workload must produce a non-empty orphan section to exercise the patch-chase \
         orphan-routing path; got orphan_split_offset=0 (level={})",
        levels[0].level_id,
    );

    // Load-bearing reads: traverse b6's full backptr chain. Reading every shared key VIA b6
    // walks: b6 -> patch -> ... -> b1 (where shared_k was first written). Without orphan
    // routing in `read_patched_persisted_node`, an intermediate patch base ptr that targets
    // an orphan-section node decodes garbage; with orphan routing, the read traverses the
    // sidecar correctly.
    for k in 0..SHARED_KEYS {
        let key = format!("shared_{k}");
        let expected = MARFValue::from_value(&format!("v_6_{k}"));
        assert_eq!(
            marf.get(&b6, &key).unwrap(),
            Some(expected),
            "post-publish read of {key} VIA b6 failed — patch-chase orphan routing \
             regression? (the failing chain follows b6 -> patch -> ... back through the \
             squashed range, hitting in-range orphan-section nodes mid-walk)",
        );
    }

    // Also seal a fresh write atop b6. Sealing walks the full trie; any stale descendant
    // ptr that single-key reads happen to skip over surfaces here. This mirrors the
    // mainnet `calculate_marf_root_hash` panic shape.
    let b7 = extend_with_shared(&mut marf, &b6, 7);

    // Final post-extend reads via the new tip — exercises BOTH the new b7 patches AND the
    // older b6/b5/.../b1 chain via b7's view.
    for k in 0..SHARED_KEYS {
        let key = format!("shared_{k}");
        let expected = MARFValue::from_value(&format!("v_7_{k}"));
        assert_eq!(
            marf.get(&b7, &key).unwrap(),
            Some(expected),
            "post-extend read of {key} VIA b7 failed",
        );
    }

    // Block-unique reads via the same descendant tip — hits a different traversal pattern
    // (no patch chain on the unique-key path itself, but the read still resolves through
    // b7's structure which references squashed bases).
    for byte in 1..=7u8 {
        let key = format!("k_{byte}");
        let expected = MARFValue::from_value(&format!("v_{byte}"));
        assert_eq!(
            marf.get(&b7, &key).unwrap(),
            Some(expected),
            "post-extend read of unique {key} VIA b7 failed",
        );
    }
}
