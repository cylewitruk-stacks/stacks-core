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

//! Recovery state machine for Phase B horizon-gated promotion.
//!
//! On every read-write MARF open, [`recover_pending_promotions`] runs before the cold-blob mmap is
//! created. It scans for `<db>.squash_pending.*.plan` files left behind by a crashed promotion and
//! drives each one to a consistent terminal state (committed or abandoned). After all plans are
//! resolved, it truncates the cold blob's uncommitted tail.
//!
//! See `.docs/squashing-v1.5-phase-b.md` §7 for the design.
//!
//! # Crash-point matrix
//!
//! Each branch below is exercised by an integration test in `test/squash_recover.rs`:
//!
//! | Crash point                                     | Step that handles it                       |
//! | ----------------------------------------------- | ------------------------------------------ |
//! | Before plan fsync                               | Step 1: no plan on disk; nothing to do     |
//! | After plan fsync, before cold-blob fsync        | Step 3: cold-blob hash mismatch → abandon  |
//! | After cold-blob fsync, before any swap step     | Step 4: replay from `pre_bytes`            |
//! | Mid-rewrite                                     | Step 4: per-entry idempotent skip + apply  |
//! | Mid-SQL                                         | SQLite rolls back; step 5 retries          |
//! | After SQL commit, before plan-file unlink       | Step 4 sees `post_bytes`, step 5 idempotent|
//!
//! # Readonly handles
//!
//! Recovery **must not** run on a readonly handle (per design doc §7.3). A readonly open with
//! pending plans returns [`Error::CorruptionError`] pointing the operator at the RW open path.
//! Silent-ignore would let a hybrid mid-swap state (some hot ptrs already rewritten, SQL still
//! routing as hot) appear to a reader as valid-looking but wrong bytes.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
#[cfg(test)]
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::chainstate::stacks::index::hot_file::HotFileSet;
use crate::chainstate::stacks::index::squash_plan::{
    discover_pending_plans, read_plan_file, sha512_256_of, RewriteEntry, SquashPlan,
};
use crate::chainstate::stacks::index::{trie_sql, Error, MarfTrieId};

/// Counters reported by a recovery pass. Exposed for diagnostics + tests; production code logs
/// them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryStats {
    /// Number of plan files found on disk.
    pub plans_discovered: usize,
    /// Number of plans that committed successfully (cold-blob region validated and replay
    /// completed).
    pub plans_committed: usize,
    /// Number of plans abandoned because their cold-blob region or sidecar didn't match the
    /// recorded hash. The plan file is removed and `marf_state.promotion_in_progress` is cleared.
    pub plans_abandoned: usize,
    /// Total rewrite entries applied via `pwrite` (does not include entries that were already in
    /// the post-state when recovery looked at them).
    pub rewrites_applied: usize,
    /// Total rewrite entries that were already in the post-state and got skipped (idempotent
    /// replay).
    pub rewrites_skipped: usize,
    /// Bytes truncated from the cold blob's uncommitted tail.
    pub cold_tail_truncated_bytes: u64,
}

/// Recover any pending promotions for the MARF at `db_path`.
///
/// Returns a [`RecoveryStats`] summary on success. Returns an error if recovery cannot complete
/// (corrupt plan file, unparseable rewrite witness, etc.) — the caller should propagate the error
/// and refuse to open the MARF.
///
/// **Readonly handles**: pass `readonly = true` and recovery will fail hard (per design doc §7.3)
/// if any plan files are present, instead of silently ignoring them.
///
/// **Caller responsibility**: this function operates on raw `File` handles for the cold blob,
/// **not** on the [`crate::chainstate::stacks::index::file::TrieFile`] abstraction. After recovery
/// commits or abandons plans, callers using mmap-backed cold-blob access must refresh their mmap
/// (the cold blob may have been truncated). Phase B's open path wiring runs recovery before the
/// TrieFile mmap is created so the refresh is implicit.
pub fn recover_pending_promotions<T: MarfTrieId>(
    db: &mut Connection,
    db_path: &str,
    hot_files: &mut HotFileSet,
    readonly: bool,
) -> Result<RecoveryStats, Error> {
    let mut stats = RecoveryStats::default();

    // ── Step 1: discover pending plans ────────────────────────────
    let plans = discover_pending_plans(db_path)?;
    stats.plans_discovered = plans.len();

    if plans.is_empty() {
        // Common case: no promotion was in flight on the prior shutdown.
        //
        // **Stale-lock recovery**: if `marf_state.promotion_in_progress` is set but no plan file
        // exists on disk, the prior process crashed in the narrow window between
        // `set_promotion_in_progress` and the plan-file fsync. Without an explicit clear here, the
        // MARF would stay permanently single-flight-locked because every subsequent cadence tick
        // would see the in-progress flag with no plan file to drive forward. Skipped on readonly
        // handles (which must not mutate any state).
        if !readonly {
            let state = trie_sql::read_marf_state(db)?;
            if state.promotion_in_progress.is_some() {
                info!(
                    "Phase B promotion recovery: clearing stale promotion lock \
                     (level_id={:?}, no plan file present — pre-fsync crash)",
                    state.promotion_in_progress
                );
                trie_sql::clear_promotion_state(db)?;
            }
        }
        // Even with no plans, we still run the cold-tail truncation step to clip any torn cold-blob
        // append from a non-promotion crash (e.g. the prior process exited mid-way through the
        // legacy synchronous squash path).
        stats.cold_tail_truncated_bytes = truncate_cold_tail(db, db_path, readonly)?;
        return Ok(stats);
    }

    // Readonly fail-hard. The mid-swap crash window can leave hot files partially rewritten with
    // merged-blob offsets while SQL still routes the in-range blocks as hot. A readonly handle that
    // proceeds anyway would read this hybrid state and serve wrong bytes. The caller (writer) must
    // complete recovery first.
    if readonly {
        // `plans` is guaranteed non-empty here (we returned early above when `plans.is_empty()`);
        // `.first()` instead of `[0]` avoids the indexing-slicing lint.
        let example = plans
            .first()
            .map(|(_, p)| p.clone())
            .unwrap_or_else(|| PathBuf::from("<unknown>"));
        return Err(Error::CorruptionError(format!(
            "readonly open: pending squash promotion plan {example:?} requires a writable open \
             to recover. Re-open the MARF read-write, complete recovery, then retry the readonly \
             open. ({} pending plan(s) total)",
            plans.len(),
        )));
    }

    // ── Step 2: process each plan in level_id order ───────────────
    let cold_blob_path = derive_cold_blob_path(db_path);
    for (level_id, plan_path) in plans {
        match recover_one_plan::<T>(db, &plan_path, &cold_blob_path, hot_files, &mut stats) {
            Ok(()) => {
                debug!("Recovered pending promotion plan: level_id={level_id}");
            }
            Err(e) => {
                // recover_one_plan distinguishes "abandon" (returns Ok with stats updated) from
                // "fail open" (returns Err here). Anything we get here is a hard failure; surface
                // it so the caller refuses to open.
                return Err(e);
            }
        }
    }

    // ── Step 3: truncate cold-blob tail ───────────────────────────
    stats.cold_tail_truncated_bytes = truncate_cold_tail(db, db_path, readonly)?;
    Ok(stats)
}

/// Drive a single plan to a terminal state. Returns `Ok(())` on either commit or abandon — both
/// leave the system consistent. Returns `Err` only on hard failure (corrupt plan, unparseable
/// rewrite witness, SQL error during commit) where the caller must refuse to open.
fn recover_one_plan<T: MarfTrieId>(
    db: &mut Connection,
    plan_path: &Path,
    cold_blob_path: &Path,
    hot_files: &mut HotFileSet,
    stats: &mut RecoveryStats,
) -> Result<(), Error> {
    // Decode the plan file.
    let plan = match read_plan_file(plan_path) {
        Ok(p) => p,
        Err(e) => {
            return Err(Error::CorruptionError(format!(
                "recovery: failed to decode plan file {plan_path:?}: {e}. Refusing to open. \
                 If you're sure this plan is junk, delete it manually.",
            )));
        }
    };

    // Verify cold-blob region. Mismatch / missing / short → abandon.
    let cold_ok = verify_cold_blob_region(cold_blob_path, &plan)?;
    if !cold_ok {
        info!(
            "recovery: abandoning plan {plan_path:?} (cold-blob region mismatch); \
             will clear promotion state and remove plan file"
        );
        abandon_plan(db, plan_path)?;
        stats.plans_abandoned += 1;
        return Ok(());
    }

    // Verify sidecar. Mismatch / missing → abandon.
    let sidecar_ok = verify_sidecar(cold_blob_path.parent(), &plan)?;
    if !sidecar_ok {
        info!(
            "recovery: abandoning plan {plan_path:?} (sidecar mismatch); \
             will clear promotion state and remove plan file"
        );
        abandon_plan(db, plan_path)?;
        stats.plans_abandoned += 1;
        return Ok(());
    }

    // Both checks pass → replay the plan idempotently.
    replay_plan::<T>(db, plan_path, hot_files, &plan, stats)?;
    stats.plans_committed += 1;
    Ok(())
}

/// Verify the plan's reserved cold-blob region matches the recorded hash. Returns `Ok(false)` for
/// "abandon this plan" cases (file missing, region too short, hash mismatch). Returns `Ok(true)` if
/// the bytes are durable and match.
fn verify_cold_blob_region(cold_blob_path: &Path, plan: &SquashPlan) -> Result<bool, Error> {
    if plan.header.cold_blob_length == 0 {
        // A zero-length region trivially "matches" — sidecar-only promotion variants might use this
        // in the future. For now, accept and let the sidecar check carry the integrity load.
        return Ok(true);
    }
    let f = match File::open(cold_blob_path) {
        Ok(f) => f,
        Err(e) => {
            warn!("recovery: cold blob {cold_blob_path:?} not openable for verification: {e}",);
            return Ok(false);
        }
    };
    let file_len = f.metadata().map_err(Error::IOError)?.len();
    let end = plan
        .header
        .cold_blob_offset
        .checked_add(plan.header.cold_blob_length)
        .ok_or(Error::OverflowError)?;
    if end > file_len {
        warn!(
            "recovery: cold blob is shorter than plan's reserved region \
             (offset={}, length={}, file_len={file_len})",
            plan.header.cold_blob_offset, plan.header.cold_blob_length,
        );
        return Ok(false);
    }

    // Hash the region. For multi-hundred-MB plans this is O(MB) of I/O
    // + hashing, but recovery is rare. Read in chunks to avoid a giant allocation.
    let mut hasher = sha2::Sha512_256::new();
    use sha2::Digest;
    let mut remaining = plan.header.cold_blob_length;
    let mut offset = plan.header.cold_blob_offset;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let chunk = std::cmp::min(remaining, buf.len() as u64) as usize;
        let chunk_buf = buf
            .get_mut(..chunk)
            .ok_or_else(|| Error::CorruptionError("recovery: cold-blob chunk slice".into()))?;
        f.read_exact_at(chunk_buf, offset).map_err(Error::IOError)?;
        hasher.update(&chunk_buf[..]);
        remaining = remaining
            .checked_sub(chunk as u64)
            .ok_or(Error::OverflowError)?;
        offset = offset
            .checked_add(chunk as u64)
            .ok_or(Error::OverflowError)?;
    }
    let computed = hasher.finalize();
    if computed.as_slice() != plan.header.cold_blob_hash.as_bytes() {
        warn!(
            "recovery: cold-blob region hash mismatch (offset={}, length={})",
            plan.header.cold_blob_offset, plan.header.cold_blob_length,
        );
        return Ok(false);
    }
    Ok(true)
}

/// Verify the published sidecar matches the recorded hash. The plan's `sidecar_path` is stored
/// relative to the DB-path's parent directory; this helper resolves it back to an absolute path
/// before checking.
fn verify_sidecar(parent: Option<&Path>, plan: &SquashPlan) -> Result<bool, Error> {
    let sidecar_path = match parent {
        Some(p) => p.join(&plan.header.sidecar_path),
        None => PathBuf::from(&plan.header.sidecar_path),
    };
    let bytes = match fs::read(&sidecar_path) {
        Ok(b) => b,
        Err(e) => {
            warn!("recovery: sidecar {sidecar_path:?} not readable: {e}");
            return Ok(false);
        }
    };
    let computed = sha512_256_of(&bytes);
    if computed.as_bytes() != plan.header.sidecar_hash.as_bytes() {
        warn!("recovery: sidecar {sidecar_path:?} hash mismatch");
        return Ok(false);
    }
    Ok(true)
}

/// Apply the rewrite plan idempotently and commit the SQL transaction.
fn replay_plan<T: MarfTrieId>(
    db: &mut Connection,
    plan_path: &Path,
    hot_files: &mut HotFileSet,
    plan: &SquashPlan,
    stats: &mut RecoveryStats,
) -> Result<(), Error> {
    // ── B5d-fu.2: catch-up scan ───────────────────────────────────
    //
    // Under the detached-spawn model (fu.2), the worker may have crashed with the coordinator still
    // appending blocks. On recovery, the on-disk plan file lists rewrites for the descendants the
    // worker observed at plan-build, but blocks committed after `tip_at_scan_start` (and before the
    // crash and any subsequent restart) need their backptrs rewritten too — otherwise reads of
    // those blocks would resolve through stale hot-layout offsets that the cold-blob promotion no
    // longer covers.
    //
    // We re-run the live-path catch-up scan here. The scanner is tolerant of already-applied bytes
    // (via the translation map's reverse set), so a partial pre-crash apply doesn't confuse it. New
    // extras are merged with the on-disk plan and persisted via `write_plan_file_atomic`, so a
    // *recurring* crash (recovery itself crashing mid-replay) sees the augmented plan on the next
    // open.
    //
    // Under fu.1's `thread::scope` dispatch the catch-up scan produces zero entries — recovery's
    // behavior is unchanged from B5a. fu.2 makes this load-bearing.
    let in_range_block_ids: HashSet<u32> =
        plan.in_range_blocks.iter().map(|b| b.block_id).collect();
    let catchup_extras = {
        let new_descendants =
            crate::chainstate::stacks::index::squash_promote::enumerate_hot_descendants_above_block_id(
                db,
                plan.header.max_height,
                plan.header.tip_at_scan_start,
            )?;
        let reverse_set =
            crate::chainstate::stacks::index::squash_promote::build_translation_reverse_set(
                &plan.translation_map,
            );
        let mut extras: Vec<RewriteEntry> = Vec::new();
        for desc in &new_descendants {
            crate::chainstate::stacks::index::squash_promote::scan_catchup_descendant(
                hot_files,
                desc,
                &in_range_block_ids,
                &plan.translation_map,
                &reverse_set,
                &mut extras,
            )?;
        }
        extras
    };

    // Persist the augmented plan if catch-up emitted new entries. Recovery's apply step then
    // replays the merged list. If the background phase already covered every descendant (no
    // concurrent appends since), `extras` is empty and we skip the re-write.
    let effective_rewrites = if catchup_extras.is_empty() {
        plan.rewrite_plan.clone()
    } else {
        let merged = crate::chainstate::stacks::index::squash_promote::merge_catchup_into_plan(
            &plan.rewrite_plan,
            catchup_extras,
        );
        let augmented = SquashPlan {
            header: plan.header.clone(),
            in_range_blocks: plan.in_range_blocks.clone(),
            translation_map: plan.translation_map.clone(),
            rewrite_plan: merged.clone(),
        };
        crate::chainstate::stacks::index::squash_plan::write_plan_file_atomic(
            plan_path, &augmented,
        )?;
        merged
    };

    // ── Classify entries (Phase 1: read with guards) ──────────────
    //
    // Originally recovery only ran at process startup, when no readers existed — the fence protocol
    // was unnecessary. Under B5d-fu.2, recovery is reachable from the detached retry worker's
    // `MARF::from_path` open, while the coordinator's live handle is still serving reads. The
    // cross-handle fence registry (B5d cross-handle fix) shares each hot file's `Arc<ReaderFence>`
    // across both handles, so setting `mutate_pending` on the worker's `HotFileSet` blocks readers
    // on the coordinator's. We must use that protocol here.
    //
    // Tricky bit: `apply_rewrite_idempotent` reads bytes via `read_at`, which acquires a read
    // guard. If we set `mutate_pending = true` first, the recovery process's own read would
    // self-deadlock (its `try_from_fence` would see the flag and back off forever). So Phase 1
    // reads — without the fence — to classify entries into "needs apply" and "already applied". No
    // concurrent writer exists at this point (the promotion lock is held), so the read result is
    // reliable. Phase 2 then sets the fence and pwrites only the "needs apply" entries.
    let mut touched_hot_seqs: HashSet<u32> = HashSet::new();
    let mut entries_to_apply: Vec<&RewriteEntry> = Vec::new();
    for entry in &effective_rewrites {
        match classify_rewrite(hot_files, entry)? {
            ApplyOutcome::Applied => {
                entries_to_apply.push(entry);
                stats.rewrites_applied += 1;
            }
            ApplyOutcome::AlreadyApplied => {
                stats.rewrites_skipped += 1;
            }
        }
        touched_hot_seqs.insert(entry.hot_file_seq);
    }

    // ── Phase 2: fenced pwrite + fsync ────────────────────────────
    //
    // Apply the recovery publish under the same reader-fence protocol as `apply_swap_phase`: set
    // `mutate_pending` for every touched file up front, drain `active_reads`, apply any needed
    // pwrites, fsync, publish the SQL redirect, then clear `mutate_pending`. The clear runs even
    // on error so a failed recovery doesn't leave the fence stuck.
    if !touched_hot_seqs.is_empty() {
        const QUIESCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        for seq in &touched_hot_seqs {
            hot_files.set_mutate_pending(*seq, true)?;
        }

        // Test-only barrier: pauses here (after set_mutate_pending, before wait_for_quiesce) when
        // armed. Lets a peer-reader regression test observe that the fence is engaged before
        // recovery progresses.
        #[cfg(test)]
        crate::chainstate::stacks::index::squash_promote::test_hooks::maybe_pause_at_recovery_fence(
            plan_path,
        );

        let publish_result = (|| -> Result<(), Error> {
            for seq in &touched_hot_seqs {
                hot_files.wait_for_quiesce(*seq, QUIESCE_TIMEOUT)?;
            }
            for entry in &entries_to_apply {
                hot_files.pwrite_ptr_field(
                    entry.hot_file_seq,
                    entry.file_offset,
                    entry.post_bytes,
                )?;
            }
            for seq in &touched_hot_seqs {
                hot_files.fsync_seq(*seq)?;
            }
            #[cfg(test)]
            crate::chainstate::stacks::index::squash_promote::test_hooks::maybe_pause_after_recovery_rewrite_before_sql(
                plan_path,
            );
            publish_recovery_sql::<T>(db, plan)
        })();

        for seq in &touched_hot_seqs {
            if let Err(e) = hot_files.set_mutate_pending(*seq, false) {
                warn!(
                    "recovery: failed to clear mutate_pending on seq={seq}: {e} \
                     (readers may block on next promotion until process restart)"
                );
            }
        }

        publish_result?;
    } else {
        publish_recovery_sql::<T>(db, plan)?;
    }

    // ── Remove the plan file. Best-effort: if removal fails, the next recovery pass replays
    // idempotently (the rewrite witness bytes will all be in `post_bytes`, the SQL is `INSERT OR
    // REPLACE`-safe), so we log and continue. ──
    if let Err(e) = fs::remove_file(plan_path) {
        warn!(
            "recovery: failed to remove plan file {plan_path:?} after commit: {e} \
             (will be retried on next open)",
        );
    }
    Ok(())
}

fn publish_recovery_sql<T: MarfTrieId>(
    db: &mut Connection,
    plan: &SquashPlan,
) -> Result<(), Error> {
    (|| -> Result<(), Error> {
        let tx = db.transaction().map_err(Error::SQLError)?;
        crate::chainstate::stacks::index::squash_promote::redirect_in_range_blocks_to_cold::<T>(
            &tx,
            &plan.in_range_blocks,
            plan.header.cold_blob_offset,
            plan.header.cold_blob_length,
        )?;
        // Recompute the published-max-block-id watermark inside this SQL transaction (mirrors the
        // live promotion path's Fix #4 semantics from the B5a Codex review). Falls back to the
        // plan header value if the live computation fails — recovery is best-effort on this
        // counter, since the worst case is a temporarily-inflated "bytes since last squash"
        // reading until the next squash refreshes it.
        let watermark = trie_sql::current_published_max_block_id(&tx)
            .unwrap_or(plan.header.published_max_block_id);
        let level_row = crate::chainstate::stacks::index::squash::SquashLevelRow {
            level_id: plan.header.level_id,
            min_height: plan.header.min_height,
            max_height: plan.header.max_height,
            blob_offset: plan.header.cold_blob_offset,
            blob_length: plan.header.cold_blob_length,
            reads_redirected: plan.header.reads_redirected,
            root_sidecar_present: plan.header.root_sidecar_present,
            root_sidecar_trimmed: plan.header.root_sidecar_trimmed,
            orphan_split_offset: plan.header.orphan_split_offset,
            published_max_block_id: watermark,
        };
        trie_sql::write_squash_level(&tx, &level_row)?;
        trie_sql::clear_promotion_state(&tx)?;
        tx.commit().map_err(Error::SQLError)?;
        Ok(())
    })()
}

/// Classification of one rewrite-plan entry against the on-disk bytes — drives whether the caller
/// should `pwrite` (Applied) or skip (AlreadyApplied) under the fenced apply phase.
enum ApplyOutcome {
    /// On-disk bytes were `pre_bytes`; the caller must pwrite `post_bytes` under the fence.
    Applied,
    /// On-disk bytes were already `post_bytes`; no pwrite needed.
    AlreadyApplied,
}

/// Read the 4 bytes at `(hot_file_seq, file_offset)` and classify against the rewrite entry's
/// pre/post witnesses. Returns `Applied` if the bytes are still pre-promotion (caller will pwrite),
/// `AlreadyApplied` if they are already post-promotion, or `CorruptionError` if neither.
///
/// **Pure read** — no pwrites here. The actual pwrite happens in `replay_plan`'s Phase 2 under the
/// reader-fence protocol so concurrent readers (on a peer `MARF` handle in fu.2's detached-spawn
/// model) cannot observe a torn rewrite.
fn classify_rewrite(hot_files: &HotFileSet, entry: &RewriteEntry) -> Result<ApplyOutcome, Error> {
    let mut current = [0u8; 4];
    let n = hot_files.read_at(entry.hot_file_seq, &mut current, entry.file_offset)?;
    if n != 4 {
        return Err(Error::CorruptionError(format!(
            "recovery: short read at hot_file_seq={} file_offset={} (got {n} bytes)",
            entry.hot_file_seq, entry.file_offset,
        )));
    }
    if current == entry.pre_bytes {
        return Ok(ApplyOutcome::Applied);
    }
    if current == entry.post_bytes {
        return Ok(ApplyOutcome::AlreadyApplied);
    }
    Err(Error::CorruptionError(format!(
        "recovery: rewrite entry at hot_file_seq={} file_offset={} has neither pre nor post bytes \
         (on-disk={current:02x?}, pre={pre:02x?}, post={post:02x?}). This is corruption — \
         possibly a wrong plan file paired with this hot file, or external mutation.",
        entry.hot_file_seq,
        entry.file_offset,
        pre = entry.pre_bytes,
        post = entry.post_bytes,
    )))
}

/// Truncate the cold blob's uncommitted tail. Returns the number of bytes truncated (0 if no
/// truncation was needed). Skipped on readonly handles.
fn truncate_cold_tail(db: &Connection, db_path: &str, readonly: bool) -> Result<u64, Error> {
    if readonly {
        return Ok(0);
    }
    let cold_blob_path = derive_cold_blob_path(db_path);
    let f = match OpenOptions::new()
        .read(true)
        .write(true)
        .open(&cold_blob_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(Error::IOError(e)),
    };
    let file_len = f.metadata().map_err(Error::IOError)?.len();
    // `get_external_blobs_length` already returns the right number for a v5 chainstate (max over
    // committed cold marf_data extents AND committed squash-level extents); see Codex finding #5
    // and the helper at trie_sql.rs:857.
    let highest_committed = trie_sql::get_external_blobs_length(db)?;
    if file_len <= highest_committed {
        return Ok(0);
    }
    let truncated = file_len
        .checked_sub(highest_committed)
        .ok_or(Error::OverflowError)?;
    info!(
        "recovery: truncating cold blob {cold_blob_path:?} from {file_len} -> {highest_committed} \
         bytes (clipping uncommitted tail)"
    );
    f.set_len(highest_committed).map_err(Error::IOError)?;
    f.sync_data().map_err(Error::IOError)?;
    Ok(truncated)
}

/// Abandon a plan: clear the in-flight promotion state in `marf_state` and remove the plan file.
/// Used when cold-blob or sidecar verification fails (the merger never reached durable state, so
/// the plan can never replay).
fn abandon_plan(db: &mut Connection, plan_path: &Path) -> Result<(), Error> {
    trie_sql::clear_promotion_state(db)?;
    if let Err(e) = fs::remove_file(plan_path) {
        warn!(
            "recovery: failed to remove abandoned plan file {plan_path:?}: {e} \
             (will retry on next open)"
        );
    }
    Ok(())
}

/// Mirror the cold-blob path convention used by `TrieFile::from_db_path` (`<db_path>.blobs`).
/// Centralized here so recovery and the writer agree on the path.
fn derive_cold_blob_path(db_path: &str) -> PathBuf {
    PathBuf::from(format!("{db_path}.blobs"))
}

#[cfg(test)]
pub(crate) fn cold_blob_path_for_tests(db_path: &str) -> PathBuf {
    derive_cold_blob_path(db_path)
}

#[cfg(test)]
pub(crate) fn write_cold_blob_at(
    cold_blob_path: &Path,
    offset: u64,
    bytes: &[u8],
) -> Result<(), Error> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .open(cold_blob_path)
        .map_err(Error::IOError)?;
    // Extend if needed so pwrite lands at the right offset.
    let file_len = f.metadata().map_err(Error::IOError)?.len();
    let needed = offset
        .checked_add(bytes.len() as u64)
        .ok_or(Error::OverflowError)?;
    if file_len < needed {
        f.set_len(needed).map_err(Error::IOError)?;
    }
    f.seek(SeekFrom::Start(offset)).map_err(Error::IOError)?;
    f.write_all(bytes).map_err(Error::IOError)?;
    f.sync_all().map_err(Error::IOError)?;
    Ok(())
}
