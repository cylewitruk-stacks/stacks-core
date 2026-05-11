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

/// Snapshot of the canonical Stacks chain over a height range, used by
/// [`MARF::drain_pending_plans`](crate::chainstate::stacks::index::marf::MARF::drain_pending_plans)
/// to validate that a pending squash plan's recorded `block_hashes` still match what the chain
/// considers canonical. Implementors typically wrap a read-only handle on the headers SQL tables.
///
/// **Iteration 1 placeholder**: this trait is the surface PR 2 will use to wire production startup
/// through `DrainPolicy::Canonical`. PR 1 only adds the type so the rest of the API can be shaped
/// against it; production callers continue to route through `DrainPolicy::TrustPlan` and never
/// reach the trait's methods.
pub trait CanonicalView {
    /// Return the canonical Stacks block hash at the given height, or `None` if no canonical block
    /// exists at that height yet (chain too short / pre-genesis).
    fn canonical_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, Error>;
}

/// Policy controlling whether [`MARF::drain_pending_plans`] revalidates pending plans against the
/// live canonical chain before publishing them.
///
/// PR 1 ships both variants; production startup paths still pass [`DrainPolicy::TrustPlan`] (no
/// revalidation, current behavior). PR 2 will switch the production startup paths to
/// [`DrainPolicy::Canonical`] with a real headers-DB-backed [`CanonicalView`].
pub enum DrainPolicy<'a> {
    /// Trust the plan as written. Equivalent to today's behavior: every pending plan is published
    /// (or abandoned on hash mismatch). Used by tests, tools, and PR 1's wrapper around the legacy
    /// recovery path.
    TrustPlan,
    /// Validate each pending plan's recorded canonical chain (`plan.in_range_blocks[*].block_hash`)
    /// against the supplied [`CanonicalView`] before publish. Plans whose recorded canonical no
    /// longer matches the live chain are discarded instead of published.
    Canonical(&'a dyn CanonicalView),
}

/// Per-plan outcome of a [`MARF::drain_pending_plans`] pass. Aggregated into [`DrainStats`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainOutcome {
    /// Plan was published successfully. The MARF's in-memory squash metadata may need refresh
    /// (caller's responsibility — startup callers don't need this since no live handle exists yet).
    Published {
        level_id: u32,
        in_range_block_count: usize,
        rewrites_applied: usize,
    },
    /// Plan was discarded because its recorded canonical chain didn't match the live canonical
    /// view. Only reachable under [`DrainPolicy::Canonical`].
    DiscardedStale {
        level_id: u32,
        diverging_height: u32,
        recorded_hash: [u8; 32],
        canonical_hash: Option<[u8; 32]>,
    },
    /// Plan was abandoned because integrity-recovery (cold-blob hash mismatch, sidecar mismatch,
    /// etc.) couldn't validate it. Mirrors the legacy `plans_abandoned` counter.
    Abandoned { level_id: u32 },
}

/// Aggregated statistics for a single [`MARF::drain_pending_plans`] call. Production callers log
/// this for operator visibility; tests assert on individual fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DrainStats {
    /// Per-plan outcomes in the order they were processed.
    pub outcomes: Vec<DrainOutcome>,
    /// Total rewrite entries applied via `pwrite` across all published plans.
    pub rewrites_applied: usize,
    /// Total rewrite entries skipped because the on-disk bytes were already in the post-state
    /// (idempotent replay).
    pub rewrites_skipped: usize,
    /// Bytes truncated from the cold blob's uncommitted tail at the end of the drain pass.
    pub cold_tail_truncated_bytes: u64,
}

impl DrainStats {
    /// `true` if the drain pass found a pending plan (whether published, discarded, or abandoned).
    pub fn any_plan_processed(&self) -> bool {
        !self.outcomes.is_empty()
    }

    /// Total number of plans the drain pass processed (sum of published, abandoned, and
    /// discarded-stale outcomes).
    pub fn plans_discovered(&self) -> usize {
        self.outcomes.len()
    }

    /// Number of plans that committed successfully ([`DrainOutcome::Published`]).
    pub fn plans_committed(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, DrainOutcome::Published { .. }))
            .count()
    }

    /// Number of plans abandoned because of integrity-recovery failure ([`DrainOutcome::Abandoned`]).
    pub fn plans_abandoned(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, DrainOutcome::Abandoned { .. }))
            .count()
    }

    /// Number of plans discarded because the live canonical chain has diverged from the plan's
    /// recorded chain ([`DrainOutcome::DiscardedStale`]). Always zero under
    /// [`DrainPolicy::TrustPlan`].
    pub fn plans_discarded_stale(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, DrainOutcome::DiscardedStale { .. }))
            .count()
    }

    /// Iterator over the [`DrainOutcome::DiscardedStale`] outcomes, in process order. Callers
    /// reach for this when they want the diagnostic detail (diverging height, recorded vs
    /// canonical hash) attached to a stale-discard log line.
    pub fn stale_discards(&self) -> impl Iterator<Item = &DrainOutcome> {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, DrainOutcome::DiscardedStale { .. }))
    }
}

/// Recover any pending promotions for the MARF at `db_path`.
///
/// Returns a [`DrainStats`] summary on success. Returns an error if recovery cannot complete
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
    canonical_view: Option<&dyn CanonicalView>,
) -> Result<DrainStats, Error> {
    let mut stats = DrainStats::default();

    // ── Step 1: discover pending plans ────────────────────────────
    let plans = discover_pending_plans(db_path)?;

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
        match recover_one_plan::<T>(
            db,
            &plan_path,
            &cold_blob_path,
            hot_files,
            &mut stats,
            canonical_view,
        ) {
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
    stats: &mut DrainStats,
    canonical_view: Option<&dyn CanonicalView>,
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
    let level_id = plan.header.level_id;

    // Verify cold-blob region. Mismatch / missing / short → abandon.
    let cold_ok = verify_cold_blob_region(cold_blob_path, &plan)?;
    if !cold_ok {
        info!(
            "recovery: abandoning plan {plan_path:?} (cold-blob region mismatch); \
             will clear promotion state and remove plan file"
        );
        abandon_plan(db, plan_path)?;
        stats.outcomes.push(DrainOutcome::Abandoned { level_id });
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
        stats.outcomes.push(DrainOutcome::Abandoned { level_id });
        return Ok(());
    }

    // Canonical-divergence check (only when caller passed [`DrainPolicy::Canonical`]).
    //
    // The plan's `in_range_blocks` vector records, in height-order, the block hash that was
    // canonical at each height in `[plan.header.min_height ..= plan.header.max_height]` at plan-
    // write time. Compare each entry to what the live `CanonicalView` reports at that height.
    // First mismatch → discard the plan instead of publishing it. This is the production-side
    // fix for the detached-worker stale-tip bug: a worker that snapshotted canonical at start
    // can find canonical has shifted by the time it's ready to publish, and publishing anyway
    // would commit a stale level that downstream divergence checks then trip on.
    if let Some(view) = canonical_view {
        if let Some(outcome) = check_canonical_divergence(view, &plan)? {
            if let DrainOutcome::DiscardedStale {
                diverging_height,
                recorded_hash,
                canonical_hash,
                ..
            } = &outcome
            {
                info!(
                    "recovery: discarding plan {plan_path:?} (canonical divergence at height {}: \
                     plan recorded {}, current canonical is {:?}); will clear promotion state \
                     and remove plan file",
                    diverging_height,
                    stacks_common::util::hash::to_hex(recorded_hash),
                    canonical_hash.map(|h| stacks_common::util::hash::to_hex(&h)),
                );
            }
            abandon_plan(db, plan_path)?;
            stats.outcomes.push(outcome);
            return Ok(());
        }
    }

    // All integrity + canonical checks pass → publish via the shared core. This is the same
    // function the runtime publish path
    // ([`crate::chainstate::stacks::index::squash_promote::apply_prepared_plan`]) calls — one
    // publish path, one set of bugs to debug.
    let in_range_block_count = plan.in_range_blocks.len();
    let (plan_applied, plan_skipped) =
        crate::chainstate::stacks::index::squash_promote::publish_prepared_inner::<T>(
            db, hot_files, plan_path, &plan,
        )?;
    stats.rewrites_applied += plan_applied;
    stats.rewrites_skipped += plan_skipped;
    stats.outcomes.push(DrainOutcome::Published {
        level_id,
        in_range_block_count,
        rewrites_applied: plan_applied,
    });
    Ok(())
}

/// Compare the plan's recorded canonical chain against the live `CanonicalView`. Returns
/// `Ok(None)` when every recorded `(height, block_hash)` pair matches what the view reports for
/// that height (or the view returns `None` for that height — treated as "skip", consistent with
/// the per-MARF divergence detector's three-state predicate). Returns `Ok(Some(record))` on the
/// first mismatch, capturing the diverging height + recorded vs canonical hashes for diagnostic
/// surfaces ([`DrainOutcome::DiscardedStale`] / log lines).
///
/// Index `i` of `plan.in_range_blocks` corresponds to height `plan.header.min_height + i` —
/// `build_in_range_block_list` emits one entry per height in the inclusive range, in order, so
/// the index→height map is exact without a second SQL hit.
pub(crate) fn check_canonical_divergence(
    view: &dyn CanonicalView,
    plan: &SquashPlan,
) -> Result<Option<DrainOutcome>, Error> {
    for (i, entry) in plan.in_range_blocks.iter().enumerate() {
        let height = plan
            .header
            .min_height
            .checked_add(i as u32)
            .ok_or_else(|| {
                Error::CorruptionError("plan in_range_blocks index overflows u32 height".into())
            })?;
        let canonical = view.canonical_at_height(height)?;
        match canonical {
            // Match: plan's recorded canonical agrees with the live view at this height.
            Some(c) if c == entry.block_hash => continue,
            // Unmapped: the view doesn't know about this height (truncated ancestry).
            // Skip per the three-state predicate — the per-MARF divergence detector
            // treats unmapped heights as "skip", not as non-canonical.
            None => continue,
            // Mismatch: live view reports a different hash at this height.
            Some(_) => {
                return Ok(Some(DrainOutcome::DiscardedStale {
                    level_id: plan.header.level_id,
                    diverging_height: height,
                    recorded_hash: entry.block_hash,
                    canonical_hash: canonical,
                }));
            }
        }
    }
    Ok(None)
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

/// Read the 4 bytes at `(hot_file_seq, file_offset)` and classify against the rewrite entry's
/// pre/post witnesses. Returns `Ok(true)` if the bytes are still pre-promotion (caller must
/// pwrite under the fence), `Ok(false)` if the bytes are already post-promotion (no pwrite
/// needed — only reachable in recovery from a partial pre-crash apply), or `CorruptionError` if
/// neither — possibly a wrong plan file paired with this hot file, or external mutation.
///
/// **Pure read.** The actual pwrite happens in
/// [`crate::chainstate::stacks::index::squash_promote::publish_prepared_inner`]'s fenced Phase
/// 2 so concurrent readers (on a peer `MARF` handle under detached-spawn dispatch) cannot
/// observe a torn rewrite.
pub(crate) fn classify_rewrite_for_publish(
    hot_files: &HotFileSet,
    entry: &RewriteEntry,
) -> Result<bool, Error> {
    let mut current = [0u8; 4];
    let n = hot_files.read_at(entry.hot_file_seq, &mut current, entry.file_offset)?;
    if n != 4 {
        return Err(Error::CorruptionError(format!(
            "publish: short read at hot_file_seq={} file_offset={} (got {n} bytes)",
            entry.hot_file_seq, entry.file_offset,
        )));
    }
    if current == entry.pre_bytes {
        return Ok(true);
    }
    if current == entry.post_bytes {
        return Ok(false);
    }
    Err(Error::CorruptionError(format!(
        "publish: rewrite entry at hot_file_seq={} file_offset={} has neither pre nor post \
         bytes (on-disk={current:02x?}, pre={pre:02x?}, post={post:02x?}). This is corruption \
         — possibly a wrong plan file paired with this hot file, or external mutation.",
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
