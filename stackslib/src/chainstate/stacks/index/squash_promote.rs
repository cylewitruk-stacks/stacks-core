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

//! Phase B horizon-gated promotion: synchronous core (slice B5a).
//!
//! End-to-end horizon-gated promotion described in `.docs/squashing-v1.5-phase-b.md` §6, but
//! synchronously and with no concurrency primitives yet:
//!
//! - **B5a (this slice)**: single-threaded `run_horizon_gated_promotion`. Reuses
//!   [`crate::chainstate::stacks::index::squash::prepare_merge_outputs`] for the merger,
//!   [`crate::chainstate::stacks::index::byte_scanner`] for the descendant rewrite plan,
//!   [`crate::chainstate::stacks::index::squash_plan`] for the on-disk plan format,
//!   [`crate::chainstate::stacks::index::squash_recover`] for crash recovery.
//! - **B5b (next)**: spawn this on a dedicated thread + `PromotionTaskHandle`, dispatch from
//!   `maybe_squash`, flip `PROMOTION_DRIVER_READY`.
//! - **B5c**: activate `mutate_pending` in `HotFile`, per-file quiesce wait, catch-up scan during
//!   swap.
//! - **B5d**: end-to-end production tests (level-34-shape regression, mid-promotion crash,
//!   mainnet-replay smoke).
//!
//! # B5a invariants
//!
//! Because B5a runs synchronously inside the caller's thread:
//! - No catch-up scan needed (no concurrent writer can append blocks during the background phase).
//! - No `HotFile::mutate_pending` quiesce needed (no concurrent reader can hold a
//!   `HotFileReadGuard` over the touched bytes).
//! - The cold-blob mmap remap happens once, after the SQL transaction commits (via
//!   `MARF::refresh_after_squash`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha512_256};
use stacks_common::types::chainstate::TrieHash;

use crate::chainstate::stacks::index::byte_scanner::{scan_serialized_trie_ptr_fields, ScannedPtr};
use crate::chainstate::stacks::index::marf::{MarfConnection, MARF};
use crate::chainstate::stacks::index::node::is_backptr;
use crate::chainstate::stacks::index::sidecar::squash_root_sidecar_path;
use crate::chainstate::stacks::index::squash::{
    prepare_merge_outputs, PhaseTimings, PreparedMerge, SquashLevelRow, SquashStats,
};
use crate::chainstate::stacks::index::squash_plan::{
    plan_file_path, read_plan_file, write_plan_file_atomic, InRangeBlock, PlanHeader, RewriteEntry,
    SquashPlan, TranslationMap,
};
use crate::chainstate::stacks::index::squash_recover::{
    check_canonical_divergence, DrainOutcome, DrainPolicy,
};
use crate::chainstate::stacks::index::storage::ROOT_PTR_DISK;
use crate::chainstate::stacks::index::{trie_sql, Error, MarfTrieId};

/// Promotion-pass summary.
#[derive(Debug, Default, Clone)]
pub struct PromotionStats {
    pub squash: SquashStats,
    pub translation_map_entries: usize,
    pub descendants_scanned: usize,
    pub rewrites_planned: usize,
    pub cold_blob_bytes_written: u64,
}

/// Output of the prepare phase of a horizon-gated promotion. Handed off from the worker side
/// (background thread) to the coordinator side (chains-coordinator) which performs the validate +
/// publish step via [`apply_prepared_plan`].
///
/// The promotion's durable artifacts — cold-blob bytes, sidecar, and on-disk plan file — are all
/// fsynced before this is returned, so a process crash between prepare and apply is recoverable on
/// the next RW open via
/// [`crate::chainstate::stacks::index::squash_recover::recover_pending_promotions`].
///
/// The merger's `node_store` temp state is finalized inside `prepare_promotion` before returning,
/// so this handle holds no resources beyond plain values + a path to the durable plan file.
#[derive(Debug, Clone)]
pub struct PreparedPromotion {
    /// Absolute path to the durable plan file. Both the runtime publish (via the coordinator's
    /// [`apply_prepared_plan`] call) and crash recovery read the plan from this path; they share
    /// one publish path so that startup and runtime go through the same validate/publish gate.
    pub plan_path: PathBuf,
    /// `next_level_id` baked into the plan. Reflected back so the coordinator can attribute log
    /// lines without re-reading the plan.
    pub level_id: u32,
    /// In-range height bounds for the prepared promotion, inclusive. The coordinator uses
    /// `min_height` to bound its [`crate::chainstate::stacks::index::squash_recover::CanonicalView`]
    /// precompute walk without re-scanning disk plans.
    pub min_height: u32,
    pub max_height: u32,
    /// Background-phase counters (translation map size, descendants scanned, rewrites planned,
    /// cold-blob bytes written). The publish phase contributes nothing to these counters; it
    /// produces a [`DrainOutcome::Published`] with `rewrites_applied` instead.
    pub stats: PromotionStats,
}

/// Run a synchronous horizon-gated promotion publishing `[min_height ..= max_height]` as a new
/// squash level on `marf`.
///
/// **Caller obligations**:
/// - The MARF must be opened with hot tier enabled.
/// - The horizon predicate must already have been verified by the caller (`should_squash`).
///
/// On success, the new squash level is published in `marf_squash_levels`, in-range `marf_data` rows
/// are flipped to `Cold` pointing at the merged blob, descendants' hot-file ptr fields are
/// rewritten to the post-promotion layout, and the plan file is removed.
///
/// On error, the plan file (if any) remains on disk for
/// [`crate::chainstate::stacks::index::squash_recover::recover_pending_promotions`] to drive
/// forward at the next RW open.
///
/// **Synchronous all-in-one entry point.** Internally splits into [`prepare_promotion`] (durable
/// merge artifacts + plan file) followed by [`apply_prepared_plan`] (catch-up scan + fenced
/// rewrites + SQL publish). The detached-worker code path uses the prepare/apply split directly,
/// with the chains-coordinator owning the publish step under a [`DrainPolicy::Canonical`]
/// validation. This synchronous wrapper passes [`DrainPolicy::TrustPlan`] because the same call
/// stack just produced the plan — no canonical check is meaningful in this scope.
pub fn run_horizon_gated_promotion<T: MarfTrieId + Send + Sync>(
    marf: &mut MARF<T>,
    mode: crate::chainstate::stacks::index::squash::SquashMode,
    min_height: u32,
    max_height: u32,
    canonical_tip: Option<T>,
) -> Result<PromotionStats, Error> {
    let marf_path = marf.get_db_path().to_string();

    // Pre-prep guards (mirror `prepare_promotion`'s guards) — run BEFORE the inner call so the
    // post-error lock-clear policy below only triggers on errors from our own prepare attempt,
    // not on a pre-existing external lock that the caller wants preserved.
    {
        let state = trie_sql::read_marf_state(marf.sqlite_conn())?;
        if state.promotion_in_progress.is_some() {
            return Err(Error::InProgressError);
        }
    }
    if !crate::chainstate::stacks::index::squash_plan::discover_pending_plans(&marf_path)?
        .is_empty()
    {
        return Err(Error::InProgressError);
    }

    // Two distinct error-handling regimes:
    //
    // **Pre-plan-fsync**: any error clears the lock so the next cadence tick can retry. The plan
    // file is not yet on disk so recovery has nothing to drive forward; clearing the lock is safe.
    //
    // **Post-plan-fsync**: the plan file is durable on disk. From this point on, recovery owns the
    // cleanup — it'll either replay the plan to completion (committing the level + clearing the
    // lock atomically) or abandon it (deleting the plan + clearing the lock). Clearing the lock now
    // would let a second promotion start while the plan still exists, with potentially overlapping
    // cold-blob reservations.
    let result = (|| -> Result<PromotionStats, Error> {
        let prepared = prepare_promotion::<T>(marf, mode, min_height, max_height, canonical_tip)?;

        // ── B5b test fault hook ───────────────────────────────────
        //
        // After the plan file is durable, the swap phase is the load-bearing recovery boundary:
        // any crash here must be replayable from the on-disk state. To exercise that property
        // end-to-end we let tests force an early return *immediately after the plan file is
        // fsynced* — leaving the cold blob, sidecar, pending plan, and partially-applied (or
        // zero-applied) hot rewrites on disk for `recover_pending_promotions` to drive forward.
        // Production builds compile this away via `#[cfg(test)]`.
        #[cfg(test)]
        if test_hooks::abort_after_plan_write_armed() {
            return Err(Error::NotSupportedError(
                "test fault: aborted after plan write".into(),
            ));
        }

        // Synchronous-publish path: the same call stack just produced the plan, so canonical
        // validation against a possibly-stale snapshot would add nothing. Detached-worker
        // dispatch routes through the coordinator's `apply_prepared_plan(... Canonical(view))`
        // instead.
        match apply_prepared_plan::<T>(marf, &prepared, DrainPolicy::TrustPlan)? {
            DrainOutcome::Published { .. } => Ok(prepared.stats),
            // Unreachable under TrustPlan: the policy never produces DiscardedStale, and
            // Abandoned is recovery-only (cold-blob/sidecar mismatch on bytes the caller just
            // wrote is impossible). Surface as a hard error rather than swallow.
            other => Err(Error::CorruptionError(format!(
                "run_horizon_gated_promotion: unexpected publish outcome under TrustPlan: \
                 {other:?}",
            ))),
        }
    })();
    match &result {
        Ok(_) => {} // success: lock cleared atomically inside swap SQL tx
        Err(_) => {
            // Check whether a plan file is on disk for this MARF. If yes, recovery owns the
            // cleanup; leave the lock set. If no, we crashed before plan fsync — clear the lock.
            let plans_after =
                crate::chainstate::stacks::index::squash_plan::discover_pending_plans(&marf_path)
                    .unwrap_or_default();
            if plans_after.is_empty() {
                if let Err(clear_err) = trie_sql::clear_promotion_state(marf.sqlite_conn()) {
                    warn!(
                        "promotion: failed to clear promotion lock after pre-plan error on \
                         {marf_path}: {clear_err}",
                    );
                }
            } else {
                warn!(
                    "promotion: failed AFTER plan file became durable; leaving lock set \
                     and {} plan file(s) on disk for `recover_pending_promotions` to drive \
                     forward on next RW open",
                    plans_after.len(),
                );
            }
        }
    }
    result
}

/// Path-based wrapper that runs the **prepare phase only** of a horizon-gated promotion. Opens
/// a fresh `MARF<T>` from `marf_path` with hot tier enabled (and `auto_recovery=false` —
/// **load-bearing**, see below), runs the merge prep + cold-blob append + sidecar publish +
/// descendant scan + plan persist, and returns a [`PreparedPromotion`] handle for the
/// coordinator to validate + publish via [`apply_prepared_plan`].
///
/// Used by [`crate::chainstate::stacks::db::StacksChainState::maybe_squash`] to dispatch
/// hot-tier promotions through detached worker threads. The coordinator's
/// [`crate::chainstate::stacks::db::StacksChainState::poll_pending_promotions`] reaps the
/// worker on a later tick, builds a
/// [`crate::chainstate::stacks::index::squash_recover::CanonicalView`] from the chainstate-
/// resolved canonical Stacks tip, and calls `apply_prepared_plan` with
/// `DrainPolicy::Canonical(&view)`. Plans whose recorded canonical chain has diverged from the
/// live view by publish time are discarded instead of published.
///
/// **Why `auto_recovery=false` is load-bearing**: this path is the detached worker. If the
/// MARF open ran recovery under `DrainPolicy::TrustPlan` (the legacy worker-side default), a
/// leftover plan from a prior tick's failed publish would get TrustPlan-published here —
/// bypassing the coordinator's canonical gate. That reopens the exact stale-tip bug class this
/// refactor closes. With recovery off, leftover plans block prepare via the pre-prep guards
/// inside [`prepare_promotion`]; the coordinator's drain path
/// (`MARF::drain_pending_plans(Canonical(view))` from `poll_pending_promotions`) is the sole
/// runtime publish gate. Process-restart recovery goes through `StacksChainState::recover`,
/// which also threads the canonical view.
pub fn run_horizon_gated_promotion_at_path<T: MarfTrieId + Send + Sync>(
    marf_path: &str,
    mode: crate::chainstate::stacks::index::squash::SquashMode,
    min_height: u32,
    max_height: u32,
    canonical_tip: Option<T>,
) -> Result<Option<PreparedPromotion>, Error> {
    use crate::chainstate::stacks::index::marf::MARFOpenOpts;
    use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
    let open_opts = MARFOpenOpts {
        hash_calculation_mode: TrieHashCalculationMode::Immediate,
        cache_strategy: "noop".to_string(),
        external_blobs: true,
        force_db_migrate: false,
        compress: false,
        mmap: false,
        // The `squash_mode` field on `MARFOpenOpts` is informational for runtime opens; the
        // actual mode used by this prepare phase is the `mode` argument threaded into
        // `prepare_promotion`. Mirror it here for consistency in any downstream observability.
        squash_mode: mode,
        squash_root_snapshot_retention_levels:
            crate::chainstate::stacks::index::squash::MARF_ROOT_SNAPSHOT_RETENTION_LEVELS,
        squash_root_snapshot_retention_blocks: None,
        squash_horizon_burn_blocks: None,
        // See the "Why auto_recovery=false is load-bearing" note above. The worker has no
        // canonical context; only the coordinator does.
        auto_recovery: false,
    };

    let mut marf = MARF::<T>::from_path(marf_path, open_opts)?;

    match prepare_promotion::<T>(&mut marf, mode, min_height, max_height, canonical_tip) {
        Ok(prepared) => Ok(Some(prepared)),
        Err(e) => {
            // Lock-clear policy mirrors `run_horizon_gated_promotion`: pre-plan-fsync error →
            // safe to clear (no plan on disk yet); post-plan-fsync error → leave lock + plan
            // for the coordinator's drain path to drive forward on a subsequent tick.
            //
            // The InProgressError case (leftover plan tripped the pre-prep guard) lands here
            // with no plan-file change of our own; we don't clear the lock because the
            // existing plan is what's holding it.
            let plans_after =
                crate::chainstate::stacks::index::squash_plan::discover_pending_plans(marf_path)
                    .unwrap_or_default();
            if plans_after.is_empty() {
                if let Err(clear_err) = trie_sql::clear_promotion_state(marf.sqlite_conn()) {
                    warn!(
                        "Auto-squash (hot-tier, detached): failed to clear promotion lock \
                         after pre-plan error on {marf_path}: {clear_err}",
                    );
                }
            }
            Err(e)
        }
    }
}

/// **Prepare phase**: pre-prep guards, merge prep, cold-blob append + fsync, sidecar publish,
/// descendant scan, plan file fsync. Stops at "plan is durable on disk." Does NOT publish —
/// that step is the caller's responsibility via [`apply_prepared_plan`] (runtime, with canonical
/// validation) or [`crate::chainstate::stacks::index::squash_recover::recover_pending_promotions`]
/// (startup recovery).
///
/// On `Ok`, returns a [`PreparedPromotion`] handle; the merger's `node_store` is finalized
/// before returning (the publish phase has no need for it). The lock is left set so recovery /
/// the coordinator's leftover-plan drain owns cleanup if the publish step crashes.
///
/// **Pre-prep guards** (single-flight lock + plan-file scan) live here so both the synchronous
/// wrapper ([`run_horizon_gated_promotion`]) and the detached-worker entry
/// ([`run_horizon_gated_promotion_at_path`]) bail uniformly on a leftover plan. With
/// `auto_recovery=false` on the worker's MARF open, leftover plans are NOT auto-published on
/// open — the coordinator's canonical-validated drain is the sole publish gate at runtime, and
/// `StacksChainState::recover` is the sole gate at startup.
///
/// Post-error lock-clear policy lives in the callers since the wrapper-vs-worker contexts
/// distinguish "pre-plan-fsync error → safe to clear" from "post-plan-fsync error → leave for
/// drain/recovery to drive forward".
pub(crate) fn prepare_promotion<T: MarfTrieId + Send + Sync>(
    marf: &mut MARF<T>,
    mode: crate::chainstate::stacks::index::squash::SquashMode,
    min_height: u32,
    max_height: u32,
    canonical_tip: Option<T>,
) -> Result<PreparedPromotion, Error> {
    let marf_path = marf.get_db_path().to_string();

    // ── Pre-prep guards ───────────────────────────────────────────
    //
    // Reject if **either** the in-memory single-flight lock is held OR a plan file exists on
    // disk. The plan-file check covers a previously-prepared plan that the coordinator hasn't
    // published yet (e.g., a transient publish failure on a prior tick); the lock check covers
    // a concurrent caller. Both conditions mean "another publish is pending — don't stack a
    // new prepare on top." The coordinator's drain path on subsequent ticks resolves the
    // pending plan; this guard exists to keep workers from racing past it.
    {
        let state = trie_sql::read_marf_state(marf.sqlite_conn())?;
        if state.promotion_in_progress.is_some() {
            return Err(Error::InProgressError);
        }
    }
    let pending_plans =
        crate::chainstate::stacks::index::squash_plan::discover_pending_plans(&marf_path)?;
    if !pending_plans.is_empty() {
        return Err(Error::InProgressError);
    }

    // Eagerly stage the lock with a placeholder level_id; the real value goes in once
    // `prepare_merge_outputs` returns it. The lock-clear policy on error lives in the caller
    // (`run_horizon_gated_promotion` / `run_horizon_gated_promotion_at_path`) — see the
    // "post-plan-fsync" boundary explanation in those wrappers.
    set_promotion_lock(marf.sqlite_conn(), u32::MAX, 0, 0)?;

    // ── Background phase: merge prep ──────────────────────────────
    let mut stats = SquashStats::default();
    let mut timings = PhaseTimings::default();
    let prepared = prepare_merge_outputs(
        marf,
        mode,
        min_height,
        max_height,
        /* reclaim */ true,
        canonical_tip,
        &mut stats,
        &mut timings,
        /* allow_descendants */ true,
    )?;

    // ── Background phase: cold-blob bytes ─────────────────────────
    //
    // Use the cold_blob_offset that `prepare_merge_outputs` baked into the sidecar's canonical
    // path. Re-querying `get_blob_append_offset` here would diverge under reclaim (the prior
    // level's bytes are about to be truncated), and the sidecar+plan would then reference different
    // offsets.
    let merged_blob_bytes = build_merged_blob_bytes(&prepared)?;
    let cold_blob_offset = prepared.cold_blob_offset;
    let cold_blob_length = merged_blob_bytes.len() as u64;
    let cold_blob_hash = sha512_256_of(&merged_blob_bytes);

    // Persist the real reservation now that we know the level_id +
    // extent.
    set_promotion_lock(
        marf.sqlite_conn(),
        prepared.next_level_id,
        cold_blob_offset,
        cold_blob_length,
    )?;

    // Append + sync + remap. The cold blob is append-only, so this is safe outside any quiesce —
    // peer handles' mmaps just don't see the new region until we update `marf_data` to point at it.
    marf.storage
        .pwrite_blob_chunk(&merged_blob_bytes, cold_blob_offset)?;
    marf.storage.finish_blob_write(None)?;

    // ── Background phase: snapshot the catch-up watermark FIRST ───
    //
    // The watermark must be captured BEFORE `enumerate_hot_descendants` runs. The catch-up scan
    // at publish time uses `block_id > watermark` to find rows the initial pass didn't cover;
    // any block committed between watermark capture and enumerate winds up in `enumerate`'s
    // result (and is scanned in the initial pass), and any block committed AFTER enumerate has
    // `block_id > watermark` (covered by catch-up). Both passes together cover the full
    // descendant set at publish time, with `merge_catchup_into_plan` de-duping any overlap.
    //
    // **Don't reorder this with `enumerate_hot_descendants` below.** If the watermark is
    // captured AFTER enumerate, blocks committed in the (enumerate, watermark] gap fall through
    // both passes — not in the initial scan (committed after enumerate ran), not in catch-up
    // (their block_id is ≤ watermark, so the `> watermark` filter excludes them). Their
    // descendant backptrs to in-range blocks are then never rewritten, leaving stale pre-publish
    // offsets that resolve into mid-node bytes after the level commits. Mainnet sync hit
    // exactly this on the perf/marf-squash-cyle branch (level-8 panic, blocks 19039/19040 left
    // with patch base ptr `(18711, 2506)` pointing inside 18711's merged-blob root).
    //
    // The regression test pinning this is
    // [`prepare_watermark_precedes_enumerate_under_concurrent_commit`] in
    // `test/squash_promote.rs`.
    let catchup_watermark = {
        #[cfg(test)]
        {
            test_hooks::forced_tip_at_scan_start()
                .map(Ok)
                .unwrap_or_else(|| trie_sql::current_published_max_block_id(marf.sqlite_conn()))?
        }
        #[cfg(not(test))]
        {
            trie_sql::current_published_max_block_id(marf.sqlite_conn())?
        }
    };

    // ── Background phase: descendant rewrite plan ─────────────────
    //
    // Resolve the COMPLETE in-range block_id set from the trailer (authoritative). Earlier code
    // derived the set from `translation_map.by_block` keys, but that subset misses any in-range
    // block whose root is a leaf (or whose root has only backptrs as children) — those
    // contribute zero entries to `ptr_to_idx`. The trailer enumerates one block per height in
    // the squash range; resolving each `block_hash → block_id` produces the exact in-range set.
    let in_range_blocks = build_in_range_block_list(&prepared, marf.sqlite_conn())?;
    let in_range_block_ids: HashSet<u32> = in_range_blocks.iter().map(|b| b.block_id).collect();

    let descendants = enumerate_hot_descendants(marf.sqlite_conn(), max_height)?;
    let descendants_scanned = descendants.len();
    let mut rewrite_plan: Vec<RewriteEntry> = Vec::new();
    {
        let hot_files = marf
            .storage
            .blobs
            .as_ref()
            .and_then(|b| b.hot_files())
            .ok_or_else(|| {
                Error::CorruptionError("prepare_promotion: hot tier must be attached".into())
            })?;
        for desc in &descendants {
            scan_one_descendant(
                hot_files,
                desc,
                &in_range_block_ids,
                &prepared.merge.translation_map,
                &mut rewrite_plan,
            )?;
        }
    }
    rewrite_plan.sort_by_key(|e| (e.hot_file_seq, e.file_offset));

    // Test-only barrier: fires AFTER enumerate completes, simulating the window where the
    // buggy ordering captured the watermark. A test arming this barrier injects a concurrent
    // commit via a peer MARF handle; under the corrected ordering the watermark is already
    // captured (snapshotted before enumerate above) and the catch-up filter at publish time
    // covers the new commit. Under a (hypothetical) regression where watermark capture moved
    // back here, the watermark would equal the new commit's block_id and catch-up would miss
    // it — exactly the mainnet level-8 race.
    #[cfg(test)]
    test_hooks::maybe_pause_after_descendant_enumerate(&marf_path);

    // ── Background phase: capture sidecar witness ─────────────────
    //
    // Recovery must verify the sidecar bytes match the plan's recorded hash before replaying — a
    // mismatch means the merger crashed mid-sidecar-write and the plan can't be safely committed.
    // We capture the witness here, AFTER the merger published the sidecar via
    // `publish_per_level_sidecar` inside `prepare_merge_outputs`, BEFORE the plan file is written.
    let (sidecar_path_relative, sidecar_hash) = {
        let abs_path = squash_root_sidecar_path(
            Path::new(&marf_path),
            prepared.next_level_id,
            min_height,
            max_height,
            cold_blob_offset,
        );
        let bytes = std::fs::read(&abs_path).map_err(|e| {
            Error::CorruptionError(format!(
                "prepare_promotion: sidecar at {abs_path:?} not readable after merge prep: {e}"
            ))
        })?;
        let hash = sha512_256_of(&bytes);
        // Store relative-to-DB-parent so recovery can resolve via `parent.join(sidecar_path)`. The
        // sidecar lives in the `<db>.squash_sidecars/<filename>` subdirectory.
        let parent = Path::new(&marf_path)
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let rel = abs_path
            .strip_prefix(&parent)
            .map(|p| p.to_path_buf())
            .unwrap_or(abs_path.clone());
        (rel.to_string_lossy().into_owned(), hash)
    };

    // ── Background phase: stage the plan file ─────────────────────
    let plan = SquashPlan {
        header: PlanHeader {
            level_id: prepared.next_level_id,
            min_height,
            max_height,
            tip_at_scan_start: catchup_watermark,
            cold_blob_offset,
            cold_blob_length,
            cold_blob_hash,
            sidecar_path: sidecar_path_relative,
            sidecar_hash,
            reads_redirected: true,
            root_sidecar_present: prepared.merge.sidecar_published,
            root_sidecar_trimmed: false,
            orphan_split_offset: prepared.merge.orphan_split_offset,
            // Placeholder; the publish phase recomputes via `current_published_max_block_id(&tx)`
            // and writes the real value into the published level row. The plan header still
            // carries the in-range max as a recovery fallback.
            published_max_block_id: in_range_blocks
                .iter()
                .map(|b| b.block_id)
                .max()
                .unwrap_or(0),
        },
        in_range_blocks: in_range_blocks.clone(),
        translation_map: prepared.merge.translation_map.clone(),
        rewrite_plan: rewrite_plan.clone(),
    };
    let plan_path = PathBuf::from(plan_file_path(&marf_path, prepared.next_level_id));
    write_plan_file_atomic(&plan_path, &plan)?;

    let translation_entries = prepared.merge.translation_map.entry_count();
    let next_level_id = prepared.next_level_id;
    let rewrites_planned = rewrite_plan.len();

    // Tear down merge state. The publish phase has no need for `node_store` — it works against
    // durable artifacts (cold blob, sidecar, plan file). Letting `node_store` outlive plan
    // persistence would keep the merge's temp file open across the prepare→publish handoff for
    // no reason.
    prepared.merge.node_store.finish()?;

    Ok(PreparedPromotion {
        plan_path,
        level_id: next_level_id,
        min_height,
        max_height,
        stats: PromotionStats {
            squash: stats,
            translation_map_entries: translation_entries,
            descendants_scanned,
            rewrites_planned,
            cold_blob_bytes_written: cold_blob_length,
        },
    })
}

/// **Publish phase**: validate (optional), catch-up scan, fenced rewrites + fsync, SQL transaction
/// (level row + redirect + clear lock), refresh in-memory squash meta, remove plan file.
///
/// Reads the durable plan from `prepared.plan_path`. Both the runtime publish path
/// (chains-coordinator's [`crate::chainstate::stacks::db::StacksChainState::poll_pending_promotions`])
/// and recovery
/// ([`crate::chainstate::stacks::index::squash_recover::recover_pending_promotions`]) call this
/// helper, so the same publish logic runs in both startup and runtime contexts.
///
/// **Policy semantics**:
/// - [`DrainPolicy::TrustPlan`] publishes unconditionally. Used by the synchronous all-in-one
///   entry point and by recovery (which has already run its own canonical-divergence check before
///   reaching this helper).
/// - [`DrainPolicy::Canonical`] validates the plan's `in_range_blocks[*].block_hash` against a
///   live [`crate::chainstate::stacks::index::squash_recover::CanonicalView`] and discards the
///   plan instead of publishing if the view has diverged. This is the runtime stale-tip fix —
///   the chains-coordinator calls this with a view derived from the canonical Stacks chain tip
///   each time it polls a finished worker.
///
/// **Outcome variants** (returned via `DrainOutcome`):
/// - `Published` — level published, plan file removed, in-memory squash meta refreshed.
/// - `DiscardedStale` — `Canonical(view)` flagged divergence; plan abandoned (cold-tail truncate
///   left as best-effort by the caller; not done here so a single failed call can't lose work
///   that was about to be valid on the next coordinator pass).
/// - `Abandoned` — not produced here. Recovery's integrity checks (cold-blob hash mismatch,
///   sidecar mismatch) live in `recover_one_plan`; this helper assumes the prepared bytes are
///   self-consistent.
pub fn apply_prepared_plan<T: MarfTrieId + Send + Sync>(
    marf: &mut MARF<T>,
    prepared: &PreparedPromotion,
    policy: DrainPolicy<'_>,
) -> Result<DrainOutcome, Error> {
    let plan = read_plan_file(&prepared.plan_path)?;

    // ── Optional canonical-divergence gate ────────────────────────
    //
    // Under `DrainPolicy::Canonical(view)` the publish gate validates the plan's recorded
    // canonical chain against the live view. This is the runtime fix for the detached-worker
    // stale-tip publish bug: the worker captures `canonical_tip` at scan-start, but Stacks-level
    // fork resolution at deep heights can flip during sync between scan and publish; if it has,
    // committing the level would record a stale chain that downstream `assert_squash_consistency`
    // checks then trip on.
    if let DrainPolicy::Canonical(view) = policy {
        if let Some(outcome) = check_canonical_divergence(view, &plan)? {
            if let DrainOutcome::DiscardedStale {
                diverging_height,
                recorded_hash,
                canonical_hash,
                ..
            } = &outcome
            {
                let plan_path_disp = prepared.plan_path.display();
                info!(
                    "promotion publish: discarding plan {plan_path_disp} (canonical divergence \
                     at height {diverging_height}: plan recorded {}, current canonical is {:?}); \
                     will clear promotion state and remove plan file",
                    stacks_common::util::hash::to_hex(recorded_hash),
                    canonical_hash.map(|h| stacks_common::util::hash::to_hex(&h)),
                );
            }
            // Same cleanup as recovery's `abandon_plan`: clear the in-flight promotion lock and
            // remove the plan file. Doesn't truncate the cold blob's reserved-but-unpublished
            // region — the next promotion's reserved offset is derived from the top committed
            // level (not file EOF), so the orphan bytes are safely overwritten.
            trie_sql::clear_promotion_state(marf.sqlite_conn())?;
            if let Err(e) = std::fs::remove_file(&prepared.plan_path) {
                let plan_path_disp = prepared.plan_path.display();
                warn!(
                    "promotion publish: failed to remove discarded plan file {plan_path_disp}: \
                     {e} (will retry on next open)",
                );
            }
            return Ok(outcome);
        }
    }

    // ── Shared inner: catch-up + fenced apply + SQL publish + plan-remove ──
    //
    // `publish_prepared_inner` is the unified core both runtime publish (this function) and
    // recovery's `recover_one_plan` route through. It operates on a `&mut Connection` +
    // `&mut HotFileSet` so it doesn't depend on a live `MARF<T>` handle.
    let (db, hot_files) = marf.storage.publish_borrows().ok_or_else(|| {
        Error::CorruptionError("apply_prepared_plan: hot tier must be attached".into())
    })?;
    let (rewrites_applied, _rewrites_skipped) =
        publish_prepared_inner::<T>(db, hot_files, &prepared.plan_path, &plan)?;

    // ── Refresh in-memory squash meta + cold mmap on this handle ──
    //
    // Recovery's open-time call doesn't need this — the open path loads fresh state after
    // recovery. The runtime publish does need it because the live MARF handle holds in-memory
    // squash metadata + a cold-blob mmap that must pick up the new level's bytes.
    marf.refresh_after_squash()?;

    Ok(DrainOutcome::Published {
        level_id: plan.header.level_id,
        in_range_block_count: plan.in_range_blocks.len(),
        rewrites_applied,
    })
}

/// **Shared publish core.** Catch-up scan, plan augmentation, fenced rewrites + fsync, SQL
/// transaction (level row + redirect + clear lock), plan-file remove. Returns
/// `(rewrites_applied, rewrites_skipped)`.
///
/// This is the one publish path used by both:
/// - [`apply_prepared_plan`] (runtime publish via the chains-coordinator's
///   `poll_pending_promotions`), wrapped with the canonical-divergence gate and
///   post-publish `MARF::refresh_after_squash`.
/// - [`crate::chainstate::stacks::index::squash_recover::recover_pending_promotions`] (startup
///   recovery), wrapped with cold-blob/sidecar integrity verification.
///
/// Operates on raw primitives (`&mut Connection`, `&mut HotFileSet`) so it has no dependency on
/// `MARF<T>` and is callable from both contexts. Each per-rewrite entry is classified
/// (`pre_bytes` → apply / `post_bytes` → skip) before the fence is engaged, so the apply phase
/// is idempotent under recovery from a partial pre-crash apply, and bug-tolerant in the runtime
/// case (any unexpected on-disk byte triggers `CorruptionError` rather than overwriting).
pub(crate) fn publish_prepared_inner<T: MarfTrieId>(
    db: &mut rusqlite::Connection,
    hot_files: &mut crate::chainstate::stacks::index::hot_file::HotFileSet,
    plan_path: &Path,
    plan: &SquashPlan,
) -> Result<(usize, usize), Error> {
    use crate::chainstate::stacks::index::squash_recover::classify_rewrite_for_publish;

    // ── Catch-up scan ─────────────────────────────────────────────
    //
    // Walk hot rows committed AFTER `plan.header.tip_at_scan_start` and emit rewrite entries for
    // any in-range backptrs they captured. Under detached-spawn dispatch the coordinator may
    // have committed additional hot rows since the worker snapshotted the watermark, and those
    // rows need their backptrs rewritten too — otherwise reads of those blocks would resolve
    // through stale hot-layout offsets that the cold-blob promotion no longer covers.
    //
    // Crash safety: if the catch-up scan emits new entries, we re-write the plan file
    // atomically with the merged rewrite list *before* applying any pwrites. Recovery (which
    // reloads the plan from disk and replays idempotently) sees the augmented list, so any
    // catch-up rewrite that was applied pre-crash is replayable by witness.
    let in_range_block_ids: HashSet<u32> =
        plan.in_range_blocks.iter().map(|b| b.block_id).collect();
    let catchup_extras = {
        let new_descendants = enumerate_hot_descendants_above_block_id(
            db,
            plan.header.max_height,
            plan.header.tip_at_scan_start,
        )?;
        let reverse_set = build_translation_reverse_set(&plan.translation_map);
        let mut extras: Vec<RewriteEntry> = Vec::new();
        for desc in &new_descendants {
            scan_catchup_descendant(
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

    // Merge background-phase + catch-up entries. De-dupes on `(seq, file_offset)`; sorts for
    // sequential I/O per file.
    let effective_rewrites = if catchup_extras.is_empty() {
        plan.rewrite_plan.clone()
    } else {
        let merged = merge_catchup_into_plan(&plan.rewrite_plan, catchup_extras);
        let augmented = SquashPlan {
            header: plan.header.clone(),
            in_range_blocks: plan.in_range_blocks.clone(),
            translation_map: plan.translation_map.clone(),
            rewrite_plan: merged.clone(),
        };
        write_plan_file_atomic(plan_path, &augmented)?;
        merged
    };

    // ── Classify entries (Phase 1: read with guards) ──────────────
    //
    // Each entry's on-disk bytes are either `pre_bytes` (need apply) or `post_bytes` (already
    // applied — only possible in recovery from a partial pre-crash apply, but the check is a
    // cheap correctness guard in the runtime path too). A neither/nor result is corruption;
    // surface it before engaging the fence.
    //
    // Tricky bit: setting `mutate_pending = true` first and then trying to `read_at` would
    // self-deadlock (our own read would back off forever). So Phase 1 reads without the fence
    // — no concurrent writer exists at this point (the promotion lock is held). Phase 2 then
    // sets the fence and pwrites only the "needs apply" entries.
    let mut rewrites_applied = 0usize;
    let mut rewrites_skipped = 0usize;
    let mut entries_to_apply: Vec<&RewriteEntry> = Vec::new();
    let mut touched_seqs: HashSet<u32> = HashSet::new();
    for entry in &effective_rewrites {
        if classify_rewrite_for_publish(hot_files, entry)? {
            entries_to_apply.push(entry);
            rewrites_applied += 1;
        } else {
            rewrites_skipped += 1;
        }
        touched_seqs.insert(entry.hot_file_seq);
    }

    // ── Phase 2: fenced pwrite + fsync + SQL publish ──────────────
    //
    // Reader-fence protocol: for each hot file the rewrite plan touches, set
    // `mutate_pending = true` and wait for live readers (any `HotFileReadGuard` on this file)
    // to drain before issuing any `pwrite`. Readers arriving while the flag is set back off
    // until it clears (see `HotFileReadGuard::try_from_fence`).
    //
    // Quiesce timeout: 5s. The expected wait is single-digit milliseconds. A timeout signals a
    // stuck reader (likely a bug in a read path that fails to drop its guard, or a deadlock).
    // On timeout we abort the publish with `InProgressError`, leaving the plan file durable
    // for the next RW open's recovery path to retry.
    if !touched_seqs.is_empty() {
        const QUIESCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        // Set `mutate_pending` on every touched file BEFORE waiting on any. Setting them all
        // up front prevents new readers from arriving on file B while we're draining file A.
        for seq in &touched_seqs {
            hot_files.set_mutate_pending(*seq, true)?;
        }

        // Test-only barrier: pauses here (after set_mutate_pending, before wait_for_quiesce)
        // when armed. Lets a peer-reader regression test observe that the fence is engaged
        // before publish progresses. Originally a recovery-only hook; fires on both publish
        // paths now that they share this inner.
        #[cfg(test)]
        test_hooks::maybe_pause_at_recovery_fence(plan_path);

        // Hold the reader fence across BOTH phases of publication: once descendant ptr
        // rewrites become durable, readers must stay blocked until the SQL transaction
        // redirects in-range rows into the same post-promotion address space.
        let rewrite_result = (|| -> Result<(), Error> {
            for seq in &touched_seqs {
                hot_files.wait_for_quiesce(*seq, QUIESCE_TIMEOUT)?;
            }
            for entry in &entries_to_apply {
                hot_files.pwrite_ptr_field(
                    entry.hot_file_seq,
                    entry.file_offset,
                    entry.post_bytes,
                )?;
            }
            for seq in &touched_seqs {
                hot_files.fsync_seq(*seq)?;
            }
            Ok(())
        })();

        #[cfg(test)]
        if rewrite_result.is_ok() {
            test_hooks::maybe_pause_after_rewrite_before_sql(plan_path);
            test_hooks::maybe_pause_after_recovery_rewrite_before_sql(plan_path);
        }

        let sql_result = if rewrite_result.is_ok() {
            publish_level_sql::<T>(db, plan)
        } else {
            Ok(())
        };

        // Always clear `mutate_pending` — whether the rewrite phase or SQL publish failed. If
        // we leave it set on error, readers would block on the next promotion attempt.
        for seq in &touched_seqs {
            if let Err(e) = hot_files.set_mutate_pending(*seq, false) {
                warn!(
                    "publish_prepared_inner: failed to clear mutate_pending on seq={seq}: {e} \
                     (readers may block on next promotion until process restart)",
                );
            }
        }

        rewrite_result?;
        sql_result?;
    } else {
        // No touched seqs (empty rewrite plan, or all entries already applied). Still publish
        // the level row + redirect + clear lock.
        publish_level_sql::<T>(db, plan)?;
    }

    #[cfg(test)]
    test_hooks::maybe_pause_after_sql_commit_before_refresh(plan_path);

    // ── Remove plan file (best-effort) ────────────────────────────
    if let Err(e) = std::fs::remove_file(plan_path) {
        let plan_path_disp = plan_path.display();
        warn!(
            "publish_prepared_inner: failed to remove plan file {plan_path_disp}: {e} \
             (will be retried on next open)",
        );
    }

    Ok((rewrites_applied, rewrites_skipped))
}

/// SQL transaction step shared by [`publish_prepared_inner`]'s two callers (runtime publish via
/// `apply_prepared_plan`, and recovery via `recover_one_plan`). Redirects the in-range
/// `marf_data` rows to the cold blob, writes the level row, and clears the in-flight promotion
/// lock — all inside one transaction so the publish lands atomically.
fn publish_level_sql<T: MarfTrieId>(
    db: &mut rusqlite::Connection,
    plan: &SquashPlan,
) -> Result<(), Error> {
    let tx = db.transaction().map_err(Error::SQLError)?;
    redirect_in_range_blocks_to_cold::<T>(
        &tx,
        &plan.in_range_blocks,
        plan.header.cold_blob_offset,
        plan.header.cold_blob_length,
    )?;
    // Compute the post-publish watermark inside the same SQL transaction. The per-MARF "bytes
    // since last squash" counter treats `block_id > watermark` as the post-publish open suffix.
    // Falls back to the plan header value if the live computation fails (recovery is best-
    // effort on this counter).
    let watermark =
        trie_sql::current_published_max_block_id(&tx).unwrap_or(plan.header.published_max_block_id);
    let level_row = SquashLevelRow {
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
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Build the in-memory merged blob bytes from `prepared.merge.node_store` plus trailer. Mirrors the
/// on-disk layout `publish_squashed_blob` would write: `[BLOB_HEADER_SIZE bytes][tip-reachable
/// nodes...][trailer bytes]`.
fn build_merged_blob_bytes<T: MarfTrieId + Send + Sync>(
    prepared: &PreparedMerge<T>,
) -> Result<Vec<u8>, Error> {
    use crate::chainstate::stacks::index::squash::{SquashTrailer, BLOB_HEADER_SIZE};
    use crate::types::chainstate::BLOCK_HEADER_HASH_ENCODED_SIZE;

    let mut buf = Vec::with_capacity(BLOB_HEADER_SIZE as usize);
    let mut header = [0u8; BLOB_HEADER_SIZE as usize];
    header[..BLOCK_HEADER_HASH_ENCODED_SIZE].copy_from_slice(prepared.tip_block.as_bytes());
    buf.extend_from_slice(&header);

    for i in 0..prepared.merge.tip_reachable_count {
        let node_bytes = prepared.merge.node_store.read_node_bytes(i)?;
        buf.extend_from_slice(&node_bytes);
    }

    // Trailer-offset-in-blob = current `buf.len()` minus the `BLOB_HEADER_SIZE` prefix? No — the
    // legacy code computes it as (write_pos - blob_offset), which here is just `buf.len()` because
    // we wrote the header at offset 0 in the buffer. The trailer footer encodes the trailer-start
    // position relative to the merged blob's beginning, which is `buf.len()` right now.
    let trailer_offset_in_blob = buf.len() as u64;
    let mut trailer_buf = Vec::new();
    let _trailer_bytes_written = prepared.merge.trailer.write_to(&mut trailer_buf)?;
    SquashTrailer::write_footer(&mut trailer_buf, trailer_offset_in_blob)?;
    buf.extend_from_slice(&trailer_buf);
    Ok(buf)
}

/// Build the in-range block list (pairs of `[u8;32]` block_hash + `block_id`) by joining the
/// trailer's per-height block_hashes with the SQL `marf_data.block_id` lookup for each.
///
/// **The trailer is authoritative for in-range membership.** A previous version cross-checked
/// every resolved `block_id` against `translation_map.by_block` keys, but that invariant is
/// wrong: an in-range block whose root is a leaf (or whose root has only backptrs as children)
/// contributes zero entries to `ptr_to_idx` — the merger DFS doesn't add per-height roots
/// themselves to `ptr_to_idx`, only their non-root descendants. The check rejected legitimate
/// promotions on the headers MARF in 2026-05-04 genesis-sync. The full root-handling story is
/// covered by [`crate::chainstate::stacks::index::storage::TrieStorageConnection::squash_opened_root_node_bytes`]
/// at read time — `ROOT_PTR_DISK` is a logical root sentinel served from the
/// `SquashRootNode` sidecar section, not a translated merged-blob offset.
fn build_in_range_block_list<T: MarfTrieId + Send + Sync>(
    prepared: &PreparedMerge<T>,
    conn: &rusqlite::Connection,
) -> Result<Vec<InRangeBlock>, Error> {
    use rusqlite::params;
    let mut blocks = Vec::with_capacity(prepared.merge.trailer.block_hashes.len());
    for hash_bytes in &prepared.merge.trailer.block_hashes {
        let hash_t = T::from_bytes(*hash_bytes);
        let block_id: i64 = conn
            .query_row(
                "SELECT block_id FROM marf_data WHERE block_hash = ?1",
                params![&hash_t],
                |r| r.get(0),
            )
            .map_err(|e| {
                Error::CorruptionError(format!(
                    "build_in_range_block_list: cannot find block_id for trailer hash: {e}"
                ))
            })?;
        let block_id = block_id as u32;
        blocks.push(InRangeBlock {
            block_hash: *hash_bytes,
            block_id,
        });
    }
    Ok(blocks)
}

#[derive(Debug)]
pub(crate) struct HotDescendant {
    pub(crate) block_id: u32,
    pub(crate) storage_seq: u32,
    pub(crate) external_offset: u64,
    pub(crate) external_length: u64,
}

/// Enumerate all hot-tier blocks at heights > `max_height`.
fn enumerate_hot_descendants(
    conn: &rusqlite::Connection,
    max_height: u32,
) -> Result<Vec<HotDescendant>, Error> {
    use rusqlite::params;
    // We don't have a per-MARF height column on `marf_data` — heights live in `block_headers` /
    // `nakamoto_block_headers`. For B5a we enumerate ALL hot rows; the rewrite-emit step filters to
    // backptrs whose `back_block` is in the in-range set, so non- descendant hot blocks contribute
    // zero rewrite entries (still a bit of wasted scan work but bounded by hot-tier size). B5c will
    // tighten the SQL to filter by height.
    let mut stmt = conn.prepare(
        "SELECT block_id, storage_seq, external_offset, external_length \
         FROM marf_data WHERE storage_kind = 1",
    )?;
    let rows = stmt
        .query_map(params![], |row| {
            Ok(HotDescendant {
                block_id: row.get::<_, i64>("block_id")? as u32,
                storage_seq: row.get::<_, i64>("storage_seq")? as u32,
                external_offset: row.get::<_, i64>("external_offset")? as u64,
                external_length: row.get::<_, i64>("external_length")? as u64,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let _ = max_height; // see SQL note above
    Ok(rows)
}

/// Read one descendant's bytes from its hot file, scan with the byte scanner, and append
/// rewrite-plan entries for every backptr whose `back_block` is in `in_range_block_ids`.
///
/// **Hard-fails** if a captured backptr targets an in-range block at a non-root offset but the
/// `(back_block, captured_offset)` pair isn't in the translation map — that signals a real
/// translation-map coverage bug. The `ROOT_PTR_DISK` case is handled separately: those backptrs
/// are intentionally NOT rewritten because `ROOT_PTR_DISK` is a logical root sentinel for
/// reclaim-squashed blocks; reads at runtime route through the `SquashRootNode` sidecar via
/// [`crate::chainstate::stacks::index::storage::TrieStorageConnection::squash_opened_root_node_bytes`]
/// rather than indexing into the merged blob.
fn scan_one_descendant(
    hot_files: &crate::chainstate::stacks::index::hot_file::HotFileSet,
    desc: &HotDescendant,
    in_range_block_ids: &HashSet<u32>,
    translation_map: &TranslationMap,
    rewrite_plan: &mut Vec<RewriteEntry>,
) -> Result<(), Error> {
    let mut block_bytes = vec![0u8; desc.external_length as usize];
    let n = hot_files.read_at(desc.storage_seq, &mut block_bytes, desc.external_offset)?;
    if n != block_bytes.len() {
        return Err(Error::CorruptionError(format!(
            "descendant scan: short read for block_id={} (got {}/{})",
            desc.block_id,
            n,
            block_bytes.len(),
        )));
    }

    // The byte scanner emits via a `FnMut(...)` callback that doesn't propagate errors. We capture
    // into a buffer + emit a recorded miss so the outer code can fail cleanly.
    let block_id = desc.block_id;
    let mut missing_entry: Option<(u32, u32)> = None;
    let mut buffered: Vec<RewriteEntry> = Vec::new();
    scan_serialized_trie_ptr_fields(&block_bytes, desc.external_offset, |sp: ScannedPtr| {
        if missing_entry.is_some() {
            return; // already failing; stop accumulating
        }
        let ptr = sp.ptr;
        if !is_backptr(ptr.id()) {
            return;
        }
        if !in_range_block_ids.contains(&ptr.back_block()) {
            return;
        }
        // ROOT_PTR_DISK is a logical root sentinel for reclaim-squashed in-range blocks: post-
        // promotion the read path serves the per-height root from the `SquashRootNode` sidecar
        // (see `read_node_with_state` / `read_node_type_id` / `read_node_hash` / `MARF::root_copy`,
        // each of which special-cases this ptr). The descendant's bytes legitimately retain
        // `(back_block, ROOT_PTR_DISK)`; no rewrite needed and the absence from the translation
        // map is expected (per-height roots aren't added to `ptr_to_idx`).
        if ptr.ptr() == ROOT_PTR_DISK as u32 {
            return;
        }
        let Some(new_offset) = translation_map.lookup(ptr.back_block(), ptr.ptr()) else {
            missing_entry = Some((ptr.back_block(), ptr.ptr()));
            return;
        };
        buffered.push(RewriteEntry {
            hot_file_seq: desc.storage_seq,
            file_offset: sp.ptr_field_file_offset,
            pre_bytes: ptr.ptr().to_be_bytes(),
            post_bytes: new_offset.to_be_bytes(),
        });
    })?;
    if let Some((back_block, captured_ptr)) = missing_entry {
        return Err(Error::CorruptionError(format!(
            "B5a: descendant block_id={block_id} captured backptr to in-range block_id={back_block} \
             at offset {captured_ptr}, but the merger's translation map has no entry for that \
             offset. Either the descendant scan saw an offset the merger didn't visit (translation- \
             map coverage bug — see `build_translation_map` / scanner emissions) or the \
             descendant block bytes are inconsistent with what the merger observed. Aborting \
             promotion before swap to avoid silent post-promotion corruption."
        )));
    }
    rewrite_plan.extend(buffered);
    Ok(())
}

/// Re-enumerate hot-tier rows with `block_id > watermark` — the "catch-up" set of descendants
/// written between plan-build and swap.
///
/// Same shape as [`enumerate_hot_descendants`] but with a `block_id` filter pushed into the SQL.
/// Under B5d's `thread::scope` dispatch this returns an empty list (coordinator can't append while
/// the worker runs); under fu.2's detached spawn the coordinator may have committed additional hot
/// rows since `tip_at_scan_start` was snapshotted, and those rows show up here.
pub(crate) fn enumerate_hot_descendants_above_block_id(
    conn: &rusqlite::Connection,
    max_height: u32,
    watermark_block_id: u32,
) -> Result<Vec<HotDescendant>, Error> {
    use rusqlite::params;
    let mut stmt = conn.prepare(
        "SELECT block_id, storage_seq, external_offset, external_length \
         FROM marf_data WHERE storage_kind = 1 AND block_id > ?1",
    )?;
    let rows = stmt
        .query_map(params![watermark_block_id as i64], |row| {
            Ok(HotDescendant {
                block_id: row.get::<_, i64>("block_id")? as u32,
                storage_seq: row.get::<_, i64>("storage_seq")? as u32,
                external_offset: row.get::<_, i64>("external_offset")? as u64,
                external_length: row.get::<_, i64>("external_length")? as u64,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let _ = max_height; // see SQL note in `enumerate_hot_descendants`
    Ok(rows)
}

/// Build the reverse view of a [`TranslationMap`]: for each in-range `block_id`, the set of
/// post-promotion offsets the merger would emit. Used by the catch-up scan to recognize
/// "already-applied" ptr fields when recovery re-scans a partially-rewritten descendant (the
/// captured offset is no longer in the forward map but IS a known post-promotion value, so it
/// should be skipped silently rather than treated as corruption).
///
/// Build cost: O(translation map entries). For typical promotion ranges this is tens of thousands
/// of entries — small enough to rebuild per swap rather than persist alongside the plan.
pub(crate) fn build_translation_reverse_set(
    translation_map: &TranslationMap,
) -> std::collections::HashMap<u32, HashSet<u32>> {
    let mut rev: std::collections::HashMap<u32, HashSet<u32>> =
        std::collections::HashMap::with_capacity(translation_map.by_block.len());
    for (block_id, by_offset) in &translation_map.by_block {
        let entry = rev.entry(*block_id).or_default();
        for new_offset in by_offset.values() {
            entry.insert(*new_offset);
        }
    }
    rev
}

/// Catch-up version of [`scan_one_descendant`]. Differs from the background-phase scanner in one
/// respect: when a captured offset targets an in-range block but is not in the forward translation
/// map, this function checks the reverse set before failing.
///
/// - Forward hit (offset is a pre-promotion node-start): emit a rewrite entry with `pre_bytes =
///   captured`, `post_bytes = mapped`.
/// - Reverse hit (offset is a known post-promotion value): the descendant's ptr field has already
///   been rewritten by an earlier swap attempt. Skip silently — the SQL transaction below will pick
///   up the correct level row, and any plan-persisted entry for this same `(seq, file_offset)` will
///   replay idempotently.
/// - Neither: corruption. Same hard-fail semantics as [`scan_one_descendant`].
pub(crate) fn scan_catchup_descendant(
    hot_files: &crate::chainstate::stacks::index::hot_file::HotFileSet,
    desc: &HotDescendant,
    in_range_block_ids: &HashSet<u32>,
    translation_map: &TranslationMap,
    reverse_set: &std::collections::HashMap<u32, HashSet<u32>>,
    rewrite_plan: &mut Vec<RewriteEntry>,
) -> Result<(), Error> {
    let mut block_bytes = vec![0u8; desc.external_length as usize];
    let n = hot_files.read_at(desc.storage_seq, &mut block_bytes, desc.external_offset)?;
    if n != block_bytes.len() {
        return Err(Error::CorruptionError(format!(
            "catch-up scan: short read for block_id={} (got {}/{})",
            desc.block_id,
            n,
            block_bytes.len(),
        )));
    }

    let block_id = desc.block_id;
    let mut missing_entry: Option<(u32, u32)> = None;
    let mut buffered: Vec<RewriteEntry> = Vec::new();
    scan_serialized_trie_ptr_fields(&block_bytes, desc.external_offset, |sp: ScannedPtr| {
        if missing_entry.is_some() {
            return;
        }
        let ptr = sp.ptr;
        if !is_backptr(ptr.id()) {
            return;
        }
        if !in_range_block_ids.contains(&ptr.back_block()) {
            return;
        }
        // ROOT_PTR_DISK is a logical root sentinel; mirror `scan_one_descendant`'s special case.
        // The descendant's bytes legitimately retain `(back_block, ROOT_PTR_DISK)`; reads at
        // runtime route through the `SquashRootNode` sidecar.
        if ptr.ptr() == ROOT_PTR_DISK as u32 {
            return;
        }
        if let Some(new_offset) = translation_map.lookup(ptr.back_block(), ptr.ptr()) {
            buffered.push(RewriteEntry {
                hot_file_seq: desc.storage_seq,
                file_offset: sp.ptr_field_file_offset,
                pre_bytes: ptr.ptr().to_be_bytes(),
                post_bytes: new_offset.to_be_bytes(),
            });
            return;
        }
        if reverse_set
            .get(&ptr.back_block())
            .is_some_and(|s| s.contains(&ptr.ptr()))
        {
            // Already rewritten by an earlier (partial) swap attempt.
            return;
        }
        missing_entry = Some((ptr.back_block(), ptr.ptr()));
    })?;
    if let Some((back_block, captured_ptr)) = missing_entry {
        return Err(Error::CorruptionError(format!(
            "B5d-fu.1 catch-up: descendant block_id={block_id} captured backptr to in-range \
             block_id={back_block} at offset {captured_ptr}, neither in the merger's translation \
             map nor in its reverse (post-promotion) set. Aborting swap to avoid silent corruption."
        )));
    }
    rewrite_plan.extend(buffered);
    Ok(())
}

/// Run the catch-up scan: walk hot rows above `tip_at_scan_start`, emit rewrite entries for any
/// that capture in-range backptrs, merge with the existing rewrite plan (de-duplicating on
/// `(hot_file_seq, file_offset)`), and return the merged + sorted vec. If `extras.is_empty()`,
/// returns the input plan unchanged.
///
/// **De-dup policy.** A given `(seq, file_offset)` should appear at most once in the merged plan.
/// Background-phase entries take precedence (they were captured against the merger's authoritative
/// snapshot); catch-up entries that collide on the same offset are dropped. In practice this can
/// only happen if a descendant was enumerated by both the background phase and the catch-up scan,
/// which the watermark filter prevents — but we de-dup defensively to keep the swap idempotent
/// under any future enumeration overlap.
pub(crate) fn merge_catchup_into_plan(
    background_plan: &[RewriteEntry],
    extras: Vec<RewriteEntry>,
) -> Vec<RewriteEntry> {
    if extras.is_empty() {
        let mut out = background_plan.to_vec();
        out.sort_by_key(|e| (e.hot_file_seq, e.file_offset));
        return out;
    }
    let mut seen: HashSet<(u32, u64)> = background_plan
        .iter()
        .map(|e| (e.hot_file_seq, e.file_offset))
        .collect();
    let mut merged: Vec<RewriteEntry> = background_plan.to_vec();
    for e in extras {
        if seen.insert((e.hot_file_seq, e.file_offset)) {
            merged.push(e);
        }
    }
    merged.sort_by_key(|e| (e.hot_file_seq, e.file_offset));
    merged
}

/// Redirect every row in `in_range_blocks` to point at `(offset, length)` in the cold blob,
/// flipping `storage_kind` to `Cold` and `storage_seq` to `0`. Prepares the UPDATE once and reuses
/// it across all binds — equivalent to calling [`trie_sql::update_external_trie_blob_by_hash`] in a
/// loop, but without re-paying SQL parse/plan/statement-allocation overhead per row.
///
/// Caller is responsible for the surrounding transaction; both production call sites (the
/// promotion swap and recovery replay) wrap this in the same transaction that writes the level row
/// and clears `promotion_state`, so the redirect commits atomically with the level publish.
///
/// Returns the total rows updated. On a healthy DB this equals `in_range_blocks.len()`; a smaller
/// value means some `block_hash` didn't match an existing row, which the caller may treat as
/// corruption.
pub(crate) fn redirect_in_range_blocks_to_cold<T: MarfTrieId>(
    conn: &rusqlite::Connection,
    in_range_blocks: &[InRangeBlock],
    offset: u64,
    length: u64,
) -> Result<usize, Error> {
    use rusqlite::params;
    let empty_blob: &[u8] = &[];
    let mut stmt = conn.prepare(
        "UPDATE marf_data SET external_offset = ?1, external_length = ?2, data = ?3, \
         storage_kind = 0, storage_seq = 0 \
         WHERE block_hash = ?4",
    )?;
    let mut updated = 0usize;
    for r in in_range_blocks {
        let bhh = T::from_bytes(r.block_hash);
        updated += stmt.execute(params![offset as i64, length as i64, empty_blob, &bhh])?;
    }
    Ok(updated)
}

/// Set the per-MARF promotion lock fields in `marf_state`.
fn set_promotion_lock(
    conn: &rusqlite::Connection,
    level_id: u32,
    offset: u64,
    length: u64,
) -> Result<(), Error> {
    use rusqlite::params;
    conn.execute(
        "UPDATE marf_state SET promotion_in_progress = ?1, \
         promotion_reserved_offset = ?2, promotion_reserved_length = ?3 WHERE id = 1",
        params![level_id as i64, offset as i64, length as i64],
    )?;
    Ok(())
}

/// Hash `bytes` with the codebase's standard MARF hasher (Sha512_256).
fn sha512_256_of(bytes: &[u8]) -> TrieHash {
    let mut hasher = Sha512_256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_slice());
    TrieHash(arr)
}

/// Test-only fault-injection hooks. Production builds compile these away via `#[cfg(test)]`.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::Cell;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use parking_lot::Mutex;

    thread_local! {
        /// When `true` on the current thread, `run_horizon_gated_promotion` returns an error
        /// immediately after `write_plan_file_atomic` succeeds, leaving the cold blob, sidecar, and
        /// plan file on disk for `recover_pending_promotions` to drive forward.
        ///
        /// **Thread-local** so concurrent tests (under cargo's default per-test threads) don't
        /// share the flag. A test that arms the fault on its own thread observes it on the same
        /// thread where `run_horizon_gated_promotion` runs (B5a/b call promotion synchronously from
        /// the test). Tests that don't arm see the default `false` — no leakage.
        ///
        /// The earlier process-global `AtomicBool` had a leak: if test A armed the fault and test B
        /// (running concurrently on another thread) called `run_horizon_gated_promotion`, B's
        /// promotion would observe and consume the fault meant for A. Switching to thread-local
        /// closes that.
        static ABORT_AFTER_PLAN_WRITE: Cell<bool> = const { Cell::new(false) };

        /// When `Some(value)`, plan-build uses `value` as the `tip_at_scan_start` watermark instead
        /// of the live `current_published_max_block_id` query. Lets fu.1 tests force a scenario
        /// where the catch-up scan has work to do even under the synchronous (`thread::scope`)
        /// dispatch model — necessary because the catch-up scan can only emit non-empty results
        /// when there are descendants committed AFTER the watermark, which doesn't naturally happen
        /// when the coordinator is blocked on the worker's join.
        ///
        /// Thread-local for the same reason as [`ABORT_AFTER_PLAN_WRITE`].
        static FORCE_TIP_AT_SCAN_START: Cell<Option<u32>> = const { Cell::new(None) };
    }

    /// Arm the abort-after-plan-write fault on the current thread.
    ///
    /// The next `run_horizon_gated_promotion` call ON THIS THREAD returns `NotSupportedError("test
    /// fault: aborted after plan write")` AFTER persisting the plan file but BEFORE the swap.
    pub fn arm_abort_after_plan_write() {
        ABORT_AFTER_PLAN_WRITE.with(|f| f.set(true));
    }

    /// Disarm the fault on the current thread.
    pub fn disarm_abort_after_plan_write() {
        ABORT_AFTER_PLAN_WRITE.with(|f| f.set(false));
    }

    /// Read-and-clear: returns the current armed state on this thread and resets to disarmed. The
    /// "clear" semantics ensure a single armed fault fires exactly once on the thread that armed
    /// it.
    pub(crate) fn abort_after_plan_write_armed() -> bool {
        ABORT_AFTER_PLAN_WRITE.with(|f| f.replace(false))
    }

    /// Force the next plan-build's `tip_at_scan_start` to `value` on this thread. Pass `None` to
    /// restore the default behavior (use `current_published_max_block_id` at scan time). Sticky — a
    /// test that arms must call `force_tip_at_scan_start(None)` to disarm. (Unlike
    /// `ABORT_AFTER_PLAN_WRITE`, this hook is read-without-clear so a single test can issue
    /// multiple promotions under the same forced watermark.)
    pub fn force_tip_at_scan_start(value: Option<u32>) {
        FORCE_TIP_AT_SCAN_START.with(|f| f.set(value));
    }

    /// Read the current forced `tip_at_scan_start` override (if any)
    /// without clearing it.
    pub(crate) fn forced_tip_at_scan_start() -> Option<u32> {
        FORCE_TIP_AT_SCAN_START.with(|f| f.get())
    }

    /// Per-test pause barrier for the live swap path's semantic window after descendant rewrites
    /// have been pwritten + fsynced and the reader fence has been cleared, but before the SQL
    /// transaction flips in-range `marf_data` rows to `Cold`. During this pause a peer reader sees
    /// exactly the same state as the live 2026-05-04 clarity panic: rewritten descendant ptr bytes
    /// are visible, while their in-range targets may still be addressed through pre-publish hot
    /// rows.
    pub struct SwapPostRewriteBarrier {
        target_path: PathBuf,
        reached: AtomicBool,
        released: AtomicBool,
    }

    impl SwapPostRewriteBarrier {
        pub fn wait_until_reached(&self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.reached.load(Ordering::SeqCst) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            false
        }

        pub fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            let mut slot = ACTIVE_SWAP_POST_REWRITE_BARRIER.lock();
            let still_ours = slot
                .as_ref()
                .map(|active| active.target_path == self.target_path)
                .unwrap_or(false);
            if still_ours {
                *slot = None;
            }
        }
    }

    static ACTIVE_SWAP_POST_REWRITE_BARRIER: Mutex<Option<Arc<SwapPostRewriteBarrier>>> =
        Mutex::new(None);

    /// Arm a barrier targeted at `db_path`. `apply_swap_phase` will pause after descendant
    /// rewrites have been fsynced but BEFORE the SQL transaction begins, while the reader fence is
    /// still engaged, as long as the plan file lives in the same parent directory.
    pub fn arm_swap_post_rewrite_barrier(
        db_path: impl Into<PathBuf>,
    ) -> Arc<SwapPostRewriteBarrier> {
        let barrier = Arc::new(SwapPostRewriteBarrier {
            target_path: db_path.into(),
            reached: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        let mut slot = ACTIVE_SWAP_POST_REWRITE_BARRIER.lock();
        assert!(
            slot.is_none(),
            "swap post-rewrite barrier already armed by another test (must release first)"
        );
        *slot = Some(Arc::clone(&barrier));
        barrier
    }

    /// Called by `apply_swap_phase` once descendant rewrites are durable, but before the SQL
    /// transaction flips in-range rows to `Cold`. The reader fence is still engaged here.
    pub(crate) fn maybe_pause_after_rewrite_before_sql(plan_path: &Path) {
        let barrier = ACTIVE_SWAP_POST_REWRITE_BARRIER.lock().clone();
        let Some(barrier) = barrier else {
            return;
        };
        let plan_parent = plan_path.parent();
        let target_parent = barrier.target_path.parent();
        if plan_parent != target_parent {
            return;
        }
        barrier.reached.store(true, Ordering::SeqCst);
        while !barrier.released.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Per-test pause barrier for the later swap window after the SQL transaction has committed,
    /// but before the worker refreshes its in-memory squash metadata and removes the plan file.
    ///
    /// This window should reflect the fully published on-disk state as seen by a fresh peer
    /// handle. If failures disappear here but still reproduce in the earlier barrier, that
    /// strongly suggests the live bug needs the mixed "rewritten descendants + pre-publish SQL"
    /// state rather than merely "worker still finishing up after commit".
    pub struct SwapPostSqlBarrier {
        target_path: PathBuf,
        reached: AtomicBool,
        released: AtomicBool,
    }

    impl SwapPostSqlBarrier {
        pub fn wait_until_reached(&self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.reached.load(Ordering::SeqCst) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            false
        }

        pub fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            let mut slot = ACTIVE_SWAP_POST_SQL_BARRIER.lock();
            let still_ours = slot
                .as_ref()
                .map(|active| active.target_path == self.target_path)
                .unwrap_or(false);
            if still_ours {
                *slot = None;
            }
        }
    }

    static ACTIVE_SWAP_POST_SQL_BARRIER: Mutex<Option<Arc<SwapPostSqlBarrier>>> = Mutex::new(None);

    /// Arm a barrier targeted at `db_path`. `apply_swap_phase` will pause after the SQL
    /// transaction commits and before the worker refreshes its handle state, as long as the plan
    /// file lives in the same parent directory.
    pub fn arm_swap_post_sql_barrier(db_path: impl Into<PathBuf>) -> Arc<SwapPostSqlBarrier> {
        let barrier = Arc::new(SwapPostSqlBarrier {
            target_path: db_path.into(),
            reached: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        let mut slot = ACTIVE_SWAP_POST_SQL_BARRIER.lock();
        assert!(
            slot.is_none(),
            "swap post-sql barrier already armed by another test (must release first)"
        );
        *slot = Some(Arc::clone(&barrier));
        barrier
    }

    /// Called by `apply_swap_phase` after the SQL transaction has committed and the on-disk state
    /// is fully published, but before `refresh_after_squash` / plan-file removal.
    pub(crate) fn maybe_pause_after_sql_commit_before_refresh(plan_path: &Path) {
        let barrier = ACTIVE_SWAP_POST_SQL_BARRIER.lock().clone();
        let Some(barrier) = barrier else {
            return;
        };
        let plan_parent = plan_path.parent();
        let target_parent = barrier.target_path.parent();
        if plan_parent != target_parent {
            return;
        }
        barrier.reached.store(true, Ordering::SeqCst);
        while !barrier.released.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Per-test pause barrier for the recovery path's later mixed-state window after rewrites are
    /// durable but before the SQL transaction publishes the level row. Like the live promotion
    /// path, the reader fence remains engaged here.
    pub struct RecoveryPostRewriteBarrier {
        target_path: PathBuf,
        reached: AtomicBool,
        released: AtomicBool,
    }

    impl RecoveryPostRewriteBarrier {
        pub fn wait_until_reached(&self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.reached.load(Ordering::SeqCst) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            false
        }

        pub fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            let mut slot = ACTIVE_RECOVERY_POST_REWRITE_BARRIER.lock();
            let still_ours = slot
                .as_ref()
                .map(|active| active.target_path == self.target_path)
                .unwrap_or(false);
            if still_ours {
                *slot = None;
            }
        }
    }

    static ACTIVE_RECOVERY_POST_REWRITE_BARRIER: Mutex<Option<Arc<RecoveryPostRewriteBarrier>>> =
        Mutex::new(None);

    /// Arm a barrier targeted at `db_path`. `replay_plan` will pause after descendant rewrites
    /// have been fsynced but BEFORE the recovery SQL transaction begins, while the reader fence is
    /// still engaged.
    pub fn arm_recovery_post_rewrite_barrier(
        db_path: impl Into<PathBuf>,
    ) -> Arc<RecoveryPostRewriteBarrier> {
        let barrier = Arc::new(RecoveryPostRewriteBarrier {
            target_path: db_path.into(),
            reached: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        let mut slot = ACTIVE_RECOVERY_POST_REWRITE_BARRIER.lock();
        assert!(
            slot.is_none(),
            "recovery post-rewrite barrier already armed by another test (must release first)"
        );
        *slot = Some(Arc::clone(&barrier));
        barrier
    }

    /// Called by `replay_plan` once descendant rewrites are durable, but before the SQL
    /// transaction publishes the level row. The reader fence is still engaged here.
    pub(crate) fn maybe_pause_after_recovery_rewrite_before_sql(plan_path: &Path) {
        let barrier = ACTIVE_RECOVERY_POST_REWRITE_BARRIER.lock().clone();
        let Some(barrier) = barrier else {
            return;
        };
        let plan_parent = plan_path.parent();
        let target_parent = barrier.target_path.parent();
        if plan_parent != target_parent {
            return;
        }
        barrier.reached.store(true, Ordering::SeqCst);
        while !barrier.released.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Per-test pause barrier for the recovery path's apply phase. Wired into `replay_plan` via
    /// [`maybe_pause_at_recovery_fence`]: after `set_mutate_pending(true)` is called for every
    /// touched hot-file seq but BEFORE `wait_for_quiesce` runs, recovery checks for an active
    /// barrier whose target path matches its plan file's parent directory; if matched, recovery
    /// signals `reached` and parks until the test calls `release()`.
    ///
    /// Lets a test set up the precise scenario "fence is engaged (mutate_pending = true) but the
    /// apply hasn't progressed" so peer readers can be observed back-pressuring on the cross-handle
    /// fence.
    pub struct RecoveryFenceBarrier {
        target_path: PathBuf,
        reached: AtomicBool,
        released: AtomicBool,
    }

    impl RecoveryFenceBarrier {
        /// Spin-wait until recovery enters the barrier (signals `reached`), with a hard timeout.
        /// Returns whether recovery reached the barrier in time.
        pub fn wait_until_reached(&self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.reached.load(Ordering::SeqCst) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            false
        }

        /// Release recovery from the barrier and clear the active slot.
        ///
        /// Recovery resumes on the next poll of `released`.
        ///
        /// Idempotent — only clears the slot if the active entry still belongs to this barrier
        /// (matched by `target_path`), so a double-release after another test re-armed doesn't
        /// stomp the new entry.
        pub fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            let mut slot = ACTIVE_BARRIER.lock();
            let still_ours = slot
                .as_ref()
                .map(|active| active.target_path == self.target_path)
                .unwrap_or(false);
            if still_ours {
                *slot = None;
            }
        }
    }

    /// Active barrier slot. At most one armed at a time; concurrent arm attempts panic via the
    /// `assert!` in `arm_recovery_fence_barrier`. Tests must release before returning to keep the
    /// slot available for the next test.
    static ACTIVE_BARRIER: Mutex<Option<Arc<RecoveryFenceBarrier>>> = Mutex::new(None);

    /// Arm a recovery-fence barrier targeted at `db_path`. Recovery's `replay_plan` will pause when
    /// its plan file's parent directory matches this path's parent directory, so the test can
    /// observe the in-fence state from outside.
    ///
    /// Panics if another test already armed a barrier without releasing — tests using this hook
    /// must run serialized OR must always release in cleanup. (Test paths are typically
    /// per-`tmp_dir`, so the chance of accidental cross-test matching via the parent-dir comparison
    /// is low.)
    pub fn arm_recovery_fence_barrier(db_path: impl Into<PathBuf>) -> Arc<RecoveryFenceBarrier> {
        let barrier = Arc::new(RecoveryFenceBarrier {
            target_path: db_path.into(),
            reached: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        let mut slot = ACTIVE_BARRIER.lock();
        assert!(
            slot.is_none(),
            "recovery-fence barrier already armed by another test (must release first)"
        );
        *slot = Some(Arc::clone(&barrier));
        barrier
    }

    /// Called by `replay_plan` after `set_mutate_pending(true)` and before `wait_for_quiesce`. If
    /// an active barrier targets this plan's path, signals `reached` and parks until released.
    ///
    /// Path matching: compares the parent directory of `plan_path` to the parent directory of the
    /// barrier's target path. The plan file lives at `<db_path>.squash_pending.<level>.plan`, so
    /// its parent is the db_path's parent. Tests using `tempdir`-style isolation get unique
    /// parents.
    pub(crate) fn maybe_pause_at_recovery_fence(plan_path: &Path) {
        let barrier = ACTIVE_BARRIER.lock().clone();
        let Some(barrier) = barrier else {
            return;
        };
        let plan_parent = plan_path.parent();
        let target_parent = barrier.target_path.parent();
        if plan_parent != target_parent {
            return;
        }
        barrier.reached.store(true, Ordering::SeqCst);
        while !barrier.released.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Per-test pause barrier for the prepare phase's post-enumerate window — the wall-clock
    /// spot where the buggy ordering captured `tip_at_scan_start`. Wired into
    /// `prepare_promotion` via [`maybe_pause_after_descendant_enumerate`]: AFTER
    /// `enumerate_hot_descendants` returns and the initial descendant scan has run, prepare
    /// checks for an active barrier whose target path matches the worker's `db_path`; if
    /// matched, prepare signals `reached` and parks until the test calls `release()`.
    ///
    /// Lets a test inject a concurrent commit (via a peer MARF handle) at exactly the spot
    /// where the watermark-vs-enumerate race lived. Under the corrected ordering, the
    /// watermark was already captured BEFORE enumerate, so a commit landing in this barrier
    /// has `block_id > tip_at_scan_start` — the initial scan misses it (committed after
    /// enumerate ran), but the catch-up filter `> watermark` at publish time covers it.
    /// Under the (hypothetical) regression where watermark capture moved back here, the
    /// watermark would equal the new commit's block_id and catch-up would miss it too —
    /// exactly the mainnet level-8 race.
    pub struct AfterDescendantEnumerateBarrier {
        target_path: PathBuf,
        reached: AtomicBool,
        released: AtomicBool,
    }

    impl AfterDescendantEnumerateBarrier {
        pub fn wait_until_reached(&self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.reached.load(Ordering::SeqCst) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            false
        }

        pub fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            let mut slot = ACTIVE_AFTER_DESCENDANT_ENUMERATE_BARRIER.lock();
            let still_ours = slot
                .as_ref()
                .map(|active| active.target_path == self.target_path)
                .unwrap_or(false);
            if still_ours {
                *slot = None;
            }
        }
    }

    static ACTIVE_AFTER_DESCENDANT_ENUMERATE_BARRIER: Mutex<
        Option<Arc<AfterDescendantEnumerateBarrier>>,
    > = Mutex::new(None);

    /// Arm a prepare-phase barrier targeted at `db_path`. The next `prepare_promotion` call
    /// against a MARF whose db_path matches will pause between watermark snapshot and
    /// descendant enumerate.
    ///
    /// Panics if another barrier of this kind is already armed.
    pub fn arm_after_descendant_enumerate_barrier(
        db_path: impl Into<PathBuf>,
    ) -> Arc<AfterDescendantEnumerateBarrier> {
        let barrier = Arc::new(AfterDescendantEnumerateBarrier {
            target_path: db_path.into(),
            reached: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        let mut slot = ACTIVE_AFTER_DESCENDANT_ENUMERATE_BARRIER.lock();
        assert!(
            slot.is_none(),
            "post-watermark-pre-enumerate barrier already armed by another test \
             (must release first)"
        );
        *slot = Some(Arc::clone(&barrier));
        barrier
    }

    /// Called by `prepare_promotion` after `tip_at_scan_start` is captured and before
    /// `enumerate_hot_descendants` runs. If an active barrier matches `db_path`, signals
    /// `reached` and parks until released.
    pub(crate) fn maybe_pause_after_descendant_enumerate(db_path: &str) {
        let barrier = ACTIVE_AFTER_DESCENDANT_ENUMERATE_BARRIER.lock().clone();
        let Some(barrier) = barrier else {
            return;
        };
        if barrier.target_path != Path::new(db_path) {
            return;
        }
        barrier.reached.store(true, Ordering::SeqCst);
        while !barrier.released.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `merge_catchup_into_plan` with no extras returns the background plan sorted by `(seq,
    /// file_offset)`.
    #[test]
    fn merge_catchup_into_plan_no_extras_just_sorts() {
        let bg = vec![
            RewriteEntry {
                hot_file_seq: 2,
                file_offset: 100,
                pre_bytes: [0, 0, 0, 1],
                post_bytes: [0, 0, 0, 2],
            },
            RewriteEntry {
                hot_file_seq: 1,
                file_offset: 50,
                pre_bytes: [0, 0, 0, 3],
                post_bytes: [0, 0, 0, 4],
            },
        ];
        let merged = merge_catchup_into_plan(&bg, vec![]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].hot_file_seq, 1);
        assert_eq!(merged[1].hot_file_seq, 2);
    }

    /// `merge_catchup_into_plan` dedupes catch-up entries that collide with background-phase
    /// entries on `(seq, file_offset)`, keeping the background-phase entry. This is the
    /// load-bearing invariant that makes `b5d_fu_1_catchup_with_forced_low_watermark` safe —
    /// without dedup, the catch-up scan's re-emissions would produce duplicate pwrites.
    #[test]
    fn merge_catchup_into_plan_dedupes_collisions_keeps_background() {
        let bg = vec![RewriteEntry {
            hot_file_seq: 1,
            file_offset: 100,
            pre_bytes: [0xaa, 0, 0, 0],
            post_bytes: [0xbb, 0, 0, 0],
        }];
        // Catch-up emits a colliding entry with different bytes — we should keep the background
        // one.
        let extras = vec![RewriteEntry {
            hot_file_seq: 1,
            file_offset: 100,
            pre_bytes: [0xcc, 0, 0, 0],
            post_bytes: [0xdd, 0, 0, 0],
        }];
        let merged = merge_catchup_into_plan(&bg, extras);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].pre_bytes, [0xaa, 0, 0, 0]);
        assert_eq!(merged[0].post_bytes, [0xbb, 0, 0, 0]);
    }

    /// `merge_catchup_into_plan` keeps catch-up entries that don't collide and produces a unified,
    /// sorted output.
    #[test]
    fn merge_catchup_into_plan_appends_non_colliding_extras() {
        let bg = vec![RewriteEntry {
            hot_file_seq: 1,
            file_offset: 100,
            pre_bytes: [0, 0, 0, 1],
            post_bytes: [0, 0, 0, 2],
        }];
        let extras = vec![
            RewriteEntry {
                hot_file_seq: 1,
                file_offset: 200, // different offset
                pre_bytes: [0, 0, 0, 3],
                post_bytes: [0, 0, 0, 4],
            },
            RewriteEntry {
                hot_file_seq: 2, // different seq
                file_offset: 100,
                pre_bytes: [0, 0, 0, 5],
                post_bytes: [0, 0, 0, 6],
            },
        ];
        let merged = merge_catchup_into_plan(&bg, extras);
        assert_eq!(merged.len(), 3);
        // Sorted by (seq, file_offset).
        assert_eq!((merged[0].hot_file_seq, merged[0].file_offset), (1, 100));
        assert_eq!((merged[1].hot_file_seq, merged[1].file_offset), (1, 200));
        assert_eq!((merged[2].hot_file_seq, merged[2].file_offset), (2, 100));
    }

    /// `build_translation_reverse_set` produces, for each block_id, the set of post-promotion
    /// offsets (the values, not the keys, of the per-block forward map).
    #[test]
    fn build_translation_reverse_set_collects_post_offsets_per_block() {
        let mut tm = TranslationMap::default();
        tm.insert(
            /* block_id */ 5, /* old */ 100, /* new */ 1000,
        );
        tm.insert(5, 200, 2000);
        tm.insert(7, 300, 3000);

        let rev = build_translation_reverse_set(&tm);
        assert_eq!(rev.len(), 2);
        assert!(rev.get(&5).unwrap().contains(&1000));
        assert!(rev.get(&5).unwrap().contains(&2000));
        assert_eq!(rev.get(&5).unwrap().len(), 2);
        assert!(rev.get(&7).unwrap().contains(&3000));
        assert_eq!(rev.get(&7).unwrap().len(), 1);
        // Pre-promotion offsets do NOT appear in the reverse set — this is the property that lets
        // the catch-up scan distinguish "captured pre-promotion offset" from "captured
        // post-promotion offset (already applied)".
        assert!(!rev.get(&5).unwrap().contains(&100));
        assert!(!rev.get(&5).unwrap().contains(&200));
    }
}
