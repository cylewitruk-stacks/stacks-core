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

//! Phase C hot-reclaim sweep: candidate enumeration, canonical-chain precompute, and per-file
//! unlinkability classification.
//!
//! See [.docs/squashing-v1.5-phase-c.md](../../../../../.docs/squashing-v1.5-phase-c.md) for the
//! full design + slicing. This module ships C1 (enumeration + canonical-chain precompute) and
//! **C2a** (per-row + per-file *tentative* classifier). C2b (the cross-file orphan-ancestry closure
//! precompute that finalizes a tentative `Unlinkable`) and C3 (DELETE-rows + unlink under reader
//! fence) build on this; C4 wires the trigger into `maybe_squash`.
//!
//! The load-bearing design choice for C1 is **file-inventory-first** enumeration: candidates come
//! from the actual on-disk [`HotFileSet::iter()`] (filtered to non-active), with `marf_data` row
//! metadata attached afterward. A SQL-first enumeration (`WHERE storage_kind = 1 GROUP BY
//! storage_seq`) silently drops the most-reclaimable case — a file whose every row has flipped to
//! `storage_kind = 0` after promotion has zero matching SQL rows and disappears from the GROUP BY
//! result entirely, but the file is still on disk and is the unconditionally-unlinkable "all blocks
//! promoted" case from [squashing-v1.5.md §7.1(a)](../../../../../.docs/squashing-v1.5.md).
//!
//! The load-bearing design choice for C2a is **tentative** verdicts: [`classify_hot_file_tentative`]
//! never returns a final `Unlinkable` on its own. A file that looks reclaimable from purely per-row
//! reasoning is still subject to the cross-file orphan-ancestry closure check (§7.3 / §4.3), which
//! C2b implements. Splitting the per-row reasoning here from the cross-file closure walk in C2b
//! keeps each piece independently testable and matches the natural data-flow boundary: this module's
//! caller (C4) will fan out tentative verdicts across all candidate files, then run a single
//! sweep-wide closure precompute over the collected retained orphans before promoting any tentative
//! `Unlinkable` to a final one.

use std::collections::{HashMap, HashSet};

use stacks_common::types::chainstate::{StacksBlockId, BLOCK_HEADER_HASH_ENCODED_SIZE};

use crate::chainstate::stacks::index::hot_file::HotFileSet;
use crate::chainstate::stacks::index::trie_sql::{self, LiveHotRow, StorageKind};
use crate::chainstate::stacks::index::{Error, MarfTrieId, SENTINEL_ARRAY};

/// One non-active hot file under sweep consideration, paired with whatever `marf_data` rows still
/// reference it.
///
/// `live_rows.is_empty()` is the load-bearing "all blocks promoted" case — the file is
/// unconditionally unlinkable per [squashing-v1.5.md
/// §7.1(a)](../../../../../.docs/squashing-v1.5.md) and C2's classifier short-circuits without
/// per-row work.
#[derive(Debug, Clone)]
pub struct HotFileSweepCandidate<T: MarfTrieId> {
    /// Hot-file sequence number (`marf_state.active_hot_seq` is excluded by the enumerator, so this
    /// is always a non-active seq).
    pub seq: u32,
    /// `marf_data` rows that still reference this file. Empty Vec means "all promoted" (or "never
    /// had any rows" — same outcome for sweep purposes: nothing to classify, file is
    /// unconditionally unlinkable).
    pub live_rows: Vec<LiveHotRow<T>>,
}

/// Enumerate non-active hot files on disk and attach their live `marf_data` rows.
///
/// **File-inventory-first** (per [phase-c §3.1](../../../../../.docs/squashing-v1.5-phase-c.md)):
/// the candidate set comes from [`HotFileSet::iter()`], not from a SQL `GROUP BY storage_seq`. This
/// guarantees that a fully-promoted file with zero `storage_kind = 1` rows (the most-reclaimable
/// case) still appears in the result with `live_rows.is_empty()`.
///
/// The active file (`HotFileSet::active_seq()`) is excluded — the writer is appending to it and it
/// is never a sweep candidate.
///
/// Per-candidate row enumeration uses [`trie_sql::hot_rows_for_seq`] which queries the partial
/// index `idx_marf_data_hot ON marf_data(storage_seq) WHERE storage_kind = 1`, so cost is
/// O(live-row-count-for-this-seq) per candidate.
pub fn enumerate_hot_files_for_sweep<T: MarfTrieId>(
    hot_files: &HotFileSet,
    conn: &rusqlite::Connection,
) -> Result<Vec<HotFileSweepCandidate<T>>, Error> {
    let active_seq = hot_files.active_seq();
    let mut candidates: Vec<HotFileSweepCandidate<T>> = hot_files
        .iter()
        .filter_map(|(seq, _hot)| if seq == active_seq { None } else { Some(seq) })
        .map(|seq| {
            let live_rows = trie_sql::hot_rows_for_seq::<T>(conn, seq)?;
            Ok(HotFileSweepCandidate { seq, live_rows })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    // Oldest-to-newest ordering matches the §7.4 sweep direction (older files crossed the horizon
    // first, more likely to be fully reclaimable). Sorting here means C4's loop can iterate the
    // returned Vec directly without re-sorting.
    candidates.sort_by_key(|c| c.seq);
    Ok(candidates)
}

/// Build the canonical-chain `height → index_block_hash` map covering `[low_height, tip_height]`,
/// suitable for sweep's orphan-detection step (per [squashing-v1.5.md
/// §7.2](../../../../../.docs/squashing-v1.5.md)).
///
/// **Why a height-keyed map and not a flat hash-set.** The underlying walker
/// (`StacksChainState::precompute_canonical_ancestors_for_sweep`) returns a **partial** `height →
/// canonical_hash` map when ancestry is truncated (a missing intermediate row in `block_headers` /
/// `nakamoto_block_headers`), and the contract is "treat unmapped heights as **skip**, not as
/// non-canonical." Flattening into a `HashSet<StacksBlockId>` would erase that distinction: a
/// canonical block whose height is below a truncation point would silently classify as an orphan in
/// C2, and the sweep could then reclaim canonical state.
///
/// C2's orphan classifier MUST consult the map by height, with this three-state predicate:
///
/// | `map.get(row_height)`            | classification                  |
/// | -------------------------------- | ------------------------------- |
/// | `Some(h) if h == row.block_hash` | canonical                       |
/// | `Some(h)` (mismatch)             | orphan candidate                |
/// | `None`                           | unknown (skip; do NOT reclaim)  |
///
/// Returns an empty map if `low_height > tip_height` (no levels loaded — sweep has nothing to do
/// anyway). Cost: O(tip_height − low_height + 1) — the underlying walk reads one row per height.
pub fn canonical_chain_for_sweep(
    chainstate_db: &rusqlite::Connection,
    tip: &StacksBlockId,
    tip_height: u32,
    low_height: u32,
) -> Result<HashMap<u32, StacksBlockId>, Error> {
    crate::chainstate::stacks::db::StacksChainState::precompute_canonical_ancestors_for_sweep(
        chainstate_db,
        tip,
        tip_height,
        low_height,
    )
    .map_err(|e| Error::CorruptionError(format!("canonical-chain walk failed: {e}")))
}

// ===========================================================================
// C2a: per-row + per-file tentative unlinkability classification
// ===========================================================================

/// Per-row classification under the canonical-chain + horizon predicates from
/// [squashing-v1.5.md §7.1 / §7.2](../../../../../.docs/squashing-v1.5.md).
///
/// Per the three-state predicate documented on [`canonical_chain_for_sweep`], an `UnknownSkip` row
/// (height unmappable in chainstate, or canonical map truncated below the row's height) is
/// **conservatively** treated as "blocks unlink" by the file-level aggregator — never as orphan.
/// This is the property that prevents a sweep from reclaiming canonical state through a truncated
/// headers walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowVerdict {
    /// Row's height has a canonical entry equal to the row's `block_hash`. The row is on the
    /// canonical chain; the file must wait for promotion.
    Canonical,
    /// Row is an orphan (canonical entry at this height differs) AND the row's height is at or
    /// below the horizon. The orphan is past the reorg window; its bytes are reclaimable.
    OrphanPastHorizon,
    /// Row is an orphan but its height is above the horizon (or no horizon is established yet, so
    /// past-horizon cannot be proven). The orphan must be retained until horizon advances; its
    /// presence blocks unlink AND contributes a closure-walk candidate to C2b.
    OrphanRetained,
    /// Either chainstate has no header row for this `block_hash`, OR the canonical map has no
    /// entry at this height (truncated ancestry). The classifier has no proof of canonicality OR
    /// orphanhood, so the file is conservatively treated as not-unlinkable. The next sweep pass
    /// with intact headers will reclassify.
    UnknownSkip,
}

/// Why a hot file's tentative verdict is `NotUnlinkable`. Carried in the verdict so the per-MARF
/// sweep loop's log line names the specific blocking condition.
///
/// The aggregator scans every row regardless of what it has already seen (so retained orphans
/// surface even from files that latch `HasCanonicalRow`), then applies a **fixed precedence** to
/// pick the reported reason: `HasCanonicalRow` > `HasRetainedOrphan` > `HasUnknownAncestryRow`. The
/// reason is independent of iteration order — a file with both a canonical row and a retained
/// orphan always reports `HasCanonicalRow`, regardless of which row the classifier visits first.
/// Precedence reflects "most informative for the operator log line": canonical-row presence pins
/// down the file's role exactly, while unknown-ancestry is the weakest signal (a transient
/// truncation that will reclassify on the next sweep).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotUnlinkableReason {
    /// At least one row is on the canonical chain. The file holds live canonical state and must
    /// wait for promotion.
    HasCanonicalRow,
    /// No canonical row, but at least one orphan is inside the horizon window (or horizon is
    /// undefined). The orphan(s) must be retained for potential reorg replay.
    HasRetainedOrphan,
    /// No canonical row + no retained orphan, but at least one row's classification was unknown
    /// (truncated ancestry). The conservative answer is "wait for the next sweep pass."
    HasUnknownAncestryRow,
}

/// Tentative per-file verdict from C2a. **`Unlinkable` here is not final**: the cross-file
/// orphan-ancestry closure check (C2b / §4.3) may downgrade it to `NotUnlinkable` if this file
/// holds an ancestor row of any retained orphan elsewhere in the hot tier.
///
/// C2a returns `Unlinkable` strictly on the per-row reasoning of [`RowVerdict`]; the orchestrator
/// in C4 collects the retained orphans surfaced alongside this verdict from every candidate, builds
/// the closure set, and then finalizes the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotFileTentativeVerdict {
    /// Every row is past-horizon orphan, OR the file has no live rows at all (the §7.1(a)
    /// "all promoted" case). Subject to the C2b closure check before final unlink.
    Unlinkable,
    NotUnlinkable {
        reason: NotUnlinkableReason,
    },
}

/// A retained-orphan row surfaced by the per-file classifier so C2b's sweep-wide closure precompute
/// can walk its ancestry. Carries the row's `seq` (so the closure walker can later compare against
/// each candidate file's seq) plus the `LiveHotRow` payload (so the closure walker can read the
/// row's blob's parent-hash bytes via the hot-file fd at `external_offset`).
#[derive(Debug, Clone)]
pub struct RetainedOrphanRow<T: MarfTrieId> {
    /// Hot-file sequence the orphan row resides in.
    pub seq: u32,
    /// Canonical-chain height the orphan was classified at. Carried for diagnostics + to let the
    /// closure walker stop early when it traverses a parent at or below the truncation/genesis
    /// boundary.
    pub height: u32,
    /// Full row metadata (`block_hash`, `external_offset`, `external_length`).
    pub row: LiveHotRow<T>,
}

/// Classify a single row against the canonical chain + horizon. Pure function; no I/O beyond the
/// `height_lookup` callback the caller provides.
///
/// `height_lookup(&block_hash) -> Option<u32>` returns `Some(h)` if chainstate's headers tables
/// know this block at height `h`, or `None` if the block is unrecorded (treat as `UnknownSkip`).
///
/// `horizon_max_height = None` means "no horizon yet established" (e.g. burn tip is too young per
/// [`compute_horizon_gated_max_height`](../db/fn.compute_horizon_gated_max_height.html)). Under
/// that condition, **no orphan can be classified past-horizon** — every orphan defaults to
/// `OrphanRetained`. This is the conservative behavior expected on chains right after startup or
/// before the first horizon-eligible block.
pub fn classify_row<T, H>(
    row: &LiveHotRow<T>,
    canonical_chain: &HashMap<u32, T>,
    horizon_max_height: Option<u32>,
    mut height_lookup: H,
) -> Result<(RowVerdict, Option<u32>), Error>
where
    T: MarfTrieId,
    H: FnMut(&T) -> Result<Option<u32>, Error>,
{
    let Some(height) = height_lookup(&row.block_hash)? else {
        return Ok((RowVerdict::UnknownSkip, None));
    };
    let verdict = match canonical_chain.get(&height) {
        // Chainstate has a canonical hash at this height; row matches → on the canonical chain.
        Some(canonical) if *canonical == row.block_hash => RowVerdict::Canonical,
        // Chainstate has a canonical hash at this height; row differs → orphan candidate. Apply the
        // horizon predicate.
        Some(_) => match horizon_max_height {
            Some(h_max) if height <= h_max => RowVerdict::OrphanPastHorizon,
            // Either no horizon yet, or this orphan is younger than the horizon. Must retain.
            _ => RowVerdict::OrphanRetained,
        },
        // Canonical map has no entry at this height — truncated ancestry. Conservative skip.
        None => RowVerdict::UnknownSkip,
    };
    Ok((verdict, Some(height)))
}

/// Per-file tentative classification: iterate the candidate's `live_rows`, classify each, and
/// aggregate to a file-level verdict + the list of retained orphans the closure precompute (C2b)
/// will walk.
///
/// Aggregation rule:
/// - Empty `live_rows` → `Unlinkable` (the §7.1(a) "all promoted" case; no per-row work needed).
/// - Any `RowVerdict::Canonical` → `NotUnlinkable { HasCanonicalRow }` (latches immediately).
/// - Any `RowVerdict::OrphanRetained` (and no canonical) → `NotUnlinkable { HasRetainedOrphan }`.
/// - Any `RowVerdict::UnknownSkip` (and no canonical + no retained-orphan) → `NotUnlinkable
///   { HasUnknownAncestryRow }`.
/// - All rows `OrphanPastHorizon` → `Unlinkable` (subject to C2b closure check).
///
/// Reason precedence is intentional: `HasCanonicalRow` is the most informative signal for an
/// operator reading the sweep log line. The classifier visits every row regardless (no early
/// return) so it can collect retained orphans across the whole file in one pass.
pub fn classify_hot_file_tentative<T, H>(
    candidate: &HotFileSweepCandidate<T>,
    canonical_chain: &HashMap<u32, T>,
    horizon_max_height: Option<u32>,
    mut height_lookup: H,
) -> Result<(HotFileTentativeVerdict, Vec<RetainedOrphanRow<T>>), Error>
where
    T: MarfTrieId,
    H: FnMut(&T) -> Result<Option<u32>, Error>,
{
    if candidate.live_rows.is_empty() {
        return Ok((HotFileTentativeVerdict::Unlinkable, Vec::new()));
    }

    let mut retained_orphans = Vec::new();
    let mut has_canonical = false;
    let mut has_retained_orphan = false;
    let mut has_unknown = false;

    for row in &candidate.live_rows {
        let (verdict, height_opt) =
            classify_row(row, canonical_chain, horizon_max_height, &mut height_lookup)?;
        match verdict {
            RowVerdict::Canonical => has_canonical = true,
            RowVerdict::OrphanPastHorizon => {
                // No bookkeeping needed: past-horizon orphans don't contribute to closure (their
                // ancestors don't matter once they themselves are past horizon).
            }
            RowVerdict::OrphanRetained => {
                has_retained_orphan = true;
                // Surface for C2b. Height MUST be Some — an orphan classification implies the
                // height lookup returned Some.
                if let Some(height) = height_opt {
                    retained_orphans.push(RetainedOrphanRow {
                        seq: candidate.seq,
                        height,
                        row: row.clone(),
                    });
                }
            }
            RowVerdict::UnknownSkip => has_unknown = true,
        }
    }

    let verdict = if has_canonical {
        HotFileTentativeVerdict::NotUnlinkable {
            reason: NotUnlinkableReason::HasCanonicalRow,
        }
    } else if has_retained_orphan {
        HotFileTentativeVerdict::NotUnlinkable {
            reason: NotUnlinkableReason::HasRetainedOrphan,
        }
    } else if has_unknown {
        HotFileTentativeVerdict::NotUnlinkable {
            reason: NotUnlinkableReason::HasUnknownAncestryRow,
        }
    } else {
        HotFileTentativeVerdict::Unlinkable
    };

    Ok((verdict, retained_orphans))
}

// ===========================================================================
// C2b: cross-file orphan-ancestry closure precompute
// ===========================================================================

/// Build the **closure set** of hot-file `storage_seq`s that hold an ancestor row of any
/// retained orphan in the sweep pass.
///
/// Per [phase-c §3.3](../../../../../.docs/squashing-v1.5-phase-c.md): a hot file is final-unlinkable
/// only if (a) its tentative verdict is `Unlinkable` AND (b) its `seq` is NOT in the closure set.
/// The orchestrator (C4) calls this once per sweep over the union of `RetainedOrphanRow`s surfaced
/// by C2a, then combines the result with each candidate's tentative verdict.
///
/// **Walk algorithm** (per orphan):
///
/// 1. Read `bytes[0..32]` from the orphan's blob via [`HotFileSet::read_at`] at
///    `(orphan.seq, orphan.row.external_offset)`. Those 32 bytes encode the parent block hash
///    (per [storage.rs:1189](../storage.rs)).
/// 2. If the parent hash is the chainstate genesis sentinel `[0u8; 32]` OR the MARF
///    [`SENTINEL_ARRAY`] `[255u8; 32]`, the walk terminates: there is no parent row to record.
/// 3. Otherwise look up the parent's row via [`trie_sql::get_trie_storage_location_by_bhh`].
/// 4. If the parent isn't in `marf_data` (NotFoundError), the walk terminates — the parent's
///    bytes were never persisted into this MARF (e.g. a pre-Phase-A row that's since been
///    archived).
/// 5. If the parent is `StorageKind::Cold`, the walk terminates: cold ancestors don't reside in
///    any hot file, so they can't contribute to the closure.
/// 6. If the parent is `StorageKind::Hot`, record `parent.seq` in the closure set, then recurse
///    with the parent as the new orphan (push its `(seq, offset, length)` onto the work stack).
///
/// **Visited-parent dedup**: a `HashSet<T>` of parent block hashes prevents re-walking shared
/// ancestor chains. Two retained orphans that diverge at height `h` share every ancestor at heights
/// `< h`, so dedup keeps the worst-case walk linear in the union of distinct ancestors.
///
/// **Cost bound**: O(retained_orphan_count × avg_ancestry_depth_to_promoted) = bounded. Retained
/// orphans are by definition inside the horizon window (recent), so each chain is short. Each step
/// is one bounded `pread`/mmap read (32 bytes) + one indexed `block_hash` lookup.
///
/// **Failure modes** (per [phase-c §3.3 Risk](../../../../../.docs/squashing-v1.5-phase-c.md)):
///
/// - A row whose `external_length` is below `BLOCK_HEADER_HASH_ENCODED_SIZE + 4` (= 36) bytes is
///   corruption — a trie blob is always at least 36 bytes by construction (32-byte parent hash +
///   4-byte zero identifier per [storage.rs:1191](../storage.rs)). The walk surfaces it as
///   `Error::CorruptionError` rather than skipping silently. Rejecting at the *full* header
///   minimum (not just the 32-byte read width) is deliberate: a length in the `32..36` range is
///   structurally impossible — the parent-hash bytes might fit, but the zero-id slot doesn't, so
///   the row can't have been written by any code path that produces a real trie blob. Per the
///   asymmetric-failure rationale below, we fail closed rather than letting potentially-corrupt
///   bytes participate in ancestry classification.
/// - A `read_at` error from `HotFileSet` (the parent's seq isn't in the set) signals a sweep
///   pre-condition violation: the candidate enumeration in C1 must have been stale, OR a prior
///   Phase B/C operation left dangling rows. Either way it's CorruptionError; the walk propagates.
///
/// The closure-set asymmetry is critical: a **false negative** (missing a real ancestor seq) is a
/// correctness bug — C3 would unlink a file that holds retained-orphan ancestor rows, breaking
/// reorg replay. A **false positive** (extra seq that wouldn't really block) is just a storage
/// leak that resolves on the next sweep. The implementation prefers raising on ambiguity (e.g. SQL
/// errors other than NotFound) over swallowing.
pub fn precompute_orphan_closure_seqs<T: MarfTrieId>(
    retained_orphans: &[RetainedOrphanRow<T>],
    hot_files: &HotFileSet,
    conn: &rusqlite::Connection,
) -> Result<HashSet<u32>, Error> {
    let mut closure: HashSet<u32> = HashSet::new();
    // Visited set is keyed by parent block hash (i.e. by the value we read from the blob's first
    // 32 bytes). Once we've fetched a given parent's row from `marf_data`, walking up the same
    // chain again from a different starting orphan would re-record the same seqs — dedup avoids it.
    let mut visited: HashSet<T> = HashSet::new();
    // Work stack: each entry is the (seq, offset, length) of a row whose blob we're about to read
    // for its parent hash. Seeded with each orphan; new entries are pushed for each hot parent
    // found.
    let mut stack: Vec<(u32, u64, u64)> = Vec::new();

    for orphan in retained_orphans {
        stack.push((
            orphan.seq,
            orphan.row.external_offset,
            orphan.row.external_length,
        ));

        while let Some((seq, offset, length)) = stack.pop() {
            // A trie blob is always at least 32 + 4 bytes (parent_hash + zero_id) by construction
            // (per [storage.rs:1188-1191](../storage.rs)). A shorter row is structurally
            // impossible — even a row whose length lands in `32..36` violates the format invariant
            // (the parent-hash bytes might fit, but the zero-identifier slot doesn't, so the row
            // can't have been written by any code path that produces a real trie blob). Per the
            // module's asymmetric-failure rationale (false negative in the closure = correctness
            // bug, false positive = storage leak), we fail closed at the *full* header minimum
            // rather than the read-width minimum.
            const MIN_TRIE_BLOB_LEN: u64 = BLOCK_HEADER_HASH_ENCODED_SIZE as u64 + 4;
            if length < MIN_TRIE_BLOB_LEN {
                return Err(Error::CorruptionError(format!(
                    "hot_reclaim closure: row at (seq={seq}, offset={offset}) has length {length} \
                     < {MIN_TRIE_BLOB_LEN}; trie blob header (parent_hash + zero_id) would not fit"
                )));
            }

            // Read the parent block hash (first 32 bytes of the blob). `read_at` enforces the
            // cross-handle reader fence; the sweep coordinator-thread caller already holds the
            // sweep frame around this whole pass.
            let mut buf = [0u8; BLOCK_HEADER_HASH_ENCODED_SIZE];
            let n = hot_files.read_at(seq, &mut buf, offset)?;
            if n < BLOCK_HEADER_HASH_ENCODED_SIZE {
                return Err(Error::CorruptionError(format!(
                    "hot_reclaim closure: short read at (seq={seq}, offset={offset}): got {n} of \
                     {BLOCK_HEADER_HASH_ENCODED_SIZE} bytes"
                )));
            }

            // Sentinel checks: chainstate-side genesis ([0u8;32]) and MARF-side SENTINEL_ARRAY
            // ([255u8;32]). The subsequent SQL lookup would also return NotFoundError for either
            // value (no real block has those hashes), so this is a fast-path optimization +
            // intent-clear early-out.
            if buf == [0u8; BLOCK_HEADER_HASH_ENCODED_SIZE] || buf == SENTINEL_ARRAY {
                continue;
            }

            let parent: T = T::from_bytes(buf);

            // Skip parents we've already walked through (DAG dedup).
            if !visited.insert(parent.clone()) {
                continue;
            }

            // Look up the parent's `marf_data` row.
            let parent_loc = match trie_sql::get_trie_storage_location_by_bhh::<T>(conn, &parent) {
                Ok(loc) => loc,
                // Parent never persisted to this MARF — walk terminates here. NOT a corruption
                // signal: archived/legacy rows can legitimately reference parents that aren't
                // present.
                Err(Error::NotFoundError) => continue,
                Err(e) => return Err(e),
            };

            match parent_loc.kind {
                // Cold ancestors live in <db>.blobs and don't contribute to the hot closure.
                StorageKind::Cold => continue,
                StorageKind::Hot => {
                    closure.insert(parent_loc.seq);
                    stack.push((parent_loc.seq, parent_loc.offset, parent_loc.length));
                }
            }
        }
    }

    Ok(closure)
}

// ===========================================================================
// C3: DELETE-rows + unlink-file under reader fence
// ===========================================================================

/// Default ceiling on how long [`apply_unlinkable`] waits for in-flight readers to drain after
/// raising the per-file `mutate_pending` fence. Picked at the same magnitude as Phase B's swap-path
/// quiesce timeouts: long enough to cover normal cache-warmed reads + a stutter, short enough that
/// a stuck peer reader doesn't hold the coordinator thread on the sweep call. On timeout, the
/// fence is cleared and the seq is left as a not-yet-reclaimed candidate for the next sweep
/// trigger.
pub const DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(1);

/// Apply C3's DELETE-rows + unlink-file mutation for a single hot file, under the cross-handle
/// reader fence.
///
/// **Pre-conditions** (the caller — C4's per-MARF sweep loop — guarantees these before calling):
///
/// - `seq` is a non-active hot file (the writer never appends here).
/// - `seq`'s tentative C2a verdict is `Unlinkable`, AND `seq ∉` the C2b closure set (the file
///   holds neither canonical state nor an ancestor row of any retained orphan).
///
/// **Sequence** (per [phase-c §3.4](../../../../../.docs/squashing-v1.5-phase-c.md)):
///
/// 1. Capture the on-disk path via [`HotFileSet::path_for_seq`] BEFORE any mutation, so the final
///    `unlink(2)` knows where to delete after the in-memory entry is gone.
/// 2. [`HotFileSet::set_mutate_pending`]`(seq, true)` — raises the fence; new readers back off.
/// 3. [`HotFileSet::wait_for_quiesce`]`(seq, timeout)` — waits for `active_reads == 0`. On timeout
///    the fence is cleared and the function returns [`Error::InProgressError`]; the caller should
///    retry the sweep on the next trigger (a stuck peer reader is transient: the scanning RPC, the
///    catch-up promotion, etc. all eventually finish).
/// 4. `DELETE FROM marf_data WHERE storage_kind = 1 AND storage_seq = ?seq` (autocommit; the
///    statement is atomic on its own).
/// 5. [`HotFileSet::set_mutate_pending`]`(seq, false)` — clears the fence. Done BEFORE
///    [`HotFileSet::drop_seq`] because `set_mutate_pending` errors if the seq isn't in the set.
///    Between this step and step 6, any reader caching a pre-DELETE `(seq, offset)` resolution
///    would proceed (mutate_pending is false) and read intact bytes from a still-mapped file —
///    correct, just operating on rows that no longer participate in SQL routing. In practice the
///    MARF read path re-queries `marf_data` per resolution (no cross-tx caching), so this window
///    is closed by SQL semantics.
/// 6. [`HotFileSet::drop_seq`]`(seq)` — removes the in-memory entry, closing the owned fd.
/// 7. `unlink(2)` the captured path. POSIX semantics: any in-flight read against an mmap on a
///    peer-handle fd would still succeed (the file lives until last-fd-close), but
///    `wait_for_quiesce` already proved no such reader exists on this handle.
///
/// **Crash windows** (handled by C5 startup reconciliation):
///
/// - Crash between step 4 and step 7 → SQL has no row, file is on disk. C5 unlinks the orphan.
/// - The reverse window ("file gone, rows still in SQL") cannot occur with this ordering: DELETE
///   precedes unlink, so any failure between them leaves rows-deleted-but-file-present, never the
///   reverse.
///
/// **Returns**: the row count from the DELETE — useful for the sweep summary log line + for tests.
///
/// **Errors**:
///
/// - `Error::CorruptionError` if `seq` isn't in `hot_files` (caller violated the pre-condition).
/// - `Error::InProgressError` on `wait_for_quiesce` timeout. Fence is cleared before returning.
/// - `Error::SQLError` if the DELETE fails. Fence is cleared before returning.
/// - `Error::IOError` if the `unlink(2)` fails. The SQL DELETE has already committed by then;
///   the leftover file is C5's reconciliation case.
pub fn apply_unlinkable(
    hot_files: &mut HotFileSet,
    conn: &rusqlite::Connection,
    seq: u32,
    quiesce_timeout: std::time::Duration,
) -> Result<u64, Error> {
    // Defensive guard against a C4 bug routing the active seq into the unlink path. The writer's
    // current append target MUST NOT be deleted out from under it (next append → EBADF + on-disk
    // corruption). C1's enumerator already filters the active seq out, so this is belt-and-
    // suspenders — but the cost of a misrouted active-seq is catastrophic (live writer state +
    // backing rows wiped), so we fail closed at the very top before any mutation.
    let active_seq = hot_files.active_seq();
    if seq == active_seq {
        return Err(Error::CorruptionError(format!(
            "hot_reclaim apply_unlinkable: refusing to unlink the active hot seq={seq}; \
             this is a sweep-routing bug — C1 enumeration must filter the active seq"
        )));
    }

    // Step 1: capture the path while the seq is still in the set.
    let path = hot_files.path_for_seq(seq)?.to_string();

    // Step 2: raise the cross-handle reader fence.
    hot_files.set_mutate_pending(seq, true)?;

    // Step 3: wait for in-flight readers to drain. On timeout, clear the fence so any later
    // readers can proceed and surface InProgressError to the caller.
    if let Err(e) = hot_files.wait_for_quiesce(seq, quiesce_timeout) {
        // Best-effort fence clear — if THIS errors too, prefer surfacing the original quiesce
        // error which is the actionable one.
        let _ = hot_files.set_mutate_pending(seq, false);
        return Err(e);
    }

    // Step 4: DELETE the SQL rows. SQLite autocommit makes this atomic on its own.
    let rows_deleted = match conn.execute(
        "DELETE FROM marf_data WHERE storage_kind = 1 AND storage_seq = ?1",
        rusqlite::params![seq as i64],
    ) {
        Ok(n) => n as u64,
        Err(e) => {
            // Clear the fence so readers can proceed; surface the SQL error.
            let _ = hot_files.set_mutate_pending(seq, false);
            return Err(Error::SQLError(e));
        }
    };

    // Step 5: clear the fence. MUST happen while the seq is still in the set
    // (set_mutate_pending requires the entry to exist).
    hot_files.set_mutate_pending(seq, false)?;

    // Step 6: drop the in-memory entry, closing the owned fd.
    hot_files.drop_seq(seq)?;

    // Step 7: unlink the file. The SQL DELETE has already committed; an unlink failure here is the
    // post-DELETE/pre-unlink crash window's analog (orphan file on disk) — surface it so C5 can
    // reconcile on the next RW open.
    std::fs::remove_file(&path).map_err(Error::IOError)?;

    Ok(rows_deleted)
}

// ===========================================================================
// C4: per-MARF sweep loop (composes C1 → C2a → C2b → C3)
// ===========================================================================

/// Per-MARF sweep summary. Returned by [`sweep_unlinkable_hot_files`] for the operator log line +
/// for tests asserting the sweep made the expected progress.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepStats {
    /// Files that progressed all the way through C3 — DELETE + unlink completed.
    pub files_unlinked: u32,
    /// Total `marf_data` rows DELETEd across every unlinked file in this sweep call.
    pub rows_deleted: u64,
    /// Files whose tentative C2a verdict was `NotUnlinkable` (canonical row, retained orphan, or
    /// truncated ancestry). The early-stop kicks in at the first one of these encountered (per
    /// §7.4 oldest-first ordering), so this counts how many such files the loop saw before
    /// stopping — typically 1 (the one that triggered the stop) or 0.
    pub files_retained_by_classifier: u32,
    /// Files whose tentative C2a verdict was `Unlinkable` but whose `seq` landed in the C2b
    /// closure set (file holds an ancestor row of a retained orphan elsewhere). C3 is skipped for
    /// these; they may become unlinkable on a later sweep once the blocking retained orphan
    /// crosses past horizon.
    pub files_blocked_by_closure: u32,
    /// Files whose `apply_unlinkable` returned `Error::InProgressError` (peer reader didn't
    /// quiesce in time). The seq is left as a candidate for the next sweep trigger.
    pub files_deferred_for_quiesce: u32,
}

impl SweepStats {
    /// Did the sweep do any forward-progress work (a file actually got unlinked / rows deleted)?
    /// Strictly progress, NOT "should this be logged" — see [`Self::is_noteworthy`] for that.
    pub fn made_progress(&self) -> bool {
        self.files_unlinked > 0 || self.rows_deleted > 0
    }

    /// Should this sweep call surface in operator logs? True for any non-default state, including
    /// the "nothing got done but here's why" cases (deferred-for-quiesce, blocked-by-closure,
    /// retained-by-classifier). Without this, a sweep stuck behind a peer reader OR repeatedly
    /// blocked by closure is silent — the operator has no observability into what's happening.
    /// (Codex 2026-05-02 caught the original `any_progress`-only gate's blind spots.)
    pub fn is_noteworthy(&self) -> bool {
        *self != Self::default()
    }
}

/// Per-MARF sweep loop that composes C1 → C2a → C2b → C3 to apply Phase C's hot-reclaim sweep
/// against a single live MARF.
///
/// Algorithm (per [phase-c §3.5](../../../../../.docs/squashing-v1.5-phase-c.md)):
///
/// 1. **Enumerate** non-active hot files via [`enumerate_hot_files_for_sweep`]. The candidate set
///    comes from the on-disk inventory; oldest-to-newest sort is provided.
/// 2. **Classify-all phase**: walk **every** candidate (no early-stop here) and run
///    [`classify_hot_file_tentative`] on each. Collect every retained orphan surfaced — this MUST
///    visit younger files too, because a retained orphan in file Y may have an ancestor in older
///    file X, and skipping Y would let the closure precompute miss that ancestry → C3 would
///    incorrectly unlink X. (Codex 2026-05-02 caught this: an earlier draft early-stopped here on
///    the first `NotUnlinkable`, which broke C2b's correctness contract.)
/// 3. **Cross-file closure precompute**: invoke [`precompute_orphan_closure_seqs`] once over the
///    full union of retained orphans from step 2. Returns the set of hot seqs that hold an
///    ancestor row of any retained orphan.
/// 4. **Apply phase**: walk classified candidates in the same oldest-first order:
///    - On `NotUnlinkable`: bump `files_retained_by_classifier`, **early-stop the apply walk**
///      (per §7.4: an older file that's still blocked implies younger ones are too — that's the
///      §7.4 invariant about how horizon eligibility flows through file ordering).
///    - On `Unlinkable`:
///      - If `seq ∈ closure_set`: bump `files_blocked_by_closure`, **continue** (a younger file
///        may still be applicable — closure-blocked is per-file, not a global stop signal).
///      - Else: invoke [`apply_unlinkable`]. On success bump `files_unlinked` + `rows_deleted`.
///        On `InProgressError`: bump `files_deferred_for_quiesce`, continue (a stuck peer reader
///        on file X doesn't justify stopping the sweep — file Y may have no readers and is
///        reclaimable RIGHT NOW). On any other error: propagate.
///
/// **Apply-all-then-stop** semantics (Q1 lock-in): step 4 applies every reclaimable file it
/// encounters before the first `NotUnlinkable`, draining a backlog of N reclaimable files in a
/// single sweep call rather than N promotion cycles. The early-stop is in step 4 (apply), NOT in
/// step 2 (classification) — step 2 walks every candidate so C2b's closure precompute is complete.
///
/// **Errors** are propagated from any step. The closure precompute's CorruptionError + the apply
/// step's IOError both surface to the caller; partial progress (some files unlinked before the
/// error) is reflected in the returned `SweepStats` only if the error is one of the
/// non-propagated kinds (`InProgressError`). For propagated errors, the caller should treat
/// `SweepStats` as undefined.
pub fn sweep_unlinkable_hot_files<T, H>(
    hot_files: &mut HotFileSet,
    conn: &rusqlite::Connection,
    canonical_chain: &HashMap<u32, T>,
    horizon_max_height: Option<u32>,
    mut height_lookup: H,
    quiesce_timeout: std::time::Duration,
) -> Result<SweepStats, Error>
where
    T: MarfTrieId,
    H: FnMut(&T) -> Result<Option<u32>, Error>,
{
    let mut stats = SweepStats::default();

    // Step 1: enumerate.
    let candidates = enumerate_hot_files_for_sweep::<T>(hot_files, conn)?;
    if candidates.is_empty() {
        return Ok(stats);
    }

    // Step 2: classify-all phase. NO early-stop here — every candidate must be classified so
    // C2b's closure precompute sees the COMPLETE set of retained orphans. A retained orphan in a
    // younger file may have an ancestor in an older tentative-Unlinkable file; without visiting
    // the younger file we'd miss that ancestor and incorrectly unlink the older file (Codex
    // 2026-05-02 regression).
    let mut classified: Vec<(HotFileSweepCandidate<T>, HotFileTentativeVerdict)> =
        Vec::with_capacity(candidates.len());
    let mut all_retained_orphans: Vec<RetainedOrphanRow<T>> = Vec::new();
    for cand in candidates {
        let (verdict, mut retained) = classify_hot_file_tentative(
            &cand,
            canonical_chain,
            horizon_max_height,
            &mut height_lookup,
        )?;
        all_retained_orphans.append(&mut retained);
        classified.push((cand, verdict));
    }

    // Step 3: sweep-wide closure precompute over the COMPLETE union of retained orphans.
    let closure_set = precompute_orphan_closure_seqs(&all_retained_orphans, hot_files, conn)?;

    // Step 4: apply phase. Oldest-first (preserved from step 2's enumeration order). NotUnlinkable
    // triggers a hard early-stop here per §7.4. Closure-blocked is per-file, NOT a stop signal.
    for (cand, verdict) in classified {
        match verdict {
            HotFileTentativeVerdict::NotUnlinkable { .. } => {
                stats.files_retained_by_classifier += 1;
                // §7.4 oldest-first early-stop: an older file that's still blocked implies all
                // younger ones are too. Stop the apply walk here.
                break;
            }
            HotFileTentativeVerdict::Unlinkable => {
                if closure_set.contains(&cand.seq) {
                    // This file holds an ancestor row of a retained orphan elsewhere — skip it,
                    // but DO continue: a younger Unlinkable file may not have that property and
                    // is still applicable.
                    stats.files_blocked_by_closure += 1;
                    continue;
                }
                match apply_unlinkable(hot_files, conn, cand.seq, quiesce_timeout) {
                    Ok(rows_deleted) => {
                        stats.files_unlinked += 1;
                        stats.rows_deleted += rows_deleted;
                    }
                    Err(Error::InProgressError) => {
                        // Peer reader didn't quiesce — leave the seq as a candidate for the next
                        // sweep trigger, continue with other reclaimable files.
                        stats.files_deferred_for_quiesce += 1;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rusqlite::Connection;
    use stacks_common::types::chainstate::BlockHeaderHash;

    use super::*;
    use crate::chainstate::stacks::index::hot_file::HotFileSet;
    use crate::chainstate::stacks::index::trie_sql;

    /// Build an empty v5 MARF DB at `<tmp_root>/<test_name>/marf.sqlite` and return its path stem +
    /// an open connection.
    fn fresh_v5_db(test_name: &str) -> (PathBuf, Connection) {
        let tmp_root = std::env::temp_dir()
            .join("hot_reclaim_tests")
            .join(test_name);
        let _ = std::fs::remove_dir_all(&tmp_root);
        std::fs::create_dir_all(&tmp_root).unwrap();
        let db_path = tmp_root.join("marf.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        trie_sql::create_tables_if_needed(&mut conn).unwrap();
        trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut conn).unwrap();
        (db_path, conn)
    }

    /// Insert a synthetic hot `marf_data` row pointing at file `seq` at `(offset, length)`. Used to
    /// build fixtures without going through MARF's append path.
    fn insert_hot_row(
        conn: &Connection,
        block_byte: u8,
        seq: u32,
        offset: u64,
        length: u64,
    ) -> BlockHeaderHash {
        let mut bytes = [0u8; 32];
        bytes[31] = block_byte;
        let bhh = BlockHeaderHash(bytes);
        conn.execute(
            "INSERT INTO marf_data \
             (block_hash, data, unconfirmed, external_offset, external_length, \
              storage_kind, storage_seq) \
             VALUES (?1, x'', 0, ?2, ?3, 1, ?4)",
            rusqlite::params![bhh, offset as i64, length as i64, seq as i64],
        )
        .unwrap();
        bhh
    }

    /// **The regression marker for the inventory-first design**: a hot file that exists on disk but
    /// has zero matching `marf_data` rows must still show up in the candidate list (with empty
    /// `live_rows`). A SQL-first `GROUP BY storage_seq` would have silently dropped this case,
    /// leaving the most-reclaimable file forever unlinkable.
    #[test]
    fn enumerate_includes_fully_promoted_file_with_zero_rows() {
        let (db_path, conn) = fresh_v5_db("enumerate_includes_fully_promoted_file_with_zero_rows");
        let stem = db_path.to_str().unwrap();
        // Create + rotate a hot file: seq=1 becomes rotated, seq=2 is active.
        let mut set = HotFileSet::open(stem, &conn, false, 32, false).unwrap();
        set.append_to_active(&[0xab; 33]).unwrap();
        set.rotate(&conn).unwrap();
        // Don't insert any marf_data rows — seq=1 is "fully promoted" (logically: every row that
        // pointed at it has since flipped to storage_kind = 0).

        let candidates = enumerate_hot_files_for_sweep::<BlockHeaderHash>(&set, &conn).unwrap();
        assert_eq!(candidates.len(), 1, "expected only the rotated file");
        assert_eq!(candidates[0].seq, 1);
        assert!(
            candidates[0].live_rows.is_empty(),
            "fully-promoted file must surface with empty live_rows"
        );
    }

    /// Mixed file: rotated, has some live rows. Must show up with the non-empty `live_rows` for C2
    /// to classify per-row.
    #[test]
    fn enumerate_attaches_live_rows_to_mixed_file() {
        let (db_path, conn) = fresh_v5_db("enumerate_attaches_live_rows_to_mixed_file");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 32, false).unwrap();
        set.append_to_active(&[0xab; 33]).unwrap();
        set.rotate(&conn).unwrap();
        // seq=1 is rotated. Insert two rows referencing it.
        let _b1 = insert_hot_row(&conn, 1, 1, 0, 16);
        let _b2 = insert_hot_row(&conn, 2, 1, 16, 17);

        let candidates = enumerate_hot_files_for_sweep::<BlockHeaderHash>(&set, &conn).unwrap();
        assert_eq!(candidates.len(), 1);
        let cand = &candidates[0];
        assert_eq!(cand.seq, 1);
        assert_eq!(cand.live_rows.len(), 2);
        // Rows come back in `external_offset ASC` per the SQL `ORDER BY`.
        assert_eq!(cand.live_rows[0].external_offset, 0);
        assert_eq!(cand.live_rows[0].external_length, 16);
        assert_eq!(cand.live_rows[1].external_offset, 16);
        assert_eq!(cand.live_rows[1].external_length, 17);
    }

    /// Active file is never a sweep candidate. Even if rows reference it (which they always do for
    /// the active file), the enumerator filters it out.
    #[test]
    fn enumerate_excludes_active_file_unconditionally() {
        let (db_path, conn) = fresh_v5_db("enumerate_excludes_active_file_unconditionally");
        let stem = db_path.to_str().unwrap();
        let set = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        // The active file (seq=1) exists. Insert a row pointing at it.
        let _b = insert_hot_row(&conn, 1, set.active_seq(), 0, 32);

        let candidates = enumerate_hot_files_for_sweep::<BlockHeaderHash>(&set, &conn).unwrap();
        assert!(
            candidates.is_empty(),
            "active file must never appear as a sweep candidate"
        );
    }

    /// Multiple rotated files with varying live-row counts. Verifies the oldest-to-newest sort
    /// order C4's loop relies on.
    #[test]
    fn enumerate_sorts_oldest_to_newest_by_seq() {
        let (db_path, conn) = fresh_v5_db("enumerate_sorts_oldest_to_newest_by_seq");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 16, false).unwrap();
        // Build seqs 1, 2, 3 (rotated) + 4 (active).
        for _ in 0..3 {
            set.append_to_active(&[0xcd; 17]).unwrap();
            set.rotate(&conn).unwrap();
        }
        assert_eq!(set.active_seq(), 4);
        // Insert one row in seq=2 to mix up the row-count distribution.
        let _b = insert_hot_row(&conn, 1, 2, 0, 8);

        let candidates = enumerate_hot_files_for_sweep::<BlockHeaderHash>(&set, &conn).unwrap();
        assert_eq!(candidates.len(), 3, "active file (4) excluded");
        let seqs: Vec<u32> = candidates.iter().map(|c| c.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3], "oldest-to-newest order");
        assert!(candidates[0].live_rows.is_empty());
        assert_eq!(candidates[1].live_rows.len(), 1);
        assert!(candidates[2].live_rows.is_empty());
    }

    // ===========================================================================
    // canonical_chain_for_sweep — height-keyed walk, truncation-aware
    // ===========================================================================
    //
    // The minimum schema `lookup_height_and_parent` reads is `block_headers (index_block_hash,
    // block_height, parent_block_id)`. Tests build that schema in a fresh in-memory SQLite DB and
    // seed rows directly — much cheaper than instantiating a full chainstate.

    fn block_id(byte: u8) -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        StacksBlockId(bytes)
    }

    /// Open a fresh in-memory SQLite DB with just enough of the chainstate `block_headers` schema
    /// for `lookup_height_and_parent`'s SELECT to succeed.
    fn fresh_chainstate_stub_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE block_headers (
                index_block_hash TEXT PRIMARY KEY NOT NULL,
                block_height     INTEGER NOT NULL,
                parent_block_id  TEXT NOT NULL
             );
             CREATE TABLE nakamoto_block_headers (
                index_block_hash TEXT PRIMARY KEY NOT NULL,
                block_height     INTEGER NOT NULL,
                parent_block_id  TEXT NOT NULL
             );",
        )
        .unwrap();
        conn
    }

    fn insert_header(conn: &Connection, bid: &StacksBlockId, height: u32, parent: &StacksBlockId) {
        conn.execute(
            "INSERT INTO block_headers (index_block_hash, block_height, parent_block_id) \
             VALUES (?1, ?2, ?3)",
            rusqlite::params![bid, height as i64, parent],
        )
        .unwrap();
    }

    /// Happy path: 4-block chain with full headers coverage. The walk returns one entry per height
    /// in `[low_height, tip_height]`.
    #[test]
    fn canonical_chain_walks_low_to_tip() {
        let conn = fresh_chainstate_stub_db();
        // Build chain: genesis-sentinel → b1(h=1) → b2(h=2) → b3(h=3) → b4(h=4).
        let zero = StacksBlockId([0u8; 32]);
        let b1 = block_id(1);
        let b2 = block_id(2);
        let b3 = block_id(3);
        let b4 = block_id(4);
        insert_header(&conn, &b1, 1, &zero);
        insert_header(&conn, &b2, 2, &b1);
        insert_header(&conn, &b3, 3, &b2);
        insert_header(&conn, &b4, 4, &b3);

        // Walk [low=2, tip=4] from b4.
        let map = canonical_chain_for_sweep(&conn, &b4, 4, 2).unwrap();
        assert_eq!(map.len(), 3, "heights 2..=4 expected");
        assert_eq!(map.get(&2), Some(&b2));
        assert_eq!(map.get(&3), Some(&b3));
        assert_eq!(map.get(&4), Some(&b4));
        // Heights below `low_height` are deliberately not present.
        assert!(map.get(&1).is_none());
        assert!(map.get(&0).is_none());
    }

    /// **Truncation safety regression**: when an intermediate ancestor row is missing from headers,
    /// the walk truncates AT the gap. Heights below the gap have NO map entry. C2 must treat those
    /// heights as `skip` — never as `orphan` — and this test pins the helper's contract that
    /// supports that decision.
    ///
    /// Without this property, flattening to a `HashSet` (the original C1 shape Codex caught) would
    /// let canonical hashes below the truncation point silently classify as orphans in C2, and the
    /// sweep could reclaim canonical state.
    #[test]
    fn canonical_chain_truncates_at_unknown_ancestor() {
        let conn = fresh_chainstate_stub_db();
        let zero = StacksBlockId([0u8; 32]);
        let b1 = block_id(1);
        let b2 = block_id(2);
        let b3 = block_id(3);
        let b4 = block_id(4);
        // Chain: b1(h=1) → b2(h=2) → b3(h=3) → b4(h=4), but b2 is missing from headers. Walking
        // from b4 should populate heights 4 and 3, then truncate (b3's parent is b2 which has no
        // row).
        insert_header(&conn, &b1, 1, &zero);
        // b2 deliberately NOT inserted.
        insert_header(&conn, &b3, 3, &b2);
        insert_header(&conn, &b4, 4, &b3);

        let map = canonical_chain_for_sweep(&conn, &b4, 4, 1).unwrap();
        assert_eq!(map.get(&4), Some(&b4), "tip height present");
        assert_eq!(map.get(&3), Some(&b3), "h=3 present (its row exists)");
        // b2's row is missing → walk truncates → h=2 has no entry.
        assert!(
            map.get(&2).is_none(),
            "h=2 must be unmapped (truncation), NOT mapped to a wrong block"
        );
        // h=1 is below the truncation point → also no entry.
        assert!(
            map.get(&1).is_none(),
            "h=1 must be unmapped (below truncation)"
        );
        assert_eq!(map.len(), 2, "exactly h=3 and h=4 mapped");
    }

    /// `low_height > tip_height` returns an empty map (no levels loaded yet — sweep has nothing to
    /// do).
    #[test]
    fn canonical_chain_empty_when_low_height_exceeds_tip() {
        let conn = fresh_chainstate_stub_db();
        let b1 = block_id(1);
        let map = canonical_chain_for_sweep(&conn, &b1, 1, 5).unwrap();
        assert!(map.is_empty());
    }

    /// Tip not in headers → walk returns immediately with an empty map. The walker's policy is
    /// "ancestry unknowable → skip", and our wrapper preserves it. Sweep callers see an empty map
    /// and have no canonical assertions to make.
    #[test]
    fn canonical_chain_unknown_tip_returns_empty() {
        let conn = fresh_chainstate_stub_db();
        let phantom = block_id(99);
        let map = canonical_chain_for_sweep(&conn, &phantom, 4, 1).unwrap();
        assert!(map.is_empty());
    }

    // ===========================================================================
    // C2a: classify_hot_file_tentative
    // ===========================================================================
    //
    // Tests use `BlockHeaderHash` as the row + canonical-map type — generic in the classifier; in
    // production both MARFs use `StacksBlockId`. The height_lookup callback is a HashMap-backed
    // closure so tests stay pure (no chainstate stub DB needed).

    fn bhh(byte: u8) -> BlockHeaderHash {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        BlockHeaderHash(bytes)
    }

    fn live_row(byte: u8, offset: u64, length: u64) -> LiveHotRow<BlockHeaderHash> {
        LiveHotRow {
            block_hash: bhh(byte),
            external_offset: offset,
            external_length: length,
        }
    }

    /// Build a `height_lookup` closure backed by `(block_hash → height)` pairs. Returns `None` for
    /// any block not in the map (the chainstate-doesn't-know-this-block case).
    fn height_lookup_from(
        pairs: &[(BlockHeaderHash, u32)],
    ) -> impl FnMut(&BlockHeaderHash) -> Result<Option<u32>, Error> + '_ {
        let map: HashMap<BlockHeaderHash, u32> = pairs.iter().cloned().collect();
        move |bhh: &BlockHeaderHash| Ok(map.get(bhh).copied())
    }

    /// Empty `live_rows` → unconditionally `Unlinkable` (the §7.1(a) all-promoted case). The
    /// classifier short-circuits without touching canonical_chain or the height lookup.
    #[test]
    fn classify_empty_live_rows_returns_unlinkable() {
        let candidate: HotFileSweepCandidate<BlockHeaderHash> = HotFileSweepCandidate {
            seq: 7,
            live_rows: Vec::new(),
        };
        let canonical = HashMap::<u32, BlockHeaderHash>::new();
        let (verdict, retained) = classify_hot_file_tentative(
            &candidate,
            &canonical,
            Some(100),
            // Lookup should never be called for an empty file; this assertion would trip if it were.
            |_: &BlockHeaderHash| -> Result<Option<u32>, Error> {
                panic!("height_lookup must not be called when live_rows is empty");
            },
        )
        .unwrap();
        assert_eq!(verdict, HotFileTentativeVerdict::Unlinkable);
        assert!(retained.is_empty());
    }

    /// All rows on the canonical chain → `NotUnlinkable { HasCanonicalRow }`. The file holds live
    /// canonical state and must wait for promotion.
    #[test]
    fn classify_all_canonical_returns_not_unlinkable() {
        let r1 = live_row(1, 0, 16);
        let r2 = live_row(2, 16, 16);
        let candidate = HotFileSweepCandidate {
            seq: 3,
            live_rows: vec![r1.clone(), r2.clone()],
        };
        let canonical: HashMap<u32, BlockHeaderHash> =
            [(10, bhh(1)), (11, bhh(2))].into_iter().collect();
        let (verdict, retained) = classify_hot_file_tentative(
            &candidate,
            &canonical,
            Some(100),
            height_lookup_from(&[(bhh(1), 10), (bhh(2), 11)]),
        )
        .unwrap();
        assert_eq!(
            verdict,
            HotFileTentativeVerdict::NotUnlinkable {
                reason: NotUnlinkableReason::HasCanonicalRow,
            }
        );
        assert!(
            retained.is_empty(),
            "canonical-only files surface no orphans"
        );
    }

    /// All rows are orphans whose heights are at or below the horizon → `Unlinkable`. The
    /// past-horizon predicate is the §7.1(b) condition.
    #[test]
    fn classify_all_orphan_past_horizon_returns_unlinkable() {
        let r1 = live_row(1, 0, 16);
        let r2 = live_row(2, 16, 16);
        let candidate = HotFileSweepCandidate {
            seq: 3,
            live_rows: vec![r1, r2],
        };
        // Canonical chain has DIFFERENT block hashes at the same heights → orphans.
        let canonical: HashMap<u32, BlockHeaderHash> =
            [(10, bhh(99)), (11, bhh(98))].into_iter().collect();
        let (verdict, retained) = classify_hot_file_tentative(
            &candidate,
            &canonical,
            Some(20), // both heights 10, 11 are ≤ 20
            height_lookup_from(&[(bhh(1), 10), (bhh(2), 11)]),
        )
        .unwrap();
        assert_eq!(verdict, HotFileTentativeVerdict::Unlinkable);
        assert!(
            retained.is_empty(),
            "past-horizon orphans don't contribute to closure"
        );
    }

    /// Mixed: some canonical, some past-horizon orphans → canonical row latches the verdict.
    #[test]
    fn classify_mixed_canonical_and_past_horizon_orphan_blocks_via_canonical() {
        let r_canonical = live_row(1, 0, 16);
        let r_orphan = live_row(2, 16, 16);
        let candidate = HotFileSweepCandidate {
            seq: 3,
            live_rows: vec![r_canonical, r_orphan],
        };
        let canonical: HashMap<u32, BlockHeaderHash> =
            [(10, bhh(1)), (11, bhh(99))].into_iter().collect();
        let (verdict, retained) = classify_hot_file_tentative(
            &candidate,
            &canonical,
            Some(20),
            height_lookup_from(&[(bhh(1), 10), (bhh(2), 11)]),
        )
        .unwrap();
        assert_eq!(
            verdict,
            HotFileTentativeVerdict::NotUnlinkable {
                reason: NotUnlinkableReason::HasCanonicalRow,
            }
        );
        assert!(retained.is_empty());
    }

    /// At least one orphan above the horizon → `NotUnlinkable { HasRetainedOrphan }` AND the
    /// orphan is surfaced for C2b's closure precompute.
    #[test]
    fn classify_retained_orphan_blocks_unlink_and_surfaces_for_closure() {
        let r_past = live_row(1, 0, 16);
        let r_retained = live_row(2, 16, 17);
        let candidate = HotFileSweepCandidate {
            seq: 5,
            live_rows: vec![r_past.clone(), r_retained.clone()],
        };
        let canonical: HashMap<u32, BlockHeaderHash> =
            [(10, bhh(99)), (50, bhh(98))].into_iter().collect();
        let (verdict, retained) = classify_hot_file_tentative(
            &candidate,
            &canonical,
            Some(20), // height 10 is past horizon; height 50 is retained
            height_lookup_from(&[(bhh(1), 10), (bhh(2), 50)]),
        )
        .unwrap();
        assert_eq!(
            verdict,
            HotFileTentativeVerdict::NotUnlinkable {
                reason: NotUnlinkableReason::HasRetainedOrphan,
            }
        );
        assert_eq!(retained.len(), 1, "only the retained orphan is surfaced");
        let surfaced = &retained[0];
        assert_eq!(surfaced.seq, 5);
        assert_eq!(surfaced.height, 50);
        assert_eq!(surfaced.row.block_hash, bhh(2));
        assert_eq!(surfaced.row.external_offset, 16);
        assert_eq!(surfaced.row.external_length, 17);
    }

    /// `horizon_max_height = None` → no orphan can be classified past-horizon. ALL orphans default
    /// to `OrphanRetained`, which blocks unlink. This is the conservative behavior on chains where
    /// burn-tip is too young for the horizon predicate to evaluate.
    #[test]
    fn classify_orphan_with_undefined_horizon_is_retained() {
        let r = live_row(1, 0, 16);
        let candidate = HotFileSweepCandidate {
            seq: 4,
            live_rows: vec![r.clone()],
        };
        let canonical: HashMap<u32, BlockHeaderHash> = [(10, bhh(99))].into_iter().collect();
        let (verdict, retained) = classify_hot_file_tentative(
            &candidate,
            &canonical,
            None, // no horizon
            height_lookup_from(&[(bhh(1), 10)]),
        )
        .unwrap();
        assert_eq!(
            verdict,
            HotFileTentativeVerdict::NotUnlinkable {
                reason: NotUnlinkableReason::HasRetainedOrphan,
            }
        );
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 10);
    }

    /// **Truncation safety**: a row whose height has no canonical entry (because the canonical-walk
    /// truncated above it) classifies as `UnknownSkip`, NOT as orphan. This is the property the
    /// three-state predicate exists to enforce: without it, a canonical block under a truncation
    /// gap would silently classify as orphan and the sweep could reclaim canonical state.
    #[test]
    fn classify_unknown_height_via_truncated_canonical_chain_blocks_unlink() {
        // The row's height (50) is BELOW the canonical-walk's truncation point — canonical map
        // simply has no entry there.
        let r = live_row(1, 0, 16);
        let candidate = HotFileSweepCandidate {
            seq: 4,
            live_rows: vec![r],
        };
        let canonical: HashMap<u32, BlockHeaderHash> =
            [(100, bhh(98)), (101, bhh(99))].into_iter().collect();
        let (verdict, retained) = classify_hot_file_tentative(
            &candidate,
            &canonical,
            Some(200),
            height_lookup_from(&[(bhh(1), 50)]),
        )
        .unwrap();
        assert_eq!(
            verdict,
            HotFileTentativeVerdict::NotUnlinkable {
                reason: NotUnlinkableReason::HasUnknownAncestryRow,
            }
        );
        assert!(
            retained.is_empty(),
            "unknown-skip rows are NOT orphans, must not feed the closure precompute"
        );
    }

    /// Row whose `block_hash` isn't in chainstate's headers tables → `UnknownSkip`. Same blocking
    /// behavior as the truncated-canonical-chain case but a different cause (chainstate-side gap
    /// vs. canonical-walk-side truncation).
    #[test]
    fn classify_row_unknown_to_chainstate_blocks_unlink() {
        let r = live_row(1, 0, 16);
        let candidate = HotFileSweepCandidate {
            seq: 4,
            live_rows: vec![r],
        };
        let canonical: HashMap<u32, BlockHeaderHash> = [(50, bhh(99))].into_iter().collect();
        let (verdict, retained) = classify_hot_file_tentative(
            &candidate,
            &canonical,
            Some(200),
            height_lookup_from(&[]), // chainstate has no row for bhh(1)
        )
        .unwrap();
        assert_eq!(
            verdict,
            HotFileTentativeVerdict::NotUnlinkable {
                reason: NotUnlinkableReason::HasUnknownAncestryRow,
            }
        );
        assert!(retained.is_empty());
    }

    /// Reason-precedence sanity check: a file with one canonical row + one retained orphan + one
    /// unknown-skip row reports `HasCanonicalRow` (the highest-precedence blocking reason). The
    /// retained orphan IS still surfaced for the closure precompute — even though THIS file is
    /// blocked by canonical, the orphan it carries can be a closure-walk anchor for OTHER files.
    #[test]
    fn classify_canonical_takes_precedence_but_retained_still_surfaces() {
        let r_canonical = live_row(1, 0, 16);
        let r_retained = live_row(2, 16, 17);
        let r_unknown = live_row(3, 33, 5);
        let candidate = HotFileSweepCandidate {
            seq: 8,
            live_rows: vec![r_canonical, r_retained.clone(), r_unknown],
        };
        let canonical: HashMap<u32, BlockHeaderHash> =
            [(10, bhh(1)), (50, bhh(99))].into_iter().collect();
        let (verdict, retained) = classify_hot_file_tentative(
            &candidate,
            &canonical,
            Some(20),
            height_lookup_from(&[
                (bhh(1), 10),
                (bhh(2), 50), /* bhh(3) deliberately absent */
            ]),
        )
        .unwrap();
        assert_eq!(
            verdict,
            HotFileTentativeVerdict::NotUnlinkable {
                reason: NotUnlinkableReason::HasCanonicalRow,
            }
        );
        assert_eq!(
            retained.len(),
            1,
            "the retained orphan is still surfaced for cross-file closure walks"
        );
        assert_eq!(retained[0].row.block_hash, bhh(2));
    }

    // ===========================================================================
    // C2b: precompute_orphan_closure_seqs
    // ===========================================================================
    //
    // Tests use a real `HotFileSet` so they exercise the full read_at + marf_data lookup path. Each
    // synthetic blob is `parent_hash (32 bytes) + 4-byte zero-id + payload pad` to match the on-disk
    // trie blob layout (per storage.rs:1189-1191). `insert_row_kind` ties a `marf_data` row to the
    // (seq, offset, length) the append yields.

    /// Append a synthetic trie blob to the active hot file. Layout: `parent_hash (32B) + zero-id
    /// (4B) + pad`. Returns the `(seq, offset, length)` that should be recorded in the matching
    /// `marf_data` row.
    fn append_blob_with_parent(
        set: &mut HotFileSet,
        parent: &BlockHeaderHash,
        pad_bytes: usize,
    ) -> (u32, u64, u64) {
        let mut blob = Vec::with_capacity(BLOCK_HEADER_HASH_ENCODED_SIZE + 4 + pad_bytes);
        blob.extend_from_slice(parent.as_ref());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend(std::iter::repeat(0u8).take(pad_bytes));
        let len = blob.len() as u64;
        let (seq, offset) = set.append_to_active(&blob).unwrap();
        (seq, offset, len)
    }

    fn insert_row_kind(
        conn: &Connection,
        block_hash: &BlockHeaderHash,
        seq: u32,
        offset: u64,
        length: u64,
        storage_kind: i64,
    ) {
        conn.execute(
            "INSERT INTO marf_data \
             (block_hash, data, unconfirmed, external_offset, external_length, \
              storage_kind, storage_seq) \
             VALUES (?1, x'', 0, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                block_hash,
                offset as i64,
                length as i64,
                storage_kind,
                seq as i64,
            ],
        )
        .unwrap();
    }

    fn retained_orphan(
        seq: u32,
        height: u32,
        block_hash: BlockHeaderHash,
        offset: u64,
        length: u64,
    ) -> RetainedOrphanRow<BlockHeaderHash> {
        RetainedOrphanRow {
            seq,
            height,
            row: LiveHotRow {
                block_hash,
                external_offset: offset,
                external_length: length,
            },
        }
    }

    /// Lone retained orphan whose blob's parent_hash is `[0u8; 32]` (chainstate genesis sentinel).
    /// Walk reads the parent, hits the sentinel branch, terminates without recording anything.
    /// Closure set is empty.
    #[test]
    fn closure_lone_retained_orphan_with_parent_sentinel_returns_empty_set() {
        let (db_path, conn) = fresh_v5_db("closure_lone_retained_orphan_with_parent_sentinel");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();
        // Active seq=1. Append the orphan's blob with parent_hash = sentinel.
        let sentinel = BlockHeaderHash([0u8; 32]);
        let (orphan_seq, orphan_off, orphan_len) =
            append_blob_with_parent(&mut set, &sentinel, /* pad */ 0);
        // Rotate so the orphan's seq becomes a non-active sweep candidate.
        set.rotate(&conn).unwrap();
        let orphan_bhh = bhh(1);
        insert_row_kind(&conn, &orphan_bhh, orphan_seq, orphan_off, orphan_len, 1);

        let orphans = vec![retained_orphan(
            orphan_seq, 50, orphan_bhh, orphan_off, orphan_len,
        )];
        let closure =
            precompute_orphan_closure_seqs::<BlockHeaderHash>(&orphans, &set, &conn).unwrap();
        assert!(
            closure.is_empty(),
            "no hot ancestors → closure set must be empty"
        );
    }

    /// Two-level chain: orphan A (hot, seq=2) → parent B (hot, seq=1) → grandparent C (cold).
    /// Walk records seq=1 for B and terminates at C (cold). Closure = {1}.
    #[test]
    fn closure_walks_to_first_cold_ancestor_and_terminates() {
        let (db_path, conn) = fresh_v5_db("closure_walks_to_first_cold_ancestor");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();

        // C is cold (no hot file involvement); we just need its `marf_data` row.
        let bhh_c = bhh(3);
        insert_row_kind(&conn, &bhh_c, 0, 0, 0, /* cold */ 0);

        // B is hot, seq=1; parent = C.
        let (b_seq, b_off, b_len) = append_blob_with_parent(&mut set, &bhh_c, 0);
        set.rotate(&conn).unwrap();
        let bhh_b = bhh(2);
        insert_row_kind(&conn, &bhh_b, b_seq, b_off, b_len, 1);

        // A is hot, seq=2; parent = B.
        let (a_seq, a_off, a_len) = append_blob_with_parent(&mut set, &bhh_b, 0);
        set.rotate(&conn).unwrap();
        let bhh_a = bhh(1);
        insert_row_kind(&conn, &bhh_a, a_seq, a_off, a_len, 1);

        // Active is now seq=3. A is the retained orphan.
        let orphans = vec![retained_orphan(a_seq, 100, bhh_a, a_off, a_len)];
        let closure =
            precompute_orphan_closure_seqs::<BlockHeaderHash>(&orphans, &set, &conn).unwrap();
        assert_eq!(closure.len(), 1, "exactly B's seq is recorded");
        assert!(
            closure.contains(&b_seq),
            "B's seq={b_seq} expected in closure"
        );
        assert!(
            !closure.contains(&a_seq),
            "the orphan's OWN seq is never recorded — only ancestors are"
        );
    }

    /// Chain terminating at the MARF [`SENTINEL_ARRAY`] (`[255u8; 32]`) instead of chainstate
    /// genesis. Closure walk treats both sentinels as terminal.
    #[test]
    fn closure_walks_to_marf_sentinel_and_terminates() {
        let (db_path, conn) = fresh_v5_db("closure_walks_to_marf_sentinel");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();

        let marf_sentinel = BlockHeaderHash(SENTINEL_ARRAY);

        // B in seq=1 with parent = MARF sentinel.
        let (b_seq, b_off, b_len) = append_blob_with_parent(&mut set, &marf_sentinel, 0);
        set.rotate(&conn).unwrap();
        let bhh_b = bhh(2);
        insert_row_kind(&conn, &bhh_b, b_seq, b_off, b_len, 1);

        // A in seq=2 with parent = B.
        let (a_seq, a_off, a_len) = append_blob_with_parent(&mut set, &bhh_b, 0);
        set.rotate(&conn).unwrap();
        let bhh_a = bhh(1);
        insert_row_kind(&conn, &bhh_a, a_seq, a_off, a_len, 1);

        let orphans = vec![retained_orphan(a_seq, 100, bhh_a, a_off, a_len)];
        let closure =
            precompute_orphan_closure_seqs::<BlockHeaderHash>(&orphans, &set, &conn).unwrap();
        assert_eq!(closure, [b_seq].into_iter().collect());
    }

    /// Three-step chain through three distinct hot seqs: A(seq=3) → B(seq=2) → C(seq=1) →
    /// sentinel. Walk records BOTH ancestor seqs.
    #[test]
    fn closure_records_each_distinct_hot_ancestor_seq() {
        let (db_path, conn) = fresh_v5_db("closure_records_each_distinct_hot_ancestor_seq");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();

        let sentinel = BlockHeaderHash([0u8; 32]);

        // C (seq=1, parent=sentinel)
        let (c_seq, c_off, c_len) = append_blob_with_parent(&mut set, &sentinel, 0);
        set.rotate(&conn).unwrap();
        let bhh_c = bhh(3);
        insert_row_kind(&conn, &bhh_c, c_seq, c_off, c_len, 1);

        // B (seq=2, parent=C)
        let (b_seq, b_off, b_len) = append_blob_with_parent(&mut set, &bhh_c, 0);
        set.rotate(&conn).unwrap();
        let bhh_b = bhh(2);
        insert_row_kind(&conn, &bhh_b, b_seq, b_off, b_len, 1);

        // A (seq=3, parent=B)
        let (a_seq, a_off, a_len) = append_blob_with_parent(&mut set, &bhh_b, 0);
        set.rotate(&conn).unwrap();
        let bhh_a = bhh(1);
        insert_row_kind(&conn, &bhh_a, a_seq, a_off, a_len, 1);

        let orphans = vec![retained_orphan(a_seq, 100, bhh_a, a_off, a_len)];
        let closure =
            precompute_orphan_closure_seqs::<BlockHeaderHash>(&orphans, &set, &conn).unwrap();
        let expected: HashSet<u32> = [b_seq, c_seq].into_iter().collect();
        assert_eq!(closure, expected, "both B and C seqs must be recorded");
    }

    /// Two retained orphans with disjoint ancestor chains. Closure is the union of each chain's
    /// ancestor seqs.
    #[test]
    fn closure_union_across_multiple_retained_orphans() {
        let (db_path, conn) = fresh_v5_db("closure_union_across_multiple_retained_orphans");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();

        let sentinel = BlockHeaderHash([0u8; 32]);

        // Chain 1: B1 (seq=1) → sentinel; A1 (seq=3) → B1.
        let (b1_seq, b1_off, b1_len) = append_blob_with_parent(&mut set, &sentinel, 0);
        set.rotate(&conn).unwrap();
        let bhh_b1 = bhh(11);
        insert_row_kind(&conn, &bhh_b1, b1_seq, b1_off, b1_len, 1);

        // Chain 2: B2 (seq=2) → sentinel.
        let (b2_seq, b2_off, b2_len) = append_blob_with_parent(&mut set, &sentinel, 0);
        set.rotate(&conn).unwrap();
        let bhh_b2 = bhh(22);
        insert_row_kind(&conn, &bhh_b2, b2_seq, b2_off, b2_len, 1);

        // A1 (seq=3) → B1.
        let (a1_seq, a1_off, a1_len) = append_blob_with_parent(&mut set, &bhh_b1, 0);
        set.rotate(&conn).unwrap();
        let bhh_a1 = bhh(1);
        insert_row_kind(&conn, &bhh_a1, a1_seq, a1_off, a1_len, 1);

        // A2 (seq=4) → B2.
        let (a2_seq, a2_off, a2_len) = append_blob_with_parent(&mut set, &bhh_b2, 0);
        set.rotate(&conn).unwrap();
        let bhh_a2 = bhh(2);
        insert_row_kind(&conn, &bhh_a2, a2_seq, a2_off, a2_len, 1);

        let orphans = vec![
            retained_orphan(a1_seq, 100, bhh_a1, a1_off, a1_len),
            retained_orphan(a2_seq, 101, bhh_a2, a2_off, a2_len),
        ];
        let closure =
            precompute_orphan_closure_seqs::<BlockHeaderHash>(&orphans, &set, &conn).unwrap();
        let expected: HashSet<u32> = [b1_seq, b2_seq].into_iter().collect();
        assert_eq!(closure, expected, "union of both chains' hot ancestor seqs");
    }

    /// Two retained orphans converging at a shared ancestor. The visited-parent dedup means the
    /// shared ancestor's row is fetched only once; its seq is recorded once. Demonstrates the DAG
    /// dedup that keeps the walk linear in the union of distinct ancestors.
    #[test]
    fn closure_dedups_shared_ancestor_chain() {
        let (db_path, conn) = fresh_v5_db("closure_dedups_shared_ancestor_chain");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();

        let sentinel = BlockHeaderHash([0u8; 32]);

        // Shared ancestor B (seq=1) → sentinel.
        let (b_seq, b_off, b_len) = append_blob_with_parent(&mut set, &sentinel, 0);
        set.rotate(&conn).unwrap();
        let bhh_b = bhh(2);
        insert_row_kind(&conn, &bhh_b, b_seq, b_off, b_len, 1);

        // A1 (seq=2) → B and A2 (seq=3) → B.
        let (a1_seq, a1_off, a1_len) = append_blob_with_parent(&mut set, &bhh_b, 0);
        set.rotate(&conn).unwrap();
        let bhh_a1 = bhh(11);
        insert_row_kind(&conn, &bhh_a1, a1_seq, a1_off, a1_len, 1);

        let (a2_seq, a2_off, a2_len) = append_blob_with_parent(&mut set, &bhh_b, 0);
        set.rotate(&conn).unwrap();
        let bhh_a2 = bhh(12);
        insert_row_kind(&conn, &bhh_a2, a2_seq, a2_off, a2_len, 1);

        let orphans = vec![
            retained_orphan(a1_seq, 100, bhh_a1, a1_off, a1_len),
            retained_orphan(a2_seq, 100, bhh_a2, a2_off, a2_len),
        ];
        let closure =
            precompute_orphan_closure_seqs::<BlockHeaderHash>(&orphans, &set, &conn).unwrap();
        assert_eq!(
            closure,
            [b_seq].into_iter().collect(),
            "shared ancestor recorded exactly once"
        );
    }

    /// A retained orphan whose `marf_data` row has `external_length` below the parent-hash width
    /// (`< 32`) is corruption — the read couldn't even fill the parent_hash buffer. The closure
    /// walk surfaces this as `Error::CorruptionError` rather than silently skipping (which would
    /// leak ancestors out of the closure).
    #[test]
    fn closure_short_blob_length_is_corruption_error() {
        let (db_path, conn) = fresh_v5_db("closure_short_blob_length_is_corruption_error");
        let stem = db_path.to_str().unwrap();
        let set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();

        // Synthetic short row pointing nowhere meaningful — the validation triggers BEFORE any
        // read_at attempt, so the seq + offset don't have to be live on disk.
        let bhh_a = bhh(1);
        let orphans = vec![retained_orphan(set.active_seq(), 100, bhh_a, 0, 16)];
        let err =
            precompute_orphan_closure_seqs::<BlockHeaderHash>(&orphans, &set, &conn).unwrap_err();
        match err {
            Error::CorruptionError(msg) => assert!(
                msg.contains("trie blob header") && msg.contains("would not fit"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected CorruptionError, got {other:?}"),
        }
    }

    /// **Regression for the C2b under-validation bug**: a row with `external_length` in the
    /// `32..36` range (parent_hash bytes fit, but the 4-byte zero-id slot doesn't) is structurally
    /// impossible per the trie blob format, but the `read_at` path could still satisfy a 32-byte
    /// read from those bytes. The walk MUST fail closed at the *full* header minimum (36) — not
    /// just the read width — so that potentially-corrupt bytes can't participate in ancestry
    /// classification. Pinned per Codex 2026-05-02 finding.
    #[test]
    fn closure_blob_length_in_32_to_35_is_corruption_error() {
        let (db_path, conn) = fresh_v5_db("closure_blob_length_in_32_to_35_is_corruption_error");
        let stem = db_path.to_str().unwrap();
        let set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();

        // Lengths 32, 33, 34, 35 are all in the structurally-impossible band: the parent_hash
        // fits but the zero-id doesn't. Each one must surface as CorruptionError.
        for short_len in 32u64..36 {
            let bhh_a = bhh(1);
            let orphans = vec![retained_orphan(set.active_seq(), 100, bhh_a, 0, short_len)];
            let err = precompute_orphan_closure_seqs::<BlockHeaderHash>(&orphans, &set, &conn)
                .unwrap_err();
            match err {
                Error::CorruptionError(msg) => assert!(
                    msg.contains(&format!("length {short_len}"))
                        && msg.contains("trie blob header"),
                    "len={short_len}: unexpected message: {msg}"
                ),
                other => panic!("len={short_len}: expected CorruptionError, got {other:?}"),
            }
        }
    }

    /// A retained orphan whose direct parent isn't in `marf_data` (e.g. archived legacy row).
    /// `NotFoundError` is treated as terminal, NOT propagated. Closure returns empty.
    #[test]
    fn closure_walk_terminates_on_parent_not_in_marf_data() {
        let (db_path, conn) = fresh_v5_db("closure_walk_terminates_on_parent_not_in_marf_data");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();

        // Orphan A (seq=1), parent = bhh(99) — but bhh(99) is NOT in marf_data.
        let bhh_phantom_parent = bhh(99);
        let (a_seq, a_off, a_len) = append_blob_with_parent(&mut set, &bhh_phantom_parent, 0);
        set.rotate(&conn).unwrap();
        let bhh_a = bhh(1);
        insert_row_kind(&conn, &bhh_a, a_seq, a_off, a_len, 1);

        let orphans = vec![retained_orphan(a_seq, 100, bhh_a, a_off, a_len)];
        let closure =
            precompute_orphan_closure_seqs::<BlockHeaderHash>(&orphans, &set, &conn).unwrap();
        assert!(
            closure.is_empty(),
            "parent missing from marf_data → walk terminates, closure stays empty"
        );
    }

    // ===========================================================================
    // C3: apply_unlinkable
    // ===========================================================================
    //
    // Tests use a real `HotFileSet` so they exercise the full mutate_pending + quiesce + DELETE +
    // drop_seq + unlink path. The cross-handle fence test opens a SECOND `HotFileSet` on the same
    // db path; both share the same `Arc<ReaderFence>` per-seq via the process-wide
    // `shared_reader_fence_for` registry — that's the actual coordinator-vs-peer-handle scenario.

    use crate::chainstate::stacks::index::hot_file::hot_file_path;

    fn count_hot_rows_for_seq(conn: &Connection, seq: u32) -> u64 {
        conn.query_row(
            "SELECT COUNT(*) FROM marf_data WHERE storage_kind = 1 AND storage_seq = ?1",
            rusqlite::params![seq as i64],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n as u64)
        .unwrap()
    }

    /// Happy path: file with multiple live rows → DELETE removes all of them, file is unlinked,
    /// HotFileSet entry is gone, return value matches the row count.
    #[test]
    fn apply_unlinkable_deletes_rows_and_unlinks_file() {
        let (db_path, conn) = fresh_v5_db("apply_unlinkable_deletes_rows_and_unlinks_file");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();

        // Build seq=1 with two synthetic rows; rotate so it becomes a non-active sweep candidate.
        let bhh_a = bhh(1);
        let (a_seq, a_off, a_len) = append_blob_with_parent(&mut set, &bhh_a, 0);
        insert_row_kind(&conn, &bhh_a, a_seq, a_off, a_len, 1);
        let bhh_b = bhh(2);
        let (b_seq, b_off, b_len) = append_blob_with_parent(&mut set, &bhh_b, 0);
        assert_eq!(
            b_seq, a_seq,
            "both rows are in the same active seq pre-rotate"
        );
        insert_row_kind(&conn, &bhh_b, b_seq, b_off, b_len, 1);
        set.rotate(&conn).unwrap();
        assert_eq!(set.active_seq(), 2, "post-rotate active is seq=2");

        let on_disk_path = hot_file_path(stem, a_seq);
        assert!(std::path::Path::new(&on_disk_path).exists());

        let rows_deleted = apply_unlinkable(
            &mut set,
            &conn,
            a_seq,
            DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
        )
        .unwrap();

        assert_eq!(rows_deleted, 2);
        assert_eq!(count_hot_rows_for_seq(&conn, a_seq), 0);
        assert!(
            !std::path::Path::new(&on_disk_path).exists(),
            "hot file must be unlinked"
        );
        assert!(
            set.iter().all(|(s, _)| s != a_seq),
            "HotFileSet entry must be dropped"
        );
    }

    /// Fully-promoted file (the §7.1(a) case): zero matching `marf_data` rows. DELETE returns 0,
    /// but the file still gets unlinked. This is the load-bearing path C2a's
    /// `classify_empty_live_rows_returns_unlinkable` short-circuit feeds into.
    #[test]
    fn apply_unlinkable_unlinks_file_with_zero_rows() {
        let (db_path, conn) = fresh_v5_db("apply_unlinkable_unlinks_file_with_zero_rows");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();
        // Append a blob to seq=1 just so the file exists on disk; do NOT insert any marf_data row.
        let _ = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        set.rotate(&conn).unwrap();
        let on_disk_path = hot_file_path(stem, 1);
        assert!(std::path::Path::new(&on_disk_path).exists());

        let rows_deleted =
            apply_unlinkable(&mut set, &conn, 1, DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT).unwrap();

        assert_eq!(rows_deleted, 0);
        assert!(!std::path::Path::new(&on_disk_path).exists());
    }

    /// **Defensive guard regression**: a caller passing the *active* hot seq (i.e. the writer's
    /// current append target) MUST be rejected with `CorruptionError` before any mutation
    /// happens. C1's enumerator already filters the active seq out, so this guard is
    /// belt-and-suspenders — but a misrouted active-seq would otherwise wipe live writer state +
    /// the rows backing it (next append: EBADF + on-disk corruption). Pinned per Codex 2026-05-02
    /// finding.
    #[test]
    fn apply_unlinkable_refuses_active_seq() {
        let (db_path, conn) = fresh_v5_db("apply_unlinkable_refuses_active_seq");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();

        // Append a row pointing at the active seq so we can prove neither the row nor the file
        // were touched after the rejection.
        let bhh_a = bhh(1);
        let active_seq = set.active_seq();
        let (a_seq, a_off, a_len) = append_blob_with_parent(&mut set, &bhh_a, 0);
        assert_eq!(a_seq, active_seq, "row landed in active seq pre-call");
        insert_row_kind(&conn, &bhh_a, a_seq, a_off, a_len, 1);
        let on_disk_path = hot_file_path(stem, active_seq);
        assert!(std::path::Path::new(&on_disk_path).exists());

        let err = apply_unlinkable(
            &mut set,
            &conn,
            active_seq,
            DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
        )
        .unwrap_err();
        match err {
            Error::CorruptionError(msg) => assert!(
                msg.contains("active hot seq") && msg.contains(&format!("seq={active_seq}")),
                "expected message naming the active seq, got: {msg}"
            ),
            other => panic!("expected CorruptionError, got {other:?}"),
        }

        // Critical: nothing was mutated.
        assert_eq!(
            count_hot_rows_for_seq(&conn, active_seq),
            1,
            "row backing the active seq must NOT be deleted"
        );
        assert!(
            std::path::Path::new(&on_disk_path).exists(),
            "active hot file must NOT be unlinked"
        );
        assert!(
            set.iter().any(|(s, _)| s == active_seq),
            "active seq must remain in HotFileSet"
        );
    }

    /// Caller passes a seq that isn't in the HotFileSet → CorruptionError surfaced from
    /// `path_for_seq`. Validates the precondition catch.
    #[test]
    fn apply_unlinkable_unknown_seq_returns_corruption_error() {
        let (db_path, conn) = fresh_v5_db("apply_unlinkable_unknown_seq_returns_corruption_error");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();

        let err = apply_unlinkable(
            &mut set,
            &conn,
            999,
            DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
        )
        .unwrap_err();
        match err {
            Error::CorruptionError(msg) => assert!(
                msg.contains("seq=999"),
                "expected message naming seq=999, got: {msg}"
            ),
            other => panic!("expected CorruptionError, got {other:?}"),
        }
    }

    /// **Cross-handle fence semantics**: a peer-handle reader holding a `HotFileReadGuard` on the
    /// target seq blocks the writer's `wait_for_quiesce`. The writer times out, returns
    /// `InProgressError`, and clears the fence so the reader can proceed afterward. SQL rows + the
    /// file must remain intact so the next sweep trigger can retry.
    ///
    /// After dropping the reader's guard, a follow-up `apply_unlinkable` succeeds. This proves the
    /// fence-cleared cleanup works (otherwise the second call's `set_mutate_pending(true)` would
    /// stack on top of an already-set flag and observably misbehave).
    #[test]
    fn apply_unlinkable_quiesce_timeout_clears_fence_and_preserves_state() {
        let (db_path, conn) =
            fresh_v5_db("apply_unlinkable_quiesce_timeout_clears_fence_and_preserves_state");
        let stem = db_path.to_str().unwrap();

        // Coordinator-side HotFileSet (the one running apply_unlinkable).
        let mut writer_set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();
        let bhh_a = bhh(1);
        let (a_seq, a_off, a_len) = append_blob_with_parent(&mut writer_set, &bhh_a, 0);
        insert_row_kind(&conn, &bhh_a, a_seq, a_off, a_len, 1);
        writer_set.rotate(&conn).unwrap();

        // Peer-handle HotFileSet (read-only). Same path → same `Arc<ReaderFence>` per-seq via the
        // process-wide registry.
        let peer_conn = Connection::open(&db_path).unwrap();
        let peer_set = HotFileSet::open(stem, &peer_conn, false, 4096, true).unwrap();

        // Acquire a peer read guard. While this guard is alive, `active_reads >= 1` for seq=a_seq.
        let _peer_guard = peer_set.acquire_read_guard(a_seq).unwrap();

        // Short timeout — apply_unlinkable's wait_for_quiesce should give up quickly.
        let err = apply_unlinkable(
            &mut writer_set,
            &conn,
            a_seq,
            std::time::Duration::from_millis(80),
        )
        .unwrap_err();
        match err {
            Error::InProgressError => {}
            other => panic!("expected InProgressError, got {other:?}"),
        }

        // SQL rows + on-disk file must be untouched on the abort path.
        assert_eq!(
            count_hot_rows_for_seq(&conn, a_seq),
            1,
            "rows must NOT be deleted on timeout"
        );
        assert!(
            std::path::Path::new(&hot_file_path(stem, a_seq)).exists(),
            "file must NOT be unlinked on timeout"
        );
        assert!(
            writer_set.iter().any(|(s, _)| s == a_seq),
            "HotFileSet entry must remain on timeout"
        );

        // The fence MUST be cleared. We don't have a direct getter, so prove it indirectly: a
        // fresh peer guard on a third handle MUST be acquirable without backoff. (If
        // mutate_pending were still set, `try_from_fence` would return None on the first try and
        // `acquire_read_guard` would spin.)
        let third_conn = Connection::open(&db_path).unwrap();
        let third_set = HotFileSet::open(stem, &third_conn, false, 4096, true).unwrap();
        let start = std::time::Instant::now();
        let _third_guard = third_set.acquire_read_guard(a_seq).unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(20),
            "fence must be cleared after timeout — guard acquisition spun for {elapsed:?}"
        );

        // Drop the blocking peer guard; a follow-up apply_unlinkable must now succeed end-to-end.
        drop(_peer_guard);
        drop(_third_guard);
        let rows_deleted = apply_unlinkable(
            &mut writer_set,
            &conn,
            a_seq,
            DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
        )
        .unwrap();
        assert_eq!(rows_deleted, 1);
        assert!(!std::path::Path::new(&hot_file_path(stem, a_seq)).exists());
    }

    // ===========================================================================
    // C4: sweep_unlinkable_hot_files
    // ===========================================================================
    //
    // These tests exercise the per-MARF sweep loop end-to-end with synthetic candidates: each
    // builds a `HotFileSet` + corresponding `marf_data` rows, then calls
    // `sweep_unlinkable_hot_files` with a hand-built canonical-chain map + height-lookup closure
    // (no chainstate stub needed).

    /// Helper: build a `height_lookup` closure backed by a `(StacksBlockId, height)` map. Mirrors
    /// the C2a test helper but typed for the StacksBlockId case used by the sweep dispatch.
    fn height_lookup_bhh<'a>(
        pairs: &'a [(BlockHeaderHash, u32)],
    ) -> impl FnMut(&BlockHeaderHash) -> Result<Option<u32>, Error> + 'a {
        let map: HashMap<BlockHeaderHash, u32> = pairs.iter().cloned().collect();
        move |bhh: &BlockHeaderHash| Ok(map.get(bhh).copied())
    }

    /// Empty hot tier (only the active file exists, no rotated candidates) → empty stats.
    #[test]
    fn sweep_no_candidates_returns_default_stats() {
        let (db_path, conn) = fresh_v5_db("sweep_no_candidates_returns_default_stats");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 4096, false).unwrap();
        let canonical: HashMap<u32, BlockHeaderHash> = HashMap::new();
        let stats = sweep_unlinkable_hot_files(
            &mut set,
            &conn,
            &canonical,
            None,
            |_: &BlockHeaderHash| Ok(None),
            DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
        )
        .unwrap();
        assert_eq!(stats, SweepStats::default());
    }

    /// **§7.4 ordering + apply-all-then-stop semantics (Q1)**: three rotated files, oldest-to-
    /// newest. File 1 is fully promoted (Unlinkable). File 2 holds a canonical row (NotUnlinkable
    /// → triggers early-stop in the APPLY walk). File 3 is fully promoted but the apply walk
    /// stops at file 2 per §7.4, so file 3 stays on disk. File 1 is applied. Final disk state:
    /// file 1 gone, files 2 and 3 still present.
    ///
    /// Note: post Codex 2026-05-02, the classifier visits ALL three files (no early-stop in
    /// step 2). The early-stop happens in step 4 (apply walk). File 3 contributes no retained
    /// orphans (no rows), so its classification is a no-op for closure purposes.
    #[test]
    fn sweep_oldest_first_with_early_stop_at_apply_phase() {
        let (db_path, conn) = fresh_v5_db("sweep_oldest_first_with_early_stop_at_apply_phase");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 64, false).unwrap();

        // Build three rotated seqs: 1, 2, 3. Active becomes 4.
        // seq=1: fully promoted (no rows).
        let _ = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        set.rotate(&conn).unwrap();
        // seq=2: holds a canonical row.
        let bhh_canon = bhh(2);
        let (s2, off2, len2) = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        insert_row_kind(&conn, &bhh_canon, s2, off2, len2, 1);
        set.rotate(&conn).unwrap();
        // seq=3: fully promoted (no rows).
        let _ = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        set.rotate(&conn).unwrap();
        assert_eq!(set.active_seq(), 4);

        // Canonical chain says bhh(2) IS canonical at height 10.
        let canonical: HashMap<u32, BlockHeaderHash> =
            [(10, bhh_canon.clone())].into_iter().collect();

        let stats = sweep_unlinkable_hot_files(
            &mut set,
            &conn,
            &canonical,
            Some(20),
            height_lookup_bhh(&[(bhh_canon.clone(), 10)]),
            DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
        )
        .unwrap();

        assert_eq!(
            stats.files_unlinked, 1,
            "only file 1 reached the apply phase before early-stop"
        );
        assert_eq!(stats.rows_deleted, 0, "file 1 was fully promoted (no rows)");
        assert_eq!(
            stats.files_retained_by_classifier, 1,
            "file 2 latches NotUnlinkable + triggers apply-phase early-stop"
        );
        assert_eq!(stats.files_blocked_by_closure, 0);
        assert_eq!(stats.files_deferred_for_quiesce, 0);

        // Disk state: file 1 unlinked, files 2 + 3 still present.
        assert!(!std::path::Path::new(&hot_file_path(stem, 1)).exists());
        assert!(std::path::Path::new(&hot_file_path(stem, 2)).exists());
        assert!(
            std::path::Path::new(&hot_file_path(stem, 3)).exists(),
            "file 3 must NOT be unlinked — apply-phase early-stop at file 2 prevents reaching it"
        );
    }

    /// **Regression for the Codex 2026-05-02 finding**: the classifier MUST walk every candidate
    /// (no early-stop in step 2), otherwise C2b's closure precompute misses retained orphans in
    /// younger files whose ancestors live in older tentative-Unlinkable files.
    ///
    /// Setup:
    /// - seq=1: holds row B (parent=sentinel). B at height 10, past horizon (20) → orphan
    ///   past-horizon → tentative Unlinkable.
    /// - seq=2: holds canonical row → tentative NotUnlinkable.
    /// - seq=3: holds retained orphan A (parent=B). A at height 50, ABOVE horizon → retained.
    ///
    /// Without the fix: classifier early-stops at seq=2, never sees A's retained orphan in seq=3,
    /// closure_set is empty, apply phase: seq=1 → applied (UNLINKED INCORRECTLY — its row B is A's
    /// parent and reorg replay would need it).
    ///
    /// With the fix: classifier visits all three. A surfaces from seq=3. Closure walk: read A's
    /// blob → parent=B → look up B → hot seq=1 → record 1 in closure. Apply phase: seq=1 → in
    /// closure_set → blocked, not unlinked. Apply phase early-stops at seq=2 (NotUnlinkable). Net:
    /// nothing unlinked, file 1 correctly preserved.
    #[test]
    fn sweep_classifier_visits_younger_files_so_closure_can_block_older_unlink() {
        let (db_path, conn) =
            fresh_v5_db("sweep_classifier_visits_younger_files_so_closure_can_block_older_unlink");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 64, false).unwrap();

        // seq=1: row B (parent=sentinel, will be classified past-horizon orphan).
        let bhh_b = bhh(2);
        let (s1, off1, len1) = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        insert_row_kind(&conn, &bhh_b, s1, off1, len1, 1);
        set.rotate(&conn).unwrap();

        // seq=2: canonical row.
        let bhh_canon = bhh(7);
        let (s2, off2, len2) = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        insert_row_kind(&conn, &bhh_canon, s2, off2, len2, 1);
        set.rotate(&conn).unwrap();

        // seq=3: retained orphan A (parent=B). A's parent is B in seq=1, the closure-relevant
        // ancestor.
        let bhh_a = bhh(1);
        let (s3, off3, len3) = append_blob_with_parent(&mut set, &bhh_b, 0);
        insert_row_kind(&conn, &bhh_a, s3, off3, len3, 1);
        set.rotate(&conn).unwrap();
        assert_eq!(set.active_seq(), 4);

        // Canonical chain: bhh_canon canonical at h=30; B at h=10 is orphan; A at h=50 is orphan.
        let canonical: HashMap<u32, BlockHeaderHash> =
            [(10, bhh(98)), (30, bhh_canon.clone()), (50, bhh(99))]
                .into_iter()
                .collect();
        let stats = sweep_unlinkable_hot_files(
            &mut set,
            &conn,
            &canonical,
            Some(20), // B (h=10) past horizon; A (h=50) retained
            height_lookup_bhh(&[(bhh_b, 10), (bhh_canon, 30), (bhh_a, 50)]),
            DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
        )
        .unwrap();

        // The critical assertions: file 1 must NOT be unlinked.
        assert_eq!(
            stats.files_unlinked, 0,
            "file 1 must NOT be unlinked — A's ancestor lives there"
        );
        assert_eq!(
            stats.files_blocked_by_closure, 1,
            "file 1 must be in closure_set (B is A's parent)"
        );
        assert_eq!(
            stats.files_retained_by_classifier, 1,
            "apply phase early-stops at file 2 (NotUnlinkable)"
        );
        assert!(
            std::path::Path::new(&hot_file_path(stem, 1)).exists(),
            "file 1 MUST stay on disk"
        );
        assert!(std::path::Path::new(&hot_file_path(stem, 2)).exists());
        assert!(std::path::Path::new(&hot_file_path(stem, 3)).exists());
    }

    /// **Apply-all-then-stop with multiple reclaimable files**: two consecutive fully-promoted
    /// files at the bottom, then a NotUnlinkable file. Both reclaimable files are applied in one
    /// sweep call (apply-all, not apply-one), then early-stop at file 3.
    #[test]
    fn sweep_applies_all_reclaimable_before_early_stop() {
        let (db_path, conn) = fresh_v5_db("sweep_applies_all_reclaimable_before_early_stop");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 64, false).unwrap();

        // seq=1: fully promoted.
        let _ = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        set.rotate(&conn).unwrap();
        // seq=2: fully promoted.
        let _ = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        set.rotate(&conn).unwrap();
        // seq=3: canonical row.
        let bhh_canon = bhh(2);
        let (s3, off3, len3) = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        insert_row_kind(&conn, &bhh_canon, s3, off3, len3, 1);
        set.rotate(&conn).unwrap();
        assert_eq!(set.active_seq(), 4);

        let canonical: HashMap<u32, BlockHeaderHash> =
            [(10, bhh_canon.clone())].into_iter().collect();
        let stats = sweep_unlinkable_hot_files(
            &mut set,
            &conn,
            &canonical,
            Some(20),
            height_lookup_bhh(&[(bhh_canon.clone(), 10)]),
            DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
        )
        .unwrap();

        assert_eq!(
            stats.files_unlinked, 2,
            "both files 1 + 2 applied in one call"
        );
        assert_eq!(stats.files_retained_by_classifier, 1);
        assert!(!std::path::Path::new(&hot_file_path(stem, 1)).exists());
        assert!(!std::path::Path::new(&hot_file_path(stem, 2)).exists());
        assert!(std::path::Path::new(&hot_file_path(stem, 3)).exists());
    }

    /// **C2b closure blocks final unlink**: file 1 looks tentative-Unlinkable per the classifier,
    /// but it holds an ancestor row of a retained orphan in file 2. Sweep applies neither file:
    /// file 1 is blocked by closure, file 2 is NotUnlinkable (the retained orphan itself).
    #[test]
    fn sweep_closure_blocks_tentative_unlinkable_file() {
        let (db_path, conn) = fresh_v5_db("sweep_closure_blocks_tentative_unlinkable_file");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 64, false).unwrap();

        // seq=1: holds row B (parent=sentinel). B will be classified Past-Horizon (at height 10),
        // so file 1's tentative verdict is Unlinkable. But B is the ancestor of orphan A in file 2,
        // so closure blocks the unlink.
        let bhh_b = bhh(2);
        let (s1, off1, len1) = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        insert_row_kind(&conn, &bhh_b, s1, off1, len1, 1);
        set.rotate(&conn).unwrap();

        // seq=2: holds orphan A (parent=B). A is at height 50 → above horizon (20) → retained.
        let bhh_a = bhh(1);
        let (s2, off2, len2) = append_blob_with_parent(&mut set, &bhh_b, 0);
        insert_row_kind(&conn, &bhh_a, s2, off2, len2, 1);
        set.rotate(&conn).unwrap();
        assert_eq!(set.active_seq(), 3);

        // Canonical chain at heights 10 + 50 says different bhhs → both rows are orphans.
        let canonical: HashMap<u32, BlockHeaderHash> =
            [(10, bhh(98)), (50, bhh(99))].into_iter().collect();

        let stats = sweep_unlinkable_hot_files(
            &mut set,
            &conn,
            &canonical,
            Some(20),
            height_lookup_bhh(&[(bhh_b, 10), (bhh_a, 50)]),
            DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
        )
        .unwrap();

        // File 1 is tentative-Unlinkable (B is past-horizon orphan) but blocked by closure
        // (B is A's parent, A is retained).
        // File 2 is NotUnlinkable (A is retained orphan), early-stop.
        assert_eq!(stats.files_unlinked, 0, "neither file should be unlinked");
        assert_eq!(
            stats.files_blocked_by_closure, 1,
            "file 1 blocked by closure"
        );
        assert_eq!(
            stats.files_retained_by_classifier, 1,
            "file 2 holds retained orphan"
        );

        assert!(std::path::Path::new(&hot_file_path(stem, 1)).exists());
        assert!(std::path::Path::new(&hot_file_path(stem, 2)).exists());
    }

    /// All-orphan-past-horizon files (no canonical rows, no retained orphans) → all applied,
    /// closure set is empty (no retained orphans → nothing to walk).
    #[test]
    fn sweep_unlinks_all_past_horizon_orphan_files() {
        let (db_path, conn) = fresh_v5_db("sweep_unlinks_all_past_horizon_orphan_files");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 64, false).unwrap();

        let bhh_x = bhh(7);
        let bhh_y = bhh(8);
        let (s1, off1, len1) = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        insert_row_kind(&conn, &bhh_x, s1, off1, len1, 1);
        set.rotate(&conn).unwrap();
        let (s2, off2, len2) = append_blob_with_parent(&mut set, &BlockHeaderHash([0u8; 32]), 0);
        insert_row_kind(&conn, &bhh_y, s2, off2, len2, 1);
        set.rotate(&conn).unwrap();

        // Canonical chain has DIFFERENT bhh's → both rows orphans. Heights at/below horizon (20).
        let canonical: HashMap<u32, BlockHeaderHash> =
            [(5, bhh(98)), (10, bhh(99))].into_iter().collect();
        let stats = sweep_unlinkable_hot_files(
            &mut set,
            &conn,
            &canonical,
            Some(20),
            height_lookup_bhh(&[(bhh_x, 5), (bhh_y, 10)]),
            DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT,
        )
        .unwrap();

        assert_eq!(stats.files_unlinked, 2);
        assert_eq!(stats.rows_deleted, 2);
        assert_eq!(stats.files_blocked_by_closure, 0);
        assert_eq!(stats.files_retained_by_classifier, 0);
    }
}
