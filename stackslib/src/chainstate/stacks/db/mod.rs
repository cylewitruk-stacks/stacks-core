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

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::prelude::*;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, io};

use clarity::vm::analysis::analysis_db::AnalysisDatabase;
use clarity::vm::clarity::TransactionConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::database::{
    BurnStateDB, ClarityDatabase, HeadersDB, STXBalance, NULL_BURN_STATE_DB,
};
use clarity::vm::errors::ClarityEvalError;
use clarity::vm::events::*;
use clarity::vm::representations::ContractName;
use clarity::vm::types::TupleData;
use clarity::vm::{SymbolicExpression, Value};
use parking_lot::{Mutex, MutexGuard};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::de::Error as de_Error;
use serde::Deserialize;
use stacks_common::codec::{read_next, write_next, StacksMessageCodec};
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId, TrieHash};
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::util::hash::{hex_bytes, to_hex};

use crate::burnchains::bitcoin::address::LegacyBitcoinAddress;
use crate::burnchains::{Address, Burnchain, BurnchainParameters, PoxConstants};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::operations::{
    DelegateStxOp, StackStxOp, TransferStxOp, VoteForAggregateKeyOp,
};
use crate::chainstate::burn::{ConsensusHash, ConsensusHashExtensions};
use crate::chainstate::nakamoto::{
    HeaderTypeNames, NakamotoBlockHeader, NakamotoChainState, NakamotoStagingBlocksConn,
    NAKAMOTO_CHAINSTATE_SCHEMA_1, NAKAMOTO_CHAINSTATE_SCHEMA_2, NAKAMOTO_CHAINSTATE_SCHEMA_3,
    NAKAMOTO_CHAINSTATE_SCHEMA_4, NAKAMOTO_CHAINSTATE_SCHEMA_5, NAKAMOTO_CHAINSTATE_SCHEMA_6,
    NAKAMOTO_CHAINSTATE_SCHEMA_7, NAKAMOTO_CHAINSTATE_SCHEMA_8,
};
use crate::chainstate::stacks::address::StacksAddressExtensions;
use crate::chainstate::stacks::boot::*;
use crate::chainstate::stacks::db::accounts::*;
use crate::chainstate::stacks::db::blocks::*;
use crate::chainstate::stacks::db::unconfirmed::UnconfirmedState;
use crate::chainstate::stacks::events::*;
use crate::chainstate::stacks::index::marf::{
    test_override_marf_compression, MARFOpenOpts, MarfConnection, MARF,
};
use crate::chainstate::stacks::index::squash::SquashMode;
use crate::chainstate::stacks::index::{ClarityMarfTrieId, Error as marf_error};
use crate::chainstate::stacks::{
    Error, StacksBlockHeader, StacksMicroblockHeader, C32_ADDRESS_VERSION_MAINNET_MULTISIG,
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_MULTISIG,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG, *,
};
use crate::clarity_vm::clarity::{
    ClarityBlockConnection, ClarityConnection, ClarityError, ClarityInstance,
    ClarityReadOnlyConnection, PreCommitClarityBlock,
};
use crate::clarity_vm::database::marf::MarfedKV;
use crate::clarity_vm::database::HeadersDBConn;
use crate::core::*;
use crate::monitoring;
use crate::net::atlas::BNS_CHARS_REGEX;
use crate::util_lib::boot::{boot_code_acc, boot_code_addr, boot_code_id, boot_code_tx_auth};
use crate::util_lib::db::{
    query_row, DBConn, DBTx, Error as db_error, FromColumn, FromRow, IndexDBConn, IndexDBTx,
};

pub mod accounts;
pub mod blocks;
pub mod contracts;
pub mod headers;
pub mod transactions;
pub mod unconfirmed;

/// Fault injection struct for various kinds of faults we'd like to introduce into the system
pub struct StacksChainStateFaults {
    // if true, then the envar STACKS_HIDE_BLOCKS_AT_HEIGHT will be consulted to get a list of
    // Stacks block heights to never propagate or announce.
    pub hide_blocks: bool,
}

impl StacksChainStateFaults {
    pub fn new() -> Self {
        Self { hide_blocks: false }
    }
}

pub struct StacksChainState {
    pub mainnet: bool,
    pub chain_id: u32,
    pub clarity_state: ClarityInstance,
    pub nakamoto_staging_blocks_conn: NakamotoStagingBlocksConn,
    pub state_index: MARF<StacksBlockId>,
    pub blocks_path: String,
    pub clarity_state_index_path: String, // path to clarity MARF
    pub clarity_state_index_root: String, // path to dir containing clarity MARF and side-store
    pub root_path: String,
    /// Cross-handle shared slot holding the in-memory unconfirmed/microblock state.
    /// See [`SharedUnconfirmedState`] for the threading model: multiple per-thread
    /// `StacksChainState` handles can be constructed against the same slot so they all
    /// observe the same `Option<UnconfirmedState>` behind a single mutex.
    pub unconfirmed_state: SharedUnconfirmedState,
    pub fault_injection: StacksChainStateFaults,
    marf_opts: Option<MARFOpenOpts>,
    /// Cadence policy for the headers MARF. Defaults to
    /// [`SquashCadenceConfig::default_headers`] —
    /// `fixed_cadence(MARF_SQUASH_CADENCE_BLOCKS)`. Headers squash is
    /// sub-second on observed mainnet workloads; smoothing isn't worth the
    /// variance loss, so the legacy block-aligned cadence is preserved.
    /// Tests and integration runners can override post-construction (the
    /// field is `pub`); a future operator-facing `Config` plumbing will
    /// populate this from TOML.
    pub squash_cadence_headers: SquashCadenceConfig,
    /// Cadence policy for the Clarity MARF. Defaults to
    /// [`SquashCadenceConfig::default_clarity`] — work-aware (64 MiB /
    /// 100..2000 blocks). Diverges intentionally from the headers default
    /// per `.docs/adaptive-squash-cadence.md` §2.4: Clarity dominates
    /// squash wall-clock (~4–7 s on mainnet's level 14) and benefits most
    /// from work-driven pause-amplitude smoothing. Values are first-cut
    /// estimates pending a calibration pass (Step 7).
    pub squash_cadence_clarity: SquashCadenceConfig,
    /// Per-deployment retention window for squash-root snapshot sidecars,
    /// in **Stacks blocks**. Passed to `MARF::trim_sidecars` after each
    /// successful squash by [`Self::maybe_squash`]. Resolved at
    /// chainstate-open time from `MARFOpenOpts` via
    /// `resolve_retention_blocks`; defaults to
    /// `MARF_ROOT_SNAPSHOT_RETENTION_BLOCKS` if neither legacy nor new
    /// config field is explicit.
    pub squash_sidecar_retention_blocks: u32,
    /// **v1.5 Phase B**: burnchain reorg horizon used by
    /// [`should_squash`]'s horizon predicate (in burn blocks). For
    /// hot-tier MARFs, a squash range may publish only when
    /// `burn_tip - burn_at(prospective_max_height) >= this`. Default
    /// `6` matches Bitcoin's standard reorg-confirmation window plus
    /// margin; legacy (non-hot-tier) MARFs ignore this value.
    /// `MARFOpenOpts::squash_horizon_burn_blocks` overrides at open
    /// time (test/ops only); future production wiring will read from
    /// `marf_state.horizon_burn_blocks` via the per-MARF storage.
    pub squash_horizon_burn_blocks: u32,
    /// **B5d-fu.2**: detached-spawn handle for the headers MARF's
    /// in-flight horizon-gated promotion. `None` when no worker is
    /// running. Drained at the top of [`Self::maybe_squash`] (and
    /// from explicit [`Self::poll_pending_promotions`] calls); on
    /// completion, the coordinator runs `refresh_after_squash` +
    /// `trim_sidecars` on its live handle.
    ///
    /// Single-flight per MARF: while `Some`, `maybe_squash` skips
    /// hot-tier dispatch for headers — the cadence policy will
    /// re-fire on the next block once the worker is reaped.
    pub(crate) headers_promotion_handle: Option<PromotionTaskHandle>,
    /// Counterpart to `headers_promotion_handle` for the Clarity
    /// MARF.
    pub(crate) clarity_promotion_handle: Option<PromotionTaskHandle>,
}

/// Handle for a detached hot-tier promotion **prepare** worker.
///
/// Owns the spawned thread's `JoinHandle`. `is_finished()` is non-blocking and lets the
/// coordinator poll without join-blocking. `join()` returns the worker's `Result`; on a
/// `JoinHandle` panic the coordinator `resume_unwind`s rather than continue with a possibly-
/// corrupt chainstate.
///
/// **Worker = prepare-only.** The thread runs
/// [`crate::chainstate::stacks::index::squash_promote::run_horizon_gated_promotion_at_path`],
/// which stops at "plan file is durable on disk" and returns a `PreparedPromotion`. The
/// coordinator's [`StacksChainState::poll_pending_promotions`] reaps the worker, builds a
/// canonical view anchored at the chainstate's just-advanced tip via
/// [`crate::chainstate::stacks::db::headers::HeadersCanonicalView::from_chainstate_tip`]
/// (same source [`StacksChainState::assert_squash_consistency`] walks for divergence
/// detection), and calls `apply_prepared_plan` to validate + publish. This split is what
/// closes the runtime stale-tip publish window: the publish gate sees the same canonical
/// chain the divergence detector will see, not the worker's scan-start snapshot or the
/// sortition's view of canonical (which can disagree with the chainstate's view during block
/// processing).
pub struct PromotionTaskHandle {
    /// Diagnostic label: `"headers"` or `"clarity"`. Threaded through to logs so polled
    /// completion / panic messages are attributable.
    label: &'static str,
    /// MARF db path the worker is operating on. Diagnostic / debugging aid.
    #[allow(dead_code)]
    path: String,
    /// The worker thread.
    ///
    /// Payload semantics:
    /// - `Ok(Some(prepared))`: prepare completed; coordinator should validate + publish.
    /// - `Ok(None)`: nothing to publish, but coordinator should `refresh_after_squash` (this
    ///   happens when worker-side recovery published a prior plan during `from_path` and the
    ///   live prepare's range is now stale).
    /// - `Err(e)`: prepare failed; coordinator logs and skips publish for this MARF this tick.
    join_handle: std::thread::JoinHandle<
        Result<
            Option<crate::chainstate::stacks::index::squash_promote::PreparedPromotion>,
            marf_error,
        >,
    >,
}

/// Result of [`StacksChainState::poll_pending_promotions`]: which detached promotion workers
/// completed (and successfully published a new squash level) since the last poll. Drives the
/// Phase C hot-reclaim sweep dispatch in [`StacksChainState::sweep_after_promotions`] — the sweep
/// runs only on MARFs whose `*_promoted` flag is `true`, since hot-file unlinkability transitions
/// only happen at promotion (rows flip `storage_kind = 1` → `0`).
///
/// Callers that don't care about the sweep dispatch (e.g. the explicit-drain shutdown path) can
/// ignore the return value; the next `maybe_squash` invocation handles the sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PromotionsReaped {
    pub headers_promoted: bool,
    pub clarity_promoted: bool,
}

impl PromotionsReaped {
    pub fn any_promoted(&self) -> bool {
        self.headers_promoted || self.clarity_promoted
    }
}

/// Cross-handle shared slot for in-memory unconfirmed/microblock state.
///
/// Wraps `Arc<parking_lot::Mutex<Option<UnconfirmedState>>>` so multiple
/// independent `StacksChainState` handles (one per thread — relayer, p2p, miner)
/// observe the same [`UnconfirmedState`]. This preserves cross-thread coherence
/// for the one subsystem that needs it (relayer writes, p2p reads, miner
/// snapshots) without serializing confirmed-state operations behind any
/// process-wide lock.
///
/// `Arc::clone` shares the slot. Each lock acquisition serializes all readers
/// and writers — `UnconfirmedState` carries a `ClarityInstance`/`MarfedKV`
/// with `!Sync` interior mutability, so a `Mutex` is required (not `RwLock`).
///
/// Threads obtain the slot via `Globals::get_shared_unconfirmed()` and pass it
/// to [`StacksChainState::open_with_shared_unconfirmed`] when opening their
/// per-thread handle.
#[derive(Clone)]
pub struct SharedUnconfirmedState {
    inner: Arc<Mutex<Option<UnconfirmedState>>>,
}

impl SharedUnconfirmedState {
    /// Empty slot — no unconfirmed state instantiated yet. Sole construction
    /// path; callers create an empty slot at chainstate-open time and the
    /// relayer populates it later via [`StacksChainState::reload_unconfirmed_state`].
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }

    /// Acquire the inner mutex. Blocking — squash-style retry-on-conflict is not used
    /// here because unconfirmed-state mutation paths (refresh, drop, reload) are all
    /// called from a single thread (the relayer) in production, so the contention
    /// surface stays small (rare writes, brief reads).
    pub fn lock(&self) -> MutexGuard<'_, Option<UnconfirmedState>> {
        self.inner.lock()
    }
}

impl Default for SharedUnconfirmedState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksAccount {
    pub principal: PrincipalData,
    pub nonce: u64,
    pub stx_balance: STXBalance,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MinerPaymentTxFees {
    Epoch2 { anchored: u128, streamed: u128 },
    Nakamoto { parent_fees: u128 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct MinerPaymentSchedule {
    pub address: StacksAddress,
    pub recipient: PrincipalData,
    pub block_hash: BlockHeaderHash,
    pub consensus_hash: ConsensusHash,
    pub parent_block_hash: BlockHeaderHash,
    pub parent_consensus_hash: ConsensusHash,
    pub coinbase: u128,
    pub tx_fees: MinerPaymentTxFees,
    pub burnchain_commit_burn: u64,
    pub burnchain_sortition_burn: u64,
    pub miner: bool, // is this a schedule payment for the block's miner?
    pub stacks_block_height: u64,
    pub vtxindex: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StacksBlockHeaderTypes {
    Epoch2(StacksBlockHeader),
    Nakamoto(NakamotoBlockHeader),
}

impl From<StacksBlockHeader> for StacksBlockHeaderTypes {
    fn from(value: StacksBlockHeader) -> Self {
        Self::Epoch2(value)
    }
}

impl From<NakamotoBlockHeader> for StacksBlockHeaderTypes {
    fn from(value: NakamotoBlockHeader) -> Self {
        Self::Nakamoto(value)
    }
}

/// Reorg-divergence record returned by [`StacksChainState::detect_squash_divergence`].
///
/// Type alias of the generic `marf::SquashDivergence<StacksBlockId>` defined alongside the per-MARF
/// detector — the chainstate fixes `T = StacksBlockId`.
pub type SquashDivergence = crate::chainstate::stacks::index::marf::SquashDivergence<StacksBlockId>;

/// Per-MARF squash cadence policy. Drives [`StacksChainState::maybe_squash`]'s
/// per-MARF predicate; each MARF (headers, Clarity) has its own
/// `SquashCadenceConfig`, so the two trigger independently.
///
/// The trigger is gated by three knobs working together:
///
/// - `min_blocks` — floor: never squash sooner than this many blocks past
///   the previous squash, regardless of work_target. Bounds per-level
///   overhead under sustained write storms.
/// - `max_blocks` — ceiling: always squash by this many blocks past the
///   previous squash, regardless of work_target. Backstop for quiet
///   periods. Also caps the divergence-detection precompute walk
///   distance (see `precompute_canonical_ancestors`).
/// - `work_target_bytes` — cumulative
///   `MarfSquashStats::external_bytes_since_last_squash` at which a
///   squash should fire, subject to the block-count guards above.
///
/// `fixed_cadence(blocks)` collapses these into the historical fixed-cadence
/// behavior (`min_blocks == max_blocks == blocks`, `work_target_bytes ==
/// u64::MAX`); chainstate uses it as the default for the headers MARF, which
/// stays block-aligned for operator predictability. The Clarity MARF default
/// ([`Self::default_clarity`]) is work-aware so it can smooth pause amplitude
/// against bursty workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SquashCadenceConfig {
    pub work_target_bytes: u64,
    pub min_blocks: u32,
    pub max_blocks: u32,
}

impl SquashCadenceConfig {
    /// Mirrors today's fixed-cadence behavior: trigger fires at exactly
    /// `blocks` blocks past the previous squash, ignoring work bytes.
    pub const fn fixed_cadence(blocks: u32) -> Self {
        Self {
            work_target_bytes: u64::MAX,
            min_blocks: blocks,
            max_blocks: blocks,
        }
    }

    /// Default cadence for the **headers MARF**. Headers squash is
    /// sub-second on all observed mainnet workloads, so smoothing isn't
    /// worth the variance loss — fixed cadence at the legacy
    /// `MARF_SQUASH_CADENCE_BLOCKS` boundary preserves the operator-
    /// meaningful "block-aligned" behavior.
    pub const fn default_headers() -> Self {
        Self::fixed_cadence(MARF_SQUASH_CADENCE_BLOCKS as u32)
    }

    /// Default cadence for the **Clarity MARF**. Work-aware: Clarity is
    /// the heavy MARF (~4–7 s sidecar I/O alone on mainnet's level 14),
    /// and its workload is bursty enough that fixed cadence amplifies
    /// pause variance into operator-visible spikes. The values here are
    /// the design's first-cut estimates from `.docs/adaptive-squash-cadence.md`
    /// §2.4 — a calibration pass on a real fresh sync (Step 7) should
    /// tune them against measured wall-clock per deployment.
    ///
    /// Knobs:
    ///   - `work_target_bytes`: 64 MiB. The cumulative
    ///     `MarfSquashStats::external_bytes_since_last_squash` at which
    ///     a squash is "due"; correlates roughly with merged-blob bytes
    ///     and orphan-section size.
    ///   - `min_blocks`: 100. Floor: bounds per-level overhead under
    ///     sustained write storms (single-block contract-deployment
    ///     bursts can otherwise trigger tiny squashes).
    ///   - `max_blocks`: 2000. Ceiling: quiet-period backstop. Also
    ///     bounds the divergence-detection precompute walk distance and
    ///     keeps the open suffix from growing unboundedly during quiet
    ///     stretches.
    pub const fn default_clarity() -> Self {
        Self {
            work_target_bytes: 64 * 1024 * 1024,
            min_blocks: 100,
            max_blocks: 2000,
        }
    }
}

/// Compute the **horizon-gated `max_height`** for a Phase B promotion: the largest Stacks-height H
/// such that the canonical block at H has `burn_header_height <= burn_tip_height -
/// horizon_burn_blocks`. Returns `None` if no canonical block on `canonical_tip`'s lineage
/// satisfies the constraint (e.g., the chain is shorter than the horizon, or the burn-tip lookup
/// fails).
///
/// This is the load-bearing computation for B5c's `maybe_squash` dispatch: with a horizon of 6 burn
/// blocks, the result is roughly "the canonical Stacks tip 6 burn blocks ago." Promotion publishes
/// the range `[min_height ..= max_height]` and treats blocks past `max_height` as in the hot-tail
/// (rewritten by the descendant scan).
///
/// **Walk strategy**: from `canonical_tip`, follow `parent_block_id` pointers until we find a
/// header whose `burn_header_height` is at or below the target. The walk is bounded by
/// `horizon_burn_blocks`-worth of Stacks blocks (typically ≤ ~50 for a 6-burn-block horizon), so
/// it's fast.
///
/// **Why not a single SQL query?** A `MAX(stacks_block_height) WHERE burn_header_height <= ?` query
/// against `nakamoto_block_headers` would return the highest height on **any** chain — including
/// non-canonical forks at the same Stacks-height. The canonical-chain constraint requires walking
/// parent pointers from a known canonical anchor.
pub fn compute_horizon_gated_max_height(
    chainstate_db: &Connection,
    sortdb_conn: &Connection,
    canonical_tip: &StacksBlockId,
    horizon_burn_blocks: u32,
) -> Result<Option<u32>, Error> {
    let burn_tip_height = match SortitionDB::get_canonical_burn_chain_tip(sortdb_conn) {
        Ok(s) => s.block_height as u32,
        Err(_) => return Ok(None),
    };
    compute_horizon_gated_max_height_with_burn_tip(
        chainstate_db,
        burn_tip_height,
        canonical_tip,
        horizon_burn_blocks,
    )
}

/// Pure-function variant of [`compute_horizon_gated_max_height`] that takes `burn_tip_height`
/// directly instead of querying the sortition DB. Used by unit tests so they don't need to spin up
/// a `SortitionDB`, and by [`compute_horizon_gated_max_height`] as the actual walk implementation.
pub fn compute_horizon_gated_max_height_with_burn_tip(
    chainstate_db: &Connection,
    burn_tip_height: u32,
    canonical_tip: &StacksBlockId,
    horizon_burn_blocks: u32,
) -> Result<Option<u32>, Error> {
    // **Safety**: the v1.5 predicate is
    // `burn_tip - burn_at(max_height) >= horizon`. When
    // `burn_tip < horizon`, no non-negative burn height satisfies it
    // — the correct answer is "no eligible range yet," not
    // "anything at burn_height 0 is eligible." A saturating-sub
    // would silently approve too-young blocks on short chains / right
    // after startup, exactly the reorg-safety case horizon gating
    // exists to prevent. See `.docs/squashing-v1.5.md` §6.1.
    if burn_tip_height < horizon_burn_blocks {
        return Ok(None);
    }
    let target_burn_height = burn_tip_height - horizon_burn_blocks;

    // Bounded walk: each iteration reads one header row + walks one parent edge. The chain depth
    // past horizon is small in practice. The hard cap protects against a malformed chain where the
    // walk would otherwise be unbounded.
    //
    // We query just the three fields we need (`block_height`, `burn_header_height`,
    // `parent_block_id`) rather than going through
    // `get_stacks_block_header_info_by_index_block_hash` / `get_parent_block_id` separately. The
    // slimmed query avoids decoding the full `StacksHeaderInfo` (which fully parses the
    // Epoch2/Nakamoto block-header fields) — both wasteful here and a hard test-fixture problem:
    // synthetic test rows with zero-default header fields fail the full decode even when they're
    // well-formed for our walk's purpose.
    const MAX_WALK_STEPS: u32 = 10_000;
    let mut current = canonical_tip.clone();
    for _ in 0..MAX_WALK_STEPS {
        let row: Option<(i64, i64, StacksBlockId)> = chainstate_db
            .query_row(
                "SELECT block_height, burn_header_height, parent_block_id \
                 FROM block_headers WHERE index_block_hash = ?1",
                rusqlite::params![&current],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, StacksBlockId>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| Error::DBError(crate::util_lib::db::Error::SqliteError(e)))?;
        let (block_height, burn_header_height, parent) = match row {
            Some(t) => t,
            None => return Ok(None), // walked off the chain
        };
        if (burn_header_height as u32) <= target_burn_height {
            return Ok(Some(block_height as u32));
        }
        // Genesis sentinel parent is `[0u8; 32]` — that won't match any block_headers row, so the
        // next iteration's query returns None and we exit.
        current = parent;
    }
    // Walked the cap without finding a match — chain is malformed or horizon is unreasonably large.
    // Treat as "no match" rather than panicking; the cadence policy will simply defer.
    warn!(
        "compute_horizon_gated_max_height: walked {} steps from {canonical_tip} without finding \
         a block at or below burn_height {target_burn_height}; defer",
        MAX_WALK_STEPS,
    );
    Ok(None)
}

/// Per-epoch variant of [`compute_horizon_gated_max_height`]. Walks back from `canonical_tip`
/// looking for the highest in-range Stacks height `h` that satisfies the **per-epoch** horizon
/// predicate:
///
/// ```text
/// burn_at(h) + max(epoch_horizon(e, configured)
///                  for e in epochs overlapping [burn_at(min_height) .. burn_at(h)])
///   <= burn_tip
/// ```
///
/// `min_height` is the prospective squash level's lower bound — typically the previous level's
/// `max_height + 1`, or `0` for the first squash. Together with the candidate `h` (max_height),
/// it determines the burn-range whose epoch span we evaluate.
///
/// The composition rule is **max-over-overlapped-epochs**: a level fully inside one epoch gets
/// that epoch's horizon; a level spanning multiple epochs gets the max of their horizons. See
/// [`StacksChainState::max_horizon_over_burn_range`] and
/// [`StacksChainState::epoch_horizon_floor`] for the schedule and rationale.
///
/// Conservative-default behavior on lookup failures (epoch list, sortdb tip, or
/// `burn_height_for_stacks_height(min_height)` returns `None`): the function returns `Ok(None)`,
/// which the cadence policy interprets as "no eligible range yet — defer." Same posture as
/// [`compute_horizon_gated_max_height`]'s short-chain handling.
pub fn compute_per_epoch_horizon_gated_max_height(
    chainstate_db: &Connection,
    sortdb_conn: &Connection,
    canonical_tip: &StacksBlockId,
    min_height: u32,
    configured_horizon: u32,
) -> Result<Option<u32>, Error> {
    let burn_tip_height = match SortitionDB::get_canonical_burn_chain_tip(sortdb_conn) {
        Ok(s) => s.block_height as u32,
        Err(_) => return Ok(None),
    };

    // Lower bound of the prospective level's burn range. If `min_height` isn't yet in
    // `block_headers` (e.g. very early sync, genesis row not yet inserted), defer.
    let burn_at_min =
        match StacksChainState::burn_height_for_stacks_height(chainstate_db, min_height) {
            Some(h) => h as u32,
            None => return Ok(None),
        };

    // Pre-fetch all epochs once; the walk below queries against this list per candidate.
    let epochs = match SortitionDB::get_stacks_epochs(sortdb_conn) {
        Ok(list) => list,
        Err(_) => return Ok(None),
    };

    const MAX_WALK_STEPS: u32 = 10_000;
    let mut current = canonical_tip.clone();
    for _ in 0..MAX_WALK_STEPS {
        let row: Option<(i64, i64, StacksBlockId)> = chainstate_db
            .query_row(
                "SELECT block_height, burn_header_height, parent_block_id \
                 FROM block_headers WHERE index_block_hash = ?1",
                rusqlite::params![&current],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, StacksBlockId>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| Error::DBError(crate::util_lib::db::Error::SqliteError(e)))?;
        let (block_height, burn_header_height, parent) = match row {
            Some(t) => t,
            None => return Ok(None),
        };
        let block_height = block_height as u32;
        let burn_header_height = burn_header_height as u32;

        // Walked below the prospective level's lower bound — no eligible candidate.
        if block_height < min_height {
            return Ok(None);
        }

        let span_horizon = StacksChainState::max_horizon_over_burn_range(
            &epochs,
            burn_at_min,
            burn_header_height,
            configured_horizon,
        );

        if burn_header_height.saturating_add(span_horizon) <= burn_tip_height {
            return Ok(Some(block_height));
        }

        if parent.as_bytes() == &[0u8; 32] {
            return Ok(None);
        }
        current = parent;
    }
    warn!(
        "compute_per_epoch_horizon_gated_max_height: walked {} steps from {canonical_tip} \
         without finding an eligible height; defer",
        MAX_WALK_STEPS,
    );
    Ok(None)
}

/// Decide whether a squash should fire for a single MARF. Pure function of the per-MARF stats
/// snapshot, the height-span since the last published squash level, the cadence config, and a
/// horizon predicate.
///
/// `blocks_since_last_squash` is height-span (`canonical_tip_height - latest_level.max_height`),
/// not commit count — see `.docs/adaptive-squash-cadence.md` §2.4 for why height-span is the
/// operator-meaningful unit.
///
/// `horizon_check` is the v1.5 Phase B burn-height-based horizon predicate: returns `true` iff the
/// prospective squash range is past the burnchain reorg horizon (so promotion is safe). Legacy
/// (non-hot-tier) MARFs pass an always-true closure; hot-tier MARFs pass a closure that compares
/// `burn_tip - burn_at(prospective_max_height)` against the configured horizon. See
/// `.docs/squashing-v1.5-phase-b.md` §3 for the rationale.
///
/// Order: `min_blocks` short-circuit → horizon check → `max_blocks` forced trigger → work target.
/// Putting the horizon check between `min_blocks` and `max_blocks` means we don't pay for it when
/// cadence wouldn't fire anyway, but a forced (work-bytes) trigger can't bypass the horizon —
/// exactly the safety property the doc specifies.
pub fn should_squash(
    stats: &crate::chainstate::stacks::index::marf::MarfSquashStats,
    blocks_since_last_squash: u32,
    cfg: &SquashCadenceConfig,
    horizon_check: impl FnOnce() -> bool,
) -> bool {
    if blocks_since_last_squash < cfg.min_blocks {
        return false;
    }
    if !horizon_check() {
        return false;
    }
    if blocks_since_last_squash >= cfg.max_blocks {
        return true;
    }
    stats.external_bytes_since_last_squash >= cfg.work_target_bytes
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksHeaderInfo {
    /// Stacks block header
    pub anchored_header: StacksBlockHeaderTypes,
    /// Last microblock header (Stacks 2.x only; this is None in Stacks 3.x)
    pub microblock_tail: Option<StacksMicroblockHeader>,
    /// Height of this Stacks block
    pub stacks_block_height: u64,
    /// MARF root hash of the headers DB (not consensus critical)
    pub index_root: TrieHash,
    /// consensus hash of the burnchain block in which this miner was selected to produce this block
    pub consensus_hash: ConsensusHash,
    /// Hash of the burnchain block in which this miner was selected to produce this block
    pub burn_header_hash: BurnchainHeaderHash,
    /// Height of the burnchain block
    pub burn_header_height: u32,
    /// Timestamp of the burnchain block
    pub burn_header_timestamp: u64,
    /// Size of the block corresponding to `anchored_header` in bytes
    pub anchored_block_size: u64,
    /// The burnchain tip that is passed to Clarity while processing this block.
    /// This should always be `Some()` for Nakamoto blocks and `None` for 2.x blocks
    pub burn_view: Option<ConsensusHash>,
    /// Total tenure size (reset at every tenure extend) in bytes
    /// Not consensus-critical (may differ between nodes)
    pub total_tenure_size: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MinerRewardInfo {
    pub from_block_consensus_hash: ConsensusHash,
    pub from_stacks_block_hash: BlockHeaderHash,
    pub from_parent_block_consensus_hash: ConsensusHash,
    pub from_parent_stacks_block_hash: BlockHeaderHash,
}

/// This is the block receipt for a Stacks block
#[derive(Debug, Clone, PartialEq)]
pub struct StacksEpochReceipt {
    pub header: StacksHeaderInfo,
    pub tx_receipts: Vec<StacksTransactionReceipt>,
    pub matured_rewards: Vec<MinerReward>,
    pub matured_rewards_info: Option<MinerRewardInfo>,
    pub parent_microblocks_cost: ExecutionCost,
    pub anchored_block_cost: ExecutionCost,
    pub parent_burn_block_hash: BurnchainHeaderHash,
    pub parent_burn_block_height: u32,
    pub parent_burn_block_timestamp: u64,
    /// This is the Stacks epoch that the block was evaluated in, which is the Stacks epoch that
    /// this block's parent was elected in.
    pub evaluated_epoch: StacksEpochId,
    pub epoch_transition: bool,
    /// Was .signers updated during this block?
    pub signers_updated: bool,
    pub coinbase_height: u64,
}

/// Headers we serve over the network
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtendedStacksHeader {
    pub consensus_hash: ConsensusHash,
    #[serde(
        serialize_with = "ExtendedStacksHeader_StacksBlockHeader_serialize",
        deserialize_with = "ExtendedStacksHeader_StacksBlockHeader_deserialize"
    )]
    pub header: StacksBlockHeader,
    pub parent_block_id: StacksBlockId,
}

/// In ExtendedStacksHeader, encode the StacksBlockHeader as a hex string
fn ExtendedStacksHeader_StacksBlockHeader_serialize<S: serde::Serializer>(
    header: &StacksBlockHeader,
    s: S,
) -> Result<S::Ok, S::Error> {
    let bytes = header.serialize_to_vec();
    let header_hex = to_hex(&bytes);
    s.serialize_str(header_hex.as_str())
}

/// In ExtendedStacksHeader, encode the StacksBlockHeader as a hex string
fn ExtendedStacksHeader_StacksBlockHeader_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<StacksBlockHeader, D::Error> {
    let header_hex = String::deserialize(d)?;
    let header_bytes = hex_bytes(&header_hex).map_err(de_Error::custom)?;
    StacksBlockHeader::consensus_deserialize(&mut &header_bytes[..]).map_err(de_Error::custom)
}

impl StacksMessageCodec for ExtendedStacksHeader {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.consensus_hash)?;
        write_next(fd, &self.header)?;
        write_next(fd, &self.parent_block_id)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<ExtendedStacksHeader, codec_error> {
        let ch = read_next(fd)?;
        let bh = read_next(fd)?;
        let pbid = read_next(fd)?;
        Ok(ExtendedStacksHeader {
            consensus_hash: ch,
            header: bh,
            parent_block_id: pbid,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DBConfig {
    pub version: String,
    pub mainnet: bool,
    pub chain_id: u32,
}

impl DBConfig {
    pub fn supports_epoch(&self, epoch_id: StacksEpochId) -> bool {
        let version_u32: u32 = self.version.parse().unwrap_or_else(|e| {
            error!("Failed to parse Stacks chainstate version as u32: {e}");
            0
        });
        match epoch_id {
            StacksEpochId::Epoch10 => true,
            StacksEpochId::Epoch20 => (1..=CHAINSTATE_VERSION_NUMBER).contains(&version_u32),
            StacksEpochId::Epoch2_05 => (2..=CHAINSTATE_VERSION_NUMBER).contains(&version_u32),
            StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32
            | StacksEpochId::Epoch33
            | StacksEpochId::Epoch34 => (3..=CHAINSTATE_VERSION_NUMBER).contains(&version_u32),
        }
    }
}

impl StacksBlockHeaderTypes {
    pub fn block_hash(&self) -> BlockHeaderHash {
        match &self {
            StacksBlockHeaderTypes::Epoch2(x) => x.block_hash(),
            StacksBlockHeaderTypes::Nakamoto(x) => x.block_hash(),
        }
    }

    pub fn is_first_mined(&self) -> bool {
        match self {
            StacksBlockHeaderTypes::Epoch2(x) => x.is_first_mined(),
            StacksBlockHeaderTypes::Nakamoto(x) => x.is_first_mined(),
        }
    }

    pub fn height(&self) -> u64 {
        match self {
            StacksBlockHeaderTypes::Epoch2(x) => x.total_work.work,
            StacksBlockHeaderTypes::Nakamoto(x) => x.chain_length,
        }
    }

    /// Get the total spend by miners for this block
    pub fn total_burns(&self) -> u64 {
        match self {
            StacksBlockHeaderTypes::Epoch2(x) => x.total_work.burn,
            StacksBlockHeaderTypes::Nakamoto(x) => x.burn_spent,
        }
    }

    pub fn as_stacks_epoch2(&self) -> Option<&StacksBlockHeader> {
        match &self {
            StacksBlockHeaderTypes::Epoch2(ref x) => Some(x),
            _ => None,
        }
    }

    pub fn as_stacks_nakamoto(&self) -> Option<&NakamotoBlockHeader> {
        match &self {
            StacksBlockHeaderTypes::Nakamoto(ref x) => Some(x),
            _ => None,
        }
    }
}

impl StacksHeaderInfo {
    pub fn index_block_hash(&self) -> StacksBlockId {
        let block_hash = self.anchored_header.block_hash();
        StacksBlockId::new(&self.consensus_hash, &block_hash)
    }

    pub fn regtest_genesis() -> StacksHeaderInfo {
        let burnchain_params = BurnchainParameters::bitcoin_regtest();
        StacksHeaderInfo {
            anchored_header: StacksBlockHeader::genesis_block_header().into(),
            microblock_tail: None,
            stacks_block_height: 0,
            index_root: TrieHash([0u8; 32]),
            burn_header_hash: burnchain_params.first_block_hash.clone(),
            burn_header_height: burnchain_params.first_block_height as u32,
            consensus_hash: ConsensusHash::empty(),
            burn_header_timestamp: 0,
            anchored_block_size: 0,
            burn_view: None,
            total_tenure_size: 0,
        }
    }

    pub fn genesis(
        root_hash: TrieHash,
        first_burnchain_block_hash: &BurnchainHeaderHash,
        first_burnchain_block_height: u32,
        first_burnchain_block_timestamp: u64,
    ) -> StacksHeaderInfo {
        StacksHeaderInfo {
            anchored_header: StacksBlockHeader::genesis_block_header().into(),
            microblock_tail: None,
            stacks_block_height: 0,
            index_root: root_hash,
            burn_header_hash: first_burnchain_block_hash.clone(),
            burn_header_height: first_burnchain_block_height,
            consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            burn_header_timestamp: first_burnchain_block_timestamp,
            anchored_block_size: 0,
            burn_view: None,
            total_tenure_size: 0,
        }
    }

    pub fn is_first_mined(&self) -> bool {
        self.anchored_header.is_first_mined()
    }

    pub fn is_epoch_2_block(&self) -> bool {
        matches!(self.anchored_header, StacksBlockHeaderTypes::Epoch2(_))
    }

    pub fn is_nakamoto_block(&self) -> bool {
        matches!(self.anchored_header, StacksBlockHeaderTypes::Nakamoto(_))
    }

    pub fn header_type_name(&self) -> &str {
        match self.anchored_header {
            StacksBlockHeaderTypes::Epoch2(_) => "epoch2",
            StacksBlockHeaderTypes::Nakamoto(_) => "nakamoto",
        }
    }
}

impl FromRow<DBConfig> for DBConfig {
    fn from_row(row: &Row) -> Result<DBConfig, db_error> {
        let version: String = row.get_unwrap("version");
        let mainnet_i64: i64 = row.get_unwrap("mainnet");
        let chain_id_i64: i64 = row.get_unwrap("chain_id");

        let mainnet = mainnet_i64 != 0;
        let chain_id = chain_id_i64 as u32;

        Ok(DBConfig {
            version,
            mainnet,
            chain_id,
        })
    }
}

impl FromRow<StacksHeaderInfo> for StacksHeaderInfo {
    fn from_row(row: &Row) -> Result<StacksHeaderInfo, db_error> {
        let block_height: u64 = u64::from_column(row, "block_height")?;
        let index_root = TrieHash::from_column(row, "index_root")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let burn_header_height: u64 = u64::from_column(row, "burn_header_height")?;
        let burn_header_timestamp = u64::from_column(row, "burn_header_timestamp")?;
        let anchored_block_size_str: String = row.get_unwrap("block_size");
        let anchored_block_size = anchored_block_size_str
            .parse::<u64>()
            .map_err(|_| db_error::ParseError)?;

        let header_type: HeaderTypeNames =
            row.get("header_type").unwrap_or(HeaderTypeNames::Epoch2);
        let stacks_header: StacksBlockHeaderTypes = {
            match header_type {
                HeaderTypeNames::Epoch2 => StacksBlockHeader::from_row(row)?.into(),
                HeaderTypeNames::Nakamoto => NakamotoBlockHeader::from_row(row)?.into(),
            }
        };
        let burn_view = {
            match header_type {
                HeaderTypeNames::Epoch2 => None,
                HeaderTypeNames::Nakamoto => Some(ConsensusHash::from_column(row, "burn_view")?),
            }
        };

        if block_height != stacks_header.height() {
            return Err(db_error::ParseError);
        }

        let total_tenure_size = {
            match header_type {
                HeaderTypeNames::Epoch2 => 0,
                HeaderTypeNames::Nakamoto => u64::from_column(row, "total_tenure_size")?,
            }
        };

        Ok(StacksHeaderInfo {
            anchored_header: stacks_header,
            microblock_tail: None,
            stacks_block_height: block_height,
            index_root,
            consensus_hash,
            burn_header_hash,
            burn_header_height: burn_header_height as u32,
            burn_header_timestamp,
            anchored_block_size,
            burn_view,
            total_tenure_size,
        })
    }
}

pub type StacksDBTx<'a> = IndexDBTx<'a, (), StacksBlockId>;
pub type StacksDBConn<'a> = IndexDBConn<'a, (), StacksBlockId>;

pub struct ClarityTx<'a, 'b> {
    block: ClarityBlockConnection<'a, 'b>,
    pub config: DBConfig,
}

impl ClarityConnection for ClarityTx<'_, '_> {
    fn with_clarity_db_readonly_owned<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(ClarityDatabase) -> (R, ClarityDatabase),
    {
        ClarityConnection::with_clarity_db_readonly_owned(&mut self.block, to_do)
    }

    fn with_analysis_db_readonly<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut AnalysisDatabase) -> R,
    {
        self.block.with_analysis_db_readonly(to_do)
    }

    fn get_epoch(&self) -> StacksEpochId {
        self.block.get_epoch()
    }
}

impl<'a, 'b> ClarityTx<'a, 'b> {
    pub fn cost_so_far(&self) -> ExecutionCost {
        self.block.cost_so_far()
    }

    pub fn get_epoch(&self) -> StacksEpochId {
        self.block.get_epoch()
    }

    /// Set the ClarityTx's cost tracker.
    /// Returns the replaced cost tracker.
    fn set_cost_tracker(&mut self, new_tracker: LimitedCostTracker) -> LimitedCostTracker {
        self.block.set_cost_tracker(new_tracker)
    }

    /// Returns the block limit for the block being created.
    pub fn block_limit(&self) -> Option<ExecutionCost> {
        self.block.block_limit()
    }

    /// Run `todo` in this ClarityTx with `new_tracker`.
    /// Returns the result of `todo` and the `new_tracker`
    pub fn with_temporary_cost_tracker<F, R>(
        &mut self,
        new_tracker: LimitedCostTracker,
        todo: F,
    ) -> (R, LimitedCostTracker)
    where
        F: FnOnce(&mut ClarityTx) -> R,
    {
        let original_tracker = self.set_cost_tracker(new_tracker);
        let result = todo(self);
        let new_tracker = self.set_cost_tracker(original_tracker);
        (result, new_tracker)
    }

    pub fn seal(&mut self) -> TrieHash {
        self.block.seal()
    }

    #[cfg(test)]
    pub fn commit_block(self) {
        self.block.commit_block();
    }

    pub fn commit_mined_block(
        self,
        block_hash: &StacksBlockId,
    ) -> Result<ExecutionCost, ClarityError> {
        Ok(self.block.commit_mined_block(block_hash)?.get_total())
    }

    pub fn commit_to_block(self, consensus_hash: &ConsensusHash, block_hash: &BlockHeaderHash) {
        let index_block_hash = StacksBlockHeader::make_index_block_hash(consensus_hash, block_hash);
        self.block.commit_to_block(&index_block_hash);
    }

    pub fn precommit_to_block(
        self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> PreCommitClarityBlock<'a> {
        let index_block_hash = StacksBlockId::new(consensus_hash, block_hash);
        self.block.precommit_to_block(index_block_hash)
    }

    pub fn commit_unconfirmed(self) {
        self.block.commit_unconfirmed();
    }

    pub fn rollback_block(self) {
        self.block.rollback_block()
    }

    pub fn rollback_unconfirmed(self) {
        self.block.rollback_unconfirmed()
    }

    pub fn reset_cost(&mut self, cost: ExecutionCost) {
        self.block.reset_block_cost(cost);
    }

    pub fn connection(&mut self) -> &mut ClarityBlockConnection<'a, 'b> {
        &mut self.block
    }

    pub fn increment_ustx_liquid_supply(&mut self, incr_by: u128) {
        self.connection()
            .as_transaction(|tx| {
                tx.with_clarity_db(|db| {
                    db.increment_ustx_liquid_supply(incr_by)
                        .map_err(|e| e.into())
                })
            })
            .expect("FATAL: `ust-liquid-supply` overflowed");
    }
}

pub struct ChainstateTx<'a> {
    pub config: DBConfig,
    pub blocks_path: String,
    pub tx: StacksDBTx<'a>,
    pub root_path: String,
}

impl<'a> ChainstateTx<'a> {
    pub fn new(
        tx: StacksDBTx<'a>,
        blocks_path: String,
        root_path: String,
        config: DBConfig,
    ) -> ChainstateTx<'a> {
        ChainstateTx {
            config,
            blocks_path,
            tx,
            root_path,
        }
    }

    pub fn get_blocks_path(&self) -> &String {
        &self.blocks_path
    }

    pub fn commit(self) -> Result<(), db_error> {
        self.tx.commit()
    }

    pub fn get_config(&self) -> &DBConfig {
        &self.config
    }

    pub fn log_transactions_processed(&self, events: &[StacksTransactionReceipt]) {
        for tx_event in events.iter() {
            let txid = tx_event.transaction.txid();
            if let Err(e) = monitoring::log_transaction_processed(&txid, &self.root_path) {
                warn!("Failed to monitor TX processed: {:?}", e; "txid" => %txid);
            }
        }
    }
}

impl<'a> Deref for ChainstateTx<'a> {
    type Target = StacksDBTx<'a>;
    fn deref(&self) -> &StacksDBTx<'a> {
        &self.tx
    }
}

impl<'a> DerefMut for ChainstateTx<'a> {
    fn deref_mut(&mut self) -> &mut StacksDBTx<'a> {
        &mut self.tx
    }
}

pub const CHAINSTATE_VERSION: &str = "13";
pub const CHAINSTATE_VERSION_NUMBER: u32 = 13;

const CHAINSTATE_INITIAL_SCHEMA: &[&str] = &[
    "PRAGMA foreign_keys = ON;",
    r#"
    -- Anchored stacks block headers
    CREATE TABLE block_headers(
        version INTEGER NOT NULL,
        total_burn TEXT NOT NULL,       -- converted to/from u64
        total_work TEXT NOT NULL,       -- converted to/from u64
        proof TEXT NOT NULL,
        parent_block TEXT NOT NULL,             -- hash of parent Stacks block
        parent_microblock TEXT NOT NULL,
        parent_microblock_sequence INTEGER NOT NULL,
        tx_merkle_root TEXT NOT NULL,
        state_index_root TEXT NOT NULL,
        microblock_pubkey_hash TEXT NOT NULL,

        block_hash TEXT NOT NULL,                   -- NOTE: this is *not* unique, since two burn chain forks can commit to the same Stacks block.
        index_block_hash TEXT UNIQUE NOT NULL,      -- NOTE: this is the hash of the block hash and consensus hash of the burn block that selected it,
                                                    -- and is guaranteed to be globally unique (across all Stacks forks and across all PoX forks).
                                                    -- index_block_hash is the block hash fed into the MARF index.

        -- internal use only
        block_height INTEGER NOT NULL,
        index_root TEXT NOT NULL,                    -- root hash of the internal, not-consensus-critical MARF that allows us to track chainstate /fork metadata
        consensus_hash TEXT UNIQUE NOT NULL,         -- all consensus hashes are guaranteed to be unique
        burn_header_hash TEXT NOT NULL,              -- burn header hash corresponding to the consensus hash (NOT guaranteed to be unique, since we can have 2+ blocks per burn block if there's a PoX fork)
        burn_header_height INT NOT NULL,             -- height of the burnchain block header that generated this consensus hash
        burn_header_timestamp INT NOT NULL,          -- timestamp from burnchain block header that generated this consensus hash
        parent_block_id TEXT NOT NULL,               -- NOTE: this is the parent index_block_hash

        cost TEXT NOT NULL,
        block_size TEXT NOT NULL,       -- converted to/from u64
        affirmation_weight INTEGER NOT NULL,

        PRIMARY KEY(consensus_hash,block_hash)
    );"#,
    r#"
    -- scheduled payments
    -- no designated primary key since there can be duplicate entries
    CREATE TABLE payments(
        address TEXT NOT NULL,              -- miner that produced this block and microblock stream
        block_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,
        parent_block_hash TEXT NOT NULL,
        parent_consensus_hash TEXT NOT NULL,
        coinbase TEXT NOT NULL,             -- encodes u128
        tx_fees_anchored TEXT NOT NULL,     -- encodes u128
        tx_fees_streamed TEXT NOT NULL,     -- encodes u128
        stx_burns TEXT NOT NULL,            -- encodes u128
        burnchain_commit_burn INT NOT NULL,
        burnchain_sortition_burn INT NOT NULL,
        miner INT NOT NULL,

        -- internal use
        stacks_block_height INTEGER NOT NULL,
        index_block_hash TEXT NOT NULL,     -- NOTE: can't enforce UNIQUE here, because there will be multiple entries per block
        vtxindex INT NOT NULL               -- user burn support vtxindex
    );"#,
    r#"
    -- users who supported miners
    CREATE TABLE user_supporters(
        address TEXT NOT NULL,
        support_burn INT NOT NULL,
        block_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,

        PRIMARY KEY(address,block_hash,consensus_hash)
    );"#,
    r#"
    CREATE TABLE db_config(
        version TEXT NOT NULL,
        mainnet INTEGER NOT NULL,
        chain_id INTEGER NOT NULL
    );"#,
    r#"
    -- Staging microblocks -- preprocessed microblocks queued up for subsequent processing and inclusion in the chunk store.
    CREATE TABLE staging_microblocks(anchored_block_hash TEXT NOT NULL,     -- this is the hash of the parent anchored block
                                     consensus_hash TEXT NOT NULL,          -- this is the hash of the burn chain block that holds the parent anchored block's block-commit
                                     index_block_hash TEXT NOT NULL,        -- this is the anchored block's index hash
                                     microblock_hash TEXT NOT NULL,
                                     parent_hash TEXT NOT NULL,             -- previous microblock
                                     index_microblock_hash TEXT NOT NULL,   -- this is the hash of consensus_hash and microblock_hash
                                     sequence INT NOT NULL,
                                     processed INT NOT NULL,
                                     orphaned INT NOT NULL,
                                     PRIMARY KEY(anchored_block_hash,consensus_hash,microblock_hash)
    );"#,
    r#"
    -- Staging microblocks data
    CREATE TABLE staging_microblocks_data(block_hash TEXT NOT NULL,
                                          block_data BLOB NOT NULL,
                                          PRIMARY KEY(block_hash)
    );"#,
    r#"
    -- Invalidated staging microblocks data
    CREATE TABLE invalidated_microblocks_data(block_hash TEXT NOT NULL,
                                              block_data BLOB NOT NULL,
                                              PRIMARY KEY(block_hash)
    );"#,
    r#"
    -- Staging blocks -- preprocessed blocks queued up for subsequent processing and inclusion in the chunk store.
    CREATE TABLE staging_blocks(anchored_block_hash TEXT NOT NULL,
                                parent_anchored_block_hash TEXT NOT NULL,
                                consensus_hash TEXT NOT NULL,
                                -- parent_consensus_hash is the consensus hash of the sortition that chose the parent Stacks block.
                                parent_consensus_hash TEXT NOT NULL,
                                parent_microblock_hash TEXT NOT NULL,
                                parent_microblock_seq INT NOT NULL,
                                microblock_pubkey_hash TEXT NOT NULL,
                                height INT NOT NULL,
                                attachable INT NOT NULL,            -- set to 1 if this block's parent is processed; 0 if not
                                orphaned INT NOT NULL,              -- set to 1 if this block can never be attached
                                processed INT NOT NULL,
                                commit_burn INT NOT NULL,
                                sortition_burn INT NOT NULL,
                                index_block_hash TEXT NOT NULL,           -- used internally; hash of consensus hash and anchored_block_hash
                                download_time INT NOT NULL,               -- how long the block was in-flight
                                arrival_time INT NOT NULL,                -- when this block was stored
                                processed_time INT NOT NULL,              -- when this block was processed
                                PRIMARY KEY(anchored_block_hash,consensus_hash)
    );"#,
    r#"
    CREATE TABLE transactions(
        id INTEGER PRIMARY KEY,
        txid TEXT NOT NULL,
        index_block_hash TEXT NOT NULL,
        tx_hex TEXT NOT NULL,
        result TEXT NOT NULL,
        UNIQUE (txid,index_block_hash)
    );"#,
];

const CHAINSTATE_SCHEMA_2: &[&str] = &[
    // new in epoch 2.05 (schema version 2)
    // table of blocks that applied an epoch transition
    r#"
    CREATE TABLE epoch_transitions(
        block_id TEXT PRIMARY KEY
    );"#,
    r#"
    UPDATE db_config SET version = "2";
    "#,
];

const CHAINSTATE_SCHEMA_3: &[&str] = &[
    // new in epoch 2.1 (schema version 3)
    // track mature miner rewards paid out, so we can report them in Clarity.
    r#"
    -- table for MinerRewards.
    -- For each block within in a fork, there will be exactly two miner records:
    -- * one that records the coinbase, anchored tx fee, and confirmed streamed tx fees, and
    -- * one that records only the produced streamed tx fees.
    -- The latter is determined once this block's stream gets subsequently confirmed.
    -- You query this table by passing both the parent and the child block hashes, since both the
    -- parent and child blocks determine the full reward for the parent block.
    CREATE TABLE matured_rewards(
        address TEXT NOT NULL,      -- address of the miner who produced the block
        recipient TEXT,             -- who received the reward (if different from the miner)
        vtxindex INTEGER NOT NULL,  -- will be 0 if this is the miner, >0 if this is a user burn support
        coinbase TEXT NOT NULL,
        tx_fees_anchored TEXT NOT NULL,
        tx_fees_streamed_confirmed TEXT NOT NULL,
        tx_fees_streamed_produced TEXT NOT NULL,

        -- fork identifier
        child_index_block_hash TEXT NOT NULL,
        parent_index_block_hash TEXT NOT NULL,

        -- there are two rewards records per (parent,child) pair. One will have a non-zero coinbase; the other will have a 0 coinbase.
        PRIMARY KEY(parent_index_block_hash,child_index_block_hash,coinbase)
    );"#,
    r#"
    -- Add a `recipient` column so that in Stacks 2.1, the block reward can be sent to someone besides the miner (e.g. a contract).
    -- If NULL, then the payment goes to the `address`.
    ALTER TABLE payments ADD COLUMN recipient TEXT;
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS index_matured_rewards_by_vtxindex ON matured_rewards(parent_index_block_hash,child_index_block_hash,vtxindex);
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS index_parent_block_id_by_block_id ON block_headers(index_block_hash,parent_block_id);
    "#,
    // table to map index block hashes to the txids of on-burnchain stacks operations that were
    // proessed
    r#"
    CREATE TABLE burnchain_txids(
        -- in epoch 2.x, this is the index block hash of the Stacks block.
        -- in epoch 3.x, this is the index block hash of the tenure-start block.
        index_block_hash TEXT PRIMARY KEY,
        -- this is a JSON-encoded list of txids
        txids TEXT NOT NULL
    );"#,
    r#"
    UPDATE db_config SET version = "3";
    "#,
];

const CHAINSTATE_SCHEMA_4: &[&str] = &[
    // schema change is JUST a new index, so just bump db_config.version
    //   and add the index to `CHAINSTATE_INDEXES` (which gets re-execed
    //   on every schema change)
    r#"
    UPDATE db_config SET version = "9";
    "#,
];

pub static CHAINSTATE_SCHEMA_5: &[&str] = &[
    // Schema change: drop the affirmation_weight column from pre_nakamoto block_headers and any indexes that reference it
    // but leave everything else the same
    r#"
    DROP INDEX IF EXISTS index_block_header_by_affirmation_weight;
    DROP INDEX IF EXISTS index_block_header_by_height_and_affirmation_weight;
    ALTER TABLE block_headers DROP COLUMN affirmation_weight;
    "#,
    r#"UPDATE db_config SET version = "11";"#,
];

const CHAINSTATE_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS index_block_hash_to_primary_key ON block_headers(index_block_hash,consensus_hash,block_hash);",
    "CREATE INDEX IF NOT EXISTS block_headers_hash_index ON block_headers(block_hash,block_height);",
    "CREATE INDEX IF NOT EXISTS block_index_hash_index ON block_headers(index_block_hash,consensus_hash,block_hash);",
    "CREATE INDEX IF NOT EXISTS block_headers_burn_header_height ON block_headers(burn_header_height);",
    "CREATE INDEX IF NOT EXISTS index_payments_block_hash_consensus_hash_vtxindex ON payments(block_hash,consensus_hash,vtxindex ASC);",
    "CREATE INDEX IF NOT EXISTS index_payments_index_block_hash_vtxindex ON payments(index_block_hash,vtxindex ASC);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_processed ON staging_microblocks(processed);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_orphaned ON staging_microblocks(orphaned);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_index_hash ON staging_microblocks(index_block_hash);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_index_hash_processed ON staging_microblocks(index_block_hash,processed);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_index_hash_orphaned ON staging_microblocks(index_block_hash,orphaned);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_microblock_hash ON staging_microblocks(microblock_hash);",
    "CREATE INDEX IF NOT EXISTS processed_stacks_blocks ON staging_blocks(processed,anchored_block_hash,consensus_hash);",
    "CREATE INDEX IF NOT EXISTS orphaned_stacks_blocks ON staging_blocks(orphaned,anchored_block_hash,consensus_hash);",
    "CREATE INDEX IF NOT EXISTS parent_blocks ON staging_blocks(parent_anchored_block_hash);",
    "CREATE INDEX IF NOT EXISTS parent_consensus_hashes ON staging_blocks(parent_consensus_hash);",
    "CREATE INDEX IF NOT EXISTS index_block_hashes ON staging_blocks(index_block_hash);",
    "CREATE INDEX IF NOT EXISTS height_stacks_blocks ON staging_blocks(height);",
    "CREATE INDEX IF NOT EXISTS txid_tx_index ON transactions(txid);",
    "CREATE INDEX IF NOT EXISTS index_block_hash_tx_index ON transactions(index_block_hash);",
    "CREATE INDEX IF NOT EXISTS index_headers_by_consensus_hash ON block_headers(consensus_hash);",
    "CREATE INDEX IF NOT EXISTS processable_block ON staging_blocks(processed, orphaned, attachable);",
];

pub use stacks_common::consts::MINER_REWARD_MATURITY;

// fraction (out of 100) of the coinbase a user will receive for reporting a microblock stream fork
pub const POISON_MICROBLOCK_COMMISSION_FRACTION: u128 = 5;

#[derive(Debug, Clone)]
pub struct ChainstateAccountBalance {
    pub address: String,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct ChainstateAccountLockup {
    pub address: String,
    pub amount: u64,
    pub block_height: u64,
}

#[derive(Debug, Clone)]
pub struct ChainstateBNSNamespace {
    pub namespace_id: String,
    pub importer: String,
    pub buckets: String,
    pub base: u64,
    pub coeff: u64,
    pub nonalpha_discount: u64,
    pub no_vowel_discount: u64,
    pub lifetime: u64,
}

#[derive(Debug, Clone)]
pub struct ChainstateBNSName {
    pub fully_qualified_name: String,
    pub owner: String,
    pub zonefile_hash: String,
}

impl ChainstateAccountLockup {
    pub fn new(address: StacksAddress, amount: u64, block_height: u64) -> ChainstateAccountLockup {
        ChainstateAccountLockup {
            address: address.to_string(),
            amount,
            block_height,
        }
    }
}

pub struct ChainStateBootData {
    pub first_burnchain_block_hash: BurnchainHeaderHash,
    pub first_burnchain_block_height: u32,
    pub first_burnchain_block_timestamp: u32,
    pub initial_balances: Vec<(PrincipalData, u64)>,
    pub pox_constants: PoxConstants,
    pub post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx)>>,
    pub get_bulk_initial_lockups:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateAccountLockup>>>>,
    pub get_bulk_initial_balances:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateAccountBalance>>>>,
    pub get_bulk_initial_namespaces:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateBNSNamespace>>>>,
    pub get_bulk_initial_names:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateBNSName>>>>,
}

impl ChainStateBootData {
    pub fn new(
        burnchain: &Burnchain,
        initial_balances: Vec<(PrincipalData, u64)>,
        post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx)>>,
    ) -> ChainStateBootData {
        ChainStateBootData {
            first_burnchain_block_hash: burnchain.first_block_hash.clone(),
            first_burnchain_block_height: burnchain.first_block_height as u32,
            first_burnchain_block_timestamp: burnchain.first_block_timestamp,
            initial_balances,
            pox_constants: burnchain.pox_constants.clone(),
            post_flight_callback,
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_namespaces: None,
            get_bulk_initial_names: None,
        }
    }
}

impl StacksChainState {
    fn instantiate_db(
        mainnet: bool,
        chain_id: u32,
        marf_path: &str,
        migrate: bool,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<MARF<StacksBlockId>, Error> {
        let mut marf = StacksChainState::open_index(marf_path, marf_opts)?;
        let mut dbtx = StacksDBTx::new(&mut marf, ());

        {
            let tx = dbtx.tx();

            for cmd in CHAINSTATE_INITIAL_SCHEMA {
                tx.execute_batch(cmd)?;
            }
            tx.execute(
                "INSERT INTO db_config (version,mainnet,chain_id) VALUES (?1,?2,?3)",
                params!["1".to_string(), (if mainnet { 1 } else { 0 }), chain_id,],
            )?;

            if migrate {
                StacksChainState::apply_schema_migrations(tx, mainnet, chain_id)?;
            }

            StacksChainState::add_indexes(tx)?;
        }

        dbtx.instantiate_index()?;
        dbtx.commit()?;
        Ok(marf)
    }

    /// Load the chainstate DBConfig, given the path to the chainstate root
    pub fn get_db_config_from_path(chainstate_root_path: &str) -> Result<DBConfig, db_error> {
        let index_pathbuf =
            StacksChainState::header_index_root_path(PathBuf::from(chainstate_root_path));
        let index_path = index_pathbuf
            .to_str()
            .ok_or_else(|| db_error::ParseError)?
            .to_string();

        let marf = StacksChainState::open_index(&index_path, None)?;
        StacksChainState::load_db_config(marf.sqlite_conn())
    }

    pub fn load_db_config(conn: &DBConn) -> Result<DBConfig, db_error> {
        let config = query_row::<DBConfig, _>(conn, "SELECT * FROM db_config LIMIT 1", NO_PARAMS)?;
        Ok(config.expect("BUG: no db_config installed"))
    }

    /// Do we need a schema migration?
    /// Return Ok(true) if so
    /// Return Ok(false) if not
    /// Return Err(..) on DB errors, or if this DB is not consistent with `mainnet` or `chain_id`
    fn need_schema_migrations(
        conn: &Connection,
        mainnet: bool,
        chain_id: u32,
    ) -> Result<bool, Error> {
        let db_config =
            StacksChainState::load_db_config(conn).expect("CORRUPTION: no db_config found");

        if db_config.mainnet != mainnet {
            error!(
                "Invalid chain state database: expected mainnet = {}, got {}",
                mainnet, db_config.mainnet
            );
            return Err(Error::InvalidChainstateDB);
        }

        if db_config.chain_id != chain_id {
            error!(
                "Invalid chain ID: expected {}, got {}",
                chain_id, db_config.chain_id
            );
            return Err(Error::InvalidChainstateDB);
        }

        Ok(db_config.version != CHAINSTATE_VERSION)
    }

    fn apply_schema_migrations(tx: &DBTx<'_>, mainnet: bool, chain_id: u32) -> Result<(), Error> {
        if !Self::need_schema_migrations(tx, mainnet, chain_id)? {
            return Ok(());
        }

        let mut db_config =
            StacksChainState::load_db_config(tx).expect("CORRUPTION: no db_config found");

        while db_config.version != CHAINSTATE_VERSION {
            match db_config.version.as_str() {
                "1" => {
                    info!("Migrating chainstate schema from version 1 to 2");
                    for cmd in CHAINSTATE_SCHEMA_2.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "2" => {
                    info!("Migrating chainstate schema from version 2 to 3");
                    for cmd in CHAINSTATE_SCHEMA_3.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "3" => {
                    info!("Migrating chainstate schema from version 3 to 4: nakamoto support");
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_1.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "4" => {
                    info!(
                        "Migrating chainstate schema from version 4 to 5: fix nakamoto tenure typo"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_2.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "5" => {
                    info!("Migrating chainstate schema from version 5 to 6: adds height_in_tenure field");
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_3.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "6" => {
                    info!(
                        "Migrating chainstate schema from version 6 to 7: adds signer_stats table"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_4.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "7" => {
                    info!(
                        "Migrating chainstate schema from version 7 to 8: add index for nakamoto block headers"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_5.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "8" => {
                    info!(
                        "Migrating chainstate schema from version 8 to 9: add index for staging_blocks"
                    );
                    for cmd in CHAINSTATE_SCHEMA_4.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "9" => {
                    info!(
                        "Migrating chainstate schema from version 9 to 10: add index for nakamoto_block_headers"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_6.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "10" => {
                    info!(
                        "Migrating chainstate schema from version 10 to 11: drop affirmation_weight from block_headers"
                    );
                    for cmd in CHAINSTATE_SCHEMA_5.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "11" => {
                    info!(
                        "Migrating chainstate schema from version 11 to 12: add index for nakamoto_block_headers"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_7.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "12" => {
                    info!(
                        "Migrating chainstate schema from version 12 to 13: add total_tenure_size field"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_8.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                _ => {
                    error!(
                        "Invalid chain state database: expected version = {}, got {}",
                        CHAINSTATE_VERSION, db_config.version
                    );
                    return Err(Error::InvalidChainstateDB);
                }
            }
            db_config =
                StacksChainState::load_db_config(tx).expect("CORRUPTION: no db_config found");
        }
        Ok(())
    }

    fn add_indexes(tx: &DBTx<'_>) -> Result<(), Error> {
        for cmd in CHAINSTATE_INDEXES {
            tx.execute_batch(cmd)?;
        }
        Ok(())
    }

    fn open_db(
        mainnet: bool,
        chain_id: u32,
        index_path: &str,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<MARF<StacksBlockId>, Error> {
        let create_flag = fs::metadata(index_path).is_err();

        if create_flag {
            // instantiate!
            StacksChainState::instantiate_db(mainnet, chain_id, index_path, true, marf_opts.clone())
        } else {
            let mut marf = StacksChainState::open_index(index_path, marf_opts)?;
            if !Self::need_schema_migrations(marf.sqlite_conn(), mainnet, chain_id)? {
                return Ok(marf);
            }

            // need a migration
            let tx = marf.storage_tx()?;
            StacksChainState::apply_schema_migrations(&tx, mainnet, chain_id)?;
            StacksChainState::add_indexes(&tx)?;
            tx.commit()?;
            Ok(marf)
        }
    }

    #[cfg(test)]
    pub fn open_db_without_migrations(
        mainnet: bool,
        chain_id: u32,
        index_path: &str,
    ) -> Result<MARF<StacksBlockId>, Error> {
        let create_flag = fs::metadata(index_path).is_err();

        if create_flag {
            // instantiate!
            StacksChainState::instantiate_db(mainnet, chain_id, index_path, false, None)
        } else {
            let mut marf = StacksChainState::open_index(index_path, None)?;

            // do we need to apply a schema change?
            let db_config = StacksChainState::load_db_config(marf.sqlite_conn())
                .expect("CORRUPTION: no db_config found");

            let tx = marf.storage_tx()?;
            StacksChainState::add_indexes(&tx)?;
            tx.commit()?;
            Ok(marf)
        }
    }

    /// Open or create the chainstate MARF index database and its associated blobs file.
    ///
    /// This function opens the SQLite-based MARF index at `marf_path`. If the index
    /// database or its corresponding blobs file does not exist, they will be created.
    ///
    /// # Arguments
    /// * `marf_path` - Path to the MARF SQLite index database.
    /// * `marf_opts` - Configuration options for opening the MARF.
    ///
    /// # Behavior
    /// Given a `marf_path` such as `chainstate/vm/clarity/index.sqlite`,
    /// the related blobs file will be `chainstate/vm/clarity/index.sqlite.blobs`.
    pub fn open_index(
        marf_path: &str,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<MARF<StacksBlockId>, db_error> {
        test_debug!("Open MARF index at {}", marf_path);
        let mut open_opts = marf_opts.unwrap_or(MARFOpenOpts::default());
        open_opts.external_blobs = true;
        // No auto-recovery override here — we honor whatever the caller passed. Production
        // startup paths (run_loop neon/nakamoto) leave `auto_recovery = false` and drive
        // canonical-validated recovery explicitly via [`StacksChainState::recover`]. Tests and
        // tools that want legacy "open + recover inline" semantics can pass
        // [`MARFOpenOpts::with_auto_recovery`] with `true`, or invoke
        // [`MARF::drain_pending_plans`] with `DrainPolicy::TrustPlan` after opening.
        test_override_marf_compression(&mut open_opts);
        let marf = MARF::from_path(marf_path, open_opts).map_err(db_error::IndexError)?;
        Ok(marf)
    }

    /// Idempotent `mkdir -p`
    fn mkdirs(path: &PathBuf) -> Result<(), Error> {
        match fs::metadata(path) {
            Ok(md) => {
                if !md.is_dir() {
                    error!("Not a directory: {:?}", path);
                    return Err(Error::DBError(db_error::ExistsError));
                }
                Ok(())
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(Error::DBError(db_error::IOError(e)));
                }
                fs::create_dir_all(path).map_err(|e| Error::DBError(db_error::IOError(e)))
            }
        }
    }

    fn parse_genesis_address(addr: &str, mainnet: bool) -> PrincipalData {
        // Typical entries are BTC encoded addresses that need converted to STX
        let stacks_address = match LegacyBitcoinAddress::from_b58(addr) {
            Ok(addr) => StacksAddress::from_legacy_bitcoin_address(&addr),
            // A few addresses (from legacy placeholder accounts) are already STX addresses
            _ => match StacksAddress::from_string(addr) {
                Some(addr) => addr,
                None => panic!("Failed to parsed genesis address {addr}"),
            },
        };
        // Convert a given address to the currently running network mode (mainnet vs testnet).
        // All addresses from the Stacks 1.0 import data should be mainnet, but we'll handle either case.
        let converted_version = if mainnet {
            match stacks_address.version() {
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                C32_ADDRESS_VERSION_TESTNET_MULTISIG => C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                _ => stacks_address.version(),
            }
        } else {
            match stacks_address.version() {
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                C32_ADDRESS_VERSION_MAINNET_MULTISIG => C32_ADDRESS_VERSION_TESTNET_MULTISIG,
                _ => stacks_address.version(),
            }
        };

        let (_, bytes) = stacks_address.destruct();
        let principal: PrincipalData = StandardPrincipalData::new(converted_version, bytes.0)
            .expect("FATAL: infallible constant version byte is not valid")
            .into();

        return principal;
    }

    /// Install the boot code into the chain history.
    fn install_boot_code(
        chainstate: &mut StacksChainState,
        mainnet: bool,
        boot_data: &mut ChainStateBootData,
    ) -> Result<Vec<StacksTransactionReceipt>, Error> {
        info!("Building genesis block");

        let tx_version = if mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let boot_code_address = boot_code_addr(mainnet);

        let boot_code_auth = boot_code_tx_auth(boot_code_address.clone());

        let mut boot_code_account = boot_code_acc(boot_code_address.clone(), 0);

        let mut initial_liquid_ustx = 0u128;
        let mut receipts = vec![];

        {
            let mut clarity_tx = chainstate.genesis_block_begin(
                &NULL_BURN_STATE_DB,
                &BURNCHAIN_BOOT_CONSENSUS_HASH,
                &BOOT_BLOCK_HASH,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            let boot_code = if mainnet {
                *boot::STACKS_BOOT_CODE_MAINNET
            } else {
                *boot::STACKS_BOOT_CODE_TESTNET
            };
            for (boot_code_name, boot_code_contract) in boot_code.iter() {
                debug!(
                    "Instantiate boot code contract '{}' ({} bytes)...",
                    boot_code_name,
                    boot_code_contract.len()
                );

                let smart_contract = TransactionPayload::SmartContract(
                    TransactionSmartContract {
                        name: ContractName::try_from(boot_code_name.to_string())
                            .expect("FATAL: invalid boot-code contract name"),
                        code_body: StacksString::from_str(boot_code_contract)
                            .expect("FATAL: invalid boot code body"),
                    },
                    None,
                );

                let boot_code_smart_contract =
                    StacksTransaction::new(tx_version, boot_code_auth.clone(), smart_contract);

                let tx_receipt = clarity_tx.connection().as_transaction(|clarity| {
                    StacksChainState::process_transaction_payload(
                        clarity,
                        &boot_code_smart_contract,
                        &boot_code_account,
                        None,
                    )
                })?;
                receipts.push(tx_receipt);

                boot_code_account.nonce += 1;
            }

            let mut allocation_events: Vec<StacksTransactionEvent> = vec![];
            if !boot_data.initial_balances.is_empty() {
                warn!(
                    "Seeding {} balances coming from the config",
                    boot_data.initial_balances.len()
                );
            }
            for (address, amount) in boot_data.initial_balances.iter() {
                clarity_tx.connection().as_transaction(|clarity| {
                    StacksChainState::account_genesis_credit(clarity, address, (*amount).into())
                });
                initial_liquid_ustx = initial_liquid_ustx
                    .checked_add(*amount as u128)
                    .expect("FATAL: liquid STX overflow");
                let mint_event = StacksTransactionEvent::STXEvent(STXEventType::STXMintEvent(
                    STXMintEventData {
                        recipient: address.clone(),
                        amount: *amount as u128,
                    },
                ));
                allocation_events.push(mint_event);
            }

            clarity_tx.connection().as_transaction(|clarity| {
                // Balances
                if let Some(get_balances) = boot_data.get_bulk_initial_balances.take() {
                    info!("Importing accounts from Stacks 1.0");
                    let mut balances_count = 0;
                    let initial_balances = get_balances();
                    for balance in initial_balances {
                        balances_count += 1;
                        let stx_address =
                            StacksChainState::parse_genesis_address(&balance.address, mainnet);
                        StacksChainState::account_genesis_credit(
                            clarity,
                            &stx_address,
                            balance.amount.into(),
                        );
                        initial_liquid_ustx = initial_liquid_ustx
                            .checked_add(balance.amount as u128)
                            .expect("FATAL: liquid STX overflow");
                        let mint_event = StacksTransactionEvent::STXEvent(
                            STXEventType::STXMintEvent(STXMintEventData {
                                recipient: stx_address,
                                amount: balance.amount.into(),
                            }),
                        );
                        allocation_events.push(mint_event);
                    }
                    info!("Seeding {} balances coming from chain dump", balances_count);
                }

                // Lockups
                if let Some(get_schedules) = boot_data.get_bulk_initial_lockups.take() {
                    info!("Initializing chain with lockups");
                    let mut lockups_per_block: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
                    let initial_lockups = get_schedules();
                    for schedule in initial_lockups {
                        let stx_address =
                            StacksChainState::parse_genesis_address(&schedule.address, mainnet);
                        let value = Value::Tuple(
                            TupleData::from_data(vec![
                                (
                                    ClarityName::from_literal("recipient"),
                                    Value::Principal(stx_address),
                                ),
                                (
                                    ClarityName::from_literal("amount"),
                                    Value::UInt(schedule.amount.into()),
                                ),
                            ])
                            .unwrap(),
                        );
                        match lockups_per_block.entry(schedule.block_height) {
                            Entry::Occupied(schedules) => {
                                schedules.into_mut().push(value);
                            }
                            Entry::Vacant(entry) => {
                                let schedules = vec![value];
                                entry.insert(schedules);
                            }
                        };
                    }

                    let lockup_contract_id = boot_code_id("lockup", mainnet);
                    let epoch = clarity.get_epoch();
                    clarity
                        .with_clarity_db(|db| {
                            for (block_height, schedule) in lockups_per_block.into_iter() {
                                let key = Value::UInt(block_height.into());
                                let value = Value::cons_list(schedule, &epoch).unwrap();
                                db.insert_entry_unknown_descriptor(
                                    &lockup_contract_id,
                                    "lockups",
                                    key,
                                    value,
                                    &epoch,
                                )?;
                            }
                            Ok(())
                        })
                        .unwrap();
                }

                // BNS Namespace
                let bns_contract_id = boot_code_id("bns", mainnet);
                if let Some(get_namespaces) = boot_data.get_bulk_initial_namespaces.take() {
                    info!("Initializing chain with namespaces");
                    let epoch = clarity.get_epoch();
                    clarity
                        .with_clarity_db(|db| {
                            let initial_namespaces = get_namespaces();
                            for entry in initial_namespaces {
                                let namespace = {
                                    if !BNS_CHARS_REGEX.is_match(&entry.namespace_id) {
                                        panic!("Invalid namespace characters");
                                    }
                                    let buffer = entry.namespace_id.as_bytes();
                                    Value::buff_from(buffer.to_vec()).expect("Invalid namespace")
                                };

                                let importer = {
                                    let address = StacksChainState::parse_genesis_address(
                                        &entry.importer,
                                        mainnet,
                                    );
                                    Value::Principal(address)
                                };

                                let revealed_at = Value::UInt(0);
                                let launched_at = Value::UInt(0);
                                let lifetime = Value::UInt(entry.lifetime.into());
                                let price_function = {
                                    let base = Value::UInt(entry.base.into());
                                    let coeff = Value::UInt(entry.coeff.into());
                                    let nonalpha_discount =
                                        Value::UInt(entry.nonalpha_discount.into());
                                    let no_vowel_discount =
                                        Value::UInt(entry.no_vowel_discount.into());
                                    let buckets: Vec<_> = entry
                                        .buckets
                                        .split(';')
                                        .map(|e| Value::UInt(e.parse::<u64>().unwrap().into()))
                                        .collect();
                                    assert_eq!(buckets.len(), 16);

                                    TupleData::from_data(vec![
                                        (
                                            ClarityName::from_literal("buckets"),
                                            Value::cons_list(buckets, &epoch).unwrap(),
                                        ),
                                        (ClarityName::from_literal("base"), base),
                                        (ClarityName::from_literal("coeff"), coeff),
                                        (
                                            ClarityName::from_literal("nonalpha-discount"),
                                            nonalpha_discount,
                                        ),
                                        (
                                            ClarityName::from_literal("no-vowel-discount"),
                                            no_vowel_discount,
                                        ),
                                    ])
                                    .unwrap()
                                };

                                let namespace_props = Value::Tuple(
                                    TupleData::from_data(vec![
                                        (ClarityName::from_literal("revealed-at"), revealed_at),
                                        (
                                            ClarityName::from_literal("launched-at"),
                                            Value::some(launched_at).unwrap(),
                                        ),
                                        (ClarityName::from_literal("lifetime"), lifetime),
                                        (ClarityName::from_literal("namespace-import"), importer),
                                        (
                                            ClarityName::from_literal("can-update-price-function"),
                                            Value::Bool(true),
                                        ),
                                        (
                                            ClarityName::from_literal("price-function"),
                                            Value::Tuple(price_function),
                                        ),
                                    ])
                                    .unwrap(),
                                );

                                db.insert_entry_unknown_descriptor(
                                    &bns_contract_id,
                                    "namespaces",
                                    namespace,
                                    namespace_props,
                                    &epoch,
                                )?;
                            }
                            Ok(())
                        })
                        .unwrap();
                }

                // BNS Names
                if let Some(get_names) = boot_data.get_bulk_initial_names.take() {
                    info!("Initializing chain with names");
                    let epoch = clarity.get_epoch();
                    clarity
                        .with_clarity_db(|db| {
                            let initial_names = get_names();
                            for entry in initial_names {
                                let components: Vec<_> =
                                    entry.fully_qualified_name.split('.').collect();
                                assert_eq!(components.len(), 2);

                                let namespace = {
                                    let namespace_str = components.get(1).unwrap();
                                    if !BNS_CHARS_REGEX.is_match(namespace_str) {
                                        panic!("Invalid namespace characters");
                                    }
                                    let buffer = namespace_str.as_bytes();
                                    Value::buff_from(buffer.to_vec()).expect("Invalid namespace")
                                };

                                let name = {
                                    let name_str = components.get(0).unwrap().to_string();
                                    if !BNS_CHARS_REGEX.is_match(&name_str) {
                                        panic!("Invalid name characters");
                                    }
                                    let buffer = name_str.as_bytes();
                                    Value::buff_from(buffer.to_vec()).expect("Invalid name")
                                };

                                let fqn = Value::Tuple(
                                    TupleData::from_data(vec![
                                        (ClarityName::from_literal("namespace"), namespace),
                                        (ClarityName::from_literal("name"), name),
                                    ])
                                    .unwrap(),
                                );

                                let owner_address =
                                    StacksChainState::parse_genesis_address(&entry.owner, mainnet);

                                let zonefile_hash = {
                                    if entry.zonefile_hash.is_empty() {
                                        Value::buff_from(vec![]).unwrap()
                                    } else {
                                        let buffer = Hash160::from_hex(&entry.zonefile_hash)
                                            .expect("Invalid zonefile_hash");
                                        Value::buff_from(buffer.to_bytes().to_vec()).unwrap()
                                    }
                                };

                                let expected_asset_type =
                                    db.get_nft_key_type(&bns_contract_id, "names")?;
                                db.set_nft_owner(
                                    &bns_contract_id,
                                    "names",
                                    &fqn,
                                    &owner_address,
                                    &expected_asset_type,
                                    &epoch,
                                )?;

                                let registered_at = Value::UInt(0);
                                let name_props = Value::Tuple(
                                    TupleData::from_data(vec![
                                        (
                                            ClarityName::from_literal("registered-at"),
                                            Value::some(registered_at).unwrap(),
                                        ),
                                        (ClarityName::from_literal("imported-at"), Value::none()),
                                        (ClarityName::from_literal("revoked-at"), Value::none()),
                                        (ClarityName::from_literal("zonefile-hash"), zonefile_hash),
                                    ])
                                    .unwrap(),
                                );

                                db.insert_entry_unknown_descriptor(
                                    &bns_contract_id,
                                    "name-properties",
                                    fqn.clone(),
                                    name_props,
                                    &epoch,
                                )?;

                                db.insert_entry_unknown_descriptor(
                                    &bns_contract_id,
                                    "owner-name",
                                    Value::Principal(owner_address),
                                    fqn,
                                    &epoch,
                                )?;
                            }
                            Ok(())
                        })
                        .unwrap();
                }
                info!("Saving Genesis block. This could take a while");
            });

            let allocations_tx = StacksTransaction::new(
                tx_version,
                boot_code_auth,
                TransactionPayload::TokenTransfer(
                    PrincipalData::Standard(boot_code_address.into()),
                    0,
                    TokenTransferMemo([0u8; 34]),
                ),
            );
            let allocations_receipt = StacksTransactionReceipt::from_stx_transfer(
                allocations_tx,
                allocation_events,
                Value::okay_true(),
                ExecutionCost::ZERO,
            );
            receipts.push(allocations_receipt);

            if let Some(callback) = boot_data.post_flight_callback.take() {
                callback(&mut clarity_tx);
            }

            // Setup burnchain parameters for pox contract
            let pox_constants = &boot_data.pox_constants;
            let contract = boot_code_id("pox", mainnet);
            let sender = PrincipalData::from(contract.clone());
            let params = vec![
                Value::UInt(boot_data.first_burnchain_block_height as u128),
                Value::UInt(pox_constants.prepare_length as u128),
                Value::UInt(pox_constants.reward_cycle_length as u128),
                Value::UInt(pox_constants.pox_rejection_fraction as u128),
            ];
            clarity_tx.connection().as_transaction(|conn| {
                conn.run_contract_call(
                    &sender,
                    None,
                    &contract,
                    "set-burnchain-parameters",
                    &params,
                    |_, _| None,
                    None,
                )
                .expect("Failed to set burnchain parameters in PoX contract");
            });

            clarity_tx
                .connection()
                .as_transaction(|tx| {
                    tx.with_clarity_db(|db| {
                        db.increment_ustx_liquid_supply(initial_liquid_ustx)
                            .map_err(|e| e.into())
                    })
                })
                .expect("FATAL: `ustx-liquid-supply` overflowed");

            clarity_tx.commit_to_block(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
        }

        // verify that genesis root hash is as expected
        {
            let genesis_root_hash = chainstate.clarity_state.with_marf(|marf| {
                let index_block_hash = StacksBlockHeader::make_index_block_hash(
                    &FIRST_BURNCHAIN_CONSENSUS_HASH,
                    &FIRST_STACKS_BLOCK_HASH,
                );
                marf.get_root_hash_at(&index_block_hash).unwrap()
            });

            info!("Computed Clarity state genesis"; "root_hash" => %genesis_root_hash);

            if mainnet {
                assert_eq!(
                    &genesis_root_hash.to_string(),
                    MAINNET_2_0_GENESIS_ROOT_HASH,
                    "Incorrect root hash for genesis block computed. expected={} computed={}",
                    MAINNET_2_0_GENESIS_ROOT_HASH,
                    genesis_root_hash
                )
            }
        }

        {
            // add a block header entry for the boot code
            let mut tx = chainstate.index_tx_begin();
            let parent_hash = StacksBlockId::sentinel();
            let first_index_hash = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );

            test_debug!(
                "Boot code headers index_put_begin {}-{}",
                &parent_hash,
                &first_index_hash
            );

            let first_root_hash = tx.put_indexed_all(&parent_hash, &first_index_hash, &[], &[])?;

            test_debug!(
                "Boot code headers index_commit {}-{}",
                &parent_hash,
                &first_index_hash
            );

            let first_tip_info = StacksHeaderInfo::genesis(
                first_root_hash,
                &boot_data.first_burnchain_block_hash,
                boot_data.first_burnchain_block_height,
                boot_data.first_burnchain_block_timestamp as u64,
            );

            StacksChainState::insert_stacks_block_header(
                &tx,
                &parent_hash,
                &first_tip_info,
                &ExecutionCost::ZERO,
            )?;
            tx.commit()?;
        }

        debug!("Finish install boot code");
        Ok(receipts)
    }

    /// Open an existing chainstate without running boot.
    ///
    /// **Recovery contract for `marf_opts = None`**: this convenience entry point preserves the
    /// pre-refactor "open + auto-recover inline" semantics for callers that don't pass explicit
    /// opts. Specifically, `None` is internally substituted with
    /// `MARFOpenOpts::default().with_auto_recovery(true)`, so any pending squash promotion plans
    /// are published or abandoned (with `TrustPlan` semantics) as part of opening. This makes
    /// `open()` a safe drop-in for tests, tools, and short-lived CLI handlers that didn't
    /// previously coordinate with [`Self::recover`].
    ///
    /// **For long-lived production startup**, callers that want canonical-validated recovery
    /// MUST pass `Some(opts)` with `auto_recovery = false` (the default for explicit opts) and
    /// follow up with [`Self::recover`] against a real `CanonicalView`. The neon and nakamoto
    /// run loops do this in `boot_chainstate`.
    pub fn open(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<(StacksChainState, Vec<StacksTransactionReceipt>), Error> {
        StacksChainState::open_and_exec(mainnet, chain_id, path_str, None, marf_opts)
    }

    /// Open a chainstate handle that shares its `unconfirmed_state` slot with other handles
    /// (typically opened against the same DB on different threads). Each call returns an
    /// independent `StacksChainState` (its own SQLite connection, MARF handle, Clarity
    /// instance for confirmed state) but installs the supplied [`SharedUnconfirmedState`]
    /// `Arc` into the new handle, so all handles constructed with the same `shared_unconfirmed`
    /// observe a single in-memory unconfirmed view through one inner mutex.
    ///
    /// Intended for use **after** boot has already migrated the on-disk chainstate via
    /// [`open_and_exec`] with `boot_data` set. The implementation calls `open_and_exec` with
    /// `boot_data = None`, which skips the genesis/install-boot-code path; any pending SQL
    /// schema migrations would still run, but on a post-boot DB those are no-ops. Use this
    /// as a per-thread factory.
    pub fn open_with_shared_unconfirmed(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
        marf_opts: Option<MARFOpenOpts>,
        shared_unconfirmed: SharedUnconfirmedState,
    ) -> Result<StacksChainState, Error> {
        let (mut chainstate, _receipts) =
            StacksChainState::open_and_exec(mainnet, chain_id, path_str, None, marf_opts)?;
        chainstate.unconfirmed_state = shared_unconfirmed;
        Ok(chainstate)
    }

    /// Re-open the chainstate -- i.e. to get a new handle to it using an existing chain state's
    /// parameters.
    ///
    /// Note: the returned handle has a **fresh, independent** [`SharedUnconfirmedState`]
    /// slot — it does NOT participate in the source handle's shared unconfirmed view. Use
    /// [`open_with_shared_unconfirmed`] when you need a sharing-aware handle.
    pub fn reopen(&self) -> Result<(StacksChainState, Vec<StacksTransactionReceipt>), Error> {
        StacksChainState::open(
            self.mainnet,
            self.chain_id,
            &self.root_path,
            self.marf_opts.clone(),
        )
    }

    /// Re-open the chainstate DB
    pub fn reopen_db(&self) -> Result<DBConn, Error> {
        let path = PathBuf::from(self.root_path.clone());
        let header_index_root_path = StacksChainState::header_index_root_path(path);
        let header_index_root = header_index_root_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let state_index = StacksChainState::open_db(
            self.mainnet,
            self.chain_id,
            &header_index_root,
            self.marf_opts.clone(),
        )?;
        Ok(state_index.into_sqlite_conn())
    }

    pub fn blocks_path(mut path: PathBuf) -> PathBuf {
        path.push("blocks");
        path
    }

    pub fn vm_state_path(mut path: PathBuf) -> PathBuf {
        path.push("vm");
        path
    }

    pub fn vm_state_index_root_path(path: PathBuf) -> PathBuf {
        let mut ret = StacksChainState::vm_state_path(path);
        ret.push("clarity");
        ret
    }

    pub fn vm_state_index_marf_path(path: PathBuf) -> PathBuf {
        let mut ret = StacksChainState::vm_state_index_root_path(path);
        ret.push("marf.sqlite");
        ret
    }

    pub fn header_index_root_path(path: PathBuf) -> PathBuf {
        let mut ret = StacksChainState::vm_state_path(path);
        ret.push("index.sqlite");
        ret
    }

    pub fn make_chainstate_dirs(path_str: &str) -> Result<(), Error> {
        let path = PathBuf::from(path_str);
        StacksChainState::mkdirs(&path)?;

        let blocks_path = StacksChainState::blocks_path(path.clone());
        StacksChainState::mkdirs(&blocks_path)?;

        let vm_state_path = StacksChainState::vm_state_path(path);
        StacksChainState::mkdirs(&vm_state_path)?;
        Ok(())
    }

    /// Open + (if `boot_data` is `Some`) initialize the chainstate.
    ///
    /// **Recovery contract for `marf_opts = None`**: identical to [`Self::open`] — `None` is
    /// substituted with `MARFOpenOpts::default().with_auto_recovery(true)` so pre-refactor
    /// callers (tests, tools, CLI handlers) that didn't coordinate with [`Self::recover`]
    /// continue to get inline auto-recovery and a fully-recovered handle.
    ///
    /// Production startup paths (run_loop neon/nakamoto) pass `Some(opts)` with
    /// `auto_recovery = false` and drive recovery explicitly via [`Self::recover`] afterward.
    pub fn open_and_exec(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
        boot_data: Option<&mut ChainStateBootData>,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<(StacksChainState, Vec<StacksTransactionReceipt>), Error> {
        // Convenience-entry contract: `None` opts means the caller wants the pre-refactor
        // "open + auto-recover inline" semantics. Substitute default opts with
        // `auto_recovery = true` so recovery happens at open time. Callers that explicitly pass
        // `Some(opts)` get whatever they specified — production startup uses `auto_recovery =
        // false` and follows up with `chainstate.recover(view)`.
        let marf_opts =
            Some(marf_opts.unwrap_or_else(|| MARFOpenOpts::default().with_auto_recovery(true)));
        StacksChainState::make_chainstate_dirs(path_str)?;
        let path = PathBuf::from(path_str);
        let blocks_path = StacksChainState::blocks_path(path.clone());
        let blocks_path_root = blocks_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let clarity_state_index_root_path =
            StacksChainState::vm_state_index_root_path(path.clone());
        let clarity_state_index_root = clarity_state_index_root_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let clarity_state_index_marf_path =
            StacksChainState::vm_state_index_marf_path(path.clone());
        let clarity_state_index_marf = clarity_state_index_marf_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let header_index_root_path = StacksChainState::header_index_root_path(path.clone());
        let header_index_root = header_index_root_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let nakamoto_staging_blocks_path =
            StacksChainState::static_get_nakamoto_staging_blocks_path(path)?;
        let nakamoto_staging_blocks_conn =
            StacksChainState::open_nakamoto_staging_blocks(&nakamoto_staging_blocks_path, true)?;

        let init_required = fs::metadata(&clarity_state_index_marf).is_err();

        let state_index =
            StacksChainState::open_db(mainnet, chain_id, &header_index_root, marf_opts.clone())?;

        let vm_state = MarfedKV::open(
            &clarity_state_index_root,
            Some(&StacksBlockHeader::make_index_block_hash(
                &MINER_BLOCK_CONSENSUS_HASH,
                &MINER_BLOCK_HEADER_HASH,
            )),
            marf_opts.clone(),
        )
        .map_err(|e| Error::ClarityError(e.into()))?;

        Self::from_marfs(
            mainnet,
            chain_id,
            path_str,
            blocks_path_root,
            clarity_state_index_marf,
            clarity_state_index_root,
            nakamoto_staging_blocks_conn,
            state_index,
            vm_state,
            init_required,
            boot_data,
            marf_opts,
        )
    }

    /// Assemble a [`StacksChainState`] from already-opened MARF handles. Splits the
    /// "compute-paths-and-open-MARFs" prelude (which lives in [`Self::open_and_exec`]) from the
    /// "wire-the-chainstate-struct-and-run-boot-init" body so production startup can:
    ///
    /// 1. Open both MARFs in deferred mode (skipping canonical-sensitive recovery).
    /// 2. Derive a single canonical view from the headers SQL tables.
    /// 3. Drain pending plans on both MARFs against that canonical view.
    /// 4. Hand fully-recovered handles to this constructor.
    ///
    /// PR 1 ships the constructor; `open_and_exec` continues to call it with handles opened via
    /// the legacy `MARF::from_path` / `MarfedKV::open` shape, so behavior is unchanged for all
    /// callers. PR 2 wires the production startup to use the deferred + drain shape.
    #[allow(clippy::too_many_arguments)]
    pub fn from_marfs(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
        blocks_path_root: String,
        clarity_state_index_marf: String,
        clarity_state_index_root: String,
        nakamoto_staging_blocks_conn: NakamotoStagingBlocksConn,
        state_index: MARF<StacksBlockId>,
        vm_state: MarfedKV,
        init_required: bool,
        boot_data: Option<&mut ChainStateBootData>,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<(StacksChainState, Vec<StacksTransactionReceipt>), Error> {
        let clarity_state = ClarityInstance::new(mainnet, chain_id, vm_state);

        // Resolve cadence + sidecar retention from baked-in defaults. The
        // operator-facing `Config` plumbing (per design §6) will replace
        // these with TOML-supplied values in a follow-up; for now the
        // library defaults are what every deployment runs.
        //
        // Headers stays on fixed cadence — its squash is sub-second and
        // smoothing isn't worth the variance loss. Clarity moves to
        // work-aware (64 MiB / 100..2000 blocks) so we exercise the
        // adaptive path under real workloads. See
        // `SquashCadenceConfig::default_clarity` for the rationale; the
        // values are first-cut estimates and should be calibrated against
        // measured wall-clock (Step 7).
        //
        // Sidecar retention uses `resolve_retention_blocks` so legacy
        // `MARFOpenOpts::squash_root_snapshot_retention_levels` configs
        // continue to work for one release.
        let squash_sidecar_retention_blocks = {
            let opts = marf_opts.as_ref();
            crate::chainstate::stacks::index::squash::resolve_retention_blocks(
                opts.map(|o| o.squash_root_snapshot_retention_levels),
                opts.and_then(|o| o.squash_root_snapshot_retention_blocks),
            )
        };
        // v1.5 Phase B: resolve the horizon used by `should_squash`'s
        // horizon predicate, in this priority order (per design doc
        // §3.4):
        //
        //   1. `MARFOpenOpts::squash_horizon_burn_blocks` if `Some(_)`
        //      — explicit caller override (tests / ops experimentation).
        //   2. `marf_state.horizon_burn_blocks` from the headers MARF's
        //      v5 schema — the persistent on-disk authoritative value.
        //   3. Hardcoded `6` (Bitcoin's reorg-confirmation window plus
        //      margin) — final fallback for pre-v5 chainstates that
        //      don't have a `marf_state` row yet.
        //
        // Reading from `marf_state` first ensures upgrades-in-place
        // pick up whatever value was persisted (e.g. an operator-
        // calibrated horizon) without requiring an ops re-config.
        let squash_horizon_burn_blocks = if let Some(override_value) = marf_opts
            .as_ref()
            .and_then(|o| o.squash_horizon_burn_blocks)
        {
            override_value
        } else {
            crate::chainstate::stacks::index::trie_sql::read_marf_state(state_index.sqlite_conn())
                .map(|s| s.horizon_burn_blocks)
                .unwrap_or(6)
        };

        let mut chainstate = StacksChainState {
            mainnet,
            chain_id,
            clarity_state,
            nakamoto_staging_blocks_conn,
            state_index,
            blocks_path: blocks_path_root,
            clarity_state_index_path: clarity_state_index_marf,
            clarity_state_index_root,
            root_path: path_str.to_string(),
            unconfirmed_state: SharedUnconfirmedState::new(),
            fault_injection: StacksChainStateFaults::new(),
            marf_opts,
            squash_cadence_headers: SquashCadenceConfig::default_headers(),
            squash_cadence_clarity: SquashCadenceConfig::default_clarity(),
            squash_sidecar_retention_blocks,
            // v1.5 Phase B horizon: resolved from `marf_opts` BEFORE
            // the move into the struct. Default 6 burn blocks
            // (Bitcoin's reorg-confirmation window plus margin); the
            // `MARFOpenOpts::squash_horizon_burn_blocks` override
            // flows through here in test/ops scenarios; production
            // reads from the persisted `marf_state.horizon_burn_blocks`
            // value (B5 wires that path).
            squash_horizon_burn_blocks,
            // B5d-fu.2: no in-flight promotions on a fresh open.
            // Recovery for any prior crashed promotion happens
            // synchronously inside `TrieFileStorage::open_opts` via
            // `recover_pending_promotions`; once the chainstate is
            // open, slot is empty until the next `maybe_squash`
            // dispatches a worker.
            headers_promotion_handle: None,
            clarity_promotion_handle: None,
        };

        let mut receipts = vec![];
        match (init_required, boot_data) {
            (true, Some(boot_data)) => {
                let mut res =
                    StacksChainState::install_boot_code(&mut chainstate, mainnet, boot_data)?;
                receipts.append(&mut res);
            }
            (true, None) => {
                panic!(
                    "StacksChainState initialization is required, but boot_data was not passed."
                );
            }
            (false, _) => {}
        }

        Ok((chainstate, receipts))
    }

    /// Drive recovery on both the headers and clarity MARFs.
    ///
    /// **When to call this**: at startup, after constructing the chainstate via
    /// [`Self::from_marfs`] (or [`Self::open_and_exec`]) with
    /// [`crate::chainstate::stacks::index::marf::MARFOpenOpts::with_auto_recovery`] set to
    /// `false`, and **before spawning the chains-coordinator / p2p / relayer threads**.
    ///
    /// **Why startup-only**: a `Some(canonical_view)` call resolves "latest known canonical
    /// chain" to validate plans against. The view is typically built from
    /// [`crate::chainstate::burn::db::sortdb::SortitionDB::get_canonical_stacks_chain_tip_hash_and_height`],
    /// which is documented as unsafe to call during block processing because it returns
    /// latest-data-known-to-the-node, not historical-block-assembly state. At startup this is
    /// fine — there's no active block processing — but invoking `recover` from a mid-life
    /// context (e.g. inside a chains-coordinator handler) would race the same block processing
    /// the warning protects against. Don't.
    ///
    /// **`canonical_view` parameter:**
    /// - `Some(view)`: drain pending squash plans against `view`. Plans whose recorded canonical
    ///   chain has diverged from the view get discarded (logged as
    ///   [`crate::chainstate::stacks::index::squash_recover::DrainOutcome::DiscardedStale`])
    ///   instead of published — closing the detached-worker stale-tip publish window that
    ///   produced the level-7 divergence panic.
    /// - `None`: drain with
    ///   [`crate::chainstate::stacks::index::squash_recover::DrainPolicy::TrustPlan`]. Use this
    ///   on the bootstrap path before any canonical Stacks tip exists, or when the caller has
    ///   no SortitionDB / headers context to derive a view.
    ///
    /// Resolving the canonical view from a SortitionDB + the chainstate's headers tables is the
    /// caller's responsibility — typically by constructing
    /// [`crate::chainstate::stacks::db::headers::HeadersCanonicalView`] from the SortDB-resolved
    /// Stacks tip + this chainstate's [`Self::state_index`] connection. Decoupling the view
    /// construction from `recover` keeps this method DB-agnostic and unit-testable with mock
    /// views.
    ///
    /// Returns the per-MARF drain stats so callers can log the recovery outcome.
    ///
    /// **Idempotent.** Safe to call repeatedly; subsequent calls with no remaining plans return
    /// empty stats.
    pub fn recover(
        &mut self,
        canonical_view: Option<
            &dyn crate::chainstate::stacks::index::squash_recover::CanonicalView,
        >,
    ) -> Result<RecoverResult, Error> {
        use crate::chainstate::stacks::index::squash_recover::DrainPolicy;
        let policy = match canonical_view {
            Some(view) => DrainPolicy::Canonical(view),
            None => DrainPolicy::TrustPlan,
        };
        let policy_was_canonical = matches!(policy, DrainPolicy::Canonical(_));

        let headers_stats = self.state_index.drain_pending_plans(match &policy {
            DrainPolicy::TrustPlan => DrainPolicy::TrustPlan,
            DrainPolicy::Canonical(v) => DrainPolicy::Canonical(*v),
        })?;
        let clarity_stats = self.clarity_state.with_marf(|marf| {
            marf.drain_pending_plans(match &policy {
                DrainPolicy::TrustPlan => DrainPolicy::TrustPlan,
                DrainPolicy::Canonical(v) => DrainPolicy::Canonical(*v),
            })
        })?;

        Ok(RecoverResult {
            headers: headers_stats,
            clarity: clarity_stats,
            policy_was_canonical,
        })
    }

    pub fn config(&self) -> DBConfig {
        DBConfig {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            version: CHAINSTATE_VERSION.to_string(),
        }
    }
}

/// Result of [`StacksChainState::recover`]. Aggregates per-MARF drain outcomes plus diagnostic
/// info about which policy actually fired (callers log this so operators can tell whether
/// canonical validation was active or the bootstrap fallback ran).
#[derive(Debug)]
pub struct RecoverResult {
    /// Drain stats for the headers MARF (`state_index`).
    pub headers: crate::chainstate::stacks::index::squash_recover::DrainStats,
    /// Drain stats for the clarity MARF (`clarity_state`'s inner `MarfedKV`).
    pub clarity: crate::chainstate::stacks::index::squash_recover::DrainStats,
    /// `true` if recovery used `DrainPolicy::Canonical`, `false` if it fell back to `TrustPlan`
    /// because the SortitionDB had no canonical Stacks tip yet.
    pub policy_was_canonical: bool,
}

impl StacksChainState {
    /// Begin a transaction against the (indexed) stacks chainstate DB.
    /// Does not create a Clarity instance.
    pub fn index_tx_begin(&mut self) -> StacksDBTx<'_> {
        StacksDBTx::new(&mut self.state_index, ())
    }

    pub fn index_conn(&self) -> StacksDBConn<'_> {
        StacksDBConn::new(&self.state_index, ())
    }

    /// Begin a transaction against the underlying DB
    /// Does not create a Clarity instance, and does not affect the MARF.
    pub fn db_tx_begin(&mut self) -> Result<DBTx<'_>, Error> {
        self.state_index.storage_tx().map_err(Error::DBError)
    }

    /// Simultaneously begin a transaction against both the headers and blocks.
    /// Used when considering a new block to append the chain state.
    pub fn chainstate_tx_begin(&mut self) -> (ChainstateTx<'_>, &mut ClarityInstance) {
        let config = self.config();
        let blocks_path = self.blocks_path.clone();
        let clarity_instance = &mut self.clarity_state;
        let inner_tx = StacksDBTx::new(&mut self.state_index, ());

        let chainstate_tx =
            ChainstateTx::new(inner_tx, blocks_path, self.root_path.clone(), config);

        (chainstate_tx, clarity_instance)
    }

    // NOTE: used for testing in the stacks testnet code.
    // DO NOT CALL FROM PRODUCTION
    pub fn clarity_eval_read_only(
        &self,
        burn_dbconn: &dyn BurnStateDB,
        parent_id_bhh: &StacksBlockId,
        contract: &QualifiedContractIdentifier,
        code: &str,
    ) -> Value {
        let result = self.clarity_state.eval_read_only(
            parent_id_bhh,
            &HeadersDBConn(StacksDBConn::new(&self.state_index, ())),
            burn_dbconn,
            contract,
            code,
        );
        result.unwrap()
    }

    /// Checked eval-read-only
    pub fn eval_read_only(
        &self,
        burn_dbconn: &dyn BurnStateDB,
        parent_id_bhh: &StacksBlockId,
        contract: &QualifiedContractIdentifier,
        code: &str,
    ) -> Result<Value, ClarityError> {
        self.clarity_state.eval_read_only(
            parent_id_bhh,
            &HeadersDBConn(StacksDBConn::new(&self.state_index, ())),
            burn_dbconn,
            contract,
            code,
        )
    }

    /// Execute a public function in `contract` from a read-only DB context
    ///  Any mutations that occur will be rolled-back before returning, regardless of
    ///  an okay or error result.
    pub fn eval_fn_read_only(
        &self,
        burn_dbconn: &dyn BurnStateDB,
        parent_id_bhh: &StacksBlockId,
        contract: &QualifiedContractIdentifier,
        function: &str,
        args: &[Value],
    ) -> Result<Value, ClarityError> {
        let headers_db = HeadersDBConn(StacksDBConn::new(&self.state_index, ()));
        let mut conn = self.clarity_state.read_only_connection_checked(
            parent_id_bhh,
            &headers_db,
            burn_dbconn,
        )?;

        let args: Vec<_> = args
            .iter()
            .map(|x| SymbolicExpression::atom_value(x.clone()))
            .collect();

        let result = conn.with_readonly_clarity_env(
            self.mainnet,
            self.chain_id,
            contract.clone().into(),
            None,
            LimitedCostTracker::Free,
            |exec_state, invoke_ctx| {
                exec_state
                    .execute_contract(
                        invoke_ctx, contract, function, &args,
                        // read-only is set to `false` so that non-read-only functions
                        //  can be executed. any transformation is rolled back.
                        false,
                    )
                    .map_err(ClarityEvalError::from)
            },
        )?;

        Ok(result)
    }

    pub fn db(&self) -> &DBConn {
        self.state_index.sqlite_conn()
    }

    /// Begin processing an epoch's transactions within the context of a chainstate transaction
    pub fn chainstate_block_begin<'a, 'b>(
        chainstate_tx: &'b ChainstateTx<'b>,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'b> {
        let conf = chainstate_tx.config.clone();
        StacksChainState::inner_clarity_tx_begin(
            conf,
            chainstate_tx,
            clarity_instance,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    /// Begin processing an epoch's transactions within the context of a chainstate transaction,
    /// but do so in a way that will not cause them to be persisted.  Used for replaying blocks.
    pub fn chainstate_ephemeral_block_begin<'a, 'b>(
        chainstate_tx: &'b ChainstateTx<'b>,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'b> {
        let conf = chainstate_tx.config.clone();
        StacksChainState::inner_ephemeral_clarity_tx_begin(
            conf,
            chainstate_tx,
            clarity_instance,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    /// Begin a transaction against the Clarity VM, _outside of_ the context of a chainstate
    /// transaction.  Used by the miner for producing blocks.
    pub fn block_begin<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        StacksChainState::inner_clarity_tx_begin(
            conf,
            &self.state_index,
            &mut self.clarity_state,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    /// Begin an ephemeral transaction against the Clarity VM, _outside of_ the context of a chainstate
    /// transaction.  The block will not be stored to disk, even if it is committed.
    /// Used by code paths which need to replay blocks.
    pub fn ephemeral_block_begin<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        StacksChainState::inner_ephemeral_clarity_tx_begin(
            conf,
            &self.state_index,
            &mut self.clarity_state,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    /// Begin a transaction against the Clarity VM for initiating the genesis block
    ///  the genesis block is special cased because it must be evaluated _before_ the
    ///  cost contract is loaded in the boot code.
    pub fn genesis_block_begin<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        let db = &self.state_index;
        let clarity_instance = &mut self.clarity_state;

        // mix burn header hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            StacksChainState::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing genesis Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_genesis_block(
            &parent_index_block,
            &new_index_block,
            db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    pub fn with_clarity_marf<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut MARF<StacksBlockId>) -> R,
    {
        self.clarity_state.with_marf(f)
    }

    /// Walk a single Stacks tip's index-block-hash backward via the headers
    /// tables (`block_headers` for Stacks 2.x, `nakamoto_block_headers` for
    /// Nakamoto), returning the block's height and its parent's
    /// index-block-hash. Returns `None` if the tip isn't recorded in either
    /// table — the caller should treat that as "ancestry unknowable from this
    /// chainstate" rather than a fatal error.
    fn lookup_height_and_parent(
        conn: &Connection,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<(u32, StacksBlockId)>, Error> {
        let sql_2x = "SELECT block_height, parent_block_id FROM block_headers \
                      WHERE index_block_hash = ?1";
        if let Some(row) = conn
            .query_row(sql_2x, params![index_block_hash], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, StacksBlockId>(1)?))
            })
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?
        {
            return Ok(Some((row.0 as u32, row.1)));
        }
        let sql_nak = "SELECT block_height, parent_block_id FROM nakamoto_block_headers \
                       WHERE index_block_hash = ?1";
        let row = conn
            .query_row(sql_nak, params![index_block_hash], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, StacksBlockId>(1)?))
            })
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        Ok(row.map(|(h, p)| (h as u32, p)))
    }

    /// Build a `height -> index_block_hash` map for the canonical ancestors of `tip` covering
    /// `[low_height ..= tip_height]`, walking the headers tables once. The map backs the closure
    /// passed to per-MARF
    /// [`MARF::detect_divergence`](crate::chainstate::stacks::index::marf::MARF::detect_divergence)
    /// so each level-range probe is an O(1) lookup against a precomputed snapshot, independent of
    /// the level's span.
    ///
    /// The walk distance is exactly `tip_height - low_height + 1` — strictly the minimum walk
    /// needed to cover the deepest reachable in-range ancestor. There is no headroom multiplier;
    /// the loop's exit conditions (`height < low_height`, `parent == sentinel`, ancestry
    /// truncation) all terminate naturally without a separate "walk cap" judgment call. The older
    /// `detect_squash_divergence` walker fell back to a `4 × level_span` cap that broke under
    /// variable cadence (a small level + long open suffix could exceed the cap legitimately and
    /// surface as a spurious error); this exact bound is correct under any cadence.
    ///
    /// Truncated ancestry (the closure returns `None` for some heights) is not fatal — the per-MARF
    /// detector skips those heights. Callers treating "ancestry unknowable from this chainstate" as
    /// a hard error get that signal downstream when the actual MARF read fails, not from this
    /// helper.
    ///
    /// Sweep-facing public alias for [`Self::precompute_canonical_ancestors`]. Phase C's
    /// hot-reclaim canonical-chain helper
    /// ([`crate::chainstate::stacks::index::hot_reclaim::canonical_chain_for_sweep`]) calls into this
    /// from outside the `db/mod.rs` module, so it needs `pub(crate)` visibility. The original
    /// walker stays private — tests + the divergence detector reach it through the chain of methods
    /// on `StacksChainState`.
    pub(crate) fn precompute_canonical_ancestors_for_sweep(
        conn: &Connection,
        tip: &StacksBlockId,
        tip_height: u32,
        low_height: u32,
    ) -> Result<HashMap<u32, StacksBlockId>, Error> {
        Self::precompute_canonical_ancestors(conn, tip, tip_height, low_height)
    }

    /// Sweep-facing public alias for the by-hash height lookup used by Phase C's per-MARF
    /// classifier. Returns `Some(height)` if the chainstate's headers tables (Stacks 2.x or
    /// Nakamoto) know `index_block_hash`, `None` otherwise. C2a's classifier treats `None` as
    /// `RowVerdict::UnknownSkip` — conservative skip, never orphan.
    ///
    /// Thin wrapper over the private [`Self::lookup_height_and_parent`]; exists so
    /// `hot_reclaim::sweep_unlinkable_hot_files` (which lives outside `db/mod.rs`) can build a
    /// height-lookup closure without reaching into a private method.
    pub(crate) fn block_height_for_sweep(
        conn: &Connection,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<u32>, Error> {
        Self::lookup_height_and_parent(conn, index_block_hash).map(|opt| opt.map(|(h, _)| h))
    }

    fn precompute_canonical_ancestors(
        conn: &Connection,
        tip: &StacksBlockId,
        tip_height: u32,
        low_height: u32,
    ) -> Result<HashMap<u32, StacksBlockId>, Error> {
        if low_height > tip_height {
            return Ok(HashMap::new());
        }
        let walk_steps = tip_height.saturating_sub(low_height).saturating_add(1) as usize;
        let mut map = HashMap::with_capacity(walk_steps);
        let mut current = tip.clone();
        for _ in 0..walk_steps {
            let Some((height, parent)) = Self::lookup_height_and_parent(conn, &current)? else {
                // Truncated ancestry — return whatever we've built so far. The per-MARF detector
                // treats unmapped heights as "skip"; callers that need a fatal signal here will see
                // it on the actual read path downstream.
                break;
            };
            if height < low_height {
                break;
            }
            map.insert(height, current);
            if parent.as_bytes() == &[0u8; 32] {
                break;
            }
            current = parent;
        }
        Ok(map)
    }

    /// Walk the given Stacks tip's ancestry and compare each ancestor at heights inside the most
    /// recent squash level's range against the canonical chain the headers MARF's squash committed
    /// to.
    ///
    /// Returns:
    /// - `Ok(None)` — ancestry is aligned with the squash, OR no squash exists, OR the tip
    ///   pre-dates the level's range.
    /// - `Ok(Some(SquashDivergence))` — the new tip's ancestor at some height in the level's range
    ///   differs from what the squash recorded as canonical. Descendants of this tip will read
    ///   stale state through the merged blob (the bug class observed at level 11). Caller should
    ///   either re-squash that level or fail-stop.
    ///
    /// Implementation: precompute a `height -> canonical` map for the headers MARF level's range,
    /// then delegate the in-range comparison to
    /// [`MARF::detect_divergence`](crate::chainstate::stacks::index::marf::MARF::detect_divergence).
    ///
    /// **Headers-MARF only.** With per-MARF cadence (Step 6), headers and Clarity squash
    /// independently, so a Clarity-MARF divergence is no longer guaranteed to surface here.
    /// This method stays as a focused public probe (used by tests and by the `re_anchors_divergent_parent`
    /// regression); the production recovery path goes through [`Self::assert_squash_consistency`],
    /// which runs detection on **both** MARFs against a shared precomputed canonical map.
    pub fn detect_squash_divergence(
        &self,
        new_tip: &StacksBlockId,
    ) -> Result<Option<SquashDivergence>, Error> {
        let Some(level) = self.state_index.latest_squash_level_canonical_chain() else {
            return Ok(None);
        };
        let conn = self.db();
        let Some((tip_height, _)) = Self::lookup_height_and_parent(conn, new_tip)? else {
            // Tip not in headers tables at all — can't compare ancestry.
            // Older walker treated this as "no detectable divergence"; preserve.
            return Ok(None);
        };
        let map =
            Self::precompute_canonical_ancestors(conn, new_tip, tip_height, level.min_height)?;
        Ok(self.state_index.detect_divergence(
            |h: u32| -> Result<Option<StacksBlockId>, marf_error> { Ok(map.get(&h).cloned()) },
        )?)
    }

    /// Run divergence detection on the just-advanced tip. With per-MARF cadence (Step 6),
    /// headers and Clarity squash independently — their level structures are no longer
    /// guaranteed to align — so detection runs separately for each MARF.
    ///
    /// The shared work is the precompute: a single `precompute_canonical_ancestors` walk covering
    /// the union of both MARFs' level ranges builds one `height -> canonical` map that backs each
    /// MARF's `detect_divergence` closure.
    ///
    /// Returns `Ok(())` if the chain's view of canonical history is consistent.
    ///
    /// **Fail-stop on any divergence (B6.1).** Pre-B6.1 this function attempted automatic
    /// recovery via the live-handle `MARF::re_squash` method when divergence was detected
    /// without committed above-level descendants, and panicked when descendants blocked
    /// recovery. Both branches are gone. Horizon-gated promotion (Phase B) makes divergence
    /// unreachable on hot-tier MARFs by design; on legacy hot-tier-disabled MARFs there is
    /// no in-process recovery path, so any detection panics with the operator-recovery
    /// message ("wipe and re-sync"). See the function body for the per-MARF panic message
    /// and rationale.
    pub fn assert_squash_consistency(
        &mut self,
        new_tip: &StacksBlockId,
        sortdb_conn: &Connection,
    ) -> Result<(), Error> {
        let _ = sortdb_conn; // historical API param; unused after B6.1 deletions

        // Phase D (2026-05-04): the `assert_squash_consistency_with_prospective` variant + the
        // two pre-append callers (Nakamoto + 2.x staging) were deleted alongside the legacy
        // squash-on-tip path. Hot tier is non-optional + horizon-gated promotion makes squash
        // divergence below the burnchain reorg horizon unreachable on every MARF, so the
        // pre-append "leading-edge divergence" case the variant existed to catch can no longer
        // happen. This function remains as the post-append tripwire invoked by the coordinator
        // for the >horizon-reorg edge case (operator-recovery: wipe + re-sync).

        // Resolve tip height once. If the tip isn't recorded in either headers table, treat as
        // "no detectable divergence" — same conservative behavior as the legacy walker.
        let tip_height = match Self::lookup_height_and_parent(self.db(), new_tip)? {
            Some((h, _)) => h,
            None => return Ok(()),
        };

        // Compute the precompute window's lower bound: the earliest height covered by either
        // MARF's most-recent active level. Use `latest_squash_level_range` (NOT
        // `_canonical_chain`) so stub levels — which mark a height boundary even though they have
        // no canonical-chain payload — still anchor the precompute. If neither MARF has a level,
        // there's nothing to diverge against.
        let h_min = self
            .state_index
            .latest_squash_level_range()
            .map(|r| r.min_height);
        let c_min = self
            .clarity_state
            .with_marf(|m| m.latest_squash_level_range())
            .map(|r| r.min_height);
        let low_height = match (h_min, c_min) {
            (Some(h), Some(c)) => h.min(c),
            (Some(h), None) => h,
            (None, Some(c)) => c,
            (None, None) => return Ok(()),
        };

        // Single tip-walk shared between both MARFs' divergence probes.
        let canonical_map =
            Self::precompute_canonical_ancestors(self.db(), new_tip, tip_height, low_height)?;

        // --- Headers MARF: detect + fail-stop on divergence ---
        //
        // Detection: closure-backed `MARF::detect_divergence` against the precomputed map.
        // Cost: O(level_span) HashMap lookups, microseconds.
        //
        // Under horizon-gated promotion (Phase B), divergence is unreachable on hot-tier
        // MARFs, so the panic below is dead code by design. On a legacy hot-tier-disabled
        // MARF it remains the correctness gate — divergence here means the chain reorged
        // across a published squash boundary and reads through subsequent commits decode
        // garbage from the wrong blob (the level-14 mainnet panic's downstream symptom).
        let headers_div = self.state_index.detect_divergence(
            |h: u32| -> Result<Option<StacksBlockId>, marf_error> {
                Ok(canonical_map.get(&h).cloned())
            },
        )?;
        if let Some(div) = headers_div {
            let msg = format!(
                "Headers MARF squash divergence detected at level_id={}: recorded {} as \
                 canonical at height {}, chain has reorg'd to {}. \
                 Recovery is unsupported: the in-process `re_squash` mechanism was \
                 removed in B6.1 because horizon-gated promotion (Phase B) prevents \
                 divergence below the burnchain reorg horizon. This signal indicates \
                 either a legacy (hot-tier-disabled) MARF or an upstream bug. Operator \
                 must wipe the chainstate and re-sync from a peer.",
                div.level_id, div.recorded_canonical, div.diverging_height, div.new_canonical,
            );
            error!("{msg}");
            panic!(
                "FATAL: headers MARF squash divergence — chainstate is unrecoverable, \
                 operator must wipe and re-sync.\n{msg}"
            );
        }

        // --- Clarity MARF: detect + fail-stop on divergence ---
        //
        // Same precomputed map; we probe the Clarity MARF independently. Same fail-stop
        // rationale as the headers branch above.
        let clarity_div = self
            .clarity_state
            .with_marf(|m| m.detect_divergence(|h: u32| Ok(canonical_map.get(&h).cloned())))?;
        if let Some(div) = clarity_div {
            let msg = format!(
                "Clarity MARF squash divergence detected at level_id={}: recorded {} as \
                 canonical at height {}, chain has reorg'd to {}. \
                 Recovery is unsupported: the in-process `re_squash` mechanism was \
                 removed in B6.1 because horizon-gated promotion (Phase B) prevents \
                 divergence below the burnchain reorg horizon. This signal indicates \
                 either a legacy (hot-tier-disabled) MARF or an upstream bug. Operator \
                 must wipe the chainstate and re-sync from a peer.",
                div.level_id, div.recorded_canonical, div.diverging_height, div.new_canonical,
            );
            error!("{msg}");
            panic!(
                "FATAL: Clarity MARF squash divergence — chainstate is unrecoverable, \
                 operator must wipe and re-sync.\n{msg}"
            );
        }

        Ok(())
    }

    /// Check whether automatic MARF squash should run at this block height and, if so, squash both
    /// the headers MARF and the Clarity MARF.
    ///
    /// **Dev-only / experimental** — crash recovery is not yet implemented.
    ///
    /// Cadence is per-MARF and policy-driven via [`Self::squash_cadence_headers`] /
    /// [`Self::squash_cadence_clarity`]. Each MARF's predicate is evaluated independently against
    /// its own [`MARF::stats`] and height-span past the latest squash level. The default
    /// configuration runs headers on `fixed_cadence(MARF_SQUASH_CADENCE_BLOCKS)` (block-aligned,
    /// matching the legacy first-fire boundary) and Clarity on the work-aware `default_clarity()`
    /// policy (64 MiB / 100..2000 blocks) so the heavy MARF gets pause- amplitude smoothing on real
    /// workloads.
    ///
    /// * `block_height` is the chainstate's just-advanced canonical tip height (used for the
    ///   per-MARF height-span derivation `tip_height - latest_level.max_height`).
    /// * `canonical_tip` is the `index_block_hash` of that block — passed through to
    ///   `squash_level_incremental_with_canonical_tip` so the squash anchors to the chainstate's
    ///   canonical view at squash time. Without this, `find_tip_block`'s MARF-block-id heuristic
    ///   can pick a non-canonical sibling during fresh sync (when multiple competing tips exist at
    ///   the cadence boundary), causing the squash to record a non-canonical chain and triggering
    ///   spurious divergence detection on the next block.
    /// * `sortdb_conn` is a connection to the sortition database, used to resolve the epoch 3.4
    ///   burn-height boundary for mode selection. **B5d-fu.2**: drain finished detached promotion
    ///   workers and run the post-promotion bookkeeping (`refresh_after_squash` + `trim_sidecars`)
    ///   for any that completed since the last call.
    ///
    /// Idempotent: a `None` slot or an `is_finished() == false` handle is skipped without
    /// contention. Called at the top of [`Self::maybe_squash`] so polling happens at every cadence
    /// tick; can also be called explicitly (e.g. before chainstate shutdown) to reap workers in
    /// flight when block processing pauses.
    ///
    /// **Worker panics are fatal**: a panicked worker indicates a soundness bug in the promotion
    /// path (e.g. a torn write the swap protocol didn't catch). Continuing after such a panic risks
    /// observable corruption — the coordinator `resume_unwind`s onto its own thread, matching the
    /// policy B5d's `thread::scope` dispatch enforced via the same mechanism.
    /// Reap finished promotion workers and run the publish gate for any plan(s) on disk.
    ///
    /// **Canonical view source: chainstate-tip-anchored, NOT sortdb-anchored.** The publish
    /// gate must validate against the same canonical chain
    /// [`Self::assert_squash_consistency`] uses for divergence detection — that's the
    /// chainstate's just-advanced canonical tip walked back through the headers tables. Using
    /// `SortitionDB::get_canonical_stacks_chain_tip_hash_and_height` here would query a
    /// different source (the sortition's view of canonical, latest-data-known-to-the-node)
    /// which can disagree with the chainstate's just-advanced tip during block processing
    /// and let a stale plan slip through the gate only to trip divergence later.
    ///
    /// `canonical_tip` and `tip_height` are the values the coordinator passes to
    /// [`Self::maybe_squash`], i.e. the StacksBlockId / height of the block whose receipt
    /// just triggered this call.
    pub fn poll_pending_promotions(
        &mut self,
        canonical_tip: &StacksBlockId,
        tip_height: u32,
    ) -> PromotionsReaped {
        use crate::chainstate::stacks::db::headers::HeadersCanonicalView;
        use crate::chainstate::stacks::index::squash_promote::apply_prepared_plan;
        use crate::chainstate::stacks::index::squash_recover::{DrainOutcome, DrainPolicy};

        let retention_blocks = self.squash_sidecar_retention_blocks;
        let mut reaped = PromotionsReaped::default();

        // Phase 1: join finished workers. Empty slots and workers still in flight are skipped
        // without contention.
        let headers_prepared = Self::join_finished_prepare(&mut self.headers_promotion_handle);
        let clarity_prepared = Self::join_finished_prepare(&mut self.clarity_promotion_handle);

        // Phase 2: collect publish work for this tick. We need to handle three sources:
        //   1. A worker just returned a fresh `PreparedPromotion` — fast path via
        //      `apply_prepared_plan` (skips integrity re-hashing of bytes the worker just
        //      wrote).
        //   2. A plan file is on disk that the prior tick's `apply_prepared_plan` failed to
        //      publish (transient SQL/IO error, etc.) — fall back to `drain_pending_plans`,
        //      which re-runs integrity checks then publishes under the same canonical gate.
        //   3. Orphan plans on disk from a previous worker that the coordinator never reaped
        //      (e.g., process crash between worker join and publish) — also drained.
        //
        // Both #2 and #3 go through `MARF::drain_pending_plans(Canonical(view))`, so a
        // transient failure on tick N is recovered on tick N+1 without requiring a process
        // restart.
        let headers_path = self.state_index.get_db_path().to_string();
        let clarity_path = self
            .clarity_state
            .with_marf(|m| m.get_db_path().to_string());
        let pending_paths: [&str; 2] = [headers_path.as_str(), clarity_path.as_str()];

        // Compute the canonical-view walk bound. Use the lowest height across all sources so
        // every `(min_height + i)` covered by any plan in this tick can be validated.
        let low_height_from_prepared = match (
            headers_prepared
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .and_then(|m| m.as_ref()),
            clarity_prepared
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .and_then(|m| m.as_ref()),
        ) {
            (Some(h), Some(c)) => Some(h.min_height.min(c.min_height)),
            (Some(h), None) => Some(h.min_height),
            (None, Some(c)) => Some(c.min_height),
            (None, None) => None,
        };
        // `lowest_pending_plan_height` propagates hard errors (corrupt plan file, IO failure on
        // the plan-discovery glob). We MUST NOT swallow those — silently treating an unreadable
        // plan as "no orphans on disk" lets a stuck failure go undetected indefinitely. Surface
        // the error loudly and bail the tick; the next tick will hit the same condition until
        // the operator (or a restart's `StacksChainState::recover`) clears it. We also peek
        // `discover_pending_plans` separately so we can distinguish "no plans" from "lowest is
        // genesis (height 0)" without ambiguity.
        let pending_paths_have_plans = pending_paths.iter().any(|p| {
            crate::chainstate::stacks::index::squash_plan::discover_pending_plans(p)
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        });
        let low_height_from_disk = if pending_paths_have_plans {
            match HeadersCanonicalView::lowest_pending_plan_height(&pending_paths) {
                Ok(h) => Some(h),
                Err(e) => {
                    warn!(
                        "Auto-squash (hot-tier, detached): pending-plan scan failed: {e}; \
                         deferring publish for this tick (plans remain durable on disk; if \
                         this persists, operator must inspect — recovery on restart will hit \
                         the same condition)"
                    );
                    return reaped;
                }
            }
        } else {
            None
        };
        let low_height = match (low_height_from_prepared, low_height_from_disk) {
            (Some(p), Some(d)) => p.min(d),
            (Some(p), None) => p,
            (None, Some(d)) => d,
            (None, None) => {
                // No prepared from workers, no orphan plans on disk. Nothing to publish.
                return reaped;
            }
        };
        let canonical_view = match HeadersCanonicalView::from_chainstate_tip(
            self.state_index.sqlite_conn(),
            canonical_tip,
            tip_height,
            low_height,
        ) {
            Ok(view) => Some(view),
            Err(e) => {
                warn!(
                    "Auto-squash (hot-tier, detached): canonical view build failed: {e}; \
                     deferring publish (plans remain durable on disk for next tick or restart \
                     recovery)"
                );
                return reaped;
            }
        };

        // `DrainPolicy<'_>` borrows `&dyn CanonicalView`, which can't be `Clone`d. The
        // underlying `canonical_view` is owned, so we re-build the policy at each call site.
        // (Inlined rather than factored into a closure because closure lifetime inference
        // doesn't tie the input lifetime to the output `DrainPolicy<'_>` cleanly.)

        // Per-arm publish tracking. We separate "published via apply (already refreshed
        // internally)" from "published via drain (drain doesn't refresh — coordinator must)"
        // so the duplicate `refresh_after_squash` on the fast path is gone: refresh fires
        // exactly once per published level, on the path that didn't already refresh.
        let mut headers_published_via_apply = false;
        let mut headers_published_via_drain = false;
        if let Some(Ok(Some(prepared))) = headers_prepared {
            let policy = match canonical_view.as_ref() {
                Some(v) => DrainPolicy::Canonical(v),
                None => DrainPolicy::TrustPlan,
            };
            match apply_prepared_plan(&mut self.state_index, &prepared, policy) {
                Ok(DrainOutcome::Published { .. }) => {
                    headers_published_via_apply = true;
                }
                Ok(DrainOutcome::DiscardedStale { .. }) | Ok(DrainOutcome::Abandoned { .. }) => {
                    // Outcome logged inside `apply_prepared_plan`.
                }
                Err(e) => warn!(
                    "Auto-squash (hot-tier, detached): headers apply_prepared_plan failed: \
                     {e} (drain fallback will retry under canonical gate)"
                ),
            }
        }
        let headers_drain_policy = match canonical_view.as_ref() {
            Some(v) => DrainPolicy::Canonical(v),
            None => DrainPolicy::TrustPlan,
        };
        match self.state_index.drain_pending_plans(headers_drain_policy) {
            Ok(stats) if stats.plans_committed() > 0 => {
                headers_published_via_drain = true;
            }
            Ok(_) => {}
            Err(e) => warn!(
                "Auto-squash (hot-tier, detached): headers drain_pending_plans failed: {e} \
                 (plans remain on disk for next tick or restart recovery)"
            ),
        }
        if headers_published_via_apply || headers_published_via_drain {
            reaped.headers_promoted = true;
            // Refresh ONLY if the drain path was what published. `apply_prepared_plan` already
            // refreshes internally on success — refreshing again here was wasted SQL + mmap
            // work on every successful runtime publish.
            if headers_published_via_drain {
                if let Err(e) = self.state_index.refresh_after_squash() {
                    warn!(
                        "Auto-squash (hot-tier, detached): headers refresh_after_squash \
                         (post-drain) failed: {e}"
                    );
                }
            }
            if let Err(e) = self.state_index.trim_sidecars(retention_blocks) {
                warn!("Auto-squash (hot-tier, detached): headers MARF sidecar trim failed: {e}");
            }
        }

        // Clarity arm: same pattern, on the clarity MARF.
        let mut clarity_published_via_apply = false;
        let mut clarity_published_via_drain = false;
        if let Some(Ok(Some(prepared))) = clarity_prepared {
            let policy = match canonical_view.as_ref() {
                Some(v) => DrainPolicy::Canonical(v),
                None => DrainPolicy::TrustPlan,
            };
            let outcome = self
                .clarity_state
                .with_marf(|m| apply_prepared_plan(m, &prepared, policy));
            match outcome {
                Ok(DrainOutcome::Published { .. }) => {
                    clarity_published_via_apply = true;
                }
                Ok(DrainOutcome::DiscardedStale { .. }) | Ok(DrainOutcome::Abandoned { .. }) => {}
                Err(e) => warn!(
                    "Auto-squash (hot-tier, detached): clarity apply_prepared_plan failed: \
                     {e} (drain fallback will retry under canonical gate)"
                ),
            }
        }
        let clarity_drain_policy = match canonical_view.as_ref() {
            Some(v) => DrainPolicy::Canonical(v),
            None => DrainPolicy::TrustPlan,
        };
        let clarity_drain_result = self
            .clarity_state
            .with_marf(|m| m.drain_pending_plans(clarity_drain_policy));
        match clarity_drain_result {
            Ok(stats) if stats.plans_committed() > 0 => {
                clarity_published_via_drain = true;
            }
            Ok(_) => {}
            Err(e) => warn!(
                "Auto-squash (hot-tier, detached): clarity drain_pending_plans failed: {e} \
                 (plans remain on disk for next tick or restart recovery)"
            ),
        }
        if clarity_published_via_apply || clarity_published_via_drain {
            reaped.clarity_promoted = true;
            // Same refresh discipline as headers: only refresh if drain was the publisher.
            self.clarity_state.with_marf(|m| {
                if clarity_published_via_drain {
                    if let Err(e) = m.refresh_after_squash() {
                        warn!(
                            "Auto-squash (hot-tier, detached): clarity refresh_after_squash \
                             (post-drain) failed: {e}"
                        );
                    }
                }
                if let Err(e) = m.trim_sidecars(retention_blocks) {
                    warn!(
                        "Auto-squash (hot-tier, detached): clarity MARF sidecar trim \
                         failed: {e}"
                    );
                }
            });
        }

        reaped
    }

    /// Helper: try-join one prepare-worker slot. Returns:
    /// - `None` if the slot is empty or the worker is still running (`is_finished() == false`).
    /// - `Some(Ok(Some(prepared)))`: worker finished, prepare succeeded; coordinator should
    ///   validate + publish.
    /// - `Some(Ok(None))`: worker finished, but on-disk state is post-recovery; coordinator
    ///   should not publish anything new (the next cadence tick re-dispatches if needed).
    /// - `Some(Err(e))`: worker's prepare returned an error; coordinator skips publish this
    ///   tick. The plan file (if any) remains on disk for next-open recovery.
    ///
    /// `resume_unwind`s on worker thread panic — a panicked prepare worker indicates a
    /// soundness bug; continuing risks observable corruption.
    fn join_finished_prepare(
        slot: &mut Option<PromotionTaskHandle>,
    ) -> Option<
        Result<
            Option<crate::chainstate::stacks::index::squash_promote::PreparedPromotion>,
            marf_error,
        >,
    > {
        let needs_drain = slot.as_ref().is_some_and(|h| h.join_handle.is_finished());
        if !needs_drain {
            return None;
        }
        let handle = slot.take()?;
        let label = handle.label;
        match handle.join_handle.join() {
            Ok(result) => {
                match &result {
                    Ok(Some(p)) => info!(
                        "Auto-squash (hot-tier, detached): {label} prepare worker finished: \
                         level_id={} range=[{}..={}]",
                        p.level_id, p.min_height, p.max_height,
                    ),
                    Ok(None) => info!(
                        "Auto-squash (hot-tier, detached): {label} prepare worker finished: \
                         nothing to publish (post-recovery state)"
                    ),
                    Err(e) => warn!(
                        "Auto-squash (hot-tier, detached): {label} prepare worker errored: {e}"
                    ),
                }
                Some(result)
            }
            Err(panic) => {
                error!(
                    "Auto-squash (hot-tier, detached): {label} prepare worker thread panicked. \
                     Resuming unwind on coordinator (panic propagates as fatal)."
                );
                std::panic::resume_unwind(panic);
            }
        }
    }

    /// Phase C sweep dispatch: invoke the per-MARF hot-reclaim sweep loop on each MARF whose
    /// detached promotion worker just finished (per `reaped`). Shares a single canonical-chain
    /// precompute + horizon max-height across both MARFs since both anchor to the same Stacks
    /// canonical chain (per-MARF dispatch in [phase-c §4.1](../../../.docs/squashing-v1.5-phase-c.md)).
    ///
    /// Best-effort by design: a sweep failure on one MARF logs + continues to the other. Sweep
    /// failure is never fatal at the chainstate level — Phase C is purely additive (per the §11
    /// risk note: a missed sweep leaks disk, never corrupts).
    fn sweep_after_promotions(
        &mut self,
        canonical_tip: &StacksBlockId,
        sortdb_conn: &Connection,
        reaped: PromotionsReaped,
    ) {
        if !reaped.any_promoted() {
            return;
        }

        // Look up the canonical tip's height. Without it we can't bound the canonical-chain walk.
        // If the tip isn't in headers — shouldn't happen post-promotion but defensively — skip.
        let tip_height = match Self::block_height_for_sweep(self.db(), canonical_tip) {
            Ok(Some(h)) => h,
            Ok(None) => {
                warn!(
                    "hot-reclaim sweep: canonical tip {canonical_tip} not in chainstate headers; \
                     skipping sweep this trigger"
                );
                return;
            }
            Err(e) => {
                warn!("hot-reclaim sweep: tip height lookup failed: {e}; skipping sweep");
                return;
            }
        };

        // Horizon predicate. `None` means horizon hasn't been established yet — C2a treats that as
        // "all orphans retained" (conservative), so the sweep can still safely run; an absent
        // horizon just means no past-horizon orphans contribute.
        //
        // The sweep must not unlink orphans that any *future* squash level would still need.
        // The smallest possible `min_height` for any future level across both MARFs is the
        // smaller of `headers_latest_max + 1` and `clarity_latest_max + 1` (or `0` if a MARF
        // has no levels yet). Using that bound — rather than a hardcoded `0` — lets the sweep
        // get progressively tighter horizons as the chain advances past noisy 2.x epochs:
        // a node already past Nakamoto activation has `min_height` solidly in epoch 3.0+
        // territory, so the per-epoch resolver returns the small Nakamoto floor (6) instead
        // of being permanently pinned to the worst 2.x floor.
        let horizon_blocks = self.squash_horizon_burn_blocks;
        let sweep_min_height = std::cmp::min(
            Self::squash_min_height_for(&self.state_index),
            self.clarity_state
                .with_marf(|m| Self::squash_min_height_for_marf(m)),
        );
        let horizon_max_height = compute_per_epoch_horizon_gated_max_height(
            self.db(),
            sortdb_conn,
            canonical_tip,
            sweep_min_height,
            horizon_blocks,
        )
        .ok()
        .flatten();

        // Build the canonical-chain precompute. `low_height = 0` is conservative — covers any
        // reasonably-aged orphan. The walk is O(tip_height + 1); cheap relative to the per-MARF
        // sweep work.
        let canonical_chain =
            match crate::chainstate::stacks::index::hot_reclaim::canonical_chain_for_sweep(
                self.db(),
                canonical_tip,
                tip_height,
                0,
            ) {
                Ok(map) => map,
                Err(e) => {
                    warn!(
                        "hot-reclaim sweep: canonical-chain precompute failed: {e}; skipping sweep"
                    );
                    return;
                }
            };

        let quiesce_timeout =
            crate::chainstate::stacks::index::hot_reclaim::DEFAULT_APPLY_UNLINKABLE_QUIESCE_TIMEOUT;

        // Headers MARF arm. The headers MARF's marf_data table lives in the SAME sqlite as the
        // chainstate's `block_headers` / `nakamoto_block_headers` (this is the chainstate sqlite).
        // So `marf_conn` returned by `sweep_borrows` IS the chainstate connection — we use it for
        // both the sweep's marf_data ops AND the height-lookup callback, no aliasing.
        if reaped.headers_promoted {
            let headers_storage = self.state_index.storage_backend_mut();
            let result = if let Some((marf_conn, hot_files)) = headers_storage.sweep_borrows() {
                let height_lookup = |bid: &StacksBlockId| -> Result<
                    Option<u32>,
                    crate::chainstate::stacks::index::Error,
                > {
                    Self::block_height_for_sweep(marf_conn, bid).map_err(|e| {
                        crate::chainstate::stacks::index::Error::CorruptionError(format!(
                            "hot-reclaim sweep height lookup: {e}"
                        ))
                    })
                };
                // Phase D D4b: record sweep-window duration into
                // `stacks_node_marf_sweep_window_duration_seconds{marf="headers"}`. Timer fires
                // on Drop so the elapsed time lands regardless of Ok/Err. No-op when the
                // monitoring_prom feature is off.
                crate::monitoring::with_marf_sweep_window_timer("headers", || {
                    crate::chainstate::stacks::index::hot_reclaim::sweep_unlinkable_hot_files(
                        hot_files,
                        marf_conn,
                        &canonical_chain,
                        horizon_max_height,
                        height_lookup,
                        quiesce_timeout,
                    )
                })
            } else {
                // Headers MARF wasn't opened with hot tier enabled — nothing to sweep + no
                // metric sample (recording 0ms here would pollute the per-call distribution).
                Ok(crate::chainstate::stacks::index::hot_reclaim::SweepStats::default())
            };
            match result {
                Ok(stats) if stats.is_noteworthy() => info!(
                    "hot-reclaim sweep (headers): {} files unlinked, {} rows deleted, \
                     {} retained, {} blocked-by-closure, {} deferred-for-quiesce",
                    stats.files_unlinked,
                    stats.rows_deleted,
                    stats.files_retained_by_classifier,
                    stats.files_blocked_by_closure,
                    stats.files_deferred_for_quiesce,
                ),
                Ok(_) => {}
                Err(e) => warn!("hot-reclaim sweep (headers) failed: {e}"),
            }
        }

        // Clarity MARF arm. Clarity's marf_data lives in a DIFFERENT sqlite from the chainstate
        // headers tables, so the height-lookup closure needs the chainstate connection, captured
        // here via `self.state_index.sqlite_conn()` BEFORE `with_marf` borrows `self.clarity_state`.
        // Field-disjoint borrows: `&self.state_index` and `&mut self.clarity_state` don't overlap.
        if reaped.clarity_promoted {
            let chainstate_conn: &Connection = self.state_index.sqlite_conn();
            let canonical_chain_ref = &canonical_chain;
            let result = self.clarity_state.with_marf(|marf| {
                let storage = marf.storage_backend_mut();
                let Some((marf_conn, hot_files)) = storage.sweep_borrows() else {
                    return Ok(
                        crate::chainstate::stacks::index::hot_reclaim::SweepStats::default(),
                    );
                };
                let height_lookup = |bid: &StacksBlockId| -> Result<
                    Option<u32>,
                    crate::chainstate::stacks::index::Error,
                > {
                    Self::block_height_for_sweep(chainstate_conn, bid).map_err(|e| {
                        crate::chainstate::stacks::index::Error::CorruptionError(format!(
                            "hot-reclaim sweep height lookup: {e}"
                        ))
                    })
                };
                // Phase D D4b: record sweep-window duration into
                // `stacks_node_marf_sweep_window_duration_seconds{marf="clarity"}`.
                crate::monitoring::with_marf_sweep_window_timer("clarity", || {
                    crate::chainstate::stacks::index::hot_reclaim::sweep_unlinkable_hot_files(
                        hot_files,
                        marf_conn,
                        canonical_chain_ref,
                        horizon_max_height,
                        height_lookup,
                        quiesce_timeout,
                    )
                })
            });
            match result {
                Ok(stats) if stats.is_noteworthy() => info!(
                    "hot-reclaim sweep (clarity): {} files unlinked, {} rows deleted, \
                     {} retained, {} blocked-by-closure, {} deferred-for-quiesce",
                    stats.files_unlinked,
                    stats.rows_deleted,
                    stats.files_retained_by_classifier,
                    stats.files_blocked_by_closure,
                    stats.files_deferred_for_quiesce,
                ),
                Ok(_) => {}
                Err(e) => warn!("hot-reclaim sweep (clarity) failed: {e}"),
            }
        }
    }

    pub fn maybe_squash(
        &mut self,
        block_height: u64,
        canonical_tip: StacksBlockId,
        sortdb: &SortitionDB,
    ) {
        use std::thread;

        let sortdb_conn = sortdb.conn();
        let tip_height = block_height as u32;

        // Drain any previously-spawned detached prepare workers that finished since the last
        // cadence tick. This is the publish gate: `poll_pending_promotions` validates each
        // worker's prepared plan against the same canonical chain
        // `assert_squash_consistency` will later use — i.e., the chainstate's just-advanced
        // tip walked back through the headers tables. Threading `canonical_tip` + `tip_height`
        // here (instead of `&SortitionDB`) ensures the gate's view matches the divergence
        // detector's view; using the sortdb's `get_canonical_stacks_chain_tip_hash_and_height`
        // would query a different (latest-data-known-to-the-node) source that can disagree
        // during block processing and let stale plans slip through.
        //
        // Single-flight gating below depends on the slots being clear when a worker has
        // finished, so this MUST run before the dispatch logic.
        //
        // **Phase C C4**: capture which MARFs the poll just published, then run the
        // hot-reclaim sweep against them. The sweep happens here (not later in this method)
        // so the cadence early-return path still triggers the sweep on ticks where publish
        // finished but no *new* squash needs to fire. Sweep failures are logged + swallowed
        // inside `sweep_after_promotions` — Phase C is purely additive.
        let reaped = self.poll_pending_promotions(&canonical_tip, tip_height);
        if reaped.any_promoted() {
            self.sweep_after_promotions(&canonical_tip, sortdb_conn, reaped);
        }

        // `block_height` is currently informational only (the periodic skip-log line); the cadence
        // policy uses horizon-gated effective heights instead. Keep `_tip_height` as a named
        // binding for the diagnostic info!() below.
        let _tip_height = block_height as u32;

        // --- Phase 0: Per-MARF cadence predicate ---
        //
        // Headers and Clarity each have their own `SquashCadenceConfig`. By default headers runs on
        // `fixed_cadence(MARF_SQUASH_CADENCE_BLOCKS)` and Clarity on the work-aware
        // `default_clarity()` policy. Compute height-span from each MARF's latest level and consult
        // `should_squash`.
        //
        // Bootstrap boundary: when no level exists yet, `blocks_since = tip_height` (NOT
        // `tip_height + 1`). The legacy fixed-cadence gate fired the first squash at `block_height
        // == cadence` (e.g. height 1000 for the default), spanning heights `[0..=1000]` — that's
        // 1001 committed blocks but `tip_height = 1000`. Using `tip_height` here lines up the
        // predicate's `>= max_blocks` check with the legacy fire point bit-for- bit. After that
        // first squash, `latest_level.max_height = tip_height`, so subsequent calls take the `Some`
        // branch and the same `tip - max_height` math drives the cadence.
        //
        // **B5c**: per-MARF blocks_since is computed below using `effective_height_for(hot_tier)`
        // so hot-tier MARFs measure cadence against the horizon-gated max-height, not the chain
        // tip. The `tip_height`-based defaults are preserved verbatim for legacy MARFs (hot tier
        // off → effective_height == tip_height).

        let headers_stats = self.state_index.stats();
        let clarity_stats = self.clarity_state.with_marf(|m| m.stats());

        // v1.5 Phase B horizon predicate + dispatch (B5c).
        //
        // Per design doc §3, horizon gating applies *only* to MARFs opened with hot tier enabled.
        // Legacy MARFs keep today's cadence behavior bit-for-bit (always-true horizon closure).
        // Hot-tier MARFs dispatch through `run_horizon_gated_promotion` on the live MARF, bypassing
        // the legacy thread::scope path entirely.
        //
        // Phase D (2026-05-04): hot tier is non-optional. The cadence policy below uses the
        // **horizon-gated effective height** for both MARFs unconditionally; the legacy "tip
        // height for non-hot-tier MARFs" branch + the `PROMOTION_DRIVER_READY` staging flag from
        // B5c were removed since every disk-backed MARF now goes through the hot-tier path.
        let horizon_blocks = self.squash_horizon_burn_blocks;

        // Compute horizon-gated max_height **per MARF** under the per-epoch horizon schedule.
        // Each MARF's prospective level has its own `min_height` (the previous level's
        // `max_height + 1`, or `0` for the first squash), and the effective horizon depends on
        // which epochs the candidate range `[min_height..=max_height]` overlaps. See
        // [`StacksChainState::epoch_horizon_floor`] for the schedule + rationale, and
        // [`compute_per_epoch_horizon_gated_max_height`] for the walk.
        //
        // `None` means "no canonical block on the chain yet satisfies the per-epoch predicate"
        // — typically chain too short, or `burn_at(min_height)` not yet in `block_headers`.
        let headers_min_height = Self::squash_min_height_for(&self.state_index);
        let clarity_min_height = self
            .clarity_state
            .with_marf(|m| Self::squash_min_height_for_marf(m));

        let headers_horizon_max_height = compute_per_epoch_horizon_gated_max_height(
            self.db(),
            sortdb_conn,
            &canonical_tip,
            headers_min_height,
            horizon_blocks,
        )
        .ok()
        .flatten();
        let clarity_horizon_max_height = compute_per_epoch_horizon_gated_max_height(
            self.db(),
            sortdb_conn,
            &canonical_tip,
            clarity_min_height,
            horizon_blocks,
        )
        .ok()
        .flatten();

        // Per-MARF blocks_since uses the horizon-gated effective height (the height of the
        // prospective squash range), so the cadence policy (`min_blocks` / `max_blocks` /
        // `work_target_bytes`) applies to the actual range that would be promoted.
        let headers_effective_height = headers_horizon_max_height.unwrap_or(0);
        let clarity_effective_height = clarity_horizon_max_height.unwrap_or(0);
        let headers_blocks_since = self
            .state_index
            .latest_squash_level_range()
            .map(|r| headers_effective_height.saturating_sub(r.max_height))
            .unwrap_or(headers_effective_height);
        let clarity_blocks_since = self
            .clarity_state
            .with_marf(|m| m.latest_squash_level_range())
            .map(|r| clarity_effective_height.saturating_sub(r.max_height))
            .unwrap_or(clarity_effective_height);

        // Per-MARF horizon closure for `should_squash`: pass iff that MARF's per-epoch
        // horizon-gated max height was computable.
        let headers_horizon_check = || headers_horizon_max_height.is_some();
        let clarity_horizon_check = || clarity_horizon_max_height.is_some();

        let headers_should_squash = should_squash(
            &headers_stats,
            headers_blocks_since,
            &self.squash_cadence_headers,
            headers_horizon_check,
        );
        let clarity_should_squash = should_squash(
            &clarity_stats,
            clarity_blocks_since,
            &self.squash_cadence_clarity,
            clarity_horizon_check,
        );

        if !headers_should_squash && !clarity_should_squash {
            if block_height % 10_000 == 0 {
                info!(
                    "maybe_squash: skipping height {block_height} \
                     (headers_blocks_since={headers_blocks_since}, \
                      clarity_blocks_since={clarity_blocks_since})"
                );
            }
            return;
        }

        info!(
            "maybe_squash: TRIGGERED at height {block_height} \
             (headers={headers_should_squash}, clarity={clarity_should_squash})"
        );

        // --- v1.5 Phase B (B5c+B5d-fu.2) — detached dispatch ---
        //
        // Promotion runs on a detached worker thread (`thread::Builder::spawn`). The coordinator
        // returns immediately after spawning so block processing isn't blocked on the worker's
        // background phase. On the NEXT `maybe_squash` tick, `poll_pending_promotions` (called at
        // the top of this method) reaps any worker that finished since the last call and runs
        // `refresh_after_squash` + `trim_sidecars` + `sweep_after_promotions` (Phase C) for that
        // MARF.
        //
        // Single-flight per MARF: `headers_promotion_handle` / `clarity_promotion_handle` slots
        // are populated below. While `Some`, the MARF is skipped here — the cadence policy will
        // re-fire on a subsequent block once the worker has been reaped.
        //
        // Concurrency surface: each worker opens its own `MARF<T>::from_path` handle, so it does
        // NOT compete with the coordinator's `state_index` on the storage state. Cross-handle
        // observability of the worker's swap-phase pwrites is mediated by the process-wide
        // ReaderFence registry (B5d cross-handle fence) and the shared squash-state generation
        // bump.
        let headers_already_running = self.headers_promotion_handle.is_some();
        let clarity_already_running = self.clarity_promotion_handle.is_some();

        // Resolve the operator-configured squash mode and run it through
        // `effective_squash_mode`. Two safety properties matter here:
        //
        // 1. **Operator intent is preserved.** Operators set `marf_full_history = true` (TOML)
        //    when they want `FullHistory` regardless of epoch — e.g. an indexer that needs
        //    historical reads against any past height. Reading the configured mode from
        //    `self.marf_opts` (populated at chainstate-open time from `MARFOpenOpts.squash_mode`)
        //    keeps that intent intact through worker dispatch.
        //
        // 2. **Pre-epoch-3.4 ranges are forced to `FullHistory`.** Even when the operator
        //    configured `TipOnly`, `effective_squash_mode` upgrades to `FullHistory` whenever
        //    the squash range starts pre-3.4, because Clarity `at-block` reads at any height
        //    inside such a range require per-height transitions. Without this upgrade, every
        //    pre-3.4 squash would corrupt historical reads at non-tip heights inside the level.
        //
        // Default is `TipOnly` if `marf_opts` is `None` (e.g. a programmatic chainstate handle
        // built without going through `Config::get_marf_opts`); the conservative default matches
        // the historical `MARFOpenOpts::default()` behavior.
        let configured_mode = self.configured_squash_mode();

        let headers_hot_plan = if headers_should_squash && !headers_already_running {
            let min_height = headers_min_height;
            let max_height = headers_horizon_max_height.unwrap_or(0);
            if max_height >= min_height {
                let mode = Self::effective_squash_mode(
                    configured_mode,
                    min_height,
                    self.db(),
                    sortdb_conn,
                );
                Some((
                    self.state_index.get_db_path().to_string(),
                    mode,
                    min_height,
                    max_height,
                ))
            } else {
                info!(
                    "Auto-squash: headers MARF skipping empty horizon-gated range \
                     ({min_height}..={max_height})"
                );
                None
            }
        } else {
            if headers_should_squash && headers_already_running {
                info!(
                    "Auto-squash: headers worker still in flight from a prior cadence tick; \
                     deferring this dispatch."
                );
            }
            None
        };
        let clarity_hot_plan = if clarity_should_squash && !clarity_already_running {
            let max_height = clarity_horizon_max_height.unwrap_or(0);
            let clarity_min = clarity_min_height;
            let clarity_path = self
                .clarity_state
                .with_marf(|m| m.get_db_path().to_string());
            if max_height >= clarity_min {
                let mode = Self::effective_squash_mode(
                    configured_mode,
                    clarity_min,
                    self.db(),
                    sortdb_conn,
                );
                Some((clarity_path, mode, clarity_min, max_height))
            } else {
                info!(
                    "Auto-squash: clarity MARF skipping empty horizon-gated range \
                     ({clarity_min}..={max_height})"
                );
                None
            }
        } else {
            if clarity_should_squash && clarity_already_running {
                info!(
                    "Auto-squash: clarity worker still in flight from a prior cadence tick; \
                     deferring this dispatch."
                );
            }
            None
        };

        // Detached spawn. `thread::Builder::spawn` returns `io::Result<JoinHandle<_>>`; on rare
        // spawn failure (e.g. resource exhaustion) we log and skip — the cadence will retry on the
        // next block.
        if let Some((path, mode, min_h, max_h)) = headers_hot_plan {
            let tip = canonical_tip.clone();
            match thread::Builder::new()
                .name("hot-tier-promote-headers".into())
                .spawn(move || {
                    run_hot_tier_promotion_worker("headers", &path, mode, min_h, max_h, tip)
                }) {
                Ok(join_handle) => {
                    self.headers_promotion_handle = Some(PromotionTaskHandle {
                        label: "headers",
                        path: self.state_index.get_db_path().to_string(),
                        join_handle,
                    });
                }
                Err(e) => {
                    warn!(
                        "Auto-squash (hot-tier, detached): failed to spawn headers worker: {e} \
                         (will retry next cadence tick)"
                    );
                }
            }
        }
        if let Some((path, mode, min_h, max_h)) = clarity_hot_plan {
            let tip = canonical_tip.clone();
            let clarity_path_for_handle = self
                .clarity_state
                .with_marf(|m| m.get_db_path().to_string());
            match thread::Builder::new()
                .name("hot-tier-promote-clarity".into())
                .spawn(move || {
                    run_hot_tier_promotion_worker("clarity", &path, mode, min_h, max_h, tip)
                }) {
                Ok(join_handle) => {
                    self.clarity_promotion_handle = Some(PromotionTaskHandle {
                        label: "clarity",
                        path: clarity_path_for_handle,
                        join_handle,
                    });
                }
                Err(e) => {
                    warn!(
                        "Auto-squash (hot-tier, detached): failed to spawn clarity worker: {e} \
                         (will retry next cadence tick)"
                    );
                }
            }
        }

        // --- Inline helper: hot-tier promotion **prepare** worker ---
        //
        // Returns the worker's prepared plan handle (or `None` if recovery published a level on
        // open and the live prepare's range was stale, or `Err` if prepare failed). The
        // coordinator's `poll_pending_promotions` reaps this on a later tick and runs the
        // canonical-validated publish step.

        /// Run the prepare phase of a hot-tier horizon-gated promotion for one MARF on a
        /// detached worker thread. Returns the prepared handle for the coordinator to validate
        /// + publish.
        fn run_hot_tier_promotion_worker(
            label: &'static str,
            path: &str,
            mode: SquashMode,
            min_height: u32,
            max_height: u32,
            canonical_tip: StacksBlockId,
        ) -> Result<
            Option<crate::chainstate::stacks::index::squash_promote::PreparedPromotion>,
            marf_error,
        > {
            info!(
                "Auto-squash (hot-tier): {label} MARF prepare \
                 [{min_height}..={max_height}] mode={mode:?} (canonical_tip={canonical_tip})"
            );
            let result = crate::chainstate::stacks::index::squash_promote::run_horizon_gated_promotion_at_path::<
                StacksBlockId,
            >(path, mode, min_height, max_height, Some(canonical_tip));
            match &result {
                Ok(Some(p)) => info!(
                    "Auto-squash (hot-tier): {label} MARF prepare complete: \
                     level_id={} translation_entries={} descendants_scanned={} \
                     rewrites_planned={}",
                    p.level_id,
                    p.stats.translation_map_entries,
                    p.stats.descendants_scanned,
                    p.stats.rewrites_planned,
                ),
                Ok(None) => info!(
                    "Auto-squash (hot-tier): {label} MARF prepare reported \
                     nothing-to-publish (post-recovery state)"
                ),
                Err(e) => warn!("Auto-squash (hot-tier): {label} MARF prepare failed: {e}"),
            }
            result
        }
    }

    fn squash_block_count(min_height: u32, tip_height: u32) -> Option<u64> {
        if min_height > tip_height {
            None
        } else {
            Some((tip_height as u64) - (min_height as u64) + 1)
        }
    }

    /// Determine the min_height for the next squash level by reading existing squash levels from
    /// the given MARF.
    fn squash_min_height_for(state_index: &MARF<StacksBlockId>) -> u32 {
        Self::squash_min_height_for_marf(state_index)
    }

    fn squash_min_height_for_marf(marf: &MARF<StacksBlockId>) -> u32 {
        use crate::chainstate::stacks::index::trie_sql;
        match trie_sql::read_squash_levels(marf.sqlite_conn()) {
            Ok(levels) => {
                if let Some(last) = levels.last() {
                    last.max_height + 1
                } else {
                    0
                }
            }
            Err(_) => 0,
        }
    }

    /// Determine the effective squash mode for a level whose range starts at `min_height` (a Stacks
    /// block height).
    ///
    /// Read the operator-configured squash mode (from `marf_full_history` in TOML, threaded
    /// through `MARFOpenOpts.squash_mode` at chainstate-open time).
    ///
    /// Returns `TipOnly` if `marf_opts` is `None` — that case only arises for programmatic
    /// chainstate handles built without going through `Config::get_marf_opts`, which preserves
    /// the historical `MARFOpenOpts::default()` behavior. Production node startup always
    /// populates `marf_opts`.
    pub(crate) fn configured_squash_mode(&self) -> SquashMode {
        Self::configured_squash_mode_from_opts(self.marf_opts.as_ref())
    }

    /// Static variant of [`Self::configured_squash_mode`] that operates on the raw
    /// `Option<&MARFOpenOpts>`. Exposed so unit tests can pin the resolution rule
    /// (operator-configured mode survives, default fallback is `TipOnly`) without standing up
    /// a full `StacksChainState` fixture. The instance method MUST stay a thin wrapper around
    /// this helper so production and tests exercise the same logic.
    pub(crate) fn configured_squash_mode_from_opts(opts: Option<&MARFOpenOpts>) -> SquashMode {
        opts.map(|o| o.squash_mode).unwrap_or(SquashMode::TipOnly)
    }

    /// Rules:
    /// - If the user configured `FullHistory`, always use `FullHistory`.
    /// - If the user configured `TipOnly`, force `FullHistory` when the range contains
    ///   pre-epoch-3.4 blocks (required for consensus-correct replay of `at-block`). Once the
    ///   entire range is post-3.4, honour the `TipOnly` preference.
    pub(crate) fn effective_squash_mode(
        configured: SquashMode,
        min_height: u32,
        headers_conn: &Connection,
        sortdb_conn: &Connection,
    ) -> SquashMode {
        if configured == SquashMode::FullHistory {
            return SquashMode::FullHistory;
        }

        // TipOnly configured — check whether the range is entirely post-epoch-3.4.
        let epoch34_burn_height = match Self::resolve_epoch34_burn_height(sortdb_conn) {
            Some(h) => h,
            None => {
                // Epoch 3.4 not defined (e.g. early chain or custom test config).
                // Conservatively use FullHistory.
                return SquashMode::FullHistory;
            }
        };

        // Look up the burn height of the Stacks block at `min_height`.
        let min_burn_height = match Self::burn_height_for_stacks_height(headers_conn, min_height) {
            Some(bh) => bh,
            None => {
                // If we can't resolve the burn height (e.g. genesis block, block not yet in headers
                // table), conservatively use FullHistory.
                return SquashMode::FullHistory;
            }
        };

        if min_burn_height >= epoch34_burn_height {
            SquashMode::TipOnly
        } else {
            SquashMode::FullHistory
        }
    }

    /// Resolve the burn height at which epoch 3.4 starts from the sortition
    /// database's `epochs` table.  Returns `None` if epoch 3.4 is not defined.
    pub(crate) fn resolve_epoch34_burn_height(sortdb_conn: &Connection) -> Option<u64> {
        use stacks_common::types::StacksEpochId;
        SortitionDB::get_stacks_epoch_by_epoch_id(sortdb_conn, &StacksEpochId::Epoch34)
            .ok()
            .flatten()
            .map(|epoch| epoch.start_height)
    }

    /// Look up the burn-chain height for a given Stacks block height from the `block_headers`
    /// table.  Returns `None` if no header is found at that height.
    ///
    /// Uses `MIN(burn_header_height)` because `block_height` is not unique — multiple forks can
    /// share the same Stacks height.  Picking the minimum is the safe conservative choice for
    /// epoch-boundary comparison: if *any* fork at this height was mined before epoch 3.4, we want
    /// `FullHistory`.
    pub(crate) fn burn_height_for_stacks_height(
        headers_conn: &Connection,
        stacks_height: u32,
    ) -> Option<u64> {
        let sql = "SELECT MIN(burn_header_height) FROM block_headers WHERE block_height = ?1";
        rusqlite::Connection::query_row(headers_conn, sql, params![stacks_height as u64], |row| {
            row.get(0)
        })
        .ok()
        .flatten()
    }

    /// Bitcoin-reorg / measurement-error padding added on top of every epoch's observed maximum
    /// same-Stacks-height burn-spread to derive its floor. See
    /// [`Self::epoch_observed_max_burn_spread`] for the per-epoch observations and
    /// [`.docs/squash-horizon-per-epoch.md`](../../../../../.docs/squash-horizon-per-epoch.md)
    /// for the analysis methodology.
    ///
    /// Why `6`:
    /// - Matches the historical "Bitcoin reorg margin + a little" used as the global default
    ///   horizon pre-this-refactor, so 3.0+ epochs (where observed spread is `0`) land on
    ///   floor=6 — the same number we'd want even in the absence of canonical churn.
    /// - Absorbs absolute uncertainty in the empirical analysis (SQL accuracy, blocks present
    ///   in the chain but absent from both Hiro archives). Both sources of error are
    ///   bounded-additive, not proportional, so a small fixed pad is the right shape.
    /// - 2.x history is frozen since the Nakamoto activation at burn `867_867` (2024-10-30),
    ///   so the observed maxima are the actual maxima — proportional padding would be
    ///   needlessly conservative.
    pub(crate) const SQUASH_HORIZON_PADDING_BURN_BLOCKS: u32 = 6;

    /// Maximum same-Stacks-height burn-spread observed in 2.x mainnet history per epoch, from
    /// the two authoritative Hiro chainstate archives. The schedule is **frozen** as of the
    /// Nakamoto activation; see [`.docs/squash-horizon-per-epoch.md`](../../../../../.docs/squash-horizon-per-epoch.md)
    /// for the SQL methodology and per-archive numbers.
    ///
    /// | Epoch | Burn-height range | Observed max sibling spread |
    /// | ---- | ---- | ---- |
    /// | `2.0` | `666050..713000` | `1649` (outlier; height 287) |
    /// | `2.05` | `713000..781551` | `35` |
    /// | `2.1` | `781551..787651` | `10` |
    /// | `2.2` | `787651..788240` | `3` |
    /// | `2.3` | `788240..791551` | `146` |
    /// | `2.4` | `791551..840360` | `116` |
    /// | `2.5` | `840360..867867` | `7` |
    /// | `3.0+` | `867867..` | `0` (no observed canonical-tip-hash churn under signer consensus) |
    ///
    /// Family-based fallback for epochs not in the empirical schedule:
    /// - Future Nakamoto sub-epochs (`>= Epoch30`) inherit the Nakamoto observed-max of `0`
    ///   (which combined with the padding gives floor=6). Signer-driven consensus forbids the
    ///   two-blocks-at-the-same-Stacks-height race that 2.x history exhibits.
    /// - Pre-`3.0` epochs not in the schedule (e.g. `Epoch10`) inherit the worst 2.x
    ///   observed-max of `1649`. Conservative; never observed in mainnet practice.
    ///
    /// **Do not "simplify" this back into a single constant.** The values are empirical
    /// per-epoch observations — see `.docs/squash-horizon-per-epoch.md` for the SQL queries
    /// and per-archive results. A future epoch with a different sibling-spread profile would
    /// need a fresh measurement and a new row in this table.
    pub(crate) fn epoch_observed_max_burn_spread(
        epoch: stacks_common::types::StacksEpochId,
    ) -> u32 {
        use stacks_common::types::StacksEpochId;
        match epoch {
            StacksEpochId::Epoch20 => 1649,
            StacksEpochId::Epoch2_05 => 35,
            StacksEpochId::Epoch21 => 10,
            StacksEpochId::Epoch22 => 3,
            StacksEpochId::Epoch23 => 146,
            StacksEpochId::Epoch24 => 116,
            StacksEpochId::Epoch25 => 7,
            StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32
            | StacksEpochId::Epoch33
            | StacksEpochId::Epoch34 => 0,
            // Family-based fallback for epochs outside the empirical schedule.
            // - `>= Epoch30`: future Nakamoto sub-epoch — inherit the Nakamoto observed-max.
            // - `< Epoch30` (e.g. Epoch10): conservatively inherit the worst 2.x observed-max.
            other if other >= StacksEpochId::Epoch30 => 0,
            _ => 1649,
        }
    }

    /// Per-epoch minimum squash horizon (burn blocks).
    ///
    /// Equals `observed_max + SQUASH_HORIZON_PADDING_BURN_BLOCKS` for the epoch — the schedule
    /// is structured so that the empirical observation and the safety padding stay separately
    /// reviewable in source. Operators can still configure a *larger* horizon via
    /// `MARFOpenOpts.squash_horizon_burn_blocks`; the runtime resolution is
    /// `configured.max(epoch_horizon_floor(epoch))`.
    pub(crate) fn epoch_horizon_floor(epoch: stacks_common::types::StacksEpochId) -> u32 {
        Self::epoch_observed_max_burn_spread(epoch) + Self::SQUASH_HORIZON_PADDING_BURN_BLOCKS
    }

    /// Operator-configurable squash horizon for a single epoch. Returns the larger of the
    /// configured value (typically defaulted from `MARFOpenOpts`) and the epoch's empirical floor,
    /// preserving operator intent uniformly across epochs.
    pub(crate) fn epoch_horizon(
        epoch: stacks_common::types::StacksEpochId,
        configured: u32,
    ) -> u32 {
        configured.max(Self::epoch_horizon_floor(epoch))
    }

    /// Compute the maximum per-epoch horizon over every epoch whose burn-range overlaps
    /// `[burn_lo .. burn_hi]` (inclusive). The composition rule is `max-over-overlapped-epochs`:
    /// a level spanning multiple epochs needs the largest horizon any of them requires, because
    /// any in-range height is invalidated by a late sibling from any of them.
    ///
    /// Codex's two-archive analysis observed no same-height sibling pair with `burn_header_height`
    /// values straddling an epoch boundary, so per-epoch horizons compose cleanly: the worst-case
    /// for a level fully inside epoch `e` is bounded by `e`'s floor; for a level spanning epochs
    /// `[e1..e2]`, by `max(e1.floor, e2.floor)` and so on.
    ///
    /// Falls back to `configured` if the epoch list is empty or no epoch contains any byte of the
    /// range — defensive only; in practice the chain epochs cover the entire burn axis.
    pub(crate) fn max_horizon_over_burn_range(
        epochs: &crate::core::EpochList,
        burn_lo: u32,
        burn_hi: u32,
        configured: u32,
    ) -> u32 {
        epochs
            .iter()
            .filter(|e| {
                // Epoch [start..end) overlaps [burn_lo..=burn_hi]?
                let e_start = e.start_height as u32;
                let e_end = e.end_height as u32;
                e_start <= burn_hi && (e_end == 0 || e_end > burn_lo)
            })
            .map(|e| Self::epoch_horizon(e.epoch_id, configured))
            .max()
            .unwrap_or(configured)
    }

    /// Run to_do on the state of the Clarity VM at the given chain tip.
    /// Returns Some(x: R) if the given parent_tip exists.
    /// Returns None if not
    pub fn with_read_only_clarity_tx<F, R>(
        &self,
        burn_dbconn: &dyn BurnStateDB,
        parent_tip: &StacksBlockId,
        to_do: F,
    ) -> Option<R>
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        match NakamotoChainState::get_block_header(self.db(), parent_tip) {
            Ok(Some(_)) => {}
            Ok(None) => {
                return None;
            }
            Err(e) => {
                warn!("Failed to query for {}: {:?}", parent_tip, &e);
                return None;
            }
        }
        let mut conn = match self.clarity_state.read_only_connection_checked(
            parent_tip,
            &self.state_index,
            burn_dbconn,
        ) {
            Ok(x) => Some(x),
            Err(e) => {
                warn!("Failed to load read only connection"; "err" => %e);
                None
            }
        }?;
        let result = to_do(&mut conn);
        Some(result)
    }

    /// Run to_do on the unconfirmed Clarity VM state
    pub fn with_read_only_unconfirmed_clarity_tx<F, R>(
        &self,
        burn_dbconn: &dyn BurnStateDB,
        to_do: F,
    ) -> Result<Option<R>, Error>
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        // Hold the unconfirmed-state lock across the read-only Clarity tx so a concurrent relayer
        // refresh / drop cannot invalidate the borrowed ClarityInstance mid-call. Lock is brief —
        // Clarity read-only conn creation + the user closure.
        let mut guard = self.unconfirmed_state.lock();
        let res = if let Some(ref mut unconfirmed_state) = *guard {
            if !unconfirmed_state.is_readable() {
                return Ok(None);
            }
            let mut conn = unconfirmed_state
                .clarity_inst
                .read_only_connection_checked(
                    &unconfirmed_state.unconfirmed_chain_tip,
                    &self.state_index,
                    burn_dbconn,
                )?;
            let result = to_do(&mut conn);
            Some(result)
        } else {
            None
        };
        Ok(res)
    }

    /// Run to_do on the unconfirmed Clarity VM state if the tip refers to the unconfirmed state;
    /// otherwise run to_do on the confirmed state of the Clarity VM. If the tip doesn't exist,
    /// then return None.
    pub fn maybe_read_only_clarity_tx<F, R>(
        &self,
        burn_dbconn: &dyn BurnStateDB,
        parent_tip: &StacksBlockId,
        to_do: F,
    ) -> Result<Option<R>, Error>
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        // Lock briefly just to read the tip + readability flag — release before delegating so the
        // chosen branch can re-acquire (or skip) on its own.
        let unconfirmed = {
            let guard = self.unconfirmed_state.lock();
            if let Some(ref unconfirmed_state) = *guard {
                *parent_tip == unconfirmed_state.unconfirmed_chain_tip
                    && unconfirmed_state.is_readable()
            } else {
                false
            }
        };

        if unconfirmed {
            self.with_read_only_unconfirmed_clarity_tx(burn_dbconn, to_do)
        } else {
            Ok(self.with_read_only_clarity_tx(burn_dbconn, parent_tip, to_do))
        }
    }

    fn get_parent_index_block(
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
    ) -> StacksBlockId {
        if *parent_block == BOOT_BLOCK_HASH {
            // begin boot block
            StacksBlockId::sentinel()
        } else if *parent_block == FIRST_STACKS_BLOCK_HASH {
            // begin first-ever block
            StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        } else {
            // subsequent block
            StacksBlockHeader::make_index_block_hash(parent_consensus_hash, parent_block)
        }
    }

    /// Begin an unconfirmed VM transaction, if there's no other open transaction for it.
    pub fn chainstate_begin_unconfirmed<'a, 'b>(
        conf: DBConfig,
        headers_db: &'b dyn HeadersDB,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        tip: &StacksBlockId,
    ) -> ClarityTx<'a, 'b> {
        let inner_clarity_tx = clarity_instance.begin_unconfirmed(tip, headers_db, burn_dbconn);
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Open a Clarity transaction against this chainstate's unconfirmed state, if it exists.
    ///
    /// `unconfirmed` is borrowed externally — the caller must acquire the
    /// [`SharedUnconfirmedState`] lock and pass `&mut UnconfirmedState` here. This is the
    /// price of putting `unconfirmed_state` behind a `Mutex` shared across handles: the
    /// returned `ClarityTx<'a, 'a>` borrows `&mut unconfirmed.clarity_inst`, so the caller
    /// must hold the unconfirmed-slot lock for the entire lifetime of the returned `ClarityTx`
    /// (the typical pattern is to bind the `MutexGuard` to a stack variable in the same scope).
    ///
    /// Single-statement caller pattern:
    ///
    /// ```ignore
    /// let mut guard = chainstate.unconfirmed_state.lock();
    /// let unconfirmed = guard.as_mut().ok_or(...)?;
    /// let mut clarity_tx = chainstate.begin_unconfirmed(burn_dbconn, unconfirmed)
    ///     .ok_or(...)?;
    /// // ... use clarity_tx ...
    /// // guard drops at end of scope after clarity_tx
    /// ```
    pub fn begin_unconfirmed<'a>(
        &'a self,
        burn_dbconn: &'a dyn BurnStateDB,
        unconfirmed: &'a mut UnconfirmedState,
    ) -> Option<ClarityTx<'a, 'a>> {
        let conf = self.config();
        if !unconfirmed.is_writable() {
            debug!("Unconfirmed state is not writable; cannot begin unconfirmed Clarity Tx");
            return None;
        }
        Some(StacksChainState::chainstate_begin_unconfirmed(
            conf,
            &self.state_index,
            &mut unconfirmed.clarity_inst,
            burn_dbconn,
            &unconfirmed.confirmed_chain_tip,
        ))
    }

    /// Create a Clarity VM database transaction
    fn inner_clarity_tx_begin<'a, 'b>(
        conf: DBConfig,
        headers_db: &'b dyn HeadersDB,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'b> {
        // mix consensus hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the pair is)
        let parent_index_block =
            StacksChainState::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_block(
            &parent_index_block,
            &new_index_block,
            headers_db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Create an ephemeral Clarity VM database transaction.
    /// The child block, identified by `new_consensus_hash` and `new_block`, will be treated as
    /// ephemeral.
    fn inner_ephemeral_clarity_tx_begin<'a, 'b>(
        conf: DBConfig,
        headers_db: &'b dyn HeadersDB,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'b> {
        // mix consensus hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the pair is)
        let parent_index_block =
            StacksChainState::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing ephemeral Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child ephemeral MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent ephemeral MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_ephemeral(
            &parent_index_block,
            &new_index_block,
            headers_db,
            burn_dbconn,
        );

        test_debug!("Got ephemeral clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Create a Clarity VM transaction connection for testing in 2.1
    #[cfg(test)]
    pub fn test_genesis_block_begin_2_1<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        let db = &self.state_index;
        let clarity_instance = &mut self.clarity_state;

        // mix burn header hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            StacksChainState::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing test genesis Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_test_genesis_block_2_1(
            &parent_index_block,
            &new_index_block,
            db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Create a Clarity VM transaction connection for testing in 2.05
    #[cfg(test)]
    pub fn test_genesis_block_begin_2_05<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        let db = &self.state_index;
        let clarity_instance = &mut self.clarity_state;

        // mix burn header hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            StacksChainState::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing test genesis Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_test_genesis_block(
            &parent_index_block,
            &new_index_block,
            db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Get the appropriate MARF index hash to use to identify a chain tip, given a block header
    pub fn get_index_hash(
        consensus_hash: &ConsensusHash,
        header_hash: &BlockHeaderHash,
    ) -> StacksBlockId {
        if consensus_hash == &FIRST_BURNCHAIN_CONSENSUS_HASH {
            StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        } else {
            StacksBlockId::new(consensus_hash, header_hash)
        }
    }

    /// Record the microblock public key hash for a block into the MARF'ed Clarity DB
    pub fn insert_microblock_pubkey_hash(
        clarity_tx: &mut ClarityTx,
        height: u32,
        mblock_pubkey_hash: &Hash160,
    ) -> Result<(), Error> {
        clarity_tx
            .connection()
            .as_transaction(|tx| {
                tx.with_clarity_db(|ref mut db| {
                    db.insert_microblock_pubkey_hash_height(mblock_pubkey_hash, height)
                        .expect("FATAL: failed to store microblock public key hash to Clarity DB");
                    Ok(())
                })
            })
            .expect("FATAL: failed to store microblock public key hash");
        Ok(())
    }

    /// Get the block height at which a microblock public key hash was used, if any
    pub fn has_microblock_pubkey_hash(
        clarity_tx: &mut ClarityTx,
        mblock_pubkey_hash: &Hash160,
    ) -> Result<Option<u32>, Error> {
        let height_opt = clarity_tx
            .connection()
            .with_clarity_db_readonly::<_, Result<_, ()>>(|ref mut db| {
                let height_opt = db
                    .get_microblock_pubkey_hash_height(mblock_pubkey_hash)
                    .expect("FATAL: failed to query microblock public key hash");
                Ok(height_opt)
            })
            .expect("FATAL: failed to query microblock public key hash");
        Ok(height_opt)
    }

    /// Get the burnchain txids for a given index block hash
    pub(crate) fn get_burnchain_txids_for_block(
        conn: &Connection,
        index_block_hash: &StacksBlockId,
    ) -> Result<Vec<Txid>, Error> {
        let sql = "SELECT txids FROM burnchain_txids WHERE index_block_hash = ?1";
        let args = params![index_block_hash];

        let txids = conn
            .query_row(sql, args, |r| {
                let txids_json: String = r.get_unwrap(0);
                let txids: Vec<Txid> = serde_json::from_str(&txids_json)
                    .expect("FATAL: database corruption: could not parse TXID JSON");

                Ok(txids)
            })
            .optional()?
            .unwrap_or_default();

        Ok(txids)
    }

    /// Get the txids of the burnchain operations applied in the past N Stacks blocks.
    /// Only works for epoch 2.x
    pub fn get_burnchain_txids_in_ancestors(
        conn: &Connection,
        index_block_hash: &StacksBlockId,
        count: u64,
    ) -> Result<HashSet<Txid>, Error> {
        let mut ret = HashSet::new();
        let ancestors = StacksChainState::get_ancestor_index_hashes(conn, index_block_hash, count)?;
        for ancestor in ancestors.into_iter() {
            let txids = StacksChainState::get_burnchain_txids_for_block(conn, &ancestor)?;
            for txid in txids.into_iter() {
                ret.insert(txid);
            }
        }
        Ok(ret)
    }

    /// Store all on-burnchain STX operations' txids by index block hash.
    /// `index_block_hash` is the tenure-start block.
    /// * For epoch 2.x, this is simply the block ID
    /// * for epoch 3.x and later, this is the first block in the tenure.
    pub fn store_burnchain_txids(
        tx: &DBTx,
        index_block_hash: &StacksBlockId,
        burn_stack_stx_ops: Vec<StackStxOp>,
        burn_transfer_stx_ops: Vec<TransferStxOp>,
        burn_delegate_stx_ops: Vec<DelegateStxOp>,
        burn_vote_for_aggregate_key_ops: Vec<VoteForAggregateKeyOp>,
    ) -> Result<(), Error> {
        let mut txids: Vec<_> = burn_stack_stx_ops
            .into_iter()
            .fold(vec![], |mut txids, op| {
                txids.push(op.txid);
                txids
            });

        let mut xfer_txids = burn_transfer_stx_ops
            .into_iter()
            .fold(vec![], |mut txids, op| {
                txids.push(op.txid);
                txids
            });

        txids.append(&mut xfer_txids);

        let mut delegate_txids = burn_delegate_stx_ops
            .into_iter()
            .fold(vec![], |mut txids, op| {
                txids.push(op.txid);
                txids
            });

        txids.append(&mut delegate_txids);

        let mut vote_txids =
            burn_vote_for_aggregate_key_ops
                .into_iter()
                .fold(vec![], |mut txids, op| {
                    txids.push(op.txid);
                    txids
                });

        txids.append(&mut vote_txids);

        let txids_json =
            serde_json::to_string(&txids).expect("FATAL: could not serialize Vec<Txid>");
        let sql = "INSERT INTO burnchain_txids (index_block_hash, txids) VALUES (?1, ?2)";
        let args = params![index_block_hash, &txids_json];
        tx.execute(sql, args)?;
        Ok(())
    }

    /// Append a Stacks block to an existing Stacks block, and grant the miner the block reward.
    /// Return the new Stacks header info.
    pub fn advance_tip(
        headers_tx: &mut StacksDBTx<'_>,
        parent_tip: &StacksBlockHeader,
        parent_consensus_hash: &ConsensusHash,
        new_tip: &StacksBlockHeader,
        new_consensus_hash: &ConsensusHash,
        new_burn_header_hash: &BurnchainHeaderHash,
        new_burnchain_height: u32,
        new_burnchain_timestamp: u64,
        microblock_tail_opt: Option<StacksMicroblockHeader>,
        block_reward: &MinerPaymentSchedule,
        mature_miner_payouts: Option<(MinerReward, Vec<MinerReward>, MinerReward, MinerRewardInfo)>, // (miner, [users], parent, matured rewards)
        anchor_block_cost: &ExecutionCost,
        anchor_block_size: u64,
        applied_epoch_transition: bool,
        burn_stack_stx_ops: Vec<StackStxOp>,
        burn_transfer_stx_ops: Vec<TransferStxOp>,
        burn_delegate_stx_ops: Vec<DelegateStxOp>,
        burn_vote_for_aggregate_key_ops: Vec<VoteForAggregateKeyOp>,
    ) -> Result<StacksHeaderInfo, Error> {
        if new_tip.parent_block != FIRST_STACKS_BLOCK_HASH {
            // not the first-ever block, so linkage must occur
            assert_eq!(new_tip.parent_block, parent_tip.block_hash());
        }

        assert_eq!(
            parent_tip
                .total_work
                .work
                .checked_add(1)
                .expect("Block height overflow"),
            new_tip.total_work.work
        );

        let parent_hash =
            StacksChainState::get_index_hash(parent_consensus_hash, &parent_tip.block_hash());

        // store each indexed field
        test_debug!(
            "Headers index_put_begin {}-{}",
            &parent_hash,
            &new_tip.index_block_hash(new_consensus_hash)
        );
        let root_hash = headers_tx.put_indexed_all(
            &parent_hash,
            &new_tip.index_block_hash(new_consensus_hash),
            &[],
            &[],
        )?;
        let index_block_hash = new_tip.index_block_hash(new_consensus_hash);
        test_debug!(
            "Headers index_indexed_all finished {}-{}",
            &parent_hash,
            &index_block_hash,
        );

        let new_tip_info = StacksHeaderInfo {
            anchored_header: new_tip.clone().into(),
            microblock_tail: microblock_tail_opt,
            index_root: root_hash,
            stacks_block_height: new_tip.total_work.work,
            consensus_hash: new_consensus_hash.clone(),
            burn_header_hash: new_burn_header_hash.clone(),
            burn_header_height: new_burnchain_height,
            burn_header_timestamp: new_burnchain_timestamp,
            anchored_block_size: anchor_block_size,
            burn_view: None,
            total_tenure_size: 0,
        };

        StacksChainState::insert_stacks_block_header(
            headers_tx.deref_mut(),
            &parent_hash,
            &new_tip_info,
            anchor_block_cost,
        )?;
        StacksChainState::insert_miner_payment_schedule(headers_tx.deref_mut(), block_reward)?;
        StacksChainState::store_burnchain_txids(
            headers_tx.deref(),
            &index_block_hash,
            burn_stack_stx_ops,
            burn_transfer_stx_ops,
            burn_delegate_stx_ops,
            burn_vote_for_aggregate_key_ops,
        )?;

        if let Some((miner_payout, user_payouts, parent_payout, reward_info)) = mature_miner_payouts
        {
            let rewarded_miner_block_id = StacksBlockHeader::make_index_block_hash(
                &reward_info.from_block_consensus_hash,
                &reward_info.from_stacks_block_hash,
            );
            let rewarded_parent_miner_block_id = StacksBlockHeader::make_index_block_hash(
                &reward_info.from_parent_block_consensus_hash,
                &reward_info.from_parent_stacks_block_hash,
            );

            StacksChainState::insert_matured_child_miner_reward(
                headers_tx.deref_mut(),
                &rewarded_parent_miner_block_id,
                &rewarded_miner_block_id,
                &miner_payout,
            )?;
            for user_payout in user_payouts.into_iter() {
                StacksChainState::insert_matured_child_user_reward(
                    headers_tx.deref_mut(),
                    &rewarded_parent_miner_block_id,
                    &rewarded_miner_block_id,
                    &user_payout,
                )?;
            }
            StacksChainState::insert_matured_parent_miner_reward(
                headers_tx.deref_mut(),
                &rewarded_parent_miner_block_id,
                &rewarded_miner_block_id,
                &parent_payout,
            )?;
        }

        if applied_epoch_transition {
            debug!("Block {} applied an epoch transition", &index_block_hash);
            let sql = "INSERT INTO epoch_transitions (block_id) VALUES (?)";
            let args = params![&index_block_hash];
            headers_tx.deref_mut().execute(sql, args)?;
        }

        info!(
            "Advanced to new tip! {}/{}",
            new_consensus_hash,
            new_tip.block_hash()
        );
        Ok(new_tip_info)
    }
}

#[cfg(test)]
pub mod test {
    use std::{env, fs};

    use clarity::vm::test_util::TEST_BURN_STATE_DB;
    use stx_genesis::GenesisData;

    use super::*;
    use crate::chainstate::stacks::*;
    use crate::util_lib::boot::boot_code_test_addr;

    pub fn instantiate_chainstate(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
    ) -> StacksChainState {
        instantiate_chainstate_with_balances(mainnet, chain_id, test_name, vec![])
    }

    pub fn instantiate_chainstate_with_balances(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
        balances: Vec<(StacksAddress, u64)>,
    ) -> StacksChainState {
        let path = chainstate_path(test_name);
        if fs::metadata(&path).is_ok() {
            fs::remove_dir_all(&path).unwrap();
        };

        let initial_balances = balances
            .into_iter()
            .map(|(addr, balance)| (PrincipalData::from(addr), balance))
            .collect();

        let mut boot_data = ChainStateBootData {
            initial_balances,
            post_flight_callback: None,
            first_burnchain_block_hash: BurnchainHeaderHash::zero(),
            first_burnchain_block_height: 0,
            first_burnchain_block_timestamp: 0,
            pox_constants: PoxConstants::testnet_default(),
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_names: None,
            get_bulk_initial_namespaces: None,
        };

        StacksChainState::open_and_exec(mainnet, chain_id, &path, Some(&mut boot_data), None)
            .unwrap()
            .0
    }

    pub fn open_chainstate(mainnet: bool, chain_id: u32, test_name: &str) -> StacksChainState {
        let path = chainstate_path(test_name);
        StacksChainState::open(mainnet, chain_id, &path, None)
            .unwrap()
            .0
    }

    pub fn chainstate_path(test_name: &str) -> String {
        format!("/tmp/stacks-node-tests/cs-{}", test_name)
    }

    #[test]
    fn test_instantiate_chainstate() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());

        // verify that the boot code is there
        let mut conn = chainstate.block_begin(
            &TEST_BURN_STATE_DB,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &MINER_BLOCK_CONSENSUS_HASH,
            &MINER_BLOCK_HEADER_HASH,
        );

        for (boot_contract_name, _) in STACKS_BOOT_CODE_TESTNET.iter() {
            let boot_contract_id = QualifiedContractIdentifier::new(
                boot_code_test_addr().into(),
                ContractName::try_from(boot_contract_name.to_string()).unwrap(),
            );
            let contract_res =
                StacksChainState::get_contract(&mut conn, &boot_contract_id).unwrap();
            assert!(contract_res.is_some());
        }
    }

    #[test]
    fn test_chainstate_sampled_genesis_consistency() {
        // Test root hash for the test chainstate data set
        let mut boot_data = ChainStateBootData {
            initial_balances: vec![],
            first_burnchain_block_hash: BurnchainHeaderHash::zero(),
            first_burnchain_block_height: 0,
            first_burnchain_block_timestamp: 0,
            pox_constants: PoxConstants::testnet_default(),
            post_flight_callback: None,
            get_bulk_initial_lockups: Some(Box::new(|| {
                Box::new(GenesisData::new(true).read_lockups().map(|item| {
                    ChainstateAccountLockup {
                        address: item.address,
                        amount: item.amount,
                        block_height: item.block_height,
                    }
                }))
            })),
            get_bulk_initial_balances: Some(Box::new(|| {
                Box::new(GenesisData::new(true).read_balances().map(|item| {
                    ChainstateAccountBalance {
                        address: item.address,
                        amount: item.amount,
                    }
                }))
            })),
            get_bulk_initial_namespaces: Some(Box::new(|| {
                Box::new(GenesisData::new(true).read_namespaces().map(|item| {
                    ChainstateBNSNamespace {
                        namespace_id: item.namespace_id,
                        importer: item.importer,
                        buckets: item.buckets,
                        base: item.base as u64,
                        coeff: item.coeff as u64,
                        nonalpha_discount: item.nonalpha_discount as u64,
                        no_vowel_discount: item.no_vowel_discount as u64,
                        lifetime: item.lifetime as u64,
                    }
                }))
            })),
            get_bulk_initial_names: Some(Box::new(|| {
                Box::new(
                    GenesisData::new(true)
                        .read_names()
                        .map(|item| ChainstateBNSName {
                            fully_qualified_name: item.fully_qualified_name,
                            owner: item.owner,
                            zonefile_hash: item.zonefile_hash,
                        }),
                )
            })),
        };

        let path = chainstate_path(function_name!());
        if fs::metadata(&path).is_ok() {
            fs::remove_dir_all(&path).unwrap();
        };

        let mut chainstate =
            StacksChainState::open_and_exec(false, 0x80000000, &path, Some(&mut boot_data), None)
                .unwrap()
                .0;

        let genesis_root_hash = chainstate.clarity_state.with_marf(|marf| {
            let index_block_hash = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            marf.get_root_hash_at(&index_block_hash).unwrap()
        });

        // If the genesis data changed, then this test will fail.
        // Just update the expected value
        assert_eq!(
            genesis_root_hash.to_string(),
            "0eb3076f0635ccdfcdc048afb8dea9048c5180a2e2b2952874af1d18f06321e8"
        );
    }

    #[test]
    fn test_chainstate_full_genesis_consistency() {
        if env::var("CIRCLE_CI_TEST") != Ok("1".into()) {
            return;
        }

        // Test root hash for the final chainstate data set
        let mut boot_data = ChainStateBootData {
            initial_balances: vec![],
            first_burnchain_block_hash: BurnchainHeaderHash::from_hex(
                BITCOIN_MAINNET_FIRST_BLOCK_HASH,
            )
            .unwrap(),
            first_burnchain_block_height: BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT as u32,
            first_burnchain_block_timestamp: BITCOIN_MAINNET_FIRST_BLOCK_TIMESTAMP,
            pox_constants: PoxConstants::mainnet_default(),
            post_flight_callback: None,
            get_bulk_initial_lockups: Some(Box::new(|| {
                Box::new(GenesisData::new(false).read_lockups().map(|item| {
                    ChainstateAccountLockup {
                        address: item.address,
                        amount: item.amount,
                        block_height: item.block_height,
                    }
                }))
            })),
            get_bulk_initial_balances: Some(Box::new(|| {
                Box::new(GenesisData::new(false).read_balances().map(|item| {
                    ChainstateAccountBalance {
                        address: item.address,
                        amount: item.amount,
                    }
                }))
            })),
            get_bulk_initial_namespaces: Some(Box::new(|| {
                Box::new(GenesisData::new(false).read_namespaces().map(|item| {
                    ChainstateBNSNamespace {
                        namespace_id: item.namespace_id,
                        importer: item.importer,
                        buckets: item.buckets,
                        base: item.base as u64,
                        coeff: item.coeff as u64,
                        nonalpha_discount: item.nonalpha_discount as u64,
                        no_vowel_discount: item.no_vowel_discount as u64,
                        lifetime: item.lifetime as u64,
                    }
                }))
            })),
            get_bulk_initial_names: Some(Box::new(|| {
                Box::new(
                    GenesisData::new(false)
                        .read_names()
                        .map(|item| ChainstateBNSName {
                            fully_qualified_name: item.fully_qualified_name,
                            owner: item.owner,
                            zonefile_hash: item.zonefile_hash,
                        }),
                )
            })),
        };

        let path = chainstate_path(function_name!());
        if fs::metadata(&path).is_ok() {
            fs::remove_dir_all(&path).unwrap();
        };

        let mut chainstate =
            StacksChainState::open_and_exec(true, 0x000000001, &path, Some(&mut boot_data), None)
                .unwrap()
                .0;

        let genesis_root_hash = chainstate.clarity_state.with_marf(|marf| {
            let index_block_hash = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            marf.get_root_hash_at(&index_block_hash).unwrap()
        });

        // If the genesis data changed, then this test will fail.
        // Just update the expected value
        assert_eq!(
            format!("{}", genesis_root_hash),
            MAINNET_2_0_GENESIS_ROOT_HASH
        );
    }

    #[test]
    fn latest_db_version_supports_latest_epoch() {
        let db = DBConfig {
            version: CHAINSTATE_VERSION.to_string(),
            mainnet: true,
            chain_id: CHAIN_ID_MAINNET,
        };
        assert!(db.supports_epoch(StacksEpochId::latest()));
    }

    #[test]
    fn test_sqlite_version() {
        let chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        assert_eq!(
            query_row(chainstate.db(), "SELECT sqlite_version()", NO_PARAMS).unwrap(),
            Some("3.45.0".to_string())
        );
    }

    pub fn tmp_db_path() -> PathBuf {
        std::env::temp_dir().join(format!("chainstate-test-{}.sqlite", rand::random::<u64>()))
    }

    #[test]
    fn chainstate_migration_v10_to_v11() -> Result<(), Error> {
        let test_name = "test_chainstate_migration_v10_to_v11";
        // Create an in-memory database
        let tmp_path = tmp_db_path();
        let conn = Connection::open(tmp_path.clone())?;

        // Simulate schema version 10 by applying all schemas up to NAKAMOTO_CHAINSTATE_SCHEMA_6
        for schema in CHAINSTATE_INITIAL_SCHEMA.iter() {
            conn.execute_batch(schema)?;
        }
        // Manually insert a version since chainstate initial schema just creates but doesn't insert anything
        // required for subsequent "updates" to be successful
        conn.execute(
            "INSERT INTO db_config (version, mainnet, chain_id) VALUES (?, ?, ?)",
            params!["1", 1, 1], // initial version 1
        )?;
        for schema in CHAINSTATE_SCHEMA_2.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in CHAINSTATE_SCHEMA_3.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_1.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_2.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_3.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_4.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_5.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in CHAINSTATE_SCHEMA_4.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_6.iter() {
            conn.execute_batch(schema)?;
        }

        // Insert dummy data into pre-nakamoto block_headers
        let sample_block_hash = BlockHeaderHash([1u8; 32]);
        let sample_consensus_hash = ConsensusHash([2u8; 20]);
        let sample_burn_header_hash = BurnchainHeaderHash([3u8; 32]);
        let sample_parent_block_id = StacksBlockId([0u8; 32]);
        let sample_index_block_hash =
            StacksBlockId::new(&sample_consensus_hash, &sample_block_hash);
        conn.execute(
            "INSERT INTO block_headers (
                version, total_burn, total_work, proof, parent_block, parent_microblock,
                parent_microblock_sequence, tx_merkle_root, state_index_root, microblock_pubkey_hash,
                block_hash, index_block_hash, block_height, index_root, consensus_hash,
                burn_header_hash, burn_header_height, burn_header_timestamp, parent_block_id,
                cost, block_size, affirmation_weight
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                1,
                "1000",
                "1",
                to_hex(&[0u8; 48]),
                to_hex(&[0u8; 32]),
                to_hex(&[0u8; 32]),
                0,
                to_hex(&[0u8; 32]),
                to_hex(&[0u8; 32]),
                to_hex(&[0u8; 20]),
                &sample_block_hash,
                &sample_index_block_hash,
                1,
                to_hex(&[0u8; 32]),
                &sample_consensus_hash,
                &sample_burn_header_hash,
                100,
                1234567890,
                &sample_parent_block_id,
                serde_json::to_string(&ExecutionCost::ZERO).unwrap(),
                "1000",
                10
            ],
        )?;

        // Verify schema version is 10 before migration
        let version: String = query_row(&conn, "SELECT version FROM db_config", NO_PARAMS)?
            .expect("Expected db_config to have a version");
        assert_eq!(
            version, "10",
            "Database version should be 10 before migration"
        );

        // Apply the simplified CHAINSTATE_SCHEMA_5 migration
        for statement in CHAINSTATE_SCHEMA_5.iter() {
            conn.execute_batch(statement)?;
        }
        // Verify schema version is updated to 11
        let version: String = query_row(&conn, "SELECT version FROM db_config", NO_PARAMS)?
            .expect("Expected db_config to have a version");
        assert_eq!(
            version, "11",
            "Database version should be 11 after migration"
        );

        // Verify affirmation_weight column is dropped
        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(block_headers)")?
            .query_map([], |row| row.get(1))?
            .collect::<Result<Vec<String>, _>>()?;
        assert!(
            !columns.contains(&"affirmation_weight".to_string()),
            "affirmation_weight column should be dropped"
        );

        // Verify indexes are dropped
        let indexes: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'block_headers'")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        assert!(
            !indexes.contains(&"index_block_header_by_affirmation_weight".to_string()),
            "index_block_header_by_affirmation_weight should be dropped"
        );
        assert!(
            !indexes.contains(&"index_block_header_by_height_and_affirmation_weight".to_string()),
            "index_block_header_by_height_and_affirmation_weight should be dropped"
        );

        // Verify data integrity
        let row: Option<(String, String, String)> = conn
            .query_row(
                "SELECT block_hash, consensus_hash, block_size
            FROM block_headers WHERE index_block_hash = ?",
                params![&sample_index_block_hash],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        assert!(row.is_some(), "Sample data should remain after migration");

        let (block_hash, consensus_hash, block_size) = row.unwrap();
        assert_eq!(
            block_hash,
            sample_block_hash.to_string(),
            "Block hash should be preserved"
        );
        assert_eq!(
            consensus_hash,
            sample_consensus_hash.to_string(),
            "Consensus hash should be preserved"
        );
        assert_eq!(block_size, "1000", "Block size should be preserved");

        Ok(())
    }

    // -------------------------------------------------------------------
    // Phase 5: mode selection tests
    // -------------------------------------------------------------------

    /// Create an in-memory SQLite connection with the sortition DB `epochs`
    /// table and optionally insert an epoch 3.4 row.
    fn mock_sortdb_conn(epoch34_start: Option<u64>) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE epochs (
                start_block_height INTEGER NOT NULL,
                end_block_height INTEGER NOT NULL,
                epoch_id INTEGER NOT NULL,
                block_limit TEXT NOT NULL,
                network_epoch INTEGER NOT NULL,
                PRIMARY KEY(start_block_height, epoch_id)
            );",
        )
        .unwrap();
        if let Some(start) = epoch34_start {
            let block_limit =
                r#"{"write_length":0,"write_count":0,"read_length":0,"read_count":0,"runtime":0}"#;
            // epoch_id for Epoch34 = 0x03004 = 12292
            conn.execute(
                "INSERT INTO epochs (epoch_id, start_block_height, end_block_height, block_limit, network_epoch)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![12292u32, start as i64, i64::MAX, block_limit, 0u8],
            )
            .unwrap();
        }
        conn
    }

    /// Create an in-memory SQLite connection with a `block_headers` table
    /// and insert rows mapping Stacks block heights to burn heights.
    fn mock_headers_conn(rows: &[(u32, u64)]) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE block_headers (
                block_height INTEGER NOT NULL,
                burn_header_height INTEGER NOT NULL
            );",
        )
        .unwrap();
        for &(stacks_h, burn_h) in rows {
            conn.execute(
                "INSERT INTO block_headers (block_height, burn_header_height) VALUES (?1, ?2)",
                params![stacks_h as i64, burn_h as i64],
            )
            .unwrap();
        }
        conn
    }

    #[test]
    fn test_squash_block_count_empty_duplicate_height_range() {
        assert_eq!(StacksChainState::squash_block_count(39_001, 39_000), None);
        assert_eq!(
            StacksChainState::squash_block_count(39_000, 39_000),
            Some(1)
        );
        assert_eq!(
            StacksChainState::squash_block_count(38_001, 39_000),
            Some(1_000)
        );
    }

    /// Regression: the operator's `marf_full_history = true` config (threaded through
    /// `MARFOpenOpts.squash_mode = FullHistory`) must survive the chainstate-open → `maybe_squash`
    /// path without being silently downgraded to `TipOnly`. The previous fix wired the safety
    /// check for pre-3.4 ranges but hardcoded `let configured_mode = SquashMode::TipOnly;` at the
    /// `maybe_squash` entry; this test pins that the configured mode is actually read from
    /// `MARFOpenOpts`.
    #[test]
    fn test_configured_squash_mode_reads_from_marf_opts() {
        use crate::chainstate::stacks::index::marf::MARFOpenOpts;
        use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;

        // Configured FullHistory.
        let opts_full = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", false)
            .with_squash_mode(SquashMode::FullHistory);
        assert_eq!(
            StacksChainState::configured_squash_mode_from_opts(Some(&opts_full)),
            SquashMode::FullHistory,
            "operator-configured FullHistory must be returned, not silently downgraded"
        );

        // Configured TipOnly (default).
        let opts_tip = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", false)
            .with_squash_mode(SquashMode::TipOnly);
        assert_eq!(
            StacksChainState::configured_squash_mode_from_opts(Some(&opts_tip)),
            SquashMode::TipOnly,
        );

        // No `marf_opts` (programmatic handle, no config) — conservative default is TipOnly.
        assert_eq!(
            StacksChainState::configured_squash_mode_from_opts(None),
            SquashMode::TipOnly,
            "missing marf_opts must fall back to the historical TipOnly default"
        );
    }

    /// End-to-end regression for the resolution chain that `maybe_squash` performs:
    ///
    /// `MARFOpenOpts → configured_squash_mode_from_opts → effective_squash_mode → final mode`.
    ///
    /// Pins the four cases that matter for operator-intent + safety:
    /// 1. `FullHistory` configured + pre-3.4 range  → `FullHistory`
    /// 2. `FullHistory` configured + post-3.4 range → `FullHistory` (operator intent preserved)
    /// 3. `TipOnly`     configured + pre-3.4 range  → `FullHistory` (safety upgrade)
    /// 4. `TipOnly`     configured + post-3.4 range → `TipOnly`     (default-throughput case)
    #[test]
    fn test_maybe_squash_mode_resolution_preserves_operator_intent() {
        use crate::chainstate::stacks::index::marf::MARFOpenOpts;
        use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;

        let sortdb = mock_sortdb_conn(Some(900_000));
        let pre_34 = mock_headers_conn(&[(100, 500_000)]);
        let post_34 = mock_headers_conn(&[(100, 1_000_000)]);

        let opts_full = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", false)
            .with_squash_mode(SquashMode::FullHistory);
        let opts_tip = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", false)
            .with_squash_mode(SquashMode::TipOnly);

        let resolve = |opts: &MARFOpenOpts, headers: &Connection| -> SquashMode {
            let configured = StacksChainState::configured_squash_mode_from_opts(Some(opts));
            StacksChainState::effective_squash_mode(configured, 100, headers, &sortdb)
        };

        assert_eq!(resolve(&opts_full, &pre_34), SquashMode::FullHistory);
        assert_eq!(
            resolve(&opts_full, &post_34),
            SquashMode::FullHistory,
            "operator intent (FullHistory) must NOT be downgraded post-3.4"
        );
        assert_eq!(
            resolve(&opts_tip, &pre_34),
            SquashMode::FullHistory,
            "TipOnly + pre-3.4 must be upgraded to FullHistory for at-block correctness"
        );
        assert_eq!(resolve(&opts_tip, &post_34), SquashMode::TipOnly);
    }

    #[test]
    fn test_effective_squash_mode_full_history_configured_always_full_history() {
        // FullHistory configured → always FullHistory regardless of epoch.
        let sortdb = mock_sortdb_conn(Some(900_000));
        let headers = mock_headers_conn(&[(100, 500_000)]);

        let mode = StacksChainState::effective_squash_mode(
            SquashMode::FullHistory,
            100,
            &headers,
            &sortdb,
        );
        assert_eq!(mode, SquashMode::FullHistory);
    }

    #[test]
    fn test_effective_squash_mode_tiponly_pre_epoch34_forced_full_history() {
        // TipOnly configured, range starts before epoch 3.4 → forced FullHistory.
        let sortdb = mock_sortdb_conn(Some(900_000));
        let headers = mock_headers_conn(&[(100, 800_000)]);

        let mode =
            StacksChainState::effective_squash_mode(SquashMode::TipOnly, 100, &headers, &sortdb);
        assert_eq!(mode, SquashMode::FullHistory);
    }

    #[test]
    fn test_effective_squash_mode_tiponly_post_epoch34_honoured() {
        // TipOnly configured, range starts at or after epoch 3.4 → TipOnly.
        let sortdb = mock_sortdb_conn(Some(900_000));
        let headers = mock_headers_conn(&[(100, 900_000)]);

        let mode =
            StacksChainState::effective_squash_mode(SquashMode::TipOnly, 100, &headers, &sortdb);
        assert_eq!(mode, SquashMode::TipOnly);

        // Also test strictly above.
        let headers2 = mock_headers_conn(&[(200, 950_000)]);
        let mode2 =
            StacksChainState::effective_squash_mode(SquashMode::TipOnly, 200, &headers2, &sortdb);
        assert_eq!(mode2, SquashMode::TipOnly);
    }

    #[test]
    fn test_effective_squash_mode_tiponly_straddling_uses_full_history() {
        // TipOnly configured, range starts just before 3.4 boundary → FullHistory.
        let sortdb = mock_sortdb_conn(Some(900_000));
        let headers = mock_headers_conn(&[(100, 899_999)]);

        let mode =
            StacksChainState::effective_squash_mode(SquashMode::TipOnly, 100, &headers, &sortdb);
        assert_eq!(mode, SquashMode::FullHistory);
    }

    #[test]
    fn test_effective_squash_mode_no_epoch34_defined() {
        // Epoch 3.4 not defined → conservatively use FullHistory.
        let sortdb = mock_sortdb_conn(None);
        let headers = mock_headers_conn(&[(100, 500_000)]);

        let mode =
            StacksChainState::effective_squash_mode(SquashMode::TipOnly, 100, &headers, &sortdb);
        assert_eq!(mode, SquashMode::FullHistory);
    }

    #[test]
    fn test_effective_squash_mode_missing_header_row() {
        // Header row not found for min_height → conservatively use FullHistory.
        let sortdb = mock_sortdb_conn(Some(900_000));
        let headers = mock_headers_conn(&[]); // no rows

        let mode =
            StacksChainState::effective_squash_mode(SquashMode::TipOnly, 100, &headers, &sortdb);
        assert_eq!(mode, SquashMode::FullHistory);
    }

    #[test]
    fn test_effective_squash_mode_fork_ambiguity_uses_conservative_min() {
        // Two forks at the same Stacks height with different burn heights.
        // One is pre-3.4, one is post-3.4. MIN should pick the pre-3.4 one
        // so the result is FullHistory (conservative).
        let sortdb = mock_sortdb_conn(Some(900_000));
        let headers = mock_headers_conn(&[
            (100, 899_999), // fork A: pre-epoch-3.4
            (100, 900_001), // fork B: post-epoch-3.4
        ]);

        let mode =
            StacksChainState::effective_squash_mode(SquashMode::TipOnly, 100, &headers, &sortdb);
        assert_eq!(
            mode,
            SquashMode::FullHistory,
            "fork-ambiguous height should conservatively use FullHistory"
        );
    }

    #[test]
    fn test_effective_squash_mode_fork_ambiguity_both_post_epoch34() {
        // Two forks, both post-3.4. MIN is still >= epoch34 → TipOnly.
        let sortdb = mock_sortdb_conn(Some(900_000));
        let headers = mock_headers_conn(&[
            (100, 900_000), // fork A: exactly at epoch-3.4
            (100, 900_005), // fork B: also post-epoch-3.4
        ]);

        let mode =
            StacksChainState::effective_squash_mode(SquashMode::TipOnly, 100, &headers, &sortdb);
        assert_eq!(
            mode,
            SquashMode::TipOnly,
            "both forks post-3.4 should allow TipOnly"
        );
    }

    /// Integration test: exercises the same config → mode → squash → verify
    /// sequence that `maybe_squash()` performs, including reading back the
    /// stored mode from the squash trailer.
    #[test]
    fn test_mode_selection_integration_config_to_squash_level() {
        use stacks_common::types::chainstate::StacksBlockId;

        use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
        use crate::chainstate::stacks::index::squash::{squash_level_incremental, SquashMode};
        use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
        use crate::chainstate::stacks::index::{trie_sql, MARFValue};

        let test_dir = format!(
            "/tmp/stacks-squash-tests/mode_selection_integration_{}",
            std::process::id()
        );
        if std::fs::metadata(&test_dir).is_ok() {
            std::fs::remove_dir_all(&test_dir).unwrap();
        }
        std::fs::create_dir_all(&test_dir).unwrap();

        // --- Simulate config plumbing ---
        // A node configured with marf_full_history = false (TipOnly default).
        let configured_mode = SquashMode::TipOnly;

        // --- Simulate epoch/header state: pre-epoch-3.4 range ---
        let sortdb = mock_sortdb_conn(Some(900_000));
        let headers = mock_headers_conn(&[(0, 800_000)]); // min_height=0 is pre-3.4

        // effective_squash_mode should force FullHistory for pre-3.4 range
        let clarity_mode =
            StacksChainState::effective_squash_mode(configured_mode, 0, &headers, &sortdb);
        assert_eq!(
            clarity_mode,
            SquashMode::FullHistory,
            "pre-3.4 range should force FullHistory even with TipOnly config"
        );

        // --- Build a real MARF and squash with the computed mode ---
        let marf_path = format!("{test_dir}/clarity.sqlite");
        let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true)
            .with_squash_mode(configured_mode);
        // Verify config plumbing: MARFOpenOpts carries the configured mode.
        assert_eq!(open_opts.squash_mode, SquashMode::TipOnly);

        let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts).unwrap();

        let num_blocks: usize = 10;
        let blocks: Vec<StacksBlockId> = (0..num_blocks)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[28..32].copy_from_slice(&((i as u32) + 1).to_be_bytes());
                StacksBlockId::from_bytes(&bytes).unwrap()
            })
            .collect();

        marf.begin(&StacksBlockId::sentinel(), &blocks[0]).unwrap();
        marf.insert("key", MARFValue::from_value("v0")).unwrap();
        marf.seal().unwrap();
        marf.commit().unwrap();

        for i in 1..num_blocks {
            marf.begin(&blocks[i - 1], &blocks[i]).unwrap();
            marf.insert("key", MARFValue::from_value(&format!("v{i}")))
                .unwrap();
            marf.seal().unwrap();
            marf.commit().unwrap();
        }

        let max_height = (num_blocks - 1) as u32;

        // Squash using the computed mode (as maybe_squash would)
        let stats = squash_level_incremental::<StacksBlockId>(
            &marf_path,
            clarity_mode, // FullHistory, forced by mode selection
            0,
            max_height,
            true,
            None,
        )
        .expect("squash should succeed");
        assert!(stats.nodes_collected > 0);

        // --- Verify: read back squash level metadata ---
        let levels = trie_sql::read_squash_levels(marf.sqlite_conn()).unwrap();
        assert_eq!(levels.len(), 1, "should have exactly one squash level");
        assert_eq!(levels[0].min_height, 0);
        assert_eq!(levels[0].max_height, max_height);

        // Re-open and verify historical reads work (FullHistory preserved history)
        drop(marf);
        let open_opts2 = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
        let mut marf = MARF::<StacksBlockId>::from_path(&marf_path, open_opts2).unwrap();

        // Historical read at block 0 should work (FullHistory preserved it)
        let val = marf
            .get(&blocks[0], "key")
            .expect("get should succeed")
            .expect("key should exist at block 0");
        // Tip read should also work
        let tip_val = marf
            .get(&blocks[num_blocks - 1], "key")
            .expect("get should succeed")
            .expect("key should exist at tip");
        // They should differ (key was updated every block)
        assert_ne!(val, tip_val, "historical and tip values should differ");
    }

    // -------------------------------------------------------------------
    // Pre-append squash-divergence guard regression tests
    //
    // Codex's review of the level-14 mainnet panic fix asked for a
    // chainstate-level test that proves a squash-boundary parent gets
    // re-anchored before the first above-level descendant is committed.
    // The MARF-level tests in `chainstate::stacks::index::test::squash`
    // already cover `re_squash_level` correctness; this test adds the
    // chainstate-level wiring: `assert_squash_consistency` walking the
    // chainstate's `block_headers` table to detect divergence, then
    // re-anchoring BOTH the headers MARF and the Clarity MARF in lockstep
    // via `re_squash_level`.
    //
    // The test does NOT drive the full block-processing pipeline (that
    // would require a TestPeer-style harness); instead it engineers the
    // exact mid-state the guard observes: a squash level recording one
    // canonical at the boundary, a `block_headers` view recording a
    // different canonical (chain reorg), and no above-level descendants
    // committed yet. The guard's job at that moment is to call
    // `assert_squash_consistency(parent_block_id, sortdb_conn)` and have
    // it succeed — exactly what's exercised below.
    // -------------------------------------------------------------------

    /// Insert a `block_headers` row with the minimum fields required for
    /// `detect_squash_divergence` to walk this block's ancestry. Non-essential
    /// columns get plausible-but-unused values; the row is sufficient to satisfy
    /// the schema's NOT NULL constraints and `lookup_height_and_parent`'s SELECT.
    #[cfg(test)]
    fn insert_test_block_header_minimal(
        conn: &Connection,
        index_block_hash: &StacksBlockId,
        parent_block_id: &StacksBlockId,
        block_height: u32,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) {
        use stacks_common::types::chainstate::VRFSeed;

        use crate::chainstate::stacks::TrieHash;

        let zero_hash = TrieHash([0u8; 32]);
        let zero_vrf = VRFSeed([0u8; 32]);
        let zero_block_hash = BlockHeaderHash([0u8; 32]);
        let pubkey_hash = stacks_common::util::hash::Hash160([0u8; 20]);
        let burn_hash = stacks_common::types::chainstate::BurnchainHeaderHash([0u8; 32]);

        // NOTE: `affirmation_weight` was dropped from the schema in a prior migration
        // (see migration to db version 11), so it is not in the INSERT despite being
        // listed in the original `CREATE TABLE` text in this file's source.
        conn.execute(
            "INSERT INTO block_headers (
                version, total_burn, total_work, proof, parent_block, parent_microblock,
                parent_microblock_sequence, tx_merkle_root, state_index_root,
                microblock_pubkey_hash, block_hash, index_block_hash, block_height,
                index_root, consensus_hash, burn_header_hash, burn_header_height,
                burn_header_timestamp, parent_block_id, cost, block_size
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20, ?21
            )",
            rusqlite::params![
                0i64,            // version
                "0",             // total_burn (TEXT)
                "0",             // total_work (TEXT)
                zero_vrf,        // proof
                zero_block_hash, // parent_block
                zero_block_hash, // parent_microblock
                0i64,            // parent_microblock_sequence
                zero_hash,       // tx_merkle_root
                zero_hash,       // state_index_root
                pubkey_hash,     // microblock_pubkey_hash
                block_hash,      // block_hash
                index_block_hash,
                block_height as i64,
                zero_hash,       // index_root
                consensus_hash,
                burn_hash,       // burn_header_hash
                0i64,            // burn_header_height
                0i64,            // burn_header_timestamp
                parent_block_id,
                "{\"write_length\":0,\"write_count\":0,\"read_length\":0,\"read_count\":0,\"runtime\":0}", // cost
                "0",             // block_size (TEXT)
            ],
        )
        .unwrap();
    }

    /// Direct unit test of `precompute_canonical_ancestors`: walk a synthetic chain inserted into
    /// `block_headers` and verify the loop terminates at exactly `tip_height - low_height + 1`
    /// steps with the right per-height contents. No MARF involved —
    /// `precompute_canonical_ancestors` only queries headers tables.
    #[test]
    fn test_precompute_canonical_ancestors_walks_exact_bound() {
        use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};

        let chainstate = instantiate_chainstate(false, 0x80000000, function_name!());

        let blk = |chr: u8, idx: u32| -> StacksBlockId {
            let mut bytes = [chr; 32];
            bytes[28..32].copy_from_slice(&idx.to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        };
        // Non-zero filler so generated `(consensus_hash, block_hash)` pairs don't collide with the
        // genesis row (which is all-zero).
        let bh = |id: u32| -> BlockHeaderHash {
            let mut bytes = [0xCCu8; 32];
            bytes[28..32].copy_from_slice(&id.to_be_bytes());
            BlockHeaderHash::from_bytes(&bytes).unwrap()
        };
        let chash = |id: u32| -> ConsensusHash {
            let mut bytes = [0xCCu8; 20];
            bytes[16..20].copy_from_slice(&id.to_be_bytes());
            ConsensusHash::from_bytes(&bytes).unwrap()
        };

        // Build a 50-block linear chain: heights 0..49. Block at height 0 points at the sentinel;
        // each subsequent block points at its predecessor.
        let blocks: Vec<StacksBlockId> = (0..50).map(|i| blk(0xCC, i)).collect();
        for height in 0..50u32 {
            let parent = if height == 0 {
                StacksBlockId::sentinel()
            } else {
                blocks[(height - 1) as usize].clone()
            };
            insert_test_block_header_minimal(
                chainstate.db(),
                &blocks[height as usize],
                &parent,
                height,
                &chash(height),
                &bh(height),
            );
        }

        // Full sweep: tip 49, low 0 → 50 entries, every height present.
        let map =
            StacksChainState::precompute_canonical_ancestors(chainstate.db(), &blocks[49], 49, 0)
                .expect("precompute should succeed on dense chain");
        assert_eq!(
            map.len(),
            50,
            "walk should visit exactly tip - low + 1 heights"
        );
        for height in 0..50u32 {
            assert_eq!(
                map.get(&height),
                Some(&blocks[height as usize]),
                "map[{height}] should be blocks[{height}]"
            );
        }

        // Partial sweep: low 30 → 20 entries, heights 30..=49 only.
        let map =
            StacksChainState::precompute_canonical_ancestors(chainstate.db(), &blocks[49], 49, 30)
                .expect("partial precompute should succeed");
        assert_eq!(map.len(), 20);
        for height in 30..50u32 {
            assert_eq!(map.get(&height), Some(&blocks[height as usize]));
        }
        assert!(
            map.get(&29).is_none(),
            "below-low heights are not populated"
        );

        // Pathological: low > tip → empty map (no walk).
        let map =
            StacksChainState::precompute_canonical_ancestors(chainstate.db(), &blocks[10], 10, 20)
                .expect("low > tip should not error");
        assert!(map.is_empty(), "low > tip yields empty map");
    }

    /// Truncated ancestry case: `block_headers` only contains heights 30..49, and the walk hits an
    /// unknown parent before reaching `low_height = 0`.
    ///
    /// The helper terminates with whatever it has built — no error — to match the legacy "ancestry
    /// unknowable from this chainstate" behavior.
    #[test]
    fn test_precompute_canonical_ancestors_terminates_on_truncated_ancestry() {
        use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};

        let chainstate = instantiate_chainstate(false, 0x80000000, function_name!());

        let blk = |chr: u8, idx: u32| -> StacksBlockId {
            let mut bytes = [chr; 32];
            bytes[28..32].copy_from_slice(&idx.to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        };
        let bh = |id: u32| -> BlockHeaderHash {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&id.to_be_bytes());
            BlockHeaderHash::from_bytes(&bytes).unwrap()
        };
        let chash = |id: u32| -> ConsensusHash {
            let mut bytes = [0u8; 20];
            bytes[16..20].copy_from_slice(&id.to_be_bytes());
            ConsensusHash::from_bytes(&bytes).unwrap()
        };

        // Insert blocks for heights 30..49 only. Block at height 30 has a parent_block_id pointing
        // at a non-existent ancestor (height 29's hash that we never insert), so the walk truncates
        // there.
        let blocks: Vec<StacksBlockId> = (30..50).map(|i| blk(0xDD, i)).collect();
        let phantom_parent = blk(0xDD, 29);
        for (idx, height) in (30..50u32).enumerate() {
            let parent = if idx == 0 {
                phantom_parent.clone()
            } else {
                blocks[idx - 1].clone()
            };
            insert_test_block_header_minimal(
                chainstate.db(),
                &blocks[idx],
                &parent,
                height,
                &chash(height),
                &bh(height),
            );
        }

        // Ask for low=0; walk truncates at height 30 (parent unknown).
        let map =
            StacksChainState::precompute_canonical_ancestors(chainstate.db(), &blocks[19], 49, 0)
                .expect("truncated ancestry should not error");
        // 30..49 = 20 entries; height 29 and below absent.
        assert_eq!(map.len(), 20, "truncated walk yields partial map");
        assert!(map.get(&29).is_none());
        assert_eq!(map.get(&30), Some(&blocks[0]));
        assert_eq!(map.get(&49), Some(&blocks[19]));
    }

    /// End-to-end regression for the walk-cap correctness fix: a small squash level (`min..max`
    /// span = 10 blocks) followed by a long open suffix (~50 blocks) with a divergent ancestor
    /// inside the level range.
    ///
    /// The pre-refactor walker capped at `4 × (level_span + 2) = 48` ancestor steps and would have
    /// returned a spurious "walk cap exhausted" error here (actual walk distance is 56). The new
    /// precompute helper walks exactly `tip_height - low_height + 1 = 61` steps and the divergence
    /// is detected cleanly.
    #[test]
    fn test_detect_squash_divergence_long_open_suffix_2x() {
        use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};

        use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
        use crate::chainstate::stacks::index::squash::squash_level_incremental;
        use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
        use crate::chainstate::stacks::index::MARFValue;

        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());

        let blk_a = |idx: u32| -> StacksBlockId {
            let mut bytes = [0xAA; 32];
            bytes[28..32].copy_from_slice(&idx.to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        };
        let blk_b = |idx: u32| -> StacksBlockId {
            let mut bytes = [0xBB; 32];
            bytes[28..32].copy_from_slice(&idx.to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        };
        let bh = |chr: u8, idx: u32| -> BlockHeaderHash {
            let mut bytes = [chr; 32];
            bytes[28..32].copy_from_slice(&idx.to_be_bytes());
            BlockHeaderHash::from_bytes(&bytes).unwrap()
        };
        let chash = |chr: u8, idx: u32| -> ConsensusHash {
            let mut bytes = [chr; 20];
            bytes[16..20].copy_from_slice(&idx.to_be_bytes());
            ConsensusHash::from_bytes(&bytes).unwrap()
        };

        // Build heights 0..9 of the original (to-be-squashed) canonical chain in the headers MARF.
        // Heights 0..4 will be shared with the post-reorg chain; heights 5..9 will be the diverged
        // tail recorded in the squash but absent from `block_headers` after the reorg.
        let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
        let headers_path = chainstate.state_index.get_db_path().to_string();
        {
            let mut marf = MARF::<StacksBlockId>::from_path(&headers_path, opts.clone()).unwrap();
            let mut commit = |parent: &StacksBlockId, child: &StacksBlockId, label: &str| {
                marf.begin(parent, child).unwrap();
                marf.insert("k", MARFValue::from_value(label)).unwrap();
                marf.seal().unwrap();
                marf.commit().unwrap();
            };
            commit(&StacksBlockId::sentinel(), &blk_a(0), "v0");
            for h in 1..10u32 {
                let parent = blk_a(h - 1);
                let child = blk_a(h);
                let label = format!("va{h}");
                commit(&parent, &child, &label);
            }
        }

        // Squash heights 0..=9 into level 0. FullHistory keeps historical reads usable but isn't
        // strictly required for this regression.
        squash_level_incremental::<StacksBlockId>(
            &headers_path,
            SquashMode::FullHistory,
            0,
            9,
            /* reclaim = */ true,
            None,
        )
        .expect("initial squash should succeed");
        chainstate.state_index.refresh_after_squash().unwrap();

        // Sanity: level metadata is what we expect — span 10, recorded canonical
        // block_a_0..block_a_9.
        let level = chainstate
            .state_index
            .latest_squash_level_canonical_chain()
            .expect("level should exist after squash");
        assert_eq!(level.min_height, 0);
        assert_eq!(level.max_height, 9);
        assert_eq!(level.block_hashes.len(), 10);
        assert_eq!(level.block_hashes[5], blk_a(5));

        // Populate `block_headers` for the post-reorg canonical chain:
        //   block_a_0 .. block_a_4   (heights 0..4, shared prefix)
        //   block_b_5                (height 5, parent = block_a_4 — the
        //                              divergence point)
        //   block_b_6 .. block_b_60  (heights 6..60, long open suffix)
        // block_a_5..block_a_9 are intentionally absent — chain has reorged.
        for h in 0..5u32 {
            let parent = if h == 0 {
                StacksBlockId::sentinel()
            } else {
                blk_a(h - 1)
            };
            insert_test_block_header_minimal(
                chainstate.db(),
                &blk_a(h),
                &parent,
                h,
                &chash(0xAA, h),
                &bh(0xAA, h),
            );
        }
        for h in 5..=60u32 {
            let parent = if h == 5 { blk_a(4) } else { blk_b(h - 1) };
            insert_test_block_header_minimal(
                chainstate.db(),
                &blk_b(h),
                &parent,
                h,
                &chash(0xBB, h),
                &bh(0xBB, h),
            );
        }

        // Detect divergence from the long-suffix tip. With the old walker (cap = (9-0+2)*4 = 44)
        // this would walk 44 steps from height 60 down to height ~16 — never entering the level
        // range — and surface as "walk cap exhausted." The new precompute walks all 61 steps and
        // the in-range comparison spots block_b_5 vs recorded block_a_5.
        let divergence = chainstate
            .detect_squash_divergence(&blk_b(60))
            .expect("precompute walk must not fail under long open suffix")
            .expect(
                "divergence expected: level recorded block_a_5 at height 5 but \
                 block_headers' tip ancestry has block_b_5",
            );
        assert_eq!(divergence.level_id, level.level_id);
        assert_eq!(divergence.diverging_height, 5);
        assert_eq!(divergence.recorded_canonical, blk_a(5));
        assert_eq!(divergence.new_canonical, blk_b(5));
    }

    /// Aligned long-suffix counterpart to the divergence test: identical 10-block level + 50-block
    /// open suffix shape, but the post-squash chain stays on the same lineage as the squash
    /// recorded.
    ///
    /// The new precompute walks the full 61 steps, every in-range height matches, and the detector
    /// returns `None`. Confirms the long-walk path is not over-eager about reporting a divergence
    /// when none exists.
    #[test]
    fn test_detect_squash_divergence_long_open_suffix_aligned_returns_none_2x() {
        use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};

        use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
        use crate::chainstate::stacks::index::squash::squash_level_incremental;
        use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
        use crate::chainstate::stacks::index::MARFValue;

        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());

        let blk_a = |idx: u32| -> StacksBlockId {
            let mut bytes = [0xAA; 32];
            bytes[28..32].copy_from_slice(&idx.to_be_bytes());
            StacksBlockId::from_bytes(&bytes).unwrap()
        };
        let bh = |idx: u32| -> BlockHeaderHash {
            let mut bytes = [0xAA; 32];
            bytes[28..32].copy_from_slice(&idx.to_be_bytes());
            BlockHeaderHash::from_bytes(&bytes).unwrap()
        };
        let chash = |idx: u32| -> ConsensusHash {
            let mut bytes = [0xAA; 20];
            bytes[16..20].copy_from_slice(&idx.to_be_bytes());
            ConsensusHash::from_bytes(&bytes).unwrap()
        };

        let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
        let headers_path = chainstate.state_index.get_db_path().to_string();
        {
            let mut marf = MARF::<StacksBlockId>::from_path(&headers_path, opts.clone()).unwrap();
            let mut commit = |parent: &StacksBlockId, child: &StacksBlockId, label: &str| {
                marf.begin(parent, child).unwrap();
                marf.insert("k", MARFValue::from_value(label)).unwrap();
                marf.seal().unwrap();
                marf.commit().unwrap();
            };
            commit(&StacksBlockId::sentinel(), &blk_a(0), "v0");
            for h in 1..10u32 {
                commit(&blk_a(h - 1), &blk_a(h), &format!("va{h}"));
            }
        }
        squash_level_incremental::<StacksBlockId>(
            &headers_path,
            SquashMode::FullHistory,
            0,
            9,
            /* reclaim = */ true,
            None,
        )
        .unwrap();
        chainstate.state_index.refresh_after_squash().unwrap();

        // Aligned chain in `block_headers`: blk_a(0)..blk_a(60), all on the same canonical lineage
        // as the squash.
        for h in 0..=60u32 {
            let parent = if h == 0 {
                StacksBlockId::sentinel()
            } else {
                blk_a(h - 1)
            };
            insert_test_block_header_minimal(
                chainstate.db(),
                &blk_a(h),
                &parent,
                h,
                &chash(h),
                &bh(h),
            );
        }

        assert!(chainstate
            .detect_squash_divergence(&blk_a(60))
            .expect("aligned long-suffix walk must not error")
            .is_none());
    }

    // ---------------------------------------------------------------------------
    // Cadence policy (Step 6): SquashCadenceConfig + should_squash predicate
    // ---------------------------------------------------------------------------

    /// `fixed_cadence(N)` collapses to "fire exactly when blocks_since == N":
    /// `min_blocks == max_blocks == N`, `work_target_bytes == u64::MAX`. The
    /// predicate is bit-identical to the historical hard-coded gate at every
    /// boundary: at `blocks_since == N` it fires, anywhere below it doesn't.
    #[test]
    fn test_should_squash_fixed_cadence_compatibility() {
        use crate::chainstate::stacks::index::marf::MarfSquashStats;
        let cfg = SquashCadenceConfig::fixed_cadence(1000);
        assert_eq!(cfg.min_blocks, 1000);
        assert_eq!(cfg.max_blocks, 1000);
        assert_eq!(cfg.work_target_bytes, u64::MAX);

        let zero_stats = MarfSquashStats {
            external_bytes_since_last_squash: 0,
        };
        let huge_stats = MarfSquashStats {
            external_bytes_since_last_squash: u64::MAX,
        };

        // Below the boundary: never fires regardless of work.
        assert!(!should_squash(&zero_stats, 999, &cfg, || true));
        assert!(!should_squash(&huge_stats, 999, &cfg, || true));
        // At and beyond the boundary: always fires.
        assert!(should_squash(&zero_stats, 1000, &cfg, || true));
        assert!(should_squash(&zero_stats, 5_000, &cfg, || true));
    }

    /// Work-aware policy: trigger fires when work_target is hit *and*
    /// `blocks_since >= min_blocks`. Below `min_blocks`, the floor blocks
    /// the trigger regardless of work — preventing "single-block storm"
    /// triggers that would produce tiny levels.
    #[test]
    fn test_should_squash_fires_on_work_target() {
        use crate::chainstate::stacks::index::marf::MarfSquashStats;
        let cfg = SquashCadenceConfig {
            work_target_bytes: 1_000_000,
            min_blocks: 100,
            max_blocks: 2000,
        };
        let work_hit = MarfSquashStats {
            external_bytes_since_last_squash: 1_000_000,
        };
        let work_below = MarfSquashStats {
            external_bytes_since_last_squash: 999_999,
        };

        // Floor active: even with work_target hit, we wait until min_blocks.
        assert!(!should_squash(&work_hit, 99, &cfg, || true));

        // Floor cleared, work_target hit → fires.
        assert!(should_squash(&work_hit, 100, &cfg, || true));
        assert!(should_squash(&work_hit, 500, &cfg, || true));

        // Floor cleared, work below target → holds off.
        assert!(!should_squash(&work_below, 100, &cfg, || true));
        assert!(!should_squash(&work_below, 1500, &cfg, || true));
    }

    /// Ceiling: regardless of work, force a squash once `blocks_since >=
    /// max_blocks`. This is the quiet-period backstop that keeps the open
    /// suffix bounded — also caps the divergence-detection precompute walk
    /// distance.
    #[test]
    fn test_should_squash_max_blocks_ceiling_fires() {
        use crate::chainstate::stacks::index::marf::MarfSquashStats;
        let cfg = SquashCadenceConfig {
            work_target_bytes: 1_000_000_000,
            min_blocks: 100,
            max_blocks: 2000,
        };
        let no_work = MarfSquashStats {
            external_bytes_since_last_squash: 0,
        };

        // Below ceiling, work below target: holds off.
        assert!(!should_squash(&no_work, 1999, &cfg, || true));
        // At/past ceiling: fires unconditionally, even with zero work.
        assert!(should_squash(&no_work, 2000, &cfg, || true));
        assert!(should_squash(&no_work, 10_000, &cfg, || true));
    }

    /// Floor below `min_blocks` blocks the trigger even with massive
    /// work_target overshoot. Regression guard: previous designs had this
    /// pass on work alone.
    #[test]
    fn test_should_squash_blocks_below_min_holds_off() {
        use crate::chainstate::stacks::index::marf::MarfSquashStats;
        let cfg = SquashCadenceConfig {
            work_target_bytes: 1024,
            min_blocks: 100,
            max_blocks: 2000,
        };
        let huge = MarfSquashStats {
            external_bytes_since_last_squash: u64::MAX,
        };
        for blocks_since in [0u32, 1, 50, 99] {
            assert!(
                !should_squash(&huge, blocks_since, &cfg, || true),
                "min_blocks floor must hold even with work_target massively exceeded \
                 at blocks_since={blocks_since}",
            );
        }
        // Boundary: fires exactly at min_blocks.
        assert!(should_squash(&huge, 100, &cfg, || true));
    }

    /// Bootstrap boundary regression: with no squash level yet,
    /// `maybe_squash`'s no-level fallback uses `blocks_since = tip_height`
    /// (NOT `tip_height + 1`). Combined with `fixed_cadence(N)`'s
    /// `min_blocks == max_blocks == N`, the first squash fires when
    /// `tip_height >= N` — matching the legacy `block_height % cadence == 0`
    /// gate's first fire at `block_height == N`.
    ///
    /// This is a unit test of the boundary math (the conversion lives in
    /// `maybe_squash`); we exercise it via the predicate at the same
    /// blocks_since values that the production path produces.
    #[test]
    fn test_should_squash_bootstrap_boundary_no_level_present() {
        use crate::chainstate::stacks::index::marf::MarfSquashStats;
        let cfg = SquashCadenceConfig::fixed_cadence(1000);
        let no_work = MarfSquashStats {
            external_bytes_since_last_squash: 0,
        };

        // No level yet: `blocks_since = tip_height`. At tip_height = 999, no
        // fire (legacy: `999 < 1000` → skip). At tip_height = 1000, fire
        // (legacy: `1000 % 1000 == 0` → fire).
        let blocks_since_at_999 = 999u32; // tip_height = 999, no level
        let blocks_since_at_1000 = 1000u32; // tip_height = 1000, no level

        assert!(
            !should_squash(&no_work, blocks_since_at_999, &cfg, || true),
            "no-level + tip_height=999 must NOT fire (matches legacy)"
        );
        assert!(
            should_squash(&no_work, blocks_since_at_1000, &cfg, || true),
            "no-level + tip_height=1000 MUST fire (matches legacy first-squash boundary)"
        );
    }

    // ---------------------------------------------------------------------------
    // v1.5 Phase B horizon predicate
    // ---------------------------------------------------------------------------

    /// Legacy mode (caller passes always-true horizon) preserves today's
    /// cadence behavior bit-for-bit. This is the load-bearing
    /// behavior-preservation property: every existing call site updated
    /// in B4 must observe identical pre-B4 outcomes.
    #[test]
    fn test_should_squash_legacy_horizon_passes_through_unchanged() {
        use crate::chainstate::stacks::index::marf::MarfSquashStats;
        let cfg = SquashCadenceConfig::fixed_cadence(1000);
        let stats = MarfSquashStats {
            external_bytes_since_last_squash: 0,
        };
        // With horizon = always true, behavior matches the
        // pre-horizon predicate exactly: < min_blocks → no fire,
        // >= max_blocks → fire.
        assert!(!should_squash(&stats, 999, &cfg, || true));
        assert!(should_squash(&stats, 1000, &cfg, || true));
    }

    /// Hot-tier mode with the horizon predicate failing (in-range)
    /// suppresses every squash regardless of cadence — the entire
    /// safety argument for v1.5.
    #[test]
    fn test_should_squash_horizon_defer_in_range_suppresses_squash() {
        use crate::chainstate::stacks::index::marf::MarfSquashStats;
        let cfg = SquashCadenceConfig::fixed_cadence(1000);
        let stats = MarfSquashStats {
            external_bytes_since_last_squash: u64::MAX,
        };
        // blocks_since past max_blocks: legacy would force-fire;
        // horizon predicate vetoes.
        assert!(!should_squash(&stats, 1000, &cfg, || false));
        assert!(!should_squash(&stats, 5000, &cfg, || false));
    }

    /// Hot-tier mode with the horizon predicate passing (past horizon)
    /// behaves like legacy: cadence rules apply normally.
    #[test]
    fn test_should_squash_horizon_allow_past_horizon_applies_cadence() {
        use crate::chainstate::stacks::index::marf::MarfSquashStats;
        let cfg = SquashCadenceConfig::fixed_cadence(1000);
        let stats = MarfSquashStats {
            external_bytes_since_last_squash: 0,
        };
        // Past horizon, cadence boundary still gates.
        assert!(!should_squash(&stats, 999, &cfg, || true));
        assert!(should_squash(&stats, 1000, &cfg, || true));
    }

    /// `min_blocks` short-circuits before the horizon check fires.
    /// This is intentional ordering — we don't pay for a horizon
    /// lookup when cadence would skip anyway.
    #[test]
    fn test_should_squash_min_blocks_short_circuits_before_horizon() {
        use crate::chainstate::stacks::index::marf::MarfSquashStats;
        let cfg = SquashCadenceConfig {
            work_target_bytes: 1_000_000,
            min_blocks: 100,
            max_blocks: 2000,
        };
        let stats = MarfSquashStats {
            external_bytes_since_last_squash: 1_000_000,
        };
        // Below min_blocks: predicate must short-circuit and never
        // call the horizon closure. Use a panicking closure to prove
        // it isn't invoked.
        let mut horizon_called = false;
        let result = should_squash(&stats, 99, &cfg, || {
            horizon_called = true;
            true
        });
        assert!(!result, "below min_blocks must not fire");
        assert!(
            !horizon_called,
            "horizon closure must not be invoked when min_blocks short-circuits",
        );
    }

    /// Forced trigger via `max_blocks` cannot bypass the horizon
    /// check — if the horizon predicate fails, the trigger defers
    /// even at `blocks_since == max_blocks`. This is the safety
    /// guarantee: a forced (work-bytes / max-blocks) trigger inside
    /// the horizon would re-introduce the level-34 hazard.
    #[test]
    fn test_should_squash_horizon_check_blocks_max_blocks_force_trigger() {
        use crate::chainstate::stacks::index::marf::MarfSquashStats;
        let cfg = SquashCadenceConfig::fixed_cadence(1000);
        let stats = MarfSquashStats {
            external_bytes_since_last_squash: 0,
        };
        // At max_blocks boundary, legacy would force-fire (bypassing
        // work_target_bytes). Horizon must still gate it.
        assert!(!should_squash(&stats, 1000, &cfg, || false));
        // Same blocks_since, horizon now passes → fire.
        assert!(should_squash(&stats, 1000, &cfg, || true));
    }

    // ---------------------------------------------------------------------------
    // B5c: compute_horizon_gated_max_height
    // ---------------------------------------------------------------------------

    /// Insert a block-headers row with custom `block_height` and
    /// `burn_header_height`. Mirrors `insert_test_block_header_minimal`
    /// but parameterizes the burn-height so we can exercise the
    /// horizon walk.
    #[cfg(test)]
    fn insert_test_block_header_with_burn_height(
        conn: &Connection,
        index_block_hash: &StacksBlockId,
        parent_block_id: &StacksBlockId,
        block_height: u32,
        burn_header_height: u32,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) {
        use stacks_common::types::chainstate::VRFSeed;

        use crate::chainstate::stacks::TrieHash;

        let zero_hash = TrieHash([0u8; 32]);
        let zero_vrf = VRFSeed([0u8; 32]);
        let zero_block_hash = BlockHeaderHash([0u8; 32]);
        let pubkey_hash = stacks_common::util::hash::Hash160([0u8; 20]);
        let burn_hash = stacks_common::types::chainstate::BurnchainHeaderHash([0u8; 32]);

        conn.execute(
            "INSERT INTO block_headers (
                version, total_burn, total_work, proof, parent_block, parent_microblock,
                parent_microblock_sequence, tx_merkle_root, state_index_root,
                microblock_pubkey_hash, block_hash, index_block_hash, block_height,
                index_root, consensus_hash, burn_header_hash, burn_header_height,
                burn_header_timestamp, parent_block_id, cost, block_size
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20, ?21
            )",
            rusqlite::params![
                0i64,
                "0",
                "0",
                zero_vrf,
                zero_block_hash,
                zero_block_hash,
                0i64,
                zero_hash,
                zero_hash,
                pubkey_hash,
                block_hash,
                index_block_hash,
                block_height as i64,
                zero_hash,
                consensus_hash,
                burn_hash,
                burn_header_height as i64,
                0i64,
                parent_block_id,
                "{\"write_length\":0,\"write_count\":0,\"read_length\":0,\"read_count\":0,\"runtime\":0}",
                "0",
            ],
        )
        .unwrap();
    }

    fn fake_blk(byte: u8) -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        StacksBlockId(bytes)
    }

    fn fake_bh(byte: u8) -> BlockHeaderHash {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        BlockHeaderHash(bytes)
    }

    fn fake_ch(byte: u8) -> ConsensusHash {
        let mut bytes = [0u8; 20];
        bytes[19] = byte;
        ConsensusHash::from_bytes(&bytes).unwrap()
    }

    /// Build a fresh chainstate, populate `block_headers` with a chain
    /// of N blocks with parameterizable burn-heights, and return the
    /// chainstate (for db access) + the canonical tip.
    fn build_chain_with_burn_heights(
        test_name: &str,
        burn_heights: &[u32],
    ) -> (StacksChainState, StacksBlockId) {
        let chainstate = instantiate_chainstate(false, 0x80000000, test_name);
        let conn = chainstate.db();
        let mut parent = StacksBlockId([0u8; 32]); // sentinel-ish
        let mut tip = parent.clone();
        for (i, &burn_height) in burn_heights.iter().enumerate() {
            let block = fake_blk((i + 1) as u8);
            insert_test_block_header_with_burn_height(
                conn,
                &block,
                &parent,
                i as u32,
                burn_height,
                &fake_ch((i + 1) as u8),
                &fake_bh((i + 1) as u8),
            );
            parent = block.clone();
            tip = block;
        }
        (chainstate, tip)
    }

    #[test]
    fn test_compute_horizon_gated_max_height_returns_tip_when_chain_is_old_enough() {
        // Build a chain at burn-heights 0, 5, 10, 15. With burn_tip = 100
        // and horizon = 6, target = 94. All blocks satisfy
        // burn_height ≤ 94, so the canonical tip's height (3) is
        // returned.
        let (chainstate, tip) = build_chain_with_burn_heights(function_name!(), &[0, 5, 10, 15]);
        let result = compute_horizon_gated_max_height_with_burn_tip(
            chainstate.db(),
            /* burn_tip */ 100,
            &tip,
            /* horizon */ 6,
        )
        .unwrap();
        assert_eq!(result, Some(3));
    }

    #[test]
    fn test_compute_horizon_gated_max_height_walks_back_to_first_block_past_horizon() {
        // Burn-heights: [0, 50, 95, 99]. With burn_tip = 100, horizon = 6,
        // target = 94. The walk from tip (burn 99) finds:
        //   - tip @ height 3, burn 99 → past target, walk parent
        //   - parent @ height 2, burn 95 → past target, walk parent
        //   - parent @ height 1, burn 50 → ≤ 94, return height 1
        let (chainstate, tip) = build_chain_with_burn_heights(function_name!(), &[0, 50, 95, 99]);
        let result = compute_horizon_gated_max_height_with_burn_tip(
            chainstate.db(),
            /* burn_tip */ 100,
            &tip,
            /* horizon */ 6,
        )
        .unwrap();
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_compute_horizon_gated_max_height_returns_none_when_chain_too_short() {
        // Single block at burn-height 99. With burn_tip = 100, horizon = 6,
        // target = 94. The walk finds tip past target, walks parent →
        // None (the parent_block_id is the sentinel/zero, not in the
        // headers table). Return None.
        let (chainstate, tip) = build_chain_with_burn_heights(function_name!(), &[99]);
        let result = compute_horizon_gated_max_height_with_burn_tip(
            chainstate.db(),
            /* burn_tip */ 100,
            &tip,
            /* horizon */ 6,
        )
        .unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_compute_horizon_gated_max_height_returns_none_when_burn_tip_below_horizon() {
        // Safety property: when `burn_tip < horizon`, no canonical
        // block can satisfy `burn_tip - burn_at(max) >= horizon`.
        // The correct answer is `None`, not `Some(0)`. A saturating-
        // sub would have silently approved any block at burn-height
        // 0 here — exactly the reorg-safety case horizon gating
        // exists to prevent.
        let (chainstate, tip) = build_chain_with_burn_heights(function_name!(), &[0, 5, 10]);
        let result = compute_horizon_gated_max_height_with_burn_tip(
            chainstate.db(),
            /* burn_tip */ 3,
            &tip,
            /* horizon */ 6,
        )
        .unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_compute_horizon_gated_max_height_handles_burn_tip_exactly_at_horizon() {
        // Boundary: burn_tip == horizon. Target = 0. A block at
        // burn-height 0 IS eligible (matches the
        // `burn_tip - burn_at >= horizon` predicate exactly).
        let (chainstate, tip) = build_chain_with_burn_heights(function_name!(), &[0, 3]);
        let result = compute_horizon_gated_max_height_with_burn_tip(
            chainstate.db(),
            /* burn_tip */ 6,
            &tip,
            /* horizon */ 6,
        )
        .unwrap();
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_compute_horizon_gated_max_height_returns_none_for_unknown_tip() {
        // canonical_tip not in block_headers → walk returns None
        // immediately.
        let chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        let unknown_tip = StacksBlockId([0xab; 32]);
        let result = compute_horizon_gated_max_height_with_burn_tip(
            chainstate.db(),
            /* burn_tip */ 100,
            &unknown_tip,
            /* horizon */ 6,
        )
        .unwrap();
        assert_eq!(result, None);
    }

    // ===========================================================================
    // Phase C C6: sweep_after_promotions dispatch coverage
    // ===========================================================================

    /// **Phase C dispatch coverage** (2026-05-02): exercises the
    /// [`StacksChainState::sweep_after_promotions`] dispatch path that `maybe_squash` invokes
    /// post-`poll_pending_promotions`. The inner `sweep_unlinkable_hot_files` loop has its own
    /// per-condition + scale tests in `index::hot_reclaim::tests` and `index::test::hot_reclaim`;
    /// this test pins the dispatch's two outer branches:
    ///
    /// 1. `reaped.any_promoted() == false` → method completes without panic. NOTE: this branch
    ///    has no externally-observable side effect even when the early-return regresses (the per-
    ///    MARF arms are gated on `reaped.headers_promoted` / `reaped.clarity_promoted` which are
    ///    both false), so the test only proves "default reaped is safe to pass," NOT "early-return
    ///    fires." A regression that removed the early return + relied on the per-arm guards would
    ///    pass this test. The early-return safety is enforced by code-review + the (cheap)
    ///    cost of the canonical-walk being skippable; observable pinning would require fault-
    ///    injection instrumentation we judged not worth the surface area.
    /// 2. `reaped.headers_promoted == true` against a chainstate that did NOT enable hot tier on
    ///    its headers MARF → `sweep_borrows()` returns `None` → the dispatch returns
    ///    `SweepStats::default()` for the headers arm + logs nothing (well below `is_noteworthy`).
    ///    Pins the "hot tier disabled" defensive branch end-to-end (the canonical-chain precompute
    ///    against the real chainstate `block_headers` table DOES fire here).
    ///
    /// Full-stack `maybe_squash` → `poll_pending_promotions` → `sweep_after_promotions` integration
    /// (with real promotions occurring on a hot-tier-enabled chainstate) is left as a Phase D
    /// follow-up — it requires multi-round promotion test infrastructure that doesn't exist today
    /// (per .docs/squashing-v1.5-phase-c.md §0.3 C6 divergence note).
    #[test]
    fn test_sweep_after_promotions_dispatch_short_circuits_and_handles_no_hot_tier() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        // Empty in-memory connection as the sortdb stub. `compute_horizon_gated_max_height` will
        // fail to read a canonical burn tip and return `Ok(None)` — the dispatch tolerates this.
        let sortdb_stub = rusqlite::Connection::open_in_memory().unwrap();
        // Pick the all-zeros tip — `block_height_for_sweep` will return `None` (not in headers),
        // exercising the dispatch's "tip not in headers" warn-and-return branch in branch 2.
        let canonical_tip = StacksBlockId([0u8; 32]);

        // Branch 1: nothing was reaped → method completes without panic. See doc comment above on
        // why this only proves "safe to call," not "early-return fires."
        chainstate.sweep_after_promotions(
            &canonical_tip,
            &sortdb_stub,
            PromotionsReaped::default(),
        );

        // Branch 2: headers reaped, but the test chainstate's headers MARF was NOT opened with hot
        // tier → sweep_borrows() returns None → headers arm yields default stats. The dispatch
        // logs nothing (default stats aren't is_noteworthy) and clarity arm is skipped (not
        // reaped). No panic = pass; this also exercises the canonical-chain precompute against the
        // real chainstate `block_headers` table (or, with the all-zeros tip, the tip-not-in-
        // headers warn-and-return branch).
        chainstate.sweep_after_promotions(
            &canonical_tip,
            &sortdb_stub,
            PromotionsReaped {
                headers_promoted: true,
                clarity_promoted: false,
            },
        );
    }

    /// Default chainstate construction wires the headers MARF to fixed
    /// cadence (sub-second squash; smoothing not worth the variance loss)
    /// and the Clarity MARF to a work-aware policy (64 MiB / 100..2000
    /// blocks) so the heavy MARF gets pause-amplitude smoothing on real
    /// workloads. Sidecar retention resolves to the legacy-equivalent
    /// block count under the default `MARFOpenOpts`. Guards against
    /// future refactors that drop the defaults silently.
    #[test]
    fn test_default_squash_cadence_config_matches_per_marf_defaults() {
        let chainstate = instantiate_chainstate(false, 0x80000000, function_name!());

        // Headers: fixed cadence at the legacy `MARF_SQUASH_CADENCE_BLOCKS`
        // boundary — preserves operator-meaningful "block-aligned" behavior.
        let expected_headers =
            SquashCadenceConfig::fixed_cadence(MARF_SQUASH_CADENCE_BLOCKS as u32);
        assert_eq!(chainstate.squash_cadence_headers, expected_headers);
        assert_eq!(
            chainstate.squash_cadence_headers,
            SquashCadenceConfig::default_headers()
        );

        // Clarity: work-aware. 64 MiB target, 100..2000 block window.
        let expected_clarity = SquashCadenceConfig {
            work_target_bytes: 64 * 1024 * 1024,
            min_blocks: 100,
            max_blocks: 2000,
        };
        assert_eq!(chainstate.squash_cadence_clarity, expected_clarity);
        assert_eq!(
            chainstate.squash_cadence_clarity,
            SquashCadenceConfig::default_clarity()
        );
        assert_ne!(
            chainstate.squash_cadence_clarity, expected_headers,
            "Clarity defaults must diverge from headers — that's the whole point of per-MARF policy"
        );

        // With `MARFOpenOpts::default()` the legacy field is
        // `MARF_ROOT_SNAPSHOT_RETENTION_LEVELS` and the new field is `None`,
        // so resolve_retention_blocks returns
        // `legacy * MARF_SQUASH_CADENCE_BLOCKS`.
        let expected_retention =
            (crate::chainstate::stacks::index::squash::MARF_ROOT_SNAPSHOT_RETENTION_LEVELS as u32)
                .saturating_mul(MARF_SQUASH_CADENCE_BLOCKS as u32);
        assert_eq!(
            chainstate.squash_sidecar_retention_blocks,
            expected_retention
        );

        // v1.5 Phase B: horizon defaults to 6 burn blocks (Bitcoin's
        // reorg-confirmation window plus margin) when no override is
        // provided via `MARFOpenOpts::squash_horizon_burn_blocks` and
        // the persisted `marf_state.horizon_burn_blocks` is at its
        // schema default.
        assert_eq!(
            chainstate.squash_horizon_burn_blocks, 6,
            "default horizon must be 6 burn blocks; bump intentionally if widening",
        );
    }

    /// `marf_state.horizon_burn_blocks` is the source of truth at
    /// chainstate-open time when no `MARFOpenOpts` override is set.
    /// Mutating the persisted value and re-opening must surface it.
    #[test]
    fn test_squash_horizon_resolves_from_marf_state_when_no_override() {
        // Bootstrap a fresh chainstate (writes the schema default,
        // horizon_burn_blocks = 6, into marf_state via the v5 migration).
        let chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        assert_eq!(
            chainstate.squash_horizon_burn_blocks, 6,
            "fresh chainstate must surface the schema-default horizon",
        );
        let headers_db_path = chainstate.state_index.get_db_path().to_string();
        // Drop the chainstate so we can re-open against a fresh handle.
        drop(chainstate);

        // Mutate the persisted horizon. Using a raw rusqlite handle
        // here mirrors what an ops calibration tool would do.
        {
            let conn = rusqlite::Connection::open(&headers_db_path).unwrap();
            conn.execute(
                "UPDATE marf_state SET horizon_burn_blocks = ?1 WHERE id = 1",
                rusqlite::params![12i64],
            )
            .unwrap();
        }

        // Re-open with no override; the chainstate must pick up the
        // persisted value.
        let reopened = open_chainstate(false, 0x80000000, function_name!());
        assert_eq!(
            reopened.squash_horizon_burn_blocks, 12,
            "re-opened chainstate must resolve horizon from marf_state",
        );
    }

    /// `MARFOpenOpts::squash_horizon_burn_blocks` overrides the
    /// persisted value when set — the test/ops escape hatch.
    #[test]
    fn test_squash_horizon_marf_opts_override_takes_precedence_over_marf_state() {
        // Bootstrap then mutate marf_state to a non-default value.
        let chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        let path = chainstate.root_path.clone();
        let headers_db_path = chainstate.state_index.get_db_path().to_string();
        drop(chainstate);

        {
            let conn = rusqlite::Connection::open(&headers_db_path).unwrap();
            conn.execute(
                "UPDATE marf_state SET horizon_burn_blocks = ?1 WHERE id = 1",
                rusqlite::params![12i64],
            )
            .unwrap();
        }

        // Open with an explicit override of 99 — must beat both the
        // persisted 12 and the hardcoded 6 fallback.
        let opts = MARFOpenOpts::default().with_squash_horizon_burn_blocks(Some(99));
        let (overridden, _) = StacksChainState::open(false, 0x80000000, &path, Some(opts)).unwrap();
        assert_eq!(
            overridden.squash_horizon_burn_blocks, 99,
            "explicit MARFOpenOpts override must take precedence over marf_state",
        );
    }

    // ===========================================================================
    // B5d-fu.2: Detached promotion-task spawn/poll lifecycle
    // ===========================================================================
    //
    // Unit tests for `join_finished_prepare` — the inner slot-management mechanism
    // `poll_pending_promotions` is built on. Real-chainstate end-to-end exercise of the dispatch
    // path is in `chainstate::stacks::index::test::squash_promote`.

    /// Synthetic prepare-worker payload variant. Maps to the slot's `JoinHandle` payload type
    /// without requiring a real MARF or `PreparedPromotion`.
    #[derive(Clone, Copy)]
    enum SyntheticPrepareOutcome {
        /// `Ok(None)` — prepare reported nothing-to-publish (post-recovery state).
        NothingToPublish,
        /// `Err(...)` — prepare returned an error.
        Errored,
    }

    /// Build a synthetic [`PromotionTaskHandle`] backed by a thread that returns the synthetic
    /// outcome after sleeping `delay_ms`. Used to drive the slot-polling logic without requiring
    /// a real MARF. Note: we don't synthesize `Ok(Some(prepared))` here — `PreparedPromotion`
    /// holds a real plan-file path that `apply_prepared_plan` would try to read; the publish
    /// path is exercised end-to-end in the squash-promote integration tests instead.
    fn synthetic_promotion_handle(
        label: &'static str,
        outcome: SyntheticPrepareOutcome,
        delay_ms: u64,
    ) -> PromotionTaskHandle {
        let join_handle = std::thread::Builder::new()
            .name(format!("test-promote-{label}"))
            .spawn(move || {
                if delay_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
                match outcome {
                    SyntheticPrepareOutcome::NothingToPublish => Ok(None),
                    SyntheticPrepareOutcome::Errored => Err(marf_error::CorruptionError(
                        "synthetic prepare error".into(),
                    )),
                }
            })
            .unwrap();
        PromotionTaskHandle {
            label,
            path: "/tmp/test".into(),
            join_handle,
        }
    }

    /// Spin until `is_finished()` flips, capped at ~1s. Returns when the worker has finished or
    /// after the timeout.
    fn wait_for_handle_finish(slot: &Option<PromotionTaskHandle>) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            if slot
                .as_ref()
                .map(|h| h.join_handle.is_finished())
                .unwrap_or(true)
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// `join_finished_prepare` on an empty slot returns `None` without contention.
    #[test]
    fn join_finished_prepare_returns_none_when_slot_empty() {
        let mut slot: Option<PromotionTaskHandle> = None;
        assert!(StacksChainState::join_finished_prepare(&mut slot).is_none());
        assert!(slot.is_none());
    }

    /// While a worker is in flight, polling returns `None` and leaves the slot populated. This
    /// is the load-bearing invariant for `maybe_squash`'s single-flight gating — without it, a
    /// still-running worker would be mis-reaped and the coordinator would either dispatch a
    /// duplicate or skip the eventual publish.
    #[test]
    fn join_finished_prepare_returns_none_while_worker_running() {
        let mut slot = Some(synthetic_promotion_handle(
            "running",
            SyntheticPrepareOutcome::NothingToPublish,
            200,
        ));
        // The worker sleeps 200ms; immediate poll must not drain.
        assert!(StacksChainState::join_finished_prepare(&mut slot).is_none());
        assert!(
            slot.is_some(),
            "slot must remain populated while worker runs"
        );
        // Wait for the worker to finish, then poll again.
        wait_for_handle_finish(&slot);
        let drained = StacksChainState::join_finished_prepare(&mut slot)
            .expect("worker has finished, expected payload");
        assert!(matches!(drained, Ok(None)));
        assert!(slot.is_none(), "slot must be drained after successful join");
    }

    /// A finished worker that reported `Ok(None)` (post-recovery, nothing to publish) is reaped
    /// and propagated to the caller. The publish gate then skips the publish for this MARF.
    #[test]
    fn join_finished_prepare_reaps_nothing_to_publish() {
        let mut slot = Some(synthetic_promotion_handle(
            "nothing",
            SyntheticPrepareOutcome::NothingToPublish,
            0,
        ));
        wait_for_handle_finish(&slot);
        let drained = StacksChainState::join_finished_prepare(&mut slot)
            .expect("worker has finished, expected payload");
        assert!(matches!(drained, Ok(None)));
        assert!(slot.is_none());
    }

    /// A finished worker that returned an error is reaped and its `Err` propagates so the
    /// publish gate logs and skips this MARF for the tick. The plan file (if any) remains on
    /// disk for next-open recovery.
    #[test]
    fn join_finished_prepare_reaps_errored_worker() {
        let mut slot = Some(synthetic_promotion_handle(
            "errored",
            SyntheticPrepareOutcome::Errored,
            0,
        ));
        wait_for_handle_finish(&slot);
        let drained = StacksChainState::join_finished_prepare(&mut slot)
            .expect("worker has finished, expected payload");
        assert!(drained.is_err());
        assert!(slot.is_none());
    }

    /// `join_finished_prepare` is idempotent at the slot level: once a worker has been drained,
    /// subsequent polls on the (now-empty) slot return `None`. Important because
    /// `poll_pending_promotions` can be called more than once per cadence tick (e.g. from an
    /// explicit drain on shutdown).
    #[test]
    fn join_finished_prepare_is_idempotent_after_drain() {
        let mut slot = Some(synthetic_promotion_handle(
            "once",
            SyntheticPrepareOutcome::NothingToPublish,
            0,
        ));
        wait_for_handle_finish(&slot);
        // First poll drains.
        assert!(StacksChainState::join_finished_prepare(&mut slot).is_some());
        // Second + third polls see the now-empty slot.
        assert!(StacksChainState::join_finished_prepare(&mut slot).is_none());
        assert!(StacksChainState::join_finished_prepare(&mut slot).is_none());
    }

    // -------------------------------------------------------------------
    // Per-epoch squash horizon tests
    //
    // The empirical floors come from two-archive analysis (see
    // `.docs/squash-horizon-per-epoch.md`). These tests pin the schedule
    // and the composition rules so a future "simplification" can't quietly
    // collapse the table back into a single constant.
    // -------------------------------------------------------------------

    /// Each epoch's observed max sibling-burn-spread, from the two-archive analysis.
    #[test]
    fn test_epoch_observed_max_burn_spread_matches_archive() {
        use stacks_common::types::StacksEpochId;
        let cases = [
            (StacksEpochId::Epoch20, 1649),
            (StacksEpochId::Epoch2_05, 35),
            (StacksEpochId::Epoch21, 10),
            (StacksEpochId::Epoch22, 3),
            (StacksEpochId::Epoch23, 146),
            (StacksEpochId::Epoch24, 116),
            (StacksEpochId::Epoch25, 7),
            (StacksEpochId::Epoch30, 0),
            (StacksEpochId::Epoch31, 0),
            (StacksEpochId::Epoch32, 0),
            (StacksEpochId::Epoch33, 0),
            (StacksEpochId::Epoch34, 0),
        ];
        for (epoch, expected) in cases {
            assert_eq!(
                StacksChainState::epoch_observed_max_burn_spread(epoch),
                expected,
                "epoch {epoch:?} observed-max mismatch"
            );
        }
    }

    /// Each epoch in the empirical schedule returns observed-max + padding.
    #[test]
    fn test_epoch_horizon_floor_known_epochs_equal_observed_plus_padding() {
        use stacks_common::types::StacksEpochId;
        let pad = StacksChainState::SQUASH_HORIZON_PADDING_BURN_BLOCKS;
        let cases = [
            StacksEpochId::Epoch20,
            StacksEpochId::Epoch2_05,
            StacksEpochId::Epoch21,
            StacksEpochId::Epoch22,
            StacksEpochId::Epoch23,
            StacksEpochId::Epoch24,
            StacksEpochId::Epoch25,
            StacksEpochId::Epoch30,
            StacksEpochId::Epoch31,
            StacksEpochId::Epoch32,
            StacksEpochId::Epoch33,
            StacksEpochId::Epoch34,
        ];
        for epoch in cases {
            let observed = StacksChainState::epoch_observed_max_burn_spread(epoch);
            let floor = StacksChainState::epoch_horizon_floor(epoch);
            assert_eq!(
                floor,
                observed + pad,
                "epoch {epoch:?}: floor={floor} should equal observed_max ({observed}) + pad ({pad})"
            );
        }
    }

    /// Pin the absolute floor values so a future change to `SQUASH_HORIZON_PADDING_BURN_BLOCKS`
    /// or to the observed-max table is loud and reviewable. If someone bumps the padding from
    /// 6 to e.g. 100 because of a new analysis, this test fails and forces the reviewer to
    /// confirm the new numbers are intentional.
    #[test]
    fn test_epoch_horizon_floor_absolute_values_today() {
        use stacks_common::types::StacksEpochId;
        let cases = [
            (StacksEpochId::Epoch20, 1655),
            (StacksEpochId::Epoch2_05, 41),
            (StacksEpochId::Epoch21, 16),
            (StacksEpochId::Epoch22, 9),
            (StacksEpochId::Epoch23, 152),
            (StacksEpochId::Epoch24, 122),
            (StacksEpochId::Epoch25, 13),
            (StacksEpochId::Epoch30, 6),
            (StacksEpochId::Epoch31, 6),
            (StacksEpochId::Epoch32, 6),
            (StacksEpochId::Epoch33, 6),
            (StacksEpochId::Epoch34, 6),
        ];
        for (epoch, expected) in cases {
            assert_eq!(
                StacksChainState::epoch_horizon_floor(epoch),
                expected,
                "epoch {epoch:?} should have floor {expected}"
            );
        }
    }

    /// Epoch10 is defined in the codebase but not in the empirical schedule; the family-based
    /// fallback (`< Epoch30`) routes it to the worst 2.x observed-max + padding.
    #[test]
    fn test_epoch_horizon_floor_epoch10_falls_back_to_pre30_conservative() {
        use stacks_common::types::StacksEpochId;
        let pad = StacksChainState::SQUASH_HORIZON_PADDING_BURN_BLOCKS;
        assert_eq!(
            StacksChainState::epoch_observed_max_burn_spread(StacksEpochId::Epoch10),
            1649,
            "Epoch10 (pre-2.0) should fall back to the worst 2.x observed-max"
        );
        assert_eq!(
            StacksChainState::epoch_horizon_floor(StacksEpochId::Epoch10),
            1649 + pad,
        );
    }

    /// `epoch_horizon` returns `configured.max(floor)` — operator's larger value wins, schedule
    /// floor wins when configured is smaller. Tests both directions for both a noisy 2.x epoch and
    /// a quiet Nakamoto epoch.
    #[test]
    fn test_epoch_horizon_preserves_operator_configured_via_max() {
        use stacks_common::types::StacksEpochId;
        // Quiet Nakamoto epoch: floor 6. Operator wants 1000 (extra paranoia) -> 1000 wins.
        assert_eq!(
            StacksChainState::epoch_horizon(StacksEpochId::Epoch30, 1000),
            1000,
            "configured > floor: configured wins"
        );
        // Same Nakamoto epoch with default-ish 6 -> floor wins (which equals 6).
        assert_eq!(
            StacksChainState::epoch_horizon(StacksEpochId::Epoch30, 6),
            6,
            "configured == floor: tied"
        );
        // Noisy 2.0 epoch: floor 1655 (= 1649 observed + 6 padding). Operator left default 6 ->
        // floor wins.
        assert_eq!(
            StacksChainState::epoch_horizon(StacksEpochId::Epoch20, 6),
            1655,
            "configured < floor: floor wins (preserves safety)"
        );
        // Same epoch with operator-configured 5000 -> configured wins.
        assert_eq!(
            StacksChainState::epoch_horizon(StacksEpochId::Epoch20, 5000),
            5000,
            "configured > floor (even on noisy epochs): configured wins"
        );
    }

    /// Build a synthetic `EpochList` for the per-archive boundaries used in the analysis. Burn
    /// heights are the actual mainnet epoch start/end values from `core/mod.rs`. Block-limit and
    /// network-epoch fields are zeroed — `max_horizon_over_burn_range` only inspects
    /// `start_height`, `end_height`, and `epoch_id`.
    fn synthetic_mainnet_epochs() -> crate::core::EpochList {
        use clarity::vm::costs::ExecutionCost;
        use stacks_common::types::{StacksEpoch, StacksEpochId};
        let mk = |epoch_id: StacksEpochId, start: u64, end: u64| StacksEpoch {
            epoch_id,
            start_height: start,
            end_height: end,
            block_limit: ExecutionCost::ZERO,
            network_epoch: 0,
        };
        crate::core::EpochList::from(vec![
            mk(StacksEpochId::Epoch20, 666050, 713000),
            mk(StacksEpochId::Epoch2_05, 713000, 781551),
            mk(StacksEpochId::Epoch21, 781551, 787651),
            mk(StacksEpochId::Epoch22, 787651, 788240),
            mk(StacksEpochId::Epoch23, 788240, 791551),
            mk(StacksEpochId::Epoch24, 791551, 840360),
            mk(StacksEpochId::Epoch25, 840360, 867867),
            mk(StacksEpochId::Epoch30, 867867, u64::MAX),
        ])
    }

    /// A burn-range fully inside one epoch returns that epoch's floor.
    #[test]
    fn test_max_horizon_over_burn_range_single_epoch() {
        let epochs = synthetic_mainnet_epochs();
        // Range fully inside Epoch20: floor = 1649 + 6 = 1655.
        assert_eq!(
            StacksChainState::max_horizon_over_burn_range(
                &epochs, 666_500, 700_000, /* configured */ 6
            ),
            1655,
            "fully-Epoch20 range yields Epoch20 floor"
        );
        // Range fully inside Epoch2_05: floor = 35 + 6 = 41.
        assert_eq!(
            StacksChainState::max_horizon_over_burn_range(&epochs, 720_000, 750_000, 6),
            41,
            "fully-Epoch2_05 range yields Epoch2_05 floor"
        );
        // Range fully inside Epoch30: floor = 0 + 6 = 6.
        assert_eq!(
            StacksChainState::max_horizon_over_burn_range(&epochs, 900_000, 950_000, 6),
            6,
            "fully-Epoch30 range yields the small Nakamoto floor"
        );
    }

    /// A burn-range spanning two epochs returns the **max** of their floors. This is the rule
    /// that prevents a level-spanning-2.0 from being squashed under 2.05's small horizon.
    #[test]
    fn test_max_horizon_over_burn_range_spans_2x_to_205_uses_max() {
        let epochs = synthetic_mainnet_epochs();
        // 666800..=720000 spans Epoch20 (1655) and Epoch2_05 (41). Max wins.
        let result = StacksChainState::max_horizon_over_burn_range(&epochs, 666_800, 720_000, 6);
        assert_eq!(
            result, 1655,
            "span Epoch20→Epoch2_05 must use max (Epoch20's 1655), not min (41)"
        );
    }

    /// A range spanning multiple 2.x epochs returns the worst floor among them. The worst
    /// observed in 2.x was Epoch20 at 1655 (1649 + 6 padding).
    #[test]
    fn test_max_horizon_over_burn_range_spans_all_2x_uses_max() {
        let epochs = synthetic_mainnet_epochs();
        // Spans 2.0 through 2.5 (and a sliver of 3.0).
        let result = StacksChainState::max_horizon_over_burn_range(&epochs, 666_100, 870_000, 6);
        assert_eq!(
            result, 1655,
            "spanning all 2.x must yield the worst 2.x floor (Epoch20=1655)"
        );
    }

    /// A post-3.0 range should yield the small Nakamoto floor regardless of configured value
    /// equal to or smaller than 6.
    #[test]
    fn test_max_horizon_over_burn_range_post_3_0_uses_small_floor() {
        let epochs = synthetic_mainnet_epochs();
        // Fully inside Epoch30, `configured = 1`: floor (6) still wins.
        assert_eq!(
            StacksChainState::max_horizon_over_burn_range(&epochs, 870_000, 950_000, 1),
            6
        );
    }

    /// Operator-configured larger value wins even when the underlying epoch floor is small. Tests
    /// the floor-vs-replacement rule end-to-end through `max_horizon_over_burn_range`.
    #[test]
    fn test_max_horizon_over_burn_range_configured_overrides_small_floors() {
        let epochs = synthetic_mainnet_epochs();
        // Inside Epoch30 (floor 6) with operator-configured 1000.
        assert_eq!(
            StacksChainState::max_horizon_over_burn_range(&epochs, 870_000, 950_000, 1000),
            1000,
            "configured 1000 must win over Epoch30 floor of 6"
        );
        // Configured 1000 is bigger than Epoch2_05's floor of 41, but smaller than Epoch20's
        // floor of 1655. The max-over-overlapped-epochs rule should pick 1655 when spanning 2.0.
        assert_eq!(
            StacksChainState::max_horizon_over_burn_range(&epochs, 666_800, 720_000, 1000),
            1655,
            "Epoch20's floor (1655) wins over configured (1000) and Epoch2_05's floor (41)"
        );
    }

    /// Empty epoch list yields the configured value as a defensive fallback. In practice the
    /// chain epochs cover the whole burn axis, so this only fires under malformed test setups.
    #[test]
    fn test_max_horizon_over_burn_range_empty_epoch_list_returns_configured() {
        let empty = crate::core::EpochList::from(Vec::new());
        assert_eq!(
            StacksChainState::max_horizon_over_burn_range(&empty, 100, 200, 42),
            42
        );
    }
}
