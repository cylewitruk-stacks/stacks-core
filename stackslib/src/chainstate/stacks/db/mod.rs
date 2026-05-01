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

/// Decide whether a squash should fire for a single MARF. Pure function of
/// the per-MARF stats snapshot, the height-span since the last published
/// squash level, and the cadence config.
///
/// `blocks_since_last_squash` is height-span (`canonical_tip_height -
/// latest_level.max_height`), not commit count — see
/// `.docs/adaptive-squash-cadence.md` §2.4 for why height-span is the
/// operator-meaningful unit.
pub fn should_squash(
    stats: &crate::chainstate::stacks::index::marf::MarfSquashStats,
    blocks_since_last_squash: u32,
    cfg: &SquashCadenceConfig,
) -> bool {
    if blocks_since_last_squash < cfg.min_blocks {
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
    /// This is the Stacks epoch that the block was evaluated in,
    /// which is the Stacks epoch that this block's parent was elected
    /// in.
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

    pub fn open_and_exec(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
        boot_data: Option<&mut ChainStateBootData>,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<(StacksChainState, Vec<StacksTransactionReceipt>), Error> {
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

    pub fn config(&self) -> DBConfig {
        DBConfig {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            version: CHAINSTATE_VERSION.to_string(),
        }
    }

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

    /// Probe whether *any* committed `marf_data` block exists at a height strictly greater than
    /// `level_max_height`, regardless of which chain it descends from.
    ///
    /// This is the load-bearing safety check for `re_squash_level`. A prior formulation walked
    /// branch-descendants of `divergence.recorded_canonical` and `divergence.new_canonical`, but
    /// that's insufficient: it misses the case where the actual post-squash committed blocks
    /// descend through a *third* block at the diverging height (e.g. a competing sibling that
    /// became canonical after the squash recorded a different block). The trailer's recorded
    /// canonical can also be phantom-unrooted if the original `find_tip_block` heuristic picked a
    /// non-canonical fork tip whose chain has since been pruned, in which case neither branch walk
    /// finds anything but real descendants of the actual chain do exist. The any-above-level check
    /// below catches all of those cases uniformly with a single indexed SQL query.
    ///
    /// The query joins `marf_data` against both `block_headers` (Stacks 2.x) and
    /// `nakamoto_block_headers` (Nakamoto) on `index_block_hash` ⇄ `marf_data.block_hash`, filters
    /// to heights strictly above the level, and requires `external_length > 0` (i.e. the block has
    /// real blob data — not pruned to zero by an earlier reclaim). Any row matching means a
    /// committed block above the level has Patches/backpointers into the old merged blob's address
    /// space; re-squashing would invalidate those.
    ///
    /// Returns the first matching `(block_height, index_block_hash)` for diagnostics, or `None` if
    /// no such block exists.
    pub fn first_committed_block_above_level(
        &self,
        level_max_height: u32,
    ) -> Result<Option<(u32, StacksBlockId)>, Error> {
        let conn = self.db();
        // `md.unconfirmed = 0` filters out unconfirmed mempool tries — those are in-progress writes
        // that haven't been committed and aren't load- bearing for the safety invariant. Existing
        // committed-block checks elsewhere in this codebase apply the same filter; matching the
        // convention here keeps the invariant explicit.
        let row = conn
            .query_row(
                "SELECT bh.block_height, md.block_hash FROM marf_data md \
                 JOIN block_headers bh ON bh.index_block_hash = md.block_hash \
                 WHERE bh.block_height > ?1 AND md.external_length > 0 \
                 AND md.unconfirmed = 0 \
                 LIMIT 1",
                params![level_max_height as i64],
                |r| Ok((r.get::<_, i64>(0)? as u32, r.get::<_, StacksBlockId>(1)?)),
            )
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        if let Some(found) = row {
            return Ok(Some(found));
        }
        let row = conn
            .query_row(
                "SELECT nbh.block_height, md.block_hash FROM marf_data md \
                 JOIN nakamoto_block_headers nbh ON nbh.index_block_hash = md.block_hash \
                 WHERE nbh.block_height > ?1 AND md.external_length > 0 \
                 AND md.unconfirmed = 0 \
                 LIMIT 1",
                params![level_max_height as i64],
                |r| Ok((r.get::<_, i64>(0)? as u32, r.get::<_, StacksBlockId>(1)?)),
            )
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        Ok(row)
    }

    /// Same load-bearing safety check as [`Self::first_committed_block_above_level`], but for the
    /// **Clarity MARF**: probe whether any committed `marf_data` block in the *Clarity* DB has a
    /// height (resolved via the chainstate's headers tables) strictly greater than
    /// `level_max_height`.
    ///
    /// Why a separate helper: the headers MARF's `marf_data` lives in the chainstate DB alongside
    /// `block_headers` / `nakamoto_block_headers`, so the existing helper does the height check in
    /// a single-DB join. The Clarity MARF's `marf_data` lives in a separate sqlite file, so we
    /// can't do a direct join. Strategy: pull confirmed Clarity-MARF block_hashes once, then look
    /// each one up in the chainstate's headers tables. Bounded in practice by the open suffix
    /// (max ~`max_blocks` Clarity commits per cadence) plus any preserved fork rows; recovery is
    /// rare so the per-row lookup cost is acceptable.
    ///
    /// Returns the first matching `(block_height, index_block_hash)` for diagnostics, or `None` if
    /// no such block exists.
    pub fn first_committed_clarity_block_above_level(
        &mut self,
        level_max_height: u32,
    ) -> Result<Option<(u32, StacksBlockId)>, Error> {
        // Step 1: collect the confirmed Clarity-MARF block_hashes. Done inside `with_marf` so the
        // borrow of the Clarity MARF's connection doesn't outlive the closure.
        let clarity_block_hashes: Vec<StacksBlockId> =
            self.clarity_state.with_marf(|clarity_marf| {
                let conn = clarity_marf.sqlite_conn();
                let mut stmt = conn
                    .prepare(
                        "SELECT block_hash FROM marf_data \
                         WHERE external_length > 0 AND unconfirmed = 0",
                    )
                    .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
                let rows = stmt
                    .query_map(NO_PARAMS, |r| r.get::<_, StacksBlockId>(0))
                    .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
                let collected: Result<Vec<StacksBlockId>, _> = rows.collect();
                collected.map_err(|e| Error::DBError(db_error::SqliteError(e)))
            })?;

        // Step 2: for each, resolve height via the chainstate's headers tables and filter.
        let conn = self.db();
        for bhh in clarity_block_hashes {
            if let Some((height, _parent)) = Self::lookup_height_and_parent(conn, &bhh)? {
                if height > level_max_height {
                    return Ok(Some((height, bhh)));
                }
            }
        }
        Ok(None)
    }

    /// Run divergence detection + safety check on the just-advanced tip. On detected divergence,
    /// attempt automatic recovery via the live-handle [`MARF::re_squash`] method on **whichever
    /// MARF(s) actually diverged**. With per-MARF cadence (Step 6), headers and Clarity squash
    /// independently — their level structures are no longer guaranteed to align — so detection
    /// and recovery run separately for each MARF.
    ///
    /// The shared work is the precompute: a single `precompute_canonical_ancestors` walk covering
    /// the union of both MARFs' level ranges builds one `height -> canonical` map that backs each
    /// MARF's `detect_divergence` closure.
    ///
    /// Recovery is anchored to `new_tip` so it doesn't redo the original `find_tip_block`
    /// heuristic the recovery is correcting for. Recovery deliberately does NOT trim sidecars —
    /// recovery often runs *because* of a Bitcoin reorg, exactly when retained sidecars are most
    /// valuable (design §3.5.4 #4).
    ///
    /// Returns `Ok(())` if the chain's view of canonical history is consistent OR if all detected
    /// divergences recovered cleanly.
    ///
    /// **Fail-stop on BLOCKED recovery.** If any MARF's safety check fails (a committed
    /// `marf_data` block exists strictly above the diverging level's `max_height`), the
    /// chainstate is unrecoverable in-process — the heavy child-trie backptr update path that
    /// would rewrite above-level descendants is explicitly out of scope. The function panics with
    /// the operator-recovery message ("wipe and re-sync") rather than returning Err, because
    /// returning Err here used to let the coordinator log a WARN and continue, then panic deep
    /// inside `MarfedKV::begin` with a noisier symptom hiding the real diagnostic.
    pub fn assert_squash_consistency(
        &mut self,
        new_tip: &StacksBlockId,
        sortdb_conn: &Connection,
    ) -> Result<(), Error> {
        self.assert_squash_consistency_with_prospective(new_tip, None, sortdb_conn)
    }

    /// Pre-append variant of [`Self::assert_squash_consistency`] that also accepts the
    /// prospective `(block_id, height)` of a block about to be committed but not yet present in
    /// `block_headers` / `nakamoto_block_headers`.
    ///
    /// **Why this is needed.** The pre-append guards in `process_next_staging_block` and
    /// `process_next_ready_nakamoto_block` call this on the *parent* of the block being
    /// appended (the new block isn't in headers yet, so a parent-anchored ancestry walk is the
    /// only one available from headers tables alone). That walk catches divergences whose
    /// leading edge is *some ancestor* of the parent — but it cannot catch the case where the
    /// just-about-to-append block IS the leading edge of divergence (i.e. its parent matches
    /// recorded canonical at the parent's height, but the new block at `parent_height + 1`
    /// disagrees with `recorded[parent_height + 1]`). Without seeding the prospective entry,
    /// that case slips through the guard, gets committed by `append_block`, and only fires from
    /// the post-append `assert_squash_consistency` in the coordinator — by which time the
    /// safety check (`first_committed_block_above_level`) may refuse recovery and the chainstate
    /// fail-stops.
    ///
    /// Seeding the prospective entry into the precomputed `height -> canonical` map plugs the
    /// hole: the existing per-MARF `detect_divergence` closure now sees the new block at its own
    /// height and surfaces the divergence before `append_block` runs. When passed `None`, this
    /// is the post-append behavior — no change.
    pub fn assert_squash_consistency_with_prospective(
        &mut self,
        new_tip: &StacksBlockId,
        prospective: Option<(StacksBlockId, u32)>,
        sortdb_conn: &Connection,
    ) -> Result<(), Error> {
        use crate::chainstate::stacks::index::squash::SquashMode;

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
        let mut canonical_map = Self::precompute_canonical_ancestors(
            self.db(),
            new_tip,
            tip_height,
            low_height,
        )?;

        // Seed the prospective new block at its own height, if one was supplied. This is what
        // closes the parent-anchored walk's blind spot for the leading-edge divergence case
        // described on the wrapping doc comment.
        let prospective_height = prospective.as_ref().map(|(_, h)| *h);
        if let Some((prospective_block, prospective_height)) = prospective {
            canonical_map.insert(prospective_height, prospective_block);
        }

        // Helper: true when a detected divergence is the *leading edge* — i.e. the prospective
        // block IS the first block on the new fork to disagree with recorded canonical. In that
        // case, automatic re-squash recovery is unsafe because the prospective block isn't yet
        // in `block_headers`/`nakamoto_block_headers` or the MARF, so `re_squash` has nothing to
        // anchor on. We still run the safety check (above-level-descendants → fail-stop), but
        // we defer recovery itself to the post-append `assert_squash_consistency` call in the
        // coordinator — by that point the block is durable and `re_squash(new_tip)` works.
        let is_leading_edge = |diverging_height: u32| -> bool {
            prospective_height
                .map(|p| p == diverging_height)
                .unwrap_or(false)
        };

        // --- Headers MARF: detect + recover independently ---
        //
        // Detection: closure-backed `MARF::detect_divergence` against the precomputed map.
        // Cost: O(level_span) HashMap lookups, microseconds.
        let headers_div = self.state_index.detect_divergence(
            |h: u32| -> Result<Option<StacksBlockId>, marf_error> {
                Ok(canonical_map.get(&h).cloned())
            },
        )?;
        if let Some(div) = headers_div {
            // Safety: re-squash is safe only when no committed `marf_data` block in the headers
            // MARF sits above the diverging level's `max_height`. Any such block has
            // Patches/backpointers into the level's old merged blob address space; re-squashing
            // remaps that space, and rewriting those descendants is out of scope.
            //
            // Look up the level's `max_height` directly from the durable SQL row rather than
            // re-querying via `latest_squash_level_canonical_chain` — the level may be a stub
            // (canonical_chain returns None for those) but the SQL row still has the range.
            let level_max_height = self
                .state_index
                .latest_squash_level_range()
                .map(|r| r.max_height)
                .ok_or_else(|| {
                    Error::DBError(db_error::Other(format!(
                        "Headers MARF squash divergence detected for level_id={} but \
                         latest squash range disappeared before recovery",
                        div.level_id
                    )))
                })?;
            if let Some((descendant_height, descendant_block)) =
                self.first_committed_block_above_level(level_max_height)?
            {
                let msg = format!(
                    "Headers MARF squash divergence detected: level_id={} recorded {} as \
                     canonical at height {}, but chain has reorg'd to {}. \
                     Recovery is BLOCKED: committed marf_data block {} at height {} \
                     (above level max height {}) has Patches/backpointers into the level's \
                     old merged blob address space. Re-squashing would invalidate those \
                     backpointers (the heavy child-trie update path is out of scope). \
                     Operator-recovery: wipe the chainstate and re-sync from a peer.",
                    div.level_id,
                    div.recorded_canonical,
                    div.diverging_height,
                    div.new_canonical,
                    descendant_block,
                    descendant_height,
                    level_max_height,
                );
                error!("{msg}");
                panic!(
                    "FATAL: headers MARF squash divergence with committed descendants — \
                     chainstate is unrecoverable, operator must wipe and re-sync.\n{msg}"
                );
            }
            if is_leading_edge(div.diverging_height) {
                info!(
                    "Headers MARF squash divergence detected pre-append at level_id={}: \
                     recorded {} as canonical at height {}, prospective new block is {}. \
                     Safety check passed (no committed descendants); deferring recovery to \
                     post-append `assert_squash_consistency` once the new block is durable.",
                    div.level_id,
                    div.recorded_canonical,
                    div.diverging_height,
                    div.new_canonical,
                );
            } else {
                info!(
                    "Headers MARF squash divergence detected at level_id={}: recorded {} as \
                     canonical at height {}, chain has reorg'd to {}. Recovery is safe \
                     (no committed descendants). Re-squashing headers MARF.",
                    div.level_id,
                    div.recorded_canonical,
                    div.diverging_height,
                    div.new_canonical,
                );
                // Headers MARF is always TipOnly (no at-block reads target it). Anchor recovery
                // to the chainstate's current canonical tip via the live-handle method. The
                // method handles its own post-publish sync; no separate `refresh_after_squash`
                // needed.
                self.state_index.re_squash(
                    div.level_id,
                    SquashMode::TipOnly,
                    true,
                    new_tip.clone(),
                )?;
                info!(
                    "Headers MARF squash divergence recovery complete: level_id={} now \
                     reflects new canonical {} at height {}.",
                    div.level_id, div.new_canonical, div.diverging_height,
                );
            }
        }

        // --- Clarity MARF: detect + recover independently ---
        //
        // Same precomputed map, but the safety check is cross-DB (Clarity's marf_data lives in a
        // separate sqlite file from chainstate's headers tables). The Clarity-specific helper
        // joins them iteratively.
        let clarity_div = self
            .clarity_state
            .with_marf(|m| m.detect_divergence(|h: u32| Ok(canonical_map.get(&h).cloned())))?;
        if let Some(div) = clarity_div {
            let level_max_height = self
                .clarity_state
                .with_marf(|m| m.latest_squash_level_range())
                .map(|r| r.max_height)
                .ok_or_else(|| {
                    Error::DBError(db_error::Other(format!(
                        "Clarity MARF squash divergence detected for level_id={} but \
                         latest squash range disappeared before recovery",
                        div.level_id
                    )))
                })?;
            if let Some((descendant_height, descendant_block)) =
                self.first_committed_clarity_block_above_level(level_max_height)?
            {
                let msg = format!(
                    "Clarity MARF squash divergence detected: level_id={} recorded {} as \
                     canonical at height {}, but chain has reorg'd to {}. \
                     Recovery is BLOCKED: committed Clarity marf_data block {} at height {} \
                     (above level max height {}) has Patches/backpointers into the level's \
                     old merged blob address space. Re-squashing would invalidate those \
                     backpointers (the heavy child-trie update path is out of scope). \
                     Operator-recovery: wipe the chainstate and re-sync from a peer.",
                    div.level_id,
                    div.recorded_canonical,
                    div.diverging_height,
                    div.new_canonical,
                    descendant_block,
                    descendant_height,
                    level_max_height,
                );
                error!("{msg}");
                panic!(
                    "FATAL: Clarity MARF squash divergence with committed descendants — \
                     chainstate is unrecoverable, operator must wipe and re-sync.\n{msg}"
                );
            }
            if is_leading_edge(div.diverging_height) {
                info!(
                    "Clarity MARF squash divergence detected pre-append at level_id={}: \
                     recorded {} as canonical at height {}, prospective new block is {}. \
                     Safety check passed (no committed descendants); deferring recovery to \
                     post-append `assert_squash_consistency` once the new block is durable.",
                    div.level_id,
                    div.recorded_canonical,
                    div.diverging_height,
                    div.new_canonical,
                );
            } else {
                info!(
                    "Clarity MARF squash divergence detected at level_id={}: recorded {} as \
                     canonical at height {}, chain has reorg'd to {}. Recovery is safe \
                     (no committed descendants). Re-squashing Clarity MARF.",
                    div.level_id,
                    div.recorded_canonical,
                    div.diverging_height,
                    div.new_canonical,
                );
                // Clarity MARF mode depends on configured preference + epoch 3.4 boundary,
                // mirroring `maybe_squash`'s clarity-side mode selection.
                let configured = self
                    .marf_opts
                    .as_ref()
                    .map(|o| o.squash_mode)
                    .unwrap_or(SquashMode::TipOnly);
                let clarity_min = self
                    .clarity_state
                    .with_marf(|m| Self::squash_min_height_for_marf(m));
                let clarity_mode =
                    Self::effective_squash_mode(configured, clarity_min, self.db(), sortdb_conn);
                self.clarity_state.with_marf(|m| {
                    m.re_squash(div.level_id, clarity_mode, true, new_tip.clone())
                })?;
                info!(
                    "Clarity MARF squash divergence recovery complete: level_id={} now \
                     reflects new canonical {} at height {}.",
                    div.level_id, div.new_canonical, div.diverging_height,
                );
            }
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
    /// matching the legacy first-fire boundary) and Clarity on the work-aware
    /// `default_clarity()` policy (64 MiB / 100..2000 blocks) so the heavy MARF gets pause-
    /// amplitude smoothing on real workloads.
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
    ///   burn-height boundary for mode selection.
    pub fn maybe_squash(
        &mut self,
        block_height: u64,
        canonical_tip: StacksBlockId,
        sortdb_conn: &Connection,
    ) {
        use std::thread;

        use crate::chainstate::stacks::index::squash::{
            create_stub_level, SquashMode, STUB_THRESHOLD,
        };

        let tip_height = block_height as u32;

        // --- Phase 0: Per-MARF cadence predicate ---
        //
        // Headers and Clarity each have their own `SquashCadenceConfig`. By default headers
        // runs on `fixed_cadence(MARF_SQUASH_CADENCE_BLOCKS)` and Clarity on the work-aware
        // `default_clarity()` policy. Compute height-span from each MARF's latest level and
        // consult `should_squash`.
        //
        // Bootstrap boundary: when no level exists yet, `blocks_since = tip_height` (NOT
        // `tip_height + 1`). The legacy fixed-cadence gate fired the first squash at
        // `block_height == cadence` (e.g. height 1000 for the default), spanning heights
        // `[0..=1000]` — that's 1001 committed blocks but `tip_height = 1000`. Using `tip_height`
        // here lines up the predicate's `>= max_blocks` check with the legacy fire point bit-for-
        // bit. After that first squash, `latest_level.max_height = tip_height`, so subsequent
        // calls take the `Some` branch and the same `tip - max_height` math drives the cadence.
        let headers_blocks_since = self
            .state_index
            .latest_squash_level_range()
            .map(|r| tip_height.saturating_sub(r.max_height))
            .unwrap_or(tip_height);
        let clarity_blocks_since = self
            .clarity_state
            .with_marf(|m| m.latest_squash_level_range())
            .map(|r| tip_height.saturating_sub(r.max_height))
            .unwrap_or(tip_height);

        let headers_stats = self.state_index.stats();
        let clarity_stats = self.clarity_state.with_marf(|m| m.stats());

        let headers_should_squash = should_squash(
            &headers_stats,
            headers_blocks_since,
            &self.squash_cadence_headers,
        );
        let clarity_should_squash = should_squash(
            &clarity_stats,
            clarity_blocks_since,
            &self.squash_cadence_clarity,
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

        // --- Phase 1: Plan both MARFs (sequential, fast) ---

        let retention_blocks = self.squash_sidecar_retention_blocks;

        // Headers MARF: always TipOnly (no at-block reads target the headers MARF).
        let headers_plan = if headers_should_squash {
            Some(SquashPlan {
                label: "headers",
                path: self.state_index.get_db_path().to_string(),
                tip_height,
                min_height: Self::squash_min_height_for(&self.state_index),
                mode: SquashMode::TipOnly,
                canonical_tip: canonical_tip.clone(),
            })
        } else {
            None
        };

        // Clarity MARF: read path + current min in one `with_marf` borrow. Only resolve when this
        // MARF's predicate fired so we don't pay for unused work in the headers-only-fires case.
        let clarity_plan = if clarity_should_squash {
            let (clarity_path, clarity_min) = self.clarity_state.with_marf(|clarity_marf| {
                (
                    clarity_marf.get_db_path().to_string(),
                    Self::squash_min_height_for_marf(clarity_marf),
                )
            });
            // Determine effective Clarity mode from configured preference + epoch 3.4 boundary.
            let configured = self
                .marf_opts
                .as_ref()
                .map(|o| o.squash_mode)
                .unwrap_or(SquashMode::TipOnly);
            Some(SquashPlan {
                label: "clarity",
                path: clarity_path,
                tip_height,
                min_height: clarity_min,
                mode: Self::effective_squash_mode(configured, clarity_min, self.db(), sortdb_conn),
                canonical_tip,
            })
        } else {
            None
        };

        // --- Phase 2: Run squash/stub operations. Both MARFs in parallel when both fired,
        // otherwise just the one that did. ---
        //
        // Each `squash_level_incremental` opens its own SQLite + MARF handle internally and
        // operates against a distinct file path, so the two threads share no mutable state. The
        // process-wide `SharedStorageState` registry is keyed by db path, so each thread gets its
        // own slot — no inner-mutex contention between them. Refresh of this chainstate's live
        // handles happens after the join, on the calling thread, where the borrow checker is
        // satisfied with sequential `&mut self` access.
        //
        // Panic propagation: join both threads, then re-raise if either panicked. This preserves
        // "don't abandon the other thread mid-flight" without silently swallowing a panic — a
        // swallowed worker panic here would mask a loud failure mode the caller expects, and a
        // stuck `truncate_pending` flag from a half-finished publish_squash would deadlock all
        // future readers (`SharedStorageState::publish_squash` clears that flag via an RAII
        // drop-guard for exactly this reason, but we still want the caller's thread to crash
        // visibly rather than continue against possibly-corrupted file state).
        let (headers_should_refresh, clarity_should_refresh) =
            match (headers_plan.as_ref(), clarity_plan.as_ref()) {
                (Some(h), Some(c)) => thread::scope(|s| {
                    let headers_handle = s.spawn(|| run_squash_plan(h));
                    let clarity_handle = s.spawn(|| run_squash_plan(c));
                    let headers_join = headers_handle.join();
                    let clarity_join = clarity_handle.join();
                    match (headers_join, clarity_join) {
                        (Ok(h), Ok(c)) => (h, c),
                        (Err(panic), Ok(_)) => {
                            error!("Auto-squash headers MARF thread panicked");
                            std::panic::resume_unwind(panic);
                        }
                        (Ok(_), Err(panic)) => {
                            error!("Auto-squash clarity MARF thread panicked");
                            std::panic::resume_unwind(panic);
                        }
                        (Err(headers_panic), Err(_clarity_panic)) => {
                            error!("Auto-squash headers AND clarity MARF threads panicked");
                            std::panic::resume_unwind(headers_panic);
                        }
                    }
                }),
                (Some(h), None) => (run_squash_plan(h), false),
                (None, Some(c)) => (false, run_squash_plan(c)),
                (None, None) => (false, false), // unreachable — guarded above
            };

        // --- Phase 3: Refresh live handles on this thread (sequential is required: the refresh
        // paths take `&mut self.state_index` / `&mut self.clarity_state`). ---
        if headers_should_refresh {
            if let Err(e) = self.state_index.refresh_after_squash() {
                warn!("Failed to refresh headers MARF after squash: {e}");
            }
        }
        if clarity_should_refresh {
            self.clarity_state.with_marf(|clarity_marf| {
                if let Err(e) = clarity_marf.refresh_after_squash() {
                    warn!("Failed to refresh clarity MARF after squash: {e}");
                }
            });
        }

        // --- Phase 4: Caller-driven sidecar trim. The squash itself no longer triggers a trim
        // (decoupled in step 5 of the adaptive squash cadence design); the chainstate, which
        // owns the operator-meaningful retention policy, is the legitimate caller. We invoke
        // it here only when the corresponding squash succeeded, matching the historical
        // post-publish behavior under the default config bit-for-bit. ---
        if headers_should_refresh {
            if let Err(e) = self.state_index.trim_sidecars(retention_blocks) {
                warn!("Headers MARF sidecar trim failed: {e}");
            }
        }
        if clarity_should_refresh {
            self.clarity_state.with_marf(|clarity_marf| {
                if let Err(e) = clarity_marf.trim_sidecars(retention_blocks) {
                    warn!("Clarity MARF sidecar trim failed: {e}");
                }
            });
        }

        // --- Inline helpers ---

        struct SquashPlan {
            label: &'static str,
            path: String,
            tip_height: u32,
            min_height: u32,
            mode: SquashMode,
            /// Chainstate's just-advanced canonical tip's `index_block_hash`. Passed through to
            /// `squash_level_incremental_with_canonical_tip` so the squash anchors to the
            /// chainstate's canonical view instead of `find_tip_block`'s MARF-block-id heuristic.
            /// The heuristic can pick a non-canonical sibling during fresh sync (multiple competing
            /// tips at the cadence boundary), causing the squash to record a non-canonical chain
            /// and the divergence detector to fire on the next block — even at well-buried heights
            /// with no real mainnet fork.
            canonical_tip: StacksBlockId,
        }

        /// Run a squash (or stub-level fallback if the range exceeds `STUB_THRESHOLD` and no prior
        /// levels exist). Returns `true` iff the calling thread should refresh its live MARF
        /// handle; on hard failure, returns `false` so the live handle keeps pointing at the
        /// unmodified file.
        fn run_squash_plan(plan: &SquashPlan) -> bool {
            let Some(block_count) =
                StacksChainState::squash_block_count(plan.min_height, plan.tip_height)
            else {
                info!(
                    "Auto-squash: {} MARF skipping empty range {}..={} \
                     (path: {})",
                    plan.label, plan.min_height, plan.tip_height, plan.path
                );
                return false;
            };
            // Late-enablement guard: a fresh range > u32 pointer space is too large to squash in
            // one shot — install a stub level instead.
            if plan.min_height == 0 && block_count > STUB_THRESHOLD {
                info!(
                    "Late-enablement: {} MARF range ({block_count} blocks) exceeds \
                     STUB_THRESHOLD ({STUB_THRESHOLD}). Creating stub level.",
                    plan.label
                );
                match create_stub_level::<StacksBlockId>(&plan.path, 0, plan.tip_height) {
                    Ok(()) => {
                        info!(
                            "Stub level created for {} MARF (0..={})",
                            plan.label, plan.tip_height
                        );
                        true
                    }
                    Err(e) => {
                        warn!("Failed to create stub level for {} MARF: {e}", plan.label);
                        false
                    }
                }
            } else {
                info!(
                    "Auto-squash: {} MARF heights {}..={} (path: {})",
                    plan.label, plan.min_height, plan.tip_height, plan.path
                );
                // reclaim=true; for L0 this is append-only since no prior levels exist. The
                // explicit `Some(canonical_tip)` anchors the squash to the chainstate's canonical
                // view at squash time, avoiding `find_tip_block`'s MARF-block-id heuristic that can
                // pick non-canonical siblings during fresh sync.
                match crate::chainstate::stacks::index::squash::squash_level_incremental::<
                    StacksBlockId,
                >(
                    &plan.path,
                    plan.mode,
                    plan.min_height,
                    plan.tip_height,
                    true,
                    Some(plan.canonical_tip.clone()),
                ) {
                    Ok(stats) => {
                        info!(
                            "Auto-squash {} MARF complete: {} nodes, {} leaves",
                            plan.label, stats.nodes_collected, stats.leaves_collected
                        );
                        true
                    }
                    Err(e) => {
                        warn!("Auto-squash {} MARF failed: {e}", plan.label);
                        false
                    }
                }
            }
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

    /// Look up the burn-chain height for a given Stacks block height
    /// from the `block_headers` table.  Returns `None` if no header is
    /// found at that height.
    ///
    /// Uses `MIN(burn_header_height)` because `block_height` is not unique
    /// — multiple forks can share the same Stacks height.  Picking the
    /// minimum is the safe conservative choice for epoch-boundary
    /// comparison: if *any* fork at this height was mined before epoch 3.4,
    /// we want `FullHistory`.
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
        // Hold the unconfirmed-state lock across the read-only Clarity tx so a
        // concurrent relayer refresh / drop cannot invalidate the borrowed
        // ClarityInstance mid-call. Lock is brief — Clarity read-only conn
        // creation + the user closure.
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
        // Lock briefly just to read the tip + readability flag — release before
        // delegating so the chosen branch can re-acquire (or skip) on its own.
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

    /// Chainstate-level regression: `assert_squash_consistency`, when called on
    /// the parent of a not-yet-committed block whose lineage diverges from the
    /// most-recent squash level's recorded canonical, must re-anchor BOTH
    /// MARFs (headers + Clarity) on the new lineage — the exact behavior the
    /// pre-append guards in `process_next_staging_block` /
    /// `process_next_nakamoto_block` rely on.
    ///
    /// Setup: build identical chains B0→B1→B2→Ba in both MARFs, squash level 0
    /// anchored to Ba on both, then add a sibling Bb at the boundary on both.
    /// Insert `block_headers` rows reflecting the chain having reorged from Ba
    /// to Bb at height 3 (Bb canonical, Ba absent). At this point no above-
    /// level descendant of Bb exists in `marf_data`, so the safety check
    /// permits recovery.
    ///
    /// Expectation: `chainstate.assert_squash_consistency(&block_b, &sortdb)`
    /// returns `Ok`, both MARFs now record `block_b` as canonical at height 3,
    /// and a follow-up call returns no divergence.
    #[test]
    fn test_assert_squash_consistency_re_anchors_divergent_parent_2x() {
        use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};

        use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
        use crate::chainstate::stacks::index::squash::{squash_level_incremental, SquashMode};
        use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
        use crate::chainstate::stacks::index::MARFValue;

        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        // Sortdb conn for `effective_squash_mode` lookups inside the recovery.
        // No epoch 3.4 row → caller mode (TipOnly here) is upgraded to FullHistory.
        let sortdb_conn = mock_sortdb_conn(None);

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

        let block_0 = blk(0xA0, 0);
        let block_1 = blk(0xA1, 1);
        let block_2 = blk(0xA2, 2);
        let block_a = blk(0xAA, 3); // pre-reorg canonical at boundary
        let block_b = blk(0xBB, 3); // post-reorg canonical (sibling)

        let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
        let headers_path = chainstate.state_index.get_db_path().to_string();
        let clarity_path = chainstate
            .clarity_state
            .with_marf(|m| m.get_db_path().to_string());

        // The chainstate's MARFs already contain the boot block. We extend from
        // `StacksBlockId::sentinel()` onto our test chain via direct MARF API —
        // bypassing `block_begin` / Clarity boot-code so the test stays focused
        // on the squash-divergence recovery wiring rather than block validation.
        let extend_chain = |path: &str| {
            let mut marf = MARF::<StacksBlockId>::from_path(path, opts.clone()).unwrap();
            let mut commit = |parent: &StacksBlockId, child: &StacksBlockId, label: &str| {
                marf.begin(parent, child).unwrap();
                marf.insert("k", MARFValue::from_value(label)).unwrap();
                marf.seal().unwrap();
                marf.commit().unwrap();
            };
            commit(&StacksBlockId::sentinel(), &block_0, "v0");
            commit(&block_0, &block_1, "v1");
            commit(&block_1, &block_2, "v2");
            commit(&block_2, &block_a, "va");
        };
        extend_chain(&headers_path);
        extend_chain(&clarity_path);

        // Squash level 0 [0..=3] anchored to block_a on both MARFs in lockstep.
        // FullHistory on both keeps historical reads usable.
        for path in [&headers_path, &clarity_path] {
            squash_level_incremental::<StacksBlockId>(
                path,
                SquashMode::FullHistory,
                0,
                3,
                /* reclaim = */ true,
                None,
            )
            .expect("initial squash should succeed");
        }
        chainstate.state_index.refresh_after_squash().unwrap();
        chainstate
            .clarity_state
            .with_marf(|m| m.refresh_after_squash())
            .unwrap();

        // Add the sibling block_b on both MARFs (chain has reorged).
        let commit_sibling = |path: &str| {
            let mut marf = MARF::<StacksBlockId>::from_path(path, opts.clone()).unwrap();
            marf.refresh_after_squash().unwrap();
            marf.begin(&block_2, &block_b).unwrap();
            marf.insert("k", MARFValue::from_value("vb")).unwrap();
            marf.seal().unwrap();
            marf.commit().unwrap();
        };
        commit_sibling(&headers_path);
        commit_sibling(&clarity_path);
        chainstate.state_index.refresh_after_squash().unwrap();
        chainstate
            .clarity_state
            .with_marf(|m| m.refresh_after_squash())
            .unwrap();

        // Populate block_headers so `detect_squash_divergence` can walk the new
        // canonical (block_b)'s ancestry. block_a is intentionally absent — the
        // chain has reorged away from it. block_0..block_2 are shared.
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_0,
            &StacksBlockId::sentinel(),
            0,
            &chash(0xA0),
            &bh(0xA0),
        );
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_1,
            &block_0,
            1,
            &chash(0xA1),
            &bh(0xA1),
        );
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_2,
            &block_1,
            2,
            &chash(0xA2),
            &bh(0xA2),
        );
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_b,
            &block_2,
            3,
            &chash(0xBB),
            &bh(0xBB),
        );

        // Sanity: divergence is detectable. The level recorded block_a as
        // canonical at height 3, the chain (block_headers) records block_b.
        let divergence = chainstate
            .detect_squash_divergence(&block_b)
            .expect("divergence walk should not fail")
            .expect(
                "divergence expected: level recorded block_a but block_headers has \
                 block_b at the boundary",
            );
        assert_eq!(divergence.recorded_canonical, block_a);
        assert_eq!(divergence.new_canonical, block_b);
        assert_eq!(divergence.diverging_height, 3);

        // No above-level committed descendants exist (block_b is at height 3,
        // not strictly above), so the safety check passes and recovery proceeds.
        assert!(chainstate
            .first_committed_block_above_level(3)
            .unwrap()
            .is_none());

        // **The behavior under test:** the pre-append guards call
        // `assert_squash_consistency(&parent_block_id, sortdb_conn)`. Here
        // parent_block_id is block_b (the candidate parent of a yet-to-be-
        // committed descendant at height 4). The call must re-anchor BOTH
        // MARFs on block_b's lineage in lockstep, without panicking.
        chainstate
            .assert_squash_consistency(&block_b, &sortdb_conn)
            .expect("recovery must succeed when no above-level descendants exist");

        // Both MARFs now record block_b as canonical at height 3.
        let headers_canonical = chainstate
            .state_index
            .latest_squash_level_canonical_chain()
            .expect("headers MARF should still have a squash level after Replace");
        assert_eq!(
            headers_canonical.block_hashes.last(),
            Some(&block_b),
            "headers MARF level canonical at boundary should be block_b after Replace"
        );
        assert_eq!(headers_canonical.max_height, 3);

        let clarity_canonical = chainstate
            .clarity_state
            .with_marf(|m| m.latest_squash_level_canonical_chain())
            .expect("clarity MARF should still have a squash level after Replace");
        assert_eq!(
            clarity_canonical.block_hashes.last(),
            Some(&block_b),
            "clarity MARF level canonical at boundary should be block_b after Replace"
        );
        assert_eq!(clarity_canonical.max_height, 3);

        // Idempotence: a second call on the now-aligned chain reports no
        // divergence (the post-process belt-and-suspenders check would be a
        // no-op here).
        assert!(chainstate
            .detect_squash_divergence(&block_b)
            .unwrap()
            .is_none());
    }

    /// Pre-append guard regression: the *leading-edge* divergence case where the about-to-be-
    /// committed block IS the first block on the new fork to disagree with recorded canonical.
    ///
    /// The scenario:
    /// - Level [0..=3] is anchored on `block_a` at height 3 on both MARFs.
    /// - `block_2` (the parent of the prospective new block) is on the recorded canonical
    ///   lineage — its ancestry walked via `block_headers` matches `recorded[0..=2]` exactly.
    /// - `block_b` is the prospective new block at height 3, on a sibling fork.
    /// - `block_b` is NOT yet in `block_headers` or the MARF (this is pre-append).
    /// - No committed `marf_data` blocks exist strictly above `max_height=3`.
    ///
    /// Expectations:
    /// 1. `assert_squash_consistency(&block_2, sortdb)` returns `Ok` with no level change — the
    ///    parent-anchored ancestry walk cannot see `block_b`, so divergence is invisible to the
    ///    pre-Part-1 guard. This is the bug class.
    /// 2. `assert_squash_consistency_with_prospective(&block_2, Some((block_b, 3)), sortdb)`
    ///    returns `Ok` with no panic and the squash level unchanged. The prospective seed
    ///    causes `detect_divergence` to surface the leading-edge divergence; the safety check
    ///    passes (no above-level descendants); recovery is deferred to the post-append guard
    ///    (which has the durable block to anchor `re_squash` on). The "no level change" half
    ///    proves the deferral half — re-anchoring would have rewritten the level's recorded
    ///    canonical at height 3 from `block_a` to `block_b`, and the assertion below catches
    ///    that.
    /// 3. Once `block_b` is durable (committed to MARF + headers), the post-append call
    ///    `assert_squash_consistency(&block_b, sortdb)` runs the recovery and re-anchors both
    ///    levels on `block_b`.
    #[test]
    fn test_assert_squash_consistency_with_prospective_defers_leading_edge_recovery() {
        use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};

        use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
        use crate::chainstate::stacks::index::squash::{squash_level_incremental, SquashMode};
        use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
        use crate::chainstate::stacks::index::MARFValue;

        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        let sortdb_conn = mock_sortdb_conn(None);

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

        let block_0 = blk(0xA0, 0);
        let block_1 = blk(0xA1, 1);
        let block_2 = blk(0xA2, 2);
        let block_a = blk(0xAA, 3); // recorded canonical at boundary
        let block_b = blk(0xBB, 3); // prospective sibling — NOT in MARF or headers yet

        let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
        let headers_path = chainstate.state_index.get_db_path().to_string();
        let clarity_path = chainstate
            .clarity_state
            .with_marf(|m| m.get_db_path().to_string());

        let extend_chain = |path: &str| {
            let mut marf = MARF::<StacksBlockId>::from_path(path, opts.clone()).unwrap();
            let mut commit = |parent: &StacksBlockId, child: &StacksBlockId, label: &str| {
                marf.begin(parent, child).unwrap();
                marf.insert("k", MARFValue::from_value(label)).unwrap();
                marf.seal().unwrap();
                marf.commit().unwrap();
            };
            commit(&StacksBlockId::sentinel(), &block_0, "v0");
            commit(&block_0, &block_1, "v1");
            commit(&block_1, &block_2, "v2");
            commit(&block_2, &block_a, "va");
        };
        extend_chain(&headers_path);
        extend_chain(&clarity_path);

        // Squash level [0..=3] anchored on block_a in lockstep on both MARFs.
        for path in [&headers_path, &clarity_path] {
            squash_level_incremental::<StacksBlockId>(
                path,
                SquashMode::FullHistory,
                0,
                3,
                /* reclaim = */ true,
                None,
            )
            .expect("initial squash should succeed");
        }
        chainstate.state_index.refresh_after_squash().unwrap();
        chainstate
            .clarity_state
            .with_marf(|m| m.refresh_after_squash())
            .unwrap();

        // Populate `block_headers` with the recorded-canonical lineage [block_0..block_2].
        // block_a is intentionally absent (chain has reorged away from it). block_b is
        // intentionally absent (it's the prospective new block — pre-append, not yet durable).
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_0,
            &StacksBlockId::sentinel(),
            0,
            &chash(0xA0),
            &bh(0xA0),
        );
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_1,
            &block_0,
            1,
            &chash(0xA1),
            &bh(0xA1),
        );
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_2,
            &block_1,
            2,
            &chash(0xA2),
            &bh(0xA2),
        );

        // Sanity: no above-level committed descendants exist. The deferral path is what we want
        // to exercise here, not the BLOCKED-fail-stop path.
        assert!(chainstate
            .first_committed_block_above_level(3)
            .unwrap()
            .is_none());

        // **Bug class**: the parent-anchored guard sees no divergence — block_2's ancestry walks
        // [block_2, block_1, block_0] all matching recorded canonical. Without the prospective
        // seed, the leading-edge divergence at height 3 is invisible.
        chainstate
            .assert_squash_consistency(&block_2, &sortdb_conn)
            .expect("parent-anchored walk passes when parent's ancestry matches recorded");
        let headers_canonical = chainstate
            .state_index
            .latest_squash_level_canonical_chain()
            .expect("level should still exist");
        assert_eq!(
            headers_canonical.block_hashes.last(),
            Some(&block_a),
            "without prospective seed, level still records block_a at boundary",
        );

        // **Behavior under test**: the prospective seed surfaces the leading-edge divergence.
        // Recovery is deferred (block_b isn't durable yet, so `re_squash` has nothing to anchor
        // on); the call returns `Ok` and the level is left untouched for the post-append guard
        // to handle.
        chainstate
            .assert_squash_consistency_with_prospective(
                &block_2,
                Some((block_b.clone(), 3)),
                &sortdb_conn,
            )
            .expect("leading-edge pre-append must defer cleanly when no above-level descendants");
        let headers_canonical_after = chainstate
            .state_index
            .latest_squash_level_canonical_chain()
            .expect("level should still exist after deferral");
        assert_eq!(
            headers_canonical_after.block_hashes.last(),
            Some(&block_a),
            "leading-edge pre-append must NOT mutate the recorded canonical \
             (recovery is deferred to post-append where block_b is durable)",
        );
        assert_eq!(headers_canonical_after.max_height, 3);
        let clarity_canonical_after = chainstate
            .clarity_state
            .with_marf(|m| m.latest_squash_level_canonical_chain())
            .expect("clarity level should still exist after deferral");
        assert_eq!(
            clarity_canonical_after.block_hashes.last(),
            Some(&block_a),
            "leading-edge pre-append must NOT mutate the Clarity recorded canonical either",
        );

        // **Post-append simulation**: now make block_b durable (commit it to both MARFs and to
        // `block_headers`) and call the post-append guard. With the new block durable,
        // `re_squash(new_tip = block_b)` works as designed and recovery completes.
        let commit_sibling = |path: &str| {
            let mut marf = MARF::<StacksBlockId>::from_path(path, opts.clone()).unwrap();
            marf.refresh_after_squash().unwrap();
            marf.begin(&block_2, &block_b).unwrap();
            marf.insert("k", MARFValue::from_value("vb")).unwrap();
            marf.seal().unwrap();
            marf.commit().unwrap();
        };
        commit_sibling(&headers_path);
        commit_sibling(&clarity_path);
        chainstate.state_index.refresh_after_squash().unwrap();
        chainstate
            .clarity_state
            .with_marf(|m| m.refresh_after_squash())
            .unwrap();
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_b,
            &block_2,
            3,
            &chash(0xBB),
            &bh(0xBB),
        );

        chainstate
            .assert_squash_consistency(&block_b, &sortdb_conn)
            .expect("post-append recovery should succeed once block_b is durable");
        let headers_canonical_recovered = chainstate
            .state_index
            .latest_squash_level_canonical_chain()
            .expect("level should still exist after post-append recovery");
        assert_eq!(
            headers_canonical_recovered.block_hashes.last(),
            Some(&block_b),
            "post-append recovery should re-anchor headers level on block_b",
        );
        let clarity_canonical_recovered = chainstate
            .clarity_state
            .with_marf(|m| m.latest_squash_level_canonical_chain())
            .expect("clarity level should still exist after post-append recovery");
        assert_eq!(
            clarity_canonical_recovered.block_hashes.last(),
            Some(&block_b),
            "post-append recovery should re-anchor Clarity level on block_b",
        );
    }

    /// Per-MARF cadence (Step 6) means headers and Clarity can have completely different level
    /// structures — including the case where one has a level and the other doesn't. This test
    /// covers a Clarity-MARF-only divergence: Clarity has squashed level [0..=3] but headers has
    /// no level yet (its cadence hasn't fired). A reorg at height 3 makes Clarity's level
    /// diverge from the chain's view in `block_headers`; headers MARF has nothing to compare
    /// against. `assert_squash_consistency` must:
    ///   1. Detect divergence on Clarity only (headers' detect_divergence returns Ok(None)).
    ///   2. Run the Clarity-specific safety check (`first_committed_clarity_block_above_level`).
    ///   3. Re-squash Clarity only, leaving headers untouched.
    ///
    /// Pre-Step-7 (lockstep cadence) this scenario was unreachable; the new code must handle it.
    #[test]
    fn test_assert_squash_consistency_handles_clarity_only_divergence() {
        use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};

        use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
        use crate::chainstate::stacks::index::squash::{squash_level_incremental, SquashMode};
        use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
        use crate::chainstate::stacks::index::MARFValue;

        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        let sortdb_conn = mock_sortdb_conn(None);

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

        let block_0 = blk(0xA0, 0);
        let block_1 = blk(0xA1, 1);
        let block_2 = blk(0xA2, 2);
        let block_a = blk(0xAA, 3); // pre-reorg canonical
        let block_b = blk(0xBB, 3); // post-reorg canonical (sibling)

        let opts = MARFOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true);
        let headers_path = chainstate.state_index.get_db_path().to_string();
        let clarity_path = chainstate
            .clarity_state
            .with_marf(|m| m.get_db_path().to_string());

        // Build identical chains [sentinel → block_0 → block_1 → block_2 → block_a] on both MARFs.
        let extend_chain = |path: &str| {
            let mut marf = MARF::<StacksBlockId>::from_path(path, opts.clone()).unwrap();
            let mut commit = |parent: &StacksBlockId, child: &StacksBlockId, label: &str| {
                marf.begin(parent, child).unwrap();
                marf.insert("k", MARFValue::from_value(label)).unwrap();
                marf.seal().unwrap();
                marf.commit().unwrap();
            };
            commit(&StacksBlockId::sentinel(), &block_0, "v0");
            commit(&block_0, &block_1, "v1");
            commit(&block_1, &block_2, "v2");
            commit(&block_2, &block_a, "va");
        };
        extend_chain(&headers_path);
        extend_chain(&clarity_path);

        // **Asymmetric setup**: squash ONLY Clarity. Headers stays without a level — exactly
        // what would happen under independent cadences if headers' trigger hasn't fired yet.
        squash_level_incremental::<StacksBlockId>(
            &clarity_path,
            SquashMode::FullHistory,
            0,
            3,
            true,
            None,
        )
        .expect("clarity squash should succeed");
        chainstate
            .clarity_state
            .with_marf(|m| m.refresh_after_squash())
            .unwrap();

        // Add sibling block_b on BOTH MARFs (chain has reorged).
        let commit_sibling = |path: &str| {
            let mut marf = MARF::<StacksBlockId>::from_path(path, opts.clone()).unwrap();
            marf.refresh_after_squash().unwrap();
            marf.begin(&block_2, &block_b).unwrap();
            marf.insert("k", MARFValue::from_value("vb")).unwrap();
            marf.seal().unwrap();
            marf.commit().unwrap();
        };
        commit_sibling(&headers_path);
        commit_sibling(&clarity_path);
        chainstate.state_index.refresh_after_squash().unwrap();
        chainstate
            .clarity_state
            .with_marf(|m| m.refresh_after_squash())
            .unwrap();

        // Populate `block_headers` for the post-reorg chain. block_a intentionally absent.
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_0,
            &StacksBlockId::sentinel(),
            0,
            &chash(0xA0),
            &bh(0xA0),
        );
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_1,
            &block_0,
            1,
            &chash(0xA1),
            &bh(0xA1),
        );
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_2,
            &block_1,
            2,
            &chash(0xA2),
            &bh(0xA2),
        );
        insert_test_block_header_minimal(
            chainstate.db(),
            &block_b,
            &block_2,
            3,
            &chash(0xBB),
            &bh(0xBB),
        );

        // **Pre-condition**: headers MARF has no squash level; Clarity's level recorded
        // block_a as canonical at height 3.
        assert!(
            chainstate
                .state_index
                .latest_squash_level_range()
                .is_none(),
            "headers MARF should have no squash level (asymmetric setup)"
        );
        let clarity_pre = chainstate
            .clarity_state
            .with_marf(|m| m.latest_squash_level_canonical_chain())
            .expect("clarity should have a squash level");
        assert_eq!(clarity_pre.block_hashes.last(), Some(&block_a));

        // **The behavior under test**: assert_squash_consistency must detect Clarity's
        // divergence and re-squash Clarity only, leaving the (level-less) headers MARF
        // untouched.
        chainstate
            .assert_squash_consistency(&block_b, &sortdb_conn)
            .expect("Clarity-only recovery must succeed when no above-level descendants exist");

        // **Post-condition**: headers MARF still has no level; Clarity's level now records
        // block_b as canonical at height 3.
        assert!(
            chainstate
                .state_index
                .latest_squash_level_range()
                .is_none(),
            "headers MARF must still have no level after Clarity-only recovery"
        );
        let clarity_post = chainstate
            .clarity_state
            .with_marf(|m| m.latest_squash_level_canonical_chain())
            .expect("clarity level should still exist after Replace");
        assert_eq!(
            clarity_post.block_hashes.last(),
            Some(&block_b),
            "Clarity level's canonical at boundary should now be block_b"
        );
        assert_eq!(clarity_post.max_height, 3);
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
        assert!(!should_squash(&zero_stats, 999, &cfg));
        assert!(!should_squash(&huge_stats, 999, &cfg));
        // At and beyond the boundary: always fires.
        assert!(should_squash(&zero_stats, 1000, &cfg));
        assert!(should_squash(&zero_stats, 5_000, &cfg));
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
        assert!(!should_squash(&work_hit, 99, &cfg));

        // Floor cleared, work_target hit → fires.
        assert!(should_squash(&work_hit, 100, &cfg));
        assert!(should_squash(&work_hit, 500, &cfg));

        // Floor cleared, work below target → holds off.
        assert!(!should_squash(&work_below, 100, &cfg));
        assert!(!should_squash(&work_below, 1500, &cfg));
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
        assert!(!should_squash(&no_work, 1999, &cfg));
        // At/past ceiling: fires unconditionally, even with zero work.
        assert!(should_squash(&no_work, 2000, &cfg));
        assert!(should_squash(&no_work, 10_000, &cfg));
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
                !should_squash(&huge, blocks_since, &cfg),
                "min_blocks floor must hold even with work_target massively exceeded \
                 at blocks_since={blocks_since}",
            );
        }
        // Boundary: fires exactly at min_blocks.
        assert!(should_squash(&huge, 100, &cfg));
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
            !should_squash(&no_work, blocks_since_at_999, &cfg),
            "no-level + tip_height=999 must NOT fire (matches legacy)"
        );
        assert!(
            should_squash(&no_work, blocks_since_at_1000, &cfg),
            "no-level + tip_height=1000 MUST fire (matches legacy first-squash boundary)"
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
    }
}
