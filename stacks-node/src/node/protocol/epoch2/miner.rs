// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::cmp::Ordering as CmpOrdering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{cmp, fs, thread};

use clarity::boot_util::boot_code_id;
use clarity::vm::types::PrincipalData;
use libsigner::v0::messages::{
    MessageSlotID, MinerSlotID, MockBlock, MockProposal, MockSignature, PeerInfo, SignerMessage,
};
use libsigner::{SignerSession, StackerDBSession};
use stacks::burnchains::bitcoin::address::{BitcoinAddress, LegacyBitcoinAddressType};
use stacks::burnchains::{Burnchain, Txid};
use stacks::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleConn};
use stacks::chainstate::burn::operations::leader_block_commit::{
    RewardSetInfo, BURN_BLOCK_MINED_AT_MODULUS,
};
use stacks::chainstate::burn::operations::{BlockstackOperationType, LeaderBlockCommitOp};
use stacks::chainstate::burn::{BlockSnapshot, ConsensusHash};
use stacks::chainstate::coordinator::{get_next_recipients, OnChainRewardSetProvider};
use stacks::chainstate::nakamoto::NakamotoChainState;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::boot::MINERS_NAME;
use stacks::chainstate::stacks::db::blocks::StagingBlock;
use stacks::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use stacks::chainstate::stacks::miner::AssembledAnchorBlock;
use stacks::chainstate::stacks::{
    CoinbasePayload, Error as ChainstateError, StacksBlockBuilder, StacksBlockHeader,
    StacksMicroblock, StacksPublicKey, StacksTransaction, StacksTransactionSigner,
    TransactionAnchorMode, TransactionPayload, TransactionVersion,
};
use stacks::config::chain_data::MinerStats;
use stacks::config::NodeConfig;
use stacks::core::mempool::MemPoolDB;
use stacks::core::{FIRST_BURNCHAIN_CONSENSUS_HASH, STACKS_EPOCH_3_0_MARKER};
use stacks::cost_estimates::metrics::UnitMetric;
use stacks::cost_estimates::UnitEstimator;
use stacks::net::stackerdb::{StackerDBs, MINER_SLOT_COUNT};
use stacks::version_string;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksBlockId, TrieHash, VRFSeed,
};
use stacks_common::types::{PublicKey, StacksEpochId};
use stacks_common::util::hash::Hash160;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::util::vrf::VRFProof;
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs};

use super::relayer::{MinerThreadResult, RelayerThread};
use super::{MinedBlocks, NeonGlobals};
use crate::burnchains::bitcoin_regtest_controller::{
    burnchain_params_from_config, BitcoinRegtestController, OngoingBlockCommit,
};
use crate::burnchains::Error as ControllerError;
use crate::node::chainstate;
use crate::node::leader_key::{generate_vrf_proof, RegisteredKey};
use crate::node::protocol::fault_injection::fault_injection_long_tenure;
use crate::node::protocol::nakamoto::{MinerDB, SignerCoordinator};
use crate::{Config, EventDispatcher, Keychain};

/// Miner chain tip, on top of which to build microblocks
#[derive(Debug, Clone, PartialEq)]
pub struct MinerTip {
    /// tip's consensus hash
    pub consensus_hash: ConsensusHash,
    /// tip's Stacks block header hash
    pub block_hash: BlockHeaderHash,
    /// Microblock private key to use to sign microblocks
    pub microblock_privkey: Secp256k1PrivateKey,
    /// Stacks height
    pub stacks_height: u64,
    /// burnchain height
    pub burn_height: u64,
}

impl MinerTip {
    pub fn new(
        ch: ConsensusHash,
        bh: BlockHeaderHash,
        pk: Secp256k1PrivateKey,
        stacks_height: u64,
        burn_height: u64,
    ) -> MinerTip {
        MinerTip {
            consensus_hash: ch,
            block_hash: bh,
            microblock_privkey: pk,
            stacks_height,
            burn_height,
        }
    }
}

/// Types of errors that can arise during mining
pub enum Error {
    /// Can't find the header record for the chain tip
    HeaderNotFoundForChainTip,
    /// Can't find the stacks block's offset in the burnchain block
    WinningVtxNotFoundForChainTip,
    /// Can't find the block sortition snapshot for the chain tip
    SnapshotNotFoundForChainTip,
    /// The burnchain tip changed while this operation was in progress
    BurnchainTipChanged,
    /// The coordinator channel closed
    CoordinatorClosed,
}

/// Metadata required for beginning a new tenure
struct ParentStacksBlockInfo {
    /// Header metadata for the Stacks block we're going to build on top of
    stacks_parent_header: StacksHeaderInfo,
    /// the consensus hash of the sortition that selected the Stacks block parent
    parent_consensus_hash: ConsensusHash,
    /// the burn block height of the sortition that selected the Stacks block parent
    parent_block_burn_height: u64,
    /// the total amount burned in the sortition that selected the Stacks block parent
    parent_block_total_burn: u64,
    /// offset in the burnchain block where the parent's block-commit was
    parent_winning_vtxindex: u16,
    /// nonce to use for this new block's coinbase transaction
    coinbase_nonce: u64,
}

pub struct BlockMinerThread {
    /// node config struct
    config: Config,
    /// handle to global state
    globals: NeonGlobals,
    /// Epoch 2 mining caches shared by successive block-miner threads
    mining_state: Epoch2MiningState,
    /// copy of the node's keychain
    keychain: Keychain,
    /// burnchain configuration
    burnchain: Burnchain,
    /// Set of blocks that we have mined, but are still potentially-broadcastable
    /// (copied from RelayerThread since we need the info to determine the strategy for mining the
    /// next block during this tenure).
    last_mined_blocks: MinedBlocks,
    /// Copy of the node's last ongoing block commit from the last time this thread was run
    ongoing_commit: Option<OngoingBlockCommit>,
    /// Copy of the node's registered VRF key
    registered_key: RegisteredKey,
    /// Burnchain block snapshot at the time this thread was initialized
    burn_block: BlockSnapshot,
    /// Handle to the node's event dispatcher
    event_dispatcher: EventDispatcher,
    /// Failed to submit last attempted block
    failed_to_submit_last_attempt: bool,
}

/// Candidate chain tip
#[derive(Debug, Clone, PartialEq)]
pub struct TipCandidate {
    pub stacks_height: u64,
    pub consensus_hash: ConsensusHash,
    pub anchored_block_hash: BlockHeaderHash,
    pub parent_consensus_hash: ConsensusHash,
    pub parent_anchored_block_hash: BlockHeaderHash,
    /// the block's sortition's burnchain height
    pub burn_height: u64,
    /// the number of Stacks blocks *at the same height* as this one, but from earlier sortitions
    /// than `burn_height`
    pub num_earlier_siblings: u64,
}

impl TipCandidate {
    pub fn id(&self) -> StacksBlockId {
        StacksBlockId::new(&self.consensus_hash, &self.anchored_block_hash)
    }

    pub fn parent_id(&self) -> StacksBlockId {
        StacksBlockId::new(
            &self.parent_consensus_hash,
            &self.parent_anchored_block_hash,
        )
    }

    pub fn new(tip: StagingBlock, burn_height: u64) -> Self {
        Self {
            stacks_height: tip.height,
            consensus_hash: tip.consensus_hash,
            anchored_block_hash: tip.anchored_block_hash,
            parent_consensus_hash: tip.parent_consensus_hash,
            parent_anchored_block_hash: tip.parent_anchored_block_hash,
            burn_height,
            num_earlier_siblings: 0,
        }
    }
}

/// Mining-policy caches whose meaning and lifetime are specific to Epoch 2.
#[derive(Clone, Default)]
pub struct Epoch2MiningState {
    /// Estimated winning probability at given Bitcoin block heights.
    estimated_winning_probs: Arc<Mutex<HashMap<u64, f64>>>,
    /// Previously selected best tips, indexed by Stacks height.
    previous_best_tips: Arc<Mutex<BTreeMap<u64, TipCandidate>>>,
}

impl Epoch2MiningState {
    /// Record an estimated winning probability.
    fn add_estimated_win_prob(&self, burn_height: u64, win_prob: f64) {
        match self.estimated_winning_probs.lock() {
            Ok(mut probs) => {
                probs.insert(burn_height, win_prob);
            }
            Err(_e) => {
                error!("FATAL: failed to lock estimated_winning_probs");
                panic!();
            }
        }
    }

    /// Get the estimated winning probability, if available.
    fn get_estimated_win_prob(&self, burn_height: u64) -> Option<f64> {
        match self.estimated_winning_probs.lock() {
            Ok(probs) => probs.get(&burn_height).cloned(),
            Err(_e) => {
                error!("FATAL: failed to lock estimated_winning_probs");
                panic!();
            }
        }
    }

    /// Record a best tip and evict entries older than the configured reorg depth.
    fn add_best_tip(&self, stacks_height: u64, tip_candidate: TipCandidate, max_depth: u64) {
        match self.previous_best_tips.lock() {
            Ok(mut tips) => {
                tips.insert(stacks_height, tip_candidate);
                let mut stale = vec![];
                for (prev_height, _) in tips.iter() {
                    if *prev_height + max_depth < stacks_height {
                        stale.push(*prev_height);
                    }
                }
                for height in stale.into_iter() {
                    tips.remove(&height);
                }
            }
            Err(_e) => {
                error!("FATAL: failed to lock previous_best_tips");
                panic!();
            }
        }
    }

    /// Get a best tip selected at a previous height.
    fn get_best_tip(&self, stacks_height: u64) -> Option<TipCandidate> {
        match self.previous_best_tips.lock() {
            Ok(tips) => tips.get(&stacks_height).cloned(),
            Err(_e) => {
                error!("FATAL: failed to lock previous_best_tips");
                panic!();
            }
        }
    }
}

impl BlockMinerThread {
    /// Instantiate the miner thread from its parent RelayerThread
    pub fn from_relayer_thread(
        rt: &RelayerThread,
        registered_key: RegisteredKey,
        burn_block: BlockSnapshot,
    ) -> BlockMinerThread {
        BlockMinerThread {
            config: rt.config.clone(),
            globals: rt.globals.clone(),
            mining_state: rt.mining_state.clone(),
            keychain: rt.keychain.clone(),
            burnchain: rt.burnchain.clone(),
            last_mined_blocks: rt.last_mined_blocks.clone(),
            ongoing_commit: rt.bitcoin_controller.get_ongoing_commit(),
            registered_key,
            burn_block,
            event_dispatcher: rt.event_dispatcher.clone(),
            failed_to_submit_last_attempt: rt.last_attempt_failed,
        }
    }

    /// Get the coinbase recipient address, if set in the config and if allowed in this epoch
    fn get_coinbase_recipient(&self, epoch_id: StacksEpochId) -> Option<PrincipalData> {
        let miner_config = self.config.get_miner_config();
        if epoch_id < StacksEpochId::Epoch21 && miner_config.block_reward_recipient.is_some() {
            warn!("Coinbase pay-to-contract is not supported in the current epoch");
            None
        } else {
            miner_config.block_reward_recipient
        }
    }

    /// Create a coinbase transaction.
    fn inner_generate_coinbase_tx(
        &mut self,
        nonce: u64,
        epoch_id: StacksEpochId,
    ) -> StacksTransaction {
        let is_mainnet = self.config.is_mainnet();
        let chain_id = self.config.burnchain.chain_id;
        let mut tx_auth = self.keychain.get_transaction_auth().unwrap();
        tx_auth.set_origin_nonce(nonce);

        let version = if is_mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let recipient_opt = self.get_coinbase_recipient(epoch_id);
        let mut tx = StacksTransaction::new(
            version,
            tx_auth,
            TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), recipient_opt, None),
        );
        tx.chain_id = chain_id;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&tx);
        self.keychain.sign_as_origin(&mut tx_signer);

        tx_signer.get_tx().unwrap()
    }

    /// Create a poison microblock transaction.
    fn inner_generate_poison_microblock_tx(
        &mut self,
        nonce: u64,
        poison_payload: TransactionPayload,
    ) -> StacksTransaction {
        let is_mainnet = self.config.is_mainnet();
        let chain_id = self.config.burnchain.chain_id;
        let mut tx_auth = self.keychain.get_transaction_auth().unwrap();
        tx_auth.set_origin_nonce(nonce);

        let version = if is_mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };
        let mut tx = StacksTransaction::new(version, tx_auth, poison_payload);
        tx.chain_id = chain_id;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&tx);
        self.keychain.sign_as_origin(&mut tx_signer);

        tx_signer.get_tx().unwrap()
    }

    /// Constructs and returns a LeaderBlockCommitOp out of the provided params.
    #[allow(clippy::too_many_arguments)]
    fn inner_generate_block_commit_op(
        &self,
        block_header_hash: BlockHeaderHash,
        burn_fee: u64,
        key: &RegisteredKey,
        parent_burnchain_height: u32,
        parent_winning_vtx: u16,
        vrf_seed: VRFSeed,
        commit_outs: Vec<PoxAddress>,
        sunset_burn: u64,
        current_burn_height: u64,
    ) -> BlockstackOperationType {
        let (parent_block_ptr, parent_vtxindex) = (parent_burnchain_height, parent_winning_vtx);
        let burn_parent_modulus = (current_burn_height % BURN_BLOCK_MINED_AT_MODULUS) as u8;
        let sender = self.keychain.get_burnchain_signer();
        BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn,
            block_header_hash,
            burn_fee,
            input: (Txid([0; 32]), 0),
            apparent_sender: sender,
            key_block_ptr: key.block_height as u32,
            key_vtxindex: key.op_vtxindex as u16,
            memo: vec![STACKS_EPOCH_3_0_MARKER],
            new_seed: vrf_seed,
            parent_block_ptr,
            parent_vtxindex,
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
            burn_parent_modulus,
            commit_outs,
        })
    }

    /// Get references to the inner assembled anchor block data we've produced for a given burnchain block height
    pub fn find_inflight_mined_blocks(
        burn_height: u64,
        last_mined_blocks: &MinedBlocks,
    ) -> Vec<&AssembledAnchorBlock> {
        let mut ret = vec![];
        for (_, (assembled_block, _)) in last_mined_blocks.iter() {
            if assembled_block.burn_block_height >= burn_height {
                ret.push(assembled_block);
            }
        }
        ret
    }

    /// Is a given Stacks staging block on the canonical burnchain fork?
    pub fn is_on_canonical_burnchain_fork(
        candidate_ch: &ConsensusHash,
        candidate_bh: &BlockHeaderHash,
        sortdb_tip_handle: &SortitionHandleConn,
    ) -> bool {
        let candidate_burn_ht = match SortitionDB::get_block_snapshot_consensus(
            sortdb_tip_handle.conn(),
            candidate_ch,
        ) {
            Ok(Some(x)) => x.block_height,
            Ok(None) => {
                warn!("Tried to evaluate potential chain tip with an unknown consensus hash";
                      "consensus_hash" => %candidate_ch,
                      "stacks_block_hash" => %candidate_bh);
                return false;
            }
            Err(e) => {
                warn!("Error while trying to evaluate potential chain tip with an unknown consensus hash";
                      "consensus_hash" => %candidate_ch,
                      "stacks_block_hash" => %candidate_bh,
                      "err" => ?e);
                return false;
            }
        };
        let tip_ch = match sortdb_tip_handle.get_consensus_at(candidate_burn_ht) {
            Ok(Some(x)) => x,
            Ok(None) => {
                warn!("Tried to evaluate potential chain tip with a consensus hash ahead of canonical tip";
                      "consensus_hash" => %candidate_ch,
                      "stacks_block_hash" => %candidate_bh);
                return false;
            }
            Err(e) => {
                warn!("Error while trying to evaluate potential chain tip with an unknown consensus hash";
                      "consensus_hash" => %candidate_ch,
                      "stacks_block_hash" => %candidate_bh,
                      "err" => ?e);
                return false;
            }
        };
        &tip_ch == candidate_ch
    }

    /// Load all candidate tips upon which to build.  This is all Stacks blocks whose heights are
    /// less than or equal to at `at_stacks_height` (or the canonical chain tip height, if not given),
    /// but greater than or equal to this end height minus `max_depth`.
    /// Returns the list of all Stacks blocks up to max_depth blocks beneath it.
    /// The blocks will be sorted first by stacks height, and then by burnchain height
    pub fn load_candidate_tips(
        burn_db: &mut SortitionDB,
        chain_state: &mut StacksChainState,
        max_depth: u64,
        at_stacks_height: Option<u64>,
    ) -> Vec<TipCandidate> {
        let stacks_tips = if let Some(start_height) = at_stacks_height {
            chain_state
                .get_stacks_chain_tips_at_height(start_height)
                .expect("FATAL: could not query chain tips at start height")
        } else {
            chain_state
                .get_stacks_chain_tips(burn_db)
                .expect("FATAL: could not query chain tips")
        };

        if stacks_tips.is_empty() {
            return vec![];
        }

        let sortdb_tip_handle = burn_db.index_handle_at_tip();

        let stacks_tips: Vec<_> = stacks_tips
            .into_iter()
            .filter(|candidate| {
                Self::is_on_canonical_burnchain_fork(
                    &candidate.consensus_hash,
                    &candidate.anchored_block_hash,
                    &sortdb_tip_handle,
                )
            })
            .collect();

        if stacks_tips.is_empty() {
            return vec![];
        }

        let mut considered = HashSet::new();
        let mut candidates = vec![];
        let end_height = stacks_tips[0].height;

        // process these tips
        for tip in stacks_tips.into_iter() {
            let index_block_hash =
                StacksBlockId::new(&tip.consensus_hash, &tip.anchored_block_hash);
            let burn_height = burn_db
                .get_consensus_hash_height(&tip.consensus_hash)
                .expect("FATAL: could not query burnchain block height")
                .expect("FATAL: no burnchain block height for Stacks tip");
            let candidate = TipCandidate::new(tip, burn_height);
            candidates.push(candidate);
            considered.insert(index_block_hash);
        }

        // process earlier tips, back to max_depth
        for cur_height in end_height.saturating_sub(max_depth)..end_height {
            let stacks_tips = chain_state
                .get_stacks_chain_tips_at_height(cur_height)
                .expect("FATAL: could not query chain tips at height")
                .into_iter()
                .filter(|candidate| {
                    Self::is_on_canonical_burnchain_fork(
                        &candidate.consensus_hash,
                        &candidate.anchored_block_hash,
                        &sortdb_tip_handle,
                    )
                });

            for tip in stacks_tips {
                let index_block_hash =
                    StacksBlockId::new(&tip.consensus_hash, &tip.anchored_block_hash);

                if considered.insert(index_block_hash) {
                    let burn_height = burn_db
                        .get_consensus_hash_height(&tip.consensus_hash)
                        .expect("FATAL: could not query burnchain block height")
                        .expect("FATAL: no burnchain block height for Stacks tip");
                    let candidate = TipCandidate::new(tip, burn_height);
                    candidates.push(candidate);
                }
            }
        }
        Self::sort_and_populate_candidates(candidates)
    }

    /// Put all tip candidates in order by stacks height, breaking ties with burnchain height.
    /// Also, count up the number of earliersiblings each tip has -- i.e. the number of stacks
    /// blocks that have the same height, but a later burnchain sortition.
    pub fn sort_and_populate_candidates(mut candidates: Vec<TipCandidate>) -> Vec<TipCandidate> {
        if candidates.is_empty() {
            return candidates;
        }
        candidates.sort_by(|tip1, tip2| {
            // stacks block height, then burnchain block height
            let ord = tip1.stacks_height.cmp(&tip2.stacks_height);
            if ord == CmpOrdering::Equal {
                return tip1.burn_height.cmp(&tip2.burn_height);
            }
            ord
        });

        // calculate the number of earlier siblings for each block.
        // this is the number of stacks blocks at the same height, but later burnchain heights.
        let mut idx = 0;
        let mut cur_stacks_height = candidates[idx].stacks_height;
        let mut num_siblings = 0;
        loop {
            idx += 1;
            if idx >= candidates.len() {
                break;
            }
            if cur_stacks_height == candidates[idx].stacks_height {
                // same stacks height, so this block has one more earlier sibling than the last
                num_siblings += 1;
                candidates[idx].num_earlier_siblings = num_siblings;
            } else {
                // new stacks height, so no earlier siblings
                num_siblings = 0;
                cur_stacks_height = candidates[idx].stacks_height;
                candidates[idx].num_earlier_siblings = 0;
            }
        }

        candidates
    }

    /// Select the best tip to mine the next block on. Potential tips are all
    /// leaf nodes where the Stacks block height is <= the max height -
    /// max_reorg_depth. Each potential tip is then scored based on the amount
    /// of orphans that its chain has caused -- that is, the number of orphans
    /// that the tip _and all of its ancestors_ (up to `max_depth`) created.
    /// The tip with the lowest score is composed of blocks that collectively made the fewest
    /// orphans, and is thus the "nicest" chain with the least orphaning.  This is the tip that is
    /// selected.
    fn pick_best_tip(
        mining_state: &Epoch2MiningState,
        config: &Config,
        burn_db: &mut SortitionDB,
        chain_state: &mut StacksChainState,
        at_stacks_height: Option<u64>,
    ) -> Option<TipCandidate> {
        debug!("Picking best Stacks tip");
        let miner_config = config.get_miner_config();
        let max_depth = miner_config.max_reorg_depth;

        // There could be more than one possible chain tip. Go find them.
        let stacks_tips =
            Self::load_candidate_tips(burn_db, chain_state, max_depth, at_stacks_height);

        let mut previous_best_tips = HashMap::new();
        let sortdb_tip_handle = burn_db.index_handle_at_tip();
        for tip in stacks_tips.iter() {
            let Some(prev_best_tip) = mining_state.get_best_tip(tip.stacks_height) else {
                continue;
            };
            if !Self::is_on_canonical_burnchain_fork(
                &prev_best_tip.consensus_hash,
                &prev_best_tip.anchored_block_hash,
                &sortdb_tip_handle,
            ) {
                continue;
            }
            previous_best_tips.insert(tip.stacks_height, prev_best_tip);
        }

        let best_tip_opt = Self::inner_pick_best_tip(stacks_tips, previous_best_tips);
        if let Some(best_tip) = best_tip_opt.as_ref() {
            mining_state.add_best_tip(best_tip.stacks_height, best_tip.clone(), max_depth);
        } else {
            // no best-tip found; revert to old tie-breaker logic
            debug!("No best-tips found; using old tie-breaking logic");
            return chain_state
                .get_stacks_chain_tip(burn_db)
                .expect("FATAL: could not load chain tip")
                .map(|staging_block| {
                    let burn_height = burn_db
                        .get_consensus_hash_height(&staging_block.consensus_hash)
                        .expect("FATAL: could not query burnchain block height")
                        .expect("FATAL: no burnchain block height for Stacks tip");
                    TipCandidate::new(staging_block, burn_height)
                });
        }
        best_tip_opt
    }

    /// Given a list of sorted candidate tips, pick the best one.  See `Self::pick_best_tip()`.
    /// Takes the list of stacks tips that are eligible to be built on, and a map of
    /// previously-chosen best tips (so if we chose a tip in the past, we keep confirming it, even
    /// if subsequent stacks blocks show up).  The previous best tips should be from recent Stacks
    /// heights; it's important that older best-tips are forgotten in order to ensure that miners
    /// will eventually (e.g. after `max_reorg_depth` Stacks blocks pass) stop trying to confirm a
    /// now-orphaned previously-chosen best-tip.  If there are multiple best-tips that conflict in
    /// `previosu_best_tips`, then only the highest one which the leaf could confirm will be
    /// considered (since the node updates its understanding of the best-tip on each RunTenure).
    pub fn inner_pick_best_tip(
        stacks_tips: Vec<TipCandidate>,
        previous_best_tips: HashMap<u64, TipCandidate>,
    ) -> Option<TipCandidate> {
        // identify leaf tips -- i.e. blocks with no children
        let parent_consensus_hashes: HashSet<_> = stacks_tips
            .iter()
            .map(|x| x.parent_consensus_hash.clone())
            .collect();

        let mut leaf_tips: Vec<_> = stacks_tips
            .iter()
            .filter(|x| !parent_consensus_hashes.contains(&x.consensus_hash))
            .collect();

        if leaf_tips.is_empty() {
            return None;
        }

        // Make scoring deterministic in the case of a tie.
        // Prefer leafs that were mined earlier on the burnchain,
        // but which pass through previously-determined best tips.
        leaf_tips.sort_by(|tip1, tip2| {
            // stacks block height, then burnchain block height
            let ord = tip1.stacks_height.cmp(&tip2.stacks_height);
            if ord == CmpOrdering::Equal {
                return tip1.burn_height.cmp(&tip2.burn_height);
            }
            ord
        });

        let mut scores = BTreeMap::new();
        for (i, leaf_tip) in leaf_tips.iter().enumerate() {
            let leaf_id = leaf_tip.id();
            // Score each leaf tip as the number of preceding Stacks blocks that are _not_ an
            // ancestor.  Because stacks_tips are in order by stacks height, a linear scan of this
            // list will allow us to match all ancestors in the last max_depth Stacks blocks.
            // `ancestor_ptr` tracks the next expected ancestor.
            let mut ancestor_ptr = leaf_tip.parent_id();
            let mut score: u64 = 0;
            let mut score_summaries = vec![];

            // find the highest stacks_tip we must confirm
            let mut must_confirm = None;
            for tip in stacks_tips.iter().rev() {
                if let Some(prev_best_tip) = previous_best_tips.get(&tip.stacks_height) {
                    if leaf_id != prev_best_tip.id() {
                        // the `ancestor_ptr` must pass through this prior best-tip
                        must_confirm = Some(prev_best_tip.clone());
                        break;
                    }
                }
            }

            for tip in stacks_tips.iter().rev() {
                if let Some(required_ancestor) = must_confirm.as_ref() {
                    if tip.stacks_height < required_ancestor.stacks_height
                        && leaf_tip.stacks_height >= required_ancestor.stacks_height
                    {
                        // This leaf does not confirm a previous-best-tip, so assign it the
                        // worst-possible score.
                        info!("Tip #{i} {}/{} at {}:{} conflicts with a previous best-tip {}/{} at {}:{}",
                              &leaf_tip.consensus_hash,
                              &leaf_tip.anchored_block_hash,
                              leaf_tip.burn_height,
                              leaf_tip.stacks_height,
                              &required_ancestor.consensus_hash,
                              &required_ancestor.anchored_block_hash,
                              required_ancestor.burn_height,
                              required_ancestor.stacks_height
                        );
                        score = u64::MAX;
                        score_summaries.push(format!("{} (best-tip reorged)", u64::MAX));
                        break;
                    }
                }
                if tip.id() == leaf_id {
                    // we can't orphan ourselves
                    continue;
                }
                if leaf_tip.stacks_height < tip.stacks_height {
                    // this tip is further along than leaf_tip, so canonicalizing leaf_tip would
                    // orphan `tip.stacks_height - leaf_tip.stacks_height` blocks.
                    score = score.saturating_add(tip.stacks_height - leaf_tip.stacks_height);
                    score_summaries.push(format!(
                        "{} (stx height diff)",
                        tip.stacks_height - leaf_tip.stacks_height
                    ));
                } else if leaf_tip.stacks_height == tip.stacks_height
                    && leaf_tip.burn_height > tip.burn_height
                {
                    // this tip has the same stacks height as the leaf, but its sortition happened
                    // earlier. This means that the leaf is trying to orphan this block and all
                    // blocks sortition'ed up to this leaf.  The miner should have instead tried to
                    // confirm this existing tip, instead of mine a sibling.
                    score = score.saturating_add(tip.num_earlier_siblings + 1);
                    score_summaries.push(format!("{} (uncles)", tip.num_earlier_siblings + 1));
                }
                if tip.id() == ancestor_ptr {
                    // did we confirm a previous best-tip? If so, then clear this
                    if let Some(required_ancestor) = must_confirm.take() {
                        if required_ancestor.id() != tip.id() {
                            // did not confirm, so restoroe
                            must_confirm = Some(required_ancestor);
                        }
                    }

                    // this stacks tip is the next ancestor.  However, that ancestor may have
                    // earlier-sortition'ed siblings that confirming this tip would orphan, so count those.
                    ancestor_ptr = tip.parent_id();
                    score = score.saturating_add(tip.num_earlier_siblings);
                    score_summaries.push(format!("{} (earlier sibs)", tip.num_earlier_siblings));
                } else {
                    // this stacks tip is not an ancestor, and would be orphaned if leaf_tip is
                    // canonical.
                    score = score.saturating_add(1);
                    score_summaries.push(format!("{} (non-ancestor)", 1));
                }
            }

            debug!(
                "Tip #{i} {}/{} at {}:{} has score {score} ({})",
                &leaf_tip.consensus_hash,
                &leaf_tip.anchored_block_hash,
                leaf_tip.burn_height,
                leaf_tip.stacks_height,
                score_summaries.join(" + ").to_string()
            );
            if score < u64::MAX {
                scores.insert(i, score);
            }
        }

        if scores.is_empty() {
            // revert to prior tie-breaking scheme
            return None;
        }

        // The lowest score is the "nicest" tip (least amount of orphaning)
        let best_tip_idx = scores
            .iter()
            .min_by_key(|(_, score)| *score)
            .expect("FATAL: candidates should not be empty here")
            .0;

        let best_tip = leaf_tips
            .get(*best_tip_idx)
            .expect("FATAL: candidates should not be empty");

        debug!(
            "Best tip is #{best_tip_idx} {}/{}",
            &best_tip.consensus_hash, &best_tip.anchored_block_hash
        );
        Some((*best_tip).clone())
    }

    // TODO: add tests from mutation testing results #4870
    #[cfg_attr(test, mutants::skip)]
    /// Load up the parent block info for mining.
    /// If there's no parent because this is the first block, then return the genesis block's info.
    /// If we can't find the parent in the DB but we expect one, return None.
    fn load_block_parent_info(
        &self,
        burn_db: &mut SortitionDB,
        chain_state: &mut StacksChainState,
    ) -> (Option<ParentStacksBlockInfo>, bool) {
        if let Some(stacks_tip) = chain_state
            .get_stacks_chain_tip(burn_db)
            .expect("FATAL: could not query chain tip")
        {
            let best_stacks_tip =
                Self::pick_best_tip(&self.mining_state, &self.config, burn_db, chain_state, None)
                    .expect("FATAL: no best chain tip");
            let miner_address = self
                .keychain
                .origin_address(self.config.is_mainnet())
                .unwrap();
            let parent_info = match ParentStacksBlockInfo::lookup(
                chain_state,
                burn_db,
                &self.burn_block,
                miner_address,
                &best_stacks_tip.consensus_hash,
                &best_stacks_tip.anchored_block_hash,
            ) {
                Ok(parent_info) => Some(parent_info),
                Err(Error::BurnchainTipChanged) => {
                    self.globals.counters.bump_missed_tenures();
                    None
                }
                Err(..) => None,
            };
            if parent_info.is_none() {
                warn!(
                    "No parent for best-tip {}/{}",
                    &best_stacks_tip.consensus_hash, &best_stacks_tip.anchored_block_hash
                );
            }
            let canonical = best_stacks_tip.consensus_hash == stacks_tip.consensus_hash
                && best_stacks_tip.anchored_block_hash == stacks_tip.anchored_block_hash;
            (parent_info, canonical)
        } else {
            debug!("No Stacks chain tip known, will return a genesis block");
            let burnchain_params = burnchain_params_from_config(&self.config.burnchain);

            let stacks_parent_header = StacksHeaderInfo::genesis(
                TrieHash([0u8; 32]),
                &burnchain_params.first_block_hash,
                burnchain_params.first_block_height as u32,
                burnchain_params.first_block_timestamp.into(),
            );

            (
                Some(ParentStacksBlockInfo {
                    stacks_parent_header,
                    parent_consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH,
                    parent_block_burn_height: 0,
                    parent_block_total_burn: 0,
                    parent_winning_vtxindex: 0,
                    coinbase_nonce: 0,
                }),
                true,
            )
        }
    }

    /// Determine which attempt this will be when mining a block, and whether or not an attempt
    /// should even be made.
    /// Returns Some(attempt, max-txs) if we should attempt to mine (and what attempt it will be)
    /// Returns None if we should not mine.
    fn get_mine_attempt(
        &self,
        chain_state: &StacksChainState,
        parent_block_info: &ParentStacksBlockInfo,
        force: bool,
    ) -> Option<(u64, u64)> {
        let parent_consensus_hash = &parent_block_info.parent_consensus_hash;
        let stacks_parent_header = &parent_block_info.stacks_parent_header;
        let parent_block_burn_height = parent_block_info.parent_block_burn_height;

        let last_mined_blocks =
            Self::find_inflight_mined_blocks(self.burn_block.block_height, &self.last_mined_blocks);

        // has the tip changed from our previously-mined block for this epoch?
        let should_unconditionally_mine = last_mined_blocks.is_empty()
            || (last_mined_blocks.len() == 1 && !self.failed_to_submit_last_attempt);
        let (attempt, max_txs) = if should_unconditionally_mine {
            // always mine if we've not mined a block for this epoch yet, or
            // if we've mined just one attempt, unconditionally try again (so we
            // can use `subsequent_miner_time_ms` in this attempt)
            if last_mined_blocks.len() == 1 {
                info!("Have only attempted one block; unconditionally trying again");
            }
            let attempt = last_mined_blocks.len() as u64 + 1;
            let mut max_txs = 0;
            for last_mined_block in last_mined_blocks.iter() {
                max_txs = cmp::max(max_txs, last_mined_block.anchored_block.txs.len());
            }
            (attempt, max_txs)
        } else {
            let mut best_attempt = 0;
            let mut max_txs = 0;
            debug!(
                "Consider {} in-flight Stacks tip(s)",
                &last_mined_blocks.len()
            );
            for prev_block in last_mined_blocks.iter() {
                debug!(
                    "Consider in-flight block {} on Stacks tip {}/{} in {} with {} txs",
                    &prev_block.anchored_block.block_hash(),
                    &prev_block.parent_consensus_hash,
                    &prev_block.anchored_block.header.parent_block,
                    &prev_block.burn_hash,
                    &prev_block.anchored_block.txs.len()
                );
                max_txs = cmp::max(max_txs, prev_block.anchored_block.txs.len());

                if prev_block.parent_consensus_hash == *parent_consensus_hash
                    && prev_block.burn_hash == self.burn_block.burn_header_hash
                    && prev_block.anchored_block.header.parent_block
                        == stacks_parent_header.anchored_header.block_hash()
                {
                    // the anchored chain tip hasn't changed since we attempted to build a block.
                    // But, have discovered any new microblocks worthy of being mined?
                    if let Ok(Some(stream)) =
                        StacksChainState::load_descendant_staging_microblock_stream(
                            chain_state.db(),
                            &StacksBlockHeader::make_index_block_hash(
                                &prev_block.parent_consensus_hash,
                                &stacks_parent_header.anchored_header.block_hash(),
                            ),
                            0,
                            u16::MAX,
                        )
                    {
                        if (prev_block.anchored_block.header.parent_microblock
                            == BlockHeaderHash([0u8; 32])
                            && stream.is_empty())
                            || (prev_block.anchored_block.header.parent_microblock
                                != BlockHeaderHash([0u8; 32])
                                && stream.len()
                                    <= (prev_block.anchored_block.header.parent_microblock_sequence
                                        as usize)
                                        + 1)
                        {
                            if !force {
                                // the chain tip hasn't changed since we attempted to build a block.  Use what we
                                // already have.
                                debug!("Relayer: Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {parent_block_burn_height}, and no new microblocks ({} <= {} + 1)",
                                       &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                                       prev_block.anchored_block.txs.len(), prev_block.burn_hash, stream.len(), prev_block.anchored_block.header.parent_microblock_sequence);

                                return None;
                            }
                        } else {
                            // there are new microblocks!
                            // TODO: only consider rebuilding our anchored block if we (a) have
                            // time, and (b) the new microblocks are worth more than the new BTC
                            // fee minus the old BTC fee
                            debug!("Relayer: Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {parent_block_burn_height}, but there are new microblocks ({} > {} + 1)",
                                   &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                                   prev_block.anchored_block.txs.len(), prev_block.burn_hash, stream.len(), prev_block.anchored_block.header.parent_microblock_sequence);

                            best_attempt = cmp::max(best_attempt, prev_block.attempt);
                        }
                    } else if !force {
                        // no microblock stream to confirm, and the stacks tip hasn't changed
                        debug!("Relayer: Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {parent_block_burn_height}, and no microblocks present",
                                &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                                prev_block.anchored_block.txs.len(), prev_block.burn_hash);

                        return None;
                    }
                } else if self.burn_block.burn_header_hash == prev_block.burn_hash {
                    // only try and re-mine if there was no sortition since the last chain tip
                    info!("Relayer: Stacks tip has changed to {parent_consensus_hash}/{} since we last tried to mine a block in {} at burn height {parent_block_burn_height}; attempt was {} (for Stacks tip {}/{})",
                            stacks_parent_header.anchored_header.block_hash(), prev_block.burn_hash, prev_block.attempt, &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block);
                    best_attempt = cmp::max(best_attempt, prev_block.attempt);
                    // Since the chain tip has changed, we should try to mine a new block, even
                    // if it has less transactions than the previous block we mined, since that
                    // previous block would now be a reorg.
                    max_txs = 0;
                } else {
                    info!("Relayer: Burn tip has changed to {} ({}) since we last tried to mine a block in {}",
                            &self.burn_block.burn_header_hash, self.burn_block.block_height, &prev_block.burn_hash);
                }
            }
            (best_attempt + 1, max_txs)
        };
        Some((attempt, u64::try_from(max_txs).expect("too many txs")))
    }

    /// Generate the VRF proof for the block we're going to build.
    /// Returns Some(proof) if we could make the proof
    /// Return None if we could not make the proof
    fn make_vrf_proof(&mut self) -> Option<VRFProof> {
        generate_vrf_proof(
            &mut self.keychain,
            self.config.get_node_config(false).mock_mining,
            &self.registered_key,
            &self.burn_block.sortition_hash,
            self.burn_block.block_height,
            &self.burn_block.burn_header_hash,
        )
    }

    /// Get the microblock private key we'll be using for this tenure, should we win.
    /// Return the private key.
    ///
    /// In testing, we ignore the parent stacks block hash because we don't have an easy way to
    /// reproduce it in integration tests.
    #[cfg(not(test))]
    fn make_microblock_private_key(
        &mut self,
        parent_stacks_hash: &StacksBlockId,
    ) -> Secp256k1PrivateKey {
        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        self.keychain
            .make_microblock_secret_key(self.burn_block.block_height, &parent_stacks_hash.0)
    }

    /// Get the microblock private key we'll be using for this tenure, should we win.
    /// Return the private key on success
    #[cfg(test)]
    fn make_microblock_private_key(
        &mut self,
        _parent_stacks_hash: &StacksBlockId,
    ) -> Secp256k1PrivateKey {
        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        warn!("test version of make_microblock_secret_key");
        self.keychain.make_microblock_secret_key(
            self.burn_block.block_height,
            &self.burn_block.block_height.to_be_bytes(),
        )
    }

    /// Load the parent microblock stream and vet it for the absence of forks.
    /// If there is a fork, then mine and relay a poison microblock transaction.
    /// Update stacks_parent_header's microblock tail to point to the end of the stream we load.
    /// Return the microblocks we'll confirm, if there are any.
    fn load_and_vet_parent_microblocks(
        &mut self,
        chain_state: &mut StacksChainState,
        sortdb: &SortitionDB,
        mem_pool: &mut MemPoolDB,
        parent_block_info: &mut ParentStacksBlockInfo,
    ) -> Option<Vec<StacksMicroblock>> {
        let parent_consensus_hash = &parent_block_info.parent_consensus_hash;
        let stacks_parent_header = &mut parent_block_info.stacks_parent_header;

        let microblock_info_opt =
            match StacksChainState::load_descendant_staging_microblock_stream_with_poison(
                chain_state.db(),
                &StacksBlockHeader::make_index_block_hash(
                    parent_consensus_hash,
                    &stacks_parent_header.anchored_header.block_hash(),
                ),
                0,
                u16::MAX,
            ) {
                Ok(x) => {
                    let num_mblocks = x.as_ref().map(|(mblocks, ..)| mblocks.len()).unwrap_or(0);
                    debug!(
                        "Loaded {num_mblocks} microblocks descending from {parent_consensus_hash}/{} (data: {})",
                        &stacks_parent_header.anchored_header.block_hash(),
                        x.is_some()
                    );
                    x
                }
                Err(e) => {
                    warn!(
                        "Failed to load descendant microblock stream from {parent_consensus_hash}/{}: {e:?}",
                        &stacks_parent_header.anchored_header.block_hash()
                    );
                    None
                }
            };

        if let Some((ref microblocks, ref poison_opt)) = &microblock_info_opt {
            if let Some(tail) = microblocks.last() {
                debug!(
                    "Confirm microblock stream tailed at {} (seq {})",
                    &tail.block_hash(),
                    tail.header.sequence
                );
            }

            // try and confirm as many microblocks as we can (but note that the stream itself may
            // be too long; we'll try again if that happens).
            stacks_parent_header.microblock_tail = microblocks.last().map(|blk| blk.header.clone());

            if let Some(poison_payload) = poison_opt {
                debug!("Detected poisoned microblock fork: {poison_payload:?}");

                // submit it multiple times with different nonces, so it'll have a good chance of
                // eventually getting picked up (even if the miner sends other transactions from
                // the same address)
                for i in 0..10 {
                    let poison_microblock_tx = self.inner_generate_poison_microblock_tx(
                        parent_block_info.coinbase_nonce + 1 + i,
                        poison_payload.clone(),
                    );

                    // submit the poison payload, privately, so we'll mine it when building the
                    // anchored block.
                    if let Err(e) = mem_pool.miner_submit(
                        chain_state,
                        sortdb,
                        parent_consensus_hash,
                        &stacks_parent_header.anchored_header.block_hash(),
                        &poison_microblock_tx,
                        Some(&self.event_dispatcher),
                        1_000_000_000.0, // prioritize this for inclusion
                    ) {
                        warn!("Detected but failed to mine poison-microblock transaction: {e:?}");
                    } else {
                        debug!("Submit poison-microblock transaction {poison_microblock_tx:?}");
                    }
                }
            }
        }

        microblock_info_opt.map(|(stream, _)| stream)
    }

    /// Get the list of possible burn addresses this miner is using
    pub fn get_miner_addrs(config: &Config, keychain: &Keychain) -> Vec<String> {
        let mut op_signer = keychain.generate_op_signer();
        let mut btc_addrs = vec![
            // legacy
            BitcoinAddress::from_bytes_legacy(
                config.burnchain.get_bitcoin_network().1,
                LegacyBitcoinAddressType::PublicKeyHash,
                &Hash160::from_data(&op_signer.get_public_key().to_bytes()).0,
            )
            .expect("FATAL: failed to construct legacy bitcoin address"),
        ];
        if config.miner.segwit {
            btc_addrs.push(
                // segwit p2wpkh
                BitcoinAddress::from_bytes_segwit_p2wpkh(
                    config.burnchain.get_bitcoin_network().1,
                    &Hash160::from_data(&op_signer.get_public_key().to_bytes_compressed()).0,
                )
                .expect("FATAL: failed to construct segwit p2wpkh address"),
            );
        }
        btc_addrs
            .into_iter()
            .map(|addr| format!("{addr}"))
            .collect()
    }

    /// Obtain the target burn fee cap, when considering how well this miner is performing.
    #[allow(clippy::too_many_arguments)]
    pub fn get_mining_spend_amount<F, G>(
        config: &Config,
        keychain: &Keychain,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        recipients: &[PoxAddress],
        start_mine_height: u64,
        at_burn_block: Option<u64>,
        mut get_prior_winning_prob: F,
        mut set_prior_winning_prob: G,
    ) -> u64
    where
        F: FnMut(u64) -> f64,
        G: FnMut(u64, f64),
    {
        let config_file_burn_fee_cap = config.get_burnchain_config().burn_fee_cap;
        let miner_config = config.get_miner_config();

        if miner_config.target_win_probability < 0.00001 {
            // this field is effectively zero
            return config_file_burn_fee_cap;
        }
        let Some(miner_stats) = config.get_miner_stats() else {
            return config_file_burn_fee_cap;
        };

        let Ok(tip) = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).map_err(|e| {
            warn!("Failed to load canonical burn chain tip: {e:?}");
            e
        }) else {
            return config_file_burn_fee_cap;
        };
        let tip = if let Some(at_burn_block) = at_burn_block.as_ref() {
            let ih = sortdb.index_handle(&tip.sortition_id);
            let Ok(Some(ancestor_tip)) = ih.get_block_snapshot_by_height(*at_burn_block) else {
                warn!("Failed to load ancestor tip at burn height {at_burn_block}");
                return config_file_burn_fee_cap;
            };
            ancestor_tip
        } else {
            tip
        };

        let Ok(active_miners_and_commits) = MinerStats::get_active_miners(sortdb, at_burn_block)
            .map_err(|e| {
                warn!("Failed to get active miners: {e:?}");
                e
            })
        else {
            return config_file_burn_fee_cap;
        };
        if active_miners_and_commits.is_empty() {
            warn!("No active miners detected; using config file burn_fee_cap");
            return config_file_burn_fee_cap;
        }

        let active_miners: Vec<_> = active_miners_and_commits
            .iter()
            .map(|(miner, _cmt)| miner.as_str())
            .collect();

        info!("Active miners: {active_miners:?}");

        let Ok(unconfirmed_block_commits) = miner_stats
            .get_unconfirmed_commits(tip.block_height + 1, &active_miners)
            .map_err(|e| {
                warn!("Failed to find unconfirmed block-commits: {e}");
                e
            })
        else {
            return config_file_burn_fee_cap;
        };

        let unconfirmed_miners_and_amounts: Vec<(String, u64)> = unconfirmed_block_commits
            .iter()
            .map(|cmt| (cmt.apparent_sender.to_string(), cmt.burn_fee))
            .collect();

        info!("Found unconfirmed block-commits: {unconfirmed_miners_and_amounts:?}");

        let (spend_dist, _total_spend) = MinerStats::get_spend_distribution(
            &active_miners_and_commits,
            &unconfirmed_block_commits,
            recipients,
        );
        let win_probs = if miner_config.fast_rampup {
            // look at spends 6+ blocks in the future
            MinerStats::get_future_win_distribution(
                &active_miners_and_commits,
                &unconfirmed_block_commits,
                recipients,
            )
        } else {
            // look at the current spends
            let Ok(unconfirmed_burn_dist) = miner_stats
                .get_unconfirmed_burn_distribution(
                    burnchain,
                    sortdb,
                    &active_miners_and_commits,
                    unconfirmed_block_commits,
                    recipients,
                    at_burn_block,
                )
                .map_err(|e| {
                    warn!("Failed to get unconfirmed burn distribution: {e:?}");
                    e
                })
            else {
                return config_file_burn_fee_cap;
            };

            MinerStats::burn_dist_to_prob_dist(&unconfirmed_burn_dist)
        };

        info!("Unconfirmed spend distribution: {spend_dist:?}");
        info!(
            "Unconfirmed win probabilities (fast_rampup={}): {win_probs:?}",
            miner_config.fast_rampup
        );

        let miner_addrs = Self::get_miner_addrs(config, keychain);
        let win_prob = miner_addrs
            .iter()
            .find_map(|x| win_probs.get(x))
            .copied()
            .unwrap_or(0.0);

        info!(
            "This miner's win probability at {} is {win_prob}",
            tip.block_height
        );
        set_prior_winning_prob(tip.block_height, win_prob);

        if win_prob < config.miner.target_win_probability {
            // no mining strategy is viable, so just quit.
            // Unless we're spinning up, that is.
            if start_mine_height + 6 < tip.block_height
                && config.miner.underperform_stop_threshold.is_some()
            {
                let underperform_stop_threshold =
                    config.miner.underperform_stop_threshold.unwrap_or(0);
                info!(
                    "Miner is spun up, but is not meeting target win probability as of {}",
                    tip.block_height
                );
                // we've spun up and we're underperforming. How long do we tolerate this?
                let mut underperformed_count = 0;
                for depth in 0..underperform_stop_threshold {
                    let prior_burn_height = tip.block_height.saturating_sub(depth);
                    let prior_win_prob = get_prior_winning_prob(prior_burn_height);
                    if prior_win_prob < config.miner.target_win_probability {
                        info!(
                            "Miner underperformed in block {prior_burn_height} ({underperformed_count}/{underperform_stop_threshold})"
                        );
                        underperformed_count += 1;
                    }
                }
                if underperformed_count == underperform_stop_threshold {
                    warn!(
                        "Miner underperformed since burn height {}; spinning down",
                        start_mine_height + 6 + underperform_stop_threshold
                    );
                    return 0;
                }
            }
        }

        config_file_burn_fee_cap
    }

    /// Produce the block-commit for this anchored block, if we can.
    /// Returns the op on success
    /// Returns None if we fail somehow.
    #[allow(clippy::too_many_arguments)]
    pub fn make_block_commit(
        &self,
        burn_db: &mut SortitionDB,
        chain_state: &mut StacksChainState,
        block_hash: BlockHeaderHash,
        parent_block_burn_height: u64,
        parent_winning_vtxindex: u16,
        vrf_proof: &VRFProof,
        target_epoch_id: StacksEpochId,
    ) -> Option<BlockstackOperationType> {
        // let's figure out the recipient set!
        let recipients = match get_next_recipients(
            &self.burn_block,
            chain_state,
            burn_db,
            &self.burnchain,
            &OnChainRewardSetProvider::new(),
        ) {
            Ok(x) => x,
            Err(e) => {
                error!("Relayer: Failure fetching recipient set: {e:?}");
                return None;
            }
        };

        let commit_outs = if !self
            .burnchain
            .pox_constants
            .is_after_pox_sunset_end(self.burn_block.block_height, target_epoch_id)
            && !self
                .burnchain
                .is_in_prepare_phase(self.burn_block.block_height + 1)
        {
            RewardSetInfo::into_commit_outs(recipients, self.config.is_mainnet())
        } else {
            vec![PoxAddress::standard_burn_address(self.config.is_mainnet())]
        };

        let burn_fee_cap = Self::get_mining_spend_amount(
            &self.config,
            &self.keychain,
            &self.burnchain,
            burn_db,
            &commit_outs,
            self.globals.get_start_mining_height(),
            None,
            |block_height| {
                self.mining_state
                    .get_estimated_win_prob(block_height)
                    .unwrap_or(0.0)
            },
            |block_height, win_prob| {
                self.mining_state
                    .add_estimated_win_prob(block_height, win_prob)
            },
        );
        if burn_fee_cap == 0 {
            warn!("Calculated burn_fee_cap is 0; will not mine");
            return None;
        }
        let sunset_burn = self.burnchain.expected_sunset_burn(
            self.burn_block.block_height + 1,
            burn_fee_cap,
            target_epoch_id,
        );
        let rest_commit = burn_fee_cap - sunset_burn;

        // let's commit, but target the current burnchain tip with our modulus
        let op = self.inner_generate_block_commit_op(
            block_hash,
            rest_commit,
            &self.registered_key,
            parent_block_burn_height
                .try_into()
                .expect("Could not convert parent block height into u32"),
            parent_winning_vtxindex,
            VRFSeed::from_proof(vrf_proof),
            commit_outs,
            sunset_burn,
            self.burn_block.block_height,
        );
        Some(op)
    }

    /// Are there enough unprocessed blocks that we shouldn't mine?
    pub fn unprocessed_blocks_prevent_mining(
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        unprocessed_block_deadline: u64,
    ) -> bool {
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .expect("FATAL: could not query canonical sortition DB tip");

        if let Some(stacks_tip) =
            NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb)
                .expect("FATAL: could not query canonical Stacks chain tip")
        {
            // if a block hasn't been processed within some deadline seconds of receipt, don't block
            //  mining
            let process_deadline = get_epoch_time_secs() - unprocessed_block_deadline;
            let has_unprocessed = StacksChainState::has_higher_unprocessed_blocks(
                chainstate.db(),
                stacks_tip.anchored_header.height(),
                process_deadline,
            )
            .expect("FATAL: failed to query staging blocks");
            if has_unprocessed {
                let highest_unprocessed_opt = StacksChainState::get_highest_unprocessed_block(
                    chainstate.db(),
                    process_deadline,
                )
                .expect("FATAL: failed to query staging blocks");

                if let Some(highest_unprocessed) = highest_unprocessed_opt {
                    let highest_unprocessed_block_sn_opt =
                        SortitionDB::get_block_snapshot_consensus(
                            sortdb.conn(),
                            &highest_unprocessed.consensus_hash,
                        )
                        .expect("FATAL: could not query sortition DB");

                    // NOTE: this could be None if it's not part of the canonical PoX fork any
                    // longer
                    if let Some(highest_unprocessed_block_sn) = highest_unprocessed_block_sn_opt {
                        if stacks_tip.anchored_header.height()
                            + u64::from(burnchain.pox_constants.prepare_length)
                            > highest_unprocessed.height
                            && highest_unprocessed_block_sn.block_height
                                + u64::from(burnchain.pox_constants.prepare_length)
                                > sort_tip.block_height
                        {
                            // we're close enough to the chain tip that it's a bad idea for us to mine
                            // -- we'll likely create an orphan
                            return true;
                        }
                    }
                }
            }
        }
        // we can mine
        false
    }

    /// Only used in mock signing to generate a peer info view
    fn generate_peer_info(&self) -> PeerInfo {
        // Create a peer info view of the current state
        let server_version = version_string("stacks-node", option_env!("STACKS_NODE_VERSION"));
        let stacks_tip_height = self.burn_block.canonical_stacks_tip_height;
        let stacks_tip = self.burn_block.canonical_stacks_tip_hash.clone();
        let stacks_tip_consensus_hash = self.burn_block.canonical_stacks_tip_consensus_hash.clone();
        let pox_consensus = self.burn_block.consensus_hash.clone();
        let burn_block_height = self.burn_block.block_height;

        PeerInfo {
            burn_block_height,
            stacks_tip_consensus_hash,
            stacks_tip,
            stacks_tip_height,
            pox_consensus,
            server_version,
            network_id: self.config.get_burnchain_config().chain_id,
        }
    }

    /// Only used in mock signing to retrieve the mock signatures for the given mock proposal
    fn wait_for_mock_signatures(
        &self,
        mock_proposal: &MockProposal,
        stackerdbs: &StackerDBs,
        timeout: Duration,
    ) -> Result<Vec<MockSignature>, ChainstateError> {
        let reward_cycle = self
            .burnchain
            .block_height_to_reward_cycle(self.burn_block.block_height)
            .expect("BUG: block commit exists before first block height");
        let signers_contract_id = MessageSlotID::BlockResponse
            .stacker_db_contract(self.config.is_mainnet(), reward_cycle);
        let slot_ids: Vec<_> = stackerdbs
            .get_signers(&signers_contract_id)
            .expect("FATAL: could not get signers from stacker DB")
            .into_iter()
            .enumerate()
            .map(|(slot_id, _)| {
                u32::try_from(slot_id).expect("FATAL: too many signers to fit into u32 range")
            })
            .collect();
        let mock_poll_start = Instant::now();
        let mut mock_signatures = vec![];
        // Because we don't care really if all signers reach quorum and this is just for testing purposes,
        // we don't need to wait for ALL signers to sign the mock proposal and should not slow down mining too much
        // Just wait a min amount of time for the mock signatures to come in
        while mock_signatures.len() < slot_ids.len() && mock_poll_start.elapsed() < timeout {
            let chunks = stackerdbs.get_latest_chunks(&signers_contract_id, &slot_ids)?;
            for chunk in chunks.into_iter().flatten() {
                if let Ok(SignerMessage::MockSignature(mock_signature)) =
                    SignerMessage::consensus_deserialize(&mut chunk.as_slice())
                {
                    if mock_signature.mock_proposal == *mock_proposal
                        && !mock_signatures.contains(&mock_signature)
                    {
                        mock_signatures.push(mock_signature);
                    }
                }
            }
        }
        Ok(mock_signatures)
    }

    /// Only used in mock signing to determine if the peer info view was already signed across
    fn mock_block_exists(&self, peer_info: &PeerInfo) -> bool {
        let miner_contract_id = boot_code_id(MINERS_NAME, self.config.is_mainnet());
        let mut miners_stackerdb = StackerDBSession::new(
            &self.config.node.rpc_bind,
            miner_contract_id,
            self.config.miner.stackerdb_timeout,
        );
        let miner_slot_ids: Vec<_> = (0..MINER_SLOT_COUNT * 2).collect();
        if let Ok(messages) = miners_stackerdb.get_latest_chunks(&miner_slot_ids) {
            for message in messages.into_iter().flatten() {
                if message.is_empty() {
                    continue;
                }
                let Ok(SignerMessage::MockBlock(mock_block)) =
                    SignerMessage::consensus_deserialize(&mut message.as_slice())
                else {
                    continue;
                };
                if mock_block.mock_proposal.peer_info == *peer_info {
                    return true;
                }
            }
        }
        false
    }

    /// Read any mock signatures from stackerdb and respond to them
    pub fn send_mock_miner_messages(&mut self) -> Result<(), String> {
        let burn_db_path = self.config.get_burn_db_file_path();
        let burn_db = SortitionDB::open(
            &burn_db_path,
            false,
            self.burnchain.pox_constants.clone(),
            Some(self.config.node.get_marf_opts()),
        )
        .expect("FATAL: could not open sortition DB");
        let epoch_id = SortitionDB::get_stacks_epoch(burn_db.conn(), self.burn_block.block_height)
            .map_err(|e| e.to_string())?
            .expect("FATAL: no epoch defined")
            .epoch_id;
        if epoch_id != StacksEpochId::Epoch25 {
            debug!("Mock miner messaging is disabled for non-epoch 2.5 blocks.";
                "epoch_id" => epoch_id.to_string()
            );
            return Ok(());
        }

        let miner_config = self.config.get_miner_config();
        if !miner_config.pre_nakamoto_mock_signing {
            debug!("Pre-Nakamoto mock signing is disabled");
            return Ok(());
        }

        let mining_key = miner_config
            .mining_key
            .expect("Cannot mock sign without mining key");

        // Create a peer info view of the current state
        let peer_info = self.generate_peer_info();
        if self.mock_block_exists(&peer_info) {
            debug!(
                "Already sent mock miner block proposal for current peer info view. Not sending another mock proposal."
            );
            return Ok(());
        }

        // find out which slot we're in. If we are not the latest sortition winner, we should not be sending anymore messages anyway
        let ih = burn_db.index_handle(&self.burn_block.sortition_id);
        let last_winner_snapshot = ih
            .get_last_snapshot_with_sortition(self.burn_block.block_height)
            .map_err(|e| e.to_string())?;

        if last_winner_snapshot.miner_pk_hash
            != Some(Hash160::from_node_public_key(
                &StacksPublicKey::from_private(&mining_key),
            ))
        {
            return Ok(());
        }
        let election_sortition = last_winner_snapshot.consensus_hash;
        let mock_proposal = MockProposal::new(peer_info, &mining_key);

        info!("Sending mock proposal to stackerdb: {mock_proposal:?}");

        let stackerdbs = StackerDBs::connect(&self.config.get_stacker_db_file_path(), false)
            .map_err(|e| e.to_string())?;
        let miner_contract_id = boot_code_id(MINERS_NAME, self.config.is_mainnet());
        let mut miners_stackerdb = StackerDBSession::new(
            &self.config.node.rpc_bind,
            miner_contract_id,
            self.config.miner.stackerdb_timeout,
        );
        let miner_db = MinerDB::open_with_config(&self.config).map_err(|e| e.to_string())?;

        SignerCoordinator::send_miners_message(
            &mining_key,
            &burn_db,
            &self.burn_block,
            &stackerdbs,
            SignerMessage::MockProposal(mock_proposal.clone()),
            MinerSlotID::BlockProposal, // There is no specific slot for mock miner messages so we use BlockProposal for MockProposal as well.
            self.config.is_mainnet(),
            &mut miners_stackerdb,
            &election_sortition,
            &miner_db,
        )
        .map_err(|e| {
            warn!("Failed to write mock proposal to stackerdb.");
            e.to_string()
        })?;

        // Retrieve any MockSignatures from stackerdb
        info!("Waiting for mock signatures...");
        let mock_signatures = self
            .wait_for_mock_signatures(&mock_proposal, &stackerdbs, Duration::from_secs(10))
            .map_err(|e| e.to_string())?;

        let mock_block = MockBlock {
            mock_proposal,
            mock_signatures,
        };

        info!("Sending mock block to stackerdb: {mock_block:?}");
        SignerCoordinator::send_miners_message(
            &mining_key,
            &burn_db,
            &self.burn_block,
            &stackerdbs,
            SignerMessage::MockBlock(mock_block),
            MinerSlotID::BlockPushed, // There is no specific slot for mock miner messages. Let's use BlockPushed for MockBlock since MockProposal uses BlockProposal.
            self.config.is_mainnet(),
            &mut miners_stackerdb,
            &election_sortition,
            &miner_db,
        )
        .map_err(|e| {
            warn!("Failed to write mock block to stackerdb.");
            e.to_string()
        })?;
        Ok(())
    }

    // TODO: add tests from mutation testing results #4871
    #[cfg_attr(test, mutants::skip)]
    /// Try to mine a Stacks block by assembling one from mempool transactions and sending a
    /// burnchain block-commit transaction.  If we succeed, then return the assembled block data as
    /// well as the microblock private key to use to produce microblocks.
    /// Return None if we couldn't build a block for whatever reason.
    pub fn run_tenure(&mut self) -> Option<MinerThreadResult> {
        debug!("block miner thread ID is {:?}", thread::current().id());
        fault_injection_long_tenure();

        let burn_db_path = self.config.get_burn_db_file_path();
        let stacks_chainstate_path = self.config.get_chainstate_path_str();

        let cost_estimator = self
            .config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = self
            .config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let mut bitcoin_controller = BitcoinRegtestController::new_ongoing_dummy(
            self.config.clone(),
            self.ongoing_commit.clone(),
        );

        let miner_config = self.config.get_miner_config();
        let last_miner_config_opt = self.globals.get_last_miner_config();
        let force_remine = if let Some(last_miner_config) = last_miner_config_opt {
            last_miner_config != miner_config
        } else {
            false
        };
        if force_remine {
            info!("Miner config changed; forcing a re-mine attempt");
        }

        self.globals.set_last_miner_config(miner_config);

        // NOTE: read-write access is needed in order to be able to query the recipient set.
        // This is an artifact of the way the MARF is built (see #1449)
        let mut burn_db = SortitionDB::open(
            &burn_db_path,
            true,
            self.burnchain.pox_constants.clone(),
            Some(self.config.node.get_marf_opts()),
        )
        .expect("FATAL: could not open sortition DB");

        let mut chain_state =
            chainstate::open_chainstate(&self.config).expect("FATAL: could not open chainstate DB");

        let mut mem_pool = MemPoolDB::open(
            self.config.is_mainnet(),
            self.config.burnchain.chain_id,
            &stacks_chainstate_path,
            cost_estimator,
            metric,
        )
        .expect("Database failure opening mempool");

        let tenure_begin = get_epoch_time_ms();

        let target_epoch_id =
            SortitionDB::get_stacks_epoch(burn_db.conn(), self.burn_block.block_height + 1)
                .ok()?
                .expect("FATAL: no epoch defined")
                .epoch_id;

        let (Some(mut parent_block_info), _) =
            self.load_block_parent_info(&mut burn_db, &mut chain_state)
        else {
            return None;
        };
        let (attempt, max_txs) =
            self.get_mine_attempt(&chain_state, &parent_block_info, force_remine)?;
        let vrf_proof = self.make_vrf_proof()?;

        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        let microblock_private_key = self.make_microblock_private_key(
            &parent_block_info.stacks_parent_header.index_block_hash(),
        );
        let mblock_pubkey_hash = {
            let mut pubkh = Hash160::from_node_public_key(&StacksPublicKey::from_private(
                &microblock_private_key,
            ));
            if cfg!(test) {
                if let Ok(mblock_pubkey_hash_str) = std::env::var("STACKS_MICROBLOCK_PUBKEY_HASH") {
                    if let Ok(bad_pubkh) = Hash160::from_hex(&mblock_pubkey_hash_str) {
                        debug!("Fault injection: set microblock public key hash to {bad_pubkh}");
                        pubkh = bad_pubkh
                    }
                }
            }
            pubkh
        };

        // create our coinbase
        let coinbase_tx =
            self.inner_generate_coinbase_tx(parent_block_info.coinbase_nonce, target_epoch_id);

        // find the longest microblock tail we can build off of and vet microblocks for forks
        self.load_and_vet_parent_microblocks(
            &mut chain_state,
            &burn_db,
            &mut mem_pool,
            &mut parent_block_info,
        );

        let burn_tip = SortitionDB::get_canonical_burn_chain_tip(burn_db.conn())
            .expect("FATAL: failed to read current burnchain tip");
        let microblocks_disabled =
            SortitionDB::are_microblocks_disabled(burn_db.conn(), burn_tip.block_height)
                .expect("FATAL: failed to query epoch's microblock status");

        // build the block itself
        let mut builder_settings = self.config.make_block_builder_settings(
            attempt,
            false,
            self.globals.get_miner_status(),
        );
        if microblocks_disabled {
            builder_settings.confirm_microblocks = false;
            if cfg!(test)
                && std::env::var("STACKS_TEST_CONFIRM_MICROBLOCKS_POST_25").as_deref() == Ok("1")
            {
                builder_settings.confirm_microblocks = true;
            }
        }
        let (anchored_block, _, _) = match StacksBlockBuilder::build_anchored_block(
            &chain_state,
            &burn_db.index_handle(&burn_tip.sortition_id),
            &mut mem_pool,
            &parent_block_info.stacks_parent_header,
            parent_block_info.parent_block_total_burn,
            &vrf_proof,
            &mblock_pubkey_hash,
            &coinbase_tx,
            builder_settings,
            Some(&self.event_dispatcher),
            &self.burnchain,
        ) {
            Ok(block) => block,
            Err(ChainstateError::InvalidStacksMicroblock(msg, mblock_header_hash)) => {
                // part of the parent microblock stream is invalid, so try again
                info!(
                    "Parent microblock stream is invalid; trying again without microblocks";
                    "microblock_offender" => %mblock_header_hash,
                    "error" => &msg
                );

                let mut builder_settings = self.config.make_block_builder_settings(
                    attempt,
                    false,
                    self.globals.get_miner_status(),
                );
                builder_settings.confirm_microblocks = false;

                // try again
                match StacksBlockBuilder::build_anchored_block(
                    &chain_state,
                    &burn_db.index_handle(&burn_tip.sortition_id),
                    &mut mem_pool,
                    &parent_block_info.stacks_parent_header,
                    parent_block_info.parent_block_total_burn,
                    &vrf_proof,
                    &mblock_pubkey_hash,
                    &coinbase_tx,
                    builder_settings,
                    Some(&self.event_dispatcher),
                    &self.burnchain,
                ) {
                    Ok(block) => block,
                    Err(e) => {
                        error!("Relayer: Failure mining anchor block even after removing offending microblock {mblock_header_hash}: {e}");
                        return None;
                    }
                }
            }
            Err(e) => {
                error!("Relayer: Failure mining anchored block: {e}");
                return None;
            }
        };

        let miner_config = self.config.get_miner_config();

        if attempt > 1
            && miner_config.min_tx_count > 0
            && u64::try_from(anchored_block.txs.len()).expect("too many txs")
                < miner_config.min_tx_count
        {
            info!("Relayer: Succeeded assembling subsequent block with {} txs, but expected at least {}", anchored_block.txs.len(), miner_config.min_tx_count);
            return None;
        }

        if miner_config.only_increase_tx_count
            && max_txs > u64::try_from(anchored_block.txs.len()).expect("too many txs")
        {
            info!("Relayer: Succeeded assembling subsequent block with {} txs, but had previously produced a block with {max_txs} txs", anchored_block.txs.len());
            return None;
        }

        info!(
            "Relayer: Succeeded assembling {} block #{}: {}, with {} txs, attempt {attempt}",
            if parent_block_info.parent_block_total_burn == 0 {
                "Genesis"
            } else {
                "Stacks"
            },
            anchored_block.header.total_work.work,
            anchored_block.block_hash(),
            anchored_block.txs.len()
        );

        // let's commit
        #[cfg(test)]
        if self.globals.counters.skip_commit_op.get() {
            debug!("Relayer: fault injection: skip block commit");
            return None;
        }
        let op = self.make_block_commit(
            &mut burn_db,
            &mut chain_state,
            anchored_block.block_hash(),
            parent_block_info.parent_block_burn_height,
            parent_block_info.parent_winning_vtxindex,
            &vrf_proof,
            target_epoch_id,
        )?;
        let burn_fee = if let BlockstackOperationType::LeaderBlockCommit(ref op) = &op {
            op.burn_fee
        } else {
            0
        };

        // last chance -- confirm that the stacks tip is unchanged (since it could have taken long
        // enough to build this block that another block could have arrived), and confirm that all
        // Stacks blocks with heights higher than the canoincal tip are processed.
        let cur_burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(burn_db.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        if let Some(stacks_tip) = Self::pick_best_tip(
            &self.mining_state,
            &self.config,
            &mut burn_db,
            &mut chain_state,
            None,
        ) {
            let is_miner_blocked = self
                .globals
                .get_miner_status()
                .lock()
                .expect("FATAL: mutex poisoned")
                .is_blocked();

            let has_unprocessed = Self::unprocessed_blocks_prevent_mining(
                &self.burnchain,
                &burn_db,
                &chain_state,
                miner_config.unprocessed_block_deadline_secs,
            );

            if stacks_tip.anchored_block_hash != anchored_block.header.parent_block
                || parent_block_info.parent_consensus_hash != stacks_tip.consensus_hash
                || cur_burn_chain_tip.burn_header_hash != self.burn_block.burn_header_hash
                || is_miner_blocked
                || has_unprocessed
            {
                info!(
                    "Relayer: Cancel block-commit; chain tip(s) have changed or cancelled";
                    "block_hash" => %anchored_block.block_hash(),
                    "tx_count" => anchored_block.txs.len(),
                    "target_height" => %anchored_block.header.total_work.work,
                    "parent_consensus_hash" => %parent_block_info.parent_consensus_hash,
                    "parent_block_hash" => %anchored_block.header.parent_block,
                    "parent_microblock_hash" => %anchored_block.header.parent_microblock,
                    "parent_microblock_seq" => anchored_block.header.parent_microblock_sequence,
                    "old_tip_burn_block_hash" => %self.burn_block.burn_header_hash,
                    "old_tip_burn_block_height" => self.burn_block.block_height,
                    "old_tip_burn_block_sortition_id" => %self.burn_block.sortition_id,
                    "attempt" => attempt,
                    "new_stacks_tip_block_hash" => %stacks_tip.anchored_block_hash,
                    "new_stacks_tip_consensus_hash" => %stacks_tip.consensus_hash,
                    "new_tip_burn_block_height" => cur_burn_chain_tip.block_height,
                    "new_tip_burn_block_sortition_id" => %cur_burn_chain_tip.sortition_id,
                    "new_burn_block_sortition_id" => %cur_burn_chain_tip.sortition_id,
                    "miner_blocked" => %is_miner_blocked,
                    "has_unprocessed" => %has_unprocessed
                );
                self.globals.counters.bump_missed_tenures();
                return None;
            }
        }

        let mut op_signer = self.keychain.generate_op_signer();
        info!(
            "Relayer: Submit block-commit";
            "burn_fee" => burn_fee,
            "block_hash" => %anchored_block.block_hash(),
            "tx_count" => anchored_block.txs.len(),
            "target_height" => anchored_block.header.total_work.work,
            "parent_consensus_hash" => %parent_block_info.parent_consensus_hash,
            "parent_block_hash" => %anchored_block.header.parent_block,
            "parent_microblock_hash" => %anchored_block.header.parent_microblock,
            "parent_microblock_seq" => anchored_block.header.parent_microblock_sequence,
            "tip_burn_block_hash" => %self.burn_block.burn_header_hash,
            "tip_burn_block_height" => self.burn_block.block_height,
            "tip_burn_block_sortition_id" => %self.burn_block.sortition_id,
            "cur_burn_block_hash" => %cur_burn_chain_tip.burn_header_hash,
            "cur_burn_block_height" => %cur_burn_chain_tip.block_height,
            "cur_burn_block_sortition_id" => %cur_burn_chain_tip.sortition_id,
            "attempt" => attempt
        );

        let NodeConfig {
            mock_mining,
            mock_mining_output_dir,
            ..
        } = self.config.get_node_config(false);

        let res = bitcoin_controller.submit_operation(target_epoch_id, op, &mut op_signer);
        match res {
            Ok(_) => {
                self.failed_to_submit_last_attempt = false;
                self.globals
                    .counters
                    .bump_neon_submitted_commits(self.burn_block.block_height);
            }
            Err(_) if mock_mining => {
                debug!("Relayer: Mock-mining enabled; not sending Bitcoin transaction");
                self.failed_to_submit_last_attempt = true;
            }
            Err(ControllerError::IdenticalOperation) => {
                info!("Relayer: Block-commit already submitted");
                self.failed_to_submit_last_attempt = true;
                return None;
            }
            Err(e) => {
                warn!("Relayer: Failed to submit Bitcoin transaction: {e:?}");
                self.failed_to_submit_last_attempt = true;
                return None;
            }
        };

        let assembled_block = AssembledAnchorBlock {
            parent_consensus_hash: parent_block_info.parent_consensus_hash.clone(),
            consensus_hash: cur_burn_chain_tip.consensus_hash.clone(),
            burn_hash: cur_burn_chain_tip.burn_header_hash.clone(),
            burn_block_height: cur_burn_chain_tip.block_height,
            orig_burn_hash: self.burn_block.burn_header_hash.clone(),
            anchored_block,
            attempt,
            tenure_begin,
        };

        if mock_mining {
            let stacks_block_height = assembled_block.anchored_block.header.total_work.work;
            info!("Mock mined Stacks block {stacks_block_height}");
            if let Some(dir) = mock_mining_output_dir {
                info!("Writing mock mined Stacks block {stacks_block_height} to file");
                fs::create_dir_all(&dir).unwrap_or_else(|e| match e.kind() {
                    ErrorKind::AlreadyExists => { /* This is fine */ }
                    _ => error!("Failed to create directory '{dir:?}': {e}"),
                });
                let filename = format!("{stacks_block_height}.json");
                let filepath = dir.join(filename);
                assembled_block
                    .serialize_to_file(&filepath)
                    .unwrap_or_else(|e| match e.kind() {
                        ErrorKind::AlreadyExists => {
                            error!("Failed to overwrite file '{filepath:?}'")
                        }
                        _ => error!("Failed to write to file '{filepath:?}': {e}"),
                    });
            }
        }

        Some(MinerThreadResult::Block(
            assembled_block,
            microblock_private_key,
            bitcoin_controller.get_ongoing_commit(),
        ))
    }
}

impl ParentStacksBlockInfo {
    /// Determine where in the set of forks to attempt to mine the next anchored block.
    /// `mine_tip_ch` and `mine_tip_bhh` identify the parent block on top of which to mine.
    /// `check_burn_block` identifies what we believe to be the burn chain's sortition history tip.
    /// This is used to mitigate (but not eliminate) a TOCTTOU issue with mining: the caller's
    /// conception of the sortition history tip may have become stale by the time they call this
    /// method, in which case, mining should *not* happen (since the block will be invalid).
    pub fn lookup(
        chain_state: &mut StacksChainState,
        burn_db: &mut SortitionDB,
        check_burn_block: &BlockSnapshot,
        miner_address: StacksAddress,
        mine_tip_ch: &ConsensusHash,
        mine_tip_bh: &BlockHeaderHash,
    ) -> Result<ParentStacksBlockInfo, Error> {
        let stacks_tip_header = StacksChainState::get_anchored_block_header_info(
            chain_state.db(),
            mine_tip_ch,
            mine_tip_bh,
        )
        .unwrap()
        .ok_or_else(|| {
            error!(
                "Could not mine new tenure, since could not find header for known chain tip.";
                "tip_consensus_hash" => %mine_tip_ch,
                "tip_stacks_block_hash" => %mine_tip_bh
            );
            Error::HeaderNotFoundForChainTip
        })?;

        // the stacks block I'm mining off of's burn header hash and vtxindex:
        let parent_snapshot =
            SortitionDB::get_block_snapshot_consensus(burn_db.conn(), mine_tip_ch)
                .expect("Failed to look up block's parent snapshot")
                .expect("Failed to look up block's parent snapshot");

        let parent_sortition_id = &parent_snapshot.sortition_id;

        let (parent_block_height, parent_winning_vtxindex, parent_block_total_burn) = if mine_tip_ch
            == &FIRST_BURNCHAIN_CONSENSUS_HASH
        {
            (0, 0, 0)
        } else {
            let parent_winning_vtxindex =
                SortitionDB::get_block_winning_vtxindex(burn_db.conn(), parent_sortition_id)
                    .expect("SortitionDB failure.")
                    .ok_or_else(|| {
                        error!(
                            "Failed to find winning vtx index for the parent sortition";
                            "parent_sortition_id" => %parent_sortition_id
                        );
                        Error::WinningVtxNotFoundForChainTip
                    })?;

            let parent_block = SortitionDB::get_block_snapshot(burn_db.conn(), parent_sortition_id)
                .expect("SortitionDB failure.")
                .ok_or_else(|| {
                    error!(
                        "Failed to find block snapshot for the parent sortition";
                        "parent_sortition_id" => %parent_sortition_id
                    );
                    Error::SnapshotNotFoundForChainTip
                })?;

            (
                parent_block.block_height,
                parent_winning_vtxindex,
                parent_block.total_burn,
            )
        };

        // don't mine off of an old burnchain block
        let burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(burn_db.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        if burn_chain_tip.consensus_hash != check_burn_block.consensus_hash {
            info!(
                "New canonical burn chain tip detected. Will not try to mine.";
                "new_consensus_hash" => %burn_chain_tip.consensus_hash,
                "old_consensus_hash" => %check_burn_block.consensus_hash,
                "new_burn_height" => burn_chain_tip.block_height,
                "old_burn_height" => check_burn_block.block_height
            );
            return Err(Error::BurnchainTipChanged);
        }

        debug!("Mining tenure's last consensus hash: {} (height {} hash {}), stacks tip consensus hash: {mine_tip_ch} (height {} hash {})",
               &check_burn_block.consensus_hash, check_burn_block.block_height, &check_burn_block.burn_header_hash,
               parent_snapshot.block_height, &parent_snapshot.burn_header_hash);

        let coinbase_nonce = {
            let principal = miner_address.into();
            let account = chain_state
                .with_read_only_clarity_tx(
                    &burn_db.index_handle(&burn_chain_tip.sortition_id),
                    &StacksBlockHeader::make_index_block_hash(mine_tip_ch, mine_tip_bh),
                    |conn| StacksChainState::get_account(conn, &principal),
                )
                .unwrap_or_else(|| {
                    panic!(
                        "BUG: stacks tip block {mine_tip_ch}/{mine_tip_bh} no longer exists after we queried it"
                    )
                });
            account.nonce
        };

        Ok(ParentStacksBlockInfo {
            stacks_parent_header: stacks_tip_header,
            parent_consensus_hash: mine_tip_ch.clone(),
            parent_block_burn_height: parent_block_height,
            parent_block_total_burn,
            parent_winning_vtxindex,
            coinbase_nonce,
        })
    }
}
