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

use std::collections::HashMap;
#[cfg(any(test, feature = "testing"))]
use std::fs;
use std::thread::JoinHandle;
use std::{mem, thread};

use clarity::vm::costs::ExecutionCost;
use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::{BlockSnapshot, ConsensusHash};
use stacks::chainstate::stacks::db::{StacksChainState, MINER_REWARD_MATURITY};
use stacks::chainstate::stacks::miner::{
    signal_mining_blocked, signal_mining_ready, AssembledAnchorBlock,
};
use stacks::chainstate::stacks::{
    Error as ChainstateError, StacksBlock, StacksBlockHeader, StacksMicroblock, StacksPublicKey,
};
use stacks::core::mempool::MemPoolDB;
use stacks::cost_estimates::metrics::UnitMetric;
use stacks::cost_estimates::UnitEstimator;
use stacks::monitoring::increment_stx_blocks_mined_counter;
use stacks::net::db::LocalPeer;
use stacks::net::relay::Relayer;
use stacks::net::{Error as NetError, NetworkResult};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash};
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::{to_hex, Hash160};
use stacks_common::util::secp256k1::Secp256k1PrivateKey;

use super::microblock_miner::MicroblockMinerThread;
use super::miner::{BlockMinerThread, Epoch2MiningState, Error, MinerTip};
use super::{MinedBlocks, NeonGlobals, BLOCK_PROCESSOR_STACK_SIZE};
use crate::burnchains::bitcoin_regtest_controller::{BitcoinRegtestController, OngoingBlockCommit};
use crate::node::chainstate;
use crate::node::leader_key::{load_activated_vrf_key, make_leader_key_register_op, RegisteredKey};
use crate::node::protocol::fault_injection::fault_injection_skip_mining;
use crate::node::runtime::DownloadReadiness;
use crate::{Config, EventDispatcher, Keychain};

/// Command types for the relayer thread, issued to it by other threads
#[allow(clippy::large_enum_variant)]
pub enum RelayerDirective {
    /// Handle some new data that arrived on the network (such as blocks, transactions, and
    HandleNetResult(NetworkResult),
    /// Announce a new sortition.  Process and broadcast the block if we won.
    ProcessTenure(ConsensusHash, BurnchainHeaderHash, BlockHeaderHash),
    /// Try to mine a block
    RunTenure(RegisteredKey, BlockSnapshot, u128), // (vrf key, chain tip, time of issuance in ms)
    /// Try to register a VRF public key
    RegisterKey(BlockSnapshot),
    /// Stop the relayer thread
    Exit,
}

/// Result of running the miner thread.  It could produce a Stacks block or a microblock.
#[allow(clippy::large_enum_variant)]
pub enum MinerThreadResult {
    Block(
        AssembledAnchorBlock,
        Secp256k1PrivateKey,
        Option<OngoingBlockCommit>,
    ),
    Microblock(
        Result<Option<(StacksMicroblock, ExecutionCost)>, NetError>,
        MinerTip,
    ),
}

/// Relayer thread
/// * accepts network results and stores blocks and microblocks
/// * forwards new blocks, microblocks, and transactions to the p2p thread
/// * processes burnchain state
/// * if mining, runs the miner and broadcasts blocks (via a subordinate MinerThread)
pub struct RelayerThread {
    /// Node config
    pub config: Config,
    /// Handle to the sortition DB (optional so we can take/replace it)
    pub sortdb: Option<SortitionDB>,
    /// Handle to the chainstate DB (optional so we can take/replace it)
    pub chainstate: Option<StacksChainState>,
    /// Handle to the mempool DB (optional so we can take/replace it)
    pub mempool: Option<MemPoolDB>,
    /// Handle to global state and inter-thread communication channels
    pub globals: NeonGlobals,
    /// Epoch 2 mining caches shared by successive block-miner threads
    pub mining_state: Epoch2MiningState,
    /// Authoritative copy of the keychain state
    pub keychain: Keychain,
    /// Burnchian configuration
    pub burnchain: Burnchain,
    /// height of last VRF key registration request
    last_vrf_key_burn_height: u64,
    /// Set of blocks that we have mined, but are still potentially-broadcastable
    pub last_mined_blocks: MinedBlocks,
    /// client to the burnchain (used only for sending block-commits)
    pub bitcoin_controller: BitcoinRegtestController,
    /// client to the event dispatcher
    pub event_dispatcher: EventDispatcher,
    /// copy of the local peer state
    local_peer: LocalPeer,
    /// last time we tried to mine a block (in millis)
    last_tenure_issue_time: u128,
    /// Network-download progress that gates mining after a burnchain advance.
    download_readiness: DownloadReadiness,
    /// consensus hash of the last sortition we saw, even if we weren't the winner
    last_tenure_consensus_hash: Option<ConsensusHash>,
    /// tip of last tenure we won (used for mining microblocks)
    pub miner_tip: Option<MinerTip>,
    /// last time we mined a microblock, in millis
    last_microblock_tenure_time: u128,
    /// when should we run the next microblock tenure, in millis
    microblock_deadline: u128,
    /// cost of the last-produced microblock stream
    pub microblock_stream_cost: ExecutionCost,

    /// Inner relayer instance for forwarding broadcasted data back to the p2p thread for dispatch
    /// to neighbors
    relayer: Relayer,

    /// handle to the subordinate miner thread
    miner_thread: Option<JoinHandle<Option<MinerThreadResult>>>,
    /// if true, then the last time the miner thread was launched, it was used to mine a Stacks
    /// block (used to alternate between mining microblocks and Stacks blocks that confirm them)
    mined_stacks_block: bool,
    /// if true, the last time the miner thread was launched, it did not mine.
    pub last_attempt_failed: bool,
}

impl RelayerThread {
    /// Instantiate the Epoch 2 relayer from runtime-owned node resources.
    pub fn new(
        config: Config,
        globals: NeonGlobals,
        burnchain: Burnchain,
        event_dispatcher: EventDispatcher,
        local_peer: LocalPeer,
        relayer: Relayer,
    ) -> RelayerThread {
        let burn_db_path = config.get_burn_db_file_path();
        let stacks_chainstate_path = config.get_chainstate_path_str();
        let is_mainnet = config.is_mainnet();
        let chain_id = config.burnchain.chain_id;

        let sortdb = SortitionDB::open(
            &burn_db_path,
            true,
            burnchain.pox_constants.clone(),
            Some(config.node.get_marf_opts()),
        )
        .expect("FATAL: failed to open burnchain DB");

        let chainstate =
            chainstate::open_chainstate(&config).expect("FATAL: failed to open chainstate DB");

        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let mempool = MemPoolDB::open(
            is_mainnet,
            chain_id,
            &stacks_chainstate_path,
            cost_estimator,
            metric,
        )
        .expect("Database failure opening mempool");

        let keychain = Keychain::default(config.node.seed.clone());
        let bitcoin_controller = BitcoinRegtestController::new_dummy(config.clone());

        RelayerThread {
            config,
            sortdb: Some(sortdb),
            chainstate: Some(chainstate),
            mempool: Some(mempool),
            globals,
            mining_state: Epoch2MiningState::default(),
            keychain,
            burnchain,
            last_vrf_key_burn_height: 0,
            last_mined_blocks: MinedBlocks::new(),
            bitcoin_controller,
            event_dispatcher,
            local_peer,

            last_tenure_issue_time: 0,
            download_readiness: DownloadReadiness::default(),

            last_tenure_consensus_hash: None,
            miner_tip: None,
            last_microblock_tenure_time: 0,
            microblock_deadline: 0,
            microblock_stream_cost: ExecutionCost::ZERO,

            relayer,

            miner_thread: None,
            mined_stacks_block: false,
            last_attempt_failed: false,
        }
    }

    /// Get an immutible ref to the sortdb
    pub fn sortdb_ref(&self) -> &SortitionDB {
        self.sortdb
            .as_ref()
            .expect("FATAL: tried to access sortdb while taken")
    }

    /// Get an immutible ref to the chainstate
    pub fn chainstate_ref(&self) -> &StacksChainState {
        self.chainstate
            .as_ref()
            .expect("FATAL: tried to access chainstate while it was taken")
    }

    /// Fool the borrow checker into letting us do something with the chainstate databases.
    /// DOES NOT COMPOSE -- do NOT call this, or self.sortdb_ref(), or self.chainstate_ref(), within
    /// `func`.  You will get a runtime panic.
    pub fn with_chainstate<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(&mut RelayerThread, &mut SortitionDB, &mut StacksChainState, &mut MemPoolDB) -> R,
    {
        let mut sortdb = self
            .sortdb
            .take()
            .expect("FATAL: tried to take sortdb while taken");
        let mut chainstate = self
            .chainstate
            .take()
            .expect("FATAL: tried to take chainstate while taken");
        let mut mempool = self
            .mempool
            .take()
            .expect("FATAL: tried to take mempool while taken");
        let res = func(self, &mut sortdb, &mut chainstate, &mut mempool);
        self.sortdb = Some(sortdb);
        self.chainstate = Some(chainstate);
        self.mempool = Some(mempool);
        res
    }

    /// have we waited for the right conditions under which to start mining a block off of our
    /// chain tip?
    pub fn has_waited_for_latest_blocks(&self) -> bool {
        self.download_readiness.permits_mining(
            self.config.miner.wait_for_block_download,
            self.config.node.wait_time_for_blocks,
            get_epoch_time_ms(),
        )
    }

    /// Return debug string for waiting for latest blocks
    pub fn debug_waited_for_latest_blocks(&self) -> String {
        self.download_readiness.diagnostic_status(
            self.config.miner.wait_for_block_download,
            self.config.node.wait_time_for_blocks,
            get_epoch_time_ms(),
        )
    }

    /// Handle a NetworkResult from the p2p/http state machine.  Usually this is the act of
    /// * preprocessing and storing new blocks and microblocks
    /// * relaying blocks, microblocks, and transactions
    /// * updating unconfirmed state views
    pub fn process_network_result(&mut self, mut net_result: NetworkResult) {
        debug!(
            "Relayer: Handle network result (from {})",
            net_result.burn_height
        );

        if self.download_readiness.observe_burn_height(
            net_result.burn_height,
            net_result.num_download_passes,
            get_epoch_time_ms(),
        ) {
            // burnchain advanced; disable mining until we also do a download pass.
            debug!(
                "Relayer: block mining until the next download pass {}",
                net_result.num_download_passes + 1
            );
            signal_mining_blocked(self.globals.get_miner_status());
        }

        let net_receipts = self.with_chainstate(|relayer_thread, sortdb, chainstate, mempool| {
            relayer_thread
                .relayer
                .process_network_result(
                    &relayer_thread.local_peer,
                    &mut net_result,
                    &relayer_thread.burnchain,
                    sortdb,
                    chainstate,
                    mempool,
                    relayer_thread.globals.sync_comms.get_ibd(),
                    Some(&relayer_thread.globals.coord_comms),
                    Some(&relayer_thread.event_dispatcher),
                )
                .expect("BUG: failure processing network results")
        });

        if net_receipts.num_new_blocks > 0 || net_receipts.num_new_confirmed_microblocks > 0 {
            // if we received any new block data that could invalidate our view of the chain tip,
            // then stop mining until we process it
            debug!("Relayer: block mining to process newly-arrived blocks or microblocks");
            signal_mining_blocked(self.globals.get_miner_status());
        }

        let mempool_txs_added = net_receipts.mempool_txs_added.len();
        if mempool_txs_added > 0 {
            self.event_dispatcher
                .process_new_mempool_txs(net_receipts.mempool_txs_added);
        }

        let num_unconfirmed_microblock_tx_receipts =
            net_receipts.processed_unconfirmed_state.receipts.len();
        if num_unconfirmed_microblock_tx_receipts > 0 {
            if let Some(unconfirmed_state) = self.chainstate_ref().unconfirmed_state.as_ref() {
                self.event_dispatcher.process_new_microblocks(
                    &unconfirmed_state.confirmed_chain_tip,
                    &net_receipts.processed_unconfirmed_state,
                );
            } else {
                warn!("Relayer: oops, unconfirmed state is uninitialized but there are microblock events");
            }
        }

        // Dispatch retrieved attachments, if any.
        if net_result.has_attachments() {
            self.event_dispatcher
                .process_new_attachments(&net_result.attachments);
        }

        // synchronize unconfirmed tx index to p2p thread
        self.with_chainstate(|relayer_thread, _sortdb, chainstate, _mempool| {
            relayer_thread.globals.send_unconfirmed_txs(chainstate);
        });

        // resume mining if we blocked it, and if we've done the requisite download
        // passes
        self.download_readiness
            .record_completed_passes(net_result.num_download_passes);
        if self.has_waited_for_latest_blocks() {
            debug!("Relayer: did a download pass, so unblocking mining");
            signal_mining_ready(self.globals.get_miner_status());
        }
    }

    /// Process the block and microblocks from a sortition that we won.
    /// At this point, we're modifying the chainstate, and merging the artifacts from the previous tenure.
    /// Blocks until the given stacks block is processed.
    /// Returns true if we accepted this block as new.
    /// Returns false if we already processed this block.
    fn accept_winning_tenure(
        &mut self,
        anchored_block: &StacksBlock,
        consensus_hash: &ConsensusHash,
        parent_consensus_hash: &ConsensusHash,
    ) -> Result<bool, ChainstateError> {
        if StacksChainState::has_stored_block(
            self.chainstate_ref().db(),
            &self.chainstate_ref().blocks_path,
            consensus_hash,
            &anchored_block.block_hash(),
        )? {
            // already processed my tenure
            return Ok(false);
        }
        let burn_height =
            SortitionDB::get_block_snapshot_consensus(self.sortdb_ref().conn(), consensus_hash)
                .map_err(|e| {
                    error!("Failed to find block snapshot for mined block: {e}");
                    e
                })?
                .ok_or_else(|| {
                    error!("Failed to find block snapshot for mined block");
                    ChainstateError::NoSuchBlockError
                })?
                .block_height;

        let epoch_id = SortitionDB::get_stacks_epoch(self.sortdb_ref().conn(), burn_height)?
            .expect("FATAL: no epoch defined")
            .epoch_id;

        // failsafe
        if !Relayer::static_check_problematic_relayed_block(
            self.chainstate_ref().mainnet,
            epoch_id,
            anchored_block,
        ) {
            // nope!
            warn!(
                "Our mined block {} was problematic. Will NOT process.",
                &anchored_block.block_hash()
            );
            #[cfg(any(test, feature = "testing"))]
            {
                use std::io::Write;
                use std::path::Path;
                if let Ok(path) = std::env::var("STACKS_BAD_BLOCKS_DIR") {
                    // record this block somewhere
                    if fs::metadata(&path).is_err() {
                        fs::create_dir_all(&path)
                            .unwrap_or_else(|_| panic!("FATAL: could not create '{path}'"));
                    }

                    let path = Path::new(&path);
                    let path = path.join(Path::new(&format!("{}", &anchored_block.block_hash())));
                    let mut file = fs::File::create(&path)
                        .unwrap_or_else(|_| panic!("FATAL: could not create '{path:?}'"));

                    let block_bits = anchored_block.serialize_to_vec();
                    let block_bits_hex = to_hex(&block_bits);
                    let block_json =
                        format!(r#"{{"block":"{block_bits_hex}","consensus":"{consensus_hash}"}}"#);
                    file.write_all(block_json.as_bytes()).unwrap_or_else(|_| {
                        panic!("FATAL: failed to write block bits to '{path:?}'")
                    });
                    info!(
                        "Fault injection: bad block {} saved to {}",
                        &anchored_block.block_hash(),
                        &path.to_str().unwrap()
                    );
                }
            }
            return Err(ChainstateError::NoTransactionsToMine);
        }

        // Preprocess the anchored block
        self.with_chainstate(|_relayer_thread, sort_db, chainstate, _mempool| {
            let ic = sort_db.index_conn();
            chainstate.preprocess_anchored_block(
                &ic,
                consensus_hash,
                anchored_block,
                parent_consensus_hash,
                0,
            )
        })?;

        Ok(true)
    }

    /// Process a new block we mined
    /// Return true if we processed it
    /// Return false if we timed out waiting for it
    /// Return Err(..) if we couldn't reach the chains coordiantor thread
    fn process_new_block(&self) -> Result<bool, Error> {
        // process the block
        let stacks_blocks_processed = self.globals.coord_comms.get_stacks_blocks_processed();
        if !self.globals.coord_comms.announce_new_stacks_block() {
            return Err(Error::CoordinatorClosed);
        }
        if !self
            .globals
            .coord_comms
            .wait_for_stacks_blocks_processed(stacks_blocks_processed, u64::MAX)
        {
            // basically unreachable
            warn!("ChainsCoordinator timed out while waiting for new stacks block to be processed");
            return Ok(false);
        }
        debug!("Relayer: Stacks block has been processed");

        Ok(true)
    }

    /// Given the two miner tips, return the newer tip.
    fn pick_higher_tip(cur: Option<MinerTip>, new: Option<MinerTip>) -> Option<MinerTip> {
        match (cur, new) {
            (Some(cur), None) => Some(cur),
            (None, Some(new)) => Some(new),
            (None, None) => None,
            (Some(cur), Some(new)) => {
                if cur.stacks_height < new.stacks_height {
                    Some(new)
                } else if cur.stacks_height > new.stacks_height {
                    Some(cur)
                } else if cur.burn_height < new.burn_height {
                    Some(new)
                } else if cur.burn_height > new.burn_height {
                    Some(cur)
                } else {
                    assert_eq!(cur, new);
                    Some(cur)
                }
            }
        }
    }

    /// Given the pointer to a recently-discovered tenure, see if we won the sortition and if so,
    /// store it, preprocess it, and forward it to our neighbors.  All the while, keep track of the
    /// latest Stacks mining tip we have produced so far.
    ///
    /// Returns (true, Some(tip)) if the coordinator is still running and we have a miner tip to
    /// build on (i.e. we won this last sortition).
    ///
    /// Returns (true, None) if the coordinator is still running, and we do NOT have a miner tip to
    /// build on (i.e. we did not win this last sortition)
    ///
    /// Returns (false, _) if the coordinator could not be reached, meaning this thread should die.
    pub fn process_one_tenure(
        &mut self,
        consensus_hash: ConsensusHash,
        block_header_hash: BlockHeaderHash,
        burn_hash: BurnchainHeaderHash,
    ) -> (bool, Option<MinerTip>) {
        let mut miner_tip = None;
        let sn =
            SortitionDB::get_block_snapshot_consensus(self.sortdb_ref().conn(), &consensus_hash)
                .expect("FATAL: failed to query sortition DB")
                .expect("FATAL: unknown consensus hash");

        debug!(
            "Relayer: Process tenure {consensus_hash}/{block_header_hash} in {burn_hash} burn height {}",
            sn.block_height
        );

        if let Some((last_mined_block_data, microblock_privkey)) =
            self.last_mined_blocks.remove(&block_header_hash)
        {
            // we won!
            let AssembledAnchorBlock {
                parent_consensus_hash,
                anchored_block: mined_block,
                burn_hash: mined_burn_hash,
                attempt: _,
                ..
            } = last_mined_block_data;

            let reward_block_height = mined_block.header.total_work.work + MINER_REWARD_MATURITY;
            info!(
                "Relayer: Won sortition! Mining reward will be received in {MINER_REWARD_MATURITY} blocks (block #{reward_block_height})"
            );
            debug!("Relayer: Won sortition!";
                  "stacks_header" => %block_header_hash,
                  "burn_hash" => %mined_burn_hash,
            );

            increment_stx_blocks_mined_counter();
            let has_new_data = match self.accept_winning_tenure(
                &mined_block,
                &consensus_hash,
                &parent_consensus_hash,
            ) {
                Ok(accepted) => accepted,
                Err(ChainstateError::ChannelClosed(_)) => {
                    warn!("Coordinator stopped, stopping relayer thread...");
                    return (false, None);
                }
                Err(e) => {
                    warn!("Error processing my tenure, bad block produced: {e}");
                    warn!(
                        "Bad block";
                        "stacks_header" => %block_header_hash,
                        "data" => %to_hex(&mined_block.serialize_to_vec()),
                    );
                    return (true, None);
                }
            };

            // advertize _and_ push blocks for now
            let blocks_available = Relayer::load_blocks_available_data(
                self.sortdb_ref(),
                vec![consensus_hash.clone()],
            )
            .expect("Failed to obtain block information for a block we mined.");

            let block_data = {
                let mut bd = HashMap::new();
                bd.insert(consensus_hash.clone(), mined_block.clone());
                bd
            };

            if let Err(e) = self.relayer.advertize_blocks(blocks_available, block_data) {
                warn!("Failed to advertise new block: {e}");
            }

            let snapshot = SortitionDB::get_block_snapshot_consensus(
                self.sortdb_ref().conn(),
                &consensus_hash,
            )
            .expect("Failed to obtain snapshot for block")
            .expect("Failed to obtain snapshot for block");

            if !snapshot.pox_valid {
                warn!(
                    "Snapshot for {consensus_hash} is no longer valid; discarding {}...",
                    &mined_block.block_hash()
                );
                miner_tip = Self::pick_higher_tip(miner_tip, None);
            } else {
                let ch = snapshot.consensus_hash.clone();
                let bh = mined_block.block_hash();
                let height = mined_block.header.total_work.work;

                let mut broadcast = true;
                if self.chainstate_ref().fault_injection.hide_blocks
                    && Relayer::fault_injection_is_block_hidden(
                        &mined_block.header,
                        snapshot.block_height,
                    )
                {
                    broadcast = false;
                }
                if broadcast {
                    if let Err(e) = self
                        .relayer
                        .broadcast_block(snapshot.consensus_hash, mined_block)
                    {
                        warn!("Failed to push new block: {e}");
                    }
                }

                // proceed to mine microblocks
                miner_tip = Some(MinerTip::new(
                    ch,
                    bh,
                    microblock_privkey,
                    height,
                    snapshot.block_height,
                ));
            }

            if has_new_data {
                // process the block, now that we've advertized it
                if let Err(Error::CoordinatorClosed) = self.process_new_block() {
                    // coordiantor stopped
                    return (false, None);
                }
            }
        } else {
            debug!(
                "Relayer: Did not win sortition in {burn_hash}, winning block was {consensus_hash}/{block_header_hash}"
            );
            miner_tip = None;
        }

        (true, miner_tip)
    }

    // TODO: add tests from mutation testing results #4872
    #[cfg_attr(test, mutants::skip)]
    /// Process all new tenures that we're aware of.
    /// Clear out stale tenure artifacts as well.
    /// Update the miner tip if we won the highest tenure (or clear it if we didn't).
    /// If we won any sortitions, send the block and microblock data to the p2p thread.
    /// Return true if we can still continue to run; false if not.
    pub fn process_new_tenures(
        &mut self,
        consensus_hash: ConsensusHash,
        burn_hash: BurnchainHeaderHash,
        block_header_hash: BlockHeaderHash,
    ) -> bool {
        let mut miner_tip = None;
        let mut num_sortitions = 0;

        // process all sortitions between the last-processed consensus hash and this
        // one.  ProcessTenure(..) messages can get lost.
        let burn_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())
            .expect("FATAL: failed to read current burnchain tip");
        let mut microblocks_disabled =
            SortitionDB::are_microblocks_disabled(self.sortdb_ref().conn(), burn_tip.block_height)
                .expect("FATAL: failed to query epoch's microblock status");

        let tenures = if let Some(last_ch) = self.last_tenure_consensus_hash.as_ref() {
            let mut tenures = vec![];
            let last_sn =
                SortitionDB::get_block_snapshot_consensus(self.sortdb_ref().conn(), last_ch)
                    .expect("FATAL: failed to query sortition DB")
                    .expect("FATAL: unknown prior consensus hash");

            debug!(
                "Relayer: query tenures between burn block heights {} and {}",
                last_sn.block_height + 1,
                burn_tip.block_height + 1
            );
            for block_to_process in (last_sn.block_height + 1)..(burn_tip.block_height + 1) {
                num_sortitions += 1;
                let sn = {
                    let ic = self.sortdb_ref().index_conn();
                    SortitionDB::get_ancestor_snapshot(
                        &ic,
                        block_to_process,
                        &burn_tip.sortition_id,
                    )
                    .expect("FATAL: failed to read ancestor snapshot from sortition DB")
                    .expect("Failed to find block in fork processed by burnchain indexer")
                };
                if !sn.sortition {
                    debug!(
                        "Relayer: Skipping tenure {}/{} at burn hash/height {},{} -- no sortition",
                        &sn.consensus_hash,
                        &sn.winning_stacks_block_hash,
                        &sn.burn_header_hash,
                        sn.block_height
                    );
                    continue;
                }
                debug!(
                    "Relayer: Will process tenure {}/{} at burn hash/height {},{}",
                    &sn.consensus_hash,
                    &sn.winning_stacks_block_hash,
                    &sn.burn_header_hash,
                    sn.block_height
                );
                tenures.push((
                    sn.consensus_hash,
                    sn.burn_header_hash,
                    sn.winning_stacks_block_hash,
                ));
            }
            tenures
        } else {
            // first-ever tenure processed
            vec![(consensus_hash, burn_hash, block_header_hash)]
        };

        debug!("Relayer: will process {} tenures", &tenures.len());
        let num_tenures = tenures.len();
        if num_tenures > 0 {
            // temporarily halt mining
            debug!(
                "Relayer: block mining to process {} tenures",
                &tenures.len()
            );
            signal_mining_blocked(self.globals.get_miner_status());
        }

        for (consensus_hash, burn_hash, block_header_hash) in tenures.into_iter() {
            self.miner_thread_try_join();
            let (continue_thread, new_miner_tip) =
                self.process_one_tenure(consensus_hash.clone(), block_header_hash, burn_hash);
            if !continue_thread {
                // coordinator thread hang-up
                return false;
            }
            miner_tip = Self::pick_higher_tip(miner_tip, new_miner_tip);

            // clear all blocks up to this consensus hash
            let this_burn_tip = SortitionDB::get_block_snapshot_consensus(
                self.sortdb_ref().conn(),
                &consensus_hash,
            )
            .expect("FATAL: failed to query sortition DB")
            .expect("FATAL: no snapshot for consensus hash");

            let old_last_mined_blocks = mem::take(&mut self.last_mined_blocks);
            self.last_mined_blocks =
                Self::clear_stale_mined_blocks(this_burn_tip.block_height, old_last_mined_blocks);

            // update last-tenure pointer
            self.last_tenure_consensus_hash = Some(consensus_hash);
        }

        if let Some(mtip) = miner_tip.take() {
            // sanity check -- is this also the canonical tip?
            let (stacks_tip_consensus_hash, stacks_tip_block_hash) =
                self.with_chainstate(|_relayer_thread, sortdb, _chainstate, _| {
                    SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).expect(
                        "FATAL: failed to query sortition DB for canonical stacks chain tip hashes",
                    )
                });

            if mtip.consensus_hash != stacks_tip_consensus_hash
                || mtip.block_hash != stacks_tip_block_hash
            {
                debug!(
                    "Relayer: miner tip {}/{} is NOT canonical ({stacks_tip_consensus_hash}/{stacks_tip_block_hash})",
                    &mtip.consensus_hash,
                    &mtip.block_hash,
                );
                miner_tip = None;
            } else {
                debug!(
                    "Relayer: Microblock miner tip is now {}/{} ({})",
                    mtip.consensus_hash,
                    mtip.block_hash,
                    StacksBlockHeader::make_index_block_hash(
                        &mtip.consensus_hash,
                        &mtip.block_hash
                    )
                );

                self.with_chainstate(|relayer_thread, sortdb, chainstate, _mempool| {
                    Relayer::refresh_unconfirmed(chainstate, sortdb);
                    relayer_thread.globals.send_unconfirmed_txs(chainstate);
                });

                miner_tip = Some(mtip);
            }
        }

        // update state for microblock mining
        self.setup_microblock_mining_state(miner_tip);

        if cfg!(test)
            && std::env::var("STACKS_TEST_FORCE_MICROBLOCKS_POST_25").as_deref() == Ok("1")
        {
            debug!("Allowing miner to mine microblocks because STACKS_TEST_FORCE_MICROBLOCKS_POST_25 = 1");
            microblocks_disabled = false;
        }

        // resume mining if we blocked it
        if num_tenures > 0 || num_sortitions > 0 {
            if self.miner_tip.is_some() {
                // we won the highest tenure
                if self.config.node.mine_microblocks && !microblocks_disabled {
                    // mine a microblock first
                    self.mined_stacks_block = true;
                } else {
                    // mine a Stacks block first -- we won't build microblocks
                    self.mined_stacks_block = false;
                }
            } else {
                // mine a Stacks block first -- we didn't win
                self.mined_stacks_block = false;
            }
            signal_mining_ready(self.globals.get_miner_status());
        }
        true
    }

    /// Update the miner tip with a new tip.  If it's changed, then clear out the microblock stream
    /// cost since we won't be mining it anymore.
    fn setup_microblock_mining_state(&mut self, new_miner_tip: Option<MinerTip>) {
        // update state
        let my_miner_tip = mem::take(&mut self.miner_tip);
        let best_tip = Self::pick_higher_tip(my_miner_tip.clone(), new_miner_tip.clone());
        if best_tip == new_miner_tip && best_tip != my_miner_tip {
            // tip has changed
            debug!("Relayer: Best miner tip went from {my_miner_tip:?} to {new_miner_tip:?}");
            self.microblock_stream_cost = ExecutionCost::ZERO;
        }
        self.miner_tip = best_tip;
    }

    /// Try to resume microblock mining if we don't need to build an anchored block
    fn try_resume_microblock_mining(&mut self) {
        if self.miner_tip.is_some() {
            // we won the highest tenure
            if self.config.node.mine_microblocks {
                // mine a microblock first
                self.mined_stacks_block = true;
            } else {
                // mine a Stacks block first -- we won't build microblocks
                self.mined_stacks_block = false;
            }
        } else {
            // mine a Stacks block first -- we didn't win
            self.mined_stacks_block = false;
        }
    }

    /// Create and broadcast a VRF public key registration transaction.
    /// Returns true if we succeed in doing so; false if not.
    pub fn rotate_vrf_and_register(&mut self, burn_block: &BlockSnapshot) {
        if burn_block.block_height == self.last_vrf_key_burn_height {
            // already in-flight
            return;
        }
        let cur_epoch =
            SortitionDB::get_stacks_epoch(self.sortdb_ref().conn(), burn_block.block_height)
                .expect("FATAL: failed to query sortition DB")
                .expect("FATAL: no epoch defined")
                .epoch_id;
        let (vrf_pk, _) = self.keychain.make_vrf_keypair(burn_block.block_height);

        debug!(
            "Submit leader-key-register for {} {}",
            &vrf_pk.to_hex(),
            burn_block.block_height
        );

        let burnchain_tip_consensus_hash = burn_block.consensus_hash.clone();
        // if the miner has set a mining key in preparation for epoch-3.0, register it as part of their VRF key registration
        // once implemented in the nakamoto_node, this will allow miners to transition from 2.5 to 3.0 without submitting a new
        // VRF key registration.
        let miner_pk = self
            .config
            .miner
            .mining_key
            .as_ref()
            .map(StacksPublicKey::from_private);
        let memo = miner_pk
            .as_ref()
            .map(|public_key| {
                Hash160::from_node_public_key(public_key)
                    .as_bytes()
                    .to_vec()
            })
            .unwrap_or_default();
        let op = make_leader_key_register_op(vrf_pk, burnchain_tip_consensus_hash, memo);

        let mut one_off_signer = self.keychain.generate_op_signer();
        if let Ok(txid) =
            self.bitcoin_controller
                .submit_operation(cur_epoch, op, &mut one_off_signer)
        {
            // advance key registration state
            self.last_vrf_key_burn_height = burn_block.block_height;
            self.globals
                .set_pending_leader_key_registration(burn_block.block_height, txid);
        }
    }

    /// Remove any block state we've mined for the given burnchain height.
    /// Return the filtered `last_mined_blocks`
    fn clear_stale_mined_blocks(burn_height: u64, last_mined_blocks: MinedBlocks) -> MinedBlocks {
        let mut ret = HashMap::new();
        for (stacks_bhh, (assembled_block, microblock_privkey)) in last_mined_blocks.into_iter() {
            if assembled_block.burn_block_height < burn_height {
                debug!(
                    "Stale mined block: {stacks_bhh} (as of {},{})",
                    &assembled_block.burn_hash, assembled_block.burn_block_height
                );
                continue;
            }
            debug!(
                "Mined block in-flight: {stacks_bhh} (as of {},{})",
                &assembled_block.burn_hash, assembled_block.burn_block_height
            );
            ret.insert(stacks_bhh, (assembled_block, microblock_privkey));
        }
        ret
    }

    /// Create the block miner thread state.
    /// Only proceeds if all of the following are true:
    ///   * The miner is not blocked
    ///   * `last_burn_block` corresponds to the canonical sortition DB's chain tip
    ///   * The time of issuance is sufficiently recent
    ///   * There are no unprocessed stacks blocks in the staging DB
    ///   * The relayer has already tried a download scan that included this sortition (which, if a
    ///     block was found, would have placed it into the staging DB and marked it as
    ///     unprocessed)
    ///   * A miner thread is not running already
    fn create_block_miner(
        &mut self,
        registered_key: RegisteredKey,
        last_burn_block: BlockSnapshot,
        issue_timestamp_ms: u128,
    ) -> Option<BlockMinerThread> {
        if self
            .globals
            .get_miner_status()
            .lock()
            .expect("FATAL: mutex poisoned")
            .is_blocked()
        {
            debug!(
                "Relayer: miner is blocked as of {}; cannot mine Stacks block at this time",
                &last_burn_block.burn_header_hash
            );
            return None;
        }

        if fault_injection_skip_mining(&self.config.node.rpc_bind, last_burn_block.block_height) {
            debug!(
                "Relayer: fault injection skip mining at block height {}",
                last_burn_block.block_height
            );
            return None;
        }

        // start a new tenure
        if let Some(cur_sortition) = self.globals.get_last_sortition() {
            if last_burn_block.sortition_id != cur_sortition.sortition_id {
                debug!(
                    "Relayer: Drop stale RunTenure for {}: current sortition is for {}",
                    &last_burn_block.burn_header_hash, &cur_sortition.burn_header_hash
                );
                self.globals.counters.bump_missed_tenures();
                return None;
            }
        }

        let burn_header_hash = last_burn_block.burn_header_hash.clone();
        let burn_chain_sn = SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        let burn_chain_tip = burn_chain_sn.burn_header_hash;

        if burn_chain_tip != burn_header_hash {
            debug!(
                "Relayer: Drop stale RunTenure for {burn_header_hash}: current sortition is for {burn_chain_tip}"
            );
            self.globals.counters.bump_missed_tenures();
            return None;
        }

        let miner_config = self.config.get_miner_config();

        let has_unprocessed = BlockMinerThread::unprocessed_blocks_prevent_mining(
            &self.burnchain,
            self.sortdb_ref(),
            self.chainstate_ref(),
            miner_config.unprocessed_block_deadline_secs,
        );
        if has_unprocessed {
            debug!(
                "Relayer: Drop RunTenure for {burn_header_hash} because there are fewer than {} pending blocks",
                self.burnchain.pox_constants.prepare_length - 1
            );
            return None;
        }

        if burn_chain_sn.block_height != self.download_readiness.burn_height()
            || !self.has_waited_for_latest_blocks()
        {
            debug!("Relayer: network has not had a chance to process in-flight blocks ({} != {} || !({}))",
                    burn_chain_sn.block_height, self.download_readiness.burn_height(), self.debug_waited_for_latest_blocks());
            return None;
        }

        let tenure_cooldown = if self.config.node.mine_microblocks {
            self.config.node.wait_time_for_microblocks as u128
        } else {
            0
        };

        // no burnchain change, so only re-run block tenure every so often in order
        // to give microblocks a chance to collect
        if issue_timestamp_ms < self.last_tenure_issue_time + tenure_cooldown {
            debug!("Relayer: will NOT run tenure since issuance at {} is too fresh (wait until {} + {} = {})",
                    issue_timestamp_ms / 1000, self.last_tenure_issue_time / 1000, tenure_cooldown / 1000, (self.last_tenure_issue_time + tenure_cooldown) / 1000);
            return None;
        }

        // if we're still mining on this burn block, then do nothing
        if self.miner_thread.is_some() {
            debug!("Relayer: will NOT run tenure since miner thread is already running for burn tip {burn_chain_tip}");
            return None;
        }

        debug!(
            "Relayer: Spawn tenure thread";
            "height" => last_burn_block.block_height,
            "burn_header_hash" => %burn_header_hash,
        );

        let miner_thread_state =
            BlockMinerThread::from_relayer_thread(self, registered_key, last_burn_block);
        Some(miner_thread_state)
    }

    /// Try to start up a block miner thread with this given VRF key and current burnchain tip.
    /// Returns true if the thread was started; false if it was not (for any reason)
    #[allow(clippy::incompatible_msrv)]
    pub fn block_miner_thread_try_start(
        &mut self,
        registered_key: RegisteredKey,
        last_burn_block: BlockSnapshot,
        issue_timestamp_ms: u128,
    ) -> bool {
        if !self.miner_thread_try_join() {
            return false;
        }

        if !self.config.get_node_config(false).mock_mining {
            // mock miner can't mine microblocks yet, so don't stop it from trying multiple
            // anchored blocks
            if self.mined_stacks_block && self.config.node.mine_microblocks {
                debug!("Relayer: mined a Stacks block already; waiting for microblock miner");
                return false;
            }
        }

        let Some(mut miner_thread_state) =
            self.create_block_miner(registered_key, last_burn_block, issue_timestamp_ms)
        else {
            return false;
        };

        if let Ok(miner_handle) = thread::Builder::new()
            .name(format!("miner-block-{}", self.local_peer.data_url))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                if let Err(e) = miner_thread_state.send_mock_miner_messages() {
                    warn!("Failed to send mock miner messages: {e}");
                }
                miner_thread_state.run_tenure()
            })
            .inspect_err(|e| error!("Relayer: Failed to start tenure thread: {e:?}"))
        {
            self.miner_thread = Some(miner_handle);
        }

        true
    }

    // TODO: add tests from mutation testing results #4872
    #[cfg_attr(test, mutants::skip)]
    /// See if we should run a microblock tenure now.
    /// Return true if so; false if not
    fn can_run_microblock_tenure(&mut self) -> bool {
        if !self.config.node.mine_microblocks {
            // not enabled
            test_debug!("Relayer: not configured to mine microblocks");
            return false;
        }

        let burn_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())
            .expect("FATAL: failed to read current burnchain tip");
        let microblocks_disabled =
            SortitionDB::are_microblocks_disabled(self.sortdb_ref().conn(), burn_tip.block_height)
                .expect("FATAL: failed to query epoch's microblock status");

        if microblocks_disabled {
            if cfg!(test)
                && std::env::var("STACKS_TEST_FORCE_MICROBLOCKS_POST_25").as_deref() == Ok("1")
            {
                debug!("Allowing miner to mine microblocks because STACKS_TEST_FORCE_MICROBLOCKS_POST_25 = 1");
            } else {
                return false;
            }
        }

        if !self.miner_thread_try_join() {
            // already running (for an anchored block or microblock)
            test_debug!("Relayer: miner thread already running so cannot mine microblock");
            return false;
        }
        if self.microblock_deadline > get_epoch_time_ms() {
            debug!(
                "Relayer: Too soon to start a microblock tenure ({} > {})",
                self.microblock_deadline,
                get_epoch_time_ms()
            );
            return false;
        }
        if self.miner_tip.is_none() {
            debug!("Relayer: did not win last block, so cannot mine microblocks");
            return false;
        }
        if !self.mined_stacks_block {
            // have not tried to mine a stacks block yet that confirms previously-mined unconfirmed
            // state (or have not tried to mine a new Stacks block yet for this active tenure);
            debug!("Relayer: Did not mine a block yet, so will not mine a microblock");
            return false;
        }
        if self.globals.get_last_sortition().is_none() {
            debug!("Relayer: no first sortition yet");
            return false;
        }

        // go ahead
        true
    }

    /// Start up a microblock miner thread if possible:
    ///   * No miner thread must be running already
    ///   * The miner must not be blocked
    ///   * We must have won the sortition on the Stacks chain tip
    ///
    /// Returns `true` if the thread was started; `false` if not.
    #[allow(clippy::incompatible_msrv)]
    pub fn microblock_miner_thread_try_start(&mut self) -> bool {
        let miner_tip = match self.miner_tip.as_ref() {
            Some(tip) => tip.clone(),
            None => {
                debug!("Relayer: did not win last block, so cannot mine microblocks");
                return false;
            }
        };

        let burnchain_tip = match self.globals.get_last_sortition() {
            Some(sn) => sn,
            None => {
                debug!("Relayer: no first sortition yet");
                return false;
            }
        };

        debug!(
            "Relayer: mined Stacks block {}/{} so can mine microblocks",
            &miner_tip.consensus_hash, &miner_tip.block_hash
        );

        if !self.miner_thread_try_join() {
            // already running (for an anchored block or microblock)
            debug!("Relayer: miner thread already running so cannot mine microblock");
            return false;
        }
        if self
            .globals
            .get_miner_status()
            .lock()
            .expect("FATAL: mutex poisoned")
            .is_blocked()
        {
            debug!(
                "Relayer: miner is blocked as of {}; cannot mine microblock at this time",
                &burnchain_tip.burn_header_hash
            );
            self.globals.counters.set_microblocks_processed(0);
            return false;
        }

        let parent_consensus_hash = &miner_tip.consensus_hash;
        let parent_block_hash = &miner_tip.block_hash;

        debug!("Relayer: Run microblock tenure for {parent_consensus_hash}/{parent_block_hash}");

        let Some(mut microblock_thread_state) = MicroblockMinerThread::from_relayer_thread(self)
        else {
            return false;
        };

        if let Ok(miner_handle) = thread::Builder::new()
            .name(format!("miner-microblock-{}", self.local_peer.data_url))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                Some(MinerThreadResult::Microblock(
                    microblock_thread_state.try_mine_microblock(miner_tip.clone()),
                    miner_tip,
                ))
            })
            .inspect_err(|e| error!("Relayer: Failed to start tenure thread: {e:?}"))
        {
            // thread started!
            self.miner_thread = Some(miner_handle);
            self.microblock_deadline =
                get_epoch_time_ms() + (self.config.node.microblock_frequency as u128);
        }

        true
    }

    /// Inner body of Self::miner_thread_try_join
    fn inner_miner_thread_try_join(
        &mut self,
        thread_handle: JoinHandle<Option<MinerThreadResult>>,
    ) -> Option<JoinHandle<Option<MinerThreadResult>>> {
        // tenure run already in progress; try and join
        if !thread_handle.is_finished() {
            debug!("Relayer: RunTenure thread not finished / is in-progress");
            return Some(thread_handle);
        }
        let last_mined_block_opt = thread_handle
            .join()
            .expect("FATAL: failed to join miner thread");
        self.last_attempt_failed = false;
        if let Some(miner_result) = last_mined_block_opt {
            match miner_result {
                MinerThreadResult::Block(
                    last_mined_block,
                    microblock_privkey,
                    ongoing_commit_opt,
                ) => {
                    // finished mining a block
                    if BlockMinerThread::find_inflight_mined_blocks(
                        last_mined_block.burn_block_height,
                        &self.last_mined_blocks,
                    )
                    .is_empty()
                    {
                        // first time we've mined a block in this burnchain block
                        debug!(
                            "Bump block processed for burnchain block {}",
                            &last_mined_block.burn_block_height
                        );
                        self.globals.counters.bump_blocks_processed();
                    }

                    debug!(
                        "Relayer: RunTenure thread joined; got Stacks block {}",
                        &last_mined_block.anchored_block.block_hash()
                    );

                    let bhh = last_mined_block.burn_hash.clone();
                    let orig_bhh = last_mined_block.orig_burn_hash.clone();
                    let tenure_begin = last_mined_block.tenure_begin;

                    self.last_mined_blocks.insert(
                        last_mined_block.anchored_block.block_hash(),
                        (last_mined_block, microblock_privkey),
                    );

                    self.last_tenure_issue_time = get_epoch_time_ms();
                    self.bitcoin_controller
                        .set_ongoing_commit(ongoing_commit_opt);

                    debug!(
                        "Relayer: RunTenure finished at {} (in {}ms) targeting {bhh} (originally {orig_bhh})",
                        self.last_tenure_issue_time,
                        self.last_tenure_issue_time.saturating_sub(tenure_begin)
                    );

                    // this stacks block confirms all in-flight microblocks we know about,
                    // including the ones we produced.
                    self.mined_stacks_block = true;
                }
                MinerThreadResult::Microblock(microblock_result, miner_tip) => {
                    // finished mining a microblock
                    match microblock_result {
                        Ok(Some((next_microblock, new_cost))) => {
                            // apply it
                            let microblock_hash = next_microblock.block_hash();

                            let (processed_unconfirmed_state, num_mblocks) = self.with_chainstate(
                                |_relayer_thread, sortdb, chainstate, _mempool| {
                                    let processed_unconfirmed_state =
                                        Relayer::refresh_unconfirmed(chainstate, sortdb);
                                    let num_mblocks = chainstate
                                        .unconfirmed_state
                                        .as_ref()
                                        .map(|unconfirmed| unconfirmed.num_microblocks())
                                        .unwrap_or(0);

                                    (processed_unconfirmed_state, num_mblocks)
                                },
                            );

                            info!(
                                "Mined one microblock: {microblock_hash} seq {} txs {} (total processed: {num_mblocks})",
                                next_microblock.header.sequence,
                                next_microblock.txs.len()
                            );
                            self.globals.counters.set_microblocks_processed(num_mblocks);

                            let parent_index_block_hash = StacksBlockHeader::make_index_block_hash(
                                &miner_tip.consensus_hash,
                                &miner_tip.block_hash,
                            );
                            self.event_dispatcher.process_new_microblocks(
                                &parent_index_block_hash,
                                &processed_unconfirmed_state,
                            );

                            // send it off
                            if let Err(e) = self.relayer.broadcast_microblock(
                                &miner_tip.consensus_hash,
                                &miner_tip.block_hash,
                                next_microblock,
                            ) {
                                error!(
                                    "Failure trying to broadcast microblock {microblock_hash}: {e}"
                                );
                            }

                            self.last_microblock_tenure_time = get_epoch_time_ms();
                            self.microblock_stream_cost = new_cost;

                            // synchronise state
                            self.with_chainstate(
                                |relayer_thread, _sortdb, chainstate, _mempool| {
                                    relayer_thread.globals.send_unconfirmed_txs(chainstate);
                                },
                            );

                            // have not yet mined a stacks block that confirms this microblock, so
                            // do that on the next run
                            self.mined_stacks_block = false;
                        }
                        Ok(None) => {
                            debug!("Relayer: did not mine microblock in this tenure");

                            // switch back to block mining
                            self.mined_stacks_block = false;
                        }
                        Err(e) => {
                            warn!("Relayer: Failed to mine next microblock: {e:?}");

                            // switch back to block mining
                            self.mined_stacks_block = false;
                        }
                    }
                }
            }
        } else {
            self.last_attempt_failed = true;
            // if we tried and failed to make an anchored block (e.g. because there's nothing to
            // do), then resume microblock mining
            if !self.mined_stacks_block {
                self.try_resume_microblock_mining();
            }
        }
        None
    }

    /// Try to join with the miner thread. If successful, join the thread and return `true`.
    /// Otherwise, if the thread is still running, return `false`.
    ///
    /// Updates internal state gleaned from the miner, such as:
    ///   * New Stacks block data
    ///   * New keychain state
    ///   * New metrics
    ///   * New unconfirmed state
    ///
    /// Returns `true` if joined; `false` if not.
    pub fn miner_thread_try_join(&mut self) -> bool {
        if let Some(thread_handle) = self.miner_thread.take() {
            let new_thread_handle = self.inner_miner_thread_try_join(thread_handle);
            self.miner_thread = new_thread_handle;
        }
        self.miner_thread.is_none()
    }

    /// Try loading up a saved VRF key
    fn load_saved_vrf_key(path: &str) -> Option<RegisteredKey> {
        let registered_key = load_activated_vrf_key(path)?;
        info!("Loaded registered key from {path}");
        Some(registered_key)
    }

    /// Top-level dispatcher
    pub fn handle_directive(&mut self, directive: RelayerDirective) -> bool {
        debug!("Relayer: received next directive");
        let continue_running = match directive {
            RelayerDirective::HandleNetResult(net_result) => {
                debug!("Relayer: directive Handle network result");
                self.process_network_result(net_result);
                debug!("Relayer: directive Handled network result");
                true
            }
            RelayerDirective::RegisterKey(last_burn_block) => {
                let mut saved_key_opt = None;
                if let Some(path) = self.config.miner.activated_vrf_key_path.as_ref() {
                    saved_key_opt = Self::load_saved_vrf_key(path);
                }
                if let Some(saved_key) = saved_key_opt {
                    self.globals.resume_leader_key(saved_key);
                } else {
                    self.rotate_vrf_and_register(&last_burn_block);
                    debug!("Relayer: directive Registered VRF key");
                }
                self.globals.counters.bump_blocks_processed();
                true
            }
            RelayerDirective::ProcessTenure(consensus_hash, burn_hash, block_header_hash) => {
                debug!("Relayer: directive Process tenures");
                let res = self.process_new_tenures(consensus_hash, burn_hash, block_header_hash);
                debug!("Relayer: directive Processed tenures");
                res
            }
            RelayerDirective::RunTenure(registered_key, last_burn_block, issue_timestamp_ms) => {
                debug!("Relayer: directive Run tenure");
                let Ok(Some(next_block_epoch)) = SortitionDB::get_stacks_epoch(
                    self.sortdb_ref().conn(),
                    last_burn_block.block_height.saturating_add(1),
                ) else {
                    warn!("Failed to load Stacks Epoch for next burn block, skipping RunTenure directive");
                    return true;
                };
                if next_block_epoch.epoch_id.uses_nakamoto_blocks() {
                    info!("Next burn block is in Nakamoto epoch, skipping RunTenure directive for 2.x node");
                    return true;
                }
                self.block_miner_thread_try_start(
                    registered_key,
                    last_burn_block,
                    issue_timestamp_ms,
                );
                debug!("Relayer: directive Ran tenure");
                true
            }
            RelayerDirective::Exit => false,
        };
        if !continue_running {
            return false;
        }

        // see if we need to run a microblock tenure
        if self.can_run_microblock_tenure() {
            self.microblock_miner_thread_try_start();
        }
        continue_running
    }
}
