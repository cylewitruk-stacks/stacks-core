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

#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::io::Write;
use std::thread;

use clarity::vm::costs::ExecutionCost;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::miner::{BlockBuilderSettings, StacksMicroblockBuilder};
use stacks::chainstate::stacks::{Error as ChainstateError, StacksBlockHeader, StacksMicroblock};
use stacks::core::mempool::MemPoolDB;
use stacks::cost_estimates::metrics::UnitMetric;
use stacks::cost_estimates::UnitEstimator;
use stacks::net::relay::Relayer;
use stacks::net::Error as NetError;
#[cfg(test)]
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::BlockHeaderHash;
#[cfg(test)]
use stacks_common::util::hash::to_hex;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs};

use super::miner::MinerTip;
use super::relayer::RelayerThread;
use super::NeonGlobals;
use crate::node::chainstate;
use crate::EventDispatcher;

/// State representing the microblock miner.
pub struct MicroblockMinerThread {
    /// handle to global state
    globals: NeonGlobals,
    /// handle to chainstate DB (optional so we can take/replace it)
    chainstate: Option<StacksChainState>,
    /// handle to sortition DB (optional so we can take/replace it)
    sortdb: Option<SortitionDB>,
    /// handle to mempool DB (optional so we can take/replace it)
    mempool: Option<MemPoolDB>,
    /// Handle to the node's event dispatcher
    event_dispatcher: EventDispatcher,
    /// Parent Stacks block's sortition's consensus hash
    parent_consensus_hash: ConsensusHash,
    /// Parent Stacks block's hash
    parent_block_hash: BlockHeaderHash,
    /// Microblock signing key
    miner_key: Secp256k1PrivateKey,
    /// How often to make microblocks, in milliseconds
    frequency: u64,
    /// Epoch timestamp, in milliseconds, when the last microblock was produced
    last_mined: u128,
    /// How many microblocks produced so far
    quantity: u64,
    /// Block budget consumed so far by this tenure (initialized to the cost of the Stacks block
    /// itself; microblocks fill up the remaining budget)
    cost_so_far: ExecutionCost,
    /// Block builder settings for the microblock miner.
    settings: BlockBuilderSettings,
}

impl MicroblockMinerThread {
    /// Instantiate the miner thread state from the relayer thread.
    /// May fail if:
    /// * we didn't win the last sortition
    /// * we couldn't open or read the DBs for some reason
    /// * we couldn't find the anchored block (i.e. it's not processed yet)
    pub fn from_relayer_thread(relayer_thread: &RelayerThread) -> Option<MicroblockMinerThread> {
        let globals = relayer_thread.globals.clone();
        let config = relayer_thread.config.clone();
        let burnchain = relayer_thread.burnchain.clone();
        let miner_tip = match relayer_thread.miner_tip.clone() {
            Some(tip) => tip,
            None => {
                debug!("Relayer: cannot instantiate microblock miner: did not win Stacks tip sortition");
                return None;
            }
        };

        let stacks_chainstate_path = config.get_chainstate_path_str();
        let burn_db_path = config.get_burn_db_file_path();
        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        // NOTE: read-write access is needed in order to be able to query the recipient set.
        // This is an artifact of the way the MARF is built (see #1449)
        let sortdb = SortitionDB::open(
            &burn_db_path,
            true,
            burnchain.pox_constants,
            Some(config.node.get_marf_opts()),
        )
        .map_err(|e| {
            error!("Relayer: Could not open sortdb '{burn_db_path}' ({e:?}); skipping tenure");
            e
        })
        .ok()?;

        let mut chainstate = chainstate::open_chainstate(&config)
            .map_err(|e| {
                error!(
                    "Relayer: Could not open chainstate '{stacks_chainstate_path}' ({e:?}); skipping microblock tenure"
                );
                e
            })
            .ok()?;

        let mempool = MemPoolDB::open(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &stacks_chainstate_path,
            cost_estimator,
            metric,
        )
        .expect("Database failure opening mempool");

        let MinerTip {
            consensus_hash: ch,
            block_hash: bhh,
            microblock_privkey: miner_key,
            ..
        } = miner_tip;

        debug!("Relayer: Instantiate microblock mining state off of {ch}/{bhh}");

        // we won a block! proceed to build a microblock tail if we've stored it
        match StacksChainState::get_anchored_block_header_info(chainstate.db(), &ch, &bhh) {
            Ok(Some(_)) => {
                let parent_index_hash = StacksBlockHeader::make_index_block_hash(&ch, &bhh);
                let cost_so_far = if relayer_thread.microblock_stream_cost == ExecutionCost::ZERO {
                    // unknown cost, or this is idempotent.
                    StacksChainState::get_stacks_block_anchored_cost(
                        chainstate.db(),
                        &parent_index_hash,
                    )
                    .expect("FATAL: failed to get anchored block cost")
                    .expect("FATAL: no anchored block cost stored for processed anchored block")
                } else {
                    relayer_thread.microblock_stream_cost.clone()
                };

                let frequency = config.node.microblock_frequency;
                let settings =
                    config.make_block_builder_settings(0, true, globals.get_miner_status());

                // port over unconfirmed state to this thread
                chainstate.unconfirmed_state = if let Some(unconfirmed_state) =
                    relayer_thread.chainstate_ref().unconfirmed_state.as_ref()
                {
                    Some(unconfirmed_state.make_readonly_owned().ok()?)
                } else {
                    None
                };

                Some(MicroblockMinerThread {
                    globals,
                    chainstate: Some(chainstate),
                    sortdb: Some(sortdb),
                    mempool: Some(mempool),
                    event_dispatcher: relayer_thread.event_dispatcher.clone(),
                    parent_consensus_hash: ch,
                    parent_block_hash: bhh,
                    miner_key,
                    frequency,
                    last_mined: 0,
                    quantity: 0,
                    cost_so_far,
                    settings,
                })
            }
            Ok(None) => {
                warn!("Relayer: No such anchored block: {ch}/{bhh}.  Cannot mine microblocks");
                None
            }
            Err(e) => {
                warn!("Relayer: Failed to get anchored block cost for {ch}/{bhh}: {e:?}");
                None
            }
        }
    }

    /// Do something with the inner chainstate DBs (borrowed mutably).
    /// Used to fool the borrow-checker.
    /// NOT COMPOSIBLE - WILL PANIC IF CALLED FROM WITHIN ITSELF.
    fn with_chainstate<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(&mut Self, &mut SortitionDB, &mut StacksChainState, &mut MemPoolDB) -> R,
    {
        let mut sortdb = self.sortdb.take().expect("FATAL: already took sortdb");
        let mut chainstate = self
            .chainstate
            .take()
            .expect("FATAL: already took chainstate");
        let mut mempool = self.mempool.take().expect("FATAL: already took mempool");

        let res = func(self, &mut sortdb, &mut chainstate, &mut mempool);

        self.sortdb = Some(sortdb);
        self.chainstate = Some(chainstate);
        self.mempool = Some(mempool);

        res
    }

    /// Unconditionally mine one microblock.
    /// Can fail if the miner thread gets cancelled (most likely cause), or if there's some kind of
    /// DB error.
    fn inner_mine_one_microblock(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        mempool: &mut MemPoolDB,
    ) -> Result<StacksMicroblock, ChainstateError> {
        debug!(
            "Try to mine one microblock off of {}/{} (total: {})",
            &self.parent_consensus_hash,
            &self.parent_block_hash,
            chainstate
                .unconfirmed_state
                .as_ref()
                .map(|us| us.num_microblocks())
                .unwrap_or(0)
        );

        let block_snapshot =
            SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &self.parent_consensus_hash)
                .map_err(|e| {
                    error!("Failed to find block snapshot for mined block: {e}");
                    e
                })?
                .ok_or_else(|| {
                    error!("Failed to find block snapshot for mined block");
                    ChainstateError::NoSuchBlockError
                })?;
        let burn_height = block_snapshot.block_height;

        let epoch_id = SortitionDB::get_stacks_epoch(sortdb.conn(), burn_height)
            .map_err(|e| {
                error!("Failed to get epoch for microblock: {e}");
                e
            })?
            .expect("FATAL: no epoch defined")
            .epoch_id;

        let mint_result = {
            let ic = sortdb.index_handle_at_block(
                chainstate,
                &block_snapshot.get_canonical_stacks_block_id(),
            )?;
            let mut microblock_miner = match StacksMicroblockBuilder::resume_unconfirmed(
                chainstate,
                &ic,
                &self.cost_so_far,
                self.settings.clone(),
            ) {
                Ok(x) => x,
                Err(e) => {
                    let msg = format!(
                        "Failed to create a microblock miner at chaintip {}/{}: {e:?}",
                        &self.parent_consensus_hash, &self.parent_block_hash
                    );
                    error!("{msg}");
                    return Err(e);
                }
            };

            let t1 = get_epoch_time_ms();

            let mblock = microblock_miner.mine_next_microblock(
                mempool,
                &self.miner_key,
                &self.event_dispatcher,
            )?;
            let new_cost_so_far = microblock_miner.get_cost_so_far().expect("BUG: cannot read cost so far from miner -- indicates that the underlying Clarity Tx is somehow in use still.");
            let t2 = get_epoch_time_ms();

            info!(
                "Mined microblock {} ({}) with {} transactions in {}ms",
                mblock.block_hash(),
                mblock.header.sequence,
                mblock.txs.len(),
                t2.saturating_sub(t1)
            );

            Ok((mblock, new_cost_so_far))
        };

        let (mined_microblock, new_cost) = match mint_result {
            Ok(x) => x,
            Err(e) => {
                warn!("Failed to mine microblock: {e}");
                return Err(e);
            }
        };

        // failsafe
        if !Relayer::static_check_problematic_relayed_microblock(
            chainstate.mainnet,
            epoch_id,
            &mined_microblock,
        ) {
            // nope!
            warn!(
                "Our mined microblock {} was problematic. Will NOT process.",
                &mined_microblock.block_hash()
            );

            #[cfg(test)]
            {
                use std::path::Path;
                if let Ok(path) = std::env::var("STACKS_BAD_BLOCKS_DIR") {
                    // record this microblock somewhere
                    if fs::metadata(&path).is_err() {
                        fs::create_dir_all(&path)
                            .unwrap_or_else(|_| panic!("FATAL: could not create '{path}'"));
                    }

                    let path = Path::new(&path);
                    let path = path.join(Path::new(&format!("{}", &mined_microblock.block_hash())));
                    let mut file = fs::File::create(&path)
                        .unwrap_or_else(|_| panic!("FATAL: could not create '{path:?}'"));

                    let mblock_bits = mined_microblock.serialize_to_vec();
                    let mblock_bits_hex = to_hex(&mblock_bits);

                    let mblock_json = format!(
                        r#"{{"microblock":"{mblock_bits_hex}","parent_consensus":"{}","parent_block":"{}"}}"#,
                        &self.parent_consensus_hash, &self.parent_block_hash
                    );
                    file.write_all(mblock_json.as_bytes()).unwrap_or_else(|_| {
                        panic!("FATAL: failed to write microblock bits to '{path:?}'")
                    });
                    info!(
                        "Fault injection: bad microblock {} saved to {}",
                        &mined_microblock.block_hash(),
                        &path.to_str().unwrap()
                    );
                }
            }
            return Err(ChainstateError::NoTransactionsToMine);
        }

        // cancelled?
        let is_miner_blocked = self
            .globals
            .get_miner_status()
            .lock()
            .expect("FATAL: mutex poisoned")
            .is_blocked();
        if is_miner_blocked {
            return Err(ChainstateError::MinerAborted);
        }

        // preprocess the microblock locally
        chainstate.preprocess_streamed_microblock(
            &self.parent_consensus_hash,
            &self.parent_block_hash,
            &mined_microblock,
        )?;

        // update unconfirmed state cost
        self.cost_so_far = new_cost;
        self.quantity += 1;
        Ok(mined_microblock)
    }

    /// Can this microblock miner mine off of this given tip?
    pub fn can_mine_on_tip(
        &self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> bool {
        self.parent_consensus_hash == *consensus_hash && self.parent_block_hash == *block_hash
    }

    /// Body of try_mine_microblock()
    fn inner_try_mine_microblock(
        &mut self,
        miner_tip: MinerTip,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        mem_pool: &mut MemPoolDB,
    ) -> Result<Option<(StacksMicroblock, ExecutionCost)>, NetError> {
        if !self.can_mine_on_tip(&self.parent_consensus_hash, &self.parent_block_hash) {
            // not configured to mine on this tip
            return Ok(None);
        }
        if !self.can_mine_on_tip(&miner_tip.consensus_hash, &miner_tip.block_hash) {
            // this tip isn't what this miner is meant to mine on
            return Ok(None);
        }

        if self.last_mined + (self.frequency as u128) >= get_epoch_time_ms() {
            // too soon to mine
            return Ok(None);
        }

        let mut next_microblock_and_runtime = None;

        // opportunistically try and mine, but only if there are no attachable blocks in
        // recent history (i.e. in the last 10 minutes)
        let num_attachable = StacksChainState::count_attachable_staging_blocks(
            chainstate.db(),
            1,
            get_epoch_time_secs() - 600,
        )?;
        if num_attachable == 0 {
            match self.inner_mine_one_microblock(sortdb, chainstate, mem_pool) {
                Ok(microblock) => {
                    // will need to relay this
                    next_microblock_and_runtime = Some((microblock, self.cost_so_far.clone()));
                }
                Err(ChainstateError::NoTransactionsToMine) => {
                    info!("Will keep polling mempool for transactions to include in a microblock");
                }
                Err(e) => {
                    warn!("Failed to mine one microblock: {e:?}");
                }
            }
        } else {
            debug!("Will not mine microblocks yet -- have {num_attachable} attachable blocks that arrived in the last 10 minutes");
        }

        self.last_mined = get_epoch_time_ms();

        Ok(next_microblock_and_runtime)
    }

    /// Try to mine one microblock, given the current chain tip and access to the chain state DBs.
    /// If we succeed, return the microblock and log the tx events to the given event dispatcher.
    /// May return None if any of the following are true:
    /// * `miner_tip` does not match this miner's miner tip
    /// * it's been too soon (less than microblock_frequency milliseconds) since we tried this call
    /// * there are simply no transactions to mine
    /// * there are still stacks blocks to be processed in the staging db
    /// * the miner thread got cancelled
    pub fn try_mine_microblock(
        &mut self,
        cur_tip: MinerTip,
    ) -> Result<Option<(StacksMicroblock, ExecutionCost)>, NetError> {
        debug!("microblock miner thread ID is {:?}", thread::current().id());
        self.with_chainstate(|mblock_miner, sortdb, chainstate, mempool| {
            mblock_miner.inner_try_mine_microblock(cur_tip, sortdb, chainstate, mempool)
        })
    }
}
