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
#[cfg(test)]
use std::sync::atomic::AtomicBool;
#[cfg(test)]
use std::sync::Arc;
use std::{cmp, mem};

use stacks::burnchains::Burnchain;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::stacks::miner::{signal_mining_blocked, signal_mining_ready};
use stacks::net::p2p::PeerNetwork;
use stacks_common::util::{get_epoch_time_secs, sleep_ms};

use super::{NodeStartup, StacksNode, BLOCK_PROCESSOR_STACK_SIZE, RELAYER_MAX_BUFFER};
use crate::node::leader_key::LeaderKeyRegistrationState;
#[cfg(test)]
use crate::node::runtime::Counters;
use crate::node::runtime::{
    BurnchainSyncCursor, EpochRuntime, EpochStartup, Globals as GenericGlobals, RuntimeContinuity,
};
use crate::Config;

pub type Globals = GenericGlobals<super::relayer::RelayerDirective>;

/// Coordinates a node running the Nakamoto protocol.
pub struct Driver {
    runtime: EpochRuntime,
    node_startup: NodeStartup,
}

impl Driver {
    /// Sets up a Nakamoto driver with fresh process continuity.
    pub fn fresh(config: Config) -> Self {
        let continuity = RuntimeContinuity::fresh(&config);
        Self::with_startup(config, continuity, NodeStartup::default())
    }

    pub fn inherited(
        config: Config,
        continuity: RuntimeContinuity,
        leader_key_registration_state: LeaderKeyRegistrationState,
        peer_network: Option<PeerNetwork>,
    ) -> Self {
        Self::with_startup(
            config,
            continuity,
            NodeStartup::inherited(leader_key_registration_state, peer_network),
        )
    }

    fn with_startup(
        config: Config,
        continuity: RuntimeContinuity,
        node_startup: NodeStartup,
    ) -> Self {
        Self {
            runtime: EpochRuntime::new(config, continuity),
            node_startup,
        }
    }

    pub fn get_coordinator_channel(&self) -> Option<CoordinatorChannels> {
        self.runtime.coordinator_channel()
    }

    #[cfg(test)]
    pub fn get_counters(&self) -> Counters {
        self.runtime.counters()
    }

    pub fn config(&self) -> &Config {
        self.runtime.config()
    }

    #[cfg(test)]
    pub fn get_termination_switch(&self) -> Arc<AtomicBool> {
        self.runtime.termination_switch()
    }

    /// Starts the Nakamoto driver.
    ///
    /// This function will block by looping infinitely.
    /// It will start the burnchain (separate thread), set-up a channel in
    /// charge of coordinating the new blocks coming from the burnchain and
    /// the nodes, taking turns on tenures.
    pub fn start(&mut self, burnchain_opt: Option<Burnchain>, mine_start: u64) {
        let rpc_port = self
            .runtime
            .config()
            .node
            .rpc_bind_addr()
            .unwrap_or_else(|| {
                panic!(
                    "Failed to parse socket: {}",
                    &self.runtime.config().node.rpc_bind
                )
            })
            .port();
        let startup = EpochStartup::new(
            burnchain_opt,
            mine_start,
            RELAYER_MAX_BUFFER,
            format!("chains-coordinator:{rpc_port}"),
            BLOCK_PROCESSOR_STACK_SIZE,
        );
        let Some(prepared) = startup.prepare_or_log(&mut self.runtime) else {
            return;
        };
        let node_startup = mem::take(&mut self.node_startup);
        let (running, mut node) = prepared.spawn_and_synchronize(|context, relay_receiver| {
            StacksNode::spawn(context, relay_receiver, node_startup)
        });
        let mut burnchain = running.burnchain;
        let burnchain_config = running.burnchain_config;
        let globals = running.globals;
        let coordinator_thread_handle = running.coordinator_thread;
        let mut sync_cursor = BurnchainSyncCursor::new(
            running.burnchain_tip,
            running.reward_cycle_height,
            mine_start,
        );
        let is_miner = running.is_miner;
        debug!("Runloop: Begin run loop");

        let mut num_sortitions_in_last_cycle;

        // prepare to fetch the first reward cycle!
        let mut target_burnchain_block_height = cmp::min(
            burnchain_config.reward_cycle_to_block_height(
                burnchain_config
                    .block_height_to_reward_cycle(sync_cursor.burnchain_height())
                    .expect("BUG: block height is not in a reward cycle")
                    + 1,
            ),
            burnchain.get_headers_height() - 1,
        );

        debug!(
            "Runloop: Begin main runloop starting a burnchain block {}",
            sync_cursor.processed_sortition_height()
        );
        let mut poll_deadline = 0;

        loop {
            if !globals.keep_running() {
                // The p2p thread relies on the same atomic_bool, it will
                // discontinue its execution after completing its ongoing runloop epoch.
                info!("Terminating p2p process");
                info!("Terminating relayer");
                info!("Terminating chains-coordinator");

                globals.coord().stop_chains_coordinator();
                coordinator_thread_handle.join().unwrap();
                node.join();

                info!("Exiting stacks-node");
                break;
            }

            let remote_chain_height = burnchain.get_headers_height() - 1;

            // wait for the p2p state-machine to do at least one pass
            debug!("Runloop: Wait until Stacks block downloads reach a quiescent state before processing more burnchain blocks"; "remote_chain_height" => remote_chain_height, "local_chain_height" => sync_cursor.burnchain_height());

            // TODO: for now, we just set initial block download false.
            //   I think that the sync watchdog probably needs to change a fair bit
            //   for nakamoto. There may be some opportunity to refactor this runloop
            //   as well (e.g., the `mine_start` should be integrated with the
            //   watchdog so that there's just one source of truth about ibd),
            //   but I think all of this can be saved for post-neon work.
            let ibd = false;
            self.runtime.sync_comms().set_ibd(ibd);

            // Download each burnchain block and process their sortitions.  This, in turn, will
            // cause the node's p2p and relayer threads to go fetch and download Stacks blocks and
            // process them.  This loop runs for one reward cycle, so that the next pass of the
            // runloop will cause the PoX sync watchdog to wait until it believes that the node has
            // obtained all the Stacks blocks it can.
            sync_cursor.log_download_target(
                &burnchain_config,
                target_burnchain_block_height,
                remote_chain_height,
            );

            loop {
                if !globals.keep_running() {
                    break;
                }

                if poll_deadline > get_epoch_time_secs() {
                    sleep_ms(1_000);
                    continue;
                }
                poll_deadline = get_epoch_time_secs() + self.config().burnchain.poll_time_secs;

                let (next_burnchain_tip, tip_burnchain_height) =
                    match burnchain.sync(Some(target_burnchain_block_height)) {
                        Ok(x) => x,
                        Err(e) => {
                            warn!("Runloop: Burnchain controller stopped: {e}");
                            continue;
                        }
                    };

                // *now* we know the burnchain height
                sync_cursor.record_synced_tip(next_burnchain_tip, tip_burnchain_height);

                let burnchain_height = sync_cursor.burnchain_height();
                let next_sortition_height = sync_cursor.tip_height();
                let sortition_db_height = sync_cursor.processed_sortition_height();

                sync_cursor.log_synced_tip(target_burnchain_block_height, remote_chain_height);

                if next_sortition_height > sortition_db_height {
                    debug!(
                        "Runloop: New burnchain block height {next_sortition_height} > {sortition_db_height}"
                    );

                    let mut sort_count = 0;

                    debug!("Runloop: block mining until we process all sortitions");
                    signal_mining_blocked(globals.get_miner_status());

                    // first, let's process all blocks in (sortition_db_height, next_sortition_height]
                    for block_to_process in sync_cursor.pending_sortition_heights() {
                        // stop mining so we can advance the sortition DB and so our
                        // ProcessTenure() directive (sent by relayer_sortition_notify() below)
                        // will be unblocked.

                        let block =
                            sync_cursor.load_snapshot(burnchain.sortdb_ref(), block_to_process);
                        if block.sortition {
                            sort_count += 1;
                        }

                        let sortition_id = &block.sortition_id;

                        // Have the node process the new block, that can include, or not, a sortition.
                        if let Err(e) = node.process_burnchain_state(
                            self.config(),
                            burnchain.sortdb_mut(),
                            sortition_id,
                            ibd,
                        ) {
                            // relayer errored, exit.
                            error!("Runloop: Block relayer and miner errored, exiting."; "err" => ?e);
                            return;
                        }
                    }

                    debug!("Runloop: enable miner after processing sortitions");
                    signal_mining_ready(globals.get_miner_status());

                    num_sortitions_in_last_cycle = sort_count;
                    debug!(
                        "Runloop: Synchronized sortitions up to block height {next_sortition_height} from {sortition_db_height} (chain tip height is {burnchain_height}); {num_sortitions_in_last_cycle} sortitions"
                    );

                    sync_cursor.mark_sortitions_processed();
                } else if ibd {
                    // drive block processing after we reach the burnchain tip.
                    // we may have downloaded all the blocks already,
                    // so we can't rely on the relayer alone to
                    // drive it.
                    globals.coord().announce_new_stacks_block();
                }

                if burnchain_height >= target_burnchain_block_height
                    || burnchain_height >= remote_chain_height
                {
                    break;
                }
            }

            // advance one reward cycle at a time.
            // If we're still downloading, then this is simply target_burnchain_block_height + reward_cycle_len.
            // Otherwise, this is burnchain_tip + reward_cycle_len
            let next_target_burnchain_block_height = cmp::min(
                burnchain_config.reward_cycle_to_block_height(
                    burnchain_config
                        .block_height_to_reward_cycle(target_burnchain_block_height)
                        .expect("FATAL: burnchain height before system start")
                        + 1,
                ),
                remote_chain_height,
            );

            debug!(
                "Runloop: Advance target burnchain block height from {target_burnchain_block_height} to {next_target_burnchain_block_height} (sortition height {})",
                sync_cursor.processed_sortition_height()
            );
            target_burnchain_block_height = next_target_burnchain_block_height;

            if let Some(readiness) =
                sync_cursor.mining_readiness(burnchain.sortdb_ref(), ibd, is_miner)
            {
                if readiness.newly_announced() {
                    globals.raise_initiative("runloop-synced".to_string());
                }
            }
        }
    }
}
