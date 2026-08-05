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

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::thread::JoinHandle;

use stacks::burnchains::Burnchain;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
#[cfg(test)]
use stacks::chainstate::stacks::db::StacksChainState;
#[cfg(test)]
use stacks::chainstate::stacks::miner::MinerStatus;
use stacks::chainstate::stacks::miner::{signal_mining_blocked, signal_mining_ready};
use stacks::net::p2p::PeerNetwork;

use super::{NeonGlobals as Globals, StacksNode, BLOCK_PROCESSOR_STACK_SIZE, RELAYER_MAX_BUFFER};
use crate::node::leader_key::LeaderKeyRegistrationState;
use crate::node::runtime::{BurnchainSyncCursor, EpochRuntime, EpochStartup, RuntimeContinuity};
#[cfg(test)]
use crate::node::runtime::{Counters, RunLoopCounter};
use crate::syncctl::PoxSyncWatchdog;
#[cfg(test)]
use crate::syncctl::PoxSyncWatchdogComms;
use crate::Config;

/// Protocol resources recovered after a clean Epoch 2 worker shutdown.
#[derive(Default)]
pub struct Epoch2Shutdown {
    leader_key_registration_state: LeaderKeyRegistrationState,
    peer_network: Option<PeerNetwork>,
}

impl Epoch2Shutdown {
    fn new(globals: Globals, peer_network: Option<PeerNetwork>) -> Self {
        let key_state = globals
            .leader_key_registration_state
            .lock()
            .unwrap_or_else(|error| {
                // This can only happen after a relayer thread panic.
                error!("FATAL: leader key registration mutex is poisoned: {error:?}");
                panic!();
            });

        Self {
            leader_key_registration_state: key_state.clone(),
            peer_network,
        }
    }

    pub fn into_parts(self) -> (LeaderKeyRegistrationState, Option<PeerNetwork>) {
        (self.leader_key_registration_state, self.peer_network)
    }
}

/// Coordinates a node running the Epoch 2 protocol.
pub struct Driver {
    runtime: EpochRuntime,
}

impl Driver {
    /// Sets up an Epoch 2 driver from a configuration.
    pub fn new(config: Config) -> Self {
        Self {
            runtime: EpochRuntime::fresh(config),
        }
    }

    pub fn get_coordinator_channel(&self) -> Option<CoordinatorChannels> {
        self.runtime.coordinator_channel()
    }

    #[cfg(test)]
    pub fn get_blocks_processed_arc(&self) -> RunLoopCounter {
        self.runtime.counters().blocks_processed
    }

    #[cfg(test)]
    pub fn get_missed_tenures_arc(&self) -> RunLoopCounter {
        self.runtime.counters().missed_tenures
    }

    #[cfg(test)]
    pub fn get_counters(&self) -> Counters {
        self.runtime.counters()
    }

    pub fn config(&self) -> &Config {
        self.runtime.config()
    }

    #[cfg(test)]
    pub fn get_pox_sync_comms(&self) -> PoxSyncWatchdogComms {
        self.runtime.sync_comms()
    }

    pub fn get_termination_switch(&self) -> Arc<AtomicBool> {
        self.runtime.termination_switch()
    }

    #[cfg(test)]
    pub fn get_miner_status(&self) -> Arc<Mutex<MinerStatus>> {
        self.runtime.miner_status()
    }

    /// Boot up the stacks chainstate.
    /// Instantiate the chainstate and push out the boot receipts to observers
    /// This is only public so we can test it.
    #[cfg(test)]
    pub fn boot_chainstate(&mut self, burnchain_config: &Burnchain) -> StacksChainState {
        self.runtime.boot_chainstate(burnchain_config)
    }

    pub fn take_runtime_continuity(&mut self) -> RuntimeContinuity {
        self.runtime.take_continuity()
    }

    /// Stop Epoch 2 workers in dependency order and recover their protocol resources.
    fn shutdown_workers(
        globals: Globals,
        coordinator_thread_handle: JoinHandle<()>,
        node: StacksNode,
    ) -> Epoch2Shutdown {
        // The p2p thread relies on the same atomic bool and exits after its current network pass.
        info!("Terminating p2p process");
        info!("Terminating relayer");
        info!("Terminating chains-coordinator");

        globals.coord().stop_chains_coordinator();
        coordinator_thread_handle.join().unwrap();
        let peer_network = node.join();

        // The peer network can be inherited only after a clean Epoch 2 shutdown.
        let shutdown = Epoch2Shutdown::new(globals, peer_network);
        info!("Exiting stacks-node");
        shutdown
    }

    /// Starts the Epoch 2 driver.
    ///
    /// This function will block by looping infinitely.
    /// It will start the burnchain (separate thread), set-up a channel in
    /// charge of coordinating the new blocks coming from the burnchain and
    /// the nodes, taking turns on tenures.
    ///
    /// Returns resources recovered from a clean worker shutdown. The supervisor determines whether
    /// they belong to an Epoch 2-to-Nakamoto transition or an ordinary process shutdown.
    pub fn start(
        &mut self,
        burnchain_opt: Option<Burnchain>,
        mine_start: u64,
    ) -> Option<Epoch2Shutdown> {
        let coordinator_thread_name = format!(
            "chains-coordinator-{}",
            &self.runtime.config().node.rpc_bind
        );
        let startup = EpochStartup::new(
            burnchain_opt,
            mine_start,
            RELAYER_MAX_BUFFER,
            coordinator_thread_name,
            BLOCK_PROCESSOR_STACK_SIZE,
        )
        .burnchain_db_readwrite(true);
        let prepared = startup.prepare_or_log(&mut self.runtime)?;
        let mut pox_watchdog =
            PoxSyncWatchdog::new(self.runtime.config(), self.runtime.sync_comms())
                .expect("FATAL: failed to instantiate PoX sync watchdog");
        let (running, mut node) = prepared.spawn_and_synchronize(StacksNode::spawn);
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

        // prepare to fetch the first reward cycle!
        debug!(
            "Runloop: Begin main runloop starting a burnchain block {}",
            sync_cursor.processed_sortition_height()
        );

        loop {
            if !globals.keep_running() {
                break Some(Self::shutdown_workers(
                    globals,
                    coordinator_thread_handle,
                    node,
                ));
            }

            let remote_chain_height = burnchain.get_headers_height() - 1;

            // wait until it's okay to process the next reward cycle's sortitions.
            let (ibd, target_burnchain_block_height) = match pox_watchdog.pox_sync_wait(
                &burnchain_config,
                sync_cursor.tip(),
                remote_chain_height,
            ) {
                Ok(x) => x,
                Err(e) => {
                    debug!("Runloop: PoX sync wait routine aborted: {e:?}");
                    continue;
                }
            };

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

                    debug!("Runloop: block mining until we process all sortitions");
                    signal_mining_blocked(globals.get_miner_status());

                    // first, let's process all blocks in (sortition_db_height, next_sortition_height]
                    for block_to_process in sync_cursor.pending_sortition_heights() {
                        // stop mining so we can advance the sortition DB and so our
                        // ProcessTenure() directive (sent by relayer_sortition_notify() below)
                        // will be unblocked.

                        let block =
                            sync_cursor.load_snapshot(burnchain.sortdb_ref(), block_to_process);

                        let sortition_id = &block.sortition_id;

                        // Have the node process the new block, that can include, or not, a sortition.
                        node.process_burnchain_state(
                            self.config(),
                            burnchain.sortdb_mut(),
                            sortition_id,
                            ibd,
                        );

                        // Now, tell the relayer to check if it won a sortition during this block,
                        // and, if so, to process and advertize the block.  This is basically a
                        // no-op during boot-up.
                        //
                        // _this will block if the relayer's buffer is full_
                        if !node.relayer_sortition_notify() {
                            // First check if we were supposed to cleanly exit
                            if !globals.keep_running() {
                                return Some(Self::shutdown_workers(
                                    globals,
                                    coordinator_thread_handle,
                                    node,
                                ));
                            }
                            // relayer hung up, exit.
                            error!("Runloop: Block relayer and miner hung up, exiting.");
                            return None;
                        }
                    }

                    debug!("Runloop: enable miner after processing sortitions");
                    signal_mining_ready(globals.get_miner_status());

                    debug!(
                        "Runloop: Synchronized sortitions up to block height {next_sortition_height} from {sortition_db_height} (chain tip height is {burnchain_height})"
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

            if let Some(readiness) =
                sync_cursor.mining_readiness(burnchain.sortdb_ref(), ibd, is_miner)
            {
                globals.set_start_mining_height_if_zero(readiness.sortition_height());

                if !node.relayer_issue_tenure(ibd) {
                    // First check if we were supposed to cleanly exit
                    if !globals.keep_running() {
                        return Some(Self::shutdown_workers(
                            globals,
                            coordinator_thread_handle,
                            node,
                        ));
                    }
                    // relayer hung up, exit.
                    error!("Runloop: Block relayer and miner hung up, exiting.");
                    break None;
                }
            }
        }
    }
}
