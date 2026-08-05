// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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
use std::sync::mpsc::TrySendError;
use std::thread;

use stacks::burnchains::db::BurnchainHeaderReader;
use stacks::burnchains::PoxConstants;
use stacks::cost_estimates::metrics::CostMetric;
use stacks::cost_estimates::{CostEstimator, FeeEstimator};
use stacks::net::dns::DNSClient;
use stacks::net::p2p::PeerNetwork;
use stacks::net::RPCHandlerArgs;
use stacks_common::util::hash::Sha256Sum;

use super::driver::Globals;
use super::relayer::RelayerDirective;
use crate::node::network::{
    run_peer_network_loop, PeerNetworkOrigin, PeerProgress, PeerRuntimeResources,
};
use crate::{Config, EventDispatcher};

/// Thread that runs the network state machine, handling both p2p and http requests.
pub struct PeerThread {
    /// Node config
    config: Config,
    /// handle to global inter-thread comms
    globals: Globals,
    /// Peer-owned network and database connections.
    resources: PeerRuntimeResources,
    /// Buffered network result relayer command.
    /// P2P network results are consolidated into a single directive.
    results_with_data: Option<RelayerDirective>,
    /// Network state-machine progress shared with the synchronization watchdog.
    progress: PeerProgress,
}

impl PeerThread {
    /// Main loop of the p2p thread.
    /// Runs in a separate thread.
    /// Continuously receives, until told otherwise.
    pub fn main(mut self, event_dispatcher: EventDispatcher) {
        debug!("p2p thread ID is {:?}", thread::current().id());
        let config = self.config.clone();
        let should_keep_running = self.globals.should_keep_running.clone();
        run_peer_network_loop(
            &config,
            should_keep_running,
            |indexer, dns_client, cost_estimator, cost_metric, fee_estimator| {
                self.run_one_pass(
                    indexer,
                    dns_client,
                    &event_dispatcher,
                    cost_estimator,
                    cost_metric,
                    fee_estimator,
                )
            },
        );

        self.globals.shutdown_peer_worker(RelayerDirective::Exit);
    }

    /// Instantiate the p2p thread.
    /// Binds the addresses in the config (which may panic if the port is blocked).
    /// This is so the node will crash "early" before any new threads start if there's going to be
    /// a bind error anyway.
    pub fn new(
        globals: Globals,
        config: &Config,
        pox_constants: PoxConstants,
        net: PeerNetwork,
        origin: PeerNetworkOrigin,
    ) -> Self {
        let config = config.clone();
        let resources = PeerRuntimeResources::open(&config, pox_constants, net, origin);
        PeerThread {
            config,
            globals,
            resources,
            results_with_data: None,
            progress: PeerProgress::default(),
        }
    }

    /// Check if the StackerDB config needs to be updated (by looking
    ///  at the signal in `self.globals`), and if so, refresh the
    ///  StackerDB config
    fn refresh_stackerdb(&mut self) {
        if !self.globals.coord_comms.need_stackerdb_update() {
            return;
        }

        let refresh_result =
            self.resources
                .with_network_state(|network, sortdb, chainstate, _mempool| {
                    network.refresh_stacker_db_configs(sortdb, chainstate)
                });
        if let Err(e) = refresh_result {
            warn!("Failed to update StackerDB configs: {e}");
        }

        self.globals.coord_comms.set_stackerdb_update(false);
    }

    /// Run one pass of the p2p/http state machine
    /// Return true if we should continue running passes; false if not
    pub fn run_one_pass<B: BurnchainHeaderReader>(
        &mut self,
        indexer: &B,
        dns_client_opt: Option<&mut DNSClient>,
        event_dispatcher: &EventDispatcher,
        cost_estimator: &dyn CostEstimator,
        cost_metric: &dyn CostMetric,
        fee_estimator: Option<&dyn FeeEstimator>,
    ) -> bool {
        // initial block download?
        let ibd = self.globals.sync_comms.get_ibd();
        let download_backpressure = self
            .results_with_data
            .as_ref()
            .map(|res| {
                if let RelayerDirective::HandleNetResult(netres) = &res {
                    netres.has_block_data_to_store()
                } else {
                    false
                }
            })
            .unwrap_or(false);

        let poll_ms = if !download_backpressure && self.resources.network().has_more_downloads() {
            // keep getting those blocks -- drive the downloader state-machine
            debug!(
                "P2P: backpressure: {download_backpressure}, more downloads: {}",
                self.resources.network().has_more_downloads()
            );
            1
        } else {
            self.resources.poll_timeout_ms()
        };

        self.refresh_stackerdb();

        // do one pass
        let exit_at_block_height = self.config.burnchain.process_exit_at_block_height;
        let txindex = self.config.node.txindex;
        let coord_comms = &self.globals.coord_comms;
        let p2p_res = self
            .resources
            .with_network_state(|network, sortdb, chainstate, mempool| {
                // NOTE: handler_args must be created such that it outlives the inner net.run() call and
                // doesn't ref anything within p2p_thread.
                let handler_args = RPCHandlerArgs {
                    exit_at_block_height,
                    genesis_chainstate_hash: Sha256Sum::from_hex(
                        stx_genesis::GENESIS_CHAINSTATE_HASH,
                    )
                    .unwrap(),
                    event_observer: Some(event_dispatcher),
                    cost_estimator: Some(cost_estimator),
                    cost_metric: Some(cost_metric),
                    fee_estimator,
                    coord_comms: Some(coord_comms),
                };
                network.run(
                    indexer,
                    sortdb,
                    chainstate,
                    mempool,
                    dns_client_opt,
                    download_backpressure,
                    ibd,
                    poll_ms,
                    &handler_args,
                    txindex,
                )
            });
        match p2p_res {
            Ok(network_result) => {
                self.progress
                    .observe(&network_result, &mut self.globals.sync_comms);
                if let Some(res) = self.results_with_data.take() {
                    if let RelayerDirective::HandleNetResult(netres) = res {
                        let new_res = netres.update(network_result);
                        self.results_with_data = Some(RelayerDirective::HandleNetResult(new_res));
                    }
                } else {
                    self.results_with_data =
                        Some(RelayerDirective::HandleNetResult(network_result));
                }

                self.globals.raise_initiative(
                    "PeerThread::run_one_pass() with data-bearing network result".to_string(),
                );
            }
            Err(e) => {
                // this is only reachable if the network is not instantiated correctly --
                // i.e. you didn't connect it
                panic!("P2P: Failed to process network dispatch: {e:?}");
            }
        };

        if let Some(next_result) = self.results_with_data.take() {
            // have blocks, microblocks, and/or transactions (don't care about anything else),
            // or a directive to mine microblocks
            self.globals.raise_initiative(
                "PeerThread::run_one_pass() with backlogged network results".to_string(),
            );
            if let Err(e) = self.globals.relay_send.try_send(next_result) {
                debug!(
                    "P2P: {:?}: download backpressure detected",
                    &self.resources.network().local_peer,
                );
                match e {
                    TrySendError::Full(directive) => {
                        // don't lose this data -- just try it again
                        self.results_with_data = Some(directive);
                    }
                    TrySendError::Disconnected(_) => {
                        info!("P2P: Relayer hang up with p2p channel");
                        self.globals.signal_stop();
                        return false;
                    }
                }
            } else {
                debug!("P2P: Dispatched result to Relayer!",);
            }
        }

        true
    }
}
