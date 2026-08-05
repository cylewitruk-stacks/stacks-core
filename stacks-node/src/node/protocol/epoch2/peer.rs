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

use std::collections::VecDeque;
use std::sync::mpsc::TrySendError;

use stacks::burnchains::db::BurnchainHeaderReader;
use stacks::burnchains::PoxConstants;
use stacks::cost_estimates::metrics::CostMetric;
use stacks::cost_estimates::{CostEstimator, FeeEstimator};
use stacks::net::dns::DNSClient;
use stacks::net::p2p::PeerNetwork;
use stacks::net::relay::Relayer;
use stacks::net::RPCHandlerArgs;
use stacks_common::util::hash::Sha256Sum;

use super::relayer::RelayerDirective;
use super::NeonGlobals;
use crate::node::network::{PeerNetworkOrigin, PeerProgress, PeerRuntimeResources};
use crate::{Config, EventDispatcher};

/// Thread that runs the network state machine, handling both p2p and http requests.
pub struct PeerThread {
    /// Node config
    pub config: Config,
    /// handle to global inter-thread comms
    pub globals: NeonGlobals,
    /// Peer-owned network and database connections.
    pub resources: PeerRuntimeResources,
    /// buffer of relayer commands with block data that couldn't be sent to the relayer just yet
    /// (i.e. due to backpressure).  We track this separately, instead of just using a bigger
    /// channel, because we need to know when backpressure occurs in order to throttle the p2p
    /// thread's downloader.
    results_with_data: VecDeque<RelayerDirective>,
    /// Network state-machine progress shared with the synchronization watchdog.
    progress: PeerProgress,
}

impl PeerThread {
    /// Instantiate the p2p thread.
    /// Binds the addresses in the config (which may panic if the port is blocked).
    /// This is so the node will crash "early" before any new threads start if there's going to be
    /// a bind error anyway.
    pub fn new(
        globals: NeonGlobals,
        config: &Config,
        pox_constants: PoxConstants,
        net: PeerNetwork,
    ) -> Self {
        let config = config.clone();
        let resources =
            PeerRuntimeResources::open(&config, pox_constants, net, PeerNetworkOrigin::Fresh);

        PeerThread {
            config,
            globals,
            resources,
            results_with_data: VecDeque::new(),
            progress: PeerProgress::default(),
        }
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
        let download_backpressure = !self.results_with_data.is_empty();
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

        // move over unconfirmed state obtained from the relayer
        let globals = &self.globals;
        self.resources
            .with_chainstate(|sortdb, chainstate, _mempool| {
                let _ = Relayer::setup_unconfirmed_state_readonly(chainstate, sortdb);
                globals.recv_unconfirmed_txs(chainstate);
            });

        let txindex = self.config.node.txindex;
        let exit_at_block_height = self.config.burnchain.process_exit_at_block_height;

        // do one pass
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
                    ..RPCHandlerArgs::default()
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
                let progress = self
                    .progress
                    .observe(&network_result, &mut self.globals.sync_comms);

                if network_result.has_data_to_store()
                    || progress.burn_height_changed()
                    || progress.inventory_advanced()
                    || progress.downloader_advanced()
                {
                    // pass along if we have blocks, microblocks, or transactions, or a status
                    // update on the network's view of the burnchain
                    self.results_with_data
                        .push_back(RelayerDirective::HandleNetResult(network_result));
                }
            }
            Err(e) => {
                // this is only reachable if the network is not instantiated correctly --
                // i.e. you didn't connect it
                panic!("P2P: Failed to process network dispatch: {e:?}");
            }
        };

        while let Some(next_result) = self.results_with_data.pop_front() {
            // have blocks, microblocks, and/or transactions (don't care about anything else),
            // or a directive to mine microblocks
            if let Err(e) = self.globals.relay_send.try_send(next_result) {
                debug!(
                    "P2P: {:?}: download backpressure detected (bufferred {})",
                    &self.resources.network().local_peer,
                    self.results_with_data.len()
                );
                match e {
                    TrySendError::Full(directive) => {
                        if let RelayerDirective::RunTenure(..) = directive {
                            // can drop this
                        } else {
                            // don't lose this data -- just try it again
                            self.results_with_data.push_front(directive);
                        }
                        break;
                    }
                    TrySendError::Disconnected(_) => {
                        info!("P2P: Relayer hang up with p2p channel");
                        self.globals.signal_stop();
                        return false;
                    }
                }
            } else {
                debug!("P2P: Dispatched result to Relayer!");
            }
        }

        true
    }
}
