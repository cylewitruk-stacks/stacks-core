#![forbid(missing_docs)]
/*!
# stacks-signer: a library for creating a Stacks compliant signer. A default implementation binary is also provided.
Usage documentation can be found in the [README](https://github.com/Trust-Machines/core-eng/stacks-signer-api/README.md).
*/

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

/// This module stores chainstate information about Stacks, SortitionDB for
/// tracking by the signer.
pub mod chainstate;
/// The cli module for the signer binary
pub mod cli;
/// The signer client for communicating with stackerdb/stacks nodes
pub mod client;
/// The configuration module for the signer
pub mod config;
/// The signer monitor for observing signer behaviours in the network
pub mod monitor_signers;
/// The monitoring server for the signer
pub mod monitoring;
/// Native signer networking and the temporary legacy compatibility composition.
pub mod network;
/// The primary runloop for the signer
pub mod runloop;
/// The signer state module
pub mod signerdb;
/// The util module for the signer
pub mod utils;
/// The v0 implementation of the signer.
pub mod v0;

#[cfg(test)]
mod tests;

use std::fmt::{Debug, Display};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use chainstate::v1::SortitionsView;
use config::GlobalConfig;
use libsigner::{SignerEvent, SignerEventReceiver, SignerEventTrait, VERSION_STRING};
use runloop::SignerResult;
use signerdb::BlockInfo;
use stacks_common::{info, warn};
use v0::signer_state::LocalStateMachine;

use crate::client::StacksClient;
use crate::config::SignerConfig;
use crate::runloop::RunLoop;

/// A trait which provides a common `Signer` interface for `v0` and `v1`
pub trait Signer<T: SignerEventTrait>: Debug + Display {
    /// Create a new `Signer` instance
    fn new(stacks_client: &StacksClient, signer_config: SignerConfig) -> Self;
    /// Attach the process-wide signer network after reward-cycle configuration is loaded.
    ///
    /// Implementations which do not publish signer messages may retain the default no-op.
    fn set_signer_network(&mut self, _network: Option<network::SignerNetworkHandle>) {}
    /// Get the reward cycle of the signer
    fn reward_cycle(&self) -> u64;
    /// Process an event
    fn process_event(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        event: Option<&SignerEvent<T>>,
        res: &Sender<SignerResult>,
        current_reward_cycle: u64,
    );
    /// Check if the signer is in the middle of processing blocks
    fn has_unprocessed_blocks(&self) -> bool;
    /// Get a reference to the local state machine of the signer
    fn get_local_state_machine(&self) -> &LocalStateMachine;
    /// Get the number of pending block proposals
    fn get_pending_proposals_count(&self) -> u64;
    /// Get canonical block according to this signer's db
    fn get_canonical_tip(&self) -> Option<BlockInfo>;
}

/// A wrapper around the running signer type for the signer
pub type RunningSigner<T> = libsigner::RunningSigner<SignerEventReceiver<T>, SignerResult, T>;

/// The wrapper for the runloop signer type
type RunLoopSigner<S, T> =
    libsigner::Signer<SignerResult, RunLoop<S, T>, SignerEventReceiver<T>, T>;

/// The spawned signer
pub struct SpawnedSigner<S: Signer<T> + Send, T: SignerEventTrait> {
    /// The underlying running signer thread handle
    running_signer: RunningSigner<T>,
    /// The result receiver for interacting with the running signer
    pub res_recv: Receiver<SignerResult>,
    /// The spawned signer's config
    pub config: GlobalConfig,
    /// The native libp2p network service, when enabled.
    libp2p_service: Option<network::SignerNetworkHandle>,
    /// Phantom data for the signer type
    _phantom: std::marker::PhantomData<S>,
}

impl<S: Signer<T> + Send, T: SignerEventTrait> SpawnedSigner<S, T> {
    /// Stop the signer thread and return the final state
    pub fn stop(mut self) -> Option<SignerResult> {
        let result = self.running_signer.stop();
        if let Some(service) = self.libp2p_service.take() {
            service.shutdown().expect("libp2p signer thread panicked");
        }
        result
    }

    /// Wait for the signer to terminate, and get the final state. WARNING: This will hang forever if the event receiver stop signal was never sent/no error occurred.
    pub fn join(mut self) -> Option<SignerResult> {
        let result = self.running_signer.join();
        if let Some(service) = self.libp2p_service.take() {
            service.shutdown().expect("libp2p signer thread panicked");
        }
        result
    }
}

impl<S: Signer<T> + Send + 'static, T: SignerEventTrait + 'static> SpawnedSigner<S, T> {
    /// Create a new spawned signer
    pub fn new(config: GlobalConfig) -> Self {
        let endpoint = config.endpoint;
        info!("Stacks signer version {:?}", VERSION_STRING.as_str());
        info!("Starting signer with config: {:?}", config);
        warn!(
            "Reminder: The signer is primarily designed for use with a local or subnet network stacks node. \
            It's important to exercise caution if you are communicating with an external node, \
            as this could potentially expose sensitive data or functionalities to security risks \
            if additional proper security checks are not integrated in place. \
            For more information, check the documentation at \
            https://docs.stacks.co/guides-and-tutorials/running-a-signer#preflight-setup"
        );
        let (res_send, res_recv) = channel();
        crate::monitoring::actions::start_serving_monitoring_metrics(config.clone()).ok();
        let libp2p_service = if config.libp2p.enabled
            || config.libp2p.signer_bridge.mode != stacks_network_types::BridgeMode::Off
        {
            Some(network::spawn(&config).expect("Failed to spawn native signer libp2p network"))
        } else {
            None
        };
        let mut ev = SignerEventReceiver::new(config.network.is_mainnet())
            .with_proposal_response_auth_token(Arc::<str>::from(config.auth_password.clone()));
        if config.libp2p.signer_bridge.mode.accepts_ingress() {
            let network = libp2p_service
                .as_ref()
                .cloned()
                .expect("legacy ingress requires the native signer network");
            ev = ev.with_stackerdb_event_observer(Arc::new(move |event| {
                network.ingest_legacy_event(event);
            }));
        }
        let runloop = RunLoop::with_signer_network(config.clone(), libp2p_service.clone());
        let mut signer: RunLoopSigner<S, T> = libsigner::Signer::new(runloop, ev, res_send);
        let running_signer = signer.spawn(endpoint).expect("Failed to spawn signer");
        SpawnedSigner {
            running_signer,
            res_recv,
            _phantom: std::marker::PhantomData,
            config,
            libp2p_service,
        }
    }
}
