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

//! Nakamoto node runtime and protocol actors.
//!
//! This module coordinates the node processes used after the Nakamoto
//! activation. The underlying network, chainstate, coordinator, and runtime
//! services are shared with Epoch 2, but the actors here implement a different
//! scheduling and mining model:
//!
//! ```text
//! System schematic.
//! Legend:
//!    |------|    Thread
//!    /------\    Shared memory
//!    @------@    Database
//!    .------.    Code module
//!
//!
//!                                 |------------------|
//!                                 | Nakamoto driver  |
//!                                 |   .----------.   |
//!                                 |   .StacksNode.   |
//!                                 |---.----------.---|
//!                           [1]      |     |     |      [2]
//!             .----------------------*     |     *------------------------------.
//!             |                       [1,3]|                                    |
//!             V                            V                                    V
//!     |---------------|    [4]     |----------------|     [5]      |--------------------------|
//!     |   P2P thread  | ---------> | Relayer thread | -----------> | ChainsCoordinator thread |
//!     |---------------|            |----------------|              |--------------------------|
//!             |                            |     |                              |
//!         [6] |                        [7] |     | [10]                         | [8]
//!             |                 /-------------\  |                              |
//!             |                 /   Globals   \  |                              |
//!             |                 /-------------\  |                              |
//!             |                        |   ^ [7] *----------------------.       |
//!             V                  [1,9] V   |                            V       V
//!     @--------------@             |---------------------|         @------------------@
//!     @  Mempool DB  @ <---[11]--- |    Miner thread     | -[12]-> @  Chainstate DBs  @
//!     @--------------@             | .-----------------. |         @------------------@
//!                                  | .SignerCoordinator. |
//!                                  |-.-----------------.-|
//!                                        |   |
//!                                   [13] |   | [1]
//!             .--------------------------'   |
//!             V                              V
//!     @---------------@            |--------------------|
//!     @   StackerDB   @ ---[14]--> | StackerDB listener |
//!     @---------------@            |--------------------|
//!
//! [1]  Spawns
//! [2]  Signals new burn and Stacks blocks
//! [3]  Raises relayer initiatives
//! [4]  Forwards the coalesced network result
//! [5]  Requests block processing
//! [6]  Stores unconfirmed transactions
//! [7]  Shares runtime state, counters, and miner status
//! [8]  Updates canonical chainstate
//! [9]  Starts and stops tenure mining
//! [10] Stores preprocessed blocks
//! [11] Reads candidate transactions
//! [12] Stores the mined block
//! [13] Publishes block proposals
//! [14] Delivers signer chunk events
//! ```
//!
//! ## Runtime actors
//!
//! - The [`Driver`] synchronizes the burnchain, signals the chains coordinator
//!   about new burn and Stacks blocks, and raises relayer initiatives once
//!   synchronized.
//! - `PeerThread` runs the P2P and RPC state machines, refreshes StackerDB
//!   configuration, coalesces pending network results, and wakes the relayer
//!   when work is available.
//! - `RelayerThread` is the Nakamoto control plane. It preprocesses and stores
//!   network-received blocks through its own chainstate handle, processes
//!   sortition directives, periodically evaluates initiatives and deadlines,
//!   submits burnchain commits, extends tenures, and starts or stops the miner.
//! - `BlockMinerThread` builds and stores tenure blocks. Its
//!   [`SignerCoordinator`] publishes each proposal to StackerDB directly and
//!   owns a listener thread that consumes the signers' chunk events.
//! - The shared chains coordinator remains responsible for processing
//!   sortitions and Stacks blocks and for updating canonical chainstate.
//!
//! ## Startup and protocol handoff
//!
//! Nakamoto can start directly or inherit [`NodeStartup`] from the Epoch 2
//! driver. An inherited startup carries the active leader-key registration and
//! the existing `PeerNetwork`, including any already-bound sockets. Fresh
//! networks bind strictly; inherited networks bind only when the sockets have
//! not already been acquired. Shared runtime continuity is reactivated by the
//! supervisor before the inherited driver starts.
//!
//! ## Deliberate differences from Epoch 2
//!
//! These actors intentionally do not implement a common protocol-actor trait
//! with their Epoch 2 counterparts:
//!
//! - the relayer wakes on timeouts to evaluate initiatives, commit deadlines,
//!   and tenure extensions instead of blocking solely on directives;
//! - the peer coalesces network results into one retained pending directive,
//!   whereas Epoch 2 uses `VecDeque`-backed queued buffering; both retain work
//!   under channel backpressure;
//! - mining is tenure-based and signer-mediated, with no microblock miner;
//! - signer communication and StackerDB refresh are Nakamoto-specific;
//! - miner and relayer state is retained across multiple blocks in a tenure.
//!
//! Shared mechanics live in the parent node modules; sequencing and
//! protocol-specific state transitions remain visible here.

use std::collections::HashSet;
use std::sync::mpsc::Receiver;
use std::thread;

use stacks::burnchains::Txid;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::stacks::Error as ChainstateError;
use stacks::libstackerdb::StackerDBChunkAckData;
use stacks::net::p2p::PeerNetwork;
use stacks::net::Error as NetError;
use stacks::util_lib::db::Error as DBError;
use stacks_common::types::chainstate::SortitionId;

use self::driver::Globals;
use crate::burnchains::Error as BurnchainsError;
use crate::node::context::SpawnContext;
use crate::node::leader_key::{LeaderKeyRegistrationState, RegisteredKey};
use crate::node::network::{NodeNetwork, PeerNetworkOrigin};
use crate::node::runtime::{BurnBlockObservation, WorkerHandles};
use crate::{Config, EventDispatcher, Keychain};

mod driver;
mod miner;
mod peer;
mod relayer;
mod signer;

pub use driver::Driver;
pub use signer::{MinerDB, SignerCoordinator};

#[cfg(test)]
pub mod test_support {
    pub use super::miner::{
        fault_injection_stall_miner, fault_injection_try_stall_miner,
        fault_injection_unstall_miner, TEST_BLOCK_ANNOUNCE_STALL, TEST_BROADCAST_PROPOSAL_STALL,
        TEST_MINER_BROADCASTING_BLOCK, TEST_MINE_SKIP, TEST_P2P_BROADCAST_SKIP,
        TEST_P2P_BROADCAST_STALL,
    };
    pub use super::relayer::{TEST_MINER_COMMIT_TIP, TEST_MINER_THREAD_STALL};
    pub use super::signer::TEST_IGNORE_SIGNERS;
}

#[cfg(test)]
mod tests;

use self::peer::PeerThread;
use self::relayer::{RelayerDirective, RelayerThread};

pub const RELAYER_MAX_BUFFER: usize = 1;

pub const BLOCK_PROCESSOR_STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MB

/// Nakamoto node state inherited from an Epoch 2 driver, or empty for direct startup.
#[derive(Default)]
pub struct NodeStartup {
    leader_key_registration_state: LeaderKeyRegistrationState,
    peer_network: Option<PeerNetwork>,
}

impl NodeStartup {
    pub fn inherited(
        leader_key_registration_state: LeaderKeyRegistrationState,
        peer_network: Option<PeerNetwork>,
    ) -> Self {
        Self {
            leader_key_registration_state,
            peer_network,
        }
    }
}

/// Node implementation for both miners and followers.
/// This struct is used to set up the node proper and launch the p2p thread and relayer thread.
/// It is further used by the main thread to communicate with these two threads.
pub struct StacksNode {
    /// Global inter-thread communication handle
    pub globals: Globals,
    /// True if we're a miner
    is_miner: bool,
    workers: WorkerHandles<()>,
}

/// Types of errors that can arise during Nakamoto StacksNode operation
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Can't find the block sortition snapshot for the chain tip
    #[error("Can't find the block sortition snapshot for the chain tip")]
    SnapshotNotFoundForChainTip,
    /// The burnchain tip changed while this operation was in progress
    #[error("The burnchain tip changed while this operation was in progress")]
    BurnchainTipChanged,
    /// The Stacks tip changed while this operation was in progress
    #[error("The Stacks tip changed while this operation was in progress")]
    StacksTipChanged,
    /// Signers rejected a block
    #[error("Signers rejected a block")]
    SignersRejected {
        /// Transaction IDs to exclude from the next block build (e.g., due to contextual rejections)
        temporarily_excluded_txids: HashSet<Txid>,
        /// Transaction IDs to permanently ban from the mempool
        permanently_excluded_txids: HashSet<Txid>,
    },
    /// Error while spawning a subordinate thread
    #[error("Error while spawning a subordinate thread: {0}")]
    SpawnError(std::io::Error),
    /// Injected testing errors
    #[error("Injected testing errors")]
    FaultInjection,
    /// This miner was elected, but another sortition occurred before mining started
    #[error("This miner was elected, but another sortition occurred before mining started")]
    MissedMiningOpportunity,
    /// Attempted to mine while there was no active VRF key
    #[error("Attempted to mine while there was no active VRF key")]
    NoVRFKeyActive,
    /// The parent block or tenure could not be found
    #[error("The parent block or tenure could not be found")]
    ParentNotFound,
    /// Something unexpected happened (e.g., hash mismatches)
    #[error("Something unexpected happened (e.g., hash mismatches)")]
    UnexpectedChainState,
    /// A burnchain operation failed when submitting it to the burnchain
    #[error("A burnchain operation failed when submitting it to the burnchain: {0}")]
    BurnchainSubmissionFailed(BurnchainsError),
    /// A new parent has been discovered since mining started
    #[error("A new parent has been discovered since mining started")]
    NewParentDiscovered,
    /// A failure occurred while constructing a VRF Proof
    #[error("A failure occurred while constructing a VRF Proof")]
    BadVrfConstruction,
    #[error("A failure occurred while mining: {0}")]
    MiningFailure(#[from] ChainstateError),
    /// The miner didn't accept their own block
    #[error("The miner didn't accept their own block: {0}")]
    AcceptFailure(ChainstateError),
    #[error("A failure occurred while signing a miner's block: {0}")]
    MinerSignatureError(&'static str),
    #[error("A failure occurred while signing a signer's block: {0}")]
    SignerSignatureError(String),
    /// A failure occurred while configuring the miner thread
    #[error("A failure occurred while configuring the miner thread: {0}")]
    MinerConfigurationFailed(&'static str),
    /// An error occurred while operating as the signing coordinator
    #[error("An error occurred while operating as the signing coordinator: {0}")]
    SigningCoordinatorFailure(String),
    /// An error occurred on StackerDB post
    #[error("An error occurred while uploading data to StackerDB: {0}")]
    StackerDBUploadError(StackerDBChunkAckData),
    // The thread that we tried to send to has closed
    #[error("The thread that we tried to send to has closed")]
    ChannelClosed,
    /// DBError wrapper
    #[error("DBError: {0}")]
    DBError(#[from] DBError),
    /// NetError wrapper
    #[error("NetError: {0}")]
    NetError(#[from] NetError),
    #[error("Timed out waiting for signatures")]
    SignatureTimeout,
}

impl StacksNode {
    pub fn spawn(
        context: SpawnContext<RelayerDirective>,
        // relay receiver endpoint for the p2p thread, so the relayer can feed it data to push
        relay_recv: Receiver<RelayerDirective>,
        startup: NodeStartup,
    ) -> StacksNode {
        let config = context.config().clone();
        let globals = context.shared();
        let is_miner = context.is_miner();
        let burnchain = context.burnchain().clone();
        let mut keychain = Keychain::default(config.node.seed.clone());
        if let Some(mining_key) = config.miner.mining_key.clone() {
            keychain.set_nakamoto_sk(mining_key);
        }

        let _ = config
            .connect_mempool_db()
            .expect("FATAL: database failure opening mempool");

        let NodeStartup {
            leader_key_registration_state,
            peer_network,
        } = startup;
        let peer_network_origin = if peer_network.is_some() {
            PeerNetworkOrigin::Inherited
        } else {
            PeerNetworkOrigin::Fresh
        };

        let (p2p_net, local_peer, relayer) =
            NodeNetwork::prepare(&config, burnchain.clone(), peer_network).into_parts();

        // setup initial key registration
        let leader_key_registration_state = if config.get_node_config(false).mock_mining {
            // mock mining, pretend to have a registered key
            LeaderKeyRegistrationState::Active(RegisteredKey::for_mock_mining(
                &keychain,
                keychain.get_nakamoto_pkh().as_bytes().to_vec(),
            ))
        } else {
            match &leader_key_registration_state {
                LeaderKeyRegistrationState::Active(registered_key) => {
                    let pubkey_hash = keychain.get_nakamoto_pkh();
                    if pubkey_hash.as_ref() == registered_key.memo {
                        leader_key_registration_state
                    } else {
                        LeaderKeyRegistrationState::Inactive
                    }
                }
                _ => LeaderKeyRegistrationState::Inactive,
            }
        };

        globals.set_initial_leader_key_registration_state(leader_key_registration_state);

        let relayer_thread =
            RelayerThread::new(&context, local_peer.clone(), relayer, keychain.clone());

        crate::monitoring::set_burnchain_signer(&keychain, &relayer_thread.bitcoin_controller);

        let relayer_thread_name = format!("relayer:{}", local_peer.port);
        let relayer_thread_handle = thread::Builder::new()
            .name(relayer_thread_name)
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                relayer_thread.main(relay_recv);
            })
            .expect("FATAL: failed to start relayer thread");

        let p2p_port = config
            .node
            .p2p_bind_addr()
            .unwrap_or_else(|| panic!("Failed to parse socket: {}", &config.node.p2p_bind))
            .port();
        let rpc_port = config
            .node
            .rpc_bind_addr()
            .unwrap_or_else(|| panic!("Failed to parse socket: {}", &config.node.rpc_bind))
            .port();

        let p2p_event_dispatcher = context.events();
        let p2p_thread = PeerThread::new(
            globals.clone(),
            &config,
            burnchain.pox_constants,
            p2p_net,
            peer_network_origin,
        );
        let p2p_thread_handle = thread::Builder::new()
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .name(format!("p2p:({p2p_port},{rpc_port})"))
            .spawn(move || {
                p2p_thread.main(p2p_event_dispatcher);
            })
            .expect("FATAL: failed to start p2p thread");

        info!("Start HTTP server on: {}", &config.node.rpc_bind);
        info!("Start P2P server on: {}", &config.node.p2p_bind);

        StacksNode {
            globals,
            is_miner,
            workers: WorkerHandles::new(relayer_thread_handle, p2p_thread_handle),
        }
    }

    /// Notify the relayer that a new burn block has been processed by the sortition db,
    ///  telling it to process the block and begin mining if this miner won.
    /// returns _false_ if the relayer hung up the channel.
    /// Called from the main thread.
    fn relayer_burnchain_notify(&self, snapshot: BlockSnapshot) -> Result<(), Error> {
        if !self.is_miner {
            // node is a follower, don't need to notify the relayer of these events.
            return Ok(());
        }

        info!(
            "Tenure: Notify burn block!";
            "consensus_hash" => %snapshot.consensus_hash,
            "burn_block_hash" => %snapshot.burn_header_hash,
            "winning_stacks_block_hash" => %snapshot.winning_stacks_block_hash,
            "burn_block_height" => &snapshot.block_height,
            "sortition_id" => %snapshot.sortition_id
        );

        // Unlike the Epoch 2 node, the Nakamoto node should *always* notify the relayer of
        //  a new burnchain block

        self.globals
            .relay_send
            .send(RelayerDirective::ProcessedBurnBlock(
                snapshot.consensus_hash,
                snapshot.parent_burn_header_hash,
                snapshot.winning_stacks_block_hash,
            ))
            .map_err(|_| Error::ChannelClosed)?;

        Ok(())
    }

    /// Process a state coming from the burnchain, by extracting the validated KeyRegisterOp
    /// and inspecting if a sortition was won.
    /// `ibd`: boolean indicating whether or not we are in the initial block download
    /// Called from the main thread.
    pub fn process_burnchain_state(
        &mut self,
        config: &Config,
        sortdb: &SortitionDB,
        sort_id: &SortitionId,
        ibd: bool,
    ) -> Result<(), Error> {
        let mut observation = BurnBlockObservation::load(sortdb, sort_id, self.is_miner);
        observation.log_processed(ibd);
        observation.activate_leader_key(&self.globals, config);
        self.globals
            .set_last_sortition(observation.snapshot().clone());

        // notify the relayer thread of the new sortition state
        self.relayer_burnchain_notify(observation.into_snapshot())
    }

    /// Join all inner threads
    pub fn join(self) {
        self.workers.join();
    }
}
