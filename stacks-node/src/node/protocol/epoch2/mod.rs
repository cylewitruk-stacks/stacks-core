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

//! Main body of code for the Stacks node and miner.
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
//!                           |------------------|
//!                           | Epoch 2 driver   |   [1,7]
//!                           |   .----------.   |--------------------------------------.
//!                           |   .StacksNode.   |                                      |
//!                           |---.----------.---|                                      |
//!                    [1,12]     |     |    |     [1]                                  |
//!              .----------------*     |    *---------------.                          |
//!              |                  [3] |                    |                          |
//!              V                      |                    V                          V
//!      |----------------|             |    [9,10]   |---------------| [11] |--------------------------|
//! .--- | Relayer thread | <-----------|-----------> |   P2P Thread  | <--- | ChainsCoordinator thread | <--.
//! |    |----------------|             V             |---------------|      |--------------------------|    |
//! |            |     |          /-------------\    [2,3]    |    |              |          |               |
//! |        [1] |     *--------> /   Globals   \ <-----------*----|--------------*          | [4]           |
//! |            |     [2,3,7]    /-------------\                  |                         |               |
//! |            V                                                 V [5]                     V               |
//! |    |----------------|                                 @--------------@        @------------------@     |
//! |    |  Miner thread  | <------------------------------ @  Mempool DB  @        @  Chainstate DBs  @     |
//! |    |----------------|             [6]                 @--------------@        @------------------@     |
//! |                                                                                        ^               |
//! |                                               [8]                                      |               |
//! *----------------------------------------------------------------------------------------*               |
//! |                                               [7]                                                      |
//! *--------------------------------------------------------------------------------------------------------*
//!
//! [1]  Spawns
//! [2]  Synchronize unconfirmed state
//! [3]  Enable/disable miner
//! [4]  Processes block data
//! [5]  Stores unconfirmed transactions
//! [6]  Reads unconfirmed transactions
//! [7]  Signals block arrival
//! [8]  Store blocks and microblocks
//! [9]  Pushes retrieved blocks and microblocks
//! [10] Broadcasts new blocks, microblocks, and transactions
//! [11] Notifies about new transaction attachment events
//! [12] Signals VRF key registration
//! ```
//!
//! When the node is running, there are 4-5 active threads at once. They are:
//!
//! * **Epoch 2 driver thread**:
//!     This is the main thread, whose code body lives in
//!     `src/node/protocol/epoch2/driver.rs`.
//!     This thread is responsible for:
//!       * Bootup
//!       * Running the burnchain indexer
//!       * Notifying the ChainsCoordinator thread when there are new burnchain blocks to process
//!
//! * **Relayer Thread**:
//!     This is the thread that stores and relays blocks and microblocks. Both
//!     it and the ChainsCoordinator thread are very I/O-heavy threads, and care has been taken to
//!     ensure that neither one attempts to acquire a write-lock in the underlying databases.
//!     Specifically, this thread directs the ChainsCoordinator thread when to process new Stacks
//!     blocks, and it directs the miner thread (if running) to stop when either it or the
//!     ChainsCoordinator thread needs to acquire the write-lock.
//!     This thread is responsible for:
//!       * Receiving new blocks and microblocks from the P2P thread via a shared channel
//!       * (Synchronously) requesting the CoordinatorThread to process newly-stored Stacks blocks
//!         and microblocks
//!       * Building up the node's unconfirmed microblock stream state, and sharing it with the P2P
//!         thread so it can answer queries about the unconfirmed microblock chain
//!       * Pushing newly-discovered blocks and microblocks to the P2P thread for broadcast
//!       * Registering the VRF public key for the miner
//!       * Spawning the block and microblock miner threads, and stopping them if their continued
//!         execution would inhibit block or microblock storage or processing.
//!       * Submitting the burnchain operation to commit to a freshly-mined block
//!
//! * **Miner Thread**:
//!     This is the thread that actually produces new blocks and microblocks. It
//!     is spawned only by the Relayer thread to carry out mining activity when the underlying
//!     chainstate is not needed by either the Relayer or ChainsCoordinator threads.
//!     This thread does the following:
//!       * Walk the mempool DB to build a new block or microblock
//!       * Return the block or microblock to the Relayer thread
//!
//! * **P2P Thread**:
//!     This is the thread that communicates with the rest of the P2P network, and
//!     handles RPC requests. It is meant to do as little storage-write I/O as possible to avoid lock
//!     contention with the Miner, Relayer, and ChainsCoordinator threads. In particular, it forwards
//!     data it receives from the P2P thread to the Relayer thread for I/O-bound processing. At the
//!     time of this writing, it still requires holding a write-lock to handle some RPC requests, but
//!     future work will remove this so that this thread's execution will not interfere with the
//!     others. This is the only thread that does socket I/O.
//!     This thread runs the PeerNetwork state machines, which include the following:
//!       * Learning the node's public IP address
//!       * Discovering neighbor nodes
//!       * Forwarding newly-discovered blocks, microblocks, and transactions from the Relayer thread
//!         to other neighbors
//!       * Synchronizing block and microblock inventory state with other neighbors
//!       * Downloading blocks and microblocks, and passing them to the Relayer for storage and
//!         processing
//!       * Downloading transaction attachments as their hashes are discovered during block processing
//!       * Synchronizing the local mempool database with other neighbors
//!         (notifications for new attachments come from a shared channel in the ChainsCoordinator thread)
//!       * Handling HTTP requests
//!
//! * **ChainsCoordinator Thread**:
//!     This thread processes sortitions and Stacks blocks and
//!     microblocks, and handles PoX reorgs should they occur (this mainly happens in boot-up). It,
//!     like the Relayer thread, is a very I/O-heavy thread, and it will hold a write-lock on the
//!     chainstate DBs while it works. Its actions are controlled by a CoordinatorComms structure in
//!     the shared node state, which the Relayer and Epoch 2 driver threads both drive (the former
//!     drives Stacks block processing, the latter sortitions).
//!     This thread is responsible for:
//!       * Responding to requests from other threads to process sortitions
//!       * Responding to requests from other threads to process Stacks blocks and microblocks
//!       * Processing PoX chain reorgs, should they ever happen
//!       * Detecting attachment creation events, and informing the P2P thread of them so it can go
//!         and download them
//!
//! In addition to the mempool and chainstate databases, these threads share access to a Globals
//! singleton that contains soft state shared between threads. Mainly, the Globals struct is meant
//! to store inter-thread shared singleton communication media all in one convenient struct. Each
//! thread has a handle to the struct's shared state handles. Global state includes:
//!       * The global flag as to whether or not the miner thread can be running
//!       * The global shutdown flag that, when set, causes all threads to terminate
//!       * Sender channel endpoints that can be shared between threads
//!       * Metrics about the node's behavior (e.g. number of blocks processed, etc.)

use std::collections::HashMap;
use std::sync::mpsc::Receiver;
use std::thread;

use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::stacks::miner::{signal_mining_blocked, AssembledAnchorBlock};
use stacks::config::NodeConfig;
use stacks::net::p2p::PeerNetwork;
use stacks_common::types::chainstate::{BlockHeaderHash, SortitionId};
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;

use crate::node::context::SpawnContext;
use crate::node::leader_key::{LeaderKeyRegistrationState, RegisteredKey};
use crate::node::network::{run_peer_network_loop, NodeNetwork};
use crate::node::runtime::{BurnBlockObservation, Globals, WorkerHandles};
use crate::{Config, EventDispatcher, Keychain};

mod driver;
mod microblock_miner;
mod miner;
mod peer;
mod relayer;

pub use driver::{Driver, Epoch2Shutdown};
pub use miner::{BlockMinerThread, TipCandidate};
use peer::PeerThread;
use relayer::{RelayerDirective, RelayerThread};

pub const RELAYER_MAX_BUFFER: usize = 100;

pub const BLOCK_PROCESSOR_STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MB

type MinedBlocks = HashMap<BlockHeaderHash, (AssembledAnchorBlock, Secp256k1PrivateKey)>;

pub type NeonGlobals = Globals<RelayerDirective>;

/// Node implementation for both miners and followers.
/// This struct is used to set up the node proper and launch the p2p thread and relayer thread.
/// It is further used by the main thread to communicate with these two threads.
pub struct StacksNode {
    /// Global inter-thread communication handle
    pub globals: NeonGlobals,
    /// True if we're a miner
    is_miner: bool,
    workers: WorkerHandles<Option<PeerNetwork>>,
}

impl StacksNode {
    /// Main loop of the relayer.
    /// Runs in a separate thread.
    /// Continuously receives
    pub fn relayer_main(mut relayer_thread: RelayerThread, relay_recv: Receiver<RelayerDirective>) {
        while let Ok(directive) = relay_recv.recv() {
            if !relayer_thread.globals.keep_running() {
                break;
            }

            if !relayer_thread.handle_directive(directive) {
                break;
            }
        }

        // kill miner if it's running
        signal_mining_blocked(relayer_thread.globals.get_miner_status());

        // set termination flag so other threads die
        relayer_thread.globals.signal_stop();

        debug!("Relayer exit!");
    }

    /// Main loop of the p2p thread.
    /// Runs in a separate thread.
    /// Continuously receives, until told otherwise.
    pub fn p2p_main(
        mut p2p_thread: PeerThread,
        event_dispatcher: EventDispatcher,
    ) -> Option<PeerNetwork> {
        let config = p2p_thread.config.clone();
        let should_keep_running = p2p_thread.globals.should_keep_running.clone();
        run_peer_network_loop(
            &config,
            should_keep_running,
            |indexer, dns_client, cost_estimator, cost_metric, fee_estimator| {
                p2p_thread.run_one_pass(
                    indexer,
                    dns_client,
                    &event_dispatcher,
                    cost_estimator,
                    cost_metric,
                    fee_estimator,
                )
            },
        );

        p2p_thread
            .globals
            .shutdown_peer_worker(RelayerDirective::Exit);
        Some(p2p_thread.resources.into_network())
    }

    pub fn spawn(
        context: SpawnContext<RelayerDirective>,
        // relay receiver endpoint for the p2p thread, so the relayer can feed it data to push
        relay_recv: Receiver<RelayerDirective>,
    ) -> StacksNode {
        let (config, burnchain, globals, event_dispatcher, is_miner) = context.into_parts();
        let keychain = Keychain::default(config.node.seed.clone());

        let _ = config
            .connect_mempool_db()
            .expect("BUG: failed to instantiate mempool");
        let (p2p_net, local_peer, relayer) =
            NodeNetwork::prepare(&config, burnchain.clone(), None).into_parts();

        let NodeConfig {
            mock_mining, miner, ..
        } = config.get_node_config(false);

        // setup initial key registration
        let leader_key_registration_state = if mock_mining {
            // mock mining, pretend to have a registered key
            LeaderKeyRegistrationState::Active(RegisteredKey::for_mock_mining(&keychain, vec![]))
        } else {
            // Warn the user that they need to set up a miner key
            if miner && config.miner.mining_key.is_none() {
                warn!("`[miner.mining_key]` not set in config file. This will be required to mine in Epoch 3.0!")
            }
            LeaderKeyRegistrationState::Inactive
        };
        globals.set_initial_leader_key_registration_state(leader_key_registration_state);

        let relayer_thread = RelayerThread::new(
            config.clone(),
            globals.clone(),
            burnchain.clone(),
            event_dispatcher.clone(),
            local_peer.clone(),
            relayer,
        );

        crate::monitoring::set_burnchain_signer(&keychain, &relayer_thread.bitcoin_controller);

        let relayer_thread_handle = thread::Builder::new()
            .name(format!("relayer-{}", &local_peer.data_url))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                debug!("relayer thread ID is {:?}", thread::current().id());
                Self::relayer_main(relayer_thread, relay_recv);
            })
            .expect("FATAL: failed to start relayer thread");

        let p2p_thread =
            PeerThread::new(globals.clone(), &config, burnchain.pox_constants, p2p_net);
        let p2p_thread_handle = thread::Builder::new()
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .name(format!(
                "p2p-({},{})",
                &config.node.p2p_bind, &config.node.rpc_bind
            ))
            .spawn(move || {
                debug!("p2p thread ID is {:?}", thread::current().id());
                Self::p2p_main(p2p_thread, event_dispatcher)
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

    /// Manage the VRF public key registration state machine.
    /// Tell the relayer thread to fire off a tenure and a block commit op,
    /// if it is time to do so.
    /// `ibd` indicates whether or not we're in the initial block download.  Used to control when
    /// to try and register VRF keys.
    /// Called from the main thread.
    /// Return true if we succeeded in carrying out the next task of the operation.
    pub fn relayer_issue_tenure(&mut self, ibd: bool) -> bool {
        if !self.is_miner {
            // node is a follower, don't try to issue a tenure
            return true;
        }

        if let Some(burnchain_tip) = self.globals.get_last_sortition() {
            if !ibd {
                // try and register a VRF key before issuing a tenure
                let leader_key_registration_state =
                    self.globals.get_leader_key_registration_state();
                match leader_key_registration_state {
                    LeaderKeyRegistrationState::Active(ref key) => {
                        debug!(
                            "Tenure: Using key {:?} off of {}",
                            &key.vrf_public_key, &burnchain_tip.burn_header_hash
                        );

                        self.globals
                            .relay_send
                            .send(RelayerDirective::RunTenure(
                                key.clone(),
                                burnchain_tip,
                                get_epoch_time_ms(),
                            ))
                            .is_ok()
                    }
                    LeaderKeyRegistrationState::Inactive => {
                        warn!(
                            "Tenure: skipped tenure because no active VRF key. Trying to register one."
                        );
                        self.globals
                            .relay_send
                            .send(RelayerDirective::RegisterKey(burnchain_tip))
                            .is_ok()
                    }
                    LeaderKeyRegistrationState::Pending(..) => true,
                }
            } else {
                // still sync'ing so just try again later
                true
            }
        } else {
            warn!("Tenure: Do not know the last burn block. As a miner, this is bad.");
            true
        }
    }

    /// Notify the relayer of a sortition, telling it to process the block
    ///  and advertize it if it was mined by the node.
    /// returns _false_ if the relayer hung up the channel.
    /// Called from the main thread.
    pub fn relayer_sortition_notify(&self) -> bool {
        if !self.is_miner {
            // node is a follower, don't try to process my own tenure.
            return true;
        }

        if let Some(snapshot) = self.globals.get_last_sortition() {
            debug!(
                "Tenure: Notify sortition!";
                "consensus_hash" => %snapshot.consensus_hash,
                "burn_block_hash" => %snapshot.burn_header_hash,
                "winning_stacks_block_hash" => %snapshot.winning_stacks_block_hash,
                "burn_block_height" => &snapshot.block_height,
                "sortition_id" => %snapshot.sortition_id
            );
            if snapshot.sortition {
                return self
                    .globals
                    .relay_send
                    .send(RelayerDirective::ProcessTenure(
                        snapshot.consensus_hash,
                        snapshot.parent_burn_header_hash,
                        snapshot.winning_stacks_block_hash,
                    ))
                    .is_ok();
            }
        } else {
            debug!("Tenure: Notify sortition! No last burn block");
        }
        true
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
    ) -> Option<BlockSnapshot> {
        let mut observation = BurnBlockObservation::load(sortdb, sort_id, self.is_miner);
        self.globals
            .set_last_sortition(observation.snapshot().clone());
        let winning_snapshot = observation.winning_snapshot();
        observation.log_processed(ibd);
        observation.activate_leader_key(&self.globals, config);
        winning_snapshot
    }

    /// Join all inner threads
    pub fn join(self) -> Option<PeerNetwork> {
        self.workers.join()
    }
}
