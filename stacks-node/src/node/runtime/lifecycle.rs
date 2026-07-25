// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use stacks::burnchains::{Burnchain, Error as BurnchainError};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::coordinator::comm::{CoordinatorChannels, CoordinatorReceivers};
use stacks::chainstate::coordinator::{
    migrate_chainstate_dbs, ChainsCoordinator, ChainsCoordinatorConfig, CoordinatorCommunication,
    Error as CoordinatorError,
};
use stacks::chainstate::stacks::db::{ChainStateBootData, StacksChainState};
use stacks::chainstate::stacks::miner::MinerStatus;
use stacks::core::StacksEpochId;
use stacks::net::atlas::AtlasDB;
use stacks::util_lib::db::Error as DatabaseError;
use stacks_common::deps_common::ctrlc as termination;
use stacks_common::deps_common::ctrlc::SignalId;

use crate::burnchains::{
    make_bitcoin_indexer, BitcoinRegtestController, BurnchainController, Error as ControllerError,
};
use crate::monitoring::{start_serving_monitoring_metrics, MonitoringError};
use crate::node::context::SpawnContext;
use crate::node::genesis::{
    announce_boot_receipts, attach_genesis_data_sources, use_test_genesis_chainstate,
};
use crate::node::leader_key::LeaderKeyRegistrationState;
use crate::node::runtime::{Counters, Globals};
use crate::syncctl::PoxSyncWatchdogComms;
use crate::{BurnchainTip, Config, EventDispatcher, Keychain};

const STDERR: i32 = 2;

fn async_safe_write_stderr(message: &str) {
    #[cfg(windows)]
    unsafe {
        libc::write(
            STDERR,
            message.as_ptr() as *const libc::c_void,
            message.len() as u32,
        );
    }
    #[cfg(not(windows))]
    unsafe {
        libc::write(
            STDERR,
            message.as_ptr() as *const libc::c_void,
            message.len(),
        );
    }
}

/// Configuration for the shared portion of epoch-aware startup.
pub struct EpochStartup {
    burnchain: Option<Burnchain>,
    mine_start: u64,
    relay_buffer: usize,
    burnchain_db_readwrite: bool,
    coordinator: (String, usize),
}

impl EpochStartup {
    pub fn new(
        burnchain: Option<Burnchain>,
        mine_start: u64,
        relay_buffer: usize,
        coordinator_thread_name: String,
        coordinator_stack_size: usize,
    ) -> Self {
        Self {
            burnchain,
            mine_start,
            relay_buffer,
            burnchain_db_readwrite: false,
            coordinator: (coordinator_thread_name, coordinator_stack_size),
        }
    }

    pub fn burnchain_db_readwrite(mut self, readwrite: bool) -> Self {
        self.burnchain_db_readwrite = readwrite;
        self
    }

    fn prepare<Directive>(
        self,
        runtime: &mut EpochRuntime,
    ) -> Result<PreparedEpochRuntime<Directive>, BurnchainError> {
        let Self {
            burnchain,
            mine_start,
            relay_buffer,
            burnchain_db_readwrite,
            coordinator: (coordinator_thread_name, coordinator_stack_size),
        } = self;
        let (coordinator_receivers, coordinator_senders) = runtime.take_coordinator_channels();
        runtime.config().apply_runtime_state();
        let mut burnchain =
            runtime.instantiate_burnchain(burnchain, coordinator_senders.clone())?;
        let burnchain_config = burnchain.get_burnchain();
        let is_miner = runtime.check_is_miner(&mut burnchain);

        let (relay_sender, relay_receiver) = sync_channel(relay_buffer);
        let globals = Globals::new(
            coordinator_senders,
            runtime.miner_status(),
            relay_sender,
            runtime.counters(),
            runtime.sync_comms(),
            runtime.termination_switch(),
            mine_start,
            LeaderKeyRegistrationState::default(),
        );
        let coordinator_thread = runtime.spawn_chains_coordinator(
            &burnchain_config,
            coordinator_receivers,
            globals.get_miner_status(),
            coordinator_thread_name,
            coordinator_stack_size,
        );
        runtime.start_monitoring_once();
        globals.coord().announce_new_burn_block();

        let (reward_cycle_height, snapshot) =
            reward_cycle_sortition_db_height(burnchain.sortdb_mut(), &burnchain_config);
        let initial_snapshot = if snapshot.block_height == burnchain_config.first_block_height {
            burnchain
                .wait_for_sortitions(globals.coord().clone(), snapshot.block_height + 1)
                .expect("Unable to get burnchain tip")
                .block_snapshot
        } else {
            snapshot
        };
        globals.set_last_sortition(initial_snapshot);

        let spawn_context = SpawnContext::new(
            runtime.config().clone(),
            burnchain_config.clone(),
            globals,
            runtime.event_dispatcher(),
            is_miner,
        );

        Ok(PreparedEpochRuntime {
            burnchain,
            burnchain_config,
            spawn_context,
            relay_receiver,
            coordinator_thread,
            reward_cycle_height,
            burnchain_db_readwrite,
        })
    }

    /// Prepare shared services and consistently report recoverable startup failures.
    pub fn prepare_or_log<Directive>(
        self,
        runtime: &mut EpochRuntime,
    ) -> Option<PreparedEpochRuntime<Directive>> {
        match self.prepare(runtime) {
            Ok(prepared) => Some(prepared),
            Err(BurnchainError::ShutdownInitiated) => {
                info!("Exiting stacks-node");
                None
            }
            Err(error) => {
                error!("Error initializing burnchain: {error}");
                info!("Exiting stacks-node");
                None
            }
        }
    }
}

/// Epoch services that are ready to launch, but whose P2P and RPC threads are not yet running.
pub struct PreparedEpochRuntime<Directive> {
    burnchain: BitcoinRegtestController,
    burnchain_config: Burnchain,
    spawn_context: SpawnContext<Directive>,
    relay_receiver: Receiver<Directive>,
    coordinator_thread: JoinHandle<()>,
    reward_cycle_height: u64,
    burnchain_db_readwrite: bool,
}

/// Epoch services after the node has launched and all pending sortitions have been processed.
pub struct RunningEpochRuntime<Directive> {
    pub burnchain: BitcoinRegtestController,
    pub burnchain_config: Burnchain,
    pub globals: Globals<Directive>,
    pub coordinator_thread: JoinHandle<()>,
    pub burnchain_tip: BurnchainTip,
    pub reward_cycle_height: u64,
    pub is_miner: bool,
}

impl<Directive> PreparedEpochRuntime<Directive> {
    /// Launch the node before waiting on coordinator work that may require its P2P stack.
    /// Readiness is signaled only after all pending sortitions have completed.
    pub fn spawn_and_synchronize<Node>(
        self,
        spawn_node: impl FnOnce(SpawnContext<Directive>, Receiver<Directive>) -> Node,
    ) -> (RunningEpochRuntime<Directive>, Node) {
        let Self {
            burnchain,
            burnchain_config,
            spawn_context,
            relay_receiver,
            coordinator_thread,
            reward_cycle_height,
            burnchain_db_readwrite,
        } = self;

        let globals = spawn_context.shared();
        let is_miner = spawn_context.is_miner();
        let node = spawn_node(spawn_context, relay_receiver);
        let burnchain_db = burnchain_config
            .open_burnchain_db(burnchain_db_readwrite)
            .expect("FATAL: failed to open burnchain DB");
        let burnchain_db_tip = burnchain_db
            .get_canonical_chain_tip()
            .expect("FATAL: failed to query burnchain DB");
        let burnchain_tip = burnchain
            .wait_for_sortitions(globals.coord().clone(), burnchain_db_tip.block_height)
            .expect("Unable to get burnchain tip");
        globals.counters.bump_blocks_processed();

        (
            RunningEpochRuntime {
                burnchain,
                burnchain_config,
                globals,
                coordinator_thread,
                burnchain_tip,
                reward_cycle_height,
                is_miner,
            },
            node,
        )
    }
}

/// Resources whose identity persists across an epoch transition.
pub struct RuntimeContinuity {
    should_keep_running: Arc<AtomicBool>,
    counters: Counters,
    monitoring_thread: Option<JoinHandle<Result<(), MonitoringError>>>,
    event_dispatcher: EventDispatcher,
}

impl RuntimeContinuity {
    pub fn fresh(config: &Config) -> Self {
        let should_keep_running = Arc::new(AtomicBool::new(true));
        setup_termination_handler(should_keep_running.clone());
        Self {
            should_keep_running,
            counters: Counters::default(),
            monitoring_thread: None,
            event_dispatcher: EventDispatcher::from_config(config),
        }
    }

    fn new(
        should_keep_running: Arc<AtomicBool>,
        counters: Counters,
        monitoring_thread: Option<JoinHandle<Result<(), MonitoringError>>>,
        event_dispatcher: EventDispatcher,
    ) -> Self {
        Self {
            should_keep_running,
            counters,
            monitoring_thread,
            event_dispatcher,
        }
    }

    pub fn reactivate(&self) {
        self.should_keep_running
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Shared ownership and lifecycle state for either epoch implementation.
pub struct EpochRuntime {
    config: Config,
    coordinator_channels: Option<(CoordinatorReceivers, CoordinatorChannels)>,
    should_keep_running: Arc<AtomicBool>,
    counters: Counters,
    event_dispatcher: EventDispatcher,
    pox_watchdog_comms: PoxSyncWatchdogComms,
    miner_status: Arc<Mutex<MinerStatus>>,
    monitoring_thread: Option<JoinHandle<Result<(), MonitoringError>>>,
}

impl EpochRuntime {
    pub fn fresh(config: Config) -> Self {
        let continuity = RuntimeContinuity::fresh(&config);
        Self::new(config, continuity)
    }

    pub fn new(config: Config, continuity: RuntimeContinuity) -> Self {
        let pox_watchdog_comms = PoxSyncWatchdogComms::new(continuity.should_keep_running.clone());
        let miner_status = Arc::new(Mutex::new(MinerStatus::make_ready(
            config.burnchain.burn_fee_cap,
        )));
        Self {
            config,
            coordinator_channels: Some(CoordinatorCommunication::instantiate()),
            should_keep_running: continuity.should_keep_running,
            counters: continuity.counters,
            event_dispatcher: continuity.event_dispatcher,
            pox_watchdog_comms,
            miner_status,
            monitoring_thread: continuity.monitoring_thread,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn counters(&self) -> Counters {
        self.counters.clone()
    }

    pub fn event_dispatcher(&self) -> EventDispatcher {
        self.event_dispatcher.clone()
    }

    pub fn event_dispatcher_ref(&self) -> &EventDispatcher {
        &self.event_dispatcher
    }

    pub fn termination_switch(&self) -> Arc<AtomicBool> {
        self.should_keep_running.clone()
    }

    pub fn sync_comms(&self) -> PoxSyncWatchdogComms {
        self.pox_watchdog_comms.clone()
    }

    pub fn miner_status(&self) -> Arc<Mutex<MinerStatus>> {
        self.miner_status.clone()
    }

    pub fn coordinator_channel(&self) -> Option<CoordinatorChannels> {
        self.coordinator_channels
            .as_ref()
            .map(|channels| channels.1.clone())
    }

    fn take_coordinator_channels(&mut self) -> (CoordinatorReceivers, CoordinatorChannels) {
        self.coordinator_channels
            .take()
            .expect("Run loop already started, can only start once after initialization")
    }

    fn start_monitoring_once(&mut self) {
        if self.monitoring_thread.is_none() {
            self.monitoring_thread = self.start_monitoring();
        }
    }

    pub fn take_continuity(&mut self) -> RuntimeContinuity {
        RuntimeContinuity::new(
            self.termination_switch(),
            self.counters(),
            self.monitoring_thread.take(),
            self.event_dispatcher(),
        )
    }
}

fn setup_termination_handler(keep_running: Arc<AtomicBool>) {
    let install = termination::set_handler(move |signal| match signal {
        SignalId::Bus => {
            async_safe_write_stderr("Caught SIGBUS; crashing immediately and dumping core\n");
            unsafe { libc::abort() };
        }
        _ => {
            let message = format!(
                "Graceful termination request received (signal `{signal}`), will complete the ongoing runloop cycles and terminate\n"
            );
            async_safe_write_stderr(&message);
            keep_running.store(false, Ordering::SeqCst);
        }
    });
    if let Err(error) = install {
        if cfg!(test) {
            info!("Error setting up signal handler, may have already been set");
        } else {
            panic!("FATAL: error setting termination handler - {error}");
        }
    }
}

impl EpochRuntime {
    fn instantiate_burnchain(
        &self,
        burnchain: Option<Burnchain>,
        coordinator: CoordinatorChannels,
    ) -> Result<BitcoinRegtestController, BurnchainError> {
        let should_keep_running = self.termination_switch();
        let mut controller = BitcoinRegtestController::with_burnchain(
            self.config().clone(),
            Some(coordinator),
            burnchain,
            Some(should_keep_running.clone()),
        );
        let burnchain = controller.get_burnchain();
        let epochs = controller.get_stacks_epochs();
        Config::assert_valid_epoch_settings(&burnchain, &epochs);

        match migrate_chainstate_dbs(
            &epochs,
            &burnchain,
            &self.config().get_burn_db_file_path(),
            &self.config().get_chainstate_path_str(),
            Some(self.config().node.get_marf_opts()),
        ) {
            Ok(_) => {}
            Err(CoordinatorError::DBError(DatabaseError::TooOldForEpoch)) => {
                error!(
                    "FATAL: chainstate database(s) are not compatible with the current system epoch"
                );
                panic!();
            }
            Err(error) => panic!("FATAL: unable to query filesystem or databases: {error:?}"),
        }

        info!(
            "Start syncing Bitcoin headers, feel free to grab a cup of coffee, this can take a while"
        );
        let target_height = match controller
            .get_burnchain()
            .get_highest_burnchain_block()
            .expect("FATAL: failed to access burnchain database")
        {
            Some(tip) => {
                let target = tip.block_height + 1;
                debug!(
                    "Burnchain DB exists and has blocks up to {}; synchronizing from where it left off up to {target}",
                    tip.block_height
                );
                target
            }
            None => {
                let target = 1.max(burnchain.first_block_height + 1);
                debug!(
                    "Burnchain DB does not exist or does not have blocks; synchronizing to first burnchain block height {target}"
                );
                target
            }
        };

        controller.start(Some(target_height)).map_err(|error| {
            if matches!(error, ControllerError::CoordinatorClosed)
                && !should_keep_running.load(Ordering::SeqCst)
            {
                info!("Shutdown initiated during burnchain initialization: {error}");
                return BurnchainError::ShutdownInitiated;
            }
            error!("Burnchain controller stopped: {error}");
            panic!();
        })?;
        controller
            .connect_dbs()
            .unwrap_or_else(|error| panic!("Failed to connect to burnchain databases: {error}"));
        let _ = controller.sortdb_mut();
        Ok(controller)
    }

    /// Determine whether this node can mine, including validating access to a usable Bitcoin UTXO.
    fn check_is_miner(&self, burnchain: &mut BitcoinRegtestController) -> bool {
        const UTXO_RETRY_INTERVAL: u64 = 10;
        const UTXO_RETRY_COUNT: u64 = 6;

        if !self.config().node.miner {
            info!("Will run as a Follower node");
            return false;
        }

        if self.config().get_node_config(false).mock_mining {
            return true;
        }

        let keychain = Keychain::default(self.config().node.seed.clone());
        let mut op_signer = keychain.generate_op_signer();
        if let Err(e) = burnchain.create_wallet_if_dne() {
            warn!("Error when creating wallet: {e:?}");
        }

        let mut address_epochs = vec![StacksEpochId::Epoch2_05];
        if self.config().miner.segwit {
            address_epochs.push(StacksEpochId::Epoch21);
        }

        for _ in 0..UTXO_RETRY_COUNT {
            for epoch_id in &address_epochs {
                let btc_addr = burnchain.get_miner_address(*epoch_id, &op_signer.get_public_key());
                info!("Miner node: checking UTXOs at address: {btc_addr}");
                let utxos = burnchain.get_utxos(*epoch_id, &op_signer.get_public_key(), 1, None, 0);
                if utxos.is_none() {
                    warn!(
                        "UTXOs not found for {btc_addr}. If this is unexpected, please ensure that your bitcoind instance is indexing transactions for the address {btc_addr} (importaddress)"
                    );
                } else {
                    info!("UTXOs found - will run as a Miner node");
                    return true;
                }
            }
            thread::sleep(std::time::Duration::from_secs(UTXO_RETRY_INTERVAL));
        }
        panic!("No UTXOs found, exiting");
    }

    pub fn boot_chainstate(&self, burnchain: &Burnchain) -> StacksChainState {
        let use_test_genesis_data = use_test_genesis_chainstate(self.config());
        let initial_balances = self
            .config()
            .initial_balances
            .iter()
            .map(|entry| (entry.address.clone(), entry.amount))
            .collect();

        let mut boot_data = ChainStateBootData::new(burnchain, initial_balances, None);
        attach_genesis_data_sources(&mut boot_data, use_test_genesis_data);

        let (chainstate, receipts) = StacksChainState::open_and_exec(
            self.config().is_mainnet(),
            self.config().burnchain.chain_id,
            &self.config().get_chainstate_path_str(),
            Some(&mut boot_data),
            Some(self.config().node.get_marf_opts()),
        )
        .unwrap();
        announce_boot_receipts(
            self.event_dispatcher_ref(),
            &chainstate,
            &burnchain.pox_constants,
            &receipts,
        );
        chainstate
    }

    fn spawn_chains_coordinator(
        &self,
        burnchain: &Burnchain,
        coordinator_receivers: CoordinatorReceivers,
        miner_status: Arc<Mutex<MinerStatus>>,
        thread_name: String,
        stack_size: usize,
    ) -> JoinHandle<()> {
        let chainstate = self.boot_chainstate(burnchain);
        let atlas_config = self.config().atlas.clone();
        let moved_config = self.config().clone();
        let moved_burnchain = burnchain.clone();
        let coordinator_dispatcher = self.event_dispatcher();
        let atlas_db = AtlasDB::connect(
            atlas_config.clone(),
            &self.config().get_atlas_db_file_path(),
            true,
        )
        .expect("Failed to connect Atlas DB during startup");
        let coordinator_indexer =
            make_bitcoin_indexer(self.config(), Some(self.termination_switch()));

        thread::Builder::new()
            .name(thread_name)
            .stack_size(stack_size)
            .spawn(move || {
                debug!(
                    "chains-coordinator thread ID is {:?}",
                    thread::current().id()
                );
                let mut cost_estimator = moved_config.make_cost_estimator();
                let mut fee_estimator = moved_config.make_fee_estimator();
                ChainsCoordinator::run(
                    ChainsCoordinatorConfig {
                        txindex: moved_config.node.txindex,
                    },
                    chainstate,
                    moved_burnchain,
                    &coordinator_dispatcher,
                    coordinator_receivers,
                    atlas_config,
                    cost_estimator.as_deref_mut(),
                    fee_estimator.as_deref_mut(),
                    miner_status,
                    coordinator_indexer,
                    atlas_db,
                );
            })
            .expect("FATAL: failed to start chains coordinator thread")
    }

    fn start_monitoring(&self) -> Option<JoinHandle<Result<(), MonitoringError>>> {
        let prometheus_bind = self.config().node.prometheus_bind.clone()?;
        Some(
            thread::Builder::new()
                .name("prometheus".to_string())
                .spawn(move || {
                    debug!("prometheus thread ID is {:?}", thread::current().id());
                    start_serving_monitoring_metrics(prometheus_bind)
                })
                .expect("FATAL: failed to start monitoring thread"),
        )
    }
}

fn reward_cycle_sortition_db_height(
    sortdb: &SortitionDB,
    burnchain: &Burnchain,
) -> (u64, BlockSnapshot) {
    let (stacks_consensus_hash, _) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn())
            .expect("BUG: failed to load canonical stacks chain tip hash");

    let snapshot = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &stacks_consensus_hash)
        .expect("BUG: failed to query sortition DB")
        .unwrap_or_else(|| {
            debug!("No canonical stacks chain tip hash present");
            SortitionDB::get_first_block_snapshot(sortdb.conn())
                .expect("BUG: failed to get first-ever block snapshot")
        });

    (
        burnchain.reward_cycle_to_block_height(
            burnchain
                .block_height_to_reward_cycle(snapshot.block_height)
                .expect("BUG: snapshot preceeds first reward cycle"),
        ),
        snapshot,
    )
}
