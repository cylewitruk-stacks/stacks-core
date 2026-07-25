use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

use stacks::burnchains::Txid;
use stacks::chainstate::burn::operations::LeaderKeyRegisterOp;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::stacks::db::unconfirmed::UnconfirmedTxMap;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::miner::MinerStatus;
use stacks::config::{BurnchainConfig, MinerConfig};

use crate::node::leader_key::{LeaderKeyRegistrationState, RegisteredKey};
use crate::node::runtime::Counters;
use crate::syncctl::PoxSyncWatchdogComms;

/// Inter-thread communication structure, shared between threads. This
/// is generic over the relayer communication channel: nakamoto and
/// neon nodes use different relayer directives.
pub struct Globals<T> {
    /// Last sortition processed
    last_sortition: Arc<Mutex<Option<BlockSnapshot>>>,
    /// Status of the miner
    miner_status: Arc<Mutex<MinerStatus>>,
    /// Communication link to the coordinator thread
    pub coord_comms: CoordinatorChannels,
    /// Unconfirmed transactions (shared between the relayer and p2p threads)
    unconfirmed_txs: Arc<Mutex<UnconfirmedTxMap>>,
    /// Writer endpoint to the relayer thread
    pub relay_send: SyncSender<T>,
    /// Counter state in the main thread
    pub counters: Counters,
    /// Connection to the PoX sync watchdog
    pub sync_comms: PoxSyncWatchdogComms,
    /// Global flag to see if we should keep running
    pub should_keep_running: Arc<AtomicBool>,
    /// Status of our VRF key registration state (shared between the main thread and the relayer)
    pub leader_key_registration_state: Arc<Mutex<LeaderKeyRegistrationState>>,
    /// Last miner config loaded
    last_miner_config: Arc<Mutex<Option<MinerConfig>>>,
    /// Last burnchain config
    last_burnchain_config: Arc<Mutex<Option<BurnchainConfig>>>,
    /// Last miner spend amount
    last_miner_spend_amount: Arc<Mutex<Option<u64>>>,
    /// burnchain height at which we start mining
    start_mining_height: Arc<Mutex<u64>>,
    /// Initiative flag.
    /// Raised when the main loop should wake up and do something.
    initiative: Arc<Mutex<Option<String>>>,
}

// Need to manually implement Clone, because [derive(Clone)] requires
//  all trait bounds to implement Clone, even though T doesn't need Clone
//  because it's behind SyncSender.
impl<T> Clone for Globals<T> {
    fn clone(&self) -> Self {
        Self {
            last_sortition: self.last_sortition.clone(),
            miner_status: self.miner_status.clone(),
            coord_comms: self.coord_comms.clone(),
            unconfirmed_txs: self.unconfirmed_txs.clone(),
            relay_send: self.relay_send.clone(),
            counters: self.counters.clone(),
            sync_comms: self.sync_comms.clone(),
            should_keep_running: self.should_keep_running.clone(),
            leader_key_registration_state: self.leader_key_registration_state.clone(),
            last_miner_config: self.last_miner_config.clone(),
            last_burnchain_config: self.last_burnchain_config.clone(),
            last_miner_spend_amount: self.last_miner_spend_amount.clone(),
            start_mining_height: self.start_mining_height.clone(),
            initiative: self.initiative.clone(),
        }
    }
}

impl<T> Globals<T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coord_comms: CoordinatorChannels,
        miner_status: Arc<Mutex<MinerStatus>>,
        relay_send: SyncSender<T>,
        counters: Counters,
        sync_comms: PoxSyncWatchdogComms,
        should_keep_running: Arc<AtomicBool>,
        start_mining_height: u64,
        leader_key_registration_state: LeaderKeyRegistrationState,
    ) -> Globals<T> {
        Globals {
            last_sortition: Arc::new(Mutex::new(None)),
            miner_status,
            coord_comms,
            unconfirmed_txs: Arc::new(Mutex::new(UnconfirmedTxMap::new())),
            relay_send,
            counters,
            sync_comms,
            should_keep_running,
            leader_key_registration_state: Arc::new(Mutex::new(leader_key_registration_state)),
            last_miner_config: Arc::new(Mutex::new(None)),
            last_burnchain_config: Arc::new(Mutex::new(None)),
            last_miner_spend_amount: Arc::new(Mutex::new(None)),
            start_mining_height: Arc::new(Mutex::new(start_mining_height)),
            initiative: Arc::new(Mutex::new(None)),
        }
    }

    /// Does the inventory sync watcher think we still need to
    /// catch up to the chain tip?
    pub fn in_initial_block_download(&self) -> bool {
        self.sync_comms.get_ibd()
    }

    /// Get the last sortition processed by the relayer thread
    pub fn get_last_sortition(&self) -> Option<BlockSnapshot> {
        self.last_sortition
            .lock()
            .unwrap_or_else(|_| {
                error!("Sortition mutex poisoned!");
                panic!();
            })
            .clone()
    }

    /// Set the last sortition processed
    pub fn set_last_sortition(&self, block_snapshot: BlockSnapshot) {
        let mut last_sortition = self.last_sortition.lock().unwrap_or_else(|_| {
            error!("Sortition mutex poisoned!");
            panic!();
        });
        last_sortition.replace(block_snapshot);
    }

    /// Get the status of the miner (blocked or ready)
    pub fn get_miner_status(&self) -> Arc<Mutex<MinerStatus>> {
        self.miner_status.clone()
    }

    pub fn block_miner(&self) {
        self.miner_status
            .lock()
            .expect("FATAL: mutex poisoned")
            .add_blocked()
    }

    pub fn unblock_miner(&self) {
        self.miner_status
            .lock()
            .expect("FATAL: mutex poisoned")
            .remove_blocked()
    }

    /// Called by the relayer to pass unconfirmed txs to the p2p thread, so the p2p thread doesn't
    /// need to do the disk I/O needed to instantiate the unconfirmed state trie they represent.
    /// Clears the unconfirmed transactions, and replaces them with the chainstate's.
    pub fn send_unconfirmed_txs(&self, chainstate: &StacksChainState) {
        let Some(ref unconfirmed) = chainstate.unconfirmed_state else {
            return;
        };
        let mut txs = self.unconfirmed_txs.lock().unwrap_or_else(|e| {
            // can only happen due to a thread panic in the relayer
            error!("FATAL: unconfirmed tx arc mutex is poisoned: {e:?}");
            panic!();
        });
        txs.clear();
        txs.extend(unconfirmed.mined_txs.clone());
    }

    /// Called by the p2p thread to accept the unconfirmed tx state processed by the relayer.
    /// Puts the shared unconfirmed transactions to chainstate.
    pub fn recv_unconfirmed_txs(&self, chainstate: &mut StacksChainState) {
        let Some(ref mut unconfirmed) = chainstate.unconfirmed_state else {
            return;
        };
        let txs = self.unconfirmed_txs.lock().unwrap_or_else(|e| {
            // can only happen due to a thread panic in the relayer
            error!("FATAL: unconfirmed tx arc mutex is poisoned: {e:?}");
            panic!();
        });
        unconfirmed.mined_txs.clear();
        unconfirmed.mined_txs.extend(txs.clone());
    }

    /// Signal system-wide stop
    #[cfg_attr(test, mutants::skip)]
    pub fn signal_stop(&self) {
        self.should_keep_running.store(false, Ordering::SeqCst);
    }

    /// Should we keep running?
    #[cfg_attr(test, mutants::skip)]
    pub fn keep_running(&self) -> bool {
        self.should_keep_running.load(Ordering::SeqCst)
    }

    /// Get the handle to the coordinator
    pub fn coord(&self) -> &CoordinatorChannels {
        &self.coord_comms
    }

    /// Get the current leader key registration state.
    /// Called from the protocol driver and relayer threads.
    pub fn get_leader_key_registration_state(&self) -> LeaderKeyRegistrationState {
        let key_state = self
            .leader_key_registration_state
            .lock()
            .unwrap_or_else(|e| {
                // can only happen due to a thread panic in the relayer
                error!("FATAL: leader key registration mutex is poisoned: {e:?}");
                panic!();
            });
        key_state.clone()
    }

    /// Set the initial leader key registration state.
    /// Called from the protocol driver while booting.
    pub fn set_initial_leader_key_registration_state(&self, new_state: LeaderKeyRegistrationState) {
        let mut key_state = self
            .leader_key_registration_state
            .lock()
            .unwrap_or_else(|e| {
                // can only happen due to a thread panic in the relayer
                error!("FATAL: leader key registration mutex is poisoned: {e:?}");
                panic!();
            });
        *key_state = new_state;
    }

    /// Advance the leader key registration state to pending, given a txid we just sent.
    /// Only the relayer thread calls this.
    pub fn set_pending_leader_key_registration(&self, target_block_height: u64, txid: Txid) {
        let mut key_state = self
            .leader_key_registration_state
            .lock()
            .unwrap_or_else(|_e| {
                error!("FATAL: failed to lock leader key registration state mutex");
                panic!();
            });
        *key_state = LeaderKeyRegistrationState::Pending(target_block_height, txid);
    }

    /// Advance the leader key registration state to active, given the VRF key registration ops
    /// we've discovered in a given snapshot.
    /// The protocol driver calls this whenever it processes a sortition.
    pub fn try_activate_leader_key_registration(
        &self,
        burn_block_height: u64,
        key_registers: Vec<LeaderKeyRegisterOp>,
    ) -> Option<RegisteredKey> {
        let mut activated_key = None;
        match self.leader_key_registration_state.lock() {
            Ok(ref mut leader_key_registration_state) => {
                for op in key_registers.into_iter() {
                    if let LeaderKeyRegistrationState::Pending(target_block_height, txid) =
                        leader_key_registration_state.clone()
                    {
                        info!(
                            "Received burnchain block #{burn_block_height} including key_register_op - {txid}"
                        );
                        if txid == op.txid {
                            let active_key = RegisteredKey {
                                target_block_height,
                                vrf_public_key: op.public_key,
                                block_height: op.block_height,
                                op_vtxindex: op.vtxindex,
                                memo: op.memo,
                            };

                            **leader_key_registration_state =
                                LeaderKeyRegistrationState::Active(active_key.clone());

                            activated_key = Some(active_key);
                        } else {
                            debug!(
                                "key_register_op {txid} does not match our pending op {}",
                                &op.txid
                            );
                        }
                    }
                }
            }
            Err(_e) => {
                error!("FATAL: failed to lock leader key registration state mutex");
                panic!();
            }
        }
        activated_key
    }

    /// Directly set the leader key activation state from a saved key
    pub fn resume_leader_key(&self, registered_key: RegisteredKey) {
        match self.leader_key_registration_state.lock() {
            Ok(ref mut leader_key_registration_state) => {
                **leader_key_registration_state = LeaderKeyRegistrationState::Active(registered_key)
            }
            Err(_e) => {
                error!("FATAL: failed to lock leader key registration state mutex");
                panic!();
            }
        }
    }

    /// Get the last miner config loaded
    pub fn get_last_miner_config(&self) -> Option<MinerConfig> {
        match self.last_miner_config.lock() {
            Ok(last_miner_config) => (*last_miner_config).clone(),
            Err(_e) => {
                error!("FATAL; failed to lock last miner config");
                panic!();
            }
        }
    }

    /// Set the last miner config loaded
    pub fn set_last_miner_config(&self, miner_config: MinerConfig) {
        match self.last_miner_config.lock() {
            Ok(ref mut last_miner_config) => **last_miner_config = Some(miner_config),
            Err(_e) => {
                error!("FATAL; failed to lock last miner config");
                panic!();
            }
        }
    }

    /// Get the last burnchain config
    pub fn get_last_burnchain_config(&self) -> Option<BurnchainConfig> {
        match self.last_burnchain_config.lock() {
            Ok(last_burnchain_config) => (*last_burnchain_config).clone(),
            Err(_e) => {
                error!("FATAL; failed to lock last burnchain config");
                panic!();
            }
        }
    }

    /// Set the last burnchain config
    pub fn set_last_burnchain_config(&self, burnchain_config: BurnchainConfig) {
        match self.last_burnchain_config.lock() {
            Ok(ref mut last_burnchain_config) => **last_burnchain_config = Some(burnchain_config),
            Err(_e) => {
                error!("FATAL; failed to lock last burnchain config");
                panic!();
            }
        }
    }

    /// Set the last miner spend amount
    pub fn set_last_miner_spend_amount(&self, spend_amount: u64) {
        match self.last_miner_spend_amount.lock() {
            Ok(ref mut last_miner_spend_amount) => **last_miner_spend_amount = Some(spend_amount),
            Err(_e) => {
                error!("FATAL; failed to lock last miner spend amount");
                panic!();
            }
        }
    }

    /// Get the height at which we should start mining
    pub fn get_start_mining_height(&self) -> u64 {
        match self.start_mining_height.lock() {
            Ok(ht) => *ht,
            Err(_e) => {
                error!("FATAL: failed to lock start_mining_height");
                panic!();
            }
        }
    }

    /// Set the height at which we started mining.
    /// Only takes effect if the current start mining height is 0.
    pub fn set_start_mining_height_if_zero(&self, value: u64) {
        match self.start_mining_height.lock() {
            Ok(ref mut ht) => {
                if **ht == 0 {
                    **ht = value;
                }
            }
            Err(_e) => {
                error!("FATAL: failed to lock start_mining_height");
                panic!();
            }
        }
    }

    /// Raise the initiative flag
    pub fn raise_initiative(&self, raiser: String) {
        match self.initiative.lock() {
            Ok(mut initiative) => {
                *initiative = Some(raiser);
            }
            Err(_e) => {
                error!("FATAL: failed to lock initiative");
                panic!();
            }
        }
    }

    /// Clear the initiative flag and return its value
    pub fn take_initiative(&self) -> Option<String> {
        match self.initiative.lock() {
            Ok(mut initiative) => (*initiative).take(),
            Err(_e) => {
                error!("FATAL: failed to lock initiative");
                panic!();
            }
        }
    }
}
