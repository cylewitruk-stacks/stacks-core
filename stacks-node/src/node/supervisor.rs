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
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use std::{fs, thread};

use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::config::BurnchainConfig;
use stacks::net::p2p::PeerNetwork;
use stacks_common::types::StacksEpochId;

use crate::node::leader_key::LeaderKeyRegistrationState;
use crate::node::protocol::epoch2::driver::{Driver as Epoch2Driver, Epoch2Shutdown};
use crate::node::protocol::nakamoto::driver::Driver as NakamotoDriver;
#[cfg(test)]
use crate::node::runtime::Counters;
use crate::node::runtime::RuntimeContinuity;
use crate::Config;

/// Selects the runtime architecture independently of a mode's network and burnchain profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimePlan {
    /// The deterministic local simulator used by the historical Helium and Mocknet modes.
    LegacySimulator,
    /// The production-style runtime that follows configured epochs from Neon into Nakamoto.
    EpochAware,
}

impl RuntimePlan {
    pub fn for_mode(mode: &str) -> Result<Self, String> {
        // Keep the executable's historical behavior: Argon is accepted by the shared config
        // parser for library/test consumers, but has never selected a stacks-node run loop.
        if mode == "argon" || !BurnchainConfig::SUPPORTED_MODES.contains(&mode) {
            return Err(format!("Burnchain mode '{mode}' not supported"));
        }

        match mode {
            "helium" | "mocknet" => Ok(Self::LegacySimulator),
            _ => Ok(Self::EpochAware),
        }
    }
}

/// Runtime and protocol resources transferred atomically from Epoch 2 to Nakamoto.
struct Epoch2Handoff {
    continuity: RuntimeContinuity,
    leader_key_registration_state: LeaderKeyRegistrationState,
    peer_network: Option<PeerNetwork>,
}

impl Epoch2Handoff {
    fn from_epoch2(epoch2: &mut Epoch2Driver, shutdown: Option<Epoch2Shutdown>) -> Self {
        let continuity = epoch2.take_runtime_continuity();
        // Epoch 2 stops by clearing this shared switch; reactivate it before constructing Nakamoto.
        continuity.reactivate();
        let (leader_key_registration_state, peer_network) =
            shutdown.unwrap_or_default().into_parts();

        Self {
            continuity,
            leader_key_registration_state,
            peer_network,
        }
    }
}

/// Supervises the one-way transition from the Epoch 2 protocol driver to Nakamoto.
pub struct NodeRunner {
    config: Config,
    active_protocol: ActiveProtocol,
    coordinator_channels: Arc<Mutex<CoordinatorChannels>>,
}

enum ActiveProtocol {
    Epoch2(Epoch2Driver),
    Nakamoto(NakamotoDriver),
}

enum ProtocolExit {
    Shutdown,
    Transition(Epoch2Handoff),
}

impl NodeRunner {
    pub fn new(config: Config) -> Result<Self, String> {
        let (coordinator_channels, active_protocol) =
            if !Self::reached_epoch_30_transition(&config)? {
                let epoch2 = Epoch2Driver::new(config.clone());
                (
                    epoch2.get_coordinator_channel().unwrap(),
                    ActiveProtocol::Epoch2(epoch2),
                )
            } else {
                let nakamoto = NakamotoDriver::fresh(config.clone());
                (
                    nakamoto.get_coordinator_channel().unwrap(),
                    ActiveProtocol::Nakamoto(nakamoto),
                )
            };

        Ok(Self {
            config,
            active_protocol,
            coordinator_channels: Arc::new(Mutex::new(coordinator_channels)),
        })
    }

    /// Gets the coordinator channels through the stable supervisor handle.
    ///
    /// The mutex permits the Epoch 2-to-Nakamoto transition to replace the backing channels while
    /// existing observers retain the same `Arc`.
    #[cfg(test)]
    pub fn coordinator_channels(&self) -> Arc<Mutex<CoordinatorChannels>> {
        self.coordinator_channels.clone()
    }

    /// Gets the counters shared by the active protocol driver.
    ///
    /// Nakamoto inherits the same counter object from Epoch 2, so no additional indirection is
    /// needed.
    #[cfg(test)]
    pub fn counters(&self) -> Counters {
        match &self.active_protocol {
            ActiveProtocol::Epoch2(driver) => driver.get_counters(),
            ActiveProtocol::Nakamoto(driver) => driver.get_counters(),
        }
    }

    /// Gets the termination switch from the active protocol driver.
    #[cfg(test)]
    pub fn get_termination_switch(&self) -> Arc<AtomicBool> {
        match &self.active_protocol {
            ActiveProtocol::Epoch2(driver) => driver.get_termination_switch(),
            ActiveProtocol::Nakamoto(driver) => driver.get_termination_switch(),
        }
    }

    /// Starts the protocol appropriate for the current burnchain height and supervises the
    /// one-way transition from Epoch 2 to Nakamoto.
    pub fn start(&mut self, burnchain_opt: Option<Burnchain>, mine_start: u64) {
        match self.active_protocol {
            ActiveProtocol::Epoch2(_) => {
                let exit = self.run_epoch2(burnchain_opt.clone(), mine_start);
                if let ProtocolExit::Transition(handoff) = exit {
                    self.transition_to_nakamoto(burnchain_opt, mine_start, handoff);
                }
            }
            ActiveProtocol::Nakamoto(_) => {
                self.run_nakamoto(burnchain_opt, mine_start);
            }
        }
    }

    fn run_nakamoto(&mut self, burnchain_opt: Option<Burnchain>, mine_start: u64) {
        let ActiveProtocol::Nakamoto(ref mut driver) = self.active_protocol else {
            panic!("FATAL: attempted to run Nakamoto while Epoch 2 was active");
        };
        driver.start(burnchain_opt, mine_start)
    }

    // configuring mutants::skip -- this function is covered through integration tests (this function
    //  is pretty definitionally an integration, so thats unavoidable), and the integration tests
    //  do not get counted in mutants coverage.
    #[cfg_attr(test, mutants::skip)]
    fn run_epoch2(&mut self, burnchain_opt: Option<Burnchain>, mine_start: u64) -> ProtocolExit {
        let ActiveProtocol::Epoch2(ref mut driver) = self.active_protocol else {
            panic!("FATAL: attempted to run Epoch 2 while Nakamoto was active");
        };
        let transition_monitor = Self::spawn_transition_monitor(&self.config, driver)
            .expect("FATAL: failed to spawn epoch-2/3-boot thread");
        let shutdown = driver.start(burnchain_opt, mine_start);

        // did we exit because of the epoch-3.0 transition, or some other reason?
        let exited_for_transition = transition_monitor
            .join()
            .expect("FATAL: failed to join epoch-2/3-boot thread");
        if !exited_for_transition {
            info!("Shutting down epoch-2/3 transition thread");
            return ProtocolExit::Shutdown;
        }

        let with_epoch2_data = shutdown.is_some();
        let handoff = Epoch2Handoff::from_epoch2(driver, shutdown);
        info!(
            "Reached Epoch-3.0 boundary, starting nakamoto node";
            "with_epoch2_data" => with_epoch2_data,
            "with_p2p_stack" => handoff.peer_network.is_some()
        );

        ProtocolExit::Transition(handoff)
    }

    fn transition_to_nakamoto(
        &mut self,
        burnchain_opt: Option<Burnchain>,
        mine_start: u64,
        handoff: Epoch2Handoff,
    ) {
        let Epoch2Handoff {
            continuity,
            leader_key_registration_state,
            peer_network,
        } = handoff;
        let nakamoto = NakamotoDriver::inherited(
            self.config.clone(),
            continuity,
            leader_key_registration_state,
            peer_network,
        );
        let new_coord_channels = nakamoto
            .get_coordinator_channel()
            .expect("FATAL: newly instantiated Nakamoto driver should have coordinator channels");
        {
            let mut coord_channel = self.coordinator_channels.lock().expect("Mutex poisoned");
            *coord_channel = new_coord_channels;
        }
        self.active_protocol = ActiveProtocol::Nakamoto(nakamoto);
        self.run_nakamoto(burnchain_opt, mine_start);
    }

    fn spawn_transition_monitor(
        config: &Config,
        epoch2: &Epoch2Driver,
    ) -> Result<JoinHandle<bool>, std::io::Error> {
        let epoch2_term_switch = epoch2.get_termination_switch();
        let config = config.clone();
        thread::Builder::new()
            .name("epoch-2/3-boot".into())
            .spawn(move || {
                loop {
                    let do_transition = Self::reached_epoch_30_transition(&config)
                        .unwrap_or_else(|err| {
                            warn!("Error checking for Epoch-3.0 transition: {err:?}. Assuming transition did not occur yet.");
                            false
                        });
                    if do_transition {
                        break;
                    }
                    if !epoch2_term_switch.load(Ordering::SeqCst) {
                        info!("Stop requested, exiting epoch-2/3-boot thread");
                        return false;
                    }
                    thread::sleep(Duration::from_secs(1));
                }
                // if loop exited, do the transition
                info!("Epoch-3.0 boundary reached, stopping Epoch 2 driver");
                epoch2_term_switch.store(false, Ordering::SeqCst);
                true
            })
    }

    fn reached_epoch_30_transition(config: &Config) -> Result<bool, String> {
        let burn_height = Self::get_burn_height(config);
        let epochs = config.burnchain.get_epoch_list();
        let epoch_3 = epochs
            .get(StacksEpochId::Epoch30)
            .ok_or("No Epoch-3.0 defined")?;

        Ok(u64::from(burn_height) >= epoch_3.start_height - 1)
    }

    fn get_burn_height(config: &Config) -> u32 {
        let burnchain = config.get_burnchain();
        let sortdb_path = config.get_burn_db_file_path();
        if fs::metadata(&sortdb_path).is_err() {
            // if the sortition db doesn't exist yet, don't try to open() it, because that creates the
            // db file even if it doesn't instantiate the tables, which breaks connect() logic.
            info!(
                "Failed to open Sortition DB while checking current burn height, assuming height = 0"
            );
            return 0;
        }

        let Ok(sortdb) = SortitionDB::open(
            &sortdb_path,
            false,
            burnchain.pox_constants,
            Some(config.node.get_marf_opts()),
        ) else {
            info!(
                "Failed to open Sortition DB while checking current burn height, assuming height = 0"
            );
            return 0;
        };

        let Ok(tip_sn) = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()) else {
            info!("Failed to query Sortition DB for current burn height, assuming height = 0");
            return 0;
        };

        u32::try_from(tip_sn.block_height).expect("FATAL: burn height exceeded u32")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::{Epoch2Driver, Epoch2Handoff, RuntimePlan};
    use crate::Config;

    #[test]
    fn epoch2_handoff_reactivates_shared_runtime() {
        let mut epoch2 = Epoch2Driver::new(Config::default());
        let termination_switch = epoch2.get_termination_switch();
        termination_switch.store(false, Ordering::SeqCst);

        let _handoff = Epoch2Handoff::from_epoch2(&mut epoch2, None);

        assert!(termination_switch.load(Ordering::SeqCst));
    }

    #[test]
    fn runtime_plan_is_independent_of_network_profile() {
        for mode in ["helium", "mocknet"] {
            assert_eq!(
                RuntimePlan::for_mode(mode),
                Ok(RuntimePlan::LegacySimulator)
            );
        }

        for mode in ["neon", "krypton", "xenon", "mainnet", "nakamoto-neon"] {
            assert_eq!(RuntimePlan::for_mode(mode), Ok(RuntimePlan::EpochAware));
        }

        assert!(RuntimePlan::for_mode("argon").is_err());
        assert!(RuntimePlan::for_mode("unknown").is_err());
    }
}
