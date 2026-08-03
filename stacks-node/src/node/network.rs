// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use clarity::vm::types::QualifiedContractIdentifier;
use stacks::burnchains::bitcoin::indexer::BitcoinIndexer;
use stacks::burnchains::{Burnchain, PoxConstants};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::core::mempool::MemPoolDB;
use stacks::core::EpochList;
use stacks::cost_estimates::metrics::{CostMetric, UnitMetric};
use stacks::cost_estimates::{CostEstimator, FeeEstimator, UnitEstimator};
use stacks::net::atlas::{AtlasConfig, AtlasDB};
use stacks::net::db::{LocalPeer, PeerDB};
use stacks::net::dns::{DNSClient, DNSResolver};
use stacks::net::p2p::PeerNetwork;
use stacks::net::relay::Relayer;
use stacks::net::stackerdb::{StackerDBConfig, StackerDBSync, StackerDBs};
use stacks::net::{NetworkResult, PeerNetworkComms, ServiceFlags};
use stacks::util_lib::strings::{UrlString, VecDisplay};
use stacks_common::types::net::PeerAddress;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;

use crate::burnchains::make_bitcoin_indexer;
use crate::node::chainstate::open_chainstate;
use crate::syncctl::PoxSyncWatchdogComms;
use crate::Config;

/// Changes observed during a pass through the peer network state machines.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerProgressUpdate {
    burn_height_changed: bool,
    inventory_advanced: bool,
    downloader_advanced: bool,
}

impl PeerProgressUpdate {
    pub fn burn_height_changed(self) -> bool {
        self.burn_height_changed
    }

    pub fn inventory_advanced(self) -> bool {
        self.inventory_advanced
    }

    pub fn downloader_advanced(self) -> bool {
        self.downloader_advanced
    }
}

/// Progress shared by the Epoch 2 and Nakamoto peer workers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerProgress {
    p2p_state_machine_passes: u64,
    inventory_sync_passes: u64,
    download_passes: u64,
    burn_height: u64,
}

/// Whether a peer network is being bound for the first time or inherited
/// across the Epoch 2-to-Nakamoto handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerNetworkOrigin {
    /// A newly constructed, necessarily unbound network. Binding is strict so
    /// an ownership violation fails during startup instead of being hidden.
    Fresh,
    /// A network transferred across a protocol handoff which may already own
    /// its configured sockets.
    Inherited,
}

/// Databases and network state owned by a protocol peer worker.
pub struct PeerRuntimeResources {
    network: PeerNetwork,
    sortition_db: SortitionDB,
    chainstate: StacksChainState,
    mempool: MemPoolDB,
    poll_timeout_ms: u64,
}

impl PeerRuntimeResources {
    pub fn open(
        config: &Config,
        pox_constants: PoxConstants,
        mut network: PeerNetwork,
        origin: PeerNetworkOrigin,
    ) -> Self {
        let mempool = config
            .connect_mempool_db()
            .expect("FATAL: database failure opening mempool");
        let sortition_db = SortitionDB::open(
            &config.get_burn_db_file_path(),
            false,
            pox_constants,
            Some(config.node.get_marf_opts()),
        )
        .expect("FATAL: could not open sortition DB");
        let chainstate = open_chainstate(config).expect("FATAL: could not open chainstate DB");

        let p2p_socket: SocketAddr = config
            .node
            .p2p_bind
            .parse()
            .unwrap_or_else(|_| panic!("Failed to parse socket: {}", &config.node.p2p_bind));
        let rpc_socket = config
            .node
            .rpc_bind
            .parse()
            .unwrap_or_else(|_| panic!("Failed to parse socket: {}", &config.node.rpc_bind));

        match origin {
            PeerNetworkOrigin::Fresh => network
                .bind(&p2p_socket, &rpc_socket)
                .expect("BUG: PeerNetwork could not bind or is already bound"),
            PeerNetworkOrigin::Inherited => {
                let did_bind = network
                    .try_bind(&p2p_socket, &rpc_socket)
                    .expect("BUG: PeerNetwork could not bind");
                if !did_bind {
                    info!("`PeerNetwork::bind()` skipped, already bound");
                }
            }
        }

        Self {
            network,
            sortition_db,
            chainstate,
            mempool,
            poll_timeout_ms: config.get_poll_time(),
        }
    }

    pub fn network(&self) -> &PeerNetwork {
        &self.network
    }

    pub fn poll_timeout_ms(&self) -> u64 {
        self.poll_timeout_ms
    }

    pub fn with_chainstate<R>(
        &mut self,
        operation: impl FnOnce(&SortitionDB, &mut StacksChainState, &mut MemPoolDB) -> R,
    ) -> R {
        operation(&self.sortition_db, &mut self.chainstate, &mut self.mempool)
    }

    pub fn with_network_state<R>(
        &mut self,
        operation: impl FnOnce(
            &mut PeerNetwork,
            &SortitionDB,
            &mut StacksChainState,
            &mut MemPoolDB,
        ) -> R,
    ) -> R {
        operation(
            &mut self.network,
            &self.sortition_db,
            &mut self.chainstate,
            &mut self.mempool,
        )
    }

    pub fn into_network(self) -> PeerNetwork {
        self.network
    }
}

/// Run the era-neutral setup and polling lifecycle around a protocol peer pass.
pub fn run_peer_network_loop(
    config: &Config,
    should_keep_running: Arc<AtomicBool>,
    mut run_one_pass: impl FnMut(
        &BitcoinIndexer,
        Option<&mut DNSClient>,
        &dyn CostEstimator,
        &dyn CostMetric,
        Option<&dyn FeeEstimator>,
    ) -> bool,
) {
    let (mut dns_resolver, mut dns_client) = DNSResolver::new(10);
    thread::Builder::new()
        .name("dns-resolver".to_string())
        .spawn(move || {
            debug!("DNS resolver thread ID is {:?}", thread::current().id());
            dns_resolver.thread_main();
        })
        .expect("FATAL: failed to start DNS resolver thread");

    // These services must be instantiated in the peer thread because they
    // cannot safely be transferred from the spawning thread.
    let fee_estimator = config.make_fee_estimator();
    let cost_estimator = config
        .make_cost_estimator()
        .unwrap_or_else(|| Box::new(UnitEstimator));
    let cost_metric = config
        .make_cost_metric()
        .unwrap_or_else(|| Box::new(UnitMetric));
    let indexer = make_bitcoin_indexer(config, Some(should_keep_running.clone()));

    while should_keep_running.load(Ordering::SeqCst)
        && run_one_pass(
            &indexer,
            Some(&mut dns_client),
            cost_estimator.as_ref(),
            cost_metric.as_ref(),
            fee_estimator.as_deref(),
        )
    {}
}

impl PeerProgress {
    /// Record a network result and notify the synchronization watchdog about
    /// newly completed state-machine passes.
    pub fn observe(
        &mut self,
        result: &NetworkResult,
        sync_comms: &mut PoxSyncWatchdogComms,
    ) -> PeerProgressUpdate {
        self.observe_counts(
            result.num_state_machine_passes,
            result.num_inv_sync_passes,
            result.num_download_passes,
            result.burn_height,
            sync_comms,
        )
    }

    fn observe_counts(
        &mut self,
        p2p_state_machine_passes: u64,
        inventory_sync_passes: u64,
        download_passes: u64,
        burn_height: u64,
        sync_comms: &mut PoxSyncWatchdogComms,
    ) -> PeerProgressUpdate {
        let p2p_advanced = self.p2p_state_machine_passes < p2p_state_machine_passes;
        if p2p_advanced {
            sync_comms.notify_p2p_state_pass();
            self.p2p_state_machine_passes = p2p_state_machine_passes;
        }

        let inventory_advanced = self.inventory_sync_passes < inventory_sync_passes;
        if inventory_advanced {
            sync_comms.notify_inv_sync_pass();
            self.inventory_sync_passes = inventory_sync_passes;
        }

        let downloader_advanced = self.download_passes < download_passes;
        if downloader_advanced {
            sync_comms.notify_download_pass();
            self.download_passes = download_passes;
        }

        let burn_height_changed = self.burn_height != burn_height;
        self.burn_height = burn_height;

        PeerProgressUpdate {
            burn_height_changed,
            inventory_advanced,
            downloader_advanced,
        }
    }
}

/// Era-independent network components needed to construct peer and relayer workers.
pub struct NodeNetwork {
    peer_network: PeerNetwork,
    local_peer: LocalPeer,
    relayer: Relayer,
}

impl NodeNetwork {
    pub fn prepare(
        config: &Config,
        burnchain: Burnchain,
        inherited_peer_network: Option<PeerNetwork>,
    ) -> Self {
        let atlas_config = config.atlas.clone();
        let mut peer_network = inherited_peer_network
            .unwrap_or_else(|| PeerNetworkBuilder::new(config, &atlas_config, burnchain).build());
        let stackerdbs = StackerDBs::connect(&config.get_stacker_db_file_path(), true)
            .expect("FATAL: failed to connect to stacker DB");
        let relayer = Relayer::from_p2p(&mut peer_network, stackerdbs);
        let local_peer = peer_network.local_peer.clone();
        Self {
            peer_network,
            local_peer,
            relayer,
        }
    }

    pub fn into_parts(self) -> (PeerNetwork, LocalPeer, Relayer) {
        (self.peer_network, self.local_peer, self.relayer)
    }
}

/// Constructs the era-independent peer network used by Neon and Nakamoto workers.
struct PeerNetworkBuilder<'a> {
    config: &'a Config,
    atlas_config: &'a AtlasConfig,
    burnchain: Burnchain,
}

impl<'a> PeerNetworkBuilder<'a> {
    fn new(config: &'a Config, atlas_config: &'a AtlasConfig, burnchain: Burnchain) -> Self {
        Self {
            config,
            atlas_config,
            burnchain,
        }
    }

    fn build(self) -> PeerNetwork {
        let sortdb = SortitionDB::open(
            &self.config.get_burn_db_file_path(),
            true,
            self.burnchain.pox_constants.clone(),
            Some(self.config.node.get_marf_opts()),
        )
        .expect("Error while instantiating sortition db");

        let epochs = EpochList::new(
            &SortitionDB::get_stacks_epochs(sortdb.conn())
                .expect("Error while loading stacks epochs"),
        );
        let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .expect("Failed to get sortition tip");
        let view =
            SortitionDB::get_burnchain_view(&sortdb.index_conn(), &self.burnchain, &sortition_tip)
                .unwrap();

        let atlasdb = AtlasDB::connect(
            self.atlas_config.clone(),
            &self.config.get_atlas_db_file_path(),
            true,
        )
        .unwrap();
        let mut chainstate =
            open_chainstate(self.config).expect("FATAL: could not open chainstate DB");
        let mut stackerdbs =
            StackerDBs::connect(&self.config.get_stacker_db_file_path(), true).unwrap();

        let requested_stackerdbs = self
            .config
            .node
            .stacker_dbs
            .iter()
            .cloned()
            .map(|contract| (contract, StackerDBConfig::noop()))
            .collect();
        let stackerdb_configs = stackerdbs
            .create_or_reconfigure_stackerdbs(
                &mut chainstate,
                &sortdb,
                requested_stackerdbs,
                &self.config.connection_options,
            )
            .unwrap();

        let stackerdb_contract_ids: Vec<QualifiedContractIdentifier> =
            stackerdb_configs.keys().cloned().collect();
        let mut stackerdb_machines = HashMap::new();
        for (contract_id, stackerdb_config) in stackerdb_configs {
            let stackerdbs =
                StackerDBs::connect(&self.config.get_stacker_db_file_path(), true).unwrap();
            let stacker_db_sync = StackerDBSync::new(
                contract_id.clone(),
                &stackerdb_config,
                PeerNetworkComms::new(),
                stackerdbs,
            );
            stackerdb_machines.insert(contract_id, (stackerdb_config, stacker_db_sync));
        }

        let peerdb = Self::build_peer_db(self.config, &self.burnchain, &stackerdb_contract_ids);
        let burnchain_db = self
            .burnchain
            .open_burnchain_db(false)
            .expect("Failed to open burnchain DB");
        let local_peer = PeerDB::get_local_peer(peerdb.conn())
            .unwrap_or_else(|_| panic!("Unable to retrieve local peer"));

        PeerNetwork::new(
            peerdb,
            atlasdb,
            stackerdbs,
            burnchain_db,
            local_peer,
            self.config.burnchain.peer_version,
            self.burnchain,
            view,
            self.config.connection_options.clone(),
            stackerdb_machines,
            epochs,
        )
    }

    fn build_peer_db(
        config: &Config,
        burnchain: &Burnchain,
        stackerdb_contract_ids: &[QualifiedContractIdentifier],
    ) -> PeerDB {
        let data_url = UrlString::try_from(config.node.data_url.to_string()).unwrap();
        let initial_neighbors = config.node.bootstrap_node.clone();
        if initial_neighbors.is_empty() {
            warn!("Without a peer to bootstrap from, the node will start mining a new chain");
        } else {
            info!(
                "Will bootstrap from peers {}",
                VecDisplay(&initial_neighbors)
            );
        }

        let p2p_sock: SocketAddr = config
            .node
            .p2p_bind
            .parse()
            .unwrap_or_else(|_| panic!("Failed to parse socket: {}", &config.node.p2p_bind));
        let p2p_addr: SocketAddr = config
            .node
            .p2p_address
            .parse()
            .unwrap_or_else(|_| panic!("Failed to parse socket: {}", &config.node.p2p_address));
        let node_privkey = Secp256k1PrivateKey::from_seed(&config.node.local_peer_seed);

        let mut peerdb = PeerDB::connect(
            &config.get_peer_db_file_path(),
            true,
            config.burnchain.chain_id,
            burnchain.network_id,
            Some(node_privkey),
            config.connection_options.private_key_lifetime,
            PeerAddress::from_socketaddr(&p2p_addr),
            p2p_sock.port(),
            data_url,
            &[],
            Some(&initial_neighbors),
            stackerdb_contract_ids,
        )
        .map_err(|error| {
            eprintln!(
                "Failed to open {}: {error:?}",
                &config.get_peer_db_file_path()
            );
            panic!();
        })
        .unwrap();

        {
            let tx = peerdb.tx_begin().unwrap();
            for initial_neighbor in &initial_neighbors {
                PeerDB::update_peer(&tx, initial_neighbor).unwrap();
                PeerDB::set_allow_peer(
                    &tx,
                    initial_neighbor.addr.network_id,
                    &initial_neighbor.addr.addrbytes,
                    initial_neighbor.addr.port,
                    -1,
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }

        if !config.node.deny_nodes.is_empty() {
            warn!("Will ignore nodes {:?}", &config.node.deny_nodes);
        }
        {
            let tx = peerdb.tx_begin().unwrap();
            for denied in &config.node.deny_nodes {
                PeerDB::set_deny_peer(
                    &tx,
                    denied.addr.network_id,
                    &denied.addr.addrbytes,
                    denied.addr.port,
                    get_epoch_time_secs() + 24 * 365 * 3600,
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        {
            let tx = peerdb.tx_begin().unwrap();
            PeerDB::set_local_services(
                &tx,
                (ServiceFlags::RPC as u16)
                    | (ServiceFlags::RELAY as u16)
                    | (ServiceFlags::STACKERDB as u16),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        peerdb
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use super::PeerProgress;
    use crate::syncctl::PoxSyncWatchdogComms;

    fn sync_comms() -> PoxSyncWatchdogComms {
        PoxSyncWatchdogComms::new(Arc::new(AtomicBool::new(true)))
    }

    #[test]
    fn peer_progress_notifies_each_new_pass_once() {
        let mut progress = PeerProgress::default();
        let mut sync_comms = sync_comms();

        let update = progress.observe_counts(1, 2, 3, 100, &mut sync_comms);
        assert!(update.inventory_advanced());
        assert!(update.downloader_advanced());
        assert!(update.burn_height_changed());
        assert_eq!(sync_comms.get_p2p_state_passes(), 1);
        assert_eq!(sync_comms.get_inv_sync_passes(), 1);
        assert_eq!(sync_comms.get_download_passes(), 1);

        let update = progress.observe_counts(1, 2, 3, 100, &mut sync_comms);
        assert!(!update.inventory_advanced());
        assert!(!update.downloader_advanced());
        assert!(!update.burn_height_changed());
        assert_eq!(sync_comms.get_p2p_state_passes(), 1);
        assert_eq!(sync_comms.get_inv_sync_passes(), 1);
        assert_eq!(sync_comms.get_download_passes(), 1);
    }

    #[test]
    fn peer_progress_reports_independent_edges() {
        let mut progress = PeerProgress::default();
        let mut sync_comms = sync_comms();
        progress.observe_counts(1, 1, 1, 100, &mut sync_comms);

        let inventory = progress.observe_counts(1, 2, 1, 100, &mut sync_comms);
        assert!(inventory.inventory_advanced());
        assert!(!inventory.downloader_advanced());
        assert!(!inventory.burn_height_changed());

        let downloader = progress.observe_counts(1, 2, 2, 100, &mut sync_comms);
        assert!(!downloader.inventory_advanced());
        assert!(downloader.downloader_advanced());
        assert!(!downloader.burn_height_changed());

        let burn_height = progress.observe_counts(1, 2, 2, 101, &mut sync_comms);
        assert!(!burn_height.inventory_advanced());
        assert!(!burn_height.downloader_advanced());
        assert!(burn_height.burn_height_changed());
    }
}
