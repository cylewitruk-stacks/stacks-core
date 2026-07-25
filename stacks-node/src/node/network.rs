// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::collections::HashMap;
use std::net::SocketAddr;

use clarity::vm::types::QualifiedContractIdentifier;
use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::core::EpochList;
use stacks::net::atlas::{AtlasConfig, AtlasDB};
use stacks::net::db::{LocalPeer, PeerDB};
use stacks::net::p2p::PeerNetwork;
use stacks::net::relay::Relayer;
use stacks::net::stackerdb::{StackerDBConfig, StackerDBSync, StackerDBs};
use stacks::net::{PeerNetworkComms, ServiceFlags};
use stacks::util_lib::strings::{UrlString, VecDisplay};
use stacks_common::types::net::PeerAddress;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;

use crate::node::chainstate::open_chainstate;
use crate::Config;

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
