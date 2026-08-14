use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

use crate::{NetworkDiagnostics, NetworkHandle, NetworkService, ServiceConfig, TransportProfile};

static NEXT_MEMORY_ADDRESS: AtomicU64 = AtomicU64::new(1_000_000);

fn next_memory_address() -> Multiaddr {
    format!(
        "/memory/{}",
        NEXT_MEMORY_ADDRESS.fetch_add(1, Ordering::Relaxed)
    )
    .parse()
    .expect("generated memory address is valid")
}

/// One real continuously-polled swarm in a [`Libp2pTestNetwork`].
pub struct TestNetworkPeer {
    name: String,
    config: ServiceConfig,
    handle: NetworkHandle,
    service: Option<NetworkService>,
}

impl TestNetworkPeer {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn peer_id(&self) -> PeerId {
        self.config.identity.public().to_peer_id()
    }

    pub fn address(&self) -> Multiaddr {
        let mut address = self
            .config
            .listen_addresses
            .first()
            .expect("test peer has a listen address")
            .clone();
        address.push(Protocol::P2p(self.peer_id()));
        address
    }

    pub fn handle(&self) -> NetworkHandle {
        self.handle.clone()
    }

    pub fn diagnostics(&self) -> NetworkDiagnostics {
        self.handle.diagnostics()
    }

    fn restart(&mut self) -> io::Result<()> {
        if let Some(service) = self.service.take() {
            service
                .shutdown()
                .map_err(|_| io::Error::other("test swarm thread panicked"))?;
        }
        // A dropped MemoryTransport listener can remain registered until its
        // executor finishes cleanup. Preserve identity but allocate a fresh,
        // collision-free carrier address for deterministic restart tests.
        self.config.listen_addresses = vec![next_memory_address()];
        let service = NetworkService::spawn(self.config.clone(), format!("test-{}", self.name))?;
        self.handle = service.handle();
        self.service = Some(service);
        Ok(())
    }

    fn shutdown(&mut self) {
        if let Some(service) = self.service.take() {
            let _ = service.shutdown();
        }
    }
}

/// Event-driven topology harness backed by real libp2p swarms over memory
/// transport. Application tests interact only through production handles and
/// diagnostics; no mock behavior or socket is substituted.
#[derive(Default)]
pub struct Libp2pTestNetwork {
    peers: BTreeMap<String, TestNetworkPeer>,
}

impl Libp2pTestNetwork {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_peer(
        &mut self,
        name: impl Into<String>,
        mut config: ServiceConfig,
    ) -> io::Result<()> {
        let name = name.into();
        if self.peers.contains_key(&name) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("test peer {name:?} already exists"),
            ));
        }
        config.transport = TransportProfile::Memory;
        if config.listen_addresses.is_empty() {
            config.listen_addresses.push(next_memory_address());
        }
        let service = NetworkService::spawn(config.clone(), format!("test-{name}"))?;
        let handle = service.handle();
        self.peers.insert(
            name.clone(),
            TestNetworkPeer {
                name,
                config,
                handle,
                service: Some(service),
            },
        );
        Ok(())
    }

    pub fn peer(&self, name: &str) -> &TestNetworkPeer {
        self.peers
            .get(name)
            .unwrap_or_else(|| panic!("unknown test peer {name:?}"))
    }

    pub fn connect(&self, dialer: &str, listener: &str) -> io::Result<()> {
        self.peer(dialer).handle.dial(self.peer(listener).address())
    }

    pub fn disconnect(&self, left: &str, right: &str) -> io::Result<()> {
        let left_id = self.peer(left).peer_id();
        let right_id = self.peer(right).peer_id();
        self.peer(left).handle.disconnect(right_id)?;
        self.peer(right).handle.disconnect(left_id)
    }

    /// Drop every link currently visible to one peer. This is deterministic at
    /// the application level and avoids transport sleeps in partition tests.
    pub fn isolate(&self, name: &str) -> io::Result<()> {
        let peer_id = self.peer(name).peer_id();
        let others = self
            .peers
            .iter()
            .filter(|(other, _)| other.as_str() != name)
            .map(|(_, peer)| (peer.peer_id(), peer.handle()))
            .collect::<Vec<_>>();
        for (other_id, other_handle) in others {
            let _ = self.peer(name).handle.disconnect(other_id);
            let _ = other_handle.disconnect(peer_id);
        }
        Ok(())
    }

    pub fn restart(&mut self, name: &str) -> io::Result<()> {
        self.peers
            .get_mut(name)
            .unwrap_or_else(|| panic!("unknown test peer {name:?}"))
            .restart()
    }

    /// Poll a semantic condition until it succeeds. The timeout is only a
    /// deadlock guard; failures include a complete bounded topology dump.
    pub fn wait_for(
        &self,
        timeout: Duration,
        mut predicate: impl FnMut(&Self) -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if predicate(self) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("test network timed out\n{}", self.dump()));
            }
            std::thread::yield_now();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn wait_connected(&self, left: &str, right: &str, timeout: Duration) -> Result<(), String> {
        let left_id = self.peer(left).peer_id().to_string();
        let right_id = self.peer(right).peer_id().to_string();
        self.wait_for(timeout, |network| {
            network
                .peer(left)
                .diagnostics()
                .connected_peers
                .contains(&right_id)
                && network
                    .peer(right)
                    .diagnostics()
                    .connected_peers
                    .contains(&left_id)
                && network.peer(left).diagnostics().successful_hellos > 0
                && network.peer(right).diagnostics().successful_hellos > 0
        })
    }

    pub fn dump(&self) -> String {
        self.peers
            .iter()
            .map(|(name, peer)| format!("{name}: {:?}", peer.diagnostics()))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn shutdown(mut self) {
        for peer in self.peers.values_mut() {
            peer.shutdown();
        }
    }
}

impl Drop for Libp2pTestNetwork {
    fn drop(&mut self) {
        for peer in self.peers.values_mut() {
            peer.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use stacks_network_types::wire::v1::Hello;

    use super::*;
    use crate::{
        node_identity_from_seed, NetworkConfig, PeerStoreConfig, PeerStorePolicy,
        DEFAULT_OBJECT_CACHE_BYTES,
    };

    fn config(seed: &[u8], chain_id: u32) -> ServiceConfig {
        let mut network = NetworkConfig::signer_profile(
            stacks_network_types::NetworkScope::new(chain_id, chain_id),
            "stacks-network-harness".to_owned(),
            &stacks_network_types::Libp2pLimits::default(),
        )
        .unwrap();
        network.max_process_memory_bytes = usize::MAX;
        ServiceConfig {
            identity: node_identity_from_seed(seed, network.scope()).unwrap(),
            network,
            transport: TransportProfile::Memory,
            listen_addresses: Vec::new(),
            bootstrap_addresses: Vec::new(),
            peer_store: None,
            private_rendezvous_peers: Vec::new(),
            role_authorizations: Vec::new(),
            local_role_record: None,
            initial_role_records: Vec::new(),
            initial_signer_envelopes: Vec::new(),
            object_validator: None,
            object_cache_bytes: DEFAULT_OBJECT_CACHE_BYTES,
            hello: Hello {
                envelope_version: 1,
                chain_id,
                network_id: chain_id,
                supported_protocol_versions: vec![1],
                peer_version: 1,
                capabilities: stacks_network_types::CAP_SIGNER_V1,
                burn_tip_height: 0,
                burn_tip_hash: Vec::new(),
                stable_burn_tip_height: 0,
                stable_burn_tip_hash: Vec::new(),
                stacks_tip_height: 0,
                stacks_tip_id: Vec::new(),
                current_reward_cycle: 0,
                advertised_multiaddrs: Vec::new(),
                legacy_identity_binding: None,
                challenge: Vec::new(),
            },
        }
    }

    #[test]
    fn topology_disconnect_reconnect_restart_and_wrong_chain() {
        let mut network = Libp2pTestNetwork::new();
        network
            .add_peer("alice", config(b"alice-harness", 1))
            .unwrap();
        network.add_peer("bob", config(b"bob-harness", 1)).unwrap();
        network
            .add_peer("carol", config(b"carol-harness", 1))
            .unwrap();
        network
            .add_peer("mallory", config(b"mallory-harness", 2))
            .unwrap();

        network.connect("alice", "bob").unwrap();
        network.connect("bob", "carol").unwrap();
        network
            .wait_connected("alice", "bob", Duration::from_secs(10))
            .unwrap();
        network
            .wait_connected("bob", "carol", Duration::from_secs(10))
            .unwrap();

        network.disconnect("bob", "carol").unwrap();
        let carol_id = network.peer("carol").peer_id().to_string();
        network
            .wait_for(Duration::from_secs(10), |network| {
                // Discovery may already have queued a redial. Hold the cut
                // until both close events are observable, then reconnect
                // explicitly below.
                network.disconnect("bob", "carol").unwrap();
                !network
                    .peer("bob")
                    .diagnostics()
                    .connected_peers
                    .contains(&carol_id)
            })
            .unwrap();
        network.connect("carol", "bob").unwrap();
        network
            .wait_connected("bob", "carol", Duration::from_secs(10))
            .unwrap();

        let carol_peer_id = network.peer("carol").peer_id();
        network.restart("carol").unwrap();
        assert_eq!(network.peer("carol").peer_id(), carol_peer_id);
        network.connect("bob", "carol").unwrap();
        network
            .wait_connected("bob", "carol", Duration::from_secs(10))
            .unwrap();

        network.connect("alice", "mallory").unwrap();
        network
            .wait_for(Duration::from_secs(10), |network| {
                network.peer("alice").diagnostics().rejected_hellos > 0
                    || network.peer("mallory").diagnostics().rejected_hellos > 0
            })
            .unwrap();
    }

    #[test]
    fn persistent_peer_store_redials_after_restart_and_reauthenticates_over_noise() {
        let temp = TempDir::new().unwrap();
        let mut network = Libp2pTestNetwork::new();
        network
            .add_peer("alice", config(b"alice-store", 91))
            .unwrap();
        let mut bob = config(b"bob-store", 91);
        bob.peer_store = Some(PeerStoreConfig {
            path: temp.path().join("peers.sqlite"),
            chain_id: bob.network.chain_id,
            network_id: bob.network.network_id,
            local_peer_id: bob.identity.public().to_peer_id(),
            policy: PeerStorePolicy {
                max_peers: 8,
                max_addresses_per_peer: 2,
                entry_ttl_secs: 600,
                startup_dial_count: 1,
                write_queue_capacity: 8,
            },
        });
        network.add_peer("bob", bob).unwrap();
        network.connect("bob", "alice").unwrap();
        network
            .wait_connected("alice", "bob", Duration::from_secs(10))
            .unwrap();
        network
            .wait_for(Duration::from_secs(10), |network| {
                let diagnostics = network.peer("bob").diagnostics();
                diagnostics.peer_store_writes >= 1
                    && diagnostics.peer_store_peers == 1
                    && diagnostics.peer_store_addresses == 1
            })
            .unwrap();

        network.restart("bob").unwrap();
        network
            .wait_for(Duration::from_secs(10), |network| {
                let diagnostics = network.peer("bob").diagnostics();
                diagnostics.peer_store_restored == 1
                    && diagnostics.successful_hellos >= 1
                    && diagnostics
                        .connected_peers
                        .contains(&network.peer("alice").peer_id().to_string())
            })
            .unwrap();
        assert_eq!(network.peer("bob").diagnostics().rejected_hellos, 0);
        network.shutdown();
    }

    #[test]
    fn ring_late_join_partition_rejoin_and_simultaneous_dial_are_event_driven() {
        let mut network = Libp2pTestNetwork::new();
        for (name, seed) in [
            ("alice", b"ring-alice".as_slice()),
            ("bob", b"ring-bob".as_slice()),
            ("carol", b"ring-carol".as_slice()),
        ] {
            network.add_peer(name, config(seed, 7)).unwrap();
        }

        // Simultaneous open may create multiple transport connections, but the
        // application topology and Hello admission remain a single peer.
        network.connect("alice", "bob").unwrap();
        network.connect("bob", "alice").unwrap();
        network.connect("bob", "carol").unwrap();
        network.connect("carol", "alice").unwrap();
        for (left, right) in [("alice", "bob"), ("bob", "carol"), ("carol", "alice")] {
            network
                .wait_connected(left, right, Duration::from_secs(10))
                .unwrap();
        }
        let bob_id = network.peer("bob").peer_id().to_string();
        assert_eq!(
            network
                .peer("alice")
                .diagnostics()
                .connected_peers
                .iter()
                .filter(|peer| *peer == &bob_id)
                .count(),
            1
        );

        network.isolate("bob").unwrap();
        network
            .wait_for(Duration::from_secs(10), |network| {
                // Discovery is intentionally live in this production-backed
                // harness, so maintain the synthetic partition until every
                // connection-close event has been observed. A one-shot
                // disconnect can otherwise race a Kademlia redial learned
                // before the cut.
                network.isolate("bob").unwrap();
                network.peer("bob").diagnostics().connected_peers.is_empty()
            })
            .unwrap();
        network.connect("bob", "carol").unwrap();
        network
            .wait_connected("bob", "carol", Duration::from_secs(10))
            .unwrap();

        network.add_peer("dave", config(b"ring-dave", 7)).unwrap();
        network.connect("dave", "alice").unwrap();
        network
            .wait_connected("dave", "alice", Duration::from_secs(10))
            .unwrap();
        assert!(network
            .peer("dave")
            .diagnostics()
            .recent_events
            .iter()
            .any(|event| event.kind == "hello-authenticated"));
    }
}
