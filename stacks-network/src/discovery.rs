// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Discovery policy and its stock libp2p protocol engines.
//!
//! Identify, Kademlia, and AutoNAT are private children. The public behaviour
//! owns address admission, Hello-gated routing-table insertion, bootstrap
//! retry/liveness state, and AutoNAT-driven client/server mode transitions.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use futures_timer::Delay;
use libp2p::autonat;
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::identify;
use libp2p::kad::{self, store::MemoryStore, Mode};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{
    CloseConnection, ConnectionDenied, ConnectionId, DialError, FromSwarm, NetworkBehaviour,
    StreamProtocol, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{identity, Multiaddr, PeerId};

use crate::{NetworkConfig, PeerEndpoint};

const DISCOVERY_TICK: Duration = Duration::from_secs(1);
const DISCOVERY_QUERY_INTERVAL: Duration = Duration::from_secs(60);
const AUTONAT_CONFIRMATION_TTL: Duration = Duration::from_secs(10 * 60);
const BOOTSTRAP_LIVENESS_TIMEOUT: Duration = Duration::from_secs(75);
const BOOTSTRAP_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const BOOTSTRAP_MAX_BACKOFF: Duration = Duration::from_secs(60);
const BOOTSTRAP_EXHAUSTED_AFTER: u32 = 8;
const MAX_IDENTIFY_ADDRESSES: usize = 16;
const MAX_IDENTIFY_ADDRESS_BYTES: usize = 256;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "DiscoveryProtocolsEvent")]
#[doc(hidden)]
pub struct DiscoveryProtocols {
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
    autonat_client: autonat::v2::client::Behaviour,
    autonat_server: autonat::v2::server::Behaviour,
}

#[derive(Debug)]
#[doc(hidden)]
#[allow(clippy::large_enum_variant)]
pub enum DiscoveryProtocolsEvent {
    Identify(identify::Event),
    Kademlia(kad::Event),
    AutonatClient(autonat::v2::client::Event),
    AutonatServer(autonat::v2::server::Event),
}

impl From<identify::Event> for DiscoveryProtocolsEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<kad::Event> for DiscoveryProtocolsEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kademlia(event)
    }
}

impl From<autonat::v2::client::Event> for DiscoveryProtocolsEvent {
    fn from(event: autonat::v2::client::Event) -> Self {
        Self::AutonatClient(event)
    }
}

impl From<autonat::v2::server::Event> for DiscoveryProtocolsEvent {
    fn from(event: autonat::v2::server::Event) -> Self {
        Self::AutonatServer(event)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryEvent {
    PeerAddressesChanged {
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        usable: bool,
    },
    BootstrapAttempt {
        peer: PeerId,
        attempt: u32,
    },
    BootstrapFailed {
        peer: PeerId,
        attempt: u32,
        next_delay: Duration,
        error: String,
    },
    BootstrapExhausted {
        peer: PeerId,
        attempts: u32,
    },
    BootstrapStale {
        peer: PeerId,
    },
    RestoredDialFailed {
        peer: PeerId,
        address: Multiaddr,
        error: String,
    },
    KademliaQueryStarted,
    ReachabilityProbe {
        address: Multiaddr,
        server: PeerId,
        reachable: bool,
        error: Option<String>,
    },
    ServingModeChanged {
        server: bool,
    },
}

#[derive(Clone, Debug)]
struct BootstrapTarget {
    address: Multiaddr,
    connected: bool,
    closing_stale: bool,
    last_alive: Option<Instant>,
    next_attempt: Instant,
    attempts: u32,
    exhausted_reported: bool,
}

impl BootstrapTarget {
    fn new(address: Multiaddr, now: Instant) -> Self {
        Self {
            address,
            connected: false,
            closing_stale: false,
            last_alive: None,
            next_attempt: now,
            attempts: 0,
            exhausted_reported: false,
        }
    }

    fn backoff(&self) -> Duration {
        let shift = self.attempts.saturating_sub(1).min(6);
        BOOTSTRAP_INITIAL_BACKOFF
            .saturating_mul(1_u32 << shift)
            .min(BOOTSTRAP_MAX_BACKOFF)
    }
}

#[derive(Debug)]
enum DiscoveryAction {
    Dial {
        peer: PeerId,
        address: Multiaddr,
        purpose: DialPurpose,
    },
    Close {
        peer: PeerId,
    },
    Event(DiscoveryEvent),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DialPurpose {
    Bootstrap,
    Restored,
}

#[derive(Debug)]
struct PendingDial {
    peer: PeerId,
    address: Multiaddr,
    purpose: DialPurpose,
}

/// Owns the only path from session-authenticated Identify observations into
/// Kademlia. Durable peer-store endpoints intentionally never enter this
/// component: they are dial hints, not current-session identity evidence.
#[derive(Default)]
struct AuthenticatedAddressBook {
    authenticated: HashSet<PeerId>,
    identified: HashMap<PeerId, Vec<Multiaddr>>,
}

impl AuthenticatedAddressBook {
    fn authenticate(&mut self, peer: PeerId, kademlia: &mut kad::Behaviour<MemoryStore>) -> bool {
        if !self.authenticated.insert(peer) {
            return false;
        }
        if let Some(addresses) = self.identified.get(&peer) {
            for address in addresses {
                kademlia.add_address(&peer, address.clone());
            }
        }
        true
    }

    fn revoke(&mut self, peer: &PeerId, kademlia: &mut kad::Behaviour<MemoryStore>) {
        self.authenticated.remove(peer);
        if let Some(addresses) = self.identified.remove(peer) {
            for address in addresses {
                kademlia.remove_address(peer, &address);
            }
        }
    }

    fn observe_identify(
        &mut self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        kademlia: &mut kad::Behaviour<MemoryStore>,
    ) -> (Vec<Multiaddr>, bool) {
        let addresses = sanitize_identify_addresses(peer, addresses);
        if let Some(previous) = self.identified.insert(peer, addresses.clone()) {
            if self.authenticated.contains(&peer) {
                for address in previous {
                    if !addresses.contains(&address) {
                        kademlia.remove_address(&peer, &address);
                    }
                }
            }
        }
        let usable = self.authenticated.contains(&peer);
        if usable {
            for address in &addresses {
                kademlia.add_address(&peer, address.clone());
            }
        }
        (addresses, usable)
    }

    fn addresses(&self, peer: &PeerId) -> &[Multiaddr] {
        self.identified
            .get(peer)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    fn is_usable(&self, peer: &PeerId) -> bool {
        self.authenticated.contains(peer) && !self.addresses(peer).is_empty()
    }

    #[cfg(test)]
    fn is_authenticated(&self, peer: &PeerId) -> bool {
        self.authenticated.contains(peer)
    }
}

/// Cohesive discovery boundary over stock Identify, Kademlia, and AutoNAT.
pub struct StacksDiscoveryBehaviour {
    protocols: DiscoveryProtocols,
    addresses: AuthenticatedAddressBook,
    bootstrap: HashMap<PeerId, BootstrapTarget>,
    dial_connections: HashMap<ConnectionId, PendingDial>,
    autonat_confirmations: HashMap<Multiaddr, HashMap<PeerId, Instant>>,
    allow_kademlia_promotion: bool,
    configured_server: bool,
    serving: bool,
    next_query: Instant,
    timer: Delay,
    actions: VecDeque<DiscoveryAction>,
}

impl StacksDiscoveryBehaviour {
    pub fn new(identity: &identity::Keypair, config: &NetworkConfig) -> Result<Self, String> {
        let local_peer_id = identity.public().to_peer_id();
        let identify = identify::Behaviour::new(
            identify::Config::new("/stacks/id/1".to_owned(), identity.public())
                .with_agent_version(config.agent_version.clone())
                .with_push_listen_addr_updates(true),
        );
        let kad_protocol = StreamProtocol::try_from_owned(format!(
            "/stacks/{:08x}/{:08x}/kad/1",
            config.chain_id, config.network_id
        ))
        .map_err(|error| error.to_string())?;
        let mut kademlia = kad::Behaviour::with_config(
            local_peer_id,
            MemoryStore::new(local_peer_id),
            kad::Config::new(kad_protocol),
        );
        kademlia.set_mode(Some(if config.kademlia_server {
            Mode::Server
        } else {
            Mode::Client
        }));
        let now = Instant::now();
        Ok(Self {
            protocols: DiscoveryProtocols {
                identify,
                kademlia,
                autonat_client: autonat::v2::client::Behaviour::default(),
                autonat_server: autonat::v2::server::Behaviour::default(),
            },
            addresses: AuthenticatedAddressBook::default(),
            bootstrap: HashMap::new(),
            dial_connections: HashMap::new(),
            autonat_confirmations: HashMap::new(),
            allow_kademlia_promotion: config.allow_kademlia_promotion,
            configured_server: config.kademlia_server,
            serving: config.kademlia_server,
            next_query: now + DISCOVERY_QUERY_INTERVAL,
            timer: Delay::new(DISCOVERY_TICK),
            actions: VecDeque::new(),
        })
    }

    /// Add a pinned bootstrap endpoint. The address must end in its expected
    /// PeerId; the suffix is removed before Kademlia and transport use.
    pub fn add_bootstrap_address(&mut self, address: Multiaddr) -> Result<PeerId, String> {
        let endpoint = PeerEndpoint::try_from(address).map_err(|error| error.to_string())?;
        let peer = endpoint.peer_id();
        let dial_address = endpoint.dial_addr().clone();
        self.protocols
            .kademlia
            .add_address(&peer, dial_address.clone());
        self.bootstrap
            .entry(peer)
            .and_modify(|target| target.address = dial_address.clone())
            .or_insert_with(|| BootstrapTarget::new(dial_address, Instant::now()));
        Ok(peer)
    }

    /// Queue one endpoint that previously completed Noise and Stacks Hello as
    /// a dial hint. It is deliberately not inserted into Kademlia: a durable
    /// observation from an earlier process lifetime does not prove that the
    /// peer still controls the endpoint, and must not be re-advertised before
    /// fresh authentication in this session.
    pub fn restore_peer_address(&mut self, peer: PeerId, address: Multiaddr) -> Result<(), String> {
        let address = crate::peer_store::normalize_dial_address(peer, address)
            .map_err(|error| error.to_string())?;
        self.actions.push_back(DiscoveryAction::Dial {
            peer,
            address,
            purpose: DialPurpose::Restored,
        });
        Ok(())
    }

    /// Mark a peer as having completed the application Hello. Identify
    /// addresses are not eligible for Kademlia routing before this call.
    pub fn authenticate_peer(&mut self, peer: PeerId) {
        if self
            .addresses
            .authenticate(peer, &mut self.protocols.kademlia)
        {
            let _ = self.protocols.kademlia.bootstrap();
        }
    }

    pub fn revoke_peer(&mut self, peer: &PeerId) {
        self.addresses.revoke(peer, &mut self.protocols.kademlia);
    }

    /// Feed a successful authenticated liveness observation (currently Ping)
    /// into pinned-bootstrap recovery without exposing bootstrap maps.
    pub fn note_peer_liveness(&mut self, peer: PeerId, now: Instant) {
        if let Some(target) = self.bootstrap.get_mut(&peer) {
            target.last_alive = Some(now);
            target.connected = true;
            target.closing_stale = false;
            target.attempts = 0;
            target.exhausted_reported = false;
        }
    }

    pub fn is_serving(&self) -> bool {
        self.serving
    }

    pub fn discovered_addresses(&self, peer: &PeerId) -> &[Multiaddr] {
        self.addresses.addresses(peer)
    }

    pub fn addresses_are_usable(&self, peer: &PeerId) -> bool {
        self.addresses.is_usable(peer)
    }

    fn observe_identify(&mut self, peer: PeerId, addresses: Vec<Multiaddr>) {
        let (addresses, usable) =
            self.addresses
                .observe_identify(peer, addresses, &mut self.protocols.kademlia);
        if usable {
            let _ = self.protocols.kademlia.bootstrap();
        }
        self.actions.push_back(DiscoveryAction::Event(
            DiscoveryEvent::PeerAddressesChanged {
                peer,
                addresses,
                usable,
            },
        ));
    }

    fn observe_autonat(&mut self, event: autonat::v2::client::Event, now: Instant) {
        let (reachable, error) = match event.result {
            Ok(()) => {
                self.autonat_confirmations
                    .entry(event.tested_addr.clone())
                    .or_default()
                    .insert(event.server, now);
                (true, None)
            }
            Err(error) => {
                if let Some(servers) = self.autonat_confirmations.get_mut(&event.tested_addr) {
                    servers.remove(&event.server);
                }
                (false, Some(error.to_string()))
            }
        };
        self.actions
            .push_back(DiscoveryAction::Event(DiscoveryEvent::ReachabilityProbe {
                address: event.tested_addr,
                server: event.server,
                reachable,
                error,
            }));
        self.reconcile_serving_mode(now);
    }

    fn reconcile_serving_mode(&mut self, now: Instant) {
        self.autonat_confirmations.retain(|_, servers| {
            servers.retain(|_, at| now.saturating_duration_since(*at) < AUTONAT_CONFIRMATION_TTL);
            !servers.is_empty()
        });
        let independently_reachable = self
            .autonat_confirmations
            .values()
            .any(|servers| servers.len() >= 2);
        let should_serve =
            self.configured_server || (self.allow_kademlia_promotion && independently_reachable);
        if should_serve == self.serving {
            return;
        }
        self.serving = should_serve;
        self.protocols.kademlia.set_mode(Some(if should_serve {
            Mode::Server
        } else {
            Mode::Client
        }));
        self.actions
            .push_back(DiscoveryAction::Event(DiscoveryEvent::ServingModeChanged {
                server: should_serve,
            }));
    }

    fn tick(&mut self, now: Instant) {
        self.reconcile_serving_mode(now);
        if now >= self.next_query {
            self.protocols.kademlia.get_closest_peers(PeerId::random());
            self.next_query = now + DISCOVERY_QUERY_INTERVAL;
            self.actions
                .push_back(DiscoveryAction::Event(DiscoveryEvent::KademliaQueryStarted));
        }
        for (peer, target) in &mut self.bootstrap {
            if target.connected {
                let stale = target.last_alive.is_none_or(|last_alive| {
                    now.saturating_duration_since(last_alive) >= BOOTSTRAP_LIVENESS_TIMEOUT
                });
                if stale && !target.closing_stale {
                    target.closing_stale = true;
                    self.actions.push_back(DiscoveryAction::Event(
                        DiscoveryEvent::BootstrapStale { peer: *peer },
                    ));
                    self.actions
                        .push_back(DiscoveryAction::Close { peer: *peer });
                }
                continue;
            }
            if now < target.next_attempt {
                continue;
            }
            target.attempts = target.attempts.saturating_add(1);
            target.next_attempt = now + target.backoff();
            self.actions
                .push_back(DiscoveryAction::Event(DiscoveryEvent::BootstrapAttempt {
                    peer: *peer,
                    attempt: target.attempts,
                }));
            if target.attempts >= BOOTSTRAP_EXHAUSTED_AFTER && !target.exhausted_reported {
                target.exhausted_reported = true;
                self.actions.push_back(DiscoveryAction::Event(
                    DiscoveryEvent::BootstrapExhausted {
                        peer: *peer,
                        attempts: target.attempts,
                    },
                ));
            }
            self.actions.push_back(DiscoveryAction::Dial {
                peer: *peer,
                address: target.address.clone(),
                purpose: DialPurpose::Bootstrap,
            });
        }
    }

    fn on_dial_failure(&mut self, peer: PeerId, error: String, now: Instant) {
        let Some(target) = self.bootstrap.get_mut(&peer) else {
            return;
        };
        target.connected = false;
        let delay = target.backoff();
        target.next_attempt = now + delay;
        self.actions
            .push_back(DiscoveryAction::Event(DiscoveryEvent::BootstrapFailed {
                peer,
                attempt: target.attempts,
                next_delay: delay,
                error,
            }));
    }
}

impl NetworkBehaviour for StacksDiscoveryBehaviour {
    type ConnectionHandler = <DiscoveryProtocols as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = DiscoveryEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.protocols
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.protocols.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.protocols.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.protocols.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        let now = Instant::now();
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                if let Some(target) = self.bootstrap.get_mut(&event.peer_id) {
                    target.connected = true;
                    target.closing_stale = false;
                    target.last_alive = Some(now);
                    target.attempts = 0;
                    target.exhausted_reported = false;
                }
                self.dial_connections.remove(&event.connection_id);
            }
            FromSwarm::ConnectionClosed(event) if event.remaining_established == 0 => {
                self.revoke_peer(&event.peer_id);
                if let Some(target) = self.bootstrap.get_mut(&event.peer_id) {
                    target.connected = false;
                    target.closing_stale = false;
                    target.last_alive = None;
                    target.next_attempt = now;
                }
            }
            FromSwarm::DialFailure(event) => {
                let pending = self.dial_connections.remove(&event.connection_id);
                if matches!(event.error, DialError::DialPeerConditionFalse(_)) {
                    // Another bootstrap, Kademlia, or restored-address dial
                    // already owns connectivity. This is successful
                    // coalescing, not endpoint evidence or a retry failure.
                } else {
                    match pending {
                        Some(PendingDial {
                            peer,
                            address,
                            purpose: DialPurpose::Restored,
                        }) => self.actions.push_back(DiscoveryAction::Event(
                            DiscoveryEvent::RestoredDialFailed {
                                peer,
                                address,
                                error: event.error.to_string(),
                            },
                        )),
                        Some(PendingDial { peer, .. }) => {
                            self.on_dial_failure(peer, event.error.to_string(), now);
                        }
                        None => {
                            if let Some(peer) = event.peer_id {
                                self.on_dial_failure(peer, event.error.to_string(), now);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        self.protocols.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.protocols
            .on_connection_handler_event(peer_id, connection_id, event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if std::pin::Pin::new(&mut self.timer).poll(cx).is_ready() {
            self.tick(Instant::now());
            self.timer.reset(DISCOVERY_TICK);
        }
        if let Some(action) = self.actions.pop_front() {
            return Poll::Ready(match action {
                DiscoveryAction::Event(event) => ToSwarm::GenerateEvent(event),
                DiscoveryAction::Close { peer } => ToSwarm::CloseConnection {
                    peer_id: peer,
                    connection: CloseConnection::All,
                },
                DiscoveryAction::Dial {
                    peer,
                    address,
                    purpose,
                } => {
                    let opts = DialOpts::peer_id(peer)
                        .condition(PeerCondition::DisconnectedAndNotDialing)
                        .addresses(vec![address.clone()])
                        .build();
                    self.dial_connections.insert(
                        opts.connection_id(),
                        PendingDial {
                            peer,
                            address,
                            purpose,
                        },
                    );
                    ToSwarm::Dial { opts }
                }
            });
        }
        loop {
            match ready!(self.protocols.poll(cx)) {
                ToSwarm::GenerateEvent(DiscoveryProtocolsEvent::Identify(
                    identify::Event::Received { peer_id, info, .. },
                )) => {
                    self.observe_identify(peer_id, info.listen_addrs);
                    if let Some(action) = self.actions.pop_front() {
                        match action {
                            DiscoveryAction::Event(event) => {
                                return Poll::Ready(ToSwarm::GenerateEvent(event));
                            }
                            _ => unreachable!("Identify only queues a typed event"),
                        }
                    }
                }
                ToSwarm::GenerateEvent(DiscoveryProtocolsEvent::AutonatClient(event)) => {
                    self.observe_autonat(event, Instant::now());
                    if let Some(DiscoveryAction::Event(event)) = self.actions.pop_front() {
                        return Poll::Ready(ToSwarm::GenerateEvent(event));
                    }
                }
                ToSwarm::GenerateEvent(
                    DiscoveryProtocolsEvent::Kademlia(_)
                    | DiscoveryProtocolsEvent::AutonatServer(_)
                    | DiscoveryProtocolsEvent::Identify(_),
                ) => {}
                other => return Poll::Ready(other.map_out(|_| unreachable!())),
            }
        }
    }
}

fn sanitize_identify_addresses(peer: PeerId, addresses: Vec<Multiaddr>) -> Vec<Multiaddr> {
    let mut accepted = Vec::new();
    for mut address in addresses {
        if address.to_vec().len() > MAX_IDENTIFY_ADDRESS_BYTES {
            continue;
        }
        if let Some(Protocol::P2p(advertised_peer)) = address.iter().last() {
            if advertised_peer != peer {
                continue;
            }
            address.pop();
        }
        let supported = address
            .iter()
            .any(|part| matches!(part, Protocol::Memory(_)))
            || address.iter().any(|part| matches!(part, Protocol::Tcp(_)));
        if !supported || accepted.contains(&address) {
            continue;
        }
        accepted.push(address);
        if accepted.len() == MAX_IDENTIFY_ADDRESSES {
            break;
        }
    }
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn behaviour() -> StacksDiscoveryBehaviour {
        let identity = identity::Keypair::generate_secp256k1();
        StacksDiscoveryBehaviour::new(&identity, &NetworkConfig::regtest()).unwrap()
    }

    fn kademlia_contains_peer(discovery: &mut StacksDiscoveryBehaviour, peer: &PeerId) -> bool {
        let Some(bucket) = discovery.protocols.kademlia.kbucket(*peer) else {
            return false;
        };
        let contains = bucket.iter().any(|entry| entry.node.key.preimage() == peer);
        contains
    }

    #[test]
    fn identify_addresses_are_bounded_normalized_and_hello_gated() {
        let mut discovery = behaviour();
        let peer = PeerId::random();
        let other = PeerId::random();
        let valid: Multiaddr = "/ip4/127.0.0.1/tcp/20445".parse().unwrap();
        let matching: Multiaddr = format!("{valid}/p2p/{peer}").parse().unwrap();
        let wrong: Multiaddr = format!("{valid}/p2p/{other}").parse().unwrap();
        let unsupported: Multiaddr = "/ip4/127.0.0.1/udp/20445".parse().unwrap();
        discovery.observe_identify(peer, vec![matching, valid.clone(), wrong, unsupported]);
        assert_eq!(discovery.discovered_addresses(&peer), &[valid]);
        assert!(!discovery.addresses_are_usable(&peer));
        assert!(!kademlia_contains_peer(&mut discovery, &peer));
        discovery.authenticate_peer(peer);
        assert!(discovery.addresses_are_usable(&peer));
        assert!(kademlia_contains_peer(&mut discovery, &peer));
        discovery.revoke_peer(&peer);
        assert!(discovery.discovered_addresses(&peer).is_empty());
        assert!(!kademlia_contains_peer(&mut discovery, &peer));
    }

    #[test]
    fn restored_address_is_a_dial_hint_not_authentication() {
        let mut discovery = behaviour();
        let peer = PeerId::random();
        let address: Multiaddr = "/memory/42000".parse().unwrap();
        discovery.restore_peer_address(peer, address).unwrap();
        assert!(!discovery.addresses_are_usable(&peer));
        assert!(!discovery.addresses.is_authenticated(&peer));
        assert!(!kademlia_contains_peer(&mut discovery, &peer));
        assert!(matches!(
            discovery.actions.pop_front(),
            Some(DiscoveryAction::Dial {
                peer: queued_peer,
                purpose: DialPurpose::Restored,
                ..
            }) if queued_peer == peer
        ));
    }

    #[test]
    fn bootstrap_retry_is_exponential_bounded_and_reports_exhaustion_once() {
        let mut discovery = behaviour();
        let peer = PeerId::random();
        let address: Multiaddr = format!("/memory/99/p2p/{peer}").parse().unwrap();
        discovery.add_bootstrap_address(address).unwrap();
        let start = Instant::now();
        let target = discovery.bootstrap.get_mut(&peer).unwrap();
        target.next_attempt = start;

        for expected in 1..=BOOTSTRAP_EXHAUSTED_AFTER + 3 {
            discovery.tick(start + Duration::from_secs(u64::from(expected) * 120));
            let target = discovery.bootstrap.get(&peer).unwrap();
            assert_eq!(target.attempts, expected);
            assert!(target.backoff() <= BOOTSTRAP_MAX_BACKOFF);
        }
        let exhausted = discovery
            .actions
            .iter()
            .filter(|action| {
                matches!(
                    action,
                    DiscoveryAction::Event(DiscoveryEvent::BootstrapExhausted { .. })
                )
            })
            .count();
        assert_eq!(exhausted, 1);
    }

    #[test]
    fn autonat_requires_two_independent_servers_and_demotes_after_expiry() {
        let mut discovery = behaviour();
        let now = Instant::now();
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/20445".parse().unwrap();
        discovery
            .autonat_confirmations
            .entry(address.clone())
            .or_default()
            .insert(PeerId::random(), now);
        discovery.reconcile_serving_mode(now);
        assert!(!discovery.is_serving());
        discovery
            .autonat_confirmations
            .entry(address)
            .or_default()
            .insert(PeerId::random(), now);
        discovery.reconcile_serving_mode(now);
        assert!(discovery.is_serving());
        discovery.reconcile_serving_mode(now + AUTONAT_CONFIRMATION_TTL);
        assert!(!discovery.is_serving());
    }

    #[test]
    fn stale_bootstrap_is_closed_only_once_until_lifecycle_reset() {
        let mut discovery = behaviour();
        let peer = PeerId::random();
        let address: Multiaddr = format!("/memory/99/p2p/{peer}").parse().unwrap();
        discovery.add_bootstrap_address(address).unwrap();
        let now = Instant::now();
        let target = discovery.bootstrap.get_mut(&peer).unwrap();
        target.connected = true;
        target.last_alive = Some(now);
        discovery.tick(now + BOOTSTRAP_LIVENESS_TIMEOUT);
        discovery.tick(now + BOOTSTRAP_LIVENESS_TIMEOUT + DISCOVERY_TICK);
        assert_eq!(
            discovery
                .actions
                .iter()
                .filter(|action| matches!(action, DiscoveryAction::Close { .. }))
                .count(),
            1
        );
    }
}
