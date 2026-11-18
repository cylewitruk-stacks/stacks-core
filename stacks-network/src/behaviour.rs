use std::convert::Infallible;
use std::time::Duration;

use libp2p::connection_limits;
use libp2p::gossipsub::{
    self, IdentTopic, MessageAuthenticity, MessageId, PeerScoreParams, PeerScoreThresholds,
    TopicScoreParams, ValidationMode,
};
use libp2p::memory_connection_limits;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identity, ping, PeerId, StreamProtocol};
use prost::Message as ProstMessage;
use sha2::{Digest, Sha256};
use stacks_network_types::wire::v1::SignerEnvelope;
use stacks_network_types::{
    signer_envelope_id, ContentId, EnvelopeLimits, Libp2pLimits, NetworkEnvelope, NetworkScope,
};

use crate::BoundedEnvelopeCodec;
use crate::{
    AdmissionConfig, AdmissionEvent, AuthenticatedGossipMessage, ConnectionAdmissionBehaviour,
    ContentExchangeBehaviour, ContentExchangeEvent, DiscoveryEvent, GossipRejectionReason,
    GossipTopicClass, RoleDirectoryBehaviour, RoleDirectoryBehaviourEvent, SignerBehaviour,
    SignerBehaviourEvent, StacksApplicationBehaviour, StacksApplicationEvent,
    StacksDiscoveryBehaviour, SyncBehaviour, SyncBehaviourEvent,
};

const GOSSIP_MAX_TRANSMIT_BYTES: usize = EnvelopeLimits::BLOCK.max_frame_bytes;

fn peer_score_params(config: &NetworkConfig) -> PeerScoreParams {
    let invalid_only = TopicScoreParams {
        topic_weight: 1.0,
        time_in_mesh_weight: 0.0,
        first_message_deliveries_weight: 0.0,
        mesh_message_deliveries_weight: 0.0,
        mesh_failure_penalty_weight: 0.0,
        // P4 is a security boundary, not a mesh-performance tuning knob.
        // Application code reports Ignore for valid duplicate/stale traffic,
        // so Reject is reserved for cryptographically or structurally invalid
        // messages and is safe to penalize immediately.
        invalid_message_deliveries_weight: -10.0,
        invalid_message_deliveries_decay: 0.9,
        ..TopicScoreParams::default()
    };
    let mut params = PeerScoreParams::default();
    if config.subscribe_signer_gossip {
        params.topics.insert(
            signer_topic(config.chain_id, config.network_id).hash(),
            invalid_only.clone(),
        );
    }
    if config.subscribe_object_gossip {
        params.topics.insert(
            block_announcement_topic(config.chain_id, config.network_id).hash(),
            invalid_only.clone(),
        );
        params.topics.insert(
            transaction_topic(config.chain_id, config.network_id).hash(),
            invalid_only,
        );
    }
    params
}

pub const HELLO_PROTOCOL: StreamProtocol = StreamProtocol::new("/stacks/hello/1");
pub const SIGNER_DIRECT_PROTOCOL: StreamProtocol = StreamProtocol::new("/stacks/signer-direct/1");
pub const ROLE_DIRECTORY_PROTOCOL: StreamProtocol = StreamProtocol::new("/stacks/role-directory/1");
pub const CONTENT_PROTOCOL: StreamProtocol = StreamProtocol::new("/stacks/content/1");
pub const CONTENT_PUSH_PROTOCOL: StreamProtocol = StreamProtocol::new("/stacks/content-push/1");
pub const SYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/stacks/sync/1");

pub fn signer_topic(chain_id: u32, network_id: u32) -> IdentTopic {
    IdentTopic::new(format!("/stacks/{chain_id:08x}/{network_id:08x}/signer/1"))
}

pub fn block_announcement_topic(chain_id: u32, network_id: u32) -> IdentTopic {
    IdentTopic::new(format!(
        "/stacks/{chain_id:08x}/{network_id:08x}/blocks/announce/1"
    ))
}

pub fn transaction_topic(chain_id: u32, network_id: u32) -> IdentTopic {
    IdentTopic::new(format!(
        "/stacks/{chain_id:08x}/{network_id:08x}/transactions/1"
    ))
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub chain_id: u32,
    pub network_id: u32,
    pub agent_version: String,
    pub max_pending_incoming: u32,
    pub max_pending_outgoing: u32,
    pub max_established_incoming: u32,
    pub max_established_outgoing: u32,
    pub max_established_total: u32,
    pub max_connections_per_peer: u32,
    pub max_connections_per_ip: u32,
    pub max_connections_per_prefix: u32,
    pub max_process_memory_bytes: usize,
    pub request_timeout: Duration,
    pub max_concurrent_streams: usize,
    pub max_inflight_requests_per_peer: usize,
    pub max_inflight_block_pushes: usize,
    pub direct_push_fanout: usize,
    pub small_transaction_bytes: usize,
    /// Subscribe to the signer semantic-message topic. Miners and
    /// signer swarms enable this; ordinary full nodes do not participate in
    /// signer coordination and should neither validate nor relay it.
    pub subscribe_signer_gossip: bool,
    /// Subscribe to node object-announcement and transaction topics. Signer
    /// swarms leave this disabled because they deliberately have no object hub
    /// and should neither validate nor relay these node-only messages.
    pub subscribe_object_gossip: bool,
    pub kademlia_server: bool,
    /// Whether AutoNAT may promote a client to serving mode. Signer swarms
    /// keep this false even when directly reachable.
    pub allow_kademlia_promotion: bool,
    pub inbound_bytes_per_second: u64,
    pub inbound_byte_burst: u64,
    pub validation_units_per_second: u64,
    pub validation_unit_burst: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionPolicy {
    pub max_pending_incoming: u32,
    pub max_pending_outgoing: u32,
    pub max_established_incoming: u32,
    pub max_established_outgoing: u32,
    pub max_established_total: u32,
    pub max_connections_per_peer: u32,
    pub max_connections_per_ip: u32,
    pub max_connections_per_prefix: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourcePolicy {
    pub max_process_memory_bytes: usize,
    pub request_timeout: Duration,
    pub max_concurrent_streams: usize,
    pub max_inflight_requests_per_peer: usize,
    pub inbound_bytes_per_second: u64,
    pub inbound_byte_burst: u64,
    pub validation_units_per_second: u64,
    pub validation_unit_burst: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentPolicy {
    pub max_inflight_block_pushes: usize,
    pub direct_push_fanout: usize,
    pub small_transaction_bytes: usize,
    pub subscribe_signer_gossip: bool,
    pub subscribe_object_gossip: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryPolicy {
    pub kademlia_server: bool,
    pub allow_kademlia_promotion: bool,
}

impl NetworkConfig {
    pub fn node_profile(
        scope: NetworkScope,
        agent_version: String,
        limits: &Libp2pLimits,
        miner: bool,
        kademlia_server: bool,
        direct_push_fanout: usize,
    ) -> Result<Self, String> {
        let mut config = Self::regtest();
        config.chain_id = scope.chain_id();
        config.network_id = scope.network_id();
        config.agent_version = agent_version;
        config.apply_limits(limits)?;
        config.subscribe_signer_gossip = miner;
        config.subscribe_object_gossip = true;
        config.kademlia_server = kademlia_server;
        config.allow_kademlia_promotion = true;
        config.direct_push_fanout = direct_push_fanout;
        config.validate()?;
        Ok(config)
    }

    pub fn signer_profile(
        scope: NetworkScope,
        agent_version: String,
        limits: &Libp2pLimits,
    ) -> Result<Self, String> {
        let mut config = Self::regtest();
        config.chain_id = scope.chain_id();
        config.network_id = scope.network_id();
        config.agent_version = agent_version;
        config.apply_limits(limits)?;
        config.subscribe_signer_gossip = true;
        config.subscribe_object_gossip = false;
        config.kademlia_server = false;
        config.allow_kademlia_promotion = false;
        config.direct_push_fanout = 0;
        config.validate()?;
        Ok(config)
    }

    pub fn memory_test_profile(scope: NetworkScope) -> Self {
        let mut config = Self::docker_regtest_profile();
        config.chain_id = scope.chain_id();
        config.network_id = scope.network_id();
        config.max_process_memory_bytes = usize::MAX;
        config
    }

    pub const fn scope(&self) -> NetworkScope {
        NetworkScope::new(self.chain_id, self.network_id)
    }

    pub const fn connection_policy(&self) -> ConnectionPolicy {
        ConnectionPolicy {
            max_pending_incoming: self.max_pending_incoming,
            max_pending_outgoing: self.max_pending_outgoing,
            max_established_incoming: self.max_established_incoming,
            max_established_outgoing: self.max_established_outgoing,
            max_established_total: self.max_established_total,
            max_connections_per_peer: self.max_connections_per_peer,
            max_connections_per_ip: self.max_connections_per_ip,
            max_connections_per_prefix: self.max_connections_per_prefix,
        }
    }

    pub const fn resource_policy(&self) -> ResourcePolicy {
        ResourcePolicy {
            max_process_memory_bytes: self.max_process_memory_bytes,
            request_timeout: self.request_timeout,
            max_concurrent_streams: self.max_concurrent_streams,
            max_inflight_requests_per_peer: self.max_inflight_requests_per_peer,
            inbound_bytes_per_second: self.inbound_bytes_per_second,
            inbound_byte_burst: self.inbound_byte_burst,
            validation_units_per_second: self.validation_units_per_second,
            validation_unit_burst: self.validation_unit_burst,
        }
    }

    pub const fn content_policy(&self) -> ContentPolicy {
        ContentPolicy {
            max_inflight_block_pushes: self.max_inflight_block_pushes,
            direct_push_fanout: self.direct_push_fanout,
            small_transaction_bytes: self.small_transaction_bytes,
            subscribe_signer_gossip: self.subscribe_signer_gossip,
            subscribe_object_gossip: self.subscribe_object_gossip,
        }
    }

    pub const fn discovery_policy(&self) -> DiscoveryPolicy {
        DiscoveryPolicy {
            kademlia_server: self.kademlia_server,
            allow_kademlia_promotion: self.allow_kademlia_promotion,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id == 0 || self.network_id == 0 {
            return Err("network scope identifiers must be nonzero".to_owned());
        }
        if self.max_connections_per_peer > self.max_established_total
            || self.max_connections_per_ip > self.max_established_total
            || self.max_connections_per_prefix > self.max_established_total
        {
            return Err("connection sub-limit exceeds total established limit".to_owned());
        }
        if self.max_connections_per_prefix < self.max_connections_per_ip {
            return Err("prefix connection limit is smaller than per-IP limit".to_owned());
        }
        if self.max_inflight_requests_per_peer > self.max_concurrent_streams {
            return Err("per-peer request limit exceeds concurrent stream limit".to_owned());
        }
        if self.inbound_byte_burst < self.inbound_bytes_per_second
            || self.validation_unit_burst < self.validation_units_per_second
        {
            return Err("resource burst is smaller than its sustained rate".to_owned());
        }
        if !self.subscribe_object_gossip && self.direct_push_fanout != 0 {
            return Err("direct block push requires object gossip service".to_owned());
        }
        if self.direct_push_fanout > self.max_inflight_block_pushes {
            return Err("direct block push fanout exceeds its bounded inflight window".to_owned());
        }
        Ok(())
    }

    /// Complete bounded profile used by the repository's Docker regtest and
    /// retained as the compatibility default for existing callers.
    pub fn docker_regtest_profile() -> Self {
        Self {
            chain_id: 0x8000_0000,
            network_id: 0x8000_0000,
            agent_version: format!("stacks-core-libp2p/{}", env!("CARGO_PKG_VERSION")),
            max_pending_incoming: 64,
            max_pending_outgoing: 32,
            max_established_incoming: 256,
            max_established_outgoing: 44,
            max_established_total: 300,
            // Permit the inbound and outbound halves of a simultaneous dial;
            // Yamux carries all protocols and application state is still
            // deduplicated by PeerId.
            max_connections_per_peer: 2,
            max_connections_per_ip: 8,
            max_connections_per_prefix: 32,
            max_process_memory_bytes: 1024 * 1024 * 1024,
            request_timeout: Duration::from_secs(10),
            max_concurrent_streams: 100,
            max_inflight_requests_per_peer: 8,
            max_inflight_block_pushes: 12,
            direct_push_fanout: 3,
            small_transaction_bytes: 64 * 1024,
            subscribe_signer_gossip: true,
            subscribe_object_gossip: true,
            kademlia_server: false,
            allow_kademlia_promotion: true,
            inbound_bytes_per_second: 4 * 1024 * 1024,
            // One incumbent-maximum authenticated proposal/event plus framing
            // overhead; sustained rate remains much lower.
            inbound_byte_burst: 20 * 1024 * 1024,
            validation_units_per_second: 100,
            validation_unit_burst: 400,
        }
    }

    pub fn regtest() -> Self {
        Self::docker_regtest_profile()
    }

    pub fn apply_limits(&mut self, limits: &Libp2pLimits) -> Result<(), String> {
        limits.validate().map_err(|error| error.to_string())?;
        self.max_pending_incoming = limits.max_pending_incoming;
        self.max_pending_outgoing = limits.max_pending_outgoing;
        self.max_established_incoming = limits.max_established_incoming;
        self.max_established_outgoing = limits.max_established_outgoing;
        self.max_established_total = limits.max_established_total;
        self.max_connections_per_peer = limits.max_connections_per_peer;
        self.max_connections_per_ip = limits.max_connections_per_ip;
        self.max_connections_per_prefix = limits.max_connections_per_prefix;
        self.max_process_memory_bytes = usize::try_from(limits.max_process_memory_bytes)
            .map_err(|_| "max_process_memory_bytes does not fit this platform".to_owned())?;
        self.request_timeout = Duration::from_secs(limits.request_timeout_secs);
        self.max_concurrent_streams = usize::try_from(limits.max_concurrent_streams)
            .map_err(|_| "max_concurrent_streams does not fit this platform".to_owned())?;
        self.max_inflight_requests_per_peer =
            usize::try_from(limits.max_inflight_requests_per_peer).map_err(|_| {
                "max_inflight_requests_per_peer does not fit this platform".to_owned()
            })?;
        self.max_inflight_block_pushes = usize::try_from(limits.max_inflight_block_pushes)
            .map_err(|_| "max_inflight_block_pushes does not fit this platform".to_owned())?;
        self.small_transaction_bytes = usize::try_from(limits.small_transaction_bytes)
            .map_err(|_| "small_transaction_bytes does not fit this platform".to_owned())?;
        self.inbound_bytes_per_second = limits.inbound_bytes_per_second;
        self.inbound_byte_burst = limits.inbound_byte_burst;
        self.validation_units_per_second = limits.validation_units_per_second;
        self.validation_unit_burst = limits.validation_unit_burst;
        Ok(())
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "StacksBehaviourEvent")]
pub struct StacksBehaviour {
    // Admission behaviours must stay first. The derive macro calls
    // `handle_established_*` in field order and stops at the first denial. If
    // a limiter comes after a stateful behaviour, that behaviour can observe
    // half-admitted connections and later receive a close count that includes
    // connections it never admitted (libp2p#connection-limits ordering).
    pub connection_limits: connection_limits::Behaviour,
    pub memory_limits: memory_connection_limits::Behaviour,
    pub admission: ConnectionAdmissionBehaviour,
    pub ping: ping::Behaviour,
    /// Identify, Kademlia, AutoNAT, and bootstrap policy are private children
    /// of the discovery boundary.
    discovery: StacksDiscoveryBehaviour,
    /// Hello and every application protocol are private children of this
    /// structural authentication boundary.
    application: StacksApplicationBehaviour,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum StacksBehaviourEvent {
    Admission(AdmissionEvent),
    Ping(ping::Event),
    Discovery(DiscoveryEvent),
    RequestResponse(request_response::Event<NetworkEnvelope, NetworkEnvelope>),
    SignerDirect(SignerBehaviourEvent),
    RoleDirectory(RoleDirectoryBehaviourEvent),
    Content(ContentExchangeEvent),
    Sync(SyncBehaviourEvent),
    Gossip(AuthenticatedGossipMessage),
    GossipRejected {
        peer: PeerId,
        topic: Option<GossipTopicClass>,
        reason: GossipRejectionReason,
    },
    PreHelloRejected {
        peer: PeerId,
        connection_id: Option<libp2p::swarm::ConnectionId>,
        protocol: crate::ApplicationProtocol,
    },
    HelloRejected {
        peer: PeerId,
        connection_id: libp2p::swarm::ConnectionId,
        reason: crate::HelloRejectionReason,
    },
}

impl From<Infallible> for StacksBehaviourEvent {
    fn from(event: Infallible) -> Self {
        libp2p::core::util::unreachable(event)
    }
}

impl From<AdmissionEvent> for StacksBehaviourEvent {
    fn from(event: AdmissionEvent) -> Self {
        Self::Admission(event)
    }
}

impl From<ping::Event> for StacksBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<DiscoveryEvent> for StacksBehaviourEvent {
    fn from(event: DiscoveryEvent) -> Self {
        Self::Discovery(event)
    }
}

impl From<StacksApplicationEvent> for StacksBehaviourEvent {
    fn from(event: StacksApplicationEvent) -> Self {
        match event {
            StacksApplicationEvent::Hello(event) => Self::RequestResponse(event),
            StacksApplicationEvent::SignerDirect(event) => Self::SignerDirect(event),
            StacksApplicationEvent::RoleDirectory(event) => Self::RoleDirectory(event),
            StacksApplicationEvent::Content(event) => Self::Content(event),
            StacksApplicationEvent::Sync(event) => Self::Sync(event),
            StacksApplicationEvent::Gossip(event) => Self::Gossip(event),
            StacksApplicationEvent::GossipRejected {
                peer,
                topic,
                reason,
            } => Self::GossipRejected {
                peer,
                topic,
                reason,
            },
            StacksApplicationEvent::PreHelloRejected {
                peer,
                connection_id,
                protocol,
            } => Self::PreHelloRejected {
                peer,
                connection_id,
                protocol,
            },
            StacksApplicationEvent::HelloRejected {
                peer,
                connection_id,
                reason,
            } => Self::HelloRejected {
                peer,
                connection_id,
                reason,
            },
        }
    }
}

impl StacksBehaviour {
    pub fn new(identity: &identity::Keypair, config: &NetworkConfig) -> Result<Self, String> {
        config.validate()?;
        let ping = ping::Behaviour::new(
            ping::Config::new()
                .with_interval(Duration::from_secs(30))
                .with_timeout(Duration::from_secs(10)),
        );

        let mut gossip_config = gossipsub::ConfigBuilder::default();
        gossip_config
            .validation_mode(ValidationMode::Strict)
            .validate_messages()
            .max_transmit_size(GOSSIP_MAX_TRANSMIT_BYTES)
            .message_id_fn(canonical_gossip_message_id);
        let mut gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(identity.clone()),
            gossip_config.build().map_err(|error| error.to_string())?,
        )
        .map_err(str::to_owned)?;
        // Enable invalid-message (P4), behavioural, and IP-colocation
        // penalties from the first release. Mesh delivery (P1-P3) tuning is
        // intentionally deferred until shadow-network measurements exist.
        gossipsub
            .with_peer_score(peer_score_params(config), PeerScoreThresholds::default())
            .map_err(|error| format!("invalid GossipSub peer-score policy: {error}"))?;
        if config.subscribe_signer_gossip {
            gossipsub
                .subscribe(&signer_topic(config.chain_id, config.network_id))
                .map_err(|error| error.to_string())?;
        }
        if config.subscribe_object_gossip {
            gossipsub
                .subscribe(&block_announcement_topic(
                    config.chain_id,
                    config.network_id,
                ))
                .map_err(|error| error.to_string())?;
            gossipsub
                .subscribe(&transaction_topic(config.chain_id, config.network_id))
                .map_err(|error| error.to_string())?;
        }

        let request_response = request_response::Behaviour::with_codec(
            BoundedEnvelopeCodec::new(EnvelopeLimits::HELLO),
            [(HELLO_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(config.request_timeout)
                .with_max_concurrent_streams(config.max_concurrent_streams),
        );
        let signer_direct = request_response::Behaviour::with_codec(
            BoundedEnvelopeCodec::new(EnvelopeLimits::BLOCK),
            [(SIGNER_DIRECT_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(config.request_timeout)
                .with_max_concurrent_streams(config.max_concurrent_streams),
        );
        let signer_direct = SignerBehaviour::new(
            signer_direct,
            stacks_network_types::NetworkScope::new(config.chain_id, config.network_id),
        );
        let role_directory = request_response::Behaviour::with_codec(
            BoundedEnvelopeCodec::new(EnvelopeLimits::DIRECTORY),
            [(ROLE_DIRECTORY_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(config.request_timeout)
                .with_max_concurrent_streams(config.max_concurrent_streams.min(32)),
        );
        let role_directory = RoleDirectoryBehaviour::new(
            role_directory,
            stacks_network_types::NetworkScope::new(config.chain_id, config.network_id),
        );
        let content_fetch = request_response::Behaviour::with_codec(
            BoundedEnvelopeCodec::new(EnvelopeLimits::BLOCK),
            [(CONTENT_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(config.request_timeout)
                .with_max_concurrent_streams(config.max_concurrent_streams),
        );
        let content_push = request_response::Behaviour::with_codec(
            BoundedEnvelopeCodec::new(EnvelopeLimits::BLOCK),
            [(CONTENT_PUSH_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(config.request_timeout)
                .with_max_concurrent_streams(config.max_concurrent_streams.min(16)),
        );
        let content = ContentExchangeBehaviour::new(
            content_fetch,
            content_push,
            config.chain_id,
            config.request_timeout,
            config.max_inflight_requests_per_peer,
            config.max_inflight_block_pushes,
        );
        let sync_protocol = request_response::Behaviour::with_codec(
            BoundedEnvelopeCodec::new(EnvelopeLimits::SYNC),
            [(SYNC_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(config.request_timeout)
                .with_max_concurrent_streams(config.max_concurrent_streams.min(32)),
        );
        let sync = SyncBehaviour::new(
            sync_protocol,
            config.chain_id,
            config.request_timeout,
            config.max_inflight_requests_per_peer,
        );
        let peer_budget = crate::PeerResourceBudget::new(
            config.inbound_bytes_per_second,
            config.inbound_byte_burst,
            config.validation_units_per_second,
            config.validation_unit_burst,
            Duration::from_secs(10 * 60),
        )?;

        let connection_limits = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(config.max_pending_incoming))
                .with_max_pending_outgoing(Some(config.max_pending_outgoing))
                .with_max_established_incoming(Some(config.max_established_incoming))
                .with_max_established_outgoing(Some(config.max_established_outgoing))
                .with_max_established(Some(config.max_established_total))
                .with_max_established_per_peer(Some(config.max_connections_per_peer)),
        );

        Ok(Self {
            ping,
            discovery: StacksDiscoveryBehaviour::new(identity, config)?,
            application: StacksApplicationBehaviour::new(
                stacks_network_types::NetworkScope::new(config.chain_id, config.network_id),
                config.small_transaction_bytes,
                peer_budget,
                config.request_timeout,
                request_response,
                signer_direct,
                role_directory,
                content,
                sync,
                gossipsub,
            ),
            connection_limits,
            memory_limits: memory_connection_limits::Behaviour::with_max_bytes(
                config.max_process_memory_bytes,
            ),
            admission: ConnectionAdmissionBehaviour::new(AdmissionConfig::from_network(config)),
        })
    }

    pub fn add_bootstrap_address(&mut self, address: libp2p::Multiaddr) -> Result<PeerId, String> {
        self.discovery.add_bootstrap_address(address)
    }

    pub fn reserve_connection_capacity_for(
        &mut self,
        peers: impl IntoIterator<Item = PeerId>,
    ) -> Result<(), String> {
        self.admission.reserve_capacity_for(peers)
    }

    pub fn restore_peer_address(
        &mut self,
        peer: PeerId,
        address: libp2p::Multiaddr,
    ) -> Result<(), String> {
        self.discovery.restore_peer_address(peer, address)
    }

    pub fn authenticate_discovery_peer(&mut self, peer: PeerId) {
        self.discovery.authenticate_peer(peer);
    }

    pub fn note_discovery_liveness(&mut self, peer: PeerId, now: std::time::Instant) {
        self.discovery.note_peer_liveness(peer, now);
    }

    pub fn kademlia_server(&self) -> bool {
        self.discovery.is_serving()
    }

    pub fn discovered_addresses(&self, peer: &PeerId) -> &[libp2p::Multiaddr] {
        self.discovery.discovered_addresses(peer)
    }

    pub fn discovery_addresses_are_usable(&self, peer: &PeerId) -> bool {
        self.discovery.addresses_are_usable(peer)
    }

    pub fn application(&self) -> &StacksApplicationBehaviour {
        &self.application
    }

    pub fn application_mut(&mut self) -> &mut StacksApplicationBehaviour {
        &mut self.application
    }

    pub fn gossip_topics(&self) -> impl Iterator<Item = &gossipsub::TopicHash> {
        self.application.gossip_topics()
    }
}

fn canonical_gossip_message_id(message: &gossipsub::Message) -> MessageId {
    let mut hasher = Sha256::new();
    hasher.update(b"STACKS_GOSSIPSUB_MESSAGE_ID_V1");
    hasher.update((message.topic.as_str().len() as u64).to_be_bytes());
    hasher.update(message.topic.as_str().as_bytes());
    // Signer identity is computed from decoded, explicitly canonical signed fields.
    // This collapses protobuf field ordering and ignored unknown-field variants.
    if message.topic.as_str().ends_with("/signer/1") {
        if let Ok(envelope) = SignerEnvelope::decode(message.data.as_slice()) {
            if let Ok(content_id) = signer_envelope_id(&envelope) {
                hasher.update(b"SIGNER");
                hasher.update(content_id.as_bytes());
                return MessageId::from(hasher.finalize().to_vec());
            }
        }
    }
    if let Ok(outer) = NetworkEnvelope::decode(&message.data, EnvelopeLimits::BLOCK) {
        if message.topic.as_str().ends_with("/blocks/announce/1") {
            if let Ok(announcement) = crate::decode_announcement(&outer, outer.chain_id()) {
                hasher.update(b"ANNOUNCEMENT");
                hasher.update(crate::announcement_id(&announcement).as_bytes());
                return MessageId::from(hasher.finalize().to_vec());
            }
        }
        if message.topic.as_str().ends_with("/transactions/1") {
            if let Ok(object) = crate::decode_content_push(&outer, outer.chain_id()) {
                hasher.update(b"TRANSACTION");
                hasher.update((object.kind as u8).to_be_bytes());
                hasher.update(object.content_id.as_bytes());
                hasher.update(
                    ContentId::from_domain_bytes(b"STACKS_TX_GOSSIP_BYTES_V1", &object.bytes)
                        .as_bytes(),
                );
                return MessageId::from(hasher.finalize().to_vec());
            }
        }
    }
    hasher.update(b"RAW");
    hasher.update((message.data.len() as u64).to_be_bytes());
    hasher.update(&message.data);
    MessageId::from(hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stacks_network_types::wire::v1::{SignerEnvelopeBody, SignerLane};
    use stacks_network_types::{NetworkObject, ObjectKind, SIGNER_ENVELOPE_VERSION};

    use crate::content_push_envelope;

    #[test]
    fn subscribed_topics_have_invalid_message_penalties_only() {
        let config = NetworkConfig::regtest();
        let params = peer_score_params(&config);
        assert_eq!(params.topics.len(), 3);
        for topic in params.topics.values() {
            assert_eq!(topic.time_in_mesh_weight, 0.0);
            assert_eq!(topic.first_message_deliveries_weight, 0.0);
            assert_eq!(topic.mesh_message_deliveries_weight, 0.0);
            assert_eq!(topic.mesh_failure_penalty_weight, 0.0);
            assert!(topic.invalid_message_deliveries_weight < 0.0);
        }
    }

    #[test]
    fn maximum_policy_transaction_fits_gossip_transport_limit() {
        let config = NetworkConfig::regtest();
        let bytes = vec![0_u8; config.small_transaction_bytes];
        let object = NetworkObject {
            kind: ObjectKind::Transaction,
            content_id: ContentId::from_domain_bytes(b"MAX_TX_TEST", &bytes),
            bytes,
        };
        let encoded = content_push_envelope(config.chain_id, &object).encode();
        assert!(encoded.len() <= GOSSIP_MAX_TRANSMIT_BYTES);
        let outer = NetworkEnvelope::decode(&encoded, EnvelopeLimits::BLOCK).unwrap();
        assert_eq!(
            crate::decode_content_push(&outer, config.chain_id).unwrap(),
            object
        );
    }

    #[test]
    fn signer_profile_does_not_subscribe_to_node_object_topics() {
        let identity = identity::Keypair::generate_secp256k1();
        let config = NetworkConfig::signer_profile(
            NetworkScope::new(1, 1),
            "test-signer".to_owned(),
            &Libp2pLimits::default(),
        )
        .unwrap();

        let behaviour = StacksBehaviour::new(&identity, &config).unwrap();
        let topics = behaviour.gossip_topics().collect::<Vec<_>>();
        let signer_topic = signer_topic(config.chain_id, config.network_id).hash();

        assert_eq!(topics, vec![&signer_topic]);
    }

    #[test]
    fn ordinary_node_profile_does_not_subscribe_to_signer_topic() {
        let identity = identity::Keypair::generate_secp256k1();
        let config = NetworkConfig::node_profile(
            NetworkScope::new(1, 1),
            "test-node".to_owned(),
            &Libp2pLimits::default(),
            false,
            false,
            3,
        )
        .unwrap();

        let behaviour = StacksBehaviour::new(&identity, &config).unwrap();
        let topics = behaviour.gossip_topics().collect::<Vec<_>>();
        let block_topic = block_announcement_topic(config.chain_id, config.network_id).hash();
        let transaction_topic = transaction_topic(config.chain_id, config.network_id).hash();

        assert_eq!(topics.len(), 2);
        assert!(topics.contains(&&block_topic));
        assert!(topics.contains(&&transaction_topic));
    }

    #[test]
    fn validated_profiles_encode_role_specific_policy() {
        let scope = NetworkScope::new(7, 8);
        let limits = Libp2pLimits::default();
        let node =
            NetworkConfig::node_profile(scope, "node".to_owned(), &limits, false, true, 2).unwrap();
        let miner =
            NetworkConfig::node_profile(scope, "miner".to_owned(), &limits, true, true, 2).unwrap();
        let signer = NetworkConfig::signer_profile(scope, "signer".to_owned(), &limits).unwrap();
        let memory = NetworkConfig::memory_test_profile(scope);
        let docker = NetworkConfig::docker_regtest_profile();

        assert!(node.subscribe_object_gossip);
        assert!(!node.subscribe_signer_gossip);
        assert!(node.kademlia_server);
        assert!(miner.subscribe_object_gossip && miner.subscribe_signer_gossip);
        assert!(signer.subscribe_signer_gossip);
        assert!(!signer.subscribe_object_gossip);
        assert!(!signer.kademlia_server && !signer.allow_kademlia_promotion);
        assert_eq!(signer.direct_push_fanout, 0);
        assert_eq!(memory.max_process_memory_bytes, usize::MAX);
        assert_eq!(docker.scope(), NetworkScope::new(0x8000_0000, 0x8000_0000));
        for profile in [&node, &miner, &signer, &memory, &docker] {
            profile.validate().unwrap();
        }
    }

    #[test]
    fn invalid_mutation_is_rejected_at_behaviour_boundary() {
        let identity = identity::Keypair::generate_secp256k1();
        let mut config = NetworkConfig::docker_regtest_profile();
        config.subscribe_object_gossip = false;
        assert!(StacksBehaviour::new(&identity, &config).is_err());

        config.direct_push_fanout = 0;
        config.max_inflight_requests_per_peer = config.max_concurrent_streams + 1;
        assert!(StacksBehaviour::new(&identity, &config).is_err());
    }

    #[test]
    fn signer_message_id_ignores_unknown_protobuf_fields() {
        let envelope = SignerEnvelope {
            body: Some(SignerEnvelopeBody {
                version: SIGNER_ENVELOPE_VERSION,
                chain_id: 1,
                network_id: 1,
                reward_cycle: 2,
                lane: SignerLane::Control as i32,
                sequence: 3,
                previous_envelope_id: Vec::new(),
                signer_public_key: vec![2; 33],
                transport_peer_id: vec![3; 39],
                payload: b"ready".to_vec(),
                burn_view_consensus_hash: Vec::new(),
                proposal_manifest: None,
            }),
            signature: vec![4; 65],
        };
        let canonical = envelope.encode_to_vec();
        let mut with_unknown = canonical.clone();
        // Unknown field 99, varint value 1. Prost discards it when decoding.
        with_unknown.extend_from_slice(&[0x98, 0x06, 0x01]);
        let message = |data| gossipsub::Message {
            source: None,
            data,
            sequence_number: None,
            topic: signer_topic(1, 1).hash(),
        };
        assert_eq!(
            canonical_gossip_message_id(&message(canonical)),
            canonical_gossip_message_id(&message(with_unknown)),
        );
    }
}
