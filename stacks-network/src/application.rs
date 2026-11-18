// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Structural Hello gate for Stacks application protocols.
//!
//! Gated request-response and GossipSub engines are private children. Their
//! events can reach the service only through this wrapper, which keys Hello
//! state by libp2p connection ID and rejects pre-Hello traffic without an
//! application callback.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use futures_timer::Delay;
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::gossipsub::{self, MessageAcceptance, MessageId, PublishError, TopicHash};
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::{
    CloseConnection, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use prost::Message as ProstMessage;
use rand::RngCore;
use stacks_network_types::wire::v1::{
    sync_request, GetSignerReplay, Hello, SignerEnvelope, Status, SyncRequest, SyncResponse,
};
use stacks_network_types::{
    Announcement, ContentId, EnvelopeLimits, NetworkEnvelope, NetworkObject, NetworkScope,
    ObjectKind, CAP_CONTENT_PUSH, CAP_OBJECT_FETCH, CAP_ROLE_DIRECTORY, CAP_SIGNER_SEMANTICS,
    CAP_SYNC, CAP_TRANSACTION_GOSSIP,
};

use crate::role_directory_behaviour::PreparedDirectoryAuthorization;
use crate::signer_behaviour::PreparedSignerAuthorization;
use crate::{
    block_announcement_topic, decode_announcement, decode_content_push, hello_envelope,
    hello_status_response_envelope, signer_topic, transaction_topic, validate_hello,
    validate_hello_response, AuthorizationSnapshot, AuthorizationSnapshotError,
    AuthorizationSnapshotUpdate, BudgetRejection, ContentExchangeBehaviour, ContentExchangeEvent,
    ContentProtocolKind, DirectPushCandidate, ObjectNetworkEvent, PublicationOutcome,
    RoleDirectoryBehaviour, RoleDirectoryBehaviourEvent, SignerBehaviour, SignerBehaviourEvent,
    StagedSignerEnvelope, SyncBehaviour, SyncBehaviourEvent, SyncRequestOwner,
};

#[cfg(test)]
use crate::decode_content_request;

const HANDSHAKE_TICK: Duration = Duration::from_secs(1);
const MAX_SEEN_HELLOS_PER_CONNECTION: usize = 2;
/// Current and next reward-cycle repair can be in flight together. Keep their
/// combined pages within half of the bounded signer event channel so recovery
/// traffic always leaves capacity for live consensus messages.
const SIGNER_REPLAY_PAGE_ITEMS: usize = crate::service::SIGNER_EVENT_QUEUE_CAPACITY / 4;
const _: () = assert!(SIGNER_REPLAY_PAGE_ITEMS > 0);
const _: () =
    assert!(SIGNER_REPLAY_PAGE_ITEMS * 2 <= crate::service::SIGNER_EVENT_QUEUE_CAPACITY / 2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationProtocol {
    SignerDirect,
    RoleDirectory,
    Content,
    ContentPush,
    Sync,
    Gossipsub,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloRejectionReason {
    WrongChainOrMalformed,
    ChallengeOrResponse,
    Replay,
    UnknownConnection,
    Timeout,
}

#[derive(Debug)]
pub enum StacksApplicationEvent {
    Hello(request_response::Event<NetworkEnvelope, NetworkEnvelope>),
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
        connection_id: Option<ConnectionId>,
        protocol: ApplicationProtocol,
    },
    HelloRejected {
        peer: PeerId,
        connection_id: ConnectionId,
        reason: HelloRejectionReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GossipTopicClass {
    Signer,
    BlockAnnouncement,
    Transaction,
}

impl GossipTopicClass {
    fn required_capability(self) -> u64 {
        match self {
            Self::Signer => CAP_SIGNER_SEMANTICS,
            Self::BlockAnnouncement => CAP_OBJECT_FETCH,
            Self::Transaction => CAP_TRANSACTION_GOSSIP,
        }
    }
}

#[derive(Debug)]
pub enum GossipRejectionReason {
    UnknownTopic,
    UnauthenticatedOrIncapable,
    UnsignedSource,
    Resource(BudgetRejection),
    InvalidPayload(String),
}

#[derive(Debug)]
pub enum AuthenticatedGossip {
    Signer(Box<StagedSignerEnvelope>),
    BlockAnnouncement(Announcement),
    Transaction(NetworkObject),
}

#[derive(Debug)]
pub struct GossipValidationToken {
    message_id: MessageId,
    propagation_source: PeerId,
}

#[derive(Debug)]
pub struct AuthenticatedGossipMessage {
    pub propagation_source: PeerId,
    pub source: PeerId,
    pub payload: AuthenticatedGossip,
    validation: GossipValidationToken,
}

impl AuthenticatedGossipMessage {
    pub fn topic(&self) -> GossipTopicClass {
        match self.payload {
            AuthenticatedGossip::Signer(_) => GossipTopicClass::Signer,
            AuthenticatedGossip::BlockAnnouncement(_) => GossipTopicClass::BlockAnnouncement,
            AuthenticatedGossip::Transaction(_) => GossipTopicClass::Transaction,
        }
    }

    pub fn into_parts(self) -> (PeerId, PeerId, AuthenticatedGossip, GossipValidationToken) {
        (
            self.propagation_source,
            self.source,
            self.payload,
            self.validation,
        )
    }
}

#[derive(Clone, Debug)]
struct GossipTopics {
    signer: TopicHash,
    block_announcement: TopicHash,
    transaction: TopicHash,
}

impl GossipTopics {
    fn new(scope: NetworkScope) -> Self {
        Self {
            signer: signer_topic(scope.chain_id(), scope.network_id()).hash(),
            block_announcement: block_announcement_topic(scope.chain_id(), scope.network_id())
                .hash(),
            transaction: transaction_topic(scope.chain_id(), scope.network_id()).hash(),
        }
    }

    fn classify(&self, topic: &TopicHash) -> Option<GossipTopicClass> {
        if topic == &self.signer {
            Some(GossipTopicClass::Signer)
        } else if topic == &self.block_announcement {
            Some(GossipTopicClass::BlockAnnouncement)
        } else if topic == &self.transaction {
            Some(GossipTopicClass::Transaction)
        } else {
            None
        }
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ApplicationGateError {
    #[error("peer has no Hello-authenticated connection")]
    Unauthenticated,
    #[error("Hello envelope is invalid: {0}")]
    Hello(String),
}

#[derive(NetworkBehaviour)]
#[doc(hidden)]
pub struct ApplicationProtocols {
    hello: request_response::Behaviour<crate::BoundedEnvelopeCodec>,
    signer_direct: SignerBehaviour,
    role_directory: RoleDirectoryBehaviour,
    content: ContentExchangeBehaviour,
    sync: SyncBehaviour,
    gossipsub: gossipsub::Behaviour,
}

#[derive(Clone, Debug)]
struct ConnectionHandshake {
    peer: PeerId,
    established_at: Instant,
    remote_hello: Option<Hello>,
    seen_hellos: Vec<ContentId>,
}

#[derive(Clone, Debug)]
struct PendingHello {
    peer: PeerId,
    challenge: Vec<u8>,
}

/// Per-connection authentication state. A PeerId aggregate is maintained only
/// for peer-scoped libp2p APIs such as GossipSub and request initiation.
#[derive(Default)]
pub struct HandshakeGate {
    connections: HashMap<ConnectionId, ConnectionHandshake>,
    authenticated_per_peer: HashMap<PeerId, usize>,
    pending: HashMap<OutboundRequestId, PendingHello>,
}

impl HandshakeGate {
    fn established(&mut self, connection_id: ConnectionId, peer: PeerId, now: Instant) {
        self.remove(connection_id);
        self.connections.insert(
            connection_id,
            ConnectionHandshake {
                peer,
                established_at: now,
                remote_hello: None,
                seen_hellos: Vec::new(),
            },
        );
    }

    fn authenticate(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        hello: Hello,
    ) -> Result<bool, HelloRejectionReason> {
        let connection = self
            .connections
            .get_mut(&connection_id)
            .filter(|connection| connection.peer == peer)
            .ok_or(HelloRejectionReason::UnknownConnection)?;
        let first = connection.remote_hello.is_none();
        connection.remote_hello = Some(hello);
        if first {
            *self.authenticated_per_peer.entry(peer).or_default() += 1;
        }
        Ok(first)
    }

    fn observe_hello_id(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        content_id: ContentId,
    ) -> Result<(), HelloRejectionReason> {
        let connection = self
            .connections
            .get_mut(&connection_id)
            .filter(|connection| connection.peer == peer)
            .ok_or(HelloRejectionReason::UnknownConnection)?;
        if connection.seen_hellos.contains(&content_id) {
            return Err(HelloRejectionReason::Replay);
        }
        if connection.seen_hellos.len() >= MAX_SEEN_HELLOS_PER_CONNECTION {
            return Err(HelloRejectionReason::Replay);
        }
        connection.seen_hellos.push(content_id);
        Ok(())
    }

    fn remove(&mut self, connection_id: ConnectionId) -> Option<PeerId> {
        let connection = self.connections.remove(&connection_id)?;
        if connection.remote_hello.is_some() {
            if let Some(count) = self.authenticated_per_peer.get_mut(&connection.peer) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.authenticated_per_peer.remove(&connection.peer);
                }
            }
        }
        Some(connection.peer)
    }

    fn revoke_peer(&mut self, peer: PeerId) -> Vec<ConnectionId> {
        let connections = self
            .connections
            .iter()
            .filter_map(|(id, state)| (state.peer == peer).then_some(*id))
            .collect::<Vec<_>>();
        for connection in &connections {
            self.remove(*connection);
        }
        self.pending.retain(|_, pending| pending.peer != peer);
        connections
    }

    pub fn is_connection_authenticated(&self, peer: &PeerId, connection_id: ConnectionId) -> bool {
        self.connections
            .get(&connection_id)
            .is_some_and(|state| state.peer == *peer && state.remote_hello.is_some())
    }

    pub fn is_peer_authenticated(&self, peer: &PeerId) -> bool {
        self.authenticated_per_peer.get(peer).copied().unwrap_or(0) > 0
    }

    /// Return whether every live connection for `peer` has completed Hello
    /// and advertised `capability`.
    ///
    /// Peer-scoped libp2p APIs may select any established connection.  Using
    /// an "any connection" aggregate would therefore let a permissive Hello
    /// lend capabilities to a second connection that did not advertise them.
    pub fn peer_supports(&self, peer: &PeerId, capability: u64) -> bool {
        let mut found = false;
        for connection in self
            .connections
            .values()
            .filter(|connection| connection.peer == *peer)
        {
            found = true;
            let Some(hello) = connection.remote_hello.as_ref() else {
                return false;
            };
            if !stacks_network_types::supports(hello.capabilities, capability) {
                return false;
            }
        }
        found
    }

    /// Check a capability against the Hello authenticated on the exact
    /// connection that carried a protocol event.
    pub fn connection_supports(
        &self,
        peer: &PeerId,
        connection_id: ConnectionId,
        capability: u64,
    ) -> bool {
        self.connections
            .get(&connection_id)
            .is_some_and(|connection| {
                connection.peer == *peer
                    && connection.remote_hello.as_ref().is_some_and(|hello| {
                        stacks_network_types::supports(hello.capabilities, capability)
                    })
            })
    }

    pub fn remote_hello(&self, connection_id: ConnectionId) -> Option<&Hello> {
        self.connections
            .get(&connection_id)
            .and_then(|connection| connection.remote_hello.as_ref())
    }

    fn expired(&self, now: Instant, timeout: Duration) -> Vec<(PeerId, ConnectionId)> {
        self.connections
            .iter()
            .filter_map(|(connection_id, connection)| {
                (connection.remote_hello.is_none()
                    && now.saturating_duration_since(connection.established_at) >= timeout)
                    .then_some((connection.peer, *connection_id))
            })
            .collect()
    }
}

pub struct StacksApplicationBehaviour {
    protocols: ApplicationProtocols,
    gate: HandshakeGate,
    scope: NetworkScope,
    gossip_topics: GossipTopics,
    small_transaction_bytes: usize,
    peer_budget: crate::PeerResourceBudget<PeerId>,
    handshake_timeout: Duration,
    timer: Delay,
    queued_events: VecDeque<StacksApplicationEvent>,
    closes: VecDeque<(PeerId, ConnectionId)>,
}

struct PreparedApplicationAuthorization {
    signer: PreparedSignerAuthorization,
    directory: PreparedDirectoryAuthorization,
    update: AuthorizationSnapshotUpdate,
    previously_bound: std::collections::BTreeSet<PeerId>,
}

impl StacksApplicationBehaviour {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        scope: NetworkScope,
        small_transaction_bytes: usize,
        peer_budget: crate::PeerResourceBudget<PeerId>,
        handshake_timeout: Duration,
        hello: request_response::Behaviour<crate::BoundedEnvelopeCodec>,
        signer_direct: SignerBehaviour,
        role_directory: RoleDirectoryBehaviour,
        content: ContentExchangeBehaviour,
        sync: SyncBehaviour,
        gossipsub: gossipsub::Behaviour,
    ) -> Self {
        Self {
            protocols: ApplicationProtocols {
                hello,
                signer_direct,
                role_directory,
                content,
                sync,
                gossipsub,
            },
            gate: HandshakeGate::default(),
            scope,
            gossip_topics: GossipTopics::new(scope),
            small_transaction_bytes,
            peer_budget,
            handshake_timeout,
            timer: Delay::new(HANDSHAKE_TICK),
            queued_events: VecDeque::new(),
            closes: VecDeque::new(),
        }
    }

    pub fn begin_handshake(
        &mut self,
        peer: PeerId,
        mut hello: Hello,
    ) -> Result<OutboundRequestId, ApplicationGateError> {
        let mut challenge = vec![0_u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);
        hello.challenge.clone_from(&challenge);
        let request = hello_envelope(&hello)
            .map_err(|error| ApplicationGateError::Hello(error.to_string()))?;
        let request_id = self.protocols.hello.send_request(&peer, request);
        self.gate
            .pending
            .insert(request_id, PendingHello { peer, challenge });
        Ok(request_id)
    }

    pub fn send_hello_response(
        &mut self,
        channel: ResponseChannel<NetworkEnvelope>,
        response: NetworkEnvelope,
    ) -> Result<(), NetworkEnvelope> {
        self.protocols.hello.send_response(channel, response)
    }

    pub fn is_peer_authenticated(&self, peer: &PeerId) -> bool {
        self.gate.is_peer_authenticated(peer)
    }

    pub fn is_connection_authenticated(&self, peer: &PeerId, connection_id: ConnectionId) -> bool {
        self.gate.is_connection_authenticated(peer, connection_id)
    }

    pub fn peer_supports(&self, peer: &PeerId, capability: u64) -> bool {
        self.gate.peer_supports(peer, capability)
    }

    pub fn connection_supports(
        &self,
        peer: &PeerId,
        connection_id: ConnectionId,
        capability: u64,
    ) -> bool {
        self.gate
            .connection_supports(peer, connection_id, capability)
    }

    pub fn remote_hello(&self, connection_id: ConnectionId) -> Option<&Hello> {
        self.gate.remote_hello(connection_id)
    }

    pub fn admit_peer_resources(
        &mut self,
        peer: PeerId,
        bytes: usize,
        validation_work: u64,
    ) -> Result<(), BudgetRejection> {
        self.peer_budget
            .admit(peer, bytes.try_into().unwrap_or(u64::MAX), validation_work)
    }

    pub fn complete_gossip_validation(
        &mut self,
        token: GossipValidationToken,
        acceptance: MessageAcceptance,
    ) -> bool {
        self.protocols.gossipsub.report_message_validation_result(
            &token.message_id,
            &token.propagation_source,
            acceptance,
        )
    }

    /// Revoke all state for an authenticated identity rebind and close every
    /// affected transport so a fresh Noise + Hello transcript is mandatory.
    pub fn revoke_peer(&mut self, peer: PeerId) {
        self.protocols.content.revoke_peer(&peer);
        self.protocols.signer_direct.revoke_peer(&peer);
        self.protocols.role_directory.revoke_peer(&peer);
        for connection_id in self.gate.revoke_peer(peer) {
            self.closes.push_back((peer, connection_id));
        }
    }

    /// Atomically prepare and commit the versioned authorization view used by
    /// signer admission and the private role directory. Every fallible step
    /// operates on owned candidate state; installation is infallible.
    pub fn apply_authorization_snapshot(
        &mut self,
        snapshot: AuthorizationSnapshot,
    ) -> Result<AuthorizationSnapshotUpdate, AuthorizationSnapshotError> {
        let prepared = Self::prepare_authorization_with(
            &snapshot,
            |snapshot| {
                self.protocols
                    .signer_direct
                    .prepare_authorization_snapshot(snapshot)
            },
            |snapshot| {
                self.protocols
                    .role_directory
                    .prepare_authorization_snapshot(snapshot)
            },
            self.protocols
                .signer_direct
                .authorization_state()
                .all_peers(),
        )?;
        let signer_update = self
            .protocols
            .signer_direct
            .commit_authorization_snapshot(prepared.signer);
        let directory_update = self
            .protocols
            .role_directory
            .commit_authorization_snapshot(prepared.directory);
        debug_assert_eq!(signer_update, directory_update);
        debug_assert_eq!(signer_update, prepared.update);
        let after = self
            .protocols
            .signer_direct
            .authorization_state()
            .all_peers();
        for peer in prepared
            .previously_bound
            .difference(&after)
            .copied()
            .collect::<Vec<_>>()
        {
            self.revoke_peer(peer);
        }
        Ok(signer_update)
    }

    fn prepare_authorization_with<SignerPrepare, DirectoryPrepare>(
        snapshot: &AuthorizationSnapshot,
        signer_prepare: SignerPrepare,
        directory_prepare: DirectoryPrepare,
        previously_bound: std::collections::BTreeSet<PeerId>,
    ) -> Result<PreparedApplicationAuthorization, AuthorizationSnapshotError>
    where
        SignerPrepare: FnOnce(
            &AuthorizationSnapshot,
        )
            -> Result<PreparedSignerAuthorization, AuthorizationSnapshotError>,
        DirectoryPrepare:
            FnOnce(
                &AuthorizationSnapshot,
            )
                -> Result<PreparedDirectoryAuthorization, AuthorizationSnapshotError>,
    {
        let signer = signer_prepare(snapshot)?;
        let directory = directory_prepare(snapshot)?;
        if signer.update() != directory.update() {
            return Err(AuthorizationSnapshotError::ConsumerDivergence);
        }
        Ok(PreparedApplicationAuthorization {
            update: signer.update().clone(),
            signer,
            directory,
            previously_bound,
        })
    }

    pub fn signer(&self) -> &SignerBehaviour {
        &self.protocols.signer_direct
    }

    pub fn signer_mut(&mut self) -> &mut SignerBehaviour {
        &mut self.protocols.signer_direct
    }

    pub fn role_directory(&self) -> &RoleDirectoryBehaviour {
        &self.protocols.role_directory
    }

    pub fn role_directory_mut(&mut self) -> &mut RoleDirectoryBehaviour {
        &mut self.protocols.role_directory
    }

    pub fn start_content_fetch(
        &mut self,
        kind: ObjectKind,
        id: ContentId,
        providers: impl IntoIterator<Item = PeerId>,
    ) -> Result<bool, ApplicationGateError> {
        let providers = providers.into_iter().collect::<Vec<_>>();
        if providers
            .iter()
            .all(|peer| !self.gate.peer_supports(peer, CAP_OBJECT_FETCH))
        {
            return Err(ApplicationGateError::Unauthenticated);
        }
        self.protocols
            .content
            .start_fetch(kind, id, providers)
            .map_err(ApplicationGateError::Hello)
    }

    #[cfg(test)]
    pub(super) fn send_content_request_unchecked(
        &mut self,
        peer: &PeerId,
        request: NetworkEnvelope,
    ) -> OutboundRequestId {
        let (kind, id) = decode_content_request(&request, self.scope.chain_id()).unwrap();
        self.protocols.content.send_fetch_unchecked(peer, kind, id)
    }

    pub fn respond_content_fetch(
        &mut self,
        response_token: u64,
        status: Status,
        object: Option<&stacks_network_types::NetworkObject>,
    ) -> Result<(), String> {
        self.protocols
            .content
            .respond_fetch(response_token, status, object)
    }

    pub fn send_content_push(
        &mut self,
        peer: &PeerId,
        object: &stacks_network_types::NetworkObject,
    ) -> Result<OutboundRequestId, ApplicationGateError> {
        if !self.gate.peer_supports(peer, CAP_CONTENT_PUSH) {
            return Err(ApplicationGateError::Unauthenticated);
        }
        self.protocols
            .content
            .push(peer, object)
            .map_err(ApplicationGateError::Hello)
    }

    pub fn respond_content_push(
        &mut self,
        response_token: u64,
        status: Status,
    ) -> Result<(), String> {
        self.protocols.content.respond_push(response_token, status)
    }

    pub fn is_content_fetching(&self, id: &ContentId) -> bool {
        self.protocols.content.is_fetching(id)
    }

    pub fn pending_content_fetches(&self) -> usize {
        self.protocols.content.pending_fetches()
    }

    pub fn deferred_content_fetches(&self) -> usize {
        self.protocols.content.deferred_fetches()
    }

    pub fn queue_content_announcement(
        &mut self,
        announcement: Announcement,
        encoded_bytes: usize,
    ) -> Result<bool, String> {
        self.protocols
            .content
            .queue_announcement(announcement, encoded_bytes)
    }

    pub fn queue_content_transaction(
        &mut self,
        object: NetworkObject,
        encoded_bytes: usize,
    ) -> Result<(), String> {
        self.protocols
            .content
            .queue_transaction(object, encoded_bytes)
    }

    pub fn remember_content_announcement(&mut self, content_id: ContentId) {
        self.protocols.content.remember_announcement(content_id);
    }

    pub fn complete_content_publication(
        &mut self,
        token: u64,
        outcome: PublicationOutcome,
    ) -> Result<(), String> {
        self.protocols.content.complete_publication(token, outcome)
    }

    pub fn select_direct_push_targets(
        &self,
        candidates: impl IntoIterator<Item = DirectPushCandidate>,
        requested_fanout: usize,
    ) -> Vec<PeerId> {
        self.protocols
            .content
            .select_direct_push_targets(candidates, requested_fanout)
    }

    pub fn pending_content_fetch_request(
        &self,
        response_token: u64,
    ) -> Option<(PeerId, ObjectKind, ContentId)> {
        self.protocols.content.pending_fetch_request(response_token)
    }

    pub fn stage_content_event(
        &mut self,
        event: ObjectNetworkEvent,
    ) -> Result<(), crate::content_behaviour::DownstreamQueueFull> {
        self.protocols.content.stage_downstream_event(event)
    }

    pub fn restore_content_event(
        &mut self,
        event: ObjectNetworkEvent,
    ) -> Result<(), crate::content_behaviour::DownstreamQueueFull> {
        self.protocols.content.restore_downstream_event(event)
    }

    pub fn pop_content_event(&mut self) -> Option<ObjectNetworkEvent> {
        self.protocols.content.pop_downstream_event()
    }

    pub fn has_content_events(&self) -> bool {
        self.protocols.content.has_downstream_events()
    }

    pub fn pending_content_events(&self) -> usize {
        self.protocols.content.pending_downstream_events()
    }

    pub fn can_stage_content_object(&self, object: &NetworkObject) -> bool {
        self.protocols.content.can_stage_downstream_object(object)
    }

    pub fn send_sync_request(
        &mut self,
        peer: &PeerId,
        request: SyncRequest,
        owner: SyncRequestOwner,
    ) -> Result<OutboundRequestId, ApplicationGateError> {
        if !self.gate.peer_supports(peer, CAP_SYNC) {
            return Err(ApplicationGateError::Unauthenticated);
        }
        self.protocols
            .sync
            .send_request(peer, request, owner)
            .map_err(ApplicationGateError::Hello)
    }

    /// Admit bounded signer-replay requests as one application transition.
    /// A replay is marked requested only after the sync behaviour owns its
    /// outbound request; the infallible marker cannot strand partial state.
    pub fn request_signer_replays_for_peer(
        &mut self,
        peer: PeerId,
        cycles: impl IntoIterator<Item = u64>,
    ) -> usize {
        let mut sent = 0;
        for reward_cycle in cycles {
            if !self
                .protocols
                .signer_direct
                .replay_needed(peer, reward_cycle)
            {
                continue;
            }
            let mut cursors = self.protocols.signer_direct.cursors(reward_cycle);
            cursors.truncate(crate::MAX_SIGNER_REPLAY_ITEMS);
            let request = SyncRequest {
                request: Some(sync_request::Request::GetSignerReplay(GetSignerReplay {
                    reward_cycle,
                    cursors,
                    max_items: SIGNER_REPLAY_PAGE_ITEMS as u32,
                    max_bytes: crate::MAX_SIGNER_REPLAY_BYTES as u32,
                })),
            };
            if self
                .send_sync_request(
                    &peer,
                    request,
                    SyncRequestOwner::SignerReplay { reward_cycle },
                )
                .is_err()
            {
                continue;
            }
            self.protocols
                .signer_direct
                .mark_replay_requested(peer, reward_cycle);
            sent += 1;
        }
        sent
    }

    pub fn start_sync_request(
        &mut self,
        providers: impl IntoIterator<Item = PeerId>,
        request: SyncRequest,
        correlation_id: u64,
        max_parallel: usize,
        hedge_delay: Duration,
    ) -> Result<u64, ApplicationGateError> {
        let providers = providers
            .into_iter()
            .filter(|peer| self.gate.peer_supports(peer, CAP_SYNC))
            .collect::<Vec<_>>();
        if providers.is_empty() {
            return Err(ApplicationGateError::Unauthenticated);
        }
        self.protocols
            .sync
            .start_request(
                request,
                providers,
                SyncRequestOwner::ExternalManaged { correlation_id },
                max_parallel,
                hedge_delay,
            )
            .map_err(ApplicationGateError::Hello)
    }

    pub fn respond_sync(
        &mut self,
        response_token: u64,
        response: SyncResponse,
    ) -> Result<(), String> {
        self.protocols.sync.respond(response_token, response)
    }

    pub(super) fn publish_gossip(
        &mut self,
        topic: impl Into<TopicHash>,
        data: impl Into<Vec<u8>>,
    ) -> Result<MessageId, PublishError> {
        self.protocols.gossipsub.publish(topic, data)
    }

    pub fn peer_score(&self, peer: &PeerId) -> Option<f64> {
        self.protocols.gossipsub.peer_score(peer)
    }

    pub fn gossip_topics(&self) -> impl Iterator<Item = &TopicHash> {
        self.protocols.gossipsub.topics()
    }

    fn handle_child_event(
        &mut self,
        event: ApplicationProtocolsEvent,
    ) -> Option<StacksApplicationEvent> {
        match event {
            ApplicationProtocolsEvent::Hello(event) => self.handle_hello_event(event),
            ApplicationProtocolsEvent::SignerDirect(event) => self.filter_signer(event),
            ApplicationProtocolsEvent::RoleDirectory(event) => self.filter_directory(event),
            ApplicationProtocolsEvent::Content(event) => self.filter_content(event),
            ApplicationProtocolsEvent::Sync(event) => self.filter_sync(event),
            ApplicationProtocolsEvent::Gossipsub(event) => {
                if let Some(peer) = gossipsub_event_peer(&event) {
                    if !self.gate.is_peer_authenticated(&peer) {
                        self.queued_events
                            .push_back(StacksApplicationEvent::PreHelloRejected {
                                peer,
                                connection_id: None,
                                protocol: ApplicationProtocol::Gossipsub,
                            });
                        return None;
                    }
                }
                self.filter_gossip(event)
            }
        }
    }

    fn handle_hello_event(
        &mut self,
        event: request_response::Event<NetworkEnvelope, NetworkEnvelope>,
    ) -> Option<StacksApplicationEvent> {
        match event {
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Request {
                        request_id,
                        request,
                        channel,
                    },
            } => {
                let result = self
                    .gate
                    .observe_hello_id(connection_id, peer, request.content_id())
                    .and_then(|_| {
                        validate_hello(&request, self.scope)
                            .map_err(|_| HelloRejectionReason::WrongChainOrMalformed)
                    })
                    .and_then(|hello| {
                        self.gate
                            .authenticate(connection_id, peer, hello)
                            .map(|_| ())
                    });
                if let Err(reason) = result {
                    let response = hello_status_response_envelope(
                        self.scope.chain_id(),
                        Status::InvalidRequest,
                    );
                    let _ = self.protocols.hello.send_response(channel, response);
                    self.queued_events
                        .push_back(StacksApplicationEvent::HelloRejected {
                            peer,
                            connection_id,
                            reason,
                        });
                    self.gate.remove(connection_id);
                    self.closes.push_back((peer, connection_id));
                    return None;
                }
                if let Some(capabilities) = self
                    .gate
                    .remote_hello(connection_id)
                    .map(|hello| hello.capabilities)
                {
                    self.protocols.content.authenticate_peer(peer, capabilities);
                    self.protocols
                        .signer_direct
                        .authenticate_peer(peer, capabilities);
                    self.protocols
                        .role_directory
                        .authenticate_peer(peer, capabilities);
                }
                Some(StacksApplicationEvent::Hello(
                    request_response::Event::Message {
                        peer,
                        connection_id,
                        message: request_response::Message::Request {
                            request_id,
                            request,
                            channel,
                        },
                    },
                ))
            }
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
            } => {
                let result = self
                    .gate
                    .pending
                    .remove(&request_id)
                    .filter(|pending| pending.peer == peer)
                    .ok_or(HelloRejectionReason::ChallengeOrResponse)
                    .and_then(|pending| {
                        validate_hello_response(&response, self.scope, &pending.challenge)
                            .map_err(|_| HelloRejectionReason::ChallengeOrResponse)
                    })
                    .and_then(|hello| {
                        self.gate
                            .authenticate(connection_id, peer, hello)
                            .map(|_| ())
                    });
                if let Err(reason) = result {
                    self.queued_events
                        .push_back(StacksApplicationEvent::HelloRejected {
                            peer,
                            connection_id,
                            reason,
                        });
                    self.gate.remove(connection_id);
                    self.closes.push_back((peer, connection_id));
                    return None;
                }
                if let Some(capabilities) = self
                    .gate
                    .remote_hello(connection_id)
                    .map(|hello| hello.capabilities)
                {
                    self.protocols.content.authenticate_peer(peer, capabilities);
                    self.protocols
                        .signer_direct
                        .authenticate_peer(peer, capabilities);
                    self.protocols
                        .role_directory
                        .authenticate_peer(peer, capabilities);
                }
                Some(StacksApplicationEvent::Hello(
                    request_response::Event::Message {
                        peer,
                        connection_id,
                        message: request_response::Message::Response {
                            request_id,
                            response,
                        },
                    },
                ))
            }
            request_response::Event::OutboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            } => {
                self.gate.pending.remove(&request_id);
                Some(StacksApplicationEvent::Hello(
                    request_response::Event::OutboundFailure {
                        peer,
                        connection_id,
                        request_id,
                        error,
                    },
                ))
            }
            other => Some(StacksApplicationEvent::Hello(other)),
        }
    }

    fn filter_signer(&mut self, event: SignerBehaviourEvent) -> Option<StacksApplicationEvent> {
        if let SignerBehaviourEvent::AdmissionRequired {
            token,
            peer,
            connection_id,
            ..
        } = &event
        {
            if !self
                .gate
                .connection_supports(peer, *connection_id, CAP_SIGNER_SEMANTICS)
            {
                self.protocols.signer_direct.reject_action(*token);
                self.queued_events
                    .push_back(StacksApplicationEvent::PreHelloRejected {
                        peer: *peer,
                        connection_id: Some(*connection_id),
                        protocol: ApplicationProtocol::SignerDirect,
                    });
                return None;
            }
        }
        Some(StacksApplicationEvent::SignerDirect(event))
    }

    fn filter_sync(&mut self, event: SyncBehaviourEvent) -> Option<StacksApplicationEvent> {
        let connection = match &event {
            SyncBehaviourEvent::InboundRequest {
                peer,
                connection_id,
                ..
            }
            | SyncBehaviourEvent::Response {
                peer,
                connection_id,
                ..
            }
            | SyncBehaviourEvent::InboundRejected {
                peer,
                connection_id,
                ..
            } => Some((*peer, *connection_id)),
            SyncBehaviourEvent::ProviderAttemptFailed { .. }
            | SyncBehaviourEvent::OutboundFailure { .. }
            | SyncBehaviourEvent::ManagedExpired { .. }
            | SyncBehaviourEvent::InboundExpired { .. } => None,
        };
        if let Some((peer, connection_id)) = connection {
            if self
                .gate
                .connection_supports(&peer, connection_id, CAP_SYNC)
            {
                return Some(StacksApplicationEvent::Sync(event));
            }
            if let SyncBehaviourEvent::InboundRequest { response_token, .. } = event {
                self.protocols
                    .sync
                    .reject_inbound(response_token, Status::Unauthorized);
            }
            self.queued_events
                .push_back(StacksApplicationEvent::PreHelloRejected {
                    peer,
                    connection_id: Some(connection_id),
                    protocol: ApplicationProtocol::Sync,
                });
            return None;
        }
        Some(StacksApplicationEvent::Sync(event))
    }

    fn filter_directory(
        &mut self,
        event: RoleDirectoryBehaviourEvent,
    ) -> Option<StacksApplicationEvent> {
        let RoleDirectoryBehaviourEvent::AdmissionRequired {
            token,
            peer,
            connection_id,
            ..
        } = &event
        else {
            return Some(StacksApplicationEvent::RoleDirectory(event));
        };
        if self
            .gate
            .connection_supports(peer, *connection_id, CAP_ROLE_DIRECTORY)
        {
            return Some(StacksApplicationEvent::RoleDirectory(event));
        }
        let _ = self
            .protocols
            .role_directory
            .reject_action(*token, Status::Unauthorized);
        self.queued_events
            .push_back(StacksApplicationEvent::PreHelloRejected {
                peer: *peer,
                connection_id: Some(*connection_id),
                protocol: ApplicationProtocol::RoleDirectory,
            });
        None
    }

    fn filter_content(&mut self, event: ContentExchangeEvent) -> Option<StacksApplicationEvent> {
        let connection = match &event {
            ContentExchangeEvent::InboundFetch {
                peer,
                connection_id,
                ..
            }
            | ContentExchangeEvent::Fetched {
                peer,
                connection_id,
                ..
            }
            | ContentExchangeEvent::InboundPush {
                peer,
                connection_id,
                ..
            }
            | ContentExchangeEvent::Rejected {
                peer,
                connection_id,
                ..
            } => Some((*peer, *connection_id)),
            ContentExchangeEvent::PushResult {
                peer,
                connection_id: Some(connection_id),
                ..
            } => Some((*peer, *connection_id)),
            ContentExchangeEvent::Publish { .. }
            | ContentExchangeEvent::FetchStarted { .. }
            | ContentExchangeEvent::FetchFailed { .. }
            | ContentExchangeEvent::ProviderFailed { .. }
            | ContentExchangeEvent::PushResult {
                connection_id: None,
                ..
            }
            | ContentExchangeEvent::InboundExpired { .. } => None,
        };
        if let Some((peer, connection_id)) = connection {
            let capability = match &event {
                ContentExchangeEvent::InboundPush { .. }
                | ContentExchangeEvent::PushResult { .. } => CAP_CONTENT_PUSH,
                _ => CAP_OBJECT_FETCH,
            };
            if self
                .gate
                .connection_supports(&peer, connection_id, capability)
            {
                return Some(StacksApplicationEvent::Content(event));
            }
            match event {
                ContentExchangeEvent::InboundFetch { response_token, .. } => {
                    self.protocols.content.reject_inbound(
                        response_token,
                        ContentProtocolKind::Fetch,
                        Status::Unauthorized,
                    )
                }
                ContentExchangeEvent::InboundPush { response_token, .. } => {
                    self.protocols.content.reject_inbound(
                        response_token,
                        ContentProtocolKind::Push,
                        Status::Unauthorized,
                    )
                }
                _ => {}
            }
            self.queued_events
                .push_back(StacksApplicationEvent::PreHelloRejected {
                    peer,
                    connection_id: Some(connection_id),
                    protocol: ApplicationProtocol::Content,
                });
            return None;
        }
        Some(StacksApplicationEvent::Content(event))
    }

    fn filter_gossip(&mut self, event: gossipsub::Event) -> Option<StacksApplicationEvent> {
        let gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        } = event
        else {
            return None;
        };
        let topic = self.gossip_topics.classify(&message.topic);
        let Some(topic) = topic else {
            self.reject_gossip(
                propagation_source,
                message_id,
                None,
                GossipRejectionReason::UnknownTopic,
            );
            return None;
        };
        if !self
            .gate
            .peer_supports(&propagation_source, topic.required_capability())
        {
            self.reject_gossip(
                propagation_source,
                message_id,
                Some(topic),
                GossipRejectionReason::UnauthenticatedOrIncapable,
            );
            return None;
        }
        if let Err(reason) = self.admit_peer_resources(propagation_source, message.data.len(), 8) {
            self.reject_gossip(
                propagation_source,
                message_id,
                Some(topic),
                GossipRejectionReason::Resource(reason),
            );
            return None;
        }
        let Some(source) = message.source else {
            self.reject_gossip(
                propagation_source,
                message_id,
                Some(topic),
                GossipRejectionReason::UnsignedSource,
            );
            return None;
        };
        let payload = match topic {
            GossipTopicClass::Signer => SignerEnvelope::decode(message.data.as_slice())
                .map_err(|error| format!("invalid signer protobuf: {error}"))
                .and_then(|envelope| {
                    self.protocols
                        .signer_direct
                        .stage_gossip(propagation_source, source, envelope)
                })
                .map(|staged| staged.map(Box::new).map(AuthenticatedGossip::Signer)),
            GossipTopicClass::BlockAnnouncement => {
                NetworkEnvelope::decode(&message.data, EnvelopeLimits::BLOCK)
                    .map_err(|error| error.to_string())
                    .and_then(|envelope| decode_announcement(&envelope, self.scope.chain_id()))
                    .map(|announcement| Some(AuthenticatedGossip::BlockAnnouncement(announcement)))
            }
            GossipTopicClass::Transaction => {
                NetworkEnvelope::decode(&message.data, EnvelopeLimits::BLOCK)
                    .map_err(|error| error.to_string())
                    .and_then(|envelope| decode_content_push(&envelope, self.scope.chain_id()))
                    .and_then(|object| {
                        if object.kind != ObjectKind::Transaction
                            || object.bytes.len() > self.small_transaction_bytes
                        {
                            return Err("transaction gossip violates kind/size policy".to_owned());
                        }
                        Ok(Some(AuthenticatedGossip::Transaction(object)))
                    })
            }
        };
        let payload = match payload {
            Ok(Some(payload)) => payload,
            Ok(None) => {
                let _ = self.protocols.gossipsub.report_message_validation_result(
                    &message_id,
                    &propagation_source,
                    MessageAcceptance::Ignore,
                );
                return None;
            }
            Err(error) => {
                self.reject_gossip(
                    propagation_source,
                    message_id,
                    Some(topic),
                    GossipRejectionReason::InvalidPayload(error),
                );
                return None;
            }
        };
        Some(StacksApplicationEvent::Gossip(AuthenticatedGossipMessage {
            propagation_source,
            source,
            payload,
            validation: GossipValidationToken {
                message_id,
                propagation_source,
            },
        }))
    }

    fn reject_gossip(
        &mut self,
        peer: PeerId,
        message_id: MessageId,
        topic: Option<GossipTopicClass>,
        reason: GossipRejectionReason,
    ) {
        let _ = self.protocols.gossipsub.report_message_validation_result(
            &message_id,
            &peer,
            MessageAcceptance::Reject,
        );
        self.queued_events
            .push_back(StacksApplicationEvent::GossipRejected {
                peer,
                topic,
                reason,
            });
    }

    fn expire_handshakes(&mut self, now: Instant) {
        for (peer, connection_id) in self.gate.expired(now, self.handshake_timeout) {
            self.gate.remove(connection_id);
            self.queued_events
                .push_back(StacksApplicationEvent::HelloRejected {
                    peer,
                    connection_id,
                    reason: HelloRejectionReason::Timeout,
                });
            self.closes.push_back((peer, connection_id));
        }
    }
}

impl NetworkBehaviour for StacksApplicationBehaviour {
    type ConnectionHandler = <ApplicationProtocols as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = StacksApplicationEvent;

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
        self.gate.established(connection_id, peer, Instant::now());
        let result = self.protocols.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        );
        if result.is_err() {
            self.gate.remove(connection_id);
        }
        result
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.gate.established(connection_id, peer, Instant::now());
        let result = self.protocols.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        );
        if result.is_err() {
            self.gate.remove(connection_id);
        }
        result
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionClosed(event) => {
                self.gate.remove(event.connection_id);
                if !self.gate.is_peer_authenticated(&event.peer_id) {
                    self.peer_budget.remove(&event.peer_id);
                    self.protocols.signer_direct.disconnect_peer(&event.peer_id);
                    self.protocols.role_directory.revoke_peer(&event.peer_id);
                }
            }
            FromSwarm::DialFailure(event) => {
                self.gate.remove(event.connection_id);
            }
            FromSwarm::ListenFailure(event) => {
                self.gate.remove(event.connection_id);
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
            self.expire_handshakes(Instant::now());
            self.peer_budget.prune_idle();
            self.timer.reset(HANDSHAKE_TICK);
        }
        if let Some((peer_id, connection_id)) = self.closes.pop_front() {
            return Poll::Ready(ToSwarm::CloseConnection {
                peer_id,
                connection: CloseConnection::One(connection_id),
            });
        }
        if let Some(event) = self.queued_events.pop_front() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }
        loop {
            let event = ready!(self.protocols.poll(cx));
            match event {
                ToSwarm::GenerateEvent(event) => {
                    if let Some(event) = self.handle_child_event(event) {
                        return Poll::Ready(ToSwarm::GenerateEvent(event));
                    }
                    if let Some(event) = self.queued_events.pop_front() {
                        return Poll::Ready(ToSwarm::GenerateEvent(event));
                    }
                }
                other => return Poll::Ready(other.map_out(|_| unreachable!())),
            }
        }
    }
}

fn gossipsub_event_peer(event: &gossipsub::Event) -> Option<PeerId> {
    match event {
        gossipsub::Event::Message {
            propagation_source, ..
        } => Some(*propagation_source),
        gossipsub::Event::Subscribed { peer_id, .. }
        | gossipsub::Event::Unsubscribed { peer_id, .. }
        | gossipsub::Event::GossipsubNotSupported { peer_id }
        | gossipsub::Event::SlowPeer { peer_id, .. } => Some(*peer_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
    use stacks_network_types::wire::v1::Role;
    use stacks_network_types::CAP_NODE_V1;

    use crate::{content_push_envelope, NetworkConfig, RoleAuthorization, StacksBehaviour};

    fn hello(chain_id: u32, network_id: u32) -> Hello {
        Hello {
            envelope_version: 1,
            chain_id,
            network_id,
            supported_protocol_versions: vec![1],
            peer_version: 1,
            capabilities: 0,
            burn_tip_height: 0,
            burn_tip_hash: vec![],
            stable_burn_tip_height: 0,
            stable_burn_tip_hash: vec![],
            stacks_tip_height: 0,
            stacks_tip_id: vec![],
            current_reward_cycle: 0,
            advertised_multiaddrs: vec![],
            legacy_identity_binding: None,
            challenge: vec![1; 32],
        }
    }

    fn signer_authorization(reward_cycle: u64, seed: u8) -> RoleAuthorization {
        let key = StacksPrivateKey::from_seed(&[seed; 32]);
        RoleAuthorization {
            role: Role::Signer,
            reward_cycle,
            role_id: Some(u32::from(seed).to_be_bytes().to_vec()),
            key: crate::AuthorizedRoleKey::PublicKey(
                StacksPublicKey::from_private(&key)
                    .to_bytes_compressed()
                    .try_into()
                    .unwrap(),
            ),
        }
    }

    fn test_behaviour() -> StacksBehaviour {
        let identity = libp2p::identity::Keypair::generate_ed25519();
        StacksBehaviour::new(&identity, &NetworkConfig::regtest()).unwrap()
    }

    fn authenticate(application: &mut StacksApplicationBehaviour, peer: PeerId, capabilities: u64) {
        let connection = ConnectionId::new_unchecked(1);
        application
            .gate
            .established(connection, peer, Instant::now());
        let mut remote = hello(application.scope.chain_id(), application.scope.network_id());
        remote.capabilities = capabilities;
        application
            .gate
            .authenticate(connection, peer, remote)
            .unwrap();
        application
            .protocols
            .signer_direct
            .authenticate_peer(peer, capabilities);
        application
            .protocols
            .content
            .authenticate_peer(peer, capabilities);
        application
            .protocols
            .role_directory
            .authenticate_peer(peer, capabilities);
    }

    fn gossip_event(
        propagation_source: PeerId,
        source: Option<PeerId>,
        topic: TopicHash,
        data: Vec<u8>,
    ) -> gossipsub::Event {
        gossipsub::Event::Message {
            propagation_source,
            message_id: MessageId::from("typed-gossip-test"),
            message: gossipsub::Message {
                source,
                data,
                sequence_number: Some(1),
                topic,
            },
        }
    }

    #[test]
    fn gate_is_connection_scoped_and_replay_safe() {
        let now = Instant::now();
        let peer = PeerId::random();
        let first = ConnectionId::new_unchecked(1);
        let second = ConnectionId::new_unchecked(2);
        let mut gate = HandshakeGate::default();
        gate.established(first, peer, now);
        gate.established(second, peer, now);
        let remote = hello(1, 2);
        let id = hello_envelope(&remote).unwrap().content_id();
        gate.observe_hello_id(first, peer, id).unwrap();
        assert_eq!(
            gate.observe_hello_id(first, peer, id),
            Err(HelloRejectionReason::Replay)
        );
        gate.authenticate(first, peer, remote).unwrap();
        assert!(gate.is_connection_authenticated(&peer, first));
        assert!(!gate.is_connection_authenticated(&peer, second));
        assert!(gate.is_peer_authenticated(&peer));
        gate.remove(first);
        assert!(!gate.is_peer_authenticated(&peer));
    }

    #[test]
    fn timeout_and_rekey_leave_no_authenticated_state() {
        let now = Instant::now();
        let peer = PeerId::random();
        let first = ConnectionId::new_unchecked(1);
        let second = ConnectionId::new_unchecked(2);
        let mut gate = HandshakeGate::default();
        gate.established(first, peer, now);
        assert!(gate
            .expired(now + Duration::from_secs(9), Duration::from_secs(10))
            .is_empty());
        assert_eq!(
            gate.expired(now + Duration::from_secs(10), Duration::from_secs(10)),
            vec![(peer, first)]
        );
        gate.authenticate(first, peer, hello(1, 2)).unwrap();
        gate.established(second, peer, now);
        assert_eq!(gate.revoke_peer(peer).len(), 2);
        assert!(!gate.is_peer_authenticated(&peer));
    }

    #[test]
    fn peer_capabilities_cannot_leak_between_connections() {
        let now = Instant::now();
        let peer = PeerId::random();
        let first = ConnectionId::new_unchecked(1);
        let second = ConnectionId::new_unchecked(2);
        let mut gate = HandshakeGate::default();
        gate.established(first, peer, now);
        gate.established(second, peer, now);

        let mut capable = hello(1, 2);
        capable.capabilities = CAP_SYNC;
        gate.authenticate(first, peer, capable).unwrap();
        assert!(gate.connection_supports(&peer, first, CAP_SYNC));
        assert!(!gate.peer_supports(&peer, CAP_SYNC));

        gate.authenticate(second, peer, hello(1, 2)).unwrap();
        assert!(!gate.connection_supports(&peer, second, CAP_SYNC));
        assert!(!gate.peer_supports(&peer, CAP_SYNC));

        gate.remove(second);
        assert!(gate.peer_supports(&peer, CAP_SYNC));
    }

    #[test]
    fn authorization_prepare_failure_never_partially_commits() {
        let mut behaviour = test_behaviour();
        let signer = signer_authorization(9, 1);
        let snapshot = AuthorizationSnapshot::new(7, 9, None, [signer.clone()]).unwrap();

        let signer_rejected = StacksApplicationBehaviour::prepare_authorization_with(
            &snapshot,
            |_| Err(AuthorizationSnapshotError::CycleScope),
            |_| panic!("directory preparation must not run after signer rejection"),
            Default::default(),
        );
        assert!(matches!(
            signer_rejected,
            Err(AuthorizationSnapshotError::CycleScope)
        ));

        let application = behaviour.application_mut();
        let directory_rejected = StacksApplicationBehaviour::prepare_authorization_with(
            &snapshot,
            |snapshot| {
                application
                    .protocols
                    .signer_direct
                    .prepare_authorization_snapshot(snapshot)
            },
            |_| Err(AuthorizationSnapshotError::MissingAppliedState),
            Default::default(),
        );
        assert!(matches!(
            directory_rejected,
            Err(AuthorizationSnapshotError::MissingAppliedState)
        ));

        // Both rejected preparations were clone-only. Retrying the exact same
        // generation remains applicable to both consumers.
        assert!(behaviour
            .application()
            .signer()
            .authorization_state()
            .authorized_keys(9)
            .is_empty());
        assert!(matches!(
            behaviour
                .application_mut()
                .apply_authorization_snapshot(snapshot.clone())
                .unwrap(),
            AuthorizationSnapshotUpdate::Changed { generation: 7, .. }
        ));
        assert_eq!(
            behaviour
                .application()
                .signer()
                .authorization_state()
                .authorized_keys(9),
            [match signer.key {
                crate::AuthorizedRoleKey::PublicKey(key) => key,
                crate::AuthorizedRoleKey::PublicKeyHash160(_) => unreachable!(),
            }]
            .into_iter()
            .collect()
        );
        assert!(matches!(
            behaviour
                .application_mut()
                .apply_authorization_snapshot(snapshot)
                .unwrap(),
            AuthorizationSnapshotUpdate::Unchanged { generation: 7, .. }
        ));
    }

    #[test]
    fn gossip_topic_registry_is_network_scoped_and_fail_closed() {
        let topics = GossipTopics::new(NetworkScope::new(0x8000_0000, 0x8000_0000));
        assert_eq!(
            topics.classify(&signer_topic(0x8000_0000, 0x8000_0000).hash()),
            Some(GossipTopicClass::Signer)
        );
        assert_eq!(
            topics.classify(&block_announcement_topic(0x8000_0000, 0x8000_0000).hash()),
            Some(GossipTopicClass::BlockAnnouncement)
        );
        assert_eq!(
            topics.classify(&transaction_topic(0x8000_0000, 0x8000_0000).hash()),
            Some(GossipTopicClass::Transaction)
        );
        assert_eq!(
            topics.classify(&signer_topic(0x8000_0001, 0x8000_0000).hash()),
            None
        );
        assert_eq!(
            topics.classify(&TopicHash::from_raw("/stacks/unknown/1")),
            None
        );
        assert_eq!(
            GossipTopicClass::Signer.required_capability(),
            CAP_SIGNER_SEMANTICS
        );
        assert_eq!(
            GossipTopicClass::BlockAnnouncement.required_capability(),
            CAP_OBJECT_FETCH
        );
        assert_eq!(
            GossipTopicClass::Transaction.required_capability(),
            CAP_TRANSACTION_GOSSIP
        );
    }

    #[test]
    fn typed_gossip_requires_exact_capability_before_decode() {
        let cases = [
            (
                GossipTopicClass::Signer,
                signer_topic(0x8000_0000, 0x8000_0000).hash(),
                CAP_SIGNER_SEMANTICS,
            ),
            (
                GossipTopicClass::BlockAnnouncement,
                block_announcement_topic(0x8000_0000, 0x8000_0000).hash(),
                CAP_OBJECT_FETCH,
            ),
            (
                GossipTopicClass::Transaction,
                transaction_topic(0x8000_0000, 0x8000_0000).hash(),
                CAP_TRANSACTION_GOSSIP,
            ),
        ];
        for (topic_class, topic, required) in cases {
            let peer = PeerId::random();
            let mut behaviour = test_behaviour();
            let application = behaviour.application_mut();
            authenticate(application, peer, CAP_NODE_V1 & !required);
            assert!(application
                .filter_gossip(gossip_event(peer, Some(peer), topic.clone(), vec![0xff]))
                .is_none());
            assert!(matches!(
                application.queued_events.pop_back(),
                Some(StacksApplicationEvent::GossipRejected {
                    topic: Some(actual),
                    reason: GossipRejectionReason::UnauthenticatedOrIncapable,
                    ..
                }) if actual == topic_class
            ));

            let mut behaviour = test_behaviour();
            let application = behaviour.application_mut();
            authenticate(application, peer, required);
            assert!(application
                .filter_gossip(gossip_event(peer, Some(peer), topic, vec![0xff]))
                .is_none());
            assert!(matches!(
                application.queued_events.pop_back(),
                Some(StacksApplicationEvent::GossipRejected {
                    topic: Some(actual),
                    reason: GossipRejectionReason::InvalidPayload(_),
                    ..
                }) if actual == topic_class
            ));
        }
    }

    #[test]
    fn typed_gossip_rejects_unknown_scope_and_unsigned_messages() {
        let peer = PeerId::random();
        let mut behaviour = test_behaviour();
        let application = behaviour.application_mut();
        authenticate(application, peer, CAP_NODE_V1);

        assert!(application
            .filter_gossip(gossip_event(
                peer,
                Some(peer),
                signer_topic(
                    application.scope.chain_id() + 1,
                    application.scope.network_id(),
                )
                .hash(),
                vec![0],
            ))
            .is_none());
        assert!(matches!(
            application.queued_events.pop_back(),
            Some(StacksApplicationEvent::GossipRejected {
                topic: None,
                reason: GossipRejectionReason::UnknownTopic,
                ..
            })
        ));

        assert!(application
            .filter_gossip(gossip_event(
                peer,
                None,
                transaction_topic(application.scope.chain_id(), application.scope.network_id(),)
                    .hash(),
                vec![0],
            ))
            .is_none());
        assert!(matches!(
            application.queued_events.pop_back(),
            Some(StacksApplicationEvent::GossipRejected {
                topic: Some(GossipTopicClass::Transaction),
                reason: GossipRejectionReason::UnsignedSource,
                ..
            })
        ));
    }

    #[test]
    fn transaction_gossip_enforces_topic_and_size_boundary() {
        let config = NetworkConfig::regtest();
        for size in [
            config.small_transaction_bytes - 1,
            config.small_transaction_bytes,
            config.small_transaction_bytes + 1,
        ] {
            let peer = PeerId::random();
            let mut behaviour = test_behaviour();
            let application = behaviour.application_mut();
            authenticate(application, peer, CAP_TRANSACTION_GOSSIP);
            let object = NetworkObject {
                kind: ObjectKind::Transaction,
                content_id: ContentId::from_domain_bytes(b"typed-gossip-test", &size.to_be_bytes()),
                bytes: vec![7; size],
            };
            let event = gossip_event(
                peer,
                Some(peer),
                transaction_topic(config.chain_id, config.network_id).hash(),
                content_push_envelope(config.chain_id, &object).encode(),
            );
            let emitted = application.filter_gossip(event);
            if size <= config.small_transaction_bytes {
                assert!(matches!(
                    emitted,
                    Some(StacksApplicationEvent::Gossip(AuthenticatedGossipMessage {
                        payload: AuthenticatedGossip::Transaction(ref actual),
                        ..
                    })) if actual == &object
                ));
            } else {
                assert!(emitted.is_none());
                assert!(matches!(
                    application.queued_events.pop_back(),
                    Some(StacksApplicationEvent::GossipRejected {
                        reason: GossipRejectionReason::InvalidPayload(_),
                        ..
                    })
                ));
            }
        }

        let peer = PeerId::random();
        let mut behaviour = test_behaviour();
        let application = behaviour.application_mut();
        authenticate(application, peer, CAP_OBJECT_FETCH);
        let object = NetworkObject {
            kind: ObjectKind::Transaction,
            content_id: ContentId::from_bytes([9; 32]),
            bytes: vec![1],
        };
        assert!(application
            .filter_gossip(gossip_event(
                peer,
                Some(peer),
                block_announcement_topic(config.chain_id, config.network_id).hash(),
                content_push_envelope(config.chain_id, &object).encode(),
            ))
            .is_none());
        assert!(matches!(
            application.queued_events.pop_back(),
            Some(StacksApplicationEvent::GossipRejected {
                topic: Some(GossipTopicClass::BlockAnnouncement),
                reason: GossipRejectionReason::InvalidPayload(_),
                ..
            })
        ));
    }

    #[test]
    fn signer_replay_request_and_marker_commit_atomically() {
        let peer = PeerId::random();
        let other_peer = PeerId::random();
        let mut behaviour = test_behaviour();
        let application = behaviour.application_mut();

        assert_eq!(application.request_signer_replays_for_peer(peer, [9]), 0);
        assert!(application.protocols.signer_direct.replay_needed(peer, 9));
        assert_eq!(application.protocols.sync.pending_outbound_len(), 0);

        authenticate(application, peer, CAP_SYNC);
        assert_eq!(application.request_signer_replays_for_peer(peer, [9]), 1);
        assert!(!application.protocols.signer_direct.replay_needed(peer, 9));
        assert_eq!(application.protocols.sync.pending_outbound_len(), 1);

        // The sync behaviour admits eight requests per peer in the regtest
        // profile. A request refused at capacity never commits its replay
        // marker and therefore remains retryable.
        assert_eq!(
            application.request_signer_replays_for_peer(peer, 10..=20),
            7
        );
        assert_eq!(application.protocols.sync.pending_outbound_len(), 8);
        assert!(application.protocols.signer_direct.replay_needed(peer, 17));
        assert!(application.protocols.signer_direct.replay_needed(peer, 20));

        authenticate(application, other_peer, CAP_SYNC);
        assert_eq!(
            application.request_signer_replays_for_peer(other_peer, [9]),
            0,
            "a cycle repair must not fan out to every authenticated provider"
        );
    }
}
