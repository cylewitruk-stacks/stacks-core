// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Bounded content fetch/push protocol ownership.
//!
//! The transport-neutral hub remains the sole canonical admission and storage
//! policy. This behaviour owns request correlation, provider attempts,
//! response channels, direct-push acknowledgements, and their deadlines.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use futures_timer::Delay;
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use stacks_network_types::wire::v1::Status;
use stacks_network_types::{
    supports, Announcement, ContentId, NetworkEnvelope, NetworkObject, ObjectKind,
    CAP_CONTENT_PUSH, CAP_OBJECT_FETCH,
};

use crate::{
    content_push_ack_envelope, content_push_envelope, content_request_envelope,
    content_response_envelope, decode_content_push, decode_content_push_ack,
    decode_content_request, decode_content_response, BoundedEnvelopeCodec,
};

const CONTENT_TIMER_TICK: Duration = Duration::from_secs(1);
const PUBLICATION_RETRY_TICK: Duration = Duration::from_millis(100);
const MAX_PENDING_INBOUND_CONTENT: usize = 256;
const MAX_DEFERRED_FETCHES: usize = 256;
const MAX_ANNOUNCEMENTS: usize = 256;
const MAX_ANNOUNCEMENT_BYTES: usize = 1024 * 1024;
const MAX_TRANSACTIONS: usize = 256;
const MAX_TRANSACTION_BYTES: usize = 16 * 1024 * 1024;
const MAX_KNOWN_ANNOUNCEMENTS: usize = 8192;
const DOWNSTREAM_EVENT_METADATA_BYTES: usize = 128;
pub const DOWNSTREAM_EVENT_QUEUE_CAPACITY: usize = 256;
pub const DOWNSTREAM_EVENT_QUEUE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DownstreamQueueFull;

struct ByteQueue<T> {
    entries: VecDeque<(T, usize)>,
    bytes: usize,
    max_items: usize,
    max_bytes: usize,
}

impl<T> ByteQueue<T> {
    fn new(max_items: usize, max_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            max_items,
            max_bytes,
        }
    }

    fn push(&mut self, value: T, bytes: usize) -> Result<(), T> {
        if !self.can_fit(bytes) {
            return Err(value);
        }
        self.entries.push_back((value, bytes));
        self.bytes += bytes;
        Ok(())
    }

    fn push_front(&mut self, value: T, bytes: usize) -> Result<(), T> {
        if !self.can_fit(bytes) {
            return Err(value);
        }
        self.entries.push_front((value, bytes));
        self.bytes += bytes;
        Ok(())
    }

    fn can_fit(&self, bytes: usize) -> bool {
        self.entries.len() < self.max_items && bytes <= self.max_bytes.saturating_sub(self.bytes)
    }

    fn front(&self) -> Option<&T> {
        self.entries.front().map(|(value, _)| value)
    }

    fn pop(&mut self) -> Option<T> {
        let (value, bytes) = self.entries.pop_front()?;
        self.bytes = self.bytes.saturating_sub(bytes);
        Some(value)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ContentProtocolsEvent")]
#[doc(hidden)]
pub struct ContentProtocols {
    fetch: FetchProtocol,
    push: PushProtocol,
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "FetchProtocolEvent")]
pub struct FetchProtocol {
    inner: request_response::Behaviour<BoundedEnvelopeCodec>,
}

#[derive(Debug)]
pub enum FetchProtocolEvent {
    Event(request_response::Event<NetworkEnvelope, NetworkEnvelope>),
}

impl From<request_response::Event<NetworkEnvelope, NetworkEnvelope>> for FetchProtocolEvent {
    fn from(event: request_response::Event<NetworkEnvelope, NetworkEnvelope>) -> Self {
        Self::Event(event)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "PushProtocolEvent")]
pub struct PushProtocol {
    inner: request_response::Behaviour<BoundedEnvelopeCodec>,
}

#[derive(Debug)]
pub enum PushProtocolEvent {
    Event(request_response::Event<NetworkEnvelope, NetworkEnvelope>),
}

impl From<request_response::Event<NetworkEnvelope, NetworkEnvelope>> for PushProtocolEvent {
    fn from(event: request_response::Event<NetworkEnvelope, NetworkEnvelope>) -> Self {
        Self::Event(event)
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub enum ContentProtocolsEvent {
    Fetch(FetchProtocolEvent),
    Push(PushProtocolEvent),
}

impl From<FetchProtocolEvent> for ContentProtocolsEvent {
    fn from(event: FetchProtocolEvent) -> Self {
        Self::Fetch(event)
    }
}

impl From<PushProtocolEvent> for ContentProtocolsEvent {
    fn from(event: PushProtocolEvent) -> Self {
        Self::Push(event)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentProtocolKind {
    Fetch,
    Push,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentPublication {
    Announcement(Announcement),
    Transaction(NetworkObject),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationOutcome {
    Published,
    Duplicate,
    NoPeers,
    Failed(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailure {
    Unavailable,
    InvalidData,
}

/// Immutable cross-behaviour facts used by the content policy to select a
/// small, diverse direct-push fanout. The service gathers these facts; the
/// content behaviour owns ranking, capability, and in-flight policy.
#[derive(Clone, Debug)]
pub struct DirectPushCandidate {
    pub peer: PeerId,
    pub outbound: bool,
    pub gossip_score: f64,
    pub rtt: Option<Duration>,
    pub failure_domain: Option<Vec<u8>>,
}

/// A validated semantic content event awaiting the embedding node's durable
/// relayer or storage service. The content behaviour owns bounded staging for
/// these events; `run_service` only routes them to the cross-thread channel.
#[derive(Clone, Debug)]
pub enum ObjectNetworkEvent {
    Object {
        source: PeerId,
        object: NetworkObject,
        direct_push: bool,
    },
    Announcement {
        source: PeerId,
        announcement: Announcement,
    },
    /// A cache miss that the embedding node may satisfy from durable storage.
    /// The opaque token binds the response to the authenticated request,
    /// expected kind, and content ID retained by this behaviour.
    Request {
        source: PeerId,
        response_token: u64,
        kind: ObjectKind,
        id: ContentId,
    },
}

fn downstream_event_owned_bytes(event: &ObjectNetworkEvent) -> usize {
    DOWNSTREAM_EVENT_METADATA_BYTES.saturating_add(match event {
        ObjectNetworkEvent::Object { object, .. } => object.bytes.len(),
        ObjectNetworkEvent::Announcement { announcement, .. } => {
            announcement.canonical_metadata.len()
        }
        ObjectNetworkEvent::Request { .. } => 0,
    })
}

#[derive(Debug)]
pub enum ContentExchangeEvent {
    Publish {
        token: u64,
        publication: ContentPublication,
    },
    FetchStarted {
        peer: PeerId,
        kind: ObjectKind,
        id: ContentId,
    },
    InboundFetch {
        peer: PeerId,
        connection_id: ConnectionId,
        response_token: u64,
        kind: ObjectKind,
        id: ContentId,
        encoded_bytes: usize,
    },
    Fetched {
        peer: PeerId,
        connection_id: ConnectionId,
        object: NetworkObject,
        encoded_bytes: usize,
    },
    FetchFailed {
        id: ContentId,
        attempted: Vec<PeerId>,
        error: String,
    },
    ProviderFailed {
        peer: PeerId,
        id: ContentId,
        failure: ProviderFailure,
        error: String,
    },
    InboundPush {
        peer: PeerId,
        connection_id: ConnectionId,
        response_token: u64,
        object: NetworkObject,
        encoded_bytes: usize,
    },
    PushResult {
        peer: PeerId,
        connection_id: Option<ConnectionId>,
        id: ContentId,
        status: Result<Status, String>,
        encoded_bytes: usize,
    },
    Rejected {
        peer: PeerId,
        connection_id: ConnectionId,
        protocol: ContentProtocolKind,
        error: String,
    },
    InboundExpired {
        peer: PeerId,
        response_token: u64,
        protocol: ContentProtocolKind,
    },
}

#[derive(Clone, Debug)]
struct FetchState {
    kind: ObjectKind,
    providers: VecDeque<PeerId>,
    attempted: HashSet<PeerId>,
    active: Option<(OutboundRequestId, PeerId)>,
    last_error: Option<String>,
}

struct PendingFetchResponse {
    peer: PeerId,
    request_id: request_response::InboundRequestId,
    kind: ObjectKind,
    id: ContentId,
    channel: ResponseChannel<NetworkEnvelope>,
    created_at: Instant,
}

struct PendingPushResponse {
    peer: PeerId,
    request_id: request_response::InboundRequestId,
    id: ContentId,
    channel: ResponseChannel<NetworkEnvelope>,
    created_at: Instant,
}

#[derive(Default)]
struct FetchTracker {
    by_content: HashMap<ContentId, FetchState>,
    content_by_request: HashMap<OutboundRequestId, ContentId>,
    inbound: HashMap<u64, PendingFetchResponse>,
    inbound_by_request: HashMap<request_response::InboundRequestId, u64>,
}

#[derive(Default)]
struct PushTracker {
    outbound: HashMap<OutboundRequestId, (PeerId, ContentId)>,
    inbound: HashMap<u64, PendingPushResponse>,
    inbound_by_request: HashMap<request_response::InboundRequestId, u64>,
}

#[derive(Default)]
struct ResponseTokens {
    next: u64,
}

impl ResponseTokens {
    fn reserve<F>(&mut self, mut in_use: F) -> Option<u64>
    where
        F: FnMut(u64) -> bool,
    {
        for _ in 0..=MAX_PENDING_INBOUND_CONTENT {
            let token = self.next;
            self.next = self.next.wrapping_add(1);
            if !in_use(token) {
                return Some(token);
            }
        }
        None
    }
}

/// One combined per-peer reservation ledger for inbound fetch and push
/// requests. Both protocols retain a response channel in the same bounded
/// token pool, so enforcing independent limits would still let one peer
/// consume twice its configured share.
struct InboundContentCapacity {
    by_peer: HashMap<PeerId, usize>,
    per_peer_limit: usize,
}

impl InboundContentCapacity {
    fn new(per_peer_limit: usize) -> Self {
        Self {
            by_peer: HashMap::new(),
            per_peer_limit: per_peer_limit.max(1),
        }
    }

    fn try_acquire(&mut self, peer: PeerId) -> bool {
        let count = self.by_peer.entry(peer).or_default();
        if *count >= self.per_peer_limit {
            return false;
        }
        *count += 1;
        true
    }

    fn release(&mut self, peer: PeerId) {
        let Some(count) = self.by_peer.get_mut(&peer) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.by_peer.remove(&peer);
        }
    }

    #[cfg(test)]
    fn count(&self, peer: PeerId) -> usize {
        self.by_peer.get(&peer).copied().unwrap_or_default()
    }
}

struct PublicationState {
    next_token: u64,
    announcements: ByteQueue<Announcement>,
    transactions: ByteQueue<NetworkObject>,
    known: HashSet<ContentId>,
    known_order: VecDeque<ContentId>,
    inflight: Option<(u64, ContentPublication)>,
}

impl PublicationState {
    fn new() -> Self {
        Self {
            next_token: 0,
            announcements: ByteQueue::new(MAX_ANNOUNCEMENTS, MAX_ANNOUNCEMENT_BYTES),
            transactions: ByteQueue::new(MAX_TRANSACTIONS, MAX_TRANSACTION_BYTES),
            known: HashSet::new(),
            known_order: VecDeque::new(),
            inflight: None,
        }
    }
}

struct DownstreamDeliveryQueue(ByteQueue<ObjectNetworkEvent>);

impl DownstreamDeliveryQueue {
    fn new() -> Self {
        Self(ByteQueue::new(
            DOWNSTREAM_EVENT_QUEUE_CAPACITY,
            DOWNSTREAM_EVENT_QUEUE_BYTES,
        ))
    }
}

pub struct ContentExchangeBehaviour {
    protocols: ContentProtocols,
    chain_id: u32,
    request_timeout: Duration,
    max_inflight_per_peer: usize,
    max_inflight_pushes: usize,
    peer_capabilities: HashMap<PeerId, u64>,
    fetches: FetchTracker,
    pushes: PushTracker,
    response_tokens: ResponseTokens,
    inbound_capacity: InboundContentCapacity,
    publications: PublicationState,
    downstream: DownstreamDeliveryQueue,
    events: VecDeque<ContentExchangeEvent>,
    timer: Delay,
    publication_timer: Delay,
}

impl ContentExchangeBehaviour {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        fetch: request_response::Behaviour<BoundedEnvelopeCodec>,
        push: request_response::Behaviour<BoundedEnvelopeCodec>,
        chain_id: u32,
        request_timeout: Duration,
        max_inflight_per_peer: usize,
        max_inflight_pushes: usize,
    ) -> Self {
        Self {
            protocols: ContentProtocols {
                fetch: FetchProtocol { inner: fetch },
                push: PushProtocol { inner: push },
            },
            chain_id,
            request_timeout,
            max_inflight_per_peer: max_inflight_per_peer.max(1),
            max_inflight_pushes: max_inflight_pushes.max(1),
            peer_capabilities: HashMap::new(),
            fetches: FetchTracker::default(),
            pushes: PushTracker::default(),
            response_tokens: ResponseTokens::default(),
            inbound_capacity: InboundContentCapacity::new(max_inflight_per_peer),
            publications: PublicationState::new(),
            downstream: DownstreamDeliveryQueue::new(),
            events: VecDeque::new(),
            timer: Delay::new(CONTENT_TIMER_TICK),
            publication_timer: Delay::new(PUBLICATION_RETRY_TICK),
        }
    }

    pub fn queue_announcement(
        &mut self,
        announcement: Announcement,
        encoded_bytes: usize,
    ) -> Result<bool, String> {
        if self.publications.known.contains(&announcement.content_id)
            || self
                .publications
                .announcements
                .entries
                .iter()
                .any(|(queued, _)| queued.content_id == announcement.content_id)
        {
            return Ok(false);
        }
        self.publications
            .announcements
            .push(announcement, encoded_bytes)
            .map_err(|_| "announcement publication queue is full".to_owned())?;
        Ok(true)
    }

    pub fn queue_transaction(
        &mut self,
        object: NetworkObject,
        encoded_bytes: usize,
    ) -> Result<(), String> {
        self.publications
            .transactions
            .push(object, encoded_bytes)
            .map_err(|_| "transaction publication queue is full".to_owned())
    }

    pub fn remember_announcement(&mut self, content_id: ContentId) {
        if !self.publications.known.insert(content_id) {
            return;
        }
        self.publications.known_order.push_back(content_id);
        while self.publications.known_order.len() > MAX_KNOWN_ANNOUNCEMENTS {
            if let Some(expired) = self.publications.known_order.pop_front() {
                self.publications.known.remove(&expired);
            }
        }
    }

    pub fn complete_publication(
        &mut self,
        token: u64,
        outcome: PublicationOutcome,
    ) -> Result<(), String> {
        let Some((expected_token, publication)) = self.publications.inflight.take() else {
            return Err("no content publication is awaiting an outcome".to_owned());
        };
        if token != expected_token {
            self.publications.inflight = Some((expected_token, publication));
            return Err("content publication outcome token mismatch".to_owned());
        }
        if outcome == PublicationOutcome::NoPeers {
            return Ok(());
        }
        match publication {
            ContentPublication::Announcement(expected) => {
                let removed = self
                    .publications
                    .announcements
                    .pop()
                    .ok_or_else(|| "announcement publication queue became empty".to_owned())?;
                if removed.content_id != expected.content_id {
                    return Err("announcement publication queue ordering changed".to_owned());
                }
                if matches!(
                    outcome,
                    PublicationOutcome::Published | PublicationOutcome::Duplicate
                ) {
                    self.remember_announcement(removed.content_id);
                }
            }
            ContentPublication::Transaction(expected) => {
                let removed = self
                    .publications
                    .transactions
                    .pop()
                    .ok_or_else(|| "transaction publication queue became empty".to_owned())?;
                if removed.content_id != expected.content_id {
                    return Err("transaction publication queue ordering changed".to_owned());
                }
            }
        }
        Ok(())
    }

    pub fn pending_publications(&self) -> (usize, usize) {
        (
            self.publications.announcements.len(),
            self.publications.transactions.len(),
        )
    }

    /// Reserve bounded ownership of a semantic event until the embedding
    /// node's channel accepts it. Returning success creates the delivery
    /// obligation; callers may safely acknowledge a direct push only then.
    pub fn stage_downstream_event(
        &mut self,
        event: ObjectNetworkEvent,
    ) -> Result<(), DownstreamQueueFull> {
        let bytes = downstream_event_owned_bytes(&event);
        self.downstream
            .0
            .push(event, bytes)
            .map_err(|_| DownstreamQueueFull)
    }

    /// Restore an event that was popped for a nonblocking delivery attempt.
    /// No intervening queue mutation can occur while the swarm owner holds
    /// `&mut self`, so a previously owned event must still fit.
    pub fn restore_downstream_event(
        &mut self,
        event: ObjectNetworkEvent,
    ) -> Result<(), DownstreamQueueFull> {
        let bytes = downstream_event_owned_bytes(&event);
        self.downstream
            .0
            .push_front(event, bytes)
            .map_err(|_| DownstreamQueueFull)
    }

    pub fn pop_downstream_event(&mut self) -> Option<ObjectNetworkEvent> {
        self.downstream.0.pop()
    }

    pub fn has_downstream_events(&self) -> bool {
        !self.downstream.0.is_empty()
    }

    pub fn pending_downstream_events(&self) -> usize {
        self.downstream.0.len()
    }

    pub fn can_stage_downstream_object(&self, object: &NetworkObject) -> bool {
        self.downstream
            .0
            .can_fit(DOWNSTREAM_EVENT_METADATA_BYTES.saturating_add(object.bytes.len()))
    }

    pub fn authenticate_peer(&mut self, peer: PeerId, capabilities: u64) {
        self.peer_capabilities.insert(peer, capabilities);
        let ids = self
            .fetches
            .by_content
            .iter()
            .filter_map(|(id, state)| state.active.is_none().then_some(*id))
            .collect::<Vec<_>>();
        for id in ids {
            self.try_next_provider(id);
        }
    }

    pub fn revoke_peer(&mut self, peer: &PeerId) {
        self.peer_capabilities.remove(peer);
    }

    pub fn start_fetch(
        &mut self,
        kind: ObjectKind,
        id: ContentId,
        providers: impl IntoIterator<Item = PeerId>,
    ) -> Result<bool, String> {
        let mut providers = providers.into_iter().collect::<VecDeque<_>>();
        if let Some(existing) = self.fetches.by_content.get_mut(&id) {
            if existing.kind != kind {
                return Err("one content ID was requested with conflicting kinds".to_owned());
            }
            while let Some(peer) = providers.pop_front() {
                if !existing.attempted.contains(&peer) && !existing.providers.contains(&peer) {
                    existing.providers.push_back(peer);
                }
            }
            self.try_next_provider(id);
            return Ok(false);
        }
        if self.fetches.by_content.len() >= MAX_DEFERRED_FETCHES {
            return Err("deferred content-fetch capacity reached".to_owned());
        }
        self.fetches.by_content.insert(
            id,
            FetchState {
                kind,
                providers,
                attempted: HashSet::new(),
                active: None,
                last_error: None,
            },
        );
        self.try_next_provider(id);
        Ok(true)
    }

    pub fn is_fetching(&self, id: &ContentId) -> bool {
        self.fetches.by_content.contains_key(id)
    }

    pub fn pending_fetches(&self) -> usize {
        self.fetches.by_content.len()
    }

    pub fn deferred_fetches(&self) -> usize {
        self.fetches
            .by_content
            .values()
            .filter(|state| state.active.is_none())
            .count()
    }

    pub fn pending_pushes(&self) -> usize {
        self.pushes.outbound.len()
    }

    pub fn select_direct_push_targets(
        &self,
        candidates: impl IntoIterator<Item = DirectPushCandidate>,
        requested_fanout: usize,
    ) -> Vec<PeerId> {
        let available = self
            .max_inflight_pushes
            .saturating_sub(self.pushes.outbound.len());
        let limit = requested_fanout.min(available);
        if limit == 0 {
            return Vec::new();
        }
        let mut ranked = candidates
            .into_iter()
            .filter(|candidate| self.peer_supports(&candidate.peer, CAP_CONTENT_PUSH))
            .filter(|candidate| {
                self.pushes
                    .outbound
                    .values()
                    .filter(|(peer, _)| *peer == candidate.peer)
                    .count()
                    < self.max_inflight_per_peer
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .outbound
                .cmp(&left.outbound)
                .then_with(|| right.gossip_score.total_cmp(&left.gossip_score))
                .then_with(|| {
                    left.rtt
                        .unwrap_or(Duration::MAX)
                        .cmp(&right.rtt.unwrap_or(Duration::MAX))
                })
                .then_with(|| left.peer.to_bytes().cmp(&right.peer.to_bytes()))
        });

        let mut selected = Vec::with_capacity(limit.min(ranked.len()));
        let mut fallback = Vec::new();
        let mut failure_domains = HashSet::new();
        for candidate in ranked {
            if candidate
                .failure_domain
                .as_ref()
                .is_none_or(|domain| failure_domains.insert(domain.clone()))
            {
                selected.push(candidate.peer);
            } else {
                fallback.push(candidate.peer);
            }
            if selected.len() == limit {
                return selected;
            }
        }
        for peer in fallback {
            selected.push(peer);
            if selected.len() == limit {
                break;
            }
        }
        selected
    }

    pub fn pending_fetch_request(
        &self,
        response_token: u64,
    ) -> Option<(PeerId, ObjectKind, ContentId)> {
        self.fetches
            .inbound
            .get(&response_token)
            .map(|pending| (pending.peer, pending.kind, pending.id))
    }

    pub fn push(
        &mut self,
        peer: &PeerId,
        object: &NetworkObject,
    ) -> Result<OutboundRequestId, String> {
        if !self.peer_supports(peer, CAP_CONTENT_PUSH) {
            return Err("content-push peer is not Hello-authenticated and capable".to_owned());
        }
        if self.pushes.outbound.len() >= self.max_inflight_pushes {
            return Err("direct content-push capacity reached".to_owned());
        }
        if self
            .pushes
            .outbound
            .values()
            .filter(|(pending_peer, _)| pending_peer == peer)
            .count()
            >= self.max_inflight_per_peer
        {
            return Err("content-push peer exceeded its in-flight request limit".to_owned());
        }
        let request = content_push_envelope(self.chain_id, object);
        let request_id = self.protocols.push.inner.send_request(peer, request);
        self.pushes
            .outbound
            .insert(request_id, (*peer, object.content_id));
        Ok(request_id)
    }

    pub fn respond_fetch(
        &mut self,
        response_token: u64,
        status: Status,
        object: Option<&NetworkObject>,
    ) -> Result<(), String> {
        let pending =
            self.fetches.inbound.get(&response_token).ok_or_else(|| {
                format!("unknown or expired content response token {response_token}")
            })?;
        if let Some(object) = object {
            if object.kind != pending.kind || object.content_id != pending.id {
                return Err("durable content response does not match request".to_owned());
            }
        }
        let pending = self
            .remove_fetch_response(response_token)
            .ok_or_else(|| format!("content response token {response_token} disappeared"))?;
        let response =
            content_response_envelope(self.chain_id, status, object, pending.kind, pending.id);
        self.protocols
            .fetch
            .inner
            .send_response(pending.channel, response)
            .map_err(|_| format!("content response channel to {} closed", pending.peer))
    }

    pub fn respond_push(&mut self, response_token: u64, status: Status) -> Result<(), String> {
        let pending = self
            .remove_push_response(response_token)
            .ok_or_else(|| format!("unknown or expired content-push token {response_token}"))?;
        let response = content_push_ack_envelope(self.chain_id, status, pending.id);
        self.protocols
            .push
            .inner
            .send_response(pending.channel, response)
            .map_err(|_| format!("content-push response channel to {} closed", pending.peer))
    }

    pub(super) fn reject_inbound(
        &mut self,
        response_token: u64,
        protocol: ContentProtocolKind,
        status: Status,
    ) {
        match protocol {
            ContentProtocolKind::Fetch => {
                let _ = self.respond_fetch(response_token, status, None);
            }
            ContentProtocolKind::Push => {
                let _ = self.respond_push(response_token, status);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn send_fetch_unchecked(
        &mut self,
        peer: &PeerId,
        kind: ObjectKind,
        id: ContentId,
    ) -> OutboundRequestId {
        self.protocols
            .fetch
            .inner
            .send_request(peer, content_request_envelope(self.chain_id, kind, id))
    }

    fn peer_supports(&self, peer: &PeerId, capability: u64) -> bool {
        self.peer_capabilities
            .get(peer)
            .is_some_and(|capabilities| supports(*capabilities, capability))
    }

    fn try_next_provider(&mut self, id: ContentId) {
        let Some(mut state) = self.fetches.by_content.remove(&id) else {
            return;
        };
        if state.active.is_some() {
            self.fetches.by_content.insert(id, state);
            return;
        }
        let mut deferred = VecDeque::new();
        let mut chosen = None;
        while let Some(peer) = state.providers.pop_front() {
            if state.attempted.contains(&peer) {
                continue;
            }
            if !self.peer_supports(&peer, CAP_OBJECT_FETCH) {
                deferred.push_back(peer);
                continue;
            }
            let in_flight = self
                .fetches
                .by_content
                .values()
                .filter(|candidate| {
                    candidate
                        .active
                        .is_some_and(|(_, active_peer)| active_peer == peer)
                })
                .count();
            if in_flight >= self.max_inflight_per_peer {
                deferred.push_back(peer);
                continue;
            }
            chosen = Some(peer);
            break;
        }
        state.providers.extend(deferred);
        if let Some(peer) = chosen {
            let request = content_request_envelope(self.chain_id, state.kind, id);
            let request_id = self.protocols.fetch.inner.send_request(&peer, request);
            state.attempted.insert(peer);
            state.active = Some((request_id, peer));
            self.fetches.content_by_request.insert(request_id, id);
            self.events.push_back(ContentExchangeEvent::FetchStarted {
                peer,
                kind: state.kind,
                id,
            });
            self.fetches.by_content.insert(id, state);
            return;
        }
        if state.providers.is_empty() && state.attempted.is_empty() {
            // Preserve the content-ID/kind binding and wait for a later
            // authenticated announcement to contribute a provider.
            self.fetches.by_content.insert(id, state);
        } else if state.providers.is_empty() {
            let mut attempted = state.attempted.into_iter().collect::<Vec<_>>();
            attempted.sort_by_key(|peer| peer.to_bytes());
            self.events.push_back(ContentExchangeEvent::FetchFailed {
                id,
                attempted,
                error: state
                    .last_error
                    .unwrap_or_else(|| "no eligible content provider".to_owned()),
            });
        } else {
            self.fetches.by_content.insert(id, state);
        }
    }

    fn fetch_failed(&mut self, request_id: OutboundRequestId, error: String) {
        let Some(id) = self.fetches.content_by_request.remove(&request_id) else {
            return;
        };
        if let Some(state) = self.fetches.by_content.get_mut(&id) {
            if let Some((_, peer)) = state.active {
                self.events.push_back(ContentExchangeEvent::ProviderFailed {
                    peer,
                    id,
                    failure: ProviderFailure::Unavailable,
                    error: error.clone(),
                });
            }
            state.active = None;
            state.last_error = Some(error);
        }
        self.try_next_provider(id);
    }

    fn reserve_token(&mut self) -> Option<u64> {
        if self.fetches.inbound.len() + self.pushes.inbound.len() >= MAX_PENDING_INBOUND_CONTENT {
            return None;
        }
        self.response_tokens.reserve(|token| {
            self.fetches.inbound.contains_key(&token) || self.pushes.inbound.contains_key(&token)
        })
    }

    fn reserve_inbound_token(&mut self, peer: PeerId) -> Option<u64> {
        if !self.inbound_capacity.try_acquire(peer) {
            return None;
        }
        match self.reserve_token() {
            Some(token) => Some(token),
            None => {
                self.inbound_capacity.release(peer);
                None
            }
        }
    }

    fn remove_fetch_response(&mut self, token: u64) -> Option<PendingFetchResponse> {
        let pending = self.fetches.inbound.remove(&token)?;
        self.fetches.inbound_by_request.remove(&pending.request_id);
        self.inbound_capacity.release(pending.peer);
        Some(pending)
    }

    fn remove_push_response(&mut self, token: u64) -> Option<PendingPushResponse> {
        let pending = self.pushes.inbound.remove(&token)?;
        self.pushes.inbound_by_request.remove(&pending.request_id);
        self.inbound_capacity.release(pending.peer);
        Some(pending)
    }

    fn on_fetch_event(&mut self, event: request_response::Event<NetworkEnvelope, NetworkEnvelope>) {
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
                let encoded_bytes = request.encoded_len();
                let decoded = self
                    .peer_supports(&peer, CAP_OBJECT_FETCH)
                    .then_some(())
                    .ok_or_else(|| "content-fetch peer is not authenticated and capable".to_owned())
                    .and_then(|_| decode_content_request(&request, self.chain_id));
                match decoded {
                    Ok((kind, id)) => {
                        let Some(token) = self.reserve_inbound_token(peer) else {
                            let response = content_response_envelope(
                                self.chain_id,
                                Status::Busy,
                                None,
                                kind,
                                id,
                            );
                            let _ = self.protocols.fetch.inner.send_response(channel, response);
                            self.events.push_back(ContentExchangeEvent::Rejected {
                                peer,
                                connection_id,
                                protocol: ContentProtocolKind::Fetch,
                                error: "content response capacity reached".to_owned(),
                            });
                            return;
                        };
                        self.fetches.inbound_by_request.insert(request_id, token);
                        self.fetches.inbound.insert(
                            token,
                            PendingFetchResponse {
                                peer,
                                request_id,
                                kind,
                                id,
                                channel,
                                created_at: Instant::now(),
                            },
                        );
                        self.events.push_back(ContentExchangeEvent::InboundFetch {
                            peer,
                            connection_id,
                            response_token: token,
                            kind,
                            id,
                            encoded_bytes,
                        });
                    }
                    Err(error) => {
                        let zero = ContentId::from_bytes([0; 32]);
                        let status = if self.peer_capabilities.contains_key(&peer) {
                            Status::InvalidRequest
                        } else {
                            Status::Unauthorized
                        };
                        let response = content_response_envelope(
                            self.chain_id,
                            status,
                            None,
                            ObjectKind::NakamotoBlock,
                            zero,
                        );
                        let _ = self.protocols.fetch.inner.send_response(channel, response);
                        self.events.push_back(ContentExchangeEvent::Rejected {
                            peer,
                            connection_id,
                            protocol: ContentProtocolKind::Fetch,
                            error,
                        });
                    }
                }
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
                let encoded_bytes = response.encoded_len();
                let Some(id) = self.fetches.content_by_request.remove(&request_id) else {
                    self.events.push_back(ContentExchangeEvent::Rejected {
                        peer,
                        connection_id,
                        protocol: ContentProtocolKind::Fetch,
                        error: "unknown content response".to_owned(),
                    });
                    return;
                };
                let Some(mut state) = self.fetches.by_content.remove(&id) else {
                    return;
                };
                state.active = None;
                let expected = state
                    .attempted
                    .contains(&peer)
                    .then_some(())
                    .ok_or_else(|| {
                        (
                            ProviderFailure::InvalidData,
                            "content response peer mismatch".to_owned(),
                        )
                    });
                let result = expected.and_then(|_| {
                    let (status, object) = decode_content_response(&response, self.chain_id)
                        .map_err(|error| (ProviderFailure::InvalidData, error))?;
                    if status != Status::Ok {
                        return Err(match status {
                            Status::Busy
                            | Status::RateLimited
                            | Status::NotFound
                            | Status::Unsupported => (
                                ProviderFailure::Unavailable,
                                format!("content fetch returned {status:?}"),
                            ),
                            _ => (
                                ProviderFailure::InvalidData,
                                format!("content fetch returned {status:?}"),
                            ),
                        });
                    }
                    let object = object.ok_or_else(|| {
                        (
                            ProviderFailure::InvalidData,
                            "content fetch has no object".to_owned(),
                        )
                    })?;
                    if object.kind != state.kind || object.content_id != id {
                        return Err((
                            ProviderFailure::InvalidData,
                            "content response does not match request".to_owned(),
                        ));
                    }
                    Ok(object)
                });
                match result {
                    Ok(object) => self.events.push_back(ContentExchangeEvent::Fetched {
                        peer,
                        connection_id,
                        object,
                        encoded_bytes,
                    }),
                    Err((failure, error)) => {
                        self.events.push_back(ContentExchangeEvent::ProviderFailed {
                            peer,
                            id,
                            failure,
                            error: error.clone(),
                        });
                        state.last_error = Some(error);
                        self.fetches.by_content.insert(id, state);
                        self.try_next_provider(id);
                    }
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.fetch_failed(request_id, error.to_string()),
            request_response::Event::InboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            } => {
                if let Some(token) = self.fetches.inbound_by_request.get(&request_id).copied() {
                    self.remove_fetch_response(token);
                }
                self.events.push_back(ContentExchangeEvent::Rejected {
                    peer,
                    connection_id,
                    protocol: ContentProtocolKind::Fetch,
                    error: error.to_string(),
                });
            }
            request_response::Event::ResponseSent { request_id, .. } => {
                if let Some(token) = self.fetches.inbound_by_request.get(&request_id).copied() {
                    self.remove_fetch_response(token);
                }
            }
        }
    }

    fn on_push_event(&mut self, event: request_response::Event<NetworkEnvelope, NetworkEnvelope>) {
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
                let encoded_bytes = request.encoded_len();
                let decoded = self
                    .peer_supports(&peer, CAP_CONTENT_PUSH)
                    .then_some(())
                    .ok_or_else(|| "content-push peer is not authenticated and capable".to_owned())
                    .and_then(|_| decode_content_push(&request, self.chain_id));
                match decoded {
                    Ok(object) => {
                        let Some(token) = self.reserve_inbound_token(peer) else {
                            let response = content_push_ack_envelope(
                                self.chain_id,
                                Status::Busy,
                                object.content_id,
                            );
                            let _ = self.protocols.push.inner.send_response(channel, response);
                            return;
                        };
                        let id = object.content_id;
                        self.pushes.inbound_by_request.insert(request_id, token);
                        self.pushes.inbound.insert(
                            token,
                            PendingPushResponse {
                                peer,
                                request_id,
                                id,
                                channel,
                                created_at: Instant::now(),
                            },
                        );
                        self.events.push_back(ContentExchangeEvent::InboundPush {
                            peer,
                            connection_id,
                            response_token: token,
                            object,
                            encoded_bytes,
                        });
                    }
                    Err(error) => {
                        let status = if self.peer_capabilities.contains_key(&peer) {
                            Status::InvalidRequest
                        } else {
                            Status::Unauthorized
                        };
                        let response = content_push_ack_envelope(
                            self.chain_id,
                            status,
                            ContentId::from_bytes([0; 32]),
                        );
                        let _ = self.protocols.push.inner.send_response(channel, response);
                        self.events.push_back(ContentExchangeEvent::Rejected {
                            peer,
                            connection_id,
                            protocol: ContentProtocolKind::Push,
                            error,
                        });
                    }
                }
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
                let encoded_bytes = response.encoded_len();
                let result = self
                    .pushes
                    .outbound
                    .remove(&request_id)
                    .ok_or_else(|| "unknown content-push response".to_owned())
                    .and_then(|(expected_peer, expected_id)| {
                        if expected_peer != peer {
                            return Err("content-push peer mismatch".to_owned());
                        }
                        let (status, id) = decode_content_push_ack(&response, self.chain_id)?;
                        if id != expected_id {
                            return Err("content-push acknowledgement ID mismatch".to_owned());
                        }
                        Ok((expected_id, status))
                    });
                let (id, status) = match result {
                    Ok((id, status)) => (id, Ok(status)),
                    Err(error) => (ContentId::from_bytes([0; 32]), Err(error)),
                };
                self.events.push_back(ContentExchangeEvent::PushResult {
                    peer,
                    connection_id: Some(connection_id),
                    id,
                    status,
                    encoded_bytes,
                });
            }
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                if let Some((_, id)) = self.pushes.outbound.remove(&request_id) {
                    self.events.push_back(ContentExchangeEvent::PushResult {
                        peer,
                        connection_id: None,
                        id,
                        status: Err(error.to_string()),
                        encoded_bytes: 0,
                    });
                }
            }
            request_response::Event::InboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            } => {
                if let Some(token) = self.pushes.inbound_by_request.get(&request_id).copied() {
                    self.remove_push_response(token);
                }
                self.events.push_back(ContentExchangeEvent::Rejected {
                    peer,
                    connection_id,
                    protocol: ContentProtocolKind::Push,
                    error: error.to_string(),
                });
            }
            request_response::Event::ResponseSent { request_id, .. } => {
                if let Some(token) = self.pushes.inbound_by_request.get(&request_id).copied() {
                    self.remove_push_response(token);
                }
            }
        }
    }

    fn expire(&mut self, now: Instant) {
        let fetches = self
            .fetches
            .inbound
            .iter()
            .filter_map(|(token, pending)| {
                (now.saturating_duration_since(pending.created_at) >= self.request_timeout)
                    .then_some((*token, pending.peer))
            })
            .collect::<Vec<_>>();
        for (token, peer) in fetches {
            self.remove_fetch_response(token);
            self.events.push_back(ContentExchangeEvent::InboundExpired {
                peer,
                response_token: token,
                protocol: ContentProtocolKind::Fetch,
            });
        }
        let pushes = self
            .pushes
            .inbound
            .iter()
            .filter_map(|(token, pending)| {
                (now.saturating_duration_since(pending.created_at) >= self.request_timeout)
                    .then_some((*token, pending.peer))
            })
            .collect::<Vec<_>>();
        for (token, peer) in pushes {
            self.remove_push_response(token);
            self.events.push_back(ContentExchangeEvent::InboundExpired {
                peer,
                response_token: token,
                protocol: ContentProtocolKind::Push,
            });
        }
        let ids = self
            .fetches
            .by_content
            .iter()
            .filter_map(|(id, state)| state.active.is_none().then_some(*id))
            .collect::<Vec<_>>();
        for id in ids {
            self.try_next_provider(id);
        }
    }
}

impl NetworkBehaviour for ContentExchangeBehaviour {
    type ConnectionHandler = <ContentProtocols as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = ContentExchangeEvent;

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
        if let FromSwarm::ConnectionClosed(event) = event {
            if event.remaining_established == 0 {
                self.revoke_peer(&event.peer_id);
            }
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
            self.expire(Instant::now());
            self.timer.reset(CONTENT_TIMER_TICK);
        }
        if std::pin::Pin::new(&mut self.publication_timer)
            .poll(cx)
            .is_ready()
        {
            if self.publications.inflight.is_none() {
                let publication = self
                    .publications
                    .announcements
                    .front()
                    .cloned()
                    .map(ContentPublication::Announcement)
                    .or_else(|| {
                        self.publications
                            .transactions
                            .front()
                            .cloned()
                            .map(ContentPublication::Transaction)
                    });
                if let Some(publication) = publication {
                    let token = self.publications.next_token;
                    self.publications.next_token = self.publications.next_token.wrapping_add(1);
                    self.publications.inflight = Some((token, publication.clone()));
                    self.events
                        .push_back(ContentExchangeEvent::Publish { token, publication });
                }
            }
            self.publication_timer.reset(PUBLICATION_RETRY_TICK);
        }
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }
        loop {
            match ready!(self.protocols.poll(cx)) {
                ToSwarm::GenerateEvent(ContentProtocolsEvent::Fetch(
                    FetchProtocolEvent::Event(event),
                )) => {
                    self.on_fetch_event(event);
                    if let Some(event) = self.events.pop_front() {
                        return Poll::Ready(ToSwarm::GenerateEvent(event));
                    }
                }
                ToSwarm::GenerateEvent(ContentProtocolsEvent::Push(PushProtocolEvent::Event(
                    event,
                ))) => {
                    self.on_push_event(event);
                    if let Some(event) = self.events.pop_front() {
                        return Poll::Ready(ToSwarm::GenerateEvent(event));
                    }
                }
                other => return Poll::Ready(other.map_out(|_| unreachable!())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::request_response::ProtocolSupport;
    use libp2p::swarm::StreamProtocol;
    use stacks_network_types::EnvelopeLimits;

    fn behaviour() -> ContentExchangeBehaviour {
        let fetch = request_response::Behaviour::with_codec(
            BoundedEnvelopeCodec::new(EnvelopeLimits::BLOCK),
            [(
                StreamProtocol::new("/stacks/content/test/1"),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );
        let push = request_response::Behaviour::with_codec(
            BoundedEnvelopeCodec::new(EnvelopeLimits::BLOCK),
            [(
                StreamProtocol::new("/stacks/push/test/1"),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );
        ContentExchangeBehaviour::new(fetch, push, 1, Duration::from_secs(10), 1, 2)
    }

    fn fixture_announcement(label: &[u8]) -> Announcement {
        Announcement {
            kind: ObjectKind::NakamotoBlock,
            content_id: ContentId::from_domain_bytes(b"announcement-queue-test", label),
            canonical_metadata: label.to_vec(),
        }
    }

    fn fixture_object(label: &[u8]) -> NetworkObject {
        NetworkObject {
            kind: ObjectKind::NakamotoBlock,
            content_id: ContentId::from_domain_bytes(b"content-delivery-queue-test", label),
            bytes: label.to_vec(),
        }
    }

    #[test]
    fn inbound_content_capacity_is_combined_per_peer_and_released_exactly() {
        let first = PeerId::random();
        let second = PeerId::random();
        let mut capacity = InboundContentCapacity::new(2);

        // These reservations may represent one fetch and one push. The shared
        // peer allowance is exhausted regardless of protocol kind.
        assert!(capacity.try_acquire(first));
        assert!(capacity.try_acquire(first));
        assert!(!capacity.try_acquire(first));
        assert_eq!(capacity.count(first), 2);

        // One peer cannot consume another peer's allowance.
        assert!(capacity.try_acquire(second));
        assert_eq!(capacity.count(second), 1);

        capacity.release(first);
        assert!(capacity.try_acquire(first));
        capacity.release(first);
        capacity.release(first);
        assert_eq!(capacity.count(first), 0);

        // A duplicate terminal event cannot underflow or recreate a ledger row.
        capacity.release(first);
        assert_eq!(capacity.count(first), 0);
    }

    #[test]
    fn byte_queue_enforces_item_and_byte_limits_and_restores_front() {
        let mut queue = ByteQueue::new(2, 10);
        assert!(queue.push("first", 6).is_ok());
        assert_eq!(queue.push("too-many-bytes", 5), Err("too-many-bytes"));
        assert!(queue.push("second", 4).is_ok());
        assert_eq!(queue.push("too-many-items", 0), Err("too-many-items"));
        assert_eq!(queue.pop(), Some("first"));
        assert!(queue.push_front("restored", 6).is_ok());
        assert_eq!(queue.pop(), Some("restored"));
        assert_eq!(queue.pop(), Some("second"));
        assert!(queue.is_empty());
    }

    #[test]
    fn downstream_delivery_obligation_is_bounded_and_order_preserving() {
        let mut content = behaviour();
        let peer = PeerId::random();
        let request = ObjectNetworkEvent::Request {
            source: peer,
            response_token: 7,
            kind: ObjectKind::NakamotoBlock,
            id: ContentId::from_bytes([7; 32]),
        };
        let object = fixture_object(b"ordered");
        content.stage_downstream_event(request).unwrap();
        content
            .stage_downstream_event(ObjectNetworkEvent::Object {
                source: peer,
                object: object.clone(),
                direct_push: false,
            })
            .unwrap();

        let first = content.pop_downstream_event().unwrap();
        content.restore_downstream_event(first).unwrap();
        assert!(matches!(
            content.pop_downstream_event(),
            Some(ObjectNetworkEvent::Request {
                response_token: 7,
                ..
            })
        ));
        assert!(matches!(
            content.pop_downstream_event(),
            Some(ObjectNetworkEvent::Object {
                object: delivered,
                ..
            }) if delivered == object
        ));
        assert!(!content.has_downstream_events());

        for token in 0..DOWNSTREAM_EVENT_QUEUE_CAPACITY {
            content
                .stage_downstream_event(ObjectNetworkEvent::Request {
                    source: peer,
                    response_token: token as u64,
                    kind: ObjectKind::NakamotoBlock,
                    id: ContentId::from_bytes([9; 32]),
                })
                .unwrap();
        }
        assert!(content
            .stage_downstream_event(ObjectNetworkEvent::Request {
                source: peer,
                response_token: u64::MAX,
                kind: ObjectKind::NakamotoBlock,
                id: ContentId::from_bytes([9; 32]),
            })
            .is_err());
        assert_eq!(
            content.pending_downstream_events(),
            DOWNSTREAM_EVENT_QUEUE_CAPACITY
        );
    }

    #[test]
    fn direct_push_selection_is_capability_bounded_diverse_and_per_peer_limited() {
        let mut content = behaviour();
        let preferred = PeerId::random();
        let same_domain = PeerId::random();
        let diverse = PeerId::random();
        let unauthenticated = PeerId::random();
        let unknown_rtt = PeerId::random();
        for peer in [preferred, same_domain, diverse, unknown_rtt] {
            content.authenticate_peer(peer, CAP_CONTENT_PUSH);
        }
        let selected = content.select_direct_push_targets(
            [
                DirectPushCandidate {
                    peer: same_domain,
                    outbound: true,
                    gossip_score: 1.0,
                    rtt: Some(Duration::from_millis(1)),
                    failure_domain: Some(vec![1]),
                },
                DirectPushCandidate {
                    peer: preferred,
                    outbound: true,
                    gossip_score: 10.0,
                    rtt: Some(Duration::from_millis(10)),
                    failure_domain: Some(vec![1]),
                },
                DirectPushCandidate {
                    peer: diverse,
                    outbound: false,
                    gossip_score: 0.0,
                    rtt: Some(Duration::from_millis(20)),
                    failure_domain: Some(vec![2]),
                },
                DirectPushCandidate {
                    peer: unauthenticated,
                    outbound: true,
                    gossip_score: 100.0,
                    rtt: None,
                    failure_domain: Some(vec![3]),
                },
            ],
            2,
        );
        assert_eq!(selected, vec![preferred, diverse]);

        assert_eq!(
            content.select_direct_push_targets(
                [
                    DirectPushCandidate {
                        peer: unknown_rtt,
                        outbound: true,
                        gossip_score: 10.0,
                        rtt: None,
                        failure_domain: Some(vec![3]),
                    },
                    DirectPushCandidate {
                        peer: preferred,
                        outbound: true,
                        gossip_score: 10.0,
                        rtt: Some(Duration::from_millis(10)),
                        failure_domain: Some(vec![1]),
                    },
                ],
                1,
            ),
            [preferred]
        );

        let first = fixture_object(b"first-push");
        let second = fixture_object(b"second-push");
        assert!(content.push(&preferred, &first).is_ok());
        assert!(content.push(&preferred, &second).is_err());
        assert!(content.push(&diverse, &second).is_ok());
        assert_eq!(content.pending_pushes(), 2);
    }

    #[test]
    fn publication_queue_suppresses_pending_and_known_announcements() {
        let mut content = behaviour();
        let first = fixture_announcement(b"first");
        let second = fixture_announcement(b"second");

        assert_eq!(content.queue_announcement(first.clone(), 5), Ok(true));
        assert_eq!(content.queue_announcement(first.clone(), 5), Ok(false));
        content.publications.inflight = Some((7, ContentPublication::Announcement(first.clone())));
        content
            .complete_publication(7, PublicationOutcome::Published)
            .unwrap();
        assert_eq!(content.queue_announcement(first, 5), Ok(false));
        assert_eq!(content.queue_announcement(second, 5), Ok(true));
        assert_eq!(content.pending_publications(), (1, 0));
    }

    #[test]
    fn no_peer_publication_outcome_retries_without_losing_queue_ownership() {
        let mut content = behaviour();
        let announcement = fixture_announcement(b"retry");
        content.queue_announcement(announcement.clone(), 5).unwrap();
        content.publications.inflight = Some((7, ContentPublication::Announcement(announcement)));

        content
            .complete_publication(7, PublicationOutcome::NoPeers)
            .unwrap();
        assert_eq!(content.pending_publications(), (1, 0));
        assert!(content.publications.inflight.is_none());
    }

    #[test]
    fn provider_attempts_wait_for_capability_and_are_deduplicated() {
        let mut content = behaviour();
        let first = PeerId::random();
        let second = PeerId::random();
        let id = ContentId::from_bytes([7; 32]);
        content
            .start_fetch(ObjectKind::NakamotoBlock, id, [first, first, second])
            .unwrap();
        assert!(content
            .fetches
            .by_content
            .get(&id)
            .unwrap()
            .active
            .is_none());
        content.authenticate_peer(first, CAP_OBJECT_FETCH);
        let state = content.fetches.by_content.get(&id).unwrap();
        assert_eq!(state.active.map(|(_, peer)| peer), Some(first));
        assert_eq!(state.attempted.len(), 1);
    }

    #[test]
    fn proposal_fetch_fails_over_to_a_non_origin_provider() {
        let mut content = behaviour();
        let origin = PeerId::random();
        let relay = PeerId::random();
        let id = ContentId::from_bytes([8; 32]);
        content.authenticate_peer(origin, CAP_OBJECT_FETCH);
        content.authenticate_peer(relay, CAP_OBJECT_FETCH);
        content
            .start_fetch(ObjectKind::BlockProposal, id, [origin, relay])
            .unwrap();
        let (request_id, active) = content
            .fetches
            .by_content
            .get(&id)
            .and_then(|state| state.active)
            .unwrap();
        assert_eq!(active, origin);

        content.fetch_failed(request_id, "origin disconnected".to_owned());

        let state = content.fetches.by_content.get(&id).unwrap();
        assert_eq!(state.active.map(|(_, peer)| peer), Some(relay));
        assert!(state.attempted.contains(&origin));
        assert!(state.attempted.contains(&relay));
    }

    #[test]
    fn conflicting_kind_for_one_content_id_fails_closed() {
        let mut content = behaviour();
        let id = ContentId::from_bytes([9; 32]);
        content
            .start_fetch(ObjectKind::NakamotoBlock, id, [])
            .unwrap();
        assert!(content
            .start_fetch(ObjectKind::Transaction, id, [])
            .is_err());
    }
}
