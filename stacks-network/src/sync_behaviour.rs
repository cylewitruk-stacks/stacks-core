// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Bounded request correlation and response production for Stacks sync.
//!
//! Chainstate reads, immutable planning, semantic validation, and provider
//! scoring remain transport-neutral services. This behaviour owns the wire
//! engine, request ownership, response tokens, deadlines, and per-peer bounds.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::task::Context;
use std::time::{Duration, Instant};

use futures_timer::Delay;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::{ConnectionId, FromSwarm};
use libp2p::PeerId;
use stacks_network_types::wire::v1::{Status, SyncRequest, SyncResponse};
use stacks_network_types::NetworkEnvelope;

use crate::{
    decode_sync_request, decode_sync_response, sync_request_envelope, sync_response_envelope,
    BoundedEnvelopeCodec,
};

const MAX_PENDING_INBOUND_SYNC: usize = 256;
const MAX_MANAGED_SYNC_REQUESTS: usize = 128;
const SYNC_TIMER_TICK: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncRequestOwner {
    External,
    ExternalManaged { correlation_id: u64 },
    SignerReplay { reward_cycle: u64 },
}

#[derive(Debug)]
pub enum SyncBehaviourEvent {
    ProviderAttemptFailed {
        peer: PeerId,
        owner: SyncRequestOwner,
        error: String,
    },
    InboundRequest {
        peer: PeerId,
        connection_id: ConnectionId,
        response_token: u64,
        request: SyncRequest,
        encoded_bytes: usize,
    },
    Response {
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: OutboundRequestId,
        owner: SyncRequestOwner,
        response: Result<SyncResponse, String>,
        encoded_bytes: usize,
    },
    OutboundFailure {
        peer: PeerId,
        request_id: OutboundRequestId,
        owner: SyncRequestOwner,
        error: String,
    },
    /// The aggregate request deadline elapsed, including time spent waiting
    /// for per-peer capacity. Active stock request-response attempts are
    /// detached and their eventual terminal events are ignored.
    ManagedExpired {
        peer: PeerId,
        owner: SyncRequestOwner,
        error: String,
    },
    InboundRejected {
        peer: PeerId,
        connection_id: ConnectionId,
        error: String,
    },
    InboundExpired {
        peer: PeerId,
        response_token: u64,
    },
}

struct PendingInbound {
    peer: PeerId,
    request_id: request_response::InboundRequestId,
    channel: ResponseChannel<NetworkEnvelope>,
    created_at: Instant,
}

#[derive(Clone, Copy)]
struct PendingOutbound {
    peer: PeerId,
    owner: SyncRequestOwner,
    managed: Option<u64>,
}

struct ManagedRequest {
    request: SyncRequest,
    initial_peer: PeerId,
    providers: VecDeque<PeerId>,
    attempted: HashSet<PeerId>,
    active: HashSet<OutboundRequestId>,
    owner: SyncRequestOwner,
    max_parallel: usize,
    hedge_delay: Duration,
    next_hedge: Instant,
    last_request_id: Option<OutboundRequestId>,
    last_peer: Option<PeerId>,
    last_error: Option<String>,
    deadline: Instant,
}

struct OutboundSyncRequests {
    pending: HashMap<OutboundRequestId, PendingOutbound>,
    managed: HashMap<u64, ManagedRequest>,
    ignored: HashMap<OutboundRequestId, Instant>,
    next_managed_id: u64,
    max_inflight_per_peer: usize,
}

impl OutboundSyncRequests {
    fn new(max_inflight_per_peer: usize) -> Self {
        Self {
            pending: HashMap::new(),
            managed: HashMap::new(),
            ignored: HashMap::new(),
            next_managed_id: 0,
            max_inflight_per_peer: max_inflight_per_peer.max(1),
        }
    }

    fn peer_has_capacity(&self, peer: PeerId) -> bool {
        self.pending
            .values()
            .filter(|pending| pending.peer == peer)
            .count()
            < self.max_inflight_per_peer
    }

    fn allocate_managed_id(&mut self) -> u64 {
        let id = self.next_managed_id;
        self.next_managed_id = self.next_managed_id.wrapping_add(1);
        id
    }
}

#[derive(Default)]
struct InboundSyncResponses {
    pending: HashMap<u64, PendingInbound>,
    by_request: HashMap<request_response::InboundRequestId, u64>,
    next_token: u64,
}

impl InboundSyncResponses {
    fn reserve_token(&mut self) -> Option<u64> {
        for _ in 0..=self.pending.len() {
            let token = self.next_token;
            self.next_token = self.next_token.wrapping_add(1);
            if !self.pending.contains_key(&token) {
                return Some(token);
            }
        }
        None
    }

    fn remove(&mut self, token: u64) -> Option<PendingInbound> {
        let pending = self.pending.remove(&token)?;
        self.by_request.remove(&pending.request_id);
        Some(pending)
    }

    fn remove_request(&mut self, request_id: request_response::InboundRequestId) {
        if let Some(token) = self.by_request.remove(&request_id) {
            self.pending.remove(&token);
        }
    }
}

/// Sync wire behaviour with bounded, typed ownership state.
pub struct SyncBehaviour {
    protocol: request_response::Behaviour<BoundedEnvelopeCodec>,
    chain_id: u32,
    request_timeout: Duration,
    outbound: OutboundSyncRequests,
    inbound: InboundSyncResponses,
    events: VecDeque<SyncBehaviourEvent>,
    timer: Delay,
}

impl SyncBehaviour {
    pub(super) fn new(
        protocol: request_response::Behaviour<BoundedEnvelopeCodec>,
        chain_id: u32,
        request_timeout: Duration,
        max_inflight_per_peer: usize,
    ) -> Self {
        Self {
            protocol,
            chain_id,
            request_timeout,
            outbound: OutboundSyncRequests::new(max_inflight_per_peer),
            inbound: InboundSyncResponses::default(),
            events: VecDeque::new(),
            timer: Delay::new(SYNC_TIMER_TICK),
        }
    }

    pub fn send_request(
        &mut self,
        peer: &PeerId,
        request: SyncRequest,
        owner: SyncRequestOwner,
    ) -> Result<OutboundRequestId, String> {
        if !self.outbound.peer_has_capacity(*peer) {
            return Err("sync peer exceeded its in-flight request limit".to_owned());
        }
        let envelope = sync_request_envelope(self.chain_id, &request)?;
        let request_id = self.protocol.send_request(peer, envelope);
        self.outbound.pending.insert(
            request_id,
            PendingOutbound {
                peer: *peer,
                owner,
                managed: None,
            },
        );
        Ok(request_id)
    }

    pub fn start_request(
        &mut self,
        request: SyncRequest,
        providers: impl IntoIterator<Item = PeerId>,
        owner: SyncRequestOwner,
        max_parallel: usize,
        hedge_delay: Duration,
    ) -> Result<u64, String> {
        sync_request_envelope(self.chain_id, &request)?;
        if self.outbound.managed.len() >= MAX_MANAGED_SYNC_REQUESTS {
            return Err("managed sync-request capacity reached".to_owned());
        }
        let mut deduplicated = VecDeque::new();
        let mut seen = HashSet::new();
        for peer in providers {
            if seen.insert(peer) {
                deduplicated.push_back(peer);
            }
        }
        let Some(initial_peer) = deduplicated.front().copied() else {
            return Err("managed sync request has no providers".to_owned());
        };
        let managed_id = self.outbound.allocate_managed_id();
        self.outbound.managed.insert(
            managed_id,
            ManagedRequest {
                request,
                initial_peer,
                providers: deduplicated,
                attempted: HashSet::new(),
                active: HashSet::new(),
                owner,
                max_parallel: max_parallel.max(1),
                hedge_delay,
                next_hedge: Instant::now(),
                last_request_id: None,
                last_peer: None,
                last_error: None,
                deadline: Instant::now() + self.request_timeout,
            },
        );
        self.try_managed_provider(managed_id, Instant::now());
        Ok(managed_id)
    }

    pub fn respond(&mut self, response_token: u64, response: SyncResponse) -> Result<(), String> {
        let pending = self
            .remove_pending_inbound(response_token)
            .ok_or_else(|| format!("unknown or expired sync response token {response_token}"))?;
        let envelope = sync_response_envelope(self.chain_id, &response)?;
        self.protocol
            .send_response(pending.channel, envelope)
            .map_err(|_| format!("sync response channel to {} closed", pending.peer))
    }

    pub(super) fn reject_inbound(&mut self, response_token: u64, status: Status) {
        let _ = self.respond(
            response_token,
            SyncResponse {
                status: status as i32,
                response: None,
            },
        );
    }

    pub fn pending_outbound_len(&self) -> usize {
        self.outbound.pending.len()
    }

    pub fn managed_len(&self) -> usize {
        self.outbound.managed.len()
    }

    fn try_managed_provider(&mut self, managed_id: u64, now: Instant) {
        let Some(mut managed) = self.outbound.managed.remove(&managed_id) else {
            return;
        };
        if managed.active.len() >= managed.max_parallel || now < managed.next_hedge {
            self.outbound.managed.insert(managed_id, managed);
            return;
        }
        let mut deferred = VecDeque::new();
        let mut selected = None;
        while let Some(peer) = managed.providers.pop_front() {
            if managed.attempted.contains(&peer) {
                continue;
            }
            if !self.outbound.peer_has_capacity(peer) {
                deferred.push_back(peer);
                continue;
            }
            selected = Some(peer);
            break;
        }
        managed.providers.extend(deferred);
        if let Some(peer) = selected {
            let envelope = match sync_request_envelope(self.chain_id, &managed.request) {
                Ok(envelope) => envelope,
                Err(error) => {
                    managed.last_error = Some(error);
                    self.finish_managed_failure(managed);
                    return;
                }
            };
            let request_id = self.protocol.send_request(&peer, envelope);
            managed.attempted.insert(peer);
            managed.active.insert(request_id);
            managed.last_request_id = Some(request_id);
            managed.last_peer = Some(peer);
            managed.next_hedge = now + managed.hedge_delay;
            self.outbound.pending.insert(
                request_id,
                PendingOutbound {
                    peer,
                    owner: managed.owner,
                    managed: Some(managed_id),
                },
            );
            self.outbound.managed.insert(managed_id, managed);
        } else if managed.active.is_empty() && managed.providers.is_empty() {
            self.finish_managed_failure(managed);
        } else {
            self.outbound.managed.insert(managed_id, managed);
        }
    }

    fn finish_managed_failure(&mut self, managed: ManagedRequest) {
        if let (Some(request_id), Some(peer)) = (managed.last_request_id, managed.last_peer) {
            self.events.push_back(SyncBehaviourEvent::OutboundFailure {
                peer,
                request_id,
                owner: managed.owner,
                error: managed
                    .last_error
                    .unwrap_or_else(|| "all sync providers failed".to_owned()),
            });
        }
    }

    fn complete_managed(&mut self, managed_id: u64, winner: OutboundRequestId, now: Instant) {
        let Some(managed) = self.outbound.managed.remove(&managed_id) else {
            return;
        };
        for request_id in managed.active {
            if request_id == winner {
                continue;
            }
            self.outbound.pending.remove(&request_id);
            self.outbound
                .ignored
                .insert(request_id, now + self.request_timeout);
        }
    }

    fn fail_managed_attempt(
        &mut self,
        managed_id: u64,
        request_id: OutboundRequestId,
        peer: PeerId,
        error: String,
        now: Instant,
    ) {
        let Some(managed) = self.outbound.managed.get_mut(&managed_id) else {
            return;
        };
        managed.active.remove(&request_id);
        managed.last_error = Some(error.clone());
        managed.next_hedge = now;
        self.events
            .push_back(SyncBehaviourEvent::ProviderAttemptFailed {
                peer,
                owner: managed.owner,
                error,
            });
        self.try_managed_provider(managed_id, now);
    }

    fn reserve_response_token(&mut self) -> Option<u64> {
        if self.inbound.pending.len() >= MAX_PENDING_INBOUND_SYNC {
            return None;
        }
        self.inbound.reserve_token()
    }

    fn remove_pending_inbound(&mut self, token: u64) -> Option<PendingInbound> {
        self.inbound.remove(token)
    }

    fn on_protocol_event(
        &mut self,
        event: request_response::Event<NetworkEnvelope, NetworkEnvelope>,
    ) {
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
                match decode_sync_request(&request, self.chain_id) {
                    Ok(request) => {
                        let per_peer = self
                            .inbound
                            .pending
                            .values()
                            .filter(|pending| pending.peer == peer)
                            .count();
                        let Some(response_token) = (per_peer < self.outbound.max_inflight_per_peer)
                            .then(|| self.reserve_response_token())
                            .flatten()
                        else {
                            let response = SyncResponse {
                                status: Status::Busy as i32,
                                response: None,
                            };
                            if let Ok(response) = sync_response_envelope(self.chain_id, &response) {
                                let _ = self.protocol.send_response(channel, response);
                            }
                            self.events.push_back(SyncBehaviourEvent::InboundRejected {
                                peer,
                                connection_id,
                                error: "sync response capacity reached".to_owned(),
                            });
                            return;
                        };
                        self.inbound.by_request.insert(request_id, response_token);
                        self.inbound.pending.insert(
                            response_token,
                            PendingInbound {
                                peer,
                                request_id,
                                channel,
                                created_at: Instant::now(),
                            },
                        );
                        self.events.push_back(SyncBehaviourEvent::InboundRequest {
                            peer,
                            connection_id,
                            response_token,
                            request,
                            encoded_bytes,
                        });
                    }
                    Err(error) => {
                        let response = SyncResponse {
                            status: Status::InvalidRequest as i32,
                            response: None,
                        };
                        if let Ok(response) = sync_response_envelope(self.chain_id, &response) {
                            let _ = self.protocol.send_response(channel, response);
                        }
                        self.events.push_back(SyncBehaviourEvent::InboundRejected {
                            peer,
                            connection_id,
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
                let Some(pending) = self.outbound.pending.remove(&request_id) else {
                    if self.outbound.ignored.remove(&request_id).is_some() {
                        return;
                    }
                    self.events.push_back(SyncBehaviourEvent::InboundRejected {
                        peer,
                        connection_id,
                        error: "unknown sync response".to_owned(),
                    });
                    return;
                };
                let response = if pending.peer != peer {
                    Err("sync response peer mismatch".to_owned())
                } else {
                    decode_sync_response(&response, self.chain_id)
                };
                if let Some(managed_id) = pending.managed {
                    match response {
                        Ok(response) => {
                            self.complete_managed(managed_id, request_id, Instant::now());
                            self.events.push_back(SyncBehaviourEvent::Response {
                                peer,
                                connection_id,
                                request_id,
                                owner: pending.owner,
                                response: Ok(response),
                                encoded_bytes,
                            });
                        }
                        Err(error) => self.fail_managed_attempt(
                            managed_id,
                            request_id,
                            peer,
                            error,
                            Instant::now(),
                        ),
                    }
                    return;
                }
                self.events.push_back(SyncBehaviourEvent::Response {
                    peer,
                    connection_id,
                    request_id,
                    owner: pending.owner,
                    response,
                    encoded_bytes,
                });
            }
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                if let Some(pending) = self.outbound.pending.remove(&request_id) {
                    let error = format!("{error} (reported peer {peer})");
                    if let Some(managed_id) = pending.managed {
                        self.fail_managed_attempt(
                            managed_id,
                            request_id,
                            pending.peer,
                            error,
                            Instant::now(),
                        );
                    } else {
                        self.events.push_back(SyncBehaviourEvent::OutboundFailure {
                            peer: pending.peer,
                            request_id,
                            owner: pending.owner,
                            error,
                        });
                    }
                } else {
                    self.outbound.ignored.remove(&request_id);
                }
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                connection_id,
            } => {
                self.inbound.remove_request(request_id);
                self.events.push_back(SyncBehaviourEvent::InboundRejected {
                    peer,
                    connection_id,
                    error: error.to_string(),
                });
            }
            request_response::Event::ResponseSent { request_id, .. } => {
                self.inbound.remove_request(request_id);
            }
        }
    }

    fn expire(&mut self, now: Instant) {
        self.outbound.ignored.retain(|_, deadline| *deadline > now);
        let expired_managed = self
            .outbound
            .managed
            .iter()
            .filter_map(|(id, request)| (now >= request.deadline).then_some(*id))
            .collect::<Vec<_>>();
        for id in expired_managed {
            let Some(managed) = self.outbound.managed.remove(&id) else {
                continue;
            };
            let peer = managed
                .last_peer
                .or_else(|| managed.providers.front().copied())
                .or_else(|| managed.attempted.iter().next().copied())
                .unwrap_or(managed.initial_peer);
            for request_id in managed.active {
                self.outbound.pending.remove(&request_id);
                self.outbound
                    .ignored
                    .insert(request_id, now + self.request_timeout);
            }
            self.events.push_back(SyncBehaviourEvent::ManagedExpired {
                peer,
                owner: managed.owner,
                error: "managed sync request exceeded its aggregate deadline".to_owned(),
            });
        }
        let managed = self
            .outbound
            .managed
            .iter()
            .filter_map(|(id, request)| {
                (request.active.len() < request.max_parallel && now >= request.next_hedge)
                    .then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in managed {
            self.try_managed_provider(id, now);
        }
        let expired = self
            .inbound
            .pending
            .iter()
            .filter_map(|(token, pending)| {
                (now.saturating_duration_since(pending.created_at) >= self.request_timeout)
                    .then_some((*token, pending.peer))
            })
            .collect::<Vec<_>>();
        for (token, peer) in expired {
            self.remove_pending_inbound(token);
            self.events.push_back(SyncBehaviourEvent::InboundExpired {
                peer,
                response_token: token,
            });
        }
    }
}

impl SyncBehaviour {
    fn on_forwarded_swarm_event(&mut self, _event: &FromSwarm<'_>) {}

    fn poll_scheduled(&mut self, cx: &mut Context<'_>) {
        if std::pin::Pin::new(&mut self.timer).poll(cx).is_ready() {
            self.expire(Instant::now());
            self.timer.reset(SYNC_TIMER_TICK);
        }
    }
}

impl_bounded_request_response_behaviour!(SyncBehaviour, SyncBehaviourEvent);

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::request_response::ProtocolSupport;
    use libp2p::swarm::StreamProtocol;
    use stacks_network_types::wire::v1::{sync_request, sync_response, GetStatus, SyncStatus};
    use stacks_network_types::EnvelopeLimits;

    fn behaviour(max_inflight: usize) -> SyncBehaviour {
        let protocol = request_response::Behaviour::with_codec(
            BoundedEnvelopeCodec::new(EnvelopeLimits::SYNC),
            [(
                StreamProtocol::new("/stacks/sync/test/1"),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );
        SyncBehaviour::new(protocol, 1, Duration::from_secs(10), max_inflight)
    }

    fn status_request() -> SyncRequest {
        SyncRequest {
            request: Some(sync_request::Request::GetStatus(GetStatus {})),
        }
    }

    #[test]
    fn outbound_ownership_and_per_peer_limit_are_exact() {
        let mut sync = behaviour(1);
        let peer = PeerId::random();
        let request_id = sync
            .send_request(&peer, status_request(), SyncRequestOwner::External)
            .unwrap();
        assert_eq!(sync.pending_outbound_len(), 1);
        assert!(sync
            .send_request(&peer, status_request(), SyncRequestOwner::External)
            .is_err());
        let pending = sync.outbound.pending.remove(&request_id).unwrap();
        assert_eq!(pending.owner, SyncRequestOwner::External);
    }

    #[test]
    fn response_tokens_do_not_alias_across_wraparound() {
        let mut sync = behaviour(1);
        sync.inbound.next_token = u64::MAX;
        assert_eq!(sync.reserve_response_token(), Some(u64::MAX));
        sync.inbound.next_token = 0;
        assert_eq!(sync.reserve_response_token(), Some(0));
    }

    #[test]
    fn managed_request_fails_over_and_reports_exhaustion_once() {
        let mut sync = behaviour(1);
        let first = PeerId::random();
        let second = PeerId::random();
        sync.start_request(
            status_request(),
            [first, second],
            SyncRequestOwner::ExternalManaged { correlation_id: 7 },
            1,
            Duration::from_secs(10),
        )
        .unwrap();
        let first_request = *sync.outbound.pending.keys().next().unwrap();
        sync.on_protocol_event(request_response::Event::OutboundFailure {
            peer: first,
            connection_id: ConnectionId::new_unchecked(1),
            request_id: first_request,
            error: request_response::OutboundFailure::DialFailure,
        });
        assert!(matches!(
            sync.events.pop_front(),
            Some(SyncBehaviourEvent::ProviderAttemptFailed { peer, .. }) if peer == first
        ));
        let (&second_request, pending) = sync.outbound.pending.iter().next().unwrap();
        assert_eq!(pending.peer, second);

        sync.on_protocol_event(request_response::Event::OutboundFailure {
            peer: second,
            connection_id: ConnectionId::new_unchecked(2),
            request_id: second_request,
            error: request_response::OutboundFailure::Timeout,
        });
        assert!(matches!(
            sync.events.pop_front(),
            Some(SyncBehaviourEvent::ProviderAttemptFailed { peer, .. }) if peer == second
        ));
        assert!(matches!(
            sync.events.pop_front(),
            Some(SyncBehaviourEvent::OutboundFailure {
                owner: SyncRequestOwner::ExternalManaged { correlation_id: 7 },
                ..
            })
        ));
        assert_eq!(sync.managed_len(), 0);
    }

    #[test]
    fn first_valid_hedged_response_wins_and_late_response_is_ignored() {
        let mut sync = behaviour(2);
        let first = PeerId::random();
        let second = PeerId::random();
        sync.start_request(
            status_request(),
            [first, second],
            SyncRequestOwner::ExternalManaged { correlation_id: 9 },
            2,
            Duration::ZERO,
        )
        .unwrap();
        sync.expire(Instant::now());
        assert_eq!(sync.outbound.pending.len(), 2);
        let (&winner, pending) = sync
            .outbound
            .pending
            .iter()
            .find(|(_, pending)| pending.peer == first)
            .unwrap();
        let response = SyncResponse {
            status: Status::Ok as i32,
            response: Some(sync_response::Response::StatusView(SyncStatus {
                burn_tip_height: 1,
                burn_tip_hash: vec![1; 32],
                stable_burn_tip_height: 1,
                stable_burn_tip_hash: vec![2; 32],
                stacks_tip_height: 1,
                stacks_tip_id: vec![3; 32],
                current_reward_cycle: 0,
            })),
        };
        sync.on_protocol_event(request_response::Event::Message {
            peer: pending.peer,
            connection_id: ConnectionId::new_unchecked(3),
            message: request_response::Message::Response {
                request_id: winner,
                response: sync_response_envelope(1, &response).unwrap(),
            },
        });
        assert_eq!(sync.managed_len(), 0);
        assert_eq!(sync.outbound.pending.len(), 0);
        assert_eq!(sync.outbound.ignored.len(), 1);
        assert!(matches!(
            sync.events.pop_front(),
            Some(SyncBehaviourEvent::Response {
                owner: SyncRequestOwner::ExternalManaged { correlation_id: 9 },
                ..
            })
        ));
    }

    #[test]
    fn managed_request_deadline_cancels_owned_attempts_once() {
        let mut sync = behaviour(1);
        let peer = PeerId::random();
        sync.start_request(
            status_request(),
            [peer],
            SyncRequestOwner::ExternalManaged { correlation_id: 11 },
            1,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(sync.pending_outbound_len(), 1);

        sync.expire(Instant::now() + Duration::from_secs(11));
        assert_eq!(sync.managed_len(), 0);
        assert_eq!(sync.pending_outbound_len(), 0);
        assert_eq!(sync.outbound.ignored.len(), 1);
        assert!(matches!(
            sync.events.pop_front(),
            Some(SyncBehaviourEvent::ManagedExpired {
                peer: expired_peer,
                owner: SyncRequestOwner::ExternalManaged { correlation_id: 11 },
                ..
            }) if expired_peer == peer
        ));
        sync.expire(Instant::now() + Duration::from_secs(12));
        assert!(sync.events.is_empty());
    }
}
