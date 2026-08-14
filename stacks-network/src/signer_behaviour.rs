// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Semantic signer authentication, admission, journal, and direct wire.
//!
//! The shared service supplies only the cross-protocol resource-budget and
//! downstream-consumer decisions. Raw direct requests and validated-but-not-
//! delivered envelopes remain owned here behind opaque tokens.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::task::Context;
use std::time::{Duration, Instant};

use futures_timer::Delay;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::{ConnectionId, FromSwarm};
use libp2p::PeerId;
use prost::Message as ProstMessage;
use stacks_network_types::wire::v1::{EnvelopeKind, SignerEnvelope, SignerLane};
use stacks_network_types::{
    signer_envelope_id, supports, ContentId, NetworkEnvelope, NetworkScope,
    CAP_PROPOSAL_UNAVAILABLE, CAP_SIGNER_SEMANTICS,
};

use crate::signer::MinerAuthorizationStatus;
use crate::{
    AuthorizationSnapshot, AuthorizationSnapshotError, AuthorizationSnapshotUpdate,
    BoundedEnvelopeCodec, MemorySignerJournal, PublicationOutcome, SignerAdmission,
    SignerAuthorizationState, SignerBindingUpdate, SignerEnvelopeVerifier, VerifiedSignerEnvelope,
};

const MAX_PENDING_SIGNER_ACTIONS: usize = 256;
const MAX_SIGNER_BEHAVIOUR_EVENTS: usize = 512;
const SIGNER_TICK: Duration = Duration::from_millis(100);
const PUBLICATION_RETRY: Duration = Duration::from_millis(250);
const DIRECT_RETRY_INITIAL: Duration = Duration::from_millis(500);
const DIRECT_RETRY_MAX: Duration = Duration::from_secs(8);
// Availability observations are local delivery obligations, but a full
// downstream queue must not turn the 100ms behaviour tick into a retry/log
// amplifier. Keep the first observation immediate, then use the same bounded
// exponential shape as direct delivery while the canonical-view TTL remains
// the overall lifetime bound.
const DEFERRED_OBSERVATION_RETRY_INITIAL: Duration = Duration::from_millis(500);
const DEFERRED_OBSERVATION_RETRY_MAX: Duration = Duration::from_secs(8);
const SIGNER_PUBLICATION_QUEUE_CAPACITY: usize = 256;
const SIGNER_PUBLICATION_QUEUE_BYTES: usize = 16 * 1024 * 1024;
const MINER_DIRECT_MAILBOX_CAPACITY: usize = 8;
const MINER_DIRECT_MAILBOX_BYTES: usize = 20 * 1024 * 1024;
// Match the signer's default block-proposal lifetime. This stays below the
// miner's 180-second base rejection step, so released work can still matter.
const MINER_RESPONSE_WINDOW: Duration = Duration::from_secs(120);
const MINER_DIRECT_MAILBOX_TTL: Duration = MINER_RESPONSE_WINDOW;
/// A replay that completed before a peer published its reconstructed state is
/// not proof that the journal will remain empty. Refresh cursors periodically
/// so simultaneous signer-set startup cannot permanently lose the one-shot
/// state update emitted before GossipSub's mesh converges.
const SIGNER_REPLAY_REFRESH: Duration = Duration::from_secs(10);
/// A failed provider is skipped briefly so the next authenticated signer can
/// serve the cycle. A deployment with only one eligible provider still
/// retries it on the following maintenance pass.
const SIGNER_REPLAY_PROVIDER_BACKOFF: Duration = Duration::from_secs(5);
const DEFERRED_MINER_AUTHORIZATION_TTL: Duration = MINER_RESPONSE_WINDOW;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerIngress {
    Direct,
    Gossip,
    Replay,
}

#[derive(Clone, Debug)]
pub struct StagedSignerEnvelope {
    pub token: u64,
    /// Connected peer that can serve content referenced by this envelope.
    pub provider: PeerId,
    /// End-to-end authenticated envelope author.
    pub source: PeerId,
    pub envelope: VerifiedSignerEnvelope,
    pub admission: SignerAdmission,
    pub revoked_peer: Option<PeerId>,
    pub ingress: SignerIngress,
    pub was_deferred: bool,
}

#[derive(Debug)]
pub enum SignerBehaviourEvent {
    AdmissionRequired {
        token: u64,
        peer: PeerId,
        connection_id: ConnectionId,
        encoded_bytes: usize,
        validation_units: u64,
    },
    DeliveryRequired(Box<StagedSignerEnvelope>),
    /// A source-bound, correctly signed miner envelope whose sortition is not
    /// present in the applied canonical snapshot. This is local availability
    /// evidence only: it is not bound, journaled, relayed, or object-fetched.
    MinerAuthorizationDeferred {
        token: u64,
        source: PeerId,
        provider: PeerId,
        envelope: Box<VerifiedSignerEnvelope>,
        ingress: SignerIngress,
    },
    MinerAuthorizationExpired {
        source: PeerId,
        ingress: SignerIngress,
    },
    Redundant {
        source: PeerId,
        envelope_id: ContentId,
        lane: SignerLane,
        sequence: u64,
        admission: SignerAdmission,
        ingress: SignerIngress,
    },
    DirectAcknowledged {
        peer: PeerId,
        envelope_id: ContentId,
    },
    DirectFailed {
        peer: PeerId,
        envelope_id: Option<ContentId>,
        error: String,
    },
    DirectSent {
        peer: PeerId,
        envelope_id: ContentId,
    },
    MailboxExpired {
        undelivered: usize,
    },
    PublishGossip {
        token: u64,
        envelope: SignerEnvelope,
    },
    PublicationCompleted {
        outcome: PublicationOutcome,
    },
    Rejected {
        peer: PeerId,
        ingress: SignerIngress,
        error: String,
    },
}

struct RawDirectAction {
    peer: PeerId,
    request: NetworkEnvelope,
    channel: ResponseChannel<NetworkEnvelope>,
}

enum PendingOrigin {
    Direct(ResponseChannel<NetworkEnvelope>),
    Gossip,
}

struct PendingDelivery {
    staged: StagedSignerEnvelope,
    origin: PendingOrigin,
    deferred_created_at: Option<Instant>,
    deferred_release_failures: u8,
}

struct DeferredMinerDelivery {
    source: PeerId,
    provider: PeerId,
    envelope: VerifiedSignerEnvelope,
    ingress: SignerIngress,
    origin: PendingOrigin,
    created_at: Instant,
    observation_delivered: bool,
    observation_inflight: bool,
    observation_failures: u8,
    next_observation_at: Instant,
    release_failures: u8,
    next_release_at: Instant,
}

/// Conserved lifecycle accounting for canonically-pending miner envelopes.
///
/// `admitted` is incremented exactly when an envelope enters `deferred_miners`.
/// Every admitted envelope is then either still pending or represented by
/// exactly one terminal counter below.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeferredMinerAuthorizationSnapshot {
    pub admitted: u64,
    pub observation_delivered: u64,
    pub observation_retries: u64,
    pub released: u64,
    pub expired: u64,
    pub unauthorized: u64,
    pub redundant: u64,
    pub binding_failed: u64,
    pub malformed: u64,
    pub pending: usize,
}

impl DeferredMinerAuthorizationSnapshot {
    pub fn resolved_total(&self) -> u64 {
        self.released
            .saturating_add(self.expired)
            .saturating_add(self.unauthorized)
            .saturating_add(self.redundant)
            .saturating_add(self.binding_failed)
            .saturating_add(self.malformed)
    }

    pub fn is_conserved(&self) -> bool {
        self.admitted
            == u64::try_from(self.pending)
                .unwrap_or(u64::MAX)
                .saturating_add(self.resolved_total())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeferredMinerResolution {
    Released,
    Expired,
    Unauthorized,
    Redundant,
    BindingFailed,
    Malformed,
}

struct QueuedPublication {
    token: u64,
    envelope: SignerEnvelope,
    bytes: usize,
}

struct RetainedDirectDelivery {
    envelope: SignerEnvelope,
    envelope_id: ContentId,
    sent_to: HashSet<PeerId>,
    retries: HashMap<PeerId, DirectRetryState>,
    created_at: Instant,
    bytes: usize,
}

#[derive(Clone, Copy)]
struct DirectRetryState {
    failures: u8,
    retry_at: Instant,
}

#[derive(Default)]
struct SignerPeers {
    rendezvous: HashSet<PeerId>,
    capabilities: HashMap<PeerId, u64>,
    connected: HashSet<PeerId>,
}

#[derive(Default)]
struct SignerIngressState {
    authorizations: SignerAuthorizationState,
    journal: MemorySignerJournal,
    raw_actions: HashMap<u64, RawDirectAction>,
    pending_deliveries: HashMap<u64, PendingDelivery>,
    deferred_miners: HashMap<u64, DeferredMinerDelivery>,
    deferred_miner_lifecycle: DeferredMinerAuthorizationSnapshot,
    next_token: u64,
}

#[derive(Default)]
struct SignerPublications {
    queue: VecDeque<QueuedPublication>,
    bytes: usize,
    inflight: Option<u64>,
    last_attempt: Option<Instant>,
}

#[derive(Default)]
struct SignerDirectDeliveries {
    pending: HashMap<OutboundRequestId, (PeerId, ContentId)>,
    retained: VecDeque<RetainedDirectDelivery>,
    bytes: usize,
}

#[derive(Clone, Copy, Debug)]
struct SignerReplayAttempt {
    provider: PeerId,
    requested_at: Instant,
}

/// Coordinate signer repair per reward cycle, rather than per remote peer.
///
/// Every authorized signer can serve the same author-signed journal. Issuing
/// one page request to every peer therefore multiplies identical work by the
/// signer-set size and can overwhelm the bounded downstream queue. A cycle
/// has at most one active/refresh attempt, with a short provider exclusion on
/// failure so deterministic peer iteration produces immediate failover.
#[derive(Default)]
struct SignerReplayTracker {
    attempts: HashMap<u64, SignerReplayAttempt>,
    failed_providers: HashMap<u64, (PeerId, Instant)>,
}

/// Cohesive signer protocol boundary. GossipSub remains a shared stock engine
/// in `StacksApplicationBehaviour`; signer-topic bytes enter through
/// `stage_gossip`, so signer policy and journal state still have one owner.
pub struct SignerBehaviour {
    protocol: request_response::Behaviour<BoundedEnvelopeCodec>,
    verifier: SignerEnvelopeVerifier,
    peers: SignerPeers,
    ingress: SignerIngressState,
    direct: SignerDirectDeliveries,
    publications: SignerPublications,
    replays: SignerReplayTracker,
    events: VecDeque<SignerBehaviourEvent>,
    timer: Delay,
}

pub struct PreparedSignerAuthorization {
    state: SignerAuthorizationState,
    update: AuthorizationSnapshotUpdate,
}

impl PreparedSignerAuthorization {
    pub fn update(&self) -> &AuthorizationSnapshotUpdate {
        &self.update
    }
}

impl SignerBehaviour {
    pub fn new(
        protocol: request_response::Behaviour<BoundedEnvelopeCodec>,
        scope: NetworkScope,
    ) -> Self {
        Self {
            protocol,
            verifier: SignerEnvelopeVerifier::new(scope),
            peers: SignerPeers::default(),
            ingress: SignerIngressState::default(),
            direct: SignerDirectDeliveries::default(),
            publications: SignerPublications::default(),
            replays: SignerReplayTracker::default(),
            events: VecDeque::new(),
            timer: Delay::new(SIGNER_TICK),
        }
    }

    pub fn set_rendezvous_peers(&mut self, peers: impl IntoIterator<Item = PeerId>) {
        self.peers.rendezvous = peers.into_iter().collect();
    }

    pub fn authenticate_peer(&mut self, peer: PeerId, capabilities: u64) {
        if supports(capabilities, CAP_SIGNER_SEMANTICS) {
            self.peers.capabilities.insert(peer, capabilities);
        } else {
            self.peers.capabilities.remove(&peer);
        }
    }

    /// Clear transport capability and pending work. Cycle-scoped identity
    /// bindings survive an ordinary disconnect and can authenticate a later
    /// replay server; explicit authorization removal/rekey uses `revoke_peer`.
    pub fn disconnect_peer(&mut self, peer: &PeerId) {
        self.peers.capabilities.remove(peer);
        self.ingress
            .raw_actions
            .retain(|_, action| &action.peer != peer);
        // A staged envelope has already passed transport binding and semantic
        // validation. Keep its delivery obligation across disconnect so a
        // queued typed event cannot reach the consumer without journal commit.
        let interrupted = self
            .direct
            .pending
            .extract_if(|_, (pending_peer, _)| pending_peer == peer)
            .map(|(_, (_, envelope_id))| envelope_id)
            .collect::<Vec<_>>();
        let now = Instant::now();
        for envelope_id in interrupted {
            self.mark_direct_failure(*peer, envelope_id, now);
        }
        let interrupted_replays = self
            .replays
            .attempts
            .iter()
            .filter_map(|(cycle, attempt)| (attempt.provider == *peer).then_some(*cycle))
            .collect::<Vec<_>>();
        for cycle in interrupted_replays {
            self.replays.attempts.remove(&cycle);
            self.replays.failed_providers.insert(cycle, (*peer, now));
        }
    }

    pub fn revoke_peer(&mut self, peer: &PeerId) {
        self.disconnect_peer(peer);
        self.ingress.authorizations.revoke_peer(peer);
    }

    pub fn apply_authorization_snapshot(
        &mut self,
        snapshot: AuthorizationSnapshot,
    ) -> Result<AuthorizationSnapshotUpdate, AuthorizationSnapshotError> {
        let prepared = self.prepare_authorization_snapshot(&snapshot)?;
        Ok(self.commit_authorization_snapshot(prepared))
    }

    pub fn prepare_authorization_snapshot(
        &self,
        snapshot: &AuthorizationSnapshot,
    ) -> Result<PreparedSignerAuthorization, AuthorizationSnapshotError> {
        let mut state = self.ingress.authorizations.clone();
        let update = state.apply_snapshot(snapshot.clone())?;
        Ok(PreparedSignerAuthorization { state, update })
    }

    pub fn commit_authorization_snapshot(
        &mut self,
        prepared: PreparedSignerAuthorization,
    ) -> AuthorizationSnapshotUpdate {
        self.ingress.authorizations = prepared.state;
        self.release_deferred_miners(Instant::now());
        prepared.update
    }

    fn release_deferred_miners(&mut self, now: Instant) {
        let deferred = std::mem::take(&mut self.ingress.deferred_miners);
        for (token, pending) in deferred {
            if now.saturating_duration_since(pending.created_at) >= DEFERRED_MINER_AUTHORIZATION_TTL
            {
                self.resolve_deferred_miner(DeferredMinerResolution::Expired);
                self.push_event(SignerBehaviourEvent::MinerAuthorizationExpired {
                    source: pending.source,
                    ingress: pending.ingress,
                });
                continue;
            }
            if !pending.observation_delivered {
                self.ingress.deferred_miners.insert(token, pending);
                continue;
            }
            if now < pending.next_release_at {
                self.ingress.deferred_miners.insert(token, pending);
                continue;
            }
            let miner_key: [u8; 33] = match pending
                .envelope
                .body
                .signer_public_key
                .as_slice()
                .try_into()
            {
                Ok(key) => key,
                Err(_) => {
                    self.resolve_deferred_miner(DeferredMinerResolution::Malformed);
                    continue;
                }
            };
            match self.ingress.authorizations.miner_authorization_status(
                pending.envelope.body.reward_cycle,
                &pending.envelope.body.burn_view_consensus_hash,
                &miner_key,
            ) {
                MinerAuthorizationStatus::CanonicalViewPending => {
                    self.ingress.deferred_miners.insert(token, pending);
                }
                MinerAuthorizationStatus::Unauthorized => {
                    self.resolve_deferred_miner(DeferredMinerResolution::Unauthorized);
                    self.push_event(SignerBehaviourEvent::Rejected {
                        peer: pending.source,
                        ingress: pending.ingress,
                        error: "deferred miner identity conflicts with canonical chain state"
                            .to_owned(),
                    });
                }
                MinerAuthorizationStatus::Authorized => {
                    let revoked_peer = match self.ingress.authorizations.bind_miner(
                        pending.envelope.body.reward_cycle,
                        pending.envelope.body.burn_view_consensus_hash.clone(),
                        miner_key,
                        pending.source,
                    ) {
                        Ok(SignerBindingUpdate::Rekeyed { revoked_peer }) => Some(revoked_peer),
                        Ok(SignerBindingUpdate::Bound | SignerBindingUpdate::Unchanged) => None,
                        Err(error) => {
                            self.resolve_deferred_miner(DeferredMinerResolution::BindingFailed);
                            self.push_event(SignerBehaviourEvent::Rejected {
                                peer: pending.source,
                                ingress: pending.ingress,
                                error: error.to_owned(),
                            });
                            continue;
                        }
                    };
                    let admission = self.ingress.journal.classify(&pending.envelope);
                    if matches!(
                        admission,
                        SignerAdmission::Duplicate | SignerAdmission::Stale
                    ) {
                        self.resolve_deferred_miner(DeferredMinerResolution::Redundant);
                        self.push_event(SignerBehaviourEvent::Redundant {
                            source: pending.source,
                            envelope_id: pending.envelope.envelope_id,
                            lane: SignerLane::BlockProposal,
                            sequence: pending.envelope.body.sequence,
                            admission,
                            ingress: pending.ingress,
                        });
                        continue;
                    }
                    let staged = StagedSignerEnvelope {
                        token,
                        provider: pending.provider,
                        source: pending.source,
                        envelope: pending.envelope,
                        admission,
                        revoked_peer,
                        ingress: pending.ingress,
                        was_deferred: true,
                    };
                    self.ingress.pending_deliveries.insert(
                        token,
                        PendingDelivery {
                            staged: staged.clone(),
                            origin: pending.origin,
                            deferred_created_at: Some(pending.created_at),
                            deferred_release_failures: pending.release_failures,
                        },
                    );
                    self.push_event(SignerBehaviourEvent::DeliveryRequired(Box::new(staged)));
                }
            }
        }
    }

    fn resolve_deferred_miner(&mut self, outcome: DeferredMinerResolution) {
        let lifecycle = &mut self.ingress.deferred_miner_lifecycle;
        let counter = match outcome {
            DeferredMinerResolution::Released => &mut lifecycle.released,
            DeferredMinerResolution::Expired => &mut lifecycle.expired,
            DeferredMinerResolution::Unauthorized => &mut lifecycle.unauthorized,
            DeferredMinerResolution::Redundant => &mut lifecycle.redundant,
            DeferredMinerResolution::BindingFailed => &mut lifecycle.binding_failed,
            DeferredMinerResolution::Malformed => &mut lifecycle.malformed,
        };
        *counter = counter.saturating_add(1);
    }

    pub fn authorization_state(&self) -> &SignerAuthorizationState {
        &self.ingress.authorizations
    }

    pub fn bind_authorized_signer(
        &mut self,
        reward_cycle: u64,
        signer_key: [u8; 33],
        peer: PeerId,
    ) -> Result<SignerBindingUpdate, &'static str> {
        self.ingress
            .authorizations
            .bind(reward_cycle, signer_key, peer)
    }

    pub fn bind_authorized_miner(
        &mut self,
        reward_cycle: u64,
        role_id: Vec<u8>,
        miner_key: [u8; 33],
        peer: PeerId,
    ) -> Result<SignerBindingUpdate, &'static str> {
        self.ingress
            .authorizations
            .bind_miner(reward_cycle, role_id, miner_key, peer)
    }

    pub fn restore_envelope(
        &mut self,
        envelope: &SignerEnvelope,
    ) -> Result<SignerAdmission, String> {
        let body = envelope
            .body
            .as_ref()
            .ok_or_else(|| "persisted signer envelope has no body".to_owned())?;
        let peer = PeerId::from_bytes(&body.transport_peer_id)
            .map_err(|_| "persisted signer envelope has an invalid transport PeerId".to_owned())?;
        let verified = self
            .verifier
            .verify(envelope, &peer)
            .map_err(|error| error.to_string())?;
        Ok(self.ingress.journal.admit(&verified))
    }

    pub fn retain_cycles(&mut self, current: u64, next: Option<u64>) {
        self.ingress.journal.retain_cycles(current, next);
    }

    pub fn replay(
        &self,
        reward_cycle: u64,
        cursors: &[stacks_network_types::wire::v1::SignerReplayCursor],
        max_items: usize,
        max_bytes: usize,
    ) -> (Vec<SignerEnvelope>, bool) {
        self.ingress
            .journal
            .replay(reward_cycle, cursors, max_items, max_bytes)
    }

    pub fn cursors(
        &self,
        reward_cycle: u64,
    ) -> Vec<stacks_network_types::wire::v1::SignerReplayCursor> {
        self.ingress.journal.cursors(reward_cycle)
    }

    pub fn equivocation_count(&self) -> usize {
        self.ingress.journal.equivocation_count()
    }

    pub fn direct_targets(
        &self,
        envelope: &SignerEnvelope,
        connected: &HashSet<PeerId>,
    ) -> Vec<PeerId> {
        const MAX_REDUNDANT_SIGNER_TARGETS: usize = 4;
        let Some(body) = envelope.body.as_ref() else {
            return Vec::new();
        };
        let Ok(lane) = SignerLane::try_from(body.lane) else {
            return Vec::new();
        };
        let (candidates, limit): (Vec<PeerId>, usize) = match lane {
            SignerLane::BlockProposal | SignerLane::BlockPushed => (
                self.ingress
                    .authorizations
                    .peers_for_cycle(body.reward_cycle)
                    .into_iter()
                    .collect(),
                usize::MAX,
            ),
            SignerLane::BlockResponse => (
                self.ingress
                    .authorizations
                    .miner_peers_for_cycle(body.reward_cycle)
                    .into_iter()
                    .collect(),
                usize::MAX,
            ),
            SignerLane::ProposalUnavailable => (
                self.ingress
                    .authorizations
                    .miner_peers_for_cycle(body.reward_cycle)
                    .into_iter()
                    .collect(),
                usize::MAX,
            ),
            SignerLane::BlockPreCommit | SignerLane::StateMachineUpdate => (
                self.ingress
                    .authorizations
                    .peers_for_cycle(body.reward_cycle)
                    .into_iter()
                    .collect(),
                MAX_REDUNDANT_SIGNER_TARGETS,
            ),
            SignerLane::Control | SignerLane::Unspecified => return Vec::new(),
        };
        let required_capabilities = if lane == SignerLane::ProposalUnavailable {
            CAP_SIGNER_SEMANTICS | CAP_PROPOSAL_UNAVAILABLE
        } else {
            CAP_SIGNER_SEMANTICS
        };
        let mut targets = candidates
            .into_iter()
            .filter(|peer| {
                connected.contains(peer)
                    && self
                        .peers
                        .capabilities
                        .get(peer)
                        .is_some_and(|caps| supports(*caps, required_capabilities))
            })
            .collect::<Vec<_>>();
        targets.sort_by_key(|peer| peer.to_bytes());
        targets.truncate(limit);
        targets
    }

    pub fn queue_publication(
        &mut self,
        local_peer: PeerId,
        envelope: SignerEnvelope,
    ) -> Result<SignerAdmission, String> {
        let bytes = envelope.encoded_len();
        if self.publications.queue.len() >= SIGNER_PUBLICATION_QUEUE_CAPACITY
            || bytes > SIGNER_PUBLICATION_QUEUE_BYTES.saturating_sub(self.publications.bytes)
        {
            return Err("signer publication queue is full".to_owned());
        }
        let verified = self
            .verifier
            .verify(&envelope, &local_peer)
            .map_err(|error| error.to_string())?;
        let admission = self.ingress.journal.classify(&verified);
        if matches!(
            admission,
            SignerAdmission::Duplicate | SignerAdmission::Stale
        ) {
            return Ok(admission);
        }
        let retained_direct_lane = envelope.body.as_ref().is_some_and(|body| {
            matches!(
                SignerLane::try_from(body.lane),
                Ok(SignerLane::BlockProposal
                    | SignerLane::BlockPushed
                    | SignerLane::ProposalUnavailable)
            )
        });
        let direct_only = envelope.body.as_ref().is_some_and(|body| {
            SignerLane::try_from(body.lane) == Ok(SignerLane::ProposalUnavailable)
        });
        let mailbox_bytes = envelope.encoded_len().saturating_mul(2).saturating_add(128);
        if retained_direct_lane && mailbox_bytes > MINER_DIRECT_MAILBOX_BYTES {
            return Err("direct signer mailbox item exceeds its byte budget".to_owned());
        }
        let token = self.reserve_token()?;
        let committed = self.ingress.journal.admit(&verified);
        debug_assert_eq!(committed, admission);
        self.dispatch_direct(&envelope);
        if retained_direct_lane {
            self.retain_direct(envelope.clone())?;
        }
        // The versioned liveness outcome is capability-negotiated point to
        // point. Keeping it off the shared topic ensures old peers observe
        // ordinary abstention instead of an unknown lane.
        if direct_only {
            return Ok(admission);
        }
        self.publications.queue.push_back(QueuedPublication {
            token,
            envelope,
            bytes,
        });
        self.publications.bytes += bytes;
        Ok(admission)
    }

    pub fn complete_publication(
        &mut self,
        token: u64,
        outcome: PublicationOutcome,
    ) -> Result<(), String> {
        if self.publications.inflight != Some(token)
            || self.publications.queue.front().map(|item| item.token) != Some(token)
        {
            return Err(format!("unknown signer publication token {token}"));
        }
        if !matches!(outcome, PublicationOutcome::NoPeers) {
            let item = self
                .publications
                .queue
                .pop_front()
                .ok_or_else(|| "signer publication queue became empty".to_owned())?;
            self.publications.bytes = self.publications.bytes.saturating_sub(item.bytes);
        }
        self.publications.inflight = None;
        self.push_event(SignerBehaviourEvent::PublicationCompleted { outcome });
        Ok(())
    }

    pub fn publication_queue_len(&self) -> usize {
        self.publications.queue.len()
    }

    pub fn direct_mailbox_len(&self) -> usize {
        self.direct.retained.len()
    }

    pub fn deferred_miner_authorization_len(&self) -> usize {
        self.ingress.deferred_miners.len()
    }

    pub fn deferred_miner_authorization_snapshot(&self) -> DeferredMinerAuthorizationSnapshot {
        DeferredMinerAuthorizationSnapshot {
            pending: self.ingress.deferred_miners.len()
                + self
                    .ingress
                    .pending_deliveries
                    .values()
                    .filter(|delivery| delivery.staged.was_deferred)
                    .count(),
            ..self.ingress.deferred_miner_lifecycle
        }
    }

    pub fn replay_needed(&self, peer: PeerId, reward_cycle: u64) -> bool {
        if self
            .replays
            .attempts
            .get(&reward_cycle)
            .is_some_and(|attempt| attempt.requested_at.elapsed() < SIGNER_REPLAY_REFRESH)
        {
            return false;
        }
        !self
            .replays
            .failed_providers
            .get(&reward_cycle)
            .is_some_and(|(failed, failed_at)| {
                *failed == peer && failed_at.elapsed() < SIGNER_REPLAY_PROVIDER_BACKOFF
            })
    }

    pub fn mark_replay_requested(&mut self, peer: PeerId, reward_cycle: u64) {
        self.replays.attempts.insert(
            reward_cycle,
            SignerReplayAttempt {
                provider: peer,
                requested_at: Instant::now(),
            },
        );
        self.replays.failed_providers.remove(&reward_cycle);
    }

    pub fn retry_replay(&mut self, peer: PeerId, reward_cycle: u64) {
        let is_current_provider = self
            .replays
            .attempts
            .get(&reward_cycle)
            .is_some_and(|attempt| attempt.provider == peer);
        if is_current_provider {
            self.replays.attempts.remove(&reward_cycle);
            self.replays
                .failed_providers
                .insert(reward_cycle, (peer, Instant::now()));
        }
    }

    /// Release a completed but truncated page for the next bounded cursor
    /// request without treating its provider as faulty.
    pub fn continue_replay(&mut self, peer: PeerId, reward_cycle: u64) {
        if self
            .replays
            .attempts
            .get(&reward_cycle)
            .is_some_and(|attempt| attempt.provider == peer)
        {
            self.replays.attempts.remove(&reward_cycle);
        }
    }

    pub fn send_direct(
        &mut self,
        peer: &PeerId,
        envelope: &SignerEnvelope,
    ) -> Result<(OutboundRequestId, ContentId), String> {
        let required_capabilities = envelope
            .body
            .as_ref()
            .and_then(|body| SignerLane::try_from(body.lane).ok())
            .filter(|lane| *lane == SignerLane::ProposalUnavailable)
            .map_or(CAP_SIGNER_SEMANTICS, |_| {
                CAP_SIGNER_SEMANTICS | CAP_PROPOSAL_UNAVAILABLE
            });
        if !self
            .peers
            .capabilities
            .get(peer)
            .is_some_and(|caps| supports(*caps, required_capabilities))
        {
            return Err("direct signer target is not Hello-authenticated and capable".to_owned());
        }
        let envelope_id = signer_envelope_id(envelope).map_err(|error| error.to_string())?;
        let request = NetworkEnvelope::new(
            self.verifier.scope().chain_id(),
            EnvelopeKind::Signer,
            0,
            envelope_id,
            envelope.encode_to_vec(),
        );
        let request_id = self.protocol.send_request(peer, request);
        self.direct.pending.insert(request_id, (*peer, envelope_id));
        Ok((request_id, envelope_id))
    }

    pub fn admit_action(&mut self, token: u64) -> Result<(), String> {
        let action = self
            .ingress
            .raw_actions
            .remove(&token)
            .ok_or_else(|| format!("unknown direct signer admission token {token}"))?;
        if !self.peers.capabilities.contains_key(&action.peer) {
            return Err("direct signer peer lacks Hello signer capability".to_owned());
        }
        if action.request.chain_id() != self.verifier.scope().chain_id()
            || action.request.kind() != EnvelopeKind::Signer
        {
            return Err("direct signer request has the wrong chain or envelope kind".to_owned());
        }
        let envelope = SignerEnvelope::decode(action.request.payload())
            .map_err(|error| format!("invalid direct signer protobuf: {error}"))?;
        let envelope_id = signer_envelope_id(&envelope).map_err(|error| error.to_string())?;
        if action.request.content_id() != envelope_id {
            return Err("direct signer request content ID mismatch".to_owned());
        }
        self.stage_verified(
            token,
            action.peer,
            action.peer,
            envelope,
            SignerIngress::Direct,
            PendingOrigin::Direct(action.channel),
        )?;
        Ok(())
    }

    pub fn reject_action(&mut self, token: u64) -> bool {
        self.ingress.raw_actions.remove(&token).is_some()
    }

    pub fn stage_gossip(
        &mut self,
        propagation_source: PeerId,
        source: PeerId,
        envelope: SignerEnvelope,
    ) -> Result<Option<StagedSignerEnvelope>, String> {
        if !self.peers.capabilities.contains_key(&propagation_source) {
            return Err("signer gossip propagator lacks Hello signer capability".to_owned());
        }
        let token = self.reserve_token()?;
        self.stage_verified(
            token,
            source,
            propagation_source,
            envelope,
            SignerIngress::Gossip,
            PendingOrigin::Gossip,
        )?;
        Ok(self
            .ingress
            .pending_deliveries
            .get(&token)
            .map(|pending| pending.staged.clone()))
    }

    pub fn stage_replay(
        &mut self,
        replay_server: PeerId,
        expected_cycle: u64,
        envelope: SignerEnvelope,
    ) -> Result<Option<StagedSignerEnvelope>, String> {
        if !self.peers.rendezvous.contains(&replay_server)
            && !self
                .ingress
                .authorizations
                .is_peer_bound(expected_cycle, &replay_server)
        {
            return Err("signer replay server is not authorized for this cycle".to_owned());
        }
        let verified = self
            .verifier
            .verify_authorship(&envelope)
            .map_err(|error| error.to_string())?;
        if verified.body.reward_cycle != expected_cycle {
            return Err("replayed signer envelope has the wrong reward cycle".to_owned());
        }
        let lane = SignerLane::try_from(verified.body.lane)
            .map_err(|_| "unknown signer lane".to_owned())?;
        if !matches!(
            lane,
            SignerLane::BlockProposal
                | SignerLane::BlockResponse
                | SignerLane::ProposalUnavailable
                | SignerLane::BlockPreCommit
                | SignerLane::StateMachineUpdate
        ) {
            return Err("signer replay contains a non-replayable lane".to_owned());
        }
        let author_key: [u8; 33] = verified
            .body
            .signer_public_key
            .as_slice()
            .try_into()
            .map_err(|_| "invalid signer/miner public key length".to_owned())?;
        let author = PeerId::from_bytes(&verified.body.transport_peer_id)
            .map_err(|_| "replayed signer envelope has an invalid author PeerId".to_owned())?;
        let revoked_peer = if lane == SignerLane::BlockProposal {
            match self.ingress.authorizations.bind_miner(
                expected_cycle,
                verified.body.burn_view_consensus_hash.clone(),
                author_key,
                author,
            ) {
                Ok(SignerBindingUpdate::Rekeyed { revoked_peer }) => Some(revoked_peer),
                Ok(SignerBindingUpdate::Bound | SignerBindingUpdate::Unchanged) => None,
                Err(_) => {
                    return Err(
                        "replayed envelope author is not authorized by canonical chain state"
                            .to_owned(),
                    )
                }
            }
        } else {
            if !self
                .ingress
                .authorizations
                .is_key_authorized(expected_cycle, &author_key)
            {
                return Err(
                    "replayed envelope author is not authorized by canonical chain state"
                        .to_owned(),
                );
            }
            None
        };
        let admission = self.ingress.journal.classify(&verified);
        if matches!(
            admission,
            SignerAdmission::Duplicate | SignerAdmission::Stale
        ) {
            self.push_event(SignerBehaviourEvent::Redundant {
                source: author,
                envelope_id: verified.envelope_id,
                lane,
                sequence: verified.body.sequence,
                admission,
                ingress: SignerIngress::Replay,
            });
            return Ok(None);
        }
        let token = self.reserve_token()?;
        let staged = StagedSignerEnvelope {
            token,
            provider: replay_server,
            source: author,
            envelope: verified,
            admission,
            revoked_peer,
            ingress: SignerIngress::Replay,
            was_deferred: false,
        };
        self.ingress.pending_deliveries.insert(
            token,
            PendingDelivery {
                staged: staged.clone(),
                origin: PendingOrigin::Gossip,
                deferred_created_at: None,
                deferred_release_failures: 0,
            },
        );
        Ok(Some(staged))
    }

    pub fn complete_delivery(
        &mut self,
        token: u64,
        delivered: bool,
    ) -> Result<SignerAdmission, String> {
        let pending = self
            .ingress
            .pending_deliveries
            .remove(&token)
            .ok_or_else(|| format!("unknown signer delivery token {token}"))?;
        if !delivered {
            let admission = pending.staged.admission;
            if let Some(created_at) = pending.deferred_created_at {
                let release_failures = pending.deferred_release_failures.saturating_add(1);
                let multiplier = 1_u32 << u32::from(release_failures.saturating_sub(1).min(4));
                let delay = DEFERRED_OBSERVATION_RETRY_INITIAL
                    .saturating_mul(multiplier)
                    .min(DEFERRED_OBSERVATION_RETRY_MAX);
                self.ingress.deferred_miners.insert(
                    token,
                    DeferredMinerDelivery {
                        source: pending.staged.source,
                        provider: pending.staged.provider,
                        envelope: pending.staged.envelope,
                        ingress: pending.staged.ingress,
                        origin: pending.origin,
                        created_at,
                        observation_delivered: true,
                        observation_inflight: false,
                        observation_failures: 0,
                        next_observation_at: Instant::now(),
                        release_failures,
                        next_release_at: Instant::now() + delay,
                    },
                );
            }
            return Ok(admission);
        }
        let admission = self.ingress.journal.admit(&pending.staged.envelope);
        if admission != pending.staged.admission {
            return Err("signer journal classification changed before delivery commit".to_owned());
        }
        if pending.staged.was_deferred {
            self.resolve_deferred_miner(DeferredMinerResolution::Released);
        }
        if let PendingOrigin::Direct(channel) = pending.origin {
            let response = NetworkEnvelope::new(
                self.verifier.scope().chain_id(),
                EnvelopeKind::Signer,
                0,
                pending.staged.envelope.envelope_id,
                Vec::new(),
            );
            // The application delivery and journal admission are already
            // committed. A deferred request-response channel can legitimately
            // expire while canonical evidence is pending, so its empty ACK is
            // best-effort and must not relabel successful delivery as failure.
            let _ = self.protocol.send_response(channel, response);
        }
        Ok(admission)
    }

    /// Complete the availability-only handoff for a canonically pending miner.
    /// Failed bounded-queue delivery is retried by `tick`; successful delivery
    /// may immediately release work if canonical authorization arrived while
    /// the observation was backpressured.
    pub fn complete_deferred_observation(&mut self, token: u64, delivered: bool) -> bool {
        self.complete_deferred_observation_at(token, delivered, Instant::now())
    }

    fn complete_deferred_observation_at(
        &mut self,
        token: u64,
        delivered: bool,
        now: Instant,
    ) -> bool {
        let Some(pending) = self.ingress.deferred_miners.get_mut(&token) else {
            return false;
        };
        pending.observation_inflight = false;
        let newly_delivered = delivered && !pending.observation_delivered;
        pending.observation_delivered |= delivered;
        if !delivered {
            pending.observation_failures = pending.observation_failures.saturating_add(1);
            let multiplier =
                1_u32 << u32::from(pending.observation_failures.saturating_sub(1).min(4));
            let delay = DEFERRED_OBSERVATION_RETRY_INITIAL
                .saturating_mul(multiplier)
                .min(DEFERRED_OBSERVATION_RETRY_MAX);
            pending.next_observation_at = now + delay;
        }
        if newly_delivered {
            self.ingress.deferred_miner_lifecycle.observation_delivered = self
                .ingress
                .deferred_miner_lifecycle
                .observation_delivered
                .saturating_add(1);
        }
        if delivered {
            self.release_deferred_miners(Instant::now());
        }
        true
    }

    fn stage_verified(
        &mut self,
        token: u64,
        source: PeerId,
        provider: PeerId,
        envelope: SignerEnvelope,
        ingress: SignerIngress,
        origin: PendingOrigin,
    ) -> Result<(), String> {
        let verified = self
            .verifier
            .verify(&envelope, &source)
            .map_err(|error| error.to_string())?;
        let lane = SignerLane::try_from(verified.body.lane)
            .map_err(|_| "unknown signer lane".to_owned())?;
        let revoked_peer = if lane == SignerLane::Control {
            None
        } else if matches!(lane, SignerLane::BlockProposal | SignerLane::BlockPushed) {
            let miner_key: [u8; 33] = verified
                .body
                .signer_public_key
                .as_slice()
                .try_into()
                .map_err(|_| "invalid miner public key length".to_owned())?;
            if lane == SignerLane::BlockProposal
                && self.ingress.authorizations.miner_authorization_status(
                    verified.body.reward_cycle,
                    &verified.body.burn_view_consensus_hash,
                    &miner_key,
                ) == MinerAuthorizationStatus::CanonicalViewPending
            {
                if self
                    .ingress
                    .deferred_miners
                    .values()
                    .any(|pending| pending.envelope.envelope_id == verified.envelope_id)
                {
                    return Ok(());
                }
                if self.ingress.deferred_miners.len() >= MAX_PENDING_SIGNER_ACTIONS {
                    return Err("deferred miner authorization capacity reached".to_owned());
                }
                self.push_event(SignerBehaviourEvent::MinerAuthorizationDeferred {
                    token,
                    source,
                    provider,
                    envelope: Box::new(verified.clone()),
                    ingress,
                });
                self.ingress.deferred_miners.insert(
                    token,
                    DeferredMinerDelivery {
                        source,
                        provider,
                        envelope: verified,
                        ingress,
                        origin,
                        created_at: Instant::now(),
                        observation_delivered: false,
                        observation_inflight: true,
                        observation_failures: 0,
                        next_observation_at: Instant::now(),
                        release_failures: 0,
                        next_release_at: Instant::now(),
                    },
                );
                self.ingress.deferred_miner_lifecycle.admitted = self
                    .ingress
                    .deferred_miner_lifecycle
                    .admitted
                    .saturating_add(1);
                return Ok(());
            }
            match self
                .ingress
                .authorizations
                .bind_miner(
                    verified.body.reward_cycle,
                    verified.body.burn_view_consensus_hash.clone(),
                    miner_key,
                    source,
                )
                .map_err(str::to_owned)?
            {
                SignerBindingUpdate::Rekeyed { revoked_peer } => Some(revoked_peer),
                SignerBindingUpdate::Bound | SignerBindingUpdate::Unchanged => None,
            }
        } else {
            let signer_key: [u8; 33] = verified
                .body
                .signer_public_key
                .as_slice()
                .try_into()
                .map_err(|_| "invalid signer public key length".to_owned())?;
            match self
                .ingress
                .authorizations
                .bind(verified.body.reward_cycle, signer_key, source)
                .map_err(str::to_owned)?
            {
                SignerBindingUpdate::Rekeyed { revoked_peer } => Some(revoked_peer),
                SignerBindingUpdate::Bound | SignerBindingUpdate::Unchanged => None,
            }
        };
        let admission = self.ingress.journal.classify(&verified);
        if matches!(
            admission,
            SignerAdmission::Duplicate | SignerAdmission::Stale
        ) {
            if let PendingOrigin::Direct(channel) = origin {
                let response = NetworkEnvelope::new(
                    self.verifier.scope().chain_id(),
                    EnvelopeKind::Signer,
                    0,
                    verified.envelope_id,
                    Vec::new(),
                );
                let _ = self.protocol.send_response(channel, response);
            }
            self.push_event(SignerBehaviourEvent::Redundant {
                source,
                envelope_id: verified.envelope_id,
                lane,
                sequence: verified.body.sequence,
                admission,
                ingress,
            });
            return Ok(());
        }
        if self.ingress.pending_deliveries.len() >= MAX_PENDING_SIGNER_ACTIONS {
            return Err("signer delivery capacity reached".to_owned());
        }
        let staged = StagedSignerEnvelope {
            token,
            provider,
            source,
            envelope: verified,
            admission,
            revoked_peer,
            ingress,
            was_deferred: false,
        };
        self.ingress.pending_deliveries.insert(
            token,
            PendingDelivery {
                staged: staged.clone(),
                origin,
                deferred_created_at: None,
                deferred_release_failures: 0,
            },
        );
        if ingress == SignerIngress::Direct {
            self.push_event(SignerBehaviourEvent::DeliveryRequired(Box::new(staged)));
        }
        Ok(())
    }

    fn reserve_token(&mut self) -> Result<u64, String> {
        if self.ingress.raw_actions.len()
            + self.ingress.pending_deliveries.len()
            + self.ingress.deferred_miners.len()
            >= MAX_PENDING_SIGNER_ACTIONS
        {
            return Err("signer admission capacity reached".to_owned());
        }
        for _ in 0..=MAX_PENDING_SIGNER_ACTIONS {
            let token = self.ingress.next_token;
            self.ingress.next_token = self.ingress.next_token.wrapping_add(1);
            if !self.ingress.raw_actions.contains_key(&token)
                && !self.ingress.pending_deliveries.contains_key(&token)
                && !self.ingress.deferred_miners.contains_key(&token)
                && !self
                    .publications
                    .queue
                    .iter()
                    .any(|item| item.token == token)
            {
                return Ok(token);
            }
        }
        Err("signer admission token space exhausted".to_owned())
    }

    fn push_event(&mut self, event: SignerBehaviourEvent) {
        if self.events.len() == MAX_SIGNER_BEHAVIOUR_EVENTS {
            let critical = matches!(
                &event,
                SignerBehaviourEvent::AdmissionRequired { .. }
                    | SignerBehaviourEvent::DeliveryRequired(_)
                    | SignerBehaviourEvent::MinerAuthorizationDeferred { .. }
                    | SignerBehaviourEvent::PublishGossip { .. }
            );
            if !critical {
                return;
            }
            let removable = self.events.iter().position(|queued| {
                !matches!(
                    queued,
                    SignerBehaviourEvent::AdmissionRequired { .. }
                        | SignerBehaviourEvent::DeliveryRequired(_)
                        | SignerBehaviourEvent::MinerAuthorizationDeferred { .. }
                        | SignerBehaviourEvent::PublishGossip { .. }
                )
            });
            if let Some(index) = removable {
                self.events.remove(index);
            } else {
                // Critical event cardinality is bounded by the 256 action
                // limit plus one publication, below this queue's capacity.
                debug_assert!(false, "critical signer event capacity invariant");
                return;
            }
        }
        self.events.push_back(event);
    }

    fn dispatch_direct(&mut self, envelope: &SignerEnvelope) {
        let targets = self.direct_targets(envelope, &self.peers.connected);
        for peer in targets {
            if let Ok((_, envelope_id)) = self.send_direct(&peer, envelope) {
                self.push_event(SignerBehaviourEvent::DirectSent { peer, envelope_id });
            }
        }
    }

    fn retain_direct(&mut self, envelope: SignerEnvelope) -> Result<(), String> {
        let envelope_id = signer_envelope_id(&envelope).map_err(|error| error.to_string())?;
        let bytes = envelope.encoded_len().saturating_mul(2).saturating_add(128);
        if bytes > MINER_DIRECT_MAILBOX_BYTES {
            return Err("direct signer mailbox item exceeds its byte budget".to_owned());
        }
        let sent_to = self
            .direct
            .pending
            .values()
            .filter_map(|(peer, pending_id)| (*pending_id == envelope_id).then_some(*peer))
            .collect();
        while self.direct.retained.len() >= MINER_DIRECT_MAILBOX_CAPACITY
            || bytes > MINER_DIRECT_MAILBOX_BYTES.saturating_sub(self.direct.bytes)
        {
            let Some(evicted) = self.direct.retained.pop_front() else {
                break;
            };
            self.direct.bytes = self.direct.bytes.saturating_sub(evicted.bytes);
            self.push_event(SignerBehaviourEvent::MailboxExpired {
                undelivered: usize::from(evicted.sent_to.is_empty()),
            });
        }
        self.direct.retained.push_back(RetainedDirectDelivery {
            envelope,
            envelope_id,
            sent_to,
            retries: HashMap::new(),
            created_at: Instant::now(),
            bytes,
        });
        self.direct.bytes += bytes;
        Ok(())
    }

    fn tick(&mut self, now: Instant) {
        let retry_deferred_observations = self
            .ingress
            .deferred_miners
            .iter_mut()
            .filter_map(|(token, pending)| {
                if pending.observation_delivered
                    || pending.observation_inflight
                    || now < pending.next_observation_at
                {
                    return None;
                }
                pending.observation_inflight = true;
                Some((
                    *token,
                    pending.source,
                    pending.provider,
                    pending.envelope.clone(),
                    pending.ingress,
                ))
            })
            .collect::<Vec<_>>();
        for (token, source, provider, envelope, ingress) in retry_deferred_observations {
            self.ingress.deferred_miner_lifecycle.observation_retries = self
                .ingress
                .deferred_miner_lifecycle
                .observation_retries
                .saturating_add(1);
            self.push_event(SignerBehaviourEvent::MinerAuthorizationDeferred {
                token,
                source,
                provider,
                envelope: Box::new(envelope),
                ingress,
            });
        }
        let expired_deferred = self
            .ingress
            .deferred_miners
            .iter()
            .filter_map(|(token, pending)| {
                (now.saturating_duration_since(pending.created_at)
                    >= DEFERRED_MINER_AUTHORIZATION_TTL)
                    .then_some(*token)
            })
            .collect::<Vec<_>>();
        for token in expired_deferred {
            if let Some(expired) = self.ingress.deferred_miners.remove(&token) {
                self.resolve_deferred_miner(DeferredMinerResolution::Expired);
                self.push_event(SignerBehaviourEvent::MinerAuthorizationExpired {
                    source: expired.source,
                    ingress: expired.ingress,
                });
            }
        }
        // A canonically authorized deferred envelope remains signer-owned
        // until the bounded application queue accepts it. Failed handoffs are
        // retried here using the same bounded backoff as availability notices.
        self.release_deferred_miners(now);
        let mut expired_undelivered = 0;
        while self.direct.retained.front().is_some_and(|delivery| {
            now.saturating_duration_since(delivery.created_at) >= MINER_DIRECT_MAILBOX_TTL
        }) {
            let Some(expired) = self.direct.retained.pop_front() else {
                break;
            };
            self.direct.bytes = self.direct.bytes.saturating_sub(expired.bytes);
            expired_undelivered += usize::from(expired.sent_to.is_empty());
        }
        if expired_undelivered > 0 {
            self.push_event(SignerBehaviourEvent::MailboxExpired {
                undelivered: expired_undelivered,
            });
        }

        let mut sends = Vec::new();
        for (index, delivery) in self.direct.retained.iter().enumerate() {
            for peer in self.direct_targets(&delivery.envelope, &self.peers.connected) {
                let retry_ready = delivery
                    .retries
                    .get(&peer)
                    .is_none_or(|retry| now >= retry.retry_at);
                if !delivery.sent_to.contains(&peer) && retry_ready {
                    sends.push((index, peer));
                }
            }
        }
        for (index, peer) in sends {
            let Some((envelope, envelope_id)) = self
                .direct
                .retained
                .get(index)
                .map(|delivery| (delivery.envelope.clone(), delivery.envelope_id))
            else {
                continue;
            };
            if self.send_direct(&peer, &envelope).is_ok() {
                if let Some(delivery) = self.direct.retained.get_mut(index) {
                    delivery.sent_to.insert(peer);
                }
                self.push_event(SignerBehaviourEvent::DirectSent { peer, envelope_id });
            }
        }

        let publication_ready = self.publications.inflight.is_none()
            && self.publications.queue.front().is_some()
            && self
                .publications
                .last_attempt
                .is_none_or(|last| now.saturating_duration_since(last) >= PUBLICATION_RETRY);
        if publication_ready {
            let Some((token, envelope)) = self
                .publications
                .queue
                .front()
                .map(|publication| (publication.token, publication.envelope.clone()))
            else {
                return;
            };
            self.publications.inflight = Some(token);
            self.publications.last_attempt = Some(now);
            self.push_event(SignerBehaviourEvent::PublishGossip { token, envelope });
        }
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
                        request, channel, ..
                    },
            } => match self.reserve_token() {
                Ok(token) => {
                    let encoded_bytes = request.encoded_len();
                    self.ingress.raw_actions.insert(
                        token,
                        RawDirectAction {
                            peer,
                            request,
                            channel,
                        },
                    );
                    self.push_event(SignerBehaviourEvent::AdmissionRequired {
                        token,
                        peer,
                        connection_id,
                        encoded_bytes,
                        validation_units: 8,
                    });
                }
                Err(error) => self.push_event(SignerBehaviourEvent::Rejected {
                    peer,
                    ingress: SignerIngress::Direct,
                    error,
                }),
            },
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                let Some((expected_peer, envelope_id)) = self.direct.pending.remove(&request_id)
                else {
                    self.push_event(SignerBehaviourEvent::DirectFailed {
                        peer,
                        envelope_id: None,
                        error: "unknown direct signer response".to_owned(),
                    });
                    return;
                };
                if peer == expected_peer
                    && response.chain_id() == self.verifier.scope().chain_id()
                    && response.kind() == EnvelopeKind::Signer
                    && response.content_id() == envelope_id
                    && response.payload().is_empty()
                {
                    for delivery in &mut self.direct.retained {
                        if delivery.envelope_id == envelope_id {
                            delivery.retries.remove(&peer);
                        }
                    }
                    self.push_event(SignerBehaviourEvent::DirectAcknowledged { peer, envelope_id });
                } else {
                    self.mark_direct_failure(peer, envelope_id, Instant::now());
                    self.push_event(SignerBehaviourEvent::DirectFailed {
                        peer,
                        envelope_id: Some(envelope_id),
                        error: "invalid direct signer acknowledgement".to_owned(),
                    });
                }
            }
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                let envelope_id = self
                    .direct
                    .pending
                    .remove(&request_id)
                    .map(|(_, envelope_id)| envelope_id);
                if let Some(envelope_id) = envelope_id {
                    self.mark_direct_failure(peer, envelope_id, Instant::now());
                }
                self.push_event(SignerBehaviourEvent::DirectFailed {
                    peer,
                    envelope_id,
                    error: error.to_string(),
                });
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                self.push_event(SignerBehaviourEvent::Rejected {
                    peer,
                    ingress: SignerIngress::Direct,
                    error: error.to_string(),
                });
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    fn mark_direct_failure(&mut self, peer: PeerId, envelope_id: ContentId, now: Instant) {
        for delivery in &mut self.direct.retained {
            if delivery.envelope_id != envelope_id {
                continue;
            }
            delivery.sent_to.remove(&peer);
            let failures = delivery
                .retries
                .get(&peer)
                .map_or(1, |retry| retry.failures.saturating_add(1));
            let multiplier = 1_u32 << u32::from(failures.saturating_sub(1).min(4));
            let delay = DIRECT_RETRY_INITIAL
                .saturating_mul(multiplier)
                .min(DIRECT_RETRY_MAX);
            delivery.retries.insert(
                peer,
                DirectRetryState {
                    failures,
                    retry_at: now + delay,
                },
            );
        }
    }
}

impl SignerBehaviour {
    fn on_forwarded_swarm_event(&mut self, event: &FromSwarm<'_>) {
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                self.peers.connected.insert(event.peer_id);
            }
            FromSwarm::ConnectionClosed(event) if event.remaining_established == 0 => {
                self.peers.connected.remove(&event.peer_id);
                self.disconnect_peer(&event.peer_id);
            }
            _ => {}
        }
    }

    fn poll_scheduled(&mut self, cx: &mut Context<'_>) {
        if std::pin::Pin::new(&mut self.timer).poll(cx).is_ready() {
            self.tick(Instant::now());
            self.timer.reset(SIGNER_TICK);
        }
    }
}

impl_bounded_request_response_behaviour!(SignerBehaviour, SignerBehaviourEvent);

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::request_response::ProtocolSupport;
    use libp2p::StreamProtocol;
    use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
    use stacks_common::types::PrivateKey;
    use stacks_common::util::hash::Hash160;
    use stacks_network_types::signer_envelope_digest;
    use stacks_network_types::wire::v1::{
        ProposalManifest, ProposalUnavailable, ProposalUnavailableReason, Role, SignerEnvelopeBody,
    };
    use stacks_network_types::{
        ContentId, PROPOSAL_MANIFEST_VERSION, PROPOSAL_UNAVAILABLE_VERSION, SIGNER_ENVELOPE_VERSION,
    };

    const CHAIN_ID: u32 = 0x8000_0000;
    const NETWORK_ID: u32 = 0x8000_0000;

    fn behaviour() -> SignerBehaviour {
        let protocol = request_response::Behaviour::with_codec(
            BoundedEnvelopeCodec::new(stacks_network_types::EnvelopeLimits::BLOCK),
            [(
                StreamProtocol::new("/stacks/signer-behaviour-test/1"),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );
        SignerBehaviour::new(protocol, NetworkScope::new(CHAIN_ID, NETWORK_ID))
    }

    fn envelope(
        key: &StacksPrivateKey,
        peer: PeerId,
        lane: SignerLane,
        sequence: u64,
    ) -> SignerEnvelope {
        let proposal_manifest = (lane == SignerLane::BlockProposal).then(|| ProposalManifest {
            version: PROPOSAL_MANIFEST_VERSION,
            content_id: ContentId::from_bytes([7; 32]).as_bytes().to_vec(),
            encoded_len: 64,
            signer_signature_hash: vec![8; 32],
            burn_height: 100,
            reward_cycle: 4,
        });
        let body = SignerEnvelopeBody {
            version: SIGNER_ENVELOPE_VERSION,
            chain_id: CHAIN_ID,
            network_id: NETWORK_ID,
            reward_cycle: 4,
            lane: lane as i32,
            sequence,
            previous_envelope_id: Vec::new(),
            signer_public_key: StacksPublicKey::from_private(key).to_bytes_compressed(),
            transport_peer_id: peer.to_bytes(),
            payload: if proposal_manifest.is_some() {
                Vec::new()
            } else {
                b"semantic signer payload".to_vec()
            },
            burn_view_consensus_hash: vec![0; 20],
            proposal_manifest,
        };
        let signature = key.sign(&signer_envelope_digest(&body)).unwrap();
        SignerEnvelope {
            body: Some(body),
            signature: signature.as_bytes().to_vec(),
        }
    }

    fn signer_authorization(key: &StacksPrivateKey) -> crate::RoleAuthorization {
        crate::RoleAuthorization {
            role: Role::Signer,
            reward_cycle: 4,
            role_id: None,
            key: crate::AuthorizedRoleKey::PublicKey(
                StacksPublicKey::from_private(key)
                    .to_bytes_compressed()
                    .try_into()
                    .expect("compressed secp256k1 key is 33 bytes"),
            ),
        }
    }

    fn miner_authorization(key: &StacksPrivateKey) -> crate::RoleAuthorization {
        let public_key = StacksPublicKey::from_private(key).to_bytes_compressed();
        crate::RoleAuthorization {
            role: Role::Miner,
            reward_cycle: 4,
            role_id: Some(vec![0; 20]),
            key: crate::AuthorizedRoleKey::PublicKeyHash160(Hash160::from_data(&public_key).0),
        }
    }

    #[test]
    fn canonical_miner_envelope_establishes_transport_binding_atomically() {
        let miner_key = StacksPrivateKey::from_seed(&[70; 32]);
        let miner_peer = PeerId::random();
        let mut behaviour = behaviour();
        // A configured rendezvous address supplies reachability only. The
        // signed envelope must still match the canonical sortition snapshot.
        behaviour.set_rendezvous_peers([miner_peer]);
        behaviour.authenticate_peer(miner_peer, CAP_SIGNER_SEMANTICS);
        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 4, None, [miner_authorization(&miner_key)]).unwrap(),
            )
            .unwrap();

        let proposal = envelope(&miner_key, miner_peer, SignerLane::BlockProposal, 1);
        let staged = behaviour
            .stage_gossip(miner_peer, miner_peer, proposal.clone())
            .unwrap()
            .expect("canonical first proposal must be admitted");
        assert!(behaviour
            .authorization_state()
            .miner_peers_for_cycle(4)
            .contains(&miner_peer));
        behaviour.complete_delivery(staged.token, true).unwrap();
        assert!(behaviour
            .stage_gossip(miner_peer, miner_peer, proposal)
            .unwrap()
            .is_none());

        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(
                    2,
                    4,
                    None,
                    [miner_authorization(&StacksPrivateKey::from_seed(&[71; 32]))],
                )
                .unwrap(),
            )
            .unwrap();
        let proposal = envelope(&miner_key, miner_peer, SignerLane::BlockProposal, 2);
        assert!(behaviour
            .stage_gossip(miner_peer, miner_peer, proposal)
            .unwrap_err()
            .contains("not authorized by the applied snapshot"));
    }

    #[test]
    fn unknown_sortition_is_deferred_without_binding_or_journal_admission() {
        let miner_key = StacksPrivateKey::from_seed(&[72; 32]);
        let miner_peer = PeerId::random();
        let signer_key = StacksPrivateKey::from_seed(&[73; 32]);
        let signer_peer = PeerId::random();
        let mut behaviour = behaviour();
        behaviour.authenticate_peer(miner_peer, CAP_SIGNER_SEMANTICS | CAP_PROPOSAL_UNAVAILABLE);
        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 4, None, Vec::new()).unwrap(),
            )
            .unwrap();

        let proposal = envelope(&miner_key, miner_peer, SignerLane::BlockProposal, 1);
        assert!(behaviour
            .stage_gossip(miner_peer, miner_peer, proposal.clone())
            .unwrap()
            .is_none());
        assert_eq!(behaviour.ingress.deferred_miners.len(), 1);
        assert_eq!(
            behaviour.deferred_miner_authorization_snapshot(),
            DeferredMinerAuthorizationSnapshot {
                admitted: 1,
                pending: 1,
                ..DeferredMinerAuthorizationSnapshot::default()
            }
        );
        assert_eq!(behaviour.ingress.pending_deliveries.len(), 0);
        assert!(!behaviour
            .authorization_state()
            .miner_peers_for_cycle(4)
            .contains(&miner_peer));
        assert!(behaviour.ingress.journal.is_empty());
        assert_eq!(
            behaviour
                .events
                .iter()
                .filter(|event| matches!(
                    event,
                    SignerBehaviourEvent::MinerAuthorizationDeferred { .. }
                ))
                .count(),
            1
        );
        assert!(!behaviour
            .events
            .iter()
            .any(|event| matches!(event, SignerBehaviourEvent::PublishGossip { .. })));
        let defer_token = behaviour
            .events
            .iter()
            .find_map(|event| match event {
                SignerBehaviourEvent::MinerAuthorizationDeferred { token, .. } => Some(*token),
                _ => None,
            })
            .unwrap();
        let first_failure_at = Instant::now();
        assert!(behaviour.complete_deferred_observation_at(defer_token, false, first_failure_at));
        behaviour
            .tick(first_failure_at + DEFERRED_OBSERVATION_RETRY_INITIAL - Duration::from_millis(1));
        assert_eq!(
            behaviour
                .deferred_miner_authorization_snapshot()
                .observation_retries,
            0,
            "the 100ms behaviour tick must not amplify a full downstream queue"
        );
        behaviour.tick(first_failure_at + DEFERRED_OBSERVATION_RETRY_INITIAL);
        assert_eq!(
            behaviour
                .deferred_miner_authorization_snapshot()
                .observation_retries,
            1
        );
        assert_eq!(
            behaviour
                .events
                .iter()
                .filter(|event| matches!(
                    event,
                    SignerBehaviourEvent::MinerAuthorizationDeferred { .. }
                ))
                .count(),
            2,
            "backpressured local abstention must remain a delivery obligation"
        );
        assert!(behaviour.complete_deferred_observation(defer_token, true));
        assert_eq!(
            behaviour
                .deferred_miner_authorization_snapshot()
                .observation_delivered,
            1
        );

        let mut unavailable =
            envelope(&signer_key, signer_peer, SignerLane::ProposalUnavailable, 1);
        let body = unavailable.body.as_mut().unwrap();
        body.payload = ProposalUnavailable {
            version: PROPOSAL_UNAVAILABLE_VERSION,
            signer_signature_hash: vec![8; 32],
            reward_cycle: 4,
            reason: ProposalUnavailableReason::ChainView as i32,
        }
        .encode_to_vec();
        unavailable.signature = signer_key
            .sign(&signer_envelope_digest(body))
            .unwrap()
            .as_bytes()
            .to_vec();
        assert_eq!(
            behaviour.direct_targets(&unavailable, &HashSet::from([miner_peer])),
            [],
            "a deferred source must not learn the signer-key-to-PeerId binding before canonical authorization"
        );
        assert!(!behaviour
            .authorization_state()
            .miner_peers_for_cycle(4)
            .contains(&miner_peer));

        // Repeated delivery of the same signed envelope is rate-limited while
        // canonical evidence is unavailable.
        assert!(behaviour
            .stage_gossip(miner_peer, miner_peer, proposal.clone())
            .unwrap()
            .is_none());
        assert_eq!(behaviour.ingress.deferred_miners.len(), 1);

        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(2, 4, None, [miner_authorization(&miner_key)]).unwrap(),
            )
            .unwrap();
        assert_eq!(behaviour.ingress.deferred_miners.len(), 0);
        let lifecycle = behaviour.deferred_miner_authorization_snapshot();
        assert_eq!(lifecycle.admitted, 1);
        assert_eq!(lifecycle.released, 0);
        assert_eq!(lifecycle.pending, 1);
        assert!(lifecycle.is_conserved());
        assert_eq!(behaviour.ingress.pending_deliveries.len(), 1);
        assert!(behaviour.ingress.journal.is_empty());
        assert!(behaviour
            .authorization_state()
            .miner_peers_for_cycle(4)
            .contains(&miner_peer));
        assert_eq!(
            behaviour.direct_targets(&unavailable, &HashSet::from([miner_peer])),
            [miner_peer],
            "canonical authorization permits the signer-attributable response"
        );
        let token = behaviour
            .events
            .iter()
            .find_map(|event| match event {
                SignerBehaviourEvent::DeliveryRequired(staged) => Some(staged.token),
                _ => None,
            })
            .expect("matching canonical snapshot must release deferred proposal");
        behaviour.complete_delivery(token, false).unwrap();
        let lifecycle = behaviour.deferred_miner_authorization_snapshot();
        assert_eq!(lifecycle.released, 0);
        assert_eq!(lifecycle.pending, 1);
        assert!(lifecycle.is_conserved());
        behaviour.tick(Instant::now() + DEFERRED_OBSERVATION_RETRY_MAX);
        assert_eq!(behaviour.ingress.pending_deliveries.len(), 1);
        behaviour.complete_delivery(token, true).unwrap();
        let lifecycle = behaviour.deferred_miner_authorization_snapshot();
        assert_eq!(lifecycle.released, 1);
        assert_eq!(lifecycle.pending, 0);
        assert!(lifecycle.is_conserved());
        assert_eq!(behaviour.ingress.journal.len(), 1);
        assert!(behaviour
            .stage_gossip(miner_peer, miner_peer, proposal)
            .unwrap()
            .is_none());
    }

    #[test]
    fn deferred_miner_negative_snapshot_resolution_is_conserved() {
        let deferred_key = StacksPrivateKey::from_seed(&[74; 32]);
        let authorized_key = StacksPrivateKey::from_seed(&[75; 32]);
        let miner_peer = PeerId::random();
        let mut behaviour = behaviour();
        behaviour.authenticate_peer(miner_peer, CAP_SIGNER_SEMANTICS | CAP_PROPOSAL_UNAVAILABLE);
        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 4, None, Vec::new()).unwrap(),
            )
            .unwrap();

        behaviour
            .stage_gossip(
                miner_peer,
                miner_peer,
                envelope(&deferred_key, miner_peer, SignerLane::BlockProposal, 1),
            )
            .unwrap();
        let token = behaviour
            .events
            .iter()
            .find_map(|event| match event {
                SignerBehaviourEvent::MinerAuthorizationDeferred { token, .. } => Some(*token),
                _ => None,
            })
            .unwrap();
        assert!(behaviour.complete_deferred_observation(token, true));
        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(2, 4, None, [miner_authorization(&authorized_key)])
                    .unwrap(),
            )
            .unwrap();

        let lifecycle = behaviour.deferred_miner_authorization_snapshot();
        assert_eq!(lifecycle.admitted, 1);
        assert_eq!(lifecycle.unauthorized, 1);
        assert_eq!(lifecycle.pending, 0);
        assert!(lifecycle.is_conserved());
    }

    #[test]
    fn deferred_miner_expiry_is_conserved() {
        let miner_key = StacksPrivateKey::from_seed(&[76; 32]);
        let miner_peer = PeerId::random();
        let mut behaviour = behaviour();
        behaviour.authenticate_peer(miner_peer, CAP_SIGNER_SEMANTICS | CAP_PROPOSAL_UNAVAILABLE);
        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 4, None, Vec::new()).unwrap(),
            )
            .unwrap();

        behaviour
            .stage_gossip(
                miner_peer,
                miner_peer,
                envelope(&miner_key, miner_peer, SignerLane::BlockProposal, 1),
            )
            .unwrap();
        let token = *behaviour
            .ingress
            .deferred_miners
            .keys()
            .next()
            .expect("proposal must be deferred");
        behaviour
            .ingress
            .deferred_miners
            .get_mut(&token)
            .expect("deferred proposal must remain present")
            .created_at = Instant::now() - DEFERRED_MINER_AUTHORIZATION_TTL;

        behaviour.tick(Instant::now());

        let lifecycle = behaviour.deferred_miner_authorization_snapshot();
        assert_eq!(lifecycle.admitted, 1);
        assert_eq!(lifecycle.expired, 1);
        assert_eq!(lifecycle.pending, 0);
        assert!(lifecycle.is_conserved());
    }

    #[test]
    fn deferred_miner_redundant_resolution_is_conserved() {
        let miner_key = StacksPrivateKey::from_seed(&[77; 32]);
        let miner_peer = PeerId::random();
        let mut behaviour = behaviour();
        behaviour.authenticate_peer(miner_peer, CAP_SIGNER_SEMANTICS | CAP_PROPOSAL_UNAVAILABLE);
        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 4, None, Vec::new()).unwrap(),
            )
            .unwrap();

        behaviour
            .stage_gossip(
                miner_peer,
                miner_peer,
                envelope(&miner_key, miner_peer, SignerLane::BlockProposal, 1),
            )
            .unwrap();
        let token = *behaviour
            .ingress
            .deferred_miners
            .keys()
            .next()
            .expect("proposal must be deferred");
        assert!(behaviour.complete_deferred_observation(token, true));
        let retained = behaviour
            .ingress
            .deferred_miners
            .get(&token)
            .expect("proposal must remain deferred")
            .envelope
            .clone();
        assert_eq!(
            behaviour.ingress.journal.admit(&retained),
            SignerAdmission::FirstSeen
        );

        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(2, 4, None, [miner_authorization(&miner_key)]).unwrap(),
            )
            .unwrap();

        let lifecycle = behaviour.deferred_miner_authorization_snapshot();
        assert_eq!(lifecycle.admitted, 1);
        assert_eq!(lifecycle.redundant, 1);
        assert_eq!(lifecycle.pending, 0);
        assert!(lifecycle.is_conserved());
        assert!(behaviour.ingress.pending_deliveries.is_empty());
    }

    #[test]
    fn deferred_miner_rekey_conflict_releases_and_revokes_old_peer() {
        let miner_key = StacksPrivateKey::from_seed(&[78; 32]);
        let miner_public_key = StacksPublicKey::from_private(&miner_key)
            .to_bytes_compressed()
            .try_into()
            .unwrap();
        let old_peer = PeerId::random();
        let new_peer = PeerId::random();
        let mut behaviour = behaviour();
        behaviour.authenticate_peer(new_peer, CAP_SIGNER_SEMANTICS | CAP_PROPOSAL_UNAVAILABLE);
        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 4, None, Vec::new()).unwrap(),
            )
            .unwrap();

        behaviour
            .stage_gossip(
                new_peer,
                new_peer,
                envelope(&miner_key, new_peer, SignerLane::BlockProposal, 1),
            )
            .unwrap();
        let token = *behaviour
            .ingress
            .deferred_miners
            .keys()
            .next()
            .expect("proposal must be deferred");
        assert!(behaviour.complete_deferred_observation(token, true));

        let prepared = behaviour
            .prepare_authorization_snapshot(
                &AuthorizationSnapshot::new(2, 4, None, [miner_authorization(&miner_key)]).unwrap(),
            )
            .unwrap();
        // Install the prepared state without triggering release so the test can
        // model a previously authenticated transport identity for this tuple.
        behaviour.ingress.authorizations = prepared.state;
        assert_eq!(
            behaviour
                .ingress
                .authorizations
                .bind_miner(4, vec![0; 20], miner_public_key, old_peer)
                .unwrap(),
            SignerBindingUpdate::Bound
        );

        behaviour.release_deferred_miners(Instant::now());

        let lifecycle = behaviour.deferred_miner_authorization_snapshot();
        assert_eq!(lifecycle.released, 0);
        assert_eq!(lifecycle.binding_failed, 0);
        assert_eq!(lifecycle.pending, 1);
        assert!(lifecycle.is_conserved());
        let staged = behaviour
            .ingress
            .pending_deliveries
            .get(&token)
            .expect("authorized proposal must be staged for delivery");
        assert_eq!(staged.staged.revoked_peer, Some(old_peer));
        assert!(behaviour.authorization_state().is_miner_bound(
            4,
            &[0; 20],
            &miner_public_key,
            &new_peer
        ));
        behaviour.complete_delivery(token, true).unwrap();
        let lifecycle = behaviour.deferred_miner_authorization_snapshot();
        assert_eq!(lifecycle.released, 1);
        assert_eq!(lifecycle.pending, 0);
        assert!(lifecycle.is_conserved());
    }

    #[test]
    fn deferred_miner_defensive_terminal_accounting_is_conserved() {
        let mut behaviour = behaviour();
        behaviour.ingress.deferred_miner_lifecycle.admitted = 2;

        behaviour.resolve_deferred_miner(DeferredMinerResolution::BindingFailed);
        behaviour.resolve_deferred_miner(DeferredMinerResolution::Malformed);

        let lifecycle = behaviour.deferred_miner_authorization_snapshot();
        assert_eq!(lifecycle.binding_failed, 1);
        assert_eq!(lifecycle.malformed, 1);
        assert!(lifecycle.is_conserved());
    }

    #[test]
    fn proposal_unavailable_is_negotiated_and_never_gossiped() {
        let signer_key = StacksPrivateKey::from_seed(&[69; 32]);
        let signer_peer = PeerId::random();
        let miner_key = StacksPrivateKey::from_seed(&[70; 32]);
        let miner_peer = PeerId::random();
        let miner_public_key = StacksPublicKey::from_private(&miner_key)
            .to_bytes_compressed()
            .try_into()
            .unwrap();
        let mut behaviour = behaviour();
        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 4, None, [miner_authorization(&miner_key)]).unwrap(),
            )
            .unwrap();
        behaviour
            .bind_authorized_miner(4, vec![0; 20], miner_public_key, miner_peer)
            .unwrap();
        let connected = HashSet::from([miner_peer]);
        let outcome = envelope(&signer_key, signer_peer, SignerLane::ProposalUnavailable, 1);

        behaviour.authenticate_peer(miner_peer, CAP_SIGNER_SEMANTICS);
        assert!(behaviour.direct_targets(&outcome, &connected).is_empty());

        behaviour.authenticate_peer(miner_peer, CAP_SIGNER_SEMANTICS | CAP_PROPOSAL_UNAVAILABLE);
        assert_eq!(behaviour.direct_targets(&outcome, &connected), [miner_peer]);
        assert_eq!(
            behaviour.queue_publication(signer_peer, outcome).unwrap(),
            SignerAdmission::FirstSeen
        );
        assert_eq!(behaviour.publication_queue_len(), 0);
        assert_eq!(behaviour.direct_mailbox_len(), 1);
        behaviour.tick(Instant::now());
        assert!(!behaviour
            .events
            .iter()
            .any(|event| matches!(event, SignerBehaviourEvent::PublishGossip { .. })));
    }

    #[test]
    fn downstream_backpressure_does_not_commit_signer_admission() {
        let key = StacksPrivateKey::from_seed(&[71; 32]);
        let peer = PeerId::random();
        let mut behaviour = behaviour();
        behaviour.authenticate_peer(peer, CAP_SIGNER_SEMANTICS);
        let wire = envelope(&key, peer, SignerLane::Control, 1);

        let first = behaviour
            .stage_gossip(peer, peer, wire.clone())
            .unwrap()
            .expect("first envelope requires delivery");
        assert_eq!(first.admission, SignerAdmission::FirstSeen);
        behaviour.complete_delivery(first.token, false).unwrap();

        let retry = behaviour
            .stage_gossip(peer, peer, wire.clone())
            .unwrap()
            .expect("failed downstream delivery remains retryable");
        assert_eq!(retry.admission, SignerAdmission::FirstSeen);
        behaviour.complete_delivery(retry.token, true).unwrap();
        assert!(behaviour.stage_gossip(peer, peer, wire).unwrap().is_none());
    }

    #[test]
    fn connected_rekey_revokes_only_the_previous_transport_binding() {
        let key = StacksPrivateKey::from_seed(&[72; 32]);
        let old_peer = PeerId::random();
        let new_peer = PeerId::random();
        let mut behaviour = behaviour();
        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 4, None, [signer_authorization(&key)]).unwrap(),
            )
            .unwrap();
        behaviour.authenticate_peer(old_peer, CAP_SIGNER_SEMANTICS);
        behaviour.authenticate_peer(new_peer, CAP_SIGNER_SEMANTICS);

        let old = behaviour
            .stage_gossip(
                old_peer,
                old_peer,
                envelope(&key, old_peer, SignerLane::BlockResponse, 1),
            )
            .unwrap()
            .unwrap();
        assert_eq!(old.revoked_peer, None);
        behaviour.complete_delivery(old.token, true).unwrap();

        let new = behaviour
            .stage_gossip(
                new_peer,
                new_peer,
                envelope(&key, new_peer, SignerLane::BlockResponse, 2),
            )
            .unwrap()
            .unwrap();
        assert_eq!(new.revoked_peer, Some(old_peer));
        assert!(!behaviour.authorization_state().is_peer_bound(4, &old_peer));
        assert!(behaviour.authorization_state().is_peer_bound(4, &new_peer));
    }

    #[test]
    fn publication_retry_and_completion_are_owned_by_the_behaviour() {
        let key = StacksPrivateKey::from_seed(&[73; 32]);
        let peer = PeerId::random();
        let mut behaviour = behaviour();
        assert_eq!(
            behaviour
                .queue_publication(peer, envelope(&key, peer, SignerLane::Control, 1))
                .unwrap(),
            SignerAdmission::FirstSeen
        );
        let now = Instant::now();
        behaviour.tick(now);
        let token = match behaviour.events.pop_front().unwrap() {
            SignerBehaviourEvent::PublishGossip { token, .. } => token,
            other => panic!("unexpected event: {other:?}"),
        };
        behaviour
            .complete_publication(token, PublicationOutcome::NoPeers)
            .unwrap();
        assert_eq!(behaviour.publication_queue_len(), 1);
        behaviour.events.clear();
        behaviour.tick(now + PUBLICATION_RETRY - Duration::from_millis(1));
        assert!(behaviour.events.is_empty());
        behaviour.tick(now + PUBLICATION_RETRY);
        let retry = match behaviour.events.pop_front().unwrap() {
            SignerBehaviourEvent::PublishGossip { token, .. } => token,
            other => panic!("unexpected event: {other:?}"),
        };
        assert_eq!(retry, token);
        behaviour
            .complete_publication(retry, PublicationOutcome::Published)
            .unwrap();
        assert_eq!(behaviour.publication_queue_len(), 0);
    }

    #[test]
    fn retained_miner_delivery_follows_late_signer_authentication() {
        let miner_key = StacksPrivateKey::from_seed(&[74; 32]);
        let signer_key = StacksPrivateKey::from_seed(&[75; 32]);
        let miner_peer = PeerId::random();
        let signer_peer = PeerId::random();
        let mut behaviour = behaviour();
        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 4, None, [signer_authorization(&signer_key)])
                    .unwrap(),
            )
            .unwrap();
        behaviour
            .bind_authorized_signer(
                4,
                match signer_authorization(&signer_key).key {
                    crate::AuthorizedRoleKey::PublicKey(key) => key,
                    crate::AuthorizedRoleKey::PublicKeyHash160(_) => unreachable!(),
                },
                signer_peer,
            )
            .unwrap();
        behaviour
            .queue_publication(
                miner_peer,
                envelope(&miner_key, miner_peer, SignerLane::BlockProposal, 1),
            )
            .unwrap();
        assert_eq!(behaviour.direct_mailbox_len(), 1);
        assert!(behaviour.direct.pending.is_empty());

        behaviour.peers.connected.insert(signer_peer);
        behaviour.authenticate_peer(signer_peer, CAP_SIGNER_SEMANTICS);
        behaviour.tick(Instant::now());
        assert!(behaviour
            .direct
            .pending
            .values()
            .any(|(peer, _)| *peer == signer_peer));
        assert!(behaviour.events.iter().any(|event| matches!(
            event,
            SignerBehaviourEvent::DirectSent { peer, .. } if *peer == signer_peer
        )));
    }

    #[test]
    fn failed_retained_direct_delivery_uses_bounded_exponential_backoff() {
        let miner_key = StacksPrivateKey::from_seed(&[76; 32]);
        let signer_key = StacksPrivateKey::from_seed(&[77; 32]);
        let miner_peer = PeerId::random();
        let signer_peer = PeerId::random();
        let mut behaviour = behaviour();
        behaviour
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 4, None, [signer_authorization(&signer_key)])
                    .unwrap(),
            )
            .unwrap();
        behaviour
            .bind_authorized_signer(
                4,
                match signer_authorization(&signer_key).key {
                    crate::AuthorizedRoleKey::PublicKey(key) => key,
                    crate::AuthorizedRoleKey::PublicKeyHash160(_) => unreachable!(),
                },
                signer_peer,
            )
            .unwrap();
        behaviour.peers.connected.insert(signer_peer);
        behaviour.authenticate_peer(signer_peer, CAP_SIGNER_SEMANTICS);
        behaviour
            .queue_publication(
                miner_peer,
                envelope(&miner_key, miner_peer, SignerLane::BlockProposal, 1),
            )
            .unwrap();
        let envelope_id = behaviour.direct.retained[0].envelope_id;
        behaviour.direct.pending.clear();
        behaviour.publications.queue.clear();
        behaviour.publications.bytes = 0;
        behaviour.events.clear();

        let failed_at = Instant::now();
        behaviour.mark_direct_failure(signer_peer, envelope_id, failed_at);
        behaviour.tick(failed_at + DIRECT_RETRY_INITIAL - Duration::from_millis(1));
        assert!(!behaviour.events.iter().any(|event| matches!(
            event,
            SignerBehaviourEvent::DirectSent { peer, .. } if *peer == signer_peer
        )));

        behaviour.tick(failed_at + DIRECT_RETRY_INITIAL);
        assert!(behaviour.events.iter().any(|event| matches!(
            event,
            SignerBehaviourEvent::DirectSent { peer, .. } if *peer == signer_peer
        )));

        behaviour.direct.pending.clear();
        behaviour.events.clear();
        let second_failure = failed_at + DIRECT_RETRY_INITIAL;
        behaviour.mark_direct_failure(signer_peer, envelope_id, second_failure);
        behaviour.tick(second_failure + DIRECT_RETRY_INITIAL);
        assert!(
            behaviour.events.is_empty(),
            "the second retry doubles its delay"
        );
        behaviour.tick(second_failure + DIRECT_RETRY_INITIAL.saturating_mul(2));
        assert!(behaviour.events.iter().any(|event| matches!(
            event,
            SignerBehaviourEvent::DirectSent { peer, .. } if *peer == signer_peer
        )));
    }

    #[test]
    fn completed_replay_is_coalesced_per_cycle_and_refreshes() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let mut behaviour = behaviour();
        behaviour.mark_replay_requested(peer_a, 4);
        assert!(!behaviour.replay_needed(peer_a, 4));
        assert!(!behaviour.replay_needed(peer_b, 4));

        behaviour.replays.attempts.insert(
            4,
            SignerReplayAttempt {
                provider: peer_a,
                requested_at: Instant::now()
                    .checked_sub(SIGNER_REPLAY_REFRESH)
                    .expect("the monotonic clock can represent a short replay interval"),
            },
        );
        assert!(behaviour.replay_needed(peer_a, 4));
        assert!(behaviour.replay_needed(peer_b, 4));
    }

    #[test]
    fn failed_replay_rotates_provider_without_stale_failure_races() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let mut behaviour = behaviour();
        behaviour.mark_replay_requested(peer_a, 4);
        behaviour.retry_replay(peer_a, 4);
        assert!(!behaviour.replay_needed(peer_a, 4));
        assert!(behaviour.replay_needed(peer_b, 4));

        behaviour.mark_replay_requested(peer_b, 4);
        behaviour.retry_replay(peer_a, 4);
        assert!(!behaviour.replay_needed(peer_a, 4));
        assert!(!behaviour.replay_needed(peer_b, 4));

        behaviour.continue_replay(peer_b, 4);
        assert!(behaviour.replay_needed(peer_a, 4));
        assert!(behaviour.replay_needed(peer_b, 4));
    }
}
