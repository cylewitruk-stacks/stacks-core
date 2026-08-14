//! Bounded, domain-grouped runtime diagnostics.
//!
//! `NetworkDiagnostics` is the stable flat response DTO. Mutation happens on
//! the grouped runtime model through `DiagnosticsHandle`; callers cannot share
//! the lock or replace the state wholesale.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use libp2p::PeerId;
use serde::Serialize;
use stacks_network_types::wire::v1::SignerLane;

use crate::{PeerStoreRuntimeSnapshot, SignerAdmission, VerifiedSignerEnvelope};

pub const DIAGNOSTIC_EVENT_CAPACITY: usize = 128;
const MAX_DETAIL_BYTES: usize = 512;
const MAX_SIGNER_OBSERVATIONS: usize = 2048;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct NetworkDiagnostics {
    pub local_peer_id: String,
    pub listening_addresses: Vec<String>,
    pub connected_peers: Vec<String>,
    pub sync_capable_peers: Vec<String>,
    pub object_sync_capable_peers: Vec<String>,
    pub preferred_sync_peers: Vec<String>,
    /// Native peers whose current PeerId and incumbent connection have both
    /// proven the same unexpired rotating legacy node key.
    pub coalesced_legacy_peers: Vec<String>,
    pub successful_hellos: u64,
    pub rejected_hellos: u64,
    pub outbound_failures: u64,
    pub published_signer_messages: u64,
    pub received_signer_messages: u64,
    pub rejected_signer_messages: u64,
    pub deferred_miner_authorizations: u64,
    pub deferred_miner_authorizations_pending: usize,
    pub deferred_miner_authorization_observations_delivered: u64,
    pub deferred_miner_authorization_observation_retries: u64,
    pub deferred_miner_authorizations_released: u64,
    pub deferred_miner_authorizations_expired: u64,
    pub deferred_miner_authorizations_unauthorized: u64,
    pub deferred_miner_authorizations_redundant: u64,
    pub deferred_miner_authorizations_binding_failed: u64,
    pub deferred_miner_authorizations_malformed: u64,
    pub signer_equivocations: u64,
    pub signer_observations: Vec<SignerObservation>,
    pub direct_signer_messages_sent: u64,
    pub direct_signer_messages_received: u64,
    pub direct_signer_failures: u64,
    pub direct_signer_deliveries_pending: usize,
    pub direct_signer_deliveries_expired: u64,
    pub signer_replay_requests_sent: u64,
    pub signer_replay_requests_received: u64,
    pub signer_replay_envelopes_served: u64,
    pub signer_replay_envelopes_received: u64,
    pub signer_replay_rejections: u64,
    pub directory_queries_sent: u64,
    pub directory_queries_received: u64,
    pub directory_records_accepted: u64,
    pub directory_rejections: u64,
    pub autonat_successes: u64,
    pub autonat_failures: u64,
    pub kademlia_server: bool,
    pub kademlia_queries_started: u64,
    pub peer_store_enabled: bool,
    pub peer_store_peers: u64,
    pub peer_store_addresses: u64,
    pub peer_store_restored: u64,
    pub peer_store_writes: u64,
    pub peer_store_write_failures: u64,
    pub peer_store_queue_drops: u64,
    pub peer_store_corruptions_recovered: u64,
    pub ping_successes: u64,
    pub ping_failures: u64,
    pub peer_rtt_ms: Vec<(String, u64)>,
    pub object_announcements_published: u64,
    pub object_announcements_received: u64,
    pub objects_published: u64,
    pub objects_received: u64,
    pub object_fetches_started: u64,
    pub object_fetch_failures: u64,
    pub object_fetches_inflight: usize,
    pub object_fetches_deferred: usize,
    pub max_object_fetches_deferred: usize,
    pub durable_object_lookups: u64,
    pub durable_object_hits: u64,
    pub durable_object_misses: u64,
    pub object_cache_items: usize,
    pub object_cache_bytes: usize,
    pub validation_queue_depth: usize,
    pub validation_queue_capacity: usize,
    pub direct_pushes_sent: u64,
    pub direct_pushes_received: u64,
    pub direct_pushes_queued: u64,
    pub direct_pushes_already_have: u64,
    pub direct_push_busy: u64,
    pub direct_push_rejected: u64,
    pub direct_push_failures: u64,
    pub command_queue_full: u64,
    pub event_queue_full: u64,
    pub resource_budget_rejections: u64,
    pub sync_requests_sent: u64,
    pub sync_requests_received: u64,
    pub sync_responses_received: u64,
    pub sync_failures: u64,
    pub last_command_queue_residence_ms: u64,
    pub max_command_queue_residence_ms: u64,
    pub oldest_command_queue_wait_ms: u64,
    pub event_loop_lag_ms: u64,
    pub event_loop_stalls: u64,
    pub observability_spans_dropped_queue: u64,
    pub observability_spans_dropped_export: u64,
    pub last_error: Option<String>,
    pub last_event_unix_ms: u128,
    pub recent_events: VecDeque<DiagnosticEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticEvent {
    pub unix_ms: u128,
    pub kind: String,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SignerObservation {
    pub reward_cycle: u64,
    pub signer_public_key: Vec<u8>,
    pub peer_id: String,
    pub lane: i32,
    pub sequence: u64,
    pub last_seen_unix_ms: u128,
    pub equivocation: bool,
}

#[derive(Clone, Default)]
pub struct TopologyDiagnostics {
    pub local_peer_id: String,
    pub listening_addresses: Vec<String>,
    pub connected_peers: Vec<String>,
    pub sync_capable_peers: Vec<String>,
    pub object_sync_capable_peers: Vec<String>,
    pub preferred_sync_peers: Vec<String>,
    pub coalesced_legacy_peers: Vec<String>,
    pub ping_successes: u64,
    pub ping_failures: u64,
    pub peer_rtt_ms: Vec<(String, u64)>,
}

#[derive(Clone, Default)]
pub struct DiscoveryDiagnostics {
    pub successful_hellos: u64,
    pub rejected_hellos: u64,
    pub outbound_failures: u64,
    pub autonat_successes: u64,
    pub autonat_failures: u64,
    pub kademlia_server: bool,
    pub kademlia_queries_started: u64,
}

#[derive(Clone, Default)]
pub struct SignerDiagnostics {
    pub published_signer_messages: u64,
    pub received_signer_messages: u64,
    pub rejected_signer_messages: u64,
    pub deferred_miner_authorizations: u64,
    pub deferred_miner_authorizations_pending: usize,
    pub deferred_miner_authorization_observations_delivered: u64,
    pub deferred_miner_authorization_observation_retries: u64,
    pub deferred_miner_authorizations_released: u64,
    pub deferred_miner_authorizations_expired: u64,
    pub deferred_miner_authorizations_unauthorized: u64,
    pub deferred_miner_authorizations_redundant: u64,
    pub deferred_miner_authorizations_binding_failed: u64,
    pub deferred_miner_authorizations_malformed: u64,
    pub signer_equivocations: u64,
    pub signer_observations: Vec<SignerObservation>,
    pub direct_signer_messages_sent: u64,
    pub direct_signer_messages_received: u64,
    pub direct_signer_failures: u64,
    pub direct_signer_deliveries_pending: usize,
    pub direct_signer_deliveries_expired: u64,
    pub signer_replay_requests_sent: u64,
    pub signer_replay_requests_received: u64,
    pub signer_replay_envelopes_served: u64,
    pub signer_replay_envelopes_received: u64,
    pub signer_replay_rejections: u64,
}

#[derive(Clone, Default)]
pub struct DirectoryDiagnostics {
    pub directory_queries_sent: u64,
    pub directory_queries_received: u64,
    pub directory_records_accepted: u64,
    pub directory_rejections: u64,
}

#[derive(Clone, Default)]
pub struct PeerStoreDiagnostics {
    pub peer_store_enabled: bool,
    pub peer_store_peers: u64,
    pub peer_store_addresses: u64,
    pub peer_store_restored: u64,
    pub peer_store_writes: u64,
    pub peer_store_write_failures: u64,
    pub peer_store_queue_drops: u64,
    pub peer_store_corruptions_recovered: u64,
}

#[derive(Clone, Default)]
pub struct ContentDiagnostics {
    pub object_announcements_published: u64,
    pub object_announcements_received: u64,
    pub objects_published: u64,
    pub objects_received: u64,
    pub object_fetches_started: u64,
    pub object_fetch_failures: u64,
    pub object_fetches_inflight: usize,
    pub object_fetches_deferred: usize,
    pub max_object_fetches_deferred: usize,
    pub durable_object_lookups: u64,
    pub durable_object_hits: u64,
    pub durable_object_misses: u64,
    pub object_cache_items: usize,
    pub object_cache_bytes: usize,
    pub validation_queue_depth: usize,
    pub validation_queue_capacity: usize,
    pub direct_pushes_sent: u64,
    pub direct_pushes_received: u64,
    pub direct_pushes_queued: u64,
    pub direct_pushes_already_have: u64,
    pub direct_push_busy: u64,
    pub direct_push_rejected: u64,
    pub direct_push_failures: u64,
}

#[derive(Clone, Default)]
pub struct ResourceDiagnostics {
    pub command_queue_full: u64,
    pub event_queue_full: u64,
    pub resource_budget_rejections: u64,
}

#[derive(Clone, Default)]
pub struct SyncDiagnostics {
    pub sync_requests_sent: u64,
    pub sync_requests_received: u64,
    pub sync_responses_received: u64,
    pub sync_failures: u64,
}

#[derive(Clone, Default)]
pub struct EventLoopDiagnostics {
    pub last_command_queue_residence_ms: u64,
    pub max_command_queue_residence_ms: u64,
    pub event_loop_lag_ms: u64,
    pub event_loop_stalls: u64,
}

#[derive(Clone, Default)]
pub struct EvidenceDiagnostics {
    pub last_error: Option<String>,
    pub last_event_unix_ms: u128,
    pub recent_events: VecDeque<DiagnosticEvent>,
}

#[derive(Clone, Default)]
pub struct DiagnosticsState {
    pub topology: TopologyDiagnostics,
    pub discovery: DiscoveryDiagnostics,
    pub signer: SignerDiagnostics,
    pub directory: DirectoryDiagnostics,
    pub peer_store: PeerStoreDiagnostics,
    pub content: ContentDiagnostics,
    pub resources: ResourceDiagnostics,
    pub sync: SyncDiagnostics,
    pub event_loop: EventLoopDiagnostics,
    pub evidence: EvidenceDiagnostics,
}

impl DiagnosticsState {
    fn snapshot(&self) -> NetworkDiagnostics {
        NetworkDiagnostics {
            local_peer_id: self.topology.local_peer_id.clone(),
            listening_addresses: self.topology.listening_addresses.clone(),
            connected_peers: self.topology.connected_peers.clone(),
            sync_capable_peers: self.topology.sync_capable_peers.clone(),
            object_sync_capable_peers: self.topology.object_sync_capable_peers.clone(),
            preferred_sync_peers: self.topology.preferred_sync_peers.clone(),
            coalesced_legacy_peers: self.topology.coalesced_legacy_peers.clone(),
            successful_hellos: self.discovery.successful_hellos,
            rejected_hellos: self.discovery.rejected_hellos,
            outbound_failures: self.discovery.outbound_failures,
            published_signer_messages: self.signer.published_signer_messages,
            received_signer_messages: self.signer.received_signer_messages,
            rejected_signer_messages: self.signer.rejected_signer_messages,
            deferred_miner_authorizations: self.signer.deferred_miner_authorizations,
            deferred_miner_authorizations_pending: self
                .signer
                .deferred_miner_authorizations_pending,
            deferred_miner_authorization_observations_delivered: self
                .signer
                .deferred_miner_authorization_observations_delivered,
            deferred_miner_authorization_observation_retries: self
                .signer
                .deferred_miner_authorization_observation_retries,
            deferred_miner_authorizations_released: self
                .signer
                .deferred_miner_authorizations_released,
            deferred_miner_authorizations_expired: self
                .signer
                .deferred_miner_authorizations_expired,
            deferred_miner_authorizations_unauthorized: self
                .signer
                .deferred_miner_authorizations_unauthorized,
            deferred_miner_authorizations_redundant: self
                .signer
                .deferred_miner_authorizations_redundant,
            deferred_miner_authorizations_binding_failed: self
                .signer
                .deferred_miner_authorizations_binding_failed,
            deferred_miner_authorizations_malformed: self
                .signer
                .deferred_miner_authorizations_malformed,
            signer_equivocations: self.signer.signer_equivocations,
            signer_observations: self.signer.signer_observations.clone(),
            direct_signer_messages_sent: self.signer.direct_signer_messages_sent,
            direct_signer_messages_received: self.signer.direct_signer_messages_received,
            direct_signer_failures: self.signer.direct_signer_failures,
            direct_signer_deliveries_pending: self.signer.direct_signer_deliveries_pending,
            direct_signer_deliveries_expired: self.signer.direct_signer_deliveries_expired,
            signer_replay_requests_sent: self.signer.signer_replay_requests_sent,
            signer_replay_requests_received: self.signer.signer_replay_requests_received,
            signer_replay_envelopes_served: self.signer.signer_replay_envelopes_served,
            signer_replay_envelopes_received: self.signer.signer_replay_envelopes_received,
            signer_replay_rejections: self.signer.signer_replay_rejections,
            directory_queries_sent: self.directory.directory_queries_sent,
            directory_queries_received: self.directory.directory_queries_received,
            directory_records_accepted: self.directory.directory_records_accepted,
            directory_rejections: self.directory.directory_rejections,
            autonat_successes: self.discovery.autonat_successes,
            autonat_failures: self.discovery.autonat_failures,
            kademlia_server: self.discovery.kademlia_server,
            kademlia_queries_started: self.discovery.kademlia_queries_started,
            peer_store_enabled: self.peer_store.peer_store_enabled,
            peer_store_peers: self.peer_store.peer_store_peers,
            peer_store_addresses: self.peer_store.peer_store_addresses,
            peer_store_restored: self.peer_store.peer_store_restored,
            peer_store_writes: self.peer_store.peer_store_writes,
            peer_store_write_failures: self.peer_store.peer_store_write_failures,
            peer_store_queue_drops: self.peer_store.peer_store_queue_drops,
            peer_store_corruptions_recovered: self.peer_store.peer_store_corruptions_recovered,
            ping_successes: self.topology.ping_successes,
            ping_failures: self.topology.ping_failures,
            peer_rtt_ms: self.topology.peer_rtt_ms.clone(),
            object_announcements_published: self.content.object_announcements_published,
            object_announcements_received: self.content.object_announcements_received,
            objects_published: self.content.objects_published,
            objects_received: self.content.objects_received,
            object_fetches_started: self.content.object_fetches_started,
            object_fetch_failures: self.content.object_fetch_failures,
            object_fetches_inflight: self.content.object_fetches_inflight,
            object_fetches_deferred: self.content.object_fetches_deferred,
            max_object_fetches_deferred: self.content.max_object_fetches_deferred,
            durable_object_lookups: self.content.durable_object_lookups,
            durable_object_hits: self.content.durable_object_hits,
            durable_object_misses: self.content.durable_object_misses,
            object_cache_items: self.content.object_cache_items,
            object_cache_bytes: self.content.object_cache_bytes,
            validation_queue_depth: self.content.validation_queue_depth,
            validation_queue_capacity: self.content.validation_queue_capacity,
            direct_pushes_sent: self.content.direct_pushes_sent,
            direct_pushes_received: self.content.direct_pushes_received,
            direct_pushes_queued: self.content.direct_pushes_queued,
            direct_pushes_already_have: self.content.direct_pushes_already_have,
            direct_push_busy: self.content.direct_push_busy,
            direct_push_rejected: self.content.direct_push_rejected,
            direct_push_failures: self.content.direct_push_failures,
            command_queue_full: self.resources.command_queue_full,
            event_queue_full: self.resources.event_queue_full,
            resource_budget_rejections: self.resources.resource_budget_rejections,
            sync_requests_sent: self.sync.sync_requests_sent,
            sync_requests_received: self.sync.sync_requests_received,
            sync_responses_received: self.sync.sync_responses_received,
            sync_failures: self.sync.sync_failures,
            last_command_queue_residence_ms: self.event_loop.last_command_queue_residence_ms,
            max_command_queue_residence_ms: self.event_loop.max_command_queue_residence_ms,
            // Filled from the command-channel tracker by NetworkHandle because
            // it must keep advancing even if this state owner is stalled.
            oldest_command_queue_wait_ms: 0,
            event_loop_lag_ms: self.event_loop.event_loop_lag_ms,
            event_loop_stalls: self.event_loop.event_loop_stalls,
            observability_spans_dropped_queue: 0,
            observability_spans_dropped_export: 0,
            last_error: self.evidence.last_error.clone(),
            last_event_unix_ms: self.evidence.last_event_unix_ms,
            recent_events: self.evidence.recent_events.clone(),
        }
    }
}

/// Cloneable access to grouped diagnostics. The lock and mutable state remain
/// private to this component; the stable outward API is an immutable snapshot.
#[derive(Clone)]
pub struct DiagnosticsHandle {
    state: Arc<Mutex<DiagnosticsState>>,
}

impl DiagnosticsHandle {
    pub fn new(local_peer_id: PeerId) -> Self {
        let mut state = DiagnosticsState::default();
        state.topology.local_peer_id = local_peer_id.to_string();
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn snapshot(&self) -> NetworkDiagnostics {
        let mut snapshot = self.with_state(|state| state.snapshot());
        let (queue, export) = crate::dropped_span_totals();
        snapshot.observability_spans_dropped_queue = queue;
        snapshot.observability_spans_dropped_export = export;
        snapshot
    }

    /// Internal escape valve for simple counters in the single service
    /// module. Cross-module users receive named methods and immutable snapshots.
    pub fn with_state<T>(&self, update: impl FnOnce(&mut DiagnosticsState) -> T) -> T {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = update(&mut state);
        state.evidence.last_event_unix_ms = now_millis();
        result
    }

    pub fn record_error(&self, error: String) {
        let detail = error.clone();
        self.with_state(|state| {
            state.evidence.last_error = Some(error);
            push_event(&mut state.evidence, "error", detail);
        });
    }

    pub fn record_event(&self, kind: &'static str, detail: String) {
        self.with_state(|state| push_event(&mut state.evidence, kind, detail));
    }

    pub fn update_connected(&self, peers: impl IntoIterator<Item = PeerId>) {
        self.with_state(|state| {
            state.topology.connected_peers =
                peers.into_iter().map(|peer| peer.to_string()).collect();
            state.topology.connected_peers.sort();
        });
    }

    pub fn apply_peer_store_snapshot(&self, snapshot: PeerStoreRuntimeSnapshot) {
        self.with_state(|state| {
            apply_peer_store_snapshot(&mut state.peer_store, snapshot);
        });
    }

    pub fn enable_peer_store(&self, snapshot: PeerStoreRuntimeSnapshot) {
        self.with_state(|state| {
            state.peer_store.peer_store_enabled = true;
            apply_peer_store_snapshot(&mut state.peer_store, snapshot);
        });
    }

    pub fn record_signer_observation(
        &self,
        verified: &VerifiedSignerEnvelope,
        source: PeerId,
        admission: SignerAdmission,
    ) {
        let Ok(lane) = SignerLane::try_from(verified.body.lane) else {
            return;
        };
        self.with_state(|state| {
            if admission == SignerAdmission::Equivocation {
                state.signer.signer_equivocations += 1;
            }
            if lane == SignerLane::Control
                || matches!(lane, SignerLane::BlockProposal | SignerLane::BlockPushed)
            {
                return;
            }
            let signer_public_key = verified.body.signer_public_key.clone();
            let observed_at = now_millis();
            if let Some(observation) = state.signer.signer_observations.iter_mut().find(|item| {
                item.reward_cycle == verified.body.reward_cycle
                    && item.signer_public_key == signer_public_key
                    && item.lane == verified.body.lane
            }) {
                if verified.body.sequence >= observation.sequence {
                    observation.peer_id = source.to_string();
                    observation.sequence = verified.body.sequence;
                    observation.last_seen_unix_ms = observed_at;
                }
                observation.equivocation |= admission == SignerAdmission::Equivocation;
            } else {
                state.signer.signer_observations.push(SignerObservation {
                    reward_cycle: verified.body.reward_cycle,
                    signer_public_key,
                    peer_id: source.to_string(),
                    lane: verified.body.lane,
                    sequence: verified.body.sequence,
                    last_seen_unix_ms: observed_at,
                    equivocation: admission == SignerAdmission::Equivocation,
                });
            }
            state
                .signer
                .signer_observations
                .sort_by_key(|item| (item.reward_cycle, item.last_seen_unix_ms));
            if state.signer.signer_observations.len() > MAX_SIGNER_OBSERVATIONS {
                let excess = state.signer.signer_observations.len() - MAX_SIGNER_OBSERVATIONS;
                state.signer.signer_observations.drain(..excess);
            }
        });
    }

    pub fn record_signer_replays_requested(&self, sent: usize) {
        if sent == 0 {
            return;
        }
        let sent = u64::try_from(sent).unwrap_or(u64::MAX);
        self.with_state(|state| {
            state.sync.sync_requests_sent = state.sync.sync_requests_sent.saturating_add(sent);
            state.signer.signer_replay_requests_sent = state
                .signer
                .signer_replay_requests_sent
                .saturating_add(sent);
        });
    }
}

fn apply_peer_store_snapshot(state: &mut PeerStoreDiagnostics, snapshot: PeerStoreRuntimeSnapshot) {
    state.peer_store_peers = snapshot.peers;
    state.peer_store_addresses = snapshot.addresses;
    state.peer_store_restored = snapshot.restored;
    state.peer_store_writes = snapshot.writes;
    state.peer_store_write_failures = snapshot.write_failures;
    state.peer_store_queue_drops = snapshot.queue_drops;
    state.peer_store_corruptions_recovered = snapshot.corruptions_recovered;
}

fn push_event(evidence: &mut EvidenceDiagnostics, kind: &str, mut detail: String) {
    if detail.len() > MAX_DETAIL_BYTES {
        detail.truncate(MAX_DETAIL_BYTES);
    }
    evidence.recent_events.push_back(DiagnosticEvent {
        unix_ms: now_millis(),
        kind: kind.to_owned(),
        detail,
    });
    while evidence.recent_events.len() > DIAGNOSTIC_EVENT_CAPACITY {
        evidence.recent_events.pop_front();
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_snapshot_stays_flat_and_evidence_is_bounded() {
        let diagnostics = DiagnosticsHandle::new(PeerId::random());
        for index in 0..(DIAGNOSTIC_EVENT_CAPACITY + 4) {
            diagnostics.record_event("fixture", format!("{index}:{}", "x".repeat(700)));
        }
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.recent_events.len(), DIAGNOSTIC_EVENT_CAPACITY);
        assert!(snapshot
            .recent_events
            .iter()
            .all(|event| event.detail.len() <= MAX_DETAIL_BYTES));
        let json = serde_json::to_value(snapshot).unwrap();
        assert!(json.get("connected_peers").is_some());
        assert!(json.get("topology").is_none());
    }

    #[test]
    fn poisoned_lock_recovers_and_networking_diagnostics_remain_available() {
        let diagnostics = DiagnosticsHandle::new(PeerId::random());
        let poisoned = diagnostics.clone();
        let _ = std::thread::spawn(move || {
            poisoned.with_state(|_| panic!("poison fixture"));
        })
        .join();
        diagnostics.record_event("after-poison", "still-live".to_owned());
        assert_eq!(
            diagnostics.snapshot().recent_events.back().unwrap().kind,
            "after-poison"
        );
    }
}
