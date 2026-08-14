use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
#[cfg(feature = "monitoring_prom")]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Weak,
};
use std::sync::{Arc, Mutex};
#[cfg(feature = "monitoring_prom")]
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use blockstack_lib::chainstate::stacks::boot::MINERS_NAME;
use blockstack_lib::chainstate::stacks::events::StackerDBChunksEvent;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::util_lib::boot::boot_code_id;
use libp2p::Multiaddr;
use libsigner::v0::messages::{MessageSlotID, MinerSlotID, SignerMessage};
use libsigner::{
    AuthenticatedSignerEvent, PublishReceipt, ReplayRequest, SignerEventAuthentication,
    SignerIngressOrigin, SignerNetwork, SignerNetworkError, SignerNetworkMessage,
};
use stacks_common::info;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_common::types::PrivateKey;
use stacks_common::util::get_epoch_time_secs;
use stacks_network::{
    signed_role_directory_record, signer_identity_from_secret, AuthorizationBootstrap,
    ContentServices, NetworkConfig, NetworkObjectValidator, NetworkService, ObjectNetworkEvent,
    PeerEndpoint, ProviderOutcome, ServiceConfig, SignerAdmission, SignerCanonicalAuthorization,
    SignerNetworkEvent, TransportBootstrap, TransportProfile,
};
use stacks_network_types::wire::v1::{
    Hello, ProposalManifest, Role, SignerEnvelope, SignerEnvelopeBody, SignerLane,
};
use stacks_network_types::{
    proposal_content_id, signer_envelope_digest, signer_envelope_id, Announcement, BridgeMode,
    ContentId, NetworkObject, NetworkScope, ObjectKind, RolloutMode, MAX_PROPOSAL_OBJECT_BYTES,
    PROPOSAL_MANIFEST_VERSION, SIGNER_ENVELOPE_VERSION,
};
use stacks_signer_bridge::{
    semantic_message_id, BridgeJournal, LegacyAuthor, LegacyChunkPolicy, LegacyLocator,
    LegacyWritePipeline, TemporarySignerBridge, TemporarySignerBridgeError,
};

use prost::Message as ProstMessage;

use crate::config::GlobalConfig;
use crate::signerdb::{SignerDb, SignerNetworkJournalRecord};

const MAX_REPLAY_ITEMS: usize = 1024;
const MAX_REPLAY_BYTES: usize = 2 * 1024 * 1024;
const LOCAL_JOURNAL_ITEMS: usize = 4096;
const MAX_REANNOUNCED_ITEMS: usize = 128;
const SEMANTIC_DEDUP_ITEMS: usize = 4096;
#[cfg(feature = "monitoring_prom")]
const OBSERVABILITY_SAMPLE_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Default)]
struct ProposalObjectValidator;

impl NetworkObjectValidator for ProposalObjectValidator {
    fn validate_announcement(&self, _announcement: &Announcement) -> Result<(), String> {
        Err("signer profiles do not accept public object announcements".to_owned())
    }

    fn validate_object(&self, object: &NetworkObject) -> Result<(), String> {
        if object.kind != ObjectKind::BlockProposal {
            return Err("signer profiles accept only block-proposal objects".to_owned());
        }
        if object.bytes.is_empty() || object.bytes.len() > MAX_PROPOSAL_OBJECT_BYTES {
            return Err("proposal object length is outside its bounded range".to_owned());
        }
        if proposal_content_id(&object.bytes) != object.content_id {
            return Err("proposal object content ID does not match its canonical bytes".to_owned());
        }
        Ok(())
    }
}

struct Libp2pSignerNetwork {
    service: Option<NetworkService>,
    stacks_private_key: StacksPrivateKey,
    signer_public_key: Vec<u8>,
    local_peer_id: libp2p::PeerId,
    rendezvous_peers: Vec<libp2p::PeerId>,
    chain_id: u32,
    network_id: u32,
    rollout_mode: RolloutMode,
    mainnet: bool,
    current_cycle: u64,
    next_cycle: Option<u64>,
    sequences: HashMap<(u64, i32), (u64, Option<ContentId>)>,
    journal: VecDeque<AuthenticatedSignerEvent>,
    journal_db: SignerDb,
    advertised_addresses: Vec<Multiaddr>,
    compatibility_bridge: Option<TemporarySignerBridge>,
    legacy_locators: HashMap<(u64, i32), LegacyLocator>,
    legacy_ingress_locators: HashMap<(String, u32), LegacyLocator>,
    compatibility_events: VecDeque<AuthenticatedSignerEvent>,
    semantic_seen: HashSet<ContentId>,
    semantic_order: VecDeque<ContentId>,
    bridge_pipeline: LegacyWritePipeline,
    pending_proposals: HashMap<ContentId, PendingProposal>,
    ready_proposals: VecDeque<AuthenticatedSignerEvent>,
}

struct PendingProposal {
    event: SignerNetworkEvent,
    manifest: ProposalManifest,
    created_at: Instant,
}

/// Cloneable, synchronized access to the process-wide native signer network.
///
/// The libp2p swarm remains single-owned by its service thread. This handle only
/// serializes the small amount of envelope sequence/journal state shared by the
/// signer runloop's current and next reward-cycle instances.
#[derive(Clone)]
pub struct SignerNetworkHandle(
    Arc<Mutex<Libp2pSignerNetwork>>,
    #[cfg(feature = "monitoring_prom")] Arc<SignerNetworkObservability>,
);

#[cfg(feature = "monitoring_prom")]
struct SignerNetworkObservability {
    shutdown: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

#[cfg(feature = "monitoring_prom")]
impl SignerNetworkObservability {
    fn spawn(network: Weak<Mutex<Libp2pSignerNetwork>>) -> io::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = std::thread::Builder::new()
            .name("signer-network-observability".to_owned())
            .spawn(move || {
                while !thread_shutdown.load(Ordering::Acquire) {
                    let Some(network) = network.upgrade() else {
                        break;
                    };
                    record_observability_metrics(&network);
                    std::thread::park_timeout(OBSERVABILITY_SAMPLE_INTERVAL);
                }
            })?;
        Ok(Self {
            shutdown,
            thread: Mutex::new(Some(thread)),
        })
    }

    fn stop_and_join(&self) -> std::thread::Result<()> {
        self.shutdown.store(true, Ordering::Release);
        let thread = self
            .thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(thread) = thread {
            thread.thread().unpark();
            thread.join()?;
        }
        Ok(())
    }
}

#[cfg(feature = "monitoring_prom")]
impl Drop for SignerNetworkObservability {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

impl std::fmt::Debug for SignerNetworkHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignerNetworkHandle")
            .finish_non_exhaustive()
    }
}

fn record_observability_metrics(network: &Mutex<Libp2pSignerNetwork>) {
    let Ok(network) = network.lock() else {
        return;
    };
    let Some(service) = network.service.as_ref() else {
        crate::monitoring::actions::record_native_network(
            &[],
            0,
            &[],
            &stacks_network::DeferredMinerAuthorizationSnapshot::default(),
        );
        return;
    };
    let diagnostics = service.diagnostics();
    let connected = diagnostics
        .connected_peers
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let signer_public_keys = diagnostics
        .signer_observations
        .iter()
        .filter(|observation| connected.contains(observation.peer_id.as_str()))
        .map(|observation| stacks_common::util::hash::to_hex(&observation.signer_public_key))
        .collect::<Vec<_>>();
    crate::monitoring::actions::record_native_network(
        &diagnostics.connected_peers,
        network
            .rendezvous_peers
            .iter()
            .filter(|peer| connected.contains(peer.to_string().as_str()))
            .count(),
        &signer_public_keys,
        &stacks_network::DeferredMinerAuthorizationSnapshot {
            admitted: diagnostics.deferred_miner_authorizations,
            observation_delivered: diagnostics.deferred_miner_authorization_observations_delivered,
            observation_retries: diagnostics.deferred_miner_authorization_observation_retries,
            released: diagnostics.deferred_miner_authorizations_released,
            expired: diagnostics.deferred_miner_authorizations_expired,
            unauthorized: diagnostics.deferred_miner_authorizations_unauthorized,
            redundant: diagnostics.deferred_miner_authorizations_redundant,
            binding_failed: diagnostics.deferred_miner_authorizations_binding_failed,
            malformed: diagnostics.deferred_miner_authorizations_malformed,
            pending: diagnostics.deferred_miner_authorizations_pending,
        },
    );
}

impl SignerNetworkHandle {
    fn new(network: Libp2pSignerNetwork) -> io::Result<Self> {
        let network = Arc::new(Mutex::new(network));
        #[cfg(feature = "monitoring_prom")]
        {
            let observability =
                Arc::new(SignerNetworkObservability::spawn(Arc::downgrade(&network))?);
            Ok(Self(network, observability))
        }
        #[cfg(not(feature = "monitoring_prom"))]
        {
            Ok(Self(network))
        }
    }

    /// Publish an endpoint-free monitoring snapshot from the process-owned
    /// native network. Signer identities are included only when a currently
    /// connected peer has produced a valid chain-authorized signer envelope.
    pub fn record_observability_metrics(&self) {
        record_observability_metrics(&self.0);
    }

    /// Whether application messages are published on the native transport.
    pub fn publishes_application_data(&self) -> bool {
        self.0
            .lock()
            .map(|network| network.rollout_mode.publishes_application_data())
            .unwrap_or(false)
    }

    /// Whether the runtime has at least one authorized local egress carrier.
    /// This includes the quarantined legacy-only rollback adapter.
    pub fn accepts_local_publication(&self) -> bool {
        self.0
            .lock()
            .map(|network| {
                network.rollout_mode.publishes_application_data()
                    || network.bridge_pipeline.is_enabled()
            })
            .unwrap_or(false)
    }

    /// Whether signer application traffic must not fall back to legacy HTTP
    /// callbacks or StackerDB carriers.
    pub fn is_native_only(&self) -> bool {
        self.0
            .lock()
            .map(|network| network.rollout_mode == RolloutMode::Libp2pOnly)
            .unwrap_or(false)
    }

    /// Whether exact `.miners` compatibility admission is installed, allowing
    /// the incumbent payload-only event to be suppressed without message loss.
    pub fn bridges_legacy_miner_ingress(&self) -> bool {
        self.0
            .lock()
            .map(|network| {
                let contract = boot_code_id(MINERS_NAME, network.mainnet).to_string();
                network
                    .legacy_ingress_locators
                    .keys()
                    .any(|(configured, _)| configured == &contract)
            })
            .unwrap_or(false)
    }

    /// Publish one semantic signer message without exposing transport internals.
    pub fn publish(
        &self,
        message: SignerNetworkMessage,
    ) -> Result<PublishReceipt, SignerNetworkError> {
        self.0
            .lock()
            .map_err(|_| SignerNetworkError::Stopped)?
            .publish(message)
    }

    /// Poll one authenticated native event without blocking.
    pub fn try_next_event(&self) -> Result<Option<AuthenticatedSignerEvent>, SignerNetworkError> {
        self.0
            .lock()
            .map_err(|_| SignerNetworkError::Stopped)?
            .try_next_event()
    }

    #[cfg(test)]
    pub(crate) fn local_test_messages(&self) -> Vec<SignerNetworkMessage> {
        self.0
            .lock()
            .expect("signer network lock poisoned")
            .journal
            .iter()
            .filter(|event| event.origin == SignerIngressOrigin::Local)
            .map(|event| event.message.clone())
            .collect()
    }

    /// Update current/next reward-cycle admission atomically.
    pub fn update_cycles(&self, current: u64, next: Option<u64>) -> Result<(), SignerNetworkError> {
        let mut network = self.0.lock().map_err(|_| SignerNetworkError::Stopped)?;
        if let Some(service) = network.service.as_ref() {
            service
                .retain_signer_cycles(current, next)
                .map_err(map_io_error)?;
        }
        network.update_cycles(current, next)
    }

    /// Replace the locally chainstate-authorized signer keys for a reward cycle.
    pub fn update_authorized_signers(
        &self,
        reward_cycle: u64,
        public_keys: Vec<[u8; 33]>,
    ) -> Result<(), SignerNetworkError> {
        let mut network = self.0.lock().map_err(|_| SignerNetworkError::Stopped)?;
        network.configure_legacy_signer_set(reward_cycle, &public_keys);
        if let Some(service) = network.service.as_ref() {
            service
                .update_authorized_signers(reward_cycle, public_keys)
                .map_err(map_io_error)?;
        }
        Ok(())
    }

    /// Replace native miner authority with canonical sortition IDs and their
    /// winning compressed-public-key hashes for one reward cycle.
    pub fn update_authorized_miners(
        &self,
        reward_cycle: u64,
        miners: Vec<(Vec<u8>, [u8; 20])>,
    ) -> Result<(), SignerNetworkError> {
        let network = self.0.lock().map_err(|_| SignerNetworkError::Stopped)?;
        let Some(service) = network.service.as_ref() else {
            return Ok(());
        };
        service
            .update_authorized_miners(reward_cycle, miners)
            .map_err(map_io_error)
    }

    /// Replace exact `.miners` slot/key-hash admission from the node's
    /// canonical current/previous sortitions.
    pub fn update_authorized_legacy_miners(
        &self,
        reward_cycle: u64,
        authorizations: Vec<(u32, SignerLane, [u8; 20])>,
    ) -> Result<(), SignerNetworkError> {
        self.0
            .lock()
            .map_err(|_| SignerNetworkError::Stopped)?
            .configure_legacy_miners(reward_cycle, authorizations);
        Ok(())
    }

    /// Verify raw legacy signer chunks and enqueue their semantic equivalents.
    /// Invalid, unknown, and local-echo chunks are contained in the bridge and
    /// never reach signer policy or the native gossip mesh.
    pub fn ingest_legacy_event(&self, event: &StackerDBChunksEvent) {
        let mut network = match self.0.lock() {
            Ok(network) => network,
            Err(_) => return,
        };
        network.ingest_legacy_event(event);
    }

    /// Install the origin-only legacy destinations for one locally registered
    /// signer cycle. Native publication remains authoritative; the optional
    /// bridge owns independent legacy versions and signing evidence.
    pub fn configure_legacy_cycle(
        &self,
        reward_cycle: u64,
        signer_slot_id: u32,
        mainnet: bool,
    ) -> Result<(), SignerNetworkError> {
        self.0
            .lock()
            .map_err(|_| SignerNetworkError::Stopped)?
            .configure_legacy_cycle(reward_cycle, signer_slot_id, mainnet)
    }

    /// Publish a cycle-scoped private directory binding for this signer. The
    /// proof is disclosed only to configured rendezvous peers by `NetworkService`.
    pub fn install_role_record(
        &self,
        reward_cycle: u64,
        signer_id: u32,
        burn_height: u64,
        valid_from_burn_height: u64,
        valid_until_burn_height: u64,
    ) -> Result<(), SignerNetworkError> {
        let network = self.0.lock().map_err(|_| SignerNetworkError::Stopped)?;
        let record = signed_role_directory_record(
            NetworkScope::new(network.chain_id, network.network_id),
            network.local_peer_id,
            Role::Signer,
            reward_cycle,
            signer_id.to_be_bytes().to_vec(),
            valid_from_burn_height,
            valid_until_burn_height,
            network.advertised_addresses.iter().cloned(),
            &network.stacks_private_key,
        )
        .map_err(SignerNetworkError::InvalidMessage)?;
        let Some(service) = network.service.as_ref() else {
            return Ok(());
        };
        service
            .update_chain_view(burn_height, network.current_cycle)
            .map_err(map_io_error)?;
        service
            .set_local_role_record(Some(record))
            .map_err(map_io_error)
    }

    /// Stop and join the native service. Safe to call more than once.
    pub fn shutdown(&self) -> std::thread::Result<()> {
        #[cfg(feature = "monitoring_prom")]
        let observability_result = self.1.stop_and_join();
        #[cfg(not(feature = "monitoring_prom"))]
        let observability_result: std::thread::Result<()> = Ok(());
        let mut network = self
            .0
            .lock()
            .expect("signer network lock poisoned during shutdown");
        let service_result = network
            .service
            .take()
            .map_or(Ok(()), NetworkService::shutdown);
        let Libp2pSignerNetwork {
            compatibility_bridge,
            bridge_pipeline,
            stacks_private_key,
            ..
        } = &mut *network;
        let writer_result = if let Some(bridge) = compatibility_bridge.as_mut() {
            bridge_pipeline.shutdown(|pipeline| {
                for warning in pipeline
                    .pump(bridge, stacks_private_key, get_epoch_time_secs())
                    .warnings
                {
                    stacks_common::warn!("Temporary signer-bridge pipeline: {warning}");
                }
            })
        } else {
            bridge_pipeline.shutdown(|_| {})
        };
        observability_result.and(service_result).and(writer_result)
    }
}

impl Libp2pSignerNetwork {
    fn configure_legacy_miners(
        &mut self,
        reward_cycle: u64,
        authorizations: Vec<(u32, SignerLane, [u8; 20])>,
    ) {
        if self.compatibility_bridge.is_none() {
            return;
        }
        let contract = boot_code_id(MINERS_NAME, self.mainnet).to_string();
        self.legacy_ingress_locators
            .retain(|(existing, _), _| existing != &contract);
        for (slot_id, lane, author_hash) in authorizations {
            if !matches!(lane, SignerLane::BlockProposal | SignerLane::BlockPushed) {
                continue;
            }
            let expected_offset = match lane {
                SignerLane::BlockProposal => u32::from(MinerSlotID::BlockProposal.to_u8()),
                SignerLane::BlockPushed => u32::from(MinerSlotID::BlockPushed.to_u8()),
                _ => unreachable!(),
            };
            if slot_id % 2 != expected_offset {
                continue;
            }
            self.legacy_ingress_locators.insert(
                (contract.clone(), slot_id),
                LegacyLocator {
                    contract: contract.clone(),
                    reward_cycle,
                    lane,
                    slot_id,
                    author: LegacyAuthor::PublicKeyHash160(author_hash),
                    allow_epoch25: false,
                },
            );
        }
    }

    fn configure_legacy_signer_set(&mut self, reward_cycle: u64, public_keys: &[[u8; 33]]) {
        if self.compatibility_bridge.is_none() {
            return;
        }
        for (slot_id, author_public_key) in public_keys.iter().copied().enumerate() {
            let Ok(slot_id) = u32::try_from(slot_id) else {
                break;
            };
            for (lane, message_slot) in [
                (SignerLane::BlockResponse, MessageSlotID::BlockResponse),
                (
                    SignerLane::StateMachineUpdate,
                    MessageSlotID::StateMachineUpdate,
                ),
                (SignerLane::BlockPreCommit, MessageSlotID::BlockPreCommit),
            ] {
                let locator = LegacyLocator {
                    contract: message_slot
                        .stacker_db_contract(self.mainnet, reward_cycle)
                        .to_string(),
                    reward_cycle,
                    lane,
                    slot_id,
                    author: LegacyAuthor::PublicKey(author_public_key),
                    allow_epoch25: false,
                };
                self.legacy_ingress_locators
                    .insert((locator.contract.clone(), slot_id), locator);
            }
        }
    }

    fn ingest_legacy_event(&mut self, event: &StackerDBChunksEvent) {
        let Some(bridge) = self.compatibility_bridge.as_mut() else {
            return;
        };
        let contract = event.contract_id.to_string();
        let policy = LegacyIngressPolicy {
            locators: &self.legacy_ingress_locators,
        };
        for chunk in &event.modified_slots {
            match bridge.ingest(&contract, chunk, &policy, get_epoch_time_secs()) {
                Ok(Some(event)) => self.compatibility_events.push_back(event),
                Ok(None) => {}
                Err(TemporarySignerBridgeError::Mapping) => {
                    // Miner contracts retain their incumbent compatibility path
                    // until sortition-authorized miner mappings are installed.
                }
                Err(error) => {
                    stacks_common::warn!("Temporary signer bridge rejected legacy ingress: {error}")
                }
            }
        }
    }

    fn admit_semantic(
        &mut self,
        event: AuthenticatedSignerEvent,
    ) -> Option<AuthenticatedSignerEvent> {
        let author = event.author_public_key()?;
        let semantic_id = semantic_message_id(&event.message, author);
        if !self.semantic_seen.insert(semantic_id) {
            return None;
        }
        self.semantic_order.push_back(semantic_id);
        if self.semantic_order.len() > SEMANTIC_DEDUP_ITEMS {
            if let Some(expired) = self.semantic_order.pop_front() {
                self.semantic_seen.remove(&expired);
            }
        }
        Some(event)
    }

    fn configure_legacy_cycle(
        &mut self,
        reward_cycle: u64,
        signer_slot_id: u32,
        mainnet: bool,
    ) -> Result<(), SignerNetworkError> {
        if self.compatibility_bridge.is_none() {
            return Ok(());
        }
        let author_public_key: [u8; 33] =
            self.signer_public_key.as_slice().try_into().map_err(|_| {
                SignerNetworkError::InvalidMessage("invalid local signer key".to_owned())
            })?;
        for (lane, message_slot) in [
            (SignerLane::BlockResponse, MessageSlotID::BlockResponse),
            (
                SignerLane::StateMachineUpdate,
                MessageSlotID::StateMachineUpdate,
            ),
            (SignerLane::BlockPreCommit, MessageSlotID::BlockPreCommit),
        ] {
            self.legacy_locators.insert(
                (reward_cycle, lane as i32),
                LegacyLocator {
                    contract: message_slot
                        .stacker_db_contract(mainnet, reward_cycle)
                        .to_string(),
                    reward_cycle,
                    lane,
                    slot_id: signer_slot_id,
                    author: LegacyAuthor::PublicKey(author_public_key),
                    allow_epoch25: false,
                },
            );
        }
        Ok(())
    }

    fn pump_compatibility_bridge(&mut self) {
        let Some(bridge) = self.compatibility_bridge.as_mut() else {
            return;
        };
        for warning in self
            .bridge_pipeline
            .pump(bridge, &self.stacks_private_key, get_epoch_time_secs())
            .warnings
        {
            stacks_common::warn!("Temporary signer-bridge pipeline: {warning}");
        }
    }

    fn record(&mut self, event: AuthenticatedSignerEvent) {
        if self.journal.len() == LOCAL_JOURNAL_ITEMS {
            self.journal.pop_front();
        }
        self.journal.push_back(event);
    }

    fn persist_event(&self, event: &AuthenticatedSignerEvent) -> Result<(), SignerNetworkError> {
        let envelope = event.native_envelope().ok_or_else(|| {
            SignerNetworkError::InvalidMessage(
                "native journal cannot persist compatibility authentication".to_owned(),
            )
        })?;
        let body = envelope.body.as_ref().ok_or_else(|| {
            SignerNetworkError::InvalidMessage("signer envelope has no body".to_owned())
        })?;
        self.journal_db
            .persist_signer_network_envelope(&journal_record(event, body, get_epoch_time_secs()))
            .map_err(|error| SignerNetworkError::Transport(error.to_string()))
    }

    fn poll_proposal_objects(&mut self) -> Result<(), SignerNetworkError> {
        const MAX_OBJECT_EVENTS_PER_POLL: usize = 16;
        const PROPOSAL_FETCH_TTL: Duration = Duration::from_secs(60);
        self.pending_proposals
            .retain(|_, pending| pending.created_at.elapsed() <= PROPOSAL_FETCH_TTL);
        for _ in 0..MAX_OBJECT_EVENTS_PER_POLL {
            let object_event = self
                .service
                .as_ref()
                .map(|service| service.try_next_object_event())
                .transpose()
                .map_err(map_io_error)?
                .flatten();
            let Some(object_event) = object_event else {
                break;
            };
            match object_event {
                ObjectNetworkEvent::Object { source, object, .. }
                    if object.kind == ObjectKind::BlockProposal =>
                {
                    let Some(pending) = self.pending_proposals.remove(&object.content_id) else {
                        if let Some(service) = self.service.as_ref() {
                            let _ = service.reject_object(object.content_id);
                        }
                        continue;
                    };
                    match authenticated_proposal_event(pending, object.clone()) {
                        Ok(event) => {
                            self.journal_db
                                .persist_signer_network_proposal(
                                    object.content_id.as_bytes(),
                                    event.message.reward_cycle,
                                    &object.bytes,
                                    get_epoch_time_secs(),
                                )
                                .map_err(|error| {
                                    SignerNetworkError::Transport(error.to_string())
                                })?;
                            if let Some(service) = self.service.as_ref() {
                                service.commit_object(object).map_err(map_io_error)?;
                                let _ = service.report_provider_outcome(
                                    source,
                                    ProviderOutcome::Success {
                                        latency: Duration::ZERO,
                                    },
                                );
                            }
                            self.ready_proposals.push_back(event);
                        }
                        Err(error) => {
                            if let Some(service) = self.service.as_ref() {
                                let _ = service.reject_object(object.content_id);
                                let _ = service
                                    .report_provider_outcome(source, ProviderOutcome::InvalidData);
                            }
                            stacks_common::warn!(
                                "Rejected fetched block-proposal object";
                                "source" => %source,
                                "error" => %error,
                            );
                        }
                    }
                }
                ObjectNetworkEvent::Request {
                    response_token,
                    kind: ObjectKind::BlockProposal,
                    id,
                    ..
                } => {
                    let object = self
                        .journal_db
                        .get_signer_network_proposal(id.as_bytes())
                        .map_err(|error| SignerNetworkError::Transport(error.to_string()))?
                        .map(|bytes| NetworkObject {
                            kind: ObjectKind::BlockProposal,
                            content_id: id,
                            bytes,
                        });
                    if let Some(service) = self.service.as_ref() {
                        service
                            .respond_object(response_token, object)
                            .map_err(map_io_error)?;
                    }
                }
                ObjectNetworkEvent::Object { object, .. } => {
                    if let Some(service) = self.service.as_ref() {
                        let _ = service.reject_object(object.content_id);
                    }
                }
                ObjectNetworkEvent::Request { response_token, .. } => {
                    if let Some(service) = self.service.as_ref() {
                        service
                            .respond_object(response_token, None)
                            .map_err(map_io_error)?;
                    }
                }
                ObjectNetworkEvent::Announcement { .. } => {}
            }
        }
        Ok(())
    }
}

fn authenticated_proposal_event(
    pending: PendingProposal,
    object: NetworkObject,
) -> Result<AuthenticatedSignerEvent, SignerNetworkError> {
    validate_proposal_bytes(
        &pending.manifest,
        object.content_id,
        &object.bytes,
        &pending.event.envelope.body.signer_public_key,
    )?;
    let envelope = pending.event.envelope;
    Ok(AuthenticatedSignerEvent {
        message: SignerNetworkMessage {
            reward_cycle: envelope.body.reward_cycle,
            lane: SignerLane::BlockProposal,
            burn_view_consensus_hash: envelope.body.burn_view_consensus_hash.clone(),
            payload: object.bytes,
        },
        authentication: SignerEventAuthentication::Native {
            envelope: Box::new(envelope.envelope),
            envelope_id: envelope.envelope_id,
        },
        origin: SignerIngressOrigin::Libp2p,
        is_equivocation: pending.event.admission == SignerAdmission::Equivocation,
    })
}

fn validate_proposal_bytes(
    manifest: &ProposalManifest,
    content_id: ContentId,
    bytes: &[u8],
    envelope_miner_public_key: &[u8],
) -> Result<(), SignerNetworkError> {
    let expected_len = usize::try_from(manifest.encoded_len).map_err(|_| {
        SignerNetworkError::InvalidMessage("proposal manifest length does not fit usize".to_owned())
    })?;
    if bytes.len() != expected_len || proposal_content_id(bytes) != content_id {
        return Err(SignerNetworkError::InvalidMessage(
            "proposal object differs from its signed manifest".to_owned(),
        ));
    }
    let mut cursor = bytes;
    let decoded = SignerMessage::consensus_deserialize(&mut cursor).map_err(|error| {
        SignerNetworkError::InvalidMessage(format!("invalid proposal object: {error}"))
    })?;
    if !cursor.is_empty() {
        return Err(SignerNetworkError::InvalidMessage(
            "proposal object has trailing bytes".to_owned(),
        ));
    }
    let SignerMessage::BlockProposal(proposal) = decoded else {
        return Err(SignerNetworkError::InvalidMessage(
            "proposal object carries a different signer message".to_owned(),
        ));
    };
    let recovered_miner = proposal.block.header.recover_miner_pk().ok_or_else(|| {
        SignerNetworkError::InvalidMessage(
            "proposal block has an unrecoverable miner signature".to_owned(),
        )
    })?;
    if recovered_miner.to_bytes_compressed().as_slice() != envelope_miner_public_key {
        return Err(SignerNetworkError::InvalidMessage(
            "proposal block miner differs from its sortition-authorized envelope".to_owned(),
        ));
    }
    if proposal.reward_cycle != manifest.reward_cycle
        || proposal.burn_height != manifest.burn_height
        || proposal.block.header.signer_signature_hash().0.as_slice()
            != manifest.signer_signature_hash.as_slice()
    {
        return Err(SignerNetworkError::InvalidMessage(
            "proposal object metadata differs from its signed manifest".to_owned(),
        ));
    }
    Ok(())
}

impl SignerNetwork for Libp2pSignerNetwork {
    fn publish(
        &mut self,
        message: SignerNetworkMessage,
    ) -> Result<PublishReceipt, SignerNetworkError> {
        if message.reward_cycle != self.current_cycle
            && Some(message.reward_cycle) != self.next_cycle
        {
            return Err(SignerNetworkError::InactiveCycle(message.reward_cycle));
        }
        let semantic_message = message.clone();
        let mut native_envelope_id = None;
        if self.rollout_mode.publishes_application_data() || message.lane == SignerLane::Control {
            let service = self.service.as_ref().ok_or(SignerNetworkError::Stopped)?;
            let key = (message.reward_cycle, message.lane as i32);
            let (sequence, previous) = self.sequences.get(&key).copied().unwrap_or((0, None));
            let encoded_payload = message.payload;
            let proposal = if message.lane == SignerLane::BlockProposal {
                let mut cursor = encoded_payload.as_slice();
                let decoded =
                    SignerMessage::consensus_deserialize(&mut cursor).map_err(|error| {
                        SignerNetworkError::InvalidMessage(format!(
                            "invalid block-proposal payload: {error}"
                        ))
                    })?;
                let SignerMessage::BlockProposal(proposal) = decoded else {
                    return Err(SignerNetworkError::InvalidMessage(
                        "block-proposal lane carried a different signer message".to_owned(),
                    ));
                };
                if !cursor.is_empty() {
                    return Err(SignerNetworkError::InvalidMessage(
                        "block-proposal payload has trailing bytes".to_owned(),
                    ));
                }
                let content_id = proposal_content_id(&encoded_payload);
                Some((
                    NetworkObject {
                        kind: ObjectKind::BlockProposal,
                        content_id,
                        bytes: encoded_payload.clone(),
                    },
                    ProposalManifest {
                        version: PROPOSAL_MANIFEST_VERSION,
                        content_id: content_id.as_bytes().to_vec(),
                        encoded_len: u64::try_from(encoded_payload.len()).map_err(|_| {
                            SignerNetworkError::InvalidMessage(
                                "proposal length does not fit its manifest".to_owned(),
                            )
                        })?,
                        signer_signature_hash: proposal
                            .block
                            .header
                            .signer_signature_hash()
                            .0
                            .to_vec(),
                        burn_height: proposal.burn_height,
                        reward_cycle: proposal.reward_cycle,
                    },
                ))
            } else {
                None
            };
            if let Some((object, manifest)) = proposal.as_ref() {
                self.journal_db
                    .persist_signer_network_proposal(
                        object.content_id.as_bytes(),
                        manifest.reward_cycle,
                        &object.bytes,
                        get_epoch_time_secs(),
                    )
                    .map_err(|error| SignerNetworkError::Transport(error.to_string()))?;
            }
            let body = SignerEnvelopeBody {
                version: SIGNER_ENVELOPE_VERSION,
                chain_id: self.chain_id,
                network_id: self.network_id,
                reward_cycle: message.reward_cycle,
                lane: message.lane as i32,
                sequence,
                previous_envelope_id: previous
                    .map(|content_id| content_id.as_bytes().to_vec())
                    .unwrap_or_default(),
                signer_public_key: self.signer_public_key.clone(),
                transport_peer_id: self.local_peer_id.to_bytes(),
                payload: proposal.as_ref().map_or(encoded_payload, |_| Vec::new()),
                burn_view_consensus_hash: message.burn_view_consensus_hash,
                proposal_manifest: proposal.as_ref().map(|(_, manifest)| manifest.clone()),
            };
            let signature = self
                .stacks_private_key
                .sign(&signer_envelope_digest(&body))
                .map_err(|error| SignerNetworkError::InvalidMessage(error.to_string()))?;
            let envelope = SignerEnvelope {
                body: Some(body),
                signature: signature.as_bytes().to_vec(),
            };
            let envelope_id = signer_envelope_id(&envelope)
                .map_err(|error| SignerNetworkError::InvalidMessage(error.to_string()))?;
            let event = AuthenticatedSignerEvent {
                message: semantic_message.clone(),
                authentication: SignerEventAuthentication::Native {
                    envelope: Box::new(envelope.clone()),
                    envelope_id,
                },
                origin: SignerIngressOrigin::Local,
                is_equivocation: false,
            };
            self.journal_db
                .persist_outgoing_signer_network_envelope(
                    &self.signer_public_key,
                    &journal_record(&event, body_ref(&envelope)?, get_epoch_time_secs()),
                    sequence.saturating_add(1),
                )
                .map_err(|error| SignerNetworkError::Transport(error.to_string()))?;
            // Advance memory immediately after the durable transaction. A failed
            // bounded enqueue leaves a replayable gap, never a reused sequence.
            self.sequences
                .insert(key, (sequence.saturating_add(1), Some(envelope_id)));
            if let Some((object, _)) = proposal {
                service
                    .publish_proposal(object, envelope)
                    .map_err(map_io_error)?;
            } else {
                service.publish_signer(envelope).map_err(map_io_error)?;
            }
            self.record(event);
            native_envelope_id = Some(envelope_id);
        }
        let mut compatibility_queued = false;
        if let (Some(bridge), Some(locator)) = (
            self.compatibility_bridge.as_mut(),
            self.legacy_locators
                .get(&(semantic_message.reward_cycle, semantic_message.lane as i32))
                .cloned(),
        ) {
            match bridge.enqueue_origin_egress(
                &semantic_message,
                native_envelope_id,
                locator,
                &self.stacks_private_key,
                get_epoch_time_secs(),
            ) {
                Ok(_) => compatibility_queued = true,
                Err(TemporarySignerBridgeError::Disabled) => {}
                Err(TemporarySignerBridgeError::QueueFull) => stacks_common::warn!(
                    "Temporary signer bridge is full; native publication remains queued"
                ),
                Err(error) => return Err(SignerNetworkError::Transport(error.to_string())),
            }
        }
        self.pump_compatibility_bridge();
        if native_envelope_id.is_none() && !compatibility_queued {
            return Err(SignerNetworkError::Disabled);
        }
        Ok(PublishReceipt {
            envelope_id: native_envelope_id
                .unwrap_or_else(|| semantic_message_id(&semantic_message, &self.signer_public_key)),
            native_queued: native_envelope_id.is_some(),
            compatibility_queued,
        })
    }

    fn try_next_event(&mut self) -> Result<Option<AuthenticatedSignerEvent>, SignerNetworkError> {
        self.pump_compatibility_bridge();
        self.poll_proposal_objects()?;
        let ready_proposal = self.ready_proposals.pop_front();
        let native_event = self
            .service
            .as_ref()
            .filter(|_| ready_proposal.is_none())
            .map(|service| service.try_next_signer_event())
            .transpose()
            .map_err(map_io_error)?
            .flatten();
        let event = if let Some(event) = ready_proposal {
            Some(event)
        } else if let Some(event) = native_event {
            if event.canonical_authorization == SignerCanonicalAuthorization::Pending {
                let manifest = event.envelope.body.proposal_manifest.as_ref();
                stacks_common::warn!(
                    "Authenticated miner proposal is pending canonical companion evidence; abstaining";
                    "source" => %event.source,
                    "reward_cycle" => event.envelope.body.reward_cycle,
                    "signer_signature_hash" => manifest
                        .map(|manifest| stacks_common::util::hash::to_hex(&manifest.signer_signature_hash))
                        .unwrap_or_else(|| "missing".to_owned()),
                );
                // This is an immediate local availability observation only.
                // A signer-signed wire response would reveal the association
                // between this transport PeerId and the signer's Stacks key to
                // a miner that canonical chainstate has not authorized yet.
                return Ok(None);
            }
            if let Some(manifest) = event.envelope.body.proposal_manifest.clone() {
                if event.admission == SignerAdmission::Equivocation {
                    let envelope = event.envelope;
                    Some(AuthenticatedSignerEvent {
                        message: SignerNetworkMessage {
                            reward_cycle: envelope.body.reward_cycle,
                            lane: SignerLane::BlockProposal,
                            burn_view_consensus_hash: envelope
                                .body
                                .burn_view_consensus_hash
                                .clone(),
                            payload: Vec::new(),
                        },
                        authentication: SignerEventAuthentication::Native {
                            envelope: Box::new(envelope.envelope),
                            envelope_id: envelope.envelope_id,
                        },
                        origin: SignerIngressOrigin::Libp2p,
                        is_equivocation: true,
                    })
                } else {
                    let content_id = stacks_network_types::validate_proposal_manifest(
                        &manifest,
                        event.envelope.body.reward_cycle,
                    )
                    .map_err(|error| SignerNetworkError::InvalidMessage(error.to_string()))?;
                    let provider = event.provider;
                    self.pending_proposals.insert(
                        content_id,
                        PendingProposal {
                            event,
                            manifest,
                            created_at: Instant::now(),
                        },
                    );
                    let mut providers = Vec::with_capacity(self.rendezvous_peers.len() + 1);
                    providers.push(provider);
                    providers.extend(
                        self.rendezvous_peers
                            .iter()
                            .copied()
                            .filter(|peer| *peer != provider),
                    );
                    let service = self.service.as_ref().ok_or(SignerNetworkError::Stopped)?;
                    let mut queued = false;
                    for provider in providers {
                        match service.request_object(
                            provider,
                            ObjectKind::BlockProposal,
                            content_id,
                        ) {
                            Ok(()) => queued = true,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                            Err(error) => {
                                stacks_common::debug!(
                                    "Skipped unavailable proposal provider";
                                    "provider" => %provider,
                                    "error" => %error,
                                );
                            }
                        }
                    }
                    if !queued {
                        self.pending_proposals.remove(&content_id);
                        return Err(SignerNetworkError::Busy);
                    }
                    None
                }
            } else {
                let envelope = event.envelope;
                Some(AuthenticatedSignerEvent {
                    message: SignerNetworkMessage {
                        reward_cycle: envelope.body.reward_cycle,
                        lane: SignerLane::try_from(envelope.body.lane).map_err(|_| {
                            SignerNetworkError::InvalidMessage(
                                "unknown authenticated lane".to_owned(),
                            )
                        })?,
                        burn_view_consensus_hash: envelope.body.burn_view_consensus_hash.clone(),
                        payload: envelope.body.payload.clone(),
                    },
                    authentication: SignerEventAuthentication::Native {
                        envelope: Box::new(envelope.envelope),
                        envelope_id: envelope.envelope_id,
                    },
                    origin: SignerIngressOrigin::Libp2p,
                    is_equivocation: event.admission == SignerAdmission::Equivocation,
                })
            }
        } else {
            self.compatibility_events.pop_front()
        };
        let event = event.filter(|event| {
            event.origin == SignerIngressOrigin::LegacyCompatibility
                || self.rollout_mode.accepts_application_ingress()
        });
        let Some(event) = event.and_then(|event| self.admit_semantic(event)) else {
            return Ok(None);
        };
        if event.native_envelope().is_some() {
            self.persist_event(&event)?;
            self.record(event.clone());
        }
        Ok(Some(event))
    }

    fn replay(
        &mut self,
        request: ReplayRequest,
    ) -> Result<Vec<AuthenticatedSignerEvent>, SignerNetworkError> {
        if request.max_items > MAX_REPLAY_ITEMS || request.max_bytes > MAX_REPLAY_BYTES {
            return Err(SignerNetworkError::InvalidMessage(
                "replay bounds exceed protocol limits".to_owned(),
            ));
        }
        let mut result = Vec::new();
        let mut bytes = 0_usize;
        for event in &self.journal {
            if event.message.reward_cycle != request.reward_cycle {
                continue;
            }
            let Some(cursor) = request
                .cursors
                .iter()
                .find(|cursor| cursor.lane == event.message.lane)
            else {
                continue;
            };
            let Some(sequence) = event
                .native_envelope()
                .and_then(|envelope| envelope.body.as_ref())
                .map(|body| body.sequence)
            else {
                continue;
            };
            if sequence <= cursor.sequence {
                continue;
            }
            if result.len() == request.max_items
                || bytes.saturating_add(event.message.payload.len()) > request.max_bytes
            {
                break;
            }
            bytes += event.message.payload.len();
            result.push(event.clone());
        }
        Ok(result)
    }

    fn update_cycles(&mut self, current: u64, next: Option<u64>) -> Result<(), SignerNetworkError> {
        if next.is_some_and(|next| next != current.saturating_add(1)) {
            return Err(SignerNetworkError::InvalidMessage(
                "next reward cycle must immediately follow current".to_owned(),
            ));
        }
        self.current_cycle = current;
        self.next_cycle = next;
        self.journal.retain(|event| {
            event.message.reward_cycle == current || Some(event.message.reward_cycle) == next
        });
        self.sequences
            .retain(|(cycle, _), _| *cycle == current || Some(*cycle) == next);
        self.legacy_locators
            .retain(|(cycle, _), _| *cycle == current || Some(*cycle) == next);
        self.legacy_ingress_locators.retain(|_, locator| {
            locator.reward_cycle == current || Some(locator.reward_cycle) == next
        });
        self.compatibility_events.retain(|event| {
            event.message.reward_cycle == current || Some(event.message.reward_cycle) == next
        });
        self.bridge_pipeline.retain_cycles(current, next);
        if let Some(bridge) = self.compatibility_bridge.as_mut() {
            bridge
                .update_cycles(current, next)
                .map_err(|error| SignerNetworkError::Transport(error.to_string()))?;
        }
        self.journal_db
            .prune_signer_network_cycles(current, next)
            .map_err(|error| SignerNetworkError::Transport(error.to_string()))?;
        // Re-announce locally-authored retained state after cycle transition or
        // restart. Remote journals deduplicate exact envelopes by content ID.
        if let Some(service) = self.service.as_ref() {
            let mut retained: Vec<_> = self
                .journal
                .iter()
                .rev()
                .filter(|event| {
                    event.origin == SignerIngressOrigin::Local
                        && (event.message.reward_cycle == current
                            || Some(event.message.reward_cycle) == next)
                })
                .take(MAX_REANNOUNCED_ITEMS)
                .collect();
            retained.reverse();
            for event in retained {
                let Some(envelope) = event.native_envelope() else {
                    continue;
                };
                service
                    .publish_signer(envelope.clone())
                    .map_err(map_io_error)?;
            }
        }
        self.pump_compatibility_bridge();
        Ok(())
    }
}

fn load_retained_network_journal(
    journal_db: &SignerDb,
) -> io::Result<VecDeque<AuthenticatedSignerEvent>> {
    let mut journal = VecDeque::new();
    for record in journal_db
        .get_signer_network_journal()
        .map_err(io::Error::other)?
    {
        let mut event = event_from_record(record)?;
        if let Some(manifest) = event
            .native_envelope()
            .and_then(|envelope| envelope.body.as_ref())
            .and_then(|body| body.proposal_manifest.as_ref())
        {
            let content_id = stacks_network_types::validate_proposal_manifest(
                manifest,
                event.message.reward_cycle,
            )
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let Some(bytes) = journal_db
                .get_signer_network_proposal(content_id.as_bytes())
                .map_err(io::Error::other)?
            else {
                // Proposal objects have a deliberately smaller retention bound
                // than the mixed-lane envelope journal. A manifest whose
                // object has aged out cannot be replayed, but it must not make
                // an otherwise healthy signer fail every subsequent restart.
                stacks_common::warn!(
                    "Skipping retained proposal manifest whose bounded object has expired";
                    "content_id" => %content_id,
                    "reward_cycle" => event.message.reward_cycle,
                );
                continue;
            };
            let envelope_miner_public_key = event
                .native_envelope()
                .and_then(|envelope| envelope.body.as_ref())
                .map(|body| body.signer_public_key.as_slice())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "proposal journal entry has no native envelope body",
                    )
                })?;
            validate_proposal_bytes(manifest, content_id, &bytes, envelope_miner_public_key)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            event.message.payload = bytes;
        }
        journal.push_back(event);
    }
    Ok(journal)
}

pub(super) fn spawn(config: &GlobalConfig) -> io::Result<SignerNetworkHandle> {
    let chain_id = config.to_chain_id();
    // Stacks currently uses the chain identifier as the application network identifier.
    let network_id = chain_id;
    let private_key = config.stacks_private_key.to_bytes();
    let private_scalar: &[u8; 32] = private_key[..32]
        .try_into()
        .expect("Stacks private keys always contain a 32-byte scalar");
    let scope = NetworkScope::new(chain_id, network_id);
    let identity = signer_identity_from_secret(private_scalar, scope)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let local_peer_id = identity.public().to_peer_id();
    let journal_db = SignerDb::new(&config.db_path).map_err(io::Error::other)?;
    let journal = load_retained_network_journal(&journal_db)?;
    let signer_public_key = StacksPublicKey::from_private(&config.stacks_private_key);
    let signer_public_key_bytes = signer_public_key.to_bytes_compressed();
    let mut sequences = HashMap::new();
    for state in journal_db
        .get_signer_network_sequences(&signer_public_key_bytes)
        .map_err(io::Error::other)?
    {
        let previous = state
            .previous_envelope_id
            .map(content_id_from_vec)
            .transpose()?;
        sequences.insert(
            (state.reward_cycle, state.lane),
            (state.next_sequence, previous),
        );
    }
    let initial_signer_envelopes = journal
        .iter()
        .filter_map(|event| event.native_envelope().cloned())
        .collect();
    let listen_addresses = parse_addresses("libp2p.bind", &config.libp2p.bind)?;
    let advertised_addresses = parse_addresses(
        "libp2p.advertise",
        if config.libp2p.advertise.is_empty() {
            &config.libp2p.bind
        } else {
            &config.libp2p.advertise
        },
    )?;
    let bootstrap_endpoints =
        parse_peer_endpoints("libp2p.bootstrap_peers", &config.libp2p.bootstrap_peers)?;
    let rendezvous_endpoints =
        parse_peer_endpoints("libp2p.rendezvous_peers", &config.libp2p.rendezvous_peers)?;
    let private_rendezvous_peers: Vec<_> = rendezvous_endpoints
        .iter()
        .map(PeerEndpoint::peer_id)
        .collect();
    // Configured rendezvous peers are outbound reachability commitments, not
    // miner identities. Keep them under bounded reconnect so role-directory
    // exchange and direct request/response remain available; proposal authority
    // is established separately by canonical sortition authorization plus a
    // source-bound miner proof or signed miner-lane envelope.
    let bootstrap_addresses = configured_dial_addresses(bootstrap_endpoints, &rendezvous_endpoints);
    let network = NetworkConfig::signer_profile(
        scope,
        format!("stacks-signer-libp2p/{}", env!("CARGO_PKG_VERSION")),
        &config.libp2p.limits,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let hello = Hello {
        envelope_version: 1,
        chain_id,
        network_id,
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
    };
    let service = if config.libp2p.enabled {
        Some(NetworkService::spawn(
            ServiceConfig::new(
                TransportBootstrap {
                    identity,
                    network,
                    transport: TransportProfile::Tcp,
                    listen_addresses,
                    bootstrap_addresses,
                    peer_store: None,
                },
                AuthorizationBootstrap {
                    private_rendezvous_peers: private_rendezvous_peers.clone(),
                    initial_signer_envelopes,
                    ..AuthorizationBootstrap::default()
                },
                ContentServices {
                    validator: Some(Arc::new(ProposalObjectValidator)),
                    cache_bytes: usize::try_from(config.libp2p.limits.object_cache_bytes).map_err(
                        |_| io::Error::other("object cache limit does not fit this platform"),
                    )?,
                },
                hello,
            )
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
            format!("signer-libp2p:{}", config.stacks_address),
        )?)
    } else {
        None
    };
    let compatibility_bridge = if config.libp2p.signer_bridge.mode == BridgeMode::Off {
        None
    } else {
        Some(
            TemporarySignerBridge::new(
                config.libp2p.signer_bridge.clone(),
                BridgeJournal::open(&config.db_path).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?,
        )
    };
    let bridge_pipeline = if config.libp2p.signer_bridge.mode.writes_legacy() {
        LegacyWritePipeline::spawn(
            "signer-legacy-bridge",
            config.node_host.to_string(),
            config.stackerdb_timeout,
            256,
        )?
    } else {
        LegacyWritePipeline::disabled()
    };
    let mut network = Libp2pSignerNetwork {
        service,
        stacks_private_key: config.stacks_private_key.clone(),
        signer_public_key: signer_public_key_bytes,
        local_peer_id,
        rendezvous_peers: private_rendezvous_peers,
        chain_id,
        network_id,
        rollout_mode: config.libp2p.rollout_mode,
        mainnet: config.network.is_mainnet(),
        current_cycle: 0,
        next_cycle: None,
        sequences,
        journal,
        journal_db,
        advertised_addresses,
        compatibility_bridge,
        legacy_locators: HashMap::new(),
        legacy_ingress_locators: HashMap::new(),
        compatibility_events: VecDeque::new(),
        semantic_seen: HashSet::new(),
        semantic_order: VecDeque::new(),
        bridge_pipeline,
        pending_proposals: HashMap::new(),
        ready_proposals: VecDeque::new(),
    };
    if network.service.is_some() {
        network
            .publish(SignerNetworkMessage {
                reward_cycle: 0,
                lane: SignerLane::Control,
                burn_view_consensus_hash: Vec::new(),
                payload: b"stacks-signer-ready/v1".to_vec(),
            })
            .map_err(io::Error::other)?;
        let diagnostics = network
            .service
            .as_ref()
            .expect("native service was checked")
            .diagnostics();
        info!(
            "Started native signer libp2p network";
            "peer_id" => diagnostics.local_peer_id,
            "configured_listeners" => config.libp2p.bind.join(","),
        );
    } else {
        info!("Started quarantined legacy signer compatibility adapter without a libp2p listener");
    }
    SignerNetworkHandle::new(network)
}

struct LegacyIngressPolicy<'a> {
    locators: &'a HashMap<(String, u32), LegacyLocator>,
}

impl LegacyChunkPolicy for LegacyIngressPolicy<'_> {
    fn resolve(&self, contract: &str, slot_id: u32) -> Option<LegacyLocator> {
        self.locators.get(&(contract.to_owned(), slot_id)).cloned()
    }
}

fn map_io_error(error: io::Error) -> SignerNetworkError {
    match error.kind() {
        io::ErrorKind::WouldBlock => SignerNetworkError::Busy,
        io::ErrorKind::BrokenPipe => SignerNetworkError::Stopped,
        _ => SignerNetworkError::Transport(error.to_string()),
    }
}

fn body_ref(envelope: &SignerEnvelope) -> Result<&SignerEnvelopeBody, SignerNetworkError> {
    envelope
        .body
        .as_ref()
        .ok_or_else(|| SignerNetworkError::InvalidMessage("signer envelope has no body".to_owned()))
}

fn journal_record(
    event: &AuthenticatedSignerEvent,
    body: &SignerEnvelopeBody,
    observed_at: u64,
) -> SignerNetworkJournalRecord {
    let envelope = event
        .native_envelope()
        .expect("native signer journal only receives native authentication");
    SignerNetworkJournalRecord {
        envelope_id: event.event_id().as_bytes().to_vec(),
        reward_cycle: body.reward_cycle,
        lane: body.lane,
        sequence: body.sequence,
        envelope: envelope.encode_to_vec(),
        origin: match event.origin {
            SignerIngressOrigin::Local => 0,
            SignerIngressOrigin::Libp2p => 1,
            SignerIngressOrigin::LegacyCompatibility => 2,
        },
        is_equivocation: event.is_equivocation,
        observed_at,
    }
}

fn event_from_record(record: SignerNetworkJournalRecord) -> io::Result<AuthenticatedSignerEvent> {
    let envelope = SignerEnvelope::decode(record.envelope.as_slice())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let body = envelope.body.as_ref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "journal envelope has no body")
    })?;
    if body.reward_cycle != record.reward_cycle
        || body.lane != record.lane
        || body.sequence != record.sequence
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal envelope metadata mismatch",
        ));
    }
    let envelope_id = signer_envelope_id(&envelope)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if envelope_id.as_bytes().as_slice() != record.envelope_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal envelope content ID mismatch",
        ));
    }
    let origin = match record.origin {
        0 => SignerIngressOrigin::Local,
        1 => SignerIngressOrigin::Libp2p,
        2 => SignerIngressOrigin::LegacyCompatibility,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal envelope has an invalid origin",
            ));
        }
    };
    Ok(AuthenticatedSignerEvent {
        message: SignerNetworkMessage {
            reward_cycle: body.reward_cycle,
            lane: SignerLane::try_from(body.lane).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "journal envelope has unknown lane",
                )
            })?,
            burn_view_consensus_hash: body.burn_view_consensus_hash.clone(),
            payload: body.payload.clone(),
        },
        authentication: SignerEventAuthentication::Native {
            envelope: Box::new(envelope),
            envelope_id,
        },
        origin,
        is_equivocation: record.is_equivocation,
    })
}

fn content_id_from_vec(bytes: Vec<u8>) -> io::Result<ContentId> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("journal content ID has {} bytes", bytes.len()),
        )
    })?;
    Ok(ContentId::from_bytes(bytes))
}

fn parse_addresses(field: &str, addresses: &[String]) -> io::Result<Vec<Multiaddr>> {
    addresses
        .iter()
        .map(|address| {
            address.parse().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid {field} multiaddress {address:?}: {error}"),
                )
            })
        })
        .collect()
}

fn parse_peer_endpoints(field: &str, addresses: &[String]) -> io::Result<Vec<PeerEndpoint>> {
    addresses
        .iter()
        .map(|address| {
            address.parse().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid {field} peer endpoint {address:?}: {error}"),
                )
            })
        })
        .collect()
}

fn configured_dial_addresses(
    bootstrap_endpoints: Vec<PeerEndpoint>,
    rendezvous_endpoints: &[PeerEndpoint],
) -> Vec<Multiaddr> {
    let mut addresses = bootstrap_endpoints
        .into_iter()
        .map(PeerEndpoint::into_multiaddr)
        .collect::<Vec<_>>();
    for rendezvous in rendezvous_endpoints.iter().cloned() {
        let address = rendezvous.into_multiaddr();
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
    use clarity::codec::StacksMessageCodec;
    use libsigner::v0::messages::SignerMessage;
    use libsigner::{BlockProposal, BlockProposalData};
    use stacks_common::util::hash::Sha512Trunc256Sum;
    use stacks_network_types::SignerBridgeConfig;
    use tempfile::TempDir;

    use super::*;

    static NEXT_TEST_MEMORY_ADDRESS: AtomicU64 = AtomicU64::new(90_000);

    fn memory_signer_service(
        identity: libp2p::identity::Keypair,
        network: NetworkConfig,
        listen_addresses: Vec<Multiaddr>,
        bootstrap_addresses: Vec<Multiaddr>,
        rendezvous_peers: Vec<libp2p::PeerId>,
        name: &str,
    ) -> NetworkService {
        let hello = Hello {
            envelope_version: 1,
            chain_id: network.chain_id,
            network_id: network.network_id,
            supported_protocol_versions: vec![1],
            peer_version: 1,
            capabilities: stacks_network_types::CAP_SIGNER_V1,
            burn_tip_height: 0,
            burn_tip_hash: Vec::new(),
            stable_burn_tip_height: 0,
            stable_burn_tip_hash: Vec::new(),
            stacks_tip_height: 0,
            stacks_tip_id: Vec::new(),
            current_reward_cycle: 9,
            advertised_multiaddrs: Vec::new(),
            legacy_identity_binding: None,
            challenge: Vec::new(),
        };
        NetworkService::spawn(
            ServiceConfig::new(
                TransportBootstrap {
                    identity,
                    network,
                    transport: TransportProfile::Memory,
                    listen_addresses,
                    bootstrap_addresses,
                    peer_store: None,
                },
                AuthorizationBootstrap {
                    private_rendezvous_peers: rendezvous_peers,
                    ..AuthorizationBootstrap::default()
                },
                ContentServices {
                    validator: Some(Arc::new(ProposalObjectValidator)),
                    cache_bytes: stacks_network::DEFAULT_OBJECT_CACHE_BYTES,
                },
                hello,
            )
            .unwrap(),
            name,
        )
        .unwrap()
    }

    #[test]
    fn configured_rendezvous_peers_are_dialed_without_duplicate_bootstraps() {
        let bootstrap_peer = libp2p::PeerId::random();
        let rendezvous_peer = libp2p::PeerId::random();
        let bootstrap: PeerEndpoint = format!("/memory/1/p2p/{bootstrap_peer}").parse().unwrap();
        let duplicate: PeerEndpoint = format!("/memory/1/p2p/{bootstrap_peer}").parse().unwrap();
        let rendezvous: PeerEndpoint = format!("/memory/2/p2p/{rendezvous_peer}").parse().unwrap();

        assert_eq!(
            configured_dial_addresses(vec![bootstrap], &[duplicate, rendezvous]),
            vec![
                format!("/memory/1/p2p/{bootstrap_peer}").parse().unwrap(),
                format!("/memory/2/p2p/{rendezvous_peer}").parse().unwrap(),
            ]
        );
    }

    #[test]
    fn proposal_manifest_binds_canonical_payload_and_metadata() {
        let miner_key = StacksPrivateKey::from_seed(b"proposal-manifest-miner");
        let miner_public_key = StacksPublicKey::from_private(&miner_key).to_bytes_compressed();
        let mut header = NakamotoBlockHeader::genesis();
        header.sign_miner(&miner_key).unwrap();
        let proposal = BlockProposal {
            block: NakamotoBlock::new(header, vec![]),
            burn_height: 123,
            reward_cycle: 9,
            block_proposal_data: BlockProposalData::empty(),
        };
        let bytes = SignerMessage::BlockProposal(proposal.clone()).serialize_to_vec();
        let content_id = proposal_content_id(&bytes);
        let manifest = ProposalManifest {
            version: PROPOSAL_MANIFEST_VERSION,
            content_id: content_id.as_bytes().to_vec(),
            encoded_len: bytes.len() as u64,
            signer_signature_hash: proposal.block.header.signer_signature_hash().0.to_vec(),
            burn_height: proposal.burn_height,
            reward_cycle: proposal.reward_cycle,
        };
        validate_proposal_bytes(&manifest, content_id, &bytes, &miner_public_key).unwrap();

        let mut wrong_metadata = manifest.clone();
        wrong_metadata.burn_height += 1;
        assert!(
            validate_proposal_bytes(&wrong_metadata, content_id, &bytes, &miner_public_key)
                .is_err()
        );
        let mut wrong_bytes = bytes.clone();
        wrong_bytes.push(0);
        assert!(
            validate_proposal_bytes(&manifest, content_id, &wrong_bytes, &miner_public_key)
                .is_err()
        );
        assert!(validate_proposal_bytes(
            &manifest,
            ContentId::from_bytes([0; 32]),
            &bytes,
            &miner_public_key
        )
        .is_err());
        let wrong_miner = StacksPublicKey::from_private(&StacksPrivateKey::from_seed(
            b"different-sortition-winner",
        ))
        .to_bytes_compressed();
        assert!(validate_proposal_bytes(&manifest, content_id, &bytes, &wrong_miner).is_err());
    }

    #[test]
    fn restart_skips_manifest_after_bounded_proposal_object_expires() {
        let tempdir = TempDir::new().unwrap();
        let database = tempdir.path().join("signer.sqlite");
        let journal_db = SignerDb::new(&database).unwrap();
        let miner_key = StacksPrivateKey::from_seed(b"expired-proposal-object-miner");
        let miner_public_key = StacksPublicKey::from_private(&miner_key).to_bytes_compressed();
        let peer = libp2p::PeerId::random();
        let mut header = NakamotoBlockHeader::genesis();
        header.sign_miner(&miner_key).unwrap();
        let proposal = BlockProposal {
            block: NakamotoBlock::new(header, vec![]),
            burn_height: 123,
            reward_cycle: 9,
            block_proposal_data: BlockProposalData::empty(),
        };
        let proposal_bytes = SignerMessage::BlockProposal(proposal.clone()).serialize_to_vec();
        let content_id = proposal_content_id(&proposal_bytes);
        let manifest = ProposalManifest {
            version: PROPOSAL_MANIFEST_VERSION,
            content_id: content_id.as_bytes().to_vec(),
            encoded_len: proposal_bytes.len() as u64,
            signer_signature_hash: proposal.block.header.signer_signature_hash().0.to_vec(),
            burn_height: proposal.burn_height,
            reward_cycle: proposal.reward_cycle,
        };
        let body = SignerEnvelopeBody {
            version: SIGNER_ENVELOPE_VERSION,
            chain_id: 0x8000_0000,
            network_id: 0x8000_0000,
            reward_cycle: proposal.reward_cycle,
            lane: SignerLane::BlockProposal as i32,
            sequence: 0,
            previous_envelope_id: Vec::new(),
            signer_public_key: miner_public_key,
            transport_peer_id: peer.to_bytes(),
            payload: Vec::new(),
            burn_view_consensus_hash: vec![1; 20],
            proposal_manifest: Some(manifest),
        };
        let envelope = SignerEnvelope {
            signature: miner_key
                .sign(&signer_envelope_digest(&body))
                .unwrap()
                .as_bytes()
                .to_vec(),
            body: Some(body),
        };
        let envelope_id = signer_envelope_id(&envelope).unwrap();
        journal_db
            .persist_signer_network_envelope(&SignerNetworkJournalRecord {
                envelope_id: envelope_id.as_bytes().to_vec(),
                reward_cycle: proposal.reward_cycle,
                lane: SignerLane::BlockProposal as i32,
                sequence: 0,
                envelope: envelope.encode_to_vec(),
                origin: 1,
                is_equivocation: false,
                observed_at: 1,
            })
            .unwrap();

        assert!(load_retained_network_journal(&journal_db)
            .unwrap()
            .is_empty());

        journal_db
            .persist_signer_network_proposal(
                content_id.as_bytes(),
                proposal.reward_cycle,
                &proposal_bytes,
                1,
            )
            .unwrap();
        let recovered = load_retained_network_journal(&journal_db).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].message.payload, proposal_bytes);
    }

    #[test]
    fn same_envelope_deferral_releases_to_normal_signer_proposal_processing() {
        let scope = NetworkScope::new(0x8000_0000, 0x8000_0000);
        let mut network = NetworkConfig::signer_profile(
            scope,
            "signer-release-processing-test".to_owned(),
            &stacks_network_types::Libp2pLimits::default(),
        )
        .unwrap();
        network.max_process_memory_bytes = usize::MAX;
        let miner_key = StacksPrivateKey::from_seed(b"deferred-proposal-miner");
        let signer_key = StacksPrivateKey::from_seed(b"deferred-proposal-signer");
        let miner_identity =
            signer_identity_from_secret(miner_key.to_bytes()[..32].try_into().unwrap(), scope)
                .unwrap();
        let signer_identity =
            signer_identity_from_secret(signer_key.to_bytes()[..32].try_into().unwrap(), scope)
                .unwrap();
        let miner_peer = miner_identity.public().to_peer_id();
        let signer_peer = signer_identity.public().to_peer_id();
        let listen: Multiaddr = format!(
            "/memory/{}",
            NEXT_TEST_MEMORY_ADDRESS.fetch_add(1, Ordering::Relaxed)
        )
        .parse()
        .unwrap();
        let bootstrap: Multiaddr = format!("{listen}/p2p/{miner_peer}").parse().unwrap();
        let miner_service = memory_signer_service(
            miner_identity,
            network.clone(),
            vec![listen],
            Vec::new(),
            Vec::new(),
            "deferred-proposal-miner",
        );
        let signer_service = memory_signer_service(
            signer_identity,
            network.clone(),
            Vec::new(),
            vec![bootstrap],
            vec![miner_peer],
            "deferred-proposal-signer",
        );
        let connected_deadline = Instant::now() + Duration::from_secs(10);
        while (!miner_service
            .diagnostics()
            .connected_peers
            .contains(&signer_peer.to_string())
            || !signer_service
                .diagnostics()
                .connected_peers
                .contains(&miner_peer.to_string()))
            && Instant::now() < connected_deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(signer_service
            .diagnostics()
            .connected_peers
            .contains(&miner_peer.to_string()));
        std::thread::sleep(Duration::from_secs(2));

        let mut header = NakamotoBlockHeader::genesis();
        header.chain_length = 1;
        header.consensus_hash = stacks_common::types::chainstate::ConsensusHash([3; 20]);
        header.pox_treatment = stacks_common::bitvec::BitVec::ones(1).unwrap();
        header.sign_miner(&miner_key).unwrap();
        let proposal = BlockProposal {
            block: NakamotoBlock::new(header, vec![]),
            burn_height: 123,
            reward_cycle: 9,
            block_proposal_data: BlockProposalData::empty(),
        };
        let proposal_bytes = SignerMessage::BlockProposal(proposal.clone()).serialize_to_vec();
        let content_id = proposal_content_id(&proposal_bytes);
        let body = SignerEnvelopeBody {
            version: SIGNER_ENVELOPE_VERSION,
            chain_id: scope.chain_id(),
            network_id: scope.network_id(),
            reward_cycle: 9,
            lane: SignerLane::BlockProposal as i32,
            sequence: 0,
            previous_envelope_id: Vec::new(),
            signer_public_key: StacksPublicKey::from_private(&miner_key).to_bytes_compressed(),
            transport_peer_id: miner_peer.to_bytes(),
            payload: Vec::new(),
            burn_view_consensus_hash: vec![3; 20],
            proposal_manifest: Some(ProposalManifest {
                version: PROPOSAL_MANIFEST_VERSION,
                content_id: content_id.as_bytes().to_vec(),
                encoded_len: proposal_bytes.len() as u64,
                signer_signature_hash: proposal.block.header.signer_signature_hash().0.to_vec(),
                burn_height: proposal.burn_height,
                reward_cycle: proposal.reward_cycle,
            }),
        };
        let envelope = SignerEnvelope {
            signature: miner_key
                .sign(&signer_envelope_digest(&body))
                .unwrap()
                .as_bytes()
                .to_vec(),
            body: Some(body),
        };
        let expected_envelope_id = signer_envelope_id(&envelope).unwrap();
        miner_service
            .publish_proposal(
                NetworkObject {
                    kind: ObjectKind::BlockProposal,
                    content_id,
                    bytes: proposal_bytes.clone(),
                },
                envelope,
            )
            .unwrap();

        let tempdir = TempDir::new().unwrap();
        let database = tempdir.path().join("signer.sqlite");
        let runtime = Libp2pSignerNetwork {
            service: Some(signer_service),
            stacks_private_key: signer_key.clone(),
            signer_public_key: StacksPublicKey::from_private(&signer_key).to_bytes_compressed(),
            local_peer_id: signer_peer,
            rendezvous_peers: vec![miner_peer],
            chain_id: scope.chain_id(),
            network_id: scope.network_id(),
            rollout_mode: RolloutMode::Libp2pOnly,
            mainnet: false,
            current_cycle: 9,
            next_cycle: None,
            sequences: HashMap::new(),
            journal: VecDeque::new(),
            journal_db: SignerDb::new(&database).unwrap(),
            advertised_addresses: Vec::new(),
            compatibility_bridge: None,
            legacy_locators: HashMap::new(),
            legacy_ingress_locators: HashMap::new(),
            compatibility_events: VecDeque::new(),
            semantic_seen: HashSet::new(),
            semantic_order: VecDeque::new(),
            bridge_pipeline: LegacyWritePipeline::disabled(),
            pending_proposals: HashMap::new(),
            ready_proposals: VecDeque::new(),
        };
        let handle = SignerNetworkHandle::new(runtime).unwrap();
        #[cfg(feature = "monitoring_prom")]
        let admitted_before =
            crate::monitoring::actions::deferred_miner_authorizations_admitted_for_test();
        let pending_deadline = Instant::now() + Duration::from_secs(10);
        while handle
            .0
            .lock()
            .unwrap()
            .service
            .as_ref()
            .unwrap()
            .diagnostics()
            .deferred_miner_authorizations
            == 0
        {
            assert!(Instant::now() < pending_deadline);
            assert!(handle.try_next_event().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(handle.try_next_event().unwrap().is_none());
        #[cfg(feature = "monitoring_prom")]
        {
            let metrics_deadline = Instant::now() + Duration::from_secs(3);
            while crate::monitoring::actions::deferred_miner_authorizations_admitted_for_test()
                <= admitted_before
            {
                assert!(
                    Instant::now() < metrics_deadline,
                    "the independent sampler must export deferral admission while signer policy is idle"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        let miner_public_key = StacksPublicKey::from_private(&miner_key).to_bytes_compressed();
        handle
            .update_authorized_miners(
                9,
                vec![(
                    vec![3; 20],
                    stacks_common::util::hash::Hash160::from_data(&miner_public_key).0,
                )],
            )
            .unwrap();

        let release_deadline = Instant::now() + Duration::from_secs(10);
        let released = loop {
            if let Some(event) = handle.try_next_event().unwrap() {
                break event;
            }
            assert!(Instant::now() < release_deadline);
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(released.message.payload, proposal_bytes);
        assert_eq!(released.message.lane, SignerLane::BlockProposal);
        assert_eq!(
            released
                .native_envelope()
                .map(|envelope| signer_envelope_id(envelope).unwrap()),
            Some(expected_envelope_id),
            "normal signer processing must receive the exact held envelope"
        );
        let diagnostics = handle
            .0
            .lock()
            .unwrap()
            .service
            .as_ref()
            .unwrap()
            .diagnostics();
        assert_eq!(diagnostics.deferred_miner_authorizations_released, 1);
        assert_eq!(diagnostics.deferred_miner_authorizations_pending, 0);

        crate::v0::signer::assert_released_native_proposal_reaches_vote(
            released,
            handle.clone(),
            &proposal,
            &miner_key,
            &signer_key,
        );

        handle.shutdown().unwrap();
        miner_service.shutdown().unwrap();
    }

    #[test]
    fn legacy_only_runtime_uses_quarantined_bridge_without_a_swarm() {
        let tempdir = TempDir::new().unwrap();
        let database = tempdir.path().join("signer.sqlite");
        let private_key = StacksPrivateKey::from_seed(&[91; 32]);
        let public_key = StacksPublicKey::from_private(&private_key).to_bytes_compressed();
        let mut runtime = Libp2pSignerNetwork {
            service: None,
            stacks_private_key: private_key,
            signer_public_key: public_key,
            local_peer_id: libp2p::PeerId::random(),
            rendezvous_peers: Vec::new(),
            chain_id: 0x8000_0000,
            network_id: 0x8000_0000,
            rollout_mode: RolloutMode::Off,
            mainnet: false,
            current_cycle: 7,
            next_cycle: Some(8),
            sequences: HashMap::new(),
            journal: VecDeque::new(),
            journal_db: SignerDb::new(&database).unwrap(),
            advertised_addresses: Vec::new(),
            compatibility_bridge: Some(
                TemporarySignerBridge::new(
                    SignerBridgeConfig::default(),
                    BridgeJournal::open(&database).unwrap(),
                )
                .unwrap(),
            ),
            legacy_locators: HashMap::new(),
            legacy_ingress_locators: HashMap::new(),
            compatibility_events: VecDeque::new(),
            semantic_seen: HashSet::new(),
            semantic_order: VecDeque::new(),
            bridge_pipeline: LegacyWritePipeline::disabled(),
            pending_proposals: HashMap::new(),
            ready_proposals: VecDeque::new(),
        };
        runtime.configure_legacy_cycle(7, 2, false).unwrap();
        let message = SignerNetworkMessage {
            reward_cycle: 7,
            lane: SignerLane::BlockPreCommit,
            burn_view_consensus_hash: vec![3; 20],
            payload: SignerMessage::BlockPreCommit(Sha512Trunc256Sum([4; 32])).serialize_to_vec(),
        };

        let receipt = runtime.publish(message).unwrap();
        assert!(!receipt.native_queued);
        assert!(receipt.compatibility_queued);
        assert!(runtime.service.is_none());
        assert_eq!(
            runtime
                .compatibility_bridge
                .as_mut()
                .unwrap()
                .try_next_write()
                .unwrap()
                .locator
                .reward_cycle,
            7
        );
    }
}
