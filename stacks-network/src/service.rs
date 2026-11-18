use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use futures::StreamExt;
use libp2p::gossipsub::{MessageAcceptance, PublishError};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, Message};
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, ping, Multiaddr, PeerId, Swarm};
use prost::Message as ProstMessage;
use stacks_network_types::wire::v1::{
    sync_request, sync_response, Hello, LegacyIdentityBinding, Role, RoleDirectoryRecord,
    SignerEnvelope, SignerLane, SignerReplayPage, Status, SyncRequest, SyncResponse,
};
use stacks_network_types::{
    supports, Announcement, ContentId, NetworkObject, ObjectKind, RewardCycleWindow,
    CAP_OBJECT_FETCH,
};
use tokio::sync::{mpsc as tokio_mpsc, watch};

use crate::diagnostics::{DiagnosticsHandle, NetworkDiagnostics};
use crate::{
    announcement_envelope, block_announcement_topic, build_swarm, content_push_envelope,
    hello_response_envelope, signer_topic, transaction_topic, verify_legacy_identity_binding,
    AuthorizationSnapshot, BudgetRejection, ContentExchangeEvent, ContentPublication,
    DirectPushCandidate, DirectoryDirection, DiscoveryEvent, LegacyIdentityRegistry, NetworkConfig,
    NetworkHub, NetworkObjectValidator, ObjectAdmission, ObjectNetworkEvent, PeerStoreConfig,
    PeerStoreRuntime, ProviderFailure, ProviderOutcome, ProviderPool, PublicationOutcome,
    RoleAuthorization, RoleAuthorizations, RoleDirectoryBehaviourEvent, SignerAdmission,
    SignerBehaviourEvent, SignerBindingUpdate, SignerIngress, StacksApplicationBehaviour,
    StacksBehaviourEvent, SyncBehaviourEvent, SyncRequestOwner, TransportProfile,
};

const COMMAND_QUEUE_CAPACITY: usize = 512;
const COMMAND_CONFIRM_TIMEOUT: Duration = Duration::from_millis(250);
// Cross-thread channels are count-bounded by `std::sync::mpsc`. Their counts
// are deliberately derived from the protocol's maximum item size so each also
// has a conservative effective byte ceiling.
pub(crate) const SIGNER_EVENT_QUEUE_CAPACITY: usize = 16;
const OBJECT_EVENT_CHANNEL_CAPACITY: usize = 16;
const SYNC_EVENT_QUEUE_CAPACITY: usize = 8;
const DEFERRED_SYNC_CONTROL_CAPACITY: usize = 64;
const DEFERRED_SYNC_CONTROL_TTL: Duration = Duration::from_secs(2);

fn sync_capability_classes(capabilities: u64) -> (bool, bool) {
    let sync_capable = supports(capabilities, stacks_network_types::CAP_SYNC);
    let object_sync_capable = sync_capable && supports(capabilities, CAP_OBJECT_FETCH);
    (sync_capable, object_sync_capable)
}

fn signer_gossip_acceptance(admission: SignerAdmission) -> MessageAcceptance {
    match admission {
        SignerAdmission::Duplicate | SignerAdmission::Stale => MessageAcceptance::Ignore,
        SignerAdmission::FirstSeen
        | SignerAdmission::HigherSequence
        | SignerAdmission::Equivocation => MessageAcceptance::Accept,
    }
}

fn should_continue_signer_replay(page_complete: bool, delivery_deferred: bool) -> bool {
    !page_complete && !delivery_deferred
}

#[derive(Clone)]
pub struct ServiceConfig {
    pub identity: identity::Keypair,
    pub network: NetworkConfig,
    pub transport: TransportProfile,
    pub listen_addresses: Vec<Multiaddr>,
    pub bootstrap_addresses: Vec<Multiaddr>,
    /// Optional durable cache of exact endpoints that previously completed an
    /// outbound Noise + Stacks Hello handshake. Signer-only and ephemeral test
    /// swarms may omit it.
    pub peer_store: Option<PeerStoreConfig>,
    /// Statically configured private rendezvous peers. This does not
    /// grant miner-lane authority; miners require a sortition-bound role proof.
    pub private_rendezvous_peers: Vec<PeerId>,
    /// Chainstate-derived role grants available at startup. Dynamic signer and
    /// miner sets are replaced through the authorization update APIs.
    pub role_authorizations: Vec<RoleAuthorization>,
    /// A locally authored record presented only to rendezvous peers or already
    /// authenticated role peers. It is never included in public Hello/Identify.
    pub local_role_record: Option<RoleDirectoryRecord>,
    /// Previously verified current/next-cycle records restored after restart.
    pub initial_role_records: Vec<RoleDirectoryRecord>,
    /// Previously verified envelopes used to restore monotonic admission before
    /// the swarm processes any network input.
    pub initial_signer_envelopes: Vec<SignerEnvelope>,
    /// Domain validator and bounded content hub. Signer-only swarms may omit it.
    pub object_validator: Option<Arc<dyn NetworkObjectValidator>>,
    pub object_cache_bytes: usize,
    pub hello: Hello,
}

pub struct TransportBootstrap {
    pub identity: identity::Keypair,
    pub network: NetworkConfig,
    pub transport: TransportProfile,
    pub listen_addresses: Vec<Multiaddr>,
    pub bootstrap_addresses: Vec<Multiaddr>,
    pub peer_store: Option<PeerStoreConfig>,
}

#[derive(Default)]
pub struct AuthorizationBootstrap {
    pub private_rendezvous_peers: Vec<PeerId>,
    pub role_authorizations: Vec<RoleAuthorization>,
    pub local_role_record: Option<RoleDirectoryRecord>,
    pub initial_role_records: Vec<RoleDirectoryRecord>,
    pub initial_signer_envelopes: Vec<SignerEnvelope>,
}

pub struct ContentServices {
    pub validator: Option<Arc<dyn NetworkObjectValidator>>,
    pub cache_bytes: usize,
}

impl ServiceConfig {
    pub fn new(
        transport: TransportBootstrap,
        authorization: AuthorizationBootstrap,
        content: ContentServices,
        hello: Hello,
    ) -> Result<Self, String> {
        let config = Self {
            identity: transport.identity,
            network: transport.network,
            transport: transport.transport,
            listen_addresses: transport.listen_addresses,
            bootstrap_addresses: transport.bootstrap_addresses,
            peer_store: transport.peer_store,
            private_rendezvous_peers: authorization.private_rendezvous_peers,
            role_authorizations: authorization.role_authorizations,
            local_role_record: authorization.local_role_record,
            initial_role_records: authorization.initial_role_records,
            initial_signer_envelopes: authorization.initial_signer_envelopes,
            object_validator: content.validator,
            object_cache_bytes: content.cache_bytes,
            hello,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.network.validate()?;
        let scope = self.network.scope();
        if self.hello.chain_id != scope.chain_id() || self.hello.network_id != scope.network_id() {
            return Err("Hello and network configuration have different scopes".to_owned());
        }
        let mut required =
            stacks_network_types::CAP_SYNC | stacks_network_types::CAP_ROLE_DIRECTORY;
        if self.network.subscribe_signer_gossip {
            required |= stacks_network_types::CAP_SIGNER_SEMANTICS;
        }
        if self.network.subscribe_object_gossip {
            required |= CAP_OBJECT_FETCH
                | stacks_network_types::CAP_CONTENT_PUSH
                | stacks_network_types::CAP_TRANSACTION_GOSSIP;
            if self.object_validator.is_none() {
                return Err("object gossip profile requires a contextual validator".to_owned());
            }
        }
        if !supports(self.hello.capabilities, required) {
            return Err("Hello omits a capability required by the network profile".to_owned());
        }
        if self.object_cache_bytes == 0
            || self.object_cache_bytes > self.network.max_process_memory_bytes
        {
            return Err("object cache budget is zero or exceeds the process budget".to_owned());
        }
        if let Some(store) = &self.peer_store {
            if store.local_peer_id != self.identity.public().to_peer_id() || store.scope() != scope
            {
                return Err("peer store identity or scope differs from the swarm".to_owned());
            }
            store.policy.validate().map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

enum Command {
    Control(ControlCommand),
    Authorization(AuthorizationCommand),
    Signer(SignerCommand),
    Content(ContentCommand),
    Sync(SyncCommand),
}

enum ControlCommand {
    Dial(Multiaddr),
    Disconnect(PeerId),
    ReportProviderOutcome {
        peer: PeerId,
        outcome: ProviderOutcome,
    },
    UpdateChainView {
        burn_height: u64,
        current_reward_cycle: u64,
    },
    UpdateLegacyIdentityBinding(Option<LegacyIdentityBinding>),
}

enum AuthorizationCommand {
    UpdateAuthorizedSigners {
        reward_cycle: u64,
        public_keys: Vec<[u8; 33]>,
    },
    UpdateAuthorizedMiners {
        reward_cycle: u64,
        miners: Vec<(Vec<u8>, [u8; 20])>,
    },
    ApplyAuthorizationSnapshot {
        snapshot: AuthorizationSnapshot,
        completion: mpsc::SyncSender<Result<crate::AuthorizationSnapshotUpdate, String>>,
    },
    RetainSignerCycles {
        window: RewardCycleWindow,
    },
    SetLocalRoleRecord(Option<RoleDirectoryRecord>),
}

enum SignerCommand {
    PublishSigner(SignerEnvelope),
    PublishProposal {
        object: NetworkObject,
        envelope: SignerEnvelope,
    },
}

enum ContentCommand {
    Publish {
        object: NetworkObject,
        announcement: Option<Announcement>,
    },
    Commit(NetworkObject),
    Announce(Announcement),
    Reject(ContentId),
    Request {
        peer: PeerId,
        kind: ObjectKind,
        id: ContentId,
    },
    RespondObject {
        response_token: u64,
        object: Option<NetworkObject>,
    },
}

enum SyncCommand {
    RequestSync {
        peer: PeerId,
        request: SyncRequest,
    },
    RequestSyncProviders {
        correlation_id: u64,
        providers: Vec<PeerId>,
        request: SyncRequest,
        max_parallel: usize,
        hedge_delay: Duration,
    },
    RespondSync {
        response_token: u64,
        response: SyncResponse,
    },
}

macro_rules! command_from {
    ($domain:ident, $variant:ident) => {
        impl From<$domain> for Command {
            fn from(command: $domain) -> Self {
                Self::$variant(command)
            }
        }
    };
}

command_from!(ControlCommand, Control);
command_from!(AuthorizationCommand, Authorization);
command_from!(SignerCommand, Signer);
command_from!(ContentCommand, Content);
command_from!(SyncCommand, Sync);

struct QueuedCommand {
    command: Command,
    enqueued_at: Instant,
    queue_id: u64,
}

/// Exact queue-age accounting kept beside the bounded command channel. Tokio's
/// receiver exposes queue length but not the front item's admission instant.
/// Tracking those instants separately keeps a wedged queue's age increasing
/// even when the service loop is no longer completing commands.
#[derive(Default)]
struct CommandQueueTracker {
    next_id: AtomicU64,
    admitted: Mutex<BTreeMap<u64, Instant>>,
}

impl CommandQueueTracker {
    fn admit(&self, admitted_at: Instant) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.admitted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, admitted_at);
        id
    }

    fn complete(&self, id: u64) {
        self.admitted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&id);
    }

    fn oldest_wait(&self) -> Duration {
        self.admitted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .min()
            .map(Instant::elapsed)
            .unwrap_or_default()
    }
}

/// An authenticated signer event emitted after transport validation. Confirmed
/// events have passed canonical authorization and journal staging; pending
/// events are availability observations only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerCanonicalAuthorization {
    Confirmed,
    /// Authorship and observed transport identity are valid, but the local
    /// companion-derived snapshot cannot yet confirm the miner sortition.
    /// Consumers may record unavailability only; they must not fetch, admit,
    /// validate, relay, or vote on the proposal.
    Pending,
}

#[derive(Clone, Debug)]
pub struct SignerNetworkEvent {
    /// The authenticated libp2p source.
    pub source: PeerId,
    /// Connected peer that propagated or replayed the envelope and can serve
    /// any referenced content object.
    pub provider: PeerId,
    /// The validated semantic envelope.
    pub envelope: crate::VerifiedSignerEnvelope,
    /// The per-author journal decision. Pending canonical authorization has
    /// not entered the journal and always carries `FirstSeen` here.
    pub admission: SignerAdmission,
    pub canonical_authorization: SignerCanonicalAuthorization,
}

/// Typed synchronization work exchanged with the node-owned sync engine. The
/// swarm never touches chainstate or blocks while waiting for a response.
#[derive(Clone, Debug)]
pub enum SyncNetworkEvent {
    InboundRequest {
        source: PeerId,
        response_token: u64,
        request: SyncRequest,
    },
    Response {
        source: PeerId,
        correlation_id: Option<u64>,
        response: SyncResponse,
    },
    OutboundFailure {
        peer: PeerId,
        correlation_id: Option<u64>,
        error: String,
    },
}

pub struct NetworkService {
    handle: NetworkHandle,
    shutdown: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

struct EventReceiver<T> {
    receiver: Arc<Mutex<mpsc::Receiver<T>>>,
    queue_name: &'static str,
}

impl<T> EventReceiver<T> {
    fn new(receiver: mpsc::Receiver<T>, queue_name: &'static str) -> Self {
        Self {
            receiver: Arc::new(Mutex::new(receiver)),
            queue_name,
        }
    }

    fn try_next(&self) -> io::Result<Option<T>> {
        match self
            .receiver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .try_recv()
        {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("libp2p {} event queue disconnected", self.queue_name),
            )),
        }
    }

    fn recv_timeout(&self, timeout: Duration) -> io::Result<Option<T>> {
        match self
            .receiver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recv_timeout(timeout)
        {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("libp2p {} event queue disconnected", self.queue_name),
            )),
        }
    }
}

impl<T> Clone for EventReceiver<T> {
    fn clone(&self) -> Self {
        Self {
            receiver: Arc::clone(&self.receiver),
            queue_name: self.queue_name,
        }
    }
}

/// Cloneable command-side handle for producers outside the swarm owner thread.
#[derive(Clone)]
pub struct NetworkHandle {
    commands: tokio_mpsc::Sender<QueuedCommand>,
    command_queue: Arc<CommandQueueTracker>,
    diagnostics: DiagnosticsHandle,
    signer_events: EventReceiver<SignerNetworkEvent>,
    object_events: EventReceiver<ObjectNetworkEvent>,
    sync_events: EventReceiver<SyncNetworkEvent>,
    legacy_identities: Arc<Mutex<LegacyIdentityRegistry>>,
}

impl NetworkHandle {
    fn try_send(&self, command: impl Into<Command>) -> io::Result<()> {
        let permit = self.commands.try_reserve().map_err(|error| match error {
            tokio_mpsc::error::TrySendError::Full(()) => {
                self.diagnostics
                    .with_state(|state| state.resources.command_queue_full += 1);
                io::Error::new(io::ErrorKind::WouldBlock, "libp2p command queue is full")
            }
            tokio_mpsc::error::TrySendError::Closed(()) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "libp2p service stopped")
            }
        })?;
        let enqueued_at = Instant::now();
        let queue_id = self.command_queue.admit(enqueued_at);
        permit.send(QueuedCommand {
            command: command.into(),
            enqueued_at,
            queue_id,
        });
        Ok(())
    }

    /// Dial a validated multiaddress without exposing swarm ownership.
    pub fn dial(&self, address: Multiaddr) -> io::Result<()> {
        self.try_send(ControlCommand::Dial(address))
    }

    /// Close every connection to a peer. Discovery may reconnect it later.
    pub fn disconnect(&self, peer: PeerId) -> io::Result<()> {
        self.try_send(ControlCommand::Disconnect(peer))
    }

    pub fn report_provider_outcome(
        &self,
        peer: PeerId,
        outcome: ProviderOutcome,
    ) -> io::Result<()> {
        self.try_send(ControlCommand::ReportProviderOutcome { peer, outcome })
    }

    /// Refresh the small chain view used for proof expiry and peer diagnostics.
    pub fn update_chain_view(&self, burn_height: u64, current_reward_cycle: u64) -> io::Result<()> {
        self.try_send(ControlCommand::UpdateChainView {
            burn_height,
            current_reward_cycle,
        })
    }

    pub fn update_legacy_identity_binding(
        &self,
        binding: Option<LegacyIdentityBinding>,
    ) -> io::Result<()> {
        self.try_send(ControlCommand::UpdateLegacyIdentityBinding(binding))
    }

    /// Queue a signed semantic signer/miner envelope.
    pub fn publish_signer(&self, envelope: SignerEnvelope) -> io::Result<()> {
        self.try_send(SignerCommand::PublishSigner(envelope))
    }

    /// Atomically retain canonical proposal bytes before advertising their
    /// signed manifest. A cache-admission failure leaves no unfetchable manifest.
    pub fn publish_proposal(
        &self,
        object: NetworkObject,
        envelope: SignerEnvelope,
    ) -> io::Result<()> {
        self.try_send(SignerCommand::PublishProposal { object, envelope })
    }

    pub fn publish_object(&self, object: NetworkObject) -> io::Result<()> {
        self.try_send(ContentCommand::Publish {
            object,
            announcement: None,
        })
    }

    /// Commit contextual validation without scheduling any native publication.
    /// Receive-only rollout uses this to make a fetched reservation durable
    /// while keeping libp2p egress disabled.
    pub fn commit_object(&self, object: NetworkObject) -> io::Result<()> {
        self.try_send(ContentCommand::Commit(object))
    }

    pub fn announce_object(&self, announcement: Announcement) -> io::Result<()> {
        self.try_send(ContentCommand::Announce(announcement))
    }

    /// Atomically enqueue a locally accepted block and its availability
    /// announcement. This prevents command-queue pressure from admitting the
    /// object without ever announcing it.
    pub fn publish_block(
        &self,
        object: NetworkObject,
        announcement: Announcement,
    ) -> io::Result<()> {
        self.try_send(ContentCommand::Publish {
            object,
            announcement: Some(announcement),
        })
    }

    /// Release a remote object's validation reservation after chainstate or
    /// mempool rejects it. Rejected bytes were never made fetchable.
    pub fn reject_object(&self, content_id: ContentId) -> io::Result<()> {
        self.try_send(ContentCommand::Reject(content_id))
    }

    /// Fetch a known inventory object from one authenticated, capable peer.
    /// The response still passes through the same two-phase validation hub as
    /// announcement-driven fetches.
    pub fn request_object(&self, peer: PeerId, kind: ObjectKind, id: ContentId) -> io::Result<()> {
        self.try_send(ContentCommand::Request { peer, kind, id })
    }

    /// Complete a durable-storage lookup initiated by an inbound content
    /// request. `None` produces a typed NotFound response.
    pub fn respond_object(
        &self,
        response_token: u64,
        object: Option<NetworkObject>,
    ) -> io::Result<()> {
        self.try_send(ContentCommand::RespondObject {
            response_token,
            object,
        })
    }

    pub fn request_sync(&self, peer: PeerId, request: SyncRequest) -> io::Result<()> {
        self.try_send(SyncCommand::RequestSync { peer, request })
    }

    pub fn request_sync_from(
        &self,
        correlation_id: u64,
        providers: Vec<PeerId>,
        request: SyncRequest,
        max_parallel: usize,
        hedge_delay: Duration,
    ) -> io::Result<()> {
        self.try_send(SyncCommand::RequestSyncProviders {
            correlation_id,
            providers,
            request,
            max_parallel,
            hedge_delay,
        })
    }

    pub fn respond_sync(&self, response_token: u64, response: SyncResponse) -> io::Result<()> {
        self.try_send(SyncCommand::RespondSync {
            response_token,
            response,
        })
    }

    /// Replace the chainstate-authorized signer keys for one reward cycle.
    pub fn update_authorized_signers(
        &self,
        reward_cycle: u64,
        public_keys: Vec<[u8; 33]>,
    ) -> io::Result<()> {
        self.try_send(AuthorizationCommand::UpdateAuthorizedSigners {
            reward_cycle,
            public_keys,
        })
    }

    /// Replace the canonical sortition-bound miners for one reward cycle.
    /// Each entry binds the sortition consensus hash to the winning key hash.
    pub fn update_authorized_miners(
        &self,
        reward_cycle: u64,
        miners: Vec<(Vec<u8>, [u8; 20])>,
    ) -> io::Result<()> {
        self.try_send(AuthorizationCommand::UpdateAuthorizedMiners {
            reward_cycle,
            miners,
        })
    }

    /// Atomically publish one authoritative, versioned current/next-cycle
    /// authorization snapshot to the signer and private-directory domains.
    /// The returned update acknowledges the generation actually applied.
    pub fn apply_authorization_snapshot(
        &self,
        snapshot: AuthorizationSnapshot,
    ) -> io::Result<crate::AuthorizationSnapshotUpdate> {
        let (completion, completed) = mpsc::sync_channel(1);
        self.try_send(AuthorizationCommand::ApplyAuthorizationSnapshot {
            snapshot,
            completion,
        })?;
        match completed.recv_timeout(COMMAND_CONFIRM_TIMEOUT) {
            Ok(Ok(update)) => Ok(update),
            Ok(Err(error)) => Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out awaiting authorization snapshot acknowledgement",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "network service stopped before acknowledging authorization snapshot",
            )),
        }
    }

    /// Drop authorization state outside the current/next overlap.
    pub fn retain_signer_cycles(&self, current: u64, next: Option<u64>) -> io::Result<()> {
        let window = RewardCycleWindow::new(current, next)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.try_send(AuthorizationCommand::RetainSignerCycles { window })
    }

    /// Install or withdraw the current cycle-scoped private role record.
    pub fn set_local_role_record(&self, record: Option<RoleDirectoryRecord>) -> io::Result<()> {
        self.try_send(AuthorizationCommand::SetLocalRoleRecord(record))
    }

    /// Return the live local transport identity.
    pub fn local_peer_id(&self) -> io::Result<PeerId> {
        self.diagnostics()
            .local_peer_id
            .parse()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Snapshot bounded service diagnostics.
    pub fn diagnostics(&self) -> NetworkDiagnostics {
        let mut snapshot = self.diagnostics.snapshot();
        snapshot.oldest_command_queue_wait_ms = self
            .command_queue
            .oldest_wait()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        snapshot
    }

    /// Reconcile the exact identities proven by live incumbent connections and
    /// return the subset independently bound to native peers. The returned keys
    /// are suitable only for suppressing optional duplicate incumbent
    /// delivery; they do not grant authorization on either transport.
    pub fn reconcile_legacy_connections(
        &self,
        connections: Vec<([u8; 33], u64)>,
        burn_height: u64,
    ) -> Vec<[u8; 33]> {
        let mut identities = self
            .legacy_identities
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        identities.reconcile_legacy_connections(connections);
        identities
            .coalesced_legacy_public_keys(burn_height)
            .collect()
    }

    pub fn try_next_signer_event(&self) -> io::Result<Option<SignerNetworkEvent>> {
        self.signer_events.try_next()
    }

    /// Wait for one authenticated signer event without polling or owning the
    /// swarm thread. Exactly one coordinator-side consumer should use this
    /// method; cloned handles share the same bounded receiver.
    pub fn recv_signer_event_timeout(
        &self,
        timeout: Duration,
    ) -> io::Result<Option<SignerNetworkEvent>> {
        self.signer_events.recv_timeout(timeout)
    }

    /// Attribute backpressure in a node-owned signer event router to the same
    /// bounded event-queue diagnostic used by the service handoff.
    pub fn record_signer_event_queue_full(&self) {
        self.diagnostics
            .with_state(|state| state.resources.event_queue_full += 1);
    }

    pub fn try_next_object_event(&self) -> io::Result<Option<ObjectNetworkEvent>> {
        self.object_events.try_next()
    }

    pub fn try_next_sync_event(&self) -> io::Result<Option<SyncNetworkEvent>> {
        self.sync_events.try_next()
    }
}

impl NetworkService {
    pub fn spawn(config: ServiceConfig, thread_name: impl Into<String>) -> io::Result<Self> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let diagnostics = DiagnosticsHandle::new(config.identity.public().to_peer_id());
        let diagnostics_for_thread = diagnostics.clone();
        let legacy_identities = Arc::new(Mutex::new(LegacyIdentityRegistry::default()));
        let legacy_identities_for_thread = Arc::clone(&legacy_identities);
        let command_queue = Arc::new(CommandQueueTracker::default());
        let command_queue_for_thread = Arc::clone(&command_queue);
        // Control admission is bounded independently from per-protocol queues so a
        // stalled swarm can never turn callers into an unbounded memory buffer.
        let (commands_tx, commands_rx) = tokio_mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (signer_events_tx, signer_events_rx) = mpsc::sync_channel(SIGNER_EVENT_QUEUE_CAPACITY);
        let signer_events_rx = EventReceiver::new(signer_events_rx, "signer");
        let (object_events_tx, object_events_rx) =
            mpsc::sync_channel(OBJECT_EVENT_CHANNEL_CAPACITY);
        let object_events_rx = EventReceiver::new(object_events_rx, "object");
        let (sync_events_tx, sync_events_rx) = mpsc::sync_channel(SYNC_EVENT_QUEUE_CAPACITY);
        let sync_events_rx = EventReceiver::new(sync_events_rx, "sync");
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = startup_tx.send(Err(io::Error::other(error.to_string())));
                        return;
                    }
                };
                runtime.block_on(run_service(
                    config,
                    ServiceRuntime {
                        commands: commands_rx,
                        command_queue: command_queue_for_thread,
                        shutdown: shutdown_rx,
                        signer_events: signer_events_tx,
                        object_events: object_events_tx,
                        sync_events: sync_events_tx,
                        diagnostics: diagnostics_for_thread,
                        legacy_identities: legacy_identities_for_thread,
                        startup: startup_tx,
                    },
                ));
            })?;

        match startup_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => Ok(Self {
                handle: NetworkHandle {
                    commands: commands_tx,
                    command_queue,
                    diagnostics,
                    signer_events: signer_events_rx,
                    object_events: object_events_rx,
                    sync_events: sync_events_rx,
                    legacy_identities,
                },
                shutdown: shutdown_tx,
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(error) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("libp2p service startup did not report readiness: {error}"),
            )),
        }
    }

    /// Obtain a cloneable producer handle without sharing event-consumer ownership.
    pub fn handle(&self) -> NetworkHandle {
        self.handle.clone()
    }

    pub fn shutdown(mut self) -> thread::Result<()> {
        let _ = self.shutdown.send(true);
        self.thread.take().map_or(Ok(()), |thread| thread.join())
    }
}

impl Deref for NetworkService {
    type Target = NetworkHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl Drop for NetworkService {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

struct ServiceRuntime {
    commands: tokio_mpsc::Receiver<QueuedCommand>,
    command_queue: Arc<CommandQueueTracker>,
    shutdown: watch::Receiver<bool>,
    signer_events: mpsc::SyncSender<SignerNetworkEvent>,
    object_events: mpsc::SyncSender<ObjectNetworkEvent>,
    sync_events: mpsc::SyncSender<SyncNetworkEvent>,
    diagnostics: DiagnosticsHandle,
    legacy_identities: Arc<Mutex<LegacyIdentityRegistry>>,
    startup: mpsc::SyncSender<io::Result<()>>,
}

fn delayed_interval(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

/// Persistent service deadlines. Keeping all timers in one state object makes
/// it impossible to accidentally recreate a `Sleep` on every `select!`
/// iteration and starve a drain under continuous swarm activity.
struct ServiceTimers {
    maintenance: tokio::time::Interval,
    event_loop_heartbeat: tokio::time::Interval,
    object_event_drain: tokio::time::Interval,
    sync_control_drain: tokio::time::Interval,
}

struct AuthorizationRuntime {
    hello: Hello,
    retained_cycles: RewardCycleWindow,
    role_authorizations: RoleAuthorizations,
    generation: u64,
    legacy_identities: Arc<Mutex<LegacyIdentityRegistry>>,
}

struct ObjectRuntime {
    hub: Option<NetworkHub>,
    providers: ProviderPool,
}

struct DownstreamRuntime {
    signer: mpsc::SyncSender<SignerNetworkEvent>,
    object: mpsc::SyncSender<ObjectNetworkEvent>,
    sync: mpsc::SyncSender<SyncNetworkEvent>,
}

struct DeferredSyncControlRequest {
    source: PeerId,
    response_token: u64,
    request: SyncRequest,
    enqueued_at: Instant,
}

#[derive(Default)]
struct DeferredSyncControlQueue {
    requests: VecDeque<DeferredSyncControlRequest>,
    peers: HashSet<PeerId>,
}

impl DeferredSyncControlQueue {
    fn admit(&mut self, event: SyncNetworkEvent, now: Instant) -> Result<(), ()> {
        let SyncNetworkEvent::InboundRequest {
            source,
            response_token,
            request,
        } = event
        else {
            return Err(());
        };
        if !is_deferable_sync_control(&request)
            || self.requests.len() >= DEFERRED_SYNC_CONTROL_CAPACITY
            || !self.peers.insert(source)
        {
            return Err(());
        }
        self.requests.push_back(DeferredSyncControlRequest {
            source,
            response_token,
            request,
            enqueued_at: now,
        });
        Ok(())
    }

    fn pop_front(&mut self) -> Option<DeferredSyncControlRequest> {
        let request = self.requests.pop_front()?;
        self.peers.remove(&request.source);
        Some(request)
    }

    fn push_front(&mut self, request: DeferredSyncControlRequest) {
        debug_assert!(self.peers.insert(request.source));
        self.requests.push_front(request);
    }

    fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }
}

/// Metadata-only requests that advance the historical sync plan. These have
/// already passed the protocol's strict count/cursor/byte validation. Bulk
/// objects and signer replay remain on
/// their dedicated bounded paths and can never consume this queue.
fn is_deferable_sync_control(request: &SyncRequest) -> bool {
    matches!(
        request.request,
        Some(
            sync_request::Request::GetStatus(_)
                | sync_request::Request::GetPoxInventory(_)
                | sync_request::Request::GetTenureInventory(_)
                | sync_request::Request::GetEpoch2Inventory(_)
                | sync_request::Request::GetMempoolPage(_)
                | sync_request::Request::GetAttachmentInventory(_)
        )
    )
}

impl DownstreamRuntime {
    fn queue_object_event(
        &self,
        application: &mut StacksApplicationBehaviour,
        event: ObjectNetworkEvent,
        diagnostics: &DiagnosticsHandle,
    ) -> bool {
        match self.object.try_send(event) {
            Ok(()) => true,
            Err(mpsc::TrySendError::Full(event)) => {
                if application.stage_content_event(event).is_ok() {
                    diagnostics.with_state(|state| state.resources.event_queue_full += 1);
                    return true;
                }
                diagnostics.with_state(|state| {
                    state.resources.event_queue_full += 1;
                    state.content.object_fetch_failures += 1;
                });
                false
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                diagnostics.record_error("semantic event queue disconnected".to_owned());
                false
            }
        }
    }
}

struct ServiceDriver {
    config: ServiceConfig,
    swarm: Swarm<crate::StacksBehaviour>,
    commands: tokio_mpsc::Receiver<QueuedCommand>,
    command_queue: Arc<CommandQueueTracker>,
    shutdown: watch::Receiver<bool>,
    downstream: DownstreamRuntime,
    deferred_sync_control: DeferredSyncControlQueue,
    diagnostics: DiagnosticsHandle,
    peer_store: Option<PeerStoreRuntime>,
    private_rendezvous_peers: HashSet<PeerId>,
    authorization: AuthorizationRuntime,
    objects: ObjectRuntime,
    timers: ServiceTimers,
    last_event_loop_heartbeat: Instant,
}

impl ServiceTimers {
    fn new() -> Self {
        Self {
            maintenance: delayed_interval(Duration::from_secs(5)),
            event_loop_heartbeat: delayed_interval(Duration::from_secs(1)),
            object_event_drain: delayed_interval(Duration::from_millis(25)),
            sync_control_drain: delayed_interval(Duration::from_millis(10)),
        }
    }
}

async fn run_service(config: ServiceConfig, runtime: ServiceRuntime) {
    let ServiceRuntime {
        commands,
        command_queue,
        shutdown,
        signer_events,
        object_events,
        sync_events,
        diagnostics,
        legacy_identities,
        startup,
    } = runtime;
    let mut swarm = match build_swarm(&config.identity, &config.network, config.transport) {
        Ok(swarm) => swarm,
        Err(error) => {
            let _ = startup.send(Err(error));
            return;
        }
    };
    let private_rendezvous_peers: HashSet<PeerId> =
        config.private_rendezvous_peers.iter().copied().collect();
    if let Err(error) = swarm
        .behaviour_mut()
        .reserve_connection_capacity_for(private_rendezvous_peers.iter().copied())
    {
        let _ = startup.send(Err(io::Error::new(io::ErrorKind::InvalidInput, error)));
        return;
    }
    for address in &config.listen_addresses {
        if let Err(error) = swarm.listen_on(address.clone()) {
            let _ = startup.send(Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                error.to_string(),
            )));
            return;
        }
    }
    let mut provider_pool = ProviderPool::new();
    for address in &config.bootstrap_addresses {
        match swarm.behaviour_mut().add_bootstrap_address(address.clone()) {
            Ok(peer) => provider_pool.pin(peer),
            Err(error) => {
                diagnostics.record_error(format!("reject bootstrap address {address}: {error}"))
            }
        }
    }
    let mut peer_store: Option<PeerStoreRuntime> = None;
    if let Some(store_config) = config.peer_store.clone() {
        let expected_peer = config.identity.public().to_peer_id();
        if store_config.local_peer_id != expected_peer
            || store_config.scope() != config.network.scope()
        {
            diagnostics.record_error(
                "disabled libp2p peer store with identity or network scope inconsistent with swarm"
                    .to_owned(),
            );
        } else {
            match PeerStoreRuntime::start(store_config, unix_time_secs()) {
                Ok(startup_state) => {
                    if let Some(path) = startup_state.recovered_corruption.as_ref() {
                        tracing::warn!(
                            target: "stacks_network",
                            path = %path.display(),
                            "preserved corrupt libp2p peer cache and started with an empty store"
                        );
                        diagnostics.record_event(
                            "peer-store-corruption-recovered",
                            format!("preserved={}", path.display()),
                        );
                    }
                    for candidate in &startup_state.candidates {
                        if let Err(error) = swarm
                            .behaviour_mut()
                            .restore_peer_address(candidate.peer_id, candidate.address.clone())
                        {
                            diagnostics.record_error(format!(
                                "reject restored libp2p peer endpoint peer={}: {error}",
                                candidate.peer_id
                            ));
                        }
                    }
                    let snapshot = startup_state.runtime.snapshot();
                    diagnostics.enable_peer_store(snapshot);
                    diagnostics.record_event(
                        "peer-store-restored",
                        format!(
                            "peers={} addresses={} candidates={} startup_dials={}",
                            snapshot.peers,
                            snapshot.addresses,
                            startup_state.candidates.len(),
                            startup_state.candidates.len()
                        ),
                    );
                    peer_store = Some(startup_state.runtime);
                }
                Err(error) => diagnostics
                    .record_error(format!("disabled unavailable libp2p peer store: {error}")),
            }
        }
    }
    let hello = config.hello.clone();
    let initial_next_cycle = config
        .role_authorizations
        .iter()
        .any(|authorization| {
            authorization.reward_cycle == hello.current_reward_cycle.saturating_add(1)
        })
        .then(|| hello.current_reward_cycle.saturating_add(1));
    let retained_cycles =
        match RewardCycleWindow::new(hello.current_reward_cycle, initial_next_cycle) {
            Ok(window) => window,
            Err(error) => {
                let _ = startup.send(Err(io::Error::new(io::ErrorKind::InvalidInput, error)));
                return;
            }
        };
    let role_authorizations = RoleAuthorizations::new(config.role_authorizations.clone());
    let authorization_generation = 0_u64;
    let hub = config
        .object_validator
        .clone()
        .map(|validator| NetworkHub::new(validator, config.object_cache_bytes));
    {
        let application = swarm.behaviour_mut().application_mut();
        application
            .role_directory_mut()
            .set_rendezvous_peers(private_rendezvous_peers.iter().copied());
        application
            .role_directory_mut()
            .update_burn_height(hello.burn_tip_height);
        application
            .signer_mut()
            .set_rendezvous_peers(private_rendezvous_peers.iter().copied());
        match AuthorizationSnapshot::new(
            authorization_generation,
            retained_cycles.current(),
            retained_cycles.next(),
            role_authorizations.entries().iter().cloned(),
        ) {
            Ok(snapshot) => {
                if let Err(error) = application.apply_authorization_snapshot(snapshot) {
                    diagnostics
                        .record_error(format!("reject initial authorization snapshot: {error}"));
                }
            }
            Err(error) => diagnostics.record_error(format!(
                "construct initial signer authorization snapshot: {error}"
            )),
        }
        for error in application
            .role_directory_mut()
            .restore_records(config.initial_role_records.clone())
        {
            diagnostics.record_error(format!("reject persisted role-directory record: {error}"));
        }
        if let Err(error) = application
            .role_directory_mut()
            .set_local_record(config.local_role_record.clone())
        {
            diagnostics.record_error(format!("reject local role-directory record: {error}"));
        }
        for envelope in &config.initial_signer_envelopes {
            if let Err(error) = application.signer_mut().restore_envelope(envelope) {
                diagnostics.record_error(format!("reject persisted signer envelope: {error}"));
            }
        }
    }
    let mut driver = ServiceDriver {
        config,
        swarm,
        commands,
        command_queue,
        shutdown,
        downstream: DownstreamRuntime {
            signer: signer_events,
            object: object_events,
            sync: sync_events,
        },
        deferred_sync_control: DeferredSyncControlQueue::default(),
        diagnostics,
        peer_store,
        private_rendezvous_peers,
        authorization: AuthorizationRuntime {
            hello,
            retained_cycles,
            role_authorizations,
            generation: authorization_generation,
            legacy_identities,
        },
        objects: ObjectRuntime {
            hub,
            providers: provider_pool,
        },
        timers: ServiceTimers::new(),
        last_event_loop_heartbeat: Instant::now(),
    };
    driver.diagnostics.with_state(|state| {
        state.discovery.kademlia_server = driver.swarm.behaviour().kademlia_server()
    });
    let _ = startup.send(Ok(()));
    driver.run().await;
}

impl ServiceDriver {
    fn handle_command(&mut self, command: Option<QueuedCommand>) -> bool {
        let hub = &mut self.objects.hub;
        let provider_pool = &mut self.objects.providers;
        let command = command.map(|queued| {
            let residence_ms = queued
                .enqueued_at
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            self.diagnostics.with_state(|state| {
                state.event_loop.last_command_queue_residence_ms = residence_ms;
                state.event_loop.max_command_queue_residence_ms = state
                    .event_loop
                    .max_command_queue_residence_ms
                    .max(residence_ms);
            });
            self.command_queue.complete(queued.queue_id);
            queued.command
        });
        match command {
            Some(Command::Control(ControlCommand::Dial(address))) => {
                if let Err(error) = self.swarm.dial(address.clone()) {
                    self.diagnostics
                        .record_error(format!("dial {address}: {error}"));
                }
            }
            Some(Command::Control(ControlCommand::Disconnect(peer))) => {
                if let Err(error) = self.swarm.disconnect_peer_id(peer) {
                    self.diagnostics
                        .record_error(format!("disconnect {peer}: {error:?}"));
                }
            }
            Some(Command::Control(ControlCommand::ReportProviderOutcome { peer, outcome })) => {
                provider_pool.observe(peer, outcome, Instant::now());
            }
            Some(Command::Control(ControlCommand::UpdateChainView {
                burn_height,
                current_reward_cycle,
            })) => {
                self.authorization.hello.burn_tip_height = burn_height;
                self.authorization.hello.current_reward_cycle = current_reward_cycle;
                self.swarm
                    .behaviour_mut()
                    .application_mut()
                    .role_directory_mut()
                    .update_burn_height(burn_height);
                self.authorization
                    .legacy_identities
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .expire(burn_height);
            }
            Some(Command::Control(ControlCommand::UpdateLegacyIdentityBinding(binding))) => {
                self.authorization.hello.legacy_identity_binding = binding;
            }
            Some(Command::Authorization(AuthorizationCommand::UpdateAuthorizedSigners {
                reward_cycle,
                public_keys,
            })) => {
                let replacement = public_keys
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>();
                if self
                    .swarm
                    .behaviour()
                    .application()
                    .signer()
                    .authorization_state()
                    .authorized_keys(reward_cycle)
                    != replacement
                {
                    self.authorization
                        .role_authorizations
                        .replace_signers(reward_cycle, public_keys);
                    self.authorization.generation = self.authorization.generation.wrapping_add(1);
                    match AuthorizationSnapshot::new(
                        self.authorization.generation,
                        self.authorization.retained_cycles.current(),
                        self.authorization.retained_cycles.next(),
                        self.authorization
                            .role_authorizations
                            .entries()
                            .iter()
                            .cloned(),
                    ) {
                        Ok(snapshot) => {
                            if let Err(error) = self
                                .swarm
                                .behaviour_mut()
                                .application_mut()
                                .apply_authorization_snapshot(snapshot)
                            {
                                self.diagnostics.record_error(format!(
                                    "reject authorization snapshot: {error}"
                                ));
                            }
                        }
                        Err(error) => self.diagnostics.record_error(format!(
                            "construct role authorization snapshot: {error}"
                        )),
                    }
                }
            }
            Some(Command::Authorization(AuthorizationCommand::UpdateAuthorizedMiners {
                reward_cycle,
                miners,
            })) => {
                self.authorization
                    .role_authorizations
                    .replace_miners(reward_cycle, miners);
                self.authorization.generation = self.authorization.generation.wrapping_add(1);
                match AuthorizationSnapshot::new(
                    self.authorization.generation,
                    self.authorization.retained_cycles.current(),
                    self.authorization.retained_cycles.next(),
                    self.authorization
                        .role_authorizations
                        .entries()
                        .iter()
                        .cloned(),
                ) {
                    Ok(snapshot) => {
                        if let Err(error) = self
                            .swarm
                            .behaviour_mut()
                            .application_mut()
                            .apply_authorization_snapshot(snapshot)
                        {
                            self.diagnostics.record_error(format!(
                                "reject miner authorization snapshot: {error}"
                            ));
                        }
                    }
                    Err(error) => self
                        .diagnostics
                        .record_error(format!("construct miner authorization snapshot: {error}")),
                }
            }
            Some(Command::Authorization(AuthorizationCommand::ApplyAuthorizationSnapshot {
                snapshot,
                completion,
            })) => {
                let snapshot_metadata = (
                    snapshot.generation(),
                    snapshot.reward_cycle_window(),
                    snapshot.entries().to_vec(),
                );
                let result = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .apply_authorization_snapshot(snapshot)
                    .map_err(|error| error.to_string());
                match &result {
                    Ok(crate::AuthorizationSnapshotUpdate::Stale { .. }) => {}
                    Ok(_) => {
                        self.authorization.generation = snapshot_metadata.0;
                        self.authorization.retained_cycles = snapshot_metadata.1;
                        self.authorization.role_authorizations =
                            RoleAuthorizations::new(snapshot_metadata.2);
                        self.swarm
                            .behaviour_mut()
                            .application_mut()
                            .signer_mut()
                            .retain_cycles(
                                self.authorization.retained_cycles.current(),
                                self.authorization.retained_cycles.next(),
                            );
                    }
                    Err(error) => self.diagnostics.record_error(format!(
                        "reject authoritative authorization snapshot: {error}"
                    )),
                }
                let _ = completion.send(result);
            }
            Some(Command::Authorization(AuthorizationCommand::RetainSignerCycles { window })) => {
                self.authorization.retained_cycles = window;
                self.authorization
                    .role_authorizations
                    .retain_cycles(window.current(), window.next());
                self.swarm
                    .behaviour_mut()
                    .application_mut()
                    .signer_mut()
                    .retain_cycles(window.current(), window.next());
                self.authorization.generation = self.authorization.generation.wrapping_add(1);
                match AuthorizationSnapshot::new(
                    self.authorization.generation,
                    window.current(),
                    window.next(),
                    self.authorization
                        .role_authorizations
                        .entries()
                        .iter()
                        .cloned(),
                ) {
                    Ok(snapshot) => {
                        if let Err(error) = self
                            .swarm
                            .behaviour_mut()
                            .application_mut()
                            .apply_authorization_snapshot(snapshot)
                        {
                            self.diagnostics.record_error(format!(
                                "reject retained authorization snapshot: {error}"
                            ));
                        }
                    }
                    Err(error) => self.diagnostics.record_error(format!(
                        "construct retained role authorization snapshot: {error}"
                    )),
                }
            }
            Some(Command::Authorization(AuthorizationCommand::SetLocalRoleRecord(record))) => {
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .role_directory_mut()
                    .set_local_record(record)
                {
                    self.diagnostics
                        .record_error(format!("reject local role-directory record: {error}"));
                }
            }
            Some(Command::Signer(SignerCommand::PublishSigner(envelope))) => {
                let local_peer = *self.swarm.local_peer_id();
                match self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .signer_mut()
                    .queue_publication(local_peer, envelope)
                {
                    Ok(SignerAdmission::Duplicate | SignerAdmission::Stale) => {
                        tracing::debug!(target: "stacks_network", "skipped redundant local signer publication");
                    }
                    Ok(_) => {}
                    Err(error) => self
                        .diagnostics
                        .record_error(format!("reject local signer publication: {error}")),
                }
            }
            Some(Command::Signer(SignerCommand::PublishProposal { object, envelope })) => {
                let Some(hub) = hub.as_mut() else {
                    self.diagnostics
                        .record_error("proposal object hub is disabled".to_owned());
                    return true;
                };
                if object.kind != ObjectKind::BlockProposal {
                    self.diagnostics
                        .record_error("proposal publication used the wrong object kind".to_owned());
                    return true;
                }
                if let Err(error) = hub.admit_object(object) {
                    self.diagnostics
                        .record_error(format!("reject local proposal object: {error}"));
                    return true;
                }
                let local_peer = *self.swarm.local_peer_id();
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .signer_mut()
                    .queue_publication(local_peer, envelope)
                {
                    self.diagnostics
                        .record_error(format!("reject local proposal manifest: {error}"));
                }
            }
            Some(Command::Content(ContentCommand::Publish {
                object,
                announcement,
            })) => {
                let Some(hub) = hub.as_mut() else {
                    self.diagnostics
                        .record_error("object hub is disabled".to_owned());
                    return true;
                };
                if let Some(candidate) = announcement.as_ref() {
                    if candidate.kind != object.kind || candidate.content_id != object.content_id {
                        self.diagnostics.record_error(
                            "block announcement does not identify its object".to_owned(),
                        );
                        return true;
                    }
                    if let Err(error) = hub.validate_announcement(candidate) {
                        self.diagnostics
                            .record_error(format!("reject local announcement: {error}"));
                        return true;
                    }
                }
                match hub.admit_object(object.clone()) {
                    Ok(admission) => {
                        if admission == ObjectAdmission::New
                            && object.kind == ObjectKind::Transaction
                            && object.bytes.len() <= self.config.network.small_transaction_bytes
                        {
                            let publication_bytes =
                                content_push_envelope(self.config.network.chain_id, &object)
                                    .encoded_len();
                            if let Err(error) = self
                                .swarm
                                .behaviour_mut()
                                .application_mut()
                                .queue_content_transaction(object.clone(), publication_bytes)
                            {
                                self.diagnostics.record_error(error);
                            }
                        }
                        if admission == ObjectAdmission::New
                            && object.kind == ObjectKind::NakamotoBlock
                        {
                            let candidates = self
                                .swarm
                                .behaviour()
                                .admission
                                .connected_peers()
                                .filter(|peer| {
                                    self.swarm
                                        .behaviour()
                                        .application()
                                        .is_peer_authenticated(peer)
                                })
                                .map(|peer| DirectPushCandidate {
                                    peer,
                                    outbound: self
                                        .swarm
                                        .behaviour()
                                        .admission
                                        .has_outbound_connection(&peer),
                                    gossip_score: self
                                        .swarm
                                        .behaviour()
                                        .application()
                                        .peer_score(&peer)
                                        .unwrap_or(0.0),
                                    rtt: provider_pool.latency(&peer),
                                    failure_domain: self
                                        .swarm
                                        .behaviour()
                                        .admission
                                        .primary_prefix(&peer)
                                        .map(|prefix| prefix.diversity_key()),
                                })
                                .collect::<Vec<_>>();
                            let targets = self
                                .swarm
                                .behaviour()
                                .application()
                                .select_direct_push_targets(
                                    candidates,
                                    self.config.network.direct_push_fanout,
                                );
                            for peer in targets {
                                match self
                                    .swarm
                                    .behaviour_mut()
                                    .application_mut()
                                    .send_content_push(&peer, &object)
                                {
                                    Ok(_) => self
                                        .diagnostics
                                        .with_state(|state| state.content.direct_pushes_sent += 1),
                                    Err(error) => {
                                        self.diagnostics.with_state(|state| {
                                            state.content.direct_push_busy += 1
                                        });
                                        tracing::debug!(target: "stacks_network", %peer, %error, "direct content push deferred or rejected");
                                    }
                                }
                            }
                        }

                        if let Some(announcement) = announcement {
                            // The validator was run before object admission, so this cannot
                            // leave a committed object paired with a malformed announcement.
                            let encoded_bytes =
                                announcement_envelope(self.config.network.chain_id, &announcement)
                                    .encoded_len();
                            match hub.admit_announcement(&announcement, *self.swarm.local_peer_id())
                            {
                                Ok(_) => {
                                    if let Err(error) = self
                                        .swarm
                                        .behaviour_mut()
                                        .application_mut()
                                        .queue_content_announcement(announcement, encoded_bytes)
                                    {
                                        self.diagnostics.record_error(error);
                                    }
                                }
                                Err(error) => self.diagnostics.record_error(format!(
                                    "reject local announcement after validation: {error}"
                                )),
                            }
                        }
                    }
                    Err(error) => self
                        .diagnostics
                        .record_error(format!("reject local object publication: {error}")),
                }
            }
            Some(Command::Content(ContentCommand::Commit(object))) => {
                let Some(hub) = hub.as_mut() else {
                    self.diagnostics
                        .record_error("object hub is disabled".to_owned());
                    return true;
                };
                if let Err(error) = hub.admit_object(object) {
                    self.diagnostics
                        .record_error(format!("reject contextual object commit: {error}"));
                }
            }
            Some(Command::Content(ContentCommand::Announce(announcement))) => {
                let Some(hub) = hub.as_mut() else {
                    self.diagnostics
                        .record_error("object hub is disabled".to_owned());
                    return true;
                };
                let encoded_bytes =
                    announcement_envelope(self.config.network.chain_id, &announcement)
                        .encoded_len();
                match hub.admit_announcement(&announcement, *self.swarm.local_peer_id()) {
                    Ok(_) => {
                        if let Err(error) = self
                            .swarm
                            .behaviour_mut()
                            .application_mut()
                            .queue_content_announcement(announcement, encoded_bytes)
                        {
                            self.diagnostics.record_error(error);
                        }
                    }
                    Err(error) => self
                        .diagnostics
                        .record_error(format!("reject local announcement: {error}")),
                }
            }
            Some(Command::Content(ContentCommand::Reject(content_id))) => {
                if let Some(hub) = hub.as_mut() {
                    hub.reject_validation(&content_id);
                }
            }
            Some(Command::Content(ContentCommand::Request { peer, kind, id })) => {
                if !self.swarm.behaviour().admission.is_connected(&peer)
                    || !self
                        .swarm
                        .behaviour()
                        .application()
                        .peer_supports(&peer, CAP_OBJECT_FETCH)
                {
                    self.diagnostics.record_error(format!(
                        "content peer {peer} is not authenticated and capable"
                    ));
                    return true;
                }
                if hub.as_ref().is_some_and(|hub| hub.get(&id).is_some()) {
                    return true;
                }
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .start_content_fetch(kind, id, [peer])
                {
                    self.diagnostics
                        .with_state(|state| state.content.object_fetch_failures += 1);
                    self.diagnostics
                        .record_error(format!("content fetch rejected: {error}"));
                }
            }
            Some(Command::Sync(SyncCommand::RequestSync { peer, request })) => {
                if !self.swarm.behaviour().admission.is_connected(&peer)
                    || !self
                        .swarm
                        .behaviour()
                        .application()
                        .peer_supports(&peer, stacks_network_types::CAP_SYNC)
                {
                    self.diagnostics
                        .record_error(format!("sync peer {peer} is not authenticated and capable"));
                    return true;
                }
                match self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .send_sync_request(&peer, request, SyncRequestOwner::External)
                {
                    Ok(_) => self
                        .diagnostics
                        .with_state(|state| state.sync.sync_requests_sent += 1),
                    Err(error) => self
                        .diagnostics
                        .record_error(format!("reject local sync request for {peer}: {error}")),
                }
            }
            Some(Command::Sync(SyncCommand::RequestSyncProviders {
                correlation_id,
                providers,
                request,
                max_parallel,
                hedge_delay,
            })) => {
                let requested_peer = providers.first().copied();
                let providers = providers
                    .into_iter()
                    .filter(|peer| {
                        self.swarm.behaviour().admission.is_connected(peer)
                            && self
                                .swarm
                                .behaviour()
                                .application()
                                .peer_supports(peer, stacks_network_types::CAP_SYNC)
                    })
                    .collect::<Vec<_>>();
                match self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .start_sync_request(
                        providers,
                        request,
                        correlation_id,
                        max_parallel,
                        hedge_delay,
                    ) {
                    Ok(_) => self
                        .diagnostics
                        .with_state(|state| state.sync.sync_requests_sent += 1),
                    Err(error) => {
                        if let Some(peer) = requested_peer {
                            let _ =
                                self.downstream
                                    .sync
                                    .try_send(SyncNetworkEvent::OutboundFailure {
                                        peer,
                                        correlation_id: Some(correlation_id),
                                        error: error.to_string(),
                                    });
                        }
                        self.diagnostics.record_error(format!(
                            "reject managed sync request {correlation_id}: {error}"
                        ));
                    }
                }
            }
            Some(Command::Content(ContentCommand::RespondObject {
                response_token,
                object,
            })) => {
                let Some((peer, kind, id)) = self
                    .swarm
                    .behaviour()
                    .application()
                    .pending_content_fetch_request(response_token)
                else {
                    self.diagnostics.record_error(format!(
                        "unknown or expired content response token {response_token}"
                    ));
                    return true;
                };
                let (status, object) = match object {
                    Some(object) if object.kind == kind && object.content_id == id => {
                        match hub.as_mut().map(|hub| hub.admit_object(object.clone())) {
                            Some(Ok(_)) => {
                                self.diagnostics
                                    .with_state(|state| state.content.durable_object_hits += 1);
                                (Status::Ok, Some(object))
                            }
                            Some(Err(error)) => {
                                self.diagnostics.record_error(format!(
                                    "reject durable object response for {peer}: {error}"
                                ));
                                (Status::InvalidRequest, None)
                            }
                            None => (Status::Unsupported, None),
                        }
                    }
                    Some(_) => {
                        self.diagnostics.record_error(format!(
                            "durable object response did not match request from {peer}"
                        ));
                        (Status::InvalidRequest, None)
                    }
                    None => {
                        self.diagnostics
                            .with_state(|state| state.content.durable_object_misses += 1);
                        (Status::NotFound, None)
                    }
                };
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .respond_content_fetch(response_token, status, object.as_ref())
                {
                    self.diagnostics.record_error(error);
                }
            }
            Some(Command::Sync(SyncCommand::RespondSync {
                response_token,
                response,
            })) => {
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .respond_sync(response_token, response)
                {
                    self.diagnostics
                        .with_state(|state| state.sync.sync_failures += 1);
                    self.diagnostics.record_error(error);
                }
            }
            None => return false,
        }
        true
    }

    fn record_event_loop_heartbeat(&mut self) {
        let now = Instant::now();
        let lag = now
            .duration_since(self.last_event_loop_heartbeat)
            .saturating_sub(Duration::from_secs(1));
        self.last_event_loop_heartbeat = now;
        let lag_ms = lag.as_millis().try_into().unwrap_or(u64::MAX);
        self.diagnostics.with_state(|state| {
            state.event_loop.event_loop_lag_ms = lag_ms;
            if lag >= Duration::from_millis(500) {
                state.event_loop.event_loop_stalls += 1;
            }
        });
        if lag >= Duration::from_millis(500) {
            self.diagnostics
                .record_event("event-loop-stall", format!("lag_ms={lag_ms}"));
            tracing::warn!(
                target: "stacks_network",
                lag_ms,
                "libp2p swarm event loop missed its latency budget"
            );
        }
    }

    fn maintain_periodic_work(&mut self) {
        if let Some(object_hub) = self.objects.hub.as_mut() {
            let expired = object_hub.expire_validations(Duration::from_secs(30));
            if expired > 0 {
                tracing::debug!(
                    target: "stacks_network",
                    expired,
                    "expired uncommitted object validations"
                );
            }
            self.diagnostics.with_state(|state| {
                state.content.object_cache_items = object_hub.object_count();
                state.content.object_cache_bytes = object_hub.object_bytes();
            });
        }

        // Hello-time replay can race a signer's first reconstructed-state
        // publication during simultaneous startup. Cursor refresh repairs
        // that gap without depending on GossipSub mesh timing. The signer
        // behaviour coalesces these deterministic candidates to one bounded
        // provider request per reward cycle and rotates after failure.
        let replay_targets = self
            .swarm
            .behaviour()
            .application()
            .signer()
            .authorization_state()
            .all_peers()
            .into_iter()
            .filter(|peer| {
                self.swarm.behaviour().admission.is_connected(peer)
                    && self
                        .swarm
                        .behaviour()
                        .application()
                        .is_peer_authenticated(peer)
            })
            .map(|peer| {
                let cycles = self
                    .swarm
                    .behaviour()
                    .application()
                    .signer()
                    .authorization_state()
                    .cycles_for_peer(&peer);
                (peer, cycles)
            })
            .collect::<Vec<_>>();
        let sent = replay_targets
            .into_iter()
            .map(|(peer, cycles)| {
                self.swarm
                    .behaviour_mut()
                    .application_mut()
                    .request_signer_replays_for_peer(peer, cycles)
            })
            .sum();
        self.diagnostics.record_signer_replays_requested(sent);
    }

    fn drain_object_events(&mut self) {
        while let Some(event) = self
            .swarm
            .behaviour_mut()
            .application_mut()
            .pop_content_event()
        {
            match self.downstream.object.try_send(event) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(event)) => {
                    if self
                        .swarm
                        .behaviour_mut()
                        .application_mut()
                        .restore_content_event(event)
                        .is_err()
                    {
                        self.diagnostics.record_error(
                            "content behaviour could not restore its owned front event".to_owned(),
                        );
                    }
                    break;
                }
                Err(mpsc::TrySendError::Disconnected(_)) => break,
            }
        }
    }

    fn refresh_runtime_views(&mut self) {
        let pending_content_fetches = self
            .swarm
            .behaviour()
            .application()
            .pending_content_fetches();
        let deferred_content_fetches = self
            .swarm
            .behaviour()
            .application()
            .deferred_content_fetches();
        let pending_content_events = self
            .swarm
            .behaviour()
            .application()
            .pending_content_events();
        let signer_direct_mailbox = self
            .swarm
            .behaviour()
            .application()
            .signer()
            .direct_mailbox_len();
        let deferred_miner_authorizations = self
            .swarm
            .behaviour()
            .application()
            .signer()
            .deferred_miner_authorization_snapshot();
        let preferred_sync_peers = self
            .objects
            .providers
            .select(
                self.swarm
                    .behaviour()
                    .admission
                    .connected_peers()
                    .filter(|peer| {
                        self.swarm
                            .behaviour()
                            .application()
                            .peer_supports(peer, stacks_network_types::CAP_SYNC | CAP_OBJECT_FETCH)
                    }),
                &HashSet::new(),
                self.swarm.behaviour().admission.connected_len(),
                Instant::now(),
            )
            .into_iter()
            .map(|peer| peer.to_string())
            .collect::<Vec<_>>();
        let mut coalesced_legacy_peers = self
            .authorization
            .legacy_identities
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .coalesced_native_peers(self.authorization.hello.burn_tip_height)
            .map(|peer| peer.to_string())
            .collect::<Vec<_>>();
        coalesced_legacy_peers.sort();
        let peer_store_snapshot = self.peer_store.as_ref().map(PeerStoreRuntime::snapshot);
        self.diagnostics.with_state(|state| {
            state.content.object_fetches_inflight = pending_content_fetches;
            state.content.object_fetches_deferred = deferred_content_fetches;
            state.content.max_object_fetches_deferred = state
                .content
                .max_object_fetches_deferred
                .max(deferred_content_fetches);
            state.content.validation_queue_depth = pending_content_events;
            state.content.validation_queue_capacity = crate::DOWNSTREAM_EVENT_QUEUE_CAPACITY;
            state.signer.direct_signer_deliveries_pending = signer_direct_mailbox;
            state.signer.deferred_miner_authorizations = deferred_miner_authorizations.admitted;
            state.signer.deferred_miner_authorizations_pending =
                deferred_miner_authorizations.pending;
            state
                .signer
                .deferred_miner_authorization_observations_delivered =
                deferred_miner_authorizations.observation_delivered;
            state
                .signer
                .deferred_miner_authorization_observation_retries =
                deferred_miner_authorizations.observation_retries;
            state.signer.deferred_miner_authorizations_released =
                deferred_miner_authorizations.released;
            state.signer.deferred_miner_authorizations_expired =
                deferred_miner_authorizations.expired;
            state.signer.deferred_miner_authorizations_unauthorized =
                deferred_miner_authorizations.unauthorized;
            state.signer.deferred_miner_authorizations_redundant =
                deferred_miner_authorizations.redundant;
            state.signer.deferred_miner_authorizations_binding_failed =
                deferred_miner_authorizations.binding_failed;
            state.signer.deferred_miner_authorizations_malformed =
                deferred_miner_authorizations.malformed;
            state.topology.preferred_sync_peers = preferred_sync_peers;
            state.topology.coalesced_legacy_peers = coalesced_legacy_peers;
        });
        if let Some(snapshot) = peer_store_snapshot {
            self.diagnostics.apply_peer_store_snapshot(snapshot);
        }
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                result = self.shutdown.changed() => {
                    if result.is_err() || *self.shutdown.borrow() {
                        break;
                    }
                },
                command = self.commands.recv() => {
                    if !self.handle_command(command) {
                        break;
                    }
                },
                _ = self.timers.event_loop_heartbeat.tick() => self.record_event_loop_heartbeat(),
                _ = self.timers.maintenance.tick() => self.maintain_periodic_work(),
                _ = self.timers.object_event_drain.tick(), if self.swarm.behaviour().application().has_content_events() => {
                    self.drain_object_events();
                },
                _ = self.timers.sync_control_drain.tick(), if !self.deferred_sync_control.is_empty() => {
                    self.drain_deferred_sync_control();
                },
                event = self.swarm.select_next_some() => self.handle_swarm_event(event),
            }
            self.refresh_runtime_views();
        }
    }

    fn handle_swarm_event(&mut self, event: SwarmEvent<StacksBehaviourEvent>) {
        // Give an older recovery probe first claim on any newly available
        // downstream slot before admitting more swarm traffic.
        self.drain_deferred_sync_control();
        let hub = &mut self.objects.hub;
        let provider_pool = &mut self.objects.providers;
        match event {
            SwarmEvent::NewListenAddr { address, .. } => self.diagnostics.with_state(|state| {
                let address = address.to_string();
                if !state.topology.listening_addresses.contains(&address) {
                    state.topology.listening_addresses.push(address);
                    state.topology.listening_addresses.sort();
                }
            }),
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                tracing::info!(target: "stacks_network", %peer_id, "libp2p connection established");
                provider_pool.upsert(
                    peer_id,
                    self.swarm
                        .behaviour()
                        .admission
                        .primary_prefix(&peer_id)
                        .map(|prefix| prefix.diversity_key()),
                    self.swarm
                        .behaviour()
                        .admission
                        .has_outbound_connection(&peer_id),
                );
                self.diagnostics
                    .update_connected(self.swarm.behaviour().admission.connected_peers());
                self.diagnostics.record_event(
                    "connection-established",
                    format!(
                        "peer={peer_id} direction={}",
                        if endpoint.is_dialer() {
                            "outbound"
                        } else {
                            "inbound"
                        }
                    ),
                );
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .begin_handshake(peer_id, self.authorization.hello.clone())
                {
                    self.diagnostics
                        .record_error(format!("construct hello: {error}"));
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                cause,
                ..
            } => {
                if num_established == 0 {
                    provider_pool.disconnect(&peer_id);
                    self.diagnostics.with_state(|state| {
                        state
                            .topology
                            .sync_capable_peers
                            .retain(|peer| peer != &peer_id.to_string());
                        state
                            .topology
                            .object_sync_capable_peers
                            .retain(|peer| peer != &peer_id.to_string());
                    });
                    self.diagnostics
                        .update_connected(self.swarm.behaviour().admission.connected_peers());
                    self.diagnostics.record_event(
                        "connection-closed",
                        format!("peer={peer_id} cause={cause:?}"),
                    );
                    tracing::info!(
                        target: "stacks_network",
                        %peer_id,
                        ?cause,
                        "libp2p connection closed"
                    );
                } else {
                    provider_pool.upsert(
                        peer_id,
                        self.swarm
                            .behaviour()
                            .admission
                            .primary_prefix(&peer_id)
                            .map(|prefix| prefix.diversity_key()),
                        self.swarm
                            .behaviour()
                            .admission
                            .has_outbound_connection(&peer_id),
                    );
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Discovery(event)) => match event {
                DiscoveryEvent::PeerAddressesChanged {
                    peer,
                    addresses,
                    usable,
                } => {
                    self.diagnostics.record_event(
                        "discovery-addresses-changed",
                        format!("peer={peer} count={} usable={usable}", addresses.len()),
                    );
                }
                DiscoveryEvent::BootstrapAttempt { peer, attempt } => {
                    self.diagnostics.record_event(
                        "bootstrap-attempt",
                        format!("peer={peer} attempt={attempt}"),
                    );
                }
                DiscoveryEvent::BootstrapFailed {
                    peer,
                    attempt,
                    next_delay,
                    error,
                } => self.diagnostics.record_error(format!(
                    "bootstrap dial failed peer={peer} attempt={attempt} retry_ms={}: {error}",
                    next_delay.as_millis()
                )),
                DiscoveryEvent::BootstrapExhausted { peer, attempts } => {
                    self.diagnostics.record_event(
                        "bootstrap-attempts-exhausted",
                        format!("peer={peer} attempts={attempts}"),
                    );
                    tracing::warn!(
                        target: "stacks_network",
                        %peer,
                        attempts,
                        "pinned bootstrap remains unreachable at capped retry backoff"
                    );
                }
                DiscoveryEvent::BootstrapStale { peer } => {
                    self.diagnostics
                        .record_event("bootstrap-stale", format!("peer={peer}"));
                    tracing::warn!(
                        target: "stacks_network",
                        %peer,
                        "closing stale pinned bootstrap connection before redial"
                    );
                }
                DiscoveryEvent::RestoredDialFailed {
                    peer,
                    address,
                    error,
                } => {
                    if let Some(store) = self.peer_store.as_ref() {
                        store.record_failure(peer, address.clone(), unix_time_secs());
                    }
                    self.diagnostics
                        .with_state(|state| state.discovery.outbound_failures += 1);
                    self.diagnostics.record_event(
                        "peer-store-dial-failed",
                        format!("peer={peer} address={address} error={error}"),
                    );
                }
                DiscoveryEvent::KademliaQueryStarted => {
                    self.diagnostics
                        .with_state(|state| state.discovery.kademlia_queries_started += 1);
                }
                DiscoveryEvent::ReachabilityProbe {
                    server,
                    reachable,
                    error,
                    ..
                } => {
                    self.diagnostics.with_state(|state| {
                        if reachable {
                            state.discovery.autonat_successes += 1;
                        } else {
                            state.discovery.autonat_failures += 1;
                        }
                    });
                    if let Some(error) = error {
                        tracing::debug!(target: "stacks_network", %server, %error, "AutoNAT reachability probe failed");
                    }
                }
                DiscoveryEvent::ServingModeChanged { server } => {
                    self.diagnostics
                        .with_state(|state| state.discovery.kademlia_server = server);
                    self.diagnostics
                        .record_event("kademlia-mode-changed", format!("server={server}"));
                }
            },
            SwarmEvent::Behaviour(StacksBehaviourEvent::Ping(ping::Event {
                peer, result, ..
            })) => match result {
                Ok(rtt) => {
                    provider_pool.note_latency(peer, rtt);
                    self.swarm
                        .behaviour_mut()
                        .note_discovery_liveness(peer, Instant::now());
                    self.diagnostics.with_state(|state| {
                        state.topology.ping_successes += 1;
                        state.topology.peer_rtt_ms = provider_pool
                            .connected_latencies()
                            .map(|(peer, rtt)| {
                                (
                                    peer.to_string(),
                                    rtt.as_millis().try_into().unwrap_or(u64::MAX),
                                )
                            })
                            .collect();
                        state
                            .topology
                            .peer_rtt_ms
                            .sort_by(|left, right| left.0.cmp(&right.0));
                    });
                }
                Err(error) => {
                    provider_pool.observe(peer, ProviderOutcome::Unavailable, Instant::now());
                    self.diagnostics
                        .with_state(|state| state.topology.ping_failures += 1);
                    self.diagnostics
                        .record_error(format!("ping failed for {peer}: {error}"));
                }
            },
            SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    connection_id,
                    message,
                },
            )) => match message {
                Message::Request {
                    request, channel, ..
                } => {
                    let span = tracing::info_span!(
                        target: "stacks_network",
                        "application_hello",
                        direction = "inbound",
                        peer_id = %peer,
                    );
                    let _entered = span.enter();
                    if !admit_peer_budget(
                        self.swarm.behaviour_mut().application_mut(),
                        peer,
                        request.encoded_len(),
                        1,
                        &self.diagnostics,
                    ) {
                        return;
                    }
                    match self
                        .swarm
                        .behaviour()
                        .application()
                        .remote_hello(connection_id)
                        .cloned()
                        .ok_or_else(|| "Hello gate did not retain authenticated request".to_owned())
                    {
                        Ok(remote_hello) => {
                            if let Some(binding) = remote_hello.legacy_identity_binding.as_ref() {
                                match verify_legacy_identity_binding(
                                    binding,
                                    peer,
                                    self.config.network.chain_id,
                                    self.authorization.hello.burn_tip_height,
                                ) {
                                    Ok(binding) => self
                                        .authorization
                                        .legacy_identities
                                        .lock()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                                        .observe_native_binding(binding),
                                    Err(error) => {
                                        self.diagnostics.with_state(|state| {
                                            state.discovery.rejected_hellos += 1
                                        });
                                        self.diagnostics.record_error(format!(
                                            "invalid legacy identity binding from {peer}: {error}"
                                        ));
                                        self.swarm
                                            .behaviour_mut()
                                            .application_mut()
                                            .revoke_peer(peer);
                                        let _ = self.swarm.disconnect_peer_id(peer);
                                        return;
                                    }
                                }
                            }
                            match hello_response_envelope(
                                &self.authorization.hello,
                                remote_hello.challenge.clone(),
                            ) {
                                Ok(response) => match self
                                    .swarm
                                    .behaviour_mut()
                                    .application_mut()
                                    .send_hello_response(channel, response)
                                {
                                    Ok(()) => {
                                        let (sync_capable, object_sync_capable) =
                                            sync_capability_classes(remote_hello.capabilities);
                                        self.swarm
                                            .behaviour_mut()
                                            .authenticate_discovery_peer(peer);
                                        if let (Some(store), Some(address)) = (
                                            self.peer_store.as_ref(),
                                            self.swarm
                                                .behaviour()
                                                .admission
                                                .authenticated_dial_address(&peer, connection_id)
                                                .cloned(),
                                        ) {
                                            store.record_authenticated(
                                                peer,
                                                address,
                                                remote_hello.capabilities,
                                                unix_time_secs(),
                                            );
                                        }
                                        tracing::info!(target: "stacks_network", %peer, "accepted authenticated libp2p hello request");
                                        self.diagnostics.with_state(|state| {
                                            state.discovery.successful_hellos += 1;
                                            let peer = peer.to_string();
                                            if sync_capable
                                                && !state
                                                    .topology
                                                    .sync_capable_peers
                                                    .contains(&peer)
                                            {
                                                state
                                                    .topology
                                                    .sync_capable_peers
                                                    .push(peer.clone());
                                                state.topology.sync_capable_peers.sort();
                                            }
                                            if object_sync_capable
                                                && !state
                                                    .topology
                                                    .object_sync_capable_peers
                                                    .contains(&peer)
                                            {
                                                state.topology.object_sync_capable_peers.push(peer);
                                                state.topology.object_sync_capable_peers.sort();
                                            }
                                        });
                                        self.diagnostics.record_event("hello-authenticated",
                                                format!("peer={peer} direction=inbound sync={sync_capable} object_sync={object_sync_capable}"),
                                            );
                                        if sync_capable {
                                            let cycles = self
                                                .swarm
                                                .behaviour()
                                                .application()
                                                .signer()
                                                .authorization_state()
                                                .cycles_for_peer(&peer);
                                            let sent = self
                                                .swarm
                                                .behaviour_mut()
                                                .application_mut()
                                                .request_signer_replays_for_peer(peer, cycles);
                                            self.diagnostics.record_signer_replays_requested(sent);
                                        }
                                    }
                                    Err(_) => self.diagnostics.record_error(format!(
                                        "hello response channel to {peer} closed"
                                    )),
                                },
                                Err(error) => self.diagnostics.record_error(format!(
                                    "construct hello response to {peer}: {error}"
                                )),
                            }
                        }
                        Err(error) => {
                            self.diagnostics
                                .with_state(|state| state.discovery.rejected_hellos += 1);
                            self.diagnostics
                                .record_error(format!("rejected hello from {peer}: {error}"));
                        }
                    }
                }
                Message::Response {
                    request_id: _,
                    response,
                } => {
                    if !admit_peer_budget(
                        self.swarm.behaviour_mut().application_mut(),
                        peer,
                        response.encoded_len(),
                        1,
                        &self.diagnostics,
                    ) {
                        return;
                    }
                    let result = self
                        .swarm
                        .behaviour()
                        .application()
                        .remote_hello(connection_id)
                        .cloned()
                        .ok_or_else(|| {
                            "Hello gate did not retain challenge-bound response".to_owned()
                        });
                    match result {
                        Ok(remote_hello) => {
                            if let Some(binding) = remote_hello.legacy_identity_binding.as_ref() {
                                match verify_legacy_identity_binding(
                                    binding,
                                    peer,
                                    self.config.network.chain_id,
                                    self.authorization.hello.burn_tip_height,
                                ) {
                                    Ok(binding) => self
                                        .authorization
                                        .legacy_identities
                                        .lock()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                                        .observe_native_binding(binding),
                                    Err(error) => {
                                        self.diagnostics.with_state(|state| {
                                            state.discovery.rejected_hellos += 1
                                        });
                                        self.diagnostics.record_error(format!(
                                            "invalid legacy identity binding from {peer}: {error}"
                                        ));
                                        self.swarm
                                            .behaviour_mut()
                                            .application_mut()
                                            .revoke_peer(peer);
                                        let _ = self.swarm.disconnect_peer_id(peer);
                                        return;
                                    }
                                }
                            }
                            let (sync_capable, object_sync_capable) =
                                sync_capability_classes(remote_hello.capabilities);
                            self.swarm.behaviour_mut().authenticate_discovery_peer(peer);
                            if let (Some(store), Some(address)) = (
                                self.peer_store.as_ref(),
                                self.swarm
                                    .behaviour()
                                    .admission
                                    .authenticated_dial_address(&peer, connection_id)
                                    .cloned(),
                            ) {
                                store.record_authenticated(
                                    peer,
                                    address,
                                    remote_hello.capabilities,
                                    unix_time_secs(),
                                );
                            }
                            tracing::info!(target: "stacks_network", %peer, "accepted challenge-bound libp2p hello response");
                            self.diagnostics.with_state(|state| {
                                state.discovery.successful_hellos += 1;
                                let peer = peer.to_string();
                                if sync_capable
                                    && !state.topology.sync_capable_peers.contains(&peer)
                                {
                                    state.topology.sync_capable_peers.push(peer.clone());
                                    state.topology.sync_capable_peers.sort();
                                }
                                if object_sync_capable
                                    && !state.topology.object_sync_capable_peers.contains(&peer)
                                {
                                    state.topology.object_sync_capable_peers.push(peer);
                                    state.topology.object_sync_capable_peers.sort();
                                }
                            });
                            self.diagnostics.record_event("hello-authenticated",
                                        format!("peer={peer} direction=outbound sync={sync_capable} object_sync={object_sync_capable}"),
                                    );
                            if sync_capable {
                                let cycles = self
                                    .swarm
                                    .behaviour()
                                    .application()
                                    .signer()
                                    .authorization_state()
                                    .cycles_for_peer(&peer);
                                let sent = self
                                    .swarm
                                    .behaviour_mut()
                                    .application_mut()
                                    .request_signer_replays_for_peer(peer, cycles);
                                self.diagnostics.record_signer_replays_requested(sent);
                            }
                        }
                        Err(error) => {
                            self.diagnostics
                                .with_state(|state| state.discovery.rejected_hellos += 1);
                            self.diagnostics.record_error(format!(
                                "rejected hello response from {peer}: {error}"
                            ));
                        }
                    }
                }
            },
            SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(
                request_response::Event::OutboundFailure {
                    request_id: _,
                    error,
                    ..
                },
            )) => {
                self.diagnostics
                    .with_state(|state| state.discovery.outbound_failures += 1);
                self.diagnostics
                    .record_error(format!("hello outbound failure: {error}"));
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                ContentExchangeEvent::Publish { token, publication },
            )) => {
                let (result, kind) = match publication {
                    ContentPublication::Announcement(announcement) => (
                        self.swarm.behaviour_mut().application_mut().publish_gossip(
                            block_announcement_topic(
                                self.config.network.chain_id,
                                self.config.network.network_id,
                            ),
                            announcement_envelope(self.config.network.chain_id, &announcement)
                                .encode(),
                        ),
                        ObjectKind::NakamotoBlock,
                    ),
                    ContentPublication::Transaction(object) => (
                        self.swarm.behaviour_mut().application_mut().publish_gossip(
                            transaction_topic(
                                self.config.network.chain_id,
                                self.config.network.network_id,
                            ),
                            content_push_envelope(self.config.network.chain_id, &object).encode(),
                        ),
                        ObjectKind::Transaction,
                    ),
                };
                let outcome = match result {
                    Ok(_) => {
                        if kind == ObjectKind::NakamotoBlock {
                            self.diagnostics.with_state(|state| {
                                state.content.object_announcements_published += 1
                            });
                        } else {
                            self.diagnostics
                                .with_state(|state| state.content.objects_published += 1);
                        }
                        PublicationOutcome::Published
                    }
                    Err(PublishError::NoPeersSubscribedToTopic) => PublicationOutcome::NoPeers,
                    Err(PublishError::Duplicate) => PublicationOutcome::Duplicate,
                    Err(error) => {
                        let message = format!("content publication failed: {error}");
                        self.diagnostics.record_error(message.clone());
                        PublicationOutcome::Failed(message)
                    }
                };
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .complete_content_publication(token, outcome)
                {
                    self.diagnostics.record_error(error);
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                ContentExchangeEvent::FetchStarted { peer, kind, id },
            )) => {
                tracing::debug!(target: "stacks_network", %peer, ?kind, ?id, "started bounded content fetch");
                self.diagnostics
                    .with_state(|state| state.content.object_fetches_started += 1);
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                ContentExchangeEvent::InboundFetch {
                    peer,
                    response_token,
                    kind,
                    id,
                    encoded_bytes,
                    ..
                },
            )) => {
                let span = tracing::info_span!(
                    target: "stacks_network",
                    "content_fetch",
                    direction = "inbound",
                    peer_id = %peer,
                );
                let _entered = span.enter();
                if !admit_peer_budget(
                    self.swarm.behaviour_mut().application_mut(),
                    peer,
                    encoded_bytes,
                    1,
                    &self.diagnostics,
                ) {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .application_mut()
                        .respond_content_fetch(response_token, Status::Busy, None);
                    return;
                }
                let cached = hub
                    .as_ref()
                    .and_then(|hub| hub.get(&id))
                    .filter(|object| object.kind == kind);
                if let Some(object) = cached {
                    if let Err(error) = self
                        .swarm
                        .behaviour_mut()
                        .application_mut()
                        .respond_content_fetch(response_token, Status::Ok, Some(object))
                    {
                        self.diagnostics.record_error(error);
                    }
                    return;
                }
                let queued = self.downstream.queue_object_event(
                    self.swarm.behaviour_mut().application_mut(),
                    ObjectNetworkEvent::Request {
                        source: peer,
                        response_token,
                        kind,
                        id,
                    },
                    &self.diagnostics,
                );
                if queued {
                    self.diagnostics
                        .with_state(|state| state.content.durable_object_lookups += 1);
                } else {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .application_mut()
                        .respond_content_fetch(response_token, Status::Busy, None);
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                ContentExchangeEvent::Fetched {
                    peer,
                    object,
                    encoded_bytes,
                    ..
                },
            )) => {
                let span = tracing::info_span!(
                    target: "stacks_network",
                    "content_fetch",
                    direction = "outbound",
                    peer_id = %peer,
                );
                let _entered = span.enter();
                if !admit_peer_budget(
                    self.swarm.behaviour_mut().application_mut(),
                    peer,
                    encoded_bytes,
                    4,
                    &self.diagnostics,
                ) {
                    return;
                }
                if let Some(hub) = hub.as_mut() {
                    match hub.begin_validation(&object) {
                        Ok(ObjectAdmission::New) => {
                            provider_pool.observe(
                                peer,
                                ProviderOutcome::Success {
                                    latency: provider_pool.latency(&peer).unwrap_or_default(),
                                },
                                Instant::now(),
                            );
                            let id = object.content_id;
                            if self.downstream.queue_object_event(
                                self.swarm.behaviour_mut().application_mut(),
                                ObjectNetworkEvent::Object {
                                    source: peer,
                                    object,
                                    direct_push: false,
                                },
                                &self.diagnostics,
                            ) {
                                self.diagnostics
                                    .with_state(|state| state.content.objects_received += 1);
                            } else {
                                hub.reject_validation(&id);
                                self.diagnostics.record_error(
                                    "fetched-object event queue exhausted its byte budget"
                                        .to_owned(),
                                );
                            }
                        }
                        Ok(ObjectAdmission::AlreadyHave) => {
                            provider_pool.observe(
                                peer,
                                ProviderOutcome::Success {
                                    latency: provider_pool.latency(&peer).unwrap_or_default(),
                                },
                                Instant::now(),
                            );
                        }
                        Err(error) => {
                            provider_pool.observe(
                                peer,
                                ProviderOutcome::InvalidData,
                                Instant::now(),
                            );
                            self.diagnostics.record_error(format!(
                                "rejected fetched object from {peer}: {error}"
                            ));
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                ContentExchangeEvent::ProviderFailed {
                    peer,
                    id,
                    failure,
                    error,
                },
            )) => {
                provider_pool.observe(
                    peer,
                    match failure {
                        ProviderFailure::Unavailable => ProviderOutcome::Unavailable,
                        ProviderFailure::InvalidData => ProviderOutcome::InvalidData,
                    },
                    Instant::now(),
                );
                self.diagnostics.record_event(
                    "content-provider-failed",
                    format!("peer={peer} id={id:?} failure={failure:?} error={error}"),
                );
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                ContentExchangeEvent::FetchFailed {
                    id,
                    attempted,
                    error,
                },
            )) => {
                self.diagnostics
                    .with_state(|state| state.content.object_fetch_failures += 1);
                self.diagnostics.record_error(format!(
                    "content fetch exhausted providers id={id:?} attempted={}: {error}",
                    attempted.len()
                ));
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                ContentExchangeEvent::InboundPush {
                    peer,
                    response_token,
                    object,
                    encoded_bytes,
                    ..
                },
            )) => {
                let span = tracing::info_span!(
                    target: "stacks_network",
                    "content_push",
                    direction = "inbound",
                    peer_id = %peer,
                );
                let _entered = span.enter();
                let id = object.content_id;
                let status = if !admit_peer_budget(
                    self.swarm.behaviour_mut().application_mut(),
                    peer,
                    encoded_bytes,
                    8,
                    &self.diagnostics,
                ) || !self
                    .swarm
                    .behaviour()
                    .application()
                    .can_stage_content_object(&object)
                {
                    self.diagnostics
                        .with_state(|state| state.content.direct_push_busy += 1);
                    Status::Busy
                } else {
                    match hub.as_mut().map(|hub| hub.begin_validation(&object)) {
                        Some(Ok(ObjectAdmission::New)) => {
                            if self.downstream.queue_object_event(
                                self.swarm.behaviour_mut().application_mut(),
                                ObjectNetworkEvent::Object {
                                    source: peer,
                                    object,
                                    direct_push: true,
                                },
                                &self.diagnostics,
                            ) {
                                self.diagnostics.with_state(|state| {
                                    state.content.direct_pushes_received += 1;
                                    state.content.objects_received += 1;
                                });
                                Status::Queued
                            } else {
                                if let Some(hub) = hub.as_mut() {
                                    hub.reject_validation(&id);
                                }
                                self.diagnostics
                                    .with_state(|state| state.content.direct_push_busy += 1);
                                Status::Busy
                            }
                        }
                        Some(Ok(ObjectAdmission::AlreadyHave)) => Status::AlreadyHave,
                        Some(Err(error)) => {
                            provider_pool.observe(
                                peer,
                                ProviderOutcome::InvalidData,
                                Instant::now(),
                            );
                            self.diagnostics.record_error(format!(
                                "rejected direct object push from {peer}: {error}"
                            ));
                            Status::InvalidRequest
                        }
                        None => Status::Busy,
                    }
                };
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .respond_content_push(response_token, status)
                {
                    self.diagnostics.record_error(error);
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                ContentExchangeEvent::PushResult {
                    peer,
                    status,
                    encoded_bytes,
                    ..
                },
            )) => {
                if encoded_bytes > 0
                    && !admit_peer_budget(
                        self.swarm.behaviour_mut().application_mut(),
                        peer,
                        encoded_bytes,
                        1,
                        &self.diagnostics,
                    )
                {
                    return;
                }
                match status {
                    Ok(Status::Queued | Status::Ok) => self
                        .diagnostics
                        .with_state(|state| state.content.direct_pushes_queued += 1),
                    Ok(Status::AlreadyHave) => self
                        .diagnostics
                        .with_state(|state| state.content.direct_pushes_already_have += 1),
                    Ok(Status::Busy | Status::RateLimited) => self
                        .diagnostics
                        .with_state(|state| state.content.direct_push_busy += 1),
                    Ok(Status::InvalidRequest | Status::Unauthorized | Status::Unsupported) => self
                        .diagnostics
                        .with_state(|state| state.content.direct_push_rejected += 1),
                    Ok(status) => {
                        self.diagnostics
                            .with_state(|state| state.content.direct_push_failures += 1);
                        self.diagnostics.record_error(format!(
                            "unexpected content-push status from {peer}: {status:?}"
                        ));
                    }
                    Err(error) => {
                        self.diagnostics
                            .with_state(|state| state.content.direct_push_failures += 1);
                        self.diagnostics
                            .record_error(format!("direct object push to {peer} failed: {error}"));
                    }
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                ContentExchangeEvent::Rejected {
                    peer,
                    protocol,
                    error,
                    ..
                },
            )) => {
                provider_pool.observe(peer, ProviderOutcome::InvalidData, Instant::now());
                self.diagnostics
                    .with_state(|state| state.content.object_fetch_failures += 1);
                self.diagnostics.record_error(format!(
                    "rejected {protocol:?} content message from {peer}: {error}"
                ));
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                ContentExchangeEvent::InboundExpired {
                    peer,
                    response_token,
                    protocol,
                },
            )) => {
                self.diagnostics
                    .with_state(|state| state.content.object_fetch_failures += 1);
                self.diagnostics.record_event(
                    "content-response-expired",
                    format!("peer={peer} token={response_token} protocol={protocol:?}"),
                );
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::AdmissionRequired {
                    token,
                    peer,
                    encoded_bytes,
                    validation_units,
                    ..
                },
            )) => {
                let admitted = admit_peer_budget(
                    self.swarm.behaviour_mut().application_mut(),
                    peer,
                    encoded_bytes,
                    validation_units,
                    &self.diagnostics,
                );
                let signer = self.swarm.behaviour_mut().application_mut().signer_mut();
                let result = if admitted {
                    signer.admit_action(token)
                } else {
                    signer.reject_action(token);
                    Ok(())
                };
                if let Err(error) = result {
                    self.diagnostics.with_state(|state| {
                        state.signer.rejected_signer_messages += 1;
                        state.signer.direct_signer_failures += 1;
                    });
                    self.diagnostics.record_error(format!(
                        "rejected direct signer request from {peer}: {error}"
                    ));
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::MinerAuthorizationDeferred {
                    token,
                    source,
                    provider,
                    envelope,
                    ingress,
                },
            )) => {
                let envelope_id = envelope.envelope_id;
                let signer_signature_hash = envelope
                    .body
                    .proposal_manifest
                    .as_ref()
                    .map(|manifest| {
                        stacks_common::util::hash::to_hex(&manifest.signer_signature_hash)
                    })
                    .unwrap_or_else(|| "missing".to_owned());
                let delivered = self
                    .downstream
                    .signer
                    .try_send(SignerNetworkEvent {
                        source,
                        provider,
                        envelope: *envelope,
                        admission: SignerAdmission::FirstSeen,
                        canonical_authorization: SignerCanonicalAuthorization::Pending,
                    })
                    .is_ok();
                self.diagnostics.with_state(|state| {
                    state.resources.event_queue_full += u64::from(!delivered);
                    state.signer.received_signer_messages += u64::from(delivered);
                });
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .signer_mut()
                    .complete_deferred_observation(token, delivered);
                tracing::warn!(
                    target: "stacks_network",
                    peer = %source,
                    ?ingress,
                    delivered,
                    %envelope_id,
                    %signer_signature_hash,
                    "deferred source-bound miner envelope pending canonical snapshot"
                );
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::MinerAuthorizationExpired { source, ingress },
            )) => {
                self.diagnostics.record_event(
                    "miner-authorization-expired",
                    format!("source={source} ingress={ingress:?}"),
                );
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::DeliveryRequired(staged),
            )) => {
                let staged = *staged;
                if let Some(revoked_peer) = staged.revoked_peer {
                    if self
                        .swarm
                        .behaviour()
                        .application()
                        .signer()
                        .authorization_state()
                        .cycles_for_peer(&revoked_peer)
                        .is_empty()
                    {
                        self.swarm
                            .behaviour_mut()
                            .application_mut()
                            .revoke_peer(revoked_peer);
                        let _ = self.swarm.disconnect_peer_id(revoked_peer);
                    }
                }
                let lane = staged.envelope.body.lane;
                let sequence = staged.envelope.body.sequence;
                let peer = staged.source;
                let observed = staged.envelope.clone();
                let delivered = self
                    .downstream
                    .signer
                    .try_send(SignerNetworkEvent {
                        source: peer,
                        provider: staged.provider,
                        envelope: staged.envelope,
                        admission: staged.admission,
                        canonical_authorization: SignerCanonicalAuthorization::Confirmed,
                    })
                    .is_ok();
                let completion = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .signer_mut()
                    .complete_delivery(staged.token, delivered);
                if delivered && completion.is_ok() {
                    self.diagnostics
                        .record_signer_observation(&observed, peer, staged.admission);
                    let signer_signature_hash = observed
                        .body
                        .proposal_manifest
                        .as_ref()
                        .map(|manifest| {
                            stacks_common::util::hash::to_hex(&manifest.signer_signature_hash)
                        })
                        .unwrap_or_else(|| "missing".to_owned());
                    tracing::info!(target: "stacks_network", %peer, lane, sequence, was_deferred = staged.was_deferred, envelope_id = %observed.envelope_id, %signer_signature_hash, "accepted direct role-signed libp2p signer envelope");
                    self.diagnostics
                        .with_state(|state| state.signer.direct_signer_messages_received += 1);
                } else {
                    self.diagnostics.with_state(|state| {
                        state.resources.event_queue_full += u64::from(!delivered);
                        state.signer.direct_signer_failures += 1;
                    });
                    if let Err(error) = completion {
                        self.diagnostics
                            .record_error(format!("commit direct signer delivery: {error}"));
                    }
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::Redundant {
                    source,
                    admission,
                    ingress: SignerIngress::Direct,
                    ..
                },
            )) => {
                tracing::debug!(target: "stacks_network", peer = %source, ?admission, "ignored redundant direct signer envelope");
                self.diagnostics
                    .with_state(|state| state.signer.direct_signer_messages_received += 1);
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::DirectAcknowledged { .. },
            )) => {}
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::DirectFailed { peer, error, .. },
            )) => {
                self.diagnostics.with_state(|state| {
                    state.discovery.outbound_failures += 1;
                    state.signer.direct_signer_failures += 1;
                });
                self.diagnostics
                    .record_error(format!("direct signer outbound failure to {peer}: {error}"));
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::DirectSent { peer, envelope_id },
            )) => {
                self.diagnostics
                    .with_state(|state| state.signer.direct_signer_messages_sent += 1);
                tracing::debug!(target: "stacks_network", %peer, ?envelope_id, "sent direct signer envelope");
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::MailboxExpired { undelivered },
            )) => {
                self.diagnostics.with_state(|state| {
                    state.signer.direct_signer_deliveries_expired += undelivered as u64
                });
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::PublishGossip { token, envelope },
            )) => {
                let topic =
                    signer_topic(self.config.network.chain_id, self.config.network.network_id);
                let outcome = match self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .publish_gossip(topic, envelope.encode_to_vec())
                {
                    Ok(_) => PublicationOutcome::Published,
                    Err(PublishError::NoPeersSubscribedToTopic) => PublicationOutcome::NoPeers,
                    Err(PublishError::Duplicate) => PublicationOutcome::Duplicate,
                    Err(error) => PublicationOutcome::Failed(error.to_string()),
                };
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .signer_mut()
                    .complete_publication(token, outcome.clone())
                {
                    self.diagnostics
                        .record_error(format!("complete signer publication: {error}"));
                }
                match outcome {
                    PublicationOutcome::Published => {
                        self.diagnostics
                            .with_state(|state| state.signer.published_signer_messages += 1);
                        tracing::info!(target: "stacks_network", "published role-signed libp2p signer semantic envelope");
                    }
                    PublicationOutcome::Duplicate => {
                        tracing::debug!(target: "stacks_network", "skipped duplicate signer publication");
                    }
                    PublicationOutcome::NoPeers => {}
                    PublicationOutcome::Failed(error) => {
                        self.diagnostics
                            .record_error(format!("signer publication failed: {error}"));
                    }
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::PublicationCompleted { .. },
            )) => {}
            SwarmEvent::Behaviour(StacksBehaviourEvent::SignerDirect(
                SignerBehaviourEvent::Rejected { peer, error, .. },
            )) => {
                self.diagnostics
                    .with_state(|state| state.signer.direct_signer_failures += 1);
                self.diagnostics.record_error(format!(
                    "direct signer inbound failure from {peer}: {error}"
                ));
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::RoleDirectory(
                RoleDirectoryBehaviourEvent::AdmissionRequired {
                    token,
                    peer,
                    encoded_bytes,
                    validation_units,
                    direction,
                    ..
                },
            )) => {
                if direction == DirectoryDirection::InboundQuery {
                    self.diagnostics
                        .with_state(|state| state.directory.directory_queries_received += 1);
                }
                let admitted = admit_peer_budget(
                    self.swarm.behaviour_mut().application_mut(),
                    peer,
                    encoded_bytes,
                    validation_units,
                    &self.diagnostics,
                );
                let result = if admitted {
                    self.swarm
                        .behaviour_mut()
                        .application_mut()
                        .role_directory_mut()
                        .admit_action(token)
                } else {
                    self.swarm
                        .behaviour_mut()
                        .application_mut()
                        .role_directory_mut()
                        .reject_action(token, Status::Busy)
                };
                if let Err(error) = result {
                    self.diagnostics
                        .with_state(|state| state.directory.directory_rejections += 1);
                    self.diagnostics.record_error(format!(
                        "role-directory admission failed for {peer}: {error}"
                    ));
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::RoleDirectory(
                RoleDirectoryBehaviourEvent::RecordAccepted { record, .. },
            )) => {
                if matches!(record.role.body.role, role if role == Role::Signer as i32 || role == Role::Miner as i32)
                {
                    let signer = self.swarm.behaviour_mut().application_mut().signer_mut();
                    let binding = if record.role.body.role == Role::Signer as i32 {
                        signer.bind_authorized_signer(
                            record.role.body.reward_cycle,
                            record.role.stacks_public_key,
                            record.peer_id,
                        )
                    } else {
                        signer.bind_authorized_miner(
                            record.role.body.reward_cycle,
                            record.role.body.role_id.clone(),
                            record.role.stacks_public_key,
                            record.peer_id,
                        )
                    };
                    match binding {
                        Ok(binding) => {
                            if let SignerBindingUpdate::Rekeyed { revoked_peer } = binding {
                                if self
                                    .swarm
                                    .behaviour()
                                    .application()
                                    .signer()
                                    .authorization_state()
                                    .cycles_for_peer(&revoked_peer)
                                    .is_empty()
                                {
                                    self.swarm
                                        .behaviour_mut()
                                        .application_mut()
                                        .revoke_peer(revoked_peer);
                                    let _ = self.swarm.disconnect_peer_id(revoked_peer);
                                }
                            }
                            if self
                                .swarm
                                .behaviour()
                                .admission
                                .is_connected(&record.peer_id)
                                && self
                                    .swarm
                                    .behaviour()
                                    .application()
                                    .is_peer_authenticated(&record.peer_id)
                            {
                                let sent = self
                                    .swarm
                                    .behaviour_mut()
                                    .application_mut()
                                    .request_signer_replays_for_peer(
                                        record.peer_id,
                                        [record.role.body.reward_cycle],
                                    );
                                self.diagnostics.record_signer_replays_requested(sent);
                            }
                        }
                        Err(error) => {
                            self.diagnostics
                                .with_state(|state| state.directory.directory_rejections += 1);
                            self.diagnostics.record_error(format!(
                                "rejected role-directory transport binding: {error}"
                            ));
                            return;
                        }
                    }
                }
                self.diagnostics
                    .with_state(|state| state.directory.directory_records_accepted += 1);
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::RoleDirectory(
                RoleDirectoryBehaviourEvent::DialHint { peer, address },
            )) => {
                if !self.swarm.behaviour().admission.is_connected(&peer) {
                    let address = if address
                        .iter()
                        .any(|protocol| matches!(protocol, Protocol::P2p(_)))
                    {
                        address
                    } else {
                        address.with(Protocol::P2p(peer))
                    };
                    if let Err(error) = self.swarm.dial(address.clone()) {
                        self.diagnostics
                            .record_error(format!("directory dial {address}: {error}"));
                    }
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::RoleDirectory(
                RoleDirectoryBehaviourEvent::QueryCompleted { direction, .. },
            )) => {
                if direction == DirectoryDirection::OutboundResponse {
                    self.diagnostics
                        .with_state(|state| state.directory.directory_queries_sent += 1);
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::RoleDirectory(
                RoleDirectoryBehaviourEvent::Rejected { peer, error, .. },
            )) => {
                self.diagnostics
                    .with_state(|state| state.directory.directory_rejections += 1);
                self.diagnostics.record_error(format!(
                    "rejected role-directory exchange with {peer}: {error}"
                ));
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::RoleDirectory(
                RoleDirectoryBehaviourEvent::OutboundFailure { peer, error },
            )) => {
                self.diagnostics.with_state(|state| {
                    state.discovery.outbound_failures += 1;
                    state.directory.directory_rejections += 1;
                });
                self.diagnostics
                    .record_error(format!("role-directory request to {peer} failed: {error}"));
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Sync(
                SyncBehaviourEvent::InboundRequest {
                    peer,
                    connection_id,
                    response_token,
                    request,
                    encoded_bytes,
                    ..
                },
            )) => {
                let span = tracing::info_span!(
                    target: "stacks_network",
                    "sync_request",
                    direction = "inbound",
                    peer_id = %peer,
                );
                let _entered = span.enter();
                if !admit_peer_budget(
                    self.swarm.behaviour_mut().application_mut(),
                    peer,
                    encoded_bytes,
                    8,
                    &self.diagnostics,
                ) {
                    let _ = self.swarm.behaviour_mut().application_mut().respond_sync(
                        response_token,
                        SyncResponse {
                            status: Status::Busy as i32,
                            response: None,
                        },
                    );
                    return;
                }
                let authorized = self.swarm.behaviour().application().connection_supports(
                    &peer,
                    connection_id,
                    stacks_network_types::CAP_SYNC,
                );
                let admitted = authorized.then_some(()).ok_or_else(|| {
                    "sync request came from an unauthenticated or incapable peer".to_owned()
                });
                match admitted.map(|_| request) {
                    Ok(request)
                        if matches!(
                            request.request.as_ref(),
                            Some(sync_request::Request::GetSignerReplay(_))
                        ) =>
                    {
                        let Some(sync_request::Request::GetSignerReplay(replay)) = request.request
                        else {
                            unreachable!("guard checked signer replay request")
                        };
                        let requester_authorized = self.private_rendezvous_peers.contains(&peer)
                            || self
                                .swarm
                                .behaviour()
                                .application()
                                .signer()
                                .authorization_state()
                                .is_peer_bound(replay.reward_cycle, &peer);
                        let cycle_retained = self
                            .authorization
                            .retained_cycles
                            .contains(replay.reward_cycle);
                        let response = if requester_authorized && cycle_retained {
                            let (mut envelopes, complete) =
                                self.swarm.behaviour().application().signer().replay(
                                    replay.reward_cycle,
                                    &replay.cursors,
                                    replay.max_items as usize,
                                    replay.max_bytes as usize,
                                );
                            envelopes.retain(|envelope| {
                                envelope.body.as_ref().is_some_and(|body| {
                                    SignerLane::try_from(body.lane).ok().is_some_and(|lane| {
                                        matches!(
                                            lane,
                                            SignerLane::BlockResponse
                                                | SignerLane::BlockPreCommit
                                                | SignerLane::StateMachineUpdate
                                        )
                                    })
                                })
                            });
                            self.diagnostics.with_state(|state| {
                                state.signer.signer_replay_requests_received += 1;
                                state.signer.signer_replay_envelopes_served +=
                                    envelopes.len() as u64;
                            });
                            SyncResponse {
                                status: Status::Ok as i32,
                                response: Some(sync_response::Response::SignerReplay(
                                    SignerReplayPage {
                                        envelopes,
                                        complete,
                                    },
                                )),
                            }
                        } else {
                            self.diagnostics
                                .with_state(|state| state.signer.signer_replay_rejections += 1);
                            SyncResponse {
                                status: Status::Unauthorized as i32,
                                response: None,
                            }
                        };
                        if let Err(error) = self
                            .swarm
                            .behaviour_mut()
                            .application_mut()
                            .respond_sync(response_token, response)
                        {
                            self.diagnostics.with_state(|state| {
                                state.sync.sync_failures += 1;
                                state.signer.signer_replay_rejections += 1;
                            });
                            self.diagnostics.record_error(error);
                        }
                    }
                    Ok(request) => {
                        let event = SyncNetworkEvent::InboundRequest {
                            source: peer,
                            response_token,
                            request,
                        };
                        let deferable_control = matches!(
                            &event,
                            SyncNetworkEvent::InboundRequest { request, .. }
                                if is_deferable_sync_control(request)
                        );
                        let admission =
                            if deferable_control && !self.deferred_sync_control.is_empty() {
                                self.deferred_sync_control.admit(event, Instant::now())
                            } else {
                                match self.downstream.sync.try_send(event) {
                                    Ok(()) => Ok(()),
                                    Err(mpsc::TrySendError::Full(event)) if deferable_control => {
                                        self.deferred_sync_control.admit(event, Instant::now())
                                    }
                                    Err(mpsc::TrySendError::Full(_))
                                    | Err(mpsc::TrySendError::Disconnected(_)) => Err(()),
                                }
                            };
                        match admission {
                            Ok(()) => {
                                self.diagnostics
                                    .with_state(|state| state.sync.sync_requests_received += 1);
                            }
                            Err(_) => {
                                let _ = self.swarm.behaviour_mut().application_mut().respond_sync(
                                    response_token,
                                    SyncResponse {
                                        status: Status::Busy as i32,
                                        response: None,
                                    },
                                );
                                self.diagnostics
                                    .with_state(|state| state.sync.sync_failures += 1);
                            }
                        }
                    }
                    Err(error) => {
                        let status = if authorized {
                            Status::InvalidRequest
                        } else {
                            Status::Unauthorized
                        };
                        let _ = self.swarm.behaviour_mut().application_mut().respond_sync(
                            response_token,
                            SyncResponse {
                                status: status as i32,
                                response: None,
                            },
                        );
                        self.diagnostics
                            .with_state(|state| state.sync.sync_failures += 1);
                        self.diagnostics
                            .record_error(format!("rejected sync request from {peer}: {error}"));
                    }
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Sync(SyncBehaviourEvent::Response {
                peer,
                request_id,
                owner,
                response,
                encoded_bytes,
                ..
            })) => {
                if matches!(
                    owner,
                    SyncRequestOwner::External | SyncRequestOwner::ExternalManaged { .. }
                ) {
                    let outcome = match &response {
                        Ok(response) if response.status == Status::Ok as i32 => {
                            ProviderOutcome::Success {
                                latency: provider_pool.latency(&peer).unwrap_or_default(),
                            }
                        }
                        Ok(response) if response.status == Status::Busy as i32 => {
                            ProviderOutcome::Busy
                        }
                        Ok(_) => ProviderOutcome::Unavailable,
                        Err(_) => ProviderOutcome::InvalidData,
                    };
                    provider_pool.observe(peer, outcome, Instant::now());
                }
                let span = tracing::info_span!(
                    target: "stacks_network",
                    "sync_request",
                    direction = "outbound",
                    peer_id = %peer,
                    request_id = ?request_id,
                );
                let _entered = span.enter();
                if !admit_peer_budget(
                    self.swarm.behaviour_mut().application_mut(),
                    peer,
                    encoded_bytes,
                    8,
                    &self.diagnostics,
                ) {
                    match owner {
                        SyncRequestOwner::SignerReplay { reward_cycle } => {
                            self.swarm
                                .behaviour_mut()
                                .application_mut()
                                .signer_mut()
                                .retry_replay(peer, reward_cycle);
                        }
                        SyncRequestOwner::External | SyncRequestOwner::ExternalManaged { .. } => {}
                    }
                    return;
                }
                if let SyncRequestOwner::SignerReplay { reward_cycle } = owner {
                    let replay = response.and_then(|response| {
                        if response.status != Status::Ok as i32 {
                            return Err("signer replay response peer or status mismatch".to_owned());
                        }
                        match response.response {
                            Some(sync_response::Response::SignerReplay(page)) => Ok(page),
                            _ => Err("signer replay response has the wrong body".to_owned()),
                        }
                    });
                    match replay {
                        Ok(page) => {
                            let envelope_count = page.envelopes.len();
                            let page_complete = page.complete;
                            let mut rejected = 0_u64;
                            let mut delivery_deferred = false;
                            for envelope in page.envelopes {
                                let staged = self
                                    .swarm
                                    .behaviour_mut()
                                    .application_mut()
                                    .signer_mut()
                                    .stage_replay(peer, reward_cycle, envelope);
                                match staged {
                                    Ok(Some(staged)) => {
                                        let observed = staged.envelope.clone();
                                        let delivered = self
                                            .downstream
                                            .signer
                                            .try_send(SignerNetworkEvent {
                                                source: staged.source,
                                                provider: staged.provider,
                                                envelope: staged.envelope,
                                                admission: staged.admission,
                                                canonical_authorization:
                                                    SignerCanonicalAuthorization::Confirmed,
                                            })
                                            .is_ok();
                                        let completion = self
                                            .swarm
                                            .behaviour_mut()
                                            .application_mut()
                                            .signer_mut()
                                            .complete_delivery(staged.token, delivered);
                                        if !delivered || completion.is_err() {
                                            rejected += 1;
                                            delivery_deferred |= !delivered;
                                            self.diagnostics.with_state(|state| {
                                                state.resources.event_queue_full +=
                                                    u64::from(!delivered)
                                            });
                                            if let Err(error) = completion {
                                                self.diagnostics.record_error(format!(
                                                    "commit signer replay: {error}"
                                                ));
                                            }
                                        } else {
                                            self.diagnostics.record_signer_observation(
                                                &observed,
                                                staged.source,
                                                staged.admission,
                                            );
                                        }
                                    }
                                    Ok(None) => {}
                                    Err(error) => {
                                        rejected += 1;
                                        self.diagnostics.record_error(format!(
                                            "rejected signer replay envelope from {peer}: {error}"
                                        ));
                                    }
                                }
                            }
                            // A truncated page may advance immediately only when every
                            // admitted item reached the bounded consumer queue. If that
                            // queue refused an item, retain the replay attempt until its
                            // refresh deadline instead of hot-looping the same cursor and
                            // multiplying recovery traffic under backpressure.
                            if should_continue_signer_replay(page_complete, delivery_deferred) {
                                self.swarm
                                    .behaviour_mut()
                                    .application_mut()
                                    .signer_mut()
                                    .continue_replay(peer, reward_cycle);
                            }
                            self.diagnostics.with_state(|state| {
                                state.signer.signer_replay_envelopes_received +=
                                    envelope_count as u64 - rejected;
                                state.signer.signer_replay_rejections += rejected;
                                state.sync.sync_responses_received += 1;
                            });
                        }
                        Err(error) => {
                            self.swarm
                                .behaviour_mut()
                                .application_mut()
                                .signer_mut()
                                .retry_replay(peer, reward_cycle);
                            self.diagnostics.with_state(|state| {
                                state.signer.signer_replay_rejections += 1;
                                state.sync.sync_failures += 1;
                            });
                            self.diagnostics.record_error(format!(
                                "invalid signer replay response from {peer}: {error}"
                            ));
                        }
                    }
                    return;
                }
                let correlation_id = match owner {
                    SyncRequestOwner::ExternalManaged { correlation_id } => Some(correlation_id),
                    _ => None,
                };
                match response {
                    Ok(response) => {
                        match self.downstream.sync.try_send(SyncNetworkEvent::Response {
                            source: peer,
                            correlation_id,
                            response,
                        }) {
                            Ok(()) => self
                                .diagnostics
                                .with_state(|state| state.sync.sync_responses_received += 1),
                            Err(_) => self.diagnostics.with_state(|state| {
                                state.resources.event_queue_full += 1;
                                state.sync.sync_failures += 1;
                            }),
                        }
                    }
                    Err(error) => {
                        self.diagnostics
                            .with_state(|state| state.sync.sync_failures += 1);
                        self.diagnostics
                            .record_error(format!("rejected sync response from {peer}: {error}"));
                    }
                }
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Sync(
                SyncBehaviourEvent::OutboundFailure {
                    request_id: _,
                    peer,
                    owner,
                    error,
                },
            )) => {
                if matches!(
                    owner,
                    SyncRequestOwner::External | SyncRequestOwner::ExternalManaged { .. }
                ) {
                    provider_pool.observe(peer, ProviderOutcome::Unavailable, Instant::now());
                }
                match owner {
                    SyncRequestOwner::SignerReplay { reward_cycle } => {
                        self.swarm
                            .behaviour_mut()
                            .application_mut()
                            .signer_mut()
                            .retry_replay(peer, reward_cycle);
                        self.diagnostics
                            .with_state(|state| state.signer.signer_replay_rejections += 1);
                    }
                    SyncRequestOwner::External => {
                        let _ = self
                            .downstream
                            .sync
                            .try_send(SyncNetworkEvent::OutboundFailure {
                                peer,
                                correlation_id: None,
                                error: error.clone(),
                            });
                    }
                    SyncRequestOwner::ExternalManaged { correlation_id } => {
                        let _ = self
                            .downstream
                            .sync
                            .try_send(SyncNetworkEvent::OutboundFailure {
                                peer,
                                correlation_id: Some(correlation_id),
                                error: error.clone(),
                            });
                    }
                }
                self.diagnostics
                    .with_state(|state| state.sync.sync_failures += 1);
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Sync(
                SyncBehaviourEvent::ProviderAttemptFailed { peer, owner, error },
            )) => {
                if matches!(
                    owner,
                    SyncRequestOwner::External | SyncRequestOwner::ExternalManaged { .. }
                ) {
                    provider_pool.observe(peer, ProviderOutcome::Unavailable, Instant::now());
                }
                self.diagnostics.record_event(
                    "sync-provider-attempt-failed",
                    format!("peer={peer} owner={owner:?} error={error}"),
                );
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Sync(
                SyncBehaviourEvent::ManagedExpired { peer, owner, error },
            )) => {
                if matches!(
                    owner,
                    SyncRequestOwner::External | SyncRequestOwner::ExternalManaged { .. }
                ) {
                    provider_pool.observe(peer, ProviderOutcome::Unavailable, Instant::now());
                }
                match owner {
                    SyncRequestOwner::External => {
                        let _ = self
                            .downstream
                            .sync
                            .try_send(SyncNetworkEvent::OutboundFailure {
                                peer,
                                correlation_id: None,
                                error: error.clone(),
                            });
                    }
                    SyncRequestOwner::ExternalManaged { correlation_id } => {
                        let _ = self
                            .downstream
                            .sync
                            .try_send(SyncNetworkEvent::OutboundFailure {
                                peer,
                                correlation_id: Some(correlation_id),
                                error: error.clone(),
                            });
                    }
                    SyncRequestOwner::SignerReplay { .. } => {
                        self.diagnostics.record_error(format!(
                            "internal managed sync request expired: {error}"
                        ));
                    }
                }
                self.diagnostics
                    .with_state(|state| state.sync.sync_failures += 1);
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Sync(
                SyncBehaviourEvent::InboundRejected { peer, error, .. },
            )) => {
                provider_pool.observe(peer, ProviderOutcome::InvalidData, Instant::now());
                self.diagnostics
                    .with_state(|state| state.sync.sync_failures += 1);
                self.diagnostics.record_error(format!(
                    "rejected sync protocol message from {peer}: {error}"
                ));
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Sync(
                SyncBehaviourEvent::InboundExpired {
                    peer,
                    response_token,
                },
            )) => {
                self.diagnostics
                    .with_state(|state| state.sync.sync_failures += 1);
                self.diagnostics.record_event(
                    "sync-response-expired",
                    format!("peer={peer} token={response_token}"),
                );
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Gossip(message)) => {
                let topic = message.topic();
                let (propagation_source, source, payload, validation) = message.into_parts();
                let span = tracing::info_span!(
                    target: "stacks_network",
                    "gossip_validation",
                    peer_id = %propagation_source,
                    topic = ?topic,
                );
                let _entered = span.enter();
                let result: Result<MessageAcceptance, String> = (|| match payload {
                    crate::AuthenticatedGossip::Signer(staged) => {
                        let staged = *staged;
                        if let Some(revoked_peer) = staged.revoked_peer {
                            if self
                                .swarm
                                .behaviour()
                                .application()
                                .signer()
                                .authorization_state()
                                .cycles_for_peer(&revoked_peer)
                                .is_empty()
                            {
                                self.swarm
                                    .behaviour_mut()
                                    .application_mut()
                                    .revoke_peer(revoked_peer);
                                let _ = self.swarm.disconnect_peer_id(revoked_peer);
                            }
                        }
                        let lane = staged.envelope.body.lane;
                        let sequence = staged.envelope.body.sequence;
                        let admission = staged.admission;
                        let observed = staged.envelope.clone();
                        let delivered = self
                            .downstream
                            .signer
                            .try_send(SignerNetworkEvent {
                                source: staged.source,
                                provider: staged.provider,
                                envelope: staged.envelope,
                                admission,
                                canonical_authorization: SignerCanonicalAuthorization::Confirmed,
                            })
                            .is_ok();
                        let completion = self
                            .swarm
                            .behaviour_mut()
                            .application_mut()
                            .signer_mut()
                            .complete_delivery(staged.token, delivered);
                        if !delivered {
                            self.diagnostics
                                .with_state(|state| state.resources.event_queue_full += 1);
                            Ok(MessageAcceptance::Ignore)
                        } else {
                            completion?;
                            self.diagnostics.record_signer_observation(
                                &observed,
                                staged.source,
                                admission,
                            );
                            let signer_signature_hash = observed
                                .body
                                .proposal_manifest
                                .as_ref()
                                .map(|manifest| {
                                    stacks_common::util::hash::to_hex(
                                        &manifest.signer_signature_hash,
                                    )
                                })
                                .unwrap_or_else(|| "missing".to_owned());
                            tracing::info!(
                                target: "stacks_network",
                                %source,
                                lane,
                                sequence,
                                ?admission,
                                was_deferred = staged.was_deferred,
                                envelope_id = %observed.envelope_id,
                                %signer_signature_hash,
                                "accepted role-signed libp2p signer semantic envelope"
                            );
                            self.diagnostics
                                .with_state(|state| state.signer.received_signer_messages += 1);
                            Ok(signer_gossip_acceptance(admission))
                        }
                    }
                    crate::AuthenticatedGossip::BlockAnnouncement(announcement) => {
                        let hub = hub
                            .as_mut()
                            .ok_or_else(|| "object hub is disabled".to_owned())?;
                        // Fetch from the authenticated forwarding peer. The
                        // signed GossipSub origin may be multiple hops away.
                        let admission =
                            hub.admit_announcement(&announcement, propagation_source)?;
                        self.swarm
                            .behaviour_mut()
                            .application_mut()
                            .remember_content_announcement(announcement.content_id);
                        if admission == ObjectAdmission::New {
                            self.downstream.queue_object_event(
                                self.swarm.behaviour_mut().application_mut(),
                                ObjectNetworkEvent::Announcement {
                                    source: propagation_source,
                                    announcement: announcement.clone(),
                                },
                                &self.diagnostics,
                            );
                        }
                        if hub.needs_object(&announcement.content_id) {
                            let providers = hub.providers(&announcement.content_id).to_vec();
                            self.swarm
                                .behaviour_mut()
                                .application_mut()
                                .start_content_fetch(
                                    announcement.kind,
                                    announcement.content_id,
                                    providers,
                                )
                                .map_err(|error| error.to_string())?;
                        }
                        self.diagnostics
                            .with_state(|state| state.content.object_announcements_received += 1);
                        Ok(MessageAcceptance::Accept)
                    }
                    crate::AuthenticatedGossip::Transaction(object) => {
                        let hub = hub
                            .as_mut()
                            .ok_or_else(|| "object hub is disabled".to_owned())?;
                        if hub.begin_validation(&object)? == ObjectAdmission::New {
                            let id = object.content_id;
                            if !self.downstream.queue_object_event(
                                self.swarm.behaviour_mut().application_mut(),
                                ObjectNetworkEvent::Object {
                                    source: propagation_source,
                                    object,
                                    direct_push: false,
                                },
                                &self.diagnostics,
                            ) {
                                // Local backpressure is not remote
                                // misbehavior: release the reservation and
                                // suppress forwarding without a P4 penalty.
                                hub.reject_validation(&id);
                                Ok(MessageAcceptance::Ignore)
                            } else {
                                self.diagnostics
                                    .with_state(|state| state.content.objects_received += 1);
                                Ok(MessageAcceptance::Accept)
                            }
                        } else {
                            Ok(MessageAcceptance::Accept)
                        }
                    }
                })();
                let acceptance = match result {
                    Ok(acceptance) => acceptance,
                    Err(error) => {
                        tracing::warn!(
                            target: "stacks_network",
                            %propagation_source,
                            %error,
                            "rejected libp2p application gossip"
                        );
                        if topic == crate::GossipTopicClass::Signer {
                            self.diagnostics
                                .with_state(|state| state.signer.rejected_signer_messages += 1);
                        }
                        MessageAcceptance::Reject
                    }
                };
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .application_mut()
                    .complete_gossip_validation(validation, acceptance);
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::GossipRejected {
                peer,
                topic,
                reason,
            }) => {
                if matches!(reason, crate::GossipRejectionReason::Resource(_)) {
                    self.diagnostics
                        .with_state(|state| state.resources.resource_budget_rejections += 1);
                }
                if topic == Some(crate::GossipTopicClass::Signer) {
                    self.diagnostics
                        .with_state(|state| state.signer.rejected_signer_messages += 1);
                }
                tracing::warn!(
                    target: "stacks_network",
                    %peer,
                    ?topic,
                    ?reason,
                    "rejected libp2p application gossip at behaviour boundary"
                );
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::Admission(event)) => {
                self.diagnostics
                    .with_state(|state| state.resources.resource_budget_rejections += 1);
                self.diagnostics.record_error(format!(
                    "connection admission rejected peer={:?} connection={} phase={:?}: {}",
                    event.peer, event.connection_id, event.phase, event.reason
                ));
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::PreHelloRejected {
                peer,
                connection_id,
                protocol,
            }) => {
                self.diagnostics
                    .with_state(|state| state.resources.resource_budget_rejections += 1);
                self.diagnostics.record_event(
                    "pre-hello-application-rejected",
                    format!("peer={peer} connection={connection_id:?} protocol={protocol:?}"),
                );
            }
            SwarmEvent::Behaviour(StacksBehaviourEvent::HelloRejected {
                peer,
                connection_id,
                reason,
            }) => {
                self.diagnostics
                    .with_state(|state| state.discovery.rejected_hellos += 1);
                if let (Some(store), Some(address)) = (
                    self.peer_store.as_ref(),
                    self.swarm
                        .behaviour()
                        .admission
                        .authenticated_dial_address(&peer, connection_id)
                        .cloned(),
                ) {
                    store.record_failure(peer, address, unix_time_secs());
                }
                self.diagnostics.record_error(format!(
                    "Hello gate rejected peer={peer} connection={connection_id}: {reason:?}"
                ));
            }
            _ => {}
        }
    }

    fn drain_deferred_sync_control(&mut self) {
        while let Some(deferred) = self.deferred_sync_control.pop_front() {
            if deferred.enqueued_at.elapsed() >= DEFERRED_SYNC_CONTROL_TTL {
                let _ = self.swarm.behaviour_mut().application_mut().respond_sync(
                    deferred.response_token,
                    SyncResponse {
                        status: Status::Busy as i32,
                        response: None,
                    },
                );
                self.diagnostics
                    .with_state(|state| state.sync.sync_failures += 1);
                continue;
            }
            let event = SyncNetworkEvent::InboundRequest {
                source: deferred.source,
                response_token: deferred.response_token,
                request: deferred.request,
            };
            match self.downstream.sync.try_send(event) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(SyncNetworkEvent::InboundRequest {
                    source,
                    response_token,
                    request,
                })) => {
                    self.deferred_sync_control
                        .push_front(DeferredSyncControlRequest {
                            source,
                            response_token,
                            request,
                            enqueued_at: deferred.enqueued_at,
                        });
                    break;
                }
                Err(mpsc::TrySendError::Disconnected(_)) => break,
                Err(mpsc::TrySendError::Full(_)) => {
                    unreachable!("deferred sync-control queue contains only inbound requests")
                }
            }
        }
    }
}

fn admit_peer_budget(
    application: &mut StacksApplicationBehaviour,
    peer: PeerId,
    bytes: usize,
    validation_work: u64,
    diagnostics: &DiagnosticsHandle,
) -> bool {
    match application.admit_peer_resources(peer, bytes, validation_work) {
        Ok(()) => true,
        Err(reason) => {
            diagnostics.with_state(|state| state.resources.resource_budget_rejections += 1);
            let resource = match reason {
                BudgetRejection::Bytes => "bytes",
                BudgetRejection::ValidationWork => "validation-work",
            };
            tracing::warn!(
                target: "stacks_network",
                %peer,
                resource,
                bytes,
                validation_work,
                "rejected peer input exceeding resource budget"
            );
            false
        }
    }
}

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
    use stacks_common::types::PrivateKey;
    use stacks_network_types::wire::v1::{
        ProposalManifest, RoleProof, RoleProofBody, SignerEnvelopeBody, SignerLane,
    };
    use stacks_network_types::{
        directory_record_digest, role_proof_digest, signer_envelope_digest,
        PROPOSAL_MANIFEST_VERSION, ROLE_PROOF_VERSION, SIGNER_ENVELOPE_VERSION,
    };

    use super::*;

    fn signer_test_network() -> NetworkConfig {
        let mut network = NetworkConfig::signer_profile(
            stacks_network_types::NetworkScope::new(0x8000_0000, 0x8000_0000),
            "stacks-network-memory-test".to_owned(),
            &stacks_network_types::Libp2pLimits::default(),
        )
        .unwrap();
        network.max_process_memory_bytes = usize::MAX;
        network
    }

    #[tokio::test]
    async fn persistent_drain_timer_fires_while_another_branch_is_always_ready() {
        let mut drain = delayed_interval(Duration::from_millis(20));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                tokio::select! {
                    _ = drain.tick() => break,
                    _ = std::future::ready(()) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("persistent interval must not restart on each select iteration");
    }

    #[test]
    fn command_queue_age_advances_until_the_oldest_item_completes() {
        let tracker = CommandQueueTracker::default();
        let oldest = tracker.admit(Instant::now() - Duration::from_millis(25));
        let newer = tracker.admit(Instant::now());
        assert!(tracker.oldest_wait() >= Duration::from_millis(20));
        tracker.complete(oldest);
        assert!(tracker.oldest_wait() < Duration::from_millis(20));
        tracker.complete(newer);
        assert_eq!(tracker.oldest_wait(), Duration::ZERO);
    }

    #[test]
    fn signer_sync_protocol_supports_bounded_proposal_object_fetch() {
        assert_eq!(
            sync_capability_classes(stacks_network_types::CAP_SIGNER_V1),
            (true, true)
        );
        assert_eq!(
            sync_capability_classes(stacks_network_types::CAP_NODE_V1),
            (true, true)
        );
    }

    #[test]
    fn signer_replay_pagination_yields_to_downstream_backpressure() {
        assert!(should_continue_signer_replay(false, false));
        assert!(!should_continue_signer_replay(true, false));
        assert!(!should_continue_signer_replay(false, true));
        assert!(!should_continue_signer_replay(true, true));
    }

    #[test]
    fn deferred_sync_control_queue_is_fifo_per_peer_and_rejects_data_payloads() {
        let now = Instant::now();
        let first = PeerId::random();
        let second = PeerId::random();
        let status = |source, response_token| SyncNetworkEvent::InboundRequest {
            source,
            response_token,
            request: SyncRequest {
                request: Some(sync_request::Request::GetStatus(
                    stacks_network_types::wire::v1::GetStatus {},
                )),
            },
        };
        let inventory = |source, response_token| SyncNetworkEvent::InboundRequest {
            source,
            response_token,
            request: SyncRequest {
                request: Some(sync_request::Request::GetEpoch2Inventory(
                    stacks_network_types::wire::v1::GetEpoch2Inventory {
                        start_height: 1,
                        count: 8,
                    },
                )),
            },
        };
        let mut queue = DeferredSyncControlQueue::default();
        assert!(queue.admit(status(first, 1), now).is_ok());
        assert!(queue.admit(inventory(first, 2), now).is_err());
        assert!(queue.admit(inventory(second, 3), now).is_ok());

        let data_payload = SyncNetworkEvent::InboundRequest {
            source: PeerId::random(),
            response_token: 4,
            request: SyncRequest {
                request: Some(sync_request::Request::GetSignerReplay(
                    stacks_network_types::wire::v1::GetSignerReplay {
                        reward_cycle: 1,
                        cursors: Vec::new(),
                        max_items: 1,
                        max_bytes: 1024,
                    },
                )),
            },
        };
        assert!(queue.admit(data_payload, now).is_err());
        assert_eq!(queue.pop_front().unwrap().response_token, 1);
        assert_eq!(queue.pop_front().unwrap().response_token, 3);
        assert!(queue.is_empty());
    }

    #[test]
    fn redundant_valid_signer_gossip_is_neutral_not_rejected() {
        assert!(matches!(
            signer_gossip_acceptance(SignerAdmission::Duplicate),
            MessageAcceptance::Ignore
        ));
        assert!(matches!(
            signer_gossip_acceptance(SignerAdmission::Stale),
            MessageAcceptance::Ignore
        ));
        assert!(matches!(
            signer_gossip_acceptance(SignerAdmission::Equivocation),
            MessageAcceptance::Accept
        ));
    }

    fn command_test_handle(
        capacity: usize,
    ) -> (NetworkHandle, tokio_mpsc::Receiver<QueuedCommand>) {
        let (commands, receiver) = tokio_mpsc::channel(capacity);
        let (_, signer_events) = mpsc::sync_channel(1);
        let (_, object_events) = mpsc::sync_channel(1);
        let (_, sync_events) = mpsc::sync_channel(1);
        (
            NetworkHandle {
                commands,
                command_queue: Arc::new(CommandQueueTracker::default()),
                diagnostics: DiagnosticsHandle::new(PeerId::random()),
                signer_events: EventReceiver::new(signer_events, "signer"),
                object_events: EventReceiver::new(object_events, "object"),
                sync_events: EventReceiver::new(sync_events, "sync"),
                legacy_identities: Arc::new(Mutex::new(LegacyIdentityRegistry::default())),
            },
            receiver,
        )
    }

    #[test]
    fn network_handle_owns_bounded_command_admission_and_diagnostics() {
        let (handle, mut receiver) = command_test_handle(1);
        let address: Multiaddr = "/memory/51".parse().unwrap();
        handle.dial(address.clone()).unwrap();
        let error = handle.dial(address).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(handle.diagnostics().command_queue_full, 1);
        assert!(matches!(
            receiver.try_recv().unwrap().command,
            Command::Control(ControlCommand::Dial(_))
        ));

        drop(receiver);
        let error = handle.disconnect(PeerId::random()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(handle.diagnostics().command_queue_full, 1);
    }

    #[test]
    fn event_receiver_distinguishes_empty_from_closed() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let receiver = EventReceiver::new(receiver, "fixture");
        assert_eq!(receiver.try_next().unwrap(), None);
        sender.send(7_u8).unwrap();
        assert_eq!(receiver.try_next().unwrap(), Some(7));
        drop(sender);
        assert_eq!(
            receiver.try_next().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
    use crate::signer_identity_from_secret;

    static NEXT_MEMORY_PORT: AtomicU64 = AtomicU64::new(50_000);

    struct FixtureObjectValidator;

    impl NetworkObjectValidator for FixtureObjectValidator {
        fn validate_announcement(&self, announcement: &Announcement) -> Result<(), String> {
            if announcement.kind == ObjectKind::NakamotoBlock
                && announcement.canonical_metadata == b"canonical-header"
            {
                Ok(())
            } else {
                Err("invalid fixture announcement".to_owned())
            }
        }

        fn validate_object(&self, object: &NetworkObject) -> Result<(), String> {
            let expected = ContentId::from_domain_bytes(b"MEMORY_OBJECT_FIXTURE_V1", &object.bytes);
            if object.content_id == expected {
                Ok(())
            } else {
                Err("fixture content ID mismatch".to_owned())
            }
        }
    }

    fn fixture_object(kind: ObjectKind, bytes: &[u8]) -> NetworkObject {
        NetworkObject {
            kind,
            content_id: ContentId::from_domain_bytes(b"MEMORY_OBJECT_FIXTURE_V1", bytes),
            bytes: bytes.to_vec(),
        }
    }

    fn next_object_event(
        service: &NetworkService,
        deadline: std::time::Instant,
    ) -> ObjectNetworkEvent {
        loop {
            if let Some(event) = service.try_next_object_event().unwrap() {
                return event;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn hello(network: &NetworkConfig) -> Hello {
        Hello {
            envelope_version: 1,
            chain_id: network.chain_id,
            network_id: network.network_id,
            supported_protocol_versions: vec![1],
            peer_version: 1,
            capabilities: stacks_network_types::CAP_NODE_V1,
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
        }
    }

    fn directory_hello(network: &NetworkConfig) -> Hello {
        let mut value = hello(network);
        value.burn_tip_height = 110;
        value.current_reward_cycle = 7;
        value
    }

    #[test]
    fn invalid_service_configuration_fails_before_thread_start() {
        let network = signer_test_network();
        let identity = identity::Keypair::generate_secp256k1();
        let mut mismatched_hello = hello(&network);
        mismatched_hello.network_id ^= 1;
        let error = match NetworkService::spawn(
            ServiceConfig {
                identity,
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
                object_cache_bytes: crate::DEFAULT_OBJECT_CACHE_BYTES,
                hello: mismatched_hello,
            },
            "must-not-start-invalid-service",
        ) {
            Ok(service) => {
                service.shutdown().unwrap();
                panic!("invalid service configuration started a worker thread");
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    fn role_authorization(key: &StacksPrivateKey, signer_id: u32) -> RoleAuthorization {
        RoleAuthorization {
            role: Role::Signer,
            reward_cycle: 7,
            role_id: Some(signer_id.to_be_bytes().to_vec()),
            key: crate::AuthorizedRoleKey::PublicKey(
                StacksPublicKey::from_private(key)
                    .to_bytes_compressed()
                    .try_into()
                    .unwrap(),
            ),
        }
    }

    fn miner_role_authorization(key: &StacksPrivateKey) -> RoleAuthorization {
        let public_key = StacksPublicKey::from_private(key).to_bytes_compressed();
        RoleAuthorization {
            role: Role::Miner,
            reward_cycle: 7,
            role_id: Some(vec![3; 20]),
            key: crate::AuthorizedRoleKey::PublicKeyHash160(
                stacks_common::util::hash::Hash160::from_data(&public_key).0,
            ),
        }
    }

    fn role_record(
        key: &StacksPrivateKey,
        signer_id: u32,
        peer: &PeerId,
        address: &Multiaddr,
    ) -> RoleDirectoryRecord {
        let body = RoleProofBody {
            version: ROLE_PROOF_VERSION,
            chain_id: 0x8000_0000,
            network_id: 0x8000_0000,
            transport_peer_id: peer.to_bytes(),
            role: Role::Signer as i32,
            reward_cycle: 7,
            role_id: signer_id.to_be_bytes().to_vec(),
            valid_from_burn_height: 100,
            valid_until_burn_height: 119,
        };
        let proof = RoleProof {
            body: Some(body.clone()),
            stacks_public_key: StacksPublicKey::from_private(key).to_bytes_compressed(),
            stacks_signature: key
                .sign(&role_proof_digest(&body))
                .unwrap()
                .as_bytes()
                .to_vec(),
        };
        let mut record = RoleDirectoryRecord {
            proof: Some(proof),
            addresses: vec![address.to_vec()],
            record_signature: vec![0; 65],
        };
        record.record_signature = key
            .sign(&directory_record_digest(&record).unwrap())
            .unwrap()
            .as_bytes()
            .to_vec();
        record
    }

    fn envelope(
        signer_key: &StacksPrivateKey,
        peer_id: &PeerId,
        network: &NetworkConfig,
        sequence: u64,
    ) -> SignerEnvelope {
        let body = SignerEnvelopeBody {
            version: SIGNER_ENVELOPE_VERSION,
            chain_id: network.chain_id,
            network_id: network.network_id,
            reward_cycle: 9,
            lane: SignerLane::StateMachineUpdate as i32,
            sequence,
            previous_envelope_id: Vec::new(),
            signer_public_key: StacksPublicKey::from_private(signer_key).to_bytes_compressed(),
            transport_peer_id: peer_id.to_bytes(),
            payload: vec![6, sequence as u8],
            burn_view_consensus_hash: vec![3; 20],
            proposal_manifest: None,
        };
        let signature = signer_key.sign(&signer_envelope_digest(&body)).unwrap();
        SignerEnvelope {
            body: Some(body),
            signature: signature.as_bytes().to_vec(),
        }
    }

    #[test]
    fn authoritative_authorization_snapshot_is_monotonic_and_acknowledged() {
        let network = signer_test_network();
        let identity =
            crate::node_identity_from_seed(b"authorization-ack-service", network.scope()).unwrap();
        let signer_key = StacksPrivateKey::from_seed(&[76; 32]);
        let authorization = RoleAuthorization {
            role: Role::Signer,
            reward_cycle: 9,
            role_id: None,
            key: crate::AuthorizedRoleKey::PublicKey(
                StacksPublicKey::from_private(&signer_key)
                    .to_bytes_compressed()
                    .try_into()
                    .unwrap(),
            ),
        };
        let service = NetworkService::spawn(
            ServiceConfig {
                identity,
                network: network.clone(),
                transport: TransportProfile::Memory,
                listen_addresses: Vec::new(),
                bootstrap_addresses: Vec::new(),
                peer_store: None,
                private_rendezvous_peers: Vec::new(),
                role_authorizations: vec![authorization.clone()],
                local_role_record: None,
                initial_role_records: Vec::new(),
                initial_signer_envelopes: Vec::new(),
                object_validator: None,
                object_cache_bytes: crate::DEFAULT_OBJECT_CACHE_BYTES,
                hello: hello(&network),
            },
            "authorization-ack-service",
        )
        .unwrap();

        assert!(matches!(
            service
                .handle()
                .apply_authorization_snapshot(
                    AuthorizationSnapshot::new(1, 9, None, [authorization.clone()]).unwrap()
                )
                .unwrap(),
            crate::AuthorizationSnapshotUpdate::Unchanged { generation: 1, .. }
        ));
        assert!(service
            .handle()
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 9, None, Vec::new()).unwrap()
            )
            .is_err());
        assert!(matches!(
            service
                .handle()
                .apply_authorization_snapshot(
                    AuthorizationSnapshot::new(0, 9, None, [authorization]).unwrap()
                )
                .unwrap(),
            crate::AuthorizationSnapshotUpdate::Stale {
                applied_generation: 1,
                received_generation: 0
            }
        ));
    }

    #[test]
    fn memory_services_fail_closed_then_deliver_chainstate_authorized_lane() {
        let network = signer_test_network();
        let alice_key = StacksPrivateKey::from_seed(&[41; 32]);
        let bob_key = StacksPrivateKey::from_seed(&[42; 32]);
        let alice_identity = signer_identity_from_secret(
            alice_key.to_bytes()[..32].try_into().unwrap(),
            network.scope(),
        )
        .unwrap();
        let bob_identity = signer_identity_from_secret(
            bob_key.to_bytes()[..32].try_into().unwrap(),
            network.scope(),
        )
        .unwrap();
        let alice_peer_id = alice_identity.public().to_peer_id();
        let bob_peer_id = bob_identity.public().to_peer_id();
        let listen: Multiaddr = format!(
            "/memory/{}",
            NEXT_MEMORY_PORT.fetch_add(1, Ordering::Relaxed)
        )
        .parse()
        .unwrap();
        let bootstrap: Multiaddr = format!("{listen}/p2p/{alice_peer_id}").parse().unwrap();
        let alice = NetworkService::spawn(
            ServiceConfig {
                identity: alice_identity,
                network: network.clone(),
                transport: TransportProfile::Memory,
                listen_addresses: vec![listen],
                bootstrap_addresses: Vec::new(),
                peer_store: None,
                private_rendezvous_peers: Vec::new(),
                role_authorizations: Vec::new(),
                local_role_record: None,
                initial_role_records: Vec::new(),
                initial_signer_envelopes: Vec::new(),
                object_validator: None,
                object_cache_bytes: crate::DEFAULT_OBJECT_CACHE_BYTES,
                hello: hello(&network),
            },
            "memory-service-alice",
        )
        .unwrap();
        let bob = NetworkService::spawn(
            ServiceConfig {
                identity: bob_identity,
                network: network.clone(),
                transport: TransportProfile::Memory,
                listen_addresses: Vec::new(),
                bootstrap_addresses: vec![bootstrap.clone()],
                peer_store: None,
                private_rendezvous_peers: vec![alice_peer_id],
                role_authorizations: Vec::new(),
                local_role_record: None,
                initial_role_records: Vec::new(),
                initial_signer_envelopes: Vec::new(),
                object_validator: None,
                object_cache_bytes: crate::DEFAULT_OBJECT_CACHE_BYTES,
                hello: hello(&network),
            },
            "memory-service-bob",
        )
        .unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while (alice.diagnostics().connected_peers.is_empty()
            || bob.diagnostics().connected_peers.is_empty())
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            alice.diagnostics().connected_peers,
            vec![bob_peer_id.to_string()]
        );

        bob.publish_signer(envelope(&bob_key, &bob_peer_id, &network, 0))
            .unwrap();
        let rejected_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while alice.diagnostics().rejected_signer_messages == 0
            && std::time::Instant::now() < rejected_deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(alice.diagnostics().rejected_signer_messages, 1);
        assert!(alice.diagnostics().signer_observations.is_empty());
        assert!(alice.try_next_signer_event().unwrap().is_none());

        let bob_public_key: [u8; 33] = StacksPublicKey::from_private(&bob_key)
            .to_bytes_compressed()
            .try_into()
            .unwrap();
        let alice_public_key: [u8; 33] = StacksPublicKey::from_private(&alice_key)
            .to_bytes_compressed()
            .try_into()
            .unwrap();
        alice
            .update_authorized_signers(9, vec![bob_public_key])
            .unwrap();
        alice.retain_signer_cycles(9, Some(10)).unwrap();
        bob.update_authorized_signers(9, vec![alice_public_key])
            .unwrap();
        bob.retain_signer_cycles(9, Some(10)).unwrap();
        bob.publish_signer(envelope(&bob_key, &bob_peer_id, &network, 1))
            .unwrap();
        let received_deadline = std::time::Instant::now() + Duration::from_secs(5);
        let received = loop {
            if let Some(event) = alice.try_next_signer_event().unwrap() {
                break event;
            }
            assert!(std::time::Instant::now() < received_deadline);
            std::thread::sleep(Duration::from_millis(20));
        };
        let received_envelope = received.envelope;
        assert_eq!(received_envelope.body.sequence, 1);
        let observations = alice.diagnostics().signer_observations;
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].reward_cycle, 9);
        assert_eq!(observations[0].signer_public_key, bob_public_key);
        assert_eq!(observations[0].sequence, 1);
        assert!(!observations[0].equivocation);

        // Alice learned Bob's reward-set-bound PeerId from the accepted event,
        // so the reverse state update uses bounded direct redundancy as well as
        // GossipSub. The receiver still emits exactly one semantic event.
        alice
            .publish_signer(envelope(&alice_key, &alice_peer_id, &network, 0))
            .unwrap();
        let direct_deadline = std::time::Instant::now() + Duration::from_secs(5);
        let direct_received = loop {
            if let Some(event) = bob.try_next_signer_event().unwrap() {
                break event;
            }
            assert!(std::time::Instant::now() < direct_deadline);
            std::thread::sleep(Duration::from_millis(20));
        };
        let direct_envelope = direct_received.envelope;
        assert_eq!(direct_envelope.body.sequence, 0);
        while bob.diagnostics().direct_signer_messages_received == 0
            && std::time::Instant::now() < direct_deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(alice.diagnostics().direct_signer_messages_sent > 0);
        assert!(bob.diagnostics().direct_signer_messages_received > 0);

        // Miner/coordinator refreshes may submit the unchanged canonical
        // reward set. This must not revoke Bob's already-proven PeerId binding.
        alice
            .update_authorized_signers(9, vec![bob_public_key])
            .unwrap();

        // A signer may reconnect with a new transport identity while its
        // reward-set key remains authorized. Exercise the real Noise/Yamux
        // connection and require the signer behaviour to atomically move the
        // binding, close the superseded connection, and retain lane history.
        let rekeyed_identity =
            crate::node_identity_from_seed(b"memory-service-bob-rekeyed", network.scope()).unwrap();
        let rekeyed_peer_id = rekeyed_identity.public().to_peer_id();
        let rekeyed = NetworkService::spawn(
            ServiceConfig {
                identity: rekeyed_identity,
                network: network.clone(),
                transport: TransportProfile::Memory,
                listen_addresses: Vec::new(),
                bootstrap_addresses: vec![bootstrap],
                peer_store: None,
                private_rendezvous_peers: vec![alice_peer_id],
                role_authorizations: Vec::new(),
                local_role_record: None,
                initial_role_records: Vec::new(),
                initial_signer_envelopes: Vec::new(),
                object_validator: None,
                object_cache_bytes: crate::DEFAULT_OBJECT_CACHE_BYTES,
                hello: hello(&network),
            },
            "memory-service-bob-rekeyed",
        )
        .unwrap();
        rekeyed
            .update_authorized_signers(9, vec![alice_public_key])
            .unwrap();
        rekeyed.retain_signer_cycles(9, Some(10)).unwrap();
        let rekey_deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !alice
            .diagnostics()
            .connected_peers
            .contains(&rekeyed_peer_id.to_string())
            && std::time::Instant::now() < rekey_deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        rekeyed
            .publish_signer(envelope(&bob_key, &rekeyed_peer_id, &network, 2))
            .unwrap();
        loop {
            if let Some(event) = alice.try_next_signer_event().unwrap() {
                assert_eq!(event.envelope.body.sequence, 2);
                assert_eq!(event.source, rekeyed_peer_id);
                break;
            }
            assert!(std::time::Instant::now() < rekey_deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
        while alice
            .diagnostics()
            .connected_peers
            .contains(&bob_peer_id.to_string())
            && std::time::Instant::now() < rekey_deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let connected = alice.diagnostics().connected_peers;
        assert!(connected.contains(&rekeyed_peer_id.to_string()));
        assert!(!connected.contains(&bob_peer_id.to_string()));

        rekeyed.shutdown().unwrap();
        bob.shutdown().unwrap();
        alice.shutdown().unwrap();
    }

    #[test]
    fn memory_miner_privately_introduces_signers_and_replays_after_late_sortition_auth() {
        let network = signer_test_network();
        let miner_identity = identity::Keypair::generate_secp256k1();
        let miner_peer = miner_identity.public().to_peer_id();
        let miner_message_key = StacksPrivateKey::from_seed(&[60; 32]);
        let bob_key = StacksPrivateKey::from_seed(&[61; 32]);
        let carol_key = StacksPrivateKey::from_seed(&[62; 32]);
        let bob_identity = signer_identity_from_secret(
            bob_key.to_bytes()[..32].try_into().unwrap(),
            network.scope(),
        )
        .unwrap();
        let carol_identity = signer_identity_from_secret(
            carol_key.to_bytes()[..32].try_into().unwrap(),
            network.scope(),
        )
        .unwrap();
        let bob_peer = bob_identity.public().to_peer_id();
        let carol_peer = carol_identity.public().to_peer_id();
        let miner_listen: Multiaddr = format!(
            "/memory/{}",
            NEXT_MEMORY_PORT.fetch_add(1, Ordering::Relaxed)
        )
        .parse()
        .unwrap();
        let bob_listen: Multiaddr = format!(
            "/memory/{}",
            NEXT_MEMORY_PORT.fetch_add(1, Ordering::Relaxed)
        )
        .parse()
        .unwrap();
        let carol_listen: Multiaddr = format!(
            "/memory/{}",
            NEXT_MEMORY_PORT.fetch_add(1, Ordering::Relaxed)
        )
        .parse()
        .unwrap();
        let miner_bootstrap: Multiaddr =
            format!("{miner_listen}/p2p/{miner_peer}").parse().unwrap();
        let authorizations = vec![
            role_authorization(&bob_key, 0),
            role_authorization(&carol_key, 1),
            miner_role_authorization(&miner_message_key),
        ];
        let carol_authorizations = authorizations
            .iter()
            .filter(|authorization| authorization.role != Role::Miner)
            .cloned()
            .collect();
        let miner_role_record = crate::signed_role_directory_record(
            network.scope(),
            miner_peer,
            Role::Miner,
            7,
            vec![3; 20],
            100,
            119,
            [miner_listen.clone()],
            &miner_message_key,
        )
        .unwrap();

        let miner = NetworkService::spawn(
            ServiceConfig {
                identity: miner_identity,
                network: network.clone(),
                transport: TransportProfile::Memory,
                listen_addresses: vec![miner_listen],
                bootstrap_addresses: Vec::new(),
                peer_store: None,
                private_rendezvous_peers: Vec::new(),
                role_authorizations: authorizations.clone(),
                local_role_record: Some(miner_role_record),
                initial_role_records: Vec::new(),
                initial_signer_envelopes: Vec::new(),
                object_validator: None,
                object_cache_bytes: crate::DEFAULT_OBJECT_CACHE_BYTES,
                hello: directory_hello(&network),
            },
            "memory-directory-miner",
        )
        .unwrap();
        let bob = NetworkService::spawn(
            ServiceConfig {
                identity: bob_identity,
                network: network.clone(),
                transport: TransportProfile::Memory,
                listen_addresses: vec![bob_listen.clone()],
                bootstrap_addresses: vec![miner_bootstrap.clone()],
                peer_store: None,
                private_rendezvous_peers: vec![miner_peer],
                role_authorizations: authorizations.clone(),
                local_role_record: Some(role_record(&bob_key, 0, &bob_peer, &bob_listen)),
                initial_role_records: Vec::new(),
                initial_signer_envelopes: Vec::new(),
                object_validator: None,
                object_cache_bytes: crate::DEFAULT_OBJECT_CACHE_BYTES,
                hello: directory_hello(&network),
            },
            "memory-directory-bob",
        )
        .unwrap();
        // Bob publishes current-cycle state before Carol exists. A late joiner
        // must recover it from the bounded author/miner journal, not from
        // GossipSub history or a StackerDB poll.
        let mut retained = envelope(&bob_key, &bob_peer, &network, 3);
        retained.body.as_mut().unwrap().reward_cycle = 7;
        retained.signature = bob_key
            .sign(&signer_envelope_digest(retained.body.as_ref().unwrap()))
            .unwrap()
            .as_bytes()
            .to_vec();
        bob.publish_signer(retained).unwrap();
        let retained_deadline = std::time::Instant::now() + Duration::from_secs(10);
        while miner.try_next_signer_event().unwrap().is_none()
            && std::time::Instant::now() < retained_deadline
        {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(miner.diagnostics().received_signer_messages > 0);

        // Publish a miner proposal before Carol exists. GossipSub has no
        // history, and Carol has not yet authenticated a signer role, so the
        // miner's bounded direct mailbox must retain it for late delivery.
        let mut retained_proposal = envelope(&miner_message_key, &miner_peer, &network, 0);
        {
            let body = retained_proposal.body.as_mut().unwrap();
            body.reward_cycle = 7;
            body.lane = SignerLane::BlockProposal as i32;
            body.payload.clear();
            body.proposal_manifest = Some(ProposalManifest {
                version: PROPOSAL_MANIFEST_VERSION,
                content_id: ContentId::from_bytes([0xaa; 32]).as_bytes().to_vec(),
                encoded_len: 2,
                signer_signature_hash: vec![0xbb; 32],
                burn_height: 100,
                reward_cycle: 7,
            });
        }
        retained_proposal.signature = miner_message_key
            .sign(&signer_envelope_digest(
                retained_proposal.body.as_ref().unwrap(),
            ))
            .unwrap()
            .as_bytes()
            .to_vec();
        miner.publish_signer(retained_proposal).unwrap();

        let carol = NetworkService::spawn(
            ServiceConfig {
                identity: carol_identity,
                network: network.clone(),
                transport: TransportProfile::Memory,
                listen_addresses: vec![carol_listen.clone()],
                bootstrap_addresses: vec![miner_bootstrap],
                peer_store: None,
                private_rendezvous_peers: vec![miner_peer],
                // Model the production race in which Noise/Hello and the
                // proposal arrive before Carol's companion has applied the
                // new canonical sortition. The miner record is initially
                // rejected and must cause a replay once authorization lands.
                role_authorizations: carol_authorizations,
                local_role_record: Some(role_record(&carol_key, 1, &carol_peer, &carol_listen)),
                initial_role_records: Vec::new(),
                initial_signer_envelopes: Vec::new(),
                object_validator: None,
                object_cache_bytes: crate::DEFAULT_OBJECT_CACHE_BYTES,
                hello: directory_hello(&network),
            },
            "memory-directory-carol",
        )
        .unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while (!bob
            .diagnostics()
            .connected_peers
            .contains(&carol_peer.to_string())
            || !carol
                .diagnostics()
                .connected_peers
                .contains(&bob_peer.to_string()))
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(bob
            .diagnostics()
            .connected_peers
            .contains(&carol_peer.to_string()));
        assert!(carol
            .diagnostics()
            .connected_peers
            .contains(&bob_peer.to_string()));

        // The retained proposal must first reach the production downstream as
        // availability-only evidence. It is the exact same signed envelope
        // that will be released after the companion-derived snapshot lands.
        let pending_deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut replayed_before_authorization = None;
        let pending_proposal = loop {
            if let Some(event) = carol.try_next_signer_event().unwrap() {
                match SignerLane::try_from(event.envelope.body.lane).unwrap() {
                    SignerLane::BlockProposal => break event,
                    SignerLane::StateMachineUpdate if event.envelope.body.sequence == 3 => {
                        replayed_before_authorization = Some(event);
                    }
                    _ => {}
                }
            }
            assert!(std::time::Instant::now() < pending_deadline);
            std::thread::sleep(Duration::from_millis(25));
        };
        assert_eq!(
            pending_proposal.canonical_authorization,
            SignerCanonicalAuthorization::Pending
        );
        let pending_envelope_id = pending_proposal.envelope.envelope_id;

        let miner_public_key =
            StacksPublicKey::from_private(&miner_message_key).to_bytes_compressed();
        carol
            .update_authorized_miners(
                7,
                vec![(
                    vec![3; 20],
                    stacks_common::util::hash::Hash160::from_data(&miner_public_key).0,
                )],
            )
            .unwrap();
        assert!(miner.diagnostics().directory_queries_received >= 2);
        assert!(miner.diagnostics().directory_records_accepted >= 2);
        assert!(bob.diagnostics().directory_records_accepted >= 1);
        assert!(carol.diagnostics().directory_records_accepted >= 1);

        let mut carol_state = envelope(&carol_key, &carol_peer, &network, 0);
        carol_state.body.as_mut().unwrap().reward_cycle = 7;
        carol_state.signature = carol_key
            .sign(&signer_envelope_digest(carol_state.body.as_ref().unwrap()))
            .unwrap()
            .as_bytes()
            .to_vec();
        carol.publish_signer(carol_state).unwrap();

        let replay_deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut replayed = replayed_before_authorization;
        let mut late_proposal = None;
        while replayed.is_none() || late_proposal.is_none() {
            if let Some(event) = carol.try_next_signer_event().unwrap() {
                match SignerLane::try_from(event.envelope.body.lane).unwrap() {
                    SignerLane::StateMachineUpdate if event.envelope.body.sequence == 3 => {
                        replayed = Some(event)
                    }
                    SignerLane::BlockProposal => {
                        assert_eq!(
                            event.canonical_authorization,
                            SignerCanonicalAuthorization::Confirmed
                        );
                        assert_eq!(event.envelope.envelope_id, pending_envelope_id);
                        late_proposal = Some(event);
                    }
                    _ => {}
                }
            }
            assert!(std::time::Instant::now() < replay_deadline);
            std::thread::sleep(Duration::from_millis(25));
        }
        let replayed = replayed.unwrap();
        let late_proposal = late_proposal.unwrap();
        assert_eq!(replayed.envelope.body.reward_cycle, 7);
        assert_eq!(replayed.envelope.body.sequence, 3);
        assert_eq!(late_proposal.source, miner_peer);
        assert!(late_proposal.envelope.body.payload.is_empty());
        assert_eq!(
            late_proposal
                .envelope
                .body
                .proposal_manifest
                .as_ref()
                .unwrap()
                .encoded_len,
            2
        );
        assert!(carol.diagnostics().signer_replay_requests_sent > 0);
        assert!(carol.diagnostics().signer_replay_envelopes_received > 0);
        assert!(
            bob.diagnostics().signer_replay_envelopes_served
                + miner.diagnostics().signer_replay_envelopes_served
                > 0,
            "one authenticated replay provider must serve the reconstructed state"
        );
        assert!(miner.diagnostics().direct_signer_messages_sent >= 2);
        let diagnostics = carol.diagnostics();
        assert_eq!(diagnostics.deferred_miner_authorizations, 1);
        assert_eq!(diagnostics.deferred_miner_authorizations_pending, 0);
        assert_eq!(
            diagnostics.deferred_miner_authorization_observations_delivered,
            1
        );
        assert_eq!(diagnostics.deferred_miner_authorizations_released, 1);
        assert_eq!(diagnostics.deferred_miner_authorizations_expired, 0);
        assert_eq!(diagnostics.deferred_miner_authorizations_unauthorized, 0);
        assert_eq!(diagnostics.deferred_miner_authorizations_redundant, 0);
        assert_eq!(diagnostics.deferred_miner_authorizations_binding_failed, 0);
        assert_eq!(diagnostics.deferred_miner_authorizations_malformed, 0);

        carol.shutdown().unwrap();
        bob.shutdown().unwrap();
        miner.shutdown().unwrap();
    }

    #[test]
    fn memory_services_fetch_announcements_direct_push_blocks_and_gossip_transactions() {
        let mut alice_network = NetworkConfig::regtest();
        alice_network.max_process_memory_bytes = usize::MAX;
        alice_network.direct_push_fanout = 0;
        let mut bob_network = alice_network.clone();
        bob_network.direct_push_fanout = 1;
        bob_network.max_inflight_requests_per_peer = 1;
        let alice_identity = identity::Keypair::generate_secp256k1();
        let bob_identity = identity::Keypair::generate_secp256k1();
        let alice_peer = alice_identity.public().to_peer_id();
        let bob_peer = bob_identity.public().to_peer_id();
        let listen: Multiaddr = format!(
            "/memory/{}",
            NEXT_MEMORY_PORT.fetch_add(1, Ordering::Relaxed)
        )
        .parse()
        .unwrap();
        let bootstrap: Multiaddr = format!("{listen}/p2p/{alice_peer}").parse().unwrap();
        let service_config =
            |identity, network: NetworkConfig, listen_addresses, bootstrap_addresses| {
                ServiceConfig {
                    identity,
                    hello: hello(&network),
                    network,
                    transport: TransportProfile::Memory,
                    listen_addresses,
                    bootstrap_addresses,
                    peer_store: None,
                    private_rendezvous_peers: Vec::new(),
                    role_authorizations: Vec::new(),
                    local_role_record: None,
                    initial_role_records: Vec::new(),
                    initial_signer_envelopes: Vec::new(),
                    object_validator: Some(Arc::new(FixtureObjectValidator)),
                    object_cache_bytes: crate::DEFAULT_OBJECT_CACHE_BYTES,
                }
            };
        let alice = NetworkService::spawn(
            service_config(alice_identity, alice_network, vec![listen], Vec::new()),
            "memory-object-alice",
        )
        .unwrap();
        let bob = NetworkService::spawn(
            service_config(bob_identity, bob_network, Vec::new(), vec![bootstrap]),
            "memory-object-bob",
        )
        .unwrap();

        let connected_deadline = std::time::Instant::now() + Duration::from_secs(10);
        while (alice.diagnostics().successful_hellos == 0
            || bob.diagnostics().successful_hellos == 0)
            && std::time::Instant::now() < connected_deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            alice.diagnostics().connected_peers,
            vec![bob_peer.to_string()]
        );
        // Give the signed GossipSub mesh heartbeat time to install subscriptions.
        std::thread::sleep(Duration::from_secs(2));

        let fetched = fixture_object(ObjectKind::NakamotoBlock, b"announcement-fetch");
        alice.publish_object(fetched.clone()).unwrap();
        alice
            .announce_object(Announcement {
                kind: ObjectKind::NakamotoBlock,
                content_id: fetched.content_id,
                canonical_metadata: b"canonical-header".to_vec(),
            })
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut saw_announcement = false;
        let mut saw_fetched = false;
        while !(saw_announcement && saw_fetched) {
            match next_object_event(&bob, deadline) {
                ObjectNetworkEvent::Announcement { announcement, .. } => {
                    assert_eq!(announcement.content_id, fetched.content_id);
                    saw_announcement = true;
                }
                ObjectNetworkEvent::Object {
                    object,
                    direct_push,
                    ..
                } => {
                    assert_eq!(object, fetched);
                    assert!(!direct_push);
                    saw_fetched = true;
                }
                ObjectNetworkEvent::Request { .. } => {
                    panic!("fetching peer unexpectedly received a provider lookup")
                }
            }
        }

        let pushed = fixture_object(ObjectKind::NakamotoBlock, b"bounded-direct-push");
        bob.publish_object(pushed.clone()).unwrap();
        match next_object_event(&alice, std::time::Instant::now() + Duration::from_secs(10)) {
            ObjectNetworkEvent::Object {
                object,
                direct_push,
                ..
            } => {
                assert_eq!(object, pushed);
                assert!(direct_push);
            }
            event => panic!("expected direct object push, got {event:?}"),
        }

        let transaction = fixture_object(ObjectKind::Transaction, b"small-transaction");
        alice.publish_object(transaction.clone()).unwrap();
        match next_object_event(&bob, std::time::Instant::now() + Duration::from_secs(10)) {
            ObjectNetworkEvent::Object {
                object,
                direct_push,
                ..
            } => {
                assert_eq!(object, transaction);
                assert!(!direct_push);
            }
            event => panic!("expected transaction gossip, got {event:?}"),
        }

        let inventory_selected = fixture_object(ObjectKind::Attachment, b"inventory-selected");
        alice.publish_object(inventory_selected.clone()).unwrap();
        // Publication and explicit fetch are independent service command
        // queues; allow the provider to commit before the request arrives.
        std::thread::sleep(Duration::from_millis(50));
        bob.request_object(
            alice_peer,
            inventory_selected.kind,
            inventory_selected.content_id,
        )
        .unwrap();
        match next_object_event(&bob, std::time::Instant::now() + Duration::from_secs(10)) {
            ObjectNetworkEvent::Object {
                object,
                direct_push,
                ..
            } => {
                assert_eq!(object, inventory_selected);
                assert!(!direct_push);
            }
            event => panic!("expected explicit inventory object fetch, got {event:?}"),
        }

        // A historical inventory page may describe more objects than a peer's
        // stream window. Exercise real Noise/Yamux memory transport with a
        // one-request window and prove that overflow is bounded/deferred, not
        // silently discarded as it was in the heavyweight legacy harness.
        let deferred = (0..4)
            .map(|index| {
                fixture_object(
                    ObjectKind::AnchoredBlock,
                    format!("deferred-inventory-{index}").as_bytes(),
                )
            })
            .collect::<Vec<_>>();
        for object in &deferred {
            alice.publish_object(object.clone()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(100));
        for object in &deferred {
            bob.request_object(alice_peer, object.kind, object.content_id)
                .unwrap();
        }
        let mut received = HashSet::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while received.len() < deferred.len() {
            match next_object_event(&bob, deadline) {
                ObjectNetworkEvent::Object { object, .. } => {
                    received.insert(object.content_id);
                }
                event => panic!("expected deferred inventory object, got {event:?}"),
            }
        }
        assert_eq!(received.len(), deferred.len());
        assert_eq!(bob.diagnostics().object_fetch_failures, 0);
        assert!(bob.diagnostics().max_object_fetches_deferred > 0);

        let durable_only = fixture_object(ObjectKind::AnchoredBlock, b"durable-only");
        bob.request_object(alice_peer, durable_only.kind, durable_only.content_id)
            .unwrap();
        let provider_request =
            next_object_event(&alice, std::time::Instant::now() + Duration::from_secs(10));
        let ObjectNetworkEvent::Request {
            source,
            response_token,
            kind,
            id,
        } = provider_request
        else {
            panic!("expected durable provider lookup, got {provider_request:?}")
        };
        assert_eq!(source, bob_peer);
        assert_eq!(kind, durable_only.kind);
        assert_eq!(id, durable_only.content_id);
        alice
            .respond_object(response_token, Some(durable_only.clone()))
            .unwrap();
        match next_object_event(&bob, std::time::Instant::now() + Duration::from_secs(10)) {
            ObjectNetworkEvent::Object { object, .. } => assert_eq!(object, durable_only),
            event => panic!("expected durable object response, got {event:?}"),
        }

        bob.shutdown().unwrap();
        alice.shutdown().unwrap();
    }

    #[test]
    fn memory_services_exchange_typed_sync_requests_without_blocking_swarm() {
        use stacks_network_types::wire::v1::{sync_request, sync_response, GetStatus, SyncStatus};

        let network = signer_test_network();
        let alice_identity = identity::Keypair::generate_secp256k1();
        let bob_identity = identity::Keypair::generate_secp256k1();
        let alice_peer = alice_identity.public().to_peer_id();
        let bob_peer = bob_identity.public().to_peer_id();
        let listen: Multiaddr = format!(
            "/memory/{}",
            NEXT_MEMORY_PORT.fetch_add(1, Ordering::Relaxed)
        )
        .parse()
        .unwrap();
        let bootstrap: Multiaddr = format!("{listen}/p2p/{alice_peer}").parse().unwrap();
        let service_config = |identity, listen_addresses, bootstrap_addresses| ServiceConfig {
            identity,
            hello: hello(&network),
            network: network.clone(),
            transport: TransportProfile::Memory,
            listen_addresses,
            bootstrap_addresses,
            peer_store: None,
            private_rendezvous_peers: Vec::new(),
            role_authorizations: Vec::new(),
            local_role_record: None,
            initial_role_records: Vec::new(),
            initial_signer_envelopes: Vec::new(),
            object_validator: None,
            object_cache_bytes: crate::DEFAULT_OBJECT_CACHE_BYTES,
        };
        let alice = NetworkService::spawn(
            service_config(alice_identity, vec![listen], Vec::new()),
            "memory-sync-alice",
        )
        .unwrap();
        let bob = NetworkService::spawn(
            service_config(bob_identity, Vec::new(), vec![bootstrap]),
            "memory-sync-bob",
        )
        .unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while (alice.diagnostics().successful_hellos == 0
            || bob.diagnostics().successful_hellos == 0)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            bob.diagnostics().sync_capable_peers,
            vec![alice_peer.to_string()]
        );
        assert_eq!(
            bob.diagnostics().object_sync_capable_peers,
            vec![alice_peer.to_string()]
        );

        bob.request_sync(
            alice_peer,
            SyncRequest {
                request: Some(sync_request::Request::GetStatus(GetStatus {})),
            },
        )
        .unwrap();

        let response_token = loop {
            if let Some(SyncNetworkEvent::InboundRequest {
                source,
                response_token,
                request,
            }) = alice.try_next_sync_event().unwrap()
            {
                assert_eq!(source, bob_peer);
                assert!(matches!(
                    request.request,
                    Some(sync_request::Request::GetStatus(_))
                ));
                break response_token;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        };

        let expected = SyncStatus {
            burn_tip_height: 42,
            burn_tip_hash: vec![1; 32],
            stable_burn_tip_height: 40,
            stable_burn_tip_hash: vec![2; 32],
            stacks_tip_height: 17,
            stacks_tip_id: vec![3; 32],
            current_reward_cycle: 9,
        };
        alice
            .respond_sync(
                response_token,
                SyncResponse {
                    status: Status::Ok as i32,
                    response: Some(sync_response::Response::StatusView(expected.clone())),
                },
            )
            .unwrap();

        loop {
            if let Some(SyncNetworkEvent::Response {
                source, response, ..
            }) = bob.try_next_sync_event().unwrap()
            {
                assert_eq!(source, alice_peer);
                assert_eq!(
                    response.response,
                    Some(sync_response::Response::StatusView(expected))
                );
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }

        bob.shutdown().unwrap();
        alice.shutdown().unwrap();
    }
}
