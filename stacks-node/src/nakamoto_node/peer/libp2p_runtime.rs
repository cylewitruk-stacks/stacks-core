//! Node-owned adapter between coherent `PeerThread` state and the native
//! libp2p service.
//!
//! `PeerThread` remains responsible for incumbent P2P/HTTP scheduling and the
//! relayer handoff. This runtime owns only native publication, ingress,
//! semantic-sync lifecycle state.

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::PeerId;
use stacks::burnchains::Burnchain;
use stacks::burnchains::Txid;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::coordinator::OnChainRewardSetProvider;
use stacks::chainstate::nakamoto::coordinator::load_nakamoto_reward_set;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::core::mempool::MemPoolDB;
use stacks::net::atlas::Attachment;
use stacks::net::p2p::PeerNetwork;
use stacks::net::semantic::{
    AttachmentSyncService, MempoolSyncService, RelayerIngressAdapter, RelayerIngressOutcome,
};
use stacks::net::sync_plan::{NakamotoSyncStep, SyncStage};
use stacks::net::NetworkResult;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::Hash160;
use stacks_network::{NetworkHandle, ObjectNetworkEvent, SyncNetworkEvent};
use stacks_network_types::wire::v1::{
    sync_request, sync_response, AttachmentInventoryPage, GetAttachmentInventory,
    GetEpoch2Inventory, GetMempoolPage, GetPoxInventory, GetStatus, GetTenureInventory,
    InventoryItem, InventoryPage, LegacyIdentityBinding, MempoolPage, ObjectType, Status,
    SyncRequest, SyncResponse, SyncStatus,
};
use stacks_network_types::{ContentId, NetworkObject, ObjectKind, RewardCycleWindow, SyncHorizons};

const AUTHORIZATION_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_OBJECTS_PER_PASS: usize = 256;
const MAX_SYNC_REQUESTS_PER_PASS: usize = 64;
const SYNC_PAGE_ITEMS: u32 = 8;
const SYNC_PROBE_INTERVAL: Duration = Duration::from_secs(30);
const SYNC_HEDGE_DELAY: Duration = Duration::from_secs(2);
const SYNC_MAX_CONCURRENCY: usize = 2;

fn sync_cycle_horizons(
    local_signing_cycle: u64,
    local_signing_cycle_reward_boundary: u64,
    processed_burn_height: u64,
    remote_cycle: u64,
) -> SyncHorizons {
    let local_pox_cycle = if local_signing_cycle_reward_boundary > processed_burn_height {
        local_signing_cycle.saturating_sub(1)
    } else {
        local_signing_cycle
    };
    SyncHorizons {
        pox_through_cycle: remote_cycle.min(local_pox_cycle),
        tenure_through_cycle: remote_cycle.min(local_signing_cycle),
    }
}

fn signer_authorization_cycle_window(
    current_cycle: u64,
    is_nakamoto_signing_cycle_start: bool,
) -> RewardCycleWindow {
    if current_cycle > 0 && is_nakamoto_signing_cycle_start {
        RewardCycleWindow::previous_and_current(current_cycle)
    } else {
        RewardCycleWindow::current_and_next(current_cycle)
    }
}

#[derive(Default)]
struct PendingSyncRequests {
    entries: HashMap<u64, (NakamotoSyncStep, Instant)>,
    next_correlation: u64,
}

impl PendingSyncRequests {
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn expire(&mut self, now: Instant, max_age: Duration) {
        self.entries
            .retain(|_, (_, sent_at)| now.saturating_duration_since(*sent_at) < max_age);
    }

    fn correlation_candidate(&self) -> u64 {
        self.next_correlation
    }

    fn install_accepted(&mut self, plan: NakamotoSyncStep, sent_at: Instant) -> u64 {
        let correlation = self.next_correlation;
        self.next_correlation = self.next_correlation.wrapping_add(1);
        self.entries.insert(correlation, (plan, sent_at));
        correlation
    }

    fn remove(&mut self, correlation: u64) -> Option<NakamotoSyncStep> {
        self.entries.remove(&correlation).map(|(plan, _)| plan)
    }

    fn remove_stage(&mut self, predicate: impl Fn(&SyncStage) -> bool) {
        self.entries
            .retain(|_, (pending, _)| !predicate(pending.stage()));
    }

    fn has_stage(&self, predicate: impl Fn(&SyncStage) -> bool) -> bool {
        self.entries
            .values()
            .any(|(pending, _)| predicate(pending.stage()))
    }
}

struct NodeSyncRuntime {
    pending: PendingSyncRequests,
    next_probe: Instant,
    status_provider_cursor: usize,
}

impl NodeSyncRuntime {
    fn retry_delay(network: &NetworkHandle, correlation_id: u64) -> Duration {
        // Stable local-identity jitter prevents a simultaneous IBD fan-in from
        // recreating the same winners on every bounded-queue retry. Include
        // the correlation ID so successive attempts also move within the
        // window. This is scheduling diversity, not security randomness.
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        if let Ok(peer) = network.local_peer_id() {
            for byte in peer.to_bytes() {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x100_0000_01b3);
            }
        }
        hash ^= correlation_id.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        Duration::from_millis(500 + hash % 2_500)
    }

    /// Keep the provider pool's highest-ranked recovery source in every hedge
    /// and rotate only the remaining slots. Sorting the ranked list by PeerId
    /// here used to erase provider health and bootstrap preference entirely;
    /// at scale, initial sync could then spend every round asking empty peers.
    fn rotate_status_hedges(&mut self, providers: &mut [PeerId], parallelism: usize) {
        if providers.len() <= 1 || parallelism <= 1 {
            return;
        }
        let alternatives = &mut providers[1..];
        let offset = self.status_provider_cursor % alternatives.len();
        alternatives.rotate_left(offset);
        self.status_provider_cursor =
            (offset + parallelism.saturating_sub(1).min(alternatives.len())) % alternatives.len();
    }
}

pub(super) struct SyncStores<'a> {
    peer_network: &'a mut PeerNetwork,
    sortdb: &'a SortitionDB,
    chainstate: &'a mut StacksChainState,
    mempool: &'a MemPoolDB,
}

impl<'a> SyncStores<'a> {
    pub(super) fn new(
        peer_network: &'a mut PeerNetwork,
        sortdb: &'a SortitionDB,
        chainstate: &'a mut StacksChainState,
        mempool: &'a MemPoolDB,
    ) -> Self {
        Self {
            peer_network,
            sortdb,
            chainstate,
            mempool,
        }
    }
}

pub(super) struct SyncContext<'a> {
    stores: SyncStores<'a>,
    network: &'a NetworkHandle,
    result: &'a NetworkResult,
}

impl<'a> SyncContext<'a> {
    pub(super) fn new(
        stores: SyncStores<'a>,
        network: &'a NetworkHandle,
        result: &'a NetworkResult,
    ) -> Self {
        Self {
            stores,
            network,
            result,
        }
    }
}

struct ObjectIngress {
    enabled: bool,
    relayer: RelayerIngressAdapter,
}

pub(super) struct NodeObjectRepository<'a> {
    peer_network: &'a mut PeerNetwork,
    chainstate: &'a StacksChainState,
    mempool: &'a MemPoolDB,
}

impl<'a> NodeObjectRepository<'a> {
    pub(super) fn new(
        peer_network: &'a mut PeerNetwork,
        chainstate: &'a StacksChainState,
        mempool: &'a MemPoolDB,
    ) -> Self {
        Self {
            peer_network,
            chainstate,
            mempool,
        }
    }

    fn load(&self, kind: ObjectKind, id: ContentId) -> Result<Option<NetworkObject>, String> {
        let block_id = || {
            StacksBlockId::from_bytes(id.as_bytes())
                .ok_or_else(|| "content ID is not a 32-byte Stacks block ID".to_owned())
        };
        match kind {
            ObjectKind::Transaction => {
                let txid = Txid::from_bytes(id.as_bytes())
                    .ok_or_else(|| "content ID is not a transaction ID".to_owned())?;
                MemPoolDB::get_tx(self.mempool.conn(), &txid)
                    .map_err(|error| error.to_string())
                    .map(|info| {
                        info.map(|info| crate::nakamoto_node::libp2p::transaction_object(&info.tx))
                    })
            }
            ObjectKind::NakamotoBlock => self
                .chainstate
                .nakamoto_blocks_db()
                .get_nakamoto_block(&block_id()?)
                .map_err(|error| error.to_string())
                .map(|block| {
                    block.map(|(block, _)| {
                        crate::nakamoto_node::libp2p::nakamoto_block_object(&block)
                    })
                }),
            ObjectKind::AnchoredBlock => {
                let block_id = block_id()?;
                let Some(header) =
                    StacksChainState::get_stacks_block_header_info_by_index_block_hash(
                        self.chainstate.db(),
                        &block_id,
                    )
                    .map_err(|error| error.to_string())?
                else {
                    return Ok(None);
                };
                if header.anchored_header.as_stacks_epoch2().is_none() {
                    return Ok(None);
                }
                let block_hash = header.anchored_header.block_hash();
                StacksChainState::load_block(
                    &self.chainstate.blocks_path,
                    &header.consensus_hash,
                    &block_hash,
                )
                .map_err(|error| error.to_string())
                .map(|block| {
                    block.map(|block| {
                        crate::nakamoto_node::libp2p::anchored_block_object(
                            &header.consensus_hash,
                            &block,
                        )
                    })
                })
            }
            ObjectKind::Microblock => {
                let block_id = block_id()?;
                let Some(info) = StacksChainState::load_staging_microblock_info_indexed(
                    self.chainstate.db(),
                    &block_id,
                )
                .map_err(|error| error.to_string())?
                else {
                    return Ok(None);
                };
                if !info.processed {
                    return Ok(None);
                }
                let Some(stream) = StacksChainState::load_processed_microblock_stream_fork(
                    self.chainstate.db(),
                    &info.consensus_hash,
                    &info.anchored_block_hash,
                    &info.microblock_hash,
                )
                .map_err(|error| error.to_string())?
                else {
                    return Ok(None);
                };
                crate::nakamoto_node::libp2p::microblock_stream_object(
                    &info.consensus_hash,
                    &stream,
                )
                .map(Some)
            }
            ObjectKind::Attachment => {
                let Some(hash) = crate::nakamoto_node::libp2p::attachment_hash_from_content_id(&id)
                else {
                    return Ok(None);
                };
                self.peer_network
                    .get_atlasdb()
                    .find_attachment(&hash)
                    .map_err(|error| error.to_string())
                    .map(|attachment| {
                        attachment.map(|attachment| {
                            crate::nakamoto_node::libp2p::attachment_object(&attachment)
                        })
                    })
            }
            ObjectKind::BlockProposal => Ok(None),
        }
    }

    fn admit_attachment(&mut self, attachment: &Attachment) -> Result<(), String> {
        let atlas = self.peer_network.get_atlasdb();
        let configured_limit =
            usize::try_from(atlas.atlas_config.attachments_max_size).unwrap_or(usize::MAX);
        if attachment.content.len() > configured_limit {
            return Err("attachment exceeds local Atlas policy".to_owned());
        }
        if atlas
            .find_attachment(&attachment.hash())
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Ok(());
        }
        self.peer_network
            .get_atlasdb_mut()
            .insert_uninstantiated_attachment(attachment)
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignerSetPublicationOutcome {
    Accepted,
    Unchanged,
    NotYetAvailable,
    Failed,
}

trait CanonicalViewSink {
    fn update_chain_view(&self, burn_height: u64, reward_cycle: u64) -> Result<(), String>;
    fn retain_signer_cycles(&self, window: RewardCycleWindow) -> Result<(), String>;
    fn update_authorized_signers(
        &self,
        reward_cycle: u64,
        public_keys: Vec<[u8; 33]>,
    ) -> Result<(), String>;
}

impl CanonicalViewSink for NetworkHandle {
    fn update_chain_view(&self, burn_height: u64, reward_cycle: u64) -> Result<(), String> {
        NetworkHandle::update_chain_view(self, burn_height, reward_cycle)
            .map_err(|error| error.to_string())
    }

    fn retain_signer_cycles(&self, window: RewardCycleWindow) -> Result<(), String> {
        NetworkHandle::retain_signer_cycles(self, window.current(), window.next())
            .map_err(|error| error.to_string())
    }

    fn update_authorized_signers(
        &self,
        reward_cycle: u64,
        public_keys: Vec<[u8; 33]>,
    ) -> Result<(), String> {
        NetworkHandle::update_authorized_signers(self, reward_cycle, public_keys)
            .map_err(|error| error.to_string())
    }
}

trait SignerSetSource {
    fn load_signers(&mut self, reward_cycle: u64) -> Result<Option<Vec<[u8; 33]>>, String>;
}

struct ChainstateSignerSetSource<'a> {
    burnchain: &'a Burnchain,
    sortdb: &'a SortitionDB,
    chainstate: &'a mut StacksChainState,
}

impl SignerSetSource for ChainstateSignerSetSource<'_> {
    fn load_signers(&mut self, reward_cycle: u64) -> Result<Option<Vec<[u8; 33]>>, String> {
        let burn_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb.conn())
            .map_err(|error| error.to_string())?;
        let stacks_tip = self.sortdb.get_canonical_stacks_tip_block_id();
        let Some((reward_info, _)) = load_nakamoto_reward_set(
            reward_cycle,
            &burn_tip.sortition_id,
            self.burnchain,
            self.chainstate,
            &stacks_tip,
            self.sortdb,
            &OnChainRewardSetProvider::new(),
        )
        .map_err(|error| format!("{error:?}"))?
        else {
            return Ok(None);
        };
        let Some(reward_set) = reward_info.known_selected_anchor_block() else {
            return Ok(None);
        };
        let mut public_keys: Vec<[u8; 33]> = reward_set
            .signers()
            .into_iter()
            .flatten()
            .map(|entry| entry.signing_key)
            .collect();
        public_keys.sort_unstable();
        public_keys.dedup();
        Ok((!public_keys.is_empty()).then_some(public_keys))
    }
}

impl ObjectIngress {
    fn prepare_pass(&self, result: &mut NetworkResult) {
        self.relayer.prepare_pass(result);
    }

    fn drain(
        &self,
        network: &NetworkHandle,
        repository: &mut NodeObjectRepository<'_>,
        result: &mut NetworkResult,
    ) {
        if !self.enabled {
            return;
        }
        for _ in 0..MAX_OBJECTS_PER_PASS {
            let event = match network.try_next_object_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(error) => {
                    warn!("Failed to poll libp2p object ingress: {error}");
                    break;
                }
            };
            match event {
                ObjectNetworkEvent::Announcement {
                    source,
                    announcement,
                } => {
                    debug!(
                        "Observed canonical libp2p object announcement";
                        "source_peer_id" => source.to_string(),
                        "content_id" => format!("{:02x?}", announcement.content_id.as_bytes()),
                    );
                }
                ObjectNetworkEvent::Request {
                    source,
                    response_token,
                    kind,
                    id,
                } => {
                    let object = match repository.load(kind, id) {
                        Ok(object) => object,
                        Err(error) => {
                            warn!(
                                "Failed to load requested libp2p object from durable storage";
                                "source_peer_id" => source.to_string(),
                                "kind" => format!("{kind:?}"),
                                "error" => error,
                            );
                            None
                        }
                    };
                    if let Err(error) = network.respond_object(response_token, object) {
                        warn!(
                            "Failed to queue durable libp2p object response";
                            "source_peer_id" => source.to_string(),
                            "error" => error.to_string(),
                        );
                    }
                }
                ObjectNetworkEvent::Object {
                    source,
                    object,
                    direct_push,
                } => match self.relayer.stage_object(result, &object) {
                    Ok(RelayerIngressOutcome::Staged) => {}
                    Ok(RelayerIngressOutcome::Attachment(attachment)) => {
                        match repository.admit_attachment(&attachment) {
                            Ok(()) => {
                                if let Err(error) = network.commit_object(object) {
                                    warn!("Failed to commit accepted libp2p attachment: {error}");
                                }
                            }
                            Err(error) => {
                                let _ = network.reject_object(object.content_id);
                                warn!(
                                    "Rejected libp2p attachment after Atlas policy check";
                                    "source_peer_id" => source.to_string(),
                                    "error" => error,
                                );
                            }
                        }
                    }
                    Err(error) => {
                        let _ = network.reject_object(object.content_id);
                        warn!(
                            "Rejected structurally invalid libp2p application object";
                            "source_peer_id" => source.to_string(),
                            "kind" => format!("{:?}", object.kind),
                            "direct_push" => direct_push,
                            "error" => error,
                        );
                    }
                },
            }
        }
    }
}

#[derive(Default)]
struct CanonicalViewPublisher {
    last_chain_view: Option<(u64, u64)>,
    retained_window: Option<RewardCycleWindow>,
    authorizations: HashMap<u64, Vec<[u8; 33]>>,
    retry_not_before: Option<Instant>,
}

#[derive(Clone, Copy)]
struct CanonicalPublication {
    burn_height: u64,
    reward_cycle: u64,
    retained_window: RewardCycleWindow,
    load_next_cycle: bool,
}

impl CanonicalViewPublisher {
    fn refresh<S: CanonicalViewSink, L: SignerSetSource>(
        &mut self,
        now: Instant,
        publication: CanonicalPublication,
        sink: &S,
        source: &mut L,
    ) {
        let CanonicalPublication {
            burn_height,
            reward_cycle,
            retained_window,
            load_next_cycle,
        } = publication;
        let marker = (burn_height, reward_cycle);
        let view_changed = self.last_chain_view != Some(marker);
        if self.retry_not_before.is_some_and(|deadline| now < deadline) {
            return;
        }
        if !view_changed && self.retry_not_before.is_none() {
            return;
        }

        if view_changed {
            if let Err(error) = sink.update_chain_view(burn_height, reward_cycle) {
                self.retry_not_before = Some(now + AUTHORIZATION_RETRY_DELAY);
                warn!(
                    "Failed to update native network canonical burn view";
                    "burn_height" => burn_height,
                    "reward_cycle" => reward_cycle,
                    "error" => error,
                );
                return;
            }
            self.last_chain_view = Some(marker);
        }

        let mut retry = false;
        let mut retention_ready = self.retained_window == Some(retained_window);
        if self.retained_window != Some(retained_window) {
            match sink.retain_signer_cycles(retained_window) {
                Ok(()) => {
                    self.retained_window = Some(retained_window);
                    retention_ready = true;
                }
                Err(error) => {
                    warn!(
                        "Failed to retain native signer authorization cycles";
                        "current_reward_cycle" => reward_cycle,
                        "retained_current" => retained_window.current(),
                        "retained_next" => ?retained_window.next(),
                        "error" => error,
                    );
                }
            }
        }
        if !retention_ready {
            // A signer set for the new window may be accepted into the
            // bounded command queue and then immediately pruned by the old
            // retained-cycle view. Keep the signer-set obligation pending
            // until retention itself has been admitted.
            self.retry_not_before = Some(now + AUTHORIZATION_RETRY_DELAY);
            return;
        }
        self.authorizations
            .retain(|cycle, _| retained_window.contains(*cycle));

        let mut cycles = BTreeSet::from([reward_cycle, retained_window.current()]);
        if load_next_cycle {
            cycles.insert(reward_cycle.saturating_add(1));
        }
        for cycle in cycles {
            match self.refresh_signer_set(cycle, sink, source) {
                SignerSetPublicationOutcome::Accepted => info!(
                    "Updated native signer authorizations from canonical reward set";
                    "reward_cycle" => cycle,
                    "signer_count" => self.authorizations.get(&cycle).map_or(0, Vec::len),
                ),
                SignerSetPublicationOutcome::Unchanged => {}
                SignerSetPublicationOutcome::NotYetAvailable => {
                    retry = true;
                    debug!(
                        "Native signer authorization reward set is not available yet";
                        "reward_cycle" => cycle,
                    );
                }
                SignerSetPublicationOutcome::Failed => retry = true,
            }
        }
        self.retry_not_before = retry.then_some(now + AUTHORIZATION_RETRY_DELAY);
    }

    fn refresh_signer_set<S: CanonicalViewSink, L: SignerSetSource>(
        &mut self,
        reward_cycle: u64,
        sink: &S,
        source: &mut L,
    ) -> SignerSetPublicationOutcome {
        let public_keys = match source.load_signers(reward_cycle) {
            Ok(Some(public_keys)) => public_keys,
            Ok(None) => return SignerSetPublicationOutcome::NotYetAvailable,
            Err(error) => {
                debug!(
                    "Native signer authorization is waiting for canonical chainstate";
                    "reward_cycle" => reward_cycle,
                    "error" => error,
                );
                return SignerSetPublicationOutcome::Failed;
            }
        };
        if self.authorizations.get(&reward_cycle) == Some(&public_keys) {
            return SignerSetPublicationOutcome::Unchanged;
        }
        if let Err(error) = sink.update_authorized_signers(reward_cycle, public_keys.clone()) {
            warn!(
                "Failed to update native signer authorizations";
                "reward_cycle" => reward_cycle,
                "error" => error,
            );
            return SignerSetPublicationOutcome::Failed;
        }
        self.authorizations.insert(reward_cycle, public_keys);
        SignerSetPublicationOutcome::Accepted
    }
}

#[derive(Default)]
struct LegacyIdentityPublisher {
    last_binding: Option<([u8; 33], u64)>,
    suppress_redundant_legacy_delivery: bool,
}

trait LegacyIdentitySink {
    fn local_peer_id(&self) -> Result<PeerId, String>;
    fn update_binding(&self, binding: LegacyIdentityBinding) -> Result<(), String>;
}

impl LegacyIdentitySink for NetworkHandle {
    fn local_peer_id(&self) -> Result<PeerId, String> {
        NetworkHandle::local_peer_id(self).map_err(|error| error.to_string())
    }

    fn update_binding(&self, binding: LegacyIdentityBinding) -> Result<(), String> {
        self.update_legacy_identity_binding(Some(binding))
            .map_err(|error| error.to_string())
    }
}

impl LegacyIdentityPublisher {
    fn publish_local<S: LegacyIdentitySink>(
        &mut self,
        chain_id: u32,
        private_key: &StacksPrivateKey,
        expiry: u64,
        sink: &S,
    ) {
        let Ok(local_public_key): Result<[u8; 33], _> = StacksPublicKey::from_private(private_key)
            .to_bytes_compressed()
            .try_into()
        else {
            warn!("Failed to encode local rotating key for native identity binding");
            return;
        };
        let marker = (local_public_key, expiry);
        if self.last_binding == Some(marker) {
            return;
        }
        let peer_id = match sink.local_peer_id() {
            Ok(peer_id) => peer_id,
            Err(error) => {
                warn!("Failed to read local native PeerId for legacy binding: {error}");
                return;
            }
        };
        let binding = match crate::nakamoto_node::libp2p::legacy_identity_binding(
            peer_id,
            chain_id,
            private_key,
            expiry,
        ) {
            Ok(binding) => binding,
            Err(error) => {
                warn!("Failed to build native legacy-key binding: {error}");
                return;
            }
        };
        match sink.update_binding(binding) {
            Ok(()) => self.last_binding = Some(marker),
            Err(error) => warn!("Failed to queue native legacy-key binding: {error}"),
        }
    }
}

pub(super) struct Libp2pPeerRuntime {
    canonical_view: CanonicalViewPublisher,
    legacy_identity: LegacyIdentityPublisher,
    objects: ObjectIngress,
    sync: NodeSyncRuntime,
}

impl Libp2pPeerRuntime {
    pub(super) fn new(
        now: Instant,
        accepts_application_ingress: bool,
        legacy_fallback_enabled: bool,
        publishes_application_data: bool,
    ) -> Self {
        Self {
            canonical_view: CanonicalViewPublisher::default(),
            legacy_identity: LegacyIdentityPublisher {
                suppress_redundant_legacy_delivery: publishes_application_data,
                ..LegacyIdentityPublisher::default()
            },
            objects: ObjectIngress {
                enabled: accepts_application_ingress,
                relayer: RelayerIngressAdapter::new(legacy_fallback_enabled),
            },
            sync: NodeSyncRuntime {
                pending: PendingSyncRequests::default(),
                next_probe: now,
                status_provider_cursor: 0,
            },
        }
    }

    pub(super) fn refresh_canonical_view(
        &mut self,
        now: Instant,
        burn_height: u64,
        burnchain: &Burnchain,
        network: &NetworkHandle,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
    ) {
        let Some(reward_cycle) = burnchain.block_height_to_reward_cycle(burn_height) else {
            return;
        };
        let retained_window = signer_authorization_cycle_window(
            reward_cycle,
            burnchain.is_naka_signing_cycle_start(burn_height),
        );
        let mut source = ChainstateSignerSetSource {
            burnchain,
            sortdb,
            chainstate,
        };
        self.canonical_view.refresh(
            now,
            CanonicalPublication {
                burn_height,
                reward_cycle,
                retained_window,
                load_next_cycle: burnchain.is_in_prepare_phase(burn_height),
            },
            network,
            &mut source,
        );
    }

    pub(super) fn refresh_legacy_identity(
        &mut self,
        chain_id: u32,
        burn_height: u64,
        network: &NetworkHandle,
        peer_network: &mut PeerNetwork,
    ) {
        let mut live_connections = Vec::new();
        for (_, conversation) in peer_network.iter_peer_convos() {
            if !conversation.is_authenticated() {
                continue;
            }
            let Some(public_key) = conversation.get_public_key() else {
                continue;
            };
            let Ok(public_key): Result<[u8; 33], _> = public_key.to_bytes_compressed().try_into()
            else {
                continue;
            };
            live_connections.push((public_key, conversation.peer_expire_block_height));
        }
        let coalesced_keys = network.reconcile_legacy_connections(live_connections, burn_height);
        peer_network.set_native_relay_exclusions(
            if self.legacy_identity.suppress_redundant_legacy_delivery {
                coalesced_keys
            } else {
                Vec::new()
            },
        );

        self.legacy_identity.publish_local(
            chain_id,
            &peer_network.local_peer.private_key,
            peer_network.local_peer.private_key_expire,
            network,
        );
    }

    pub(super) fn prepare_network_result(&self, result: &mut NetworkResult) {
        self.objects.prepare_pass(result);
    }

    pub(super) fn drain_objects(
        &mut self,
        network: &NetworkHandle,
        repository: &mut NodeObjectRepository<'_>,
        result: &mut NetworkResult,
    ) {
        self.objects.drain(network, repository, result);
    }

    pub(super) fn drain_sync(&mut self, context: SyncContext<'_>) {
        SyncPass {
            state: &mut self.sync,
            context,
        }
        .drain();
    }
}

struct SyncPass<'a> {
    state: &'a mut NodeSyncRuntime,
    context: SyncContext<'a>,
}

impl SyncPass<'_> {
    fn canonical_stacks_tip(&self, fallback: &NetworkResult) -> (u64, StacksBlockId) {
        match SortitionDB::get_canonical_stacks_chain_tip_hash_and_height(
            self.context.stores.sortdb.conn(),
        ) {
            Ok((consensus_hash, block_hash, height)) => {
                (height, StacksBlockId::new(&consensus_hash, &block_hash))
            }
            Err(error) => {
                warn!(
                    "Failed to load durable canonical Stacks tip for native sync status";
                    "error" => error.to_string(),
                );
                (fallback.stacks_tip_height, fallback.stacks_tip.clone())
            }
        }
    }

    fn drain(&mut self) {
        let network = self.context.network;
        let network_result = self.context.result;
        for _ in 0..MAX_SYNC_REQUESTS_PER_PASS {
            let event = match network.try_next_sync_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(error) => {
                    warn!("Failed to poll libp2p sync ingress: {error}");
                    break;
                }
            };
            match event {
                SyncNetworkEvent::InboundRequest {
                    source,
                    response_token,
                    request,
                } => {
                    let response = match request.request {
                        Some(sync_request::Request::GetStatus(_)) => SyncResponse {
                            // `NetworkResult` is a per-pass delta and may be
                            // empty after block processing even while durable
                            // chainstate has a non-genesis canonical tip.
                            // Status is a state snapshot, so source it from the
                            // canonical sortition index instead.
                            status: Status::Ok as i32,
                            response: Some(sync_response::Response::StatusView({
                                let (stacks_tip_height, stacks_tip) =
                                    self.canonical_stacks_tip(network_result);
                                SyncStatus {
                                    burn_tip_height: self
                                        .context
                                        .stores
                                        .peer_network
                                        .chain_view
                                        .burn_block_height,
                                    burn_tip_hash: self
                                        .context
                                        .stores
                                        .peer_network
                                        .chain_view
                                        .burn_block_hash
                                        .as_bytes()
                                        .to_vec(),
                                    stable_burn_tip_height: self
                                        .context
                                        .stores
                                        .peer_network
                                        .chain_view
                                        .burn_stable_block_height,
                                    stable_burn_tip_hash: self
                                        .context
                                        .stores
                                        .peer_network
                                        .chain_view
                                        .burn_stable_block_hash
                                        .as_bytes()
                                        .to_vec(),
                                    stacks_tip_height,
                                    stacks_tip_id: stacks_tip.as_bytes().to_vec(),
                                    current_reward_cycle: self
                                        .context
                                        .stores
                                        .peer_network
                                        .burnchain
                                        .block_height_to_reward_cycle(network_result.burn_height)
                                        .unwrap_or(0),
                                }
                            })),
                        },
                        Some(sync_request::Request::GetPoxInventory(request)) => {
                            self.serve_pox_inventory(request.start_cycle, request.count)
                        }
                        Some(sync_request::Request::GetTenureInventory(request)) => self
                            .serve_tenure_inventory(
                                request.reward_cycle,
                                request.cursor,
                                request.max_items,
                                network,
                            ),
                        Some(sync_request::Request::GetEpoch2Inventory(request)) => self
                            .serve_epoch2_inventory(request.start_height, request.count, network),
                        Some(sync_request::Request::GetMempoolPage(request)) => self
                            .serve_mempool_inventory(
                                &request.cursor,
                                request.max_items,
                                request.max_bytes,
                                network,
                            ),
                        Some(sync_request::Request::GetAttachmentInventory(request)) => self
                            .serve_attachment_inventory(
                                &request.cursor,
                                request.max_items,
                                network,
                            ),
                        _ => SyncResponse {
                            status: Status::Unsupported as i32,
                            response: None,
                        },
                    };
                    if let Err(error) = network.respond_sync(response_token, response) {
                        warn!(
                            "Failed to queue libp2p sync response";
                            "source_peer_id" => source.to_string(),
                            "error" => error.to_string(),
                        );
                    }
                }
                SyncNetworkEvent::Response {
                    source,
                    correlation_id: Some(correlation_id),
                    response,
                } => {
                    self.handle_sync_response(
                        source,
                        correlation_id,
                        response,
                        network_result,
                        network,
                    );
                }
                SyncNetworkEvent::Response { .. } => {}
                SyncNetworkEvent::OutboundFailure {
                    peer,
                    correlation_id: Some(correlation_id),
                    error,
                } => {
                    self.state.pending.remove(correlation_id);
                    self.state.next_probe =
                        Instant::now() + NodeSyncRuntime::retry_delay(network, correlation_id);
                    warn!(
                        "libp2p sync request failed";
                        "peer_id" => peer.to_string(),
                        "error" => error,
                    );
                }
                SyncNetworkEvent::OutboundFailure { .. } => {}
            }
        }
        self.drive_sync(network_result, network);
    }

    fn drive_sync(&mut self, network_result: &NetworkResult, network: &NetworkHandle) {
        let now = Instant::now();
        self.state.pending.expire(now, Duration::from_secs(15));
        let diagnostics = network.diagnostics();
        let validation_slots = diagnostics
            .validation_queue_capacity
            .saturating_sub(diagnostics.validation_queue_depth);
        let concurrency = stacks_network::adaptive_sync_concurrency(
            SYNC_MAX_CONCURRENCY,
            validation_slots,
            diagnostics.validation_queue_depth,
            diagnostics.validation_queue_capacity,
        );
        if concurrency == 0 {
            self.state.next_probe = now + Duration::from_secs(1);
            return;
        }
        if !self.state.pending.is_empty() || now < self.state.next_probe {
            return;
        }
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let recent_sync_failure = diagnostics.recent_events.iter().rev().any(|event| {
            event.kind == "error"
                && event.detail.to_ascii_lowercase().contains("sync")
                && now_unix_ms.saturating_sub(event.unix_ms) <= 30_000
        });
        let recent_validation_orphan = diagnostics.recent_events.iter().rev().any(|event| {
            event.kind == "validation-result-orphaned"
                && now_unix_ms.saturating_sub(event.unix_ms) <= 30_000
        });
        let stall_reason = if diagnostics.connected_peers.is_empty() {
            1
        } else if diagnostics.object_sync_capable_peers.is_empty() {
            2
        } else if diagnostics.event_loop_lag_ms >= 500 {
            3
        } else if diagnostics.last_command_queue_residence_ms >= 500 {
            4
        } else if recent_validation_orphan {
            6
        } else if recent_sync_failure {
            5
        } else {
            0
        };
        stacks::monitoring::set_libp2p_network_metrics(
            diagnostics.connected_peers.len(),
            diagnostics.object_sync_capable_peers.len(),
            diagnostics.event_loop_lag_ms,
            diagnostics.last_command_queue_residence_ms,
            diagnostics.oldest_command_queue_wait_ms,
            stall_reason,
        );
        stacks::monitoring::set_libp2p_connected_peer_links(&diagnostics.connected_peers);
        let connected = diagnostics
            .connected_peers
            .iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>();
        let signer_public_keys = diagnostics
            .signer_observations
            .iter()
            .filter(|observation| connected.contains(observation.peer_id.as_str()))
            .map(|observation| stacks_common::util::hash::to_hex(&observation.signer_public_key))
            .collect::<Vec<_>>();
        stacks::monitoring::set_libp2p_authenticated_signer_links(&signer_public_keys);
        match serde_json::to_value(&diagnostics) {
            Ok(snapshot) => stacks::monitoring::set_libp2p_network_diagnostics(snapshot),
            Err(error) => warn!("Failed to serialize libp2p diagnostic snapshot: {error}"),
        }
        info!(
            "libp2p network health snapshot";
            "connected_peers" => diagnostics.connected_peers.len(),
            "sync_capable_peers" => diagnostics.sync_capable_peers.len(),
            "object_sync_capable_peers" => diagnostics.object_sync_capable_peers.len(),
            "successful_hellos" => diagnostics.successful_hellos,
            "rejected_hellos" => diagnostics.rejected_hellos,
            "event_loop_lag_ms" => diagnostics.event_loop_lag_ms,
            "event_loop_stalls" => diagnostics.event_loop_stalls,
            "command_queue_residence_ms" => diagnostics.last_command_queue_residence_ms,
            "max_command_queue_residence_ms" => diagnostics.max_command_queue_residence_ms,
            "oldest_command_queue_wait_ms" => diagnostics.oldest_command_queue_wait_ms,
            "object_fetch_failures" => diagnostics.object_fetch_failures,
            "objects_received" => diagnostics.objects_received,
            "sync_responses_received" => diagnostics.sync_responses_received,
            "sync_failures" => diagnostics.sync_failures,
            "resource_budget_rejections" => diagnostics.resource_budget_rejections,
            "stall_reason_code" => stall_reason,
        );
        let mut providers = (if diagnostics.preferred_sync_peers.is_empty() {
            &diagnostics.object_sync_capable_peers
        } else {
            &diagnostics.preferred_sync_peers
        })
        .iter()
        .filter_map(|peer| peer.parse::<PeerId>().ok())
        .collect::<Vec<_>>();
        // During IBD, independently correlate each status probe: a
        // valid-but-empty response must not cancel a slower current provider
        // in the same sample. Keep the pool's highest-ranked source in every
        // sample and rotate the remaining hedge slots. Once a local tip
        // exists, the ordinary hedged request remains the lower-overhead
        // steady-state path.
        self.state.rotate_status_hedges(&mut providers, concurrency);
        let Some(peer) = providers.first().copied() else {
            self.state.next_probe = now + SYNC_PROBE_INTERVAL;
            return;
        };
        let request = SyncRequest {
            request: Some(sync_request::Request::GetStatus(GetStatus {})),
        };
        let (local_stacks_height, _) = self.canonical_stacks_tip(network_result);
        if local_stacks_height == 0 {
            let mut started = false;
            for provider in providers.into_iter().take(concurrency) {
                started |= self.start_sync_request(
                    vec![provider],
                    request.clone(),
                    NakamotoSyncStep::status(),
                    1,
                    network,
                );
            }
            if !started {
                self.state.next_probe = now + Duration::from_secs(1);
                return;
            }
        } else {
            self.start_sync_request(
                providers,
                request,
                NakamotoSyncStep::status(),
                concurrency,
                network,
            );
        }
        // An accepted command can still be rejected by a downstream bounded
        // resource budget without producing a response. Keep initial provider
        // rotation prompt after the pending-entry expiry; steady state uses
        // the ordinary probe cadence. A non-empty pending set still prevents
        // overlapping rounds above.
        self.state.next_probe = if local_stacks_height == 0 {
            now + Duration::from_secs(1)
        } else {
            now + SYNC_PROBE_INTERVAL
        };
        debug!(
            "Probed authenticated libp2p sync peer";
            "peer_id" => peer.to_string(),
            "local_stacks_height" => local_stacks_height,
        );
    }

    fn start_provider_affine_step(
        &mut self,
        provider: PeerId,
        request: SyncRequest,
        plan: NakamotoSyncStep,
        network: &NetworkHandle,
    ) {
        // Status discovery is safely hedged because every reply carries the
        // state used to select a source. Once one status wins, the remaining
        // inventory pages and object IDs form a snapshot-relative plan and
        // must stay with that provider. Hedging a later page across arbitrary
        // peers can splice a valid empty inventory from a behind peer into a
        // plan established by a current peer, falsely completing IBD.
        // Transport failure or Busy restarts status discovery and therefore
        // chooses a new coherent provider; it never mixes snapshots in place.
        self.start_sync_request(vec![provider], request, plan, 1, network);
    }

    fn start_sync_request(
        &mut self,
        providers: Vec<PeerId>,
        request: SyncRequest,
        pending: NakamotoSyncStep,
        max_parallel: usize,
        network: &NetworkHandle,
    ) -> bool {
        if max_parallel == 0 {
            return false;
        }
        let correlation_id = self.state.pending.correlation_candidate();
        if network
            .request_sync_from(
                correlation_id,
                providers,
                request,
                max_parallel,
                SYNC_HEDGE_DELAY,
            )
            .is_err()
        {
            return false;
        }
        let installed = self.state.pending.install_accepted(pending, Instant::now());
        debug_assert_eq!(correlation_id, installed);
        true
    }

    fn handle_sync_response(
        &mut self,
        source: PeerId,
        correlation_id: u64,
        response: SyncResponse,
        network_result: &NetworkResult,
        network: &NetworkHandle,
    ) {
        let Some(pending) = self.state.pending.remove(correlation_id) else {
            debug!(
                "Ignored uncorrelated libp2p sync response";
                "source_peer_id" => source.to_string(),
            );
            return;
        };
        if Status::try_from(response.status).ok() != Some(Status::Ok) {
            self.state.next_probe =
                Instant::now() + NodeSyncRuntime::retry_delay(network, correlation_id);
            debug!(
                "libp2p sync peer declined request";
                "source_peer_id" => source.to_string(),
                "status" => response.status,
            );
            return;
        }
        let stage = pending.stage().clone();
        match (stage, response.response) {
            (SyncStage::Status, Some(sync_response::Response::StatusView(remote))) => {
                let (local_stacks_height, _) = self.canonical_stacks_tip(network_result);
                if remote.stacks_tip_height <= local_stacks_height {
                    // A behind/equal hedge is not evidence that no other
                    // correlated provider is ahead. Preserve every remaining
                    // status probe in IBD and steady state. Only the final
                    // response may conclude this status round.
                    if self
                        .state
                        .pending
                        .has_stage(|stage| matches!(stage, SyncStage::Status))
                    {
                        return;
                    }
                    if local_stacks_height == 0 {
                        self.state.next_probe = Instant::now() + Duration::from_secs(1);
                    } else {
                        self.schedule_sync_step(source, NakamotoSyncStep::mempool(), network);
                    }
                    return;
                }
                // A current provider wins by chain height. Other status
                // responses remain transport-correlated but are now
                // semantically obsolete.
                self.state
                    .pending
                    .remove_stage(|stage| matches!(stage, SyncStage::Status));
                let epoch3_start =
                    self.context.stores.peer_network.epochs[StacksEpochId::Epoch30].start_height;
                let epoch2_start = self
                    .context
                    .stores
                    .peer_network
                    .get_burnchain()
                    .first_block_height;
                let epoch2_end = epoch3_start.min(remote.burn_tip_height.saturating_add(1));
                let first_nakamoto_cycle = self
                    .context
                    .stores
                    .peer_network
                    .get_burnchain()
                    .block_height_to_reward_cycle(epoch3_start)
                    .unwrap_or(0);
                // The Bitcoin header downloader can be ahead of the canonical
                // sortition tip while chain processing waits for a PoX anchor.
                // Only ask the remote for PoX boundaries already derivable
                // from locally processed burn state; using the downloaded burn
                // height here makes an honest future boundary look invalid and
                // disconnects the very peer that can supply the missing anchor.
                let processed_burn_height =
                    SortitionDB::get_canonical_burn_chain_tip(self.context.stores.sortdb.conn())
                        .map(|tip| tip.block_height)
                        .unwrap_or(network_result.burn_height);
                let burnchain = self.context.stores.peer_network.get_burnchain();
                let local_signing_cycle = burnchain
                    .block_height_to_reward_cycle(processed_burn_height)
                    .unwrap_or(0);
                // `block_height_to_reward_cycle` identifies the active cycle,
                // whose boundary can be one block beyond a tip stalled at the
                // preceding anchor. Clamp to the greatest boundary that is
                // actually present in the canonical sortition view.
                let horizons = sync_cycle_horizons(
                    local_signing_cycle,
                    burnchain.reward_cycle_to_block_height(local_signing_cycle),
                    processed_burn_height,
                    remote.current_reward_cycle,
                );
                let next = NakamotoSyncStep::after_status(
                    horizons
                        .pox_through_cycle
                        .saturating_add(u64::from(horizons.pox_through_cycle > 0)),
                    epoch2_start,
                    epoch2_end,
                    first_nakamoto_cycle,
                    horizons.tenure_through_cycle,
                );
                self.advance_sync_step(source, next, network);
            }
            (
                SyncStage::Pox {
                    cursor: requested_start,
                },
                Some(sync_response::Response::Inventory(page)),
            ) => {
                if let Err(error) = self.validate_pox_page(requested_start, &page) {
                    warn!(
                        "Rejected inconsistent libp2p PoX inventory";
                        "source_peer_id" => source.to_string(),
                        "error" => error,
                    );
                    let _ = network.report_provider_outcome(
                        source,
                        stacks_network::ProviderOutcome::InvalidData,
                    );
                    let _ = network.disconnect(source);
                    self.state.next_probe = Instant::now() + Duration::from_secs(2);
                    return;
                }
                self.advance_sync_step(
                    source,
                    pending.advance_inventory(page.next_cursor, page.complete),
                    network,
                );
            }
            (SyncStage::Epoch2 { .. }, Some(sync_response::Response::Inventory(page))) => {
                self.fetch_inventory_objects(source, &page, network);
                self.advance_sync_step(
                    source,
                    pending.advance_inventory(page.next_cursor, page.complete),
                    network,
                );
            }
            (SyncStage::Tenure { .. }, Some(sync_response::Response::Inventory(page))) => {
                self.fetch_inventory_objects(source, &page, network);
                self.advance_sync_step(
                    source,
                    pending.advance_inventory(page.next_cursor, page.complete),
                    network,
                );
            }
            (SyncStage::Mempool { .. }, Some(sync_response::Response::Mempool(page))) => {
                for id in &page.transaction_ids {
                    if let Ok(id) = ContentId::try_from(id.as_slice()) {
                        if let Err(error) =
                            network.request_object(source, ObjectKind::Transaction, id)
                        {
                            debug!("Failed to queue libp2p mempool object fetch: {error}");
                        }
                    }
                }
                self.advance_sync_step(
                    source,
                    pending.advance_mempool(page.next_cursor, page.complete),
                    network,
                );
            }
            (SyncStage::Attachments { .. }, Some(sync_response::Response::Attachments(page))) => {
                for item in page.items.iter().filter(|item| item.available) {
                    if let Ok(id) = ContentId::try_from(item.object_id.as_slice()) {
                        if let Err(error) =
                            network.request_object(source, ObjectKind::Attachment, id)
                        {
                            debug!("Failed to queue libp2p attachment fetch: {error}");
                        }
                    }
                }
                self.advance_sync_step(
                    source,
                    pending.advance_attachments(page.next_cursor, page.complete),
                    network,
                );
            }
            (pending, response) => {
                let _ = network
                    .report_provider_outcome(source, stacks_network::ProviderOutcome::InvalidData);
                warn!(
                    "libp2p sync response did not match its request";
                    "source_peer_id" => source.to_string(),
                    "pending" => ?pending,
                    "response" => ?response,
                );
                self.state.next_probe = Instant::now() + Duration::from_secs(2);
            }
        }
    }

    fn advance_sync_step(
        &mut self,
        source: PeerId,
        next: Result<NakamotoSyncStep, stacks::net::sync_plan::SyncPlanError>,
        network: &NetworkHandle,
    ) {
        match next {
            Ok(step) => self.schedule_sync_step(source, step, network),
            Err(error) => {
                let _ = network
                    .report_provider_outcome(source, stacks_network::ProviderOutcome::InvalidData);
                let _ = network.disconnect(source);
                self.state.next_probe = Instant::now() + Duration::from_secs(2);
                warn!(
                    "Rejected non-progressing libp2p sync page";
                    "source_peer_id" => source.to_string(),
                    "error" => error.to_string(),
                );
            }
        }
    }

    fn schedule_sync_step(
        &mut self,
        peer: PeerId,
        step: NakamotoSyncStep,
        network: &NetworkHandle,
    ) {
        match step.stage().clone() {
            SyncStage::Pox { cursor } => self.request_pox_page(peer, step, cursor, network),
            SyncStage::Epoch2 { cursor } => self.request_epoch2_page(peer, step, cursor, network),
            SyncStage::Tenure {
                reward_cycle,
                cursor,
            } => self.request_tenure_page(peer, step, reward_cycle, cursor, network),
            SyncStage::Mempool { cursor } => self.request_mempool_page(peer, step, cursor, network),
            SyncStage::Attachments { cursor } => {
                self.request_attachment_page(peer, step, cursor, network)
            }
            SyncStage::Complete => {
                self.state.next_probe = Instant::now() + SYNC_PROBE_INTERVAL;
            }
            SyncStage::Status => {
                debug_assert!(false, "status is only the sync-plan root");
                self.state.next_probe = Instant::now() + Duration::from_secs(2);
            }
        }
    }

    fn fetch_inventory_objects(
        &self,
        source: PeerId,
        page: &InventoryPage,
        network: &NetworkHandle,
    ) {
        for item in page.items.iter().filter(|item| item.available) {
            let Ok(id) = ContentId::try_from(item.object_id.as_slice()) else {
                continue;
            };
            let Some(kind) = ObjectType::try_from(item.kind)
                .ok()
                .and_then(|kind| ObjectKind::try_from(kind).ok())
            else {
                continue;
            };
            if let Err(error) = network.request_object(source, kind, id) {
                debug!("Failed to queue libp2p inventory object fetch: {error}");
            }
        }
    }

    /// PoX inventory is consensus context, not a hint. Compare every returned
    /// cycle boundary to the local burnchain before accepting object IDs from
    /// the same peer. A disagreement closes the authenticated connection and
    /// lets peer selection retry elsewhere.
    fn validate_pox_page(&self, requested_start: u64, page: &InventoryPage) -> Result<(), String> {
        let tip = SortitionDB::get_canonical_burn_chain_tip(self.context.stores.sortdb.conn())
            .map_err(|error| error.to_string())?;
        let index = self.context.stores.sortdb.index_handle(&tip.sortition_id);
        let mut expected_cycle = requested_start;
        for item in &page.items {
            if item.index != expected_cycle {
                return Err(format!(
                    "non-contiguous PoX cycle {}, expected {expected_cycle}",
                    item.index
                ));
            }
            if item.object_id.len() != 20 {
                return Err(format!(
                    "PoX cycle {} has a non-consensus-hash object ID",
                    item.index
                ));
            }
            let height = self
                .context
                .stores
                .peer_network
                .get_burnchain()
                .reward_cycle_to_block_height(item.index);
            let snapshot = if height == tip.block_height {
                Some(tip.clone())
            } else {
                index
                    .get_block_snapshot_by_height(height)
                    .map_err(|error| error.to_string())?
            }
            .ok_or_else(|| format!("local burnchain has no PoX boundary at height {height}"))?;
            if snapshot.consensus_hash.as_bytes() != item.object_id.as_slice() {
                return Err(format!(
                    "PoX consensus hash disagrees at cycle {}",
                    item.index
                ));
            }
            expected_cycle = expected_cycle.saturating_add(1);
        }
        if page.next_cursor != expected_cycle {
            return Err(format!(
                "PoX next cursor {} does not follow returned cycle {expected_cycle}",
                page.next_cursor
            ));
        }
        Ok(())
    }

    fn request_pox_page(
        &mut self,
        peer: PeerId,
        plan: NakamotoSyncStep,
        start_cycle: u64,
        network: &NetworkHandle,
    ) {
        let count = plan
            .bounds()
            .pox_end_cycle()
            .saturating_sub(start_cycle)
            .min(u64::from(SYNC_PAGE_ITEMS)) as u32;
        debug_assert!(count > 0, "PoX stage always has a non-empty bounded range");
        let request = SyncRequest {
            request: Some(sync_request::Request::GetPoxInventory(GetPoxInventory {
                start_cycle,
                count,
            })),
        };
        self.start_provider_affine_step(peer, request, plan, network);
    }

    fn request_epoch2_page(
        &mut self,
        peer: PeerId,
        plan: NakamotoSyncStep,
        start_height: u64,
        network: &NetworkHandle,
    ) {
        let count = plan
            .bounds()
            .epoch2_end()
            .saturating_sub(start_height)
            .min(u64::from(SYNC_PAGE_ITEMS)) as u32;
        debug_assert!(
            count > 0,
            "epoch-2 stage always has a non-empty bounded range"
        );
        let request = SyncRequest {
            request: Some(sync_request::Request::GetEpoch2Inventory(
                GetEpoch2Inventory {
                    start_height,
                    count,
                },
            )),
        };
        self.start_provider_affine_step(peer, request, plan, network);
    }

    fn request_tenure_page(
        &mut self,
        peer: PeerId,
        plan: NakamotoSyncStep,
        reward_cycle: u64,
        cursor: u64,
        network: &NetworkHandle,
    ) {
        debug_assert!(reward_cycle <= plan.bounds().current_reward_cycle());
        let request = SyncRequest {
            request: Some(sync_request::Request::GetTenureInventory(
                GetTenureInventory {
                    reward_cycle,
                    cursor,
                    max_items: SYNC_PAGE_ITEMS,
                },
            )),
        };
        self.start_provider_affine_step(peer, request, plan, network);
    }

    fn request_mempool_page(
        &mut self,
        peer: PeerId,
        plan: NakamotoSyncStep,
        cursor: Vec<u8>,
        network: &NetworkHandle,
    ) {
        let request = SyncRequest {
            request: Some(sync_request::Request::GetMempoolPage(GetMempoolPage {
                cursor: cursor.clone(),
                max_items: SYNC_PAGE_ITEMS,
                max_bytes: SYNC_PAGE_ITEMS * 32,
            })),
        };
        self.start_provider_affine_step(peer, request, plan, network);
    }

    fn request_attachment_page(
        &mut self,
        peer: PeerId,
        plan: NakamotoSyncStep,
        cursor: Vec<u8>,
        network: &NetworkHandle,
    ) {
        let request = SyncRequest {
            request: Some(sync_request::Request::GetAttachmentInventory(
                GetAttachmentInventory {
                    cursor: cursor.clone(),
                    max_items: SYNC_PAGE_ITEMS,
                },
            )),
        };
        self.start_provider_affine_step(peer, request, plan, network);
    }

    fn serve_pox_inventory(&self, start_cycle: u64, count: u32) -> SyncResponse {
        let result = (|| {
            let tip = SortitionDB::get_canonical_burn_chain_tip(self.context.stores.sortdb.conn())?;
            let index = self.context.stores.sortdb.index_handle(&tip.sortition_id);
            let known_end = u64::try_from(self.context.stores.peer_network.get_pox_id().len())
                .unwrap_or(u64::MAX);
            let range = stacks_network::bounded_inventory_range(start_cycle, count, known_end);
            let requested_end = start_cycle.saturating_add(u64::from(count));
            let range_len = usize::try_from(range.end.saturating_sub(range.start)).unwrap_or(0);
            let start_index = usize::try_from(start_cycle).unwrap_or(usize::MAX);
            let anchor_inventory = self
                .context
                .stores
                .peer_network
                .get_pox_id()
                .inventory_slice(start_index, range_len);
            let mut items = Vec::with_capacity(range_len);
            for (offset, cycle) in range.enumerate() {
                let height = self
                    .context
                    .stores
                    .peer_network
                    .get_burnchain()
                    .reward_cycle_to_block_height(cycle);
                if height > tip.block_height {
                    break;
                }
                let snapshot = if height == tip.block_height {
                    Some(tip.clone())
                } else {
                    index.get_block_snapshot_by_height(height)?
                };
                let Some(snapshot) = snapshot else {
                    break;
                };
                items.push(InventoryItem {
                    index: cycle,
                    object_id: snapshot.consensus_hash.as_bytes().to_vec(),
                    available: anchor_inventory.get(offset).copied().unwrap_or(false),
                    kind: ObjectType::Unspecified as i32,
                });
            }
            let next_cursor = items
                .last()
                .map(|item| item.index.saturating_add(1))
                .unwrap_or(start_cycle);
            Ok::<_, stacks::util_lib::db::Error>(InventoryPage {
                complete: next_cursor >= known_end || next_cursor >= requested_end,
                next_cursor,
                items,
            })
        })();
        match result {
            Ok(page) => SyncResponse {
                status: Status::Ok as i32,
                response: Some(sync_response::Response::Inventory(page)),
            },
            Err(error) => {
                warn!("Failed to serve libp2p PoX inventory: {error}");
                SyncResponse {
                    status: Status::Busy as i32,
                    response: None,
                }
            }
        }
    }

    fn serve_epoch2_inventory(
        &self,
        start_height: u64,
        count: u32,
        network: &NetworkHandle,
    ) -> SyncResponse {
        let result = crate::nakamoto_node::libp2p::epoch2_inventory_page(
            self.context.stores.peer_network.get_burnchain(),
            self.context.stores.sortdb,
            self.context.stores.chainstate,
            start_height,
            count,
            network,
        );
        match result {
            Ok(page) => SyncResponse {
                status: Status::Ok as i32,
                response: Some(sync_response::Response::Inventory(page)),
            },
            Err(error) => {
                warn!("Failed to serve libp2p Epoch 2.x inventory: {error}");
                SyncResponse {
                    status: Status::Busy as i32,
                    response: None,
                }
            }
        }
    }

    fn serve_tenure_inventory(
        &mut self,
        reward_cycle: u64,
        cursor: u64,
        max_items: u32,
        network: &NetworkHandle,
    ) -> SyncResponse {
        let result = (|| -> Result<InventoryPage, String> {
            let tip = SortitionDB::get_canonical_burn_chain_tip(self.context.stores.sortdb.conn())
                .map_err(|error| error.to_string())?;
            let stacks_tip_consensus = self
                .context
                .stores
                .peer_network
                .stacks_tip
                .consensus_hash
                .clone();
            let stacks_tip_block = self
                .context
                .stores
                .peer_network
                .stacks_tip
                .block_hash
                .clone();
            let tenures = self
                .context
                .stores
                .peer_network
                .nakamoto_inv_generator
                .make_tenure_bitvector(
                    &tip,
                    self.context.stores.sortdb,
                    self.context.stores.chainstate,
                    &stacks_tip_consensus,
                    &stacks_tip_block,
                    reward_cycle,
                )
                .map_err(|error| error.to_string())?;
            let mut tenure_offset = usize::try_from(cursor >> 32).unwrap_or(usize::MAX);
            let mut block_offset =
                usize::try_from(cursor & u64::from(u32::MAX)).unwrap_or(usize::MAX);
            if tenure_offset > tenures.len() {
                return Err("tenure inventory cursor exceeds the cycle".to_owned());
            }
            let limit = usize::try_from(max_items).unwrap_or(usize::MAX);
            let cycle_start = self
                .context
                .stores
                .peer_network
                .get_burnchain()
                .nakamoto_first_block_of_cycle(reward_cycle);
            let sortition_index = self.context.stores.sortdb.index_handle(&tip.sortition_id);
            let mut items = Vec::with_capacity(limit);
            while tenure_offset < tenures.len() && items.len() < limit {
                if !tenures[tenure_offset] {
                    tenure_offset += 1;
                    block_offset = 0;
                    continue;
                }
                let burn_height =
                    cycle_start.saturating_add(u64::try_from(tenure_offset).unwrap_or(u64::MAX));
                let snapshot = if burn_height == tip.block_height {
                    Some(tip.clone())
                } else {
                    sortition_index
                        .get_block_snapshot_by_height(burn_height)
                        .map_err(|error| error.to_string())?
                };
                let Some(snapshot) = snapshot else {
                    break;
                };
                let mut blocks = self
                    .context
                    .stores
                    .chainstate
                    .nakamoto_blocks_db()
                    .get_nakamoto_blocks_in_tenure(&snapshot.consensus_hash)
                    .map_err(|error| error.to_string())?;
                blocks.sort_by(|left, right| {
                    left.header
                        .chain_length
                        .cmp(&right.header.chain_length)
                        .then_with(|| left.header.block_id().0.cmp(&right.header.block_id().0))
                });
                blocks.dedup_by_key(|block| block.header.block_id());
                if block_offset > blocks.len() {
                    return Err("tenure inventory block cursor exceeds the tenure".to_owned());
                }
                while block_offset < blocks.len() && items.len() < limit {
                    let block = &blocks[block_offset];
                    let object = crate::nakamoto_node::libp2p::nakamoto_block_object(block);
                    let object_id = object.content_id.as_bytes().to_vec();
                    network
                        .commit_object(object)
                        .map_err(|error| error.to_string())?;
                    items.push(InventoryItem {
                        index: block.header.chain_length,
                        object_id,
                        available: true,
                        kind: ObjectType::NakamotoBlock as i32,
                    });
                    block_offset += 1;
                }
                if block_offset >= blocks.len() {
                    tenure_offset += 1;
                    block_offset = 0;
                }
            }
            let complete = tenure_offset >= tenures.len();
            let next_cursor = if complete {
                u64::try_from(tenures.len()).unwrap_or(u64::MAX) << 32
            } else {
                (u64::try_from(tenure_offset).unwrap_or(u64::MAX) << 32)
                    | u64::try_from(block_offset)
                        .unwrap_or(u64::MAX)
                        .min(u64::from(u32::MAX))
            };
            Ok(InventoryPage {
                items,
                next_cursor,
                complete,
            })
        })();
        match result {
            Ok(page) => SyncResponse {
                status: Status::Ok as i32,
                response: Some(sync_response::Response::Inventory(page)),
            },
            Err(error) => {
                warn!("Failed to serve libp2p Nakamoto tenure inventory: {error}");
                SyncResponse {
                    status: Status::Busy as i32,
                    response: None,
                }
            }
        }
    }

    fn serve_mempool_inventory(
        &self,
        cursor: &[u8],
        max_items: u32,
        max_bytes: u32,
        network: &NetworkHandle,
    ) -> SyncResponse {
        let result = (|| -> Result<MempoolPage, String> {
            let cursor = if cursor.is_empty() {
                None
            } else {
                Txid::from_bytes(cursor)
            };
            let page = MempoolSyncService::inventory_page(
                self.context.stores.mempool.conn(),
                cursor.as_ref(),
                usize::try_from(max_items).unwrap_or(usize::MAX),
                usize::try_from(max_bytes).unwrap_or(usize::MAX),
            )
            .map_err(|error| error.to_string())?;
            let mut transaction_ids = Vec::with_capacity(page.transactions.len());
            for (txid, transaction) in page.transactions {
                network
                    .commit_object(crate::nakamoto_node::libp2p::transaction_object(
                        &transaction,
                    ))
                    .map_err(|error| error.to_string())?;
                transaction_ids.push(txid.as_bytes().to_vec());
            }
            Ok(MempoolPage {
                transaction_ids,
                next_cursor: page
                    .next_cursor
                    .map(|txid| txid.as_bytes().to_vec())
                    .unwrap_or_default(),
                complete: page.complete,
            })
        })();
        match result {
            Ok(page) => SyncResponse {
                status: Status::Ok as i32,
                response: Some(sync_response::Response::Mempool(page)),
            },
            Err(error) => {
                warn!("Failed to serve bounded libp2p mempool page: {error}");
                SyncResponse {
                    status: Status::Busy as i32,
                    response: None,
                }
            }
        }
    }

    fn serve_attachment_inventory(
        &self,
        cursor: &[u8],
        max_items: u32,
        network: &NetworkHandle,
    ) -> SyncResponse {
        let result = (|| -> Result<AttachmentInventoryPage, String> {
            let cursor = if cursor.is_empty() {
                None
            } else {
                Hash160::from_bytes(cursor)
                    .ok_or_else(|| "invalid attachment inventory cursor".to_owned())?
                    .into()
            };
            let page = AttachmentSyncService::inventory_page(
                self.context.stores.peer_network.get_atlasdb(),
                cursor.as_ref(),
                usize::try_from(max_items).unwrap_or(usize::MAX),
            )
            .map_err(|error| error.to_string())?;
            let mut items = Vec::with_capacity(page.attachments.len());
            for (_, attachment) in page.attachments {
                let object = crate::nakamoto_node::libp2p::attachment_object(&attachment);
                let object_id = object.content_id.as_bytes().to_vec();
                network
                    .commit_object(object)
                    .map_err(|error| error.to_string())?;
                items.push(InventoryItem {
                    index: 0,
                    object_id,
                    available: true,
                    kind: ObjectType::Attachment as i32,
                });
            }
            Ok(AttachmentInventoryPage {
                items,
                next_cursor: page
                    .next_cursor
                    .as_ref()
                    .map(|hash| hash.0.to_vec())
                    .unwrap_or_default(),
                complete: page.complete,
            })
        })();
        match result {
            Ok(page) => SyncResponse {
                status: Status::Ok as i32,
                response: Some(sync_response::Response::Attachments(page)),
            },
            Err(error) => {
                warn!("Failed to serve libp2p attachment inventory: {error}");
                SyncResponse {
                    status: Status::Busy as i32,
                    response: None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    #[derive(Default)]
    struct FakeCanonicalViewSink {
        chain_views: RefCell<Vec<(u64, u64)>>,
        retained_windows: RefCell<Vec<RewardCycleWindow>>,
        signer_sets: RefCell<Vec<(u64, Vec<[u8; 33]>)>>,
        chain_failures: Cell<usize>,
        retain_failures: Cell<usize>,
        signer_failures: RefCell<HashMap<u64, usize>>,
    }

    impl CanonicalViewSink for FakeCanonicalViewSink {
        fn update_chain_view(&self, burn_height: u64, reward_cycle: u64) -> Result<(), String> {
            self.chain_views
                .borrow_mut()
                .push((burn_height, reward_cycle));
            let remaining = self.chain_failures.get();
            if remaining > 0 {
                self.chain_failures.set(remaining - 1);
                return Err("injected chain-view failure".into());
            }
            Ok(())
        }

        fn retain_signer_cycles(&self, window: RewardCycleWindow) -> Result<(), String> {
            self.retained_windows.borrow_mut().push(window);
            let remaining = self.retain_failures.get();
            if remaining > 0 {
                self.retain_failures.set(remaining - 1);
                return Err("injected retention failure".into());
            }
            Ok(())
        }

        fn update_authorized_signers(
            &self,
            reward_cycle: u64,
            public_keys: Vec<[u8; 33]>,
        ) -> Result<(), String> {
            self.signer_sets
                .borrow_mut()
                .push((reward_cycle, public_keys));
            let mut failures = self.signer_failures.borrow_mut();
            let remaining = failures.entry(reward_cycle).or_default();
            if *remaining > 0 {
                *remaining -= 1;
                return Err("injected signer-set failure".into());
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeSignerSetSource {
        sets: HashMap<u64, Vec<[u8; 33]>>,
        loads: Vec<u64>,
    }

    impl SignerSetSource for FakeSignerSetSource {
        fn load_signers(&mut self, reward_cycle: u64) -> Result<Option<Vec<[u8; 33]>>, String> {
            self.loads.push(reward_cycle);
            Ok(self.sets.get(&reward_cycle).cloned())
        }
    }

    fn signer_set_source(cycles: impl IntoIterator<Item = u64>) -> FakeSignerSetSource {
        FakeSignerSetSource {
            sets: cycles
                .into_iter()
                .map(|cycle| (cycle, vec![[u8::try_from(cycle).unwrap(); 33]]))
                .collect(),
            loads: Vec::new(),
        }
    }

    struct FakeLegacyIdentitySink {
        peer_id: Option<PeerId>,
        bindings: RefCell<Vec<LegacyIdentityBinding>>,
        failures: Cell<usize>,
    }

    impl FakeLegacyIdentitySink {
        fn new() -> Self {
            Self {
                peer_id: Some(PeerId::random()),
                bindings: RefCell::new(Vec::new()),
                failures: Cell::new(0),
            }
        }
    }

    impl LegacyIdentitySink for FakeLegacyIdentitySink {
        fn local_peer_id(&self) -> Result<PeerId, String> {
            self.peer_id.ok_or_else(|| "injected PeerId failure".into())
        }

        fn update_binding(&self, binding: LegacyIdentityBinding) -> Result<(), String> {
            let failures = self.failures.get();
            if failures > 0 {
                self.failures.set(failures - 1);
                return Err("injected binding failure".into());
            }
            self.bindings.borrow_mut().push(binding);
            Ok(())
        }
    }

    fn identity_key(byte: u8) -> StacksPrivateKey {
        StacksPrivateKey::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn publication(
        burn_height: u64,
        reward_cycle: u64,
        retained_window: RewardCycleWindow,
        load_next_cycle: bool,
    ) -> CanonicalPublication {
        CanonicalPublication {
            burn_height,
            reward_cycle,
            retained_window,
            load_next_cycle,
        }
    }

    #[test]
    fn modulo_zero_retention_failure_retries_without_false_completion() {
        let now = Instant::now();
        let window = RewardCycleWindow::previous_and_current(13);
        let sink = FakeCanonicalViewSink::default();
        sink.retain_failures.set(1);
        let mut source = signer_set_source([12, 13]);
        let mut publisher = CanonicalViewPublisher::default();

        publisher.refresh(now, publication(260, 13, window, false), &sink, &mut source);
        assert_eq!(&*sink.chain_views.borrow(), &[(260, 13)]);
        assert_eq!(&*sink.retained_windows.borrow(), &[window]);
        assert!(sink.signer_sets.borrow().is_empty());
        assert!(publisher.authorizations.is_empty());

        publisher.refresh(
            now + AUTHORIZATION_RETRY_DELAY - Duration::from_millis(1),
            publication(260, 13, window, false),
            &sink,
            &mut source,
        );
        assert_eq!(sink.retained_windows.borrow().len(), 1);

        publisher.refresh(
            now + AUTHORIZATION_RETRY_DELAY,
            publication(260, 13, window, false),
            &sink,
            &mut source,
        );
        assert_eq!(&*sink.chain_views.borrow(), &[(260, 13)]);
        assert_eq!(&*sink.retained_windows.borrow(), &[window, window]);
        assert_eq!(
            sink.signer_sets
                .borrow()
                .iter()
                .map(|(cycle, _)| *cycle)
                .collect::<Vec<_>>(),
            vec![12, 13]
        );
        assert_eq!(publisher.retained_window, Some(window));
        assert_eq!(
            publisher
                .authorizations
                .keys()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([12, 13])
        );

        publisher.refresh(
            now + AUTHORIZATION_RETRY_DELAY * 2,
            publication(260, 13, window, false),
            &sink,
            &mut source,
        );
        assert_eq!(sink.chain_views.borrow().len(), 1);
        assert_eq!(sink.retained_windows.borrow().len(), 2);
        assert_eq!(sink.signer_sets.borrow().len(), 2);
    }

    #[test]
    fn failed_chain_view_honors_retry_deadline_even_if_view_advances() {
        let now = Instant::now();
        let sink = FakeCanonicalViewSink::default();
        sink.chain_failures.set(1);
        let mut source = signer_set_source([13]);
        let mut publisher = CanonicalViewPublisher::default();

        publisher.refresh(
            now,
            publication(261, 13, RewardCycleWindow::current_only(13), false),
            &sink,
            &mut source,
        );
        assert!(publisher.last_chain_view.is_none());
        assert_eq!(sink.chain_views.borrow().len(), 1);

        publisher.refresh(
            now + AUTHORIZATION_RETRY_DELAY - Duration::from_millis(1),
            publication(262, 13, RewardCycleWindow::current_only(13), false),
            &sink,
            &mut source,
        );
        assert_eq!(sink.chain_views.borrow().len(), 1);

        publisher.refresh(
            now + AUTHORIZATION_RETRY_DELAY,
            publication(262, 13, RewardCycleWindow::current_only(13), false),
            &sink,
            &mut source,
        );
        assert_eq!(publisher.last_chain_view, Some((262, 13)));
        assert_eq!(sink.chain_views.borrow().len(), 2);
    }

    #[test]
    fn failed_signer_set_stays_pending_independently() {
        let now = Instant::now();
        let window = RewardCycleWindow::current_and_next(13);
        let sink = FakeCanonicalViewSink::default();
        sink.signer_failures.borrow_mut().insert(14, 1);
        let mut source = signer_set_source([13, 14]);
        let mut publisher = CanonicalViewPublisher::default();

        publisher.refresh(now, publication(261, 13, window, true), &sink, &mut source);
        assert!(publisher.authorizations.contains_key(&13));
        assert!(!publisher.authorizations.contains_key(&14));

        publisher.refresh(
            now + AUTHORIZATION_RETRY_DELAY,
            publication(261, 13, window, true),
            &sink,
            &mut source,
        );
        assert!(publisher.authorizations.contains_key(&14));
        assert_eq!(
            sink.signer_sets
                .borrow()
                .iter()
                .filter(|(cycle, _)| *cycle == 13)
                .count(),
            1
        );
        assert_eq!(
            sink.signer_sets
                .borrow()
                .iter()
                .filter(|(cycle, _)| *cycle == 14)
                .count(),
            2
        );
    }

    #[test]
    fn unavailable_signer_set_retries_and_unchanged_set_does_not_republish() {
        let now = Instant::now();
        let window = RewardCycleWindow::current_only(13);
        let sink = FakeCanonicalViewSink::default();
        let mut source = FakeSignerSetSource::default();
        let mut publisher = CanonicalViewPublisher::default();

        publisher.refresh(now, publication(261, 13, window, false), &sink, &mut source);
        assert_eq!(source.loads, vec![13]);
        assert!(!publisher.authorizations.contains_key(&13));

        publisher.refresh(
            now + AUTHORIZATION_RETRY_DELAY - Duration::from_millis(1),
            publication(261, 13, window, false),
            &sink,
            &mut source,
        );
        assert_eq!(source.loads, vec![13]);

        source.sets.insert(13, vec![[13; 33]]);
        publisher.refresh(
            now + AUTHORIZATION_RETRY_DELAY,
            publication(261, 13, window, false),
            &sink,
            &mut source,
        );
        assert!(publisher.authorizations.contains_key(&13));
        assert_eq!(sink.signer_sets.borrow().len(), 1);

        // A changed burn view still republishes the chain marker, but the
        // byte-identical canonical signer set remains installed exactly once.
        publisher.refresh(
            now + AUTHORIZATION_RETRY_DELAY * 2,
            publication(262, 13, window, false),
            &sink,
            &mut source,
        );
        assert_eq!(sink.chain_views.borrow().len(), 2);
        assert_eq!(sink.signer_sets.borrow().len(), 1);
    }

    #[test]
    fn legacy_identity_marker_advances_only_after_accepted_publication() {
        let key = identity_key(1);
        let mut publisher = LegacyIdentityPublisher::default();
        let sink = FakeLegacyIdentitySink::new();
        sink.failures.set(1);

        publisher.publish_local(0x8000_0000, &key, 100, &sink);
        assert!(publisher.last_binding.is_none());
        assert!(sink.bindings.borrow().is_empty());

        publisher.publish_local(0x8000_0000, &key, 100, &sink);
        assert!(publisher.last_binding.is_some());
        assert_eq!(sink.bindings.borrow().len(), 1);

        // An accepted unchanged key/expiry is idempotent. Expiry rotation and
        // key rotation each establish a new signed binding.
        publisher.publish_local(0x8000_0000, &key, 100, &sink);
        assert_eq!(sink.bindings.borrow().len(), 1);
        publisher.publish_local(0x8000_0000, &key, 101, &sink);
        publisher.publish_local(0x8000_0000, &identity_key(2), 101, &sink);
        assert_eq!(sink.bindings.borrow().len(), 3);
    }

    #[test]
    fn unavailable_peer_id_leaves_identity_publication_retryable() {
        let key = identity_key(3);
        let mut publisher = LegacyIdentityPublisher::default();
        let mut sink = FakeLegacyIdentitySink::new();
        sink.peer_id = None;

        publisher.publish_local(0x8000_0000, &key, 100, &sink);
        assert!(publisher.last_binding.is_none());
        assert!(sink.bindings.borrow().is_empty());
    }

    #[test]
    fn signing_and_pox_horizons_split_at_mod_zero() {
        // Height 260 is signed by cycle 13, while its modulo-1 PoX reward
        // boundary is height 261 and is not yet in the processed sortition DB.
        assert_eq!(
            sync_cycle_horizons(13, 261, 260, 14),
            SyncHorizons {
                pox_through_cycle: 12,
                tenure_through_cycle: 13,
            }
        );
        assert_eq!(
            sync_cycle_horizons(13, 261, 261, 14),
            SyncHorizons {
                pox_through_cycle: 13,
                tenure_through_cycle: 13,
            }
        );
        assert_eq!(
            sync_cycle_horizons(13, 261, 260, 12),
            SyncHorizons {
                pox_through_cycle: 12,
                tenure_through_cycle: 12,
            }
        );
    }

    #[test]
    fn signer_authorization_retains_previous_only_at_mod_zero() {
        assert_eq!(
            signer_authorization_cycle_window(13, true),
            RewardCycleWindow::new(12, Some(13)).unwrap()
        );
        assert_eq!(
            signer_authorization_cycle_window(13, false),
            RewardCycleWindow::new(13, Some(14)).unwrap()
        );
        assert_eq!(
            signer_authorization_cycle_window(0, true),
            RewardCycleWindow::new(0, Some(1)).unwrap()
        );
        assert_eq!(
            signer_authorization_cycle_window(u64::MAX, false),
            RewardCycleWindow::current_only(u64::MAX)
        );
    }

    #[test]
    fn pending_sync_installs_only_after_transport_acceptance() {
        let now = Instant::now();
        let mut pending = PendingSyncRequests::default();

        // Merely obtaining the ID used for a transport attempt neither
        // advances allocation nor creates a response obligation.
        assert_eq!(pending.correlation_candidate(), 0);
        assert_eq!(pending.correlation_candidate(), 0);
        assert!(pending.is_empty());

        let correlation = pending.install_accepted(NakamotoSyncStep::status(), now);
        assert_eq!(correlation, 0);
        assert_eq!(pending.correlation_candidate(), 1);
        assert!(!pending.is_empty());
        assert!(matches!(
            pending.remove(correlation).map(|plan| plan.stage().clone()),
            Some(SyncStage::Status)
        ));
        // A late hedge response cannot consume or advance the plan twice.
        assert!(pending.remove(correlation).is_none());
    }

    #[test]
    fn status_hedges_preserve_the_recovery_anchor_and_rotate_alternatives() {
        let peers = (0..5).map(|_| PeerId::random()).collect::<Vec<_>>();
        let mut runtime = NodeSyncRuntime {
            pending: PendingSyncRequests::default(),
            next_probe: Instant::now(),
            status_provider_cursor: 0,
        };

        let mut first = peers.clone();
        runtime.rotate_status_hedges(&mut first, 2);
        assert_eq!(&first[..2], &peers[..2]);

        let mut second = peers.clone();
        runtime.rotate_status_hedges(&mut second, 2);
        assert_eq!(second[0], peers[0]);
        assert_eq!(second[1], peers[2]);

        let mut third = peers.clone();
        runtime.rotate_status_hedges(&mut third, 2);
        assert_eq!(third[0], peers[0]);
        assert_eq!(third[1], peers[3]);
    }

    #[test]
    fn not_ahead_status_response_does_not_cancel_other_hedged_probes() {
        let now = Instant::now();
        let mut pending = PendingSyncRequests::default();
        let first = pending.install_accepted(NakamotoSyncStep::status(), now);
        let second = pending.install_accepted(NakamotoSyncStep::status(), now);

        assert!(matches!(
            pending.remove(first).map(|plan| plan.stage().clone()),
            Some(SyncStage::Status)
        ));
        assert!(pending.has_stage(|stage| matches!(stage, SyncStage::Status)));

        assert!(matches!(
            pending.remove(second).map(|plan| plan.stage().clone()),
            Some(SyncStage::Status)
        ));
        assert!(!pending.has_stage(|stage| matches!(stage, SyncStage::Status)));
    }

    #[test]
    fn pending_sync_expiry_stage_cancellation_and_wrap_are_bounded() {
        let now = Instant::now();
        let mut pending = PendingSyncRequests {
            entries: HashMap::new(),
            next_correlation: u64::MAX,
        };
        let status =
            pending.install_accepted(NakamotoSyncStep::status(), now - Duration::from_secs(16));
        assert_eq!(status, u64::MAX);
        assert_eq!(pending.correlation_candidate(), 0);
        pending.install_accepted(NakamotoSyncStep::mempool(), now);

        pending.expire(now, Duration::from_secs(15));
        assert!(pending.remove(status).is_none());
        assert_eq!(pending.entries.len(), 1);

        pending.install_accepted(NakamotoSyncStep::status(), now);
        pending.remove_stage(|stage| matches!(stage, SyncStage::Status));
        assert_eq!(pending.entries.len(), 1);
        assert!(pending
            .entries
            .values()
            .all(|(plan, _)| matches!(plan.stage(), SyncStage::Mempool { .. })));
    }
}
