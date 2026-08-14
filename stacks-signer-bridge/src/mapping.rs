use std::collections::{HashMap, VecDeque};

use clarity::codec::StacksMessageCodec;
use libsigner::v0::messages::{SignerMessage, SignerMessageTypePrefix};
use libsigner::{
    AuthenticatedSignerEvent, SignerEventAuthentication, SignerIngressOrigin, SignerNetworkMessage,
};
use libstackerdb::StackerDBChunkData;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_common::util::hash::Hash160;
use stacks_network_types::bridge::{legacy_chunk_content_id, semantic_signer_message_content_id};
use stacks_network_types::wire::v1::SignerLane;
use stacks_network_types::ContentId;

use crate::{
    BridgeJournal, BridgeJournalError, CorrelationRecord, SignerBridgeConfig,
    SignerBridgeConfigError,
};

const MAX_LEGACY_CHUNK_BYTES: usize = 2 * 1024 * 1024;

/// Exact legacy author evidence supplied by chainstate or configuration.
#[derive(Clone, Debug, PartialEq)]
pub enum LegacyAuthor {
    /// Full key is known, as it is for signer slots and local bridge egress.
    PublicKey([u8; 33]),
    /// Sortition publishes the Nakamoto signing-key hash, not the full key.
    PublicKeyHash160([u8; 20]),
}

impl LegacyAuthor {
    fn admits(&self, public_key: &StacksPublicKey) -> bool {
        match self {
            Self::PublicKey(expected) => public_key.to_bytes_compressed().as_slice() == expected,
            Self::PublicKeyHash160(expected) => {
                Hash160::from_data(&public_key.to_bytes_compressed()).as_bytes() == expected
            }
        }
    }

    fn exact_public_key(&self) -> Option<&[u8; 33]> {
        match self {
            Self::PublicKey(public_key) => Some(public_key),
            Self::PublicKeyHash160(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LegacyLocator {
    pub contract: String,
    pub reward_cycle: u64,
    pub lane: SignerLane,
    pub slot_id: u32,
    pub author: LegacyAuthor,
    pub allow_epoch25: bool,
}

/// Chainstate/configuration-owned resolver. Unknown contract/slot pairs must
/// return `None`; the bridge never infers authorization from payload bytes.
pub trait LegacyChunkPolicy {
    fn resolve(&self, contract: &str, slot_id: u32) -> Option<LegacyLocator>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct PendingLegacyWrite {
    pub locator: LegacyLocator,
    pub chunk: StackerDBChunkData,
    pub chunk_id: ContentId,
    pub semantic_id: ContentId,
    pub native_envelope_id: Option<ContentId>,
}

impl PendingLegacyWrite {
    fn encoded_len(&self) -> usize {
        self.chunk.data.len().saturating_add(256)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BridgeDiagnostics {
    pub ingress_accepted: u64,
    pub ingress_observed: u64,
    pub ingress_rejected: u64,
    pub ingress_duplicates: u64,
    pub ingress_equivocations: u64,
    pub suppressed_local_echoes: u64,
    pub egress_queued: u64,
    pub egress_queue_full: u64,
    pub egress_succeeded: u64,
    pub egress_failed: u64,
    pub queue_items: usize,
    pub queue_bytes: usize,
    pub last_progress_unix_secs: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum TemporarySignerBridgeError {
    #[error(transparent)]
    Config(#[from] SignerBridgeConfigError),
    #[error(transparent)]
    Journal(#[from] BridgeJournalError),
    #[error("legacy bridge direction is disabled by runtime mode")]
    Disabled,
    #[error("unknown or unauthorized legacy contract/slot mapping")]
    Mapping,
    #[error("legacy chunk exceeds the signer protocol limit")]
    TooLarge,
    #[error("legacy chunk signature does not match the configured author")]
    Author,
    #[error("legacy signer payload is malformed or has trailing bytes")]
    Payload,
    #[error("legacy signer payload type does not match its configured lane")]
    Lane,
    #[error("legacy bridge queue is full")]
    QueueFull,
    #[error("legacy chunk signing or encoding failed: {0}")]
    Signing(String),
}

pub struct TemporarySignerBridge {
    config: SignerBridgeConfig,
    journal: BridgeJournal,
    writes: VecDeque<PendingLegacyWrite>,
    queue_bytes: usize,
    latest: HashMap<(String, u32, u64), (u32, ContentId)>,
    diagnostics: BridgeDiagnostics,
}

impl TemporarySignerBridge {
    pub fn new(
        config: SignerBridgeConfig,
        journal: BridgeJournal,
    ) -> Result<Self, TemporarySignerBridgeError> {
        config.validate()?;
        Ok(Self {
            config,
            journal,
            writes: VecDeque::new(),
            queue_bytes: 0,
            latest: HashMap::new(),
            diagnostics: BridgeDiagnostics::default(),
        })
    }

    /// Verify and translate one legacy chunk for local consumption. The result
    /// carries opaque signed-chunk evidence and is never eligible for native
    /// gossip because it has no native author signature.
    pub fn ingest(
        &mut self,
        contract: &str,
        chunk: &StackerDBChunkData,
        policy: &impl LegacyChunkPolicy,
        observed_at: u64,
    ) -> Result<Option<AuthenticatedSignerEvent>, TemporarySignerBridgeError> {
        if !self.config.mode.accepts_ingress() {
            return Err(TemporarySignerBridgeError::Disabled);
        }
        if chunk.data.len() > MAX_LEGACY_CHUNK_BYTES {
            self.diagnostics.ingress_rejected += 1;
            return Err(TemporarySignerBridgeError::TooLarge);
        }
        let locator = policy
            .resolve(contract, chunk.slot_id)
            .filter(|locator| locator.contract == contract && locator.slot_id == chunk.slot_id)
            .ok_or_else(|| {
                self.diagnostics.ingress_rejected += 1;
                TemporarySignerBridgeError::Mapping
            })?;
        let author = chunk.recover_pk().map_err(|_| {
            self.diagnostics.ingress_rejected += 1;
            TemporarySignerBridgeError::Author
        })?;
        if !locator.author.admits(&author) {
            self.diagnostics.ingress_rejected += 1;
            return Err(TemporarySignerBridgeError::Author);
        }

        let mut payload = chunk.data.as_slice();
        let decoded = SignerMessage::consensus_deserialize(&mut payload).map_err(|_| {
            self.diagnostics.ingress_rejected += 1;
            TemporarySignerBridgeError::Payload
        })?;
        if !payload.is_empty() {
            self.diagnostics.ingress_rejected += 1;
            return Err(TemporarySignerBridgeError::Payload);
        }
        let prefix = SignerMessageTypePrefix::from(&decoded);
        if lane_for_prefix(prefix, locator.allow_epoch25) != Some(locator.lane) {
            self.diagnostics.ingress_rejected += 1;
            return Err(TemporarySignerBridgeError::Lane);
        }
        let signed_chunk = encode_chunk(chunk)?;
        let chunk_id = legacy_chunk_id(contract, locator.reward_cycle, &signed_chunk);
        if self.journal.is_local_echo(chunk_id)? {
            self.diagnostics.suppressed_local_echoes += 1;
            self.progress(observed_at);
            return Ok(None);
        }

        let latest_key = (contract.to_owned(), chunk.slot_id, locator.reward_cycle);
        let mut is_equivocation = false;
        if let Some((latest_version, latest_id)) = self.latest.get(&latest_key) {
            if chunk.slot_version < *latest_version
                || (chunk.slot_version == *latest_version && chunk_id == *latest_id)
            {
                self.diagnostics.ingress_duplicates += 1;
                return Ok(None);
            }
            if chunk.slot_version == *latest_version {
                is_equivocation = true;
                self.diagnostics.ingress_equivocations += 1;
            }
        }
        if !is_equivocation {
            self.latest
                .insert(latest_key, (chunk.slot_version, chunk_id));
        }

        self.diagnostics.ingress_observed += 1;
        self.progress(observed_at);
        if !self.config.mode.emits_events() {
            return Ok(None);
        }
        self.diagnostics.ingress_accepted += 1;
        Ok(Some(AuthenticatedSignerEvent {
            message: SignerNetworkMessage {
                reward_cycle: locator.reward_cycle,
                lane: locator.lane,
                burn_view_consensus_hash: Vec::new(),
                payload: chunk.data.clone(),
            },
            authentication: SignerEventAuthentication::LegacyCompatibility {
                signed_chunk,
                chunk_id,
                author_public_key: author.to_bytes_compressed(),
                slot_version: chunk.slot_version,
            },
            origin: SignerIngressOrigin::LegacyCompatibility,
            is_equivocation,
        }))
    }

    /// Translate a locally authored semantic message to a signed legacy chunk.
    /// Possession of the exact configured private key is the origin-only guard.
    pub fn enqueue_origin_egress(
        &mut self,
        message: &SignerNetworkMessage,
        native_envelope_id: Option<ContentId>,
        locator: LegacyLocator,
        author: &StacksPrivateKey,
        observed_at: u64,
    ) -> Result<ContentId, TemporarySignerBridgeError> {
        if !self.config.mode.writes_legacy() {
            return Err(TemporarySignerBridgeError::Disabled);
        }
        if message.reward_cycle != locator.reward_cycle || message.lane != locator.lane {
            return Err(TemporarySignerBridgeError::Lane);
        }
        let author_public_key = StacksPublicKey::from_private(author).to_bytes_compressed();
        let Some(expected_author) = locator.author.exact_public_key() else {
            return Err(TemporarySignerBridgeError::Author);
        };
        if author_public_key.as_slice() != expected_author {
            return Err(TemporarySignerBridgeError::Author);
        }
        let mut payload = message.payload.as_slice();
        let decoded = SignerMessage::consensus_deserialize(&mut payload)
            .map_err(|_| TemporarySignerBridgeError::Payload)?;
        if !payload.is_empty()
            || lane_for_prefix(
                SignerMessageTypePrefix::from(&decoded),
                locator.allow_epoch25,
            ) != Some(locator.lane)
        {
            return Err(TemporarySignerBridgeError::Lane);
        }
        let estimated_bytes = message.payload.len().saturating_add(256);
        if self.writes.len() >= self.config.queue_max_items
            || self.queue_bytes.saturating_add(estimated_bytes) > self.config.queue_max_bytes
        {
            self.diagnostics.egress_queue_full += 1;
            return Err(TemporarySignerBridgeError::QueueFull);
        }
        let semantic_id = semantic_message_id(message, &author_public_key);
        let contract = locator.contract.clone();
        let slot_id = locator.slot_id;
        let payload = message.payload.clone();
        let reward_cycle = message.reward_cycle;
        let record = self
            .journal
            .reserve_and_record_with(&contract, slot_id, |slot_version| {
                let mut chunk = StackerDBChunkData::new(slot_id, slot_version, payload);
                chunk
                    .sign(author)
                    .map_err(|error| BridgeJournalError::Build(error.to_string()))?;
                let signed_chunk = encode_chunk(&chunk)
                    .map_err(|error| BridgeJournalError::Build(error.to_string()))?;
                let chunk_id = legacy_chunk_id(&contract, reward_cycle, &signed_chunk);
                Ok(CorrelationRecord {
                    semantic_id,
                    native_envelope_id,
                    chunk_id,
                    reward_cycle,
                    contract: contract.clone(),
                    slot_id,
                    slot_version,
                    chunk: signed_chunk,
                    state: 0,
                    observed_at,
                })
            })?;
        let mut encoded = record.chunk.as_slice();
        let chunk = StackerDBChunkData::consensus_deserialize(&mut encoded)
            .map_err(|error| TemporarySignerBridgeError::Signing(error.to_string()))?;
        if !encoded.is_empty() {
            return Err(TemporarySignerBridgeError::Signing(
                "journaled chunk has trailing bytes".to_owned(),
            ));
        }
        let pending = PendingLegacyWrite {
            locator,
            chunk,
            chunk_id: record.chunk_id,
            semantic_id,
            native_envelope_id,
        };
        self.queue_bytes = self.queue_bytes.saturating_add(pending.encoded_len());
        self.writes.push_back(pending);
        self.diagnostics.egress_queued += 1;
        self.refresh_queue_diagnostics();
        self.progress(observed_at);
        Ok(record.chunk_id)
    }

    pub fn try_next_write(&mut self) -> Option<PendingLegacyWrite> {
        let write = self.writes.pop_front()?;
        self.queue_bytes = self.queue_bytes.saturating_sub(write.encoded_len());
        self.refresh_queue_diagnostics();
        Some(write)
    }

    pub fn record_write_outcome(
        &mut self,
        chunk_id: ContentId,
        succeeded: bool,
        observed_at: u64,
    ) -> Result<(), TemporarySignerBridgeError> {
        self.journal
            .mark_state(chunk_id, if succeeded { 1 } else { 2 })?;
        if succeeded {
            self.diagnostics.egress_succeeded += 1;
        } else {
            self.diagnostics.egress_failed += 1;
        }
        self.progress(observed_at);
        Ok(())
    }

    pub fn advance_legacy_version_floor(
        &self,
        contract: &str,
        slot_id: u32,
        next_version: u32,
    ) -> Result<(), TemporarySignerBridgeError> {
        self.journal
            .advance_version_floor(contract, slot_id, next_version)?;
        Ok(())
    }

    pub fn update_cycles(
        &mut self,
        current: u64,
        next: Option<u64>,
    ) -> Result<(), TemporarySignerBridgeError> {
        self.journal.prune_cycles(current, next)?;
        self.latest
            .retain(|(_, _, cycle), _| *cycle == current || Some(*cycle) == next);
        self.writes.retain(|write| {
            write.locator.reward_cycle == current || Some(write.locator.reward_cycle) == next
        });
        self.queue_bytes = self
            .writes
            .iter()
            .map(PendingLegacyWrite::encoded_len)
            .sum();
        self.refresh_queue_diagnostics();
        Ok(())
    }

    pub fn diagnostics(&self) -> BridgeDiagnostics {
        self.diagnostics.clone()
    }

    fn progress(&mut self, observed_at: u64) {
        self.diagnostics.last_progress_unix_secs = observed_at;
    }

    fn refresh_queue_diagnostics(&mut self) {
        self.diagnostics.queue_items = self.writes.len();
        self.diagnostics.queue_bytes = self.queue_bytes;
    }
}

pub fn legacy_chunk_id(contract: &str, reward_cycle: u64, signed_chunk: &[u8]) -> ContentId {
    legacy_chunk_content_id(contract, reward_cycle, signed_chunk)
}

pub fn semantic_message_id(message: &SignerNetworkMessage, author: &[u8]) -> ContentId {
    semantic_signer_message_content_id(message.reward_cycle, message.lane, author, &message.payload)
}

fn encode_chunk(chunk: &StackerDBChunkData) -> Result<Vec<u8>, TemporarySignerBridgeError> {
    let mut encoded = Vec::new();
    chunk
        .consensus_serialize(&mut encoded)
        .map_err(|error| TemporarySignerBridgeError::Signing(error.to_string()))?;
    Ok(encoded)
}

fn lane_for_prefix(prefix: SignerMessageTypePrefix, allow_epoch25: bool) -> Option<SignerLane> {
    match prefix {
        SignerMessageTypePrefix::BlockProposal => Some(SignerLane::BlockProposal),
        SignerMessageTypePrefix::BlockResponse => Some(SignerLane::BlockResponse),
        SignerMessageTypePrefix::BlockPushed => Some(SignerLane::BlockPushed),
        SignerMessageTypePrefix::StateMachineUpdate => Some(SignerLane::StateMachineUpdate),
        SignerMessageTypePrefix::BlockPreCommit => Some(SignerLane::BlockPreCommit),
        SignerMessageTypePrefix::MockSignature if allow_epoch25 => Some(SignerLane::BlockResponse),
        SignerMessageTypePrefix::MockProposal if allow_epoch25 => Some(SignerLane::BlockProposal),
        SignerMessageTypePrefix::MockBlock if allow_epoch25 => Some(SignerLane::BlockPushed),
        SignerMessageTypePrefix::MockSignature
        | SignerMessageTypePrefix::MockProposal
        | SignerMessageTypePrefix::MockBlock => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::BridgeMode;
    use libsigner::v0::messages::SignerMessage;
    use stacks_common::util::hash::Sha512Trunc256Sum;
    use tempfile::TempDir;

    use super::*;

    #[derive(Clone)]
    struct ExactPolicy(LegacyLocator);

    impl LegacyChunkPolicy for ExactPolicy {
        fn resolve(&self, contract: &str, slot_id: u32) -> Option<LegacyLocator> {
            (contract == self.0.contract && slot_id == self.0.slot_id).then(|| self.0.clone())
        }
    }

    fn payload() -> Vec<u8> {
        let mut bytes = Vec::new();
        SignerMessage::BlockPreCommit(Sha512Trunc256Sum([7; 32]))
            .consensus_serialize(&mut bytes)
            .unwrap();
        bytes
    }

    fn setup(path: &std::path::Path) -> (TemporarySignerBridge, StacksPrivateKey, ExactPolicy) {
        let key = StacksPrivateKey::from_seed(&[71; 32]);
        let locator = LegacyLocator {
            contract: "ST000000000000000000002AMW42H.signers-0-3".to_owned(),
            reward_cycle: 12,
            lane: SignerLane::BlockPreCommit,
            slot_id: 4,
            author: LegacyAuthor::PublicKey(
                StacksPublicKey::from_private(&key)
                    .to_bytes_compressed()
                    .try_into()
                    .unwrap(),
            ),
            allow_epoch25: false,
        };
        let bridge = TemporarySignerBridge::new(
            SignerBridgeConfig::default(),
            BridgeJournal::open(path).unwrap(),
        )
        .unwrap();
        (bridge, key, ExactPolicy(locator))
    }

    #[test]
    fn verified_legacy_ingress_never_manufactures_native_authentication() {
        let tempdir = TempDir::new().unwrap();
        let (mut bridge, key, policy) = setup(&tempdir.path().join("bridge.sqlite"));
        let mut chunk = StackerDBChunkData::new(policy.0.slot_id, 9, payload());
        chunk.sign(&key).unwrap();
        let event = bridge
            .ingest(&policy.0.contract, &chunk, &policy, 1000)
            .unwrap()
            .unwrap();
        assert_eq!(event.origin, SignerIngressOrigin::LegacyCompatibility);
        assert_eq!(event.message.lane, SignerLane::BlockPreCommit);
        assert!(event.native_envelope().is_none());
        assert!(matches!(
            event.authentication,
            SignerEventAuthentication::LegacyCompatibility {
                slot_version: 9,
                ..
            }
        ));

        let wrong_key = StacksPrivateKey::from_seed(&[72; 32]);
        chunk.sign(&wrong_key).unwrap();
        assert!(matches!(
            bridge.ingest(&policy.0.contract, &chunk, &policy, 1001),
            Err(TemporarySignerBridgeError::Author)
        ));
    }

    #[test]
    fn hash_authorization_admits_exact_sortition_key_but_cannot_authorize_egress() {
        let tempdir = TempDir::new().unwrap();
        let (mut bridge, key, mut policy) = setup(&tempdir.path().join("bridge.sqlite"));
        let key_bytes = StacksPublicKey::from_private(&key).to_bytes_compressed();
        policy.0.author = LegacyAuthor::PublicKeyHash160(Hash160::from_data(&key_bytes).0);
        let mut chunk = StackerDBChunkData::new(policy.0.slot_id, 1, payload());
        chunk.sign(&key).unwrap();
        assert!(bridge
            .ingest(&policy.0.contract, &chunk, &policy, 1000)
            .unwrap()
            .is_some());

        let message = SignerNetworkMessage {
            reward_cycle: policy.0.reward_cycle,
            lane: policy.0.lane,
            burn_view_consensus_hash: Vec::new(),
            payload: payload(),
        };
        assert!(matches!(
            bridge.enqueue_origin_egress(&message, None, policy.0, &key, 1001),
            Err(TemporarySignerBridgeError::Author)
        ));
    }

    #[test]
    fn origin_egress_versions_survive_restart_and_written_chunks_are_suppressed() {
        let tempdir = TempDir::new().unwrap();
        let path = tempdir.path().join("bridge.sqlite");
        let message = SignerNetworkMessage {
            reward_cycle: 12,
            lane: SignerLane::BlockPreCommit,
            burn_view_consensus_hash: vec![3; 20],
            payload: payload(),
        };

        {
            let (mut bridge, key, policy) = setup(&path);
            let chunk_id = bridge
                .enqueue_origin_egress(&message, None, policy.0.clone(), &key, 2000)
                .unwrap();
            let write = bridge.try_next_write().unwrap();
            assert_eq!(write.chunk.slot_version, 0);
            assert_eq!(write.chunk_id, chunk_id);
            assert!(bridge
                .ingest(&policy.0.contract, &write.chunk, &policy, 2001)
                .unwrap()
                .is_none());
            assert_eq!(bridge.diagnostics().suppressed_local_echoes, 1);
        }

        let (mut reopened, key, policy) = setup(&path);
        reopened
            .enqueue_origin_egress(&message, None, policy.0.clone(), &key, 2002)
            .unwrap();
        assert_eq!(reopened.try_next_write().unwrap().chunk.slot_version, 1);
    }

    #[test]
    fn cycle_updates_retain_only_current_and_next_and_allow_reorg_reentry() {
        let tempdir = TempDir::new().unwrap();
        let (mut bridge, key, policy) = setup(&tempdir.path().join("bridge.sqlite"));

        for reward_cycle in [12, 13, 14] {
            let mut locator = policy.0.clone();
            locator.reward_cycle = reward_cycle;
            bridge
                .enqueue_origin_egress(
                    &SignerNetworkMessage {
                        reward_cycle,
                        lane: locator.lane,
                        burn_view_consensus_hash: vec![reward_cycle as u8; 20],
                        payload: payload(),
                    },
                    None,
                    locator,
                    &key,
                    2500 + reward_cycle,
                )
                .unwrap();
        }

        let pending_for = |bridge: &TemporarySignerBridge, reward_cycle| {
            bridge
                .writes
                .iter()
                .find(|write| write.locator.reward_cycle == reward_cycle)
                .cloned()
                .unwrap()
        };
        let cycle_12 = pending_for(&bridge, 12);
        let cycle_13 = pending_for(&bridge, 13);
        let cycle_14 = pending_for(&bridge, 14);

        bridge.update_cycles(12, Some(13)).unwrap();
        assert_eq!(bridge.diagnostics().queue_items, 2);

        let mut cycle_14_policy = policy.clone();
        cycle_14_policy.0.reward_cycle = 14;
        assert!(bridge
            .ingest(
                &cycle_14.locator.contract,
                &cycle_14.chunk,
                &cycle_14_policy,
                2600,
            )
            .unwrap()
            .is_some());
        assert!(bridge
            .ingest(&cycle_12.locator.contract, &cycle_12.chunk, &policy, 2601,)
            .unwrap()
            .is_none());

        // A reorg can move the active window backwards. Cycle 12 remains
        // correlated while the former next cycle is pruned and retryable.
        bridge.update_cycles(12, None).unwrap();
        assert_eq!(bridge.diagnostics().queue_items, 1);
        let mut cycle_13_policy = policy.clone();
        cycle_13_policy.0.reward_cycle = 13;
        assert!(bridge
            .ingest(
                &cycle_13.locator.contract,
                &cycle_13.chunk,
                &cycle_13_policy,
                2602,
            )
            .unwrap()
            .is_some());
        assert!(bridge
            .ingest(&cycle_12.locator.contract, &cycle_12.chunk, &policy, 2603,)
            .unwrap()
            .is_none());
    }

    #[test]
    fn observe_mode_verifies_without_emitting_or_writing() {
        let tempdir = TempDir::new().unwrap();
        let path = tempdir.path().join("bridge.sqlite");
        let (mut bridge, key, policy) = setup(&path);
        bridge.config.mode = BridgeMode::Observe;
        let mut chunk = StackerDBChunkData::new(policy.0.slot_id, 1, payload());
        chunk.sign(&key).unwrap();
        assert!(bridge
            .ingest(&policy.0.contract, &chunk, &policy, 3000)
            .unwrap()
            .is_none());
        assert_eq!(bridge.diagnostics().ingress_observed, 1);
        assert!(matches!(
            bridge.enqueue_origin_egress(
                &SignerNetworkMessage {
                    reward_cycle: 12,
                    lane: SignerLane::BlockPreCommit,
                    burn_view_consensus_hash: Vec::new(),
                    payload: payload(),
                },
                None,
                policy.0,
                &key,
                3001,
            ),
            Err(TemporarySignerBridgeError::Disabled)
        ));
    }

    #[test]
    fn off_and_ingress_only_modes_enforce_both_directions() {
        let tempdir = TempDir::new().unwrap();
        let path = tempdir.path().join("bridge.sqlite");
        let (mut bridge, key, policy) = setup(&path);
        let mut chunk = StackerDBChunkData::new(policy.0.slot_id, 1, payload());
        chunk.sign(&key).unwrap();
        let message = SignerNetworkMessage {
            reward_cycle: policy.0.reward_cycle,
            lane: policy.0.lane,
            burn_view_consensus_hash: Vec::new(),
            payload: payload(),
        };

        bridge.config.mode = BridgeMode::Off;
        assert!(matches!(
            bridge.ingest(&policy.0.contract, &chunk, &policy, 4000),
            Err(TemporarySignerBridgeError::Disabled)
        ));
        assert!(matches!(
            bridge.enqueue_origin_egress(&message, None, policy.0.clone(), &key, 4001),
            Err(TemporarySignerBridgeError::Disabled)
        ));

        bridge.config.mode = BridgeMode::IngressOnly;
        let event = bridge
            .ingest(&policy.0.contract, &chunk, &policy, 4002)
            .unwrap()
            .expect("ingress-only must emit verified semantic events");
        assert_eq!(event.origin, SignerIngressOrigin::LegacyCompatibility);
        assert!(matches!(
            bridge.enqueue_origin_egress(&message, None, policy.0, &key, 4003),
            Err(TemporarySignerBridgeError::Disabled)
        ));
    }
}
