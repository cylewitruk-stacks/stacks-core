use std::collections::{HashSet, VecDeque};

use libsigner::{
    AuthenticatedSignerEvent, PublishReceipt, ReplayRequest, SignerNetwork, SignerNetworkError,
    SignerNetworkMessage,
};
use libstackerdb::StackerDBChunkData;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_network_types::ContentId;

use crate::{
    semantic_message_id, LegacyChunkPolicy, LegacyLocator, PendingLegacyWrite,
    TemporarySignerBridge, TemporarySignerBridgeError,
};

const SEMANTIC_DEDUP_ITEMS: usize = 4096;

pub trait OriginLegacyMapping {
    fn locator_for_origin(
        &self,
        message: &SignerNetworkMessage,
        author_public_key: &[u8; 33],
    ) -> Option<LegacyLocator>;
}

pub trait LegacyChunkWriter {
    fn write(&mut self, pending: &PendingLegacyWrite) -> Result<(), String>;
}

/// Native-first signer transport composed with the quarantined compatibility
/// bridge. Only `publish`, which holds the local author key, can write legacy;
/// remote native events never enter that path.
pub struct CompositeSignerNetwork<N, M, W> {
    native: N,
    bridge: TemporarySignerBridge,
    mapping: M,
    writer: W,
    local_key: StacksPrivateKey,
    compatibility_events: VecDeque<AuthenticatedSignerEvent>,
    retry_writes: VecDeque<PendingLegacyWrite>,
    semantic_seen: HashSet<ContentId>,
    semantic_order: VecDeque<ContentId>,
}

impl<N, M, W> CompositeSignerNetwork<N, M, W>
where
    N: SignerNetwork,
    M: OriginLegacyMapping,
    W: LegacyChunkWriter,
{
    pub fn new(
        native: N,
        bridge: TemporarySignerBridge,
        mapping: M,
        writer: W,
        local_key: StacksPrivateKey,
    ) -> Self {
        Self {
            native,
            bridge,
            mapping,
            writer,
            local_key,
            compatibility_events: VecDeque::new(),
            retry_writes: VecDeque::new(),
            semantic_seen: HashSet::new(),
            semantic_order: VecDeque::new(),
        }
    }

    pub fn ingest_legacy(
        &mut self,
        contract: &str,
        chunk: &StackerDBChunkData,
        policy: &impl LegacyChunkPolicy,
        observed_at: u64,
    ) -> Result<(), TemporarySignerBridgeError> {
        if let Some(event) = self.bridge.ingest(contract, chunk, policy, observed_at)? {
            self.compatibility_events.push_back(event);
        }
        Ok(())
    }

    pub fn pump_compatibility_writer(&mut self, observed_at: u64) {
        let pending = self
            .retry_writes
            .pop_front()
            .or_else(|| self.bridge.try_next_write());
        let Some(pending) = pending else {
            return;
        };
        let succeeded = self.writer.write(&pending).is_ok();
        let _ = self
            .bridge
            .record_write_outcome(pending.chunk_id, succeeded, observed_at);
        if !succeeded {
            self.retry_writes.push_back(pending);
        }
    }

    pub fn bridge(&self) -> &TemporarySignerBridge {
        &self.bridge
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
}

impl<N, M, W> SignerNetwork for CompositeSignerNetwork<N, M, W>
where
    N: SignerNetwork,
    M: OriginLegacyMapping + Send,
    W: LegacyChunkWriter + Send,
{
    fn publish(
        &mut self,
        message: SignerNetworkMessage,
    ) -> Result<PublishReceipt, SignerNetworkError> {
        let mut receipt = self.native.publish(message.clone())?;
        let author: [u8; 33] = StacksPublicKey::from_private(&self.local_key)
            .to_bytes_compressed()
            .try_into()
            .expect("compressed Stacks public keys are 33 bytes");
        if let Some(locator) = self.mapping.locator_for_origin(&message, &author) {
            match self.bridge.enqueue_origin_egress(
                &message,
                Some(receipt.envelope_id),
                locator,
                &self.local_key,
                unix_time_secs(),
            ) {
                Ok(_) => receipt.compatibility_queued = true,
                Err(TemporarySignerBridgeError::Disabled) => {}
                Err(TemporarySignerBridgeError::QueueFull) => {
                    // Native delivery is authoritative and remains queued. The
                    // explicit false result exposes compatibility degradation.
                }
                Err(error) => return Err(SignerNetworkError::Transport(error.to_string())),
            }
        }
        Ok(receipt)
    }

    fn try_next_event(&mut self) -> Result<Option<AuthenticatedSignerEvent>, SignerNetworkError> {
        for _ in 0..2 {
            let event = match self.native.try_next_event()? {
                Some(event) => Some(event),
                None => self.compatibility_events.pop_front(),
            };
            let Some(event) = event else {
                return Ok(None);
            };
            if let Some(event) = self.admit_semantic(event) {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    fn replay(
        &mut self,
        request: ReplayRequest,
    ) -> Result<Vec<AuthenticatedSignerEvent>, SignerNetworkError> {
        self.native.replay(request)
    }

    fn update_cycles(&mut self, current: u64, next: Option<u64>) -> Result<(), SignerNetworkError> {
        self.native.update_cycles(current, next)?;
        self.bridge
            .update_cycles(current, next)
            .map_err(|error| SignerNetworkError::Transport(error.to_string()))?;
        self.compatibility_events.retain(|event| {
            event.message.reward_cycle == current || Some(event.message.reward_cycle) == next
        });
        self.retry_writes.retain(|write| {
            write.locator.reward_cycle == current || Some(write.locator.reward_cycle) == next
        });
        Ok(())
    }
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use clarity::codec::StacksMessageCodec;
    use libsigner::v0::messages::SignerMessage;
    use libsigner::{SignerEventAuthentication, SignerIngressOrigin};
    use stacks_common::util::hash::Sha512Trunc256Sum;
    use stacks_network_types::wire::v1::{SignerEnvelope, SignerEnvelopeBody, SignerLane};
    use tempfile::TempDir;

    use super::*;
    use crate::{BridgeJournal, SignerBridgeConfig};

    struct FakeNative {
        events: VecDeque<AuthenticatedSignerEvent>,
    }

    impl SignerNetwork for FakeNative {
        fn publish(
            &mut self,
            message: SignerNetworkMessage,
        ) -> Result<PublishReceipt, SignerNetworkError> {
            Ok(PublishReceipt {
                envelope_id: ContentId::from_domain_bytes(b"fake-native", &message.payload),
                native_queued: true,
                compatibility_queued: false,
            })
        }

        fn try_next_event(
            &mut self,
        ) -> Result<Option<AuthenticatedSignerEvent>, SignerNetworkError> {
            Ok(self.events.pop_front())
        }

        fn replay(
            &mut self,
            _request: ReplayRequest,
        ) -> Result<Vec<AuthenticatedSignerEvent>, SignerNetworkError> {
            Ok(Vec::new())
        }

        fn update_cycles(
            &mut self,
            _current: u64,
            _next: Option<u64>,
        ) -> Result<(), SignerNetworkError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct Mapping(LegacyLocator);

    impl OriginLegacyMapping for Mapping {
        fn locator_for_origin(
            &self,
            _message: &SignerNetworkMessage,
            _author_public_key: &[u8; 33],
        ) -> Option<LegacyLocator> {
            Some(self.0.clone())
        }
    }

    impl LegacyChunkPolicy for Mapping {
        fn resolve(&self, contract: &str, slot_id: u32) -> Option<LegacyLocator> {
            (self.0.contract == contract && self.0.slot_id == slot_id).then(|| self.0.clone())
        }
    }

    #[derive(Default)]
    struct Writer;

    impl LegacyChunkWriter for Writer {
        fn write(&mut self, _pending: &PendingLegacyWrite) -> Result<(), String> {
            Ok(())
        }
    }

    fn payload() -> Vec<u8> {
        let mut bytes = Vec::new();
        SignerMessage::BlockPreCommit(Sha512Trunc256Sum([9; 32]))
            .consensus_serialize(&mut bytes)
            .unwrap();
        bytes
    }

    #[test]
    fn native_publish_remains_primary_and_dual_ingress_is_counted_once() {
        let tempdir = TempDir::new().unwrap();
        let key = StacksPrivateKey::from_seed(&[81; 32]);
        let author = StacksPublicKey::from_private(&key).to_bytes_compressed();
        let message = SignerNetworkMessage {
            reward_cycle: 4,
            lane: SignerLane::BlockPreCommit,
            burn_view_consensus_hash: vec![1; 20],
            payload: payload(),
        };
        let native_event = AuthenticatedSignerEvent {
            message: message.clone(),
            authentication: SignerEventAuthentication::Native {
                envelope: SignerEnvelope {
                    body: Some(SignerEnvelopeBody {
                        version: 1,
                        chain_id: 1,
                        network_id: 1,
                        reward_cycle: 4,
                        lane: SignerLane::BlockPreCommit as i32,
                        sequence: 0,
                        previous_envelope_id: Vec::new(),
                        signer_public_key: author.clone(),
                        transport_peer_id: vec![1],
                        payload: message.payload.clone(),
                        burn_view_consensus_hash: vec![1; 20],
                        proposal_manifest: None,
                    }),
                    signature: vec![0; 65],
                },
                envelope_id: ContentId::from_domain_bytes(b"native-event", &message.payload),
            },
            origin: SignerIngressOrigin::Libp2p,
            is_equivocation: false,
        };
        let locator = LegacyLocator {
            contract: "ST000000000000000000002AMW42H.signers-0-3".to_owned(),
            reward_cycle: 4,
            lane: SignerLane::BlockPreCommit,
            slot_id: 2,
            author: crate::LegacyAuthor::PublicKey(author.try_into().unwrap()),
            allow_epoch25: false,
        };
        let mapping = Mapping(locator);
        let native = FakeNative {
            events: [native_event].into_iter().collect(),
        };
        let bridge = TemporarySignerBridge::new(
            SignerBridgeConfig::default(),
            BridgeJournal::open(tempdir.path().join("bridge.sqlite")).unwrap(),
        )
        .unwrap();
        let mut composite =
            CompositeSignerNetwork::new(native, bridge, mapping.clone(), Writer, key);

        let receipt = composite.publish(message.clone()).unwrap();
        assert!(receipt.native_queued);
        assert!(receipt.compatibility_queued);
        let write = composite.bridge.try_next_write().unwrap();
        // Put the generated legacy copy through ingress before consuming the
        // equivalent native event. Local echo suppression prevents a loop.
        composite
            .ingest_legacy(&mapping.0.contract, &write.chunk, &mapping, 10)
            .unwrap();
        assert_eq!(
            composite.try_next_event().unwrap().unwrap().origin,
            SignerIngressOrigin::Libp2p
        );
        assert!(composite.try_next_event().unwrap().is_none());
    }
}
