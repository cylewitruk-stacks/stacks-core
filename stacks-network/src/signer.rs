use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use libp2p::PeerId;
use prost::Message as ProstMessage;
use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::types::PublicKey;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_network_types::wire::v1::{
    Role, SignerEnvelope, SignerEnvelopeBody, SignerReplayCursor,
};
use stacks_network_types::{
    signer_envelope_digest, signer_envelope_id, validate_signer_envelope_bounds, ContentId,
    NetworkScope, SignerEnvelopeError,
};

use crate::{
    AuthorizationSnapshot, AuthorizationSnapshotError, AuthorizationSnapshotState,
    AuthorizationSnapshotUpdate,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerBindingUpdate {
    Bound,
    Unchanged,
    /// The same authorized signer identity presented a fresh role proof for a
    /// new transport identity. The old PeerId must be disconnected and must
    /// complete Noise, Hello, and role authentication again if it returns.
    Rekeyed {
        revoked_peer: PeerId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MinerAuthorizationStatus {
    Authorized,
    /// The signed tuple is well-formed and cycle-scoped, but the applied
    /// canonical snapshot does not yet contain its sortition. This is not
    /// evidence that the miner is invalid: a companion may simply be behind.
    CanonicalViewPending,
    Unauthorized,
}

/// Identity-aware signer authorization and transport binding state.
///
/// This is deliberately separate from the directory. Both consume the same
/// immutable snapshot, but neither can mutate the other's state.
#[derive(Clone, Debug, Default)]
pub struct SignerAuthorizationState {
    snapshots: AuthorizationSnapshotState,
    signer_bindings: HashMap<(u64, [u8; 33]), PeerId>,
    miner_bindings: HashMap<(u64, Vec<u8>, [u8; 33]), PeerId>,
}

impl SignerAuthorizationState {
    pub(crate) fn miner_authorization_status(
        &self,
        reward_cycle: u64,
        role_id: &[u8],
        miner_key: &[u8; 33],
    ) -> MinerAuthorizationStatus {
        let Some(snapshot) = self.snapshots.applied() else {
            return MinerAuthorizationStatus::CanonicalViewPending;
        };
        if !snapshot.reward_cycle_window().contains(reward_cycle) {
            return MinerAuthorizationStatus::Unauthorized;
        }
        let matching_role = snapshot.entries().iter().filter(|entry| {
            entry.role == Role::Miner
                && entry.reward_cycle == reward_cycle
                && entry
                    .role_id
                    .as_ref()
                    .is_none_or(|expected| expected.as_slice() == role_id)
        });
        let mut role_seen = false;
        for entry in matching_role {
            role_seen = true;
            if entry.key.matches(miner_key) {
                return MinerAuthorizationStatus::Authorized;
            }
        }
        if role_seen {
            MinerAuthorizationStatus::Unauthorized
        } else {
            MinerAuthorizationStatus::CanonicalViewPending
        }
    }

    pub fn apply_snapshot(
        &mut self,
        snapshot: AuthorizationSnapshot,
    ) -> Result<AuthorizationSnapshotUpdate, AuthorizationSnapshotError> {
        let update = self.snapshots.apply(snapshot)?;
        if matches!(update, AuthorizationSnapshotUpdate::Changed { .. }) {
            let applied = self
                .snapshots
                .applied()
                .ok_or(AuthorizationSnapshotError::MissingAppliedState)?;
            self.signer_bindings
                .retain(|(cycle, key), _| applied.authorizes(Role::Signer, *cycle, &[], key));
            self.miner_bindings.retain(|(cycle, role_id, key), _| {
                applied.authorizes(Role::Miner, *cycle, role_id, key)
            });
        }
        Ok(update)
    }

    pub fn bind(
        &mut self,
        reward_cycle: u64,
        signer_key: [u8; 33],
        peer: PeerId,
    ) -> Result<SignerBindingUpdate, &'static str> {
        if !self.is_key_authorized(reward_cycle, &signer_key) {
            return Err("signer identity is not authorized by the applied snapshot");
        }
        match self
            .signer_bindings
            .insert((reward_cycle, signer_key), peer)
        {
            None => Ok(SignerBindingUpdate::Bound),
            Some(existing) if existing == peer => Ok(SignerBindingUpdate::Unchanged),
            Some(revoked_peer) => Ok(SignerBindingUpdate::Rekeyed { revoked_peer }),
        }
    }

    pub fn bind_miner(
        &mut self,
        reward_cycle: u64,
        role_id: Vec<u8>,
        miner_key: [u8; 33],
        peer: PeerId,
    ) -> Result<SignerBindingUpdate, &'static str> {
        if self.miner_authorization_status(reward_cycle, &role_id, &miner_key)
            != MinerAuthorizationStatus::Authorized
        {
            return Err("miner identity is not authorized by the applied snapshot");
        }
        match self
            .miner_bindings
            .insert((reward_cycle, role_id, miner_key), peer)
        {
            None => Ok(SignerBindingUpdate::Bound),
            Some(existing) if existing == peer => Ok(SignerBindingUpdate::Unchanged),
            Some(revoked_peer) => Ok(SignerBindingUpdate::Rekeyed { revoked_peer }),
        }
    }

    pub fn revoke_peer(&mut self, peer: &PeerId) -> usize {
        let before = self.binding_len();
        self.signer_bindings.retain(|_, bound| bound != peer);
        self.miner_bindings.retain(|_, bound| bound != peer);
        before.saturating_sub(self.binding_len())
    }

    pub fn is_key_authorized(&self, reward_cycle: u64, key: &[u8; 33]) -> bool {
        self.snapshots
            .applied()
            .is_some_and(|snapshot| snapshot.signer_keys(reward_cycle).contains(key))
    }

    pub fn authorized_keys(&self, reward_cycle: u64) -> BTreeSet<[u8; 33]> {
        self.snapshots
            .applied()
            .map(|snapshot| snapshot.signer_keys(reward_cycle))
            .unwrap_or_default()
    }

    pub fn is_peer_bound(&self, reward_cycle: u64, peer: &PeerId) -> bool {
        self.signer_bindings
            .iter()
            .any(|((cycle, _), bound)| *cycle == reward_cycle && bound == peer)
    }

    pub fn cycles_for_peer(&self, peer: &PeerId) -> Vec<u64> {
        self.signer_bindings
            .iter()
            .filter_map(|((cycle, _), bound)| (bound == peer).then_some(*cycle))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn peers_for_cycle(&self, reward_cycle: u64) -> BTreeSet<PeerId> {
        self.signer_bindings
            .iter()
            .filter_map(|((cycle, _), peer)| (*cycle == reward_cycle).then_some(*peer))
            .collect()
    }

    pub fn is_miner_bound(
        &self,
        reward_cycle: u64,
        role_id: &[u8],
        key: &[u8; 33],
        peer: &PeerId,
    ) -> bool {
        self.miner_bindings
            .get(&(reward_cycle, role_id.to_vec(), *key))
            .is_some_and(|bound| bound == peer)
    }

    pub fn miner_peers_for_cycle(&self, reward_cycle: u64) -> BTreeSet<PeerId> {
        self.miner_bindings
            .iter()
            .filter_map(|((cycle, _, _), peer)| (*cycle == reward_cycle).then_some(*peer))
            .collect()
    }

    pub fn all_peers(&self) -> BTreeSet<PeerId> {
        self.signer_bindings
            .values()
            .chain(self.miner_bindings.values())
            .copied()
            .collect()
    }

    pub fn binding_len(&self) -> usize {
        self.signer_bindings.len() + self.miner_bindings.len()
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedSignerEnvelope {
    /// Original author-signed envelope retained for replay/evidence.
    pub envelope: SignerEnvelope,
    pub body: SignerEnvelopeBody,
    pub envelope_id: ContentId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerAdmission {
    FirstSeen,
    HigherSequence,
    Duplicate,
    Equivocation,
    /// A valid, previously superseded envelope. This is ordinary under
    /// multi-path gossip and replay and must not penalize the forwarding peer.
    Stale,
}

/// In-memory admission model used by the swarm. A persistent implementation
/// can replace it behind this narrow boundary without changing wire handling.
#[derive(Default)]
pub struct MemorySignerJournal {
    latest: HashMap<(Vec<u8>, u64, i32), VerifiedSignerEnvelope>,
    equivocations: VecDeque<VerifiedSignerEnvelope>,
    equivocation_ids: HashSet<ContentId>,
}

impl MemorySignerJournal {
    pub fn len(&self) -> usize {
        self.latest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.latest.is_empty()
    }

    /// Classify an envelope without changing replay/equivocation state.
    ///
    /// This lets the service reserve downstream delivery before committing an
    /// otherwise-new envelope. If the consumer queue is full, a later retry is
    /// still classified as new instead of being silently converted to stale or
    /// duplicate.
    pub fn classify(&self, envelope: &VerifiedSignerEnvelope) -> SignerAdmission {
        if self.equivocation_ids.contains(&envelope.envelope_id) {
            return SignerAdmission::Duplicate;
        }
        let key = (
            envelope.body.signer_public_key.clone(),
            envelope.body.reward_cycle,
            envelope.body.lane,
        );
        let Some(latest) = self.latest.get(&key) else {
            return SignerAdmission::FirstSeen;
        };
        if envelope.body.sequence < latest.body.sequence {
            return SignerAdmission::Stale;
        }
        if envelope.body.sequence == latest.body.sequence {
            if envelope.envelope_id == latest.envelope_id {
                return SignerAdmission::Duplicate;
            }
            return SignerAdmission::Equivocation;
        }
        SignerAdmission::HigherSequence
    }

    pub fn admit(&mut self, envelope: &VerifiedSignerEnvelope) -> SignerAdmission {
        let admission = self.classify(envelope);
        let key = (
            envelope.body.signer_public_key.clone(),
            envelope.body.reward_cycle,
            envelope.body.lane,
        );
        match admission {
            SignerAdmission::FirstSeen => {
                self.latest.insert(key, envelope.clone());
            }
            SignerAdmission::HigherSequence => {
                self.latest.insert(key, envelope.clone());
            }
            SignerAdmission::Equivocation => {
                // First-seen remains current. The conflict is retained as
                // evidence and may still propagate to reveal equivocation.
                if self.equivocations.len() == 1024 {
                    if let Some(expired) = self.equivocations.pop_front() {
                        self.equivocation_ids.remove(&expired.envelope_id);
                    }
                }
                self.equivocation_ids.insert(envelope.envelope_id);
                self.equivocations.push_back(envelope.clone());
            }
            SignerAdmission::Duplicate | SignerAdmission::Stale => {}
        }
        admission
    }

    pub fn equivocation_count(&self) -> usize {
        self.equivocations.len()
    }

    /// Return deterministic per-author/lane cursors for bounded repair.
    pub fn cursors(&self, reward_cycle: u64) -> Vec<SignerReplayCursor> {
        let mut cursors: Vec<_> = self
            .latest
            .values()
            .filter(|envelope| envelope.body.reward_cycle == reward_cycle)
            .map(|envelope| SignerReplayCursor {
                signer_public_key: envelope.body.signer_public_key.clone(),
                lane: envelope.body.lane,
                sequence: envelope.body.sequence,
            })
            .collect();
        cursors.sort_by(|left, right| {
            (&left.signer_public_key, left.lane, left.sequence).cmp(&(
                &right.signer_public_key,
                right.lane,
                right.sequence,
            ))
        });
        cursors
    }

    /// Select original signed envelopes after the requester's cursors. Known
    /// same-sequence conflicts are always included so equivocation evidence is
    /// not hidden by a cursor that only names the first-seen sequence.
    pub fn replay(
        &self,
        reward_cycle: u64,
        cursors: &[SignerReplayCursor],
        max_items: usize,
        max_bytes: usize,
    ) -> (Vec<SignerEnvelope>, bool) {
        let cursor_for = |envelope: &VerifiedSignerEnvelope| {
            cursors
                .iter()
                .find(|cursor| {
                    cursor.signer_public_key == envelope.body.signer_public_key
                        && cursor.lane == envelope.body.lane
                })
                .map(|cursor| cursor.sequence)
        };
        let mut candidates: Vec<_> = self
            .latest
            .values()
            .filter(|envelope| {
                envelope.body.reward_cycle == reward_cycle
                    && cursor_for(envelope).is_none_or(|sequence| envelope.body.sequence > sequence)
            })
            .cloned()
            .chain(
                self.equivocations
                    .iter()
                    .filter(|envelope| envelope.body.reward_cycle == reward_cycle)
                    .cloned(),
            )
            .collect();
        candidates.sort_by(|left, right| {
            (
                &left.body.signer_public_key,
                left.body.lane,
                left.body.sequence,
                left.envelope_id.as_bytes(),
            )
                .cmp(&(
                    &right.body.signer_public_key,
                    right.body.lane,
                    right.body.sequence,
                    right.envelope_id.as_bytes(),
                ))
        });
        let mut bytes = 0_usize;
        let mut envelopes = Vec::new();
        let mut complete = true;
        for candidate in candidates {
            let encoded_len = candidate.envelope.encoded_len();
            if envelopes.len() == max_items || bytes.saturating_add(encoded_len) > max_bytes {
                complete = false;
                break;
            }
            bytes += encoded_len;
            envelopes.push(candidate.envelope);
        }
        (envelopes, complete)
    }

    /// Drop state outside the current/next-cycle retention window.
    pub fn retain_cycles(&mut self, current: u64, next: Option<u64>) {
        self.latest
            .retain(|(_, cycle, _), _| *cycle == current || Some(*cycle) == next);
        self.equivocations.retain(|envelope| {
            envelope.body.reward_cycle == current || Some(envelope.body.reward_cycle) == next
        });
        self.equivocation_ids = self
            .equivocations
            .iter()
            .map(|envelope| envelope.envelope_id)
            .collect();
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum SignerValidationError {
    #[error(transparent)]
    Bounds(#[from] SignerEnvelopeError),
    #[error("signer envelope is scoped to the wrong chain or network")]
    WrongNetwork,
    #[error("signer envelope is not bound to its GossipSub source")]
    PeerBinding,
    #[error("invalid signer public key")]
    PublicKey,
    #[error("invalid signer signature")]
    Signature,
}

/// Network-scoped verification context for signer envelopes. Keeping the two
/// scope identifiers together prevents a caller from accidentally mixing
/// chain and application-network values across verification paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignerEnvelopeVerifier {
    scope: NetworkScope,
}

impl SignerEnvelopeVerifier {
    pub const fn new(scope: NetworkScope) -> Self {
        Self { scope }
    }

    pub const fn scope(self) -> NetworkScope {
        self.scope
    }

    pub fn verify(
        self,
        envelope: &SignerEnvelope,
        source: &PeerId,
    ) -> Result<VerifiedSignerEnvelope, SignerValidationError> {
        let verified = self.verify_authorship(envelope)?;
        if verified.body.transport_peer_id != source.to_bytes() {
            return Err(SignerValidationError::PeerBinding);
        }
        Ok(verified)
    }

    pub fn verify_authorship(
        self,
        envelope: &SignerEnvelope,
    ) -> Result<VerifiedSignerEnvelope, SignerValidationError> {
        let body = validate_signer_envelope_bounds(envelope)?;
        if body.chain_id != self.scope.chain_id() || body.network_id != self.scope.network_id() {
            return Err(SignerValidationError::WrongNetwork);
        }
        let public_key = StacksPublicKey::from_slice(&body.signer_public_key)
            .map_err(|_| SignerValidationError::PublicKey)?;
        let signature_bytes: [u8; 65] = envelope
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| SignerValidationError::Signature)?;
        let signature = MessageSignature(signature_bytes);
        let digest = signer_envelope_digest(body);
        if !public_key
            .verify(&digest, &signature)
            .map_err(|_| SignerValidationError::Signature)?
        {
            return Err(SignerValidationError::Signature);
        }
        Ok(VerifiedSignerEnvelope {
            envelope: envelope.clone(),
            body: body.clone(),
            envelope_id: signer_envelope_id(envelope)?,
        })
    }
}

pub fn verify_signer_envelope(
    envelope: &SignerEnvelope,
    source: &PeerId,
    chain_id: u32,
    network_id: u32,
) -> Result<VerifiedSignerEnvelope, SignerValidationError> {
    SignerEnvelopeVerifier::new(NetworkScope::new(chain_id, network_id)).verify(envelope, source)
}

/// Verify an original author-signed envelope received through a replay server.
/// The signer signature itself binds the claimed transport PeerId; the caller
/// must separately authorize both the signer key and the replay server role.
pub fn verify_signer_envelope_authorship(
    envelope: &SignerEnvelope,
    chain_id: u32,
    network_id: u32,
) -> Result<VerifiedSignerEnvelope, SignerValidationError> {
    SignerEnvelopeVerifier::new(NetworkScope::new(chain_id, network_id)).verify_authorship(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stacks_common::types::chainstate::StacksPrivateKey;
    use stacks_common::types::PrivateKey;
    use stacks_network_types::wire::v1::SignerLane;
    use stacks_network_types::SIGNER_ENVELOPE_VERSION;

    fn signed_envelope(key: &StacksPrivateKey, peer: &PeerId) -> SignerEnvelope {
        let public_key = StacksPublicKey::from_private(key);
        let body = SignerEnvelopeBody {
            version: SIGNER_ENVELOPE_VERSION,
            chain_id: 0x8000_0000,
            network_id: 0x8000_0000,
            reward_cycle: 4,
            lane: SignerLane::Control as i32,
            sequence: 1,
            previous_envelope_id: Vec::new(),
            signer_public_key: public_key.to_bytes_compressed(),
            transport_peer_id: peer.to_bytes(),
            payload: b"ready".to_vec(),
            burn_view_consensus_hash: vec![0; 20],
            proposal_manifest: None,
        };
        let signature = key.sign(&signer_envelope_digest(&body)).unwrap();
        SignerEnvelope {
            body: Some(body),
            signature: signature.as_bytes().to_vec(),
        }
    }

    fn resign(key: &StacksPrivateKey, envelope: &mut SignerEnvelope) {
        envelope.signature = key
            .sign(&signer_envelope_digest(envelope.body.as_ref().unwrap()))
            .unwrap()
            .as_bytes()
            .to_vec();
    }

    fn signer_authorization(cycle: u64, key: [u8; 33]) -> crate::RoleAuthorization {
        crate::RoleAuthorization {
            role: stacks_network_types::wire::v1::Role::Signer,
            reward_cycle: cycle,
            role_id: None,
            key: crate::AuthorizedRoleKey::PublicKey(key),
        }
    }

    #[test]
    fn authorization_refresh_reconciles_identity_and_rekey_without_global_clear() {
        let key_a = [1; 33];
        let key_b = [2; 33];
        let key_c = [3; 33];
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let peer_c = PeerId::random();
        let mut state = SignerAuthorizationState::default();
        state
            .apply_snapshot(
                AuthorizationSnapshot::new(
                    1,
                    9,
                    Some(10),
                    [
                        signer_authorization(9, key_a),
                        signer_authorization(9, key_b),
                        signer_authorization(10, key_c),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(state.bind(9, key_a, peer_a), Ok(SignerBindingUpdate::Bound));
        assert_eq!(state.bind(9, key_b, peer_b), Ok(SignerBindingUpdate::Bound));
        assert_eq!(
            state.bind(10, key_c, peer_c),
            Ok(SignerBindingUpdate::Bound)
        );

        let unchanged = state
            .apply_snapshot(
                AuthorizationSnapshot::new(
                    2,
                    9,
                    Some(10),
                    [
                        signer_authorization(9, key_a),
                        signer_authorization(9, key_b),
                        signer_authorization(10, key_c),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            unchanged,
            AuthorizationSnapshotUpdate::Unchanged { generation: 2, .. }
        ));
        assert_eq!(state.binding_len(), 3);

        state
            .apply_snapshot(
                AuthorizationSnapshot::new(
                    3,
                    9,
                    Some(10),
                    [
                        signer_authorization(9, key_a),
                        signer_authorization(10, key_c),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(state.is_peer_bound(9, &peer_a));
        assert!(!state.is_peer_bound(9, &peer_b));
        assert!(state.is_peer_bound(10, &peer_c));

        let replacement = PeerId::random();
        assert_eq!(
            state.bind(9, key_a, replacement),
            Ok(SignerBindingUpdate::Rekeyed {
                revoked_peer: peer_a
            })
        );
        assert!(!state.is_peer_bound(9, &peer_a));
        assert!(state.is_peer_bound(9, &replacement));
    }

    #[test]
    fn stale_snapshot_cannot_restore_revoked_signer_binding() {
        let key = [4; 33];
        let peer = PeerId::random();
        let mut state = SignerAuthorizationState::default();
        state
            .apply_snapshot(
                AuthorizationSnapshot::new(4, 9, None, [signer_authorization(9, key)]).unwrap(),
            )
            .unwrap();
        state.bind(9, key, peer).unwrap();
        state
            .apply_snapshot(AuthorizationSnapshot::new(5, 9, None, Vec::new()).unwrap())
            .unwrap();
        assert!(!state.is_peer_bound(9, &peer));
        assert!(matches!(
            state
                .apply_snapshot(
                    AuthorizationSnapshot::new(4, 9, None, [signer_authorization(9, key)]).unwrap()
                )
                .unwrap(),
            AuthorizationSnapshotUpdate::Stale {
                applied_generation: 5,
                received_generation: 4
            }
        ));
        assert!(state.bind(9, key, peer).is_err());
    }

    #[test]
    fn verifies_author_signature_and_transport_binding() {
        let key = StacksPrivateKey::from_seed(&[1; 32]);
        let peer = PeerId::random();
        let envelope = signed_envelope(&key, &peer);
        assert!(verify_signer_envelope(&envelope, &peer, 0x8000_0000, 0x8000_0000).is_ok());

        let other_peer = PeerId::random();
        assert!(matches!(
            verify_signer_envelope(&envelope, &other_peer, 0x8000_0000, 0x8000_0000),
            Err(SignerValidationError::PeerBinding)
        ));
    }

    #[test]
    fn rejects_payload_tampering() {
        let key = StacksPrivateKey::from_seed(&[2; 32]);
        let peer = PeerId::random();
        let mut envelope = signed_envelope(&key, &peer);
        envelope.body.as_mut().unwrap().payload[0] ^= 1;
        assert!(matches!(
            verify_signer_envelope(&envelope, &peer, 0x8000_0000, 0x8000_0000),
            Err(SignerValidationError::Signature)
        ));
    }

    #[test]
    fn journal_preserves_first_seen_and_accepts_any_higher_sequence() {
        let key = StacksPrivateKey::from_seed(&[3; 32]);
        let peer = PeerId::random();
        let first = verify_signer_envelope(
            &signed_envelope(&key, &peer),
            &peer,
            0x8000_0000,
            0x8000_0000,
        )
        .unwrap();
        let mut journal = MemorySignerJournal::default();
        assert_eq!(journal.admit(&first), SignerAdmission::FirstSeen);
        assert_eq!(journal.admit(&first), SignerAdmission::Duplicate);

        let mut conflict_wire = signed_envelope(&key, &peer);
        conflict_wire.body.as_mut().unwrap().payload = b"conflict".to_vec();
        conflict_wire.signature = key
            .sign(&signer_envelope_digest(
                conflict_wire.body.as_ref().unwrap(),
            ))
            .unwrap()
            .as_bytes()
            .to_vec();
        let conflict =
            verify_signer_envelope(&conflict_wire, &peer, 0x8000_0000, 0x8000_0000).unwrap();
        assert_eq!(journal.admit(&conflict), SignerAdmission::Equivocation);
        assert_eq!(journal.admit(&conflict), SignerAdmission::Duplicate);
        assert_eq!(journal.equivocation_count(), 1);

        let mut higher_wire = signed_envelope(&key, &peer);
        higher_wire.body.as_mut().unwrap().sequence = 2;
        // A mismatched predecessor does not block incumbent-parity replacement.
        higher_wire.body.as_mut().unwrap().previous_envelope_id = vec![9; 32];
        higher_wire.signature = key
            .sign(&signer_envelope_digest(higher_wire.body.as_ref().unwrap()))
            .unwrap()
            .as_bytes()
            .to_vec();
        let higher = verify_signer_envelope(&higher_wire, &peer, 0x8000_0000, 0x8000_0000).unwrap();
        assert_eq!(journal.admit(&higher), SignerAdmission::HigherSequence);
        assert_eq!(journal.admit(&first), SignerAdmission::Stale);
    }

    #[test]
    fn replay_is_per_author_lane_bounded_and_preserves_equivocation_evidence() {
        let key = StacksPrivateKey::from_seed(&[4; 32]);
        let peer = PeerId::random();
        let verify = |envelope: &SignerEnvelope| {
            verify_signer_envelope(envelope, &peer, 0x8000_0000, 0x8000_0000).unwrap()
        };
        let first_wire = signed_envelope(&key, &peer);
        let first = verify(&first_wire);
        let mut conflict_wire = first_wire.clone();
        conflict_wire.body.as_mut().unwrap().payload = b"equivocation".to_vec();
        resign(&key, &mut conflict_wire);
        let conflict = verify(&conflict_wire);
        let mut higher_wire = first_wire;
        higher_wire.body.as_mut().unwrap().sequence = 2;
        higher_wire.body.as_mut().unwrap().payload = b"newer".to_vec();
        resign(&key, &mut higher_wire);
        let higher = verify(&higher_wire);

        let mut journal = MemorySignerJournal::default();
        journal.admit(&first);
        journal.admit(&conflict);
        journal.admit(&higher);

        let cursors = vec![SignerReplayCursor {
            signer_public_key: higher.body.signer_public_key.clone(),
            lane: higher.body.lane,
            sequence: 1,
        }];
        let (page, complete) = journal.replay(4, &cursors, 8, 64 * 1024);
        assert!(complete);
        assert_eq!(page.len(), 2);
        assert!(page
            .iter()
            .any(|envelope| { envelope.body.as_ref().unwrap().sequence == 2 }));
        assert!(page
            .iter()
            .any(|envelope| { envelope.body.as_ref().unwrap().payload == b"equivocation" }));

        let (bounded, complete) = journal.replay(4, &[], 1, 64 * 1024);
        assert_eq!(bounded.len(), 1);
        assert!(!complete);
        journal.retain_cycles(5, None);
        assert!(journal.replay(4, &[], 8, 64 * 1024).0.is_empty());
    }
}
