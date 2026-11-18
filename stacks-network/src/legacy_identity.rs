use std::collections::HashMap;

use libp2p::PeerId;
use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::types::PublicKey;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_network_types::wire::v1::LegacyIdentityBinding;
use stacks_network_types::{
    legacy_identity_binding_digest, validate_legacy_identity_binding_bounds,
    LegacyIdentityBindingError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLegacyIdentityBinding {
    pub peer_id: PeerId,
    pub legacy_node_public_key: [u8; 33],
    pub legacy_key_expire_burn_height: u64,
}

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum LegacyIdentityValidationError {
    #[error(transparent)]
    Bounds(#[from] LegacyIdentityBindingError),
    #[error("legacy identity binding is scoped to the wrong chain")]
    WrongChain,
    #[error("legacy identity binding names a different Noise peer")]
    PeerBinding,
    #[error("legacy identity binding is expired at the local burn view")]
    Expired,
    #[error("legacy identity binding has an invalid public key")]
    PublicKey,
    #[error("legacy identity binding has an invalid signature")]
    Signature,
}

pub fn verify_legacy_identity_binding(
    binding: &LegacyIdentityBinding,
    source: PeerId,
    chain_id: u32,
    burn_height: u64,
) -> Result<VerifiedLegacyIdentityBinding, LegacyIdentityValidationError> {
    validate_legacy_identity_binding_bounds(binding)?;
    if binding.chain_id != chain_id {
        return Err(LegacyIdentityValidationError::WrongChain);
    }
    if binding.peer_id != source.to_bytes() {
        return Err(LegacyIdentityValidationError::PeerBinding);
    }
    // The incumbent rotates before processing a burn height equal to the
    // advertised expiry, so equality is already stale.
    if burn_height >= binding.legacy_key_expire_burn_height {
        return Err(LegacyIdentityValidationError::Expired);
    }
    let public_key_bytes: [u8; 33] = binding
        .legacy_node_public_key
        .as_slice()
        .try_into()
        .map_err(|_| LegacyIdentityValidationError::PublicKey)?;
    let public_key = StacksPublicKey::from_slice(&public_key_bytes)
        .map_err(|_| LegacyIdentityValidationError::PublicKey)?;
    let signature_bytes: [u8; 65] = binding
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| LegacyIdentityValidationError::Signature)?;
    if !public_key
        .verify(
            &legacy_identity_binding_digest(binding),
            &MessageSignature(signature_bytes),
        )
        .map_err(|_| LegacyIdentityValidationError::Signature)?
    {
        return Err(LegacyIdentityValidationError::Signature);
    }
    Ok(VerifiedLegacyIdentityBinding {
        peer_id: source,
        legacy_node_public_key: public_key_bytes,
        legacy_key_expire_burn_height: binding.legacy_key_expire_burn_height,
    })
}

/// Conservative cross-transport identity registry. A binding is usable only
/// after both Noise/Hello and an incumbent authenticated handshake prove the
/// same key and expiry. Observing a replacement binding immediately removes
/// the old association; endpoints are never accepted as evidence.
#[derive(Clone, Debug, Default)]
pub struct LegacyIdentityRegistry {
    native_bindings: HashMap<PeerId, VerifiedLegacyIdentityBinding>,
    legacy_handshakes: HashMap<[u8; 33], u64>,
}

impl LegacyIdentityRegistry {
    pub fn observe_native_binding(&mut self, binding: VerifiedLegacyIdentityBinding) {
        self.native_bindings.insert(binding.peer_id, binding);
    }

    /// Replace the incumbent identities proven by connections that are live in
    /// the caller's current network pass. A historical proof is not sufficient
    /// for cross-transport delivery suppression: once the incumbent
    /// connection closes, both transports must become independently eligible
    /// again.
    pub fn reconcile_legacy_connections(
        &mut self,
        connections: impl IntoIterator<Item = ([u8; 33], u64)>,
    ) {
        self.legacy_handshakes.clear();
        self.legacy_handshakes.extend(connections);
    }

    pub fn is_coalesced(
        &self,
        peer_id: PeerId,
        legacy_public_key: &[u8; 33],
        burn_height: u64,
    ) -> bool {
        let Some(binding) = self.native_bindings.get(&peer_id) else {
            return false;
        };
        binding.legacy_node_public_key == *legacy_public_key
            && burn_height < binding.legacy_key_expire_burn_height
            && self
                .legacy_handshakes
                .get(legacy_public_key)
                .is_some_and(|expiry| *expiry == binding.legacy_key_expire_burn_height)
    }

    /// Native peers that have also proven a live incumbent connection under
    /// the same rotating node key. Callers may suppress only optional,
    /// peer-targeted duplicate delivery for this set. Canonical gossip and
    /// fetch repair must remain available so expiry or rekey cannot censor a
    /// peer.
    pub fn coalesced_native_peers(&self, burn_height: u64) -> impl Iterator<Item = PeerId> + '_ {
        self.native_bindings
            .iter()
            .filter_map(move |(peer_id, binding)| {
                self.is_coalesced(*peer_id, &binding.legacy_node_public_key, burn_height)
                    .then_some(*peer_id)
            })
    }

    /// Rotating incumbent keys that are independently bound to a native peer
    /// and a currently live legacy connection.
    pub fn coalesced_legacy_public_keys(
        &self,
        burn_height: u64,
    ) -> impl Iterator<Item = [u8; 33]> + '_ {
        self.native_bindings.values().filter_map(move |binding| {
            self.is_coalesced(
                binding.peer_id,
                &binding.legacy_node_public_key,
                burn_height,
            )
            .then_some(binding.legacy_node_public_key)
        })
    }

    pub fn expire(&mut self, burn_height: u64) {
        self.native_bindings
            .retain(|_, binding| burn_height < binding.legacy_key_expire_burn_height);
        self.legacy_handshakes
            .retain(|_, expiry| burn_height < *expiry);
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.native_bindings.remove(peer_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stacks_common::types::chainstate::StacksPrivateKey;
    use stacks_common::types::PrivateKey;
    use stacks_network_types::LEGACY_IDENTITY_BINDING_VERSION;

    fn signed_binding(key: &StacksPrivateKey, peer: PeerId, expiry: u64) -> LegacyIdentityBinding {
        let mut binding = LegacyIdentityBinding {
            version: LEGACY_IDENTITY_BINDING_VERSION,
            chain_id: 1,
            peer_id: peer.to_bytes(),
            legacy_node_public_key: StacksPublicKey::from_private(key).to_bytes_compressed(),
            legacy_key_expire_burn_height: expiry,
            signature: vec![0; 65],
        };
        binding.signature = key
            .sign(&legacy_identity_binding_digest(&binding))
            .unwrap()
            .as_bytes()
            .to_vec();
        binding
    }

    #[test]
    fn coalescing_requires_both_proofs_and_rekey_revokes_before_resuming() {
        let peer = PeerId::random();
        let old_key = StacksPrivateKey::from_seed(&[1; 32]);
        let new_key = StacksPrivateKey::from_seed(&[2; 32]);
        let old_public: [u8; 33] = StacksPublicKey::from_private(&old_key)
            .to_bytes_compressed()
            .try_into()
            .unwrap();
        let new_public: [u8; 33] = StacksPublicKey::from_private(&new_key)
            .to_bytes_compressed()
            .try_into()
            .unwrap();
        let mut registry = LegacyIdentityRegistry::default();

        let old = verify_legacy_identity_binding(&signed_binding(&old_key, peer, 100), peer, 1, 90)
            .unwrap();
        registry.observe_native_binding(old);
        assert!(!registry.is_coalesced(peer, &old_public, 90));
        registry.reconcile_legacy_connections([(old_public, 100)]);
        assert!(registry.is_coalesced(peer, &old_public, 99));
        assert_eq!(
            registry.coalesced_native_peers(99).collect::<Vec<_>>(),
            [peer]
        );
        assert!(!registry.is_coalesced(peer, &old_public, 100));
        assert!(registry.coalesced_native_peers(100).next().is_none());

        let new =
            verify_legacy_identity_binding(&signed_binding(&new_key, peer, 200), peer, 1, 100)
                .unwrap();
        registry.observe_native_binding(new);
        assert!(!registry.is_coalesced(peer, &old_public, 100));
        assert!(!registry.is_coalesced(peer, &new_public, 100));
        registry.reconcile_legacy_connections([(new_public, 200)]);
        assert!(registry.is_coalesced(peer, &new_public, 100));
        assert_eq!(
            registry.coalesced_native_peers(100).collect::<Vec<_>>(),
            [peer]
        );
        assert_eq!(
            registry
                .coalesced_legacy_public_keys(100)
                .collect::<Vec<_>>(),
            [new_public]
        );

        registry.reconcile_legacy_connections([]);
        assert!(!registry.is_coalesced(peer, &new_public, 100));
        assert!(registry.coalesced_native_peers(100).next().is_none());

        registry.reconcile_legacy_connections([(new_public, 200)]);
        assert!(registry.is_coalesced(peer, &new_public, 100));
    }

    #[test]
    fn binding_rejects_wrong_peer_chain_expiry_and_tampering() {
        let peer = PeerId::random();
        let key = StacksPrivateKey::from_seed(&[3; 32]);
        let binding = signed_binding(&key, peer, 10);
        assert!(verify_legacy_identity_binding(&binding, peer, 1, 9).is_ok());
        assert!(matches!(
            verify_legacy_identity_binding(&binding, PeerId::random(), 1, 9),
            Err(LegacyIdentityValidationError::PeerBinding)
        ));
        assert!(matches!(
            verify_legacy_identity_binding(&binding, peer, 2, 9),
            Err(LegacyIdentityValidationError::WrongChain)
        ));
        assert!(matches!(
            verify_legacy_identity_binding(&binding, peer, 1, 10),
            Err(LegacyIdentityValidationError::Expired)
        ));
        let mut tampered = binding;
        tampered.legacy_key_expire_burn_height += 1;
        assert!(matches!(
            verify_legacy_identity_binding(&tampered, peer, 1, 9),
            Err(LegacyIdentityValidationError::Signature)
        ));
    }
}
