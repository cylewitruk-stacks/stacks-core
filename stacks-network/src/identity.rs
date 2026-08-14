use hkdf::Hkdf;
use libp2p::identity::{self, Keypair};
use sha2::Sha256;
use stacks_network_types::NetworkScope;
use zeroize::Zeroize;

const NODE_IDENTITY_DOMAIN: &[u8] = b"STACKS_LIBP2P_NODE_IDENTITY_V1";
const SIGNER_IDENTITY_DOMAIN: &[u8] = b"STACKS_LIBP2P_SIGNER_IDENTITY_V1";
const SECP256K1_IDENTITY_CONTEXT: &[u8] = b"secp256k1";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("node identity seed must not be empty")]
    EmptyNodeSeed,
    #[error("signer secret scalar is invalid")]
    InvalidSignerSecret,
    #[error("identity derivation exhausted its counter")]
    CounterExhausted,
    #[error("identity HKDF expansion failed: {0}")]
    Kdf(String),
}

/// Derive a stable, network-scoped node transport identity. The HKDF domain
/// deliberately separates this key from the legacy P2P preamble signing key,
/// even though both begin from the configured `local_peer_seed`.
pub fn node_identity_from_seed(seed: &[u8], scope: NetworkScope) -> Result<Keypair, IdentityError> {
    if seed.is_empty() {
        return Err(IdentityError::EmptyNodeSeed);
    }
    derive_identity_with(seed, NODE_IDENTITY_DOMAIN, scope, |candidate| {
        identity::secp256k1::SecretKey::try_from_bytes(candidate).ok()
    })
}

/// Derive a signer transport identity that is unlinkable from the public
/// consensus signer key without knowledge of the signer secret scalar.
pub fn signer_identity_from_secret(
    signer_secret: &[u8; 32],
    scope: NetworkScope,
) -> Result<Keypair, IdentityError> {
    // Reject malformed consensus keys before treating them as KDF input.
    identity::secp256k1::SecretKey::try_from_bytes(*signer_secret)
        .map_err(|_| IdentityError::InvalidSignerSecret)?;

    derive_identity_with(signer_secret, SIGNER_IDENTITY_DOMAIN, scope, |candidate| {
        identity::secp256k1::SecretKey::try_from_bytes(candidate).ok()
    })
}

fn derive_identity_with<F>(
    secret_material: &[u8],
    domain: &[u8],
    scope: NetworkScope,
    mut accept: F,
) -> Result<Keypair, IdentityError>
where
    F: FnMut([u8; 32]) -> Option<identity::secp256k1::SecretKey>,
{
    let hkdf = Hkdf::<Sha256>::new(Some(domain), secret_material);
    for counter in 0..=u32::MAX {
        let mut info =
            Vec::with_capacity(SECP256K1_IDENTITY_CONTEXT.len() + 3 * std::mem::size_of::<u32>());
        info.extend_from_slice(SECP256K1_IDENTITY_CONTEXT);
        info.extend_from_slice(&scope.chain_id().to_be_bytes());
        info.extend_from_slice(&scope.network_id().to_be_bytes());
        info.extend_from_slice(&counter.to_be_bytes());

        let mut candidate = [0u8; 32];
        hkdf.expand(info.as_slice(), &mut candidate)
            .map_err(|error| IdentityError::Kdf(error.to_string()))?;
        if let Some(secret) = accept(candidate) {
            candidate.zeroize();
            return Ok(identity::secp256k1::Keypair::from(secret).into());
        }
        candidate.zeroize();
    }
    Err(IdentityError::CounterExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_identity_is_stable_and_seed_separated() {
        let first = node_identity_from_seed(b"node-a", NetworkScope::new(1, 2)).unwrap();
        let restart = node_identity_from_seed(b"node-a", NetworkScope::new(1, 2)).unwrap();
        let other = node_identity_from_seed(b"node-b", NetworkScope::new(1, 2)).unwrap();
        let other_network = node_identity_from_seed(b"node-a", NetworkScope::new(1, 3)).unwrap();
        assert_eq!(first.public().to_peer_id(), restart.public().to_peer_id());
        assert_ne!(first.public().to_peer_id(), other.public().to_peer_id());
        assert_ne!(
            first.public().to_peer_id(),
            other_network.public().to_peer_id()
        );
    }

    #[test]
    fn node_transport_identity_is_not_the_legacy_seed_key() {
        let seed = [7_u8; 32];
        let transport = node_identity_from_seed(&seed, NetworkScope::new(1, 2)).unwrap();
        let legacy_secret = identity::secp256k1::SecretKey::try_from_bytes(seed).unwrap();
        let legacy: Keypair = identity::secp256k1::Keypair::from(legacy_secret).into();
        assert_ne!(
            transport.public().to_peer_id(),
            legacy.public().to_peer_id()
        );
    }

    #[test]
    fn signer_identity_is_stable_and_network_separated() {
        let secret = [7u8; 32];
        let scope = NetworkScope::new(0x8000_0000, 0x8000_0000);
        let first = signer_identity_from_secret(&secret, scope).unwrap();
        let restart = signer_identity_from_secret(&secret, scope).unwrap();
        let other_network = signer_identity_from_secret(&secret, NetworkScope::new(1, 1)).unwrap();
        assert_eq!(first.public().to_peer_id(), restart.public().to_peer_id());
        assert_ne!(
            first.public().to_peer_id(),
            other_network.public().to_peer_id()
        );
    }

    #[test]
    fn signer_identity_rejection_loop_is_testable() {
        let secret = [9u8; 32];
        let mut attempts = 0;
        let identity = derive_identity_with(
            &secret,
            SIGNER_IDENTITY_DOMAIN,
            NetworkScope::new(1, 2),
            |candidate| {
                attempts += 1;
                if attempts < 3 {
                    return None;
                }
                identity::secp256k1::SecretKey::try_from_bytes(candidate).ok()
            },
        )
        .unwrap();
        assert_eq!(attempts, 3);
        assert!(identity.public().try_into_secp256k1().is_ok());
    }
}
