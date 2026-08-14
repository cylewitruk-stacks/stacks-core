//! Canonical transcript for safely coalescing legacy and libp2p node peers.

use prost::Message;

use crate::transcript::CanonicalTranscript;
use crate::wire::v1::LegacyIdentityBinding;

pub const LEGACY_IDENTITY_BINDING_VERSION: u32 = 1;
const LEGACY_IDENTITY_BINDING_DOMAIN: &[u8] = b"STACKS_LIBP2P_LEGACY_IDENTITY_BINDING_V1";
const MAX_BINDING_BYTES: usize = 512;

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum LegacyIdentityBindingError {
    #[error("legacy identity binding is too large")]
    TooLarge,
    #[error("unsupported legacy identity binding version {0}")]
    UnsupportedVersion(u32),
    #[error("legacy identity binding has a malformed PeerId")]
    InvalidPeerId,
    #[error("legacy identity binding has a malformed public key")]
    InvalidPublicKey,
    #[error("legacy identity binding has a malformed signature")]
    InvalidSignature,
    #[error("legacy identity binding has no expiry")]
    InvalidExpiry,
}

pub fn validate_legacy_identity_binding_bounds(
    binding: &LegacyIdentityBinding,
) -> Result<(), LegacyIdentityBindingError> {
    if binding.encoded_len() > MAX_BINDING_BYTES {
        return Err(LegacyIdentityBindingError::TooLarge);
    }
    if binding.version != LEGACY_IDENTITY_BINDING_VERSION {
        return Err(LegacyIdentityBindingError::UnsupportedVersion(
            binding.version,
        ));
    }
    if binding.peer_id.is_empty() || binding.peer_id.len() > 128 {
        return Err(LegacyIdentityBindingError::InvalidPeerId);
    }
    if binding.legacy_node_public_key.len() != 33 {
        return Err(LegacyIdentityBindingError::InvalidPublicKey);
    }
    if binding.signature.len() != 65 {
        return Err(LegacyIdentityBindingError::InvalidSignature);
    }
    if binding.legacy_key_expire_burn_height == 0 {
        return Err(LegacyIdentityBindingError::InvalidExpiry);
    }
    Ok(())
}

/// Digest signed by the currently active legacy node conversation key.
pub fn legacy_identity_binding_digest(binding: &LegacyIdentityBinding) -> [u8; 32] {
    let mut transcript = CanonicalTranscript::with_capacity(192);
    transcript
        .bytes(LEGACY_IDENTITY_BINDING_DOMAIN)
        .u32(binding.version)
        .u32(binding.chain_id)
        .bytes(&binding.peer_id)
        .bytes(&binding.legacy_node_public_key)
        .u64(binding.legacy_key_expire_burn_height);
    transcript.finish_sha256()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> LegacyIdentityBinding {
        LegacyIdentityBinding {
            version: LEGACY_IDENTITY_BINDING_VERSION,
            chain_id: 1,
            peer_id: vec![2; 39],
            legacy_node_public_key: vec![3; 33],
            legacy_key_expire_burn_height: 100,
            signature: vec![4; 65],
        }
    }

    #[test]
    fn digest_commits_to_every_signed_field_but_not_the_signature() {
        let original = binding();
        let digest = legacy_identity_binding_digest(&original);
        // Captured from the staged pre-CanonicalTranscript implementation.
        assert_eq!(
            digest,
            [
                0xb7, 0xbe, 0xb4, 0x41, 0x1b, 0x3f, 0x0f, 0x8e, 0x4a, 0xbf, 0x9c, 0x6c, 0x3a, 0x6c,
                0xc3, 0x57, 0x6f, 0xdc, 0x86, 0xe4, 0x18, 0x93, 0xc3, 0x5d, 0xa3, 0x62, 0xca, 0x65,
                0x3d, 0xb8, 0x45, 0x9c,
            ]
        );
        let mutations: &[fn(&mut LegacyIdentityBinding)] = &[
            |binding| binding.version += 1,
            |binding| binding.chain_id += 1,
            |binding| binding.peer_id[0] ^= 1,
            |binding| binding.legacy_node_public_key[0] ^= 1,
            |binding| binding.legacy_key_expire_burn_height += 1,
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_ne!(legacy_identity_binding_digest(&changed), digest);
        }
        let mut changed_signature = original;
        changed_signature.signature[0] ^= 1;
        assert_eq!(legacy_identity_binding_digest(&changed_signature), digest);
    }
}
