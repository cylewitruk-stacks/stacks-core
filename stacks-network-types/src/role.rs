use prost::Message;

use crate::transcript::CanonicalTranscript;
use crate::wire::v1::{Role, RoleProof, RoleProofBody};
use crate::ContentId;

pub const ROLE_PROOF_VERSION: u32 = 1;
pub const ROLE_PROOF_DOMAIN: &[u8] = b"STACKS_LIBP2P_ROLE_V1";
pub const MAX_ROLE_ID_BYTES: usize = 32;
pub const MAX_ROLE_PROOF_BYTES: usize = 1024;

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum RoleProofError {
    #[error("role proof is too large")]
    TooLarge,
    #[error("role proof has no body")]
    MissingBody,
    #[error("unsupported role proof version {0}")]
    UnsupportedVersion(u32),
    #[error("invalid role")]
    InvalidRole,
    #[error("invalid transport PeerId")]
    InvalidPeerId,
    #[error("invalid role identifier")]
    InvalidRoleId,
    #[error("invalid role proof burn-height window")]
    InvalidHeightWindow,
    #[error("invalid Stacks public key")]
    InvalidPublicKey,
    #[error("invalid Stacks signature")]
    InvalidSignature,
}

pub fn validate_role_proof_bounds(proof: &RoleProof) -> Result<&RoleProofBody, RoleProofError> {
    if proof.encoded_len() > MAX_ROLE_PROOF_BYTES {
        return Err(RoleProofError::TooLarge);
    }
    let body = proof.body.as_ref().ok_or(RoleProofError::MissingBody)?;
    if body.version != ROLE_PROOF_VERSION {
        return Err(RoleProofError::UnsupportedVersion(body.version));
    }
    if Role::try_from(body.role).is_err() || body.role == Role::Unspecified as i32 {
        return Err(RoleProofError::InvalidRole);
    }
    if body.transport_peer_id.is_empty() || body.transport_peer_id.len() > 128 {
        return Err(RoleProofError::InvalidPeerId);
    }
    if body.role_id.is_empty() || body.role_id.len() > MAX_ROLE_ID_BYTES {
        return Err(RoleProofError::InvalidRoleId);
    }
    if body.valid_from_burn_height > body.valid_until_burn_height {
        return Err(RoleProofError::InvalidHeightWindow);
    }
    if proof.stacks_public_key.len() != 33 {
        return Err(RoleProofError::InvalidPublicKey);
    }
    if proof.stacks_signature.len() != 65 {
        return Err(RoleProofError::InvalidSignature);
    }
    Ok(body)
}

/// Canonical transcript signed by the original role-authorizing Stacks key.
pub fn role_proof_digest(body: &RoleProofBody) -> [u8; 32] {
    let mut transcript = CanonicalTranscript::with_capacity(body.encoded_len() + 64);
    transcript
        .bytes(ROLE_PROOF_DOMAIN)
        .u32(body.version)
        .u32(body.chain_id)
        .u32(body.network_id)
        .bytes(&body.transport_peer_id)
        .i32(body.role)
        .u64(body.reward_cycle)
        .bytes(&body.role_id)
        .u64(body.valid_from_burn_height)
        .u64(body.valid_until_burn_height);
    transcript.finish_sha256()
}

pub fn role_proof_id(proof: &RoleProof) -> Result<ContentId, RoleProofError> {
    let body = validate_role_proof_bounds(proof)?;
    let mut transcript =
        CanonicalTranscript::with_capacity(32 + proof.stacks_public_key.len() + 65);
    transcript
        .raw(&role_proof_digest(body))
        .bytes(&proof.stacks_public_key)
        .bytes(&proof.stacks_signature);
    Ok(ContentId::from_domain_bytes(
        ROLE_PROOF_DOMAIN,
        &transcript.into_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> RoleProofBody {
        RoleProofBody {
            version: ROLE_PROOF_VERSION,
            chain_id: 1,
            network_id: 2,
            transport_peer_id: vec![3; 39],
            role: Role::Signer as i32,
            reward_cycle: 4,
            role_id: 5_u32.to_be_bytes().to_vec(),
            valid_from_burn_height: 100,
            valid_until_burn_height: 119,
        }
    }

    #[test]
    fn digest_commits_to_every_role_field() {
        let original = body();
        let expected = role_proof_digest(&original);
        // Captured from the staged pre-CanonicalTranscript implementation.
        assert_eq!(
            expected,
            [
                0x87, 0xff, 0xeb, 0x14, 0xe2, 0x8f, 0x31, 0x12, 0xa4, 0xde, 0x2d, 0xc0, 0x47, 0xa0,
                0x28, 0xef, 0xef, 0xf2, 0x8a, 0x1e, 0x88, 0x53, 0x62, 0xd0, 0xfc, 0xdc, 0x41, 0x6a,
                0xc0, 0x81, 0xff, 0x00,
            ]
        );
        let mutations: &[fn(&mut RoleProofBody)] = &[
            |b| b.version += 1,
            |b| b.chain_id += 1,
            |b| b.network_id += 1,
            |b| b.transport_peer_id[0] ^= 1,
            |b| b.role += 1,
            |b| b.reward_cycle += 1,
            |b| b.role_id[0] ^= 1,
            |b| b.valid_from_burn_height += 1,
            |b| b.valid_until_burn_height += 1,
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_ne!(role_proof_digest(&changed), expected);
        }
    }

    #[test]
    fn proof_id_has_a_stable_canonical_vector() {
        let proof = RoleProof {
            body: Some(body()),
            stacks_public_key: vec![2; 33],
            stacks_signature: vec![4; 65],
        };
        // Captured from the staged pre-CanonicalTranscript implementation.
        assert_eq!(
            role_proof_id(&proof).unwrap().as_bytes(),
            &[
                0x26, 0x00, 0xa0, 0xdf, 0x5d, 0xe2, 0xd4, 0x41, 0x43, 0x47, 0x1b, 0x33, 0x53, 0xe1,
                0x8e, 0xc6, 0x0b, 0x18, 0xcf, 0x84, 0x1e, 0x32, 0xc3, 0x5c, 0x5e, 0xf2, 0xbb, 0xb0,
                0x8d, 0xd0, 0xf7, 0x1c,
            ]
        );
    }
}
