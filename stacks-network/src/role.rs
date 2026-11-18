use libp2p::PeerId;
use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::types::PublicKey;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_network_types::wire::v1::{Role, RoleProof, RoleProofBody};
use stacks_network_types::{
    role_proof_digest, role_proof_id, validate_role_proof_bounds, ContentId, NetworkScope,
    RoleProofError,
};

/// Chainstate-owned authorization queried only after the proof is structurally and
/// cryptographically valid. Implementations must invalidate cached answers on reorg.
pub trait RoleAuthorizer {
    fn is_authorized(
        &self,
        role: Role,
        reward_cycle: u64,
        role_id: &[u8],
        stacks_public_key: &[u8; 33],
    ) -> bool;
}

#[derive(Clone, Debug)]
pub struct VerifiedRoleProof {
    pub body: RoleProofBody,
    pub stacks_public_key: [u8; 33],
    pub proof_id: ContentId,
}

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum RoleValidationError {
    #[error(transparent)]
    Bounds(#[from] RoleProofError),
    #[error("role proof is scoped to the wrong chain or network")]
    WrongNetwork,
    #[error("role proof is not bound to the authenticated transport PeerId")]
    PeerBinding,
    #[error("role proof is outside its burn-height validity window")]
    Expired,
    #[error("invalid role public key")]
    PublicKey,
    #[error("invalid role signature")]
    Signature,
    #[error("role is not authorized by current chainstate")]
    Unauthorized,
}

/// Complete chain context for validating a role proof at one canonical burn
/// height. The borrowed authorizer makes the chainstate decision explicit
/// while keeping scope identifiers inseparable.
pub struct RoleVerificationContext<'a, A: RoleAuthorizer> {
    scope: NetworkScope,
    burn_height: u64,
    authorizer: &'a A,
}

impl<'a, A: RoleAuthorizer> RoleVerificationContext<'a, A> {
    pub const fn new(scope: NetworkScope, burn_height: u64, authorizer: &'a A) -> Self {
        Self {
            scope,
            burn_height,
            authorizer,
        }
    }

    pub fn verify(
        &self,
        proof: &RoleProof,
        source: &PeerId,
    ) -> Result<VerifiedRoleProof, RoleValidationError> {
        verify_role_proof_inner(proof, source, self.scope, self.burn_height, self.authorizer)
    }
}

pub fn verify_role_proof(
    proof: &RoleProof,
    source: &PeerId,
    chain_id: u32,
    network_id: u32,
    burn_height: u64,
    authorizer: &impl RoleAuthorizer,
) -> Result<VerifiedRoleProof, RoleValidationError> {
    RoleVerificationContext::new(
        NetworkScope::new(chain_id, network_id),
        burn_height,
        authorizer,
    )
    .verify(proof, source)
}

fn verify_role_proof_inner(
    proof: &RoleProof,
    source: &PeerId,
    scope: NetworkScope,
    burn_height: u64,
    authorizer: &impl RoleAuthorizer,
) -> Result<VerifiedRoleProof, RoleValidationError> {
    let body = validate_role_proof_bounds(proof)?;
    if body.chain_id != scope.chain_id() || body.network_id != scope.network_id() {
        return Err(RoleValidationError::WrongNetwork);
    }
    if body.transport_peer_id != source.to_bytes() {
        return Err(RoleValidationError::PeerBinding);
    }
    if burn_height < body.valid_from_burn_height || burn_height > body.valid_until_burn_height {
        return Err(RoleValidationError::Expired);
    }
    let public_key_bytes: [u8; 33] = proof
        .stacks_public_key
        .as_slice()
        .try_into()
        .map_err(|_| RoleValidationError::PublicKey)?;
    let public_key = StacksPublicKey::from_slice(&public_key_bytes)
        .map_err(|_| RoleValidationError::PublicKey)?;
    let signature_bytes: [u8; 65] = proof
        .stacks_signature
        .as_slice()
        .try_into()
        .map_err(|_| RoleValidationError::Signature)?;
    if !public_key
        .verify(&role_proof_digest(body), &MessageSignature(signature_bytes))
        .map_err(|_| RoleValidationError::Signature)?
    {
        return Err(RoleValidationError::Signature);
    }
    let role = Role::try_from(body.role).map_err(|_| RoleValidationError::Unauthorized)?;
    if !authorizer.is_authorized(role, body.reward_cycle, &body.role_id, &public_key_bytes) {
        return Err(RoleValidationError::Unauthorized);
    }
    Ok(VerifiedRoleProof {
        body: body.clone(),
        stacks_public_key: public_key_bytes,
        proof_id: role_proof_id(proof)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stacks_common::types::chainstate::StacksPrivateKey;
    use stacks_common::types::PrivateKey;
    use stacks_network_types::ROLE_PROOF_VERSION;

    struct ExactAuthorizer {
        key: [u8; 33],
    }

    impl RoleAuthorizer for ExactAuthorizer {
        fn is_authorized(
            &self,
            role: Role,
            reward_cycle: u64,
            role_id: &[u8],
            stacks_public_key: &[u8; 33],
        ) -> bool {
            role == Role::Signer
                && reward_cycle == 7
                && role_id == 3_u32.to_be_bytes()
                && stacks_public_key == &self.key
        }
    }

    fn proof(key: &StacksPrivateKey, peer: &PeerId) -> RoleProof {
        let body = RoleProofBody {
            version: ROLE_PROOF_VERSION,
            chain_id: 0x8000_0000,
            network_id: 0x8000_0000,
            transport_peer_id: peer.to_bytes(),
            role: Role::Signer as i32,
            reward_cycle: 7,
            role_id: 3_u32.to_be_bytes().to_vec(),
            valid_from_burn_height: 140,
            valid_until_burn_height: 159,
        };
        let signature = key.sign(&role_proof_digest(&body)).unwrap();
        RoleProof {
            body: Some(body),
            stacks_public_key: StacksPublicKey::from_private(key).to_bytes_compressed(),
            stacks_signature: signature.as_bytes().to_vec(),
        }
    }

    #[test]
    fn proof_binds_authorization_peer_network_and_height() {
        let key = StacksPrivateKey::from_seed(&[11; 32]);
        let peer = PeerId::random();
        let authorizer = ExactAuthorizer {
            key: StacksPublicKey::from_private(&key)
                .to_bytes_compressed()
                .try_into()
                .unwrap(),
        };
        let proof = proof(&key, &peer);
        assert!(
            verify_role_proof(&proof, &peer, 0x8000_0000, 0x8000_0000, 150, &authorizer,).is_ok()
        );
        assert!(matches!(
            verify_role_proof(
                &proof,
                &PeerId::random(),
                0x8000_0000,
                0x8000_0000,
                150,
                &authorizer,
            ),
            Err(RoleValidationError::PeerBinding)
        ));
        assert!(matches!(
            verify_role_proof(&proof, &peer, 0x8000_0000, 0x8000_0000, 160, &authorizer,),
            Err(RoleValidationError::Expired)
        ));
    }

    #[test]
    fn proof_rejects_signature_tampering_and_unknown_authority() {
        let key = StacksPrivateKey::from_seed(&[12; 32]);
        let peer = PeerId::random();
        let mut proof = proof(&key, &peer);
        let wrong_authorizer = ExactAuthorizer { key: [2; 33] };
        assert!(matches!(
            verify_role_proof(
                &proof,
                &peer,
                0x8000_0000,
                0x8000_0000,
                150,
                &wrong_authorizer,
            ),
            Err(RoleValidationError::Unauthorized)
        ));
        proof.body.as_mut().unwrap().role_id[0] ^= 1;
        assert!(matches!(
            verify_role_proof(
                &proof,
                &peer,
                0x8000_0000,
                0x8000_0000,
                150,
                &wrong_authorizer,
            ),
            Err(RoleValidationError::Signature)
        ));
    }
}
