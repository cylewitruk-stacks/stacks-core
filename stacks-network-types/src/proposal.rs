use thiserror::Error;

use crate::wire::v1::ProposalManifest;
use crate::ContentId;

pub const PROPOSAL_MANIFEST_VERSION: u32 = 1;
pub const MAX_PROPOSAL_OBJECT_BYTES: usize = 2 * 1024 * 1024;
pub const SIGNER_SIGNATURE_HASH_BYTES: usize = 32;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProposalManifestError {
    #[error("unsupported proposal manifest version {0}")]
    Version(u32),
    #[error("proposal content ID has length {0}, expected 32")]
    ContentId(usize),
    #[error("proposal object length {0} is outside the supported range")]
    EncodedLength(u64),
    #[error("proposal signer-signature hash has length {0}, expected 32")]
    SignerSignatureHash(usize),
    #[error("proposal manifest reward cycle differs from its signed envelope")]
    RewardCycle,
}

pub fn proposal_content_id(bytes: &[u8]) -> ContentId {
    ContentId::from_domain_bytes(b"STACKS_BLOCK_PROPOSAL_V1", bytes)
}

pub fn validate_proposal_manifest(
    manifest: &ProposalManifest,
    envelope_reward_cycle: u64,
) -> Result<ContentId, ProposalManifestError> {
    if manifest.version != PROPOSAL_MANIFEST_VERSION {
        return Err(ProposalManifestError::Version(manifest.version));
    }
    let content_id = ContentId::try_from(manifest.content_id.as_slice())
        .map_err(|_| ProposalManifestError::ContentId(manifest.content_id.len()))?;
    let max_len = u64::try_from(MAX_PROPOSAL_OBJECT_BYTES).expect("proposal limit fits u64");
    if manifest.encoded_len == 0 || manifest.encoded_len > max_len {
        return Err(ProposalManifestError::EncodedLength(manifest.encoded_len));
    }
    if manifest.signer_signature_hash.len() != SIGNER_SIGNATURE_HASH_BYTES {
        return Err(ProposalManifestError::SignerSignatureHash(
            manifest.signer_signature_hash.len(),
        ));
    }
    if manifest.reward_cycle != envelope_reward_cycle {
        return Err(ProposalManifestError::RewardCycle);
    }
    Ok(content_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_content_id_is_domain_separated_and_stable() {
        let id = proposal_content_id(b"proposal-golden-vector-v1");
        assert_eq!(
            id.to_string(),
            "4fbe02306cf52ff5a05223f5fde422efbd3392a5ae2cafb4e8a8d4d13d300376"
        );
        assert_ne!(
            id,
            ContentId::from_domain_bytes(b"STACKS_OBJECT_V1", b"proposal-golden-vector-v1")
        );
    }
}
