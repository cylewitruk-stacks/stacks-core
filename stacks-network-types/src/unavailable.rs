use thiserror::Error;

use crate::wire::v1::{ProposalUnavailable, ProposalUnavailableReason};
use crate::ContentId;

pub const PROPOSAL_UNAVAILABLE_VERSION: u32 = 1;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProposalUnavailableError {
    #[error("unsupported proposal-unavailable version {0}")]
    Version(u32),
    #[error("proposal-unavailable signer-signature hash must contain 32 bytes")]
    SignerSignatureHash,
    #[error("proposal-unavailable reward cycle differs from its signed envelope")]
    RewardCycle,
    #[error("proposal-unavailable reason is unspecified or unknown")]
    Reason,
}

pub fn validate_proposal_unavailable(
    unavailable: &ProposalUnavailable,
    envelope_reward_cycle: u64,
) -> Result<ContentId, ProposalUnavailableError> {
    if unavailable.version != PROPOSAL_UNAVAILABLE_VERSION {
        return Err(ProposalUnavailableError::Version(unavailable.version));
    }
    let id = ContentId::try_from(unavailable.signer_signature_hash.as_slice())
        .map_err(|_| ProposalUnavailableError::SignerSignatureHash)?;
    if unavailable.reward_cycle != envelope_reward_cycle {
        return Err(ProposalUnavailableError::RewardCycle);
    }
    let reason = ProposalUnavailableReason::try_from(unavailable.reason)
        .map_err(|_| ProposalUnavailableError::Reason)?;
    if reason == ProposalUnavailableReason::Unspecified {
        return Err(ProposalUnavailableError::Reason);
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome() -> ProposalUnavailable {
        ProposalUnavailable {
            version: PROPOSAL_UNAVAILABLE_VERSION,
            signer_signature_hash: vec![7; 32],
            reward_cycle: 42,
            reason: ProposalUnavailableReason::CompanionTimeout as i32,
        }
    }

    #[test]
    fn proposal_unavailable_is_strictly_versioned_and_cycle_bound() {
        let valid = outcome();
        assert_eq!(
            validate_proposal_unavailable(&valid, 42).unwrap(),
            ContentId::from_bytes([7; 32])
        );

        let mut wrong_version = valid.clone();
        wrong_version.version += 1;
        assert_eq!(
            validate_proposal_unavailable(&wrong_version, 42),
            Err(ProposalUnavailableError::Version(2))
        );
        assert_eq!(
            validate_proposal_unavailable(&valid, 41),
            Err(ProposalUnavailableError::RewardCycle)
        );
    }

    #[test]
    fn proposal_unavailable_rejects_ambiguous_or_malformed_outcomes() {
        let mut malformed = outcome();
        malformed.signer_signature_hash.pop();
        assert_eq!(
            validate_proposal_unavailable(&malformed, 42),
            Err(ProposalUnavailableError::SignerSignatureHash)
        );

        let mut unspecified = outcome();
        unspecified.reason = ProposalUnavailableReason::Unspecified as i32;
        assert_eq!(
            validate_proposal_unavailable(&unspecified, 42),
            Err(ProposalUnavailableError::Reason)
        );

        let mut unknown = outcome();
        unknown.reason = i32::MAX;
        assert_eq!(
            validate_proposal_unavailable(&unknown, 42),
            Err(ProposalUnavailableError::Reason)
        );
    }
}
