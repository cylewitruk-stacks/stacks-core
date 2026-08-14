use prost::Message;
use sha2::{Digest, Sha256};

use crate::transcript::CanonicalTranscript;
use crate::wire::v1::{SignerEnvelope, SignerEnvelopeBody, SignerLane};
use crate::{validate_proposal_manifest, ContentId};

pub const SIGNER_ENVELOPE_VERSION: u32 = 1;
pub const MAX_SIGNER_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SIGNER_ENVELOPE_BYTES: usize = MAX_SIGNER_PAYLOAD_BYTES + 1024;
pub const STACKS_SIGNER_ENVELOPE_DOMAIN: &[u8] = b"STACKS_LIBP2P_SIGNER_ENVELOPE_V1";

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum SignerEnvelopeError {
    #[error("missing signer envelope body")]
    MissingBody,
    #[error("unsupported signer envelope version {0}")]
    UnsupportedVersion(u32),
    #[error("invalid signer lane")]
    InvalidLane,
    #[error("invalid signer public key length")]
    InvalidPublicKey,
    #[error("invalid transport peer ID")]
    InvalidPeerId,
    #[error("invalid signer signature length")]
    InvalidSignature,
    #[error("signer payload is too large")]
    PayloadTooLarge,
    #[error("invalid previous envelope ID")]
    InvalidPreviousEnvelopeId,
    #[error("burn-view consensus hash must be empty or 20 bytes")]
    InvalidBurnViewConsensusHash,
    #[error("signer envelope is too large")]
    EnvelopeTooLarge,
    #[error("block-proposal envelopes must contain one manifest and no inline payload")]
    InvalidProposalMode,
    #[error("invalid block-proposal manifest: {0}")]
    InvalidProposalManifest(String),
}

pub fn validate_signer_envelope_bounds(
    envelope: &SignerEnvelope,
) -> Result<&SignerEnvelopeBody, SignerEnvelopeError> {
    if envelope.encoded_len() > MAX_SIGNER_ENVELOPE_BYTES {
        return Err(SignerEnvelopeError::EnvelopeTooLarge);
    }
    let body = envelope
        .body
        .as_ref()
        .ok_or(SignerEnvelopeError::MissingBody)?;
    if body.version != SIGNER_ENVELOPE_VERSION {
        return Err(SignerEnvelopeError::UnsupportedVersion(body.version));
    }
    let lane = SignerLane::try_from(body.lane).map_err(|_| SignerEnvelopeError::InvalidLane)?;
    if lane == SignerLane::Unspecified {
        return Err(SignerEnvelopeError::InvalidLane);
    }
    if body.signer_public_key.len() != 33 {
        return Err(SignerEnvelopeError::InvalidPublicKey);
    }
    if body.transport_peer_id.is_empty() || body.transport_peer_id.len() > 128 {
        return Err(SignerEnvelopeError::InvalidPeerId);
    }
    if envelope.signature.len() != 65 {
        return Err(SignerEnvelopeError::InvalidSignature);
    }
    if body.payload.len() > MAX_SIGNER_PAYLOAD_BYTES {
        return Err(SignerEnvelopeError::PayloadTooLarge);
    }
    if !body.previous_envelope_id.is_empty() && body.previous_envelope_id.len() != 32 {
        return Err(SignerEnvelopeError::InvalidPreviousEnvelopeId);
    }
    if !body.burn_view_consensus_hash.is_empty() && body.burn_view_consensus_hash.len() != 20 {
        return Err(SignerEnvelopeError::InvalidBurnViewConsensusHash);
    }
    match (
        lane,
        body.proposal_manifest.as_ref(),
        body.payload.is_empty(),
    ) {
        (SignerLane::BlockProposal, Some(manifest), true) => {
            validate_proposal_manifest(manifest, body.reward_cycle)
                .map_err(|error| SignerEnvelopeError::InvalidProposalManifest(error.to_string()))?;
        }
        (SignerLane::BlockProposal, _, _) | (_, Some(_), _) => {
            return Err(SignerEnvelopeError::InvalidProposalMode);
        }
        _ => {}
    }
    Ok(body)
}

/// Hash committed by the author's Stacks key. Length-prefixing keeps the
/// transcript unambiguous and independent of protobuf implementation details.
pub fn signer_envelope_digest(body: &SignerEnvelopeBody) -> [u8; 32] {
    let mut transcript = CanonicalTranscript::with_capacity(body.encoded_len() + 128);
    transcript
        .bytes(STACKS_SIGNER_ENVELOPE_DOMAIN)
        .u32(body.version)
        .u32(body.chain_id)
        .u32(body.network_id)
        .u64(body.reward_cycle)
        .i32(body.lane)
        .u64(body.sequence)
        .bytes(&body.previous_envelope_id)
        .bytes(&body.signer_public_key)
        .bytes(&body.transport_peer_id)
        .bytes(&body.burn_view_consensus_hash);
    let payload_hash = Sha256::digest(&body.payload);
    transcript.raw(&payload_hash);
    if let Some(manifest) = body.proposal_manifest.as_ref() {
        transcript
            .raw(&[1])
            .u32(manifest.version)
            .bytes(&manifest.content_id)
            .u64(manifest.encoded_len)
            .bytes(&manifest.signer_signature_hash)
            .u64(manifest.burn_height)
            .u64(manifest.reward_cycle);
    }
    transcript.finish_sha256()
}

pub fn signer_envelope_id(envelope: &SignerEnvelope) -> Result<ContentId, SignerEnvelopeError> {
    let body = validate_signer_envelope_bounds(envelope)?;
    let mut transcript = CanonicalTranscript::with_capacity(32 + envelope.signature.len());
    transcript
        .raw(b"STACKS_LIBP2P_SIGNER_ENVELOPE_ID_V1")
        .raw(&signer_envelope_digest(body))
        .raw(&envelope.signature);
    Ok(ContentId::from_domain_bytes(
        b"STACKS_LIBP2P_SIGNER_ENVELOPE_ID_V1",
        &transcript.into_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> SignerEnvelopeBody {
        SignerEnvelopeBody {
            version: SIGNER_ENVELOPE_VERSION,
            chain_id: 0x8000_0000,
            network_id: 0x8000_0000,
            reward_cycle: 7,
            lane: SignerLane::BlockResponse as i32,
            sequence: 3,
            previous_envelope_id: vec![2; 32],
            signer_public_key: vec![3; 33],
            transport_peer_id: vec![4; 39],
            payload: vec![5; 128],
            burn_view_consensus_hash: vec![6; 20],
            proposal_manifest: None,
        }
    }

    #[test]
    fn digest_commits_to_every_body_field() {
        let original = body();
        let expected = signer_envelope_digest(&original);
        // Captured from the staged pre-CanonicalTranscript implementation.
        assert_eq!(
            expected,
            [
                0x37, 0x6c, 0xe8, 0x2b, 0x03, 0xe2, 0x92, 0xc1, 0x46, 0xe4, 0x59, 0xbd, 0x43, 0x69,
                0x5a, 0x08, 0x86, 0xf9, 0x34, 0xeb, 0xb3, 0x82, 0x6c, 0xff, 0xdb, 0xec, 0x34, 0x09,
                0x24, 0x5f, 0xa4, 0x7a,
            ]
        );
        let mutations: &[fn(&mut SignerEnvelopeBody)] = &[
            |b| b.version += 1,
            |b| b.chain_id += 1,
            |b| b.network_id += 1,
            |b| b.reward_cycle += 1,
            |b| b.lane += 1,
            |b| b.sequence += 1,
            |b| b.previous_envelope_id[0] ^= 1,
            |b| b.signer_public_key[0] ^= 1,
            |b| b.transport_peer_id[0] ^= 1,
            |b| b.payload[0] ^= 1,
            |b| b.burn_view_consensus_hash[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_ne!(signer_envelope_digest(&changed), expected);
        }
    }

    #[test]
    fn envelope_id_matches_the_pre_transcript_implementation() {
        let envelope = SignerEnvelope {
            body: Some(body()),
            signature: vec![7; 65],
        };
        assert_eq!(
            signer_envelope_id(&envelope).unwrap().as_bytes(),
            &[
                0x8f, 0x1d, 0xc1, 0x1f, 0x79, 0x81, 0x87, 0xa0, 0x56, 0x03, 0x77, 0xc5, 0xd4, 0x4a,
                0x5c, 0x61, 0xc3, 0x0b, 0x3b, 0x86, 0xe7, 0xe4, 0xd2, 0x6f, 0xa9, 0x42, 0xab, 0x73,
                0xe7, 0x63, 0x0c, 0x26,
            ]
        );
    }

    #[test]
    fn rejects_oversized_payload_before_use() {
        let envelope = SignerEnvelope {
            body: Some(SignerEnvelopeBody {
                payload: vec![0; MAX_SIGNER_PAYLOAD_BYTES + 1],
                ..body()
            }),
            signature: vec![0; 65],
        };
        assert_eq!(
            validate_signer_envelope_bounds(&envelope),
            Err(SignerEnvelopeError::PayloadTooLarge)
        );
    }
}
