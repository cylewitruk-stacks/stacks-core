use prost::Message;

use crate::role_proof_id;
use crate::transcript::CanonicalTranscript;
use crate::wire::v1::RoleDirectoryRecord;

pub const ROLE_DIRECTORY_RECORD_DOMAIN: &[u8] = b"STACKS_LIBP2P_ROLE_DIRECTORY_RECORD_V1";
pub const MAX_DIRECTORY_ADDRESSES: usize = 16;
pub const MAX_DIRECTORY_ADDRESS_BYTES: usize = 512;
pub const MAX_DIRECTORY_RECORD_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum DirectoryRecordError {
    #[error("role directory record is too large")]
    TooLarge,
    #[error("role directory record has no role proof")]
    MissingProof,
    #[error("role directory record has too many addresses")]
    TooManyAddresses,
    #[error("role directory record contains an empty or oversized address")]
    InvalidAddressLength,
    #[error("role directory addresses are not in canonical sorted unique order")]
    NonCanonicalAddresses,
    #[error("role directory record signature must be 65 bytes")]
    InvalidSignature,
    #[error("invalid role proof: {0}")]
    RoleProof(#[from] crate::RoleProofError),
}

pub fn validate_directory_record_bounds(
    record: &RoleDirectoryRecord,
) -> Result<(), DirectoryRecordError> {
    if record.encoded_len() > MAX_DIRECTORY_RECORD_BYTES {
        return Err(DirectoryRecordError::TooLarge);
    }
    let proof = record
        .proof
        .as_ref()
        .ok_or(DirectoryRecordError::MissingProof)?;
    if record.addresses.len() > MAX_DIRECTORY_ADDRESSES {
        return Err(DirectoryRecordError::TooManyAddresses);
    }
    if record
        .addresses
        .iter()
        .any(|address| address.is_empty() || address.len() > MAX_DIRECTORY_ADDRESS_BYTES)
    {
        return Err(DirectoryRecordError::InvalidAddressLength);
    }
    if record
        .addresses
        .windows(2)
        .any(|pair| pair[0].as_slice() >= pair[1].as_slice())
    {
        return Err(DirectoryRecordError::NonCanonicalAddresses);
    }
    if record.record_signature.len() != 65 {
        return Err(DirectoryRecordError::InvalidSignature);
    }
    // This also applies all structural proof bounds before any signature work.
    role_proof_id(proof)?;
    Ok(())
}

/// Canonical transcript signed by the Stacks key already authenticated by the
/// role proof. Canonical ordering gives a single signed record for an address set.
pub fn directory_record_digest(
    record: &RoleDirectoryRecord,
) -> Result<[u8; 32], DirectoryRecordError> {
    validate_directory_record_bounds(record)?;
    let proof = record
        .proof
        .as_ref()
        .ok_or(DirectoryRecordError::MissingProof)?;
    let proof_id = role_proof_id(proof)?;
    let mut transcript = CanonicalTranscript::with_capacity(record.encoded_len() + 64);
    transcript
        .bytes(ROLE_DIRECTORY_RECORD_DOMAIN)
        .raw(proof_id.as_bytes())
        .u32(record.addresses.len() as u32);
    for address in &record.addresses {
        transcript.bytes(address);
    }
    Ok(transcript.finish_sha256())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::v1::{Role, RoleProof, RoleProofBody};

    fn record() -> RoleDirectoryRecord {
        RoleDirectoryRecord {
            proof: Some(RoleProof {
                body: Some(RoleProofBody {
                    version: crate::ROLE_PROOF_VERSION,
                    chain_id: 1,
                    network_id: 2,
                    transport_peer_id: vec![3; 39],
                    role: Role::Signer as i32,
                    reward_cycle: 4,
                    role_id: 5_u32.to_be_bytes().to_vec(),
                    valid_from_burn_height: 100,
                    valid_until_burn_height: 119,
                }),
                stacks_public_key: vec![2; 33],
                stacks_signature: vec![4; 65],
            }),
            addresses: vec![b"/ip4/127.0.0.1/tcp/20445".to_vec()],
            record_signature: vec![5; 65],
        }
    }

    #[test]
    fn digest_commits_to_addresses_and_proof() {
        let original = record();
        let digest = directory_record_digest(&original).unwrap();
        // Captured from the staged pre-CanonicalTranscript implementation.
        assert_eq!(
            digest,
            [
                0x55, 0xb4, 0xed, 0xfa, 0xf9, 0x84, 0xac, 0x17, 0x5a, 0x0e, 0x8c, 0xd2, 0x93, 0xd4,
                0x0d, 0xd4, 0x6a, 0x56, 0x48, 0x56, 0x40, 0xd6, 0xba, 0x38, 0x7e, 0xe7, 0xca, 0x91,
                0xaf, 0x8f, 0x75, 0xa8,
            ]
        );
        let mut changed = original.clone();
        changed.addresses[0][5] ^= 1;
        assert_ne!(directory_record_digest(&changed).unwrap(), digest);
        changed = original;
        changed.proof.as_mut().unwrap().stacks_signature[0] ^= 1;
        assert_ne!(directory_record_digest(&changed).unwrap(), digest);
    }

    #[test]
    fn rejects_noncanonical_addresses() {
        let mut value = record();
        value.addresses = vec![b"/memory/2".to_vec(), b"/memory/1".to_vec()];
        assert_eq!(
            validate_directory_record_bounds(&value),
            Err(DirectoryRecordError::NonCanonicalAddresses)
        );
    }
}
