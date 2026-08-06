//! Cryptographic derivations for opaque block and chainstate value types.

use sha2::{Digest, Sha512_256};
use stacks_primitives::block::{BlockHeaderHash, ConsensusHash, StacksBlockId, TrieHash};
use stacks_primitives::hash::{Hash160, Sha512Trunc256Sum};
use stacks_primitives::vrf::VRFSeed;

use crate::hash::{Hash160Digest as _, Sha512Trunc256Digest as _};
use crate::vrf::VRFProof;

pub trait TrieHashDigest {
    fn from_key(key: &str) -> Self;
    fn from_data(data: &[u8]) -> Self;
    fn from_data_array<B: AsRef<[u8]>>(data: &[B]) -> Self;
}

impl TrieHashDigest for TrieHash {
    fn from_key(key: &str) -> Self {
        Self::from_data(key.as_bytes())
    }

    fn from_data(data: &[u8]) -> Self {
        if data.is_empty() {
            return TrieHash::EMPTY;
        }
        TrieHash(Sha512_256::digest(data).into())
    }

    fn from_data_array<B: AsRef<[u8]>>(data: &[B]) -> Self {
        if data.is_empty() {
            return TrieHash::EMPTY;
        }
        let mut hasher = Sha512_256::new();
        for item in data {
            hasher.update(item);
        }
        TrieHash(hasher.finalize().into())
    }
}

pub trait BlockHeaderHashDigest {
    fn to_hash160(&self) -> Hash160;
    fn from_serialized_header(bytes: &[u8]) -> Self;
}

impl BlockHeaderHashDigest for BlockHeaderHash {
    fn to_hash160(&self) -> Hash160 {
        Hash160::from_sha256(&self.0)
    }

    fn from_serialized_header(bytes: &[u8]) -> Self {
        BlockHeaderHash(Sha512Trunc256Sum::from_data(bytes).0)
    }
}

pub trait StacksBlockIdDigest {
    fn new(consensus_hash: &ConsensusHash, block_hash: &BlockHeaderHash) -> Self;
}

impl StacksBlockIdDigest for StacksBlockId {
    fn new(consensus_hash: &ConsensusHash, block_hash: &BlockHeaderHash) -> Self {
        let mut hasher = Sha512_256::new();
        hasher.update(block_hash.as_bytes());
        hasher.update(consensus_hash.as_bytes());
        StacksBlockId(Sha512Trunc256Sum::from_hasher(hasher).0)
    }
}

pub trait VRFSeedDigest {
    fn initial() -> Self;
    fn from_proof(proof: &VRFProof) -> Self;
    fn is_from_proof(&self, proof: &VRFProof) -> bool;
}

impl VRFSeedDigest for VRFSeed {
    fn initial() -> Self {
        Self::INITIAL
    }

    fn from_proof(proof: &VRFProof) -> Self {
        VRFSeed(Sha512Trunc256Sum::from_data(&proof.to_bytes()).0)
    }

    fn is_from_proof(&self, proof: &VRFProof) -> bool {
        self == &Self::from_proof(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trie_hash_is_canonical() {
        assert_eq!(TrieHash::from_data(&[]), TrieHash::EMPTY);
        assert_eq!(TrieHash::from_data_array::<&[u8]>(&[]), TrieHash::EMPTY);
    }

    #[test]
    fn block_id_commits_to_both_inputs_in_order() {
        let consensus = ConsensusHash([1; 20]);
        let block = BlockHeaderHash([2; 32]);
        let id = StacksBlockId::new(&consensus, &block);

        let mut bytes = Vec::from(block.0);
        bytes.extend_from_slice(&consensus.0);
        assert_eq!(id.0, Sha512Trunc256Sum::from_data(&bytes).0);
    }
}
