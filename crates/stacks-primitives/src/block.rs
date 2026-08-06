use serde::{Deserialize, Serialize};
use stacks_macros::{
    impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_newtype, impl_byte_array_serde,
};

use crate::hash::Sha512Trunc256Sum;
use crate::secp256k1::MessageSignature;

/// Max size of a serialized Stacks block.
pub const MAX_BLOCK_LEN: u32 = 2 * 1024 * 1024;

pub struct BlockHeaderHash(pub [u8; 32]);
impl_array_newtype!(BlockHeaderHash, u8, 32);
impl_array_hexstring_fmt!(BlockHeaderHash);
impl_byte_array_newtype!(
    BlockHeaderHash,
    u8,
    32,
    crate::HexError,
    crate::hex::decode_array
);
impl_byte_array_serde!(BlockHeaderHash);
pub const BLOCK_HEADER_HASH_ENCODED_SIZE: usize = 32;

/// Hash of a Trie node.
#[derive(Default, Copy)]
pub struct TrieHash(pub [u8; 32]);
impl_array_newtype!(TrieHash, u8, 32);
impl_array_hexstring_fmt!(TrieHash);
impl_byte_array_newtype!(TrieHash, u8, 32, crate::HexError, crate::hex::decode_array);
impl_byte_array_serde!(TrieHash);
pub const TRIEHASH_ENCODED_SIZE: usize = 32;

impl TrieHash {
    /// SHA2-512/256 hash of an empty string.
    pub const EMPTY: TrieHash = TrieHash([
        0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51, 0x14,
        0x06, 0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0,
        0x96, 0x7a,
    ]);
}

pub struct BurnchainHeaderHash(pub [u8; 32]);
impl_array_newtype!(BurnchainHeaderHash, u8, 32);
impl_array_hexstring_fmt!(BurnchainHeaderHash);
impl_byte_array_newtype!(
    BurnchainHeaderHash,
    u8,
    32,
    crate::HexError,
    crate::hex::decode_array
);
impl_byte_array_serde!(BurnchainHeaderHash);

/// Identifier used to identify sortitions in the SortitionDB.
pub struct SortitionId(pub [u8; 32]);
impl_array_newtype!(SortitionId, u8, 32);
impl_array_hexstring_fmt!(SortitionId);
impl_byte_array_newtype!(
    SortitionId,
    u8,
    32,
    crate::HexError,
    crate::hex::decode_array
);
impl_byte_array_serde!(SortitionId);

pub struct StacksBlockId(pub [u8; 32]);
impl_array_newtype!(StacksBlockId, u8, 32);
impl_array_hexstring_fmt!(StacksBlockId);
impl_byte_array_newtype!(
    StacksBlockId,
    u8,
    32,
    crate::HexError,
    crate::hex::decode_array
);
impl_byte_array_serde!(StacksBlockId);

/// A newtype for `StacksBlockId` that indicates a block is a tenure-change
/// block. This helps to explicitly differentiate tenure-change blocks in the
/// code.
pub struct TenureBlockId(pub StacksBlockId);

impl From<StacksBlockId> for TenureBlockId {
    fn from(id: StacksBlockId) -> TenureBlockId {
        TenureBlockId(id)
    }
}

pub struct ConsensusHash(pub [u8; 20]);
impl_array_newtype!(ConsensusHash, u8, 20);
impl_array_hexstring_fmt!(ConsensusHash);
impl_byte_array_newtype!(
    ConsensusHash,
    u8,
    20,
    crate::HexError,
    crate::hex::decode_array
);
impl_byte_array_serde!(ConsensusHash);
pub const CONSENSUS_HASH_ENCODED_SIZE: u32 = 20;

/// How much work has gone into this chain so far?
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StacksWorkScore {
    pub burn: u64,
    pub work: u64,
}

impl StacksWorkScore {
    /// Stacks work score for the first-mined block.
    pub fn initial() -> StacksWorkScore {
        StacksWorkScore { burn: 0, work: 1 }
    }

    /// Stacks work score for the boot code block.
    pub fn genesis() -> StacksWorkScore {
        StacksWorkScore { burn: 0, work: 0 }
    }
}

/// Header structure for a microblock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StacksMicroblockHeader {
    pub version: u8,
    pub sequence: u16,
    pub prev_block: BlockHeaderHash,
    pub tx_merkle_root: Sha512Trunc256Sum,
    pub signature: MessageSignature,
}

impl StacksMicroblockHeader {
    /// Create the first microblock header in a microblock stream.
    /// The header will not be signed.
    pub fn first_unsigned(
        parent_block_hash: &BlockHeaderHash,
        tx_merkle_root: &Sha512Trunc256Sum,
    ) -> StacksMicroblockHeader {
        StacksMicroblockHeader {
            version: 0,
            sequence: 0,
            prev_block: parent_block_hash.clone(),
            tx_merkle_root: tx_merkle_root.clone(),
            signature: MessageSignature::empty(),
        }
    }

    /// Create the first microblock header in a microblock stream for an empty microblock stream.
    /// The header will not be signed.
    pub fn first_empty_unsigned(parent_block_hash: &BlockHeaderHash) -> StacksMicroblockHeader {
        StacksMicroblockHeader::first_unsigned(parent_block_hash, &Sha512Trunc256Sum([0u8; 32]))
    }
}
