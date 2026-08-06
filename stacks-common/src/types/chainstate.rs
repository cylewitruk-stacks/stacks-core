// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Compatibility facade for canonical chainstate value types.
//!
//! New code should import opaque values from `stacks-primitives`, their
//! cryptographic derivations from `stacks-crypto`, protocol rules from
//! `stacks-protocol`, and database adapters from `stacks-rusqlite`.

pub use stacks_crypto::block::{
    BlockHeaderHashDigest, StacksBlockIdDigest, TrieHashDigest, VRFSeedDigest,
};
#[cfg(any(test, feature = "testing"))]
use stacks_crypto::hash::DoubleSha256Digest as _;
pub use stacks_crypto::hash::TxidDigest;
pub use stacks_crypto::secp256k1::{
    Secp256k1PrivateKey as StacksPrivateKey, Secp256k1PublicKey as StacksPublicKey,
};
pub use stacks_primitives::address::StacksAddress;
pub use stacks_primitives::block::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, SortitionId, StacksBlockId,
    StacksMicroblockHeader, StacksWorkScore, TenureBlockId, TrieHash,
    BLOCK_HEADER_HASH_ENCODED_SIZE, CONSENSUS_HASH_ENCODED_SIZE, MAX_BLOCK_LEN,
    TRIEHASH_ENCODED_SIZE,
};
pub use stacks_primitives::hash::{Txid, TXID_ENCODED_SIZE};
pub use stacks_primitives::vrf::{VRFSeed, VRF_SEED_ENCODED_SIZE};
pub use stacks_protocol::pox::{PoxId, SortitionIdExt};

pub use super::StacksAddressExtensions;
pub use crate::address::AddressHashModeExtensions;
use crate::codec::{Error as CodecError, StacksMessageCodec};
use crate::deps_common::bitcoin::util::hash::Sha256dHash;
use crate::util::{HexDeser, HexError, HexSer};

pub const STACKS_ADDRESS_ENCODED_SIZE: u32 = 1 + stacks_primitives::hash::HASH160_ENCODED_SIZE;

macro_rules! impl_common_hex_traits {
    ($($type:path),+ $(,)?) => {
        $(
            impl HexDeser for $type {
                fn try_from_hex(value: &str) -> Result<Self, HexError> {
                    let bytes = crate::util::hash::hex_bytes(value)?;
                    Self::from_bytes(&bytes).ok_or(HexError::BadLength(value.len()))
                }
            }

            impl HexSer for $type {
                fn fmt_hex(
                    &self,
                    formatter: &mut std::fmt::Formatter<'_>,
                ) -> std::fmt::Result {
                    std::fmt::LowerHex::fmt(self, formatter)
                }
            }
        )+
    };
}

impl_common_hex_traits!(
    TrieHash,
    BurnchainHeaderHash,
    BlockHeaderHash,
    SortitionId,
    VRFSeed,
    StacksBlockId,
    ConsensusHash,
);

/// Codec-dependent block-header derivation retained for compatibility.
pub trait BlockHeaderHashCodecExt {
    fn from_serializer<C: StacksMessageCodec>(serializer: &C) -> Result<Self, CodecError>
    where
        Self: Sized;
}

impl BlockHeaderHashCodecExt for BlockHeaderHash {
    fn from_serializer<C: StacksMessageCodec>(serializer: &C) -> Result<Self, CodecError> {
        use sha2::{Digest as _, Sha512_256};

        let mut hasher = Sha512_256::new();
        serializer.consensus_serialize(&mut hasher)?;
        Ok(BlockHeaderHash(hasher.finalize().into()))
    }
}

/// Legacy Bitcoin interoperability for burnchain hashes.
pub trait BurnchainHeaderHashBitcoinExt {
    fn from_bitcoin_hash(hash: &Sha256dHash) -> Self;
    fn to_bitcoin_hash(&self) -> Sha256dHash;
    fn zero() -> Self;

    #[cfg(any(test, feature = "testing"))]
    fn from_test_data(block_height: u64, index_root: &TrieHash, noise: u64) -> Self;
}

impl BurnchainHeaderHashBitcoinExt for BurnchainHeaderHash {
    fn from_bitcoin_hash(hash: &Sha256dHash) -> Self {
        Self::from_bytes_be(hash.as_bytes()).expect("burnchain hashes are both 32 bytes")
    }

    fn to_bitcoin_hash(&self) -> Sha256dHash {
        let mut bytes = self.0;
        bytes.reverse();
        Sha256dHash(bytes)
    }

    fn zero() -> Self {
        Self::ZERO
    }

    #[cfg(any(test, feature = "testing"))]
    fn from_test_data(block_height: u64, index_root: &TrieHash, noise: u64) -> Self {
        use stacks_crypto::hash::DoubleSha256;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&block_height.to_be_bytes());
        bytes.extend_from_slice(index_root.as_bytes());
        bytes.extend_from_slice(&noise.to_be_bytes());
        Self(DoubleSha256::from_data(&bytes).0)
    }
}

/// Legacy Bitcoin transaction-hash conversions.
pub trait TxidBitcoinExt {
    fn from_bitcoin_tx_hash(hash: &Sha256dHash) -> Self;
    fn to_bitcoin_tx_hash(txid: &Self) -> Sha256dHash;

    #[cfg(any(test, feature = "testing"))]
    fn from_test_data(
        block_height: u64,
        transaction_index: u32,
        burn_header_hash: &BurnchainHeaderHash,
        noise: u64,
    ) -> Self;
}

impl TxidBitcoinExt for Txid {
    fn from_bitcoin_tx_hash(hash: &Sha256dHash) -> Self {
        let mut bytes = hash.0;
        bytes.reverse();
        Self(bytes)
    }

    fn to_bitcoin_tx_hash(txid: &Self) -> Sha256dHash {
        let mut bytes = txid.0;
        bytes.reverse();
        Sha256dHash(bytes)
    }

    #[cfg(any(test, feature = "testing"))]
    fn from_test_data(
        block_height: u64,
        transaction_index: u32,
        burn_header_hash: &BurnchainHeaderHash,
        noise: u64,
    ) -> Self {
        use stacks_crypto::hash::DoubleSha256;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&block_height.to_be_bytes());
        bytes.extend_from_slice(&transaction_index.to_be_bytes());
        bytes.extend_from_slice(burn_header_hash.as_bytes());
        bytes.extend_from_slice(&noise.to_be_bytes());
        Self(DoubleSha256::from_data(&bytes).0)
    }
}

/// Genesis-specific compatibility behavior; ordinary block ID derivation is
/// provided by [`StacksBlockIdDigest`].
pub trait StacksBlockIdGenesisExt {
    fn first_mined() -> Self;
}

impl StacksBlockIdGenesisExt for StacksBlockId {
    fn first_mined() -> Self {
        Self::new(
            &crate::consts::FIRST_BURNCHAIN_CONSENSUS_HASH,
            &crate::consts::FIRST_STACKS_BLOCK_HASH,
        )
    }
}
