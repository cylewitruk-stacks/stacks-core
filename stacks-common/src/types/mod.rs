// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::cmp::Ordering;
use std::fmt;
use std::io::{Read, Write};

#[cfg(feature = "rusqlite")]
pub mod sqlite;

use crate::address::c32::{c32_address, c32_address_decode};
use crate::address::{
    public_keys_to_address_hash, to_bits_p2pkh, AddressHashMode,
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use crate::codec::{read_next, write_next, Error as CodecError, StacksMessageCodec};
use crate::types::chainstate::{StacksAddress, StacksPublicKey};
use crate::util::hash::Hash160;
use crate::util::secp256k1::Secp256k1PublicKey;

pub mod chainstate;
pub mod net;

#[cfg(test)]
pub mod tests;

/// A container for public keys (compressed secp256k1 public keys)
pub struct StacksPublicKeyBuffer(pub [u8; 33]);
impl_array_newtype!(StacksPublicKeyBuffer, u8, 33);
impl_array_hexstring_fmt!(StacksPublicKeyBuffer);
impl_byte_array_newtype!(StacksPublicKeyBuffer, u8, 33);
impl_byte_array_message_codec!(StacksPublicKeyBuffer, 33);
impl_byte_array_serde!(StacksPublicKeyBuffer);

impl StacksPublicKeyBuffer {
    pub fn from_public_key(pubkey: &Secp256k1PublicKey) -> StacksPublicKeyBuffer {
        let pubkey_bytes_vec = pubkey.to_bytes_compressed();
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&pubkey_bytes_vec[..]);
        StacksPublicKeyBuffer(pubkey_bytes)
    }

    pub fn to_public_key(&self) -> Result<Secp256k1PublicKey, &'static str> {
        Secp256k1PublicKey::from_slice(&self.0)
            .map_err(|_e_str| "Failed to decode Stacks public key")
    }
}

pub trait Address: Clone + fmt::Debug + fmt::Display {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_string(from: &str) -> Option<Self>
    where
        Self: Sized;
    fn is_burn(&self) -> bool;
}

pub use stacks_p2p::EpochPeerVersion;
pub use stacks_primitives::epoch::StacksEpochId;
#[cfg(any(test, feature = "testing"))]
pub use stacks_primitives::epoch::StacksEpochRangeTestExt;
pub use stacks_protocol::epoch::{
    get_coinbase_intervals, ChainEpochRules, ClarityEpochRules, CoinbaseInterval,
    EpochCoinbaseReward, MempoolCollectionBehavior, SIP031EmissionInterval,
    COINBASE_INTERVALS_MAINNET, COINBASE_INTERVALS_TESTNET, MINING_COMMITMENT_FREQUENCY_NAKAMOTO,
    MINING_COMMITMENT_WINDOW,
};
#[cfg(any(test, feature = "testing"))]
pub use stacks_protocol::epoch::{set_test_coinbase_schedule, set_test_sip_031_emission_schedule};
pub use stacks_protocol::network::{
    mainnet_epoch_schedule, regtest_epoch_schedule, testnet_epoch_schedule, EpochScheduleLimits,
    BITCOIN_MAINNET_FIRST_BLOCK_HASH, BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT,
    BITCOIN_MAINNET_FIRST_BLOCK_TIMESTAMP, BITCOIN_MAINNET_GENESIS_BURN_HEIGHT,
    BITCOIN_MAINNET_INITIAL_REWARD_START_BLOCK, BITCOIN_MAINNET_STACKS_21_BURN_HEIGHT,
    BITCOIN_MAINNET_STACKS_22_BURN_HEIGHT, BITCOIN_MAINNET_STACKS_23_BURN_HEIGHT,
    BITCOIN_MAINNET_STACKS_24_BURN_HEIGHT, BITCOIN_MAINNET_STACKS_25_BURN_HEIGHT,
    BITCOIN_MAINNET_STACKS_2_05_BURN_HEIGHT, BITCOIN_MAINNET_STACKS_30_BURN_HEIGHT,
    BITCOIN_MAINNET_STACKS_31_BURN_HEIGHT, BITCOIN_MAINNET_STACKS_32_BURN_HEIGHT,
    BITCOIN_MAINNET_STACKS_33_BURN_HEIGHT, BITCOIN_MAINNET_STACKS_34_BURN_HEIGHT,
    BITCOIN_MAINNET_STACKS_40_BURN_HEIGHT, BITCOIN_MAINNET_STACKS_41_BURN_HEIGHT,
    BITCOIN_REGTEST_FIRST_BLOCK_HASH, BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT,
    BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP, BITCOIN_TESTNET_FIRST_BLOCK_HASH,
    BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT, BITCOIN_TESTNET_FIRST_BLOCK_TIMESTAMP,
    BITCOIN_TESTNET_GENESIS_BURN_HEIGHT, BITCOIN_TESTNET_STACKS_21_BURN_HEIGHT,
    BITCOIN_TESTNET_STACKS_22_BURN_HEIGHT, BITCOIN_TESTNET_STACKS_23_BURN_HEIGHT,
    BITCOIN_TESTNET_STACKS_24_BURN_HEIGHT, BITCOIN_TESTNET_STACKS_25_BURN_HEIGHT,
    BITCOIN_TESTNET_STACKS_2_05_BURN_HEIGHT, BITCOIN_TESTNET_STACKS_30_BURN_HEIGHT,
    BITCOIN_TESTNET_STACKS_31_BURN_HEIGHT, BITCOIN_TESTNET_STACKS_32_BURN_HEIGHT,
    BITCOIN_TESTNET_STACKS_33_BURN_HEIGHT, BITCOIN_TESTNET_STACKS_34_BURN_HEIGHT,
    BITCOIN_TESTNET_STACKS_40_BURN_HEIGHT, BITCOIN_TESTNET_STACKS_41_BURN_HEIGHT,
};

impl PartialOrd for StacksAddress {
    fn partial_cmp(&self, other: &StacksAddress) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StacksAddress {
    fn cmp(&self, other: &StacksAddress) -> Ordering {
        match self.version().cmp(&other.version()) {
            Ordering::Equal => self.bytes().cmp(other.bytes()),
            inequality => inequality,
        }
    }
}

impl StacksAddress {
    pub fn is_mainnet(&self) -> bool {
        match self.version() {
            C32_ADDRESS_VERSION_MAINNET_MULTISIG | C32_ADDRESS_VERSION_MAINNET_SINGLESIG => true,
            C32_ADDRESS_VERSION_TESTNET_MULTISIG | C32_ADDRESS_VERSION_TESTNET_SINGLESIG => false,
            _ => false,
        }
    }

    pub fn burn_address(mainnet: bool) -> StacksAddress {
        Self::new(
            if mainnet {
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG
            } else {
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG
            },
            Hash160([0u8; 20]),
        )
        .unwrap_or_else(|_| panic!("FATAL: constant address versions are invalid"))
        // infallible
    }

    /// Generate an address from a given address hash mode, signature threshold, and list of public
    /// keys.  Only return an address if the combination given is supported.
    /// The version is may be arbitrary.
    pub fn from_public_keys(
        version: u8,
        hash_mode: &AddressHashMode,
        num_sigs: usize,
        pubkeys: &Vec<StacksPublicKey>,
    ) -> Option<StacksAddress> {
        // must be sufficient public keys
        if pubkeys.len() < num_sigs {
            return None;
        }

        // address hash mode must be consistent with the number of keys
        match *hash_mode {
            AddressHashMode::SerializeP2PKH | AddressHashMode::SerializeP2WPKH
                // must be a single public key, and must require one signature
                if (num_sigs != 1 || pubkeys.len() != 1) => {
                    return None;
                }
            _ => {}
        }

        // if segwit, then keys must all be compressed
        match *hash_mode {
            AddressHashMode::SerializeP2WPKH | AddressHashMode::SerializeP2WSH => {
                for pubkey in pubkeys {
                    if !pubkey.compressed() {
                        return None;
                    }
                }
            }
            _ => {}
        }

        let hash_bits = public_keys_to_address_hash(hash_mode, num_sigs, pubkeys);
        StacksAddress::new(version, hash_bits).ok()
    }

    /// Make a P2PKH StacksAddress
    pub fn p2pkh(mainnet: bool, pubkey: &StacksPublicKey) -> StacksAddress {
        let bytes = to_bits_p2pkh(pubkey);
        Self::p2pkh_from_hash(mainnet, bytes)
    }

    /// Make a P2PKH StacksAddress
    pub fn p2pkh_from_hash(mainnet: bool, hash: Hash160) -> StacksAddress {
        let version = if mainnet {
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG
        } else {
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG
        };
        Self::new(version, hash)
            .unwrap_or_else(|_| panic!("FATAL: constant address versions are invalid"))
        // infallible
    }
}

impl std::fmt::Display for StacksAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // the .unwrap_or_else() should be unreachable since StacksAddress is constructed to only
        // accept a 5-bit value for its version
        c32_address(self.version(), self.bytes().as_bytes())
            .expect("Stacks version is not C32-encodable")
            .fmt(f)
    }
}

impl Address for StacksAddress {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes().as_bytes().to_vec()
    }

    fn from_string(s: &str) -> Option<StacksAddress> {
        let (version, bytes) = c32_address_decode(s).ok()?;

        if bytes.len() != 20 {
            return None;
        }

        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&bytes[..]);
        StacksAddress::new(version, Hash160(hash_bytes)).ok()
    }

    fn is_burn(&self) -> bool {
        self.bytes() == &Hash160([0u8; 20])
    }
}

pub use stacks_protocol::epoch::{EpochList, StacksEpoch};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Copy)]
pub enum MiningReason {
    BlockFound = 0,
    Extended = 1,
    ReadCountExtend = 2,
}

impl TryFrom<u8> for MiningReason {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, CodecError> {
        match value {
            x if x == MiningReason::BlockFound as u8 => Ok(MiningReason::BlockFound),
            x if x == MiningReason::Extended as u8 => Ok(MiningReason::Extended),
            x if x == MiningReason::ReadCountExtend as u8 => Ok(MiningReason::ReadCountExtend),
            _ => Err(CodecError::DeserializeError(format!(
                "unknown mining reason {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MinerDiagnosticData {
    pub burnchain_tip_height: u64,
    pub burnchain_tip_consensus_hash: chainstate::ConsensusHash,
    pub burnchain_tip_header_hash: chainstate::BurnchainHeaderHash,
    pub tenure_extend_time_stamp: u64,
    pub read_count_extend_timestamp: u64,
    pub mining_reason: MiningReason,
}

impl StacksMessageCodec for MinerDiagnosticData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.burnchain_tip_height)?;
        write_next(fd, &self.burnchain_tip_consensus_hash)?;
        write_next(fd, &self.burnchain_tip_header_hash)?;
        write_next(fd, &self.tenure_extend_time_stamp)?;
        write_next(fd, &self.read_count_extend_timestamp)?;
        write_next(fd, &(self.mining_reason as u8))?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let burnchain_tip_height = read_next(fd)?;
        let burnchain_tip_consensus_hash = read_next(fd)?;
        let burnchain_tip_header_hash = read_next(fd)?;
        let tenure_extend_time_stamp = read_next(fd)?;
        let read_count_extend_timestamp = read_next(fd)?;
        let mining_reason = read_next::<u8, _>(fd)?.try_into()?;

        Ok(MinerDiagnosticData {
            burnchain_tip_height,
            burnchain_tip_consensus_hash,
            burnchain_tip_header_hash,
            tenure_extend_time_stamp,
            read_count_extend_timestamp,
            mining_reason,
        })
    }
}
