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

use std::fmt;
use std::io::{Read, Write};

#[cfg(feature = "rusqlite")]
pub mod sqlite;

use crate::address::{
    AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
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

/// Compatibility surface for address behavior whose canonical owners are
/// `stacks-crypto` (derivation) and `stacks-protocol` (network policy).
pub trait StacksAddressExtensions {
    fn is_mainnet(&self) -> bool;
    fn burn_address(mainnet: bool) -> Self;
    /// Generate an address from a given address hash mode, signature threshold, and list of public
    /// keys.  Only return an address if the combination given is supported.
    // Preserve the legacy facade signature while callers migrate to
    // `stacks_crypto::address::StacksAddressCryptoExt`, whose API accepts a
    // slice. Removing this facade is the appropriate point to drop `&Vec`.
    #[allow(clippy::ptr_arg)]
    fn from_public_keys(
        version: u8,
        hash_mode: &AddressHashMode,
        num_sigs: usize,
        pubkeys: &Vec<StacksPublicKey>,
    ) -> Option<Self>
    where
        Self: Sized;
    fn p2pkh(mainnet: bool, pubkey: &StacksPublicKey) -> Self;
    fn p2pkh_from_hash(mainnet: bool, hash: Hash160) -> Self;
}

impl StacksAddressExtensions for StacksAddress {
    fn is_mainnet(&self) -> bool {
        stacks_protocol::StacksAddressNetworkExt::is_mainnet(self)
    }

    fn burn_address(mainnet: bool) -> Self {
        stacks_protocol::burn_address(mainnet)
    }

    #[allow(clippy::ptr_arg)]
    fn from_public_keys(
        version: u8,
        hash_mode: &AddressHashMode,
        num_sigs: usize,
        pubkeys: &Vec<StacksPublicKey>,
    ) -> Option<Self> {
        stacks_crypto::address::StacksAddressCryptoExt::from_public_keys(
            version, *hash_mode, num_sigs, pubkeys,
        )
    }

    fn p2pkh(mainnet: bool, pubkey: &StacksPublicKey) -> Self {
        let hash = stacks_crypto::address::public_keys_to_address_hash(
            AddressHashMode::SerializeP2PKH,
            1,
            std::slice::from_ref(pubkey),
        )
        .expect("a single public key is valid P2PKH input");
        Self::p2pkh_from_hash(mainnet, hash)
    }

    fn p2pkh_from_hash(mainnet: bool, hash: Hash160) -> Self {
        let version = if mainnet {
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG
        } else {
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG
        };
        Self::new(version, hash).expect("constant address versions are valid")
    }
}

impl Address for StacksAddress {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes().as_bytes().to_vec()
    }

    fn from_string(s: &str) -> Option<StacksAddress> {
        StacksAddress::from_string(s)
    }

    fn is_burn(&self) -> bool {
        StacksAddress::is_burn(self)
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
