use core::convert::TryFrom;
use core::fmt;
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};
use stacks_primitives::address::{AddressHashMode, StacksAddress};
use stacks_primitives::hash::Hash160;
use stacks_primitives::network::{Mainnet, StacksNetwork, Testnet};

pub trait AddressNetwork: StacksNetwork {
    const C32_ADDRESS_VERSION_SINGLESIG: u8;
    const C32_ADDRESS_VERSION_MULTISIG: u8;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StacksNetworkAddressError {
    InvalidVersion(u8),
}

impl fmt::Display for StacksNetworkAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion(version) => {
                write!(f, "address version {version} is invalid for this network")
            }
        }
    }
}

impl std::error::Error for StacksNetworkAddressError {}

pub trait AddressHashModeNetworkExt {
    fn to_version_mainnet(&self) -> u8;
    fn to_version_testnet(&self) -> u8;
    fn to_version<Network>(&self) -> u8
    where
        Network: AddressNetwork;
}

impl AddressHashModeNetworkExt for AddressHashMode {
    fn to_version_mainnet(&self) -> u8 {
        self.to_version::<Mainnet>()
    }

    fn to_version_testnet(&self) -> u8 {
        self.to_version::<Testnet>()
    }

    fn to_version<Network>(&self) -> u8
    where
        Network: AddressNetwork,
    {
        match *self {
            AddressHashMode::SerializeP2PKH => Network::C32_ADDRESS_VERSION_SINGLESIG,
            _ => Network::C32_ADDRESS_VERSION_MULTISIG,
        }
    }
}

pub fn address_hash_mode_from_version_for_network<Network>(version: u8) -> Option<AddressHashMode>
where
    Network: AddressNetwork,
{
    if version == Network::C32_ADDRESS_VERSION_SINGLESIG {
        Some(AddressHashMode::SerializeP2PKH)
    } else if version == Network::C32_ADDRESS_VERSION_MULTISIG {
        Some(AddressHashMode::SerializeP2SH)
    } else {
        None
    }
}

/// WARNING: this does not support segwit-p2sh.
pub fn address_hash_mode_from_version(version: u8) -> AddressHashMode {
    if matches!(
        address_hash_mode_from_version_for_network::<Mainnet>(version),
        Some(AddressHashMode::SerializeP2PKH)
    ) || matches!(
        address_hash_mode_from_version_for_network::<Testnet>(version),
        Some(AddressHashMode::SerializeP2PKH)
    ) {
        AddressHashMode::SerializeP2PKH
    } else {
        AddressHashMode::SerializeP2SH
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct StacksNetworkAddress<Network>
where
    Network: AddressNetwork,
{
    hash_mode: AddressHashMode,
    bytes: Hash160,
    _network: PhantomData<Network>,
}

impl<Network> StacksNetworkAddress<Network>
where
    Network: AddressNetwork,
{
    pub fn new(hash_mode: AddressHashMode, bytes: Hash160) -> StacksNetworkAddress<Network> {
        StacksNetworkAddress {
            hash_mode,
            bytes,
            _network: PhantomData,
        }
    }

    pub fn singlesig(bytes: Hash160) -> StacksNetworkAddress<Network> {
        StacksNetworkAddress::new(AddressHashMode::SerializeP2PKH, bytes)
    }

    pub fn multisig(bytes: Hash160) -> StacksNetworkAddress<Network> {
        StacksNetworkAddress::new(AddressHashMode::SerializeP2SH, bytes)
    }

    pub fn burn_address() -> StacksNetworkAddress<Network> {
        StacksNetworkAddress::singlesig(Hash160([0u8; 20]))
    }

    pub fn hash_mode(&self) -> AddressHashMode {
        self.hash_mode
    }

    pub fn version(&self) -> u8 {
        self.hash_mode.to_version::<Network>()
    }

    pub fn bytes(&self) -> &Hash160 {
        &self.bytes
    }

    pub fn destruct(self) -> (AddressHashMode, Hash160) {
        (self.hash_mode, self.bytes)
    }

    pub fn to_raw(&self) -> StacksAddress {
        StacksAddress::new(self.version(), self.bytes.clone())
            .expect("FATAL: address network constants are invalid")
    }

    pub fn into_raw(self) -> StacksAddress {
        StacksAddress::new(self.version(), self.bytes)
            .expect("FATAL: address network constants are invalid")
    }

    pub fn try_from_raw(
        address: StacksAddress,
    ) -> Result<StacksNetworkAddress<Network>, StacksNetworkAddressError> {
        StacksNetworkAddress::try_from(address)
    }
}

impl<Network> From<StacksNetworkAddress<Network>> for StacksAddress
where
    Network: AddressNetwork,
{
    fn from(address: StacksNetworkAddress<Network>) -> Self {
        address.into_raw()
    }
}

impl<Network> TryFrom<StacksAddress> for StacksNetworkAddress<Network>
where
    Network: AddressNetwork,
{
    type Error = StacksNetworkAddressError;

    fn try_from(address: StacksAddress) -> Result<Self, Self::Error> {
        let hash_mode = address_hash_mode_from_version_for_network::<Network>(address.version())
            .ok_or(StacksNetworkAddressError::InvalidVersion(address.version()))?;
        let (_, bytes) = address.destruct();

        Ok(StacksNetworkAddress::new(hash_mode, bytes))
    }
}

pub trait StacksAddressNetworkExt {
    fn is_mainnet(&self) -> bool;
}

impl StacksAddressNetworkExt for StacksAddress {
    fn is_mainnet(&self) -> bool {
        address_hash_mode_from_version_for_network::<Mainnet>(self.version()).is_some()
    }
}

pub fn burn_address(mainnet: bool) -> StacksAddress {
    if mainnet {
        burn_address_for_network::<Mainnet>()
    } else {
        burn_address_for_network::<Testnet>()
    }
}

pub fn burn_address_for_network<Network>() -> StacksAddress
where
    Network: AddressNetwork,
{
    StacksNetworkAddress::<Network>::burn_address().into_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_policy_is_applied_outside_the_raw_address() {
        let mainnet = StacksNetworkAddress::<Mainnet>::singlesig(Hash160([1; 20])).into_raw();
        let testnet = StacksNetworkAddress::<Testnet>::singlesig(Hash160([1; 20])).into_raw();

        assert_eq!(mainnet.version(), Mainnet::C32_ADDRESS_VERSION_SINGLESIG);
        assert_eq!(testnet.version(), Testnet::C32_ADDRESS_VERSION_SINGLESIG);
        assert!(mainnet.is_mainnet());
        assert!(!testnet.is_mainnet());
    }

    #[test]
    fn typed_addresses_reject_versions_from_other_networks() {
        let testnet = StacksNetworkAddress::<Testnet>::singlesig(Hash160([1; 20])).into_raw();
        let error = StacksNetworkAddress::<Mainnet>::try_from_raw(testnet)
            .expect_err("testnet version must not be accepted as mainnet");

        assert_eq!(
            error,
            StacksNetworkAddressError::InvalidVersion(Testnet::C32_ADDRESS_VERSION_SINGLESIG)
        );
    }

    #[test]
    fn burn_addresses_are_network_policy_over_zero_hashes() {
        let mainnet = burn_address_for_network::<Mainnet>();
        let testnet = burn_address_for_network::<Testnet>();

        assert!(mainnet.is_burn());
        assert!(testnet.is_burn());
        assert_ne!(mainnet.version(), testnet.version());
    }
}
