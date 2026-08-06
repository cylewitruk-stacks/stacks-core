use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::hash::Hash160;

mod c32;

pub use c32::{c32_address, c32_address_decode};

/// Serialization modes for public keys to addresses.
///
/// These describe the domain-level Stacks address hash modes. The actual
/// public-key/script hashing lives outside `stacks-primitives`.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Hash, Eq, Copy, Serialize, Deserialize)]
pub enum AddressHashMode {
    SerializeP2PKH = 0x00,
    SerializeP2SH = 0x01,
    SerializeP2WPKH = 0x02,
    SerializeP2WSH = 0x03,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidAddressHashMode(pub u8);

impl fmt::Display for InvalidAddressHashMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid address hash mode {}", self.0)
    }
}

impl std::error::Error for InvalidAddressHashMode {}

impl TryFrom<u8> for AddressHashMode {
    type Error = InvalidAddressHashMode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::SerializeP2PKH),
            0x01 => Ok(Self::SerializeP2SH),
            0x02 => Ok(Self::SerializeP2WPKH),
            0x03 => Ok(Self::SerializeP2WSH),
            value => Err(InvalidAddressHashMode(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    InvalidVersion(u8),
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion(version) => write!(f, "invalid address version {version}"),
        }
    }
}

impl std::error::Error for AddressError {}

/// Error produced by canonical C32Check address encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum C32Error {
    InvalidCrockford32,
    InvalidVersion(u8),
    BadChecksum(u32, u32),
    InvalidLength(usize),
}

impl fmt::Display for C32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCrockford32 => f.write_str("invalid Crockford base32 string"),
            Self::InvalidVersion(version) => write!(f, "invalid C32 version {version}"),
            Self::BadChecksum(expected, actual) => write!(
                f,
                "C32 checksum 0x{actual:x} does not match expected 0x{expected:x}"
            ),
            Self::InvalidLength(length) => write!(f, "invalid C32 payload length {length}"),
        }
    }
}

impl std::error::Error for C32Error {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct StacksAddress {
    version: u8,
    bytes: Hash160,
}

impl StacksAddress {
    pub fn new(version: u8, hash: Hash160) -> Result<StacksAddress, AddressError> {
        if version >= 32 {
            return Err(AddressError::InvalidVersion(version));
        }

        Ok(StacksAddress {
            version,
            bytes: hash,
        })
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn new_unsafe(version: u8, bytes: Hash160) -> Self {
        Self { version, bytes }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn bytes(&self) -> &Hash160 {
        &self.bytes
    }

    pub fn destruct(self) -> (u8, Hash160) {
        (self.version, self.bytes)
    }

    pub fn has_valid_version(&self) -> bool {
        self.version < 32
    }

    /// Parse a canonical C32Check-encoded Stacks address.
    pub fn from_c32(value: &str) -> Result<Self, C32Error> {
        value.parse()
    }

    /// Compatibility helper for callers of the legacy `Address` trait API.
    pub fn from_string(value: &str) -> Option<Self> {
        Self::from_c32(value).ok()
    }

    /// Whether this address has the all-zero hash used by burn addresses.
    pub fn is_burn(&self) -> bool {
        self.bytes == Hash160::ZERO
    }
}

impl fmt::Display for StacksAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = c32_address(self.version, self.bytes.as_bytes())
            .expect("StacksAddress always contains a valid 5-bit C32 version");
        f.write_str(&encoded)
    }
}

impl FromStr for StacksAddress {
    type Err = C32Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (version, bytes) = c32_address_decode(value)?;
        let hash = Hash160::from_bytes(&bytes).ok_or(C32Error::InvalidLength(bytes.len()))?;
        Self::new(version, hash)
            .map_err(|AddressError::InvalidVersion(version)| C32Error::InvalidVersion(version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_text_round_trip() {
        let address = StacksAddress::new(
            22,
            Hash160::from_hex("a46ff88886c2ef9762d970b4d2c63678835bd39d").unwrap(),
        )
        .unwrap();
        let encoded = "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7";

        assert_eq!(address.to_string(), encoded);
        assert_eq!(StacksAddress::from_c32(encoded).unwrap(), address);
        assert_eq!(encoded.parse::<StacksAddress>().unwrap(), address);
    }

    #[test]
    fn address_ordering_matches_version_then_hash() {
        let low_hash = StacksAddress::new(22, Hash160([0; 20])).unwrap();
        let high_hash = StacksAddress::new(22, Hash160([1; 20])).unwrap();
        let high_version = StacksAddress::new(26, Hash160([0; 20])).unwrap();

        assert!(low_hash < high_hash);
        assert!(high_hash < high_version);
    }

    #[test]
    fn burn_address_is_value_intrinsic() {
        assert!(StacksAddress::new(22, Hash160::ZERO).unwrap().is_burn());
        assert!(!StacksAddress::new(22, Hash160([1; 20])).unwrap().is_burn());
    }

    #[test]
    fn address_parser_rejects_non_address_payload_lengths() {
        let encoded = c32_address(22, &[1; 19]).unwrap();
        assert_eq!(
            encoded.parse::<StacksAddress>(),
            Err(C32Error::InvalidLength(19))
        );
    }
}
