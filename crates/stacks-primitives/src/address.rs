use serde::{Deserialize, Serialize};

use crate::hash::Hash160;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    InvalidVersion(u8),
    InvalidNetworkVersion(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
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
}
