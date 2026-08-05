use std::io::{Read, Write};

use stacks_primitives::address::StacksAddress;
use stacks_primitives::hash::Hash160;

use crate::{read_next, write_next, Error as CodecError, StacksMessageCodec};

pub const HASH160_ENCODED_SIZE: u32 = 20;
pub const STACKS_ADDRESS_ENCODED_SIZE: u32 = 1 + HASH160_ENCODED_SIZE;

impl StacksMessageCodec for Hash160 {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        consensus_serialize_hash160(self, fd)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Hash160, CodecError> {
        consensus_deserialize_hash160(fd)
    }
}

impl StacksMessageCodec for StacksAddress {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        consensus_serialize(self, fd)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksAddress, CodecError> {
        consensus_deserialize(fd)
    }
}

pub fn consensus_serialize<W: Write>(
    address: &StacksAddress,
    fd: &mut W,
) -> Result<(), CodecError> {
    let version = address.version();
    write_next(fd, &version)?;
    fd.write_all(address.bytes().as_bytes())
        .map_err(CodecError::WriteError)
}

pub fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksAddress, CodecError> {
    let version: u8 = read_next(fd)?;
    if version >= 32 {
        return Err(CodecError::DeserializeError(
            "Address version byte must be in range 0 to 31".into(),
        ));
    }

    let hash160 = consensus_deserialize_hash160(fd)?;
    StacksAddress::new(version, hash160)
        .map_err(|_| CodecError::DeserializeError("Invalid address version byte".into()))
}

pub fn consensus_serialize_hash160<W: Write>(hash: &Hash160, fd: &mut W) -> Result<(), CodecError> {
    fd.write_all(hash.as_bytes())
        .map_err(CodecError::WriteError)
}

pub fn consensus_deserialize_hash160<R: Read>(fd: &mut R) -> Result<Hash160, CodecError> {
    let bytes: [u8; 20] = StacksMessageCodec::consensus_deserialize(fd)?;
    Ok(Hash160(bytes))
}
