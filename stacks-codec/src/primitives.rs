use std::io::{Read, Write};

use stacks_primitives::block::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, SortitionId, StacksBlockId,
    StacksMicroblockHeader, StacksWorkScore, TrieHash,
};
use stacks_primitives::hash::{
    DoubleSha256, Keccak256Hash, Sha256Sum, Sha512Sum, Sha512Trunc256Sum, Txid,
};
use stacks_primitives::secp256k1::{
    CompressedSecp256k1PublicKeyBytes, MessageSignature, SchnorrSignature, Secp256k1PublicKeyBytes,
    COMPRESSED_PUBLIC_KEY_ENCODED_SIZE, UNCOMPRESSED_PUBLIC_KEY_ENCODED_SIZE,
};
use stacks_primitives::vrf::VRFProof;

use crate::{read_next, write_next, Error as CodecError, StacksMessageCodec};

impl_byte_array_message_codec!(BlockHeaderHash, 32);
impl_byte_array_message_codec!(BurnchainHeaderHash, 32);
impl_byte_array_message_codec!(ConsensusHash, 20);
impl_byte_array_message_codec!(SortitionId, 32);
impl_byte_array_message_codec!(StacksBlockId, 32);
impl_byte_array_message_codec!(TrieHash, 32);
impl_byte_array_message_codec!(Txid, 32);
impl_byte_array_message_codec!(Keccak256Hash, 32);
impl_byte_array_message_codec!(Sha256Sum, 32);
impl_byte_array_message_codec!(Sha512Sum, 64);
impl_byte_array_message_codec!(Sha512Trunc256Sum, 32);
impl_byte_array_message_codec!(DoubleSha256, 32);
impl_byte_array_message_codec!(CompressedSecp256k1PublicKeyBytes, 33);
impl_byte_array_message_codec!(MessageSignature, 65);
impl_byte_array_message_codec!(SchnorrSignature, 65);
impl_byte_array_message_codec!(VRFProof, 80);

impl StacksMessageCodec for StacksWorkScore {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.burn)?;
        write_next(fd, &self.work)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let burn = read_next(fd)?;
        let work = read_next(fd)?;
        Ok(Self { burn, work })
    }
}

impl StacksMessageCodec for Secp256k1PublicKeyBytes {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        fd.write_all(self.as_bytes())
            .map_err(CodecError::WriteError)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let mut first_byte = [0u8; 1];
        fd.read_exact(&mut first_byte)
            .map_err(CodecError::ReadError)?;

        let remaining_len = match first_byte[0] {
            0x02 | 0x03 => COMPRESSED_PUBLIC_KEY_ENCODED_SIZE - 1,
            0x04 => UNCOMPRESSED_PUBLIC_KEY_ENCODED_SIZE - 1,
            byte => {
                return Err(CodecError::DeserializeError(format!(
                    "Unsupported secp256k1 public key prefix: {byte}"
                )));
            }
        };

        let mut bytes = vec![0u8; 1 + remaining_len];
        bytes[0] = first_byte[0];
        fd.read_exact(&mut bytes[1..])
            .map_err(CodecError::ReadError)?;

        Secp256k1PublicKeyBytes::from_bytes(&bytes)
            .map_err(|e| CodecError::DeserializeError(e.to_string()))
    }
}

impl StacksMessageCodec for StacksMicroblockHeader {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.version)?;
        write_next(fd, &self.sequence)?;
        write_next(fd, &self.prev_block)?;
        write_next(fd, &self.tx_merkle_root)?;
        write_next(fd, &self.signature)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let version = read_next(fd)?;
        let sequence = read_next(fd)?;
        let prev_block = read_next(fd)?;
        let tx_merkle_root = read_next(fd)?;
        let signature = read_next(fd)?;

        Ok(StacksMicroblockHeader {
            version,
            sequence,
            prev_block,
            tx_merkle_root,
            signature,
        })
    }
}
