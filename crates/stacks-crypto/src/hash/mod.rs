use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512, Sha512_256};
use sha3::Keccak256;
pub use stacks_primitives::hash::{
    DOUBLE_SHA256_ENCODED_SIZE, DoubleSha256, HASH160_ENCODED_SIZE, Hash160, Keccak256Hash,
    Sha256Sum, Sha512Sum, Sha512Trunc256Sum, Txid,
};

mod merkle;

pub use merkle::{MerkleHashFunc, MerkleTree};

pub trait Hash160Digest {
    fn from_sha256(sha256_hash: &[u8; 32]) -> Hash160;
    fn from_data(data: &[u8]) -> Hash160;
}

impl Hash160Digest for Hash160 {
    fn from_sha256(sha256_hash: &[u8; 32]) -> Hash160 {
        let mut rmd = Ripemd160::new();
        rmd.update(sha256_hash);
        Hash160(rmd.finalize().into())
    }

    fn from_data(data: &[u8]) -> Hash160 {
        let sha2_result = Sha256::digest(data);
        Hash160(Ripemd160::digest(sha2_result).into())
    }
}

pub trait Sha512SumDigest {
    fn from_data(data: &[u8]) -> Sha512Sum;
}

impl Sha512SumDigest for Sha512Sum {
    fn from_data(data: &[u8]) -> Sha512Sum {
        Sha512Sum(Sha512::digest(data).into())
    }
}

pub trait Sha512Trunc256Digest {
    fn from_data(data: &[u8]) -> Sha512Trunc256Sum;
    fn from_hasher(hasher: Sha512_256) -> Sha512Trunc256Sum;
}

impl Sha512Trunc256Digest for Sha512Trunc256Sum {
    fn from_data(data: &[u8]) -> Sha512Trunc256Sum {
        Sha512Trunc256Sum(Sha512_256::digest(data).into())
    }

    fn from_hasher(hasher: Sha512_256) -> Sha512Trunc256Sum {
        Sha512Trunc256Sum(hasher.finalize().into())
    }
}

pub trait Keccak256Digest {
    fn from_data(data: &[u8]) -> Keccak256Hash;
}

impl Keccak256Digest for Keccak256Hash {
    fn from_data(data: &[u8]) -> Keccak256Hash {
        Keccak256Hash(Keccak256::digest(data).into())
    }
}

pub trait Sha256Digest {
    fn from_data(data: &[u8]) -> Sha256Sum;
    fn zero() -> Sha256Sum;
}

impl Sha256Digest for Sha256Sum {
    fn from_data(data: &[u8]) -> Sha256Sum {
        Sha256Sum(Sha256::digest(data).into())
    }

    fn zero() -> Sha256Sum {
        Sha256Sum([0u8; 32])
    }
}

pub trait DoubleSha256Digest {
    fn from_data(data: &[u8]) -> DoubleSha256;
    fn le_hex_string(&self) -> String;
    fn be_hex_string(&self) -> String;
}

impl DoubleSha256Digest for DoubleSha256 {
    fn from_data(data: &[u8]) -> DoubleSha256 {
        DoubleSha256(Sha256::digest(Sha256::digest(data)).into())
    }

    fn le_hex_string(&self) -> String {
        const_hex::encode(self.0)
    }

    fn be_hex_string(&self) -> String {
        let mut data = self.0;
        data.reverse();
        const_hex::encode(data)
    }
}

pub trait TxidDigest {
    fn from_stacks_tx(txdata: &[u8]) -> Txid;
    fn from_sighash_bytes(txdata: &[u8]) -> Txid;
}

impl TxidDigest for Txid {
    fn from_stacks_tx(txdata: &[u8]) -> Txid {
        Txid(Sha512_256::digest(txdata).into())
    }

    fn from_sighash_bytes(txdata: &[u8]) -> Txid {
        Self::from_stacks_tx(txdata)
    }
}

impl MerkleHashFunc for Hash160 {
    fn empty() -> Hash160 {
        Hash160([0u8; 20])
    }

    fn from_tagged_data(tag: u8, data: &[u8]) -> Hash160 {
        let mut sha2 = Sha256::new();
        sha2.update([tag]);
        sha2.update(data);
        let sha2_bytes = sha2.finalize().into();
        Hash160::from_sha256(&sha2_bytes)
    }

    fn bits(&self) -> &[u8] {
        &self.0
    }
}

impl MerkleHashFunc for Sha256Sum {
    fn empty() -> Sha256Sum {
        Sha256Sum([0u8; 32])
    }

    fn from_tagged_data(tag: u8, data: &[u8]) -> Sha256Sum {
        let mut sha2 = Sha256::new();
        sha2.update([tag]);
        sha2.update(data);
        Sha256Sum(sha2.finalize().into())
    }

    fn bits(&self) -> &[u8] {
        &self.0
    }
}

impl MerkleHashFunc for DoubleSha256 {
    fn empty() -> DoubleSha256 {
        DoubleSha256([0u8; 32])
    }

    fn from_tagged_data(tag: u8, data: &[u8]) -> DoubleSha256 {
        let mut sha2_1 = Sha256::new();
        sha2_1.update([tag]);
        sha2_1.update(data);

        let mut sha2_2 = Sha256::new();
        sha2_2.update(sha2_1.finalize());
        DoubleSha256(sha2_2.finalize().into())
    }

    fn bits(&self) -> &[u8] {
        &self.0
    }
}

impl MerkleHashFunc for Sha512Trunc256Sum {
    fn empty() -> Sha512Trunc256Sum {
        Sha512Trunc256Sum([0u8; 32])
    }

    fn from_tagged_data(tag: u8, data: &[u8]) -> Sha512Trunc256Sum {
        let mut sha2 = Sha512_256::new();
        sha2.update([tag]);
        sha2.update(data);
        Sha512Trunc256Sum(sha2.finalize().into())
    }

    fn bits(&self) -> &[u8] {
        &self.0
    }
}
