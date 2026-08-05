use serde::{Deserialize, Serialize};
use stacks_primitives::secp256k1::{MessageSignature, Secp256k1PublicKeyBytes};

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionAuthFlags {
    AuthStandard = 0x04,
    AuthSponsored = 0x05,
}

/// Transaction signatures are validated by calculating the public key from the signature, and
/// verifying that all public keys hash to the signing account's hash. To do so, we must preserve
/// enough information in the auth structure to recover each public key's bytes.
///
/// An auth field can be a public key or a signature. In both cases, the public key may be encoded
/// as compressed or uncompressed.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionAuthFieldID {
    PublicKeyCompressed = 0x00,
    PublicKeyUncompressed = 0x01,
    SignatureCompressed = 0x02,
    SignatureUncompressed = 0x03,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionPublicKeyEncoding {
    Compressed = 0x00,
    Uncompressed = 0x01,
}

impl TransactionPublicKeyEncoding {
    pub fn from_u8(n: u8) -> Option<TransactionPublicKeyEncoding> {
        match n {
            x if x == TransactionPublicKeyEncoding::Compressed as u8 => {
                Some(TransactionPublicKeyEncoding::Compressed)
            }
            x if x == TransactionPublicKeyEncoding::Uncompressed as u8 => {
                Some(TransactionPublicKeyEncoding::Uncompressed)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionAuthField {
    PublicKey(Secp256k1PublicKeyBytes),
    Signature(TransactionPublicKeyEncoding, MessageSignature),
}

impl TransactionAuthField {
    pub fn is_public_key(&self) -> bool {
        matches!(self, TransactionAuthField::PublicKey(_))
    }

    pub fn is_signature(&self) -> bool {
        matches!(self, TransactionAuthField::Signature(..))
    }

    pub fn as_public_key(&self) -> Option<Secp256k1PublicKeyBytes> {
        match *self {
            TransactionAuthField::PublicKey(ref pubk) => Some(pubk.clone()),
            _ => None,
        }
    }

    pub fn as_signature(&self) -> Option<(TransactionPublicKeyEncoding, MessageSignature)> {
        match *self {
            TransactionAuthField::Signature(ref key_fmt, ref sig) => Some((*key_fmt, sig.clone())),
            _ => None,
        }
    }
}
