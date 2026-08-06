// TODO: migrate callers to `stacks-crypto` and `stacks-primitives` directly,
// then remove this compatibility bridge.
#[cfg(any(test, feature = "testing"))]
pub use stacks_crypto::secp256k1::MessageSignatureCryptoExt;
#[cfg(not(target_family = "wasm"))]
pub use stacks_crypto::secp256k1::MessageSignatureSecp256k1;
#[cfg(not(feature = "wasm-deterministic"))]
pub use stacks_crypto::secp256k1::{secp256k1_decompress, secp256k1_recover, secp256k1_verify};
pub use stacks_crypto::secp256k1::{
    Error, Secp256k1PrivateKey, Secp256k1PublicKey, SigningKey, VerifyingKey,
};
pub use stacks_primitives::secp256k1::{
    MessageSignature, SchnorrSignature, Secp256k1PublicKeyBytes,
    COMPRESSED_PUBLIC_KEY_ENCODED_SIZE, MESSAGE_SIGNATURE_ENCODED_SIZE,
    SCHNORR_SIGNATURE_ENCODED_SIZE, UNCOMPRESSED_PUBLIC_KEY_ENCODED_SIZE,
};
