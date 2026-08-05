use stacks_macros::{
    impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_newtype, impl_byte_array_serde,
};

/// Opaque wire-level VRF proof bytes.
///
/// Cryptographic construction and verification live outside `stacks-primitives`.
pub struct VRFProof(pub [u8; 80]);
impl_array_newtype!(VRFProof, u8, 80);
impl_array_hexstring_fmt!(VRFProof);
impl_byte_array_newtype!(VRFProof, u8, 80);
impl_byte_array_serde!(VRFProof);

pub const VRF_PROOF_ENCODED_SIZE: u32 = 80;
