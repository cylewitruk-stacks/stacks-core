use stacks_macros::{
    impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_newtype, impl_byte_array_serde,
};

/// The 32-byte seed derived from a validated VRF proof.
///
/// This is an opaque value type. Proof validation and seed derivation belong
/// to `stacks-crypto`.
pub struct VRFSeed(pub [u8; 32]);
impl_array_newtype!(VRFSeed, u8, 32);
impl_array_hexstring_fmt!(VRFSeed);
impl_byte_array_newtype!(VRFSeed, u8, 32, crate::HexError, crate::hex::decode_array);
impl_byte_array_serde!(VRFSeed);

pub const VRF_SEED_ENCODED_SIZE: u32 = 32;

impl VRFSeed {
    /// The genesis VRF seed.
    pub const INITIAL: Self = Self::ZERO;
}
