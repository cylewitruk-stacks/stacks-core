use sha2::{Digest, Sha256};

/// Minimal canonical transcript builder. Domain constants remain explicit in
/// each protocol's dedicated digest function; this type only standardizes
/// unambiguous scalar and length-prefixed byte insertion.
pub struct CanonicalTranscript {
    bytes: Vec<u8>,
}

impl CanonicalTranscript {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.bytes
            .extend_from_slice(&(value.len() as u64).to_be_bytes());
        self.bytes.extend_from_slice(value);
        self
    }

    pub fn raw(&mut self, value: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(value);
        self
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.raw(&value.to_be_bytes())
    }

    pub fn i32(&mut self, value: i32) -> &mut Self {
        self.raw(&value.to_be_bytes())
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.raw(&value.to_be_bytes())
    }

    pub fn finish_sha256(self) -> [u8; 32] {
        Sha256::digest(self.bytes).into()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
