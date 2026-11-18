use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::wire::v1::{Envelope, EnvelopeKind};

pub const CONTENT_ID_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ContentId([u8; CONTENT_ID_LEN]);

impl ContentId {
    pub const fn from_bytes(bytes: [u8; CONTENT_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_domain_bytes(domain: &'static [u8], bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    pub const fn as_bytes(&self) -> &[u8; CONTENT_ID_LEN] {
        &self.0
    }
}

impl TryFrom<&[u8]> for ContentId {
    type Error = EnvelopeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; CONTENT_ID_LEN] = bytes
            .try_into()
            .map_err(|_| EnvelopeError::InvalidContentId(bytes.len()))?;
        Ok(Self(bytes))
    }
}

impl TryFrom<Vec<u8>> for ContentId {
    type Error = EnvelopeError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    pub const V1: Self = Self(1);

    pub const fn new(version: u32) -> Self {
        Self(version)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeLimits {
    pub max_frame_bytes: usize,
    pub max_payload_bytes: usize,
}

impl EnvelopeLimits {
    pub const HELLO: Self = Self {
        max_frame_bytes: 16 * 1024,
        max_payload_bytes: 12 * 1024,
    };

    pub const BLOCK: Self = Self {
        max_frame_bytes: 2 * 1024 * 1024 + 4096,
        max_payload_bytes: 2 * 1024 * 1024,
    };

    pub const DIRECTORY: Self = Self {
        max_frame_bytes: 72 * 1024,
        max_payload_bytes: 64 * 1024,
    };

    pub const SYNC: Self = Self {
        max_frame_bytes: 17 * 1024 * 1024 + 64 * 1024,
        max_payload_bytes: 17 * 1024 * 1024,
    };
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum EnvelopeError {
    #[error("frame length {actual} exceeds limit {limit}")]
    FrameTooLarge { actual: usize, limit: usize },
    #[error("payload length {actual} exceeds limit {limit}")]
    PayloadTooLarge { actual: usize, limit: usize },
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u32),
    #[error("unspecified or unknown envelope kind {0}")]
    InvalidKind(i32),
    #[error("content ID must contain exactly 32 bytes, got {0}")]
    InvalidContentId(usize),
    #[error("encoded_len {declared} does not match payload length {actual}")]
    EncodedLengthMismatch { declared: u64, actual: usize },
    #[error("protobuf decode failed: {0}")]
    Decode(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkEnvelope {
    wire: Envelope,
    content_id: ContentId,
    kind: EnvelopeKind,
}

impl NetworkEnvelope {
    pub fn new(
        chain_id: u32,
        kind: EnvelopeKind,
        flags: u32,
        content_id: ContentId,
        payload: Vec<u8>,
    ) -> Self {
        let wire = Envelope {
            version: ProtocolVersion::V1.get(),
            chain_id,
            kind: kind as i32,
            flags,
            content_id: content_id.as_bytes().to_vec(),
            encoded_len: payload.len() as u64,
            payload,
        };
        Self {
            wire,
            content_id,
            kind,
        }
    }

    pub fn decode(bytes: &[u8], limits: EnvelopeLimits) -> Result<Self, EnvelopeError> {
        if bytes.len() > limits.max_frame_bytes {
            return Err(EnvelopeError::FrameTooLarge {
                actual: bytes.len(),
                limit: limits.max_frame_bytes,
            });
        }
        let wire =
            Envelope::decode(bytes).map_err(|error| EnvelopeError::Decode(error.to_string()))?;
        Self::validate(wire, limits)
    }

    pub fn validate(wire: Envelope, limits: EnvelopeLimits) -> Result<Self, EnvelopeError> {
        if wire.version != ProtocolVersion::V1.get() {
            return Err(EnvelopeError::UnsupportedVersion(wire.version));
        }
        let kind = EnvelopeKind::try_from(wire.kind)
            .ok()
            .filter(|kind| *kind != EnvelopeKind::Unspecified)
            .ok_or(EnvelopeError::InvalidKind(wire.kind))?;
        let content_id_bytes: [u8; CONTENT_ID_LEN] = wire
            .content_id
            .as_slice()
            .try_into()
            .map_err(|_| EnvelopeError::InvalidContentId(wire.content_id.len()))?;
        if wire.payload.len() > limits.max_payload_bytes {
            return Err(EnvelopeError::PayloadTooLarge {
                actual: wire.payload.len(),
                limit: limits.max_payload_bytes,
            });
        }
        if wire.encoded_len != wire.payload.len() as u64 {
            return Err(EnvelopeError::EncodedLengthMismatch {
                declared: wire.encoded_len,
                actual: wire.payload.len(),
            });
        }
        Ok(Self {
            content_id: ContentId::from_bytes(content_id_bytes),
            wire,
            kind,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.wire.encode_to_vec()
    }

    /// Return the protobuf frame length without allocating an encoded buffer.
    pub fn encoded_len(&self) -> usize {
        self.wire.encoded_len()
    }

    pub const fn content_id(&self) -> ContentId {
        self.content_id
    }

    pub const fn kind(&self) -> EnvelopeKind {
        self.kind
    }

    pub fn payload(&self) -> &[u8] {
        &self.wire.payload
    }

    pub const fn chain_id(&self) -> u32 {
        self.wire.chain_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> NetworkEnvelope {
        let payload = b"hello".to_vec();
        NetworkEnvelope::new(
            0x8000_0000,
            EnvelopeKind::HelloRequest,
            0,
            ContentId::from_domain_bytes(b"test", &payload),
            payload,
        )
    }

    #[test]
    fn envelope_round_trip() {
        let envelope = envelope();
        let encoded = envelope.encode();
        // Captured from the staged pre-cleanup prost encoder.
        let historical_vector = [
            0x08, 0x01, 0x10, 0x80, 0x80, 0x80, 0x80, 0x08, 0x18, 0x01, 0x2a, 0x20, 0xb5, 0x1d,
            0x1d, 0x86, 0x82, 0x3c, 0x2d, 0xc3, 0x6f, 0xf0, 0xb7, 0xa2, 0xac, 0xfd, 0x4d, 0x61,
            0x94, 0x9f, 0x80, 0x1e, 0x43, 0x9a, 0xbd, 0xf0, 0x0e, 0x06, 0x05, 0x2f, 0xc5, 0x59,
            0x7a, 0x4a, 0x30, 0x05, 0x3a, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
        ];
        assert_eq!(encoded, historical_vector);
        let decoded = NetworkEnvelope::decode(&historical_vector, EnvelopeLimits::HELLO).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.encode(), historical_vector);
    }

    #[test]
    fn rejects_inconsistent_encoded_length() {
        let mut wire = envelope().wire;
        wire.encoded_len += 1;
        assert_eq!(
            NetworkEnvelope::validate(wire, EnvelopeLimits::HELLO),
            Err(EnvelopeError::EncodedLengthMismatch {
                declared: 6,
                actual: 5,
            })
        );
    }

    #[test]
    fn rejects_oversized_payload_before_domain_decode() {
        let payload = vec![0; EnvelopeLimits::HELLO.max_payload_bytes + 1];
        let wire = Envelope {
            version: ProtocolVersion::V1.get(),
            chain_id: 1,
            kind: EnvelopeKind::HelloRequest as i32,
            flags: 0,
            content_id: [0; CONTENT_ID_LEN].to_vec(),
            encoded_len: payload.len() as u64,
            payload,
        };
        assert!(matches!(
            NetworkEnvelope::validate(wire, EnvelopeLimits::HELLO),
            Err(EnvelopeError::PayloadTooLarge { .. })
        ));
    }
}
