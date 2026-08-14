use serde::Deserialize;

use crate::transcript::CanonicalTranscript;
use crate::wire::v1::SignerLane;
use crate::ContentId;

pub const DEFAULT_BRIDGE_AUDIT_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_BRIDGE_QUEUE_MAX_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_BRIDGE_QUEUE_MAX_ITEMS: usize = 1024;
const LEGACY_CHUNK_ID_DOMAIN: &[u8] = b"STACKS_SIGNER_BRIDGE_CHUNK_V1";
const SEMANTIC_MESSAGE_ID_DOMAIN: &[u8] = b"STACKS_SIGNER_SEMANTIC_MESSAGE_V1";

/// Canonical compatibility ID for one signed legacy StackerDB chunk.
pub fn legacy_chunk_content_id(
    contract: &str,
    reward_cycle: u64,
    signed_chunk: &[u8],
) -> ContentId {
    let mut transcript =
        CanonicalTranscript::with_capacity(contract.len() + signed_chunk.len() + 24);
    transcript
        .bytes(contract.as_bytes())
        .u64(reward_cycle)
        .bytes(signed_chunk);
    ContentId::from_domain_bytes(LEGACY_CHUNK_ID_DOMAIN, &transcript.into_bytes())
}

/// Canonical compatibility ID for one decoded semantic signer message.
pub fn semantic_signer_message_content_id(
    reward_cycle: u64,
    lane: SignerLane,
    author: &[u8],
    payload: &[u8],
) -> ContentId {
    let mut transcript = CanonicalTranscript::with_capacity(author.len() + payload.len() + 24);
    transcript
        .u64(reward_cycle)
        .i32(lane as i32)
        .bytes(author)
        .bytes(payload);
    ContentId::from_domain_bytes(SEMANTIC_MESSAGE_ID_DOMAIN, &transcript.into_bytes())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum BridgeMode {
    Off,
    Observe,
    IngressOnly,
    Bidirectional,
}

impl BridgeMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Observe => "observe",
            Self::IngressOnly => "ingress-only",
            Self::Bidirectional => "bidirectional",
        }
    }

    pub const fn accepts_ingress(self) -> bool {
        matches!(
            self,
            Self::Observe | Self::IngressOnly | Self::Bidirectional
        )
    }

    pub const fn emits_events(self) -> bool {
        matches!(self, Self::IngressOnly | Self::Bidirectional)
    }

    pub const fn writes_legacy(self) -> bool {
        matches!(self, Self::Bidirectional)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SignerBridgeConfig {
    pub mode: BridgeMode,
    pub audit_journal_max_bytes: u64,
    pub audit_retention_cycles: u64,
    pub queue_max_items: usize,
    pub queue_max_bytes: usize,
}

impl Default for SignerBridgeConfig {
    fn default() -> Self {
        Self {
            mode: BridgeMode::Bidirectional,
            audit_journal_max_bytes: DEFAULT_BRIDGE_AUDIT_MAX_BYTES,
            audit_retention_cycles: 2,
            queue_max_items: DEFAULT_BRIDGE_QUEUE_MAX_ITEMS,
            queue_max_bytes: DEFAULT_BRIDGE_QUEUE_MAX_BYTES,
        }
    }
}

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum SignerBridgeConfigError {
    #[error("bridge audit journal must have a nonzero bounded size")]
    AuditSize,
    #[error("bridge retention must cover the current/next overlap and remain bounded")]
    Retention,
    #[error("bridge queue item and byte limits must be nonzero and internally consistent")]
    Queue,
}

impl SignerBridgeConfig {
    pub fn validate(&self) -> Result<(), SignerBridgeConfigError> {
        if self.audit_journal_max_bytes == 0 || self.audit_journal_max_bytes > 1024 * 1024 * 1024 {
            return Err(SignerBridgeConfigError::AuditSize);
        }
        if !(2..=4).contains(&self.audit_retention_cycles) {
            return Err(SignerBridgeConfigError::Retention);
        }
        if self.queue_max_items == 0
            || self.queue_max_items > 65_536
            || self.queue_max_bytes == 0
            || self.queue_max_bytes > self.audit_journal_max_bytes as usize
        {
            return Err(SignerBridgeConfigError::Queue);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_bidirectional_and_bounded() {
        let config = SignerBridgeConfig::default();
        assert_eq!(config.mode, BridgeMode::Bidirectional);
        assert_eq!(config.mode.as_str(), "bidirectional");
        config.validate().unwrap();
        assert!(config.queue_max_bytes < config.audit_journal_max_bytes as usize);
    }

    #[test]
    fn bridge_content_ids_are_domain_separated_and_stable() {
        let chunk = legacy_chunk_content_id("signers-v1", 9, b"signed");
        let semantic =
            semantic_signer_message_content_id(9, SignerLane::BlockResponse, b"author", b"signed");
        assert_ne!(chunk, semantic);
        assert_eq!(
            chunk.to_string(),
            "21cbe8c95f62dfb3ed130b354c9314c79d702c5ed67def77b7bb1ab8ff0d9015"
        );
        assert_eq!(
            semantic.to_string(),
            "234c8ce5f8d00aa7dfd95606f86bb8cb199b36a82dccb9e379190716ee13ac7b"
        );
    }
}
