//! Shared outer-envelope binding for typed application protocols.

use stacks_network_types::wire::v1::EnvelopeKind;
use stacks_network_types::{ContentId, NetworkEnvelope};

/// A deliberately narrow codec for one chain, envelope kind, and content-ID
/// domain. Payload protobuf validation stays in the owning protocol module.
#[derive(Clone, Copy)]
pub struct ScopedEnvelopeCodec {
    chain_id: u32,
    kind: EnvelopeKind,
    domain: &'static [u8],
    protocol: &'static str,
}

impl ScopedEnvelopeCodec {
    pub const fn new(
        chain_id: u32,
        kind: EnvelopeKind,
        domain: &'static [u8],
        protocol: &'static str,
    ) -> Self {
        Self {
            chain_id,
            kind,
            domain,
            protocol,
        }
    }

    pub fn wrap(self, payload: Vec<u8>) -> NetworkEnvelope {
        NetworkEnvelope::new(
            self.chain_id,
            self.kind,
            0,
            ContentId::from_domain_bytes(self.domain, &payload),
            payload,
        )
    }

    pub fn validate(self, envelope: &NetworkEnvelope) -> Result<(), String> {
        if envelope.chain_id() != self.chain_id || envelope.kind() != self.kind {
            return Err(format!(
                "{} envelope has wrong chain or kind",
                self.protocol
            ));
        }
        if envelope.content_id() != ContentId::from_domain_bytes(self.domain, envelope.payload()) {
            return Err(format!("{} envelope content ID mismatch", self.protocol));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_kind_and_domain_are_independently_bound() {
        let payload = b"payload".to_vec();
        let first = ScopedEnvelopeCodec::new(7, EnvelopeKind::SyncRequest, b"domain-a", "a");
        let encoded = first.wrap(payload.clone());
        assert!(first.validate(&encoded).is_ok());
        assert!(
            ScopedEnvelopeCodec::new(8, EnvelopeKind::SyncRequest, b"domain-a", "a")
                .validate(&encoded)
                .is_err()
        );
        assert!(
            ScopedEnvelopeCodec::new(7, EnvelopeKind::SyncResponse, b"domain-a", "a")
                .validate(&encoded)
                .is_err()
        );
        assert!(
            ScopedEnvelopeCodec::new(7, EnvelopeKind::SyncRequest, b"domain-b", "b")
                .validate(&encoded)
                .is_err()
        );
    }
}
