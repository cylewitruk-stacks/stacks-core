use serde::{Deserialize, Serialize};

use crate::wire::v1::ObjectType;
use crate::ContentId;

/// Maximum encoded transport-neutral peer identity retained in provenance.
pub const MAX_NETWORK_PEER_ID_BYTES: usize = 128;
/// Maximum untrusted relay path retained as diagnostic/loop-suppression evidence.
pub const MAX_RELAY_PATH_LEN: usize = 16;

/// The adapter through which semantic data entered or will leave the hub.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum TransportKind {
    /// Native libp2p transport.
    Libp2p,
    /// Incumbent Stacks P2P transport.
    Legacy,
    /// Authenticated HTTP upload, used only by the temporary compatibility bridge.
    HttpUpload,
    /// Locally produced data.
    Local,
}

/// A bounded opaque peer identity. Interpretation belongs to its transport adapter.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct NetworkPeerId(Vec<u8>);

impl NetworkPeerId {
    /// Construct a bounded peer identity.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SemanticError> {
        if bytes.is_empty() || bytes.len() > MAX_NETWORK_PEER_ID_BYTES {
            return Err(SemanticError::InvalidPeerIdLength(bytes.len()));
        }
        Ok(Self(bytes))
    }

    /// Return the transport-owned bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A transport-scoped connection source.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct PeerRef {
    pub transport: TransportKind,
    pub peer_id: NetworkPeerId,
    /// Adapter-local connection generation; never used as global identity.
    pub connection_id: u64,
}

/// Provenance retained across semantic validation and transport bridging.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IngressMeta {
    pub source: PeerRef,
    pub received_unix_ms: u64,
    pub wire_bytes: u64,
    pub message_id: ContentId,
    pub relay_path: Vec<NetworkPeerId>,
}

impl IngressMeta {
    /// Reject unbounded provenance before it reaches the hub.
    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.relay_path.len() > MAX_RELAY_PATH_LEN {
            return Err(SemanticError::RelayPathTooLong(self.relay_path.len()));
        }
        Ok(())
    }
}

/// Content classes routed by the shared semantic hub.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ObjectKind {
    Transaction,
    NakamotoBlock,
    AnchoredBlock,
    Microblock,
    Attachment,
    BlockProposal,
}

impl From<ObjectKind> for ObjectType {
    fn from(kind: ObjectKind) -> Self {
        match kind {
            ObjectKind::Transaction => Self::Transaction,
            ObjectKind::NakamotoBlock => Self::NakamotoBlock,
            ObjectKind::AnchoredBlock => Self::AnchoredBlock,
            ObjectKind::Microblock => Self::Microblock,
            ObjectKind::Attachment => Self::Attachment,
            ObjectKind::BlockProposal => Self::BlockProposal,
        }
    }
}

impl TryFrom<ObjectType> for ObjectKind {
    type Error = SemanticError;

    fn try_from(kind: ObjectType) -> Result<Self, Self::Error> {
        match kind {
            ObjectType::Transaction => Ok(Self::Transaction),
            ObjectType::NakamotoBlock => Ok(Self::NakamotoBlock),
            ObjectType::AnchoredBlock => Ok(Self::AnchoredBlock),
            ObjectType::Microblock => Ok(Self::Microblock),
            ObjectType::Attachment => Ok(Self::Attachment),
            ObjectType::BlockProposal => Ok(Self::BlockProposal),
            ObjectType::Unspecified => Err(SemanticError::InvalidObjectKind),
        }
    }
}

/// Bytes whose content ID has been computed by the domain adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkObject {
    pub kind: ObjectKind,
    pub content_id: ContentId,
    pub bytes: Vec<u8>,
}

/// A compact availability signal. Kind-specific canonical metadata remains in `bytes`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Announcement {
    pub kind: ObjectKind,
    pub content_id: ContentId,
    pub canonical_metadata: Vec<u8>,
}

/// Semantic ingress shared by legacy and native transports.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NetworkIngress {
    Announcement(Announcement, IngressMeta),
    Object(NetworkObject, IngressMeta),
    Signer {
        envelope_id: ContentId,
        encoded_envelope: Vec<u8>,
        meta: IngressMeta,
    },
}

/// Transport-neutral publication requests emitted only after domain acceptance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NetworkCommand {
    Publish(NetworkObject),
    Announce(Announcement),
    Disconnect { peer: PeerRef, reason: String },
}

/// Validation failures for transport-neutral contracts.
#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum SemanticError {
    #[error("peer identity length must be in 1..={MAX_NETWORK_PEER_ID_BYTES}, got {0}")]
    InvalidPeerIdLength(usize),
    #[error("relay path exceeds {MAX_RELAY_PATH_LEN} entries, got {0}")]
    RelayPathTooLong(usize),
    #[error("object kind is unspecified")]
    InvalidObjectKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_is_bounded() {
        assert!(NetworkPeerId::new(Vec::new()).is_err());
        assert!(NetworkPeerId::new(vec![0; MAX_NETWORK_PEER_ID_BYTES + 1]).is_err());
        let peer = NetworkPeerId::new(vec![1; 32]).unwrap();
        let meta = IngressMeta {
            source: PeerRef {
                transport: TransportKind::Libp2p,
                peer_id: peer.clone(),
                connection_id: 1,
            },
            received_unix_ms: 0,
            wire_bytes: 1,
            message_id: ContentId::from_bytes([0; 32]),
            relay_path: vec![peer; MAX_RELAY_PATH_LEN + 1],
        };
        assert_eq!(
            meta.validate(),
            Err(SemanticError::RelayPathTooLong(MAX_RELAY_PATH_LEN + 1))
        );
    }

    #[test]
    fn object_kind_wire_conversion_is_total_except_unspecified() {
        for kind in [
            ObjectKind::Transaction,
            ObjectKind::NakamotoBlock,
            ObjectKind::AnchoredBlock,
            ObjectKind::Microblock,
            ObjectKind::Attachment,
            ObjectKind::BlockProposal,
        ] {
            assert_eq!(ObjectKind::try_from(ObjectType::from(kind)), Ok(kind));
        }
        assert_eq!(
            ObjectKind::try_from(ObjectType::Unspecified),
            Err(SemanticError::InvalidObjectKind)
        );
    }
}
