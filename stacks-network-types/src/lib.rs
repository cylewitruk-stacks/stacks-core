//! Transport-neutral contracts for the Stacks libp2p network.
//!
//! This crate intentionally contains no runtime, sockets, libp2p behaviours, or
//! chainstate handles. Both the legacy adapter and the async network use these
//! types at their shared semantic boundary.

pub mod bridge;
pub mod capabilities;
pub mod directory;
pub mod legacy_identity;
pub mod limits;
pub mod proposal;
pub mod protocol;
pub mod role;
pub mod rollout;
pub mod semantic;
pub mod signer;
mod transcript;
pub mod unavailable;
pub mod value;

pub use bridge::{
    BridgeMode, SignerBridgeConfig, SignerBridgeConfigError, DEFAULT_BRIDGE_AUDIT_MAX_BYTES,
    DEFAULT_BRIDGE_QUEUE_MAX_BYTES, DEFAULT_BRIDGE_QUEUE_MAX_ITEMS,
};
pub use capabilities::{
    supports, CAP_CONTENT_PUSH, CAP_NODE_V1, CAP_OBJECT_FETCH, CAP_PROPOSAL_UNAVAILABLE,
    CAP_ROLE_DIRECTORY, CAP_SIGNER_SEMANTICS, CAP_SIGNER_V1, CAP_SYNC, CAP_TRANSACTION_GOSSIP,
};
pub use directory::{
    directory_record_digest, validate_directory_record_bounds, DirectoryRecordError,
    MAX_DIRECTORY_ADDRESSES, MAX_DIRECTORY_ADDRESS_BYTES, MAX_DIRECTORY_RECORD_BYTES,
};
pub use legacy_identity::{
    legacy_identity_binding_digest, validate_legacy_identity_binding_bounds,
    LegacyIdentityBindingError, LEGACY_IDENTITY_BINDING_VERSION,
};
pub use limits::{Libp2pLimits, Libp2pLimitsError};
pub use proposal::{
    proposal_content_id, validate_proposal_manifest, ProposalManifestError,
    MAX_PROPOSAL_OBJECT_BYTES, PROPOSAL_MANIFEST_VERSION,
};
pub use protocol::{
    ContentId, EnvelopeError, EnvelopeLimits, NetworkEnvelope, ProtocolVersion, CONTENT_ID_LEN,
};
pub use role::{
    role_proof_digest, role_proof_id, validate_role_proof_bounds, RoleProofError,
    ROLE_PROOF_VERSION,
};
pub use rollout::RolloutMode;
pub use semantic::{
    Announcement, IngressMeta, NetworkCommand, NetworkIngress, NetworkObject, NetworkPeerId,
    ObjectKind, PeerRef, SemanticError, TransportKind,
};
pub use signer::{
    signer_envelope_digest, signer_envelope_id, validate_signer_envelope_bounds,
    SignerEnvelopeError, MAX_SIGNER_ENVELOPE_BYTES, MAX_SIGNER_PAYLOAD_BYTES,
    SIGNER_ENVELOPE_VERSION,
};
pub use unavailable::{
    validate_proposal_unavailable, ProposalUnavailableError, PROPOSAL_UNAVAILABLE_VERSION,
};
pub use value::{NetworkScope, RewardCycleWindow, RewardCycleWindowError, SyncHorizons};

/// Prost-generated v1 wire types.
pub mod wire {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/stacks.network.v1.rs"));
    }
}
