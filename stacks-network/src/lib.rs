//! Secure libp2p transport and semantic network hub for Stacks.

#[macro_use]
mod request_response_forwarding;

pub mod admission;
pub mod application;
pub mod authorization;
pub mod behaviour;
pub mod budget;
pub mod codec;
pub mod content_behaviour;
mod diagnostics;
pub mod directory;
pub mod directory_protocol;
pub mod discovery;
pub mod endpoint;
pub mod hello;
pub mod hub;
pub mod identity;
pub mod legacy_identity;
pub mod mailbox;
pub mod object_protocol;
pub mod observability;
mod outer_envelope;
pub mod peer_store;
pub mod provider;
pub mod role;
pub mod role_directory_behaviour;
pub mod service;
pub mod signer;
pub mod signer_behaviour;
pub mod swarm;
pub mod sync_behaviour;
pub mod sync_protocol;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod transport;

pub use admission::{
    AdmissionConfig, AdmissionDenied, AdmissionEvent, AdmissionPhase, ConnectionAdmissionBehaviour,
    NetworkPrefix,
};
pub use application::{
    ApplicationGateError, ApplicationProtocol, AuthenticatedGossip, AuthenticatedGossipMessage,
    GossipRejectionReason, GossipTopicClass, GossipValidationToken, HandshakeGate,
    HelloRejectionReason, StacksApplicationBehaviour, StacksApplicationEvent,
};
pub use authorization::{
    AuthorizationIdentity, AuthorizationSnapshot, AuthorizationSnapshotError,
    AuthorizationSnapshotState, AuthorizationSnapshotUpdate,
};
pub use behaviour::{
    block_announcement_topic, signer_topic, transaction_topic, ConnectionPolicy, ContentPolicy,
    DiscoveryPolicy, NetworkConfig, ResourcePolicy, StacksBehaviour, StacksBehaviourEvent,
    CONTENT_PROTOCOL, CONTENT_PUSH_PROTOCOL, ROLE_DIRECTORY_PROTOCOL, SIGNER_DIRECT_PROTOCOL,
    SYNC_PROTOCOL,
};
pub use budget::{BudgetRejection, PeerResourceBudget};
pub use codec::BoundedEnvelopeCodec;
pub use content_behaviour::{
    ContentExchangeBehaviour, ContentExchangeEvent, ContentProtocolKind, ContentPublication,
    DirectPushCandidate, ObjectNetworkEvent, ProviderFailure, PublicationOutcome,
    DOWNSTREAM_EVENT_QUEUE_CAPACITY,
};
pub use diagnostics::{DiagnosticEvent, NetworkDiagnostics, SignerObservation};
pub use directory::{
    signed_role_directory_record, verify_directory_record, AuthorizedRoleKey, DirectoryError,
    DirectoryView, RoleAuthorization, RoleAuthorizations, RoleDirectory, VerifiedDirectoryRecord,
    MAX_DIRECTORY_QUERY_RECORDS, MAX_DIRECTORY_RECORDS,
};
pub use directory_protocol::{
    decode_directory_query, decode_directory_response, directory_query_envelope,
    directory_response_envelope,
};
pub use discovery::{DiscoveryEvent, StacksDiscoveryBehaviour};
pub use endpoint::{PeerEndpoint, PeerEndpointError};
pub use hello::{
    hello_envelope, hello_response_envelope, hello_status_response_envelope, validate_hello,
    validate_hello_response, HelloError,
};
pub use hub::{
    announcement_id, NetworkHub, NetworkObjectValidator, ObjectAdmission,
    DEFAULT_OBJECT_CACHE_BYTES, MAX_PROVIDERS_PER_OBJECT,
};
pub use identity::{node_identity_from_seed, signer_identity_from_secret};
pub use legacy_identity::{
    verify_legacy_identity_binding, LegacyIdentityRegistry, LegacyIdentityValidationError,
    VerifiedLegacyIdentityBinding,
};
pub use object_protocol::{
    announcement_envelope, content_push_ack_envelope, content_push_envelope,
    content_request_envelope, content_response_envelope, decode_announcement, decode_content_push,
    decode_content_push_ack, decode_content_request, decode_content_response,
};
pub use observability::{dropped_span_totals, install_tracing, ObservabilityGuard};
pub use peer_store::{
    PeerStoreCandidate, PeerStoreConfig, PeerStorePolicy, PeerStoreRuntime,
    PeerStoreRuntimeSnapshot, PeerStoreStartup, SqlitePeerStore,
};
pub use provider::{adaptive_sync_concurrency, ProviderOutcome, ProviderPool};
pub use role::{
    verify_role_proof, RoleAuthorizer, RoleValidationError, RoleVerificationContext,
    VerifiedRoleProof,
};
pub use role_directory_behaviour::{
    DirectoryDirection, RoleDirectoryBehaviour, RoleDirectoryBehaviourEvent,
};
pub use service::{
    AuthorizationBootstrap, ContentServices, NetworkHandle, NetworkService, ServiceConfig,
    SignerCanonicalAuthorization, SignerNetworkEvent, SyncNetworkEvent, TransportBootstrap,
};
pub use signer::{
    verify_signer_envelope, verify_signer_envelope_authorship, MemorySignerJournal,
    SignerAdmission, SignerAuthorizationState, SignerBindingUpdate, SignerEnvelopeVerifier,
    SignerValidationError, VerifiedSignerEnvelope,
};
pub use signer_behaviour::{
    DeferredMinerAuthorizationSnapshot, SignerBehaviour, SignerBehaviourEvent, SignerIngress,
    StagedSignerEnvelope,
};
pub use swarm::{build_swarm, TransportProfile};
pub use sync_behaviour::{SyncBehaviour, SyncBehaviourEvent, SyncRequestOwner};
pub use sync_protocol::{
    bounded_inventory_range, decode_sync_request, decode_sync_response, sync_request_envelope,
    sync_response_envelope, validate_sync_request, validate_sync_response, MAX_SIGNER_REPLAY_BYTES,
    MAX_SIGNER_REPLAY_ITEMS, MAX_SYNC_CURSOR_BYTES, MAX_SYNC_EPOCH2_HEIGHTS, MAX_SYNC_ID_BYTES,
    MAX_SYNC_INVENTORY_ITEMS, MAX_SYNC_MEMPOOL_ITEMS, MAX_SYNC_REQUESTED_BYTES,
};
#[cfg(any(test, feature = "test-support"))]
pub use test_support::{Libp2pTestNetwork, TestNetworkPeer};
pub use transport::{memory_transport, tcp_transport, StacksTransport};
