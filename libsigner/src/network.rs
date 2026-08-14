//! Transport-neutral signer-network boundary.

use stacks_network_types::wire::v1::{SignerEnvelope, SignerLane};
use stacks_network_types::ContentId;

/// A semantic signer message before transport authentication is attached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerNetworkMessage {
    /// Reward cycle whose authorization and routing apply.
    pub reward_cycle: u64,
    /// Semantic lane; the payload codec must agree with this value.
    pub lane: SignerLane,
    /// Current burn view, empty only for non-consensus control messages.
    pub burn_view_consensus_hash: Vec<u8>,
    /// Existing consensus-encoded `SignerMessage` bytes.
    pub payload: Vec<u8>,
}

/// The authenticated source path retained for deduplication and diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerIngressOrigin {
    /// End-to-end signed native libp2p envelope.
    Libp2p,
    /// Locally verified legacy compatibility ingress.
    LegacyCompatibility,
    /// Locally authored event.
    Local,
}

/// A signer event after transport authentication and per-author admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSignerEvent {
    /// Transport-neutral semantic message consumed by signer policy.
    pub message: SignerNetworkMessage,
    /// End-to-end evidence for how the author was authenticated.
    pub authentication: SignerEventAuthentication,
    /// Authenticated ingress path.
    pub origin: SignerIngressOrigin,
    /// Whether a different envelope was already retained at this sequence.
    pub is_equivocation: bool,
}

/// Authentication evidence is explicit so the legacy bridge never fabricates
/// a native outer signature on behalf of a StackerDB author.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerEventAuthentication {
    /// Original author-signed native envelope, suitable for replay/evidence.
    Native {
        /// Complete native envelope signed by its Stacks author.
        envelope: Box<SignerEnvelope>,
        /// Canonical identity of the complete native envelope.
        envelope_id: ContentId,
    },
    /// Locally verified legacy chunk. Generic signer code sees only opaque
    /// evidence bytes; contract/slot/session details stay in the bridge crate.
    LegacyCompatibility {
        /// Consensus encoding of the original signed legacy chunk.
        signed_chunk: Vec<u8>,
        /// Canonical identity of the signed chunk and verified locator.
        chunk_id: ContentId,
        /// Compressed Stacks key recovered from the verified chunk signature.
        author_public_key: Vec<u8>,
        /// Independent legacy slot version used for ordering and audit.
        slot_version: u32,
    },
}

impl AuthenticatedSignerEvent {
    /// Return the native envelope ID or legacy signed-chunk ID.
    pub fn event_id(&self) -> ContentId {
        match &self.authentication {
            SignerEventAuthentication::Native { envelope_id, .. } => *envelope_id,
            SignerEventAuthentication::LegacyCompatibility { chunk_id, .. } => *chunk_id,
        }
    }

    /// Borrow native evidence, or `None` for a compatibility event.
    pub fn native_envelope(&self) -> Option<&SignerEnvelope> {
        match &self.authentication {
            SignerEventAuthentication::Native { envelope, .. } => Some(envelope.as_ref()),
            SignerEventAuthentication::LegacyCompatibility { .. } => None,
        }
    }

    /// Borrow the verified original Stacks author key from either transport.
    pub fn author_public_key(&self) -> Option<&[u8]> {
        match &self.authentication {
            SignerEventAuthentication::Native { envelope, .. } => envelope
                .body
                .as_ref()
                .map(|body| body.signer_public_key.as_slice()),
            SignerEventAuthentication::LegacyCompatibility {
                author_public_key, ..
            } => Some(author_public_key),
        }
    }
}

/// Per-lane replay cursor. The next response starts strictly after `sequence`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayCursor {
    /// Lane to replay.
    pub lane: SignerLane,
    /// Last sequence already held by the requester.
    pub sequence: u64,
}

/// Bounded replay request for current or next-cycle signer data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayRequest {
    /// Requested reward cycle.
    pub reward_cycle: u64,
    /// Independent per-lane cursors.
    pub cursors: Vec<ReplayCursor>,
    /// Maximum returned items.
    pub max_items: usize,
    /// Maximum sum of consensus payload bytes.
    pub max_bytes: usize,
}

/// Explicit native/compatibility publication admission result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishReceipt {
    /// Identity assigned to the author-signed envelope.
    pub envelope_id: ContentId,
    /// Native path accepted the publication into a bounded queue.
    pub native_queued: bool,
    /// Compatibility path accepted the publication, when installed.
    pub compatibility_queued: bool,
}

/// Transport and bounded-admission failures surfaced to signer policy.
#[derive(Debug, thiserror::Error)]
pub enum SignerNetworkError {
    /// Application publication is disabled by the staged rollout policy.
    #[error("signer network application data is disabled")]
    Disabled,
    /// A bounded queue has no reserved capacity for this message.
    #[error("signer network is busy")]
    Busy,
    /// The selected cycle is outside current/next authorization.
    #[error("reward cycle {0} is not active")]
    InactiveCycle(u64),
    /// The message cannot be encoded, signed, or validated.
    #[error("invalid signer message: {0}")]
    InvalidMessage(String),
    /// The underlying network has stopped.
    #[error("signer network stopped")]
    Stopped,
    /// A non-admission transport operation failed.
    #[error("signer network transport failure: {0}")]
    Transport(String),
}

/// The signer state machine's only dependency on signer-to-signer/miner transport.
/// Native implementations and the temporary compatibility composition implement
/// this interface; StackerDB contracts, slots, chunks, and sessions do not cross it.
pub trait SignerNetwork: Send {
    /// Sign and enqueue a locally authored semantic message.
    fn publish(
        &mut self,
        message: SignerNetworkMessage,
    ) -> Result<PublishReceipt, SignerNetworkError>;

    /// Poll one authenticated event without blocking signer policy.
    fn try_next_event(&mut self) -> Result<Option<AuthenticatedSignerEvent>, SignerNetworkError>;

    /// Return bounded original author-signed replay data.
    fn replay(
        &mut self,
        request: ReplayRequest,
    ) -> Result<Vec<AuthenticatedSignerEvent>, SignerNetworkError>;

    /// Atomically change current/next-cycle admission and subscription policy.
    fn update_cycles(&mut self, current: u64, next: Option<u64>) -> Result<(), SignerNetworkError>;
}
