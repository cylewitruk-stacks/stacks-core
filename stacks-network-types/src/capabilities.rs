//! Public, non-role-bearing protocol capability bits carried in `Hello`.

pub const CAP_SIGNER_SEMANTICS: u64 = 1 << 0;
pub const CAP_OBJECT_FETCH: u64 = 1 << 1;
pub const CAP_CONTENT_PUSH: u64 = 1 << 2;
pub const CAP_TRANSACTION_GOSSIP: u64 = 1 << 3;
pub const CAP_SYNC: u64 = 1 << 4;
pub const CAP_ROLE_DIRECTORY: u64 = 1 << 5;
/// Supports the separately versioned, non-consensus proposal-unavailable lane.
pub const CAP_PROPOSAL_UNAVAILABLE: u64 = 1 << 6;

pub const CAP_NODE_V1: u64 = CAP_SIGNER_SEMANTICS
    | CAP_OBJECT_FETCH
    | CAP_CONTENT_PUSH
    | CAP_TRANSACTION_GOSSIP
    | CAP_SYNC
    | CAP_ROLE_DIRECTORY
    | CAP_PROPOSAL_UNAVAILABLE;

// Signer processes use typed signer messages, role-directory exchange, and
// bounded replay. This public bit does not disclose a private signer role.
pub const CAP_SIGNER_V1: u64 = CAP_SIGNER_SEMANTICS
    | CAP_ROLE_DIRECTORY
    | CAP_SYNC
    | CAP_OBJECT_FETCH
    | CAP_PROPOSAL_UNAVAILABLE;

pub const fn supports(capabilities: u64, required: u64) -> bool {
    capabilities & required == required
}
