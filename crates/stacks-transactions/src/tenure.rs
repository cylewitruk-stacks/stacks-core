use core::fmt;

use serde::{Deserialize, Serialize};
use stacks_primitives::block::{ConsensusHash, StacksBlockId};
use stacks_primitives::hash::Hash160;
use variant_count::VariantCount;

/// Cause of change in mining tenure
/// Depending on cause, tenure can be ended or extended
/// NB: `PartialEq` is _not_ implemented for this enum in order to ensure that callers use the
/// instance methods to ascertain what kind of tenure change this is.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, VariantCount)]
pub enum TenureChangeCause {
    /// A valid winning block-commit
    BlockFound = 0,
    /// The next burnchain block is taking too long, so extend the runtime budget.
    /// This extends all dimensions
    Extended = 1,
    /// NEW in SIP-034: extend specific dimensions
    ExtendedRuntime = 2,
    ExtendedReadCount = 3,
    ExtendedReadLength = 4,
    ExtendedWriteCount = 5,
    ExtendedWriteLength = 6,
}

impl fmt::Display for TenureChangeCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            TenureChangeCause::BlockFound => "BlockFound",
            TenureChangeCause::Extended => "Extend",
            TenureChangeCause::ExtendedRuntime => "ExtendRuntime",
            TenureChangeCause::ExtendedReadCount => "ExtendReadCount",
            TenureChangeCause::ExtendedReadLength => "ExtendReadLength",
            TenureChangeCause::ExtendedWriteCount => "ExtendWriteCount",
            TenureChangeCause::ExtendedWriteLength => "ExtendWriteLength",
        };
        name.fmt(f)
    }
}

impl TryFrom<u8> for TenureChangeCause {
    type Error = ();

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(Self::BlockFound),
            1 => Ok(Self::Extended),
            2 => Ok(Self::ExtendedRuntime),
            3 => Ok(Self::ExtendedReadCount),
            4 => Ok(Self::ExtendedReadLength),
            5 => Ok(Self::ExtendedWriteCount),
            6 => Ok(Self::ExtendedWriteLength),
            _ => Err(()),
        }
    }
}

impl TenureChangeCause {
    pub const ALL: &'static [TenureChangeCause] = &[
        TenureChangeCause::BlockFound,
        TenureChangeCause::Extended,
        TenureChangeCause::ExtendedRuntime,
        TenureChangeCause::ExtendedReadCount,
        TenureChangeCause::ExtendedReadLength,
        TenureChangeCause::ExtendedWriteCount,
        TenureChangeCause::ExtendedWriteLength,
    ];

    /// Does this tenure change cause require a sortition to be valid?
    pub fn expects_sortition(&self) -> bool {
        match self {
            Self::BlockFound => true,
            Self::Extended => false,
            Self::ExtendedRuntime => false,
            Self::ExtendedReadCount => false,
            Self::ExtendedReadLength => false,
            Self::ExtendedWriteCount => false,
            Self::ExtendedWriteLength => false,
        }
    }

    /// Convert to u8 representation
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Does this tenure change cause represent the start of a new tenure?
    pub fn is_new_tenure(&self) -> bool {
        match self {
            Self::BlockFound => true,
            Self::Extended => false,
            Self::ExtendedRuntime => false,
            Self::ExtendedReadCount => false,
            Self::ExtendedReadLength => false,
            Self::ExtendedWriteCount => false,
            Self::ExtendedWriteLength => false,
        }
    }

    /// Explicit equality check, so as to avoid any accidental incomplete equality checks with the
    /// new SIP-034 tenure change cause variants
    pub fn is_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (TenureChangeCause::BlockFound, TenureChangeCause::BlockFound) => true,
            (TenureChangeCause::Extended, TenureChangeCause::Extended) => true,
            (TenureChangeCause::ExtendedRuntime, TenureChangeCause::ExtendedRuntime) => true,
            (TenureChangeCause::ExtendedReadCount, TenureChangeCause::ExtendedReadCount) => true,
            (TenureChangeCause::ExtendedReadLength, TenureChangeCause::ExtendedReadLength) => true,
            (TenureChangeCause::ExtendedWriteCount, TenureChangeCause::ExtendedWriteCount) => true,
            (TenureChangeCause::ExtendedWriteLength, TenureChangeCause::ExtendedWriteLength) => {
                true
            }
            (_, _) => false,
        }
    }

    pub fn is_full_extend(&self) -> bool {
        matches!(self, TenureChangeCause::Extended)
    }

    pub fn is_read_count_extend(&self) -> bool {
        matches!(self, TenureChangeCause::ExtendedReadCount)
    }

    pub fn is_extended(&self) -> bool {
        match self {
            TenureChangeCause::BlockFound => false,
            TenureChangeCause::Extended => true,
            TenureChangeCause::ExtendedRuntime => true,
            TenureChangeCause::ExtendedReadCount => true,
            TenureChangeCause::ExtendedReadLength => true,
            TenureChangeCause::ExtendedWriteCount => true,
            TenureChangeCause::ExtendedWriteLength => true,
        }
    }
}

const _: () = assert!(TenureChangeCause::ALL.len() == TenureChangeCause::VARIANT_COUNT);

/// Reasons why a `TenureChange` transaction can be bad
pub enum TenureChangeError {
    /// Not signed by required threshold (>70%)
    SignatureInvalid,
    /// `previous_tenure_end` does not match parent block
    PreviousTenureInvalid,
    /// Block is not a Nakamoto block
    NotNakamoto,
}

/// A transaction from Stackers to signal new mining tenure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenureChangePayload {
    /// Consensus hash of this tenure.  Corresponds to the sortition in which the miner of this
    /// block was chosen.  It may be the case that this miner's tenure gets _extended_ across
    /// subsequent sortitions; if this happens, then this `consensus_hash` value _remains the same_
    /// as the sortition in which the winning block-commit was mined.
    pub tenure_consensus_hash: ConsensusHash,
    /// Consensus hash of the previous tenure.  Corresponds to the sortition of the previous
    /// winning block-commit.
    pub prev_tenure_consensus_hash: ConsensusHash,
    /// Current consensus hash on the underlying burnchain.  Corresponds to the last-seen
    /// sortition.
    pub burn_view_consensus_hash: ConsensusHash,
    /// The StacksBlockId of the last block from the previous tenure
    pub previous_tenure_end: StacksBlockId,
    /// The number of blocks produced since the last sortition-linked tenure
    pub previous_tenure_blocks: u32,
    /// A flag to indicate the cause of this tenure change
    pub cause: TenureChangeCause,
    /// The ECDSA public key hash of the current tenure
    pub pubkey_hash: Hash160,
}

impl TenureChangePayload {
    pub fn extend(
        &self,
        burn_view_consensus_hash: ConsensusHash,
        last_tenure_block_id: StacksBlockId,
        num_blocks_so_far: u32,
    ) -> Self {
        TenureChangePayload {
            tenure_consensus_hash: self.tenure_consensus_hash.clone(),
            prev_tenure_consensus_hash: self.tenure_consensus_hash.clone(),
            burn_view_consensus_hash,
            previous_tenure_end: last_tenure_block_id,
            previous_tenure_blocks: num_blocks_so_far,
            cause: TenureChangeCause::Extended,
            pubkey_hash: self.pubkey_hash.clone(),
        }
    }

    pub fn extend_with_cause(
        &self,
        burn_view_consensus_hash: ConsensusHash,
        last_tenure_block_id: StacksBlockId,
        num_blocks_so_far: u32,
        cause: TenureChangeCause,
    ) -> Self {
        let mut ext = self.extend(
            burn_view_consensus_hash,
            last_tenure_block_id,
            num_blocks_so_far,
        );
        ext.cause = cause;
        ext
    }
}

/// NB This explicit implementation is needed because PartialEq is deliberately _not_ implemented
/// for TenureChangeCause
impl PartialEq for TenureChangePayload {
    fn eq(&self, other: &Self) -> bool {
        self.tenure_consensus_hash == other.tenure_consensus_hash
            && self.prev_tenure_consensus_hash == other.prev_tenure_consensus_hash
            && self.burn_view_consensus_hash == other.burn_view_consensus_hash
            && self.previous_tenure_end == other.previous_tenure_end
            && self.previous_tenure_blocks == other.previous_tenure_blocks
            && self.cause.is_eq(&other.cause)
            && self.pubkey_hash == other.pubkey_hash
    }
}
