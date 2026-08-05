// TODO: migrate callers to `stacks-codec` directly, then remove this bridge.
pub use stacks_codec::codec::*;

use crate::types::chainstate::SortitionId;

impl_byte_array_message_codec!(SortitionId, 32);
