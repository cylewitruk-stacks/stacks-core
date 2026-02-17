use blockstack_lib::chainstate::stacks::index::MARFValue;
use stacks_common::types::chainstate::StacksBlockId;

/// Build a deterministic [`StacksBlockId`] from a numeric seed.
///
/// The seed is encoded big-endian into the first four bytes; the
/// remaining 28 bytes are zero.  This is sufficient for benchmarks
/// where we only need distinct, reproducible block identifiers.
pub fn block_id(seed: u32) -> StacksBlockId {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&seed.to_be_bytes());
    StacksBlockId::from(bytes)
}

/// Generate a batch of `count` key / value pairs suitable for
/// [`MARF::insert_batch`] or similar helpers.
///
/// Keys follow the pattern `"{key_prefix}:{seed_start + i:08x}"`.
/// Values are `MARFValue::from(value_start + i + 1)`.
pub fn make_batch(
    key_prefix: &str,
    seed_start: u32,
    count: u32,
    value_start: u32,
) -> (Vec<String>, Vec<MARFValue>) {
    let mut keys = Vec::with_capacity(count as usize);
    let mut values = Vec::with_capacity(count as usize);

    for i in 0..count {
        keys.push(format!("{key_prefix}:{:08x}", seed_start + i));
        values.push(MARFValue::from(value_start + i + 1));
    }

    (keys, values)
}
