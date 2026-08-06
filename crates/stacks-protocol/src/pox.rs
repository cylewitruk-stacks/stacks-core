//! Proof-of-Transfer fork identifiers and their consensus derivation rules.

use std::fmt;
use std::fmt::Write as _;
use std::io::Write as _;
use std::str::FromStr;

use sha2::{Digest as _, Sha512_256};
use stacks_crypto::hash::{Sha512Trunc256Digest as _, Sha512Trunc256Sum};
use stacks_primitives::{BurnchainHeaderHash, SortitionId};

/// Identifies the presence or absence of anchor blocks across reward cycles.
#[derive(Clone, Debug, PartialEq)]
pub struct PoxId(Vec<bool>);

impl PoxId {
    pub fn new(contents: Vec<bool>) -> Self {
        Self(contents)
    }

    pub fn initial() -> Self {
        Self(vec![true])
    }

    pub fn from_bools(values: Vec<bool>) -> Self {
        Self(values)
    }

    pub fn extend_with_present_block(&mut self) {
        self.0.push(true);
    }

    pub fn extend_with_not_present_block(&mut self) {
        self.0.push(false);
    }

    pub fn stubbed() -> Self {
        Self(vec![])
    }

    pub fn has_ith_anchor_block(&self, index: usize) -> bool {
        self.0.get(index).copied().unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn bit_slice(&self, start: usize, length: usize) -> (Vec<u8>, u64) {
        let mut bytes = vec![0];
        let mut count = 0;
        for bit in start..start.saturating_add(length) {
            let Some(present) = self.0.get(bit) else {
                break;
            };
            let relative = bit - start;
            if relative > 0 && relative.is_multiple_of(8) {
                bytes.push(0);
            }
            if *present {
                let last = bytes.len() - 1;
                bytes[last] |= 1 << (relative % 8);
            }
            count += 1;
        }
        (bytes, count)
    }

    pub fn num_inventory_reward_cycles(&self) -> usize {
        self.0.len().saturating_sub(1)
    }

    pub fn has_prefix(&self, prefix: &Self) -> bool {
        self.0.starts_with(&prefix.0)
    }

    pub fn into_inner(self) -> Vec<bool> {
        self.0
    }
}

impl FromStr for PoxId {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .chars()
            .map(|character| match character {
                '0' => Ok(false),
                '1' => Ok(true),
                _ => Err("Unexpected character in PoX ID serialization"),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }
}

impl fmt::Display for PoxId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for present in &self.0 {
            formatter.write_char(if *present { '1' } else { '0' })?;
        }
        Ok(())
    }
}

/// Consensus derivation rules for sortition identifiers.
pub trait SortitionIdExt {
    fn stubbed(burn_header_hash: &BurnchainHeaderHash) -> Self;
    fn new(burn_header_hash: &BurnchainHeaderHash, pox_id: &PoxId) -> Self;
}

impl SortitionIdExt for SortitionId {
    fn stubbed(burn_header_hash: &BurnchainHeaderHash) -> Self {
        Self::new(burn_header_hash, &PoxId::stubbed())
    }

    fn new(burn_header_hash: &BurnchainHeaderHash, pox_id: &PoxId) -> Self {
        if pox_id.is_empty() {
            return SortitionId(burn_header_hash.0);
        }

        let mut hasher = Sha512_256::new();
        hasher.update(burn_header_hash.as_bytes());
        write!(hasher, "{pox_id}").expect("hash writers are infallible");
        SortitionId(Sha512Trunc256Sum::from_hasher(hasher).0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pox_id_text_round_trip_and_prefix() {
        let id: PoxId = "10110".parse().unwrap();
        assert_eq!(id.to_string(), "10110");
        assert!(id.has_prefix(&"101".parse().unwrap()));
        assert!(!id.has_prefix(&"111".parse().unwrap()));
    }

    #[test]
    fn stubbed_sortition_preserves_burn_hash() {
        let burn_hash = BurnchainHeaderHash([0x42; 32]);
        assert_eq!(SortitionId::stubbed(&burn_hash).0, burn_hash.0);
    }
}
