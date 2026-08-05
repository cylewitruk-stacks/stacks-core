use core::cmp::Ordering;
use core::ops::{Deref, DerefMut, Index, IndexMut};

use serde::Deserialize;
use stacks_primitives::StacksEpochId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct StacksEpoch<L> {
    pub epoch_id: StacksEpochId,
    pub start_height: u64,
    pub end_height: u64,
    pub block_limit: L,
    pub network_epoch: u8,
}

impl<L> StacksEpoch<L> {
    pub fn find_epoch(epochs: &[StacksEpoch<L>], height: u64) -> Option<usize> {
        for (i, epoch) in epochs.iter().enumerate() {
            if epoch.start_height <= height && height < epoch.end_height {
                return Some(i);
            }
        }
        None
    }

    pub fn find_epoch_by_id(epochs: &[StacksEpoch<L>], epoch_id: StacksEpochId) -> Option<usize> {
        for (i, epoch) in epochs.iter().enumerate() {
            if epoch.epoch_id == epoch_id {
                return Some(i);
            }
        }
        None
    }
}

impl<L: PartialEq> PartialOrd for StacksEpoch<L> {
    fn partial_cmp(&self, other: &StacksEpoch<L>) -> Option<Ordering> {
        self.epoch_id.partial_cmp(&other.epoch_id)
    }
}

impl<L: PartialEq + Eq> Ord for StacksEpoch<L> {
    fn cmp(&self, other: &StacksEpoch<L>) -> Ordering {
        self.epoch_id.cmp(&other.epoch_id)
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct EpochList<L: Clone>(Vec<StacksEpoch<L>>);

impl<L: Clone> From<Vec<StacksEpoch<L>>> for EpochList<L> {
    fn from(value: Vec<StacksEpoch<L>>) -> Self {
        Self(value)
    }
}

impl<L: Clone> EpochList<L> {
    pub fn new(epochs: &[StacksEpoch<L>]) -> EpochList<L> {
        EpochList(epochs.to_vec())
    }

    pub fn get(&self, index: StacksEpochId) -> Option<&StacksEpoch<L>> {
        self.0.get(StacksEpoch::find_epoch_by_id(&self.0, index)?)
    }

    pub fn get_mut(&mut self, index: StacksEpochId) -> Option<&mut StacksEpoch<L>> {
        let index = StacksEpoch::find_epoch_by_id(&self.0, index)?;
        self.0.get_mut(index)
    }

    pub fn truncate_after(&mut self, epoch_id: StacksEpochId) {
        if let Some(index) = StacksEpoch::find_epoch_by_id(&self.0, epoch_id) {
            self.0.truncate(index + 1);
        }
    }

    pub fn epoch_id_at_height(&self, height: u64) -> Option<StacksEpochId> {
        StacksEpoch::find_epoch(self, height).map(|idx| self.0[idx].epoch_id)
    }

    pub fn epoch_at_height(&self, height: u64) -> Option<StacksEpoch<L>> {
        StacksEpoch::find_epoch(self, height).map(|idx| self.0[idx].clone())
    }

    pub fn push(&mut self, epoch: StacksEpoch<L>) {
        if let Some(last) = self.0.last() {
            assert!(
                epoch.start_height == last.end_height && epoch.epoch_id > last.epoch_id,
                "Epochs must be pushed in order"
            );
        }
        self.0.push(epoch);
    }

    pub fn to_vec(self) -> Vec<StacksEpoch<L>> {
        self.0
    }
}

impl<L: Clone> Index<StacksEpochId> for EpochList<L> {
    type Output = StacksEpoch<L>;

    fn index(&self, index: StacksEpochId) -> &StacksEpoch<L> {
        self.get(index)
            .expect("Invalid StacksEpochId: could not find corresponding epoch")
    }
}

impl<L: Clone> IndexMut<StacksEpochId> for EpochList<L> {
    fn index_mut(&mut self, index: StacksEpochId) -> &mut StacksEpoch<L> {
        self.get_mut(index)
            .expect("Invalid StacksEpochId: could not find corresponding epoch")
    }
}

impl<L: Clone> Deref for EpochList<L> {
    type Target = [StacksEpoch<L>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<L: Clone> DerefMut for EpochList<L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
