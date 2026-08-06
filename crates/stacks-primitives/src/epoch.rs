#[cfg(any(test, feature = "testing"))]
use core::ops::{Bound, RangeBounds};
use core::str::FromStr;

use serde::{Deserialize, Serialize};

macro_rules! define_stacks_epochs {
    ($($variant:ident = $value:expr),* $(,)?) => {
        #[repr(u32)]
        #[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum StacksEpochId {
            $($variant = $value),*
        }

        impl StacksEpochId {
            pub const ALL: &'static [StacksEpochId] = &[
                $(StacksEpochId::$variant),*
            ];
        }
    };
}

define_stacks_epochs! {
    Epoch10 = 0x01000,
    Epoch20 = 0x02000,
    Epoch2_05 = 0x02005,
    Epoch21 = 0x0200a,
    Epoch22 = 0x0200f,
    Epoch23 = 0x02014,
    Epoch24 = 0x02019,
    Epoch25 = 0x0201a,
    Epoch30 = 0x03000,
    Epoch31 = 0x03001,
    Epoch32 = 0x03002,
    Epoch33 = 0x03003,
    Epoch34 = 0x03004,
    Epoch40 = 0x04000,
    Epoch41 = 0x04001,
}

impl StacksEpochId {
    /// Highest epoch enabled in release builds.
    /// Keep this in sync with `versions.toml` and `PEER_NETWORK_EPOCH`.
    pub const RELEASE_LATEST_EPOCH: StacksEpochId = StacksEpochId::Epoch40;

    #[cfg(any(test, feature = "testing"))]
    pub const fn latest() -> StacksEpochId {
        StacksEpochId::Epoch41
    }

    #[cfg(not(any(test, feature = "testing")))]
    pub const fn latest() -> StacksEpochId {
        StacksEpochId::RELEASE_LATEST_EPOCH
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn since(epoch: StacksEpochId) -> &'static [StacksEpochId] {
        let idx = Self::ALL
            .iter()
            .position(|&e| e == epoch)
            .expect("epoch not found in ALL");

        &Self::ALL[idx..]
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn between(start: StacksEpochId, end: StacksEpochId) -> &'static [StacksEpochId] {
        let start_idx = Self::ALL
            .iter()
            .position(|&e| e == start)
            .expect("start epoch not found in ALL");
        let end_idx = Self::ALL
            .iter()
            .position(|&e| e == end)
            .expect("end epoch not found in ALL");
        assert!(start_idx <= end_idx, "start epoch must be <= end epoch");

        &Self::ALL[start_idx..=end_idx]
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn index_of(epoch: Self) -> usize {
        Self::ALL
            .iter()
            .position(|&candidate| candidate == epoch)
            .expect("epoch not found in ALL")
    }

    /// Returns all defined epochs after `epoch`, excluding `epoch` itself.
    #[cfg(any(test, feature = "testing"))]
    pub fn all_after(epoch: Self) -> &'static [Self] {
        (Bound::Excluded(epoch), Bound::Unbounded).as_slice()
    }

    #[cfg(any(test, feature = "testing"))]
    pub const fn first() -> Self {
        Self::ALL[0]
    }

    #[cfg(any(test, feature = "testing"))]
    pub const fn last() -> Self {
        Self::ALL[Self::ALL.len() - 1]
    }
}

/// Test-only iteration helpers for standard Rust ranges of Stacks epochs.
#[cfg(any(test, feature = "testing"))]
pub trait StacksEpochRangeTestExt: RangeBounds<StacksEpochId> + Sized {
    fn iter(&self) -> core::slice::Iter<'static, StacksEpochId> {
        self.as_slice().iter()
    }

    fn as_slice(&self) -> &'static [StacksEpochId] {
        let start = match self.start_bound() {
            Bound::Included(epoch) => StacksEpochId::index_of(*epoch),
            Bound::Excluded(epoch) => StacksEpochId::index_of(*epoch) + 1,
            Bound::Unbounded => 0,
        };
        let end = match self.end_bound() {
            Bound::Included(epoch) => StacksEpochId::index_of(*epoch) + 1,
            Bound::Excluded(epoch) => StacksEpochId::index_of(*epoch),
            Bound::Unbounded => StacksEpochId::ALL.len(),
        };

        &StacksEpochId::ALL[start..end.max(start)]
    }
}

#[cfg(any(test, feature = "testing"))]
impl<R> StacksEpochRangeTestExt for R where R: RangeBounds<StacksEpochId> {}

impl core::fmt::Display for StacksEpochId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StacksEpochId::Epoch10 => write!(f, "1.0"),
            StacksEpochId::Epoch20 => write!(f, "2.0"),
            StacksEpochId::Epoch2_05 => write!(f, "2.05"),
            StacksEpochId::Epoch21 => write!(f, "2.1"),
            StacksEpochId::Epoch22 => write!(f, "2.2"),
            StacksEpochId::Epoch23 => write!(f, "2.3"),
            StacksEpochId::Epoch24 => write!(f, "2.4"),
            StacksEpochId::Epoch25 => write!(f, "2.5"),
            StacksEpochId::Epoch30 => write!(f, "3.0"),
            StacksEpochId::Epoch31 => write!(f, "3.1"),
            StacksEpochId::Epoch32 => write!(f, "3.2"),
            StacksEpochId::Epoch33 => write!(f, "3.3"),
            StacksEpochId::Epoch34 => write!(f, "3.4"),
            StacksEpochId::Epoch40 => write!(f, "4.0"),
            StacksEpochId::Epoch41 => write!(f, "4.1"),
        }
    }
}

impl FromStr for StacksEpochId {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1.0" => Ok(StacksEpochId::Epoch10),
            "2.0" => Ok(StacksEpochId::Epoch20),
            "2.05" => Ok(StacksEpochId::Epoch2_05),
            "2.1" => Ok(StacksEpochId::Epoch21),
            "2.2" => Ok(StacksEpochId::Epoch22),
            "2.3" => Ok(StacksEpochId::Epoch23),
            "2.4" => Ok(StacksEpochId::Epoch24),
            "2.5" => Ok(StacksEpochId::Epoch25),
            "3.0" => Ok(StacksEpochId::Epoch30),
            "3.1" => Ok(StacksEpochId::Epoch31),
            "3.2" => Ok(StacksEpochId::Epoch32),
            "3.3" => Ok(StacksEpochId::Epoch33),
            "3.4" => Ok(StacksEpochId::Epoch34),
            "4.0" => Ok(StacksEpochId::Epoch40),
            "4.1" => Ok(StacksEpochId::Epoch41),
            _ => Err("Invalid epoch string"),
        }
    }
}

impl TryFrom<u32> for StacksEpochId {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<StacksEpochId, Self::Error> {
        match value {
            x if x == StacksEpochId::Epoch10 as u32 => Ok(StacksEpochId::Epoch10),
            x if x == StacksEpochId::Epoch20 as u32 => Ok(StacksEpochId::Epoch20),
            x if x == StacksEpochId::Epoch2_05 as u32 => Ok(StacksEpochId::Epoch2_05),
            x if x == StacksEpochId::Epoch21 as u32 => Ok(StacksEpochId::Epoch21),
            x if x == StacksEpochId::Epoch22 as u32 => Ok(StacksEpochId::Epoch22),
            x if x == StacksEpochId::Epoch23 as u32 => Ok(StacksEpochId::Epoch23),
            x if x == StacksEpochId::Epoch24 as u32 => Ok(StacksEpochId::Epoch24),
            x if x == StacksEpochId::Epoch25 as u32 => Ok(StacksEpochId::Epoch25),
            x if x == StacksEpochId::Epoch30 as u32 => Ok(StacksEpochId::Epoch30),
            x if x == StacksEpochId::Epoch31 as u32 => Ok(StacksEpochId::Epoch31),
            x if x == StacksEpochId::Epoch32 as u32 => Ok(StacksEpochId::Epoch32),
            x if x == StacksEpochId::Epoch33 as u32 => Ok(StacksEpochId::Epoch33),
            x if x == StacksEpochId::Epoch34 as u32 => Ok(StacksEpochId::Epoch34),
            x if x == StacksEpochId::Epoch40 as u32 => Ok(StacksEpochId::Epoch40),
            x if x == StacksEpochId::Epoch41 as u32 => Ok(StacksEpochId::Epoch41),
            _ => Err("Invalid epoch"),
        }
    }
}
