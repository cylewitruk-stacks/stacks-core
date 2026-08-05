use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

pub const MICROSTACKS_PER_STACKS: u32 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoinbaseInterval {
    pub coinbase: u128,
    pub effective_start_height: u64,
}

pub static COINBASE_INTERVALS_MAINNET: LazyLock<[CoinbaseInterval; 5]> = LazyLock::new(|| {
    let emissions_schedule = [
        CoinbaseInterval {
            coinbase: 1_000 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 0,
        },
        CoinbaseInterval {
            coinbase: 500 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 278_950,
        },
        CoinbaseInterval {
            coinbase: 250 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 383_950,
        },
        CoinbaseInterval {
            coinbase: 125 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 593_950,
        },
        CoinbaseInterval {
            coinbase: (625 * u128::from(MICROSTACKS_PER_STACKS)) / 10,
            effective_start_height: 803_950,
        },
    ];
    assert!(CoinbaseInterval::check_order(&emissions_schedule));
    emissions_schedule
});

pub static COINBASE_INTERVALS_TESTNET: LazyLock<[CoinbaseInterval; 5]> = LazyLock::new(|| {
    let emissions_schedule = [
        CoinbaseInterval {
            coinbase: 1_000 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 0,
        },
        CoinbaseInterval {
            coinbase: 500 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 77_777,
        },
        CoinbaseInterval {
            coinbase: 250 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 77_777 * 7,
        },
        CoinbaseInterval {
            coinbase: 125 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 77_777 * 14,
        },
        CoinbaseInterval {
            coinbase: (625 * u128::from(MICROSTACKS_PER_STACKS)) / 10,
            effective_start_height: 77_777 * 21,
        },
    ];
    assert!(CoinbaseInterval::check_order(&emissions_schedule));
    emissions_schedule
});

#[cfg(any(test, feature = "testing"))]
pub static COINBASE_INTERVALS_TEST: std::sync::Mutex<Option<Vec<CoinbaseInterval>>> =
    std::sync::Mutex::new(None);

#[cfg(any(test, feature = "testing"))]
pub fn set_test_coinbase_schedule(coinbase_schedule: Option<Vec<CoinbaseInterval>>) {
    match COINBASE_INTERVALS_TEST.lock() {
        Ok(mut schedule_guard) => {
            *schedule_guard = coinbase_schedule;
        }
        Err(_e) => {
            panic!("COINBASE_INTERVALS_TEST mutex poisoned");
        }
    }
}

impl CoinbaseInterval {
    pub fn get_coinbase_at_effective_height(
        intervals: &[CoinbaseInterval],
        effective_height: u64,
    ) -> u128 {
        if intervals.is_empty() {
            return 0;
        }
        if intervals.len() == 1 {
            if intervals[0].effective_start_height <= effective_height {
                return intervals[0].coinbase;
            } else {
                return 0;
            }
        }

        for i in 0..(intervals.len() - 1) {
            if intervals[i].effective_start_height <= effective_height
                && effective_height < intervals[i + 1].effective_start_height
            {
                return intervals[i].coinbase;
            }
        }

        intervals.last().unwrap_or_else(|| unreachable!()).coinbase
    }

    pub fn check_order(intervals: &[CoinbaseInterval]) -> bool {
        if intervals.len() < 2 {
            return true;
        }

        let mut ht = intervals[0].effective_start_height;
        for interval in intervals.iter().skip(1) {
            if interval.effective_start_height < ht {
                return false;
            }
            ht = interval.effective_start_height;
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SIP031EmissionInterval {
    pub amount: u128,
    pub start_height: u64,
}

pub static SIP031_EMISSION_INTERVALS_MAINNET: LazyLock<[SIP031EmissionInterval; 6]> =
    LazyLock::new(|| {
        let emissions_schedule = [
            SIP031EmissionInterval {
                amount: 0,
                start_height: 1_170_540,
            },
            SIP031EmissionInterval {
                amount: 1_155 * u128::from(MICROSTACKS_PER_STACKS),
                start_height: 1_117_980,
            },
            SIP031EmissionInterval {
                amount: 1_305 * u128::from(MICROSTACKS_PER_STACKS),
                start_height: 1_065_420,
            },
            SIP031EmissionInterval {
                amount: 1_705 * u128::from(MICROSTACKS_PER_STACKS),
                start_height: 1_012_860,
            },
            SIP031EmissionInterval {
                amount: 1_140 * u128::from(MICROSTACKS_PER_STACKS),
                start_height: 960_300,
            },
            SIP031EmissionInterval {
                amount: 475 * u128::from(MICROSTACKS_PER_STACKS),
                start_height: 907_740,
            },
        ];
        assert!(SIP031EmissionInterval::check_inversed_order(
            &emissions_schedule
        ));
        emissions_schedule
    });

pub static SIP031_EMISSION_INTERVALS_TESTNET: LazyLock<[SIP031EmissionInterval; 6]> =
    LazyLock::new(|| {
        let emissions_schedule = [
            SIP031EmissionInterval {
                amount: 0,
                start_height: 71_525 + (360 * 6),
            },
            SIP031EmissionInterval {
                amount: 5_000,
                start_height: 71_525 + (360 * 5),
            },
            SIP031EmissionInterval {
                amount: 4_000,
                start_height: 71_525 + (360 * 4),
            },
            SIP031EmissionInterval {
                amount: 3_000,
                start_height: 71_525 + (360 * 3),
            },
            SIP031EmissionInterval {
                amount: 2_000,
                start_height: 71_525 + (360 * 2),
            },
            SIP031EmissionInterval {
                amount: 1_000,
                start_height: 71_525 + 360,
            },
        ];
        assert!(SIP031EmissionInterval::check_inversed_order(
            &emissions_schedule
        ));
        emissions_schedule
    });

#[cfg(any(test, feature = "testing"))]
pub static SIP031_EMISSION_INTERVALS_TEST: std::sync::Mutex<Option<Vec<SIP031EmissionInterval>>> =
    std::sync::Mutex::new(None);

#[cfg(any(test, feature = "testing"))]
pub fn set_test_sip_031_emission_schedule(emission_schedule: Option<Vec<SIP031EmissionInterval>>) {
    if let Some(emission_schedule_vec) = &emission_schedule {
        assert!(SIP031EmissionInterval::check_inversed_order(
            emission_schedule_vec
        ));
    }
    match SIP031_EMISSION_INTERVALS_TEST.lock() {
        Ok(mut schedule_guard) => {
            *schedule_guard = emission_schedule;
        }
        Err(_e) => {
            panic!("SIP031_EMISSION_INTERVALS_TEST mutex poisoned");
        }
    }
}

#[cfg(any(test, feature = "testing"))]
fn get_sip_031_emission_schedule(_mainnet: bool) -> Vec<SIP031EmissionInterval> {
    match SIP031_EMISSION_INTERVALS_TEST.lock() {
        Ok(schedule_opt) => {
            if let Some(schedule) = (*schedule_opt).as_ref() {
                schedule.clone()
            } else {
                vec![]
            }
        }
        Err(_e) => {
            panic!("SIP031_EMISSION_INTERVALS_TEST mutex poisoned");
        }
    }
}

#[cfg(not(any(test, feature = "testing")))]
fn get_sip_031_emission_schedule(mainnet: bool) -> Vec<SIP031EmissionInterval> {
    if mainnet {
        SIP031_EMISSION_INTERVALS_MAINNET.to_vec()
    } else {
        SIP031_EMISSION_INTERVALS_TESTNET.to_vec()
    }
}

impl SIP031EmissionInterval {
    pub fn get_sip_031_emission_at_height(burn_height: u64, mainnet: bool) -> u128 {
        let intervals = get_sip_031_emission_schedule(mainnet);

        if intervals.is_empty() {
            return 0;
        }

        for interval in intervals {
            if burn_height >= interval.start_height {
                return interval.amount;
            }
        }

        0
    }

    pub fn check_inversed_order(intervals: &[SIP031EmissionInterval]) -> bool {
        let Some(mut ht) = intervals.first().map(|x| x.start_height) else {
            return true;
        };

        for interval in intervals.iter().skip(1) {
            if interval.start_height > ht {
                return false;
            }
            ht = interval.start_height;
        }
        true
    }
}

#[cfg(any(test, feature = "testing"))]
pub fn get_coinbase_intervals(mainnet: bool) -> Vec<CoinbaseInterval> {
    match COINBASE_INTERVALS_TEST.lock() {
        Ok(schedule_opt) => {
            if let Some(schedule) = (*schedule_opt).as_ref() {
                return schedule.clone();
            }
        }
        Err(_e) => {
            panic!("COINBASE_INTERVALS_TEST mutex poisoned");
        }
    }

    if mainnet {
        COINBASE_INTERVALS_MAINNET.to_vec()
    } else {
        COINBASE_INTERVALS_TESTNET.to_vec()
    }
}

#[cfg(not(any(test, feature = "testing")))]
pub fn get_coinbase_intervals(mainnet: bool) -> Vec<CoinbaseInterval> {
    if mainnet {
        COINBASE_INTERVALS_MAINNET.to_vec()
    } else {
        COINBASE_INTERVALS_TESTNET.to_vec()
    }
}

pub(crate) fn coinbase_reward_pre_sip029(
    first_burnchain_height: u64,
    current_burnchain_height: u64,
) -> u128 {
    let effective_ht = current_burnchain_height.saturating_sub(first_burnchain_height);
    let blocks_per_year = 52596;
    let stx_reward = if effective_ht < blocks_per_year * 4 {
        1000
    } else if effective_ht < blocks_per_year * 8 {
        500
    } else if effective_ht < blocks_per_year * 12 {
        250
    } else {
        125
    };

    stx_reward * u128::from(MICROSTACKS_PER_STACKS)
}

pub(crate) fn coinbase_reward_sip029(
    mainnet: bool,
    first_burnchain_height: u64,
    current_burnchain_height: u64,
) -> u128 {
    let effective_ht = current_burnchain_height.saturating_sub(first_burnchain_height);
    let coinbase_intervals = get_coinbase_intervals(mainnet);
    CoinbaseInterval::get_coinbase_at_effective_height(&coinbase_intervals, effective_ht)
}
