// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#[cfg(test)]
pub fn fault_injection_long_tenure() {
    let Ok(tenure_str) = std::env::var("STX_TEST_SLOW_TENURE") else {
        return;
    };
    let Ok(tenure_time) = tenure_str.parse::<u64>() else {
        error!("Parse error for STX_TEST_SLOW_TENURE");
        panic!();
    };
    info!("Fault injection: sleeping for {tenure_time} milliseconds to simulate a long tenure");
    stacks_common::util::sleep_ms(tenure_time);
}

#[cfg(not(test))]
pub fn fault_injection_long_tenure() {}

#[cfg(test)]
pub fn fault_injection_skip_mining(rpc_bind: &str, target_burn_height: u64) -> bool {
    let Ok(disable_heights) = std::env::var("STACKS_DISABLE_MINER") else {
        return false;
    };
    let disable_schedule: serde_json::Value = serde_json::from_str(&disable_heights).unwrap();
    for disabled in disable_schedule.as_array().unwrap() {
        if disabled.get("rpc_bind").unwrap().as_str().unwrap() != rpc_bind {
            continue;
        }
        for target_block_value in disabled.get("blocks").unwrap().as_array().unwrap() {
            let target_block = u64::try_from(target_block_value.as_i64().unwrap()).unwrap();
            if target_block == target_burn_height {
                return true;
            }
        }
    }
    false
}

#[cfg(not(test))]
pub fn fault_injection_skip_mining(_rpc_bind: &str, _target_burn_height: u64) -> bool {
    false
}
