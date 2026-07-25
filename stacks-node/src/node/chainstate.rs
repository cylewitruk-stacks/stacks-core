// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Shared chainstate opening for protocol node assembly.

use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::Error as ChainstateError;

use crate::Config;

/// Open chainstate with the fault-injection settings shared by both epoch implementations.
pub fn open_chainstate(config: &Config) -> Result<StacksChainState, ChainstateError> {
    let (mut chainstate, _) = StacksChainState::open(
        config.is_mainnet(),
        config.burnchain.chain_id,
        &config.get_chainstate_path_str(),
        Some(config.node.get_marf_opts()),
    )?;
    chainstate.fault_injection.hide_blocks = config.node.fault_injection_hide_blocks;
    Ok(chainstate)
}
