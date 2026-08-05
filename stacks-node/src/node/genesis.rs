// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Genesis data loading and boot receipt dispatch.

use std::env;

use clarity::vm::costs::ExecutionCost;
use stacks::burnchains::{PoxConstants, Txid};
use stacks::chainstate::coordinator::BlockEventDispatcher;
use stacks::chainstate::stacks::db::{
    ChainStateBootData, ChainstateAccountBalance, ChainstateAccountLockup, ChainstateBNSName,
    ChainstateBNSNamespace, StacksChainState,
};
use stacks::chainstate::stacks::events::StacksTransactionReceipt;
use stacks::chainstate::stacks::index::ClarityMarfTrieId;
use stacks::chainstate::stacks::StacksBlock;
use stacks_common::types::chainstate::StacksBlockId;

use crate::genesis_data::USE_TEST_GENESIS_CHAINSTATE;
use crate::{Config, EventDispatcher};

pub fn get_account_lockups(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateAccountLockup>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_lockups()
            .map(|item| ChainstateAccountLockup {
                address: item.address,
                amount: item.amount,
                block_height: item.block_height,
            }),
    )
}

pub fn get_account_balances(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateAccountBalance>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_balances()
            .map(|item| ChainstateAccountBalance {
                address: item.address,
                amount: item.amount,
            }),
    )
}

pub fn get_namespaces(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateBNSNamespace>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_namespaces()
            .map(|item| ChainstateBNSNamespace {
                namespace_id: item.namespace_id,
                importer: item.importer,
                buckets: item.buckets,
                base: item.base as u64,
                coeff: item.coeff as u64,
                nonalpha_discount: item.nonalpha_discount as u64,
                no_vowel_discount: item.no_vowel_discount as u64,
                lifetime: item.lifetime as u64,
            }),
    )
}

pub fn get_names(use_test_chainstate_data: bool) -> Box<dyn Iterator<Item = ChainstateBNSName>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_names()
            .map(|item| ChainstateBNSName {
                fully_qualified_name: item.fully_qualified_name,
                owner: item.owner,
                zonefile_hash: item.zonefile_hash,
            }),
    )
}

/// Attach the configured genesis-data readers to chainstate boot data.
pub fn attach_genesis_data_sources(
    boot_data: &mut ChainStateBootData,
    use_test_chainstate_data: bool,
) {
    boot_data.get_bulk_initial_lockups = Some(Box::new(move || {
        get_account_lockups(use_test_chainstate_data)
    }));
    boot_data.get_bulk_initial_balances = Some(Box::new(move || {
        get_account_balances(use_test_chainstate_data)
    }));
    boot_data.get_bulk_initial_namespaces =
        Some(Box::new(move || get_namespaces(use_test_chainstate_data)));
    boot_data.get_bulk_initial_names = Some(Box::new(move || get_names(use_test_chainstate_data)));
}

// Check if the small test genesis chainstate data should be used.
// First check env var, then config file, then use default.
pub fn use_test_genesis_chainstate(config: &Config) -> bool {
    if env::var("BLOCKSTACK_USE_TEST_GENESIS_CHAINSTATE") == Ok("1".to_string()) {
        true
    } else if let Some(use_test_genesis_chainstate) = config.node.use_test_genesis_chainstate {
        use_test_genesis_chainstate
    } else {
        USE_TEST_GENESIS_CHAINSTATE
    }
}

pub fn announce_boot_receipts(
    event_dispatcher: &EventDispatcher,
    chainstate: &StacksChainState,
    pox_constants: &PoxConstants,
    boot_receipts: &[StacksTransactionReceipt],
) {
    let block_header_0 = StacksChainState::get_genesis_header_info(chainstate.db())
        .expect("FATAL: genesis block header not stored");
    let block_0 = StacksBlock {
        header: block_header_0
            .anchored_header
            .as_stacks_epoch2()
            .expect("FATAL: Expected a Stacks 2.0 Genesis block")
            .clone(),
        txs: vec![],
    };

    debug!("Push {} boot receipts", &boot_receipts.len());
    event_dispatcher.announce_block(
        &block_0.into(),
        &block_header_0,
        boot_receipts,
        &StacksBlockId::sentinel(),
        &Txid([0x00; 32]),
        &[],
        None,
        &block_header_0.burn_header_hash,
        block_header_0.burn_header_height,
        block_header_0.burn_header_timestamp,
        &ExecutionCost::ZERO,
        &ExecutionCost::ZERO,
        pox_constants,
        &None,
        &None,
        None,
        0,
    );
}

#[cfg(test)]
mod tests {
    use stacks_common::types::chainstate::BurnchainHeaderHash;

    use super::*;

    #[test]
    fn attaches_all_genesis_data_sources() {
        let mut boot_data = ChainStateBootData {
            first_burnchain_block_hash: BurnchainHeaderHash::zero(),
            first_burnchain_block_height: 0,
            first_burnchain_block_timestamp: 0,
            initial_balances: vec![],
            pox_constants: PoxConstants::testnet_default(),
            post_flight_callback: None,
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_namespaces: None,
            get_bulk_initial_names: None,
        };

        attach_genesis_data_sources(&mut boot_data, true);

        assert_eq!(
            boot_data.get_bulk_initial_lockups.take().unwrap()().count(),
            get_account_lockups(true).count()
        );
        assert_eq!(
            boot_data.get_bulk_initial_balances.take().unwrap()().count(),
            get_account_balances(true).count()
        );
        assert_eq!(
            boot_data.get_bulk_initial_namespaces.take().unwrap()().count(),
            get_namespaces(true).count()
        );
        assert_eq!(
            boot_data.get_bulk_initial_names.take().unwrap()().count(),
            get_names(true).count()
        );
    }
}
