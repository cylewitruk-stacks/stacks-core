use clarity::vm::database::BurnStateDB;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::{
    TransactionAuth, TransactionPayload, TransactionSpendingCondition,
};

use super::node::ChainTip;
use super::tenure::Tenure;
use crate::BurnchainTip;

macro_rules! info_blue {
    ($($arg:tt)*) => ({
        eprintln!("\x1b[0;96m{}\x1b[0m", format!($($arg)*));
    })
}

#[allow(unused_macros)]
macro_rules! info_yellow {
    ($($arg:tt)*) => ({
        eprintln!("\x1b[0;33m{}\x1b[0m", format!($($arg)*));
    })
}

macro_rules! info_green {
    ($($arg:tt)*) => ({
        eprintln!("\x1b[0;32m{}\x1b[0m", format!($($arg)*));
    })
}

#[allow(clippy::type_complexity)]
pub struct DriverCallbacks {
    on_new_stacks_chain_state:
        Option<fn(u64, &BurnchainTip, &ChainTip, &mut StacksChainState, &dyn BurnStateDB)>,
    on_new_tenure: Option<fn(u64, &BurnchainTip, &ChainTip, &mut Tenure)>,
}

impl Default for DriverCallbacks {
    fn default() -> Self {
        Self::new()
    }
}

impl DriverCallbacks {
    pub fn new() -> DriverCallbacks {
        DriverCallbacks {
            on_new_stacks_chain_state: None,
            on_new_tenure: None,
        }
    }

    #[cfg(test)]
    pub fn on_new_stacks_chain_state(
        &mut self,
        callback: fn(u64, &BurnchainTip, &ChainTip, &mut StacksChainState, &dyn BurnStateDB),
    ) {
        self.on_new_stacks_chain_state = Some(callback);
    }

    #[cfg(test)]
    pub fn on_new_tenure(&mut self, callback: fn(u64, &BurnchainTip, &ChainTip, &mut Tenure)) {
        self.on_new_tenure = Some(callback);
    }

    pub fn invoke_new_burn_chain_state(
        &self,
        _round: u64,
        burnchain_tip: &BurnchainTip,
        _chain_tip: &ChainTip,
    ) {
        info_blue!(
            "Burnchain block #{} ({}) was produced with sortition #{}",
            burnchain_tip.block_snapshot.block_height,
            burnchain_tip.block_snapshot.burn_header_hash,
            burnchain_tip.block_snapshot.sortition_hash
        );
    }

    pub fn invoke_new_stacks_chain_state(
        &self,
        round: u64,
        burnchain_tip: &BurnchainTip,
        chain_tip: &ChainTip,
        chain_state: &mut StacksChainState,
        burn_dbconn: &dyn BurnStateDB,
    ) {
        info_green!(
            "Stacks block #{} ({}) successfully produced, including {} transactions",
            chain_tip.metadata.stacks_block_height,
            chain_tip.metadata.index_block_hash(),
            chain_tip.block.txs.len()
        );
        for tx in chain_tip.block.txs.iter() {
            match &tx.auth {
                TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(auth)) => {
                    println!(
                        "-> Tx issued by {:?} (fee: {}, nonce: {})",
                        auth.signer, auth.tx_fee, auth.nonce
                    )
                }
                _ => println!("-> Tx {:?}", tx.auth),
            }
            match &tx.payload {
                TransactionPayload::Coinbase(..) => println!("   Coinbase"),
                TransactionPayload::SmartContract(contract, ..) => println!(
                    "   Publish smart contract\n**************************\n{:?}\n**************************",
                    contract.code_body
                ),
                TransactionPayload::TokenTransfer(recipent, amount, _) => {
                    println!("   Transfering {amount} µSTX to {recipent}")
                }
                _ => println!("   {:?}", tx.payload),
            }
        }

        if let Some(cb) = self.on_new_stacks_chain_state {
            cb(round, burnchain_tip, chain_tip, chain_state, burn_dbconn);
        }
    }

    pub fn invoke_new_tenure(
        &self,
        round: u64,
        burnchain_tip: &BurnchainTip,
        chain_tip: &ChainTip,
        tenure: &mut Tenure,
    ) {
        if let Some(cb) = self.on_new_tenure {
            cb(round, burnchain_tip, chain_tip, tenure);
        }
    }
}
