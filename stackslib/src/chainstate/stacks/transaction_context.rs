// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Transaction metadata shared during an immutable processing operation.

use std::borrow::Cow;
use std::cell::OnceCell;
use std::ops::Deref;

use super::StacksTransaction;
use crate::burnchains::Txid;

/// An immutable transaction view sharing a lazily computed ID with nested calls.
/// The borrow prevents mutation of the transaction while its ID is cached.
pub struct TransactionContext<'a> {
    /// Transaction being processed.
    transaction: &'a StacksTransaction,
    /// Owned at the entry point, borrowed by nested processing and logging calls.
    txid: Cow<'a, OnceCell<Txid>>,
}

impl TransactionContext<'_> {
    /// Compute the ID once for this processing operation.
    pub fn txid(&self) -> Txid {
        self.txid.get_or_init(|| self.transaction.txid()).clone()
    }

    /// Access the transaction without transferring the metadata cache.
    pub fn transaction(&self) -> &StacksTransaction {
        self.transaction
    }
}

impl<'a> From<&'a StacksTransaction> for TransactionContext<'a> {
    fn from(transaction: &'a StacksTransaction) -> Self {
        Self {
            transaction,
            txid: Cow::Owned(OnceCell::new()),
        }
    }
}

impl<'a> From<&'a TransactionContext<'_>> for TransactionContext<'a> {
    fn from(context: &'a TransactionContext<'_>) -> Self {
        Self {
            transaction: context.transaction,
            txid: Cow::Borrowed(&context.txid),
        }
    }
}

impl Deref for TransactionContext<'_> {
    type Target = StacksTransaction;

    fn deref(&self) -> &Self::Target {
        self.transaction
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use stacks_common::util::secp256k1::Secp256k1PrivateKey;

    use super::*;
    use crate::chainstate::stacks::{TransactionAuth, TransactionPayload, TransactionVersion};

    /// Nested processing shares one cache, which cannot outlive the immutable borrow.
    #[test]
    fn transaction_context_shares_id_and_refreshes_after_mutation() {
        let key = Secp256k1PrivateKey::from_seed(b"transaction-context-test");
        let mut tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&key).unwrap(),
            TransactionPayload::new_smart_contract("test", "(define-public (run) (ok true))", None)
                .unwrap(),
        );
        let original_id;
        {
            let context = TransactionContext::from(&tx);
            assert!(context.txid.get().is_none());
            let nested = TransactionContext::from(&context);
            assert!(ptr::eq(context.txid.as_ref(), nested.txid.as_ref()));
            original_id = nested.txid();
            assert_eq!(context.txid.get(), Some(&original_id));
            assert_eq!(context.txid(), tx.txid());
        }
        tx.set_origin_nonce(1);
        let context = TransactionContext::from(&tx);
        assert!(context.txid.get().is_none());
        assert_ne!(context.txid(), original_id);
        assert_eq!(context.txid(), tx.txid());
    }
}
