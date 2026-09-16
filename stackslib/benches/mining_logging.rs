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

//! Measures transaction append in a Nakamoto block builder, excluding fixture setup,
//! signing, candidate-block opening, rollback, and receipt validation. Each mining
//! iteration contains four transactions. Diagnostic groups measure one rejected
//! payload's logging, without executing the transaction.
//!
//! Run each logging configuration in a fresh process, since the settings are cached:
//!
//! ```sh
//! STACKS_LOG_CLARITY_VALUES=1 STACKS_LOG_CONTRACT_SOURCE=1 cargo bench -p stackslib --features testing --bench mining_logging -- --save-baseline full
//! STACKS_LOG_CLARITY_VALUES=0 STACKS_LOG_CONTRACT_SOURCE=0 cargo bench -p stackslib --features testing --bench mining_logging -- --baseline full
//! ```
//!
//! Keep the global log level at INFO and use the same output sink for both runs.
//! Add `slog_json` and `STACKS_LOG_JSON=1` to measure JSON. `-- --test` validates
//! the workload matrix without collecting measurements. These are append-path
//! measurements, excluding mempool selection, block finalization, and networking.

use std::fs;
use std::hint::black_box;
use std::time::{Duration, Instant};

use clarity::vm::test_util::{UnitTestBurnStateDB, TEST_HEADER_DB};
use clarity::vm::types::{TupleData, Value};
use clarity::vm::ClarityName;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use stacks_common::consts::{
    CHAIN_ID_TESTNET, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};
use stacks_common::types::StacksEpochId;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use tempfile::{Builder as TempDirBuilder, TempDir};

use blockstack_lib::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::chainstate::stacks::db::testing::TestChainstateBuilder;
use blockstack_lib::chainstate::stacks::db::{
    ClarityTx, StacksBlockHeaderTypes, StacksChainState, StacksHeaderInfo,
};
use blockstack_lib::chainstate::stacks::events::StacksTransactionReceipt;
use blockstack_lib::chainstate::stacks::miner::{
    BlockBuilder, TransactionResourceBudgets, TransactionResult,
};
use blockstack_lib::chainstate::stacks::{
    Error, StacksTransaction, StacksTransactionSigner, TransactionAuth, TransactionPayload,
    TransactionVersion,
};
use blockstack_lib::config::DEFAULT_MAX_TENURE_BYTES;

/// Transactions appended per measured batch, including the largest inputs.
const BATCH_SIZE: u64 = 4;

/// Burn-state fixture for current Nakamoto transaction execution.
const BURN_DB: UnitTestBurnStateDB = UnitTestBurnStateDB {
    epoch_id: StacksEpochId::Epoch40,
};

/// Contract, input, and independently specified expected result for one workload.
struct Workload {
    /// Stable Criterion case name.
    name: String,
    /// Source deployed before calls, or during the measured deploy workload.
    source: String,
    /// None measures deployment; Some measures calls to `run`.
    args: Option<Vec<Value>>,
    /// Expected successful receipt result.
    expected: Value,
}

/// Constructs scalar, structured, compute, and deployment controls.
fn workloads() -> Vec<Workload> {
    let mut cases = Vec::new();
    for size in [32, 4096, 65536] {
        for (kind, value) in [
            ("buff", Value::buff_from(vec![0xab; size]).unwrap()),
            (
                "string-ascii",
                Value::string_ascii_from_bytes(vec![b'x'; size]).unwrap(),
            ),
        ] {
            cases.push(Workload {
                name: format!("echo-{kind}-{size}"),
                source: format!("(define-public (run (value ({kind} {size}))) (ok value))"),
                args: Some(vec![value.clone()]),
                expected: Value::okay(value).unwrap(),
            });
        }
    }
    for count in [16, 1024] {
        let values = Value::list_from((0..count).map(Value::UInt).collect()).unwrap();
        let tuple = Value::Tuple(
            TupleData::from_data(vec![
                (ClarityName::from_literal("items"), values.clone()),
                (
                    ClarityName::from_literal("meta"),
                    Value::Tuple(
                        TupleData::from_data(vec![
                            (
                                ClarityName::from_literal("label"),
                                Value::string_ascii_from_bytes(b"nested".to_vec()).unwrap(),
                            ),
                            (ClarityName::from_literal("valid"), Value::Bool(true)),
                        ])
                        .unwrap(),
                    ),
                ),
            ])
            .unwrap(),
        );
        cases.push(Workload {
            name: format!("nested-{count}"),
            source: format!("(define-public (run (value (tuple (items (list {count} uint)) (meta (tuple (label (string-ascii 6)) (valid bool)))))) (ok value))"),
            args: Some(vec![tuple.clone()]),
            expected: Value::okay(tuple).unwrap(),
        });
        cases.push(Workload {
            name: format!("fold-{count}"),
            source: format!("(define-private (step (x uint) (sum uint)) (+ sum (* x x))) (define-public (run (items (list {count} uint))) (ok (fold step items u0)))"),
            args: Some(vec![values]),
            expected: Value::okay(Value::UInt((0..count).map(|x| x*x).sum())).unwrap(),
        });
    }
    cases.push(Workload {
        name: "input-only-buff-65536".into(),
        source: "(define-public (run (value (buff 65536))) (ok (len value)))".into(),
        args: Some(vec![Value::buff_from(vec![0xab; 65536]).unwrap()]),
        expected: Value::okay(Value::UInt(65536)).unwrap(),
    });
    cases.push(Workload {
        name: "output-only-ascii-65536".into(),
        source: format!("(define-public (run) (ok \"{}\"))", "x".repeat(65536)),
        args: Some(vec![]),
        expected: Value::okay(Value::string_ascii_from_bytes(vec![b'x'; 65536]).unwrap()).unwrap(),
    });
    for definitions in [1, 32, 256] {
        let mut source = "(define-public (run (value uint)) (ok value))\n".to_string();
        for n in 0..definitions {
            source.push_str(&format!(
                "(define-private (helper-{n} (x uint)) (+ x u{n}))\n"
            ));
        }
        cases.push(Workload {
            name: format!("contract-functions-{definitions}"),
            source: source.clone(),
            args: Some(vec![Value::UInt(7)]),
            expected: Value::okay(Value::UInt(7)).unwrap(),
        });
        cases.push(Workload {
            name: format!("deploy-functions-{definitions}"),
            source,
            args: None,
            expected: Value::okay(Value::Bool(true)).unwrap(),
        });
    }
    cases
}

/// Signs fixed transactions outside the measured region.
fn signed_tx(
    key: &Secp256k1PrivateKey,
    nonce: u64,
    payload: TransactionPayload,
) -> StacksTransaction {
    let mut tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(key).unwrap(),
        payload,
    );
    tx.chain_id = CHAIN_ID_TESTNET;
    tx.set_origin_nonce(nonce);
    tx.set_tx_fee(1);
    let mut signer = StacksTransactionSigner::new(&tx);
    signer.sign_origin(key).unwrap();
    signer.get_tx().unwrap()
}

/// Committed fixture state and signed transactions reused after each rollback.
struct MiningFixture {
    /// Chainstate with a funded origin and, for calls, a deployed contract.
    chainstate: StacksChainState,
    /// Signed batch with consecutive nonces.
    txs: Vec<StacksTransaction>,
    /// Parent metadata used by the transaction append path.
    parent: StacksHeaderInfo,
    /// Removes fixture files after all database handles have closed.
    _directory: TempDir,
}

impl MiningFixture {
    /// Creates a deterministic funded parent, excluding setup from timing.
    fn new(case: &Workload) -> Self {
        let key = Secp256k1PrivateKey::from_seed(b"mining-logging-criterion");
        let address = TransactionAuth::from_p2pkh(&key)
            .unwrap()
            .origin()
            .address_testnet();
        fs::create_dir_all("/tmp/stacks-node-tests").unwrap();
        let directory = TempDirBuilder::new()
            .prefix("cs-mining-logging-")
            .tempdir_in("/tmp/stacks-node-tests")
            .unwrap();
        let name = directory
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .strip_prefix("cs-")
            .unwrap();
        let mut chainstate = TestChainstateBuilder::new_testnet(name)
            .with_balances(vec![(address.clone(), 1_000_000_000)])
            .build();
        let mut conn = chainstate.block_begin(
            &BURN_DB,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1; 20]),
            &BlockHeaderHash([1; 32]),
        );
        if case.args.is_some() {
            let publish = signed_tx(
                &key,
                0,
                TransactionPayload::new_smart_contract("logging-bench", &case.source, None)
                    .unwrap(),
            );
            let (_, receipt) =
                StacksChainState::process_transaction(&mut conn, &publish, true, None).unwrap();
            assert_eq!(receipt.result, Value::okay(Value::Bool(true)).unwrap());
            assert!(receipt.vm_error.is_none());
        }
        conn.commit_to_block(&ConsensusHash([1; 20]), &BlockHeaderHash([1; 32]));
        let txs = (0..BATCH_SIZE)
            .map(|index| {
                let (nonce, payload) = if let Some(args) = &case.args {
                    (
                        index + 1,
                        TransactionPayload::new_contract_call(
                            address.clone(),
                            "logging-bench",
                            "run",
                            args.clone(),
                        )
                        .unwrap(),
                    )
                } else {
                    (
                        index,
                        TransactionPayload::new_smart_contract(
                            &format!("deploy-{index}"),
                            &case.source,
                            None,
                        )
                        .unwrap(),
                    )
                };
                signed_tx(&key, nonce, payload)
            })
            .collect();
        let mut parent = StacksHeaderInfo::regtest_genesis();
        parent.anchored_header = StacksBlockHeaderTypes::Nakamoto(NakamotoBlockHeader::genesis());
        parent.consensus_hash = ConsensusHash([1; 20]);
        Self {
            chainstate,
            txs,
            parent,
            _directory: directory,
        }
    }

    /// Times only transaction append; rolls back the candidate block afterwards.
    fn mine_batch(&mut self, expected: &Value) -> (Duration, Vec<StacksTransactionReceipt>) {
        let mut conn = ClarityTx::from_block_connection(self.chainstate.clarity_state.begin_block(
            &StacksBlockId::new(&ConsensusHash([1; 20]), &BlockHeaderHash([1; 32])),
            &StacksBlockId::new(&ConsensusHash([2; 20]), &BlockHeaderHash([2; 32])),
            &TEST_HEADER_DB,
            &BURN_DB,
        ));
        assert_eq!(conn.get_epoch(), StacksEpochId::Epoch40);
        let mut builder = NakamotoBlockBuilder::new(
            &self.parent,
            &ConsensusHash([2; 20]),
            0,
            None,
            None,
            1,
            None,
            None,
            Some(1),
            u64::from(DEFAULT_MAX_TENURE_BYTES),
        )
        .unwrap();
        let budgets = TransactionResourceBudgets::unlimited();
        let mut receipt_size = 0;
        let mut results = Vec::with_capacity(self.txs.len());
        let started = Instant::now();
        for tx in &self.txs {
            results.push(builder.try_mine_tx(
                &mut conn,
                black_box(tx),
                &budgets,
                &mut receipt_size,
            ));
        }
        let elapsed = started.elapsed();
        let receipts = results
            .into_iter()
            .map(|result| {
                let TransactionResult::Success(success) =
                    result.expect("mining must accept the transaction")
                else {
                    panic!("mining did not succeed");
                };
                assert_eq!(&success.receipt.result, expected);
                assert!(!success.receipt.post_condition_aborted);
                assert!(success.receipt.vm_error.is_none());
                assert!(success.receipt.events.is_empty());
                success.receipt
            })
            .collect();
        conn.rollback_block();
        (elapsed, receipts)
    }
}

/// Measures mining work using identical candidate transactions and parent state.
fn mining_logging(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("mining_logging");
    group.throughput(Throughput::Elements(BATCH_SIZE));
    for case in workloads() {
        group.bench_function(&case.name, |b| {
            let mut fixture = MiningFixture::new(&case);
            let (_, expected_receipts) = fixture.mine_batch(&case.expected);
            b.iter_custom(|iterations| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    let (duration, receipts) = fixture.mine_batch(&case.expected);
                    elapsed += duration;
                    assert_eq!(receipts, expected_receipts);
                }
                elapsed
            })
        });
    }
    group.finish();
    // These are diagnostic-only measurements, separate from successful mining.
    let mut group = criterion.benchmark_group("problematic_publish_logging");
    group.throughput(Throughput::Elements(1));
    for size in [4096, 65536] {
        let name = format!("source-{size}");
        let source = format!("(define-public (run) (ok true))\n;; {}", "x".repeat(size));
        let tx = signed_tx(
            &Secp256k1PrivateKey::from_seed(b"source-logging"),
            0,
            TransactionPayload::new_smart_contract("source-bench", &source, None).unwrap(),
        );
        group.bench_function(name, |b| {
            b.iter(|| {
                let (problematic, _) = TransactionResult::is_problematic(
                    black_box(&tx),
                    Error::AnalysisResourceBudgetExceeded("benchmark".into()),
                    StacksEpochId::Epoch40,
                );
                assert!(problematic);
            })
        });
    }
    group.finish();
    let mut group = criterion.benchmark_group("problematic_call_logging");
    group.throughput(Throughput::Elements(1));
    let key = Secp256k1PrivateKey::from_seed(b"call-logging");
    let address = TransactionAuth::from_p2pkh(&key)
        .unwrap()
        .origin()
        .address_testnet();
    for size in [4096, 65536] {
        let tx = signed_tx(
            &key,
            0,
            TransactionPayload::new_contract_call(
                address.clone(),
                "call-bench",
                "run",
                vec![Value::buff_from(vec![0xab; size]).unwrap()],
            )
            .unwrap(),
        );
        group.bench_function(format!("arguments-{size}"), |b| {
            b.iter(|| {
                let (problematic, _) = TransactionResult::is_problematic(
                    black_box(&tx),
                    Error::ExecutionResourceBudgetExceeded("benchmark".into()),
                    StacksEpochId::Epoch40,
                );
                assert!(problematic);
            })
        });
    }
    group.finish();
}

criterion_group!(benches, mining_logging);
criterion_main!(benches);
