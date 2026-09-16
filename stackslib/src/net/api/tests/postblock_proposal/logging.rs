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

//! Production JSON records, captured in fresh processes for each detail setting.

use std::env;
use std::fs;
use std::process::{self, Command};
use std::slice;

use clarity::vm::test_util::UnitTestBurnStateDB;
use clarity::vm::Value;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use stacks_common::consts::{
    CHAIN_ID_TESTNET, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash};
use stacks_common::types::StacksEpochId;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use tempfile::Builder as TempDirBuilder;

use super::assert_analysis_budget_rejects_proposal;
use crate::chainstate::stacks::db::testing::TestChainstateBuilder;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::miner::TransactionResult;
use crate::chainstate::stacks::{
    Error, StacksTransaction, StacksTransactionSigner, TransactionAuth, TransactionPayload,
    TransactionVersion,
};
use crate::clarity_vm::clarity::ClarityError;
use crate::util_lib::strings::VecDisplay;

/// Selects fixture execution instead of spawning another test process.
const CHILD_MODE: &str = "STACKS_TEST_JSON_LOGGING_CHILD";
/// Separates expected records from ordinary libtest output on stdout.
const EXPECTED_PREFIX: &str = "LOGGING_EXPECTATIONS=";

/// Independent operator switch controlling a record's detailed fields.
#[derive(Serialize, Deserialize)]
enum DetailSetting {
    /// Contract-call arguments and return values.
    Values,
    /// Contract source and publish payloads.
    Source,
}

/// Exact expected record shapes, excluding process and source-code metadata.
#[derive(Serialize, Deserialize)]
struct ExpectedRecord {
    /// Detail switch for this record.
    setting: DetailSetting,
    /// Common fields identifying exactly one emitted record.
    selector: JsonValue,
    /// Original record with complete values or payload.
    full: JsonValue,
    /// Record with heavy fields omitted or replaced by identifiers.
    summary: JsonValue,
}

impl ExpectedRecord {
    /// Combine common fields with the independently specified detail alternatives.
    fn new(
        setting: DetailSetting,
        common: JsonValue,
        full_fields: JsonValue,
        summary_fields: JsonValue,
    ) -> Self {
        let mut full = common.clone();
        full.as_object_mut()
            .unwrap()
            .extend(full_fields.as_object().unwrap().clone());
        let mut summary = common.clone();
        summary
            .as_object_mut()
            .unwrap()
            .extend(summary_fields.as_object().unwrap().clone());
        Self {
            setting,
            selector: common,
            full,
            summary,
        }
    }
}

/// Exercise real call sites using the process-wide JSON logger and independent flags.
#[test]
fn production_json_logging() {
    if env::var(CHILD_MODE).as_deref() == Ok("1") {
        let mut expected = contract_records();
        let name = format!("json-logging-proposal-{}", process::id());
        let (tx, reason) = assert_analysis_budget_rejects_proposal(&name);
        expected.push(ExpectedRecord::new(
            DetailSetting::Source,
            json!({"msg": "Rejected block proposal", "level": "WARN", "reason": reason}),
            json!({"tx": format!("{tx:?}")}),
            json!({"txid": tx.txid().to_string()}),
        ));
        println!(
            "\n{EXPECTED_PREFIX}{}",
            serde_json::to_string(&expected).unwrap()
        );
        return;
    }

    let test_name = format!(
        "{}::production_json_logging",
        module_path!().split_once("::").unwrap().1,
    );
    for values in [false, true] {
        for source in [false, true] {
            let output = Command::new(env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture", "--test-threads=1"])
                .env(CHILD_MODE, "1")
                .env("STACKS_LOG_JSON", "1")
                .env("STACKS_LOG_DEBUG", "0")
                .env("BLOCKSTACK_DEBUG", "0")
                .env("STACKS_LOG_TRACE", "0")
                .env("STACKS_LOG_CRITONLY", "0")
                .env("STACKS_LOG_CLARITY_VALUES", if values { "1" } else { "0" })
                .env("STACKS_LOG_CONTRACT_SOURCE", if source { "1" } else { "0" })
                .output()
                .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(
                output.status.success(),
                "values={values}, source={source}:\n{stdout}\n{stderr}"
            );
            let expected: Vec<ExpectedRecord> = serde_json::from_str(
                stdout
                    .lines()
                    .find_map(|line| line.strip_prefix(EXPECTED_PREFIX))
                    .expect("child must execute the fixture and emit expectations"),
            )
            .unwrap();
            let records: Vec<JsonValue> = stderr
                .lines()
                .filter(|line| line.starts_with('{'))
                .map(|line| serde_json::from_str(line).expect("valid production JSON log"))
                .collect();
            assert_records(&records, expected, values, source);
        }
    }
}

/// Require exactly one complete record per expectation, including absent keys.
fn assert_records(
    records: &[JsonValue],
    expected: Vec<ExpectedRecord>,
    values: bool,
    source: bool,
) {
    for expected in expected {
        let matching: Vec<_> = records
            .iter()
            .filter(|record| {
                expected
                    .selector
                    .as_object()
                    .unwrap()
                    .iter()
                    .all(|(key, value)| record.get(key) == Some(value))
            })
            .collect();
        assert_eq!(matching.len(), 1, "record selector: {}", expected.selector);
        let mut actual = (*matching.first().unwrap()).clone();
        let object = actual.as_object_mut().unwrap();
        for key in ["ts", "file", "line", "thread"] {
            assert!(
                object.remove(key).is_some(),
                "production logger metadata: {key}"
            );
        }
        let enabled = match expected.setting {
            DetailSetting::Values => values,
            DetailSetting::Source => source,
        };
        assert_eq!(
            actual,
            if enabled {
                expected.full
            } else {
                expected.summary
            },
            "values={values}, source={source}"
        );
    }
}

/// Sign deterministic fixture transactions with consecutive nonces.
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

/// Execute successful and failing calls, then exercise each problematic-payload record.
fn contract_records() -> Vec<ExpectedRecord> {
    let key = Secp256k1PrivateKey::from_seed(b"production-json-logging");
    let address = TransactionAuth::from_p2pkh(&key)
        .unwrap()
        .origin()
        .address_testnet();
    fs::create_dir_all("/tmp/stacks-node-tests").unwrap();
    let directory = TempDirBuilder::new()
        .prefix("cs-json-logging-")
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
        .with_balances(vec![(address.clone(), 1_000_000)])
        .build();
    let burn_db = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch40,
    };
    let mut conn = chainstate.block_begin(
        &burn_db,
        &FIRST_BURNCHAIN_CONSENSUS_HASH,
        &FIRST_STACKS_BLOCK_HASH,
        &ConsensusHash([1; 20]),
        &BlockHeaderHash([1; 32]),
    );
    let source = "(define-public (echo (value (buff 4096))) (ok value))
                  (define-public (fail (value (buff 4096))) (ok (/ u1 u0)))";
    let publish = signed_tx(
        &key,
        0,
        TransactionPayload::new_smart_contract("json-logging", source, None).unwrap(),
    );
    let (_, receipt) =
        StacksChainState::process_transaction(&mut conn, &publish, true, None).unwrap();
    assert_eq!(receipt.result, Value::okay(Value::Bool(true)).unwrap());
    let value = Value::buff_from(vec![0xab; 4096]).unwrap();
    let mut expected = Vec::new();
    let mut calls = Vec::new();
    for (index, function) in ["echo", "fail"].into_iter().enumerate() {
        let tx = signed_tx(
            &key,
            index as u64 + 1,
            TransactionPayload::new_contract_call(
                address.clone(),
                "json-logging",
                function,
                vec![value.clone()],
            )
            .unwrap(),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, true, None).unwrap();
        let mut common = json!({
            "msg": "Contract-call successfully processed", "level": "INFO",
            "txid": tx.txid().to_string(), "origin": address.to_string(),
            "origin_nonce": (index + 1).to_string(),
            "contract_name": format!("{address}.json-logging"), "function_name": function,
        });
        let mut full_fields =
            json!({"function_args": format!("{}", VecDisplay(slice::from_ref(&value)))});
        if function == "echo" {
            let result = Value::okay(value.clone()).unwrap();
            assert_eq!(receipt.result, result);
            assert!(receipt.vm_error.is_none());
            full_fields
                .as_object_mut()
                .unwrap()
                .insert("return_value".into(), json!(result.to_string()));
            common.as_object_mut().unwrap().insert(
                "cost".into(),
                json!(format!("{:?}", receipt.execution_cost)),
            );
        } else {
            assert_eq!(receipt.result, Value::err_none());
            common.as_object_mut().unwrap().insert(
                "msg".into(),
                json!("Contract-call processed with runtime error"),
            );
            common.as_object_mut().unwrap().insert(
                "error".into(),
                json!(receipt.vm_error.expect("runtime error receipt").to_string()),
            );
        }
        expected.push(ExpectedRecord::new(
            DetailSetting::Values,
            common,
            full_fields,
            json!({}),
        ));
        calls.push(tx);
    }
    conn.rollback_block();
    // Source summaries must use the transaction's network, including mainnet.
    let mut mainnet_publish = publish.clone();
    mainnet_publish.version = TransactionVersion::Mainnet;
    for tx in [calls.first().unwrap(), &publish, &mainnet_publish] {
        for (error, message, detail) in [
            (
                Error::InvalidFee,
                "Problematic transaction caused InvalidFee",
                None,
            ),
            (
                Error::ExecutionResourceBudgetExceeded("execution-probe".into()),
                "Problematic transaction caused ExecutionResourceBudgetExceeded",
                Some("execution-probe"),
            ),
            (
                Error::AnalysisResourceBudgetExceeded("analysis-probe".into()),
                "Problematic transaction caused AnalysisResourceBudgetExceeded",
                Some("analysis-probe"),
            ),
            (
                Error::ClarityError(ClarityError::ExecutionResourceBudgetExceeded(
                    "clarity-probe".into(),
                )),
                "Problematic transaction caused ExecutionResourceBudgetExceeded",
                Some("clarity-probe"),
            ),
        ] {
            let (problematic, _) =
                TransactionResult::is_problematic(tx, error, StacksEpochId::Epoch40);
            assert!(problematic);
            let mut common = json!({
                "msg": message, "level": "INFO", "txid": tx.txid().to_string(),
                "origin": tx.origin_address().to_string(),
            });
            if let Some(detail) = detail {
                common
                    .as_object_mut()
                    .unwrap()
                    .insert("error".into(), json!(detail));
            }
            let mut summary =
                json!({"contract_name": format!("{}.json-logging", tx.origin_address())});
            let setting = if matches!(tx.payload, TransactionPayload::ContractCall(_)) {
                summary
                    .as_object_mut()
                    .unwrap()
                    .insert("function_name".into(), json!("echo"));
                DetailSetting::Values
            } else {
                DetailSetting::Source
            };
            expected.push(ExpectedRecord::new(
                setting,
                common,
                json!({"payload": format!("{:?}", tx.payload)}),
                summary,
            ));
        }
    }
    expected
}
