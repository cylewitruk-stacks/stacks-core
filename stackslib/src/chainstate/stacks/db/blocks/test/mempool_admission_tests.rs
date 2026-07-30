use super::*;
use crate::core::CHAIN_ID_TESTNET;

/// Build a stacks-transfer whose signature is from the wrong key (invalid).
/// Ported from the former `make_bad_stacks_transfer` helper in
/// `stacks-node/src/tests/mempool.rs`.
fn make_bad_stacks_transfer(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    recipient: &PrincipalData,
    amount: u64,
) -> StacksTransaction {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));

    let mut spending_condition =
        TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(sender))
            .expect("Failed to create p2pkh spending condition from public key.");
    spending_condition.set_nonce(nonce);
    spending_condition.set_tx_fee(tx_fee);
    let auth = TransactionAuth::Standard(spending_condition);

    let mut unsigned_tx = StacksTransaction::new(TransactionVersion::Testnet, auth, payload);
    unsigned_tx.chain_id = CHAIN_ID_TESTNET;

    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
    // sign with a random key, NOT `sender` -- yields an invalid signature
    tx_signer.sign_origin(&StacksPrivateKey::random()).unwrap();
    tx_signer.get_tx().unwrap()
}

/// Port of the former `mempool_setup_chainstate` integration test from
/// `stacks-node/src/tests/mempool.rs`.
///
/// It builds a chainstate that publishes the five contracts the original used
/// (`foo_contract`, `trait-contract`, `use-trait-contract`,
/// `implement-trait-contract`, `bad-trait-contract`) in a single anchored block,
/// then drives `StacksChainState::will_admit_mempool_tx` through the original's
/// rejection matrix and asserts the exact `MemPoolRejection` variants.
///
/// The fixture runs in Epoch 2.0 (the default `unit_test_pre_2_05` epochs), the
/// same epoch the original published in. The publisher account starts at 100_000
/// uSTX and pays 5 * 100 uSTX in publish fees, leaving 99_500 -- matching the
/// `NotEnoughFunds(.., 99500)` expectations carried over verbatim.
///
/// Dropped cases vs. the original: the four poison-microblock cases collapsed
/// into one. `will_admit_mempool_tx` now early-returns
/// `MemPoolRejection::Other("PoisonMicroblock transactions not accepted via mempool")`
/// for every poison-microblock payload before any microblock-key validation runs
/// (see the guard at the top of `will_admit_mempool_tx`). The original's
/// distinctions between poison variants (and the `Keychain`-derived microblock key
/// lookup they required) no longer affect the outcome, so a single poison case
/// covers the live behavior.
#[test]
fn mempool_will_admit_tx_rejection_matrix() {
    use clarity::vm::database::NULL_BURN_STATE_DB;

    use crate::core::test_util::sign_standard_single_sig_tx_anchor_mode_version;

    const FOO_CONTRACT: &str = "(define-public (foo) (ok 1))
                                (define-public (bar (x uint)) (ok x))";
    const TRAIT_CONTRACT: &str = "(define-trait tr ((value () (response uint uint))))";
    const USE_TRAIT_CONTRACT: &str = "(use-trait tr-trait .trait-contract.tr)
                                     (define-public (baz (abc <tr-trait>)) (ok (contract-of abc)))";
    const IMPLEMENT_TRAIT_CONTRACT: &str = "(define-public (value) (ok u1))";
    const BAD_TRAIT_CONTRACT: &str = "(define-public (foo-bar) (ok u1))";

    let chain_id = CHAIN_ID_TESTNET;

    // the publisher of all contracts and origin of every probe tx
    let contract_sk = StacksPrivateKey::from_hex(
        "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01",
    )
    .unwrap();
    let contract_addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&contract_sk)],
    )
    .unwrap();

    // the "other" account used as a recipient and for network-mismatch probes
    let other_sk = StacksPrivateKey::from_hex(
        "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201",
    )
    .unwrap();
    let other_addr: PrincipalData = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&other_sk)],
    )
    .unwrap()
    .into();

    let mut peer_config = TestPeerConfig::new(function_name!(), 0, 0);
    peer_config.chain_config.initial_balances =
        vec![(contract_addr.to_account_principal(), 100_000)];
    let mut peer = TestPeer::new(peer_config);

    let mut coinbase_nonce = 0;

    // mine one empty tenure to get a Stacks chain tip past genesis
    peer.tenure_with_txs(&[], &mut coinbase_nonce);

    // publish the five contracts in a single tenure (nonces 0..=4, fee 100 each).
    // 5 * 100 = 500 uSTX in fees, leaving the publisher with 99_500.
    let publish_txs = vec![
        make_user_contract_publish(&contract_sk, 0, 100, "foo_contract", FOO_CONTRACT),
        make_user_contract_publish(&contract_sk, 1, 100, "trait-contract", TRAIT_CONTRACT),
        make_user_contract_publish(
            &contract_sk,
            2,
            100,
            "use-trait-contract",
            USE_TRAIT_CONTRACT,
        ),
        make_user_contract_publish(
            &contract_sk,
            3,
            100,
            "implement-trait-contract",
            IMPLEMENT_TRAIT_CONTRACT,
        ),
        make_user_contract_publish(
            &contract_sk,
            4,
            100,
            "bad-trait-contract",
            BAD_TRAIT_CONTRACT,
        ),
    ];
    peer.tenure_with_txs(&publish_txs, &mut coinbase_nonce);

    peer.with_db_state(|sortdb, chainstate, _relayer, _mempool| {
        let (consensus_hash, block_hash) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
        let consensus_hash = &consensus_hash;
        let block_hash = &block_hash;

        let admit = |chainstate: &mut StacksChainState, tx: &StacksTransaction| {
            let len = tx.serialize_to_vec().len() as u64;
            chainstate.will_admit_mempool_tx(
                &NULL_BURN_STATE_DB,
                consensus_hash,
                block_hash,
                tx,
                len,
            )
        };

        // a couple of valid ones first
        let tx = make_user_contract_publish(&contract_sk, 5, 1000, "bar_contract", FOO_CONTRACT);
        admit(chainstate, &tx).unwrap();

        let tx = make_user_contract_call(
            &contract_sk,
            5,
            200,
            &contract_addr,
            "foo_contract",
            "bar",
            vec![Value::UInt(1)],
        );
        admit(chainstate, &tx).unwrap();

        // high-S signature: technically valid, but the mempool must reject it
        let tx = make_user_stacks_transfer(&contract_sk, 5, 200, &other_addr, 1000);
        let high_s_tx = tx.with_negated_s_in_signature();
        let e = admit(chainstate, &high_s_tx).unwrap_err();
        match e {
            MemPoolRejection::FailedToValidate(crate::chainstate::stacks::Error::NetError(
                net_error::VerifyingError(msg),
            )) => assert_eq!(msg, "Invalid signature: high-S"),
            _ => panic!("unexpected error {e:?} from high-S signature tx"),
        }

        // the original low-S signature is fine
        admit(chainstate, &tx).unwrap();

        // bad signature (signed by the wrong key)
        let tx = make_bad_stacks_transfer(&contract_sk, 5, 200, &other_addr, 1000);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(
            e,
            MemPoolRejection::FailedToValidate(crate::chainstate::stacks::Error::NetError(
                net_error::VerifyingError(_)
            ))
        ));

        // mismatched network on contract-call (mainnet address version byte)
        let bad_addr = StacksAddress::from_public_keys(
            18,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&other_sk)],
        )
        .unwrap();
        let tx = make_user_contract_call(
            &contract_sk,
            5,
            200,
            &bad_addr,
            "foo_contract",
            "bar",
            vec![Value::UInt(1), Value::Int(2)],
        );
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::BadAddressVersionByte));

        // mismatched network on transfer (mainnet recipient)
        let bad_recipient: PrincipalData = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&other_sk)],
        )
        .unwrap()
        .into();
        let tx = make_user_stacks_transfer(&contract_sk, 5, 200, &bad_recipient, 1000);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::BadAddressVersionByte));

        // bad fee
        let tx = make_user_stacks_transfer(&contract_sk, 5, 0, &other_addr, 1000);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::FeeTooLow(0, _)));

        // bad nonce (already used)
        let tx = make_user_stacks_transfer(&contract_sk, 0, 200, &other_addr, 1000);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::BadNonces(_)));

        // a nonce far beyond the account's exceeds the mempool chaining limit:
        // origin_max_nonce = account nonce (5) + 1 + MAXIMUM_MEMPOOL_TX_CHAINING
        let tx = make_user_stacks_transfer(&contract_sk, 40, 200, &other_addr, 1000);
        let e = admit(chainstate, &tx).unwrap_err();
        match e {
            MemPoolRejection::TooMuchChaining {
                max_nonce,
                actual_nonce,
                is_origin,
                ..
            } => {
                assert_eq!(max_nonce, 5 + 1 + MAXIMUM_MEMPOOL_TX_CHAINING);
                assert_eq!(actual_nonce, 40);
                assert!(is_origin);
            }
            _ => panic!("unexpected error {e:?} from too-much-chaining tx"),
        }

        // not enough funds (fee 110000 + amount 1000 = 111000 > 99500)
        let tx = make_user_stacks_transfer(&contract_sk, 5, 110000, &other_addr, 1000);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::NotEnoughFunds(111000, 99500)));

        // sender == recipient
        let contract_princ = PrincipalData::from(contract_addr.clone());
        let tx = make_user_stacks_transfer(&contract_sk, 5, 300, &contract_princ, 1000);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(if let MemPoolRejection::TransferRecipientIsSender(r) = e {
            r == contract_princ
        } else {
            false
        });

        // recipient must be testnet (mainnet version byte, constructed via StacksAddress::new)
        let testnet_recipient = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&other_sk)],
        )
        .unwrap();
        let mainnet_recipient = StacksAddress::new(
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            testnet_recipient.destruct().1,
        )
        .unwrap();
        let mainnet_princ = mainnet_recipient.into();
        let tx = make_user_stacks_transfer(&contract_sk, 5, 300, &mainnet_princ, 1000);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::BadAddressVersionByte));

        // tx version must be testnet
        let payload = TransactionPayload::TokenTransfer(
            PrincipalData::from(contract_addr.clone()),
            1000,
            TokenTransferMemo([0; 34]),
        );
        let tx = sign_standard_single_sig_tx_anchor_mode_version(
            payload,
            &contract_sk,
            5,
            300,
            chain_id,
            TransactionAnchorMode::OnChainOnly,
            TransactionVersion::Mainnet,
        );
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::BadTransactionVersion));

        // tx chain id must match the chain's. Signed WITH the wrong chain id so the
        // signature stays internally consistent and rejection comes from the chain-id
        // check in process_transaction_precheck, not from signature verification.
        // Recipient must differ from sender: the recipient-is-sender semantic check
        // runs before the precheck.
        let payload = TransactionPayload::TokenTransfer(
            PrincipalData::from(other_addr.clone()),
            1000,
            TokenTransferMemo([0; 34]),
        );
        let tx = sign_standard_single_sig_tx_anchor_mode_version(
            payload,
            &contract_sk,
            5,
            300,
            chain_id + 1,
            TransactionAnchorMode::OnChainOnly,
            TransactionVersion::Testnet,
        );
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::FailedToValidate(_)));

        // send amount must be positive
        let tx = make_user_stacks_transfer(&contract_sk, 5, 300, &other_addr, 0);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::TransferAmountMustBePositive));

        // not enough funds again (111000 > 99500)
        let tx = make_user_stacks_transfer(&contract_sk, 5, 110000, &other_addr, 1000);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::NotEnoughFunds(111000, 99500)));

        // not enough funds (fee 99700 + amount 1000 = 100700 > 99500)
        let tx = make_user_stacks_transfer(&contract_sk, 5, 99700, &other_addr, 1000);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::NotEnoughFunds(100700, 99500)));

        // contract-call against a contract that does not exist
        let tx = make_user_contract_call(
            &contract_sk,
            5,
            200,
            &contract_addr,
            "bar_contract",
            "bar",
            vec![Value::UInt(1)],
        );
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::NoSuchContract));

        // contract-call against a function that does not exist
        let tx = make_user_contract_call(
            &contract_sk,
            5,
            200,
            &contract_addr,
            "foo_contract",
            "foobar",
            vec![Value::UInt(1)],
        );
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::NoSuchPublicFunction));

        // contract-call with wrong argument types
        let tx = make_user_contract_call(
            &contract_sk,
            5,
            200,
            &contract_addr,
            "foo_contract",
            "bar",
            vec![Value::UInt(1), Value::Int(2)],
        );
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::BadFunctionArgument(_)));

        // re-publishing an existing contract
        let tx = make_user_contract_publish(&contract_sk, 5, 1000, "foo_contract", FOO_CONTRACT);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::ContractAlreadyExists(_)));

        // poison-microblock: rejected outright by will_admit_mempool_tx's guard,
        // regardless of the microblock contents/keys (see method-level comment).
        let microblock_1 = StacksMicroblockHeader {
            version: 0,
            sequence: 0,
            prev_block: BlockHeaderHash([0; 32]),
            tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
            signature: MessageSignature([1; 65]),
        };
        let microblock_2 = StacksMicroblockHeader {
            version: 0,
            sequence: 1,
            prev_block: BlockHeaderHash([0; 32]),
            tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
            signature: MessageSignature([1; 65]),
        };
        let tx = make_user_poison_microblock(
            &contract_sk,
            5,
            1000,
            TransactionPayload::PoisonMicroblock(microblock_1, microblock_2),
        );
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::Other(_)));

        // coinbase via mempool
        let tx = make_user_coinbase(&contract_sk, 5, 1000);
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::NoCoinbaseViaMempool));

        // trait argument that satisfies the trait -> accepted
        let implement_trait_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
            StandardPrincipalData::from(contract_addr.clone()),
            ContractName::from_literal("implement-trait-contract"),
        ));
        let tx = make_user_contract_call(
            &contract_sk,
            5,
            250,
            &contract_addr,
            "use-trait-contract",
            "baz",
            vec![Value::Principal(implement_trait_principal)],
        );
        admit(chainstate, &tx).unwrap();

        // trait argument that does NOT satisfy the trait -> rejected
        let bad_trait_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
            StandardPrincipalData::from(contract_addr.clone()),
            ContractName::from_literal("bad-trait-contract"),
        ));
        let tx = make_user_contract_call(
            &contract_sk,
            5,
            250,
            &contract_addr,
            "use-trait-contract",
            "baz",
            vec![Value::Principal(bad_trait_principal)],
        );
        let e = admit(chainstate, &tx).unwrap_err();
        assert!(matches!(e, MemPoolRejection::BadFunctionArgument(_)));

        Ok::<(), net_error>(())
    })
    .unwrap();
}

/// Unit coverage for the mempool-rejection JSON returned by `/v2/transactions`.
///
/// Ports the wire-format assertions of the former in-process `mempool_errors`
/// integration test (`stacks-node/src/tests/integrations.rs`). `into_json` is a
/// pure function, so the `reason` / `reason_data` contract clients depend on is
/// tested here directly instead of by booting a node + bitcoind. The mempool
/// *producing* these rejections is covered by `mempool_will_admit_tx_rejection_matrix`.
#[test]
fn mempool_rejection_into_json() {
    let txid = Txid([0x12; 32]);
    let principal: PrincipalData =
        StacksAddress::new(C32_ADDRESS_VERSION_TESTNET_SINGLESIG, Hash160([0x01; 20]))
            .unwrap()
            .into();

    // every rejection carries the same envelope
    let assert_envelope = |v: &serde_json::Value, reason: &str| {
        assert_eq!(v.get("txid").unwrap().as_str().unwrap(), txid.to_hex());
        assert_eq!(
            v.get("error").unwrap().as_str().unwrap(),
            "transaction rejected"
        );
        assert_eq!(v.get("reason").unwrap().as_str().unwrap(), reason);
    };

    // TooMuchChaining: nonce 30 exceeds the chaining limit of 26
    let v = MemPoolRejection::TooMuchChaining {
        max_nonce: 26,
        actual_nonce: 30,
        principal: principal.clone(),
        is_origin: true,
    }
    .into_json(&txid);
    assert_envelope(&v, "TooMuchChaining");
    let d = v.get("reason_data").unwrap();
    assert!(d.get("is_origin").unwrap().as_bool().unwrap());
    assert_eq!(
        d.get("principal").unwrap().as_str().unwrap(),
        principal.to_string()
    );
    assert_eq!(d.get("expected").unwrap().as_u64().unwrap(), 26);
    assert_eq!(d.get("actual").unwrap().as_u64().unwrap(), 30);

    // FeeTooLow(actual, expected): a 180-byte tx paying a fee of 1
    let v = MemPoolRejection::FeeTooLow(1, 180).into_json(&txid);
    assert_envelope(&v, "FeeTooLow");
    let d = v.get("reason_data").unwrap();
    assert_eq!(d.get("expected").unwrap().as_u64().unwrap(), 180);
    assert_eq!(d.get("actual").unwrap().as_u64().unwrap(), 1);

    // NotEnoughFunds(expected, actual): amounts are 0x-prefixed, 32-hex-digit big-endian
    let v = MemPoolRejection::NotEnoughFunds(2456, 990).into_json(&txid);
    assert_envelope(&v, "NotEnoughFunds");
    let d = v.get("reason_data").unwrap();
    assert_eq!(
        d.get("expected").unwrap().as_str().unwrap(),
        format!("0x{:032x}", 2456u128)
    );
    assert_eq!(
        d.get("actual").unwrap().as_str().unwrap(),
        format!("0x{:032x}", 990u128)
    );

    // a sponsored tx running its sponsor out of funds surfaces the same shape
    let v = MemPoolRejection::NotEnoughFunds(2000, 990).into_json(&txid);
    assert_envelope(&v, "NotEnoughFunds");
    let d = v.get("reason_data").unwrap();
    assert_eq!(
        d.get("expected").unwrap().as_str().unwrap(),
        format!("0x{:032x}", 2000u128)
    );
    assert_eq!(
        d.get("actual").unwrap().as_str().unwrap(),
        format!("0x{:032x}", 990u128)
    );
}
