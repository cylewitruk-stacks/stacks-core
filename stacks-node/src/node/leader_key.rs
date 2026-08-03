// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Leader-key registration state and persistence.

use std::fs;
use std::io::{Read, Write};

use stacks::burnchains::Txid;
use stacks::chainstate::burn::operations::{BlockstackOperationType, LeaderKeyRegisterOp};
use stacks::chainstate::burn::{ConsensusHash, SortitionHash};
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey};

use crate::Keychain;

const MOCK_MINER_VRF_KEY_HEIGHT: u64 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisteredKey {
    /// burn block height we intended this VRF key register to land in
    pub target_block_height: u64,
    /// burn block height it actually landed in
    pub block_height: u64,
    /// offset in the block's tx list where this operation is
    pub op_vtxindex: u32,
    /// the public key itself
    pub vrf_public_key: VRFPublicKey,
    /// `memo` field that was used to register key
    /// Could be `Hash160(miner_pubkey)`, or empty
    pub memo: Vec<u8>,
}

impl RegisteredKey {
    /// Construct the synthetic registration used by mock-mining nodes.
    ///
    /// Protocol callers retain responsibility for choosing the registration
    /// memo, while the fixed key height and unmined location remain shared.
    pub fn for_mock_mining(keychain: &Keychain, memo: Vec<u8>) -> Self {
        let (vrf_public_key, _) = keychain.make_vrf_keypair(MOCK_MINER_VRF_KEY_HEIGHT);
        Self {
            target_block_height: MOCK_MINER_VRF_KEY_HEIGHT,
            block_height: 1,
            op_vtxindex: 1,
            vrf_public_key,
            memo,
        }
    }
}

#[derive(Clone, Default)]
pub enum LeaderKeyRegistrationState {
    #[default]
    Inactive,
    Pending(u64, Txid),
    Active(RegisteredKey),
}

impl LeaderKeyRegistrationState {
    pub fn get_active(&self) -> Option<RegisteredKey> {
        if let Self::Active(registered_key) = self {
            Some(registered_key.clone())
        } else {
            None
        }
    }
}

/// Construct the protocol-neutral portion of a leader-key registration.
///
/// Callers retain responsibility for selecting the memo and deciding when and
/// how to submit the operation.
pub fn make_leader_key_register_op(
    public_key: VRFPublicKey,
    consensus_hash: ConsensusHash,
    memo: Vec<u8>,
) -> BlockstackOperationType {
    BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
        public_key,
        memo,
        consensus_hash,
        vtxindex: 0,
        txid: Txid([0u8; 32]),
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash::zero(),
    })
}

/// Generate and report the VRF proof used by either protocol miner.
pub fn generate_vrf_proof(
    keychain: &mut Keychain,
    mock_mining: bool,
    registered_key: &RegisteredKey,
    sortition_hash: &SortitionHash,
    burn_block_height: u64,
    burn_block_hash: &BurnchainHeaderHash,
) -> Option<VRFProof> {
    let key_height = if mock_mining {
        MOCK_MINER_VRF_KEY_HEIGHT
    } else {
        registered_key.target_block_height
    };
    let proof = keychain.generate_proof(key_height, sortition_hash.as_bytes());

    let Some(proof) = proof else {
        error!(
            "Unable to generate VRF proof, will be unable to mine";
            "burn_block_sortition_hash" => %sortition_hash,
            "burn_block_block_height" => burn_block_height,
            "burn_block_hash" => %burn_block_hash,
            "vrf_pubkey" => registered_key.vrf_public_key.to_hex()
        );
        return None;
    };

    debug!(
        "Generated VRF Proof: {} over {} ({},{}) with key {}",
        proof.to_hex(),
        sortition_hash,
        burn_block_height,
        burn_block_hash,
        registered_key.vrf_public_key.to_hex()
    );
    Some(proof)
}

/// Read and deserialize a persisted leader key.
///
/// Protocol implementations retain ownership of deciding whether the decoded key is acceptable.
/// In particular, Nakamoto additionally validates the registration memo against its mining key.
pub fn load_activated_vrf_key(path: &str) -> Option<RegisteredKey> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            warn!("Could not open {path}: {error:?}");
            return None;
        }
    };
    let mut registered_key_bytes = vec![];
    if let Err(error) = file.read_to_end(&mut registered_key_bytes) {
        warn!("Failed to read registered key bytes from {path}: {error:?}");
        return None;
    }

    let Ok(registered_key) = serde_json::from_slice(&registered_key_bytes) else {
        warn!("Did not load registered key from {path}: could not decode JSON");
        return None;
    };

    Some(registered_key)
}

pub fn save_activated_vrf_key(path: &str, activated_key: &RegisteredKey) {
    info!("Activated VRF key; saving to {path}");
    let Ok(key_json) = serde_json::to_string(activated_key) else {
        warn!("Failed to serialize VRF key");
        return;
    };
    let mut file = match fs::File::create(path) {
        Ok(file) => file,
        Err(error) => {
            warn!("Failed to create {path}: {error:?}");
            return;
        }
    };
    if let Err(error) = file.write_all(key_json.as_bytes()) {
        warn!("Failed to write activated VRF key to {path}: {error:?}");
        return;
    }
    info!("Saved activated VRF key to {path}");
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;

    use stacks::burnchains::Txid;
    use stacks::chainstate::burn::operations::BlockstackOperationType;
    use stacks::chainstate::burn::{ConsensusHash, SortitionHash};
    use stacks_common::types::chainstate::BurnchainHeaderHash;
    use stacks_common::util::vrf::{VRFPrivateKey, VRFPublicKey};
    use tempfile::tempdir;

    use super::{
        generate_vrf_proof, load_activated_vrf_key, make_leader_key_register_op, RegisteredKey,
    };
    use crate::Keychain;

    #[test]
    fn leader_key_operation_uses_caller_identity_and_unmined_defaults() {
        let public_key = VRFPublicKey::from_private(&VRFPrivateKey::new());
        let consensus_hash = ConsensusHash([7; 20]);
        let memo = vec![1, 2, 3];

        let operation =
            make_leader_key_register_op(public_key.clone(), consensus_hash.clone(), memo.clone());
        let BlockstackOperationType::LeaderKeyRegister(operation) = operation else {
            panic!("expected leader-key registration");
        };

        assert_eq!(operation.public_key, public_key);
        assert_eq!(operation.consensus_hash, consensus_hash);
        assert_eq!(operation.memo, memo);
        assert_eq!(operation.vtxindex, 0);
        assert_eq!(operation.txid, Txid([0; 32]));
        assert_eq!(operation.block_height, 0);
        assert_eq!(operation.burn_header_hash, BurnchainHeaderHash::zero());
    }

    #[test]
    fn vrf_proof_uses_the_protocol_selected_key_height() {
        let mut keychain = Keychain::default(vec![1; 32]);
        let (registered_public_key, _) = keychain.make_vrf_keypair(42);
        keychain.make_vrf_keypair(1);
        let registered_key = RegisteredKey {
            target_block_height: 42,
            block_height: 43,
            op_vtxindex: 0,
            vrf_public_key: registered_public_key,
            memo: vec![],
        };
        let sortition_hash = SortitionHash([2; 32]);
        let burn_block_hash = BurnchainHeaderHash([3; 32]);

        let registered_proof = generate_vrf_proof(
            &mut keychain,
            false,
            &registered_key,
            &sortition_hash,
            100,
            &burn_block_hash,
        )
        .expect("registered key should produce a proof");
        let mock_proof = generate_vrf_proof(
            &mut keychain,
            true,
            &registered_key,
            &sortition_hash,
            100,
            &burn_block_hash,
        )
        .expect("mock key should produce a proof");

        assert_ne!(registered_proof, mock_proof);

        let mock_key = RegisteredKey::for_mock_mining(&keychain, vec![1, 2, 3]);
        assert_eq!(mock_key.target_block_height, 1);
        assert_eq!(mock_key.block_height, 1);
        assert_eq!(mock_key.op_vtxindex, 1);
        assert_eq!(mock_key.memo, vec![1, 2, 3]);
    }

    #[test]
    fn load_nonexistent_vrf_key() {
        let directory = tempdir().expect("Failed to create temporary directory");
        let path = directory.path().join("does_not_exist.json");

        assert!(load_activated_vrf_key(path.to_str().unwrap()).is_none());
    }

    #[test]
    fn load_empty_vrf_key() {
        let directory = tempdir().expect("Failed to create temporary directory");
        let path = directory.path().join("empty.json");
        File::create(&path).expect("Failed to create test file");

        assert!(load_activated_vrf_key(path.to_str().unwrap()).is_none());
    }

    #[test]
    fn load_bad_vrf_key() {
        let directory = tempdir().expect("Failed to create temporary directory");
        let path = directory.path().join("invalid_saved_key.json");
        let json_content = r#"{ "hello": "world" }"#;

        let mut file = File::create(&path).expect("Failed to create test file");
        file.write_all(json_content.as_bytes())
            .expect("Failed to write to test file");

        assert!(load_activated_vrf_key(path.to_str().unwrap()).is_none());
    }
}
