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
use stacks_common::util::vrf::VRFPublicKey;

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

    use tempfile::tempdir;

    use super::load_activated_vrf_key;

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
