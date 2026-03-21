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

use std::fs;

use rusqlite::{Connection, OpenFlags};

use super::*;
use crate::chainstate::stacks::index::file::*;
use crate::chainstate::stacks::index::test::marf::MarfTestExt as _;
use crate::chainstate::stacks::index::*;
use crate::util_lib::db::*;

fn db_path(test_name: &str) -> String {
    let path = format!("/tmp/{}.sqlite", test_name);
    path
}

fn setup_db(test_name: &str) -> Connection {
    let path = db_path(test_name);
    if fs::metadata(&path).is_ok() {
        fs::remove_file(&path).unwrap();
    }

    let mut db = sqlite_open(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        true,
    )
    .unwrap();
    trie_sql::create_tables_if_needed(&mut db).unwrap();
    db
}

#[test]
fn test_load_store_trie_blob() {
    let mut db = setup_db("test_load_store_trie_blob");
    let mut blobs =
        TrieFile::from_db_path(&db_path("test_load_store_trie_blob"), false, false).unwrap();
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db).unwrap();

    blobs
        .store_trie_blob::<BlockHeaderHash>(&db, &BlockHeaderHash([0x01; 32]), &[1, 2, 3, 4, 5])
        .unwrap();
    blobs
        .store_trie_blob::<BlockHeaderHash>(
            &db,
            &BlockHeaderHash([0x02; 32]),
            &[10, 20, 30, 40, 50],
        )
        .unwrap();

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x01; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap(), 0);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![1, 2, 3, 4, 5]);

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x02; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap(), 5);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![10, 20, 30, 40, 50]);
}

#[test]
fn test_migrate_existing_trie_blobs() {
    let test_file = "/tmp/test_migrate_existing_trie_blobs.sqlite";
    let test_blobs_file = "/tmp/test_migrate_existing_trie_blobs.sqlite.blobs";
    if fs::metadata(&test_file).is_ok() {
        fs::remove_file(&test_file).unwrap();
    }
    if fs::metadata(&test_blobs_file).is_ok() {
        fs::remove_file(&test_blobs_file).unwrap();
    }

    let (data, last_block_header, root_header_map) = {
        let marf_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", false);

        let f = TrieFileStorage::open(test_file, marf_opts).unwrap();
        let mut marf = MARF::from_storage(f);

        // make data to insert
        let data = make_test_insert_data(128, 128);
        let mut last_block_header = BlockHeaderHash::sentinel();
        for (i, block_data) in data.iter().enumerate() {
            let mut block_hash_bytes = [0u8; 32];
            block_hash_bytes[0..8].copy_from_slice(&(i as u64).to_be_bytes());

            let block_header = BlockHeaderHash(block_hash_bytes);
            marf.begin(&last_block_header, &block_header).unwrap();

            for (key, value) in block_data.iter() {
                let path = TrieHash::from_key(key);
                let leaf = TrieLeaf::from_value(&[], value.clone());
                marf.insert_raw(path, leaf).unwrap();
            }
            marf.commit().unwrap();
            last_block_header = block_header;
        }

        let root_header_map =
            trie_sql::read_all_block_hashes_and_roots::<BlockHeaderHash>(marf.sqlite_conn())
                .unwrap();
        (data, last_block_header, root_header_map)
    };

    // migrate
    let mut marf_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    marf_opts.force_db_migrate = true;

    let f = TrieFileStorage::open(test_file, marf_opts).unwrap();
    let mut marf = MARF::from_storage(f);

    // blobs file exists
    assert!(fs::metadata(&test_blobs_file).is_ok());

    // verify that the new blob structure is well-formed
    let blob_root_header_map = {
        let blobs = TrieFile::from_db_path(test_file, false, false).unwrap();
        let blob_root_header_map = blobs
            .read_all_block_hashes_and_roots::<BlockHeaderHash>(marf.sqlite_conn())
            .unwrap();
        blob_root_header_map
    };

    assert_eq!(blob_root_header_map.len(), root_header_map.len());
    for (e1, e2) in blob_root_header_map.iter().zip(root_header_map.iter()) {
        assert_eq!(e1, e2);
    }

    // verify that we can read everything from the blobs
    for block_data in data.iter() {
        for (key, value) in block_data.iter() {
            let path = TrieHash::from_key(key);
            let marf_leaf = TrieLeaf::from_value(&[], value.clone());

            let leaf = marf.internals().expect_path(&last_block_header, &path);

            assert_eq!(leaf.data.to_vec(), marf_leaf.data.to_vec());
        }
    }
}

fn make_test_marf_with_single_block(
    test_file: &str,
    external_blobs: bool,
) -> (MARF<BlockHeaderHash>, BlockHeaderHash) {
    let marf_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", external_blobs);
    let f = TrieFileStorage::open(test_file, marf_opts).unwrap();
    let mut marf = MARF::from_storage(f);

    let block_header = BlockHeaderHash([0x11; 32]);
    marf.begin(&BlockHeaderHash::sentinel(), &block_header)
        .unwrap();
    marf.insert_raw(
        TrieHash::from_key("stable-node-seam"),
        TrieLeaf::from_value(&[], MARFValue::from_value("stable-node-seam-value")),
    )
    .unwrap();
    marf.commit().unwrap();

    (marf, block_header)
}

fn assert_reopened_root_stable_node_bytes(
    marf: &mut MARF<BlockHeaderHash>,
    block_header: &BlockHeaderHash,
) {
    let mut reopened = marf.reopen_connection().unwrap();
    let (root_ptr, expected_hash) = {
        let mut conn = reopened.connection();
        conn.open_block(block_header).unwrap();
        let root_ptr = conn.root_trieptr();
        let expected_hash = conn.read_node_hash(&root_ptr).unwrap();
        (root_ptr, expected_hash)
    };

    let decoded_node = {
        let mut conn = reopened.connection();
        conn.open_block(block_header).unwrap();
        let mut scratch = MarfReadState::new();
        conn.read_node_with_state(&root_ptr, &mut scratch)
            .unwrap()
            .into_owned_node()
            .unwrap()
            .0
    };
    let decoded_ref = TrieNodeRef::from(&decoded_node);

    {
        let mut scratch = MarfReadState::new();
        let stable_node = reopened.read_node(&root_ptr, &mut scratch).unwrap();
        assert_eq!(stable_node.node_type(), Some(TrieNodeID::Node256));
        assert_eq!(stable_node.hash, Some(expected_hash));
        assert_eq!(stable_node.is_leaf().unwrap(), decoded_ref.is_leaf());
        assert_eq!(stable_node.path_bytes().unwrap(), decoded_ref.path_bytes());
        assert_eq!(stable_node.ptrs().unwrap(), decoded_ref.ptrs());
        assert_eq!(stable_node.walk(0x11).unwrap(), decoded_ref.walk(0x11));
        assert_eq!(stable_node.walk(0xaa).unwrap(), decoded_ref.walk(0xaa));
        assert_eq!(
            stable_node
                .as_leaf()
                .unwrap()
                .map(|leaf| leaf.data.to_vec()),
            decoded_ref.as_leaf().map(|leaf| leaf.data.to_vec())
        );
        assert_eq!(
            stable_node.as_node_ref().unwrap().0.ptrs(),
            decoded_ref.ptrs()
        );
        assert_eq!(stable_node.into_owned_node().unwrap().0, decoded_node);
    }

    // Verify that a second read_node call returns consistent results (per-node path).
    {
        let mut scratch = MarfReadState::new();
        let node = reopened.read_node(&root_ptr, &mut scratch).unwrap();
        assert_eq!(node.node_type(), Some(TrieNodeID::Node256));
        assert_eq!(node.hash, Some(expected_hash));
        assert_eq!(node.into_owned_node().unwrap().0, decoded_node);
    }

    let path = TrieHash::from_key("stable-node-seam");
    let expected_value = MARFValue::from_value("stable-node-seam-value");

    let reopened_value = reopened.get(block_header, "stable-node-seam").unwrap();
    assert_eq!(reopened_value, Some(expected_value.clone()));

    let reopened_value_from_hash = reopened.get_from_hash(block_header, &path).unwrap();
    assert_eq!(reopened_value_from_hash, Some(expected_value.clone()));

    let proof_entry = reopened
        .get_with_proof(block_header, "stable-node-seam")
        .unwrap()
        .expect("expected reopened proof for stable-node-seam");
    assert_eq!(proof_entry.0, expected_value);
    assert!(!proof_entry.1 .0.is_empty());

    let proof_entry_from_hash = reopened
        .get_with_proof_from_hash(block_header, &path)
        .unwrap()
        .expect("expected reopened proof from hash for stable-node-seam");
    assert_eq!(proof_entry_from_hash.0, expected_value);
    assert!(!proof_entry_from_hash.1 .0.is_empty());
}

#[test]
fn test_reopened_connection_stable_blob_seam_sqlite_backed() {
    let test_file = "/tmp/test_reopened_connection_stable_blob_seam_sqlite_backed.sqlite";
    if fs::metadata(test_file).is_ok() {
        fs::remove_file(test_file).unwrap();
    }

    let (mut marf, block_header) = make_test_marf_with_single_block(test_file, false);
    assert_reopened_root_stable_node_bytes(&mut marf, &block_header);
}

#[test]
fn test_reopened_connection_stable_blob_seam_external_backed() {
    let test_file = "/tmp/test_reopened_connection_stable_blob_seam_external_backed.sqlite";
    let test_blobs_file =
        "/tmp/test_reopened_connection_stable_blob_seam_external_backed.sqlite.blobs";
    if fs::metadata(test_file).is_ok() {
        fs::remove_file(test_file).unwrap();
    }
    if fs::metadata(test_blobs_file).is_ok() {
        fs::remove_file(test_blobs_file).unwrap();
    }

    let (mut marf, block_header) = make_test_marf_with_single_block(test_file, true);
    assert!(fs::metadata(test_blobs_file).is_ok());
    assert_reopened_root_stable_node_bytes(&mut marf, &block_header);
}
