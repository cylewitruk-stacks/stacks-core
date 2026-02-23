// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
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

use stacks_common::types::chainstate::{StacksBlockId, TrieHash};

use crate::chainstate::stacks::index::node::{
    TrieCursor, TrieNode16, TrieNode256, TrieNode4, TrieNode48, TrieNodeID, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::scratch::{MarfReadScratch, TrieNodeDecodeScratch};
use crate::chainstate::stacks::index::{MARFValue, TrieLeaf};

fn make_test_nodes() -> Vec<TrieNodeType> {
    let mut node4 = TrieNode4::new(&[0x01, 0x02]);
    node4.ptrs[0] = TriePtr::new(TrieNodeID::Leaf as u8, 0x11, 7);

    let mut node16 = TrieNode16::new(&[0x03, 0x04, 0x05]);
    node16.ptrs[0] = TriePtr::new(TrieNodeID::Node4 as u8, 0x22, 9);

    let mut node48 = TrieNode48::new(&[0x06, 0x07, 0x08, 0x09]);
    node48.indexes[0x33] = 0;
    node48.ptrs[0] = TriePtr::new(TrieNodeID::Node16 as u8, 0x33, 11);

    let mut node256 = TrieNode256::new(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e]);
    node256.ptrs[0x44] = TriePtr::new(TrieNodeID::Node48 as u8, 0x44, 13);

    let leaf = TrieLeaf::from_value(&[0x0f, 0x10], MARFValue::from_value("scratch-leaf"));

    vec![
        TrieNodeType::Node4(node4),
        TrieNodeType::Node16(node16),
        TrieNodeType::Node48(Box::new(node48)),
        TrieNodeType::Node256(Box::new(node256)),
        TrieNodeType::Leaf(leaf),
    ]
}

#[test]
fn trie_node_decode_scratch_store_and_get_ref_per_variant() {
    let mut scratch = TrieNodeDecodeScratch::new();

    for node in make_test_nodes() {
        let node_ref = scratch.store_from_ref(&node);
        assert_eq!(node_ref.to_owned_node(), node);

        let get_ref = scratch.get_ref();
        assert_eq!(get_ref.to_owned_node(), node);
    }
}

#[test]
fn trie_node_decode_scratch_overwrite_tracks_latest_node() {
    let mut scratch = TrieNodeDecodeScratch::new();

    let node4 = TrieNodeType::Node4(TrieNode4::new(&[0x01]));
    let node16 = TrieNodeType::Node16(TrieNode16::new(&[0x02, 0x03]));
    let leaf = TrieNodeType::Leaf(TrieLeaf::from_value(
        &[0x04, 0x05, 0x06],
        MARFValue::from_value("latest"),
    ));

    scratch.store_from_ref(&node4);
    assert_eq!(scratch.get_ref().to_owned_node(), node4);

    scratch.store_from_ref(&node16);
    assert_eq!(scratch.get_ref().to_owned_node(), node16);

    scratch.store_from_ref(&leaf);
    assert_eq!(scratch.get_ref().to_owned_node(), leaf);
}

#[test]
fn marf_read_scratch_cursor_lifecycle() {
    let mut scratch = MarfReadScratch::<StacksBlockId>::new();
    let path = TrieHash([0x11; 32]);

    assert!(scratch.cursor_ref().is_none());

    {
        let cursor = scratch.cursor_mut(&path);
        assert_eq!(cursor.path, path);
        cursor.index = 7;
    }

    let taken = scratch
        .take_cursor()
        .expect("expected cursor to be present");
    assert_eq!(taken.path, path);
    assert_eq!(taken.index, 7);
    assert!(scratch.cursor_ref().is_none());

    let custom_root = TriePtr::new(TrieNodeID::Node4 as u8, 0x55, 99);
    let custom_path = TrieHash([0x22; 32]);
    scratch.set_cursor(TrieCursor::new(&custom_path, custom_root));

    let cursor = scratch
        .cursor_ref()
        .expect("expected cursor after set_cursor");
    assert_eq!(cursor.path, custom_path);
    assert_eq!(cursor.ptr(), custom_root);
}

#[test]
fn marf_read_scratch_cursor_mut_is_idempotent() {
    let mut scratch = MarfReadScratch::<StacksBlockId>::new();
    let first_path = TrieHash([0x33; 32]);
    let second_path = TrieHash([0x44; 32]);

    {
        let cursor = scratch.cursor_mut(&first_path);
        cursor.index = 5;
    }

    // cursor_mut() must return the existing cursor and not replace it.
    let cursor = scratch.cursor_mut(&second_path);
    assert_eq!(cursor.path, first_path);
    assert_eq!(cursor.index, 5);
}
