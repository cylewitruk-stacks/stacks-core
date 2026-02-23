// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use stacks_common::types::chainstate::TrieHash;

use crate::chainstate::stacks::index::node::{
    TrieCursor, TrieLeafRef, TrieNode16, TrieNode256, TrieNode4, TrieNode48, TrieNodeID,
    TrieNodeRef, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::{MarfTrieId, TrieLeaf};

#[derive(Default)]
pub struct TrieNodeDecodeScratch {
    node4: Option<TrieNode4>,
    node16: Option<TrieNode16>,
    node48: Option<TrieNode48>,
    node256: Option<TrieNode256>,
    leaf: Option<TrieLeaf>,
    owned: Option<TrieNodeType>,
    current_id: Option<TrieNodeID>,
}

impl TrieNodeDecodeScratch {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn get_ref(&self) -> TrieNodeRef<'_> {
        match self
            .current_id
            .expect("BUG: decode scratch has no current node")
        {
            TrieNodeID::Node4 => {
                let n = self.node4.as_ref().unwrap();
                TrieNodeRef::Node4 {
                    path: n.path.as_slice(),
                    ptrs: &n.ptrs,
                }
            }
            TrieNodeID::Node16 => {
                let n = self.node16.as_ref().unwrap();
                TrieNodeRef::Node16 {
                    path: n.path.as_slice(),
                    ptrs: &n.ptrs,
                }
            }
            TrieNodeID::Node48 => {
                let n = self.node48.as_ref().unwrap();
                TrieNodeRef::Node48 {
                    path: n.path.as_slice(),
                    indexes: &n.indexes,
                    ptrs: &n.ptrs,
                }
            }
            TrieNodeID::Node256 => {
                let n = self.node256.as_ref().unwrap();
                TrieNodeRef::Node256 {
                    path: n.path.as_slice(),
                    ptrs: &n.ptrs,
                }
            }
            TrieNodeID::Leaf => {
                let n = self.leaf.as_ref().unwrap();
                TrieNodeRef::Leaf(TrieLeafRef {
                    path: n.path.as_slice(),
                    data: &n.data,
                })
            }
            TrieNodeID::Empty => {
                let n = self.owned.as_ref().unwrap();
                TrieNodeRef::from(n)
            }
        }
    }

    #[inline]
    pub fn store(&mut self, node: TrieNodeType) -> TrieNodeRef<'_> {
        self.current_id = Some(TrieNodeID::Empty);
        self.owned = Some(node);
        TrieNodeRef::from(self.owned.as_ref().expect("BUG: decode scratch lost node"))
    }

    #[inline]
    pub fn store_from_ref(&mut self, node: &TrieNodeType) -> TrieNodeRef<'_> {
        match node {
            TrieNodeType::Node4(n) => self.store_node4(n.clone()),
            TrieNodeType::Node16(n) => self.store_node16(n.clone()),
            TrieNodeType::Node48(n) => self.store_node48((**n).clone()),
            TrieNodeType::Node256(n) => self.store_node256((**n).clone()),
            TrieNodeType::Leaf(n) => self.store_leaf(n.clone()),
        }
    }

    #[inline]
    pub(crate) fn store_node4(&mut self, node: TrieNode4) -> TrieNodeRef<'_> {
        self.current_id = Some(TrieNodeID::Node4);
        self.node4 = Some(node);
        let n = self.node4.as_ref().expect("BUG: decode scratch lost node4");
        TrieNodeRef::Node4 {
            path: n.path.as_slice(),
            ptrs: &n.ptrs,
        }
    }

    #[inline]
    pub(crate) fn store_node16(&mut self, node: TrieNode16) -> TrieNodeRef<'_> {
        self.current_id = Some(TrieNodeID::Node16);
        self.node16 = Some(node);
        let n = self
            .node16
            .as_ref()
            .expect("BUG: decode scratch lost node16");
        TrieNodeRef::Node16 {
            path: n.path.as_slice(),
            ptrs: &n.ptrs,
        }
    }

    #[inline]
    pub(crate) fn store_node48(&mut self, node: TrieNode48) -> TrieNodeRef<'_> {
        self.current_id = Some(TrieNodeID::Node48);
        self.node48 = Some(node);
        let n = self
            .node48
            .as_ref()
            .expect("BUG: decode scratch lost node48");
        TrieNodeRef::Node48 {
            path: n.path.as_slice(),
            indexes: &n.indexes,
            ptrs: &n.ptrs,
        }
    }

    #[inline]
    pub(crate) fn store_node256(&mut self, node: TrieNode256) -> TrieNodeRef<'_> {
        self.current_id = Some(TrieNodeID::Node256);
        self.node256 = Some(node);
        let n = self
            .node256
            .as_ref()
            .expect("BUG: decode scratch lost node256");
        TrieNodeRef::Node256 {
            path: n.path.as_slice(),
            ptrs: &n.ptrs,
        }
    }

    #[inline]
    pub(crate) fn store_leaf(&mut self, node: TrieLeaf) -> TrieNodeRef<'_> {
        self.current_id = Some(TrieNodeID::Leaf);
        self.leaf = Some(node);
        let n = self.leaf.as_ref().expect("BUG: decode scratch lost leaf");
        TrieNodeRef::Leaf(TrieLeafRef {
            path: n.path.as_slice(),
            data: &n.data,
        })
    }
}

pub(crate) struct MarfReadScratch<T: MarfTrieId> {
    cursor: Option<TrieCursor<T>>,
    decode_scratch: TrieNodeDecodeScratch,
}

impl<T: MarfTrieId> Default for MarfReadScratch<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: MarfTrieId> MarfReadScratch<T> {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            cursor: None,
            decode_scratch: TrieNodeDecodeScratch::new(),
        }
    }

    #[inline]
    pub(crate) fn cursor_mut(&mut self, path: &TrieHash) -> &mut TrieCursor<T> {
        self.cursor
            .get_or_insert_with(|| TrieCursor::new(path, TriePtr::default()))
    }

    #[inline]
    pub(crate) fn take_cursor(&mut self) -> Option<TrieCursor<T>> {
        self.cursor.take()
    }

    #[inline]
    pub(crate) fn set_cursor(&mut self, cursor: TrieCursor<T>) {
        self.cursor = Some(cursor);
    }

    #[inline]
    pub(crate) fn cursor_ref(&self) -> Option<&TrieCursor<T>> {
        self.cursor.as_ref()
    }

    #[inline]
    pub(crate) fn decode_scratch(&self) -> &TrieNodeDecodeScratch {
        &self.decode_scratch
    }

    #[inline]
    pub(crate) fn decode_scratch_mut(&mut self) -> &mut TrieNodeDecodeScratch {
        &mut self.decode_scratch
    }
}
