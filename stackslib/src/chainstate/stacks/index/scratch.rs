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

use crate::chainstate::stacks::index::node::{
    ParkedNodeHandle, TrieLeafRef, TrieLeafSquashed, TrieLeafSquashedRef, TrieNode, TrieNode16,
    TrieNode256, TrieNode4, TrieNode48, TrieNodeID, TrieNodePatch, TrieNodeRef, TrieNodeType,
    TriePtr,
};
use crate::chainstate::stacks::index::{
    Error, NodeDecodeScratch, NodeParking, NodePatching, TrieLeaf, TrieNodeArena,
};

#[derive(Debug, Default)]
pub struct MarfReadState {
    node4: Option<TrieNode4>,
    node16: Option<TrieNode16>,
    node48: Option<TrieNode48>,
    node256: Option<TrieNode256>,
    leaf: Option<TrieLeaf>,
    leaf_squashed: Option<TrieLeafSquashed>,
    patch: Option<TrieNodePatch>,
    node_bytes: Vec<u8>,
    /// Reusable buffer for patch chain accumulation. Taken by `take_patch_chain_buf` and restored
    /// by `restore_patch_chain_buf` to avoid per-read allocation in the patch-chasing loop.
    patch_chain_buf: Vec<(u32, TriePtr, TrieNodePatch)>,
    owned: Option<TrieNodeType>,
    parked: Vec<TrieNodeType>,
    current_id: Option<TrieNodeID>,
}

impl MarfReadState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn take_node_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.node_bytes)
    }

    pub fn take_patch_chain_buf(&mut self) -> Vec<(u32, TriePtr, TrieNodePatch)> {
        let mut buf = std::mem::take(&mut self.patch_chain_buf);
        buf.clear();
        buf
    }

    pub fn restore_patch_chain_buf(&mut self, buf: Vec<(u32, TriePtr, TrieNodePatch)>) {
        self.patch_chain_buf = buf;
    }

    pub fn restore_node_bytes(&mut self, node_bytes: Vec<u8>) {
        self.node_bytes = node_bytes;
    }

    pub fn clear_current_node(&mut self) {
        self.current_id = None;
        self.owned = None;
    }

    pub fn has_current_node(&self) -> bool {
        self.current_id.is_some()
    }

    pub fn clear_parked_nodes(&mut self) {
        self.parked.clear();
    }

    pub fn get_parked_ref(&self, parked_handle: ParkedNodeHandle) -> TrieNodeRef<'_> {
        let node = self
            .parked
            .get(parked_handle.slot())
            .expect("BUG: decode scratch missing parked node slot");
        TrieNodeRef::from(node)
    }

    pub fn park_owned_node(&mut self, node: TrieNodeType) -> ParkedNodeHandle {
        self.parked.push(node);
        ParkedNodeHandle::new(self.parked.len() - 1)
    }

    pub fn park_current_node(&mut self) -> Result<ParkedNodeHandle, Error> {
        let node = match self.current_id.take().ok_or_else(|| {
            Error::CorruptionError("decode scratch has no current node to park".to_string())
        })? {
            TrieNodeID::Node4 => TrieNodeType::Node4(
                self.node4
                    .take()
                    .expect("BUG: decode scratch lost node4 before parking"),
            ),
            TrieNodeID::Node16 => TrieNodeType::Node16(
                self.node16
                    .take()
                    .expect("BUG: decode scratch lost node16 before parking"),
            ),
            TrieNodeID::Node48 => TrieNodeType::Node48(Box::new(
                self.node48
                    .take()
                    .expect("BUG: decode scratch lost node48 before parking"),
            )),
            TrieNodeID::Node256 => TrieNodeType::Node256(Box::new(
                self.node256
                    .take()
                    .expect("BUG: decode scratch lost node256 before parking"),
            )),
            TrieNodeID::Leaf => TrieNodeType::Leaf(
                self.leaf
                    .take()
                    .expect("BUG: decode scratch lost leaf before parking"),
            ),
            TrieNodeID::Empty => self
                .owned
                .take()
                .expect("BUG: decode scratch lost owned node before parking"),
            TrieNodeID::Patch => {
                return Err(Error::CorruptionError(
                    "Cannot park patch nodes in decode scratch".to_string(),
                ));
            }
            TrieNodeID::LeafSquashed => TrieNodeType::LeafSquashed(
                self.leaf_squashed
                    .take()
                    .expect("BUG: decode scratch lost leaf_squashed before parking"),
            ),
        };

        Ok(self.park_owned_node(node))
    }

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
                    indexes: n.indexes(),
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
            TrieNodeID::Patch => {
                unreachable!("BUG: patch nodes are never stored in decode scratch")
            }
            TrieNodeID::LeafSquashed => {
                let n = self.leaf_squashed.as_ref().unwrap();
                // tip_value() is infallible here: entries were validated
                // non-empty at construction and deserialization. The trait
                // signature (`fn get_ref -> TrieNodeRef`) does not permit
                // error propagation, so we expect.
                TrieNodeRef::LeafSquashed(TrieLeafSquashedRef {
                    path: n.path.as_slice(),
                    tip_value: n
                        .tip_value()
                        .expect("BUG: LeafSquashed invariant violated: entries is empty"),
                    entries: &n.entries,
                })
            }
        }
    }

    pub fn to_owned_node(&self) -> TrieNodeType {
        match self
            .current_id
            .expect("BUG: decode scratch has no current node")
        {
            TrieNodeID::Node4 => TrieNodeType::Node4(
                self.node4
                    .as_ref()
                    .expect("BUG: decode scratch lost node4")
                    .clone(),
            ),
            TrieNodeID::Node16 => TrieNodeType::Node16(
                self.node16
                    .as_ref()
                    .expect("BUG: decode scratch lost node16")
                    .clone(),
            ),
            TrieNodeID::Node48 => TrieNodeType::Node48(Box::new(
                self.node48
                    .as_ref()
                    .expect("BUG: decode scratch lost node48")
                    .clone(),
            )),
            TrieNodeID::Node256 => TrieNodeType::Node256(Box::new(
                self.node256
                    .as_ref()
                    .expect("BUG: decode scratch lost node256")
                    .clone(),
            )),
            TrieNodeID::Leaf => TrieNodeType::Leaf(
                self.leaf
                    .as_ref()
                    .expect("BUG: decode scratch lost leaf")
                    .clone(),
            ),
            TrieNodeID::Empty => self
                .owned
                .as_ref()
                .expect("BUG: decode scratch lost owned node")
                .clone(),
            TrieNodeID::Patch => {
                unreachable!("BUG: patch nodes are never stored in decode scratch")
            }
            TrieNodeID::LeafSquashed => TrieNodeType::LeafSquashed(
                self.leaf_squashed
                    .as_ref()
                    .expect("BUG: decode scratch lost leaf_squashed")
                    .clone(),
            ),
        }
    }

    pub fn store(&mut self, node: TrieNodeType) -> TrieNodeRef<'_> {
        self.current_id = Some(TrieNodeID::Empty);
        self.owned = Some(node);
        TrieNodeRef::from(self.owned.as_ref().expect("BUG: decode scratch lost node"))
    }

    pub fn store_from_ref(&mut self, node: &TrieNodeType) -> TrieNodeRef<'_> {
        match node {
            TrieNodeType::Node4(n) => self.store_node4(n.clone()),
            TrieNodeType::Node16(n) => self.store_node16(n.clone()),
            TrieNodeType::Node48(n) => self.store_node48((**n).clone()),
            TrieNodeType::Node256(n) => self.store_node256((**n).clone()),
            TrieNodeType::Leaf(n) => self.store_leaf(n.clone()),
            TrieNodeType::LeafSquashed(_) => self.store(node.clone()),
        }
    }

    pub fn store_node4(&mut self, node: TrieNode4) -> TrieNodeRef<'_> {
        self.current_id = Some(TrieNodeID::Node4);
        self.node4 = Some(node);
        let n = self.node4.as_ref().expect("BUG: decode scratch lost node4");
        TrieNodeRef::Node4 {
            path: n.path.as_slice(),
            ptrs: &n.ptrs,
        }
    }

    pub fn store_node16(&mut self, node: TrieNode16) -> TrieNodeRef<'_> {
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

    pub fn store_node48(&mut self, node: TrieNode48) -> TrieNodeRef<'_> {
        self.current_id = Some(TrieNodeID::Node48);
        self.node48 = Some(node);
        let n = self
            .node48
            .as_ref()
            .expect("BUG: decode scratch lost node48");
        TrieNodeRef::Node48 {
            path: n.path.as_slice(),
            indexes: n.indexes(),
            ptrs: &n.ptrs,
        }
    }

    pub fn store_node256(&mut self, node: TrieNode256) -> TrieNodeRef<'_> {
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

    pub fn store_leaf(&mut self, node: TrieLeaf) -> TrieNodeRef<'_> {
        self.current_id = Some(TrieNodeID::Leaf);
        self.leaf = Some(node);
        let n = self.leaf.as_ref().expect("BUG: decode scratch lost leaf");
        TrieNodeRef::Leaf(TrieLeafRef {
            path: n.path.as_slice(),
            data: &n.data,
        })
    }

    pub fn patch(&self) -> &TrieNodePatch {
        self.patch
            .as_ref()
            .expect("BUG: decode scratch lost patch node")
    }

    pub fn take_patch(&mut self) -> TrieNodePatch {
        self.patch
            .take()
            .expect("BUG: decode scratch lost patch node")
    }

    pub fn apply_patches_in_place(
        &mut self,
        patches: &[(u32, TriePtr, TrieNodePatch)],
        cur_block_id: u32,
    ) -> Result<(), Error> {
        let added_depth = patches.len();
        let new_source = patches.last().map(|(block_id, ptr, _)| (*block_id, *ptr));

        match self
            .current_id
            .expect("BUG: decode scratch has no current node")
        {
            TrieNodeID::Node4 => {
                let node = self.node4.as_mut().expect("BUG: decode scratch lost node4");
                for (patch_block_id, _, patch) in patches.iter() {
                    if !patch.apply_to(node, *patch_block_id, cur_block_id) {
                        return Err(Error::CorruptionError(
                            "Failed to apply patches to node".to_string(),
                        ));
                    }
                }
                node.patch_depth += added_depth;
                node.last_patch_source = new_source.or(node.last_patch_source);
            }
            TrieNodeID::Node16 => {
                let node = self
                    .node16
                    .as_mut()
                    .expect("BUG: decode scratch lost node16");
                for (patch_block_id, _, patch) in patches.iter() {
                    if !patch.apply_to(node, *patch_block_id, cur_block_id) {
                        return Err(Error::CorruptionError(
                            "Failed to apply patches to node".to_string(),
                        ));
                    }
                }
                node.patch_depth += added_depth;
                node.last_patch_source = new_source.or(node.last_patch_source);
            }
            TrieNodeID::Node48 => {
                let node = self
                    .node48
                    .as_mut()
                    .expect("BUG: decode scratch lost node48");
                for (patch_block_id, _, patch) in patches.iter() {
                    if !patch.apply_to(node, *patch_block_id, cur_block_id) {
                        return Err(Error::CorruptionError(
                            "Failed to apply patches to node".to_string(),
                        ));
                    }
                }
                node.patch_depth += added_depth;
                node.last_patch_source = new_source.or(node.last_patch_source);
            }
            TrieNodeID::Node256 => {
                let node = self
                    .node256
                    .as_mut()
                    .expect("BUG: decode scratch lost node256");
                for (patch_block_id, _, patch) in patches.iter() {
                    if !patch.apply_to(node, *patch_block_id, cur_block_id) {
                        return Err(Error::CorruptionError(
                            "Failed to apply patches to node".to_string(),
                        ));
                    }
                }
                node.patch_depth += added_depth;
                node.last_patch_source = new_source.or(node.last_patch_source);
            }
            TrieNodeID::Leaf | TrieNodeID::Empty | TrieNodeID::Patch | TrieNodeID::LeafSquashed => {
                return Err(Error::CorruptionError(
                    "Cannot apply patches to non-intermediate decode scratch node".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn decode_node4_from_slice(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let node = self.node4.get_or_insert_with(TrieNode4::empty);
        let consumed = node.load_from_slice(bytes)?;
        self.owned = None;
        self.current_id = Some(TrieNodeID::Node4);
        Ok(consumed)
    }

    pub fn decode_node16_from_slice(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let node = self.node16.get_or_insert_with(TrieNode16::empty);
        let consumed = node.load_from_slice(bytes)?;
        self.owned = None;
        self.current_id = Some(TrieNodeID::Node16);
        Ok(consumed)
    }

    pub fn decode_node48_from_slice(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let node = self.node48.get_or_insert_with(TrieNode48::empty);
        let consumed = node.load_from_slice(bytes)?;
        self.owned = None;
        self.current_id = Some(TrieNodeID::Node48);
        Ok(consumed)
    }

    pub fn decode_node256_from_slice(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let node = self.node256.get_or_insert_with(TrieNode256::empty);
        let consumed = node.load_from_slice(bytes)?;
        self.owned = None;
        self.current_id = Some(TrieNodeID::Node256);
        Ok(consumed)
    }

    pub fn decode_leaf_from_slice(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let node = self.leaf.get_or_insert_with(TrieLeaf::empty);
        let consumed = node.load_from_slice(bytes)?;
        self.owned = None;
        self.current_id = Some(TrieNodeID::Leaf);
        Ok(consumed)
    }

    pub fn decode_leaf_squashed_from_slice(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let node = self.leaf_squashed.get_or_insert_with(|| TrieLeafSquashed {
            path: Default::default(),
            entries: Vec::new(),
        });
        let consumed = node.load_from_slice(bytes)?;
        self.owned = None;
        self.current_id = Some(TrieNodeID::LeafSquashed);
        Ok(consumed)
    }

    pub fn decode_patch_from_slice(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let node = self.patch.get_or_insert_with(|| TrieNodePatch {
            ptr: TriePtr::default(),
            ptr_diff: Vec::new(),
        });
        let consumed = node.load_from_slice(bytes)?;
        self.owned = None;
        self.current_id = Some(TrieNodeID::Patch);
        Ok(consumed)
    }

    /// Consolidated decode dispatcher. Routes to the appropriate per-type decode method.
    pub fn decode_node_from_slice(&mut self, id: TrieNodeID, bytes: &[u8]) -> Result<usize, Error> {
        match id {
            TrieNodeID::Node4 => self.decode_node4_from_slice(bytes),
            TrieNodeID::Node16 => self.decode_node16_from_slice(bytes),
            TrieNodeID::Node48 => self.decode_node48_from_slice(bytes),
            TrieNodeID::Node256 => self.decode_node256_from_slice(bytes),
            TrieNodeID::Leaf => self.decode_leaf_from_slice(bytes),
            TrieNodeID::LeafSquashed => self.decode_leaf_squashed_from_slice(bytes),
            _ => Err(Error::CorruptionError(format!(
                "Cannot decode node type {id:?} from slice"
            ))),
        }
    }
}

// --- Capability trait implementations ---
//
// These implement the NodeDecodeScratch / NodeParking / NodePatching traits.

impl NodeDecodeScratch for MarfReadState {
    fn take_node_bytes(&mut self) -> Vec<u8> {
        MarfReadState::take_node_bytes(self)
    }

    fn restore_node_bytes(&mut self, bytes: Vec<u8>) {
        MarfReadState::restore_node_bytes(self, bytes)
    }

    fn decode_node_from_slice(&mut self, id: TrieNodeID, bytes: &[u8]) -> Result<usize, Error> {
        MarfReadState::decode_node_from_slice(self, id, bytes)
    }

    fn decode_patch_from_slice(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        MarfReadState::decode_patch_from_slice(self, bytes)
    }

    fn get_ref(&self) -> TrieNodeRef<'_> {
        MarfReadState::get_ref(self)
    }

    fn patch(&self) -> &TrieNodePatch {
        MarfReadState::patch(self)
    }

    fn take_patch(&mut self) -> TrieNodePatch {
        MarfReadState::take_patch(self)
    }

    fn take_patch_chain_buf(&mut self) -> Vec<(u32, TriePtr, TrieNodePatch)> {
        MarfReadState::take_patch_chain_buf(self)
    }

    fn restore_patch_chain_buf(&mut self, buf: Vec<(u32, TriePtr, TrieNodePatch)>) {
        MarfReadState::restore_patch_chain_buf(self, buf)
    }

    /// Note: delegates to the inherent `MarfReadState::store()` method.
    /// When called through `&mut impl NodeDecodeScratch`, Rust dispatches to this trait method.
    /// When called as `self.store()` inside MarfReadState methods, Rust dispatches to the
    /// inherent method. Both have identical behavior.
    fn store(&mut self, node: TrieNodeType) -> TrieNodeRef<'_> {
        MarfReadState::store(self, node)
    }

    fn clear_current_node(&mut self) {
        MarfReadState::clear_current_node(self)
    }

    fn has_current_node(&self) -> bool {
        MarfReadState::has_current_node(self)
    }
}

impl NodeParking for MarfReadState {
    fn park_current_node(&mut self) -> Result<ParkedNodeHandle, Error> {
        MarfReadState::park_current_node(self)
    }

    fn park_owned_node(&mut self, node: TrieNodeType) -> ParkedNodeHandle {
        MarfReadState::park_owned_node(self, node)
    }

    fn get_parked_ref(&self, handle: ParkedNodeHandle) -> TrieNodeRef<'_> {
        MarfReadState::get_parked_ref(self, handle)
    }

    fn clear_parked_nodes(&mut self) {
        MarfReadState::clear_parked_nodes(self)
    }
}

impl NodePatching for MarfReadState {
    fn apply_patches_in_place(
        &mut self,
        patches: &[(u32, TriePtr, TrieNodePatch)],
        cur_block_id: u32,
    ) -> Result<(), Error> {
        MarfReadState::apply_patches_in_place(self, patches, cur_block_id)
    }
}

impl TrieNodeArena for MarfReadState {
    fn park<'a>(&'a mut self, node: TrieNodeType) -> TrieNodeRef<'a> {
        self.store(node)
    }
}

// TrieNodeReadState is now a marker trait with a blanket impl over
// NodeParking + NodePatching, so MarfReadState satisfies it automatically.
