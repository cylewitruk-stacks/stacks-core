use core::fmt;

use serde::{Deserialize, Serialize};

const MERKLE_PATH_LEAF_TAG: u8 = 0x00;
const MERKLE_PATH_NODE_TAG: u8 = 0x01;

// hash function for Merkle trees
pub trait MerkleHashFunc {
    fn empty() -> Self
    where
        Self: Sized;
    fn from_tagged_data(tag: u8, data: &[u8]) -> Self
    where
        Self: Sized;
    fn bits(&self) -> &[u8];
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(C)]
pub enum MerklePathOrder {
    Left = 0x02,
    Right = 0x03,
}

pub struct MerkleTree<H: MerkleHashFunc> {
    // nodes[0] is the list of leaves
    // nodes[-1][0] is the root
    nodes: Vec<Vec<H>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MerklePathPoint<H: MerkleHashFunc> {
    pub order: MerklePathOrder,
    pub hash: H,
}

pub type MerklePath<H> = Vec<MerklePathPoint<H>>;

/// Merkle tree implementation with tagged nodes:
///
/// * A leaf hash is `H(0x00 + data)`
/// * A node hash is `H(0x01 + left.hash + right.hash)`
///
/// An empty tree has a root hash of `0x00000...00000`.
///
/// NOTE: This is consensus-critical code, because it is used to generate the transaction Merkle
/// tree roots in Stacks blocks.
impl<H> MerkleTree<H>
where
    H: MerkleHashFunc + Clone + PartialEq + fmt::Debug,
{
    pub fn empty() -> MerkleTree<H> {
        MerkleTree { nodes: vec![] }
    }

    pub fn new(data: &[Vec<u8>]) -> MerkleTree<H> {
        if data.is_empty() {
            return MerkleTree { nodes: vec![] };
        }

        let mut leaf_hashes: Vec<H> = data
            .iter()
            .map(|buf| MerkleTree::get_leaf_hash(&buf[..]))
            .collect();

        // force even number
        if !leaf_hashes.len().is_multiple_of(2) {
            let dup = leaf_hashes[leaf_hashes.len() - 1].clone();
            leaf_hashes.push(dup);
        }

        let mut nodes = vec![];
        nodes.push(leaf_hashes);

        loop {
            // next row
            let i = nodes.len() - 1;
            let capacity = nodes[i].len().saturating_add(1) / 2;
            let mut row_hashes = Vec::with_capacity(capacity);

            for j in 0..(nodes[i].len() / 2) {
                let h = MerkleTree::get_node_hash(&nodes[i][2 * j], &nodes[i][2 * j + 1]);
                row_hashes.push(h);
            }

            if row_hashes.len() == 1 {
                // at root
                nodes.push(row_hashes);
                break;
            }

            // force even
            if row_hashes.len() % 2 != 0 {
                let dup = row_hashes[row_hashes.len() - 1].clone();
                row_hashes.push(dup);
            }
            nodes.push(row_hashes);
        }

        MerkleTree { nodes }
    }

    /// Get the leaf hash
    pub fn get_leaf_hash(leaf_data: &[u8]) -> H {
        H::from_tagged_data(MERKLE_PATH_LEAF_TAG, leaf_data)
    }

    /// Get a non-leaf hash
    pub fn get_node_hash(left: &H, right: &H) -> H {
        let iter = left.bits().iter();
        let iter = iter.chain(right.bits().iter());
        let buf = iter.copied().collect::<Vec<_>>();
        H::from_tagged_data(MERKLE_PATH_NODE_TAG, &buf)
    }

    /// Find a given hash in a merkle tree row
    fn find_hash_index(&self, hash: &H, row_index: usize) -> Option<usize> {
        if row_index >= self.nodes.len() {
            panic!(
                "Tried to index Merkle tree at height {} (>= {})",
                row_index,
                self.nodes.len()
            );
        }
        (0..self.nodes[row_index].len()).find(|&i| self.nodes[row_index][i] == *hash)
    }

    /// Given an index into the Merkle tree, find the pair of hashes
    /// that comprise a sibling pair.
    /// Panics if the row_index or hash_index values are invalid.  In particular:
    /// * row_index must be positive and less than the number of rows
    /// * hash_index must correspond to a hash in its row
    /// * if hash_index is even, then it must have a right sibling
    fn find_siblings(&self, row_index: usize, hash_index: usize) -> (H, H) {
        if row_index == self.nodes.len() - 1 {
            panic!("Tried to find sibling of root");
        }

        if row_index >= self.nodes.len() {
            panic!(
                "Tried to index Merkle tree at height {} (>= {})",
                row_index,
                self.nodes.len()
            );
        }
        if hash_index >= self.nodes[row_index].len() {
            panic!(
                "Tried to index Merkle tree at column {} (>= {}) in row {}",
                hash_index,
                self.nodes[row_index].len(),
                row_index
            );
        }

        if hash_index.is_multiple_of(2) {
            if hash_index + 1 >= self.nodes[row_index].len() {
                panic!(
                    "Corrupt Merkle tree -- colunn {hash_index} is the last item in row {row_index}"
                );
            }

            // left sibling
            (
                self.nodes[row_index][hash_index].clone(),
                self.nodes[row_index][hash_index + 1].clone(),
            )
        } else {
            // right sibling
            (
                self.nodes[row_index][hash_index - 1].clone(),
                self.nodes[row_index][hash_index].clone(),
            )
        }
    }

    /// Get the Merkle root hash.
    /// will be all 0's if the tree is empty.
    pub fn root(&self) -> H {
        if !self.nodes.is_empty() {
            if !self.nodes[self.nodes.len() - 1].is_empty() {
                self.nodes[self.nodes.len() - 1][0].clone()
            } else {
                H::empty()
            }
        } else {
            H::empty()
        }
    }

    /// Get the path from the given data's leaf up to the root.
    /// will be None if the data isn't a leaf.
    pub fn path(&self, data: &[u8]) -> Option<MerklePath<H>> {
        let leaf_hash = MerkleTree::get_leaf_hash(data);
        let mut hash_index = self.find_hash_index(&leaf_hash, 0)?;

        let mut path: MerklePath<H> = Vec::with_capacity(self.nodes.len());

        let mut next_hash = leaf_hash;

        for i in 0..self.nodes.len() - 1 {
            let (left, right) = self.find_siblings(i, hash_index);
            if next_hash == left {
                // this is the left hash
                path.push(MerklePathPoint {
                    order: MerklePathOrder::Left,
                    hash: right.clone(),
                });
            } else {
                // this is the right hash
                path.push(MerklePathPoint {
                    order: MerklePathOrder::Right,
                    hash: left.clone(),
                });
            }

            next_hash = MerkleTree::get_node_hash(&left, &right);
            hash_index = self.find_hash_index(&next_hash, i + 1)?;
        }

        Some(path)
    }

    /// Verify a datum and its Merkle path against a Merkle root
    pub fn path_verify(data: &[u8], path: &MerklePath<H>, root: &H) -> bool {
        if path.is_empty() {
            // invalid path
            return false;
        }

        let mut hash_acc = MerkleTree::get_leaf_hash(data);
        for path_point in path {
            match path_point.order {
                MerklePathOrder::Left => {
                    hash_acc = MerkleTree::get_node_hash(&hash_acc, &path_point.hash);
                }
                MerklePathOrder::Right => {
                    hash_acc = MerkleTree::get_node_hash(&path_point.hash, &hash_acc);
                }
            }
        }

        hash_acc == *root
    }
}
