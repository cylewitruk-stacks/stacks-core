use std::collections::VecDeque;

use clap::Args;
use clarity::types::chainstate::TRIEHASH_ENCODED_SIZE;
use stackslib::chainstate::stacks::index::node::{
    TrieNodeID, clear_ctrl_bits, is_backptr, is_compressed,
};
use stackslib::chainstate::stacks::index::storage::ROOT_PTR_DISK;

use crate::cli::CliCtx;
use crate::types::BlobEntry;
use crate::util::{backptr_count, child_count, decode_entry, node_type_name, read_blob};

#[derive(Args)]
pub struct TrieArgs {
    pub block_id: u32,
}

pub fn exec(ctx: &CliCtx, args: TrieArgs) {
    let TrieArgs { block_id } = args;

    let blob = read_blob(ctx, block_id);

    println!("Block {block_id}: blob size = {} bytes", blob.len());
    println!();
    println!(
        "{:>5}  {:>8}  {:>8}  {:>8}  {:>6}  {:>4}  {:>4}  {:<10}  path_len",
        "bfs#", "offset", "size", "end", "type", "kids", "bkpt", "encoding"
    );
    println!("{}", "-".repeat(85));

    let mut frontier: VecDeque<(u32, usize, u8)> = VecDeque::new();
    // Root is always Node256 at ROOT_PTR_DISK.
    frontier.push_back((0, ROOT_PTR_DISK as usize, TrieNodeID::Node256 as u8));

    let mut bfs_index = 0u32;

    while let Some((_parent_bfs, offset, ptr_id)) = frontier.pop_front() {
        if offset >= blob.len() {
            println!("{bfs_index:>5}  {offset:>8}  ERROR: offset past end of blob");
            bfs_index += 1;
            continue;
        }

        match decode_entry(&blob, offset, ptr_id) {
            Ok(BlobEntry::Node { node, consumed, .. }) => {
                let ntype = node_type_name(&node);
                let kids = child_count(&node);
                let bkpt = backptr_count(&node);
                let path_len = node.path_bytes().len();
                let compressed =
                    is_compressed(*blob.get(offset + TRIEHASH_ENCODED_SIZE).unwrap_or(&0));

                let encoding = if compressed { "compressed" } else { "normal" };

                println!(
                    "{bfs_index:>5}  {offset:>8}  {consumed:>8}  {:>8}  {ntype:>6}  {kids:>4}  {bkpt:>4}  {encoding:<10}  {path_len}",
                    offset + consumed,
                );

                // Enqueue children (non-empty, non-backptr).
                if !node.is_leaf() {
                    for ptr in node.ptrs().iter() {
                        if !ptr.is_empty() && !is_backptr(ptr.id()) {
                            frontier.push_back((
                                bfs_index,
                                ptr.ptr() as usize,
                                clear_ctrl_bits(ptr.id()),
                            ));
                        }
                    }
                }
            }
            Ok(BlobEntry::Patch {
                patch, consumed, ..
            }) => {
                let base_block = patch.ptr.back_block();
                let base_ptr = patch.ptr.ptr();
                let diff_count = patch.ptr_diff.len();

                println!(
                    "{bfs_index:>5}  {offset:>8}  {consumed:>8}  {:>8}  {:>6}  {diff_count:>4}      {:<10}  base=({base_block},{base_ptr})",
                    offset + consumed,
                    "Patch",
                    "patch",
                );

                // Patch nodes have new children in ptr_diff (non-empty, non-backptr).
                for ptr in patch.ptr_diff.iter() {
                    if !ptr.is_empty() && !is_backptr(ptr.id()) {
                        frontier.push_back((
                            bfs_index,
                            ptr.ptr() as usize,
                            clear_ctrl_bits(ptr.id()),
                        ));
                    }
                }
            }
            Err(e) => {
                println!("{bfs_index:>5}  {offset:>8}  ERROR: failed to decode: {e:?}");
            }
        }

        bfs_index += 1;
    }

    println!("\nTotal entries: {bfs_index}");
}
