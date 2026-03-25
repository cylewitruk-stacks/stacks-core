use std::collections::VecDeque;

use clap::Args;
use clarity::types::chainstate::TRIEHASH_ENCODED_SIZE;
use sha2::{Digest as _, Sha256};
use stackslib::chainstate::stacks::index::node::{
    TrieNodeID, clear_ctrl_bits, is_backptr, is_compressed,
};
use stackslib::chainstate::stacks::index::storage::ROOT_PTR_DISK;

use crate::cli::CliCtx;
use crate::types::BlobEntry;
use crate::util::{backptr_count, child_count, decode_entry, node_type_name, read_blob};

#[derive(Args)]
pub struct ManifestArgs {
    pub block_id: u32,
}

pub fn exec(ctx: &CliCtx, args: ManifestArgs) {
    let ManifestArgs { block_id } = args;
    let blob = read_blob(ctx, block_id);

    let blob_sha = Sha256::digest(&blob);
    println!(
        "Block {block_id}: blob size = {} bytes, sha256 = {:x}",
        blob.len(),
        blob_sha
    );
    println!();
    println!(
        "{:>5}  {:>8}  {:>6}  {:>8}  {:>4}  {:>4}  {:<8}  {:>8}  patch_info",
        "bfs#", "offset", "type", "size", "kids", "bkpt", "enc", "path_len"
    );
    println!("{}", "-".repeat(95));

    let mut frontier: VecDeque<(usize, u8)> = VecDeque::new();
    frontier.push_back((ROOT_PTR_DISK as usize, TrieNodeID::Node256 as u8));

    let mut bfs_index = 0u32;
    let mut total_normal = 0u32;
    let mut total_patch = 0u32;
    let mut total_normal_bytes = 0usize;
    let mut total_patch_bytes = 0usize;

    while let Some((offset, ptr_id)) = frontier.pop_front() {
        if offset >= blob.len() {
            println!("{bfs_index:>5}  {offset:>8}  ERROR: past end");
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
                let enc = if compressed { "comp" } else { "full" };

                println!(
                    "{bfs_index:>5}  {offset:>8}  {ntype:>6}  {consumed:>8}  {kids:>4}  {bkpt:>4}  {enc:<8}  {path_len:>8}"
                );

                total_normal += 1;
                total_normal_bytes += consumed;

                if !node.is_leaf() {
                    for ptr in node.ptrs().iter() {
                        if !ptr.is_empty() && !is_backptr(ptr.id()) {
                            frontier.push_back((ptr.ptr() as usize, clear_ctrl_bits(ptr.id())));
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
                    "{bfs_index:>5}  {offset:>8}  {:>6}  {consumed:>8}  {diff_count:>4}        {:<8}  {:>8}  base=({base_block},{base_ptr}) diffs={diff_count}",
                    "Patch", "patch", "",
                );

                total_patch += 1;
                total_patch_bytes += consumed;

                for ptr in patch.ptr_diff.iter() {
                    if !ptr.is_empty() && !is_backptr(ptr.id()) {
                        frontier.push_back((ptr.ptr() as usize, clear_ctrl_bits(ptr.id())));
                    }
                }
            }
            Err(e) => {
                println!("{bfs_index:>5}  {offset:>8}  ERROR: {e:?}");
            }
        }

        bfs_index += 1;
    }

    println!();
    println!("Summary:");
    println!("  Total entries:     {bfs_index}");
    println!("  Normal nodes:      {total_normal} ({total_normal_bytes} bytes)");
    println!("  Patch nodes:       {total_patch} ({total_patch_bytes} bytes)");
    println!(
        "  Patch ratio:       {:.1}%",
        if bfs_index > 0 {
            100.0 * total_patch as f64 / bfs_index as f64
        } else {
            0.0
        }
    );
}
