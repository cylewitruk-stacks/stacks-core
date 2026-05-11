use clap::{Args, ValueEnum};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use stacks_common::util::hash::hex_bytes;
use stackslib::chainstate::stacks::index::marf::{MARF, MARFOpenOpts, MarfConnection};
use stackslib::chainstate::stacks::index::storage::TrieFileStorage;

use crate::cli::CliCtx;

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum WalkIntentArg {
    /// Default at-block read path (merged-tip + `LeafSquashed::value_at_height`).
    AtBlock,
    /// Fork-extension read path (per-height-root sidecar).
    ForkExtend,
    /// Run BOTH and print each result; useful for diagnosing merged-tip vs sidecar divergence.
    Both,
}

#[derive(Args)]
pub struct WalkArgs {
    /// Block hash to walk (hex string, 64 chars)
    pub block_hash: String,

    /// MARF key to look up (e.g., `vm::SP…boomboxes-cycle-18::4::b-18::…`). Hashed via
    /// `TrieHash::from_key` to derive the trie path. Mutually exclusive with `--key-path`.
    #[arg(long, conflicts_with = "key_path")]
    pub key: Option<String>,

    /// 32-byte trie path hex (64 chars). Use when you have the path directly (e.g. from a
    /// `MARF_SQUASH_TRACE leaf_path` log line). Mutually exclusive with `--key`.
    #[arg(long)]
    pub key_path: Option<String>,

    /// Which `WalkIntent` to use. `both` runs the lookup twice and prints both results — the
    /// fastest way to diagnose merged-tip vs per-height-root sidecar divergence.
    #[arg(long, value_enum, default_value_t = WalkIntentArg::AtBlock)]
    pub walk_intent: WalkIntentArg,
}

pub fn exec(ctx: &CliCtx, args: WalkArgs) {
    let db_path = ctx.db_path().to_str().expect("DB path must be valid UTF-8");

    let block_hash = {
        let bytes = hex_bytes(&args.block_hash).unwrap_or_else(|e| {
            eprintln!("Invalid hex block hash '{}': {e}", args.block_hash);
            std::process::exit(1);
        });
        if bytes.len() != 32 {
            eprintln!("Block hash must be 32 bytes (64 hex chars)");
            std::process::exit(1);
        }
        StacksBlockId::from_bytes(&bytes).expect("32 bytes should always work")
    };

    let (key_str, path) = match (&args.key, &args.key_path) {
        (Some(k), None) => (Some(k.clone()), TrieHash::from_key(k)),
        (None, Some(p)) => {
            let bytes = hex_bytes(p).unwrap_or_else(|e| {
                eprintln!("Invalid hex key path '{p}': {e}");
                std::process::exit(1);
            });
            if bytes.len() != 32 {
                eprintln!("Key path must be 32 bytes (64 hex chars)");
                std::process::exit(1);
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            (None, TrieHash(arr))
        }
        (None, None) => {
            eprintln!("must supply either --key or --key-path");
            std::process::exit(1);
        }
        (Some(_), Some(_)) => unreachable!("clap conflicts_with prevents this"),
    };

    println!("Block:        {block_hash}");
    if let Some(k) = &key_str {
        println!("Key:          {k}");
    }
    println!("Path:         {path}");
    println!("Path[0]:      0x{:02x} (root child index)", path.0[0]);
    println!("Walk-intent:  {:?}", args.walk_intent);
    println!();

    println!("=== WITH MMAP ===");
    run_walk(
        db_path,
        ctx.blobs_path().is_some(),
        true,
        &block_hash,
        &path,
        key_str.as_deref(),
        args.walk_intent,
    );

    println!();
    println!("=== WITHOUT MMAP ===");
    run_walk(
        db_path,
        ctx.blobs_path().is_some(),
        false,
        &block_hash,
        &path,
        key_str.as_deref(),
        args.walk_intent,
    );
}

fn run_walk(
    db_path: &str,
    external_blobs: bool,
    mmap: bool,
    block_hash: &StacksBlockId,
    path: &TrieHash,
    key_str: Option<&str>,
    walk_intent: WalkIntentArg,
) {
    let marf_opts = MARFOpenOpts {
        external_blobs,
        mmap,
        compress: false,
        ..MARFOpenOpts::default()
    };

    let f = TrieFileStorage::open(db_path, marf_opts).unwrap_or_else(|e| {
        eprintln!("Failed to open MARF: {e:?}");
        std::process::exit(1);
    });
    let mut marf = MARF::from_storage(f);

    match marf.open_block(block_hash) {
        Ok(()) => println!("  open_block: OK"),
        Err(e) => {
            println!("  open_block: FAILED: {e:?}");
            return;
        }
    }

    let lookup_at_block = |marf: &mut MARF<StacksBlockId>| {
        if let Some(k) = key_str {
            MarfConnection::get(marf, block_hash, k)
        } else {
            MarfConnection::get_from_hash(marf, block_hash, path)
        }
    };

    let lookup_fork_extend = |marf: &mut MARF<StacksBlockId>| {
        if let Some(k) = key_str {
            marf.get_with_fork_extend_intent(block_hash, k)
        } else {
            marf.get_path_with_fork_extend_intent(block_hash, path)
        }
    };

    let print_result = |label: &str, res: Result<Option<_>, _>| match res {
        Ok(Some(val)) => println!("  {label}: Ok(Some({val:?}))"),
        Ok(None) => println!("  {label}: Ok(None)  *** key not found ***"),
        Err(e) => println!("  {label}: Err({e:?})"),
    };

    match walk_intent {
        WalkIntentArg::AtBlock => print_result("AtBlock   ", lookup_at_block(&mut marf)),
        WalkIntentArg::ForkExtend => print_result("ForkExtend", lookup_fork_extend(&mut marf)),
        WalkIntentArg::Both => {
            print_result("AtBlock   ", lookup_at_block(&mut marf));
            print_result("ForkExtend", lookup_fork_extend(&mut marf));
        }
    }
}
