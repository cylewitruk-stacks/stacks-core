use clap::Args;
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use stacks_common::util::hash::hex_bytes;
use stackslib::chainstate::stacks::index::marf::{
    MARF, MARFOpenOpts, MarfConnection, OWN_BLOCK_HEIGHT_KEY,
};
use stackslib::chainstate::stacks::index::storage::TrieFileStorage;

use crate::cli::CliCtx;

#[derive(Args)]
pub struct WalkArgs {
    /// Block hash to walk (hex string, 64 chars)
    pub block_hash: String,

    /// Optional parent block hash to inspect for __MARF_BLOCK_HEIGHT_SELF.
    #[arg(long)]
    pub parent_block_hash: Option<String>,

    /// MARF key to look up (default: __MARF_BLOCK_HEIGHT_SELF)
    #[arg(long, default_value = "__MARF_BLOCK_HEIGHT_SELF")]
    pub key: String,
}

pub fn exec(ctx: &CliCtx, args: WalkArgs) {
    let db_path = ctx.db_path().to_str().expect("DB path must be valid UTF-8");

    let block_hash = parse_block_hash(&args.block_hash, "block hash");
    let parent_block_hash = args
        .parent_block_hash
        .as_deref()
        .map(|hash| parse_block_hash(hash, "parent block hash"));

    let key = &args.key;
    let path = TrieHash::from_key(key);

    println!("Block:   {block_hash}");
    println!("Key:     {key}");
    println!("Path:    {path}");
    println!("Path[0]: 0x{:02x} (root child index)", path.0[0]);
    println!();

    // --- Test with mmap enabled ---
    println!("=== WITH MMAP ===");
    run_walk(
        db_path,
        ctx.blobs_path().is_some(),
        true,
        &block_hash,
        parent_block_hash.as_ref(),
        key,
    );

    // --- Test with mmap disabled ---
    println!();
    println!("=== WITHOUT MMAP ===");
    run_walk(
        db_path,
        ctx.blobs_path().is_some(),
        false,
        &block_hash,
        parent_block_hash.as_ref(),
        key,
    );
}

fn parse_block_hash(hash: &str, label: &str) -> StacksBlockId {
    let bytes = hex_bytes(hash).unwrap_or_else(|e| {
        eprintln!("Invalid hex {label} '{hash}': {e}");
        std::process::exit(1);
    });
    if bytes.len() != 32 {
        eprintln!("{label} must be 32 bytes (64 hex chars)");
        std::process::exit(1);
    }
    StacksBlockId::from_bytes(&bytes).expect("32 bytes should always work")
}

fn run_walk(
    db_path: &str,
    external_blobs: bool,
    mmap: bool,
    block_hash: &StacksBlockId,
    parent_block_hash: Option<&StacksBlockId>,
    key: &str,
) {
    let marf_opts = MARFOpenOpts {
        external_blobs,
        mmap,
        compress: false, // Read-only, doesn't matter
        ..MARFOpenOpts::default()
    };

    let f = TrieFileStorage::open(db_path, marf_opts).unwrap_or_else(|e| {
        eprintln!("Failed to open MARF: {e:?}");
        std::process::exit(1);
    });
    let mut marf = MARF::from_storage(f);

    // Step 1: open_block
    match marf.open_block(block_hash) {
        Ok(()) => println!("  open_block: OK"),
        Err(e) => {
            println!("  open_block: FAILED: {e:?}");
            return;
        }
    }

    // Step 2: get_block_height_of (the exact crash call)
    match marf.get_block_height_of(block_hash, block_hash) {
        Ok(Some(height)) => println!("  get_block_height_of: Ok(Some({height}))"),
        Ok(None) => println!("  get_block_height_of: Ok(None)  *** THIS IS THE BUG ***"),
        Err(e) => println!("  get_block_height_of: Err({e:?})"),
    }

    // Step 3: get_by_key for OWN_BLOCK_HEIGHT_KEY
    match MarfConnection::get(&mut marf, block_hash, key) {
        Ok(Some(val)) => println!("  get(\"{key}\"): Ok(Some({val:?}))"),
        Ok(None) => println!("  get(\"{key}\"): Ok(None)  *** KEY NOT FOUND ***"),
        Err(e) => println!("  get(\"{key}\"): Err({e:?})"),
    }

    if let Some(parent_hash) = parent_block_hash {
        match MarfConnection::get(&mut marf, parent_hash, OWN_BLOCK_HEIGHT_KEY) {
            Ok(Some(val)) => println!("  Parent {OWN_BLOCK_HEIGHT_KEY}: Ok(Some({val:?}))"),
            Ok(None) => {
                println!("  Parent {OWN_BLOCK_HEIGHT_KEY}: Ok(None)  *** PARENT ALSO MISSING ***")
            }
            Err(e) => println!("  Parent {OWN_BLOCK_HEIGHT_KEY}: Err({e:?})"),
        }
    }
}
