use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

use clap::Args;
use stacks_common::util::hash::to_hex;
use stackslib::chainstate::stacks::index::hot_file::hot_file_path;
use stackslib::chainstate::stacks::index::squash_plan::{discover_pending_plans, read_plan_file};
use stackslib::chainstate::stacks::index::trie_sql::{self, StorageKind};

use crate::cli::CliCtx;

#[derive(Args)]
pub struct PlanArgs {
    /// Explicit plan-file path. If omitted, discover pending plans for `--db`.
    #[arg(long)]
    pub path: Option<PathBuf>,

    /// If multiple pending plans exist, inspect this level id.
    #[arg(long)]
    pub level_id: Option<u32>,

    /// Show translation-map entries for this source block_id.
    #[arg(long)]
    pub translation_block_id: Option<u32>,

    /// Show rewrite-plan entries whose hot-file offsets fall within this block's current storage
    /// range. Also compares each entry's on-disk bytes to the plan's pre/post witnesses.
    #[arg(long)]
    pub rewrite_block_id: Option<u32>,

    /// When used with `--rewrite-block-id`, restrict output to entries whose block-relative
    /// `file_offset - block_offset` lies within `rewrite_near_offset +/- window`.
    #[arg(long)]
    pub rewrite_near_offset: Option<u64>,

    /// Maximum number of rows to print for filtered sections.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,

    /// Half-width for `--rewrite-near-offset`.
    #[arg(long, default_value_t = 128)]
    pub window: u64,
}

pub fn exec(ctx: &CliCtx, args: PlanArgs) {
    let plan_path = resolve_plan_path(ctx, &args);
    let plan = read_plan_file(&plan_path).unwrap_or_else(|e| {
        eprintln!("Failed to read plan {:?}: {e:?}", plan_path);
        std::process::exit(1);
    });

    println!("Plan path: {:?}", plan_path);
    println!(
        "Header: level_id={}, heights=[{}..={}], tip_at_scan_start={}, cold_blob=[{:#x}..{:#x})",
        plan.header.level_id,
        plan.header.min_height,
        plan.header.max_height,
        plan.header.tip_at_scan_start,
        plan.header.cold_blob_offset,
        plan.header.cold_blob_offset + plan.header.cold_blob_length,
    );
    println!(
        "Flags: reads_redirected={}, root_sidecar_present={}, root_sidecar_trimmed={}, orphan_split_offset={}, published_max_block_id={}",
        plan.header.reads_redirected,
        plan.header.root_sidecar_present,
        plan.header.root_sidecar_trimmed,
        plan.header.orphan_split_offset,
        plan.header.published_max_block_id,
    );
    println!(
        "Counts: in_range_blocks={}, translation_blocks={}, translation_entries={}, rewrites={}",
        plan.in_range_blocks.len(),
        plan.translation_map.by_block.len(),
        plan.translation_map.entry_count(),
        plan.rewrite_plan.len(),
    );
    println!("Sidecar: {}", plan.header.sidecar_path);
    println!(
        "Cold blob hash: {}",
        to_hex(plan.header.cold_blob_hash.as_bytes())
    );
    println!(
        "Sidecar hash:   {}",
        to_hex(plan.header.sidecar_hash.as_bytes())
    );

    if let Some(block_id) = args.translation_block_id {
        println!();
        print_translation_entries(&plan, block_id, args.limit);
    }

    if let Some(block_id) = args.rewrite_block_id {
        println!();
        print_rewrite_entries_for_block(
            ctx,
            &plan,
            block_id,
            args.rewrite_near_offset,
            args.window,
            args.limit,
        );
    }
}

fn resolve_plan_path(ctx: &CliCtx, args: &PlanArgs) -> PathBuf {
    if let Some(path) = &args.path {
        return path.clone();
    }

    let db_path = ctx.db_path().to_string_lossy().to_string();
    let plans = discover_pending_plans(&db_path).unwrap_or_else(|e| {
        eprintln!(
            "Failed to discover pending plans for {:?}: {e:?}",
            ctx.db_path()
        );
        std::process::exit(1);
    });
    if plans.is_empty() {
        eprintln!("No pending squash plans found for {:?}", ctx.db_path());
        std::process::exit(1);
    }

    if let Some(level_id) = args.level_id {
        if let Some((_, path)) = plans.into_iter().find(|(id, _)| *id == level_id) {
            return path;
        }
        eprintln!(
            "No pending plan with level_id={} for {:?}",
            level_id,
            ctx.db_path()
        );
        std::process::exit(1);
    }

    if plans.len() == 1 {
        return plans[0].1.clone();
    }

    eprintln!(
        "Multiple pending plans found for {:?}; pass --level-id or --path:",
        ctx.db_path()
    );
    for (level_id, path) in plans {
        eprintln!("  level_id={level_id}: {:?}", path);
    }
    std::process::exit(1);
}

fn print_translation_entries(
    plan: &stackslib::chainstate::stacks::index::squash_plan::SquashPlan,
    block_id: u32,
    limit: usize,
) {
    let Some(entries) = plan.translation_map.by_block.get(&block_id) else {
        println!("Translation map: no entries for block_id={block_id}");
        return;
    };

    println!(
        "Translation map for block_id={block_id}: {} entries",
        entries.len()
    );
    println!("   old_offset -> new_offset");
    for (idx, (old_offset, new_offset)) in entries.iter().enumerate() {
        if idx >= limit {
            println!("   ... {} more entries omitted", entries.len() - limit);
            break;
        }
        println!("   {:>10} -> {}", old_offset, new_offset);
    }
}

fn print_rewrite_entries_for_block(
    ctx: &CliCtx,
    plan: &stackslib::chainstate::stacks::index::squash_plan::SquashPlan,
    block_id: u32,
    rewrite_near_offset: Option<u64>,
    window: u64,
    limit: usize,
) {
    let location = trie_sql::get_trie_storage_location(ctx.db(), block_id).unwrap_or_else(|e| {
        eprintln!("Failed to resolve storage location for block_id={block_id}: {e:?}");
        std::process::exit(1);
    });

    println!(
        "Rewrite scan for block_id={block_id}: kind={:?}, seq={}, offset={}, length={}",
        location.kind, location.seq, location.offset, location.length
    );

    if location.kind != StorageKind::Hot {
        println!("Block is not hot-tier storage; rewrite entries only target hot files.");
        return;
    }

    let block_start = location.offset;
    let block_end = location.offset + location.length;
    let rel_start = rewrite_near_offset.map(|center| center.saturating_sub(window));
    let rel_end = rewrite_near_offset.map(|center| center.saturating_add(window));
    let mut matches: Vec<_> = plan
        .rewrite_plan
        .iter()
        .filter(|entry| {
            entry.hot_file_seq == location.seq
                && entry.file_offset >= block_start
                && entry.file_offset < block_end
                && rel_start.is_none_or(|start| entry.file_offset - block_start >= start)
                && rel_end.is_none_or(|end| entry.file_offset - block_start <= end)
        })
        .collect();
    matches.sort_by_key(|entry| entry.file_offset);

    match rewrite_near_offset {
        Some(center) => println!(
            "Matching rewrite entries near block-relative offset {} (+/- {}): {}",
            center,
            window,
            matches.len()
        ),
        None => println!(
            "Matching rewrite entries in this block range: {}",
            matches.len()
        ),
    }
    if matches.is_empty() {
        return;
    }

    let hot_path = hot_path_for_location(ctx.db_path(), location.seq);
    println!("Hot file: {:?}", hot_path);
    println!("   file_offset   rel_off      pre       post     current  state");
    for (idx, entry) in matches.iter().enumerate() {
        if idx >= limit {
            println!("   ... {} more entries omitted", matches.len() - limit);
            break;
        }
        let current = read_u32_witness(&hot_path, entry.file_offset);
        let state = if current == entry.pre_bytes {
            "pre"
        } else if current == entry.post_bytes {
            "post"
        } else {
            "other"
        };
        println!(
            "   {:>11} {:>9}  {}  {}  {}  {}",
            entry.file_offset,
            entry.file_offset - block_start,
            to_hex(&entry.pre_bytes),
            to_hex(&entry.post_bytes),
            to_hex(&current),
            state,
        );
    }
}

fn hot_path_for_location(db_path: &Path, seq: u32) -> PathBuf {
    let stem = db_path.to_string_lossy();
    PathBuf::from(hot_file_path(&stem, seq))
}

fn read_u32_witness(path: &Path, file_offset: u64) -> [u8; 4] {
    let mut f = std::fs::File::open(path).unwrap_or_else(|e| {
        eprintln!("Failed to open hot file {:?}: {e}", path);
        std::process::exit(1);
    });
    f.seek(SeekFrom::Start(file_offset)).unwrap_or_else(|e| {
        eprintln!("Failed to seek {:?} to {}: {e}", path, file_offset);
        std::process::exit(1);
    });
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf).unwrap_or_else(|e| {
        eprintln!(
            "Failed to read 4-byte witness at {:?}+{}: {e}",
            path, file_offset
        );
        std::process::exit(1);
    });
    buf
}
