use clap::Args;
use stackslib::chainstate::stacks::index::squash::{SQUASH_FOOTER_SIZE, SquashTrailer};
use stackslib::chainstate::stacks::index::trie_sql;

use crate::cli::CliCtx;

#[derive(Args)]
pub struct LevelsArgs {}

pub fn exec(ctx: &CliCtx, _args: LevelsArgs) {
    let levels = trie_sql::read_squash_levels(ctx.db()).unwrap_or_else(|e| {
        eprintln!("Failed to read marf_squash_levels: {e:?}");
        std::process::exit(1);
    });

    if levels.is_empty() {
        println!("(no squash levels)");
        return;
    }

    let blob_path = ctx.blobs_path().cloned().unwrap_or_else(|| {
        eprintln!("Cold blob file not found alongside DB; cannot read trailers");
        std::process::exit(1);
    });
    let blob_bytes = std::fs::read(&blob_path).unwrap_or_else(|e| {
        eprintln!("Failed to read {blob_path:?}: {e}");
        std::process::exit(1);
    });

    println!(
        "{:>7} {:>10} {:>10} {:>14} {:>13} {:>12} {:>15} {:>13} {:>15}",
        "level",
        "min_h",
        "max_h",
        "blob_off",
        "blob_len",
        "mode",
        "sidecar_present",
        "sidecar_trim",
        "reads_redir",
    );

    for level in &levels {
        let off = level.blob_offset as usize;
        let len = level.blob_length as usize;
        if off + len > blob_bytes.len() {
            eprintln!(
                "level {} blob_offset+length out of range (off={off}, len={len}, blob_size={})",
                level.level_id,
                blob_bytes.len()
            );
            continue;
        }
        let blob_slice = &blob_bytes[off..off + len];

        let footer_offset = match SquashTrailer::read_footer(blob_slice) {
            Some(f) => f as usize,
            None => {
                eprintln!("level {}: footer not found in blob slice", level.level_id);
                continue;
            }
        };
        let trailer_end = blob_slice.len().saturating_sub(SQUASH_FOOTER_SIZE);
        if footer_offset > trailer_end {
            eprintln!(
                "level {}: footer_offset={footer_offset} > trailer_end={trailer_end}",
                level.level_id
            );
            continue;
        }
        let trailer = match SquashTrailer::read_from(
            &blob_slice[footer_offset..trailer_end],
            level.blob_offset + footer_offset as u64,
        ) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("level {}: trailer parse failed: {e:?}", level.level_id);
                continue;
            }
        };

        let mode_label = format!("{:?}", trailer.info.mode);
        println!(
            "{:>7} {:>10} {:>10} {:>14} {:>13} {:>12} {:>15} {:>13} {:>15}",
            level.level_id,
            level.min_height,
            level.max_height,
            level.blob_offset,
            level.blob_length,
            mode_label,
            level.root_sidecar_present,
            level.root_sidecar_trimmed,
            level.reads_redirected,
        );
    }
}
