use crate::cli::CliCtx;

pub fn exec(ctx: &CliCtx) {
    let mut stmt = ctx
        .db()
        .prepare(
            "SELECT block_id, block_hash, length(data) as data_len, \
             external_offset, external_length \
             FROM marf_data ORDER BY block_id",
        )
        .unwrap();

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, u64>(3)?,
                row.get::<_, u64>(4)?,
            ))
        })
        .unwrap();

    println!(
        "{:>8}  {:>10}  {:>10}  {:>12}  {:>12}  block_hash",
        "block_id", "inline_len", "ext_len", "ext_offset", "storage"
    );
    println!("{}", "-".repeat(90));

    for row in rows {
        let (block_id, bhh_hex, inline_len, ext_offset, ext_length) = row.unwrap();
        let storage = if ext_length > 0 {
            "external"
        } else if inline_len > 0 {
            "inline"
        } else {
            "empty"
        };
        println!(
            "{block_id:>8}  {inline_len:>10}  {ext_length:>10}  {ext_offset:>12}  {storage:>12}  {bhh_hex}"
        );
    }

    if let Some(blobs_path) = ctx.blobs_path()
        && let Ok(meta) = std::fs::metadata(blobs_path)
    {
        println!("\nExternal blobs file size: {} bytes", meta.len());
    }
}
