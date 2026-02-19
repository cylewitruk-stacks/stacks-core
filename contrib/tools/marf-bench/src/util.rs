use std::collections::BTreeMap;
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};

use crate::report::SummaryRow;

pub fn run_checked(mut cmd: Command, context: &str) -> Result<()> {
    let out = cmd
        .output()
        .with_context(|| format!("{context}: command execution failed"))?;
    if out.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    bail!(
        "{context}: {}{}{}",
        stdout.trim(),
        if !stdout.is_empty() && !stderr.is_empty() {
            "\n"
        } else {
            ""
        },
        stderr.trim()
    )
}

pub fn sanitize_revision(rev: &str) -> String {
    rev.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn log(message: &str) {
    eprintln!("[marf-bench] {message}");
}

pub fn to_row_map(rows: &[SummaryRow]) -> BTreeMap<(String, String), SummaryRow> {
    let mut map = BTreeMap::new();
    for row in rows {
        map.insert(
            (row.benchmark().to_string(), row.name().to_string()),
            row.clone(),
        );
    }
    map
}

pub fn sort_rows(rows: &[SummaryRow]) -> Vec<SummaryRow> {
    let mut sorted = rows.to_vec();
    sorted.sort_by(|a, b| {
        a.benchmark()
            .cmp(&b.benchmark())
            .then_with(|| a.name().cmp(&b.name()))
    });
    sorted
}

pub fn pct(base: f64, target: f64) -> f64 {
    if base == 0.0 {
        return 0.0;
    }
    ((target - base) * 100.0) / base
}

pub fn extract_summary_lines(text: &str) -> Vec<SummaryRow> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 6 || parts[0] != "summary" || parts[1] == "benchmark" {
            continue;
        }

        let total_ms = match parts[3].parse::<f64>() {
            Ok(value) => value,
            Err(_) => continue,
        };
        let alloc_count = match parts[4].parse::<u64>() {
            Ok(value) => value,
            Err(_) => continue,
        };
        let alloc_bytes = match parts[5].parse::<u64>() {
            Ok(value) => value,
            Err(_) => continue,
        };

        rows.push(SummaryRow::new(
            parts[1],
            parts[2],
            total_ms,
            alloc_count,
            alloc_bytes,
        ));
    }
    rows
}

pub fn combine_output_text(output: &Output) -> String {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

pub fn print_output(output: &Output) {
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
}
