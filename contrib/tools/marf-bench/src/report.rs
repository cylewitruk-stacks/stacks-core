use std::collections::BTreeSet;

use crate::OutputFormat;
use crate::util::{log, pct, sort_rows, to_row_map};

#[derive(Debug, Clone)]
pub struct SummaryRow {
    benchmark: String,
    name: String,
    total_ms: f64,
    alloc_count: u64,
    alloc_bytes: u64,
}

impl SummaryRow {
    pub fn new(
        benchmark: impl Into<String>,
        name: impl Into<String>,
        total_ms: f64,
        alloc_count: u64,
        alloc_bytes: u64,
    ) -> Self {
        Self {
            benchmark: benchmark.into(),
            name: name.into(),
            total_ms,
            alloc_count,
            alloc_bytes,
        }
    }

    pub fn benchmark(&self) -> &str {
        &self.benchmark
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

pub fn print_single_run(output_format: OutputFormat, rows: &[SummaryRow]) {
    let sorted = sort_rows(rows);
    match output_format {
        OutputFormat::Tsv => {
            for row in sorted {
                println!(
                    "{}\t{}\t{:.3}\t{}\t{}",
                    row.benchmark, row.name, row.total_ms, row.alloc_count, row.alloc_bytes
                );
            }
        }
        OutputFormat::Summary | OutputFormat::Raw => {
            let benchmark_header = "benchmark";
            let name_header = "name";
            let benchmark_w = sorted
                .iter()
                .map(|row| row.benchmark().len())
                .max()
                .unwrap_or(benchmark_header.len())
                .max(benchmark_header.len())
                + 2;
            let name_w = sorted
                .iter()
                .map(|row| row.name().len())
                .max()
                .unwrap_or(name_header.len())
                .max(name_header.len())
                + 2;

            println!();
            log("Run summary");
            println!(
                "{:<benchmark_w$}{:<name_w$}{:>12}  {:>12}  {:>12}",
                benchmark_header,
                name_header,
                "total_ms",
                "alloc_count",
                "alloc_bytes",
                benchmark_w = benchmark_w,
                name_w = name_w,
            );
            for row in sorted {
                println!(
                    "{:<benchmark_w$}{:<name_w$}{:>12.3}  {:>12}  {:>12}",
                    row.benchmark,
                    row.name,
                    row.total_ms,
                    row.alloc_count,
                    row.alloc_bytes,
                    benchmark_w = benchmark_w,
                    name_w = name_w,
                );
            }
        }
    }
}

pub fn print_comparison(
    output_format: OutputFormat,
    base_label: &str,
    target_label: &str,
    base_rows: &[SummaryRow],
    target_rows: &[SummaryRow],
) {
    let base_map = to_row_map(base_rows);
    let target_map = to_row_map(target_rows);

    let mut keys = BTreeSet::new();
    for key in base_map.keys() {
        if target_map.contains_key(key) {
            keys.insert(key.clone());
        }
    }

    if output_format == OutputFormat::Tsv {
        for (benchmark, name) in keys {
            let base = &base_map[&(benchmark.clone(), name.clone())];
            let target = &target_map[&(benchmark.clone(), name.clone())];
            println!(
                "{}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.4}\t{}\t{}\t{}\t{:.4}\t{}\t{}\t{}\t{:.4}",
                benchmark,
                name,
                base.total_ms,
                target.total_ms,
                target.total_ms - base.total_ms,
                pct(base.total_ms, target.total_ms),
                base.alloc_count,
                target.alloc_count,
                target.alloc_count as i128 - base.alloc_count as i128,
                pct(base.alloc_count as f64, target.alloc_count as f64),
                base.alloc_bytes,
                target.alloc_bytes,
                target.alloc_bytes as i128 - base.alloc_bytes as i128,
                pct(base.alloc_bytes as f64, target.alloc_bytes as f64)
            );
        }
        return;
    }

    let mut rows: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = Vec::new();
    let mut benchmark_w = "benchmark".len();
    let mut name_w = "name".len();
    let mut total_w = "total(ms) b/t".len();
    let mut total_delta_w = "Δ".len();
    let mut count_w = "alloc_count b/t".len();
    let mut count_delta_w = "Δ".len();
    let mut bytes_w = "alloc_bytes b/t".len();
    let mut bytes_delta_w = "Δ".len();

    for (benchmark, name) in keys {
        let base = &base_map[&(benchmark.clone(), name.clone())];
        let target = &target_map[&(benchmark.clone(), name.clone())];

        let total_cell = format!("{:.3}/{:.3}", base.total_ms, target.total_ms);
        let total_delta_cell = format!("{:+.1}%", pct(base.total_ms, target.total_ms));
        let count_cell = format!("{}/{}", base.alloc_count, target.alloc_count);
        let count_delta_cell = format!(
            "{:+.1}%",
            pct(base.alloc_count as f64, target.alloc_count as f64)
        );
        let bytes_cell = format!("{}/{}", base.alloc_bytes, target.alloc_bytes);
        let bytes_delta_cell = format!(
            "{:+.1}%",
            pct(base.alloc_bytes as f64, target.alloc_bytes as f64)
        );

        benchmark_w = benchmark_w.max(benchmark.len());
        name_w = name_w.max(name.len());
        total_w = total_w.max(total_cell.len());
        total_delta_w = total_delta_w.max(total_delta_cell.len());
        count_w = count_w.max(count_cell.len());
        count_delta_w = count_delta_w.max(count_delta_cell.len());
        bytes_w = bytes_w.max(bytes_cell.len());
        bytes_delta_w = bytes_delta_w.max(bytes_delta_cell.len());

        rows.push((
            benchmark,
            name,
            total_cell,
            total_delta_cell,
            count_cell,
            count_delta_cell,
            bytes_cell,
            bytes_delta_cell,
        ));
    }

    println!();
    log("Comparison summary");
    println!("values: {base_label} / {target_label} / %delta");
    let divider = "-".repeat(
        benchmark_w
            + 2
            + name_w
            + 2
            + total_w
            + 2
            + total_delta_w
            + 2
            + count_w
            + 2
            + count_delta_w
            + 2
            + bytes_w
            + 2
            + bytes_delta_w,
    );
    println!(
        "{:<benchmark_w$}  {:<name_w$}  {:>total_w$}  {:>total_delta_w$}  {:>count_w$}  {:>count_delta_w$}  {:>bytes_w$}  {:>bytes_delta_w$}",
        "benchmark",
        "name",
        "total(ms) b/t",
        "Δ",
        "alloc_count b/t",
        "Δ",
        "alloc_bytes b/t",
        "Δ",
        benchmark_w = benchmark_w,
        name_w = name_w,
        total_w = total_w,
        total_delta_w = total_delta_w,
        count_w = count_w,
        count_delta_w = count_delta_w,
        bytes_w = bytes_w,
        bytes_delta_w = bytes_delta_w,
    );
    println!("{divider}");

    let mut current_benchmark: Option<String> = None;
    for (
        benchmark,
        name,
        total_cell,
        total_delta_cell,
        count_cell,
        count_delta_cell,
        bytes_cell,
        bytes_delta_cell,
    ) in rows
    {
        if let Some(prev) = &current_benchmark {
            if prev != &benchmark {
                println!("{divider}");
            }
        }
        println!(
            "{:<benchmark_w$}  {:<name_w$}  {:>total_w$}  {:>total_delta_w$}  {:>count_w$}  {:>count_delta_w$}  {:>bytes_w$}  {:>bytes_delta_w$}",
            &benchmark,
            name,
            total_cell,
            total_delta_cell,
            count_cell,
            count_delta_cell,
            bytes_cell,
            bytes_delta_cell,
            benchmark_w = benchmark_w,
            name_w = name_w,
            total_w = total_w,
            total_delta_w = total_delta_w,
            count_w = count_w,
            count_delta_w = count_delta_w,
            bytes_w = bytes_w,
            bytes_delta_w = bytes_delta_w,
        );
        current_benchmark = Some(benchmark);
    }
    println!("{divider}");
}
