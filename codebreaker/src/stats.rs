use anyhow::{anyhow, bail, Result};
use hypercube::vhc::read_vhc_file;
use rand::Rng;
use std::cmp::min;
use std::collections::HashMap;
use std::path::Path;

pub struct StatsOptions {
    pub raw: bool,
    pub block: Option<usize>,
}

impl Default for StatsOptions {
    fn default() -> Self {
        Self {
            raw: false,
            block: None,
        }
    }
}

/// Run cryptanalysis on either a raw file or a Hypercube VHC block.
pub fn run(path: &Path, options: &StatsOptions) -> Result<String> {
    if options.raw {
        analyze_raw_file(path)
    } else {
        analyze_vhc_file(path, options.block)
    }
}

fn analyze_raw_file(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    if data.is_empty() {
        bail!("File is empty");
    }

    let mut output = String::new();
    output.push_str("Codebreaker Cryptanalysis\n");
    output.push_str("========================\n\n");
    output.push_str(&format!("File: {}\n", path.display()));
    output.push_str(&format!("Mode: Raw bytes\n"));
    output.push_str(&format!("Bytes analyzed: {}\n\n", data.len()));
    append_block_stats(&mut output, &data)?;
    Ok(output)
}

fn analyze_vhc_file(path: &Path, block: Option<usize>) -> Result<String> {
    let vhc = read_vhc_file(path)?;

    if vhc.blocks.is_empty() {
        return Err(anyhow!("No blocks in {}", path.display()));
    }

    let sequence_size = 16;
    let mac_size = vhc.header.mac_bytes();

    let block_idx = match block {
        Some(idx) => {
            if idx >= vhc.blocks.len() {
                bail!(
                    "Block index {} out of bounds (0..{})",
                    idx,
                    vhc.blocks.len() - 1
                );
            }
            idx
        }
        None => rand::thread_rng().gen_range(0..vhc.blocks.len()),
    };

    let full_block = &vhc.blocks[block_idx];
    if full_block.len() < sequence_size + mac_size {
        bail!("Block {} is too small to contain sequence+MAC", block_idx);
    }
    let data_start = sequence_size;
    let data_end = full_block.len() - mac_size;
    let block_data = &full_block[data_start..data_end];

    let mut output = String::new();
    output.push_str("Hypercube Block Cryptanalysis\n");
    output.push_str("=============================\n\n");
    output.push_str(&format!("File: {}\n", path.display()));
    output.push_str(&format!(
        "Block: {} (of {} total)\n",
        block_idx,
        vhc.blocks.len()
    ));
    output.push_str(&format!(
        "Block size: {} bytes (data only, excluding 16B seq + {}B MAC)\n\n",
        block_data.len(),
        mac_size
    ));

    append_block_stats(&mut output, block_data)?;
    Ok(output)
}

fn append_block_stats(output: &mut String, block_data: &[u8]) -> Result<()> {
    if block_data.is_empty() {
        bail!("Not enough bytes to analyze");
    }

    let mut dashboard = Dashboard::new("Cryptanalysis Results");

    // Frequency analysis
    let (most_common, least_common, _zero_count) = byte_frequency_analysis(block_data);
    let unique_bytes = count_unique_bytes(block_data);
    let ic = index_of_coincidence(block_data);
    let bigrams = top_ngrams(block_data, 2, 3);
    let trigrams = top_ngrams(block_data, 3, 3);
    let kasiski = kasiski_analysis(block_data);
    let crib = crib_coincidence(block_data);
    let mut freq_section = dashboard.section("Frequency Analysis");
    freq_section = freq_section
        .metric(
            "Unique Bytes",
            format!("{}/256", unique_bytes),
            format!(
                "Most common 0x{:02X} ({}×), least common 0x{:02X} ({}×)",
                most_common.0, most_common.1, least_common.0, least_common.1
            ),
            severity_unique(unique_bytes, block_data.len()),
        )
        .metric(
            "Index of Coincidence",
            format!("{:.4}", ic),
            "≈0.038 for random English text",
            severity_index_of_coincidence(ic),
        )
        .metric(
            "Top Bigrams",
            format_ngrams(&bigrams),
            "Highest-frequency 2-byte sequences",
            Severity::Pass,
        )
        .metric(
            "Top Trigrams",
            format_ngrams(&trigrams),
            "Highest-frequency 3-byte sequences",
            Severity::Pass,
        )
        .metric(
            "Kasiski Distances",
            kasiski.summary.clone(),
            "Repeated trigrams distance GCD",
            kasiski.severity,
        )
        .metric(
            "Crib Coincidence",
            format!(
                "shift {} ⇒ {} matches ({:.1}%)",
                crib.shift,
                crib.matches,
                crib.ratio * 100.0
            ),
            "Higher ratios imply repeating patterns",
            severity_crib(crib.ratio),
        );
    dashboard.add_section(freq_section);

    // Entropy & randomness section
    let entropy = calculate_entropy(block_data);
    let entropy_pct = (entropy / 8.0) * 100.0;
    let sliding = shingled_entropy(block_data, 32);
    let min_entropy = calculate_min_entropy(block_data);
    let renyi_entropy = calculate_renyi_entropy(block_data);
    let mut entropy_section = dashboard.section("Entropy & Randomness");
    entropy_section = entropy_section
        .metric(
            "Shannon Entropy",
            format!("{:.4} bits/byte ({:.1}% max)", entropy, entropy_pct),
            interpret_entropy(entropy),
            severity_entropy(entropy),
        )
        .metric(
            "Min-Entropy",
            format!("{:.4} bits/byte", min_entropy),
            "Worst-case unpredictability",
            severity_min_entropy(min_entropy),
        )
        .metric(
            "Rényi Entropy (α=2)",
            format!("{:.4} bits/byte", renyi_entropy),
            "Emphasizes repeated values",
            severity_entropy(renyi_entropy),
        )
        .metric(
            "Hamming Weight Bias",
            format!("{:.3}%", monobit_bias(block_data) * 100.0),
            "Deviation from 50/50 bit balance",
            severity_monobit(monobit_bias(block_data)),
        )
        .metric(
            "Sliding Entropy (32B)",
            format!(
                "avg {:.3} (min {:.3}, max {:.3})",
                sliding.average, sliding.min, sliding.max
            ),
            "Local randomness window",
            severity_entropy(sliding.average),
        );
    dashboard.add_section(entropy_section);

    // Distribution section
    let chi_square = calculate_chi_square(block_data);
    let chi_p_value = chi_square_p_value(chi_square, 255);
    let ks = kolmogorov_smirnov_uniform(block_data);
    let ad = anderson_darling_uniform(block_data);
    let kuiper = kuiper_uniform(block_data);
    let ascii_ratio = calculate_ascii_ratio(block_data);
    let mut dist_section = dashboard.section("Goodness-of-Fit");
    dist_section = dist_section
        .metric(
            "Chi-Square (df=255)",
            format!("{:.2} (p={})", chi_square, format_p_value(chi_p_value)),
            interpret_chi_square(chi_p_value),
            severity_p_value(chi_p_value),
        )
        .metric(
            "Kolmogorov–Smirnov",
            format!("D={:.4}, p={}", ks.d_stat, format_p_value(ks.p_value)),
            interpret_ks(ks.p_value),
            severity_p_value(ks.p_value),
        )
        .metric(
            "Anderson–Darling",
            format!("A²={:.3}", ad),
            "Higher ⇒ deviates from uniform",
            severity_anderson_darling(ad),
        )
        .metric(
            "Kuiper",
            format!("V={:.3}", kuiper),
            "Sensitive to tail differences",
            severity_kuiper(kuiper),
        )
        .metric(
            "ASCII Ratio",
            format!("{:.1}%", ascii_ratio * 100.0),
            interpret_ascii(ascii_ratio),
            severity_ascii(ascii_ratio),
        );
    dashboard.add_section(dist_section);

    // Correlation section
    let runs = calculate_runs_test(block_data);
    let correlation = calculate_serial_correlation(block_data);
    let autocorr = calculate_autocorrelation(block_data, &[1, 2, 4, 8, 16]);
    let cross = cross_correlation(block_data, 16);
    let mut corr_section = dashboard.section("Serial & Autocorrelation");
    corr_section = corr_section
        .metric(
            "Runs Test",
            format!("{} runs (expected {:.0})", runs.0, runs.1),
            interpret_runs(runs.0, runs.1),
            severity_runs(runs.0 as f64, runs.1),
        )
        .metric(
            "Serial Correlation",
            format!("{:.4}", correlation),
            interpret_correlation(correlation),
            severity_correlation(correlation),
        )
        .metric(
            "Autocorrelation (lags 1,2,4,8,16)",
            if autocorr.is_empty() {
                "n/a".to_string()
            } else {
                autocorr
                    .iter()
                    .map(|(lag, value)| format!("{}:{:+.3}", lag, value))
                    .collect::<Vec<_>>()
                    .join("  ")
            },
            "Correlation of shifted streams",
            severity_autocorr(&autocorr),
        )
        .metric(
            "Cross-correlation (16B shift)",
            format!("{:+.4}", cross),
            "Correlation between halves",
            severity_correlation(cross),
        );
    dashboard.add_section(corr_section);

    // Bit-plane section
    let bit_planes = bit_plane_stats(block_data);
    let mut bit_section = dashboard.section("Bit-Plane Uniformity");
    for plane in &bit_planes {
        bit_section = bit_section.metric(
            &format!("Bit {}", plane.bit),
            format!(
                "χ²={:.2}, p={}, ones={}/{}",
                plane.chi_square,
                format_p_value(plane.p_value),
                plane.ones,
                plane.total
            ),
            "Expect p≈0.5 for uniform bits",
            severity_p_value(plane.p_value),
        );
    }
    dashboard.add_section(bit_section);

    // Differential bias
    let xor_stats = xor_bias(block_data);
    let mut diff_section = dashboard.section("Differential Bias");
    diff_section = diff_section.metric(
        "XOR Δ bias",
        format!(
            "0x{:02X} occurs {:.2}% of time",
            xor_stats.byte,
            xor_stats.frequency * 100.0
        ),
        "Uniform XOR should be ≈0.39%",
        severity_xor_bias(xor_stats.frequency),
    );
    dashboard.add_section(diff_section);

    // Linear/differential metrics
    let bit_corr = bit_correlation_stats(block_data);
    let mut linear_section = dashboard.section("Linear/Differential Metrics");
    linear_section = linear_section.metric(
        "Bit correlation matrix",
        format!(
            "avg |r|={:.4}, max |r|={:.4}",
            bit_corr.avg_abs, bit_corr.max_abs
        ),
        "Correlation between bit positions",
        severity_correlation(bit_corr.max_abs),
    );
    dashboard.add_section(linear_section);

    // Spectral tests
    let spectral = spectral_stats(block_data);
    let mut spectral_section = dashboard.section("Spectral Tests");
    spectral_section = spectral_section
        .metric(
            "DFT peak magnitude",
            format!("{:.4}", spectral.peak),
            "Large peaks ⇒ periodic bias",
            severity_spectral(spectral.peak),
        )
        .metric(
            "Average spectral energy",
            format!("{:.4}", spectral.avg_energy),
            "Reference level for normalized bytes",
            Severity::Pass,
        );
    dashboard.add_section(spectral_section);

    // Randomness batteries
    let mut battery_section = dashboard.section("Randomness Batteries");
    battery_section = battery_section
        .metric(
            "NIST SP 800-22",
            "Not run (requires multi-megabit sample)".to_string(),
            "Use external suite for long captures",
            Severity::Warn,
        )
        .metric(
            "Diehard/Dieharder",
            "Not run (insufficient data)".to_string(),
            "Use dieharder/testu01 offline",
            Severity::Warn,
        )
        .metric(
            "TestU01",
            "Not run (insufficient data)".to_string(),
            "Run SmallCrush/Crush/BigCrush offline",
            Severity::Warn,
        );
    dashboard.add_section(battery_section);

    // Linear complexity
    let lin = linear_complexity(block_data);
    let lin_ratio = lin.length as f64 / lin.total_bits as f64;
    let mut lin_section = dashboard.section("Linear Complexity");
    lin_section = lin_section.metric(
        "Berlekamp–Massey",
        format!(
            "L = {} over {} bits ({:.1}%)",
            lin.length,
            lin.total_bits,
            lin_ratio * 100.0
        ),
        "Higher ratio ⇒ harder to predict",
        severity_linear_complexity(lin_ratio),
    );
    dashboard.add_section(lin_section);

    // Multivariate/TVLA-style
    let t_value = welch_t_test(block_data);
    let mut multi_section = dashboard.section("Multivariate/TVLA");
    multi_section = multi_section.metric(
        "Welch t-test (even vs odd bytes)",
        format!("t = {:.3}", t_value),
        "|t| > 4.5 typically signals leakage",
        severity_t_value(t_value),
    );
    dashboard.add_section(multi_section);

    // Specialized diagnostics
    let hw = hamming_weight_stats(block_data);
    let rl = run_length_stats_bits(block_data);
    let mut special_section = dashboard.section("Specialized Diagnostics");
    special_section = special_section
        .metric(
            "Hamming weight",
            format!("mean {:.2}, σ {:.2}", hw.mean, hw.std_dev),
            "Expected ~50% ones",
            severity_monobit((hw.mean / 8.0) - 0.5),
        )
        .metric(
            "Bit run lengths",
            format!("avg {:.2}, longest {} bits", rl.average, rl.longest),
            "Long runs imply structure",
            severity_run_length(rl.longest),
        );
    dashboard.add_section(special_section);

    output.push_str(&dashboard.render());

    let dump_size = block_data.len().min(256);
    output.push_str(&format!("\nHexdump (first {} bytes)\n", dump_size));
    output.push_str("------------------------\n");
    output.push_str(&hexdump(&block_data[..dump_size]));

    output.push_str("\nTests Requiring Larger Samples:\n");
    output.push_str("  - NIST SP 800-22 suite\n");
    output.push_str("  - Diehard/Dieharder\n");
    output.push_str("  - TestU01 batteries\n");
    output.push_str("  - Permutation/Lag Overlap comparisons\n");
    Ok(())
}

#[derive(Clone, Copy)]
enum Severity {
    Pass,
    Warn,
    Fail,
}

impl Severity {
    fn indicator(&self) -> &'static str {
        match self {
            Severity::Pass => "✔",
            Severity::Warn => "⚠",
            Severity::Fail => "✖",
        }
    }

    fn colorize(&self, text: &str) -> String {
        color(text, self.color_code())
    }

    fn max(a: Severity, b: Severity) -> Severity {
        match (a, b) {
            (Severity::Fail, _) | (_, Severity::Fail) => Severity::Fail,
            (Severity::Warn, _) | (_, Severity::Warn) => Severity::Warn,
            _ => Severity::Pass,
        }
    }

    fn color_code(&self) -> &'static str {
        match self {
            Severity::Pass => FG_GREEN,
            Severity::Warn => FG_YELLOW,
            Severity::Fail => FG_RED,
        }
    }
}

struct MetricLine {
    label: String,
    value: String,
    detail: String,
    severity: Severity,
}

struct Section {
    name: String,
    items: Vec<MetricLine>,
}

impl Section {
    fn metric(
        mut self,
        label: &str,
        value: String,
        detail: impl Into<String>,
        severity: Severity,
    ) -> Self {
        self.items.push(MetricLine {
            label: label.to_string(),
            value,
            detail: detail.into(),
            severity,
        });
        self
    }
}

struct Dashboard {
    title: String,
    sections: Vec<Section>,
    status: Severity,
}

impl Dashboard {
    fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            sections: Vec::new(),
            status: Severity::Pass,
        }
    }

    fn section(&mut self, name: &str) -> Section {
        Section {
            name: name.to_string(),
            items: Vec::new(),
        }
    }

    fn add_section(&mut self, section: Section) {
        let section_severity = section.items.iter().fold(Severity::Pass, |acc, item| {
            Severity::max(acc, item.severity)
        });
        self.status = Severity::max(self.status, section_severity);
        self.sections.push(section);
    }
}

fn monobit_bias(data: &[u8]) -> f64 {
    let mut ones = 0u64;
    for byte in data {
        ones += byte.count_ones() as u64;
    }
    let total = (data.len() * 8) as f64;
    ((ones as f64 / total) - 0.5).abs()
}

fn severity_entropy(entropy: f64) -> Severity {
    match entropy {
        h if h >= 7.0 => Severity::Pass,
        h if h >= 6.0 => Severity::Warn,
        _ => Severity::Fail,
    }
}

fn severity_monobit(bias: f64) -> Severity {
    if bias < 0.02 {
        Severity::Pass
    } else if bias < 0.05 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_ascii(ratio: f64) -> Severity {
    if ratio < 0.2 {
        Severity::Pass
    } else if ratio < 0.5 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_runs(actual: f64, expected: f64) -> Severity {
    let diff = (actual - expected).abs() / expected.max(1.0);
    if diff < 0.1 {
        Severity::Pass
    } else if diff < 0.25 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_correlation(corr: f64) -> Severity {
    let abs = corr.abs();
    if abs < 0.05 {
        Severity::Pass
    } else if abs < 0.15 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_autocorr(values: &[(usize, f64)]) -> Severity {
    let mut severity = Severity::Pass;
    for (_, value) in values {
        let abs = value.abs();
        severity = Severity::max(
            severity,
            if abs < 0.05 {
                Severity::Pass
            } else if abs < 0.15 {
                Severity::Warn
            } else {
                Severity::Fail
            },
        );
    }
    severity
}

fn severity_p_value(p: f64) -> Severity {
    if p < 0.01 || p > 0.99 {
        Severity::Fail
    } else if p < 0.05 || p > 0.95 {
        Severity::Warn
    } else {
        Severity::Pass
    }
}

fn severity_linear_complexity(ratio: f64) -> Severity {
    if ratio >= 0.5 {
        Severity::Pass
    } else if ratio >= 0.35 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_index_of_coincidence(ic: f64) -> Severity {
    if ic < 0.03 {
        Severity::Pass
    } else if ic < 0.045 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_unique(unique: usize, len: usize) -> Severity {
    let ratio = unique as f64 / len as f64;
    if ratio > 0.6 {
        Severity::Pass
    } else if ratio > 0.3 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_min_entropy(entropy: f64) -> Severity {
    if entropy >= 6.5 {
        Severity::Pass
    } else if entropy >= 5.0 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_crib(ratio: f64) -> Severity {
    if ratio < 0.05 {
        Severity::Pass
    } else if ratio < 0.15 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_anderson_darling(value: f64) -> Severity {
    if value < 0.6 {
        Severity::Pass
    } else if value < 1.2 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_kuiper(value: f64) -> Severity {
    if value < 0.1 {
        Severity::Pass
    } else if value < 0.2 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_xor_bias(freq: f64) -> Severity {
    if freq < 0.01 {
        Severity::Pass
    } else if freq < 0.05 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_spectral(peak: f64) -> Severity {
    if peak < 0.2 {
        Severity::Pass
    } else if peak < 0.4 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_t_value(t: f64) -> Severity {
    let abs = t.abs();
    if abs < 2.5 {
        Severity::Pass
    } else if abs < 4.5 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

fn severity_run_length(longest: usize) -> Severity {
    if longest <= 8 {
        Severity::Pass
    } else if longest <= 16 {
        Severity::Warn
    } else {
        Severity::Fail
    }
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const FG_GREEN: &str = "\x1b[32m";
const FG_YELLOW: &str = "\x1b[33m";
const FG_RED: &str = "\x1b[31m";

fn style(text: &str, codes: &[&str]) -> String {
    let mut prefix = String::new();
    for code in codes {
        prefix.push_str(code);
    }
    format!("{}{}{}", prefix, text, RESET)
}

fn color(text: &str, color_code: &str) -> String {
    style(text, &[color_code])
}

struct TableRow {
    section: String,
    metric: String,
    value: String,
    notes: String,
    severity: Severity,
}

impl Dashboard {
    fn rows(&self) -> Vec<TableRow> {
        let mut rows = Vec::new();
        for section in &self.sections {
            for (idx, item) in section.items.iter().enumerate() {
                rows.push(TableRow {
                    section: if idx == 0 {
                        section.name.clone()
                    } else {
                        String::new()
                    },
                    metric: item.label.clone(),
                    value: item.value.clone(),
                    notes: item.detail.clone(),
                    severity: item.severity,
                });
            }
        }
        rows
    }

    fn render(self) -> String {
        let rows = self.rows();
        let headers = [
            "Section".to_string(),
            "Metric".to_string(),
            "Value".to_string(),
            "Notes".to_string(),
            "Status".to_string(),
        ];
        let mut widths = [7usize, 6, 5, 5, 6];
        for row in &rows {
            widths[0] = widths[0].max(row.section.len());
            widths[1] = widths[1].max(row.metric.len());
            widths[2] = widths[2].max(row.value.len());
            widths[3] = widths[3].max(row.notes.len());
            widths[4] =
                widths[4].max(format!("{} {}", row.severity.indicator(), row.severity).len());
        }
        widths[4] = widths[4].max(headers[4].len());

        let mut output = String::new();
        output.push_str(&format!(
            "{} {}\n\n",
            style(
                &format!("{} {}", self.status.indicator(), self.title),
                &[self.status.color_code(), BOLD]
            ),
            color(
                match self.status {
                    Severity::Pass => "(no anomalies detected)",
                    Severity::Warn => "(warning signals found)",
                    Severity::Fail => "(critical issues detected)",
                },
                self.status.color_code()
            )
        ));

        output.push_str(&horizontal_rule(&widths));
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            pad(&headers[0], widths[0]),
            pad(&headers[1], widths[1]),
            pad(&headers[2], widths[2]),
            pad(&headers[3], widths[3]),
            pad(&headers[4], widths[4])
        ));
        output.push_str(&horizontal_rule(&widths));

        for row in rows {
            let section_lines = wrap_cell(&row.section, widths[0]);
            let metric_lines = wrap_cell(&row.metric, widths[1]);
            let value_lines = wrap_cell(&row.value, widths[2]);
            let notes_lines = wrap_cell(&row.notes, widths[3]);
            let status_text = format!("{} {}", row.severity.indicator(), row.severity);
            let status_lines = wrap_cell(&status_text, widths[4]);

            let height = *[
                section_lines.len(),
                metric_lines.len(),
                value_lines.len(),
                notes_lines.len(),
                status_lines.len(),
            ]
            .iter()
            .max()
            .unwrap_or(&1);

            for i in 0..height {
                output.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    pad(section_lines.get(i).unwrap_or(&"".to_string()), widths[0]),
                    pad(metric_lines.get(i).unwrap_or(&"".to_string()), widths[1]),
                    pad(value_lines.get(i).unwrap_or(&"".to_string()), widths[2]),
                    pad(notes_lines.get(i).unwrap_or(&"".to_string()), widths[3]),
                    row.severity.colorize(&pad(
                        status_lines.get(i).unwrap_or(&"".to_string()),
                        widths[4]
                    ))
                ));
            }
            output.push_str(&horizontal_rule(&widths));
        }

        output
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Severity::Pass => "PASS",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        };
        write!(f, "{}", text)
    }
}

fn horizontal_rule(widths: &[usize; 5]) -> String {
    let mut line = String::from("+");
    for &w in widths {
        line.push_str(&format!("{}+", "-".repeat(w + 2)));
    }
    line.push('\n');
    line
}

fn pad(text: &str, width: usize) -> String {
    format!("{:<width$}", text, width = width)
}

fn wrap_cell(text: &str, width: usize) -> Vec<String> {
    if text.is_empty() {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            if word.len() > width {
                lines.extend(split_word(word, width));
                current = String::new();
            } else {
                current = word.to_string();
            }
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn split_word(word: &str, width: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < word.len() {
        let end = (start + width).min(word.len());
        chunks.push(word[start..end].to_string());
        start = end;
    }
    chunks
}

/// Calculate Shannon entropy (bits per byte)
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn interpret_entropy(entropy: f64) -> &'static str {
    match entropy {
        h if h >= 7.5 => "Very high entropy (encryption or white noise)",
        h if h >= 6.5 => "High entropy (well-randomized data)",
        h if h >= 5.5 => "Moderate entropy (structured but transformed)",
        h if h >= 4.0 => "Low entropy (plain text or similar)",
        _ => "Very low entropy (highly structured)",
    }
}

fn calculate_min_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let max_count = freq.iter().copied().max().unwrap_or(0) as f64;
    if max_count == 0.0 {
        0.0
    } else {
        let p_max = max_count / data.len() as f64;
        -p_max.log2()
    }
}

fn calculate_renyi_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let total = data.len() as f64;
    let sum_sq: f64 = freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            p * p
        })
        .sum();
    if sum_sq == 0.0 {
        0.0
    } else {
        -sum_sq.log2()
    }
}

/// Chi-square goodness of fit test
fn calculate_chi_square(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let expected = data.len() as f64 / 256.0;
    let mut chi_square = 0.0;

    for &count in &freq {
        let diff = count as f64 - expected;
        chi_square += diff * diff / expected;
    }

    chi_square
}

/// Approximate p-value for chi-square (normal approximation)
fn chi_square_p_value(chi_square: f64, df: usize) -> f64 {
    let z = ((2.0 * chi_square).sqrt() - (2.0 * df as f64 - 1.0).sqrt()) / std::f64::consts::SQRT_2;
    0.5 * (1.0 - erf(z / std::f64::consts::SQRT_2))
}

fn erf(x: f64) -> f64 {
    let a1 = 0.254829592;
    let a2 = -0.284496736;
    let a3 = 1.421413741;
    let a4 = -1.453152027;
    let a5 = 1.061405429;
    let p = 0.3275911;

    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + p * x);
    let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp();
    sign * y
}

fn interpret_chi_square(p: f64) -> &'static str {
    if p < 0.01 || p > 0.99 {
        "SUSPECT - significant deviation from uniform"
    } else if p < 0.05 || p > 0.95 {
        "Marginal - slight deviation from uniform"
    } else {
        "PASS - consistent with random data"
    }
}

fn format_p_value(p: f64) -> String {
    if p < 0.001 {
        "< 0.001".to_string()
    } else if p > 0.999 {
        "> 0.999".to_string()
    } else {
        format!("{:.3}", p)
    }
}

fn byte_frequency_analysis(data: &[u8]) -> ((u8, u64), (u8, u64), u64) {
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let mut most_common = (0u8, 0u64);
    let mut least_common = (0u8, u64::MAX);
    let mut zero_count = 0;

    for (i, &count) in freq.iter().enumerate() {
        if count > most_common.1 {
            most_common = (i as u8, count);
        }
        if count < least_common.1 {
            least_common = (i as u8, count);
        }
        if i == 0 {
            zero_count = count;
        }
    }

    (most_common, least_common, zero_count)
}

fn count_unique_bytes(data: &[u8]) -> usize {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    for &byte in data {
        set.insert(byte);
    }
    set.len()
}

fn calculate_runs_test(data: &[u8]) -> (usize, f64) {
    if data.is_empty() {
        return (0, 0.0);
    }

    let mut current_bit = data[0] & 1;
    let mut runs = 1;
    let total_bits = data.len() * 8;
    let mut ones = 0;

    for byte in data {
        for i in 0..8 {
            let bit = (byte >> i) & 1;
            if bit != current_bit {
                runs += 1;
                current_bit = bit;
            }
            if bit == 1 {
                ones += 1;
            }
        }
    }

    let zeros = total_bits - ones;
    let expected_runs = (2 * zeros * ones) as f64 / total_bits as f64 + 1.0;

    (runs, expected_runs)
}

fn interpret_runs(actual: usize, expected: f64) -> &'static str {
    let diff = (actual as f64 - expected).abs() / expected;
    if diff < 0.1 {
        "Random-looking run lengths"
    } else if actual as f64 > expected {
        "Too many short runs (alternating pattern)"
    } else {
        "Too few runs (long streaks)"
    }
}

fn calculate_serial_correlation(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }

    let mut sum = 0f64;
    let mut sum_sq = 0f64;
    let mut sum_prod = 0f64;

    for i in 0..data.len() - 1 {
        let x = data[i] as f64;
        let y = data[i + 1] as f64;
        sum += x;
        sum_sq += x * x;
        sum_prod += x * y;
    }

    let n = (data.len() - 1) as f64;
    let numerator = n * sum_prod - sum * sum;
    let denominator = n * sum_sq - sum * sum;

    if denominator.abs() < f64::EPSILON {
        0.0
    } else {
        numerator / denominator
    }
}

fn interpret_correlation(correlation: f64) -> &'static str {
    if correlation.abs() < 0.05 {
        "No significant correlation"
    } else if correlation > 0.0 {
        "Positive correlation (values follow similar trend)"
    } else {
        "Negative correlation (values oscillate)"
    }
}

fn calculate_ascii_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let ascii_count = data
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r')
        .count();

    ascii_count as f64 / data.len() as f64
}

fn interpret_ascii(ratio: f64) -> &'static str {
    if ratio > 0.9 {
        "Mostly ASCII text"
    } else if ratio > 0.5 {
        "Mixed ASCII and binary"
    } else if ratio > 0.1 {
        "Mostly binary data"
    } else {
        "Likely encrypted or random data"
    }
}

fn calculate_autocorrelation(data: &[u8], lags: &[usize]) -> Vec<(usize, f64)> {
    let mut results = Vec::new();

    for &lag in lags {
        if lag >= data.len() {
            continue;
        }

        let mut sum = 0f64;
        let mut sum_sq = 0f64;
        let mut sum_prod = 0f64;

        for i in 0..data.len() - lag {
            let x = data[i] as f64;
            let y = data[i + lag] as f64;
            sum += x;
            sum_sq += x * x;
            sum_prod += x * y;
        }

        let n = (data.len() - lag) as f64;
        let numerator = n * sum_prod - sum * sum;
        let denominator = n * sum_sq - sum * sum;

        if denominator.abs() < f64::EPSILON {
            results.push((lag, 0.0));
        } else {
            results.push((lag, numerator / denominator));
        }
    }

    results
}

fn cross_correlation(data: &[u8], shift: usize) -> f64 {
    if data.len() <= shift {
        return 0.0;
    }
    let mut sum_xy = 0f64;
    let mut sum_x = 0f64;
    let mut sum_y = 0f64;
    let mut sum_x2 = 0f64;
    let mut sum_y2 = 0f64;
    let n = (data.len() - shift) as f64;
    for i in 0..data.len() - shift {
        let x = data[i] as f64;
        let y = data[i + shift] as f64;
        sum_xy += x * y;
        sum_x += x;
        sum_y += y;
        sum_x2 += x * x;
        sum_y2 += y * y;
    }
    let numerator = n * sum_xy - sum_x * sum_y;
    let denominator = ((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y)).sqrt();
    if denominator.abs() < f64::EPSILON {
        0.0
    } else {
        numerator / denominator
    }
}

fn xor_bias(data: &[u8]) -> XorBias {
    if data.len() < 2 {
        return XorBias {
            byte: 0,
            frequency: 0.0,
        };
    }
    let mut freq = [0usize; 256];
    for window in data.windows(2) {
        freq[(window[0] ^ window[1]) as usize] += 1;
    }
    let (byte, count) = freq
        .iter()
        .enumerate()
        .max_by_key(|(_, &count)| count)
        .unwrap();
    XorBias {
        byte: byte as u8,
        frequency: *count as f64 / (data.len() - 1) as f64,
    }
}

fn bit_correlation_stats(data: &[u8]) -> BitCorrelationStats {
    if data.is_empty() {
        return BitCorrelationStats {
            avg_abs: 0.0,
            max_abs: 0.0,
        };
    }
    let mut totals = [[0.0f64; 8]; 8];
    let mut counts = [[0usize; 8]; 8];
    for byte in data {
        for i in 0..8 {
            let bi = ((byte >> i) & 1) as f64;
            for j in i + 1..8 {
                let bj = ((byte >> j) & 1) as f64;
                totals[i][j] += (bi - 0.5) * (bj - 0.5);
                counts[i][j] += 1;
            }
        }
    }
    let mut sum_abs = 0.0;
    let mut count_pairs = 0usize;
    let mut max_abs = 0.0;
    for i in 0..8 {
        for j in i + 1..8 {
            if counts[i][j] > 0 {
                let corr = totals[i][j] / counts[i][j] as f64;
                let abs = corr.abs();
                sum_abs += abs;
                count_pairs += 1;
                if abs > max_abs {
                    max_abs = abs;
                }
            }
        }
    }
    BitCorrelationStats {
        avg_abs: if count_pairs == 0 {
            0.0
        } else {
            sum_abs / count_pairs as f64
        },
        max_abs,
    }
}

fn spectral_stats(data: &[u8]) -> SpectralStats {
    if data.is_empty() {
        return SpectralStats {
            peak: 0.0,
            avg_energy: 0.0,
        };
    }
    let n = data.len();
    let norm: Vec<f64> = data.iter().map(|&b| b as f64 / 255.0 - 0.5).collect();
    let mut peak = 0.0f64;
    let mut energy = 0.0f64;
    for k in 1..n {
        let mut real = 0.0f64;
        let mut imag = 0.0f64;
        for (idx, &value) in norm.iter().enumerate() {
            let angle = -2.0 * std::f64::consts::PI * k as f64 * idx as f64 / n as f64;
            real += value * angle.cos();
            imag += value * angle.sin();
        }
        let mag = (real.powi(2) + imag.powi(2)).sqrt() / n as f64;
        peak = peak.max(mag);
        energy += mag * mag;
    }
    SpectralStats {
        peak,
        avg_energy: energy / (n as f64).max(1.0),
    }
}

fn welch_t_test(data: &[u8]) -> f64 {
    if data.len() < 4 {
        return 0.0;
    }
    let (mut even, mut odd) = (Vec::new(), Vec::new());
    for (idx, byte) in data.iter().enumerate() {
        if idx % 2 == 0 {
            even.push(*byte as f64);
        } else {
            odd.push(*byte as f64);
        }
    }
    welch_t(&even, &odd)
}

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    if a.len() < 2 || b.len() < 2 {
        return 0.0;
    }
    let mean_a = mean(a);
    let mean_b = mean(b);
    let var_a = variance(a, mean_a);
    let var_b = variance(b, mean_b);
    let denom = (var_a / a.len() as f64 + var_b / b.len() as f64).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (mean_a - mean_b) / denom
    }
}

fn mean(values: &[f64]) -> f64 {
    values.iter().copied().sum::<f64>() / values.len() as f64
}

fn variance(values: &[f64], mean: f64) -> f64 {
    values
        .iter()
        .map(|v| {
            let diff = v - mean;
            diff * diff
        })
        .sum::<f64>()
        / (values.len().saturating_sub(1) as f64)
}

fn hamming_weight_stats(data: &[u8]) -> HammingWeightStats {
    if data.is_empty() {
        return HammingWeightStats {
            mean: 0.0,
            std_dev: 0.0,
        };
    }
    let mut weights: Vec<f64> = Vec::with_capacity(data.len());
    for byte in data {
        weights.push(byte.count_ones() as f64);
    }
    let mean = mean(&weights);
    let std_dev = variance(&weights, mean).sqrt();
    HammingWeightStats { mean, std_dev }
}

fn run_length_stats_bits(data: &[u8]) -> RunLengthStats {
    if data.is_empty() {
        return RunLengthStats {
            average: 0.0,
            longest: 0,
        };
    }
    let mut runs = Vec::new();
    let mut current_bit = (data[0] & 1) != 0;
    let mut current_len = 0usize;
    for byte in data {
        for bit in 0..8 {
            let value = ((byte >> bit) & 1) != 0;
            if value == current_bit {
                current_len += 1;
            } else {
                runs.push(current_len);
                current_bit = value;
                current_len = 1;
            }
        }
    }
    if current_len > 0 {
        runs.push(current_len);
    }
    let longest = runs.iter().copied().max().unwrap_or(0);
    let average = runs.iter().copied().sum::<usize>() as f64 / runs.len() as f64;
    RunLengthStats { average, longest }
}
struct BitPlaneStats {
    bit: usize,
    ones: u64,
    total: u64,
    chi_square: f64,
    p_value: f64,
}

struct KasiskiResult {
    summary: String,
    severity: Severity,
}

struct CribResult {
    shift: usize,
    matches: usize,
    ratio: f64,
}

struct XorBias {
    byte: u8,
    frequency: f64,
}

struct BitCorrelationStats {
    avg_abs: f64,
    max_abs: f64,
}

struct SpectralStats {
    peak: f64,
    avg_energy: f64,
}

struct HammingWeightStats {
    mean: f64,
    std_dev: f64,
}

struct RunLengthStats {
    average: f64,
    longest: usize,
}

fn bit_plane_stats(data: &[u8]) -> Vec<BitPlaneStats> {
    let mut stats = Vec::with_capacity(8);

    for bit in 0..8 {
        let mut ones = 0u64;
        for &byte in data {
            if (byte >> bit) & 1 == 1 {
                ones += 1;
            }
        }

        let total = data.len() as u64;
        let zeros = total - ones;
        let expected = total as f64 / 2.0;
        let chi_square =
            ((ones as f64 - expected).powi(2) + (zeros as f64 - expected).powi(2)) / expected;
        let p_value = chi_square_p_value(chi_square, 1);

        stats.push(BitPlaneStats {
            bit,
            ones,
            total,
            chi_square,
            p_value,
        });
    }

    stats
}

fn index_of_coincidence(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let numerator: u64 = freq
        .iter()
        .map(|&c| if c > 1 { c * (c - 1) } else { 0 })
        .sum();
    let denominator = (data.len() * (data.len() - 1)) as f64;
    if denominator == 0.0 {
        0.0
    } else {
        numerator as f64 / denominator
    }
}

fn top_ngrams(data: &[u8], n: usize, limit: usize) -> Vec<(Vec<u8>, usize)> {
    if data.len() < n {
        return Vec::new();
    }
    let mut map: HashMap<Vec<u8>, usize> = HashMap::new();
    for window in data.windows(n) {
        *map.entry(window.to_vec()).or_insert(0) += 1;
    }
    let mut items: Vec<_> = map.into_iter().collect();
    items.sort_by(|a, b| b.1.cmp(&a.1));
    items.truncate(limit);
    items
}

fn format_ngrams(ngrams: &[(Vec<u8>, usize)]) -> String {
    if ngrams.is_empty() {
        return "n/a".into();
    }
    ngrams
        .iter()
        .map(|(bytes, count)| {
            let printable: String = bytes
                .iter()
                .map(|b| {
                    if b.is_ascii_graphic() {
                        *b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{} ({})", printable, count)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn gcd_u64(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd_u64(b, a % b)
    }
}

fn kasiski_analysis(data: &[u8]) -> KasiskiResult {
    if data.len() < 6 {
        return KasiskiResult {
            summary: "n/a".into(),
            severity: Severity::Pass,
        };
    }
    let mut positions: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, window) in data.windows(3).enumerate() {
        let key = ((window[0] as u32) << 16) | ((window[1] as u32) << 8) | window[2] as u32;
        positions.entry(key).or_default().push(i);
    }
    let mut gcd = 0u64;
    let mut repeated = 0usize;
    for (_key, pos) in positions {
        if pos.len() > 1 {
            repeated += 1;
            for pair in pos.windows(2) {
                let diff = (pair[1] - pair[0]) as u64;
                gcd = if gcd == 0 { diff } else { gcd_u64(gcd, diff) };
            }
        }
    }
    if repeated == 0 || gcd == 0 {
        return KasiskiResult {
            summary: "no repeating trigrams".into(),
            severity: Severity::Pass,
        };
    }
    let severity = if gcd <= 3 {
        Severity::Fail
    } else if gcd <= 6 {
        Severity::Warn
    } else {
        Severity::Pass
    };
    KasiskiResult {
        summary: format!("{} repeats, gcd distance {}", repeated, gcd),
        severity,
    }
}

fn crib_coincidence(data: &[u8]) -> CribResult {
    if data.len() < 4 {
        return CribResult {
            shift: 0,
            matches: 0,
            ratio: 0.0,
        };
    }
    let max_shift = min(32, data.len() - 1);
    let mut best = CribResult {
        shift: 0,
        matches: 0,
        ratio: 0.0,
    };
    for shift in 1..=max_shift {
        let mut matches = 0usize;
        for i in 0..data.len() - shift {
            if data[i] == data[i + shift] {
                matches += 1;
            }
        }
        let ratio = matches as f64 / (data.len() - shift) as f64;
        if ratio > best.ratio {
            best = CribResult {
                shift,
                matches,
                ratio,
            };
        }
    }
    best
}

struct KsResult {
    d_stat: f64,
    p_value: f64,
}

fn kolmogorov_smirnov_uniform(data: &[u8]) -> KsResult {
    if data.is_empty() {
        return KsResult {
            d_stat: 0.0,
            p_value: 1.0,
        };
    }

    let mut sorted: Vec<f64> = data.iter().map(|&b| b as f64 / 255.0).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let n = sorted.len() as f64;
    let mut d_stat = 0.0;

    for (i, &value) in sorted.iter().enumerate() {
        let cdf = (i + 1) as f64 / n;
        let diff = (value - cdf).abs();
        if diff > d_stat {
            d_stat = diff;
        }
    }

    // Kolmogorov distribution approximation
    let p_value = if n.sqrt() * d_stat < 1.18 {
        let lambda = (n.sqrt() + 0.12 + 0.11 / n.sqrt()) * d_stat;
        let mut sum = 0.0;
        for k in 1..100 {
            let term = (-2.0 * (k as f64).powi(2) * lambda * lambda).exp();
            sum += (-1.0f64).powi(k as i32 - 1) * term;
        }
        (2.0 * sum).clamp(0.0, 1.0)
    } else {
        let lambda = (n.sqrt() + 0.12 + 0.11 / n.sqrt()) * d_stat;
        (-2.0 * lambda.powi(2)).exp()
    };

    KsResult { d_stat, p_value }
}

fn interpret_ks(p: f64) -> &'static str {
    match p {
        p if p < 0.01 => "Distribution deviates significantly from uniform",
        p if p < 0.05 => "Slight deviation from uniform",
        p if p > 0.99 => "Suspiciously uniform",
        _ => "Consistent with uniform distribution",
    }
}

fn anderson_darling_uniform(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<f64> = data.iter().map(|&b| b as f64 / 255.0).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len() as f64;
    let mut sum = 0.0;
    for (i, x) in sorted.iter().enumerate() {
        let xi = x.max(1e-12).min(1.0 - 1e-12);
        let term = (2.0 * (i as f64 + 1.0) - 1.0) * (xi.ln() + (1.0 - xi).ln());
        sum += term;
    }
    let a2 = -n - (sum / n);
    a2
}

fn kuiper_uniform(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<f64> = data.iter().map(|&b| b as f64 / 255.0).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len() as f64;
    let mut d_plus = 0.0f64;
    let mut d_minus = 0.0f64;
    for (i, &x) in sorted.iter().enumerate() {
        let i = i as f64 + 1.0;
        d_plus = d_plus.max(i / n - x);
        d_minus = d_minus.max(x - (i - 1.0) / n);
    }
    d_plus + d_minus
}

struct ShingleEntropy {
    average: f64,
    min: f64,
    max: f64,
}

fn shingled_entropy(data: &[u8], window: usize) -> ShingleEntropy {
    if data.len() < window {
        return ShingleEntropy {
            average: calculate_entropy(data),
            min: 0.0,
            max: 0.0,
        };
    }

    let mut entropies = Vec::new();
    for chunk in data.windows(window) {
        entropies.push(calculate_entropy(chunk));
    }

    let sum: f64 = entropies.iter().sum();
    let average = sum / entropies.len() as f64;
    let min = entropies.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = entropies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    ShingleEntropy { average, min, max }
}

struct LinearComplexity {
    length: usize,
    total_bits: usize,
}

fn linear_complexity(data: &[u8]) -> LinearComplexity {
    let mut bits = Vec::with_capacity(data.len() * 8);
    for &byte in data {
        for bit in (0..8).rev() {
            bits.push((byte >> bit) & 1);
        }
    }

    let mut c = vec![0u8; bits.len()];
    let mut b = vec![0u8; bits.len()];
    c[0] = 1;
    b[0] = 1;

    let mut l = 0usize;
    let mut m: isize = -1;

    for n in 0..bits.len() {
        let mut d = bits[n];
        for i in 1..=l {
            d ^= c[i] & bits[n - i];
        }
        if d == 1 {
            let temp = c.clone();
            let shift = n as isize - m;
            for j in 0..b.len() {
                if b[j] == 1 {
                    let idx = j as isize + shift;
                    if idx >= 0 && (idx as usize) < c.len() {
                        c[idx as usize] ^= 1;
                    }
                }
            }
            if 2 * l <= n {
                l = n + 1 - l;
                m = n as isize;
                b = temp;
            }
        }
    }

    LinearComplexity {
        length: l,
        total_bits: bits.len(),
    }
}

fn hexdump(data: &[u8]) -> String {
    let mut output = String::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        output.push_str(&format!("{:08X}  ", i * 16));

        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02X} ", byte));
            if j == 7 {
                output.push(' ');
            }
        }

        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                output.push_str("   ");
                if j == 7 {
                    output.push(' ');
                }
            }
        }

        output.push_str(" |");
        for &byte in chunk {
            if byte >= 0x20 && byte <= 0x7E {
                output.push(byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_random() {
        let data: Vec<u8> = (0..1000).map(|i| ((i * 17 + 31) % 256) as u8).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.0);
    }

    #[test]
    fn test_entropy_constant() {
        let data = vec![42u8; 1000];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 0.01);
    }

    #[test]
    fn test_hexdump() {
        let data = b"Hello, World!";
        let dump = hexdump(data);
        assert!(dump.contains("48 65 6C 6C"));
        assert!(dump.contains("|Hello, World!|"));
    }

    #[test]
    fn test_chi_square() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let chi = calculate_chi_square(&data);
        assert!(chi < 1.0);
    }
}
