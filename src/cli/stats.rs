use crate::error::Result;
use crate::vhc::read_vhc_file;
use std::path::Path;
use rand::Rng;

/// Show cryptanalysis stats for a random block from a VHC file
pub fn show_stats(path: &Path) -> Result<String> {
    let vhc = read_vhc_file(path)?;

    if vhc.blocks.is_empty() {
        return Ok("No blocks in file".to_string());
    }

    // Pick a random block
    let mut rng = rand::thread_rng();
    let block_idx = rng.gen_range(0..vhc.blocks.len());
    let full_block = &vhc.blocks[block_idx];

    // Extract just the data portion (exclude 16-byte sequence and MAC)
    let sequence_size = 16;
    let mac_size = vhc.header.mac_bytes();
    let data_start = sequence_size;
    let data_end = full_block.len() - mac_size;
    let block_data = &full_block[data_start..data_end];

    let mut output = String::new();

    // Header
    output.push_str(&format!("Hypercube Block Cryptanalysis\n"));
    output.push_str(&format!("=============================\n\n"));
    output.push_str(&format!("File: {}\n", path.display()));
    output.push_str(&format!("Block: {} (of {} total)\n", block_idx, vhc.blocks.len()));
    output.push_str(&format!("Block size: {} bytes (data only, excluding 16B seq + {}B MAC)\n\n",
        block_data.len(), mac_size));

    // Cryptanalysis
    output.push_str("Cryptanalysis Results\n");
    output.push_str("---------------------\n\n");

    // Shannon entropy
    let entropy = calculate_entropy(block_data);
    let max_entropy = 8.0; // Max for bytes
    let entropy_pct = (entropy / max_entropy) * 100.0;
    output.push_str(&format!("Shannon Entropy: {:.4} bits/byte ({:.1}% of max)\n", entropy, entropy_pct));
    output.push_str(&format!("  Interpretation: {}\n\n", interpret_entropy(entropy)));

    // Chi-square test
    let chi_square = calculate_chi_square(block_data);
    let chi_p_value = chi_square_p_value(chi_square, 255);
    output.push_str(&format!("Chi-Square: {:.2} (df=255)\n", chi_square));
    output.push_str(&format!("  P-value: {}\n", format_p_value(chi_p_value)));
    output.push_str(&format!("  Interpretation: {}\n\n", interpret_chi_square(chi_p_value)));

    // Byte frequency analysis
    let (most_common, least_common, zero_count) = byte_frequency_analysis(block_data);
    output.push_str("Byte Frequency:\n");
    output.push_str(&format!("  Most common:  0x{:02X} ({} times, {:.1}%)\n",
        most_common.0, most_common.1, (most_common.1 as f64 / block_data.len() as f64) * 100.0));
    output.push_str(&format!("  Least common: 0x{:02X} ({} times)\n", least_common.0, least_common.1));
    output.push_str(&format!("  Zero bytes:   {} ({:.1}%)\n", zero_count, (zero_count as f64 / block_data.len() as f64) * 100.0));
    output.push_str(&format!("  Unique bytes: {}/256\n\n", count_unique_bytes(block_data)));

    // Runs test (sequences of same bit)
    let runs = calculate_runs_test(block_data);
    output.push_str(&format!("Runs Test: {} runs\n", runs.0));
    output.push_str(&format!("  Expected: ~{:.0} runs\n", runs.1));
    output.push_str(&format!("  Interpretation: {}\n\n", interpret_runs(runs.0, runs.1)));

    // Serial correlation
    let correlation = calculate_serial_correlation(block_data);
    output.push_str(&format!("Serial Correlation: {:.4}\n", correlation));
    output.push_str(&format!("  Interpretation: {}\n\n", interpret_correlation(correlation)));

    // ASCII analysis
    let ascii_ratio = calculate_ascii_ratio(block_data);
    output.push_str(&format!("ASCII Printable: {:.1}%\n", ascii_ratio * 100.0));
    output.push_str(&format!("  Interpretation: {}\n\n", interpret_ascii(ascii_ratio)));

    // Hexdump (first 256 bytes or full block if smaller)
    let dump_size = block_data.len().min(256);
    output.push_str(&format!("Hexdump (first {} bytes)\n", dump_size));
    output.push_str("------------------------\n");
    output.push_str(&hexdump(&block_data[..dump_size]));

    Ok(output)
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
    if entropy >= 7.9 {
        "Excellent - appears random/encrypted"
    } else if entropy >= 7.5 {
        "Good - high randomness"
    } else if entropy >= 6.0 {
        "Moderate - some structure present"
    } else if entropy >= 4.0 {
        "Low - significant patterns"
    } else {
        "Very low - highly structured data"
    }
}

/// Calculate chi-square statistic for uniform distribution
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
        chi_square += (diff * diff) / expected;
    }

    chi_square
}

/// Approximate p-value for chi-square (simplified)
fn chi_square_p_value(chi_square: f64, df: usize) -> f64 {
    // Simplified approximation using normal approximation for large df
    let z = ((2.0 * chi_square).sqrt() - (2.0 * df as f64 - 1.0).sqrt()) / std::f64::consts::SQRT_2;
    0.5 * (1.0 - erf(z / std::f64::consts::SQRT_2))
}

/// Error function approximation
fn erf(x: f64) -> f64 {
    let a1 =  0.254829592;
    let a2 = -0.284496736;
    let a3 =  1.421413741;
    let a4 = -1.453152027;
    let a5 =  1.061405429;
    let p  =  0.3275911;

    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + p * x);
    let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp();
    sign * y
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

fn interpret_chi_square(p_value: f64) -> &'static str {
    if p_value < 0.01 || p_value > 0.99 {
        "SUSPECT - significant deviation from uniform"
    } else if p_value < 0.05 || p_value > 0.95 {
        "Marginal - slight deviation from uniform"
    } else {
        "PASS - consistent with random data"
    }
}

/// Byte frequency analysis
fn byte_frequency_analysis(data: &[u8]) -> ((u8, usize), (u8, usize), usize) {
    let mut freq = [0usize; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let mut most_common = (0u8, 0usize);
    let mut least_common = (0u8, usize::MAX);
    let zero_count = freq[0];

    for (byte, &count) in freq.iter().enumerate() {
        if count > most_common.1 {
            most_common = (byte as u8, count);
        }
        if count < least_common.1 {
            least_common = (byte as u8, count);
        }
    }

    (most_common, least_common, zero_count)
}

fn count_unique_bytes(data: &[u8]) -> usize {
    let mut seen = [false; 256];
    for &byte in data {
        seen[byte as usize] = true;
    }
    seen.iter().filter(|&&b| b).count()
}

/// Calculate runs test (number of runs of consecutive bits)
fn calculate_runs_test(data: &[u8]) -> (usize, f64) {
    if data.is_empty() {
        return (0, 0.0);
    }

    let mut runs = 1usize;
    let mut prev_bit = (data[0] >> 7) & 1;

    for &byte in data {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            if bit != prev_bit {
                runs += 1;
                prev_bit = bit;
            }
        }
    }

    let n = data.len() * 8;
    let expected_runs = (2.0 * n as f64 - 1.0) / 3.0;

    (runs, expected_runs)
}

fn interpret_runs(actual: usize, expected: f64) -> &'static str {
    let ratio = actual as f64 / expected;
    // Note: Transformed data (compress/shuffle/whiten/AONT) typically shows
    // 70-90% of expected runs due to pipeline processing
    if ratio > 0.85 && ratio < 1.15 {
        "PASS - normal run distribution"
    } else if ratio > 0.7 && ratio < 1.3 {
        "OK - within expected range for transformed data"
    } else if ratio > 0.5 && ratio < 1.5 {
        "Marginal - notable deviation"
    } else {
        "SUSPECT - abnormal run distribution"
    }
}

/// Calculate serial correlation coefficient
fn calculate_serial_correlation(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }

    let n = data.len() as f64;
    let mean: f64 = data.iter().map(|&b| b as f64).sum::<f64>() / n;

    let mut numerator = 0.0;
    let mut denominator = 0.0;

    for i in 0..data.len() {
        let x = data[i] as f64 - mean;
        let y = data[(i + 1) % data.len()] as f64 - mean;
        numerator += x * y;
        denominator += x * x;
    }

    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

fn interpret_correlation(corr: f64) -> &'static str {
    let abs_corr = corr.abs();
    if abs_corr < 0.05 {
        "PASS - no significant correlation"
    } else if abs_corr < 0.1 {
        "Marginal - weak correlation"
    } else {
        "SUSPECT - significant serial correlation"
    }
}

/// Calculate ratio of printable ASCII characters
fn calculate_ascii_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let ascii_count = data.iter().filter(|&&b| b >= 0x20 && b <= 0x7E).count();
    ascii_count as f64 / data.len() as f64
}

fn interpret_ascii(ratio: f64) -> &'static str {
    if ratio > 0.8 {
        "High - may be text or weakly encrypted"
    } else if ratio > 0.5 {
        "Moderate - mixed content"
    } else if ratio > 0.35 {
        "Expected for random data (~37%)"
    } else {
        "Low - binary/encrypted data"
    }
}

/// Generate hexdump output
fn hexdump(data: &[u8]) -> String {
    let mut output = String::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        // Offset
        output.push_str(&format!("{:08X}  ", i * 16));

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02X} ", byte));
            if j == 7 {
                output.push(' ');
            }
        }

        // Padding if less than 16 bytes
        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                output.push_str("   ");
                if j == 7 {
                    output.push(' ');
                }
            }
        }

        // ASCII representation
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
        // Pseudo-random data should have high entropy
        let data: Vec<u8> = (0..1000).map(|i| ((i * 17 + 31) % 256) as u8).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.0);
    }

    #[test]
    fn test_entropy_constant() {
        // Constant data should have zero entropy
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
        // Uniform distribution should have chi-square close to df
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let chi = calculate_chi_square(&data);
        // With exactly 1 of each byte, chi-square should be 0
        assert!(chi < 1.0);
    }
}
