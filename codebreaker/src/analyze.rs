use anyhow::Result;
use hypercube::cube::{analyze_data, CubeConfig};
use hypercube::header::Compression;
use std::path::Path;

/// Suggest a Hypercube configuration for an input file.
pub fn analyze_file(path: &Path, compression: Compression, dimension: usize) -> Result<String> {
    let data = std::fs::read(path)?;
    let cube = CubeConfig::hypercube(dimension);
    let analysis = analyze_data(&data, compression, cube)?;

    let mut output = String::new();
    output.push_str("Hypercube Cube Analyzer\n");
    output.push_str("=======================\n\n");
    output.push_str(&format!("File: {}\n", path.display()));
    output.push_str(&format!(
        "Original size: {}\n",
        format_size(analysis.original_bytes as u64)
    ));
    output.push_str(&format!(
        "Compressed size ({}): {}\n",
        format!("{:?}", compression).to_lowercase(),
        format_size(analysis.compressed_bytes as u64)
    ));
    output.push_str(&format!(
        "Payload after metadata: {}\n\n",
        format_size(analysis.payload_bytes as u64)
    ));
    output.push_str(&format!(
        "Cube {}: {} partitions × {} blocks\n",
        analysis.cube.id, analysis.cube.partitions, analysis.cube.blocks_per_partition
    ));
    output.push_str(&format!(
        "Block payload size: {} bytes ({} bits)\n",
        analysis.block_size_bytes,
        analysis.block_size_bytes * 8
    ));
    output.push_str(&format!(
        "Per-compartment capacity: {}\n",
        format_size(analysis.capacity_bytes as u64)
    ));
    output.push_str(&format!(
        "Headroom if padded to cube: {}\n",
        format_size(analysis.headroom_bytes() as u64)
    ));

    Ok(output)
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_analyze_file_reports_cube() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("data.bin");
        std::fs::write(&input, b"hello world").unwrap();
        let report = analyze_file(&input, Compression::Zstd, 32).unwrap();
        assert!(report.contains("Cube 32")); // dimension = 32, now shows "partitions"
    }
}
