use crate::error::Result;
use crate::vhc::{get_block_count, read_vhc_header};
use std::fs;
use std::path::Path;

/// Display information about a VHC file
pub fn show_info(path: &Path) -> Result<String> {
    let header = read_vhc_header(path)?;
    let block_count = get_block_count(path)?;
    let file_size = fs::metadata(path)?.len() as usize;

    let cube = header.cube();
    let block_bits = header.block_bits();
    let block_payload_bytes = header.block_size;
    let per_partition_blocks = header.blocks_per_partition();
    let partition_capacity = block_payload_bytes * per_partition_blocks;
    let theoretical_blocks = header.theoretical_block_count();
    let payload_capacity_bytes = header.payload_capacity_bytes();
    let payload_capacity_bits = block_bits * theoretical_blocks;
    let per_block_overhead = 16 + header.mac_bytes();
    let theoretical_overhead_bytes = per_block_overhead * theoretical_blocks;
    let header_bytes = header.to_bytes()?.len();
    let header_overhead = 4 + 4 + header_bytes;
    let theoretical_total_bytes = header_overhead + header.total_block_size() * theoretical_blocks;

    let mut output = String::new();

    output.push_str(&format!("Hypercube VHC File Information\n"));
    output.push_str(&format!("==============================\n\n"));

    output.push_str(&format!("File: {}\n", path.display()));
    output.push_str(&format!("Actual size: {}\n", format_size(file_size as u64)));
    output.push_str(&format!("Version: {}\n", header.version));
    output.push_str(&format!("\n"));

    output.push_str(&format!("Cube Geometry:\n"));
    output.push_str(&format!("  Cube id: {}\n", cube));
    output.push_str(&format!("  Partitions: {}\n", header.dimension));
    output.push_str(&format!(
        "  Blocks per partition: {}\n",
        per_partition_blocks
    ));
    let partitions_used =
        (block_count + per_partition_blocks - 1) / per_partition_blocks.max(1);
    output.push_str(&format!(
        "  Partitions in use: {} / {}\n",
        partitions_used, header.dimension
    ));
    output.push_str(&format!(
        "  Block payload: {} bytes ({} bits)\n",
        block_payload_bytes, block_bits
    ));
    output.push_str(&format!(
        "  Capacity per partition: {}\n",
        format_size(partition_capacity as u64)
    ));
    output.push_str(&format!(
        "  Fragment size: {} bytes ({} fragments per block)\n",
        header.fragment_size,
        header.fragments_per_block()
    ));
    output.push_str(&format!("\n"));

    output.push_str(&format!("Algorithms:\n"));
    output.push_str(&format!("  Compression: {:?}\n", header.compression));
    output.push_str(&format!("  AONT: {:?}\n", header.aont));
    output.push_str(&format!("  Hash: {:?}\n", header.hash));
    output.push_str(&format!("  MAC bits: {}\n", header.mac_bits));
    output.push_str(&format!("\n"));

    // Current block statistics
    let total_block_size = header.total_block_size();
    let current_payload = block_count * block_payload_bytes;
    let current_overhead = block_count * per_block_overhead;
    let current_storage = block_count * total_block_size;
    output.push_str(&format!("Current Storage:\n"));
    output.push_str(&format!("  Total blocks written: {}\n", block_count));
    output.push_str(&format!(
        "  Block size (with MAC): {} bytes\n",
        total_block_size
    ));
    output.push_str(&format!(
        "  Payload stored: {}\n",
        format_size(current_payload as u64)
    ));
    output.push_str(&format!(
        "  Overhead stored (sequence + MAC): {}\n",
        format_size(current_overhead as u64)
    ));
    output.push_str(&format!(
        "  Data region usage: {}\n",
        format_size(current_storage as u64)
    ));
    output.push_str(&format!("\n"));

    if block_count > theoretical_blocks {
        output.push_str(&format!(
            "Warning: cube stores {} blocks but capacity is {}. Rebuild with a larger cube.\n\n",
            block_count, theoretical_blocks
        ));
    }

    output.push_str(&format!("Capacity (Full Cube):\n"));
    output.push_str(&format!(
        "  Payload capacity: {} ({})\n",
        format_size(payload_capacity_bytes as u64),
        format_bits(payload_capacity_bits as u64),
    ));
    output.push_str(&format!(
        "  Overhead (sequence + MAC): {}\n",
        format_size(theoretical_overhead_bytes as u64)
    ));
    output.push_str(&format!(
        "  Header overhead: {}\n",
        format_size(header_overhead as u64)
    ));
    output.push_str(&format!(
        "  Full cube file size: {}\n",
        format_size(theoretical_total_bytes as u64)
    ));
    output.push_str(&format!("\n"));

    // Security note
    output.push_str(&format!("Security Model:\n"));
    output.push_str(&format!("  Blocks are not tracked by partition.\n"));
    output.push_str(&format!("  To extract, provide your secret key.\n"));
    output.push_str(&format!(
        "  Only blocks matching your key will be recovered.\n"
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

fn format_bits(bits: u64) -> String {
    if bits < 1024 {
        format!("{} bits", bits)
    } else if bits < 1024 * 1024 {
        format!("{:.1} Kb", bits as f64 / 1024.0)
    } else if bits < 1024 * 1024 * 1024 {
        format!("{:.1} Mb", bits as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} Gb", bits as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::add::{add_partition, AddOptions};
    use tempfile::tempdir;

    #[test]
    fn test_show_info() {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join("input.txt");
        let vhc_path = dir.path().join("test.vhc");

        std::fs::write(&input_path, b"Test data").unwrap();

        let options = AddOptions {
            secret: "secret".into(),
            ..Default::default()
        };
        add_partition(&input_path, &vhc_path, &options).unwrap();

        let info = show_info(&vhc_path).unwrap();

        assert!(info.contains("Version: 1"));
        assert!(info.contains("Cube id: 32")); // Cube id equals dimension
        assert!(info.contains("Blocks per partition:"));
        assert!(info.contains("Total blocks written:"));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1048576), "1.0 MB");
    }
}
