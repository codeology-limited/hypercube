use crate::error::Result;
use crate::vhc::{read_vhc_header, get_block_count};
use std::path::Path;

/// Display information about a VHC file
pub fn show_info(path: &Path) -> Result<String> {
    let header = read_vhc_header(path)?;
    let block_count = get_block_count(path)?;

    let mut output = String::new();

    output.push_str(&format!("Hypercube VHC File Information\n"));
    output.push_str(&format!("==============================\n\n"));

    output.push_str(&format!("File: {}\n", path.display()));
    output.push_str(&format!("Version: {}\n", header.version));
    output.push_str(&format!("\n"));

    output.push_str(&format!("Cube Parameters:\n"));
    output.push_str(&format!("  Dimension: {}\n", header.dimension));
    output.push_str(&format!("  Block size: {} bytes\n", header.block_size));
    output.push_str(&format!("  Fragment size: {} bytes\n", header.fragment_size));
    output.push_str(&format!("  Fragments per block: {}\n", header.fragments_per_block()));
    output.push_str(&format!("\n"));

    output.push_str(&format!("Algorithms:\n"));
    output.push_str(&format!("  Compression: {:?}\n", header.compression));
    output.push_str(&format!("  Shuffle: {:?}\n", header.shuffle));
    output.push_str(&format!("  AONT: {:?}\n", header.aont));
    output.push_str(&format!("  Hash: {:?}\n", header.hash));
    output.push_str(&format!("  Whitener: {:?}\n", header.whitener));
    output.push_str(&format!("  MAC bits: {}\n", header.mac_bits));
    output.push_str(&format!("\n"));

    // Block statistics
    let total_block_size = header.total_block_size();
    let data_size = block_count * total_block_size;
    output.push_str(&format!("Storage:\n"));
    output.push_str(&format!("  Total blocks: {}\n", block_count));
    output.push_str(&format!("  Block size (with MAC): {} bytes\n", total_block_size));
    output.push_str(&format!("  Data size: {}\n", format_size(data_size as u64)));
    output.push_str(&format!("\n"));

    // Security note
    output.push_str(&format!("Security Model:\n"));
    output.push_str(&format!("  Blocks are not tracked by compartment.\n"));
    output.push_str(&format!("  To extract, provide your secret key.\n"));
    output.push_str(&format!("  Only blocks matching your key will be recovered.\n"));

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
    use crate::cli::add::{add_compartment, AddOptions};
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
        add_compartment(&input_path, &vhc_path, &options).unwrap();

        let info = show_info(&vhc_path).unwrap();

        assert!(info.contains("Version: 1"));
        assert!(info.contains("Dimension: 128"));
        assert!(info.contains("Block size: 4096"));
        assert!(info.contains("Total blocks:"));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1048576), "1.0 MB");
    }
}
