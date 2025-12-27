use crate::partition::extract_partition;
use crate::error::Result;
use crate::vhc::read_vhc_file;
use std::path::Path;

/// Options for the extract command
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub secret: String,
}

/// Extract a partition from a VHC file
/// Scans all blocks and authenticates each with the secret
/// Returns the number of blocks that matched
pub fn extract_from_vhc(
    input_path: &Path,
    output_path: &Path,
    options: &ExtractOptions,
) -> Result<usize> {
    // Read VHC file (all blocks)
    let vhc = read_vhc_file(input_path)?;

    // Extract partition by scanning all blocks
    // The extract function tries to authenticate each block with the secret
    let data = extract_partition(&vhc.blocks, options.secret.as_bytes(), &vhc.header)?;

    // Write extracted data to output
    std::fs::write(output_path, &data)?;

    // Return number of blocks that were authenticated
    // (We don't have direct access to this, but we can estimate from data size)
    let blocks_used = (data.len() / vhc.header.block_size) + 1;
    Ok(blocks_used)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::add::{add_partition, AddOptions};
    use tempfile::tempdir;

    #[test]
    fn test_extract_roundtrip() {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join("input.txt");
        let vhc_path = dir.path().join("test.vhc");
        let output_path = dir.path().join("output.txt");

        // Use larger data to ensure reasonable block sizes (>32 bytes for AONT key)
        let original_data: Vec<u8> = (0..2000).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        std::fs::write(&input_path, &original_data).unwrap();

        // Add partition
        let add_options = AddOptions {
            secret: "my_secret".into(),
            ..Default::default()
        };
        add_partition(&input_path, &vhc_path, &add_options).unwrap();

        // Extract partition
        let extract_options = ExtractOptions {
            secret: "my_secret".into(),
        };
        extract_from_vhc(&vhc_path, &output_path, &extract_options).unwrap();

        // Verify content
        let extracted = std::fs::read(&output_path).unwrap();
        assert_eq!(original_data, extracted);
    }

    #[test]
    fn test_extract_wrong_secret() {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join("input.txt");
        let vhc_path = dir.path().join("test.vhc");
        let output_path = dir.path().join("output.txt");

        std::fs::write(&input_path, b"Secret data").unwrap();

        let add_options = AddOptions {
            secret: "correct_secret".into(),
            ..Default::default()
        };
        add_partition(&input_path, &vhc_path, &add_options).unwrap();

        let extract_options = ExtractOptions {
            secret: "wrong_secret".into(),
        };
        let result = extract_from_vhc(&vhc_path, &output_path, &extract_options);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_multiple_partitions() {
        let dir = tempdir().unwrap();
        let input1 = dir.path().join("input1.txt");
        let input2 = dir.path().join("input2.txt");
        let vhc_path = dir.path().join("test.vhc");
        let output = dir.path().join("output.txt");

        // Use larger random-ish data to ensure reasonable block sizes
        let data1: Vec<u8> = (0..5000).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let data2: Vec<u8> = (0..5000).map(|i| ((i * 11 + 29) % 256) as u8).collect();

        std::fs::write(&input1, &data1).unwrap();
        std::fs::write(&input2, &data2).unwrap();

        // Add first partition
        let options1 = AddOptions {
            secret: "secret1".into(),
            ..Default::default()
        };
        add_partition(&input1, &vhc_path, &options1).unwrap();

        // Add second partition
        let options2 = AddOptions {
            secret: "secret2".into(),
            ..Default::default()
        };
        add_partition(&input2, &vhc_path, &options2).unwrap();

        // Extract first partition
        let extract1 = ExtractOptions {
            secret: "secret1".into(),
        };
        extract_from_vhc(&vhc_path, &output, &extract1).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), data1);

        // Extract second partition
        let extract2 = ExtractOptions {
            secret: "secret2".into(),
        };
        extract_from_vhc(&vhc_path, &output, &extract2).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), data2);
    }
}
