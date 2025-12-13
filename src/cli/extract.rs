use crate::error::Result;
use crate::compartment::extract_compartment;
use crate::vhc::read_vhc_file;
use std::path::Path;

/// Options for the extract command
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub secret: String,
}

/// Extract a compartment from a VHC file
/// Scans all blocks and authenticates each with the secret
/// Returns the number of blocks that matched
pub fn extract_from_vhc(
    input_path: &Path,
    output_path: &Path,
    options: &ExtractOptions,
) -> Result<usize> {
    // Read VHC file (all blocks)
    let vhc = read_vhc_file(input_path)?;

    // Extract compartment by scanning all blocks
    // The extract function tries to authenticate each block with the secret
    let data = extract_compartment(
        &vhc.blocks,
        options.secret.as_bytes(),
        &vhc.header,
    )?;

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
    use crate::cli::add::{add_compartment, AddOptions};
    use tempfile::tempdir;

    #[test]
    fn test_extract_roundtrip() {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join("input.txt");
        let vhc_path = dir.path().join("test.vhc");
        let output_path = dir.path().join("output.txt");

        let original_data = b"Hello, World! This is a test.";
        std::fs::write(&input_path, original_data).unwrap();

        // Add compartment
        let add_options = AddOptions {
            secret: "my_secret".into(),
            ..Default::default()
        };
        add_compartment(&input_path, &vhc_path, &add_options).unwrap();

        // Extract compartment
        let extract_options = ExtractOptions {
            secret: "my_secret".into(),
        };
        extract_from_vhc(&vhc_path, &output_path, &extract_options).unwrap();

        // Verify content
        let extracted = std::fs::read(&output_path).unwrap();
        assert_eq!(original_data.as_slice(), &extracted[..]);
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
        add_compartment(&input_path, &vhc_path, &add_options).unwrap();

        let extract_options = ExtractOptions {
            secret: "wrong_secret".into(),
        };
        let result = extract_from_vhc(&vhc_path, &output_path, &extract_options);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_multiple_compartments() {
        let dir = tempdir().unwrap();
        let input1 = dir.path().join("input1.txt");
        let input2 = dir.path().join("input2.txt");
        let vhc_path = dir.path().join("test.vhc");
        let output = dir.path().join("output.txt");

        let data1 = b"First compartment data";
        let data2 = b"Second compartment data";

        std::fs::write(&input1, data1).unwrap();
        std::fs::write(&input2, data2).unwrap();

        // Add first compartment
        let options1 = AddOptions {
            secret: "secret1".into(),
            ..Default::default()
        };
        add_compartment(&input1, &vhc_path, &options1).unwrap();

        // Add second compartment
        let options2 = AddOptions {
            secret: "secret2".into(),
            ..Default::default()
        };
        add_compartment(&input2, &vhc_path, &options2).unwrap();

        // Extract first compartment
        let extract1 = ExtractOptions { secret: "secret1".into() };
        extract_from_vhc(&vhc_path, &output, &extract1).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), data1);

        // Extract second compartment
        let extract2 = ExtractOptions { secret: "secret2".into() };
        extract_from_vhc(&vhc_path, &output, &extract2).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), data2);
    }
}
