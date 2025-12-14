use crate::cli::seal::seal_file;
use crate::compartment::create_compartment;
use crate::cube::{analyze_data, cube_config};
use crate::error::{HypercubeError, Result};
use crate::header::{Aont, Compression, HashAlgorithm, Shuffle, VhcHeader, Whitener};
use crate::vhc::{append_blocks_to_vhc, get_block_count, read_vhc_header, write_vhc_file, VhcFile};
use std::path::Path;

/// Options for the add command
#[derive(Debug, Clone)]
pub struct AddOptions {
    pub secret: String,
    pub compression: Compression,
    pub shuffle: Shuffle,
    pub aont: Aont,
    pub hash: HashAlgorithm,
    pub whitener: Whitener,
    pub cube: usize,
    pub mac_bits: usize,
    pub compartment: Option<usize>, // Ignored in new model
    pub seal: bool,
}

impl Default for AddOptions {
    fn default() -> Self {
        Self {
            secret: String::new(),
            compression: Compression::default(),
            shuffle: Shuffle::default(),
            aont: Aont::default(),
            hash: HashAlgorithm::default(),
            whitener: Whitener::default(),
            cube: 1,
            mac_bits: 256,
            compartment: None,
            seal: false,
        }
    }
}

/// Add a compartment to a VHC file
/// Returns the number of blocks added
pub fn add_compartment(
    input_path: &Path,
    output_path: &Path,
    options: &AddOptions,
) -> Result<usize> {
    // Read input file
    let input_data = std::fs::read(input_path)?;

    // Load existing header or create new file
    let (header, current_blocks, mut pad_blocks) = if output_path.exists() {
        let header = read_vhc_header(output_path)?;
        let blocks = get_block_count(output_path)?;
        (header, blocks, None)
    } else {
        let cube_cfg = cube_config(options.cube)?;
        let analysis = analyze_data(&input_data, options.compression, cube_cfg)?;
        let block_bytes = analysis.block_size_bytes;

        // Create new VHC file with header
        let mut header = VhcHeader::new(
            cube_cfg.id,
            cube_cfg.compartments,
            cube_cfg.blocks_per_compartment,
            block_bytes,
            options.mac_bits,
        )?;
        header.compression = options.compression;
        header.shuffle = options.shuffle;
        header.aont = options.aont;
        header.hash = options.hash;
        header.whitener = options.whitener;

        // Write empty file with just header
        let vhc = VhcFile::new(header.clone());
        write_vhc_file(output_path, &vhc)?;
        let blocks_per = header.blocks_per_compartment();
        (header, 0, Some(blocks_per))
    };
    if pad_blocks.is_none() {
        pad_blocks = Some(header.blocks_per_compartment());
    }
    let capacity = header.theoretical_block_count();

    // Create the compartment - returns serialized blocks
    let result = create_compartment(&input_data, options.secret.as_bytes(), &header, pad_blocks)?;

    let block_count = result.blocks.len();
    let remaining = capacity.saturating_sub(current_blocks);
    if block_count > remaining {
        return Err(HypercubeError::FileFull(capacity));
    }

    // Append blocks to VHC file
    append_blocks_to_vhc(output_path, &result.blocks)?;

    // Handle --seal option: add chaff compartments
    if options.seal {
        seal_file(output_path)?;
    }

    Ok(block_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vhc::{get_block_count, read_vhc_header};
    use tempfile::tempdir;

    #[test]
    fn test_add_compartment_new_file() {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join("input.txt");
        let output_path = dir.path().join("output.vhc");

        std::fs::write(&input_path, b"Hello, World!").unwrap();

        let options = AddOptions {
            secret: "my_secret".into(),
            ..Default::default()
        };

        let block_count = add_compartment(&input_path, &output_path, &options).unwrap();
        assert!(block_count > 0);
        assert!(output_path.exists());

        // Verify blocks were written
        let file_blocks = get_block_count(&output_path).unwrap();
        let header = read_vhc_header(&output_path).unwrap();
        assert_eq!(block_count, header.blocks_per_compartment());
        assert_eq!(file_blocks, block_count);
    }

    #[test]
    fn test_add_multiple_compartments() {
        let dir = tempdir().unwrap();
        let input1 = dir.path().join("input1.txt");
        let input2 = dir.path().join("input2.txt");
        let output = dir.path().join("output.vhc");

        std::fs::write(&input1, b"First compartment data that is longer").unwrap();
        std::fs::write(&input2, b"Second compartment data").unwrap();

        let options1 = AddOptions {
            secret: "secret1".into(),
            ..Default::default()
        };

        let options2 = AddOptions {
            secret: "secret2".into(),
            ..Default::default()
        };

        let count1 = add_compartment(&input1, &output, &options1).unwrap();
        let count2 = add_compartment(&input2, &output, &options2).unwrap();

        // Verify total blocks
        let total_blocks = get_block_count(&output).unwrap();
        assert_eq!(total_blocks, count1 + count2);
    }

    #[test]
    fn test_add_specific_compartment() {
        // In the new model, compartment ID is ignored
        // All blocks are just appended
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let output = dir.path().join("output.vhc");

        std::fs::write(&input, b"Test data").unwrap();

        let options = AddOptions {
            secret: "secret".into(),
            compartment: Some(5), // This is ignored now
            ..Default::default()
        };

        let block_count = add_compartment(&input, &output, &options).unwrap();
        assert!(block_count > 0);
    }
}
