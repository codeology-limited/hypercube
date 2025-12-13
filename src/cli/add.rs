use crate::error::Result;
use crate::header::{VhcHeader, Compression, Shuffle, Aont, HashAlgorithm, Whitener};
use crate::compartment::{create_compartment, generate_chaff};
use crate::vhc::{VhcFile, write_vhc_file, append_blocks_to_vhc, read_vhc_header};
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
    pub block_size: usize,
    pub mac_bits: usize,
    pub dimension: usize,
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
            block_size: 4096,
            mac_bits: 256,
            dimension: 128,
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
    let header = if output_path.exists() {
        read_vhc_header(output_path)?
    } else {
        // Create new VHC file with header
        let mut header = VhcHeader::new(
            options.dimension,
            options.block_size,
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
        header
    };

    // Create the compartment - returns serialized blocks
    let result = create_compartment(
        &input_data,
        options.secret.as_bytes(),
        &header,
    )?;

    let block_count = result.blocks.len();

    // Append blocks to VHC file
    append_blocks_to_vhc(output_path, &result.blocks)?;

    // Handle --seal option: add chaff compartments
    if options.seal {
        seal_with_chaff(output_path, &header, options.dimension)?;
    }

    Ok(block_count)
}

/// Fill remaining capacity with chaff blocks
/// Since there's no compartment tracking, we just add more blocks
fn seal_with_chaff(path: &Path, header: &VhcHeader, _dimension: usize) -> Result<()> {
    use rand::Rng;

    // Generate some random number of chaff compartments
    let num_chaff: usize = rand::thread_rng().gen_range(3..10);

    for _ in 0..num_chaff {
        // Generate random chaff data (random size between 100 and 10000 bytes)
        let chaff_size: usize = rand::thread_rng().gen_range(100..10000);
        let chaff_data = generate_chaff(chaff_size);

        // Generate a unique secret for this chaff compartment
        // (nobody will ever know this secret)
        let chaff_secret: Vec<u8> = (0..32).map(|_| rand::thread_rng().gen()).collect();

        // Create chaff compartment
        let result = create_compartment(
            &chaff_data,
            &chaff_secret,
            header,
        )?;

        // Append chaff blocks
        append_blocks_to_vhc(path, &result.blocks)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::vhc::get_block_count;

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
