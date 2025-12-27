use crate::cli::seal::seal_file;
use crate::partition::create_partition;
use crate::cube::{analyze_data, CubeConfig};
use crate::error::{HypercubeError, Result};
use crate::header::{Aont, Compression, HashAlgorithm, VhcHeader};
use crate::vhc::{append_blocks_to_vhc, get_block_count, read_vhc_header, write_vhc_file, VhcFile};
use std::path::Path;

/// Options for the add command
#[derive(Debug, Clone)]
pub struct AddOptions {
    pub secret: String,
    pub compression: Compression,
    pub aont: Aont,
    pub hash: HashAlgorithm,
    /// Hypercube dimension (N partitions × N blocks). Must be multiple of 8.
    pub dimension: usize,
    pub mac_bits: usize,
    pub seal: bool,
}

impl Default for AddOptions {
    fn default() -> Self {
        Self {
            secret: String::new(),
            compression: Compression::default(),
            aont: Aont::default(),
            hash: HashAlgorithm::default(),
            dimension: 32,
            mac_bits: 256,
            seal: false,
        }
    }
}

/// Add a partition to a VHC file
/// Returns the number of blocks added
pub fn add_partition(
    input_path: &Path,
    output_path: &Path,
    options: &AddOptions,
) -> Result<usize> {
    let input_data = std::fs::read(input_path)?;
    let effective_compression = options.compression;

    // Load existing header or create new file
    let (header, current_blocks, mut pad_blocks) = if output_path.exists() {
        let header = read_vhc_header(output_path)?;
        let blocks = get_block_count(output_path)?;
        
        // Check if new data can fit in existing cube's block size
        let compressed = crate::pipeline::compress(&input_data, header.compression)?;
        let payload_size = crate::header::PartitionMeta::SIZE + compressed.len();
        let max_payload = header.block_size * header.data_blocks_per_partition();
        if payload_size > max_payload {
            return Err(HypercubeError::DataTooLarge {
                data_size: payload_size,
                max_size: max_payload,
            });
        }
        
        (header, blocks, None)
    } else {
        // Validate dimension is multiple of 8
        if options.dimension < 8 || options.dimension % 8 != 0 {
            return Err(HypercubeError::InvalidDimension(options.dimension));
        }

        // Create cube config from dimension (N×N hypercube)
        let cube_cfg = CubeConfig {
            id: options.dimension,
            partitions: options.dimension,
            blocks_per_partition: options.dimension,
        };
        let analysis = analyze_data(&input_data, effective_compression, cube_cfg)?;
        let mut block_bytes = analysis.block_size_bytes;

        // Ensure block size is even and at least 32 bytes (for AONT key)
        if block_bytes < 32 {
            block_bytes = 32;
        }
        if block_bytes % 2 != 0 {
            block_bytes += 1;
        }

        // Create new VHC file with header
        let mut header = VhcHeader::new(
            cube_cfg.id,
            cube_cfg.partitions,
            cube_cfg.blocks_per_partition,
            block_bytes,
            options.mac_bits,
        )?;
        header.compression = effective_compression;
        header.aont = options.aont;
        header.hash = options.hash;
        // Write empty file with just header
        let vhc = VhcFile::new(header.clone());
        write_vhc_file(output_path, &vhc)?;
        let blocks_per = header.data_blocks_per_partition();
        (header, 0, Some(blocks_per))
    };
    if pad_blocks.is_none() {
        pad_blocks = Some(header.data_blocks_per_partition());
    }
    let capacity = header.theoretical_block_count();

    // Create the partition - returns serialized blocks
    let result = create_partition(&input_data, options.secret.as_bytes(), &header, pad_blocks)?;

    let block_count = result.blocks.len();
    let remaining = capacity.saturating_sub(current_blocks);
    if block_count > remaining {
        return Err(HypercubeError::FileFull(capacity));
    }

    // Append blocks to VHC file
    append_blocks_to_vhc(output_path, &result.blocks)?;

    // Handle --seal option: add chaff partitions
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
    fn test_add_partition_new_file() {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join("input.txt");
        let output_path = dir.path().join("output.vhc");

        std::fs::write(&input_path, b"Hello, World!").unwrap();

        let options = AddOptions {
            secret: "my_secret".into(),
            ..Default::default()
        };

        let block_count = add_partition(&input_path, &output_path, &options).unwrap();
        assert!(block_count > 0);
        assert!(output_path.exists());

        // Verify blocks were written
        let file_blocks = get_block_count(&output_path).unwrap();
        let header = read_vhc_header(&output_path).unwrap();
        assert_eq!(block_count, header.blocks_per_partition());
        assert_eq!(file_blocks, block_count);
    }

    #[test]
    fn test_add_multiple_partitions() {
        let dir = tempdir().unwrap();
        let input1 = dir.path().join("input1.txt");
        let input2 = dir.path().join("input2.txt");
        let output = dir.path().join("output.vhc");

        std::fs::write(&input1, b"First partition data that is longer").unwrap();
        std::fs::write(&input2, b"Second partition data").unwrap();

        let options1 = AddOptions {
            secret: "secret1".into(),
            ..Default::default()
        };

        let options2 = AddOptions {
            secret: "secret2".into(),
            ..Default::default()
        };

        let count1 = add_partition(&input1, &output, &options1).unwrap();
        let count2 = add_partition(&input2, &output, &options2).unwrap();

        // Verify total blocks
        let total_blocks = get_block_count(&output).unwrap();
        assert_eq!(total_blocks, count1 + count2);
    }

    #[test]
    fn test_add_specific_partition() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let output = dir.path().join("output.vhc");

        std::fs::write(&input, b"Test data").unwrap();

        let options = AddOptions {
            secret: "secret".into(),
            ..Default::default()
        };

        let block_count = add_partition(&input, &output, &options).unwrap();
        assert!(block_count > 0);
    }
}
