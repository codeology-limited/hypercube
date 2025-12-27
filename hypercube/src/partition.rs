use crate::error::{HypercubeError, Result};
use crate::header::{PartitionMeta, VhcHeader};
use crate::pipeline::{
    apply_aont, authenticate_blocks, compress, decompress, fragment_all, generate_sequence_base,
    reverse_aont, segment, sequence_blocks, unfragment_all, unsequence_blocks, verify_mac,
    AuthenticatedBlock, SequenceNumber, SequencedBlock, SEQUENCE_SIZE,
};
use rand::{rngs::OsRng, RngCore};

/// Result of creating a partition - just the serialized blocks
pub struct CreatePartitionResult {
    /// Serialized blocks ready for storage (each = sequence + data + MAC)
    pub blocks: Vec<Vec<u8>>,
}

/// Create a partition from input data
/// Pipeline: Compress → Segment → Fragment → AONT → Sequence → MAC
pub fn create_partition(
    data: &[u8],
    secret: &[u8],
    header: &VhcHeader,
    pad_to_blocks: Option<usize>,
) -> Result<CreatePartitionResult> {
    // Step 1: Compress
    let compressed = compress(data, header.compression)?;

    // Step 2: Prepend metadata
    let meta = PartitionMeta {
        compressed_size: compressed.len() as u64,
        original_size: data.len() as u64,
    };
    let mut data_with_meta = Vec::with_capacity(PartitionMeta::SIZE + compressed.len());
    data_with_meta.extend_from_slice(&meta.to_bytes());
    data_with_meta.extend_from_slice(&compressed);

    // Pad if requested
    if let Some(target_blocks) = pad_to_blocks {
        if target_blocks == 0 {
            return Err(HypercubeError::InvalidDimension(0));
        }
        let target_bytes = header.block_size * target_blocks;
        if data_with_meta.len() > target_bytes {
            return Err(HypercubeError::FileFull(target_blocks));
        }
        data_with_meta.resize(target_bytes, 0u8);
    }

    // Step 3: Segment into blocks
    let blocks = segment(&data_with_meta, header.block_size);

    // Step 4: Fragment blocks
    let (fragments, frags_per_block) = fragment_all(&blocks, header.fragment_size);

    // Step 5: Apply AONT (randomized, adds key block)
    let fragments = apply_aont(fragments, header.aont, frags_per_block);

    // Step 6: Unfragment back to blocks
    let transformed_blocks = unfragment_all(&fragments, frags_per_block);

    // Step 7: Add sequence numbers
    let sequence_base = generate_sequence_base();
    let sequenced = sequence_blocks(transformed_blocks, sequence_base);

    // Step 8: Authenticate with MAC
    let authenticated = authenticate_blocks(sequenced, secret, header.hash, header.mac_bits);

    // Step 9: Serialize blocks
    let serialized: Vec<Vec<u8>> = authenticated
        .iter()
        .map(|block| {
            let mut buf = Vec::with_capacity(SEQUENCE_SIZE + block.data.len() + block.mac.len());
            buf.extend_from_slice(&block.sequence_bytes);
            buf.extend_from_slice(&block.data);
            buf.extend_from_slice(&block.mac);
            buf
        })
        .collect();

    Ok(CreatePartitionResult { blocks: serialized })
}

/// Extract data from a VHC file by scanning ALL blocks and authenticating each
pub fn extract_partition(
    all_blocks: &[Vec<u8>],
    secret: &[u8],
    header: &VhcHeader,
) -> Result<Vec<u8>> {
    let mac_bytes = header.mac_bytes();
    let data_size = header.block_size;
    let expected_block_size = SEQUENCE_SIZE + data_size + mac_bytes;

    // Step 1: Scan and authenticate blocks
    let mut authenticated_blocks: Vec<AuthenticatedBlock> = Vec::new();

    for block in all_blocks {
        if block.len() != expected_block_size {
            continue;
        }

        let mut sequence_bytes = [0u8; SEQUENCE_SIZE];
        sequence_bytes.copy_from_slice(&block[..SEQUENCE_SIZE]);
        let block_data = &block[SEQUENCE_SIZE..SEQUENCE_SIZE + data_size];
        let mac = &block[SEQUENCE_SIZE + data_size..];

        let auth_block = AuthenticatedBlock {
            sequence_bytes,
            data: block_data.to_vec(),
            mac: mac.to_vec(),
        };

        if verify_mac(&auth_block, secret, header.hash, header.mac_bits) {
            authenticated_blocks.push(auth_block);
        }
    }

    if authenticated_blocks.is_empty() {
        return Err(HypercubeError::IntegrityError(
            "No blocks authenticated with this secret".into(),
        ));
    }

    // Step 2: Extract sequenced blocks
    let sequenced: Vec<SequencedBlock> = authenticated_blocks
        .into_iter()
        .map(|b| SequencedBlock {
            sequence: SequenceNumber::from_bytes(b.sequence_bytes),
            data: b.data,
        })
        .collect();

    // Step 3: Remove sequence numbers and verify order
    let transformed_blocks = unsequence_blocks(sequenced)
        .ok_or_else(|| HypercubeError::IntegrityError("Invalid sequence numbers".into()))?;

    // Step 4: Fragment for reverse AONT
    let (fragments, frags_per_block) = fragment_all(&transformed_blocks, header.fragment_size);

    // Step 5: Reverse AONT
    let fragments = reverse_aont(fragments, header.aont, frags_per_block);

    // Step 6: Unfragment back to blocks
    let blocks = unfragment_all(&fragments, frags_per_block);

    // Step 7: Join all blocks
    let mut all_data = Vec::new();
    for block in blocks {
        all_data.extend_from_slice(&block);
    }

    // Step 8: Extract metadata
    if all_data.len() < PartitionMeta::SIZE {
        return Err(HypercubeError::IntegrityError(
            "Data too short for metadata".into(),
        ));
    }

    let meta = PartitionMeta::from_bytes(&all_data)?;

    // Step 9: Extract compressed data
    let compressed_start = PartitionMeta::SIZE;
    let compressed_end = compressed_start + meta.compressed_size as usize;

    if compressed_end > all_data.len() {
        return Err(HypercubeError::IntegrityError(
            "Invalid compressed size in metadata".into(),
        ));
    }

    let compressed = &all_data[compressed_start..compressed_end];

    // Step 10: Decompress
    let data = decompress(compressed, header.compression)?;

    if data.len() != meta.original_size as usize {
        return Err(HypercubeError::IntegrityError(
            "Original size mismatch after decompression".into(),
        ));
    }

    Ok(data)
}

/// Generate random chaff data for sealing
pub fn generate_chaff(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    OsRng.fill_bytes(&mut data);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::VhcHeader;

    #[test]
    fn test_create_extract_roundtrip() {
        let header = VhcHeader::new(32, 32, 32, 64, 256).unwrap();
        let secret = b"my secret key";
        let original_data = b"Hello, World! This is test data for the hypercube format.";

        let result = create_partition(original_data, secret, &header, None).unwrap();
        let extracted = extract_partition(&result.blocks, secret, &header).unwrap();

        assert_eq!(original_data.as_slice(), &extracted[..]);
    }

    #[test]
    fn test_create_extract_large_data() {
        let header = VhcHeader::new(32, 32, 32, 64, 256).unwrap();
        let secret = b"secret";
        let original_data: Vec<u8> = (0..50000).map(|i| (i % 256) as u8).collect();

        let result = create_partition(&original_data, secret, &header, None).unwrap();
        let extracted = extract_partition(&result.blocks, secret, &header).unwrap();

        assert_eq!(original_data, extracted);
    }

    #[test]
    fn test_wrong_secret_fails() {
        let header = VhcHeader::new(32, 32, 32, 64, 256).unwrap();
        let original_data = b"Secret data";

        let result = create_partition(original_data, b"correct", &header, None).unwrap();
        let extracted = extract_partition(&result.blocks, b"wrong", &header);

        assert!(extracted.is_err());
    }

    #[test]
    fn test_multiple_partitions_mixed() {
        let header = VhcHeader::new(32, 32, 32, 64, 256).unwrap();

        let data1 = b"First partition data";
        let data2 = b"Second partition data";
        let secret1 = b"secret1";
        let secret2 = b"secret2";

        let result1 = create_partition(data1, secret1, &header, None).unwrap();
        let result2 = create_partition(data2, secret2, &header, None).unwrap();

        // Mix blocks together
        let mut all_blocks = result1.blocks.clone();
        all_blocks.extend(result2.blocks.clone());

        // Extract each partition
        let extracted1 = extract_partition(&all_blocks, secret1, &header).unwrap();
        let extracted2 = extract_partition(&all_blocks, secret2, &header).unwrap();

        assert_eq!(data1.as_slice(), &extracted1[..]);
        assert_eq!(data2.as_slice(), &extracted2[..]);
    }

    #[test]
    fn test_generate_chaff() {
        let chaff = generate_chaff(1000);
        assert_eq!(chaff.len(), 1000);
        assert!(chaff.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_create_partition_pads_to_cube() {
        let header = VhcHeader::new(32, 32, 32, 32, 256).unwrap();
        let secret = b"pad";
        let data = b"hi";
        let target = header.data_blocks_per_partition();
        let result = create_partition(data, secret, &header, Some(target)).expect("partition");
        assert_eq!(result.blocks.len(), header.blocks_per_partition());
    }
}
