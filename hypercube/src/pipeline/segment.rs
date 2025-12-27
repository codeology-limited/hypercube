/// Segment data into blocks of the specified size
/// Pads the last block if necessary to reach block_size
pub fn segment(data: &[u8], block_size: usize) -> Vec<Vec<u8>> {
    if data.is_empty() {
        // Return at least one empty-padded block
        return vec![vec![0u8; block_size]];
    }

    let mut blocks = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let end = std::cmp::min(offset + block_size, data.len());
        let mut block = data[offset..end].to_vec();

        // Pad last block if necessary
        if block.len() < block_size {
            block.resize(block_size, 0);
        }

        blocks.push(block);
        offset += block_size;
    }

    blocks
}

/// Unsegment (join) blocks back into original data
/// original_size is needed to remove padding from the last block
pub fn unsegment(blocks: &[Vec<u8>], original_size: usize) -> Vec<u8> {
    if blocks.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(original_size);

    for (i, block) in blocks.iter().enumerate() {
        if i == blocks.len() - 1 {
            // Last block - only take up to original_size
            let remaining = original_size.saturating_sub(result.len());
            result.extend_from_slice(&block[..remaining.min(block.len())]);
        } else {
            result.extend_from_slice(block);
        }
    }

    result.truncate(original_size);
    result
}

/// Calculate number of blocks needed for data of given size
pub fn block_count(data_size: usize, block_size: usize) -> usize {
    if data_size == 0 {
        1
    } else {
        (data_size + block_size - 1) / block_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_exact_fit() {
        let data = vec![1u8; 8192]; // Exactly 2 blocks of 4096
        let blocks = segment(&data, 4096);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].len(), 4096);
        assert_eq!(blocks[1].len(), 4096);
    }

    #[test]
    fn test_segment_with_padding() {
        let data = vec![1u8; 5000]; // 1 full block + 904 bytes
        let blocks = segment(&data, 4096);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].len(), 4096);
        assert_eq!(blocks[1].len(), 4096); // Padded
        assert_eq!(&blocks[1][904..], &vec![0u8; 4096 - 904][..]);
    }

    #[test]
    fn test_segment_empty() {
        let data: Vec<u8> = vec![];
        let blocks = segment(&data, 4096);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].len(), 4096);
        assert!(blocks[0].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_unsegment_roundtrip() {
        let original: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let blocks = segment(&original, 4096);
        let restored = unsegment(&blocks, original.len());
        assert_eq!(original, restored);
    }

    #[test]
    fn test_unsegment_empty() {
        let blocks: Vec<Vec<u8>> = vec![];
        let restored = unsegment(&blocks, 0);
        assert!(restored.is_empty());
    }

    #[test]
    fn test_block_count() {
        assert_eq!(block_count(0, 4096), 1);
        assert_eq!(block_count(1, 4096), 1);
        assert_eq!(block_count(4096, 4096), 1);
        assert_eq!(block_count(4097, 4096), 2);
        assert_eq!(block_count(8192, 4096), 2);
        assert_eq!(block_count(10000, 4096), 3);
    }
}
