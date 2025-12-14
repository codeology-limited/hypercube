/// Fragment a block into smaller pieces of fragment_size
/// block_size must be evenly divisible by fragment_size (no remainders)
pub fn fragment_block(block: &[u8], fragment_size: usize) -> Vec<Vec<u8>> {
    assert!(
        block.len() % fragment_size == 0,
        "Block size {} must be evenly divisible by fragment size {}",
        block.len(),
        fragment_size
    );

    block
        .chunks_exact(fragment_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Fragment all blocks into a flat list of fragments
/// Returns (fragments, fragments_per_block) for later reconstruction
pub fn fragment_all(blocks: &[Vec<u8>], fragment_size: usize) -> (Vec<Vec<u8>>, usize) {
    if blocks.is_empty() {
        return (Vec::new(), 0);
    }

    let fragments_per_block = blocks[0].len() / fragment_size;
    let mut all_fragments = Vec::with_capacity(blocks.len() * fragments_per_block);

    for block in blocks {
        let frags = fragment_block(block, fragment_size);
        all_fragments.extend(frags);
    }

    (all_fragments, fragments_per_block)
}

/// Unfragment: reassemble fragments back into a block
pub fn unfragment_block(fragments: &[Vec<u8>]) -> Vec<u8> {
    let mut block = Vec::with_capacity(fragments.iter().map(|f| f.len()).sum());
    for frag in fragments {
        block.extend_from_slice(frag);
    }
    block
}

/// Unfragment all: reassemble flat fragment list back into blocks
pub fn unfragment_all(fragments: &[Vec<u8>], fragments_per_block: usize) -> Vec<Vec<u8>> {
    if fragments.is_empty() || fragments_per_block == 0 {
        return Vec::new();
    }

    fragments
        .chunks_exact(fragments_per_block)
        .map(|chunk| unfragment_block(chunk))
        .collect()
}

/// Calculate the best fragment size for a given block size
/// Returns a power of 2 between 16 and 256 that evenly divides block_size
pub fn calculate_fragment_size(block_size: usize) -> usize {
    // Prefer these sizes in order
    for &size in &[64, 128, 32, 256, 16] {
        if block_size % size == 0 {
            return size;
        }
    }
    // Fallback: find any power of 2 that works
    let mut size = 64;
    while size > 1 {
        if block_size % size == 0 {
            return size;
        }
        size /= 2;
    }
    1 // Should never reach here for valid block sizes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_block() {
        let block: Vec<u8> = (0u16..256).map(|i| i as u8).collect();
        let fragments = fragment_block(&block, 64);
        assert_eq!(fragments.len(), 4);
        assert_eq!(fragments[0], (0u8..64).collect::<Vec<u8>>());
        assert_eq!(fragments[1], (64u8..128).collect::<Vec<u8>>());
        assert_eq!(fragments[2], (128u8..192).collect::<Vec<u8>>());
        assert_eq!(
            fragments[3],
            (192u16..256).map(|i| i as u8).collect::<Vec<u8>>()
        );
    }

    #[test]
    fn test_fragment_unfragment_roundtrip() {
        let block: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let fragments = fragment_block(&block, 64);
        let restored = unfragment_block(&fragments);
        assert_eq!(block, restored);
    }

    #[test]
    fn test_fragment_all() {
        let blocks: Vec<Vec<u8>> = vec![
            (0u16..256).map(|i| i as u8).collect(),
            (0u16..256).map(|i| (255 - i) as u8).collect(),
        ];
        let (fragments, frags_per_block) = fragment_all(&blocks, 64);
        assert_eq!(frags_per_block, 4);
        assert_eq!(fragments.len(), 8);
    }

    #[test]
    fn test_fragment_unfragment_all_roundtrip() {
        let blocks: Vec<Vec<u8>> = vec![
            (0..4096).map(|i| (i % 256) as u8).collect(),
            (0..4096).map(|i| (255 - i % 256) as u8).collect(),
            (0..4096).map(|i| ((i * 7) % 256) as u8).collect(),
        ];
        let fragment_size = 64;
        let (fragments, frags_per_block) = fragment_all(&blocks, fragment_size);
        let restored = unfragment_all(&fragments, frags_per_block);
        assert_eq!(blocks, restored);
    }

    #[test]
    fn test_calculate_fragment_size() {
        assert_eq!(calculate_fragment_size(4096), 64);
        assert_eq!(calculate_fragment_size(2048), 64);
        assert_eq!(calculate_fragment_size(8192), 64);
        assert_eq!(calculate_fragment_size(65536), 64);
    }

    #[test]
    #[should_panic]
    fn test_fragment_uneven_panics() {
        let block: Vec<u8> = vec![0; 100];
        fragment_block(&block, 64); // 100 is not divisible by 64
    }
}
