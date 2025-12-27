use crate::error::Result;
use crate::header::{PartitionMeta, Compression};
use crate::pipeline::compress;

/// Cube configuration describing partition/blocks layout
/// For a hypercube, partitions == blocks_per_partition (N×N)
#[derive(Debug, Clone, Copy)]
pub struct CubeConfig {
    /// Cube identifier (equals dimension for hypercubes)
    pub id: usize,
    /// Number of partitions (dimension)
    pub partitions: usize,
    /// Blocks per partition (equals partitions for hypercubes)
    pub blocks_per_partition: usize,
}

impl CubeConfig {
    /// Create a new hypercube configuration with dimension N
    /// Results in N partitions, each with N blocks (N×N total)
    pub fn hypercube(dimension: usize) -> Self {
        Self {
            id: dimension,
            partitions: dimension,
            blocks_per_partition: dimension,
        }
    }

    pub fn total_blocks(&self) -> usize {
        self.partitions * self.blocks_per_partition
    }
}

/// Summary of how a payload maps to a cube
#[derive(Debug, Clone)]
pub struct CubeAnalysis {
    pub cube: CubeConfig,
    pub original_bytes: usize,
    pub compressed_bytes: usize,
    pub payload_bytes: usize,
    pub block_size_bytes: usize,
    pub capacity_bytes: usize,
}

impl CubeAnalysis {
    pub fn headroom_bytes(&self) -> usize {
        self.capacity_bytes.saturating_sub(self.payload_bytes)
    }
}

/// Analyze data for a specific cube & compression setting
/// Note: For Rivest AONT, one block is used for the key, so effective data blocks = blocks_per_partition - 1
pub fn analyze_data(
    data: &[u8],
    compression: Compression,
    cube: CubeConfig,
) -> Result<CubeAnalysis> {
    let compressed = compress(data, compression)?;
    let payload_bytes = PartitionMeta::SIZE + compressed.len();
    // Reserve one block for AONT key
    let data_blocks = cube.blocks_per_partition.saturating_sub(1).max(1);
    let block_size_bytes = required_block_size(payload_bytes, data_blocks);
    let capacity_bytes = block_size_bytes * data_blocks;

    Ok(CubeAnalysis {
        cube,
        original_bytes: data.len(),
        compressed_bytes: compressed.len(),
        payload_bytes,
        block_size_bytes,
        capacity_bytes,
    })
}

/// Determine the minimal block size (bytes) needed to hold payload across given number of blocks
pub fn required_block_size(payload_bytes: usize, blocks: usize) -> usize {
    let blocks = blocks.max(1);
    let per_block = (payload_bytes + blocks - 1) / blocks;
    per_block.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypercube_config() {
        let cfg = CubeConfig::hypercube(32);
        assert_eq!(cfg.partitions, 32);
        assert_eq!(cfg.blocks_per_partition, 32);
        assert_eq!(cfg.total_blocks(), 1024);
    }

    #[test]
    fn test_hypercube_small() {
        let cfg = CubeConfig::hypercube(8);
        assert_eq!(cfg.partitions, 8);
        assert_eq!(cfg.blocks_per_partition, 8);
        assert_eq!(cfg.total_blocks(), 64);
    }

    #[test]
    fn test_required_block_size() {
        // 31 data blocks (one reserved for AONT key)
        let block = required_block_size(640, 31);
        assert_eq!(block, 21); // ceil(640/31) = 21
    }
}
