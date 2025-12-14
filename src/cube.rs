use crate::error::{HypercubeError, Result};
use crate::header::{CompartmentMeta, Compression};
use crate::pipeline::compress;

/// Cube configuration describing compartment/blocks layout
#[derive(Debug, Clone, Copy)]
pub struct CubeConfig {
    pub id: usize,
    pub compartments: usize,
    pub blocks_per_compartment: usize,
}

impl CubeConfig {
    pub fn total_blocks(&self) -> usize {
        self.compartments * self.blocks_per_compartment
    }
}

/// Look up a cube configuration by id
pub fn cube_config(id: usize) -> Result<CubeConfig> {
    match id {
        1 => Ok(CubeConfig {
            id: 1,
            compartments: 32,
            blocks_per_compartment: 32,
        }),
        other => Err(HypercubeError::InvalidCube(other)),
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
pub fn analyze_data(
    data: &[u8],
    compression: Compression,
    cube: CubeConfig,
) -> Result<CubeAnalysis> {
    let compressed = compress(data, compression)?;
    let payload_bytes = CompartmentMeta::SIZE + compressed.len();
    let block_size_bytes = required_block_size(payload_bytes, cube);
    let capacity_bytes = block_size_bytes * cube.blocks_per_compartment;

    Ok(CubeAnalysis {
        cube,
        original_bytes: data.len(),
        compressed_bytes: compressed.len(),
        payload_bytes,
        block_size_bytes,
        capacity_bytes,
    })
}

/// Determine the minimal block size (bytes) needed to hold payload across the cube's blocks
pub fn required_block_size(payload_bytes: usize, cube: CubeConfig) -> usize {
    let blocks = cube.blocks_per_compartment.max(1);
    let per_block = (payload_bytes + blocks - 1) / blocks;
    per_block.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cube_config_lookup() {
        let cfg = cube_config(1).unwrap();
        assert_eq!(cfg.compartments, 32);
        assert_eq!(cfg.blocks_per_compartment, 32);
        assert_eq!(cfg.total_blocks(), 1024);
    }

    #[test]
    fn test_required_block_size() {
        let cfg = cube_config(1).unwrap();
        let block = required_block_size(640, cfg);
        assert_eq!(block, 20);
    }
}
