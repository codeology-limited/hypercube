use crate::error::{HypercubeError, Result};
use serde::{Deserialize, Serialize};

/// Compression algorithm options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    #[default]
    Zstd,
    Lz4,
    Brotli,
    None,
}

impl std::str::FromStr for Compression {
    type Err = HypercubeError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "zstd" => Ok(Self::Zstd),
            "lz4" => Ok(Self::Lz4),
            "brotli" => Ok(Self::Brotli),
            "none" => Ok(Self::None),
            _ => Err(HypercubeError::UnsupportedAlgorithm(format!(
                "compression: {}",
                s
            ))),
        }
    }
}

/// Shuffle algorithm options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Shuffle {
    #[default]
    Feistel,
    FisherYates,
}

impl std::str::FromStr for Shuffle {
    type Err = HypercubeError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "feistel" => Ok(Self::Feistel),
            "fisher-yates" | "fisheryates" => Ok(Self::FisherYates),
            _ => Err(HypercubeError::UnsupportedAlgorithm(format!(
                "shuffle: {}",
                s
            ))),
        }
    }
}

/// AONT algorithm options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Aont {
    #[default]
    Rivest,
    Oaep,
}

impl std::str::FromStr for Aont {
    type Err = HypercubeError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "rivest" => Ok(Self::Rivest),
            "oaep" => Ok(Self::Oaep),
            _ => Err(HypercubeError::UnsupportedAlgorithm(format!("aont: {}", s))),
        }
    }
}

/// Hash algorithm options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    #[default]
    Sha3,
    Blake3,
    Sha256,
}

impl std::str::FromStr for HashAlgorithm {
    type Err = HypercubeError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "sha3" => Ok(Self::Sha3),
            "blake3" => Ok(Self::Blake3),
            "sha256" => Ok(Self::Sha256),
            _ => Err(HypercubeError::UnsupportedAlgorithm(format!("hash: {}", s))),
        }
    }
}

/// Whitener algorithm options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Whitener {
    #[default]
    Keccak,
    Xor,
}

impl std::str::FromStr for Whitener {
    type Err = HypercubeError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "keccak" => Ok(Self::Keccak),
            "xor" => Ok(Self::Xor),
            _ => Err(HypercubeError::UnsupportedAlgorithm(format!(
                "whitener: {}",
                s
            ))),
        }
    }
}

/// Compartment metadata - stored at the START of compressed data
/// Layout: [compressed_size: 8][original_size: 8][shuffle_seed: 32][compressed data...]
#[derive(Debug, Clone)]
pub struct CompartmentMeta {
    /// Compressed size in bytes (excluding this metadata header)
    pub compressed_size: u64,
    /// Original (uncompressed) size in bytes
    pub original_size: u64,
    /// Shuffle seed derived from secret (for verification)
    pub shuffle_seed: [u8; 32],
}

impl CompartmentMeta {
    /// Metadata size: 8 bytes (compressed) + 8 bytes (original) + 32 bytes (seed) = 48 bytes
    pub const SIZE: usize = 48;

    /// Serialize metadata to bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.compressed_size.to_le_bytes());
        buf[8..16].copy_from_slice(&self.original_size.to_le_bytes());
        buf[16..48].copy_from_slice(&self.shuffle_seed);
        buf
    }

    /// Deserialize metadata from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(HypercubeError::InvalidFormat("Metadata too short".into()));
        }
        let compressed_size = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let original_size = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let mut shuffle_seed = [0u8; 32];
        shuffle_seed.copy_from_slice(&data[16..48]);
        Ok(Self {
            compressed_size,
            original_size,
            shuffle_seed,
        })
    }
}

/// VHC file header - plaintext, describes global parameters only
/// NO compartment information stored - that would reveal which blocks belong together
/// Security model: scan all blocks, authenticate each with your secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VhcHeader {
    /// Format version
    pub version: u32,
    /// Cube identifier (maps to compartment/block layout)
    pub cube_id: usize,
    /// Number of compartments (dimension along one axis)
    pub dimension: usize,
    /// Blocks per compartment
    pub blocks_per_compartment: usize,
    /// Block size in bytes (payload)
    pub block_size: usize,
    /// MAC tag size in bits (128, 256, or 512)
    pub mac_bits: usize,
    /// Compression algorithm
    pub compression: Compression,
    /// Shuffle algorithm
    pub shuffle: Shuffle,
    /// AONT algorithm
    pub aont: Aont,
    /// Hash algorithm for MAC
    pub hash: HashAlgorithm,
    /// Whitener algorithm
    pub whitener: Whitener,
    /// Fragment size in bytes
    pub fragment_size: usize,
}

impl Default for VhcHeader {
    fn default() -> Self {
        let cube_id = 1;
        let compartments = 32;
        let blocks_per_compartment = 32;
        let block_size = 32;
        Self {
            version: 1,
            cube_id,
            dimension: compartments,
            blocks_per_compartment,
            block_size,
            mac_bits: 256,
            compression: Compression::default(),
            shuffle: Shuffle::default(),
            aont: Aont::default(),
            hash: HashAlgorithm::default(),
            whitener: Whitener::default(),
            fragment_size: Self::calculate_fragment_size(block_size),
        }
    }
}

impl VhcHeader {
    /// Create a new header using an explicit geometry
    pub fn new(
        cube_id: usize,
        compartments: usize,
        blocks_per_compartment: usize,
        block_size: usize,
        mac_bits: usize,
    ) -> Result<Self> {
        if compartments < 1 || compartments > 65536 {
            return Err(HypercubeError::InvalidDimension(compartments));
        }
        if blocks_per_compartment < 1 || blocks_per_compartment > 65536 {
            return Err(HypercubeError::InvalidDimension(blocks_per_compartment));
        }
        if block_size == 0 {
            return Err(HypercubeError::InvalidBlockSize(block_size));
        }

        // Validate MAC bits
        if mac_bits != 128 && mac_bits != 256 && mac_bits != 512 {
            return Err(HypercubeError::InvalidMacBits(mac_bits));
        }

        let fragment_size = Self::calculate_fragment_size(block_size);

        Ok(Self {
            version: 1,
            cube_id,
            dimension: compartments,
            blocks_per_compartment,
            block_size,
            mac_bits,
            fragment_size,
            ..Default::default()
        })
    }

    /// Calculate fragment size for a given block size
    /// Smaller cubes shuffle tiny fragments; larger cubes promote chunkier fragments
    fn calculate_fragment_size(block_size: usize) -> usize {
        if block_size == 0 {
            return 1;
        }
        // Aim for roughly <=16 fragments per block, clamp fragment size to <=256 bytes
        let mut frag_size = 1;
        while frag_size * 2 <= block_size
            && (block_size / (frag_size * 2)) > 8
            && frag_size * 2 <= 256
        {
            frag_size *= 2;
        }
        while frag_size > 1 && block_size % frag_size != 0 {
            frag_size /= 2;
        }
        frag_size
    }

    /// Serialize header to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserialize header from JSON bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(data)?)
    }

    /// Get number of fragments per block
    pub fn fragments_per_block(&self) -> usize {
        self.block_size / self.fragment_size
    }

    /// Get MAC size in bytes
    pub fn mac_bytes(&self) -> usize {
        self.mac_bits / 8
    }

    /// Get block payload size in bits
    pub fn block_bits(&self) -> usize {
        self.block_size * 8
    }

    /// Cube size (also equals compartments and blocks per compartment)
    pub fn cube(&self) -> usize {
        self.cube_id
    }

    /// Blocks per compartment
    pub fn blocks_per_compartment(&self) -> usize {
        self.blocks_per_compartment
    }

    /// Total blocks when the cube is full
    pub fn theoretical_block_count(&self) -> usize {
        self.blocks_per_compartment * self.dimension
    }

    /// Maximum payload capacity (excluding MAC/sequence/header)
    pub fn payload_capacity_bytes(&self) -> usize {
        self.block_size * self.theoretical_block_count()
    }

    /// Get total block size (data + sequence + MAC)
    pub fn total_block_size(&self) -> usize {
        self.block_size + 16 + self.mac_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_creation() {
        let header = VhcHeader::new(1, 32, 32, 64, 256).unwrap();
        assert_eq!(header.cube_id, 1);
        assert_eq!(header.dimension, 32);
        assert_eq!(header.blocks_per_compartment, 32);
        assert_eq!(header.block_size, 64);
        assert_eq!(header.mac_bits, 256);
        assert_eq!(header.total_block_size(), 64 + 16 + 32);
    }

    #[test]
    fn test_invalid_geometry() {
        assert!(VhcHeader::new(1, 0, 32, 64, 256).is_err());
        assert!(VhcHeader::new(1, 32, 0, 64, 256).is_err());
        assert!(VhcHeader::new(1, 32, 32, 0, 256).is_err());
    }

    #[test]
    fn test_serialization() {
        let header = VhcHeader::new(1, 32, 32, 128, 512).unwrap();
        let bytes = header.to_bytes().unwrap();
        let restored = VhcHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.cube_id, restored.cube_id);
        assert_eq!(header.block_size, restored.block_size);
        assert_eq!(header.mac_bits, restored.mac_bits);
    }

    #[test]
    fn test_compartment_meta() {
        let meta = CompartmentMeta {
            compressed_size: 1000,
            original_size: 12345,
            shuffle_seed: [0xAB; 32],
        };
        let bytes = meta.to_bytes();
        let restored = CompartmentMeta::from_bytes(&bytes).unwrap();
        assert_eq!(meta.compressed_size, restored.compressed_size);
        assert_eq!(meta.original_size, restored.original_size);
        assert_eq!(meta.shuffle_seed, restored.shuffle_seed);
    }
}
