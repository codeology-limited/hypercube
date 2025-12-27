use thiserror::Error;

#[derive(Error, Debug)]
pub enum HypercubeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Invalid block size: {0}. Must be positive and even")]
    InvalidBlockSize(usize),

    #[error("Invalid cube size: {0}. Must be 16-2048 bits and divisible by 8")]
    InvalidCubeSize(usize),

    #[error("Invalid dimension: {0}. Must be a multiple of 8 (8, 16, 24, 32, ...)")]
    InvalidDimension(usize),

    #[error("Invalid MAC bits: {0}. Must be 128, 256, or 512")]
    InvalidMacBits(usize),

    #[error("Partition {0} not found")]
    PartitionNotFound(usize),

    #[error("Partition {0} already exists")]
    PartitionExists(usize),

    #[error("Cube is full: maximum {0} blocks reached")]
    FileFull(usize),

    #[error("Data too large: {data_size} bytes, max {max_size} bytes per partition. Delete existing .vhc file to resize.")]
    DataTooLarge { data_size: usize, max_size: usize },

    #[error("Payload requires {0} bytes, exceeding maximum cube capacity (512 KiB)")]
    PayloadTooLarge(usize),

    #[error("Invalid cube id: {0}")]
    InvalidCube(usize),

    #[error("MAC verification failed for partition {0}")]
    MacVerificationFailed(usize),

    #[error("Compression error: {0}")]
    CompressionError(String),

    #[error("Decompression error: {0}")]
    DecompressionError(String),

    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Data integrity error: {0}")]
    IntegrityError(String),

    #[error("Secret required")]
    SecretRequired,
}

pub type Result<T> = std::result::Result<T, HypercubeError>;
