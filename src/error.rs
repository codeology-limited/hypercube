use thiserror::Error;

#[derive(Error, Debug)]
pub enum HypercubeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Invalid block size: {0}. Must be between 2KB and 512KB and a power of 2")]
    InvalidBlockSize(usize),

    #[error("Invalid dimension: {0}. Must be between 2 and 65536")]
    InvalidDimension(usize),

    #[error("Invalid MAC bits: {0}. Must be 128, 256, or 512")]
    InvalidMacBits(usize),

    #[error("Compartment {0} not found")]
    CompartmentNotFound(usize),

    #[error("Compartment {0} already exists")]
    CompartmentExists(usize),

    #[error("File is full: maximum {0} compartments reached")]
    FileFull(usize),

    #[error("MAC verification failed for compartment {0}")]
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
