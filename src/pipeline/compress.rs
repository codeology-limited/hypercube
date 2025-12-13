use crate::error::{HypercubeError, Result};
use crate::header::Compression;
use std::io::{Read, Write};

/// Compress data using the specified algorithm
pub fn compress(data: &[u8], algorithm: Compression) -> Result<Vec<u8>> {
    match algorithm {
        Compression::Zstd => compress_zstd(data),
        Compression::Lz4 => compress_lz4(data),
        Compression::Brotli => compress_brotli(data),
        Compression::None => Ok(data.to_vec()),
    }
}

/// Decompress data using the specified algorithm
pub fn decompress(data: &[u8], algorithm: Compression) -> Result<Vec<u8>> {
    match algorithm {
        Compression::Zstd => decompress_zstd(data),
        Compression::Lz4 => decompress_lz4(data),
        Compression::Brotli => decompress_brotli(data),
        Compression::None => Ok(data.to_vec()),
    }
}

fn compress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    zstd::encode_all(data, 3)
        .map_err(|e| HypercubeError::CompressionError(format!("zstd: {}", e)))
}

fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(data)
        .map_err(|e| HypercubeError::DecompressionError(format!("zstd: {}", e)))
}

fn compress_lz4(data: &[u8]) -> Result<Vec<u8>> {
    Ok(lz4_flex::compress_prepend_size(data))
}

fn decompress_lz4(data: &[u8]) -> Result<Vec<u8>> {
    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| HypercubeError::DecompressionError(format!("lz4: {}", e)))
}

fn compress_brotli(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut writer = brotli::CompressorWriter::new(&mut output, 4096, 4, 22);
    writer.write_all(data)
        .map_err(|e| HypercubeError::CompressionError(format!("brotli: {}", e)))?;
    drop(writer);
    Ok(output)
}

fn decompress_brotli(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut reader = brotli::Decompressor::new(data, 4096);
    reader.read_to_end(&mut output)
        .map_err(|e| HypercubeError::DecompressionError(format!("brotli: {}", e)))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_roundtrip(algorithm: Compression, data: &[u8]) {
        let compressed = compress(data, algorithm).unwrap();
        let decompressed = decompress(&compressed, algorithm).unwrap();
        assert_eq!(data, &decompressed[..]);
    }

    #[test]
    fn test_zstd_roundtrip() {
        test_roundtrip(Compression::Zstd, b"Hello, World! This is a test of compression.");
    }

    #[test]
    fn test_lz4_roundtrip() {
        test_roundtrip(Compression::Lz4, b"Hello, World! This is a test of compression.");
    }

    #[test]
    fn test_brotli_roundtrip() {
        test_roundtrip(Compression::Brotli, b"Hello, World! This is a test of compression.");
    }

    #[test]
    fn test_none_roundtrip() {
        test_roundtrip(Compression::None, b"Hello, World! This is a test of compression.");
    }

    #[test]
    fn test_empty_data() {
        for alg in [Compression::Zstd, Compression::Lz4, Compression::Brotli, Compression::None] {
            test_roundtrip(alg, b"");
        }
    }

    #[test]
    fn test_large_data() {
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        for alg in [Compression::Zstd, Compression::Lz4, Compression::Brotli, Compression::None] {
            test_roundtrip(alg, &data);
        }
    }
}
