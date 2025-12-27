use crate::error::{HypercubeError, Result};
use crate::header::VhcHeader;
use rand::{seq::SliceRandom, thread_rng};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Magic bytes for VHC file format
const VHC_MAGIC: &[u8; 4] = b"VHC\x01";

/// A VHC file containing header and raw blocks
/// Blocks are opaque - no tracking of which partition they belong to
/// Security model: scan all blocks, authenticate each with your secret
#[derive(Debug)]
pub struct VhcFile {
    pub header: VhcHeader,
    /// Raw block data (each block = sequence + data + MAC)
    pub blocks: Vec<Vec<u8>>,
}

impl VhcFile {
    /// Create a new empty VHC file with the given header
    pub fn new(header: VhcHeader) -> Self {
        Self {
            header,
            blocks: Vec::new(),
        }
    }

    /// Add blocks to the file
    pub fn add_blocks(&mut self, new_blocks: Vec<Vec<u8>>) {
        self.blocks.extend(new_blocks);
    }

    /// Get total number of blocks
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

/// Read a VHC file from disk
pub fn read_vhc_file(path: &Path) -> Result<VhcFile> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len() as usize;
    let mut reader = BufReader::new(file);

    // Read and verify magic
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != VHC_MAGIC {
        return Err(HypercubeError::InvalidFormat(
            "Invalid VHC magic bytes".into(),
        ));
    }

    // Read header length (4 bytes, little-endian)
    let mut header_len_bytes = [0u8; 4];
    reader.read_exact(&mut header_len_bytes)?;
    let header_len = u32::from_le_bytes(header_len_bytes) as usize;

    // Read header JSON
    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;
    let header = VhcHeader::from_bytes(&header_bytes)?;

    // Calculate data section size
    let data_start = 4 + 4 + header_len; // magic + header_len + header
    let data_size = file_len - data_start;
    let block_size = header.total_block_size();

    // Read all blocks
    let num_blocks = data_size / block_size;
    let mut blocks = Vec::with_capacity(num_blocks);

    for _ in 0..num_blocks {
        let mut block = vec![0u8; block_size];
        reader.read_exact(&mut block)?;
        blocks.push(block);
    }

    Ok(VhcFile { header, blocks })
}

/// Write a VHC file to disk (creates new file or overwrites)
pub fn write_vhc_file(path: &Path, vhc: &VhcFile) -> Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    // Write magic
    writer.write_all(VHC_MAGIC)?;

    // Serialize header
    let header_bytes = vhc.header.to_bytes()?;

    // Write header length
    let header_len = header_bytes.len() as u32;
    writer.write_all(&header_len.to_le_bytes())?;

    // Write header
    writer.write_all(&header_bytes)?;

    // Write all blocks
    for block in &vhc.blocks {
        writer.write_all(block)?;
    }

    writer.flush()?;
    Ok(())
}

/// Append blocks to an existing VHC file and reshuffle the global block table
pub fn append_blocks_to_vhc(path: &Path, new_blocks: &[Vec<u8>]) -> Result<()> {
    if new_blocks.is_empty() {
        return Ok(());
    }

    let mut vhc = read_vhc_file(path)?;
    vhc.blocks.extend(new_blocks.iter().cloned());

    if vhc.blocks.len() > 1 {
        let mut rng = thread_rng();
        vhc.blocks.shuffle(&mut rng);
    }

    write_vhc_file(path, &vhc)
}

/// Read just the header from a VHC file (without loading all blocks)
pub fn read_vhc_header(path: &Path) -> Result<VhcHeader> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // Read and verify magic
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != VHC_MAGIC {
        return Err(HypercubeError::InvalidFormat(
            "Invalid VHC magic bytes".into(),
        ));
    }

    // Read header length
    let mut header_len_bytes = [0u8; 4];
    reader.read_exact(&mut header_len_bytes)?;
    let header_len = u32::from_le_bytes(header_len_bytes) as usize;

    // Read header JSON
    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;
    VhcHeader::from_bytes(&header_bytes)
}

/// Get block count from file without loading blocks
pub fn get_block_count(path: &Path) -> Result<usize> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len() as usize;
    let mut reader = BufReader::new(file);

    // Skip magic
    reader.seek(SeekFrom::Start(4))?;

    // Read header length
    let mut header_len_bytes = [0u8; 4];
    reader.read_exact(&mut header_len_bytes)?;
    let header_len = u32::from_le_bytes(header_len_bytes) as usize;

    // Read header to get block size
    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;
    let header = VhcHeader::from_bytes(&header_bytes)?;

    // Calculate block count
    let data_start = 4 + 4 + header_len;
    let data_size = file_len - data_start;
    let block_size = header.total_block_size();

    Ok(data_size / block_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_vhc_file_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.vhc");

        // Create a VHC file with some blocks (dimension 32, block_size 64)
        let header = VhcHeader::new(32, 32, 32, 64, 256).unwrap();
        let mut vhc = VhcFile::new(header);

        let block_size = vhc.header.total_block_size();
        let block1: Vec<u8> = (0..block_size).map(|i| (i % 256) as u8).collect();
        let block2: Vec<u8> = (0..block_size).map(|i| ((i + 100) % 256) as u8).collect();

        vhc.add_blocks(vec![block1.clone(), block2.clone()]);

        // Write to disk
        write_vhc_file(&path, &vhc).unwrap();

        // Read back
        let loaded = read_vhc_file(&path).unwrap();

        assert_eq!(loaded.header.dimension, 32);
        assert_eq!(loaded.blocks.len(), 2);
        assert_eq!(loaded.blocks[0], block1);
        assert_eq!(loaded.blocks[1], block2);
    }

    #[test]
    fn test_vhc_invalid_magic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("invalid.vhc");

        std::fs::write(&path, b"INVALID").unwrap();

        let result = read_vhc_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_append_blocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("append.vhc");

        // Create initial file (dimension 32, block_size 64)
        let header = VhcHeader::new(32, 32, 32, 64, 256).unwrap();
        let block_size = header.total_block_size();
        let vhc = VhcFile::new(header);
        write_vhc_file(&path, &vhc).unwrap();

        // Append some blocks
        let block1: Vec<u8> = vec![0xAA; block_size];
        let block2: Vec<u8> = vec![0xBB; block_size];
        append_blocks_to_vhc(&path, &[block1.clone(), block2.clone()]).unwrap();

        // Append more blocks
        let block3: Vec<u8> = vec![0xCC; block_size];
        append_blocks_to_vhc(&path, &[block3.clone()]).unwrap();

        // Read and verify
        let loaded = read_vhc_file(&path).unwrap();
        assert_eq!(loaded.blocks.len(), 3);

        let mut actual = loaded.blocks.clone();
        actual.sort();
        let mut expected = vec![block1, block2, block3];
        expected.sort();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_read_header_only() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("header.vhc");

        let header = VhcHeader::new(32, 32, 32, 128, 512).unwrap();
        let block_size = header.total_block_size();
        let mut vhc = VhcFile::new(header);
        vhc.add_blocks(vec![vec![0u8; block_size]; 100]); // 100 blocks
        write_vhc_file(&path, &vhc).unwrap();

        // Read just header
        let header_only = read_vhc_header(&path).unwrap();
        assert_eq!(header_only.dimension, 32);
        assert_eq!(header_only.block_size, 128);
        assert_eq!(header_only.mac_bits, 512);

        // Get block count
        let count = get_block_count(&path).unwrap();
        assert_eq!(count, 100);
    }
}
