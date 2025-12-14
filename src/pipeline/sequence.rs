/// Sequence number size in bytes (128 bits = 16 bytes)
pub const SEQUENCE_SIZE: usize = 16;

/// A 128-bit sequence number
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SequenceNumber([u8; SEQUENCE_SIZE]);

impl SequenceNumber {
    /// Create a new sequence number from a u128
    pub fn new(value: u128) -> Self {
        Self(value.to_le_bytes())
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; SEQUENCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; SEQUENCE_SIZE] {
        &self.0
    }

    /// Convert to u128
    pub fn to_u128(&self) -> u128 {
        u128::from_le_bytes(self.0)
    }

    /// Increment the sequence number
    pub fn increment(&mut self) {
        let val = self.to_u128().wrapping_add(1);
        self.0 = val.to_le_bytes();
    }
}

impl Default for SequenceNumber {
    fn default() -> Self {
        Self::new(0)
    }
}

/// A block with its sequence number attached
#[derive(Debug, Clone)]
pub struct SequencedBlock {
    pub sequence: SequenceNumber,
    pub data: Vec<u8>,
}

impl SequencedBlock {
    /// Create a new sequenced block
    pub fn new(sequence: SequenceNumber, data: Vec<u8>) -> Self {
        Self { sequence, data }
    }

    /// Serialize to bytes: sequence || data
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(SEQUENCE_SIZE + self.data.len());
        result.extend_from_slice(self.sequence.as_bytes());
        result.extend_from_slice(&self.data);
        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < SEQUENCE_SIZE {
            return None;
        }

        let mut seq_bytes = [0u8; SEQUENCE_SIZE];
        seq_bytes.copy_from_slice(&bytes[..SEQUENCE_SIZE]);

        Some(Self {
            sequence: SequenceNumber::from_bytes(seq_bytes),
            data: bytes[SEQUENCE_SIZE..].to_vec(),
        })
    }
}

/// Add sequence numbers to blocks
/// Sequences start from a random base for each compartment
pub fn sequence_blocks(blocks: Vec<Vec<u8>>, base: u128) -> Vec<SequencedBlock> {
    let mut seq = SequenceNumber::new(base);
    let mut result = Vec::with_capacity(blocks.len());

    for block in blocks {
        result.push(SequencedBlock::new(seq, block));
        seq.increment();
    }

    result
}

/// Remove sequence numbers and verify ordering
/// Returns blocks in sequence order, or None if sequences are invalid
pub fn unsequence_blocks(mut blocks: Vec<SequencedBlock>) -> Option<Vec<Vec<u8>>> {
    if blocks.is_empty() {
        return Some(Vec::new());
    }

    // Sort by sequence number
    blocks.sort_by_key(|b| b.sequence);

    // Verify consecutive sequences
    let base = blocks[0].sequence.to_u128();
    for (i, block) in blocks.iter().enumerate() {
        if block.sequence.to_u128() != base.wrapping_add(i as u128) {
            return None; // Missing or duplicate sequence
        }
    }

    Some(blocks.into_iter().map(|b| b.data).collect())
}

/// Generate a random base sequence number
pub fn generate_sequence_base() -> u128 {
    use rand::Rng;
    rand::thread_rng().gen()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_number() {
        let seq = SequenceNumber::new(12345);
        assert_eq!(seq.to_u128(), 12345);

        let mut seq = SequenceNumber::new(0);
        seq.increment();
        assert_eq!(seq.to_u128(), 1);
    }

    #[test]
    fn test_sequence_number_overflow() {
        let mut seq = SequenceNumber::new(u128::MAX);
        seq.increment();
        assert_eq!(seq.to_u128(), 0); // Wraps around
    }

    #[test]
    fn test_sequenced_block_serialization() {
        let block = SequencedBlock::new(SequenceNumber::new(42), vec![1, 2, 3, 4, 5]);

        let bytes = block.to_bytes();
        assert_eq!(bytes.len(), SEQUENCE_SIZE + 5);

        let restored = SequencedBlock::from_bytes(&bytes).unwrap();
        assert_eq!(restored.sequence, block.sequence);
        assert_eq!(restored.data, block.data);
    }

    #[test]
    fn test_sequence_unsequence_roundtrip() {
        let blocks: Vec<Vec<u8>> = (0..10).map(|i| vec![i as u8; 64]).collect();

        let base = 1000u128;
        let sequenced = sequence_blocks(blocks.clone(), base);

        assert_eq!(sequenced.len(), 10);
        assert_eq!(sequenced[0].sequence.to_u128(), 1000);
        assert_eq!(sequenced[9].sequence.to_u128(), 1009);

        let unsequenced = unsequence_blocks(sequenced).unwrap();
        assert_eq!(blocks, unsequenced);
    }

    #[test]
    fn test_unsequence_reorders() {
        let blocks: Vec<Vec<u8>> = vec![vec![0; 4], vec![1; 4], vec![2; 4]];

        let mut sequenced = sequence_blocks(blocks.clone(), 0);

        // Shuffle the order
        sequenced.swap(0, 2);
        sequenced.swap(1, 2);

        // Should still recover original order
        let unsequenced = unsequence_blocks(sequenced).unwrap();
        assert_eq!(blocks, unsequenced);
    }

    #[test]
    fn test_unsequence_detects_missing() {
        let blocks: Vec<Vec<u8>> = vec![vec![0; 4], vec![1; 4], vec![2; 4]];

        let mut sequenced = sequence_blocks(blocks, 0);
        sequenced.remove(1); // Remove middle block

        // Should fail due to missing sequence
        assert!(unsequence_blocks(sequenced).is_none());
    }

    #[test]
    fn test_unsequence_empty() {
        let blocks: Vec<SequencedBlock> = Vec::new();
        let result = unsequence_blocks(blocks);
        assert_eq!(result, Some(Vec::new()));
    }

    #[test]
    fn test_from_bytes_too_short() {
        let bytes = vec![0u8; 10]; // Less than SEQUENCE_SIZE
        assert!(SequencedBlock::from_bytes(&bytes).is_none());
    }
}
