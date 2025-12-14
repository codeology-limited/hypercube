use crate::error::{HypercubeError, Result};
use crate::header::{CompartmentMeta, VhcHeader};
use crate::pipeline::{
    apply_aont, authenticate_blocks, compress, decompress, fragment_all, generate_sequence_base,
    reverse_aont, segment, sequence_blocks, unfragment_all, unsequence_blocks, unwhiten_fragments,
    verify_mac, whiten_fragments, AuthenticatedBlock, SequenceNumber, SequencedBlock,
    SEQUENCE_SIZE,
};
use rand::{rngs::OsRng, Rng, RngCore};

/// Result of creating a compartment - just the serialized blocks
pub struct CreateCompartmentResult {
    /// Serialized blocks ready for storage (each = sequence + data + MAC)
    pub blocks: Vec<Vec<u8>>,
}

/// Generate a random shuffle seed using system CSPRNG
pub fn generate_shuffle_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut seed);
    seed
}

/// Create a compartment from input data
/// Applies the full pipeline: Compress → [Metadata+Compressed] → Segment → Fragment → Shuffle → Whiten → AONT → Sequence → AuthMAC
/// Shuffle seed is derived from secret (deterministic for each secret)
/// Metadata is prepended to compressed data for extraction
/// If `pad_to_blocks` is provided, the payload is padded to occupy exactly that many blocks.
pub fn create_compartment(
    data: &[u8],
    secret: &[u8],
    header: &VhcHeader,
    pad_to_blocks: Option<usize>,
) -> Result<CreateCompartmentResult> {
    // Derive shuffle seed from secret (deterministic)
    // Same secret always produces same shuffle pattern
    let shuffle_seed = derive_shuffle_seed(secret);

    // Step 1: Compress the original data
    let compressed = compress(data, header.compression)?;

    // Step 2: Prepend metadata to compressed data
    // Metadata contains sizes needed to remove padding during extraction
    let meta = CompartmentMeta {
        compressed_size: compressed.len() as u64,
        original_size: data.len() as u64,
        shuffle_seed,
    };
    let mut data_with_meta = Vec::with_capacity(CompartmentMeta::SIZE + compressed.len());
    data_with_meta.extend_from_slice(&meta.to_bytes());
    data_with_meta.extend_from_slice(&compressed);

    if let Some(target_blocks) = pad_to_blocks {
        if target_blocks == 0 {
            return Err(HypercubeError::InvalidDimension(0));
        }
        let target_bytes = header.block_size * target_blocks;
        if data_with_meta.len() > target_bytes {
            return Err(HypercubeError::FileFull(target_blocks));
        }
        if data_with_meta.len() < target_bytes {
            data_with_meta.resize(target_bytes, 0u8);
        }
    }

    // Step 3: Segment into blocks (metadata + compressed data)
    let blocks = segment(&data_with_meta, header.block_size);

    // Step 3: Fragment blocks
    let (mut fragments, frags_per_block) = fragment_all(&blocks, header.fragment_size);

    // Step 4: Global shuffle using random seed
    shuffle_fragments(&mut fragments, &shuffle_seed);

    // Step 5: Whiten (UNKEYED - deterministic)
    whiten_fragments(&mut fragments, header.whitener);

    // Step 6: Apply AONT (KEYLESS)
    apply_aont(&mut fragments, header.aont);

    // Step 7: Unfragment back to blocks (for sequencing and MAC)
    let transformed_blocks = unfragment_all(&fragments, frags_per_block);

    // Step 8: Add sequence numbers (uses system CSPRNG for base)
    let sequence_base = generate_sequence_base();
    let sequenced = sequence_blocks(transformed_blocks, sequence_base);

    // Step 9: Authenticate with MAC (KEYED - only step using secret)
    let authenticated = authenticate_blocks(sequenced, secret, header.hash, header.mac_bits);

    // Step 10: Serialize blocks for storage
    let serialized: Vec<Vec<u8>> = authenticated
        .iter()
        .map(|block| {
            let mut buf = Vec::with_capacity(SEQUENCE_SIZE + block.data.len() + block.mac.len());
            buf.extend_from_slice(&block.sequence_bytes);
            buf.extend_from_slice(&block.data);
            buf.extend_from_slice(&block.mac);
            buf
        })
        .collect();

    Ok(CreateCompartmentResult { blocks: serialized })
}

/// Extract data from a VHC file by scanning ALL blocks and authenticating each
///
/// Security model: Scan every block, try to authenticate with secret.
/// Collect blocks that pass MAC verification - those are your compartment's blocks.
/// Metadata (original_size + shuffle_seed) is embedded in the recovered data.
pub fn extract_compartment(
    all_blocks: &[Vec<u8>],
    secret: &[u8],
    header: &VhcHeader,
) -> Result<Vec<u8>> {
    let mac_bytes = header.mac_bytes();
    let data_size = header.block_size;
    let expected_block_size = SEQUENCE_SIZE + data_size + mac_bytes;

    // Step 1: Scan ALL blocks, authenticate each with secret
    // Collect blocks that pass MAC verification
    let mut authenticated_blocks: Vec<AuthenticatedBlock> = Vec::new();

    for block in all_blocks {
        if block.len() != expected_block_size {
            continue; // Wrong size, skip
        }

        // Parse block into components
        let mut sequence_bytes = [0u8; SEQUENCE_SIZE];
        sequence_bytes.copy_from_slice(&block[..SEQUENCE_SIZE]);
        let block_data = &block[SEQUENCE_SIZE..SEQUENCE_SIZE + data_size];
        let mac = &block[SEQUENCE_SIZE + data_size..];

        let auth_block = AuthenticatedBlock {
            sequence_bytes,
            data: block_data.to_vec(),
            mac: mac.to_vec(),
        };

        // Try to verify MAC with our secret
        if verify_mac(&auth_block, secret, header.hash, header.mac_bits) {
            authenticated_blocks.push(auth_block);
        }
    }

    if authenticated_blocks.is_empty() {
        return Err(HypercubeError::IntegrityError(
            "No blocks authenticated with this secret".into(),
        ));
    }

    // Step 2: Extract sequenced blocks (MAC already verified)
    let sequenced: Vec<SequencedBlock> = authenticated_blocks
        .into_iter()
        .map(|b| SequencedBlock {
            sequence: SequenceNumber::from_bytes(b.sequence_bytes),
            data: b.data,
        })
        .collect();

    // Step 3: Remove sequence numbers and verify order
    let transformed_blocks = unsequence_blocks(sequenced)
        .ok_or_else(|| HypercubeError::IntegrityError("Invalid sequence numbers".into()))?;

    // We need to know the compressed size for unsegment
    // But we don't know it yet - we'll discover it after decompression
    // For now, join all blocks and decompress will handle it

    // Step 4: Fragment for reverse transforms
    let (mut fragments, frags_per_block) = fragment_all(&transformed_blocks, header.fragment_size);

    // At this point we need the shuffle_seed, but we don't have it yet!
    // It's embedded in the data... but we need to unshuffle to get the data.
    //
    // SOLUTION: The shuffle_seed must come from somewhere we can access.
    // Option 1: Derive from secret (deterministic)
    // Option 2: Try all possible seeds (impractical)
    // Option 3: Store encrypted shuffle_seed alongside blocks
    //
    // For now, we derive shuffle_seed from the secret itself
    let shuffle_seed = derive_shuffle_seed(secret);

    // Step 5: Reverse AONT
    reverse_aont(&mut fragments, header.aont);

    // Step 6: Unwhiten
    unwhiten_fragments(&mut fragments, header.whitener);

    // Step 7: Unshuffle using derived seed
    unshuffle_fragments(&mut fragments, &shuffle_seed);

    // Step 8: Unfragment back to blocks
    let blocks = unfragment_all(&fragments, frags_per_block);

    // Step 9: Join all blocks
    let mut all_data = Vec::new();
    for block in blocks {
        all_data.extend_from_slice(&block);
    }

    // Step 10: Extract metadata from the start
    if all_data.len() < CompartmentMeta::SIZE {
        return Err(HypercubeError::IntegrityError(
            "Data too short for metadata".into(),
        ));
    }

    let meta = CompartmentMeta::from_bytes(&all_data)?;

    // Verify the embedded shuffle_seed matches our derived one
    // (This confirms the secret is correct and data is intact)
    if meta.shuffle_seed != shuffle_seed {
        return Err(HypercubeError::IntegrityError(
            "Shuffle seed mismatch".into(),
        ));
    }

    // Step 11: Extract compressed data (remove padding using compressed_size)
    let compressed_start = CompartmentMeta::SIZE;
    let compressed_end = compressed_start + meta.compressed_size as usize;

    if compressed_end > all_data.len() {
        return Err(HypercubeError::IntegrityError(
            "Invalid compressed size in metadata".into(),
        ));
    }

    let compressed = &all_data[compressed_start..compressed_end];

    // Step 12: Decompress to get original data
    let data = decompress(compressed, header.compression)?;

    // Verify original size matches
    if data.len() != meta.original_size as usize {
        return Err(HypercubeError::IntegrityError(
            "Original size mismatch after decompression".into(),
        ));
    }

    Ok(data)
}

/// Derive shuffle seed deterministically from secret
/// This allows extraction without storing the seed separately
fn derive_shuffle_seed(secret: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"hypercube_shuffle_seed_v1");
    hasher.update(secret);
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    seed
}

/// Index-space Feistel permutation
///
/// This implements a true Feistel network on indices (not data):
/// - For each index i, compute π(i) using Feistel rounds
/// - No permutation tables needed - computed on the fly
/// - Fully reversible by running rounds backwards
/// - Uses "cycle walking" for non-power-of-2 sizes
///
/// Number of Feistel rounds (6 is standard for good diffusion)
const FEISTEL_ROUNDS: usize = 6;

/// Compute the Feistel round function F(R, round, seed)
fn feistel_round_function(right: u64, round: usize, seed: &[u8; 32]) -> u64 {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(b"hypercube_feistel_v1");
    hasher.update(seed);
    hasher.update(round.to_le_bytes());
    hasher.update(right.to_le_bytes());
    let hash = hasher.finalize();

    // Take first 8 bytes as u64
    u64::from_le_bytes(hash[..8].try_into().unwrap())
}

/// Apply forward Feistel permutation to a single index
/// Uses cycle walking for non-power-of-2 sizes
fn feistel_permute(index: usize, n: usize, seed: &[u8; 32]) -> usize {
    if n <= 1 {
        return index;
    }

    // Find smallest power of 2 >= n
    let bits = (usize::BITS - (n - 1).leading_zeros()) as usize;
    let half_bits = (bits + 1) / 2;
    let mask = (1u64 << half_bits) - 1;

    let mut result = index as u64;

    // Cycle walking: keep applying Feistel until we get a valid index
    loop {
        // Split into left and right halves
        let mut left = result >> half_bits;
        let mut right = result & mask;

        // Apply Feistel rounds
        for round in 0..FEISTEL_ROUNDS {
            let f = feistel_round_function(right, round, seed) & mask;
            let new_right = left ^ f;
            left = right;
            right = new_right;
        }

        // Recombine
        result = (left << half_bits) | right;

        // Cycle walking: if result is out of range, apply again
        if (result as usize) < n {
            return result as usize;
        }
        // Apply another round of Feistel for cycle walking
    }
}

/// Apply inverse Feistel permutation to a single index
fn feistel_unpermute(index: usize, n: usize, seed: &[u8; 32]) -> usize {
    if n <= 1 {
        return index;
    }

    // Find smallest power of 2 >= n
    let bits = (usize::BITS - (n - 1).leading_zeros()) as usize;
    let half_bits = (bits + 1) / 2;
    let mask = (1u64 << half_bits) - 1;

    let mut result = index as u64;

    // Cycle walking: keep applying inverse Feistel until we get a valid index
    loop {
        // Split into left and right halves
        let mut left = result >> half_bits;
        let mut right = result & mask;

        // Apply Feistel rounds in REVERSE order
        for round in (0..FEISTEL_ROUNDS).rev() {
            let f = feistel_round_function(left, round, seed) & mask;
            let new_left = right ^ f;
            right = left;
            left = new_left;
        }

        // Recombine
        result = (left << half_bits) | right;

        // Cycle walking: if result is out of range, apply again
        if (result as usize) < n {
            return result as usize;
        }
    }
}

/// Shuffle fragments using index-space Feistel permutation
///
/// For each fragment at index i, compute π(i) and move fragment to that position.
/// No permutation tables stored - the Feistel network computes positions on the fly.
/// The seed should be generated from system CSPRNG and stored for extraction.
fn shuffle_fragments(fragments: &mut [Vec<u8>], seed: &[u8; 32]) {
    if fragments.len() <= 1 {
        return;
    }

    let n = fragments.len();

    // Build the permutation by computing Feistel for each index
    let permutation: Vec<usize> = (0..n).map(|i| feistel_permute(i, n, seed)).collect();

    // Apply forward permutation
    apply_permutation_in_place(fragments, &permutation);
}

/// Unshuffle fragments using inverse Feistel permutation
/// The seed must be the same seed used during shuffle (stored in CompartmentInfo)
fn unshuffle_fragments(fragments: &mut [Vec<u8>], seed: &[u8; 32]) {
    if fragments.len() <= 1 {
        return;
    }

    let n = fragments.len();

    // Build the inverse permutation by computing inverse Feistel for each index
    let inverse: Vec<usize> = (0..n).map(|i| feistel_unpermute(i, n, seed)).collect();

    // Apply inverse permutation
    apply_permutation_in_place(fragments, &inverse);
}

fn apply_permutation_in_place(fragments: &mut [Vec<u8>], permutation: &[usize]) {
    let n = fragments.len();
    let mut visited = vec![false; n];

    for i in 0..n {
        if visited[i] || permutation[i] == i {
            visited[i] = true;
            continue;
        }

        let mut current = i;
        loop {
            let next = permutation[current];
            visited[current] = true;
            if next == i {
                break;
            }
            fragments.swap(current, next);
            current = next;
        }
    }
}

/// Serialize authenticated blocks to bytes for storage
pub fn serialize_blocks(blocks: &[AuthenticatedBlock], mac_bytes: usize) -> Vec<u8> {
    let block_size: usize = blocks
        .first()
        .map(|b| SEQUENCE_SIZE + b.data.len() + mac_bytes)
        .unwrap_or(0);

    let mut result = Vec::with_capacity(blocks.len() * block_size);
    for block in blocks {
        result.extend_from_slice(&block.sequence_bytes);
        result.extend_from_slice(&block.data);
        result.extend_from_slice(&block.mac);
    }
    result
}

/// Deserialize authenticated blocks from bytes
/// block_size is the data portion size (from header), not including sequence or MAC
pub fn deserialize_blocks(
    data: &[u8],
    block_size: usize,
    mac_bytes: usize,
) -> Result<Vec<AuthenticatedBlock>> {
    // block_size is the data portion, total includes sequence and MAC
    let data_size = block_size;
    let total_block_size = SEQUENCE_SIZE + data_size + mac_bytes;

    if data.len() % total_block_size != 0 {
        return Err(HypercubeError::InvalidFormat(format!(
            "Data size {} is not a multiple of block size {}",
            data.len(),
            total_block_size
        )));
    }

    let mut blocks = Vec::new();
    for chunk in data.chunks_exact(total_block_size) {
        let mut sequence_bytes = [0u8; SEQUENCE_SIZE];
        sequence_bytes.copy_from_slice(&chunk[..SEQUENCE_SIZE]);

        let block_data = chunk[SEQUENCE_SIZE..SEQUENCE_SIZE + data_size].to_vec();
        let mac = chunk[SEQUENCE_SIZE + data_size..].to_vec();

        blocks.push(AuthenticatedBlock {
            sequence_bytes,
            data: block_data,
            mac,
        });
    }

    Ok(blocks)
}

/// Generate random chaff data for sealing
pub fn generate_chaff(size: usize) -> Vec<u8> {
    let mut rng = OsRng;
    (0..size).map(|_| rng.gen()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::VhcHeader;

    #[test]
    fn test_create_extract_roundtrip() {
        let header = VhcHeader::new(1, 32, 32, 64, 256).unwrap();
        let secret = b"my secret key";
        let original_data = b"Hello, World! This is test data for the hypercube format.";

        // Create compartment - returns serialized blocks
        let result = create_compartment(original_data, secret, &header, None).unwrap();

        // Extract compartment by scanning all blocks
        let extracted = extract_compartment(&result.blocks, secret, &header).unwrap();

        assert_eq!(original_data.as_slice(), &extracted[..]);
    }

    #[test]
    fn test_create_extract_large_data() {
        let header = VhcHeader::new(1, 32, 32, 64, 256).unwrap();
        let secret = b"secret";
        let original_data: Vec<u8> = (0..50000).map(|i| (i % 256) as u8).collect();

        let result = create_compartment(&original_data, secret, &header, None).unwrap();

        let extracted = extract_compartment(&result.blocks, secret, &header).unwrap();

        assert_eq!(original_data, extracted);
    }

    #[test]
    fn test_wrong_secret_fails() {
        let header = VhcHeader::new(1, 32, 32, 64, 256).unwrap();
        let secret = b"correct secret";
        let wrong_secret = b"wrong secret";
        let data = b"sensitive data";

        let result = create_compartment(data, secret, &header, None).unwrap();

        // Wrong secret should fail to authenticate any blocks
        let extract_result = extract_compartment(&result.blocks, wrong_secret, &header);
        assert!(extract_result.is_err());
    }

    #[test]
    fn test_multiple_compartments_mixed() {
        // Test that blocks from multiple compartments can coexist
        // and each can be extracted with its own secret
        let header = VhcHeader::new(1, 32, 32, 64, 256).unwrap();

        let secret1 = b"secret1";
        let secret2 = b"secret2";
        let data1 = b"Data for compartment 1";
        let data2 = b"Data for compartment 2";

        let result1 = create_compartment(data1, secret1, &header, None).unwrap();
        let result2 = create_compartment(data2, secret2, &header, None).unwrap();

        // Mix all blocks together (simulating a VHC file)
        let mut all_blocks: Vec<Vec<u8>> = Vec::new();
        all_blocks.extend(result1.blocks.clone());
        all_blocks.extend(result2.blocks.clone());

        // Extract each compartment with its secret
        let extracted1 = extract_compartment(&all_blocks, secret1, &header).unwrap();
        let extracted2 = extract_compartment(&all_blocks, secret2, &header).unwrap();

        assert_eq!(data1.as_slice(), &extracted1[..]);
        assert_eq!(data2.as_slice(), &extracted2[..]);
    }

    #[test]
    fn test_generate_chaff() {
        let chaff = generate_chaff(1000);
        assert_eq!(chaff.len(), 1000);

        // Chaff should be random (not all zeros)
        assert!(chaff.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_create_compartment_pads_to_cube() {
        let header = VhcHeader::new(1, 32, 32, 32, 256).unwrap();
        let secret = b"pad";
        let data = b"hi";
        let target = header.blocks_per_compartment();
        let result = create_compartment(data, secret, &header, Some(target)).expect("compartment");
        assert_eq!(result.blocks.len(), target);
    }
}
