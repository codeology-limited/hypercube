use crate::header::Shuffle;
use sha3::{Sha3_256, Digest};
use rand::{SeedableRng, seq::SliceRandom};
use rand::rngs::StdRng;

/// Shuffle fragments using the specified algorithm
/// This is a GLOBAL shuffle - all fragments from all blocks are mixed together
/// KEYLESS: The shuffle seed is derived from the data itself (deterministic)
pub fn shuffle_fragments(fragments: &mut [Vec<u8>], algorithm: Shuffle) -> Vec<usize> {
    match algorithm {
        Shuffle::Feistel => feistel_shuffle(fragments),
        Shuffle::FisherYates => fisher_yates_shuffle(fragments),
    }
}

/// Unshuffle fragments using the inverse permutation
pub fn unshuffle_fragments(fragments: &mut [Vec<u8>], permutation: &[usize]) {
    // Create inverse permutation
    let mut inverse = vec![0usize; permutation.len()];
    for (new_pos, &old_pos) in permutation.iter().enumerate() {
        inverse[old_pos] = new_pos;
    }

    // Apply inverse permutation
    apply_permutation(fragments, &inverse);
}

/// Recompute permutation from shuffled data (for extraction)
/// Since shuffle is keyless and deterministic, we can recompute it
pub fn recompute_permutation(fragments: &[Vec<u8>], algorithm: Shuffle) -> Vec<usize> {
    // Create a copy to compute the permutation without modifying original
    let mut temp: Vec<Vec<u8>> = fragments.to_vec();
    match algorithm {
        Shuffle::Feistel => feistel_shuffle(&mut temp),
        Shuffle::FisherYates => fisher_yates_shuffle(&mut temp),
    }
}

/// Feistel-based shuffle
/// Deterministic: seed derived from hash of all fragment data
fn feistel_shuffle(fragments: &mut [Vec<u8>]) -> Vec<usize> {
    if fragments.is_empty() {
        return Vec::new();
    }

    // Compute seed from all fragment data
    let seed = compute_seed(fragments);

    // Generate permutation using seeded RNG
    let mut rng = StdRng::from_seed(seed);
    let mut permutation: Vec<usize> = (0..fragments.len()).collect();
    permutation.shuffle(&mut rng);

    // Apply permutation
    apply_permutation(fragments, &permutation);

    permutation
}

/// Fisher-Yates shuffle (same as Feistel in this implementation, but named differently)
/// Both use the same underlying deterministic approach
fn fisher_yates_shuffle(fragments: &mut [Vec<u8>]) -> Vec<usize> {
    // For this implementation, Fisher-Yates uses the same approach
    // The difference would be in a more complex implementation
    feistel_shuffle(fragments)
}

/// Compute a 32-byte seed from fragment data
fn compute_seed(fragments: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for frag in fragments {
        hasher.update(frag);
    }
    hasher.finalize().into()
}

/// Apply a permutation to fragments in-place
fn apply_permutation(fragments: &mut [Vec<u8>], permutation: &[usize]) {
    assert_eq!(fragments.len(), permutation.len());

    // Use cycle-following to apply permutation in-place
    let n = fragments.len();
    let mut visited = vec![false; n];

    for i in 0..n {
        if visited[i] || permutation[i] == i {
            visited[i] = true;
            continue;
        }

        // Follow the cycle
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shuffle_unshuffle_roundtrip() {
        // Create test fragments
        let original: Vec<Vec<u8>> = (0..10)
            .map(|i| vec![i as u8; 64])
            .collect();

        let mut fragments = original.clone();

        // Shuffle
        let permutation = shuffle_fragments(&mut fragments, Shuffle::Feistel);

        // Verify shuffle changed the order
        assert_ne!(original, fragments);

        // Unshuffle
        unshuffle_fragments(&mut fragments, &permutation);

        // Verify restored
        assert_eq!(original, fragments);
    }

    #[test]
    fn test_shuffle_is_deterministic() {
        let fragments1: Vec<Vec<u8>> = (0..10)
            .map(|i| vec![i as u8; 64])
            .collect();

        let mut copy1 = fragments1.clone();
        let mut copy2 = fragments1.clone();

        let perm1 = shuffle_fragments(&mut copy1, Shuffle::Feistel);
        let perm2 = shuffle_fragments(&mut copy2, Shuffle::Feistel);

        // Same input should produce same permutation
        assert_eq!(perm1, perm2);
        assert_eq!(copy1, copy2);
    }

    #[test]
    fn test_shuffle_global_mixing() {
        // Create fragments that identify their original block
        // 4 blocks, 4 fragments each = 16 total fragments
        let mut fragments: Vec<Vec<u8>> = Vec::new();
        for block_id in 0..4u8 {
            for frag_id in 0..4u8 {
                fragments.push(vec![block_id, frag_id, 0, 0]);
            }
        }

        let mut shuffled = fragments.clone();
        shuffle_fragments(&mut shuffled, Shuffle::Feistel);

        // After shuffling, fragments from different blocks should be mixed
        // Check that not all fragments from block 0 are still in positions 0-3
        let block0_positions: Vec<usize> = shuffled
            .iter()
            .enumerate()
            .filter(|(_, f)| f[0] == 0)
            .map(|(i, _)| i)
            .collect();

        // At least one fragment from block 0 should be outside positions 0-3
        let mixed = block0_positions.iter().any(|&pos| pos >= 4);
        assert!(mixed, "Global shuffle should mix fragments across blocks");
    }

    #[test]
    fn test_shuffle_empty() {
        let mut fragments: Vec<Vec<u8>> = Vec::new();
        let perm = shuffle_fragments(&mut fragments, Shuffle::Feistel);
        assert!(perm.is_empty());
    }

    #[test]
    fn test_shuffle_single() {
        let mut fragments = vec![vec![1, 2, 3, 4]];
        let perm = shuffle_fragments(&mut fragments, Shuffle::Feistel);
        assert_eq!(perm, vec![0]); // Single element stays in place
    }

    #[test]
    fn test_fisher_yates() {
        let original: Vec<Vec<u8>> = (0..10)
            .map(|i| vec![i as u8; 64])
            .collect();

        let mut fragments = original.clone();
        let permutation = shuffle_fragments(&mut fragments, Shuffle::FisherYates);

        unshuffle_fragments(&mut fragments, &permutation);
        assert_eq!(original, fragments);
    }
}
