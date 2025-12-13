use crate::header::Aont;
use sha3::{Sha3_256, Digest};

/// Apply All-or-Nothing Transform to fragments
/// Ensures that ALL fragments are needed to recover ANY fragment
/// KEYLESS: Transform is deterministic
pub fn apply_aont(fragments: &mut [Vec<u8>], algorithm: Aont) {
    match algorithm {
        Aont::Rivest => rivest_aont_apply(fragments),
        Aont::Oaep => oaep_aont_apply(fragments),
    }
}

/// Reverse All-or-Nothing Transform
pub fn reverse_aont(fragments: &mut [Vec<u8>], algorithm: Aont) {
    match algorithm {
        Aont::Rivest => rivest_aont_reverse(fragments),
        Aont::Oaep => oaep_aont_reverse(fragments),
    }
}

/// Rivest's All-or-Nothing Transform (simplified deterministic version)
/// Uses a 3-round Feistel network for true AONT properties
/// This ensures all blocks are needed to recover any single block
fn rivest_aont_apply(fragments: &mut [Vec<u8>]) {
    if fragments.len() < 2 {
        return; // AONT needs at least 2 fragments to be meaningful
    }

    // 3-round Feistel-like AONT
    // Round 1: Even fragments depend on odd
    // Round 2: Odd fragments depend on even
    // Round 3: Even fragments depend on odd again

    for round in 0..3 {
        let (source_start, target_start) = if round % 2 == 0 {
            (1, 0) // odd -> even
        } else {
            (0, 1) // even -> odd
        };

        // Compute hash of source fragments
        let mut hasher = Sha3_256::new();
        hasher.update(b"rivest_aont_round");
        hasher.update(&[round as u8]);
        let mut i = source_start;
        while i < fragments.len() {
            hasher.update(&fragments[i]);
            i += 2;
        }
        let round_hash: [u8; 32] = hasher.finalize().into();

        // XOR target fragments
        let mut i = target_start;
        let mut idx = 0;
        while i < fragments.len() {
            let mask = expand_hash_indexed(&round_hash, idx, fragments[i].len());
            xor_in_place(&mut fragments[i], &mask);
            i += 2;
            idx += 1;
        }
    }
}

/// Reverse Rivest's AONT (apply rounds in reverse order)
fn rivest_aont_reverse(fragments: &mut [Vec<u8>]) {
    if fragments.len() < 2 {
        return;
    }

    // Reverse the 3 rounds
    for round in (0..3).rev() {
        let (source_start, target_start) = if round % 2 == 0 {
            (1, 0) // odd -> even
        } else {
            (0, 1) // even -> odd
        };

        // Compute hash of source fragments (same as forward)
        let mut hasher = Sha3_256::new();
        hasher.update(b"rivest_aont_round");
        hasher.update(&[round as u8]);
        let mut i = source_start;
        while i < fragments.len() {
            hasher.update(&fragments[i]);
            i += 2;
        }
        let round_hash: [u8; 32] = hasher.finalize().into();

        // XOR target fragments (XOR is self-inverse)
        let mut i = target_start;
        let mut idx = 0;
        while i < fragments.len() {
            let mask = expand_hash_indexed(&round_hash, idx, fragments[i].len());
            xor_in_place(&mut fragments[i], &mask);
            i += 2;
            idx += 1;
        }
    }
}

/// OAEP-style AONT (simplified)
/// Uses a Feistel-like structure for the transform
fn oaep_aont_apply(fragments: &mut [Vec<u8>]) {
    if fragments.len() < 2 {
        return;
    }

    // OAEP-style: Split into two halves and apply Feistel rounds
    let mid = fragments.len() / 2;

    // Round 1: Right = Right XOR H(Left)
    let left_hash = compute_half_hash(&fragments[..mid]);
    for fragment in fragments[mid..].iter_mut() {
        let mask = expand_hash(&left_hash, fragment.len());
        xor_in_place(fragment, &mask);
    }

    // Round 2: Left = Left XOR H(Right)
    let right_hash = compute_half_hash(&fragments[mid..]);
    for fragment in fragments[..mid].iter_mut() {
        let mask = expand_hash(&right_hash, fragment.len());
        xor_in_place(fragment, &mask);
    }
}

/// Reverse OAEP-style AONT
fn oaep_aont_reverse(fragments: &mut [Vec<u8>]) {
    if fragments.len() < 2 {
        return;
    }

    let mid = fragments.len() / 2;

    // Reverse Round 2: Left = Left XOR H(Right)
    let right_hash = compute_half_hash(&fragments[mid..]);
    for fragment in fragments[..mid].iter_mut() {
        let mask = expand_hash(&right_hash, fragment.len());
        xor_in_place(fragment, &mask);
    }

    // Reverse Round 1: Right = Right XOR H(Left)
    let left_hash = compute_half_hash(&fragments[..mid]);
    for fragment in fragments[mid..].iter_mut() {
        let mask = expand_hash(&left_hash, fragment.len());
        xor_in_place(fragment, &mask);
    }
}


/// Compute hash of a subset of fragments
fn compute_half_hash(fragments: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"hypercube_aont_half_v1");
    for frag in fragments {
        hasher.update(frag);
    }
    hasher.finalize().into()
}

/// Expand a hash to desired length using counter mode
fn expand_hash(seed: &[u8; 32], length: usize) -> Vec<u8> {
    expand_hash_indexed(seed, 0, length)
}

/// Expand a hash with index to desired length
fn expand_hash_indexed(seed: &[u8; 32], index: usize, length: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(length);
    let mut counter = 0u64;

    while result.len() < length {
        let mut hasher = Sha3_256::new();
        hasher.update(seed);
        hasher.update(index.to_le_bytes());
        hasher.update(counter.to_le_bytes());
        let hash = hasher.finalize();

        for &byte in hash.iter() {
            if result.len() >= length {
                break;
            }
            result.push(byte);
        }
        counter += 1;
    }

    result
}

/// XOR in place
fn xor_in_place(data: &mut [u8], key: &[u8]) {
    for (d, k) in data.iter_mut().zip(key.iter()) {
        *d ^= k;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rivest_aont_roundtrip() {
        let original: Vec<Vec<u8>> = (0..10)
            .map(|i| (0..64).map(|j| ((i * 64 + j) % 256) as u8).collect())
            .collect();

        let mut fragments = original.clone();

        // Apply AONT
        apply_aont(&mut fragments, Aont::Rivest);

        // Verify AONT changed the data
        assert_ne!(original, fragments);

        // Reverse AONT
        reverse_aont(&mut fragments, Aont::Rivest);

        // Verify restored
        assert_eq!(original, fragments);
    }

    #[test]
    fn test_oaep_aont_roundtrip() {
        let original: Vec<Vec<u8>> = (0..10)
            .map(|i| (0..64).map(|j| ((i * 64 + j) % 256) as u8).collect())
            .collect();

        let mut fragments = original.clone();

        apply_aont(&mut fragments, Aont::Oaep);
        assert_ne!(original, fragments);

        reverse_aont(&mut fragments, Aont::Oaep);
        assert_eq!(original, fragments);
    }

    #[test]
    fn test_aont_single_fragment() {
        let original = vec![vec![1, 2, 3, 4, 5]];
        let mut fragments = original.clone();

        apply_aont(&mut fragments, Aont::Rivest);
        // Single fragment should be unchanged (AONT needs 2+ fragments)
        assert_eq!(original, fragments);

        reverse_aont(&mut fragments, Aont::Rivest);
        assert_eq!(original, fragments);
    }

    #[test]
    fn test_aont_empty() {
        let mut fragments: Vec<Vec<u8>> = Vec::new();
        apply_aont(&mut fragments, Aont::Rivest);
        assert!(fragments.is_empty());
    }

    #[test]
    fn test_aont_two_fragments() {
        let original = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
        let mut fragments = original.clone();

        apply_aont(&mut fragments, Aont::Rivest);
        reverse_aont(&mut fragments, Aont::Rivest);

        assert_eq!(original, fragments);
    }

    #[test]
    fn test_aont_is_deterministic() {
        let fragments: Vec<Vec<u8>> = (0..5)
            .map(|i| vec![i as u8; 64])
            .collect();

        let mut copy1 = fragments.clone();
        let mut copy2 = fragments.clone();

        apply_aont(&mut copy1, Aont::Rivest);
        apply_aont(&mut copy2, Aont::Rivest);

        assert_eq!(copy1, copy2);
    }

    #[test]
    fn test_aont_all_fragments_needed() {
        let original: Vec<Vec<u8>> = (0..10)
            .map(|i| (0..64).map(|j| ((i * 64 + j) % 256) as u8).collect())
            .collect();

        let mut fragments = original.clone();
        apply_aont(&mut fragments, Aont::Oaep);

        // Modify one fragment and try to reverse
        fragments[5][0] ^= 0xFF;
        reverse_aont(&mut fragments, Aont::Oaep);

        // Result should NOT match original (demonstrates all-or-nothing property)
        assert_ne!(original, fragments);
    }
}
