use crate::header::Aont;
use rand::RngCore;
use sha3::{Digest, Sha3_256};

const KEY_SIZE: usize = 32;

/// Apply All-or-Nothing Transform to fragments
/// Rivest AONT adds one block's worth of key fragments; OAEP keeps same count
/// `frags_per_block` is needed for Rivest to maintain block alignment
pub fn apply_aont(fragments: Vec<Vec<u8>>, algorithm: Aont, frags_per_block: usize) -> Vec<Vec<u8>> {
    match algorithm {
        Aont::Rivest => rivest_aont_apply(fragments, frags_per_block),
        Aont::Oaep => oaep_aont_apply(fragments),
    }
}

/// Reverse All-or-Nothing Transform
/// Rivest AONT removes one block's worth of key fragments; OAEP keeps same count
pub fn reverse_aont(fragments: Vec<Vec<u8>>, algorithm: Aont, frags_per_block: usize) -> Vec<Vec<u8>> {
    match algorithm {
        Aont::Rivest => rivest_aont_reverse(fragments, frags_per_block),
        Aont::Oaep => oaep_aont_reverse(fragments),
    }
}

/// Rivest's original package transform (1997)
///
/// Forward:
///   m'[i] = m[i] XOR PRF(K, i)  for all i
///   Append key block as multiple fragments to maintain block alignment
///
/// We add enough key fragments to form one complete block after unfragment.
/// The key is stored in the first fragment; others are padding.
fn rivest_aont_apply(fragments: Vec<Vec<u8>>, frags_per_block: usize) -> Vec<Vec<u8>> {
    if fragments.is_empty() {
        return fragments;
    }

    let frag_size = fragments[0].len();
    let mut fragments = fragments;

    // Generate random 32-byte key
    let mut key = [0u8; KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut key);

    // Transform all fragments with PRF
    for (i, frag) in fragments.iter_mut().enumerate() {
        let mask = prf(&key, i, frag.len());
        xor_in_place(frag, &mask);
    }

    // Compute key block: K XOR H(0||m'[0]) XOR H(1||m'[1]) XOR ...
    let mut key_block = key;
    for (i, frag) in fragments.iter().enumerate() {
        let h = hash_indexed(i, frag);
        xor_in_place(&mut key_block, &h);
    }

    // Add frags_per_block fragments to form one complete key block
    // Spread the 32-byte key_block across the fragments
    let key_frags_needed = (KEY_SIZE + frag_size - 1) / frag_size;
    for i in 0..frags_per_block {
        let mut key_frag = vec![0u8; frag_size];
        if i < key_frags_needed {
            let start = i * frag_size;
            let end = (start + frag_size).min(KEY_SIZE);
            if start < KEY_SIZE {
                let copy_len = end - start;
                key_frag[..copy_len].copy_from_slice(&key_block[start..end]);
            }
        }
        fragments.push(key_frag);
    }

    fragments
}

/// Reverse Rivest's package transform
fn rivest_aont_reverse(fragments: Vec<Vec<u8>>, frags_per_block: usize) -> Vec<Vec<u8>> {
    if fragments.len() < frags_per_block + 1 {
        return fragments;
    }

    let mut fragments = fragments;
    let frag_size = fragments[0].len();

    // Pop the key block (frags_per_block fragments)
    let key_frags: Vec<_> = fragments.split_off(fragments.len() - frags_per_block);

    // Reconstruct key_block from key fragments
    let mut key_block = [0u8; KEY_SIZE];
    let key_frags_needed = (KEY_SIZE + frag_size - 1) / frag_size;
    for (i, frag) in key_frags.iter().enumerate().take(key_frags_needed) {
        let start = i * frag_size;
        let end = (start + frag_size).min(KEY_SIZE);
        if start < KEY_SIZE {
            let copy_len = end - start;
            key_block[start..end].copy_from_slice(&frag[..copy_len]);
        }
    }

    // Recover K: key_block XOR H(0||m'[0]) XOR H(1||m'[1]) XOR ...
    for (i, frag) in fragments.iter().enumerate() {
        let h = hash_indexed(i, frag);
        xor_in_place(&mut key_block, &h);
    }

    // Undo PRF on all fragments
    for (i, frag) in fragments.iter_mut().enumerate() {
        let mask = prf(&key_block, i, frag.len());
        xor_in_place(frag, &mask);
    }

    fragments
}

/// PRF: SHA3(K || index) expanded to desired length
fn prf(key: &[u8; KEY_SIZE], index: usize, length: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(length);
    let mut ctr = 0u64;
    while result.len() < length {
        let mut hasher = Sha3_256::new();
        hasher.update(b"hypercube_rivest_prf");
        hasher.update(key);
        hasher.update(index.to_le_bytes());
        hasher.update(ctr.to_le_bytes());
        for b in hasher.finalize() {
            if result.len() >= length {
                break;
            }
            result.push(b);
        }
        ctr += 1;
    }
    result
}

/// Hash with index prefix: SHA3(index || data)
fn hash_indexed(index: usize, data: &[u8]) -> [u8; KEY_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(index.to_le_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

/// OAEP-style AONT (2-round Feistel, deterministic, no size change)
fn oaep_aont_apply(mut fragments: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    if fragments.len() < 2 {
        return fragments;
    }

    let mid = fragments.len() / 2;

    let left_hash = compute_half_hash(&fragments[..mid]);
    for frag in fragments[mid..].iter_mut() {
        let mask = expand_hash(&left_hash, frag.len());
        xor_in_place(frag, &mask);
    }

    let right_hash = compute_half_hash(&fragments[mid..]);
    for frag in fragments[..mid].iter_mut() {
        let mask = expand_hash(&right_hash, frag.len());
        xor_in_place(frag, &mask);
    }

    fragments
}

fn oaep_aont_reverse(mut fragments: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    if fragments.len() < 2 {
        return fragments;
    }

    let mid = fragments.len() / 2;

    let right_hash = compute_half_hash(&fragments[mid..]);
    for frag in fragments[..mid].iter_mut() {
        let mask = expand_hash(&right_hash, frag.len());
        xor_in_place(frag, &mask);
    }

    let left_hash = compute_half_hash(&fragments[..mid]);
    for frag in fragments[mid..].iter_mut() {
        let mask = expand_hash(&left_hash, frag.len());
        xor_in_place(frag, &mask);
    }

    fragments
}

fn compute_half_hash(fragments: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"hypercube_aont_half");
    for frag in fragments {
        hasher.update(frag);
    }
    hasher.finalize().into()
}

fn expand_hash(seed: &[u8; 32], length: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(length);
    let mut ctr = 0u64;
    while result.len() < length {
        let mut hasher = Sha3_256::new();
        hasher.update(seed);
        hasher.update(ctr.to_le_bytes());
        for b in hasher.finalize() {
            if result.len() >= length {
                break;
            }
            result.push(b);
        }
        ctr += 1;
    }
    result
}

fn xor_in_place(data: &mut [u8], key: &[u8]) {
    for (d, k) in data.iter_mut().zip(key.iter()) {
        *d ^= k;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FRAGS_PER_BLOCK: usize = 4;

    #[test]
    fn test_rivest_aont_roundtrip() {
        let original: Vec<Vec<u8>> = (0..40) // 10 blocks * 4 frags
            .map(|i| vec![(i * 17) as u8; 32])
            .collect();

        let transformed = apply_aont(original.clone(), Aont::Rivest, TEST_FRAGS_PER_BLOCK);
        assert_eq!(transformed.len(), original.len() + TEST_FRAGS_PER_BLOCK); // one block added

        let recovered = reverse_aont(transformed, Aont::Rivest, TEST_FRAGS_PER_BLOCK);
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_rivest_aont_is_randomized() {
        let fragments: Vec<Vec<u8>> = (0..20).map(|i| vec![i as u8; 32]).collect();

        let t1 = apply_aont(fragments.clone(), Aont::Rivest, TEST_FRAGS_PER_BLOCK);
        let t2 = apply_aont(fragments.clone(), Aont::Rivest, TEST_FRAGS_PER_BLOCK);

        assert_ne!(t1, t2);
    }

    #[test]
    fn test_oaep_aont_roundtrip() {
        let original: Vec<Vec<u8>> = (0..10)
            .map(|i| vec![(i * 17) as u8; 32])
            .collect();

        let transformed = apply_aont(original.clone(), Aont::Oaep, TEST_FRAGS_PER_BLOCK);
        assert_eq!(transformed.len(), original.len());

        let recovered = reverse_aont(transformed, Aont::Oaep, TEST_FRAGS_PER_BLOCK);
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_aont_empty() {
        let empty: Vec<Vec<u8>> = vec![];
        let t = apply_aont(empty.clone(), Aont::Rivest, TEST_FRAGS_PER_BLOCK);
        assert!(t.is_empty());
    }

    #[test]
    fn test_aont_single_block() {
        // 4 fragments = 1 block
        let single_block: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 32]).collect();
        let t = apply_aont(single_block.clone(), Aont::Rivest, TEST_FRAGS_PER_BLOCK);
        assert_eq!(t.len(), 8); // original 4 + key block 4
        let r = reverse_aont(t, Aont::Rivest, TEST_FRAGS_PER_BLOCK);
        assert_eq!(r, single_block);
    }

    #[test]
    fn test_rivest_all_fragments_needed() {
        let original: Vec<Vec<u8>> = (0..40).map(|i| vec![i as u8; 32]).collect();
        let mut transformed = apply_aont(original.clone(), Aont::Rivest, TEST_FRAGS_PER_BLOCK);

        // Corrupt one fragment (not in key block)
        transformed[3][0] ^= 0xFF;

        let recovered = reverse_aont(transformed, Aont::Rivest, TEST_FRAGS_PER_BLOCK);
        assert_ne!(recovered, original);
    }
}
