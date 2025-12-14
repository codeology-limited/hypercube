use crate::header::Whitener;
use sha3::{Digest, Keccak256};

/// Whiten fragments using the specified algorithm
/// UNKEYED: Whitening is deterministic based on fragment position
/// Applied AFTER shuffle, BEFORE AONT
pub fn whiten_fragments(fragments: &mut [Vec<u8>], algorithm: Whitener) {
    match algorithm {
        Whitener::Keccak => keccak_whiten(fragments),
        Whitener::Xor => xor_whiten(fragments),
    }
}

/// Unwhiten fragments (same operation as whiten for XOR-based methods)
pub fn unwhiten_fragments(fragments: &mut [Vec<u8>], algorithm: Whitener) {
    // Both Keccak and XOR whitening are their own inverses (XOR-based)
    whiten_fragments(fragments, algorithm);
}

/// Keccak whitening
/// Uses the Keccak sponge to generate a deterministic stream per fragment
/// XOR the stream with fragment data
fn keccak_whiten(fragments: &mut [Vec<u8>]) {
    for (i, fragment) in fragments.iter_mut().enumerate() {
        let whitening_stream = generate_keccak_stream(i, fragment.len());
        for (j, byte) in fragment.iter_mut().enumerate() {
            *byte ^= whitening_stream[j];
        }
    }
}

/// Generate a Keccak-based whitening stream for a fragment
/// Uses Keccak sponge in squeeze mode to generate arbitrary length output
fn generate_keccak_stream(index: usize, length: usize) -> Vec<u8> {
    let mut stream = Vec::with_capacity(length);
    let mut counter = 0u64;

    while stream.len() < length {
        // Absorb: index || counter || domain separator
        let mut hasher = Keccak256::new();
        hasher.update(b"hypercube_keccak_whiten_v1");
        hasher.update(index.to_le_bytes());
        hasher.update(counter.to_le_bytes());
        let hash = hasher.finalize();

        // Squeeze: take bytes from hash output
        for &byte in hash.iter() {
            if stream.len() >= length {
                break;
            }
            stream.push(byte);
        }
        counter += 1;
    }

    stream
}

/// XOR whitening (legacy)
/// Each fragment is XORed with a deterministic stream derived from position
fn xor_whiten(fragments: &mut [Vec<u8>]) {
    for (i, fragment) in fragments.iter_mut().enumerate() {
        let whitening_key = generate_xor_key(i, fragment.len());
        for (j, byte) in fragment.iter_mut().enumerate() {
            *byte ^= whitening_key[j];
        }
    }
}

/// Generate a deterministic XOR whitening key for a fragment at given index
fn generate_xor_key(index: usize, length: usize) -> Vec<u8> {
    use sha3::Sha3_256;

    let mut key = Vec::with_capacity(length);
    let mut counter = 0u64;

    while key.len() < length {
        // Hash: index || counter
        let mut hasher = Sha3_256::new();
        hasher.update(b"hypercube_whiten_v1");
        hasher.update(index.to_le_bytes());
        hasher.update(counter.to_le_bytes());
        let hash = hasher.finalize();

        for &byte in hash.iter() {
            if key.len() >= length {
                break;
            }
            key.push(byte);
        }
        counter += 1;
    }

    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_whiten_unwhiten_roundtrip() {
        let original: Vec<Vec<u8>> = (0..10)
            .map(|i| (0..64).map(|j| ((i * 64 + j) % 256) as u8).collect())
            .collect();

        let mut fragments = original.clone();

        // Whiten
        whiten_fragments(&mut fragments, Whitener::Keccak);

        // Verify whitening changed the data
        assert_ne!(original, fragments);

        // Unwhiten
        unwhiten_fragments(&mut fragments, Whitener::Keccak);

        // Verify restored
        assert_eq!(original, fragments);
    }

    #[test]
    fn test_xor_whiten_unwhiten_roundtrip() {
        let original: Vec<Vec<u8>> = (0..10)
            .map(|i| (0..64).map(|j| ((i * 64 + j) % 256) as u8).collect())
            .collect();

        let mut fragments = original.clone();

        // Whiten
        whiten_fragments(&mut fragments, Whitener::Xor);

        // Verify whitening changed the data
        assert_ne!(original, fragments);

        // Unwhiten (XOR is its own inverse)
        unwhiten_fragments(&mut fragments, Whitener::Xor);

        // Verify restored
        assert_eq!(original, fragments);
    }

    #[test]
    fn test_keccak_whitening_is_deterministic() {
        let fragments: Vec<Vec<u8>> = vec![vec![1, 2, 3, 4, 5, 6, 7, 8]; 5];

        let mut copy1 = fragments.clone();
        let mut copy2 = fragments.clone();

        whiten_fragments(&mut copy1, Whitener::Keccak);
        whiten_fragments(&mut copy2, Whitener::Keccak);

        assert_eq!(copy1, copy2);
    }

    #[test]
    fn test_whitening_varies_by_index() {
        // Two identical fragments at different indices should whiten differently
        let frag = vec![0u8; 64];
        let mut frag1 = vec![frag.clone()];
        let mut frag2 = vec![vec![0u8; 64], frag.clone()];

        whiten_fragments(&mut frag1, Whitener::Keccak);
        whiten_fragments(&mut frag2, Whitener::Keccak);

        // Fragment at index 0 vs fragment at index 1 should be different
        assert_ne!(frag1[0], frag2[1]);
    }

    #[test]
    fn test_keccak_stream_generation() {
        let stream1 = generate_keccak_stream(0, 64);
        let stream2 = generate_keccak_stream(1, 64);
        let stream3 = generate_keccak_stream(0, 64);

        assert_eq!(stream1.len(), 64);
        assert_eq!(stream2.len(), 64);
        assert_ne!(stream1, stream2); // Different indices produce different streams
        assert_eq!(stream1, stream3); // Same index produces same stream
    }

    #[test]
    fn test_whitening_empty() {
        let mut fragments: Vec<Vec<u8>> = Vec::new();
        whiten_fragments(&mut fragments, Whitener::Keccak);
        assert!(fragments.is_empty());
    }

    #[test]
    fn test_whitening_long_fragment() {
        let mut fragments = vec![vec![0u8; 1024]];
        whiten_fragments(&mut fragments, Whitener::Keccak);

        // Should not panic and should produce non-zero output
        assert!(fragments[0].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_keccak_differs_from_xor() {
        let original: Vec<Vec<u8>> = vec![vec![42u8; 64]; 5];

        let mut keccak_result = original.clone();
        let mut xor_result = original.clone();

        whiten_fragments(&mut keccak_result, Whitener::Keccak);
        whiten_fragments(&mut xor_result, Whitener::Xor);

        // Keccak and XOR should produce different outputs
        assert_ne!(keccak_result, xor_result);
    }
}
