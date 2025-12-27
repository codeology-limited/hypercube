use crate::error::{HypercubeError, Result};
use crate::header::HashAlgorithm;
use crate::pipeline::sequence::{SequencedBlock, SEQUENCE_SIZE};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sha3::Sha3_256;

type HmacSha3_256 = Hmac<Sha3_256>;
type HmacSha256 = Hmac<Sha256>;

/// A block with sequence, data, and MAC tag
#[derive(Debug, Clone)]
pub struct AuthenticatedBlock {
    pub sequence_bytes: [u8; SEQUENCE_SIZE],
    pub data: Vec<u8>,
    pub mac: Vec<u8>,
}

impl AuthenticatedBlock {
    /// Serialize to bytes: sequence || data || mac
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(SEQUENCE_SIZE + self.data.len() + self.mac.len());
        result.extend_from_slice(&self.sequence_bytes);
        result.extend_from_slice(&self.data);
        result.extend_from_slice(&self.mac);
        result
    }

    /// Deserialize from bytes given known mac_bytes size
    pub fn from_bytes(bytes: &[u8], mac_bytes: usize) -> Option<Self> {
        if bytes.len() < SEQUENCE_SIZE + mac_bytes {
            return None;
        }

        let data_len = bytes.len() - SEQUENCE_SIZE - mac_bytes;

        let mut sequence_bytes = [0u8; SEQUENCE_SIZE];
        sequence_bytes.copy_from_slice(&bytes[..SEQUENCE_SIZE]);

        let data = bytes[SEQUENCE_SIZE..SEQUENCE_SIZE + data_len].to_vec();
        let mac = bytes[SEQUENCE_SIZE + data_len..].to_vec();

        Some(Self {
            sequence_bytes,
            data,
            mac,
        })
    }
}

/// Compute MAC for a sequenced block using the specified algorithm
pub fn compute_mac(
    block: &SequencedBlock,
    secret: &[u8],
    algorithm: HashAlgorithm,
    mac_bits: usize,
) -> Vec<u8> {
    let message = block.to_bytes();
    compute_mac_raw(&message, secret, algorithm, mac_bits)
}

/// Compute MAC for raw bytes
fn compute_mac_raw(
    data: &[u8],
    secret: &[u8],
    algorithm: HashAlgorithm,
    mac_bits: usize,
) -> Vec<u8> {
    let mac_bytes = mac_bits / 8;

    match algorithm {
        HashAlgorithm::Sha3 => {
            let mut mac =
                HmacSha3_256::new_from_slice(secret).expect("HMAC can take key of any size");
            mac.update(data);
            let result = mac.finalize().into_bytes();
            truncate_mac(&result, mac_bytes)
        }
        HashAlgorithm::Blake3 => {
            let key = derive_blake3_key(secret);
            let hash = blake3::keyed_hash(&key, data);
            truncate_mac(hash.as_bytes(), mac_bytes)
        }
        HashAlgorithm::Sha256 => {
            let mut mac =
                HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
            mac.update(data);
            let result = mac.finalize().into_bytes();
            truncate_mac(&result, mac_bytes)
        }
    }
}

/// Derive a 32-byte key for BLAKE3 from arbitrary secret
fn derive_blake3_key(secret: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(secret);
    *hash.as_bytes()
}

/// Truncate MAC to desired length
fn truncate_mac(mac: &[u8], bytes: usize) -> Vec<u8> {
    if bytes >= mac.len() {
        // If requested size is larger, we need to expand
        // Use HMAC in counter mode to expand
        let mut result = mac.to_vec();
        while result.len() < bytes {
            let extension = blake3::hash(&result);
            result.extend_from_slice(extension.as_bytes());
        }
        result.truncate(bytes);
        result
    } else {
        mac[..bytes].to_vec()
    }
}

/// Verify MAC for a block
pub fn verify_mac(
    block: &AuthenticatedBlock,
    secret: &[u8],
    algorithm: HashAlgorithm,
    mac_bits: usize,
) -> bool {
    let mut message = Vec::with_capacity(SEQUENCE_SIZE + block.data.len());
    message.extend_from_slice(&block.sequence_bytes);
    message.extend_from_slice(&block.data);

    let expected_mac = compute_mac_raw(&message, secret, algorithm, mac_bits);
    constant_time_compare(&expected_mac, &block.mac)
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Authenticate sequenced blocks
pub fn authenticate_blocks(
    blocks: Vec<SequencedBlock>,
    secret: &[u8],
    algorithm: HashAlgorithm,
    mac_bits: usize,
) -> Vec<AuthenticatedBlock> {
    blocks
        .into_iter()
        .map(|block| {
            let mac = compute_mac(&block, secret, algorithm, mac_bits);
            AuthenticatedBlock {
                sequence_bytes: *block.sequence.as_bytes(),
                data: block.data,
                mac,
            }
        })
        .collect()
}

/// Verify and extract sequenced blocks
pub fn verify_and_extract_blocks(
    blocks: Vec<AuthenticatedBlock>,
    secret: &[u8],
    algorithm: HashAlgorithm,
    mac_bits: usize,
) -> Result<Vec<SequencedBlock>> {
    use crate::pipeline::sequence::SequenceNumber;

    let mut result = Vec::with_capacity(blocks.len());

    for (i, block) in blocks.into_iter().enumerate() {
        if !verify_mac(&block, secret, algorithm, mac_bits) {
            return Err(HypercubeError::MacVerificationFailed(i));
        }

        result.push(SequencedBlock {
            sequence: SequenceNumber::from_bytes(block.sequence_bytes),
            data: block.data,
        });
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::sequence::SequenceNumber;

    fn test_block() -> SequencedBlock {
        SequencedBlock::new(SequenceNumber::new(12345), vec![1, 2, 3, 4, 5, 6, 7, 8])
    }

    #[test]
    fn test_compute_mac_sha3() {
        let block = test_block();
        let secret = b"secret key";
        let mac = compute_mac(&block, secret, HashAlgorithm::Sha3, 256);
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_compute_mac_blake3() {
        let block = test_block();
        let secret = b"secret key";
        let mac = compute_mac(&block, secret, HashAlgorithm::Blake3, 256);
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_compute_mac_sha256() {
        let block = test_block();
        let secret = b"secret key";
        let mac = compute_mac(&block, secret, HashAlgorithm::Sha256, 256);
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_mac_different_sizes() {
        let block = test_block();
        let secret = b"secret key";

        let mac128 = compute_mac(&block, secret, HashAlgorithm::Sha3, 128);
        let mac256 = compute_mac(&block, secret, HashAlgorithm::Sha3, 256);
        let mac512 = compute_mac(&block, secret, HashAlgorithm::Sha3, 512);

        assert_eq!(mac128.len(), 16);
        assert_eq!(mac256.len(), 32);
        assert_eq!(mac512.len(), 64);
    }

    #[test]
    fn test_verify_mac_valid() {
        let block = test_block();
        let secret = b"secret key";
        let mac = compute_mac(&block, secret, HashAlgorithm::Sha3, 256);

        let auth_block = AuthenticatedBlock {
            sequence_bytes: *block.sequence.as_bytes(),
            data: block.data,
            mac,
        };

        assert!(verify_mac(&auth_block, secret, HashAlgorithm::Sha3, 256));
    }

    #[test]
    fn test_verify_mac_invalid_secret() {
        let block = test_block();
        let secret = b"secret key";
        let mac = compute_mac(&block, secret, HashAlgorithm::Sha3, 256);

        let auth_block = AuthenticatedBlock {
            sequence_bytes: *block.sequence.as_bytes(),
            data: block.data,
            mac,
        };

        assert!(!verify_mac(
            &auth_block,
            b"wrong key",
            HashAlgorithm::Sha3,
            256
        ));
    }

    #[test]
    fn test_verify_mac_tampered_data() {
        let block = test_block();
        let secret = b"secret key";
        let mac = compute_mac(&block, secret, HashAlgorithm::Sha3, 256);

        let mut auth_block = AuthenticatedBlock {
            sequence_bytes: *block.sequence.as_bytes(),
            data: block.data,
            mac,
        };

        // Tamper with data
        auth_block.data[0] ^= 0xFF;

        assert!(!verify_mac(&auth_block, secret, HashAlgorithm::Sha3, 256));
    }

    #[test]
    fn test_authenticate_verify_roundtrip() {
        let blocks: Vec<SequencedBlock> = (0..5)
            .map(|i| SequencedBlock::new(SequenceNumber::new(i as u128), vec![i as u8; 64]))
            .collect();

        let secret = b"my secret";
        let authenticated = authenticate_blocks(blocks.clone(), secret, HashAlgorithm::Sha3, 256);

        let extracted =
            verify_and_extract_blocks(authenticated, secret, HashAlgorithm::Sha3, 256).unwrap();

        assert_eq!(extracted.len(), blocks.len());
        for (orig, ext) in blocks.iter().zip(extracted.iter()) {
            assert_eq!(orig.sequence, ext.sequence);
            assert_eq!(orig.data, ext.data);
        }
    }

    #[test]
    fn test_authenticated_block_serialization() {
        let auth_block = AuthenticatedBlock {
            sequence_bytes: [1u8; SEQUENCE_SIZE],
            data: vec![2, 3, 4, 5],
            mac: vec![6, 7, 8, 9, 10, 11, 12, 13],
        };

        let bytes = auth_block.to_bytes();
        let restored = AuthenticatedBlock::from_bytes(&bytes, 8).unwrap();

        assert_eq!(auth_block.sequence_bytes, restored.sequence_bytes);
        assert_eq!(auth_block.data, restored.data);
        assert_eq!(auth_block.mac, restored.mac);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_compare(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_compare(&[1, 2, 3], &[1, 2]));
    }
}
