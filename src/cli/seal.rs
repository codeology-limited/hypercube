use crate::compartment::create_compartment;
use crate::error::{HypercubeError, Result};
use crate::vhc::{append_blocks_to_vhc, get_block_count, read_vhc_header};
use rand::rngs::OsRng;
use rand::RngCore;
use std::cmp;
use std::path::Path;
use std::time::Instant;

/// Fill the remaining cube capacity with random chaff blocks
/// Returns the number of blocks added
pub fn seal_file(path: &Path) -> Result<usize> {
    let header = read_vhc_header(path)?;
    let current_blocks = get_block_count(path)?;
    let capacity = header.theoretical_block_count();

    if capacity == 0 {
        return Ok(0);
    }
    if current_blocks > capacity {
        return Err(HypercubeError::FileFull(capacity));
    }
    if current_blocks == capacity {
        return Ok(0);
    }

    let mut remaining = capacity - current_blocks;
    let total = remaining;
    let mut new_blocks: Vec<Vec<u8>> = Vec::with_capacity(remaining);
    let mut rng = OsRng;

    while remaining > 0 {
        let iter_start = Instant::now();
        let chunk_goal = remaining.min(header.blocks_per_compartment());
        let chunk_bytes = cmp::max(1, header.block_size) * cmp::max(1, chunk_goal);
        let mut random_data = vec![0u8; chunk_bytes];
        rng.fill_bytes(&mut random_data);

        let mut secret = vec![0u8; 32];
        rng.fill_bytes(&mut secret);

        let compartment = create_compartment(&random_data, &secret, &header, None)?;
        let produced = compartment.blocks.len();
        if produced == 0 {
            continue;
        }

        let take = remaining.min(produced);
        new_blocks.extend(compartment.blocks.into_iter().take(take));
        remaining -= take;
        let processed = total - remaining;
        let elapsed = iter_start.elapsed();
        let per_block = elapsed / (take as u32);
        println!(
            "Sealing: added {} blocks ({}/{}); avg {:?} per block",
            take, processed, total, per_block
        );
    }

    let added = new_blocks.len();
    append_blocks_to_vhc(path, &new_blocks)?;
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::add::{add_compartment, AddOptions};
    use crate::vhc::{get_block_count, read_vhc_header};
    use tempfile::tempdir;

    #[test]
    fn test_seal_file_fills_capacity() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let vhc = dir.path().join("cube.vhc");
        std::fs::write(&input, b"seed data").unwrap();

        let opts = AddOptions {
            secret: "secret".into(),
            cube: 1,
            ..Default::default()
        };
        add_compartment(&input, &vhc, &opts).unwrap();

        let added = seal_file(&vhc).unwrap();
        assert!(added > 0);
        let header = read_vhc_header(&vhc).unwrap();
        let final_blocks = get_block_count(&vhc).unwrap();
        assert_eq!(final_blocks, header.theoretical_block_count());

        // Re-sealing should be a no-op
        let second = seal_file(&vhc).unwrap();
        assert_eq!(second, 0);
    }
}
