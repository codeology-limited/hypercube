use hypercube::cli::{add_partition, extract_from_vhc, AddOptions, ExtractOptions};
use hypercube::cube::{analyze_data, CubeConfig};
use hypercube::header::{Aont, Compression, HashAlgorithm, Shuffle, VhcHeader, Whitener};
use hypercube::pipeline::{
    apply_aont, authenticate_blocks, calculate_fragment_size, compress, decompress, fragment_all,
    reverse_aont, segment, sequence_blocks, shuffle_fragments, unfragment_all, unsegment,
    unshuffle_fragments, unwhiten_fragments, verify_and_extract_blocks, whiten_fragments,
    AuthenticatedBlock,
};
use hypercube::pipeline::sequence::unsequence_blocks;
use hypercube::{read_vhc_file, write_vhc_file, HypercubeError, VhcFile};
use std::error::Error;
use std::fs;
use tempfile::tempdir;

#[test]
fn library_roundtrip_handles_multiple_partitions() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let vault = dir.path().join("vault.vhc");
    let first = dir.path().join("first.bin");
    let second = dir.path().join("second.bin");
    let recovered = dir.path().join("recovered.bin");

    fs::write(&first, b"First partition payload with enough bytes")?;
    fs::write(&second, b"Second partition payload that differs")?;

    let add_first = AddOptions {
        secret: "alpha-secret".into(),
        ..Default::default()
    };
    let add_second = AddOptions {
        secret: "beta-secret".into(),
        ..Default::default()
    };

    add_partition(&first, &vault, &add_first)?;
    add_partition(&second, &vault, &add_second)?;

    let extract_second = ExtractOptions {
        secret: "beta-secret".into(),
    };
    extract_from_vhc(&vault, &recovered, &extract_second)?;
    assert_eq!(fs::read(&recovered)?, fs::read(&second)?);

    let extract_first = ExtractOptions {
        secret: "alpha-secret".into(),
    };
    extract_from_vhc(&vault, &recovered, &extract_first)?;
    assert_eq!(fs::read(&recovered)?, fs::read(&first)?);

    let wrong = ExtractOptions {
        secret: "unknown".into(),
    };
    assert!(
        extract_from_vhc(&vault, &recovered, &wrong).is_err(),
        "wrong secret should not authenticate any blocks"
    );

    Ok(())
}

#[test]
fn cube_analysis_reports_consistent_headroom() -> Result<(), Box<dyn Error>> {
    let cfg = CubeConfig::hypercube(32);
    let payload = vec![0u8; 2048];
    let analysis = analyze_data(&payload, Compression::Zstd, cfg)?;

    assert!(
        analysis.block_size_bytes > 0,
        "block size should always be positive"
    );
    assert!(
        analysis.capacity_bytes >= analysis.payload_bytes,
        "capacity must be at least as large as payload"
    );
    assert_eq!(
        analysis.headroom_bytes(),
        analysis.capacity_bytes - analysis.payload_bytes,
        "headroom should equal capacity minus payload"
    );

    Ok(())
}

#[test]
fn vhc_read_write_roundtrip_via_public_api() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("vhc_file.vhc");
    let header = VhcHeader::new(32, 32, 32, 64, 256)?;
    let mut file = VhcFile::new(header.clone());

    let block = vec![0xAA; header.total_block_size()];
    file.add_blocks(vec![block.clone()]);

    write_vhc_file(&path, &file)?;
    let read_back = read_vhc_file(&path)?;

    assert_eq!(read_back.header.cube_id, header.cube_id);
    assert_eq!(read_back.blocks.len(), 1);
    assert_eq!(read_back.blocks[0], block);

    Ok(())
}

#[test]
fn pipeline_transforms_roundtrip_to_original_data() -> Result<(), Box<dyn Error>> {
    let fixture = PipelineFixture::new();

    let verified = verify_and_extract_blocks(
        fixture.authenticated.clone(),
        &fixture.secret,
        fixture.hash,
        fixture.mac_bits,
    )?;
    let ordered_blocks = unsequence_blocks(verified).expect("sequences should be contiguous");

    let (mut fragments, frags_per_block) =
        fragment_all(&ordered_blocks, fixture.fragment_size);
    reverse_aont(&mut fragments, fixture.aont);
    unwhiten_fragments(&mut fragments, fixture.whitener);
    unshuffle_fragments(&mut fragments, fixture.shuffle, &fixture.shuffle_seed);

    let rebuilt_blocks = unfragment_all(&fragments, frags_per_block);
    let payload = unsegment(&rebuilt_blocks, fixture.compressed_len);
    let decompressed = decompress(&payload, fixture.compression)?;

    assert_eq!(decompressed, fixture.original_data);

    Ok(())
}

#[test]
fn pipeline_mac_verification_rejects_tampering() {
    let fixture = PipelineFixture::new();
    let mut tampered = fixture.authenticated.clone();

    // Flip a bit inside the first block to invalidate the MAC
    tampered[0].data[0] ^= 0xAA;

    let err = verify_and_extract_blocks(
        tampered,
        &fixture.secret,
        fixture.hash,
        fixture.mac_bits,
    )
    .expect_err("tampered MAC must fail");

    match err {
        HypercubeError::MacVerificationFailed(index) => assert_eq!(index, 0),
        other => panic!("unexpected error type: {other:?}"),
    }
}

struct PipelineFixture {
    original_data: Vec<u8>,
    compression: Compression,
    fragment_size: usize,
    compressed_len: usize,
    shuffle: Shuffle,
    shuffle_seed: [u8; 32],
    secret: Vec<u8>,
    hash: HashAlgorithm,
    mac_bits: usize,
    whitener: Whitener,
    aont: Aont,
    authenticated: Vec<AuthenticatedBlock>,
}

impl PipelineFixture {
    fn new() -> Self {
        let original_data: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let compression = Compression::Zstd;
        let block_size = 128;
        let fragment_size = calculate_fragment_size(block_size);
        let shuffle = Shuffle::Feistel;
        let shuffle_seed = [0x11; 32];
        let whitener = Whitener::Keccak;
        let aont = Aont::Rivest;
        let hash = HashAlgorithm::Sha3;
        let mac_bits = 256;
        let secret = b"pipeline-fixture-secret".to_vec();

        let compressed = compress(&original_data, compression).expect("compress data");
        let compressed_len = compressed.len();
        let blocks = segment(&compressed, block_size);
        assert!(
            blocks.len() > 1,
            "fixture should generate multiple payload blocks for coverage"
        );
        let (mut fragments, frags_per_block) = fragment_all(&blocks, fragment_size);
        shuffle_fragments(&mut fragments, shuffle, &shuffle_seed);
        whiten_fragments(&mut fragments, whitener);
        apply_aont(&mut fragments, aont);
        let transformed_blocks = unfragment_all(&fragments, frags_per_block);

        let sequenced = sequence_blocks(transformed_blocks, 42);
        let authenticated =
            authenticate_blocks(sequenced, &secret, hash, mac_bits);

        Self {
            original_data,
            compression,
            fragment_size,
            compressed_len,
            shuffle,
            shuffle_seed,
            secret,
            hash,
            mac_bits,
            whitener,
            aont,
            authenticated,
        }
    }
}
