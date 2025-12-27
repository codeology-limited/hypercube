use std::error::Error;
use std::fs;
use std::process::{Command, Output};
use tempfile::tempdir;

fn hypercube_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hypercube"))
}

fn run(args: &[&str]) -> Result<Output, Box<dyn Error>> {
    Ok(hypercube_command().args(args).output()?)
}

#[test]
fn cli_end_to_end_flow() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let input = dir.path().join("secret.txt");
    let vault = dir.path().join("vault.vhc");
    let extracted = dir.path().join("recovered.txt");

    fs::write(&input, b"Super secret payload for Hypercube!")?;

    // Add partition
    let add = run(&[
        "add",
        "--secret",
        "passphrase",
        input.to_str().unwrap(),
        vault.to_str().unwrap(),
    ])?;
    assert!(
        add.status.success(),
        "add command failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    assert!(
        String::from_utf8(add.stdout.clone())?.contains("Added"),
        "add output missing confirmation"
    );

    assert!(vault.exists(), "vault file should exist after add");

    // Info should mention cube id (equals dimension) and blocks per partition
    let info = run(&["info", vault.to_str().unwrap()])?;
    let info_stdout = String::from_utf8(info.stdout)?;
    assert!(info_stdout.contains("Cube id: 32")); // Cube id equals dimension
    assert!(info_stdout.contains("Blocks per partition: 32"));

    // Extract partition
    let extract = run(&[
        "extract",
        "--secret",
        "passphrase",
        vault.to_str().unwrap(),
        extracted.to_str().unwrap(),
    ])?;
    assert!(
        extract.status.success(),
        "extract command failed: {}",
        String::from_utf8_lossy(&extract.stderr)
    );

    let recovered = fs::read(&extracted)?;
    let original = fs::read(&input)?;
    assert_eq!(recovered, original, "extracted data must match input");

    // Seal should fill the cube (32x32 = 1024 blocks)
    let seal = run(&["seal", vault.to_str().unwrap()])?;
    assert!(
        seal.status.success(),
        "seal command failed: {}",
        String::from_utf8_lossy(&seal.stderr)
    );

    let info_after_seal = run(&["info", vault.to_str().unwrap()])?;
    let info_sealed = String::from_utf8(info_after_seal.stdout)?;
    assert!(
        info_sealed.contains("Total blocks written: 1024"),
        "sealed vault should contain full cube of blocks"
    );

    Ok(())
}

#[test]
fn add_defaults_output_extension() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let input = dir.path().join("data.bin");
    fs::write(&input, b"payload data")?;

    let expected = {
        let mut os = input.as_os_str().to_os_string();
        os.push(".vhc");
        std::path::PathBuf::from(os)
    };

    let add = run(&["add", "--secret", "passphrase", input.to_str().unwrap()])?;
    assert!(
        add.status.success(),
        "add command failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    assert!(
        expected.exists(),
        "expected VHC file {} to be created automatically",
        expected.display()
    );

    Ok(())
}
