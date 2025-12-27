use hypercube::cli::{add_partition, AddOptions};
use std::error::Error;
use std::fs;
use std::process::{Command, Output};
use tempfile::tempdir;

fn codebreaker_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_codebreaker"))
}

fn run(args: &[&str]) -> Result<Output, Box<dyn Error>> {
    Ok(codebreaker_cmd().args(args).output()?)
}

#[test]
fn analyze_command_reports_cube() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let input = dir.path().join("data.bin");
    fs::write(&input, b"visual payload")?;

    let output = run(&["analyze", input.to_str().unwrap()])?;
    assert!(
        output.status.success(),
        "analyze failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Hypercube Cube Analyzer"));
    assert!(stdout.contains("Cube 32")); // default dimension is 32
    Ok(())
}

#[test]
fn stats_command_reads_vhc_files() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let input = dir.path().join("payload.txt");
    let vault = dir.path().join("vault.vhc");
    fs::write(&input, b"payload data for stats")?;

    let opts = AddOptions {
        secret: "codebreaker-secret".into(),
        ..Default::default()
    };
    add_partition(&input, &vault, &opts).expect("failed to create VHC");

    let output = run(&["stats", vault.to_str().unwrap()])?;
    assert!(
        output.status.success(),
        "stats failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Hypercube Block Cryptanalysis"));
    Ok(())
}
