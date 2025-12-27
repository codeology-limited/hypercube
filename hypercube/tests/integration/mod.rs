use std::error::Error;
use std::fs;
use std::process::{Command, Output};
use tempfile::tempdir;

fn hypercube_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hypercube"))
}

fn run(args: &[&str]) -> Output {
    hypercube_cmd()
        .args(args)
        .output()
        .expect("failed to run hypercube binary")
}

#[test]
fn version_flag_prints_build_information() {
    let output = run(&["--version"]);
    assert!(
        output.status.success(),
        "version command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("hypercube "),
        "unexpected version line: {}",
        stdout
    );
    assert!(
        stdout.contains("build"),
        "version output should include build value: {}",
        stdout
    );
}

#[test]
fn running_without_subcommand_displays_help() {
    let output = hypercube_cmd()
        .output()
        .expect("failed to run hypercube binary");
    assert!(
        output.status.success(),
        "help output failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage: hypercube"),
        "help output missing usage: {}",
        stdout
    );
    assert!(
        stdout.contains("Commands:"),
        "help output missing command list: {}",
        stdout
    );
}

#[test]
fn analyze_command_reports_cube_metrics() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let input = dir.path().join("payload.bin");
    fs::write(&input, b"Hypercube integration analysis payload")?;

    let output = run(&["analyze", "--cube", "1", input.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "analyze failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)?;
    assert!(
        stdout.contains("Hypercube Cube Analyzer"),
        "analyze output missing header: {}",
        stdout
    );
    assert!(
        stdout.contains("Cube 1"),
        "analyze output should mention cube 1: {}",
        stdout
    );
    assert!(
        stdout.contains("Headroom"),
        "analyze output missing capacity data: {}",
        stdout
    );

    Ok(())
}
