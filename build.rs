use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    // Read and increment build number
    let build_file = Path::new("BUILD_NUMBER");
    let build_number: u64 = if build_file.exists() {
        fs::read_to_string(build_file)
            .unwrap_or_else(|_| "0".to_string())
            .trim()
            .parse()
            .unwrap_or(0)
    } else {
        0
    };

    let new_build = build_number + 1;
    fs::write(build_file, new_build.to_string()).expect("Failed to write build number");

    // Detect if this is a release build
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let is_release = profile == "release";

    // Read version from VERSION file
    let version_file = Path::new("VERSION");
    let version = if version_file.exists() {
        fs::read_to_string(version_file)
            .unwrap_or_else(|_| "0.1.0".to_string())
            .trim()
            .to_string()
    } else {
        "0.1.0".to_string()
    };

    // Get git commit hash if available
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Set environment variables for compilation
    println!("cargo:rustc-env=HYPERCUBE_VERSION={}", version);
    println!("cargo:rustc-env=HYPERCUBE_BUILD={}", new_build);
    println!("cargo:rustc-env=HYPERCUBE_PROFILE={}", if is_release { "release" } else { "development" });
    println!("cargo:rustc-env=HYPERCUBE_GIT_HASH={}", git_hash);

    // Rerun if these files change
    println!("cargo:rerun-if-changed=BUILD_NUMBER");
    println!("cargo:rerun-if-changed=VERSION");
    println!("cargo:rerun-if-env-changed=PROFILE");
}
