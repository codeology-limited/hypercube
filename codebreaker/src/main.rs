mod analyze;
mod stats;

use analyze::analyze_file;
use clap::{Parser, Subcommand};
use hypercube::header::Compression;
use stats::{run as run_stats, StatsOptions};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "codebreaker")]
#[command(about = "General-purpose cryptanalysis toolkit for Hypercube artifacts")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze how a payload fits into a Hypercube
    Analyze {
        /// Input file to analyze
        file: PathBuf,

        /// Compression algorithm to simulate
        #[arg(long, default_value = "zstd", value_parser = parse_compression)]
        compression: Compression,

        /// Hypercube dimension (N×N blocks, must be multiple of 8)
        #[arg(long, default_value_t = 32)]
        dimension: usize,
    },

    /// Run cryptanalysis on a VHC block or raw file
    Stats {
        /// File to analyze (VHC container by default)
        file: PathBuf,

        /// Specific block index (default: random block)
        #[arg(long)]
        block: Option<usize>,

        /// Treat input as raw bytes instead of a VHC container
        #[arg(long)]
        raw: bool,
    },
}

fn parse_compression(s: &str) -> Result<Compression, String> {
    s.parse().map_err(|e| format!("{}", e))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Analyze {
            file,
            compression,
            dimension,
        } => {
            let report = analyze_file(&file, compression, dimension)?;
            print!("{}", report);
        }
        Commands::Stats { file, block, raw } => {
            let options = StatsOptions { raw, block };
            let report = run_stats(&file, &options)?;
            print!("{}", report);
        }
    }

    Ok(())
}
