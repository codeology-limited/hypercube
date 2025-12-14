use clap::{Parser, Subcommand};
use hypercube::cli::{
    add_compartment, analyze_file, extract_from_vhc, seal_file, show_info, show_stats, AddOptions,
    ExtractOptions,
};
use hypercube::header::{Aont, Compression, HashAlgorithm, Shuffle, Whitener};
use std::path::PathBuf;
use std::process::ExitCode;

/// Version info from build.rs
const VERSION: &str = env!("HYPERCUBE_VERSION");
const BUILD: &str = env!("HYPERCUBE_BUILD");
const PROFILE: &str = env!("HYPERCUBE_PROFILE");
const GIT_HASH: &str = env!("HYPERCUBE_GIT_HASH");

/// Combined version string (compile-time concatenation not possible, so we build at runtime)
fn get_version() -> &'static str {
    use std::sync::OnceLock;
    static VERSION_STRING: OnceLock<String> = OnceLock::new();
    VERSION_STRING.get_or_init(|| format!("{} {} build {} ({})", PROFILE, VERSION, BUILD, GIT_HASH))
}

#[derive(Parser)]
#[command(name = "hypercube")]
#[command(author, about = "Rivest Chaffing and Winnowing cryptographic container", long_about = None)]
struct Cli {
    /// Print version
    #[arg(short = 'V', long)]
    version: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a compartment to a VHC file
    #[command(alias = "a")]
    Add {
        /// Secret key for this compartment
        #[arg(long, required = true)]
        secret: String,

        /// Input file to add
        input: PathBuf,

        /// Output VHC file (creates if doesn't exist)
        output: PathBuf,

        /// Hash algorithm for MAC
        #[arg(long, default_value = "sha3", value_parser = parse_hash)]
        hash: HashAlgorithm,

        /// AONT algorithm
        #[arg(long, default_value = "rivest", value_parser = parse_aont)]
        aont: Aont,

        /// Shuffle algorithm
        #[arg(long, default_value = "feistel", value_parser = parse_shuffle)]
        shuffle: Shuffle,

        /// Whitener algorithm
        #[arg(long, default_value = "keccak", value_parser = parse_whitener)]
        whitener: Whitener,

        /// Compression algorithm
        #[arg(long, default_value = "zstd", value_parser = parse_compression)]
        compression: Compression,

        /// Cube preset (1 = 32 compartments × 32 blocks)
        #[arg(long, default_value = "1", value_parser = parse_cube)]
        cube: usize,

        /// MAC size in bits (128, 256, or 512)
        #[arg(long, default_value = "256")]
        mac_bits: usize,

        /// Target specific compartment index
        #[arg(long)]
        compartment: Option<usize>,

        /// Fill all remaining compartments with chaff
        #[arg(long)]
        seal: bool,
    },

    /// Extract a compartment from a VHC file
    #[command(alias = "x")]
    Extract {
        /// Secret key for the compartment
        #[arg(long, required = true)]
        secret: String,

        /// Input VHC file
        input: PathBuf,

        /// Output file
        output: PathBuf,
    },

    /// Show information about a VHC file
    #[command(alias = "i")]
    Info {
        /// VHC file to inspect
        file: PathBuf,
    },

    /// Cryptanalysis of a random block
    #[command(alias = "s")]
    Stats {
        /// VHC file to analyze
        file: PathBuf,
    },

    /// Fill remaining capacity with random chaff blocks
    Seal {
        /// VHC file to seal
        file: PathBuf,
    },

    /// Analyze a file and suggest a cube size
    Analyze {
        /// Compression algorithm to simulate
        #[arg(long, default_value = "zstd", value_parser = parse_compression)]
        compression: Compression,

        /// Cube preset to evaluate
        #[arg(long, default_value = "1", value_parser = parse_cube)]
        cube: usize,

        /// File to analyze
        file: PathBuf,
    },
}

fn parse_hash(s: &str) -> Result<HashAlgorithm, String> {
    s.parse().map_err(|e| format!("{}", e))
}

fn parse_aont(s: &str) -> Result<Aont, String> {
    s.parse().map_err(|e| format!("{}", e))
}

fn parse_shuffle(s: &str) -> Result<Shuffle, String> {
    s.parse().map_err(|e| format!("{}", e))
}

fn parse_whitener(s: &str) -> Result<Whitener, String> {
    s.parse().map_err(|e| format!("{}", e))
}

fn parse_compression(s: &str) -> Result<Compression, String> {
    s.parse().map_err(|e| format!("{}", e))
}

fn parse_cube(s: &str) -> Result<usize, String> {
    let value: usize = s.parse().map_err(|e| format!("{}", e))?;
    match value {
        1 => Ok(value),
        _ => Err(format!("Unsupported cube id: {}", value)),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Handle --version flag
    if cli.version {
        println!("hypercube {}", get_version());
        return ExitCode::SUCCESS;
    }

    // Require a command if not showing version
    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            // Show help when no command provided
            use clap::CommandFactory;
            Cli::command().print_help().unwrap();
            println!();
            return ExitCode::SUCCESS;
        }
    };

    let result = match command {
        Commands::Add {
            secret,
            input,
            output,
            hash,
            aont,
            shuffle,
            whitener,
            compression,
            cube,
            mac_bits,
            compartment,
            seal,
        } => {
            let options = AddOptions {
                secret,
                compression,
                shuffle,
                aont,
                hash,
                whitener,
                cube,
                mac_bits,
                compartment,
                seal,
            };

            match add_compartment(&input, &output, &options) {
                Ok(block_count) => {
                    println!("Added {} blocks to {}", block_count, output.display());
                    if seal {
                        println!("File sealed with chaff blocks");
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }

        Commands::Extract {
            secret,
            input,
            output,
        } => {
            let options = ExtractOptions { secret };

            match extract_from_vhc(&input, &output, &options) {
                Ok(_) => {
                    println!("Extracted to {}", output.display());
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }

        Commands::Info { file } => match show_info(&file) {
            Ok(info) => {
                print!("{}", info);
                Ok(())
            }
            Err(e) => Err(e),
        },

        Commands::Stats { file } => match show_stats(&file) {
            Ok(stats) => {
                print!("{}", stats);
                Ok(())
            }
            Err(e) => Err(e),
        },

        Commands::Seal { file } => match seal_file(&file) {
            Ok(0) => {
                println!("{} is already full", file.display());
                Ok(())
            }
            Ok(added) => {
                println!("Added {} random blocks to {}", added, file.display());
                Ok(())
            }
            Err(e) => Err(e),
        },

        Commands::Analyze {
            compression,
            cube,
            file,
        } => match analyze_file(&file, compression, cube) {
            Ok(report) => {
                print!("{}", report);
                Ok(())
            }
            Err(e) => Err(e),
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}
