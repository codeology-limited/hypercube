//! Hypercube - Rivest Chaffing and Winnowing Cryptographic Container
//!
//! A file format that implements Rivest's Chaffing and Winnowing concept,
//! where multiple compartments can be stored in a single file, each with
//! its own secret key. Without the correct key, a compartment's data is
//! indistinguishable from chaff (random data).
//!
//! ## Transform Pipeline
//!
//! Each compartment's data goes through the following transforms:
//!
//! ```text
//! Input → Compress → Segment → Fragment → Shuffle → Whiten → AONT → Sequence → AuthMAC → Output
//! ```
//!
//! - **Compress**: zstd (default), lz4, brotli, or none
//! - **Segment**: Split into fixed-size blocks
//! - **Fragment**: Split blocks into smaller pieces
//! - **Shuffle**: Global Feistel shuffle of all fragments (random seed from CSPRNG)
//! - **Whiten**: Keccak whitening (UNKEYED, deterministic)
//! - **AONT**: All-or-Nothing Transform (KEYLESS)
//! - **Sequence**: Add 128-bit sequence numbers
//! - **AuthMAC**: HMAC authentication (KEYED - only step using secret)
//!
//! ## Example
//!
//! ```no_run
//! use hypercube::cli::{add_compartment, extract_from_vhc, AddOptions, ExtractOptions};
//! use std::path::Path;
//!
//! // Add a compartment
//! let add_opts = AddOptions {
//!     secret: "my_secret".into(),
//!     ..Default::default()
//! };
//! add_compartment(
//!     Path::new("input.txt"),
//!     Path::new("output.vhc"),
//!     &add_opts,
//! ).unwrap();
//!
//! // Extract a compartment
//! let extract_opts = ExtractOptions {
//!     secret: "my_secret".into(),
//! };
//! extract_from_vhc(
//!     Path::new("output.vhc"),
//!     Path::new("extracted.txt"),
//!     &extract_opts,
//! ).unwrap();
//! ```

pub mod cli;
pub mod compartment;
pub mod cube;
pub mod error;
pub mod header;
pub mod pipeline;
pub mod vhc;

pub use error::{HypercubeError, Result};
pub use header::VhcHeader;
pub use vhc::{read_vhc_file, write_vhc_file, VhcFile};
