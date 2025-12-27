# Codebreaker

Codebreaker is a standalone CLI for running cryptanalysis against Hypercube payloads (and arbitrary byte streams). It currently exposes two subcommands:

- `codebreaker analyze <file> [--compression zstd] [--cube 1]` – runs the Hypercube cube analyzer that used to live inside the Hypercube CLI.
- `codebreaker stats <vhc-or-raw-file> [--block N] [--raw]` – renders a full-page dashboard of statistical diagnostics: frequency (ngrams, index of coincidence, Kasiski, crib coincidence), entropy family (Shannon/min/Rényi/sliding), goodness-of-fit (χ², KS, Anderson–Darling, Kuiper, ASCII ratio), serial/auto-correlation (runs, serial, lagged/shifted cross-correlation), differential (bit-plane χ², XOR delta bias), spectral transforms, linear-differential metrics, linear complexity, multivariate/TVLA-style Welch t-tests, and specialized diagnostics (Hamming weight distribution, run-length stats). Without `--raw`, it treats the input as a `.vhc` container and selects a block (either random or via `--block`). With `--raw`, the entire file is analyzed directly.

All functionality is deterministic and script-friendly; pass `--help` for the detailed flag list. The binary depends on the `hypercube` library crate for file parsing and cube math, so both projects always compile from the same workspace. The dashboard decorates each metric with PASS/WARN/FAIL colors to highlight potential weaknesses at a glance.
