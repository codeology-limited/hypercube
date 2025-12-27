# Codeology Workspace

This repository now hosts two related binaries:

1. **Hypercube** – the Rivest Chaffing & Winnowing container CLI (`hypercube/`)
2. **Codebreaker** – a standalone cryptanalysis utility that provides the former `analyze` and `stats` commands plus room for future diagnostics (`codebreaker/`)

## Building

```bash
# Build both binaries
make build

# Install debug builds of hypercube + codebreaker to /usr/local/bin
make install-debug

# Install optimized release builds
make release
```

Individual crates can be built via `make hypercube` or `make codebreaker`.

## Running

- Hypercube CLI: `hypercube add`, `hypercube extract`, `hypercube info`, `hypercube seal`
- Codebreaker CLI: `codebreaker analyze <file>`, `codebreaker stats <vhc-or-raw-file> [--raw] [--block N]`

See the crate-specific READMEs under `hypercube/README.md` and `codebreaker/README.md` for detailed usage.
