# hypercube
Authenticated Rivest Chaffing & Winnowing container that hides many “compartments” inside one block soup.

## Concept
- Every compartment is a regular file that gets processed, chopped, and mixed with all the others. Nothing in the container tells you which blocks belong together.
- The only secret is the passphrase/key you use when adding a compartment. Extraction simply scans every block, runs an HMAC check with your secret, and keeps the blocks that verify.
- Because every block is authenticated before anything else, an attacker that does not know the secret sees only random-looking data (whitened + all-or-nothing transformed) and has zero way to tell when they have guessed right.

## Quick Start
1. **Build the CLI**
   ```bash
   cargo build --release
   # binary at target/release/hypercube
   ```
2. **Add a compartment**
   ```bash
   hypercube add --secret "correct horse battery staple" \
     secrets.txt vault.vhc
   ```
   Optional knobs: `--compression {zstd|lz4|brotli|none}`, `--shuffle`, `--aont`, `--hash {sha3|blake3|sha256}`, `--whitener`, `--cube {1}` (geometry preset; `1` = 32 compartments × 32 blocks), `--mac-bits`, and `--seal` (adds a handful of random chaff compartments immediately).
3. **Check block sizing (optional)**
   ```bash
   hypercube analyze secrets.txt     # shows block size/headroom for cube=1
   ```
4. **Extract**
   ```bash
   hypercube extract --secret "correct horse battery staple" \
     vault.vhc recovered.txt
   ```
5. **Inspect a container**
   ```bash
   hypercube info vault.vhc     # human readable header + storage stats
   hypercube stats vault.vhc    # randomness report for a random block
   ```
6. **Seal with chaff**
   ```bash
   hypercube seal vault.vhc     # fill remaining cube capacity with random blocks
   ```

## File Layout
- Header (plain JSON, after 4-byte `VHC\x01` magic) states the global transform choices: cube size, MAC bits, compression type, shuffle/AONT/whitener/hash algorithms, etc.
- `--cube` selects a preset geometry. Currently only `cube=1` exists, which maps to 32 compartments and 32 blocks per compartment.
- When you add the first compartment, hypercube compresses the payload, chooses a block payload size so that those 32 blocks exactly hold the data (after metadata), and records that block size in the header. The payload is padded (cryptographically inert) so the compartment truly fills all 32 blocks. Later compartments reuse the same block size and must still fit within 32 blocks; larger files are rejected rather than truncated.
- The cube is a hard ceiling: once the file stores `N * N` blocks, `hypercube add` refuses further writes until you delete/rebuild with a larger cube.
- Blocks live back-to-back after the header. Each block is `16B sequence || cube/8 bytes of transformed data || mac_bytes`. With the defaults above and a 256-bit MAC (`mac_bytes = 32`), every block consumes 50 bytes on disk before compression effects.
- There is **no index** of compartments. You can append arbitrarily many compartments; extraction always brute-force scans the block table.
- After every write, hypercube reloads the file, injects the new blocks, and shuffles the entire block table with a CSPRNG so physical block positions never correlate with compartment order.

### Cube Analyzer

Run `hypercube analyze file` to preview how a payload maps onto the cube preset:

```
Hypercube Cube Analyzer
=======================

File: secrets.txt
Original size: 12.4 KB
Compressed size (zstd): 4.9 KB
Payload after metadata: 5.0 KB

Cube 1: 32 compartments × 32 blocks
Block payload size: 26 bytes (208 bits)
Per-compartment capacity: 5.2 KB
Headroom if padded to cube: 208 B
```

Use `--compression` to match the algorithm you intend to store with (e.g., `hypercube analyze --compression brotli ...`). When the cube is created, the first compartment is padded to that block size so every block slot is filled.

## Transform Pipeline (per compartment)
```
Input → Compress → Metadata prepend → Segment → Fragment → Secret-driven Feistel shuffle
     → Keccak/XOR whitening → All-Or-Nothing Transform → Sequence numbering
     → HMAC/BLAKE3 authentication → Output blocks
```
- **Compress**  
  Shrinks data (default Zstd) to minimize block count and smooth patterns before shuffling. Lossless; metadata stores both original and compressed sizes.
- **Metadata prepend**  
  Stores `[compressed_size || original_size || shuffle_seed]` (48 bytes) in front of the compressed stream; required to know padding boundaries during extraction.
- **Segment + Fragment**  
  Breaks the stream into cube-sized blocks, then into fragments whose size is derived from the cube (tiny cubes fragment down to single bytes; large cubes work on bigger chunks up to 256B) so shuffle/AONT can mix both bit-level and chunk-level patterns.
- **Secret-driven shuffle**  
  Fragments are permuted by a Feistel network that uses a 32-byte seed deterministically derived from the compartment secret. Without the secret you cannot predict where a fragment landed, and the permutation never needs to be stored anywhere else.
- **Whitening**  
  Keccak-F (default) or XOR-based keystream that gets XORed with every fragment. This erases visual structure and makes every block look like high-entropy noise regardless of source content.
- **All-Or-Nothing Transform (AONT)**  
  Rivest/OAEP-style mixing that ensures that tampering with or losing a single fragment makes the entire data set useless. There is no partial disclosure even if some blocks leak.
- **Sequence numbering**  
  Each reconstructed block receives a random 128-bit base counter so reorder attacks are easy to detect.
- **Auth MAC**  
  HMAC-SHA3 (default), BLAKE3, or HMAC-SHA256 over `sequence||data`. This is the *only* keyed step. If the MAC fails the block is discarded; if it passes we know the block belonged to the secret holder and is intact.

Extraction simply inverts each step after MAC verification:
1. Collect all blocks with valid MACs for your secret.
2. Sort by sequence, stitch the block payloads, and defragment.
3. Reverse AONT, unwhiten, unshuffle (needs the stored seed, which only becomes readable after MAC verification), defragment, unsegment, drop metadata padding, and decompress.

## Security Model
- **Goal**: Provide deniable storage and compartmentalized access without classic encryption. You prove membership by knowing the secret that authenticates blocks; everyone else just sees chaff.
- **Trust root**: The per-block MAC. Everything else is deterministic or public. If the MAC is unforgeable the attacker cannot tell which blocks belong to whom nor modify data unnoticed.
- **No compartment directory**: Even if someone has the container, they cannot enumerate how many real compartments exist. Chaff compartments (`--seal`) further muddy the water.
- **Integrity-first**: Confidentiality is “probabilistic” (looks random) but not cryptographic secrecy—if the attacker ever learns your secret they get your data. Therefore treat the secret like an encryption key.
- **Header transparency**: Because the header is cleartext, algorithm agility is visible but harmless. An attacker does not learn which secrets are present because that information is never stored.
- **File-level randomization**: Every update reorders all stored blocks randomly, so even tracking disk offsets over time does not reveal which blocks were added or which compartment triggered the change.

## Attack Surface & Hardness
| MAC bits | Work factor (guesses) | Time @ 1e12 guesses/sec | Practical meaning |
|---------:|----------------------:|-------------------------:|-------------------|
| 128      | 3.4 × 10³⁸           | ~1.1 × 10¹⁹ years        | Bare minimum. Roughly a billion-billion times the age of the universe. |
| 256      | 1.2 × 10⁷⁷           | ~3.7 × 10⁵⁷ years        | Default. Impossible to brute force with any conceivable hardware. |
| 512      | 1.3 × 10¹⁵⁴          | absurd                   | Use only if you enjoy giant MACs; security already limited by your secret quality. |

**Primary attacks**
- *Brute-forcing the secret*: Resistance equals your secret’s entropy. A human-readable password is almost always weaker than the MAC size. Use at least 32 random bytes/base64 characters if you expect nation-state adversaries.
- *Forgery without the secret*: Requires guessing a correct MAC. Probability per block is `1 / 2^{mac_bits}`. Even with perfect hardware and infinite storage, the expected cracking time is shown above.
- *Pattern analysis*: Whitening + AONT removes visible structure. Compression ensures there are no obvious plaintext fragments. The `stats` subcommand is a convenience tool to show that stored blocks look random (high entropy, flat frequency, low correlation).
- *Traffic analysis*: Appending blocks leaks file growth, but nothing ties those blocks to a specific compartment. Sealing with chaff keeps the block count moving even when you add nothing important.

**Residual risks**
- Secrets reused elsewhere leak here too: The shuffle seed is derived from the secret, so compromising the secret compromises both authenticity and ordering.
- The container is not forward-secure: If someone copies the file today and you later re-use the same secret, they can authenticate the historical copy.
- Denial-of-service remains possible: Attackers can flood the file with garbage blocks, forcing you to scan more data, but they cannot forge valid blocks.

## Operational Guidance
1. **Key management** – Generate 256-bit (or longer) random secrets. Store them alongside the compartment name in a password manager or hardware token.
2. **Cube sizing** – Run `hypercube analyze file` beforehand to see the block payload/headroom for the cube preset you plan to use (currently only `--cube 1`). Future presets will follow the same flow: pick the cube, inspect the analyzer output, then add.
3. **MAC size** – Keep the default 256-bit MAC; 128-bit is only for low-stakes archives. 512-bit adds storage overhead with no real benefit unless audit/compliance demands it.
4. **Shuffle/AONT/Whitener choices** – Defaults offer the highest diffusion. Only change them when interoperability with another build matters.
5. **Sealing** – Run `hypercube seal vault.vhc` (or pass `--seal` on the final `add`) to pack the cube with random compartments so observers can’t tell how many real ones you stored.
6. **Backups** – The container is just a file. Back it up like any other encrypted volume; nothing special is required, but keep secrets off-box.
7. **Verification** – `cargo test` runs an extensive suite covering every pipeline stage, and `hypercube stats` helps spot corruption (a block with low entropy likely indicates tampering).

## Development Notes
- Build: `cargo build --release`
- Tests: `cargo test`
- Key files:
  - `src/compartment.rs` – full pipeline, Feistel shuffle, serialization.
  - `src/pipeline/*` – individual transform implementations.
  - `src/vhc.rs` – file format IO helpers.
  - `src/cli` – `add`, `extract`, `info`, `stats` subcommands.

Hypercube is intentionally simple in cryptographic dependency terms—modern hash functions (SHA3, BLAKE3, SHA256), standard compression libraries, and deterministic transforms. Treat it like any other security tool: keep secrets strong, keep binaries up to date, and monitor block counts for unexpected growth.

## Defaults & Order of Operations
- **Defaults**: compression=`zstd`, shuffle=`feistel`, whitener=`keccak`, AONT=`rivest`, MAC hash=`sha3`, cube=`1` (32 compartments × 32 blocks; block payload derived from the first compartment), mac_bits=`256`, fragment_size derived from the cube.
- **Order of operations (OOO)** is fixed for every compartment: `Compress → Metadata prepend → Segment → Fragment → Secret Feistel shuffle → Whiten → AONT → Sequence → Auth MAC`. Extraction always inverts this exact order.
- **Why document it**: the defaults provide the highest diffusion with moderate file growth, and the fixed OOO ensures everyone evaluating the format can reason about security claims without hidden branches.

### Example overrides
Switch to OAEP AONT, Fisher–Yates shuffling, XOR whitening, and BLAKE3 MAC while keeping other defaults:
```bash
hypercube add --secret "$(openssl rand -hex 32)" \
  --aont oaep --shuffle fisher-yates --whitener xor --hash blake3 \
  important.bin vault.vhc
```

Increase integrity overhead for a cold-storage archive: larger blocks, Brotli compression, SHA-256 MAC, and 512-bit tags:
```bash
hypercube add --secret "$(openssl rand -hex 32)" \
  --cube 1024 --compression brotli --hash sha256 --mac-bits 512 \
  archive.tar vault.vhc
```

Order of operations never changes even when altering algorithms—the pipeline still follows the same OOO chain listed above.
