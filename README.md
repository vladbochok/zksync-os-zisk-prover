# ZKsync OS: ZiSK Prover

This repo contains the Prover Service implementation for ZKsync OS ZiSK (RV64IMA) prover — the second proof system alongside Airbender.

## Overview

The ZiSK prover generates STARK + SNARK proofs for ZKsync OS batches using the ZiSK zkVM. It runs as an external service that polls the sequencer for work, generates proofs via `cargo-zisk`, and submits them back for multi-proof composition with Airbender.

### Architecture

```
Sequencer (zksync-os-server)
    │
    ├── /ZiSK/pick  → ZiSK batch data (BatchInput, bincode)
    │
    └── /ZiSK/submit ← ZiSK SNARK proof (768 bytes) + public values (256 bytes)
                         │
                         ▼
              MultiProofSnarkProof (Airbender + ZiSK combined)
                         │
                         ▼
                    L1 verification
```

### Proof Pipeline

For each batch, the prover runs two `cargo-zisk` subprocesses sequentially:

1. **STARK aggregation** (`cargo-zisk prove`): Executes the ZiSK guest ELF, generates per-AIR FRI proofs, aggregates into a vadcop final proof. ~20 min on GPU.
2. **SNARK wrapping** (`cargo-zisk prove-snark`): Wraps the STARK proof into a Plonk SNARK suitable for on-chain verification. ~3 min on GPU.

Both stages use GPU acceleration when `cargo-zisk` is built with GPU support.

## Prerequisites

- **ZiSK toolchain**: `cargo-zisk` in PATH ([install](https://github.com/0xPolygonHermez/zisk))
- **ZiSK guest ELF**: Built from `zksync-os-zisk/guest/` via `cargo-zisk build --release`
- **STARK proving key**: `~/.zisk/provingKey/` (via `ziskup setup`)
- **SNARK proving key**: `~/.zisk/provingKeySnark/` (via `ziskup setup_snark`)
- **GPU**: NVIDIA with 16GB+ VRAM (CUDA required for GPU mode)

## Usage

Before starting, make sure your **sequencer** has ZiSK proving enabled:

```yaml
prover_input_generator:
  second_proof_system: true
```

### Start the prover service

```bash
cargo run --release -- \
  --sequencer-url http://localhost:3124 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path /path/to/zksync-os-zisk-guest \
  --proving-key ~/.zisk/provingKey \
  --proving-key-snark ~/.zisk/provingKeySnark
```

### With authentication

```bash
cargo run --release -- \
  --sequencer-url http://user:password@sequencer.example.com:3124 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path /path/to/zksync-os-zisk-guest \
  --proving-key ~/.zisk/provingKey \
  --proving-key-snark ~/.zisk/provingKeySnark
```

### With VK hash filtering

Only prove batches matching specific verification key hashes:

```bash
cargo run --release -- \
  --sequencer-url http://localhost:3124 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path /path/to/zksync-os-zisk-guest \
  --proving-key ~/.zisk/provingKey \
  --proving-key-snark ~/.zisk/provingKeySnark \
  --supported-vk 0x21a582e2fb44e0732b565ffe36331ffb77a315870076b1dc1556579bbc4a67b2
```

Or load from a file:

```bash
cargo run --release -- \
  ... \
  --vk-hashes-file supported_vk_hashes.txt
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--sequencer-url` | required | Sequencer URL. Supports `http://user:pass@host:port`. |
| `--zisk-binary` | required | Path to `cargo-zisk` binary. |
| `--elf-path` | required | Path to ZiSK guest ELF. |
| `--proving-key` | required | STARK proving key directory. |
| `--proving-key-snark` | required | SNARK proving key directory. |
| `--work-dir` | `/tmp/zisk_proofs` | Intermediate proof files (cleaned after each proof). |
| `--poll-interval-secs` | `5` | Seconds between polls when no work available. |
| `--iterations` | `0` | Exit after N proofs (0 = unlimited). |
| `--supported-vk` | (none) | Accepted VK hashes. Repeatable. Empty = accept all. |
| `--vk-hashes-file` | (none) | File with VK hashes (one per line, # comments). |
| `--metrics-address` | `0.0.0.0:3313` | Prometheus metrics endpoint. |

### Metrics

Prometheus metrics are served at `--metrics-address` (default `:3313`):

| Metric | Type | Description |
|--------|------|-------------|
| `zisk_prover_http_latency` | Histogram | HTTP pick/submit latency |
| `zisk_prover_proof_generation_time` | Histogram | Total proof time (STARK + SNARK) |
| `zisk_prover_stark_time` | Histogram | STARK aggregation time |
| `zisk_prover_snark_time` | Histogram | SNARK wrapping time |

## GPU Sharing with Airbender

Both Airbender and ZiSK provers use the GPU. For single-GPU setups, run them sequentially:

```bash
# Round: Airbender first (--iterations 1), then ZiSK (--iterations 1)
zksync-os-prover-service --iterations 1 ...  # exits after 1 SNARK, frees GPU
zksync-os-zisk-prover-service --iterations 1 ...  # exits after 1 proof, frees GPU
```

See `run_e2e_gpu.sh` in the parent repo for the orchestration script.

## License

ZKsync OS repositories are distributed under the terms of either

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/blog/license/mit/>)

at your option.
