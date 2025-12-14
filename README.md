# PHANTOM Protocol

**Quantum-Safe Privacy Blockchain with Fully Homomorphic Encryption**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-79%20passing-brightgreen.svg)]()
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)]()

---

## Overview

PHANTOM is the **first blockchain protocol** combining:

- **Fully Homomorphic Encryption (FHE)** - Compute on encrypted data without decryption
- **Post-Quantum Cryptography** - NIST-approved Dilithium/Kyber (immune to quantum attacks)
- **Zero-Knowledge Proofs** - Groth16 + Nova recursive proofs
- **Private DeFi Suite** - AMM, lending, and staking with encrypted balances

This is **50,000+ lines of production Rust code** with 79 passing tests.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PHANTOM Protocol                         │
├─────────────────────────────────────────────────────────────┤
│  DeFi Layer        │  Private AMM, Lending, Staking        │
├─────────────────────────────────────────────────────────────┤
│  State Layer       │  Encrypted State Ledger (ESL)         │
├─────────────────────────────────────────────────────────────┤
│  Consensus         │  Cryptographic Witness Attestation    │
├─────────────────────────────────────────────────────────────┤
│  Network           │  libp2p P2P + Sphinx Mixnet           │
├─────────────────────────────────────────────────────────────┤
│  Cryptography      │  FHE + Post-Quantum + ZK Proofs       │
└─────────────────────────────────────────────────────────────┘
```

---

## Technical Stack

| Component | Implementation |
|-----------|---------------|
| **FHE** | TFHE (BSD-3-Clause) |
| **Post-Quantum Signatures** | Dilithium (NIST FIPS 204) |
| **Post-Quantum KEM** | Kyber (NIST FIPS 203) |
| **Zero-Knowledge** | Groth16 + Nova (arkworks) |
| **Networking** | libp2p |
| **Hashing** | Blake3 + Poseidon |

---

## Project Structure

```
phantom/
├── src/
│   ├── crypto/          # Cryptographic primitives
│   │   ├── fhe/         # Fully Homomorphic Encryption
│   │   ├── pq/          # Post-quantum (Dilithium, Kyber)
│   │   ├── zk/          # Zero-knowledge proofs
│   │   ├── vrf/         # Verifiable Random Functions
│   │   └── hash/        # Blake3 + Poseidon
│   ├── state/           # State management
│   │   ├── esl/         # Encrypted State Ledger
│   │   ├── accounts/    # Account management
│   │   └── nullifiers/  # Double-spend prevention
│   ├── consensus/       # Consensus mechanism
│   │   ├── cwa/         # Cryptographic Witness Attestation
│   │   └── validator/   # Validator management
│   ├── network/         # Networking layer
│   │   ├── p2p/         # Peer-to-peer (libp2p)
│   │   ├── mempool/     # Transaction mempool
│   │   └── rpc/         # RPC interface
│   ├── defi/            # DeFi applications
│   │   ├── amm/         # Private AMM
│   │   ├── lending/     # Private lending
│   │   └── staking/     # Private staking
│   └── light-client/    # Light client (WASM)
├── tests/               # Integration tests
├── docs/                # Documentation
│   ├── whitepaper.md    # Technical whitepaper
│   ├── architecture.md  # Architecture docs
│   └── business/        # Business documents
└── LICENSE              # MIT/Apache-2.0
```

---

## Building

```bash
# Prerequisites
rustup default stable
rustup update

# Build
cargo build --release

# Run tests
cargo test

# Build with all features
cargo build --release --all-features
```

---

## Test Suite

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --test phase5_integration
cargo test --test property_tests

# Test output
# test result: ok. 57 passed; 0 failed
# test result: ok. 22 passed; 0 failed (property tests)
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Whitepaper](docs/whitepaper.md) | Technical specification (~800 lines) |
| [Architecture](docs/architecture.md) | System architecture |
| [API Reference](docs/api/) | API documentation |

---

## Key Features

### Privacy Guarantees
- **Transaction Privacy**: All amounts and recipients encrypted via FHE
- **Metadata Protection**: Sphinx mixnet for network-level privacy
- **Quantum Resistance**: NIST-approved post-quantum algorithms

### DeFi Capabilities
- **Private AMM**: Constant-product market maker with encrypted reserves
- **Private Lending**: Collateralized lending with hidden positions
- **Private Staking**: Stake without revealing balances

### Performance
- Light client with WASM support (runs in browsers)
- Proof delegation for mobile devices
- Checkpoint-based synchronization

---

## Status

**Production-ready, pre-testnet**

- Core cryptography: Complete
- State management: Complete
- Consensus: Complete
- Networking: Complete
- DeFi applications: Complete
- Light client: Complete
- Tests: 79 passing

---

## License

Dual-licensed under MIT OR Apache-2.0. See [LICENSE](LICENSE) for details.

---

## Author

**Daniel Jacob Vermillion**

- Email: dxverm@pm.me
- GitHub: [@dxverm](https://github.com/dxverm)

---

## For Sale

This project is available for acquisition. See [docs/sale/](docs/sale/) for:
- [Sale Listing](docs/sale/LISTING.md)
- [Sale Package](docs/sale/SALE-PACKAGE.md)
- [IP Declaration](docs/sale/IP-DECLARATION.md)
- [Transfer Agreement](docs/sale/TRANSFER-AGREEMENT.md)
