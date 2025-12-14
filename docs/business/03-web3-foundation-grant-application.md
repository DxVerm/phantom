# Web3 Foundation Grant Application

## Project: PHANTOM Post-Quantum Cryptographic Library

---

## 1. Project Overview

### Project Name
PHANTOM-Crypto: Post-Quantum and FHE Primitives for Substrate/Polkadot

### Brief Description
A Rust library providing post-quantum signatures (Dilithium), Fully Homomorphic Encryption, and encrypted state management primitives, designed for integration with Substrate-based chains.

### Team Website
[To be created]

### Legal Structure
[To be determined - likely Delaware C-Corp or Swiss Foundation]

### Team Code Repositories
- https://github.com/DxVerm/phantom

---

## 2. Project Details

### Overview

PHANTOM-Crypto provides production-ready cryptographic primitives that address two critical challenges facing all blockchains:

1. **Privacy**: Current blockchains expose all transaction data publicly
2. **Quantum Resistance**: Existing signature schemes will be broken by quantum computers

### Technical Architecture

```
phantom-crypto/
├── fhe/                 # Fully Homomorphic Encryption
│   ├── tfhe_impl.rs     # TFHE scheme implementation
│   ├── encrypted_ops.rs # Homomorphic operations
│   └── params.rs        # Security parameters
│
├── pq/                  # Post-Quantum Cryptography
│   ├── dilithium.rs     # NIST-approved signatures
│   ├── keypair.rs       # Key generation
│   └── verify.rs        # Signature verification
│
├── state/               # Encrypted State Management
│   ├── esl_tree.rs      # Encrypted State Ledger
│   ├── merkle.rs        # Merkle proofs for encrypted data
│   └── nullifiers.rs    # Double-spend prevention
│
└── substrate/           # Substrate Integration (NEW)
    ├── pallet_pq_auth/  # Post-quantum authentication pallet
    ├── pallet_private/  # Private transaction pallet
    └── runtime_api/     # Runtime API extensions
```

### Technology Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Language | Rust | Memory safety, Substrate compatibility |
| FHE | TFHE-rs | Best performance for boolean circuits |
| PQ Signatures | pqcrypto | Audited NIST implementations |
| Proofs | arkworks | Substrate-compatible ZK |
| Hashing | Blake3 + Poseidon | Performance + ZK-friendliness |

### Substrate Integration Plan

The grant deliverables will include:

1. **pallet-pq-signatures**: Drop-in replacement for sr25519/ed25519 with Dilithium
2. **pallet-private-balances**: Encrypted balance storage using FHE
3. **pallet-nullifiers**: Double-spend prevention for private transactions
4. **Runtime API**: Extensions for privacy-preserving queries

### Current State

| Component | Status | Tests |
|-----------|--------|-------|
| FHE Library | Complete | 15 tests |
| PQ Signatures | Complete | 12 tests |
| ESL Tree | Complete | 10 tests |
| Light Client | Complete | 20 tests |
| **Substrate Pallets** | **Planned** | **Milestone 1-2** |

---

## 3. Ecosystem Fit

### Where does your project fit?

PHANTOM-Crypto fills a critical gap in the Polkadot ecosystem:

| Existing Solution | Limitation | PHANTOM Solution |
|-------------------|------------|------------------|
| sr25519 signatures | Quantum vulnerable | Dilithium (quantum-safe) |
| Public balances | No privacy | FHE-encrypted balances |
| Standard Merkle trees | Leak data | Encrypted state trees |

### Target Audience

1. **Parachain developers** wanting privacy features
2. **Enterprise users** requiring confidential transactions
3. **Future-focused chains** preparing for quantum computing

### Similar Projects

| Project | Difference from PHANTOM |
|---------|------------------------|
| Manta Network | Uses ZK only, no FHE |
| Phala Network | TEE-based (hardware trust) |
| None | Post-quantum + FHE combination |

**Unique Value**: PHANTOM is the only project combining post-quantum signatures with FHE for Substrate.

---

## 4. Team

### Team Members

**Lead Developer**: Daniel Jacob Vermillion

### Contact
- **Email**: dxverm@pm.me
- **GitHub**: [@dxverm](https://github.com/dxverm)

### Legal Entity
[To be formed if grant awarded]

---

## 5. Development Roadmap

### Overview

| | Milestone 1 | Milestone 2 | Milestone 3 |
|---|-------------|-------------|-------------|
| Duration | 4 weeks | 6 weeks | 4 weeks |
| FTE | 1 | 1 | 1 |
| Cost | $10,000 | $15,000 | $5,000 |

**Total Duration**: 14 weeks
**Total Cost**: $30,000

---

### Milestone 1: Core Library Substrate Adaptation

**Duration**: 4 weeks
**Cost**: $10,000

| Number | Deliverable | Specification |
|--------|-------------|---------------|
| 0a | License | Apache 2.0 |
| 0b | Documentation | Inline docs + tutorial |
| 0c | Testing | Unit tests with >80% coverage |
| 0d | Docker | Container for running tests |
| 1 | pq-crypto crate | Substrate-compatible Dilithium wrapper |
| 2 | fhe-primitives crate | TFHE operations for Substrate types |
| 3 | Benchmarks | Performance comparison with existing |

**Verification**:
- `cargo test` passes all tests
- Benchmarks show <2x overhead vs ed25519

---

### Milestone 2: Substrate Pallets

**Duration**: 6 weeks
**Cost**: $15,000

| Number | Deliverable | Specification |
|--------|-------------|---------------|
| 0a | License | Apache 2.0 |
| 0b | Documentation | Pallet documentation + integration guide |
| 0c | Testing | Integration tests with substrate-test-runtime |
| 0d | Docker | Full node container |
| 1 | pallet-pq-auth | Post-quantum authentication pallet |
| 2 | pallet-encrypted-balances | FHE-based balance storage |
| 3 | Runtime integration | Example runtime using both pallets |
| 4 | Article | Technical blog post explaining implementation |

**Verification**:
- Pallets compile with latest Substrate
- Example runtime produces blocks
- Integration tests pass

---

### Milestone 3: Documentation & Ecosystem

**Duration**: 4 weeks
**Cost**: $5,000

| Number | Deliverable | Specification |
|--------|-------------|---------------|
| 0a | License | Apache 2.0 |
| 0b | Documentation | Complete API reference |
| 0c | Testing | Final test coverage report |
| 1 | Migration Guide | How to add PQ to existing chains |
| 2 | Security Analysis | Threat model document |
| 3 | Video Tutorial | 30-min walkthrough |
| 4 | Crates.io | Published crates |

**Verification**:
- Documentation hosted on docs.rs
- Video published on YouTube
- Crates published and installable

---

## 6. Future Plans

### Short-term (3-6 months after grant)
- Seek additional funding for security audit
- Partner with 2-3 parachains for integration pilots
- Apply for Substrate Builders Program

### Long-term
- Contribute to Polkadot's post-quantum migration planning
- Explore W3F collaboration on privacy standards
- Build developer community around the libraries

### Funding
- This grant covers initial development
- Will seek ecosystem grants for audit
- May pursue VC funding for dedicated chain

---

## 7. Additional Information

### How did you hear about the Grants Program?
Web3 Foundation website and ecosystem research

### Previous Grants
None - this is our first application

### Other Funding
Currently bootstrapped

### What work has been done?
Core cryptographic primitives are complete (50,000+ lines of Rust). This grant specifically funds Substrate integration, which is new development.

### Are there other teams working on this?
No other team combines post-quantum + FHE for Substrate. Manta uses ZK only; Phala uses TEEs.

---

## Appendix: Technical Benchmarks

### Dilithium Performance (Current Implementation)

| Operation | Time | vs ed25519 |
|-----------|------|------------|
| Key Generation | 0.8ms | 4x slower |
| Sign | 1.2ms | 6x slower |
| Verify | 0.4ms | 2x slower |

*Acceptable for blockchain use cases where security > speed*

### FHE Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Encrypt u64 | 5ms | Per value |
| Add (encrypted) | 0.1ms | Homomorphic |
| Multiply (encrypted) | 50ms | Bootstrapping needed |
| Decrypt | 3ms | Per value |

*Suitable for balance updates, not high-frequency trading*
