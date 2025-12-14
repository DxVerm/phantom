# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Email**: dxverm@pm.me

**Subject Line**: `[SECURITY] PHANTOM - Brief Description`

### What to Include

1. **Description**: Clear description of the vulnerability
2. **Impact**: What can an attacker accomplish?
3. **Steps to Reproduce**: Detailed steps to reproduce the issue
4. **Affected Components**: Which modules are affected?
5. **Suggested Fix**: If you have one (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Target**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 60 days

### What to Expect

1. We will acknowledge your report promptly
2. We will investigate and validate the issue
3. We will work on a fix and coordinate disclosure
4. We will credit you in the security advisory (unless you prefer anonymity)

### Scope

The following are in scope for security reports:

- **Cryptographic implementations** (FHE, Dilithium, Kyber, ZK proofs)
- **Consensus mechanism** vulnerabilities
- **Network protocol** issues
- **State management** bugs that could lead to fund loss
- **DeFi module** vulnerabilities (AMM, lending, staking)

### Out of Scope

- Vulnerabilities in dependencies (report to upstream)
- Issues already reported
- Theoretical attacks without practical exploitation

## Security Measures

### Cryptographic Security

- **Post-Quantum Signatures**: Dilithium (NIST FIPS 204)
- **Post-Quantum KEM**: Kyber (NIST FIPS 203)
- **FHE**: TFHE-based implementation
- **ZK Proofs**: Groth16 with arkworks

### Code Security

- Memory-safe Rust implementation
- No unsafe blocks in critical paths
- Comprehensive test coverage
- Static analysis with `cargo clippy`

### Planned Security Audits

Before mainnet launch, we plan to engage:
- Trail of Bits
- OpenZeppelin
- NCC Group

## Bug Bounty Program

A formal bug bounty program will be announced after the security audit is complete.

## Security Updates

Security updates will be announced via:
- GitHub Security Advisories
- Project README
- Direct communication with known users

---

**Thank you for helping keep PHANTOM secure!**
