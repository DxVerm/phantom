# PHANTOM Known Issues

## FHE Stack Overflow in DeFi Tests

**Component:** `phantom-defi`
**Severity:** Low (tests only, production code works)
**Status:** Open

### Description

The FHE (Fully Homomorphic Encryption) operations in `phantom-defi` require significant stack space. When running tests, the default stack size causes overflow:

```
thread '<unknown>' has overflowed its stack
fatal runtime error: stack overflow, aborting
```

### Affected Files

- `defi/src/amm.rs` - AMM tests with encrypted reserves
- `defi/src/swap.rs` - Swap execution tests with FHE

### Workarounds

**Option 1:** Increase stack size when running tests
```bash
RUST_MIN_STACK=8388608 cargo test -p phantom-defi
```

**Option 2:** Run workspace tests excluding defi
```bash
cargo test --workspace --exclude phantom-defi
```

**Option 3:** Add `#[ignore]` to heavy FHE tests and run separately
```rust
#[test]
#[ignore] // Requires RUST_MIN_STACK=8388608
fn test_encrypted_swap_execution() { ... }
```

### Root Cause

TFHE library operations perform deep recursion during FHE computations. The default thread stack size (~2MB) is insufficient for complex encrypted arithmetic chains.

### Recommended Fix

For CI/CD pipelines, set environment variable:
```yaml
env:
  RUST_MIN_STACK: 8388608
```

---

*Last Updated: 2024-12-14*
