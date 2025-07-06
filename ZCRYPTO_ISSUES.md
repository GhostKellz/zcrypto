# ZCrypto Issues for v0.5.0

This document tracks compilation issues found in the zcrypto v0.5.0 dependency that need to be addressed.

## Issues Found During ZQUIC v0.4.0 Development

### 1. Pointless Discard in Post-Quantum Module

**File:** `/src/pq.zig:79`
**Issue:** 
```zig
_ = rho;  // Line 79
```
**Problem:** Variable `rho` is discarded but then used later on line 88:
```zig
@memcpy(keypair.public_key[0..32], rho);  // Line 88
```

**Fix:** Remove the pointless discard since `rho` is actually used.

### 2. Mutable Variable Never Mutated in ML-KEM

**File:** `/src/pq/ml_kem.zig:410`
**Issue:**
```zig
var m_prime = v.sub(&s_dot_u);  // Line 410
```
**Problem:** Variable declared as `var` but never mutated after initialization.

**Fix:** Change to `const`:
```zig
const m_prime = v.sub(&s_dot_u);
```

## Impact on ZQUIC

These issues currently prevent clean compilation of ZQUIC v0.4.0 when using strict compiler settings. While they don't affect functionality, they do generate compilation errors that block the build process.

## Workaround

For now, ZQUIC v0.4.0 can be built by ignoring these zcrypto warnings/errors. The post-quantum functionality still works correctly despite these compilation issues.

## Recommendation

The zcrypto library maintainers should address these issues in the next patch release (v0.5.1) to ensure clean compilation across all dependent projects.

## Status

- **Reported:** 2025-07-06 during ZQUIC v0.4.0 development
- **Affected ZQUIC Version:** v0.4.0
- **ZCrypto Version:** v0.5.0
- **Severity:** Low (compilation warnings/errors, no functional impact)
- **Priority:** Medium (affects build cleanliness)

---

*This document will be updated as these issues are resolved in future zcrypto releases.*