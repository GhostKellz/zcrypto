# Alpha Integration Status & Roadmap

This document tracks the maturity status of all Zig libraries used in Wraith and provides a roadmap for stabilizing alpha/experimental projects to production-ready (RC/1.0) quality.

**Target**: Get all dependencies to **Release Candidate (RC)** or **1.0** status before Wraith reaches production.

---
### zcrypto - Cryptography Library
- **Status**: ⚠️ Modular, needs verification
- **Repository**: https://github.com/ghostkellz/zcrypto
- **Wraith Use**: TLS 1.3, certificate handling, crypto primitives

#### What Wraith Needs:
1. **TLS 1.3 Server** - Accept TLS connections
2. **TLS 1.3 Client** - Connect to HTTPS upstreams
3. **Certificate Loading** - PEM/DER format support
4. **SNI Support** - Multiple certificates per server
5. **OCSP Stapling** - Certificate status checking
6. **Cipher Suite Selection** - Configurable, secure defaults
7. **Key Exchange** - ECDHE, X25519
8. **Hash Functions** - SHA-256, SHA-384, SHA-512
9. **Symmetric Crypto** - AES-GCM, ChaCha20-Poly1305
10. **Random Number Generation** - Cryptographically secure RNG

#### Stabilization Checklist:
- [ ] TLS 1.3 RFC compliance (RFC 8446)
- [ ] Security audit (crypto implementation, timing attacks)
- [ ] Interoperability testing (OpenSSL, BoringSSL, rustls)
- [ ] Performance benchmarking (handshakes, bulk encryption)
- [ ] Constant-time operations (prevent timing attacks)
- [ ] Side-channel resistance testing
- [ ] Certificate validation correctness
- [ ] OCSP stapling reliability
- [ ] Documentation and examples
- [ ] Modular architecture verification (only link what's needed)

#### Current Gaps (Estimated):
- TLS 1.3 implementation needs security audit
- Certificate handling may have edge cases
- Performance optimization may be needed
- Constant-time guarantees need verification

**Priority**: P0 (CRITICAL - TLS is mandatory for production)


