# Examples

Practical examples demonstrating zcrypto usage patterns.

## Core Examples

### [Basic Cryptography](basic.md)
- Hash functions (SHA-256, Blake2b)
- Symmetric encryption (AES-GCM, ChaCha20-Poly1305)
- Digital signatures (Ed25519)
- Key exchange (X25519, ECDH)

### [Key Derivation](key-derivation.md)
- HKDF for key expansion
- PBKDF2 for password hashing
- BIP39 mnemonic generation

### [Batch Operations](batch.md)
- Batch signature verification
- Bulk key generation

## Feature Examples

### [TLS/QUIC](tls-example.md)
- TLS 1.3 client/server
- QUIC crypto operations
- Certificate handling

### [Post-Quantum](pq-example.md)
- ML-KEM key encapsulation
- ML-DSA signatures
- Hybrid schemes

### [Hardware Acceleration](hw-example.md)
- SIMD operations
- AES-NI detection and usage
- Performance comparisons

### [Async Operations](async-example.md)
- Async encryption/decryption
- Concurrent crypto operations
- Integration with zsync

### [Blockchain](blockchain-example.md)
- Schnorr signatures
- BIP32 HD wallets
- ZK rollup proofs

### [VPN Protocols](vpn-example.md)
- WireGuard handshake
- IPsec key exchange
- IKEv2 implementation

## Advanced Examples

### [Enterprise Integration](enterprise-example.md)
- HSM key storage
- Key rotation policies
- Audit logging

### [Zero-Knowledge Proofs](zkp-example.md)
- Bulletproofs range proofs
- Groth16 verifiable computation
- SNARK construction

### [WebAssembly](wasm-example.md)
- Browser crypto operations
- WASM module compilation
- JavaScript interop

## Running Examples

```bash
# Build all examples
zig build examples

# Run specific example
zig build run-example -- example-name

# Build with custom features
zig build examples -Dtls=true -Dpost_quantum=true
```

## Example Structure

Each example includes:
- Complete working code
- Build configuration
- Usage instructions
- Performance notes
- Error handling patterns

## Contributing Examples

Add new examples to the `examples/` directory and update this documentation.