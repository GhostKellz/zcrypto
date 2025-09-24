# Features Overview

zcrypto v0.9.0 supports optional feature flags for modular compilation. Enable only the features you need to minimize binary size and compilation time.

## Available Features

| Feature | Flag | Description | Size Impact |
|---------|------|-------------|-------------|
| **TLS/QUIC** | `tls` | TLS 1.3, QUIC crypto, X.509 certificates | ~8MB |
| **Post-Quantum** | `post_quantum` | ML-DSA, ML-KEM, Kyber, Dilithium | ~5MB |
| **Hardware Acceleration** | `hardware_accel` | AES-NI, AVX2, SIMD optimizations | ~2MB |
| **Blockchain** | `blockchain` | Schnorr signatures, ZK rollups | ~3MB |
| **VPN** | `vpn` | WireGuard, IPsec, IKEv2 protocols | ~4MB |
| **WebAssembly** | `wasm` | WASM crypto operations | ~1MB |
| **Enterprise** | `enterprise` | HSM integration, key rotation | ~3MB |
| **Zero-Knowledge Proofs** | `zkp` | Bulletproofs, Groth16, SNARKs | ~6MB |
| **Async Operations** | `async` | Async crypto with zsync integration | ~2MB |

## Feature Dependencies

Some features depend on others:

- **async** → requires zsync dependency
- **tls** → can use hardware_accel for performance
- **blockchain** → can use zkp for advanced features
- **enterprise** → can use hardware_accel and hsm
- **zkp** → can use hardware_accel for performance

## Use Case Examples

### Embedded/IoT Device
```zig
// Minimal crypto for constrained devices
const zcrypto = b.lazyDependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
    // Only essential primitives
    .tls = false,
    .post_quantum = false,
    .hardware_accel = false,
    .blockchain = false,
    .vpn = false,
    .wasm = false,
    .enterprise = false,
    .zkp = false,
    .async = false,
});
// Result: ~3MB binary
```

### Web Application
```zig
// TLS and async for web services
const zcrypto = b.lazyDependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
    .tls = true,
    .async = true,
    // Other features disabled
});
// Result: ~12MB binary
```

### Blockchain Node
```zig
// Full blockchain and ZKP support
const zcrypto = b.lazyDependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
    .blockchain = true,
    .zkp = true,
    .hardware_accel = true,
    // Core features
});
// Result: ~18MB binary
```

### VPN Server
```zig
// VPN protocols with hardware acceleration
const zcrypto = b.lazyDependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
    .vpn = true,
    .hardware_accel = true,
    .tls = true,
    // Core features
});
// Result: ~17MB binary
```

## Feature-Specific Documentation

- **[TLS/QUIC](tls.md)** - Transport security protocols
- **[Post-Quantum](post-quantum.md)** - Quantum-resistant cryptography
- **[Hardware Acceleration](hardware.md)** - CPU-specific optimizations
- **[Blockchain](blockchain.md)** - Decentralized crypto primitives
- **[VPN](vpn.md)** - Virtual private network protocols
- **[WebAssembly](wasm.md)** - Browser-compatible crypto
- **[Enterprise](enterprise.md)** - Enterprise security features
- **[Zero-Knowledge Proofs](zkp.md)** - Privacy-preserving proofs
- **[Async Operations](async.md)** - Asynchronous cryptography

## Build Configuration

See **[Build Configuration](../getting-started/build-config.md)** for detailed setup instructions.

## Performance Notes

- Hardware acceleration can improve performance by 2-10x
- Async operations add ~2MB but enable concurrent crypto
- Post-quantum algorithms are slower but future-proof
- ZKP operations are computationally intensive

## Compatibility

All features are backward compatible. Code written for core zcrypto will work with any feature combination.