# Build Configuration

zcrypto v0.9.0 introduces a **modular build system** that allows you to include only the cryptographic features you need, significantly reducing binary size and compilation time.

## 🎯 Feature Flags

zcrypto uses build-time feature flags to enable/disable optional components:

```bash
# Enable only core crypto (minimal build)
zig build -Dtls=false -Dpost-quantum=false -Dhardware-accel=false

# Enable TLS + hardware acceleration (web server)
zig build -Dtls=true -Dhardware-accel=true -Dpost-quantum=false

# Enable everything (full-featured)
zig build  # All features enabled by default
```

## 📋 Available Feature Flags

| Flag | Default | Description | Impact |
|------|---------|-------------|---------|
| `tls` | `true` | TLS 1.3 and QUIC support | ~8KB |
| `post-quantum` | `true` | ML-KEM/ML-DSA algorithms | ~5KB |
| `hardware-accel` | `true` | SIMD/AES-NI optimizations | ~3KB |
| `blockchain` | `true` | BLS/Schnorr signatures | ~4KB |
| `vpn` | `true` | VPN-specific crypto | ~3KB |
| `wasm` | `true` | WebAssembly support | ~2KB |
| `enterprise` | `true` | HSM/Formal verification | ~6KB |
| `zkp` | `true` | Zero-knowledge proofs | ~7KB |
| `async` | `true` | zsync async operations | ~4KB |

## 📊 Build Size Comparison

| Configuration | Binary Size | Compile Time | Use Case |
|---------------|-------------|--------------|----------|
| **Full Featured** | ~35MB | ~45s | Enterprise applications |
| **TLS + Hardware** | ~15MB | ~25s | Web servers, APIs |
| **Core Only** | ~8MB | ~12s | Embedded, IoT |
| **Post-Quantum** | ~12MB | ~18s | Future-proof crypto |

## 🔧 Usage in build.zig

### Basic Integration

```zig
// build.zig
const zcrypto = b.lazyDependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
    // Enable only TLS and hardware acceleration
    .tls = true,
    .hardware_accel = true,
    // Disable everything else
    .post_quantum = false,
    .blockchain = false,
    .vpn = false,
    .wasm = false,
    .enterprise = false,
    .zkp = false,
    .async = false,
});

const exe = b.addExecutable(.{
    // ...
    .imports = &.{
        .{ .name = "zcrypto", .module = zcrypto.module("zcrypto") },
    },
});
```

### Embedded Systems

```zig
// Minimal configuration for embedded
const zcrypto = b.lazyDependency("zcrypto", .{
    .target = target,
    .optimize = .ReleaseSmall,
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
```

### WebAssembly

```zig
// WASM-optimized build
const zcrypto = b.lazyDependency("zcrypto", .{
    .target = .{ .cpu_arch = .wasm32, .os_tag = .freestanding },
    .optimize = .ReleaseSmall,
    .tls = false,
    .post_quantum = false,
    .hardware_accel = false,
    .enterprise = false,
    .zkp = false,
});
```

## 📦 Module Structure

When features are enabled, they become available as submodules:

```zig
const zcrypto = @import("zcrypto");

// Core (always available)
const hash = zcrypto.hash;
const sym = zcrypto.sym;

// Features (only when enabled)
const tls = zcrypto.tls;           // TLS 1.3 + QUIC
const post_quantum = zcrypto.post_quantum;  // ML-KEM + ML-DSA
const hardware = zcrypto.hardware; // SIMD operations
// ... etc
```

## ⚠️ Important Notes

- **Core crypto is always included** - hash, symmetric crypto, basic primitives
- **Features are additive** - enabling a feature doesn't disable others
- **Dependencies are automatic** - zsync is only required when `async=true`
- **Cross-platform** - Feature detection works on all supported platforms
- **Zero overhead** - Disabled features are completely excluded from compilation

## 🔍 Runtime Feature Detection

Some features support runtime detection:

```zig
// Hardware acceleration detection
const hw = zcrypto.hardware;
const features = hw.HardwareAcceleration.detect();
if (features.aes_ni) {
    // Use AES-NI optimized functions
}
```

## 🚀 Migration Guide

### From v0.8.x

```zig
// Old way (v0.8.x) - everything included
const zcrypto = @import("zcrypto");

// New way (v0.9.0) - selective features
const zcrypto = @import("zcrypto");
const tls = zcrypto.tls;  // Only available if -Dtls=true
```

### Conditional Feature Usage

```zig
// Safe feature usage with conditional compilation
const zcrypto = @import("zcrypto");

// Core features (always available)
const hash = zcrypto.hash.sha256(data);

// Optional features (check availability)
if (@import("builtin").is_test) {
    // In tests, all features are available
    const tls = zcrypto.tls;
} else {
    // In production, only enabled features are available
    // const tls = zcrypto.tls; // Compile error if -Dtls=false
}
```

## 🎯 Best Practices

1. **Start minimal** - Enable only what you need
2. **Profile regularly** - Measure binary size and performance
3. **Use feature flags** - Different builds for different deployment targets
4. **Test thoroughly** - Ensure all required features are enabled in CI/CD

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ghostkellz/zcrypto/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ghostkellz/zcrypto/discussions)