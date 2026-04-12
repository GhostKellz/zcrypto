# Quick Start

Get started with zcrypto v1.0.0 in minutes.

## 📦 Installation

### Zig Fetch (Recommended)

```bash
# Add to your project
zig fetch --save https://github.com/ghostkellz/zcrypto/archive/refs/tags/v1.0.0.tar.gz
```

### build.zig

```zig
// build.zig
const zcrypto = b.lazyDependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
    // Configure features as needed
    .tls = true,
    .@"hardware-accel" = true,
});

// In your executable/library
const exe = b.addExecutable(.{
    // ...
    .imports = &.{
        .{ .name = "zcrypto", .module = zcrypto.module("zcrypto") },
    },
});
```

## 🚀 Basic Usage

### Hashing

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const data = "Hello, zcrypto!";
    const hash = zcrypto.hash.sha256(data);
    std.debug.print("SHA-256: {x}\n", .{std.fmt.fmtSliceHexLower(&hash)});
}
```

### Symmetric Encryption

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const plaintext = "Secret message";
    const key = [_]u8{0x01} ** 32; // 256-bit key

    // Encrypt
    const ciphertext = try zcrypto.sym.encryptAesGcm(allocator, plaintext, &key);
    defer allocator.free(ciphertext);

    // Decrypt
    const decrypted = try zcrypto.sym.decryptAesGcm(allocator, ciphertext, &key);
    defer allocator.free(decrypted);

    std.debug.print("Decrypted: {s}\n", .{decrypted});
}
```

### Digital Signatures

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    // Generate keypair
    const keypair = zcrypto.asym.ed25519.generate();

    const message = "Sign this message";

    // Sign
    const signature = try zcrypto.asym.signEd25519(message, keypair.private_key);

    // Verify
    const valid = zcrypto.asym.verifyEd25519(message, signature, keypair.public_key);
    std.debug.print("Signature valid: {}\n", .{valid});
}
```

## ⚡ Hardware Acceleration

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    // Detect hardware capabilities
    const hw = zcrypto.hardware.HardwareAcceleration.detect();
    std.debug.print("AES-NI: {}\n", .{hw.aes_ni});
    std.debug.print("AVX2: {}\n", .{hw.avx2});

    // Use SIMD operations
    var a = [_]u8{1, 2, 3, 4};
    var b = [_]u8{5, 6, 7, 8};
    var result: [4]u8 = undefined;

    zcrypto.hardware.SIMD.vectorizedXor(&a, &b, &result);
    // result = {4, 4, 4, 12}
}
```

## 🔐 TLS/QUIC (when enabled)

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Derive QUIC initial secrets
    const connection_id = [_]u8{0x01, 0x02, 0x03, 0x04};
    const secrets = zcrypto.tls.deriveInitialSecrets(&connection_id, true);

    // Use in QUIC connection
    std.debug.print("Client initial secret: {x}\n", .{
        std.fmt.fmtSliceHexLower(&secrets.client_initial_secret)
    });
}
```

## 🌌 Post-Quantum Crypto (experimental, when enabled)

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const keypair = try zcrypto.kyber.generateKeypair();
    const encapsulation = try zcrypto.kyber.encapsulate(keypair.public_key);
    const shared_secret = try zcrypto.kyber.decapsulate(keypair.private_key, encapsulation.ciphertext);

    std.debug.print("Shared secret established: {x}\n", .{std.fmt.fmtSliceHexLower(&shared_secret)});
}
```

Build this example with `-Dpost-quantum=true -Dexperimental-crypto=true`.

## 🔄 Async Operations (when enabled)

```zig
const zcrypto = @import("zcrypto");
const zsync = @import("zsync");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Create async crypto instance
    var blocking_io = zsync.BlockingIo.init(allocator, 4096);
    defer blocking_io.deinit();

    const async_crypto = zcrypto.async_crypto.AsyncCrypto.init(
        blocking_io.io(),
        allocator
    );

    const data = "Async encryption test";
    const key = [_]u8{0xAB} ** 32;

    // Async encryption
    const encrypted = try async_crypto.encryptAsync(data, &key);
    defer allocator.free(encrypted);

    std.debug.print("Async encryption successful: {} bytes\n", .{encrypted.len});
}
```

## 🎯 Next Steps

- **[Build Configuration](build-config.md)** - Customize features for your use case
- **[API Reference](../api/core.md)** - Stable core API documentation
- **[Examples](../examples/basic.md)** - More detailed examples
- **[Integration](../integration.md)** - Real-world integration guides

## 📞 Need Help?

- **GitHub Issues**: [Report bugs](https://github.com/ghostkellz/zcrypto/issues)
- **Discussions**: [Ask questions](https://github.com/ghostkellz/zcrypto/discussions)
- **Examples**: Check the `examples/` directory for working code
