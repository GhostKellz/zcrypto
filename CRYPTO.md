# ZCrypto: Zig Cryptography Infrastructure Guide

A comprehensive guide for using ZCrypto in Zig cryptography projects and infrastructure.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Modules](#core-modules)
- [Common Use Cases](#common-use-cases)
- [Advanced Usage](#advanced-usage)
- [Security Best Practices](#security-best-practices)
- [Performance Considerations](#performance-considerations)
- [Examples](#examples)

## Overview

ZCrypto is a modern cryptography library designed for Zig applications that need reliable, fast, and secure cryptographic operations. It provides a clean, modular API for:

- **Hashing**: SHA-256, SHA-512, BLAKE3, HMAC
- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Key Derivation**: HKDF, PBKDF2, Argon2
- **Random Generation**: Cryptographically secure random bytes
- **Utilities**: Constant-time operations, encoding/decoding
- **TLS/QUIC Support**: Specialized routines for modern protocols

## Installation

### Using Zig Package Manager

Add ZCrypto to your `build.zig.zon`:

```zig
.{
    .name = "your-project",
    .version = "0.1.0",
    .dependencies = .{
        .zcrypto = .{
            .url = "https://github.com/yourusername/zcrypto/archive/main.tar.gz",
            .hash = "1220...", // Add actual hash
        },
    },
}
```

In your `build.zig`:

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "your-app",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add ZCrypto dependency
    const zcrypto = b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("zcrypto", zcrypto.module("zcrypto"));

    b.installArtifact(exe);
}
```

### Local Development

Clone the repository and use it as a local dependency:

```bash
git clone https://github.com/yourusername/zcrypto.git
cd your-project
# Reference local zcrypto in build.zig
```

## Quick Start

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Hash some data
    const data = "Hello, ZCrypto!";
    const hash = zcrypto.hash.sha256(data);
    std.debug.print("SHA-256: {s}\n", .{std.fmt.fmtSliceHexLower(&hash)});

    // Generate random bytes
    var random_bytes: [32]u8 = undefined;
    try zcrypto.rand.fillBytes(&random_bytes);
    std.debug.print("Random: {s}\n", .{std.fmt.fmtSliceHexLower(&random_bytes)});

    // Encrypt data
    const key = try zcrypto.rand.generateKey(32);
    const plaintext = "Secret message";
    const ciphertext = try zcrypto.sym.encryptAesGcm(allocator, plaintext, &key);
    defer allocator.free(ciphertext);
    
    std.debug.print("Encrypted {} bytes\n", .{ciphertext.len});
}
```

## Core Modules

### Hash Module (`zcrypto.hash`)

Provides cryptographic hash functions and message authentication codes.

```zig
// Basic hashing
const sha256_hash = zcrypto.hash.sha256("data");
const sha512_hash = zcrypto.hash.sha512("data");
const blake3_hash = zcrypto.hash.blake3("data");

// HMAC
const key = "secret-key";
const message = "message to authenticate";
const hmac_result = zcrypto.hash.hmacSha256(message, key);
```

### Symmetric Encryption (`zcrypto.sym`)

Modern authenticated encryption with AES-GCM and ChaCha20-Poly1305.

```zig
const allocator = std.heap.page_allocator;

// AES-256-GCM
const key = try zcrypto.rand.generateKey(32);
const plaintext = "Confidential data";

const ciphertext = try zcrypto.sym.encryptAesGcm(allocator, plaintext, &key);
defer allocator.free(ciphertext);

const decrypted = try zcrypto.sym.decryptAesGcm(allocator, ciphertext, &key);
defer allocator.free(decrypted);

// ChaCha20-Poly1305
const chacha_ciphertext = try zcrypto.sym.encryptChaCha20Poly1305(allocator, plaintext, &key);
defer allocator.free(chacha_ciphertext);
```

### Key Derivation (`zcrypto.kdf`)

Secure key derivation for passwords and key stretching.

```zig
// HKDF for key expansion
const input_key = "initial-key-material";
const salt = "optional-salt";
const info = "application-context";
const derived_key = try zcrypto.kdf.hkdf(input_key, salt, info, 32);

// PBKDF2 for password hashing
const password = "user-password";
const pbkdf2_salt = try zcrypto.rand.generateSalt(16);
const password_hash = try zcrypto.kdf.pbkdf2(password, &pbkdf2_salt, 100000, 32);

// Argon2 (recommended for new applications)
const argon2_hash = try zcrypto.kdf.argon2id(password, &pbkdf2_salt, 32);
```

### Random Generation (`zcrypto.rand`)

Cryptographically secure random number generation.

```zig
// Generate random bytes
var buffer: [32]u8 = undefined;
try zcrypto.rand.fillBytes(&buffer);

// Generate keys
const aes_key = try zcrypto.rand.generateKey(32);  // 256-bit key
const hmac_key = try zcrypto.rand.generateKey(64); // 512-bit key

// Generate salts
const salt = try zcrypto.rand.generateSalt(16);

// Generate nonces/IVs
var nonce: [12]u8 = undefined;
try zcrypto.rand.fillBytes(&nonce);
```

### Utilities (`zcrypto.util`)

Security-focused utility functions.

```zig
// Constant-time comparison (prevents timing attacks)
const secret1 = "password123";
const secret2 = "password456";
const are_equal = zcrypto.util.constantTimeCompare(secret1, secret2);

// Secure memory clearing
var sensitive_data = "secret key data";
zcrypto.util.secureZero(sensitive_data);

// Base64 encoding/decoding
const allocator = std.heap.page_allocator;
const data = "Hello, World!";
const encoded = try zcrypto.util.base64Encode(allocator, data);
defer allocator.free(encoded);

const decoded = try zcrypto.util.base64Decode(allocator, encoded);
defer allocator.free(decoded);

// Hexadecimal encoding/decoding
const hex_encoded = try zcrypto.util.hexEncode(allocator, data);
defer allocator.free(hex_encoded);
```

## Common Use Cases

### 1. Secure Password Storage

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn hashPassword(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
    const salt = try zcrypto.rand.generateSalt(16);
    const hash = try zcrypto.kdf.argon2id(password, &salt, 32);
    
    // Store both salt and hash (in practice, use a proper format)
    const result = try allocator.alloc(u8, salt.len + hash.len);
    @memcpy(result[0..salt.len], &salt);
    @memcpy(result[salt.len..], &hash);
    
    return result;
}

pub fn verifyPassword(stored_hash: []const u8, password: []const u8) !bool {
    if (stored_hash.len < 16 + 32) return false;
    
    const salt = stored_hash[0..16];
    const hash = stored_hash[16..];
    
    const computed_hash = try zcrypto.kdf.argon2id(password, salt, 32);
    return zcrypto.util.constantTimeCompare(hash, &computed_hash);
}
```

### 2. File Encryption

```zig
pub fn encryptFile(allocator: std.mem.Allocator, file_path: []const u8, password: []const u8) !void {
    // Read file
    const file_data = try std.fs.cwd().readFileAlloc(allocator, file_path, 1024 * 1024 * 100); // 100MB max
    defer allocator.free(file_data);
    
    // Derive key from password
    const salt = try zcrypto.rand.generateSalt(16);
    const key = try zcrypto.kdf.pbkdf2(password, &salt, 100000, 32);
    
    // Encrypt
    const ciphertext = try zcrypto.sym.encryptAesGcm(allocator, file_data, &key);
    defer allocator.free(ciphertext);
    
    // Write encrypted file with salt prepended
    const output_file = try std.fs.cwd().createFile(file_path ++ ".enc", .{});
    defer output_file.close();
    
    try output_file.writeAll(&salt);
    try output_file.writeAll(ciphertext);
}
```

### 3. API Token Generation

```zig
pub fn generateApiToken(allocator: std.mem.Allocator) ![]u8 {
    var token_bytes: [32]u8 = undefined;
    try zcrypto.rand.fillBytes(&token_bytes);
    
    // Encode as URL-safe base64
    return zcrypto.util.base64Encode(allocator, &token_bytes);
}

pub fn generateSessionId() ![32]u8 {
    var session_id: [32]u8 = undefined;
    try zcrypto.rand.fillBytes(&session_id);
    return session_id;
}
```

### 4. Message Authentication

```zig
pub fn signMessage(message: []const u8, secret_key: []const u8) [32]u8 {
    return zcrypto.hash.hmacSha256(message, secret_key);
}

pub fn verifyMessage(message: []const u8, signature: []const u8, secret_key: []const u8) bool {
    const computed_signature = signMessage(message, secret_key);
    return zcrypto.util.constantTimeCompare(signature, &computed_signature);
}
```

## Advanced Usage

### Custom TLS/QUIC Integration

```zig
// QUIC initial secrets derivation
const connection_id = "example-connection-id";
const client_initial_secret = try zcrypto.tls.deriveQuicInitialSecret(connection_id, true);
const server_initial_secret = try zcrypto.tls.deriveQuicInitialSecret(connection_id, false);

// TLS key derivation
const master_secret = "derived-master-secret";
const client_write_key = try zcrypto.tls.deriveWriteKey(master_secret, "client", 32);
const server_write_key = try zcrypto.tls.deriveWriteKey(master_secret, "server", 32);
```

### Performance-Critical Operations

```zig
// For high-frequency operations, reuse allocators and buffers
pub const CryptoContext = struct {
    allocator: std.mem.Allocator,
    key_buffer: [32]u8,
    work_buffer: []u8,
    
    pub fn init(allocator: std.mem.Allocator) !CryptoContext {
        return CryptoContext{
            .allocator = allocator,
            .key_buffer = undefined,
            .work_buffer = try allocator.alloc(u8, 4096),
        };
    }
    
    pub fn deinit(self: *CryptoContext) void {
        self.allocator.free(self.work_buffer);
    }
    
    pub fn hashData(self: *CryptoContext, data: []const u8) [32]u8 {
        return zcrypto.hash.sha256(data);
    }
};
```

## Security Best Practices

### 1. Key Management
- **Never hardcode keys** in source code
- **Use secure key derivation** (HKDF, PBKDF2, Argon2)
- **Rotate keys regularly** in production systems
- **Clear sensitive data** from memory after use

```zig
// Good: Derive keys from secure sources
const key = try zcrypto.kdf.hkdf(master_key, salt, context, 32);
defer zcrypto.util.secureZero(&key);

// Bad: Hardcoded keys
// const key = "hardcoded-secret-key"; // DON'T DO THIS
```

### 2. Random Number Generation
- **Always use cryptographically secure** random generators
- **Never reuse nonces** with the same key
- **Use appropriate entropy** for your use case

```zig
// Good: Cryptographically secure random
var nonce: [12]u8 = undefined;
try zcrypto.rand.fillBytes(&nonce);

// Bad: Predictable values
// const nonce = [_]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}; // DON'T DO THIS
```

### 3. Timing Attack Prevention
- **Use constant-time comparisons** for sensitive data
- **Avoid branching** on secret values
- **Use authenticated encryption** (AES-GCM, ChaCha20-Poly1305)

```zig
// Good: Constant-time comparison
const is_valid = zcrypto.util.constantTimeCompare(provided_token, expected_token);

// Bad: Variable-time comparison
// const is_valid = std.mem.eql(u8, provided_token, expected_token); // Timing attack risk
```

### 4. Error Handling
- **Handle all cryptographic errors**
- **Don't leak information** through error messages
- **Fail securely** when operations fail

```zig
// Good: Proper error handling
const result = zcrypto.sym.decryptAesGcm(allocator, ciphertext, &key) catch |err| switch (err) {
    error.AuthenticationFailed => return error.InvalidData,
    else => return err,
};

// Bad: Ignoring errors
// const result = zcrypto.sym.decryptAesGcm(allocator, ciphertext, &key) catch unreachable;
```

## Performance Considerations

### Benchmarking

ZCrypto includes built-in benchmarks. Run them with:

```bash
zig build bench
```

### Optimization Tips

1. **Choose appropriate algorithms**:
   - ChaCha20-Poly1305 for software-only environments
   - AES-GCM when hardware acceleration is available

2. **Reuse contexts** for repeated operations:
   - Allocate buffers once and reuse
   - Keep encryption contexts alive for multiple operations

3. **Batch operations** when possible:
   - Hash multiple messages together
   - Use streaming APIs for large data

4. **Memory management**:
   - Use arena allocators for temporary cryptographic operations
   - Clear sensitive data promptly

## Examples

### Complete Password Manager

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub const PasswordManager = struct {
    allocator: std.mem.Allocator,
    master_key: [32]u8,
    
    pub fn init(allocator: std.mem.Allocator, master_password: []const u8) !PasswordManager {
        // Derive master key from password
        const salt = "PasswordManager-v1.0"; // In practice, use a stored random salt
        const master_key = try zcrypto.kdf.pbkdf2(master_password, salt, 100000, 32);
        
        return PasswordManager{
            .allocator = allocator,
            .master_key = master_key,
        };
    }
    
    pub fn deinit(self: *PasswordManager) void {
        zcrypto.util.secureZero(&self.master_key);
    }
    
    pub fn encryptPassword(self: *PasswordManager, password: []const u8) ![]u8 {
        return zcrypto.sym.encryptAesGcm(self.allocator, password, &self.master_key);
    }
    
    pub fn decryptPassword(self: *PasswordManager, encrypted_password: []const u8) ![]u8 {
        return zcrypto.sym.decryptAesGcm(self.allocator, encrypted_password, &self.master_key);
    }
};
```

### Secure Communication Protocol

```zig
pub const SecureChannel = struct {
    send_key: [32]u8,
    recv_key: [32]u8,
    send_counter: u64,
    recv_counter: u64,
    
    pub fn init(shared_secret: []const u8) SecureChannel {
        const send_key = zcrypto.kdf.hkdf(shared_secret, "SecureChannel", "send", 32);
        const recv_key = zcrypto.kdf.hkdf(shared_secret, "SecureChannel", "recv", 32);
        
        return SecureChannel{
            .send_key = send_key,
            .recv_key = recv_key,
            .send_counter = 0,
            .recv_counter = 0,
        };
    }
    
    pub fn encryptMessage(self: *SecureChannel, allocator: std.mem.Allocator, message: []const u8) ![]u8 {
        defer self.send_counter += 1;
        
        // Include counter in additional data for replay protection
        const counter_bytes = std.mem.asBytes(&self.send_counter);
        
        return zcrypto.sym.encryptAesGcmWithAad(allocator, message, counter_bytes, &self.send_key);
    }
    
    pub fn decryptMessage(self: *SecureChannel, allocator: std.mem.Allocator, ciphertext: []const u8) ![]u8 {
        defer self.recv_counter += 1;
        
        const counter_bytes = std.mem.asBytes(&self.recv_counter);
        
        return zcrypto.sym.decryptAesGcmWithAad(allocator, ciphertext, counter_bytes, &self.recv_key);
    }
};
```

## Contributing

ZCrypto is open source and welcomes contributions. See the main repository for:

- Contribution guidelines
- Issue tracking
- Feature requests
- Security vulnerability reporting

## License

ZCrypto is released under the MIT License. See LICENSE file for details.

---

For more information, visit the [ZCrypto GitHub repository](https://github.com/yourusername/zcrypto) or check out the [API documentation](DOCS.md).
