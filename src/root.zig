//! zcrypto - A modern cryptography library for Zig
//!
//! Designed for high-performance, memory-safe cryptographic operations
//! with a focus on TLS 1.3, QUIC, and modern public-key cryptography.
const std = @import("std");

/// Standardized crypto errors for consistent error handling
pub const CryptoError = error{
    InvalidSeed,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidHmacKey,
    InvalidKeyFormat,
    SignatureVerificationFailed,
    KeyDerivationFailed,
    InsufficientEntropy,
    InvalidKeySize,
    InvalidNonceSize,
    InvalidTagSize,
    DecryptionFailed,
    EncryptionFailed,
    InvalidInput,
};

// Re-export all modules for clean API
pub const hash = @import("hash.zig");
pub const auth = @import("auth.zig");
pub const sym = @import("sym.zig");
pub const asym = @import("asym.zig");
pub const kdf = @import("kdf.zig");
pub const rand = @import("rand.zig");
pub const util = @import("util.zig");
pub const bip = @import("bip.zig");
pub const batch = @import("batch.zig");

// Post-quantum cryptography module
pub const pq = @import("pq.zig");

// TLS/QUIC specific modules
pub const tls = @import("tls.zig");
pub const quic = @import("quic.zig");

// FFI exports for Rust integration
pub const ffi = @import("ffi.zig");

// Version information  
pub const version = "0.4.0";

test {
    // Import all module tests
    _ = hash;
    _ = auth;
    _ = sym;
    _ = asym;
    _ = kdf;
    _ = rand;
    _ = util;
    _ = bip;
    _ = pq;
    _ = tls;
    _ = quic;
    _ = ffi;
}
