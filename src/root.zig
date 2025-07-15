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

// Advanced cryptographic modules
pub const quic_crypto = @import("quic_crypto.zig");
pub const hardware = @import("hardware.zig");
pub const post_quantum = @import("post_quantum.zig");
pub const kex = @import("kex.zig");
pub const async_crypto = @import("async_crypto.zig");
pub const zkp = @import("zkp.zig");
pub const bls = @import("bls.zig");
pub const schnorr = @import("schnorr.zig");

// Performance and ecosystem integration (v0.7.0)
pub const zero_copy = @import("zero_copy.zig");
pub const bbr_crypto = @import("bbr_crypto.zig");
pub const vpn_crypto = @import("vpn_crypto.zig");
pub const wasm_crypto = @import("wasm_crypto.zig");
pub const blockchain_crypto = @import("blockchain_crypto.zig");
pub const pool_crypto = @import("pool_crypto.zig");

// Enterprise and security features
pub const formal = @import("formal.zig");
pub const hsm = @import("hsm.zig");
pub const perf_analysis = @import("perf_analysis.zig");

// Post-quantum cryptography module (legacy compatibility)
pub const pq = @import("pq.zig");

// TLS/QUIC specific modules
pub const tls = @import("tls.zig");
pub const quic = @import("quic.zig");

// FFI exports for Rust integration
pub const ffi = @import("ffi.zig");

// Convenience exports for common algorithms
pub const kyber = post_quantum.ML_KEM_768;
pub const dilithium = post_quantum.ML_DSA_65;
pub const x25519 = kex.X25519;
pub const ed25519 = kex.Ed25519;

// Version information
pub const version = "0.7.0";

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
    _ = quic_crypto;
    _ = hardware;
    _ = post_quantum;
    _ = kex;
    _ = async_crypto;
    _ = zkp;
    _ = formal;
    _ = hsm;
    _ = perf_analysis;

    // New v0.7.0 modules
    _ = zero_copy;
    _ = bbr_crypto;
    _ = vpn_crypto;
    _ = wasm_crypto;
    _ = blockchain_crypto;
    _ = pool_crypto;
}
