//! zcrypto Async Feature Module - Asynchronous cryptographic operations
//!
//! Provides async crypto operations using zsync runtime when enabled.

const std = @import("std");

// Re-export async modules
pub const async_crypto = @import("async_crypto.zig");

// Re-export main types for convenience
pub const AsyncCrypto = async_crypto.AsyncCrypto;
pub const AsyncCryptoResult = async_crypto.AsyncCryptoResult;

// Note: Io, Future, and BlockingIo types are defined in async_crypto.zig
// and will be available when zsync is linked

// Async test suite
test {
    _ = async_crypto;
}
