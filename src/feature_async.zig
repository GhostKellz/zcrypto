//! zcrypto Async Feature Module.
//!
//! Provides zsync-backed async integration helpers when the async feature is
//! enabled. The current release surface targets the stable `zsync` core APIs.

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
