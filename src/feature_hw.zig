//! zcrypto Hardware Acceleration Feature Module - SIMD and CPU-specific optimizations
//!
//! Provides hardware-accelerated cryptographic operations when enabled.

const std = @import("std");

// Re-export hardware acceleration modules
pub const hardware = @import("hardware.zig");

// Re-export main types for convenience
pub const HardwareAcceleration = hardware.HardwareAcceleration;
pub const SIMD = hardware.SIMD;

// Hardware acceleration test suite
test {
    _ = hardware;
}
