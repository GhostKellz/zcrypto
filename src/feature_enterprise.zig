//! zcrypto Enterprise Feature Module - HSM and formal verification support
//!
//! Provides enterprise-grade cryptographic features when enabled.

const std = @import("std");

// Re-export enterprise modules
pub const formal = @import("formal.zig");
pub const hsm = @import("hsm.zig");
pub const perf_analysis = @import("perf_analysis.zig");

// Enterprise test suite
test {
    _ = formal;
    _ = hsm;
    _ = perf_analysis;
}
