//! Security Guards for zcrypto
//!
//! This module provides compile-time and runtime guards to prevent
//! accidental use of incomplete or insecure cryptographic code paths.
//!
//! Phase 0 Security Controls:
//! - Experimental crypto: Placeholder implementations that are NOT production-ready
//! - Insecure options: Options like insecure_skip_verify that bypass security checks

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

/// Whether experimental/placeholder crypto implementations are allowed.
/// This MUST be explicitly enabled at build time with -Dexperimental-crypto=true.
///
/// Experimental crypto includes:
/// - Placeholder key derivation in QUIC
/// - Stub TLS certificate verification
/// - Placeholder HSM/TPM operations
/// - XOR-based "encryption" placeholders
pub const allow_experimental_crypto = build_options.allow_experimental_crypto;

/// Whether insecure options (like insecure_skip_verify) are allowed in release builds.
/// This MUST be explicitly enabled at build time with -Dallow-insecure=true.
pub const allow_insecure_options = build_options.allow_insecure_options;

/// Returns true if this is a release/optimized build
pub fn isReleaseBuild() bool {
    return builtin.mode != .Debug;
}

/// Compile-time assertion that experimental crypto is enabled.
/// Use this to guard placeholder implementations.
pub fn requireExperimentalCrypto(comptime feature_name: []const u8) void {
    if (!allow_experimental_crypto) {
        @compileError(
            "SECURITY ERROR: '" ++ feature_name ++ "' uses placeholder/incomplete cryptography. " ++
                "This code path is NOT safe for production use. " ++
                "To enable for testing/development, rebuild with: -Dexperimental-crypto=true",
        );
    }
}

/// Runtime check for insecure options in release builds.
/// Returns an error if insecure options are used in release builds without explicit opt-in.
pub fn checkInsecureOption(comptime option_name: []const u8) error{InsecureOptionInReleaseBuild}!void {
    if (isReleaseBuild() and !allow_insecure_options) {
        std.log.err(
            "SECURITY ERROR: '{s}' is not allowed in release builds. " ++
                "This option bypasses critical security checks. " ++
                "To enable (DANGEROUS), rebuild with: -Dallow-insecure=true",
            .{option_name},
        );
        return error.InsecureOptionInReleaseBuild;
    }
    if (allow_insecure_options) {
        std.log.warn(
            "SECURITY WARNING: '{s}' is enabled. " ++
                "Security checks are bypassed. Do NOT use in production.",
            .{option_name},
        );
    }
}

/// Log a warning when experimental crypto is used (even when allowed).
/// Call this at runtime to ensure visibility.
pub fn warnExperimentalCrypto(comptime feature_name: []const u8) void {
    if (allow_experimental_crypto) {
        std.log.warn(
            "SECURITY WARNING: Using experimental/placeholder crypto: '{s}'. " ++
                "This implementation is NOT production-ready and may be insecure.",
            .{feature_name},
        );
    }
}

/// Security errors that can be returned by guarded functions
pub const SecurityError = error{
    InsecureOptionInReleaseBuild,
    ExperimentalCryptoNotAllowed,
    PlaceholderCryptoDisabled,
};

test "security guards compile-time check" {
    // This test verifies the security module compiles correctly.
    // The actual compile-time guards are tested by attempting to
    // use guarded code paths without the experimental flag.
    if (allow_experimental_crypto) {
        warnExperimentalCrypto("test");
    }
}
