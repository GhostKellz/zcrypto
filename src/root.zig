//! zcrypto - A modern cryptography library for Zig
//!
//! Designed for high-performance, memory-safe cryptographic operations
//! with a focus on TLS 1.3, QUIC, and modern public-key cryptography.
const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

/// Core module and standardized crypto errors for stable v1.0.x callers.
pub const core = @import("core.zig");
pub const CryptoError = core.CryptoError;

// Security guards (always available - controls access to experimental/insecure code)
pub const security = @import("security.zig");

// Stable core modules for v1.0.x consumers.
pub const hash = @import("hash.zig");
pub const auth = @import("auth.zig");
pub const sym = @import("sym.zig");
pub const asym = @import("asym.zig");
pub const kdf = @import("kdf.zig");
pub const rand = @import("rand.zig");
pub const util = @import("util.zig");
pub const bip = @import("bip.zig");
pub const batch = @import("batch.zig");
pub const kex = @import("kex.zig");
pub const blake3 = @import("blake3.zig");
pub const merkle = @import("merkle.zig");
pub const timing = @import("timing.zig");
pub const arena = @import("arena.zig");

/// Hardware-backed key storage: TPM 2.0 and PKCS#11 tokens.
///
/// Not behind `enable_enterprise`, unlike the `formal.hsm` alias that still
/// reaches the same file. That gate exists to keep placeholder crypto out of a
/// default build, and this module no longer contains any: the fabricated key
/// handles, host-side HKDF sold as TPM derivation and OS entropy returned under
/// a hardware name are gone. It also costs a default build nothing — with
/// `-Dtpm`/`-Dpkcs11` off the backend names resolve to shims that report
/// `BackendNotBuilt`, so there is no dependency to acquire and no native
/// library to find. Keeping it gated only meant its tests never ran in the
/// default test build, which is the situation that let the placeholders live.
pub const hsm = @import("hsm.zig");

// Stable QUIC-oriented helpers.
pub const quic_crypto = @import("quic_crypto.zig");
pub const quic = @import("quic.zig");
pub const key_rotation = @import("key_rotation.zig");
pub const QuicCrypto = quic.QuicCrypto;

// Feature-gated modules. Disabled features intentionally expose empty namespaces
// so compatibility checks using @hasDecl on the root do not fail.
pub const tls = if (build_options.enable_tls) @import("feature_tls.zig") else struct {}{};
pub const post_quantum = if (build_options.enable_post_quantum) @import("feature_pq.zig") else struct {}{};
pub const hardware = if (build_options.enable_hardware_accel) @import("feature_hw.zig") else struct {}{};
pub const blockchain_crypto = if (build_options.enable_blockchain) @import("feature_blockchain.zig") else struct {}{};
pub const ghostchain = if (build_options.enable_blockchain) @import("ghostchain.zig") else struct {}{};
pub const vpn_crypto = if (build_options.enable_vpn) @import("feature_vpn.zig") else struct {}{};
pub const wasm_crypto = if (build_options.enable_wasm) @import("feature_wasm.zig") else struct {}{};
pub const formal = if (build_options.enable_enterprise) @import("feature_enterprise.zig") else struct {}{};
pub const zkp = if (build_options.enable_zkp) @import("feature_zkp.zig") else struct {}{};
pub const async_crypto = if (build_options.enable_async) @import("feature_async.zig") else struct {};

// Compatibility aliases retained for v1.0.x migration. New code should prefer
// post_quantum.*, hardware.*, kex.X25519, and kex.Ed25519 directly.
pub const pq = if (build_options.enable_post_quantum) post_quantum else struct {}{};
pub const HardwareCrypto = if (build_options.enable_hardware_accel) @import("hardware.zig").HardwareCrypto else struct {}{};

// Convenience aliases for common stable algorithms.
pub const kyber = if (build_options.enable_post_quantum) post_quantum.kyber else struct {}{};
pub const dilithium = if (build_options.enable_post_quantum) post_quantum.dilithium else struct {}{};
pub const x25519 = kex.X25519;
pub const ed25519 = kex.Ed25519;

// Version information
pub const version = build_options.version;

pub const build_config = struct {
    pub const tls_enabled = build_options.enable_tls;
    pub const post_quantum_enabled = build_options.enable_post_quantum;
    pub const hardware_accel_enabled = build_options.enable_hardware_accel;
    pub const blockchain_enabled = build_options.enable_blockchain;
    pub const vpn_enabled = build_options.enable_vpn;
    pub const wasm_enabled = build_options.enable_wasm;
    pub const enterprise_enabled = build_options.enable_enterprise;
    pub const zkp_enabled = build_options.enable_zkp;
    pub const async_enabled = build_options.enable_async;
    pub const experimental_crypto_enabled = build_options.allow_experimental_crypto;
};

/// How this copy of zcrypto was actually compiled.
///
/// `@import("builtin")` is resolved per module instance, so these describe the
/// zcrypto module itself rather than whoever imported it. That distinction is
/// the whole point: a consumer that asserts on its *own* `builtin.mode` learns
/// nothing about the library it linked against, because a dependency pinned to
/// Debug looks identical from the outside. Comparing `build_info` against the
/// consumer's own `builtin` is what actually proves the build graph propagated
/// the requested mode and target.
pub const build_info = struct {
    pub const mode = builtin.mode;
    pub const cpu_arch = builtin.target.cpu.arch;
    pub const os_tag = builtin.target.os.tag;
    pub const abi = builtin.target.abi;
};

/// Negative control for `api_surface.zig`. Empty unless `-Dapi-surface-control`
/// is passed, in which case it exports a function that cannot compile.
///
/// `api_surface.zig` is only worth anything if it still analyses exported
/// functions nothing calls. Nothing about that is self-evident from a green run
/// -- a `refRecursive` that quietly stopped descending, or a `_ = &@field` the
/// compiler folded away, would leave the test passing and the surface
/// unchecked, which is exactly the state this repository was in before it
/// existed. The gate builds with this flag on and requires the build to *fail*.
///
/// A wrong-arity call rather than `@compileError`, because that is the bug class
/// being guarded against and it exercises the same body analysis a real defect
/// would.
pub const api_surface_control = if (build_options.api_surface_control) struct {
    pub fn neverCalledAndCannotCompile() void {
        _ = std.crypto.kdf.hkdf.HkdfSha256.extract();
    }
} else struct {};

test {
    // Compiles every public declaration. Keep this first: it is the only thing
    // here that fails for a decl no other test calls.
    _ = @import("api_surface.zig");

    _ = core;

    // Import all core module tests
    _ = hash;
    _ = auth;
    _ = sym;
    _ = asym;
    _ = kdf;
    _ = rand;
    _ = util;
    _ = bip;
    _ = batch;
    _ = quic_crypto;
    _ = quic;
    _ = key_rotation;
    _ = blake3;
    _ = merkle;
    _ = timing;
    _ = arena;
    _ = hsm;

    // Feature modules (conditionally available)
    // Note: These tests will only run if the features were enabled during build
    if (build_options.enable_tls) _ = tls;
    if (build_options.enable_post_quantum) _ = post_quantum;
    if (build_options.enable_hardware_accel) _ = hardware;
    if (build_options.enable_blockchain) {
        _ = blockchain_crypto;
        _ = ghostchain;
    }
    if (build_options.enable_vpn) _ = vpn_crypto;
    if (build_options.enable_wasm) _ = wasm_crypto;
    if (build_options.enable_enterprise) _ = formal;
    if (build_options.enable_zkp) _ = zkp;
    if (build_options.enable_async) _ = async_crypto;
}
