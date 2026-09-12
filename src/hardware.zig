//! Compile-target feature detection, and wrappers over the `std.crypto`
//! primitives that consume those features.
//!
//! This module does not implement acceleration. It used to read as though it
//! did: entry points named `...Hw`, a branch on detected features, and a
//! separate "hardware" callee behind each branch. Every one of those callees
//! forwarded to its software sibling, so both arms of every branch ran the same
//! code, and the tests that compared them could only ever agree.
//!
//! The real instruction selection happens inside `std.crypto`, at comptime,
//! from the build target:
//!
//! - AES: `std/crypto/aes.zig` selects `aes/aesni.zig` for x86_64 with `aes`
//!   and `avx`, `aes/armcrypto.zig` for aarch64 with `aes`, else `aes/soft.zig`.
//!   It publishes the outcome as `std.crypto.core.aes.has_hardware_support`.
//! - ChaCha20: `std/crypto/chacha20.zig` picks a vector width from `avx512f`,
//!   `avx2`, or `neon`.
//! - SHA-256: `std/crypto/sha2.zig` uses the SHA extensions for x86 with `sha`
//!   *and* `avx2`, or aarch64 with `sha2`.
//!
//! So calling the plain `std.crypto` API is what gets the accelerated code. A
//! branch here could not add acceleration, only disagree about it -- and it did:
//! the AES branch tested `aes and pclmulqdq` while the stdlib requires `aes and
//! avx`, and the SHA branch tested `sha` alone while the stdlib also requires
//! `avx2`. Those conditions are not equivalent, and a build for
//! `x86_64+aes+pclmul` satisfies this module's test while the stdlib compiles in
//! the software AES.
//!
//! `HardwareAcceleration.detect()` is retained because callers use it as build
//! metadata, but see its own comment: it is not a runtime capability check.

const std = @import("std");
const builtin = @import("builtin");
const rand = @import("rand.zig");
const util = @import("util.zig");

pub const HardwareAcceleration = struct {
    aes_ni: bool = false, // Intel AES-NI instructions
    sha_ext: bool = false, // Intel SHA extensions
    arm_crypto: bool = false, // ARM Crypto extensions
    pclmulqdq: bool = false, // Carry-less multiplication
    avx2: bool = false, // AVX2 SIMD instructions
    avx512: bool = false, // AVX-512 SIMD instructions

    /// Reports the CPU features of the *build target*, not of the machine
    /// executing the call. It reads `builtin.cpu.features`, which is fixed when
    /// the binary is compiled; there is no CPUID here. A binary built with
    /// `-Dcpu=baseline` reports no acceleration on a machine that has it, and a
    /// binary built with `-Dcpu=native` on one host reports that host's features
    /// on every machine it is later copied to -- where the instructions may not
    /// exist at all, which is a SIGILL and not something a flag read can prevent.
    ///
    /// Treat this as build metadata for logs and benchmarks. It does not select
    /// an implementation: see the module comment for where that actually happens.
    pub fn detect() HardwareAcceleration {
        var features = HardwareAcceleration{};

        switch (builtin.cpu.arch) {
            .x86_64 => {
                if (std.Target.x86.featureSetHas(builtin.cpu.features, .aes)) {
                    features.aes_ni = true;
                }
                if (std.Target.x86.featureSetHas(builtin.cpu.features, .sha)) {
                    features.sha_ext = true;
                }
                if (std.Target.x86.featureSetHas(builtin.cpu.features, .pclmul)) {
                    features.pclmulqdq = true;
                }
                if (std.Target.x86.featureSetHas(builtin.cpu.features, .avx2)) {
                    features.avx2 = true;
                }
                if (std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f)) {
                    features.avx512 = true;
                }
            },
            .aarch64 => {
                if (std.Target.aarch64.featureSetHas(builtin.cpu.features, .aes)) {
                    features.arm_crypto = true;
                }
            },
            else => {
                // No hardware acceleration for other architectures yet
            },
        }

        return features;
    }

    pub fn isAvailable(self: HardwareAcceleration, feature: HardwareFeature) bool {
        return switch (feature) {
            .aes_ni => self.aes_ni,
            .sha_ext => self.sha_ext,
            .arm_crypto => self.arm_crypto,
            .pclmulqdq => self.pclmulqdq,
            .avx2 => self.avx2,
            .avx512 => self.avx512,
        };
    }
};

pub const HardwareFeature = enum {
    aes_ni,
    sha_ext,
    arm_crypto,
    pclmulqdq,
    avx2,
    avx512,
};

/// Vectorized operations using SIMD when available
pub const SIMD = struct {
    /// XOR two buffers.
    ///
    /// There used to be three branches here, chosen by `detect()` and buffer
    /// length. They all computed the same byte-wise XOR: the AVX2 arm called the
    /// SSE arm, and the SSE arm was a scalar loop that hand-unrolled 16 bytes at
    /// a time without ever naming an SSE instruction. The single loop below is
    /// what the compiler vectorizes for the actual target, which is the only
    /// place the target is known.
    /// These lengths come from the caller, so they are a boundary condition and
    /// are enforced with returned errors. They were `std.debug.assert`, which
    /// ReleaseFast removes: passing a `result` shorter than `a` then wrote past
    /// the end of the caller's buffer, reproducibly reaching SIGSEGV in a
    /// ReleaseFast build while Debug aborted on the assert. Same reasoning, and
    /// same fix, as the `HardwareCrypto` length contract below.
    pub fn vectorizedXor(a: []const u8, b: []const u8, result: []u8) !void {
        if (a.len != b.len) return error.LengthMismatch;
        if (result.len < a.len) return error.BufferTooSmall;

        for (a, b, result[0..a.len]) |byte_a, byte_b, *byte_result| {
            byte_result.* = byte_a ^ byte_b;
        }
    }

    /// Compares two buffers in time that depends on their length but not on
    /// their contents. Same history as `vectorizedXor`: the branches differed
    /// only in how the identical accumulate loop was spelled.
    ///
    /// The early `a.len != b.len` return is a length leak, not a content leak,
    /// and is deliberate -- a differing length is already public in every caller
    /// here. Contents are folded into a single accumulator with no branch.
    pub fn vectorizedMemcmp(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;

        var result: u8 = 0;
        for (a, b) |byte_a, byte_b| {
            result |= byte_a ^ byte_b;
        }
        return result == 0;
    }

    /// Parallel AES encryption for multiple blocks
    pub fn parallelAesEncrypt(keys: []const [16]u8, plaintexts: []const []const u8, ciphertexts: [][]u8) !void {
        // Caller-supplied lengths again, and the multi-object `for` below
        // requires them to be equal -- its own safety check is also removed in
        // ReleaseFast, so an assert here bought nothing in the build that needed
        // it most.
        if (keys.len != plaintexts.len) return error.LengthMismatch;
        if (ciphertexts.len != plaintexts.len) return error.LengthMismatch;

        // `detect()` used to choose between two branches whose bodies were
        // character-for-character identical. `Aes128.initEnc` already resolves to
        // the AES-NI or ARM implementation when the target supports it.
        for (keys, plaintexts, ciphertexts) |key, plaintext, ciphertext| {
            if (plaintext.len != 16 or ciphertext.len < 16) continue;

            const aes = std.crypto.core.aes.Aes128.initEnc(key);
            aes.encrypt(ciphertext[0..16], plaintext[0..16]);
        }
    }
};

/// Linux /dev/crypto interface
pub const DevCrypto = struct {
    fd: ?std.posix.fd_t = null,

    pub fn init() !DevCrypto {
        // `std.posix.AT.FDCWD` does not exist on Windows, and this branch is
        // comptime-known, so gating here keeps the POSIX call out of semantic
        // analysis entirely rather than merely unreached at runtime.
        if (builtin.os.tag != .linux) return DevCrypto{ .fd = null };

        // Try to open /dev/crypto using posix openat
        const fd = std.posix.openat(std.posix.AT.FDCWD, "/dev/crypto", .{ .ACCMODE = .RDWR }, 0) catch |err| switch (err) {
            error.FileNotFound, error.AccessDenied => return DevCrypto{ .fd = null },
            else => return err,
        };

        return DevCrypto{ .fd = fd };
    }

    pub fn deinit(self: *DevCrypto) void {
        if (builtin.os.tag != .linux) return;
        if (self.fd) |fd| {
            _ = std.posix.system.close(fd);
            self.fd = null;
        }
    }

    pub fn isAvailable(self: DevCrypto) bool {
        return self.fd != null;
    }

    /// Perform AES encryption using /dev/crypto
    pub fn aesEncrypt(self: *DevCrypto, key: []const u8, plaintext: []const u8, ciphertext: []u8) !void {
        if (self.fd == null) {
            return error.DeviceNotAvailable;
        }

        // Mock implementation - real implementation would use ioctl calls
        _ = key;
        _ = plaintext;
        _ = ciphertext;

        // In reality, this would:
        // 1. Create crypto session with CIOCGSESSION ioctl
        // 2. Setup crypto operation with CIOCCRYPT ioctl
        // 3. Execute operation and get results
        return error.NotImplemented;
    }
};

/// OpenSSL engine integration
pub const OpenSSLEngine = struct {
    engine_handle: ?*anyopaque = null,

    pub fn init(engine_name: []const u8) !OpenSSLEngine {
        _ = engine_name;
        // Try to load OpenSSL engine
        // In real implementation, this would use dlopen/dlsym
        return OpenSSLEngine{ .engine_handle = null };
    }

    pub fn deinit(self: *OpenSSLEngine) void {
        if (self.engine_handle) |handle| {
            _ = handle;
            // In real implementation, would call ENGINE_free()
            self.engine_handle = null;
        }
    }

    pub fn isAvailable(self: OpenSSLEngine) bool {
        return self.engine_handle != null;
    }

    /// Use OpenSSL engine for crypto operations
    pub fn engineCrypto(self: *OpenSSLEngine, operation: []const u8, input: []const u8, output: []u8) !void {
        if (self.engine_handle == null) {
            return error.EngineNotLoaded;
        }

        _ = operation;
        _ = input;
        _ = output;

        // In reality, this would call OpenSSL engine functions
        return error.NotImplemented;
    }
};

/// Length-checked wrappers over the `std.crypto` AEAD and hash primitives.
///
/// The `Hw` suffix is kept only because it is the released public name; it
/// describes no property of these functions. Nothing here is a distinct
/// implementation, and no branch here picks one -- see the module comment. What
/// these wrappers do add is a length contract enforced with returned errors
/// rather than `std.debug.assert`, so it survives ReleaseFast.
pub const HardwareCrypto = struct {
    /// AEAD wrapper over `std.crypto.aead.aes_gcm.Aes128Gcm` / `Aes256Gcm`,
    /// selected by key length.
    pub fn aesGcmEncryptHw(key: []const u8, nonce: []const u8, plaintext: []const u8, aad: []const u8, ciphertext: []u8, tag: []u8) !void {
        // These lengths come from the caller, so they are a boundary condition
        // rather than an internal invariant. The inner routines only asserted
        // them, and `std.debug.assert` compiles to nothing in ReleaseFast, so a
        // short nonce or output buffer read and wrote past the end there.
        //
        // The nonce length is required to be exact, not a minimum. Both AEADs
        // behind this wrapper take a fixed 12-byte nonce, and the inner routines
        // reach it as `nonce[0..12]`. Accepting `>= 12` therefore truncated a
        // longer nonce silently: the caller believed it had encrypted under the
        // nonce it supplied, and two distinct 13-byte nonces sharing a 12-byte
        // prefix collapsed to the same value. For GCM and Poly1305 that is
        // catastrophic nonce reuse -- key recovery for the authenticator -- from
        // an input the caller had every reason to think was distinct. Rejecting
        // the length is the only safe reading, because there is no correct way
        // to guess which 12 of the 13 bytes were meant.
        //
        // Output buffers keep `>=`: those are capacity, where extra room is
        // genuinely harmless, and the exact written length is documented.
        if (key.len != 16 and key.len != 32) return error.InvalidKey;
        if (nonce.len != 12) return error.InvalidNonce;
        if (ciphertext.len < plaintext.len) return error.BufferTooSmall;
        if (tag.len < 16) return error.BufferTooSmall;

        try aesGcmEncrypt(key, nonce, plaintext, aad, ciphertext, tag);
    }

    /// AEAD wrapper over `std.crypto.aead.chacha_poly.ChaCha20Poly1305`.
    pub fn chacha20Poly1305EncryptHw(key: []const u8, nonce: []const u8, plaintext: []const u8, aad: []const u8, ciphertext: []u8, tag: []u8) !void {
        if (key.len != 32) return error.InvalidKey;
        if (nonce.len != 12) return error.InvalidNonce;
        if (ciphertext.len < plaintext.len) return error.BufferTooSmall;
        if (tag.len < 16) return error.BufferTooSmall;

        try chacha20Poly1305Encrypt(key, nonce, plaintext, aad, ciphertext, tag);
    }

    /// SHA-256 wrapper over `std.crypto.hash.sha2.Sha256`.
    pub fn sha256HashHw(data: []const u8, hash: []u8) !void {
        if (hash.len < 32) return error.BufferTooSmall;

        // The `features.sha_ext` branch that used to be here called a function
        // whose body was a copy of the branch it was chosen over. Worse, its
        // condition was wrong: `std/crypto/sha2.zig` takes the SHA-extension
        // path only with `sha` *and* `avx2`, so a `sha`-without-`avx2` target
        // took the arm labelled "Use Intel SHA extensions" and got the generic
        // block function.
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(data);
        hasher.final(hash[0..32]);
    }

    fn aesGcmEncrypt(key: []const u8, nonce: []const u8, plaintext: []const u8, aad: []const u8, ciphertext: []u8, tag: []u8) !void {
        std.debug.assert(ciphertext.len >= plaintext.len);
        std.debug.assert(tag.len >= 16);

        switch (key.len) {
            16 => {
                const key_array: [16]u8 = key[0..16].*;
                const nonce_array: [12]u8 = nonce[0..12].*;
                std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(ciphertext[0..plaintext.len], tag[0..16], plaintext, aad, nonce_array, key_array);
            },
            32 => {
                const key_array: [32]u8 = key[0..32].*;
                const nonce_array: [12]u8 = nonce[0..12].*;
                std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(ciphertext[0..plaintext.len], tag[0..16], plaintext, aad, nonce_array, key_array);
            },
            else => return error.InvalidKey,
        }
    }

    fn chacha20Poly1305Encrypt(key: []const u8, nonce: []const u8, plaintext: []const u8, aad: []const u8, ciphertext: []u8, tag: []u8) !void {
        std.debug.assert(key.len == 32);
        std.debug.assert(nonce.len == 12);
        std.debug.assert(ciphertext.len >= plaintext.len);
        std.debug.assert(tag.len >= 16);

        const key_array: [32]u8 = key[0..32].*;
        const nonce_array: [12]u8 = nonce[0..12].*;
        std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(ciphertext[0..plaintext.len], tag[0..16], plaintext, aad, nonce_array, key_array);
    }
};

/// Benchmark utilities.
pub const Benchmark = struct {
    pub const Result = struct {
        operations_per_second: f64,
        bytes_per_second: f64,
        average_latency_ns: u64,

        /// Whether the AES this measurement actually ran was the hardware
        /// implementation, taken from `std.crypto`'s own published answer.
        ///
        /// This replaces a `hardware_accelerated` field computed here as
        /// `aes_ni and pclmulqdq`. That expression is not the condition the
        /// stdlib uses -- it selects `aes/aesni.zig` on `aes and avx` -- so the
        /// old field labelled a `x86_64+aes+pclmul` build "accelerated" while
        /// the numbers next to it came from `aes/soft.zig`. A benchmark result
        /// that misattributes its own throughput is worse than one that omits
        /// the attribution.
        aes_hardware_backed: bool,
    };

    /// Takes an allocator because it used to take `std.testing.allocator`,
    /// which is `@compileError("not testing")` outside the test runner. Zig only
    /// analyzes referenced functions, so this compiled for as long as nobody
    /// called it -- and nobody did, in-tree or out. The one routine that
    /// produced this module's acceleration evidence could not be built by any
    /// consumer, which is why the wrong `hardware_accelerated` value it returned
    /// went unnoticed.
    pub fn benchmarkAesGcm(allocator: std.mem.Allocator, key_size: usize, data_size: usize, iterations: usize) !Result {
        if (key_size != 16 and key_size != 32) return error.InvalidKey;
        // Averages and rates below divide by this.
        if (iterations == 0) return error.InvalidInput;

        const key = try allocator.alloc(u8, key_size);
        defer allocator.free(key);
        const nonce = std.mem.zeroes([12]u8);
        const plaintext = try allocator.alloc(u8, data_size);
        defer allocator.free(plaintext);
        const ciphertext = try allocator.alloc(u8, data_size);
        defer allocator.free(ciphertext);
        var tag: [16]u8 = undefined;

        // Fill with test data
        rand.fill(key);
        rand.fill(plaintext);

        // Monotonic, not the wall clock. A realtime clock can be stepped
        // backwards by NTP or an operator mid-run, which made this delta
        // negative and panicked the `@intCast` to u64 in safe builds. Refusing
        // a negative delta was the stopgap; measuring against a clock that
        // cannot produce one is the fix.
        const start = try util.getMonotonicOrError();

        for (0..iterations) |_| {
            try HardwareCrypto.aesGcmEncryptHw(key, &nonce, plaintext, "", ciphertext, &tag);
        }

        const total_time_ns = try (try util.getMonotonicOrError()).since(start);

        // Zero is still refused, and still has to be. Monotonic means the clock
        // never goes backwards, not that it is infinitely fine-grained: too few
        // iterations on a coarse clock lands both readings on the same tick, and
        // that divides into an infinite ops/sec. Reporting a fabricated number
        // is the failure mode this routine is being cleaned up for.
        if (total_time_ns == 0) return error.ClockUnusable;

        const average_latency_ns = total_time_ns / iterations;
        const operations_per_second = (@as(f64, @floatFromInt(iterations)) * 1_000_000_000.0) / @as(f64, @floatFromInt(total_time_ns));
        const bytes_per_second = (@as(f64, @floatFromInt(iterations * data_size)) * 1_000_000_000.0) / @as(f64, @floatFromInt(total_time_ns));

        return Result{
            .operations_per_second = operations_per_second,
            .bytes_per_second = bytes_per_second,
            .average_latency_ns = average_latency_ns,
            .aes_hardware_backed = std.crypto.core.aes.has_hardware_support,
        };
    }
};

// Tests
const testing = std.testing;

test "hardware acceleration detection" {
    const features = HardwareAcceleration.detect();

    // Should at least detect basic architecture
    switch (builtin.cpu.arch) {
        .x86_64 => {
            // May or may not have AES-NI, but detection should work
            _ = features.aes_ni;
        },
        .aarch64 => {
            // May or may not have ARM crypto, but detection should work
            _ = features.arm_crypto;
        },
        else => {},
    }
}

test "vectorized XOR" {
    const a = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const b = [_]u8{ 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    var result: [8]u8 = undefined;

    try SIMD.vectorizedXor(&a, &b, &result);

    // Verify XOR operation
    for (a, b, result) |byte_a, byte_b, byte_result| {
        try testing.expectEqual(byte_a ^ byte_b, byte_result);
    }
}

test "vectorized XOR rejects mismatched lengths instead of running off the buffer" {
    // These were `std.debug.assert`, so in ReleaseFast a short output buffer
    // wrote past the caller's allocation -- reproduced as a SIGSEGV. Returned
    // errors are checked identically in every optimization mode, which is the
    // whole point of not using an assert on a caller-supplied length.
    const a = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const b = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };

    const canary: u8 = 0xA5;
    var out: [8]u8 = @splat(canary);

    try testing.expectError(error.LengthMismatch, SIMD.vectorizedXor(&a, b[0..4], &out));
    try testing.expectError(error.BufferTooSmall, SIMD.vectorizedXor(&a, &b, out[0..4]));

    // A rejected call must not have written anything, or the caller is left
    // holding a partially transformed buffer next to an error return.
    for (out) |byte| try testing.expectEqual(canary, byte);

    // ...and the well-formed call still works, so the checks above are
    // rejecting the bad lengths rather than failing for an unrelated reason.
    try SIMD.vectorizedXor(&a, &b, &out);
    for (a, b, out) |byte_a, byte_b, byte_out| {
        try testing.expectEqual(byte_a ^ byte_b, byte_out);
    }
}

test "vectorized memcmp" {
    const a = [_]u8{ 1, 2, 3, 4, 5 };
    const b = [_]u8{ 1, 2, 3, 4, 5 };
    const c = [_]u8{ 1, 2, 3, 4, 6 };

    try testing.expect(SIMD.vectorizedMemcmp(&a, &b));
    try testing.expect(!SIMD.vectorizedMemcmp(&a, &c));
}

test "/dev/crypto availability" {
    var dev_crypto = DevCrypto.init() catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied => {
            // Expected on systems without /dev/crypto
            return;
        },
        else => return err,
    };
    defer dev_crypto.deinit();

    // Test that we can detect availability
    _ = dev_crypto.isAvailable();
}

test "OpenSSL engine loading" {
    var engine = try OpenSSLEngine.init("aesni");
    defer engine.deinit();

    // Engine likely won't be available in test environment
    try testing.expect(!engine.isAvailable());
}

test "hardware crypto fallback" {
    const key = blk: {
        var bytes = std.mem.zeroes([16]u8);
        @memset(bytes[0..], 0x01);
        break :blk bytes;
    };
    const nonce = blk: {
        var bytes = std.mem.zeroes([12]u8);
        @memset(bytes[0..], 0x02);
        break :blk bytes;
    };
    const plaintext = "Hello, World!";
    var ciphertext: [13]u8 = undefined;
    var tag: [16]u8 = undefined;

    try HardwareCrypto.aesGcmEncryptHw(&key, &nonce, plaintext, "", &ciphertext, &tag);

    // Should not crash and produce some output
    var all_zeros = true;
    for (ciphertext) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try testing.expect(!all_zeros);
}

test "benchmark is callable and attributes its own backend" {
    // There was no test here, and no caller anywhere, which is how
    // `benchmarkAesGcm` shipped as public API that could not be compiled: it
    // allocated from `std.testing.allocator`, a `@compileError` outside the test
    // runner. Zig only analyzes referenced functions, so nothing ever noticed.
    // This test exists to keep it referenced from a normal allocator.
    const result = try Benchmark.benchmarkAesGcm(testing.allocator, 32, 1024, 16);

    // Not asserting a throughput -- that is a property of the machine, and
    // pinning one would make this a flaky test rather than a useful one. What is
    // checkable is that the numbers are finite and the attribution is the
    // stdlib's own, not this module's guess at it.
    try testing.expect(std.math.isFinite(result.operations_per_second));
    try testing.expect(result.operations_per_second > 0);
    try testing.expect(std.math.isFinite(result.bytes_per_second));
    try testing.expectEqual(std.crypto.core.aes.has_hardware_support, result.aes_hardware_backed);

    // Arguments that would divide by zero or pick no AES variant are refused
    // rather than producing a Result the caller cannot distinguish from a real
    // measurement.
    try testing.expectError(error.InvalidInput, Benchmark.benchmarkAesGcm(testing.allocator, 32, 64, 0));
    try testing.expectError(error.InvalidKey, Benchmark.benchmarkAesGcm(testing.allocator, 24, 64, 4));
}
