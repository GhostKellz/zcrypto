//! Security property reporting for zcrypto
//!
//! This module carries the vocabulary for talking about security properties
//! (`SecurityProperty`, `VerificationContext`, `VerificationResult`) and one
//! working bookkeeping helper, `MemorySafetyVerifier`.
//!
//! It does not perform formal verification. Earlier revisions claimed to, and
//! the analyses behind those claims did not support them:
//!
//! - `ConstantTimeVerifier.verify` timed a function over caller-supplied inputs
//!   and reported "constant-time verified" when the wall-clock samples were
//!   consistent. Consistency across arbitrary inputs is not independence from
//!   secret data: a function that branches on a secret passes whenever the
//!   inputs supplied happen not to exercise the branch. Establishing the real
//!   property needs a fixed-vs-random methodology (dudect/ct-grind) against a
//!   leakage model, not a variance threshold on one machine.
//! - `SideChannelVerifier.verifyCacheTimingResistance` claimed to use
//!   performance counters. It read no counters; its "cache flush" was a
//!   `comptime` loop over a `comptime var`, which emits no runtime code and
//!   evicts nothing. It compared one wall-clock sample per input.
//! - `PostQuantumVerifier.verifyPQSecurity` compared the caller's algorithm
//!   *name* against a hardcoded list and ignored `key_size` entirely. It
//!   verified nothing about the primitive, and the list included SIKE, which
//!   has been broken classically since 2022 — so it answered "post-quantum
//!   secure" for an algorithm that is not secure at all.
//! - `verifySecurityProperty(.post_quantum_safe, ...)` discarded the caller's
//!   function and hardcoded `verifyPQSecurity("ML-KEM", 256, 128)`, so it
//!   returned `verified = true` for every input.
//!
//! Those four entry points now return `FormalError.UnsupportedAlgorithm` rather
//! than a `verified = true` result a caller could act on. The two timing
//! helpers additionally allocated from `std.testing.allocator` inside `pub fn`s,
//! and the side-channel helper indexed `times[0]` before checking that any
//! samples existed.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const util = @import("util.zig");

pub const FormalError = error{
    VerificationFailed,
    InvalidSecurityProperty,
    CompileTimeProofFailed,
    SideChannelDetected,
    MemoryLeakDetected,
    TimingLeakDetected,
    /// This build carries no analysis capable of deciding the requested property.
    UnsupportedAlgorithm,
};

/// Security properties this module has vocabulary for. Naming a property here
/// says nothing about whether zcrypto can decide it; see the module notes.
pub const SecurityProperty = enum {
    constant_time, // Execution time independent of secrets
    side_channel_free, // No observable side channels
    memory_safe, // No buffer overflows or use-after-free
    forward_secure, // Past compromises don't affect future security
    post_quantum_safe, // Resistant to quantum attacks
    perfect_secrecy, // Information-theoretic security
};

/// Describes a property claim under discussion. Purely descriptive: constructing
/// one performs no analysis, and `verified` stays false unless a caller sets it.
pub const VerificationContext = struct {
    property: SecurityProperty,
    function_name: []const u8,
    parameters: []const u8,
    verified: bool = false,

    pub fn init(property: SecurityProperty, function_name: []const u8, parameters: []const u8) VerificationContext {
        return VerificationContext{
            .property = property,
            .function_name = function_name,
            .parameters = parameters,
        };
    }
};

/// Outcome of an analysis. The `proof` field is a human-readable description of
/// what was checked, not a machine-checkable proof object.
pub const VerificationResult = struct {
    property: SecurityProperty,
    verified: bool,
    proof: ?[]const u8 = null,
    counterexample: ?[]const u8 = null,
    proof_time_ns: u64,

    pub fn success(property: SecurityProperty, proof: []const u8, time_ns: u64) VerificationResult {
        return VerificationResult{
            .property = property,
            .verified = true,
            .proof = proof,
            .proof_time_ns = time_ns,
        };
    }

    pub fn failure(property: SecurityProperty, counterexample: []const u8, time_ns: u64) VerificationResult {
        return VerificationResult{
            .property = property,
            .verified = false,
            .counterexample = counterexample,
            .proof_time_ns = time_ns,
        };
    }
};

/// Constant-time analysis. Not implemented; see the module notes.
pub const ConstantTimeVerifier = struct {
    /// Always returns `FormalError.UnsupportedAlgorithm`.
    ///
    /// Deciding this property requires a fixed-vs-random leakage test against a
    /// stated threat model. Timing variance over caller-chosen inputs, which is
    /// what this used to measure, cannot distinguish a constant-time function
    /// from one whose secret-dependent branch those inputs never reached.
    pub fn verify(comptime T: type, comptime func: anytype, inputs: []const T) FormalError!VerificationResult {
        _ = func;
        _ = inputs;
        return FormalError.UnsupportedAlgorithm;
    }
};

/// Memory safety bookkeeping.
///
/// This is a ledger, not a proof: it reconciles the allocations and frees the
/// caller reports to it. It observes no real allocator, so it cannot see
/// anything the caller does not report, and a clean result says only that the
/// reported ledger balances. For actual detection use a checking allocator
/// (`std.testing.allocator`, `GeneralPurposeAllocator` with safety on) or ASan.
pub const MemorySafetyVerifier = struct {
    allocations: std.ArrayList([]u8),
    deallocations: std.ArrayList([]u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MemorySafetyVerifier {
        return MemorySafetyVerifier{
            .allocations = .empty,
            .deallocations = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MemorySafetyVerifier) void {
        self.allocations.deinit(self.allocator);
        self.deallocations.deinit(self.allocator);
    }

    /// Record that the caller allocated `memory`.
    pub fn trackAllocation(self: *MemorySafetyVerifier, memory: []u8) !void {
        try self.allocations.append(self.allocator, memory);
    }

    /// Record that the caller freed `memory`.
    pub fn trackDeallocation(self: *MemorySafetyVerifier, memory: []u8) !void {
        try self.deallocations.append(self.allocator, memory);
    }

    /// Reconcile the ledger: report whether every recorded allocation was freed
    /// exactly once. Scoped to what was recorded — see the type-level note.
    pub fn verify(self: *MemorySafetyVerifier) !VerificationResult {
        const start_time = try util.getMonotonicOrError();

        var leaked_count: usize = 0;
        for (self.allocations.items) |alloc| {
            var found = false;
            for (self.deallocations.items) |dealloc| {
                if (alloc.ptr == dealloc.ptr and alloc.len == dealloc.len) {
                    found = true;
                    break;
                }
            }
            if (!found) leaked_count += 1;
        }

        var double_free_count: usize = 0;
        for (self.deallocations.items, 0..) |dealloc1, i| {
            for (self.deallocations.items[i + 1 ..]) |dealloc2| {
                if (dealloc1.ptr == dealloc2.ptr and dealloc1.len == dealloc2.len) {
                    double_free_count += 1;
                }
            }
        }

        // `since` rather than a subtraction and `@intCast`: the old form cast an
        // i128 difference to u64, so a clock that stepped backwards between the
        // two reads was illegal behavior -- a panic in a safe build -- rather
        // than a reportable error.
        const total_time = try (try util.getMonotonicOrError()).since(start_time);

        if (leaked_count == 0 and double_free_count == 0) {
            return VerificationResult.success(
                .memory_safe,
                "Recorded allocations and frees reconcile; scope is the caller's ledger only",
                total_time,
            );
        } else {
            return VerificationResult.failure(
                .memory_safe,
                "Recorded ledger does not reconcile: unfreed allocation or repeated free",
                total_time,
            );
        }
    }
};

/// Side-channel analysis. Not implemented; see the module notes.
pub const SideChannelVerifier = struct {
    /// Always returns `FormalError.UnsupportedAlgorithm`.
    ///
    /// Cache-timing analysis requires real eviction and hardware performance
    /// counters. This build has neither.
    pub fn verifyCacheTimingResistance(comptime func: anytype, test_inputs: anytype) FormalError!VerificationResult {
        _ = func;
        _ = test_inputs;
        return FormalError.UnsupportedAlgorithm;
    }
};

/// Post-quantum security analysis. Not implemented; see the module notes.
pub const PostQuantumVerifier = struct {
    /// Always returns `FormalError.UnsupportedAlgorithm`.
    ///
    /// Whether a primitive resists quantum attack is a cryptanalytic question
    /// about the primitive, not about the string a caller passes for its name.
    /// For the parameter sets zcrypto actually implements, see `post_quantum`,
    /// which is backed by the standard library's FIPS 203/204 primitives.
    pub fn verifyPQSecurity(algorithm_name: []const u8, key_size: usize, security_level: u8) FormalError!VerificationResult {
        _ = algorithm_name;
        _ = key_size;
        _ = security_level;
        return FormalError.UnsupportedAlgorithm;
    }
};

/// Dispatch to the analysis for `property`. Every property routes to an
/// unimplemented analysis, so this always fails; see the module notes.
pub fn verifySecurityProperty(
    comptime property: SecurityProperty,
    comptime func: anytype,
    comptime test_data: anytype,
) FormalError!VerificationResult {
    _ = func;
    _ = test_data;
    _ = property;
    return FormalError.UnsupportedAlgorithm;
}

// =============================================================================
// TESTS
// =============================================================================

test "timing and post-quantum analyses report themselves unsupported" {
    const inputs = [_]u32{ 0, 1, 255 };
    const noop = struct {
        fn f(x: u32) u32 {
            return x;
        }
    }.f;

    // Each of these previously returned verified = true. The assertions below
    // are the regression guard: a result a caller could act on is a failure.
    try testing.expectError(
        FormalError.UnsupportedAlgorithm,
        ConstantTimeVerifier.verify(u32, noop, &inputs),
    );
    try testing.expectError(
        FormalError.UnsupportedAlgorithm,
        SideChannelVerifier.verifyCacheTimingResistance(noop, inputs),
    );
    try testing.expectError(
        FormalError.UnsupportedAlgorithm,
        PostQuantumVerifier.verifyPQSecurity("ML-KEM", 256, 128),
    );
    // Notably this used to answer "post-quantum secure" for SIKE, broken in 2022.
    try testing.expectError(
        FormalError.UnsupportedAlgorithm,
        PostQuantumVerifier.verifyPQSecurity("SIKE", 434, 128),
    );
    try testing.expectError(
        FormalError.UnsupportedAlgorithm,
        verifySecurityProperty(.post_quantum_safe, noop, inputs),
    );
    try testing.expectError(
        FormalError.UnsupportedAlgorithm,
        verifySecurityProperty(.constant_time, noop, inputs),
    );
    try testing.expectError(
        FormalError.UnsupportedAlgorithm,
        verifySecurityProperty(.perfect_secrecy, noop, inputs),
    );
}

test "memory safety ledger reconciles matched allocations" {
    var verifier = MemorySafetyVerifier.init(testing.allocator);
    defer verifier.deinit();

    const memory1 = try testing.allocator.alloc(u8, 100);
    defer testing.allocator.free(memory1);
    const memory2 = try testing.allocator.alloc(u8, 200);
    defer testing.allocator.free(memory2);

    try verifier.trackAllocation(memory1);
    try verifier.trackAllocation(memory2);
    try verifier.trackDeallocation(memory1);
    try verifier.trackDeallocation(memory2);

    const result = try verifier.verify();
    try testing.expect(result.verified);
    try testing.expect(result.property == .memory_safe);
}

test "memory safety ledger reports unfreed and repeated entries" {
    const memory = try testing.allocator.alloc(u8, 64);
    defer testing.allocator.free(memory);

    {
        // Allocated, never freed.
        var verifier = MemorySafetyVerifier.init(testing.allocator);
        defer verifier.deinit();
        try verifier.trackAllocation(memory);
        try testing.expect(!(try verifier.verify()).verified);
    }
    {
        // Freed twice.
        var verifier = MemorySafetyVerifier.init(testing.allocator);
        defer verifier.deinit();
        try verifier.trackAllocation(memory);
        try verifier.trackDeallocation(memory);
        try verifier.trackDeallocation(memory);
        try testing.expect(!(try verifier.verify()).verified);
    }
    {
        // An empty ledger reconciles vacuously, and says nothing about the program.
        var verifier = MemorySafetyVerifier.init(testing.allocator);
        defer verifier.deinit();
        try testing.expect((try verifier.verify()).verified);
    }
}

test "VerificationContext records a claim without asserting it" {
    const ctx = VerificationContext.init(.constant_time, "someFunction", "u32");
    try testing.expect(ctx.property == .constant_time);
    try testing.expect(!ctx.verified);
}
