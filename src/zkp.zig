//! Zero-knowledge proofs — Bulletproofs, Groth16 zk-SNARKs, zk-STARKs —
//! NOT IMPLEMENTED.
//!
//! This module defines the proof, key, and circuit shapes so callers can carry
//! and free ZK material, but it performs no proof operation. Every function that
//! would produce or check a proof returns `ZKError.UnsupportedAlgorithm`.
//!
//! History: this file previously shipped hash-based stand-ins for all three
//! systems. None of them was a proof system:
//!
//!   * `Bulletproofs.verifyRange` discarded the commitment, the range bounds and
//!     the generators, computed Fiat-Shamir challenges it never compared against
//!     anything, and ended in `return true`. Its own test passed a *random*
//!     commitment unrelated to the proof and asserted the result was valid —
//!     which is precisely the check a range proof exists to fail.
//!   * `Groth16.verify` compared two SHA-256 digests taken over disjoint inputs,
//!     under a comment noting that a real implementation "would use bilinear
//!     pairings". There was no pairing and no trusted setup; `setup` sampled
//!     random bytes.
//!   * `STARKs.verify` discarded the public inputs and constraints and gated on
//!     two helpers that could not fail: `verifyMerklePath` ignored all four of
//!     its arguments and returned `true`, and `verifyFRIProof` returned `true`
//!     for any structurally non-empty proof. It then returned `true`.
//!
//! Every one of those was a success-shaped return that a caller would read as
//! "this proof is valid". They are removed rather than kept behind a warning,
//! because a warning does not stop a `true` from being trusted. The prover
//! halves are removed too: a proof that proves nothing is as dangerous as a
//! verifier that checks nothing, since a caller would publish it believing it
//! carried a zero-knowledge guarantee.
//!
//! Implementing any of these requires pairing-friendly or prime-order curve
//! arithmetic and polynomial commitment machinery that the Zig standard library
//! does not provide. Use a reviewed proving library if you need it.

const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

pub const ZKError = error{
    InvalidProof,
    InvalidWitness,
    InvalidPublicInput,
    ProofGenerationFailed,
    VerificationFailed,
    InvalidCircuit,
    InvalidCommitment,
    InsufficientRandomness,
    /// No proof system backend is available. Returned by every operation here.
    UnsupportedAlgorithm,
};

/// Bulletproofs range proofs. Shapes only; no operation is available.
pub const Bulletproofs = struct {
    /// Order of the secp256k1 group. Retained as an inert constant for callers
    /// parsing external proof material; nothing in this module uses it.
    pub const CURVE_ORDER = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    pub const GENERATOR_SIZE = 64; // Number of generators for a vector commitment

    pub const RangeProof = struct {
        a: [32]u8, // Commitment to aL and aR
        s: [32]u8, // Commitment to sL and sR
        t1: [32]u8, // Commitment to t1
        t2: [32]u8, // Commitment to t2
        tau_x: [32]u8, // Blinding factor for t
        mu: [32]u8, // Blinding factor for inner product
        ipproof: InnerProductProof,

        pub const InnerProductProof = struct {
            l: [][32]u8, // Left vector commitments
            r: [][32]u8, // Right vector commitments
            a: [32]u8, // Final inner product value
            b: [32]u8, // Final inner product value
        };
    };

    /// Generator carrier.
    ///
    /// The entries are SHA-256 outputs, not curve points: this module has no
    /// curve, so it cannot hash to one. They are domain-separated deterministic
    /// bytes and nothing more. Kept because the allocation contract is real even
    /// though no operation consumes them.
    pub const Generators = struct {
        g: [][32]u8,
        h: [][32]u8,
        u: [32]u8,

        pub fn init(allocator: std.mem.Allocator, size: usize) !Generators {
            const g = try allocator.alloc([32]u8, size);
            errdefer allocator.free(g);
            const h = try allocator.alloc([32]u8, size);
            errdefer allocator.free(h);

            for (g, 0..) |*gen, i| {
                var input: [8]u8 = undefined;
                std.mem.writeInt(u64, &input, i, .little);
                crypto.hash.sha2.Sha256.hash(&input, gen, .{});
            }

            for (h, 0..) |*gen, i| {
                var input: [8]u8 = undefined;
                std.mem.writeInt(u64, &input, i + size, .little);
                crypto.hash.sha2.Sha256.hash(&input, gen, .{});
            }

            var u: [32]u8 = undefined;
            crypto.hash.sha2.Sha256.hash("bulletproof_challenge_generator", &u, .{});

            return Generators{ .g = g, .h = h, .u = u };
        }

        pub fn deinit(self: *Generators, allocator: std.mem.Allocator) void {
            allocator.free(self.g);
            allocator.free(self.h);
        }
    };

    /// Always fails: producing a range proof requires group arithmetic and a
    /// polynomial commitment scheme this module does not have.
    pub fn proveRange(allocator: std.mem.Allocator, value: u64, blinding: [32]u8, min_value: u64, max_value: u64, generators: *const Generators) ZKError!RangeProof {
        _ = allocator;
        _ = value;
        _ = blinding;
        _ = min_value;
        _ = max_value;
        _ = generators;
        return ZKError.UnsupportedAlgorithm;
    }

    /// Always fails: no Bulletproofs backend. Never returns a verification
    /// verdict.
    ///
    /// Returns an error rather than `false` on purpose. A `false` would imply
    /// the proof was checked and rejected; nothing here checks anything.
    pub fn verifyRange(commitment: [32]u8, min_value: u64, max_value: u64, proof: RangeProof, generators: *const Generators) ZKError!bool {
        _ = commitment;
        _ = min_value;
        _ = max_value;
        _ = proof;
        _ = generators;
        return ZKError.UnsupportedAlgorithm;
    }

    /// Free a `RangeProof`'s inner-product vectors.
    ///
    /// No operation here can produce a `RangeProof`, so this only applies to
    /// proofs a caller allocated itself.
    pub fn deinitProof(allocator: std.mem.Allocator, proof: *RangeProof) void {
        allocator.free(proof.ipproof.l);
        allocator.free(proof.ipproof.r);
    }
};

/// Groth16 zk-SNARKs. Shapes only; no operation is available.
pub const Groth16 = struct {
    pub const ProvingKey = struct {
        alpha: [32]u8,
        beta: [32]u8,
        delta: [32]u8,
        ic: [][32]u8, // Input commitments
        l: [][32]u8, // Left wire commitments
        r: [][32]u8, // Right wire commitments
        o: [][32]u8, // Output wire commitments
        h: [][32]u8, // H query

        pub fn deinit(self: *ProvingKey, allocator: std.mem.Allocator) void {
            allocator.free(self.ic);
            allocator.free(self.l);
            allocator.free(self.r);
            allocator.free(self.o);
            allocator.free(self.h);
        }
    };

    pub const VerifyingKey = struct {
        alpha: [32]u8,
        beta: [32]u8,
        gamma: [32]u8,
        delta: [32]u8,
        ic: [][32]u8, // Input commitments

        pub fn deinit(self: *VerifyingKey, allocator: std.mem.Allocator) void {
            allocator.free(self.ic);
        }
    };

    pub const Proof = struct {
        a: [32]u8, // Proof element A
        b: [64]u8, // Proof element B (G2 point, hence 64 bytes)
        c: [32]u8, // Proof element C
    };

    pub const Circuit = struct {
        num_inputs: usize,
        num_aux: usize,
        num_constraints: usize,
        constraints: []Constraint,

        pub const Constraint = struct {
            a: []Variable,
            b: []Variable,
            c: []Variable,

            pub const Variable = struct {
                index: usize,
                coefficient: [32]u8,
            };
        };

        pub fn deinit(self: *Circuit, allocator: std.mem.Allocator) void {
            for (self.constraints) |*constraint| {
                allocator.free(constraint.a);
                allocator.free(constraint.b);
                allocator.free(constraint.c);
            }
            allocator.free(self.constraints);
        }
    };

    /// Always fails: Groth16 requires a trusted setup ceremony over a
    /// pairing-friendly curve. Sampling random bytes, as this used to do, is not
    /// one — it produces keys that bind to nothing.
    pub fn setup(allocator: std.mem.Allocator, circuit: *const Circuit) ZKError!struct { pk: ProvingKey, vk: VerifyingKey } {
        _ = allocator;
        _ = circuit;
        return ZKError.UnsupportedAlgorithm;
    }

    /// Always fails: no Groth16 backend.
    pub fn prove(allocator: std.mem.Allocator, pk: *const ProvingKey, circuit: *const Circuit, inputs: []const [32]u8, witness: []const [32]u8) ZKError!Proof {
        _ = allocator;
        _ = pk;
        _ = circuit;
        _ = inputs;
        _ = witness;
        return ZKError.UnsupportedAlgorithm;
    }

    /// Always fails: verification is a pairing check, which is unavailable.
    /// Never returns a verification verdict.
    pub fn verify(vk: *const VerifyingKey, inputs: []const [32]u8, proof: Proof) ZKError!bool {
        _ = vk;
        _ = inputs;
        _ = proof;
        return ZKError.UnsupportedAlgorithm;
    }
};

/// zk-STARKs. Shapes only; no operation is available.
pub const STARKs = struct {
    pub const FRI_DOMAIN_SIZE = 1024;
    pub const NUM_QUERIES = 40;

    pub const Proof = struct {
        merkle_root: [32]u8,
        fri_proof: FRIProof,
        query_responses: []QueryResponse,

        pub const FRIProof = struct {
            commitments: [][32]u8,
            final_polynomial: [][32]u8,
            query_proofs: []QueryProof,

            pub const QueryProof = struct {
                path: [][32]u8,
                values: [][32]u8,
            };
        };

        pub const QueryResponse = struct {
            index: usize,
            value: [32]u8,
            merkle_path: [][32]u8,
        };

        pub fn deinit(self: *Proof, allocator: std.mem.Allocator) void {
            allocator.free(self.fri_proof.commitments);
            allocator.free(self.fri_proof.final_polynomial);
            for (self.fri_proof.query_proofs) |*qp| {
                allocator.free(qp.path);
                allocator.free(qp.values);
            }
            allocator.free(self.fri_proof.query_proofs);

            for (self.query_responses) |*qr| {
                allocator.free(qr.merkle_path);
            }
            allocator.free(self.query_responses);
        }
    };

    pub const ExecutionTrace = struct {
        width: usize,
        height: usize,
        data: [][]const [32]u8,

        pub fn deinit(self: *ExecutionTrace, allocator: std.mem.Allocator) void {
            for (self.data) |row| {
                allocator.free(row);
            }
            allocator.free(self.data);
        }
    };

    /// Always fails: a STARK prover needs a low-degree extension over a finite
    /// field with FRI commitments. Zero-padding a trace with random bytes, as
    /// this used to do, commits to nothing.
    pub fn prove(allocator: std.mem.Allocator, trace: *const ExecutionTrace, constraints: []const []const u8) ZKError!Proof {
        _ = allocator;
        _ = trace;
        _ = constraints;
        return ZKError.UnsupportedAlgorithm;
    }

    /// Always fails: no STARK backend. Never returns a verification verdict.
    pub fn verify(allocator: std.mem.Allocator, proof: *const Proof, public_inputs: []const [32]u8, constraints: []const []const u8) ZKError!bool {
        _ = allocator;
        _ = proof;
        _ = public_inputs;
        _ = constraints;
        return ZKError.UnsupportedAlgorithm;
    }
};

// Tests

test "Bulletproofs operations report themselves unsupported" {
    // If a real backend is ever added, these expectations must be replaced with
    // known-answer vectors, not deleted.
    const allocator = testing.allocator;

    var generators = try Bulletproofs.Generators.init(allocator, 64);
    defer generators.deinit(allocator);

    const blinding: [32]u8 = @splat(0xAB);
    try testing.expectError(
        ZKError.UnsupportedAlgorithm,
        Bulletproofs.proveRange(allocator, 42, blinding, 0, 100, &generators),
    );

    // The old verifier returned true here even though the commitment is
    // unrelated to the proof — the exact soundness failure this guards.
    const commitment: [32]u8 = @splat(0xCD);
    const empty: [][32]u8 = &.{};
    const proof = Bulletproofs.RangeProof{
        .a = @splat(0),
        .s = @splat(0),
        .t1 = @splat(0),
        .t2 = @splat(0),
        .tau_x = @splat(0),
        .mu = @splat(0),
        .ipproof = .{ .l = empty, .r = empty, .a = @splat(0), .b = @splat(0) },
    };
    try testing.expectError(
        ZKError.UnsupportedAlgorithm,
        Bulletproofs.verifyRange(commitment, 0, 100, proof, &generators),
    );
}

test "Bulletproofs generators own and release their allocations" {
    // Guards the allocation contract that survives even though no operation
    // consumes a Generators value; testing.allocator fails the test on a leak.
    const allocator = testing.allocator;

    var generators = try Bulletproofs.Generators.init(allocator, 8);
    try testing.expectEqual(@as(usize, 8), generators.g.len);
    try testing.expectEqual(@as(usize, 8), generators.h.len);
    // g and h are separately domain-separated, so they must not coincide.
    try testing.expect(!std.mem.eql(u8, &generators.g[0], &generators.h[0]));
    generators.deinit(allocator);
}

test "Groth16 operations report themselves unsupported" {
    const allocator = testing.allocator;
    const empty: [][32]u8 = &.{};

    var circuit = Groth16.Circuit{
        .num_inputs = 1,
        .num_aux = 0,
        .num_constraints = 0,
        .constraints = &.{},
    };
    try testing.expectError(ZKError.UnsupportedAlgorithm, Groth16.setup(allocator, &circuit));

    const pk = Groth16.ProvingKey{
        .alpha = @splat(0),
        .beta = @splat(0),
        .delta = @splat(0),
        .ic = empty,
        .l = empty,
        .r = empty,
        .o = empty,
        .h = empty,
    };
    const vk = Groth16.VerifyingKey{
        .alpha = @splat(0),
        .beta = @splat(0),
        .gamma = @splat(0),
        .delta = @splat(0),
        .ic = empty,
    };
    const inputs = [_][32]u8{@splat(1)};
    const proof = Groth16.Proof{ .a = @splat(0), .b = @splat(0), .c = @splat(0) };

    try testing.expectError(
        ZKError.UnsupportedAlgorithm,
        Groth16.prove(allocator, &pk, &circuit, &inputs, &.{}),
    );
    try testing.expectError(ZKError.UnsupportedAlgorithm, Groth16.verify(&vk, &inputs, proof));
}

test "STARKs operations report themselves unsupported" {
    const allocator = testing.allocator;

    var trace = STARKs.ExecutionTrace{ .width = 0, .height = 0, .data = &.{} };
    const constraints = [_][]const u8{"x * y = z"};

    try testing.expectError(
        ZKError.UnsupportedAlgorithm,
        STARKs.prove(allocator, &trace, &constraints),
    );

    // The old verifier gated on two helpers that could not fail, so a proof of
    // random bytes like this one verified as valid.
    const empty: [][32]u8 = &.{};
    const proof = STARKs.Proof{
        .merkle_root = @splat(0xEF),
        .fri_proof = .{
            .commitments = empty,
            .final_polynomial = empty,
            .query_proofs = &.{},
        },
        .query_responses = &.{},
    };
    const public_inputs = [_][32]u8{@splat(42)};
    try testing.expectError(
        ZKError.UnsupportedAlgorithm,
        STARKs.verify(allocator, &proof, &public_inputs, &constraints),
    );
}
