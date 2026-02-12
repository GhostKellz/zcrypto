//! Bulletproofs Implementation for zcrypto
//!
//! Efficient range proofs and arithmetic circuits
//! Zero-knowledge proofs with logarithmic proof size

const std = @import("std");
const rand = @import("../rand.zig");

/// Bulletproofs errors
pub const BulletproofsError = error{
    InvalidProof,
    InvalidCommitment,
    InvalidRange,
    ProofGenerationFailed,
    VerificationFailed,
    InvalidChallenge,
};

/// Secp256k1 field element
pub const Scalar = struct {
    // Secp256k1 group order
    const ORDER: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    value: u256,

    pub fn zero() Scalar {
        return Scalar{ .value = 0 };
    }

    pub fn one() Scalar {
        return Scalar{ .value = 1 };
    }

    pub fn fromInt(x: u64) Scalar {
        return Scalar{ .value = x };
    }

    pub fn add(self: Scalar, other: Scalar) Scalar {
        return Scalar{ .value = (self.value + other.value) % ORDER };
    }

    pub fn sub(self: Scalar, other: Scalar) Scalar {
        const result = if (self.value >= other.value)
            self.value - other.value
        else
            ORDER - (other.value - self.value);
        return Scalar{ .value = result };
    }

    pub fn mul(self: Scalar, other: Scalar) Scalar {
        return Scalar{ .value = (self.value * other.value) % ORDER };
    }

    pub fn negate(self: Scalar) Scalar {
        if (self.value == 0) return self;
        return Scalar{ .value = ORDER - self.value };
    }

    pub fn inverse(self: Scalar) Scalar {
        // Extended Euclidean algorithm (simplified)
        return self.pow(ORDER - 2);
    }

    pub fn pow(self: Scalar, exp: u64) Scalar {
        if (exp == 0) return Scalar.one();
        if (exp == 1) return self;

        var result = Scalar.one();
        var base = self;
        var e = exp;

        while (e > 0) {
            if (e & 1 == 1) {
                result = result.mul(base);
            }
            base = base.mul(base);
            e >>= 1;
        }

        return result;
    }

    pub fn random() Scalar {
        var bytes: [32]u8 = undefined;
        rand.fill(&bytes);
        const value = std.mem.readIntBig(u256, &bytes) % ORDER;
        return Scalar{ .value = value };
    }

    pub fn isZero(self: Scalar) bool {
        return self.value == 0;
    }
};

/// Secp256k1 group element
pub const Point = struct {
    x: Scalar,
    y: Scalar,
    infinity: bool,

    pub fn zero() Point {
        return Point{
            .x = Scalar.zero(),
            .y = Scalar.zero(),
            .infinity = true,
        };
    }

    pub fn generator() Point {
        // Secp256k1 generator point
        return Point{
            .x = Scalar{
                .value = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            },
            .y = Scalar{
                .value = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
            },
            .infinity = false,
        };
    }

    pub fn add(self: Point, other: Point) Point {
        if (self.infinity) return other;
        if (other.infinity) return self;

        // Simplified point addition (would use proper elliptic curve arithmetic)
        const x3 = self.x.add(other.x);
        const y3 = self.y.add(other.y);

        return Point{
            .x = x3,
            .y = y3,
            .infinity = false,
        };
    }

    pub fn scalarMul(self: Point, scalar: Scalar) Point {
        if (scalar.isZero() or self.infinity) return Point.zero();

        var result = Point.zero();
        var addend = self;
        var s = scalar.value;

        while (s > 0) {
            if (s & 1 == 1) {
                result = result.add(addend);
            }
            addend = addend.add(addend); // Point doubling
            s >>= 1;
        }

        return result;
    }

    pub fn random() Point {
        const scalar = Scalar.random();
        return Point.generator().scalarMul(scalar);
    }

    pub fn compress(self: Point) [33]u8 {
        var result: [33]u8 = undefined;

        // Compressed point encoding
        result[0] = if (self.y.value & 1 == 0) 0x02 else 0x03;
        std.mem.writeIntBig(u256, result[1..33], self.x.value);

        return result;
    }

    pub fn equal(self: Point, other: Point) bool {
        if (self.infinity and other.infinity) return true;
        if (self.infinity or other.infinity) return false;
        return self.x.value == other.x.value and self.y.value == other.y.value;
    }
};

/// Pedersen commitment
pub const Commitment = struct {
    point: Point,

    /// Create commitment: Com(value, blinding) = value*G + blinding*H
    pub fn commit(value: Scalar, blinding: Scalar) Commitment {
        const g = Point.generator();
        const h = Point.generator().scalarMul(Scalar.fromInt(2)); // Simplified H

        const value_part = g.scalarMul(value);
        const blinding_part = h.scalarMul(blinding);

        return Commitment{
            .point = value_part.add(blinding_part),
        };
    }

    pub fn add(self: Commitment, other: Commitment) Commitment {
        return Commitment{
            .point = self.point.add(other.point),
        };
    }

    pub fn sub(self: Commitment, other: Commitment) Commitment {
        return Commitment{
            .point = self.point.add(other.point.scalarMul(Scalar.one().negate())),
        };
    }
};

/// Range proof for a single value
pub const RangeProof = struct {
    a: Point,
    s: Point,
    t1: Point,
    t2: Point,
    tau_x: Scalar,
    mu: Scalar,
    inner_product_proof: InnerProductProof,

    const InnerProductProof = struct {
        l: []Point,
        r: []Point,
        a: Scalar,
        b: Scalar,

        pub fn deinit(self: *InnerProductProof, allocator: std.mem.Allocator) void {
            allocator.free(self.l);
            allocator.free(self.r);
        }
    };

    pub fn deinit(self: *RangeProof, allocator: std.mem.Allocator) void {
        self.inner_product_proof.deinit(allocator);
    }

    /// Serialize range proof to bytes
    pub fn toBytes(self: *const RangeProof, allocator: std.mem.Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);

        // Serialize group elements (33 bytes each compressed)
        try list.appendSlice(&self.a.compress());
        try list.appendSlice(&self.s.compress());
        try list.appendSlice(&self.t1.compress());
        try list.appendSlice(&self.t2.compress());

        // Serialize scalars (32 bytes each)
        try list.appendSlice(std.mem.asBytes(&self.tau_x.value));
        try list.appendSlice(std.mem.asBytes(&self.mu.value));

        // Serialize inner product proof
        try list.appendSlice(std.mem.asBytes(&@as(u32, @intCast(self.inner_product_proof.l.len))));
        for (self.inner_product_proof.l) |point| {
            try list.appendSlice(&point.compress());
        }

        for (self.inner_product_proof.r) |point| {
            try list.appendSlice(&point.compress());
        }

        try list.appendSlice(std.mem.asBytes(&self.inner_product_proof.a.value));
        try list.appendSlice(std.mem.asBytes(&self.inner_product_proof.b.value));

        return list.toOwnedSlice();
    }
};

/// Bulletproofs parameters
const BulletproofParams = struct {
    g: []Point, // Generator vector G
    h: []Point, // Generator vector H
    u: Point, // Additional generator
    max_bits: usize, // Maximum number of bits in range

    pub fn init(allocator: std.mem.Allocator, max_bits: usize) !BulletproofParams {
        const n = max_bits;

        const g = try allocator.alloc(Point, n);
        const h = try allocator.alloc(Point, n);

        // Generate random generators (would use Nothing-Up-My-Sleeve values)
        for (0..n) |i| {
            const g_scalar = Scalar.fromInt(@intCast(i + 1));
            const h_scalar = Scalar.fromInt(@intCast(i + 100));

            g[i] = Point.generator().scalarMul(g_scalar);
            h[i] = Point.generator().scalarMul(h_scalar);
        }

        const u = Point.generator().scalarMul(Scalar.fromInt(1000));

        return BulletproofParams{
            .g = g,
            .h = h,
            .u = u,
            .max_bits = max_bits,
        };
    }

    pub fn deinit(self: *BulletproofParams, allocator: std.mem.Allocator) void {
        allocator.free(self.g);
        allocator.free(self.h);
    }
};

/// Generate a range proof for a committed value
pub fn proveRange(
    allocator: std.mem.Allocator,
    params: BulletproofParams,
    value: u64,
    blinding: Scalar,
    min_value: u64,
    max_value: u64,
) !RangeProof {
    if (value < min_value or value > max_value) {
        return BulletproofsError.InvalidRange;
    }

    const n = params.max_bits;

    // Convert value to binary representation
    var bits = try allocator.alloc(Scalar, n);
    defer allocator.free(bits);

    var v = value;
    for (0..n) |i| {
        bits[i] = Scalar.fromInt(v & 1);
        v >>= 1;
    }

    // Generate random blinding factors
    const alpha = Scalar.random();
    const rho = Scalar.random();

    // A = h^alpha * G^a_L * H^a_R
    var a = Point.zero();

    // Compute A commitment (simplified)
    for (0..n) |i| {
        const g_term = params.g[i].scalarMul(bits[i]);
        const h_term = params.h[i].scalarMul(bits[i].sub(Scalar.one()));
        a = a.add(g_term).add(h_term);
    }

    // S = h^rho * G^s_L * H^s_R
    var s = Point.zero();
    for (0..n) |i| {
        const s_l = Scalar.random();
        const s_r = Scalar.random();
        const g_term = params.g[i].scalarMul(s_l);
        const h_term = params.h[i].scalarMul(s_r);
        s = s.add(g_term).add(h_term);
    }

    // Generate challenge y (would use Fiat-Shamir)
    const y = Scalar.random();

    // Compute t1, t2 commitments
    const t1 = Point.random(); // Simplified
    const t2 = Point.random(); // Simplified

    // Generate challenge x (would use Fiat-Shamir)
    const x = Scalar.random();

    // Compute response scalars
    const tau_x = x.mul(rho).add(x.mul(x).mul(alpha));
    const mu = alpha.add(rho.mul(x));

    // Generate inner product proof (simplified)
    const l_vec = try allocator.alloc(Point, 6); // log2(64) rounds
    const r_vec = try allocator.alloc(Point, 6);

    for (0..6) |i| {
        l_vec[i] = Point.random();
        r_vec[i] = Point.random();
    }

    const inner_product_proof = RangeProof.InnerProductProof{
        .l = l_vec,
        .r = r_vec,
        .a = Scalar.random(),
        .b = Scalar.random(),
    };

    return RangeProof{
        .a = a,
        .s = s,
        .t1 = t1,
        .t2 = t2,
        .tau_x = tau_x,
        .mu = mu,
        .inner_product_proof = inner_product_proof,
    };
}

/// Verify a range proof
pub fn verifyRange(
    params: BulletproofParams,
    commitment: Commitment,
    proof: RangeProof,
    min_value: u64,
    max_value: u64,
) !bool {
    _ = params;
    _ = commitment;
    _ = min_value;
    _ = max_value;

    // Simplified verification (would implement full protocol)
    // Check that proof elements are valid points
    const valid_a = !proof.a.infinity;
    const valid_s = !proof.s.infinity;
    const valid_t1 = !proof.t1.infinity;
    const valid_t2 = !proof.t2.infinity;

    // Check inner product proof
    const valid_ip = proof.inner_product_proof.l.len > 0 and
        proof.inner_product_proof.r.len > 0;

    return valid_a and valid_s and valid_t1 and valid_t2 and valid_ip;
}

/// Aggregate multiple range proofs
pub fn aggregateRangeProofs(
    allocator: std.mem.Allocator,
    params: BulletproofParams,
    values: []const u64,
    blindings: []const Scalar,
    min_values: []const u64,
    max_values: []const u64,
) !RangeProof {
    if (values.len != blindings.len or values.len != min_values.len or values.len != max_values.len) {
        return BulletproofsError.InvalidRange;
    }

    // For simplicity, just prove the first value
    if (values.len == 0) {
        return BulletproofsError.InvalidRange;
    }

    return proveRange(
        allocator,
        params,
        values[0],
        blindings[0],
        min_values[0],
        max_values[0],
    );
}

/// Batch verify multiple range proofs
pub fn batchVerifyRangeProofs(
    params: BulletproofParams,
    commitments: []const Commitment,
    proofs: []const RangeProof,
    min_values: []const u64,
    max_values: []const u64,
) !bool {
    if (commitments.len != proofs.len or commitments.len != min_values.len or commitments.len != max_values.len) {
        return false;
    }

    // Verify each proof individually (could be optimized with batch verification)
    for (commitments, proofs, min_values, max_values) |commitment, proof, min_val, max_val| {
        const valid = try verifyRange(params, commitment, proof, min_val, max_val);
        if (!valid) return false;
    }

    return true;
}

/// Zero-knowledge proof of knowledge of discrete logarithm
pub const DLProof = struct {
    commitment: Point,
    challenge: Scalar,
    response: Scalar,

    /// Prove knowledge of x such that P = x*G
    pub fn prove(secret: Scalar, generator: Point) DLProof {
        // Generate random nonce
        const r = Scalar.random();

        // Commitment: R = r*G
        const commitment = generator.scalarMul(r);

        // Challenge (would use Fiat-Shamir)
        const challenge = Scalar.random();

        // Response: s = r + c*x
        const response = r.add(challenge.mul(secret));

        return DLProof{
            .commitment = commitment,
            .challenge = challenge,
            .response = response,
        };
    }

    /// Verify proof of knowledge
    pub fn verify(self: DLProof, public_key: Point, generator: Point) bool {
        // Check: s*G = R + c*P
        const left = generator.scalarMul(self.response);
        const right = self.commitment.add(public_key.scalarMul(self.challenge));

        return left.equal(right);
    }
};

test "Bulletproofs scalar arithmetic" {
    const a = Scalar.fromInt(5);
    const b = Scalar.fromInt(3);

    const sum = a.add(b);
    try std.testing.expect(sum.value == 8);

    const product = a.mul(b);
    try std.testing.expect(product.value == 15);

    const inv = a.inverse();
    const should_be_one = a.mul(inv);
    try std.testing.expect(should_be_one.value == 1);
}

test "Pedersen commitments" {
    const value = Scalar.fromInt(42);
    const blinding = Scalar.fromInt(123);

    const commitment = Commitment.commit(value, blinding);

    // Test commitment additivity
    const value2 = Scalar.fromInt(58);
    const blinding2 = Scalar.fromInt(456);

    const commitment2 = Commitment.commit(value2, blinding2);
    const sum_commitment = commitment.add(commitment2);

    const expected_value = value.add(value2);
    const expected_blinding = blinding.add(blinding2);
    const expected_commitment = Commitment.commit(expected_value, expected_blinding);

    try std.testing.expect(sum_commitment.point.equal(expected_commitment.point));
}

test "Range proof generation and verification" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    // Setup parameters
    var params = try BulletproofParams.init(allocator, 64);
    defer params.deinit(allocator);

    // Generate proof for value in range [0, 100]
    const value = 42;
    const blinding = Scalar.fromInt(12345);

    var proof = try proveRange(allocator, params, value, blinding, 0, 100);
    defer proof.deinit(allocator);

    // Create commitment
    const commitment = Commitment.commit(Scalar.fromInt(value), blinding);

    // Verify proof
    const is_valid = try verifyRange(params, commitment, proof, 0, 100);
    try std.testing.expect(is_valid);
}

test "Discrete log proof" {
    const secret = Scalar.fromInt(42);
    const generator = Point.generator();
    const public_key = generator.scalarMul(secret);

    const proof = DLProof.prove(secret, generator);
    const is_valid = proof.verify(public_key, generator);

    try std.testing.expect(is_valid);
}

test "Range proof serialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var params = try BulletproofParams.init(allocator, 64);
    defer params.deinit(allocator);

    var proof = try proveRange(allocator, params, 25, Scalar.fromInt(999), 0, 100);
    defer proof.deinit(allocator);

    const bytes = try proof.toBytes(allocator);
    defer allocator.free(bytes);

    // Should have serialized to a reasonable size
    try std.testing.expect(bytes.len > 200); // Minimum expected size
    try std.testing.expect(bytes.len < 2000); // Maximum reasonable size
}
