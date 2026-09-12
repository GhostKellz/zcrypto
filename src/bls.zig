//! BLS (Boneh-Lynn-Shacham) signatures over BLS12-381 — NOT IMPLEMENTED.
//!
//! This module defines the BLS12-381 wire sizes and key/share shapes so callers
//! can parse and carry BLS material, but it performs no BLS operation. Every
//! function that would produce or check a signature returns
//! `BLSError.UnsupportedAlgorithm`.
//!
//! History: this file previously shipped hash-based stand-ins for key
//! derivation, signing, verification, aggregation, and threshold sharing. None
//! of them was BLS. `verifyBLS` in particular returned `true` for any input
//! whose compression bits were set, except messages containing the literal
//! substring "Wrong" — which existed only so the in-file negative test would
//! pass. Any caller reaching a `true` from that function was reading a forged
//! signature as valid. The stand-ins are removed rather than kept behind a
//! warning, because a warning does not stop a success-shaped return value from
//! being trusted.
//!
//! Implementing BLS12-381 requires pairing-friendly curve arithmetic that the
//! Zig standard library does not provide; supplying it is out of scope for this
//! module. Use a reviewed pairing library if you need BLS.

const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

pub const BLSError = error{
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidMessage,
    PointAtInfinity,
    PairingFailed,
    AggregationFailed,
    /// No BLS12-381 backend is available. Returned by every operation here.
    UnsupportedAlgorithm,
};

/// BLS12-381 wire sizes.
pub const BLS_PRIVATE_KEY_SIZE = 32;
pub const BLS_PUBLIC_KEY_SIZE = 48; // G1 compressed point
pub const BLS_SIGNATURE_SIZE = 96; // G2 compressed point

/// Carrier for BLS key material. Holds bytes; performs no curve operation.
pub const BLSKeyPair = struct {
    public_key: [BLS_PUBLIC_KEY_SIZE]u8,
    private_key: [BLS_PRIVATE_KEY_SIZE]u8,

    /// Always fails: no BLS backend.
    pub fn sign(self: BLSKeyPair, message: []const u8) BLSError![BLS_SIGNATURE_SIZE]u8 {
        return signBLS(message, self.private_key);
    }

    /// Always fails: no BLS backend. Never returns a verification verdict.
    pub fn verify(self: BLSKeyPair, message: []const u8, signature: [BLS_SIGNATURE_SIZE]u8) BLSError!bool {
        return verifyBLS(message, signature, self.public_key);
    }

    pub fn zeroize(self: *BLSKeyPair) void {
        crypto.secureZero(u8, &self.private_key);
    }
};

/// Always fails: deriving a G1 public key requires curve arithmetic this module
/// does not have.
pub fn generateBLS() BLSError!BLSKeyPair {
    return BLSError.UnsupportedAlgorithm;
}

/// Always fails: no BLS backend.
pub fn signBLS(message: []const u8, private_key: [BLS_PRIVATE_KEY_SIZE]u8) BLSError![BLS_SIGNATURE_SIZE]u8 {
    _ = message;
    _ = private_key;
    return BLSError.UnsupportedAlgorithm;
}

/// Always fails: no BLS backend.
///
/// Returns an error rather than `false` on purpose. A `false` would imply the
/// signature was checked and rejected; nothing here checks anything.
pub fn verifyBLS(message: []const u8, signature: [BLS_SIGNATURE_SIZE]u8, public_key: [BLS_PUBLIC_KEY_SIZE]u8) BLSError!bool {
    _ = message;
    _ = signature;
    _ = public_key;
    return BLSError.UnsupportedAlgorithm;
}

/// Always fails: aggregation is point addition on G2, which is unavailable.
pub fn aggregateSignatures(allocator: std.mem.Allocator, signatures: []const [BLS_SIGNATURE_SIZE]u8) BLSError![BLS_SIGNATURE_SIZE]u8 {
    _ = allocator;
    _ = signatures;
    return BLSError.UnsupportedAlgorithm;
}

/// Always fails: no BLS backend.
pub fn verifyAggregateSignature(messages: []const []const u8, signature: [BLS_SIGNATURE_SIZE]u8, public_keys: []const [BLS_PUBLIC_KEY_SIZE]u8) BLSError!bool {
    _ = messages;
    _ = signature;
    _ = public_keys;
    return BLSError.UnsupportedAlgorithm;
}

/// Threshold BLS. Shapes only; no operation is available.
pub const ThresholdBLS = struct {
    threshold: u32,
    total_shares: u32,

    pub const Share = struct {
        index: u32,
        private_share: [BLS_PRIVATE_KEY_SIZE]u8,
        public_share: [BLS_PUBLIC_KEY_SIZE]u8,
    };

    /// Always fails: Shamir sharing over the BLS12-381 scalar field is
    /// unavailable, and sharing a key with a hash is not secret sharing.
    pub fn generateShares(allocator: std.mem.Allocator, threshold: u32, total_shares: u32, master_key: [BLS_PRIVATE_KEY_SIZE]u8) BLSError![]Share {
        _ = allocator;
        _ = threshold;
        _ = total_shares;
        _ = master_key;
        return BLSError.UnsupportedAlgorithm;
    }

    /// Always fails: no BLS backend.
    pub fn combineSignatures(allocator: std.mem.Allocator, partial_sigs: []const struct { index: u32, signature: [BLS_SIGNATURE_SIZE]u8 }, threshold: u32) BLSError![BLS_SIGNATURE_SIZE]u8 {
        _ = allocator;
        _ = partial_sigs;
        _ = threshold;
        return BLSError.UnsupportedAlgorithm;
    }
};

/// Namespaced aliases. Same contract: every operation is unavailable.
pub const bls = struct {
    pub const KeyPair = BLSKeyPair;

    pub fn generate() BLSError!KeyPair {
        return generateBLS();
    }

    pub fn sign(message: []const u8, private_key: [BLS_PRIVATE_KEY_SIZE]u8) BLSError![BLS_SIGNATURE_SIZE]u8 {
        return signBLS(message, private_key);
    }

    pub fn verify(message: []const u8, signature: [BLS_SIGNATURE_SIZE]u8, public_key: [BLS_PUBLIC_KEY_SIZE]u8) BLSError!bool {
        return verifyBLS(message, signature, public_key);
    }

    pub fn aggregate(allocator: std.mem.Allocator, signatures: []const [BLS_SIGNATURE_SIZE]u8) BLSError![BLS_SIGNATURE_SIZE]u8 {
        return aggregateSignatures(allocator, signatures);
    }

    pub fn verifyAggregate(messages: []const []const u8, signature: [BLS_SIGNATURE_SIZE]u8, public_keys: []const [BLS_PUBLIC_KEY_SIZE]u8) BLSError!bool {
        return verifyAggregateSignature(messages, signature, public_keys);
    }
};

// Tests

test "BLS wire sizes match BLS12-381 compressed encodings" {
    // These constants are the reason the module still exists: callers parsing
    // BLS material off the wire need them even though we cannot operate on it.
    try testing.expectEqual(@as(usize, 32), BLS_PRIVATE_KEY_SIZE);
    try testing.expectEqual(@as(usize, 48), BLS_PUBLIC_KEY_SIZE);
    try testing.expectEqual(@as(usize, 96), BLS_SIGNATURE_SIZE);
}

test "every BLS operation reports itself unsupported" {
    // The point of this test is that no call below can return a success-shaped
    // value. If a real backend is ever added, these expectations must be
    // replaced with known-answer vectors, not deleted.
    const zero_priv: [BLS_PRIVATE_KEY_SIZE]u8 = @splat(0);
    const zero_pub: [BLS_PUBLIC_KEY_SIZE]u8 = @splat(0);
    const zero_sig: [BLS_SIGNATURE_SIZE]u8 = @splat(0);

    try testing.expectError(BLSError.UnsupportedAlgorithm, generateBLS());
    try testing.expectError(BLSError.UnsupportedAlgorithm, signBLS("m", zero_priv));
    try testing.expectError(BLSError.UnsupportedAlgorithm, verifyBLS("m", zero_sig, zero_pub));
    try testing.expectError(BLSError.UnsupportedAlgorithm, aggregateSignatures(testing.allocator, &.{zero_sig}));
    try testing.expectError(BLSError.UnsupportedAlgorithm, verifyAggregateSignature(&.{"m"}, zero_sig, &.{zero_pub}));
    try testing.expectError(BLSError.UnsupportedAlgorithm, ThresholdBLS.generateShares(testing.allocator, 3, 5, zero_priv));
    try testing.expectError(BLSError.UnsupportedAlgorithm, ThresholdBLS.combineSignatures(testing.allocator, &.{}, 3));
}

test "namespaced bls aliases refuse identically to the free functions" {
    // The alias namespace was a separate reachable path to the old fakes, so it
    // gets its own coverage rather than being assumed to follow.
    const zero_priv: [BLS_PRIVATE_KEY_SIZE]u8 = @splat(0);
    const zero_pub: [BLS_PUBLIC_KEY_SIZE]u8 = @splat(0);
    const zero_sig: [BLS_SIGNATURE_SIZE]u8 = @splat(0);

    try testing.expectError(BLSError.UnsupportedAlgorithm, bls.generate());
    try testing.expectError(BLSError.UnsupportedAlgorithm, bls.sign("m", zero_priv));
    try testing.expectError(BLSError.UnsupportedAlgorithm, bls.verify("m", zero_sig, zero_pub));
    try testing.expectError(BLSError.UnsupportedAlgorithm, bls.aggregate(testing.allocator, &.{zero_sig}));
    try testing.expectError(BLSError.UnsupportedAlgorithm, bls.verifyAggregate(&.{"m"}, zero_sig, &.{zero_pub}));
}

test "keypair methods refuse and zeroize still works" {
    var keypair = BLSKeyPair{
        .public_key = @splat(0xAA),
        .private_key = @splat(0xBB),
    };
    const zero_sig: [BLS_SIGNATURE_SIZE]u8 = @splat(0);

    try testing.expectError(BLSError.UnsupportedAlgorithm, keypair.sign("m"));
    try testing.expectError(BLSError.UnsupportedAlgorithm, keypair.verify("m", zero_sig));

    keypair.zeroize();
    try testing.expect(std.mem.allEqual(u8, &keypair.private_key, 0));
}
