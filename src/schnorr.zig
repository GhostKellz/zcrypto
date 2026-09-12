//! Schnorr signatures over secp256k1 (BIP340), MuSig2, adaptor signatures —
//! NOT IMPLEMENTED.
//!
//! This module defines the BIP340 wire sizes and the key/nonce/context shapes so
//! callers can parse and carry Schnorr material, but it performs no signature
//! operation. Every function that would produce or check a signature returns
//! `SchnorrError.UnsupportedAlgorithm`.
//!
//! History: this file previously shipped hash-based stand-ins for BIP340
//! signing and verification, MuSig2 key/nonce/partial-signature aggregation, and
//! adaptor signatures. None of them performed secp256k1 arithmetic.
//! `verifySchnorr` discarded the public key entirely and returned `true` for any
//! signature whose halves were non-zero, except messages containing the literal
//! substring "Wrong" — which existed only so the in-file negative test would
//! pass. Any caller reaching a `true` from that function was reading a forged
//! signature as valid. The stand-ins are removed rather than kept behind a
//! warning, because a warning does not stop a success-shaped return value from
//! being trusted.
//!
//! Restoring these operations means implementing BIP340 over secp256k1 with its
//! x-only key encoding, nonce derivation, and even-Y convention, which is out of
//! scope for this module. Use a reviewed BIP340 implementation if you need it.

const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

pub const SchnorrError = error{
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidNonce,
    InvalidChallenge,
    AggregationFailed,
    /// No BIP340/secp256k1 backend is available. Returned by every operation here.
    UnsupportedAlgorithm,
};

/// BIP340 wire sizes.
pub const SCHNORR_PRIVATE_KEY_SIZE = 32;
pub const SCHNORR_PUBLIC_KEY_SIZE = 32; // X-coordinate only (BIP340)
pub const SCHNORR_SIGNATURE_SIZE = 64; // (r, s)

/// Carrier for Schnorr key material. Holds bytes; performs no curve operation.
pub const SchnorrKeyPair = struct {
    public_key: [SCHNORR_PUBLIC_KEY_SIZE]u8,
    private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8,

    /// Always fails: no BIP340 backend.
    pub fn sign(self: SchnorrKeyPair, message: []const u8) SchnorrError![SCHNORR_SIGNATURE_SIZE]u8 {
        return signSchnorr(message, self.private_key);
    }

    /// Always fails: no BIP340 backend. Never returns a verification verdict.
    pub fn verify(self: SchnorrKeyPair, message: []const u8, signature: [SCHNORR_SIGNATURE_SIZE]u8) SchnorrError!bool {
        return verifySchnorr(message, signature, self.public_key);
    }

    pub fn zeroize(self: *SchnorrKeyPair) void {
        crypto.secureZero(u8, &self.private_key);
    }
};

/// Always fails: deriving an x-only public key requires secp256k1 scalar
/// multiplication this module does not have.
pub fn generateSchnorr() SchnorrError!SchnorrKeyPair {
    return SchnorrError.UnsupportedAlgorithm;
}

/// Always fails: no BIP340 backend.
pub fn signSchnorr(message: []const u8, private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8) SchnorrError![SCHNORR_SIGNATURE_SIZE]u8 {
    _ = message;
    _ = private_key;
    return SchnorrError.UnsupportedAlgorithm;
}

/// Always fails: no BIP340 backend.
///
/// Returns an error rather than `false` on purpose. A `false` would imply the
/// signature was checked and rejected; nothing here checks anything.
pub fn verifySchnorr(message: []const u8, signature: [SCHNORR_SIGNATURE_SIZE]u8, public_key: [SCHNORR_PUBLIC_KEY_SIZE]u8) SchnorrError!bool {
    _ = message;
    _ = signature;
    _ = public_key;
    return SchnorrError.UnsupportedAlgorithm;
}

/// MuSig2 multi-signatures. Shapes only; no operation is available.
pub const MuSig2 = struct {
    pub const KeyAggContext = struct {
        aggregate_pubkey: [SCHNORR_PUBLIC_KEY_SIZE]u8,
        key_agg_coeff: [][32]u8,

        pub fn deinit(self: *KeyAggContext, allocator: std.mem.Allocator) void {
            allocator.free(self.key_agg_coeff);
        }
    };

    pub const Nonce = struct {
        r1: [32]u8,
        r2: [32]u8,
        public_nonce: [64]u8,
    };

    /// Always fails: aggregating x-only keys is point addition, not hashing.
    pub fn keyAggregate(allocator: std.mem.Allocator, public_keys: []const [SCHNORR_PUBLIC_KEY_SIZE]u8) SchnorrError!KeyAggContext {
        _ = allocator;
        _ = public_keys;
        return SchnorrError.UnsupportedAlgorithm;
    }

    /// Always fails: MuSig2 nonces are curve points and must pair with a real
    /// signing round; returning bytes here would invite nonce reuse.
    pub fn nonceGen(session_id: [32]u8, private_key: ?[SCHNORR_PRIVATE_KEY_SIZE]u8, message: []const u8, extra_input: ?[]const u8) SchnorrError!Nonce {
        _ = session_id;
        _ = private_key;
        _ = message;
        _ = extra_input;
        return SchnorrError.UnsupportedAlgorithm;
    }

    /// Always fails: no BIP340 backend.
    pub fn nonceAggregate(public_nonces: []const [64]u8) SchnorrError![66]u8 {
        _ = public_nonces;
        return SchnorrError.UnsupportedAlgorithm;
    }

    /// Always fails: no BIP340 backend.
    pub fn partialSign(message: []const u8, private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8, nonce: Nonce, agg_nonce: [66]u8, key_agg_ctx: KeyAggContext) SchnorrError![32]u8 {
        _ = message;
        _ = private_key;
        _ = nonce;
        _ = agg_nonce;
        _ = key_agg_ctx;
        return SchnorrError.UnsupportedAlgorithm;
    }

    /// Always fails: no BIP340 backend.
    pub fn partialSigAggregate(partial_sigs: []const [32]u8, agg_nonce: [66]u8) SchnorrError![SCHNORR_SIGNATURE_SIZE]u8 {
        _ = partial_sigs;
        _ = agg_nonce;
        return SchnorrError.UnsupportedAlgorithm;
    }
};

/// Adaptor signatures. Shapes only; no operation is available.
pub const AdaptorSignature = struct {
    r: [32]u8,
    s_adaptor: [32]u8,
    adaptor_point: [32]u8,

    /// Always fails: no BIP340 backend.
    pub fn create(message: []const u8, private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8, adaptor_point: [32]u8) SchnorrError!AdaptorSignature {
        _ = message;
        _ = private_key;
        _ = adaptor_point;
        return SchnorrError.UnsupportedAlgorithm;
    }

    /// Always fails: no BIP340 backend. Never returns a verification verdict.
    pub fn verify(self: AdaptorSignature, message: []const u8, public_key: [SCHNORR_PUBLIC_KEY_SIZE]u8, adaptor_point: [32]u8) SchnorrError!bool {
        _ = self;
        _ = message;
        _ = public_key;
        _ = adaptor_point;
        return SchnorrError.UnsupportedAlgorithm;
    }

    /// Always fails: completing an adaptor signature is scalar addition modulo
    /// the secp256k1 group order, which is unavailable.
    pub fn complete(self: AdaptorSignature, adaptor_secret: [32]u8) SchnorrError![SCHNORR_SIGNATURE_SIZE]u8 {
        _ = self;
        _ = adaptor_secret;
        return SchnorrError.UnsupportedAlgorithm;
    }
};

/// Namespaced aliases. Same contract: every operation is unavailable.
pub const schnorr = struct {
    pub const KeyPair = SchnorrKeyPair;

    pub fn generate() SchnorrError!KeyPair {
        return generateSchnorr();
    }

    pub fn sign(message: []const u8, private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8) SchnorrError![SCHNORR_SIGNATURE_SIZE]u8 {
        return signSchnorr(message, private_key);
    }

    pub fn verify(message: []const u8, signature: [SCHNORR_SIGNATURE_SIZE]u8, public_key: [SCHNORR_PUBLIC_KEY_SIZE]u8) SchnorrError!bool {
        return verifySchnorr(message, signature, public_key);
    }
};

// Tests

test "Schnorr wire sizes match BIP340 encodings" {
    try testing.expectEqual(@as(usize, 32), SCHNORR_PRIVATE_KEY_SIZE);
    try testing.expectEqual(@as(usize, 32), SCHNORR_PUBLIC_KEY_SIZE);
    try testing.expectEqual(@as(usize, 64), SCHNORR_SIGNATURE_SIZE);
}

test "every Schnorr operation reports itself unsupported" {
    // If a real BIP340 backend is ever added, these expectations must be
    // replaced with the BIP340 test vectors, not deleted.
    const zero32: [32]u8 = @splat(0);
    const zero_sig: [SCHNORR_SIGNATURE_SIZE]u8 = @splat(0);

    try testing.expectError(SchnorrError.UnsupportedAlgorithm, generateSchnorr());
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, signSchnorr("m", zero32));
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, verifySchnorr("m", zero_sig, zero32));
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, schnorr.generate());
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, schnorr.sign("m", zero32));
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, schnorr.verify("m", zero_sig, zero32));
}

test "MuSig2 and adaptor signatures report themselves unsupported" {
    const zero32: [32]u8 = @splat(0);
    const zero66: [66]u8 = @splat(0);
    const zero_nonce = MuSig2.Nonce{ .r1 = zero32, .r2 = zero32, .public_nonce = @splat(0) };
    const empty_ctx = MuSig2.KeyAggContext{ .aggregate_pubkey = zero32, .key_agg_coeff = &.{} };

    try testing.expectError(SchnorrError.UnsupportedAlgorithm, MuSig2.keyAggregate(testing.allocator, &.{zero32}));
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, MuSig2.nonceGen(zero32, null, "m", null));
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, MuSig2.nonceAggregate(&.{@splat(0)}));
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, MuSig2.partialSign("m", zero32, zero_nonce, zero66, empty_ctx));
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, MuSig2.partialSigAggregate(&.{zero32}, zero66));

    const adaptor = AdaptorSignature{ .r = zero32, .s_adaptor = zero32, .adaptor_point = zero32 };
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, AdaptorSignature.create("m", zero32, zero32));
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, adaptor.verify("m", zero32, zero32));
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, adaptor.complete(zero32));
}

test "keypair methods refuse and zeroize still works" {
    var keypair = SchnorrKeyPair{
        .public_key = @splat(0xAA),
        .private_key = @splat(0xBB),
    };
    const zero_sig: [SCHNORR_SIGNATURE_SIZE]u8 = @splat(0);

    try testing.expectError(SchnorrError.UnsupportedAlgorithm, keypair.sign("m"));
    try testing.expectError(SchnorrError.UnsupportedAlgorithm, keypair.verify("m", zero_sig));

    keypair.zeroize();
    try testing.expect(std.mem.allEqual(u8, &keypair.private_key, 0));
}
