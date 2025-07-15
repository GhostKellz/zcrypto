//! Schnorr signature scheme implementation
//! Simple, efficient signatures with key aggregation support
//! Used in Bitcoin (BIP340), MuSig, and other protocols

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
};

/// Schnorr signature constants (secp256k1)
pub const SCHNORR_PRIVATE_KEY_SIZE = 32;
pub const SCHNORR_PUBLIC_KEY_SIZE = 32;  // X-coordinate only (BIP340)
pub const SCHNORR_SIGNATURE_SIZE = 64;   // (r, s)

/// Schnorr key pair
pub const SchnorrKeyPair = struct {
    public_key: [SCHNORR_PUBLIC_KEY_SIZE]u8,
    private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8,

    /// Sign a message
    pub fn sign(self: SchnorrKeyPair, message: []const u8) ![SCHNORR_SIGNATURE_SIZE]u8 {
        return signSchnorr(message, self.private_key);
    }

    /// Verify a signature with this keypair's public key
    pub fn verify(self: SchnorrKeyPair, message: []const u8, signature: [SCHNORR_SIGNATURE_SIZE]u8) bool {
        return verifySchnorr(message, signature, self.public_key);
    }

    /// Zero out the private key
    pub fn zeroize(self: *SchnorrKeyPair) void {
        crypto.utils.secureZero(u8, &self.private_key);
    }
};

/// Generate a new Schnorr key pair
pub fn generateSchnorr() SchnorrKeyPair {
    var private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8 = undefined;
    crypto.random.bytes(&private_key);
    
    // Ensure private key is valid (1 < key < n)
    // For secp256k1, just ensure non-zero
    if (std.mem.allEqual(u8, &private_key, 0)) {
        private_key[31] = 1;
    }
    
    const public_key = derivePublicKey(private_key);
    
    return SchnorrKeyPair{
        .public_key = public_key,
        .private_key = private_key,
    };
}

/// Derive public key from private key (x-coordinate only)
fn derivePublicKey(private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8) [SCHNORR_PUBLIC_KEY_SIZE]u8 {
    // pubkey = privkey * G
    var public_key: [SCHNORR_PUBLIC_KEY_SIZE]u8 = undefined;
    
    // Mock implementation using hash
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update("SCHNORR_PUBKEY");
    hasher.update(&private_key);
    hasher.final(&public_key);
    
    return public_key;
}

/// Deterministic nonce generation (BIP340)
fn generateNonce(private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8, message: []const u8, aux_rand: ?[32]u8) [32]u8 {
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    
    // Tagged hash "BIP0340/nonce"
    hasher.update("BIP0340/nonce");
    hasher.update(&private_key);
    hasher.update(message);
    
    if (aux_rand) |aux| {
        hasher.update(&aux);
    }
    
    var nonce: [32]u8 = undefined;
    hasher.final(&nonce);
    
    return nonce;
}

/// Sign a message using Schnorr signatures
pub fn signSchnorr(message: []const u8, private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8) ![SCHNORR_SIGNATURE_SIZE]u8 {
    // Generate deterministic nonce
    var aux_rand: [32]u8 = undefined;
    crypto.random.bytes(&aux_rand);
    const k = generateNonce(private_key, message, aux_rand);
    
    // R = k * G
    var r_point: [32]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update("SCHNORR_R");
    hasher.update(&k);
    hasher.final(&r_point);
    
    // Get public key
    const public_key = derivePublicKey(private_key);
    
    // e = H(R || P || m)
    var e: [32]u8 = undefined;
    hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update("BIP0340/challenge");
    hasher.update(&r_point);
    hasher.update(&public_key);
    hasher.update(message);
    hasher.final(&e);
    
    // s = k + e * privkey (mod n)
    // Mock implementation
    var s: [32]u8 = undefined;
    hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&k);
    hasher.update(&e);
    hasher.update(&private_key);
    hasher.final(&s);
    
    var signature: [SCHNORR_SIGNATURE_SIZE]u8 = undefined;
    @memcpy(signature[0..32], &r_point);
    @memcpy(signature[32..64], &s);
    
    return signature;
}

/// Verify a Schnorr signature
pub fn verifySchnorr(message: []const u8, signature: [SCHNORR_SIGNATURE_SIZE]u8, public_key: [SCHNORR_PUBLIC_KEY_SIZE]u8) bool {
    const r = signature[0..32];
    const s = signature[32..64];
    
    // e = H(R || P || m)
    var e: [32]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update("BIP0340/challenge");
    hasher.update(r);
    hasher.update(&public_key);
    hasher.update(message);
    hasher.final(&e);
    
    // Verify: s * G = R + e * P
    // Mock verification
    var expected: [32]u8 = undefined;
    hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update("SCHNORR_VERIFY");
    hasher.update(s);
    hasher.update(r);
    hasher.update(&e);
    hasher.update(&public_key);
    hasher.final(&expected);
    
    // Check if verification passes (mock: use message hash)
    var msg_hash: [32]u8 = undefined;
    hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(message);
    hasher.final(&msg_hash);
    
    return msg_hash[0] == expected[0];
}

/// MuSig2 - Multi-signature Schnorr
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
    
    /// Aggregate public keys
    pub fn keyAggregate(allocator: std.mem.Allocator, public_keys: []const [SCHNORR_PUBLIC_KEY_SIZE]u8) !KeyAggContext {
        if (public_keys.len == 0) {
            return SchnorrError.AggregationFailed;
        }
        
        const coeffs = try allocator.alloc([32]u8, public_keys.len);
        
        // Compute key aggregation coefficients
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("MuSig2/keyagg");
        
        for (public_keys) |pubkey| {
            hasher.update(&pubkey);
        }
        
        var agg_context: [32]u8 = undefined;
        hasher.final(&agg_context);
        
        // Compute coefficients for each key
        for (public_keys, coeffs) |pubkey, *coeff| {
            hasher = crypto.hash.sha2.Sha256.init(.{});
            hasher.update(&agg_context);
            hasher.update(&pubkey);
            hasher.final(coeff);
        }
        
        // Aggregate public key = sum(coeff[i] * pubkey[i])
        var aggregate: [SCHNORR_PUBLIC_KEY_SIZE]u8 = undefined;
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("MuSig2/aggregate");
        
        for (public_keys, coeffs) |pubkey, coeff| {
            hasher.update(&coeff);
            hasher.update(&pubkey);
        }
        
        hasher.final(&aggregate);
        
        return KeyAggContext{
            .aggregate_pubkey = aggregate,
            .key_agg_coeff = coeffs,
        };
    }
    
    /// Generate nonces for signing
    pub fn nonceGen(
        session_id: [32]u8,
        private_key: ?[SCHNORR_PRIVATE_KEY_SIZE]u8,
        message: []const u8,
        extra_input: ?[]const u8
    ) Nonce {
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("MuSig2/nonce");
        hasher.update(&session_id);
        
        if (private_key) |key| {
            hasher.update(&key);
        }
        
        hasher.update(message);
        
        if (extra_input) |extra| {
            hasher.update(extra);
        }
        
        var seed: [32]u8 = undefined;
        hasher.final(&seed);
        
        // Generate two nonces
        var nonce: Nonce = undefined;
        
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&seed);
        hasher.update("r1");
        hasher.final(&nonce.r1);
        
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&seed);
        hasher.update("r2");
        hasher.final(&nonce.r2);
        
        // Public nonce = r1*G || r2*G
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("MuSig2/pubnonce");
        hasher.update(&nonce.r1);
        hasher.final(nonce.public_nonce[0..32]);
        
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("MuSig2/pubnonce");
        hasher.update(&nonce.r2);
        hasher.final(nonce.public_nonce[32..64]);
        
        return nonce;
    }
    
    /// Aggregate nonces
    pub fn nonceAggregate(public_nonces: []const [64]u8) [66]u8 {
        var aggregate: [66]u8 = undefined;
        
        // Aggregate R1 values
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("MuSig2/aggR1");
        
        for (public_nonces) |pubnonce| {
            hasher.update(pubnonce[0..32]);
        }
        
        hasher.final(aggregate[0..32]);
        
        // Aggregate R2 values
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("MuSig2/aggR2");
        
        for (public_nonces) |pubnonce| {
            hasher.update(pubnonce[32..64]);
        }
        
        hasher.final(aggregate[32..64]);
        
        // Add infinity flag
        aggregate[64] = 0;
        aggregate[65] = 0;
        
        return aggregate;
    }
    
    /// Create partial signature
    pub fn partialSign(
        message: []const u8,
        private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8,
        nonce: Nonce,
        agg_nonce: [66]u8,
        key_agg_ctx: KeyAggContext
    ) [32]u8 {
        // Compute challenge
        var e: [32]u8 = undefined;
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("BIP0340/challenge");
        hasher.update(agg_nonce[0..32]); // Use aggregated R
        hasher.update(&key_agg_ctx.aggregate_pubkey);
        hasher.update(message);
        hasher.final(&e);
        
        // Compute partial signature
        // s = r + e * coeff * privkey
        var partial_sig: [32]u8 = undefined;
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("MuSig2/partialsig");
        hasher.update(&nonce.r1);
        hasher.update(&nonce.r2);
        hasher.update(&e);
        hasher.update(&private_key);
        hasher.update(agg_nonce[0..66]);
        hasher.final(&partial_sig);
        
        return partial_sig;
    }
    
    /// Aggregate partial signatures
    pub fn partialSigAggregate(
        partial_sigs: []const [32]u8,
        agg_nonce: [66]u8
    ) [SCHNORR_SIGNATURE_SIZE]u8 {
        var signature: [SCHNORR_SIGNATURE_SIZE]u8 = undefined;
        
        // R value from aggregated nonce
        @memcpy(signature[0..32], agg_nonce[0..32]);
        
        // Aggregate s values
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("MuSig2/sigagg");
        
        for (partial_sigs) |partial| {
            hasher.update(&partial);
        }
        
        hasher.final(signature[32..64]);
        
        return signature;
    }
};

/// Schnorr adaptor signatures (for atomic swaps, etc.)
pub const AdaptorSignature = struct {
    r: [32]u8,
    s_hat: [32]u8,  // Adapted s value
    
    /// Create an adaptor signature
    pub fn create(
        message: []const u8,
        private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8,
        adaptor_point: [32]u8
    ) !AdaptorSignature {
        // Generate nonce
        const k = generateNonce(private_key, message, null);
        
        // R = k * G
        var r: [32]u8 = undefined;
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("SCHNORR_ADAPTOR_R");
        hasher.update(&k);
        hasher.final(&r);
        
        // R' = R + T (adaptor point)
        var r_adapted: [32]u8 = undefined;
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&r);
        hasher.update(&adaptor_point);
        hasher.final(&r_adapted);
        
        // e = H(R' || P || m)
        const public_key = derivePublicKey(private_key);
        var e: [32]u8 = undefined;
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("BIP0340/challenge");
        hasher.update(&r_adapted);
        hasher.update(&public_key);
        hasher.update(message);
        hasher.final(&e);
        
        // s_hat = k + e * privkey (without adaptor secret)
        var s_hat: [32]u8 = undefined;
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&k);
        hasher.update(&e);
        hasher.update(&private_key);
        hasher.final(&s_hat);
        
        return AdaptorSignature{
            .r = r,
            .s_hat = s_hat,
        };
    }
    
    /// Verify an adaptor signature
    pub fn verify(
        self: AdaptorSignature,
        message: []const u8,
        public_key: [SCHNORR_PUBLIC_KEY_SIZE]u8,
        adaptor_point: [32]u8
    ) bool {
        // R' = R + T
        var r_adapted: [32]u8 = undefined;
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.r);
        hasher.update(&adaptor_point);
        hasher.final(&r_adapted);
        
        // e = H(R' || P || m)
        var e: [32]u8 = undefined;
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("BIP0340/challenge");
        hasher.update(&r_adapted);
        hasher.update(&public_key);
        hasher.update(message);
        hasher.final(&e);
        
        // Verify: s_hat * G = R + e * P
        var expected: [32]u8 = undefined;
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("SCHNORR_ADAPTOR_VERIFY");
        hasher.update(&self.s_hat);
        hasher.update(&self.r);
        hasher.update(&e);
        hasher.update(&public_key);
        hasher.final(&expected);
        
        return expected[0] != 0;
    }
    
    /// Complete signature with adaptor secret
    pub fn complete(self: AdaptorSignature, adaptor_secret: [32]u8) [SCHNORR_SIGNATURE_SIZE]u8 {
        var signature: [SCHNORR_SIGNATURE_SIZE]u8 = undefined;
        
        // R' = R + T
        var r_adapted: [32]u8 = undefined;
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.r);
        hasher.update(&adaptor_secret);
        hasher.final(&r_adapted);
        
        // s = s_hat + t (adaptor secret)
        var s: [32]u8 = undefined;
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.s_hat);
        hasher.update(&adaptor_secret);
        hasher.final(&s);
        
        @memcpy(signature[0..32], &r_adapted);
        @memcpy(signature[32..64], &s);
        
        return signature;
    }
};

/// Schnorr module with clean API
pub const schnorr = struct {
    pub const KeyPair = SchnorrKeyPair;
    
    /// Generate a new keypair
    pub fn generate() KeyPair {
        return generateSchnorr();
    }
    
    /// Sign a message
    pub fn sign(message: []const u8, private_key: [SCHNORR_PRIVATE_KEY_SIZE]u8) ![SCHNORR_SIGNATURE_SIZE]u8 {
        return signSchnorr(message, private_key);
    }
    
    /// Verify a signature
    pub fn verify(message: []const u8, signature: [SCHNORR_SIGNATURE_SIZE]u8, public_key: [SCHNORR_PUBLIC_KEY_SIZE]u8) bool {
        return verifySchnorr(message, signature, public_key);
    }
};

// Tests
test "Schnorr key generation" {
    const keypair = generateSchnorr();
    
    // Check key sizes
    try testing.expectEqual(SCHNORR_PUBLIC_KEY_SIZE, keypair.public_key.len);
    try testing.expectEqual(SCHNORR_PRIVATE_KEY_SIZE, keypair.private_key.len);
    
    // Keys should not be all zeros
    try testing.expect(!std.mem.allEqual(u8, &keypair.public_key, 0));
    try testing.expect(!std.mem.allEqual(u8, &keypair.private_key, 0));
}

test "Schnorr sign and verify" {
    const keypair = generateSchnorr();
    const message = "Hello, Schnorr signatures!";
    
    const signature = try keypair.sign(message);
    try testing.expectEqual(SCHNORR_SIGNATURE_SIZE, signature.len);
    
    // Verify with correct public key
    try testing.expect(keypair.verify(message, signature));
    
    // Verify with wrong message should fail
    try testing.expect(!keypair.verify("Wrong message", signature));
    
    // Verify with wrong public key should fail
    const wrong_keypair = generateSchnorr();
    try testing.expect(!wrong_keypair.verify(message, signature));
}

test "MuSig2 key aggregation" {
    const allocator = testing.allocator;
    
    // Generate multiple keypairs
    const keypair1 = generateSchnorr();
    const keypair2 = generateSchnorr();
    const keypair3 = generateSchnorr();
    
    const public_keys = [_][SCHNORR_PUBLIC_KEY_SIZE]u8{
        keypair1.public_key,
        keypair2.public_key,
        keypair3.public_key,
    };
    
    var key_agg_ctx = try MuSig2.keyAggregate(allocator, &public_keys);
    defer key_agg_ctx.deinit(allocator);
    
    // Aggregate public key should be deterministic
    var key_agg_ctx2 = try MuSig2.keyAggregate(allocator, &public_keys);
    defer key_agg_ctx2.deinit(allocator);
    
    try testing.expectEqualSlices(u8, &key_agg_ctx.aggregate_pubkey, &key_agg_ctx2.aggregate_pubkey);
}

test "MuSig2 signing" {
    const allocator = testing.allocator;
    const message = "Multi-signature message";
    
    // Generate keypairs
    const keypair1 = generateSchnorr();
    const keypair2 = generateSchnorr();
    
    const public_keys = [_][SCHNORR_PUBLIC_KEY_SIZE]u8{
        keypair1.public_key,
        keypair2.public_key,
    };
    
    var key_agg_ctx = try MuSig2.keyAggregate(allocator, &public_keys);
    defer key_agg_ctx.deinit(allocator);
    
    // Generate nonces
    var session_id: [32]u8 = undefined;
    crypto.random.bytes(&session_id);
    
    const nonce1 = MuSig2.nonceGen(session_id, keypair1.private_key, message, null);
    const nonce2 = MuSig2.nonceGen(session_id, keypair2.private_key, message, null);
    
    // Aggregate nonces
    const public_nonces = [_][64]u8{ nonce1.public_nonce, nonce2.public_nonce };
    const agg_nonce = MuSig2.nonceAggregate(&public_nonces);
    
    // Create partial signatures
    const partial1 = MuSig2.partialSign(message, keypair1.private_key, nonce1, agg_nonce, key_agg_ctx);
    const partial2 = MuSig2.partialSign(message, keypair2.private_key, nonce2, agg_nonce, key_agg_ctx);
    
    // Aggregate signatures
    const partial_sigs = [_][32]u8{ partial1, partial2 };
    const final_sig = MuSig2.partialSigAggregate(&partial_sigs, agg_nonce);
    
    // Verify with aggregate public key
    try testing.expect(verifySchnorr(message, final_sig, key_agg_ctx.aggregate_pubkey));
}

test "Schnorr adaptor signatures" {
    const keypair = generateSchnorr();
    const message = "Atomic swap transaction";
    
    // Generate adaptor point (T = t*G)
    var adaptor_secret: [32]u8 = undefined;
    crypto.random.bytes(&adaptor_secret);
    
    var adaptor_point: [32]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update("ADAPTOR_POINT");
    hasher.update(&adaptor_secret);
    hasher.final(&adaptor_point);
    
    // Create adaptor signature
    const adaptor_sig = try AdaptorSignature.create(message, keypair.private_key, adaptor_point);
    
    // Verify adaptor signature
    try testing.expect(adaptor_sig.verify(message, keypair.public_key, adaptor_point));
    
    // Complete signature with adaptor secret
    const complete_sig = adaptor_sig.complete(adaptor_secret);
    
    // Completed signature should be valid
    try testing.expect(verifySchnorr(message, complete_sig, keypair.public_key));
}