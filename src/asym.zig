//! Asymmetric cryptography - Ed25519, Curve25519
//!
//! Digital signatures and key exchange using modern elliptic curves.
//! All operations use constant-time implementations.

const std = @import("std");

/// Ed25519 public key size
pub const ED25519_PUBLIC_KEY_SIZE = 32;

/// Ed25519 private key size (seed) - zcrypto v0.5.0 uses 64-byte private keys
pub const ED25519_PRIVATE_KEY_SIZE = 64;

/// Ed25519 signature size
pub const ED25519_SIGNATURE_SIZE = 64;

/// Curve25519 public key size
pub const CURVE25519_PUBLIC_KEY_SIZE = 32;

/// Curve25519 private key size
pub const CURVE25519_PRIVATE_KEY_SIZE = 32;

/// Ed25519 keypair
pub const Ed25519KeyPair = struct {
    public_key: [ED25519_PUBLIC_KEY_SIZE]u8,
    private_key: [ED25519_PRIVATE_KEY_SIZE]u8,

    /// Sign a message with this keypair
    pub fn sign(self: Ed25519KeyPair, message: []const u8) ![ED25519_SIGNATURE_SIZE]u8 {
        const secret_key = std.crypto.sign.Ed25519.SecretKey.fromBytes(self.private_key) catch return error.InvalidPrivateKey;
        const key_pair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
        const signature = key_pair.sign(message, null) catch return error.SigningFailed;
        return signature.toBytes();
    }

    /// Verify that this keypair's public key matches
    pub fn verify(self: Ed25519KeyPair, message: []const u8, signature: [ED25519_SIGNATURE_SIZE]u8) bool {
        return verifyEd25519(message, signature, self.public_key);
    }

    /// Zero out the private key (call when done)
    pub fn zeroize(self: *Ed25519KeyPair) void {
        std.crypto.utils.secureZero(u8, &self.private_key);
    }
};

/// Curve25519 keypair for key exchange
pub const Curve25519KeyPair = struct {
    public_key: [CURVE25519_PUBLIC_KEY_SIZE]u8,
    private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8,

    /// Perform Diffie-Hellman key exchange
    pub fn dh(self: Curve25519KeyPair, other_public_key: [CURVE25519_PUBLIC_KEY_SIZE]u8) ![CURVE25519_PUBLIC_KEY_SIZE]u8 {
        return std.crypto.dh.X25519.scalarmult(self.private_key, other_public_key);
    }

    /// Zero out the private key (call when done)
    pub fn zeroize(self: *Curve25519KeyPair) void {
        std.crypto.utils.secureZero(u8, &self.private_key);
    }
};

/// Generate a new Ed25519 keypair
pub fn generateEd25519() Ed25519KeyPair {
    // Generate using the standard Zig crypto library approach
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generate();
    
    return Ed25519KeyPair{
        .public_key = key_pair.public_key.bytes,
        .private_key = key_pair.secret_key.bytes,
    };
}

/// Generate a new Curve25519 keypair
pub fn generateCurve25519() Curve25519KeyPair {
    var private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8 = undefined;
    std.crypto.random.bytes(&private_key);
    const public_key = std.crypto.dh.X25519.recoverPublicKey(private_key) catch return Curve25519KeyPair{ .public_key = [_]u8{0} ** 32, .private_key = private_key };

    return Curve25519KeyPair{
        .public_key = public_key,
        .private_key = private_key,
    };
}

/// Sign a message using Ed25519
pub fn signEd25519(message: []const u8, private_key: [ED25519_PRIVATE_KEY_SIZE]u8) ![ED25519_SIGNATURE_SIZE]u8 {
    const secret_key = std.crypto.sign.Ed25519.SecretKey.fromBytes(private_key) catch return error.InvalidPrivateKey;
    const key_pair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
    const signature = key_pair.sign(message, null) catch return error.SigningFailed;
    return signature.toBytes();
}

/// Verify an Ed25519 signature
pub fn verifyEd25519(message: []const u8, signature: [ED25519_SIGNATURE_SIZE]u8, public_key: [ED25519_PUBLIC_KEY_SIZE]u8) bool {
    const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
    sig.verify(message, pub_key) catch return false;
    return true;
}

/// Perform X25519 Diffie-Hellman key exchange
pub fn dhX25519(private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8, public_key: [CURVE25519_PUBLIC_KEY_SIZE]u8) [CURVE25519_PUBLIC_KEY_SIZE]u8 {
    return std.crypto.dh.X25519.scalarmult(private_key, public_key);
}

/// Generate X25519 public key from private key
pub fn x25519PublicKey(private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8) [CURVE25519_PUBLIC_KEY_SIZE]u8 {
    return std.crypto.dh.X25519.recoverPublicKey(private_key) catch [_]u8{0} ** 32;
}

/// Ed25519 module with clean API matching your docs
pub const ed25519 = struct {
    pub const KeyPair = Ed25519KeyPair;

    /// Generate a new keypair
    pub fn generate() KeyPair {
        return generateEd25519();
    }

    /// Generate keypair from 32-byte seed (deterministic)
    pub fn generateFromSeed(seed: [32]u8) KeyPair {
        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch |err| switch (err) {
            error.IdentityElement => {
                // In the extremely rare case of an identity element, modify the seed slightly
                var modified_seed = seed;
                modified_seed[0] +%= 1;
                return generateFromSeed(modified_seed);
            },
        };
        return KeyPair{
            .public_key = kp.public_key.bytes,
            .private_key = kp.secret_key.bytes,
        };
    }

    /// Sign a message
    pub fn sign(message: []const u8, private_key: [ED25519_PRIVATE_KEY_SIZE]u8) ![ED25519_SIGNATURE_SIZE]u8 {
        return signEd25519(message, private_key);
    }

    /// Verify a signature
    pub fn verify(message: []const u8, signature: [ED25519_SIGNATURE_SIZE]u8, public_key: [ED25519_PUBLIC_KEY_SIZE]u8) bool {
        return verifyEd25519(message, signature, public_key);
    }
};

/// X25519 module
pub const x25519 = struct {
    pub const KeyPair = Curve25519KeyPair;

    /// Generate a new keypair
    pub fn generate() KeyPair {
        return generateCurve25519();
    }

    /// Perform key exchange
    pub fn dh(private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8, public_key: [CURVE25519_PUBLIC_KEY_SIZE]u8) [CURVE25519_PUBLIC_KEY_SIZE]u8 {
        return dhX25519(private_key, public_key);
    }

    /// Generate public key from private key
    pub fn publicKey(private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8) [CURVE25519_PUBLIC_KEY_SIZE]u8 {
        return x25519PublicKey(private_key);
    }
};

/// secp256k1 constants (Bitcoin/Ethereum curve)
pub const SECP256K1_PRIVATE_KEY_SIZE = 32;
pub const SECP256K1_PUBLIC_KEY_SIZE = 33; // Compressed
pub const SECP256K1_SIGNATURE_SIZE = 64;

/// secp256r1 constants (NIST P-256)  
pub const SECP256R1_PRIVATE_KEY_SIZE = 32;
pub const SECP256R1_PUBLIC_KEY_SIZE = 33; // Compressed
pub const SECP256R1_SIGNATURE_SIZE = 64;

/// secp256k1 keypair for Bitcoin/Ethereum compatibility
pub const Secp256k1KeyPair = struct {
    public_key_compressed: [SECP256K1_PUBLIC_KEY_SIZE]u8,  // Full 33-byte compressed key
    public_key_x: [32]u8,                                  // X-coordinate only (for consistency)
    private_key: [SECP256K1_PRIVATE_KEY_SIZE]u8,

    /// Get public key in desired format
    pub fn publicKey(self: @This(), format: enum { compressed, x_only }) []const u8 {
        return switch (format) {
            .compressed => &self.public_key_compressed,
            .x_only => &self.public_key_x,
        };
    }

    /// Sign a message with secp256k1
    pub fn sign(self: Secp256k1KeyPair, message: [32]u8) ![SECP256K1_SIGNATURE_SIZE]u8 {
        return signSecp256k1(message, self.private_key);
    }

    /// Verify signature with this keypair's public key
    pub fn verify(self: Secp256k1KeyPair, message: [32]u8, signature: [SECP256K1_SIGNATURE_SIZE]u8) bool {
        return verifySecp256k1(message, signature, self.public_key_compressed);
    }

    /// Zero out the private key
    pub fn zeroize(self: *Secp256k1KeyPair) void {
        std.crypto.utils.secureZero(u8, &self.private_key);
    }
};

/// secp256r1 keypair for NIST P-256 compatibility
pub const Secp256r1KeyPair = struct {
    public_key: [SECP256R1_PUBLIC_KEY_SIZE]u8,
    private_key: [SECP256R1_PRIVATE_KEY_SIZE]u8,

    /// Sign a message with secp256r1
    pub fn sign(self: Secp256r1KeyPair, message: [32]u8) ![SECP256R1_SIGNATURE_SIZE]u8 {
        return signSecp256r1(message, self.private_key);
    }

    /// Verify signature with this keypair's public key
    pub fn verify(self: Secp256r1KeyPair, message: [32]u8, signature: [SECP256R1_SIGNATURE_SIZE]u8) bool {
        return verifySecp256r1(message, signature, self.public_key);
    }

    /// Zero out the private key
    pub fn zeroize(self: *Secp256r1KeyPair) void {
        std.crypto.utils.secureZero(u8, &self.private_key);
    }
};

/// Generate secp256k1 keypair
pub fn generateSecp256k1() Secp256k1KeyPair {
    const kp = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.KeyPair.generate();
    const compressed = kp.public_key.toCompressedSec1();
    
    return Secp256k1KeyPair{
        .public_key_compressed = compressed,
        .public_key_x = compressed[1..33].*, // Skip compression prefix
        .private_key = kp.secret_key.bytes,
    };
}

/// Generate secp256r1 keypair
pub fn generateSecp256r1() Secp256r1KeyPair {
    const kp = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generate();
    return Secp256r1KeyPair{
        .public_key = kp.public_key.toCompressedSec1(),
        .private_key = kp.secret_key.bytes,
    };
}

/// Sign with secp256k1 (Bitcoin/Ethereum style)
pub fn signSecp256k1(message: [32]u8, private_key: [SECP256K1_PRIVATE_KEY_SIZE]u8) ![SECP256K1_SIGNATURE_SIZE]u8 {
    const secret_key = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.SecretKey.fromBytes(private_key) catch return error.InvalidPrivateKey;
    const kp = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
    const sig = kp.sign(&message, null) catch return error.SigningFailed;
    return sig.toBytes();
}

/// Verify secp256k1 signature
pub fn verifySecp256k1(message: [32]u8, signature: [SECP256K1_SIGNATURE_SIZE]u8, public_key: [SECP256K1_PUBLIC_KEY_SIZE]u8) bool {
    const pub_key = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.PublicKey.fromSec1(&public_key) catch return false;
    const sig = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.Signature.fromBytes(signature);
    sig.verify(&message, pub_key) catch return false;
    return true;
}

/// Sign with secp256r1 (NIST P-256)
pub fn signSecp256r1(message: [32]u8, private_key: [SECP256R1_PRIVATE_KEY_SIZE]u8) ![SECP256R1_SIGNATURE_SIZE]u8 {
    const secret_key = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(private_key) catch return error.InvalidPrivateKey;
    const kp = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
    const sig = kp.sign(&message, null) catch return error.SigningFailed;
    return sig.toBytes();
}

/// Verify secp256r1 signature  
pub fn verifySecp256r1(message: [32]u8, signature: [SECP256R1_SIGNATURE_SIZE]u8, public_key: [SECP256R1_PUBLIC_KEY_SIZE]u8) bool {
    const pub_key = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&public_key) catch return false;
    const sig = std.crypto.sign.ecdsa.EcdsaP256Sha256.Signature.fromBytes(signature);
    sig.verify(&message, pub_key) catch return false;
    return true;
}

/// secp256k1 module with clean API
pub const secp256k1 = struct {
    pub const KeyPair = Secp256k1KeyPair;

    /// Generate a new keypair
    pub fn generate() KeyPair {
        return generateSecp256k1();
    }

    /// Sign a message hash
    pub fn sign(message: [32]u8, private_key: [SECP256K1_PRIVATE_KEY_SIZE]u8) ![SECP256K1_SIGNATURE_SIZE]u8 {
        return signSecp256k1(message, private_key);
    }

    /// Verify a signature
    pub fn verify(message: [32]u8, signature: [SECP256K1_SIGNATURE_SIZE]u8, public_key: [SECP256K1_PUBLIC_KEY_SIZE]u8) bool {
        return verifySecp256k1(message, signature, public_key);
    }
};

/// secp256r1 module with clean API
pub const secp256r1 = struct {
    pub const KeyPair = Secp256r1KeyPair;

    /// Generate a new keypair
    pub fn generate() KeyPair {
        return generateSecp256r1();
    }

    /// Sign a message hash
    pub fn sign(message: [32]u8, private_key: [SECP256R1_PRIVATE_KEY_SIZE]u8) ![SECP256R1_SIGNATURE_SIZE]u8 {
        return signSecp256r1(message, private_key);
    }

    /// Verify a signature
    pub fn verify(message: [32]u8, signature: [SECP256R1_SIGNATURE_SIZE]u8, public_key: [SECP256R1_PUBLIC_KEY_SIZE]u8) bool {
        return verifySecp256r1(message, signature, public_key);
    }
};

test "ed25519 keypair generation and signing" {
    const keypair = generateEd25519();
    const message = "Hello, zcrypto signatures!";
    
    const signature = try keypair.sign(message);
    const valid = keypair.verify(message, signature);
    
    try std.testing.expect(valid);
    
    // Test with wrong message
    const wrong_message = "Wrong message";
    const invalid = keypair.verify(wrong_message, signature);
    try std.testing.expect(!invalid);
}

test "ed25519 standalone functions" {
    const keypair = ed25519.generate();
    const message = "Standalone API test";
    
    const signature = try ed25519.sign(message, keypair.private_key);
    const valid = ed25519.verify(message, signature, keypair.public_key);
    
    try std.testing.expect(valid);
}

test "ed25519 deterministic generation from seed" {
    const seed = [_]u8{42} ** 32;
    
    // Generate two keypairs from the same seed
    const keypair1 = ed25519.generateFromSeed(seed);
    const keypair2 = ed25519.generateFromSeed(seed);
    
    // Should be identical
    try std.testing.expectEqualSlices(u8, &keypair1.public_key, &keypair2.public_key);
    try std.testing.expectEqualSlices(u8, &keypair1.private_key, &keypair2.private_key);
    
    // Test signing with generated key
    const message = "Deterministic test message";
    const signature = try keypair1.sign(message);
    const valid = keypair1.verify(message, signature);
    
    try std.testing.expect(valid);
}

test "x25519 key exchange" {
    const alice = x25519.generate();
    const bob = x25519.generate();

    // Perform key exchange
    const alice_shared = try alice.dh(bob.public_key);
    const bob_shared = try bob.dh(alice.public_key);

    // Should produce the same shared secret
    try std.testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

test "x25519 public key derivation" {
    const keypair = x25519.generate();
    const derived_public = x25519.publicKey(keypair.private_key);

    try std.testing.expectEqualSlices(u8, &keypair.public_key, &derived_public);
}

test "secp256k1 keypair generation and signing" {
    const keypair = secp256k1.generate();
    const message = [_]u8{0xAB} ** 32; // Hash of message
    
    const signature = try keypair.sign(message);
    const valid = keypair.verify(message, signature);
    
    try std.testing.expect(valid);
    
    // Test with different message
    const wrong_message = [_]u8{0xCD} ** 32;
    const invalid = keypair.verify(wrong_message, signature);
    try std.testing.expect(!invalid);
}

test "secp256r1 keypair generation and signing" {
    const keypair = secp256r1.generate();
    const message = [_]u8{0xEF} ** 32; // Hash of message
    
    const signature = try keypair.sign(message);
    const valid = keypair.verify(message, signature);
    
    try std.testing.expect(valid);
    
    // Test with different message
    const wrong_message = [_]u8{0x12} ** 32;
    const invalid = keypair.verify(wrong_message, signature);
    try std.testing.expect(!invalid);
}

test "secp256k1 standalone functions" {
    const keypair = secp256k1.generate();
    const message = [_]u8{0x34} ** 32;
    
    const signature = try secp256k1.sign(message, keypair.private_key);
    const valid = secp256k1.verify(message, signature, keypair.public_key_compressed);
    
    try std.testing.expect(valid);
}

test "secp256k1 dual public key formats" {
    const keypair = secp256k1.generate();
    
    // Test both public key formats
    const compressed = keypair.publicKey(.compressed);
    const x_only = keypair.publicKey(.x_only);
    
    try std.testing.expectEqual(@as(usize, 33), compressed.len);
    try std.testing.expectEqual(@as(usize, 32), x_only.len);
    
    // X-only should be the compressed key without the prefix
    try std.testing.expectEqualSlices(u8, compressed[1..], x_only);
}

test "secp256r1 standalone functions" {
    const keypair = secp256r1.generate();
    const message = [_]u8{0x56} ** 32;
    
    const signature = try secp256r1.sign(message, keypair.private_key);
    const valid = secp256r1.verify(message, signature, keypair.public_key);
    
    try std.testing.expect(valid);
}
