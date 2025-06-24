//! Asymmetric cryptography - Ed25519, Curve25519
//!
//! Digital signatures and key exchange using modern elliptic curves.
//! All operations use constant-time implementations.

const std = @import("std");

/// Ed25519 public key size
pub const ED25519_PUBLIC_KEY_SIZE = 32;

/// Ed25519 private key size (seed)
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
    pub fn sign(self: Ed25519KeyPair, message: []const u8) [ED25519_SIGNATURE_SIZE]u8 {
        const secret_key = std.crypto.sign.Ed25519.SecretKey.fromBytes(self.private_key) catch unreachable;
        const key_pair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch unreachable;
        const signature = key_pair.sign(message, null) catch unreachable;
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
    const public_key = std.crypto.dh.X25519.recoverPublicKey(private_key) catch unreachable;

    return Curve25519KeyPair{
        .public_key = public_key,
        .private_key = private_key,
    };
}

/// Sign a message using Ed25519
pub fn signEd25519(message: []const u8, private_key: [ED25519_PRIVATE_KEY_SIZE]u8) [ED25519_SIGNATURE_SIZE]u8 {
    const secret_key = std.crypto.sign.Ed25519.SecretKey.fromBytes(private_key) catch unreachable;
    const key_pair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch unreachable;
    const signature = key_pair.sign(message, null) catch unreachable;
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
    return std.crypto.dh.X25519.recoverPublicKey(private_key) catch unreachable;
}

/// Ed25519 module with clean API matching your docs
pub const ed25519 = struct {
    pub const KeyPair = Ed25519KeyPair;

    /// Generate a new keypair
    pub fn generate() KeyPair {
        return generateEd25519();
    }

    /// Sign a message
    pub fn sign(message: []const u8, private_key: [ED25519_PRIVATE_KEY_SIZE]u8) [ED25519_SIGNATURE_SIZE]u8 {
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

test "ed25519 keypair generation and signing" {
    const keypair = generateEd25519();
    const message = "Hello, zcrypto signatures!";
    
    const signature = keypair.sign(message);
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
    
    const signature = ed25519.sign(message, keypair.private_key);
    const valid = ed25519.verify(message, signature, keypair.public_key);
    
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
