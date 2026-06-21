//! Asymmetric cryptography - Ed25519, Curve25519
//!
//! Digital signatures and key exchange using modern elliptic curves.
//! All operations use constant-time implementations.

const std = @import("std");
const rand = @import("rand.zig");

fn decodeHex(comptime N: usize, hex: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// Ed25519 public key size
pub const ED25519_PUBLIC_KEY_SIZE = 32;

/// Ed25519 private key size. This API uses 64-byte secret keys.
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

    /// Import a keypair from raw bytes and verify the public key matches.
    pub fn fromBytes(public_key: [ED25519_PUBLIC_KEY_SIZE]u8, private_key: [ED25519_PRIVATE_KEY_SIZE]u8) !Ed25519KeyPair {
        const derived_public = try ed25519PublicKey(private_key);
        if (!std.mem.eql(u8, &derived_public, &public_key)) return error.InvalidPublicKey;
        return .{ .public_key = public_key, .private_key = private_key };
    }

    /// Export public key bytes.
    pub fn publicKeyBytes(self: Ed25519KeyPair) [ED25519_PUBLIC_KEY_SIZE]u8 {
        return self.public_key;
    }

    /// Export private key bytes. Callers own zeroization of returned copies.
    pub fn privateKeyBytes(self: Ed25519KeyPair) [ED25519_PRIVATE_KEY_SIZE]u8 {
        return self.private_key;
    }

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
        std.crypto.secureZero(u8, &self.private_key);
    }
};

/// Curve25519 keypair for key exchange
pub const Curve25519KeyPair = struct {
    public_key: [CURVE25519_PUBLIC_KEY_SIZE]u8,
    private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8,

    /// Import a keypair from raw bytes and verify the public key matches.
    pub fn fromBytes(public_key: [CURVE25519_PUBLIC_KEY_SIZE]u8, private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8) !Curve25519KeyPair {
        const derived_public = try x25519PublicKeyChecked(private_key);
        if (!std.mem.eql(u8, &derived_public, &public_key)) return error.InvalidPublicKey;
        return .{ .public_key = public_key, .private_key = private_key };
    }

    /// Export public key bytes.
    pub fn publicKeyBytes(self: Curve25519KeyPair) [CURVE25519_PUBLIC_KEY_SIZE]u8 {
        return self.public_key;
    }

    /// Export private key bytes. Callers own zeroization of returned copies.
    pub fn privateKeyBytes(self: Curve25519KeyPair) [CURVE25519_PRIVATE_KEY_SIZE]u8 {
        return self.private_key;
    }

    /// Perform Diffie-Hellman key exchange
    pub fn dh(self: Curve25519KeyPair, other_public_key: [CURVE25519_PUBLIC_KEY_SIZE]u8) ![CURVE25519_PUBLIC_KEY_SIZE]u8 {
        return std.crypto.dh.X25519.scalarmult(self.private_key, other_public_key);
    }

    /// Zero out the private key (call when done)
    pub fn zeroize(self: *Curve25519KeyPair) void {
        std.crypto.secureZero(u8, &self.private_key);
    }
};

/// Generate a new Ed25519 keypair
pub fn generateEd25519() Ed25519KeyPair {
    // Generate random seed and use deterministic key generation
    var seed: [32]u8 = undefined;
    rand.fill(&seed);
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch {
        // If identity element (extremely rare), regenerate
        rand.fill(&seed);
        return generateEd25519();
    };

    return Ed25519KeyPair{
        .public_key = key_pair.public_key.bytes,
        .private_key = key_pair.secret_key.bytes,
    };
}

/// Generate a new Curve25519 keypair
pub fn generateCurve25519() Curve25519KeyPair {
    var private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8 = undefined;
    rand.fill(&private_key);
    const public_key = std.crypto.dh.X25519.recoverPublicKey(private_key) catch return Curve25519KeyPair{ .public_key = std.mem.zeroes([32]u8), .private_key = private_key };

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

/// Generate Ed25519 public key from a 64-byte private key.
pub fn ed25519PublicKey(private_key: [ED25519_PRIVATE_KEY_SIZE]u8) ![ED25519_PUBLIC_KEY_SIZE]u8 {
    const secret_key = std.crypto.sign.Ed25519.SecretKey.fromBytes(private_key) catch return error.InvalidPrivateKey;
    const key_pair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
    return key_pair.public_key.bytes;
}

/// Verify an Ed25519 signature
pub fn verifyEd25519(message: []const u8, signature: [ED25519_SIGNATURE_SIZE]u8, public_key: [ED25519_PUBLIC_KEY_SIZE]u8) bool {
    const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
    sig.verify(message, pub_key) catch return false;
    return true;
}

/// Perform X25519 Diffie-Hellman key exchange
pub fn dhX25519(private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8, public_key: [CURVE25519_PUBLIC_KEY_SIZE]u8) error{IdentityElement}![CURVE25519_PUBLIC_KEY_SIZE]u8 {
    return try std.crypto.dh.X25519.scalarmult(private_key, public_key);
}

/// Generate X25519 public key from private key
pub fn x25519PublicKey(private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8) [CURVE25519_PUBLIC_KEY_SIZE]u8 {
    return std.crypto.dh.X25519.recoverPublicKey(private_key) catch std.mem.zeroes([32]u8);
}

/// Generate X25519 public key from private key, returning errors instead of a zero fallback.
pub fn x25519PublicKeyChecked(private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8) ![CURVE25519_PUBLIC_KEY_SIZE]u8 {
    return std.crypto.dh.X25519.recoverPublicKey(private_key) catch return error.InvalidPrivateKey;
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

    /// Import a keypair from raw bytes and verify the public key matches.
    pub fn fromBytes(public_key: [ED25519_PUBLIC_KEY_SIZE]u8, private_key: [ED25519_PRIVATE_KEY_SIZE]u8) !KeyPair {
        return KeyPair.fromBytes(public_key, private_key);
    }

    /// Derive public key bytes from private key bytes.
    pub fn publicKey(private_key: [ED25519_PRIVATE_KEY_SIZE]u8) ![ED25519_PUBLIC_KEY_SIZE]u8 {
        return ed25519PublicKey(private_key);
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
    pub fn dh(private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8, public_key: [CURVE25519_PUBLIC_KEY_SIZE]u8) error{IdentityElement}![CURVE25519_PUBLIC_KEY_SIZE]u8 {
        return try dhX25519(private_key, public_key);
    }

    /// Generate public key from private key
    pub fn publicKey(private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8) [CURVE25519_PUBLIC_KEY_SIZE]u8 {
        return x25519PublicKey(private_key);
    }

    /// Generate public key from private key, returning errors instead of a zero fallback.
    pub fn publicKeyChecked(private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8) ![CURVE25519_PUBLIC_KEY_SIZE]u8 {
        return x25519PublicKeyChecked(private_key);
    }

    /// Import a keypair from raw bytes and verify the public key matches.
    pub fn fromBytes(public_key: [CURVE25519_PUBLIC_KEY_SIZE]u8, private_key: [CURVE25519_PRIVATE_KEY_SIZE]u8) !KeyPair {
        return KeyPair.fromBytes(public_key, private_key);
    }
};

/// secp256k1 constants (Bitcoin/Ethereum curve)
pub const SECP256K1_PRIVATE_KEY_SIZE = 32;
pub const SECP256K1_PUBLIC_KEY_SIZE = 33; // Compressed
pub const SECP256K1_SIGNATURE_SIZE = 64;

/// secp256r1 constants (NIST P-256)
pub const SECP256R1_PRIVATE_KEY_SIZE = 32;
pub const SECP256R1_PUBLIC_KEY_SIZE = 33; // Compressed
pub const SECP256R1_SIGNATURE_SIZE = 64; // Fixed-width (r || s)
/// Maximum DER-encoded ECDSA P-256 signature length (variable, <= this).
pub const SECP256R1_DER_SIGNATURE_MAX = std.crypto.sign.ecdsa.EcdsaP256Sha256.Signature.der_encoded_length_max;

/// secp384r1 constants (NIST P-384)
pub const SECP384R1_PRIVATE_KEY_SIZE = 48;
pub const SECP384R1_PUBLIC_KEY_SIZE = 49; // Compressed
pub const SECP384R1_SIGNATURE_SIZE = 96; // Fixed-width (r || s)
/// Maximum DER-encoded ECDSA P-384 signature length (variable, <= this).
pub const SECP384R1_DER_SIGNATURE_MAX = std.crypto.sign.ecdsa.EcdsaP384Sha384.Signature.der_encoded_length_max;

/// secp256k1 keypair for Bitcoin/Ethereum compatibility
pub const Secp256k1KeyPair = struct {
    public_key_compressed: [SECP256K1_PUBLIC_KEY_SIZE]u8, // Full 33-byte compressed key
    public_key_x: [32]u8, // X-coordinate only (for consistency)
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
        std.crypto.secureZero(u8, &self.private_key);
    }
};

/// secp256r1 keypair for NIST P-256 compatibility
pub const Secp256r1KeyPair = struct {
    public_key: [SECP256R1_PUBLIC_KEY_SIZE]u8,
    private_key: [SECP256R1_PRIVATE_KEY_SIZE]u8,

    /// Import a compressed SEC1 public key and private key, verifying they match.
    pub fn fromBytes(public_key: [SECP256R1_PUBLIC_KEY_SIZE]u8, private_key: [SECP256R1_PRIVATE_KEY_SIZE]u8) !Secp256r1KeyPair {
        const derived_public = try secp256r1PublicKey(private_key);
        if (!std.mem.eql(u8, &derived_public, &public_key)) return error.InvalidPublicKey;
        return .{ .public_key = public_key, .private_key = private_key };
    }

    /// Export compressed SEC1 public key bytes.
    pub fn publicKeyBytes(self: Secp256r1KeyPair) [SECP256R1_PUBLIC_KEY_SIZE]u8 {
        return self.public_key;
    }

    /// Export private key bytes. Callers own zeroization of returned copies.
    pub fn privateKeyBytes(self: Secp256r1KeyPair) [SECP256R1_PRIVATE_KEY_SIZE]u8 {
        return self.private_key;
    }

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
        std.crypto.secureZero(u8, &self.private_key);
    }
};

/// secp384r1 keypair for NIST P-384 compatibility
pub const Secp384r1KeyPair = struct {
    public_key: [SECP384R1_PUBLIC_KEY_SIZE]u8,
    private_key: [SECP384R1_PRIVATE_KEY_SIZE]u8,

    /// Import a compressed SEC1 public key and private key, verifying they match.
    pub fn fromBytes(public_key: [SECP384R1_PUBLIC_KEY_SIZE]u8, private_key: [SECP384R1_PRIVATE_KEY_SIZE]u8) !Secp384r1KeyPair {
        const derived_public = try secp384r1PublicKey(private_key);
        if (!std.mem.eql(u8, &derived_public, &public_key)) return error.InvalidPublicKey;
        return .{ .public_key = public_key, .private_key = private_key };
    }

    /// Export compressed SEC1 public key bytes.
    pub fn publicKeyBytes(self: Secp384r1KeyPair) [SECP384R1_PUBLIC_KEY_SIZE]u8 {
        return self.public_key;
    }

    /// Export private key bytes. Callers own zeroization of returned copies.
    pub fn privateKeyBytes(self: Secp384r1KeyPair) [SECP384R1_PRIVATE_KEY_SIZE]u8 {
        return self.private_key;
    }

    /// Sign a 48-byte message with secp384r1 (fixed-width r||s output)
    pub fn sign(self: Secp384r1KeyPair, message: [48]u8) ![SECP384R1_SIGNATURE_SIZE]u8 {
        return signSecp384r1(message, self.private_key);
    }

    /// Verify a fixed-width signature with this keypair's public key
    pub fn verify(self: Secp384r1KeyPair, message: [48]u8, signature: [SECP384R1_SIGNATURE_SIZE]u8) bool {
        return verifySecp384r1(message, signature, self.public_key);
    }

    /// Zero out the private key
    pub fn zeroize(self: *Secp384r1KeyPair) void {
        std.crypto.secureZero(u8, &self.private_key);
    }
};

/// Generate secp256k1 keypair
pub fn generateSecp256k1() Secp256k1KeyPair {
    // Use deterministic generation with random seed
    var seed: [32]u8 = undefined;
    rand.fill(&seed);
    const kp = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(seed) catch {
        // If generation fails, try with a different seed
        rand.fill(&seed);
        return generateSecp256k1();
    };
    const compressed_temp = kp.public_key.toCompressedSec1();

    // Copy the compressed key to ensure it's not a temporary reference
    var public_key_compressed: [SECP256K1_PUBLIC_KEY_SIZE]u8 = undefined;
    @memcpy(&public_key_compressed, &compressed_temp);

    var public_key_x: [32]u8 = undefined;
    @memcpy(&public_key_x, compressed_temp[1..33]);

    return Secp256k1KeyPair{
        .public_key_compressed = public_key_compressed,
        .public_key_x = public_key_x,
        .private_key = kp.secret_key.bytes,
    };
}

/// Generate secp256r1 keypair
pub fn generateSecp256r1() Secp256r1KeyPair {
    // Use deterministic generation with random seed
    var seed: [32]u8 = undefined;
    rand.fill(&seed);
    const kp = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(seed) catch {
        // If generation fails, try with a different seed
        rand.fill(&seed);
        return generateSecp256r1();
    };
    return Secp256r1KeyPair{
        .public_key = kp.public_key.toCompressedSec1(),
        .private_key = kp.secret_key.bytes,
    };
}

/// Generate compressed SEC1 P-256 public key from private key.
pub fn secp256r1PublicKey(private_key: [SECP256R1_PRIVATE_KEY_SIZE]u8) ![SECP256R1_PUBLIC_KEY_SIZE]u8 {
    const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const secret_key = Scheme.SecretKey.fromBytes(private_key) catch return error.InvalidPrivateKey;
    const kp = Scheme.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
    return kp.public_key.toCompressedSec1();
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

/// Generate secp384r1 keypair (NIST P-384)
pub fn generateSecp384r1() Secp384r1KeyPair {
    var seed: [48]u8 = undefined;
    rand.fill(&seed);
    const kp = std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair.generateDeterministic(seed) catch {
        rand.fill(&seed);
        return generateSecp384r1();
    };
    return Secp384r1KeyPair{
        .public_key = kp.public_key.toCompressedSec1(),
        .private_key = kp.secret_key.bytes,
    };
}

/// Generate compressed SEC1 P-384 public key from private key.
pub fn secp384r1PublicKey(private_key: [SECP384R1_PRIVATE_KEY_SIZE]u8) ![SECP384R1_PUBLIC_KEY_SIZE]u8 {
    const Scheme = std.crypto.sign.ecdsa.EcdsaP384Sha384;
    const secret_key = Scheme.SecretKey.fromBytes(private_key) catch return error.InvalidPrivateKey;
    const kp = Scheme.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
    return kp.public_key.toCompressedSec1();
}

/// Sign with secp384r1 (NIST P-384), fixed-width r||s output
pub fn signSecp384r1(message: [48]u8, private_key: [SECP384R1_PRIVATE_KEY_SIZE]u8) ![SECP384R1_SIGNATURE_SIZE]u8 {
    const secret_key = std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(private_key) catch return error.InvalidPrivateKey;
    const kp = std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
    const sig = kp.sign(&message, null) catch return error.SigningFailed;
    return sig.toBytes();
}

/// Verify secp384r1 fixed-width signature
pub fn verifySecp384r1(message: [48]u8, signature: [SECP384R1_SIGNATURE_SIZE]u8, public_key: [SECP384R1_PUBLIC_KEY_SIZE]u8) bool {
    const pub_key = std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(&public_key) catch return false;
    const sig = std.crypto.sign.ecdsa.EcdsaP384Sha384.Signature.fromBytes(signature);
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

    /// Import a keypair from raw bytes and verify the public key matches.
    pub fn fromBytes(public_key: [SECP256R1_PUBLIC_KEY_SIZE]u8, private_key: [SECP256R1_PRIVATE_KEY_SIZE]u8) !KeyPair {
        return KeyPair.fromBytes(public_key, private_key);
    }

    /// Derive compressed SEC1 public key bytes from private key bytes.
    pub fn publicKey(private_key: [SECP256R1_PRIVATE_KEY_SIZE]u8) ![SECP256R1_PUBLIC_KEY_SIZE]u8 {
        return secp256r1PublicKey(private_key);
    }

    /// Maximum DER-encoded signature length (use for `signMessageDer` buffer).
    pub const DER_SIGNATURE_MAX = SECP256R1_DER_SIGNATURE_MAX;

    /// Sign an arbitrary-length message and return a DER-encoded ECDSA
    /// signature written into `buf`. The scheme hashes the message internally
    /// (SHA-256). Returns a slice of `buf` (length <= DER_SIGNATURE_MAX).
    /// FIPS 186 / stdlib-backed (no hand-rolled ASN.1).
    pub fn signMessageDer(
        message: []const u8,
        private_key: [SECP256R1_PRIVATE_KEY_SIZE]u8,
        buf: *[SECP256R1_DER_SIGNATURE_MAX]u8,
    ) ![]u8 {
        const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        const secret_key = Scheme.SecretKey.fromBytes(private_key) catch return error.InvalidPrivateKey;
        const kp = Scheme.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
        const sig = kp.sign(message, null) catch return error.SigningFailed;
        return sig.toDer(buf);
    }

    /// Verify a DER-encoded ECDSA signature over an arbitrary-length message.
    /// `public_key_sec1` is a compressed (33B) or uncompressed (65B) SEC1 key.
    pub fn verifyMessageDer(
        message: []const u8,
        der_sig: []const u8,
        public_key_sec1: []const u8,
    ) bool {
        const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        const pub_key = Scheme.PublicKey.fromSec1(public_key_sec1) catch return false;
        const sig = Scheme.Signature.fromDer(der_sig) catch return false;
        sig.verify(message, pub_key) catch return false;
        return true;
    }
};

/// secp384r1 module with clean API (NIST P-384)
pub const secp384r1 = struct {
    pub const KeyPair = Secp384r1KeyPair;

    /// Generate a new keypair
    pub fn generate() KeyPair {
        return generateSecp384r1();
    }

    /// Sign a 48-byte message (fixed-width r||s output)
    pub fn sign(message: [48]u8, private_key: [SECP384R1_PRIVATE_KEY_SIZE]u8) ![SECP384R1_SIGNATURE_SIZE]u8 {
        return signSecp384r1(message, private_key);
    }

    /// Verify a fixed-width signature
    pub fn verify(message: [48]u8, signature: [SECP384R1_SIGNATURE_SIZE]u8, public_key: [SECP384R1_PUBLIC_KEY_SIZE]u8) bool {
        return verifySecp384r1(message, signature, public_key);
    }

    /// Import a keypair from raw bytes and verify the public key matches.
    pub fn fromBytes(public_key: [SECP384R1_PUBLIC_KEY_SIZE]u8, private_key: [SECP384R1_PRIVATE_KEY_SIZE]u8) !KeyPair {
        return KeyPair.fromBytes(public_key, private_key);
    }

    /// Derive compressed SEC1 public key bytes from private key bytes.
    pub fn publicKey(private_key: [SECP384R1_PRIVATE_KEY_SIZE]u8) ![SECP384R1_PUBLIC_KEY_SIZE]u8 {
        return secp384r1PublicKey(private_key);
    }

    /// Maximum DER-encoded signature length (use for `signMessageDer` buffer).
    pub const DER_SIGNATURE_MAX = SECP384R1_DER_SIGNATURE_MAX;

    /// Sign an arbitrary-length message and return a DER-encoded ECDSA
    /// signature written into `buf`. The scheme hashes the message internally
    /// (SHA-384). Returns a slice of `buf` (length <= DER_SIGNATURE_MAX).
    /// FIPS 186 / stdlib-backed (no hand-rolled ASN.1).
    pub fn signMessageDer(
        message: []const u8,
        private_key: [SECP384R1_PRIVATE_KEY_SIZE]u8,
        buf: *[SECP384R1_DER_SIGNATURE_MAX]u8,
    ) ![]u8 {
        const Scheme = std.crypto.sign.ecdsa.EcdsaP384Sha384;
        const secret_key = Scheme.SecretKey.fromBytes(private_key) catch return error.InvalidPrivateKey;
        const kp = Scheme.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
        const sig = kp.sign(message, null) catch return error.SigningFailed;
        return sig.toDer(buf);
    }

    /// Verify a DER-encoded ECDSA signature over an arbitrary-length message.
    /// `public_key_sec1` is a compressed (49B) or uncompressed (97B) SEC1 key.
    pub fn verifyMessageDer(
        message: []const u8,
        der_sig: []const u8,
        public_key_sec1: []const u8,
    ) bool {
        const Scheme = std.crypto.sign.ecdsa.EcdsaP384Sha384;
        const pub_key = Scheme.PublicKey.fromSec1(public_key_sec1) catch return false;
        const sig = Scheme.Signature.fromDer(der_sig) catch return false;
        sig.verify(message, pub_key) catch return false;
        return true;
    }
};

// =============================================================================
// ASYNC CONVENIENCE FUNCTIONS
// =============================================================================

/// Async convenience functions that use the async_crypto module
/// Import async_crypto to use these functions in async contexts
pub const Async = struct {
    /// Get async asymmetric crypto handler
    /// Usage: const async_asym = zcrypto.asym.Async.init(allocator, runtime);
    pub fn init(allocator: std.mem.Allocator, runtime: anytype) !@import("async_crypto.zig").AsyncAsymmetric {
        return @import("async_crypto.zig").AsyncAsymmetric.init(allocator, runtime);
    }

    /// Async Ed25519 key generation
    /// Returns Task that can be awaited for Ed25519KeyPair
    pub fn generateEd25519Async(allocator: std.mem.Allocator, runtime: anytype) @import("async_crypto.zig").Task(Ed25519KeyPair) {
        const async_asym = init(allocator, runtime) catch unreachable;
        return async_asym.generateEd25519KeypairAsync();
    }

    /// Async Ed25519 signing
    /// Returns Task that can be awaited for signature result
    pub fn ed25519SignAsync(allocator: std.mem.Allocator, runtime: anytype, private_key: [ED25519_PRIVATE_KEY_SIZE]u8, message: []const u8) @import("async_crypto.zig").Task(@import("async_crypto.zig").AsyncCryptoResult) {
        const async_asym = init(allocator, runtime) catch unreachable;
        const ed25519_private_key = @import("async_crypto.zig").AsymCrypto.Ed25519.PrivateKey{ .bytes = private_key };
        return async_asym.ed25519SignAsync(ed25519_private_key, message);
    }

    /// Async secp256k1 key generation
    /// Returns Task that can be awaited for Secp256k1KeyPair
    pub fn generateSecp256k1Async(allocator: std.mem.Allocator, runtime: anytype) @import("async_crypto.zig").Task(Secp256k1KeyPair) {
        const async_asym = init(allocator, runtime) catch unreachable;
        return async_asym.generateSecp256k1KeypairAsync();
    }

    /// Async X25519 key exchange
    /// Returns Task that can be awaited for shared secret
    pub fn x25519KeyExchangeAsync(allocator: std.mem.Allocator, runtime: anytype, our_private: [CURVE25519_PRIVATE_KEY_SIZE]u8, their_public: [CURVE25519_PUBLIC_KEY_SIZE]u8) @import("async_crypto.zig").Task(@import("async_crypto.zig").AsyncCryptoResult) {
        const async_asym = init(allocator, runtime) catch unreachable;
        const x25519_private = @import("async_crypto.zig").AsymCrypto.X25519.PrivateKey{ .bytes = our_private };
        const x25519_public = @import("async_crypto.zig").AsymCrypto.X25519.PublicKey{ .bytes = their_public };
        return async_asym.x25519KeyExchangeAsync(x25519_private, x25519_public);
    }

    /// Async Ed25519 batch signature verification
    /// Verifies multiple signatures in parallel for improved performance
    pub fn ed25519BatchVerifyAsync(allocator: std.mem.Allocator, runtime: anytype, verifications: []const Ed25519VerifyData) @import("async_crypto.zig").Task([]bool) {
        const async_asym = init(allocator, runtime) catch unreachable;
        return async_asym.ed25519BatchVerifyAsync(verifications);
    }
};

/// Data structure for batch Ed25519 verification
pub const Ed25519VerifyData = struct {
    public_key: [ED25519_PUBLIC_KEY_SIZE]u8,
    message: []const u8,
    signature: [ED25519_SIGNATURE_SIZE]u8,

    pub fn fromKeypair(keypair: Ed25519KeyPair, message: []const u8, signature: [ED25519_SIGNATURE_SIZE]u8) Ed25519VerifyData {
        return Ed25519VerifyData{
            .public_key = keypair.public_key,
            .message = message,
            .signature = signature,
        };
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
    const seed = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 42);
        break :blk bytes;
    };

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

test "ed25519 RFC 8032 test vector 1" {
    const seed = decodeHex(32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const expected_public = decodeHex(32, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const expected_signature = decodeHex(64, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    const keypair = ed25519.generateFromSeed(seed);
    try std.testing.expectEqualSlices(u8, &expected_public, &keypair.public_key);

    const signature = try ed25519.sign("", keypair.private_key);
    try std.testing.expectEqualSlices(u8, &expected_signature, &signature);
    try std.testing.expect(ed25519.verify("", signature, keypair.public_key));

    var tampered = signature;
    tampered[0] ^= 0x01;
    try std.testing.expect(!ed25519.verify("", tampered, keypair.public_key));
}

test "ed25519 key import export validates matching public key" {
    const keypair = ed25519.generate();

    const public_key = keypair.publicKeyBytes();
    var private_key = keypair.privateKeyBytes();
    defer std.crypto.secureZero(u8, &private_key);

    const imported = try ed25519.fromBytes(public_key, private_key);
    try std.testing.expectEqualSlices(u8, &public_key, &imported.public_key);
    try std.testing.expectEqualSlices(u8, &private_key, &imported.private_key);
    try std.testing.expectEqualSlices(u8, &public_key, &try ed25519.publicKey(private_key));

    var wrong_public = public_key;
    wrong_public[0] ^= 0x01;
    try std.testing.expectError(error.InvalidPublicKey, ed25519.fromBytes(wrong_public, private_key));
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

test "x25519 RFC 7748 test vector" {
    const alice_private = decodeHex(32, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const alice_public_expected = decodeHex(32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const bob_private = decodeHex(32, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const bob_public_expected = decodeHex(32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const shared_expected = decodeHex(32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    const alice_public = try x25519.publicKeyChecked(alice_private);
    const bob_public = try x25519.publicKeyChecked(bob_private);
    try std.testing.expectEqualSlices(u8, &alice_public_expected, &alice_public);
    try std.testing.expectEqualSlices(u8, &bob_public_expected, &bob_public);

    const alice_shared = try x25519.dh(alice_private, bob_public);
    const bob_shared = try x25519.dh(bob_private, alice_public);
    try std.testing.expectEqualSlices(u8, &shared_expected, &alice_shared);
    try std.testing.expectEqualSlices(u8, &shared_expected, &bob_shared);
}

test "x25519 key import export validates matching public key" {
    const keypair = x25519.generate();

    const public_key = keypair.publicKeyBytes();
    var private_key = keypair.privateKeyBytes();
    defer std.crypto.secureZero(u8, &private_key);

    const imported = try x25519.fromBytes(public_key, private_key);
    try std.testing.expectEqualSlices(u8, &public_key, &imported.public_key);
    try std.testing.expectEqualSlices(u8, &private_key, &imported.private_key);
    try std.testing.expectEqualSlices(u8, &public_key, &try x25519.publicKeyChecked(private_key));

    var wrong_public = public_key;
    wrong_public[0] ^= 0x01;
    try std.testing.expectError(error.InvalidPublicKey, x25519.fromBytes(wrong_public, private_key));
}

test "secp256k1 keypair generation and signing" {
    const keypair = secp256k1.generate();
    const message = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0xAB);
        break :blk bytes;
    }; // Hash of message

    const signature = try keypair.sign(message);
    const valid = keypair.verify(message, signature);

    try std.testing.expect(valid);

    // Test with different message
    const wrong_message = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0xCD);
        break :blk bytes;
    };
    const invalid = keypair.verify(wrong_message, signature);
    try std.testing.expect(!invalid);
}

test "secp256r1 keypair generation and signing" {
    const keypair = secp256r1.generate();
    const message = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0xEF);
        break :blk bytes;
    }; // Hash of message

    const signature = try keypair.sign(message);
    const valid = keypair.verify(message, signature);

    try std.testing.expect(valid);

    // Test with different message
    const wrong_message = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0x12);
        break :blk bytes;
    };
    const invalid = keypair.verify(wrong_message, signature);
    try std.testing.expect(!invalid);
}

test "secp256k1 standalone functions" {
    const keypair = secp256k1.generate();
    const message = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0x34);
        break :blk bytes;
    };

    const signature = try secp256k1.sign(message, keypair.private_key);
    const valid = secp256k1.verify(message, signature, keypair.public_key_compressed);

    try std.testing.expect(valid);
}

test "secp256k1 dual public key formats" {
    const keypair = secp256k1.generate();

    // Test both public key formats exist and have correct lengths
    const compressed = keypair.publicKey(.compressed);
    const x_only = keypair.publicKey(.x_only);

    try std.testing.expectEqual(@as(usize, 33), compressed.len);
    try std.testing.expectEqual(@as(usize, 32), x_only.len);

    // Test that the keypair fields are properly initialized (non-zero)
    var compressed_all_zero = true;
    for (keypair.public_key_compressed) |byte| {
        if (byte != 0) {
            compressed_all_zero = false;
            break;
        }
    }
    try std.testing.expect(!compressed_all_zero);

    var x_only_all_zero = true;
    for (keypair.public_key_x) |byte| {
        if (byte != 0) {
            x_only_all_zero = false;
            break;
        }
    }
    try std.testing.expect(!x_only_all_zero);
}

test "secp256r1 standalone functions" {
    const keypair = secp256r1.generate();
    const message = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0x56);
        break :blk bytes;
    };

    const signature = try secp256r1.sign(message, keypair.private_key);
    const valid = secp256r1.verify(message, signature, keypair.public_key);

    try std.testing.expect(valid);
}

test "secp256r1 key import export validates matching public key" {
    const keypair = secp256r1.generate();

    const public_key = keypair.publicKeyBytes();
    var private_key = keypair.privateKeyBytes();
    defer std.crypto.secureZero(u8, &private_key);

    const imported = try secp256r1.fromBytes(public_key, private_key);
    try std.testing.expectEqualSlices(u8, &public_key, &imported.public_key);
    try std.testing.expectEqualSlices(u8, &private_key, &imported.private_key);
    try std.testing.expectEqualSlices(u8, &public_key, &try secp256r1.publicKey(private_key));

    var wrong_public = public_key;
    wrong_public[0] ^= 0x01;
    try std.testing.expectError(error.InvalidPublicKey, secp256r1.fromBytes(wrong_public, private_key));
}

test "secp384r1 keypair generation and signing" {
    const keypair = secp384r1.generate();
    var message: [48]u8 = undefined;
    @memset(&message, 0x38);

    const signature = try secp384r1.sign(message, keypair.private_key);
    try std.testing.expect(secp384r1.verify(message, signature, keypair.public_key));

    var tampered = message;
    tampered[0] ^= 0xFF;
    try std.testing.expect(!secp384r1.verify(tampered, signature, keypair.public_key));
}

test "secp384r1 key import export validates matching public key" {
    const keypair = secp384r1.generate();

    const public_key = keypair.publicKeyBytes();
    var private_key = keypair.privateKeyBytes();
    defer std.crypto.secureZero(u8, &private_key);

    const imported = try secp384r1.fromBytes(public_key, private_key);
    try std.testing.expectEqualSlices(u8, &public_key, &imported.public_key);
    try std.testing.expectEqualSlices(u8, &private_key, &imported.private_key);
    try std.testing.expectEqualSlices(u8, &public_key, &try secp384r1.publicKey(private_key));

    var wrong_public = public_key;
    wrong_public[0] ^= 0x01;
    try std.testing.expectError(error.InvalidPublicKey, secp384r1.fromBytes(wrong_public, private_key));
}

test "secp256r1 sign->DER->verify round trip" {
    const keypair = secp256r1.generate();
    const message = "TLS 1.3 CertificateVerify content (P-256)";

    var der_buf: [secp256r1.DER_SIGNATURE_MAX]u8 = undefined;
    const der_sig = try secp256r1.signMessageDer(message, keypair.private_key, &der_buf);

    try std.testing.expect(secp256r1.verifyMessageDer(message, der_sig, &keypair.public_key));

    // Tampered message must fail closed.
    try std.testing.expect(!secp256r1.verifyMessageDer("different content", der_sig, &keypair.public_key));

    // Malformed DER must fail closed, not crash.
    const bad_der = [_]u8{ 0x30, 0x00, 0x01, 0x02 };
    try std.testing.expect(!secp256r1.verifyMessageDer(message, &bad_der, &keypair.public_key));
}

test "secp384r1 sign->DER->verify round trip" {
    const keypair = secp384r1.generate();
    const message = "TLS 1.3 CertificateVerify content (P-384)";

    var der_buf: [secp384r1.DER_SIGNATURE_MAX]u8 = undefined;
    const der_sig = try secp384r1.signMessageDer(message, keypair.private_key, &der_buf);

    try std.testing.expect(secp384r1.verifyMessageDer(message, der_sig, &keypair.public_key));

    // Tampered message must fail closed.
    try std.testing.expect(!secp384r1.verifyMessageDer("different content", der_sig, &keypair.public_key));

    // Malformed DER must fail closed, not crash.
    const bad_der = [_]u8{ 0x30, 0x00, 0x01, 0x02 };
    try std.testing.expect(!secp384r1.verifyMessageDer(message, &bad_der, &keypair.public_key));
}
