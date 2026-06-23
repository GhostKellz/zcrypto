//! Stable core zcrypto example for v1.0.x consumers.

const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try demoHashing();
    try demoAead(allocator);
    try demoSignatures();
    try demoKeyExchange();
    try demoKdf(allocator);
    try demoQuicAead();
}

fn demoHashing() !void {
    const digest = zcrypto.hash.sha256("stable core example");
    var sha_hex: [64]u8 = undefined;
    std.debug.print("sha256: {s}\n", .{zcrypto.hash.toHex([32]u8, digest, &sha_hex)});

    var blake = zcrypto.blake3.Blake3.init();
    blake.update("stable ");
    blake.update("blake3");
    const blake_digest = blake.final();
    var blake_hex: [64]u8 = undefined;
    std.debug.print("blake3: {s}\n", .{zcrypto.hash.toHex([32]u8, blake_digest, &blake_hex)});
}

fn demoAead(allocator: std.mem.Allocator) !void {
    var key: [32]u8 = undefined;
    zcrypto.rand.fill(&key);
    defer zcrypto.util.secureZero(&key);

    const plaintext = "authenticated payload";
    const ciphertext = try zcrypto.sym.encryptAesGcm(allocator, plaintext, &key);
    defer allocator.free(ciphertext);

    const decrypted = try zcrypto.sym.decryptAesGcm(allocator, ciphertext, &key);
    defer allocator.free(decrypted);
    if (!zcrypto.util.constantTimeCompare(plaintext, decrypted)) return error.AeadRoundTripFailed;

    const chacha = try zcrypto.sym.encryptChaCha20(allocator, plaintext, &key);
    defer allocator.free(chacha);
    const chacha_plain = try zcrypto.sym.decryptChaCha20(allocator, chacha, &key);
    defer allocator.free(chacha_plain);
    if (!std.mem.eql(u8, plaintext, chacha_plain)) return error.ChaChaRoundTripFailed;
}

fn demoSignatures() !void {
    var keypair = try zcrypto.kex.Ed25519.generateKeypair();
    defer keypair.zeroize();

    const message = "message to sign";
    const signature = try zcrypto.kex.Ed25519.sign(keypair.private_key, message);
    if (!try zcrypto.kex.Ed25519.verify(keypair.public_key, message, signature)) {
        return error.SignatureVerificationFailed;
    }
}

fn demoKeyExchange() !void {
    var alice = try zcrypto.kex.X25519.generateKeypair();
    defer alice.zeroize();
    var bob = try zcrypto.kex.X25519.generateKeypair();
    defer bob.zeroize();

    const alice_secret = try zcrypto.kex.X25519.computeSharedSecret(alice.private_key, bob.public_key);
    const bob_secret = try zcrypto.kex.X25519.computeSharedSecret(bob.private_key, alice.public_key);
    if (!zcrypto.util.constantTimeCompare(&alice_secret, &bob_secret)) return error.KeyExchangeFailed;
}

fn demoKdf(allocator: std.mem.Allocator) !void {
    const okm = try zcrypto.kdf.hkdfSha256(allocator, "ikm", "salt", "zcrypto-example", 32);
    defer allocator.free(okm);
    if (okm.len != 32) return error.InvalidKdfOutput;
}

fn demoQuicAead() !void {
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    zcrypto.rand.fill(&key);
    zcrypto.rand.fill(&nonce);
    defer zcrypto.util.secureZero(&key);

    var packet = std.mem.zeroes([64]u8);
    const plaintext = packet[0..24];
    @memset(plaintext, 0x5a);
    const aad = "quic header";

    var tag: [16]u8 = undefined;
    const aead = zcrypto.quic_crypto.QuicCrypto.AEAD.init(.aes_256_gcm, &key);
    _ = try aead.sealInPlace(&nonce, plaintext, aad, &tag);
    _ = try aead.openInPlace(&nonce, plaintext, aad, &tag);
}

test "stable core example compiles" {
    try std.testing.expect(true);
}
