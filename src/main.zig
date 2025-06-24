const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🔐 zcrypto v{s} - Modern Cryptography for Zig\n\n", .{zcrypto.version});

    // Hash example
    std.debug.print("📝 Hash Functions:\n", .{});
    const message = "Hello, zcrypto!";
    const hash_result = zcrypto.hash.sha256(message);
    var hex_buf: [64]u8 = undefined;
    const hex = zcrypto.hash.toHex([32]u8, hash_result, &hex_buf);
    std.debug.print("  SHA-256(\"{s}\") = {s}\n", .{ message, hex });    // Digital signatures (TODO: Fix Ed25519 for Zig 0.15)
    std.debug.print("\n✍️  Digital Signatures:\n", .{});
    // const keypair = zcrypto.asym.ed25519.generate();
    // const test_message = "Sign this message!";
    // const signature = keypair.sign(test_message);
    // const is_valid = keypair.verify(test_message, signature);
    std.debug.print("  Ed25519 implementation pending (API changes in Zig 0.15)\n", .{});
    // std.debug.print("  Signature valid: {}\n", .{is_valid});
    
    // Symmetric encryption
    std.debug.print("\n🔒 Symmetric Encryption:\n", .{});
    const key = zcrypto.rand.randomArray(16);
    const nonce = zcrypto.rand.randomArray(12);
    const plaintext = "Secret message for AES-GCM!";
    const aad = "metadata";

    const encrypted = try zcrypto.sym.encryptAes128Gcm(allocator, key, nonce, plaintext, aad);
    defer encrypted.deinit();    std.debug.print("  Encrypted {} bytes with AES-128-GCM\n", .{plaintext.len});
    
    const decrypted = try zcrypto.sym.decryptAes128Gcm(allocator, key, nonce, encrypted.data, encrypted.tag, aad);
    defer if (decrypted) |d| allocator.free(d);
    std.debug.print("  Decryption successful: {}\n", .{decrypted != null});
    
    // QUIC/TLS integration
    std.debug.print("\n🌐 QUIC/TLS Integration:\n", .{});
    const connection_id = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
    const secrets = zcrypto.tls.deriveInitialSecrets(&connection_id, true);
    std.debug.print("  Derived QUIC initial secrets from connection ID\n", .{});
    
    const client_keys = try secrets.deriveKeys(allocator, true);
    defer client_keys.deinit();
    std.debug.print("  Derived client traffic keys\n", .{});
    
    // Key derivation
    std.debug.print("\n🔑 Key Derivation:\n", .{});
    const master_secret = "master-secret-for-demo";
    const derived_key = try zcrypto.kdf.deriveKey(allocator, master_secret, "application-key", 32);
    defer allocator.free(derived_key);
    std.debug.print("  Derived 32-byte application key from master secret\n", .{});
    
    // Random generation
    std.debug.print("\n🎲 Random Generation:\n", .{});
    const random_bytes = try zcrypto.rand.randomBytes(allocator, 16);
    defer allocator.free(random_bytes);
    std.debug.print("  Generated {} random bytes\n", .{random_bytes.len});
    
    // TLS Configuration Demo
    std.debug.print("\n🔐 TLS Configuration:\n", .{});
    const alpn_protocols = [_][]const u8{ "h2", "http/1.1" };
    const tls_config = zcrypto.tls.config.TlsConfig.init(allocator)
        .withServerName("example.com")
        .withALPN(@constCast(&alpn_protocols))
        .withInsecureSkipVerify(false);
    defer tls_config.deinit();
    
    try tls_config.validate();
    std.debug.print("  Configured TLS client for {s}\n", .{tls_config.server_name.?});
    std.debug.print("  Supported ALPN protocols: {} configured\n", .{tls_config.alpn_protocols.?.len});
    
    // TLS Key Schedule Demo
    var key_schedule = try zcrypto.tls.KeySchedule.init(allocator, .sha256);
    defer key_schedule.deinit();
    
    try key_schedule.deriveEarlySecret(null);
    const ecdhe_secret = [_]u8{0x42} ** 32;
    try key_schedule.deriveHandshakeSecret(&ecdhe_secret);
    try key_schedule.deriveMasterSecret();
    std.debug.print("  Completed TLS 1.3 key schedule derivation\n", .{});
    
    std.debug.print("\n✅ All cryptographic operations completed successfully!\n", .{});
    std.debug.print("🚀 Ready for integration with zquic and tokioZ!\n", .{});
}
