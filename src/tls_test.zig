//! TLS Integration Tests and Examples
//!
//! Demonstrates usage of the high-level TLS API

const std = @import("std");
const zcrypto = @import("root.zig");

test "TLS configuration builder pattern" {
    const allocator = std.testing.allocator;
    
    // Example: Basic client configuration
    const client_config = zcrypto.tls.config.TlsConfig.init(allocator)
        .withServerName("example.com")
        .withInsecureSkipVerify(false);
    defer client_config.deinit();
    
    try std.testing.expectEqualStrings("example.com", client_config.server_name.?);
    try std.testing.expectEqual(false, client_config.insecure_skip_verify);
}

test "TLS configuration with ALPN" {
    const allocator = std.testing.allocator;
    
    const protocols = [_][]const u8{ "h2", "http/1.1" };
    const config = zcrypto.tls.config.TlsConfig.init(allocator)
        .withALPN(@constCast(&protocols));
    defer config.deinit();
    
    try std.testing.expectEqual(@as(usize, 2), config.alpn_protocols.?.len);
    try std.testing.expectEqualStrings("h2", config.alpn_protocols.?[0]);
    try std.testing.expectEqualStrings("http/1.1", config.alpn_protocols.?[1]);
}

test "TLS server configuration" {
    const allocator = std.testing.allocator;
    
    // Create dummy certificate and key
    const cert = zcrypto.tls.config.Certificate{
        .der = try allocator.dupe(u8, "dummy certificate data"),
    };
    defer cert.deinit(allocator);
    
    const key = zcrypto.tls.config.PrivateKey{
        .key_type = .ed25519,
        .der = try allocator.dupe(u8, "dummy key data"),
    };
    defer key.deinit(allocator);
    
    const config = zcrypto.tls.config.TlsConfig.init(allocator)
        .withCertificate(cert, key)
        .withALPN(&[_][]const u8{ "h2", "http/1.1" });
    defer config.deinit();
    
    try config.validate();
    try std.testing.expect(config.certificates != null);
    try std.testing.expect(config.private_key != null);
}

test "TLS cipher suite properties" {
    const suite = zcrypto.tls.config.CipherSuite.TLS_AES_128_GCM_SHA256;
    
    try std.testing.expectEqual(@as(usize, 16), suite.keySize());
    try std.testing.expectEqualStrings("TLS_AES_128_GCM_SHA256", suite.toString());
    try std.testing.expectEqual(zcrypto.tls.config.HashAlgorithm.sha256, suite.hashAlgorithm());
}

test "TLS key schedule" {
    const allocator = std.testing.allocator;
    
    var key_schedule = try zcrypto.tls.KeySchedule.init(allocator, .sha256);
    defer key_schedule.deinit();
    
    // Derive early secret (no PSK)
    try key_schedule.deriveEarlySecret(null);
    
    // Simulate ECDHE secret
    const ecdhe_secret = [_]u8{0x42} ** 32;
    try key_schedule.deriveHandshakeSecret(&ecdhe_secret);
    
    // Derive master secret
    try key_schedule.deriveMasterSecret();
    
    // All secrets should be 32 bytes for SHA-256
    try std.testing.expectEqual(@as(usize, 32), key_schedule.early_secret.len);
    try std.testing.expectEqual(@as(usize, 32), key_schedule.handshake_secret.len);
    try std.testing.expectEqual(@as(usize, 32), key_schedule.master_secret.len);
}

test "TLS transcript hash" {
    var transcript = zcrypto.tls.TranscriptHash.init(.sha256);
    
    // Update with some test data
    transcript.update("ClientHello");
    transcript.update("ServerHello");
    
    var hash_out: [32]u8 = undefined;
    transcript.final(&hash_out);
    
    // Hash should be non-zero
    var all_zero = true;
    for (hash_out) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "TLS AEAD cipher" {
    const allocator = std.testing.allocator;
    
    const key = [_]u8{0x42} ** 16;
    const iv = [_]u8{0x69} ** 12;
    
    var cipher = try zcrypto.tls.AeadCipher.init(
        allocator,
        .TLS_AES_128_GCM_SHA256,
        &key,
        &iv,
    );
    defer cipher.deinit();
    
    // Test encryption/decryption
    const plaintext = "Hello, TLS!";
    const aad = "additional data";
    const nonce = [_]u8{0x13} ** 12;
    
    const ciphertext = try cipher.encrypt(allocator, &nonce, plaintext, aad);
    defer ciphertext.deinit();
    
    const decrypted = try cipher.decrypt(allocator, &nonce, ciphertext.data, &ciphertext.tag, aad);
    defer if (decrypted) |d| allocator.free(d);
    
    try std.testing.expect(decrypted != null);
    try std.testing.expectEqualStrings(plaintext, decrypted.?);
}

// Example: Complete TLS client usage
pub fn exampleTlsClient() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Configure TLS client
    const config = zcrypto.tls.config.TlsConfig.init(allocator)
        .withServerName("example.com")
        .withALPN(&[_][]const u8{ "h2", "http/1.1" })
        .withInsecureSkipVerify(false);
    defer config.deinit();
    
    // Connect to server
    const stream = try std.net.tcpConnectToHost(allocator, "example.com", 443);
    defer stream.close();
    
    // Create TLS client
    var client = try zcrypto.tls.client.TlsClient.init(allocator, stream, config);
    defer client.deinit();
    
    // Perform handshake
    try client.handshake();
    
    // Send HTTP request
    const request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    _ = try client.write(request);
    
    // Read response
    var buffer: [4096]u8 = undefined;
    const n = try client.read(&buffer);
    std.debug.print("Received {} bytes\n", .{n});
    
    // Close connection
    try client.close();
}

// Example: Complete TLS server usage
pub fn exampleTlsServer() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Load certificate and private key (in real usage, load from files)
    const cert = zcrypto.tls.config.Certificate{
        .der = try allocator.dupe(u8, "certificate data"),
    };
    defer cert.deinit(allocator);
    
    const key = zcrypto.tls.config.PrivateKey{
        .key_type = .ed25519,
        .der = try allocator.dupe(u8, "private key data"),
    };
    defer key.deinit(allocator);
    
    // Configure TLS server
    const config = zcrypto.tls.config.TlsConfig.init(allocator)
        .withCertificate(cert, key)
        .withALPN(&[_][]const u8{ "h2", "http/1.1" });
    defer config.deinit();
    
    // Start listening
    var server = try zcrypto.tls.server.TlsServer.listen(allocator, "0.0.0.0", 8443, config);
    defer server.close();
    
    std.debug.print("TLS server listening on port 8443\n", .{});
    
    // Accept connections
    while (true) {
        var conn = try server.accept();
        defer conn.deinit();
        defer conn.close() catch {};
        
        // Handle connection in a thread (simplified for example)
        var buffer: [4096]u8 = undefined;
        const n = try conn.read(&buffer);
        
        if (n > 0) {
            std.debug.print("Received: {s}\n", .{buffer[0..n]});
            
            // Send response
            const response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, TLS!\r\n";
            _ = try conn.write(response);
        }
    }
}

test "TLS version strings" {
    try std.testing.expectEqualStrings("TLS 1.2", zcrypto.tls.config.TlsVersion.tls_1_2.toString());
    try std.testing.expectEqualStrings("TLS 1.3", zcrypto.tls.config.TlsVersion.tls_1_3.toString());
}

test "TLS configuration validation" {
    const allocator = std.testing.allocator;
    
    // Test invalid version range
    const invalid_config = zcrypto.tls.config.TlsConfig.init(allocator)
        .withVersions(.tls_1_3, .tls_1_2);
    defer invalid_config.deinit();
    
    try std.testing.expectError(error.InvalidVersionRange, invalid_config.validate());
    
    // Test valid configuration
    const valid_config = zcrypto.tls.config.TlsConfig.init(allocator)
        .withVersions(.tls_1_2, .tls_1_3);
    defer valid_config.deinit();
    
    try valid_config.validate();
}

test "TLS configuration cloning" {
    const allocator = std.testing.allocator;
    
    const original = zcrypto.tls.config.TlsConfig.init(allocator)
        .withServerName("example.com")
        .withInsecureSkipVerify(true);
    defer original.deinit();
    
    const cloned = try original.clone(allocator);
    defer cloned.deinit();
    
    try std.testing.expectEqualStrings("example.com", cloned.server_name.?);
    try std.testing.expectEqual(true, cloned.insecure_skip_verify);
    
    // Ensure deep copy
    try std.testing.expect(original.server_name.?.ptr != cloned.server_name.?.ptr);
}

test "TLS X25519 key exchange" {
    const allocator = std.testing.allocator;
    
    // Generate client and server keypairs
    const client_keypair = zcrypto.asym.x25519.generate();
    const server_keypair = zcrypto.asym.x25519.generate();
    
    // Perform key exchange
    const client_shared = zcrypto.asym.x25519.dh(client_keypair.private_key, server_keypair.public_key);
    const server_shared = zcrypto.asym.x25519.dh(server_keypair.private_key, client_keypair.public_key);
    
    // Shared secrets should match
    try std.testing.expectEqualSlices(u8, &client_shared, &server_shared);
}

test "TLS finished verify data computation" {
    const allocator = std.testing.allocator;
    
    // Initialize a mock TLS client with required fields
    const config = zcrypto.tls.config.TlsConfig.init(allocator);
    defer config.deinit();
    
    // Create a dummy stream
    const address = try std.net.Address.parseIp("127.0.0.1", 443);
    const stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    
    var client = try zcrypto.tls.client.TlsClient.init(allocator, stream, config);
    defer client.deinit();
    
    // Set up required state for finished computation
    client.cipher_suite = .TLS_AES_128_GCM_SHA256;
    client.client_handshake_secret = [_]u8{0x42} ** 32;
    client.server_handshake_secret = [_]u8{0x69} ** 32;
    
    // Test finished verify data computation
    const client_verify = try client.computeFinishedVerifyData(true);
    defer allocator.free(client_verify);
    
    const server_verify = try client.computeFinishedVerifyData(false);
    defer allocator.free(server_verify);
    
    // Verify data should be 32 bytes for SHA256
    try std.testing.expectEqual(@as(usize, 32), client_verify.len);
    try std.testing.expectEqual(@as(usize, 32), server_verify.len);
    
    // Client and server verify data should be different
    try std.testing.expect(!std.mem.eql(u8, client_verify, server_verify));
}

test "TLS key schedule with real ECDHE" {
    const allocator = std.testing.allocator;
    
    // Generate ECDHE shared secret
    const client_keypair = zcrypto.asym.x25519.generate();
    const server_keypair = zcrypto.asym.x25519.generate();
    const shared_secret = zcrypto.asym.x25519.dh(client_keypair.private_key, server_keypair.public_key);
    
    // Initialize key schedule
    var key_schedule = try zcrypto.tls.KeySchedule.init(allocator, .sha256);
    defer key_schedule.deinit();
    
    // Derive secrets
    try key_schedule.deriveEarlySecret(null);
    try key_schedule.deriveHandshakeSecret(&shared_secret);
    try key_schedule.deriveMasterSecret();
    
    // All secrets should be 32 bytes for SHA256
    try std.testing.expectEqual(@as(usize, 32), key_schedule.early_secret.len);
    try std.testing.expectEqual(@as(usize, 32), key_schedule.handshake_secret.len);
    try std.testing.expectEqual(@as(usize, 32), key_schedule.master_secret.len);
    
    // Secrets should be different
    try std.testing.expect(!std.mem.eql(u8, key_schedule.early_secret, key_schedule.handshake_secret));
    try std.testing.expect(!std.mem.eql(u8, key_schedule.handshake_secret, key_schedule.master_secret));
}

test "TLS traffic key derivation" {
    const allocator = std.testing.allocator;
    
    // Create test secret
    const secret = [_]u8{0x42} ** 32;
    
    // Test key derivation for AES-128-GCM
    const key = try zcrypto.kdf.hkdfExpandLabel(allocator, &secret, "key", "", 16);
    defer allocator.free(key);
    
    const iv = try zcrypto.kdf.hkdfExpandLabel(allocator, &secret, "iv", "", 12);
    defer allocator.free(iv);
    
    try std.testing.expectEqual(@as(usize, 16), key.len);
    try std.testing.expectEqual(@as(usize, 12), iv.len);
    
    // Keys should be deterministic but different
    try std.testing.expect(!std.mem.eql(u8, key[0..12], iv));
}

test "TLS AEAD cipher with proper nonce" {
    const allocator = std.testing.allocator;
    
    // Create proper traffic keys
    const key = [_]u8{0x42} ** 16;
    const base_iv = [_]u8{0x69} ** 12;
    
    var cipher = try zcrypto.tls.AeadCipher.init(
        allocator,
        .TLS_AES_128_GCM_SHA256,
        &key,
        &base_iv,
    );
    defer cipher.deinit();
    
    // Test encryption with sequence number
    const plaintext = "Hello, TLS 1.3!";
    const aad = "TLS record header";
    
    // Compute proper nonce (base_iv XOR sequence_number)
    var nonce = base_iv;
    const seq_num: u64 = 42;
    const seq_bytes = std.mem.toBytes(seq_num);
    for (0..8) |i| {
        nonce[4 + i] ^= seq_bytes[7 - i]; // Big-endian
    }
    
    const ciphertext = try cipher.encrypt(allocator, &nonce, plaintext, aad);
    defer ciphertext.deinit();
    
    const decrypted = try cipher.decrypt(allocator, &nonce, ciphertext.data, &ciphertext.tag, aad);
    defer if (decrypted) |d| allocator.free(d);
    
    try std.testing.expect(decrypted != null);
    try std.testing.expectEqualStrings(plaintext, decrypted.?);
}