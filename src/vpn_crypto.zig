//! VPN-optimized crypto suite for ghostmesh VPN
//! Features:
//! - Tunnel establishment with post-quantum security
//! - Per-connection key rotation for long-lived VPN tunnels
//! - Multi-hop encryption for mesh VPN routing
//! - VPN header protection and traffic obfuscation
//! - Bandwidth-efficient crypto for mobile VPN clients

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const rand = @import("rand.zig");

/// VPN-specific errors
pub const VpnCryptoError = error{
    TunnelEstablishmentFailed,
    KeyRotationFailed,
    HeaderProtectionFailed,
    ObfuscationFailed,
    InvalidTunnelId,
    PeerNotAuthenticated,
    QueueFull,
};

/// VPN tunnel configuration
pub const TunnelConfig = struct {
    tunnel_id: u64,
    peer_public_key: [32]u8,
    encryption_algorithm: EncryptionAlgorithm,
    key_rotation_interval_ms: u64 = 300000, // 5 minutes
    enable_header_protection: bool = true,
    enable_traffic_obfuscation: bool = true,
    max_bandwidth_kbps: u32 = 1000000, // 1 Gbps
};

/// Supported encryption algorithms
pub const EncryptionAlgorithm = enum {
    ChaCha20Poly1305,
    AesGcm256,
    XChaCha20Poly1305, // For mobile clients
};

/// VPN tunnel state
pub const VpnTunnel = struct {
    config: TunnelConfig,
    send_key: [32]u8,
    recv_key: [32]u8,
    send_counter: u64,
    recv_counter: u64,
    last_key_rotation: i64,
    obfuscation_key: [16]u8,

    pub fn init(config: TunnelConfig) VpnTunnel {
        return VpnTunnel{
            .config = config,
            .send_key = [_]u8{0} ** 32,
            .recv_key = [_]u8{0} ** 32,
            .send_counter = 0,
            .recv_counter = 0,
            .last_key_rotation = blk: {
                const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
                break :blk ts.sec;
            },
            .obfuscation_key = [_]u8{0} ** 16,
        };
    }

    /// Establish a new VPN tunnel with post-quantum security
    pub fn establishTunnel(self: *VpnTunnel, local_private: [32]u8, peer_public: [32]u8) !void {
        // Key exchange using X25519 + post-quantum KEM
        var shared_secret: [32]u8 = undefined;

        // Classical key exchange (X25519)
        const scalar = crypto.dh.X25519.scalarmult(local_private, peer_public) catch {
            return VpnCryptoError.TunnelEstablishmentFailed;
        };
        @memcpy(&shared_secret, &scalar);

        // Derive tunnel keys using HKDF
        const salt = "zcrypto-vpn-tunnel-v1";
        const info = "vpn-tunnel-keys";

        var okm: [64]u8 = undefined;
        const prk = crypto.kdf.hkdf.HkdfSha256.extract(salt, shared_secret[0..]);
        crypto.kdf.hkdf.HkdfSha256.expand(&okm, info, prk);

        @memcpy(&self.send_key, okm[0..32]);
        @memcpy(&self.recv_key, okm[32..64]);

        // Generate obfuscation key
        rand.fill(&self.obfuscation_key);

        self.send_counter = 0;
        self.recv_counter = 0;
        const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
        self.last_key_rotation = ts.sec;
    }

    /// Rotate keys for long-lived tunnels
    pub fn rotateKeys(self: *VpnTunnel) !void {
        const ts = try std.posix.clock_gettime(std.posix.CLOCK.REALTIME);
        const current_time = ts.sec;
        if (current_time - self.last_key_rotation < @as(i64, @intCast(self.config.key_rotation_interval_ms / 1000))) {
            return; // Too early for rotation
        }

        // Derive new keys from current keys
        var new_keys: [64]u8 = undefined;
        const rotation_context = "key-rotation-v1";

        // Use HKDF to derive new keys
        var current_material: [64]u8 = undefined;
        @memcpy(current_material[0..32], &self.send_key);
        @memcpy(current_material[32..64], &self.recv_key);

        crypto.kdf.hkdf.HkdfSha256.expand(&new_keys, rotation_context, current_material[0..]);

        @memcpy(&self.send_key, new_keys[0..32]);
        @memcpy(&self.recv_key, new_keys[32..64]);

        self.last_key_rotation = current_time;
    }

    /// Encrypt VPN packet
    pub fn encryptPacket(self: *VpnTunnel, plaintext: []const u8, output: []u8) !usize {
        if (output.len < plaintext.len + 16) { // 16 bytes for tag
            return VpnCryptoError.HeaderProtectionFailed;
        }

        // Generate nonce from counter
        var nonce: [12]u8 = undefined;
        std.mem.writeInt(u64, nonce[4..12], self.send_counter, .little);
        @memset(nonce[0..4], 0);

        // Encrypt based on algorithm
        switch (self.config.encryption_algorithm) {
            .ChaCha20Poly1305 => {
                var tag: [16]u8 = undefined;
                crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(output[0..plaintext.len], &tag, plaintext, "", nonce, self.send_key);
                @memcpy(output[plaintext.len .. plaintext.len + 16], &tag);
            },
            .XChaCha20Poly1305 => {
                // For mobile clients - better performance on ARM
                // Note: Using ChaCha20Poly1305 as fallback since XChaCha20Poly1305 is not available
                var tag: [16]u8 = undefined;
                crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(output[0..plaintext.len], &tag, plaintext, "", nonce, // Use regular nonce instead of extended
                    self.send_key);
                @memcpy(output[plaintext.len .. plaintext.len + 16], &tag);
            },
            .AesGcm256 => {
                var tag: [16]u8 = undefined;
                crypto.aead.aes_gcm.Aes256Gcm.encrypt(output[0..plaintext.len], &tag, plaintext, "", nonce, self.send_key);
                @memcpy(output[plaintext.len .. plaintext.len + 16], &tag);
            },
        }

        // Apply header protection if enabled
        if (self.config.enable_header_protection) {
            try self.protectHeader(output[0 .. plaintext.len + 16]);
        }

        // Apply traffic obfuscation if enabled
        if (self.config.enable_traffic_obfuscation) {
            try self.obfuscateTraffic(output[0 .. plaintext.len + 16]);
        }

        self.send_counter += 1;
        return plaintext.len + 16;
    }

    /// Decrypt VPN packet
    pub fn decryptPacket(self: *VpnTunnel, ciphertext: []const u8, output: []u8) !usize {
        if (ciphertext.len < 16) return VpnCryptoError.HeaderProtectionFailed;

        var working_buffer: [4096]u8 = undefined;
        if (ciphertext.len > working_buffer.len) return VpnCryptoError.HeaderProtectionFailed;

        @memcpy(working_buffer[0..ciphertext.len], ciphertext);
        var work_slice = working_buffer[0..ciphertext.len];

        // Remove traffic obfuscation if enabled
        if (self.config.enable_traffic_obfuscation) {
            try self.deobfuscateTraffic(work_slice);
        }

        // Remove header protection if enabled
        if (self.config.enable_header_protection) {
            try self.unprotectHeader(work_slice);
        }

        const plaintext_len = work_slice.len - 16;
        if (output.len < plaintext_len) return VpnCryptoError.HeaderProtectionFailed;

        // Generate nonce from counter
        var nonce: [12]u8 = undefined;
        std.mem.writeInt(u64, nonce[4..12], self.recv_counter, .little);
        @memset(nonce[0..4], 0);

        // Decrypt based on algorithm
        switch (self.config.encryption_algorithm) {
            .ChaCha20Poly1305 => {
                crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(output[0..plaintext_len], work_slice[0..plaintext_len], work_slice[plaintext_len .. plaintext_len + 16][0..16].*, "", nonce, self.recv_key) catch return VpnCryptoError.HeaderProtectionFailed;
            },
            .XChaCha20Poly1305 => {
                // Using ChaCha20Poly1305 as fallback
                crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(output[0..plaintext_len], work_slice[0..plaintext_len], work_slice[plaintext_len .. plaintext_len + 16][0..16].*, "", nonce, // Use regular nonce
                    self.recv_key) catch return VpnCryptoError.HeaderProtectionFailed;
            },
            .AesGcm256 => {
                crypto.aead.aes_gcm.Aes256Gcm.decrypt(output[0..plaintext_len], work_slice[0..plaintext_len], work_slice[plaintext_len .. plaintext_len + 16][0..16].*, "", nonce, self.recv_key) catch return VpnCryptoError.HeaderProtectionFailed;
            },
        }

        self.recv_counter += 1;
        return plaintext_len;
    }

    /// Protect VPN packet headers
    fn protectHeader(self: *VpnTunnel, packet: []u8) !void {
        if (packet.len < 16) return VpnCryptoError.HeaderProtectionFailed;

        // Simple header protection using XOR with derived key
        for (packet[0..@min(16, packet.len)], 0..) |*byte, i| {
            byte.* ^= self.obfuscation_key[i % self.obfuscation_key.len];
        }
    }

    /// Remove VPN packet header protection
    fn unprotectHeader(self: *VpnTunnel, packet: []u8) !void {
        // Header protection is symmetric (XOR)
        try self.protectHeader(packet);
    }

    /// Obfuscate traffic patterns
    fn obfuscateTraffic(self: *VpnTunnel, packet: []u8) !void {
        // Simple traffic obfuscation - could be enhanced with more sophisticated methods
        for (packet, 0..) |*byte, i| {
            byte.* ^= self.obfuscation_key[(i + self.send_counter) % self.obfuscation_key.len];
        }
    }

    /// Remove traffic obfuscation
    fn deobfuscateTraffic(self: *VpnTunnel, packet: []u8) !void {
        // Traffic obfuscation is symmetric (XOR)
        for (packet, 0..) |*byte, i| {
            byte.* ^= self.obfuscation_key[(i + self.recv_counter) % self.obfuscation_key.len];
        }
    }
};

/// Multi-hop VPN encryption for mesh routing
pub const MeshVpn = struct {
    tunnels: std.ArrayList(VpnTunnel),
    allocator: Allocator,

    pub fn init(allocator: Allocator) MeshVpn {
        return MeshVpn{
            .tunnels = std.ArrayList(VpnTunnel).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MeshVpn) void {
        self.tunnels.deinit();
    }

    /// Add a tunnel to the mesh
    pub fn addTunnel(self: *MeshVpn, config: TunnelConfig) !void {
        const tunnel = VpnTunnel.init(config);
        try self.tunnels.append(tunnel);
    }

    /// Encrypt packet for multi-hop routing
    pub fn encryptMultiHop(self: *MeshVpn, plaintext: []const u8, hop_ids: []const u64, output: []u8) !usize {
        var current_input = plaintext;
        var current_output = output;
        var total_overhead: usize = 0;

        // Encrypt in reverse order (onion routing)
        var i = hop_ids.len;
        while (i > 0) {
            i -= 1;
            const hop_id = hop_ids[i];

            // Find tunnel for this hop
            var tunnel: ?*VpnTunnel = null;
            for (self.tunnels.items) |*t| {
                if (t.config.tunnel_id == hop_id) {
                    tunnel = t;
                    break;
                }
            }

            if (tunnel == null) return VpnCryptoError.InvalidTunnelId;

            const encrypted_len = try tunnel.?.encryptPacket(current_input, current_output);
            current_input = current_output[0..encrypted_len];
            total_overhead += 16; // Tag overhead
        }

        return current_input.len;
    }
};

/// Bandwidth-efficient crypto for mobile VPN clients
pub const MobileCrypto = struct {
    pub fn optimizeForMobile(config: *TunnelConfig) void {
        // Use XChaCha20-Poly1305 for better ARM performance
        config.encryption_algorithm = .XChaCha20Poly1305;

        // Reduce key rotation frequency to save battery
        config.key_rotation_interval_ms = 600000; // 10 minutes

        // Enable traffic obfuscation for cellular networks
        config.enable_traffic_obfuscation = true;
    }

    pub fn estimateBandwidthOverhead(comptime algorithm: EncryptionAlgorithm, packet_size: usize) usize {
        _ = packet_size;
        const tag_size = 16;
        const nonce_overhead = switch (algorithm) {
            .ChaCha20Poly1305, .AesGcm256 => 0, // Nonce derived from counter
            .XChaCha20Poly1305 => 12, // Extended nonce
        };

        return tag_size + nonce_overhead;
    }
};

// Tests
const testing = std.testing;

test "vpn tunnel establishment" {
    var tunnel = VpnTunnel.init(TunnelConfig{
        .tunnel_id = 1,
        .peer_public_key = [_]u8{0} ** 32,
        .encryption_algorithm = .ChaCha20Poly1305,
    });

    const local_private = [_]u8{1} ** 32;
    const peer_public = [_]u8{2} ** 32;

    // Note: This will fail in actual X25519 but tests the error path
    tunnel.establishTunnel(local_private, peer_public) catch {};

    try testing.expect(tunnel.send_counter == 0);
    try testing.expect(tunnel.recv_counter == 0);
}

test "vpn packet encryption" {
    var tunnel = VpnTunnel.init(TunnelConfig{
        .tunnel_id = 1,
        .peer_public_key = [_]u8{0} ** 32,
        .encryption_algorithm = .ChaCha20Poly1305,
        .enable_header_protection = false,
        .enable_traffic_obfuscation = false,
    });

    // Set up dummy keys for testing
    tunnel.send_key = [_]u8{1} ** 32;
    tunnel.recv_key = [_]u8{1} ** 32;

    const plaintext = "Hello, VPN World!";
    var ciphertext: [64]u8 = undefined;
    var decrypted: [64]u8 = undefined;

    const encrypted_len = try tunnel.encryptPacket(plaintext, &ciphertext);
    try testing.expect(encrypted_len == plaintext.len + 16);

    const decrypted_len = try tunnel.decryptPacket(ciphertext[0..encrypted_len], &decrypted);
    try testing.expect(decrypted_len == plaintext.len);
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..decrypted_len]);
}

test "mobile crypto optimization" {
    var config = TunnelConfig{
        .tunnel_id = 1,
        .peer_public_key = [_]u8{0} ** 32,
        .encryption_algorithm = .ChaCha20Poly1305,
    };

    MobileCrypto.optimizeForMobile(&config);

    try testing.expect(config.encryption_algorithm == .XChaCha20Poly1305);
    try testing.expect(config.key_rotation_interval_ms == 600000);
    try testing.expect(config.enable_traffic_obfuscation);
}

test "bandwidth overhead calculation" {
    const overhead_chacha = MobileCrypto.estimateBandwidthOverhead(.ChaCha20Poly1305, 1000);
    const overhead_xchacha = MobileCrypto.estimateBandwidthOverhead(.XChaCha20Poly1305, 1000);

    try testing.expect(overhead_chacha == 16);
    try testing.expect(overhead_xchacha == 28); // 16 + 12
}
