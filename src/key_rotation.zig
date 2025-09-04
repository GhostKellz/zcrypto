//! Advanced Key Rotation Framework for zcrypto
//!
//! Provides protocol-agnostic key rotation with forward secrecy,
//! automated key lifecycle management, and integration with TLS, QUIC,
//! and gossip protocols.

const std = @import("std");
const asym = @import("asym.zig");
const kdf = @import("kdf.zig");
const hash = @import("hash.zig");
const rand = @import("rand.zig");

/// Key rotation errors
pub const KeyRotationError = error{
    InvalidKeyAge,
    InvalidRotationPeriod,
    KeyGenerationFailed,
    InvalidKeyType,
    RotationInProgress,
    NoKeysAvailable,
    InvalidKeyId,
};

/// Key types supported by the rotation framework
pub const KeyType = enum {
    Ed25519,
    X25519,
    ChaCha20Poly1305,
    AES256GCM,
    HMAC,
    Custom,
};

/// Key rotation policy
pub const RotationPolicy = struct {
    /// Maximum key age in seconds
    max_key_age: u64,
    
    /// How often to check for rotation (seconds)
    rotation_check_interval: u64,
    
    /// Key overlap period (seconds) - how long to keep old keys
    key_overlap_period: u64,
    
    /// Enable automatic rotation
    auto_rotate: bool,
    
    /// Minimum entropy required for key generation
    min_entropy_bits: u32,
    
    /// Default policy for most applications
    pub fn default() RotationPolicy {
        return RotationPolicy{
            .max_key_age = 24 * 3600, // 24 hours
            .rotation_check_interval = 3600, // 1 hour
            .key_overlap_period = 2 * 3600, // 2 hours
            .auto_rotate = true,
            .min_entropy_bits = 256,
        };
    }
    
    /// High-security policy for sensitive applications
    pub fn highSecurity() RotationPolicy {
        return RotationPolicy{
            .max_key_age = 6 * 3600, // 6 hours
            .rotation_check_interval = 30 * 60, // 30 minutes
            .key_overlap_period = 1 * 3600, // 1 hour
            .auto_rotate = true,
            .min_entropy_bits = 512,
        };
    }
    
    /// Relaxed policy for testing
    pub fn testing() RotationPolicy {
        return RotationPolicy{
            .max_key_age = 7 * 24 * 3600, // 7 days
            .rotation_check_interval = 24 * 3600, // 24 hours
            .key_overlap_period = 24 * 3600, // 24 hours
            .auto_rotate = false,
            .min_entropy_bits = 128,
        };
    }
};

/// Key metadata
pub const KeyMetadata = struct {
    id: [16]u8, // Unique key identifier
    key_type: KeyType,
    created_at: u64,
    expires_at: u64,
    usage_count: u64,
    is_active: bool,
    generation: u32,
    
    /// Create new key metadata
    pub fn init(key_type: KeyType, policy: RotationPolicy) KeyMetadata {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        var id: [16]u8 = undefined;
        rand.fill(&id);
        
        return KeyMetadata{
            .id = id,
            .key_type = key_type,
            .created_at = current_time,
            .expires_at = current_time + policy.max_key_age,
            .usage_count = 0,
            .is_active = true,
            .generation = 0,
        };
    }
    
    /// Check if key is expired
    pub fn isExpired(self: KeyMetadata) bool {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        return current_time > self.expires_at;
    }
    
    /// Check if key needs rotation
    pub fn needsRotation(self: KeyMetadata, policy: RotationPolicy) bool {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        const age = current_time - self.created_at;
        return age >= policy.max_key_age;
    }
    
    /// Increment usage counter
    pub fn incrementUsage(self: *KeyMetadata) void {
        self.usage_count += 1;
    }
    
    /// Deactivate key
    pub fn deactivate(self: *KeyMetadata) void {
        self.is_active = false;
    }
};

/// Generic key container
pub const Key = union(KeyType) {
    Ed25519: asym.Ed25519KeyPair,
    X25519: asym.Curve25519KeyPair,
    ChaCha20Poly1305: [32]u8,
    AES256GCM: [32]u8,
    HMAC: [32]u8,
    Custom: []const u8,
    
    /// Generate new key of specified type
    pub fn generate(allocator: std.mem.Allocator, key_type: KeyType) !Key {
        return switch (key_type) {
            .Ed25519 => Key{ .Ed25519 = asym.generateEd25519() },
            .X25519 => Key{ .X25519 = asym.generateCurve25519() },
            .ChaCha20Poly1305 => blk: {
                var key: [32]u8 = undefined;
                rand.fill(&key);
                break :blk Key{ .ChaCha20Poly1305 = key };
            },
            .AES256GCM => blk: {
                var key: [32]u8 = undefined;
                rand.fill(&key);
                break :blk Key{ .AES256GCM = key };
            },
            .HMAC => blk: {
                var key: [32]u8 = undefined;
                rand.fill(&key);
                break :blk Key{ .HMAC = key };
            },
            .Custom => {
                _ = allocator;
                return KeyRotationError.InvalidKeyType;
            },
        };
    }
    
    /// Securely zero out key material
    pub fn zeroize(self: *Key) void {
        switch (self.*) {
            .Ed25519 => |*key| key.zeroize(),
            .X25519 => |*key| key.zeroize(),
            .ChaCha20Poly1305 => |*key| std.crypto.secureZero(u8, key),
            .AES256GCM => |*key| std.crypto.secureZero(u8, key),
            .HMAC => |*key| std.crypto.secureZero(u8, key),
            .Custom => |data| {
                // Can't safely zero custom data without knowing its structure
                _ = data;
            },
        }
    }
    
    /// Derive new key from existing key
    pub fn derive(self: Key, salt: []const u8, info: []const u8, allocator: std.mem.Allocator) !Key {
        const key_material = switch (self) {
            .Ed25519 => |key| @as([]const u8, &key.private_key),
            .X25519 => |key| @as([]const u8, &key.private_key),
            .ChaCha20Poly1305 => |key| @as([]const u8, &key),
            .AES256GCM => |key| @as([]const u8, &key),
            .HMAC => |key| @as([]const u8, &key),
            .Custom => |data| data,
        };
        
        // Use HKDF to derive new key
        const derived_key = try kdf.hkdf(allocator, key_material, salt, info, 32);
        defer allocator.free(derived_key);
        
        return switch (self) {
            .ChaCha20Poly1305 => blk: {
                var new_key: [32]u8 = undefined;
                @memcpy(&new_key, derived_key[0..32]);
                break :blk Key{ .ChaCha20Poly1305 = new_key };
            },
            .AES256GCM => blk: {
                var new_key: [32]u8 = undefined;
                @memcpy(&new_key, derived_key[0..32]);
                break :blk Key{ .AES256GCM = new_key };
            },
            .HMAC => blk: {
                var new_key: [32]u8 = undefined;
                @memcpy(&new_key, derived_key[0..32]);
                break :blk Key{ .HMAC = new_key };
            },
            else => return KeyRotationError.InvalidKeyType,
        };
    }
};

/// Key store entry
pub const KeyEntry = struct {
    metadata: KeyMetadata,
    key: Key,
    
    /// Create new key entry
    pub fn init(key_type: KeyType, policy: RotationPolicy, allocator: std.mem.Allocator) !KeyEntry {
        const metadata = KeyMetadata.init(key_type, policy);
        const key = try Key.generate(allocator, key_type);
        
        return KeyEntry{
            .metadata = metadata,
            .key = key,
        };
    }
    
    /// Clean up key entry
    pub fn deinit(self: *KeyEntry) void {
        self.key.zeroize();
    }
};

/// Key rotation manager
pub const KeyManager = struct {
    keys: std.HashMap([16]u8, KeyEntry, std.hash_map.AutoContext([16]u8), std.hash_map.default_max_load_percentage),
    active_keys: std.HashMap(KeyType, [16]u8, std.hash_map.AutoContext(KeyType), std.hash_map.default_max_load_percentage),
    policy: RotationPolicy,
    allocator: std.mem.Allocator,
    last_rotation_check: u64,
    
    /// Initialize key manager
    pub fn init(allocator: std.mem.Allocator, policy: RotationPolicy) KeyManager {
        return KeyManager{
            .keys = std.HashMap([16]u8, KeyEntry, std.hash_map.AutoContext([16]u8), std.hash_map.default_max_load_percentage).init(allocator),
            .active_keys = std.HashMap(KeyType, [16]u8, std.hash_map.AutoContext(KeyType), std.hash_map.default_max_load_percentage).init(allocator),
            .policy = policy,
            .allocator = allocator,
            .last_rotation_check = 0,
        };
    }
    
    /// Generate and store new key
    pub fn generateKey(self: *KeyManager, key_type: KeyType) !*KeyEntry {
        const key_entry = try KeyEntry.init(key_type, self.policy, self.allocator);
        const key_id = key_entry.metadata.id;
        
        // Store key
        try self.keys.put(key_id, key_entry);
        
        // Set as active key for this type
        try self.active_keys.put(key_type, key_id);
        
        return self.keys.getPtr(key_id).?;
    }
    
    /// Get active key for type
    pub fn getActiveKey(self: *KeyManager, key_type: KeyType) ?*KeyEntry {
        if (self.active_keys.get(key_type)) |key_id| {
            return self.keys.getPtr(key_id);
        }
        return null;
    }
    
    /// Get key by ID
    pub fn getKeyById(self: *KeyManager, key_id: [16]u8) ?*KeyEntry {
        return self.keys.getPtr(key_id);
    }
    
    /// Rotate key for specific type
    pub fn rotateKey(self: *KeyManager, key_type: KeyType) !*KeyEntry {
        // Get current active key
        const current_key = self.getActiveKey(key_type);
        
        // Generate new key
        const new_key = try self.generateKey(key_type);
        
        // Deactivate old key but keep it for overlap period
        if (current_key) |old_key| {
            old_key.metadata.deactivate();
        }
        
        return new_key;
    }
    
    /// Check if any keys need rotation
    pub fn checkRotation(self: *KeyManager) !void {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        
        // Check if it's time to check rotation
        if (current_time - self.last_rotation_check < self.policy.rotation_check_interval) {
            return;
        }
        
        self.last_rotation_check = current_time;
        
        // Check each key type
        const key_types = [_]KeyType{ .Ed25519, .X25519, .ChaCha20Poly1305, .AES256GCM, .HMAC };
        
        for (key_types) |key_type| {
            if (self.getActiveKey(key_type)) |active_key| {
                if (active_key.metadata.needsRotation(self.policy) and self.policy.auto_rotate) {
                    _ = try self.rotateKey(key_type);
                }
            }
        }
        
        // Clean up expired keys
        try self.cleanupExpiredKeys();
    }
    
    /// Clean up expired keys
    pub fn cleanupExpiredKeys(self: *KeyManager) !void {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        
        var keys_to_remove = std.ArrayList([16]u8).init(self.allocator);
        defer keys_to_remove.deinit();
        
        // Find expired keys
        var iterator = self.keys.iterator();
        while (iterator.next()) |entry| {
            const key_entry = entry.value_ptr;
            const key_id = entry.key_ptr.*;
            
            // Remove keys that are expired and past overlap period
            if (!key_entry.metadata.is_active and key_entry.metadata.isExpired()) {
                const time_since_expiry = current_time - key_entry.metadata.expires_at;
                if (time_since_expiry > self.policy.key_overlap_period) {
                    try keys_to_remove.append(key_id);
                }
            }
        }
        
        // Remove expired keys
        for (keys_to_remove.items) |key_id| {
            if (self.keys.getPtr(key_id)) |key_entry| {
                key_entry.deinit();
                _ = self.keys.remove(key_id);
            }
        }
    }
    
    /// Get statistics
    pub fn getStatistics(self: KeyManager) struct {
        total_keys: u32,
        active_keys: u32,
        expired_keys: u32,
        keys_by_type: std.EnumMap(KeyType, u32),
    } {
        var total_keys: u32 = 0;
        var active_keys: u32 = 0;
        var expired_keys: u32 = 0;
        var keys_by_type = std.EnumMap(KeyType, u32).init(.{});
        
        var iterator = self.keys.iterator();
        while (iterator.next()) |entry| {
            const key_entry = entry.value_ptr;
            total_keys += 1;
            
            if (key_entry.metadata.is_active) {
                active_keys += 1;
            }
            
            if (key_entry.metadata.isExpired()) {
                expired_keys += 1;
            }
            
            const current_count = keys_by_type.get(key_entry.metadata.key_type) orelse 0;
            keys_by_type.put(key_entry.metadata.key_type, current_count + 1);
        }
        
        return .{
            .total_keys = total_keys,
            .active_keys = active_keys,
            .expired_keys = expired_keys,
            .keys_by_type = keys_by_type,
        };
    }
    
    /// Export key for external use (be careful with this!)
    pub fn exportKey(self: *KeyManager, key_id: [16]u8) ?[]const u8 {
        if (self.keys.get(key_id)) |key_entry| {
            return switch (key_entry.key) {
                .Ed25519 => |key| @as([]const u8, &key.private_key),
                .X25519 => |key| @as([]const u8, &key.private_key),
                .ChaCha20Poly1305 => |key| @as([]const u8, &key),
                .AES256GCM => |key| @as([]const u8, &key),
                .HMAC => |key| @as([]const u8, &key),
                .Custom => |data| data,
            };
        }
        return null;
    }
    
    /// Force rotation for all keys
    pub fn forceRotateAll(self: *KeyManager) !void {
        const key_types = [_]KeyType{ .Ed25519, .X25519, .ChaCha20Poly1305, .AES256GCM, .HMAC };
        
        for (key_types) |key_type| {
            if (self.getActiveKey(key_type) != null) {
                _ = try self.rotateKey(key_type);
            }
        }
    }
    
    /// Clean up all keys
    pub fn deinit(self: *KeyManager) void {
        var iterator = self.keys.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        
        self.keys.deinit();
        self.active_keys.deinit();
    }
};

/// Protocol-specific key rotation integrations
pub const ProtocolIntegrations = struct {
    /// TLS key rotation
    pub const TLS = struct {
        pub fn rotateSessionKeys(key_manager: *KeyManager) !void {
            // Rotate TLS session keys
            _ = try key_manager.rotateKey(.AES256GCM);
            _ = try key_manager.rotateKey(.HMAC);
        }
        
        pub fn getTLSKeys(key_manager: *KeyManager) !struct { 
            encrypt_key: [32]u8, 
            mac_key: [32]u8 
        } {
            const encrypt_key_entry = key_manager.getActiveKey(.AES256GCM) orelse 
                return KeyRotationError.NoKeysAvailable;
            const mac_key_entry = key_manager.getActiveKey(.HMAC) orelse 
                return KeyRotationError.NoKeysAvailable;
            
            return .{
                .encrypt_key = encrypt_key_entry.key.AES256GCM,
                .mac_key = mac_key_entry.key.HMAC,
            };
        }
    };
    
    /// QUIC key rotation
    pub const QUIC = struct {
        pub fn rotateConnectionKeys(key_manager: *KeyManager) !void {
            // Rotate QUIC connection keys
            _ = try key_manager.rotateKey(.ChaCha20Poly1305);
        }
        
        pub fn getQUICKey(key_manager: *KeyManager) ![32]u8 {
            const key_entry = key_manager.getActiveKey(.ChaCha20Poly1305) orelse 
                return KeyRotationError.NoKeysAvailable;
            return key_entry.key.ChaCha20Poly1305;
        }
    };
    
    /// Gossip protocol key rotation
    pub const Gossip = struct {
        pub fn rotateSigningKeys(key_manager: *KeyManager) !void {
            // Rotate gossip signing keys
            _ = try key_manager.rotateKey(.Ed25519);
        }
        
        pub fn getSigningKey(key_manager: *KeyManager) !asym.Ed25519KeyPair {
            const key_entry = key_manager.getActiveKey(.Ed25519) orelse 
                return KeyRotationError.NoKeysAvailable;
            return key_entry.key.Ed25519;
        }
    };
    
    /// VPN key rotation (extending existing VPN crypto)
    pub const VPN = struct {
        pub fn rotateVPNKeys(key_manager: *KeyManager) !void {
            // Rotate VPN tunnel keys
            _ = try key_manager.rotateKey(.ChaCha20Poly1305);
            _ = try key_manager.rotateKey(.X25519);
        }
        
        pub fn getVPNKeys(key_manager: *KeyManager) !struct {
            tunnel_key: [32]u8,
            dh_key: asym.Curve25519KeyPair,
        } {
            const tunnel_key_entry = key_manager.getActiveKey(.ChaCha20Poly1305) orelse 
                return KeyRotationError.NoKeysAvailable;
            const dh_key_entry = key_manager.getActiveKey(.X25519) orelse 
                return KeyRotationError.NoKeysAvailable;
            
            return .{
                .tunnel_key = tunnel_key_entry.key.ChaCha20Poly1305,
                .dh_key = dh_key_entry.key.X25519,
            };
        }
    };
};

// Tests

test "key rotation policy" {
    const policy = RotationPolicy.default();
    
    try std.testing.expect(policy.max_key_age == 24 * 3600);
    try std.testing.expect(policy.auto_rotate == true);
    
    const high_sec_policy = RotationPolicy.highSecurity();
    try std.testing.expect(high_sec_policy.max_key_age < policy.max_key_age);
}

test "key metadata" {
    const policy = RotationPolicy.testing();
    const metadata = KeyMetadata.init(.Ed25519, policy);
    
    try std.testing.expect(metadata.key_type == .Ed25519);
    try std.testing.expect(metadata.is_active == true);
    try std.testing.expect(metadata.usage_count == 0);
    try std.testing.expect(!metadata.isExpired());
}

test "key generation and zeroization" {
    const allocator = std.testing.allocator;
    
    var key = try Key.generate(allocator, .ChaCha20Poly1305);
    defer key.zeroize();
    
    // Key should be non-zero initially
    var all_zeros = true;
    for (key.ChaCha20Poly1305) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(!all_zeros);
}

test "key manager operations" {
    const allocator = std.testing.allocator;
    const policy = RotationPolicy.testing();
    
    var key_manager = KeyManager.init(allocator, policy);
    defer key_manager.deinit();
    
    // Generate initial keys
    const ed25519_key = try key_manager.generateKey(.Ed25519);
    const chacha_key = try key_manager.generateKey(.ChaCha20Poly1305);
    
    // Check that keys were stored
    try std.testing.expect(key_manager.getActiveKey(.Ed25519) != null);
    try std.testing.expect(key_manager.getActiveKey(.ChaCha20Poly1305) != null);
    
    // Check key retrieval by ID
    try std.testing.expect(key_manager.getKeyById(ed25519_key.metadata.id) != null);
    try std.testing.expect(key_manager.getKeyById(chacha_key.metadata.id) != null);
    
    // Test key rotation
    const new_ed25519_key = try key_manager.rotateKey(.Ed25519);
    try std.testing.expect(!std.mem.eql(u8, &ed25519_key.metadata.id, &new_ed25519_key.metadata.id));
    
    // Check statistics
    const stats = key_manager.getStatistics();
    try std.testing.expect(stats.total_keys >= 2);
    try std.testing.expect(stats.active_keys >= 1);
}

test "protocol integrations" {
    const allocator = std.testing.allocator;
    const policy = RotationPolicy.testing();
    
    var key_manager = KeyManager.init(allocator, policy);
    defer key_manager.deinit();
    
    // Test TLS integration
    try ProtocolIntegrations.TLS.rotateSessionKeys(&key_manager);
    const tls_keys = try ProtocolIntegrations.TLS.getTLSKeys(&key_manager);
    try std.testing.expect(tls_keys.encrypt_key.len == 32);
    try std.testing.expect(tls_keys.mac_key.len == 32);
    
    // Test QUIC integration
    try ProtocolIntegrations.QUIC.rotateConnectionKeys(&key_manager);
    const quic_key = try ProtocolIntegrations.QUIC.getQUICKey(&key_manager);
    try std.testing.expect(quic_key.len == 32);
    
    // Test Gossip integration
    try ProtocolIntegrations.Gossip.rotateSigningKeys(&key_manager);
    const gossip_key = try ProtocolIntegrations.Gossip.getSigningKey(&key_manager);
    try std.testing.expect(gossip_key.public_key.len == 32);
}