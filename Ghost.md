# GhostMesh Integration Guide

This document covers using `zcrypto` as the cryptographic backbone for GhostMesh, a modern QUIC-based VPN similar to WireGuard and Tailscale.

## Overview

GhostMesh leverages `zcrypto` for all cryptographic operations, providing:
- **QUIC packet encryption/decryption** using ChaCha20-Poly1305
- **Key exchange** via X25519 ECDH
- **Authentication** using Ed25519 signatures
- **Key derivation** for session keys and packet number spaces
- **Random generation** for nonces and ephemeral keys

## Installation

Add zcrypto to your GhostMesh project using Zig's package manager and or zion dev tool:

```zig
// build.zig.zon
.{
    .name = "ghostmesh",
    .version = "0.1.0",
    .dependencies = .{
        .zcrypto = .{
            .url = "https://github.com/ghostkellz/zcrypto/archive/main.tar.gz",
            .hash = "...", // Use zig fetch to get the hash
        },
    },
}
```

```zig
// build.zig
const zcrypto = b.dependency("zcrypto", .{});
exe.root_module.addImport("zcrypto", zcrypto.module("zcrypto"));
```

## Core Integration Points

### 1. QUIC Connection Setup

```zig
const zcrypto = @import("zcrypto");
const std = @import("std");

const GhostConnection = struct {
    // Local and remote keys
    local_private: [32]u8,
    local_public: [32]u8,
    remote_public: [32]u8,
    
    // Derived shared secret
    shared_secret: [32]u8,
    
    // QUIC packet protection keys
    client_key: [32]u8,
    server_key: [32]u8,
    
    pub fn init(allocator: std.mem.Allocator) !GhostConnection {
        var conn: GhostConnection = undefined;
        
        // Generate ephemeral keypair for this connection
        const keypair = try zcrypto.asym.x25519GenerateKeyPair(allocator);
        defer allocator.free(keypair.private);
        defer allocator.free(keypair.public);
        
        @memcpy(&conn.local_private, keypair.private);
        @memcpy(&conn.local_public, keypair.public);
        
        return conn;
    }
    
    pub fn performHandshake(self: *GhostConnection, allocator: std.mem.Allocator, remote_public: []const u8) !void {
        @memcpy(&self.remote_public, remote_public);
        
        // Perform X25519 ECDH
        const shared = try zcrypto.asym.x25519DiffieHellman(allocator, &self.local_private, &self.remote_public);
        defer allocator.free(shared);
        @memcpy(&self.shared_secret, shared);
        
        // Derive QUIC protection keys using HKDF
        const client_info = "ghostmesh client key";
        const server_info = "ghostmesh server key";
        
        const client_key = try zcrypto.kdf.hkdfExpand(allocator, zcrypto.hash.Sha256, &self.shared_secret, client_info, 32);
        defer allocator.free(client_key);
        @memcpy(&self.client_key, client_key);
        
        const server_key = try zcrypto.kdf.hkdfExpand(allocator, zcrypto.hash.Sha256, &self.shared_secret, server_info, 32);
        defer allocator.free(server_key);
        @memcpy(&self.server_key, server_key);
    }
};
```

### 2. QUIC Packet Protection

```zig
const PacketProtection = struct {
    key: [32]u8,
    
    pub fn encryptPacket(self: *PacketProtection, allocator: std.mem.Allocator, packet_number: u64, payload: []const u8) ![]u8 {
        // Generate nonce from packet number (QUIC style)
        var nonce: [12]u8 = undefined;
        zcrypto.util.writeU64BE(packet_number, nonce[4..12]);
        
        // Encrypt using ChaCha20-Poly1305
        return try zcrypto.sym.chaCha20Poly1305Encrypt(allocator, &self.key, &nonce, payload, &[_]u8{});
    }
    
    pub fn decryptPacket(self: *PacketProtection, allocator: std.mem.Allocator, packet_number: u64, ciphertext: []const u8) ![]u8 {
        var nonce: [12]u8 = undefined;
        zcrypto.util.writeU64BE(packet_number, nonce[4..12]);
        
        return try zcrypto.sym.chaCha20Poly1305Decrypt(allocator, &self.key, &nonce, ciphertext, &[_]u8{});
    }
};
```

### 3. Peer Authentication

```zig
const PeerIdentity = struct {
    public_key: [32]u8,
    
    pub fn signHandshake(allocator: std.mem.Allocator, private_key: []const u8, handshake_data: []const u8) ![]u8 {
        // Note: Ed25519 implementation pending Zig 0.15+ API updates
        // This is a placeholder for the signing logic
        _ = allocator;
        _ = private_key;
        _ = handshake_data;
        return error.NotImplemented;
    }
    
    pub fn verifyHandshake(public_key: []const u8, signature: []const u8, handshake_data: []const u8) !bool {
        // Note: Ed25519 implementation pending Zig 0.15+ API updates
        _ = public_key;
        _ = signature;
        _ = handshake_data;
        return error.NotImplemented;
    }
};
```

### 4. Key Rotation

```zig
const KeyManager = struct {
    current_generation: u64,
    keys: std.HashMap(u64, [32]u8, std.hash_map.DefaultContext(u64), std.hash_map.default_max_load_percentage),
    
    pub fn rotateKeys(self: *KeyManager, allocator: std.mem.Allocator, master_secret: []const u8) !void {
        self.current_generation += 1;
        
        const key_info = try std.fmt.allocPrint(allocator, "ghostmesh key gen {d}", .{self.current_generation});
        defer allocator.free(key_info);
        
        const new_key = try zcrypto.kdf.hkdfExpand(allocator, zcrypto.hash.Sha256, master_secret, key_info, 32);
        defer allocator.free(new_key);
        
        var key_array: [32]u8 = undefined;
        @memcpy(&key_array, new_key);
        try self.keys.put(self.current_generation, key_array);
    }
};
```

## Configuration Examples

### Basic VPN Node

```zig
const GhostNode = struct {
    connections: std.HashMap(std.net.Address, GhostConnection, AddressContext, std.hash_map.default_max_load_percentage),
    identity_key: [32]u8,
    
    pub fn init(allocator: std.mem.Allocator) !GhostNode {
        var node: GhostNode = undefined;
        node.connections = std.HashMap(std.net.Address, GhostConnection, AddressContext, std.hash_map.default_max_load_percentage).init(allocator);
        
        // Generate long-term identity key
        zcrypto.rand.fillRandom(&node.identity_key);
        
        return node;
    }
    
    pub fn connectToPeer(self: *GhostNode, allocator: std.mem.Allocator, peer_addr: std.net.Address, peer_public_key: []const u8) !void {
        var conn = try GhostConnection.init(allocator);
        try conn.performHandshake(allocator, peer_public_key);
        try self.connections.put(peer_addr, conn);
    }
};
```

### Mesh Network Discovery

```zig
const MeshDiscovery = struct {
    pub fn broadcastPresence(allocator: std.mem.Allocator, node_id: []const u8, private_key: []const u8) ![]u8 {
        const timestamp = std.time.timestamp();
        const message = try std.fmt.allocPrint(allocator, "ghostmesh:{s}:{d}", .{ node_id, timestamp });
        defer allocator.free(message);
        
        // Sign the presence announcement
        return PeerIdentity.signHandshake(allocator, private_key, message);
    }
};
```

## Security Considerations

1. **Forward Secrecy**: Use ephemeral X25519 keys for each connection
2. **Key Rotation**: Implement periodic key rotation for long-lived connections
3. **Packet Number Protection**: Use QUIC-style packet number encryption
4. **Replay Protection**: Maintain packet number windows per connection
5. **Identity Verification**: Always verify peer signatures during handshake

## Performance Tips

1. **Connection Pooling**: Reuse `GhostConnection` instances where possible
2. **Batch Operations**: Encrypt/decrypt multiple packets in batches
3. **Memory Management**: Use arena allocators for temporary cryptographic operations
4. **Hardware Acceleration**: zcrypto leverages Zig's std.crypto optimizations

## Troubleshooting

### Common Issues

1. **Key Mismatch**: Ensure both peers use the same key derivation parameters
2. **Nonce Reuse**: Never reuse packet numbers within the same key epoch
3. **Memory Leaks**: Always defer free allocated cryptographic material
4. **Timing Attacks**: Use constant-time comparison functions from `zcrypto.util`

### Debug Helpers

```zig
pub fn debugConnection(conn: *GhostConnection) void {
    std.debug.print("Local public: {s}\n", .{std.fmt.fmtSliceHexLower(&conn.local_public)});
    std.debug.print("Remote public: {s}\n", .{std.fmt.fmtSliceHexLower(&conn.remote_public)});
    std.debug.print("Shared secret: {s}\n", .{std.fmt.fmtSliceHexLower(&conn.shared_secret)});
}
```

## Future Enhancements

- [ ] Post-quantum key exchange (Kyber integration)
- [ ] Hardware security module (HSM) support
- [ ] Zero-copy packet processing
- [ ] Advanced key management policies
- [ ] Quantum-resistant signatures

---

For more examples and advanced usage, see the `examples/` directory in the zcrypto repository.
