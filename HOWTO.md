# zcrypto Integration HOWTO - GhostChain Ecosystem

**Complete guide for integrating zcrypto v0.3.0 across all GhostChain projects**

---

## 🎯 **Overview**

zcrypto is the foundational cryptographic library for the entire GhostChain ecosystem. This guide shows how each project should integrate and use zcrypto for maximum security, performance, and consistency.

### **Supported Projects:**
- **Zig Projects**: zsig, zledger, zwallet, zvm, ghostbridge, zns, zquic, Wraith
- **Rust Projects**: ghostd, walletd, gcrypt (as FFI supplement)
- **VPN Systems**: Ghostmesh VPN
- **Infrastructure**: All gRPC services, P2P networks, blockchain components

---

## 🏗️ **Project-Specific Integration Patterns**

### 🔐 **zsig (Digital Signature Service)**

**Primary Use Cases:** Message signing, signature verification, identity attestation

```zig
const zcrypto = @import("zcrypto");

// Identity Management
pub const SigningIdentity = struct {
    ed25519_key: zcrypto.asym.Ed25519KeyPair,
    secp256k1_key: zcrypto.asym.Secp256k1KeyPair,
    
    pub fn fromSeed(seed: [32]u8) !SigningIdentity {
        return SigningIdentity{
            .ed25519_key = try zcrypto.asym.ed25519.generateFromSeed(seed),
            .secp256k1_key = zcrypto.secp256k1.generate(), // Random for this
        };
    }
    
    pub fn signMessage(self: *SigningIdentity, message: []const u8, algorithm: enum { ed25519, secp256k1 }) ![64]u8 {
        return switch (algorithm) {
            .ed25519 => self.ed25519_key.sign(message),
            .secp256k1 => blk: {
                const hash = zcrypto.hash.sha256(message);
                break :blk self.secp256k1_key.sign(hash);
            },
        };
    }
    
    pub fn deinit(self: *SigningIdentity) void {
        self.ed25519_key.zeroize();
        self.secp256k1_key.zeroize();
    }
};

// Batch Verification for Performance
pub fn verifyBatchSignatures(allocator: std.mem.Allocator, messages: [][]const u8, signatures: [][64]u8, public_keys: [][32]u8) ![]bool {
    var results = try allocator.alloc(bool, messages.len);
    for (messages, signatures, public_keys, 0..) |msg, sig, pubkey, i| {
        results[i] = zcrypto.asym.ed25519.verify(msg, sig, pubkey);
    }
    return results;
}
```

### 💰 **zwallet (Cryptocurrency Wallet)**

**Primary Use Cases:** HD wallet management, transaction signing, key derivation

```zig
const zcrypto = @import("zcrypto");
const std = @import("std");

pub const HDWallet = struct {
    master_key: zcrypto.bip.bip32.ExtendedKey,
    allocator: std.mem.Allocator,
    
    pub fn fromMnemonic(allocator: std.mem.Allocator, mnemonic_words: []const []const u8, passphrase: []const u8) !HDWallet {
        // Generate mnemonic from words
        const mnemonic = try zcrypto.bip.bip39.fromWords(allocator, mnemonic_words);
        defer mnemonic.deinit(allocator);
        
        // Convert to seed
        const seed = try mnemonic.toSeed(allocator, passphrase);
        defer allocator.free(seed);
        
        // Generate master key
        const master = zcrypto.bip.bip32.masterKeyFromSeed(seed);
        
        return HDWallet{
            .master_key = master,
            .allocator = allocator,
        };
    }
    
    pub fn deriveBitcoinAccount(self: *HDWallet, account: u32) !BitcoinAccount {
        const path = zcrypto.bip.bip44.bitcoinPath(account, 0, 0); // m/44'/0'/account'/0/0
        const derived_key = try zcrypto.bip.bip44.deriveKey(self.master_key, path);
        
        return BitcoinAccount{
            .private_key = derived_key.key,
            .public_key = zcrypto.asym.secp256k1.publicKeyFromPrivate(derived_key.key),
        };
    }
    
    pub fn deriveEthereumAccount(self: *HDWallet, account: u32) !EthereumAccount {
        const path = zcrypto.bip.bip44.ethereumPath(account, 0, 0); // m/44'/60'/account'/0/0
        const derived_key = try zcrypto.bip.bip44.deriveKey(self.master_key, path);
        
        return EthereumAccount{
            .private_key = derived_key.key,
            .address = ethereumAddressFromKey(derived_key.key),
        };
    }
    
    fn ethereumAddressFromKey(private_key: [32]u8) [20]u8 {
        const public_key = zcrypto.asym.secp256k1.publicKeyFromPrivate(private_key);
        const hash = zcrypto.hash.keccak256(&public_key);
        return hash[12..32].*; // Last 20 bytes
    }
};

// Transaction Signing
pub fn signBitcoinTransaction(private_key: [32]u8, tx_hash: [32]u8) ![64]u8 {
    return zcrypto.asym.secp256k1.sign(tx_hash, private_key);
}

pub fn signEthereumTransaction(private_key: [32]u8, tx_hash: [32]u8) !struct { signature: [64]u8, recovery_id: u8 } {
    const signature = zcrypto.asym.secp256k1.sign(tx_hash, private_key);
    // TODO: Add recovery ID computation
    return .{ .signature = signature, .recovery_id = 0 };
}
```

### 📊 **zledger (Distributed Ledger)**

**Primary Use Cases:** Block signing, merkle tree construction, consensus proofs

```zig
const zcrypto = @import("zcrypto");

pub const Block = struct {
    header: BlockHeader,
    transactions: []Transaction,
    signature: [64]u8,
    
    pub fn sign(self: *Block, validator_key: zcrypto.asym.Ed25519KeyPair) void {
        const block_hash = self.computeHash();
        self.signature = validator_key.sign(&block_hash);
    }
    
    pub fn verify(self: Block, validator_public_key: [32]u8) bool {
        const block_hash = self.computeHash();
        return zcrypto.asym.ed25519.verify(&block_hash, self.signature, validator_public_key);
    }
    
    fn computeHash(self: Block) [32]u8 {
        // Compute merkle root of transactions
        const merkle_root = self.computeMerkleRoot();
        
        // Hash block header + merkle root
        var hasher = zcrypto.hash.Sha256.init();
        hasher.update(std.mem.asBytes(&self.header));
        hasher.update(&merkle_root);
        return hasher.final();
    }
    
    fn computeMerkleRoot(self: Block) [32]u8 {
        if (self.transactions.len == 0) return [_]u8{0} ** 32;
        if (self.transactions.len == 1) {
            return zcrypto.hash.sha256(std.mem.asBytes(&self.transactions[0]));
        }
        
        // Build merkle tree
        var hashes = std.ArrayList([32]u8).init(std.heap.page_allocator);
        defer hashes.deinit();
        
        // Hash all transactions
        for (self.transactions) |tx| {
            hashes.append(zcrypto.hash.sha256(std.mem.asBytes(&tx))) catch unreachable;
        }
        
        // Build tree bottom-up
        while (hashes.items.len > 1) {
            var next_level = std.ArrayList([32]u8).init(std.heap.page_allocator);
            defer next_level.deinit();
            
            var i: usize = 0;
            while (i < hashes.items.len) : (i += 2) {
                const left = hashes.items[i];
                const right = if (i + 1 < hashes.items.len) hashes.items[i + 1] else left;
                
                var combined: [64]u8 = undefined;
                @memcpy(combined[0..32], &left);
                @memcpy(combined[32..64], &right);
                
                next_level.append(zcrypto.hash.sha256(&combined)) catch unreachable;
            }
            
            hashes.deinit();
            hashes = next_level;
        }
        
        return hashes.items[0];
    }
};
```

### 🌐 **ghostbridge (gRPC Relay)**

**Primary Use Cases:** TLS 1.3 connections, QUIC transport, message authentication

```zig
const zcrypto = @import("zcrypto");

pub const SecureChannel = struct {
    tls_context: zcrypto.tls.TlsContext,
    traffic_keys: zcrypto.tls.TrafficKeys,
    
    pub fn establishTls13(allocator: std.mem.Allocator, server_cert: []const u8, client_identity: ?zcrypto.asym.Ed25519KeyPair) !SecureChannel {
        // TLS 1.3 handshake using zcrypto
        var tls_ctx = try zcrypto.tls.TlsContext.init(allocator);
        
        // Client certificate if provided
        if (client_identity) |identity| {
            try tls_ctx.setClientCertificate(identity);
        }
        
        // Perform handshake
        try tls_ctx.connect(server_cert);
        
        return SecureChannel{
            .tls_context = tls_ctx,
            .traffic_keys = tls_ctx.getTrafficKeys(),
        };
    }
    
    pub fn encryptMessage(self: *SecureChannel, allocator: std.mem.Allocator, plaintext: []const u8) ![]u8 {
        return try zcrypto.tls.encryptApplicationData(allocator, &self.traffic_keys, plaintext);
    }
    
    pub fn decryptMessage(self: *SecureChannel, allocator: std.mem.Allocator, ciphertext: []const u8) ![]u8 {
        return try zcrypto.tls.decryptApplicationData(allocator, &self.traffic_keys, ciphertext);
    }
};

// QUIC Integration
pub const QuicConnection = struct {
    initial_secrets: zcrypto.tls.QuicSecrets,
    packet_keys: zcrypto.tls.QuicPacketKeys,
    
    pub fn initConnection(connection_id: []const u8) QuicConnection {
        const secrets = zcrypto.tls.deriveQuicInitialSecrets(connection_id);
        const keys = zcrypto.tls.deriveQuicPacketKeys(&secrets);
        
        return QuicConnection{
            .initial_secrets = secrets,
            .packet_keys = keys,
        };
    }
    
    pub fn encryptPacket(self: *QuicConnection, allocator: std.mem.Allocator, packet_number: u64, plaintext: []const u8) ![]u8 {
        return try zcrypto.tls.encryptQuicPacket(allocator, &self.packet_keys, packet_number, plaintext);
    }
    
    pub fn decryptPacket(self: *QuicConnection, allocator: std.mem.Allocator, packet_number: u64, ciphertext: []const u8) ![]u8 {
        return try zcrypto.tls.decryptQuicPacket(allocator, &self.packet_keys, packet_number, ciphertext);
    }
};
```

### 🔍 **zns (Name Service)**

**Primary Use Cases:** DNS record signing, DNSSEC, name resolution authentication

```zig
const zcrypto = @import("zcrypto");

pub const DnsRecord = struct {
    name: []const u8,
    record_type: u16,
    data: []const u8,
    signature: [64]u8,
    
    pub fn sign(self: *DnsRecord, zone_key: zcrypto.asym.Ed25519KeyPair) void {
        const record_hash = self.computeHash();
        self.signature = zone_key.sign(&record_hash);
    }
    
    pub fn verify(self: DnsRecord, zone_public_key: [32]u8) bool {
        const record_hash = self.computeHash();
        return zcrypto.asym.ed25519.verify(&record_hash, self.signature, zone_public_key);
    }
    
    fn computeHash(self: DnsRecord) [32]u8 {
        var hasher = zcrypto.hash.Sha256.init();
        hasher.update(self.name);
        hasher.update(std.mem.asBytes(&self.record_type));
        hasher.update(self.data);
        return hasher.final();
    }
};

pub const ZoneManager = struct {
    zone_key: zcrypto.asym.Ed25519KeyPair,
    records: std.HashMap([]const u8, DnsRecord),
    
    pub fn addRecord(self: *ZoneManager, name: []const u8, record_type: u16, data: []const u8) !void {
        var record = DnsRecord{
            .name = name,
            .record_type = record_type,
            .data = data,
            .signature = undefined,
        };
        
        record.sign(self.zone_key);
        try self.records.put(name, record);
    }
    
    pub fn resolveAndVerify(self: *ZoneManager, name: []const u8) ?DnsRecord {
        if (self.records.get(name)) |record| {
            if (record.verify(self.zone_key.public_key)) {
                return record;
            }
        }
        return null;
    }
};
```

### 🛡️ **Ghostmesh VPN**

**Primary Use Cases:** VPN tunnel encryption, peer authentication, key exchange

```zig
const zcrypto = @import("zcrypto");

pub const VpnPeer = struct {
    identity: zcrypto.asym.Ed25519KeyPair,
    x25519_keypair: zcrypto.asym.Curve25519KeyPair,
    shared_secret: ?[32]u8 = null,
    tunnel_keys: ?TunnelKeys = null,
    
    const TunnelKeys = struct {
        encrypt_key: [32]u8,
        decrypt_key: [32]u8,
        encrypt_nonce: [12]u8,
        decrypt_nonce: [12]u8,
    };
    
    pub fn init() VpnPeer {
        return VpnPeer{
            .identity = zcrypto.asym.ed25519.generate(),
            .x25519_keypair = zcrypto.asym.x25519.generate(),
        };
    }
    
    pub fn performHandshake(self: *VpnPeer, peer_x25519_public: [32]u8, peer_identity_public: [32]u8) !void {
        // X25519 key exchange
        self.shared_secret = zcrypto.asym.x25519.dh(self.x25519_keypair.private_key, peer_x25519_public);
        
        // Derive tunnel keys using HKDF
        const salt = "ghostmesh-vpn-v1";
        const info = "tunnel-keys";
        
        const derived = try zcrypto.kdf.hkdf(
            std.heap.page_allocator,
            &self.shared_secret.?,
            salt,
            info,
            64 // 32 bytes for each direction
        );
        defer std.heap.page_allocator.free(derived);
        
        self.tunnel_keys = TunnelKeys{
            .encrypt_key = derived[0..32].*,
            .decrypt_key = derived[32..64].*,
            .encrypt_nonce = [_]u8{0} ** 12,
            .decrypt_nonce = [_]u8{0} ** 12,
        };
    }
    
    pub fn encryptPacket(self: *VpnPeer, allocator: std.mem.Allocator, packet: []const u8) ![]u8 {
        if (self.tunnel_keys == null) return error.NoTunnelKeys;
        
        const keys = self.tunnel_keys.?;
        const ciphertext = try zcrypto.sym.encryptChaCha20Poly1305(
            allocator,
            packet,
            &keys.encrypt_key,
            &keys.encrypt_nonce
        );
        
        // Increment nonce (simplified - should be more sophisticated)
        self.tunnel_keys.?.encrypt_nonce[11] += 1;
        
        return ciphertext.data;
    }
    
    pub fn decryptPacket(self: *VpnPeer, allocator: std.mem.Allocator, ciphertext: []const u8, tag: [16]u8) ![]u8 {
        if (self.tunnel_keys == null) return error.NoTunnelKeys;
        
        const keys = self.tunnel_keys.?;
        const packet_data = zcrypto.sym.Ciphertext{
            .data = ciphertext,
            .tag = tag,
        };
        
        const plaintext = try zcrypto.sym.decryptChaCha20Poly1305(
            allocator,
            packet_data,
            &keys.decrypt_key,
            &keys.decrypt_nonce
        );
        
        // Increment nonce
        self.tunnel_keys.?.decrypt_nonce[11] += 1;
        
        return plaintext;
    }
    
    pub fn deinit(self: *VpnPeer) void {
        self.identity.zeroize();
        self.x25519_keypair.zeroize();
        if (self.shared_secret) |*secret| {
            zcrypto.util.secureZero(u8, secret);
        }
    }
};
```

---

## 🦀 **Rust FFI Integration (ghostd, walletd)**

For Rust projects that need zcrypto functionality:

### FFI Bindings Setup

```rust
// build.rs
fn main() {
    // Link zcrypto library
    println!("cargo:rustc-link-lib=static=zcrypto");
    println!("cargo:rustc-link-search=native=../zcrypto/zig-out/lib");
    
    // Generate bindings
    let bindings = bindgen::Builder::default()
        .header("../zcrypto/include/zcrypto.h")
        .generate()
        .expect("Unable to generate bindings");
        
    bindings
        .write_to_file("src/zcrypto_bindings.rs")
        .expect("Couldn't write bindings!");
}
```

### Rust Integration Example

```rust
use crate::zcrypto_bindings::*;

pub struct RustCryptoWrapper {
    ed25519_keypair: *mut Ed25519KeyPair,
}

impl RustCryptoWrapper {
    pub fn new() -> Result<Self, CryptoError> {
        unsafe {
            let keypair = zcrypto_ed25519_generate();
            if keypair.is_null() {
                return Err(CryptoError::KeyGenerationFailed);
            }
            
            Ok(RustCryptoWrapper {
                ed25519_keypair: keypair,
            })
        }
    }
    
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        unsafe {
            let mut signature = [0u8; 64];
            let result = zcrypto_ed25519_sign(
                self.ed25519_keypair,
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr()
            );
            
            if result == 0 {
                Ok(signature.to_vec())
            } else {
                Err(CryptoError::SigningFailed)
            }
        }
    }
}

impl Drop for RustCryptoWrapper {
    fn drop(&mut self) {
        unsafe {
            zcrypto_ed25519_destroy(self.ed25519_keypair);
        }
    }
}
```

---

## ⚡ **Performance Best Practices**

### Batch Operations
```zig
// Use batch operations for high throughput
const signatures = try zcrypto.batch.verifyBatch(messages, sigs, pubkeys, .ed25519);

// Reuse contexts for repeated operations
var hasher = zcrypto.hash.Sha256.init();
hasher.update(data1);
hasher.update(data2);
const result = hasher.final();
```

### Memory Management
```zig
// Prefer stack allocation for fixed-size results
const hash = zcrypto.hash.sha256(data); // [32]u8 on stack

// Use arenas for temporary allocations
var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
defer arena.deinit();
const temp_data = try zcrypto.sym.encrypt(arena.allocator(), plaintext, key);
```

### Key Lifetime Management
```zig
// Always zeroize sensitive data
defer {
    keypair.zeroize();
    shared_secret.zeroize();
}

// Use RAII patterns
const SecureKey = struct {
    key: [32]u8,
    
    pub fn deinit(self: *SecureKey) void {
        zcrypto.util.secureZero(u8, &self.key);
    }
};
```

---

## 🔧 **Build Integration**

### Zig Projects (build.zig)
```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    
    // Add zcrypto dependency
    const zcrypto = b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
    });
    
    const exe = b.addExecutable(.{
        .name = "your-project",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    
    exe.root_module.addImport("zcrypto", zcrypto.module("zcrypto"));
    
    b.installArtifact(exe);
}
```

### Cargo.toml (Rust projects)
```toml
[dependencies]
# Your other dependencies

[build-dependencies]
bindgen = "0.69"
cc = "1.0"

[lib]
name = "your_project"
crate-type = ["cdylib", "rlib"]
```

---

## 🛡️ **Security Guidelines**

### Key Management
1. **Always zeroize keys** when done
2. **Use secure random generation** for all keys
3. **Validate all inputs** before cryptographic operations
4. **Use constant-time operations** for sensitive comparisons

### Error Handling
1. **Never panic on invalid input** - return errors gracefully
2. **Don't leak information** in error messages
3. **Use appropriate error types** for different failure modes

### Side-Channel Protection
1. **Use timing-safe comparisons** for authentication
2. **Avoid data-dependent branching** in crypto code
3. **Clear sensitive data** from memory promptly

---

## 📋 **Integration Checklist**

### Before Integration
- [ ] Include zcrypto as dependency in build system
- [ ] Set up proper error handling patterns
- [ ] Plan key lifetime management strategy
- [ ] Identify performance-critical paths

### During Integration
- [ ] Use appropriate crypto primitives for each use case
- [ ] Implement proper key zeroization
- [ ] Add comprehensive error handling
- [ ] Test with invalid/malicious inputs

### After Integration
- [ ] Run security tests and fuzzing
- [ ] Benchmark performance-critical operations
- [ ] Audit key management practices
- [ ] Document crypto usage patterns

---

## 🎯 **Common Integration Patterns**

### Authentication Service
```zig
pub fn authenticateUser(identity: []const u8, challenge: []const u8, signature: [64]u8, public_key: [32]u8) bool {
    const expected_message = zcrypto.hash.sha256(challenge);
    return zcrypto.asym.ed25519.verify(&expected_message, signature, public_key);
}
```

### Secure Communication
```zig
pub fn establishSecureChannel(peer_public_key: [32]u8) !SecureChannel {
    const our_keypair = zcrypto.asym.x25519.generate();
    const shared_secret = zcrypto.asym.x25519.dh(our_keypair.private_key, peer_public_key);
    
    const channel_keys = try zcrypto.kdf.hkdf(
        allocator,
        &shared_secret,
        "ghost-secure-channel",
        "v1",
        64
    );
    
    return SecureChannel.init(channel_keys);
}
```

### Data Integrity
```zig
pub fn verifyDataIntegrity(data: []const u8, hmac_key: []const u8, expected_tag: [32]u8) bool {
    return zcrypto.auth.verifyHmacSha256(data, hmac_key, expected_tag);
}
```

---

**This HOWTO provides complete integration guidance for all GhostChain projects using zcrypto. Each project should follow the patterns appropriate to their use case while maintaining consistent security practices across the ecosystem.**