# 👻 GHOSTCHAIN CRYPTOGRAPHIC INTEGRATION GUIDE

**Complete integration documentation for all GhostChain projects using zcrypto v0.5.0**

---

## 📋 **TABLE OF CONTENTS**

1. [Overview](#overview)
2. [zcrypto Quick Reference](#zcrypto-quick-reference)
3. [zsig - Digital Signature Service](#zsig---digital-signature-service)
4. [ghostd - Network Daemon](#ghostd---network-daemon)
5. [walletd - Cryptocurrency Wallet](#walletd---cryptocurrency-wallet)
6. [zledger - Blockchain Ledger](#zledger---blockchain-ledger)
7. [zvm - Virtual Machine](#zvm---virtual-machine)
8. [Common Integration Patterns](#common-integration-patterns)
9. [Security Best Practices](#security-best-practices)
10. [Performance Guidelines](#performance-guidelines)

---

## 🌟 **OVERVIEW**

The GhostChain ecosystem consists of five core cryptographic projects, all powered by **zcrypto v0.5.0**. This guide provides complete integration examples and best practices for each project.

### **GhostChain Architecture**

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    zsig     │    │   ghostd    │    │   walletd   │
│  Signatures │◄──►│   Daemon    │◄──►│   Wallet    │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       │            ┌─────────────┐            │
       └───────────►│   zledger   │◄───────────┘
                    │   Ledger    │
                    └─────────────┘
                           │
                    ┌─────────────┐
                    │     zvm     │
                    │ Virtual VM  │
                    └─────────────┘
```

### **Supported Cryptographic Algorithms**

- **Classical**: Ed25519, X25519, secp256k1, secp256r1
- **Post-Quantum**: ML-KEM-768, ML-DSA-65
- **Hybrid**: X25519+ML-KEM-768 for maximum security
- **Hash Functions**: SHA-256, BLAKE2b, SHA-3
- **Symmetric**: AES-128-GCM, ChaCha20-Poly1305

---

## 🔧 **ZCRYPTO QUICK REFERENCE**

### **Key API Differences from Documentation**

⚠️ **Important**: The following corrections apply to zcrypto v0.5.0:

```zig
// ✅ CORRECT API USAGE:

// 1. Ed25519 private keys are 64 bytes, not 32
const keypair = zcrypto.asym.ed25519.generate();
// keypair.private_key is [64]u8

// 2. X25519 uses generate(), not create()
const x25519_keys = zcrypto.asym.x25519.generate();

// 3. generateFromSeed returns KeyPair directly, not error union
const seed = [_]u8{42} ** 32;
const det_keypair = zcrypto.asym.ed25519.generateFromSeed(seed);

// 4. KeyPair methods use value receivers, not pointers
const signature = try keypair.sign(message); // Not &keypair
const valid = keypair.verify(message, signature); // Not &keypair
```

### **Common Imports**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

// Frequently used modules
const ed25519 = zcrypto.asym.ed25519;
const secp256k1 = zcrypto.asym.secp256k1;
const ml_kem = zcrypto.pq.ml_kem.ML_KEM_768;
const ml_dsa = zcrypto.pq.ml_dsa.ML_DSA_65;
```

---

## 🔐 **ZSIG - DIGITAL SIGNATURE SERVICE**

**Purpose**: Production-ready digital signature service with hybrid classical + post-quantum security.

### **Core Features**
- ✅ Ed25519 + ML-DSA-65 hybrid signatures
- ✅ secp256k1 backup signatures for Bitcoin/Ethereum compatibility
- ✅ Timestamped signatures with integrity verification
- ✅ Batch signing for high-throughput scenarios
- ✅ Secure key management and cleanup

### **Implementation**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

/// Production-ready digital signature service for GhostChain
pub const ZSigService = struct {
    // Hybrid cryptography for maximum security
    classical_keys: zcrypto.asym.ed25519.KeyPair,
    pq_keys: zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair,
    backup_secp_keys: zcrypto.asym.secp256k1.KeyPair,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) !ZSigService {
        return ZSigService{
            .classical_keys = zcrypto.asym.ed25519.generate(),
            .pq_keys = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.generateRandom(allocator),
            .backup_secp_keys = zcrypto.asym.secp256k1.generate(),
            .allocator = allocator,
        };
    }
    
    /// Sign data with hybrid classical + post-quantum signatures
    pub fn signDocument(self: *const ZSigService, document: []const u8) !struct {
        classical: [64]u8,
        post_quantum: [3309]u8,
        secp256k1_backup: [64]u8,
        integrity_hash: [32]u8,
        timestamp: u64,
    } {
        const timestamp = std.time.timestamp();
        
        // Create timestamped data
        const timestamped_data = try std.fmt.allocPrint(
            self.allocator, "{s}:{d}", .{ document, timestamp }
        );
        defer self.allocator.free(timestamped_data);
        
        // Generate all signatures
        const classical_sig = try self.classical_keys.sign(timestamped_data);
        
        var pq_randomness: [32]u8 = undefined;
        std.crypto.random.bytes(&pq_randomness);
        const pq_sig = try self.pq_keys.sign(timestamped_data, pq_randomness);
        
        const secp_hash = zcrypto.hash.sha256(timestamped_data);
        const secp_sig = try self.backup_secp_keys.sign(secp_hash);
        
        // Create integrity hash of all signatures
        const integrity_hash = zcrypto.hash.sha256(
            &(classical_sig ++ pq_sig ++ secp_sig)
        );
        
        return .{
            .classical = classical_sig,
            .post_quantum = pq_sig,
            .secp256k1_backup = secp_sig,
            .integrity_hash = integrity_hash,
            .timestamp = @intCast(timestamp),
        };
    }
    
    /// Verify document with all signature types
    pub fn verifyDocument(
        classical_public: [32]u8,
        pq_public: [1952]u8,
        secp_public: [33]u8,
        document: []const u8,
        signatures: anytype,
    ) !bool {
        // Reconstruct timestamped data
        const timestamped_data = try std.fmt.allocPrint(
            std.heap.page_allocator, "{s}:{d}", .{ document, signatures.timestamp }
        );
        defer std.heap.page_allocator.free(timestamped_data);
        
        // Verify all signatures
        const classical_valid = zcrypto.asym.ed25519.verify(
            timestamped_data, signatures.classical, classical_public
        );
        
        const pq_valid = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.verify(
            pq_public, timestamped_data, signatures.post_quantum
        );
        
        const secp_hash = zcrypto.hash.sha256(timestamped_data);
        const secp_valid = zcrypto.asym.secp256k1.verify(
            secp_hash, signatures.secp256k1_backup, secp_public
        );
        
        // Verify integrity hash
        const computed_hash = zcrypto.hash.sha256(
            &(signatures.classical ++ signatures.post_quantum ++ signatures.secp256k1_backup)
        );
        const integrity_valid = std.mem.eql(u8, &computed_hash, &signatures.integrity_hash);
        
        return classical_valid and pq_valid and secp_valid and integrity_valid;
    }
    
    /// Batch sign multiple documents for performance
    pub fn batchSignDocuments(
        self: *const ZSigService,
        documents: [][]const u8,
    ) ![]struct {
        classical: [64]u8,
        post_quantum: [3309]u8,
        document_hash: [32]u8,
    } {
        const signatures = try self.allocator.alloc(@TypeOf(.{
            .classical = [_]u8{0} ** 64,
            .post_quantum = [_]u8{0} ** 3309,
            .document_hash = [_]u8{0} ** 32,
        }), documents.len);
        
        for (documents, 0..) |doc, i| {
            const doc_hash = zcrypto.hash.sha256(doc);
            signatures[i] = .{
                .classical = try self.classical_keys.sign(doc),
                .post_quantum = blk: {
                    var randomness: [32]u8 = undefined;
                    std.crypto.random.bytes(&randomness);
                    break :blk try self.pq_keys.sign(doc, randomness);
                },
                .document_hash = doc_hash,
            };
        }
        
        return signatures;
    }
    
    pub fn deinit(self: *ZSigService) void {
        // Secure cleanup
        self.classical_keys.zeroize();
        self.backup_secp_keys.zeroize();
    }
};
```

### **Usage Example**

```zig
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize zsig service
    var zsig = try ZSigService.init(allocator);
    defer zsig.deinit();
    
    // Sign a document
    const document = "GhostChain Contract #12345";
    const signatures = try zsig.signDocument(document);
    
    // Verify signatures
    const public_keys = zsig.getPublicKeys();
    const valid = try ZSigService.verifyDocument(
        public_keys.classical,
        public_keys.post_quantum,
        public_keys.secp256k1,
        document,
        signatures
    );
    
    std.debug.print("✅ Document signed and verified: {}\n", .{valid});
}
```

---

## 🌐 **GHOSTD - NETWORK DAEMON**

**Purpose**: High-performance network daemon with post-quantum QUIC cryptography.

### **Core Features**
- ✅ Post-quantum hybrid QUIC (X25519+ML-KEM-768)
- ✅ Zero-copy packet processing for maximum performance
- ✅ Multi-peer connection management
- ✅ Secure TLS 1.3 with custom ALPN protocols
- ✅ Real-time message broadcasting

### **Implementation**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

/// High-performance network daemon for GhostChain
pub const GhostDaemon = struct {
    quic_crypto: zcrypto.quic.QuicCrypto,
    tls_config: zcrypto.tls.config.TlsConfig,
    connections: std.HashMap(u64, ConnectionContext),
    hybrid_keys: zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair,
    allocator: std.mem.Allocator,
    
    const ConnectionContext = struct {
        id: [8]u8,
        peer_address: []const u8,
        established_at: u64,
        shared_secret: ?[64]u8,
        packet_count: u64,
    };
    
    pub fn init(allocator: std.mem.Allocator, bind_address: []const u8) !GhostDaemon {
        // Initialize post-quantum hybrid QUIC
        const quic_crypto = zcrypto.quic.QuicCrypto.init(
            .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384
        );
        
        // Configure TLS for secure handshakes
        const alpn_protocols = [_][]const u8{ "ghostchain/1.0", "h3" };
        const tls_config = zcrypto.tls.config.TlsConfig.init(allocator)
            .withServerName("ghostchain.local")
            .withALPN(@constCast(&alpn_protocols))
            .withInsecureSkipVerify(false);
        
        return GhostDaemon{
            .quic_crypto = quic_crypto,
            .tls_config = tls_config,
            .connections = std.HashMap(u64, ConnectionContext).init(allocator),
            .hybrid_keys = try zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate(),
            .allocator = allocator,
        };
    }
    
    /// Handle new peer connection with post-quantum handshake
    pub fn handleNewPeer(self: *GhostDaemon, peer_address: []const u8) !u64 {
        // Generate unique connection ID
        var connection_id: [8]u8 = undefined;
        std.crypto.random.bytes(&connection_id);
        
        // Derive QUIC keys for this connection
        try self.quic_crypto.deriveInitialKeys(&connection_id);
        
        // Create connection context
        const conn_hash = std.hash.Wyhash.hash(0, &connection_id);
        try self.connections.put(conn_hash, ConnectionContext{
            .id = connection_id,
            .peer_address = try self.allocator.dupe(u8, peer_address),
            .established_at = @intCast(std.time.timestamp()),
            .shared_secret = null,
            .packet_count = 0,
        });
        
        std.debug.print("🔗 New GhostChain peer: {s} (ID: {any})\n", 
            .{ peer_address, connection_id });
        
        return conn_hash;
    }
    
    /// Process encrypted packet with zero-copy performance
    pub fn processPacket(
        self: *GhostDaemon,
        connection_hash: u64,
        packet: []u8,
        header_len: usize,
    ) ![]const u8 {
        var connection = self.connections.getPtr(connection_hash) orelse {
            return error.UnknownConnection;
        };
        
        // Increment packet counter
        connection.packet_count += 1;
        
        // Decrypt packet in-place for maximum performance
        const payload_len = try zcrypto.quic.ZeroCopy.decryptInPlace(
            &self.quic_crypto,
            .application,
            true, // server-side
            connection.packet_count,
            packet,
            header_len,
        );
        
        return packet[header_len..header_len + payload_len];
    }
    
    /// Broadcast message to all connected peers
    pub fn broadcastMessage(self: *GhostDaemon, message: []const u8) !void {
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            const connection = entry.value_ptr;
            
            // Create packet buffer
            var packet_buffer: [4096]u8 = undefined;
            const header = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x01 }; // QUIC header
            @memcpy(packet_buffer[0..header.len], &header);
            @memcpy(packet_buffer[header.len..header.len + message.len], message);
            
            // Encrypt for this connection
            try zcrypto.quic.ZeroCopy.encryptInPlace(
                &self.quic_crypto,
                .application,
                true, // server-side
                connection.packet_count + 1,
                packet_buffer[0..header.len + message.len],
                header.len,
            );
            
            std.debug.print("📡 Broadcasted to {s}\n", .{connection.peer_address});
        }
    }
    
    pub fn deinit(self: *GhostDaemon) void {
        // Cleanup connections
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.peer_address);
        }
        self.connections.deinit();
        self.tls_config.deinit();
    }
};
```

---

## 💰 **WALLETD - CRYPTOCURRENCY WALLET**

**Purpose**: Secure multi-currency wallet daemon with encrypted storage.

### **Core Features**
- ✅ Multi-currency support (GhostChain, Bitcoin, Ethereum, NIST)
- ✅ Deterministic key generation from seed phrases
- ✅ AES-128-GCM encrypted storage with master key derivation
- ✅ Address generation for all supported currencies
- ✅ Transaction signing with appropriate curves

### **Implementation**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

/// Secure cryptocurrency wallet for GhostChain
pub const WalletDaemon = struct {
    // Multi-currency support
    ed25519_keys: zcrypto.asym.ed25519.KeyPair,     // GhostChain native
    secp256k1_keys: zcrypto.asym.secp256k1.KeyPair, // Bitcoin/Ethereum
    secp256r1_keys: zcrypto.asym.secp256r1.KeyPair, // NIST compliance
    
    // Encryption for wallet storage
    master_key: [32]u8,
    encrypted_storage: std.HashMap([]const u8, []u8),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, password: []const u8) !WalletDaemon {
        // Derive master key from password
        const master_key_bytes = try zcrypto.kdf.deriveKey(
            allocator, password, "walletd-master-v1", 32
        );
        defer allocator.free(master_key_bytes);
        
        var master_key: [32]u8 = undefined;
        @memcpy(&master_key, master_key_bytes[0..32]);
        
        return WalletDaemon{
            .ed25519_keys = zcrypto.asym.ed25519.generate(),
            .secp256k1_keys = zcrypto.asym.secp256k1.generate(),
            .secp256r1_keys = zcrypto.asym.secp256r1.generate(),
            .master_key = master_key,
            .encrypted_storage = std.HashMap([]const u8, []u8).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Generate deterministic wallet from seed phrase
    pub fn fromSeedPhrase(
        allocator: std.mem.Allocator,
        seed_phrase: []const u8,
    ) !WalletDaemon {
        // Hash seed phrase to create deterministic seed
        const seed_hash = zcrypto.hash.sha256(seed_phrase);
        
        return WalletDaemon{
            .ed25519_keys = zcrypto.asym.ed25519.generateFromSeed(seed_hash),
            .secp256k1_keys = zcrypto.asym.secp256k1.generate(), // TODO: deterministic
            .secp256r1_keys = zcrypto.asym.secp256r1.generate(), // TODO: deterministic
            .master_key = seed_hash,
            .encrypted_storage = std.HashMap([]const u8, []u8).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Sign transaction for different cryptocurrencies
    pub fn signTransaction(
        self: *const WalletDaemon,
        currency: enum { ghostchain, bitcoin, ethereum, nist },
        transaction_data: []const u8,
    ) ![]u8 {
        const tx_hash = zcrypto.hash.sha256(transaction_data);
        
        switch (currency) {
            .ghostchain => {
                const signature = try self.ed25519_keys.sign(transaction_data);
                return try self.allocator.dupe(u8, &signature);
            },
            .bitcoin, .ethereum => {
                const signature = try self.secp256k1_keys.sign(tx_hash);
                return try self.allocator.dupe(u8, &signature);
            },
            .nist => {
                const signature = try self.secp256r1_keys.sign(tx_hash);
                return try self.allocator.dupe(u8, &signature);
            },
        }
    }
    
    /// Export public keys for address generation
    pub fn getPublicKeys(self: *const WalletDaemon) struct {
        ghostchain: [32]u8,
        bitcoin_compressed: [33]u8,
        bitcoin_x_only: [32]u8,
        ethereum: [33]u8,
        nist: [33]u8,
    } {
        return .{
            .ghostchain = self.ed25519_keys.public_key,
            .bitcoin_compressed = self.secp256k1_keys.public_key_compressed,
            .bitcoin_x_only = self.secp256k1_keys.public_key_x,
            .ethereum = self.secp256k1_keys.public_key_compressed,
            .nist = self.secp256r1_keys.public_key,
        };
    }
    
    /// Encrypt and store sensitive data
    pub fn storeEncrypted(
        self: *WalletDaemon,
        key: []const u8,
        data: []const u8,
    ) !void {
        // Generate unique nonce for this storage
        const nonce = zcrypto.rand.randomArray(12);
        
        // Encrypt data using master key
        const encrypted = try zcrypto.sym.encryptAes128Gcm(
            self.allocator,
            self.master_key[0..16].*,
            nonce,
            data,
            key, // Use key as additional authenticated data
        );
        
        // Store with nonce prepended
        const storage_data = try self.allocator.alloc(u8, 12 + encrypted.data.len + 16);
        @memcpy(storage_data[0..12], &nonce);
        @memcpy(storage_data[12..12 + encrypted.data.len], encrypted.data);
        @memcpy(storage_data[12 + encrypted.data.len..], &encrypted.tag);
        
        const key_copy = try self.allocator.dupe(u8, key);
        try self.encrypted_storage.put(key_copy, storage_data);
        
        encrypted.deinit();
    }
    
    pub fn deinit(self: *WalletDaemon) void {
        // Secure cleanup
        self.ed25519_keys.zeroize();
        self.secp256k1_keys.zeroize();
        self.secp256r1_keys.zeroize();
        std.crypto.utils.secureZero(u8, &self.master_key);
        
        // Free encrypted storage
        var iterator = self.encrypted_storage.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.encrypted_storage.deinit();
    }
};
```

---

## 📦 **ZLEDGER - BLOCKCHAIN LEDGER**

**Purpose**: High-performance blockchain ledger with post-quantum security.

### **Core Features**
- ✅ Hybrid Ed25519 + ML-DSA-65 block signatures
- ✅ Merkle tree transaction verification
- ✅ Proof-of-work mining with SHA-3
- ✅ Block validation and integrity checking
- ✅ Merkle proof generation for transaction inclusion

### **Implementation**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

/// High-performance blockchain ledger for GhostChain
pub const ZLedger = struct {
    // Block signing authority
    validator_keys: zcrypto.asym.ed25519.KeyPair,
    pq_validator_keys: zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair,
    
    // Block storage and validation
    blocks: std.ArrayList(Block),
    merkle_trees: std.HashMap([32]u8, MerkleTree),
    allocator: std.mem.Allocator,
    
    const Block = struct {
        height: u64,
        previous_hash: [32]u8,
        merkle_root: [32]u8,
        timestamp: u64,
        transactions: [][32]u8, // Transaction hashes
        validator_signature: [64]u8,
        pq_signature: [3309]u8,
        nonce: u64,
    };
    
    const MerkleTree = struct {
        root: [32]u8,
        leaves: [][32]u8,
        proof_nodes: [][32]u8,
    };
    
    pub fn init(allocator: std.mem.Allocator) !ZLedger {
        return ZLedger{
            .validator_keys = zcrypto.asym.ed25519.generate(),
            .pq_validator_keys = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.generateRandom(allocator),
            .blocks = std.ArrayList(Block).init(allocator),
            .merkle_trees = std.HashMap([32]u8, MerkleTree).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Create and validate new block
    pub fn createBlock(
        self: *ZLedger,
        transactions: []const [32]u8,
    ) !Block {
        const height = self.blocks.items.len;
        const previous_hash = if (height > 0) 
            self.calculateBlockHash(self.blocks.items[height - 1])
        else 
            [_]u8{0} ** 32;
        
        // Build Merkle tree for transactions
        const merkle_tree = try self.buildMerkleTree(transactions);
        
        // Create block structure
        var block = Block{
            .height = height,
            .previous_hash = previous_hash,
            .merkle_root = merkle_tree.root,
            .timestamp = @intCast(std.time.timestamp()),
            .transactions = try self.allocator.dupe([32]u8, transactions),
            .validator_signature = undefined,
            .pq_signature = undefined,
            .nonce = 0,
        };
        
        // Mine block (simplified proof of work)
        while (true) {
            const block_hash = self.calculateBlockHash(block);
            if (block_hash[0] == 0 and block_hash[1] == 0) break; // 2-byte difficulty
            block.nonce += 1;
        }
        
        // Sign block with hybrid signatures
        const block_data = try self.serializeBlockForSigning(block);
        defer self.allocator.free(block_data);
        
        block.validator_signature = try self.validator_keys.sign(block_data);
        
        var pq_randomness: [32]u8 = undefined;
        std.crypto.random.bytes(&pq_randomness);
        block.pq_signature = try self.pq_validator_keys.sign(block_data, pq_randomness);
        
        // Store Merkle tree
        try self.merkle_trees.put(merkle_tree.root, merkle_tree);
        
        return block;
    }
    
    /// Validate block integrity and signatures
    pub fn validateBlock(
        self: *const ZLedger,
        block: Block,
        validator_public: [32]u8,
        pq_public: [1952]u8,
    ) !bool {
        // Validate proof of work
        const block_hash = self.calculateBlockHash(block);
        if (block_hash[0] != 0 or block_hash[1] != 0) return false;
        
        // Validate Merkle root
        const computed_merkle = try self.buildMerkleTree(block.transactions);
        defer self.allocator.free(computed_merkle.leaves);
        defer self.allocator.free(computed_merkle.proof_nodes);
        
        if (!std.mem.eql(u8, &computed_merkle.root, &block.merkle_root)) {
            return false;
        }
        
        // Validate signatures
        const block_data = try self.serializeBlockForSigning(block);
        defer self.allocator.free(block_data);
        
        const classical_valid = zcrypto.asym.ed25519.verify(
            block_data, block.validator_signature, validator_public
        );
        
        const pq_valid = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.verify(
            pq_public, block_data, block.pq_signature
        );
        
        return classical_valid and pq_valid;
    }
    
    pub fn deinit(self: *ZLedger) void {
        // Cleanup blocks
        for (self.blocks.items) |block| {
            self.allocator.free(block.transactions);
        }
        self.blocks.deinit();
        
        // Cleanup Merkle trees
        var tree_iter = self.merkle_trees.iterator();
        while (tree_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.leaves);
            self.allocator.free(entry.value_ptr.proof_nodes);
        }
        self.merkle_trees.deinit();
        
        // Secure key cleanup
        self.validator_keys.zeroize();
    }
};
```

---

## ⚡ **ZVM - VIRTUAL MACHINE**

**Purpose**: Secure virtual machine with built-in cryptographic operations.

### **Core Features**
- ✅ Cryptographically signed program execution
- ✅ Built-in Ed25519 and secp256k1 operations
- ✅ Secure random number generation
- ✅ Key derivation and secure memory management
- ✅ Trusted program verification and sandboxing

### **Implementation**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

/// Secure virtual machine with built-in cryptographic operations
pub const ZVM = struct {
    // VM execution context
    stack: std.ArrayList(Value),
    memory: []u8,
    program_counter: usize,
    
    // Cryptographic context
    crypto_keys: CryptoContext,
    trusted_signatures: std.HashMap([32]u8, bool),
    allocator: std.mem.Allocator,
    
    const Value = union(enum) {
        integer: i64,
        bytes: []const u8,
        hash: [32]u8,
        signature: [64]u8,
        public_key: [32]u8,
    };
    
    const CryptoContext = struct {
        ed25519_keys: zcrypto.asym.ed25519.KeyPair,
        secp256k1_keys: zcrypto.asym.secp256k1.KeyPair,
        execution_keypair: zcrypto.asym.ed25519.KeyPair,
        secure_random_state: std.rand.DefaultPrng,
    };
    
    const Opcode = enum(u8) {
        // Cryptographic operations
        hash_sha256 = 0x10,
        sign_ed25519 = 0x12,
        verify_ed25519 = 0x13,
        keygen_ed25519 = 0x20,
        secure_random = 0x30,
        derive_key = 0x22,
        verify_program = 0x32,
        halt = 0xFF,
    };
    
    pub fn init(allocator: std.mem.Allocator, memory_size: usize) !ZVM {
        var secure_seed: [32]u8 = undefined;
        std.crypto.random.bytes(&secure_seed);
        
        return ZVM{
            .stack = std.ArrayList(Value).init(allocator),
            .memory = try allocator.alloc(u8, memory_size),
            .program_counter = 0,
            .crypto_keys = CryptoContext{
                .ed25519_keys = zcrypto.asym.ed25519.generate(),
                .secp256k1_keys = zcrypto.asym.secp256k1.generate(),
                .execution_keypair = zcrypto.asym.ed25519.generate(),
                .secure_random_state = std.rand.DefaultPrng.init(@bitCast(secure_seed[0..8].*)),
            },
            .trusted_signatures = std.HashMap([32]u8, bool).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Execute cryptographically signed program
    pub fn executeProgram(
        self: *ZVM,
        program: []const u8,
        program_signature: [64]u8,
        signer_public_key: [32]u8,
    ) !void {
        // Verify program integrity
        const program_hash = zcrypto.hash.sha256(program);
        const signature_valid = zcrypto.asym.ed25519.verify(
            program, program_signature, signer_public_key
        );
        
        if (!signature_valid) {
            return error.InvalidProgramSignature;
        }
        
        // Check if signer is trusted
        if (!self.trusted_signatures.contains(program_hash)) {
            std.debug.print("⚠️  Executing untrusted program from: {any}\n", .{signer_public_key});
        }
        
        self.program_counter = 0;
        
        while (self.program_counter < program.len) {
            const opcode: Opcode = @enumFromInt(program[self.program_counter]);
            try self.executeOpcode(opcode, program);
        }
    }
    
    pub fn deinit(self: *ZVM) void {
        // Secure cleanup
        self.crypto_keys.ed25519_keys.zeroize();
        self.crypto_keys.secp256k1_keys.zeroize();
        self.crypto_keys.execution_keypair.zeroize();
        
        // Clear memory
        std.crypto.utils.secureZero(u8, self.memory);
        self.allocator.free(self.memory);
        
        self.stack.deinit();
        self.trusted_signatures.deinit();
    }
};
```

---

## 🔄 **COMMON INTEGRATION PATTERNS**

### **Error Handling**

```zig
const CryptoError = error{
    InvalidPrivateKey,
    SigningFailed,
    VerificationFailed,
    KeyDerivationFailed,
    InvalidInput,
};

fn handleCryptoOperation() !void {
    const keypair = zcrypto.asym.ed25519.generate();
    
    const signature = keypair.sign("message") catch |err| switch (err) {
        error.InvalidInput => {
            std.log.err("Invalid input provided to signing function");
            return;
        },
        error.SigningFailed => {
            std.log.err("Failed to create signature");
            return;
        },
        else => return err,
    };
    
    _ = signature;
}
```

### **Memory Management**

```zig
pub fn efficientCrypto(allocator: std.mem.Allocator) !void {
    // Use stack allocation for keys
    var keypair: zcrypto.asym.ed25519.KeyPair = undefined;
    keypair = zcrypto.asym.ed25519.generate();
    
    // Use arena allocator for temporary operations
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();
    
    // Temporary keys automatically freed
    const derived_key = try zcrypto.kdf.deriveKey(
        arena_allocator, "master", "derived", 32
    );
    _ = derived_key;
    
    // Secure cleanup
    defer keypair.zeroize();
}
```

### **Key Generation Patterns**

```zig
// Deterministic keys for testing
const test_seed = [_]u8{42} ** 32;
const test_keypair = zcrypto.asym.ed25519.generateFromSeed(test_seed);

// Random keys for production
const prod_keypair = zcrypto.asym.ed25519.generate();

// Hybrid post-quantum keys
const hybrid_keypair = try zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate();
```

---

## 🛡️ **SECURITY BEST PRACTICES**

### **1. Key Management**
- ✅ Always call `.zeroize()` on keypairs when done
- ✅ Use deterministic keys only for testing
- ✅ Store private keys encrypted with strong passwords
- ✅ Use secure random number generation

### **2. Signature Verification**
- ✅ Always verify signatures before processing data
- ✅ Use hybrid signatures for critical operations
- ✅ Implement replay protection with timestamps
- ✅ Validate all public keys before use

### **3. Memory Security**
- ✅ Use `std.crypto.utils.secureZero()` for sensitive data
- ✅ Prefer stack allocation for temporary keys
- ✅ Use arena allocators for batch operations
- ✅ Clear stack variables containing secrets

### **4. Network Security**
- ✅ Use post-quantum QUIC for network communications
- ✅ Implement proper TLS 1.3 configuration
- ✅ Use authenticated encryption for all data
- ✅ Validate connection certificates

---

## ⚡ **PERFORMANCE GUIDELINES**

### **1. Zero-Copy Operations**
```zig
// Use in-place encryption for high throughput
try zcrypto.quic.ZeroCopy.encryptInPlace(
    &crypto, .application, true, packet_number, packet, header_len
);
```

### **2. Batch Processing**
```zig
// Batch sign multiple documents
const signatures = try zsig.batchSignDocuments(documents);
```

### **3. Efficient Memory Patterns**
- Use stack allocation for keys when possible
- Prefer arena allocators for temporary operations
- Reuse buffers for repeated operations
- Minimize heap allocations in hot paths

### **4. Algorithm Selection**
- **Ed25519**: Best for general-purpose signing
- **secp256k1**: Required for Bitcoin/Ethereum compatibility
- **ML-DSA-65**: Use for post-quantum security
- **Hybrid**: Use for maximum security with performance trade-offs

---

## 🎯 **INTEGRATION CHECKLIST**

### **Before Integration**
- [ ] Verify zcrypto v0.5.0 is installed and building
- [ ] Read this documentation thoroughly
- [ ] Choose appropriate algorithms for your use case
- [ ] Plan key management and storage strategy

### **During Development**
- [ ] Use correct API patterns (64-byte Ed25519 private keys, etc.)
- [ ] Implement proper error handling
- [ ] Add secure memory cleanup
- [ ] Write comprehensive tests

### **Before Production**
- [ ] Security audit of key management
- [ ] Performance testing under load
- [ ] Verify all signatures are validated
- [ ] Test disaster recovery procedures

---

**🚀 Ready to build the future of secure computing with GhostChain!**

*For questions and support, refer to the individual project documentation and zcrypto API reference.*