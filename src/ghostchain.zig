//! Ghostchain Blockchain Integration Module
//!
//! Type-safe wrappers and convenience functions specifically designed for
//! Ghostchain (Hedera Hashgraph 2.0) blockchain development.
//!
//! This module provides:
//! - Transaction signature verification
//! - Block hashing and Merkle trees
//! - Consensus signature aggregation
//! - High-performance batch operations
//! - Type-safe crypto primitives
//!
//! ## Usage
//!
//! ```zig
//! const ghostchain = @import("zcrypto").ghostchain;
//!
//! // Transaction processing
//! const tx_hash = ghostchain.hashTransaction(tx_bytes);
//! const valid = try ghostchain.verifyTransaction(tx);
//!
//! // Consensus operations
//! var workspace = try ghostchain.ConsensusWorkspace.init(allocator);
//! defer workspace.deinit();
//!
//! const results = try workspace.verifyGossipBatch(gossip_batch);
//! ```

const std = @import("std");
const asym = @import("asym.zig");
const blake3_mod = @import("blake3.zig");
const merkle_mod = @import("merkle.zig");
const batch_mod = @import("batch.zig");
const arena_mod = @import("arena.zig");
const timing_mod = @import("timing.zig");
const testing = std.testing;

/// Type aliases for blockchain crypto primitives
pub const PublicKey = [32]u8;
pub const PrivateKey = [64]u8;
pub const Signature = [64]u8;
pub const Hash = [32]u8;
pub const Address = [20]u8; // First 20 bytes of public key hash

/// Transaction signature structure
pub const TransactionSignature = struct {
    signature: Signature,
    public_key: PublicKey,
    signer_address: Address,
};

/// Block header hash structure
pub const BlockHash = struct {
    hash: Hash,
    merkle_root: Hash,
    timestamp: i64,
};

/// Hash transaction data using Blake3
///
/// Computes a deterministic hash of transaction bytes suitable for
/// signing, Merkle tree inclusion, and transaction ID.
///
/// ## Parameters
/// - `transaction_data`: Raw transaction bytes
///
/// ## Returns
/// 32-byte Blake3 hash of transaction
///
/// ## Example
/// ```zig
/// const tx_hash = hashTransaction(tx.serialize());
/// // Use as transaction ID or for signing
/// ```
pub fn hashTransaction(transaction_data: []const u8) Hash {
    return blake3_mod.blake3(transaction_data);
}

/// Hash block header using Blake3
///
/// Computes block header hash for block identification and chain linking.
///
/// ## Parameters
/// - `header_data`: Serialized block header
///
/// ## Returns
/// 32-byte Blake3 hash of block header
pub fn hashBlockHeader(header_data: []const u8) Hash {
    return blake3_mod.blake3(header_data);
}

/// Derive address from public key
///
/// Creates a 20-byte address by hashing the public key and taking first 20 bytes.
/// Compatible with Ethereum-style addressing.
///
/// ## Parameters
/// - `public_key`: Ed25519 public key (32 bytes)
///
/// ## Returns
/// 20-byte address
///
/// ## Example
/// ```zig
/// const address = deriveAddress(sender_pubkey);
/// ```
pub fn deriveAddress(public_key: PublicKey) Address {
    const hash = blake3_mod.blake3(&public_key);
    var address: Address = undefined;
    @memcpy(&address, hash[0..20]);
    return address;
}

/// Sign transaction with private key
///
/// Creates an Ed25519 signature over the transaction hash.
///
/// ## Parameters
/// - `transaction_data`: Raw transaction bytes
/// - `private_key`: Signer's private key
///
/// ## Returns
/// Ed25519 signature
///
/// ## Security
/// This function is constant-time with respect to the private key.
///
/// ## Example
/// ```zig
/// const sig = try signTransaction(tx.serialize(), my_private_key);
/// tx.signature = sig;
/// ```
pub fn signTransaction(
    transaction_data: []const u8,
    private_key: PrivateKey,
) !Signature {
    const tx_hash = hashTransaction(transaction_data);
    return try asym.ed25519.sign(&tx_hash, private_key);
}

/// Verify transaction signature
///
/// Verifies an Ed25519 signature over a transaction.
///
/// ## Parameters
/// - `transaction_data`: Raw transaction bytes
/// - `signature`: Ed25519 signature to verify
/// - `public_key`: Signer's public key
///
/// ## Returns
/// `true` if signature is valid, `false` otherwise
///
/// ## Example
/// ```zig
/// const valid = verifyTransaction(
///     tx.serialize(),
///     tx.signature,
///     tx.sender_pubkey,
/// );
/// if (!valid) return error.InvalidSignature;
/// ```
pub fn verifyTransaction(
    transaction_data: []const u8,
    signature: Signature,
    public_key: PublicKey,
) bool {
    const tx_hash = hashTransaction(transaction_data);
    return asym.ed25519.verify(&tx_hash, signature, public_key);
}

/// Build Merkle tree from transaction hashes
///
/// Creates a Merkle tree for transaction commitment in a block.
///
/// ## Parameters
/// - `allocator`: Memory allocator
/// - `transaction_hashes`: Array of transaction hashes
///
/// ## Returns
/// Merkle tree with root for block header
///
/// ## Example
/// ```zig
/// const tree = try buildTransactionMerkleTree(allocator, tx_hashes);
/// defer tree.deinit();
///
/// const merkle_root = tree.root();
/// block.header.merkle_root = merkle_root;
/// ```
pub fn buildTransactionMerkleTree(
    allocator: std.mem.Allocator,
    transaction_hashes: []const Hash,
) !merkle_mod.MerkleTree {
    return try merkle_mod.MerkleTree.build(allocator, transaction_hashes);
}

/// Generate Merkle proof for transaction inclusion
///
/// Creates a proof that a transaction is included in a block.
///
/// ## Parameters
/// - `tree`: Merkle tree from block
/// - `transaction_index`: Index of transaction in block
///
/// ## Returns
/// Merkle proof (array of sibling hashes)
///
/// ## Example
/// ```zig
/// const proof = try generateTransactionProof(&tree, tx_index);
/// defer allocator.free(proof);
///
/// // Light client can verify transaction inclusion
/// ```
pub fn generateTransactionProof(
    tree: *const merkle_mod.MerkleTree,
    transaction_index: usize,
) ![]Hash {
    return try tree.generateProof(transaction_index);
}

/// Verify Merkle proof for transaction
///
/// Verifies that a transaction is included in a block using Merkle proof.
///
/// ## Parameters
/// - `tree`: Merkle tree (or just need root hash)
/// - `transaction_hash`: Hash of transaction to verify
/// - `transaction_index`: Position in block
/// - `proof`: Merkle proof (sibling hashes)
///
/// ## Returns
/// `true` if transaction is in block, `false` otherwise
///
/// ## Example
/// ```zig
/// const valid = tree.verifyProof(tx_hash, tx_index, proof);
/// if (valid) {
///     // Transaction is confirmed in block
/// }
/// ```
pub fn verifyTransactionProof(
    tree: *const merkle_mod.MerkleTree,
    transaction_hash: Hash,
    transaction_index: usize,
    proof: []const Hash,
) bool {
    return tree.verifyProof(transaction_hash, transaction_index, proof);
}

/// Consensus workspace for high-performance gossip processing
///
/// Provides optimized crypto operations for consensus round processing.
/// Uses arena allocation for efficient batch processing.
///
/// ## Usage
/// ```zig
/// var workspace = try ConsensusWorkspace.init(allocator);
/// defer workspace.deinit();
///
/// while (consensus_active) {
///     const gossip = receive_gossip_round();
///
///     const results = try workspace.verifyGossipBatch(
///         gossip.messages,
///         gossip.signatures,
///         gossip.public_keys,
///     );
///
///     process_verified_gossip(results);
///     workspace.reset(); // Reuse memory for next round
/// }
/// ```
pub const ConsensusWorkspace = struct {
    crypto_workspace: arena_mod.CryptoWorkspace,
    allocator: std.mem.Allocator,

    /// Initialize consensus workspace
    pub fn init(allocator: std.mem.Allocator) ConsensusWorkspace {
        return .{
            .crypto_workspace = arena_mod.CryptoWorkspace.init(allocator),
            .allocator = allocator,
        };
    }

    /// Free workspace
    pub fn deinit(self: *ConsensusWorkspace) void {
        self.crypto_workspace.deinit();
    }

    /// Reset workspace for next consensus round
    pub fn reset(self: *ConsensusWorkspace) void {
        self.crypto_workspace.reset();
    }

    /// Verify batch of gossip signatures (sequential)
    ///
    /// ## Parameters
    /// - `messages`: Array of gossip messages
    /// - `signatures`: Array of signatures
    /// - `public_keys`: Array of validator public keys
    ///
    /// ## Returns
    /// Array of verification results
    pub fn verifyGossipBatch(
        self: *ConsensusWorkspace,
        messages: []const []const u8,
        signatures: []const Signature,
        public_keys: []const PublicKey,
    ) ![]bool {
        return try self.crypto_workspace.verifyBatch(
            messages,
            signatures,
            public_keys,
        );
    }

    /// Verify batch of gossip signatures (parallel)
    ///
    /// Uses multiple threads for 4-8x speedup on multi-core systems.
    ///
    /// ## Parameters
    /// - `messages`: Array of gossip messages
    /// - `signatures`: Array of signatures
    /// - `public_keys`: Array of validator public keys
    /// - `thread_count`: Number of threads (0 = auto-detect)
    ///
    /// ## Returns
    /// Array of verification results
    ///
    /// ## Performance
    /// Best for batches > 100 signatures. For smaller batches, use
    /// `verifyGossipBatch` (sequential) instead.
    pub fn verifyGossipBatchParallel(
        self: *ConsensusWorkspace,
        messages: []const []const u8,
        signatures: []const Signature,
        public_keys: []const PublicKey,
        thread_count: usize,
    ) ![]bool {
        return try self.crypto_workspace.verifyBatchParallel(
            messages,
            signatures,
            public_keys,
            thread_count,
        );
    }

    /// Fast-fail gossip verification
    ///
    /// Returns immediately on first invalid signature.
    /// More efficient for mempool validation where most sigs are valid.
    ///
    /// ## Returns
    /// `true` if all signatures valid, `false` if any invalid
    pub fn verifyGossipBatchFast(
        self: *ConsensusWorkspace,
        messages: []const []const u8,
        signatures: []const Signature,
        public_keys: []const PublicKey,
        thread_count: usize,
    ) !bool {
        return try batch_mod.verifyBatchEd25519Fast(
            messages,
            signatures,
            public_keys,
            thread_count,
            self.crypto_workspace.allocator(),
        );
    }

    /// Hash batch of transactions
    ///
    /// ## Parameters
    /// - `transactions`: Array of transaction data
    ///
    /// ## Returns
    /// Array of transaction hashes
    pub fn hashTransactionBatch(
        self: *ConsensusWorkspace,
        transactions: []const []const u8,
    ) ![]Hash {
        return try self.crypto_workspace.hashBatch(transactions);
    }
};

/// Blockchain crypto errors
pub const BlockchainCryptoError = error{
    InvalidSignature,
    InvalidPublicKey,
    InvalidTransactionHash,
    MerkleProofFailed,
    InvalidBlockHash,
};

//
// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================
//

/// Verify transaction with detailed error
///
/// Like `verifyTransaction` but returns specific error instead of bool.
///
/// ## Returns
/// `void` if valid, specific error if invalid
///
/// ## Example
/// ```zig
/// try verifyTransactionDetailed(tx.data, tx.signature, tx.pubkey);
/// // Throws error if invalid
/// ```
pub fn verifyTransactionDetailed(
    transaction_data: []const u8,
    signature: Signature,
    public_key: PublicKey,
) BlockchainCryptoError!void {
    if (!verifyTransaction(transaction_data, signature, public_key)) {
        return BlockchainCryptoError.InvalidSignature;
    }
}

/// Check if address matches public key
///
/// ## Parameters
/// - `address`: Address to check
/// - `public_key`: Public key to derive address from
///
/// ## Returns
/// `true` if address matches, `false` otherwise
///
/// ## Security
/// Uses constant-time comparison to prevent timing attacks.
pub fn verifyAddress(address: Address, public_key: PublicKey) bool {
    const derived = deriveAddress(public_key);
    return timing_mod.timingSafeEqual(&address, &derived);
}

//
// ============================================================================
// TESTS
// ============================================================================
//

test "hash transaction" {
    const tx_data = "transaction data";
    const hash1 = hashTransaction(tx_data);
    const hash2 = hashTransaction(tx_data);

    // Deterministic
    try testing.expectEqualSlices(u8, &hash1, &hash2);
    try testing.expectEqual(@as(usize, 32), hash1.len);
}

test "derive address" {
    const keypair = asym.ed25519.generate();
    const address = deriveAddress(keypair.public_key);

    try testing.expectEqual(@as(usize, 20), address.len);

    // Same key produces same address
    const address2 = deriveAddress(keypair.public_key);
    try testing.expectEqualSlices(u8, &address, &address2);
}

test "sign and verify transaction" {
    const keypair = asym.ed25519.generate();
    const tx_data = "test transaction";

    const sig = try signTransaction(tx_data, keypair.private_key);
    const valid = verifyTransaction(tx_data, sig, keypair.public_key);

    try testing.expect(valid);
}

test "verify transaction invalid signature" {
    const keypair = asym.ed25519.generate();
    const tx_data = "test transaction";

    const invalid_sig = [_]u8{0} ** 64;
    const valid = verifyTransaction(tx_data, invalid_sig, keypair.public_key);

    try testing.expect(!valid);
}

test "build transaction merkle tree" {
    const tx_hashes = &[_]Hash{
        blake3_mod.blake3("tx1"),
        blake3_mod.blake3("tx2"),
        blake3_mod.blake3("tx3"),
        blake3_mod.blake3("tx4"),
    };

    var tree = try buildTransactionMerkleTree(testing.allocator, tx_hashes);
    defer tree.deinit();

    const root = tree.root();
    try testing.expectEqual(@as(usize, 32), root.len);
}

test "transaction merkle proof" {
    const tx_hashes = &[_]Hash{
        blake3_mod.blake3("tx1"),
        blake3_mod.blake3("tx2"),
        blake3_mod.blake3("tx3"),
    };

    var tree = try buildTransactionMerkleTree(testing.allocator, tx_hashes);
    defer tree.deinit();

    // Generate and verify proof
    const proof = try generateTransactionProof(&tree, 1);
    defer testing.allocator.free(proof);

    const valid = verifyTransactionProof(&tree, tx_hashes[1], 1, proof);
    try testing.expect(valid);

    // Invalid proof should fail
    const invalid = verifyTransactionProof(&tree, tx_hashes[0], 1, proof);
    try testing.expect(!invalid);
}

test "ConsensusWorkspace basic" {
    var workspace = ConsensusWorkspace.init(testing.allocator);
    defer workspace.deinit();

    const keypair = asym.ed25519.generate();
    const message = "gossip message";
    const sig = try keypair.sign(message);

    const messages = &[_][]const u8{message};
    const signatures = &[_]Signature{sig};
    const public_keys = &[_]PublicKey{keypair.public_key};

    const results = try workspace.verifyGossipBatch(messages, signatures, public_keys);

    try testing.expect(results[0]);
}

test "ConsensusWorkspace reset and reuse" {
    var workspace = ConsensusWorkspace.init(testing.allocator);
    defer workspace.deinit();

    const keypair = asym.ed25519.generate();

    // First round
    {
        const msg = "round 1";
        const sig = try keypair.sign(msg);
        const messages = &[_][]const u8{msg};
        const sigs = &[_]Signature{sig};
        const keys = &[_]PublicKey{keypair.public_key};

        _ = try workspace.verifyGossipBatch(messages, sigs, keys);
        workspace.reset();
    }

    // Second round (reuses memory)
    {
        const msg = "round 2";
        const sig = try keypair.sign(msg);
        const messages = &[_][]const u8{msg};
        const sigs = &[_]Signature{sig};
        const keys = &[_]PublicKey{keypair.public_key};

        _ = try workspace.verifyGossipBatch(messages, sigs, keys);
        workspace.reset();
    }
}

test "verify address" {
    const keypair = asym.ed25519.generate();
    const address = deriveAddress(keypair.public_key);

    try testing.expect(verifyAddress(address, keypair.public_key));

    // Different key should not match
    const other_keypair = asym.ed25519.generate();
    try testing.expect(!verifyAddress(address, other_keypair.public_key));
}

test "verifyTransactionDetailed" {
    const keypair = asym.ed25519.generate();
    const tx_data = "test";

    const sig = try signTransaction(tx_data, keypair.private_key);

    // Valid signature should not error
    try verifyTransactionDetailed(tx_data, sig, keypair.public_key);

    // Invalid signature should error
    const invalid_sig = [_]u8{0} ** 64;
    const result = verifyTransactionDetailed(tx_data, invalid_sig, keypair.public_key);
    try testing.expectError(BlockchainCryptoError.InvalidSignature, result);
}
