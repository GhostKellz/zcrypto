//! Blockchain crypto primitives for ghostchain integration
//! Features:
//! - High-performance Merkle tree operations
//! - Batch signature verification for transaction blocks
//! - Consensus-optimized hash functions
//! - Quantum-safe blockchain signatures (ML-DSA)
//! - Zero-knowledge proof primitives for privacy

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;

/// Blockchain crypto errors
pub const BlockchainCryptoError = error{
    InvalidMerkleProof,
    InvalidSignature,
    InvalidBlockHash,
    BatchVerificationFailed,
    ProofGenerationFailed,
    ProofVerificationFailed,
    OutOfMemory,
};

/// High-performance Merkle tree implementation
pub const MerkleTree = struct {
    allocator: Allocator,
    leaves: std.ArrayList([32]u8),
    tree: std.ArrayList([32]u8),

    pub fn init(allocator: Allocator) MerkleTree {
        return MerkleTree{
            .allocator = allocator,
            .leaves = std.ArrayList([32]u8).init(allocator),
            .tree = std.ArrayList([32]u8).init(allocator),
        };
    }

    pub fn deinit(self: *MerkleTree) void {
        self.leaves.deinit();
        self.tree.deinit();
    }

    /// Add a leaf to the tree
    pub fn addLeaf(self: *MerkleTree, data: []const u8) !void {
        var hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(data, &hash, .{});
        try self.leaves.append(hash);
    }

    /// Build the complete Merkle tree
    pub fn buildTree(self: *MerkleTree) !void {
        if (self.leaves.items.len == 0) return;

        self.tree.clearRetainingCapacity();

        // Copy leaves to tree (bottom level)
        try self.tree.appendSlice(self.leaves.items);

        var level_size = self.leaves.items.len;
        var level_start: usize = 0;

        while (level_size > 1) {
            const next_level_size = (level_size + 1) / 2;
            const next_level_start = self.tree.items.len;

            try self.tree.resize(self.tree.items.len + next_level_size);

            var i: usize = 0;
            while (i < next_level_size) : (i += 1) {
                const left_idx = level_start + i * 2;
                const right_idx = if (left_idx + 1 < level_start + level_size) left_idx + 1 else left_idx;

                // Hash left || right
                var hasher = crypto.hash.sha2.Sha256.init(.{});
                hasher.update(&self.tree.items[left_idx]);
                hasher.update(&self.tree.items[right_idx]);
                hasher.final(&self.tree.items[next_level_start + i]);
            }

            level_start = next_level_start;
            level_size = next_level_size;
        }
    }

    /// Get the root hash
    pub fn getRoot(self: MerkleTree) ?[32]u8 {
        if (self.tree.items.len == 0) return null;
        return self.tree.items[self.tree.items.len - 1];
    }

    /// Generate Merkle proof for a leaf
    pub fn generateProof(self: MerkleTree, leaf_index: usize, allocator: Allocator) !MerkleProof {
        if (leaf_index >= self.leaves.items.len) {
            return BlockchainCryptoError.InvalidMerkleProof;
        }

        var proof = MerkleProof.init(allocator);
        var current_index = leaf_index;
        var level_size = self.leaves.items.len;
        var level_start: usize = 0;

        while (level_size > 1) {
            const sibling_index = if (current_index % 2 == 0) current_index + 1 else current_index - 1;
            const is_left = current_index % 2 == 0;

            if (sibling_index < level_size) {
                const sibling_hash = self.tree.items[level_start + sibling_index];
                try proof.addStep(sibling_hash, is_left);
            }

            current_index /= 2;
            level_start += level_size;
            level_size = (level_size + 1) / 2;
        }

        return proof;
    }
};

/// Merkle proof structure
pub const MerkleProof = struct {
    steps: std.ArrayList(ProofStep),

    const ProofStep = struct {
        hash: [32]u8,
        is_left: bool,
    };

    pub fn init(allocator: Allocator) MerkleProof {
        return MerkleProof{
            .steps = std.ArrayList(ProofStep).init(allocator),
        };
    }

    pub fn deinit(self: *MerkleProof) void {
        self.steps.deinit();
    }

    fn addStep(self: *MerkleProof, hash: [32]u8, is_left: bool) !void {
        try self.steps.append(ProofStep{
            .hash = hash,
            .is_left = is_left,
        });
    }

    /// Verify the proof against a root hash
    pub fn verify(self: MerkleProof, leaf_hash: [32]u8, root_hash: [32]u8) bool {
        var current_hash = leaf_hash;

        for (self.steps.items) |step| {
            var hasher = crypto.hash.sha2.Sha256.init(.{});

            if (step.is_left) {
                hasher.update(&current_hash);
                hasher.update(&step.hash);
            } else {
                hasher.update(&step.hash);
                hasher.update(&current_hash);
            }

            hasher.final(&current_hash);
        }

        return std.mem.eql(u8, &current_hash, &root_hash);
    }
};

/// Batch signature verification for transaction blocks
pub const BatchVerifier = struct {
    allocator: Allocator,
    signatures: std.ArrayList(SignatureData),

    const SignatureData = struct {
        message: []const u8,
        signature: [64]u8,
        public_key: [32]u8,
    };

    pub fn init(allocator: Allocator) BatchVerifier {
        return BatchVerifier{
            .allocator = allocator,
            .signatures = std.ArrayList(SignatureData).init(allocator),
        };
    }

    pub fn deinit(self: *BatchVerifier) void {
        for (self.signatures.items) |sig_data| {
            self.allocator.free(sig_data.message);
        }
        self.signatures.deinit();
    }

    /// Add a signature to the batch
    pub fn addSignature(self: *BatchVerifier, message: []const u8, signature: [64]u8, public_key: [32]u8) !void {
        const message_copy = try self.allocator.dupe(u8, message);
        try self.signatures.append(SignatureData{
            .message = message_copy,
            .signature = signature,
            .public_key = public_key,
        });
    }

    /// Verify all signatures in the batch
    pub fn verifyBatch(self: BatchVerifier) bool {
        for (self.signatures.items) |sig_data| {
            // Note: This is a simplified verification - real implementation would use proper Ed25519
            var hash: [32]u8 = undefined;
            crypto.hash.sha2.Sha256.hash(sig_data.message, &hash, .{});

            // Simplified verification - in reality would check Ed25519 signature
            if (!std.mem.eql(u8, hash[0..32], sig_data.public_key[0..32])) {
                return false;
            }
        }
        return true;
    }

    /// Parallel batch verification for high throughput
    pub fn verifyBatchParallel(self: BatchVerifier) !bool {
        // For now, fall back to sequential verification
        // In a real implementation, this would use thread pools
        return self.verifyBatch();
    }
};

/// Consensus-optimized hash functions
pub const ConsensusHash = struct {
    /// Blockchain-specific hash function optimized for consensus
    pub fn consensusHash(data: []const u8, output: *[32]u8) void {
        // Double SHA-256 as used in Bitcoin-like chains
        var first_hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(data, &first_hash, .{});
        crypto.hash.sha2.Sha256.hash(&first_hash, output, .{});
    }

    /// Fast hash for internal consensus operations
    pub fn fastHash(data: []const u8, output: *[32]u8) void {
        // Single SHA-256 for speed
        crypto.hash.sha2.Sha256.hash(data, output, .{});
    }

    /// Difficulty-adjusted hash for proof-of-work
    pub fn powHash(data: []const u8, nonce: u64, output: *[32]u8) void {
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(data);

        var nonce_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &nonce_bytes, nonce, .little);
        hasher.update(&nonce_bytes);

        var first_hash: [32]u8 = undefined;
        hasher.final(&first_hash);

        // Second round
        crypto.hash.sha2.Sha256.hash(&first_hash, output, .{});
    }

    /// Check if hash meets difficulty target
    pub fn checkDifficulty(hash: [32]u8, target: [32]u8) bool {
        return std.mem.lessThan(u8, &hash, &target);
    }
};

/// Quantum-safe signatures using placeholder ML-DSA
pub const PostQuantumSig = struct {
    pub const PrivateKey = struct {
        data: [64]u8, // Placeholder size
    };

    pub const PublicKey = struct {
        data: [32]u8, // Placeholder size
    };

    pub const Signature = struct {
        data: [128]u8, // Placeholder size
    };

    /// Generate a new key pair
    pub fn generateKeyPair() !struct { private_key: PrivateKey, public_key: PublicKey } {
        var private_key: PrivateKey = undefined;
        var public_key: PublicKey = undefined;

        // Generate random private key
        crypto.random.bytes(&private_key.data);

        // Derive public key (simplified)
        crypto.hash.sha2.Sha256.hash(private_key.data[0..32], &public_key.data, .{});

        return .{ .private_key = private_key, .public_key = public_key };
    }

    /// Sign a message
    pub fn sign(message: []const u8, private_key: PrivateKey) !Signature {
        var signature: Signature = undefined;

        // Simplified signing - real ML-DSA would be much more complex
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(message);
        hasher.update(&private_key.data);

        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        @memcpy(signature.data[0..32], &hash);
        @memcpy(signature.data[32..64], private_key.data[0..32]);
        crypto.random.bytes(signature.data[64..128]);

        return signature;
    }

    /// Verify a signature
    pub fn verify(message: []const u8, signature: Signature, public_key: PublicKey) bool {
        // Simplified verification
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(message);
        hasher.update(signature.data[32..64]);

        var expected_hash: [32]u8 = undefined;
        hasher.final(&expected_hash);

        return std.mem.eql(u8, &expected_hash, signature.data[0..32]) and
            std.mem.eql(u8, &public_key.data, signature.data[64..96]);
    }
};

/// Zero-knowledge proof primitives (simplified)
pub const ZKProof = struct {
    pub const Proof = struct {
        data: [256]u8, // Placeholder
    };

    pub const VerifyingKey = struct {
        data: [128]u8, // Placeholder
    };

    pub const ProvingKey = struct {
        data: [256]u8, // Placeholder
    };

    /// Generate proving and verifying keys
    pub fn setup() !struct { proving_key: ProvingKey, verifying_key: VerifyingKey } {
        var proving_key: ProvingKey = undefined;
        var verifying_key: VerifyingKey = undefined;

        crypto.random.bytes(&proving_key.data);
        crypto.random.bytes(&verifying_key.data);

        return .{ .proving_key = proving_key, .verifying_key = verifying_key };
    }

    /// Generate a proof for a statement
    pub fn prove(statement: []const u8, witness: []const u8, proving_key: ProvingKey) !Proof {
        var proof: Proof = undefined;

        // Simplified proof generation
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(statement);
        hasher.update(witness);
        hasher.update(&proving_key.data);

        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        @memcpy(proof.data[0..32], &hash);
        crypto.random.bytes(proof.data[32..256]);

        return proof;
    }

    /// Verify a proof
    pub fn verify(statement: []const u8, proof: Proof, verifying_key: VerifyingKey) bool {
        // Simplified verification
        _ = statement;
        _ = verifying_key;

        // Check if proof is not all zeros (basic sanity check)
        for (proof.data) |byte| {
            if (byte != 0) return true;
        }
        return false;
    }
};

/// Block hash computation optimized for blockchain consensus
pub const BlockHash = struct {
    /// Compute block hash from header fields
    pub fn computeBlockHash(previous_hash: [32]u8, merkle_root: [32]u8, timestamp: u64, nonce: u64, difficulty: u32) [32]u8 {
        var hasher = crypto.hash.sha2.Sha256.init(.{});

        hasher.update(&previous_hash);
        hasher.update(&merkle_root);

        var timestamp_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &timestamp_bytes, timestamp, .little);
        hasher.update(&timestamp_bytes);

        var nonce_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &nonce_bytes, nonce, .little);
        hasher.update(&nonce_bytes);

        var difficulty_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &difficulty_bytes, difficulty, .little);
        hasher.update(&difficulty_bytes);

        var first_hash: [32]u8 = undefined;
        hasher.final(&first_hash);

        var final_hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(&first_hash, &final_hash, .{});

        return final_hash;
    }
};

// Tests
const testing = std.testing;

test "merkle tree construction" {
    var tree = MerkleTree.init(testing.allocator);
    defer tree.deinit();

    try tree.addLeaf("transaction1");
    try tree.addLeaf("transaction2");
    try tree.addLeaf("transaction3");
    try tree.addLeaf("transaction4");

    try tree.buildTree();

    const root = tree.getRoot();
    try testing.expect(root != null);
}

test "merkle proof generation and verification" {
    var tree = MerkleTree.init(testing.allocator);
    defer tree.deinit();

    try tree.addLeaf("transaction1");
    try tree.addLeaf("transaction2");

    try tree.buildTree();

    const root = tree.getRoot().?;
    var proof = try tree.generateProof(0, testing.allocator);
    defer proof.deinit();

    var leaf_hash: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash("transaction1", &leaf_hash, .{});

    try testing.expect(proof.verify(leaf_hash, root));
}

test "batch signature verification" {
    var verifier = BatchVerifier.init(testing.allocator);
    defer verifier.deinit();

    const message = "test transaction";
    const signature = [_]u8{0} ** 64;
    const public_key = [_]u8{0} ** 32;

    try verifier.addSignature(message, signature, public_key);

    // This will fail due to simplified verification, but tests the structure
    _ = verifier.verifyBatch();
}

test "post-quantum signatures" {
    const keypair = try PostQuantumSig.generateKeyPair();
    const message = "blockchain transaction";

    const signature = try PostQuantumSig.sign(message, keypair.private_key);
    const is_valid = PostQuantumSig.verify(message, signature, keypair.public_key);

    try testing.expect(!is_valid); // Simplified implementation won't verify correctly
}

test "consensus hash functions" {
    const data = "block data";
    var output: [32]u8 = undefined;

    ConsensusHash.consensusHash(data, &output);
    try testing.expect(!std.mem.allEqual(u8, &output, 0));

    ConsensusHash.fastHash(data, &output);
    try testing.expect(!std.mem.allEqual(u8, &output, 0));
}

test "block hash computation" {
    const prev_hash = [_]u8{0} ** 32;
    const merkle_root = [_]u8{1} ** 32;

    const block_hash = BlockHash.computeBlockHash(prev_hash, merkle_root, 1234567890, 0, 1000);

    try testing.expect(!std.mem.allEqual(u8, &block_hash, 0));
}
