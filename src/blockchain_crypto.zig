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
const rand = @import("rand.zig");

/// Blockchain crypto errors
pub const BlockchainCryptoError = error{
    InvalidMerkleProof,
    InvalidSignature,
    InvalidBlockHash,
    BatchVerificationFailed,
    ProofGenerationFailed,
    ProofVerificationFailed,
    OutOfMemory,
    /// No implementation backs the requested operation. Returned instead of a
    /// verification verdict so a caller cannot mistake "not implemented" for
    /// "valid".
    UnsupportedAlgorithm,
};

/// High-performance Merkle tree implementation
pub const MerkleTree = struct {
    allocator: Allocator,
    leaves: std.ArrayListUnmanaged([32]u8),
    tree: std.ArrayListUnmanaged([32]u8),

    pub fn init(allocator: Allocator) MerkleTree {
        return MerkleTree{
            .allocator = allocator,
            .leaves = .empty,
            .tree = .empty,
        };
    }

    pub fn deinit(self: *MerkleTree) void {
        self.leaves.deinit(self.allocator);
        self.tree.deinit(self.allocator);
    }

    /// Add a leaf to the tree
    pub fn addLeaf(self: *MerkleTree, data: []const u8) !void {
        var hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(data, &hash, .{});
        try self.leaves.append(self.allocator, hash);
    }

    /// Build the complete Merkle tree
    pub fn buildTree(self: *MerkleTree) !void {
        if (self.leaves.items.len == 0) return;

        self.tree.clearRetainingCapacity();

        // Copy leaves to tree (bottom level)
        try self.tree.appendSlice(self.allocator, self.leaves.items);

        var level_size = self.leaves.items.len;
        var level_start: usize = 0;

        while (level_size > 1) {
            const next_level_size = (level_size + 1) / 2;
            const next_level_start = self.tree.items.len;

            try self.tree.resize(self.allocator, self.tree.items.len + next_level_size);

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

    /// Number of nodes `buildTree` writes for a given leaf count.
    fn nodeCount(leaf_count: usize) usize {
        if (leaf_count == 0) return 0;
        var total = leaf_count;
        var level = leaf_count;
        while (level > 1) {
            level = (level + 1) / 2;
            total += level;
        }
        return total;
    }

    /// Get the root hash. Null until `buildTree` has run.
    pub fn getRoot(self: MerkleTree) ?[32]u8 {
        if (self.tree.items.len != nodeCount(self.leaves.items.len)) return null;
        if (self.tree.items.len == 0) return null;
        return self.tree.items[self.tree.items.len - 1];
    }

    /// Generate Merkle proof for a leaf
    pub fn generateProof(self: MerkleTree, leaf_index: usize, allocator: Allocator) !MerkleProof {
        if (leaf_index >= self.leaves.items.len) {
            return BlockchainCryptoError.InvalidMerkleProof;
        }
        // The walk below indexes `tree` using level offsets derived from the leaf
        // count, so it is only in bounds while the two agree. They diverge when
        // `buildTree` was never called, or when leaves were appended after it ran.
        if (self.tree.items.len != nodeCount(self.leaves.items.len)) {
            return BlockchainCryptoError.InvalidMerkleProof;
        }

        var proof = MerkleProof.init(allocator);
        errdefer proof.deinit();

        var current_index = leaf_index;
        var level_size = self.leaves.items.len;
        var level_start: usize = 0;

        while (level_size > 1) {
            const is_left = current_index % 2 == 0;
            const paired_index = if (is_left) current_index + 1 else current_index - 1;
            // `buildTree` hashes the final node of an odd-sized level against
            // itself, so the unpaired node's sibling is itself. Omitting the step
            // (the previous behaviour) produced proofs that never verified.
            const sibling_index = if (paired_index < level_size) paired_index else current_index;

            try proof.addStep(self.tree.items[level_start + sibling_index], is_left);

            current_index /= 2;
            level_start += level_size;
            level_size = (level_size + 1) / 2;
        }

        return proof;
    }
};

/// Merkle proof structure
pub const MerkleProof = struct {
    allocator: Allocator,
    steps: std.ArrayListUnmanaged(ProofStep),

    const ProofStep = struct {
        hash: [32]u8,
        is_left: bool,
    };

    pub fn init(allocator: Allocator) MerkleProof {
        return MerkleProof{
            .allocator = allocator,
            .steps = .empty,
        };
    }

    pub fn deinit(self: *MerkleProof) void {
        self.steps.deinit(self.allocator);
    }

    fn addStep(self: *MerkleProof, hash: [32]u8, is_left: bool) !void {
        try self.steps.append(self.allocator, ProofStep{
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
    signatures: std.ArrayListUnmanaged(SignatureData),

    const SignatureData = struct {
        message: []const u8,
        signature: [64]u8,
        public_key: [32]u8,
    };

    pub fn init(allocator: Allocator) BatchVerifier {
        return BatchVerifier{
            .allocator = allocator,
            .signatures = .empty,
        };
    }

    pub fn deinit(self: *BatchVerifier) void {
        for (self.signatures.items) |sig_data| {
            self.allocator.free(sig_data.message);
        }
        self.signatures.deinit(self.allocator);
    }

    /// Add a signature to the batch
    pub fn addSignature(self: *BatchVerifier, message: []const u8, signature: [64]u8, public_key: [32]u8) !void {
        const message_copy = try self.allocator.dupe(u8, message);
        try self.signatures.append(self.allocator, SignatureData{
            .message = message_copy,
            .signature = signature,
            .public_key = public_key,
        });
    }

    /// Verify every Ed25519 signature in the batch.
    ///
    /// Returns false as soon as one entry fails, including entries whose key or
    /// signature bytes are not a well-formed Ed25519 encoding. An empty batch
    /// verifies vacuously, matching the "all entries valid" contract.
    ///
    /// This checks each signature independently rather than using a randomized
    /// batch equation, so it is not faster than verifying one at a time; the
    /// name describes the input shape, not a speedup.
    pub fn verifyBatch(self: BatchVerifier) bool {
        for (self.signatures.items) |sig_data| {
            const public_key = crypto.sign.Ed25519.PublicKey.fromBytes(sig_data.public_key) catch return false;
            const signature = crypto.sign.Ed25519.Signature.fromBytes(sig_data.signature);
            signature.verify(sig_data.message, public_key) catch return false;
        }
        return true;
    }

    /// Same verification as `verifyBatch`, on the calling thread.
    ///
    /// No thread pool is used and no work overlaps. Retained only so existing
    /// callers keep compiling.
    pub fn verifyBatchParallel(self: BatchVerifier) !bool {
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

/// Quantum-safe blockchain signatures — NOT IMPLEMENTED here.
///
/// Every operation returns `BlockchainCryptoError.UnsupportedAlgorithm`. The
/// key and signature shapes are kept so existing callers still compile and get
/// an error instead of silently wrong results.
///
/// History: this type carried hash-based stand-ins whose sizes matched no ML-DSA
/// parameter set. `sign` copied the first 32 bytes of the private key straight
/// into the signature, so publishing a signature published half the signing key.
/// `verify` recomputed that same hash and additionally compared the public key
/// against `signature.data[64..96]`, bytes that `sign` filled with fresh random
/// data — so a signature this module produced never verified, and the whole
/// construction gave neither authenticity nor secrecy.
///
/// For real post-quantum signatures use the ML-DSA implementations behind
/// `-Dpost-quantum=true` (`post_quantum.ML_DSA_44/65/87`), which are backed by
/// the standard library rather than reimplemented here.
pub const PostQuantumSig = struct {
    pub const PrivateKey = struct {
        data: [64]u8,
    };

    pub const PublicKey = struct {
        data: [32]u8,
    };

    pub const Signature = struct {
        data: [128]u8,
    };

    /// Always fails: use `post_quantum.ML_DSA_65.generateKeypair`.
    pub fn generateKeyPair() BlockchainCryptoError!struct { private_key: PrivateKey, public_key: PublicKey } {
        return BlockchainCryptoError.UnsupportedAlgorithm;
    }

    /// Always fails: use `post_quantum.ML_DSA_65.sign`.
    pub fn sign(message: []const u8, private_key: PrivateKey) BlockchainCryptoError!Signature {
        _ = message;
        _ = private_key;
        return BlockchainCryptoError.UnsupportedAlgorithm;
    }

    /// Always fails: use `post_quantum.ML_DSA_65.verify`.
    ///
    /// Returns an error rather than `false` on purpose. A `false` would imply
    /// the signature was checked and rejected; nothing here checks anything.
    pub fn verify(message: []const u8, signature: Signature, public_key: PublicKey) BlockchainCryptoError!bool {
        _ = message;
        _ = signature;
        _ = public_key;
        return BlockchainCryptoError.UnsupportedAlgorithm;
    }
};

/// Zero-knowledge proofs — NOT IMPLEMENTED here.
///
/// Every operation returns `BlockchainCryptoError.UnsupportedAlgorithm`.
///
/// History: `verify` ignored both the statement and the verifying key and
/// returned `true` for any proof that was not entirely zero bytes. Since `prove`
/// filled 224 of the 256 proof bytes with random data, essentially every byte
/// string was accepted as a valid proof of every statement — the exact opposite
/// of soundness.
///
/// The `zkp` module behind `-Dzkp=true` is where proof systems would live; see
/// its documentation for the current state of each one.
pub const ZKProof = struct {
    pub const Proof = struct {
        data: [256]u8,
    };

    pub const VerifyingKey = struct {
        data: [128]u8,
    };

    pub const ProvingKey = struct {
        data: [256]u8,
    };

    /// Always fails: there is no proof system to set up.
    pub fn setup() BlockchainCryptoError!struct { proving_key: ProvingKey, verifying_key: VerifyingKey } {
        return BlockchainCryptoError.UnsupportedAlgorithm;
    }

    /// Always fails: there is no proof system.
    pub fn prove(statement: []const u8, witness: []const u8, proving_key: ProvingKey) BlockchainCryptoError!Proof {
        _ = statement;
        _ = witness;
        _ = proving_key;
        return BlockchainCryptoError.UnsupportedAlgorithm;
    }

    /// Always fails: there is no proof system.
    ///
    /// Returns an error rather than `false` on purpose. A `false` would imply
    /// the proof was checked and rejected; nothing here checks anything.
    pub fn verify(statement: []const u8, proof: Proof, verifying_key: VerifyingKey) BlockchainCryptoError!bool {
        _ = statement;
        _ = proof;
        _ = verifying_key;
        return BlockchainCryptoError.UnsupportedAlgorithm;
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

test "merkle proofs verify for every leaf at every tree size" {
    // Odd leaf counts exercise the duplicated final node. Before the sibling fix
    // the unpaired leaf's step was dropped and its proof never verified.
    inline for (.{ 1, 2, 3, 4, 5, 7, 8, 9 }) |leaf_count| {
        var tree = MerkleTree.init(testing.allocator);
        defer tree.deinit();

        var buf: [32]u8 = undefined;
        for (0..leaf_count) |i| {
            const label = try std.fmt.bufPrint(&buf, "tx-{d}-of-{d}", .{ i, leaf_count });
            try tree.addLeaf(label);
        }
        try tree.buildTree();
        const root = tree.getRoot().?;

        for (0..leaf_count) |i| {
            var proof = try tree.generateProof(i, testing.allocator);
            defer proof.deinit();
            try testing.expect(proof.verify(tree.leaves.items[i], root));
            // A proof only authenticates its own leaf.
            var wrong_leaf = tree.leaves.items[i];
            wrong_leaf[0] ^= 0x01;
            try testing.expect(!proof.verify(wrong_leaf, root));
            var wrong_root = root;
            wrong_root[31] ^= 0x80;
            try testing.expect(!proof.verify(tree.leaves.items[i], wrong_root));
        }
    }
}

test "merkle tree rejects proofs it cannot index" {
    var tree = MerkleTree.init(testing.allocator);
    defer tree.deinit();

    // No leaves, no tree: nothing to prove and no root to report.
    try testing.expect(tree.getRoot() == null);
    try testing.expectError(BlockchainCryptoError.InvalidMerkleProof, tree.generateProof(0, testing.allocator));

    try tree.addLeaf("a");
    try tree.addLeaf("b");
    try tree.addLeaf("c");

    // buildTree has not run, so the level offsets would read past `tree`.
    try testing.expect(tree.getRoot() == null);
    try testing.expectError(BlockchainCryptoError.InvalidMerkleProof, tree.generateProof(0, testing.allocator));

    try tree.buildTree();
    try testing.expect(tree.getRoot() != null);
    try testing.expectError(BlockchainCryptoError.InvalidMerkleProof, tree.generateProof(3, testing.allocator));

    // Appending after building leaves the two out of step again.
    try tree.addLeaf("d");
    try testing.expect(tree.getRoot() == null);
    try testing.expectError(BlockchainCryptoError.InvalidMerkleProof, tree.generateProof(0, testing.allocator));

    try tree.buildTree();
    try testing.expect(tree.getRoot() != null);
    var proof = try tree.generateProof(3, testing.allocator);
    defer proof.deinit();
    try testing.expect(proof.verify(tree.leaves.items[3], tree.getRoot().?));
}

test "merkle proofs do not transfer between trees" {
    var left = MerkleTree.init(testing.allocator);
    defer left.deinit();
    var right = MerkleTree.init(testing.allocator);
    defer right.deinit();

    for ([_][]const u8{ "a", "b", "c" }) |leaf| try left.addLeaf(leaf);
    for ([_][]const u8{ "a", "b", "z" }) |leaf| try right.addLeaf(leaf);
    try left.buildTree();
    try right.buildTree();

    try testing.expect(!std.mem.eql(u8, &left.getRoot().?, &right.getRoot().?));

    var proof = try left.generateProof(2, testing.allocator);
    defer proof.deinit();
    try testing.expect(proof.verify(left.leaves.items[2], left.getRoot().?));
    try testing.expect(!proof.verify(left.leaves.items[2], right.getRoot().?));
    try testing.expect(!proof.verify(right.leaves.items[2], left.getRoot().?));
}

test "batch verification accepts genuine Ed25519 signatures" {
    const seed: [32]u8 = @splat(0x42);
    const kp = try crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const message = "test transaction";
    const signature = try kp.sign(message, null);

    var verifier = BatchVerifier.init(testing.allocator);
    defer verifier.deinit();

    try verifier.addSignature(message, signature.toBytes(), kp.public_key.toBytes());
    try testing.expect(verifier.verifyBatch());
    try testing.expect(try verifier.verifyBatchParallel());
}

test "batch verification rejects tampered input" {
    // Each case below passed under the previous hash-comparison stand-in, which
    // ignored the signature entirely. They are the regression guard for it.
    const seed: [32]u8 = @splat(0x42);
    const kp = try crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const message = "test transaction";
    const signature = try kp.sign(message, null);
    const public_key = kp.public_key.toBytes();

    // Altered message.
    {
        var verifier = BatchVerifier.init(testing.allocator);
        defer verifier.deinit();
        try verifier.addSignature("test transactioX", signature.toBytes(), public_key);
        try testing.expect(!verifier.verifyBatch());
    }

    // Flipped signature bit.
    {
        var bad_sig = signature.toBytes();
        bad_sig[0] ^= 0x01;
        var verifier = BatchVerifier.init(testing.allocator);
        defer verifier.deinit();
        try verifier.addSignature(message, bad_sig, public_key);
        try testing.expect(!verifier.verifyBatch());
    }

    // Signature from a different key.
    {
        const other_seed: [32]u8 = @splat(0x43);
        const other = try crypto.sign.Ed25519.KeyPair.generateDeterministic(other_seed);
        var verifier = BatchVerifier.init(testing.allocator);
        defer verifier.deinit();
        try verifier.addSignature(message, signature.toBytes(), other.public_key.toBytes());
        try testing.expect(!verifier.verifyBatch());
    }

    // All-zero key and signature: not a well-formed Ed25519 encoding. The old
    // implementation compared SHA256(message) against the key bytes and never
    // looked at the signature at all.
    {
        var verifier = BatchVerifier.init(testing.allocator);
        defer verifier.deinit();
        try verifier.addSignature(message, std.mem.zeroes([64]u8), std.mem.zeroes([32]u8));
        try testing.expect(!verifier.verifyBatch());
    }

    // One bad entry poisons an otherwise valid batch.
    {
        var verifier = BatchVerifier.init(testing.allocator);
        defer verifier.deinit();
        try verifier.addSignature(message, signature.toBytes(), public_key);
        try verifier.addSignature("other transaction", signature.toBytes(), public_key);
        try testing.expect(!verifier.verifyBatch());
    }
}

test "empty batch verifies vacuously" {
    var verifier = BatchVerifier.init(testing.allocator);
    defer verifier.deinit();
    try testing.expect(verifier.verifyBatch());
}

test "PostQuantumSig and ZKProof report themselves unsupported" {
    // If real backends are ever added, these expectations must be replaced with
    // known-answer vectors, not deleted.
    const priv = PostQuantumSig.PrivateKey{ .data = @splat(0) };
    const pub_key = PostQuantumSig.PublicKey{ .data = @splat(0) };
    const sig = PostQuantumSig.Signature{ .data = @splat(0) };

    try testing.expectError(BlockchainCryptoError.UnsupportedAlgorithm, PostQuantumSig.generateKeyPair());
    try testing.expectError(BlockchainCryptoError.UnsupportedAlgorithm, PostQuantumSig.sign("m", priv));
    try testing.expectError(BlockchainCryptoError.UnsupportedAlgorithm, PostQuantumSig.verify("m", sig, pub_key));

    const proof = ZKProof.Proof{ .data = @splat(0xFF) };
    const vk = ZKProof.VerifyingKey{ .data = @splat(0) };
    const pk = ZKProof.ProvingKey{ .data = @splat(0) };

    try testing.expectError(BlockchainCryptoError.UnsupportedAlgorithm, ZKProof.setup());
    try testing.expectError(BlockchainCryptoError.UnsupportedAlgorithm, ZKProof.prove("statement", "witness", pk));
    // A non-zero proof was exactly what the old `verify` accepted for any
    // statement; it must now refuse instead of returning a verdict.
    try testing.expectError(BlockchainCryptoError.UnsupportedAlgorithm, ZKProof.verify("statement", proof, vk));
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
    const prev_hash = std.mem.zeroes([32]u8);
    const merkle_root = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0x01);
        break :blk bytes;
    };

    const block_hash = BlockHash.computeBlockHash(prev_hash, merkle_root, 1234567890, 0, 1000);

    try testing.expect(!std.mem.allEqual(u8, &block_hash, 0));
}
