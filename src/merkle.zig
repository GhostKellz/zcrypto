//! Merkle Tree Implementation for Blockchain
//!
//! Merkle trees allow efficient verification of data inclusion in a set.
//! Used in blockchains for:
//! - Transaction commitment in blocks
//! - Light client proofs
//! - State root calculations
//!
//! Features:
//! - Efficient construction from leaf hashes
//! - Proof generation and verification
//! - Support for empty trees and single leaves
//! - Blake3-based hashing for performance
//!
//! Security: Uses Blake3 for all hashing operations.
//! Implements proper domain separation between leaves and internal nodes.

const std = @import("std");
const blake3 = @import("blake3.zig");
const testing = std.testing;

/// Merkle tree node hash size (32 bytes)
pub const HASH_SIZE = 32;

/// Merkle tree node hash type
pub const Hash = [HASH_SIZE]u8;

/// Merkle tree errors
pub const MerkleError = error{
    EmptyLeaves,
    InvalidProof,
    InvalidLeafIndex,
    OutOfMemory,
};

/// Merkle tree structure
///
/// Stores the root hash and leaf data for proof generation.
pub const MerkleTree = struct {
    allocator: std.mem.Allocator,
    leaves: []Hash,
    root_hash: Hash,

    /// Build a Merkle tree from leaf hashes
    ///
    /// ## Parameters
    /// - `allocator`: Memory allocator
    /// - `leaves`: Array of leaf hashes (transaction hashes, etc.)
    ///
    /// ## Returns
    /// A complete Merkle tree with root computed
    ///
    /// ## Example
    /// ```zig
    /// const leaves = &[_]Hash{
    ///     blake3.blake3("tx1"),
    ///     blake3.blake3("tx2"),
    ///     blake3.blake3("tx3"),
    /// };
    /// const tree = try MerkleTree.build(allocator, leaves);
    /// defer tree.deinit();
    /// const root = tree.root();
    /// ```
    ///
    /// ## Performance
    /// - Time: O(n) where n is number of leaves
    /// - Space: O(n) for leaf storage
    pub fn build(allocator: std.mem.Allocator, leaves: []const Hash) !MerkleTree {
        if (leaves.len == 0) {
            return MerkleError.EmptyLeaves;
        }

        // Copy leaves
        const leaves_copy = try allocator.alloc(Hash, leaves.len);
        errdefer allocator.free(leaves_copy);
        @memcpy(leaves_copy, leaves);

        // Compute root
        const root_hash = try computeRoot(allocator, leaves);

        return MerkleTree{
            .allocator = allocator,
            .leaves = leaves_copy,
            .root_hash = root_hash,
        };
    }

    /// Free all memory used by the tree
    pub fn deinit(self: *MerkleTree) void {
        self.allocator.free(self.leaves);
    }

    /// Get the Merkle root hash
    ///
    /// ## Returns
    /// The root hash of the tree (top-level hash)
    ///
    /// ## Example
    /// ```zig
    /// const root = tree.root();
    /// ```
    pub fn root(self: *const MerkleTree) Hash {
        return self.root_hash;
    }

    /// Generate a Merkle proof for a specific leaf
    ///
    /// The proof contains sibling hashes needed to reconstruct
    /// the path from leaf to root.
    ///
    /// ## Parameters
    /// - `leaf_index`: Index of the leaf to prove (0-based)
    ///
    /// ## Returns
    /// Array of sibling hashes forming the proof path
    ///
    /// ## Example
    /// ```zig
    /// const proof = try tree.generateProof(2);  // Proof for 3rd transaction
    /// defer allocator.free(proof);
    /// ```
    pub fn generateProof(
        self: *const MerkleTree,
        leaf_index: usize,
    ) ![]Hash {
        if (leaf_index >= self.leaves.len) {
            return MerkleError.InvalidLeafIndex;
        }

        var proof: std.ArrayList(Hash) = .{};
        errdefer proof.deinit(self.allocator);

        // Build proof by walking up the tree
        var current_level = try self.allocator.alloc(Hash, self.leaves.len);
        defer self.allocator.free(current_level);
        @memcpy(current_level, self.leaves);

        var current_index = leaf_index;

        while (current_level.len > 1) {
            // Find sibling
            const sibling_index = if (current_index % 2 == 0)
                current_index + 1
            else
                current_index - 1;

            // Add sibling to proof if it exists
            if (sibling_index < current_level.len) {
                try proof.append(self.allocator, current_level[sibling_index]);
            } else {
                // Odd number of nodes, duplicate last node
                try proof.append(self.allocator, current_level[current_index]);
            }

            // Build next level
            const next_level_size = (current_level.len + 1) / 2;
            var next_level = try self.allocator.alloc(Hash, next_level_size);

            for (0..next_level_size) |i| {
                const left_idx = i * 2;
                const right_idx = left_idx + 1;

                const left = current_level[left_idx];
                const right = if (right_idx < current_level.len)
                    current_level[right_idx]
                else
                    current_level[left_idx]; // Duplicate if odd

                next_level[i] = hashPair(left, right);
            }

            self.allocator.free(current_level);
            current_level = next_level;
            current_index = current_index / 2;
        }

        return proof.toOwnedSlice(self.allocator);
    }

    /// Verify a Merkle proof
    ///
    /// Checks if a leaf with the given hash is part of the tree
    /// by reconstructing the path to the root.
    ///
    /// ## Parameters
    /// - `leaf_hash`: Hash of the leaf to verify
    /// - `leaf_index`: Position of the leaf in the tree
    /// - `proof`: Sibling hashes forming the proof path
    ///
    /// ## Returns
    /// `true` if the proof is valid, `false` otherwise
    ///
    /// ## Example
    /// ```zig
    /// const valid = tree.verifyProof(tx_hash, 2, proof);
    /// if (valid) {
    ///     // Transaction is in the block
    /// }
    /// ```
    pub fn verifyProof(
        self: *const MerkleTree,
        leaf_hash: Hash,
        leaf_index: usize,
        proof: []const Hash,
    ) bool {
        if (leaf_index >= self.leaves.len) {
            return false;
        }

        var computed_hash = leaf_hash;
        var current_index = leaf_index;

        // Reconstruct path to root
        for (proof) |sibling_hash| {
            computed_hash = if (current_index % 2 == 0)
                hashPair(computed_hash, sibling_hash)
            else
                hashPair(sibling_hash, computed_hash);

            current_index = current_index / 2;
        }

        // Check if computed root matches actual root
        return std.mem.eql(u8, &computed_hash, &self.root_hash);
    }
};

/// Compute Merkle root from leaves
fn computeRoot(allocator: std.mem.Allocator, leaves: []const Hash) !Hash {
    if (leaves.len == 0) {
        return error.EmptyLeaves;
    }

    if (leaves.len == 1) {
        return leaves[0];
    }

    var current_level = try allocator.alloc(Hash, leaves.len);
    defer allocator.free(current_level);
    @memcpy(current_level, leaves);

    while (current_level.len > 1) {
        const next_level_size = (current_level.len + 1) / 2;
        var next_level = try allocator.alloc(Hash, next_level_size);

        for (0..next_level_size) |i| {
            const left_idx = i * 2;
            const right_idx = left_idx + 1;

            const left = current_level[left_idx];
            const right = if (right_idx < current_level.len)
                current_level[right_idx]
            else
                current_level[left_idx]; // Duplicate if odd

            next_level[i] = hashPair(left, right);
        }

        allocator.free(current_level);
        current_level = next_level;
    }

    const root = current_level[0];
    return root;
}

/// Hash a pair of nodes to create parent node
///
/// Uses domain separation to prevent second-preimage attacks.
/// Internal nodes are hashed differently from leaves.
///
/// ## Parameters
/// - `left`: Left child hash
/// - `right`: Right child hash
///
/// ## Returns
/// Parent node hash
fn hashPair(left: Hash, right: Hash) Hash {
    var hasher = blake3.Blake3.init();

    // Domain separation: prefix with marker for internal nodes
    hasher.update(&[_]u8{0x01}); // 0x01 = internal node marker
    hasher.update(&left);
    hasher.update(&right);

    return hasher.final();
}

/// Create leaf hash with domain separation
///
/// Hashes data with a domain separator to prevent confusion
/// between leaf data and internal node hashes.
///
/// ## Parameters
/// - `data`: Leaf data (transaction, account state, etc.)
///
/// ## Returns
/// Leaf hash suitable for Merkle tree
///
/// ## Example
/// ```zig
/// const tx_hash = hashLeaf(transaction_bytes);
/// ```
pub fn hashLeaf(data: []const u8) Hash {
    var hasher = blake3.Blake3.init();

    // Domain separation: prefix with marker for leaf nodes
    hasher.update(&[_]u8{0x00}); // 0x00 = leaf node marker
    hasher.update(data);

    return hasher.final();
}

//
// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================
//

/// Build Merkle tree from raw data (not pre-hashed)
///
/// Automatically hashes the leaves before building the tree.
///
/// ## Parameters
/// - `allocator`: Memory allocator
/// - `data_items`: Array of data items to hash
///
/// ## Returns
/// Complete Merkle tree
///
/// ## Example
/// ```zig
/// const transactions = &[_][]const u8{ tx1_bytes, tx2_bytes, tx3_bytes };
/// const tree = try buildFromData(allocator, transactions);
/// ```
pub fn buildFromData(
    allocator: std.mem.Allocator,
    data_items: []const []const u8,
) !MerkleTree {
    var leaves = try allocator.alloc(Hash, data_items.len);
    defer allocator.free(leaves);

    for (data_items, 0..) |data, i| {
        leaves[i] = hashLeaf(data);
    }

    return MerkleTree.build(allocator, leaves);
}

//
// ============================================================================
// TESTS
// ============================================================================
//

test "merkle tree basic" {
    const allocator = testing.allocator;

    const leaves = &[_]Hash{
        blake3.blake3("tx1"),
        blake3.blake3("tx2"),
        blake3.blake3("tx3"),
        blake3.blake3("tx4"),
    };

    var tree = try MerkleTree.build(allocator, leaves);
    defer tree.deinit();

    const root_val = tree.root();
    try testing.expectEqual(@as(usize, 32), root_val.len);
}

test "merkle tree single leaf" {
    const allocator = testing.allocator;

    const leaves = &[_]Hash{blake3.blake3("single transaction")};

    var tree = try MerkleTree.build(allocator, leaves);
    defer tree.deinit();

    const root_val = tree.root();
    try testing.expectEqual(@as(usize, 32), root_val.len);
}

test "merkle tree empty fails" {
    const allocator = testing.allocator;
    const leaves = &[_]Hash{};

    const result = MerkleTree.build(allocator, leaves);
    try testing.expectError(MerkleError.EmptyLeaves, result);
}

test "merkle proof generation and verification" {
    const allocator = testing.allocator;

    const leaves = &[_]Hash{
        blake3.blake3("tx1"),
        blake3.blake3("tx2"),
        blake3.blake3("tx3"),
        blake3.blake3("tx4"),
    };

    var tree = try MerkleTree.build(allocator, leaves);
    defer tree.deinit();

    // Generate proof for second transaction
    const proof = try tree.generateProof(1);
    defer allocator.free(proof);

    // Verify the proof
    const valid = tree.verifyProof(leaves[1], 1, proof);
    try testing.expect(valid);

    // Invalid proof should fail
    const invalid = tree.verifyProof(leaves[0], 1, proof);
    try testing.expect(!invalid);
}

test "merkle proof all leaves" {
    const allocator = testing.allocator;

    const leaves = &[_]Hash{
        blake3.blake3("tx1"),
        blake3.blake3("tx2"),
        blake3.blake3("tx3"),
    };

    var tree = try MerkleTree.build(allocator, leaves);
    defer tree.deinit();

    // Verify all leaves have valid proofs
    for (leaves, 0..) |leaf, i| {
        const proof = try tree.generateProof(i);
        defer allocator.free(proof);

        const valid = tree.verifyProof(leaf, i, proof);
        try testing.expect(valid);
    }
}

test "merkle build from data" {
    const allocator = testing.allocator;

    const transactions = &[_][]const u8{
        "transaction 1 data",
        "transaction 2 data",
        "transaction 3 data",
    };

    var tree = try buildFromData(allocator, transactions);
    defer tree.deinit();

    const root_val = tree.root();
    try testing.expectEqual(@as(usize, 32), root_val.len);
}

test "merkle hash leaf domain separation" {
    const data = "test data";

    const leaf_hash = hashLeaf(data);
    const direct_hash = blake3.blake3(data);

    // Leaf hash should be different from direct hash (due to domain separator)
    var different = false;
    for (leaf_hash, direct_hash) |a, b| {
        if (a != b) {
            different = true;
            break;
        }
    }
    try testing.expect(different);
}

test "merkle deterministic" {
    const allocator = testing.allocator;

    const leaves = &[_]Hash{
        blake3.blake3("tx1"),
        blake3.blake3("tx2"),
    };

    var tree1 = try MerkleTree.build(allocator, leaves);
    defer tree1.deinit();

    var tree2 = try MerkleTree.build(allocator, leaves);
    defer tree2.deinit();

    // Same inputs should produce same root
    const root1 = tree1.root();
    const root2 = tree2.root();
    try testing.expectEqualSlices(u8, &root1, &root2);
}

test "merkle large tree" {
    const allocator = testing.allocator;

    // Build tree with 100 leaves
    var leaves = try allocator.alloc(Hash, 100);
    defer allocator.free(leaves);

    for (leaves, 0..) |*leaf, i| {
        var buf: [20]u8 = undefined;
        const str = try std.fmt.bufPrint(&buf, "tx{d}", .{i});
        leaf.* = blake3.blake3(str);
    }

    var tree = try MerkleTree.build(allocator, leaves);
    defer tree.deinit();

    // Verify proofs for random leaves
    const test_indices = [_]usize{ 0, 50, 99 };
    for (test_indices) |idx| {
        const proof = try tree.generateProof(idx);
        defer allocator.free(proof);

        const valid = tree.verifyProof(leaves[idx], idx, proof);
        try testing.expect(valid);
    }
}
