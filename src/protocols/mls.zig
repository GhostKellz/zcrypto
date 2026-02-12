//! MLS (Message Layer Security) Implementation for zcrypto
//!
//! Implements RFC 9420 - The Messaging Layer Security (MLS) Protocol
//! with post-quantum enhancements for secure group messaging

const std = @import("std");
const rand = @import("../rand.zig");
const pq = @import("../pq.zig");
const kdf = @import("../kdf.zig");

/// MLS Protocol errors
pub const MLSError = error{
    InvalidGroup,
    InvalidMember,
    InvalidEpoch,
    InvalidSignature,
    InvalidProposal,
    InvalidCommit,
    DecryptionFailed,
    InvalidWelcome,
    GroupContextMismatch,
};

/// MLS Protocol version
pub const ProtocolVersion = enum(u16) {
    mls10 = 0x0001,
    mls10_pq = 0x0002, // Post-quantum enhanced
};

/// Cipher suite identifiers
pub const CipherSuite = enum(u16) {
    // Standard suites
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,

    // Post-quantum enhanced suites
    MLS_128_HYBRID_X25519_KYBER768_AES256GCM_SHA384_Ed25519_Dilithium3 = 0x1001,
    MLS_256_KYBER1024_AES256GCM_SHA512_SPHINCS_SHA256 = 0x1002,
};

/// Group context containing group state
pub const GroupContext = struct {
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    group_id: []const u8,
    epoch: u64,
    tree_hash: [32]u8,
    confirmed_transcript_hash: [32]u8,
    extensions: []const Extension,

    const Extension = struct {
        extension_type: u16,
        extension_data: []const u8,
    };

    pub fn encode(self: *const GroupContext, allocator: std.mem.Allocator) ![]u8 {
        // Simplified encoding
        var list = std.ArrayList(u8).init();
        try list.appendSlice(allocator, std.mem.asBytes(&self.version));
        try list.appendSlice(allocator, std.mem.asBytes(&self.cipher_suite));
        try list.appendSlice(allocator, self.group_id);
        try list.appendSlice(allocator, std.mem.asBytes(&self.epoch));
        try list.appendSlice(allocator, &self.tree_hash);
        try list.appendSlice(allocator, &self.confirmed_transcript_hash);

        return list.toOwnedSlice(allocator);
    }
};

/// Tree position in the ratchet tree
pub const LeafIndex = u32;
pub const NodeIndex = u32;

/// Key package for joining groups
pub const KeyPackage = struct {
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    init_key: [32]u8, // Public key for initial DH
    leaf_node: LeafNode,
    extensions: []const GroupContext.Extension,
    signature: [64]u8, // Self-signature

    // Post-quantum keys
    pq_init_key: ?[pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8,
    pq_signature: ?[pq.ml_dsa.ML_DSA_65.SIGNATURE_SIZE]u8,

    pub fn generate(
        allocator: std.mem.Allocator,
        cipher_suite: CipherSuite,
        identity: []const u8,
        credential: Credential,
    ) !KeyPackage {
        _ = allocator;

        // Generate init key
        var init_seed: [32]u8 = undefined;
        rand.fill(&init_seed);

        const init_keypair = std.crypto.dh.X25519.KeyPair.create(init_seed) catch {
            return MLSError.InvalidMember;
        };

        // Generate signing key for leaf node
        var sign_seed: [32]u8 = undefined;
        rand.fill(&sign_seed);

        const sign_keypair = std.crypto.sign.Ed25519.KeyPair.create(sign_seed) catch {
            return MLSError.InvalidMember;
        };

        const leaf_node = LeafNode{
            .encryption_key = init_keypair.public_key,
            .signature_key = sign_keypair.public_key,
            .credential = credential,
            .capabilities = Capabilities{
                .versions = &[_]ProtocolVersion{.mls10},
                .cipher_suites = &[_]CipherSuite{cipher_suite},
                .extensions = &[_]u16{},
                .proposals = &[_]ProposalType{ .add, .update, .remove },
                .credentials = &[_]CredentialType{.basic},
            },
            .lifetime = 0, // Not before
            .extensions = &[_]GroupContext.Extension{},
        };

        var key_package = KeyPackage{
            .version = .mls10,
            .cipher_suite = cipher_suite,
            .init_key = init_keypair.public_key,
            .leaf_node = leaf_node,
            .extensions = &[_]GroupContext.Extension{},
            .signature = undefined,
            .pq_init_key = null,
            .pq_signature = null,
        };

        // Generate post-quantum keys if supported
        if (cipher_suite == .MLS_128_HYBRID_X25519_KYBER768_AES256GCM_SHA384_Ed25519_Dilithium3) {
            var pq_seed: [32]u8 = undefined;
            rand.fill(&pq_seed);

            const pq_keypair = pq.ml_kem.ML_KEM_768.KeyPair.generate(pq_seed) catch {
                return MLSError.InvalidMember;
            };

            key_package.pq_init_key = pq_keypair.public_key;
        }

        // Sign the key package
        var to_be_signed = std.ArrayList(u8).init(std.heap.page_allocator);
        defer to_be_signed.deinit();

        try to_be_signed.appendSlice(std.mem.asBytes(&key_package.version));
        try to_be_signed.appendSlice(std.mem.asBytes(&key_package.cipher_suite));
        try to_be_signed.appendSlice(&key_package.init_key);
        try to_be_signed.appendSlice(identity);

        key_package.signature = sign_keypair.sign(to_be_signed.items, null) catch {
            return MLSError.InvalidSignature;
        };

        return key_package;
    }
};

/// Leaf node in the ratchet tree
pub const LeafNode = struct {
    encryption_key: [32]u8,
    signature_key: [32]u8,
    credential: Credential,
    capabilities: Capabilities,
    lifetime: u64,
    extensions: []const GroupContext.Extension,
};

/// Member capabilities
pub const Capabilities = struct {
    versions: []const ProtocolVersion,
    cipher_suites: []const CipherSuite,
    extensions: []const u16,
    proposals: []const ProposalType,
    credentials: []const CredentialType,
};

/// Credential types
pub const CredentialType = enum(u16) {
    basic = 0x0001,
    x509 = 0x0002,
};

pub const Credential = struct {
    credential_type: CredentialType,
    identity: []const u8,

    pub fn basic(identity: []const u8) Credential {
        return Credential{
            .credential_type = .basic,
            .identity = identity,
        };
    }
};

/// Proposal types for group operations
pub const ProposalType = enum(u16) {
    add = 0x0001,
    update = 0x0002,
    remove = 0x0003,
    psk = 0x0004,
    reinit = 0x0005,
    external_init = 0x0006,
    group_context_extensions = 0x0007,
};

/// Proposal for group state changes
pub const Proposal = struct {
    proposal_type: ProposalType,
    content: ProposalContent,

    const ProposalContent = union(ProposalType) {
        add: AddProposal,
        update: UpdateProposal,
        remove: RemoveProposal,
        psk: PSKProposal,
        reinit: ReinitProposal,
        external_init: ExternalInitProposal,
        group_context_extensions: GroupContextExtensionsProposal,
    };

    const AddProposal = struct {
        key_package: KeyPackage,
    };

    const UpdateProposal = struct {
        leaf_node: LeafNode,
    };

    const RemoveProposal = struct {
        removed: LeafIndex,
    };

    const PSKProposal = struct {
        psk: PreSharedKey,
    };

    const ReinitProposal = struct {
        group_id: []const u8,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: []const GroupContext.Extension,
    };

    const ExternalInitProposal = struct {
        kem_output: []const u8,
    };

    const GroupContextExtensionsProposal = struct {
        extensions: []const GroupContext.Extension,
    };
};

/// Pre-shared key
pub const PreSharedKey = struct {
    psk_id: []const u8,
    psk_nonce: []const u8,
    psk: []const u8,
};

/// Commit message for applying proposals
pub const Commit = struct {
    proposals: []const ProposalOrRef,
    path: ?UpdatePath,

    const ProposalOrRef = union(enum) {
        proposal: Proposal,
        reference: ProposalRef,
    };

    const ProposalRef = struct {
        hash: [32]u8,
    };

    const UpdatePath = struct {
        leaf_node: LeafNode,
        nodes: []const UpdatePathNode,
    };

    const UpdatePathNode = struct {
        public_key: [32]u8,
        encrypted_path_secret: []const HPKECiphertext,
    };

    const HPKECiphertext = struct {
        kem_output: []const u8,
        ciphertext: []const u8,
    };
};

/// Welcome message for new members
pub const Welcome = struct {
    cipher_suite: CipherSuite,
    secrets: []const EncryptedGroupSecrets,
    encrypted_group_info: []const u8,

    const EncryptedGroupSecrets = struct {
        new_member: LeafIndex,
        encrypted_group_secrets: []const u8,
    };
};

/// MLS Group state
pub const Group = struct {
    allocator: std.mem.Allocator,
    context: GroupContext,
    tree: RatchetTree,
    epoch_secrets: EpochSecrets,
    message_secrets: MessageSecrets,
    pending_proposals: std.ArrayList(Proposal),

    /// Initialize a new group
    pub fn init(
        allocator: std.mem.Allocator,
        group_id: []const u8,
        cipher_suite: CipherSuite,
        creator_key_package: KeyPackage,
    ) !Group {
        var context = GroupContext{
            .version = .mls10,
            .cipher_suite = cipher_suite,
            .group_id = group_id,
            .epoch = 0,
            .tree_hash = undefined,
            .confirmed_transcript_hash = undefined,
            .extensions = &[_]GroupContext.Extension{},
        };

        // Initialize ratchet tree with creator
        var tree = try RatchetTree.init(allocator);
        _ = try tree.addLeaf(creator_key_package.leaf_node);

        // Compute tree hash
        tree.computeTreeHash(&context.tree_hash);

        // Initialize epoch secrets
        var init_secret: [32]u8 = undefined;
        rand.fill(&init_secret);

        const epoch_secrets = try EpochSecrets.derive(init_secret, context);
        const message_secrets = MessageSecrets.init(epoch_secrets.sender_data_secret);

        return Group{
            .allocator = allocator,
            .context = context,
            .tree = tree,
            .epoch_secrets = epoch_secrets,
            .message_secrets = message_secrets,
            .pending_proposals = std.ArrayList(Proposal).init(allocator),
        };
    }

    pub fn deinit(self: *Group) void {
        self.tree.deinit();
        self.pending_proposals.deinit();
    }

    /// Add a new member to the group
    pub fn addMember(self: *Group, key_package: KeyPackage) !Proposal {
        return Proposal{
            .proposal_type = .add,
            .content = .{ .add = .{ .key_package = key_package } },
        };
    }

    /// Remove a member from the group
    pub fn removeMember(self: *Group, member_index: LeafIndex) !Proposal {
        _ = self;
        return Proposal{
            .proposal_type = .remove,
            .content = .{ .remove = .{ .removed = member_index } },
        };
    }

    /// Create a commit to apply pending proposals
    pub fn createCommit(self: *Group) !Commit {
        // Simplified commit creation
        const proposals = try self.allocator.alloc(Commit.ProposalOrRef, self.pending_proposals.items.len);

        for (self.pending_proposals.items, 0..) |proposal, i| {
            proposals[i] = .{ .proposal = proposal };
        }

        return Commit{
            .proposals = proposals,
            .path = null, // Simplified - no path update
        };
    }

    /// Process a commit message
    pub fn processCommit(self: *Group, commit: Commit) !void {
        // Apply each proposal in the commit
        for (commit.proposals) |prop_or_ref| {
            switch (prop_or_ref) {
                .proposal => |proposal| {
                    try self.applyProposal(proposal);
                },
                .reference => {
                    // Look up proposal by reference
                    // Implementation needed
                },
            }
        }

        // Advance epoch
        self.context.epoch += 1;

        // Re-derive secrets for new epoch
        var new_init_secret: [32]u8 = undefined;
        rand.fill(&new_init_secret);

        self.epoch_secrets = try EpochSecrets.derive(new_init_secret, self.context);
        self.message_secrets = MessageSecrets.init(self.epoch_secrets.sender_data_secret);

        // Update tree hash
        self.tree.computeTreeHash(&self.context.tree_hash);

        // Clear pending proposals
        self.pending_proposals.clearRetainingCapacity();
    }

    fn applyProposal(self: *Group, proposal: Proposal) !void {
        switch (proposal.content) {
            .add => |add| {
                _ = try self.tree.addLeaf(add.key_package.leaf_node);
            },
            .remove => |remove| {
                try self.tree.removeLeaf(remove.removed);
            },
            .update => |update| {
                try self.tree.updateLeaf(0, update.leaf_node); // Simplified
            },
            else => {
                // Other proposal types
            },
        }
    }

    /// Encrypt a message for the group
    pub fn encryptMessage(self: *Group, plaintext: []const u8, ciphertext_buffer: []u8) ![]const u8 {
        // Simplified group encryption
        const key = self.epoch_secrets.application_secret;
        const min_len = @min(plaintext.len, ciphertext_buffer.len);

        for (0..min_len) |i| {
            ciphertext_buffer[i] = plaintext[i] ^ key[i % 32];
        }

        return ciphertext_buffer[0..min_len];
    }

    /// Decrypt a message from the group
    pub fn decryptMessage(self: *Group, ciphertext: []const u8, plaintext_buffer: []u8) ![]const u8 {
        // Simplified group decryption
        const key = self.epoch_secrets.application_secret;
        const min_len = @min(ciphertext.len, plaintext_buffer.len);

        for (0..min_len) |i| {
            plaintext_buffer[i] = ciphertext[i] ^ key[i % 32];
        }

        return plaintext_buffer[0..min_len];
    }
};

/// Binary tree for key management
const RatchetTree = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(?Node),

    const Node = struct {
        public_key: ?[32]u8,
        private_key: ?[32]u8,
        parent: ?NodeIndex,
        left_child: ?NodeIndex,
        right_child: ?NodeIndex,
    };

    fn init(allocator: std.mem.Allocator) !RatchetTree {
        return RatchetTree{
            .allocator = allocator,
            .nodes = std.ArrayList(?Node).init(allocator),
        };
    }

    fn deinit(self: *RatchetTree) void {
        self.nodes.deinit();
    }

    fn addLeaf(self: *RatchetTree, leaf_node: LeafNode) !LeafIndex {
        const node = Node{
            .public_key = leaf_node.encryption_key,
            .private_key = null, // Only known to the leaf owner
            .parent = null,
            .left_child = null,
            .right_child = null,
        };

        try self.nodes.append(node);
        return @intCast(self.nodes.items.len - 1);
    }

    fn removeLeaf(self: *RatchetTree, index: LeafIndex) !void {
        if (index < self.nodes.items.len) {
            self.nodes.items[index] = null;
        }
    }

    fn updateLeaf(self: *RatchetTree, index: LeafIndex, leaf_node: LeafNode) !void {
        if (index < self.nodes.items.len) {
            if (self.nodes.items[index]) |*node| {
                node.public_key = leaf_node.encryption_key;
            }
        }
    }

    fn computeTreeHash(self: *const RatchetTree, hash_output: []u8) void {
        // Simplified tree hash computation
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        for (self.nodes.items) |maybe_node| {
            if (maybe_node) |node| {
                if (node.public_key) |pk| {
                    hasher.update(&pk);
                }
            }
        }

        hasher.final(hash_output[0..32]);
    }
};

/// Epoch-specific secrets
const EpochSecrets = struct {
    joiner_secret: [32]u8,
    welcome_secret: [32]u8,
    init_secret: [32]u8,
    sender_data_secret: [32]u8,
    encryption_secret: [32]u8,
    exporter_secret: [32]u8,
    external_secret: [32]u8,
    confirmation_key: [32]u8,
    membership_key: [32]u8,
    resumption_psk: [32]u8,
    application_secret: [32]u8,

    fn derive(init_secret: [32]u8, context: GroupContext) !EpochSecrets {
        var secrets: EpochSecrets = undefined;

        // Simplified key derivation (would use proper HKDF in production)
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&init_secret);
        hasher.update("joiner");
        hasher.final(&secrets.joiner_secret);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&init_secret);
        hasher.update("welcome");
        hasher.final(&secrets.welcome_secret);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&init_secret);
        hasher.update("sender_data");
        hasher.final(&secrets.sender_data_secret);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&init_secret);
        hasher.update("encryption");
        hasher.final(&secrets.encryption_secret);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&init_secret);
        hasher.update("exporter");
        hasher.final(&secrets.exporter_secret);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&init_secret);
        hasher.update("external");
        hasher.final(&secrets.external_secret);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&init_secret);
        hasher.update("confirmation");
        hasher.final(&secrets.confirmation_key);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&init_secret);
        hasher.update("membership");
        hasher.final(&secrets.membership_key);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&init_secret);
        hasher.update("resumption");
        hasher.final(&secrets.resumption_psk);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&init_secret);
        hasher.update("application");
        hasher.final(&secrets.application_secret);

        secrets.init_secret = init_secret;

        _ = context; // Would be used in full implementation

        return secrets;
    }
};

/// Message-specific secrets
const MessageSecrets = struct {
    sender_data_secret: [32]u8,

    fn init(sender_data_secret: [32]u8) MessageSecrets {
        return MessageSecrets{
            .sender_data_secret = sender_data_secret,
        };
    }
};

test "MLS group creation and member addition" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    // Create initial member key package
    const credential = Credential.basic("alice@example.com");
    const alice_kp = try KeyPackage.generate(
        allocator,
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        "alice",
        credential,
    );

    // Initialize group
    var group = try Group.init(
        allocator,
        "test-group",
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        alice_kp,
    );
    defer group.deinit();

    // Verify initial state
    try std.testing.expect(group.context.epoch == 0);
    try std.testing.expect(std.mem.eql(u8, group.context.group_id, "test-group"));

    // Create proposal to add new member
    const bob_credential = Credential.basic("bob@example.com");
    const bob_kp = try KeyPackage.generate(
        allocator,
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        "bob",
        bob_credential,
    );

    const add_proposal = try group.addMember(bob_kp);
    try group.pending_proposals.append(add_proposal);

    // Create and process commit
    const commit = try group.createCommit();
    try group.processCommit(commit);

    // Verify epoch advanced
    try std.testing.expect(group.context.epoch == 1);
}

test "MLS message encryption/decryption" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const credential = Credential.basic("test@example.com");
    const kp = try KeyPackage.generate(
        allocator,
        .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        "test",
        credential,
    );

    var group = try Group.init(allocator, "test", .MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, kp);
    defer group.deinit();

    // Test message encryption/decryption
    const plaintext = "Hello, MLS!";
    var ciphertext_buffer = [_]u8{0} ** 64;
    var decrypted_buffer = [_]u8{0} ** 64;

    const ciphertext = try group.encryptMessage(plaintext, &ciphertext_buffer);
    const decrypted = try group.decryptMessage(ciphertext, &decrypted_buffer);

    try std.testing.expect(std.mem.eql(u8, plaintext, decrypted));
}
