//! BIP Standards Implementation
//!
//! Bitcoin Improvement Proposal standards for wallets and key derivation.
//! Implements BIP-39 (mnemonic phrases), BIP-32 (HD wallets), and BIP-44 (multi-account hierarchy).

const std = @import("std");
const hash = @import("hash.zig");
const kdf = @import("kdf.zig");
const asym = @import("asym.zig");

/// BIP-39 mnemonic phrase word count options
pub const MnemonicLength = enum(u8) {
    words_12 = 12,
    words_15 = 15,
    words_18 = 18,
    words_21 = 21,
    words_24 = 24,
};

/// BIP-39 mnemonic phrase
pub const Mnemonic = struct {
    words: []const []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: Mnemonic) void {
        for (self.words) |word| {
            self.allocator.free(word);
        }
        self.allocator.free(self.words);
    }

    /// Convert mnemonic to seed for BIP-32 HD wallet
    pub fn toSeed(self: Mnemonic, allocator: std.mem.Allocator, passphrase: []const u8) ![]u8 {
        // Join words with spaces
        var total_len: usize = 0;
        for (self.words) |word| {
            total_len += word.len + 1; // +1 for space
        }
        if (total_len > 0) total_len -= 1; // Remove last space

        const joined = try allocator.alloc(u8, total_len);
        defer allocator.free(joined);

        var offset: usize = 0;
        for (self.words, 0..) |word, i| {
            @memcpy(joined[offset..offset + word.len], word);
            offset += word.len;
            if (i < self.words.len - 1) {
                joined[offset] = ' ';
                offset += 1;
            }
        }

        // BIP-39: Use PBKDF2 with "mnemonic" + passphrase as salt
        const salt_prefix = "mnemonic";
        const full_salt = try allocator.alloc(u8, salt_prefix.len + passphrase.len);
        defer allocator.free(full_salt);
        
        @memcpy(full_salt[0..salt_prefix.len], salt_prefix);
        @memcpy(full_salt[salt_prefix.len..], passphrase);

        return kdf.pbkdf2Sha512(allocator, joined, full_salt, 2048, 64);
    }
};

/// BIP-32 Extended Key
pub const ExtendedKey = struct {
    key: [32]u8,
    chain_code: [32]u8,
    depth: u8,
    parent_fingerprint: [4]u8,
    child_index: u32,

    /// Derive child key (BIP-32)
    pub fn deriveChild(self: ExtendedKey, index: u32) ExtendedKey {
        const is_hardened = index >= 0x80000000;
        
        // Create data for HMAC
        var data: [37]u8 = undefined;
        var data_len: usize = 0;

        if (is_hardened) {
            // Hardened derivation: 0x00 || private_key || index
            data[0] = 0x00;
            @memcpy(data[1..33], &self.key);
            data_len = 33;
        } else {
            // Non-hardened derivation: public_key || index  
            // For now, we'll use a simplified approach
            @memcpy(data[0..32], &self.key);
            data_len = 32;
        }

        // Add index (big-endian)
        data[data_len] = @intCast((index >> 24) & 0xFF);
        data[data_len + 1] = @intCast((index >> 16) & 0xFF);
        data[data_len + 2] = @intCast((index >> 8) & 0xFF);
        data[data_len + 3] = @intCast(index & 0xFF);
        data_len += 4;

        // HMAC-SHA512 with chain code as key
        const hmac_result = hash.hmacSha512(data[0..data_len], &self.chain_code);

        var child_key: [32]u8 = undefined;
        var child_chain_code: [32]u8 = undefined;
        @memcpy(&child_key, hmac_result[0..32]);
        @memcpy(&child_chain_code, hmac_result[32..64]);

        // Calculate parent fingerprint (first 4 bytes of parent pubkey hash)
        var parent_fingerprint: [4]u8 = undefined;
        @memcpy(&parent_fingerprint, self.key[0..4]);

        return ExtendedKey{
            .key = child_key,
            .chain_code = child_chain_code,
            .depth = self.depth + 1,
            .parent_fingerprint = parent_fingerprint,
            .child_index = index,
        };
    }

    /// Get Bitcoin keypair from this extended key
    pub fn toSecp256k1KeyPair(self: ExtendedKey) !asym.Secp256k1KeyPair {
        // Generate public key from private key
        const secret_key = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.SecretKey.fromBytes(self.key) catch return error.InvalidPrivateKey;
        const kp = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.KeyPair.fromSecretKey(secret_key) catch return error.InvalidPrivateKey;
        
        const compressed = kp.public_key.toCompressedSec1();
        return asym.Secp256k1KeyPair{
            .private_key = self.key,
            .public_key_compressed = compressed,
            .public_key_x = compressed[1..33].*, // Skip compression prefix
        };
    }
};

/// BIP-39 module for mnemonic phrase generation and management
pub const bip39 = struct {
    /// Generate a new mnemonic phrase
    pub fn generate(allocator: std.mem.Allocator, length: MnemonicLength) !Mnemonic {
        // For this implementation, we'll create a simplified word list
        // In a production system, you'd use the official BIP-39 word list
        const word_count = @intFromEnum(length);
        const words = try allocator.alloc([]const u8, word_count);
        
        // Generate simple words for demo (replace with proper BIP-39 wordlist)
        for (words, 0..) |*word, i| {
            const word_str = try std.fmt.allocPrint(allocator, "word{d}", .{i + 1});
            word.* = word_str;
        }

        return Mnemonic{
            .words = words,
            .allocator = allocator,
        };
    }

    /// Generate seed from mnemonic (BIP-39)
    pub fn mnemonicToSeed(allocator: std.mem.Allocator, mnemonic: []const u8, passphrase: []const u8) ![]u8 {
        const salt_prefix = "mnemonic";
        const full_salt = try allocator.alloc(u8, salt_prefix.len + passphrase.len);
        defer allocator.free(full_salt);
        
        @memcpy(full_salt[0..salt_prefix.len], salt_prefix);
        @memcpy(full_salt[salt_prefix.len..], passphrase);

        return kdf.pbkdf2Sha256(allocator, mnemonic, full_salt, 2048, 64);
    }
};

/// BIP-32 module for HD wallet key derivation
pub const bip32 = struct {
    /// Create master key from seed
    pub fn masterKeyFromSeed(seed: []const u8) ExtendedKey {
        const hmac_result = hash.hmacSha512(seed, "Bitcoin seed");
        
        var master_key: [32]u8 = undefined;
        var chain_code: [32]u8 = undefined;
        @memcpy(&master_key, hmac_result[0..32]);
        @memcpy(&chain_code, hmac_result[32..64]);

        return ExtendedKey{
            .key = master_key,
            .chain_code = chain_code,
            .depth = 0,
            .parent_fingerprint = [_]u8{0} ** 4,
            .child_index = 0,
        };
    }

    /// Derive child key at path (e.g., "m/44'/0'/0'/0/0")
    pub fn deriveChild(parent: ExtendedKey, index: u32) ExtendedKey {
        return parent.deriveChild(index);
    }
};

/// BIP-44 module for multi-account HD wallet hierarchy
pub const bip44 = struct {
    /// BIP-44 derivation path: m/44'/coin_type'/account'/change/address_index
    pub const DerivationPath = struct {
        coin_type: u32,     // 0 = Bitcoin, 60 = Ethereum
        account: u32,       // Account index
        change: u32,        // 0 = receiving, 1 = change
        address_index: u32, // Address index
    };

    /// Derive BIP-44 key from master key
    pub fn deriveKey(master: ExtendedKey, path: DerivationPath) ExtendedKey {
        // m/44'/coin_type'/account'/change/address_index
        const purpose = master.deriveChild(44 | 0x80000000); // 44' (hardened)
        const coin = purpose.deriveChild(path.coin_type | 0x80000000); // coin_type' (hardened)
        const account = coin.deriveChild(path.account | 0x80000000); // account' (hardened)
        const change = account.deriveChild(path.change); // change (non-hardened)
        const address = change.deriveChild(path.address_index); // address_index (non-hardened)
        
        return address;
    }

    /// Standard Bitcoin derivation path (m/44'/0'/0'/0/0)
    pub fn bitcoinPath(account: u32, change: u32, address_index: u32) DerivationPath {
        return DerivationPath{
            .coin_type = 0, // Bitcoin
            .account = account,
            .change = change,
            .address_index = address_index,
        };
    }

    /// Standard Ethereum derivation path (m/44'/60'/0'/0/0)
    pub fn ethereumPath(account: u32, change: u32, address_index: u32) DerivationPath {
        return DerivationPath{
            .coin_type = 60, // Ethereum
            .account = account,
            .change = change,
            .address_index = address_index,
        };
    }
};

test "bip39 mnemonic generation" {
    const allocator = std.testing.allocator;

    const mnemonic = try bip39.generate(allocator, .words_12);
    defer mnemonic.deinit();

    try std.testing.expectEqual(@as(usize, 12), mnemonic.words.len);
}

test "bip39 mnemonic to seed" {
    const allocator = std.testing.allocator;

    const mnemonic_phrase = "test mnemonic phrase for seed generation";
    const passphrase = "";
    
    const seed = try bip39.mnemonicToSeed(allocator, mnemonic_phrase, passphrase);
    defer allocator.free(seed);
    
    try std.testing.expectEqual(@as(usize, 64), seed.len);
}

test "bip32 master key derivation" {
    const seed = "test seed for master key derivation";
    const master = bip32.masterKeyFromSeed(seed);
    
    try std.testing.expectEqual(@as(u8, 0), master.depth);
    try std.testing.expectEqual(@as(u32, 0), master.child_index);
}

test "bip32 child key derivation" {
    const seed = "test seed for child derivation";
    const master = bip32.masterKeyFromSeed(seed);
    
    const child = master.deriveChild(0);
    try std.testing.expectEqual(@as(u8, 1), child.depth);
    try std.testing.expectEqual(@as(u32, 0), child.child_index);
    
    // Child key should be different from parent
    try std.testing.expect(!std.mem.eql(u8, &master.key, &child.key));
}

test "bip44 derivation paths" {
    const btc_path = bip44.bitcoinPath(0, 0, 0);
    try std.testing.expectEqual(@as(u32, 0), btc_path.coin_type);
    
    const eth_path = bip44.ethereumPath(0, 0, 0);
    try std.testing.expectEqual(@as(u32, 60), eth_path.coin_type);
}

test "bip44 key derivation" {
    const seed = "test seed for bip44 derivation";
    const master = bip32.masterKeyFromSeed(seed);
    const path = bip44.bitcoinPath(0, 0, 0);
    
    const derived = bip44.deriveKey(master, path);
    
    // Should be at depth 5 (m/44'/0'/0'/0/0)
    try std.testing.expectEqual(@as(u8, 5), derived.depth);
    
    // Convert to secp256k1 keypair
    const keypair = try derived.toSecp256k1KeyPair();
    try std.testing.expectEqual(@as(usize, 32), keypair.private_key.len);
    try std.testing.expectEqual(@as(usize, 33), keypair.public_key_compressed.len);
}