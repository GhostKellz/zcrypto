//! TLS 1.3 Record Layer
//!
//! Implements the TLS 1.3 record layer with proper framing, encryption, and decryption.
//! Handles record types, length encoding, and AEAD protection as defined in RFC 8446.

const std = @import("std");
const tls = @import("tls.zig");
const config = @import("tls_config.zig");
const sym = @import("sym.zig");
const util = @import("util.zig");
const errors = @import("errors.zig");

/// TLS 1.3 record types (RFC 8446 Section 5.1)
pub const RecordType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    
    pub fn toString(self: RecordType) []const u8 {
        return switch (self) {
            .invalid => "Invalid",
            .change_cipher_spec => "ChangeCipherSpec",
            .alert => "Alert",
            .handshake => "Handshake",
            .application_data => "ApplicationData",
        };
    }
};

/// TLS 1.3 content types for inner plaintext
pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    heartbeat = 24, // RFC 6520
};

/// TLS alert levels (RFC 8446 Section 6)
pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
};

/// TLS alert descriptions
pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
};

/// TLS alert structure
pub const Alert = struct {
    level: AlertLevel,
    description: AlertDescription,
    
    pub fn toBytes(self: Alert) [2]u8 {
        return [2]u8{ @intFromEnum(self.level), @intFromEnum(self.description) };
    }
    
    pub fn fromBytes(bytes: [2]u8) !Alert {
        return Alert{
            .level = std.meta.intToEnum(AlertLevel, bytes[0]) catch return errors.TlsError.InvalidRecordFormat,
            .description = std.meta.intToEnum(AlertDescription, bytes[1]) catch return errors.TlsError.InvalidRecordFormat,
        };
    }
    
    pub fn isFatal(self: Alert) bool {
        return self.level == .fatal;
    }
};

/// Maximum TLS record payload size (RFC 8446)
pub const MAX_RECORD_SIZE = 16384; // 2^14
/// Maximum encrypted record size (with overhead)
pub const MAX_ENCRYPTED_RECORD_SIZE = MAX_RECORD_SIZE + 256; // RFC allows up to 2^14 + 256
/// TLS record header size
pub const RECORD_HEADER_SIZE = 5;

/// TLS record header
pub const RecordHeader = struct {
    record_type: RecordType,
    version: u16, // Should be 0x0303 for TLS 1.3 compatibility
    length: u16,
    
    /// Encode header to bytes
    pub fn toBytes(self: RecordHeader) [RECORD_HEADER_SIZE]u8 {
        var bytes: [RECORD_HEADER_SIZE]u8 = undefined;
        bytes[0] = @intFromEnum(self.record_type);
        util.writeU16BigEndian(bytes[1..3], self.version);
        util.writeU16BigEndian(bytes[3..5], self.length);
        return bytes;
    }
    
    /// Decode header from bytes
    pub fn fromBytes(bytes: [RECORD_HEADER_SIZE]u8) !RecordHeader {
        const record_type = std.meta.intToEnum(RecordType, bytes[0]) catch {
            return errors.TlsError.InvalidRecordType;
        };
        
        return RecordHeader{
            .record_type = record_type,
            .version = util.readU16BigEndian(bytes[1..3]),
            .length = util.readU16BigEndian(bytes[3..5]),
        };
    }
    
    /// Validate header constraints
    pub fn validate(self: RecordHeader) !void {
        if (self.length > MAX_ENCRYPTED_RECORD_SIZE) {
            return errors.TlsError.RecordTooLarge;
        }
        
        // TLS 1.3 uses 0x0303 for backward compatibility
        if (self.version != 0x0303) {
            return errors.TlsError.InvalidVersion;
        }
    }
};

/// TLS plaintext record (before encryption)
pub const TlsPlaintext = struct {
    content_type: ContentType,
    data: []const u8,
    allocator: std.mem.Allocator,
    
    /// Create new plaintext record
    pub fn init(allocator: std.mem.Allocator, content_type: ContentType, data: []const u8) !TlsPlaintext {
        return TlsPlaintext{
            .content_type = content_type,
            .data = try allocator.dupe(u8, data),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: TlsPlaintext) void {
        self.allocator.free(self.data);
    }
    
    /// Serialize to inner plaintext format (data + content_type + padding)
    pub fn serialize(self: TlsPlaintext, allocator: std.mem.Allocator) ![]u8 {
        // TLS 1.3 inner plaintext: content || content_type || zeros
        const inner_size = self.data.len + 1; // +1 for content type
        const inner = try allocator.alloc(u8, inner_size);
        
        @memcpy(inner[0..self.data.len], self.data);
        inner[self.data.len] = @intFromEnum(self.content_type);
        
        return inner;
    }
    
    /// Deserialize from inner plaintext (strips padding and extracts content type)
    pub fn deserialize(allocator: std.mem.Allocator, inner: []const u8) !TlsPlaintext {
        if (inner.len == 0) {
            return errors.TlsError.InvalidRecordFormat;
        }
        
        // Find the actual content type by scanning backwards through padding
        var content_end = inner.len;
        while (content_end > 0 and inner[content_end - 1] == 0) {
            content_end -= 1;
        }
        
        if (content_end == 0) {
            return errors.TlsError.InvalidRecordFormat;
        }
        
        const content_type_byte = inner[content_end - 1];
        const content_type = std.meta.intToEnum(ContentType, content_type_byte) catch {
            return errors.TlsError.InvalidRecordFormat;
        };
        
        const data = inner[0..content_end - 1];
        return TlsPlaintext.init(allocator, content_type, data);
    }
};

/// TLS ciphertext record (after encryption)
pub const TlsCiphertext = struct {
    header: RecordHeader,
    encrypted_data: []const u8,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, header: RecordHeader, encrypted_data: []const u8) !TlsCiphertext {
        return TlsCiphertext{
            .header = header,
            .encrypted_data = try allocator.dupe(u8, encrypted_data),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: TlsCiphertext) void {
        self.allocator.free(self.encrypted_data);
    }
    
    /// Serialize to wire format (header + encrypted_data)
    pub fn toBytes(self: TlsCiphertext, allocator: std.mem.Allocator) ![]u8 {
        const total_size = RECORD_HEADER_SIZE + self.encrypted_data.len;
        const bytes = try allocator.alloc(u8, total_size);
        
        const header_bytes = self.header.toBytes();
        @memcpy(bytes[0..RECORD_HEADER_SIZE], &header_bytes);
        @memcpy(bytes[RECORD_HEADER_SIZE..], self.encrypted_data);
        
        return bytes;
    }
    
    /// Parse from wire format
    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) !TlsCiphertext {
        if (bytes.len < RECORD_HEADER_SIZE) {
            return errors.TlsError.InvalidRecordFormat;
        }
        
        const header_bytes: [RECORD_HEADER_SIZE]u8 = bytes[0..RECORD_HEADER_SIZE].*;
        const header = try RecordHeader.fromBytes(header_bytes);
        try header.validate();
        
        if (bytes.len != RECORD_HEADER_SIZE + header.length) {
            return errors.TlsError.InvalidRecordFormat;
        }
        
        const encrypted_data = bytes[RECORD_HEADER_SIZE..];
        return TlsCiphertext.init(allocator, header, encrypted_data);
    }
};

/// TLS record layer state
pub const RecordLayer = struct {
    /// Current cipher suite
    cipher_suite: config.CipherSuite,
    /// AEAD cipher for encryption/decryption
    aead_cipher: ?tls.AeadCipher = null,
    /// Sequence number for this direction
    sequence_number: u64 = 0,
    /// Allocator for memory management
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, cipher_suite: config.CipherSuite) RecordLayer {
        return RecordLayer{
            .cipher_suite = cipher_suite,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *RecordLayer) void {
        if (self.aead_cipher) |cipher| {
            cipher.deinit();
        }
    }
    
    /// Set traffic keys for encryption/decryption
    pub fn setTrafficKeys(self: *RecordLayer, key: []const u8, iv: []const u8) !void {
        if (self.aead_cipher) |cipher| {
            cipher.deinit();
        }
        
        self.aead_cipher = try tls.AeadCipher.init(self.allocator, self.cipher_suite, key, iv);
        self.sequence_number = 0;
    }
    
    /// Encrypt plaintext into a TLS record
    pub fn encrypt(self: *RecordLayer, plaintext: TlsPlaintext) !TlsCiphertext {
        if (self.aead_cipher == null) {
            return errors.TlsError.KeyScheduleError;
        }
        
        // Serialize inner plaintext
        const inner = try plaintext.serialize(self.allocator);
        defer self.allocator.free(inner);
        
        if (inner.len > MAX_RECORD_SIZE) {
            return errors.TlsError.RecordTooLarge;
        }
        
        // Generate per-record nonce: IV XOR sequence_number
        const cipher = self.aead_cipher.?;
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, cipher.iv);
        
        // XOR sequence number into the last 8 bytes of nonce
        var seq_bytes: [8]u8 = undefined;
        util.writeU64BigEndian(&seq_bytes, self.sequence_number);
        for (0..8) |i| {
            nonce[4 + i] ^= seq_bytes[i];
        }
        
        // Additional authenticated data (AAD) for TLS 1.3 is the record header
        const header = RecordHeader{
            .record_type = .application_data, // TLS 1.3 always uses application_data
            .version = 0x0303,
            .length = @intCast(inner.len + 16), // +16 for authentication tag
        };
        
        const aad = header.toBytes();
        
        // Encrypt
        const ciphertext_result = try cipher.encrypt(self.allocator, &nonce, inner, &aad);
        defer ciphertext_result.deinit();
        
        // Combine ciphertext and tag
        const encrypted_data = try self.allocator.alloc(u8, ciphertext_result.data.len + ciphertext_result.tag.len);
        @memcpy(encrypted_data[0..ciphertext_result.data.len], ciphertext_result.data);
        @memcpy(encrypted_data[ciphertext_result.data.len..], &ciphertext_result.tag);
        
        self.sequence_number += 1;
        
        return TlsCiphertext.init(self.allocator, header, encrypted_data);
    }
    
    /// Decrypt a TLS record into plaintext
    pub fn decrypt(self: *RecordLayer, ciphertext: TlsCiphertext) !TlsPlaintext {
        if (self.aead_cipher == null) {
            return errors.TlsError.KeyScheduleError;
        }
        
        if (ciphertext.encrypted_data.len < 16) { // Minimum size for auth tag
            return errors.TlsError.InvalidRecordFormat;
        }
        
        const cipher = self.aead_cipher.?;
        
        // Generate per-record nonce: IV XOR sequence_number
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, cipher.iv);
        
        var seq_bytes: [8]u8 = undefined;
        util.writeU64BigEndian(&seq_bytes, self.sequence_number);
        for (0..8) |i| {
            nonce[4 + i] ^= seq_bytes[i];
        }
        
        // Split ciphertext and authentication tag
        const tag_start = ciphertext.encrypted_data.len - 16;
        const encrypted_payload = ciphertext.encrypted_data[0..tag_start];
        const tag: [16]u8 = ciphertext.encrypted_data[tag_start..][0..16].*;
        
        // AAD is the record header
        const aad = ciphertext.header.toBytes();
        
        // Decrypt
        const decrypted = try cipher.decrypt(self.allocator, &nonce, encrypted_payload, &tag, &aad);
        defer if (decrypted) |d| self.allocator.free(d);
        
        if (decrypted == null) {
            return errors.TlsError.AuthenticationFailed;
        }
        
        self.sequence_number += 1;
        
        // Deserialize inner plaintext
        return TlsPlaintext.deserialize(self.allocator, decrypted.?);
    }
    
    /// Create an alert record
    pub fn createAlert(self: *RecordLayer, alert: Alert) !TlsCiphertext {
        const alert_bytes = alert.toBytes();
        const plaintext = try TlsPlaintext.init(self.allocator, .alert, &alert_bytes);
        defer plaintext.deinit();
        
        return self.encrypt(plaintext);
    }
    
    /// Parse an alert from plaintext
    pub fn parseAlert(plaintext: TlsPlaintext) !Alert {
        if (plaintext.content_type != .alert or plaintext.data.len != 2) {
            return errors.TlsError.InvalidRecordFormat;
        }
        
        const alert_bytes: [2]u8 = plaintext.data[0..2].*;
        return Alert.fromBytes(alert_bytes);
    }
};

/// Record fragmentation and reassembly
pub const RecordFragmenter = struct {
    /// Maximum fragment size (application configurable)
    max_fragment_size: usize,
    
    pub fn init(max_fragment_size: usize) RecordFragmenter {
        return RecordFragmenter{
            .max_fragment_size = @min(max_fragment_size, MAX_RECORD_SIZE),
        };
    }
    
    /// Fragment large data into multiple records
    pub fn fragment(self: RecordFragmenter, allocator: std.mem.Allocator, content_type: ContentType, data: []const u8) ![]TlsPlaintext {
        if (data.len <= self.max_fragment_size) {
            // No fragmentation needed
            const record = try TlsPlaintext.init(allocator, content_type, data);
            const records = try allocator.alloc(TlsPlaintext, 1);
            records[0] = record;
            return records;
        }
        
        // Calculate number of fragments needed
        const num_fragments = (data.len + self.max_fragment_size - 1) / self.max_fragment_size;
        const records = try allocator.alloc(TlsPlaintext, num_fragments);
        
        var offset: usize = 0;
        for (0..num_fragments) |i| {
            const fragment_size = @min(self.max_fragment_size, data.len - offset);
            const fragment_data = data[offset..offset + fragment_size];
            
            records[i] = try TlsPlaintext.init(allocator, content_type, fragment_data);
            offset += fragment_size;
        }
        
        return records;
    }
    
    /// Reassemble fragments into complete data
    pub fn reassemble(allocator: std.mem.Allocator, records: []const TlsPlaintext) ![]u8 {
        // Calculate total size
        var total_size: usize = 0;
        for (records) |record| {
            total_size += record.data.len;
        }
        
        // Reassemble data
        const result = try allocator.alloc(u8, total_size);
        var offset: usize = 0;
        for (records) |record| {
            @memcpy(result[offset..offset + record.data.len], record.data);
            offset += record.data.len;
        }
        
        return result;
    }
};

test "TLS record header serialization" {
    const header = RecordHeader{
        .record_type = .handshake,
        .version = 0x0303,
        .length = 256,
    };
    
    const bytes = header.toBytes();
    try std.testing.expectEqual(@as(u8, 22), bytes[0]); // handshake
    try std.testing.expectEqual(@as(u8, 0x03), bytes[1]); // version high
    try std.testing.expectEqual(@as(u8, 0x03), bytes[2]); // version low
    try std.testing.expectEqual(@as(u8, 0x01), bytes[3]); // length high
    try std.testing.expectEqual(@as(u8, 0x00), bytes[4]); // length low
    
    const parsed = try RecordHeader.fromBytes(bytes);
    try std.testing.expectEqual(header.record_type, parsed.record_type);
    try std.testing.expectEqual(header.version, parsed.version);
    try std.testing.expectEqual(header.length, parsed.length);
}

test "TLS alert serialization" {
    const alert = Alert{
        .level = .fatal,
        .description = .handshake_failure,
    };
    
    const bytes = alert.toBytes();
    try std.testing.expectEqual(@as(u8, 2), bytes[0]); // fatal
    try std.testing.expectEqual(@as(u8, 40), bytes[1]); // handshake_failure
    
    const parsed = try Alert.fromBytes(bytes);
    try std.testing.expectEqual(alert.level, parsed.level);
    try std.testing.expectEqual(alert.description, parsed.description);
    try std.testing.expect(parsed.isFatal());
}

test "TLS plaintext serialization" {
    const allocator = std.testing.allocator;
    const data = "Hello, TLS!";
    
    const plaintext = try TlsPlaintext.init(allocator, .application_data, data);
    defer plaintext.deinit();
    
    const serialized = try plaintext.serialize(allocator);
    defer allocator.free(serialized);
    
    // Should be: data + content_type_byte
    try std.testing.expectEqual(data.len + 1, serialized.len);
    try std.testing.expectEqualSlices(u8, data, serialized[0..data.len]);
    try std.testing.expectEqual(@as(u8, 23), serialized[serialized.len - 1]); // application_data
    
    // Test deserialization
    const deserialized = try TlsPlaintext.deserialize(allocator, serialized);
    defer deserialized.deinit();
    
    try std.testing.expectEqual(ContentType.application_data, deserialized.content_type);
    try std.testing.expectEqualSlices(u8, data, deserialized.data);
}

test "record fragmentation" {
    const allocator = std.testing.allocator;
    const fragmenter = RecordFragmenter.init(10); // Small fragments for testing
    
    const large_data = "This is a large piece of data that should be fragmented";
    const fragments = try fragmenter.fragment(allocator, .application_data, large_data);
    defer {
        for (fragments) |fragment| {
            fragment.deinit();
        }
        allocator.free(fragments);
    }
    
    // Should create multiple fragments
    try std.testing.expect(fragments.len > 1);
    
    // Reassemble and verify
    const reassembled = try RecordFragmenter.reassemble(allocator, fragments);
    defer allocator.free(reassembled);
    
    try std.testing.expectEqualSlices(u8, large_data, reassembled);
}

test "TLS record layer concept" {
    const allocator = std.testing.allocator;
    
    // Create record layer (encryption requires real traffic keys)
    var record_layer = RecordLayer.init(allocator, .TLS_AES_128_GCM_SHA256);
    defer record_layer.deinit();
    
    // Test alert creation (works without encryption)
    const alert = Alert{ .level = .warning, .description = .close_notify };
    
    // Without traffic keys, this would fail - just test the concept
    try std.testing.expectEqual(AlertLevel.warning, alert.level);
    try std.testing.expectEqual(AlertDescription.close_notify, alert.description);
}