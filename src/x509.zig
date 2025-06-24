//! X.509 Certificate Parsing
//!
//! Basic DER-encoded X.509 certificate parsing for TLS certificate validation.
//! Implements essential parsing for TLS 1.3 certificate chains.

const std = @import("std");
const util = @import("util.zig");

/// ASN.1 DER tag types
pub const DerTag = enum(u8) {
    boolean = 0x01,
    integer = 0x02,
    bit_string = 0x03,
    octet_string = 0x04,
    null = 0x05,
    oid = 0x06,
    utf8_string = 0x0c,
    printable_string = 0x13,
    ia5_string = 0x16,
    utc_time = 0x17,
    generalized_time = 0x18,
    sequence = 0x30,
    set = 0x31,
    context_specific_0 = 0xa0,
    context_specific_1 = 0xa1,
    context_specific_2 = 0xa2,
    context_specific_3 = 0xa3,
};

const errors = @import("errors.zig");

/// Legacy DER errors - use errors.X509Error for new code
pub const DerError = errors.X509Error;

/// ASN.1 object identifier
pub const ObjectId = struct {
    bytes: []const u8,
    
    pub fn equals(self: ObjectId, other: ObjectId) bool {
        return std.mem.eql(u8, self.bytes, other.bytes);
    }
    
    pub fn toString(self: ObjectId, allocator: std.mem.Allocator) ![]u8 {
        if (self.bytes.len == 0) return try allocator.dupe(u8, "");
        
        var result = std.ArrayList(u8).init(allocator);
        defer result.deinit();
        
        // First two components are encoded in first byte
        const first_byte = self.bytes[0];
        const first = first_byte / 40;
        const second = first_byte % 40;
        
        try result.writer().print("{}.{}", .{ first, second });
        
        // Remaining components
        var i: usize = 1;
        while (i < self.bytes.len) {
            var value: u64 = 0;
            while (i < self.bytes.len) {
                const byte = self.bytes[i];
                value = (value << 7) | (byte & 0x7f);
                i += 1;
                if ((byte & 0x80) == 0) break;
            }
            try result.writer().print(".{}", .{value});
        }
        
        return result.toOwnedSlice();
    }
};

/// Common OIDs used in X.509 certificates
pub const CommonOids = struct {
    pub const rsa_encryption = ObjectId{ .bytes = &[_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 } };
    pub const sha256_with_rsa = ObjectId{ .bytes = &[_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b } };
    pub const ed25519 = ObjectId{ .bytes = &[_]u8{ 0x2b, 0x65, 0x70 } };
    pub const common_name = ObjectId{ .bytes = &[_]u8{ 0x55, 0x04, 0x03 } };
    pub const subject_alt_name = ObjectId{ .bytes = &[_]u8{ 0x55, 0x1d, 0x11 } };
    pub const key_usage = ObjectId{ .bytes = &[_]u8{ 0x55, 0x1d, 0x0f } };
};

/// X.509 certificate public key information
pub const PublicKeyInfo = struct {
    algorithm: ObjectId,
    public_key: []const u8,
    
    pub fn deinit(self: PublicKeyInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.algorithm.bytes);
        allocator.free(self.public_key);
    }
};

/// X.509 certificate extension
pub const Extension = struct {
    oid: ObjectId,
    critical: bool,
    value: []const u8,
    
    pub fn deinit(self: Extension, allocator: std.mem.Allocator) void {
        allocator.free(self.oid.bytes);
        allocator.free(self.value);
    }
};

/// X.509 certificate validity period
pub const Validity = struct {
    not_before: i64, // Unix timestamp
    not_after: i64,  // Unix timestamp
    
    pub fn isValid(self: Validity, timestamp: i64) bool {
        return timestamp >= self.not_before and timestamp <= self.not_after;
    }
    
    pub fn isCurrentlyValid(self: Validity) bool {
        return self.isValid(std.time.timestamp());
    }
};

/// X.509 certificate subject/issuer name
pub const Name = struct {
    common_name: ?[]const u8 = null,
    raw_der: []const u8,
    
    pub fn deinit(self: Name, allocator: std.mem.Allocator) void {
        if (self.common_name) |cn| allocator.free(cn);
        allocator.free(self.raw_der);
    }
};

/// Parsed X.509 certificate
pub const Certificate = struct {
    version: u8,
    serial_number: []const u8,
    signature_algorithm: ObjectId,
    issuer: Name,
    validity: Validity,
    subject: Name,
    public_key_info: PublicKeyInfo,
    extensions: []Extension,
    signature: []const u8,
    raw_der: []const u8,
    allocator: std.mem.Allocator,
    
    /// Parse a DER-encoded X.509 certificate
    pub fn parse(allocator: std.mem.Allocator, der: []const u8) !Certificate {
        var parser = DerParser.init(der);
        
        // Certificate ::= SEQUENCE {
        const cert_seq = try parser.parseSequence();
        var cert_parser = DerParser.init(cert_seq);
        
        // tbsCertificate TBSCertificate,
        const tbs_cert = try cert_parser.parseSequence();
        var tbs_parser = DerParser.init(tbs_cert);
        
        // Parse version [0] EXPLICIT Version DEFAULT v1
        var version: u8 = 1;
        if (tbs_parser.peekTag() == @intFromEnum(DerTag.context_specific_0)) {
            const version_explicit = try tbs_parser.parseContextSpecific(0);
            var version_parser = DerParser.init(version_explicit);
            const version_int = try version_parser.parseInteger();
            if (version_int.len > 0) {
                version = @intCast(version_int[0] + 1);
            }
        }
        
        // serialNumber CertificateSerialNumber,
        const serial_number = try allocator.dupe(u8, try tbs_parser.parseInteger());
        
        // signature AlgorithmIdentifier,
        const sig_alg_seq = try tbs_parser.parseSequence();
        var sig_alg_parser = DerParser.init(sig_alg_seq);
        const signature_algorithm = ObjectId{ .bytes = try allocator.dupe(u8, try sig_alg_parser.parseOid()) };
        
        // issuer Name,
        const issuer_seq = try tbs_parser.parseSequence();
        const issuer = try parseName(allocator, issuer_seq);
        
        // validity Validity,
        const validity = try parseValidity(&tbs_parser);
        
        // subject Name,
        const subject_seq = try tbs_parser.parseSequence();
        const subject = try parseName(allocator, subject_seq);
        
        // subjectPublicKeyInfo SubjectPublicKeyInfo,
        const public_key_info = try parsePublicKeyInfo(allocator, &tbs_parser);
        
        // extensions [3] EXPLICIT Extensions OPTIONAL
        var extensions = std.ArrayList(Extension).init(allocator);
        if (tbs_parser.peekTag() == @intFromEnum(DerTag.context_specific_3)) {
            const ext_explicit = try tbs_parser.parseContextSpecific(3);
            var ext_parser = DerParser.init(ext_explicit);
            const ext_seq = try ext_parser.parseSequence();
            try parseExtensions(allocator, &extensions, ext_seq);
        }
        
        // signatureAlgorithm AlgorithmIdentifier,
        _ = try cert_parser.parseSequence(); // Skip, already parsed
        
        // signature BIT STRING
        const signature = try allocator.dupe(u8, try cert_parser.parseBitString());
        
        return Certificate{
            .version = version,
            .serial_number = serial_number,
            .signature_algorithm = signature_algorithm,
            .issuer = issuer,
            .validity = validity,
            .subject = subject,
            .public_key_info = public_key_info,
            .extensions = try extensions.toOwnedSlice(),
            .signature = signature,
            .raw_der = try allocator.dupe(u8, der),
            .allocator = allocator,
        };
    }
    
    /// Free certificate memory
    pub fn deinit(self: Certificate) void {
        self.allocator.free(self.serial_number);
        self.allocator.free(self.signature_algorithm.bytes);
        self.issuer.deinit(self.allocator);
        self.subject.deinit(self.allocator);
        self.public_key_info.deinit(self.allocator);
        
        for (self.extensions) |ext| {
            ext.deinit(self.allocator);
        }
        self.allocator.free(self.extensions);
        
        self.allocator.free(self.signature);
        self.allocator.free(self.raw_der);
    }
    
    /// Check if certificate is currently valid (not expired)
    pub fn isValid(self: Certificate) bool {
        return self.validity.isCurrentlyValid();
    }
    
    /// Get common name from subject
    pub fn getCommonName(self: Certificate) ?[]const u8 {
        return self.subject.common_name;
    }
    
    /// Get subject alternative names
    pub fn getSubjectAltNames(self: Certificate, allocator: std.mem.Allocator) ![][]const u8 {
        for (self.extensions) |ext| {
            if (ext.oid.equals(CommonOids.subject_alt_name)) {
                return parseSubjectAltNames(allocator, ext.value);
            }
        }
        return &[_][]const u8{};
    }
    
    /// Verify certificate signature against issuer's public key
    pub fn verifySignature(self: Certificate, issuer_public_key: []const u8) !bool {
        // For now, only support Ed25519 signatures
        if (!self.signature_algorithm.equals(CommonOids.ed25519)) {
            return error.UnsupportedSignatureAlgorithm;
        }
        
        if (issuer_public_key.len != 32) {
            return error.InvalidPublicKeySize;
        }
        
        if (self.signature.len != 64) {
            return error.InvalidSignatureSize;
        }
        
        // Extract the TBS (To Be Signed) certificate portion
        // This requires re-parsing to find the TBS boundary
        var parser = DerParser.init(self.raw_der);
        const cert_seq = try parser.parseSequence();
        var cert_parser = DerParser.init(cert_seq);
        
        // Parse TBS certificate length to get boundaries
        const tbs_start = cert_parser.pos;
        _ = try cert_parser.parseSequence(); // Skip over TBS content
        const tbs_end = cert_parser.pos;
        
        const tbs_der = cert_seq[tbs_start..tbs_end];
        
        // Verify Ed25519 signature
        const public_key: [32]u8 = issuer_public_key[0..32].*;
        const signature: [64]u8 = self.signature[0..64].*;
        
        const asym = @import("asym.zig");
        return asym.ed25519.verify(tbs_der, signature, public_key);
    }
    
    /// Check if certificate is valid for the given hostname
    pub fn isValidForHostname(self: Certificate, hostname: []const u8) !bool {
        // Check Subject Common Name
        if (self.getCommonName()) |cn| {
            if (hostnameMatches(hostname, cn)) {
                return true;
            }
        }
        
        // Check Subject Alternative Names
        const allocator = self.allocator;
        const sans = try self.getSubjectAltNames(allocator);
        defer {
            for (sans) |san| {
                allocator.free(san);
            }
            allocator.free(sans);
        }
        
        for (sans) |san| {
            if (hostnameMatches(hostname, san)) {
                return true;
            }
        }
        
        return false;
    }
};

/// DER parser state
const DerParser = struct {
    data: []const u8,
    pos: usize = 0,
    
    fn init(data: []const u8) DerParser {
        return .{ .data = data };
    }
    
    fn remaining(self: DerParser) []const u8 {
        return self.data[self.pos..];
    }
    
    fn advance(self: *DerParser, n: usize) !void {
        if (self.pos + n > self.data.len) return DerError.UnexpectedEOF;
        self.pos += n;
    }
    
    fn peekTag(self: DerParser) u8 {
        if (self.pos >= self.data.len) return 0;
        return self.data[self.pos];
    }
    
    fn parseTag(self: *DerParser, expected: DerTag) !void {
        if (self.pos >= self.data.len) return DerError.UnexpectedEOF;
        const tag = self.data[self.pos];
        if (tag != @intFromEnum(expected)) return errors.X509Error.InvalidTag;
        self.pos += 1;
    }
    
    fn parseLength(self: *DerParser) !usize {
        if (self.pos >= self.data.len) return DerError.UnexpectedEOF;
        
        const first_byte = self.data[self.pos];
        self.pos += 1;
        
        if ((first_byte & 0x80) == 0) {
            // Short form
            return first_byte;
        }
        
        // Long form
        const length_bytes = first_byte & 0x7f;
        if (length_bytes == 0) return DerError.InvalidLength; // Indefinite length not allowed in DER
        if (length_bytes > 4) return DerError.InvalidLength; // Length too long
        if (self.pos + length_bytes > self.data.len) return DerError.UnexpectedEOF;
        
        var length: usize = 0;
        for (0..length_bytes) |_| {
            length = (length << 8) | self.data[self.pos];
            self.pos += 1;
        }
        
        return length;
    }
    
    fn parseSequence(self: *DerParser) ![]const u8 {
        try self.parseTag(.sequence);
        const length = try self.parseLength();
        if (self.pos + length > self.data.len) return DerError.UnexpectedEOF;
        const content = self.data[self.pos..self.pos + length];
        try self.advance(length);
        return content;
    }
    
    fn parseInteger(self: *DerParser) ![]const u8 {
        try self.parseTag(.integer);
        const length = try self.parseLength();
        if (self.pos + length > self.data.len) return DerError.UnexpectedEOF;
        const content = self.data[self.pos..self.pos + length];
        try self.advance(length);
        return content;
    }
    
    fn parseOid(self: *DerParser) ![]const u8 {
        try self.parseTag(.oid);
        const length = try self.parseLength();
        if (self.pos + length > self.data.len) return DerError.UnexpectedEOF;
        const content = self.data[self.pos..self.pos + length];
        try self.advance(length);
        return content;
    }
    
    fn parseBitString(self: *DerParser) ![]const u8 {
        try self.parseTag(.bit_string);
        const length = try self.parseLength();
        if (length == 0) return DerError.InvalidLength;
        if (self.pos + length > self.data.len) return DerError.UnexpectedEOF;
        
        const unused_bits = self.data[self.pos];
        if (unused_bits > 7) return DerError.InvalidDerEncoding;
        
        const content = self.data[self.pos + 1..self.pos + length];
        try self.advance(length);
        return content;
    }
    
    fn parseOctetString(self: *DerParser) ![]const u8 {
        try self.parseTag(.octet_string);
        const length = try self.parseLength();
        if (self.pos + length > self.data.len) return DerError.UnexpectedEOF;
        const content = self.data[self.pos..self.pos + length];
        try self.advance(length);
        return content;
    }
    
    fn parseContextSpecific(self: *DerParser, expected: u8) ![]const u8 {
        const expected_tag = 0xa0 | expected;
        if (self.pos >= self.data.len) return DerError.UnexpectedEOF;
        const tag = self.data[self.pos];
        if (tag != expected_tag) return DerError.InvalidTag;
        self.pos += 1;
        
        const length = try self.parseLength();
        if (self.pos + length > self.data.len) return DerError.UnexpectedEOF;
        const content = self.data[self.pos..self.pos + length];
        try self.advance(length);
        return content;
    }
    
    fn parseUtcTime(self: *DerParser) !i64 {
        try self.parseTag(.utc_time);
        const length = try self.parseLength();
        if (length != 13) return DerError.InvalidDerEncoding; // YYMMDDHHMMSSZ
        if (self.pos + length > self.data.len) return DerError.UnexpectedEOF;
        
        const time_str = self.data[self.pos..self.pos + length];
        try self.advance(length);
        
        // Parse YYMMDDHHMMSSZ format
        if (time_str[12] != 'Z') return DerError.InvalidDerEncoding;
        
        const year = try std.fmt.parseInt(u16, time_str[0..2], 10);
        const month = try std.fmt.parseInt(u8, time_str[2..4], 10);
        const day = try std.fmt.parseInt(u8, time_str[4..6], 10);
        const hour = try std.fmt.parseInt(u8, time_str[6..8], 10);
        const minute = try std.fmt.parseInt(u8, time_str[8..10], 10);
        const second = try std.fmt.parseInt(u8, time_str[10..12], 10);
        
        // Y2K handling: 50-99 -> 1950-1999, 00-49 -> 2000-2049
        const full_year: u16 = if (year >= 50) year + 1900 else year + 2000;
        
        // Convert to Unix timestamp (simplified)
        const days_since_epoch = daysSinceEpoch(full_year, month, day);
        const timestamp: i64 = @as(i64, days_since_epoch) * 86400 + 
                              @as(i64, hour) * 3600 + 
                              @as(i64, minute) * 60 + 
                              @as(i64, second);
        
        return timestamp;
    }
};

// Helper functions
fn parseName(allocator: std.mem.Allocator, der: []const u8) !Name {
    var parser = DerParser.init(der);
    var common_name: ?[]const u8 = null;
    
    // Name is a SEQUENCE OF RelativeDistinguishedName
    while (parser.pos < parser.data.len) {
        const rdn_seq = try parser.parseSequence();
        var rdn_parser = DerParser.init(rdn_seq);
        
        while (rdn_parser.pos < rdn_parser.data.len) {
            const attr_seq = try rdn_parser.parseSequence();
            var attr_parser = DerParser.init(attr_seq);
            
            const oid_bytes = try attr_parser.parseOid();
            const oid = ObjectId{ .bytes = oid_bytes };
            
            if (oid.equals(CommonOids.common_name)) {
                // Parse the attribute value (can be various string types)
                const tag = attr_parser.peekTag();
                var value: []const u8 = undefined;
                
                switch (tag) {
                    @intFromEnum(DerTag.utf8_string) => {
                        try attr_parser.parseTag(.utf8_string);
                        const length = try attr_parser.parseLength();
                        value = attr_parser.data[attr_parser.pos..attr_parser.pos + length];
                    },
                    @intFromEnum(DerTag.printable_string) => {
                        try attr_parser.parseTag(.printable_string);
                        const length = try attr_parser.parseLength();
                        value = attr_parser.data[attr_parser.pos..attr_parser.pos + length];
                    },
                    else => continue, // Skip unsupported string types
                }
                
                common_name = try allocator.dupe(u8, value);
                break;
            }
        }
    }
    
    return Name{
        .common_name = common_name,
        .raw_der = try allocator.dupe(u8, der),
    };
}

fn parseValidity(parser: *DerParser) !Validity {
    const validity_seq = try parser.parseSequence();
    var validity_parser = DerParser.init(validity_seq);
    
    const not_before = try validity_parser.parseUtcTime();
    const not_after = try validity_parser.parseUtcTime();
    
    return Validity{
        .not_before = not_before,
        .not_after = not_after,
    };
}

fn parsePublicKeyInfo(allocator: std.mem.Allocator, parser: *DerParser) !PublicKeyInfo {
    const pki_seq = try parser.parseSequence();
    var pki_parser = DerParser.init(pki_seq);
    
    // algorithm AlgorithmIdentifier
    const alg_seq = try pki_parser.parseSequence();
    var alg_parser = DerParser.init(alg_seq);
    const algorithm = ObjectId{ .bytes = try allocator.dupe(u8, try alg_parser.parseOid()) };
    
    // subjectPublicKey BIT STRING
    const public_key = try allocator.dupe(u8, try pki_parser.parseBitString());
    
    return PublicKeyInfo{
        .algorithm = algorithm,
        .public_key = public_key,
    };
}

fn parseExtensions(allocator: std.mem.Allocator, extensions: *std.ArrayList(Extension), der: []const u8) !void {
    var parser = DerParser.init(der);
    
    while (parser.pos < parser.data.len) {
        const ext_seq = try parser.parseSequence();
        var ext_parser = DerParser.init(ext_seq);
        
        const oid = ObjectId{ .bytes = try allocator.dupe(u8, try ext_parser.parseOid()) };
        
        // critical BOOLEAN DEFAULT FALSE
        var critical = false;
        if (ext_parser.peekTag() == @intFromEnum(DerTag.boolean)) {
            try ext_parser.parseTag(.boolean);
            const length = try ext_parser.parseLength();
            if (length != 1) return DerError.InvalidDerEncoding;
            critical = ext_parser.data[ext_parser.pos] != 0;
            try ext_parser.advance(1);
        }
        
        // extnValue OCTET STRING
        const value = try allocator.dupe(u8, try ext_parser.parseOctetString());
        
        try extensions.append(Extension{
            .oid = oid,
            .critical = critical,
            .value = value,
        });
    }
}

fn parseSubjectAltNames(allocator: std.mem.Allocator, der: []const u8) ![][]const u8 {
    var parser = DerParser.init(der);
    var names = std.ArrayList([]const u8).init(allocator);
    
    const san_seq = try parser.parseSequence();
    var san_parser = DerParser.init(san_seq);
    
    while (san_parser.pos < san_parser.data.len) {
        const tag = san_parser.peekTag();
        if ((tag & 0x80) != 0) { // Context-specific tag
            const name_type = tag & 0x0f;
            if (name_type == 2) { // dNSName
                try san_parser.advance(1); // Skip tag
                const length = try san_parser.parseLength();
                const dns_name = san_parser.data[san_parser.pos..san_parser.pos + length];
                try names.append(try allocator.dupe(u8, dns_name));
                try san_parser.advance(length);
            } else {
                // Skip other name types
                try san_parser.advance(1);
                const length = try san_parser.parseLength();
                try san_parser.advance(length);
            }
        } else {
            try san_parser.advance(1); // Skip unknown tags
        }
    }
    
    return names.toOwnedSlice();
}

fn daysSinceEpoch(year: u16, month: u8, day: u8) i32 {
    // Simplified calculation (doesn't handle all edge cases)
    var days: i32 = 0;
    
    // Years since 1970
    for (1970..year) |y| {
        days += if (isLeapYear(@intCast(y))) 366 else 365;
    }
    
    // Months in current year
    const days_in_month = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    for (1..month) |m| {
        days += days_in_month[m - 1];
        if (m == 2 and isLeapYear(year)) days += 1;
    }
    
    // Days in current month
    days += day - 1;
    
    return days;
}

fn isLeapYear(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

/// Check if hostname matches certificate name (supports wildcards)
fn hostnameMatches(hostname: []const u8, cert_name: []const u8) bool {
    // Exact match
    if (std.mem.eql(u8, hostname, cert_name)) {
        return true;
    }
    
    // Wildcard match (*.example.com)
    if (cert_name.len >= 2 and cert_name[0] == '*' and cert_name[1] == '.') {
        const wildcard_domain = cert_name[2..];
        
        // Find the first dot in hostname
        if (std.mem.indexOf(u8, hostname, ".")) |dot_pos| {
            const hostname_domain = hostname[dot_pos + 1..];
            return std.mem.eql(u8, hostname_domain, wildcard_domain);
        }
    }
    
    return false;
}

test "X.509 certificate OID parsing" {
    const allocator = std.testing.allocator;
    
    // Test RSA encryption OID
    const rsa_oid = CommonOids.rsa_encryption;
    const rsa_str = try rsa_oid.toString(allocator);
    defer allocator.free(rsa_str);
    
    try std.testing.expectEqualStrings("1.2.840.113549.1.1.1", rsa_str);
}

test "X.509 DER parser basic operations" {
    // Test DER length parsing
    var parser = DerParser.init(&[_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 });
    
    const seq = try parser.parseSequence();
    try std.testing.expectEqual(@as(usize, 3), seq.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, seq);
}

test "X.509 certificate validation helpers" {
    // Test validity period
    const validity = Validity{
        .not_before = 1609459200, // 2021-01-01
        .not_after = 1672531200,  // 2023-01-01
    };
    
    try std.testing.expect(validity.isValid(1640995200)); // 2022-01-01
    try std.testing.expect(!validity.isValid(1577836800)); // 2020-01-01
    try std.testing.expect(!validity.isValid(1704067200)); // 2024-01-01
}

test "X.509 hostname matching" {
    // Exact match
    try std.testing.expect(hostnameMatches("example.com", "example.com"));
    try std.testing.expect(!hostnameMatches("example.com", "other.com"));
    
    // Wildcard match
    try std.testing.expect(hostnameMatches("www.example.com", "*.example.com"));
    try std.testing.expect(hostnameMatches("api.example.com", "*.example.com"));
    try std.testing.expect(!hostnameMatches("example.com", "*.example.com")); // No subdomain
    try std.testing.expect(!hostnameMatches("sub.api.example.com", "*.example.com")); // Too many levels
}

test "X.509 certificate chain validation concept" {
    // This test demonstrates the concept - in practice would need real certificate data
    const allocator = std.testing.allocator;
    
    // Mock certificate data (in practice this would be real DER)
    const mock_cert_der = [_]u8{
        0x30, 0x82, 0x01, 0x00, // Certificate SEQUENCE
        // ... (rest would be actual certificate DER)
    };
    
    // For now, just test that parsing fails gracefully with invalid data
    const result = Certificate.parse(allocator, &mock_cert_der);
    try std.testing.expectError(DerError.UnexpectedEOF, result);
}