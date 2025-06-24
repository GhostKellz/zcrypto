//! TLS Configuration Module
//!
//! Provides high-level configuration structures for TLS connections,
//! supporting both client and server configurations with a builder pattern.

const std = @import("std");
const asym = @import("asym.zig");
const x509 = @import("x509.zig");
const errors = @import("errors.zig");

/// TLS protocol versions
pub const TlsVersion = enum(u16) {
    tls_1_2 = 0x0303,
    tls_1_3 = 0x0304,

    pub fn toString(self: TlsVersion) []const u8 {
        return switch (self) {
            .tls_1_2 => "TLS 1.2",
            .tls_1_3 => "TLS 1.3",
        };
    }
};

/// TLS 1.3 cipher suites
pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,

    pub fn toString(self: CipherSuite) []const u8 {
        return switch (self) {
            .TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            .TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
            .TLS_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        };
    }

    pub fn keySize(self: CipherSuite) usize {
        return switch (self) {
            .TLS_AES_128_GCM_SHA256 => 16,
            .TLS_AES_256_GCM_SHA384 => 32,
            .TLS_CHACHA20_POLY1305_SHA256 => 32,
        };
    }

    pub fn hashAlgorithm(self: CipherSuite) HashAlgorithm {
        return switch (self) {
            .TLS_AES_128_GCM_SHA256 => .sha256,
            .TLS_AES_256_GCM_SHA384 => .sha384,
            .TLS_CHACHA20_POLY1305_SHA256 => .sha256,
        };
    }
};

/// Hash algorithms used in TLS
pub const HashAlgorithm = enum {
    sha256,
    sha384,
    sha512,

    pub fn digestSize(self: HashAlgorithm) usize {
        return switch (self) {
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }
};

/// Certificate structure
pub const Certificate = struct {
    /// DER-encoded certificate data
    der: []const u8,
    /// Optional certificate chain
    chain: ?[][]const u8 = null,
    /// Parsed certificate (lazy loaded)
    parsed: ?x509.Certificate = null,

    pub fn deinit(self: Certificate, allocator: std.mem.Allocator) void {
        allocator.free(self.der);
        if (self.chain) |chain| {
            for (chain) |cert| {
                allocator.free(cert);
            }
            allocator.free(chain);
        }
        if (self.parsed) |parsed| {
            parsed.deinit();
        }
    }
    
    /// Parse the certificate (lazy loading)
    pub fn parse(self: *Certificate, allocator: std.mem.Allocator) !*x509.Certificate {
        if (self.parsed == null) {
            self.parsed = try x509.Certificate.parse(allocator, self.der);
        }
        return &self.parsed.?;
    }
    
    /// Create certificate from DER data
    pub fn fromDer(allocator: std.mem.Allocator, der: []const u8) !Certificate {
        return Certificate{
            .der = try allocator.dupe(u8, der),
            .chain = null,
            .parsed = null,
        };
    }
    
    /// Create certificate with chain from DER data
    pub fn fromDerWithChain(allocator: std.mem.Allocator, der: []const u8, chain: [][]const u8) !Certificate {
        const owned_chain = try allocator.alloc([]u8, chain.len);
        for (chain, 0..) |cert, i| {
            owned_chain[i] = try allocator.dupe(u8, cert);
        }
        
        return Certificate{
            .der = try allocator.dupe(u8, der),
            .chain = owned_chain,
            .parsed = null,
        };
    }
};

/// Private key types
pub const PrivateKeyType = enum {
    ed25519,
    x25519,
    rsa,
    ecdsa_p256,
    ecdsa_p384,
};

/// Private key structure
pub const PrivateKey = struct {
    key_type: PrivateKeyType,
    /// DER-encoded private key
    der: []const u8,

    pub fn deinit(self: PrivateKey, allocator: std.mem.Allocator) void {
        allocator.free(self.der);
    }
};

/// Session cache interface
pub const SessionCache = struct {
    /// Store a session
    storeFn: *const fn (session_id: []const u8, session_data: []const u8) void,
    /// Retrieve a session
    getFn: *const fn (session_id: []const u8) ?[]const u8,
    /// Remove a session
    removeFn: *const fn (session_id: []const u8) void,
};

/// Default cipher suites for TLS 1.3
pub const default_cipher_suites = [_]CipherSuite{
    .TLS_AES_128_GCM_SHA256,
    .TLS_AES_256_GCM_SHA384,
    .TLS_CHACHA20_POLY1305_SHA256,
};

/// Memory ownership tracking for TLS configuration
const OwnedData = struct {
    server_name: bool = false,
    alpn_protocols: bool = false,
    cipher_suites: bool = false,
    certificates: bool = false,
    root_cas: bool = false,
    session_ticket_keys: bool = false,
};

/// TLS configuration structure
pub const TlsConfig = struct {
    /// Minimum TLS version
    min_version: TlsVersion = .tls_1_3,
    /// Maximum TLS version
    max_version: TlsVersion = .tls_1_3,
    
    /// Enabled cipher suites
    cipher_suites: []const CipherSuite = &default_cipher_suites,
    
    /// Server certificates and private key
    certificates: ?[]Certificate = null,
    private_key: ?PrivateKey = null,
    
    /// Client configuration
    server_name: ?[]const u8 = null,
    insecure_skip_verify: bool = false,
    root_cas: ?[]Certificate = null,
    
    /// ALPN protocols
    alpn_protocols: ?[][]const u8 = null,
    
    /// Session management
    session_cache: ?SessionCache = null,
    enable_session_tickets: bool = true,
    
    /// Performance settings
    max_fragment_size: u16 = 16384,
    
    /// Session ticket keys (server only)
    session_ticket_keys: ?[][32]u8 = null,
    
    /// Allocator for dynamic allocations
    allocator: std.mem.Allocator = undefined,
    
    /// Memory ownership tracking (private)
    _owned: OwnedData = .{},

    /// Initialize a new TLS configuration
    pub fn init(allocator: std.mem.Allocator) TlsConfig {
        return .{ .allocator = allocator };
    }

    /// Set server certificate and private key
    pub fn withCertificate(self: TlsConfig, cert: Certificate, key: PrivateKey) TlsConfig {
        var config = self;
        config.certificates = self.allocator.alloc(Certificate, 1) catch unreachable;
        config.certificates.?[0] = cert;
        config.private_key = key;
        return config;
    }

    /// Set multiple certificates (for SNI)
    pub fn withCertificates(self: TlsConfig, certs: []Certificate, key: PrivateKey) TlsConfig {
        var config = self;
        config.certificates = certs;
        config.private_key = key;
        return config;
    }

    /// Set server name for SNI (creates a reference, not a copy)
    pub fn withServerName(self: TlsConfig, name: []const u8) TlsConfig {
        var config = self;
        config.server_name = name;
        config._owned.server_name = false; // Mark as reference
        return config;
    }
    
    /// Set server name for SNI (creates an owned copy)
    pub fn withServerNameOwned(self: TlsConfig, name: []const u8) !TlsConfig {
        var config = self;
        config.server_name = try config.allocator.dupe(u8, name);
        config._owned.server_name = true; // Mark as owned
        return config;
    }

    /// Set ALPN protocols (creates a reference, not a copy)
    pub fn withALPN(self: TlsConfig, protocols: [][]const u8) TlsConfig {
        var config = self;
        config.alpn_protocols = protocols;
        config._owned.alpn_protocols = false; // Mark as reference
        return config;
    }
    
    /// Set ALPN protocols (creates an owned copy)
    pub fn withALPNOwned(self: TlsConfig, protocols: [][]const u8) !TlsConfig {
        var config = self;
        
        // Deep copy the protocols array
        const new_protocols = try config.allocator.alloc([]const u8, protocols.len);
        for (protocols, 0..) |proto, i| {
            new_protocols[i] = try config.allocator.dupe(u8, proto);
        }
        
        config.alpn_protocols = new_protocols;
        config._owned.alpn_protocols = true; // Mark as owned
        return config;
    }

    /// Set custom cipher suites
    pub fn withCipherSuites(self: TlsConfig, suites: []const CipherSuite) TlsConfig {
        var config = self;
        config.cipher_suites = suites;
        return config;
    }

    /// Set root certificate authorities
    pub fn withRootCAs(self: TlsConfig, cas: []Certificate) TlsConfig {
        var config = self;
        config.root_cas = cas;
        return config;
    }

    /// Enable/disable certificate verification
    pub fn withInsecureSkipVerify(self: TlsConfig, skip: bool) TlsConfig {
        var config = self;
        config.insecure_skip_verify = skip;
        return config;
    }

    /// Set TLS version range
    pub fn withVersions(self: TlsConfig, min: TlsVersion, max: TlsVersion) TlsConfig {
        var config = self;
        config.min_version = min;
        config.max_version = max;
        return config;
    }

    /// Set session cache
    pub fn withSessionCache(self: TlsConfig, cache: SessionCache) TlsConfig {
        var config = self;
        config.session_cache = cache;
        return config;
    }

    /// Validate configuration
    pub fn validate(self: TlsConfig) !void {
        if (@intFromEnum(self.min_version) > @intFromEnum(self.max_version)) {
            return errors.ConfigError.InvalidVersionRange;
        }

        if (self.cipher_suites.len == 0) {
            return errors.ConfigError.NoCipherSuites;
        }

        // Server-side validation
        if (self.certificates != null and self.private_key == null) {
            return errors.ConfigError.MissingPrivateKey;
        }

        if (self.private_key != null and self.certificates == null) {
            return errors.ConfigError.MissingCertificate;
        }
        
        // Validate certificates if present
        if (self.certificates) |certs| {
            for (certs) |*cert| {
                var parsed = try cert.parse(self.allocator);
                if (!parsed.isValid()) {
                    return error.ExpiredCertificate;
                }
            }
        }
        
        // Validate root CAs if present
        if (self.root_cas) |cas| {
            for (cas) |*ca| {
                var parsed = try ca.parse(self.allocator);
                if (!parsed.isValid()) {
                    return error.ExpiredRootCA;
                }
            }
        }
    }
    
    /// Verify server certificate against hostname (client-side)
    pub fn verifyCertificate(self: TlsConfig, cert_der: []const u8, hostname: ?[]const u8) !bool {
        if (self.insecure_skip_verify) {
            return true;
        }
        
        const cert = try x509.Certificate.parse(self.allocator, cert_der);
        defer cert.deinit();
        
        // Check validity period
        if (!cert.isValid()) {
            return error.CertificateExpired;
        }
        
        // Check hostname if provided
        if (hostname) |host| {
            if (!try cert.isValidForHostname(host)) {
                return error.HostnameMismatch;
            }
        }
        
        // Check against root CAs if provided
        if (self.root_cas) |cas| {
            for (cas) |*ca| {
                const ca_parsed = try ca.parse(self.allocator);
                // Simple validation - in practice would need full chain validation
                if (try cert.verifySignature(ca_parsed.public_key_info.public_key)) {
                    return true;
                }
            }
            return error.UntrustedCertificate;
        }
        
        // If no root CAs configured, accept any valid certificate
        return true;
    }

    /// Clone the configuration (creates owned copies of all data)
    pub fn clone(self: TlsConfig, allocator: std.mem.Allocator) !TlsConfig {
        var config = self;
        config.allocator = allocator;
        
        // Mark all cloned data as owned
        config._owned = .{
            .server_name = self.server_name != null,
            .alpn_protocols = self.alpn_protocols != null,
            .cipher_suites = self.cipher_suites.ptr != &default_cipher_suites,
            .certificates = self.certificates != null,
            .root_cas = self.root_cas != null,
            .session_ticket_keys = self.session_ticket_keys != null,
        };
        
        // Deep copy slices
        if (self.cipher_suites.ptr != &default_cipher_suites) {
            config.cipher_suites = try allocator.dupe(CipherSuite, self.cipher_suites);
        }
        
        if (self.server_name) |name| {
            config.server_name = try allocator.dupe(u8, name);
        }
        
        if (self.alpn_protocols) |protocols| {
            const new_protocols = try allocator.alloc([]u8, protocols.len);
            for (protocols, 0..) |proto, i| {
                new_protocols[i] = try allocator.dupe(u8, proto);
            }
            config.alpn_protocols = new_protocols;
        }
        
        // TODO: Clone certificates, root_cas, session_ticket_keys
        
        return config;
    }

    /// Free allocated resources
    /// Only frees resources that were allocated by this config (marked as owned).
    pub fn deinit(self: TlsConfig) void {
        // Free server name if owned
        if (self._owned.server_name and self.server_name != null) {
            self.allocator.free(self.server_name.?);
        }
        
        // Free ALPN protocols if owned
        if (self._owned.alpn_protocols and self.alpn_protocols != null) {
            for (self.alpn_protocols.?) |proto| {
                self.allocator.free(@constCast(proto));
            }
            self.allocator.free(self.alpn_protocols.?);
        }
        
        // Free cipher suites if owned
        if (self._owned.cipher_suites and self.cipher_suites.ptr != &default_cipher_suites) {
            self.allocator.free(self.cipher_suites);
        }
        
        // Free certificates if owned
        if (self._owned.certificates and self.certificates != null) {
            for (self.certificates.?) |cert| {
                cert.deinit(self.allocator);
            }
            self.allocator.free(self.certificates.?);
        }
        
        // Free private key if owned
        if (self.private_key != null) {
            self.private_key.?.deinit(self.allocator);
        }
        
        // Free root CAs if owned
        if (self._owned.root_cas and self.root_cas != null) {
            for (self.root_cas.?) |ca| {
                ca.deinit(self.allocator);
            }
            self.allocator.free(self.root_cas.?);
        }
        
        // Free session ticket keys if owned
        if (self._owned.session_ticket_keys and self.session_ticket_keys != null) {
            self.allocator.free(self.session_ticket_keys.?);
        }
    }
};

test "TLS config initialization" {
    const allocator = std.testing.allocator;
    
    const config = TlsConfig.init(allocator);
    defer config.deinit();
    
    try std.testing.expectEqual(TlsVersion.tls_1_3, config.min_version);
    try std.testing.expectEqual(TlsVersion.tls_1_3, config.max_version);
    try std.testing.expectEqual(@as(usize, 3), config.cipher_suites.len);
}

test "TLS config builder pattern" {
    const allocator = std.testing.allocator;
    
    const protocols = [_][]const u8{ "h2", "http/1.1" };
    const config = TlsConfig.init(allocator)
        .withServerName("example.com")
        .withALPN(@constCast(&protocols))
        .withInsecureSkipVerify(true);
    defer config.deinit();
    
    try std.testing.expectEqualStrings("example.com", config.server_name.?);
    try std.testing.expectEqual(true, config.insecure_skip_verify);
    try std.testing.expectEqual(@as(usize, 2), config.alpn_protocols.?.len);
}

test "TLS config validation" {
    const allocator = std.testing.allocator;
    
    // Valid config
    const valid_config = TlsConfig.init(allocator);
    defer valid_config.deinit();
    try valid_config.validate();
    
    // Invalid version range
    const invalid_config = TlsConfig.init(allocator)
        .withVersions(.tls_1_3, .tls_1_2);
    defer invalid_config.deinit();
    try std.testing.expectError(error.InvalidVersionRange, invalid_config.validate());
}

test "cipher suite properties" {
    try std.testing.expectEqual(@as(usize, 16), CipherSuite.TLS_AES_128_GCM_SHA256.keySize());
    try std.testing.expectEqual(@as(usize, 32), CipherSuite.TLS_AES_256_GCM_SHA384.keySize());
    try std.testing.expectEqual(HashAlgorithm.sha256, CipherSuite.TLS_AES_128_GCM_SHA256.hashAlgorithm());
}

test "TLS configuration memory ownership" {
    const allocator = std.testing.allocator;
    
    // Test reference-based configuration (no memory to free)
    {
        const server_name = "test.example.com";
        const config = TlsConfig.init(allocator)
            .withServerName(server_name);
        defer config.deinit();
        
        try std.testing.expectEqualStrings(server_name, config.server_name.?);
        try std.testing.expectEqual(false, config._owned.server_name);
    }
    
    // Test owned configuration (memory should be freed)
    {
        const server_name = "test.example.com";
        const config = try TlsConfig.init(allocator)
            .withServerNameOwned(server_name);
        defer config.deinit();
        
        try std.testing.expectEqualStrings(server_name, config.server_name.?);
        try std.testing.expectEqual(true, config._owned.server_name);
        // Memory will be freed by deinit()
    }
}

test "TLS configuration ALPN ownership" {
    const allocator = std.testing.allocator;
    
    // Test owned ALPN protocols
    const protocols = [_][]const u8{ "h2", "http/1.1" };
    const config = try TlsConfig.init(allocator)
        .withALPNOwned(@constCast(&protocols));
    defer config.deinit();
    
    try std.testing.expectEqual(@as(usize, 2), config.alpn_protocols.?.len);
    try std.testing.expectEqual(true, config._owned.alpn_protocols);
    try std.testing.expectEqualStrings("h2", config.alpn_protocols.?[0]);
    try std.testing.expectEqualStrings("http/1.1", config.alpn_protocols.?[1]);
}