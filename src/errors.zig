//! ZCrypto Error Handling
//!
//! Centralized error definitions and handling strategies for the ZCrypto library.
//! Provides consistent error types, error context, and error reporting across all modules.

const std = @import("std");

/// Core cryptographic errors
pub const CryptoError = error{
    /// Invalid key size for the algorithm
    InvalidKeySize,
    /// Invalid initialization vector size
    InvalidIvSize,
    /// Invalid nonce size
    InvalidNonceSize,
    /// Invalid tag size for authenticated encryption
    InvalidTagSize,
    /// Authentication verification failed
    AuthenticationFailed,
    /// Invalid padding in block cipher
    InvalidPadding,
    /// Unsupported algorithm or operation
    UnsupportedAlgorithm,
    /// Invalid signature format or verification failed
    InvalidSignature,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Random number generation failed
    RandomGenerationFailed,
};

/// TLS protocol errors
pub const TlsError = error{
    /// Invalid TLS version in handshake
    InvalidVersion,
    /// Unsupported cipher suite
    UnsupportedCipherSuite,
    /// Invalid handshake message
    InvalidHandshake,
    /// Handshake verification failed
    HandshakeVerificationFailed,
    /// Invalid record type
    InvalidRecordType,
    /// Record length exceeds maximum
    RecordTooLarge,
    /// Invalid record format
    InvalidRecordFormat,
    /// TLS alert received
    AlertReceived,
    /// Unexpected message in handshake sequence
    UnexpectedMessage,
    /// Certificate validation failed
    CertificateValidationFailed,
    /// Missing required extension
    MissingExtension,
    /// Invalid extension format
    InvalidExtension,
    /// Key schedule derivation failed
    KeyScheduleError,
    /// Session resumption failed
    SessionResumptionFailed,
};

/// X.509 certificate errors
pub const X509Error = error{
    /// Invalid DER encoding
    InvalidDerEncoding,
    /// Invalid ASN.1 tag
    InvalidTag,
    /// Invalid ASN.1 length encoding
    InvalidLength,
    /// Unexpected end of data
    UnexpectedEOF,
    /// Invalid certificate format
    InvalidCertificate,
    /// Certificate has expired
    CertificateExpired,
    /// Certificate not yet valid
    CertificateNotYetValid,
    /// Certificate signature verification failed
    InvalidCertificateSignature,
    /// Hostname does not match certificate
    HostnameMismatch,
    /// Certificate chain validation failed
    ChainValidationFailed,
    /// Unknown certificate extension
    UnknownExtension,
    /// Invalid public key format
    InvalidPublicKey,
    /// Unsupported signature algorithm
    UnsupportedSignatureAlgorithm,
};

/// Network and I/O errors
pub const NetworkError = error{
    /// Connection failed
    ConnectionFailed,
    /// Connection timeout
    ConnectionTimeout,
    /// Connection reset by peer
    ConnectionReset,
    /// Network unreachable
    NetworkUnreachable,
    /// Invalid address format
    InvalidAddress,
    /// Socket operation failed
    SocketError,
    /// DNS resolution failed
    DnsResolutionFailed,
    /// Protocol violation
    ProtocolViolation,
};

/// Configuration and validation errors
pub const ConfigError = error{
    /// Invalid configuration parameter
    InvalidConfiguration,
    /// Missing required configuration
    MissingConfiguration,
    /// Configuration validation failed
    ValidationFailed,
    /// Incompatible configuration options
    IncompatibleConfiguration,
    /// Invalid version range
    InvalidVersionRange,
    /// Missing certificate
    MissingCertificate,
    /// Missing private key
    MissingPrivateKey,
    /// No cipher suites configured
    NoCipherSuites,
    /// Certificate and key mismatch
    CertificateKeyMismatch,
};

/// Memory and resource errors
pub const ResourceError = error{
    /// Memory allocation failed
    OutOfMemory,
    /// Buffer too small
    BufferTooSmall,
    /// Resource limit exceeded
    ResourceLimitExceeded,
    /// Invalid buffer size
    InvalidBufferSize,
    /// Resource already in use
    ResourceInUse,
    /// Resource not available
    ResourceUnavailable,
};

/// All possible ZCrypto errors
pub const ZCryptoError = CryptoError || TlsError || X509Error || NetworkError || ConfigError || ResourceError;

/// Error context for debugging and logging
pub const ErrorContext = struct {
    /// Error code
    err: ZCryptoError,
    /// Module where error occurred
    module: []const u8,
    /// Function where error occurred
    function: []const u8,
    /// Additional context message
    message: ?[]const u8 = null,
    /// File and line information (optional)
    location: ?SourceLocation = null,
    
    /// Source location information
    pub const SourceLocation = struct {
        file: []const u8,
        line: u32,
        column: u32,
    };
    
    /// Create error context
    pub fn init(err: ZCryptoError, module: []const u8, function: []const u8) ErrorContext {
        return ErrorContext{
            .err = err,
            .module = module,
            .function = function,
        };
    }
    
    /// Create error context with message
    pub fn withMessage(err: ZCryptoError, module: []const u8, function: []const u8, message: []const u8) ErrorContext {
        return ErrorContext{
            .err = err,
            .module = module,
            .function = function,
            .message = message,
        };
    }
    
    /// Create error context with location
    pub fn withLocation(err: ZCryptoError, module: []const u8, function: []const u8, file: []const u8, line: u32, column: u32) ErrorContext {
        return ErrorContext{
            .err = err,
            .module = module,
            .function = function,
            .location = SourceLocation{
                .file = file,
                .line = line,
                .column = column,
            },
        };
    }
    
    /// Format error for logging
    pub fn format(self: ErrorContext, allocator: std.mem.Allocator) ![]u8 {
        var result = std.ArrayList(u8).init(allocator);
        const writer = result.writer();
        
        try writer.print("ZCrypto Error: {} in {s}:{s}", .{ self.err, self.module, self.function });
        
        if (self.message) |msg| {
            try writer.print(" - {s}", .{msg});
        }
        
        if (self.location) |loc| {
            try writer.print(" ({s}:{}:{})", .{ loc.file, loc.line, loc.column });
        }
        
        return result.toOwnedSlice();
    }
    
    /// Print error to stderr
    pub fn log(self: ErrorContext) void {
        const stderr = std.io.getStdErr().writer();
        stderr.print("ZCrypto Error: {} in {s}:{s}", .{ self.err, self.module, self.function }) catch {};
        
        if (self.message) |msg| {
            stderr.print(" - {s}", .{msg}) catch {};
        }
        
        if (self.location) |loc| {
            stderr.print(" ({s}:{}:{})", .{ loc.file, loc.line, loc.column }) catch {};
        }
        
        stderr.print("\n", .{}) catch {};
    }
};

/// Result type for operations that can fail with context
pub fn Result(comptime T: type) type {
    return union(enum) {
        ok: T,
        err: ErrorContext,
        
        /// Check if result is ok
        pub fn isOk(self: @This()) bool {
            return switch (self) {
                .ok => true,
                .err => false,
            };
        }
        
        /// Check if result is error
        pub fn isErr(self: @This()) bool {
            return !self.isOk();
        }
        
        /// Unwrap the ok value (panics on error)
        pub fn unwrap(self: @This()) T {
            return switch (self) {
                .ok => |value| value,
                .err => |ctx| {
                    ctx.log();
                    @panic("Unwrapped error result");
                },
            };
        }
        
        /// Unwrap the ok value or return default
        pub fn unwrapOr(self: @This(), default: T) T {
            return switch (self) {
                .ok => |value| value,
                .err => default,
            };
        }
        
        /// Get error context (panics if ok)
        pub fn unwrapErr(self: @This()) ErrorContext {
            return switch (self) {
                .ok => @panic("Unwrapped ok result as error"),
                .err => |ctx| ctx,
            };
        }
        
        /// Map ok value to another type
        pub fn map(self: @This(), comptime U: type, func: fn(T) U) Result(U) {
            return switch (self) {
                .ok => |value| Result(U){ .ok = func(value) },
                .err => |ctx| Result(U){ .err = ctx },
            };
        }
        
        /// Chain results (monadic bind)
        pub fn andThen(self: @This(), comptime U: type, func: fn(T) Result(U)) Result(U) {
            return switch (self) {
                .ok => |value| func(value),
                .err => |ctx| Result(U){ .err = ctx },
            };
        }
    };
}

/// Convenience macros for error handling
pub fn resultOk(value: anytype) Result(@TypeOf(value)) {
    return Result(@TypeOf(value)){ .ok = value };
}

pub fn resultErr(comptime T: type, err: ZCryptoError, module: []const u8, function: []const u8) Result(T) {
    return Result(T){ .err = ErrorContext.init(err, module, function) };
}

pub fn resultErrMsg(comptime T: type, err: ZCryptoError, module: []const u8, function: []const u8, message: []const u8) Result(T) {
    return Result(T){ .err = ErrorContext.withMessage(err, module, function, message) };
}

/// Convert standard Zig error to ZCrypto error context
pub fn convertError(err: anyerror, module: []const u8, function: []const u8) ErrorContext {
    const zcrypto_err: ZCryptoError = switch (err) {
        error.OutOfMemory => ResourceError.OutOfMemory,
        error.InvalidKeySize => CryptoError.InvalidKeySize,
        error.InvalidTag => X509Error.InvalidTag,
        error.InvalidLength => X509Error.InvalidLength,
        error.UnexpectedEOF => X509Error.UnexpectedEOF,
        error.InvalidEncoding => X509Error.InvalidDerEncoding,
        error.ConnectionRefused => NetworkError.ConnectionFailed,
        error.Timeout => NetworkError.ConnectionTimeout,
        else => @panic("Unhandled error type"),
    };
    
    return ErrorContext.init(zcrypto_err, module, function);
}

test "error context creation and formatting" {
    const allocator = std.testing.allocator;
    
    const ctx = ErrorContext.withMessage(
        CryptoError.InvalidKeySize,
        "sym",
        "encryptAes128Gcm",
        "Key must be 16 bytes for AES-128"
    );
    
    const formatted = try ctx.format(allocator);
    defer allocator.free(formatted);
    
    try std.testing.expect(std.mem.indexOf(u8, formatted, "InvalidKeySize") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "sym:encryptAes128Gcm") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "Key must be 16 bytes") != null);
}

test "result type operations" {
    // Test ok result
    const ok_result = resultOk(@as(u32, 42));
    try std.testing.expect(ok_result.isOk());
    try std.testing.expectEqual(@as(u32, 42), ok_result.unwrap());
    
    // Test error result
    const err_result = resultErr(u32, CryptoError.InvalidKeySize, "test", "function");
    try std.testing.expect(err_result.isErr());
    try std.testing.expectEqual(@as(u32, 0), err_result.unwrapOr(0));
    
    // Test map operation
    const mapped = ok_result.map(u64, struct {
        fn double(x: u32) u64 {
            return @as(u64, x) * 2;
        }
    }.double);
    try std.testing.expectEqual(@as(u64, 84), mapped.unwrap());
}

test "error conversion" {
    const ctx = convertError(error.OutOfMemory, "test", "function");
    try std.testing.expectEqual(ResourceError.OutOfMemory, ctx.err);
    try std.testing.expectEqualStrings("test", ctx.module);
    try std.testing.expectEqualStrings("function", ctx.function);
}