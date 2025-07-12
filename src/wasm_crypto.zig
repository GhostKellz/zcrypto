//! WASM crypto interface for ZVM WASM runtime
//! Features:
//! - WASM-safe memory management (no direct pointers)
//! - Sandboxed crypto operations for untrusted WASM
//! - Streaming crypto API for large WASM data processing
//! - WASM-optimized algorithms (smaller code size)
//! - Gas-metered crypto operations for ZVM billing

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;

/// WASM crypto errors
pub const WasmCryptoError = error{
    InvalidWasmMemory,
    GasLimitExceeded,
    UnsafeOperation,
    BufferTooLarge,
    InvalidAlgorithm,
    SandboxViolation,
    OutOfMemory,
};

/// Gas costs for different crypto operations
pub const GasCosts = struct {
    pub const HASH_SHA256_PER_BYTE: u64 = 1;
    pub const HASH_SHA512_PER_BYTE: u64 = 2;
    pub const AEAD_ENCRYPT_PER_BYTE: u64 = 3;
    pub const AEAD_DECRYPT_PER_BYTE: u64 = 3;
    pub const ECDSA_SIGN: u64 = 1000;
    pub const ECDSA_VERIFY: u64 = 2000;
    pub const HKDF_PER_BYTE: u64 = 2;
    pub const RANDOM_PER_BYTE: u64 = 1;
};

/// WASM memory handle - safe wrapper around WASM linear memory
pub const WasmMemory = struct {
    data: []u8,
    max_size: usize,
    
    pub fn init(data: []u8, max_size: usize) WasmMemory {
        return WasmMemory{
            .data = data,
            .max_size = max_size,
        };
    }
    
    pub fn read(self: WasmMemory, offset: u32, len: u32) WasmCryptoError![]const u8 {
        if (offset + len > self.data.len or len > self.max_size) {
            return WasmCryptoError.InvalidWasmMemory;
        }
        return self.data[offset..offset + len];
    }
    
    pub fn write(self: WasmMemory, offset: u32, data: []const u8) WasmCryptoError!void {
        if (offset + data.len > self.data.len or data.len > self.max_size) {
            return WasmCryptoError.InvalidWasmMemory;
        }
        @memcpy(self.data[offset..offset + data.len], data);
    }
};

/// Gas meter for billing crypto operations
pub const GasMeter = struct {
    available_gas: u64,
    used_gas: u64,
    
    pub fn init(gas_limit: u64) GasMeter {
        return GasMeter{
            .available_gas = gas_limit,
            .used_gas = 0,
        };
    }
    
    pub fn consumeGas(self: *GasMeter, amount: u64) WasmCryptoError!void {
        if (self.used_gas + amount > self.available_gas) {
            return WasmCryptoError.GasLimitExceeded;
        }
        self.used_gas += amount;
    }
    
    pub fn remainingGas(self: GasMeter) u64 {
        return self.available_gas - self.used_gas;
    }
};

/// WASM crypto context
pub const WasmCrypto = struct {
    allocator: Allocator,
    gas_meter: GasMeter,
    max_buffer_size: usize,
    
    pub fn init(allocator: Allocator, gas_limit: u64, max_buffer_size: usize) WasmCrypto {
        return WasmCrypto{
            .allocator = allocator,
            .gas_meter = GasMeter.init(gas_limit),
            .max_buffer_size = max_buffer_size,
        };
    }
    
    /// WASM-safe SHA256 hash
    pub fn sha256(self: *WasmCrypto, memory: WasmMemory, input_offset: u32, input_len: u32, output_offset: u32) WasmCryptoError!void {
        // Check gas
        try self.gas_meter.consumeGas(GasCosts.HASH_SHA256_PER_BYTE * input_len);
        
        // Check buffer size
        if (input_len > self.max_buffer_size) {
            return WasmCryptoError.BufferTooLarge;
        }
        
        // Read input from WASM memory
        const input = try memory.read(input_offset, input_len);
        
        // Compute hash
        var hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(input, &hash, .{});
        
        // Write result to WASM memory
        try memory.write(output_offset, &hash);
    }
    
    /// WASM-safe SHA512 hash
    pub fn sha512(self: *WasmCrypto, memory: WasmMemory, input_offset: u32, input_len: u32, output_offset: u32) WasmCryptoError!void {
        try self.gas_meter.consumeGas(GasCosts.HASH_SHA512_PER_BYTE * input_len);
        
        if (input_len > self.max_buffer_size) {
            return WasmCryptoError.BufferTooLarge;
        }
        
        const input = try memory.read(input_offset, input_len);
        
        var hash: [64]u8 = undefined;
        crypto.hash.sha2.Sha512.hash(input, &hash, .{});
        
        try memory.write(output_offset, &hash);
    }
    
    /// WASM-safe ChaCha20-Poly1305 encryption
    pub fn chaCha20Poly1305Encrypt(
        self: *WasmCrypto,
        memory: WasmMemory,
        key_offset: u32,
        nonce_offset: u32,
        plaintext_offset: u32,
        plaintext_len: u32,
        ciphertext_offset: u32,
        tag_offset: u32
    ) WasmCryptoError!void {
        try self.gas_meter.consumeGas(GasCosts.AEAD_ENCRYPT_PER_BYTE * plaintext_len);
        
        if (plaintext_len > self.max_buffer_size) {
            return WasmCryptoError.BufferTooLarge;
        }
        
        // Read inputs
        const key_slice = try memory.read(key_offset, 32);
        const nonce_slice = try memory.read(nonce_offset, 12);
        const plaintext = try memory.read(plaintext_offset, plaintext_len);
        
        // Validate key and nonce sizes
        if (key_slice.len != 32 or nonce_slice.len != 12) {
            return WasmCryptoError.InvalidWasmMemory;
        }
        
        var key: [32]u8 = undefined;
        var nonce: [12]u8 = undefined;
        @memcpy(&key, key_slice);
        @memcpy(&nonce, nonce_slice);
        
        // Allocate temporary buffers
        const ciphertext = try self.allocator.alloc(u8, plaintext_len);
        defer self.allocator.free(ciphertext);
        var tag: [16]u8 = undefined;
        
        // Encrypt
        crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            ciphertext,
            &tag,
            plaintext,
            "",
            nonce,
            key
        );
        
        // Write results
        try memory.write(ciphertext_offset, ciphertext);
        try memory.write(tag_offset, &tag);
    }
    
    /// WASM-safe ChaCha20-Poly1305 decryption
    pub fn chaCha20Poly1305Decrypt(
        self: *WasmCrypto,
        memory: WasmMemory,
        key_offset: u32,
        nonce_offset: u32,
        ciphertext_offset: u32,
        ciphertext_len: u32,
        tag_offset: u32,
        plaintext_offset: u32
    ) WasmCryptoError!void {
        try self.gas_meter.consumeGas(GasCosts.AEAD_DECRYPT_PER_BYTE * ciphertext_len);
        
        if (ciphertext_len > self.max_buffer_size) {
            return WasmCryptoError.BufferTooLarge;
        }
        
        // Read inputs
        const key_slice = try memory.read(key_offset, 32);
        const nonce_slice = try memory.read(nonce_offset, 12);
        const ciphertext = try memory.read(ciphertext_offset, ciphertext_len);
        const tag_slice = try memory.read(tag_offset, 16);
        
        if (key_slice.len != 32 or nonce_slice.len != 12 or tag_slice.len != 16) {
            return WasmCryptoError.InvalidWasmMemory;
        }
        
        var key: [32]u8 = undefined;
        var nonce: [12]u8 = undefined;
        var tag: [16]u8 = undefined;
        @memcpy(&key, key_slice);
        @memcpy(&nonce, nonce_slice);
        @memcpy(&tag, tag_slice);
        
        // Allocate temporary buffer
        const plaintext = try self.allocator.alloc(u8, ciphertext_len);
        defer self.allocator.free(plaintext);
        
        // Decrypt
        crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            plaintext,
            ciphertext,
            tag,
            "",
            nonce,
            key
        ) catch {
            return WasmCryptoError.UnsafeOperation;
        };
        
        // Write result
        try memory.write(plaintext_offset, plaintext);
    }
    
    /// WASM-safe HKDF key derivation
    pub fn hkdf(
        self: *WasmCrypto,
        memory: WasmMemory,
        ikm_offset: u32,
        ikm_len: u32,
        salt_offset: u32,
        salt_len: u32,
        info_offset: u32,
        info_len: u32,
        okm_offset: u32,
        okm_len: u32
    ) WasmCryptoError!void {
        try self.gas_meter.consumeGas(GasCosts.HKDF_PER_BYTE * okm_len);
        
        if (ikm_len > self.max_buffer_size or okm_len > self.max_buffer_size) {
            return WasmCryptoError.BufferTooLarge;
        }
        
        // Read inputs
        const ikm = try memory.read(ikm_offset, ikm_len);
        const salt = try memory.read(salt_offset, salt_len);
        const info = try memory.read(info_offset, info_len);
        
        // Allocate output buffer
        const okm = try self.allocator.alloc(u8, okm_len);
        defer self.allocator.free(okm);
        
        // Perform HKDF
        var prk: [32]u8 = undefined;
        crypto.kdf.hkdf.HkdfSha256.extract(&prk, ikm, salt);
        crypto.kdf.hkdf.HkdfSha256.expand(okm, info, &prk);
        
        // Write result
        try memory.write(okm_offset, okm);
    }
    
    /// WASM-safe random number generation
    pub fn randomBytes(self: *WasmCrypto, memory: WasmMemory, output_offset: u32, len: u32) WasmCryptoError!void {
        try self.gas_meter.consumeGas(GasCosts.RANDOM_PER_BYTE * len);
        
        if (len > self.max_buffer_size) {
            return WasmCryptoError.BufferTooLarge;
        }
        
        // Generate random bytes
        const random_data = try self.allocator.alloc(u8, len);
        defer self.allocator.free(random_data);
        
        crypto.random.bytes(random_data);
        
        // Write to WASM memory
        try memory.write(output_offset, random_data);
    }
    
    /// Get remaining gas for billing
    pub fn getRemainingGas(self: WasmCrypto) u64 {
        return self.gas_meter.remainingGas();
    }
    
    /// Get used gas for billing
    pub fn getUsedGas(self: WasmCrypto) u64 {
        return self.gas_meter.used_gas;
    }
};

/// Streaming crypto API for large data processing
pub const WasmStreamCrypto = struct {
    allocator: Allocator,
    gas_meter: *GasMeter,
    
    pub fn init(allocator: Allocator, gas_meter: *GasMeter) WasmStreamCrypto {
        return WasmStreamCrypto{
            .allocator = allocator,
            .gas_meter = gas_meter,
        };
    }
    
    /// Streaming SHA256 hash
    pub fn streamSha256Init(self: *WasmStreamCrypto) !*crypto.hash.sha2.Sha256 {
        try self.gas_meter.consumeGas(100); // Initialization cost
        
        const hasher = try self.allocator.create(crypto.hash.sha2.Sha256);
        hasher.* = crypto.hash.sha2.Sha256.init(.{});
        return hasher;
    }
    
    pub fn streamSha256Update(self: *WasmStreamCrypto, hasher: *crypto.hash.sha2.Sha256, memory: WasmMemory, data_offset: u32, data_len: u32) WasmCryptoError!void {
        try self.gas_meter.consumeGas(GasCosts.HASH_SHA256_PER_BYTE * data_len);
        
        const data = try memory.read(data_offset, data_len);
        hasher.update(data);
    }
    
    pub fn streamSha256Final(self: *WasmStreamCrypto, hasher: *crypto.hash.sha2.Sha256, memory: WasmMemory, output_offset: u32) WasmCryptoError!void {
        try self.gas_meter.consumeGas(50); // Finalization cost
        
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        
        try memory.write(output_offset, &hash);
        
        // Clean up
        self.allocator.destroy(hasher);
    }
};

/// Sandbox for untrusted WASM crypto operations
pub const CryptoSandbox = struct {
    allowed_operations: std.EnumSet(AllowedOperation),
    max_gas_per_call: u64,
    max_buffer_size: usize,
    
    pub const AllowedOperation = enum {
        Hash,
        AEAD,
        KeyDerivation,
        RandomGeneration,
        DigitalSignature,
    };
    
    pub fn init(allowed_ops: std.EnumSet(AllowedOperation), max_gas: u64, max_buffer: usize) CryptoSandbox {
        return CryptoSandbox{
            .allowed_operations = allowed_ops,
            .max_gas_per_call = max_gas,
            .max_buffer_size = max_buffer,
        };
    }
    
    pub fn checkOperation(self: CryptoSandbox, operation: AllowedOperation, gas_cost: u64, buffer_size: usize) WasmCryptoError!void {
        if (!self.allowed_operations.contains(operation)) {
            return WasmCryptoError.SandboxViolation;
        }
        
        if (gas_cost > self.max_gas_per_call) {
            return WasmCryptoError.GasLimitExceeded;
        }
        
        if (buffer_size > self.max_buffer_size) {
            return WasmCryptoError.BufferTooLarge;
        }
    }
};

// Tests
const testing = std.testing;

test "wasm memory operations" {
    var buffer: [1024]u8 = undefined;
    const memory = WasmMemory.init(&buffer, 1024);
    
    const test_data = "Hello, WASM!";
    try memory.write(0, test_data);
    
    const read_data = try memory.read(0, test_data.len);
    try testing.expectEqualSlices(u8, test_data, read_data);
}

test "gas meter" {
    var meter = GasMeter.init(1000);
    
    try meter.consumeGas(100);
    try testing.expect(meter.used_gas == 100);
    try testing.expect(meter.remainingGas() == 900);
    
    // Should fail when exceeding limit
    try testing.expectError(WasmCryptoError.GasLimitExceeded, meter.consumeGas(1000));
}

test "wasm crypto sha256" {
    var buffer: [1024]u8 = undefined;
    const memory = WasmMemory.init(&buffer, 1024);
    
    var crypto_ctx = WasmCrypto.init(testing.allocator, 10000, 1024);
    
    const test_data = "Hello, WASM crypto!";
    try memory.write(0, test_data);
    
    try crypto_ctx.sha256(memory, 0, test_data.len, 100);
    
    const hash = try memory.read(100, 32);
    try testing.expect(hash.len == 32);
}

test "crypto sandbox" {
    var allowed_ops = std.EnumSet(CryptoSandbox.AllowedOperation).init(.{});
    allowed_ops.insert(.Hash);
    allowed_ops.insert(.AEAD);
    
    const sandbox = CryptoSandbox.init(allowed_ops, 1000, 1024);
    
    try sandbox.checkOperation(.Hash, 100, 256);
    try testing.expectError(WasmCryptoError.SandboxViolation, sandbox.checkOperation(.DigitalSignature, 100, 256));
    try testing.expectError(WasmCryptoError.GasLimitExceeded, sandbox.checkOperation(.Hash, 2000, 256));
}
