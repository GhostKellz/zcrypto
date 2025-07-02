# 🔌 ZCRYPTO v0.5.0 API REFERENCE

**Complete API Documentation for Post-Quantum Cryptographic Library**

---

## 📋 **TABLE OF CONTENTS**

1. [Quick Start](#quick-start)
2. [Core Cryptographic Primitives](#core-cryptographic-primitives)
3. [Post-Quantum Algorithms](#post-quantum-algorithms)
4. [QUIC Cryptography](#quic-cryptography)
5. [TLS Integration](#tls-integration)
6. [Foreign Function Interface](#foreign-function-interface)
7. [Usage Examples](#usage-examples)
8. [Error Handling](#error-handling)
9. [Integration Patterns](#integration-patterns)

---

## 🚀 **QUICK START**

### **Installation & Build**

```bash
# Add zcrypto as a dependency
zig fetch --save git+https://github.com/your-org/zcrypto.git

# Or include directly in build.zig
const zcrypto = b.dependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zcrypto", zcrypto.module("zcrypto"));
```

### **Basic Usage**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    // Hash some data
    const message = "Hello, zcrypto!";
    const hash = zcrypto.hash.sha256(message);
    
    // Generate Ed25519 key pair
    const keypair = zcrypto.asym.ed25519.generate();
    
    // Sign a message
    const signature = try keypair.sign(message);
    const is_valid = keypair.verify(message, signature);
    
    std.debug.print("Message: {s}\n", .{message});
    std.debug.print("Signature valid: {}\n", .{is_valid});
}
```

---

## 🔑 **CORE CRYPTOGRAPHIC PRIMITIVES**

### **Hash Functions**

#### `zcrypto.hash`

```zig
pub const hash = struct {
    /// SHA-256 hash function (32 bytes output)
    pub fn sha256(input: []const u8) [32]u8;
    
    /// BLAKE2b hash function (64 bytes output)
    pub fn blake2b(input: []const u8) [64]u8;
    
    /// Convert hash to hex string
    pub fn toHex(comptime T: type, hash_bytes: T, buffer: []u8) []u8;
};
```

**Example:**
```zig
const data = "Sign this data";
const digest = zcrypto.hash.sha256(data);

// Convert to hex for display
var hex_buf: [64]u8 = undefined;
const hex = zcrypto.hash.toHex([32]u8, digest, &hex_buf);
std.debug.print("SHA-256: {s}\n", .{hex});
```

### **Asymmetric Cryptography**

#### `zcrypto.asym.ed25519`

```zig
pub const ed25519 = struct {
    pub const KeyPair = struct {
        public_key: [32]u8,
        private_key: [64]u8,
        
        /// Generate new Ed25519 key pair
        pub fn generate() KeyPair;
        
        /// Sign a message
        pub fn sign(self: KeyPair, message: []const u8) ![64]u8;
        
        /// Verify signature
        pub fn verify(self: KeyPair, message: []const u8, signature: [64]u8) bool;
    };
};
```

**Example:**
```zig
// Generate keys for your signing service
const signing_keys = zcrypto.asym.ed25519.generate();

// Sign transaction data
const tx_data = "transfer 100 tokens to alice";
const signature = try signing_keys.sign(tx_data);

// Verify signature
const is_valid = signing_keys.verify(tx_data, signature);
std.debug.print("Transaction signature valid: {}\n", .{is_valid});
```

### **Symmetric Cryptography**

#### `zcrypto.sym`

```zig
pub const sym = struct {
    pub const EncryptedData = struct {
        data: []u8,
        tag: [16]u8,
        
        pub fn deinit(self: EncryptedData) void;
    };
    
    /// AES-128-GCM encryption
    pub fn encryptAes128Gcm(
        allocator: std.mem.Allocator,
        key: [16]u8,
        nonce: [12]u8,
        plaintext: []const u8,
        aad: []const u8
    ) !EncryptedData;
    
    /// AES-128-GCM decryption
    pub fn decryptAes128Gcm(
        allocator: std.mem.Allocator,
        key: [16]u8,
        nonce: [12]u8,
        ciphertext: []const u8,
        tag: [16]u8,
        aad: []const u8
    ) !?[]u8;
};
```

**Example:**
```zig
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
defer _ = gpa.deinit();
const allocator = gpa.allocator();

// Encrypt sensitive data
const key = zcrypto.rand.randomArray(16);
const nonce = zcrypto.rand.randomArray(12);
const secret_message = "API key: sk_1234567890";

const encrypted = try zcrypto.sym.encryptAes128Gcm(
    allocator, key, nonce, secret_message, "metadata"
);
defer encrypted.deinit();

// Decrypt later
const decrypted = try zcrypto.sym.decryptAes128Gcm(
    allocator, key, nonce, encrypted.data, encrypted.tag, "metadata"
);
defer if (decrypted) |d| allocator.free(d);
```

### **Key Derivation**

#### `zcrypto.kdf`

```zig
pub const kdf = struct {
    /// Derive key using HKDF
    pub fn deriveKey(
        allocator: std.mem.Allocator,
        input_key_material: []const u8,
        info: []const u8,
        length: usize
    ) ![]u8;
};
```

**Example:**
```zig
// Derive application-specific keys
const master_secret = "shared-master-secret";
const api_key = try zcrypto.kdf.deriveKey(
    allocator, master_secret, "api-encryption", 32
);
defer allocator.free(api_key);

const db_key = try zcrypto.kdf.deriveKey(
    allocator, master_secret, "database-encryption", 32
);
defer allocator.free(db_key);
```

### **Random Generation**

#### `zcrypto.rand`

```zig
pub const rand = struct {
    /// Generate random array of specified size
    pub fn randomArray(comptime size: usize) [size]u8;
    
    /// Generate random bytes
    pub fn randomBytes(allocator: std.mem.Allocator, size: usize) ![]u8;
};
```

---

## 🌌 **POST-QUANTUM ALGORITHMS**

### **ML-KEM (Key Encapsulation)**

#### `zcrypto.pq.ml_kem.ML_KEM_768`

```zig
pub const ML_KEM_768 = struct {
    pub const PUBLIC_KEY_SIZE = 1184;
    pub const PRIVATE_KEY_SIZE = 2400;
    pub const CIPHERTEXT_SIZE = 1088;
    pub const SHARED_SECRET_SIZE = 32;
    
    pub const KeyPair = struct {
        public_key: [PUBLIC_KEY_SIZE]u8,
        private_key: [PRIVATE_KEY_SIZE]u8,
        
        /// Generate ML-KEM-768 key pair
        pub fn generate(seed: [32]u8) !KeyPair;
        
        /// Generate with random seed
        pub fn generateRandom() !KeyPair;
        
        /// Encapsulate shared secret
        pub fn encapsulate(
            public_key: [PUBLIC_KEY_SIZE]u8,
            randomness: [32]u8
        ) !struct {
            ciphertext: [CIPHERTEXT_SIZE]u8,
            shared_secret: [SHARED_SECRET_SIZE]u8,
        };
        
        /// Decapsulate shared secret
        pub fn decapsulate(
            self: *const KeyPair,
            ciphertext: [CIPHERTEXT_SIZE]u8
        ) ![SHARED_SECRET_SIZE]u8;
    };
};
```

**Example:**
```zig
// Generate post-quantum key pair for secure communication
const pq_keys = try zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.generateRandom();

// Client: encapsulate shared secret
var randomness: [32]u8 = undefined;
std.crypto.random.bytes(&randomness);

const encaps_result = try zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(
    pq_keys.public_key, randomness
);

// Server: decapsulate shared secret
const shared_secret = try pq_keys.decapsulate(encaps_result.ciphertext);

// Both sides now have the same shared secret
std.debug.print("Shared secret established: {} bytes\n", .{shared_secret.len});
```

### **ML-DSA (Digital Signatures)**

#### `zcrypto.pq.ml_dsa.ML_DSA_65`

```zig
pub const ML_DSA_65 = struct {
    pub const PUBLIC_KEY_SIZE = 1952;
    pub const PRIVATE_KEY_SIZE = 4016;
    pub const SIGNATURE_SIZE = 3309;
    
    pub const KeyPair = struct {
        public_key: [PUBLIC_KEY_SIZE]u8,
        private_key: [PRIVATE_KEY_SIZE]u8,
        
        /// Generate ML-DSA-65 key pair
        pub fn generate(seed: [32]u8) !KeyPair;
        
        /// Generate with random seed
        pub fn generateRandom(allocator: std.mem.Allocator) !KeyPair;
        
        /// Sign message
        pub fn sign(
            self: *const KeyPair,
            message: []const u8,
            randomness: [32]u8
        ) ![SIGNATURE_SIZE]u8;
        
        /// Verify signature (static method)
        pub fn verify(
            public_key: [PUBLIC_KEY_SIZE]u8,
            message: []const u8,
            signature: [SIGNATURE_SIZE]u8
        ) !bool;
    };
};
```

**Example:**
```zig
// Generate post-quantum signing keys
const pq_signer = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.generateRandom(allocator);

// Sign important document
const document = "Certificate of Authenticity: Quantum-Safe Document v1.0";
var signing_randomness: [32]u8 = undefined;
std.crypto.random.bytes(&signing_randomness);

const pq_signature = try pq_signer.sign(document, signing_randomness);

// Verify signature
const is_valid = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.verify(
    pq_signer.public_key, document, pq_signature
);
std.debug.print("Post-quantum signature valid: {}\n", .{is_valid});
```

### **Hybrid Cryptography**

#### `zcrypto.pq.hybrid.X25519_ML_KEM_768`

```zig
pub const X25519_ML_KEM_768 = struct {
    pub const HybridKeyPair = struct {
        classical_public: [32]u8,
        classical_private: [32]u8,
        pq_public: [1184]u8,
        pq_private: [2400]u8,
        
        /// Generate hybrid key pair
        pub fn generate() !HybridKeyPair;
        
        /// Perform hybrid key exchange
        pub fn exchange(
            self: *const HybridKeyPair,
            peer_classical: [32]u8,
            peer_pq_ciphertext: [1088]u8
        ) ![64]u8; // Combined 64-byte shared secret
    };
};
```

**Example:**
```zig
// Generate hybrid keys for maximum security
const alice_keys = try zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate();
const bob_keys = try zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate();

// Alice: create key exchange material for Bob
var randomness: [32]u8 = undefined;
std.crypto.random.bytes(&randomness);

const encaps_result = try zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(
    bob_keys.pq_public, randomness
);

// Bob: perform hybrid key exchange
const shared_secret = try bob_keys.exchange(
    alice_keys.classical_public,
    encaps_result.ciphertext
);

std.debug.print("Hybrid shared secret: {} bytes\n", .{shared_secret.len});
```

---

## 🌐 **QUIC CRYPTOGRAPHY**

### **QuicCrypto**

#### `zcrypto.quic.QuicCrypto`

```zig
pub const QuicCrypto = struct {
    /// Initialize QUIC crypto context
    pub fn init(cipher_suite: CipherSuite) QuicCrypto;
    
    /// Derive initial keys from connection ID
    pub fn deriveInitialKeys(
        self: *QuicCrypto,
        connection_id: []const u8
    ) QuicError!void;
    
    /// Encrypt QUIC packet
    pub fn encryptPacket(
        self: *const QuicCrypto,
        level: EncryptionLevel,
        is_server: bool,
        packet_number: u64,
        header: []const u8,
        payload: []const u8,
        output: []u8
    ) QuicError!usize;
    
    /// Decrypt QUIC packet
    pub fn decryptPacket(
        self: *const QuicCrypto,
        level: EncryptionLevel,
        is_server: bool,
        packet_number: u64,
        header: []const u8,
        ciphertext: []const u8,
        output: []u8
    ) QuicError!usize;
};

pub const CipherSuite = enum {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ML_KEM_768_X25519_AES256_GCM_SHA384,  // Post-quantum hybrid
};

pub const EncryptionLevel = enum {
    initial,
    early_data,    // 0-RTT
    handshake,
    application,   // 1-RTT
};
```

**Example:**
```zig
// Initialize QUIC crypto for your networking service
var quic_crypto = zcrypto.quic.QuicCrypto.init(.TLS_AES_256_GCM_SHA384);

// Derive initial keys
const connection_id = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
try quic_crypto.deriveInitialKeys(&connection_id);

// Encrypt packet
const header = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 };
const payload = "QUIC handshake data";
var encrypted_packet: [1500]u8 = undefined;

const encrypted_len = try quic_crypto.encryptPacket(
    .initial,
    false, // client-side
    1,     // packet number
    &header,
    payload,
    &encrypted_packet
);

std.debug.print("Encrypted QUIC packet: {} bytes\n", .{encrypted_len});
```

### **Zero-Copy Operations**

#### `zcrypto.quic.ZeroCopy`

```zig
pub const ZeroCopy = struct {
    /// In-place packet encryption for high performance
    pub fn encryptInPlace(
        crypto: *const QuicCrypto,
        level: EncryptionLevel,
        is_server: bool,
        packet_number: u64,
        packet: []u8,
        header_len: usize
    ) QuicError!void;
    
    /// In-place packet decryption
    pub fn decryptInPlace(
        crypto: *const QuicCrypto,
        level: EncryptionLevel,
        is_server: bool,
        packet_number: u64,
        packet: []u8,
        header_len: usize
    ) QuicError!usize;
};
```

**Example:**
```zig
// High-performance packet processing
var packet = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 } ++ "Data payload".*;
const header_len = 5;
const packet_number = 42;

// Encrypt in-place (zero-copy)
try zcrypto.quic.ZeroCopy.encryptInPlace(
    &quic_crypto, .application, false, packet_number, &packet, header_len
);

// Later: decrypt in-place
const payload_len = try zcrypto.quic.ZeroCopy.decryptInPlace(
    &quic_crypto, .application, false, packet_number, &packet, header_len
);

std.debug.print("Decrypted payload: {} bytes\n", .{payload_len});
```

---

## 🔗 **TLS INTEGRATION**

### **TLS Configuration**

#### `zcrypto.tls.config.TlsConfig`

```zig
pub const TlsConfig = struct {
    server_name: ?[]const u8,
    alpn_protocols: ?[][]const u8,
    insecure_skip_verify: bool,
    
    /// Initialize TLS configuration
    pub fn init(allocator: std.mem.Allocator) TlsConfig;
    
    /// Set server name for SNI
    pub fn withServerName(self: TlsConfig, name: []const u8) TlsConfig;
    
    /// Set ALPN protocols
    pub fn withALPN(self: TlsConfig, protocols: [][]const u8) TlsConfig;
    
    /// Skip certificate verification (insecure)
    pub fn withInsecureSkipVerify(self: TlsConfig, skip: bool) TlsConfig;
    
    /// Validate configuration
    pub fn validate(self: *const TlsConfig) !void;
    
    /// Cleanup
    pub fn deinit(self: TlsConfig) void;
};
```

**Example:**
```zig
// Configure TLS for your service
const alpn_protocols = [_][]const u8{ "h2", "http/1.1" };
const tls_config = zcrypto.tls.config.TlsConfig.init(allocator)
    .withServerName("api.myservice.com")
    .withALPN(@constCast(&alpn_protocols))
    .withInsecureSkipVerify(false);
defer tls_config.deinit();

try tls_config.validate();
std.debug.print("TLS configured for: {s}\n", .{tls_config.server_name.?});
```

### **Key Schedule**

#### `zcrypto.tls.KeySchedule`

```zig
pub const KeySchedule = struct {
    /// Initialize TLS 1.3 key schedule
    pub fn init(allocator: std.mem.Allocator, hash_algorithm: HashAlgorithm) !KeySchedule;
    
    /// Derive early secret
    pub fn deriveEarlySecret(self: *KeySchedule, psk: ?[]const u8) !void;
    
    /// Derive handshake secret
    pub fn deriveHandshakeSecret(self: *KeySchedule, ecdhe_secret: []const u8) !void;
    
    /// Derive master secret
    pub fn deriveMasterSecret(self: *KeySchedule) !void;
    
    /// Cleanup
    pub fn deinit(self: *KeySchedule) void;
};

pub const HashAlgorithm = enum { sha256, sha384 };
```

**Example:**
```zig
// TLS 1.3 key schedule for your secure protocol
var key_schedule = try zcrypto.tls.KeySchedule.init(allocator, .sha256);
defer key_schedule.deinit();

// Derive secrets step by step
try key_schedule.deriveEarlySecret(null);

const ecdhe_secret = [_]u8{0x42} ** 32; // From X25519/ML-KEM
try key_schedule.deriveHandshakeSecret(&ecdhe_secret);
try key_schedule.deriveMasterSecret();

std.debug.print("TLS 1.3 key schedule completed\n");
```

---

## 🔗 **FOREIGN FUNCTION INTERFACE**

### **C API Exports**

The library provides a complete C API for integration with other languages:

```c
// Basic types
typedef struct {
    bool success;
    uint32_t data_len;
    uint32_t error_code;
} CryptoResult;

// Hash functions
CryptoResult zcrypto_sha256(const uint8_t* input, uint32_t input_len, uint8_t* output);
CryptoResult zcrypto_blake2b(const uint8_t* input, uint32_t input_len, uint8_t* output);

// Ed25519 operations
CryptoResult zcrypto_ed25519_keygen(uint8_t* public_key, uint8_t* private_key);
CryptoResult zcrypto_ed25519_sign(
    const uint8_t* message, uint32_t message_len,
    const uint8_t* private_key,
    uint8_t* signature
);
CryptoResult zcrypto_ed25519_verify(
    const uint8_t* message, uint32_t message_len,
    const uint8_t* signature,
    const uint8_t* public_key
);

// Post-quantum operations
CryptoResult zcrypto_ml_kem_768_keygen(uint8_t* public_key, uint8_t* secret_key);
CryptoResult zcrypto_ml_kem_768_encaps(
    const uint8_t* public_key,
    uint8_t* ciphertext,
    uint8_t* shared_secret
);
CryptoResult zcrypto_ml_kem_768_decaps(
    const uint8_t* secret_key,
    const uint8_t* ciphertext,
    uint8_t* shared_secret
);

// Hybrid operations
CryptoResult zcrypto_hybrid_x25519_ml_kem_keygen(
    uint8_t* classical_public,
    uint8_t* classical_private,
    uint8_t* pq_public,
    uint8_t* pq_private
);

// QUIC operations
CryptoResult zcrypto_quic_encrypt_packet_inplace(
    const uint8_t* context,
    uint32_t level,
    bool is_server,
    uint64_t packet_number,
    uint8_t* packet,
    uint32_t packet_len,
    uint32_t header_len
);

// Utility functions
CryptoResult zcrypto_version(uint8_t* buffer, uint32_t buffer_len);
CryptoResult zcrypto_has_post_quantum(void);
CryptoResult zcrypto_get_features(uint32_t* features);
```

---

## 📝 **USAGE EXAMPLES**

### **Example 1: Digital Signature Service**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub const SignatureService = struct {
    classical_keys: zcrypto.asym.ed25519.KeyPair,
    pq_keys: zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) !SignatureService {
        const classical_keys = zcrypto.asym.ed25519.generate();
        const pq_keys = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.generateRandom(allocator);
        
        return SignatureService{
            .classical_keys = classical_keys,
            .pq_keys = pq_keys,
            .allocator = allocator,
        };
    }
    
    pub fn signDocument(self: *const SignatureService, document: []const u8) !struct {
        classical: [64]u8,
        post_quantum: [3309]u8,
    } {
        // Create classical signature
        const classical_sig = try self.classical_keys.sign(document);
        
        // Create post-quantum signature
        var randomness: [32]u8 = undefined;
        std.crypto.random.bytes(&randomness);
        const pq_sig = try self.pq_keys.sign(document, randomness);
        
        return .{
            .classical = classical_sig,
            .post_quantum = pq_sig,
        };
    }
    
    pub fn verifyDocument(
        classical_public: [32]u8,
        pq_public: [1952]u8,
        document: []const u8,
        signatures: anytype,
    ) !bool {
        // Verify classical signature
        const classical_keypair = zcrypto.asym.ed25519.KeyPair{
            .public_key = classical_public,
            .private_key = undefined, // Not needed for verification
        };
        
        if (!classical_keypair.verify(document, signatures.classical)) {
            return false;
        }
        
        // Verify post-quantum signature
        const pq_valid = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.verify(
            pq_public, document, signatures.post_quantum
        );
        
        return pq_valid;
    }
};
```

### **Example 2: Secure Communication Channel**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub const SecureChannel = struct {
    hybrid_keys: zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair,
    shared_secret: ?[64]u8,
    
    pub fn init() !SecureChannel {
        return SecureChannel{
            .hybrid_keys = try zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate(),
            .shared_secret = null,
        };
    }
    
    pub fn getPublicKeys(self: *const SecureChannel) struct {
        classical: [32]u8,
        post_quantum: [1184]u8,
    } {
        return .{
            .classical = self.hybrid_keys.classical_public,
            .post_quantum = self.hybrid_keys.pq_public,
        };
    }
    
    pub fn establishSharedSecret(
        self: *SecureChannel,
        peer_classical: [32]u8,
        peer_pq_ciphertext: [1088]u8,
    ) !void {
        self.shared_secret = try self.hybrid_keys.exchange(
            peer_classical, peer_pq_ciphertext
        );
    }
    
    pub fn encryptMessage(
        self: *const SecureChannel,
        allocator: std.mem.Allocator,
        message: []const u8,
    ) !zcrypto.sym.EncryptedData {
        if (self.shared_secret == null) {
            return error.NoSharedSecret;
        }
        
        // Derive symmetric key from shared secret
        const key = self.shared_secret.?[0..16].*;
        const nonce = self.shared_secret.?[16..28].*;
        
        return try zcrypto.sym.encryptAes128Gcm(
            allocator, key, nonce, message, "secure_channel"
        );
    }
    
    pub fn decryptMessage(
        self: *const SecureChannel,
        allocator: std.mem.Allocator,
        encrypted: zcrypto.sym.EncryptedData,
    ) !?[]u8 {
        if (self.shared_secret == null) {
            return error.NoSharedSecret;
        }
        
        const key = self.shared_secret.?[0..16].*;
        const nonce = self.shared_secret.?[16..28].*;
        
        return try zcrypto.sym.decryptAes128Gcm(
            allocator, key, nonce, encrypted.data, encrypted.tag, "secure_channel"
        );
    }
};
```

### **Example 3: QUIC Server Integration**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub const QuicServer = struct {
    crypto: zcrypto.quic.QuicCrypto,
    connections: std.HashMap(u64, ConnectionState),
    allocator: std.mem.Allocator,
    
    const ConnectionState = struct {
        id: [8]u8,
        keys_derived: bool,
    };
    
    pub fn init(allocator: std.mem.Allocator) QuicServer {
        return QuicServer{
            .crypto = zcrypto.quic.QuicCrypto.init(.TLS_ML_KEM_768_X25519_AES256_GCM_SHA384),
            .connections = std.HashMap(u64, ConnectionState).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn handleNewConnection(self: *QuicServer, connection_id: [8]u8) !void {
        // Derive initial keys for this connection
        try self.crypto.deriveInitialKeys(&connection_id);
        
        const conn_hash = std.hash.Wyhash.hash(0, &connection_id);
        try self.connections.put(conn_hash, ConnectionState{
            .id = connection_id,
            .keys_derived = true,
        });
        
        std.debug.print("New QUIC connection established: {any}\n", .{connection_id});
    }
    
    pub fn processPacket(
        self: *QuicServer,
        connection_id: [8]u8,
        packet: []u8,
        header_len: usize,
        packet_number: u64,
    ) !usize {
        const conn_hash = std.hash.Wyhash.hash(0, &connection_id);
        const connection = self.connections.get(conn_hash) orelse {
            return error.UnknownConnection;
        };
        
        if (!connection.keys_derived) {
            return error.KeysNotDerived;
        }
        
        // Decrypt packet in-place for zero-copy performance
        return try zcrypto.quic.ZeroCopy.decryptInPlace(
            &self.crypto,
            .application,
            true, // server-side
            packet_number,
            packet,
            header_len,
        );
    }
    
    pub fn deinit(self: *QuicServer) void {
        self.connections.deinit();
    }
};
```

---

## ⚠️ **ERROR HANDLING**

### **Error Types**

```zig
/// Core cryptographic errors
pub const CryptoError = error{
    InvalidSeed,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidHmacKey,
    InvalidKeyFormat,
    SignatureVerificationFailed,
    KeyDerivationFailed,
    InsufficientEntropy,
    InvalidKeySize,
    InvalidNonceSize,
    InvalidTagSize,
    DecryptionFailed,
    EncryptionFailed,
    InvalidInput,
};

/// Post-quantum cryptography errors
pub const PQError = error{
    KeyGenFailed,
    EncapsFailed,
    DecapsFailed,
    SigningFailed,
    VerificationFailed,
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidCiphertext,
    InvalidSignature,
    InvalidSharedSecret,
    UnsupportedParameter,
};

/// QUIC cryptography errors
pub const QuicError = error{
    InvalidConnectionId,
    InvalidPacketNumber,
    InvalidKeys,
    PacketDecryptionFailed,
    HeaderProtectionFailed,
    KeyDerivationFailed,
    InvalidCipherSuite,
    EncryptionFailed,
    DecryptionFailed,
    InvalidPacket,
    PQHandshakeFailed,
    HybridModeRequired,
    UnsupportedPQAlgorithm,
};
```

### **Error Handling Patterns**

```zig
// Graceful error handling
fn handleCryptoOperation() !void {
    const keypair = zcrypto.asym.ed25519.generate();
    
    const signature = keypair.sign("message") catch |err| switch (err) {
        error.InvalidInput => {
            std.log.err("Invalid input provided to signing function");
            return;
        },
        error.SignatureVerificationFailed => {
            std.log.err("Failed to create signature");
            return;
        },
        else => return err, // Propagate other errors
    };
    
    // Use signature...
    _ = signature;
}

// Error propagation
fn cryptoWorkflow() ![]u8 {
    const keys = try generateKeys(); // May fail
    const data = try encryptData(keys, "secret"); // May fail
    const hash = zcrypto.hash.sha256(data); // Never fails
    
    return try allocator.dupe(u8, &hash);
}
```

---

## 🔧 **INTEGRATION PATTERNS**

## 🏗️ **GHOSTCHAIN PROJECT INTEGRATIONS**

### **zsig - Digital Signature Service**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

/// Production-ready digital signature service for GhostChain
pub const ZSigService = struct {
    // Hybrid cryptography for maximum security
    classical_keys: zcrypto.asym.ed25519.KeyPair,
    pq_keys: zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair,
    backup_secp_keys: zcrypto.asym.secp256k1.KeyPair,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) !ZSigService {
        return ZSigService{
            .classical_keys = zcrypto.asym.ed25519.generate(),
            .pq_keys = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.generateRandom(allocator),
            .backup_secp_keys = zcrypto.asym.secp256k1.generate(),
            .allocator = allocator,
        };
    }
    
    /// Sign data with hybrid classical + post-quantum signatures
    pub fn signDocument(self: *const ZSigService, document: []const u8) !struct {
        classical: [64]u8,
        post_quantum: [3309]u8,
        secp256k1_backup: [64]u8,
        integrity_hash: [32]u8,
        timestamp: u64,
    } {
        const timestamp = std.time.timestamp();
        
        // Create timestamped data
        const timestamped_data = try std.fmt.allocPrint(
            self.allocator, "{s}:{d}", .{ document, timestamp }
        );
        defer self.allocator.free(timestamped_data);
        
        // Generate all signatures
        const classical_sig = try self.classical_keys.sign(timestamped_data);
        
        var pq_randomness: [32]u8 = undefined;
        std.crypto.random.bytes(&pq_randomness);
        const pq_sig = try self.pq_keys.sign(timestamped_data, pq_randomness);
        
        const secp_hash = zcrypto.hash.sha256(timestamped_data);
        const secp_sig = try self.backup_secp_keys.sign(secp_hash);
        
        // Create integrity hash of all signatures
        const integrity_hash = zcrypto.hash.sha256(
            &(classical_sig ++ pq_sig ++ secp_sig)
        );
        
        return .{
            .classical = classical_sig,
            .post_quantum = pq_sig,
            .secp256k1_backup = secp_sig,
            .integrity_hash = integrity_hash,
            .timestamp = @intCast(timestamp),
        };
    }
    
    /// Verify document with all signature types
    pub fn verifyDocument(
        classical_public: [32]u8,
        pq_public: [1952]u8,
        secp_public: [33]u8,
        document: []const u8,
        signatures: anytype,
    ) !bool {
        // Reconstruct timestamped data
        const timestamped_data = try std.fmt.allocPrint(
            std.heap.page_allocator, "{s}:{d}", .{ document, signatures.timestamp }
        );
        defer std.heap.page_allocator.free(timestamped_data);
        
        // Verify all signatures
        const classical_valid = zcrypto.asym.ed25519.verify(
            timestamped_data, signatures.classical, classical_public
        );
        
        const pq_valid = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.verify(
            pq_public, timestamped_data, signatures.post_quantum
        );
        
        const secp_hash = zcrypto.hash.sha256(timestamped_data);
        const secp_valid = zcrypto.asym.secp256k1.verify(
            secp_hash, signatures.secp256k1_backup, secp_public
        );
        
        // Verify integrity hash
        const computed_hash = zcrypto.hash.sha256(
            &(signatures.classical ++ signatures.post_quantum ++ signatures.secp256k1_backup)
        );
        const integrity_valid = std.mem.eql(u8, &computed_hash, &signatures.integrity_hash);
        
        return classical_valid and pq_valid and secp_valid and integrity_valid;
    }
    
    /// Batch sign multiple documents for performance
    pub fn batchSignDocuments(
        self: *const ZSigService,
        documents: [][]const u8,
    ) ![]struct {
        classical: [64]u8,
        post_quantum: [3309]u8,
        document_hash: [32]u8,
    } {
        const signatures = try self.allocator.alloc(@TypeOf(.{
            .classical = [_]u8{0} ** 64,
            .post_quantum = [_]u8{0} ** 3309,
            .document_hash = [_]u8{0} ** 32,
        }), documents.len);
        
        for (documents, 0..) |doc, i| {
            const doc_hash = zcrypto.hash.sha256(doc);
            signatures[i] = .{
                .classical = try self.classical_keys.sign(doc),
                .post_quantum = blk: {
                    var randomness: [32]u8 = undefined;
                    std.crypto.random.bytes(&randomness);
                    break :blk try self.pq_keys.sign(doc, randomness);
                },
                .document_hash = doc_hash,
            };
        }
        
        return signatures;
    }
    
    pub fn deinit(self: *ZSigService) void {
        // Secure cleanup
        self.classical_keys.zeroize();
        self.backup_secp_keys.zeroize();
    }
};
```

### **ghostd - Network Daemon with QUIC Crypto**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

/// High-performance network daemon for GhostChain
pub const GhostDaemon = struct {
    quic_crypto: zcrypto.quic.QuicCrypto,
    tls_config: zcrypto.tls.config.TlsConfig,
    connections: std.HashMap(u64, ConnectionContext),
    hybrid_keys: zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair,
    allocator: std.mem.Allocator,
    
    const ConnectionContext = struct {
        id: [8]u8,
        peer_address: []const u8,
        established_at: u64,
        shared_secret: ?[64]u8,
        packet_count: u64,
    };
    
    pub fn init(allocator: std.mem.Allocator, bind_address: []const u8) !GhostDaemon {
        // Initialize post-quantum hybrid QUIC
        const quic_crypto = zcrypto.quic.QuicCrypto.init(
            .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384
        );
        
        // Configure TLS for secure handshakes
        const alpn_protocols = [_][]const u8{ "ghostchain/1.0", "h3" };
        const tls_config = zcrypto.tls.config.TlsConfig.init(allocator)
            .withServerName("ghostchain.local")
            .withALPN(@constCast(&alpn_protocols))
            .withInsecureSkipVerify(false);
        
        return GhostDaemon{
            .quic_crypto = quic_crypto,
            .tls_config = tls_config,
            .connections = std.HashMap(u64, ConnectionContext).init(allocator),
            .hybrid_keys = try zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate(),
            .allocator = allocator,
        };
    }
    
    /// Handle new peer connection with post-quantum handshake
    pub fn handleNewPeer(self: *GhostDaemon, peer_address: []const u8) !u64 {
        // Generate unique connection ID
        var connection_id: [8]u8 = undefined;
        std.crypto.random.bytes(&connection_id);
        
        // Derive QUIC keys for this connection
        try self.quic_crypto.deriveInitialKeys(&connection_id);
        
        // Create connection context
        const conn_hash = std.hash.Wyhash.hash(0, &connection_id);
        try self.connections.put(conn_hash, ConnectionContext{
            .id = connection_id,
            .peer_address = try self.allocator.dupe(u8, peer_address),
            .established_at = @intCast(std.time.timestamp()),
            .shared_secret = null,
            .packet_count = 0,
        });
        
        std.debug.print("🔗 New GhostChain peer: {s} (ID: {any})\n", 
            .{ peer_address, connection_id });
        
        return conn_hash;
    }
    
    /// Process encrypted packet with zero-copy performance
    pub fn processPacket(
        self: *GhostDaemon,
        connection_hash: u64,
        packet: []u8,
        header_len: usize,
    ) ![]const u8 {
        var connection = self.connections.getPtr(connection_hash) orelse {
            return error.UnknownConnection;
        };
        
        // Increment packet counter
        connection.packet_count += 1;
        
        // Decrypt packet in-place for maximum performance
        const payload_len = try zcrypto.quic.ZeroCopy.decryptInPlace(
            &self.quic_crypto,
            .application,
            true, // server-side
            connection.packet_count,
            packet,
            header_len,
        );
        
        return packet[header_len..header_len + payload_len];
    }
    
    /// Broadcast message to all connected peers
    pub fn broadcastMessage(self: *GhostDaemon, message: []const u8) !void {
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            const connection = entry.value_ptr;
            
            // Create packet buffer
            var packet_buffer: [4096]u8 = undefined;
            const header = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x01 }; // QUIC header
            @memcpy(packet_buffer[0..header.len], &header);
            @memcpy(packet_buffer[header.len..header.len + message.len], message);
            
            // Encrypt for this connection
            try zcrypto.quic.ZeroCopy.encryptInPlace(
                &self.quic_crypto,
                .application,
                true, // server-side
                connection.packet_count + 1,
                packet_buffer[0..header.len + message.len],
                header.len,
            );
            
            std.debug.print("📡 Broadcasted to {s}\n", .{connection.peer_address});
        }
    }
    
    pub fn deinit(self: *GhostDaemon) void {
        // Cleanup connections
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.peer_address);
        }
        self.connections.deinit();
        self.tls_config.deinit();
    }
};
```

### **walletd - Cryptocurrency Wallet Daemon**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

/// Secure cryptocurrency wallet for GhostChain
pub const WalletDaemon = struct {
    // Multi-currency support
    ed25519_keys: zcrypto.asym.ed25519.KeyPair,     // GhostChain native
    secp256k1_keys: zcrypto.asym.secp256k1.KeyPair, // Bitcoin/Ethereum
    secp256r1_keys: zcrypto.asym.secp256r1.KeyPair, // NIST compliance
    
    // Encryption for wallet storage
    master_key: [32]u8,
    encrypted_storage: std.HashMap([]const u8, []u8),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, password: []const u8) !WalletDaemon {
        // Derive master key from password
        const master_key_bytes = try zcrypto.kdf.deriveKey(
            allocator, password, "walletd-master-v1", 32
        );
        defer allocator.free(master_key_bytes);
        
        var master_key: [32]u8 = undefined;
        @memcpy(&master_key, master_key_bytes[0..32]);
        
        return WalletDaemon{
            .ed25519_keys = zcrypto.asym.ed25519.generate(),
            .secp256k1_keys = zcrypto.asym.secp256k1.generate(),
            .secp256r1_keys = zcrypto.asym.secp256r1.generate(),
            .master_key = master_key,
            .encrypted_storage = std.HashMap([]const u8, []u8).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Generate deterministic wallet from seed phrase
    pub fn fromSeedPhrase(
        allocator: std.mem.Allocator,
        seed_phrase: []const u8,
    ) !WalletDaemon {
        // Hash seed phrase to create deterministic seed
        const seed_hash = zcrypto.hash.sha256(seed_phrase);
        
        return WalletDaemon{
            .ed25519_keys = zcrypto.asym.ed25519.generateFromSeed(seed_hash),
            .secp256k1_keys = zcrypto.asym.secp256k1.generate(), // TODO: deterministic
            .secp256r1_keys = zcrypto.asym.secp256r1.generate(), // TODO: deterministic
            .master_key = seed_hash,
            .encrypted_storage = std.HashMap([]const u8, []u8).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Sign transaction for different cryptocurrencies
    pub fn signTransaction(
        self: *const WalletDaemon,
        currency: enum { ghostchain, bitcoin, ethereum, nist },
        transaction_data: []const u8,
    ) ![]u8 {
        const tx_hash = zcrypto.hash.sha256(transaction_data);
        
        switch (currency) {
            .ghostchain => {
                const signature = try self.ed25519_keys.sign(transaction_data);
                return try self.allocator.dupe(u8, &signature);
            },
            .bitcoin, .ethereum => {
                const signature = try self.secp256k1_keys.sign(tx_hash);
                return try self.allocator.dupe(u8, &signature);
            },
            .nist => {
                const signature = try self.secp256r1_keys.sign(tx_hash);
                return try self.allocator.dupe(u8, &signature);
            },
        }
    }
    
    /// Encrypt and store sensitive data
    pub fn storeEncrypted(
        self: *WalletDaemon,
        key: []const u8,
        data: []const u8,
    ) !void {
        // Generate unique nonce for this storage
        const nonce = zcrypto.rand.randomArray(12);
        
        // Encrypt data using master key
        const encrypted = try zcrypto.sym.encryptAes128Gcm(
            self.allocator,
            self.master_key[0..16].*,
            nonce,
            data,
            key, // Use key as additional authenticated data
        );
        
        // Store with nonce prepended
        const storage_data = try self.allocator.alloc(u8, 12 + encrypted.data.len + 16);
        @memcpy(storage_data[0..12], &nonce);
        @memcpy(storage_data[12..12 + encrypted.data.len], encrypted.data);
        @memcpy(storage_data[12 + encrypted.data.len..], &encrypted.tag);
        
        const key_copy = try self.allocator.dupe(u8, key);
        try self.encrypted_storage.put(key_copy, storage_data);
        
        encrypted.deinit();
    }
    
    /// Decrypt and retrieve stored data
    pub fn retrieveDecrypted(
        self: *const WalletDaemon,
        key: []const u8,
    ) !?[]u8 {
        const storage_data = self.encrypted_storage.get(key) orelse return null;
        
        if (storage_data.len < 28) return error.InvalidStorageData; // 12 + 16 minimum
        
        const nonce = storage_data[0..12].*;
        const ciphertext = storage_data[12..storage_data.len - 16];
        const tag = storage_data[storage_data.len - 16..].*;
        
        return try zcrypto.sym.decryptAes128Gcm(
            self.allocator,
            self.master_key[0..16].*,
            nonce,
            ciphertext,
            tag,
            key,
        );
    }
    
    /// Export public keys for address generation
    pub fn getPublicKeys(self: *const WalletDaemon) struct {
        ghostchain: [32]u8,
        bitcoin_compressed: [33]u8,
        bitcoin_x_only: [32]u8,
        ethereum: [33]u8,
        nist: [33]u8,
    } {
        return .{
            .ghostchain = self.ed25519_keys.public_key,
            .bitcoin_compressed = self.secp256k1_keys.public_key_compressed,
            .bitcoin_x_only = self.secp256k1_keys.public_key_x,
            .ethereum = self.secp256k1_keys.public_key_compressed,
            .nist = self.secp256r1_keys.public_key,
        };
    }
    
    pub fn deinit(self: *WalletDaemon) void {
        // Secure cleanup
        self.ed25519_keys.zeroize();
        self.secp256k1_keys.zeroize();
        self.secp256r1_keys.zeroize();
        zcrypto.util.secureZero([32]u8, &self.master_key);
        
        // Free encrypted storage
        var iterator = self.encrypted_storage.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.encrypted_storage.deinit();
    }
};
```

### **zledger - Blockchain Ledger System**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

/// High-performance blockchain ledger for GhostChain
pub const ZLedger = struct {
    // Block signing authority
    validator_keys: zcrypto.asym.ed25519.KeyPair,
    pq_validator_keys: zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair,
    
    // Block storage and validation
    blocks: std.ArrayList(Block),
    merkle_trees: std.HashMap([32]u8, MerkleTree),
    allocator: std.mem.Allocator,
    
    const Block = struct {
        height: u64,
        previous_hash: [32]u8,
        merkle_root: [32]u8,
        timestamp: u64,
        transactions: [][32]u8, // Transaction hashes
        validator_signature: [64]u8,
        pq_signature: [3309]u8,
        nonce: u64,
    };
    
    const MerkleTree = struct {
        root: [32]u8,
        leaves: [][32]u8,
        proof_nodes: [][32]u8,
    };
    
    pub fn init(allocator: std.mem.Allocator) !ZLedger {
        return ZLedger{
            .validator_keys = zcrypto.asym.ed25519.generate(),
            .pq_validator_keys = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.generateRandom(allocator),
            .blocks = std.ArrayList(Block).init(allocator),
            .merkle_trees = std.HashMap([32]u8, MerkleTree).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Create and validate new block
    pub fn createBlock(
        self: *ZLedger,
        transactions: []const [32]u8,
    ) !Block {
        const height = self.blocks.items.len;
        const previous_hash = if (height > 0) 
            self.calculateBlockHash(self.blocks.items[height - 1])
        else 
            [_]u8{0} ** 32;
        
        // Build Merkle tree for transactions
        const merkle_tree = try self.buildMerkleTree(transactions);
        
        // Create block structure
        var block = Block{
            .height = height,
            .previous_hash = previous_hash,
            .merkle_root = merkle_tree.root,
            .timestamp = @intCast(std.time.timestamp()),
            .transactions = try self.allocator.dupe([32]u8, transactions),
            .validator_signature = undefined,
            .pq_signature = undefined,
            .nonce = 0,
        };
        
        // Mine block (simplified proof of work)
        while (true) {
            const block_hash = self.calculateBlockHash(block);
            if (block_hash[0] == 0 and block_hash[1] == 0) break; // 2-byte difficulty
            block.nonce += 1;
        }
        
        // Sign block with hybrid signatures
        const block_data = try self.serializeBlockForSigning(block);
        defer self.allocator.free(block_data);
        
        block.validator_signature = try self.validator_keys.sign(block_data);
        
        var pq_randomness: [32]u8 = undefined;
        std.crypto.random.bytes(&pq_randomness);
        block.pq_signature = try self.pq_validator_keys.sign(block_data, pq_randomness);
        
        // Store Merkle tree
        try self.merkle_trees.put(merkle_tree.root, merkle_tree);
        
        return block;
    }
    
    /// Validate block integrity and signatures
    pub fn validateBlock(
        self: *const ZLedger,
        block: Block,
        validator_public: [32]u8,
        pq_public: [1952]u8,
    ) !bool {
        // Validate proof of work
        const block_hash = self.calculateBlockHash(block);
        if (block_hash[0] != 0 or block_hash[1] != 0) return false;
        
        // Validate Merkle root
        const computed_merkle = try self.buildMerkleTree(block.transactions);
        defer self.allocator.free(computed_merkle.leaves);
        defer self.allocator.free(computed_merkle.proof_nodes);
        
        if (!std.mem.eql(u8, &computed_merkle.root, &block.merkle_root)) {
            return false;
        }
        
        // Validate signatures
        const block_data = try self.serializeBlockForSigning(block);
        defer self.allocator.free(block_data);
        
        const classical_valid = zcrypto.asym.ed25519.verify(
            block_data, block.validator_signature, validator_public
        );
        
        const pq_valid = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.verify(
            pq_public, block_data, block.pq_signature
        );
        
        return classical_valid and pq_valid;
    }
    
    /// Add validated block to ledger
    pub fn addBlock(self: *ZLedger, block: Block) !void {
        // Validate block height sequence
        if (block.height != self.blocks.items.len) {
            return error.InvalidBlockHeight;
        }
        
        // Validate previous hash
        if (self.blocks.items.len > 0) {
            const expected_prev = self.calculateBlockHash(self.blocks.items[self.blocks.items.len - 1]);
            if (!std.mem.eql(u8, &block.previous_hash, &expected_prev)) {
                return error.InvalidPreviousHash;
            }
        }
        
        try self.blocks.append(block);
        std.debug.print("📦 Block {} added to ledger (txs: {})\n", 
            .{ block.height, block.transactions.len });
    }
    
    /// Generate Merkle proof for transaction inclusion
    pub fn generateMerkleProof(
        self: *const ZLedger,
        merkle_root: [32]u8,
        transaction_hash: [32]u8,
    ) !?[]const [32]u8 {
        const tree = self.merkle_trees.get(merkle_root) orelse return null;
        
        // Find transaction index
        const tx_index = for (tree.leaves, 0..) |leaf, i| {
            if (std.mem.eql(u8, &leaf, &transaction_hash)) break i;
        } else return null;
        
        // Generate proof path (simplified)
        var proof = std.ArrayList([32]u8).init(self.allocator);
        var current_index = tx_index;
        var level_size = tree.leaves.len;
        
        while (level_size > 1) {
            const sibling_index = if (current_index % 2 == 0) current_index + 1 else current_index - 1;
            if (sibling_index < level_size) {
                try proof.append(tree.proof_nodes[sibling_index]); // Simplified access
            }
            current_index /= 2;
            level_size = (level_size + 1) / 2;
        }
        
        return proof.toOwnedSlice();
    }
    
    fn buildMerkleTree(self: *const ZLedger, transactions: []const [32]u8) !MerkleTree {
        if (transactions.len == 0) {
            return MerkleTree{
                .root = [_]u8{0} ** 32,
                .leaves = try self.allocator.dupe([32]u8, &[_][32]u8{}),
                .proof_nodes = try self.allocator.dupe([32]u8, &[_][32]u8{}),
            };
        }
        
        var current_level = try self.allocator.dupe([32]u8, transactions);
        var all_nodes = std.ArrayList([32]u8).init(self.allocator);
        try all_nodes.appendSlice(current_level);
        
        while (current_level.len > 1) {
            var next_level = std.ArrayList([32]u8).init(self.allocator);
            
            var i: usize = 0;
            while (i < current_level.len) : (i += 2) {
                const left = current_level[i];
                const right = if (i + 1 < current_level.len) current_level[i + 1] else left;
                
                const combined = left ++ right;
                const hash = zcrypto.hash.sha256(&combined);
                try next_level.append(hash);
            }
            
            self.allocator.free(current_level);
            current_level = try next_level.toOwnedSlice();
            try all_nodes.appendSlice(current_level);
        }
        
        const root = current_level[0];
        self.allocator.free(current_level);
        
        return MerkleTree{
            .root = root,
            .leaves = try self.allocator.dupe([32]u8, transactions),
            .proof_nodes = try all_nodes.toOwnedSlice(),
        };
    }
    
    fn calculateBlockHash(self: *const ZLedger, block: Block) [32]u8 {
        // Serialize block for hashing (simplified)
        var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
        hasher.update(std.mem.asBytes(&block.height));
        hasher.update(&block.previous_hash);
        hasher.update(&block.merkle_root);
        hasher.update(std.mem.asBytes(&block.timestamp));
        hasher.update(std.mem.asBytes(&block.nonce));
        
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }
    
    fn serializeBlockForSigning(self: *const ZLedger, block: Block) ![]u8 {
        // Simplified serialization for signing
        const size = @sizeOf(u64) * 3 + 32 * 2 + block.transactions.len * 32;
        const data = try self.allocator.alloc(u8, size);
        
        var offset: usize = 0;
        @memcpy(data[offset..offset + 8], std.mem.asBytes(&block.height));
        offset += 8;
        @memcpy(data[offset..offset + 32], &block.previous_hash);
        offset += 32;
        @memcpy(data[offset..offset + 32], &block.merkle_root);
        offset += 32;
        @memcpy(data[offset..offset + 8], std.mem.asBytes(&block.timestamp));
        offset += 8;
        @memcpy(data[offset..offset + 8], std.mem.asBytes(&block.nonce));
        offset += 8;
        
        for (block.transactions) |tx| {
            @memcpy(data[offset..offset + 32], &tx);
            offset += 32;
        }
        
        return data;
    }
    
    pub fn deinit(self: *ZLedger) void {
        // Cleanup blocks
        for (self.blocks.items) |block| {
            self.allocator.free(block.transactions);
        }
        self.blocks.deinit();
        
        // Cleanup Merkle trees
        var tree_iter = self.merkle_trees.iterator();
        while (tree_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.leaves);
            self.allocator.free(entry.value_ptr.proof_nodes);
        }
        self.merkle_trees.deinit();
        
        // Secure key cleanup
        self.validator_keys.zeroize();
    }
};
```

### **zvm - Virtual Machine with Cryptographic Operations**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

/// Secure virtual machine with built-in cryptographic operations
pub const ZVM = struct {
    // VM execution context
    stack: std.ArrayList(Value),
    memory: []u8,
    program_counter: usize,
    
    // Cryptographic context
    crypto_keys: CryptoContext,
    trusted_signatures: std.HashMap([32]u8, bool),
    allocator: std.mem.Allocator,
    
    const Value = union(enum) {
        integer: i64,
        bytes: []const u8,
        hash: [32]u8,
        signature: [64]u8,
        public_key: [32]u8,
    };
    
    const CryptoContext = struct {
        ed25519_keys: zcrypto.asym.ed25519.KeyPair,
        secp256k1_keys: zcrypto.asym.secp256k1.KeyPair,
        execution_keypair: zcrypto.asym.ed25519.KeyPair,
        secure_random_state: std.rand.DefaultPrng,
    };
    
    const Opcode = enum(u8) {
        // Standard VM operations
        push_int = 0x01,
        push_bytes = 0x02,
        pop = 0x03,
        dup = 0x04,
        swap = 0x05,
        
        // Cryptographic operations
        hash_sha256 = 0x10,
        hash_blake2b = 0x11,
        sign_ed25519 = 0x12,
        verify_ed25519 = 0x13,
        sign_secp256k1 = 0x14,
        verify_secp256k1 = 0x15,
        
        // Key operations
        keygen_ed25519 = 0x20,
        keygen_secp256k1 = 0x21,
        derive_key = 0x22,
        
        // Secure operations
        secure_random = 0x30,
        secure_zero = 0x31,
        verify_program = 0x32,
        
        // Control flow
        jump = 0x40,
        jump_if = 0x41,
        call = 0x42,
        ret = 0x43,
        halt = 0xFF,
    };
    
    pub fn init(allocator: std.mem.Allocator, memory_size: usize) !ZVM {
        var secure_seed: [32]u8 = undefined;
        std.crypto.random.bytes(&secure_seed);
        
        return ZVM{
            .stack = std.ArrayList(Value).init(allocator),
            .memory = try allocator.alloc(u8, memory_size),
            .program_counter = 0,
            .crypto_keys = CryptoContext{
                .ed25519_keys = zcrypto.asym.ed25519.generate(),
                .secp256k1_keys = zcrypto.asym.secp256k1.generate(),
                .execution_keypair = zcrypto.asym.ed25519.generate(),
                .secure_random_state = std.rand.DefaultPrng.init(@bitCast(secure_seed[0..8].*)),
            },
            .trusted_signatures = std.HashMap([32]u8, bool).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Execute cryptographically signed program
    pub fn executeProgram(
        self: *ZVM,
        program: []const u8,
        program_signature: [64]u8,
        signer_public_key: [32]u8,
    ) !void {
        // Verify program integrity
        const program_hash = zcrypto.hash.sha256(program);
        const signature_valid = zcrypto.asym.ed25519.verify(
            program, program_signature, signer_public_key
        );
        
        if (!signature_valid) {
            return error.InvalidProgramSignature;
        }
        
        // Check if signer is trusted
        if (!self.trusted_signatures.contains(program_hash)) {
            std.debug.print("⚠️  Executing untrusted program from: {any}\n", .{signer_public_key});
        }
        
        self.program_counter = 0;
        
        while (self.program_counter < program.len) {
            const opcode: Opcode = @enumFromInt(program[self.program_counter]);
            try self.executeOpcode(opcode, program);
        }
    }
    
    fn executeOpcode(self: *ZVM, opcode: Opcode, program: []const u8) !void {
        switch (opcode) {
            .hash_sha256 => {
                const data_value = self.stack.pop();
                const data = switch (data_value) {
                    .bytes => |bytes| bytes,
                    else => return error.InvalidOperand,
                };
                const hash = zcrypto.hash.sha256(data);
                try self.stack.append(Value{ .hash = hash });
            },
            
            .sign_ed25519 => {
                const data_value = self.stack.pop();
                const data = switch (data_value) {
                    .bytes => |bytes| bytes,
                    else => return error.InvalidOperand,
                };
                const signature = try self.crypto_keys.ed25519_keys.sign(data);
                try self.stack.append(Value{ .signature = signature });
            },
            
            .verify_ed25519 => {
                const public_key_value = self.stack.pop();
                const signature_value = self.stack.pop();
                const data_value = self.stack.pop();
                
                const public_key = switch (public_key_value) {
                    .public_key => |key| key,
                    else => return error.InvalidOperand,
                };
                const signature = switch (signature_value) {
                    .signature => |sig| sig,
                    else => return error.InvalidOperand,
                };
                const data = switch (data_value) {
                    .bytes => |bytes| bytes,
                    else => return error.InvalidOperand,
                };
                
                const valid = zcrypto.asym.ed25519.verify(data, signature, public_key);
                try self.stack.append(Value{ .integer = if (valid) 1 else 0 });
            },
            
            .keygen_ed25519 => {
                const new_keys = zcrypto.asym.ed25519.generate();
                try self.stack.append(Value{ .public_key = new_keys.public_key });
                // Private key stored securely in VM context
                self.crypto_keys.execution_keypair = new_keys;
            },
            
            .secure_random => {
                const size_value = self.stack.pop();
                const size = switch (size_value) {
                    .integer => |i| @as(usize, @intCast(i)),
                    else => return error.InvalidOperand,
                };
                
                if (size > 1024) return error.RandomSizeTooLarge;
                
                const random_bytes = try self.allocator.alloc(u8, size);
                self.crypto_keys.secure_random_state.fill(random_bytes);
                try self.stack.append(Value{ .bytes = random_bytes });
            },
            
            .derive_key => {
                const info_value = self.stack.pop();
                const material_value = self.stack.pop();
                
                const info = switch (info_value) {
                    .bytes => |bytes| bytes,
                    else => return error.InvalidOperand,
                };
                const material = switch (material_value) {
                    .bytes => |bytes| bytes,
                    else => return error.InvalidOperand,
                };
                
                const derived_key = try zcrypto.kdf.deriveKey(
                    self.allocator, material, info, 32
                );
                try self.stack.append(Value{ .bytes = derived_key });
            },
            
            .verify_program => {
                const signature_value = self.stack.pop();
                const program_value = self.stack.pop();
                const public_key_value = self.stack.pop();
                
                const signature = switch (signature_value) {
                    .signature => |sig| sig,
                    else => return error.InvalidOperand,
                };
                const program_data = switch (program_value) {
                    .bytes => |bytes| bytes,
                    else => return error.InvalidOperand,
                };
                const public_key = switch (public_key_value) {
                    .public_key => |key| key,
                    else => return error.InvalidOperand,
                };
                
                const valid = zcrypto.asym.ed25519.verify(program_data, signature, public_key);
                
                // Mark program as trusted if valid
                if (valid) {
                    const program_hash = zcrypto.hash.sha256(program_data);
                    try self.trusted_signatures.put(program_hash, true);
                }
                
                try self.stack.append(Value{ .integer = if (valid) 1 else 0 });
            },
            
            .secure_zero => {
                const data_value = self.stack.pop();
                switch (data_value) {
                    .bytes => |bytes| {
                        // Securely zero the memory
                        std.crypto.utils.secureZero(u8, @constCast(bytes));
                        self.allocator.free(bytes);
                    },
                    else => return error.InvalidOperand,
                }
            },
            
            .halt => {
                return; // Program termination
            },
            
            else => {
                return error.UnknownOpcode;
            },
        }
        
        self.program_counter += 1;
    }
    
    /// Add trusted program signer
    pub fn addTrustedSigner(self: *ZVM, public_key: [32]u8, program_hash: [32]u8) !void {
        try self.trusted_signatures.put(program_hash, true);
        std.debug.print("✅ Added trusted program: {any}\n", .{program_hash});
    }
    
    /// Get VM state for debugging
    pub fn getState(self: *const ZVM) struct {
        stack_size: usize,
        program_counter: usize,
        trusted_programs: usize,
    } {
        return .{
            .stack_size = self.stack.items.len,
            .program_counter = self.program_counter,
            .trusted_programs = self.trusted_signatures.count(),
        };
    }
    
    pub fn deinit(self: *ZVM) void {
        // Secure cleanup
        self.crypto_keys.ed25519_keys.zeroize();
        self.crypto_keys.secp256k1_keys.zeroize();
        self.crypto_keys.execution_keypair.zeroize();
        
        // Clear memory
        std.crypto.utils.secureZero(u8, self.memory);
        self.allocator.free(self.memory);
        
        // Clear stack
        for (self.stack.items) |item| {
            switch (item) {
                .bytes => |bytes| self.allocator.free(bytes),
                else => {},
            }
        }
        self.stack.deinit();
        
        self.trusted_signatures.deinit();
    }
};
```

### **For Key Management Services**

```zig
// Key management integration
const KeyManager = struct {
    master_key: [32]u8,
    allocator: std.mem.Allocator,
    
    pub fn deriveServiceKey(
        self: *const KeyManager,
        service_name: []const u8,
        key_type: []const u8,
    ) ![]u8 {
        const info = try std.fmt.allocPrint(
            self.allocator, "{s}:{s}", .{ service_name, key_type }
        );
        defer self.allocator.free(info);
        
        return try zcrypto.kdf.deriveKey(
            self.allocator, &self.master_key, info, 32
        );
    }
};
```

---

## 🚀 **PERFORMANCE NOTES**

### **Zero-Copy Operations**

- Use `zcrypto.quic.ZeroCopy` for high-throughput packet processing
- Prefer in-place encryption/decryption when possible
- Stack allocation is preferred over heap allocation for keys

### **Batch Processing**

- Use batch operations for multiple cryptographic operations
- Consider SIMD optimizations available in x86_64 and ARM modules

### **Memory Management**

```zig
// Efficient memory patterns
pub fn efficientCrypto(allocator: std.mem.Allocator) !void {
    // Use stack allocation for keys
    var keypair: zcrypto.asym.ed25519.KeyPair = undefined;
    keypair = zcrypto.asym.ed25519.generate();
    
    // Use arena allocator for temporary operations
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();
    
    // Temporary keys automatically freed
    const derived_key = try zcrypto.kdf.deriveKey(
        arena_allocator, "master", "derived", 32
    );
    _ = derived_key;
    
    // Secure cleanup
    defer zcrypto.util.secureZero(std.mem.asBytes(&keypair));
}
```

---

**🎯 This API documentation provides everything you need to integrate zcrypto v0.5.0 into your projects with confidence and security!**