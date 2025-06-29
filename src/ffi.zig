//! FFI (Foreign Function Interface) for zcrypto v0.4.0
//!
//! Provides C ABI exports for seamless integration with Rust services:
//! - ghostbridge (gRPC relay over QUIC)
//! - ghostd (blockchain daemon)
//! - walletd (wallet microservice)
//! - cns/zns (name resolution services)
//! - wraith (QUIC proxy)
//!
//! All functions use C calling convention for maximum compatibility.

const std = @import("std");
const zcrypto = @import("root.zig");

/// FFI Result structure for consistent error handling
const CryptoResult = extern struct {
    success: bool,
    data_len: u32,
    error_code: u32,
    
    const SUCCESS = CryptoResult{ .success = true, .data_len = 0, .error_code = 0 };
    
    fn failure(code: u32) CryptoResult {
        return CryptoResult{ .success = false, .data_len = 0, .error_code = code };
    }
    
    fn successWithLen(len: u32) CryptoResult {
        return CryptoResult{ .success = true, .data_len = len, .error_code = 0 };
    }
};

/// Error codes for FFI
const FFI_ERROR_INVALID_INPUT = 1;
const FFI_ERROR_CRYPTO_FAILED = 2;
const FFI_ERROR_INSUFFICIENT_BUFFER = 3;
const FFI_ERROR_KEY_GENERATION_FAILED = 4;
const FFI_ERROR_SIGNATURE_FAILED = 5;
const FFI_ERROR_VERIFICATION_FAILED = 6;
const FFI_ERROR_ENCRYPTION_FAILED = 7;
const FFI_ERROR_DECRYPTION_FAILED = 8;
const FFI_ERROR_POST_QUANTUM_FAILED = 9;
const FFI_ERROR_QUIC_FAILED = 10;

// ============================================================================
// HASH FUNCTIONS
// ============================================================================

/// SHA-256 hash function
/// @param input: Input data to hash
/// @param input_len: Length of input data
/// @param output: Output buffer (must be at least 32 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_sha256(
    input: [*]const u8,
    input_len: u32,
    output: [*]u8
) callconv(.C) CryptoResult {
    if (input_len == 0) return CryptoResult.failure(FFI_ERROR_INVALID_INPUT);
    
    const input_slice = input[0..input_len];
    const digest = zcrypto.hash.sha256(input_slice);
    
    @memcpy(output[0..32], &digest);
    return CryptoResult.successWithLen(32);
}

/// Blake2b hash function (using existing implementation)
/// @param input: Input data to hash
/// @param input_len: Length of input data
/// @param output: Output buffer (must be at least 64 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_blake2b(
    input: [*]const u8,
    input_len: u32,
    output: [*]u8
) callconv(.C) CryptoResult {
    if (input_len == 0) return CryptoResult.failure(FFI_ERROR_INVALID_INPUT);
    
    const input_slice = input[0..input_len];
    const digest = zcrypto.hash.blake2b(input_slice);
    
    @memcpy(output[0..64], &digest);
    return CryptoResult.successWithLen(64);
}

// ============================================================================
// ASYMMETRIC CRYPTOGRAPHY
// ============================================================================

/// Generate Ed25519 key pair
/// @param public_key: Output buffer for public key (32 bytes)
/// @param private_key: Output buffer for private key (64 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_ed25519_keygen(
    public_key: [*]u8,
    private_key: [*]u8
) callconv(.C) CryptoResult {
    const keypair = zcrypto.asym.ed25519.generate();
    
    @memcpy(public_key[0..32], &keypair.public_key);
    @memcpy(private_key[0..64], &keypair.private_key);
    return CryptoResult.SUCCESS;
}

/// Ed25519 signature
/// @param message: Message to sign
/// @param message_len: Length of message
/// @param private_key: Private key (64 bytes)
/// @param signature: Output buffer for signature (64 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_ed25519_sign(
    message: [*]const u8,
    message_len: u32,
    private_key: [*]const u8,
    signature: [*]u8
) callconv(.C) CryptoResult {
    if (message_len == 0) return CryptoResult.failure(FFI_ERROR_INVALID_INPUT);
    
    const message_slice = message[0..message_len];
    const priv_key: [64]u8 = private_key[0..64].*;
    
    const keypair = zcrypto.asym.Ed25519KeyPair{
        .public_key = undefined, // Will be computed
        .private_key = priv_key,
    };
    
    const sig = keypair.sign(message_slice) catch {
        return CryptoResult.failure(FFI_ERROR_SIGNATURE_FAILED);
    };
    
    @memcpy(signature[0..64], &sig);
    return CryptoResult.successWithLen(64);
}

/// Ed25519 signature verification
/// @param message: Message that was signed
/// @param message_len: Length of message
/// @param signature: Signature to verify (64 bytes)
/// @param public_key: Public key (32 bytes)
/// @return CryptoResult with success=verification result
pub export fn zcrypto_ed25519_verify(
    message: [*]const u8,
    message_len: u32,
    signature: [*]const u8,
    public_key: [*]const u8
) callconv(.C) CryptoResult {
    if (message_len == 0) return CryptoResult.failure(FFI_ERROR_INVALID_INPUT);
    
    const message_slice = message[0..message_len];
    const sig: [64]u8 = signature[0..64].*;
    const pub_key: [32]u8 = public_key[0..32].*;
    
    const valid = zcrypto.asym.verifyEd25519(message_slice, sig, pub_key);
    
    return if (valid) CryptoResult.SUCCESS else CryptoResult.failure(FFI_ERROR_VERIFICATION_FAILED);
}

// ============================================================================
// POST-QUANTUM CRYPTOGRAPHY
// ============================================================================

/// Generate ML-KEM-768 key pair
/// @param public_key: Output buffer for public key (1184 bytes)
/// @param private_key: Output buffer for private key (2400 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_ml_kem_768_keygen(
    public_key: [*]u8,
    private_key: [*]u8
) callconv(.C) CryptoResult {
    const keypair = zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.generateRandom() catch {
        return CryptoResult.failure(FFI_ERROR_POST_QUANTUM_FAILED);
    };
    
    @memcpy(public_key[0..zcrypto.pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE], &keypair.public_key);
    @memcpy(private_key[0..zcrypto.pq.ml_kem.ML_KEM_768.PRIVATE_KEY_SIZE], &keypair.private_key);
    return CryptoResult.SUCCESS;
}

/// ML-KEM-768 encapsulation
/// @param public_key: Public key (1184 bytes)
/// @param ciphertext: Output buffer for ciphertext (1088 bytes)
/// @param shared_secret: Output buffer for shared secret (32 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_ml_kem_768_encaps(
    public_key: [*]const u8,
    ciphertext: [*]u8,
    shared_secret: [*]u8
) callconv(.C) CryptoResult {
    const pub_key: [zcrypto.pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8 = public_key[0..zcrypto.pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE].*;
    var randomness: [32]u8 = undefined;
    std.crypto.random.bytes(&randomness);
    
    const result = zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(pub_key, randomness) catch {
        return CryptoResult.failure(FFI_ERROR_POST_QUANTUM_FAILED);
    };
    
    @memcpy(ciphertext[0..zcrypto.pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE], &result.ciphertext);
    @memcpy(shared_secret[0..32], &result.shared_secret);
    return CryptoResult.SUCCESS;
}

/// Generate hybrid X25519 + ML-KEM-768 key pair
/// @param classical_public: Output for X25519 public key (32 bytes)
/// @param classical_private: Output for X25519 private key (32 bytes)
/// @param pq_public: Output for ML-KEM-768 public key (1184 bytes)
/// @param pq_private: Output for ML-KEM-768 private key (2400 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_hybrid_x25519_ml_kem_keygen(
    classical_public: [*]u8,
    classical_private: [*]u8,
    pq_public: [*]u8,
    pq_private: [*]u8
) callconv(.C) CryptoResult {
    const keypair = zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate() catch {
        return CryptoResult.failure(FFI_ERROR_POST_QUANTUM_FAILED);
    };
    
    @memcpy(classical_public[0..32], &keypair.classical_public);
    @memcpy(classical_private[0..32], &keypair.classical_private);
    @memcpy(pq_public[0..zcrypto.pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE], &keypair.pq_public);
    @memcpy(pq_private[0..zcrypto.pq.ml_kem.ML_KEM_768.PRIVATE_KEY_SIZE], &keypair.pq_private);
    return CryptoResult.SUCCESS;
}

// ============================================================================
// QUIC CRYPTOGRAPHY
// ============================================================================

/// Initialize QUIC crypto context
/// @param cipher_suite: Cipher suite ID (0=AES-128-GCM, 1=AES-256-GCM, 2=ChaCha20-Poly1305, 3=PQ-Hybrid)
/// @param context: Output buffer for crypto context (opaque, implementation-defined size)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_quic_init(
    cipher_suite: u32,
    context: [*]u8
) callconv(.C) CryptoResult {
    const cs = switch (cipher_suite) {
        0 => zcrypto.quic.CipherSuite.TLS_AES_128_GCM_SHA256,
        1 => zcrypto.quic.CipherSuite.TLS_AES_256_GCM_SHA384,
        2 => zcrypto.quic.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        3 => zcrypto.quic.CipherSuite.TLS_ML_KEM_768_X25519_AES256_GCM_SHA384,
        else => return CryptoResult.failure(FFI_ERROR_INVALID_INPUT),
    };
    
    const crypto = zcrypto.quic.QuicCrypto.init(cs);
    
    // Store the crypto context in the provided buffer
    // Note: In real implementation, we'd need proper serialization
    const context_bytes = std.mem.asBytes(&crypto);
    @memcpy(context[0..context_bytes.len], context_bytes);
    
    return CryptoResult.successWithLen(@intCast(context_bytes.len));
}

/// Derive QUIC initial keys from connection ID
/// @param context: QUIC crypto context
/// @param connection_id: Connection ID bytes
/// @param connection_id_len: Length of connection ID
/// @return CryptoResult with success/failure status
pub export fn zcrypto_quic_derive_initial_keys(
    context: [*]u8,
    connection_id: [*]const u8,
    connection_id_len: u32
) callconv(.C) CryptoResult {
    if (connection_id_len == 0) return CryptoResult.failure(FFI_ERROR_INVALID_INPUT);
    
    // Note: In real implementation, we'd properly deserialize the context
    var crypto = std.mem.bytesToValue(zcrypto.quic.QuicCrypto, context[0..@sizeOf(zcrypto.quic.QuicCrypto)]);
    
    const cid_slice = connection_id[0..connection_id_len];
    crypto.deriveInitialKeys(cid_slice) catch {
        return CryptoResult.failure(FFI_ERROR_QUIC_FAILED);
    };
    
    // Store updated context back
    const context_bytes = std.mem.asBytes(&crypto);
    @memcpy(context[0..context_bytes.len], context_bytes);
    
    return CryptoResult.SUCCESS;
}

/// Encrypt QUIC packet
/// @param context: QUIC crypto context
/// @param level: Encryption level (0=initial, 1=early_data, 2=handshake, 3=application)
/// @param is_server: Whether this is server-side encryption
/// @param packet_number: Packet number
/// @param header: Packet header
/// @param header_len: Header length
/// @param payload: Payload to encrypt
/// @param payload_len: Payload length
/// @param output: Output buffer for encrypted packet
/// @param output_capacity: Capacity of output buffer
/// @return CryptoResult with encrypted length or failure
pub export fn zcrypto_quic_encrypt_packet(
    context: [*]const u8,
    level: u32,
    is_server: bool,
    packet_number: u64,
    header: [*]const u8,
    header_len: u32,
    payload: [*]const u8,
    payload_len: u32,
    output: [*]u8,
    output_capacity: u32
) callconv(.C) CryptoResult {
    if (header_len == 0 or payload_len == 0) return CryptoResult.failure(FFI_ERROR_INVALID_INPUT);
    
    const crypto = std.mem.bytesToValue(zcrypto.quic.QuicCrypto, context[0..@sizeOf(zcrypto.quic.QuicCrypto)]);
    
    const enc_level = switch (level) {
        0 => zcrypto.quic.EncryptionLevel.initial,
        1 => zcrypto.quic.EncryptionLevel.early_data,
        2 => zcrypto.quic.EncryptionLevel.handshake,
        3 => zcrypto.quic.EncryptionLevel.application,
        else => return CryptoResult.failure(FFI_ERROR_INVALID_INPUT),
    };
    
    const header_slice = header[0..header_len];
    const payload_slice = payload[0..payload_len];
    const output_slice = output[0..output_capacity];
    
    const encrypted_len = crypto.encryptPacket(
        enc_level,
        is_server,
        packet_number,
        header_slice,
        payload_slice,
        output_slice
    ) catch {
        return CryptoResult.failure(FFI_ERROR_QUIC_FAILED);
    };
    
    return CryptoResult.successWithLen(@intCast(encrypted_len));
}

// ============================================================================
// KEY DERIVATION
// ============================================================================

/// HKDF-Extract (placeholder - will implement with proper KDF API)
/// @param salt: Salt value
/// @param salt_len: Salt length
/// @param ikm: Input key material
/// @param ikm_len: IKM length
/// @param prk: Output pseudorandom key (32 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_hkdf_extract(
    salt: [*]const u8,
    salt_len: u32,
    ikm: [*]const u8,
    ikm_len: u32,
    prk: [*]u8
) callconv(.C) CryptoResult {
    _ = salt;
    _ = salt_len;
    _ = ikm;
    _ = ikm_len;
    _ = prk;
    // TODO: Implement when KDF API is updated
    return CryptoResult.failure(FFI_ERROR_CRYPTO_FAILED);
}

/// HKDF-Expand-Label (placeholder - will implement with proper KDF API)
/// @param prk: Pseudorandom key
/// @param prk_len: PRK length
/// @param label: Label string
/// @param label_len: Label length
/// @param context: Context data
/// @param context_len: Context length
/// @param okm: Output key material
/// @param okm_len: Desired OKM length
/// @return CryptoResult with success/failure status
pub export fn zcrypto_hkdf_expand_label(
    prk: [*]const u8,
    prk_len: u32,
    label: [*]const u8,
    label_len: u32,
    context: [*]const u8,
    context_len: u32,
    okm: [*]u8,
    okm_len: u32
) callconv(.C) CryptoResult {
    _ = prk;
    _ = prk_len;
    _ = label;
    _ = label_len;
    _ = context;
    _ = context_len;
    _ = okm;
    _ = okm_len;
    // TODO: Implement when KDF API is updated
    return CryptoResult.failure(FFI_ERROR_CRYPTO_FAILED);
}

// ============================================================================
// SYMMETRIC ENCRYPTION
// ============================================================================

/// AES-256-GCM encryption (placeholder - will implement with proper SYM API)
/// @param key: Encryption key (32 bytes)
/// @param nonce: Nonce (12 bytes)
/// @param aad: Additional authenticated data
/// @param aad_len: AAD length
/// @param plaintext: Data to encrypt
/// @param plaintext_len: Plaintext length
/// @param ciphertext: Output buffer for ciphertext + tag
/// @param ciphertext_capacity: Capacity of ciphertext buffer
/// @return CryptoResult with encrypted length or failure
pub export fn zcrypto_aes256_gcm_encrypt(
    key: [*]const u8,
    nonce: [*]const u8,
    aad: [*]const u8,
    aad_len: u32,
    plaintext: [*]const u8,
    plaintext_len: u32,
    ciphertext: [*]u8,
    ciphertext_capacity: u32
) callconv(.C) CryptoResult {
    _ = key;
    _ = nonce;
    _ = aad;
    _ = aad_len;
    _ = plaintext;
    _ = plaintext_len;
    _ = ciphertext;
    _ = ciphertext_capacity;
    // TODO: Implement when SYM API is updated
    return CryptoResult.failure(FFI_ERROR_ENCRYPTION_FAILED);
}

// ============================================================================
// VERSION AND INFO
// ============================================================================

/// Get zcrypto version string
/// @param buffer: Output buffer for version string
/// @param buffer_len: Buffer capacity
/// @return CryptoResult with version string length
pub export fn zcrypto_version(
    buffer: [*]u8,
    buffer_len: u32
) callconv(.C) CryptoResult {
    const version = zcrypto.version;
    if (buffer_len < version.len) {
        return CryptoResult.failure(FFI_ERROR_INSUFFICIENT_BUFFER);
    }
    
    @memcpy(buffer[0..version.len], version);
    return CryptoResult.successWithLen(@intCast(version.len));
}

/// Check if post-quantum algorithms are available
/// @return CryptoResult with success=available
pub export fn zcrypto_has_post_quantum() callconv(.C) CryptoResult {
    // Always true in v0.4.0
    return CryptoResult.SUCCESS;
}

/// Get cipher suite info
/// @param cipher_suite: Cipher suite ID
/// @param key_len: Output for key length
/// @param hash_len: Output for hash length
/// @return CryptoResult with success/failure status
pub export fn zcrypto_cipher_suite_info(
    cipher_suite: u32,
    key_len: [*]u32,
    hash_len: [*]u32
) callconv(.C) CryptoResult {
    const cs = switch (cipher_suite) {
        0 => zcrypto.quic.CipherSuite.TLS_AES_128_GCM_SHA256,
        1 => zcrypto.quic.CipherSuite.TLS_AES_256_GCM_SHA384,
        2 => zcrypto.quic.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        3 => zcrypto.quic.CipherSuite.TLS_ML_KEM_768_X25519_AES256_GCM_SHA384,
        else => return CryptoResult.failure(FFI_ERROR_INVALID_INPUT),
    };
    
    key_len[0] = @intCast(cs.keyLength());
    hash_len[0] = switch (cs) {
        .TLS_AES_128_GCM_SHA256 => 32,
        .TLS_AES_256_GCM_SHA384 => 48,
        .TLS_CHACHA20_POLY1305_SHA256 => 32,
        .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384 => 48,
    };
    
    return CryptoResult.SUCCESS;
}

test "FFI exports compilation" {
    // Basic test to ensure all exports compile
    var buffer: [64]u8 = undefined;
    const result = zcrypto_version(&buffer, 64);
    try std.testing.expect(result.success);
}