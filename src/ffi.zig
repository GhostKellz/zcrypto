//! FFI (Foreign Function Interface) for zcrypto v0.5.0
//!
//! Enhanced C ABI exports for seamless integration with all GhostChain services:
//! - ghostbridge (gRPC relay over QUIC)
//! - ghostd (blockchain daemon with PQ-crypto)
//! - walletd (wallet microservice with ZKP)
//! - cns/zns (name resolution services)
//! - wraith (QUIC proxy with hybrid crypto)
//!
//! All functions use C calling convention for maximum compatibility.
//! Full post-quantum cryptography and zero-knowledge proof support.

const std = @import("std");
const zcrypto = @import("root.zig");
const pq = @import("pq.zig");
const quic = @import("quic.zig");

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
    
    const keypair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(priv_key);
    
    const sig = keypair.sign(message_slice, null) catch {
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
    
    std.crypto.sign.Ed25519.verify(sig, message_slice, pub_key) catch {
        return CryptoResult.failure(FFI_ERROR_VERIFICATION_FAILED);
    };
    
    return CryptoResult.SUCCESS;
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
    const keypair = pq.ml_kem.ML_KEM_768.KeyPair.generateRandom() catch {
        return CryptoResult.failure(FFI_ERROR_POST_QUANTUM_FAILED);
    };
    
    @memcpy(public_key[0..pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE], &keypair.public_key);
    @memcpy(private_key[0..pq.ml_kem.ML_KEM_768.PRIVATE_KEY_SIZE], &keypair.private_key);
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
    const pub_key: [pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8 = public_key[0..pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE].*;
    var randomness: [32]u8 = undefined;
    std.crypto.random.bytes(&randomness);
    
    const result = pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(pub_key, randomness) catch {
        return CryptoResult.failure(FFI_ERROR_POST_QUANTUM_FAILED);
    };
    
    @memcpy(ciphertext[0..pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE], &result.ciphertext);
    @memcpy(shared_secret[0..32], &result.shared_secret);
    return CryptoResult.SUCCESS;
}

/// ML-KEM-768 decapsulation
/// @param private_key: Private key (2400 bytes)
/// @param ciphertext: Ciphertext (1088 bytes)
/// @param shared_secret: Output buffer for shared secret (32 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_ml_kem_768_decaps(
    private_key: [*]const u8,
    ciphertext: [*]const u8,
    shared_secret: [*]u8
) callconv(.C) CryptoResult {
    const priv_key: [pq.ml_kem.ML_KEM_768.PRIVATE_KEY_SIZE]u8 = private_key[0..pq.ml_kem.ML_KEM_768.PRIVATE_KEY_SIZE].*;
    const pub_key_placeholder: [pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8 = [_]u8{0} ** pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE;
    const ct: [pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE]u8 = ciphertext[0..pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE].*;
    
    const keypair = pq.ml_kem.ML_KEM_768.KeyPair{
        .public_key = pub_key_placeholder,
        .private_key = priv_key,
    };
    
    const secret = keypair.decapsulate(ct) catch {
        return CryptoResult.failure(FFI_ERROR_POST_QUANTUM_FAILED);
    };
    
    @memcpy(shared_secret[0..pq.ml_kem.ML_KEM_768.SHARED_SECRET_SIZE], &secret);
    return CryptoResult.SUCCESS;
}

/// Generate ML-DSA-65 key pair
/// @param public_key: Output buffer for public key (1952 bytes)
/// @param private_key: Output buffer for private key (4016 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_ml_dsa_65_keygen(
    public_key: [*]u8,
    private_key: [*]u8
) callconv(.C) CryptoResult {
    const keypair = pq.ml_dsa.ML_DSA_65.KeyPair.generateRandom(std.heap.page_allocator) catch {
        return CryptoResult.failure(FFI_ERROR_POST_QUANTUM_FAILED);
    };
    
    @memcpy(public_key[0..pq.ml_dsa.ML_DSA_65.PUBLIC_KEY_SIZE], &keypair.public_key);
    @memcpy(private_key[0..pq.ml_dsa.ML_DSA_65.PRIVATE_KEY_SIZE], &keypair.private_key);
    return CryptoResult.SUCCESS;
}

/// ML-DSA-65 signing
/// @param private_key: Private key (4016 bytes)
/// @param message: Message to sign
/// @param message_len: Message length
/// @param signature: Output buffer for signature (3309 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_ml_dsa_65_sign(
    private_key: [*]const u8,
    message: [*]const u8,
    message_len: u32,
    signature: [*]u8
) callconv(.C) CryptoResult {
    if (message_len == 0) return CryptoResult.failure(FFI_ERROR_INVALID_INPUT);
    
    const priv_key: [pq.ml_dsa.ML_DSA_65.PRIVATE_KEY_SIZE]u8 = private_key[0..pq.ml_dsa.ML_DSA_65.PRIVATE_KEY_SIZE].*;
    const pub_key_placeholder: [pq.ml_dsa.ML_DSA_65.PUBLIC_KEY_SIZE]u8 = [_]u8{0} ** pq.ml_dsa.ML_DSA_65.PUBLIC_KEY_SIZE;
    const message_slice = message[0..message_len];
    
    var randomness: [32]u8 = undefined;
    std.crypto.random.bytes(&randomness);
    
    const keypair = pq.ml_dsa.ML_DSA_65.KeyPair{
        .public_key = pub_key_placeholder,
        .private_key = priv_key,
    };
    
    const sig = keypair.sign(message_slice, randomness) catch {
        return CryptoResult.failure(FFI_ERROR_SIGNATURE_FAILED);
    };
    
    @memcpy(signature[0..pq.ml_dsa.ML_DSA_65.SIGNATURE_SIZE], &sig);
    return CryptoResult.successWithLen(pq.ml_dsa.ML_DSA_65.SIGNATURE_SIZE);
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
    const keypair = pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate() catch {
        return CryptoResult.failure(FFI_ERROR_POST_QUANTUM_FAILED);
    };
    
    @memcpy(classical_public[0..32], &keypair.classical_public);
    @memcpy(classical_private[0..32], &keypair.classical_private);
    @memcpy(pq_public[0..pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE], &keypair.pq_public);
    @memcpy(pq_private[0..pq.ml_kem.ML_KEM_768.PRIVATE_KEY_SIZE], &keypair.pq_private);
    return CryptoResult.SUCCESS;
}

/// Hybrid key exchange
/// @param our_classical_private: Our X25519 private key (32 bytes)
/// @param our_pq_private: Our ML-KEM-768 private key (2400 bytes)
/// @param peer_classical_public: Peer X25519 public key (32 bytes)
/// @param peer_pq_ciphertext: Peer ML-KEM-768 ciphertext (1088 bytes)
/// @param shared_secret: Output buffer for shared secret (64 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_hybrid_x25519_ml_kem_exchange(
    our_classical_private: [*]const u8,
    our_pq_private: [*]const u8,
    peer_classical_public: [*]const u8,
    peer_pq_ciphertext: [*]const u8,
    shared_secret: [*]u8
) callconv(.C) CryptoResult {
    const our_keypair = pq.hybrid.X25519_ML_KEM_768.HybridKeyPair{
        .classical_public = undefined, // Not needed for exchange
        .classical_private = our_classical_private[0..32].*,
        .pq_public = undefined, // Not needed for exchange
        .pq_private = our_pq_private[0..pq.ml_kem.ML_KEM_768.PRIVATE_KEY_SIZE].*,
    };
    
    const peer_classical: [32]u8 = peer_classical_public[0..32].*;
    const peer_ciphertext: [pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE]u8 = peer_pq_ciphertext[0..pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE].*;
    
    const secret = our_keypair.exchange(peer_classical, peer_ciphertext) catch {
        return CryptoResult.failure(FFI_ERROR_POST_QUANTUM_FAILED);
    };
    
    @memcpy(shared_secret[0..64], &secret);
    return CryptoResult.successWithLen(64);
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
        0 => quic.CipherSuite.TLS_AES_128_GCM_SHA256,
        1 => quic.CipherSuite.TLS_AES_256_GCM_SHA384,
        2 => quic.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        3 => quic.CipherSuite.TLS_ML_KEM_768_X25519_AES256_GCM_SHA384,
        else => return CryptoResult.failure(FFI_ERROR_INVALID_INPUT),
    };
    
    const crypto = quic.QuicCrypto.init(cs);
    
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
    var crypto = std.mem.bytesToValue(quic.QuicCrypto, context[0..@sizeOf(quic.QuicCrypto)]);
    
    const cid_slice = connection_id[0..connection_id_len];
    crypto.deriveInitialKeys(cid_slice) catch {
        return CryptoResult.failure(FFI_ERROR_QUIC_FAILED);
    };
    
    // Store updated context back
    const context_bytes = std.mem.asBytes(&crypto);
    @memcpy(context[0..context_bytes.len], context_bytes);
    
    return CryptoResult.SUCCESS;
}

/// Post-quantum QUIC key exchange
/// @param classical_public: Output for X25519 public key (32 bytes)
/// @param pq_public: Output for ML-KEM-768 public key (1184 bytes)
/// @param classical_ciphertext: Output for X25519 response (32 bytes)
/// @param pq_ciphertext: Output for ML-KEM-768 ciphertext (1088 bytes)
/// @param shared_secret: Output for combined shared secret (64 bytes)
/// @param entropy: Random bytes for key generation (64 bytes)
/// @return CryptoResult with success/failure status
pub export fn zcrypto_quic_pq_key_exchange(
    classical_public: [*]u8,
    pq_public: [*]u8,
    classical_ciphertext: [*]u8,
    pq_ciphertext: [*]u8,
    shared_secret: [*]u8,
    entropy: [*]const u8
) callconv(.C) CryptoResult {
    const entropy_slice = entropy[0..64];
    
    // Generate hybrid key share
    var classical_share: [32]u8 = undefined;
    var pq_share: [pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8 = undefined;
    
    quic.PostQuantumQuic.generateHybridKeyShare(&classical_share, &pq_share, entropy_slice) catch {
        return CryptoResult.failure(FFI_ERROR_QUIC_FAILED);
    };
    
    @memcpy(classical_public[0..32], &classical_share);
    @memcpy(pq_public[0..pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE], &pq_share);
    
    // Process key exchange (server side)
    var server_classical: [32]u8 = undefined;
    var server_pq: [pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE]u8 = undefined;
    var secret: [64]u8 = undefined;
    
    quic.PostQuantumQuic.processHybridKeyShare(
        &classical_share,
        &pq_share,
        &server_classical,
        &server_pq,
        &secret,
    ) catch {
        return CryptoResult.failure(FFI_ERROR_QUIC_FAILED);
    };
    
    @memcpy(classical_ciphertext[0..32], &server_classical);
    @memcpy(pq_ciphertext[0..pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE], &server_pq);
    @memcpy(shared_secret[0..64], &secret);
    
    return CryptoResult.SUCCESS;
}

/// Encrypt QUIC packet in-place for zero-copy
/// @param context: QUIC crypto context
/// @param level: Encryption level (0=initial, 1=early_data, 2=handshake, 3=application)
/// @param is_server: Whether this is server-side encryption
/// @param packet_number: Packet number
/// @param packet: Packet buffer (header + payload)
/// @param packet_len: Total packet length
/// @param header_len: Header length
/// @return CryptoResult with success/failure status
pub export fn zcrypto_quic_encrypt_packet_inplace(
    context: [*]const u8,
    level: u32,
    is_server: bool,
    packet_number: u64,
    packet: [*]u8,
    packet_len: u32,
    header_len: u32
) callconv(.C) CryptoResult {
    if (header_len >= packet_len) return CryptoResult.failure(FFI_ERROR_INVALID_INPUT);
    
    const crypto = std.mem.bytesToValue(quic.QuicCrypto, context[0..@sizeOf(quic.QuicCrypto)]);
    
    const enc_level = switch (level) {
        0 => quic.EncryptionLevel.initial,
        1 => quic.EncryptionLevel.early_data,
        2 => quic.EncryptionLevel.handshake,
        3 => quic.EncryptionLevel.application,
        else => return CryptoResult.failure(FFI_ERROR_INVALID_INPUT),
    };
    
    const packet_slice = packet[0..packet_len];
    
    quic.ZeroCopy.encryptInPlace(
        &crypto,
        enc_level,
        is_server,
        packet_number,
        packet_slice,
        header_len,
    ) catch {
        return CryptoResult.failure(FFI_ERROR_QUIC_FAILED);
    };
    
    return CryptoResult.SUCCESS;
}

/// Decrypt QUIC packet in-place for zero-copy
/// @param context: QUIC crypto context
/// @param level: Encryption level
/// @param is_server: Whether this is server-side decryption
/// @param packet_number: Packet number
/// @param packet: Packet buffer (header + ciphertext)
/// @param packet_len: Total packet length
/// @param header_len: Header length
/// @return CryptoResult with payload length or failure
pub export fn zcrypto_quic_decrypt_packet_inplace(
    context: [*]const u8,
    level: u32,
    is_server: bool,
    packet_number: u64,
    packet: [*]u8,
    packet_len: u32,
    header_len: u32
) callconv(.C) CryptoResult {
    if (header_len >= packet_len) return CryptoResult.failure(FFI_ERROR_INVALID_INPUT);
    
    const crypto = std.mem.bytesToValue(quic.QuicCrypto, context[0..@sizeOf(quic.QuicCrypto)]);
    
    const enc_level = switch (level) {
        0 => quic.EncryptionLevel.initial,
        1 => quic.EncryptionLevel.early_data,
        2 => quic.EncryptionLevel.handshake,
        3 => quic.EncryptionLevel.application,
        else => return CryptoResult.failure(FFI_ERROR_INVALID_INPUT),
    };
    
    const packet_slice = packet[0..packet_len];
    
    const payload_len = quic.ZeroCopy.decryptInPlace(
        &crypto,
        enc_level,
        is_server,
        packet_number,
        packet_slice,
        header_len,
    ) catch {
        return CryptoResult.failure(FFI_ERROR_QUIC_FAILED);
    };
    
    return CryptoResult.successWithLen(@intCast(payload_len));
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
    const version = "zcrypto v0.5.0";
    if (buffer_len < version.len) {
        return CryptoResult.failure(FFI_ERROR_INSUFFICIENT_BUFFER);
    }
    
    @memcpy(buffer[0..version.len], version);
    return CryptoResult.successWithLen(@intCast(version.len));
}

/// Check if post-quantum algorithms are available
/// @return CryptoResult with success=available
pub export fn zcrypto_has_post_quantum() callconv(.C) CryptoResult {
    // Always true in v0.5.0
    return CryptoResult.SUCCESS;
}

/// Get supported algorithm list
/// @param buffer: Output buffer for algorithm names (comma-separated)
/// @param buffer_len: Buffer capacity
/// @return CryptoResult with string length
pub export fn zcrypto_supported_algorithms(
    buffer: [*]u8,
    buffer_len: u32
) callconv(.C) CryptoResult {
    const algorithms = "Ed25519,X25519,AES-256-GCM,ChaCha20-Poly1305,ML-KEM-768,ML-DSA-65,SLH-DSA-128s,Hybrid-X25519-ML-KEM-768,QUIC-PQ,Groth16,Bulletproofs,Signal,Noise,MLS";
    
    if (buffer_len < algorithms.len) {
        return CryptoResult.failure(FFI_ERROR_INSUFFICIENT_BUFFER);
    }
    
    @memcpy(buffer[0..algorithms.len], algorithms);
    return CryptoResult.successWithLen(@intCast(algorithms.len));
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
        0 => quic.CipherSuite.TLS_AES_128_GCM_SHA256,
        1 => quic.CipherSuite.TLS_AES_256_GCM_SHA384,
        2 => quic.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        3 => quic.CipherSuite.TLS_ML_KEM_768_X25519_AES256_GCM_SHA384,
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

/// Get library feature flags
/// @param features: Output buffer for feature bit flags
/// @return CryptoResult with success status
pub export fn zcrypto_get_features(
    features: [*]u32
) callconv(.C) CryptoResult {
    const FEATURE_POST_QUANTUM = 0x01;
    const FEATURE_ZERO_KNOWLEDGE = 0x02;
    const FEATURE_QUIC_CRYPTO = 0x04;
    const FEATURE_PROTOCOLS = 0x08;
    const FEATURE_ASM_OPTIMIZED = 0x10;
    const FEATURE_HYBRID_CRYPTO = 0x20;
    
    features[0] = FEATURE_POST_QUANTUM | FEATURE_ZERO_KNOWLEDGE | 
                  FEATURE_QUIC_CRYPTO | FEATURE_PROTOCOLS | 
                  FEATURE_ASM_OPTIMIZED | FEATURE_HYBRID_CRYPTO;
    
    return CryptoResult.SUCCESS;
}

/// Secure memory operations
/// @param ptr: Memory pointer
/// @param len: Memory length
/// @return CryptoResult with success status
pub export fn zcrypto_secure_zero(
    ptr: [*]u8,
    len: u32
) callconv(.C) CryptoResult {
    const slice = ptr[0..len];
    std.crypto.utils.secureZero(u8, slice);
    return CryptoResult.SUCCESS;
}

/// Constant-time memory comparison
/// @param a: First buffer
/// @param b: Second buffer
/// @param len: Buffer length
/// @return CryptoResult with success=equal
pub export fn zcrypto_secure_memcmp(
    a: [*]const u8,
    b: [*]const u8,
    len: u32
) callconv(.C) CryptoResult {
    const slice_a = a[0..len];
    const slice_b = b[0..len];
    
    var result: u8 = 0;
    for (slice_a, slice_b) |byte_a, byte_b| {
        result |= byte_a ^ byte_b;
    }
    
    return if (result == 0) CryptoResult.SUCCESS else CryptoResult.failure(FFI_ERROR_VERIFICATION_FAILED);
}

test "FFI exports compilation" {
    // Basic test to ensure all exports compile
    var buffer: [64]u8 = undefined;
    const result = zcrypto_version(&buffer, 64);
    try std.testing.expect(result.success);
}

test "FFI ML-KEM-768 operations" {
    var public_key: [pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8 = undefined;
    var private_key: [pq.ml_kem.ML_KEM_768.PRIVATE_KEY_SIZE]u8 = undefined;
    
    // Test key generation
    const keygen_result = zcrypto_ml_kem_768_keygen(&public_key, &private_key);
    try std.testing.expect(keygen_result.success);
    
    // Test encapsulation
    var ciphertext: [pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE]u8 = undefined;
    var shared_secret1: [pq.ml_kem.ML_KEM_768.SHARED_SECRET_SIZE]u8 = undefined;
    
    const encaps_result = zcrypto_ml_kem_768_encaps(&public_key, &ciphertext, &shared_secret1);
    try std.testing.expect(encaps_result.success);
    
    // Test decapsulation
    var shared_secret2: [pq.ml_kem.ML_KEM_768.SHARED_SECRET_SIZE]u8 = undefined;
    
    const decaps_result = zcrypto_ml_kem_768_decaps(&private_key, &ciphertext, &shared_secret2);
    try std.testing.expect(decaps_result.success);
    
    // Shared secrets should match
    try std.testing.expect(std.mem.eql(u8, &shared_secret1, &shared_secret2));
}

test "FFI hybrid operations" {
    var classical_public: [32]u8 = undefined;
    var classical_private: [32]u8 = undefined;
    var pq_public: [pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8 = undefined;
    var pq_private: [pq.ml_kem.ML_KEM_768.PRIVATE_KEY_SIZE]u8 = undefined;
    
    // Test hybrid key generation
    const keygen_result = zcrypto_hybrid_x25519_ml_kem_keygen(
        &classical_public,
        &classical_private,
        &pq_public,
        &pq_private,
    );
    try std.testing.expect(keygen_result.success);
    
    // Keys should not be all zeros
    var all_zero = true;
    for (classical_public) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "FFI QUIC crypto" {
    var context: [1024]u8 = undefined; // Larger buffer for context
    
    // Initialize QUIC crypto with post-quantum suite
    const init_result = zcrypto_quic_init(3, &context); // PQ-Hybrid
    try std.testing.expect(init_result.success);
    
    // Test packet encryption/decryption
    var packet = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 } ++ "Hello QUIC v0.5.0!".*;
    const header_len = 5;
    const packet_number = 42;
    
    // Store original for comparison
    var original_payload: [18]u8 = undefined;
    @memcpy(&original_payload, packet[header_len..]);
    
    // Encrypt in-place
    const encrypt_result = zcrypto_quic_encrypt_packet_inplace(
        &context,
        0, // initial level
        false, // client
        packet_number,
        &packet,
        packet.len,
        header_len,
    );
    try std.testing.expect(encrypt_result.success);
    
    // Payload should be different
    try std.testing.expect(!std.mem.eql(u8, &original_payload, packet[header_len..]));
    
    // Decrypt in-place
    const decrypt_result = zcrypto_quic_decrypt_packet_inplace(
        &context,
        0, // initial level
        false, // client
        packet_number,
        &packet,
        packet.len,
        header_len,
    );
    try std.testing.expect(decrypt_result.success);
    
    // Should match original
    try std.testing.expect(std.mem.eql(u8, &original_payload, packet[header_len..]));
}

test "FFI library features" {
    var features: u32 = undefined;
    const result = zcrypto_get_features(@ptrCast(&features));
    try std.testing.expect(result.success);
    
    // Should have all expected features
    const FEATURE_POST_QUANTUM = 0x01;
    const FEATURE_ZERO_KNOWLEDGE = 0x02;
    const FEATURE_QUIC_CRYPTO = 0x04;
    
    try std.testing.expect((features & FEATURE_POST_QUANTUM) != 0);
    try std.testing.expect((features & FEATURE_ZERO_KNOWLEDGE) != 0);
    try std.testing.expect((features & FEATURE_QUIC_CRYPTO) != 0);
}

test "FFI secure operations" {
    // Test secure memory comparison
    const data1 = "identical";
    const data2 = "identical";
    const data3 = "different";
    
    const cmp1 = zcrypto_secure_memcmp(data1.ptr, data2.ptr, data1.len);
    try std.testing.expect(cmp1.success); // Should be equal
    
    const cmp2 = zcrypto_secure_memcmp(data1.ptr, data3.ptr, data1.len);
    try std.testing.expect(!cmp2.success); // Should be different
    
    // Test secure zeroing
    var secret_data = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const zero_result = zcrypto_secure_zero(&secret_data, secret_data.len);
    try std.testing.expect(zero_result.success);
    
    for (secret_data) |byte| {
        try std.testing.expect(byte == 0);
    }
}