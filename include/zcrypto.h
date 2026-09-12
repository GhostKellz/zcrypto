/*
 * zcrypto C ABI.
 *
 * This header is the contract between the library and every C caller. It is
 * installed alongside the static library and is compiled against the real
 * artifact by tests/ffi/consumer.c, so a prototype that drifts from the Zig
 * `export fn` it names becomes a build failure rather than a silent ABI break.
 *
 * Conventions that hold for the whole surface:
 *
 *   - Every entry point returns zcrypto_result_t by value. `success` is the
 *     only field that decides whether the call worked; `error_code` explains a
 *     failure and is 0 on success; `data_len` carries a produced length where
 *     the operation has one and is 0 otherwise.
 *   - Lengths are uint32_t, not size_t. Callers on 64-bit platforms must narrow
 *     explicitly, and the library rejects anything above ZCRYPTO_MAX_INPUT_SIZE
 *     rather than truncating.
 *   - Arguments are validated before any pointer is dereferenced or any slice is
 *     constructed. A null pointer paired with a zero length is accepted wherever
 *     the operation has a meaningful empty case; a null pointer with a non-zero
 *     length is always rejected.
 *   - The library cannot validate a dangling pointer, and does not try. Callers
 *     are responsible for the lifetime of every buffer they pass.
 *   - No function in this header allocates memory the caller must release. The
 *     single exception is the QUIC context, which is acquired by
 *     zcrypto_quic_init and must be released by zcrypto_quic_free.
 */

#ifndef ZCRYPTO_H
#define ZCRYPTO_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Result and error codes                                                     */
/* ------------------------------------------------------------------------- */

/*
 * Mirrors the Zig `extern struct` returned by every export. Layout is
 * bool + uint32_t + uint32_t, which is 12 bytes with 4-byte alignment on the
 * supported platforms. consumer.c asserts that at compile time.
 */
typedef struct zcrypto_result {
    bool     success;
    uint32_t data_len;
    uint32_t error_code;
} zcrypto_result_t;

#define ZCRYPTO_OK                            0u
#define ZCRYPTO_ERROR_INVALID_INPUT           1u
#define ZCRYPTO_ERROR_CRYPTO_FAILED           2u
#define ZCRYPTO_ERROR_INSUFFICIENT_BUFFER     3u
#define ZCRYPTO_ERROR_KEY_GENERATION_FAILED   4u
#define ZCRYPTO_ERROR_SIGNATURE_FAILED        5u
#define ZCRYPTO_ERROR_VERIFICATION_FAILED     6u
#define ZCRYPTO_ERROR_ENCRYPTION_FAILED       7u
#define ZCRYPTO_ERROR_DECRYPTION_FAILED       8u
#define ZCRYPTO_ERROR_POST_QUANTUM_FAILED     9u
#define ZCRYPTO_ERROR_QUIC_FAILED            10u
#define ZCRYPTO_ERROR_NULL_POINTER           11u
#define ZCRYPTO_ERROR_INVALID_HANDLE         12u
#define ZCRYPTO_ERROR_HANDLE_TABLE_FULL      13u

/* ------------------------------------------------------------------------- */
/* Sizes                                                                      */
/* ------------------------------------------------------------------------- */

/* Upper bound on any single input buffer, in bytes. */
#define ZCRYPTO_MAX_INPUT_SIZE      (16u * 1024u * 1024u)

#define ZCRYPTO_SHA256_SIZE         32u
#define ZCRYPTO_BLAKE2B_SIZE        64u

#define ZCRYPTO_ED25519_PUBLIC_KEY_SIZE   32u
#define ZCRYPTO_ED25519_PRIVATE_KEY_SIZE  64u
#define ZCRYPTO_ED25519_SIGNATURE_SIZE    64u

#define ZCRYPTO_X25519_PUBLIC_KEY_SIZE    32u
#define ZCRYPTO_X25519_PRIVATE_KEY_SIZE   32u

#define ZCRYPTO_AES256_GCM_KEY_SIZE   32u
#define ZCRYPTO_AES256_GCM_NONCE_SIZE 12u
#define ZCRYPTO_AES256_GCM_TAG_SIZE   16u

#define ZCRYPTO_HKDF_PRK_SIZE       32u
/* HKDF-Expand is bounded at 255 * hash_len by RFC 5869. */
#define ZCRYPTO_HKDF_MAX_OKM_SIZE   (255u * 32u)
#define ZCRYPTO_HKDF_MAX_INFO_SIZE  1024u

/*
 * FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) parameter sizes. These are asserted
 * against the Zig implementation constants at compile time in src/ffi.zig, so a
 * stdlib change that moved them would fail the build instead of silently
 * disagreeing with this header.
 */
#define ZCRYPTO_ML_KEM_768_PUBLIC_KEY_SIZE    1184u
#define ZCRYPTO_ML_KEM_768_PRIVATE_KEY_SIZE   2400u
#define ZCRYPTO_ML_KEM_768_CIPHERTEXT_SIZE    1088u
#define ZCRYPTO_ML_KEM_768_SHARED_SECRET_SIZE   32u

#define ZCRYPTO_ML_DSA_65_PUBLIC_KEY_SIZE     1952u
#define ZCRYPTO_ML_DSA_65_PRIVATE_KEY_SIZE    4032u
#define ZCRYPTO_ML_DSA_65_SIGNATURE_SIZE      3309u

/* Hybrid X25519 + ML-KEM-768 exchange. */
#define ZCRYPTO_HYBRID_SHARED_SECRET_SIZE     64u
/* Entropy consumed by zcrypto_quic_pq_key_exchange. */
#define ZCRYPTO_QUIC_PQ_ENTROPY_SIZE          64u

/* Size of the opaque QUIC handle, in bytes. */
#define ZCRYPTO_QUIC_HANDLE_SIZE              16u
/* RFC 9000 caps a connection ID at 20 bytes; the library also rejects 0. */
#define ZCRYPTO_QUIC_MAX_CONNECTION_ID_SIZE   20u

/* ------------------------------------------------------------------------- */
/* Enumerated arguments                                                       */
/* ------------------------------------------------------------------------- */

/* Cipher suite identifiers accepted by zcrypto_quic_init and
 * zcrypto_cipher_suite_info. Any other value is ZCRYPTO_ERROR_INVALID_INPUT. */
#define ZCRYPTO_CIPHER_AES_128_GCM_SHA256               0u
#define ZCRYPTO_CIPHER_AES_256_GCM_SHA384               1u
#define ZCRYPTO_CIPHER_CHACHA20_POLY1305_SHA256         2u
#define ZCRYPTO_CIPHER_ML_KEM_768_X25519_AES256_GCM_SHA384 3u

/* QUIC encryption levels, matching the Zig EncryptionLevel enum order. */
#define ZCRYPTO_LEVEL_INITIAL      0u
#define ZCRYPTO_LEVEL_EARLY_DATA   1u
#define ZCRYPTO_LEVEL_HANDSHAKE    2u
#define ZCRYPTO_LEVEL_APPLICATION  3u

/* Feature bits returned by zcrypto_get_features. A bit that is clear means the
 * feature was compiled out; the corresponding entry points then fail rather
 * than returning fabricated success. */
#define ZCRYPTO_FEATURE_POST_QUANTUM    0x001u
#define ZCRYPTO_FEATURE_ZERO_KNOWLEDGE  0x002u
#define ZCRYPTO_FEATURE_QUIC_CRYPTO     0x004u
#define ZCRYPTO_FEATURE_PROTOCOLS       0x008u
#define ZCRYPTO_FEATURE_ASM_OPTIMIZED   0x010u
#define ZCRYPTO_FEATURE_HYBRID_CRYPTO   0x020u
#define ZCRYPTO_FEATURE_ASYNC           0x040u
#define ZCRYPTO_FEATURE_BLOCKCHAIN      0x080u
#define ZCRYPTO_FEATURE_VPN             0x100u
#define ZCRYPTO_FEATURE_WASM            0x200u
#define ZCRYPTO_FEATURE_ENTERPRISE      0x400u

/* ------------------------------------------------------------------------- */
/* Hashing                                                                    */
/* ------------------------------------------------------------------------- */

/* output_len must be >= ZCRYPTO_SHA256_SIZE. Empty input is valid. */
zcrypto_result_t zcrypto_sha256(const uint8_t *input, uint32_t input_len,
                                uint8_t *output, uint32_t output_len);

/* output_len must be >= ZCRYPTO_BLAKE2B_SIZE. Empty input is valid. */
zcrypto_result_t zcrypto_blake2b(const uint8_t *input, uint32_t input_len,
                                 uint8_t *output, uint32_t output_len);

/* ------------------------------------------------------------------------- */
/* Ed25519                                                                    */
/* ------------------------------------------------------------------------- */

zcrypto_result_t zcrypto_ed25519_keygen(uint8_t *public_key, uint32_t public_key_len,
                                        uint8_t *private_key, uint32_t private_key_len);

/* private_key_len must be exactly 32 or exactly 64. 32 is the RFC 8032 seed;
 * 64 is the expanded form produced by zcrypto_ed25519_keygen, which is the seed
 * followed by the public key. Any other length is rejected. Signing an empty
 * message is valid. */
zcrypto_result_t zcrypto_ed25519_sign(const uint8_t *message, uint32_t message_len,
                                      const uint8_t *private_key, uint32_t private_key_len,
                                      uint8_t *signature, uint32_t signature_len);

/* Returns success only when the signature verifies. A well-formed signature
 * over a different message fails with ZCRYPTO_ERROR_VERIFICATION_FAILED. */
zcrypto_result_t zcrypto_ed25519_verify(const uint8_t *message, uint32_t message_len,
                                        const uint8_t *signature, uint32_t signature_len,
                                        const uint8_t *public_key, uint32_t public_key_len);

/* ------------------------------------------------------------------------- */
/* ML-KEM-768 (post-quantum KEM)                                              */
/* ------------------------------------------------------------------------- */

/*
 * Availability, for every post-quantum entry point in this header -- the two
 * families below, the hybrid exchange, and zcrypto_quic_pq_key_exchange.
 *
 * All of them are exported in every build, so a program compiled against this
 * header links against any build of the library. What the build flag changes is
 * behaviour: when post-quantum support is absent, each of these calls fails with
 * ZCRYPTO_ERROR_POST_QUANTUM_FAILED and writes nothing to its output buffers.
 * The refusal is returned before argument validation, so it is reported in
 * preference to a buffer-size or null-pointer error.
 *
 * Query support with zcrypto_has_post_quantum, the ZCRYPTO_FEATURE_POST_QUANTUM
 * bit, or the algorithm string; all three agree, and all three agree with what
 * these entry points will actually do.
 */

/*
 * Two variants exist for each operation. The unsuffixed form takes no lengths
 * and therefore trusts the caller to have allocated exactly the documented
 * size; the _checked form takes explicit capacities and validates them. New
 * code should use the _checked form.
 */

zcrypto_result_t zcrypto_ml_kem_768_keygen(uint8_t *public_key, uint8_t *private_key);

zcrypto_result_t zcrypto_ml_kem_768_keygen_checked(uint8_t *public_key, uint32_t public_key_len,
                                                   uint8_t *private_key, uint32_t private_key_len);

zcrypto_result_t zcrypto_ml_kem_768_encaps(const uint8_t *public_key,
                                           uint8_t *ciphertext, uint8_t *shared_secret);

zcrypto_result_t zcrypto_ml_kem_768_encaps_checked(const uint8_t *public_key, uint32_t public_key_len,
                                                   uint8_t *ciphertext, uint32_t ciphertext_len,
                                                   uint8_t *shared_secret, uint32_t shared_secret_len);

zcrypto_result_t zcrypto_ml_kem_768_decaps(const uint8_t *private_key,
                                           const uint8_t *ciphertext, uint8_t *shared_secret);

zcrypto_result_t zcrypto_ml_kem_768_decaps_checked(const uint8_t *private_key, uint32_t private_key_len,
                                                   const uint8_t *ciphertext, uint32_t ciphertext_len,
                                                   uint8_t *shared_secret, uint32_t shared_secret_len);

/* ------------------------------------------------------------------------- */
/* ML-DSA-65 (post-quantum signature)                                         */
/* ------------------------------------------------------------------------- */

zcrypto_result_t zcrypto_ml_dsa_65_keygen(uint8_t *public_key, uint8_t *private_key);

zcrypto_result_t zcrypto_ml_dsa_65_keygen_checked(uint8_t *public_key, uint32_t public_key_len,
                                                  uint8_t *private_key, uint32_t private_key_len);

zcrypto_result_t zcrypto_ml_dsa_65_sign(const uint8_t *private_key,
                                        const uint8_t *message, uint32_t message_len,
                                        uint8_t *signature);

zcrypto_result_t zcrypto_ml_dsa_65_sign_checked(const uint8_t *private_key, uint32_t private_key_len,
                                                const uint8_t *message, uint32_t message_len,
                                                uint8_t *signature, uint32_t signature_len);

/* Note: there is deliberately no unchecked verify. Verification consumes a
 * caller-supplied signature whose length cannot be assumed. */
zcrypto_result_t zcrypto_ml_dsa_65_verify_checked(const uint8_t *public_key, uint32_t public_key_len,
                                                  const uint8_t *message, uint32_t message_len,
                                                  const uint8_t *signature, uint32_t signature_len);

/* ------------------------------------------------------------------------- */
/* Hybrid X25519 + ML-KEM-768                                                 */
/* ------------------------------------------------------------------------- */

zcrypto_result_t zcrypto_hybrid_x25519_ml_kem_keygen(uint8_t *classical_public,
                                                     uint8_t *classical_private,
                                                     uint8_t *pq_public,
                                                     uint8_t *pq_private);

zcrypto_result_t zcrypto_hybrid_x25519_ml_kem_exchange(const uint8_t *our_classical_private,
                                                       const uint8_t *our_pq_private,
                                                       const uint8_t *peer_classical_public,
                                                       const uint8_t *peer_pq_ciphertext,
                                                       uint8_t *shared_secret);

/* ------------------------------------------------------------------------- */
/* QUIC packet protection                                                     */
/* ------------------------------------------------------------------------- */

/*
 * The QUIC context is the only resource in this ABI with an ownership pairing.
 * zcrypto_quic_init writes an opaque ZCRYPTO_QUIC_HANDLE_SIZE-byte handle into
 * caller memory; the caller must pass that same handle to zcrypto_quic_free
 * exactly once. The handle embeds a generation counter, so freeing twice or
 * using a stale handle is detected and reported as
 * ZCRYPTO_ERROR_INVALID_HANDLE rather than corrupting the context table.
 *
 * The context table is fixed size. Exhausting it returns
 * ZCRYPTO_ERROR_HANDLE_TABLE_FULL, which is a leak signal, not a transient
 * condition to retry.
 */

zcrypto_result_t zcrypto_quic_init(uint32_t cipher_suite,
                                   uint8_t *handle_out, uint32_t handle_out_len);

zcrypto_result_t zcrypto_quic_free(const uint8_t *handle);

zcrypto_result_t zcrypto_quic_derive_initial_keys(const uint8_t *handle,
                                                  const uint8_t *connection_id,
                                                  uint32_t connection_id_len);

/* Post-quantum, despite living in the otherwise unconditional QUIC namespace:
 * governed by the availability rules stated above the ML-KEM-768 section. */
zcrypto_result_t zcrypto_quic_pq_key_exchange(uint8_t *classical_public,
                                              uint8_t *pq_public,
                                              uint8_t *classical_ciphertext,
                                              uint8_t *pq_ciphertext,
                                              uint8_t *shared_secret,
                                              const uint8_t *entropy);

/* Encrypts in place. `packet` holds header_len header bytes followed by the
 * payload, and must have ZCRYPTO_AES256_GCM_TAG_SIZE bytes of spare capacity
 * beyond packet_len for the authentication tag. */
zcrypto_result_t zcrypto_quic_encrypt_packet_inplace(const uint8_t *handle, uint32_t level,
                                                     bool is_server, uint64_t packet_number,
                                                     uint8_t *packet, uint32_t packet_len,
                                                     uint32_t header_len);

/* Decrypts in place. On authentication failure the payload region is not left
 * holding usable unauthenticated plaintext. */
zcrypto_result_t zcrypto_quic_decrypt_packet_inplace(const uint8_t *handle, uint32_t level,
                                                     bool is_server, uint64_t packet_number,
                                                     uint8_t *packet, uint32_t packet_len,
                                                     uint32_t header_len);

/* ------------------------------------------------------------------------- */
/* HKDF-SHA256                                                                */
/* ------------------------------------------------------------------------- */

/* salt may be NULL when salt_len is 0, which selects the all-zero salt of
 * RFC 5869. prk_len must be >= ZCRYPTO_HKDF_PRK_SIZE. */
zcrypto_result_t zcrypto_hkdf_extract(const uint8_t *salt, uint32_t salt_len,
                                      const uint8_t *ikm, uint32_t ikm_len,
                                      uint8_t *prk, uint32_t prk_len);

/* prk_len must be exactly ZCRYPTO_HKDF_PRK_SIZE. okm_len is the requested
 * output length and must not exceed ZCRYPTO_HKDF_MAX_OKM_SIZE. */
zcrypto_result_t zcrypto_hkdf_expand(const uint8_t *prk, uint32_t prk_len,
                                     const uint8_t *info, uint32_t info_len,
                                     uint8_t *okm, uint32_t okm_len);

/* ------------------------------------------------------------------------- */
/* AES-256-GCM                                                                */
/* ------------------------------------------------------------------------- */

/*
 * The tag is appended to the ciphertext rather than returned separately, so the
 * ciphertext buffer needs plaintext_len + ZCRYPTO_AES256_GCM_TAG_SIZE bytes and
 * data_len reports that combined length. Decrypt consumes the same layout.
 *
 * On authentication failure zcrypto_aes256_gcm_decrypt zeroes the caller's
 * plaintext buffer over the payload length before returning
 * ZCRYPTO_ERROR_DECRYPTION_FAILED, so no unauthenticated plaintext is left
 * observable. Callers must still treat a failed decrypt as producing no output.
 */

zcrypto_result_t zcrypto_aes256_gcm_encrypt(const uint8_t *key, uint32_t key_len,
                                            const uint8_t *nonce, uint32_t nonce_len,
                                            const uint8_t *aad, uint32_t aad_len,
                                            const uint8_t *plaintext, uint32_t plaintext_len,
                                            uint8_t *ciphertext, uint32_t ciphertext_capacity);

zcrypto_result_t zcrypto_aes256_gcm_decrypt(const uint8_t *key, uint32_t key_len,
                                            const uint8_t *nonce, uint32_t nonce_len,
                                            const uint8_t *aad, uint32_t aad_len,
                                            const uint8_t *ciphertext, uint32_t ciphertext_len,
                                            uint8_t *plaintext, uint32_t plaintext_capacity);

/* ------------------------------------------------------------------------- */
/* Introspection                                                              */
/* ------------------------------------------------------------------------- */

/* Writes the version string, not NUL-terminated, and reports its length in
 * data_len. */
zcrypto_result_t zcrypto_version(uint8_t *buffer, uint32_t buffer_len);

/* success reflects whether post-quantum support was compiled in. When it was
 * not, error_code is ZCRYPTO_ERROR_POST_QUANTUM_FAILED. */
zcrypto_result_t zcrypto_has_post_quantum(void);

/* Writes a comma-separated algorithm list, not NUL-terminated, and reports its
 * length in data_len. */
zcrypto_result_t zcrypto_supported_algorithms(uint8_t *buffer, uint32_t buffer_len);

/* Reports key and hash lengths in bytes for one of the ZCRYPTO_CIPHER_*
 * identifiers. Both output pointers must be non-NULL. */
zcrypto_result_t zcrypto_cipher_suite_info(uint32_t cipher_suite,
                                           uint32_t *key_len, uint32_t *hash_len);

/* Writes the ZCRYPTO_FEATURE_* bitmask for this build. */
zcrypto_result_t zcrypto_get_features(uint32_t *features);

/* ------------------------------------------------------------------------- */
/* Memory helpers                                                             */
/* ------------------------------------------------------------------------- */

/* A zero length succeeds without dereferencing ptr, so (NULL, 0) is valid. */
zcrypto_result_t zcrypto_secure_zero(uint8_t *ptr, uint32_t len);

/* Constant-time comparison. success means the buffers are equal; a difference
 * reports ZCRYPTO_ERROR_VERIFICATION_FAILED. A zero length compares equal
 * without dereferencing either pointer. */
zcrypto_result_t zcrypto_secure_memcmp(const uint8_t *a, const uint8_t *b, uint32_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZCRYPTO_H */
