// Minimal C-facing smoke example for zcrypto's exported ABI.
//
// Build/link this from a consumer that exports zcrypto's FFI symbols. This file
// intentionally declares only the small subset it uses so it stays useful even
// before a generated public header is added.

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    bool success;
    uint32_t data_len;
    uint32_t error_code;
} CryptoResult;

extern CryptoResult zcrypto_get_features(uint32_t *features);
extern CryptoResult zcrypto_sha256(const uint8_t *input, uint32_t input_len, uint8_t *output, uint32_t output_len);
extern CryptoResult zcrypto_aes256_gcm_encrypt(
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *nonce,
    uint32_t nonce_len,
    const uint8_t *aad,
    uint32_t aad_len,
    const uint8_t *plaintext,
    uint32_t plaintext_len,
    uint8_t *ciphertext,
    uint32_t ciphertext_capacity);
extern CryptoResult zcrypto_aes256_gcm_decrypt(
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *nonce,
    uint32_t nonce_len,
    const uint8_t *aad,
    uint32_t aad_len,
    const uint8_t *ciphertext,
    uint32_t ciphertext_len,
    uint8_t *plaintext,
    uint32_t plaintext_capacity);
extern CryptoResult zcrypto_ed25519_keygen(uint8_t *public_key, uint32_t public_key_len, uint8_t *private_key, uint32_t private_key_len);
extern CryptoResult zcrypto_ed25519_sign(const uint8_t *message, uint32_t message_len, const uint8_t *private_key, uint32_t private_key_len, uint8_t *signature, uint32_t signature_len);
extern CryptoResult zcrypto_ed25519_verify(const uint8_t *message, uint32_t message_len, const uint8_t *signature, uint32_t signature_len, const uint8_t *public_key, uint32_t public_key_len);

static int require_ok(const char *name, CryptoResult result) {
    if (!result.success) {
        fprintf(stderr, "%s failed with error_code=%u\n", name, result.error_code);
        return 1;
    }
    return 0;
}

int main(void) {
    uint32_t features = 0;
    if (require_ok("zcrypto_get_features", zcrypto_get_features(&features))) return 1;
    printf("zcrypto features: 0x%08x\n", features);

    const uint8_t message[] = "ffi smoke";
    uint8_t digest[32] = {0};
    if (require_ok("zcrypto_sha256", zcrypto_sha256(message, (uint32_t)(sizeof(message) - 1), digest, sizeof(digest)))) return 1;

    uint8_t key[32];
    uint8_t nonce[12];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x24, sizeof(nonce));

    const uint8_t aad[] = "aad";
    uint8_t ciphertext[sizeof(message) - 1 + 16] = {0};
    CryptoResult encrypted = zcrypto_aes256_gcm_encrypt(
        key,
        sizeof(key),
        nonce,
        sizeof(nonce),
        aad,
        (uint32_t)(sizeof(aad) - 1),
        message,
        (uint32_t)(sizeof(message) - 1),
        ciphertext,
        sizeof(ciphertext));
    if (require_ok("zcrypto_aes256_gcm_encrypt", encrypted)) return 1;

    uint8_t plaintext[sizeof(message) - 1] = {0};
    CryptoResult decrypted = zcrypto_aes256_gcm_decrypt(
        key,
        sizeof(key),
        nonce,
        sizeof(nonce),
        aad,
        (uint32_t)(sizeof(aad) - 1),
        ciphertext,
        encrypted.data_len,
        plaintext,
        sizeof(plaintext));
    if (require_ok("zcrypto_aes256_gcm_decrypt", decrypted)) return 1;
    if (memcmp(message, plaintext, sizeof(plaintext)) != 0) {
        fprintf(stderr, "AEAD plaintext mismatch\n");
        return 1;
    }

    uint8_t public_key[32] = {0};
    uint8_t private_key[64] = {0};
    if (require_ok("zcrypto_ed25519_keygen", zcrypto_ed25519_keygen(public_key, sizeof(public_key), private_key, sizeof(private_key)))) return 1;

    uint8_t signature[64] = {0};
    if (require_ok("zcrypto_ed25519_sign", zcrypto_ed25519_sign(message, (uint32_t)(sizeof(message) - 1), private_key, sizeof(private_key), signature, sizeof(signature)))) return 1;
    if (require_ok("zcrypto_ed25519_verify", zcrypto_ed25519_verify(message, (uint32_t)(sizeof(message) - 1), signature, sizeof(signature), public_key, sizeof(public_key)))) return 1;

    printf("zcrypto FFI smoke passed\n");
    return 0;
}
