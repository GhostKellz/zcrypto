/*
 * Executable C consumer for the zcrypto C ABI.
 *
 * This is a real linked program, not a syntax check. It includes the installed
 * header, links the produced static library, and calls the exported symbols, so
 * a prototype that disagrees with its Zig definition fails the build and a
 * behavioural regression fails the run.
 *
 * Two things it deliberately does NOT do:
 *
 *   - It never passes a dangling or unmapped pointer. The library cannot
 *     validate one and does not claim to; a test that did so would be asserting
 *     a guarantee that does not exist.
 *   - It never allocates a buffer merely to prove a huge length is rejected.
 *     Boundary rejection is tested with real capacities and hostile length
 *     arguments, which is what a C caller can actually get wrong.
 *
 * Expected values are independent of this library: published RFC and NIST test
 * vectors where they exist, and self-consistency (round-trip, tamper, cross-key)
 * only where no authoritative vector is available.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zcrypto.h"

/* ------------------------------------------------------------------------- */
/* Harness                                                                    */
/* ------------------------------------------------------------------------- */

static unsigned g_checks;
static unsigned g_failures;
static const char *g_group = "?";

static void group(const char *name)
{
    g_group = name;
    printf("-- %s\n", name);
}

static void check(int ok, const char *what, const char *file, int line)
{
    g_checks++;
    if (!ok) {
        g_failures++;
        printf("   FAIL [%s] %s (%s:%d)\n", g_group, what, file, line);
    }
}

#define CHECK(cond) check((cond) ? 1 : 0, #cond, __FILE__, __LINE__)

/* Reports the observed error code on mismatch: knowing a call failed is much
 * less useful than knowing it failed the way the ABI documents. */
static void check_result(zcrypto_result_t r, bool want_success, uint32_t want_code,
                         const char *what, const char *file, int line)
{
    g_checks++;
    if (r.success != want_success || r.error_code != want_code) {
        g_failures++;
        printf("   FAIL [%s] %s (%s:%d): got success=%d code=%u, want success=%d code=%u\n",
               g_group, what, file, line,
               (int)r.success, r.error_code, (int)want_success, want_code);
    }
}

#define EXPECT_OK(call) check_result((call), true, ZCRYPTO_OK, #call, __FILE__, __LINE__)
#define EXPECT_ERR(call, code) check_result((call), false, (code), #call, __FILE__, __LINE__)

/* ------------------------------------------------------------------------- */
/* Guarded buffers                                                            */
/* ------------------------------------------------------------------------- */

/*
 * Every output buffer handed to the library is bracketed by sentinel bytes. A
 * capacity check that passes but writes one byte too far shows up here rather
 * than as heap corruption noticed hours later somewhere unrelated.
 */

#define GUARD_LEN  32u
#define GUARD_BYTE 0xA5u

typedef struct {
    uint8_t *base; /* start of the whole allocation, including guards */
    uint8_t *data; /* what the library sees */
    uint32_t len;
} guarded_t;

static guarded_t guarded_new(uint32_t len)
{
    guarded_t g;
    size_t total = (size_t)len + 2u * (size_t)GUARD_LEN;
    g.base = (uint8_t *)malloc(total);
    if (g.base == NULL) {
        fprintf(stderr, "out of memory allocating %zu bytes\n", total);
        exit(2);
    }
    memset(g.base, (int)GUARD_BYTE, total);
    g.data = g.base + GUARD_LEN;
    g.len = len;
    return g;
}

/* Fills only the caller-visible region, leaving the sentinels intact. */
static void guarded_fill(guarded_t *g, uint8_t byte)
{
    if (g->len > 0u) {
        memset(g->data, (int)byte, (size_t)g->len);
    }
}

static int guarded_intact(const guarded_t *g)
{
    uint32_t i;
    for (i = 0u; i < GUARD_LEN; i++) {
        if (g->base[i] != (uint8_t)GUARD_BYTE) {
            return 0;
        }
        if (g->data[g->len + i] != (uint8_t)GUARD_BYTE) {
            return 0;
        }
    }
    return 1;
}

/* True when the caller-visible region still holds `byte` in every position and
 * the sentinels are intact — that is, the library wrote nothing at all. A call
 * that correctly reports failure but fills the output buffer anyway still hands
 * the caller key material it must not have, and guarded_intact alone, which only
 * inspects the sentinels, would not notice. */
static int guarded_untouched(const guarded_t *g, uint8_t byte)
{
    uint32_t i;
    for (i = 0u; i < g->len; i++) {
        if (g->data[i] != byte) {
            return 0;
        }
    }
    return guarded_intact(g);
}

static void guarded_free(guarded_t *g)
{
    free(g->base);
    g->base = NULL;
    g->data = NULL;
    g->len = 0u;
}

/* ------------------------------------------------------------------------- */
/* Hex helpers                                                                */
/* ------------------------------------------------------------------------- */

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return 10 + (c - 'a'); }
    if (c >= 'A' && c <= 'F') { return 10 + (c - 'A'); }
    return -1;
}

/* Decodes hex into out, returning the byte count, or aborting on a malformed
 * literal. A typo in a test vector is a bug in the test, not a finding. */
static uint32_t unhex(const char *hex, uint8_t *out, uint32_t out_cap)
{
    size_t n = strlen(hex);
    uint32_t i;
    if ((n % 2u) != 0u || (n / 2u) > (size_t)out_cap) {
        fprintf(stderr, "malformed hex literal of length %zu\n", n);
        exit(2);
    }
    for (i = 0u; i < (uint32_t)(n / 2u); i++) {
        int hi = hex_nibble(hex[2u * i]);
        int lo = hex_nibble(hex[2u * i + 1u]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "malformed hex literal: %s\n", hex);
            exit(2);
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (uint32_t)(n / 2u);
}

static int bytes_eq_hex(const uint8_t *got, uint32_t got_len, const char *want_hex)
{
    uint8_t want[8192];
    uint32_t want_len = unhex(want_hex, want, (uint32_t)sizeof(want));
    if (want_len != got_len) {
        return 0;
    }
    return memcmp(got, want, (size_t)got_len) == 0;
}

/* True when every byte in the region is zero. Used to check that a failed
 * decrypt did not leave usable plaintext behind. */
static int all_zero(const uint8_t *p, uint32_t len)
{
    uint32_t i;
    for (i = 0u; i < len; i++) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

/* Whether `needle` appears in the first `hay_len` bytes of `hay`. The library's
 * string outputs are not NUL-terminated, so strstr is not usable directly. */
static int contains(const uint8_t *hay, uint32_t hay_len, const char *needle)
{
    size_t n = strlen(needle);
    uint32_t i;
    if ((size_t)hay_len < n) {
        return 0;
    }
    for (i = 0u; i + (uint32_t)n <= hay_len; i++) {
        if (memcmp(hay + i, needle, n) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Post-quantum availability                                                  */
/* ------------------------------------------------------------------------- */

/*
 * Whether this build actually performs post-quantum operations.
 *
 * Read from the library rather than from a build flag on purpose. A C consumer
 * has no visibility into the Zig build options, so the only thing it can gate on
 * is what the ABI reports — which is exactly the position a downstream caller is
 * in. Gating the tests the same way means a build whose reported capability and
 * implemented behaviour disagree fails here instead of silently adapting.
 *
 * test_capabilities() separately proves this one report agrees with the feature
 * bit and the algorithm string, so caching a single query is safe.
 */
static int pq_enabled(void)
{
    static int cached = -1;
    if (cached < 0) {
        cached = zcrypto_has_post_quantum().success ? 1 : 0;
    }
    return cached;
}

/* ------------------------------------------------------------------------- */
/* ABI layout                                                                 */
/* ------------------------------------------------------------------------- */

/*
 * If the result struct this header describes is not the struct the library
 * returns, every other check in this file is reading garbage. Assert the shape
 * first, at compile time where possible.
 */
static void test_abi_layout(void)
{
    group("ABI layout");

    CHECK(sizeof(zcrypto_result_t) == 12u);
    CHECK(offsetof(zcrypto_result_t, success) == 0u);
    CHECK(offsetof(zcrypto_result_t, data_len) == 4u);
    CHECK(offsetof(zcrypto_result_t, error_code) == 8u);
    CHECK(sizeof(bool) == 1u);
}

/* ------------------------------------------------------------------------- */
/* Version and capability reporting                                           */
/* ------------------------------------------------------------------------- */

/*
 * The point of these checks is agreement, not content. A build that compiles
 * post-quantum out must say so consistently through every channel that reports
 * it, and the entry points must then refuse rather than fabricate success.
 */
static void test_capabilities(void)
{
    guarded_t buf = guarded_new(256u);
    guarded_t tiny = guarded_new(4u);
    uint32_t features = 0u;
    uint32_t algs_len;
    bool pq_flag;
    bool pq_bit;
    bool pq_advertised;

    group("capabilities");

    /* Version: reported length, and rejection of a buffer that is too small. */
    {
        zcrypto_result_t r = zcrypto_version(buf.data, buf.len);
        EXPECT_OK(r);
        CHECK(r.data_len > 0u);
        CHECK(guarded_intact(&buf));
        CHECK(contains(buf.data, r.data_len, "zcrypto"));

        EXPECT_ERR(zcrypto_version(tiny.data, tiny.len), ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        CHECK(guarded_intact(&tiny));

        EXPECT_ERR(zcrypto_version(NULL, 256u), ZCRYPTO_ERROR_NULL_POINTER);
    }

    /* Feature bitmask. */
    EXPECT_OK(zcrypto_get_features(&features));
    EXPECT_ERR(zcrypto_get_features(NULL), ZCRYPTO_ERROR_NULL_POINTER);

    /* QUIC crypto is unconditional in this ABI, so its bit must always be set;
     * if it ever is not, the packet entry points below are lying. */
    CHECK((features & ZCRYPTO_FEATURE_QUIC_CRYPTO) != 0u);

    /* Three independent reports of post-quantum availability must agree. */
    {
        zcrypto_result_t r = zcrypto_has_post_quantum();
        pq_flag = r.success;
        CHECK(r.error_code == (pq_flag ? ZCRYPTO_OK : ZCRYPTO_ERROR_POST_QUANTUM_FAILED));
    }

    pq_bit = (features & ZCRYPTO_FEATURE_POST_QUANTUM) != 0u;
    CHECK(pq_flag == pq_bit);

    /* Hybrid crypto is set from the same build flag as post-quantum, so the two
     * bits cannot disagree. */
    CHECK(pq_bit == ((features & ZCRYPTO_FEATURE_HYBRID_CRYPTO) != 0u));

    {
        zcrypto_result_t r = zcrypto_supported_algorithms(buf.data, buf.len);
        EXPECT_OK(r);
        algs_len = r.data_len;
        CHECK(algs_len > 0u);
        CHECK(guarded_intact(&buf));

        /* Classical algorithms are always present. */
        CHECK(contains(buf.data, algs_len, "Ed25519"));
        CHECK(contains(buf.data, algs_len, "AES-256-GCM"));

        /* Post-quantum names must appear if and only if PQ is compiled in.
         * Advertising an algorithm the build cannot perform is the specific
         * failure this check exists to catch. */
        pq_advertised = contains(buf.data, algs_len, "ML-KEM-768") ? true : false;
        CHECK(pq_advertised == pq_flag);
        CHECK((contains(buf.data, algs_len, "ML-DSA-65") ? true : false) == pq_flag);

        EXPECT_ERR(zcrypto_supported_algorithms(tiny.data, tiny.len),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        EXPECT_ERR(zcrypto_supported_algorithms(NULL, 256u), ZCRYPTO_ERROR_NULL_POINTER);
    }

    guarded_free(&buf);
    guarded_free(&tiny);
}

/* ------------------------------------------------------------------------- */
/* Cipher suite metadata                                                      */
/* ------------------------------------------------------------------------- */

static void test_cipher_suite_info(void)
{
    uint32_t key_len = 0u;
    uint32_t hash_len = 0u;

    group("cipher suite info");

    EXPECT_OK(zcrypto_cipher_suite_info(ZCRYPTO_CIPHER_AES_128_GCM_SHA256, &key_len, &hash_len));
    CHECK(key_len == 16u);
    CHECK(hash_len == 32u);

    EXPECT_OK(zcrypto_cipher_suite_info(ZCRYPTO_CIPHER_AES_256_GCM_SHA384, &key_len, &hash_len));
    CHECK(key_len == 32u);
    CHECK(hash_len == 48u);

    EXPECT_OK(zcrypto_cipher_suite_info(ZCRYPTO_CIPHER_CHACHA20_POLY1305_SHA256, &key_len, &hash_len));
    CHECK(key_len == 32u);
    CHECK(hash_len == 32u);

    EXPECT_OK(zcrypto_cipher_suite_info(ZCRYPTO_CIPHER_ML_KEM_768_X25519_AES256_GCM_SHA384,
                                        &key_len, &hash_len));
    CHECK(key_len == 32u);
    CHECK(hash_len == 48u);

    /* Unknown identifiers are rejected, including the value just past the end
     * of the enumeration and the maximum. */
    EXPECT_ERR(zcrypto_cipher_suite_info(4u, &key_len, &hash_len), ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_cipher_suite_info(0xFFFFFFFFu, &key_len, &hash_len),
               ZCRYPTO_ERROR_INVALID_INPUT);

    /* Null output pointers are rejected before anything is written. */
    EXPECT_ERR(zcrypto_cipher_suite_info(0u, NULL, &hash_len), ZCRYPTO_ERROR_NULL_POINTER);
    EXPECT_ERR(zcrypto_cipher_suite_info(0u, &key_len, NULL), ZCRYPTO_ERROR_NULL_POINTER);
    EXPECT_ERR(zcrypto_cipher_suite_info(0u, NULL, NULL), ZCRYPTO_ERROR_NULL_POINTER);
}

/* ------------------------------------------------------------------------- */
/* Hashing                                                                    */
/* ------------------------------------------------------------------------- */

/*
 * Expected digests are the published values for SHA-256 (FIPS 180-4) and
 * BLAKE2b-512 (RFC 7693), so this checks the library against the standard
 * rather than against itself.
 *
 * The capacity matrix is the same for both: zero, one short, exact, and
 * oversized. Exact must succeed and must not touch the sentinel; oversized must
 * succeed and write only the digest; anything short must be refused.
 */
static void test_sha256(void)
{
    group("SHA-256");

    /* Empty input, exact capacity. */
    {
        guarded_t out = guarded_new(ZCRYPTO_SHA256_SIZE);
        zcrypto_result_t r = zcrypto_sha256(NULL, 0u, out.data, out.len);
        EXPECT_OK(r);
        CHECK(r.data_len == ZCRYPTO_SHA256_SIZE);
        CHECK(bytes_eq_hex(out.data, r.data_len,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        CHECK(guarded_intact(&out));
        guarded_free(&out);
    }

    /* "abc", exact capacity. */
    {
        guarded_t out = guarded_new(ZCRYPTO_SHA256_SIZE);
        const uint8_t msg[] = { 'a', 'b', 'c' };
        zcrypto_result_t r = zcrypto_sha256(msg, 3u, out.data, out.len);
        EXPECT_OK(r);
        CHECK(bytes_eq_hex(out.data, r.data_len,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        CHECK(guarded_intact(&out));
        guarded_free(&out);
    }

    /* Oversized capacity: succeeds, reports the digest length, and leaves the
     * bytes past the digest untouched rather than padding them. */
    {
        guarded_t out = guarded_new(ZCRYPTO_SHA256_SIZE + 64u);
        const uint8_t msg[] = { 'a', 'b', 'c' };
        zcrypto_result_t r;
        guarded_fill(&out, 0xEE);
        r = zcrypto_sha256(msg, 3u, out.data, out.len);
        EXPECT_OK(r);
        CHECK(r.data_len == ZCRYPTO_SHA256_SIZE);
        CHECK(bytes_eq_hex(out.data, ZCRYPTO_SHA256_SIZE,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        CHECK(out.data[ZCRYPTO_SHA256_SIZE] == 0xEEu);
        CHECK(guarded_intact(&out));
        guarded_free(&out);
    }

    /* One byte short, and zero: refused, and nothing written. */
    {
        guarded_t out = guarded_new(ZCRYPTO_SHA256_SIZE);
        const uint8_t msg[] = { 'a', 'b', 'c' };
        guarded_fill(&out, 0xEE);

        EXPECT_ERR(zcrypto_sha256(msg, 3u, out.data, ZCRYPTO_SHA256_SIZE - 1u),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        EXPECT_ERR(zcrypto_sha256(msg, 3u, out.data, 0u),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);

        CHECK(out.data[0] == 0xEEu);
        CHECK(guarded_intact(&out));
        guarded_free(&out);
    }

    /* Null combinations permitted and forbidden by the ABI. */
    {
        guarded_t out = guarded_new(ZCRYPTO_SHA256_SIZE);
        const uint8_t msg[] = { 'a' };

        /* Null output is never acceptable. */
        EXPECT_ERR(zcrypto_sha256(msg, 1u, NULL, ZCRYPTO_SHA256_SIZE),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        /* Null input with a non-zero length is a lie about the input. */
        EXPECT_ERR(zcrypto_sha256(NULL, 1u, out.data, out.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        /* An input length beyond the documented maximum is refused without the
         * caller having to allocate anything of that size. */
        EXPECT_ERR(zcrypto_sha256(msg, ZCRYPTO_MAX_INPUT_SIZE + 1u, out.data, out.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        EXPECT_ERR(zcrypto_sha256(msg, 0xFFFFFFFFu, out.data, out.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);

        CHECK(guarded_intact(&out));
        guarded_free(&out);
    }
}

static void test_blake2b(void)
{
    group("BLAKE2b-512");

    {
        guarded_t out = guarded_new(ZCRYPTO_BLAKE2B_SIZE);
        zcrypto_result_t r = zcrypto_blake2b(NULL, 0u, out.data, out.len);
        EXPECT_OK(r);
        CHECK(r.data_len == ZCRYPTO_BLAKE2B_SIZE);
        CHECK(bytes_eq_hex(out.data, r.data_len,
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
            "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"));
        CHECK(guarded_intact(&out));
        guarded_free(&out);
    }

    {
        guarded_t out = guarded_new(ZCRYPTO_BLAKE2B_SIZE);
        const uint8_t msg[] = { 'a', 'b', 'c' };
        zcrypto_result_t r = zcrypto_blake2b(msg, 3u, out.data, out.len);
        EXPECT_OK(r);
        CHECK(bytes_eq_hex(out.data, r.data_len,
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"));
        CHECK(guarded_intact(&out));
        guarded_free(&out);
    }

    {
        guarded_t out = guarded_new(ZCRYPTO_BLAKE2B_SIZE);
        const uint8_t msg[] = { 'a', 'b', 'c' };
        EXPECT_ERR(zcrypto_blake2b(msg, 3u, out.data, ZCRYPTO_BLAKE2B_SIZE - 1u),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        EXPECT_ERR(zcrypto_blake2b(msg, 3u, out.data, 0u),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        EXPECT_ERR(zcrypto_blake2b(NULL, 1u, out.data, out.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        CHECK(guarded_intact(&out));
        guarded_free(&out);
    }
}

/* ------------------------------------------------------------------------- */
/* HKDF-SHA256                                                                */
/* ------------------------------------------------------------------------- */

/* RFC 5869 Appendix A.1, the SHA-256 basic test case. */
static void test_hkdf(void)
{
    uint8_t ikm[64];
    uint8_t salt[64];
    uint8_t info[64];
    uint32_t ikm_len;
    uint32_t salt_len;
    uint32_t info_len;
    guarded_t prk = guarded_new(ZCRYPTO_HKDF_PRK_SIZE);

    group("HKDF-SHA256");

    ikm_len = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm, (uint32_t)sizeof(ikm));
    salt_len = unhex("000102030405060708090a0b0c", salt, (uint32_t)sizeof(salt));
    info_len = unhex("f0f1f2f3f4f5f6f7f8f9", info, (uint32_t)sizeof(info));

    {
        zcrypto_result_t r = zcrypto_hkdf_extract(salt, salt_len, ikm, ikm_len, prk.data, prk.len);
        EXPECT_OK(r);
        CHECK(r.data_len == ZCRYPTO_HKDF_PRK_SIZE);
        CHECK(bytes_eq_hex(prk.data, r.data_len,
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
        CHECK(guarded_intact(&prk));
    }

    {
        guarded_t okm = guarded_new(42u);
        zcrypto_result_t r = zcrypto_hkdf_expand(prk.data, prk.len, info, info_len,
                                                 okm.data, okm.len);
        EXPECT_OK(r);
        CHECK(r.data_len == 42u);
        CHECK(bytes_eq_hex(okm.data, r.data_len,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"));
        CHECK(guarded_intact(&okm));
        guarded_free(&okm);
    }

    /* Extract: a PRK buffer shorter than the digest is refused; salt may be
     * null when its length is zero, which selects the all-zero salt. */
    {
        guarded_t small = guarded_new(ZCRYPTO_HKDF_PRK_SIZE);
        EXPECT_ERR(zcrypto_hkdf_extract(salt, salt_len, ikm, ikm_len,
                                        small.data, ZCRYPTO_HKDF_PRK_SIZE - 1u),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        EXPECT_ERR(zcrypto_hkdf_extract(salt, salt_len, ikm, ikm_len, NULL, ZCRYPTO_HKDF_PRK_SIZE),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        EXPECT_OK(zcrypto_hkdf_extract(NULL, 0u, ikm, ikm_len, small.data, small.len));
        EXPECT_ERR(zcrypto_hkdf_extract(salt, salt_len, NULL, 1u, small.data, small.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        CHECK(guarded_intact(&small));
        guarded_free(&small);
    }

    /* Expand: the PRK length is exact, not a minimum, and the output length is
     * capped by RFC 5869 at 255 * hash_len. */
    {
        guarded_t okm = guarded_new(32u);
        EXPECT_ERR(zcrypto_hkdf_expand(prk.data, ZCRYPTO_HKDF_PRK_SIZE - 1u, info, info_len,
                                       okm.data, okm.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        EXPECT_ERR(zcrypto_hkdf_expand(prk.data, ZCRYPTO_HKDF_PRK_SIZE + 1u, info, info_len,
                                       okm.data, okm.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        EXPECT_ERR(zcrypto_hkdf_expand(NULL, ZCRYPTO_HKDF_PRK_SIZE, info, info_len,
                                       okm.data, okm.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        /* Over-long output is rejected on the length argument alone; no buffer
         * of that size is ever allocated by this test. */
        EXPECT_ERR(zcrypto_hkdf_expand(prk.data, prk.len, info, info_len,
                                       okm.data, ZCRYPTO_HKDF_MAX_OKM_SIZE + 1u),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        /* Info longer than the documented maximum is refused. */
        EXPECT_ERR(zcrypto_hkdf_expand(prk.data, prk.len, info, ZCRYPTO_HKDF_MAX_INFO_SIZE + 1u,
                                       okm.data, okm.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        CHECK(guarded_intact(&okm));
        guarded_free(&okm);
    }

    guarded_free(&prk);
}

/* ------------------------------------------------------------------------- */
/* AES-256-GCM                                                                */
/* ------------------------------------------------------------------------- */

/*
 * Expected ciphertexts are NIST GCM test cases 13 and 14 for AES-256. Because
 * this ABI appends the tag to the ciphertext, the expected output is the test
 * case's C concatenated with its T.
 */
static void test_aes256_gcm_vectors(void)
{
    uint8_t key[ZCRYPTO_AES256_GCM_KEY_SIZE];
    uint8_t nonce[ZCRYPTO_AES256_GCM_NONCE_SIZE];

    group("AES-256-GCM vectors");

    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));

    /* Case 13: empty plaintext, empty AAD. Output is the tag alone, and an
     * empty message must be accepted rather than rejected as degenerate. */
    {
        guarded_t ct = guarded_new(ZCRYPTO_AES256_GCM_TAG_SIZE);
        zcrypto_result_t r = zcrypto_aes256_gcm_encrypt(key, (uint32_t)sizeof(key),
                                                        nonce, (uint32_t)sizeof(nonce),
                                                        NULL, 0u, NULL, 0u,
                                                        ct.data, ct.len);
        EXPECT_OK(r);
        CHECK(r.data_len == ZCRYPTO_AES256_GCM_TAG_SIZE);
        CHECK(bytes_eq_hex(ct.data, r.data_len, "530f8afbc74536b9a963b4f1c4cb738b"));
        CHECK(guarded_intact(&ct));

        /* And it round-trips back to nothing. */
        {
            guarded_t pt = guarded_new(1u);
            zcrypto_result_t d = zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                                            nonce, (uint32_t)sizeof(nonce),
                                                            NULL, 0u, ct.data, ct.len,
                                                            pt.data, pt.len);
            EXPECT_OK(d);
            CHECK(d.data_len == 0u);
            CHECK(guarded_intact(&pt));
            guarded_free(&pt);
        }
        guarded_free(&ct);
    }

    /* Case 14: 16 zero bytes of plaintext, empty AAD. */
    {
        uint8_t pt_in[16];
        guarded_t ct = guarded_new(16u + ZCRYPTO_AES256_GCM_TAG_SIZE);
        zcrypto_result_t r;
        memset(pt_in, 0, sizeof(pt_in));

        r = zcrypto_aes256_gcm_encrypt(key, (uint32_t)sizeof(key),
                                       nonce, (uint32_t)sizeof(nonce),
                                       NULL, 0u, pt_in, (uint32_t)sizeof(pt_in),
                                       ct.data, ct.len);
        EXPECT_OK(r);
        CHECK(r.data_len == 16u + ZCRYPTO_AES256_GCM_TAG_SIZE);
        CHECK(bytes_eq_hex(ct.data, r.data_len,
            "cea7403d4d606b6e074ec5d3baf39d18"
            "d0d1c8a799996bf0265b98b5d48ab919"));
        CHECK(guarded_intact(&ct));

        {
            guarded_t pt = guarded_new(16u);
            zcrypto_result_t d = zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                                            nonce, (uint32_t)sizeof(nonce),
                                                            NULL, 0u, ct.data, ct.len,
                                                            pt.data, pt.len);
            EXPECT_OK(d);
            CHECK(d.data_len == 16u);
            CHECK(all_zero(pt.data, 16u));
            CHECK(guarded_intact(&pt));
            guarded_free(&pt);
        }
        guarded_free(&ct);
    }
}

/*
 * The negative half: wrong sizes, wrong capacities, and ciphertext the caller
 * should not be able to decrypt. The decrypt-failure cases also assert what the
 * output buffer contains afterwards, because "it failed" is not sufficient if
 * the plaintext is sitting in the caller's buffer anyway.
 */
static void test_aes256_gcm_negative(void)
{
    uint8_t key[ZCRYPTO_AES256_GCM_KEY_SIZE];
    uint8_t nonce[ZCRYPTO_AES256_GCM_NONCE_SIZE];
    uint8_t aad[8];
    const uint8_t msg[] = "attack at dawn";
    const uint32_t msg_len = (uint32_t)sizeof(msg) - 1u; /* drop the NUL */
    const uint32_t ct_len = msg_len + ZCRYPTO_AES256_GCM_TAG_SIZE;
    guarded_t ct = guarded_new(ct_len);
    uint32_t i;

    group("AES-256-GCM negative");

    for (i = 0u; i < (uint32_t)sizeof(key); i++)   { key[i] = (uint8_t)(i + 1u); }
    for (i = 0u; i < (uint32_t)sizeof(nonce); i++) { nonce[i] = (uint8_t)(0x40u + i); }
    for (i = 0u; i < (uint32_t)sizeof(aad); i++)   { aad[i] = (uint8_t)(0x90u + i); }

    EXPECT_OK(zcrypto_aes256_gcm_encrypt(key, (uint32_t)sizeof(key),
                                         nonce, (uint32_t)sizeof(nonce),
                                         aad, (uint32_t)sizeof(aad),
                                         msg, msg_len, ct.data, ct.len));
    CHECK(guarded_intact(&ct));

    /* Encrypt: key and nonce lengths are exact, not minimums. */
    {
        guarded_t out = guarded_new(ct_len);
        EXPECT_ERR(zcrypto_aes256_gcm_encrypt(key, 31u, nonce, (uint32_t)sizeof(nonce),
                                              NULL, 0u, msg, msg_len, out.data, out.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        EXPECT_ERR(zcrypto_aes256_gcm_encrypt(key, 33u, nonce, (uint32_t)sizeof(nonce),
                                              NULL, 0u, msg, msg_len, out.data, out.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        EXPECT_ERR(zcrypto_aes256_gcm_encrypt(key, (uint32_t)sizeof(key), nonce, 11u,
                                              NULL, 0u, msg, msg_len, out.data, out.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        EXPECT_ERR(zcrypto_aes256_gcm_encrypt(key, (uint32_t)sizeof(key), nonce, 13u,
                                              NULL, 0u, msg, msg_len, out.data, out.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        EXPECT_ERR(zcrypto_aes256_gcm_encrypt(NULL, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              NULL, 0u, msg, msg_len, out.data, out.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        CHECK(guarded_intact(&out));
        guarded_free(&out);
    }

    /* Encrypt capacity: exact succeeds, one short is refused, zero is refused,
     * oversized succeeds and still reports the true length. */
    {
        guarded_t out = guarded_new(ct_len + 64u);
        zcrypto_result_t r;

        EXPECT_ERR(zcrypto_aes256_gcm_encrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              NULL, 0u, msg, msg_len,
                                              out.data, ct_len - 1u),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        EXPECT_ERR(zcrypto_aes256_gcm_encrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              NULL, 0u, msg, msg_len, out.data, 0u),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        r = zcrypto_aes256_gcm_encrypt(key, (uint32_t)sizeof(key),
                                       nonce, (uint32_t)sizeof(nonce),
                                       NULL, 0u, msg, msg_len, out.data, out.len);
        EXPECT_OK(r);
        CHECK(r.data_len == ct_len);
        CHECK(guarded_intact(&out));
        guarded_free(&out);
    }

    /* Decrypt: a ciphertext shorter than the tag cannot be authenticated and is
     * rejected as malformed input rather than as a failed decryption. */
    {
        guarded_t pt = guarded_new(msg_len);
        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              aad, (uint32_t)sizeof(aad),
                                              ct.data, ZCRYPTO_AES256_GCM_TAG_SIZE - 1u,
                                              pt.data, pt.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              aad, (uint32_t)sizeof(aad),
                                              ct.data, 0u, pt.data, pt.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        CHECK(guarded_intact(&pt));
        guarded_free(&pt);
    }

    /* Decrypt capacity: one byte short of the payload is refused. */
    {
        guarded_t pt = guarded_new(msg_len);
        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              aad, (uint32_t)sizeof(aad),
                                              ct.data, ct.len, pt.data, msg_len - 1u),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        CHECK(guarded_intact(&pt));
        guarded_free(&pt);
    }

    /* Null parameters on the decrypt side. Encrypt was covered above and decrypt
     * was not, which is the direction that matters more: these pointers are
     * `allowzero` precisely so the null guard survives optimization, and an
     * untested guard is one the optimizer may delete without any test noticing.
     *
     * A null *output* buffer reports INSUFFICIENT_BUFFER rather than
     * NULL_POINTER. That is not an oversight to be tidied up later: every entry
     * point that validates an output buffer reports it the same way, because the
     * null check and the capacity check share one helper. Asserted here so the
     * uniformity is pinned rather than rediscovered. */
    {
        guarded_t pt = guarded_new(msg_len);
        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(NULL, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              aad, (uint32_t)sizeof(aad),
                                              ct.data, ct.len, pt.data, pt.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              NULL, (uint32_t)sizeof(nonce),
                                              aad, (uint32_t)sizeof(aad),
                                              ct.data, ct.len, pt.data, pt.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        /* A null AAD with a non-zero length is a lie about the buffer and is
         * refused; the encrypt tests already show null with length zero is fine. */
        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              NULL, 8u,
                                              ct.data, ct.len, pt.data, pt.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              aad, (uint32_t)sizeof(aad),
                                              NULL, ct_len, pt.data, pt.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              aad, (uint32_t)sizeof(aad),
                                              ct.data, ct.len, NULL, msg_len),
                   ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
        CHECK(guarded_intact(&pt));
        guarded_free(&pt);
    }

    /* Tampered ciphertext body: authentication must fail, and the caller's
     * output buffer must not be left holding usable plaintext. */
    {
        guarded_t bad = guarded_new(ct_len);
        guarded_t pt = guarded_new(msg_len);
        memcpy(bad.data, ct.data, (size_t)ct_len);
        bad.data[0] ^= 0x01u;
        guarded_fill(&pt, 0xEE);

        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              aad, (uint32_t)sizeof(aad),
                                              bad.data, bad.len, pt.data, pt.len),
                   ZCRYPTO_ERROR_DECRYPTION_FAILED);
        CHECK(all_zero(pt.data, msg_len));
        CHECK(memcmp(pt.data, msg, (size_t)msg_len) != 0);
        CHECK(guarded_intact(&pt));
        guarded_free(&pt);
        guarded_free(&bad);
    }

    /* Tampered tag. */
    {
        guarded_t bad = guarded_new(ct_len);
        guarded_t pt = guarded_new(msg_len);
        memcpy(bad.data, ct.data, (size_t)ct_len);
        bad.data[ct_len - 1u] ^= 0x80u;
        guarded_fill(&pt, 0xEE);

        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              aad, (uint32_t)sizeof(aad),
                                              bad.data, bad.len, pt.data, pt.len),
                   ZCRYPTO_ERROR_DECRYPTION_FAILED);
        CHECK(all_zero(pt.data, msg_len));
        CHECK(guarded_intact(&pt));
        guarded_free(&pt);
        guarded_free(&bad);
    }

    /* Truncated ciphertext: still long enough to contain a tag, so it reaches
     * authentication and fails there. */
    {
        guarded_t pt = guarded_new(msg_len);
        guarded_fill(&pt, 0xEE);
        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              aad, (uint32_t)sizeof(aad),
                                              ct.data, ct_len - 1u, pt.data, pt.len),
                   ZCRYPTO_ERROR_DECRYPTION_FAILED);
        CHECK(guarded_intact(&pt));
        guarded_free(&pt);
    }

    /* Wrong AAD, wrong nonce, and wrong key each fail authentication. Dropping
     * the AAD entirely must not silently succeed. */
    {
        guarded_t pt = guarded_new(msg_len);
        uint8_t other[ZCRYPTO_AES256_GCM_KEY_SIZE];
        uint8_t bad_aad[8];

        memcpy(other, key, sizeof(other));
        other[0] ^= 0xFFu;
        memcpy(bad_aad, aad, sizeof(bad_aad));
        bad_aad[0] ^= 0xFFu;

        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              bad_aad, (uint32_t)sizeof(bad_aad),
                                              ct.data, ct.len, pt.data, pt.len),
                   ZCRYPTO_ERROR_DECRYPTION_FAILED);
        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                              nonce, (uint32_t)sizeof(nonce),
                                              NULL, 0u,
                                              ct.data, ct.len, pt.data, pt.len),
                   ZCRYPTO_ERROR_DECRYPTION_FAILED);
        EXPECT_ERR(zcrypto_aes256_gcm_decrypt(other, (uint32_t)sizeof(other),
                                              nonce, (uint32_t)sizeof(nonce),
                                              aad, (uint32_t)sizeof(aad),
                                              ct.data, ct.len, pt.data, pt.len),
                   ZCRYPTO_ERROR_DECRYPTION_FAILED);
        CHECK(guarded_intact(&pt));
        guarded_free(&pt);
    }

    /* A correct decrypt still works after all of the above, proving the failures
     * above were rejections and not a wedged context. */
    {
        guarded_t pt = guarded_new(msg_len);
        zcrypto_result_t d = zcrypto_aes256_gcm_decrypt(key, (uint32_t)sizeof(key),
                                                        nonce, (uint32_t)sizeof(nonce),
                                                        aad, (uint32_t)sizeof(aad),
                                                        ct.data, ct.len, pt.data, pt.len);
        EXPECT_OK(d);
        CHECK(d.data_len == msg_len);
        CHECK(memcmp(pt.data, msg, (size_t)msg_len) == 0);
        CHECK(guarded_intact(&pt));
        guarded_free(&pt);
    }

    guarded_free(&ct);
}

/* ------------------------------------------------------------------------- */
/* Ed25519                                                                    */
/* ------------------------------------------------------------------------- */

/*
 * Signature vectors are RFC 8032 section 7.1 TEST 1 and TEST 2. TEST 1 signs an
 * empty message, which doubles as the empty-input case for this algorithm.
 *
 * Each vector is signed twice: once with the 32-byte seed and once with the
 * 64-byte expanded key. Ed25519 is deterministic, so both must produce the
 * published signature byte for byte.
 */
static void ed25519_vector(const char *seed_hex, const char *pk_hex,
                           const char *msg_hex, const char *sig_hex)
{
    uint8_t seed[32];
    uint8_t pk[32];
    uint8_t expanded[64];
    uint8_t msg[64];
    uint32_t msg_len;
    guarded_t sig = guarded_new(ZCRYPTO_ED25519_SIGNATURE_SIZE);

    (void)unhex(seed_hex, seed, (uint32_t)sizeof(seed));
    (void)unhex(pk_hex, pk, (uint32_t)sizeof(pk));
    msg_len = unhex(msg_hex, msg, (uint32_t)sizeof(msg));

    memcpy(expanded, seed, sizeof(seed));
    memcpy(expanded + 32, pk, sizeof(pk));

    /* 32-byte seed form. */
    {
        zcrypto_result_t r = zcrypto_ed25519_sign(msg_len ? msg : NULL, msg_len,
                                                  seed, (uint32_t)sizeof(seed),
                                                  sig.data, sig.len);
        EXPECT_OK(r);
        CHECK(r.data_len == ZCRYPTO_ED25519_SIGNATURE_SIZE);
        CHECK(bytes_eq_hex(sig.data, r.data_len, sig_hex));
        CHECK(guarded_intact(&sig));
    }

    /* 64-byte expanded form must agree with the seed form. */
    {
        guarded_t sig2 = guarded_new(ZCRYPTO_ED25519_SIGNATURE_SIZE);
        zcrypto_result_t r = zcrypto_ed25519_sign(msg_len ? msg : NULL, msg_len,
                                                  expanded, (uint32_t)sizeof(expanded),
                                                  sig2.data, sig2.len);
        EXPECT_OK(r);
        CHECK(bytes_eq_hex(sig2.data, r.data_len, sig_hex));
        CHECK(memcmp(sig.data, sig2.data, ZCRYPTO_ED25519_SIGNATURE_SIZE) == 0);
        CHECK(guarded_intact(&sig2));
        guarded_free(&sig2);
    }

    /* The published signature verifies against the published public key. */
    EXPECT_OK(zcrypto_ed25519_verify(msg_len ? msg : NULL, msg_len,
                                     sig.data, sig.len, pk, (uint32_t)sizeof(pk)));

    /* Flipping any single bit of the signature must break verification. */
    {
        guarded_t bad = guarded_new(ZCRYPTO_ED25519_SIGNATURE_SIZE);
        memcpy(bad.data, sig.data, ZCRYPTO_ED25519_SIGNATURE_SIZE);
        bad.data[0] ^= 0x01u;
        EXPECT_ERR(zcrypto_ed25519_verify(msg_len ? msg : NULL, msg_len,
                                          bad.data, bad.len, pk, (uint32_t)sizeof(pk)),
                   ZCRYPTO_ERROR_VERIFICATION_FAILED);
        /* Also the last byte, which is the scalar half rather than the point. */
        memcpy(bad.data, sig.data, ZCRYPTO_ED25519_SIGNATURE_SIZE);
        bad.data[ZCRYPTO_ED25519_SIGNATURE_SIZE - 1u] ^= 0x08u;
        EXPECT_ERR(zcrypto_ed25519_verify(msg_len ? msg : NULL, msg_len,
                                          bad.data, bad.len, pk, (uint32_t)sizeof(pk)),
                   ZCRYPTO_ERROR_VERIFICATION_FAILED);
        CHECK(guarded_intact(&bad));
        guarded_free(&bad);
    }

    /* A valid signature must not verify under a different public key. */
    {
        uint8_t other_pk[32];
        memcpy(other_pk, pk, sizeof(other_pk));
        other_pk[0] ^= 0x01u;
        EXPECT_ERR(zcrypto_ed25519_verify(msg_len ? msg : NULL, msg_len,
                                          sig.data, sig.len, other_pk, (uint32_t)sizeof(other_pk)),
                   ZCRYPTO_ERROR_VERIFICATION_FAILED);
    }

    guarded_free(&sig);
}

static void test_ed25519(void)
{
    group("Ed25519");

    /* RFC 8032 TEST 1: empty message. */
    ed25519_vector(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    /* RFC 8032 TEST 2: single-byte message. */
    ed25519_vector(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da0"
        "85ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
}

/*
 * Key sizes are exact for this algorithm, and the sign path accepts two of
 * them. Anything else must be refused before the key is interpreted.
 */
static void test_ed25519_sizes(void)
{
    guarded_t pk = guarded_new(ZCRYPTO_ED25519_PUBLIC_KEY_SIZE);
    guarded_t sk = guarded_new(ZCRYPTO_ED25519_PRIVATE_KEY_SIZE);
    guarded_t sig = guarded_new(ZCRYPTO_ED25519_SIGNATURE_SIZE);
    const uint8_t msg[] = { 't', 'e', 's', 't' };

    group("Ed25519 sizes");

    /* Keygen capacity: exact succeeds; one short on either buffer is refused. */
    EXPECT_OK(zcrypto_ed25519_keygen(pk.data, pk.len, sk.data, sk.len));
    CHECK(guarded_intact(&pk));
    CHECK(guarded_intact(&sk));

    EXPECT_ERR(zcrypto_ed25519_keygen(pk.data, ZCRYPTO_ED25519_PUBLIC_KEY_SIZE - 1u,
                                      sk.data, sk.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ed25519_keygen(pk.data, pk.len,
                                      sk.data, ZCRYPTO_ED25519_PRIVATE_KEY_SIZE - 1u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ed25519_keygen(pk.data, 0u, sk.data, sk.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ed25519_keygen(NULL, pk.len, sk.data, sk.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ed25519_keygen(pk.data, pk.len, NULL, sk.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);

    /* A freshly generated key must produce a signature that verifies, and the
     * generated public key must be the one that verifies it. */
    EXPECT_OK(zcrypto_ed25519_sign(msg, (uint32_t)sizeof(msg), sk.data, sk.len,
                                   sig.data, sig.len));
    EXPECT_OK(zcrypto_ed25519_verify(msg, (uint32_t)sizeof(msg), sig.data, sig.len,
                                     pk.data, pk.len));

    /* Sign: private key lengths other than 32 or 64 are refused. */
    EXPECT_ERR(zcrypto_ed25519_sign(msg, (uint32_t)sizeof(msg), sk.data, 31u, sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ed25519_sign(msg, (uint32_t)sizeof(msg), sk.data, 33u, sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ed25519_sign(msg, (uint32_t)sizeof(msg), sk.data, 63u, sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ed25519_sign(msg, (uint32_t)sizeof(msg), sk.data, 65u, sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ed25519_sign(msg, (uint32_t)sizeof(msg), sk.data, 0u, sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ed25519_sign(msg, (uint32_t)sizeof(msg), NULL, 64u, sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);

    /* Sign: signature buffer capacity is a minimum of 64. */
    EXPECT_ERR(zcrypto_ed25519_sign(msg, (uint32_t)sizeof(msg), sk.data, sk.len,
                                    sig.data, ZCRYPTO_ED25519_SIGNATURE_SIZE - 1u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ed25519_sign(msg, (uint32_t)sizeof(msg), sk.data, sk.len, sig.data, 0u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ed25519_sign(msg, (uint32_t)sizeof(msg), sk.data, sk.len, NULL, 64u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);

    /* Sign: a null message with a non-zero length is rejected. */
    EXPECT_ERR(zcrypto_ed25519_sign(NULL, 1u, sk.data, sk.len, sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);

    /* Verify: signature and public key lengths are exact. */
    EXPECT_ERR(zcrypto_ed25519_verify(msg, (uint32_t)sizeof(msg), sig.data, 63u,
                                      pk.data, pk.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ed25519_verify(msg, (uint32_t)sizeof(msg), sig.data, 65u,
                                      pk.data, pk.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ed25519_verify(msg, (uint32_t)sizeof(msg), sig.data, sig.len,
                                      pk.data, 31u),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ed25519_verify(msg, (uint32_t)sizeof(msg), sig.data, sig.len,
                                      pk.data, 33u),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ed25519_verify(msg, (uint32_t)sizeof(msg), NULL, 64u, pk.data, pk.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ed25519_verify(msg, (uint32_t)sizeof(msg), sig.data, sig.len, NULL, 32u),
               ZCRYPTO_ERROR_INVALID_INPUT);

    /* Verify: a signature over a different message must not verify. */
    {
        const uint8_t other[] = { 't', 'e', 's', 'u' };
        EXPECT_ERR(zcrypto_ed25519_verify(other, (uint32_t)sizeof(other), sig.data, sig.len,
                                          pk.data, pk.len),
                   ZCRYPTO_ERROR_VERIFICATION_FAILED);
    }

    CHECK(guarded_intact(&pk));
    CHECK(guarded_intact(&sk));
    CHECK(guarded_intact(&sig));

    guarded_free(&pk);
    guarded_free(&sk);
    guarded_free(&sig);
}

/* ------------------------------------------------------------------------- */
/* QUIC context ownership                                                     */
/* ------------------------------------------------------------------------- */

/*
 * The QUIC context is the only allocation in this ABI with an explicit release,
 * so it is the only place a C caller can leak or double-free. These checks are
 * about the handle discipline itself rather than about packet protection.
 */
static void test_quic_handle_lifecycle(void)
{
    guarded_t handle = guarded_new(ZCRYPTO_QUIC_HANDLE_SIZE);

    group("QUIC handle lifecycle");

    /* Handle buffer capacity: exact succeeds, short is refused. */
    EXPECT_ERR(zcrypto_quic_init(ZCRYPTO_CIPHER_AES_128_GCM_SHA256,
                                 handle.data, ZCRYPTO_QUIC_HANDLE_SIZE - 1u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_quic_init(ZCRYPTO_CIPHER_AES_128_GCM_SHA256, handle.data, 0u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_quic_init(ZCRYPTO_CIPHER_AES_128_GCM_SHA256, NULL,
                                 ZCRYPTO_QUIC_HANDLE_SIZE),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);

    /* Unknown cipher suites are refused without consuming a table slot; the
     * exhaustion check later would notice if they did. */
    EXPECT_ERR(zcrypto_quic_init(4u, handle.data, handle.len), ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_init(0xFFFFFFFFu, handle.data, handle.len),
               ZCRYPTO_ERROR_INVALID_INPUT);

    /* Acquire, then release exactly once. */
    {
        zcrypto_result_t r = zcrypto_quic_init(ZCRYPTO_CIPHER_AES_128_GCM_SHA256,
                                               handle.data, handle.len);
        EXPECT_OK(r);
        CHECK(r.data_len == ZCRYPTO_QUIC_HANDLE_SIZE);
        CHECK(guarded_intact(&handle));

        EXPECT_OK(zcrypto_quic_free(handle.data));

        /* Releasing the same handle again must be detected, not repeated. The
         * generation counter in the handle is what makes this observable. */
        EXPECT_ERR(zcrypto_quic_free(handle.data), ZCRYPTO_ERROR_INVALID_HANDLE);

        /* And the stale handle must not still address a live context. */
        {
            const uint8_t cid[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
            EXPECT_ERR(zcrypto_quic_derive_initial_keys(handle.data, cid, (uint32_t)sizeof(cid)),
                       ZCRYPTO_ERROR_INVALID_HANDLE);
        }
    }

    /* A handle the caller never obtained must be rejected rather than indexing
     * into the table. All-zero has the wrong magic; a corrupted magic on an
     * otherwise live handle must fail too. */
    {
        guarded_t bogus = guarded_new(ZCRYPTO_QUIC_HANDLE_SIZE);
        memset(bogus.data, 0, ZCRYPTO_QUIC_HANDLE_SIZE);
        EXPECT_ERR(zcrypto_quic_free(bogus.data), ZCRYPTO_ERROR_INVALID_HANDLE);

        memset(bogus.data, 0xFF, ZCRYPTO_QUIC_HANDLE_SIZE);
        EXPECT_ERR(zcrypto_quic_free(bogus.data), ZCRYPTO_ERROR_INVALID_HANDLE);
        CHECK(guarded_intact(&bogus));
        guarded_free(&bogus);
    }

    EXPECT_ERR(zcrypto_quic_free(NULL), ZCRYPTO_ERROR_NULL_POINTER);

    {
        zcrypto_result_t r = zcrypto_quic_init(ZCRYPTO_CIPHER_AES_128_GCM_SHA256,
                                               handle.data, handle.len);
        EXPECT_OK(r);

        /* Live handle with a corrupted magic field. */
        {
            guarded_t tweaked = guarded_new(ZCRYPTO_QUIC_HANDLE_SIZE);
            memcpy(tweaked.data, handle.data, ZCRYPTO_QUIC_HANDLE_SIZE);
            tweaked.data[0] ^= 0xFFu;
            EXPECT_ERR(zcrypto_quic_free(tweaked.data), ZCRYPTO_ERROR_INVALID_HANDLE);
            guarded_free(&tweaked);
        }

        EXPECT_OK(zcrypto_quic_free(handle.data));
    }

    guarded_free(&handle);
}

/*
 * Exhausting the fixed context table must report a distinct error rather than
 * overwriting a live slot, and the table must be fully reusable afterwards.
 * This is the check that would catch a leak in the allocate/release pairing.
 */
static void test_quic_handle_exhaustion(void)
{
    enum { CAPACITY = 256 };
    static uint8_t handles[CAPACITY][ZCRYPTO_QUIC_HANDLE_SIZE];
    uint8_t overflow_handle[ZCRYPTO_QUIC_HANDLE_SIZE];
    unsigned acquired = 0u;
    unsigned i;

    group("QUIC handle exhaustion");

    for (i = 0u; i < (unsigned)CAPACITY; i++) {
        zcrypto_result_t r = zcrypto_quic_init(ZCRYPTO_CIPHER_AES_128_GCM_SHA256,
                                               handles[i], ZCRYPTO_QUIC_HANDLE_SIZE);
        if (!r.success) {
            break;
        }
        acquired++;
    }

    /* Every slot should have been available, since the earlier group released
     * everything it took. */
    CHECK(acquired == (unsigned)CAPACITY);

    /* One more must fail with the table-full code specifically. */
    EXPECT_ERR(zcrypto_quic_init(ZCRYPTO_CIPHER_AES_128_GCM_SHA256,
                                 overflow_handle, ZCRYPTO_QUIC_HANDLE_SIZE),
               ZCRYPTO_ERROR_HANDLE_TABLE_FULL);

    for (i = 0u; i < acquired; i++) {
        EXPECT_OK(zcrypto_quic_free(handles[i]));
    }

    /* The table is usable again after release. */
    {
        uint8_t again[ZCRYPTO_QUIC_HANDLE_SIZE];
        EXPECT_OK(zcrypto_quic_init(ZCRYPTO_CIPHER_AES_128_GCM_SHA256,
                                    again, ZCRYPTO_QUIC_HANDLE_SIZE));
        EXPECT_OK(zcrypto_quic_free(again));
    }
}

/*
 * Packet protection, plus the length arithmetic around it. The overflow case is
 * a regression test: `header_len` is attacker-controlled from C, and the bounds
 * check used to compute `header_len + 17` before bounding header_len, which
 * wraps u32 and traps rather than returning an error.
 */
static void test_quic_packet_protection(void)
{
    uint8_t handle[ZCRYPTO_QUIC_HANDLE_SIZE];
    const uint8_t cid[] = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const uint32_t header_len = 8u;
    const uint32_t payload_len = 32u;
    const uint32_t packet_len = header_len + payload_len + ZCRYPTO_AES256_GCM_TAG_SIZE;
    guarded_t packet = guarded_new(packet_len);
    uint8_t original[64];
    uint32_t i;

    group("QUIC packet protection");

    EXPECT_OK(zcrypto_quic_init(ZCRYPTO_CIPHER_AES_128_GCM_SHA256, handle,
                                ZCRYPTO_QUIC_HANDLE_SIZE));

    /* Connection ID bounds: RFC 9000 allows up to 20 bytes, and this ABI also
     * requires at least one. */
    EXPECT_ERR(zcrypto_quic_derive_initial_keys(handle, cid, 0u), ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_derive_initial_keys(handle, cid,
                                                ZCRYPTO_QUIC_MAX_CONNECTION_ID_SIZE + 1u),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_derive_initial_keys(handle, NULL, 8u), ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_derive_initial_keys(NULL, cid, 8u), ZCRYPTO_ERROR_NULL_POINTER);
    EXPECT_OK(zcrypto_quic_derive_initial_keys(handle, cid, (uint32_t)sizeof(cid)));

    /* Round-trip a packet at the initial level. */
    for (i = 0u; i < packet_len; i++) {
        packet.data[i] = (uint8_t)(i & 0xFFu);
    }
    memcpy(original, packet.data, (size_t)(header_len + payload_len));

    {
        zcrypto_result_t r = zcrypto_quic_encrypt_packet_inplace(
            handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
            packet.data, packet_len, header_len);
        EXPECT_OK(r);
        CHECK(guarded_intact(&packet));
        /* The payload must actually have changed. */
        CHECK(memcmp(packet.data + header_len, original + header_len, (size_t)payload_len) != 0);
        /* The header is authenticated, not encrypted, so it is unchanged. */
        CHECK(memcmp(packet.data, original, (size_t)header_len) == 0);
    }

    {
        zcrypto_result_t r = zcrypto_quic_decrypt_packet_inplace(
            handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
            packet.data, packet_len, header_len);
        EXPECT_OK(r);
        CHECK(r.data_len == payload_len);
        CHECK(memcmp(packet.data, original, (size_t)(header_len + payload_len)) == 0);
        CHECK(guarded_intact(&packet));
    }

    /* Tampered packet must fail authentication. */
    {
        zcrypto_result_t r = zcrypto_quic_encrypt_packet_inplace(
            handle, ZCRYPTO_LEVEL_INITIAL, false, 1u,
            packet.data, packet_len, header_len);
        EXPECT_OK(r);
        packet.data[header_len + 3u] ^= 0x40u;
        EXPECT_ERR(zcrypto_quic_decrypt_packet_inplace(handle, ZCRYPTO_LEVEL_INITIAL, false, 1u,
                                                       packet.data, packet_len, header_len),
                   ZCRYPTO_ERROR_DECRYPTION_FAILED);
        CHECK(guarded_intact(&packet));
    }

    /* Length arithmetic. header_len must be strictly less than packet_len, and
     * there must be room for a tag. None of these may trap. */
    EXPECT_ERR(zcrypto_quic_encrypt_packet_inplace(handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   packet.data, packet_len, packet_len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_encrypt_packet_inplace(handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   packet.data, packet_len, packet_len + 1u),
               ZCRYPTO_ERROR_INVALID_INPUT);
    /* Regression: a header length near the u32 maximum must be rejected, not
     * overflowed. */
    EXPECT_ERR(zcrypto_quic_encrypt_packet_inplace(handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   packet.data, packet_len, 0xFFFFFFFFu),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_encrypt_packet_inplace(handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   packet.data, packet_len, 0xFFFFFFF0u),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_decrypt_packet_inplace(handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   packet.data, packet_len, 0xFFFFFFFFu),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_decrypt_packet_inplace(handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   packet.data, packet_len, 0xFFFFFFF0u),
               ZCRYPTO_ERROR_INVALID_INPUT);
    /* Too small to hold a tag after the header. */
    EXPECT_ERR(zcrypto_quic_encrypt_packet_inplace(handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   packet.data, header_len + 16u, header_len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_decrypt_packet_inplace(handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   packet.data, header_len + 15u, header_len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_encrypt_packet_inplace(handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   NULL, packet_len, header_len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_encrypt_packet_inplace(NULL, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   packet.data, packet_len, header_len),
               ZCRYPTO_ERROR_NULL_POINTER);
    /* The decrypt path has its own null checks and had been taken on trust: the
     * length and level cases above cover it, but the NULL cases only ever
     * exercised encrypt. Since the whole reason these parameters are `allowzero`
     * is that a nonnull-annotated pointer lets the optimizer delete the guard,
     * an untested direction is exactly where that deletion would go unnoticed. */
    EXPECT_ERR(zcrypto_quic_decrypt_packet_inplace(handle, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   NULL, packet_len, header_len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_decrypt_packet_inplace(NULL, ZCRYPTO_LEVEL_INITIAL, false, 0u,
                                                   packet.data, packet_len, header_len),
               ZCRYPTO_ERROR_NULL_POINTER);

    /* Levels that need a completed handshake are refused on a context that only
     * has initial keys, and an out-of-range level is refused outright. */
    EXPECT_ERR(zcrypto_quic_encrypt_packet_inplace(handle, ZCRYPTO_LEVEL_EARLY_DATA, false, 0u,
                                                   packet.data, packet_len, header_len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_encrypt_packet_inplace(handle, ZCRYPTO_LEVEL_HANDSHAKE, false, 0u,
                                                   packet.data, packet_len, header_len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_encrypt_packet_inplace(handle, ZCRYPTO_LEVEL_APPLICATION, false, 0u,
                                                   packet.data, packet_len, header_len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_encrypt_packet_inplace(handle, 4u, false, 0u,
                                                   packet.data, packet_len, header_len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_quic_decrypt_packet_inplace(handle, 0xFFFFFFFFu, false, 0u,
                                                   packet.data, packet_len, header_len),
               ZCRYPTO_ERROR_INVALID_INPUT);

    CHECK(guarded_intact(&packet));
    EXPECT_OK(zcrypto_quic_free(handle));
    guarded_free(&packet);
}

/* ------------------------------------------------------------------------- */
/* Memory helpers                                                             */
/* ------------------------------------------------------------------------- */

static void test_memory_helpers(void)
{
    guarded_t a = guarded_new(64u);
    guarded_t b = guarded_new(64u);

    group("memory helpers");

    guarded_fill(&a, 0x5Au);
    guarded_fill(&b, 0x5Au);

    /* Equal buffers compare equal; a single differing byte does not. */
    EXPECT_OK(zcrypto_secure_memcmp(a.data, b.data, a.len));
    b.data[63] ^= 0x01u;
    EXPECT_ERR(zcrypto_secure_memcmp(a.data, b.data, a.len), ZCRYPTO_ERROR_VERIFICATION_FAILED);
    b.data[63] ^= 0x01u;
    /* A difference in the first byte must be caught too: an early-exit
     * implementation would still pass the previous check. */
    b.data[0] ^= 0x80u;
    EXPECT_ERR(zcrypto_secure_memcmp(a.data, b.data, a.len), ZCRYPTO_ERROR_VERIFICATION_FAILED);
    b.data[0] ^= 0x80u;

    /* Zero length compares equal without touching either pointer, so null is
     * acceptable in that case only. */
    EXPECT_OK(zcrypto_secure_memcmp(a.data, b.data, 0u));
    EXPECT_OK(zcrypto_secure_memcmp(NULL, NULL, 0u));
    EXPECT_ERR(zcrypto_secure_memcmp(NULL, b.data, 1u), ZCRYPTO_ERROR_NULL_POINTER);
    EXPECT_ERR(zcrypto_secure_memcmp(a.data, NULL, 1u), ZCRYPTO_ERROR_NULL_POINTER);

    /* secure_zero clears exactly the requested range and nothing beyond it. */
    guarded_fill(&a, 0xC3u);
    EXPECT_OK(zcrypto_secure_zero(a.data, 32u));
    CHECK(all_zero(a.data, 32u));
    CHECK(a.data[32] == 0xC3u);
    CHECK(guarded_intact(&a));

    EXPECT_OK(zcrypto_secure_zero(a.data, a.len));
    CHECK(all_zero(a.data, a.len));
    CHECK(guarded_intact(&a));

    /* Zero length is a no-op that accepts null. */
    EXPECT_OK(zcrypto_secure_zero(NULL, 0u));
    EXPECT_ERR(zcrypto_secure_zero(NULL, 1u), ZCRYPTO_ERROR_NULL_POINTER);

    guarded_free(&a);
    guarded_free(&b);
}

/* ------------------------------------------------------------------------- */
/* ML-KEM-768 (FIPS 203)                                                      */
/* ------------------------------------------------------------------------- */

/*
 * There are no published ML-KEM vectors usable from here: the ABI draws its own
 * encapsulation randomness internally, so a C caller cannot steer it to a known
 * ciphertext. What a consumer can prove is the property that matters — a secret
 * produced by encapsulating to a public key is reproduced by decapsulating with
 * the matching private key, and by nothing else.
 */
static void test_ml_kem_768(void)
{
    guarded_t pk = guarded_new(ZCRYPTO_ML_KEM_768_PUBLIC_KEY_SIZE);
    guarded_t sk = guarded_new(ZCRYPTO_ML_KEM_768_PRIVATE_KEY_SIZE);
    guarded_t ct = guarded_new(ZCRYPTO_ML_KEM_768_CIPHERTEXT_SIZE);
    guarded_t ss_a = guarded_new(ZCRYPTO_ML_KEM_768_SHARED_SECRET_SIZE);
    guarded_t ss_b = guarded_new(ZCRYPTO_ML_KEM_768_SHARED_SECRET_SIZE);
    guarded_t ct2 = guarded_new(ZCRYPTO_ML_KEM_768_CIPHERTEXT_SIZE);
    guarded_t ss_c = guarded_new(ZCRYPTO_ML_KEM_768_SHARED_SECRET_SIZE);
    guarded_t pk2 = guarded_new(ZCRYPTO_ML_KEM_768_PUBLIC_KEY_SIZE);
    guarded_t sk2 = guarded_new(ZCRYPTO_ML_KEM_768_PRIVATE_KEY_SIZE);

    group("ML-KEM-768");

    EXPECT_OK(zcrypto_ml_kem_768_keygen_checked(pk.data, pk.len, sk.data, sk.len));
    CHECK(guarded_intact(&pk));
    CHECK(guarded_intact(&sk));
    /* An all-zero key would mean the generator never ran. */
    CHECK(!all_zero(pk.data, pk.len));
    CHECK(!all_zero(sk.data, sk.len));

    EXPECT_OK(zcrypto_ml_kem_768_encaps_checked(pk.data, pk.len,
                                                ct.data, ct.len,
                                                ss_a.data, ss_a.len));
    CHECK(guarded_intact(&ct));
    CHECK(guarded_intact(&ss_a));
    CHECK(!all_zero(ct.data, ct.len));
    CHECK(!all_zero(ss_a.data, ss_a.len));

    EXPECT_OK(zcrypto_ml_kem_768_decaps_checked(sk.data, sk.len,
                                                ct.data, ct.len,
                                                ss_b.data, ss_b.len));
    CHECK(guarded_intact(&ss_b));
    CHECK(memcmp(ss_a.data, ss_b.data, (size_t)ss_a.len) == 0);

    /* Encapsulation must not be deterministic: two calls against the same
     * public key have to produce different ciphertexts and different secrets,
     * or the internal randomness is not being drawn. */
    EXPECT_OK(zcrypto_ml_kem_768_encaps_checked(pk.data, pk.len,
                                                ct2.data, ct2.len,
                                                ss_c.data, ss_c.len));
    CHECK(memcmp(ct.data, ct2.data, (size_t)ct.len) != 0);
    CHECK(memcmp(ss_a.data, ss_c.data, (size_t)ss_a.len) != 0);

    /* A ciphertext encapsulated to a different key must not yield the peer's
     * secret. FIPS 203 decapsulation is defined to succeed with an implicitly
     * rejected pseudorandom value rather than to fail, so assert the security
     * property and accept whichever status this wrapper reports. */
    EXPECT_OK(zcrypto_ml_kem_768_keygen_checked(pk2.data, pk2.len, sk2.data, sk2.len));
    EXPECT_OK(zcrypto_ml_kem_768_encaps_checked(pk2.data, pk2.len,
                                                ct2.data, ct2.len,
                                                ss_c.data, ss_c.len));
    {
        zcrypto_result_t r = zcrypto_ml_kem_768_decaps_checked(sk.data, sk.len,
                                                               ct2.data, ct2.len,
                                                               ss_b.data, ss_b.len);
        if (r.success) {
            CHECK(memcmp(ss_c.data, ss_b.data, (size_t)ss_b.len) != 0);
        } else {
            CHECK(r.error_code == ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
        }
    }

    /* Same for a bit-flipped ciphertext against the correct private key. */
    memcpy(ct2.data, ct.data, (size_t)ct.len);
    ct2.data[0] ^= 0x01u;
    {
        zcrypto_result_t r = zcrypto_ml_kem_768_decaps_checked(sk.data, sk.len,
                                                               ct2.data, ct2.len,
                                                               ss_b.data, ss_b.len);
        if (r.success) {
            CHECK(memcmp(ss_a.data, ss_b.data, (size_t)ss_b.len) != 0);
        } else {
            CHECK(r.error_code == ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
        }
        CHECK(guarded_intact(&ss_b));
    }

    guarded_free(&pk);
    guarded_free(&sk);
    guarded_free(&ct);
    guarded_free(&ss_a);
    guarded_free(&ss_b);
    guarded_free(&ct2);
    guarded_free(&ss_c);
    guarded_free(&pk2);
    guarded_free(&sk2);
}

static void test_ml_kem_768_sizes(void)
{
    guarded_t pk = guarded_new(ZCRYPTO_ML_KEM_768_PUBLIC_KEY_SIZE);
    guarded_t sk = guarded_new(ZCRYPTO_ML_KEM_768_PRIVATE_KEY_SIZE);
    guarded_t ct = guarded_new(ZCRYPTO_ML_KEM_768_CIPHERTEXT_SIZE);
    guarded_t ss = guarded_new(ZCRYPTO_ML_KEM_768_SHARED_SECRET_SIZE);
    guarded_t big_pk = guarded_new(ZCRYPTO_ML_KEM_768_PUBLIC_KEY_SIZE + 64u);
    guarded_t big_sk = guarded_new(ZCRYPTO_ML_KEM_768_PRIVATE_KEY_SIZE + 64u);

    group("ML-KEM-768 sizes");

    /* Output capacity: zero, one short, exact, oversized. Output buffers carry
     * "at least this much" semantics, so oversized must be accepted. */
    EXPECT_ERR(zcrypto_ml_kem_768_keygen_checked(pk.data, 0u, sk.data, sk.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_kem_768_keygen_checked(pk.data, pk.len - 1u, sk.data, sk.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_kem_768_keygen_checked(pk.data, pk.len, sk.data, 0u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_kem_768_keygen_checked(pk.data, pk.len, sk.data, sk.len - 1u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_kem_768_keygen_checked(NULL, pk.len, sk.data, sk.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_kem_768_keygen_checked(pk.data, pk.len, NULL, sk.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_OK(zcrypto_ml_kem_768_keygen_checked(big_pk.data, big_pk.len,
                                                big_sk.data, big_sk.len));
    CHECK(guarded_intact(&big_pk));
    CHECK(guarded_intact(&big_sk));
    EXPECT_OK(zcrypto_ml_kem_768_keygen_checked(pk.data, pk.len, sk.data, sk.len));

    /* Input length is an exact-match contract, not a minimum: an oversized
     * public key is a different key, so it must be rejected rather than
     * silently truncated. */
    EXPECT_ERR(zcrypto_ml_kem_768_encaps_checked(pk.data, 0u, ct.data, ct.len,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_kem_768_encaps_checked(pk.data, pk.len - 1u, ct.data, ct.len,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_kem_768_encaps_checked(pk.data, pk.len + 1u, ct.data, ct.len,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_kem_768_encaps_checked(NULL, pk.len, ct.data, ct.len,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_kem_768_encaps_checked(pk.data, pk.len, ct.data, ct.len - 1u,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_kem_768_encaps_checked(pk.data, pk.len, ct.data, ct.len,
                                                 ss.data, ss.len - 1u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_kem_768_encaps_checked(pk.data, pk.len, NULL, ct.len,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);

    EXPECT_OK(zcrypto_ml_kem_768_encaps_checked(pk.data, pk.len, ct.data, ct.len,
                                                ss.data, ss.len));

    EXPECT_ERR(zcrypto_ml_kem_768_decaps_checked(sk.data, sk.len - 1u, ct.data, ct.len,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_kem_768_decaps_checked(sk.data, sk.len + 1u, ct.data, ct.len,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_kem_768_decaps_checked(NULL, sk.len, ct.data, ct.len,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_kem_768_decaps_checked(sk.data, sk.len, ct.data, ct.len - 1u,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_kem_768_decaps_checked(sk.data, sk.len, ct.data, ct.len + 1u,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_kem_768_decaps_checked(sk.data, sk.len, NULL, ct.len,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_kem_768_decaps_checked(sk.data, sk.len, ct.data, ct.len,
                                                 ss.data, 0u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);

    /* Lengths near the u32 maximum must be turned away by the exact-match test
     * rather than becoming an enormous slice. */
    EXPECT_ERR(zcrypto_ml_kem_768_encaps_checked(pk.data, 0xFFFFFFFFu, ct.data, ct.len,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_kem_768_decaps_checked(sk.data, 0xFFFFFFFFu, ct.data, ct.len,
                                                 ss.data, ss.len),
               ZCRYPTO_ERROR_INVALID_INPUT);

    CHECK(guarded_intact(&pk));
    CHECK(guarded_intact(&sk));
    CHECK(guarded_intact(&ct));
    CHECK(guarded_intact(&ss));

    guarded_free(&pk);
    guarded_free(&sk);
    guarded_free(&ct);
    guarded_free(&ss);
    guarded_free(&big_pk);
    guarded_free(&big_sk);
}

/* ------------------------------------------------------------------------- */
/* ML-DSA-65 (FIPS 204)                                                       */
/* ------------------------------------------------------------------------- */

static void test_ml_dsa_65(void)
{
    guarded_t pk = guarded_new(ZCRYPTO_ML_DSA_65_PUBLIC_KEY_SIZE);
    guarded_t sk = guarded_new(ZCRYPTO_ML_DSA_65_PRIVATE_KEY_SIZE);
    guarded_t sig = guarded_new(ZCRYPTO_ML_DSA_65_SIGNATURE_SIZE);
    guarded_t sig2 = guarded_new(ZCRYPTO_ML_DSA_65_SIGNATURE_SIZE);
    guarded_t pk2 = guarded_new(ZCRYPTO_ML_DSA_65_PUBLIC_KEY_SIZE);
    guarded_t sk2 = guarded_new(ZCRYPTO_ML_DSA_65_PRIVATE_KEY_SIZE);
    static const char msg[] = "zcrypto ML-DSA-65 consumer message";
    const uint32_t msg_len = (uint32_t)(sizeof(msg) - 1u);

    group("ML-DSA-65");

    EXPECT_OK(zcrypto_ml_dsa_65_keygen_checked(pk.data, pk.len, sk.data, sk.len));
    CHECK(guarded_intact(&pk));
    CHECK(guarded_intact(&sk));
    CHECK(!all_zero(pk.data, pk.len));
    CHECK(!all_zero(sk.data, sk.len));

    {
        zcrypto_result_t r = zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len,
                                                            (const uint8_t *)msg, msg_len,
                                                            sig.data, sig.len);
        EXPECT_OK(r);
        CHECK(r.data_len == ZCRYPTO_ML_DSA_65_SIGNATURE_SIZE);
    }
    CHECK(guarded_intact(&sig));
    CHECK(!all_zero(sig.data, sig.len));

    EXPECT_OK(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                               (const uint8_t *)msg, msg_len,
                                               sig.data, sig.len));

    /* Signing is randomized, so two signatures over the same message differ and
     * both must verify. */
    EXPECT_OK(zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len,
                                             (const uint8_t *)msg, msg_len,
                                             sig2.data, sig2.len));
    CHECK(memcmp(sig.data, sig2.data, (size_t)sig.len) != 0);
    EXPECT_OK(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                               (const uint8_t *)msg, msg_len,
                                               sig2.data, sig2.len));

    /* Tampered message. */
    {
        char bad[sizeof(msg)];
        memcpy(bad, msg, sizeof(msg));
        bad[0] = (char)(bad[0] ^ 0x01);
        EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                                    (const uint8_t *)bad, msg_len,
                                                    sig.data, sig.len),
                   ZCRYPTO_ERROR_VERIFICATION_FAILED);
    }

    /* Truncated message against an untouched signature. */
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                                (const uint8_t *)msg, msg_len - 1u,
                                                sig.data, sig.len),
               ZCRYPTO_ERROR_VERIFICATION_FAILED);

    /* Tampered signature, first byte and last byte. */
    memcpy(sig2.data, sig.data, (size_t)sig.len);
    sig2.data[0] ^= 0x01u;
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                                (const uint8_t *)msg, msg_len,
                                                sig2.data, sig2.len),
               ZCRYPTO_ERROR_VERIFICATION_FAILED);
    memcpy(sig2.data, sig.data, (size_t)sig.len);
    sig2.data[sig2.len - 1u] ^= 0x80u;
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                                (const uint8_t *)msg, msg_len,
                                                sig2.data, sig2.len),
               ZCRYPTO_ERROR_VERIFICATION_FAILED);

    /* Wrong public key. */
    EXPECT_OK(zcrypto_ml_dsa_65_keygen_checked(pk2.data, pk2.len, sk2.data, sk2.len));
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk2.data, pk2.len,
                                                (const uint8_t *)msg, msg_len,
                                                sig.data, sig.len),
               ZCRYPTO_ERROR_VERIFICATION_FAILED);

    /* An all-zero signature must never verify. */
    guarded_fill(&sig2, 0x00u);
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                                (const uint8_t *)msg, msg_len,
                                                sig2.data, sig2.len),
               ZCRYPTO_ERROR_VERIFICATION_FAILED);

    /* The empty message is a legitimate input: null with a zero length must be
     * accepted, and the resulting signature must verify the same way. */
    EXPECT_OK(zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len, NULL, 0u,
                                             sig.data, sig.len));
    EXPECT_OK(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len, NULL, 0u,
                                               sig.data, sig.len));
    /* ...and must not verify a non-empty message. */
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                                (const uint8_t *)msg, msg_len,
                                                sig.data, sig.len),
               ZCRYPTO_ERROR_VERIFICATION_FAILED);

    CHECK(guarded_intact(&sig));
    CHECK(guarded_intact(&sig2));

    guarded_free(&pk);
    guarded_free(&sk);
    guarded_free(&sig);
    guarded_free(&sig2);
    guarded_free(&pk2);
    guarded_free(&sk2);
}

static void test_ml_dsa_65_sizes(void)
{
    guarded_t pk = guarded_new(ZCRYPTO_ML_DSA_65_PUBLIC_KEY_SIZE);
    guarded_t sk = guarded_new(ZCRYPTO_ML_DSA_65_PRIVATE_KEY_SIZE);
    guarded_t sig = guarded_new(ZCRYPTO_ML_DSA_65_SIGNATURE_SIZE);
    guarded_t big_sig = guarded_new(ZCRYPTO_ML_DSA_65_SIGNATURE_SIZE + 64u);
    static const char msg[] = "size boundaries";
    const uint32_t msg_len = (uint32_t)(sizeof(msg) - 1u);

    group("ML-DSA-65 sizes");

    EXPECT_ERR(zcrypto_ml_dsa_65_keygen_checked(pk.data, 0u, sk.data, sk.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_dsa_65_keygen_checked(pk.data, pk.len - 1u, sk.data, sk.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_dsa_65_keygen_checked(pk.data, pk.len, sk.data, sk.len - 1u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_dsa_65_keygen_checked(NULL, pk.len, sk.data, sk.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_OK(zcrypto_ml_dsa_65_keygen_checked(pk.data, pk.len, sk.data, sk.len));

    /* Private key length is exact-match; signature capacity is a minimum. */
    EXPECT_ERR(zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len - 1u,
                                              (const uint8_t *)msg, msg_len,
                                              sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len + 1u,
                                              (const uint8_t *)msg, msg_len,
                                              sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_dsa_65_sign_checked(NULL, sk.len,
                                              (const uint8_t *)msg, msg_len,
                                              sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_dsa_65_sign_checked(sk.data, 0xFFFFFFFFu,
                                              (const uint8_t *)msg, msg_len,
                                              sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    /* A null message pointer with a non-zero length is always a caller bug. */
    EXPECT_ERR(zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len, NULL, msg_len,
                                              sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    /* An implausible message length must be rejected before being sliced. */
    EXPECT_ERR(zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len,
                                              (const uint8_t *)msg, 0xFFFFFFFFu,
                                              sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len,
                                              (const uint8_t *)msg, msg_len,
                                              sig.data, 0u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len,
                                              (const uint8_t *)msg, msg_len,
                                              sig.data, sig.len - 1u),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_ERR(zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len,
                                              (const uint8_t *)msg, msg_len,
                                              NULL, sig.len),
               ZCRYPTO_ERROR_INSUFFICIENT_BUFFER);

    /* Oversized signature capacity is accepted, reports the true length, and
     * must not write past it. */
    guarded_fill(&big_sig, 0x5Au);
    {
        zcrypto_result_t r = zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len,
                                                            (const uint8_t *)msg, msg_len,
                                                            big_sig.data, big_sig.len);
        EXPECT_OK(r);
        CHECK(r.data_len == ZCRYPTO_ML_DSA_65_SIGNATURE_SIZE);
        CHECK(guarded_intact(&big_sig));
        /* The tail beyond the reported length is untouched. */
        CHECK(big_sig.data[ZCRYPTO_ML_DSA_65_SIGNATURE_SIZE] == 0x5Au);
        CHECK(big_sig.data[big_sig.len - 1u] == 0x5Au);
        /* Verification takes an exact signature length, so a caller holding an
         * oversized buffer must pass r.data_len rather than the capacity. */
        EXPECT_OK(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                                   (const uint8_t *)msg, msg_len,
                                                   big_sig.data, r.data_len));
        EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                                    (const uint8_t *)msg, msg_len,
                                                    big_sig.data, big_sig.len),
                   ZCRYPTO_ERROR_INVALID_INPUT);
    }

    EXPECT_OK(zcrypto_ml_dsa_65_sign_checked(sk.data, sk.len,
                                             (const uint8_t *)msg, msg_len,
                                             sig.data, sig.len));

    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len - 1u,
                                                (const uint8_t *)msg, msg_len,
                                                sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(NULL, pk.len,
                                                (const uint8_t *)msg, msg_len,
                                                sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                                (const uint8_t *)msg, msg_len,
                                                sig.data, sig.len - 1u),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len,
                                                (const uint8_t *)msg, msg_len,
                                                NULL, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, pk.len, NULL, msg_len,
                                                sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(pk.data, 0xFFFFFFFFu,
                                                (const uint8_t *)msg, msg_len,
                                                sig.data, sig.len),
               ZCRYPTO_ERROR_INVALID_INPUT);

    CHECK(guarded_intact(&pk));
    CHECK(guarded_intact(&sk));
    CHECK(guarded_intact(&sig));

    guarded_free(&pk);
    guarded_free(&sk);
    guarded_free(&sig);
    guarded_free(&big_sig);
}

/* ------------------------------------------------------------------------- */
/* Hybrid X25519 + ML-KEM-768                                                 */
/* ------------------------------------------------------------------------- */

/*
 * The hybrid exchange is the export a QUIC consumer reaches for, so the round
 * trip is driven end to end: both halves are generated, the peer encapsulates
 * against the published ML-KEM public key, and the resulting 64-byte secret is
 * checked for the one property a hybrid construction exists to provide — that
 * it depends on both contributions.
 */
static void test_hybrid_x25519_ml_kem(void)
{
    guarded_t c_pub = guarded_new(ZCRYPTO_X25519_PUBLIC_KEY_SIZE);
    guarded_t c_priv = guarded_new(ZCRYPTO_X25519_PRIVATE_KEY_SIZE);
    guarded_t q_pub = guarded_new(ZCRYPTO_ML_KEM_768_PUBLIC_KEY_SIZE);
    guarded_t q_priv = guarded_new(ZCRYPTO_ML_KEM_768_PRIVATE_KEY_SIZE);
    guarded_t peer_c_pub = guarded_new(ZCRYPTO_X25519_PUBLIC_KEY_SIZE);
    guarded_t peer_c_priv = guarded_new(ZCRYPTO_X25519_PRIVATE_KEY_SIZE);
    guarded_t peer_q_pub = guarded_new(ZCRYPTO_ML_KEM_768_PUBLIC_KEY_SIZE);
    guarded_t peer_q_priv = guarded_new(ZCRYPTO_ML_KEM_768_PRIVATE_KEY_SIZE);
    guarded_t ct = guarded_new(ZCRYPTO_ML_KEM_768_CIPHERTEXT_SIZE);
    guarded_t kem_ss = guarded_new(ZCRYPTO_ML_KEM_768_SHARED_SECRET_SIZE);
    guarded_t secret = guarded_new(ZCRYPTO_HYBRID_SHARED_SECRET_SIZE);
    guarded_t secret2 = guarded_new(ZCRYPTO_HYBRID_SHARED_SECRET_SIZE);

    group("hybrid X25519 + ML-KEM-768");

    EXPECT_OK(zcrypto_hybrid_x25519_ml_kem_keygen(c_pub.data, c_priv.data,
                                                  q_pub.data, q_priv.data));
    CHECK(guarded_intact(&c_pub));
    CHECK(guarded_intact(&c_priv));
    CHECK(guarded_intact(&q_pub));
    CHECK(guarded_intact(&q_priv));
    CHECK(!all_zero(c_pub.data, c_pub.len));
    CHECK(!all_zero(c_priv.data, c_priv.len));
    CHECK(!all_zero(q_pub.data, q_pub.len));
    CHECK(!all_zero(q_priv.data, q_priv.len));

    /* Two calls must not return the same key material. */
    EXPECT_OK(zcrypto_hybrid_x25519_ml_kem_keygen(peer_c_pub.data, peer_c_priv.data,
                                                  peer_q_pub.data, peer_q_priv.data));
    CHECK(memcmp(c_priv.data, peer_c_priv.data, (size_t)c_priv.len) != 0);
    CHECK(memcmp(q_priv.data, peer_q_priv.data, (size_t)q_priv.len) != 0);

    /* The peer encapsulates to our published ML-KEM public key. */
    EXPECT_OK(zcrypto_ml_kem_768_encaps_checked(q_pub.data, q_pub.len,
                                                ct.data, ct.len,
                                                kem_ss.data, kem_ss.len));

    {
        zcrypto_result_t r = zcrypto_hybrid_x25519_ml_kem_exchange(c_priv.data,
                                                                   q_priv.data,
                                                                   peer_c_pub.data,
                                                                   ct.data,
                                                                   secret.data);
        EXPECT_OK(r);
        CHECK(r.data_len == ZCRYPTO_HYBRID_SHARED_SECRET_SIZE);
    }
    CHECK(guarded_intact(&secret));
    CHECK(!all_zero(secret.data, secret.len));
    /* The two 32-byte halves must differ; identical halves would mean one
     * contribution was written over both. */
    CHECK(memcmp(secret.data, secret.data + 32, 32u) != 0);

    /* Determinism: the same inputs give the same secret. */
    EXPECT_OK(zcrypto_hybrid_x25519_ml_kem_exchange(c_priv.data, q_priv.data,
                                                    peer_c_pub.data, ct.data,
                                                    secret2.data));
    CHECK(memcmp(secret.data, secret2.data, (size_t)secret.len) == 0);

    /* Changing the classical peer key must change the secret. */
    EXPECT_OK(zcrypto_hybrid_x25519_ml_kem_exchange(c_priv.data, q_priv.data,
                                                    c_pub.data, ct.data,
                                                    secret2.data));
    CHECK(memcmp(secret.data, secret2.data, (size_t)secret.len) != 0);

    /* Changing only the ML-KEM ciphertext must also change the secret. If it
     * does not, the post-quantum contribution is not reaching the output. */
    {
        guarded_t ct2 = guarded_new(ZCRYPTO_ML_KEM_768_CIPHERTEXT_SIZE);
        guarded_t ss2 = guarded_new(ZCRYPTO_ML_KEM_768_SHARED_SECRET_SIZE);
        EXPECT_OK(zcrypto_ml_kem_768_encaps_checked(q_pub.data, q_pub.len,
                                                    ct2.data, ct2.len,
                                                    ss2.data, ss2.len));
        CHECK(memcmp(ct.data, ct2.data, (size_t)ct.len) != 0);
        EXPECT_OK(zcrypto_hybrid_x25519_ml_kem_exchange(c_priv.data, q_priv.data,
                                                        peer_c_pub.data, ct2.data,
                                                        secret2.data));
        CHECK(memcmp(secret.data, secret2.data, (size_t)secret.len) != 0);
        guarded_free(&ct2);
        guarded_free(&ss2);
    }
    CHECK(guarded_intact(&secret2));

    guarded_free(&c_pub);
    guarded_free(&c_priv);
    guarded_free(&q_pub);
    guarded_free(&q_priv);
    guarded_free(&peer_c_pub);
    guarded_free(&peer_c_priv);
    guarded_free(&peer_q_pub);
    guarded_free(&peer_q_priv);
    guarded_free(&ct);
    guarded_free(&kem_ss);
    guarded_free(&secret);
    guarded_free(&secret2);
}

/* ------------------------------------------------------------------------- */
/* Post-quantum entry points in a build that reports no post-quantum           */
/* ------------------------------------------------------------------------- */

/*
 * A build that reports no post-quantum support must not perform post-quantum
 * operations.
 *
 * This is not hypothetical. Every PQ symbol used to call ML-KEM/ML-DSA
 * unconditionally while all three capability reports — zcrypto_has_post_quantum,
 * the ZCRYPTO_FEATURE_POST_QUANTUM bit, and the algorithm string — were driven
 * by the build flag. A default build therefore answered "no post-quantum" to
 * every question a caller could ask and then generated genuine ML-KEM keys
 * anyway, so a caller that correctly gated on the documented capability got the
 * opposite of what it was told.
 *
 * Two things are asserted per entry point, and the second is the one that
 * matters. The call must report ZCRYPTO_ERROR_POST_QUANTUM_FAILED, and it must
 * write nothing: an error return next to a filled key buffer still leaves the
 * caller holding material the build claims it cannot produce.
 *
 * The symbols stay exported in this configuration by design, so one C consumer
 * binary links against any build of the library. What the flag changes is
 * behaviour, not the symbol table — which is why refusal has to be tested rather
 * than assumed from a link failure that will never happen.
 */

#define PQ_MARK 0x5Au

static void test_post_quantum_disabled(void)
{
    guarded_t kem_pk = guarded_new(ZCRYPTO_ML_KEM_768_PUBLIC_KEY_SIZE);
    guarded_t kem_sk = guarded_new(ZCRYPTO_ML_KEM_768_PRIVATE_KEY_SIZE);
    guarded_t kem_ct = guarded_new(ZCRYPTO_ML_KEM_768_CIPHERTEXT_SIZE);
    guarded_t kem_ss = guarded_new(ZCRYPTO_ML_KEM_768_SHARED_SECRET_SIZE);
    guarded_t dsa_pk = guarded_new(ZCRYPTO_ML_DSA_65_PUBLIC_KEY_SIZE);
    guarded_t dsa_sk = guarded_new(ZCRYPTO_ML_DSA_65_PRIVATE_KEY_SIZE);
    guarded_t dsa_sig = guarded_new(ZCRYPTO_ML_DSA_65_SIGNATURE_SIZE);
    guarded_t c_pub = guarded_new(ZCRYPTO_X25519_PUBLIC_KEY_SIZE);
    guarded_t c_priv = guarded_new(ZCRYPTO_X25519_PRIVATE_KEY_SIZE);
    guarded_t c_ct = guarded_new(ZCRYPTO_X25519_PUBLIC_KEY_SIZE);
    guarded_t hybrid_ss = guarded_new(ZCRYPTO_HYBRID_SHARED_SECRET_SIZE);
    guarded_t entropy = guarded_new(ZCRYPTO_QUIC_PQ_ENTROPY_SIZE);
    const char *msg = "a disabled build must not sign this";
    uint32_t msg_len = (uint32_t)strlen(msg);

    group("post-quantum disabled");

    /* Every buffer starts at a marker the library never writes, so "wrote
     * nothing" is distinguishable from "wrote zeros". */
    guarded_fill(&kem_pk, PQ_MARK);
    guarded_fill(&kem_sk, PQ_MARK);
    guarded_fill(&kem_ct, PQ_MARK);
    guarded_fill(&kem_ss, PQ_MARK);
    guarded_fill(&dsa_pk, PQ_MARK);
    guarded_fill(&dsa_sk, PQ_MARK);
    guarded_fill(&dsa_sig, PQ_MARK);
    guarded_fill(&c_pub, PQ_MARK);
    guarded_fill(&c_priv, PQ_MARK);
    guarded_fill(&c_ct, PQ_MARK);
    guarded_fill(&hybrid_ss, PQ_MARK);
    guarded_fill(&entropy, PQ_MARK);

    /* ML-KEM-768, unchecked and checked. */
    EXPECT_ERR(zcrypto_ml_kem_768_keygen(kem_pk.data, kem_sk.data),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    EXPECT_ERR(zcrypto_ml_kem_768_keygen_checked(kem_pk.data, kem_pk.len,
                                                 kem_sk.data, kem_sk.len),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    CHECK(guarded_untouched(&kem_pk, PQ_MARK));
    CHECK(guarded_untouched(&kem_sk, PQ_MARK));

    EXPECT_ERR(zcrypto_ml_kem_768_encaps(kem_pk.data, kem_ct.data, kem_ss.data),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    EXPECT_ERR(zcrypto_ml_kem_768_encaps_checked(kem_pk.data, kem_pk.len,
                                                 kem_ct.data, kem_ct.len,
                                                 kem_ss.data, kem_ss.len),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    CHECK(guarded_untouched(&kem_ct, PQ_MARK));
    CHECK(guarded_untouched(&kem_ss, PQ_MARK));

    EXPECT_ERR(zcrypto_ml_kem_768_decaps(kem_sk.data, kem_ct.data, kem_ss.data),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    EXPECT_ERR(zcrypto_ml_kem_768_decaps_checked(kem_sk.data, kem_sk.len,
                                                 kem_ct.data, kem_ct.len,
                                                 kem_ss.data, kem_ss.len),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    CHECK(guarded_untouched(&kem_ss, PQ_MARK));

    /* ML-DSA-65, unchecked and checked. There is deliberately no unchecked
     * verify to exercise; inventing one to make the surface symmetrical would
     * add an entry point that cannot know the signature length. */
    EXPECT_ERR(zcrypto_ml_dsa_65_keygen(dsa_pk.data, dsa_sk.data),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    EXPECT_ERR(zcrypto_ml_dsa_65_keygen_checked(dsa_pk.data, dsa_pk.len,
                                                dsa_sk.data, dsa_sk.len),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    CHECK(guarded_untouched(&dsa_pk, PQ_MARK));
    CHECK(guarded_untouched(&dsa_sk, PQ_MARK));

    EXPECT_ERR(zcrypto_ml_dsa_65_sign(dsa_sk.data, (const uint8_t *)msg, msg_len,
                                      dsa_sig.data),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    EXPECT_ERR(zcrypto_ml_dsa_65_sign_checked(dsa_sk.data, dsa_sk.len,
                                              (const uint8_t *)msg, msg_len,
                                              dsa_sig.data, dsa_sig.len),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    CHECK(guarded_untouched(&dsa_sig, PQ_MARK));

    /* Verification must refuse rather than report a verdict. Answering either
     * "valid" or "invalid" would imply the build evaluated an ML-DSA signature
     * it cannot evaluate. */
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(dsa_pk.data, dsa_pk.len,
                                                (const uint8_t *)msg, msg_len,
                                                dsa_sig.data, dsa_sig.len),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);

    /* Hybrid X25519 + ML-KEM-768. The classical half is available in every
     * build, so a partial result here would be the most tempting thing to
     * return and the most dangerous: a caller cannot tell a hybrid secret from
     * a bare X25519 one by inspection. */
    EXPECT_ERR(zcrypto_hybrid_x25519_ml_kem_keygen(c_pub.data, c_priv.data,
                                                   kem_pk.data, kem_sk.data),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    CHECK(guarded_untouched(&c_pub, PQ_MARK));
    CHECK(guarded_untouched(&c_priv, PQ_MARK));
    CHECK(guarded_untouched(&kem_pk, PQ_MARK));
    CHECK(guarded_untouched(&kem_sk, PQ_MARK));

    EXPECT_ERR(zcrypto_hybrid_x25519_ml_kem_exchange(c_priv.data, kem_sk.data,
                                                     c_pub.data, kem_ct.data,
                                                     hybrid_ss.data),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    CHECK(guarded_untouched(&hybrid_ss, PQ_MARK));

    /* The QUIC post-quantum key exchange is reached through the QUIC namespace,
     * which is unconditional, so it is the entry point most likely to be missed
     * when auditing which symbols the PQ flag governs. */
    EXPECT_ERR(zcrypto_quic_pq_key_exchange(c_pub.data, kem_pk.data,
                                            c_ct.data, kem_ct.data,
                                            hybrid_ss.data, entropy.data),
               ZCRYPTO_ERROR_POST_QUANTUM_FAILED);
    CHECK(guarded_untouched(&c_pub, PQ_MARK));
    CHECK(guarded_untouched(&kem_pk, PQ_MARK));
    CHECK(guarded_untouched(&c_ct, PQ_MARK));
    CHECK(guarded_untouched(&kem_ct, PQ_MARK));
    CHECK(guarded_untouched(&hybrid_ss, PQ_MARK));

    guarded_free(&kem_pk);
    guarded_free(&kem_sk);
    guarded_free(&kem_ct);
    guarded_free(&kem_ss);
    guarded_free(&dsa_pk);
    guarded_free(&dsa_sk);
    guarded_free(&dsa_sig);
    guarded_free(&c_pub);
    guarded_free(&c_priv);
    guarded_free(&c_ct);
    guarded_free(&hybrid_ss);
    guarded_free(&entropy);
}

/* ------------------------------------------------------------------------- */
/* Unchecked post-quantum entry points                                        */
/* ------------------------------------------------------------------------- */

/*
 * The tests above use the `_checked` variants throughout, because those are what
 * a new consumer should call. That left the unchecked entry points — which are
 * still exported, still documented, and still what older callers link against —
 * covered by nothing at all. A guard applied to the checked family and missed on
 * the unchecked one would have passed the whole suite.
 *
 * Only the round trip is asserted here. Buffer-boundary behaviour is not: these
 * entry points take no lengths, so there is no capacity contract to test.
 */
static void test_post_quantum_unchecked(void)
{
    guarded_t kem_pk = guarded_new(ZCRYPTO_ML_KEM_768_PUBLIC_KEY_SIZE);
    guarded_t kem_sk = guarded_new(ZCRYPTO_ML_KEM_768_PRIVATE_KEY_SIZE);
    guarded_t kem_ct = guarded_new(ZCRYPTO_ML_KEM_768_CIPHERTEXT_SIZE);
    guarded_t ss_a = guarded_new(ZCRYPTO_ML_KEM_768_SHARED_SECRET_SIZE);
    guarded_t ss_b = guarded_new(ZCRYPTO_ML_KEM_768_SHARED_SECRET_SIZE);
    guarded_t dsa_pk = guarded_new(ZCRYPTO_ML_DSA_65_PUBLIC_KEY_SIZE);
    guarded_t dsa_sk = guarded_new(ZCRYPTO_ML_DSA_65_PRIVATE_KEY_SIZE);
    guarded_t dsa_sig = guarded_new(ZCRYPTO_ML_DSA_65_SIGNATURE_SIZE);
    const char *msg = "unchecked entry points must still be real";
    uint32_t msg_len = (uint32_t)strlen(msg);

    group("post-quantum unchecked entry points");

    /* ML-KEM: encapsulate to a generated key, decapsulate with its private
     * half, and require the two secrets to agree. */
    EXPECT_OK(zcrypto_ml_kem_768_keygen(kem_pk.data, kem_sk.data));
    CHECK(guarded_intact(&kem_pk));
    CHECK(guarded_intact(&kem_sk));
    CHECK(!all_zero(kem_pk.data, kem_pk.len));
    CHECK(!all_zero(kem_sk.data, kem_sk.len));

    EXPECT_OK(zcrypto_ml_kem_768_encaps(kem_pk.data, kem_ct.data, ss_a.data));
    CHECK(guarded_intact(&kem_ct));
    CHECK(guarded_intact(&ss_a));
    CHECK(!all_zero(ss_a.data, ss_a.len));

    EXPECT_OK(zcrypto_ml_kem_768_decaps(kem_sk.data, kem_ct.data, ss_b.data));
    CHECK(guarded_intact(&ss_b));
    CHECK(memcmp(ss_a.data, ss_b.data, (size_t)ss_a.len) == 0);

    /* ML-DSA: a signature from the unchecked signer must verify under the
     * checked verifier, which is the only verify this ABI exposes. Crossing the
     * two families is the point — it proves they operate on the same encoding
     * rather than each being self-consistently wrong. */
    EXPECT_OK(zcrypto_ml_dsa_65_keygen(dsa_pk.data, dsa_sk.data));
    CHECK(!all_zero(dsa_pk.data, dsa_pk.len));
    CHECK(!all_zero(dsa_sk.data, dsa_sk.len));

    EXPECT_OK(zcrypto_ml_dsa_65_sign(dsa_sk.data, (const uint8_t *)msg, msg_len,
                                     dsa_sig.data));
    CHECK(guarded_intact(&dsa_sig));
    CHECK(!all_zero(dsa_sig.data, dsa_sig.len));

    EXPECT_OK(zcrypto_ml_dsa_65_verify_checked(dsa_pk.data, dsa_pk.len,
                                               (const uint8_t *)msg, msg_len,
                                               dsa_sig.data, dsa_sig.len));

    /* A tampered signature must not verify. Without this, a verifier that
     * returns success unconditionally passes the check above. */
    dsa_sig.data[0] ^= 0x01u;
    EXPECT_ERR(zcrypto_ml_dsa_65_verify_checked(dsa_pk.data, dsa_pk.len,
                                                (const uint8_t *)msg, msg_len,
                                                dsa_sig.data, dsa_sig.len),
               ZCRYPTO_ERROR_VERIFICATION_FAILED);

    guarded_free(&kem_pk);
    guarded_free(&kem_sk);
    guarded_free(&kem_ct);
    guarded_free(&ss_a);
    guarded_free(&ss_b);
    guarded_free(&dsa_pk);
    guarded_free(&dsa_sk);
    guarded_free(&dsa_sig);
}

/* ------------------------------------------------------------------------- */
/* QUIC post-quantum key exchange                                             */
/* ------------------------------------------------------------------------- */

static void test_quic_pq_key_exchange(void)
{
    guarded_t c_pub = guarded_new(ZCRYPTO_X25519_PUBLIC_KEY_SIZE);
    guarded_t q_pub = guarded_new(ZCRYPTO_ML_KEM_768_PUBLIC_KEY_SIZE);
    guarded_t c_ct = guarded_new(ZCRYPTO_X25519_PUBLIC_KEY_SIZE);
    guarded_t q_ct = guarded_new(ZCRYPTO_ML_KEM_768_CIPHERTEXT_SIZE);
    guarded_t secret = guarded_new(ZCRYPTO_HYBRID_SHARED_SECRET_SIZE);
    guarded_t secret2 = guarded_new(ZCRYPTO_HYBRID_SHARED_SECRET_SIZE);
    uint8_t entropy[ZCRYPTO_QUIC_PQ_ENTROPY_SIZE];
    uint32_t i;

    group("QUIC post-quantum key exchange");

    for (i = 0u; i < (uint32_t)sizeof(entropy); i++) {
        entropy[i] = (uint8_t)(i * 7u + 1u);
    }

    EXPECT_OK(zcrypto_quic_pq_key_exchange(c_pub.data, q_pub.data,
                                           c_ct.data, q_ct.data,
                                           secret.data, entropy));
    CHECK(guarded_intact(&c_pub));
    CHECK(guarded_intact(&q_pub));
    CHECK(guarded_intact(&c_ct));
    CHECK(guarded_intact(&q_ct));
    CHECK(guarded_intact(&secret));
    CHECK(!all_zero(c_pub.data, c_pub.len));
    CHECK(!all_zero(q_pub.data, q_pub.len));
    CHECK(!all_zero(q_ct.data, q_ct.len));
    CHECK(!all_zero(secret.data, secret.len));

    /* The 64-byte secret is a classical half concatenated with a
     * post-quantum half. Two identical 32-byte halves would mean one
     * contribution was copied over the other. */
    CHECK(memcmp(secret.data, secret.data + 32, 32u) != 0);

    /* The caller supplies the classical entropy but not the ML-KEM
     * encapsulation randomness, which the library draws itself. Repeating the
     * call with the same entropy must therefore still produce a different
     * ciphertext and a different secret; identical output would mean the
     * post-quantum half is deterministic in the caller's input. */
    EXPECT_OK(zcrypto_quic_pq_key_exchange(c_pub.data, q_pub.data,
                                           c_ct.data, q_ct.data,
                                           secret2.data, entropy));
    CHECK(memcmp(secret.data, secret2.data, (size_t)secret.len) != 0);

    guarded_free(&c_pub);
    guarded_free(&q_pub);
    guarded_free(&c_ct);
    guarded_free(&q_ct);
    guarded_free(&secret);
    guarded_free(&secret2);
}

int main(void)
{
    printf("zcrypto C consumer\n");

    test_abi_layout();
    test_capabilities();
    test_cipher_suite_info();
    test_sha256();
    test_blake2b();
    test_hkdf();
    test_aes256_gcm_vectors();
    test_aes256_gcm_negative();
    test_ed25519();
    test_ed25519_sizes();
    test_quic_handle_lifecycle();
    test_quic_handle_exhaustion();
    test_quic_packet_protection();
    test_memory_helpers();

    /*
     * The post-quantum entry points exist in every build, so both branches are
     * real test coverage rather than one being a skip. Which branch runs is
     * decided by the library's own capability report, and test_capabilities()
     * has already proved that report is internally consistent.
     *
     * The argument-validation suites belong on the enabled side. The refusal in
     * a disabled build is returned before argument validation — when the feature
     * is absent there is no buffer contract to enforce and nothing meaningful to
     * say about a bad length — so asserting INSUFFICIENT_BUFFER there would be
     * asserting a contract the build does not have.
     */
    if (pq_enabled()) {
        test_ml_kem_768();
        test_ml_kem_768_sizes();
        test_ml_dsa_65();
        test_ml_dsa_65_sizes();
        test_hybrid_x25519_ml_kem();
        test_post_quantum_unchecked();
        test_quic_pq_key_exchange();
    } else {
        test_post_quantum_disabled();
    }

    printf("\n%u checks, %u failures\n", g_checks, g_failures);
    return (g_failures == 0u) ? 0 : 1;
}
