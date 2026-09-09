/* sim/shim/include/cx.h — minimal Ledger SDK cx.h stand-in for the APDU
 * simulator. Only the surface actually used by the production handlers
 * and the libzknox key layer is declared; implementations live in
 * shim_crypto.c and are backed by vendored trezor-crypto / orlp-ed25519.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef uint32_t cx_err_t;
#define CX_OK                 0x00000000u
#define CX_INVALID_PARAMETER  0xFFFFFF01u
#define CX_INTERNAL_ERROR     0xFFFFFF02u
#define CX_EC_INVALID_POINT   0xFFFFFF03u

typedef enum {
    CX_CURVE_NONE = 0,
    CX_CURVE_SECP256K1 = 0x21,
    CX_CURVE_Ed25519   = 0x70,
} cx_curve_t;
#define CX_CURVE_256K1 CX_CURVE_SECP256K1

/* ── ECFP key structures (sized like the SDK 256-bit variants) ── */
typedef struct {
    cx_curve_t curve;
    size_t     d_len;
    uint8_t    d[32];
} cx_ecfp_private_key_t;
typedef cx_ecfp_private_key_t cx_ecfp_256_private_key_t;

typedef struct {
    cx_curve_t curve;
    size_t     W_len;
    uint8_t    W[65];
} cx_ecfp_public_key_t;
typedef cx_ecfp_public_key_t cx_ecfp_256_public_key_t;

cx_err_t cx_ecfp_init_private_key_no_throw(cx_curve_t curve,
                                           const uint8_t *rawkey, size_t key_len,
                                           cx_ecfp_private_key_t *pvkey);
cx_err_t cx_ecfp_generate_pair_no_throw(cx_curve_t curve,
                                        cx_ecfp_public_key_t *pubkey,
                                        cx_ecfp_private_key_t *privkey,
                                        int keepprivate);

/* ── Hashes ── */
#define CX_LAST (1u << 0)

typedef struct { uint8_t opaque[424]; uint32_t alg; } cx_hash_t;
typedef cx_hash_t cx_sha3_t;
typedef cx_hash_t cx_sha256_t;
typedef cx_hash_t cx_blake2b_t;

cx_err_t cx_keccak_init_no_throw(cx_sha3_t *hash, size_t size);
cx_err_t cx_sha256_init(cx_sha256_t *hash);
cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode,
                          const uint8_t *in, size_t len,
                          uint8_t *out, size_t out_len);
cx_err_t cx_keccak_256_hash(const uint8_t *in, size_t len, uint8_t out[32]);
/* BOLOS convention: returns the number of bytes written (64), 0 on error */
size_t cx_hash_sha512(const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t out_len);
cx_err_t cx_blake2b_512_hash(const uint8_t *in, size_t len, uint8_t out[64]);

/* Incremental generic API (init_ex/update/final) — used by one handler */
cx_err_t cx_hash_init_ex(cx_hash_t *hash, uint32_t alg, size_t out_size);
cx_err_t cx_hash_update(cx_hash_t *hash, const uint8_t *in, size_t len);
cx_err_t cx_hash_final(cx_hash_t *hash, uint8_t *digest);
#define CX_KECCAK 6u
#define CX_SHA256 3u
#define CX_SHA512 5u
#define CX_BLAKE2B 9u

/* ── RNG ── */
cx_err_t cx_get_random_bytes(void *buffer, size_t len);
void     cx_trng_init(void);

/* ── ECDSA (via crypto_helpers.h wrapper) flags ── */
#define CX_RND_RFC6979       (3u << 9)
#define CX_ECCINFO_PARITY_ODD 1u

/* ── Edwards / scalar mult (libzknox key layer, mostly unused paths) ── */
cx_err_t cx_ecfp_scalar_mult_no_throw(cx_curve_t curve, uint8_t *P,
                                      const uint8_t *k, size_t k_len);
cx_err_t cx_edwards_decompress_point_no_throw(cx_curve_t curve,
                                              uint8_t *P, size_t P_len);

/* ── Minimal cx_bn (big numbers, big-endian byte semantics) ── */
typedef uint32_t cx_bn_t;
cx_err_t cx_bn_lock(size_t word_size, uint32_t flags);
cx_err_t cx_bn_unlock(void);
cx_err_t cx_bn_alloc(cx_bn_t *x, size_t size);
cx_err_t cx_bn_alloc_init(cx_bn_t *x, size_t size,
                          const uint8_t *value, size_t value_len);
cx_err_t cx_bn_init(cx_bn_t x, const uint8_t *value, size_t value_len);
cx_err_t cx_bn_copy(cx_bn_t dst, cx_bn_t src);
cx_err_t cx_bn_reduce(cx_bn_t r, cx_bn_t a, cx_bn_t n);
cx_err_t cx_bn_export(cx_bn_t x, uint8_t *bytes, size_t len);
cx_err_t cx_bn_destroy(cx_bn_t *x);

/* ── AES-256-GCM (debug INS encrypt_note) ── */
typedef struct { uint8_t opaque[560]; } cx_aes_gcm_context_t;
void     cx_aes_gcm_init(cx_aes_gcm_context_t *ctx);
cx_err_t cx_aes_gcm_set_key(cx_aes_gcm_context_t *ctx, const uint8_t *key, size_t key_len);
cx_err_t cx_aes_gcm_encrypt_and_tag(cx_aes_gcm_context_t *ctx,
                                    uint8_t *in, size_t len,
                                    const uint8_t *iv, size_t iv_len,
                                    const uint8_t *aad, size_t aad_len,
                                    uint8_t *out, uint8_t *tag, size_t tag_len);
cx_err_t cx_aes_gcm_decrypt_and_auth(cx_aes_gcm_context_t *ctx,
                                     uint8_t *in, size_t len,
                                     const uint8_t *iv, size_t iv_len,
                                     const uint8_t *aad, size_t aad_len,
                                     uint8_t *out, const uint8_t *tag, size_t tag_len);
