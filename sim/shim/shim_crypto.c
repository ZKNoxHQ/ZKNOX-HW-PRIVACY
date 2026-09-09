/* sim/shim/shim_crypto.c — software implementations of the Ledger SDK
 * crypto surface used by the production handlers.
 *
 * Derivations reproduce BOLOS bit-for-bit:
 *   - os_derive_bip32_no_throw (secp256k1): BIP32. The 7702 path is
 *     fully hardened so only HMAC-SHA512 + scalar add mod n is needed;
 *     non-hardened steps are supported too (pubkey via trezor ecdsa).
 *   - os_derive_bip32_with_seed_no_throw (HDW_ED25519_SLIP10 + custom
 *     seed key): SLIP-0010 extended derivation, used by the RAILGUN
 *     keys with seed key "babyjubjub seed".
 *
 * The BIP39 seed comes from SIM_SEED (hex, 64 bytes) or defaults to the
 * seed of the standard test mnemonic "yellow" x 12.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "cx.h"
#include "os.h"
#include "crypto_helpers.h"

#include "sha2.h"
#include "sha3.h"
#include "hmac.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "bignum.h"
#include "memzero.h"
#include "blake2b.h"

/* orlp/ed25519 internals for affine pubkey coordinates */
#include "fixedint.h"
#include "fe.h"
#include "ge.h"
#include "sha512.h"

/* ───────────────────────── seed ───────────────────────── */
/* BIP39 seed of "yellow yellow ... yellow" (12 words), passphrase "".
 * Precomputed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048, 64). */
static const uint8_t DEFAULT_SEED[64] = {
    0x0f, 0x87, 0x73, 0x08, 0xa5, 0x5c, 0x29, 0xb5,
    0x1a, 0x82, 0xef, 0x83, 0xf2, 0x99, 0xa9, 0x84,
    0xad, 0x91, 0x63, 0x26, 0x0d, 0x0f, 0x43, 0x1a,
    0x3e, 0x0c, 0xf4, 0xa4, 0xb9, 0xf0, 0x63, 0xfb,
    0xef, 0xbf, 0x3e, 0x5b, 0x5f, 0x27, 0xae, 0xf1,
    0x3b, 0xfd, 0x80, 0xc3, 0x0f, 0x70, 0x63, 0x4a,
    0xd0, 0xb2, 0x8e, 0xc0, 0xb4, 0xd7, 0xa0, 0xf3,
    0xf3, 0x4a, 0xc9, 0x9d, 0x3b, 0x37, 0x07, 0xc2,
};

static uint8_t g_seed[64];
static int g_seed_ready = 0;

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static const uint8_t *sim_seed(void) {
    if (!g_seed_ready) {
        const char *env = getenv("SIM_SEED");
        if (env && strlen(env) == 128) {
            for (int i = 0; i < 64; i++) {
                int h = hexval(env[2 * i]), l = hexval(env[2 * i + 1]);
                if (h < 0 || l < 0) { env = NULL; break; }
                g_seed[i] = (uint8_t)((h << 4) | l);
            }
        } else {
            env = NULL;
        }
        if (!env) memcpy(g_seed, DEFAULT_SEED, 64);
        g_seed_ready = 1;
    }
    return g_seed;
}

/* ───────────────────── BIP32 secp256k1 ───────────────────── */

static cx_err_t bip32_master(uint8_t k[32], uint8_t c[32]) {
    uint8_t I[64];
    hmac_sha512((const uint8_t *)"Bitcoin seed", 12, sim_seed(), 64, I);
    memcpy(k, I, 32);
    memcpy(c, I + 32, 32);
    memzero(I, 64);
    return CX_OK;
}

/* k_child = parse256(IL) + k_parent mod n ; fails if IL >= n or child = 0 */
static int scalar_add_mod_n(uint8_t k[32], const uint8_t il[32]) {
    bignum256 a, b;
    bn_read_be(il, &a);
    if (!bn_is_less(&a, &secp256k1.order)) return -1;
    bn_read_be(k, &b);
    bn_add(&b, &a);
    bn_mod(&b, &secp256k1.order);
    if (bn_is_zero(&b)) return -1;
    bn_write_be(&b, k);
    memzero(&a, sizeof(a));
    memzero(&b, sizeof(b));
    return 0;
}

static cx_err_t bip32_ckd(uint8_t k[32], uint8_t c[32], uint32_t i) {
    uint8_t data[37];
    uint8_t I[64];
    if (i & 0x80000000u) {
        data[0] = 0x00;
        memcpy(data + 1, k, 32);
    } else {
        /* non-hardened: serP(point(k)) */
        if (ecdsa_get_public_key33(&secp256k1, k, data) != 0) return CX_INTERNAL_ERROR;
    }
    data[33] = (uint8_t)(i >> 24);
    data[34] = (uint8_t)(i >> 16);
    data[35] = (uint8_t)(i >> 8);
    data[36] = (uint8_t)(i);
    hmac_sha512(c, 32, data, 37, I);
    memcpy(c, I + 32, 32);
    int rc = scalar_add_mod_n(k, I);
    memzero(I, 64);
    memzero(data, 37);
    return rc == 0 ? CX_OK : CX_INTERNAL_ERROR;
}

cx_err_t os_derive_bip32_no_throw(cx_curve_t curve, const uint32_t *path,
                                  size_t path_len, uint8_t *privkey,
                                  uint8_t *chain) {
    if (curve != CX_CURVE_SECP256K1) return CX_INVALID_PARAMETER;
    uint8_t k[32], c[32];
    bip32_master(k, c);
    for (size_t i = 0; i < path_len; i++) {
        if (bip32_ckd(k, c, path[i]) != CX_OK) {
            memzero(k, 32); memzero(c, 32);
            return CX_INTERNAL_ERROR;
        }
    }
    memcpy(privkey, k, 32);
    if (chain) memcpy(chain, c, 32);
    memzero(k, 32); memzero(c, 32);
    return CX_OK;
}

/* ─────────────── SLIP-0010 (custom seed key, ed25519 mechanics) ─────────────── */

cx_err_t os_derive_bip32_with_seed_no_throw(os_derivation_mode_t mode,
                                            cx_curve_t curve,
                                            const uint32_t *path, size_t path_len,
                                            uint8_t *privkey, uint8_t *chain,
                                            unsigned char *seed_key,
                                            size_t seed_key_len) {
    if (mode != HDW_ED25519_SLIP10) return CX_INVALID_PARAMETER;
    (void)curve;
    uint8_t k[32], c[32], I[64], data[37];

    const uint8_t *skey = seed_key;
    size_t skey_len = seed_key_len;
    if (!skey || skey_len == 0) { skey = (const uint8_t *)"ed25519 seed"; skey_len = 12; }

    hmac_sha512(skey, skey_len, sim_seed(), 64, I);
    memcpy(k, I, 32);
    memcpy(c, I + 32, 32);

    for (size_t idx = 0; idx < path_len; idx++) {
        uint32_t i = path[idx];
        /* SLIP-0010 ed25519: hardened only; BOLOS forces the bit. */
        i |= 0x80000000u;
        data[0] = 0x00;
        memcpy(data + 1, k, 32);
        data[33] = (uint8_t)(i >> 24);
        data[34] = (uint8_t)(i >> 16);
        data[35] = (uint8_t)(i >> 8);
        data[36] = (uint8_t)(i);
        hmac_sha512(c, 32, data, 37, I);
        memcpy(k, I, 32);
        memcpy(c, I + 32, 32);
    }
    memcpy(privkey, k, 32);
    if (chain) memcpy(chain, c, 32);
    memzero(k, 32); memzero(c, 32); memzero(I, 64); memzero(data, 37);
    return CX_OK;
}

/* ───────────────────── ECFP keypairs ───────────────────── */

cx_err_t cx_ecfp_init_private_key_no_throw(cx_curve_t curve,
                                           const uint8_t *rawkey, size_t key_len,
                                           cx_ecfp_private_key_t *pvkey) {
    if (key_len > sizeof(pvkey->d)) return CX_INVALID_PARAMETER;
    pvkey->curve = curve;
    pvkey->d_len = key_len;
    if (rawkey) memcpy(pvkey->d, rawkey, key_len);
    return CX_OK;
}

/* ed25519: pk = clamp(SHA512(seed)[0:32]) * B, returned as 04||X_be||Y_be
 * to match the BOLOS cx_ecfp_generate_pair contract that the app relies
 * on (it recompresses to Y_le + sign(X) itself). */
static cx_err_t ed25519_pub_xy(const uint8_t seed[32], uint8_t W[65]) {
    uint8_t az[64];
    sha512(seed, 32, az);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    ge_p3 A;
    ge_scalarmult_base(&A, az);

    fe zinv, x, y;
    fe_invert(zinv, A.Z);
    fe_mul(x, A.X, zinv);
    fe_mul(y, A.Y, zinv);

    uint8_t xb[32], yb[32];
    fe_tobytes(xb, x); /* little-endian */
    fe_tobytes(yb, y);

    W[0] = 0x04;
    for (int i = 0; i < 32; i++) {
        W[1 + i]  = xb[31 - i];  /* big-endian X */
        W[33 + i] = yb[31 - i];  /* big-endian Y */
    }
    memzero(az, sizeof(az));
    return CX_OK;
}

cx_err_t cx_ecfp_generate_pair_no_throw(cx_curve_t curve,
                                        cx_ecfp_public_key_t *pubkey,
                                        cx_ecfp_private_key_t *privkey,
                                        int keepprivate) {
    (void)keepprivate;
    pubkey->curve = curve;
    if (curve == CX_CURVE_SECP256K1) {
        uint8_t pub65[65];
        if (ecdsa_get_public_key65(&secp256k1, privkey->d, pub65) != 0)
            return CX_INTERNAL_ERROR;
        memcpy(pubkey->W, pub65, 65);
        pubkey->W_len = 65;
        return CX_OK;
    }
    if (curve == CX_CURVE_Ed25519) {
        if (privkey->d_len != 32) return CX_INVALID_PARAMETER;
        pubkey->W_len = 65;
        return ed25519_pub_xy(privkey->d, pubkey->W);
    }
    return CX_INVALID_PARAMETER;
}

/* ─────────────── crypto_helpers: derive + ECDSA sign ─────────────── */

static void der_encode_sig(const uint8_t r[32], const uint8_t s[32],
                           uint8_t *der, size_t *der_len) {
    uint8_t rb[33], sb[33];
    size_t rl = 32, sl = 32, off;
    const uint8_t *rp = r, *sp = s;
    while (rl > 1 && rp[0] == 0) { rp++; rl--; }
    while (sl > 1 && sp[0] == 0) { sp++; sl--; }
    if (rp[0] & 0x80) { rb[0] = 0; memcpy(rb + 1, rp, rl); rp = rb; rl++; }
    if (sp[0] & 0x80) { sb[0] = 0; memcpy(sb + 1, sp, sl); sp = sb; sl++; }
    der[0] = 0x30;
    der[1] = (uint8_t)(4 + rl + sl);
    off = 2;
    der[off++] = 0x02; der[off++] = (uint8_t)rl;
    memcpy(der + off, rp, rl); off += rl;
    der[off++] = 0x02; der[off++] = (uint8_t)sl;
    memcpy(der + off, sp, sl); off += sl;
    *der_len = off;
}

cx_err_t bip32_derive_ecdsa_sign_hash_256(cx_curve_t curve,
                                          const uint32_t *path, size_t path_len,
                                          uint32_t sign_mode, uint32_t hashID,
                                          const uint8_t *hash, size_t hash_len,
                                          uint8_t *sig, size_t *sig_len,
                                          uint32_t *info) {
    (void)sign_mode; (void)hashID;
    if (curve != CX_CURVE_SECP256K1 || hash_len != 32) return CX_INVALID_PARAMETER;

    uint8_t priv[32];
    cx_err_t err = os_derive_bip32_no_throw(curve, path, path_len, priv, NULL);
    if (err != CX_OK) return err;

    /* trezor ecdsa_sign_digest: RFC6979 deterministic k, canonical low-s,
     * pby = parity of R.y AFTER the low-s flip — same semantics as BOLOS
     * CX_RND_RFC6979 + CX_ECCINFO_PARITY_ODD. */
    uint8_t sig64[64];
    uint8_t pby = 0;
    int rc = ecdsa_sign_digest(&secp256k1, priv, hash, sig64, &pby, NULL);
    memzero(priv, 32);
    if (rc != 0) return CX_INTERNAL_ERROR;

    size_t der_len = 0;
    der_encode_sig(sig64, sig64 + 32, sig, &der_len);
    if (sig_len) *sig_len = der_len;
    if (info) *info = pby ? CX_ECCINFO_PARITY_ODD : 0;
    memzero(sig64, 64);
    return CX_OK;
}

cx_err_t bip32_derive_get_pubkey_256(cx_curve_t curve,
                                     const uint32_t *path, size_t path_len,
                                     uint8_t raw_pubkey[65], uint8_t *chain_code,
                                     uint32_t hashID) {
    (void)hashID;
    uint8_t priv[32];
    cx_err_t err = os_derive_bip32_no_throw(curve, path, path_len, priv, chain_code);
    if (err != CX_OK) return err;
    int rc = ecdsa_get_public_key65(&secp256k1, priv, raw_pubkey);
    memzero(priv, 32);
    return rc == 0 ? CX_OK : CX_INTERNAL_ERROR;
}

/* ───────────────────── hashes ───────────────────── */

struct sim_hash_ctx {
    uint32_t alg;      /* CX_KECCAK / CX_SHA256 / CX_SHA512 */
    union {
        SHA3_CTX      keccak;
        SHA256_CTX    sha256;
        SHA512_CTX    sha512;
        BLAKE2B_CTX   blake2b;
    } u;
    size_t out_size;
};
_Static_assert(sizeof(struct sim_hash_ctx) <= sizeof(cx_hash_t),
               "cx_hash_t opaque area too small");

cx_err_t cx_keccak_init_no_throw(cx_sha3_t *hash, size_t size) {
    if (size != 256) return CX_INVALID_PARAMETER;
    struct sim_hash_ctx *c = (struct sim_hash_ctx *)hash;
    c->alg = CX_KECCAK;
    keccak_256_Init(&c->u.keccak);
    return CX_OK;
}

cx_err_t cx_sha256_init(cx_sha256_t *hash) {
    struct sim_hash_ctx *c = (struct sim_hash_ctx *)hash;
    c->alg = CX_SHA256;
    sha256_Init(&c->u.sha256);
    return CX_OK;
}

cx_err_t cx_hash_init_ex(cx_hash_t *hash, uint32_t alg, size_t out_size) {
    struct sim_hash_ctx *c = (struct sim_hash_ctx *)hash;
    switch (alg) {
    case CX_KECCAK:
        if (out_size != 32) return CX_INVALID_PARAMETER;
        return cx_keccak_init_no_throw(hash, 256);
    case CX_SHA256: return cx_sha256_init(hash);
    case CX_SHA512:
        c->alg = CX_SHA512;
        sha512_Init(&c->u.sha512);
        return CX_OK;
    case CX_BLAKE2B:
        c->alg = CX_BLAKE2B;
        c->out_size = out_size;
        return blake2b_Init(&c->u.blake2b, out_size) == 0 ? CX_OK : CX_INVALID_PARAMETER;
    default: return CX_INVALID_PARAMETER;
    }
}

static cx_err_t sim_hash_update(struct sim_hash_ctx *c, const uint8_t *in, size_t len) {
    switch (c->alg) {
    case CX_KECCAK: keccak_Update(&c->u.keccak, in, len); return CX_OK;
    case CX_SHA256: sha256_Update(&c->u.sha256, in, len); return CX_OK;
    case CX_SHA512: sha512_Update(&c->u.sha512, in, len); return CX_OK;
    case CX_BLAKE2B: return blake2b_Update(&c->u.blake2b, in, len) == 0 ? CX_OK : CX_INVALID_PARAMETER;
    default: return CX_INVALID_PARAMETER;
    }
}

static cx_err_t sim_hash_final(struct sim_hash_ctx *c, uint8_t *out) {
    switch (c->alg) {
    case CX_KECCAK: keccak_Final(&c->u.keccak, out); return CX_OK;
    case CX_SHA256: sha256_Final(&c->u.sha256, out); return CX_OK;
    case CX_SHA512: sha512_Final(&c->u.sha512, out); return CX_OK;
    case CX_BLAKE2B: return blake2b_Final(&c->u.blake2b, out, c->out_size) == 0 ? CX_OK : CX_INVALID_PARAMETER;
    default: return CX_INVALID_PARAMETER;
    }
}

cx_err_t cx_hash_update(cx_hash_t *hash, const uint8_t *in, size_t len) {
    return sim_hash_update((struct sim_hash_ctx *)hash, in, len);
}

cx_err_t cx_hash_final(cx_hash_t *hash, uint8_t *digest) {
    return sim_hash_final((struct sim_hash_ctx *)hash, digest);
}

cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode,
                          const uint8_t *in, size_t len,
                          uint8_t *out, size_t out_len) {
    (void)out_len;
    struct sim_hash_ctx *c = (struct sim_hash_ctx *)hash;
    cx_err_t err = CX_OK;
    if (in && len) err = sim_hash_update(c, in, len);
    if (err != CX_OK) return err;
    if (mode & CX_LAST) err = sim_hash_final(c, out);
    return err;
}

cx_err_t cx_keccak_256_hash(const uint8_t *in, size_t len, uint8_t out[32]) {
    keccak_256(in, len, out);
    return CX_OK;
}

size_t cx_hash_sha512(const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t out_len) {
    if (out_len < 64) return 0;
    sha512_Raw(in, in_len, out);
    return 64; /* BOLOS returns the digest size */
}

cx_err_t cx_blake2b_512_hash(const uint8_t *in, size_t len, uint8_t out[64]) {
    return blake2b(in, (uint32_t)len, out, 64) == 0 ? CX_OK : CX_INTERNAL_ERROR;
}

/* ───────────────────── RNG ───────────────────── */

cx_err_t cx_get_random_bytes(void *buffer, size_t len) {
    /* Deterministic when SIM_RNG_SEED is set (reproducible tests). */
    static uint64_t st = 0;
    static int inited = 0;
    const char *env = getenv("SIM_RNG_SEED");
    if (env) {
        if (!inited) { st = strtoull(env, NULL, 0) | 1u; inited = 1; }
        uint8_t *p = buffer;
        for (size_t i = 0; i < len; i++) {
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            p[i] = (uint8_t)st;
        }
        return CX_OK;
    }
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return CX_INTERNAL_ERROR;
    size_t n = fread(buffer, 1, len, f);
    fclose(f);
    return n == len ? CX_OK : CX_INTERNAL_ERROR;
}

void cx_trng_init(void) {}

/* random32 required by vendored trezor rand.c users */
uint32_t random32(void) {
    uint32_t v = 0;
    cx_get_random_bytes(&v, sizeof(v));
    return v;
}


/* ───────────── minimal cx_bn (big-endian byte arrays, ≤64B) ───────────── */

#define SIM_BN_MAX   16
#define SIM_BN_BYTES 64

static struct { uint8_t v[SIM_BN_BYTES]; size_t size; int used; } g_bn[SIM_BN_MAX];

cx_err_t cx_bn_lock(size_t word_size, uint32_t flags) {
    (void)word_size; (void)flags;
    memset(g_bn, 0, sizeof(g_bn));
    return CX_OK;
}
cx_err_t cx_bn_unlock(void) { memset(g_bn, 0, sizeof(g_bn)); return CX_OK; }

cx_err_t cx_bn_alloc(cx_bn_t *x, size_t size) {
    if (size > SIM_BN_BYTES) return CX_INVALID_PARAMETER;
    for (int i = 0; i < SIM_BN_MAX; i++) {
        if (!g_bn[i].used) {
            g_bn[i].used = 1;
            g_bn[i].size = size;
            memset(g_bn[i].v, 0, SIM_BN_BYTES);
            *x = (cx_bn_t)i;
            return CX_OK;
        }
    }
    return CX_INTERNAL_ERROR;
}

cx_err_t cx_bn_init(cx_bn_t x, const uint8_t *value, size_t value_len) {
    if (x >= SIM_BN_MAX || !g_bn[x].used || value_len > g_bn[x].size)
        return CX_INVALID_PARAMETER;
    memset(g_bn[x].v, 0, SIM_BN_BYTES);
    /* right-aligned in the fixed 64-byte big-endian array, matching
     * cx_bn_export's offset convention */
    memcpy(g_bn[x].v + (SIM_BN_BYTES - value_len), value, value_len);
    return CX_OK;
}

cx_err_t cx_bn_alloc_init(cx_bn_t *x, size_t size,
                          const uint8_t *value, size_t value_len) {
    cx_err_t err = cx_bn_alloc(x, size);
    if (err != CX_OK) return err;
    return cx_bn_init(*x, value, value_len);
}

cx_err_t cx_bn_copy(cx_bn_t dst, cx_bn_t src) {
    if (dst >= SIM_BN_MAX || src >= SIM_BN_MAX || !g_bn[dst].used || !g_bn[src].used)
        return CX_INVALID_PARAMETER;
    memcpy(g_bn[dst].v, g_bn[src].v, SIM_BN_BYTES);
    return CX_OK;
}

/* byte-array helpers on the fixed 64-byte big-endian representation */
static int ba_cmp(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, SIM_BN_BYTES);
}
static void ba_sub(uint8_t *a, const uint8_t *b) { /* a -= b (a >= b) */
    int borrow = 0;
    for (int i = SIM_BN_BYTES - 1; i >= 0; i--) {
        int d = (int)a[i] - (int)b[i] - borrow;
        borrow = d < 0;
        a[i] = (uint8_t)(d + (borrow ? 256 : 0));
    }
}
static int ba_shl1(uint8_t *a) { /* a <<= 1, returns carry out */
    int carry = 0;
    for (int i = SIM_BN_BYTES - 1; i >= 0; i--) {
        int c = a[i] >> 7;
        a[i] = (uint8_t)((a[i] << 1) | carry);
        carry = c;
    }
    return carry;
}
static void ba_shr1(uint8_t *a) {
    int carry = 0;
    for (int i = 0; i < SIM_BN_BYTES; i++) {
        int c = a[i] & 1;
        a[i] = (uint8_t)((a[i] >> 1) | (carry << 7));
        carry = c;
    }
}

cx_err_t cx_bn_reduce(cx_bn_t r, cx_bn_t a, cx_bn_t n) {
    if (r >= SIM_BN_MAX || a >= SIM_BN_MAX || n >= SIM_BN_MAX) return CX_INVALID_PARAMETER;
    uint8_t rem[SIM_BN_BYTES], m[SIM_BN_BYTES];
    memcpy(rem, g_bn[a].v, SIM_BN_BYTES);
    /* align m to rem, then classic shift-subtract */
    memcpy(m, g_bn[n].v, SIM_BN_BYTES);
    static const uint8_t zero[SIM_BN_BYTES] = {0};
    if (ba_cmp(m, zero) == 0) return CX_INVALID_PARAMETER;
    int shifts = 0;
    while (ba_cmp(m, rem) < 0) {
        uint8_t tmp[SIM_BN_BYTES];
        memcpy(tmp, m, SIM_BN_BYTES);
        if (ba_shl1(tmp)) break; /* would overflow: m already max-aligned */
        if (ba_cmp(tmp, rem) > 0) break;
        memcpy(m, tmp, SIM_BN_BYTES);
        shifts++;
    }
    for (;;) {
        if (ba_cmp(rem, m) >= 0) ba_sub(rem, m);
        if (shifts == 0) break;
        ba_shr1(m);
        shifts--;
    }
    memcpy(g_bn[r].v, rem, SIM_BN_BYTES);
    return CX_OK;
}

cx_err_t cx_bn_export(cx_bn_t x, uint8_t *bytes, size_t len) {
    if (x >= SIM_BN_MAX || !g_bn[x].used || len > SIM_BN_BYTES) return CX_INVALID_PARAMETER;
    memcpy(bytes, g_bn[x].v + (SIM_BN_BYTES - len), len);
    return CX_OK;
}

cx_err_t cx_bn_destroy(cx_bn_t *x) {
    if (x && *x < SIM_BN_MAX) {
        memset(&g_bn[*x], 0, sizeof(g_bn[0]));
    }
    return CX_OK;
}
