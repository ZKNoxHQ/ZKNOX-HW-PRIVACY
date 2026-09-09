/* sim/shim/shim_crypto_ext.c — debug-mode extensions:
 *   - Ed25519 point decompress + variable-base scalar mult (BOLOS buffer
 *     convention: 65B 04||X_be||Y_be, decompress input 02||comp32).
 *   - AES-256-GCM via vendored Gladman (trezor-firmware crypto/aes).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "cx.h"
#include "memzero.h"

#include "fixedint.h"
#include "fe.h"
#include "ge.h"

#include "aesgcm.h"

/* ── Ed25519 ── */

static void fe_to_be32(uint8_t out[32], const fe f) {
    uint8_t le[32];
    fe_tobytes(le, (int32_t *)f);
    for (int i = 0; i < 32; i++) out[i] = le[31 - i];
}

/* decompress: in/out share the BOLOS buffer P[65].
 * input  P[0]=0x02, P[1..33]=RFC8032 compressed (LE y + sign bit)
 * output P[0]=0x04, P[1..33]=X_be, P[33..65]=Y_be */
cx_err_t cx_edwards_decompress_point_no_throw(cx_curve_t curve,
                                              uint8_t *P, size_t P_len) {
    if (curve != CX_CURVE_Ed25519 || P_len < 65 || P[0] != 0x02)
        return CX_INVALID_PARAMETER;

    ge_p3 A;
    /* ge_frombytes_negate_vartime computes -A from the compressed form */
    if (ge_frombytes_negate_vartime(&A, P + 1) != 0)
        return CX_EC_INVALID_POINT;
    /* negate X and T to recover A */
    fe_neg(A.X, A.X);
    fe_neg(A.T, A.T);

    fe zinv, x, y;
    fe_invert(zinv, A.Z);
    fe_mul(x, A.X, zinv);
    fe_mul(y, A.Y, zinv);

    P[0] = 0x04;
    fe_to_be32(P + 1, x);
    fe_to_be32(P + 33, y);
    return CX_OK;
}

/* variable-base scalar mult on the BOLOS 04||X_be||Y_be buffer.
 * k is big-endian. Implemented as k*A + 0*B via ge_double_scalarmult. */
cx_err_t cx_ecfp_scalar_mult_no_throw(cx_curve_t curve, uint8_t *P,
                                      const uint8_t *k, size_t k_len) {
    if (curve != CX_CURVE_Ed25519 || k_len != 32 || P[0] != 0x04)
        return CX_INVALID_PARAMETER;

    /* rebuild compressed form from X_be/Y_be to reuse ge_frombytes */
    uint8_t comp[32];
    for (int i = 0; i < 32; i++) comp[i] = P[64 - i];    /* y little-endian */
    comp[31] &= 0x7F;
    comp[31] |= (uint8_t)((P[32] & 1u) << 7);            /* sign of x */

    ge_p3 A;
    if (ge_frombytes_negate_vartime(&A, comp) != 0)
        return CX_EC_INVALID_POINT;
    fe_neg(A.X, A.X);
    fe_neg(A.T, A.T);

    uint8_t k_le[32], zero[32] = {0};
    for (int i = 0; i < 32; i++) k_le[i] = k[31 - i];

    ge_p2 R2;
    ge_double_scalarmult_vartime(&R2, k_le, &A, zero);   /* k*A + 0*B */

    fe zinv, x, y;
    fe_invert(zinv, R2.Z);
    fe_mul(x, R2.X, zinv);
    fe_mul(y, R2.Y, zinv);

    P[0] = 0x04;
    fe_to_be32(P + 1, x);
    fe_to_be32(P + 33, y);
    memzero(k_le, 32);
    return CX_OK;
}

/* ── AES-256-GCM ── */

struct sim_gcm { gcm_ctx g; int keyed; };
_Static_assert(sizeof(struct sim_gcm) <= sizeof(cx_aes_gcm_context_t),
               "cx_aes_gcm_context_t too small");

void cx_aes_gcm_init(cx_aes_gcm_context_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

cx_err_t cx_aes_gcm_set_key(cx_aes_gcm_context_t *ctx,
                            const uint8_t *key, size_t key_len) {
    struct sim_gcm *c = (struct sim_gcm *)ctx;
    if (gcm_init_and_key(key, (unsigned long)key_len, &c->g) != RETURN_GOOD)
        return CX_INVALID_PARAMETER;
    c->keyed = 1;
    return CX_OK;
}

cx_err_t cx_aes_gcm_encrypt_and_tag(cx_aes_gcm_context_t *ctx,
                                    uint8_t *in, size_t len,
                                    const uint8_t *iv, size_t iv_len,
                                    const uint8_t *aad, size_t aad_len,
                                    uint8_t *out, uint8_t *tag, size_t tag_len) {
    struct sim_gcm *c = (struct sim_gcm *)ctx;
    if (!c->keyed) return CX_INVALID_PARAMETER;
    if (out != in) memcpy(out, in, len);
    int rc = gcm_encrypt_message(iv, (unsigned long)iv_len,
                                 aad, (unsigned long)aad_len,
                                 out, (unsigned long)len,
                                 tag, (unsigned long)tag_len, &c->g);
    return rc == RETURN_GOOD ? CX_OK : CX_INTERNAL_ERROR;
}

/* Mirror of encrypt_and_tag. gcm_decrypt_message verifies the tag itself and
 * returns RETURN_ERROR on mismatch — which is a legitimate rejection, not a
 * fault: the caller maps it to a clean error. Needed by the DKG share
 * transport (the note path only ever encrypts on-device). */
cx_err_t cx_aes_gcm_decrypt_and_auth(cx_aes_gcm_context_t *ctx,
                                     uint8_t *in, size_t len,
                                     const uint8_t *iv, size_t iv_len,
                                     const uint8_t *aad, size_t aad_len,
                                     uint8_t *out, const uint8_t *tag, size_t tag_len) {
    struct sim_gcm *c = (struct sim_gcm *)ctx;
    if (!c->keyed) return CX_INVALID_PARAMETER;
    if (out != in) memcpy(out, in, len);
    int rc = gcm_decrypt_message(iv, (unsigned long)iv_len,
                                 aad, (unsigned long)aad_len,
                                 out, (unsigned long)len,
                                 tag, (unsigned long)tag_len, &c->g);
    if (rc != RETURN_GOOD) { memset(out, 0, len); return CX_INVALID_PARAMETER; }
    return CX_OK;
}
