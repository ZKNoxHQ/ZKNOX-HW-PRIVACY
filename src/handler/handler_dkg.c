// handler_dkg.c
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "os.h"
#include "cx.h"
#include "os_random.h"
#include "buffer.h"
#include "io.h"

#include "../sw.h"
#include "handler_frost_sign.h"
#include "../constants.h"
#include "zkn_errors.h"
#include "zkn_keyderivation.h"
#include "zkn_tEdwards.h"
#include "zkn_vss.h"
#include "zkn_rfc9591frost.h"
#include "zkn_ed25519_ecdh.h"
#include "zkn_ed25519_scalar.h"
#include "zkn_aes_gcm.h"
#include "handler_dkg.h"
#include "../zkn_features.h"

#if defined(ZKN_FROST)

/* Bounds are deliberately tighter than VSS_MAX_*: the commitments have to be
 * buffered whole to feed Babyfrost_H5 (rfc9591_reduce_wide is static, so the
 * digest can't be streamed without exposing it from the libC). 5*3*32 = 480 B
 * covers 2-of-3 and 3-of-5. Raising these means adding a streaming tagged-hash
 * to zkn_rfc9591frost.h first. */
#define DKG_MAX_N        5
#define DKG_MAX_T        3
#define DKG_NONCE_LEN    12
#define DKG_TAG_LEN      16

enum dkg_state {
    DKG_IDLE = 0, DKG_DEALT, DKG_COMMITTED, DKG_COLLECTED, DKG_PROVISIONED
};

/* Transient ceremony state. The coefficients are the sensitive part: they are
 * derived here and never leave, and DKG_ABORT wipes them. */
static struct {
    uint8_t  state;
    uint32_t account;
    size_t   id, t, n;
    uint8_t  epoch[VSS_EPOCH_LEN];
    uint8_t  name[VSS_MAX_NAME_LEN];
    size_t   name_len;

    uint8_t  coeffs[DKG_MAX_T * 32];           /* secret */

    /* Streamed instead of storing n*t points (RAM on Nano). */
    uint8_t  hj[DKG_MAX_N][32];                /* H(C_j) per dealer */
    uint8_t  c0[DKG_MAX_N][64];                /* C_{j,0}, for A = sum */
    uint8_t  hk[DKG_MAX_N][32];                /* comm pubkeys */
    uint8_t  dealer_id[DKG_MAX_N];
    size_t   ndealers;
    uint8_t  last_c0[64];                      /* monotonicity check */
    int      have_last;

    uint8_t  comp[DKG_MAX_N * DKG_MAX_T * 32]; /* compressed commitments, digest input */
    size_t   comp_len;
    uint8_t  digest[32];

    uint8_t  acc[32];                          /* sum of received shares */
    uint16_t recv_mask;

    /* Persisted at FINALIZE. Real firmware: NVRAM.
     * This is f(i) = sum of the dealers' evaluations — the share as the FROST
     * papers define it. The zkn_frost_* API wants 8*f(i) (BabyJubJub cofactor;
     * A = sum C_{j,0} is on the prime-order subgroup), so the multiply happens
     * in dkg_get_signer, at the point of use, not here. */
    uint8_t  skshare_div8[32];
    uint8_t  A[64];
} g_dkg;

int dkg_get_signer(uint8_t *skshare_out, uint8_t *A_out,
                   size_t *id_out, size_t *t_out, size_t *n_out)
{
    if (g_dkg.state != DKG_PROVISIONED) return -1;
    /* 8*f(i) mod L — what zkn_frost_commit/zkn_partial_sig take, mirroring
     * get_vss.c's sk_share vs sk_share_div8. Handing over the raw sum yields
     * partial signatures that verify individually and fail to aggregate. */
    if (skshare_out) {
        /* The bn engine needs its lock held; callers reach this before taking
         * their own, so take and release it here. */
        if (zkn_bn_lock(32, 0) != 0) return -1;
        int rc = -1;
        zkn_edcurve_t c;
        if (tEdwards_Curve_alloc_init(&c, _BABYJUJUB_ID) != 0) goto signer_cleanup;
        zkn_bn_t s, e, r;
        if (zkn_bn_alloc(&s, 32) != 0 || zkn_bn_alloc(&e, 32) != 0 ||
            zkn_bn_alloc(&r, 32) != 0) goto signer_cleanup;
        rc = zkn_bn_init(s, g_dkg.skshare_div8, 32) || zkn_bn_set_u32(e, 8)
           || zkn_bn_mod_mul(r, s, e, c.order) || zkn_bn_export(r, skshare_out, 32);
signer_cleanup:
        (void)zkn_bn_unlock();
        if (rc != 0) return -1;
    }
    if (A_out)       memcpy(A_out, g_dkg.A, 64);
    if (id_out)      *id_out = g_dkg.id;
    if (t_out)       *t_out  = g_dkg.t;
    if (n_out)       *n_out  = g_dkg.n;
    return 0;
}

/* ── helpers ───────────────────────────────────────────────────── */

static uint32_t rd32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* RFC 8032 compression, mirroring curve.ts::pointCompress + toBytes:
 *   encoded = y | (x&1) << 255, serialized 32-byte little-endian.
 * The C VSS API hands out x||y big-endian, so we byte-reverse y. This is what
 * feeds the digest — it must match SerializeElement byte for byte. */
static void dkg_compress(const uint8_t *xy_be64, uint8_t *out_le32) {
    for (size_t i = 0; i < 32; i++) out_le32[i] = xy_be64[63 - i];  /* y, BE -> LE */
    out_le32[31] |= (uint8_t)((xy_be64[31] & 1) << 7);              /* sign of x -> bit 255 */
}

/* Order of dealers in the digest is sortKey(C_{j,0}) = hex(x)||':'||hex(y),
 * i.e. big-endian numeric on x then y — exactly memcmp on x||y BE. */
static int dkg_c0_cmp(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 64); }

static int dkg_index_of(size_t id) {
    for (size_t k = 0; k < g_dkg.ndealers; k++)
        if (g_dkg.dealer_id[k] == (uint8_t)id) return (int)k;
    return -1;
}

static void dkg_wipe(void) {
    explicit_bzero(&g_dkg, sizeof(g_dkg));
    g_dkg.state = DKG_IDLE;
    /* The FROST nonces are a secret of the share that just went away: without
     * this, (d_i, e_i) and FS_NONCED survive an explicit wipe, and a restore
     * could sign with commitments published under the previous provisioning. */
    fs_wipe();
}

/* Comm key: Ed25519, derived on a dedicated hardened path; the private half
 * never leaves production firmware.
 * The ECDH scalar is the EdDSA one (SHA-512 + clamp + mod L), NOT the raw
 * private key: the pubkey is [clamp(H(priv))]B, so using the raw key would make
 * ECDH asymmetric — k_ij != k_ji — and every share would fail to decrypt. */
static int dkg_comm_scalar(uint32_t account, uint8_t *scalar32) {
    uint8_t seed[64], cc[32];
    int rc = -1;
    if (derive_private_key(KEY_TYPE_DKG_COMM, account, seed, cc) != ZKN_OK) goto out;
    if (zkn_ed25519_scalar_from_seed(seed, scalar32) != 0) goto out;
    rc = 0;
out:
    explicit_bzero(seed, sizeof(seed));
    explicit_bzero(cc, sizeof(cc));
    return rc;
}

/* ── 0x60 GET_COMM_PUBKEY ──────────────────────────────────────── */
int handler_dkg_get_comm_pubkey(buffer_t *cdata)
{
    if (cdata->size != 4) return io_send_sw(SW_WRONG_DATA_LENGTH);
    uint8_t seed[64], cc[32], pub[32];
    size_t publen = 0;
    if (derive_private_key(KEY_TYPE_DKG_COMM, rd32be(cdata->ptr), seed, cc) != ZKN_OK)
        return io_send_sw(SW_SIGNATURE_FAIL);
    zkn_error_t rc = derive_public_key(KEY_TYPE_DKG_COMM, PUBKEY_FORMAT_RAW, seed, pub, &publen);
    explicit_bzero(seed, sizeof(seed));
    explicit_bzero(cc, sizeof(cc));
    if (rc != ZKN_OK || publen != 32) return io_send_sw(SW_SIGNATURE_FAIL);
    return io_send_response_pointer(pub, 32, SW_OK);
}

/* ── 0x61 DEAL ─────────────────────────────────────────────────── */
int handler_dkg_deal(buffer_t *cdata)
{
    if (cdata->size < 8) return io_send_sw(SW_WRONG_DATA_LENGTH);
    const uint8_t *d = cdata->ptr;
    uint32_t account = rd32be(d);
    size_t id = d[4], t = d[5], n = d[6], nl = d[7];
    if (cdata->size != 8 + nl) return io_send_sw(SW_WRONG_DATA_LENGTH);
    if (id == 0 || id > n || t == 0 || t > n || n > DKG_MAX_N) return io_send_sw(SW_WRONG_DATA_LENGTH);
    if (t > DKG_MAX_T || nl > VSS_MAX_NAME_LEN) return io_send_sw(SW_WRONG_DATA_LENGTH);
    /* Re-dealing over a provisioned signer would destroy it: force an explicit
     * ABORT rather than silently overwriting. */
    if (g_dkg.state == DKG_PROVISIONED) return io_send_sw(SW_BAD_STATE);

    dkg_wipe();
    g_dkg.account = account; g_dkg.id = id; g_dkg.t = t; g_dkg.n = n;
    g_dkg.name_len = nl;
    if (nl) memcpy(g_dkg.name, d + 8, nl);

    /* Audit L3: single cleanup point for the sensitive intermediates.
     * seed[64] carries the raw spending seed; cc[32] the chain code; p
     * carries a copy of seed+epoch. On the RNG-failure path g_dkg.epoch
     * may hold a partial RNG write, which is used to bind FROST nonces
     * and DKG shares — wipe it so no stray copy becomes a correlation
     * oracle. Declarations up-front so goto cleanup never crosses an
     * initialiser (-Wjump-misses-init). */
    uint8_t seed[64] = {0}, cc[32] = {0};
    uint8_t out[VSS_EPOCH_LEN + DKG_MAX_T * 64];
    participant_t p;
    zkn_edcurve_t curve;
    int sw = 0, rc = 0;
    bool bn_locked = false;
    explicit_bzero(&p, sizeof(p));

    /* The epoch is the ONLY randomness here: the coefficients are deterministic
     * (recovery), so this is what stops two ceremonies of the same (n,t,name)
     * from reusing the same polynomial. Drawn on-device: a host-supplied epoch
     * could be replayed. */
    if (cx_get_random_bytes(g_dkg.epoch, VSS_EPOCH_LEN) != CX_OK) {
        explicit_bzero(g_dkg.epoch, VSS_EPOCH_LEN);
        sw = SW_SIGNATURE_FAIL; goto cleanup;
    }

    if (derive_private_key(KEY_TYPE_SPENDING, account, seed, cc) != ZKN_OK) {
        sw = SW_SIGNATURE_FAIL; goto cleanup;
    }

    p.id = id; p.n = n; p.name_len = nl;
    memcpy(p.seed, seed, 32);
    memcpy(p.epoch, g_dkg.epoch, VSS_EPOCH_LEN);
    if (nl) memcpy(p.name, g_dkg.name, nl);

    if (zkn_bn_lock(32, 0) != 0) {
        sw = SW_SIGNATURE_FAIL; goto cleanup;
    }
    bn_locked = true;

    if (tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID) != 0) {
        sw = SW_SIGNATURE_FAIL; goto cleanup;
    }

    rc = makeDealerCoeffsDeterministic(&curve, &p, t, 0, g_dkg.coeffs);
    if (rc != 0) { dkg_wipe(); sw = SW_SIGNATURE_FAIL; goto cleanup; }
    if (makeDealerCommitments(&curve, g_dkg.coeffs, t, out + VSS_EPOCH_LEN) != 0) {
        dkg_wipe(); sw = SW_SIGNATURE_FAIL; goto cleanup;
    }
    if (zkn_bn_unlock() != 0) {
        bn_locked = false;
        dkg_wipe(); sw = SW_SIGNATURE_FAIL; goto cleanup;
    }
    bn_locked = false;
    memcpy(out, g_dkg.epoch, VSS_EPOCH_LEN);
    g_dkg.state = DKG_DEALT;

    explicit_bzero(seed, sizeof(seed));
    explicit_bzero(cc, sizeof(cc));
    explicit_bzero(&p, sizeof(p));
    return io_send_response_pointer(out, VSS_EPOCH_LEN + t * 64, SW_OK);

cleanup:
    if (bn_locked) (void)zkn_bn_unlock();
    explicit_bzero(seed, sizeof(seed));
    explicit_bzero(cc, sizeof(cc));
    explicit_bzero(&p, sizeof(p));
    return io_send_sw(sw);
}

/* ── 0x62 SET_COMMITS (chunked) ────────────────────────────────── */
int handler_dkg_set_commits(uint8_t p1, buffer_t *cdata)
{
    const uint8_t P1_FIRST = 0x00, P1_LAST = 0x02;
    if (p1 > P1_LAST) return io_send_sw(SW_WRONG_P1P2);
    if (p1 == P1_FIRST) {
        if (g_dkg.state != DKG_DEALT) return io_send_sw(SW_BAD_STATE);
        g_dkg.ndealers = 0; g_dkg.have_last = 0; g_dkg.comp_len = 0;
    } else if (g_dkg.state != DKG_DEALT) {
        return io_send_sw(SW_BAD_STATE);
    }

    const size_t rec = 1 + 32 + g_dkg.t * 64;
    if (cdata->size == 0 || cdata->size % rec != 0) return io_send_sw(SW_WRONG_DATA_LENGTH);

    for (size_t off = 0; off + rec <= cdata->size; off += rec) {
        const uint8_t *r = cdata->ptr + off;
        size_t id = r[0];
        if (id == 0 || id > g_dkg.n) return io_send_sw(SW_WRONG_DATA_LENGTH);
        if (g_dkg.ndealers >= DKG_MAX_N) return io_send_sw(SW_WRONG_DATA_LENGTH);
        if (dkg_index_of(id) >= 0) return io_send_sw(SW_WRONG_DATA_LENGTH);  /* dup */

        const uint8_t *hk = r + 1;
        const uint8_t *cj = r + 33;

        /* HK is the one field here the digest does not cover (see comp[]
         * below: only the commitments are absorbed). Diffie-Hellman with an
         * unauthenticated peer key is a man-in-the-middle by construction — a
         * host that swaps HK_j for its own g^a derives the very key we do,
         * since KDF(s_i·g^a) == KDF(a·HK_i) and HK_i is public and routed by
         * that same host. It then reads every share addressed to j, i.e. all
         * of sk_j, without touching j's device. Nothing downstream notices: A
         * is computed from the genuine commitments, so FINALIZE still shows
         * the right value on screen.
         *
         * Our own entry is the one we can anchor: it must be the key this seed
         * derives. That alone breaks the attack — the victim refuses. Binding
         * HK into the digest is the complementary fix, but it changes the wire
         * digest and has to land with vss-dkg.ts, so it is not done here. */
        if (id == g_dkg.id) {
            uint8_t seed[64], cc[32], mine[32];
            size_t mine_len = 0;
            if (derive_private_key(KEY_TYPE_DKG_COMM, g_dkg.account, seed, cc) != ZKN_OK) {
                explicit_bzero(seed, sizeof(seed));
                explicit_bzero(cc, sizeof(cc));
                return io_send_sw(SW_SIGNATURE_FAIL);
            }
            zkn_error_t drc = derive_public_key(KEY_TYPE_DKG_COMM, PUBKEY_FORMAT_RAW,
                                                seed, mine, &mine_len);
            explicit_bzero(seed, sizeof(seed));
            explicit_bzero(cc, sizeof(cc));
            if (drc != ZKN_OK || mine_len != 32) return io_send_sw(SW_SIGNATURE_FAIL);
            int mismatch = (memcmp(mine, hk, 32) != 0);
            explicit_bzero(mine, sizeof(mine));
            if (mismatch) return io_send_sw(SW_SIGNATURE_FAIL);
        }

        /* Sorted order is what makes the digest canonical: every device must
         * absorb the same byte string. A host that reorders is rejected here. */
        if (g_dkg.have_last && dkg_c0_cmp(g_dkg.last_c0, cj) >= 0)
            return io_send_sw(SW_WRONG_DATA_LENGTH);
        memcpy(g_dkg.last_c0, cj, 64);
        g_dkg.have_last = 1;

        /* Accumulate the compressed points (digest input), and keep only
         * H_j + C_{j,0} + HK_j per dealer. */
        if (g_dkg.comp_len + g_dkg.t * 32 > sizeof(g_dkg.comp)) return io_send_sw(SW_WRONG_DATA_LENGTH);
        for (size_t k = 0; k < g_dkg.t; k++)
            dkg_compress(cj + k * 64, g_dkg.comp + g_dkg.comp_len + k * 32);
        g_dkg.comp_len += g_dkg.t * 32;

        uint8_t hj[64];
        if (zkn_blake2b_512_hash(cj, g_dkg.t * 64, hj) != 0) return io_send_sw(SW_SIGNATURE_FAIL);

        size_t k = g_dkg.ndealers++;
        g_dkg.dealer_id[k] = (uint8_t)id;
        memcpy(g_dkg.hj[k], hj, 32);
        memcpy(g_dkg.c0[k], cj, 64);
        memcpy(g_dkg.hk[k], hk, 32);
    }

    if (p1 != P1_LAST) return io_send_sw(SW_OK);

    if (g_dkg.ndealers != g_dkg.n) return io_send_sw(SW_WRONG_DATA_LENGTH);

    /* commitmentsDigest = H5(concat of compressed commitments, dealer-sorted),
     * i.e. vss-dkg.ts::commitmentsDigest over encodeCommitmentsBytes. */
    if (zkn_bn_lock(32, 0) != 0) return io_send_sw(SW_SIGNATURE_FAIL);
    int math_rc = -1;
    zkn_edcurve_t curve;
    if (tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID) != 0) goto commits_cleanup;
    zkn_bn_t h;
    if (zkn_bn_alloc(&h, 32) != 0) goto commits_cleanup;
    if (Babyfrost_H5(g_dkg.comp, g_dkg.comp_len, curve.order, h) != 0) goto commits_cleanup;
    if (zkn_bn_export(h, g_dkg.digest, 32) != 0) goto commits_cleanup;
    math_rc = 0;

commits_cleanup:
    if (zkn_bn_unlock() != 0) math_rc = -1;
    if (math_rc != 0) return io_send_sw(SW_SIGNATURE_FAIL);

    g_dkg.state = DKG_COMMITTED;
    return io_send_response_pointer(g_dkg.digest, 32, SW_OK);
}

/* AAD = SerializeScalar(id) || commitmentsDigest, both 32-byte little-endian. */
static void dkg_aad(size_t id, uint8_t *aad64) {
    explicit_bzero(aad64, 64);
    for (size_t k = 0; k < 8; k++) aad64[k] = (uint8_t)((id >> (8 * k)) & 0xFF);
    for (size_t k = 0; k < 32; k++) aad64[32 + k] = g_dkg.digest[31 - k];  /* BE -> LE */
}

/* ── 0x63 GET_SHARE ────────────────────────────────────────────── */
int handler_dkg_get_share(buffer_t *cdata)
{
    /* Refused before COMMITTED: this IS the round-1 barrier. Without a frozen
     * digest there is no AAD to bind the share to this ceremony. */
    if (g_dkg.state != DKG_COMMITTED) return io_send_sw(SW_BAD_STATE);
    if (cdata->size != 1) return io_send_sw(SW_WRONG_DATA_LENGTH);
    size_t j = cdata->ptr[0];
    if (j == 0 || j > g_dkg.n || j == g_dkg.id) return io_send_sw(SW_WRONG_DATA_LENGTH);
    int k = dkg_index_of(j);
    if (k < 0) return io_send_sw(SW_WRONG_DATA_LENGTH);

    uint8_t share[32] = {0};
    if (zkn_bn_lock(32, 0) != 0) return io_send_sw(SW_SIGNATURE_FAIL);
    int math_rc = -1;
    zkn_edcurve_t curve;
    if (tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID) == 0 &&
        computeDealerShareForId(&curve, g_dkg.coeffs, g_dkg.t, j, share) == 0)
        math_rc = 0;
    if (zkn_bn_unlock() != 0) math_rc = -1;
    if (math_rc != 0) {
        explicit_bzero(share, sizeof(share));
        return io_send_sw(SW_SIGNATURE_FAIL);
    }

    uint8_t sc[32] = {0}, key[32] = {0};
    if (dkg_comm_scalar(g_dkg.account, sc) != 0) {
        explicit_bzero(sc, sizeof(sc));
        explicit_bzero(key, sizeof(key));
        explicit_bzero(share, sizeof(share));
        return io_send_sw(SW_SIGNATURE_FAIL);
    }
    int rc = zkn_ed25519_ecdh_kdf(sc, g_dkg.hk[k], key);
    explicit_bzero(sc, sizeof(sc));
    if (rc != 0) {
        explicit_bzero(key, sizeof(key));
        explicit_bzero(share, sizeof(share));
        return io_send_sw(SW_SIGNATURE_FAIL);
    }

    /* Share on the wire is 32-byte little-endian (vss.toBytes). */
    uint8_t share_le[32] = {0};
    for (size_t i = 0; i < 32; i++) share_le[i] = share[31 - i];
    explicit_bzero(share, sizeof(share));

    uint8_t out[DKG_NONCE_LEN + 32 + DKG_TAG_LEN] = {0}, aad[64] = {0};
    /* Fresh nonce per encryption: the ECDH key is fixed per pair, so a repeat
     * would break GCM authentication. */
    if (cx_get_random_bytes(out, DKG_NONCE_LEN) != CX_OK) {
        explicit_bzero(key, sizeof(key));
        explicit_bzero(share_le, sizeof(share_le));
        explicit_bzero(out, sizeof(out));
        explicit_bzero(aad, sizeof(aad));
        return io_send_sw(SW_SIGNATURE_FAIL);
    }
    dkg_aad(j, aad);
    rc = zkn_aes256_gcm_encrypt_aad(key, out, DKG_NONCE_LEN, aad, sizeof(aad),
                                    share_le, 32, out + DKG_NONCE_LEN, out + DKG_NONCE_LEN + 32);
    explicit_bzero(key, sizeof(key));
    explicit_bzero(share_le, sizeof(share_le));
    explicit_bzero(aad, sizeof(aad));
    if (rc != 0) {
        explicit_bzero(out, sizeof(out));
        return io_send_sw(SW_SIGNATURE_FAIL);
    }
    return io_send_response_pointer(out, sizeof(out), SW_OK);
}

/* ── 0x64 PUT_SHARE ────────────────────────────────────────────── */
int handler_dkg_put_share(buffer_t *cdata)
{
    if (g_dkg.state != DKG_COMMITTED) return io_send_sw(SW_BAD_STATE);
    const size_t need = 1 + g_dkg.t * 64 + DKG_NONCE_LEN + 32 + DKG_TAG_LEN;
    if (cdata->size != need) return io_send_sw(SW_WRONG_DATA_LENGTH);

    const uint8_t *d = cdata->ptr;
    size_t j = d[0];
    if (j == 0 || j > g_dkg.n || j == g_dkg.id) return io_send_sw(SW_WRONG_DATA_LENGTH);
    int k = dkg_index_of(j);
    if (k < 0) return io_send_sw(SW_WRONG_DATA_LENGTH);
    /* A dealer sends exactly one share: a second is a replay. */
    if (g_dkg.recv_mask & (1u << k)) return io_send_sw(SW_BAD_STATE);

    const uint8_t *cj    = d + 1;
    const uint8_t *nonce = cj + g_dkg.t * 64;
    const uint8_t *ct    = nonce + DKG_NONCE_LEN;
    const uint8_t *tag   = ct + 32;

    /* Re-anchor: the host carries the commitments, we kept only H_j. Any
     * substitution shows up here. */
    uint8_t hj[64];
    if (zkn_blake2b_512_hash(cj, g_dkg.t * 64, hj) != 0) return io_send_sw(SW_SIGNATURE_FAIL);
    if (memcmp(hj, g_dkg.hj[k], 32) != 0) return io_send_sw(SW_SIGNATURE_FAIL);

    uint8_t sc[32], key[32];
    if (dkg_comm_scalar(g_dkg.account, sc) != 0) return io_send_sw(SW_SIGNATURE_FAIL);
    int rc = zkn_ed25519_ecdh_kdf(sc, g_dkg.hk[k], key);
    explicit_bzero(sc, sizeof(sc));
    if (rc != 0) return io_send_sw(SW_SIGNATURE_FAIL);

    /* GCM proves WHO sent it; it says nothing about whether the share is
     * consistent with what the dealer publicly committed to. */
    uint8_t aad[64], share_le[32];
    dkg_aad(g_dkg.id, aad);
    rc = zkn_aes256_gcm_decrypt_aad(key, nonce, DKG_NONCE_LEN, aad, sizeof(aad),
                                    ct, 32, tag, share_le);
    explicit_bzero(key, sizeof(key));
    if (rc != 0) return io_send_sw(SW_SIGNATURE_FAIL);

    uint8_t share_be[32];
    for (size_t i = 0; i < 32; i++) share_be[i] = share_le[31 - i];
    explicit_bzero(share_le, sizeof(share_le));

    /* Feldman and the share accumulator both use the CX BN pool. Keep them in
     * one lock lifetime, then release every handle wholesale. */
    if (zkn_bn_lock(32, 0) != 0) {
        explicit_bzero(share_be, sizeof(share_be));
        return io_send_sw(SW_SIGNATURE_FAIL);
    }
    int math_rc = -1;
    zkn_edcurve_t curve;
    bool valid = false;
    if (tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID) == 0 &&
        verifyFeldmanShare(&curve, g_dkg.id, share_be, cj, g_dkg.t, &valid) == 0 && valid) {
        zkn_bn_t a, s;
        if (zkn_bn_alloc(&a, 32) == 0 && zkn_bn_alloc(&s, 32) == 0 &&
            zkn_bn_init(a, g_dkg.acc, 32) == 0 &&
            zkn_bn_init(s, share_be, 32) == 0 &&
            zkn_bn_mod_add(a, a, s, curve.order) == 0 &&
            zkn_bn_export(a, g_dkg.acc, 32) == 0)
            math_rc = 0;
    }
    explicit_bzero(share_be, sizeof(share_be));
    if (zkn_bn_unlock() != 0) math_rc = -1;
    if (math_rc != 0) return io_send_sw(SW_SIGNATURE_FAIL);

    g_dkg.recv_mask |= (uint16_t)(1u << k);

    /* Every dealer but ourselves. */
    uint16_t full = (uint16_t)((1u << g_dkg.ndealers) - 1);
    int me = dkg_index_of(g_dkg.id);
    if (me >= 0) full &= (uint16_t)~(1u << me);
    if ((g_dkg.recv_mask & full) == full) g_dkg.state = DKG_COLLECTED;

    return io_send_sw(SW_OK);
}

/* ── 0x65 FINALIZE ─────────────────────────────────────────────── */
int handler_dkg_finalize(buffer_t *cdata)
{
    /* The JS manager logs and carries on when a share is missing, summing what
     * it has — a silently wrong skShare. The device must refuse instead. */
    if (g_dkg.state != DKG_COLLECTED) return io_send_sw(SW_BAD_STATE);
    if (cdata->size != 0) return io_send_sw(SW_WRONG_DATA_LENGTH);

    uint8_t own[32] = {0}, new_share[32] = {0}, new_A[64] = {0};
    if (zkn_bn_lock(32, 0) != 0) return io_send_sw(SW_SIGNATURE_FAIL);
    int math_rc = -1;
    zkn_edcurve_t curve;

    if (tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID) == 0 &&
        computeDealerShareForId(&curve, g_dkg.coeffs, g_dkg.t, g_dkg.id, own) == 0) {
        /* skShare_i = own f_i(i) + sum of received shares. */
        zkn_bn_t a, o;
        if (zkn_bn_alloc(&a, 32) == 0 && zkn_bn_alloc(&o, 32) == 0 &&
            zkn_bn_init(a, g_dkg.acc, 32) == 0 &&
            zkn_bn_init(o, own, 32) == 0 &&
            zkn_bn_mod_add(a, a, o, curve.order) == 0 &&
            zkn_bn_export(a, new_share, 32) == 0) {
            /* A = sum of the dealers' constant-term commitments. */
            zkn_edpoint_t acc, pt;
            if (tEdwards_alloc(&curve, &acc) == 0 &&
                tEdwards_alloc(&curve, &pt) == 0 &&
                tEdwards_init(&curve, g_dkg.c0[0], g_dkg.c0[0] + 32, &acc) == 0) {
                math_rc = 0;
                for (size_t k = 1; k < g_dkg.ndealers; k++) {
                    if (tEdwards_init(&curve, g_dkg.c0[k], g_dkg.c0[k] + 32, &pt) != 0 ||
                        tEdwards_add(&curve, &acc, &pt, &acc) != 0) {
                        math_rc = -1;
                        break;
                    }
                }
                if (math_rc == 0 &&
                    (tEdwards_normalize(&curve, &acc) != 0 ||
                     tEdwards_export(&curve, &acc, new_A, new_A + 32) != 0))
                    math_rc = -1;
            }
        }
    }
    explicit_bzero(own, sizeof(own));
    if (zkn_bn_unlock() != 0) math_rc = -1;
    if (math_rc != 0) {
        explicit_bzero(new_share, sizeof(new_share));
        explicit_bzero(new_A, sizeof(new_A));
        return io_send_sw(SW_SIGNATURE_FAIL);
    }

    memcpy(g_dkg.skshare_div8, new_share, sizeof(new_share));
    memcpy(g_dkg.A, new_A, sizeof(new_A));
    explicit_bzero(new_share, sizeof(new_share));
    explicit_bzero(new_A, sizeof(new_A));

    /* Real firmware: display "<name> - t-of-n - A" and wait for Approve before
     * writing NVRAM. Comparing A across the n screens is the equality check —
     * one compromised device is enough to create divergent views. The simulator
     * has no UI, so this is where that gate goes. */

    g_dkg.state = DKG_PROVISIONED;
    explicit_bzero(g_dkg.coeffs, sizeof(g_dkg.coeffs));  /* no longer needed */
    return io_send_response_pointer(g_dkg.A, 64, SW_OK);
}

/* ── 0x66 ABORT / 0x67 STATUS ──────────────────────────────────── */
int handler_dkg_abort(void) { dkg_wipe(); return io_send_sw(SW_OK); }

#if defined(ZKNOX_DEBUG)

/* TEST ONLY — see the header. Exports the comm private key (NOT the clamped
 * scalar) because that is what the JS reference takes: getSharedSymmetricKey
 * does the SHA-512 + clamp itself. */
int handler_dkg_debug_comm_privkey(buffer_t *cdata)
{
    if (cdata->size != 4) return io_send_sw(SW_WRONG_DATA_LENGTH);
    uint8_t seed[64], cc[32];
    if (derive_private_key(KEY_TYPE_DKG_COMM, rd32be(cdata->ptr), seed, cc) != ZKN_OK)
        return io_send_sw(SW_SIGNATURE_FAIL);
    int rc = io_send_response_pointer(seed, 32, SW_OK);
    explicit_bzero(seed, sizeof(seed));
    explicit_bzero(cc, sizeof(cc));
    return rc;
}

/* TEST ONLY — see the header. */
int handler_dkg_debug_skshare(void)
{
    if (g_dkg.state != DKG_PROVISIONED) return io_send_sw(SW_BAD_STATE);
    uint8_t out[64];
    if (dkg_get_signer(out, NULL, NULL, NULL, NULL) != 0) return io_send_sw(SW_BAD_STATE);
    memcpy(out + 32, g_dkg.skshare_div8, 32);
    return io_send_response_pointer(out, 64, SW_OK);
}

#endif // ZKNOX_DEBUG

int handler_dkg_status(void)
{
    uint8_t out[6] = { g_dkg.state, (uint8_t)g_dkg.id, (uint8_t)g_dkg.t, (uint8_t)g_dkg.n,
                       (uint8_t)(g_dkg.recv_mask >> 8), (uint8_t)(g_dkg.recv_mask & 0xFF) };
    return io_send_response_pointer(out, sizeof(out), SW_OK);
}

/* ────────────────────────────────────────────────────────────────────────
 * Share backup / restore.
 *
 * The idea: instead of replaying the ceremony to re-derive skShare (which needs
 * every dealer's epoch and the shares they sent), the device exports skShare
 * encrypted under a key derived from its OWN seed. A device restored from that
 * seed re-derives the key and decrypts — no ceremony, no other devices.
 *
 * Because the key comes from the spending seed (KEY_TYPE_SPENDING, the same
 * secret skShare already descends from), the blob is inert without the seed:
 * it can sit in the clear next to the ceremony journal. Whoever holds the seed
 * already holds everything, so this adds no exposure — but it does mean the
 * seed alone reconstitutes the signing share, without the device.
 *
 * The context (id, n, t, name, A) travels as AAD: authenticated, not secret, so
 * a coordinator can read it to route the right blob to the right device while
 * never touching the share.
 * ──────────────────────────────────────────────────────────────────────── */

#define DKG_BACKUP_MAGIC   0x5A4B4253u  /* "ZKBS" */
#define DKG_BACKUP_VERSION 1

/* backup_key = BLAKE-512( "ZKNOX-share-backup-v1" || spending_seed )[0..32).
 * Domain-separated so it can never coincide with any other use of the seed. */
static int dkg_backup_key(uint32_t account, uint8_t key_out[32])
{
    static const char tag[] = "ZKNOX-share-backup-v1";
    uint8_t seed[64], cc[32], buf[sizeof(tag) - 1 + 32], h[64];
    if (derive_private_key(KEY_TYPE_SPENDING, account, seed, cc) != ZKN_OK) {
        explicit_bzero(seed, sizeof seed); explicit_bzero(cc, sizeof cc);
        return -1;
    }
    memcpy(buf, tag, sizeof(tag) - 1);
    memcpy(buf + sizeof(tag) - 1, seed, 32);
    int rc = zkn_blake2b_512_hash(buf, sizeof buf, h);
    if (rc == 0) memcpy(key_out, h, 32);
    explicit_bzero(seed, sizeof seed); explicit_bzero(cc, sizeof cc);
    explicit_bzero(buf, sizeof buf); explicit_bzero(h, sizeof h);
    return rc;
}

/* The AAD binds the blob to this exact provisioning. Fixed layout so export and
 * restore agree byte for byte.
 *   magic(4) || version(1) || id(1) || n(1) || t(1) || A(64) || name_len(1) || name */
static size_t dkg_backup_aad(uint8_t *out)
{
    size_t o = 0;
    out[o++] = (DKG_BACKUP_MAGIC >> 24) & 0xff; out[o++] = (DKG_BACKUP_MAGIC >> 16) & 0xff;
    out[o++] = (DKG_BACKUP_MAGIC >> 8) & 0xff;  out[o++] = DKG_BACKUP_MAGIC & 0xff;
    out[o++] = DKG_BACKUP_VERSION;
    out[o++] = (uint8_t)g_dkg.id;
    out[o++] = (uint8_t)g_dkg.n;
    out[o++] = (uint8_t)g_dkg.t;
    memcpy(out + o, g_dkg.A, 64); o += 64;
    out[o++] = (uint8_t)g_dkg.name_len;
    memcpy(out + o, g_dkg.name, g_dkg.name_len); o += g_dkg.name_len;
    return o;
}

/* DKG_EXPORT_SHARE (0x6a)
 *   in:  account(4 BE)
 *   out: aad(var) || nonce(12) || ct(32) || tag(16)
 * The blob carries its own AAD in the clear so restore can reconstruct it and
 * a coordinator can route by (id, n, t, name) without decrypting. */
int handler_dkg_export_share(buffer_t *cdata)
{
    if (g_dkg.state != DKG_PROVISIONED) return io_send_sw(SW_BAD_STATE);
    if (cdata->size != 4) return io_send_sw(SW_WRONG_DATA_LENGTH);
    uint32_t account = rd32be(cdata->ptr);

    uint8_t aad[8 + 64 + 1 + VSS_MAX_NAME_LEN];
    size_t aad_len = dkg_backup_aad(aad);

    uint8_t key[32], nonce[12] = {0}, out[sizeof aad + 12 + 32 + 16];
    if (dkg_backup_key(account, key) != 0) return io_send_sw(SW_SIGNATURE_FAIL);
    /* A silent RNG failure here would leave `nonce` as stack residue — deterministic
     * across two consecutive exports of the same share, that's AES-GCM nonce reuse
     * and full plaintext recovery. Treat any non-CX_OK as fatal and wipe. */
    if (cx_get_random_bytes(nonce, sizeof nonce) != CX_OK) {
        explicit_bzero(key, sizeof key);
        explicit_bzero(nonce, sizeof nonce);
        return io_send_sw(SW_SIGNATURE_FAIL);
    }

    memcpy(out, aad, aad_len);
    memcpy(out + aad_len, nonce, 12);

    /* Encrypt skshare_div8 — the raw evaluation. Restore is then symmetric with
     * a ceremony: the *8 stays in dkg_get_signer, at the point of use. */
    int rc = zkn_aes256_gcm_encrypt_aad(key, nonce, 12, aad, aad_len,
                                        g_dkg.skshare_div8, 32,
                                        out + aad_len + 12, out + aad_len + 12 + 32);
    explicit_bzero(key, sizeof key);
    explicit_bzero(nonce, sizeof nonce);
    if (rc != 0) return io_send_sw(SW_SIGNATURE_FAIL);

    return io_send_response_pointer(out, aad_len + 12 + 32 + 16, SW_OK);
}

/* DKG_RESTORE_SHARE (0x6b)
 *   in:  account(4 BE) || aad(var) || nonce(12) || ct(32) || tag(16)
 *   out: A(64)
 * Short-circuits the state machine straight to PROVISIONED. The GCM tag is the
 * gate: a wrong seed, a tampered blob, or the wrong group all fail the tag and
 * nothing is written. On success skShare and A come from the blob's AAD, so the
 * restored device is indistinguishable from one that ran the ceremony. */
int handler_dkg_restore_share(buffer_t *cdata)
{
    /* Refuse to clobber a live ceremony or an existing provisioning. */
    if (g_dkg.state != DKG_IDLE) return io_send_sw(SW_BAD_STATE);

    const uint8_t *p = cdata->ptr;
    size_t size = cdata->size;
    if (size < 4 + 8 + 64 + 1 + 12 + 32 + 16) return io_send_sw(SW_WRONG_DATA_LENGTH);

    uint32_t account = rd32be(p); p += 4; size -= 4;

    /* Parse the AAD prefix. */
    const uint8_t *aad = p;
    uint32_t magic = ((uint32_t)aad[0] << 24) | ((uint32_t)aad[1] << 16)
                   | ((uint32_t)aad[2] << 8) | aad[3];
    if (magic != DKG_BACKUP_MAGIC || aad[4] != DKG_BACKUP_VERSION)
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    uint8_t r_id = aad[5], r_n = aad[6], r_t = aad[7];
    const uint8_t *r_A = aad + 8;
    uint8_t r_name_len = aad[8 + 64];
    if (r_name_len > VSS_MAX_NAME_LEN) return io_send_sw(SW_WRONG_DATA_LENGTH);
    if (r_id < 1 || r_id > r_n || r_t < 1 || r_t > r_n || r_n > DKG_MAX_N || r_t > DKG_MAX_T)
        return io_send_sw(SW_WRONG_DATA_LENGTH);

    size_t aad_len = 8 + 64 + 1 + r_name_len;
    if (size != aad_len + 12 + 32 + 16) return io_send_sw(SW_WRONG_DATA_LENGTH);

    const uint8_t *nonce = aad + aad_len;
    const uint8_t *ct    = nonce + 12;
    const uint8_t *tag   = ct + 32;

    uint8_t key[32], share[32];
    if (dkg_backup_key(account, key) != 0) return io_send_sw(SW_SIGNATURE_FAIL);
    int rc = zkn_aes256_gcm_decrypt_aad(key, nonce, 12, aad, aad_len, ct, 32, tag, share);
    explicit_bzero(key, sizeof key);
    if (rc != 0) { explicit_bzero(share, sizeof share); return io_send_sw(SW_SIGNATURE_FAIL); }

    /* Tag verified: the blob is ours and intact. Commit to PROVISIONED. Real
     * firmware writes NVRAM here (nvm_write + PIC); the sim keeps the globals. */
    g_dkg.account = account;
    g_dkg.id = r_id; g_dkg.n = r_n; g_dkg.t = r_t;
    g_dkg.name_len = r_name_len;
    memcpy(g_dkg.name, aad + 8 + 64 + 1, r_name_len);
    memcpy(g_dkg.skshare_div8, share, 32);
    memcpy(g_dkg.A, r_A, 64);
    explicit_bzero(share, sizeof share);
    g_dkg.state = DKG_PROVISIONED;

    return io_send_response_pointer(g_dkg.A, 64, SW_OK);
}

#endif // ZKN_FROST
