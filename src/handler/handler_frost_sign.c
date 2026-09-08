// handler_frost_sign.c
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "os_random.h"
#include "buffer.h"
#include "io.h"

#include "../sw.h"
#include "../constants.h"
#include "../zkn_features.h"
#include "zkn_errors.h"
#include "zkn_tEdwards.h"
#include "zkn_frost.h"
#include "zkn_vss.h"
#include "handler_dkg.h"
#include "handler_frost_sign.h"

#if defined(ZKN_FROST)

#define FS_MAX_SIGNERS  3       /* mirrors DKG_MAX_T: a quorum is t signers */
#define FS_REC          160     /* id(32) || D.x||D.y || E.x||E.y, all BE */
#define FS_BUF          (32 + FS_MAX_SIGNERS * FS_REC)

enum { FS_IDLE = 0, FS_NONCED };

static struct {
    uint8_t state;
    uint8_t nonces[64];         /* d_i || e_i — secret, single-use */
    uint8_t buf[FS_BUF];        /* msg || commitment list, reassembled */
    size_t  len;
} g_fs;

void fs_wipe(void) { explicit_bzero(&g_fs, sizeof(g_fs)); g_fs.state = FS_IDLE; }

/* ── 0x70 COMMIT ───────────────────────────────────────────────── */
int handler_frost_hw_commit(buffer_t *cdata)
{
    if (cdata->size != 0) return io_send_sw(SW_WRONG_DATA_LENGTH);

    uint8_t sk[32];
    if (dkg_get_signer(sk, NULL, NULL, NULL, NULL) != 0)
        return io_send_sw(SW_BAD_STATE);   /* no DKG output to sign with */

    ZKN_ERROR_INIT();
    uint8_t out[128];
    ZKN_CHECK(zkn_bn_lock(32, 0));
    zkn_edcurve_t curve;
    ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID));

    zkn_edpoint_t comms[2];
    ZKN_CHECK(tEdwards_alloc(&curve, comms));
    ZKN_CHECK(tEdwards_alloc(&curve, comms + 1));

    /* zkn_frost_commit draws (d_i, e_i) internally from the device RNG and
     * returns the two commitment points. */
    ZKN_CHECK(zkn_frost_commit(&curve, sk, g_fs.nonces, comms));
    explicit_bzero(sk, sizeof(sk));

    ZKN_CHECK(tEdwards_export(&curve, comms,     out,      out + 32));
    ZKN_CHECK(tEdwards_export(&curve, comms + 1, out + 64, out + 96));
    (void)zkn_bn_unlock();

    g_fs.state = FS_NONCED;
    g_fs.len = 0;
    return io_send_response_pointer(out, sizeof(out), SW_OK);

end:
    explicit_bzero(sk, sizeof(sk));
    fs_wipe();                       /* half-drawn nonces must not survive */
    (void)zkn_bn_unlock();
    return io_send_sw(SW_SIGNATURE_FAIL);
}

/* ── 0x71 SIGN (chunked) ───────────────────────────────────────── */
int handler_frost_hw_sign(uint8_t p1, buffer_t *cdata)
{
    const uint8_t P1_FIRST = 0x00, P1_LAST = 0x02;
    if (p1 > P1_LAST) return io_send_sw(SW_WRONG_P1P2);
    if (g_fs.state != FS_NONCED) return io_send_sw(SW_BAD_STATE);

    if (p1 == P1_FIRST) g_fs.len = 0;
    if (g_fs.len + cdata->size > sizeof(g_fs.buf)) return io_send_sw(SW_WRONG_DATA_LENGTH);
    memcpy(g_fs.buf + g_fs.len, cdata->ptr, cdata->size);
    g_fs.len += cdata->size;

    if (p1 != P1_LAST) return io_send_sw(SW_OK);

    uint8_t sk[32], A[64];
    size_t my_id, t, n;
    if (dkg_get_signer(sk, A, &my_id, &t, &n) != 0) return io_send_sw(SW_BAD_STATE);

    if (g_fs.len < 32 + FS_REC) { explicit_bzero(sk, 32); return io_send_sw(SW_WRONG_DATA_LENGTH); }
    size_t nsig = (g_fs.len - 32) / FS_REC;
    if ((g_fs.len - 32) % FS_REC != 0 || nsig > FS_MAX_SIGNERS) {
        explicit_bzero(sk, 32); return io_send_sw(SW_WRONG_DATA_LENGTH);
    }
    /* A quorum is exactly t: fewer cannot reconstruct, more is not what the
     * lambdas were derived for. */
    if (nsig != t) { explicit_bzero(sk, 32); return io_send_sw(SW_WRONG_DATA_LENGTH); }

    const uint8_t *msg  = g_fs.buf;
    uint8_t *list = g_fs.buf + 32;

    /* Signer ids, read from the list the host sent. lambda is derived from
     * THESE — the host picks the quorum, not the interpolation. */
    size_t ids[FS_MAX_SIGNERS];
    int me = -1;
    for (size_t i = 0; i < nsig; i++) {
        const uint8_t *idb = list + i * FS_REC;
        for (size_t k = 0; k < 24; k++)
            if (idb[k] != 0) { explicit_bzero(sk, 32); return io_send_sw(SW_WRONG_DATA_LENGTH); }
        size_t v = 0;
        for (size_t k = 24; k < 32; k++) v = (v << 8) | idb[k];
        if (v == 0 || v > n) { explicit_bzero(sk, 32); return io_send_sw(SW_WRONG_DATA_LENGTH); }
        if (i > 0 && v <= ids[i - 1]) { explicit_bzero(sk, 32); return io_send_sw(SW_WRONG_DATA_LENGTH); }
        ids[i] = v;
        if (v == my_id) me = (int)i;
    }
    /* Signing for a quorum we are not in would produce a share nobody can use. */
    if (me < 0) { explicit_bzero(sk, 32); return io_send_sw(SW_WRONG_DATA_LENGTH); }

    ZKN_ERROR_INIT();
    uint8_t out[32], lambda[32];
    ZKN_CHECK(zkn_bn_lock(32, 0));
    zkn_edcurve_t curve;
    ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID));

    /* On-device lambda. The test handler took it as an argument with 3 hardcoded
     * signers; a host-chosen lambda invalidates the aggregate while each share
     * still verifies individually. */
    ZKN_CHECK(deriveInterpolatingValue(&curve, ids, nsig, my_id, lambda));

    ZKN_CHECK(zkn_partial_sig(&curve, my_id, sk, A,
                              g_fs.nonces, g_fs.nonces + 32,
                              list, nsig, (uint8_t *)msg, 32, lambda, out));
    (void)zkn_bn_unlock();
    explicit_bzero(sk, sizeof(sk));
    explicit_bzero(lambda, sizeof(lambda));

    /* Real firmware: display the message (clear-signed) and the quorum, and
     * wait for Approve before releasing z_i. Approving an opaque 32-byte hash
     * is not a confirmation — that gate belongs here, and the simulator has no
     * UI to put it behind. */

    /* Burn the nonces BEFORE returning: reuse across two messages reveals
     * skShare_i. A second SIGN now falls into SW_BAD_STATE. */
    explicit_bzero(g_fs.nonces, sizeof(g_fs.nonces));
    g_fs.state = FS_IDLE;
    g_fs.len = 0;

    return io_send_response_pointer(out, 32, SW_OK);

end:
    explicit_bzero(sk, sizeof(sk));
    fs_wipe();                       /* on any failure the nonces are burnt too */
    (void)zkn_bn_unlock();
    return io_send_sw(SW_SIGNATURE_FAIL);
}

/* ── 0x72 RESET ────────────────────────────────────────────────── */
int handler_frost_hw_reset(void) { fs_wipe(); return io_send_sw(SW_OK); }

#endif // ZKN_FROST
