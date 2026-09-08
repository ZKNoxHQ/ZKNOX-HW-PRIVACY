// handler_frost_sign.h
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// FROST signing on top of the DKG (RFC 9591 §5), for a real signer rather than
// a test vector. The difference from the FROST_* test handlers (0x20-0x2E) is
// what the host is allowed to supply:
//
//   test handlers          here
//   ─────────────          ────
//   FROST_INJECT: host      skShare comes from the DKG state. Never an APDU.
//     supplies skShare
//   lambda passed in as     lambda is derived on-device from the signer ids in
//     an argument             the commitment list.
//   FROST_INJECT_NONCES     nonces are drawn on-device and single-use.
//
// The lambda one is not cosmetic: a wrong lambda invalidates the aggregate
// while every individual share still verifies — the exact bug that was fixed in
// curves-lite. Letting the host choose it hands that back.
//
//   PROVISIONED --FROST_COMMIT--> NONCED --FROST_SIGN--> PROVISIONED
//
// FROST_SIGN consumes the nonces. Signing twice with the same (d_i, e_i) leaks
// skShare_i outright: two equations, two unknowns. So SIGN wipes them before
// returning, and a second SIGN without a fresh COMMIT is refused. Nonces are
// deliberately NOT persisted: losing them costs a round, reusing them costs the
// key.

#ifndef _HANDLER_FROST_SIGN_H
#define _HANDLER_FROST_SIGN_H

#include <stdint.h>
#include "buffer.h"

// FROST_HW_COMMIT (0x70) — draw (d_i, e_i), publish (D_i, E_i).
//   in:  —
//   out: D_i(64) || E_i(64), x||y big-endian
int handler_frost_hw_commit(buffer_t *cdata);

// FROST_HW_SIGN (0x71) — chunked: 32 + t*160 bytes overflows one APDU
// (512 for t=3), same reason the test handlers had INJECT_COM1/COM2.
//   P1: 0x00 FIRST, 0x01 NEXT, 0x02 LAST
//   in (across chunks): msg(32) || [ id(32) D.x(32) D.y(32) E.x(32) E.y(32) ] * t
//   out: (LAST only) z_i(32)
int handler_frost_hw_sign(uint8_t p1, buffer_t *cdata);

// Drop the nonces. Called by DKG_ABORT too: (d_i, e_i) belong to the share
// being wiped, and the state machine above has no NONCED-without-share state.
void fs_wipe(void);

// FROST_HW_RESET (0x72) — drop the nonces.
int handler_frost_hw_reset(void);

#endif // _HANDLER_FROST_SIGN_H
