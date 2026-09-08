// handler_sign.h
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// EdDSA-Poseidon sign APDU handlers.
//
// The signature is over a twisted-Edwards curve with Poseidon as the
// challenge hash — the shape a zk circuit can verify cheaply in-circuit,
// which is why it exists here rather than plain Ed25519.

#ifndef _HANDLER_SIGN_H
#define _HANDLER_SIGN_H

#include <stdint.h>
#include "buffer.h"
#include "../constants.h"

// BLIND_SIGN (0x12) — EdDSA-Poseidon blind-sign with UI approval.
// P1 selects the curve: 0x00 (legacy = BabyJubjub), 0x01 = Bandersnatch,
// 0x02 = BabyJubjub. Other values are rejected.
//   in:  account(4 BE) || msg(32)
//   out: (on Approve) sig_len(1) || R8x||R8y||S (96) || msg(32)
int handler_blind_sign(uint8_t p1, buffer_t *cdata);

// Helper: called by validate_eddsa_poseidon_sign after user approval.
// Derives the key from the staged account and signs the staged message.
int handler_eddsa_poseidon_sign_stored(void);

#ifdef ZKNOX_DEBUG
// BLIND_SIGN_NO_DISPLAY (0x02) — as BLIND_SIGN, no UI confirmation.
// Same P1 encoding. Test/integration handler.
int handler_blind_sign_no_display(uint8_t p1, buffer_t *cdata);

// SIGN_WITH_PRIVKEY (0x50) — sign with a host-supplied raw scalar, so a
// host suite can cross-check the device against a reference implementation
// on shared test vectors.
//   in:  curve_id(1) || prv(32) || msg(32)
int handler_sign_with_privkey(buffer_t *cdata);
#endif

#endif // _HANDLER_SIGN_H
