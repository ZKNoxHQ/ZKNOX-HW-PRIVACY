// handler_keys.h
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// Key derivation APDU handlers.
//
// The handler takes a 4-byte big-endian account index and derives on a fully
// hardened, firmware-fixed path (see zkn_keyderivation.h in the libC). The
// host chooses the account, never the path.
//
// This app derives exactly two secrets, and neither is exportable:
//   - the twisted-Edwards signing key, used by BLIND_SIGN and as the DKG
//     coefficient seed;
//   - the Ed25519 DKG transport identity, used only inside handler_dkg.c.
// There is no key-export instruction in a production build.

#ifndef _HANDLER_KEYS_H
#define _HANDLER_KEYS_H

#include <stdint.h>
#include "buffer.h"

// SIGNING_PUBKEY (0x01) — twisted-Edwards signing pubkey, x||y (64 B).
//   in:  account(4 BE)
//   P1 = 0x00 silent (DEBUG builds only) / 0x01 display-and-confirm
int handler_signing_pubkey(buffer_t *cdata, uint8_t p1);

// VIEWING_PUBKEY (0x10) — Ed25519 viewing pubkey (32 B, RFC 8032 compressed).
//   in:  account(4 BE)
//   P1 = 0x00 silent (DEBUG builds only) / 0x01 display-and-confirm
int handler_viewing_pubkey(buffer_t *cdata, uint8_t p1);

// VIEWING_PRIVKEY (0x13) — export the raw Ed25519 viewing private key (32 B),
// gated by mandatory user approval. P1 = 0x00, P2 = 0x00.
//   in:  account(4 BE)
int handler_viewing_privkey(buffer_t *cdata);

#endif // _HANDLER_KEYS_H
