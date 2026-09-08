// handler_sign.c
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// EdDSA-Poseidon sign APDU handlers.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "io.h"
#include "buffer.h"

#include "../sw.h"
#include "../globals.h"
#include "../ui/display.h"

#include "zkn_errors.h"
#include "zkn_tEdwards.h"
#include "zkn_eddsa.h"
#include "zkn_keyderivation.h"

#include "handler_sign.h"

// Read uint32 big-endian from buffer
static inline uint32_t read_u32_be(const uint8_t *buf)
{
  return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
         ((uint32_t)buf[2] << 8)  |  (uint32_t)buf[3];
}

// Decode P1 as curveID. P1=0 preserves legacy behavior (BabyJubjub), while
// P1=CURVE_BANDERSNATCH (0x01) / P1=CURVE_BABYJUBJUB (0x02) select explicitly.
// Returns -1 on unknown P1 so callers can emit SW_WRONG_P1P2.
static int decode_sign_curve(uint8_t p1, uint32_t *out)
{
  if (p1 == 0 || p1 == _BABYJUJUB_ID) { *out = _BABYJUJUB_ID;    return 0; }
  if (p1 == _BANDERSNATCH_ID)         { *out = _BANDERSNATCH_ID; return 0; }
  return -1;
}

// ─────────────────────────────────────────────────────────────────────────
// handler_eddsa_poseidon_sign_stored
//
// Helper called from validate_eddsa_poseidon_sign() after user approval.
// Derives the privkey from the account stored in sign_info.payload[0..3],
// signs the message at payload+4, and stores the 96-byte result in
// G_context.sign_info.signature.
// ─────────────────────────────────────────────────────────────────────────
int handler_eddsa_poseidon_sign_stored(void)
{
  ZKN_ERROR_INIT();

  uint32_t account = read_u32_be(G_context.sign_info.payload);
  uint8_t derived_priv[64];
  uint8_t chain_code[32];
  bool bn_locked = false;

  error = derive_private_key(KEY_TYPE_SPENDING, account, derived_priv, chain_code);
  if (error != ZKN_OK)
    goto end;

  ZKN_CHECK(zkn_bn_lock(32, 0));
  bn_locked = true;

  zkn_edcurve_t curve;
  zkn_edpoint_t Kpub;
  // sign_info.curveID is populated by handler_blind_sign. 0 is treated as
  // legacy BabyJubjub.
  uint8_t stored_cid = G_context.sign_info.curveID;
  uint32_t curveID = (stored_cid == _BANDERSNATCH_ID) ? _BANDERSNATCH_ID : _BABYJUJUB_ID;

  ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, curveID));
  ZKN_CHECK(tEdwards_alloc(&curve, &Kpub));
  ZKN_CHECK(zkn_prv2pub(&curve, derived_priv, &Kpub));
  ZKN_CHECK(EddsaPoseidon_Sign_final(&curve, derived_priv, &Kpub,
                                     G_context.sign_info.payload + 4, 32,
                                     G_context.sign_info.signature));
  G_context.sign_info.signature_len = EDDSA_POSEIDON_SIG_LEN;

end:
  if (bn_locked)
    zkn_bn_unlock();
  explicit_bzero(derived_priv, sizeof(derived_priv));
  explicit_bzero(chain_code, sizeof(chain_code));
  return error;
}

// ─────────────────────────────────────────────────────────────────────────
// BLIND_SIGN (INS=0x12) — stage the payload in G_context, show the approval
// UI, derive the key and sign once the user confirms.
//
// P1: curveID (0x00 = legacy BabyJubjub, 0x01 = Bandersnatch, 0x02 = BabyJubjub).
// Data: account(4 BE) || msg(32) = 36 bytes
// Returns len(1) | sig(96) | msg(32) after the user confirms.
// ─────────────────────────────────────────────────────────────────────────
int handler_blind_sign(uint8_t p1, buffer_t *cdata)
{
  if (cdata->size != SIGN_PAYLOAD_LEN)
    return io_send_sw(SW_WRONG_DATA_LENGTH);

  uint32_t curveID;
  if (decode_sign_curve(p1, &curveID) != 0)
    return io_send_sw(SW_WRONG_P1P2);

  explicit_bzero(&G_context, sizeof(G_context));
  G_context.req_type = CONFIRM_SIGN;
  G_context.state = STATE_NONE;

  // Store account + msg for deferred signing after user approval; the
  // curve goes into sign_info.curveID (read back by the stored handler).
  memmove(G_context.sign_info.payload, cdata->ptr, SIGN_PAYLOAD_LEN);
  G_context.sign_info.curveID = (uint8_t)curveID;

  // Copy the message (bytes 4-35) into m_hash for display and response
  memmove(G_context.sign_info.m_hash, cdata->ptr + 4, 32);

  G_context.state = STATE_PARSED;

  return ui_display_blind_sign_eddsa_poseidon();
}

#ifdef ZKNOX_DEBUG
// ─────────────────────────────────────────────────────────────────────────
// BLIND_SIGN_NO_DISPLAY (INS=0x02) — sign from the BIP32 path, no UI.
//
// P1: curveID (same encoding as BLIND_SIGN).
// Data: account(4 BE) || msg(32) = 36 bytes
// Returns R8x|R8y|S (96 bytes).
// ─────────────────────────────────────────────────────────────────────────
int handler_blind_sign_no_display(uint8_t p1, buffer_t *cdata)
{
  ZKN_ERROR_INIT();

  if (cdata->size != SIGN_PAYLOAD_LEN)
    return io_send_sw(SW_WRONG_DATA_LENGTH);

  uint32_t curveID;
  if (decode_sign_curve(p1, &curveID) != 0)
    return io_send_sw(SW_WRONG_P1P2);

  uint8_t derived_priv[64];
  uint8_t chain_code[32];
  uint8_t msg[32];
  uint8_t out[EDDSA_POSEIDON_SIG_LEN];
  bool bn_locked = false;

  uint32_t account = read_u32_be(cdata->ptr);
  memcpy(msg, cdata->ptr + 4, 32);

  error = derive_private_key(KEY_TYPE_SPENDING, account, derived_priv, chain_code);
  if (error != ZKN_OK)
    goto end;

  ZKN_CHECK(zkn_bn_lock(32, 0));
  bn_locked = true;

  zkn_edcurve_t curve;
  zkn_edpoint_t Kpub;

  ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, curveID));
  ZKN_CHECK(tEdwards_alloc(&curve, &Kpub));
  ZKN_CHECK(zkn_prv2pub(&curve, derived_priv, &Kpub));
  ZKN_CHECK(EddsaPoseidon_Sign_final(&curve, derived_priv, &Kpub, msg, 32, out));

  zkn_bn_unlock();
  bn_locked = false;

  explicit_bzero(derived_priv, sizeof(derived_priv));
  explicit_bzero(chain_code, sizeof(chain_code));

  return io_send_response_pointer(out, sizeof(out), SW_OK);

end:
  if (bn_locked)
    zkn_bn_unlock();
  explicit_bzero(derived_priv, sizeof(derived_priv));
  explicit_bzero(chain_code, sizeof(chain_code));
  return io_send_sw(error);
}

// ─────────────────────────────────────────────────────────────────────────
// SIGN_WITH_PRIVKEY (INS=0x50) — direct sign with a host-supplied scalar.
//
// Data: curveID(1) || prv(32) || msg(32) = 65 bytes
// Returns R8x|R8y|S (96 bytes).
//
// /!\ DEBUG-ONLY handler — accepts a raw privkey from the host. It signs
//     with a key the device never derived, so it proves nothing about the
//     device's own key material; it exists purely to check the arithmetic
//     against reference vectors.
// ─────────────────────────────────────────────────────────────────────────
int handler_sign_with_privkey(buffer_t *cdata)
{
  ZKN_ERROR_INIT();

  if (cdata->size != 65)
    return io_send_sw(SW_WRONG_DATA_LENGTH);

  uint32_t curveID;
  if (decode_sign_curve(cdata->ptr[0], &curveID) != 0)
    return io_send_sw(SW_INCORRECT_DATA);

  uint8_t prv[32];
  uint8_t msg[32];
  uint8_t out[EDDSA_POSEIDON_SIG_LEN];
  bool bn_locked = false;

  memcpy(prv, cdata->ptr + 1,  32);
  memcpy(msg, cdata->ptr + 33, 32);

  ZKN_CHECK(zkn_bn_lock(32, 0));
  bn_locked = true;

  zkn_edcurve_t curve;
  zkn_edpoint_t Kpub;

  ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, curveID));
  ZKN_CHECK(tEdwards_alloc(&curve, &Kpub));
  ZKN_CHECK(zkn_prv2pub(&curve, prv, &Kpub));
  ZKN_CHECK(EddsaPoseidon_Sign_final(&curve, prv, &Kpub, msg, 32, out));

  zkn_bn_unlock();
  bn_locked = false;

  explicit_bzero(prv, sizeof(prv));

  return io_send_response_pointer(out, sizeof(out), SW_OK);

end:
  if (bn_locked)
    zkn_bn_unlock();
  explicit_bzero(prv, sizeof(prv));
  return io_send_sw(error);
}
#endif // ZKNOX_DEBUG
