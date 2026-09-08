// handler_dkg.h
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// Two-round VSS/DKG (Pedersen, everyone is a dealer — no trusted dealer).
// Mirrors js/curves-lite/src/frost/vss-dkg.ts and the DKGManager flow.
//
//   Round 1   DKG_DEAL        -> C_i       [barrier: aggregator collects all]
//             DKG_SET_COMMITS -> digest
//   Round 2   DKG_GET_SHARE   -> enc(s_ij) [barrier: aggregator routes]
//             DKG_PUT_SHARE
//   Output    DKG_FINALIZE    -> A (user confirms on screen)
//
// The barrier between the rounds is NOT arbitrary: the share AAD is
// id || commitmentsDigest, so nothing can be encrypted before every dealer
// has published its commitments. GET_SHARE before COMMITTED is refused.
//
// State machine: IDLE -> DEALT -> COMMITTED -> COLLECTED -> PROVISIONED,
// DKG_ABORT returns to IDLE from any transient state (wiping the coefficients).

#ifndef _HANDLER_DKG_H
#define _HANDLER_DKG_H

#include <stdint.h>
#include "buffer.h"

// DKG_GET_COMM_PUBKEY (0x60) — publish this device's Ed25519 comm pubkey.
//   in:  account(4 BE)          out: HK_i(32, RFC 8032 compressed)
int handler_dkg_get_comm_pubkey(buffer_t *cdata);

// DKG_DEAL (0x61) — round 1 emission. Draws a fresh epoch, derives the
// coefficients from (seed, ctx) — never from the host — and publishes C_i.
//   in:  account(4 BE) id(1) t(1) n(1) name_len(1) name(<=32)
//   out: epoch(16) || C_i(t*64, x||y BE)
int handler_dkg_deal(buffer_t *cdata);

// DKG_SET_COMMITS (0x62) — round 1 reception, chunked. Dealers MUST arrive
// sorted by sortKey(C_{j,0}) (vss-dkg.ts encodeCommitmentsBytes); the device
// checks monotonicity so the host cannot reorder and change the digest.
// Streams the digest instead of storing n*t points: keeps H_j and C_{j,0} only.
//   P1: 0x00 FIRST, 0x01 NEXT, 0x02 LAST
//   in:  per dealer: id_j(1) HK_j(32) C_j(t*64)
//   out: (LAST only) commitmentsDigest(32)
int handler_dkg_set_commits(uint8_t p1, buffer_t *cdata);

// DKG_GET_SHARE (0x63) — round 2 emission. Refused before COMMITTED.
//   in:  j(1)
//   out: nonce(12) || ct(32) || tag(16)
int handler_dkg_get_share(buffer_t *cdata);

// DKG_PUT_SHARE (0x64) — round 2 reception. C_j is re-sent by the host and
// re-anchored against the H_j frozen at SET_COMMITS, so the host carries the
// storage without being able to substitute anything.
//   in:  j(1) C_j(t*64) nonce(12) ct(32) tag(16)
//   out: —
int handler_dkg_put_share(buffer_t *cdata);

// DKG_FINALIZE (0x65) — skShare = sum, A = sum C_{j,0}. Refuses unless every
// dealer's share arrived: a missing one yields a silently wrong skShare.
//   in:  —                      out: A(64, x||y BE)
int handler_dkg_finalize(buffer_t *cdata);

// DKG_ABORT (0x66) — wipe all transient state.
int handler_dkg_abort(void);

// DKG_STATUS (0x67) — debug: state(1) id(1) t(1) n(1) recv_bitmap(2 BE)
int handler_dkg_status(void);

/* The bridge from DKG to FROST: the signer reads its share here rather than
 * being handed one over the wire. Returns non-zero unless the device is
 * PROVISIONED, so signing is impossible before a ceremony completes.
 * Real firmware reads NVRAM; here it is a RAM global, which is the sim's main
 * divergence — a power cycle loses the share. */
int dkg_get_signer(uint8_t *skshare_out, uint8_t *A_out,
                   size_t *id_out, size_t *t_out, size_t *n_out);

// DKG_DEBUG_COMM_PRIVKEY (0x68) — TEST ONLY. Hands the Ed25519 comm private
// key to the host. It exists so the JS reference can derive the ECDH key
// itself and decrypt a share: checking device-against-device would pass even
// if both sides shared the same mistake (wrong AAD, wrong endianness).
// This is the same key INS 0x46 already exposes, so it is not a new
// exfiltration path — but it must not exist in production either way.
//   in:  account(4 BE)          out: privkey(32)
int handler_dkg_debug_comm_privkey(buffer_t *cdata);

// DKG_DEBUG_SKSHARE (0x69) — TEST ONLY. Exports the signing share. skShare is
// otherwise only verified transitively (Feldman inside PUT_SHARE, and A), so
// this gives the JS reference a direct oracle: skShare*Base8 == 8*Y_i.
//   in: -    out: skshare(32 BE, already *8) || skshare_div8(32 BE)
int handler_dkg_debug_skshare(void);

// DKG_EXPORT_SHARE (0x6a) — encrypt skShare under a seed-derived key so a
// reinitialised device can restore it without replaying the ceremony.
//   in:  account(4 BE)   out: aad || nonce(12) || ct(32) || tag(16)
int handler_dkg_export_share(buffer_t *cdata);

// DKG_RESTORE_SHARE (0x6b) — decrypt an exported blob straight to PROVISIONED.
//   in:  account(4 BE) || blob   out: A(64)
int handler_dkg_restore_share(buffer_t *cdata);

#endif // _HANDLER_DKG_H
