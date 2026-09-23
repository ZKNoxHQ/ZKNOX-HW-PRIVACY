// handler_keys.c
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// APDU handler for public key derivation.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "io.h"
#include "buffer.h"

#include "handler_keys.h"
#include "globals.h"
#include "types.h"
#include "sw.h"
#include "display.h"

#include "zkn_errors.h"
#include "zkn_keyderivation.h"

// Read uint32 big-endian from buffer
static inline uint32_t read_u32_be(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8)  |  (uint32_t)buf[3];
}

/**
 * SIGNING_PUBKEY (INS 0x01)
 *
 * APDU data (4 B): account(4 BE)
 *   P1 = 0x00  silent — returns the key directly (DEBUG builds only)
 *   P1 = 0x01  display-and-confirm; returns the key on Approve
 *
 * Response: twisted-Edwards public key, x(32) || y(32) big-endian.
 *
 * A public key is not a secret, but it is identifying material: it is the
 * long-term handle by which a protocol built on this app addresses the
 * user. Production therefore always asks; the silent path is debug-only,
 * where the tests need to fetch a key without driving a screen.
 */
int handler_signing_pubkey(buffer_t *cdata, uint8_t p1)
{
    if (p1 != 0x00 && p1 != 0x01)
        return io_send_sw(SW_WRONG_P1P2);
#ifndef ZKNOX_DEBUG
    if (p1 == 0x00)
        return io_send_sw(SW_WRONG_P1P2);
#endif

    if (cdata->size != 4)
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    uint32_t account = read_u32_be(cdata->ptr);

    uint8_t derived_priv[64];
    uint8_t chain_code[32];
    uint8_t pubkey[PUBKEY_BABYJUBJUB_LEN];
    size_t pubkey_len = 0;

    zkn_error_t error = derive_private_key(KEY_TYPE_SPENDING, account,
                                           derived_priv, chain_code);
    if (error != ZKN_OK)
    {
        explicit_bzero(derived_priv, sizeof(derived_priv));
        explicit_bzero(chain_code, sizeof(chain_code));
        return io_send_sw(error);
    }

    error = derive_public_key(KEY_TYPE_SPENDING, PUBKEY_FORMAT_RAW,
                              derived_priv, pubkey, &pubkey_len);

    // Clear private key immediately
    explicit_bzero(derived_priv, sizeof(derived_priv));
    explicit_bzero(chain_code, sizeof(chain_code));

    if (error != ZKN_OK)
        return io_send_sw(error);

    if (pubkey_len == 0 || pubkey_len > sizeof(G_context.pk_info.raw_public_key))
        return io_send_sw(SW_WRONG_RESPONSE_LENGTH);

    if (p1 == 0x01)
    {
        // Display-and-confirm. Stash pubkey + account in G_context;
        // validate_pubkey_export sends the pubkey on Approve.
        explicit_bzero(&G_context, sizeof(G_context));
        G_context.req_type = CONFIRM_PUBKEY_EXPORT;
        memcpy(G_context.pk_info.raw_public_key, pubkey, pubkey_len);
        G_context.pk_info.raw_public_key_len = pubkey_len;
        G_context.bip32_path[0]              = account;
        G_context.bip32_path_len             = 1;
        G_context.state = STATE_PARSED;
        return ui_display_pubkey_export();
    }

    // p1 == 0x00, debug-only silent path.
    return io_send_response_pointer(pubkey, pubkey_len, SW_OK);
}

/**
 * VIEWING_PUBKEY (INS 0x10)
 *
 * APDU data (4 B): account(4 BE)
 *   P1 = 0x00  silent (DEBUG builds only)
 *   P1 = 0x01  display-and-confirm; returns the key on Approve
 *
 * Response: Ed25519 viewing public key, 32 bytes (RFC 8032 compressed).
 *
 * Like the signing pubkey, this is identifying material (it is part of the
 * user's 0zk address), so production always confirms.
 */
int handler_viewing_pubkey(buffer_t *cdata, uint8_t p1)
{
    if (p1 != 0x00 && p1 != 0x01)
        return io_send_sw(SW_WRONG_P1P2);
#ifndef ZKNOX_DEBUG
    if (p1 == 0x00)
        return io_send_sw(SW_WRONG_P1P2);
#endif

    if (cdata->size != 4)
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    uint32_t account = read_u32_be(cdata->ptr);

    uint8_t derived_priv[64];
    uint8_t chain_code[32];
    uint8_t pubkey[PUBKEY_ED25519_LEN];
    size_t pubkey_len = 0;

    zkn_error_t error = derive_private_key(KEY_TYPE_VIEWING, account,
                                           derived_priv, chain_code);
    if (error != ZKN_OK)
    {
        explicit_bzero(derived_priv, sizeof(derived_priv));
        explicit_bzero(chain_code, sizeof(chain_code));
        return io_send_sw(error);
    }

    error = derive_public_key(KEY_TYPE_VIEWING, PUBKEY_FORMAT_RAW,
                              derived_priv, pubkey, &pubkey_len);

    explicit_bzero(derived_priv, sizeof(derived_priv));
    explicit_bzero(chain_code, sizeof(chain_code));

    if (error != ZKN_OK)
        return io_send_sw(error);

    if (pubkey_len == 0 || pubkey_len > sizeof(G_context.pk_info.raw_public_key))
        return io_send_sw(SW_WRONG_RESPONSE_LENGTH);

    if (p1 == 0x01)
    {
        // Display-and-confirm. Shares the pubkey-export flow with the
        // signing key; is_viewing only selects the on-screen title.
        explicit_bzero(&G_context, sizeof(G_context));
        G_context.req_type = CONFIRM_PUBKEY_EXPORT;
        memcpy(G_context.pk_info.raw_public_key, pubkey, pubkey_len);
        G_context.pk_info.raw_public_key_len = pubkey_len;
        G_context.pk_info.is_viewing         = 1;
        G_context.bip32_path[0]              = account;
        G_context.bip32_path_len             = 1;
        G_context.state = STATE_PARSED;
        return ui_display_pubkey_export();
    }

    // p1 == 0x00, debug-only silent path.
    return io_send_response_pointer(pubkey, pubkey_len, SW_OK);
}

/**
 * VIEWING_PRIVKEY (INS 0x13)
 *
 * APDU data (4 B): account(4 BE).  P1 = 0x00, P2 = 0x00.
 *
 * Exports the raw 32-byte Ed25519 viewing private key — the SLIP-0010
 * derived seed used by scanning software, NOT a clamped scalar. Mandatory
 * user approval: the secret is derived only after Approve, in
 * validate_viewing_privkey, and is never staged in G_context.
 */
int handler_viewing_privkey(buffer_t *cdata)
{
    if (cdata->size != 4)
        return io_send_sw(SW_WRONG_DATA_LENGTH);

    explicit_bzero(&G_context, sizeof(G_context));
    G_context.bip32_path[0]  = read_u32_be(cdata->ptr);
    G_context.bip32_path_len = 1;
    G_context.req_type       = CONFIRM_VIEWING_PRIVKEY;
    G_context.state          = STATE_PARSED;

    return ui_display_viewing_privkey();
}
