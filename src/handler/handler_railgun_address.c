// handler_railgun_address.c
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// RAILGUN_ADDRESS (INS 0x14) — derive the canonical "share my address"
// 0zk1… string for a given account and ask the user to confirm before
// returning it to the host. The on-device bech32m encoding lets the user
// verify the stealth address on the trusted screen, so a malicious host
// can't substitute a different address into what gets shared.
//
// Ported from the RAILGUN Ledger app: same INS, same wire format, same
// master-key derivation (MPK = Poseidon3(spendX, spendY, Poseidon1(vk))).

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "io.h"
#include "buffer.h"

#include "handler_railgun_address.h"
#include "globals.h"
#include "types.h"
#include "sw.h"
#include "display.h"

#include "zkn_errors.h"
#include "zkn_keyderivation.h"
#include "zkn_poseidon.h"
#include "zkn_bech32m.h"

static inline uint32_t read_u32_be(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] <<  8) |  (uint32_t)buf[3];
}

int handler_railgun_address(buffer_t *cdata, uint8_t p1, uint8_t p2)
{
    // P1 = 0x01 (display + confirm) or 0x00 (silent, debug only). P2 RFU.
    if ((p1 != 0x00 && p1 != 0x01) || p2 != 0x00)
        return io_send_sw(SW_WRONG_P1P2);
#ifndef ZKNOX_DEBUG
    if (p1 == 0x00)
        return io_send_sw(SW_WRONG_P1P2);
#endif
    if (cdata->size != 4)
        return io_send_sw(SW_WRONG_DATA_LENGTH);

    const uint32_t account = read_u32_be(cdata->ptr);

    // Buffers that hold secret material. Wiped on every exit path via
    // the `out:` cleanup label below.
    uint8_t viewing_priv[64] = {0};
    uint8_t chain_code[32]   = {0};
    uint8_t nk[32]           = {0};
    int rc = -1;
    zkn_error_t err;

    // Non-secret buffers — fine to leave on stack.
    uint8_t viewing_pub[32];
    uint8_t spend_pub[64];
    size_t  viewing_pub_len = 0;
    size_t  spend_pub_len   = 0;
    uint8_t payload[ZKN_0ZK_DECODED_LEN];
    uint8_t zk_addr[ZKN_0ZK_STRING_LEN];

    // 1) Viewing privkey → viewing pubkey (Ed25519 RFC 8032, 32 B).
    err = derive_private_key(KEY_TYPE_VIEWING, account, viewing_priv, chain_code);
    if (err != ZKN_OK) {
        rc = io_send_sw(err);
        goto out;
    }
    err = derive_public_key(KEY_TYPE_VIEWING, PUBKEY_FORMAT_RAW,
                            viewing_priv, viewing_pub, &viewing_pub_len);
    if (err != ZKN_OK) {
        rc = io_send_sw(err);
        goto out;
    }
    if (viewing_pub_len != ZKN_0ZK_VK_LEN) {
        rc = io_send_sw(SW_BAD_STATE);
        goto out;
    }

    // 2) nk = Poseidon1(viewingPriv) — engine's nullifier key derivation.
    //    The 32-byte SLIP-10 chain key (first half of derived_priv) is the
    //    engine's `viewingPrivateKey` and the input to Poseidon1.
    if (zkn_poseidon_hash(viewing_priv, 1, nk) != 0) {
        rc = io_send_sw(SW_SIGNATURE_FAIL);
        goto out;
    }

    // 3) Spending pubkey (BabyJubjub x||y, 64 B). Separate SLIP-10 walk
    //    because spending lives on a different path than viewing.
    {
        uint8_t spend_priv[64]  = {0};
        uint8_t spend_chain[32] = {0};
        err = derive_private_key(KEY_TYPE_SPENDING, account,
                                 spend_priv, spend_chain);
        if (err != ZKN_OK) {
            explicit_bzero(spend_priv,  sizeof(spend_priv));
            explicit_bzero(spend_chain, sizeof(spend_chain));
            rc = io_send_sw(err);
            goto out;
        }
        err = derive_public_key(KEY_TYPE_SPENDING, PUBKEY_FORMAT_RAW,
                                spend_priv, spend_pub, &spend_pub_len);
        explicit_bzero(spend_priv,  sizeof(spend_priv));
        explicit_bzero(spend_chain, sizeof(spend_chain));
        if (err != ZKN_OK) {
            rc = io_send_sw(err);
            goto out;
        }
        if (spend_pub_len != PUBKEY_BABYJUBJUB_LEN) {
            rc = io_send_sw(SW_BAD_STATE);
            goto out;
        }
    }

    // 4) MPK = Poseidon3(spendX, spendY, nk).
    {
        uint8_t mpk_input[96];
        memcpy(mpk_input,      spend_pub,      32);  // X
        memcpy(mpk_input + 32, spend_pub + 32, 32);  // Y
        memcpy(mpk_input + 64, nk,             32);
        if (zkn_poseidon_hash(mpk_input, 3,
                              payload + ZKN_0ZK_MPK_OFFSET) != 0) {
            rc = io_send_sw(SW_SIGNATURE_FAIL);
            goto out;
        }
    }

    // 5) Assemble 73-byte payload: version || MPK || network || vk.
    payload[0] = ZKN_0ZK_VERSION;
    memcpy(payload + ZKN_0ZK_NET_OFFSET,
           ZKN_NETWORK_ALLCHAINS_ID, ZKN_NETWORK_ID_LEN);
    memcpy(payload + ZKN_0ZK_VK_OFFSET, viewing_pub, ZKN_0ZK_VK_LEN);

    // 6) Bech32m encode → 127-char "0zk1…".
    if (zkn_0zk_encode(payload, zk_addr) != 0) {
        rc = io_send_sw(SW_SIGNATURE_FAIL);
        goto out;
    }

    // 7) Hand off based on P1.
    if (p1 == 0x01)
    {
        // Display + confirm. Stash in G_context; on Approve
        // validate_railgun_0zk_address sends the 127-byte string back,
        // on Reject SW_DENY. G_context is wiped on both paths.
        explicit_bzero(&G_context, sizeof(G_context));
        G_context.req_type      = CONFIRM_RAILGUN_ADDRESS;
        G_context.bip32_path[0] = account;
        G_context.bip32_path_len = 1;
        memcpy(G_context.pk_info.zk_address, zk_addr, ZKN_0ZK_STRING_LEN);
        G_context.pk_info.zk_address[ZKN_0ZK_STRING_LEN] = '\0';
        G_context.state = STATE_PARSED;

        rc = ui_display_railgun_0zk_address();
    }
    else
    {
        // p1 == 0x00 — debug-only silent path. Send the 127-byte string
        // straight back; no G_context staging, no UI.
        rc = io_send_response_pointer(zk_addr, ZKN_0ZK_STRING_LEN, SW_OK);
    }

out:
    explicit_bzero(viewing_priv, sizeof(viewing_priv));
    explicit_bzero(chain_code,   sizeof(chain_code));
    explicit_bzero(nk,           sizeof(nk));
    return rc;
}
