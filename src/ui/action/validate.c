/*****************************************************************************
 *   ZKNOX-HW-PRIVACY — approve/reject actions.
 *
 *   Derived from the Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS. (c) 2025 ZKNOX SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdbool.h> // bool
#include <string.h>  // explicit_bzero

#include "io.h"

#include "validate.h"
#include "menu.h"
#include "sw.h"
#include "globals.h"
#include "send_response.h"
#include "handler_sign.h"

#include "zkn_errors.h"
#include "zkn_keyderivation.h"
#include "zkn_bech32m.h"

/*
 * A review callback acts only on the request it was opened for. Every handler
 * that stages a request also replaces the screen, so a mismatch should not
 * occur; but if G_context were ever overwritten while an older review stayed
 * up, Approve on that screen must not act on the newer request.
 */
static bool context_is_pending(request_type_e req_type)
{
    return G_context.req_type == req_type && G_context.state == STATE_PARSED;
}

static void context_wipe(void)
{
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.state = STATE_NONE;
}

bool validate_eddsa_poseidon_sign(bool choice)
{
    bool done = false;

    if (!context_is_pending(CONFIRM_SIGN))
    {
        io_send_sw(SW_BAD_STATE);
    }
    else if (choice)
    {
        G_context.state = STATE_APPROVED;

        if (handler_eddsa_poseidon_sign_stored() != 0)
        {
            io_send_sw(SW_SIGNATURE_FAIL);
        }
        else
        {
            done = (helper_send_response_sig() >= 0);
        }
    }
    else
    {
        io_send_sw(SW_DENY);
    }

    /* Wipe unconditionally so the payload, message and signature do not
     * linger, and STATE_APPROVED never survives the callback. */
    context_wipe();
    return done;
}

/*
 * The pubkey is re-wiped from G_context after sending: even though a
 * pubkey is not a secret, the export confirmation is one-shot, and no
 * subsequent INS should be able to re-read the slot.
 */
bool validate_pubkey_export(bool choice)
{
    bool done = false;

    if (!context_is_pending(CONFIRM_PUBKEY_EXPORT))
    {
        io_send_sw(SW_BAD_STATE);
    }
    else if (choice)
    {
        size_t len = G_context.pk_info.raw_public_key_len;
        if (len == 0 || len > sizeof(G_context.pk_info.raw_public_key))
        {
            io_send_sw(SW_BAD_STATE);
        }
        else
        {
            done = (io_send_response_pointer(G_context.pk_info.raw_public_key, len, SW_OK) >= 0);
        }
    }
    else
    {
        io_send_sw(SW_DENY);
    }
    context_wipe();
    return done;
}

/*
 * Viewing private key export. The secret is never staged in G_context: it is
 * derived here, sent, and wiped, so a rejected or failed export leaves no
 * residue. The 32 bytes are the raw SLIP-0010 viewing seed (not a clamped
 * scalar) — the value scanning software needs.
 */
bool validate_viewing_privkey(bool choice)
{
    bool done = false;

    if (!context_is_pending(CONFIRM_VIEWING_PRIVKEY))
    {
        io_send_sw(SW_BAD_STATE);
    }
    else if (choice)
    {
        /* Derive only after approval; the secret is never staged. Matches the
         * RAILGUN app's viewing-key export flow. */
        uint8_t derived_priv[64];
        uint8_t chain_code[32];
        zkn_error_t error = derive_private_key(KEY_TYPE_VIEWING,
                                               G_context.bip32_path[0],
                                               derived_priv, chain_code);
        if (error != ZKN_OK)
        {
            io_send_sw(SW_SIGNATURE_FAIL);
        }
        else
        {
            done = (io_send_response_pointer(derived_priv, 32, SW_OK) >= 0);
        }
        explicit_bzero(derived_priv, sizeof(derived_priv));
        explicit_bzero(chain_code, sizeof(chain_code));
    }
    else
    {
        io_send_sw(SW_DENY);
    }
    context_wipe();
    return done;
}

/*
 * 0zk1… address confirmation. Sends the 127-byte ASCII string staged by
 * handler_railgun_address on Approve. Not secret, but one-shot: wiped after.
 */
bool validate_railgun_0zk_address(bool choice)
{
    bool done = false;

    if (!context_is_pending(CONFIRM_RAILGUN_ADDRESS))
    {
        io_send_sw(SW_BAD_STATE);
    }
    else if (choice)
    {
        done = (io_send_response_pointer((const uint8_t *)G_context.pk_info.zk_address,
                                         ZKN_0ZK_STRING_LEN, SW_OK) >= 0);
    }
    else
    {
        io_send_sw(SW_DENY);
    }
    context_wipe();
    return done;
}
