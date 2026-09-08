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

void validate_eddsa_poseidon_sign(bool choice)
{
    if (choice)
    {
        G_context.state = STATE_APPROVED;

        if (handler_eddsa_poseidon_sign_stored() != 0)
        {
            io_send_sw(SW_SIGNATURE_FAIL);
        }
        else
        {
            helper_send_response_sig();
        }
    }
    else
    {
        io_send_sw(SW_DENY);
    }

    /* Wipe unconditionally so the payload, message and signature do not
     * linger, and STATE_APPROVED never survives the callback. */
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.state = STATE_NONE;
}

/*
 * The pubkey is re-wiped from G_context after sending: even though a
 * pubkey is not a secret, the export confirmation is one-shot, and no
 * subsequent INS should be able to re-read the slot.
 */
void validate_pubkey_export(bool choice)
{
    if (choice)
    {
        size_t len = G_context.pk_info.raw_public_key_len;
        if (len == 0 || len > sizeof(G_context.pk_info.raw_public_key))
        {
            io_send_sw(SW_BAD_STATE);
        }
        else
        {
            io_send_response_pointer(G_context.pk_info.raw_public_key, len, SW_OK);
        }
    }
    else
    {
        io_send_sw(SW_DENY);
    }
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.state = STATE_NONE;
}
