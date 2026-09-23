/*****************************************************************************
 *   ZKNOX
 *   (c) 2025 ZKNOX SAS.
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

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "io.h"
#include "ledger_assert.h"

#include "dispatcher.h"
#include "constants.h"
#include "globals.h"
#include "types.h"
#include "sw.h"
#include "zkn_features.h"

#include "handler_keys.h"
#include "handler_sign.h"
#include "handler_version.h"
#include "handler_railgun_address.h"

/* ZKN_FROST — threshold signing: the VSS/DKG ceremony and FROST signing on its
 * output. Split out of ZKNOX_DEBUG so the feature can ship without dragging in
 * the key-extraction INSes, which stay debug-only. See src/zkn_features.h. */
#if defined(ZKN_FROST)
#include "handler_dkg.h"
#include "handler_frost_sign.h"
#endif

// Helper: initialize buffer from command data
#define INIT_BUF_OR_FAIL()                           \
    do                                               \
    {                                                \
        if (!cmd->data)                              \
            return io_send_sw(SW_WRONG_DATA_LENGTH); \
        buf.ptr = cmd->data;                         \
        buf.size = cmd->lc;                          \
        buf.offset = 0;                              \
    } while (0)

int apdu_dispatcher(const command_t *cmd)
{
    LEDGER_ASSERT(cmd != NULL, "NULL cmd");

    if (cmd->cla != CLA)
    {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }

    buffer_t buf = {0};

    switch (cmd->ins)
    {
        // ─── Keys ────────────────────────────────────────────────────────

    case SIGNING_PUBKEY:
        /* P1 = display / silent gate; P2 is RFU. */
        if (cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_signing_pubkey(&buf, cmd->p1);

        // ─── Signing ─────────────────────────────────────────────────────

    case BLIND_SIGN:
        /* P1 = curve id; P2 is RFU. */
        if (cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_blind_sign(cmd->p1, &buf);

        // ─── Viewing key / 0zk address ─────────────────────────────────────

    case VIEWING_PUBKEY:
        /* P1 = display / silent gate; P2 is RFU. */
        if (cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_viewing_pubkey(&buf, cmd->p1);

    case VIEWING_PRIVKEY:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_viewing_privkey(&buf);

    case RAILGUN_ADDRESS:
        INIT_BUF_OR_FAIL();
        return handler_railgun_address(&buf, cmd->p1, cmd->p2);

        // ─── App identification ──────────────────────────────────────────

    /* ISO 7816 RFU bytes must be 0x00. The handlers below don't take p1/p2
     * (the data is meaningless to them), so we validate here before
     * invoking — avoids a fingerprinting / forward-compat hazard from
     * silently accepting non-zero RFU values. */
    case GET_VERSION:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        return handler_get_version();

    case GET_APP_NAME:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        return handler_get_app_name();

#if defined(ZKN_FROST)

        // ─── VSS/DKG ─────────────────────────────────────────────────────

    case DKG_GET_COMM_PUBKEY:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_dkg_get_comm_pubkey(&buf);

    case DKG_DEAL:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_dkg_deal(&buf);

    case DKG_SET_COMMITS:
        /* P1 = FIRST/NEXT/LAST chunk marker; P2 is RFU. */
        if (cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_dkg_set_commits(cmd->p1, &buf);

    case DKG_GET_SHARE:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_dkg_get_share(&buf);

    case DKG_PUT_SHARE:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_dkg_put_share(&buf);

    case DKG_FINALIZE: {
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        buffer_t empty = {0};
        return handler_dkg_finalize(&empty);
    }

    case DKG_ABORT:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        return handler_dkg_abort();

    case DKG_STATUS:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        return handler_dkg_status();

    case DKG_EXPORT_SHARE:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_dkg_export_share(&buf);

    case DKG_RESTORE_SHARE:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_dkg_restore_share(&buf);

        // ─── FROST signing on the DKG output ─────────────────────────────

    case FROST_HW_COMMIT: {
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        buffer_t empty = {0};
        return handler_frost_hw_commit(&empty);
    }

    case FROST_HW_SIGN:
        /* P1 = FIRST/NEXT/LAST chunk marker; P2 is RFU. */
        if (cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_frost_hw_sign(cmd->p1, &buf);

    case FROST_HW_RESET:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        return handler_frost_hw_reset();

#endif // ZKN_FROST

#ifdef ZKNOX_DEBUG

    /* Each case below explicitly validates the RFU bytes its handler doesn't
     * consume — debug-only INSes get the same treatment as prod ones so a
     * future move-to-prod inherits the check for free. */

    case BLIND_SIGN_NO_DISPLAY:
        /* P1 = curve id; P2 is RFU. */
        if (cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_blind_sign_no_display(cmd->p1, &buf);

    case SIGN_WITH_PRIVKEY:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_sign_with_privkey(&buf);

    /* Key extraction: these never leave ZKNOX_DEBUG, even once ZKN_FROST
     * ships. Both handlers live INSIDE handler_dkg.c's ZKN_FROST gate, in a
     * nested ZKNOX_DEBUG block — they only exist when both are set, so the
     * cases must be guarded on both too. */
#if defined(ZKN_FROST)
    case DKG_DEBUG_SKSHARE:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        return handler_dkg_debug_skshare();

    case DKG_DEBUG_COMM_PRIVKEY:
        if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SW_WRONG_P1P2);
        INIT_BUF_OR_FAIL();
        return handler_dkg_debug_comm_privkey(&buf);
#endif // ZKN_FROST

#endif // ZKNOX_DEBUG

    default:
        return io_send_sw(SW_INS_NOT_SUPPORTED);
    }
}
