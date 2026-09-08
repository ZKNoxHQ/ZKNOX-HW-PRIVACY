/*****************************************************************************
 *   ZKNOX — NBGL UI for the EdDSA-Poseidon blind-sign flow.
 *
 *   Shows the user:
 *     - which account index the signature will be produced under,
 *     - the 32-byte message, in hex.
 *
 *   The message is opaque by construction: this app implements the
 *   primitive, not a protocol, so there is nothing here that could turn
 *   32 bytes into a human-meaningful statement. That is exactly what
 *   blind signing means, and the review says so — an application that
 *   wants a clear-signing screen has to supply the semantics itself.
 *
 *   On Approve, validate_eddsa_poseidon_sign derives the key and signs.
 *   On Reject, SW_DENY. G_context is wiped on both paths.
 *****************************************************************************/

#include <stdbool.h>
#include <string.h>

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "globals.h"
#include "sw.h"
#include "validate.h"
#include "menu.h"

// Hex encoding of the 32-byte message (64 chars + NUL)
static char g_eddsa_msg[65];
// Decimal encoding of the 32-bit account index (uint32 = 10 digits + NUL)
static char g_eddsa_account[12];

static nbgl_contentTagValue_t pairs[2];
static nbgl_contentTagValueList_t pairList;

static void review_choice(bool confirm)
{
    validate_eddsa_poseidon_sign(confirm);
    if (confirm)
    {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    }
    else
    {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

int ui_display_blind_sign_eddsa_poseidon(void)
{
    if (G_context.req_type != CONFIRM_SIGN || G_context.state != STATE_PARSED)
    {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    memset(g_eddsa_msg, 0, sizeof(g_eddsa_msg));
    memset(g_eddsa_account, 0, sizeof(g_eddsa_account));

    // Format the 32-byte message (stored in m_hash) as hex for display.
    if (format_hex(G_context.sign_info.m_hash, 32, g_eddsa_msg, sizeof(g_eddsa_msg)) == -1)
    {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }

    // Format the account index. handler_blind_sign stored it at
    // payload[0..3] in big-endian; handler_eddsa_poseidon_sign_stored
    // reads the same 4 bytes back when it derives the signing key. The
    // user MUST see this on the review screen — without it a corrupted
    // host could produce a signature under a different identity than the
    // user intended, and every field on screen would still look right.
    const uint8_t *acc_be = G_context.sign_info.payload;
    uint64_t account = ((uint64_t)acc_be[0] << 24) |
                       ((uint64_t)acc_be[1] << 16) |
                       ((uint64_t)acc_be[2] << 8)  |
                       ((uint64_t)acc_be[3]);
    if (!format_u64(g_eddsa_account, sizeof(g_eddsa_account), account))
    {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }

    pairs[0].item  = "Account";
    pairs[0].value = g_eddsa_account;
    pairs[1].item  = "Message";
    pairs[1].value = g_eddsa_msg;

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 2;
    pairList.pairs = pairs;

    nbgl_useCaseReviewBlindSigning(TYPE_MESSAGE,
                                   &pairList,
                                   &ICON_APP_MAIN,
                                   "Review EdDSA-Poseidon\nsignature request",
                                   NULL,
#ifdef SCREEN_SIZE_WALLET
                                   "Sign\nmessage",
#else
                                   NULL,
#endif
                                   NULL,
                                   review_choice);
    return 0;
}
