/*****************************************************************************
 *   ZKNOX — NBGL UI for signing-pubkey export approval.
 *
 *   Shows the user:
 *     - which account index they are about to export a pubkey for,
 *     - the pubkey bytes in hex, so they can compare against an
 *       out-of-band source.
 *
 *   On Approve, validate_pubkey_export sends the raw pubkey bytes (length
 *   from G_context.pk_info.raw_public_key_len). On Reject, SW_DENY. In
 *   both cases G_context is wiped.
 *
 *   This UI lives in production; the silent export path is debug-only
 *   (see handler_signing_pubkey).
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

/* Decimal uint32 account index = 10 digits + NUL. */
static char g_pk_account[12];
/* Hex of the pubkey: 64 B = 128 hex chars, plus a leading "0x" and NUL. */
static char g_pk_hex[2 + 64 * 2 + 1];

#if defined(TARGET_NANOS)
/* LNS SDK (lib_nbgl at lns-2.1.0-v24.0): nbgl_useCaseAddressReview copies
 * the whole additionalTagValueList struct over the pointer field of its
 * context, which overwrites the title pointer with nbPairs and faults on the
 * first page. On Nano S the same two fields go through the plain review:
 * title, account, value, Approve / Reject. */
#define PK_NB_PAIRS 2
#else
#define PK_NB_PAIRS 1
#endif

static nbgl_contentTagValue_t pairs[PK_NB_PAIRS];
static nbgl_contentTagValueList_t pairList;

static void review_choice(bool confirm)
{
    bool exported = validate_pubkey_export(confirm);
    if (!confirm)
    {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
    }
    else if (exported)
    {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    }
    else
    {
        nbgl_useCaseStatus("Export failed", false, ui_menu_main);
    }
}

int ui_display_pubkey_export(void)
{
    if (G_context.req_type != CONFIRM_PUBKEY_EXPORT ||
        G_context.state != STATE_PARSED)
    {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    const size_t pubkey_len = G_context.pk_info.raw_public_key_len;
    if (pubkey_len == 0 || pubkey_len > sizeof(G_context.pk_info.raw_public_key))
    {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    /* Account index → decimal. */
    memset(g_pk_account, 0, sizeof(g_pk_account));
    if (!format_u64(g_pk_account, sizeof(g_pk_account),
                    (uint64_t)G_context.bip32_path[0]))
    {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }

    /* Pubkey → "0x" + lowercase hex. */
    memset(g_pk_hex, 0, sizeof(g_pk_hex));
    g_pk_hex[0] = '0';
    g_pk_hex[1] = 'x';
    if (format_hex(G_context.pk_info.raw_public_key, pubkey_len,
                   g_pk_hex + 2, sizeof(g_pk_hex) - 2) == -1)
    {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }

    pairs[0].item  = "Account";
    pairs[0].value = g_pk_account;
    /* No pair for the hex: nbgl_useCaseAddressReview already shows g_pk_hex
     * as the primary (top-of-screen) value, and duplicating it as a
     * tag-value row both repeats and truncates unpleasantly on the Nano's
     * narrow tag column. */

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 1;
    pairList.pairs   = pairs;

#if defined(TARGET_NANOS)
    pairs[1].item  = G_context.pk_info.is_viewing ? "Viewing pubkey" : "Signing pubkey";
    pairs[1].value = g_pk_hex;
    pairList.nbPairs = 2;

    nbgl_useCaseReview(TYPE_OPERATION,
                       &pairList,
                       &ICON_APP_MAIN,
                       G_context.pk_info.is_viewing
                           ? "Export\nviewing pubkey"
                           : "Export\nsigning pubkey",
                       NULL,
                       NULL,
                       review_choice);
#else
    nbgl_useCaseAddressReview(g_pk_hex,
                              &pairList,
                              &ICON_APP_MAIN,
                              G_context.pk_info.is_viewing
                                  ? "Export\nviewing pubkey"
                                  : "Export\nsigning pubkey",
                              NULL,
                              review_choice);
#endif
    return 0;
}
