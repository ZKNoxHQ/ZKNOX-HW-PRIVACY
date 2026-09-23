/*****************************************************************************
 *   ZKNOX — NBGL UI for 0zk1… address confirmation (INS 0x14).
 *
 *   Shows the account index and the canonical 0zk1… address so the user can
 *   verify it on the trusted screen before it is shared. On Approve,
 *   validate_railgun_0zk_address returns the 127-byte string; on Reject,
 *   SW_DENY. G_context is wiped on both paths.
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
static char g_addr_account[12];

static nbgl_contentTagValue_t pairs[1];
static nbgl_contentTagValueList_t pairList;

static void review_choice(bool confirm)
{
    validate_railgun_0zk_address(confirm);
    if (confirm)
    {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    }
    else
    {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
    }
}

int ui_display_railgun_0zk_address(void)
{
    if (G_context.req_type != CONFIRM_RAILGUN_ADDRESS ||
        G_context.state != STATE_PARSED)
    {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    /* The address is a NUL-terminated ASCII string staged by the handler. */
    if (G_context.pk_info.zk_address[0] == '\0')
    {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    memset(g_addr_account, 0, sizeof(g_addr_account));
    if (!format_u64(g_addr_account, sizeof(g_addr_account),
                    (uint64_t)G_context.bip32_path[0]))
    {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }

    pairs[0].item  = "Account";
    pairs[0].value = g_addr_account;

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 1;
    pairList.pairs   = pairs;

    nbgl_useCaseAddressReview(G_context.pk_info.zk_address,
                              &pairList,
                              &ICON_APP_MAIN,
                              "Verify RAILGUN\n0zk address",
                              NULL,
                              review_choice);
    return 0;
}
