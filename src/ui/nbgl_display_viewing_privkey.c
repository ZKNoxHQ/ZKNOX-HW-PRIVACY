/*****************************************************************************
 *   ZKNOX — NBGL UI for viewing-private-key export approval (INS 0x13).
 *
 *   Exporting the viewing key hands scanning ability to software: the user
 *   must explicitly allow it. The secret itself is never shown and never
 *   staged — validate_viewing_privkey derives and sends it only on Approve,
 *   then wipes. On Reject, SW_DENY. G_context is wiped on both paths.
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
static char g_vk_account[12];

static void review_choice(bool confirm)
{
    validate_viewing_privkey(confirm);
    if (confirm)
    {
        nbgl_useCaseStatus("Viewing key\nexported", true, ui_menu_main);
    }
    else
    {
        nbgl_useCaseStatus("Viewing key\nrejected", false, ui_menu_main);
    }
}

int ui_display_viewing_privkey(void)
{
    if (G_context.req_type != CONFIRM_VIEWING_PRIVKEY ||
        G_context.state != STATE_PARSED)
    {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    memset(g_vk_account, 0, sizeof(g_vk_account));
    if (!format_u64(g_vk_account, sizeof(g_vk_account),
                    (uint64_t)G_context.bip32_path[0]))
    {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }

    nbgl_useCaseChoice(&ICON_APP_WARNING,
                       "Allow viewing access\nto software wallet?",
                       g_vk_account,
                       "Allow",
                       "Reject",
                       review_choice);
    return 0;
}
