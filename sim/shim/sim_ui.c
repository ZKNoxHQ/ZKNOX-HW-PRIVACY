/* sim/shim/sim_ui.c — auto-approve UI: every ui_display_* immediately
 * invokes its validate_* callback. SIM_REJECT=1 flips to auto-reject to
 * exercise the SW_DENY paths.
 *
 * The surface is exactly the one src/ui/display.h declares and
 * src/ui/action/validate.h answers; this app has no clear-sign, no 7702
 * and no transaction review, so the entry points the RAILGUN app needed are
 * gone rather than stubbed. A handler reaching for one of them will fail to
 * link, which is the signal that this file has to follow the app. */
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include "validate.h"
#include "io.h"
#include "sw.h"
#include "menu.h"

#include "sim_core.h"

/* -1 = read SIM_REJECT, 0 = reject, 1 = approve. A caller that links the
 * simulator (sim_core.h) sets it and can flip it between exchanges, which
 * SIM_REJECT cannot do: it is read once per process here only because the
 * line protocol gives a caller no other way in. */
static int g_decision = -1;

void zkn_sim_set_ui_decision(int decision) { g_decision = decision; }

static bool sim_choice(void) {
    if (g_decision >= 0) return g_decision != 0;
    return getenv("SIM_REJECT") == NULL;
}
static void trace(const char *what) {
    if (getenv("SIM_VERBOSE"))
        fprintf(stderr, "[sim-ui] %s -> %s\n", what,
                sim_choice() ? "APPROVE" : "REJECT");
}

void ui_menu_main(void) {}

int ui_display_blind_sign_eddsa_poseidon(void) {
    trace("blind_sign_eddsa_poseidon");
    validate_eddsa_poseidon_sign(sim_choice());
    return 0;
}
int ui_display_pubkey_export(void) {
    trace("pubkey_export");
    validate_pubkey_export(sim_choice());
    return 0;
}
int ui_display_viewing_privkey(void) {
    trace("viewing_privkey");
    validate_viewing_privkey(sim_choice());
    return 0;
}
int ui_display_railgun_0zk_address(void) {
    trace("railgun_0zk_address");
    validate_railgun_0zk_address(sim_choice());
    return 0;
}
