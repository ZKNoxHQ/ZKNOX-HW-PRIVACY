/* sim/shim/sim_ui.c — auto-approve UI: every ui_display_* immediately
 * invokes its validate_* callback. SIM_REJECT=1 flips to auto-reject to
 * exercise the SW_DENY paths. CLEAR_SIGN UI entry points are stubbed to
 * hard-fail: that INS is not simulated. */
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include "validate.h"
#include "io.h"
#include "sw.h"
#include "menu.h"

static bool sim_choice(void) { return getenv("SIM_REJECT") == NULL; }
static void trace(const char *what) {
    if (getenv("SIM_VERBOSE"))
        fprintf(stderr, "[sim-ui] %s -> %s\n", what,
                sim_choice() ? "APPROVE" : "REJECT");
}

void ui_menu_main(void) {}

int ui_display_transaction(void) {
    trace("transaction");
    validate_transaction(sim_choice());
    return 0;
}
int ui_display_blind_signed_transaction(void) {
    trace("blind_signed_transaction");
    validate_transaction(sim_choice());
    return 0;
}
int ui_display_blind_sign_eddsa_poseidon(void) {
    trace("blind_sign_eddsa_poseidon");
    validate_eddsa_poseidon_sign(sim_choice());
    return 0;
}
int ui_display_viewing_privkey(void) {
    trace("viewing_privkey");
    validate_viewing_privkey(sim_choice());
    return 0;
}
int ui_display_railgun_pubkey_export(void) {
    trace("railgun_pubkey_export");
    validate_railgun_pubkey_export(sim_choice());
    return 0;
}
int ui_display_railgun_0zk_address(void) {
    trace("railgun_0zk_address");
    validate_railgun_0zk_address(sim_choice());
    return 0;
}
int ui_display_7702_auth(void) {
    trace("7702_auth");
    validate_7702_auth(sim_choice());
    return 0;
}
int ui_display_7702_address(void) {
    trace("7702_address");
    validate_7702_address(sim_choice());
    return 0;
}
int ui_display_sign_hash(void) {
    trace("sign_hash");
    validate_sign_hash(sim_choice());
    return 0;
}
/* CLEAR_SIGN flows — not simulated */
int ui_display_clear_sign_unshield(void)      { return io_send_sw(SW_INS_NOT_SUPPORTED); }
int ui_display_clear_sign_transfer(void)      { return io_send_sw(SW_INS_NOT_SUPPORTED); }
int ui_display_clear_sign_dual_transfer(void) { return io_send_sw(SW_INS_NOT_SUPPORTED); }
