/* sim/shim/sim_stubs.c — CLEAR_SIGN (INS 0x11) is out of scope for the
 * simulator: its stateful multi-APDU session drives real NBGL flows.
 * The dispatcher case and validate.c references must still link. */
#include <stdint.h>
#include "buffer.h"
#include "io.h"
#include "sw.h"

int handler_clear_sign(uint8_t p1, uint8_t p2, buffer_t *cdata) {
    (void)cdata; (void)p1; (void)p2;
    return io_send_sw(SW_INS_NOT_SUPPORTED);
}
void clear_sign_reset_state(void) {}
void clear_sign_stage_pending_shield_ct(void) {}
int clear_sign_multi_sign_and_respond(void) {
    return io_send_sw(SW_INS_NOT_SUPPORTED);
}

/* SHIELD_COMPUTE (INS 0x15) and build_shield_material belong to the clear-sign
 * world the sim excludes (see above). Their dispatcher/validate.c references
 * must still link, so stub them the same way. Neither is reachable on the sim:
 * clear-sign and shield host tests are device-only. */
int handler_shield_compute(uint8_t p2, buffer_t *cdata) {
    (void)p2; (void)cdata;
    return io_send_sw(SW_INS_NOT_SUPPORTED);
}
int build_shield_material(const uint8_t target_mpk[32],
                          const uint8_t target_vkpub[32],
                          uint8_t out_npk[32],
                          uint8_t out_shield_key[32],
                          uint8_t out_bundle[96]) {
    (void)target_mpk; (void)target_vkpub;
    (void)out_npk; (void)out_shield_key; (void)out_bundle;
    return -1;  /* never called on the sim; present only so validate.c links */
}
