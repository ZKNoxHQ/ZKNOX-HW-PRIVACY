/* sim/shim/include/sim_compat.h — force-included in every TU (Makefile
 * -include). Declares symbols the app references without declaration in
 * some MODE combinations, so the sim builds against both the pre- and
 * post-audit dispatcher layouts without touching app sources. */
#pragma once
#include <stdint.h>
#include "buffer.h"

/* MODE=prod: dispatcher.c keeps the CLEAR_SIGN case but only includes
 * handler_clear_sign.h under ZKNOX_DEBUG on current main. The sim stubs
 * this handler to SW_INS_NOT_SUPPORTED either way (sim_stubs.c). */
int handler_clear_sign(uint8_t p1, uint8_t p2, buffer_t *cdata);

/* SHIELD_COMPUTE (0x15) is ZKNOX_DEBUG-only in the dispatcher and pulls
 * build_shield_material from the clear-sign unit, which the sim does not
 * compile. Declare both so every TU links; sim_stubs.c provides the bodies. */
int handler_shield_compute(uint8_t p2, buffer_t *cdata);
int build_shield_material(const uint8_t target_mpk[32],
                          const uint8_t target_vkpub[32],
                          uint8_t out_npk[32],
                          uint8_t out_shield_key[32],
                          uint8_t out_bundle[96]);
