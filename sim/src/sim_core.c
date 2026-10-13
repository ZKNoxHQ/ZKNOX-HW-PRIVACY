/* sim/src/sim_core.c — one APDU in, one response out.
 *
 * This was `process_apdu` in main.c. It is the only seam the firmware needs:
 * fill a `command_t`, call the real `apdu_dispatcher`, read back what the
 * shim's `io_send_*` left in its accumulator. Pulling it out of main.c is
 * what lets a Rust test binary link the same objects and call it directly
 * instead of piping hex through a child process.
 */
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "types.h"
#include "dispatcher.h"
#include "sw.h"

#include "sim_core.h"

/* The shim's response accumulator, filled by io_send_sw /
 * io_send_response_pointer. */
extern uint8_t  sim_resp[];
extern size_t   sim_resp_len;
extern uint16_t sim_sw;
extern int      sim_replied;

int zkn_sim_exchange(const uint8_t *apdu, size_t len,
                     uint8_t *out, size_t *out_len) {
    command_t cmd;
    memset(&cmd, 0, sizeof(cmd));

    if (len < 4) {
        out[0] = 0x67; out[1] = 0x00; /* wrong length */
        *out_len = 2;
        return 0;
    }
    cmd.cla = apdu[0];
    cmd.ins = apdu[1];
    cmd.p1  = apdu[2];
    cmd.p2  = apdu[3];
    cmd.lc  = 0;
    cmd.data = NULL;
    if (len >= 5) {
        cmd.lc = apdu[4];
        if ((size_t)cmd.lc + 5 > len) {
            out[0] = 0x67; out[1] = 0x00;
            *out_len = 2;
            return 0;
        }
        if (cmd.lc > 0) cmd.data = (uint8_t *)(apdu + 5);
    }

    sim_replied = 0;
    sim_resp_len = 0;
    sim_sw = 0;

    apdu_dispatcher(&cmd);

    if (!sim_replied) { /* handler forgot to reply — should not happen */
        sim_sw = 0x6F00;
        sim_resp_len = 0;
    }
    memcpy(out, sim_resp, sim_resp_len);
    out[sim_resp_len]     = (uint8_t)(sim_sw >> 8);
    out[sim_resp_len + 1] = (uint8_t)(sim_sw & 0xFF);
    *out_len = sim_resp_len + 2;
    return 0;
}

const char *zkn_sim_version(void) { return SIM_VERSION; }

int zkn_sim_has_debug_ins(void) {
#ifdef ZKNOX_MODE_DEBUG
    return 1;
#else
    return 0;
#endif
}

int zkn_sim_has_frost(void) {
#ifdef ZKN_FROST
    return 1;
#else
    return 0;
#endif
}
