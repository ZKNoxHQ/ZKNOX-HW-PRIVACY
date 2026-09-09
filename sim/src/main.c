/* sim/src/main.c — ZKNOX APDU simulator.
 *
 * Drives the REAL dispatcher + handlers, compiled for the host with the
 * SDK shim, against the software crypto backend.
 *
 * Interface: line-based hex on stdin/stdout. One APDU per line in,
 * one response (data || SW) per line out. No network, no framing, no
 * sessions — the JS side spawns this binary and pipes lines.
 *
 * Env: SIM_SEED (128 hex chars), SIM_REJECT=1, SIM_VERBOSE=1,
 *      SIM_RNG_SEED (deterministic RNG for reproducibility).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "types.h"
#include "dispatcher.h"
#include "sw.h"

extern uint8_t  sim_resp[];
extern size_t   sim_resp_len;
extern uint16_t sim_sw;
extern int      sim_replied;

static int process_apdu(const uint8_t *apdu, size_t len,
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

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char **argv) {
    char line[16384];

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("apdu_sim %s (%s)\n", SIM_VERSION,
#ifdef ZKNOX_MODE_DEBUG
               "debug"
#else
               "prod"
#endif
        );
        return 0;
    }
    uint8_t apdu[8192], out[8192];

    setvbuf(stdout, NULL, _IOLBF, 0); /* line-buffered even when piped */

    while (fgets(line, sizeof(line), stdin)) {
        size_t n = 0;
        int hi = -1;
        for (char *p = line; *p; p++) {
            int v = hexval((unsigned char)*p);
            if (v < 0) continue;
            if (hi < 0) hi = v;
            else { apdu[n++] = (uint8_t)((hi << 4) | v); hi = -1; }
        }
        if (n == 0) continue;
        size_t out_len = 0;
        process_apdu(apdu, n, out, &out_len);
        for (size_t i = 0; i < out_len; i++) printf("%02x", out[i]);
        printf("\n");
    }
    return 0;
}
