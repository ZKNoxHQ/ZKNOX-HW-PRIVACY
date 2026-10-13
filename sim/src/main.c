/* sim/src/main.c — ZKNOX APDU simulator, line protocol front-end.
 *
 * The simulator itself is `sim_core.c`: it drives the REAL dispatcher +
 * handlers, compiled for the host with the SDK shim, against the software
 * crypto backend. This file is only the transport.
 *
 * Interface: line-based hex on stdin/stdout. One APDU per line in,
 * one response (data || SW) per line out. No network, no framing, no
 * sessions — the caller spawns this binary and pipes lines. Several
 * participants means several processes, the firmware's ceremony state being
 * a file static.
 *
 * Env: SIM_SEED (128 hex chars), SIM_REJECT=1, SIM_VERBOSE=1,
 *      SIM_RNG_SEED (deterministic RNG for reproducibility).
 *
 * `rs/crates/zknox-sim` links sim_core.o instead and calls it directly,
 * with setters in place of these variables.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sim_core.h"

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char **argv) {
    char line[16384];

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("apdu_sim %s (%s%s)\n", zkn_sim_version(),
               zkn_sim_has_debug_ins() ? "debug" : "prod",
               zkn_sim_has_frost() ? ", frost" : "");
        return 0;
    }
    uint8_t apdu[8192], out[ZKN_SIM_RESP_MAX];

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
        zkn_sim_exchange(apdu, n, out, &out_len);
        for (size_t i = 0; i < out_len; i++) printf("%02x", out[i]);
        printf("\n");
    }
    return 0;
}
