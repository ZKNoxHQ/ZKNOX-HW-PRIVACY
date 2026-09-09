/* sim/shim/shim_io.c — io plumbing + app globals for the simulator. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "io.h"
#include "types.h"
#include "globals.h"

global_ctx_t G_context;
const internal_storage_t N_storage_real = { .initialized = 1 };

/* response accumulation for the current APDU */
uint8_t  sim_resp[4096];
size_t   sim_resp_len = 0;
uint16_t sim_sw = 0;
int      sim_replied = 0;

int io_send_sw(uint16_t sw) {
    sim_resp_len = 0;
    sim_sw = sw;
    sim_replied = 1;
    return 0;
}

int io_send_response_pointer(const uint8_t *ptr, size_t size, uint16_t sw) {
    if (size > sizeof(sim_resp)) return -1;
    memcpy(sim_resp, ptr, size);
    sim_resp_len = size;
    sim_sw = sw;
    sim_replied = 1;
    return 0;
}

void os_sched_exit(int code) {
    fprintf(stderr, "[sim] os_sched_exit(%d)\n", code);
    exit(code);
}

bool format_hex_impl(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    if (out_len < 2 * in_len + 1) return 0;
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out[2*i]   = h[in[i] >> 4];
        out[2*i+1] = h[in[i] & 0xF];
    }
    out[2*in_len] = 0;
    return 1;
}
/* alias attendu par format.h */
bool format_hex(const uint8_t *in, size_t in_len, char *out, size_t out_len)
    __attribute__((alias("format_hex_impl")));
uint8_t G_io_apdu_buffer[260];
void random_buffer(uint8_t *buf, size_t len) {
    extern uint32_t random32(void);
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)random32();
}
#include <stdbool.h>
bool consteq(const void *s1, const void *s2, size_t n) {
    const uint8_t *a = s1, *b = s2;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}
uint8_t g_frost_identifier[32];
uint8_t g_frost_group_key[64];
uint8_t g_frost_secret[32];
uint8_t g_frost_nonces[64];
uint8_t g_frost_com[480];
uint32_t g_frost_status;
