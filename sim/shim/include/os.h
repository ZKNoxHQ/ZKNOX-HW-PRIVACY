/* sim shim os.h */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "cx.h"

#define PIC(x) (x)
#define PRINTF(...) do { if (getenv("SIM_VERBOSE")) fprintf(stderr, __VA_ARGS__); } while (0)
#ifndef HAVE_EXPLICIT_BZERO_DECL
void explicit_bzero(void *s, size_t n);
#endif

typedef enum { HDW_NORMAL = 0, HDW_ED25519_SLIP10 = 1, HDW_SLIP21 = 2 } os_derivation_mode_t;

cx_err_t os_derive_bip32_no_throw(cx_curve_t curve, const uint32_t *path,
                                  size_t path_len, uint8_t *privkey,
                                  uint8_t *chain);
cx_err_t os_derive_bip32_with_seed_no_throw(os_derivation_mode_t mode,
                                            cx_curve_t curve,
                                            const uint32_t *path, size_t path_len,
                                            uint8_t *privkey, uint8_t *chain,
                                            unsigned char *seed_key,
                                            size_t seed_key_len);
void os_sched_exit(int code);
#include <stdlib.h>
