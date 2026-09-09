/* sim shim parser.h — command_t as in the Ledger SDK */
#pragma once
#include <stdint.h>
typedef struct {
    uint8_t  cla;
    uint8_t  ins;
    uint8_t  p1;
    uint8_t  p2;
    uint8_t  lc;
    uint8_t *data;
} command_t;
