#pragma once

#include <stdint.h>

#include "ux.h"

#include "io.h"
#include "types.h"
#include "constants.h"

/**
 * Global context for user requests.
 */
extern global_ctx_t G_context;

/**
 * Global structure for NVM data storage.
 *
 * `initialized` is the "NVM has been provisioned" sentinel: app_main.c
 * checks it on boot and writes a default-initialised storage struct
 * on first run.
 */
typedef struct internal_storage_t
{
    uint8_t initialized;
} internal_storage_t;

extern const internal_storage_t N_storage_real;
#define N_storage (*(volatile internal_storage_t *)PIC(&N_storage_real))
