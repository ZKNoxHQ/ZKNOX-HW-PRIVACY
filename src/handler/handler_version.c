// handler_version.c — GET_VERSION / GET_APP_NAME implementations
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

#include <stdint.h>
#include <string.h>

#include "os.h"
#include "io.h"

#include "../sw.h"
#include "../constants.h"
#include "handler_version.h"

// ── GET_VERSION (INS=0x03) ─────────────────────────────────────────────
//
// APDU:  CLA=E0  INS=0x03  P1=0  P2=0  Lc=0
// Response: MAJOR(1) || MINOR(1) || PATCH(1) || SW
//
// APPVERSION_M / APPVERSION_N / APPVERSION_P are -D defines passed in
// from the Makefile (see APPVERSION_* lines in the project Makefile).

int handler_get_version(void)
{
    uint8_t out[APPVERSION_LEN];
    out[0] = (uint8_t)APPVERSION_M;
    out[1] = (uint8_t)APPVERSION_N;
    out[2] = (uint8_t)APPVERSION_P;
    return io_send_response_pointer(out, sizeof(out), SW_OK);
}

// ── GET_APP_NAME (INS=0x04) ────────────────────────────────────────────
//
// APDU:  CLA=E0  INS=0x04  P1=0  P2=0  Lc=0
// Response: APPNAME bytes (no length prefix) || SW
//
// APPNAME is a string literal defined in the Makefile (e.g. "RAILGUN").
// APPNAME_LEN = strlen(APPNAME) via constants.h.

int handler_get_app_name(void)
{
    return io_send_response_pointer((const uint8_t *)APPNAME, APPNAME_LEN, SW_OK);
}
