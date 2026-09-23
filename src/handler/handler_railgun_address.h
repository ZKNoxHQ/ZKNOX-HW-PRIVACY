// handler_railgun_address.h
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

#ifndef _HANDLER_RAILGUN_ADDRESS_H
#define _HANDLER_RAILGUN_ADDRESS_H

#include <stdint.h>
#include "buffer.h"

// RAILGUN_ADDRESS (0x14) — canonical 0zk1… address for an account, shown on
// the trusted screen before it is returned.
//   in:  account(4 BE)
//   P1 = 0x00 silent (DEBUG builds only) / 0x01 display-and-confirm; P2 = 0x00
//   out: 127 ASCII bytes (not NUL-terminated) on Approve
int handler_railgun_address(buffer_t *cdata, uint8_t p1, uint8_t p2);

#endif // _HANDLER_RAILGUN_ADDRESS_H
