// handler_version.h — Standard Ledger app GET_VERSION / GET_APP_NAME
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// Implements the canonical app-level identification APDUs used by
// integration SDKs (Ledger Live, ledgerctl, app-client SDKs).
//
// The BOLOS default APDU handler (CLA=0xB0 INS=0x01) provides the same
// info at the OS level and works regardless of these handlers. These
// app-level INS values exist for clients that query the app under its
// own CLA (0xE0).
//
//   GET_VERSION   (INS=0x03)  no data, returns MAJOR(1) || MINOR(1) || PATCH(1)
//   GET_APP_NAME  (INS=0x04)  no data, returns APPNAME bytes (no length prefix)

#pragma once

int handler_get_version(void);
int handler_get_app_name(void);
