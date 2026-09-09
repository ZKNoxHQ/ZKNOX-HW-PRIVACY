/* sim shim bip32.h — serves BOTH consumers of the "bip32.h" name:
 *  - the app (types.h) needs MAX_BIP32_PATH,
 *  - vendored trezor-crypto (secp256k1.h/.c) needs curve_info. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hasher.h"
#include "ecdsa.h"

#define MAX_BIP32_PATH 10

typedef struct {
  const char *bip32_name;
  const ecdsa_curve *params;
  HasherType hasher_base58;
  HasherType hasher_sign;
  HasherType hasher_pubkey;
  HasherType hasher_script;
} curve_info;
