/* sim shim crypto_helpers.h */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "cx.h"
cx_err_t bip32_derive_ecdsa_sign_hash_256(cx_curve_t curve,
                                          const uint32_t *path, size_t path_len,
                                          uint32_t sign_mode, uint32_t hashID,
                                          const uint8_t *hash, size_t hash_len,
                                          uint8_t *sig, size_t *sig_len,
                                          uint32_t *info);
cx_err_t bip32_derive_get_pubkey_256(cx_curve_t curve,
                                     const uint32_t *path, size_t path_len,
                                     uint8_t raw_pubkey[65], uint8_t *chain_code,
                                     uint32_t hashID);
