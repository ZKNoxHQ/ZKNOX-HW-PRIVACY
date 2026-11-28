// zkn_app_config.h
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

/* What this application uses of ZKNOX-LibC.
 *
 * The Makefile names this file to the library (-DZKN_CONFIG_FILE), and
 * src/zknox/src/common/zkn_config.h includes it before the defaults of the
 * library, in every source of the app and of the library. It holds #define
 * lines only, each under #ifndef: a -D on the command line still wins.
 *
 * The Makefile sets one switch per target, ZKN_LOW_RAM on Nano S. What that
 * switch brings is written in two places: the part of the library in
 * zkn_config.h (low-RAM variants, fixed-base table read from flash, blinded
 * key scalar), the part of the app below.
 */
#ifndef ZKN_APP_CONFIG_H
#define ZKN_APP_CONFIG_H

/* Every target.
 *
 * ZKN_POSEIDON_ARITIES   the Poseidon tables linked for the BN254 field, one
 *                        bit per number of inputs: 1 and 3 (0zk address) and
 *                        5 (signature). The table of the Bandersnatch field
 *                        (5 inputs) keeps its default. DECISIONS.md, ADR-007
 *                        and ADR-012. */
#ifndef ZKN_POSEIDON_ARITIES
#define ZKN_POSEIDON_ARITIES 0x2A
#endif

/* ZKN_LOW_RAM: 4.6 KB of RAM for statics and stack together.
 *
 * POSEIDON_MAX_INPUTS       the largest Poseidon arity the app uses (5, the
 *                           EdDSA challenge), which sizes the hash context
 * ZKN_FROST_MAX_SIGNERS     the app signs for a quorum of at most DKG_MAX_T
 *                           signers (FS_MAX_SIGNERS in handler_frost_sign.c)
 * ZKN_CEREMONY_SCRATCH_NVM  public bulk of the ceremony state in an NVRAM
 *                           scratch area (src/handler/zkn_nv_scratch.h,
 *                           DECISIONS.md, ADR-003) */
#if defined(ZKN_LOW_RAM)
#  ifndef POSEIDON_MAX_INPUTS
#    define POSEIDON_MAX_INPUTS 5
#  endif
#  ifndef ZKN_FROST_MAX_SIGNERS
#    define ZKN_FROST_MAX_SIGNERS 3
#  endif
#  ifndef ZKN_CEREMONY_SCRATCH_NVM
#    define ZKN_CEREMONY_SCRATCH_NVM 1
#  endif
#endif

#endif /* ZKN_APP_CONFIG_H */
