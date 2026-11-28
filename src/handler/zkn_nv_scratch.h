// zkn_nv_scratch.h
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

#pragma once

/* Where the bulky, PUBLIC part of the threshold ceremony state lives.
 *
 * Default (every target but Nano S): in the RAM struct of the handler. The
 * macros below then expand to the plain statements the handlers always had
 * (memcpy, in-place output), so the generated code does not change.
 *
 * ZKN_CEREMONY_SCRATCH_NVM (Nano S: it comes with ZKN_LOW_RAM, see
 * src/zkn_app_config.h): in an NVRAM scratch area. The Nano S has 4.6 KB of RAM for statics and stack together; the
 * commitments, their hashes, the comm public keys, the digest input and the
 * reassembled FROST request are 1.8 KB of it. All of that is public data that
 * the host sent or will receive. Secrets (polynomial coefficients, share
 * accumulator, key share, FROST nonces) stay in RAM on every target.
 *
 * The scratch area is NOT persistence. The state machine (in RAM) gates every
 * read: after an app restart the state is IDLE and nothing written before is
 * reachable. Flash is read like memory and written with nvm_write only, hence
 * the staging macros for callees that write their output in place.
 *
 *   ZKN_NV_PUT(dst, src, len)     copy into the bulk area
 *   ZKN_NV_ZERO(dst, len)         clear part of the bulk area
 *   ZKN_NV_STAGE(name, len)       declare a staging buffer (nothing in RAM mode)
 *   ZKN_NV_DST(dst, stage)        where a callee must write: stage, or dst in RAM mode
 *   ZKN_NV_FLUSH(dst, stage, len) commit the staging buffer (nothing in RAM mode)
 */

#include "zkn_config.h" /* the options of the build, ZKN_CEREMONY_SCRATCH_NVM among them */

#if defined(ZKN_CEREMONY_SCRATCH_NVM)

#include "os.h"

#define ZKN_NV_PUT(dst, src, len)                                      \
    do {                                                               \
        if ((len) != 0) nvm_write((void *)(dst), (void *)(src), (len)); \
    } while (0)
#define ZKN_NV_ZERO(dst, len)          nvm_write((void *)(dst), NULL, (len))
#define ZKN_NV_STAGE(name, len)        uint8_t name[len]
#define ZKN_NV_DST(dst, stage)         (stage)
#define ZKN_NV_FLUSH(dst, stage, len)  nvm_write((void *)(dst), (stage), (len))

#else

#define ZKN_NV_PUT(dst, src, len)      memcpy((dst), (src), (len))
#define ZKN_NV_ZERO(dst, len)          explicit_bzero((dst), (len))
#define ZKN_NV_STAGE(name, len)
#define ZKN_NV_DST(dst, stage)         (dst)
#define ZKN_NV_FLUSH(dst, stage, len)  ((void)0)

#endif
