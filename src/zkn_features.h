#pragma once

/* zkn_features.h — compile-time feature gates.
 *
 * NOT named features.h: src/ is on the include path (-I), and -I directories
 * are searched before the system ones even for <...> includes. A src/features.h
 * shadows glibc's <features.h>, which bits/libc-header-start.h pulls in from
 * every <stdint.h> and <string.h> — __GLIBC_USE and __THROW then never get
 * defined and the whole translation unit collapses. Keep the zkn_ prefix.
 *
 * Two independent switches, set by the Makefile as -D flags. Nothing to do in
 * this header; it exists to document what the gates mean and what still blocks
 * lifting them.
 *
 *   ZKNOX_DEBUG  the test and introspection surface: no-UI signing, raw-scalar
 *                signing, viewing-key export without approval, and the two DKG
 *                INSes that hand out secrets (0x68 DKG_DEBUG_COMM_PRIVKEY,
 *                0x69 DKG_DEBUG_SKSHARE).
 *
 *   ZKN_FROST    threshold signing: the VSS/DKG ceremony (INS 0x60–0x6b, minus
 *                the two DEBUG ones) and FROST signing on its output
 *                (0x70–0x72).
 *
 * They are deliberately independent, so MODE=debug FROST=0 stays available as
 * the split's own regression configuration. MODE=prod FROST=1 is a Makefile
 * error until the blocking list below is complete.
 *
 *   BLOCKING, before threshold signing can ship in a production build
 *   - The share lives in RAM globals — no nvm_write. Finish a ceremony, leave
 *     the app, and the share is gone. Unusable, not merely unpolished.
 *   - FROST_HW_SIGN releases z_i with no user confirmation at all. The gate in
 *     handler_frost_sign.c is a comment, not code. The device signs whatever
 *     the host hands it — which is the one thing a hardware wallet exists to
 *     prevent. Note the caveat that comes with it: approving an opaque 32-byte
 *     hash is not a confirmation, so this needs a clear-signing path supplied
 *     by the protocol layered on top, not just a screen.
 *   - DKG_FINALIZE displays nothing and waits for no approval either. Comparing
 *     the group key A across the n screens IS the ceremony's out-of-band
 *     channel; without it, a coordinator handing two devices different values
 *     of A goes unnoticed.
 *
 *   DECIDED BUT NOT DONE
 *   - HK is not covered by the commitments digest. SET_COMMITS anchors our own
 *     entry, which breaks the attack; binding HK into the digest would make a
 *     substitution detectable by everyone. It changes the wire digest, so it
 *     has to land together with the host-side reference implementation.
 *
 *   DONE — kept here as the record of what the gate is for
 *   - DKG transport uses its own hardened Ed25519 identity (KEY_TYPE_DKG_COMM),
 *     never the intentionally exportable viewing-key path.
 *   - D_j/E_j from the wire are checked against the curve equation
 *     (zkn_compute_group_commitment).
 *   - Secret scalars on a fixed base use the constant-time MSM, not the
 *     variable-time double-and-add (zkn_frost_commit and friends). The
 *     invariant that keeps that true is written at tEdwards_scalarMul.
 */
