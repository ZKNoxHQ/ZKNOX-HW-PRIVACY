# Decisions

Architecture decisions for ZKNOX-HW-PRIVACY, newest first.

## ADR-002: Nano S review screens use the plain review use case

Date: 2026-11-25

### Context

The Nano S builds against the LNS SDK (`API_LEVEL_LNS`, tag `lns-2.1.0-v24.0`).
Two NBGL use cases the other devices rely on are not usable there:

- `nbgl_useCaseReviewBlindSigning` does not exist.
- `nbgl_useCaseAddressReview` faults when `additionalTagValueList` is not
  NULL. `lib_nbgl/src/nbgl_use_case_nanos.c` copies the whole
  `nbgl_contentTagValueList_t` over `context.review.tagValueList`, which is a
  pointer. The copy overwrites the neighbouring fields: `reviewTitle` receives
  `nbPairs`, and the first page calls `strlen(1)`.

### Decision

Under `TARGET_NANOS` only, the three reviews go through `nbgl_useCaseReview`:

| Screen | Other devices | Nano S |
|---|---|---|
| Public key export | address review + "Account" row | review: Account, key |
| 0zk address | address review + "Account" row | review: Account, address |
| Blind sign | blind-signing review | review titled "Blind sign message" |

The fields shown and the Approve / Reject outcome are the same.

### Consequences

The Nano S has no SDK-provided blind-signing warning page. The warning is the
title of the first page. The title page holds two short lines beside the icon,
which is why it does not name the algorithm.

## ADR-001: Nano S runs the low-RAM variants of ZKNOX-LibC

Date: 2026-11-25

### Context

The Nano S secure element gives an app 4608 bytes of RAM for statics and
stack together, and it is an ARMv6-M core (Thumb-1, no `UMULL`). With 1420
bytes of statics, 3184 bytes are left for the stack.

The software backend keeps every bignum in the caller's frame. Measured on the
unmodified code, the signing path needs about 7000 bytes of stack: 3432 for
`EddsaPoseidon_Sign_final`, 2000 for the randomized 16-entry table of the
fixed-base multiplication, 880 for the handler. The emulator faults on the
first signature.

### Decision

A compile-time switch, `ZKN_LOW_RAM`, selects smaller-footprint
implementations in the library. The Makefile sets it for `TARGET_NANOS` and
for no other target.

1. Fixed-base scalar multiplication uses two 128-bit windows over the 4-entry
   precomputed table instead of four 64-bit windows over the 16-entry one. The
   construction is the one of `tEdwards_4MSM_precomp_table`: every iteration
   doubles and adds, the table entry is selected by a masked scan of all
   entries, each entry gets a fresh projective randomization per
   multiplication, and the accumulator is re-randomized every 16 iterations.
   The randomized table in RAM shrinks from 1536 to 384 bytes.
2. The Poseidon mixing layer reads the MDS matrix from the const table, one
   entry at a time, instead of holding a Montgomery copy of it in the context
   (2048 bytes).
3. On the software backend, `EddsaPoseidon_Sign_final` runs each step in its
   own non-inlined function (key check, nonce hash, nonce reduction,
   commitment, challenge, response). Frames no longer stack up. The secret
   scalar is recomputed in the last step instead of being carried across the
   scalar multiplications.
4. The Thumb-2 Montgomery assembly is not assembled for ARMv6-M. The C
   versions are used.
5. `FROST=1` is refused for this target. The DKG transport needs
   `cx_aes_gcm_*`, which the LNS cxng does not have, and with the ceremony
   state the statics grow to 3.5 KB.

### Consequences

- Peak stack measured on the emulated Nano S (Speculos 0.25.5, `BACKEND=sw`,
  `MODE=prod`), per command, out of 3184 bytes: Railgun address 2592, blind
  sign 2576, signing public key 2312, viewing public key 920, viewing private
  key 632. The margin is 592 bytes.
- Results are unchanged: public keys and signatures equal circomlibjs
  (`prv2pub`, `signPoseidon`) byte for byte, and the library's host tests pass
  with and without the switch.
- One signature costs 15154 Montgomery multiplications instead of 10846
  (+40%). Signing time on a real Nano S has not been measured.
- Flash images of the Nano S Plus target are byte-identical before and after
  the change, for both backends.
- `BACKEND=cx` builds for Nano S and its static worst case fits (2304 bytes on
  the signing path), but it has not been run: Speculos does not emulate
  `cx_mont_*` for this model.

### Alternatives considered

- Selecting the table entry straight from flash and randomizing it afterwards,
  with no table in RAM. Rejected: the selection would then handle unmasked,
  known table constants.
- Moving the large buffers to static storage. Rejected: statics and stack
  share the same 4608 bytes.
- A single randomization factor shared by all 16 entries, stored as (x, y)
  pairs. Rejected: still 1024 bytes, and weaker than one factor per entry.
