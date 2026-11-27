# Decisions

Architecture decisions for ZKNOX-HW-PRIVACY, newest first.

## ADR-008: the signer takes the subgroup order from the curve

Date: 2026-11-27

### Context

`EddsaPoseidon_Sign_final` reduced the nonce and computed `S` with the
BabyJubjub subgroup order, a constant in the function, for every curve. The
bound on the message had been made to follow the curve; the order had not. On
Bandersnatch the result did not satisfy `[S]B = R + [8h]A`, the equation a
verifier checks. No test verified a Bandersnatch signature, and the low-RAM
vectors of this branch pinned the faulty output. The threshold paths are not
concerned: they read `curve->order`.

ZKNOX-LibC corrected its signer on main (pull request 4, `d1a0da6`). Nano S
does not run that code: it runs the low-RAM signer of ADR-001 and ADR-006,
which had the same two constants, the order and `2^256 mod l`.

### Decision

The standard signer of the submodule is the one of main, line for line.

The low-RAM signer reads `l` from `curve->order`. The reduction of the nonce
uses it in place and computes `2^256 mod l` from `2^256 - l` with one
`zkn_bn_reduce`, as main does. The response runs after the challenge has
released `curve->order` with the work variables of the curve, so the bytes of
`l` are exported before and cross the challenge in the 64 bytes of scratch
that held the nonce hash, free once the nonce is reduced. No constant per
curve, no new buffer.

The two Bandersnatch vectors of `tests/test_lowram_vectors.c` are replaced by
the output of main, and the regression test of main, which verifies a
signature on each curve, comes with the signer. The Rust suite gets one
signature on Bandersnatch against a fixed vector, through `SIGN_WITH_PRIVKEY`.

### Consequences

- Bandersnatch signatures change on every target, and they verify. Those of
  earlier builds did not.
- BabyJubjub signatures are the same bytes: `2^256 mod l` computed at run
  time is the constant that was removed.
- Nano S: same code size (48087 bytes in `MODE=prod`, 66519 in
  `MODE=debug FROST=1`), same stack peaks (2296 of 3184 in production, 2616
  of 2904 with `FROST=1`), 6391 Montgomery products per signature, about 5000
  cycles more out of 135 M. Expected time on the device: 6.2 s on either
  curve.
- Checked on the host: the library's tests in the four combinations of
  `ZKN_LOW_RAM` and `ZKN_FIXEDBASE_FLASH_TABLE`, where the regression test
  goes through the low-RAM signer when the switch is on.
- Checked on the emulated Nano S: the JavaScript and Rust suites, three
  ceremonies, and `BLIND_SIGN` of the production image on both curves, whose
  signatures equal those of main for the same key and satisfy the equation
  under curve arithmetic written apart from the library. The new Rust test
  fails on the image of the previous delivery.
- Nano S Plus: with the library's main after pull request 4 and the Poseidon
  delivery of ADR-007 under upstream main of the app, the flash images are
  byte-identical with and without this branch, for both backends, in
  `MODE=prod FROST=0` and `MODE=debug FROST=1`.
- The threshold paths stay BabyJubjub only, as before: the FROST challenge
  and its message bound name that curve.

### Alternatives considered

- Constants per curve for `l` and `2^256 mod l`, chosen by curve id: 128
  bytes of flash and a second place where a curve parameter lives. The curve
  structure already holds `l`.
- A 32-byte copy of `l` in the frame of the signer, which is what the
  standard signer does: 32 bytes of stack at the deepest point of a
  signature, on a target whose margin is 288 with `FROST=1`.
- Leaving `2^256 - l` unreduced, which the low-RAM modular multiplication
  accepts: about 5000 cycles saved, and a signer that no longer follows main
  step for step.

## ADR-007: Nano S takes the table implementation of Poseidon

Date: 2026-11-26

### Context

After ADR-006 the Poseidon hash of the challenge is 63 % of a signature on
Nano S: 4369 Montgomery products and 515502 steps of the Grain generator. The
generator alone is 20 %. The rest goes to the dense matrix of every round, to
one conversion to Montgomery form per constant and per matrix coefficient,
and to the S-box of the partial rounds, which went through the generic
exponentiation: about 16 products for x^5.

The library has a Poseidon line that removes all of this: pull request 3 of
ZKNOX-LibC, then its v0.2.7 delivery (`src/zknox/DECISIONS.md`, ADR-001 and
ADR-002 there). Round constants are moved through the linear layer, so a
partial round adds one. Tables are in flash, in Montgomery form, in the limb
format of the multiplication. x^5 is three products. Partial rounds keep the
dense matrix (k = 0 sparse rounds).

### Decision

The submodule takes that implementation as delivered, for every target. It
replaces the low-RAM mixing layer of ADR-001: the new context holds no matrix,
so there is nothing left to vary. Two lines are added to it:
`POSEIDON_MAX_INPUTS` stays overridable, as since ADR-003, and the table of
partial round counts keeps its seven entries when the bound is lowered.

For `TARGET_NANOS` the Makefile defines `ZKN_POSEIDON_ARITIES=0x2A`: the BN254
tables for 1, 3 and 5 inputs, which are the arities the app hashes (0zk
address, signature). The Bandersnatch table for 5 inputs keeps its default.

### Consequences

- On the emulated Nano S image: 6391 Montgomery products per signature
  instead of 8018 and no generator, 135.5 M cycles instead of 213.9 M.
  Expected on the device: 6.2 s. Not measured yet.
- What a signature is made of now: Poseidon 42 %, the two fixed-base
  multiplications 41 %, the two inversions 16 %.
- Flash on Nano S: 12.2 KB more (48087 bytes of code in `MODE=prod`, 66519 in
  `MODE=debug FROST=1`). The four tables are 2432, 3328, 4608 and 4608 bytes.
- Stack on the emulated Nano S: the deepest production command is back at
  2296 bytes, margin 888 of 3184. With `FROST=1` the margin stays at 288.
- Same digests and signatures: the library's tests pass in the four
  combinations of `ZKN_LOW_RAM` and `ZKN_FIXEDBASE_FLASH_TABLE`, including
  the two Poseidon suites that come with the delivery, and the JavaScript and
  Rust suites pass on the emulated Nano S, the 0zk address and both blind
  signs included.
- The other targets change with the library, as they would on its own
  branch: on Nano S Plus the software-backend image grows by 26.6 KB with
  every table linked, and the cx image does not move. The Nano S port adds
  nothing to that: with the same delivery applied to upstream main, the Nano
  S Plus images are byte-identical with and without this branch, for both
  backends, in `MODE=prod FROST=0` and `MODE=debug FROST=1`. Defining the
  arity mask for the other targets as well would give 18 KB back.
- The second commit of pull request 3, on the Ed25519 cofactor, is not part
  of this.

### Alternatives considered

- Sparse matrices for the partial rounds of Poseidon-5, which the library
  generates on request. With all 60 rounds sparse a hash saves 1500 products,
  1.4 s on this device, for 20.4 KB of flash per field. Not taken here: the
  library's default is kept. It is the next step if flash is available.
- The round constants of pull request 3 alone. It removes the generator and
  keeps the conversions and the exponentiation.

## ADR-006: on Nano S the signer derives the public key itself, once

Date: 2026-11-26

### Context

A signature needs two fixed-base multiplications: R = [r]B, and A = [s]B,
which enters the challenge Poseidon(R, A, M). The app ran three, and five
inversions, 519 products each:

1. the handler calls `zkn_prv2pub` to build the `Pub` argument of
   `EddsaPoseidon_Sign_final`: one multiplication, one inversion;
2. `EddsaPoseidon_Sign_final` derives the public key again from the private
   key and refuses to sign if `Pub` differs: one multiplication and two
   inversions, the second on the caller's `Pub`, which is already affine.
   This check closes the "double public key" oracle: the nonce does not
   depend on `Pub`, the challenge does, so two signatures of one message
   under two different `Pub` give the private scalar;
3. R: one multiplication, then two inversions, because `tEdwards_normalize`
   is followed by `tEdwards_export`, which normalizes again.

In the three handlers that sign, `Pub` comes from the same private key a few
lines above: step 2 checks step 1.

### Decision

The low-RAM signer gains a second entry point,
`EddsaPoseidon_Sign(curve, prv, msg, len, out)`. It takes no public key: it
derives it from `prv`, once, and runs the same steps. With no `Pub` coming in
there is nothing to forge and nothing to compare. The header defines
`ZKN_HAVE_EDDSA_POSEIDON_SIGN` where the function exists (`ZKN_LOW_RAM` on the
software backend), and the three signing paths of `src/handler/handler_sign.c`
use it there. Elsewhere they are compiled as before.

In the same low-RAM code, R is no longer normalized before
`tEdwards_export`.

`EddsaPoseidon_Sign_final` keeps its signature and its check.

### Consequences

- Two fixed-base multiplications and two inversions per signature on Nano S.
  On the emulated image (`tools/nanos_cycle_profile.py`): 8018 Montgomery
  products instead of 10871, 213.9 M cycles instead of 274.2 M. Expected on
  the device: 9.8 s instead of 12.57 s. Not measured yet.
- Same signature, byte for byte: `tests/test_lowram_vectors.c` checks the new
  entry point against the vectors of the other one, on both curves, and its
  refusals (length, message not below p).
- The second derivation also caught, as a side effect, a fault injected in
  the first one. That is gone: a fault in the single derivation of A is not
  detected. A fault in R or in the hash was not detected before either.
- Stack: the deepest production command, the blind sign, peaks at 2300
  bytes instead of 2296 on the emulated device (margin 884 of 3184). With
  `FROST=1` the margin stays at 288.
- The standard implementation and the other targets are not touched: their
  flash images are byte-identical. They still run three multiplications and
  five inversions per signature, and the same change applies to them.
- The Poseidon hash is now 63 % of a signature on Nano S, the Grain generator
  alone 20 %. See ADR-007.

### Alternatives considered

- Keeping the derivation in the handler and dropping the check when the
  caller says its `Pub` is trusted. Rejected: it brings the oracle back
  behind a flag.
- Caching the public key across signatures, which would leave one
  multiplication. Rejected: a stale or corrupted cached key is exactly the
  oracle, and a check costs the multiplication it was meant to save.

## ADR-005: `BACKEND=cx` is refused on Nano S

Date: 2026-11-26

### Context

ADR-001 recorded that the cx backend builds for Nano S and that its static
worst case fits, and that it had never run: Speculos has no `cx_mont_*` for
this model. It has now run on a Nano S, firmware 2.1.0, `MODE=debug FROST=0`,
with `sign_with_privkey_matches_the_reference` of
`rs/crates/hw-tests/tests/sign.rs`: one SIGN_WITH_PRIVKEY (0x50) compared with
the circomlibjs signature.

| Backend | Time | Signature |
|---|---|---|
| `sw`, before ADR-004 | 28.33 s | equal to the reference |
| `cx` | 19.14 s | wrong |

With `cx`, R8 and S both differ from the reference. R8 is not a point of the
curve and the signature does not verify. S is not what the reference nonce and
key give with the returned R8 either, so the fault is not limited to the
commitment. What the device computed has not been identified.

### Decision

For `TARGET_NANOS` the Makefile stops with an error when `BACKEND` is not
`sw`, in every `MODE` and with or without `FROST`. It replaces the narrower
check of ADR-003 (`BACKEND=cx FROST=1`).

### Consequences

- One backend on Nano S, the one the emulator runs and the suites cover.
- A cx image loaded on a Nano S before this change signs wrongly and has to be
  replaced. Whether its wrong signatures tell anything about the key has not
  been established.
- The cause is open. Nothing changes on the other targets: their images are
  byte-identical.

### Alternatives considered

- Finding the fault on the device. Not done: without emulator support every
  probe is a sideload, and the gain is small. The cx build was 1.5 times
  faster than the C code it was compared with, less than what ADR-004 expects
  from the software backend.
- Keeping the build behind a switch. Rejected: an image that signs wrongly
  with a secret key should not come out of the Makefile.

## ADR-004: Nano S speed: Montgomery multiplication in Thumb-1 assembly, fixed-base table read from flash

Date: 2026-11-26

### Context

First run on a physical Nano S (firmware 2.1.0, `BACKEND=sw`,
`MODE=debug FROST=1`, the code as ADR-003 left it):

| Test (`rs/crates/hw-tests`) | Commands | Time |
|---|---|---|
| `sign_with_privkey_matches_the_reference` | one signature | 28.33 s, correct |
| `dkg_identity_is_separate_from_the_signing_key` | DKG_GET_COMM_PUBKEY, SIGNING_PUBKEY (one fixed-base multiplication) | 7.03 s |

Speculos runs at host speed and had shown nothing of this.

One signature is the public key followed by `EddsaPoseidon_Sign_final`: three
fixed-base multiplications, five inversions and one Poseidon hash of five
elements. Counted on the device image under emulation: 15152 Montgomery
products, 2728 of them per fixed-base multiplication, and 515502 steps of the
Grain LFSR that produces the Poseidon round constants.

Two costs stand out.

- The multiplication itself. ARMv6-M has no 32x32->64 multiply, so the
  compiler builds every limb product from `__aeabi_lmul`. One Montgomery
  product in C is 776 `MULS` and about 12230 cycles on a core with the
  single-cycle multiplier, 36290 with the 32-cycle one.
- The 2-window fixed-base multiplication of ADR-001: 128 doublings and 128
  additions, where the standard build has 64 and 64.

### Decision

1. `zkn_mul_mont_256` in Thumb-1 assembly
   (`src/zknox/src/zkn_mont/zkn_mont256_armv6m.S`). Same CIOS algorithm as the
   C version, same output for every input, reduced or not. Each 32x32 product
   is four 16x16 `MULS`, inline. No branch and no address depends on the data.
   The file enables itself when built for an ARMv6-M core;
   `ZKN_MONT256_NO_ASM` keeps the C version. The squaring goes through it.

   The C routine it replaces did not run in constant time on this core.
   `__aeabi_lmul`, which the compiler calls for every limb product, branches
   on a carry of its operands: under emulation the cycle count of one product
   moved between 12190 and 12408 over 154 pairs of BabyJubjub field elements.
   The assembly takes 4125 cycles for every input. On these cores
   `zkn_from_mont_256` goes through it too, as the product of its operand and
   1, which gives the same value as the C reduction for every input. No field
   operation calls `__aeabi_lmul` any more; the one call left in the image is
   in `format_u64`, a display helper.

2. `ZKN_FIXEDBASE_FLASH_TABLE`, defined for `TARGET_NANOS`. The fixed-base
   multiplication uses the four 64-bit windows and the 16-entry table of the
   standard build, and reads the table where the linker put it, in flash,
   with no randomized copy in RAM: 64 doublings and 64 mixed additions. On
   this target it replaces item 1 of ADR-001 and takes the alternative ADR-001
   had rejected.

   Kept from the two other versions: every step reads the 16 entries and keeps
   one under a mask, so control flow and addresses do not depend on the
   scalar; the accumulator is randomized before the first step and every 16
   steps.

   Given up: the per-entry projective randomization. The entry that comes out
   of the selection is one of 16 public constants, and its bytes go through
   the selection and into the addition as they are. A power or EM trace of
   the selection therefore relates to known values, where the two other
   versions only ever handle the entries multiplied by a secret random
   factor. The scalars concerned are the private key, at every public key
   derivation, and the nonce of every signature.

   The 2-window version stays in the library. Removing the define from
   `ZKN_NANOS_DEFINES` brings it back, at 2728 products per fixed-base
   multiplication instead of 1296.

3. Poseidon is not touched here. ADR-007 does it.

### Consequences

- One Montgomery product on an emulated Cortex-M0+
  (`src/zknox/tools/mont256_armv6m_check.py`):

  | | `MULS` | Cycles, 1-cycle multiplier | Cycles, 32-cycle multiplier | Stack |
  |---|---|---|---|---|
  | C, from the image before this change | 776 | 12230 on average | 36290 on average | 160 |
  | Assembly | 520 | 4125 | 20245 | 84 |

  The assembly is 1086 bytes. The same script compares it bit for bit with a
  transcription of the C algorithm: seven moduli, limit values, reduced and
  unreduced operands, result written over an operand.
- One signature: 10871 Montgomery products instead of 15152, 1296 per
  fixed-base multiplication instead of 2728.
- Measured on the device: one signature in 12.57 s instead of 28.33 s, the
  public key test in 2.76 s instead of 7.03 s.
- The core has the 32-cycle multiplier. `tools/nanos_cycle_profile.py` runs
  the whole signature handler of an image under emulation and counts its
  cycles: 615.0 M before, 274.2 M after, with `MULS` at 32 cycles and the
  Cortex-M0 timings. One clock, 21.8 MHz, gives both measured times within
  0.5 %. With `MULS` at one cycle the two would need clocks 11 % apart. Two
  thirds of the cycles of a signature are spent inside `MULS`.
- Where the 12.57 s go, from the same profile: the Poseidon hash 49 % (the
  Grain generator alone 16 %), the three fixed-base multiplications 30 %, the
  five inversions 20 %. ADR-006 removes one multiplication and three
  inversions.
- The public key test gained 0.4 s more than this profile accounts for. The
  calls to the random generator of the OS, 10 per fixed-base multiplication
  before and 4 after, are outside the profile; they have not been timed.
- Stack. Peak measured on the emulated Nano S (Speculos 0.25.5):

  | Command | `MODE=prod`, of 3184 | `MODE=debug FROST=1`, of 2904 |
  |---|---|---|
  | Blind sign | 2296 (was 2576) | 2296 (was 2576) |
  | Railgun address | 2264 (was 2592) | 2288 (was 2616) |
  | Signing public key | 1984 (was 2312) | 1992 (was 2320) |
  | FROST_HW_SIGN | | 2616 (unchanged) |

  The margin of the production image goes from 592 to 888 bytes. With
  `FROST=1` it stays at 288, set by FROST_HW_SIGN alone. The frame of
  `tEdwards_fixedBase_4MSM` goes from 1040 to 540 bytes.
- Flash: 1664 bytes more in `MODE=prod` (35991 bytes of code), 2176 more in
  `MODE=debug FROST=1` (54487). The two 16-entry tables are 2048 bytes.
- Results are unchanged. The library's host tests pass in the four
  combinations of `ZKN_LOW_RAM` and `ZKN_FIXEDBASE_FLASH_TABLE`. On the
  emulated Nano S, with the assembly running: the JavaScript suites, the Rust
  single-device suites, ceremonies 2-of-3 and 3-of-5 with the device in seats
  1, 3 and 5, and the production commands against circomlibjs.
- Flash images of the Nano S Plus target are byte-identical before and after,
  for both backends, in `MODE=prod FROST=0` and `MODE=debug FROST=1`.

### Alternatives considered

- The assembly alone, keeping the 2-window multiplication and its randomized
  table. 15152 products per signature instead of 10871. It is the fallback if
  the trade-off of item 2 is not wanted.
- Randomizing the entry after the selection. It costs about three products
  per step, and the selection still reads the constants.
- Splitting the scalar into two random shares. It doubles the number of
  fixed-base multiplications.
- A dedicated squaring. It would save about a fifth of the `MULS` of a
  squaring (36 limb products instead of 64 before the reduction). Left for
  after the device measurement.
- The cx backend. See ADR-005.

## ADR-003: threshold signing on Nano S keeps secrets in RAM and public state in NVRAM

Date: 2026-11-25

### Context

ADR-001 left the DKG and FROST signing out of the Nano S build for two
reasons. Measured on a build with the check removed:

- RAM. The ceremony state is 2120 bytes of statics (`g_dkg` 1536, `g_fs` 584).
  With the 1420 bytes of the rest of the app, 1064 bytes are left for a stack
  that needs up to 3950 (FROST_HW_SIGN).
- AES-GCM. The DKG transport and the share backup use `cx_aes_gcm_*`. The LNS
  cxng only has the AES block primitives.

### Decision

`FROST=1` is accepted on Nano S with `BACKEND=sw`. It stays opt-in, debug
builds included, and `MODE=prod FROST=1` stays an error on every target. Four
changes make it fit. The first two are in the app, the others in the library.

1. Ceremony state. Of the 2120 bytes, 1840 are public: the epoch, the
   ceremony name, the hash, the constant term and the transport key of each
   dealer, the compressed commitments that feed the digest, the digest, the
   group key, and the reassembled signing request (message and commitment
   list). The host sent them or will receive them. On Nano S they live in an
   NVRAM scratch area (`ZKN_CEREMONY_SCRATCH_NVM`,
   `src/handler/zkn_nv_scratch.h`). What stays in RAM, on every target: the
   state machine, the polynomial coefficients, the share accumulator, the key
   share and the FROST nonces. No secret is written to flash.

   The scratch area is not persistence. Every read is gated by the state
   machine, which is in RAM: after a restart the state is IDLE and what the
   area holds is unreachable. `DKG_ABORT`, a new `DKG_DEAL` and the failure
   paths clear it. The blocking item of `src/zkn_features.h`, the share that
   does not survive leaving the app, is untouched.

   The handlers reach these fields through macros (`DKG_NV`, `FS_NV`,
   `ZKN_NV_PUT`, `ZKN_NV_STAGE`, `ZKN_NV_DST`, `ZKN_NV_FLUSH`). On the other
   targets they expand to the member accesses and `memcpy` calls that were
   there before.

2. `ZKN_FROST_MAX_SIGNERS=3` and `POSEIDON_MAX_INPUTS=5` for this target: the
   app signs for a quorum of at most `DKG_MAX_T` and hashes at most five
   field elements. Both size stack buffers in the library.

3. AES-GCM over the block cipher (`ZKN_AES_GCM_OVER_CX_AES`). The library
   gains `zkn_gcm_ct`: GCM for a caller-supplied block function, with GHASH
   computed bit by bit under masks, no table and no branch on the data. On
   Nano S the block function is `cx_aes_enc_block`. Same arguments and limits
   as the syscall wrappers.

4. Low-RAM variants, under `ZKN_LOW_RAM`. On the software backend
   `zkn_compute_binding_factors`, `zkn_partial_sig` and `verifyFeldmanShare`
   run each step in its own non-inlined function and pass 32 or 64 bytes to
   the next one, as `EddsaPoseidon_Sign_final` does since ADR-001. The
   BLAKE-512 compression reads the message words from the block and calls G
   instead of inlining it eight times per round (frame 480 to about 250
   bytes). `zkn_bn_mod_mul` is two Montgomery products with the context built
   in place (depth 544 to 336 bytes).

### Consequences

- RAM on Nano S with `FROST=1`: 1700 bytes of statics, 2904 of stack, 1856 of
  NVRAM data. Without it nothing moves: 1420, 3184, and the production image
  measures as in ADR-001 (peak 2592, margin 592).
- Peak stack measured on the emulated Nano S (Speculos 0.25.5, `BACKEND=sw`,
  `MODE=debug FROST=1`), out of 2904 bytes:

  | Command | Peak |
  |---|---|
  | FROST_HW_SIGN | 2616 |
  | Railgun address | 2616 |
  | Blind sign | 2576 |
  | DKG_DEAL | 2568 |
  | DKG_PUT_SHARE | 2552 |
  | FROST_HW_COMMIT | 2336 |
  | Signing public key | 2320 |
  | DKG_FINALIZE | 2032 |
  | DKG_SET_COMMITS | 1976 |
  | DKG_GET_SHARE | 1720 |
  | DKG_EXPORT_SHARE | 1408 |
  | DKG_RESTORE_SHARE | 1168 |

  The margin is 288 bytes. It is set as much by the 0zk address, an existing
  command, as by the signature share: the 280 bytes of state that stay in RAM
  come out of the stack of every command. Measured and static figures agree
  to the byte on every DKG and FROST command.
- Run on the emulated device: the JavaScript suites (`dkg`, `frost-hw`,
  `sign`), the Rust single-device suites, and full ceremonies with the device
  as one participant among host simulators, 2-of-3 and 3-of-5, in several
  seats. The aggregate signature is verified by `frost-babyjubjub` under the
  circomlib equation. Binding factors, signature shares, coefficients,
  commitments and shares of the low-RAM variants equal those of the
  unmodified library byte for byte (`tests/test_lowram_vectors.c`).
- Flash images of the Nano S Plus target are byte-identical before and after,
  for both backends, in `MODE=prod FROST=0` and `MODE=debug FROST=1`.
- Flash writes. A ceremony clears then fills the DKG area (21 pages of 64
  bytes), a signature fills the request buffer (8 pages). Write time and wear
  have not been measured on a device.
- `BACKEND=cx FROST=1` is an error on Nano S. Its frames are not the ones
  measured here and Speculos cannot run it for this model. ADR-005 extends
  the refusal to every build of this target.
- Nothing here has run on a physical Nano S. First device run: ADR-004.

### Alternatives considered

- The whole state in NVRAM, secrets included. Rejected: coefficients and
  share would sit in flash across a power loss, and a wipe would become a
  flash operation that can fail.
- AES-GCM from the software AES of the library (`src/sw_crypto`). Rejected:
  it is table-based and host-only on purpose. The block cipher of the secure
  element is the one to use; only the mode was missing.
- Splitting the handlers into phases to shorten their frames. Rejected: it
  changes the code generated for the other targets.

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
   The randomized table in RAM shrinks from 1536 to 384 bytes. Replaced on
   Nano S by ADR-004, which reads the 16-entry table from flash.
2. The Poseidon mixing layer reads the MDS matrix from the const table, one
   entry at a time, instead of holding a Montgomery copy of it in the context
   (2048 bytes). Replaced by the table implementation of the library, which
   keeps no matrix in RAM on any target: ADR-007.
3. On the software backend, `EddsaPoseidon_Sign_final` runs each step in its
   own non-inlined function (key check, nonce hash, nonce reduction,
   commitment, challenge, response). Frames no longer stack up. The secret
   scalar is recomputed in the last step instead of being carried across the
   scalar multiplications.
4. The Thumb-2 Montgomery assembly is not assembled for ARMv6-M. The C
   versions are used.
5. `FROST=1` was refused for this target at that point: the DKG transport
   needs `cx_aes_gcm_*`, which the LNS cxng does not have, and with the
   ceremony state the statics grow to 3.5 KB. ADR-003 lifts this for
   `BACKEND=sw`.

### Consequences

- Peak stack measured on the emulated Nano S (Speculos 0.25.5, `BACKEND=sw`,
  `MODE=prod`), per command, out of 3184 bytes: Railgun address 2592, blind
  sign 2576, signing public key 2312, viewing public key 920, viewing private
  key 632. The margin is 592 bytes.
- Results are unchanged: public keys and signatures equal circomlibjs
  (`prv2pub`, `signPoseidon`) byte for byte, and the library's host tests pass
  with and without the switch.
- One signature costs 15154 Montgomery multiplications instead of 10846
  (+40%). Signing time on a real Nano S has not been measured. Measured
  since: ADR-004.
- Flash images of the Nano S Plus target are byte-identical before and after
  the change, for both backends.
- `BACKEND=cx` builds for Nano S and its static worst case fits (1892 bytes on
  the signing path), but it has not been run: Speculos does not emulate
  `cx_mont_*` for this model. Run since on a device, where it signs wrongly:
  ADR-005.

### Alternatives considered

- Selecting the table entry straight from flash and randomizing it afterwards,
  with no table in RAM. Rejected: the selection would then handle unmasked,
  known table constants. Taken up in ADR-004 for the speed, with that cost
  stated.
- Moving the large buffers to static storage. Rejected: statics and stack
  share the same 4608 bytes.
- A single randomization factor shared by all 16 entries, stored as (x, y)
  pairs. Rejected: still 1024 bytes, and weaker than one factor per entry.
