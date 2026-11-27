# Decisions

Architecture decisions for ZKNOX-HW-PRIVACY, newest first.

## ADR-012: one switch for the Nano S port, `ZKN_LOW_RAM`

Date: 2026-11-27

### Context

The Nano S port was a list in the Makefile. Under `TARGET_NANOS` it set
`ZKN_LOW_RAM` and seven more defines: `POSEIDON_MAX_INPUTS=5`,
`ZKN_POSEIDON_ARITIES=0x2A`, `ZKN_AES_GCM_OVER_CX_AES`,
`ZKN_CEREMONY_SCRATCH_NVM`, `ZKN_FROST_MAX_SIGNERS=3` and, with `BACKEND=sw`,
`ZKN_FIXEDBASE_FLASH_TABLE` and `ZKN_FIXEDBASE_SCALAR_BLINDING`. It repeated
them in `CFLAGS` and kept `ZKN_MONT256_ASM` for the other targets only. The
simulator had none of them.

The branch is to be merged into `main`. For that the port has to be one
switch, and a build without the switch has to be the build of before.

The defines are of three kinds:

- what little RAM asks of the library: the low-RAM variants and, with the
  software bignums, the flash table and the blinded scalar;
- what little RAM asks of the app: a Poseidon context for 5 inputs, a quorum
  of 3, the public ceremony state in NVRAM;
- what the chip or its SDK asks, whatever the RAM: GCM over the AES block,
  the work-arounds of the coprocessor, the Thumb-1 multiplication in place
  of the Thumb-2 assembly.

The arity mask is of none of them: it says which hashes the app computes,
and that is the same on every target.

### Decision

1. The Makefile sets `ZKN_LOW_RAM` on Nano S and no other code option for
   that target. `FROST ?= 0` there is a default of the build.
2. The library resolves its options in one header,
   `src/zknox/src/common/zkn_config.h`, which `zkn_bn.h` includes first. With
   `ZKN_LOW_RAM` and the software bignums it defines
   `ZKN_FIXEDBASE_FLASH_TABLE` and `ZKN_FIXEDBASE_SCALAR_BLINDING`. Both stay
   options of their own, with `ZKN_FIXEDBASE_NO_FLASH_TABLE` and
   `ZKN_FIXEDBASE_NO_SCALAR_BLINDING` to take them out (ZKNOX-LibC,
   DECISIONS.md, ADR-003).
3. The app states what it uses of the library in `src/zkn_app_config.h`. The
   Makefile names that file with `ZKN_CONFIG_FILE` and `zkn_config.h`
   includes it before the defaults of the library, so the sources of the app
   and those of the library read the same values. It holds the arity mask,
   for every target, and under `ZKN_LOW_RAM`: `POSEIDON_MAX_INPUTS` 5,
   `ZKN_FROST_MAX_SIGNERS` 3 and `ZKN_CEREMONY_SCRATCH_NVM`.
   `handler_frost_sign.c` does not compile if its `FS_MAX_SIGNERS` is above
   `ZKN_FROST_MAX_SIGNERS`.
4. What depends on the chip or on the SDK follows the target. In a device
   build `zkn_config.h` reads `bolos_target.h` and defines
   `ZKN_AES_GCM_OVER_CX_AES` for `TARGET_NANOS`. `zkn_bn.h` already set the
   two work-arounds of the coprocessor that way (ADR-011), and the Thumb-1
   multiplication already enabled itself on an ARMv6-M core (ADR-004).
   `zkn_mont256.c` now drops `ZKN_MONT256_ASM` on a core without Thumb-2, so
   the Makefile sets it for every target, as `main` does.
5. The arity mask applies to every target. The app hashes over BN254 with 1,
   3 and 5 inputs; the tables for 2, 4, 6 and 7 inputs are linked nowhere.
6. The simulator names the same file to the app sources it compiles and to
   the library it builds.

### Consequences

- Nano S: the five images are byte-identical to those of ADR-011, `sw` prod,
  `sw` debug with `FROST=0` and `FROST=1`, `cx` prod and `cx` debug with
  `FROST=1`. Nothing to run again on the device.
- `cx` images of the other targets: byte-identical. Nano S Plus prod and
  debug, Nano X, Stax and Flex prod.
- `sw` images of the other targets: 18432 bytes smaller, the four tables.
  Code and data, in bytes:

  | Image | Before | Now |
  |---|---|---|
  | Nano S Plus `sw` prod | 74847 | 56415 |
  | Nano S Plus `sw` debug, `FROST=1` | 89183 | 70751 |
  | Nano X `sw` prod | 74591 | 56159 |
  | Stax `sw` prod | 97991 | 79559 |
  | Flex `sw` prod | 98033 | 79601 |

  With the mask taken out of `src/zkn_app_config.h` the two Nano S Plus `sw`
  images are byte-identical to before: the mask is their only change.
- On those targets the library now refuses a Poseidon over BN254 with 2, 4,
  6 or 7 inputs. No command of the app computes one.
- Against `main`: the Nano S Plus `sw` prod image is 48223 bytes there. This
  branch was at 74847 and is at 56415.
- The library: its 40 objects are byte-identical to those of the options it
  replaces in five configurations, and its 29 test suites pass in six
  (ZKNOX-LibC, ADR-003).
- Checked with the simulator, built with the file of the app: its self-test
  in both modes and the 32 tests of the Rust suite.
- Checked on the emulated Nano S Plus, `sw` debug image with the mask: the
  Rust suites `dkg` and `frost_hw`, the three `sign` tests that need no
  screen, the three ceremonies with the emulated device as a participant,
  and two 0zk addresses equal to those of the image of before.
- Not run: a Nano S Plus device. Not built: Apex.
- The versioned binaries of `build/prod` and `build/dev` are not rebuilt by
  this change.

### Alternatives considered

- The list kept in the Makefile behind one make variable. It stays a list to
  keep in step in three build systems, and the simulator did not have it.
- The sizes of the app (5 inputs, quorum of 3) as defaults of the library
  under `ZKN_LOW_RAM`. They are numbers of this app; the tests of the library
  hash with 6 and 7 inputs in low-RAM mode.
- A configuration file found by name with `__has_include`. A missing include
  path would build the defaults without a word.
- The mask on Nano S only. The other targets would keep 18 KB of tables that
  no command reaches.

## ADR-011: the cx backend is allowed on Nano S: no aliased result, field elements compared as residues

Date: 2026-11-27

### Context

ADR-005 refused `BACKEND=cx` on Nano S because it signs wrongly on the
device, and left the cause open. It is found.

A debug image of the cx backend ran a ladder of fixed computations on a Nano
S, firmware 2.1.0, from the modular arithmetic up to a signature, and the
host compared each value with the reference. First run, BabyJubjub, eight
steps read:

- The Montgomery radix is 2^256, as the library assumes: `to_montgomery(1)`
  into another bignum returns 2^256 mod p.
- Modular arithmetic, and Montgomery arithmetic with distinct bignums, are
  right.
- The Montgomery form of 1 that the curve holds is wrong. The curve computes
  it in place, `cx_mont_to_montgomery(x, x, ctx)`, and the device returns the
  Montgomery form of `1 + J * 2^128`, where `J` is the top 128 bits of
  `2^384 mod p`.
- Every curve value after that is wrong, the base point included.

That value has one explanation. On this device a bignum is made of 128-bit
words (`CX_BN_WORD_ALIGNEMENT`) and the coprocessor multiplies word by word.
It reads the operand from the bignum it writes the result to: after the
first word, the high word it reads is the high word of its own intermediate
result, `z0 * R^2 * 2^-128 mod p`, where `z0` is the low word of the operand.
Converting into another bignum is right, converting in place is not.

The library converts in place wherever it turns a constant or an input into
Montgomery form: the curve constants (1, a, d), the Poseidon constants and
states, the points it randomizes. 74 calls in the eight steps read, 482 in a
signature.

A host model of `cx_bn`, exact but for this one behaviour, linked with the
cx code path of the library as Nano S builds it, returns the 19 wrong values
the device returned in those steps, byte for byte, and the reference where
the device returned it. Exact, the same model returns the reference at every
step and passes the Rust suite, ceremonies included: the cx code path of the
library is right, the fault is in what the device does with an aliased
result.

The second run asked the device about each primitive, called with the result
bignum as an operand and compared with the same call into another bignum:

| Wrong with an aliased result | Right with an aliased result |
|---|---|
| `cx_mont_to_montgomery(x, x)` | `cx_mont_invert_nprime`, r == a |
| `cx_mont_from_montgomery(x, x)` | `cx_bn_mod_add`, r == a, r == b |
| `cx_mont_mul`, r == a, r == b, r == a == b | `cx_bn_mod_sub`, r == a, r == b |
| `cx_mont_pow`, r == a | `cx_bn_mod_invert_nprime`, r == a |
| `cx_bn_mod_mul`, r == a, r == b | |
| `cx_bn_reduce(r, r)` | |

Same answers for both fields. Every multiplication and the reduction are
wrong, the additions and the inversions are right.

Nano S Plus does not have it: its cx image makes the same conversions in
place and is reported to sign correctly on the device. The other models have
not been looked at for this.

### Decision

With the cx backend on Nano S, the six primitives of the left column go
through `src/zknox/src/bn/zkn_bn_ledger.c`. When the result bignum is also an
operand, the syscall writes into a fresh bignum, which is copied to the
result and released. Every other call goes straight to the syscall.

The switch is `ZKN_CX_NO_ALIAS` in `src/zknox/src/bn/zkn_bn.h`, set when
`TARGET_NANOS` is defined. Other targets keep the direct mapping, and can be
given the switch from their build if one of them shows the fault.

The device has a second fault, measured in the third run below: a Montgomery
product comes back in `[0, 2p)`. Code that compares two field elements, or a
field element with a small constant, now calls `zkn_bn_cmp_mod` and
`zkn_bn_cmp_u32_mod` (`zkn_bn.h`), which take the modulus. With the cx
backend on Nano S (`ZKN_CX_UNREDUCED`, set when `TARGET_NANOS` is defined)
they reduce their operands into fresh bignums and compare those. Everywhere
else they are `zkn_bn_cmp` and `zkn_bn_cmp_u32`. Three places use them: the
curve equation, the neutral point, and the public key the signer derives
again.

`BACKEND=cx` is allowed again on Nano S, as on the other targets: the
refusal of ADR-005 is lifted, and with it the one ADR-003 had for
`BACKEND=cx FROST=1`. `BACKEND=sw` stays the default. It is the faster one
there, 3.9 s per signature against 21.3 s, and the only one with the
fixed-base table read from flash and the blinded key scalar (ADR-004,
ADR-010): the Makefile defines those two for `BACKEND=sw` only, and the cx
build keeps the fixed-base multiplication of `ZKN_LOW_RAM`, two windows over
a randomized table in RAM.

### On the device

Second run, with the guard on the Montgomery primitives. Through the names
the library uses, every Montgomery call with an aliased result came back
right. BabyJubjub: the twelve steps are right, the signature included.
Bandersnatch: eleven steps are right, and the signature was refused, with
`ZKN_ERR_INVALID_PARAM`. The device holds 64 bignums of 32 bytes; a
signature needs 54.

Third run, with the six guards. Through the names the library uses, the
fifteen aliased calls are right, `cx_bn_mod_mul` and `cx_bn_reduce`
included. BabyJubjub: three signatures of three are right, 20.6 s each.
Bandersnatch: three of three are refused, after 7.7 s each.

The refusal is a second fault of the device, and that run identified it:
the coprocessor does not reduce a Montgomery product below p. Four squares
were chosen so that the value before the last conditional subtraction is at
least p; for the four, on both fields, the device returned the expected
value plus p. A value modulo p then exists as two bignums.

The standard signer derives the public key again and compares it, as
bignums in Montgomery form, with the one it was given. That comparison is
what fails. The model given unreduced products does the same thing: the
Bandersnatch signature is refused at the same call with the same code, every
other step is right and no value is wrong.

BabyJubjub is not spared, its test key is. A product of two values below p
is below `p (1 + p / 2^256)` before the last subtraction, so a coordinate
can come back as its value plus p only when its Montgomery form is below
`p^2 / 2^256`: 0.19 p for the BabyJubjub field, 0.45 p for the Bandersnatch
field. The public key of the ladder has its coordinates at 0.46 p and 0.82 p
on BabyJubjub, never refused, and at 0.08 p and 0.05 p on Bandersnatch,
refused four times of four. A third of the BabyJubjub keys have a
coordinate under the threshold, and 70 % of the Bandersnatch keys. On the
model, with keys drawn at random and three signatures per key, 6 BabyJubjub
keys of 40 are refused at least once, and 16 Bandersnatch keys of 40.

With the comparisons of residues, the model signs every time: 240
signatures over 40 random keys per curve, the ladder, and the Rust suite,
with unreduced products alone and with additions and subtractions that
correct by one modulus only.

Fourth run, with the comparisons of residues. Every step is right on both
curves, and so are the eight signatures asked: two per curve with the key
of the ladder, and one for each of two more keys per curve, chosen among
those the model refused most. 21.3 s each. The same run read, for ten
primitives, how many of eight results on operands just below p come back at
or above p: `cx_mont_mul` 1 on the BabyJubjub field and 4 on the
Bandersnatch field, which are the counts of a product without its last
subtraction, and none for the nine others (the conversions, `cx_mont_pow`,
the inversions, `cx_bn_mod_mul`, `cx_bn_mod_add`, `cx_bn_mod_sub`,
`cx_bn_reduce`).

The library also hands those products to `cx_bn_mod_add` and
`cx_bn_mod_sub`, which the SDK specifies for operands strictly below the
modulus; every value read on the device was right nonetheless.

A bignum syscall takes about 0.7 ms on this device: 87 s for the 126 000 of
the second run, and a signature is 25 700 of them, which is the 19.14 s of
ADR-005. A signature took 20.6 s with the six guards and 21.3 s in the
fourth run.

### The cx build on Nano S

| | `MODE=prod` | `MODE=debug FROST=1` |
|---|---|---|
| Code | 36887 bytes | 54423 bytes |
| Statics | 1420 bytes | 1700 bytes |
| Stack | 3184 bytes | 2904 bytes |
| Deepest command, static worst case | 1952 bytes | 2000 bytes |

The bignums are in the pool of the coprocessor, 64 of 32 bytes. On the model
a signature has 54 alive at its deepest point and a threshold ceremony 57:
with a pool of 56 the ceremony fails.

What has run with it on a device: the self-test, that is the curve
arithmetic, the hashes and eight signatures through SIGN_WITH_PRIVKEY, and
then the four device suites of `rs/` (`sign`, `dkg`, `frost_hw`, `ceremony`)
on a debug image with `FROST=1`, which passed. The same commands pass on the
host model given the faults and the pool of the device, the Rust suite and
the ceremonies with the model in seats 1, 3 and 5. The stack figures are
static: no emulator runs this build.

### Consequences

- Images: the six that the Makefile built before are byte-identical, Nano S
  `sw` (production, and debug with `FROST=1`) and Nano S Plus `sw` and `cx`
  (same two modes). The work-arounds are 570 bytes of a Nano S cx image.
- On the host model with the nine faults of the table, the cx code path
  returns the reference at every step of the ladder and passes the Rust
  suite, 33 tests, ceremonies included. The device agrees on every step it
  ran, the Bandersnatch signature apart.
- An aliased call costs four more syscalls and one more live bignum. A
  signature makes 595 of them (482 conversions in, 5 out, 48 products, 60
  powers).
- ADR-005 left open whether the wrong signatures tell anything about the
  key. They can. The faulty image hashes the key and reduces the nonce
  correctly, so for one message it uses the nonce a correct image uses, with
  another challenge, because the public key, the commitment and the Poseidon
  constants are wrong. Two signatures of one message, one from each image,
  give the private scalar: `s = (S - S') / (h - h') mod l`. Checked on the
  model. The faulty challenge `h'` follows from the faulty signature, the
  public key that image exports and the fault, which is deterministic. A key
  that signed with a cx image on Nano S and with any correct image should be
  considered exposed. The runs recorded in ADR-005 used the fixed key of the
  test vector.
- A new comparison of field elements has to go through `zkn_bn_cmp_mod`.
  `zkn_bn_cmp` on such values is right on every backend but this one.

### Alternatives considered

- Fixing the call sites: 20 conversions in place in the library, and the
  next one written would bring the fault back.
- Guarding `cx_mont_invert_nprime` as well, as the first version did. The
  device computes it correctly with an aliased result and the library never
  calls it that way.
- Guarding every target. Rejected: the Nano S Plus images would change for
  nothing, and no other model is known to have the fault.
- Reducing every Montgomery product, so that `zkn_bn_cmp` stays right.
  Three more syscalls per product at least, the reduction in place being
  one of the wrong calls: 36 000 more per signature, 25 s.

## ADR-010: on Nano S the private scalar is blinded in the public key derivation

Date: 2026-11-27

### Context

Since ADR-004 the fixed-base multiplication of Nano S reads its table from
flash. The point being built is randomized, the table is not: the entry
selected at each step is a known constant, and its bytes go through the
selection and the first products of the addition unmasked. The other devices
randomize every entry, in 1.5 KB of RAM that this one does not have.

Since ADR-006 the signer derives the public key itself, `A = [s]B`, at every
signature. `s` never changes, so the same 64 entries are selected in the
same order every time: whatever a trace exposes about them can be averaged
over as many signatures as an attacker collects. The other fixed-base
scalars are not in that position. The FROST nonces and the DKG coefficients
are used once, and the EdDSA nonce changes with the message.

### Decision

`zkn_prv2pub` multiplies the base point by `s + lambda * l`, where `l` is
the order of the base point and `lambda` is 32 random bits drawn at each
call. The result is the same point.

- The blinded scalar has up to 288 bits. The comb keeps its four windows,
  72 bits each instead of 64: 72 steps, and a second pair of 16-entry tables
  per curve whose points are 2^72 apart.
- The tables come from `tools/gen_fixedbase_tables.py`. The 64-bit tables of
  the library were committed without their generator; the script rebuilds
  them first, with curve arithmetic of its own, and stops if they differ
  from the committed bytes.
- `s + lambda * l` is computed on 16-bit digits, so that each product fits
  32 bits and is one `MULS`. A 64-bit product would call `__aeabi_lmul`,
  which is not constant time on this core (ADR-004).
- Only the key derivation takes this path. The nonce multiplications keep
  their 64 steps.

`ZKN_FIXEDBASE_SCALAR_BLINDING` selects it; the Makefile defines it for
`TARGET_NANOS`. It needs the flash table and the software bignums.

### Consequences

- Same keys and signatures. `tests/test_fixedbase_blind.c` compares the
  blinded multiplication with the plain one on 597 products per curve; the
  library's tests pass in six configurations, the two with the blinding
  among them; the JavaScript and Rust suites, the ceremonies and the
  production commands pass on the emulated Nano S.
- One signature: 6555 Montgomery products instead of 6391, 83.6 M cycles
  instead of 81.5 M, 3.8 s expected on the device, 3.7 s on Bandersnatch.
  Measured since: 3.9 s. Ten calls to the random generator instead of eight.
- Flash: 2432 bytes more, 2048 of them tables: 52567 bytes of code in
  `MODE=prod`, 70935 in `MODE=debug FROST=1`. The stack peaks measured on
  the emulated device do not move: 2296 of 3184 in production, 2616 of 2904
  with `FROST=1`.
- Two signatures select the same sequence of entries when they draw the same
  `lambda`: once in 2^32.
- What it does not do. A single trace still carries its own scalar: whoever
  reads the 288 selections of one multiplication has `s + lambda * l`, and
  its remainder modulo `l` is `s`. And the EdDSA nonce is not blinded: it is
  the same for the same message, so signing one message many times repeats
  one sequence of entries in the nonce multiplication.
- The other targets do not define the switch, and the tables they do not
  use are dropped at link time: the Nano S Plus flash images are the same
  bytes with and without this branch, for both backends, in
  `MODE=prod FROST=0` and `MODE=debug FROST=1`.

### Alternatives considered

- 64 random bits: 80 steps, about 0.2 s per multiplication instead of 0.1 s.
  32 bits already make a repeated sequence a one in 2^32 event.
- Blinding the nonce multiplication too, through the same entry point:
  0.1 s more per signature. Left out: the case it covers is one message
  signed many times.
- Splitting the scalar into two random halves and multiplying twice: twice
  the cost of the multiplication.
- A randomized copy of the table in RAM, as on the other devices: ADR-004.

## ADR-009: on Nano S the multiplication has a path for the two curve fields

Date: 2026-11-27

### Context

After ADR-007 a signature is 6391 Montgomery products and they are 95.5 % of
its cycles. A product is 520 `MULS`. The secure element of the Nano S has the
iterative multiplier of this core, 32 cycles per `MULS`, so 82 % of a product
is spent inside `MULS`, and one `MULS` costs as much as 32 additions or
shifts.

Two things follow. A 32-bit product from three `MULS` and a dozen more
instructions is cheaper than one from four. And in the reduction one operand
of every product is a limb of the modulus, a constant: it can be multiplied
with no `MULS` at all.

The multiplication takes its modulus as an argument. The app calls it with
four: the base fields of the two curves, where the points and Poseidon live,
and the two subgroup orders, for a few products per signature.

### Decision

`zkn_mul_mont_256` tests its modulus, which is public: `n0` first, then the
limbs. For BN254 r and BLS12-381 r it takes a path written for this
multiplier. Any other modulus takes the former code, unchanged.

In the field path:

- `m * p[j]` is a fixed sequence of shifts, additions and subtractions, read
  off the non-adjacent form of `p[j]`: four instructions per digit, on a
  64-bit accumulator. `m = t[0] * n0` goes the same way. The sequences are
  generated from the modulus by `tools/gen_mont256_armv6m.py` into
  `zkn_mont256_armv6m_fields.inc`, which is committed; `--check` tells
  whether the file still matches its generator.
- `a[j] * b[i]` takes three `MULS`: the two halves, and
  `|xl - xh| * |yh - yl|` with its sign applied as a mask, from which the
  middle term comes. The form with sums of halves does not fit: 17 bits by
  17 overflow the 32 bits `MULS` returns.

The subgroup orders stay out of this path on purpose. The sign of the middle
term is a word of zeros or of ones that depends on the operands, and the
scalars reduced modulo an order (the secret scalar and the nonce in
`S = r + h s`, the shares) are not randomized.

Two switches: `ZKN_MONT256_NO_FIELD_PATHS` leaves the path out, for a core
with a single-cycle multiplier, where it is slower than the other one.
`ZKN_MONT256_FIELD_NO_KARATSUBA` keeps the path with four `MULS` per product
and no sign.

### Consequences

- Per product, 32-cycle multiplier, under emulation: 192 `MULS` and 11766
  cycles for BN254 r, 11267 for BLS12-381 r, against 520 and 20245. The other
  moduli: 20261, the 16 more being the test on the modulus.
- One signature on the emulated Nano S image: 81.4 M cycles instead of
  135.5 M, 3.7 s expected on the device; 78.2 M and 3.6 s on Bandersnatch.
  Not measured yet. The share of the multiplication goes from 95.5 % to
  92.6 %.
- Same output for every input: the emulated routine is compared with the
  algorithm of the C version on 8316 products over eleven moduli, reduced or
  not, with operands whose halves are equal or ordered both ways, and with
  four moduli one limb or one `n0` away from a field, which must go back to
  the other path. The routine linked in the production image gives the same
  results.
- Each modulus takes the same number of cycles for every input; the check
  script fails otherwise.
- Flash: 2048 bytes more, 50135 bytes of code in `MODE=prod` and 68503 in
  `MODE=debug FROST=1`. Stack: the frame of the multiplication goes from 84
  to 88 bytes; the peaks measured on the emulated device do not move (2296
  of 3184 in production, 2616 of 2904 with `FROST=1`).
- What the sign exposes. In the scalar multiplications the operands are
  coordinates, randomized as ADR-004 describes. In the challenge of a
  signature they are public. One computation puts a secret through this
  path without randomization: Poseidon of the viewing private key, when the
  0zk address is derived. That key is the one the app exports to the host on
  request. `ZKN_MONT256_FIELD_NO_KARATSUBA` removes the sign for 0.4 s per
  signature: 13134 cycles per product, 4.1 s expected.
- The other targets do not compile this file: it is an empty object outside
  Thumb-1.

### Alternatives considered

- Chains on the 16-bit halves of each limb, four per product, recombined as
  the four `MULS` were. Same number of digits, and the recombination stays:
  about 10 cycles more per product of the reduction.
- The same path for every modulus, with the chains replaced by `MULS`. It
  would put the unrandomized scalars through the signed middle term for a
  few products per signature.
- Karatsuba above the limbs, on halves of the operands, with the product
  and the reduction separated: 48, 36 or 27 limb products instead of 64 in
  `a * b` depending on the depth, about 32 more bytes of stack. Not done
  here. It is the next step on the multiplication if 3.7 s is not enough.
- A squaring of its own. It saves part of `a * a` only, and squarings are a
  minority of the products of a signature.

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
  Expected on the device: 6.2 s. Measured since: two signatures, one per
  curve, in 12.37 s.
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

Superseded by ADR-011, which found the cause and lifts the refusal.

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
