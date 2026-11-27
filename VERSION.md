# Changelog

## Unreleased

Date: 2026-11-27

### Private scalar blinded in the public key derivation

- On Nano S `zkn_prv2pub` multiplies the base point by `s + lambda * l`:
  the private scalar plus a multiple of the subgroup order, `lambda` being
  32 random bits drawn at each call. The public key is the same point. The
  entries read from the flash table, which cannot be randomized on this
  device, are no longer the same sequence at every signature. See
  [DECISIONS.md](DECISIONS.md), ADR-010.
- The scalar has up to 288 bits: 72 steps instead of 64, over a second pair
  of tables per curve, with the points 2^72 apart.
- Only the key derivation. The nonce multiplications keep their 64 steps.
- One signature on the emulated Nano S image: 6555 Montgomery products
  instead of 6391, 83.6 M cycles instead of 81.5 M, 3.8 s expected on the
  device (3.7 s on Bandersnatch). Ten calls to the random generator instead
  of eight. Same signatures, byte for byte.
- Flash: 2432 bytes more, 2048 of them tables (52567 bytes of code in
  `MODE=prod`, 70935 in `MODE=debug FROST=1`). The stack peaks of the
  commands do not move (margins 888 and 288).
- It does not protect a single trace: whoever reads the 288 selections of
  one multiplication has `s + lambda * l`, and its remainder modulo `l` is
  `s`.

### Multiplication for the two curve fields

- On Nano S the Montgomery multiplication has a path of its own for BN254 r
  and BLS12-381 r, the base fields of BabyJubjub and Bandersnatch, where
  nearly all the products of a signature are. The chip multiplies in 32
  cycles and shifts or adds in one, and this path is written for that. See
  [DECISIONS.md](DECISIONS.md), ADR-009.
- The reduction has no `MULS` left: each product by a limb of the modulus is
  a fixed sequence of shifts, additions and subtractions, generated from the
  modulus. `a * b[i]` takes three `MULS` per 32-bit product instead of four.
  192 `MULS` per product instead of 520.
- Cycles per product under emulation, 32-cycle multiplier: 11766 for BN254 r
  and 11267 for BLS12-381 r, against 20245. Every other modulus keeps the
  former code, at 20261 with the test that tells the fields apart.
- One signature on the emulated Nano S image: 81.4 M cycles instead of
  135.5 M, 3.7 s expected on the device. On Bandersnatch: 78.2 M, 3.6 s.
  Same signatures, byte for byte.
- Flash: 2048 bytes more (50135 bytes of code in `MODE=prod`, 68503 in
  `MODE=debug FROST=1`). Stack: 4 bytes more in the multiplication, and the
  peaks of the commands do not move (margins 888 and 288).
- Each modulus takes the same number of cycles for every input, checked on
  8316 products. The new path computes one more value that depends on the
  operands, the sign of a middle term; ADR-009 says where that matters and
  which switch removes it (`ZKN_MONT256_FIELD_NO_KARATSUBA`, 4.1 s).
- The 6.2 s of the previous step are now measured: two signatures, one per
  curve, in 12.37 s on the device.

### Bandersnatch signatures

- The EdDSA signer reduced `r` and `S` modulo the BabyJubjub subgroup order
  on every curve. On Bandersnatch the signature it returned did not satisfy
  `[S]B = R + [8h]A`. ZKNOX-LibC corrected its signer on main (pull request
  4, merged as `d1a0da6`). The submodule takes that change, and the low-RAM
  signer that Nano S runs gets the same one: the order is read from the
  curve. See [DECISIONS.md](DECISIONS.md), ADR-008.
- Bandersnatch signatures change on every target. BabyJubjub signatures are
  the same bytes as before.
- On the emulated Nano S, production image: `BLIND_SIGN` on Bandersnatch
  returns the signature of the library's main for the same key and message,
  and it satisfies the equation under curve arithmetic written apart from
  the library. Same check on BabyJubjub.
- Cost on Nano S: none that shows. Same code size (48087 bytes in
  `MODE=prod`, 66519 in `MODE=debug FROST=1`), same stack peaks (margins 888
  and 288), 6391 Montgomery products per signature, about 5000 cycles more
  out of 135 M.
- `rs/`, 0.5.4: `sign_with_privkey_on_bandersnatch_matches_the_reference`,
  one signature on Bandersnatch against a fixed vector. It fails on the
  image of the previous delivery and passes on this one.
- Comments brought up to date: the Makefile said that Nano S takes the C
  multiplication and a Poseidon matrix read from flash, and
  `run-rs-device-tests.sh` that nothing is written to flash.

### Nano S on the device

First runs on a physical Nano S, firmware 2.1.0, and what they changed. See
[DECISIONS.md](DECISIONS.md), ADR-004 to ADR-007.

| | One signature | Public key test |
|---|---|---|
| C code of the first port | 28.33 s | 7.03 s |
| Assembly multiplication, table read from flash (ADR-004) | 12.57 s | 2.76 s |
| Public key derived once by the signer (ADR-006) | 9.8 s expected | unchanged |
| Poseidon from tables (ADR-007) | 6.2 s | unchanged |
| Multiplication path of the curve fields (ADR-009) | 3.7 s expected | 1.7 s expected |
| Private scalar blinded in the key derivation (ADR-010) | 3.8 s expected | 1.8 s expected |

- `BACKEND=cx` returns a wrong signature on the device, in 19.14 s. The
  Makefile now refuses it for `TARGET_NANOS`, in every `MODE`.
- The 256-bit Montgomery multiplication is in Thumb-1 assembly on this
  target: 520 `MULS` and 4125 cycles per product under emulation, against 776
  and about 12230 for the C code (20245 against 36290 on a core with the
  32-cycle multiplier, which is what the Nano S has).
- The C multiplication was not constant time on this core: `__aeabi_lmul`,
  called for every limb product, branches on a carry of its operands. The
  assembly takes the same number of cycles for every input, and the
  conversion out of Montgomery form goes through it as well.
- `ZKN_FIXEDBASE_FLASH_TABLE` is defined for `TARGET_NANOS`: the fixed-base
  multiplication runs its 64 steps over the 16-entry table read from flash,
  with no randomized copy of the table in RAM. ADR-004 states what this gives
  up on side channels and how to go back.
- On this target the three signing paths call `EddsaPoseidon_Sign`, which
  derives the public key itself, once: two fixed-base multiplications and two
  inversions per signature instead of three and five. ADR-006 states what
  goes with the second derivation.
- Poseidon is the table implementation of ZKNOX-LibC (pull request 3 and
  its v0.2.7 delivery): no Grain generator at run time, constants in
  Montgomery form in flash, x^5 in three products. `ZKN_POSEIDON_ARITIES=0x2A`
  for `TARGET_NANOS` links the three BN254 tables the app uses. 12.2 KB of
  flash more on Nano S. This part changes the other targets too: on Nano S
  Plus the software-backend image grows by 26.6 KB with every table linked.
- Montgomery products per signature: 15152, then 10871, then 8018, then 6391.
- `tools/nanos_cycle_profile.py`: runs the signature handler of a Nano S
  image in an ARMv6-M emulator, checks the signature and counts cycles per
  function. It is where the figures above and the 9.8 s come from.
- Stack margin of the production image: 888 bytes instead of 592. With
  `FROST=1` it stays at 288.

### Added

- Nano S target (LNS SDK, `BOLOS_SDK=$NANOS_SDK`). Production commands:
  signing public key, viewing public key, viewing private key, 0zk address,
  blind sign on BabyJubjub and Bandersnatch.
- Threshold signing on Nano S: `make BOLOS_SDK=$NANOS_SDK MODE=debug FROST=1`,
  `BACKEND=sw` only. DKG (0x60 to 0x6b) and FROST signing (0x70 to 0x72), up
  to 3-of-5, same wire format as the other devices. See
  [DECISIONS.md](DECISIONS.md), ADR-003.
- `ZKN_LOW_RAM` switch, set by the Makefile for `TARGET_NANOS`. See ADR-001.
- `src/handler/zkn_nv_scratch.h`: where the public bulk of the ceremony state
  lives. RAM on every target except Nano S, where it is an NVRAM scratch
  area.
- `icons/app_zknox_16px.gif`: Nano S dashboard icon. Placeholder, the 14 px
  icon on a 16 px canvas.
- `tools/stackdepth.py`, `tools/nanos_stack_hwm.py`: static and measured stack
  use on Nano S.
- `tools/speculos_sim_bridge.py`: lets a Speculos instance take a seat that
  expects the host simulator, so the Rust suite can drive an emulated device,
  alone or as one participant of a ceremony, with the stack measured per
  command.

### Changed

- Makefile, for `TARGET_NANOS`: `ICON_NANOS`; `ZKN_MONT256_ASM` left out;
  `ZKN_LOW_RAM`, `POSEIDON_MAX_INPUTS=5`, `ZKN_POSEIDON_ARITIES=0x2A`,
  `ZKN_AES_GCM_OVER_CX_AES`,
  `ZKN_FIXEDBASE_FLASH_TABLE`, `ZKN_CEREMONY_SCRATCH_NVM` and
  `ZKN_FROST_MAX_SIGNERS=3` defined. `FROST` defaults to 0 on that target,
  debug included, and `BACKEND=cx` is an error there.
- `src/handler/handler_dkg.c`, `src/handler/handler_frost_sign.c`: accesses to
  the commitments, their hashes, the transport public keys, the digest, the
  group key and the reassembled signing request go through the macros of
  `zkn_nv_scratch.h`. On every target except Nano S they expand to the
  statements that were there before.
- Nano S review screens for the public key export, the 0zk address and the
  blind sign go through `nbgl_useCaseReview`. See ADR-002.

### ZKNOX-LibC (submodule `src/zknox`)

These changes belong to the library repository and need their own commit
there, followed by a submodule bump here.

Under `ZKN_LOW_RAM`:

- `src/ecc/zkn_tEdwards.c`: constant-time 2-window fixed-base multiplication.
- `src/ecc/zkn_eddsa.c`: phased `EddsaPoseidon_Sign_final` (software backend).
- `src/ecc/zkn_frost.c`: phased `zkn_compute_binding_factors` and
  `zkn_partial_sig` (software backend).
- `src/ecc/zkn_vss.c`: phased `verifyFeldmanShare` (software backend).
- `src/hash/zkn_blake512.c`: compression function with the message words read
  from the block and G out of line.
- `src/bn/zkn_bn_sw.c`: `zkn_bn_mod_mul` as two Montgomery products.
- `src/ecc/zkn_frost.h`: `ZKN_FROST_MAX_SIGNERS` defaults to 5 instead of 16.

Independent of it:

- `src/aes/zkn_gcm_ct.{c,h}`: GCM over a caller-supplied block cipher, with a
  constant-time GHASH. `src/aes/zkn_aes_gcm.c` uses it with `cx_aes_enc_block`
  under `ZKN_AES_GCM_OVER_CX_AES`, for SDKs without `cx_aes_gcm_*`.
- Poseidon is the table implementation of the library's Poseidon line
  (pull request 3, then its v0.2.7 delivery; `src/zknox/DECISIONS.md`):
  `src/zkn_mont/zkn_poseidon_soft.{c,h}`,
  `src/zkn_mont/zkn_poseidon_opt_tables.{c,h}`, `tools/gen_poseidon_opt.py`,
  `tests/test_poseidon_opt.c`, `tests/test_poseidon_arities.c`,
  `tests/poseidon_cli.c`, `js/poseidon_diff.mjs`, `make/modules.mk`,
  `make/tests.mk`, `tests/README.md`, `STATUS.md`. It replaces the low-RAM
  mixing layer of the first port. Two lines differ from that delivery:
  `POSEIDON_MAX_INPUTS` can be lowered at build time (it sizes the hash
  context), and the table of partial round counts keeps its seven entries
  when it is.
- `src/ecc/zkn_eddsa.c`: both signers take the subgroup order from
  `curve->order` instead of the BabyJubjub constant. The standard signer is
  the one of the library's main after pull request 4, line for line. The
  low-RAM signer computes `2^256 mod l` the same way and carries the bytes
  of `l` across the challenge in scratch it already had.
- `tests/test_security_regressions.c`: as on main, signatures of both curves
  are verified, `[S]B = R + [8h]A` written out.
- `tests/test_lowram_vectors.c`: the two Bandersnatch signatures are replaced
  by those of the corrected library.
- `src/ecc/zkn_tEdwards.{c,h}`, where the fixed-base multiplication reads its
  table from flash: `tEdwards_fixedBase_4MSM_blind`, the same point through
  a scalar blinded with a random multiple of the order, and
  `tEdwards_fixedBase_4MSM_masked`, the same with the multiple given by the
  caller (`ZKN_HAVE_FIXEDBASE_BLIND`). The loop over the table takes the
  size of its windows, 8 or 9 bytes.
- `src/ecc/zkn_fixedbase72_tables.{c,h}`: the tables with 72-bit windows for
  the two curves, generated. `tools/gen_fixedbase_tables.py` writes them
  after rebuilding the 64-bit tables the library already had and comparing
  them with `bbjj_precomp.c` and `bandersnatch_precomp.c`; `--check`
  compares with the files on disk.
- `src/ecc/zkn_eddsa.c`: `zkn_prv2pub` goes through the blinded
  multiplication under `ZKN_FIXEDBASE_SCALAR_BLINDING`.
- `Makefile`, `make/modules.mk`: `ZKN_FIXEDBASE_SCALAR_BLINDING=1` for host
  builds, the table file in the curve sources.
- `tests/test_fixedbase_blind.c`: the blinded multiplication against the
  plain one, 597 products per curve: scalars on the edges of the windows of
  both layouts and around the order, multiples on the edges of their digits,
  then `zkn_prv2pub`.
- `src/zkn_mont/zkn_mont256_armv6m.S`: second path for the two curve fields,
  chosen on the modulus: three `MULS` per product in `a * b[i]`, reduction by
  shifts and additions. `ZKN_MONT256_NO_FIELD_PATHS` leaves it out,
  `ZKN_MONT256_FIELD_NO_KARATSUBA` keeps four `MULS` per product in it.
- `src/zkn_mont/zkn_mont256_armv6m_fields.inc`: the reduction rows of the two
  fields, generated. `tools/gen_mont256_armv6m.py` writes it, and with
  `--check` compares it with the file on disk.
- `tools/mont256_armv6m_check.py`: cycles, `MULS` and stack per modulus, an
  error when a modulus does not take the same number of cycles for every
  input, operands whose 16-bit halves are equal or ordered both ways, and
  four moduli that differ from a field by one limb or share its `n0`.
- `src/zkn_mont/zkn_mont256_arm32.S`: empty object on Thumb-1 cores.
- `src/zkn_mont/zkn_mont256_armv6m.S`: `zkn_mul_mont_256` for Thumb-1 cores,
  same output as the C version, which `src/zkn_mont/zkn_mont256.c` leaves out
  on these cores unless `ZKN_MONT256_NO_ASM` is defined. Empty object on
  every other target. On these cores `zkn_from_mont_256` is the product of
  its operand and 1.
- `src/ecc/zkn_tEdwards.c`: `tEdwards_4MSM_flash_table_ct`, the fixed-base
  multiplication over the const 16-entry table, selected by
  `ZKN_FIXEDBASE_FLASH_TABLE` on the software backend.
- `src/ecc/zkn_eddsa.{c,h}`, under `ZKN_LOW_RAM` on the software backend:
  `EddsaPoseidon_Sign`, the signer that derives the public key itself
  (`ZKN_HAVE_EDDSA_POSEIDON_SIGN`), and one inversion instead of two on R.
  `EddsaPoseidon_Sign_final` keeps its arguments, its check and its output.
- `tools/mont256_armv6m_check.py`: runs the assembly, or the routine linked
  in a device ELF, in a Cortex-M0+ emulator against the C algorithm, and
  counts `MULS`, cycles and stack.
- `src/compat/zkn_rng_compat.h`: includes `os_random.h`.
- `src/sw_crypto/zkn_aes_gcm_sw.c`: host-only single-block AES-256, used by
  the GCM test.
- `Makefile`: `ZKN_LOW_RAM=1` and `ZKN_FIXEDBASE_FLASH_TABLE=1` for host
  builds; `zkn_gcm_ct.c` in the `WITH_KEYS=1` sources.
- `tests/test_lowram_vectors.c`: fixed vectors for every replaced path, the
  threshold ones produced by the unmodified library. `tests/test_gcm_ct.c`:
  NIST vectors and a differential run against the software GCM. Run with
  each switch on and off: `make test WITH_KEYS=1 ZKN_LOW_RAM=1
  ZKN_FIXEDBASE_FLASH_TABLE=1` is the Nano S combination.

### Rust suite (`rs/`)

See [rs/VERSION.md](rs/VERSION.md), 0.5.3: a process can take the device's
seat in a ceremony (`HW_PARTICIPANT_BIN`), and a 3-of-5 ceremony at the
firmware's limits. `rs/README.md` no longer says that a device run writes
nothing to flash: on Nano S the public part of the ceremony state does.
0.5.4: one signature on Bandersnatch against a fixed vector.

### Not changed

Apart from what the library changes for every target, the Poseidon
implementation and the order the signer reduces with, nothing moves outside
Nano S: with the library's main after pull request 4 and its Poseidon
delivery under upstream main of the app, flash images of the Nano S Plus
target are byte-identical with and without this branch, for `BACKEND=sw` and
`BACKEND=cx`, in `MODE=prod FROST=0` and in `MODE=debug FROST=1`.
