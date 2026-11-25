# Changelog

## Unreleased

Date: 2026-11-25

### Added

- Nano S target (LNS SDK, `BOLOS_SDK=$NANOS_SDK`), `FROST=0` only. Production
  commands: signing public key, viewing public key, viewing private key, 0zk
  address, blind sign on BabyJubjub and Bandersnatch.
- `ZKN_LOW_RAM` switch, set by the Makefile for `TARGET_NANOS`. See
  [DECISIONS.md](DECISIONS.md), ADR-001.
- `icons/app_zknox_16px.gif`: Nano S dashboard icon. Placeholder, the 14 px
  icon on a 16 px canvas.

### Changed

- Makefile: `ICON_NANOS`, `ZKN_MONT256_ASM` left out and `ZKN_LOW_RAM` defined
  for `TARGET_NANOS`, `FROST` defaults to 0 and `FROST=1` is an error on that
  target.
- Nano S review screens for the public key export, the 0zk address and the
  blind sign go through `nbgl_useCaseReview`. See ADR-002.

### ZKNOX-LibC (submodule `src/zknox`)

These changes belong to the library repository and need their own commit
there, followed by a submodule bump here.

- `src/ecc/zkn_tEdwards.c`: constant-time 2-window fixed-base multiplication
  under `ZKN_LOW_RAM`.
- `src/zkn_mont/zkn_poseidon_soft.{c,h}`: MDS matrix read from the const table
  under `ZKN_LOW_RAM`.
- `src/ecc/zkn_eddsa.c`: phased `EddsaPoseidon_Sign_final` under
  `ZKN_LOW_RAM` on the software backend.
- `src/zkn_mont/zkn_mont256_arm32.S`: empty object on Thumb-1 cores.
- `src/aes/zkn_aes_gcm.c`: syscall wrappers left out on `TARGET_NANOS`.
- `src/compat/zkn_rng_compat.h`: includes `os_random.h`.
- `Makefile`: `ZKN_LOW_RAM=1` for host builds.
- `tests/test_lowram_vectors.c`: fixed vectors for the three replaced paths.
  Run it both ways: `make test` and `make test ZKN_LOW_RAM=1`.

### Not changed

Flash images of the Nano S Plus target are byte-identical before and after,
for `BACKEND=sw` and `BACKEND=cx`.
