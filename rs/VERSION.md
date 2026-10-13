# Changelog

## 0.3.0 — 2026-10-12

The suite now targets the host simulator in `sim/` instead of Speculos. No
container, no emulator, no device: the full run is seconds.

- `ledger`: the Speculos socket backend is gone, replaced by a child-process
  backend speaking the simulator's protocol (one hex APDU per line in, one hex
  response per line out). `SIM_BIN` overrides the binary; USB HID stays behind
  the `hid` feature.
- `context`: `using_sim()`, and the skip rule keyed on the simulator being
  built rather than on `SPECULOS_APDU`. `SIM_SEED` now also moves the suite off
  its seed-bound oracles.
- `tests/sign.rs`: `BLIND_SIGN` (0x12) runs its approval path on every run
  instead of waiting for `INTERACTIVE=1`, and a new test drives `SIM_REJECT=1`
  to check the refusal returns no signature.
- `tests/transport.rs`: rewritten against a shell mock of the simulator, with
  a case for a backend that exits mid-exchange.
- `run-rs-tests.sh`: builds `sim/` and runs the suite; Docker and Speculos are
  gone from the Rust path.

Outside `rs/`, `sim/` had to be brought back to this app (see its README):
its Makefile still compiled the RAILGUN app's sources, and its UI shim still
answered the RAILGUN app's review screens.

Measured on this tree: 27 tests, all passing, 2.6 s.

## 0.3.1 — 2026-10-12

- `tests/ceremony.rs`: the full sequence across three simulator processes —
  DKG (comm keys, DEAL, SET_COMMITS, GET_SHARE/PUT_SHARE, FINALIZE), FROST
  signature by two of them, and verification. Each `z_i` is checked against
  the public share rebuilt from the Feldman commitments, the aggregate under
  `S·B8 == R8 + 8·hm·A`, and the aggregate against another message, which
  must fail. The nonce burn and the `skShare = 8 × skShareDiv8` relation are
  asserted on the way.

28 tests, all passing, 3.3 s.

## 0.3.2 — 2026-10-12

- `run-rs-device-tests.sh`: the same suite against a physical Ledger. The
  single-device suites talk to it over USB HID, and in `tests/ceremony.rs` it
  becomes participant 1 of the DKG while the other two stay simulated, so the
  ceremony and the FROST signature run between hardware and software
  participants.
- `ledger`: `HW_DEVICE=1` puts the device ahead of the simulator,
  `HW_PARTICIPANT_ID` picks which participant it plays, and `open_hid()` is
  public.
- `tests/ceremony.rs`: the `DEBUG_SKSHARE` cross-check is skipped when the
  firmware has no 0x69 instead of failing.
- `tests/sign.rs`: the `SIM_REJECT` test drives its own simulator, so it also
  runs in a device session.

Not run here: no Ledger is attached to this machine. What was checked is that
the device path builds with `--features hid` and that a missing device fails
immediately, with its reason, rather than hanging or passing quietly.

## 0.4.0 — 2026-10-12

Two ceremonies instead of one, and the transport keys are now derived
host-side rather than taken as announced.

- `oracle`: `path_dkg_comm`, `dkg_comm_pubkey_from_seed` and
  `dkg_comm_pubkey` — SLIP-0010 down `m/421'/1984'/account'/0'/0'`, then the
  Ed25519 public key of the node, which is what `DKG_GET_COMM_PUBKEY` returns.
- `tests/ceremony.rs`: split into a parametrised runner and two tests.
  `a_ceremony_on_the_canonical_seed_signs_and_verifies` is 2-of-3 with every
  participant on mnemonic "yellow"×12 — the shape `run-rs-device-tests.sh`
  reproduces with a Ledger in it.
  `a_ceremony_on_random_per_participant_seeds_signs_and_verifies` draws n
  (3..5), t (2..3), a fresh 64-byte seed per participant, the quorum, the
  ceremony name and the message from the OS CSPRNG, and prints them so a
  failing run can be replayed.
- `tests/ceremony.rs`: every participant's announced transport key is checked
  against the one its seed derives, which replaces the old "the seeds must
  differ" assertion; distinctness is still asserted when the seeds do differ.
  Dealers are also checked to have dealt different polynomials, and the
  aggregate is now checked under a different group key as well as against a
  different message.
- `tests/ceremony.rs`: the simulated participants are spawned with an explicit
  `SIM_SEED`, empty for the canonical seed, so an ambient `SIM_SEED` in the
  caller's environment cannot reseed them through process inheritance.
- `tests/oracle.rs`: the host derivation is frozen against the yellow×12 value
  `sim/test/selftest.sh` and `js/` carry, so the device and the host cannot
  agree on a wrong key.
- `tests/dkg.rs`: `get_comm_pubkey_matches_the_yellow_oracle` compares the
  captured constant with the derivation before comparing the device with it.
- `run-rs-device-tests.sh`, `rs/README.md`: the device's seed is now load
  bearing for the ceremony too, and `SEED=other` waives that check as it
  already waived the oracles.

30 tests, all passing, 3.4 s. The random ceremony was run 16 times over
n ∈ {3,4,5} and t ∈ {2,3}: 16 passes. The transport-key check was negative
controlled by flipping one bit of a seed, which fails by participant number.

## 0.2.0 — 2026-10-12

Added `crates/hw-tests`: the `js/` functional suite of ZKNOX-HW-PRIVACY ported
to Rust, driving the app over the same APDUs from the same fixtures.

- `apdu`, `hex`, `ledger`, `context`, `slip0010`, `fixtures`: the JavaScript
  `js/apdu-constants.js` and `js/lib/*` one for one, Speculos socket included,
  with a USB HID backend behind the `hid` feature.
- `oracle`: the circomlib reference of `sign.test.js`, computed with
  `frost-babyjubjub`.
- `tests/dkg.rs`, `tests/frost_hw.rs`, `tests/sign.rs`: the three device
  suites, same assertions and same skip rules.
- `tests/oracle.rs`: the Rust oracle against 32 frozen circomlib vectors,
  inputs drawn from the OS CSPRNG. No device needed.
- `tests/transport.rs`: Speculos framing and APDU encoding against a mock
  socket, including the 192-byte FROST chunk and the status-word paths. No
  device needed.
- `run-rs-tests.sh` at the repository root, the counterpart of
  `run-js-tests.sh`.
- `js/tools/gen-rust-oracle-vectors.mjs` and `rs/xcheck/gen-oracle-inputs.py`
  to regenerate the vectors.

Fixed while porting: the oracle must reduce the message modulo the BabyJubJub
base prime before signing, which `F.toMontgomery` does on the JavaScript side.
The suite's own message is below the prime, so only the random vectors show it.

Dropped the `zeroize` and `rmp-serde` version pins: they existed only to build
on rustc 1.75.

## 0.1.0 — 2026-09-22

First release. Rust port of `@railgun-reloaded/curves` at the GitLab state of
2026-09-21 (`dev` plus the `zknox/NN-*` branches up to MR !11).

Added
- `bytes`, `curve`, `hashing`, `poseidon`, `eddsa`, `frost`, `dkg`: full port
  of the primitive layer, including the `@zk-kit/baby-jubjub` and
  `@zk-kit/utils` behaviour the TypeScript relies on (`addPoint`,
  `mulPointEscalar`, `inCurve`, `packPoint`, `unpackPoint`, `F1Field`
  comparison semantics).
- `key_agreement`: X25519 and the RAILGUN engine Ed25519 + SHA-256 scheme.
- `participant`, `ceremony`, `manager`: the `DKGParticipant` contract, the
  `runCeremony` driver of MR !11, and the software participant (DKG half of
  `DKGManager`, no snapshot).
- `rng`: `Rng` trait, OS source, and the deterministic DRBG used by the
  cross-check.
- `tests/integration.rs`: 32 random ceremonies (Feldman dealing, AES-GCM share
  envelopes, finalization, threshold signing, EdDSA-Poseidon verification) with
  the matching negative cases.
- `tests/ceremony.rs`: 32 random ceremonies through `run_ceremony` over the
  participant contract, both key-agreement schemes, plus the state-machine
  rejections.
- `snapshot`: the resumable `DKGSnapshot` of `manager/dkg.ts` (version 1,
  hex-encoded JSON), with `SoftwareParticipant::to_snapshot` /
  `from_snapshot`.
- `signing`: `FROSTSigningManager` and `SigningSession`, with the `safe` and
  `mid-round` snapshots and the session rules (single commit per session,
  message binding, full partial set before aggregation, aggregate verified
  before it is returned).
- `tests/signing.rs`: 32 random two-manager signing rounds plus the session
  rules and snapshot-kind rejections.
- `shareable`: the `module-index.ts` payloads — `getShareableViewingKey`,
  `getShareableMultisigKey`, `decodeShareableKey`, `decodeMultisigKey`,
  `poseidon`, `poseidonHex`, `getPublicSpendingKey`, `getPublicViewingKey`,
  `signEDDSA`, `verifyEDDSA` — with msgpack bytes identical to
  `@msgpack/msgpack`.
- `xcheck/`: vector generator (OS CSPRNG), Rust and JavaScript runners,
  comparator, ceremony transcript harness, DKG and signing snapshot interop
  harnesses.

Cross-check results at release (`xcheck/run.sh`)
- 83 functions x 32 inputs: 2656 cases, 2656 matching, 0 mismatching.
- 32 ceremonies produced by Rust, verified by JavaScript: 2831/2831 checks.
- 32 ceremonies produced by JavaScript, verified by Rust: 2919/2919 checks.
- 32 snapshot sets written by Rust, restored and finalized by JavaScript:
  500/500 checks.
- 32 snapshot sets written by JavaScript, restored and finalized by Rust:
  540/540 checks.
- 32 signing snapshot sets written by Rust, restored and finalized by
  JavaScript: 256/256 checks.
- 32 signing snapshot sets written by JavaScript, restored and finalized by
  Rust: 256/256 checks.

## 0.5.0 — 2026-10-13

A third test set: `crates/zknox-sim` links `sim/` into the test binary instead
of spawning it, which makes an APDU a function call and the dispatcher's whole
contract cheap enough to sweep rather than sample.

- `sim/src/sim_core.{c,h}`: `process_apdu` out of `main.c` as
  `zkn_sim_exchange`, plus `zkn_sim_version`, `zkn_sim_has_debug_ins`,
  `zkn_sim_has_frost` so a caller can read the build gates off the C.
- `sim/shim`: the seed, the review decision and the RNG became setters —
  `zkn_sim_set_seed`, `zkn_sim_set_seed_default`, `zkn_sim_set_ui_decision`,
  `zkn_sim_set_rng_seed`, `zkn_sim_set_rng_os`. The `SIM_*` variables still
  work and still decide when nothing was set explicitly.
- `sim/Makefile`: a `lib` target producing one merged static archive
  (`libzknoxsim.a`), `SAN=1` for AddressSanitizer and UBSan, `EXTRA_CFLAGS`
  and `EXTRA_LDFLAGS`, and `-Isrc`.
- `crates/zknox-sim`: `build.rs` drives `sim/Makefile` so the compile flags
  keep one home; `Sim` is the device handle, exclusive behind a mutex because
  one process is one device.
- `crates/zknox-sim/tests`: `dispatcher.rs` sweeps the whole `(INS, P1, P2)`
  space, 16.7 million exchanges, against the RFU rule transcribed from
  `src/apdu/dispatcher.c` — `6a86` on exactly the violations, `6d00` on
  exactly the unmapped instructions, every answer a status word `src/sw.h`
  declares. `config.rs` checks the `ZKN_FROST` and `ZKNOX_DEBUG` gates against
  the compiled build in both directions. `control.rs` runs 32 random seeds
  through both derivation branches, flips the review screen inside one session
  and pins the deterministic RNG. `robustness.rs` throws 100k random APDUs and
  every body length at the dispatcher. `throughput.rs` is the measurement,
  ignored by default.
- `crates/hw-tests`: `INS_VIEWING_PUBKEY` (0x10), `INS_VIEWING_PRIVKEY` (0x13)
  and `INS_RAILGUN_ADDRESS` (0x14), which the dispatcher maps and the constants
  were missing, and `derived_spending_key_from_seed`.
- `run-sim-tests.sh`, with `--san` and `--prod`.

Found on the first run: `SIM_RNG_SEED` was not injective. The shim did
`state = seed | 1`, so seeds 2 and 3 drove the same stream; now only 0 is
remapped. UBSan reports a left shift of a negative value in
`vendor/ed25519/fe.c`, which is why `shift-base` is the one check excluded
under `SAN=1`.

17 tests and a doc-test, all passing: 2.3 s for the sweep, 3.4 s for
the set. Green in three
configurations — `MODE=debug FROST=1`, `MODE=prod FROST=1`, `MODE=prod
FROST=0` — and under ASan + UBSan, where the whole set takes 31 s. 2.2 million
random APDUs over 11 seeds, no finding.

## 0.5.1 — 2026-10-13

- `run-rs-device-tests.sh`: check for libudev before compiling. The `hid`
  feature builds hidapi, whose hidraw backend enumerates through libudev on
  Linux, and without the development package cargo fails forty lines into a
  build-script panic. The check names the package per distribution and covers
  the case where `pkg-config` on PATH is a conda or homebrew shim, which finds
  no system library and reports it as a missing one.
- `rs/README.md`: the same, plus Ledger's udev rules, without which the device
  is enumerated but cannot be opened and the suite says `No Ledger device
  found`.

## 0.5.2 — 2026-10-13

- `run-rs-device-tests.sh`: the libudev check covers the compiler as well as
  pkg-config. A conda or miniforge prefix on PATH breaks both independently —
  its pkg-config searches only its own prefix, and its cc compiles against its
  own sysroot, so `libudev.h` is reported missing with the package installed
  and pkg-config already corrected. Each tool is probed, the system one is
  used when the one on PATH cannot see a library that is installed, and an
  explicit `PKG_CONFIG` or `CC` is never overridden. Both are scoped to the
  cargo invocation, so the simulator's own build keeps the toolchain it had.
