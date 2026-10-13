# Rust functional tests

The `js/` suite, ported to Rust. Same APDUs, same assertions, same skip rules,
with two differences: the cryptographic oracle is computed by
`frost-babyjubjub` instead of `circomlibjs` (the two are kept honest against
each other by frozen vectors, below), and the target is the host simulator in
[`sim/`](../sim/README.md) rather than Speculos. No container, no emulator, no
device: `sim/` compiles the real dispatcher and handlers against the SDK shim,
and the suite pipes APDUs to it. The whole run takes a few seconds.

| JavaScript | Rust |
|---|---|
| `js/apdu-constants.js` | `crates/hw-tests/src/apdu.rs` |
| `js/lib/hex.js` | `crates/hw-tests/src/hex.rs` |
| `js/lib/ledger.js` | `crates/hw-tests/src/ledger.rs` (simulator and USB HID, no Speculos socket) |
| `js/lib/test-context.js` | `crates/hw-tests/src/context.rs` |
| `js/lib/slip0010.js` | `crates/hw-tests/src/slip0010.rs` |
| `js/fixtures/test-mnemonic.js` | `fixtures` module of `crates/hw-tests/src/lib.rs` |
| circomlib oracle in `sign.test.js` | `crates/hw-tests/src/oracle.rs` |
| `js/test/dkg.test.js` | `crates/hw-tests/tests/dkg.rs` |
| `js/test/frost-hw.test.js` | `crates/hw-tests/tests/frost_hw.rs` |
| `js/test/sign.test.js` | `crates/hw-tests/tests/sign.rs` |
| — | `crates/hw-tests/tests/ceremony.rs` (full multi-device DKG + FROST, canonical and random seeds) |
| — | `crates/hw-tests/tests/oracle.rs`, `tests/transport.rs` (no device needed) |
| — | `crates/zknox-sim` (the simulator linked in: the dispatcher's contract, swept) |

`crates/frost-babyjubjub` is the Rust port of `@railgun-reloaded/curves`
(GitLab `railgun-protocol/reloaded/curves`, state of 2026-09-21, MR !11
included): BabyJubJub, circom Poseidon, EdDSA-Poseidon, FROST, Feldman VSS,
the DKG participant contract and both snapshot formats. The suite here uses
its EdDSA-Poseidon; the rest is what a Rust co-signer would need to run a
ceremony with the device. See `VERSION.md` and `DECISIONS.md`.

`crates/zknox-sim` is the third test set: the same simulator, linked into the
test binary instead of spawned. See *The linked simulator* below.

## Run

```sh
../run-rs-tests.sh              # build sim MODE=debug, run everything
../run-rs-tests.sh --no-build   # reuse sim/build/debug/apdu_sim

../run-rs-device-tests.sh       # same suite against a physical Ledger

../run-sim-tests.sh             # the linked simulator (crates/zknox-sim)
../run-sim-tests.sh --san       # the same under AddressSanitizer + UBSan
../run-sim-tests.sh --prod      # against a MODE=prod FROST=1 build
```

`run-rs-device-tests.sh` points the single-device suites at the Ledger over
USB HID and makes it participant 1 of the canonical ceremony, the other two
staying simulated — so the DKG and the FROST signature run between real
hardware and software participants. It needs a device built
`MODE=debug FROST=1`, unlocked, with the app open, and seeded yellow×12: the
seed-bound oracles are one reason, and the ceremony's transport-key check is
the other, the device's seed being the one the suite cannot set. `SEED=other`
waives all three. Nothing is written to flash: the DKG share lives in RAM.

To drive it yourself:

```sh
cd sim && make MODE=debug && cd ../rs
cargo test -p zknox-hw-tests -- --test-threads=1
SIM_BIN=/path/to/apdu_sim cargo test -p zknox-hw-tests -- --test-threads=1
HW_DEVICE=1 cargo test -p zknox-hw-tests --features hid -- --test-threads=1   # physical Ledger
SIM_SEED=<128 hex> ...                                             # another seed; skips the seed-bound assertions
SIM_VERBOSE=1 ...                                                  # the simulator traces its UI decisions
```

`MODE=debug` is what the suite needs: it compiles `BLIND_SIGN_NO_DISPLAY`
(0x02) and `SIGN_WITH_PRIVKEY` (0x50), and brings `FROST=1` with it for the
DKG and FROST handlers.

`--test-threads=1` is the equivalent of `node --test --test-concurrency=1`:
the suites share one transport and the device has a single ceremony state. The
transport is behind a mutex, so the suite is correct without the flag too, just
slower to no purpose.

The `hid` feature is the counterpart of the optional
`@ledgerhq/hw-transport-node-hid` dependency. It needs `libudev` headers on
Linux (`apt install libudev-dev pkg-config`, or `systemd-devel` on Fedora);
macOS builds it against IOKit with nothing to install.
`run-rs-device-tests.sh` checks for them before compiling and says what to
install, since the failure otherwise arrives as a build-script panic forty
lines into cargo's output. Two tools have to find libudev and a conda or
miniforge prefix on PATH breaks both: its `pkg-config` searches only its own
prefix, and its `cc` compiles against its own sysroot, so the header comes out
missing even once pkg-config is corrected. The script probes each and falls
back to `/usr/bin/pkg-config` and `/usr/bin/cc` when the ones on PATH cannot
see a library that is installed, scoped to the cargo invocation; an explicit
`PKG_CONFIG` or `CC` is left alone. `conda deactivate` settles it too.

Talking to the device as a non-root user also needs Ledger's udev rules
(`LedgerHQ/udev-rules`); without them the device is enumerated but
`hidapi` cannot open it, and the suite reports `No Ledger device found`.

## Skip, and when a skip becomes a failure

With no backend configured at all, the device suites print `SKIP …` and pass,
as `t.skip("no device")` does on the JavaScript side. With `SIM_BIN` or
`HW_DEVICE` set, a built simulator at its default path, or the `hid` feature
on, a backend that does not answer **fails**: a green run against no device
would hide exactly what these suites exist to catch. Same asymmetry as
`js/README.md` describes for a firmware built without `FROST=1`.

`run-rs-tests.sh` runs `-p zknox-hw-tests` only, which is seconds. The
`frost-babyjubjub` crate carries its own regression suites (64 random
ceremonies, Feldman VSS through FROST aggregation); they are minutes long in a
debug-profile build even with optimized dependencies, so run them on their own
and in release:

```sh
cargo test --release -p frost-babyjubjub
```

Two suites need no device at all and run in plain `cargo test`:

- `tests/oracle.rs` — the host-side reference against 32 circomlib vectors;
- `tests/transport.rs` — the pipe protocol and the APDU encoding against a
  two-line shell mock that answers like the simulator, including the 192-byte
  FROST chunk, the status-word paths and a backend that exits mid-exchange.

## Oracle vectors

`crates/hw-tests/tests/fixtures/oracle-vectors.json` freezes what circomlib
says, so `cargo test` validates the Rust oracle without node. Regenerate after
touching either side:

```sh
python3 rs/xcheck/gen-oracle-inputs.py /tmp/oracle-inputs.json 32
cd js && node tools/gen-rust-oracle-vectors.mjs /tmp/oracle-inputs.json \
    ../rs/crates/hw-tests/tests/fixtures/oracle-vectors.json
```

Inputs come from the OS CSPRNG (`secrets`), expectations from `circomlibjs` —
the same library and the same `circomlibRef` function the JavaScript suite
uses.

The rest of `rs/xcheck/` is the harness that validated `frost-babyjubjub`
against the TypeScript `curves` library itself (83 functions × 32 inputs, plus
ceremony and snapshot interop both ways). It needs a built curves checkout and
is unrelated to this firmware: `CURVES_DIR=/path/to/curves ./rs/xcheck/run.sh`.
Kept as the provenance of the crate; delete it if the crate ever moves to its
own repository.

## The full ceremony

`tests/ceremony.rs` is what the JavaScript suite says it cannot do:
`js/test/frost-hw.test.js` keeps the happy-path signature out because a valid
FROST signature needs t co-signers, "a 2-device setup", and one Speculos
instance is one device. A simulator is a process, so n participants cost n
processes. With `HW_DEVICE=1` one of them is a real Ledger instead
(`HW_PARTICIPANT_ID` picks which), which is what `run-rs-device-tests.sh`
does: the device deals, receives, finalizes and signs alongside simulated
peers, and the same checks apply to the result.

Two ceremonies run the same code path:

| test | participants | drawn |
|---|---|---|
| `a_ceremony_on_the_canonical_seed_signs_and_verifies` | 2-of-3, all on mnemonic "yellow"×12 | the message |
| `a_ceremony_on_random_per_participant_seeds_signs_and_verifies` | t-of-n, one fresh 64-byte seed per participant | n (3..5), t (2..3), the seeds, the quorum, the ceremony name, the message |

The first is the shape the device run reproduces with hardware in it. The
second is pure software — a physical Ledger cannot be handed a seed — and
every draw comes from the OS CSPRNG, printed so a failing run can be replayed
with the same `SIM_SEED`s.

Having both says what the seeds are and are not for. A verifier's whole input
is the message, the signature and the group public key, so participants
sharing a seed is neither required nor forbidden. What the ceremony does
require is that each announced transport key be the one that participant's
seed derives, and both tests recompute all of them host-side — SLIP-0010 with
the `"babyjubjub seed"` HMAC key down `m/421'/1984'/account'/0'/0'`, then the
Ed25519 public key of the node — rather than trusting what came back over the
wire. That is the host's half of the man-in-the-middle guard `handler_dkg.c`
documents; the device's half is its own self-HK check. `tests/oracle.rs`
freezes the derivation against the yellow×12 value captured long before it
existed, so the two sides cannot agree on a wrong answer.

The tests run the real sequence — `DKG_GET_COMM_PUBKEY`, `DEAL`,
`SET_COMMITS` in the canonical C0 order, `GET_SHARE`/`PUT_SHARE` between every
pair, `FINALIZE` — with the host as the untrusted coordinator that carries
ciphertexts and never sees a secret. Then the quorum runs `FROST_HW_COMMIT`
and `FROST_HW_SIGN`, and the result is checked four ways:

- each `z_i` on its own, against the public share rebuilt from the Feldman
  commitments: `z_i·B8 == (D_i + ρ_i·E_i) + (λ_i·c)·P_i`;
- the aggregate, under the circomlib equation `S·B8 == R8 + 8·hm·A`;
- the same aggregate under a different group key, which must fail;
- the same aggregate against another message, which must fail.

Both sides of those equations come from `frost-babyjubjub`, so a pass means
the firmware and the TypeScript library agree on the binding factors, the
group commitment, the challenge and the interpolation — not that the firmware
is self-consistent. It also checks what the sequence alone would hide: the
devices all land on the same digest and the same group key, no two dealers
deal the same polynomial, `skShare` is 8 × `skShareDiv8` and matches the
commitments, and a second `SIGN` on burnt nonces is refused.

One thing it caught that a single device cannot: `GET_SHARE` needs
`COMMITTED` and a participant that has already taken everyone's shares has
moved to `COLLECTED`, so publishing and consuming have to be two phases.

`n` and `t` stay inside `DKG_MAX_N` (5) and `DKG_MAX_T` (3), and the quorum
is exactly `t` records because `handler_frost_sign.c` refuses any other
count.

## The linked simulator

`crates/zknox-sim` compiles `sim/` into one static archive and calls the real
`apdu_dispatcher` through FFI. The seam was already there: `process_apdu` in
`sim/src/main.c` was a buffer in, buffer out function over the dispatcher, and
it now lives in `sim/src/sim_core.c` under the name `zkn_sim_exchange`, with
`main.c` reduced to the hex loop over it. `build.rs` does not re-derive the
compile flags; it runs `sim/Makefile`'s `lib` target, so the flags that make
the simulator the firmware have one home.

An APDU then costs a function call: 9.8 million a second against 31 thousand
through the pipe, a factor of about 300, measured by

```sh
cargo test -p zknox-sim --test throughput -- --ignored --nocapture
```

That is what pays for the four things this set checks and the other two
cannot:

- **the whole `(INS, P1, P2)` space**, 16.7 million exchanges in 2.3 s, against
  the RFU contract `src/apdu/dispatcher.c` states instruction by instruction.
  The claims are that `6a86` appears on exactly the RFU violations and nowhere
  else, `6d00` on exactly the instructions the build does not map, and that
  every answer anywhere in the space is a status word `src/sw.h` declares. The
  same sweep over the pipe takes nine minutes, which is why `hw-tests` checks
  a handful of values.
- **32 random seeds in one run**, each checked on two derivation branches at
  once: the BabyJubJub signing key down `m/44'/1984'/account'/0'/0'` and the
  Ed25519 transport key down `m/421'/1984'/account'/0'/0'`, both recomputed
  host-side. `SIM_SEED` is read once at startup, so over the pipe this is 32
  process spawns.
- **the approval and the refusal path in one session.** `hw-tests` spawns a
  second simulator whose whole life is answering no once; here the decision is
  a setter, so approve, refuse and approve again happen on one device and the
  two approvals are compared.
- **a hundred thousand random APDUs**, and every body length from 0 to 255 for
  every instruction, checking the dispatcher always answers a documented
  status word and never `6f00`.

`ZKNOX_SIM_MODE` and `ZKNOX_SIM_FROST` pick the configuration, and the gate
tests adapt: `MODE=prod FROST=1` is the pair `sim/Makefile` calls "the only
way to find out whether the split actually holds", and it passes.

`ZKNOX_SIM_ASAN=1` (or `--san`) builds the simulator's own sources under
AddressSanitizer and UBSan and links the runtimes into the test binary — no
nightly toolchain, since only the C is instrumented. The full set passes,
the sweep included, in 31 s. `shift-base` is excluded because
`vendor/ed25519/fe.c` shifts negative integers on purpose; everything else is
fatal. libzknox is built by its own Makefile and is not instrumented, so what
ASan watches there is its heap access rather than its stack.

What the linked simulator cannot do is a ceremony. The firmware's DKG state
(`handler_dkg.c`), its FROST state (`handler_frost_sign.c`), the `cx_bn` pool
and the seed cache are file statics, so one process is one device; `Sim::lock`
hands out the single device behind a mutex, which is also why this set needs no
`--test-threads=1`. The t-of-n ceremony stays with the process backend, and a
firmware crash that would have surfaced there as a transport error takes the
test runner with it here. That is the trade, and it is why both sets exist.

## What else the simulator buys

Two more tests the JavaScript suite cannot run unattended:

- `blind_sign_with_ui_matches_the_reference` — on hardware this waits for a
  button press, so the JavaScript version is behind `INTERACTIVE=1`. The
  simulator's UI approves on its own, so the approval path of `BLIND_SIGN`
  (0x12) is covered on every run.
- `blind_sign_is_refused_when_the_user_rejects` — `SIM_REJECT=1` makes the UI
  answer no, and the handler must return a refusal rather than a signature
  (it returns `6985`). The test spawns a second simulator for it, since that
  variable is read once at startup.

## A note on the message encoding

`circomlibRef` passes `F.toMontgomery(msg)`, which reads the 32 bytes as a
little-endian field element **and reduces them modulo the BabyJubJub base
prime**. The reduced value is what circomlib hashes into the nonce and feeds to
Poseidon, so a message at or above the prime signs as its residue. The suite's
own message is below the prime, so this never shows up there; the random oracle
vectors are above it three times out of four, which is how it got noticed. The
Rust oracle reduces the same way.
