# ZKNOX-HW-PRIVACY

A Ledger app that exposes **generic zero-knowledge-friendly signing
primitives** and nothing else:

- **EdDSA-Poseidon signing** over a twisted-Edwards curve (BabyJubjub or
  Bandersnatch) — the signature shape a zk circuit can verify cheaply
  in-circuit;
- **FROST threshold signing** on top of a two-round Pedersen VSS/DKG, so a
  key can be split across devices with no trusted dealer.

The cryptography itself lives in [ZKNOX-LibC](https://github.com/ZKNoxHQ/ZKNOX-LibC),
pulled in as the `src/zknox` submodule. This repository is the firmware
around it: key derivation, the APDU surface, the state machines, and the
approval screens.

> [!WARNING]
> **This code has not been audited.** It is research and development
> software, provided as is and without warranty of any kind. It has not
> undergone external security review, and neither the firmware in this
> repository nor the cryptography it pulls in from ZKNOX-LibC should be
> assumed correct or safe.
>
> Do not use it to protect keys or funds you are not prepared to lose. The
> blocking list at the top of [src/zkn_features.h](src/zkn_features.h)
> records the limitations that are already understood; the absence of an
> item from that list is not evidence that it is sound.

## Scope

This app implements **primitives, not a protocol**. There is no notion here
of a chain, a token, an amount, a recipient, or a note. It signs a 32-byte
message and it participates in a threshold ceremony; giving those bytes
meaning is the job of whatever sits on top.

That boundary is deliberate and it has a cost worth stating plainly: a
32-byte message is opaque to the device, so `BLIND_SIGN` is a blind
signature and the review screen says so. An application that wants a user
to approve something they can actually read has to supply the semantics
itself — either by building on this app's key derivation in its own
firmware, or by adding a clear-signing layer downstream.

What the device *can* answer for on its own, it does:

- the account index is on the review screen, because it selects the key;
- signing never happens before approval — the key is derived inside the
  approve callback, so a declined request never materialises a signature;
- the context is wiped on both the approve and reject paths, so no signing
  token survives into a later APDU;
- no instruction in a production build exports a private key.

## APDU surface

`CLA = 0xE0`. Status words are in [src/sw.h](src/sw.h).

### Always present

| INS | Name | Data | Response |
|-----|------|------|----------|
| `0x01` | `SIGNING_PUBKEY` | `account(4 BE)` | `x(32) \|\| y(32)` |
| `0x03` | `GET_VERSION` | — | `major(1) \|\| minor(1) \|\| patch(1)` |
| `0x04` | `GET_APP_NAME` | — | `APPNAME` |
| `0x12` | `BLIND_SIGN` | `account(4 BE) \|\| msg(32)` | `len(1) \|\| R8x\|\|R8y\|\|S (96) \|\| msg(32)` |

`SIGNING_PUBKEY`: `P1=0x01` displays the key and returns it on Approve.
`P1=0x00` is a silent path that exists only in `MODE=debug`.

`BLIND_SIGN`: `P1` selects the curve — `0x00` legacy (= BabyJubjub),
`0x01` Bandersnatch, `0x02` BabyJubjub. `P2` is RFU and must be zero.

### VSS/DKG ceremony (`FROST=1` builds)

| INS | Name | Data | Response |
|-----|------|------|----------|
| `0x60` | `DKG_GET_COMM_PUBKEY` | `account(4 BE)` | `HK_i(32)` |
| `0x61` | `DKG_DEAL` | `account(4) id(1) t(1) n(1) len(1) name` | `epoch(16) \|\| C_i(t*64)` |
| `0x62` | `DKG_SET_COMMITS` | `[ id(1) HK_j(32) C_j(t*64) ]` chunked | digest(32) on LAST |
| `0x63` | `DKG_GET_SHARE` | `j(1)` | `nonce(12) \|\| ct(32) \|\| tag(16)` |
| `0x64` | `DKG_PUT_SHARE` | `j(1) C_j(t*64) nonce(12) ct(32) tag(16)` | — |
| `0x65` | `DKG_FINALIZE` | — | `A(64)` |
| `0x66` | `DKG_ABORT` | — | — |
| `0x67` | `DKG_STATUS` | — | `state(1) id(1) t(1) n(1) mask(2 BE)` |
| `0x6a` | `DKG_EXPORT_SHARE` | `account(4 BE)` | `aad \|\| nonce(12) \|\| ct(32) \|\| tag(16)` |
| `0x6b` | `DKG_RESTORE_SHARE` | `account(4 BE) \|\| blob` | `A(64)` |

State machine: `IDLE → DEALT → COMMITTED → COLLECTED → PROVISIONED`.
`DKG_ABORT` returns to `IDLE` from any transient state, wiping the
coefficients.

The barrier between the two rounds is not arbitrary: the share AAD is
`id || commitmentsDigest`, so nothing can be encrypted before every dealer
has published its commitments. `GET_SHARE` before `COMMITTED` is refused.

Bounds are `n ≤ 5`, `t ≤ 3` — enough for 2-of-3 and 3-of-5. Raising them
means adding a streaming tagged-hash to the libC first; see the comment at
the top of [handler_dkg.c](src/handler/handler_dkg.c).

### FROST signing (`FROST=1` builds)

| INS | Name | Data | Response |
|-----|------|------|----------|
| `0x70` | `FROST_HW_COMMIT` | — | `D_i(64) \|\| E_i(64)` |
| `0x71` | `FROST_HW_SIGN` | `msg(32) \|\| [ id(32) D(64) E(64) ] * t`, chunked | `z_i(32)` on LAST |
| `0x72` | `FROST_HW_RESET` | — | — |

`PROVISIONED --COMMIT--> NONCED --SIGN--> PROVISIONED`. `SIGN` consumes the
nonces and wipes them before returning: signing twice with the same
`(d_i, e_i)` is two equations in two unknowns and hands over `skShare_i`.
A second `SIGN` without a fresh `COMMIT` is refused.

The interpolation coefficient is derived **on-device** from the signer ids
in the commitment list. A host-chosen lambda invalidates the aggregate
while every individual share still verifies — a failure mode that is
invisible until the aggregate is checked.

### Debug-only (`MODE=debug`)

`0x02 BLIND_SIGN_NO_DISPLAY`, `0x50 SIGN_WITH_PRIVKEY`,
`0x68 DKG_DEBUG_COMM_PRIVKEY`, `0x69 DKG_DEBUG_SKSHARE`, and the silent
`P1=0x00` path of `SIGNING_PUBKEY`.

These sign without a screen or hand out secrets outright. They exist so a
host suite can check the device against reference vectors without driving a
UI. A production build must not contain them, and
[src/constants.h](src/constants.h) hard-`#error`s if `ZKNOX_DEBUG` is
somehow live in a `MODE=prod` build. `tests/standalone/test_dispatcher.py`
asserts their absence from the other side.

## Key derivation

Two secrets, neither exportable:

| Key | Path | Curve | Used by |
|-----|------|-------|---------|
| signing | `m/44'/1984'/account'/0'/0'` | twisted Edwards | `BLIND_SIGN`, DKG coefficients |
| DKG transport | `m/421'/1984'/account'/0'/0'` | Ed25519 | share encryption, never leaves |

All levels are hardened; the path is firmware-fixed and the host supplies
only the account index. The constants live in the libC
(`src/zknox/src/keys/zkn_keyderivation.h`) so that every ZKNOX app derives
the same key from the same seed for a given account.

The DKG transport identity is deliberately *not* a child of any exportable
path: possession of a scanning key must not be enough to derive it.

## Build

Everything runs in the Ledger dev container:

```shell
./docker.sh                                  # drops you in a shell at /app
make -j BOLOS_SDK=$NANOSP_SDK                # MODE=prod FROST=0, the default
make -j BOLOS_SDK=$NANOSP_SDK MODE=debug     # implies FROST=1
```

Three switches, all orthogonal:

| Variable | Values | Meaning |
|----------|--------|---------|
| `BACKEND` | `sw` (default), `cx` | pure-software bignums vs. BOLOS `cx_bn_*` syscalls |
| `MODE` | `prod` (default), `debug` | whether the test/introspection INSes are compiled in |
| `FROST` | `0` / `1` (defaults to `1` under `MODE=debug`) | whether the DKG + FROST ceremony is compiled in |

Build output is namespaced by all three
(`build/<target>/<backend>/<mode>/frost-<n>/`) so switching one cannot
reuse another's object files. A copy is staged at `build/<target>/bin/` for
the Ledger VS Code extension and for ragger.

`MODE=prod FROST=1` is a deliberate Makefile error. The blocking list — the
share lives in RAM with no `nvm_write`, `FROST_HW_SIGN` releases `z_i` with
no user confirmation, `DKG_FINALIZE` shows nothing — is in
[src/zkn_features.h](src/zkn_features.h).

### Nano S

The original Nano S builds against the LNS SDK:

```shell
make -j BOLOS_SDK=$NANOS_SDK                         # MODE=prod
make -j BOLOS_SDK=$NANOS_SDK MODE=debug              # FROST=0 unless asked
make -j BOLOS_SDK=$NANOS_SDK MODE=debug FROST=1      # DKG and FROST
```

It has 4.6 KB of RAM and an ARMv6-M core, so the Makefile defines
`ZKN_LOW_RAM` for it: same keys and signatures, smaller stack. That is the
one switch of the port. What it brings is written in two headers,
[src/zknox/src/common/zkn_config.h](src/zknox/src/common/zkn_config.h) for
the library and [src/zkn_app_config.h](src/zkn_app_config.h) for the app,
and what depends on the chip or on its SDK follows the target (ADR-012).
With `FROST=1` the public part of the ceremony state (commitments, hashes,
transport keys, the signing request) goes to an NVRAM scratch area and the
secrets stay in RAM; the commands and their wire format are those of the other devices, up
to 3-of-5. Details in [DECISIONS.md](DECISIONS.md), ADR-001 and ADR-003.

`BACKEND=sw` is the default there and the faster backend. `BACKEND=cx` is
available as on the other devices: 21 s per signature against 3.9 s, without
the flash table and the blinded key scalar. It used to return wrong
signatures on a Nano S and the Makefile refused it (ADR-005); Speculos could
not have shown it: 0.25.5 is the last release with this model and it does
not emulate `cx_mont_*` for it. The cause is the device. Its multiplications
return a wrong value when the result bignum is also an operand, and the
library converts to Montgomery form in place; and it leaves its Montgomery
products unreduced, where the library compared some of them as bignums. The
library works around both on this target and both curves sign correctly on
the device (ADR-011): a self-test of the arithmetic, then the four device
suites of `rs/`.

Speed, on a Nano S with firmware 2.1.0: 28 s per signature with the C code of
the first port. Two changes address it (ADR-004). The field multiplication is
in Thumb-1 assembly, with the same number of cycles for every input, which
the compiled C did not have on this core. The fixed-base multiplication reads
its 16-entry table from flash and no longer keeps a randomized copy of a
table in RAM, which halves its steps and removes the per-entry randomization;
ADR-004 states the side-channel cost and how to go back. Measured with these
two: 12.6 s per signature. Then the signer derives the public key itself,
once, where the handler and the signer each derived it (ADR-006), and
Poseidon comes from the library's tables, in Montgomery form in flash, with
no round-constant generator at run time (ADR-007). Measured with both: 6.2 s
per signature. Then, for the two fields the curves are defined over, the
multiplication reduces with shifts and additions and takes three `MULS` per
product, 192 instead of 520 (ADR-009), and the private scalar is blinded in
the public key derivation (ADR-010): the key is multiplied as
`s + lambda * l`, with a fresh 32-bit `lambda`, so that the entries read
from the flash table differ from one signature to the next. Measured with
both: 3.9 s per signature.
The DKG and FROST commands have been validated on the emulated device only.

Stack left on the emulated device at the deepest command: 888 bytes of 3184
without FROST, 288 of 2904 with it. Three scripts check the budget:

```shell
python3 tools/stackdepth.py build/nanos/bin/app.elf main validate_eddsa_poseidon_sign
python3 tools/nanos_stack_hwm.py build/nanos/bin/app.elf    # Speculos running
STACK_ELF=$PWD/build/nanos/bin/app.elf SIM_BIN=$PWD/tools/speculos_sim_bridge.py \
    cargo test --manifest-path rs/Cargo.toml -p zknox-hw-tests \
    --test dkg --test frost_hw -- --test-threads=1 --nocapture
```

The first gives the static worst case of a call chain from the disassembly
(direct calls only). It follows every call of a function whatever its
arguments, so the two DKG commands that derive the transport key through
`derive_public_key` are charged the BabyJubjub branch they never take;
`--cut derive_public_key:derive_pubkey_babyjubjub` gives their real depth.
The second paints the stack of the emulated device and reports the
high-water mark of each production command. The third does the same for the
DKG and FROST commands while the Rust suite drives the emulated device; with
`HW_PARTICIPANT_BIN` instead of `SIM_BIN` and `--test ceremony`, the device
is one participant of a full ceremony (see [rs/README.md](rs/README.md)).

`python3 src/zknox/tools/mont256_armv6m_check.py --elf build/nanos/bin/app.elf`
runs the assembly multiplication, as a source file and as linked in the
image, in a Cortex-M0+ emulator against the C algorithm, and counts its
cycles. `python3 tools/nanos_cycle_profile.py build/nanos/bin/app.elf --clock 21.8`
does it for a whole signature: it runs the SIGN_WITH_PRIVKEY handler of a
debug image, checks the signature against the reference and gives the cycles
per function, and the time at the clock the device measurements point to.

### Every device at once

```shell
./docker.sh
./build-all.sh                               # every device, both modes
./build-all.sh --prod                        # production only
DEVICES="nanos2 flex" ./build-all.sh         # restrict to those targets
BACKEND=cx ./build-all.sh                    # the syscall backend instead
```

`build-all.sh` discovers the SDKs the container carries, asks the Makefile
for each one's target rather than guessing it from the variable's name, and
builds every device `ledger_app.toml` declares twice:

```text
build/prod/<target>/app.elf  app.apdu  artifact-manifest.txt   MODE=prod,  FROST=0
build/dev/<target>/app.elf   app.apdu  artifact-manifest.txt   MODE=debug, FROST=1
build/toolchain.txt
```

Both trees are committed, each binary beside a manifest naming the commit,
the submodule commit, the backend, the mode, the FROST gate and the ELF's
sha256. The development binaries carry the key-extraction instructions, so
what they are is written down rather than left to be discovered; the point of
publishing them is that anyone testing against this app runs the binary the
suites were run on.

`build/toolchain.txt` records what those binaries were built with — app
version, both commits, and each SDK's path, API level and git describe —
together with the OS of whatever device is attached. That pair is worth
having written down: `make load` refuses a device whose OS was built against
another API level than the SDK, with nothing but `SW 511f` to say so.

The script also holds an invariant the Makefile alone does not.
`build/<target>/bin/` is restaged after every successful build, whatever its
mode, so building `MODE=debug` to flash a test device replaced the staged
release binary with one exposing `BLIND_SIGN_NO_DISPLAY`,
`SIGN_WITH_PRIVKEY` and the DKG key-extraction instructions — and a
`git add -A` afterwards committed it. `build-all.sh` builds the development
tree first and stages production last and explicitly, so that copy is the
production binary whatever order the devices come in:

```shell
grep -h . build/*/bin/configuration.txt      # every line: mode=prod, frost=0
```

## Tests

Standard ragger/Speculos functional tests:

```shell
pip install -r tests/standalone/requirements.txt
make -j BOLOS_SDK=$NANOSP_SDK MODE=debug      # or MODE=prod
cd tests/standalone && pytest -v --device nanosp
```

The suite probes the build it is pointed at rather than assuming one: the
`is_debug_build` and `has_frost` fixtures ask the device which
instructions exist, so the same tests run against every configuration and
skip what is genuinely absent. `MODE=debug FROST=1` runs 115 of them;
`MODE=prod` runs 61 and skips the rest, having first asserted that the
debug surface really is gone.

Three APDU-level suites sit alongside it, checking cryptographic output
against host-side reference implementations rather than the dispatcher
surface. The first two assert the same things over the same APDUs, against
different targets: [`js/`](js/README.md) (node:test, circomlib oracle), where
`./run-js-tests.sh` builds `MODE=debug FROST=1` and boots Speculos in the dev
container, and [`rs/`](rs/README.md) (cargo test, `frost-babyjubjub` oracle),
where `./run-rs-tests.sh` builds [`sim/`](sim/README.md) and pipes the APDUs
to it — no container, no emulator, seconds to run — while
`./run-rs-device-tests.sh` runs that same suite against a physical Ledger,
with the other DKG participants simulated.

The third asserts something else. `./run-sim-tests.sh` links `sim/` into the
test binary rather than spawning it, so an APDU costs a function call instead
of a round trip through a pipe, about three hundred times less. That buys the
checks the other two cannot afford: the whole `(INS, P1, P2)` space swept
against the RFU contract `src/apdu/dispatcher.c` states instruction by
instruction, 16.7 million exchanges in two seconds; key derivation under 32
random seeds in one run; the approval and the refusal path of `BLIND_SIGN` in
one session; a hundred thousand random APDUs. `--san` runs all of it under
AddressSanitizer and UBSan. What it gives up is the process boundary, and with
it the ceremony: the firmware's DKG state is a file static, so one process is
one device.

A full t-of-n ceremony needs n participants, which is why the JavaScript
suite stops at the DKG state machine, the wire shapes and every transition
the device must refuse: one Speculos instance is one device. A simulator is
a process, so `rs/crates/hw-tests/tests/ceremony.rs` runs the whole thing —
DKG, FROST signature, verification — twice: once with every participant on
the canonical yellow×12 seed, which is the shape `./run-rs-device-tests.sh`
reproduces with a Ledger standing in for one of them, and once in pure
software with n, t, the quorum, the message and a 64-byte seed per
participant drawn at random. Both check each announced transport key against
the one its seed derives, every partial signature against the Feldman
commitments, and the aggregate under the circomlib equation.

## Layout

```text
src/
├── app_main.c            APDU loop; any uncaught BOLOS exception exits fail-closed
├── constants.h  sw.h  types.h  globals.h  zkn_features.h
├── zkn_app_config.h      what the app uses of ZKNOX-LibC, and what ZKN_LOW_RAM means for it
├── apdu/dispatcher.c     INS → handler, with RFU validation per instruction
├── handler/
│   ├── handler_keys.c        signing pubkey derivation
│   ├── handler_sign.c        EdDSA-Poseidon, deferred until approval
│   ├── handler_dkg.c         two-round VSS/DKG
│   ├── handler_frost_sign.c  FROST on the DKG output
│   └── handler_version.c
├── helper/send_response.c
├── ui/                   NBGL review screens + the approve/reject actions
└── zknox/                ZKNOX-LibC submodule
tests/
├── application_client/   APDU client and response unpackers
└── standalone/           pytest suite
js/                       APDU-level functional suite (node:test)
rs/
├── crates/frost-babyjubjub/  Rust port of @railgun-reloaded/curves
├── crates/hw-tests/          the js/ suite in Rust (cargo test)
└── crates/zknox-sim/         sim/ linked in: the dispatcher's contract, swept
sim/                      host simulator: the real dispatcher, no emulator
build/
├── prod/<target>/        MODE=prod binaries, with their manifests
├── dev/<target>/         MODE=debug binaries, with their manifests
├── toolchain.txt         SDK API levels and the attached device's OS
└── <target>/bin/         the staged release copy, always production
build-all.sh              every device, both modes
docker.sh                 the Ledger dev container
run-js-tests.sh  run-rs-tests.sh  run-rs-device-tests.sh  run-sim-tests.sh
```

## Licence

Apache 2.0 — see [LICENSE.md](LICENSE.md).
