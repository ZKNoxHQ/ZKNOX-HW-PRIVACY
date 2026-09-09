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

What the suite does **not** do is run a full t-of-n ceremony — that needs
n devices. It covers the DKG state machine, the wire shapes, and every
transition the device must refuse; cross-implementation agreement on the
digest and the partial-signature arithmetic belongs to the libC's own host
tests (`src/zknox/tests/`).

## Layout

```text
src/
├── app_main.c            APDU loop; any uncaught BOLOS exception exits fail-closed
├── constants.h  sw.h  types.h  globals.h  zkn_features.h
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
```

## Licence

Apache 2.0 — see [LICENSE.md](LICENSE.md).
