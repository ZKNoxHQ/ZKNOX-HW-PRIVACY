# JS functional tests

Node `node:test` suites driving the app over raw APDUs. Ported from the RAILGUN
app, trimmed to the instructions this firmware actually dispatches: **FROST/DKG**
and **blind signing**. Everything RAILGUN-specific (clear-sign, viewing key,
secp256k1/7702, shield, on-chain vectors) is absent because the C code here has
no handler for it.

These complement `tests/standalone/` (Ragger/pytest, UI navigation and the
dispatcher surface) — this suite is APDU-level and checks cryptographic output
against host-side reference implementations.

## Run

```sh
../run-js-tests.sh              # build MODE=debug FROST=1, boot Speculos, run
../run-js-tests.sh --no-build   # reuse the existing js_dbg.elf
```

The script exists because the work is split across two environments: the Ledger
dev container has the SDK and Speculos but no node; the host has node but no
SDK. So Speculos runs in the container with its APDU port published, and the
suite runs on the host against `127.0.0.1:9999`.

To drive it yourself:

```sh
SPECULOS_APDU=127.0.0.1:9999 npm test     # against a running Speculos
npm test                                   # against a physical Ledger over USB HID
INTERACTIVE=1 npm test                     # also run the tests needing button presses
```

`MODEL=flex SDK_VAR=FLEX_SDK ../run-js-tests.sh` switches device.

## Build flags this suite requires

| Flag | Why |
|---|---|
| `FROST=1` | compiles the DKG ceremony (0x60–0x6b) and FROST signing (0x70–0x72) |
| `MODE=debug` | compiles `BLIND_SIGN_NO_DISPLAY` (0x02), `SIGN_WITH_PRIVKEY` (0x50), and the silent `SIGNING_PUBKEY` P1=0 |

Against a `MODE=prod FROST=0` build these instructions answer
`SW_INS_NOT_SUPPORTED` and the suite fails rather than skips — that asymmetry is
deliberate, since a silent skip would hide a firmware built the wrong way.

## Seed

Every suite assumes the device holds the **yellow×12** mnemonic
(`yellow` twelve times). `run-js-tests.sh` passes it to Speculos. Two things are
bound to it:

- `HK_YELLOW_ACCT0` in `test/dkg.test.js` — the DKG transport pubkey oracle.
  Captured from this app on Speculos; it matches the value the RAILGUN app
  produces, since both derive `KEY_TYPE_DKG_COMM` down the same libC path
  (`m/421'/1984'/account'/0'/0'`).
- `test/fixtures/restore-blob-yellow.hex` — a 2-of-3 backup blob (`t=2, n=3,
  id=1`), taken from the RAILGUN repo and verified to restore on this firmware.
  It only decrypts on a device holding the seed it was exported from.

Set `SEED=<anything else>` to skip the two seed-bound assertions.

## What each file covers

| File | Covers |
|---|---|
| `test/dkg.test.js` | `GET_COMM_PUBKEY` determinism + oracle, separation from the signing key, `STATUS`/`ABORT`, `DEAL` shape, the round-1 barrier, `RESTORE_SHARE` incl. GCM-tag rejection |
| `test/frost-hw.test.js` | `EXPORT_SHARE` shape and nonce freshness, export/restore round-trip stability, `FROST_HW_COMMIT`, and the three `FROST_HW_SIGN` guards (state, quorum size, membership) |
| `test/sign.test.js` | `BLIND_SIGN_NO_DISPLAY` and `SIGN_WITH_PRIVKEY` byte-matched against circomlib; `BLIND_SIGN` behind `INTERACTIVE=1` |

## Deliberate omissions

- **No happy-path FROST signature.** A valid one needs `t` co-signers'
  commitments, so it belongs to a multi-device setup. What is here are the
  guards, which a single device can reach and where handler bugs hide.
- **No full DKG ceremony.** `g_dkg` lives in RAM, so `DEAL→FINALIZE` only makes
  sense inside one transport session with `n` participants. `RESTORE_SHARE` is
  the shortcut that gets a device to `PROVISIONED` without one.
- **No fixture generator.** RAILGUN's `gen-restore-blob.mjs` drives three
  instances of its host-side APDU simulator, which this repo does not have. To
  regenerate the blob here you would need three Speculos instances on different
  seeds and a ceremony aggregator.
