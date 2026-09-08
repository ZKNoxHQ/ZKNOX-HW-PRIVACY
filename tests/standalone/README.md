# Standalone functional tests

Ragger + Speculos tests for the app launched from the device dashboard.

## Running them

```shell
pip install -r requirements.txt
# from the repo root, inside ./docker.sh:
#   make -j BOLOS_SDK=$NANOSP_SDK MODE=debug
pytest -v --tb=short --device nanosp
```

`--device` takes `nanox`, `nanosp`, `stax`, `flex`, `apex_p` or `all`. Add
`--display` to watch the screens go by.

Ragger picks the binary up from `build/<target>/bin/app.elf`, which the
Makefile stages after every successful build.

## What runs where

The suite has no view of the make flags the binary was built with, so it
asks the device instead. `conftest.py` probes for a debug-only instruction
and for `DKG_STATUS`, and exposes the answers as the `is_debug_build` and
`has_frost` fixtures; the `debug_only` and `frost_only` fixtures skip on
them. The same command therefore works against any configuration:

| Build | Passed | Skipped |
|-------|--------|---------|
| `MODE=debug FROST=1` | 115 | 5 (the prod-absence assertions) |
| `MODE=prod` | 61 | 59 (DKG/FROST and the debug cross-checks) |

## Files

| File | Covers |
|------|--------|
| `test_name_version.py` | `GET_APP_NAME`, `GET_VERSION`, the BOLOS-level `0xB0 0x01`, RFU bytes |
| `test_pubkey_cmd.py` | `SIGNING_PUBKEY`: approve, reject, determinism, on-curve, bad P1/P2/length |
| `test_blind_sign_cmd.py` | `BLIND_SIGN`: approve, reject, what the signature depends on, error paths |
| `test_dkg_cmd.py` | the DKG state machine, wire shapes, and every transition it must refuse |
| `test_frost_sign_cmd.py` | the FROST guard rails: no signing without a share, no signing without nonces |
| `test_dispatcher.py` | bad CLA, unknown INS, and that the debug surface is absent from a prod build |

## Snapshots

The UI tests pass `do_comparison=False`: they walk every review page, so a
handler that crashes mid-review still fails the test, but they do not check
pixel-exact golden images. To turn that on, drop the argument and run once
with `--golden_run` to capture into `snapshots/<device>/<test_name>/`.

## What is deliberately not here

A full t-of-n DKG needs n devices, and one Speculos instance is one device.
These tests establish what a single device is answerable for on its own.
Cross-implementation agreement — does this device's commitments digest
match the host reference, does a quorum of partial signatures aggregate to
a valid signature — belongs to the libC host tests in `src/zknox/tests/`,
which have the curve arithmetic to hand.
