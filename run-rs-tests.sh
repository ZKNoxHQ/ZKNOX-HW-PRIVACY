#!/usr/bin/env bash
# run-rs-tests.sh — build the host simulator and run the rs/ suite against it.
#
# No container, no emulator, no device: sim/ compiles the real dispatcher and
# handlers against the SDK shim, and the Rust suite drives it over a pipe.
#
#   ./run-rs-tests.sh              build sim + run everything
#   ./run-rs-tests.sh --no-build   reuse the existing sim/build/debug/apdu_sim
#
# MODE=debug is required: it compiles BLIND_SIGN_NO_DISPLAY (0x02) and
# SIGN_WITH_PRIVKEY (0x50), and brings FROST=1 with it, which is what the DKG
# and FROST suites need. Against a prod build those instructions answer
# SW_INS_NOT_SUPPORTED and the suite fails rather than skips.
#
# Env passed through to the simulator: SIM_SEED (128 hex, defaults to
# yellow×12), SIM_REJECT, SIM_VERBOSE, SIM_RNG_SEED. SIM_BIN points the suite
# at another binary; with the `hid` feature and no simulator it talks to a
# physical Ledger over USB.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" != "--no-build" ]; then
    echo "── building the simulator (MODE=debug) ──"
    make -C "$REPO/sim" MODE=debug
fi

echo "── running rust suite ──"
# --test-threads=1 mirrors `node --test --test-concurrency=1`: the suites share
# one simulator process and the device has one ceremony state.
cargo test --manifest-path "$REPO/rs/Cargo.toml" -p zknox-hw-tests -- --test-threads=1
