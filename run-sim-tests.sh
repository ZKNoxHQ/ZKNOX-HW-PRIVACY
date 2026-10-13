#!/usr/bin/env bash
# run-sim-tests.sh — the third test set: the simulator linked into the test
# binary rather than spawned.
#
#   ./run-sim-tests.sh                 the suite
#   ./run-sim-tests.sh --san           the same under AddressSanitizer + UBSan
#   ./run-sim-tests.sh --prod          against a MODE=prod FROST=1 build
#   ./run-sim-tests.sh --prod --san    both
#
# `rs/crates/zknox-sim` compiles sim/ into a static archive and calls the real
# dispatcher through FFI, so an APDU costs a function call instead of a round
# trip through a pipe: about three hundred times faster, measured by
# `cargo test -p zknox-sim --test throughput -- --ignored --nocapture`. That is
# what pays for what this set checks and the other two cannot:
#
#   - the whole (INS, P1, P2) space, 16.7 million exchanges, against the RFU
#     contract src/apdu/dispatcher.c states instruction by instruction;
#   - key derivation under 32 random seeds in one run, the seed being a setter
#     here rather than an environment variable read once at startup;
#   - the approval and the refusal path of BLIND_SIGN in one session;
#   - a hundred thousand random APDUs, checking the dispatcher always answers
#     a status word src/sw.h declares.
#
# What it cannot do is a t-of-n ceremony: the firmware's DKG state is a file
# static, so one process is one device. That stays in ./run-rs-tests.sh.
#
# Needs a C toolchain and the src/zknox submodule; build.rs drives sim/Makefile
# so the compile flags have one home.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE=debug
SAN=0
for arg in "$@"; do
    case "$arg" in
        --san)  SAN=1 ;;
        --prod) MODE=prod ;;
        --debug) MODE=debug ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

export ZKNOX_SIM_MODE="$MODE"
export ZKNOX_SIM_FROST=1
[ "$SAN" = 1 ] && export ZKNOX_SIM_ASAN=1

echo "── linked simulator: MODE=$MODE FROST=1${SAN:+ SAN=$SAN} ──"
# No --test-threads=1: the device is behind a mutex in the crate, so the
# suites serialize themselves.
cargo test --manifest-path "$REPO/rs/Cargo.toml" -p zknox-sim
