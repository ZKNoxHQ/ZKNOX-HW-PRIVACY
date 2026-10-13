#!/usr/bin/env bash
# run-rs-device-tests.sh — the rs/ suite against a physical Ledger, with the
# other DKG participants simulated.
#
#   ./run-rs-device-tests.sh              build the simulator, then run
#   ./run-rs-device-tests.sh --no-build   reuse sim/build/debug/apdu_sim
#
# What runs where:
#   - dkg, frost_hw, sign          the device, over USB HID
#   - ceremony (canonical)         the device is participant 1 of a 2-of-3 DKG;
#                                  participants 2 and 3 are simulator processes
#                                  on the same yellow×12 seed
#   - ceremony (random seeds)      host only: a physical device cannot be handed
#                                  a seed, so this one stays pure software even
#                                  here
#   - oracle, transport            host only, no device
#
# Requirements on the device:
#   - firmware built MODE=debug FROST=1 (0x02, 0x50, the silent 0x01 P1=0 and
#     the DKG/FROST instructions). Against a prod build these answer
#     SW_INS_NOT_SUPPORTED and the suite fails rather than skips.
#   - unlocked, the app open, and seeded with the yellow×12 mnemonic — the
#     comm-key oracle and the restore blob are bound to it. Another seed:
#     prefix with SEED=other to skip those two assertions.
#
# The canonical ceremony needs that same seed for a different reason: it checks
# every participant's announced transport key against the one its seed derives
# host-side, and the device's seed is the one thing here that cannot be set
# from the outside. A device on another seed fails that check by name.
#
# Nothing is written to flash: the DKG share lives in RAM (see
# src/zkn_features.h), so the ceremony leaves the device as it found it, bar
# a power cycle.
#
#   HW_PARTICIPANT_ID=2 ./run-rs-device-tests.sh   device plays another id
#   INTERACTIVE=1 ./run-rs-device-tests.sh         also the button-press test
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The `hid` feature builds hidapi, whose hidraw backend enumerates devices
# through libudev on Linux. Without the development package cargo fails forty
# lines into a build-script panic, so the check happens here instead.
# Environment handed to cargo only, so the simulator's own build is untouched.
HID_ENV=()

missing_libudev() {
    cat >&2 <<'MSG'
libudev development files are missing; hidapi cannot build without them.

    sudo apt install libudev-dev pkg-config     # Debian, Ubuntu
    sudo dnf install systemd-devel pkgconf      # Fedora, RHEL
    sudo pacman -S systemd-libs pkgconf         # Arch

If the package IS installed and this still fires, the toolchain on PATH
cannot see it: a conda, miniforge or homebrew prefix comes with its own
pkg-config and its own sysroot, and neither looks in /usr. Run outside that
environment (`conda deactivate`), or name the system tools:

    PKG_CONFIG=/usr/bin/pkg-config CC=/usr/bin/cc ./run-rs-device-tests.sh
MSG
    exit 1
}

if [ "$(uname -s)" = "Linux" ]; then
    # Two independent things have to find libudev, and a conda-style prefix
    # breaks both: pkg-config, which tells cargo where the library is, and the
    # C compiler cc-rs then uses to build hidapi's hid.c against its header.
    # Each is checked, and the system tool is used when the one on PATH cannot
    # see a library that is installed — but never over an explicit choice.
    if ! "${PKG_CONFIG:-pkg-config}" --exists libudev 2>/dev/null; then
        if [ -n "${PKG_CONFIG:-}" ] || ! /usr/bin/pkg-config --exists libudev 2>/dev/null; then
            missing_libudev
        fi
        echo "── pkg-config on PATH ($(command -v pkg-config)) does not see libudev;" >&2
        echo "   using /usr/bin/pkg-config, which does ──" >&2
        HID_ENV+=(PKG_CONFIG=/usr/bin/pkg-config)
    fi

    if ! echo '#include <libudev.h>' | "${CC:-cc}" -fsyntax-only -x c - 2>/dev/null; then
        if [ -n "${CC:-}" ] || ! echo '#include <libudev.h>' | /usr/bin/cc -fsyntax-only -x c - 2>/dev/null; then
            missing_libudev
        fi
        echo "── $(command -v cc) cannot reach libudev.h (its own sysroot);" >&2
        echo "   using /usr/bin/cc, which can ──" >&2
        HID_ENV+=(CC=/usr/bin/cc)
    fi
fi

if [ "${1:-}" != "--no-build" ]; then
    echo "── building the simulator for the other participants (MODE=debug) ──"
    make -C "$REPO/sim" MODE=debug
fi

echo "── running rust suite against the device (USB HID) ──"
echo "   plug in the Ledger, unlock it and open the app"
# HW_DEVICE puts the physical device first for the single-device suites and
# makes it participant HW_PARTICIPANT_ID (1 by default) of the ceremony.
# --test-threads=1 because the suites share one device handle and the device
# has one ceremony state.
HW_DEVICE=1 env "${HID_ENV[@]}" cargo test --manifest-path "$REPO/rs/Cargo.toml" \
    -p zknox-hw-tests --features hid -- --test-threads=1 --nocapture
