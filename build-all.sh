#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────
# build-all.sh — every device, twice: production and development.
#
#   ./build-all.sh                 both trees, every device the image has
#   ./build-all.sh --prod          production only
#   ./build-all.sh --dev           development only
#   DEVICES="nanos2 flex" ./build-all.sh      restrict to those targets
#   BACKEND=cx ./build-all.sh      BOLOS cx_bn syscalls instead of software
#
# Runs inside the Ledger dev container, where the SDKs live:
#
#   ./docker.sh
#   ./build-all.sh
#
# Output, beside the namespaced build directories the Makefile already keeps:
#
#   build/prod/<target>/app.elf  app.apdu  artifact-manifest.txt
#   build/dev/<target>/app.elf   app.apdu  artifact-manifest.txt
#   build/toolchain.txt
#
# `prod` is MODE=prod, which carries FROST=0: no debug instructions, no
# ceremony. `dev` is MODE=debug, which implies FROST=1: the test and
# introspection instructions (0x02, 0x50, the silent 0x01 P1=0, 0x68, 0x69)
# and the DKG/FROST set. MODE=prod FROST=1 is a deliberate Makefile error —
# the blocking list is in src/zkn_features.h — so there is no third tree.
#
# One invariant this script exists to hold: build/<target>/bin/, which the
# Makefile stages for the VS Code extension and which other repositories
# consume directly, always ends up holding the PRODUCTION binary. The
# Makefile restages it after every successful build, so a dev build left it
# carrying debug instructions; here the dev tree is built first and prod is
# staged last and explicitly.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"

BUILD_PROD=1
BUILD_DEV=1
for arg in "$@"; do
    case "$arg" in
        --prod) BUILD_DEV=0 ;;
        --dev)  BUILD_PROD=0 ;;
        -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

BACKEND="${BACKEND:-sw}"

# The Makefile announces MODE, FROST and BACKEND through $(info), which goes
# to stdout and would land in anything captured from it. Those lines are
# guarded on these variables, so set them for the query calls only.
# Asks the Makefile for one of its own variables, with the SDK included so
# TARGET and the derived paths are the real ones. Prints nothing and still
# succeeds when make cannot answer, so one unusable SDK does not end the run
# under `set -e`; callers test for an empty answer.
ask() { # ask <sdk> <var> [make vars...]
    local sdk="$1" var="$2"; shift 2
    ZKNOX_MODE_ANNOUNCED=1 ZKNOX_FROST_ANNOUNCED=1 ZKNOX_BACKEND_ANNOUNCED=1 \
        make -s --no-print-directory BOLOS_SDK="$sdk" "$@" \
        --eval "zkn-ask: ; @echo \$($var)" zkn-ask 2>/dev/null | tail -1 || true
}

# ── which SDKs are available ────────────────────────────────────────
# Discovered from the environment rather than hardcoded, so a device the
# image adds later needs no change here. A *_SDK variable counts when it
# points at a directory carrying Makefile.target.
declare -a SDKS=()
while IFS='=' read -r name value; do
    [ -n "${value:-}" ] || continue
    [ -f "$value/Makefile.target" ] || continue
    SDKS+=("$value")
done < <(env | grep -E '^[A-Z0-9_]+_SDK=' | sort -u)

if [ "${#SDKS[@]}" -eq 0 ]; then
    cat >&2 <<'MSG'
No Ledger SDK found in the environment.

This script builds for every device, which needs the SDKs of the Ledger dev
container:

    ./docker.sh
    ./build-all.sh

Outside the container, BOLOS_SDK=/path/to/sdk make also works for a single
device.
MSG
    exit 1
fi

# Devices this app declares. ledger_app.toml is the source of truth; its
# names are the manifest's, which differ from the Makefile's TARGET for the
# Nano S Plus ("nanos+" there, "nanos2" everywhere else).
manifest_targets() {
    sed -n 's/^devices *= *\[\(.*\)\].*/\1/p' ledger_app.toml \
        | tr -d '" ' | tr ',' '\n' | while read -r d; do
        case "$d" in
            "") continue ;;
            nanos+) echo nanos2 ;;
            *) echo "$d" ;;
        esac
    done
}
SUPPORTED="$(manifest_targets | tr '\n' ' ')"
WANTED="${DEVICES:-}"

echo "── backend $BACKEND, devices declared: $SUPPORTED──"

declare -a BUILT=() SKIPPED=() FAILED=()

# ── one (sdk, mode) pair ────────────────────────────────────────────
build_one() { # build_one <sdk> <target> <mode> <tree>
    local sdk="$1" target="$2" mode="$3" tree="$4"
    local out="build/$tree/$target"

    echo
    echo "── $target: $tree (MODE=$mode) ──"
    if ! make -j BOLOS_SDK="$sdk" MODE="$mode" BACKEND="$BACKEND"; then
        FAILED+=("$target/$tree")
        return 1
    fi
    # Provenance beside the ELF: target, backend, mode, frost, both commits
    # and the ELF's sha256, written by the Makefile itself.
    make BOLOS_SDK="$sdk" MODE="$mode" BACKEND="$BACKEND" artifact-manifest

    local bindir
    bindir="$(ask "$sdk" BIN_DIR MODE="$mode" BACKEND="$BACKEND")"
    if [ ! -f "$bindir/app.elf" ]; then
        echo "   $bindir/app.elf missing after a successful build" >&2
        FAILED+=("$target/$tree")
        return 1
    fi
    mkdir -p "$out"
    cp "$bindir/app.elf" "$bindir/app.apdu" "$out/"
    [ -f "$bindir/artifact-manifest.txt" ] && cp "$bindir/artifact-manifest.txt" "$out/"
    echo "   → $out/"
    BUILT+=("$target/$tree")
    return 0
}

# ── the loop ────────────────────────────────────────────────────────
for sdk in "${SDKS[@]}"; do
    target="$(ask "$sdk" TARGET)"
    if [ -z "$target" ]; then
        echo "   $sdk: cannot determine TARGET, skipped" >&2
        SKIPPED+=("$sdk")
        continue
    fi
    case " $SUPPORTED " in
        *" $target "*) ;;
        *) SKIPPED+=("$target (not in ledger_app.toml)"); continue ;;
    esac
    if [ -n "$WANTED" ]; then
        case " $WANTED " in
            *" $target "*) ;;
            *) SKIPPED+=("$target (not in DEVICES)"); continue ;;
        esac
    fi

    # Dev first, production last: the Makefile restages build/<target>/bin
    # after every successful build, and that copy must end up being prod.
    [ "$BUILD_DEV" = 1 ]  && build_one "$sdk" "$target" debug dev || true
    [ "$BUILD_PROD" = 1 ] && build_one "$sdk" "$target" prod prod || true

    if [ "$BUILD_PROD" = 1 ] && [ -f "build/prod/$target/app.elf" ]; then
        stage="$(ask "$sdk" LEDGER_EXTENSION_BIN_DIR)"
        mkdir -p "$stage"
        cp "build/prod/$target/app.elf" "build/prod/$target/app.apdu" "$stage/"
        printf 'backend=%s\nmode=prod\nfrost=0\n' "$BACKEND" > "$stage/configuration.txt"
        echo "   staged production into $stage/"
    fi
done

# ── build/toolchain.txt ─────────────────────────────────────────────
# What the binaries beside it were built with, and what the attached device
# runs. The pair is the thing worth recording: `make load` refuses a device
# whose OS was built against another API level than the SDK (SW 511f), and
# this file is where to look when it does.
sdk_api_level() { # best effort, several SDK layouts
    local sdk="$1" v=""
    [ -f "$sdk/API_LEVEL" ] && v="$(tr -d ' \n' < "$sdk/API_LEVEL")"
    [ -z "$v" ] && v="$(grep -hoE '^[[:space:]]*API_LEVEL[[:space:]]*[:?]?=[[:space:]]*[0-9]+' \
        "$sdk"/Makefile.defines "$sdk"/Makefile.standard_app 2>/dev/null \
        | grep -oE '[0-9]+$' | head -1)"
    echo "${v:-unknown}"
}

TOOLCHAIN=build/toolchain.txt
mkdir -p build
{
    echo "# generated by ./build-all.sh"
    echo "generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # APPNAME and APPVERSION need an SDK too, the Makefile including
    # $(BOLOS_SDK)/Makefile.target before it defines anything. Read straight
    # out of the Makefile when no SDK answers, so this file is never blank
    # about what it describes.
    app_name="$(ask "${SDKS[0]}" APPNAME | tr -d '"')"
    app_version="$(ask "${SDKS[0]}" APPVERSION | tr -d '"')"
    [ -n "$app_name" ] || app_name="$(sed -n 's/^APPNAME *= *"\?\([^"]*\)"\? *$/\1/p' Makefile | head -1)"
    if [ -z "$app_version" ]; then
        app_version="$(sed -n 's/^APPVERSION_[MNP] *= *\([0-9]*\).*/\1/p' Makefile | paste -sd. -)"
    fi
    echo "app_name=$app_name"
    echo "app_version=$app_version"
    echo "backend=$BACKEND"
    echo "commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "zknox_commit=$(git -C src/zknox rev-parse HEAD 2>/dev/null || echo unknown)"

    for sdk in "${SDKS[@]}"; do
        target="$(ask "$sdk" TARGET)"
        [ -n "$target" ] || continue
        echo
        echo "[sdk $target]"
        echo "path=$sdk"
        echo "api_level=$(sdk_api_level "$sdk")"
        echo "git=$(git -C "$sdk" describe --tags --always --dirty 2>/dev/null || echo unknown)"
    done

    echo
    echo "[device]"
    # The OS of whatever is plugged in, if anything answers. Needs the device
    # on the dashboard; a failure here is normal and not an error.
    if out="$(python3 -m ledgerblue.getVersion 2>/dev/null)"; then
        echo "$out" | sed 's/^/  /'
    else
        echo "  none attached, or not on the dashboard"
    fi
} > "$TOOLCHAIN"

echo
echo "── $TOOLCHAIN ──"
sed 's/^/   /' "$TOOLCHAIN"

echo
echo "── summary ──"
[ "${#BUILT[@]}"   -gt 0 ] && printf '   built   %s\n' "${BUILT[@]}"
[ "${#SKIPPED[@]}" -gt 0 ] && printf '   skipped %s\n' "${SKIPPED[@]}"
[ "${#FAILED[@]}"  -gt 0 ] && printf '   FAILED  %s\n' "${FAILED[@]}"
[ "${#FAILED[@]}" -eq 0 ]
