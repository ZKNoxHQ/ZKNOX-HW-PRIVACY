#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────
# docker.sh — Launch the Ledger app dev container for this app.
# ────────────────────────────────────────────────────────────────────

set -euo pipefail

# Resolve the absolute path of the repo root (where this script lives).
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Sanity check: are we in a Ledger app directory?
if [ ! -f "$REPO_DIR/Makefile" ]; then
    echo "ERROR: no Makefile in $REPO_DIR"
    exit 1
fi

# Sanity check: is the submodule checked out?
if [ ! -f "$REPO_DIR/src/zknox/Makefile" ]; then
    echo "WARNING: src/zknox/ appears empty. Initialising submodule..."
    ( cd "$REPO_DIR" && git submodule update --init --recursive )
fi

echo "Mounting:   $REPO_DIR  ->  /app"
echo ""

docker run --rm -ti \
    --user "$(id -u):$(id -g)" \
    --privileged \
    -v /dev/bus/usb:/dev/bus/usb \
    -v "$REPO_DIR:/app" \
    ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
