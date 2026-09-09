#!/usr/bin/env bash
# run-js-tests.sh — build the app, boot Speculos in the Ledger dev container,
# and run the js/ suite against it from the host.
#
# The container has the SDK and Speculos but no node/npm; the host has node but
# not the SDK. So Speculos runs in the container with its APDU port published,
# and `npm test` runs on the host against 127.0.0.1:9999.
#
#   ./run-js-tests.sh              build + run everything
#   ./run-js-tests.sh --no-build   reuse the existing js_dbg.elf
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE=ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
MODEL="${MODEL:-nanosp}"
SDK_VAR="${SDK_VAR:-NANOSP_SDK}"
PORT="${PORT:-9999}"
# The SDK's build directory is named after the target, which is not always the
# speculos model name. Other targets' output may already be sitting in build/,
# so name the one we want rather than globbing.
case "$MODEL" in
    nanosp) BUILD_DIR=nanos2 ;;
    *)      BUILD_DIR="$MODEL" ;;
esac
NAME="zknox-speculos-js-$$"
# The suite's oracles and the restore blob are bound to this seed.
SEED="yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow"

cd "$REPO"

if [ "${1:-}" != "--no-build" ]; then
    echo "── building MODE=debug FROST=1 for $MODEL ──"
    docker run --rm --user "$(id -u):$(id -g)" -v "$REPO:/app" -w /app "$IMAGE" \
        bash -lc "export BOLOS_SDK=\$$SDK_VAR && make MODE=debug FROST=1 -j8 >/dev/null && cp build/$BUILD_DIR/bin/app.elf /app/js_dbg.elf"
fi

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "── starting speculos ($MODEL, APDU on :$PORT) ──"
docker run -d --rm --name "$NAME" --user "$(id -u):$(id -g)" \
    -v "$REPO:/app" -w /app -p "127.0.0.1:$PORT:$PORT" "$IMAGE" \
    speculos --model "$MODEL" --display headless --api-port 0 --apdu-port "$PORT" \
    --seed "$SEED" js_dbg.elf >/dev/null

for _ in $(seq 1 60); do
    (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && { exec 3<&-; break; }
    sleep 0.5
done
sleep 1

echo "── running js suite ──"
cd "$REPO/js"
[ -d node_modules ] || npm install --no-audit --no-fund
SPECULOS_APDU="127.0.0.1:$PORT" npm test
