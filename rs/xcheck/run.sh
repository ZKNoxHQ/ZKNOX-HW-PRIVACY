#!/usr/bin/env bash
# Cross-checks the Rust crate against the TypeScript library.
#
#   CURVES_DIR=/path/to/curves ./xcheck/run.sh [cases-per-op] [ceremonies]
#
# CURVES_DIR must be a built checkout (npm install && npm run build).
set -euo pipefail

CASES="${1:-32}"
CEREMONIES="${2:-32}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
: "${CURVES_DIR:?set CURVES_DIR to the curves package root}"
OUT="$(mktemp -d)"

echo "== building"
cargo build --release --manifest-path "$ROOT/Cargo.toml"

echo "== generating $CASES vectors per function (OS CSPRNG)"
( cd "$HERE" && CURVES_DIR="$CURVES_DIR" python3 gen_vectors.py "$OUT/vectors.json" "$CASES" )

echo "== running both implementations"
"$ROOT/target/release/xcheck" "$OUT/vectors.json" "$OUT/rust.json"
cp "$HERE/js_runner.mjs" "$CURVES_DIR/.xcheck_runner.mjs"
( cd "$CURVES_DIR" && node .xcheck_runner.mjs "$OUT/vectors.json" "$OUT/js.json" )

echo "== comparing"
python3 "$HERE/compare.py" "$OUT/rust.json" "$OUT/js.json"

echo "== $CEREMONIES ceremonies each way"
cp "$HERE/ceremony_js.mjs" "$CURVES_DIR/.ceremony_js.mjs"
"$ROOT/target/release/ceremony" run "$CEREMONIES" "$OUT/rust-ceremony.json"
( cd "$CURVES_DIR" && node .ceremony_js.mjs run "$CEREMONIES" "$OUT/js-ceremony.json" )
( cd "$CURVES_DIR" && node .ceremony_js.mjs verify "$OUT/rust-ceremony.json" )
"$ROOT/target/release/ceremony" verify "$OUT/js-ceremony.json"

echo "== $CEREMONIES snapshot sets each way"
"$ROOT/target/release/ceremony" snapshots "$CEREMONIES" "$OUT/rust-snap.json"
( cd "$CURVES_DIR" && node .ceremony_js.mjs snapshots "$CEREMONIES" "$OUT/js-snap.json" )
( cd "$CURVES_DIR" && node .ceremony_js.mjs verify-snapshots "$OUT/rust-snap.json" )
"$ROOT/target/release/ceremony" verify-snapshots "$OUT/js-snap.json"

echo "== $CEREMONIES signing snapshot sets each way"
"$ROOT/target/release/ceremony" signing-snapshots "$CEREMONIES" "$OUT/rust-sig.json"
( cd "$CURVES_DIR" && node .ceremony_js.mjs signing-snapshots "$CEREMONIES" "$OUT/js-sig.json" )
( cd "$CURVES_DIR" && node .ceremony_js.mjs verify-signing-snapshots "$OUT/rust-sig.json" )
"$ROOT/target/release/ceremony" verify-signing-snapshots "$OUT/js-sig.json"

echo "== ok ($OUT)"
