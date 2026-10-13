#!/bin/bash
# sim/test/selftest.sh — quick KAT self-test of the APDU simulator.
#
# Line protocol on stdin/stdout, no JS, no device. Covers the dispatcher
# surface this app actually has, with the seed every suite assumes
# (mnemonic "yellow" x12, the simulator's default).
#
# The DEBUG-only instructions (0x02 BLIND_SIGN_NO_DISPLAY, 0x50
# SIGN_WITH_PRIVKEY) and the DKG/FROST set are checked when the binary under
# test carries them; against a prod build those checks are skipped, not failed.
#
#   make test             # MODE=prod
#   make MODE=debug test  # the full set
set -u
SIM="${SIM:-./build/debug/apdu_sim}"
[ -x "$SIM" ] || SIM=./build/prod/apdu_sim
[ -x "$SIM" ] || { echo "build first: make (or make MODE=debug)"; exit 1; }

pass=0; fail=0; skip=0
send() { printf '%s\n' "$1" | "$SIM"; }
check() { # check <label> <apdu_hex> <expected_regex_on_resp_hex>
    local label="$1" apdu="$2" want="$3" got
    got=$(send "$apdu")
    if [[ "$got" =~ $want ]]; then
        echo "ok   $label"; pass=$((pass+1))
    else
        echo "FAIL $label"; echo "     apdu: $apdu"; echo "     got : $got"; fail=$((fail+1))
    fi
}
check_opt() { # same, but a 6d00/6e00 answer means the build lacks the INS
    local label="$1" apdu="$2" want="$3" got
    got=$(send "$apdu")
    case "$got" in
        6d00|6e00|6a86) echo "skip $label (not in this build)"; skip=$((skip+1)); return;;
    esac
    if [[ "$got" =~ $want ]]; then
        echo "ok   $label"; pass=$((pass+1))
    else
        echo "FAIL $label"; echo "     apdu: $apdu"; echo "     got : $got"; fail=$((fail+1))
    fi
}

MSG=8c1f26718227707c6e5c61417b47daccafabca9f574c16e1521dd6a9c70d8405

# ── basics ──
check "GET_VERSION"               "e003000000" "^0001009000$"
check "GET_APP_NAME"              "e004000000" "^5a4b4e4f589000$"   # "ZKNOX"
check "GET_VERSION P1 RFU refuse" "e003010000" "^6a86$"
check "unknown INS refused"       "e0ff000000" "^6[de]00$"

# ── keys: the signing pubkey is a deterministic function of the seed. The
#    silent P1=0 variant is DEBUG-only; P1=1 goes through the review screen,
#    which the simulator approves. ──
check     "SIGNING_PUBKEY confirm" "e00101000400000000" \
    "^090c08681bf4538b88c616e2ecda023fe7ca89fc952e3baa3eeddfdc14e33f281e8cfa233cded8ddd6f5dd2936382cade20578d3dcb6bb58303ea07e69bc87ab9000$"
check_opt "SIGNING_PUBKEY silent"  "e00100000400000000" "^[0-9a-f]{128}9000$"

# ── DKG transport identity, the yellow×12 oracle shared with js/ and rs/ ──
check_opt "DKG_GET_COMM_PUBKEY" "e06000000400000000" \
    "^9fc8d2779ee5bfb7662e02b5c8e23c71a4de3045621b15e031cbe481687de0819000$"
check_opt "DKG_STATUS idle"     "e067000000" "^00[0-9a-f]{10}9000$"
check_opt "DKG_ABORT"           "e066000000" "^9000$"
check_opt "GET_SHARE before COMMITTED refused" "e06300000102" "^b007$"

# ── EdDSA-Poseidon, against the vector js/test/sign.test.js and
#    rs/crates/hw-tests/tests/sign.rs both check the device on ──
check_opt "BLIND_SIGN_NO_DISPLAY" "e00200002400000000${MSG}" \
    "^2954bb04ccd89f65b27b7912fa447925972286de0bf4161b2b3260cadea5a4ed2b6c8873579e9805c1a15519e8ad9f2d9d30f7d95fc5a3ac5706d9b9944d191905b15ff1bd5a2c2f9cc0bc033aa8c14de3410ac82d93c8477d42a493575b54279000$"

# ── the approval path: BLIND_SIGN returns len(1)||sig(96)||echo(32) ──
check "BLIND_SIGN approved" "e01200002400000000${MSG}" \
    "^60[0-9a-f]{192}${MSG}9000$"

# ── and the refusal path, which only the simulator can drive unattended ──
got=$(SIM_REJECT=1 send "e01200002400000000${MSG}")
if [[ "$got" =~ ^6985$ ]]; then
    echo "ok   BLIND_SIGN refused under SIM_REJECT"; pass=$((pass+1))
else
    echo "FAIL BLIND_SIGN refused under SIM_REJECT"; echo "     got : $got"; fail=$((fail+1))
fi

echo
echo "$pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
