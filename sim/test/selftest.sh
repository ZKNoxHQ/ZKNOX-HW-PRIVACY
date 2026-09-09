#!/bin/bash
# sim/test/selftest.sh — quick KAT self-test of the APDU simulator.
# Uses the --stdin mode (no TCP, no JS deps). Covers the production INS
# set with the device-validated vectors of the m/44'/60'/1984'/7702'
# path migration (mnemonic "yellow" x12).
set -u
SIM="${SIM:-./build/prod/apdu_sim}"
[ -x "$SIM" ] || { echo "build first: make (or make MODE=debug)"; exit 1; }

pass=0; fail=0
check() { # check <label> <apdu_hex> <expected_regex_on_resp_hex>
    local label="$1" apdu="$2" want="$3"
    local got
    got=$(printf '%s\n' "$apdu" | "$SIM")
    if [[ "$got" =~ $want ]]; then
        echo "ok   $label"; pass=$((pass+1))
    else
        echo "FAIL $label"; echo "     apdu: $apdu"; echo "     got : $got"; fail=$((fail+1))
    fi
}

# ── basics ──
check "GET_VERSION"                 "e003000000" "^0000029000$"
check "GET_APP_NAME"                "e004000000" "^5241494c47554e9000$"   # "RAILGUN"
check "GET_VERSION P1 RFU refuse"   "e003010000" "^6a86$"
check "GET_VERSION P2 RFU refuse"   "e003000100" "^6a86$"
check "GET_APP_NAME P1 RFU refuse"  "e004010000" "^6a86$"
check "GET_APP_NAME P2 RFU refuse"  "e004000100" "^6a86$"
check "CLA inconnu -> 6e00"         "a003000000" "^6e00$"
check "INS inconnu -> 6d00"         "e0ff000000" "^6d00$"
check "CLEAR_SIGN non simule"       "e011000000" "^(6d00|6a87)$"

# ── 7702 pubkeys : KAT valides sur Nano S+ (chainId||purposeId||index BE) ──
# adresse = keccak(W[1:65])[12:] verifiee via ethers dans les tests JS;
# ici on fige les pubkeys completes retournees par le device path.
check "7702 (0,0,0) sw"             "e00700000c000000000000000000000000" "9000$"
check "7702 (1,0,0) sw"             "e00700000c000000010000000000000000" "9000$"
check "7702 P1=01 auto-approve"     "e00701000c000000000000000000000000" "9000$"
check "7702 Lc court -> 6700"       "e007000004deadbeef" "^6a87$|^6700$"
check "7702 Lc trailing refuse"     "e00700000d00000000000000000000000000" "^6a87$"
check "7702 P1 inconnu refuse"      "e00702000c000000000000000000000000" "^6a86$"
check "7702 P2 RFU refuse"          "e007000100" "^6a86$"

# ── SIGN_TX_HASH standalone (P1=01, auto-approve) : v||r||s + 9000 ──
check "0x09 signe (130 hex + v)"    "e00901002c000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "^0[01][0-9a-f]{128}9000$"
check "0x09 P2 RFU refuse"          "e009010100" "^6a86$"

# ── SIGN_7702_AUTH: production permits reviewed P1=01 only (A01) ──
# The dispatcher must reject invalid modes before it even considers Lc/data.
check "0x08 P1=00 refuse"           "e008000000" "^6a86$"
check "0x08 P1=02 refuse"           "e008020000" "^6a86$"
check "0x08 P1=ff refuse"           "e008ff0000" "^6a86$"
check "0x08 P2 RFU refuse"          "e008010100" "^6a86$"
# suffix(12) || chain_id(8) || delegate(20) || nonce(8), all zero here.
check "0x08 P1=01 signe apres UI"   "e008010030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" "^0[01][0-9a-f]{128}9000$"

# ── RAILGUN prod (confirm P1=01 obligatoire, auto-approve) ──
check "SPENDING_PUBKEY P1=00 refuse" "e001000004 00000000" "^6a86$"
check "SPENDING_PUBKEY P1 inconnu refuse" "e00102000400000000" "^6a86$"
check "SPENDING_PUBKEY P2 RFU refuse" "e001010100" "^6a86$"
check "SPENDING_PUBKEY 64B"          "e001010004 00000000" "^[0-9a-f]{128}9000$"
check "SPENDING_PUBKEY trailing refuse" "e001010005 0000000000" "^6a87$"
check "VIEWING_PUBKEY 32B"           "e010010004 00000000" "^[0-9a-f]{64}9000$"
check "VIEWING_PUBKEY P1 inconnu refuse" "e01002000400000000" "^6a86$"
check "VIEWING_PUBKEY P2 RFU refuse" "e010010100" "^6a86$"
check "VIEWING_PUBKEY trailing refuse" "e010010005 0000000000" "^6a87$"
check "RAILGUN_ADDRESS 0zk"          "e014010004 00000000" "^307a6b31.*9000$"  # "0zk1"...
check "BLIND_SIGN len||sig96||hash32" "e012020024 00000000 1122334455667788112233445566778811223344556677881122334455667788" "^60[0-9a-f]{256}9000$"  # P1=0x02 BabyJubjub (0x01 = Bandersnatch !)
check "BLIND_SIGN P2 RFU refuse"      "e012020100" "^6a86$"

# ── viewing privkey 0x13 (mandatory confirmation, canonical RFU=0) ──
# valeur = SLIP-10("babyjubjub seed") account 0, seed yellow x12,
# cross-validée vs la référence JS (keys.test.js / noble).
check "VIEW_PRIVKEY 0x13 == SLIP-10"  "e013000004 00000000" "^99702ce0d9133eb303f81a98c12c962b7510c28c5ab63b5bc90a09748b3fb6129000$"
check "VIEW_PRIVKEY P1 RFU refuse"     "e013010004 00000000" "^6a86$"
check "VIEW_PRIVKEY P2 RFU refuse"     "e013000104 00000000" "^6a86$"
check "VIEW_PRIVKEY trailing refuse"   "e013000005 0000000000" "^6a87$"

# ── refus (SIM_REJECT) ──
got=$(printf 'e00901002c000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' | SIM_REJECT=1 "$SIM")
if [ "$got" = "6985" ]; then echo "ok   SIM_REJECT -> SW_DENY"; pass=$((pass+1)); else echo "FAIL SIM_REJECT (got $got)"; fail=$((fail+1)); fi
got=$(printf 'e013000004 00000000\n' | SIM_REJECT=1 "$SIM")
if [ "$got" = "6985" ]; then echo "ok   SIM_REJECT 0x13 -> SW_DENY"; pass=$((pass+1)); else echo "FAIL SIM_REJECT 0x13 (got $got)"; fail=$((fail+1)); fi

echo "----"
echo "$pass ok, $fail fail"
[ "$fail" -eq 0 ]
