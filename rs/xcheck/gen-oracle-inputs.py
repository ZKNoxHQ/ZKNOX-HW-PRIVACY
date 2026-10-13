#!/usr/bin/env python3
"""Random inputs for the oracle vectors, drawn from the OS CSPRNG.

    python3 rs/xcheck/gen-oracle-inputs.py <out.json> [count]

Kept separate from the generator so the values come from `secrets`, not from
whatever randomness the JavaScript side happens to use.
"""
import json
import secrets
import sys

out_path = sys.argv[1]
count = int(sys.argv[2]) if len(sys.argv) > 2 else 32

WORDS = ["yellow", "abandon", "zoo", "legal", "winner", "thank", "sausage", "letter"]

signatures = [
    {"priv": secrets.token_bytes(32).hex(), "msg": secrets.token_bytes(32).hex()}
    for _ in range(count)
]

derivations = [{"mnemonic": "yellow " * 11 + "yellow", "path": [44, 1984, 0, 0, 0]}]
for _ in range(count - 1):
    mnemonic = " ".join(secrets.choice(WORDS) for _ in range(12))
    path = [secrets.randbelow(2048) for _ in range(1 + secrets.randbelow(5))]
    derivations.append({"mnemonic": mnemonic, "path": path})

with open(out_path, "w") as f:
    json.dump({"signatures": signatures, "derivations": derivations}, f)
print(f"{len(signatures)} signatures, {len(derivations)} derivations -> {out_path}")
