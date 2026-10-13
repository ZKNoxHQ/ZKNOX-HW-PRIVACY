#!/usr/bin/env python3
"""Compares the Rust and JavaScript cross-check results, per function.

Success rules:
  - both succeeded  -> outputs must be deeply equal
  - both failed     -> agreement (messages are reported but not required to
                       match, since some come from third-party libraries)
  - one of the two  -> mismatch

Usage: python3 compare.py <rust.json> <js.json> [--verbose]
"""

import json
import sys
from collections import defaultdict


def load(path):
    return {r["id"]: r for r in json.load(open(path))}


def main():
    rust = load(sys.argv[1])
    js = load(sys.argv[2])
    verbose = "--verbose" in sys.argv

    stats = defaultdict(lambda: {"n": 0, "ok": 0, "bothErr": 0, "bad": []})
    for cid, r in rust.items():
        j = js.get(cid)
        s = stats[r["op"]]
        s["n"] += 1
        if j is None:
            s["bad"].append((cid, "missing in js", None))
            continue
        if r["ok"] and j["ok"]:
            if r["out"] == j["out"]:
                s["ok"] += 1
            else:
                s["bad"].append((cid, r["out"], j["out"]))
        elif not r["ok"] and not j["ok"]:
            s["bothErr"] += 1
            s["ok"] += 1
        else:
            s["bad"].append(
                (cid, f"rust {'ok' if r['ok'] else r.get('err')}", f"js {'ok' if j['ok'] else j.get('err')}")
            )

    width = max(len(op) for op in stats)
    failed = 0
    for op in sorted(stats):
        s = stats[op]
        bad = len(s["bad"])
        failed += bad
        flag = "OK  " if bad == 0 else "FAIL"
        print(f"{flag} {op.ljust(width)}  {s['ok']:>3}/{s['n']:<3} match"
              f"  ({s['bothErr']} both-error)")
        if bad and verbose:
            for cid, a, b in s["bad"][:3]:
                print(f"       #{cid}\n         rust: {a}\n         js  : {b}")

    total = sum(s["n"] for s in stats.values())
    print(f"\n{len(stats)} functions, {total} cases, {total - failed} matching, {failed} mismatching")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
