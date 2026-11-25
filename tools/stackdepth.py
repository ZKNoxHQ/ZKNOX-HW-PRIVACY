#!/usr/bin/env python3
"""Worst-case stack depth of a Thumb ELF from its disassembly.

Frame size per function = pushes + 'sub sp' (+ literal-loaded 'add sp, rX').
Edges = direct bl / tail b to another function. Indirect calls (blx rX) are
reported, not followed. Recursion is reported and cut.
"""
import re, subprocess, sys, collections

elf = sys.argv[1]
roots = sys.argv[2:]
dis = subprocess.run(["arm-none-eabi-objdump", "-d", "--no-show-raw-insn", elf],
                     capture_output=True, text=True, check=True).stdout
funcs = collections.OrderedDict()
cur = None
for line in dis.splitlines():
    m = re.match(r"^([0-9a-f]+) <([^>]+)>:$", line)
    if m:
        cur = m.group(2)
        funcs[cur] = {"addr": int(m.group(1), 16), "ins": []}
        continue
    m = re.match(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
    if m and cur:
        funcs[cur]["ins"].append((int(m.group(1), 16), m.group(2), m.group(3)))

def literal(addr_txt, f):
    # objdump prints "ldr r4, [pc, #x] @ (addr <sym+off>)" ; value sits in a .word line
    m = re.search(r"@ \(([0-9a-f]+)", addr_txt)
    if not m:
        return None
    a = int(m.group(1), 16)
    for ia, op, args in f["ins"]:
        if ia == a and op == ".word":
            return int(args.split()[0], 16)
    return None

info = {}
for name, f in funcs.items():
    frame = 0; maxframe = 0
    calls = set(); indirect = 0
    regs = {}
    for ia, op, args in f["ins"]:
        base = op.split(".")[0]
        if base == "push":
            n = len([r for r in re.findall(r"r\d+|lr|sl|fp|ip|sb", args)])
            frame += 4 * n
        elif base in ("sub", "subs") and args.replace(" ", "").startswith("sp,#"):
            frame += int(args.split("#")[1].split()[0].rstrip(";"), 0)
        elif base in ("sub", "subs") and re.match(r"sp,\s*sp,\s*#", args):
            frame += int(args.split("#")[1].split()[0], 0)
        elif base == "ldr" and "[pc" in args:
            r = args.split(",")[0].strip()
            v = literal(args, f)
            if v is not None:
                regs[r] = v
        elif base == "add" and re.match(r"sp,\s*(r\d+)$", args.strip()):
            r = args.split(",")[1].strip()
            v = regs.get(r)
            if v is not None and v & 0x80000000:
                frame += (1 << 32) - v
        elif base in ("bl", "b", "blx") or (base.startswith("b") and base[1:] in
              ("eq","ne","cs","cc","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","hs","lo")):
            m = re.search(r"<([^>+]+)(\+0x[0-9a-f]+)?>", args)
            if m:
                tgt = m.group(1)
                if tgt != name and (base == "bl" or m.group(2) is None):
                    calls.add(tgt)
            elif base == "blx":
                indirect += 1
        maxframe = max(maxframe, frame)
    info[name] = (maxframe, calls, indirect)

memo = {}; rec = set()
def depth(n, path=()):
    if n in memo: return memo[n]
    if n in path:
        rec.add(n); return (0, [])
    if n not in info: return (0, [])
    fr, calls, _ = info[n]
    best = (0, [])
    for c in calls:
        d = depth(c, path + (n,))
        if d[0] > best[0]: best = d
    memo[n] = (fr + best[0], [(n, fr)] + best[1])
    return memo[n]

sys.setrecursionlimit(10000)
if not roots:
    allf = sorted(((depth(n)[0], n) for n in info), reverse=True)[:25]
    for d, n in allf:
        print(f"{d:6d}  {n}  (own {info[n][0]}, indirect {info[n][2]})")
else:
    for r in roots:
        d, chain = depth(r)
        print(f"== {r}: worst-case {d} bytes")
        for n, fr in chain:
            print(f"   {fr:5d}  {n}" + ("  [indirect calls]" if info[n][2] else ""))
if rec:
    print("recursion cut at:", ", ".join(sorted(rec)))
