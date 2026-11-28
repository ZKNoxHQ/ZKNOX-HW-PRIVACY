#!/usr/bin/env python3
"""Cycle profile of one signature, from a Nano S app ELF, under emulation.

    python3 tools/nanos_cycle_profile.py build/nanos/bin/app.elf
    python3 tools/nanos_cycle_profile.py app.elf --clock 21.8 --track zkn_poseidon,tEdwards_normalize

Runs handler_sign_with_privkey (SIGN_WITH_PRIVKEY, 0x50, debug builds) of the
image in an ARMv6-M emulator and counts cycles. The flash image is mapped
below its link address (the app is position independent), the RAM at its real
address with the real top of stack, so the frames are the device's. The random
generator and the reply are replaced by stubs; nothing else is. The signature
that comes out is compared with the expected one.

Cycles are counted per basic block with the Cortex-M0+ instruction timings
(1 per instruction, 2 for a load, a store or a taken branch, 1 + n for
push/pop of n registers, 3 for bl and pop pc) and reported for the two
multipliers these cores are built with, MULS in 1 cycle or in 32. The
Cortex-M0 and SC000, with their three-stage pipeline, pay one more cycle per
taken branch, bl, bx and pop pc: that total is given as well.

What it does not see: time spent outside the app (the random generator of the
OS, USB) and anything specific to the chip (wait states, clock changes).

On a Nano S with firmware 2.1.0, the measured signature times match the
32-cycle multiplier and the M0 timings at about 21.8 MHz (DECISIONS.md,
ADR-004).

Needs arm-none-eabi-objcopy/nm and the Python packages unicorn and capstone.
"""
import argparse
import bisect
import os
import subprocess
import sys
import tempfile

from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs
from unicorn import UC_ARCH_ARM, UC_HOOK_BLOCK, UC_MODE_MCLASS, UC_MODE_THUMB, Uc, UcError
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_SP)

# The vector of rs/crates/hw-tests/tests/sign.rs: spending key of the test
# mnemonic, account 0, and the circomlibjs signature (R8.x | R8.y | S).
PRV = "624fc1ef37a8c3311af0a837c9c4b0d5e008095cd08a9c4c65993cd244460dbb"
MSG = "8c1f26718227707c6e5c61417b47daccafabca9f574c16e1521dd6a9c70d8405"
SIG = ("2954bb04ccd89f65b27b7912fa447925972286de0bf4161b2b3260cadea5a4ed"
       "2b6c8873579e9805c1a15519e8ad9f2d9d30f7d95fc5a3ac5706d9b9944d1919"
       "05b15ff1bd5a2c2f9cc0bc033aa8c14de3410ac82d93c8477d42a493575b5427")

BASE = 0x00100000                  # where the flash image runs
RAM, RAM_SIZE = 0x20000000, 0x4000
STOP = 0x000F0000                  # return address of the handler
ARGS = 0x20002000                  # the APDU data, above the app's RAM

# Replaced on entry: (code written over the first bytes, what the hook does).
STUBS = {
    "cx_rng_no_throw": bytes.fromhex("00207047"),            # movs r0,#0 ; bx lr
    "cx_get_random_bytes": bytes.fromhex("00207047"),
    "io_send_response_buffers": bytes.fromhex("7047"),       # bx lr
    "SVC_Call": bytes.fromhex("0021"),                       # movs r1,#0 in place of svc 1
    "SVC_cx_call": bytes.fromhex("c046"),                    # nop in place of svc 1
}


def run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def load(elf):
    tmp = tempfile.mkdtemp(prefix="nanos-profile-")
    binf = os.path.join(tmp, "text.bin")
    run(["arm-none-eabi-objcopy", "-O", "binary", "-j", ".text", elf, binf])
    image = bytearray(open(binf, "rb").read())
    syms, funcs = {}, set()
    for line in run(["arm-none-eabi-nm", elf]).splitlines():
        f = line.split()
        if len(f) == 3:
            addr = int(f[0], 16) & ~1
            syms.setdefault(f[2], addr)
            if f[1] in "tTwW":
                funcs.add((addr, f[2]))
    for need in ("_nvram", "_estack", "handler_sign_with_privkey"):
        if need not in syms:
            sys.exit(f"{elf}: no symbol {need} (a Nano S debug build is expected)")
    return image, syms, sorted(funcs)


def profile(elf, prv, msg, curve, track):
    image, syms, funcs = load(elf)
    link = syms["_nvram"]
    starts = [a for a, _ in funcs]
    names = [n for _, n in funcs]
    at = lambda name: BASE + syms[name] - link

    for name, code in STUBS.items():
        if name in syms:
            off = syms[name] - link
            image[off:off + len(code)] = code

    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    uc.mem_map(BASE, (len(image) + 0x1FFF) & ~0xFFF)
    uc.mem_write(BASE, bytes(image))
    uc.mem_map(RAM, RAM_SIZE)
    uc.mem_map(STOP, 0x1000)
    estack = syms["_estack"]

    rng_at = {at(n) for n in ("cx_rng_no_throw", "cx_get_random_bytes") if n in syms}
    send_at = at("io_send_response_buffers")
    svc_at = {at(n) for n in ("SVC_Call", "SVC_cx_call") if n in syms}
    track_at = {at(n): n for n in track if n in syms}

    # counters: [instructions, cycles (M0+, MULS = 1), extra cycles on M0, MULS]
    total = [0, 0, 0, 0]
    self_cost, incl, cache, calls = {}, {}, {}, []
    st = {"prev": None, "rng": 0, "svc": 0, "out": None, "low_sp": estack}

    def decode(addr, size):
        n = c = x = m = 0
        kind = None
        for ins in cs.disasm(bytes(uc.mem_read(addr, size)), addr):
            mn, ops = ins.mnemonic, ins.op_str
            n += 1
            kind = None
            if mn.startswith("mul"):
                m += 1; c += 1
            elif mn.startswith(("ldm", "stm")):
                c += 1 + ops.count(",")
            elif mn.startswith(("ldr", "str")):
                c += 2
            elif mn == "push":
                c += 2 + ops.count(",")
            elif mn == "pop":
                regs = ops.count(",") + 1
                if "pc" in ops:
                    c += 3 + regs; x += 1
                else:
                    c += 1 + regs
            elif mn == "bl":
                c += 3; x += 1
            elif mn in ("bx", "blx"):
                c += 2; x += 1
            elif mn in ("b", "b.n", "b.w"):
                c += 2; x += 1
            elif mn.startswith("b") and not mn.startswith(("bic", "bkpt")):
                c += 1; kind = "cond"          # counted as not taken; fixed up below
            else:
                c += 1
        i = bisect.bisect_right(starts, addr - BASE + link) - 1
        return n, c, x, m, kind, addr + size, names[i] if i >= 0 else "?"

    def on_block(_uc, addr, size, _):
        info = cache.get(addr)
        if info is None:
            info = cache[addr] = decode(addr, size)
        n, c, x, m, kind, end, fn = info
        prev = st["prev"]
        if prev is not None and prev[0] == "cond" and prev[1] != addr:
            p = self_cost[prev[2]]
            p[1] += 1; p[2] += 1               # taken branch: 2 cycles, 3 on M0
            total[1] += 1; total[2] += 1
        p = self_cost.get(fn)
        if p is None:
            p = self_cost[fn] = [0, 0, 0, 0]
        p[0] += n; p[1] += c; p[2] += x; p[3] += m
        before = tuple(total)
        total[0] += n; total[1] += c; total[2] += x; total[3] += m
        st["prev"] = (kind, end, fn)
        if calls and calls[-1][1] == addr:     # back from a tracked function
            name, _, snap = calls.pop()
            acc = incl.setdefault(name, [0, 0, 0, 0, 0])
            for k in range(4):
                acc[k] += before[k] - snap[k]
            acc[4] += 1
        if addr in track_at:
            calls.append((track_at[addr], uc.reg_read(UC_ARM_REG_LR) & ~1, before))
        if addr in rng_at:
            buf, ln = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)
            uc.mem_write(buf, os.urandom(ln))
            st["rng"] += 1
        elif addr == send_at:
            bufs = uc.reg_read(UC_ARM_REG_R0)
            ptr = int.from_bytes(uc.mem_read(bufs, 4), "little")
            ln = int.from_bytes(uc.mem_read(bufs + 4, 4), "little")
            st["out"] = bytes(uc.mem_read(ptr, ln)) if ln else b""
            uc.emu_stop()
        elif addr in svc_at:
            st["svc"] += 1
            uc.reg_write(UC_ARM_REG_R0, 0)
        sp = uc.reg_read(UC_ARM_REG_SP)
        if sp < st["low_sp"]:
            st["low_sp"] = sp

    uc.hook_add(UC_HOOK_BLOCK, on_block)

    data = bytes([curve]) + prv + msg
    uc.mem_write(ARGS + 0x100, data)
    uc.mem_write(ARGS, b"".join(v.to_bytes(4, "little") for v in (ARGS + 0x100, len(data), 0)))
    uc.reg_write(UC_ARM_REG_SP, estack)
    uc.reg_write(UC_ARM_REG_R0, ARGS)
    uc.reg_write(UC_ARM_REG_LR, STOP | 1)
    try:
        uc.emu_start(at("handler_sign_with_privkey") | 1, STOP)
    except UcError as e:
        pc = uc.reg_read(UC_ARM_REG_PC)
        sys.exit(f"emulation stopped: {e} at {pc - BASE + link:#x} (after {st['prev'][2] if st['prev'] else '?'}): "
                 "a call that leaves the app and has no stub")
    return {"out": st["out"], "rng": st["rng"], "svc": st["svc"], "stack": estack - st["low_sp"],
            "total": total, "self": self_cost, "incl": incl}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("elf")
    ap.add_argument("--prv", default=PRV, help="private key, 32 bytes of hex")
    ap.add_argument("--msg", default=MSG, help="message, 32 bytes of hex")
    ap.add_argument("--expect", default=None, help="expected signature, 96 bytes of hex (default: the one of the default vector)")
    ap.add_argument("--curve", type=int, default=0, help="first byte of the APDU data (0: BabyJubjub)")
    ap.add_argument("--track", default="zkn_poseidon,tEdwards_fixedBase_4MSM,tEdwards_normalize,zkn_mul_mont_256,next64_graingen",
                    help="functions whose inclusive cost is reported")
    ap.add_argument("--clock", type=float, default=None, help="MHz, to print seconds for the 32-cycle multiplier on M0")
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()

    expect = args.expect
    if expect is None and (args.prv, args.msg, args.curve) == (PRV, MSG, 0):
        expect = SIG
    r = profile(args.elf, bytes.fromhex(args.prv), bytes.fromhex(args.msg), args.curve,
                [n for n in args.track.split(",") if n])
    out = r["out"]
    if not out or len(out) != 96:
        print("the handler returned no signature")
        return 1
    n, c, x, m = r["total"]
    slow = lambda v: v[1] + v[2] + 31 * v[3]                      # M0 timings, MULS in 32 cycles
    print(f"signature  {out.hex()}")
    if expect is not None:
        print(f"           {'equal to' if out.hex() == expect.lower() else 'DIFFERENT FROM'} the expected one")
    print(f"stack {r['stack']} bytes below the top; {r['rng']} calls to the random generator; {r['svc']} other calls out of the app")
    print(f"instructions {n}; MULS {m}")
    print(f"cycles, M0+ timings: {c} with MULS in 1 cycle, {c + 31 * m} in 32")
    print(f"cycles, M0 timings:  {c + x} with MULS in 1 cycle, {c + x + 31 * m} in 32")
    if args.clock:
        print(f"at {args.clock} MHz, M0 timings, MULS in 32 cycles: {slow(r['total']) / args.clock / 1e6:.2f} s")
    whole = slow(r["total"])
    print("\ninclusive, M0 timings and MULS in 32 cycles:")
    for name, v in sorted(r["incl"].items(), key=lambda kv: -slow(kv[1])):
        print(f"  {name:30s} {v[4]:7d} calls {slow(v) / 1e6:9.2f} M cycles {100 * slow(v) / whole:5.1f} %")
    print("\nself, M0 timings and MULS in 32 cycles:")
    for name, v in sorted(r["self"].items(), key=lambda kv: -slow(kv[1]))[:args.top]:
        print(f"  {name:30s} {slow(v) / 1e6:9.2f} M cycles {100 * slow(v) / whole:5.1f} %")
    return 0 if expect is None or out.hex() == expect.lower() else 1


if __name__ == "__main__":
    sys.exit(main())
