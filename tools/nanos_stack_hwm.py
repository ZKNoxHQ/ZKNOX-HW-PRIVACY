#!/usr/bin/env python3
"""Measure the stack high-water mark of the app under Speculos.

Runs every production command, approves on screen, and reports for each one
the deepest point the stack reached. The stack is painted with 0xA5 through
/proc/<pid>/mem of the qemu process before each command and scanned after it,
so this must run on the machine (or in the container) where Speculos runs,
with the right to read that process.

    speculos --model nanos --display headless --apdu-port 9999 \
             --api-port 5000 --seed "<seed>" build/nanos/bin/app.elf &
    python3 tools/nanos_stack_hwm.py build/nanos/bin/app.elf

Speculos 0.25.5 is the last release with the Nano S model. Needs
arm-none-eabi-nm in PATH. The numbers are only meaningful for a model whose
RAM size the linker script describes exactly, which is the case here: the
stack region is read from the ELF symbols _stack and _estack.
"""
import argparse
import json
import subprocess
import sys
import threading
import time
import urllib.request

ACCEPT = ("approve", "confirm", "accept", "allow", "sign")
REJECT = ("reject", "cancel")
MSG = "8c1f26718227707c6e5c61417b47daccafabca9f574c16e1521dd6a9c70d8405"

# name, APDU, approve?
COMMANDS = [
    ("GET_VERSION", "e003000000", True),
    ("SIGNING_PUBKEY", "e00101000400000000", True),
    ("VIEWING_PUBKEY", "e01001000400000000", True),
    ("VIEWING_PRIVKEY", "e01300000400000000", True),
    ("RAILGUN_ADDRESS", "e01401000400000000", True),
    ("BLIND_SIGN BabyJubjub", "e01202002400000000" + MSG, True),
    ("BLIND_SIGN Bandersnatch", "e01201002400000000" + MSG, True),
    ("BLIND_SIGN rejected", "e01202002400000000" + MSG, False),
]


class Speculos:
    def __init__(self, api):
        self.api = api.rstrip("/")

    def _req(self, path, data=None, timeout=300):
        req = urllib.request.Request(
            self.api + path,
            data=None if data is None else json.dumps(data).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")

    def apdu(self, hexstr):
        return self._req("/apdu", {"data": hexstr})["data"]

    def button(self, name):
        self._req(f"/button/{name}", {"action": "press-and-release"})

    def screen(self):
        events = self._req("/events?currentscreenonly=true", timeout=10)["events"]
        return " | ".join(e["text"] for e in events)

    def wait_idle(self, timeout=30):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                if "ready" in self.screen().lower():
                    return
            except OSError:
                pass
            time.sleep(0.5)
        raise RuntimeError("the app did not come back to its home screen")


class Stack:
    """The app's stack inside the emulator process."""

    def __init__(self, elf, pid, keep):
        nm = subprocess.run(["arm-none-eabi-nm", elf], capture_output=True, text=True, check=True).stdout
        sym = {}
        for line in nm.splitlines():
            parts = line.split()
            if len(parts) == 3:
                sym[parts[2]] = int(parts[0], 16)
        self.lo, self.hi = sym["_stack"], sym["_estack"]
        self.keep = keep
        self.mem = open(f"/proc/{pid}/mem", "r+b", buffering=0)

    @property
    def size(self):
        return self.hi - self.lo

    def paint(self):
        # The top `keep` bytes belong to the idle loop: leave them alone.
        self.mem.seek(self.lo)
        self.mem.write(b"\xa5" * (self.size - self.keep))

    def high_water_mark(self):
        self.mem.seek(self.lo)
        buf = self.mem.read(self.size)
        untouched = 0
        while untouched < len(buf) and buf[untouched] == 0xA5:
            untouched += 1
        return self.size - untouched


def run(spec, stack, name, apdu_hex, approve):
    spec.wait_idle()
    stack.paint()
    out = {}

    def send():
        try:
            out["resp"] = spec.apdu(apdu_hex)
        except Exception as exc:  # the emulator died or closed the socket
            out["resp"] = f"<{type(exc).__name__}>"

    th = threading.Thread(target=send)
    th.start()
    time.sleep(1.2)
    want = ACCEPT if approve else REJECT
    if th.is_alive():
        for _ in range(60):
            low = spec.screen().lower().strip()
            if any(low.startswith(w) and len(low) < 16 for w in want):
                spec.button("both")
                break
            spec.button("right")
            time.sleep(0.35)
    th.join(300)
    time.sleep(0.8)
    return stack.high_water_mark(), out["resp"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("elf", help="the ELF Speculos is running")
    ap.add_argument("--api", default="http://127.0.0.1:5000", help="Speculos REST API")
    ap.add_argument("--pid", type=int, help="pid of the qemu-arm-static process (default: found with pgrep)")
    ap.add_argument("--keep", type=int, default=512, help="bytes below _estack left unpainted (idle loop)")
    args = ap.parse_args()

    pid = args.pid
    if pid is None:
        found = subprocess.run(["pgrep", "-f", "qemu-arm-static.*launcher"], capture_output=True, text=True).stdout.split()
        if not found:
            sys.exit("no qemu-arm-static process found: is Speculos running here?")
        pid = int(found[0])

    spec = Speculos(args.api)
    stack = Stack(args.elf, pid, args.keep)
    print(f"stack: {stack.size} bytes (0x{stack.lo:x}..0x{stack.hi:x})\n")
    worst = 0
    for name, apdu_hex, approve in COMMANDS:
        hwm, resp = run(spec, stack, name, apdu_hex, approve)
        worst = max(worst, hwm)
        # A fully consumed region means the stack ran into the statics.
        flag = "  OVERFLOW" if hwm >= stack.size else ""
        note = "  (floor: unpainted idle area)" if hwm <= args.keep else ""
        print(f"{name:26s} {hwm:5d} / {stack.size}   sw={resp[-4:]}{flag}{note}")
    print(f"\npeak {worst} of {stack.size} bytes, margin {stack.size - worst}")
    sys.exit(1 if worst >= stack.size else 0)


if __name__ == "__main__":
    main()
