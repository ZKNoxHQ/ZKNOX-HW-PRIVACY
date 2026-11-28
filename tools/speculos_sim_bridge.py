#!/usr/bin/env python3
"""Let a Speculos instance take a seat that expects the host simulator.

Speaks the protocol of sim/build/debug/apdu_sim (one hex APDU per line on
stdin, one hex reply per line on stdout, status word included) and forwards
each command to the Speculos APDU socket. That is enough for the Rust suite
to drive an emulated device:

    # the single-device suites
    SIM_BIN=$PWD/tools/speculos_sim_bridge.py \\
        cargo test --manifest-path rs/Cargo.toml -p zknox-hw-tests \\
        --test dkg --test frost_hw -- --test-threads=1

    # a full ceremony, the emulated device being participant HW_PARTICIPANT_ID
    HW_PARTICIPANT_BIN=$PWD/tools/speculos_sim_bridge.py \\
        cargo test --manifest-path rs/Cargo.toml -p zknox-hw-tests \\
        --test ceremony -- --test-threads=1 --nocapture

Environment:
    SPECULOS_APDU   host:port of the APDU socket (default 127.0.0.1:9999)
    STACK_ELF       the ELF Speculos runs. When set, the app stack is painted
                    before each command and scanned after it, and a line goes
                    to stderr each time an instruction reaches a new peak (the
                    harness ends this process without notice, so there is no
                    summary at the end: the last line of each instruction is
                    its peak). Same requirements as tools/nanos_stack_hwm.py:
                    run where the emulator runs, with the right to read its
                    memory.

The emulated device keeps the seed Speculos was started with: the ceremony
needs the suite's mnemonic there (yellow x 12), as on a physical device.
"""
import os
import socket
import subprocess
import sys
import time

# Reply of a handler leaves the device from deep inside it. Painting right
# away would land on frames that are still live, so let the app unwind to its
# idle loop first.
UNWIND_DELAY = 0.4

INS_NAMES = {
    0x01: "SIGNING_PUBKEY", 0x02: "BLIND_SIGN_NO_DISPLAY", 0x03: "GET_VERSION", 0x12: "BLIND_SIGN",
    0x50: "SIGN_WITH_PRIVKEY",
    0x60: "DKG_GET_COMM_PUBKEY", 0x61: "DKG_DEAL", 0x62: "DKG_SET_COMMITS", 0x63: "DKG_GET_SHARE",
    0x64: "DKG_PUT_SHARE", 0x65: "DKG_FINALIZE", 0x66: "DKG_ABORT", 0x67: "DKG_STATUS",
    0x68: "DKG_DEBUG_COMM_PRIVKEY", 0x69: "DKG_DEBUG_SKSHARE", 0x6a: "DKG_EXPORT_SHARE",
    0x6b: "DKG_RESTORE_SHARE",
    0x70: "FROST_HW_COMMIT", 0x71: "FROST_HW_SIGN", 0x72: "FROST_HW_RESET",
}


def open_stack(elf):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from nanos_stack_hwm import Stack
    found = subprocess.run(["pgrep", "-f", "qemu-arm-static.*launcher"],
                           capture_output=True, text=True).stdout.split()
    if not found:
        sys.exit("speculos_sim_bridge: no qemu-arm-static process found, is Speculos running here?")
    return Stack(elf, int(found[0]), 512)


def main():
    host, _, port = os.environ.get("SPECULOS_APDU", "127.0.0.1:9999").rpartition(":")
    sock = socket.create_connection((host or "127.0.0.1", int(port)))
    stack = open_stack(os.environ["STACK_ELF"]) if os.environ.get("STACK_ELF") else None
    peaks = {}

    def recv(n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                sys.exit("speculos_sim_bridge: Speculos closed the APDU socket (did the app stop?)")
            buf += chunk
        return buf

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        apdu = bytes.fromhex(line)
        if stack:
            time.sleep(UNWIND_DELAY)
            stack.paint()
        sock.sendall(len(apdu).to_bytes(4, "big") + apdu)
        size = int.from_bytes(recv(4), "big")
        reply = recv(size + 2)
        if stack and len(apdu) >= 2:
            used = stack.high_water_mark()
            if used > peaks.get(apdu[1], 0):
                peaks[apdu[1]] = used
                name = INS_NAMES.get(apdu[1], f"INS 0x{apdu[1]:02x}")
                print(f"  stack  {name:24s} {used:5d} / {stack.size}  (margin {stack.size - used})",
                      file=sys.stderr, flush=True)
        sys.stdout.write(reply.hex() + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
