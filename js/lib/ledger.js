// lib/ledger.js — transport open/close + exchange with SW check.
//
// Two backends, picked by environment:
//
//   SPECULOS_APDU=host:port  → Speculos' raw APDU socket. This is the only
//                              backend that runs unattended, so it is what the
//                              npm scripts use. See js/README.md.
//   (nothing set)            → a physical Ledger over USB HID.
//
// @ledgerhq/hw-transport-node-hid and its native binding are imported lazily,
// so the Speculos path never touches node-gyp.

import { buf2hex } from "./hex.js";

// Speculos' APDU port speaks length-prefixed frames: 4-byte BE length then the
// APDU; the reply is a 4-byte BE length covering the response data, followed by
// the 2 status bytes (which the length does NOT count).
async function openSpeculos(hostPort) {
    const net = await import("node:net");
    const [host, port] = hostPort.split(":");
    const sock = net.createConnection({ host: host || "127.0.0.1", port: Number(port || 9999) });
    sock.setNoDelay(true);

    await new Promise((resolve, reject) => {
        sock.once("connect", resolve);
        sock.once("error", reject);
    });

    let buf = Buffer.alloc(0);
    const waiters = [];
    let failure = null;

    // An open socket keeps node's event loop alive, so `node --test` would
    // never exit once the last test finished. Hold a ref only while an
    // exchange is in flight; go unref'd whenever we are idle.
    const setIdle = (idle) => { if (idle) sock.unref(); else sock.ref(); };
    setIdle(true);

    sock.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        // A frame is complete once we hold its 4-byte header plus len+2 bytes.
        for (;;) {
            if (buf.length < 4) return;
            const len = buf.readUInt32BE(0);
            if (buf.length < 4 + len + 2) return;
            const frame = buf.subarray(4, 4 + len + 2);
            buf = buf.subarray(4 + len + 2);
            const w = waiters.shift();
            if (w) w.resolve(Buffer.from(frame));
            if (waiters.length === 0) setIdle(true);
        }
    });

    const die = (err) => {
        failure = err;
        while (waiters.length) waiters.shift().reject(err);
    };
    sock.on("error", die);
    sock.on("close", () => die(new Error("speculos closed the APDU connection")));

    return {
        exchange: (apdu) =>
            new Promise((resolve, reject) => {
                if (failure) return reject(failure);
                waiters.push({ resolve, reject });
                setIdle(false);
                const header = Buffer.alloc(4);
                header.writeUInt32BE(apdu.length, 0);
                sock.write(Buffer.concat([header, Buffer.from(apdu)]));
            }),
        close: async () => { sock.destroy(); },
    };
}

export async function openTransport() {
    if (process.env.SPECULOS_APDU) return openSpeculos(process.env.SPECULOS_APDU);

    const TransportNodeHid =
        (await import("@ledgerhq/hw-transport-node-hid/lib/TransportNodeHid")).default;
    const Transport = TransportNodeHid.default ?? TransportNodeHid;
    const devices = await Transport.list();
    if (devices.length === 0) throw new Error("No Ledger device found");
    return Transport.open(devices[0]);
}

export async function exchange(transport, apdu, label) {
    const resp = await transport.exchange(apdu);
    const sw = buf2hex(resp.slice(-2));
    const data = resp.slice(0, -2);
    if (sw !== "9000") throw new Error(`[${label}] SW=${sw}`);
    return data;
}

export async function withTransport(fn) {
    const transport = await openTransport();
    try {
        return await fn(transport);
    } finally {
        await transport.close();
    }
}
