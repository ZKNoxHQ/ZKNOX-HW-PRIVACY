// lib/test-context.js — Shared Ledger transport for node:test suites.
//
// All device-required suites share a single USB transport. Suites call
// `getTransport()` from a `before()` hook; the first call opens the
// device, subsequent calls return the same handle. `closeTransport()` is
// wired to `process.on("exit")` so the device gets released cleanly.
//
// If no Ledger is connected, `getTransport()` resolves to `null` and
// each test should call `t.skip("no device")` and return early.

import { openTransport } from "./ledger.js";

let _transport = null;
let _openAttempted = false;
let _openError = null;

export async function getTransport() {
    if (_openAttempted) return _transport;
    _openAttempted = true;
    try {
        _transport = await openTransport();
    } catch (e) {
        _openError = e;
        _transport = null;
    }
    return _transport;
}

export function getOpenError() {
    return _openError;
}

async function closeTransport() {
    if (_transport) {
        try { await _transport.close(); } catch { /* ignore */ }
        _transport = null;
    }
}

process.on("exit", () => {
    // Best-effort sync cleanup; node-hid release on exit is usually fine.
    closeTransport();
});

// Helper: suite-level skip when no device. Usage in a `before()` hook:
//
//   import { requireDevice } from "../lib/test-context.js";
//   let transport;
//   before(async function() { transport = await requireDevice(this); });
//
// `requireDevice` returns the transport or calls `ctx.skip()` and throws,
// short-circuiting the rest of the suite.
export async function requireDevice(testCtx) {
    const t = await getTransport();
    if (!t) {
        const msg = `no Ledger device available${_openError ? `: ${_openError.message}` : ""}`;
        if (testCtx && typeof testCtx.skip === "function") testCtx.skip(msg);
        throw new Error(msg);
    }
    return t;
}
