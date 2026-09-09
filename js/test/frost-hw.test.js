// frost-hw.test.js — EXPORT_SHARE and FROST HW signing (INS 0x70–0x72) on a
// device provisioned via RESTORE_SHARE. Needs a FROST=1 build.
//
// RESTORE is the bridge: it brings the device to PROVISIONED from a captured
// blob (validated separately in dkg.test.js), so these tests exercise what sits
// on TOP of a provisioned share without running the full sequential ceremony:
//   - EXPORT_SHARE      → real AES-GCM encrypt + fresh RNG nonce
//   - FROST_HW_COMMIT   → zkn_frost_commit, two on-curve commitments
//   - FROST_HW_SIGN grds→ the state/quorum/membership guards (SW_BAD_STATE,
//                         SW_WRONG_DATA_LENGTH) that a single device CAN hit
//
// A valid FROST signature needs t co-signers' commitments (FS_REC records), so
// the happy-path SIGN is intentionally NOT here — it belongs to a 2-device
// setup. Guards are where handler bugs hide, and they are single-device.
//
// The fixture is a 2-of-3 blob (t=2).

import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { requireDevice } from "../lib/test-context.js";
import { exchange } from "../lib/ledger.js";
import {
    INS_DKG_STATUS,
    INS_DKG_ABORT,
    INS_DKG_RESTORE_SHARE,
    INS_DKG_EXPORT_SHARE,
    INS_FROST_HW_COMMIT,
    INS_FROST_HW_SIGN,
    INS_FROST_HW_RESET,
    FROST_FS_REC,
    FROST_P1_FIRST,
    FROST_P1_LAST,
    SW_BAD_STATE,
    SW_WRONG_DATA_LENGTH,
    DKG_STATE,
    accountBE,
    buildApduBuffer,
} from "../apdu-constants.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(__dirname, "fixtures", "restore-blob-yellow.hex");

// exchange that returns {ok, data|sw} instead of throwing, for guard tests.
async function tryExchange(transport, apdu, label) {
    try {
        const data = await exchange(transport, apdu, label);
        return { ok: true, data };
    } catch (e) {
        const m = /SW=([0-9a-fA-F]{4})/.exec(e.message);
        return { ok: false, sw: m ? m[1].toLowerCase() : "????" };
    }
}

// FROST_HW_SIGN streams its payload: a single APDU's Lc is one byte (≤255), but
// msg(32)+t×160 exceeds that for t≥2. The handler accumulates chunks — P1_FIRST
// resets the buffer, any non-LAST chunk appends and returns OK, P1_LAST appends
// then finalizes (computes or rejects). We send msg+signer[0] as FIRST, then
// each remaining signer, the last one as LAST. Every chunk stays under 255.
async function signStreamed(transport, msg, signerRecs) {
    // FIRST chunk: msg(32) + first signer(160) = 192 bytes.
    let r = await tryExchange(transport,
        buildApduBuffer(INS_FROST_HW_SIGN, FROST_P1_FIRST, 0,
            Buffer.concat([msg, signerRecs[0]])), "SIGN[first]");
    if (!r.ok) return r;
    // middle signers (none for t=2): P1 must be neither FIRST (would reset the
    // buffer) nor LAST (would finalize early) — use 0x01 to append-and-continue.
    for (let i = 1; i < signerRecs.length - 1; i++) {
        r = await tryExchange(transport,
            buildApduBuffer(INS_FROST_HW_SIGN, 0x01, 0, signerRecs[i]), `SIGN[${i}]`);
        if (!r.ok) return r;
    }
    // LAST chunk: final signer, triggers compute/reject.
    return await tryExchange(transport,
        buildApduBuffer(INS_FROST_HW_SIGN, FROST_P1_LAST, 0,
            signerRecs[signerRecs.length - 1]), "SIGN[last]");
}

describe("FROST HW on RESTORE-provisioned device (INS 0x6a, 0x70, 0x71)", () => {
    let transport;
    let t = 0, n = 0;
    // Node's `before` hook context has no .skip() (that's TestContext-only).
    // Set a shared reason if provisioning can't happen and let each test skip
    // itself via tc.skip().
    let skipReason = null;

    before(async function () {
        transport = await requireDevice(this);
        if (!existsSync(FIXTURE)) {
            skipReason = `no blob fixture at ${FIXTURE}`;
            return;
        }
        // provision: ABORT → RESTORE → PROVISIONED
        const blob = Buffer.from(readFileSync(FIXTURE, "utf8").trim(), "hex");
        await exchange(transport, buildApduBuffer(INS_DKG_ABORT), "ABORT");
        const A = await exchange(transport,
            buildApduBuffer(INS_DKG_RESTORE_SHARE, 0, 0, Buffer.concat([accountBE(0), blob])),
            "RESTORE");
        assert.equal(A.length, 64, "RESTORE returns 64-byte A");
        const s = await exchange(transport, buildApduBuffer(INS_DKG_STATUS), "STATUS");
        assert.equal(s[0], DKG_STATE.PROVISIONED, "device must be PROVISIONED");
        t = s[2]; n = s[3]; // STATUS layout: state|id|t|n|mask(2)
    });

    // ── EXPORT_SHARE: real AES-GCM encrypt ──
    test("EXPORT_SHARE returns a well-formed backup blob", async (tc) => {
        if (skipReason) return tc.skip(skipReason);
        const blob = await exchange(transport,
            buildApduBuffer(INS_DKG_EXPORT_SHARE, 0, 0, accountBE(0)), "EXPORT");
        // magic ZKBS = 0x5a4b4253
        assert.equal(blob.readUInt32BE(0), 0x5a4b4253, "blob must carry the ZKBS magic");
        assert.ok(blob.length >= 4 + 12 + 32 + 16, "blob must fit aad+nonce+ct+tag");
        // nonce (12B) sits after the aad; it must not be all-zero (the RNG ran).
        const tail = blob.subarray(blob.length - (12 + 32 + 16));
        assert.ok(tail.subarray(0, 12).some((b) => b !== 0), "nonce must be non-zero");
    });

    test("two EXPORTs differ (fresh nonce) but both restore the same A", async (tc) => {
        if (skipReason) return tc.skip(skipReason);
        const b1 = await exchange(transport,
            buildApduBuffer(INS_DKG_EXPORT_SHARE, 0, 0, accountBE(0)), "EXPORT#1");
        const b2 = await exchange(transport,
            buildApduBuffer(INS_DKG_EXPORT_SHARE, 0, 0, accountBE(0)), "EXPORT#2");
        assert.notDeepEqual(b1, b2, "fresh nonce → different ciphertext each time");

        // round-trip: the device is PROVISIONED, so to RESTORE we must ABORT to
        // IDLE first (RESTORE requires IDLE). Do it twice from the same blob and
        // check A is stable.
        await exchange(transport, buildApduBuffer(INS_DKG_ABORT), "ABORT");
        const A0 = await exchange(transport,
            buildApduBuffer(INS_DKG_RESTORE_SHARE, 0, 0, Buffer.concat([accountBE(0), b2])),
            "RESTORE(A0)");
        await exchange(transport, buildApduBuffer(INS_DKG_ABORT), "ABORT");
        const A1 = await exchange(transport,
            buildApduBuffer(INS_DKG_RESTORE_SHARE, 0, 0, Buffer.concat([accountBE(0), b2])),
            "RESTORE(A1)");
        assert.deepEqual(A0, A1, "same share → same A across an export/restore round-trip");
    });

    // ── FROST_HW_COMMIT: nonce generation ──
    test("FROST_HW_COMMIT returns two on-curve commitments", async (tc) => {
        if (skipReason) return tc.skip(skipReason);
        const out = await exchange(transport,
            buildApduBuffer(INS_FROST_HW_COMMIT, 0, 0), "FROST_COMMIT");
        assert.equal(out.length, 128, "COMMIT returns 2×64-byte points (hiding, binding)");
        assert.ok(out.subarray(0, 64).some((b) => b !== 0), "hiding commitment non-zero");
        assert.ok(out.subarray(64, 128).some((b) => b !== 0), "binding commitment non-zero");
    });

    // ── FROST_HW_SIGN guards (single-device reachable) ──
    test("SIGN without a prior COMMIT is refused (FS state guard)", async (tc) => {
        if (skipReason) return tc.skip(skipReason);
        // Reset FROST state to FS_IDLE (0x72), so no COMMIT is pending. SIGN must
        // then fail on the state guard regardless of what ran before.
        await exchange(transport, buildApduBuffer(INS_FROST_HW_RESET), "FROST_RESET");
        const msg = Buffer.alloc(32, 0x11);
        const r = await tryExchange(transport,
            buildApduBuffer(INS_FROST_HW_SIGN, FROST_P1_LAST, 0, msg), "SIGN/no-commit");
        assert.equal(r.ok, false, "SIGN without COMMIT must fail");
        assert.equal(r.sw, SW_BAD_STATE, "must be SW_BAD_STATE");
    });

    test("SIGN with the wrong number of signers is refused (quorum != t)", async (tc) => {
        if (skipReason) return tc.skip(skipReason);
        // COMMIT first to reach FS_NONCED, then send a signer list of size != t.
        await exchange(transport, buildApduBuffer(INS_FROST_HW_COMMIT, 0, 0), "COMMIT");
        // one signer record while t == 2 → nsig(1) != t(2) → SW_WRONG_DATA_LENGTH
        const msg = Buffer.alloc(32, 0x22);
        const oneSigner = Buffer.alloc(FROST_FS_REC);
        oneSigner[31] = 1; // id = 1
        const payload = Buffer.concat([msg, oneSigner]);
        const r = await tryExchange(transport,
            buildApduBuffer(INS_FROST_HW_SIGN, FROST_P1_LAST, 0, payload), "SIGN/nsig!=t");
        assert.equal(r.ok, false, "wrong signer count must fail");
        assert.equal(r.sw, SW_WRONG_DATA_LENGTH, "must be SW_WRONG_DATA_LENGTH");
    });

    test("SIGN for a quorum the device is not in is refused (membership)", async (tc) => {
        if (skipReason) return tc.skip(skipReason);
        await exchange(transport, buildApduBuffer(INS_FROST_HW_COMMIT, 0, 0), "COMMIT");
        // Build a size-t signer list that deliberately EXCLUDES this device's id
        // (myId), so the handler must reject on membership (me < 0). We read myId
        // from STATUS and pick the t smallest ids in 1..n that are != myId.
        const s = await exchange(transport, buildApduBuffer(INS_DKG_STATUS), "STATUS");
        const myId = s[1]; // STATUS: state|id|t|n|mask
        const others = [];
        for (let id = 1; id <= n && others.length < t; id++) {
            if (id !== myId) others.push(id);
        }
        assert.equal(others.length, t, `need ${t} ids excluding self; got ${others}`);
        const mk = (id) => { const r = Buffer.alloc(FROST_FS_REC); r[31] = id; return r; };
        const recs = others.map(mk); // ascending by construction
        // t signers → msg + t×160 exceeds one APDU; stream it (see signStreamed).
        const r = await signStreamed(transport, Buffer.alloc(32, 0x33), recs);
        assert.equal(r.ok, false, "signing outside our quorum must fail");
        assert.equal(r.sw, SW_WRONG_DATA_LENGTH, "must be SW_WRONG_DATA_LENGTH (me < 0)");
    });
});
