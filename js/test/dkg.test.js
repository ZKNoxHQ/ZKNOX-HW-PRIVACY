// dkg.test.js — VSS/DKG APDUs (INS 0x60–0x6b). Needs a FROST=1 build.
//
// Two things decide what is unit-testable here:
//   - state: the ceremony state (g_dkg) is in RAM, so DEAL→FINALIZE only makes
//     sense within ONE transport session. STATUS/ABORT/GET_COMM_PUBKEY need no
//     state and stand alone.
//   - determinism: DEAL draws a fresh epoch and GET_SHARE a fresh nonce, so
//     their output can't be compared byte-for-byte — only checked for shape.
//
// This file does NOT sign (no EdDSA-Poseidon), so it is safe on any firmware:
// the CX-wipe hazard only applies to FROST signing, kept out of here.

import { describe, before, test } from "node:test";
import assert from "node:assert/strict";
import { exchange } from "../lib/ledger.js";
import { requireDevice } from "../lib/test-context.js";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
    INS_SIGNING_PUBKEY,
    PUBKEY_P1_SILENT,
    INS_DKG_GET_COMM_PUBKEY,
    INS_DKG_STATUS,
    INS_DKG_ABORT,
    INS_DKG_DEAL,
    INS_DKG_GET_SHARE,
    INS_DKG_RESTORE_SHARE,
    DKG_STATE,
    accountBE,
    buildDkgDealPayload,
    buildApduBuffer,
} from "../apdu-constants.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

// BabyJubJub prime — to sanity-check that DEAL's commitment coordinates are
// field elements (a cheap on-device-output validity check, short of full
// on-curve verification).
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const beToBig = (b) => BigInt("0x" + Buffer.from(b).toString("hex"));

describe("DKG / VSS (INS 0x60–0x6b)", () => {
    let transport;
    before(async function () { transport = await requireDevice(this); });

    // ── GET_COMM_PUBKEY: the one true unit test ─────────────────────
    // No state, no randomness: the comm key is a deterministic function of the
    // seed, so it is the first real exercise of key derivation on device.
    //
    // Oracle for the yellow×12 seed. This value was captured from this app
    // running on Speculos with that mnemonic, and it matches the one the
    // RAILGUN app produces — both derive KEY_TYPE_DKG_COMM down the same
    // libC path (m/421'/1984'/account'/0'/0'), so agreement is expected and a
    // divergence would mean one of them moved.
    const HK_YELLOW_ACCT0 =
        "9fc8d2779ee5bfb7662e02b5c8e23c71a4de3045621b15e031cbe481687de081";

    test("GET_COMM_PUBKEY returns a 32-byte key, stable across calls", async () => {
        const apdu = buildApduBuffer(INS_DKG_GET_COMM_PUBKEY, 0, 0, accountBE(0));
        const a = await exchange(transport, apdu, "DKG_GET_COMM_PUBKEY");
        assert.equal(a.length, 32, "HK must be 32 bytes");
        const b = await exchange(transport, apdu, "DKG_GET_COMM_PUBKEY/again");
        assert.deepEqual(a, b, "comm key must be deterministic for a fixed seed");
    });

    // The DKG transport identity must not be reachable from a key the app
    // hands out. This app has no viewing key (that is a RAILGUN concept), so
    // the exportable counterpart here is the signing key. P1=0 is the silent
    // variant, DEBUG builds only.
    test("DKG transport identity is separate from the signing key", async () => {
        const account = accountBE(0);
        const hk = await exchange(transport,
            buildApduBuffer(INS_DKG_GET_COMM_PUBKEY, 0, 0, account),
            "DKG_GET_COMM_PUBKEY");
        const signing = await exchange(transport,
            buildApduBuffer(INS_SIGNING_PUBKEY, PUBKEY_P1_SILENT, 0, account),
            "SIGNING_PUBKEY");
        assert.notDeepEqual(Buffer.from(hk), Buffer.from(signing.subarray(0, hk.length)),
            "non-exported DKG identity must not reuse the signing-key path");
    });

    // Bit-exact against the known oracle — the go/no-go for the derivation.
    // Only meaningful when the seed is yellow×12; skipped otherwise.
    test("GET_COMM_PUBKEY matches the yellow×12 oracle (bit-exact)", async (t) => {
        if (process.env.SEED && process.env.SEED !== "yellow") {
            t.skip("non-default seed: oracle only valid for yellow×12");
            return;
        }
        const a = await exchange(transport,
            buildApduBuffer(INS_DKG_GET_COMM_PUBKEY, 0, 0, accountBE(0)),
            "DKG_GET_COMM_PUBKEY");
        assert.equal(Buffer.from(a).toString("hex"), HK_YELLOW_ACCT0,
            "HK must byte-match the yellow×12 oracle");
    });

    // ── STATUS / ABORT: state machine at rest ───────────────────────
    test("STATUS reports a well-formed state", async () => {
        const s = await exchange(transport, buildApduBuffer(INS_DKG_STATUS), "DKG_STATUS");
        assert.equal(s.length, 6, "status is state|id|t|n|mask(2)");
        assert.ok(s[0] <= DKG_STATE.PROVISIONED, "state in range");
    });

    test("ABORT returns to IDLE", async () => {
        await exchange(transport, buildApduBuffer(INS_DKG_ABORT), "DKG_ABORT");
        const s = await exchange(transport, buildApduBuffer(INS_DKG_STATUS), "DKG_STATUS");
        assert.equal(s[0], DKG_STATE.IDLE, "state must be IDLE after ABORT");
    });

    // ── DEAL: shape only (epoch makes it non-deterministic) ─────────
    test("DEAL yields a fresh epoch and t on-field commitments", async () => {
        await exchange(transport, buildApduBuffer(INS_DKG_ABORT), "DKG_ABORT");
        const t = 2, n = 3;
        const out = await exchange(transport,
            buildApduBuffer(INS_DKG_DEAL, 0, 0, buildDkgDealPayload(0, 1, t, n, "unit-test")),
            "DKG_DEAL");
        assert.equal(out.length, 16 + t * 64, "epoch(16) || C(t*64)");
        for (let k = 0; k < t; k++) {
            const x = beToBig(out.subarray(16 + k * 64, 16 + k * 64 + 32));
            const y = beToBig(out.subarray(16 + k * 64 + 32, 16 + k * 64 + 64));
            assert.ok(x < P && y < P, `commitment ${k} coordinates in field`);
        }
        const s = await exchange(transport, buildApduBuffer(INS_DKG_STATUS), "DKG_STATUS");
        assert.equal(s[0], DKG_STATE.DEALT, "state must be DEALT after DEAL");
        await exchange(transport, buildApduBuffer(INS_DKG_ABORT), "DKG_ABORT");
    });

    // ── the barrier: GET_SHARE before COMMITTED must be refused ─────
    // exchange() throws on non-9000 SW, so a refusal is a thrown error we assert.
    test("GET_SHARE before COMMITTED is refused (round-1 barrier)", async () => {
        await exchange(transport, buildApduBuffer(INS_DKG_ABORT), "DKG_ABORT");
        await exchange(transport,
            buildApduBuffer(INS_DKG_DEAL, 0, 0, buildDkgDealPayload(0, 1, 2, 3, "unit-test")),
            "DKG_DEAL");
        // now in DEALT, not COMMITTED → GET_SHARE must fail with SW_BAD_STATE
        await assert.rejects(
            () => exchange(transport,
                buildApduBuffer(INS_DKG_GET_SHARE, 0, 0, Buffer.from([2])), "DKG_GET_SHARE"),
            /b007|bad.?state|status/i,
            "GET_SHARE must be refused before COMMITTED");
        await exchange(transport, buildApduBuffer(INS_DKG_ABORT), "DKG_ABORT");
    });
});

// ── RESTORE_SHARE: a unit test by shortcut ──────────────────────────────
// RESTORE only needs the IDLE start state — no ceremony to build up to. Feed a
// pre-captured backup blob into a fresh device; it must decrypt straight to
// PROVISIONED and return A. This exercises the real AES-GCM decrypt and the
// backup-key derivation, neither of which is bypassed by BACKEND=sw.
//
// The blob is seed-bound: it only restores on a device holding the same seed it
// was exported from (yellow×12). See js/README.md for how it was produced.
describe("DKG / RESTORE_SHARE (INS 0x6b)", () => {
    let transport;
    const fixture = join(__dirname, "fixtures", "restore-blob-yellow.hex");

    before(async function () { transport = await requireDevice(this); });

    test("RESTORE_SHARE from a captured blob provisions the device", async (t) => {
        if (!existsSync(fixture)) {
            t.skip(`no blob fixture at ${fixture}`);
            return;
        }
        if (process.env.SEED && process.env.SEED !== "yellow") {
            t.skip("blob is bound to yellow×12; device seed differs");
            return;
        }
        const blob = Buffer.from(readFileSync(fixture, "utf8").trim(), "hex");

        await exchange(transport, buildApduBuffer(INS_DKG_ABORT), "DKG_ABORT");
        let s = await exchange(transport, buildApduBuffer(INS_DKG_STATUS), "DKG_STATUS");
        assert.equal(s[0], DKG_STATE.IDLE, "must start IDLE");

        // RESTORE: account(4 BE) || blob → A(64)
        const payload = Buffer.concat([accountBE(0), blob]);
        const A = await exchange(transport,
            buildApduBuffer(INS_DKG_RESTORE_SHARE, 0, 0, payload),
            "DKG_RESTORE_SHARE");
        assert.equal(A.length, 64, "RESTORE returns the 64-byte group key A");

        s = await exchange(transport, buildApduBuffer(INS_DKG_STATUS), "DKG_STATUS");
        assert.equal(s[0], DKG_STATE.PROVISIONED, "device must be PROVISIONED after restore");

        await exchange(transport, buildApduBuffer(INS_DKG_ABORT), "DKG_ABORT");
    });

    test("RESTORE_SHARE rejects a tampered blob (GCM tag)", async (t) => {
        if (!existsSync(fixture)) { t.skip("no blob fixture"); return; }
        const blob = Buffer.from(readFileSync(fixture, "utf8").trim(), "hex");
        const bad = Buffer.from(blob);
        bad[bad.length - 1] ^= 0x01; // flip a tag bit

        await exchange(transport, buildApduBuffer(INS_DKG_ABORT), "DKG_ABORT");
        await assert.rejects(
            () => exchange(transport,
                buildApduBuffer(INS_DKG_RESTORE_SHARE, 0, 0,
                    Buffer.concat([accountBE(0), bad])),
                "DKG_RESTORE_SHARE/tampered"),
            /b00[78]|fail|status/i,
            "a tampered blob must be rejected by the GCM tag");
    });
});
