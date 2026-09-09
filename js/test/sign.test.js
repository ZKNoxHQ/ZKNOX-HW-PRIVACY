// sign.test.js — EdDSA-Poseidon blind signing on BabyJubjub.
//
// Three handlers exercised:
//   - BLIND_SIGN_NO_DISPLAY (INS=0x02): account+msg, BIP-32 derivation, no UI
//   - SIGN_WITH_PRIVKEY     (INS=0x50): caller supplies the privkey
//   - BLIND_SIGN            (INS=0x12): same as 0x02 but with UI approval
//
// The first two are DEBUG-only instructions, so this file needs MODE=debug.
// BLIND_SIGN requires manual confirmation on-device; it is skipped unless
// INTERACTIVE=1 is set, so `npm test` stays unattended.
//
// The oracle is circomlib, running the same EdDSA-Poseidon scheme off-device
// from a key derived host-side down m/44'/1984'/account'/0'/0' — the app's
// PATH_SPENDING. A mismatch means the device and the reference disagree about
// either the derivation or the signature.

import { describe, before, test } from "node:test";
import assert from "node:assert/strict";

import { buildEddsa, buildBabyjub } from "circomlibjs";

import { hex2buf, buf2hex, toHex } from "../lib/hex.js";
import { mnemonicToSeed, getMasterKeyFromSeed, derivePath } from "../lib/slip0010.js";
import { exchange } from "../lib/ledger.js";
import { requireDevice } from "../lib/test-context.js";
import {
    INS_BLIND_SIGN_NO_DISPLAY,
    INS_BLIND_SIGN,
    INS_SIGN_WITH_PRIVKEY,
    CURVE_BABYJUBJUB,
    buildApduBuffer,
    accountBuf,
} from "../apdu-constants.js";
import { TEST_MNEMONIC, TEST_ACCOUNT } from "../fixtures/test-mnemonic.js";

const MSG_HEX = "8c1f26718227707c6e5c61417b47daccafabca9f574c16e1521dd6a9c70d8405";

function circomlibRef(eddsa, F, privBytes, msg) {
    // The device's EdDSA-Poseidon implementation hashes the message in
    // Montgomery form; the matching circomlib call is signPoseidon(prv, toMontgomery(msg)).
    const sig = eddsa.signPoseidon(privBytes, F.toMontgomery(msg));
    return {
        r8x: buf2hex(new Uint8Array(F.fromMontgomery(sig.R8[0])).reverse()),
        r8y: buf2hex(new Uint8Array(F.fromMontgomery(sig.R8[1])).reverse()),
        s: sig.S.toString(16).padStart(64, "0"),
    };
}

describe("blind sign (EdDSA-Poseidon / BabyJubjub)", () => {
    let transport;
    let eddsa, F;
    let derivedPrivHex;

    before(async (t) => {
        transport = await requireDevice(t);
        eddsa = await buildEddsa();
        F = (await buildBabyjub()).F;
        const seed = mnemonicToSeed(TEST_MNEMONIC);
        const master = getMasterKeyFromSeed(toHex(seed));
        // PATH_SPENDING — m/44'/1984'/account'/0'/0', all hardened.
        derivedPrivHex = derivePath(master, [44, 1984, TEST_ACCOUNT, 0, 0]).chainKey;
    });

    test("BLIND_SIGN_NO_DISPLAY (0x02) — account-derived key matches circomlib", async () => {
        const msg = hex2buf(MSG_HEX);
        const ref = circomlibRef(eddsa, F, hex2buf(derivedPrivHex), msg);

        const resp = await exchange(transport,
            buildApduBuffer(INS_BLIND_SIGN_NO_DISPLAY, 0, 0,
                Buffer.concat([accountBuf(TEST_ACCOUNT), msg])),
            "BLIND_SIGN_NO_DISPLAY");
        assert.equal(resp.length, 96, "expected 96-byte signature");
        assert.deepEqual(
            {
                r8x: buf2hex(resp.slice(0, 32)),
                r8y: buf2hex(resp.slice(32, 64)),
                s: buf2hex(resp.slice(64, 96)),
            },
            ref,
        );
    });

    test("SIGN_WITH_PRIVKEY (0x50) — raw privkey matches circomlib", async () => {
        const msg = hex2buf(MSG_HEX);
        const priv = hex2buf(derivedPrivHex);
        const ref = circomlibRef(eddsa, F, priv, msg);

        const apduData = Buffer.concat([Buffer.from([CURVE_BABYJUBJUB]), priv, msg]);
        const resp = await exchange(transport,
            buildApduBuffer(INS_SIGN_WITH_PRIVKEY, 0, 0, apduData),
            "SIGN_WITH_PRIVKEY");
        assert.equal(resp.length, 96, "expected 96-byte signature");
        assert.deepEqual(
            {
                r8x: buf2hex(resp.slice(0, 32)),
                r8y: buf2hex(resp.slice(32, 64)),
                s: buf2hex(resp.slice(64, 96)),
            },
            ref,
        );
    });

    test("BLIND_SIGN (0x12) — UI-approved sig matches BLIND_SIGN_NO_DISPLAY", {
        skip: !process.env.INTERACTIVE && "set INTERACTIVE=1 to run (requires manual approval)",
    }, async () => {
        const msg = hex2buf(MSG_HEX);
        const ref = circomlibRef(eddsa, F, hex2buf(derivedPrivHex), msg);

        console.log("\n  ⚠️  Approve the blind-sign request on the device...");
        const resp = await exchange(transport,
            buildApduBuffer(INS_BLIND_SIGN, 0, 0,
                Buffer.concat([accountBuf(TEST_ACCOUNT), msg])),
            "BLIND_SIGN");

        // Response shape: len(1) | sig(96) | echoed msg_hash(32)
        assert.equal(resp.length, 129, "expected 129-byte blind-sign response");
        assert.equal(resp[0], 96, "expected sig_len = 96");
        assert.deepEqual(
            {
                r8x: buf2hex(resp.slice(1, 33)),
                r8y: buf2hex(resp.slice(33, 65)),
                s: buf2hex(resp.slice(65, 97)),
            },
            ref,
        );
        assert.equal(buf2hex(resp.slice(97, 129)), MSG_HEX, "echoed msg_hash mismatch");
    });
});
