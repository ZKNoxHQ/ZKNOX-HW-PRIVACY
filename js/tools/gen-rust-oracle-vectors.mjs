// gen-rust-oracle-vectors.mjs — freezes the circomlib oracle into vectors the
// Rust suite checks itself against, so `cargo test` needs no node.
//
//   node tools/gen-rust-oracle-vectors.mjs <inputs.json> <out.json>
//
// Inputs are generated separately with the OS CSPRNG (see
// rs/xcheck/gen-oracle-inputs.py); this script only computes what circomlib
// says the answer is, with exactly the reference the JS suite uses.

import { readFileSync, writeFileSync } from "node:fs";
import { buildEddsa, buildBabyjub } from "circomlibjs";

import { hex2buf, buf2hex, toHex } from "../lib/hex.js";
import { mnemonicToSeed, getMasterKeyFromSeed, derivePath } from "../lib/slip0010.js";

const eddsa = await buildEddsa();
const F = (await buildBabyjub()).F;

// Same function as js/test/sign.test.js.
function circomlibRef(privBytes, msg) {
    const sig = eddsa.signPoseidon(privBytes, F.toMontgomery(msg));
    return {
        r8x: buf2hex(new Uint8Array(F.fromMontgomery(sig.R8[0])).reverse()),
        r8y: buf2hex(new Uint8Array(F.fromMontgomery(sig.R8[1])).reverse()),
        s: sig.S.toString(16).padStart(64, "0"),
    };
}

const inputs = JSON.parse(readFileSync(process.argv[2], "utf8"));

const signatures = inputs.signatures.map(({ priv, msg }) => ({
    priv,
    msg,
    expected: circomlibRef(hex2buf(priv), hex2buf(msg)),
}));

const derivations = inputs.derivations.map(({ mnemonic, path }) => {
    const master = getMasterKeyFromSeed(toHex(mnemonicToSeed(mnemonic)));
    return {
        mnemonic,
        path,
        seed: toHex(mnemonicToSeed(mnemonic)),
        masterChainKey: master.chainKey,
        masterChainCode: master.chainCode,
        chainKey: derivePath(master, path).chainKey,
    };
});

writeFileSync(process.argv[3], JSON.stringify({ signatures, derivations }, null, 1));
console.log(`${signatures.length} signatures, ${derivations.length} derivations -> ${process.argv[3]}`);
