// lib/slip0010.js — SLIP-0010 key derivation (HMAC key = "babyjubjub seed")

import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { toHex, hexToBytes } from "./hex.js";

export function mnemonicToSeed(m) {
  const enc = new TextEncoder();
  return pbkdf2(sha512, enc.encode(m.normalize("NFKD")), enc.encode("mnemonic"), { c: 2048, dkLen: 64 });
}

export function getMasterKeyFromSeed(seedHex) {
  const key = new TextEncoder().encode("babyjubjub seed");
  const I = hmac(sha512, key, hexToBytes(seedHex));
  return { chainKey: toHex(I.slice(0, 32)), chainCode: toHex(I.slice(32)) };
}

export function childDerive(parent, index) {
  const idxHex = (index + 0x80000000).toString(16).padStart(8, "0");
  const I = hmac(sha512, hexToBytes(parent.chainCode), hexToBytes("00" + parent.chainKey + idxHex));
  return { chainKey: toHex(I.slice(0, 32)), chainCode: toHex(I.slice(32)) };
}

export function derivePath(master, segments) {
  let node = master;
  for (const idx of segments) node = childDerive(node, idx);
  return node;
}
