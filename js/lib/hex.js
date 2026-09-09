// lib/hex.js — Shared hex/buffer conversion helpers

export const hex2buf = h => Buffer.from(h, "hex");
export const buf2hex = b => Buffer.from(b).toString("hex");
export const reverse = b => Buffer.from(Buffer.from(b)).reverse();

export function toHex(arr) {
  return Array.from(new Uint8Array(arr)).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}

export function nToHex(n, byteLen) {
  return n.toString(16).padStart(byteLen * 2, "0");
}
