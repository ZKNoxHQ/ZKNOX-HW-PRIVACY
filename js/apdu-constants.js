// apdu-constants.js — Single source of truth for APDU INS codes.
//
// Must stay in sync with src/apdu/dispatcher.c and the InsType enum in
// tests/application_client/zknox_command_sender.py.
//
// This app's surface is narrower than the RAILGUN app's: no clear-sign, no
// viewing key, no secp256k1/7702. Only the instructions the C code actually
// dispatches are listed here.

export const CLA = 0xe0;

// ── Core commands ───────────────────────────────────────────────────────────
export const INS_SIGNING_PUBKEY = 0x01;
// P1 of SIGNING_PUBKEY: 0x00 returns the key with no UI (DEBUG builds only),
// 0x01 shows the address-review flow and returns it on approval.
export const PUBKEY_P1_SILENT = 0x00;
export const PUBKEY_P1_CONFIRM = 0x01;

// BLIND_SIGN_NO_DISPLAY: same as BLIND_SIGN but skips the approval UI.
// DEBUG builds only (MODE=debug).
export const INS_BLIND_SIGN_NO_DISPLAY = 0x02;

export const INS_GET_VERSION = 0x03; // returns MAJOR(1)||MINOR(1)||PATCH(1)
export const INS_GET_APP_NAME = 0x04; // returns APPNAME bytes, no length prefix

export const INS_BLIND_SIGN = 0x12;
export const INS_SIGN_WITH_PRIVKEY = 0x50; // DEBUG builds only

// ── Curve IDs (P1 of the signing instructions) ──────────────────────────────
export const CURVE_BABYJUBJUB_LEGACY = 0x00; // P1=0 keeps the pre-selector default
export const CURVE_BANDERSNATCH = 0x01;
export const CURVE_BABYJUBJUB = 0x02;

// ─────────────────────────────────────────────────────────────────────
// DKG / VSS — INS 0x60–0x6b. FROST=1 builds only; 0x68/0x69 also need
// MODE=debug. The ceremony state (g_dkg) lives in RAM: on a real device the
// whole DEAL→FINALIZE run must stay in ONE transport session, or it is lost.
// ─────────────────────────────────────────────────────────────────────
export const INS_DKG_GET_COMM_PUBKEY = 0x60; // in: account(4)        out: HK(32)
export const INS_DKG_DEAL = 0x61; // in: acct(4) id t n nlen name  out: epoch(16)||C(t*64)
export const INS_DKG_SET_COMMITS = 0x62; // P1 FIRST/NEXT/LAST      out: digest(32)
export const INS_DKG_GET_SHARE = 0x63; // in: recipient_id(1)  out: nonce(12)||ct(32)||tag(16)
export const INS_DKG_PUT_SHARE = 0x64; // in: j C_j nonce ct tag   out: -
export const INS_DKG_FINALIZE = 0x65; // in: -                    out: A(64)
export const INS_DKG_ABORT = 0x66; // in: -                    out: -
export const INS_DKG_STATUS = 0x67; // in: -   out: state|id|t|n|mask(2)
export const INS_DKG_DEBUG_COMM_PRIVKEY = 0x68; // DEBUG  in: account(4) out: privkey(32)
export const INS_DKG_DEBUG_SKSHARE = 0x69; // DEBUG  in: -  out: sk(32)||sk_div8(32)
export const INS_DKG_EXPORT_SHARE = 0x6a; // in: account(4)  out: aad||nonce(12)||ct(32)||tag(16)
export const INS_DKG_RESTORE_SHARE = 0x6b; // in: account(4)||blob  out: A(64)

export const DKG_P1_FIRST = 0x00;
export const DKG_P1_NEXT = 0x01;
export const DKG_P1_LAST = 0x02;

// DKG state machine values returned by STATUS.
export const DKG_STATE = { IDLE: 0, DEALT: 1, COMMITTED: 2, COLLECTED: 3, PROVISIONED: 4 };

// ── FROST HW signing on the DKG output (INS 0x70–0x72) ──────────────────────
// COMMIT takes no data and returns 128 B (hiding‖binding). SIGN streams
// msg(32)‖signers, each signer FS_REC = 160 B = id(32)‖D.x‖D.y‖E.x‖E.y.
export const INS_FROST_HW_COMMIT = 0x70; // in: -                out: D(64)||E(64)
export const INS_FROST_HW_SIGN = 0x71; // P1 FIRST/LAST; msg(32)||nsig*160  out: z_i(32)
export const INS_FROST_HW_RESET = 0x72; // in: -                out: -
export const FROST_FS_REC = 160; // id(32)||D.x||D.y||E.x||E.y, all BE
export const FROST_P1_FIRST = 0x00;
export const FROST_P1_LAST = 0x02;

// ── Status words asserted by the tests ──────────────────────────────────────
export const SW_OK = "9000";
export const SW_WRONG_DATA_LENGTH = "6a87";
export const SW_BAD_STATE = "b007";
export const SW_SIGNATURE_FAIL = "b008";

// ── Helpers ─────────────────────────────────────────────────────────────────
// Build a Buffer APDU: CLA INS P1 P2 Lc [Data]
export function buildApduBuffer(ins, p1 = 0, p2 = 0, data = null) {
    const header = Buffer.from([CLA, ins, p1, p2]);
    if (!data || data.length === 0) return Buffer.concat([header, Buffer.from([0])]);
    return Buffer.concat([header, Buffer.from([data.length]), data]);
}

// Encode account index as 4-byte big-endian Buffer, as the handlers read it.
export function accountBE(account = 0) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(account >>> 0, 0);
    return b;
}
export const accountBuf = accountBE;

// DKG_DEAL payload: account(4 BE) || id(1) || t(1) || n(1) || name_len(1) || name.
export function buildDkgDealPayload(account, id, t, n, name) {
    const nameBuf = Buffer.from(name, "utf8");
    if (nameBuf.length > 32) throw new Error("group name > 32 bytes");
    return Buffer.concat([accountBE(account), Buffer.from([id, t, n, nameBuf.length]), nameBuf]);
}
