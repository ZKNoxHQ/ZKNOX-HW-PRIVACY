//! Port of `js/apdu-constants.js` — the single source of truth for INS codes,
//! kept in sync with `src/apdu/dispatcher.c` and the `InsType` enum in
//! `tests/application_client/zknox_command_sender.py`.

/// `CLA`.
pub const CLA: u8 = 0xe0;

// ── Core commands ───────────────────────────────────────────────────────────
/// `INS_SIGNING_PUBKEY`.
pub const INS_SIGNING_PUBKEY: u8 = 0x01;
/// P1 of `SIGNING_PUBKEY`: no UI, DEBUG builds only.
pub const PUBKEY_P1_SILENT: u8 = 0x00;
/// P1 of `SIGNING_PUBKEY`: address-review flow, returned on approval.
pub const PUBKEY_P1_CONFIRM: u8 = 0x01;

/// `INS_BLIND_SIGN_NO_DISPLAY` — same as BLIND_SIGN without the approval UI.
pub const INS_BLIND_SIGN_NO_DISPLAY: u8 = 0x02;
/// `INS_GET_VERSION` — MAJOR(1)||MINOR(1)||PATCH(1).
pub const INS_GET_VERSION: u8 = 0x03;
/// `INS_GET_APP_NAME` — APPNAME bytes, no length prefix.
pub const INS_GET_APP_NAME: u8 = 0x04;
/// `INS_BLIND_SIGN`.
pub const INS_BLIND_SIGN: u8 = 0x12;
/// `INS_SIGN_WITH_PRIVKEY` — DEBUG builds only.
pub const INS_SIGN_WITH_PRIVKEY: u8 = 0x50;

// ── Viewing key and 0zk address ─────────────────────────────────────────────
// No JavaScript counterpart; the dispatcher maps them, so the Rust side names
// them. `rs/crates/zknox-sim` sweeps the whole instruction space and needs the
// map to be complete.
/// `INS_VIEWING_PUBKEY` — in: account(4), out: Ed25519 viewing pubkey.
pub const INS_VIEWING_PUBKEY: u8 = 0x10;
/// `INS_VIEWING_PRIVKEY` — in: account(4), out: the key, after approval.
pub const INS_VIEWING_PRIVKEY: u8 = 0x13;
/// `INS_RAILGUN_ADDRESS` — in: account(4), out: the canonical 0zk1… address.
pub const INS_RAILGUN_ADDRESS: u8 = 0x14;

// ── Curve IDs (P1 of the signing instructions) ──────────────────────────────
/// `CURVE_BABYJUBJUB_LEGACY` — P1=0 keeps the pre-selector default.
pub const CURVE_BABYJUBJUB_LEGACY: u8 = 0x00;
/// `CURVE_BANDERSNATCH`.
pub const CURVE_BANDERSNATCH: u8 = 0x01;
/// `CURVE_BABYJUBJUB`.
pub const CURVE_BABYJUBJUB: u8 = 0x02;

// ── DKG / VSS, INS 0x60–0x6b (FROST=1 builds) ───────────────────────────────
/// `INS_DKG_GET_COMM_PUBKEY` — in: account(4), out: HK(32).
pub const INS_DKG_GET_COMM_PUBKEY: u8 = 0x60;
/// `INS_DKG_DEAL` — in: acct(4) id t n nlen name, out: epoch(16)||C(t*64).
pub const INS_DKG_DEAL: u8 = 0x61;
/// `INS_DKG_SET_COMMITS` — P1 FIRST/NEXT/LAST, out: digest(32).
pub const INS_DKG_SET_COMMITS: u8 = 0x62;
/// `INS_DKG_GET_SHARE` — in: recipient_id(1), out: nonce(12)||ct(32)||tag(16).
pub const INS_DKG_GET_SHARE: u8 = 0x63;
/// `INS_DKG_PUT_SHARE` — in: j C_j nonce ct tag.
pub const INS_DKG_PUT_SHARE: u8 = 0x64;
/// `INS_DKG_FINALIZE` — out: A(64).
pub const INS_DKG_FINALIZE: u8 = 0x65;
/// `INS_DKG_ABORT`.
pub const INS_DKG_ABORT: u8 = 0x66;
/// `INS_DKG_STATUS` — out: state|id|t|n|mask(2).
pub const INS_DKG_STATUS: u8 = 0x67;
/// `INS_DKG_DEBUG_COMM_PRIVKEY` — DEBUG, in: account(4), out: privkey(32).
pub const INS_DKG_DEBUG_COMM_PRIVKEY: u8 = 0x68;
/// `INS_DKG_DEBUG_SKSHARE` — DEBUG, out: sk(32)||sk_div8(32).
pub const INS_DKG_DEBUG_SKSHARE: u8 = 0x69;
/// `INS_DKG_EXPORT_SHARE` — in: account(4), out: aad||nonce(12)||ct(32)||tag(16).
pub const INS_DKG_EXPORT_SHARE: u8 = 0x6a;
/// `INS_DKG_RESTORE_SHARE` — in: account(4)||blob, out: A(64).
pub const INS_DKG_RESTORE_SHARE: u8 = 0x6b;

/// `DKG_P1_FIRST`.
pub const DKG_P1_FIRST: u8 = 0x00;
/// `DKG_P1_NEXT`.
pub const DKG_P1_NEXT: u8 = 0x01;
/// `DKG_P1_LAST`.
pub const DKG_P1_LAST: u8 = 0x02;

/// DKG state machine values returned by STATUS (`DKG_STATE`).
pub mod dkg_state {
    /// `IDLE`.
    pub const IDLE: u8 = 0;
    /// `DEALT`.
    pub const DEALT: u8 = 1;
    /// `COMMITTED`.
    pub const COMMITTED: u8 = 2;
    /// `COLLECTED`.
    pub const COLLECTED: u8 = 3;
    /// `PROVISIONED`.
    pub const PROVISIONED: u8 = 4;
}

// ── FROST HW signing on the DKG output (INS 0x70–0x72) ──────────────────────
/// `INS_FROST_HW_COMMIT` — out: D(64)||E(64).
pub const INS_FROST_HW_COMMIT: u8 = 0x70;
/// `INS_FROST_HW_SIGN` — P1 FIRST/LAST, msg(32)||nsig*160, out: z_i(32).
pub const INS_FROST_HW_SIGN: u8 = 0x71;
/// `INS_FROST_HW_RESET`.
pub const INS_FROST_HW_RESET: u8 = 0x72;
/// `FROST_FS_REC` — id(32)||D.x||D.y||E.x||E.y, all big-endian.
pub const FROST_FS_REC: usize = 160;
/// `FROST_P1_FIRST`.
pub const FROST_P1_FIRST: u8 = 0x00;
/// P1 value that appends a chunk without resetting or finalizing.
pub const FROST_P1_NEXT: u8 = 0x01;
/// `FROST_P1_LAST`.
pub const FROST_P1_LAST: u8 = 0x02;

// ── Status words asserted by the tests ──────────────────────────────────────
/// `SW_OK`.
pub const SW_OK: &str = "9000";
/// `SW_WRONG_DATA_LENGTH`.
pub const SW_WRONG_DATA_LENGTH: &str = "6a87";
/// `SW_BAD_STATE`.
pub const SW_BAD_STATE: &str = "b007";
/// `SW_SIGNATURE_FAIL`.
pub const SW_SIGNATURE_FAIL: &str = "b008";

/// `buildApduBuffer` — CLA INS P1 P2 Lc [Data].
pub fn build_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![CLA, ins, p1, p2];
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    out
}

/// `buildApduBuffer(ins)` with no data.
pub fn build_apdu0(ins: u8) -> Vec<u8> {
    build_apdu(ins, 0, 0, &[])
}

/// `accountBE` / `accountBuf` — account index as 4-byte big-endian.
pub fn account_be(account: u32) -> [u8; 4] {
    account.to_be_bytes()
}

/// `buildDkgDealPayload` — account(4 BE) || id(1) || t(1) || n(1) || nlen(1) || name.
pub fn build_dkg_deal_payload(account: u32, id: u8, t: u8, n: u8, name: &str) -> Vec<u8> {
    let name = name.as_bytes();
    assert!(name.len() <= 32, "group name > 32 bytes");
    let mut out = account_be(account).to_vec();
    out.extend_from_slice(&[id, t, n, name.len() as u8]);
    out.extend_from_slice(name);
    out
}
