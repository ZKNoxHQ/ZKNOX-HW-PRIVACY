//! Port of `js/test/dkg.test.js` — VSS/DKG APDUs (INS 0x60–0x6b). Needs a
//! `FROST=1` build.
//!
//! Two things decide what is unit-testable here:
//!   - state: the ceremony state (`g_dkg`) is in RAM, so DEAL→FINALIZE only
//!     makes sense within one transport session. STATUS/ABORT/GET_COMM_PUBKEY
//!     need no state and stand alone.
//!   - determinism: DEAL draws a fresh epoch and GET_SHARE a fresh nonce, so
//!     their output cannot be compared byte for byte, only checked for shape.
//!
//! This file does not sign, so it is safe on any firmware: the CX-wipe hazard
//! only applies to FROST signing, kept out of here.

use num_bigint::BigUint;

use zknox_hw_tests::apdu::{dkg_state, *};
use zknox_hw_tests::context::{default_seed, device_or_skip};
use zknox_hw_tests::fixtures::{fixture_path, TEST_MNEMONIC};
use zknox_hw_tests::hex::{buf2hex, hex2buf};
use zknox_hw_tests::ledger::exchange;
use zknox_hw_tests::oracle::dkg_comm_pubkey;

/// BabyJubJub prime — to sanity-check that DEAL's commitment coordinates are
/// field elements, a cheap validity check short of full on-curve verification.
fn field_prime() -> BigUint {
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
        .parse()
        .unwrap()
}

fn be_to_big(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(b)
}

/// Oracle for the yellow×12 seed, captured from this app on Speculos. It
/// matches the value the RAILGUN app produces — both derive KEY_TYPE_DKG_COMM
/// down the same libC path (m/421'/1984'/account'/0'/0') — so agreement is
/// expected and a divergence would mean one of them moved.
const HK_YELLOW_ACCT0: &str = "9fc8d2779ee5bfb7662e02b5c8e23c71a4de3045621b15e031cbe481687de081";

#[test]
fn get_comm_pubkey_is_32_bytes_and_stable() {
    let Some(mut dev) = device_or_skip("get_comm_pubkey_stable") else {
        return;
    };
    let apdu = build_apdu(INS_DKG_GET_COMM_PUBKEY, 0, 0, &account_be(0));
    let a = exchange(dev.transport(), &apdu, "DKG_GET_COMM_PUBKEY").expect("GET_COMM_PUBKEY");
    assert_eq!(a.len(), 32, "HK must be 32 bytes");
    let b = exchange(dev.transport(), &apdu, "DKG_GET_COMM_PUBKEY/again").expect("again");
    assert_eq!(a, b, "comm key must be deterministic for a fixed seed");
}

/// The DKG transport identity must not be reachable from a key the app hands
/// out. This app has no viewing key (a RAILGUN concept), so the exportable
/// counterpart is the signing key; P1=0 is the silent variant, DEBUG only.
#[test]
fn dkg_identity_is_separate_from_the_signing_key() {
    let Some(mut dev) = device_or_skip("dkg_identity_separate") else {
        return;
    };
    let account = account_be(0);
    let hk = exchange(
        dev.transport(),
        &build_apdu(INS_DKG_GET_COMM_PUBKEY, 0, 0, &account),
        "DKG_GET_COMM_PUBKEY",
    )
    .expect("GET_COMM_PUBKEY");
    let signing = exchange(
        dev.transport(),
        &build_apdu(INS_SIGNING_PUBKEY, PUBKEY_P1_SILENT, 0, &account),
        "SIGNING_PUBKEY",
    )
    .expect("SIGNING_PUBKEY");
    // `subarray` on the JavaScript side simply yields a shorter slice when the
    // signing key is shorter, so clamp rather than panic on the range.
    let n = hk.len().min(signing.len());
    assert_ne!(
        hk[..n],
        signing[..n],
        "non-exported DKG identity must not reuse the signing-key path"
    );
}

/// Two independent references for one key: the frozen capture above, and the
/// host derivation [`dkg_comm_pubkey`] runs from the mnemonic (SLIP-0010 with
/// the `"babyjubjub seed"` HMAC key, then the Ed25519 public key of the node).
/// The derivation is what `ceremony.rs` checks every participant against,
/// including the ones on a random seed, so pinning it here against a value
/// captured before it existed is what rules out two sides agreeing on the
/// wrong answer.
#[test]
fn get_comm_pubkey_matches_the_yellow_oracle() {
    assert_eq!(
        buf2hex(&dkg_comm_pubkey(TEST_MNEMONIC, 0)),
        HK_YELLOW_ACCT0,
        "the host derivation must reproduce the captured oracle"
    );
    if !default_seed() {
        eprintln!("SKIP yellow oracle: non-default seed");
        return;
    }
    let Some(mut dev) = device_or_skip("get_comm_pubkey_oracle") else {
        return;
    };
    let a = exchange(
        dev.transport(),
        &build_apdu(INS_DKG_GET_COMM_PUBKEY, 0, 0, &account_be(0)),
        "DKG_GET_COMM_PUBKEY",
    )
    .expect("GET_COMM_PUBKEY");
    assert_eq!(
        buf2hex(&a),
        HK_YELLOW_ACCT0,
        "HK must byte-match the yellow×12 oracle"
    );
}

#[test]
fn status_reports_a_well_formed_state() {
    let Some(mut dev) = device_or_skip("status_well_formed") else {
        return;
    };
    let s = exchange(dev.transport(), &build_apdu0(INS_DKG_STATUS), "DKG_STATUS").expect("STATUS");
    assert_eq!(s.len(), 6, "status is state|id|t|n|mask(2)");
    assert!(s[0] <= dkg_state::PROVISIONED, "state in range");
}

#[test]
fn abort_returns_to_idle() {
    let Some(mut dev) = device_or_skip("abort_returns_to_idle") else {
        return;
    };
    exchange(dev.transport(), &build_apdu0(INS_DKG_ABORT), "DKG_ABORT").expect("ABORT");
    let s = exchange(dev.transport(), &build_apdu0(INS_DKG_STATUS), "DKG_STATUS").expect("STATUS");
    assert_eq!(s[0], dkg_state::IDLE, "state must be IDLE after ABORT");
}

#[test]
fn deal_yields_a_fresh_epoch_and_on_field_commitments() {
    let Some(mut dev) = device_or_skip("deal_shape") else {
        return;
    };
    exchange(dev.transport(), &build_apdu0(INS_DKG_ABORT), "DKG_ABORT").expect("ABORT");
    let (t, n) = (2u8, 3u8);
    let out = exchange(
        dev.transport(),
        &build_apdu(
            INS_DKG_DEAL,
            0,
            0,
            &build_dkg_deal_payload(0, 1, t, n, "unit-test"),
        ),
        "DKG_DEAL",
    )
    .expect("DEAL");
    assert_eq!(out.len(), 16 + t as usize * 64, "epoch(16) || C(t*64)");
    let p = field_prime();
    for k in 0..t as usize {
        let x = be_to_big(&out[16 + k * 64..16 + k * 64 + 32]);
        let y = be_to_big(&out[16 + k * 64 + 32..16 + k * 64 + 64]);
        assert!(x < p && y < p, "commitment {k} coordinates in field");
    }
    let s = exchange(dev.transport(), &build_apdu0(INS_DKG_STATUS), "DKG_STATUS").expect("STATUS");
    assert_eq!(s[0], dkg_state::DEALT, "state must be DEALT after DEAL");
    exchange(dev.transport(), &build_apdu0(INS_DKG_ABORT), "DKG_ABORT").expect("ABORT");
}

/// The round-1 barrier: GET_SHARE before COMMITTED must be refused.
#[test]
fn get_share_before_committed_is_refused() {
    let Some(mut dev) = device_or_skip("get_share_barrier") else {
        return;
    };
    exchange(dev.transport(), &build_apdu0(INS_DKG_ABORT), "DKG_ABORT").expect("ABORT");
    exchange(
        dev.transport(),
        &build_apdu(
            INS_DKG_DEAL,
            0,
            0,
            &build_dkg_deal_payload(0, 1, 2, 3, "unit-test"),
        ),
        "DKG_DEAL",
    )
    .expect("DEAL");
    // now in DEALT, not COMMITTED → GET_SHARE must fail with SW_BAD_STATE
    let err = exchange(
        dev.transport(),
        &build_apdu(INS_DKG_GET_SHARE, 0, 0, &[2]),
        "DKG_GET_SHARE",
    )
    .expect_err("GET_SHARE must be refused before COMMITTED");
    assert_eq!(
        err.sw, SW_BAD_STATE,
        "expected SW_BAD_STATE, got {}",
        err.sw
    );
    exchange(dev.transport(), &build_apdu0(INS_DKG_ABORT), "DKG_ABORT").expect("ABORT");
}

// ── RESTORE_SHARE: a unit test by shortcut ──────────────────────────────
// RESTORE only needs the IDLE start state — no ceremony to build up to. Feed a
// pre-captured backup blob into a fresh device; it must decrypt straight to
// PROVISIONED and return A. This exercises the real AES-GCM decrypt and the
// backup-key derivation, neither of which is bypassed by BACKEND=sw.
//
// The blob is seed-bound: it only restores on a device holding the same seed
// it was exported from (yellow×12). See js/README.md for how it was produced.

fn restore_blob() -> Option<Vec<u8>> {
    let path = fixture_path("restore-blob-yellow.hex");
    match std::fs::read_to_string(&path) {
        Ok(s) => Some(hex2buf(s.trim())),
        Err(_) => {
            eprintln!("SKIP: no blob fixture at {}", path.display());
            None
        }
    }
}

#[test]
fn restore_share_provisions_the_device() {
    if !default_seed() {
        eprintln!("SKIP restore_share: blob is bound to yellow×12");
        return;
    }
    let Some(blob) = restore_blob() else { return };
    let Some(mut dev) = device_or_skip("restore_share") else {
        return;
    };

    exchange(dev.transport(), &build_apdu0(INS_DKG_ABORT), "DKG_ABORT").expect("ABORT");
    let s = exchange(dev.transport(), &build_apdu0(INS_DKG_STATUS), "DKG_STATUS").expect("STATUS");
    assert_eq!(s[0], dkg_state::IDLE, "must start IDLE");

    // RESTORE: account(4 BE) || blob → A(64)
    let mut payload = account_be(0).to_vec();
    payload.extend_from_slice(&blob);
    let a = exchange(
        dev.transport(),
        &build_apdu(INS_DKG_RESTORE_SHARE, 0, 0, &payload),
        "DKG_RESTORE_SHARE",
    )
    .expect("RESTORE");
    assert_eq!(a.len(), 64, "RESTORE returns the 64-byte group key A");

    let s = exchange(dev.transport(), &build_apdu0(INS_DKG_STATUS), "DKG_STATUS").expect("STATUS");
    assert_eq!(
        s[0],
        dkg_state::PROVISIONED,
        "device must be PROVISIONED after restore"
    );
    exchange(dev.transport(), &build_apdu0(INS_DKG_ABORT), "DKG_ABORT").expect("ABORT");
}

#[test]
fn restore_share_rejects_a_tampered_blob() {
    let Some(blob) = restore_blob() else { return };
    let Some(mut dev) = device_or_skip("restore_share_tampered") else {
        return;
    };
    let mut bad = blob.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01; // flip a tag bit

    exchange(dev.transport(), &build_apdu0(INS_DKG_ABORT), "DKG_ABORT").expect("ABORT");
    let mut payload = account_be(0).to_vec();
    payload.extend_from_slice(&bad);
    let err = exchange(
        dev.transport(),
        &build_apdu(INS_DKG_RESTORE_SHARE, 0, 0, &payload),
        "DKG_RESTORE_SHARE/tampered",
    )
    .expect_err("a tampered blob must be rejected by the GCM tag");
    assert!(
        err.sw == SW_BAD_STATE || err.sw == SW_SIGNATURE_FAIL,
        "expected b007 or b008, got {}",
        err.sw
    );
}
