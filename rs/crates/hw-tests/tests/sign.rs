//! Port of `js/test/sign.test.js` — EdDSA-Poseidon blind signing on BabyJubjub.
//!
//! Three handlers exercised:
//!   - `BLIND_SIGN_NO_DISPLAY` (0x02): account + msg, BIP-32 derivation, no UI
//!   - `SIGN_WITH_PRIVKEY` (0x50): caller supplies the privkey
//!   - `BLIND_SIGN` (0x12): same as 0x02 but with UI approval
//!
//! The first two are DEBUG-only instructions, so this file needs `MODE=debug`.
//! `BLIND_SIGN` requires a manual confirmation; it is skipped unless
//! `INTERACTIVE=1` is set, so the suite stays unattended.
//!
//! The oracle is the Rust EdDSA-Poseidon of `frost-babyjubjub`, running the
//! same scheme off-device from a key derived host-side down
//! m/44'/1984'/account'/0'/0' — the app's PATH_SPENDING. A mismatch means the
//! device and the reference disagree about either the derivation or the
//! signature.

use zknox_hw_tests::apdu::*;
use zknox_hw_tests::context::{device_or_skip, interactive, using_sim};
use zknox_hw_tests::fixtures::{TEST_ACCOUNT, TEST_MNEMONIC};
use zknox_hw_tests::hex::{buf2hex, hex2buf};
use zknox_hw_tests::ledger::exchange;
use zknox_hw_tests::oracle::{circomlib_ref, derived_spending_key, SigHex};

const MSG_HEX: &str = "8c1f26718227707c6e5c61417b47daccafabca9f574c16e1521dd6a9c70d8405";

#[test]
fn blind_sign_no_display_matches_the_reference() {
    let Some(mut dev) = device_or_skip("blind_sign_no_display") else {
        return;
    };
    let msg = hex2buf(MSG_HEX);
    let priv_key = derived_spending_key(TEST_MNEMONIC, TEST_ACCOUNT);
    let reference = circomlib_ref(&priv_key, &msg);

    let mut data = account_be(TEST_ACCOUNT).to_vec();
    data.extend_from_slice(&msg);
    let resp = exchange(
        dev.transport(),
        &build_apdu(INS_BLIND_SIGN_NO_DISPLAY, 0, 0, &data),
        "BLIND_SIGN_NO_DISPLAY",
    )
    .expect("BLIND_SIGN_NO_DISPLAY");

    assert_eq!(resp.len(), 96, "expected 96-byte signature");
    assert_eq!(SigHex::from_response(&resp), reference);
}

#[test]
fn sign_with_privkey_matches_the_reference() {
    let Some(mut dev) = device_or_skip("sign_with_privkey") else {
        return;
    };
    let msg = hex2buf(MSG_HEX);
    let priv_key = derived_spending_key(TEST_MNEMONIC, TEST_ACCOUNT);
    let reference = circomlib_ref(&priv_key, &msg);

    let mut data = vec![CURVE_BABYJUBJUB];
    data.extend_from_slice(&priv_key);
    data.extend_from_slice(&msg);
    let resp = exchange(
        dev.transport(),
        &build_apdu(INS_SIGN_WITH_PRIVKEY, 0, 0, &data),
        "SIGN_WITH_PRIVKEY",
    )
    .expect("SIGN_WITH_PRIVKEY");

    assert_eq!(resp.len(), 96, "expected 96-byte signature");
    assert_eq!(SigHex::from_response(&resp), reference);
}

/// On hardware this one waits for a button press, so it needs `INTERACTIVE=1`.
/// The simulator's UI approves on its own, so there it runs with the rest and
/// covers the approval path the other two instructions skip.
#[test]
fn blind_sign_with_ui_matches_the_reference() {
    // Resolve this before taking the device: the mutex behind the shared
    // transport is not reentrant, and `using_sim` takes it too.
    let on_sim = using_sim();
    if !interactive() && !on_sim {
        eprintln!("SKIP blind_sign_with_ui: set INTERACTIVE=1 to run (requires manual approval)");
        return;
    }
    let Some(mut dev) = device_or_skip("blind_sign_with_ui") else {
        return;
    };
    let msg = hex2buf(MSG_HEX);
    let priv_key = derived_spending_key(TEST_MNEMONIC, TEST_ACCOUNT);
    let reference = circomlib_ref(&priv_key, &msg);

    if !on_sim {
        eprintln!("\n  Approve the blind-sign request on the device...");
    }
    let mut data = account_be(TEST_ACCOUNT).to_vec();
    data.extend_from_slice(&msg);
    let resp = exchange(
        dev.transport(),
        &build_apdu(INS_BLIND_SIGN, 0, 0, &data),
        "BLIND_SIGN",
    )
    .expect("BLIND_SIGN");

    // Response shape: len(1) | sig(96) | echoed msg_hash(32)
    assert_eq!(resp.len(), 129, "expected 129-byte blind-sign response");
    assert_eq!(resp[0], 96, "expected sig_len = 96");
    assert_eq!(SigHex::from_response(&resp[1..97]), reference);
    assert_eq!(buf2hex(&resp[97..129]), MSG_HEX, "echoed msg_hash mismatch");
}

/// The refusal path, which only the simulator can reach unattended:
/// `SIM_REJECT=1` makes its UI answer no, and the handler must then return
/// `SW_DENY` rather than a signature. Needs its own child, since the
/// simulator reads the variable once at startup.
#[test]
fn blind_sign_is_refused_when_the_user_rejects() {
    // Independent of the main transport: it drives its own simulator, so it
    // still runs in a device session, where the device itself cannot be made
    // to refuse without someone pressing the button.
    let binary = zknox_hw_tests::ledger::default_sim_binary();
    if !binary.exists() {
        eprintln!("SKIP blind_sign_rejected: no simulator built");
        return;
    }
    let mut rejecting = zknox_hw_tests::ledger::spawn_sim_with_env(&binary, &[("SIM_REJECT", "1")])
        .expect("spawn a rejecting simulator");

    let mut data = account_be(TEST_ACCOUNT).to_vec();
    data.extend_from_slice(&hex2buf(MSG_HEX));
    let err = exchange(
        &mut rejecting,
        &build_apdu(INS_BLIND_SIGN, 0, 0, &data),
        "BLIND_SIGN/rejected",
    )
    .expect_err("a refused review must not produce a signature");
    assert_ne!(err.sw, "9000", "refusal must not come back as success");
    eprintln!("BLIND_SIGN refused with SW={}", err.sw);
}
