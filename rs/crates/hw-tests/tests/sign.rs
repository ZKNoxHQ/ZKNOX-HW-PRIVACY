//! Port of `js/test/sign.test.js` — EdDSA-Poseidon blind signing on BabyJubjub,
//! and on Bandersnatch against fixed vectors: the signature, the key of the
//! `"bandersnatch seed"` master the app derives for that curve, its public key.
//!
//! Four handlers exercised:
//!   - `BLIND_SIGN_NO_DISPLAY` (0x02): account + msg, BIP-32 derivation, no UI
//!   - `SIGN_WITH_PRIVKEY` (0x50): caller supplies the privkey
//!   - `BLIND_SIGN` (0x12): same as 0x02 but with UI approval
//!   - `SIGNING_PUBKEY` (0x01), silent: the public key of a curve
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
use zknox_hw_tests::ledger::{exchange, try_exchange};
use zknox_hw_tests::oracle::{
    circomlib_ref, derived_bandersnatch_key, derived_spending_key, SigHex,
};

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

/// Key of the Bandersnatch test, 32 bytes drawn at random once.
const BANDERSNATCH_PRIV_HEX: &str =
    "c81b5c7619d5314492e8cf7f43a40cc665e618584a4ffb549a75f86fb2d96525";

/// Its reference. This crate has no off-device EdDSA on Bandersnatch, so the
/// references of this curve are fixed vectors. They come from a signer
/// written apart from ZKNOX-LibC: Python integers for the curve, BLAKE-512
/// from the `blake-hash` package of circomlibjs, and the Poseidon instance of
/// the BLS12-381 scalar field (255/6/8/60) from the reference generator of
/// ZKNOX-Poseidons. That signer returns the circomlibjs signature on
/// BabyJubjub, and its Bandersnatch signatures satisfy `[S]B = R + [8h]A`.
/// Until the library hashed with that instance it used the BN254 constants
/// over the BLS12-381 field, and the `S` of this vector was another.
const BANDERSNATCH_SIG_HEX: &str = "44f9c1558b279b5570d2ff44170b40e2147e71240d6dbf4bde025c550e469b1d\
                                    0d15c0bc2055650be0231d1bc64c8cb55c04d07555be1384e5c4aff237c72d75\
                                    188e71c5958b60c144c0e807664dcc4971f4beb995728601e6c0b06f74015107";

#[test]
fn sign_with_privkey_on_bandersnatch_matches_the_reference() {
    let Some(mut dev) = device_or_skip("sign_with_privkey_on_bandersnatch") else {
        return;
    };

    let mut data = vec![CURVE_BANDERSNATCH];
    data.extend_from_slice(&hex2buf(BANDERSNATCH_PRIV_HEX));
    data.extend_from_slice(&hex2buf(MSG_HEX));
    let resp = exchange(
        dev.transport(),
        &build_apdu(INS_SIGN_WITH_PRIVKEY, 0, 0, &data),
        "SIGN_WITH_PRIVKEY/Bandersnatch",
    )
    .expect("SIGN_WITH_PRIVKEY on Bandersnatch");

    assert_eq!(resp.len(), 96, "expected 96-byte signature");
    assert_eq!(buf2hex(&resp), BANDERSNATCH_SIG_HEX);
}

/// The Bandersnatch public key of account 0 on the test mnemonic, from the
/// same signer as [`BANDERSNATCH_SIG_HEX`]: SLIP-0010 down the spending path
/// under `"bandersnatch seed"`, then the circomlib key derivation on
/// Bandersnatch.
const BANDERSNATCH_PUBKEY_HEX: &str = "35272b1b008a8805cc3c7debb8ee215e33796cbac673ee5c8b6ce97056eac0d1\
                                       71c6eb6202c0f6053f3ad336fa8f197b7dbdf851828bc18b5652f256280f3d12";

/// Its signature of `MSG_HEX`, from that signer too.
const BANDERSNATCH_BLIND_SIG_HEX: &str = "70c61a1ad9c8d61367ea2135a4e2a9efa02d364310be72b91b9bd9435da01e7f\
                                          2e6dd4f3136eec1cf05923db3c9416b0f5922bea494dfe424772330a521caea2\
                                          07d914b1fc1679199a4d1bc8e3a61d810936f998b06985d025ad625d68e7f0a7";

/// On Bandersnatch the app signs with the key of the `"bandersnatch seed"`
/// master. Checked three ways: against the fixed vector, against
/// `SIGN_WITH_PRIVKEY` fed the key this crate derives under that master, and
/// against the same command fed the BabyJubjub key, which must sign otherwise.
#[test]
fn blind_sign_on_bandersnatch_uses_the_bandersnatch_seed_key() {
    let Some(mut dev) = device_or_skip("blind_sign_on_bandersnatch") else {
        return;
    };
    let msg = hex2buf(MSG_HEX);

    let mut data = account_be(TEST_ACCOUNT).to_vec();
    data.extend_from_slice(&msg);
    let derived = exchange(
        dev.transport(),
        &build_apdu(INS_BLIND_SIGN_NO_DISPLAY, CURVE_BANDERSNATCH, 0, &data),
        "BLIND_SIGN_NO_DISPLAY/Bandersnatch",
    )
    .expect("BLIND_SIGN_NO_DISPLAY on Bandersnatch");
    assert_eq!(derived.len(), 96, "expected 96-byte signature");
    assert_eq!(buf2hex(&derived), BANDERSNATCH_BLIND_SIG_HEX);

    let mut with_key = |key: [u8; 32], label: &str| {
        let mut data = vec![CURVE_BANDERSNATCH];
        data.extend_from_slice(&key);
        data.extend_from_slice(&msg);
        exchange(
            dev.transport(),
            &build_apdu(INS_SIGN_WITH_PRIVKEY, 0, 0, &data),
            label,
        )
        .expect("SIGN_WITH_PRIVKEY on Bandersnatch")
    };
    let own = with_key(
        derived_bandersnatch_key(TEST_MNEMONIC, TEST_ACCOUNT),
        "SIGN_WITH_PRIVKEY/bandersnatch seed",
    );
    let other = with_key(
        derived_spending_key(TEST_MNEMONIC, TEST_ACCOUNT),
        "SIGN_WITH_PRIVKEY/babyjubjub seed",
    );
    assert_eq!(
        buf2hex(&derived),
        buf2hex(&own),
        "the key of the bandersnatch seed master"
    );
    assert_ne!(
        buf2hex(&derived),
        buf2hex(&other),
        "not the key of the babyjubjub seed master"
    );
}

/// `SIGNING_PUBKEY` takes the curve in P2, as `BLIND_SIGN` takes it in P1:
/// Bandersnatch has its own key, 0 and 2 both name the BabyJubjub one, and
/// any other value is refused.
#[test]
fn signing_pubkey_follows_the_curve_in_p2() {
    let Some(mut dev) = device_or_skip("signing_pubkey_follows_the_curve") else {
        return;
    };
    let account = account_be(TEST_ACCOUNT);
    let mut pubkey = |p2: u8| {
        try_exchange(
            dev.transport(),
            &build_apdu(INS_SIGNING_PUBKEY, PUBKEY_P1_SILENT, p2, &account),
            "SIGNING_PUBKEY",
        )
    };

    let bandersnatch = pubkey(CURVE_BANDERSNATCH).expect("SIGNING_PUBKEY on Bandersnatch");
    assert_eq!(buf2hex(&bandersnatch), BANDERSNATCH_PUBKEY_HEX);

    let legacy = pubkey(CURVE_BABYJUBJUB_LEGACY).expect("SIGNING_PUBKEY, P2 = 0");
    let babyjubjub = pubkey(CURVE_BABYJUBJUB).expect("SIGNING_PUBKEY on BabyJubjub");
    assert_eq!(legacy.len(), 64);
    assert_eq!(
        buf2hex(&legacy),
        buf2hex(&babyjubjub),
        "P2 = 0 and P2 = 2 are the same key"
    );
    assert_ne!(
        buf2hex(&legacy),
        buf2hex(&bandersnatch),
        "one key per curve"
    );

    assert_eq!(pubkey(0x03).expect_err("unknown curve"), "6a86");
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
