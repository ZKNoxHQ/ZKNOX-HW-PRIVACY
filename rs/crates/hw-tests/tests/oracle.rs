//! The host-side oracle, frozen against circomlib.
//!
//! `js/test/sign.test.js` compares the device against `circomlibjs`; this
//! suite compares the Rust reference against the same library, on 32 random
//! inputs drawn from the OS CSPRNG. The vectors in
//! `tests/fixtures/oracle-vectors.json` are produced by
//! `js/tools/gen-rust-oracle-vectors.mjs`, so a drift between the two
//! implementations shows up here rather than as a mysterious device failure.
//!
//! Runs without a device.

use serde_json::Value;

use zknox_hw_tests::fixtures::{TEST_ACCOUNT, TEST_MNEMONIC};
use zknox_hw_tests::hex::{buf2hex, hex2buf};
use zknox_hw_tests::oracle::{circomlib_ref, dkg_comm_pubkey, path_dkg_comm};
use zknox_hw_tests::slip0010::{derive_path, master_key_from_seed, mnemonic_to_seed};

fn vectors() -> Value {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/oracle-vectors.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("parse oracle vectors")
}

#[test]
fn eddsa_poseidon_matches_circomlib() {
    let v = vectors();
    let cases = v["signatures"].as_array().expect("signatures");
    assert!(cases.len() >= 32, "expected at least 32 vectors");
    for (i, c) in cases.iter().enumerate() {
        let priv_key = hex2buf(c["priv"].as_str().unwrap());
        let msg = hex2buf(c["msg"].as_str().unwrap());
        let got = circomlib_ref(&priv_key, &msg);
        let want = &c["expected"];
        assert_eq!(got.r8x, want["r8x"].as_str().unwrap(), "case {i}: R8.x");
        assert_eq!(got.r8y, want["r8y"].as_str().unwrap(), "case {i}: R8.y");
        assert_eq!(got.s, want["s"].as_str().unwrap(), "case {i}: S");
    }
}

#[test]
fn slip0010_derivation_matches_the_js_library() {
    let v = vectors();
    let cases = v["derivations"].as_array().expect("derivations");
    assert!(cases.len() >= 32, "expected at least 32 vectors");
    for (i, c) in cases.iter().enumerate() {
        let mnemonic = c["mnemonic"].as_str().unwrap();
        let path: Vec<u32> = c["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u32)
            .collect();

        let seed = mnemonic_to_seed(mnemonic);
        assert_eq!(
            buf2hex(&seed),
            c["seed"].as_str().unwrap(),
            "case {i}: seed"
        );

        let master = master_key_from_seed(&seed);
        assert_eq!(
            buf2hex(&master.chain_key),
            c["masterChainKey"].as_str().unwrap(),
            "case {i}: master chain key"
        );
        assert_eq!(
            buf2hex(&master.chain_code),
            c["masterChainCode"].as_str().unwrap(),
            "case {i}: master chain code"
        );

        let node = derive_path(&master, &path);
        assert_eq!(
            buf2hex(&node.chain_key),
            c["chainKey"].as_str().unwrap(),
            "case {i}: derived chain key for {path:?}"
        );
    }
}

/// The DKG transport key, pinned against the value `sim/test/selftest.sh` and
/// `js/` both carry for the yellow×12 seed.
///
/// `tests/dkg.rs` compares the device against this derivation and
/// `tests/ceremony.rs` compares every participant against it; freezing the
/// constant here is what keeps a silent agreement between two broken sides
/// from passing. The path is the one `zkn_keyderivation.c` reserves for
/// `KEY_TYPE_DKG_COMM`.
#[test]
fn the_dkg_transport_key_matches_the_frozen_yellow_vector() {
    assert_eq!(
        path_dkg_comm(0),
        [421, 1984, 0, 0, 0],
        "m/421'/1984'/0'/0'/0'"
    );
    assert_eq!(
        buf2hex(&dkg_comm_pubkey(TEST_MNEMONIC, TEST_ACCOUNT)),
        "9fc8d2779ee5bfb7662e02b5c8e23c71a4de3045621b15e031cbe481687de081"
    );
    // A different account is a different key, or the account would not be
    // part of the path.
    assert_ne!(
        dkg_comm_pubkey(TEST_MNEMONIC, 1),
        dkg_comm_pubkey(TEST_MNEMONIC, TEST_ACCOUNT)
    );
}
