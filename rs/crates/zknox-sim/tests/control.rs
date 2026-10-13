//! What the line protocol cannot drive: the seed, the review screen and the
//! randomness, changed between exchanges inside one session.
//!
//! `SIM_SEED`, `SIM_REJECT` and `SIM_RNG_SEED` are read once, at startup, so
//! over the pipe each value costs a process. `hw-tests` pays that price where
//! it has to: `blind_sign_is_refused_when_the_user_rejects` spawns a second
//! simulator for the sole purpose of answering no once. Linked in, they are
//! setters, and these tests are what that makes affordable.

use frost_babyjubjub::bytes::bigint_to_bytes;
use frost_babyjubjub::eddsa::EddsaPoseidon;
use frost_babyjubjub::rng::{OsRng, Rng};

use zknox_hw_tests::apdu::*;
use zknox_hw_tests::hex::buf2hex;
use zknox_hw_tests::oracle::{derived_spending_key_from_seed, dkg_comm_pubkey_from_seed};
use zknox_sim::Sim;

const ACCOUNT: u32 = 0;

/// Thirty-two seeds from the OS CSPRNG, each checked on two independent
/// derivation branches: the BabyJubJub signing key down
/// m/44'/1984'/account'/0'/0', and the Ed25519 DKG transport key down
/// m/421'/1984'/account'/0'/0'.
///
/// The host recomputes both from the seed, so this is the derivation checked
/// against an implementation that shares no code with it — not the device
/// checked against itself. Over the pipe it would be 32 process spawns and
/// 32 `SIM_SEED` strings; here it is one loop.
#[test]
fn thirty_two_seeds_derive_thirty_two_matching_key_sets() {
    let mut sim = Sim::lock();
    let eddsa = EddsaPoseidon::new();
    let mut rng = OsRng;

    let mut seen_hk: Vec<String> = Vec::new();
    for case in 0..32 {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        sim.set_seed(&seed);

        // The BabyJubJub signing key: x || y, big-endian, as the handler
        // returns it. P1=0 is the silent variant, so this half needs a debug
        // build; P1=1 goes through the review screen the simulator approves.
        let p1 = if zknox_sim::has_debug_ins() {
            PUBKEY_P1_SILENT
        } else {
            PUBKEY_P1_CONFIRM
        };
        let got = sim
            .exchange(
                &build_apdu(INS_SIGNING_PUBKEY, p1, 0, &account_be(ACCOUNT)),
                "SIGNING_PUBKEY",
            )
            .unwrap_or_else(|e| panic!("case {case} seed {}: {e}", buf2hex(&seed)));
        assert_eq!(got.len(), 64, "x(32) || y(32)");

        let sk = derived_spending_key_from_seed(&seed, ACCOUNT);
        let point = eddsa.prv2pub(&sk);
        let mut want = bigint_to_bytes(&point.x, 32).expect("x");
        want.extend_from_slice(&bigint_to_bytes(&point.y, 32).expect("y"));
        assert_eq!(
            buf2hex(&got),
            buf2hex(&want),
            "case {case} seed {}: signing key does not match the host derivation",
            buf2hex(&seed)
        );

        if !zknox_sim::has_frost() {
            continue;
        }
        let hk = sim
            .exchange(
                &build_apdu(INS_DKG_GET_COMM_PUBKEY, 0, 0, &account_be(ACCOUNT)),
                "DKG_GET_COMM_PUBKEY",
            )
            .expect("GET_COMM_PUBKEY");
        assert_eq!(
            buf2hex(&hk),
            buf2hex(&dkg_comm_pubkey_from_seed(&seed, ACCOUNT)),
            "case {case} seed {}: transport key does not match the host derivation",
            buf2hex(&seed)
        );
        // Two derivation branches of one seed must not collide, and two seeds
        // must not give one key.
        assert_ne!(buf2hex(&hk), buf2hex(&got[..32]), "case {case}");
        let hk = buf2hex(&hk);
        assert!(
            !seen_hk.contains(&hk),
            "case {case}: repeated transport key"
        );
        seen_hk.push(hk);
    }
}

/// Going back to the built-in seed must restore the frozen vectors, which is
/// what lets a test change the seed without leaking into the next one.
#[test]
fn the_default_seed_comes_back() {
    if !zknox_sim::has_frost() {
        eprintln!("SKIP: built FROST=0");
        return;
    }
    let mut sim = Sim::lock();
    let apdu = build_apdu(INS_DKG_GET_COMM_PUBKEY, 0, 0, &account_be(ACCOUNT));
    const YELLOW: &str = "9fc8d2779ee5bfb7662e02b5c8e23c71a4de3045621b15e031cbe481687de081";

    assert_eq!(buf2hex(&sim.exchange(&apdu, "hk").expect("hk")), YELLOW);
    sim.set_seed(&[0x11; 64]);
    assert_ne!(buf2hex(&sim.exchange(&apdu, "hk").expect("hk")), YELLOW);
    sim.set_seed_default();
    assert_eq!(buf2hex(&sim.exchange(&apdu, "hk").expect("hk")), YELLOW);
}

/// Approve, refuse, approve again, all on one device.
///
/// The refusal path is the one that matters: `handler_sign.c` defers the
/// signature until approval, so a refusal must produce `6985` and no
/// signature bytes at all. `hw-tests` can only check this by spawning a
/// simulator that answers no for its whole life.
#[test]
fn the_review_screen_can_be_answered_both_ways_in_one_session() {
    let mut sim = Sim::lock();
    let msg = [0x8cu8; 32];
    let mut data = account_be(ACCOUNT).to_vec();
    data.extend_from_slice(&msg);
    let apdu = build_apdu(INS_BLIND_SIGN, CURVE_BABYJUBJUB_LEGACY, 0, &data);

    sim.set_ui(true);
    let approved = sim.exchange(&apdu, "BLIND_SIGN/approve").expect("approved");
    assert_eq!(approved.len(), 1 + 96 + 32, "len || sig(96) || echo(32)");
    assert_eq!(approved[0], 96, "the length prefix of the signature");

    sim.set_ui(false);
    let err = sim
        .exchange(&apdu, "BLIND_SIGN/reject")
        .expect_err("a refusal must not return a signature");
    assert_eq!(err.sw, "6985", "SW_DENY");

    sim.set_ui(true);
    let again = sim.exchange(&apdu, "BLIND_SIGN/approve").expect("approved");
    assert_eq!(
        buf2hex(&again),
        buf2hex(&approved),
        "the same message under the same key signs the same way"
    );
}

/// The dealt polynomial is deterministic in (seed, epoch, id, n, t, name), and
/// the epoch is the only randomness `handler_dkg.c` draws. Pinning the RNG
/// must therefore make `DEAL` reproducible, and that is worth knowing: it is
/// the property a recovery story rests on.
#[test]
fn a_seeded_rng_makes_the_dealt_polynomial_reproducible() {
    if !zknox_sim::has_frost() {
        eprintln!("SKIP: built FROST=0");
        return;
    }
    let mut sim = Sim::lock();
    let deal = build_apdu(
        INS_DKG_DEAL,
        0,
        0,
        &build_dkg_deal_payload(ACCOUNT, 1, 2, 3, "rs-rng"),
    );

    let mut deal_with = |rng_seed: Option<u64>| -> Vec<u8> {
        sim.reset();
        match rng_seed {
            Some(s) => sim.set_rng_seed(s),
            None => sim.set_rng_os(),
        }
        sim.exchange(&deal, "DEAL").expect("DEAL")
    };

    let a = deal_with(Some(0xc0ffee));
    let b = deal_with(Some(0xc0ffee));
    assert_eq!(
        buf2hex(&a),
        buf2hex(&b),
        "one RNG seed must give one epoch and one commitment vector"
    );

    let c = deal_with(Some(0xc0ffef));
    assert_ne!(
        buf2hex(&a[..16]),
        buf2hex(&c[..16]),
        "another RNG seed must give another epoch"
    );
    assert_ne!(
        buf2hex(&a[16..]),
        buf2hex(&c[16..]),
        "and therefore another polynomial"
    );

    let d = deal_with(None);
    let e = deal_with(None);
    assert_ne!(
        buf2hex(&d[..16]),
        buf2hex(&e[..16]),
        "on the OS source two deals must not share an epoch"
    );
}
