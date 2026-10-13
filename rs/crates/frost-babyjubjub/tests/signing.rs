//! 32 random two-party signing rounds through `FrostSigningManager`: two
//! managers each holding part of the signing set, exchanging round-1
//! commitments and partials, both finalizing to the same signature. Plus the
//! session rules the TypeScript enforces.

use frost_babyjubjub::bytes::bigint_to_buffer;
use frost_babyjubjub::curve::Curve;
use frost_babyjubjub::dkg::TrustedDkg;
use frost_babyjubjub::eddsa::{EddsaPoseidon, Signature};
use frost_babyjubjub::rng::{OsRng, Rng};
use frost_babyjubjub::signing::{FrostSigningManager, SignerShare};
use num_bigint::BigInt;

const RUNS: usize = 32;

fn rand_below(rng: &mut dyn Rng, n: u32) -> u32 {
    let mut b = [0u8; 4];
    rng.fill_bytes(&mut b);
    u32::from_le_bytes(b) % n
}

#[test]
fn two_managers_sign_together() {
    let curve = Curve::new();
    let dkg = TrustedDkg::new();
    let eddsa = EddsaPoseidon::new();
    let mut rng = OsRng;

    for run in 0..RUNS {
        let n = 3 + rand_below(&mut rng, 3);
        let t = 2 + rand_below(&mut rng, n - 1);
        let secret = curve.random_scalar(&mut rng, true);
        let keygen = dkg
            .trusted_dealer_keygen(&mut rng, &secret, n, t)
            .expect("keygen");
        let pk = keygen.vss_commitment[0].clone();
        let shares: Vec<SignerShare> = keygen
            .participant_private_keys
            .iter()
            .take(t as usize)
            .map(|(x, y)| SignerShare {
                id: *x,
                sk_share: curve.mod_order(&(BigInt::from(8u32) * y)),
            })
            .collect();

        // split the signing set across two managers
        let split = 1 + rand_below(&mut rng, t - 1) as usize;
        let mut a = FrostSigningManager::new(pk.clone(), t as usize);
        let mut b = FrostSigningManager::new(pk.clone(), t as usize);
        for s in &shares[..split] {
            a.add_signer(s.clone()).expect("add a");
        }
        for s in &shares[split..] {
            b.add_signer(s.clone()).expect("add b");
        }
        assert!(a.add_signer(shares[0].clone()).is_err(), "run {run}");

        a.round1(&mut rng).expect("round1 a");
        b.round1(&mut rng).expect("round1 b");
        assert!(a.round1(&mut rng).is_err(), "run {run}: committed twice");

        for c in b.export_round1().expect("export b") {
            a.add_remote_signer(&c).expect("remote into a");
        }
        for c in a.export_round1().expect("export a") {
            b.add_remote_signer(&c).expect("remote into b");
        }
        assert_eq!(
            a.session_commitment_list("default").unwrap(),
            b.session_commitment_list("default").unwrap(),
            "run {run}: the two managers built different commitment lists"
        );

        let msg = curve.random_scalar(&mut rng, true);
        let pa = a.sign(&msg).expect("sign a");
        let pb = b.sign(&msg).expect("sign b");

        assert!(!a.ready_to_finalize().unwrap(), "run {run}");
        a.receive_partials(&pa).unwrap();
        a.receive_partials(&pb).unwrap();
        b.receive_partials(&pb).unwrap();
        b.receive_partials(&pa).unwrap();
        assert!(a.ready_to_finalize().unwrap(), "run {run}");
        assert!(a.get_missing_partials().unwrap().is_empty(), "run {run}");

        let sa = a.finalize(&msg).expect("finalize a");
        let sb = b.finalize(&msg).expect("finalize b");
        assert_eq!(sa.r8, sb.r8, "run {run}");
        assert_eq!(sa.s, sb.s, "run {run}");
        assert!(
            eddsa.verify_poseidon(
                &bigint_to_buffer(&msg),
                &Signature {
                    r8: sa.r8.clone(),
                    s: sa.s.clone()
                },
                &pk
            ),
            "run {run}: aggregate does not verify"
        );

        // finalizing another message on the same session is refused
        assert!(
            a.finalize(&curve.mod_order(&(&msg + 1u32))).is_err(),
            "run {run}: finalized a message the session did not sign"
        );
    }
}

#[test]
fn sessions_are_isolated_and_rules_hold() {
    let curve = Curve::new();
    let dkg = TrustedDkg::new();
    let eddsa = EddsaPoseidon::new();
    let mut rng = OsRng;

    let secret = curve.random_scalar(&mut rng, true);
    let keygen = dkg
        .trusted_dealer_keygen(&mut rng, &secret, 3, 2)
        .expect("keygen");
    let pk = keygen.vss_commitment[0].clone();
    let mut m = FrostSigningManager::new(pk.clone(), 2);
    for (x, y) in keygen.participant_private_keys.iter().take(2) {
        m.add_signer(SignerShare {
            id: *x,
            sk_share: curve.mod_order(&(BigInt::from(8u32) * y)),
        })
        .unwrap();
    }

    // an identifier of 0 would shift every Lagrange coefficient
    let bogus = frost_babyjubjub::frost::Commitment {
        identifier: BigInt::from(0u32),
        hiding_nonce_commitment: curve.scalar_base_mult(&BigInt::from(3u32)),
        binding_nonce_commitment: curve.scalar_base_mult(&BigInt::from(4u32)),
    };
    m.start_session("s1").unwrap();
    assert!(m.session_add_remote_signer("s1", &bogus).is_err());
    assert!(m.start_session("s1").is_err());
    assert!(m.session("nope").is_err());

    // two sessions sign two different messages without interfering
    m.start_session("s2").unwrap();
    let m1 = curve.random_scalar(&mut rng, true);
    let m2 = curve.random_scalar(&mut rng, true);
    m.session_round1(&mut rng, "s1").unwrap();
    m.session_round1(&mut rng, "s2").unwrap();
    let p1 = m.session_sign("s1", &m1).unwrap();
    let p2 = m.session_sign("s2", &m2).unwrap();
    m.session_receive_partials("s1", &p1).unwrap();
    m.session_receive_partials("s2", &p2).unwrap();
    let s1 = m.session_finalize("s1", &m1).unwrap();
    let s2 = m.session_finalize("s2", &m2).unwrap();
    assert_ne!(s1.r8, s2.r8);
    assert!(eddsa.verify_poseidon(
        &bigint_to_buffer(&m1),
        &Signature { r8: s1.r8, s: s1.s },
        &pk
    ));
    assert!(eddsa.verify_poseidon(
        &bigint_to_buffer(&m2),
        &Signature { r8: s2.r8, s: s2.s },
        &pk
    ));

    // a committed session never lands in a safe snapshot
    let safe = m.to_snapshot();
    assert!(safe.sessions.is_empty());
    assert_eq!(
        safe.omitted_sessions.as_ref().map(|v| v.len()),
        Some(2),
        "committed sessions must be listed as omitted"
    );
    assert!(FrostSigningManager::from_mid_round_snapshot(&safe).is_err());
    assert!(FrostSigningManager::from_snapshot(&m.to_mid_round_snapshot()).is_err());

    // a missing partial blocks finalization
    m.session_reset("s1").unwrap();
    m.session_round1(&mut rng, "s1").unwrap();
    let _ = m.session_sign("s1", &m1).unwrap();
    assert!(m.session_finalize("s1", &m1).is_err());
}
