//! 32 random ceremonies driven through the `DKGParticipant` contract by
//! `run_ceremony`, then signed with FROST: the manager path end to end, with
//! both key-agreement schemes.

use std::collections::BTreeMap;

use frost_babyjubjub::bytes::bigint_to_buffer;
use frost_babyjubjub::ceremony::run_ceremony;
use frost_babyjubjub::curve::Curve;
use frost_babyjubjub::dkg::TrustedDkg;
use frost_babyjubjub::eddsa::{EddsaPoseidon, Signature};
use frost_babyjubjub::frost::BabyFrost;
use frost_babyjubjub::key_agreement::{EngineEd25519KeyAgreement, X25519KeyAgreement};
use frost_babyjubjub::manager::SoftwareParticipant;
use frost_babyjubjub::participant::{
    DkgCommitInput, DkgFlowState, DkgParticipant, SoftwareCommitInput,
};
use frost_babyjubjub::rng::{OsRng, Rng};
use num_bigint::BigInt;

const RUNS: usize = 32;

fn rand_below(rng: &mut dyn Rng, n: u32) -> u32 {
    let mut b = [0u8; 4];
    rng.fill_bytes(&mut b);
    u32::from_le_bytes(b) % n
}

#[test]
fn ceremony_driver_produces_signing_shares() {
    let curve = Curve::new();
    let dkg = TrustedDkg::new();
    let frost = BabyFrost::new();
    let eddsa = EddsaPoseidon::new();
    let mut seed_rng = OsRng;

    for run in 0..RUNS {
        let n = 3 + rand_below(&mut seed_rng, 3) as usize;
        let t = 2 + rand_below(&mut seed_rng, (n - 1) as u32) as usize;
        // alternate the two schemes across runs; every participant of one
        // ceremony must use the same one
        let engine_scheme = run % 2 == 1;

        let com_keys: Vec<Vec<u8>> = (0..n).map(|_| seed_rng.random_bytes(32)).collect();
        let secrets: Vec<BigInt> = (0..n)
            .map(|_| curve.random_scalar(&mut seed_rng, true))
            .collect();
        let mut rngs: Vec<OsRng> = (0..n).map(|_| OsRng).collect();

        let mut participants: Vec<SoftwareParticipant> = Vec::new();
        for (i, rng) in rngs.iter_mut().enumerate() {
            let p = if engine_scheme {
                SoftwareParticipant::with_key_agreement(
                    &format!("p{}", i + 1),
                    &com_keys[i],
                    Box::new(EngineEd25519KeyAgreement),
                    rng,
                )
            } else {
                SoftwareParticipant::with_key_agreement(
                    &format!("p{}", i + 1),
                    &com_keys[i],
                    Box::new(X25519KeyAgreement),
                    rng,
                )
            };
            participants.push(p.expect("participant"));
        }
        assert!(participants
            .iter()
            .all(|p| p.get_state() == DkgFlowState::Init));

        let inputs: Vec<SoftwareCommitInput> = secrets
            .iter()
            .map(|s| SoftwareCommitInput {
                base: DkgCommitInput {
                    desired_shares: n as u32,
                    threshold: t as u32,
                },
                secret: s.clone(),
            })
            .collect();

        let trace = run_ceremony(&mut participants, &inputs).expect("ceremony");

        assert_eq!(trace.roster.len(), n, "run {run}");
        assert_eq!(trace.commitments.len(), n, "run {run}");
        assert_eq!(trace.bundles.len(), n, "run {run}");
        assert_eq!(trace.results.len(), n, "run {run}");

        // every participant agrees on the group key and the viewing key
        let pk_group = trace.results[0].pk_group.clone();
        let viewing = trace.results[0].viewing_private_key.clone();
        for r in &trace.results {
            assert_eq!(r.pk_group, pk_group, "run {run}");
            assert_eq!(r.viewing_private_key, viewing, "run {run}");
        }

        // the group key is the sum of the dealt constant terms
        let secret_sum = secrets
            .iter()
            .fold(BigInt::from(0u32), |acc, s| curve.mod_order(&(acc + s)));
        assert_eq!(curve.scalar_base_mult(&secret_sum), pk_group, "run {run}");

        // the dealt commitments are the ones the trace carries
        let all: Vec<_> = trace.commitments.values().cloned().collect();
        assert!(dkg.verify_all_commitments_subgroup(&all), "run {run}");
        assert_eq!(
            dkg.combine_group_pubkey_from_commitments(&all).unwrap(),
            pk_group,
            "run {run}"
        );

        // a threshold subset signs and the aggregate verifies under the group key
        let sk_shares: BTreeMap<u32, BigInt> = trace
            .results
            .iter()
            .map(|r| (r.id, r.sk_share.clone().expect("software share")))
            .collect();
        let signers: Vec<u32> = trace.results.iter().take(t).map(|r| r.id).collect();

        let msg = curve.random_scalar(&mut seed_rng, true);
        let mut nonces = BTreeMap::new();
        let mut list = Vec::new();
        for s in &signers {
            let b = frost
                .commit(&mut seed_rng, &sk_shares[s], &BigInt::from(*s))
                .unwrap();
            nonces.insert(*s, b.nonces);
            list.push(b.commitments);
        }
        let mut shares = Vec::new();
        for s in &signers {
            let id = BigInt::from(*s);
            let share = frost
                .sign(&id, &sk_shares[s], &pk_group, &nonces[s], &msg, &list)
                .unwrap();
            let ci = list.iter().find(|c| c.identifier == id).unwrap();
            assert!(
                frost
                    .verify_signature_share(&id, &sk_shares[s], ci, &share, &list, &pk_group, &msg)
                    .unwrap(),
                "run {run}"
            );
            shares.push(share);
        }
        let agg = frost.aggregate(&list, &msg, &pk_group, &shares).unwrap();
        assert!(
            eddsa.verify_poseidon(
                &bigint_to_buffer(&msg),
                &Signature {
                    r8: agg.r8,
                    s: agg.s
                },
                &pk_group
            ),
            "run {run}: ceremony shares do not produce a valid signature"
        );
    }
}

#[test]
fn contract_rejects_encrypting_before_the_commitment_set_is_frozen() {
    let curve = Curve::new();
    let mut rng_a = OsRng;
    let mut rng_b = OsRng;
    let mut seed = OsRng;
    let ka = X25519KeyAgreement;
    let sk_a = seed.random_bytes(32);
    let sk_b = seed.random_bytes(32);

    let mut a = SoftwareParticipant::with_key_agreement("a", &sk_a, Box::new(ka), &mut rng_a)
        .expect("a");
    let mut b = SoftwareParticipant::with_key_agreement("b", &sk_b, Box::new(ka), &mut rng_b)
        .expect("b");

    let mut roster = BTreeMap::new();
    roster.insert(1u32, a.get_announcement().pub_key);
    roster.insert(2u32, b.get_announcement().pub_key);
    a.assign_roster(&roster).expect("roster a");
    b.assign_roster(&roster).expect("roster b");
    assert_eq!(a.get_state(), DkgFlowState::RosterAssigned);

    let input = SoftwareCommitInput {
        base: DkgCommitInput {
            desired_shares: 2,
            threshold: 2,
        },
        secret: curve.random_scalar(&mut seed, true),
    };
    let ca = a.commitment_round(&input).expect("commit a");
    assert_eq!(a.get_state(), DkgFlowState::CommitmentsCreated);

    // encrypting before the set is complete must fail, and the message must
    // name the self-add trap the TypeScript warns about
    let err = a.get_encrypted_shares().unwrap_err().to_string();
    assert!(err.contains("commitmentRound() does not self-add"), "{err}");

    let cb = b.commitment_round(&input).expect("commit b");
    a.add_participant_commitments(1, &ca).unwrap();
    a.add_participant_commitments(2, &cb).unwrap();
    assert_eq!(a.get_state(), DkgFlowState::CommitmentsCollected);
    assert!(a.get_encrypted_shares().is_ok());

    // finalizing before every bundle arrived must fail too
    assert!(a.finalize().is_err());
}
