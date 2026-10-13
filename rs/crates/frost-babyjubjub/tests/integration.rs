//! 32 random end-to-end ceremonies: Feldman VSS dealing, encrypted share
//! distribution, finalization, FROST signing and EdDSA-Poseidon verification,
//! plus the matching negative cases. Self-contained: `cargo test --release`.

use std::collections::BTreeMap;

use frost_babyjubjub::bytes::bigint_to_buffer;
use frost_babyjubjub::curve::Curve;
use frost_babyjubjub::dkg::TrustedDkg;
use frost_babyjubjub::eddsa::{EddsaPoseidon, Signature};
use frost_babyjubjub::frost::BabyFrost;
use frost_babyjubjub::rng::{OsRng, Rng};
use num_bigint::BigInt;

const RUNS: usize = 32;

fn rand_below(rng: &mut dyn Rng, n: u32) -> u32 {
    let mut b = [0u8; 4];
    rng.fill_bytes(&mut b);
    u32::from_le_bytes(b) % n
}

#[test]
fn ceremony_vss_sign_verify() {
    let curve = Curve::new();
    let dkg = TrustedDkg::new();
    let frost = BabyFrost::new();
    let eddsa = EddsaPoseidon::new();
    let mut rng = OsRng;

    for run in 0..RUNS {
        let n = 3 + rand_below(&mut rng, 3) as i64;
        let t = 2 + rand_below(&mut rng, (n - 1) as u32) as i64;
        let ids: Vec<i64> = (1..=n).collect();

        // --- dealing: every participant deals a degree t-1 polynomial
        let mut coefficients: BTreeMap<i64, Vec<BigInt>> = BTreeMap::new();
        let mut all: Vec<Vec<_>> = Vec::new();
        for d in &ids {
            let coeffs: Vec<BigInt> = (0..t).map(|_| curve.random_scalar(&mut rng, true)).collect();
            all.push(dkg.vss_commit(&coeffs));
            coefficients.insert(*d, coeffs);
        }
        assert!(dkg.verify_all_commitments_subgroup(&all), "run {run}");

        // --- distribution: AES-GCM envelopes bound to the commitment digest
        let mut keys: BTreeMap<i64, BTreeMap<i64, Vec<u8>>> = BTreeMap::new();
        let mut bundles = BTreeMap::new();
        for d in &ids {
            let per: BTreeMap<i64, Vec<u8>> =
                ids.iter().map(|r| (*r, rng.random_bytes(32))).collect();
            let shares = dkg.compute_shares_for_ids(&coefficients[d], &ids).unwrap();
            let enc = dkg
                .encrypt_shares_aes_gcm_with_aad(&mut rng, &shares, &per, &all)
                .unwrap();
            keys.insert(*d, per);
            bundles.insert(*d, enc);
        }

        // an envelope opened with the wrong recipient id must fail (AAD binding)
        let wrong = dkg.decrypt_share_aes_gcm_with_aad(&bundles[&1][&1], &keys[&1][&1], 2, &all);
        assert!(wrong.is_err(), "run {run}: AAD is not bound to the recipient");

        // --- finalization
        let mut sk_shares = BTreeMap::new();
        let mut div8 = BTreeMap::new();
        let mut viewing: Option<Vec<u8>> = None;
        for r in &ids {
            let mut by_dealer = Vec::new();
            for d in &ids {
                let s = dkg
                    .decrypt_share_aes_gcm_with_aad(&bundles[d][r], &keys[d][r], *r, &all)
                    .unwrap();
                assert_eq!(
                    s,
                    dkg.polynomial_evaluate(&BigInt::from(*r), &coefficients[d]),
                    "run {run}"
                );
                assert!(
                    dkg.verify_feldman_share(*r, &s, &all[(*d - 1) as usize]),
                    "run {run}"
                );
                assert!(
                    !dkg.verify_feldman_share(
                        *r,
                        &curve.mod_order(&(&s + 1u32)),
                        &all[(*d - 1) as usize]
                    ),
                    "run {run}: tampered share accepted"
                );
                by_dealer.push((*d, s));
            }
            let f = dkg.finalize_participant(*r, &by_dealer, &all).unwrap();
            assert_eq!(
                f.share.sk_share,
                curve.mod_order(&(BigInt::from(8u32) * &f.share.sk_share_div8)),
                "run {run}"
            );
            // the viewing key is a function of the commitments only: same for all
            match &viewing {
                None => viewing = Some(f.viewing_private_key.clone()),
                Some(v) => assert_eq!(v, &f.viewing_private_key, "run {run}"),
            }
            sk_shares.insert(*r, f.share.sk_share);
            div8.insert(*r, f.share.sk_share_div8);
        }

        let pk_group = dkg.combine_group_pubkey_from_commitments(&all).unwrap();
        let secret_sum = ids.iter().fold(BigInt::from(0u32), |acc, d| {
            curve.mod_order(&(acc + &coefficients[d][0]))
        });
        assert_eq!(curve.scalar_base_mult(&secret_sum), pk_group, "run {run}");

        // --- a random threshold subset signs
        let mut pool = ids.clone();
        let mut signers = Vec::new();
        for _ in 0..t {
            signers.push(pool.remove(rand_below(&mut rng, pool.len() as u32) as usize));
        }
        signers.sort_unstable();

        // Lagrange reconstruction over that subset returns the group secret
        let subset: Vec<(i64, BigInt)> = signers.iter().map(|s| (*s, div8[s].clone())).collect();
        assert_eq!(
            dkg.reconstruct_constant_from_shares(&subset).unwrap(),
            secret_sum,
            "run {run}"
        );

        let msg = curve.random_scalar(&mut rng, true);
        let mut nonces = BTreeMap::new();
        let mut list = Vec::new();
        for s in &signers {
            let b = frost
                .commit(&mut rng, &sk_shares[s], &BigInt::from(*s))
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
            assert!(
                !frost
                    .verify_signature_share(
                        &id,
                        &sk_shares[s],
                        ci,
                        &curve.mod_order(&(&share + 1u32)),
                        &list,
                        &pk_group,
                        &msg
                    )
                    .unwrap(),
                "run {run}: tampered signature share accepted"
            );
            shares.push(share);
        }

        // --- aggregate and verify as a plain EdDSA-Poseidon signature
        let agg = frost.aggregate(&list, &msg, &pk_group, &shares).unwrap();
        let sig = Signature {
            r8: agg.r8.clone(),
            s: agg.s.clone(),
        };
        assert!(
            eddsa.verify_poseidon(&bigint_to_buffer(&msg), &sig, &pk_group),
            "run {run}: aggregate does not verify"
        );
        assert!(
            !eddsa.verify_poseidon(
                &bigint_to_buffer(&msg),
                &Signature {
                    r8: sig.r8.clone(),
                    s: curve.mod_order(&(&sig.s + 1u32))
                },
                &pk_group
            ),
            "run {run}: tampered signature accepted"
        );
        // the same signature must not verify under a different message
        let other = curve.mod_order(&(&msg + 1u32));
        assert!(
            !eddsa.verify_poseidon(&bigint_to_buffer(&other), &sig, &pk_group),
            "run {run}: signature accepted for another message"
        );

        // a subset smaller than the threshold cannot reach the group secret
        if (signers.len() as i64) > 1 {
            let short: Vec<(i64, BigInt)> = subset[..subset.len() - 1].to_vec();
            assert_ne!(
                dkg.reconstruct_constant_from_shares(&short).unwrap(),
                secret_sum,
                "run {run}: t-1 shares reconstructed the secret"
            );
        }
    }
}
