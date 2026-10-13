//! Full ceremonies across several devices: DKG, FROST signature, verification.
//!
//! This is what the JavaScript suite cannot do. `js/test/frost-hw.test.js`
//! says it plainly: a valid FROST signature needs t co-signers' commitments,
//! so the happy path "belongs to a 2-device setup" and only the guards are
//! tested. One Speculos instance is one device, and nobody runs three.
//!
//! The simulator is a process, so n devices cost n processes. The host here is
//! the untrusted coordinator: it carries commitments and encrypted shares
//! between participants and never sees a secret.
//!
//! What is verified at the end is not the device against itself: the aggregate
//! is checked with `frost-babyjubjub`, the Rust port of
//! `@railgun-reloaded/curves`, under the circomlib EdDSA-Poseidon equation
//! `S·B8 == R8 + 8·hm·A`. So a pass means the firmware's FROST and the
//! TypeScript library agree on the binding factors, the group commitment, the
//! challenge and the interpolation — not merely that the firmware is
//! self-consistent.
//!
//! Two ceremonies run the same code path:
//!
//! - [`a_ceremony_on_the_canonical_seed_signs_and_verifies`] — every
//!   participant on mnemonic "yellow"×12, 2-of-3, which is also the shape
//!   `run-rs-device-tests.sh` drives with a physical Ledger standing in for
//!   one participant.
//! - [`a_ceremony_on_random_per_participant_seeds_signs_and_verifies`] — a
//!   fresh 64-byte seed per participant from the OS CSPRNG, with n, t, the
//!   quorum, the ceremony name and the message drawn too.
//!
//! Having both says what the seeds are and are not for. Verification needs
//! the group public key and nothing else, so sharing a seed is neither
//! required nor forbidden: what the ceremony does require is that each
//! announced transport key be the one that participant's seed derives, and
//! both tests recompute all of them host-side (SLIP-0010 down
//! m/421'/1984'/account'/0'/0', then the Ed25519 public key) instead of
//! trusting what came back over the wire.

use std::collections::BTreeSet;

use frost_babyjubjub::bytes::{bigint_to_bytes, le_buffer_to_bigint};
use frost_babyjubjub::curve::{Curve, Point};
use frost_babyjubjub::eddsa::{EddsaPoseidon, Signature};
use frost_babyjubjub::frost::{BabyFrost, Commitment};
use frost_babyjubjub::rng::{OsRng, Rng};
use num_bigint::BigInt;

use zknox_hw_tests::apdu::{dkg_state, *};
use zknox_hw_tests::context::default_seed;
use zknox_hw_tests::fixtures::TEST_MNEMONIC;
use zknox_hw_tests::hex::buf2hex;
use zknox_hw_tests::ledger::{
    default_sim_binary, exchange, hw_device_requested, open_hid, spawn_sim_with_env, try_exchange,
    Transport,
};
use zknox_hw_tests::oracle::dkg_comm_pubkey_from_seed;
use zknox_hw_tests::slip0010::mnemonic_to_seed;

const ACCOUNT: u32 = 0;
/// `DKG_MAX_N` in `src/handler/handler_dkg.c`.
const DKG_MAX_N: usize = 5;
/// `DKG_MAX_T`, which `handler_frost_sign.c` mirrors as `FS_MAX_SIGNERS`.
const DKG_MAX_T: usize = 3;

// ── parameters ──────────────────────────────────────────────────────────

/// Which BIP39 seed a participant runs on.
#[derive(Clone)]
enum Seeding {
    /// The simulator's own default, mnemonic "yellow"×12 — and the seed a
    /// physical Ledger under `HW_DEVICE` is expected to carry.
    Default,
    /// A 64-byte BIP39 seed, handed to the simulator through `SIM_SEED`.
    Explicit([u8; 64]),
}

impl Seeding {
    /// The 64 seed bytes themselves.
    fn material(&self) -> [u8; 64] {
        match self {
            Seeding::Default => mnemonic_to_seed(TEST_MNEMONIC),
            Seeding::Explicit(seed) => *seed,
        }
    }

    /// The transport key this seed derives, recomputed host-side.
    fn expected_hk(&self, account: u32) -> [u8; 32] {
        dkg_comm_pubkey_from_seed(&self.material(), account)
    }

    /// What goes in the child's `SIM_SEED`.
    ///
    /// Always set, even for [`Seeding::Default`]: a child process inherits the
    /// suite's own environment, so an ambient `SIM_SEED` would otherwise
    /// reseed the participants this ceremony means to leave on yellow×12 and
    /// the transport-key check would fail for a reason nobody could see. The
    /// empty string is not the 128 hex characters `shim_crypto.c` requires, so
    /// it falls back to the built-in seed.
    fn sim_seed(&self) -> String {
        match self {
            Seeding::Default => String::new(),
            Seeding::Explicit(seed) => buf2hex(seed),
        }
    }
}

/// One ceremony's parameters.
struct Setup {
    /// Shown in skip and failure messages.
    label: String,
    /// Threshold.
    t: usize,
    account: u32,
    /// Ceremony name, which the dealer polynomial is bound to.
    name: String,
    /// One entry per participant; ids are `1..=seeds.len()`.
    seeds: Vec<Seeding>,
    /// Indices of the `t` signers, ascending. The firmware wants exactly `t`
    /// records, strictly increasing by id.
    quorum: Vec<usize>,
    /// The scalar to sign.
    message: BigInt,
    /// Whether a physical Ledger may stand in for `HW_PARTICIPANT_ID`.
    allow_device: bool,
}

impl Setup {
    fn n(&self) -> usize {
        self.seeds.len()
    }
}

// ── participants ────────────────────────────────────────────────────────

/// One participant, simulated or physical.
struct Device {
    id: u8,
    transport: Transport,
    /// True when this one is the physical Ledger rather than a simulator.
    physical: bool,
    /// Transport public key as announced by `DKG_GET_COMM_PUBKEY`.
    hk: Vec<u8>,
    /// The commitment vector it dealt, `t` points of 64 big-endian bytes.
    commitments: Vec<u8>,
}

impl Device {
    fn send(&mut self, apdu: &[u8], label: &str) -> Vec<u8> {
        exchange(&mut self.transport, apdu, label)
            .unwrap_or_else(|e| panic!("device {}: {e}", self.id))
    }

    /// `C_{d,k}` as a curve point.
    fn commitment(&self, k: usize) -> Point {
        point_be(&self.commitments[k * 64..(k + 1) * 64])
    }
}

fn point_be(b: &[u8]) -> Point {
    Point::new(
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &b[..32]),
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &b[32..64]),
    )
}

/// Which participant the physical Ledger plays, when `HW_DEVICE` is set.
/// `HW_PARTICIPANT_ID` moves it; the others stay simulated.
fn hw_participant_id() -> u8 {
    std::env::var("HW_PARTICIPANT_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
}

/// Starts participant `id`, or `None` when the simulator has not been built.
fn boot(setup: &Setup, index: usize) -> Option<Device> {
    let id = index as u8 + 1;
    let seeding = &setup.seeds[index];
    let device_plays_this_one =
        setup.allow_device && hw_device_requested() && id == hw_participant_id();

    let transport = if device_plays_this_one {
        assert!(
            matches!(seeding, Seeding::Default),
            "participant {id} is the physical Ledger, whose seed cannot be chosen: \
             only a ceremony on the canonical seed can host one"
        );
        // HW_DEVICE names a backend, so a device that does not answer is a
        // failure, not a skip — same rule as the single-device suites.
        open_hid().unwrap_or_else(|e| panic!("participant {id} is the Ledger, and: {e}"))
    } else {
        let binary = default_sim_binary();
        if !binary.exists() {
            return None;
        }
        let seed = seeding.sim_seed();
        spawn_sim_with_env(&binary, &[("SIM_SEED", seed.as_str())])
            .unwrap_or_else(|e| panic!("spawn simulator {id}: {e}"))
    };
    Some(Device {
        id,
        transport,
        physical: device_plays_this_one,
        hk: Vec::new(),
        commitments: Vec::new(),
    })
}

// ── the ceremony ────────────────────────────────────────────────────────

/// Runs one ceremony end to end. Returns false when it was skipped for want
/// of a simulator.
fn run(setup: &Setup) -> bool {
    let n = setup.n();
    let t = setup.t;
    assert!(
        (2..=DKG_MAX_T).contains(&t) && t <= n && n <= DKG_MAX_N,
        "{n}-of-{t} is out of the firmware's range"
    );
    assert_eq!(
        setup.quorum.len(),
        t,
        "the firmware wants exactly t signers"
    );

    let curve = Curve::new();
    let frost = BabyFrost::new();
    let eddsa = EddsaPoseidon::new();

    let mut devices: Vec<Device> = Vec::new();
    for index in 0..n {
        match boot(setup, index) {
            Some(d) => devices.push(d),
            None => {
                eprintln!(
                    "SKIP {}: no simulator at {} (cd sim && make MODE=debug)",
                    setup.label,
                    default_sim_binary().display()
                );
                return false;
            }
        }
    }

    // ── round 0: transport keys and the dealt commitments ───────────────
    for (index, d) in devices.iter_mut().enumerate() {
        let hk = d.send(
            &build_apdu(INS_DKG_GET_COMM_PUBKEY, 0, 0, &account_be(setup.account)),
            "GET_COMM_PUBKEY",
        );
        assert_eq!(hk.len(), 32);
        // The announced key is checked, not trusted: it must be the one this
        // participant's seed derives down m/421'/1984'/account'/0'/0'. A host
        // that substitutes its own key reads every share addressed to the
        // victim, which is the attack `handler_dkg.c` guards against from the
        // device's side.
        //
        // The one participant whose seed the suite cannot set is a physical
        // Ledger, so `SEED=other` waives the check for that one — the same
        // escape hatch the seed-bound oracles in `dkg.rs` and `sign.rs` have.
        if d.physical && !default_seed() {
            eprintln!(
                "participant {}: SEED=other, taking the device's transport key as announced",
                d.id
            );
        } else {
            assert_eq!(
                buf2hex(&hk),
                buf2hex(&setup.seeds[index].expected_hk(setup.account)),
                "participant {}: the transport key is not the one its seed derives",
                d.id
            );
        }
        d.hk = hk;

        d.send(&build_apdu0(INS_DKG_ABORT), "ABORT");
        let id = d.id;
        let out = d.send(
            &build_apdu(
                INS_DKG_DEAL,
                0,
                0,
                &build_dkg_deal_payload(setup.account, id, t as u8, n as u8, &setup.name),
            ),
            "DEAL",
        );
        assert_eq!(out.len(), 16 + t * 64, "epoch(16) || C(t*64)");
        d.commitments = out[16..].to_vec();
    }

    // Distinct seeds must give distinct transport keys. The canonical setup
    // deliberately shares one seed across participants, and the ceremony
    // still completes: the DKG binds the dealer polynomial to the
    // participant id, not to the seed alone, and verification only ever
    // needs the group public key.
    let distinct_seeds = setup
        .seeds
        .iter()
        .map(|s| s.material().to_vec())
        .collect::<BTreeSet<_>>()
        .len()
        == n;
    if distinct_seeds {
        for i in 0..n {
            for j in i + 1..n {
                assert_ne!(
                    devices[i].hk, devices[j].hk,
                    "distinct seeds must give distinct transport keys"
                );
            }
        }
    }
    // Whatever the seeds, the dealers must deal different polynomials, or the
    // sharing would be one dealer counted n times.
    for i in 0..n {
        for j in i + 1..n {
            assert_ne!(
                devices[i].commitments, devices[j].commitments,
                "participants {} and {} dealt the same polynomial",
                devices[i].id, devices[j].id
            );
        }
    }

    // ── round 1: every participant absorbs every dealer's commitments ───
    // The device enforces a canonical order: records strictly increasing by
    // C0, which is what makes the digest the same on all of them.
    let mut records: Vec<(Vec<u8>, Vec<u8>)> = devices
        .iter()
        .map(|d| {
            let mut rec = vec![d.id];
            rec.extend_from_slice(&d.hk);
            rec.extend_from_slice(&d.commitments);
            (d.commitments[..64].to_vec(), rec)
        })
        .collect();
    records.sort_by(|a, b| a.0.cmp(&b.0));

    let mut digest: Option<Vec<u8>> = None;
    for d in devices.iter_mut() {
        for (k, (_, rec)) in records.iter().enumerate() {
            let p1 = if k == 0 {
                DKG_P1_FIRST
            } else if k == records.len() - 1 {
                DKG_P1_LAST
            } else {
                DKG_P1_NEXT
            };
            let out = d.send(&build_apdu(INS_DKG_SET_COMMITS, p1, 0, rec), "SET_COMMITS");
            if p1 == DKG_P1_LAST {
                assert_eq!(out.len(), 32, "SET_COMMITS LAST returns the digest");
                match &digest {
                    None => digest = Some(out),
                    Some(first) => assert_eq!(
                        first, &out,
                        "every participant must land on the same digest"
                    ),
                }
            }
        }
        let s = d.send(&build_apdu0(INS_DKG_STATUS), "STATUS");
        assert_eq!(s[0], dkg_state::COMMITTED, "device {} not COMMITTED", d.id);
    }

    // ── round 2: every dealer publishes, then everybody consumes ────────
    // Both phases are separate on purpose: GET_SHARE needs COMMITTED, and a
    // participant that has already taken every share has moved on to
    // COLLECTED. Interleaving them deadlocks the state machine, which is the
    // kind of thing only a multi-device run finds.
    let mut envelopes: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    for dealer in 0..n {
        for recipient in 0..n {
            if dealer == recipient {
                continue;
            }
            let rid = devices[recipient].id;
            let envelope =
                devices[dealer].send(&build_apdu(INS_DKG_GET_SHARE, 0, 0, &[rid]), "GET_SHARE");
            assert_eq!(envelope.len(), 12 + 32 + 16, "nonce || ct || tag");
            envelopes.push((dealer, recipient, envelope));
        }
    }
    for (dealer, recipient, envelope) in envelopes {
        let did = devices[dealer].id;
        let dealer_commitments = devices[dealer].commitments.clone();
        let mut payload = vec![did];
        payload.extend_from_slice(&dealer_commitments);
        payload.extend_from_slice(&envelope);
        devices[recipient].send(&build_apdu(INS_DKG_PUT_SHARE, 0, 0, &payload), "PUT_SHARE");
    }

    // ── round 3: finalize, and the group key the host can predict ───────
    let expected_a = {
        let mut acc = devices[0].commitment(0);
        for d in devices.iter().skip(1) {
            acc = curve.add_point(&acc, &d.commitment(0));
        }
        acc
    };
    let mut group_key: Option<Point> = None;
    for d in devices.iter_mut() {
        let s = d.send(&build_apdu0(INS_DKG_STATUS), "STATUS");
        assert_eq!(s[0], dkg_state::COLLECTED, "device {} not COLLECTED", d.id);
        let a = d.send(&build_apdu0(INS_DKG_FINALIZE), "FINALIZE");
        assert_eq!(a.len(), 64, "FINALIZE returns A");
        let a = point_be(&a);
        assert_eq!(a, expected_a, "device {} disagrees on the group key", d.id);
        match &group_key {
            None => group_key = Some(a),
            Some(first) => assert_eq!(first, &a),
        }
        let s = d.send(&build_apdu0(INS_DKG_STATUS), "STATUS");
        assert_eq!(s[0], dkg_state::PROVISIONED);
    }
    let group_key = group_key.expect("A");

    // Public share of participant i, rebuilt from the Feldman commitments:
    // P_i = 8 · Σ_d Σ_k i^k · C_{d,k}, the 8 being the factor finalize folds
    // into skShare. The device's debug instruction hands out its own share, so
    // the two can be compared.
    let all_commitments: Vec<Vec<Point>> = devices
        .iter()
        .map(|d| (0..t).map(|k| d.commitment(k)).collect())
        .collect();
    let public_share = |i: u8| -> Point {
        let mut acc = curve.identity();
        for dealer in all_commitments.iter() {
            let mut pow = BigInt::from(1u32);
            for c in dealer.iter() {
                acc = curve.add_point(&acc, &curve.scalar_mult(c, &pow));
                pow = curve.mod_order(&(pow * BigInt::from(i)));
            }
        }
        curve.scalar_mult(&acc, &BigInt::from(8u32))
    };
    for d in devices.iter_mut() {
        let id = d.id;
        // DEBUG-only instruction: a prod device simply has no 0x69, and the
        // commitments check below is the part that matters anyway.
        let dbg = match try_exchange(
            &mut d.transport,
            &build_apdu0(INS_DKG_DEBUG_SKSHARE),
            "DEBUG_SKSHARE",
        ) {
            Ok(v) => v,
            Err(sw) => {
                eprintln!("device {id}: no DEBUG_SKSHARE (SW={sw}), skipping the share check");
                continue;
            }
        };
        assert_eq!(dbg.len(), 64, "sk(32) || sk_div8(32)");
        let sk = BigInt::from_bytes_be(num_bigint::Sign::Plus, &dbg[..32]);
        let sk_div8 = BigInt::from_bytes_be(num_bigint::Sign::Plus, &dbg[32..]);
        assert_eq!(
            sk,
            curve.mod_order(&(BigInt::from(8u32) * &sk_div8)),
            "device {id}: skShare must be 8 × skShareDiv8"
        );
        assert_eq!(
            curve.scalar_base_mult(&sk),
            public_share(id),
            "device {id}: share does not match the Feldman commitments"
        );
    }

    // ── FROST: a quorum of t signs one message ──────────────────────────
    let message = &setup.message;
    let msg_le = curve.to_bytes(message).expect("message fits");

    let mut commitment_list: Vec<Commitment> = Vec::new();
    let mut records: Vec<Vec<u8>> = Vec::new();
    for &k in &setup.quorum {
        let id = devices[k].id;
        let out = devices[k].send(&build_apdu0(INS_FROST_HW_COMMIT), "FROST_COMMIT");
        assert_eq!(out.len(), 128, "D(64) || E(64)");
        let hiding = point_be(&out[..64]);
        let binding = point_be(&out[64..]);

        let mut rec = vec![0u8; 32];
        rec[31] = id;
        rec.extend_from_slice(&out);
        assert_eq!(rec.len(), FROST_FS_REC);
        records.push(rec);

        commitment_list.push(Commitment {
            identifier: BigInt::from(id),
            hiding_nonce_commitment: hiding,
            binding_nonce_commitment: binding,
        });
    }

    // Everything the per-share check needs, read off the commitment list once.
    let binding_factors = frost
        .compute_binding_factors(&group_key, &commitment_list, &msg_le)
        .expect("binding factors");
    let r8 = frost
        .compute_group_commitment(&commitment_list, &binding_factors)
        .expect("group commitment");
    let challenge = frost.compute_challenge(&r8, &group_key, message);
    let ids: Vec<BigInt> = commitment_list
        .iter()
        .map(|c| c.identifier.clone())
        .collect();

    let mut shares: Vec<BigInt> = Vec::new();
    for (i, &k) in setup.quorum.iter().enumerate() {
        // msg(32) || first record as FIRST, every other record after it, the
        // last one as LAST — one APDU's Lc is a single byte.
        let mut first = msg_le.clone();
        first.extend_from_slice(&records[0]);
        devices[k].send(
            &build_apdu(INS_FROST_HW_SIGN, FROST_P1_FIRST, 0, &first),
            "SIGN[first]",
        );
        for rec in records.iter().take(records.len() - 1).skip(1) {
            devices[k].send(
                &build_apdu(INS_FROST_HW_SIGN, FROST_P1_NEXT, 0, rec),
                "SIGN[next]",
            );
        }
        let z = devices[k].send(
            &build_apdu(
                INS_FROST_HW_SIGN,
                FROST_P1_LAST,
                0,
                &records[records.len() - 1],
            ),
            "SIGN[last]",
        );
        assert_eq!(z.len(), 32, "z_i");
        let z = BigInt::from_bytes_be(num_bigint::Sign::Plus, &z);

        // Each share, checked on its own against the public share rebuilt from
        // the commitments: z_i·B8 == (D_i + ρ_i·E_i) + (λ_i·c)·P_i.
        let id = BigInt::from(devices[k].id);
        let lambda = frost.derive_interpolating_value(&ids, &id).expect("lambda");
        let rho = frost
            .binding_factor_for_participant(&binding_factors, &id)
            .expect("rho");
        let commitment_share = curve.add_point(
            &commitment_list[i].hiding_nonce_commitment,
            &curve.scalar_mult(&commitment_list[i].binding_nonce_commitment, &rho),
        );
        let right = curve.add_point(
            &commitment_share,
            &curve.scalar_mult(
                &public_share(devices[k].id),
                &curve.mod_order(&(lambda * &challenge)),
            ),
        );
        assert_eq!(
            curve.scalar_base_mult(&z),
            right,
            "device {}: its signature share does not verify",
            devices[k].id
        );

        shares.push(z);
    }

    // ── the aggregate, verified by the port of the TypeScript library ───
    let signature = frost
        .aggregate(&commitment_list, message, &group_key, &shares)
        .expect("aggregate");
    assert!(
        eddsa.verify_poseidon(
            &bigint_to_bytes(message, 32).expect("message"),
            &Signature {
                r8: signature.r8.clone(),
                s: signature.s.clone()
            },
            &group_key
        ),
        "the aggregate must verify as EdDSA-Poseidon under the group key"
    );
    // The verifier's whole input is the message, the signature and that group
    // key — no seed, no share, nothing per-participant — which is why the
    // seeds can be shared or unrelated without the verification caring. Under
    // another key the same signature must fail.
    assert!(
        !eddsa.verify_poseidon(
            &bigint_to_bytes(message, 32).expect("message"),
            &Signature {
                r8: signature.r8.clone(),
                s: signature.s.clone()
            },
            &curve.add_point(&group_key, &curve.scalar_base_mult(&BigInt::from(1u32)))
        ),
        "a signature valid under a different group key would be no signature at all"
    );
    // and must not verify for another message
    let other = curve.mod_order(&(message + 1u32));
    assert!(
        !eddsa.verify_poseidon(
            &bigint_to_bytes(&other, 32).expect("message"),
            &Signature {
                r8: signature.r8,
                s: signature.s
            },
            &group_key
        ),
        "a signature valid for any message would be a broken challenge"
    );

    // The nonces are burnt on the device: a second SIGN must be refused.
    let mut again = msg_le.clone();
    again.extend_from_slice(&records[0]);
    let err = exchange(
        &mut devices[setup.quorum[0]].transport,
        &build_apdu(INS_FROST_HW_SIGN, FROST_P1_FIRST, 0, &again),
        "SIGN/again",
    )
    .expect_err("signing twice on one commitment must be refused");
    assert_eq!(
        err.sw, SW_BAD_STATE,
        "expected SW_BAD_STATE, got {}",
        err.sw
    );

    // Sanity on the message encoding: the device reads msg little-endian, the
    // host signs the same scalar.
    assert_eq!(le_buffer_to_bigint(&msg_le), *message);
    true
}

// ── draws ───────────────────────────────────────────────────────────────

/// Uniform in `0..k`, by rejection so there is no modulo bias.
fn below(rng: &mut dyn Rng, k: u32) -> u32 {
    assert!(k > 0);
    let limit = u32::MAX - (u32::MAX % k) - 1;
    loop {
        let mut b = [0u8; 4];
        rng.fill_bytes(&mut b);
        let v = u32::from_le_bytes(b);
        if v <= limit {
            return v % k;
        }
    }
}

/// `k` distinct indices out of `0..n`, ascending.
fn subset(rng: &mut dyn Rng, n: usize, k: usize) -> Vec<usize> {
    let mut pool: Vec<usize> = (0..n).collect();
    for i in 0..k {
        let j = i + below(rng, (n - i) as u32) as usize;
        pool.swap(i, j);
    }
    let mut picked = pool[..k].to_vec();
    picked.sort_unstable();
    picked
}

// ── the two ceremonies ──────────────────────────────────────────────────

/// 2-of-3 on the canonical seed, every participant on mnemonic "yellow"×12.
///
/// This is the configuration `run-rs-device-tests.sh` reruns with a physical
/// Ledger as one of the participants, so the pure-software run and the device
/// run compare like for like — the device's transport key is then checked
/// against the same host derivation as everybody else's.
#[test]
fn a_ceremony_on_the_canonical_seed_signs_and_verifies() {
    let message = Curve::new().random_scalar(&mut OsRng, true);
    run(&Setup {
        label: "canonical ceremony (2-of-3, yellow×12)".to_string(),
        t: 2,
        account: ACCOUNT,
        name: "rs-e2e".to_string(),
        seeds: vec![Seeding::Default; 3],
        quorum: vec![0, 1],
        message,
        allow_device: true,
    });
}

/// The same ceremony with everything drawn: a 64-byte seed per participant,
/// n, t, the quorum, the ceremony name and the message.
///
/// Pure software — a physical Ledger cannot be handed a seed, so this one
/// never uses one even under `HW_DEVICE`. The seeds being unrelated is the
/// point: each participant derives its own transport key, the host recomputes
/// all of them, and the signature still verifies under the group public key
/// alone. Every draw comes from the OS CSPRNG, and the parameters are printed
/// so a failing run can be replayed by hand with the same `SIM_SEED`s.
#[test]
fn a_ceremony_on_random_per_participant_seeds_signs_and_verifies() {
    let mut rng = OsRng;
    let n = 3 + below(&mut rng, (DKG_MAX_N - 3 + 1) as u32) as usize;
    let t_max = std::cmp::min(DKG_MAX_T, n);
    let t = 2 + below(&mut rng, (t_max - 2 + 1) as u32) as usize;
    let quorum = subset(&mut rng, n, t);
    let name = format!("rs-rand-{}", buf2hex(&rng.random_bytes(6)));
    let message = Curve::new().random_scalar(&mut rng, true);

    let seeds: Vec<Seeding> = (0..n)
        .map(|_| {
            let mut seed = [0u8; 64];
            rng.fill_bytes(&mut seed);
            Seeding::Explicit(seed)
        })
        .collect();

    eprintln!("random ceremony: {t}-of-{n}, name {name:?}");
    eprintln!("  message  {}", message);
    eprintln!(
        "  quorum   ids {:?}",
        quorum.iter().map(|k| k + 1).collect::<Vec<_>>()
    );
    for (index, s) in seeds.iter().enumerate() {
        eprintln!("  SIM_SEED id {} {}", index + 1, s.sim_seed());
    }

    run(&Setup {
        label: format!("random ceremony ({t}-of-{n}, one seed per participant)"),
        t,
        account: ACCOUNT,
        name,
        seeds,
        quorum,
        message,
        allow_device: false,
    });
}
