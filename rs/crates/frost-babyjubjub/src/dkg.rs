//! Port of `src/frost/trusted-dkg.ts` (`TrustedDKG`).

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use num_bigint::BigInt;
use num_traits::Zero;

use crate::curve::{Curve, Point};
use crate::error::{Error, Result};
use crate::frost::CONTEXT_STRING;
use crate::hashing::{HashKind, Rfc9591Hasher};
use crate::rng::Rng;

/// `EncryptedShare`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedShare {
    /// `nonce` (12 bytes).
    pub nonce: Vec<u8>,
    /// `ciphertext` (payload followed by the 16-byte tag).
    pub ciphertext: Vec<u8>,
}

/// `Share` — a finalized signer share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// `id`.
    pub id: u32,
    /// `skShare` — the share used for FROST signing (8 × `skShareDiv8`).
    pub sk_share: BigInt,
    /// `skShareDiv8` — the raw polynomial evaluation.
    pub sk_share_div8: BigInt,
}

/// Output of `finalizeParticipant`.
#[derive(Clone, Debug)]
pub struct Finalized {
    /// `share`.
    pub share: Share,
    /// `PKGroup`.
    pub pk_group: Point,
    /// `viewingPrivateKey`.
    pub viewing_private_key: Vec<u8>,
}

/// Output of `trustedDealerKeygen`.
#[derive(Clone, Debug)]
pub struct DealerKeygen {
    /// `participantPrivateKeys` — `(x_i, y_i)` pairs for `x_i` in `1..=max+1`.
    pub participant_private_keys: Vec<(u32, BigInt)>,
    /// `coefficients`, constant term first.
    pub coefficients: Vec<BigInt>,
    /// `base` — the constant-term commitment.
    pub base: Point,
    /// `vssCommitment`.
    pub vss_commitment: Vec<Point>,
}

/// Output of `deriveGroupInfo`.
#[derive(Clone, Debug)]
pub struct GroupInfo {
    /// `PK`.
    pub pk: Point,
    /// `participantPublicKeys`.
    pub participant_public_keys: Vec<Point>,
    /// `viewingPrivateKey`.
    pub viewing_private_key: Vec<u8>,
}

/// `TrustedDKG`.
#[derive(Clone, Debug)]
pub struct TrustedDkg {
    /// Curve helper (inheritance in the TypeScript).
    pub curve: Curve,
    /// `hasher`.
    pub hasher: Rfc9591Hasher,
}

impl Default for TrustedDkg {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustedDkg {
    /// `new TrustedDKG()`.
    pub fn new() -> Self {
        let curve = Curve::new();
        let hasher = Rfc9591Hasher::new(CONTEXT_STRING, curve.order().clone());
        TrustedDkg { curve, hasher }
    }

    /// Same, with the BLAKE-512 base hash of `fix/blake512-hasher`.
    pub fn new_blake512() -> Self {
        let curve = Curve::new();
        let hasher =
            Rfc9591Hasher::with_hash(CONTEXT_STRING, curve.order().clone(), HashKind::Blake512);
        TrustedDkg { curve, hasher }
    }

    /// `polynomialEvaluate`.
    pub fn polynomial_evaluate(&self, x: &BigInt, coefficients: &[BigInt]) -> BigInt {
        let mut value = BigInt::zero();
        for c in coefficients.iter().rev() {
            value *= x;
            value += c;
        }
        self.curve.mod_order(&value)
    }

    /// `trustedDealerKeygen`.
    pub fn trusted_dealer_keygen(
        &self,
        rng: &mut dyn Rng,
        secret_key: &BigInt,
        max_participants: u32,
        min_participants: u32,
    ) -> Result<DealerKeygen> {
        let mut coefficients = Vec::new();
        for _ in 0..min_participants.saturating_sub(1) {
            coefficients.push(self.curve.random_scalar(rng, true));
        }
        let (participant_private_keys, coeffs) =
            self.secret_share_shard(secret_key, &coefficients, max_participants);
        let vss_commitment = self.vss_commit(&coeffs);
        let base = vss_commitment
            .first()
            .cloned()
            .ok_or_else(|| Error::new("trustedDealerKeygen: empty commitment"))?;
        Ok(DealerKeygen {
            participant_private_keys,
            coefficients: coeffs,
            base,
            vss_commitment,
        })
    }

    /// `vssCommit`.
    pub fn vss_commit(&self, coefficients: &[BigInt]) -> Vec<Point> {
        coefficients
            .iter()
            .map(|c| self.curve.scalar_base_mult(c))
            .collect()
    }

    /// `vssVerify`.
    pub fn vss_verify(
        &self,
        i: &BigInt,
        sk_i: &BigInt,
        vss_commitment: &[Point],
        _min_participants: u32,
    ) -> bool {
        let s_i = self.curve.scalar_base_mult(sk_i);
        let mut s_ip = self.curve.identity();
        let mut pow = BigInt::from(1u32);
        for c in vss_commitment {
            let commit = self.curve.mul_point_escalar(c, &pow);
            s_ip = self.curve.add_point(&s_ip, &commit);
            pow *= i;
        }
        self.curve.points_equal(&s_i, &s_ip)
    }

    /// `secretShareShard` — shares for `x_i` in `1..=max_participants + 1`.
    pub fn secret_share_shard(
        &self,
        s: &BigInt,
        coefficients: &[BigInt],
        max_participants: u32,
    ) -> (Vec<(u32, BigInt)>, Vec<BigInt>) {
        let mut coeffs = Vec::with_capacity(coefficients.len() + 1);
        coeffs.push(s.clone());
        coeffs.extend_from_slice(coefficients);
        let mut shares = Vec::new();
        for x_i in 1..=max_participants + 1 {
            let y_i = self.polynomial_evaluate(&BigInt::from(x_i), &coeffs);
            shares.push((x_i, y_i));
        }
        (shares, coeffs)
    }

    /// `deriveGroupInfo`.
    pub fn derive_group_info(
        &self,
        max_participants: u32,
        min_participants: u32,
        vss_commitment: &[Point],
    ) -> Result<GroupInfo> {
        let pk = vss_commitment
            .first()
            .cloned()
            .ok_or_else(|| Error::new("deriveGroupInfo: empty commitment"))?;
        if (min_participants as usize) > vss_commitment.len() {
            return Err(Error::new("deriveGroupInfo: commitment too short"));
        }
        let mut participant_public_keys = Vec::new();
        for i in 1..=max_participants + 1 {
            let mut pk_i = self.curve.identity();
            let mut pow = BigInt::from(1u32);
            for c in vss_commitment.iter().take(min_participants as usize) {
                let commit = self.curve.mul_point_escalar(c, &pow);
                pk_i = self.curve.add_point(&pk_i, &commit);
                pow *= i;
            }
            participant_public_keys.push(pk_i);
        }
        let viewing_private_key = self.derive_view_key_from_pk(&[vss_commitment.to_vec()])?;
        Ok(GroupInfo {
            pk,
            participant_public_keys,
            viewing_private_key,
        })
    }

    /// `assertSortedConsecutiveIds`.
    pub fn assert_sorted_consecutive_ids(ids: &[i64]) -> Result<()> {
        if ids.is_empty() {
            return Err(Error::new("empty recipient id list"));
        }
        if ids.iter().any(|id| *id <= 0) {
            return Err(Error::new(
                "recipient ids must be strictly increasing positive integers (self may be excluded)",
            ));
        }
        for i in 1..ids.len() {
            if ids[i] <= ids[i - 1] {
                return Err(Error::new(
                    "recipient ids must be strictly increasing positive integers (self may be excluded)",
                ));
            }
        }
        Ok(())
    }

    fn verify_commitments_shape(&self, all: &[Vec<Point>]) -> Result<usize> {
        if all.is_empty() {
            return Err(Error::new("no dealer commitments"));
        }
        if all.iter().any(|c| c.is_empty()) {
            return Err(Error::new("dealer missing commitments"));
        }
        let t = all[0].len();
        for c in all {
            if c.len() != t {
                return Err(Error::new("commitment degree mismatch across dealers"));
            }
        }
        Ok(t)
    }

    /// `computeSharesForIds`.
    pub fn compute_shares_for_ids(
        &self,
        coefficients: &[BigInt],
        recipient_ids: &[i64],
    ) -> Result<BTreeMap<i64, BigInt>> {
        Self::assert_sorted_consecutive_ids(recipient_ids)?;
        let mut out = BTreeMap::new();
        for id in recipient_ids {
            out.insert(
                *id,
                self.polynomial_evaluate(&BigInt::from(*id), coefficients),
            );
        }
        Ok(out)
    }

    /// `combineGroupPubkeyFromCommitments`.
    pub fn combine_group_pubkey_from_commitments(&self, all: &[Vec<Point>]) -> Result<Point> {
        if all.is_empty() {
            return Err(Error::new("no dealer commitments"));
        }
        self.verify_commitments_shape(all)?;
        let mut acc = self.curve.identity();
        for dealer_com in all {
            let p0 = dealer_com
                .first()
                .ok_or_else(|| Error::new("dealer missing commitments"))?;
            if !self.curve.points_equal(
                &self.curve.mul_point_escalar(p0, self.curve.order()),
                &self.curve.identity(),
            ) {
                return Err(Error::new("C0 not in subgroup"));
            }
            acc = self.curve.add_point(&acc, p0);
        }
        Ok(acc)
    }

    /// `verifyAllCommitmentsSubgroup`.
    pub fn verify_all_commitments_subgroup(&self, all: &[Vec<Point>]) -> bool {
        if all.is_empty() {
            return false;
        }
        for dealer_com in all {
            if dealer_com.is_empty() {
                return false;
            }
            for cj in dealer_com {
                if !self.curve.points_equal(
                    &self.curve.mul_point_escalar(cj, self.curve.order()),
                    &self.curve.identity(),
                ) {
                    return false;
                }
            }
        }
        true
    }

    /// `verifyFeldmanShare`.
    pub fn verify_feldman_share(&self, id: i64, sk_i: &BigInt, commitments: &[Point]) -> bool {
        if id <= 0 || commitments.is_empty() {
            return false;
        }
        let lhs = self.curve.scalar_base_mult(&self.curve.mod_order(sk_i));
        let mut rhs = self.curve.identity();
        let mut pow = BigInt::from(1u32);
        let id_l = self.curve.mod_order(&BigInt::from(id));
        for cj in commitments {
            if !self.curve.points_equal(
                &self.curve.mul_point_escalar(cj, self.curve.order()),
                &self.curve.identity(),
            ) {
                return false;
            }
            rhs = self.curve.add_point(&rhs, &self.curve.scalar_mult(cj, &pow));
            pow = self.curve.mod_order(&(&pow * &id_l));
        }
        self.curve.points_equal(&lhs, &rhs)
    }

    /// `deriveInterpolatingValue`.
    pub fn derive_interpolating_value(&self, ids: &[BigInt], x_i: &BigInt) -> Result<BigInt> {
        if x_i <= &BigInt::zero() || ids.iter().any(|a| a <= &BigInt::zero()) {
            return Err(Error::new("invalid parameters"));
        }
        if !ids.iter().any(|a| a == x_i) {
            return Err(Error::new("invalid parameters"));
        }
        let mut num = BigInt::from(1u32);
        let mut dom = BigInt::from(1u32);
        for x_j in ids {
            if x_j == x_i {
                continue;
            }
            num = self.curve.mod_order(&(&num * self.curve.mod_order(x_j)));
            dom = self
                .curve
                .mod_order(&(&dom * self.curve.mod_order(&(x_j - x_i))));
        }
        let inv_dom = self.curve.inv_mod_order(&dom)?;
        Ok(self.curve.mod_order(&(num * inv_dom)))
    }

    /// `reconstructConstantFromShares`.
    pub fn reconstruct_constant_from_shares(&self, subset: &[(i64, BigInt)]) -> Result<BigInt> {
        if subset.is_empty() {
            return Err(Error::new("no shares"));
        }
        let ids: Vec<BigInt> = subset
            .iter()
            .map(|(id, _)| self.curve.mod_order(&BigInt::from(*id)))
            .collect();
        let mut a0 = BigInt::zero();
        for (id, s_i) in subset {
            let lambda =
                self.derive_interpolating_value(&ids, &self.curve.mod_order(&BigInt::from(*id)))?;
            a0 = self
                .curve
                .mod_order(&(&a0 + self.curve.mod_order(s_i) * lambda));
        }
        Ok(a0)
    }

    fn sort_key(p: &Point) -> String {
        format!("{:0>64x}:{:0>64x}", p.x, p.y)
    }

    /// `deriveViewKeyFromPK`.
    pub fn derive_view_key_from_pk(&self, all: &[Vec<Point>]) -> Result<Vec<u8>> {
        let mut c0s: Vec<Point> = Vec::new();
        for dealer in all {
            if dealer.is_empty() {
                continue;
            }
            c0s.push(dealer[0].clone());
        }
        c0s.sort_by(|a, b| Self::sort_key(a).cmp(&Self::sort_key(b)));
        let mut acc = BigInt::zero();
        for c0 in &c0s {
            let v = self.hasher.h7(&self.curve.serialize_element(c0)?);
            let v_k = self.curve.mod_order(&v);
            acc = self.curve.mod_order(&(&acc + v_k));
        }
        let value = if acc.is_zero() { BigInt::from(1u32) } else { acc };
        self.curve.to_bytes(&value)
    }

    /// `finalizeParticipant`.
    pub fn finalize_participant(
        &self,
        participant_id: i64,
        s_ki_by_dealer: &[(i64, BigInt)],
        all_dealer_commitments: &[Vec<Point>],
    ) -> Result<Finalized> {
        if participant_id <= 0 {
            return Err(Error::new("bad participantId"));
        }
        if s_ki_by_dealer.is_empty() || s_ki_by_dealer.len() != all_dealer_commitments.len() {
            return Err(Error::new("dealer/share count mismatch"));
        }
        let mut dealer_ids: Vec<i64> = s_ki_by_dealer.iter().map(|(d, _)| *d).collect();
        dealer_ids.sort_unstable();
        Self::assert_sorted_consecutive_ids(&dealer_ids)?;
        let mut s_i = BigInt::zero();
        for (_, s_ki) in s_ki_by_dealer {
            s_i = self.curve.mod_order(&(&s_i + self.curve.mod_order(s_ki)));
        }
        let sk_share_div8 = s_i;
        let sk_share = self.curve.mod_order(&(BigInt::from(8u32) * &sk_share_div8));
        let viewing_private_key = self.derive_view_key_from_pk(all_dealer_commitments)?;
        let pk_group = self.combine_group_pubkey_from_commitments(all_dealer_commitments)?;
        Ok(Finalized {
            share: Share {
                id: participant_id as u32,
                sk_share,
                sk_share_div8,
            },
            pk_group,
            viewing_private_key,
        })
    }

    /// `commitmentsDigest`.
    pub fn commitments_digest(&self, all: &[Vec<Point>]) -> Result<BigInt> {
        let enc = self.encode_commitments_bytes(all)?;
        Ok(self.hasher.h5(&enc))
    }

    fn encode_commitments_bytes(&self, all: &[Vec<Point>]) -> Result<Vec<u8>> {
        let mut dealers: Vec<&Vec<Point>> = all.iter().filter(|d| !d.is_empty()).collect();
        dealers.sort_by(|a, b| {
            if Self::sort_key(&a[0]) < Self::sort_key(&b[0]) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        let mut out = Vec::new();
        for dealer in dealers {
            for cj in dealer {
                out.extend_from_slice(&self.curve.serialize_element(cj)?);
            }
        }
        Ok(out)
    }

    /// `encryptSharesAESGCMWithAAD`.
    pub fn encrypt_shares_aes_gcm_with_aad(
        &self,
        rng: &mut dyn Rng,
        shares: &BTreeMap<i64, BigInt>,
        key_by_id: &BTreeMap<i64, Vec<u8>>,
        all_dealer_commitments: &[Vec<Point>],
    ) -> Result<BTreeMap<i64, EncryptedShare>> {
        let ids: Vec<i64> = shares.keys().copied().collect();
        Self::assert_sorted_consecutive_ids(&ids)?;
        let mut out = BTreeMap::new();
        let digest = self.commitments_digest(all_dealer_commitments)?;
        let digest_bytes = self.curve.to_bytes(&digest)?;
        for (id, s) in shares {
            let key = key_by_id.get(id);
            let key = match key {
                Some(k) if k.len() == 32 => k,
                _ => return Err(Error::new(format!("bad AES key for id {id}"))),
            };
            let nonce = rng.random_bytes(12);
            let pt = self.curve.to_bytes(&self.curve.mod_order(s))?;
            let mut aad = self.curve.serialize_scalar(&BigInt::from(*id))?;
            aad.extend_from_slice(&digest_bytes);
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::new(format!("bad AES key for id {id}")))?;
            let ciphertext = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &pt,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::new("aes-gcm: encryption failed"))?;
            out.insert(
                *id,
                EncryptedShare {
                    nonce,
                    ciphertext,
                },
            );
        }
        Ok(out)
    }

    /// `decryptShareAESGCMWithAAD`.
    pub fn decrypt_share_aes_gcm_with_aad(
        &self,
        enc: &EncryptedShare,
        key_bytes: &[u8],
        participant_id: i64,
        all_dealer_commitments: &[Vec<Point>],
    ) -> Result<BigInt> {
        if key_bytes.len() != 32 {
            return Err(Error::new("bad AES key length"));
        }
        if participant_id <= 0 {
            return Err(Error::new("bad participant id"));
        }
        // A nonce of the wrong length is a malformed payload, never something to
        // repair: the GitLab source rejects it instead of truncating or padding.
        let nonce = enc.nonce.clone();
        let ct = enc.ciphertext.clone();
        if nonce.len() != 12 {
            return Err(Error::new("bad nonce length (expected 12)"));
        }
        if ct.len() < 16 {
            return Err(Error::new("bad ciphertext (must include 16B tag)"));
        }
        let digest = self.commitments_digest(all_dealer_commitments)?;
        let mut aad = self.curve.serialize_scalar(&BigInt::from(participant_id))?;
        aad.extend_from_slice(&self.curve.to_bytes(&digest)?);
        let cipher =
            Aes256Gcm::new_from_slice(key_bytes).map_err(|_| Error::new("bad AES key length"))?;
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::new("invalid tag"))?;
        Ok(self.curve.from_bytes(&pt))
    }
}
