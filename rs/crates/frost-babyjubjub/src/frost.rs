//! Port of `src/frost/babyfrost.ts` (`BabyFROST`).

use num_bigint::BigInt;
use num_traits::Zero;

use crate::curve::{Curve, Point};
use crate::error::{Error, Result};
use crate::hashing::{HashKind, Rfc9591Hasher};
use crate::rng::Rng;

/// `contextString` of the ciphersuite.
pub const CONTEXT_STRING: &str = "FROST-EDBABYJUJUB-BLAKE512-v1";

/// `Commitment` — a participant's round-1 public commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    /// `identifier`.
    pub identifier: BigInt,
    /// `hidingNonceCommitment`.
    pub hiding_nonce_commitment: Point,
    /// `bindingNonceCommitment`.
    pub binding_nonce_commitment: Point,
}

/// `BindingFactor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingFactor {
    /// `identifier`.
    pub identifier: BigInt,
    /// `bindingFactor`.
    pub binding_factor: BigInt,
}

/// `NoncePair` — the signer's private round-1 nonces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoncePair {
    /// `hidingNonce`.
    pub hiding_nonce: BigInt,
    /// `bindingNonce`.
    pub binding_nonce: BigInt,
}

/// `Bindings` — round-1 output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bindings {
    /// `nonces`.
    pub nonces: NoncePair,
    /// `commitments`.
    pub commitments: Commitment,
}

/// Aggregate signature returned by [`BabyFrost::aggregate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateSignature {
    /// `R8`.
    pub r8: Point,
    /// `S`.
    pub s: BigInt,
}

/// `BabyFROST`.
#[derive(Clone, Debug)]
pub struct BabyFrost {
    /// Curve helper (inheritance in the TypeScript).
    pub curve: Curve,
    /// `hasher`.
    pub hasher: Rfc9591Hasher,
}

impl Default for BabyFrost {
    fn default() -> Self {
        Self::new()
    }
}

impl BabyFrost {
    /// `new BabyFROST()`.
    pub fn new() -> Self {
        let curve = Curve::new();
        let hasher = Rfc9591Hasher::new(CONTEXT_STRING, curve.order().clone());
        BabyFrost { curve, hasher }
    }

    /// Same, with the BLAKE-512 base hash of `fix/blake512-hasher`.
    pub fn new_blake512() -> Self {
        let curve = Curve::new();
        let hasher =
            Rfc9591Hasher::with_hash(CONTEXT_STRING, curve.order().clone(), HashKind::Blake512);
        BabyFrost { curve, hasher }
    }

    /// `H1`.
    pub fn h1(&self, m: &[u8]) -> BigInt {
        self.hasher.h1(m)
    }

    /// `H2`.
    pub fn h2(&self, r8: &Point, a: &Point, msg_hash: &BigInt) -> BigInt {
        self.hasher.h2(r8, a, msg_hash)
    }

    /// `H3`.
    pub fn h3(&self, m: &[u8]) -> BigInt {
        self.hasher.h3(m)
    }

    /// `H4`.
    pub fn h4(&self, m: &[u8]) -> BigInt {
        self.hasher.h4(m)
    }

    /// `H5`.
    pub fn h5(&self, m: &[u8]) -> BigInt {
        self.hasher.h5(m)
    }

    /// `generateNonce`.
    pub fn generate_nonce(&self, rng: &mut dyn Rng, secret: &BigInt) -> Result<BigInt> {
        let random = self
            .curve
            .serialize_scalar(&self.curve.random_scalar(rng, true))?;
        let serialized = self.curve.serialize_scalar(secret)?;
        let mut h = Vec::with_capacity(64);
        h.extend_from_slice(&random);
        h.extend_from_slice(&serialized);
        Ok(self.h3(&h))
    }

    /// `deriveInterpolatingValue`.
    pub fn derive_interpolating_value(&self, l: &[BigInt], x_i: &BigInt) -> Result<BigInt> {
        if x_i <= &BigInt::zero() || l.iter().any(|a| a <= &BigInt::zero()) {
            return Err(Error::new("invalid parameters"));
        }
        if !l.iter().any(|a| a == x_i) {
            return Err(Error::new("invalid parameters"));
        }
        let mut num = BigInt::from(1u32);
        let mut dom = BigInt::from(1u32);
        for x_j in l {
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

    /// `encodeGroupCommitmentList`.
    pub fn encode_group_commitment_list(&self, commitment_list: &[Commitment]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for c in commitment_list {
            out.extend_from_slice(&self.curve.serialize_scalar(&c.identifier)?);
            out.extend_from_slice(&self.curve.serialize_element(&c.hiding_nonce_commitment)?);
            out.extend_from_slice(&self.curve.serialize_element(&c.binding_nonce_commitment)?);
        }
        Ok(out)
    }

    /// `participantsFromCommitmentList`.
    pub fn participants_from_commitment_list(&self, commitment_list: &[Commitment]) -> Vec<BigInt> {
        commitment_list.iter().map(|c| c.identifier.clone()).collect()
    }

    /// `bindingFactorForParticipant`.
    pub fn binding_factor_for_participant(
        &self,
        binding_factor_list: &[BindingFactor],
        identifier: &BigInt,
    ) -> Result<BigInt> {
        for bf in binding_factor_list {
            if &bf.identifier == identifier {
                return Ok(bf.binding_factor.clone());
            }
        }
        Err(Error::new("invalid participant"))
    }

    /// `computeBindingFactors`.
    pub fn compute_binding_factors(
        &self,
        group_public_key: &Point,
        commitment_list: &[Commitment],
        message: &[u8],
    ) -> Result<Vec<BindingFactor>> {
        let group_public_key_enc = self.curve.serialize_element(group_public_key)?;
        let msg_hash = self.h4(message);
        let encoded_commitment_hash = self.h5(&self.encode_group_commitment_list(commitment_list)?);
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&group_public_key_enc);
        prefix.extend_from_slice(&self.curve.to_bytes(&msg_hash)?);
        prefix.extend_from_slice(&self.curve.to_bytes(&encoded_commitment_hash)?);
        let mut out = Vec::with_capacity(commitment_list.len());
        for c in commitment_list {
            let mut rho_input = prefix.clone();
            rho_input.extend_from_slice(&self.curve.serialize_scalar(&c.identifier)?);
            out.push(BindingFactor {
                identifier: c.identifier.clone(),
                binding_factor: self.h1(&rho_input),
            });
        }
        Ok(out)
    }

    /// `computeGroupCommitment`.
    pub fn compute_group_commitment(
        &self,
        commitment_list: &[Commitment],
        binding_factor_list: &[BindingFactor],
    ) -> Result<Point> {
        let mut group_commitment = self.curve.identity();
        for c in commitment_list {
            let bf = self.binding_factor_for_participant(binding_factor_list, &c.identifier)?;
            let binding_nonce = self.curve.scalar_mult(&c.binding_nonce_commitment, &bf);
            group_commitment = self.curve.add_point(
                &self
                    .curve
                    .add_point(&group_commitment, &c.hiding_nonce_commitment),
                &binding_nonce,
            );
        }
        Ok(group_commitment)
    }

    /// `computeChallenge`.
    pub fn compute_challenge(
        &self,
        group_commitment: &Point,
        group_public_key: &Point,
        message: &BigInt,
    ) -> BigInt {
        self.h2(group_commitment, group_public_key, message)
    }

    /// `commit` — round 1.
    pub fn commit(&self, rng: &mut dyn Rng, sk_i: &BigInt, identifier: &BigInt) -> Result<Bindings> {
        let hiding_nonce = self.generate_nonce(rng, &self.curve.mod_order(sk_i))?;
        let binding_nonce = self.generate_nonce(rng, &self.curve.mod_order(sk_i))?;
        let hiding_nonce_commitment = self.curve.scalar_base_mult(&hiding_nonce);
        let binding_nonce_commitment = self.curve.scalar_base_mult(&binding_nonce);
        Ok(Bindings {
            nonces: NoncePair {
                hiding_nonce,
                binding_nonce,
            },
            commitments: Commitment {
                identifier: identifier.clone(),
                hiding_nonce_commitment,
                binding_nonce_commitment,
            },
        })
    }

    /// `sign` — round 2 signature share.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &self,
        identifier: &BigInt,
        sk_i: &BigInt,
        group_public_key: &Point,
        nonce_i: &NoncePair,
        message: &BigInt,
        commitment_list: &[Commitment],
    ) -> Result<BigInt> {
        let msg_bytes = self.curve.to_bytes(message)?;
        let binding_factor_list =
            self.compute_binding_factors(group_public_key, commitment_list, &msg_bytes)?;
        let binding_factor =
            self.binding_factor_for_participant(&binding_factor_list, identifier)?;
        let group_commitment =
            self.compute_group_commitment(commitment_list, &binding_factor_list)?;
        let participant_list = self.participants_from_commitment_list(commitment_list);
        let lambda_i = self.derive_interpolating_value(&participant_list, identifier)?;
        let challenge = self.compute_challenge(&group_commitment, group_public_key, message);
        let sig_share = &nonce_i.hiding_nonce
            + (&nonce_i.binding_nonce * &binding_factor)
            + (lambda_i * sk_i * challenge);
        Ok(self.curve.mod_order(&sig_share))
    }

    /// `aggregate`.
    pub fn aggregate(
        &self,
        commitment_list: &[Commitment],
        message: &BigInt,
        group_public_key: &Point,
        sig_shares: &[BigInt],
    ) -> Result<AggregateSignature> {
        let msg_bytes = self.curve.to_bytes(message)?;
        let binding_factor_list =
            self.compute_binding_factors(group_public_key, commitment_list, &msg_bytes)?;
        let group_commitment =
            self.compute_group_commitment(commitment_list, &binding_factor_list)?;
        let mut z = BigInt::zero();
        for z_i in sig_shares {
            z = self.curve.mod_order(&(&z + z_i));
        }
        Ok(AggregateSignature {
            r8: group_commitment,
            s: self.curve.mod_order(&z),
        })
    }

    /// `verifySignatureShare`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_signature_share(
        &self,
        identifier: &BigInt,
        sk_i: &BigInt,
        commitment_i: &Commitment,
        sig_share_i: &BigInt,
        commitment_list: &[Commitment],
        group_public_key: &Point,
        message: &BigInt,
    ) -> Result<bool> {
        let msg_bytes = self.curve.to_bytes(message)?;
        let binding_factor_list =
            self.compute_binding_factors(group_public_key, commitment_list, &msg_bytes)?;
        let binding_factor =
            self.binding_factor_for_participant(&binding_factor_list, identifier)?;
        let group_commitment =
            self.compute_group_commitment(commitment_list, &binding_factor_list)?;

        let binding_mult = self
            .curve
            .scalar_mult(&commitment_i.binding_nonce_commitment, &binding_factor);
        let commitment_share = self
            .curve
            .add_point(&commitment_i.hiding_nonce_commitment, &binding_mult);

        let challenge = self.compute_challenge(&group_commitment, group_public_key, message);
        let participant_list = self.participants_from_commitment_list(commitment_list);
        let lambda_i = self.derive_interpolating_value(&participant_list, identifier)?;

        let left_side = self.curve.scalar_base_mult(sig_share_i);
        let right_side_scalar = self.curve.mod_order(&(lambda_i * sk_i * challenge));
        let right_side_point = self.curve.scalar_base_mult(&right_side_scalar);
        let right_side = self.curve.add_point(&commitment_share, &right_side_point);
        Ok(self.curve.points_equal(&left_side, &right_side))
    }
}
