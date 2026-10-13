//! Port of `src/eddsa/babyposeidon.ts` (`EddsaPoseidon`).

use num_bigint::BigInt;

use crate::bytes::{bytes_to_bigint, le_bigint_to_buffer, le_buffer_to_bigint};
use crate::curve::{base8, sub_order, Curve, Point};
use crate::error::Result;
use crate::poseidon::poseidon5;

/// EdDSA-Poseidon signature `{ R8, S }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// `R8`.
    pub r8: Point,
    /// `S`.
    pub s: BigInt,
}

/// `EddsaPoseidon`, which extends the curve helper in the TypeScript.
#[derive(Clone, Debug, Default)]
pub struct EddsaPoseidon {
    /// Underlying curve helper (the TypeScript uses inheritance).
    pub curve: Curve,
}

impl EddsaPoseidon {
    /// Creates the helper.
    pub fn new() -> Self {
        EddsaPoseidon {
            curve: Curve::new(),
        }
    }

    /// `secretScalar` (private in the TypeScript).
    pub fn secret_scalar(&self, prv: &[u8]) -> BigInt {
        let h = self.curve.blake512(prv);
        let pruned = self.curve.prune_buffer(&h[..32]);
        le_buffer_to_bigint(&pruned) >> 3
    }

    /// `prv2pub`.
    pub fn prv2pub(&self, prv: &[u8]) -> Point {
        self.curve
            .mul_point_escalar(base8(), &self.secret_scalar(prv))
    }

    /// `signPoseidon`.
    pub fn sign_poseidon(&self, prv: &[u8], msg: &[u8]) -> Result<Signature> {
        let message = bytes_to_bigint(msg);
        let hash = self.curve.blake512(prv);
        let s = le_buffer_to_bigint(&self.curve.prune_buffer(&hash[..32]));
        let a = self.curve.mul_point_escalar(base8(), &(&s >> 3));

        let mut r_input = Vec::with_capacity(64);
        r_input.extend_from_slice(&hash[32..64]);
        r_input.extend_from_slice(&le_bigint_to_buffer(&message, 32)?);
        let r_bytes = self.curve.blake512(&r_input);
        let r = le_buffer_to_bigint(&r_bytes) % sub_order();
        let r8 = self.curve.mul_point_escalar(base8(), &r);

        let hm = poseidon5(&r8.x, &r8.y, &a.x, &a.y, &message);
        let s_sig = (&r + hm * &s) % sub_order();
        Ok(Signature { r8, s: s_sig })
    }

    /// `verifyPoseidon`.
    pub fn verify_poseidon(&self, msg: &[u8], sig: &Signature, a: &Point) -> bool {
        if !self.curve.in_curve(&sig.r8) || !self.curve.in_curve(a) || &sig.s >= sub_order() {
            return false;
        }
        let message = bytes_to_bigint(msg);
        let hm = poseidon5(&sig.r8.x, &sig.r8.y, &a.x, &a.y, &message);
        let p_left = self.curve.mul_point_escalar(base8(), &sig.s);
        let p_right = self.curve.add_point(
            &sig.r8,
            &self.curve.mul_point_escalar(a, &(hm * BigInt::from(8u32))),
        );
        p_left.x == p_right.x && p_left.y == p_right.y
    }

    /// `packPoint` — 32-byte big-endian encoding of the zk-kit packed value.
    pub fn pack_point(&self, point: &Point) -> Result<Vec<u8>> {
        let packed = self.curve.pack_point(point)?;
        crate::bytes::bigint_to_bytes(&packed, 32)
    }

    /// `unpackPoint`.
    pub fn unpack_point(&self, bytes_in: &[u8]) -> Option<Point> {
        let formatted = bytes_to_bigint(bytes_in);
        self.curve.unpack_point(&formatted)
    }
}
