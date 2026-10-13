//! Port of `src/curve.ts` (`RailJubCurvePoint`) together with the
//! `@zk-kit/baby-jubjub` primitives it calls (`addPoint`, `mulPointEscalar`,
//! `inCurve`, `packPoint`, `unpackPoint`) and `@zk-kit/utils`' `F1Field`
//! comparison semantics.

use std::sync::OnceLock;

use blake_hash::Digest as BlakeDigest;
use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};

use crate::bytes::{
    bigint_to_buffer, le_bigint_to_buffer, le_bigint_to_buffer_min, le_buffer_to_bigint,
};
use crate::error::{Error, Result};
use crate::rng::Rng;

/// Affine point, the `Point<bigint>` tuple of the TypeScript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    /// x coordinate.
    pub x: BigInt,
    /// y coordinate.
    pub y: BigInt,
}

impl Point {
    /// Builds a point from its coordinates.
    pub fn new(x: BigInt, y: BigInt) -> Self {
        Point { x, y }
    }
}

fn big(s: &str) -> BigInt {
    s.parse().unwrap()
}

/// BabyJubJub base field prime (`r` in `@zk-kit/baby-jubjub`).
pub fn field_prime() -> &'static BigInt {
    static V: OnceLock<BigInt> = OnceLock::new();
    V.get_or_init(|| {
        big("21888242871839275222246405745257275088548364400416034343698204186575808495617")
    })
}

/// Full curve order (`order`), eight times the prime subgroup order.
pub fn curve_order() -> &'static BigInt {
    static V: OnceLock<BigInt> = OnceLock::new();
    V.get_or_init(|| {
        big("21888242871839275222246405745257275088614511777268538073601725287587578984328")
    })
}

/// Prime subgroup order (`subOrder`), written `l` in the RFC.
pub fn sub_order() -> &'static BigInt {
    static V: OnceLock<BigInt> = OnceLock::new();
    V.get_or_init(|| {
        big("2736030358979909402780800718157159386076813972158567259200215660948447373041")
    })
}

/// Curve coefficient `a`.
pub fn coeff_a() -> &'static BigInt {
    static V: OnceLock<BigInt> = OnceLock::new();
    V.get_or_init(|| BigInt::from(168700u32))
}

/// Curve coefficient `d`.
pub fn coeff_d() -> &'static BigInt {
    static V: OnceLock<BigInt> = OnceLock::new();
    V.get_or_init(|| BigInt::from(168696u32))
}

/// Subgroup generator (`Base8`).
pub fn base8() -> &'static Point {
    static V: OnceLock<Point> = OnceLock::new();
    V.get_or_init(|| {
        Point::new(
            big("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
            big("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
        )
    })
}

/// `RailJubCurvePoint` — BabyJubJub arithmetic and serialization.
#[derive(Clone, Debug, Default)]
pub struct Curve;

impl Curve {
    /// Creates the helper (stateless; the TypeScript class holds constants only).
    pub fn new() -> Self {
        Curve
    }

    // ---------------------------------------------------------------- constants

    /// `curveOrder`.
    pub fn curve_order(&self) -> &'static BigInt {
        curve_order()
    }

    /// `order` / `Order()` — the prime subgroup order.
    pub fn order(&self) -> &'static BigInt {
        sub_order()
    }

    /// `fieldPrime`.
    pub fn field_prime(&self) -> &'static BigInt {
        field_prime()
    }

    /// `generator`.
    pub fn generator(&self) -> &'static Point {
        base8()
    }

    /// `Identity()` — the neutral element `[0, 1]`.
    pub fn identity(&self) -> Point {
        Point::new(BigInt::zero(), BigInt::one())
    }

    // ------------------------------------------------------- field arithmetic

    /// `modP`.
    pub fn mod_p(&self, x: &BigInt) -> BigInt {
        let p = field_prime();
        let r = x % p;
        if r.is_negative() {
            r + p
        } else {
            r
        }
    }

    /// `modPInv`, `None` when the inverse does not exist.
    pub fn mod_p_inv(&self, a: &BigInt) -> Option<BigInt> {
        let p = field_prime();
        let (mut t, mut new_t) = (BigInt::zero(), BigInt::one());
        let (mut r, mut new_r) = (p.clone(), self.mod_p(a));
        while !new_r.is_zero() {
            let q = &r / &new_r;
            let tmp_t = t - &q * &new_t;
            t = std::mem::replace(&mut new_t, tmp_t);
            let tmp_r = r - &q * &new_r;
            r = std::mem::replace(&mut new_r, tmp_r);
        }
        if !r.is_one() {
            return None;
        }
        if t.is_negative() {
            t += p;
        }
        Some(t)
    }

    /// `modPPow`.
    pub fn mod_p_pow(&self, base: &BigInt, exp: &BigInt) -> BigInt {
        let p = field_prime();
        let mut result = BigInt::one();
        let mut b = self.mod_p(base);
        let mut e = exp.clone();
        while e.is_positive() {
            if (&e % 2u32).is_one() {
                result = (result * &b) % p;
            }
            e /= 2u32;
            b = (&b * &b) % p;
        }
        result
    }

    /// `legendreSymbol`.
    pub fn legendre_symbol(&self, a: &BigInt) -> BigInt {
        let p = field_prime();
        let ls = self.mod_p_pow(a, &((p - 1u32) / 2u32));
        if ls == p - 1u32 {
            BigInt::from(-1)
        } else {
            ls
        }
    }

    /// `modPSqrt` — `None` for non-residues (and for zero, like the source).
    pub fn mod_p_sqrt(&self, n: &BigInt) -> Option<BigInt> {
        if !self.legendre_symbol(n).is_one() {
            return None;
        }
        let p = field_prime();
        // p ≡ 1 (mod 4) for BN254, so this is always Tonelli-Shanks.
        if (p % 4u32) == BigInt::from(3u32) {
            return Some(self.mod_p_pow(n, &((p + 1u32) / 4u32)));
        }
        self.tonelli_shanks(n)
    }

    /// `tonelliShanks`, the private helper of `curve.ts`.
    pub fn tonelli_shanks(&self, n: &BigInt) -> Option<BigInt> {
        let p = field_prime();
        let mut q = p - 1u32;
        let mut s = 0u32;
        while (&q % 2u32).is_zero() {
            q /= 2u32;
            s += 1;
        }
        let mut z = BigInt::from(2u32);
        while self.legendre_symbol(&z) != BigInt::from(-1) {
            z += 1u32;
        }
        let mut m = s;
        let mut c = self.mod_p_pow(&z, &q);
        let mut t = self.mod_p_pow(n, &q);
        let mut r = self.mod_p_pow(n, &((&q + 1u32) / 2u32));
        loop {
            if t.is_zero() {
                return Some(BigInt::zero());
            }
            if t.is_one() {
                return Some(r);
            }
            let mut i = 1u32;
            let mut temp = (&t * &t) % p;
            while !temp.is_one() && i < m {
                temp = (&temp * &temp) % p;
                i += 1;
            }
            let exp = BigInt::one() << (m - i - 1);
            let b = self.mod_p_pow(&c, &exp);
            m = i;
            c = (&b * &b) % p;
            t = (&t * &c) % p;
            r = (&r * &b) % p;
        }
    }

    // ------------------------------------------------ group law (`@zk-kit`)

    /// `addPoint` of `@zk-kit/baby-jubjub`.
    pub fn add_point(&self, p1: &Point, p2: &Point) -> Point {
        let p = field_prime();
        let a = coeff_a();
        let d = coeff_d();
        let beta = (&p1.x * &p2.y) % p;
        let gamma = (&p1.y * &p2.x) % p;
        let delta = (self.f_sub(&p1.y, &((a * &p1.x) % p)) * self.f_add(&p2.x, &p2.y)) % p;
        let tau = (&beta * &gamma) % p;
        let dtau = (d * &tau) % p;
        let x3 = self.f_div(&self.f_add(&beta, &gamma), &self.f_add(&BigInt::one(), &dtau));
        let num_y = self.f_add(&delta, &self.f_sub(&((a * &beta) % p), &gamma));
        let y3 = self.f_div(&num_y, &self.f_sub(&BigInt::one(), &dtau));
        Point::new(x3, y3)
    }

    /// `mulPointEscalar` of `@zk-kit/baby-jubjub` (double-and-add, no reduction).
    pub fn mul_point_escalar(&self, base: &Point, e: &BigInt) -> Point {
        let mut res = self.identity();
        let mut rem = e.clone();
        let mut exp = base.clone();
        while !rem.is_zero() {
            if (&rem % 2u32).abs().is_one() {
                res = self.add_point(&res, &exp);
            }
            exp = self.add_point(&exp, &exp);
            rem >>= 1;
        }
        res
    }

    /// `inCurve` of `@zk-kit/baby-jubjub`.
    pub fn in_curve(&self, pt: &Point) -> bool {
        let p = field_prime();
        let x2 = (&pt.x * &pt.x) % p;
        let y2 = (&pt.y * &pt.y) % p;
        let lhs = self.f_add(&((coeff_a() * &x2) % p), &y2);
        let rhs = self.f_add(&BigInt::one(), &(((&x2 * &y2) % p * coeff_d()) % p));
        lhs == rhs
    }

    fn f_add(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let p = field_prime();
        let r = a + b;
        if &r >= p {
            r - p
        } else {
            r
        }
    }

    fn f_sub(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let p = field_prime();
        if a >= b {
            a - b
        } else {
            p - b + a
        }
    }

    fn f_div(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let p = field_prime();
        let inv = self.mod_p_inv(b).expect("Zero has no inverse");
        (a * inv) % p
    }

    /// `F1Field.lt(a, 0)` — the signed comparison used by `packPoint`.
    fn f_is_negative(&self, a: &BigInt) -> bool {
        let p = field_prime();
        let half = p >> 1;
        let aa = if a > &half { a - p } else { a.clone() };
        aa.is_negative()
    }

    fn f_neg(&self, a: &BigInt) -> BigInt {
        if a.is_zero() {
            BigInt::zero()
        } else {
            field_prime() - a
        }
    }

    // -------------------------------------------------- compression (curve.ts)

    /// `pointCompress` — `y | (sign(x) << 255)`.
    pub fn point_compress(&self, pt: &Point) -> BigInt {
        let sign = &pt.x & BigInt::one();
        &pt.y | (sign << 255)
    }

    /// `pointDecompress`.
    pub fn point_decompress(&self, s: &BigInt) -> Option<Point> {
        let sign = (s >> 255) & BigInt::one();
        let y = s & ((BigInt::one() << 255) - 1u32);
        let x = self.recover_x(&y, &sign)?;
        Some(Point::new(x, y))
    }

    /// `recoverX`.
    pub fn recover_x(&self, y: &BigInt, sign: &BigInt) -> Option<BigInt> {
        let a = coeff_a();
        let d = coeff_d();
        let y2 = self.mod_p(&(y * y));
        let u = self.mod_p(&(&y2 - 1u32));
        let v = self.mod_p(&(d * &y2 - a));
        let v_inv = self.mod_p_inv(&v)?;
        let x2 = self.mod_p(&(u * v_inv));
        let mut x = self.mod_p_sqrt(&x2)?;
        if &(&x & BigInt::one()) != sign {
            x = self.mod_p(&(-x));
        }
        Some(x)
    }

    // ------------------------------------------------------------- sampling

    /// `rejectionSampling` (appendix D.1/D.2).
    pub fn rejection_sampling(&self, rng: &mut dyn Rng) -> BigInt {
        loop {
            let mut bytes = rng.random_bytes(32);
            bytes[31] &= 0x1f;
            if let Ok(s) = self.deserialize_scalar(&bytes) {
                return s;
            }
        }
    }

    /// `wideBytes` — 48-byte wide reduction with bias rejection.
    pub fn wide_bytes(&self, rng: &mut dyn Rng) -> BigInt {
        let n_bytes = 48usize;
        let r = BigInt::one() << (n_bytes * 8);
        let limit = &r - (&r % self.order());
        loop {
            let bytes = rng.random_bytes(n_bytes);
            let x = le_buffer_to_bigint(&bytes);
            if x < limit {
                return x % self.order();
            }
        }
    }

    /// `RandomScalar`.
    pub fn random_scalar(&self, rng: &mut dyn Rng, rejection_sampling: bool) -> BigInt {
        if rejection_sampling {
            self.rejection_sampling(rng)
        } else {
            self.wide_bytes(rng)
        }
    }

    // ------------------------------------------------------------- scalar mult

    /// `ScalarBaseMult`.
    pub fn scalar_base_mult(&self, k: &BigInt) -> Point {
        self.mul_point_escalar(self.generator(), &self.mod_order(k))
    }

    /// `ScalarMult`.
    pub fn scalar_mult(&self, a: &Point, k: &BigInt) -> Point {
        self.mul_point_escalar(a, &self.mod_order(k))
    }

    // ---------------------------------------------------------- serialization

    /// `SerializeElement`.
    pub fn serialize_element(&self, a: &Point) -> Result<Vec<u8>> {
        if self.points_equal(a, &self.identity()) {
            return Err(Error::new("SerializeElement: input is group identity"));
        }
        let packed = self.point_compress(a);
        le_bigint_to_buffer(&packed, 32)
    }

    /// `DeserializeElement`.
    pub fn deserialize_element(&self, buf: &[u8]) -> Result<Point> {
        if buf.len() != 32 {
            return Err(Error::new("DeserializeElement: invalid length"));
        }
        let encoded = le_buffer_to_bigint(buf);
        let pt = self
            .point_decompress(&encoded)
            .ok_or_else(|| Error::new("DeserializeElement: invalid point encoding"))?;
        if self.points_equal(&pt, &self.identity()) {
            return Err(Error::new("DeserializeElement: point is identity"));
        }
        let check = self.mul_point_escalar(&pt, self.order());
        if !self.points_equal(&check, &self.identity()) {
            return Err(Error::new(
                "DeserializeElement: not in prime-order subgroup",
            ));
        }
        Ok(pt)
    }

    /// `SerializeScalar`.
    pub fn serialize_scalar(&self, s: &BigInt) -> Result<Vec<u8>> {
        if s.is_negative() || s >= self.order() {
            return Err(Error::new("SerializeScalar: scalar out of range"));
        }
        let mut out = self.to_bytes(s)?;
        out[31] &= 0x1f;
        Ok(out)
    }

    /// `DeserializeScalar`.
    pub fn deserialize_scalar(&self, buf: &[u8]) -> Result<BigInt> {
        if buf.len() != 32 {
            return Err(Error::new("DeserializeScalar: invalid length"));
        }
        if buf[31] & 0xe0 != 0 {
            return Err(Error::new("DeserializeScalar: top bits non-zero"));
        }
        let s = self.from_bytes(buf);
        if s.is_negative() || s >= *self.order() {
            return Err(Error::new("DeserializeScalar: scalar out of range"));
        }
        Ok(s)
    }

    /// `pointsEqual`.
    pub fn points_equal(&self, a: &Point, b: &Point) -> bool {
        a.x == b.x && a.y == b.y
    }

    /// `toBytes` — canonical 32-byte little-endian scalar encoding.
    pub fn to_bytes(&self, a: &BigInt) -> Result<Vec<u8>> {
        le_bigint_to_buffer(a, 32)
    }

    /// `fromBytes`.
    pub fn from_bytes(&self, a: &[u8]) -> BigInt {
        le_buffer_to_bigint(a)
    }

    /// `modCurveOrder`.
    pub fn mod_curve_order(&self, x: &BigInt) -> BigInt {
        let r = x % self.curve_order();
        if r.is_negative() {
            r + self.curve_order()
        } else {
            r
        }
    }

    /// `modOrder`.
    pub fn mod_order(&self, x: &BigInt) -> BigInt {
        let r = x % self.order();
        if r.is_negative() {
            r + self.order()
        } else {
            r
        }
    }

    /// `invModOrder`.
    pub fn inv_mod_order(&self, a: &BigInt) -> Result<BigInt> {
        let n = self.order();
        let (mut t, mut new_t) = (BigInt::zero(), BigInt::one());
        let (mut r, mut new_r) = (n.clone(), self.mod_order(a));
        while !new_r.is_zero() {
            let q = &r / &new_r;
            let tmp_t = t - &q * &new_t;
            t = std::mem::replace(&mut new_t, tmp_t);
            let tmp_r = r - &q * &new_r;
            r = std::mem::replace(&mut new_r, tmp_r);
        }
        if !r.is_one() {
            return Err(Error::new("inverse does not exist"));
        }
        if t.is_negative() {
            t += n;
        }
        Ok(t)
    }

    /// `pruneBuffer`.
    pub fn prune_buffer(&self, buff: &[u8]) -> Vec<u8> {
        let mut out = buff.to_vec();
        if out.is_empty() {
            return out;
        }
        out[0] &= 0xf8;
        let last = out.len() - 1;
        if last >= 31 {
            out[31] &= 0x7f;
            out[31] |= 0x40;
        }
        out
    }

    /// BLAKE-512 (the SHA-3 finalist), `blake512` of `@noble/hashes/blake1`.
    pub fn blake512(&self, m: &[u8]) -> Vec<u8> {
        blake_hash::Blake512::digest(m).to_vec()
    }

    /// `prvToSubScalar`.
    pub fn prv_to_sub_scalar(&self, prv: &[u8]) -> BigInt {
        let h64 = self.blake512(prv);
        let pr = self.prune_buffer(&h64);
        let s = le_buffer_to_bigint(&pr[..32]);
        s >> 3
    }

    /// `toMontgomery`.
    pub fn to_montgomery(&self, ed: &Point) -> Result<(BigInt, BigInt)> {
        if ed.x.is_zero() {
            return Err(Error::new("toMontgomery: x = 0 maps to v undefined"));
        }
        let den_u = self.mod_p(&(BigInt::one() - &ed.y));
        if den_u.is_zero() {
            return Err(Error::new(
                "toMontgomery: y = 1 (identity) not mappable",
            ));
        }
        let inv = self
            .mod_p_inv(&den_u)
            .ok_or_else(|| Error::new("toMontgomery: non invertible denominator"))?;
        let u = self.mod_p(&(self.mod_p(&(BigInt::one() + &ed.y)) * inv));
        let v = self.mod_p(&(&u * self.mod_p(&ed.x)));
        Ok((u, v))
    }

    // --------------------------------------------- zk-kit pack / unpack point

    /// `packPoint` of `@zk-kit/baby-jubjub` (sign = signed-`lt` on x).
    pub fn pack_point(&self, pt: &Point) -> Result<BigInt> {
        let mut buffer = le_bigint_to_buffer(&pt.y, 32)?;
        if self.f_is_negative(&pt.x) {
            buffer[31] |= 0x80;
        }
        Ok(le_buffer_to_bigint(&buffer))
    }

    /// `unpackPoint` of `@zk-kit/baby-jubjub`, quirks included: the buffer is
    /// minimal-length, so the sign bit is only read when the packed value
    /// actually reaches byte 31.
    pub fn unpack_point(&self, packed: &BigInt) -> Option<Point> {
        let mut buffer = le_bigint_to_buffer_min(packed);
        let mut sign = false;
        if buffer.len() > 31 && buffer[31] & 0x80 != 0 {
            sign = true;
            buffer[31] &= 0x7f;
        }
        let y = le_buffer_to_bigint(&buffer);
        if y > *field_prime() {
            return None;
        }
        let p = field_prime();
        let y2 = (&y * &y) % p;
        let num = self.f_sub(&BigInt::one(), &y2);
        let den = self.f_sub(coeff_a(), &((coeff_d() * &y2) % p));
        let arg = self.f_div(&num, &den);
        let mut x = self.zk_tonelli_shanks(&arg)?;
        if sign {
            x = self.f_neg(&x);
        }
        Some(Point::new(x, y))
    }

    /// `tonelliShanks` of `@zk-kit/baby-jubjub/sqrt`: returns the root that is
    /// non-negative under the signed comparison, `None` for non-residues.
    fn zk_tonelli_shanks(&self, n: &BigInt) -> Option<BigInt> {
        if n.is_zero() {
            return Some(BigInt::zero());
        }
        let x = self.mod_p_sqrt(n)?;
        Some(if self.f_is_negative(&x) {
            self.f_neg(&x)
        } else {
            x
        })
    }

    /// Minimal-length big-endian encoding, exposed for the harness.
    pub fn bigint_to_buffer(&self, v: &BigInt) -> Vec<u8> {
        bigint_to_buffer(v)
    }
}

/// Convenience: `Sign` re-export for callers building points from bytes.
pub use num_bigint::Sign as BigSign;
