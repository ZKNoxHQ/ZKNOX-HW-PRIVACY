//! Circom-compatible Poseidon over BN254 `Fr`, port of
//! `src/poseidon/poseidon-lite-wrapper.ts` (which wraps `poseidon-lite`).
//!
//! The round constants and MDS matrices are the binary parameter files shipped
//! by kohaku's `crates/poseidon-rust` (TACEO, MIT/Apache-2.0), each value a
//! 32-byte little-endian canonical field element. They are embedded verbatim,
//! so the parameters are literally kohaku's; only the permutation loop is
//! re-implemented here, in the unoptimized circomlib form, because that is the
//! one whose intermediate state matches `poseidon-lite`.
//!
//! `t` is the state width, arity + 1. Arities 1..=13 are available.

use std::sync::OnceLock;

use num_bigint::BigInt;
use num_traits::{One, Zero};

use crate::error::{Error, Result};

/// BN254 scalar field prime, the field Poseidon operates on.
pub fn field_prime() -> &'static BigInt {
    static P: OnceLock<BigInt> = OnceLock::new();
    P.get_or_init(|| {
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
            .parse()
            .unwrap()
    })
}

/// Number of full rounds, identical for every `t` in circomlib.
const ROUNDS_F: usize = 8;

struct Params {
    #[allow(dead_code)]
    t: usize,
    rounds: usize,
    mds: Vec<BigInt>,
    rc: Vec<BigInt>,
}

macro_rules! params_for {
    ($($t:literal),*) => {
        fn raw_params(t: usize) -> Option<(&'static [u8], &'static [u8])> {
            match t {
                $($t => Some((
                    include_bytes!(concat!("params/mds_t", stringify!($t), ".bin")),
                    include_bytes!(concat!("params/rc_t", stringify!($t), ".bin")),
                )),)*
                _ => None,
            }
        }
    };
}

params_for!(2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14);

fn decode(bin: &[u8]) -> Vec<BigInt> {
    bin.chunks_exact(32)
        .map(|c| BigInt::from_bytes_le(num_bigint::Sign::Plus, c))
        .collect()
}

fn params(t: usize) -> Result<&'static Params> {
    static CACHE: OnceLock<Vec<OnceLock<Option<Params>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| (0..=14).map(|_| OnceLock::new()).collect());
    if t > 14 {
        return Err(Error::new(
            "Poseidon function index must be between 1 and 16",
        ));
    }
    let slot = cache[t].get_or_init(|| {
        let (mds_bin, rc_bin) = raw_params(t)?;
        let mds = decode(mds_bin);
        let rc = decode(rc_bin);
        let rounds = rc.len() / t;
        Some(Params {
            t,
            rounds,
            mds,
            rc,
        })
    });
    slot.as_ref().ok_or_else(|| {
        Error::new("Poseidon function index must be between 1 and 16")
    })
}

fn pow5(x: &BigInt, p: &BigInt) -> BigInt {
    let x2 = (x * x) % p;
    let x4 = (&x2 * &x2) % p;
    (x4 * x) % p
}

/// Runs the permutation on a full state of width `t` and returns the state.
fn permute(state_in: &[BigInt]) -> Result<Vec<BigInt>> {
    let t = state_in.len();
    let pa = params(t)?;
    let p = field_prime();
    let rp = pa.rounds - ROUNDS_F;
    let mut state: Vec<BigInt> = state_in.to_vec();
    for r in 0..pa.rounds {
        for i in 0..t {
            state[i] = (&state[i] + &pa.rc[r * t + i]) % p;
        }
        if r < ROUNDS_F / 2 || r >= ROUNDS_F / 2 + rp {
            for s in state.iter_mut() {
                *s = pow5(s, p);
            }
        } else {
            state[0] = pow5(&state[0], p);
        }
        let mut next = Vec::with_capacity(t);
        for i in 0..t {
            let mut acc = BigInt::zero();
            for (j, sj) in state.iter().enumerate() {
                acc += &pa.mds[i * t + j] * sj;
            }
            next.push(acc % p);
        }
        state = next;
    }
    Ok(state)
}

/// Circom `poseidon(inputs)`: sponge state `[0, ...inputs]`, first output word.
///
/// Equivalent to `poseidonN(inputs)` from `poseidon-lite`.
pub fn poseidon(inputs: &[BigInt]) -> Result<BigInt> {
    Ok(poseidon_multi(inputs, 1)?.remove(0))
}

/// `poseidonN(inputs, nOuts)` — first `n_outs` words of the final state.
pub fn poseidon_multi(inputs: &[BigInt], n_outs: usize) -> Result<Vec<BigInt>> {
    if inputs.is_empty() || inputs.len() > 16 {
        return Err(Error::new(
            "Poseidon function index must be between 1 and 16",
        ));
    }
    let p = field_prime();
    let mut state = Vec::with_capacity(inputs.len() + 1);
    state.push(BigInt::zero());
    for i in inputs {
        let v = i % p;
        state.push(if v.sign() == num_bigint::Sign::Minus {
            v + p
        } else {
            v
        });
    }
    let out = permute(&state)?;
    if n_outs > out.len() {
        return Err(Error::new(format!(
            "Expected output to be an array of length {n_outs}"
        )));
    }
    Ok(out[..n_outs].to_vec())
}

/// `poseidon5(...)`, the arity used by the challenge hash `H2` and by
/// EdDSA-Poseidon.
pub fn poseidon5(a: &BigInt, b: &BigInt, c: &BigInt, d: &BigInt, e: &BigInt) -> BigInt {
    poseidon(&[a.clone(), b.clone(), c.clone(), d.clone(), e.clone()])
        .expect("poseidon5 parameters are always available")
}

/// Sanity helper: `1` as a field element (used by tests).
pub fn one() -> BigInt {
    BigInt::one()
}
