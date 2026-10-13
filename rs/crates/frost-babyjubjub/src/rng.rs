//! Randomness.
//!
//! The TypeScript calls `randomBytes` from `@noble/hashes` directly inside the
//! primitives; here every randomized function takes `&mut dyn Rng` so that the
//! cross-check harness can drive both implementations from the same stream.

use blake2::{Blake2b512, Digest};

/// Source of random bytes, mirroring `randomBytes(n)`.
pub trait Rng {
    /// Fills `out` with `out.len()` bytes.
    fn fill_bytes(&mut self, out: &mut [u8]);

    /// Returns `n` fresh bytes.
    fn random_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.fill_bytes(&mut v);
        v
    }
}

/// OS CSPRNG (`getrandom`). Panics if the OS source fails, like `randomBytes`.
pub struct OsRng;

impl Rng for OsRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        getrandom::getrandom(out).expect("OS randomness unavailable");
    }
}

/// Deterministic test DRBG, byte-identical to the JavaScript one in
/// `xcheck/drbg.mjs`.
///
/// For each request of `n` bytes it emits `ceil(n/64)` blocks
/// `BLAKE2b-512(seed || u64le(counter++))` and keeps the first `n` bytes; the
/// tail of the last block is discarded. Never use it outside tests.
pub struct Drbg {
    seed: [u8; 32],
    counter: u64,
}

impl Drbg {
    /// Creates a DRBG from a 32-byte seed.
    pub fn new(seed: [u8; 32]) -> Self {
        Drbg { seed, counter: 0 }
    }
}

impl Rng for Drbg {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            let mut h = Blake2b512::new();
            h.update(self.seed);
            h.update(self.counter.to_le_bytes());
            self.counter += 1;
            let block = h.finalize();
            let take = std::cmp::min(64, out.len() - done);
            out[done..done + take].copy_from_slice(&block[..take]);
            done += take;
        }
    }
}
