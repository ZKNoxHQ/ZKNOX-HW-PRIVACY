//! Port of `src/hashing.ts` (`RFC9591Hasher`).
//!
//! The default base hash is BLAKE-512 (the SHA-3 finalist), matching the
//! GitLab source after `fix/blake512-hasher`. BLAKE2b-512, the hash the older
//! GitHub branch used, stays available through [`HashKind::Blake2b512`].

use blake2::{Blake2b512, Digest as Blake2Digest};
use blake_hash::Digest as BlakeDigest;
use num_bigint::BigInt;
use num_traits::Signed;

use crate::bytes::le_buffer_to_bigint;
use crate::curve::Point;
use crate::poseidon::poseidon5;

/// Base hash used before scalar reduction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashKind {
    /// `blake2b(m, { dkLen: 64 })` — the pre-`fix/blake512-hasher` default.
    Blake2b512,
    /// BLAKE-512, the SHA-3 finalist: the current default.
    Blake512,
}

impl HashKind {
    /// Applies the hash.
    pub fn hash(&self, m: &[u8]) -> Vec<u8> {
        match self {
            HashKind::Blake2b512 => Blake2b512::digest(m).to_vec(),
            HashKind::Blake512 => blake_hash::Blake512::digest(m).to_vec(),
        }
    }
}

/// `RFC9591Hasher` — domain-separated hashes `H1`..`H7`.
#[derive(Clone, Debug)]
pub struct Rfc9591Hasher {
    /// `contextString`.
    pub context_string: String,
    order: BigInt,
    hash_fn: HashKind,
}

impl Rfc9591Hasher {
    /// `new RFC9591Hasher(contextString, order)`.
    pub fn new(context_string: impl Into<String>, order: BigInt) -> Self {
        Self::with_hash(context_string, order, HashKind::Blake512)
    }

    /// Same, with an explicit base hash.
    pub fn with_hash(context_string: impl Into<String>, order: BigInt, hash_fn: HashKind) -> Self {
        Rfc9591Hasher {
            context_string: context_string.into(),
            order,
            hash_fn,
        }
    }

    /// `mod`.
    pub fn r#mod(&self, x: &BigInt) -> BigInt {
        let r = x % &self.order;
        if r.is_negative() {
            r + &self.order
        } else {
            r
        }
    }

    /// `Hash`.
    pub fn hash(&self, m: &[u8]) -> Vec<u8> {
        self.hash_fn.hash(m)
    }

    /// `taggedHash`.
    pub fn tagged_hash(&self, tag: &str, input: &[u8]) -> Vec<u8> {
        let mut combined =
            Vec::with_capacity(self.context_string.len() + tag.len() + input.len());
        combined.extend_from_slice(self.context_string.as_bytes());
        combined.extend_from_slice(tag.as_bytes());
        combined.extend_from_slice(input);
        self.hash(&combined)
    }

    /// `deriveHashed`.
    pub fn derive_hashed(&self, tag: &str, input: &[u8]) -> BigInt {
        let digest = self.tagged_hash(tag, input);
        // The TypeScript round-trips the digest through a 64-byte LE buffer,
        // which is the identity for a 64-byte digest.
        self.r#mod(&le_buffer_to_bigint(&digest))
    }

    /// `H1` — binding factor (`rho`).
    pub fn h1(&self, m: &[u8]) -> BigInt {
        self.derive_hashed("rho", m)
    }

    /// `H2` — challenge, Poseidon so that the aggregate verifies as EdDSA.
    pub fn h2(&self, r8: &Point, a: &Point, msg_hash: &BigInt) -> BigInt {
        self.r#mod(&poseidon5(&r8.x, &r8.y, &a.x, &a.y, msg_hash))
    }

    /// `H3` — nonce.
    pub fn h3(&self, m: &[u8]) -> BigInt {
        self.derive_hashed("nonce", m)
    }

    /// `H4` — message.
    pub fn h4(&self, m: &[u8]) -> BigInt {
        self.derive_hashed("msg", m)
    }

    /// `H5` — commitment list digest.
    pub fn h5(&self, m: &[u8]) -> BigInt {
        self.derive_hashed("com", m)
    }

    /// `H6` — coefficient domain.
    pub fn h6(&self, m: &[u8]) -> BigInt {
        self.derive_hashed("coeff", m)
    }

    /// `H7` — viewing key derivation.
    pub fn h7(&self, m: &[u8]) -> BigInt {
        self.derive_hashed("view", m)
    }
}
