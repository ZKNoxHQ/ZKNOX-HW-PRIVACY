//! Rust port of `@railgun-reloaded/curves` (branch `zy0n/port-fixes`).
//!
//! Every public item mirrors a function of the TypeScript library, one for one,
//! with the JavaScript name given in the doc comment. Semantics are copied
//! including quirks (error strings, unreduced exponents, minimal-length
//! buffers), so that outputs are byte-identical and the two implementations can
//! be cross-checked case by case.
//!
//! Module map:
//!
//! | TypeScript                     | Rust              |
//! |--------------------------------|-------------------|
//! | `src/bytes.ts`                 | [`bytes`]         |
//! | `src/curve.ts`                 | [`curve`]         |
//! | `src/hashing.ts`               | [`hashing`]       |
//! | `src/poseidon/*`               | [`poseidon`]      |
//! | `src/eddsa/babyposeidon.ts`    | [`eddsa`]         |
//! | `src/frost/babyfrost.ts`       | [`frost`]         |
//! | `src/frost/trusted-dkg.ts`     | [`dkg`]           |
//! | `src/manager/key-agreement.ts` | [`key_agreement`] |
//! | `src/manager/participant.ts`   | [`participant`]   |
//! | `src/manager/ceremony.ts`      | [`ceremony`]      |
//! | `src/manager/dkg.ts` (DKG half)| [`manager`]       |
//! | `DKGSnapshot` of `manager/dkg.ts` | [`snapshot`]   |
//! | `src/manager/signing.ts`       | [`signing`]       |
//! | `src/module-index.ts` payloads | [`shareable`]     |
//!
//! The whole library is ported.

pub mod bytes;
pub mod ceremony;
pub mod curve;
pub mod dkg;
pub mod eddsa;
pub mod error;
pub mod frost;
pub mod hashing;
pub mod key_agreement;
pub mod manager;
pub mod participant;
pub mod poseidon;
pub mod rng;
pub mod shareable;
pub mod signing;
pub mod snapshot;

pub use curve::{Curve, Point};
pub use error::{Error, Result};
pub use rng::{Drbg, OsRng, Rng};

/// Signed big integer, used everywhere the TypeScript uses `bigint`.
pub type Big = num_bigint::BigInt;
