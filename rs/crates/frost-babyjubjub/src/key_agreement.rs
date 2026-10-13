//! Port of `src/manager/key-agreement.ts`.
//!
//! Two participants turn their announced communication keys into the 32-byte
//! AES-256-GCM key that protects a share in transit. The DKG does not care
//! which scheme is used as long as every participant of a ceremony uses the
//! same one, so the scheme identifier travels with the session.

use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};

/// `KeyAgreement`.
pub trait KeyAgreement {
    /// `scheme` — stable identifier recorded in snapshots.
    fn scheme(&self) -> &'static str;

    /// `getPublicKey`.
    fn public_key(&self, secret_key: &[u8]) -> Result<[u8; 32]>;

    /// `getSharedSecret`.
    fn shared_secret(&self, secret_key: &[u8], their_pub: &[u8]) -> Result<[u8; 32]>;
}

fn sk32(secret_key: &[u8]) -> Result<[u8; 32]> {
    if secret_key.len() != 32 {
        return Err(Error::new("bad secret key length"));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(secret_key);
    Ok(s)
}

fn pk32(their_pub: &[u8]) -> Result<[u8; 32]> {
    if their_pub.len() != 32 {
        return Err(Error::new("bad public key length"));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(their_pub);
    Ok(s)
}

/// `X25519KeyAgreement` — raw X25519 shared point, used directly as the key.
#[derive(Clone, Copy, Debug, Default)]
pub struct X25519KeyAgreement;

impl KeyAgreement for X25519KeyAgreement {
    fn scheme(&self) -> &'static str {
        "x25519"
    }

    fn public_key(&self, secret_key: &[u8]) -> Result<[u8; 32]> {
        Ok(X25519_BASEPOINT.mul_clamped(sk32(secret_key)?).to_bytes())
    }

    fn shared_secret(&self, secret_key: &[u8], their_pub: &[u8]) -> Result<[u8; 32]> {
        Ok(MontgomeryPoint(pk32(their_pub)?)
            .mul_clamped(sk32(secret_key)?)
            .to_bytes())
    }
}

/// `EngineEd25519KeyAgreement` — the scheme the RAILGUN engine uses between
/// wallets (`getSharedSymmetricKey`): SHA-256 of the compressed point `[s]·P`,
/// with `s` the clamped Ed25519 scalar of our secret key.
#[derive(Clone, Copy, Debug, Default)]
pub struct EngineEd25519KeyAgreement;

impl EngineEd25519KeyAgreement {
    /// Engine `getPrivateScalarFromPrivateKey`.
    pub fn private_scalar(secret_key: &[u8]) -> Result<Scalar> {
        let sk = sk32(secret_key)?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&Sha512::digest(sk)[..32]);
        h[0] &= 248;
        h[31] &= 127;
        h[31] |= 64;
        Ok(Scalar::from_bytes_mod_order(h))
    }
}

impl KeyAgreement for EngineEd25519KeyAgreement {
    fn scheme(&self) -> &'static str {
        "railgun-engine-ed25519-sha256"
    }

    fn public_key(&self, secret_key: &[u8]) -> Result<[u8; 32]> {
        let sk = sk32(secret_key)?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&Sha512::digest(sk)[..32]);
        Ok(curve25519_dalek::EdwardsPoint::mul_base_clamped(h)
            .compress()
            .to_bytes())
    }

    fn shared_secret(&self, secret_key: &[u8], their_pub: &[u8]) -> Result<[u8; 32]> {
        let s = Self::private_scalar(secret_key)?;
        let point = CompressedEdwardsY(pk32(their_pub)?)
            .decompress()
            .ok_or_else(|| Error::new("bad public key"))?;
        let shared = point * s;
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(shared.compress().to_bytes()));
        Ok(out)
    }
}

/// `keyAgreementFromScheme`.
pub fn key_agreement_from_scheme(scheme: &str) -> Result<Box<dyn KeyAgreement>> {
    match scheme {
        "x25519" => Ok(Box::new(X25519KeyAgreement)),
        "railgun-engine-ed25519-sha256" => Ok(Box::new(EngineEd25519KeyAgreement)),
        other => Err(Error::new(format!("unknown key agreement scheme: {other}"))),
    }
}
