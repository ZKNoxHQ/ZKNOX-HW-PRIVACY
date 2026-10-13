//! Host-side cryptographic reference, replacing the `circomlibjs` oracle of
//! `js/test/sign.test.js`.
//!
//! The JavaScript computes `eddsa.signPoseidon(prv, F.toMontgomery(msg))` and
//! reads the result back out of Montgomery form. Stripped of the
//! representation shuffling, that is: take the 32 message bytes as a
//! little-endian field element, run circomlib EdDSA-Poseidon, and report the
//! signature as big-endian words — which is the layout the device returns. The
//! port here does exactly that, on top of the `frost-babyjubjub` crate whose
//! EdDSA-Poseidon is itself cross-checked against circomlib.

use frost_babyjubjub::bytes::{bigint_to_bytes, le_buffer_to_bigint};
use frost_babyjubjub::curve::Curve;
use frost_babyjubjub::eddsa::EddsaPoseidon;
use frost_babyjubjub::key_agreement::{EngineEd25519KeyAgreement, KeyAgreement};

use crate::hex::buf2hex;
use crate::slip0010::{derive_path, master_key_from_seed, mnemonic_to_seed, Node};

/// A signature in the device's wire layout: three 32-byte big-endian words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigHex {
    /// `R8.x`.
    pub r8x: String,
    /// `R8.y`.
    pub r8y: String,
    /// `S`.
    pub s: String,
}

impl SigHex {
    /// Reads the device's 96-byte response into the same shape.
    pub fn from_response(resp: &[u8]) -> Self {
        assert_eq!(resp.len(), 96, "expected 96-byte signature");
        SigHex {
            r8x: buf2hex(&resp[0..32]),
            r8y: buf2hex(&resp[32..64]),
            s: buf2hex(&resp[64..96]),
        }
    }
}

/// The `circomlibRef` of `sign.test.js`.
///
/// `F.toMontgomery(msg)` reads the 32 bytes as a little-endian field element
/// and reduces them modulo the BabyJubJub base prime, and it is that reduced
/// value circomlib both hashes into the nonce and feeds to Poseidon. Messages
/// at or above the prime therefore sign as their residue — the suite's own
/// message is below it, but the random oracle vectors are not, which is how
/// the reduction got noticed.
pub fn circomlib_ref(priv_bytes: &[u8], msg: &[u8]) -> SigHex {
    let eddsa = EddsaPoseidon::new();
    let reduced = Curve::new().mod_p(&le_buffer_to_bigint(msg));
    // sign_poseidon reads its message big-endian.
    let msg_be = bigint_to_bytes(&reduced, 32).expect("message fits 32 bytes");
    let sig = eddsa
        .sign_poseidon(priv_bytes, &msg_be)
        .expect("sign_poseidon");
    SigHex {
        r8x: buf2hex(&bigint_to_bytes(&sig.r8.x, 32).expect("R8.x")),
        r8y: buf2hex(&bigint_to_bytes(&sig.r8.y, 32).expect("R8.y")),
        s: buf2hex(&bigint_to_bytes(&sig.s, 32).expect("S")),
    }
}

/// `PATH_SPENDING` — m/44'/1984'/account'/0'/0', all hardened.
pub fn path_spending(account: u32) -> [u32; 5] {
    [44, 1984, account, 0, 0]
}

/// The private spending key the app derives for `account`, computed host-side
/// from the mnemonic exactly as `sign.test.js` does.
pub fn derived_spending_key(mnemonic: &str, account: u32) -> [u8; 32] {
    derived_spending_key_from_seed(&mnemonic_to_seed(mnemonic), account)
}

/// [`derived_spending_key`] from a 64-byte BIP39 seed, for the suites that
/// move the device off its mnemonic.
pub fn derived_spending_key_from_seed(seed: &[u8], account: u32) -> [u8; 32] {
    let master: Node = master_key_from_seed(seed);
    derive_path(&master, &path_spending(account)).chain_key
}

/// `PATH_DKG_COMM` — m/421'/1984'/account'/0'/0', all hardened.
///
/// `src/zknox/src/keys/zkn_keyderivation.c` keeps this branch for
/// `KEY_TYPE_DKG_COMM`: the DKG transport identity, an Ed25519 key that is
/// never exported as a secret. 421 is the purpose the firmware reserves for
/// it, 1984 the RAILGUN coin type.
pub fn path_dkg_comm(account: u32) -> [u32; 5] {
    [421, 1984, account, 0, 0]
}

/// The DKG transport public key `DKG_GET_COMM_PUBKEY` (0x60) returns, computed
/// host-side from a 64-byte BIP39 seed.
///
/// SLIP-0010 down [`path_dkg_comm`], then the Ed25519 public key of the node's
/// chain key — `SHA-512`, clamp, multiply the base point, compress — which is
/// what the firmware's `derive_pubkey_ed25519` does. Deriving it here is what
/// lets a ceremony check the announced key rather than trust it: the self-HK
/// test in `handler_dkg.c` is the device's own defence against a swapped
/// transport key, and this is the host's.
pub fn dkg_comm_pubkey_from_seed(seed: &[u8], account: u32) -> [u8; 32] {
    let master: Node = master_key_from_seed(seed);
    let node = derive_path(&master, &path_dkg_comm(account));
    EngineEd25519KeyAgreement
        .public_key(&node.chain_key)
        .expect("32-byte chain key")
}

/// [`dkg_comm_pubkey_from_seed`] from a mnemonic.
pub fn dkg_comm_pubkey(mnemonic: &str, account: u32) -> [u8; 32] {
    dkg_comm_pubkey_from_seed(&mnemonic_to_seed(mnemonic), account)
}
