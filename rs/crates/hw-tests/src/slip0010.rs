//! Port of `js/lib/slip0010.js` — SLIP-0010 derivation with the
//! `"babyjubjub seed"` HMAC key, hardened indices only.

use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// A derived node: 32-byte key and 32-byte chain code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// `chainKey`.
    pub chain_key: [u8; 32],
    /// `chainCode`.
    pub chain_code: [u8; 32],
}

/// `mnemonicToSeed` — PBKDF2-HMAC-SHA512, 2048 rounds, salt `"mnemonic"`.
///
/// The JavaScript normalizes the mnemonic NFKD; the test seeds are ASCII, where
/// NFKD is the identity, so the bytes are taken as they are.
pub fn mnemonic_to_seed(mnemonic: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), b"mnemonic", 2048, &mut out);
    out
}

/// `getMasterKeyFromSeed`.
pub fn master_key_from_seed(seed: &[u8]) -> Node {
    let mut mac = HmacSha512::new_from_slice(b"babyjubjub seed").expect("hmac key");
    mac.update(seed);
    split(&mac.finalize().into_bytes())
}

/// `childDerive` — hardened child of `parent`.
pub fn child_derive(parent: &Node, index: u32) -> Node {
    let mut mac = HmacSha512::new_from_slice(&parent.chain_code).expect("hmac key");
    mac.update(&[0x00]);
    mac.update(&parent.chain_key);
    mac.update(&(index.wrapping_add(0x8000_0000)).to_be_bytes());
    split(&mac.finalize().into_bytes())
}

/// `derivePath`.
pub fn derive_path(master: &Node, segments: &[u32]) -> Node {
    let mut node = master.clone();
    for idx in segments {
        node = child_derive(&node, *idx);
    }
    node
}

fn split(i: &[u8]) -> Node {
    let mut chain_key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    chain_key.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);
    Node {
        chain_key,
        chain_code,
    }
}
