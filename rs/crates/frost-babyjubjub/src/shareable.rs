//! Port of the shareable-key half of `src/module-index.ts`: the hex-encoded
//! msgpack payloads a wallet passes around to share a viewing key, and the
//! multisig variant that carries the session metadata with it.
//!
//! The payload is a msgpack map with string keys in a fixed order, so the
//! bytes produced here are the ones `@msgpack/msgpack` produces from the same
//! object.

use num_bigint::BigInt;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bytes::{bigint_to_buffer, le_buffer_to_bigint};
use crate::curve::Point;
use crate::eddsa::{EddsaPoseidon, Signature};
use crate::error::{Error, Result};
use crate::key_agreement::{EngineEd25519KeyAgreement, KeyAgreement};
use crate::poseidon::poseidon_multi;
use crate::snapshot::{bytes_hex, parse_bytes_hex};

/// `DecodedShareableKey`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedShareableKey {
    /// `vpriv`.
    pub vpriv: String,
    /// `spub`.
    pub spub: String,
    /// `sid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// `sk`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sk: Option<String>,
    /// `pid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u64>,
}

/// `DecodedMultisigKey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedMultisigKey {
    /// `vpriv`.
    pub vpriv: Vec<u8>,
    /// `spub`.
    pub spub: Point,
    /// `sid`.
    pub sid: String,
    /// `sk`, `0x`-prefixed.
    pub sk: String,
    /// `pid`.
    pub pid: u64,
}

/// `normalizeHex`.
pub fn normalize_hex(value: &str, field: &str) -> Result<String> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::new(format!("Invalid {field}: expected hex string")));
    }
    if hex.is_empty() {
        return Err(Error::new(format!("Invalid {field}: empty hex string")));
    }
    Ok(if hex.len() % 2 == 0 {
        hex.to_string()
    } else {
        format!("0{hex}")
    })
}

/// `assertPrivateKeyLength`.
pub fn assert_private_key_length(key: &[u8], field: &str) -> Result<()> {
    if key.len() != 32 {
        return Err(Error::new(format!("Invalid {field} length")));
    }
    Ok(())
}

/// `poseidon` — inputs are little-endian field elements encoded as bytes, and
/// so is the digest.
///
/// The TypeScript reverses each input before handing it to `poseidon-lite`,
/// which reads a byte array big-endian, so the value hashed is the
/// little-endian reading of the input.
pub fn poseidon_bytes(inputs: &[Vec<u8>]) -> Result<Vec<u8>> {
    let big: Vec<BigInt> = inputs
        .iter()
        .map(|a| BigInt::from_bytes_le(num_bigint::Sign::Plus, a))
        .collect();
    let result = poseidon_multi(&big, 1)?.remove(0);
    let mut out = bigint_to_buffer(&result);
    out.reverse();
    Ok(out)
}

/// `poseidonHex` — inputs parsable by `BigInt` (decimal, or `0x` hex).
pub fn poseidon_hex(inputs: &[String]) -> Result<BigInt> {
    let mut parsed = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        let v = parse_js_bigint(input)
            .ok_or_else(|| Error::new(format!("Invalid Poseidon input at index {index}")))?;
        parsed.push(bigint_to_buffer(&v));
    }
    let result = poseidon_bytes(&parsed)?;
    // bytesToBigInt of the little-endian digest, as the TypeScript does
    Ok(BigInt::from_bytes_be(num_bigint::Sign::Plus, &result))
}

/// Parses the strings `BigInt()` accepts here: decimal or `0x` hexadecimal.
fn parse_js_bigint(s: &str) -> Option<BigInt> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        if hex.is_empty() {
            return None;
        }
        return BigInt::parse_bytes(hex.as_bytes(), 16);
    }
    if t.is_empty() {
        return Some(BigInt::zero());
    }
    BigInt::parse_bytes(t.as_bytes(), 10)
}

/// `getPublicSpendingKey`.
pub fn get_public_spending_key(private_key: &[u8]) -> Result<Point> {
    assert_private_key_length(private_key, "private key")?;
    Ok(EddsaPoseidon::new().prv2pub(private_key))
}

/// `getPublicViewingKey` — the Ed25519 public key of the viewing secret.
pub fn get_public_viewing_key(private_viewing_key: &[u8]) -> Result<Vec<u8>> {
    assert_private_key_length(private_viewing_key, "private viewing key")?;
    Ok(EngineEd25519KeyAgreement
        .public_key(private_viewing_key)?
        .to_vec())
}

/// `signEDDSA`.
pub fn sign_eddsa(private_key: &[u8], message: &BigInt) -> Result<Signature> {
    assert_private_key_length(private_key, "private key")?;
    EddsaPoseidon::new().sign_poseidon(private_key, &bigint_to_buffer(message))
}

/// `verifyEDDSA`.
pub fn verify_eddsa(message: &BigInt, signature: &Signature, pubkey: &Point) -> bool {
    EddsaPoseidon::new().verify_poseidon(&bigint_to_buffer(message), signature, pubkey)
}

fn spub_string(spending_public_key: &Point) -> Result<String> {
    let eddsa = EddsaPoseidon::new();
    let packed = eddsa.pack_point(spending_public_key)?;
    Ok(format!("{:0>64x}", le_buffer_to_bigint(&packed)))
}

fn encode_map(data: &DecodedShareableKey) -> Result<String> {
    let mut buf = Vec::new();
    let mut ser = rmp_serde::Serializer::new(&mut buf)
        .with_struct_map()
        .with_bytes(rmp_serde::config::BytesMode::ForceIterables);
    data.serialize(&mut ser)
        .map_err(|e| Error::new(format!("msgpack encode failed: {e}")))?;
    Ok(bytes_hex(&buf))
}

/// `getShareableViewingKey`.
pub fn get_shareable_viewing_key(
    spending_public_key: &Point,
    viewing_private_key: &[u8],
) -> Result<String> {
    assert_private_key_length(viewing_private_key, "viewing private key")?;
    let mut reversed = viewing_private_key.to_vec();
    reversed.reverse();
    encode_map(&DecodedShareableKey {
        vpriv: format!("{:0>64x}", le_buffer_to_bigint(&reversed)),
        spub: spub_string(spending_public_key)?,
        sid: None,
        sk: None,
        pid: None,
    })
}

/// `getShareableMultisigKey`.
pub fn get_shareable_multisig_key(
    spending_public_key: &Point,
    viewing_private_key: &[u8],
    session_id: &str,
    symmetric_key: &str,
    participant_id: i64,
) -> Result<String> {
    assert_private_key_length(viewing_private_key, "viewing private key")?;
    let spub = spub_string(spending_public_key)?;
    let formatted_symmetric_key = symmetric_key.strip_prefix("0x").unwrap_or(symmetric_key);
    if session_id.is_empty() {
        return Err(Error::new("Invalid sessionID"));
    }
    if participant_id <= 0 {
        return Err(Error::new("Invalid participantId"));
    }
    let mut reversed = viewing_private_key.to_vec();
    reversed.reverse();
    encode_map(&DecodedShareableKey {
        vpriv: format!("{:0>64x}", le_buffer_to_bigint(&reversed)),
        spub,
        sid: Some(session_id.to_string()),
        sk: Some(formatted_symmetric_key.to_string()),
        pid: Some(participant_id as u64),
    })
}

/// `decodeShareableKey`.
pub fn decode_shareable_key(shareable_key: &str) -> Result<DecodedShareableKey> {
    let normalized = normalize_hex(shareable_key, "shareable key")?;
    let buf = parse_bytes_hex(&normalized)?;
    let raw: Value = rmp_serde::from_slice(&buf)
        .map_err(|_| Error::new("Invalid shareable key payload"))?;
    let map = raw
        .as_object()
        .ok_or_else(|| Error::new("Invalid shareable key payload"))?;

    let vpriv = map.get("vpriv").and_then(|v| v.as_str());
    let spub = map.get("spub").and_then(|v| v.as_str());
    let (vpriv, spub) = match (vpriv, spub) {
        (Some(a), Some(b)) => (a.to_string(), b.to_string()),
        _ => return Err(Error::new("Invalid shareable key payload")),
    };

    let sid = match map.get("sid") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(Error::new("Invalid shareable key session id")),
    };
    let sk = match map.get("sk") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(Error::new("Invalid shareable key symmetric key")),
    };
    let pid = match map.get("pid") {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => {
            let v = n
                .as_u64()
                .ok_or_else(|| Error::new("Invalid shareable key participant id"))?;
            if v == 0 || !n.is_u64() {
                return Err(Error::new("Invalid shareable key participant id"));
            }
            Some(v)
        }
        Some(_) => return Err(Error::new("Invalid shareable key participant id")),
    };

    Ok(DecodedShareableKey {
        vpriv,
        spub,
        sid,
        sk,
        pid,
    })
}

/// `decodeMultisigKey`.
pub fn decode_multisig_key(multisig_shareable_key: &str) -> Result<DecodedMultisigKey> {
    let decoded = decode_shareable_key(multisig_shareable_key)?;
    let (sid, sk, pid) = match (&decoded.sid, &decoded.sk, decoded.pid) {
        (Some(sid), Some(sk), Some(pid)) => (sid.clone(), sk.clone(), pid),
        _ => return Err(Error::new("Invalid multisig shareable key payload")),
    };
    let eddsa = EddsaPoseidon::new();
    let spub_hex = normalize_hex(&decoded.spub, "spending public key")?;
    let spub_value = BigInt::parse_bytes(spub_hex.as_bytes(), 16)
        .ok_or_else(|| Error::new("Invalid spending public key: expected hex string"))?;
    let spub_bytes = eddsa.curve.to_bytes(&spub_value)?;
    let unpacked = eddsa
        .unpack_point(&spub_bytes)
        .ok_or_else(|| Error::new("Invalid multisig shareable key public key"))?;
    Ok(DecodedMultisigKey {
        vpriv: parse_bytes_hex(&normalize_hex(&decoded.vpriv, "viewing private key")?)?,
        spub: unpacked,
        sid,
        sk: format!("0x{sk}"),
        pid,
    })
}
