//! Port of `src/bytes.ts` plus the two `@railgun-reloaded/bytes` primitives it
//! builds on (`bytesToBigInt`, `bigIntToBytes`).

use num_bigint::{BigInt, Sign};
use num_traits::Zero;

use crate::error::{Error, Result};

/// `bytesToBigInt` — big-endian decode.
pub fn bytes_to_bigint(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, bytes)
}

/// `bigIntToBytes(value, byteLength)` — fixed-length big-endian encode.
///
/// Errors exactly where the TypeScript throws: negative value, or a value that
/// does not fit in `byte_length` bytes.
pub fn bigint_to_bytes(value: &BigInt, byte_length: usize) -> Result<Vec<u8>> {
    if value.sign() == Sign::Minus {
        return Err(Error::new(
            "bigIntToBytes: negative values are not supported",
        ));
    }
    let mut out = vec![0u8; byte_length];
    if value.is_zero() {
        return Ok(out);
    }
    let be = value.to_bytes_be().1;
    if be.len() > byte_length {
        return Err(Error::new(format!(
            "bigIntToBytes: value does not fit in {byte_length} bytes"
        )));
    }
    out[byte_length - be.len()..].copy_from_slice(&be);
    Ok(out)
}

/// `leBufferToBigInt` — little-endian decode.
pub fn le_buffer_to_bigint(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, bytes)
}

/// `leBigIntToBuffer(value, size)` — fixed-length little-endian encode.
pub fn le_bigint_to_buffer(value: &BigInt, size: usize) -> Result<Vec<u8>> {
    let mut v = bigint_to_bytes(value, size)?;
    v.reverse();
    Ok(v)
}

/// `bigIntToBuffer` — minimal-length big-endian encode (at least one byte).
pub fn bigint_to_buffer(value: &BigInt) -> Vec<u8> {
    let mut hex = format!("{:x}", value);
    if hex.len() % 2 == 1 {
        hex.insert(0, '0');
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let raw = hex.as_bytes();
    for i in 0..hex.len() / 2 {
        let h = (raw[2 * i] as char).to_digit(16).unwrap_or(0) as u8;
        let l = (raw[2 * i + 1] as char).to_digit(16).unwrap_or(0) as u8;
        out.push((h << 4) | l);
    }
    out
}

/// `leBigIntToBuffer(value)` with no size — minimal-length little-endian
/// encode, as used by `@zk-kit/baby-jubjub`'s `unpackPoint`.
pub fn le_bigint_to_buffer_min(value: &BigInt) -> Vec<u8> {
    let mut v = bigint_to_buffer(value);
    v.reverse();
    v
}
