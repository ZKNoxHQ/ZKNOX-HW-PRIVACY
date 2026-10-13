//! Port of `js/lib/hex.js`.

/// `hex2buf`.
pub fn hex2buf(h: &str) -> Vec<u8> {
    let h = h.trim();
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

/// `buf2hex` / `toHex`.
pub fn buf2hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `reverse`.
pub fn reverse(b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    v.reverse();
    v
}

/// `nToHex`.
pub fn n_to_hex(n: &num_bigint::BigUint, byte_len: usize) -> String {
    format!("{:0>width$x}", n, width = byte_len * 2)
}
