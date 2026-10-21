//! SDNV (Self-Delimiting Numeric Value) codec — RFC 5326 §2, item 20.
//!
//! Big-endian base-128: 7 bits of value per octet, MSB-first. The most
//! significant bit (bit 7, `0x80`) indicates continuation on all octets
//! except the terminal octet (`0x00`).
//!
//! Following RFC 5326 and CCSDS recommendations, values up to `u64::MAX` are
//! supported in at most [`MAX_LEN`] (10) octets.

use alloc::vec::Vec;

use thiserror::Error;

/// Maximum accepted SDNV length in octets.
///
/// Any `u64` fits in at most 10 octets (⌈64 / 7⌉ = 10).
pub const MAX_LEN: usize = 10;

/// Specialized Result for SDNV operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur during SDNV decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Error {
    /// Input ended before encountering an octet with the continuation bit cleared.
    #[error("SDNV input truncated before terminal octet")]
    Truncated,

    /// Decoded value exceeds `u64::MAX` or the encoding exceeds [`MAX_LEN`] octets.
    #[error("SDNV value exceeds u64 or maximum length limit")]
    Overflow,
}

/// Computes the number of octets required for the canonical encoding of `v`.
///
/// Returns a value in `1..=10`.
#[must_use]
pub fn encoded_len(v: u64) -> usize {
    let bits = 64 - (v | 1).leading_zeros() as usize;
    bits.div_ceil(7)
}

/// Encodes `v` into a stack-allocated buffer without any heap allocations.
///
/// Returns the fixed array and the exact number of bytes written (`1..=10`).
#[must_use]
pub fn encode_to_array(v: u64) -> ([u8; MAX_LEN], usize) {
    let n = encoded_len(v);
    let mut out = [0u8; MAX_LEN];
    for (i, slot) in out[..n].iter_mut().enumerate() {
        let shift = 7 * (n - 1 - i);
        let group = ((v >> shift) & 0x7F) as u8;
        let cont = if i + 1 == n { 0x00 } else { 0x80 };
        *slot = cont | group;
    }
    (out, n)
}

/// Appends the canonical (minimal) SDNV encoding of `v` to `out`.
pub fn encode(v: u64, out: &mut Vec<u8>) {
    let (buf, n) = encode_to_array(v);
    out.extend_from_slice(&buf[..n]);
}

/// Decodes one SDNV from the start of `input`.
///
/// Returns `(value, octets_consumed)`. Accepts non-canonical leading `0x80`
/// padding within the [`MAX_LEN`] cap.
///
/// # Errors
///
/// Returns [`Error::Truncated`] if `input` ends before the terminal octet.
/// Returns [`Error::Overflow`] if the value exceeds `u64` or requires more
/// than [`MAX_LEN`] octets.
pub fn decode(input: &[u8]) -> Result<(u64, usize)> {
    let mut acc: u64 = 0;
    for (i, &b) in input.iter().enumerate() {
        if i == MAX_LEN {
            return Err(Error::Overflow);
        }
        if acc >> 57 != 0 {
            return Err(Error::Overflow);
        }
        acc = (acc << 7) | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            return Ok((acc, i + 1));
        }
    }
    if input.len() >= MAX_LEN {
        Err(Error::Overflow)
    } else {
        Err(Error::Truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode(v, &mut out);
        out
    }

    #[test]
    fn rfc_worked_example() {
        // RFC 5326 §2: 0x1234 -> 10100100 00110100 = 0xA4 0x34.
        assert_eq!(enc(0x1234), [0xA4, 0x34]);
        assert_eq!(decode(&[0xA4, 0x34]), Ok((0x1234, 2)));
    }

    #[test]
    fn boundary_values() {
        assert_eq!(enc(0), [0x00]);
        assert_eq!(enc(127), [0x7F]);
        assert_eq!(enc(128), [0x81, 0x00]);
        assert_eq!(enc(16_383), [0xFF, 0x7F]);
        assert_eq!(enc(16_384), [0x81, 0x80, 0x00]);

        let max = enc(u64::MAX);
        assert_eq!(max.len(), 10);
        assert_eq!(max[0], 0x81);
        assert!(max[1..9].iter().all(|&b| b == 0xFF));
        assert_eq!(max[9], 0x7F);
        assert_eq!(decode(&max), Ok((u64::MAX, 10)));
    }

    #[test]
    fn encoded_len_consistency() {
        for v in [0, 1, 127, 128, 16_383, 16_384, 0x1234, u64::MAX, 1 << 62] {
            assert_eq!(encoded_len(v), enc(v).len());
        }
    }

    #[test]
    fn decode_prefix_only() {
        assert_eq!(decode(&[0x7F, 0xAA, 0xBB]), Ok((127, 1)));
    }

    #[test]
    fn non_canonical_padding() {
        assert_eq!(decode(&[0x80, 0x80, 0x01]), Ok((1, 3)));

        let mut padded = alloc::vec![0x80; 9];
        padded.push(0x01);
        assert_eq!(decode(&padded), Ok((1, 10)));
    }

    #[test]
    fn reject_over_ten_octets() {
        let mut long = alloc::vec![0x80; 10];
        long.push(0x01);
        assert_eq!(decode(&long), Err(Error::Overflow));
    }

    #[test]
    fn reject_u64_overflow() {
        let mut over = alloc::vec![0x82];
        over.extend_from_slice(&[0x80; 8]);
        over.push(0x00);
        assert_eq!(decode(&over), Err(Error::Overflow));
    }

    #[test]
    fn truncated_inputs() {
        assert_eq!(decode(&[]), Err(Error::Truncated));
        assert_eq!(decode(&[0x80]), Err(Error::Truncated));
        assert_eq!(decode(&[0xA4]), Err(Error::Truncated));
    }
}
