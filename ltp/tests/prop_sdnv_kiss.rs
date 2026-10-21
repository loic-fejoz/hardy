use std::vec;
use std::vec::Vec;

use proptest::collection::vec as prop_vec;
use proptest::prelude::*;

use hardy_ltp::{kiss, sdnv};

proptest! {
    // --- SDNV Invariants ---

    #[test]
    fn sdnv_roundtrip(v in any::<u64>()) {
        let mut buf = Vec::new();
        sdnv::encode(v, &mut buf);
        prop_assert_eq!(sdnv::decode(&buf), Ok((v, buf.len())));
    }

    #[test]
    fn sdnv_canonical_minimal(v in any::<u64>()) {
        let mut buf = Vec::new();
        sdnv::encode(v, &mut buf);
        prop_assert_eq!(buf.len(), sdnv::encoded_len(v));

        if buf.len() > 1 {
            prop_assert_ne!(buf[0], 0x80, "leading padding octet found in canonical encoding");
        }

        for (i, b) in buf.iter().enumerate() {
            prop_assert_eq!(b & 0x80 != 0, i + 1 < buf.len(), "continuation bit mismatch at index {}", i);
        }
    }

    #[test]
    fn sdnv_padded_decodes_identically(v in any::<u64>(), pad in 1_usize..=3) {
        let mut canonical = Vec::new();
        sdnv::encode(v, &mut canonical);

        if canonical.len() + pad <= sdnv::MAX_LEN {
            let mut padded = vec![0x80; pad];
            padded.extend_from_slice(&canonical);
            prop_assert_eq!(sdnv::decode(&padded), Ok((v, canonical.len() + pad)));
        }
    }

    #[test]
    fn sdnv_decode_never_panics(bytes in prop_vec(any::<u8>(), 0..32)) {
        let _ = sdnv::decode(&bytes);
    }

    // --- KISS Framing Invariants ---

    #[test]
    fn kiss_escape_unescape_roundtrip(data in prop_vec(any::<u8>(), 0..1024)) {
        let mut escaped = Vec::new();
        kiss::escape(&data, &mut escaped);

        prop_assert!(!escaped.contains(&kiss::FEND), "escaped data must not contain raw FEND");

        let unescaped = kiss::unescape(&escaped).expect("unescape must succeed on validly escaped data");
        prop_assert_eq!(unescaped, data);
    }

    #[test]
    fn kiss_frame_roundtrip(port in 0u8..16, payload in prop_vec(any::<u8>(), 0..512)) {
        let mut framed = Vec::new();
        kiss::encode_frame(port, kiss::Command::Data, &payload, &mut framed);

        let decoded = kiss::decode_frame(&framed)
            .expect("decode must succeed")
            .expect("frame must be present");

        prop_assert_eq!(decoded.0.port, port);
        prop_assert_eq!(decoded.0.command, kiss::Command::Data);
        prop_assert_eq!(decoded.0.payload, payload);
        prop_assert_eq!(decoded.1, framed.len());
    }

    #[test]
    fn kiss_decode_never_panics(bytes in prop_vec(any::<u8>(), 0..128)) {
        let _ = kiss::decode_frame(&bytes);
    }
}
