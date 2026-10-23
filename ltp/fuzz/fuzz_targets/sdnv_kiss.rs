#![no_main]

use libfuzzer_sys::fuzz_target;

use hardy_ltp::{
    kiss::{decode_frame, encode_frame, escape, unescape},
    sdnv::{decode, encode_to_array, encoded_len},
};

fuzz_target!(|data: &[u8]| {
    // 1. SDNV variable-length integer decoding
    if let Ok((val, used)) = decode(data) {
        assert!(used <= data.len(), "used bytes cannot exceed input length");
        let (buf, enc_len) = encode_to_array(val);
        assert_eq!(enc_len, encoded_len(val));
        assert!(
            enc_len <= used,
            "canonical SDNV encoding exceeds accepted length"
        );
        let (re_val, re_used) =
            decode(&buf[..enc_len]).expect("re-decode of canonical SDNV failed");
        assert_eq!(re_val, val);
        assert_eq!(re_used, enc_len);
    }

    // 2. KISS escape / unescape roundtrip
    if let Ok(unescaped) = unescape(data) {
        let mut escaped = Vec::new();
        escape(&unescaped, &mut escaped);
        let re_unescaped = unescape(&escaped).expect("re-unescape of valid escape failed");
        assert_eq!(re_unescaped, unescaped);
    }

    // 3. KISS frame decoding and roundtrip
    if let Ok(Some((frame, used))) = decode_frame(data) {
        assert!(
            used <= data.len(),
            "consumed bytes cannot exceed buffer length"
        );
        let mut encoded = Vec::new();
        encode_frame(frame.port, frame.command, &frame.payload, &mut encoded);
        if let Ok(Some((redecoded, re_used))) = decode_frame(&encoded) {
            assert_eq!(re_used, encoded.len());
            assert_eq!(redecoded, frame);
        }
    }
});
