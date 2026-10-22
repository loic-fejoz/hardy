#![no_main]

use libfuzzer_sys::fuzz_target;

use hardy_ltp::segment::Segment;

fuzz_target!(|data: &[u8]| {
    if let Ok((seg, used)) = Segment::parse(data) {
        assert!(used <= data.len(), "used bytes cannot exceed input length");
        let encoded = seg.encode_to_vec();
        assert!(
            encoded.len() <= used,
            "canonical encoding longer than accepted wire bytes"
        );
        let (reparsed, reused) = Segment::parse(&encoded).expect("re-parse of own encoding failed");
        assert_eq!(
            reused,
            encoded.len(),
            "re-parse did not consume exact encoded bytes"
        );
        assert_eq!(reparsed, seg, "decode/encode/decode is not a fixed point");
    }
});
