//! Fuzz testing helper harness for the HQFBP Convergence Layer Adapter.

use std::time::Duration;

use hardy_hqfbp_cla::{RxSessionManager, parse_encodings_from_str};
use hqfbp_rs::kiss::KissDecoder;

/// Feeds arbitrary byte streams into KISS decoding and HQFBP deframing layers.
pub fn fuzz_kiss_and_hqfbp(data: &[u8]) {
    // 1. Fuzz string-based encoding parser
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_encodings_from_str(s);
    }

    // 2. Fuzz KISS decoder stream
    let mut decoder = KissDecoder::new();
    let mut session_mgr = RxSessionManager::new(8, 64 * 1024, Duration::from_secs(5));

    for &byte in data {
        if let Some(frame) = decoder.process_byte(byte)
            && !frame.is_empty()
            && (frame[0] & 0x0F == 0x00)
        {
            let _ = session_mgr.process_pdu(&frame[1..]);
        }
    }

    // 3. Fuzz direct PDU deframing
    let _ = session_mgr.process_pdu(data);
    let _ = session_mgr.drain_completed_messages();
    session_mgr.sweep_expired_default();
}
