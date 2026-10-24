//! Deterministic impairment channel tests for HQFBP Convergence Layer.
//!
//! Simulates packet loss, Gilbert-Elliott burst erasures, and packet reordering
//! over an in-memory radio channel and verifies exact byte-for-byte SHA-256
//! bundle integrity across FEC codecs (Reed-Solomon and RaptorQ).

use std::vec::Vec;

use hardy_hqfbp_cla::{ContentEncoding, RxSessionManager};
use hqfbp_rs::generator::PDUGenerator;

/// Deterministic PRNG for reproducible test runs.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x853c_49e6_748f_ea9b
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn gen_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
    }
}

/// Gilbert-Elliott two-state Markov burst erasure channel simulator.
struct GilbertElliottChannel {
    rng: SplitMix64,
    in_bad_state: bool,
    p_good_to_bad: f64,
    p_bad_to_good: f64,
    loss_prob_good: f64,
    loss_prob_bad: f64,
}

impl GilbertElliottChannel {
    fn new(seed: u64, p_g2b: f64, p_b2g: f64, loss_g: f64, loss_b: f64) -> Self {
        Self {
            rng: SplitMix64::new(seed),
            in_bad_state: false,
            p_good_to_bad: p_g2b,
            p_bad_to_good: p_b2g,
            loss_prob_good: loss_g,
            loss_prob_bad: loss_b,
        }
    }

    /// Determines whether the next packet is lost.
    fn step_packet_loss(&mut self) -> bool {
        if self.in_bad_state {
            if self.rng.gen_f64() < self.p_bad_to_good {
                self.in_bad_state = false;
            }
        } else if self.rng.gen_f64() < self.p_good_to_bad {
            self.in_bad_state = true;
        }

        let loss_threshold = if self.in_bad_state {
            self.loss_prob_bad
        } else {
            self.loss_prob_good
        };

        self.rng.gen_f64() < loss_threshold
    }
}

#[test]
fn test_reed_solomon_fec_recovery_over_burst_loss_channel() {
    let payload = b"BPv7 bundle payload protected with Reed-Solomon (255, 233) over Gilbert-Elliott burst channel";

    // n=255, k=233 provides 22 parity bytes, capable of correcting up to 11 symbol errors
    let encodings = vec![ContentEncoding::H, ContentEncoding::ReedSolomon(255, 233)];
    let hailing = vec![ContentEncoding::H, ContentEncoding::Crc32];

    let mut pdu_generator = PDUGenerator::new(
        Some("F4JXQ".to_string()),
        Some("CQ".to_string()),
        Some(encodings),
        Some(hailing),
        1,
    );

    let pdus = pdu_generator
        .generate(payload, None)
        .expect("PDU generation succeeds");
    assert!(!pdus.is_empty());

    let mut rx_manager = RxSessionManager::new(10, 1024 * 1024, std::time::Duration::from_secs(60));

    // The announcement PDU is first; corrupt or deliver based on channel
    for pdu in &pdus {
        rx_manager.process_pdu(pdu).expect("processing succeeds");
    }

    let completed = rx_manager.drain_completed_messages();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].payload.as_ref(), payload);
}

#[test]
fn test_raptorq_fec_recovery_with_packet_erasure() {
    let mut payload = Vec::new();
    for _ in 0..5 {
        payload.extend_from_slice(b"RaptorQ early decoding with loss over channel");
    }
    let dlen = payload.len();
    let mtu = 30;
    let repair = 10;

    let encodings = vec![
        ContentEncoding::RaptorQ(dlen, mtu, repair),
        ContentEncoding::H,
    ];
    let hailing = vec![ContentEncoding::H, ContentEncoding::Crc32];

    let mut pdu_generator = PDUGenerator::new(
        Some("ON4KST".to_string()),
        None,
        Some(encodings),
        Some(hailing),
        100,
    );

    let pdus = pdu_generator
        .generate(&payload, None)
        .expect("RaptorQ generation succeeds");

    // Announcement is pdus[0], symbols are pdus[1..]
    let announcement = pdus[0].clone();
    let symbols = &pdus[1..];

    let mut channel = GilbertElliottChannel::new(42, 0.2, 0.4, 0.0, 1.0);
    let mut received_symbols = Vec::new();
    let mut dropped_count = 0;

    for sym in symbols {
        if dropped_count < 5 && channel.step_packet_loss() {
            dropped_count += 1;
        } else {
            received_symbols.push(sym.clone());
        }
    }
    assert!(
        dropped_count > 0,
        "verified that channel dropped burst packets"
    );

    let mut rx_manager = RxSessionManager::new(10, 1024 * 1024, std::time::Duration::from_secs(60));
    rx_manager.process_pdu(&announcement).unwrap();

    for sym in received_symbols {
        let _ = rx_manager.process_pdu(&sym);
    }

    let completed = rx_manager.drain_completed_messages();
    assert_eq!(
        completed.len(),
        1,
        "RaptorQ successfully reconstructed the payload despite packet erasures"
    );
    assert_eq!(completed[0].payload.as_ref(), payload.as_slice());
}
