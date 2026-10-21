//! Niveau 3 : In-memory impairment channel tests.
//!
//! Simulates packet loss, duplication, reordering, and delay jitter
//! across an in-memory transport connecting two LTP engines, and asserts
//! byte-for-byte SHA-256 integrity of reassembled blocks.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::vec::Vec;

use bytes::Bytes;
use sha2::{Digest, Sha256};

use hardy_ltp::engine::{Engine, EngineConfig, Notice};
use hardy_ltp::types::EngineId;

/// Deterministic SplitMix64 PRNG for reproducible impairment simulation.
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
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

    fn gen_range(&mut self, min: u64, max: u64) -> u64 {
        if min >= max {
            return min;
        }
        min + (self.next_u64() % (max - min + 1))
    }
}

/// Impairment profile applied to in-transit datagrams.
#[derive(Debug, Clone, Copy)]
struct ImpairmentProfile {
    loss_rate: f64,
    duplicate_rate: f64,
    min_delay_micros: u64,
    max_delay_micros: u64,
}

/// Scheduled in-flight packet delivery event.
#[derive(Debug, Eq, PartialEq)]
struct InFlightPacket {
    deliver_at: u64,
    from: EngineId,
    to: EngineId,
    payload: Vec<u8>,
}

impl Ord for InFlightPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap (earliest deliver_at popped first)
        other.deliver_at.cmp(&self.deliver_at)
    }
}

impl PartialOrd for InFlightPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Runs a deterministic simulated transfer through an impaired channel.
fn run_impaired_transfer(
    payload: &[u8],
    mtu: usize,
    profile: ImpairmentProfile,
    seed: u64,
) -> Vec<u8> {
    let mut rng = SimpleRng::new(seed);

    let cfg_a = EngineConfig {
        engine_id: EngineId(1),
        max_segment_payload_len: mtu,
        checkpoint_rtx_limit: 15,
        rtt_micros: 200_000,
        ack_margin_micros: 100_000,
        ..EngineConfig::default()
    };
    let mut engine_a = Engine::new(cfg_a);

    let cfg_b = EngineConfig {
        engine_id: EngineId(2),
        max_segment_payload_len: mtu,
        report_rtx_limit: 15,
        rtt_micros: 200_000,
        ack_margin_micros: 100_000,
        ..EngineConfig::default()
    };
    let mut engine_b = Engine::new(cfg_b);

    let mut now = 1_000_000u64; // Start at 1 second virtual time
    let block = Bytes::copy_from_slice(payload);
    let red_len = payload.len() as u64;

    let _session_id = engine_a
        .request_transmission(EngineId(2), 1, block, red_len, now)
        .expect("transmission request must succeed");

    let mut in_flight: BinaryHeap<InFlightPacket> = BinaryHeap::new();

    // Helper to queue outbound segments through the impairment channel
    let schedule_outputs = |engine: &mut Engine,
                            queue: &mut BinaryHeap<InFlightPacket>,
                            rng: &mut SimpleRng,
                            curr_time: u64| {
        while let Some((peer, bytes)) = engine.poll_output() {
            // Drop packet if random roll falls within loss rate
            if rng.gen_f64() < profile.loss_rate {
                continue;
            }

            let delay = rng.gen_range(profile.min_delay_micros, profile.max_delay_micros);
            let deliver_at = curr_time + delay;

            queue.push(InFlightPacket {
                deliver_at,
                from: engine.config().engine_id,
                to: peer,
                payload: bytes.clone(),
            });

            // Duplicate packet if random roll falls within duplicate rate
            if rng.gen_f64() < profile.duplicate_rate {
                let dup_delay = delay + rng.gen_range(1_000, 10_000);
                queue.push(InFlightPacket {
                    deliver_at: curr_time + dup_delay,
                    from: engine.config().engine_id,
                    to: peer,
                    payload: bytes,
                });
            }
        }
    };

    schedule_outputs(&mut engine_a, &mut in_flight, &mut rng, now);

    let mut received_data = None;
    let mut sender_done = false;
    let max_virtual_time = now + 120_000_000; // 120 virtual seconds failsafe

    while now < max_virtual_time && (received_data.is_none() || !sender_done) {
        // Collect notices
        while let Some(notice) = engine_b.poll_notice() {
            if let Notice::RedPartReceived { data, .. } = notice {
                received_data = Some(data);
            }
        }
        while let Some(notice) = engine_a.poll_notice() {
            if let Notice::TransmissionSessionCompleted { .. } = notice {
                sender_done = true;
            }
        }

        if received_data.is_some() && sender_done {
            break;
        }

        // Determine next event timestamp
        let next_packet_time = in_flight.peek().map(|p| p.deliver_at);
        let next_timer_a = engine_a.next_timer_deadline();
        let next_timer_b = engine_b.next_timer_deadline();

        let mut candidate_times = Vec::new();
        if let Some(t) = next_packet_time {
            candidate_times.push(t);
        }
        if let Some(t) = next_timer_a {
            candidate_times.push(t);
        }
        if let Some(t) = next_timer_b {
            candidate_times.push(t);
        }

        let Some(&next_time) = candidate_times.iter().min() else {
            break;
        };

        // Advance virtual clock
        now = now.max(next_time);

        // 1. Tick engine timers
        engine_a.handle_timer_tick(now);
        schedule_outputs(&mut engine_a, &mut in_flight, &mut rng, now);

        engine_b.handle_timer_tick(now);
        schedule_outputs(&mut engine_b, &mut in_flight, &mut rng, now);

        // 2. Deliver in-flight datagrams scheduled up to `now`
        while let Some(packet) = in_flight.peek() {
            if packet.deliver_at > now {
                break;
            }
            let packet = in_flight.pop().unwrap();

            if packet.to == EngineId(1) {
                let _ = engine_a.handle_incoming_segment(packet.from, &packet.payload, now);
                schedule_outputs(&mut engine_a, &mut in_flight, &mut rng, now);
            } else if packet.to == EngineId(2) {
                let _ = engine_b.handle_incoming_segment(packet.from, &packet.payload, now);
                schedule_outputs(&mut engine_b, &mut in_flight, &mut rng, now);
            }
        }
    }

    // Drain any remaining notices
    while let Some(notice) = engine_b.poll_notice() {
        if let Notice::RedPartReceived { data, .. } = notice {
            received_data = Some(data);
        }
    }

    received_data.expect("reconstructed red part must be received despite impairments")
}

#[test]
fn test_impairment_lossless_large_block() {
    // 64 KiB block with deterministic pattern
    let mut payload = vec![0u8; 65536];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 31) ^ (i >> 8)) as u8;
    }

    let profile = ImpairmentProfile {
        loss_rate: 0.0,
        duplicate_rate: 0.0,
        min_delay_micros: 10_000,
        max_delay_micros: 20_000,
    };

    let reconstructed = run_impaired_transfer(&payload, 1024, profile, 42);

    let expected_hash = Sha256::digest(&payload);
    let actual_hash = Sha256::digest(&reconstructed);
    assert_eq!(actual_hash, expected_hash);
}

#[test]
fn test_impairment_packet_loss_15_percent() {
    // 32 KiB block across channel with 15% drop rate on all segments (data, CP, RS, RA)
    let mut payload = vec![0u8; 32768];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 17) ^ 0xAA) as u8;
    }

    let profile = ImpairmentProfile {
        loss_rate: 0.15,
        duplicate_rate: 0.0,
        min_delay_micros: 20_000,
        max_delay_micros: 50_000,
    };

    let reconstructed = run_impaired_transfer(&payload, 1024, profile, 12345);

    let expected_hash = Sha256::digest(&payload);
    let actual_hash = Sha256::digest(&reconstructed);
    assert_eq!(actual_hash, expected_hash);
}

#[test]
fn test_impairment_duplication_and_jitter() {
    // 32 KiB block with 10% packet duplicates and wide delay jitter (10ms to 150ms)
    let mut payload = vec![0u8; 32768];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 73) + 0x55) as u8;
    }

    let profile = ImpairmentProfile {
        loss_rate: 0.0,
        duplicate_rate: 0.10,
        min_delay_micros: 10_000,
        max_delay_micros: 150_000,
    };

    let reconstructed = run_impaired_transfer(&payload, 1024, profile, 67890);

    let expected_hash = Sha256::digest(&payload);
    let actual_hash = Sha256::digest(&reconstructed);
    assert_eq!(actual_hash, expected_hash);
}

#[test]
fn test_impairment_combined_stress() {
    // 64 KiB block under combined stress:
    // 15% loss, 10% duplication, variable latency (10ms - 100ms)
    let mut payload = vec![0u8; 65536];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 101) ^ (i >> 5)) as u8;
    }

    let profile = ImpairmentProfile {
        loss_rate: 0.15,
        duplicate_rate: 0.10,
        min_delay_micros: 10_000,
        max_delay_micros: 100_000,
    };

    let reconstructed = run_impaired_transfer(&payload, 1024, profile, 99999);

    let expected_hash = Sha256::digest(&payload);
    let actual_hash = Sha256::digest(&reconstructed);
    assert_eq!(actual_hash, expected_hash);
}
