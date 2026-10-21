//! Interoperability tests between hardy-ltp and licklider-core through an impaired channel.
//!
//! Validates cross-implementation RFC 5326 protocol conformance by testing
//! Hardy as Sender -> Licklider as Receiver, and Licklider as Sender -> Hardy as Receiver.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::vec::Vec;

use bytes::Bytes;
use sha2::{Digest, Sha256};

use hardy_ltp::engine::{
    Engine as HardyEngine, EngineConfig as HardyConfig, Notice as HardyNotice,
};
use hardy_ltp::types::EngineId as HardyEngineId;

use licklider_core::config::{Config as LickliderConfig, PeerConfig as LickliderPeerConfig};
use licklider_core::time::{Duration as LickliderDuration, Timestamp as LickliderTimestamp};
use licklider_core::types::EngineId as LickliderEngineId;
use licklider_core::{
    Engine as LickliderEngine, Input as LickliderInput, Notice as LickliderNotice,
    Output as LickliderOutput, TransmissionRequest as LickliderTransmissionRequest,
};

/// Deterministic SplitMix64 PRNG.
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

#[derive(Debug, Clone, Copy)]
struct ImpairmentProfile {
    loss_rate: f64,
    duplicate_rate: f64,
    min_delay_micros: u64,
    max_delay_micros: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct InFlightPacket {
    deliver_at: u64,
    from: u64,
    to: u64,
    payload: Vec<u8>,
}

impl Ord for InFlightPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        other.deliver_at.cmp(&self.deliver_at)
    }
}

impl PartialOrd for InFlightPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Tests Hardy (sender) transmitting to Licklider (receiver).
fn run_hardy_sender_licklider_receiver(
    payload: &[u8],
    mtu: usize,
    profile: ImpairmentProfile,
    seed: u64,
) -> Vec<u8> {
    let mut rng = SimpleRng::new(seed);

    // Hardy: Engine 1
    let hardy_cfg = HardyConfig {
        engine_id: HardyEngineId(1),
        max_segment_payload_len: mtu,
        checkpoint_rtx_limit: 15,
        rtt_micros: 200_000,
        ack_margin_micros: 100_000,
        ..HardyConfig::default()
    };
    let mut hardy = HardyEngine::new(hardy_cfg);

    // Licklider: Engine 2
    let mut lick_cfg = LickliderConfig::new(LickliderEngineId(2), seed);
    lick_cfg.checkpoint_rtx_limit = 15;
    lick_cfg.report_rtx_limit = 15;
    let mut licklider = LickliderEngine::new(lick_cfg).expect("licklider config valid");

    let mut peer_cfg = LickliderPeerConfig::new(LickliderEngineId(1));
    peer_cfg.max_segment_len = mtu + 64; // segment len includes headers
    peer_cfg.remote_delay = LickliderDuration::from_millis(300);
    licklider.add_peer(peer_cfg).expect("add peer valid");
    licklider.register_client_service(1);

    let mut now = 1_000_000u64; // 1s
    let block = Bytes::copy_from_slice(payload);
    let red_len = payload.len() as u64;

    hardy
        .request_transmission(HardyEngineId(2), 1, block, red_len, now)
        .expect("transmission request succeeds");

    let mut in_flight: BinaryHeap<InFlightPacket> = BinaryHeap::new();

    // Helper to queue packets with impairment
    let schedule_packet = |from: u64,
                           to: u64,
                           payload: Vec<u8>,
                           queue: &mut BinaryHeap<InFlightPacket>,
                           rng: &mut SimpleRng,
                           curr_time: u64| {
        if rng.gen_f64() < profile.loss_rate {
            return;
        }
        let delay = rng.gen_range(profile.min_delay_micros, profile.max_delay_micros);
        let deliver_at = curr_time + delay;
        queue.push(InFlightPacket {
            deliver_at,
            from,
            to,
            payload: payload.clone(),
        });
        if rng.gen_f64() < profile.duplicate_rate {
            let dup_delay = delay + rng.gen_range(1_000, 5_000);
            queue.push(InFlightPacket {
                deliver_at: curr_time + dup_delay,
                from,
                to,
                payload,
            });
        }
    };

    // Drain Hardy output
    while let Some((peer, bytes)) = hardy.poll_output() {
        schedule_packet(1, peer.0, bytes, &mut in_flight, &mut rng, now);
    }

    let mut received_data = None;
    let mut hardy_done = false;
    let max_virtual_time = now + 120_000_000;

    while now < max_virtual_time && (received_data.is_none() || !hardy_done) {
        // Collect notices
        while let Some(notice) = hardy.poll_notice() {
            if let HardyNotice::TransmissionSessionCompleted { .. } = notice {
                hardy_done = true;
            }
        }

        let lick_ts = LickliderTimestamp::from_micros(now);
        while let Some(out) = licklider.poll_output(lick_ts) {
            match out {
                LickliderOutput::Transmit { peer, segment } => {
                    schedule_packet(2, peer.0, segment, &mut in_flight, &mut rng, now);
                }
                LickliderOutput::Notice(LickliderNotice::RedPartReceived { data, .. }) => {
                    received_data = Some(data);
                }
                _ => {}
            }
        }

        if received_data.is_some() && hardy_done {
            break;
        }

        // Compute next event timestamp
        let next_packet = in_flight.peek().map(|p| p.deliver_at);
        let next_timer_hardy = hardy.next_timer_deadline();
        let next_timer_lick = licklider.next_timeout().map(|t| t.as_micros());

        let mut candidate_times = Vec::new();
        if let Some(t) = next_packet {
            candidate_times.push(t);
        }
        if let Some(t) = next_timer_hardy {
            candidate_times.push(t);
        }
        if let Some(t) = next_timer_lick {
            candidate_times.push(t);
        }

        let Some(&next_time) = candidate_times.iter().min() else {
            break;
        };

        now = now.max(next_time);

        // 1. Tick timers
        hardy.handle_timer_tick(now);
        while let Some((peer, bytes)) = hardy.poll_output() {
            schedule_packet(1, peer.0, bytes, &mut in_flight, &mut rng, now);
        }

        let lick_now = LickliderTimestamp::from_micros(now);
        licklider.handle_timeout(lick_now);
        while let Some(out) = licklider.poll_output(lick_now) {
            match out {
                LickliderOutput::Transmit { peer, segment } => {
                    schedule_packet(2, peer.0, segment, &mut in_flight, &mut rng, now);
                }
                LickliderOutput::Notice(LickliderNotice::RedPartReceived { data, .. }) => {
                    received_data = Some(data);
                }
                _ => {}
            }
        }

        // 2. Deliver in-flight packets
        while let Some(packet) = in_flight.peek() {
            if packet.deliver_at > now {
                break;
            }
            let packet = in_flight.pop().unwrap();

            if packet.to == 1 {
                let _ =
                    hardy.handle_incoming_segment(HardyEngineId(packet.from), &packet.payload, now);
                while let Some((peer, bytes)) = hardy.poll_output() {
                    schedule_packet(1, peer.0, bytes, &mut in_flight, &mut rng, now);
                }
            } else if packet.to == 2 {
                let lick_now = LickliderTimestamp::from_micros(now);
                licklider.handle_input(
                    lick_now,
                    LickliderInput::Segment {
                        peer: LickliderEngineId(packet.from),
                        data: &packet.payload,
                    },
                );
                while let Some(out) = licklider.poll_output(lick_now) {
                    match out {
                        LickliderOutput::Transmit { peer, segment } => {
                            schedule_packet(2, peer.0, segment, &mut in_flight, &mut rng, now);
                        }
                        LickliderOutput::Notice(LickliderNotice::RedPartReceived {
                            data, ..
                        }) => {
                            received_data = Some(data);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    received_data.expect("Licklider must have received and reassembled the red part")
}

/// Tests Licklider (sender) transmitting to Hardy (receiver).
fn run_licklider_sender_hardy_receiver(
    payload: &[u8],
    mtu: usize,
    profile: ImpairmentProfile,
    seed: u64,
) -> Vec<u8> {
    let mut rng = SimpleRng::new(seed);

    // Hardy: Engine 2 (receiver)
    let hardy_cfg = HardyConfig {
        engine_id: HardyEngineId(2),
        max_segment_payload_len: mtu,
        report_rtx_limit: 15,
        rtt_micros: 200_000,
        ack_margin_micros: 100_000,
        ..HardyConfig::default()
    };
    let mut hardy = HardyEngine::new(hardy_cfg);

    // Licklider: Engine 1 (sender)
    let mut lick_cfg = LickliderConfig::new(LickliderEngineId(1), seed);
    lick_cfg.checkpoint_rtx_limit = 15;
    lick_cfg.report_rtx_limit = 15;
    let mut licklider = LickliderEngine::new(lick_cfg).expect("licklider config valid");

    let mut peer_cfg = LickliderPeerConfig::new(LickliderEngineId(2));
    peer_cfg.max_segment_len = mtu + 64;
    peer_cfg.remote_delay = LickliderDuration::from_millis(300);
    licklider.add_peer(peer_cfg).expect("add peer valid");
    licklider.register_client_service(1);

    let mut now = 1_000_000u64; // 1s
    let block = Bytes::copy_from_slice(payload);
    let red_len = payload.len() as u64;

    let req = LickliderTransmissionRequest {
        destination: LickliderEngineId(2),
        client_service: 1,
        data: block,
        red_len,
    };

    let lick_now = LickliderTimestamp::from_micros(now);
    licklider
        .request_transmission(lick_now, req)
        .expect("licklider transmission request");

    let mut in_flight: BinaryHeap<InFlightPacket> = BinaryHeap::new();

    let schedule_packet = |from: u64,
                           to: u64,
                           payload: Vec<u8>,
                           queue: &mut BinaryHeap<InFlightPacket>,
                           rng: &mut SimpleRng,
                           curr_time: u64| {
        if rng.gen_f64() < profile.loss_rate {
            return;
        }
        let delay = rng.gen_range(profile.min_delay_micros, profile.max_delay_micros);
        let deliver_at = curr_time + delay;
        queue.push(InFlightPacket {
            deliver_at,
            from,
            to,
            payload: payload.clone(),
        });
        if rng.gen_f64() < profile.duplicate_rate {
            let dup_delay = delay + rng.gen_range(1_000, 5_000);
            queue.push(InFlightPacket {
                deliver_at: curr_time + dup_delay,
                from,
                to,
                payload,
            });
        }
    };

    // Drain Licklider initial output
    while let Some(out) = licklider.poll_output(lick_now) {
        if let LickliderOutput::Transmit { peer, segment } = out {
            schedule_packet(1, peer.0, segment, &mut in_flight, &mut rng, now);
        }
    }

    let mut received_data = None;
    let mut licklider_done = false;
    let max_virtual_time = now + 120_000_000;

    while now < max_virtual_time && (received_data.is_none() || !licklider_done) {
        while let Some(notice) = hardy.poll_notice() {
            if let HardyNotice::RedPartReceived { data, .. } = notice {
                received_data = Some(data);
            }
        }

        let lick_ts = LickliderTimestamp::from_micros(now);
        while let Some(out) = licklider.poll_output(lick_ts) {
            match out {
                LickliderOutput::Transmit { peer, segment } => {
                    schedule_packet(1, peer.0, segment, &mut in_flight, &mut rng, now);
                }
                LickliderOutput::Notice(LickliderNotice::TransmissionSessionCompleted {
                    ..
                }) => {
                    licklider_done = true;
                }
                _ => {}
            }
        }

        if received_data.is_some() && licklider_done {
            break;
        }

        let next_packet = in_flight.peek().map(|p| p.deliver_at);
        let next_timer_hardy = hardy.next_timer_deadline();
        let next_timer_lick = licklider.next_timeout().map(|t| t.as_micros());

        let mut candidate_times = Vec::new();
        if let Some(t) = next_packet {
            candidate_times.push(t);
        }
        if let Some(t) = next_timer_hardy {
            candidate_times.push(t);
        }
        if let Some(t) = next_timer_lick {
            candidate_times.push(t);
        }

        let Some(&next_time) = candidate_times.iter().min() else {
            break;
        };

        now = now.max(next_time);

        // 1. Tick timers
        hardy.handle_timer_tick(now);
        while let Some((peer, bytes)) = hardy.poll_output() {
            schedule_packet(2, peer.0, bytes, &mut in_flight, &mut rng, now);
        }

        let lick_now = LickliderTimestamp::from_micros(now);
        licklider.handle_timeout(lick_now);
        while let Some(out) = licklider.poll_output(lick_now) {
            match out {
                LickliderOutput::Transmit { peer, segment } => {
                    schedule_packet(1, peer.0, segment, &mut in_flight, &mut rng, now);
                }
                LickliderOutput::Notice(LickliderNotice::TransmissionSessionCompleted {
                    ..
                }) => {
                    licklider_done = true;
                }
                _ => {}
            }
        }

        // 2. Deliver in-flight packets
        while let Some(packet) = in_flight.peek() {
            if packet.deliver_at > now {
                break;
            }
            let packet = in_flight.pop().unwrap();

            if packet.to == 2 {
                let _ =
                    hardy.handle_incoming_segment(HardyEngineId(packet.from), &packet.payload, now);
                while let Some((peer, bytes)) = hardy.poll_output() {
                    schedule_packet(2, peer.0, bytes, &mut in_flight, &mut rng, now);
                }
            } else if packet.to == 1 {
                let lick_now = LickliderTimestamp::from_micros(now);
                licklider.handle_input(
                    lick_now,
                    LickliderInput::Segment {
                        peer: LickliderEngineId(packet.from),
                        data: &packet.payload,
                    },
                );
                while let Some(out) = licklider.poll_output(lick_now) {
                    match out {
                        LickliderOutput::Transmit { peer, segment } => {
                            schedule_packet(1, peer.0, segment, &mut in_flight, &mut rng, now);
                        }
                        LickliderOutput::Notice(
                            LickliderNotice::TransmissionSessionCompleted { .. },
                        ) => {
                            licklider_done = true;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    received_data.expect("Hardy must have received and reassembled the red part")
}

#[test]
fn test_interop_hardy_tx_licklider_rx_nominal() {
    let mut payload = vec![0u8; 32768];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 37) ^ 0x5A) as u8;
    }

    let profile = ImpairmentProfile {
        loss_rate: 0.0,
        duplicate_rate: 0.0,
        min_delay_micros: 10_000,
        max_delay_micros: 20_000,
    };

    let reconstructed = run_hardy_sender_licklider_receiver(&payload, 1024, profile, 111);

    assert_eq!(Sha256::digest(&reconstructed), Sha256::digest(&payload));
}

#[test]
fn test_interop_hardy_tx_licklider_rx_impaired_15_percent_loss() {
    let mut payload = vec![0u8; 32768];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 41) ^ 0xC3) as u8;
    }

    let profile = ImpairmentProfile {
        loss_rate: 0.15,
        duplicate_rate: 0.05,
        min_delay_micros: 10_000,
        max_delay_micros: 50_000,
    };

    let reconstructed = run_hardy_sender_licklider_receiver(&payload, 1024, profile, 222);

    assert_eq!(Sha256::digest(&reconstructed), Sha256::digest(&payload));
}

#[test]
fn test_interop_licklider_tx_hardy_rx_nominal() {
    let mut payload = vec![0u8; 32768];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 53) ^ 0x3C) as u8;
    }

    let profile = ImpairmentProfile {
        loss_rate: 0.0,
        duplicate_rate: 0.0,
        min_delay_micros: 10_000,
        max_delay_micros: 20_000,
    };

    let reconstructed = run_licklider_sender_hardy_receiver(&payload, 1024, profile, 333);

    assert_eq!(Sha256::digest(&reconstructed), Sha256::digest(&payload));
}

#[test]
fn test_interop_licklider_tx_hardy_rx_impaired_15_percent_loss() {
    let mut payload = vec![0u8; 32768];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 61) ^ 0xA5) as u8;
    }

    let profile = ImpairmentProfile {
        loss_rate: 0.15,
        duplicate_rate: 0.05,
        min_delay_micros: 10_000,
        max_delay_micros: 50_000,
    };

    let reconstructed = run_licklider_sender_hardy_receiver(&payload, 1024, profile, 444);

    assert_eq!(Sha256::digest(&reconstructed), Sha256::digest(&payload));
}
