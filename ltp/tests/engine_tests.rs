//! Deterministic integration tests for the Sans-I/O LTP Engine.

use bytes::Bytes;
use std::vec::Vec;

use hardy_ltp::engine::{Engine, EngineConfig, Notice};
use hardy_ltp::types::{CancelReason, EngineId};

#[test]
fn nominal_red_block_transfer() {
    let cfg_a = EngineConfig {
        engine_id: EngineId(1),
        max_segment_payload_len: 1000,
        ..EngineConfig::default()
    };
    let mut engine_a = Engine::new(cfg_a);

    let cfg_b = EngineConfig {
        engine_id: EngineId(2),
        max_segment_payload_len: 1000,
        ..EngineConfig::default()
    };
    let mut engine_b = Engine::new(cfg_b);

    let now = 1_000_000u64; // 1 second
    let payload = vec![0xABu8; 2500]; // 3 segments: 1000, 1000, 500
    let block = Bytes::copy_from_slice(&payload);

    let session_id = engine_a
        .request_transmission(EngineId(2), 1, block, 2500, now)
        .expect("request should succeed");

    // 1. Drain outbound data segments from A and deliver to B
    let mut data_segs = Vec::new();
    while let Some((peer, bytes)) = engine_a.poll_output() {
        assert_eq!(peer, EngineId(2));
        data_segs.push(bytes);
    }
    assert_eq!(data_segs.len(), 3); // 2 data + 1 CP

    for seg_bytes in data_segs {
        engine_b
            .handle_incoming_segment(EngineId(1), &seg_bytes, now)
            .expect("deliver to B");
    }

    // 2. B received the checkpoint, so B should have generated a Report Segment (RS)
    let (peer, rs_bytes) = engine_b.poll_output().expect("B must emit Report Segment");
    assert_eq!(peer, EngineId(1));

    // Deliver RS to A
    engine_a
        .handle_incoming_segment(EngineId(2), &rs_bytes, now)
        .expect("deliver RS to A");

    // 3. A must emit Report Acknowledgment (RA) and complete transmission
    let (peer, ra_bytes) = engine_a
        .poll_output()
        .expect("A must emit Report Acknowledgment");
    assert_eq!(peer, EngineId(2));

    let a_notice = engine_a.poll_notice().expect("A should have completed");
    assert_eq!(
        a_notice,
        Notice::TransmissionSessionCompleted {
            session: session_id
        }
    );

    // Deliver RA to B
    engine_b
        .handle_incoming_segment(EngineId(1), &ra_bytes, now)
        .expect("deliver RA to B");

    // B should have delivered the complete Red part
    let b_notice = engine_b.poll_notice().expect("B should deliver block");
    match b_notice {
        Notice::RedPartReceived {
            session,
            source,
            client_service,
            data,
            eob,
        } => {
            assert_eq!(session, session_id);
            assert_eq!(source, EngineId(1));
            assert_eq!(client_service, 1);
            assert_eq!(data, payload);
            assert!(eob);
        }
        other => panic!("unexpected notice from B: {other:?}"),
    }
}

#[test]
fn retransmission_on_packet_loss() {
    let cfg_a = EngineConfig {
        engine_id: EngineId(1),
        max_segment_payload_len: 1000,
        ..EngineConfig::default()
    };
    let mut engine_a = Engine::new(cfg_a);

    let cfg_b = EngineConfig {
        engine_id: EngineId(2),
        max_segment_payload_len: 1000,
        ..EngineConfig::default()
    };
    let mut engine_b = Engine::new(cfg_b);

    let now = 1_000_000u64;
    let payload = vec![0x55u8; 3000]; // 3 segments of 1000 bytes
    let block = Bytes::copy_from_slice(&payload);

    let session_id = engine_a
        .request_transmission(EngineId(2), 1, block, 3000, now)
        .expect("request should succeed");

    let mut segs = Vec::new();
    while let Some((_, bytes)) = engine_a.poll_output() {
        segs.push(bytes);
    }
    assert_eq!(segs.len(), 3);

    // Deliver segment 0 and segment 2 (CP), DROPPING segment 1!
    engine_b
        .handle_incoming_segment(EngineId(1), &segs[0], now)
        .unwrap();
    engine_b
        .handle_incoming_segment(EngineId(1), &segs[2], now)
        .unwrap();

    // B received CP and detects gap 1000..2000. B emits Report Segment (RS).
    let (_, rs_bytes) = engine_b.poll_output().expect("B must emit RS");

    // Deliver RS to A
    engine_a
        .handle_incoming_segment(EngineId(2), &rs_bytes, now)
        .unwrap();

    // A emits RA
    let (_, ra_bytes) = engine_a.poll_output().expect("A must emit RA");

    // And A must emit a retransmission segment for the gap (1000..2000) with a new Checkpoint!
    let (_, rtx_bytes) = engine_a.poll_output().expect("A must retransmit gap");

    // Deliver RA and the retransmitted segment to B
    engine_b
        .handle_incoming_segment(EngineId(1), &ra_bytes, now)
        .unwrap();
    engine_b
        .handle_incoming_segment(EngineId(1), &rtx_bytes, now)
        .unwrap();

    // Now B has all 3000 bytes! B emits updated RS covering 0..3000
    let (_, final_rs_bytes) = engine_b.poll_output().expect("B emits final RS");

    // Deliver final RS to A
    engine_a
        .handle_incoming_segment(EngineId(2), &final_rs_bytes, now)
        .unwrap();

    // A emits final RA and finishes session
    let (_, final_ra_bytes) = engine_a.poll_output().expect("A emits final RA");
    assert_eq!(
        engine_a.poll_notice(),
        Some(Notice::TransmissionSessionCompleted {
            session: session_id
        })
    );

    // Deliver final RA to B
    engine_b
        .handle_incoming_segment(EngineId(1), &final_ra_bytes, now)
        .unwrap();

    // B delivers the complete reconstructed block!
    match engine_b.poll_notice().expect("B delivers block") {
        Notice::RedPartReceived { data, .. } => {
            assert_eq!(data, payload);
        }
        other => panic!("unexpected notice: {other:?}"),
    }
}

#[test]
fn checkpoint_timeout_and_retransmission() {
    let cfg_a = EngineConfig {
        engine_id: EngineId(1),
        max_segment_payload_len: 1000,
        rtt_micros: 1_000_000,
        ack_margin_micros: 500_000,
        ..EngineConfig::default()
    };
    let mut engine_a = Engine::new(cfg_a);

    let cfg_b = EngineConfig {
        engine_id: EngineId(2),
        ..EngineConfig::default()
    };
    let mut engine_b = Engine::new(cfg_b);

    let mut now = 1_000_000u64;
    let block = Bytes::from_static(b"checkpoint test data");

    let session_id = engine_a
        .request_transmission(EngineId(2), 1, block, 20, now)
        .unwrap();

    // Drain CP segment from A, but SIMULATE PACKET LOSS (do NOT deliver to B!)
    let (_, _cp_bytes) = engine_a.poll_output().unwrap();
    assert!(engine_a.poll_output().is_none());

    // Advance time beyond the timer deadline (rtt + margin = 1.5s -> deadline = 2.5s)
    now += 1_600_000;
    engine_a.handle_timer_tick(now);

    // A's timer expired, so A must retransmit the checkpoint segment!
    let (_, rtx_cp_bytes) = engine_a
        .poll_output()
        .expect("A must retransmit CP on timeout");

    // Now deliver the retransmission to B
    engine_b
        .handle_incoming_segment(EngineId(1), &rtx_cp_bytes, now)
        .unwrap();

    // B sends RS
    let (_, rs_bytes) = engine_b.poll_output().unwrap();
    engine_a
        .handle_incoming_segment(EngineId(2), &rs_bytes, now)
        .unwrap();

    // A sends RA and completes
    let (_, ra_bytes) = engine_a.poll_output().unwrap();
    assert_eq!(
        engine_a.poll_notice(),
        Some(Notice::TransmissionSessionCompleted {
            session: session_id
        })
    );

    engine_b
        .handle_incoming_segment(EngineId(1), &ra_bytes, now)
        .unwrap();
    assert!(engine_b.poll_notice().is_some());
}

#[test]
fn retry_limit_exceeded_cancels_session() {
    let cfg = EngineConfig {
        engine_id: EngineId(1),
        checkpoint_rtx_limit: 2, // Allow only 2 retries
        rtt_micros: 100_000,
        ack_margin_micros: 50_000, // Timer interval = 150_000
        ..EngineConfig::default()
    };
    let mut engine = Engine::new(cfg);

    let mut now = 1_000_000u64;
    let block = Bytes::from_static(b"fail me");
    let session_id = engine
        .request_transmission(EngineId(2), 1, block, 7, now)
        .unwrap();

    // Drain initial transmission
    let _ = engine.poll_output().unwrap();

    // Retry 1
    now += 160_000;
    engine.handle_timer_tick(now);
    assert!(engine.poll_output().is_some());

    // Retry 2
    now += 160_000;
    engine.handle_timer_tick(now);
    assert!(engine.poll_output().is_some());

    // Exceed limit on 3rd expiration
    now += 160_000;
    engine.handle_timer_tick(now);

    // Engine must emit Cancel Segment (CS)
    let (peer, _cs_bytes) = engine.poll_output().expect("must emit CS");
    assert_eq!(peer, EngineId(2));

    // And must notify client that session was cancelled with Rlexc
    assert_eq!(
        engine.poll_notice(),
        Some(Notice::TransmissionSessionCancelled {
            session: session_id,
            reason: CancelReason::Rlexc,
        })
    );
}

#[test]
fn mixed_red_and_green_transfer() {
    let cfg_a = EngineConfig {
        engine_id: EngineId(1),
        max_segment_payload_len: 1000,
        ..EngineConfig::default()
    };
    let mut engine_a = Engine::new(cfg_a);

    let cfg_b = EngineConfig {
        engine_id: EngineId(2),
        max_segment_payload_len: 1000,
        ..EngineConfig::default()
    };
    let mut engine_b = Engine::new(cfg_b);

    let now = 1_000_000u64;
    let mut payload = vec![0x11u8; 1500]; // 1500 bytes Red
    payload.extend_from_slice(&[0x22u8; 1500]); // 1500 bytes Green
    let block = Bytes::copy_from_slice(&payload);

    let session_id = engine_a
        .request_transmission(EngineId(2), 1, block, 1500, now)
        .unwrap();

    // Drain segments: 2 Red (1000 + 500 CP) + 2 Green (1000 + 500 EOB)
    let mut segs = Vec::new();
    while let Some((_, bytes)) = engine_a.poll_output() {
        segs.push(bytes);
    }
    assert_eq!(segs.len(), 4);

    for s in segs {
        engine_b
            .handle_incoming_segment(EngineId(1), &s, now)
            .unwrap();
    }

    // B should have received:
    // 1. RedPartReceived (since 1500 red bytes are fully received upon segment 1)
    match engine_b.poll_notice().unwrap() {
        Notice::RedPartReceived { data, eob, .. } => {
            assert_eq!(data, &payload[..1500]);
            assert!(!eob); // Block has green data following, so red doesn't end block!
        }
        _ => panic!("expected red notice"),
    }

    // 2. Green segments
    let notice_g1 = engine_b.poll_notice().unwrap();
    match notice_g1 {
        Notice::GreenSegmentArrived {
            offset, data, eob, ..
        } => {
            assert_eq!(offset, 1500);
            assert_eq!(data.len(), 1000);
            assert!(!eob);
        }
        _ => panic!("expected green notice 1"),
    }

    let notice_g2 = engine_b.poll_notice().unwrap();
    match notice_g2 {
        Notice::GreenSegmentArrived {
            offset, data, eob, ..
        } => {
            assert_eq!(offset, 2500);
            assert_eq!(data.len(), 500);
            assert!(eob);
        }
        _ => panic!("expected green notice 2"),
    }

    // Complete the Red handshake: B issued RS for the checkpoint
    let (_, rs) = engine_b.poll_output().unwrap();
    engine_a
        .handle_incoming_segment(EngineId(2), &rs, now)
        .unwrap();
    let (_, ra) = engine_a.poll_output().unwrap();
    engine_b
        .handle_incoming_segment(EngineId(1), &ra, now)
        .unwrap();

    // Verify sender completed
    assert_eq!(
        engine_a.poll_notice(),
        Some(Notice::TransmissionSessionCompleted {
            session: session_id
        })
    );
}

#[test]
fn test_inactivity_timeout_cleans_up_stalled_session() {
    let cfg = EngineConfig {
        engine_id: EngineId(1),
        session_inactivity_timeout_micros: 10_000_000, // 10s
        ..Default::default()
    };
    let mut engine = Engine::new(cfg);
    let now = 1_000_000;

    let payload = Bytes::from_static(b"stalled session test");
    let session_id = engine
        .request_transmission(EngineId(2), 1, payload, 20, now)
        .unwrap();

    // Advance time beyond inactivity timeout
    let expired_now = now + 15_000_000;
    engine.handle_timer_tick(expired_now);

    // Engine should have cancelled the session
    assert_eq!(
        engine.poll_notice(),
        Some(Notice::TransmissionSessionCancelled {
            session: session_id,
            reason: hardy_ltp::types::CancelReason::Rlexc,
        })
    );
}

#[test]
fn test_out_of_bounds_report_scope_does_not_panic() {
    let mut engine = Engine::new(EngineConfig {
        engine_id: EngineId(1),
        ..Default::default()
    });
    let now = 1_000_000;

    let payload = Bytes::from_static(b"short payload");
    let session_id = engine
        .request_transmission(EngineId(2), 1, payload, 13, now)
        .unwrap();

    // Fabricate an out-of-bounds report segment with upper_bound = 999999
    let malicious_rs = hardy_ltp::segment::ReportSegment {
        report_serial: core::num::NonZeroU64::new(1).unwrap(),
        checkpoint_serial: 1,
        upper_bound: 999_999,
        lower_bound: 0,
        claims: vec![hardy_ltp::segment::ReceptionClaim {
            offset: 0,
            length: 5,
        }],
    };
    let wire_seg = hardy_ltp::segment::Segment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: hardy_ltp::segment::SegmentBody::Report(malicious_rs),
    };

    // Feeding this must NOT panic; scope must be clamped to session.red_len
    engine
        .handle_incoming_segment(EngineId(2), &wire_seg.encode_to_vec(), now)
        .unwrap();
}

#[test]
fn test_block_too_large_rejected() {
    let mut engine = Engine::new(EngineConfig {
        engine_id: EngineId(1),
        max_block_size: 1024,
        ..Default::default()
    });

    let big_payload = vec![0u8; 2048];
    let res = engine.request_transmission(EngineId(2), 1, Bytes::from(big_payload), 100, 1_000_000);
    assert!(matches!(
        res,
        Err(hardy_ltp::engine::Error::BlockTooLarge {
            block_len: 2048,
            max_block_size: 1024
        })
    ));
}

#[test]
fn test_report_with_zero_claims_rfc_compliant() {
    let rs = hardy_ltp::segment::ReportSegment {
        report_serial: core::num::NonZeroU64::new(1).unwrap(),
        checkpoint_serial: 1,
        upper_bound: 500,
        lower_bound: 0,
        claims: Vec::new(), // 0 claims: nothing received in [0, 500)
    };
    let seg = hardy_ltp::segment::Segment {
        session: hardy_ltp::types::SessionId {
            originator: EngineId(1),
            number: 1,
        },
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: hardy_ltp::segment::SegmentBody::Report(rs.clone()),
    };
    let wire = seg.encode_to_vec();

    // Must parse successfully without ClaimCountInvalid error
    let (parsed, _) = hardy_ltp::segment::Segment::parse(&wire).unwrap();
    match parsed.body {
        hardy_ltp::segment::SegmentBody::Report(parsed_rs) => {
            assert_eq!(parsed_rs.claims.len(), 0);
            assert_eq!(parsed_rs.upper_bound, 500);
        }
        _ => panic!("expected report segment"),
    }
}
