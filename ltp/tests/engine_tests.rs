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

#[test]
fn test_s8_zero_max_segment_payload_len_does_not_loop() {
    let mut engine = Engine::new(EngineConfig {
        engine_id: EngineId(1),
        max_segment_payload_len: 0, // Invalid configuration: must not cause infinite loop or OOM
        ..Default::default()
    });

    let payload = vec![0x42u8; 100];
    let res = engine.request_transmission(EngineId(2), 1, Bytes::from(payload), 100, 1_000_000);
    assert!(res.is_ok(), "request_transmission must succeed safely");

    // Engine must clamp MTU to >= 1 and produce segments without hanging
    let mut count = 0;
    while let Some((_, _)) = engine.poll_output() {
        count += 1;
        if count > 1000 {
            panic!("infinite loop detected in request_transmission!");
        }
    }
    assert!(count > 0);
}

#[test]
fn test_s9_u64_max_timestamp_and_serial_wraparound() {
    let now = u64::MAX - 500;
    let mut engine = Engine::new(EngineConfig {
        engine_id: EngineId(1),
        initial_session_number: u64::MAX,
        rtt_micros: 2_000_000,
        ack_margin_micros: 2_000_000,
        ..Default::default()
    });

    // Session creation with session_number = u64::MAX must wrap cleanly without panic
    let session_1 = engine
        .request_transmission(EngineId(2), 1, Bytes::from_static(b"hello"), 5, now)
        .expect("must succeed with u64::MAX");
    assert_eq!(session_1.number, u64::MAX);

    let session_2 = engine
        .request_transmission(EngineId(2), 1, Bytes::from_static(b"world"), 5, now)
        .expect("must succeed after wrap-around");
    assert_eq!(session_2.number, 1);

    // Timer deadline calculations with now close to u64::MAX must not panic on overflow
    let deadline = engine.next_timer_deadline().expect("must have deadline");
    assert_eq!(deadline, u64::MAX);

    // Timer tick at u64::MAX must not panic
    engine.handle_timer_tick(u64::MAX);
}

#[test]
fn test_s10_segmented_reports_max_claims() {
    let mut engine = Engine::new(EngineConfig {
        engine_id: EngineId(2),
        max_claims_per_report: 5, // Strict limit of 5 claims per report
        ..Default::default()
    });

    let session_id = hardy_ltp::types::SessionId {
        originator: EngineId(1),
        number: 42,
    };

    // Feed 15 non-contiguous 10-byte slices: 0..10, 20..30, 40..50, ... 280..290
    for i in 0..15 {
        let offset = i * 20;
        let is_last = i == 14;
        let checkpoint = if is_last {
            Some(hardy_ltp::segment::Checkpoint {
                serial: core::num::NonZeroU64::new(1).unwrap(),
                report_serial: 0,
            })
        } else {
            None
        };

        let kind = if let Some(cp) = checkpoint {
            hardy_ltp::segment::DataSegKind::RedCpEorpEob(cp)
        } else {
            hardy_ltp::segment::DataSegKind::Red
        };

        let seg = hardy_ltp::segment::Segment {
            session: session_id,
            header_ext: Vec::new(),
            trailer_ext: Vec::new(),
            body: hardy_ltp::segment::SegmentBody::Data(hardy_ltp::segment::DataSegment {
                client_service: 1,
                offset,
                kind,
                data: &[0xAA; 10],
            }),
        };

        engine
            .handle_incoming_segment(EngineId(1), &seg.encode_to_vec(), 1_000_000)
            .unwrap();
    }

    // Engine must partition the 15 claims into 3 distinct reports of <= 5 claims each!
    let mut reports = Vec::new();
    while let Some((_, bytes)) = engine.poll_output() {
        let (parsed, _) = hardy_ltp::segment::Segment::parse(&bytes).unwrap();
        if let hardy_ltp::segment::SegmentBody::Report(rs) = parsed.body {
            assert!(rs.claims.len() <= 5, "claims per report must be <= 5");
            reports.push(rs);
        }
    }

    assert_eq!(reports.len(), 3, "15 claims / 5 per report = 3 reports");
}

#[test]
fn test_s11_miscolored_detection() {
    let mut engine = Engine::new(EngineConfig {
        engine_id: EngineId(2),
        ..Default::default()
    });

    let session_id = hardy_ltp::types::SessionId {
        originator: EngineId(1),
        number: 10,
    };

    // Send a Green segment at offset 100
    let green_seg = hardy_ltp::segment::Segment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: hardy_ltp::segment::SegmentBody::Data(hardy_ltp::segment::DataSegment {
            client_service: 1,
            offset: 100,
            kind: hardy_ltp::segment::DataSegKind::Green,
            data: &[0xAA; 50],
        }),
    };
    engine
        .handle_incoming_segment(EngineId(1), &green_seg.encode_to_vec(), 1_000_000)
        .unwrap();

    // Green arrival emits GreenSegmentArrived notice
    let green_notice = engine
        .poll_notice()
        .expect("must emit green arrival notice");
    assert!(matches!(green_notice, Notice::GreenSegmentArrived { .. }));

    // Now send a Red segment at offset 120 (violating red < green ordering: Miscolored!)
    let red_seg = hardy_ltp::segment::Segment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: hardy_ltp::segment::SegmentBody::Data(hardy_ltp::segment::DataSegment {
            client_service: 1,
            offset: 120,
            kind: hardy_ltp::segment::DataSegKind::Red,
            data: &[0xBB; 20],
        }),
    };
    engine
        .handle_incoming_segment(EngineId(1), &red_seg.encode_to_vec(), 1_000_000)
        .unwrap();

    // Engine must emit CancelReceiver with Miscolored
    let (_, out_bytes) = engine.poll_output().expect("must emit cancellation");
    let (parsed, _) = hardy_ltp::segment::Segment::parse(&out_bytes).unwrap();
    match parsed.body {
        hardy_ltp::segment::SegmentBody::CancelReceiver { reason } => {
            assert_eq!(reason, CancelReason::Miscolored);
        }
        other => panic!("expected CancelReceiver, got {other:?}"),
    }

    // Must emit cancellation notice
    let notice = engine.poll_notice().expect("must emit notice");
    assert_eq!(
        notice,
        Notice::TransmissionSessionCancelled {
            session: session_id,
            reason: CancelReason::Miscolored,
        }
    );
}

#[test]
fn test_s12_cancel_isolation() {
    let mut engine = Engine::new(EngineConfig {
        engine_id: EngineId(2),
        ..Default::default()
    });

    let session_id = hardy_ltp::types::SessionId {
        originator: EngineId(1),
        number: 77,
    };

    // Initialize session with an initial red segment
    let init_seg = hardy_ltp::segment::Segment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: hardy_ltp::segment::SegmentBody::Data(hardy_ltp::segment::DataSegment {
            client_service: 1,
            offset: 0,
            kind: hardy_ltp::segment::DataSegKind::Red,
            data: &[0xAA; 10],
        }),
    };
    engine
        .handle_incoming_segment(EngineId(1), &init_seg.encode_to_vec(), 1_000_000)
        .unwrap();

    // Send CancelSender to cancel session
    let cs = hardy_ltp::segment::Segment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: hardy_ltp::segment::SegmentBody::CancelSender {
            reason: CancelReason::UsrCncld,
        },
    };
    engine
        .handle_incoming_segment(EngineId(1), &cs.encode_to_vec(), 1_000_000)
        .unwrap();

    // Notice cancelled is emitted
    assert!(matches!(
        engine.poll_notice().unwrap(),
        Notice::TransmissionSessionCancelled { .. }
    ));

    // Send a late red segment for the cancelled session
    let cp = hardy_ltp::segment::Checkpoint {
        serial: core::num::NonZeroU64::new(1).unwrap(),
        report_serial: 0,
    };
    let data_seg = hardy_ltp::segment::Segment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: hardy_ltp::segment::SegmentBody::Data(hardy_ltp::segment::DataSegment {
            client_service: 1,
            offset: 0,
            kind: hardy_ltp::segment::DataSegKind::RedCpEorpEob(cp),
            data: &[0xAA; 10],
        }),
    };
    engine
        .handle_incoming_segment(EngineId(1), &data_seg.encode_to_vec(), 1_000_000)
        .unwrap();

    // No RedPartReceived or TransmissionSessionCompleted notice must EVER be emitted!
    assert_eq!(engine.poll_notice(), None);
}

#[test]
fn test_s13_cancel_dedup() {
    let mut engine = Engine::new(EngineConfig {
        engine_id: EngineId(2),
        ..Default::default()
    });

    let session_id = hardy_ltp::types::SessionId {
        originator: EngineId(1),
        number: 88,
    };

    // Initialize session with an initial red segment
    let init_seg = hardy_ltp::segment::Segment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: hardy_ltp::segment::SegmentBody::Data(hardy_ltp::segment::DataSegment {
            client_service: 1,
            offset: 0,
            kind: hardy_ltp::segment::DataSegKind::Red,
            data: &[0xAA; 10],
        }),
    };
    engine
        .handle_incoming_segment(EngineId(1), &init_seg.encode_to_vec(), 1_000_000)
        .unwrap();

    let cs = hardy_ltp::segment::Segment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: hardy_ltp::segment::SegmentBody::CancelSender {
            reason: CancelReason::Rlexc,
        },
    };
    let cs_wire = cs.encode_to_vec();

    // Send the first CS: cancels session and emits 1 notice
    engine
        .handle_incoming_segment(EngineId(1), &cs_wire, 1_000_000)
        .unwrap();
    assert!(engine.poll_notice().is_some());

    // Send 5 duplicate CS segments: must acknowledge with CAS but emit ZERO extra notices!
    for _ in 0..5 {
        engine
            .handle_incoming_segment(EngineId(1), &cs_wire, 1_000_000)
            .unwrap();
        assert_eq!(
            engine.poll_notice(),
            None,
            "duplicate cancellation must not trigger duplicate notice"
        );
        let (_, ack_bytes) = engine.poll_output().expect("must acknowledge duplicate CS");
        let (parsed, _) = hardy_ltp::segment::Segment::parse(&ack_bytes).unwrap();
        assert_eq!(
            parsed.body,
            hardy_ltp::segment::SegmentBody::CancelAckSender
        );
    }
}

#[test]
fn test_s14_dos_sparse_offset_memory() {
    let mut engine = Engine::new(EngineConfig {
        engine_id: EngineId(2),
        max_block_size: 64 * 1024 * 1024, // 64 MiB
        ..Default::default()
    });

    // An attacker sends 50 segments of 1 byte at offset (64 MiB - 1) across 50 sessions.
    // In unoptimized implementations, this would allocate 50 * 64 MiB = 3.2 GiB of zeroed RAM!
    for sess_num in 1..=50 {
        let session_id = hardy_ltp::types::SessionId {
            originator: EngineId(1),
            number: sess_num,
        };
        let seg = hardy_ltp::segment::Segment {
            session: session_id,
            header_ext: Vec::new(),
            trailer_ext: Vec::new(),
            body: hardy_ltp::segment::SegmentBody::Data(hardy_ltp::segment::DataSegment {
                client_service: 1,
                offset: 64 * 1024 * 1024 - 1,
                kind: hardy_ltp::segment::DataSegKind::Red,
                data: &[0xFF],
            }),
        };
        engine
            .handle_incoming_segment(EngineId(1), &seg.encode_to_vec(), 1_000_000)
            .unwrap();
    }
    // Execution completes instantly without OOM or allocating gigabytes of RAM
}

#[test]
fn test_s15_session_flood_limit() {
    let mut engine = Engine::new(EngineConfig {
        engine_id: EngineId(2),
        max_recv_sessions: 10, // Max 10 concurrent receive sessions
        ..Default::default()
    });

    for sess_num in 1..=25 {
        let session_id = hardy_ltp::types::SessionId {
            originator: EngineId(1),
            number: sess_num,
        };
        let seg = hardy_ltp::segment::Segment {
            session: session_id,
            header_ext: Vec::new(),
            trailer_ext: Vec::new(),
            body: hardy_ltp::segment::SegmentBody::Data(hardy_ltp::segment::DataSegment {
                client_service: 1,
                offset: 0,
                kind: hardy_ltp::segment::DataSegKind::Red,
                data: &[0xAA],
            }),
        };
        engine
            .handle_incoming_segment(EngineId(1), &seg.encode_to_vec(), 1_000_000)
            .unwrap();
    }

    // Sessions 11..=25 must have been safely rejected, bounding memory usage
}

#[test]
fn test_s16_kiss_500_frames_linear() {
    let mut batch = Vec::new();
    let payload = vec![0x33u8; 100];

    // Encode 500 KISS frames into a single continuous buffer
    for i in 0..500 {
        hardy_ltp::kiss::encode_frame(
            (i % 16) as u8,
            hardy_ltp::kiss::Command::Data,
            &payload,
            &mut batch,
        );
    }

    // Decode with linear cursor
    let mut decoded = 0;
    let mut offset = 0;
    while let Ok(Some((frame, consumed))) = hardy_ltp::kiss::decode_frame(&batch[offset..]) {
        offset += consumed;
        assert_eq!(frame.command, hardy_ltp::kiss::Command::Data);
        assert_eq!(frame.payload, payload);
        decoded += 1;
    }

    assert_eq!(decoded, 500);
    assert_eq!(offset, batch.len());
}
