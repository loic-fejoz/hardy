//! Property tests for the LTP Segment AST and wire codec.

use core::num::NonZeroU64;
use std::vec::Vec;

use proptest::collection::vec as prop_vec;
use proptest::prelude::*;

use hardy_ltp::segment::{
    Checkpoint, DataSegKind, DataSegment, ReceptionClaim, ReportSegment, Segment, SegmentBody,
};
use hardy_ltp::types::{CancelReason, EngineId, SessionId};

// Generators for arbitrary valid Segment structures
fn arb_engine_id() -> impl Strategy<Value = EngineId> {
    any::<u64>().prop_map(EngineId)
}

fn arb_session_id() -> impl Strategy<Value = SessionId> {
    (arb_engine_id(), any::<u64>())
        .prop_map(|(originator, number)| SessionId { originator, number })
}

fn arb_cancel_reason() -> impl Strategy<Value = CancelReason> {
    (0u8..=5).prop_map(|code| CancelReason::from_code(code).expect("valid code"))
}

fn arb_checkpoint() -> impl Strategy<Value = Checkpoint> {
    (1u64..=u64::MAX, any::<u64>()).prop_map(|(serial, report_serial)| Checkpoint {
        serial: NonZeroU64::new(serial).expect("non zero"),
        report_serial,
    })
}

fn arb_data_kind() -> impl Strategy<Value = DataSegKind> {
    prop_oneof![
        Just(DataSegKind::Red),
        arb_checkpoint().prop_map(DataSegKind::RedCp),
        arb_checkpoint().prop_map(DataSegKind::RedCpEorp),
        arb_checkpoint().prop_map(DataSegKind::RedCpEorpEob),
        Just(DataSegKind::Green),
        Just(DataSegKind::GreenEob),
    ]
}

fn arb_report_segment() -> impl Strategy<Value = ReportSegment> {
    (
        1u64..=u64::MAX,
        any::<u64>(),
        0u64..=1_000_000,
        1u64..=50_000,
    )
        .prop_flat_map(|(raw_serial, cp_serial, lower_bound, scope)| {
            let upper_bound = lower_bound + scope;
            prop_vec((1u64..=1000, 0u64..=1000), 0..=8).prop_map(move |items| {
                let mut claims = Vec::new();
                let mut current_offset = 0;
                for (len, gap) in items {
                    if current_offset + len <= scope {
                        claims.push(ReceptionClaim {
                            offset: current_offset,
                            length: len,
                        });
                        current_offset += len + gap;
                    } else {
                        break;
                    }
                }
                ReportSegment {
                    report_serial: NonZeroU64::new(raw_serial).unwrap(),
                    checkpoint_serial: cp_serial,
                    upper_bound,
                    lower_bound,
                    claims,
                }
            })
        })
}

proptest! {
    #[test]
    fn segment_parse_never_panics(bytes in prop_vec(any::<u8>(), 0..256)) {
        let _ = Segment::parse(&bytes);
    }

    #[test]
    fn data_segment_roundtrip(
        session in arb_session_id(),
        client_service in any::<u64>(),
        offset in any::<u64>(),
        kind in arb_data_kind(),
        payload in prop_vec(any::<u8>(), 0..256),
    ) {
        let seg = Segment {
            session,
            header_ext: Vec::new(),
            trailer_ext: Vec::new(),
            body: SegmentBody::Data(DataSegment {
                client_service,
                offset,
                kind,
                data: &payload,
            }),
        };

        let encoded = seg.encode_to_vec();
        let (decoded, consumed) = Segment::parse(&encoded).expect("valid encoded data segment must parse");

        prop_assert_eq!(consumed, encoded.len());
        prop_assert_eq!(decoded.session, seg.session);
        prop_assert_eq!(decoded.type_code(), seg.type_code());
        prop_assert_eq!(decoded.body, seg.body);
    }

    #[test]
    fn report_ack_roundtrip(
        session in arb_session_id(),
        report_serial in any::<u64>(),
    ) {
        let seg = Segment {
            session,
            header_ext: Vec::new(),
            trailer_ext: Vec::new(),
            body: SegmentBody::ReportAck { report_serial },
        };

        let encoded = seg.encode_to_vec();
        let (decoded, consumed) = Segment::parse(&encoded).expect("valid report ack must parse");

        prop_assert_eq!(consumed, encoded.len());
        prop_assert_eq!(decoded.body, seg.body);
    }

    #[test]
    fn cancel_segments_roundtrip(
        session in arb_session_id(),
        reason in arb_cancel_reason(),
        is_sender in any::<bool>(),
    ) {
        let body = if is_sender {
            SegmentBody::CancelSender { reason }
        } else {
            SegmentBody::CancelReceiver { reason }
        };

        let seg = Segment {
            session,
            header_ext: Vec::new(),
            trailer_ext: Vec::new(),
            body,
        };

        let encoded = seg.encode_to_vec();
        let (decoded, consumed) = Segment::parse(&encoded).expect("valid cancel segment must parse");

        prop_assert_eq!(consumed, encoded.len());
        prop_assert_eq!(decoded.body, seg.body);
    }

    #[test]
    fn cancel_ack_segments_roundtrip(
        session in arb_session_id(),
        is_sender in any::<bool>(),
    ) {
        let body = if is_sender {
            SegmentBody::CancelAckSender
        } else {
            SegmentBody::CancelAckReceiver
        };

        let seg = Segment {
            session,
            header_ext: Vec::new(),
            trailer_ext: Vec::new(),
            body,
        };

        let encoded = seg.encode_to_vec();
        let (decoded, consumed) = Segment::parse(&encoded).expect("valid cancel ack segment must parse");

        prop_assert_eq!(consumed, encoded.len());
        prop_assert_eq!(decoded.body, seg.body);
    }

    #[test]
    fn report_segment_roundtrip(
        session in arb_session_id(),
        report in arb_report_segment(),
    ) {
        let seg = Segment {
            session,
            header_ext: Vec::new(),
            trailer_ext: Vec::new(),
            body: SegmentBody::Report(report),
        };

        let encoded = seg.encode_to_vec();
        prop_assert_eq!(
            encoded.len(),
            seg.exact_encoded_len(&seg.header_ext, &seg.trailer_ext)
        );

        let (decoded, consumed) = Segment::parse(&encoded).expect("valid report segment must parse");

        prop_assert_eq!(consumed, encoded.len());
        prop_assert_eq!(decoded.session, seg.session);
        prop_assert_eq!(decoded.type_code(), seg.type_code());
        prop_assert_eq!(decoded.body, seg.body);
    }

    #[test]
    fn report_segment_bounds_invariant_rejected(
        lower in 100u64..=1000,
        upper in 0u64..=100,
    ) {
        let seg = ReportSegment {
            report_serial: NonZeroU64::new(1).unwrap(),
            checkpoint_serial: 0,
            upper_bound: upper,
            lower_bound: lower,
            claims: Vec::new(),
        };
        let s = Segment {
            session: SessionId {
                originator: EngineId(1),
                number: 1,
            },
            header_ext: Vec::new(),
            trailer_ext: Vec::new(),
            body: SegmentBody::Report(seg),
        };
        let encoded = s.encode_to_vec();
        prop_assert!(Segment::parse(&encoded).is_err());
    }
}
