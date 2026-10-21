//! Property tests for the LTP Segment AST and wire codec.

use core::num::NonZeroU64;
use std::vec::Vec;

use proptest::collection::vec as prop_vec;
use proptest::prelude::*;

use hardy_ltp::segment::{Checkpoint, DataSegKind, DataSegment, Segment, SegmentBody};
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
}
