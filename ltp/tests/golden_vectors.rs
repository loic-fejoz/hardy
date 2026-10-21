//! Conformance tests using pinned golden vectors from RFC 5326 and reference specifications.

use core::num::NonZeroU64;
use std::vec::Vec;

use hardy_ltp::segment::{
    Checkpoint, DataSegKind, ParseError, ReceptionClaim, Segment, SegmentBody,
};
use hardy_ltp::types::{CancelReason, EngineId};

fn unhex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|pair| u8::from_str_radix(pair, 16).expect("valid hex byte"))
        .collect()
}

#[test]
fn golden_data_segment_red_plain() {
    // Type 0: Red data, not CP, not EORP, not EOB
    // Session: originator 42, session 7. Extensions: 0.
    // Client service: 1, offset: 0, length: 10, data: "hello mars"
    let hex = "00 2a 07 00 01 00 0a 68 65 6c 6c 6f 20 6d 61 72 73";
    let bytes = unhex(hex);

    let (seg, consumed) = Segment::parse(&bytes).expect("parse should succeed");
    assert_eq!(consumed, bytes.len());
    assert_eq!(seg.type_code(), 0);
    assert_eq!(seg.session.originator, EngineId(42));
    assert_eq!(seg.session.number, 7);
    assert!(seg.header_ext.is_empty());
    assert!(seg.trailer_ext.is_empty());

    match &seg.body {
        SegmentBody::Data(ds) => {
            assert_eq!(ds.client_service, 1);
            assert_eq!(ds.offset, 0);
            assert_eq!(ds.kind, DataSegKind::Red);
            assert_eq!(ds.data, b"hello mars");
        }
        _ => panic!("expected Data segment"),
    }

    assert_eq!(seg.encode_to_vec(), bytes);
}

#[test]
fn golden_data_segment_red_cp_original() {
    // Type 1: Checkpoint on original transmission (report serial 0)
    // CP serial = 0x1234 (4660) -> encoded as 0xA4 0x34
    // Payload: "chunk"
    let hex = "01 2a 07 00 01 95 70 05 a4 34 00 63 68 75 6e 6b";
    let bytes = unhex(hex);

    let (seg, consumed) = Segment::parse(&bytes).expect("parse should succeed");
    assert_eq!(consumed, bytes.len());
    assert_eq!(seg.type_code(), 1);

    match &seg.body {
        SegmentBody::Data(ds) => {
            assert_eq!(ds.client_service, 1);
            assert_eq!(ds.offset, 2800);
            assert_eq!(
                ds.kind,
                DataSegKind::RedCp(Checkpoint {
                    serial: NonZeroU64::new(4660).unwrap(),
                    report_serial: 0,
                })
            );
            assert_eq!(ds.data, b"chunk");
        }
        _ => panic!("expected Data segment"),
    }

    assert_eq!(seg.encode_to_vec(), bytes);
}

#[test]
fn golden_data_segment_red_cp_eorp_eob() {
    // Type 3: Final segment of fully-red block (CP + EORP + EOB)
    let hex = "03 2a 07 00 01 8a 78 01 a4 34 00 78";
    let bytes = unhex(hex);

    let (seg, consumed) = Segment::parse(&bytes).expect("parse should succeed");
    assert_eq!(consumed, bytes.len());
    assert_eq!(seg.type_code(), 3);

    match &seg.body {
        SegmentBody::Data(ds) => {
            assert_eq!(ds.client_service, 1);
            assert_eq!(ds.offset, 1400);
            assert_eq!(
                ds.kind,
                DataSegKind::RedCpEorpEob(Checkpoint {
                    serial: NonZeroU64::new(4660).unwrap(),
                    report_serial: 0,
                })
            );
            assert_eq!(ds.data, b"x");
        }
        _ => panic!("expected Data segment"),
    }

    assert_eq!(seg.encode_to_vec(), bytes);
}

#[test]
fn golden_data_segment_green_eob() {
    // Type 7: Green EOB (block's final segment)
    let hex = "07 2a 07 00 01 c6 28 03 66 69 6e";
    let bytes = unhex(hex);

    let (seg, consumed) = Segment::parse(&bytes).expect("parse should succeed");
    assert_eq!(consumed, bytes.len());
    assert_eq!(seg.type_code(), 7);

    match &seg.body {
        SegmentBody::Data(ds) => {
            assert_eq!(ds.client_service, 1);
            assert_eq!(ds.offset, 9000);
            assert_eq!(ds.kind, DataSegKind::GreenEob);
            assert_eq!(ds.data, b"fin");
        }
        _ => panic!("expected Data segment"),
    }

    assert_eq!(seg.encode_to_vec(), bytes);
}

#[test]
fn golden_report_segment_rfc_worked_example() {
    // RFC 5326 §3.2.2 worked example:
    // Lower bound: 1000, Upper bound: 6000
    // Claims: (offset 0, length 2000) and (offset 3000, length 500)
    // Relative to lower bound!
    let hex = "08 2a 07 00 a7 08 8d 25 ae 70 87 68 02 00 8f 50 97 38 83 74";
    let bytes = unhex(hex);

    let (seg, consumed) = Segment::parse(&bytes).expect("parse should succeed");
    assert_eq!(consumed, bytes.len());
    assert_eq!(seg.type_code(), 8);

    match &seg.body {
        SegmentBody::Report(rs) => {
            assert_eq!(rs.report_serial, NonZeroU64::new(5000).unwrap());
            assert_eq!(rs.checkpoint_serial, 1701);
            assert_eq!(rs.upper_bound, 6000);
            assert_eq!(rs.lower_bound, 1000);
            assert_eq!(
                rs.claims,
                vec![
                    ReceptionClaim {
                        offset: 0,
                        length: 2000
                    },
                    ReceptionClaim {
                        offset: 3000,
                        length: 500
                    },
                ]
            );
        }
        _ => panic!("expected Report segment"),
    }

    assert_eq!(seg.encode_to_vec(), bytes);
}

#[test]
fn golden_report_acknowledgment() {
    // Type 9: Report Acknowledgment (RA)
    // Originator: 42, Session: 7. Exts: 0. Report serial: 5000 (0xA7 0x08)
    let hex = "09 2a 07 00 a7 08";
    let bytes = unhex(hex);

    let (seg, consumed) = Segment::parse(&bytes).expect("parse should succeed");
    assert_eq!(consumed, bytes.len());
    assert_eq!(seg.type_code(), 9);

    match &seg.body {
        SegmentBody::ReportAck { report_serial } => {
            assert_eq!(*report_serial, 5000);
        }
        _ => panic!("expected ReportAck segment"),
    }

    assert_eq!(seg.encode_to_vec(), bytes);
}

#[test]
fn golden_cancellation_segments() {
    // Type 12: Cancel Sender (CS), Reason: USR_CNCLD (0x00)
    let cs_bytes = unhex("0c 2a 07 00 00");
    let (cs, _) = Segment::parse(&cs_bytes).expect("parse CS");
    assert_eq!(cs.type_code(), 12);
    assert_eq!(
        cs.body,
        SegmentBody::CancelSender {
            reason: CancelReason::UsrCncld
        }
    );
    assert_eq!(cs.encode_to_vec(), cs_bytes);

    // Type 13: Cancel Ack Sender (CAS)
    let cas_bytes = unhex("0d 2a 07 00");
    let (cas, _) = Segment::parse(&cas_bytes).expect("parse CAS");
    assert_eq!(cas.type_code(), 13);
    assert_eq!(cas.body, SegmentBody::CancelAckSender);
    assert_eq!(cas.encode_to_vec(), cas_bytes);

    // Type 14: Cancel Receiver (CR), Reason: RLEXC (0x02)
    let cr_bytes = unhex("0e 2a 07 00 02");
    let (cr, _) = Segment::parse(&cr_bytes).expect("parse CR");
    assert_eq!(cr.type_code(), 14);
    assert_eq!(
        cr.body,
        SegmentBody::CancelReceiver {
            reason: CancelReason::Rlexc
        }
    );
    assert_eq!(cr.encode_to_vec(), cr_bytes);

    // Type 15: Cancel Ack Receiver (CAR)
    let car_bytes = unhex("0f 2a 07 00");
    let (car, _) = Segment::parse(&car_bytes).expect("parse CAR");
    assert_eq!(car.type_code(), 15);
    assert_eq!(car.body, SegmentBody::CancelAckReceiver);
    assert_eq!(car.encode_to_vec(), car_bytes);
}

#[test]
fn golden_segment_with_extensions() {
    // Segment with 1 header extension (tag 0x01, len 3, val "foo")
    // and 1 trailer extension (tag 0x00, len 2, val "ok")
    // Ext counts: (1 << 4) | 1 = 0x11
    // Header ext: tag 0x01, len 0x03, "foo" (0x66 0x6f 0x6f)
    // Body: ReportAck for serial 42
    // Trailer ext: tag 0x00, len 0x02, "ok" (0x6f 0x6b)
    let expected = unhex("09 2a 07 11 01 03 66 6f 6f 2a 00 02 6f 6b");
    let (seg, consumed) = Segment::parse(&expected).expect("parse extension segment");
    assert_eq!(consumed, expected.len());
    assert_eq!(seg.header_ext.len(), 1);
    assert_eq!(seg.header_ext[0].tag, 0x01);
    assert_eq!(seg.header_ext[0].value, b"foo");
    assert_eq!(seg.trailer_ext.len(), 1);
    assert_eq!(seg.trailer_ext[0].tag, 0x00);
    assert_eq!(seg.trailer_ext[0].value, b"ok");
    assert_eq!(seg.encode_to_vec(), expected);
}

#[test]
fn reject_malformed_segments() {
    // Non-zero version: 0x10 (version 1)
    let bad_ver = unhex("10 2a 07 00");
    assert_eq!(Segment::parse(&bad_ver), Err(ParseError::BadVersion(1)));

    // Undefined segment type codes: 5, 6, 10, 11
    for code in [5, 6, 10, 11] {
        let bad_type = vec![code, 0x2a, 0x07, 0x00];
        assert_eq!(
            Segment::parse(&bad_type),
            Err(ParseError::UndefinedType(code))
        );
    }

    // Zero checkpoint serial in CP segment: type 1, CP serial = 0
    let zero_cp = unhex("01 2a 07 00 01 00 01 00 00 61");
    assert_eq!(Segment::parse(&zero_cp), Err(ParseError::ZeroSerial));

    // Zero report serial in RS segment: type 8, RS serial = 0
    let zero_rs = unhex("08 2a 07 00 00 00 0a 00 01 00 0a");
    assert_eq!(Segment::parse(&zero_rs), Err(ParseError::ZeroSerial));

    // RS lower bound >= upper bound: upper 500, lower 1000
    let inv_bounds = unhex("08 2a 07 00 01 00 83 74 87 68 01 00 05");
    assert_eq!(
        Segment::parse(&inv_bounds),
        Err(ParseError::BoundsInvariant)
    );

    // RS claim length == 0
    let zero_claim_len = unhex("08 2a 07 00 01 00 0a 00 01 00 00");
    assert_eq!(
        Segment::parse(&zero_claim_len),
        Err(ParseError::ClaimInvariant)
    );

    // RS claim extends beyond scope: scope 10, claim length 11
    let over_claim = unhex("08 2a 07 00 01 00 0a 00 01 00 0b");
    assert_eq!(Segment::parse(&over_claim), Err(ParseError::ClaimInvariant));

    // Reserved cancellation reason code: 0x06
    let res_reason = unhex("0c 2a 07 00 06");
    assert_eq!(
        Segment::parse(&res_reason),
        Err(ParseError::ReservedReason(6))
    );
}
