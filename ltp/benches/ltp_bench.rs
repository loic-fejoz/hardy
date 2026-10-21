//! Criterion benchmarks for high-throughput LTP and KISS operations.

use core::hint::black_box;
use core::num::NonZeroU64;
use std::vec::Vec;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use hardy_ltp::kiss::{self, Command};
use hardy_ltp::sdnv;
use hardy_ltp::segment::{
    Checkpoint, DataSegKind, DataSegment, ReceptionClaim, ReportSegment, Segment, SegmentBody,
};
use hardy_ltp::types::{EngineId, SessionId};

fn bench_sdnv(c: &mut Criterion) {
    let mut group = c.benchmark_group("sdnv");

    group.bench_function("encode_1byte", |b| {
        let mut buf = Vec::with_capacity(16);
        b.iter(|| {
            buf.clear();
            sdnv::encode(black_box(42), &mut buf);
            black_box(&buf);
        })
    });

    group.bench_function("encode_multibyte", |b| {
        let mut buf = Vec::with_capacity(16);
        b.iter(|| {
            buf.clear();
            sdnv::encode(black_box(1_000_000), &mut buf);
            black_box(&buf);
        })
    });

    group.bench_function("encode_u64_max", |b| {
        let mut buf = Vec::with_capacity(16);
        b.iter(|| {
            buf.clear();
            sdnv::encode(black_box(u64::MAX), &mut buf);
            black_box(&buf);
        })
    });

    let enc_1b = [0x2Au8];
    group.bench_function("decode_1byte", |b| {
        b.iter(|| {
            let res = sdnv::decode(black_box(&enc_1b)).unwrap();
            black_box(res);
        })
    });

    let mut enc_multi = Vec::new();
    sdnv::encode(1_000_000, &mut enc_multi);
    group.bench_function("decode_multibyte", |b| {
        b.iter(|| {
            let res = sdnv::decode(black_box(&enc_multi)).unwrap();
            black_box(res);
        })
    });

    group.finish();
}

fn bench_kiss(c: &mut Criterion) {
    let mut group = c.benchmark_group("kiss");

    for size in [1024, 65536] {
        // Typical binary payload with sparse escape characters (approx 1 per 256 bytes)
        let mut payload = vec![0xAAu8; size];
        for i in (0..size).step_by(256) {
            payload[i] = kiss::FEND;
        }

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("escape", size), &payload, |b, data| {
            let mut out = Vec::with_capacity(size + size / 32);
            b.iter(|| {
                out.clear();
                kiss::escape(black_box(data), &mut out);
                black_box(&out);
            })
        });

        let mut escaped = Vec::new();
        kiss::escape(&payload, &mut escaped);

        group.bench_with_input(BenchmarkId::new("unescape", size), &escaped, |b, data| {
            b.iter(|| {
                let unescaped = kiss::unescape(black_box(data)).unwrap();
                black_box(unescaped);
            })
        });
    }

    // Benchmark frame roundtrip (1400-byte MTU payload)
    let mtu_payload = vec![0x42u8; 1400];
    group.throughput(Throughput::Bytes(1400));
    group.bench_function("frame_roundtrip_1400B", |b| {
        let mut frame_buf = Vec::with_capacity(1500);
        b.iter(|| {
            frame_buf.clear();
            kiss::encode_frame(0, Command::Data, black_box(&mtu_payload), &mut frame_buf);
            let (frame, consumed) = kiss::decode_frame(black_box(&frame_buf)).unwrap().unwrap();
            black_box((frame, consumed));
        })
    });

    group.finish();
}

fn bench_segment(c: &mut Criterion) {
    let mut group = c.benchmark_group("segment");

    let payload = vec![0x55u8; 1400];
    let session = SessionId {
        originator: EngineId(100),
        number: 42,
    };
    let cp = Checkpoint {
        serial: NonZeroU64::new(1).unwrap(),
        report_serial: 0,
    };

    let data_seg = Segment {
        session,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::Data(DataSegment {
            client_service: 1,
            offset: 0,
            kind: DataSegKind::RedCpEorpEob(cp),
            data: &payload,
        }),
    };

    let encoded_data_seg = data_seg.encode_to_vec();
    group.throughput(Throughput::Bytes(encoded_data_seg.len() as u64));

    group.bench_function("encode_data_1400B", |b| {
        b.iter(|| {
            let bytes = black_box(&data_seg).encode_to_vec();
            black_box(bytes);
        })
    });

    group.bench_function("parse_data_1400B", |b| {
        b.iter(|| {
            let (seg, consumed) = Segment::parse(black_box(&encoded_data_seg)).unwrap();
            black_box((seg, consumed));
        })
    });

    // 20 claims report segment
    let mut claims = Vec::with_capacity(20);
    for i in 0..20 {
        claims.push(ReceptionClaim {
            offset: i * 100,
            length: 50,
        });
    }

    let report_seg = Segment {
        session,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::Report(ReportSegment {
            report_serial: NonZeroU64::new(10).unwrap(),
            checkpoint_serial: 1,
            upper_bound: 2000,
            lower_bound: 0,
            claims,
        }),
    };

    let encoded_report = report_seg.encode_to_vec();

    group.bench_function("encode_report_20claims", |b| {
        b.iter(|| {
            let bytes = black_box(&report_seg).encode_to_vec();
            black_box(bytes);
        })
    });

    group.bench_function("parse_report_20claims", |b| {
        b.iter(|| {
            let (seg, consumed) = Segment::parse(black_box(&encoded_report)).unwrap();
            black_box((seg, consumed));
        })
    });

    group.finish();
}

criterion_group!(benches, bench_sdnv, bench_kiss, bench_segment);
criterion_main!(benches);
