#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

use hardy_ltp::{
    engine::{Engine, EngineConfig},
    types::EngineId,
};
use hardy_ltp_fuzz::EngineOp;

fuzz_target!(|ops: Vec<EngineOp>| {
    let config = EngineConfig {
        engine_id: EngineId(1),
        max_segment_payload_len: 512,
        max_block_size: 64 * 1024,
        max_recv_sessions: 32,
        checkpoint_rtx_limit: 3,
        report_rtx_limit: 3,
        cancel_rtx_limit: 3,
        ..EngineConfig::default()
    };

    let mut engine = Engine::new(config);

    // Limit execution length to keep fuzz iterations deterministic and fast
    for op in ops.into_iter().take(50) {
        match op {
            EngineOp::IncomingSegment { from, data, now } => {
                let _ = engine.handle_incoming_segment(EngineId(from), &data, now);
            }
            EngineOp::RequestTransmission {
                peer,
                client_service,
                mut block,
                red_len,
                now,
            } => {
                // Bound block length to prevent excessive allocations during fuzzing
                block.truncate(8 * 1024);
                let _ = engine.request_transmission(
                    EngineId(peer),
                    client_service,
                    Bytes::from(block),
                    red_len,
                    now,
                );
            }
            EngineOp::TimerTick { now } => {
                engine.handle_timer_tick(now);
            }
            EngineOp::DrainOutputs => {
                let mut count = 0;
                while engine.poll_output().is_some() && count < 64 {
                    count += 1;
                }
            }
            EngineOp::DrainNotices => {
                let mut count = 0;
                while engine.poll_notice().is_some() && count < 64 {
                    count += 1;
                }
            }
        }
    }
});
