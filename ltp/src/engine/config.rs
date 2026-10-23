//! Configuration parameters for an LTP engine instance.

use alloc::vec::Vec;

use crate::types::EngineId;

/// Configuration parameters for an LTP engine.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Local LTP engine identifier.
    pub engine_id: EngineId,
    /// Maximum client service data payload length per segment in octets (MTU limit).
    pub max_segment_payload_len: usize,
    /// Maximum retransmission attempts for an unacknowledged checkpoint.
    pub checkpoint_rtx_limit: u32,
    /// Maximum retransmission attempts for an unacknowledged report segment.
    pub report_rtx_limit: u32,
    /// Maximum retransmission attempts for a cancel segment.
    pub cancel_rtx_limit: u32,
    /// Estimated nominal round-trip time to peer in microseconds.
    pub rtt_micros: u64,
    /// Extra margin added to retransmission timers in microseconds.
    pub ack_margin_micros: u64,
    /// Maximum allowed block / red-buffer size in octets to prevent memory exhaustion (DoS).
    pub max_block_size: u64,
    /// Inactivity timeout in microseconds after which idle incomplete sessions are cancelled.
    pub session_inactivity_timeout_micros: u64,
    /// Initial session number generator start value.
    pub initial_session_number: u64,
    /// Maximum concurrent active receive sessions to mitigate DoS (default 1024).
    pub max_recv_sessions: usize,
    /// Maximum active unacknowledged reports tracked per session (default 64).
    pub max_reports_per_session: usize,
    /// Maximum reception claims included in a single report segment (default 20, RFC 5326 / ION limit).
    pub max_claims_per_report: usize,
    /// Allowed client service IDs (RFC 5326 §6.2).
    /// If `None`, any client service ID is accepted. If `Some(services)`, segments targeting
    /// an unregistered client service ID trigger session cancellation with `CR(UNREACH)`.
    pub allowed_client_services: Option<Vec<u64>>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            engine_id: EngineId(1),
            max_segment_payload_len: 1400,
            checkpoint_rtx_limit: 5,
            report_rtx_limit: 5,
            cancel_rtx_limit: 5,
            rtt_micros: 2_000_000,
            ack_margin_micros: 2_000_000,
            max_block_size: 64 * 1024 * 1024,              // 64 MiB
            session_inactivity_timeout_micros: 60_000_000, // 60s
            initial_session_number: 1,
            max_recv_sessions: 1024,
            max_reports_per_session: 64,
            max_claims_per_report: 20,
            allowed_client_services: None,
        }
    }
}

/// Timing parameters (RTT and ACK margin) for a specific peer LTP engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerTiming {
    /// Round-trip time in microseconds.
    pub rtt_micros: u64,
    /// Extra margin added to retransmission timers in microseconds.
    pub ack_margin_micros: u64,
}

impl PeerTiming {
    /// Constructs a new `PeerTiming` descriptor.
    #[must_use]
    pub const fn new(rtt_micros: u64, ack_margin_micros: u64) -> Self {
        Self {
            rtt_micros,
            ack_margin_micros,
        }
    }

    /// Total timeout duration (RTT + ack margin) in microseconds.
    #[must_use]
    pub const fn timeout_duration_micros(&self) -> u64 {
        self.rtt_micros.saturating_add(self.ack_margin_micros)
    }
}
