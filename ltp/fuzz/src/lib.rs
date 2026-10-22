use arbitrary::Arbitrary;

/// Operation commands for structured LTP engine fuzzing.
#[derive(Debug, Arbitrary)]
pub enum EngineOp {
    /// Ingest a raw wire segment from a peer engine.
    IncomingSegment {
        /// Peer engine ID sending the segment.
        from: u64,
        /// Raw segment wire octets.
        data: Vec<u8>,
        /// Simulated monotonic timestamp in microseconds.
        now: u64,
    },
    /// Request a new block transmission to a peer.
    RequestTransmission {
        /// Destination engine ID.
        peer: u64,
        /// Application client service identifier.
        client_service: u64,
        /// Block content octets.
        block: Vec<u8>,
        /// Length of the reliable red prefix within the block.
        red_len: u64,
        /// Monotonic timestamp in microseconds.
        now: u64,
    },
    /// Advance the monotonic simulation clock.
    TimerTick {
        /// Monotonic timestamp in microseconds.
        now: u64,
    },
    /// Drain queued outbound segment transmissions.
    DrainOutputs,
    /// Drain generated client service notices.
    DrainNotices,
}
