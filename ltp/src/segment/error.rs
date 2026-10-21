//! Error types for LTP segment parsing.

use thiserror::Error;

use crate::sdnv;

/// Errors that can occur when parsing an LTP segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ParseError {
    /// An SDNV field was truncated or overflowed.
    #[error("bad SDNV: {0}")]
    Sdnv(#[from] sdnv::Error),

    /// Segment version nibble was not 0 (§3.1).
    #[error("unsupported LTP version nibble: {0}")]
    BadVersion(u8),

    /// Undefined segment type code (5, 6, 10, or 11; §3.1.2).
    #[error("undefined segment type code: {0}")]
    UndefinedType(u8),

    /// Input buffer ended unexpectedly before segment completion.
    #[error("segment truncated")]
    Truncated,

    /// A checkpoint or report serial number was zero (§3.2.1, §3.2.2).
    #[error("zero checkpoint or report serial number")]
    ZeroSerial,

    /// Report segment lower bound is greater than or equal to upper bound.
    #[error("report lower bound >= upper bound")]
    BoundsInvariant,

    /// Report claim count was zero or exceeded safety limits.
    #[error("report claim count invalid")]
    ClaimCountInvalid,

    /// A reception claim violated RFC 5326 §3.2.2 invariants.
    #[error("reception claim violated RFC 5326 §3.2.2 invariants")]
    ClaimInvariant,

    /// A cancellation segment carried a reserved reason code (`0x06`–`0xFF`).
    #[error("reserved cancel reason code: 0x{0:02x}")]
    ReservedReason(u8),
}
