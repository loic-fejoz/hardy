//! LTP segment model and wire codec (RFC 5326 §3).

use alloc::vec::Vec;
use core::num::NonZeroU64;

use crate::types::{CancelReason, SessionId};

mod error;
mod parse;
mod write;

pub use error::ParseError;

/// One header or trailer extension TLV (RFC 5326 §3.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extension<'a> {
    /// Extension tag identifier.
    pub tag: u8,
    /// Raw extension value bytes.
    pub value: &'a [u8],
}

/// A parsed LTP segment (RFC 5326 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment<'a> {
    /// Session identifier this segment belongs to.
    pub session: SessionId,
    /// Header extension TLVs (0..=15).
    pub header_ext: Vec<Extension<'a>>,
    /// Trailer extension TLVs (0..=15).
    pub trailer_ext: Vec<Extension<'a>>,
    /// Type-specific segment payload.
    pub body: SegmentBody<'a>,
}

/// Segment body, classified by type code (RFC 5326 §3.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentBody<'a> {
    /// Types 0..=4, 7: Application client service data segment.
    Data(DataSegment<'a>),
    /// Type 8: Reception report segment (RS).
    Report(ReportSegment),
    /// Type 9: Report acknowledgment (RA).
    ReportAck {
        /// Serial number of the report being acknowledged.
        report_serial: u64,
    },
    /// Type 12: Cancellation segment from block sender (CS).
    CancelSender {
        /// Reason for cancellation.
        reason: CancelReason,
    },
    /// Type 13: Cancellation acknowledgment to block sender (CAS). Empty content.
    CancelAckSender,
    /// Type 14: Cancellation segment from block receiver (CR).
    CancelReceiver {
        /// Reason for cancellation.
        reason: CancelReason,
    },
    /// Type 15: Cancellation acknowledgment to block receiver (CAR). Empty content.
    CancelAckReceiver,
}

/// Application client service data segment (RFC 5326 §3.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSegment<'a> {
    /// Destination client service identifier (e.g. 1 for BPv7, RFC 7116).
    pub client_service: u64,
    /// Byte offset of this data within the transmitted block.
    pub offset: u64,
    /// Category, checkpointing, and block boundary flags.
    pub kind: DataSegKind,
    /// Client service payload data.
    pub data: &'a [u8],
}

/// Classification of a data segment (RFC 5326 §3.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSegKind {
    /// Type 0: Red data, not a checkpoint, not EORP, not EOB.
    Red,
    /// Type 1: Red data, checkpoint, not EORP, not EOB.
    RedCp(Checkpoint),
    /// Type 2: Red data, checkpoint, end of red part (EORP), not EOB.
    RedCpEorp(Checkpoint),
    /// Type 3: Red data, checkpoint, end of red part, end of block (EOB).
    RedCpEorpEob(Checkpoint),
    /// Type 4: Green data, not EOB.
    Green,
    /// Type 7: Green data, end of block (EOB).
    GreenEob,
}

impl DataSegKind {
    /// Returns true if this data segment is part of the reliable (red) part.
    #[must_use]
    pub fn is_red(self) -> bool {
        !matches!(self, Self::Green | Self::GreenEob)
    }

    /// Returns the checkpoint fields if this data segment is a checkpoint.
    #[must_use]
    pub fn checkpoint(self) -> Option<Checkpoint> {
        match self {
            Self::RedCp(cp) | Self::RedCpEorp(cp) | Self::RedCpEorpEob(cp) => Some(cp),
            Self::Red | Self::Green | Self::GreenEob => None,
        }
    }

    /// Returns true if this segment marks the end of the red part (EORP).
    #[must_use]
    pub fn is_eorp(self) -> bool {
        matches!(self, Self::RedCpEorp(_) | Self::RedCpEorpEob(_))
    }

    /// Returns true if this segment marks the end of the block (EOB).
    #[must_use]
    pub fn is_eob(self) -> bool {
        matches!(self, Self::RedCpEorpEob(_) | Self::GreenEob)
    }
}

/// Checkpoint serial fields carried by checkpoint data segments (RFC 5326 §3.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// Checkpoint serial number (strictly non-zero).
    pub serial: NonZeroU64,
    /// Serial of the report segment that triggered this checkpoint (or 0 for initial send).
    pub report_serial: u64,
}

/// A reception report segment (RS, RFC 5326 §3.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportSegment {
    /// Report serial number (strictly non-zero).
    pub report_serial: NonZeroU64,
    /// Serial of the checkpoint that elicited this report (or 0 for asynchronous reports).
    pub checkpoint_serial: u64,
    /// Scope upper bound (exclusive offset in block).
    pub upper_bound: u64,
    /// Scope lower bound (inclusive offset in block).
    pub lower_bound: u64,
    /// List of reception claims within the scope.
    pub claims: Vec<ReceptionClaim>,
}

/// A reception claim within a report segment (RFC 5326 §3.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceptionClaim {
    /// Offset of received data relative to the report's `lower_bound`.
    pub offset: u64,
    /// Length of contiguous received data in octets (at least 1).
    pub length: u64,
}

impl Segment<'_> {
    /// Returns the 4-bit segment type code for this segment.
    #[must_use]
    pub fn type_code(&self) -> u8 {
        match &self.body {
            SegmentBody::Data(ds) => match ds.kind {
                DataSegKind::Red => 0,
                DataSegKind::RedCp(_) => 1,
                DataSegKind::RedCpEorp(_) => 2,
                DataSegKind::RedCpEorpEob(_) => 3,
                DataSegKind::Green => 4,
                DataSegKind::GreenEob => 7,
            },
            SegmentBody::Report(_) => 8,
            SegmentBody::ReportAck { .. } => 9,
            SegmentBody::CancelSender { .. } => 12,
            SegmentBody::CancelAckSender => 13,
            SegmentBody::CancelReceiver { .. } => 14,
            SegmentBody::CancelAckReceiver => 15,
        }
    }
}
