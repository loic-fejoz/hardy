//! Session representations for sending and receiving LTP blocks (RFC 5326 §8).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::num::NonZeroU64;

use bytes::Bytes;

use crate::range::RangeSet;
use crate::segment::ReportSegment;
use crate::types::{CancelReason, EngineId, SessionId};

/// A recorded checkpoint issued by the block sender.
#[derive(Debug, Clone)]
pub struct CheckpointRecord {
    /// Checkpoint serial number.
    pub serial: NonZeroU64,
    /// Report serial echoed by this checkpoint.
    pub report_serial: u64,
    /// Block offset of the checkpoint segment data.
    pub offset: u64,
    /// Payload length of the checkpoint segment.
    pub length: u64,
    /// End of red part indicator.
    pub is_eorp: bool,
    /// End of block indicator.
    pub is_eob: bool,
    /// Number of times this checkpoint has been transmitted.
    pub retries: u32,
}

/// Sender-side session tracking a transmitted block (RFC 5326 §8.1).
#[derive(Debug)]
pub struct SendSession {
    /// Session identifier.
    pub id: SessionId,
    /// Destination peer engine ID.
    pub peer: EngineId,
    /// Destination client service ID.
    pub client_service: u64,
    /// Retained block data until red part is fully acknowledged.
    pub block: Bytes,
    /// Length of the reliable (red) part in octets.
    pub red_len: u64,
    /// Most recently issued checkpoint serial.
    pub last_cp_serial: u64,
    /// Issued checkpoints awaiting report, keyed by checkpoint serial.
    pub checkpoints: BTreeMap<u64, CheckpointRecord>,
    /// Cumulative union of all received report claims.
    pub claims_received: RangeSet,
    /// Set of report serials already processed for deduplication.
    pub report_serials_seen: BTreeSet<u64>,
    /// True once the EOB segment has been queued/emitted.
    pub eob_sent: bool,
    /// Monotonic timestamp of last session activity in microseconds.
    pub last_activity: u64,
    /// Cancellation reason if this session is currently cancelling.
    pub cancel_reason: Option<CancelReason>,
    /// Number of cancellation segments transmitted.
    pub cancel_retries: u32,
}

impl SendSession {
    /// Creates a new sender session.
    #[must_use]
    pub fn new(
        id: SessionId,
        peer: EngineId,
        client_service: u64,
        block: Bytes,
        red_len: u64,
        initial_cp_serial: u64,
        now: u64,
    ) -> Self {
        Self {
            id,
            peer,
            client_service,
            block,
            red_len,
            last_cp_serial: initial_cp_serial,
            checkpoints: BTreeMap::new(),
            claims_received: RangeSet::new(),
            report_serials_seen: BTreeSet::new(),
            eob_sent: false,
            last_activity: now,
            cancel_reason: None,
            cancel_retries: 0,
        }
    }

    /// Returns true if the red part has been fully claimed and all block segments emitted.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.eob_sent && self.claims_received.covers(&(0..self.red_len))
    }
}

/// An issued report segment recorded by the receiver awaiting acknowledgment (RA).
#[derive(Debug, Clone)]
pub struct ReportRecord {
    /// Exact report segment body for byte-identical retransmission.
    pub report: ReportSegment,
    /// Number of times this report has been transmitted.
    pub retries: u32,
    /// True once an RA has acknowledged this report.
    pub acked: bool,
}

/// Receiver-side session tracking an incoming block (RFC 5326 §8.2).
#[derive(Debug)]
pub struct RecvSession {
    /// Session identifier.
    pub id: SessionId,
    /// Sender peer engine ID.
    pub peer: EngineId,
    /// Destination client service ID.
    pub client_service: u64,
    /// Reassembly buffer for the reliable (red) part.
    pub red_buf: Vec<u8>,
    /// Received red extents.
    pub red_received: RangeSet,
    /// Red-part total length (known when EORP arrives).
    pub red_part_len: Option<u64>,
    /// Total block length (known when EOB arrives).
    pub block_len: Option<u64>,
    /// True if the red part ends the block.
    pub red_ends_block: bool,
    /// Most recently issued report serial number.
    pub last_report_serial: u64,
    /// Issued reports keyed by report serial number.
    pub reports: BTreeMap<u64, ReportRecord>,
    /// Checkpoint serials answered -> report serial issued.
    pub cp_serials_answered: BTreeMap<u64, u64>,
    /// Union of claims acknowledged by RA.
    pub reported_coverage: RangeSet,
    /// True once the complete red part has been delivered as a notice.
    pub red_delivered: bool,
    /// Monotonic timestamp of last session activity in microseconds.
    pub last_activity: u64,
    /// Cancellation reason if this session is currently cancelling.
    pub cancel_reason: Option<CancelReason>,
    /// Number of cancellation segments transmitted.
    pub cancel_retries: u32,
}

impl RecvSession {
    /// Creates a new receiver session.
    #[must_use]
    pub fn new(
        id: SessionId,
        peer: EngineId,
        client_service: u64,
        initial_rs_serial: u64,
        now: u64,
    ) -> Self {
        Self {
            id,
            peer,
            client_service,
            red_buf: Vec::new(),
            red_received: RangeSet::new(),
            red_part_len: None,
            block_len: None,
            red_ends_block: false,
            last_report_serial: initial_rs_serial,
            reports: BTreeMap::new(),
            cp_serials_answered: BTreeMap::new(),
            reported_coverage: RangeSet::new(),
            red_delivered: false,
            last_activity: now,
            cancel_reason: None,
            cancel_retries: 0,
        }
    }

    /// Stores a red data segment into the reassembly buffer.
    pub fn insert_red(&mut self, offset: u64, data: &[u8], max_block_size: u64) -> bool {
        let Some(end) = offset.checked_add(data.len() as u64) else {
            return false;
        };
        if end > max_block_size {
            return false;
        }
        let Ok(start_idx) = usize::try_from(offset) else {
            return false;
        };
        let Ok(end_idx) = usize::try_from(end) else {
            return false;
        };

        if self.red_buf.len() < end_idx {
            self.red_buf.resize(end_idx, 0);
        }

        self.red_buf[start_idx..end_idx].copy_from_slice(data);
        self.red_received.insert(offset..end);
        true
    }

    /// Returns true if the complete red part has been received.
    #[must_use]
    pub fn is_red_complete(&self) -> bool {
        if let Some(len) = self.red_part_len {
            self.red_received.covers(&(0..len))
        } else {
            false
        }
    }
}
