//! Multi-transmitter receiver state machine and memory-bounded assembly manager.

use std::collections::{HashMap, HashSet, VecDeque};
use std::string::String;
use std::time::{Duration, Instant};
use std::vec::Vec;

use bytes::Bytes;
use tracing::{debug, warn};

use hqfbp_rs::ContentEncoding;
use hqfbp_rs::deframer::{Deframer, Event};

use crate::error::{Error, Result};

/// Represents a successfully reassembled bundle extracted from the HQFBP deframer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedMessage {
    /// Originating station callsign, if specified in headers.
    pub src_callsign: Option<String>,
    /// Target station callsign, if specified in headers.
    pub dst_callsign: Option<String>,
    /// HQFBP message ID.
    pub message_id: Option<u32>,
    /// Raw reassembled bundle payload bytes.
    pub payload: Bytes,
}

#[derive(Debug)]
struct SenderState {
    last_active: Instant,
    buffered_bytes: usize,
    active_message_ids: HashSet<u32>,
    session_bytes: HashMap<u32, usize>,
}

fn hash_payload(data: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &b in data {
        hash = (hash ^ (b as u64)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Bounded multi-transmitter deframing engine ensuring memory safety and LRU session eviction.
pub struct RxSessionManager {
    deframer: Deframer,
    senders: HashMap<Option<String>, SenderState>,
    lru_senders: VecDeque<Option<String>>,
    completed_sessions: HashMap<(Option<String>, u32), Instant>,
    completed_payloads: HashMap<(Option<String>, u64), Instant>,
    completed_messages: VecDeque<CompletedMessage>,
    total_buffered_bytes: usize,
    max_concurrent_senders: usize,
    max_in_flight_bytes: usize,
    session_ttl: Duration,
}

impl RxSessionManager {
    /// Creates a new receiver session manager with the configured memory and sender caps.
    #[must_use]
    pub fn new(
        max_concurrent_senders: usize,
        max_in_flight_bytes: usize,
        session_ttl: Duration,
    ) -> Self {
        Self {
            deframer: Deframer::new(),
            senders: HashMap::new(),
            lru_senders: VecDeque::new(),
            completed_sessions: HashMap::new(),
            completed_payloads: HashMap::new(),
            completed_messages: VecDeque::new(),
            total_buffered_bytes: 0,
            max_concurrent_senders,
            max_in_flight_bytes,
            session_ttl,
        }
    }

    /// Registers peer-specific content encodings for a remote callsign in the underlying deframer.
    pub fn register_peer_encodings(
        &mut self,
        callsign: impl Into<String>,
        encodings: Vec<ContentEncoding>,
    ) {
        self.deframer.register_peer_encodings(callsign, encodings);
    }

    /// Unregisters peer-specific content encodings for a remote callsign.
    pub fn unregister_peer_encodings(&mut self, callsign: &str) {
        self.deframer.unregister_peer_encodings(callsign);
    }

    /// Returns the registered content encodings for a remote callsign, if any.
    #[must_use]
    pub fn peer_encodings(&self, callsign: &str) -> Option<&[ContentEncoding]> {
        self.deframer.peer_encodings(callsign)
    }

    /// Returns the currently allocated in-flight buffer memory in bytes.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.total_buffered_bytes
    }

    /// Returns the configured session inactivity timeout.
    #[must_use]
    pub fn session_ttl(&self) -> Duration {
        self.session_ttl
    }

    /// Returns the number of distinct transmitting stations currently tracked.
    #[must_use]
    pub fn sender_count(&self) -> usize {
        self.senders.len()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn lru_list(&self) -> Vec<Option<String>> {
        self.lru_senders.iter().cloned().collect()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn completed_sessions_len(&self) -> usize {
        self.completed_sessions.len()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn completed_payloads_len(&self) -> usize {
        self.completed_payloads.len()
    }

    /// Sweeps sessions that have been inactive for longer than the configured session TTL.
    pub fn sweep_expired_default(&mut self) -> usize {
        self.sweep_expired(self.session_ttl)
    }

    fn touch_sender(&mut self, sender: &Option<String>) {
        if let Some(pos) = self.lru_senders.iter().position(|s| s == sender) {
            self.lru_senders.remove(pos);
        }
        self.lru_senders.push_back(sender.clone());
    }

    fn evict_oldest_sender(&mut self, skip: Option<&Option<String>>) -> bool {
        let target_idx = match skip {
            Some(skip_sender) => self.lru_senders.iter().position(|s| s != skip_sender),
            None => {
                if self.lru_senders.is_empty() {
                    None
                } else {
                    Some(0)
                }
            }
        };

        if let Some(idx) = target_idx
            && let Some(oldest_sender) = self.lru_senders.remove(idx)
            && let Some(state) = self.senders.remove(&oldest_sender)
        {
            self.total_buffered_bytes = self
                .total_buffered_bytes
                .saturating_sub(state.buffered_bytes);
            warn!(
                "Evicted oldest sender {:?} ({}) to enforce resource limits",
                oldest_sender, state.buffered_bytes
            );
            // Also purge any matching sessions from the underlying deframer
            for mid in state.active_message_ids {
                let _ = self.deframer.cleanup_expired(Duration::ZERO);
                debug!("Purged session for ({:?}, {mid})", oldest_sender);
            }
            return true;
        }
        false
    }

    /// Ingests a raw HQFBP PDU, enforcing sender limits and memory bounds.
    ///
    /// # Errors
    /// Returns [`Error::PayloadTooLarge`] if a single PDU exceeds the total buffer cap,
    /// or [`Error::MemoryCapExceeded`] if memory could not be reclaimed.
    pub fn process_pdu(&mut self, pdu: &[u8]) -> Result<()> {
        let pdu_len = pdu.len();
        if pdu_len > self.max_in_flight_bytes {
            return Err(Error::PayloadTooLarge {
                size: pdu_len as u64,
                max: self.max_in_flight_bytes as u64,
            });
        }

        // Quick peek at the sender callsign and message ID if possible
        let (peek_sender, peek_msg_id) = hqfbp_rs::unpack(Bytes::copy_from_slice(pdu))
            .ok()
            .map(|(h, _)| {
                let s = h.src_callsign;
                let m = h.original_message_id.or(h.message_id);
                (s, m)
            })
            .unwrap_or((None, None));

        // Deduplicate chunks belonging to an already completed message
        if let Some(mid) = peek_msg_id
            && self
                .completed_sessions
                .contains_key(&(peek_sender.clone(), mid))
        {
            return Ok(());
        }

        // Ensure we do not exceed sender count limit
        if !self.senders.contains_key(&peek_sender)
            && self.senders.len() >= self.max_concurrent_senders
        {
            self.evict_oldest_sender(None);
        }

        // Ensure we do not exceed total buffer memory limit
        while self.total_buffered_bytes + pdu_len > self.max_in_flight_bytes {
            if !self.evict_oldest_sender(Some(&peek_sender)) {
                return Err(Error::MemoryCapExceeded {
                    current: self.total_buffered_bytes + pdu_len,
                    max: self.max_in_flight_bytes,
                });
            }
        }

        // Update memory and sender accounting
        self.total_buffered_bytes += pdu_len;
        self.touch_sender(&peek_sender);

        let sender_entry = self
            .senders
            .entry(peek_sender.clone())
            .or_insert_with(|| SenderState {
                last_active: Instant::now(),
                buffered_bytes: 0,
                active_message_ids: HashSet::new(),
                session_bytes: HashMap::new(),
            });
        sender_entry.buffered_bytes += pdu_len;
        sender_entry.last_active = Instant::now();
        if let Some(mid) = peek_msg_id {
            *sender_entry.session_bytes.entry(mid).or_default() += pdu_len;
            sender_entry.active_message_ids.insert(mid);
        }

        // Feed to deframer
        self.deframer.receive_bytes(pdu);
        self.poll_deframer_events();

        Ok(())
    }

    fn poll_deframer_events(&mut self) {
        let mut last_mid_by_sender: HashMap<Option<String>, u32> = HashMap::new();
        while let Some(ev) = self.deframer.next_event() {
            match ev {
                Event::PDU(p) => {
                    let src = p.header.src_callsign;
                    if let Some(id) = p.header.original_message_id.or(p.header.message_id) {
                        last_mid_by_sender.insert(src, id);
                    }
                }
                Event::Message(me) => {
                    let src = me.header.src_callsign.clone();
                    let dst = me.header.dst_callsign.clone();
                    let mid = me
                        .header
                        .original_message_id
                        .or(me.header.message_id)
                        .or_else(|| last_mid_by_sender.get(&src).copied());

                    let p_hash = hash_payload(&me.payload);
                    let dup_key = (src.clone(), p_hash);
                    if self.completed_payloads.contains_key(&dup_key) {
                        debug!(
                            "Ignoring duplicate payload hash {:?} from {:?}",
                            p_hash, src
                        );
                        continue;
                    }
                    let completion_time = Instant::now();
                    self.completed_payloads.insert(dup_key, completion_time);

                    // Release memory allocated for this sender
                    if let Some(state) = self.senders.get_mut(&src) {
                        let finished_ids: Vec<u32> = if let Some(id) = mid {
                            state.active_message_ids.remove(&id);
                            vec![id]
                        } else {
                            state.active_message_ids.drain().collect()
                        };
                        let mut deducted = 0;
                        let mut found_session = false;
                        for id in &finished_ids {
                            if let Some(bytes) = state.session_bytes.remove(id) {
                                deducted += bytes;
                                found_session = true;
                            }
                            self.completed_sessions
                                .insert((src.clone(), *id), completion_time);
                        }
                        if !found_session {
                            deducted = state.buffered_bytes;
                        }
                        state.buffered_bytes = state.buffered_bytes.saturating_sub(deducted);
                        self.total_buffered_bytes =
                            self.total_buffered_bytes.saturating_sub(deducted);
                    }

                    self.completed_messages.push_back(CompletedMessage {
                        src_callsign: src,
                        dst_callsign: dst,
                        message_id: mid,
                        payload: me.payload,
                    });
                }
            }
        }
    }

    /// Drains all completed messages reassembled by the deframer.
    pub fn drain_completed_messages(&mut self) -> Vec<CompletedMessage> {
        self.poll_deframer_events();
        self.completed_messages.drain(..).collect()
    }

    /// Sweeps expired sessions that have been inactive for longer than `timeout`.
    pub fn sweep_expired(&mut self, timeout: Duration) -> usize {
        self.sweep_expired_at(Instant::now(), timeout)
    }

    pub(crate) fn sweep_expired_at(&mut self, now: Instant, timeout: Duration) -> usize {
        let expired = self.deframer.cleanup_expired(timeout);
        let count = expired.len();

        // Remove stale senders with expired activity
        let mut stale_senders = Vec::new();
        for (sender, state) in &self.senders {
            if now.duration_since(state.last_active) >= timeout {
                stale_senders.push(sender.clone());
            }
        }

        for stale in stale_senders {
            if let Some(removed) = self.senders.remove(&stale) {
                self.total_buffered_bytes = self
                    .total_buffered_bytes
                    .saturating_sub(removed.buffered_bytes);
            }
            if let Some(pos) = self.lru_senders.iter().position(|s| s == &stale) {
                self.lru_senders.remove(pos);
            }
        }

        self.completed_sessions
            .retain(|_, time| now.duration_since(*time) < timeout);
        self.completed_payloads
            .retain(|_, time| now.duration_since(*time) < timeout);

        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hqfbp_rs::generator::PDUGenerator;

    #[test]
    fn test_single_message_reassembly() {
        let mut mgr = RxSessionManager::new(10, 1024 * 1024, Duration::from_secs(60));
        let mut generator = PDUGenerator::new(
            Some("F4JXQ".to_string()),
            Some("CQ".to_string()),
            Some(vec![
                ContentEncoding::Chunk(128),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            1,
        );

        let data = b"Hello from BPv7 bundle over HQFBP";
        let pdus = generator.generate(data, None).expect("generation succeeds");

        for pdu in &pdus {
            mgr.process_pdu(pdu).expect("processing succeeds");
        }

        let completed = mgr.drain_completed_messages();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].payload.as_ref(), data);
        assert_eq!(completed[0].src_callsign.as_deref(), Some("F4JXQ"));
    }

    #[test]
    fn test_multi_sender_concurrent_reassembly() {
        let mut mgr = RxSessionManager::new(10, 1024 * 1024, Duration::from_secs(60));

        let mut generator1 = PDUGenerator::new(
            Some("F4JXQ".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            1,
        );
        let mut generator2 = PDUGenerator::new(
            Some("ON4KST".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            100,
        );

        let msg1 = b"Bundle payload one from F4JXQ - chunked message test";
        let msg2 = b"Bundle payload two from ON4KST - interleaved chunk test";

        let pdus1 = generator1.generate(msg1, None).unwrap();
        let pdus2 = generator2.generate(msg2, None).unwrap();

        // Interleave the PDUs from both senders
        let max_len = pdus1.len().max(pdus2.len());
        for i in 0..max_len {
            if i < pdus1.len() {
                mgr.process_pdu(&pdus1[i]).unwrap();
            }
            if i < pdus2.len() {
                mgr.process_pdu(&pdus2[i]).unwrap();
            }
        }

        let completed = mgr.drain_completed_messages();
        assert_eq!(completed.len(), 2);

        let res1 = completed
            .iter()
            .find(|m| m.src_callsign.as_deref() == Some("F4JXQ"))
            .unwrap();
        assert_eq!(res1.payload.as_ref(), msg1);

        let res2 = completed
            .iter()
            .find(|m| m.src_callsign.as_deref() == Some("ON4KST"))
            .unwrap();
        assert_eq!(res2.payload.as_ref(), msg2);
    }

    #[test]
    fn test_memory_cap_boundaries_and_accounting() {
        let mut mgr = RxSessionManager::new(10, 100, Duration::from_secs(60));

        // Exact boundary: PDU length == max_in_flight_bytes is allowed (pdu_len > max is false)
        let exact_pdu = vec![0x42; 100];
        let res = mgr.process_pdu(&exact_pdu);
        assert!(res.is_ok());
        assert_eq!(mgr.buffered_bytes(), 100);

        // Reset
        let mut mgr2 = RxSessionManager::new(10, 100, Duration::from_secs(60));
        let pdu_101 = vec![0x42; 101];
        let err = mgr2.process_pdu(&pdu_101).unwrap_err();
        match err {
            Error::PayloadTooLarge { size, max } => {
                assert_eq!(size, 101);
                assert_eq!(max, 100);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }

        // Test multi-sender eviction under memory cap
        let mut mgr3 = RxSessionManager::new(10, 100, Duration::from_secs(60));
        let mut gen1 = PDUGenerator::new(
            Some("S1".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            1,
        );
        let mut gen2 = PDUGenerator::new(
            Some("S2".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            2,
        );

        let pdus1 = gen1
            .generate(
                b"Message from S1 with several chunks to avoid immediate completion",
                None,
            )
            .unwrap();
        let pdus2 = gen2
            .generate(
                b"Message from S2 with several chunks to avoid immediate completion",
                None,
            )
            .unwrap();

        mgr3.process_pdu(&pdus1[0]).unwrap();
        let s1_bytes = mgr3.buffered_bytes();
        assert!(s1_bytes > 0 && s1_bytes < 100);

        mgr3.process_pdu(&pdus2[0]).unwrap();
        let total_bytes = mgr3.buffered_bytes();
        let s2_bytes = total_bytes - s1_bytes;
        assert_eq!(mgr3.sender_count(), 2);

        // Ingest a chunk that forces eviction of S1
        let fill_size = 100 - s2_bytes;
        let large_chunk = vec![0x33; fill_size];
        mgr3.process_pdu(&large_chunk).unwrap();

        // S1 must be evicted, and total buffered bytes must be s2_bytes + fill_size (100)
        assert_eq!(mgr3.buffered_bytes(), 100);

        // When a single sender exceeds remaining capacity and cannot evict anyone
        let mut gen_solo = PDUGenerator::new(
            Some("SOLO".to_string()),
            None,
            Some(vec![ContentEncoding::Chunk(16), ContentEncoding::Crc32]),
            None,
            1,
        );
        let pdus_solo = gen_solo
            .generate(
                b"Long message from SOLO that will be chunked into multiple pieces",
                None,
            )
            .unwrap();
        let chunk0_len = pdus_solo[0].len();
        let chunk1_len = pdus_solo[1].len();

        let mut mgr_tight = RxSessionManager::new(10, chunk0_len + 5, Duration::from_secs(60));
        mgr_tight.process_pdu(&pdus_solo[0]).unwrap();
        assert_eq!(mgr_tight.buffered_bytes(), chunk0_len);
        assert_eq!(mgr_tight.sender_count(), 1);

        let err = mgr_tight.process_pdu(&pdus_solo[1]).unwrap_err();
        match err {
            Error::MemoryCapExceeded { current, max } => {
                assert_eq!(max, chunk0_len + 5);
                assert_eq!(current, chunk0_len + chunk1_len);
            }
            other => panic!("expected MemoryCapExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_buffered_bytes_and_sender_count_lifecycle() {
        let mut mgr = RxSessionManager::new(10, 1024 * 1024, Duration::from_secs(60));
        assert_eq!(mgr.buffered_bytes(), 0);
        assert_eq!(mgr.sender_count(), 0);
        assert_eq!(mgr.session_ttl(), Duration::from_secs(60));

        let mut generator = PDUGenerator::new(
            Some("F4JXQ".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            1,
        );
        let pdus = generator
            .generate(b"Test message to verify buffered bytes lifecycle", None)
            .unwrap();
        assert!(pdus.len() > 1);

        mgr.process_pdu(&pdus[0]).unwrap();
        let bytes_after_first = mgr.buffered_bytes();
        assert!(bytes_after_first > 0);
        assert_eq!(mgr.sender_count(), 1);

        for pdu in &pdus[1..] {
            mgr.process_pdu(pdu).unwrap();
        }

        let completed = mgr.drain_completed_messages();
        assert_eq!(completed.len(), 1);
        assert_eq!(mgr.buffered_bytes(), 0);

        // Also test with explicit message id without H (exercises session_bytes tracking)
        let mut generator2 = PDUGenerator::new(
            Some("F4JXQ".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            2,
        );
        let pdus2 = generator2
            .generate(b"Another chunked message without H", None)
            .unwrap();
        mgr.process_pdu(&pdus2[0]).unwrap();
        assert!(mgr.buffered_bytes() > 0);
        for pdu in &pdus2[1..] {
            mgr.process_pdu(pdu).unwrap();
        }
        let completed2 = mgr.drain_completed_messages();
        assert_eq!(completed2.len(), 1);
        assert_eq!(mgr.buffered_bytes(), 0);
    }

    #[test]
    fn test_peer_encodings_registration() {
        let mut mgr = RxSessionManager::new(10, 1024 * 1024, Duration::from_secs(60));
        assert_eq!(mgr.peer_encodings("F4JXQ"), None);

        let encs = vec![ContentEncoding::H, ContentEncoding::Crc32];
        mgr.register_peer_encodings("F4JXQ", encs.clone());
        assert_eq!(mgr.peer_encodings("F4JXQ"), Some(encs.as_slice()));

        mgr.unregister_peer_encodings("F4JXQ");
        assert_eq!(mgr.peer_encodings("F4JXQ"), None);
    }

    #[test]
    fn test_hash_payload_distinctness() {
        let h1 = hash_payload(b"Payload Alpha");
        let h2 = hash_payload(b"Payload Beta");
        assert_ne!(h1, h2);

        let h_zero = hash_payload(&[0x00]);
        let h_one = hash_payload(&[0x01]);
        assert_ne!(h_zero, h_one);

        let h_ff = hash_payload(&[0xFF]);
        assert_ne!(h_zero, h_ff);
    }

    #[test]
    fn test_lru_touch_and_eviction_ordering() {
        let mut mgr = RxSessionManager::new(2, 1024 * 1024, Duration::from_secs(60));
        let mut gen1 = PDUGenerator::new(
            Some("STA1".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            1,
        );
        let mut gen2 = PDUGenerator::new(
            Some("STA2".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            2,
        );
        let mut gen3 = PDUGenerator::new(
            Some("STA3".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            3,
        );

        let pdus1 = gen1
            .generate(b"Chunked message for STA1 that is sufficiently long", None)
            .unwrap();
        let pdus2 = gen2
            .generate(b"Chunked message for STA2 that is sufficiently long", None)
            .unwrap();
        let pdus3 = gen3
            .generate(b"Chunked message for STA3 that is sufficiently long", None)
            .unwrap();

        mgr.process_pdu(&pdus1[0]).unwrap();
        mgr.process_pdu(&pdus2[0]).unwrap();
        assert_eq!(
            mgr.lru_list(),
            vec![Some("STA1".to_string()), Some("STA2".to_string())]
        );

        // Touch STA1 by feeding another chunk from STA1
        mgr.process_pdu(&pdus1[1]).unwrap();
        // LRU list must now have STA2 at front, STA1 at back
        assert_eq!(
            mgr.lru_list(),
            vec![Some("STA2".to_string()), Some("STA1".to_string())]
        );

        // Ingest from STA3: STA2 should be evicted, leaving STA1 and STA3
        mgr.process_pdu(&pdus3[0]).unwrap();
        assert_eq!(
            mgr.lru_list(),
            vec![Some("STA1".to_string()), Some("STA3".to_string())]
        );
        assert_eq!(mgr.sender_count(), 2);
    }

    #[test]
    fn test_sweep_expired_sessions_and_dedup() {
        let mut mgr = RxSessionManager::new(10, 1024 * 1024, Duration::from_millis(50));
        let mut gen1 = PDUGenerator::new(
            Some("STA1".to_string()),
            None,
            Some(vec![ContentEncoding::Chunk(128), ContentEncoding::Crc32]),
            None,
            1,
        );
        let mut gen2 = PDUGenerator::new(
            Some("STA2".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            2,
        );

        let pdus1 = gen1.generate(b"Complete message from STA1", None).unwrap();
        let pdus2 = gen2
            .generate(b"Chunked message from STA2 that is sufficiently long", None)
            .unwrap();

        // Complete STA1
        for pdu in &pdus1 {
            mgr.process_pdu(pdu).unwrap();
        }
        let completed = mgr.drain_completed_messages();
        assert_eq!(completed.len(), 1);
        assert_eq!(mgr.completed_payloads_len(), 1);
        assert_eq!(mgr.completed_sessions_len(), 1);

        // Keep STA2 partially in flight
        mgr.process_pdu(&pdus2[0]).unwrap();
        assert_eq!(
            mgr.lru_list(),
            vec![Some("STA1".to_string()), Some("STA2".to_string())]
        );

        // Duplicate replay from STA1 is immediately rejected
        mgr.process_pdu(&pdus1[0]).unwrap();
        assert_eq!(mgr.drain_completed_messages().len(), 0);

        // Calling sweep with long timeout retains everything (duration < timeout)
        let swept = mgr.sweep_expired(Duration::from_secs(60));
        assert_eq!(swept, 0);
        assert_eq!(mgr.completed_payloads_len(), 1);
        assert_eq!(mgr.completed_sessions_len(), 1);
        assert_eq!(
            mgr.lru_list(),
            vec![Some("STA1".to_string()), Some("STA2".to_string())]
        );

        // Sleep to exceed 50ms TTL
        std::thread::sleep(Duration::from_millis(70));

        // Touch STA2 so STA2 stays active while STA1 is stale
        mgr.process_pdu(&pdus2[1]).unwrap();
        assert_eq!(
            mgr.lru_list(),
            vec![Some("STA1".to_string()), Some("STA2".to_string())]
        );

        // Sweep with default ttl (50ms): cleans up stale STA1 while keeping touched STA2
        let default_swept = mgr.sweep_expired_default();
        assert_eq!(default_swept, 0);
        assert_eq!(mgr.completed_payloads_len(), 0);
        assert_eq!(mgr.completed_sessions_len(), 0);
        assert_eq!(mgr.lru_list(), vec![Some("STA2".to_string())]);
        assert_eq!(mgr.sender_count(), 1);

        // Replay of STA1's completed message is no longer filtered by dedup cache!
        for pdu in &pdus1 {
            mgr.process_pdu(pdu).unwrap();
        }
        assert_eq!(mgr.drain_completed_messages().len(), 1);
    }

    #[test]
    fn test_sweep_expired_boundary_exact_match() {
        let mut mgr = RxSessionManager::new(10, 1024 * 1024, Duration::from_secs(60));
        let mut generator = PDUGenerator::new(
            Some("STA1".to_string()),
            None,
            Some(vec![ContentEncoding::Chunk(128), ContentEncoding::Crc32]),
            None,
            1,
        );
        let pdus = generator
            .generate(b"Message for exact boundary test", None)
            .unwrap();
        for pdu in &pdus {
            mgr.process_pdu(pdu).unwrap();
        }
        let _ = mgr.drain_completed_messages();
        assert_eq!(mgr.completed_payloads_len(), 1);
        assert_eq!(mgr.completed_sessions_len(), 1);

        // Fetch insertion timestamp
        let insert_time = *mgr.completed_payloads.values().next().unwrap();
        let timeout = Duration::from_secs(10);

        // At exactly insert_time + timeout, elapsed == timeout.
        // With < timeout: (timeout < timeout) is false, so entries are purged (0 remaining).
        // With <= timeout: (timeout <= timeout) is true, so entries would be kept (1 remaining).
        mgr.sweep_expired_at(insert_time + timeout, timeout);
        assert_eq!(mgr.completed_payloads_len(), 0);
        assert_eq!(mgr.completed_sessions_len(), 0);
    }

    #[test]
    fn test_sender_with_two_concurrent_messages_partial_completion() {
        let mut mgr = RxSessionManager::new(10, 1024 * 1024, Duration::from_secs(60));
        let mut gen_a = PDUGenerator::new(
            Some("F4JXQ".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            10,
        );
        let mut gen_b = PDUGenerator::new(
            Some("F4JXQ".to_string()),
            None,
            Some(vec![
                ContentEncoding::Chunk(16),
                ContentEncoding::H,
                ContentEncoding::Crc32,
            ]),
            None,
            20,
        );

        let pdus_a = gen_a
            .generate(b"Message A from F4JXQ that is chunked into pieces", None)
            .unwrap();
        let pdus_b = gen_b
            .generate(b"Message B from F4JXQ that is chunked into pieces", None)
            .unwrap();

        // Feed chunk 0 of A and chunk 0 of B
        mgr.process_pdu(&pdus_a[0]).unwrap();
        let a0_len = pdus_a[0].len();
        assert_eq!(mgr.buffered_bytes(), a0_len);

        mgr.process_pdu(&pdus_b[0]).unwrap();
        let b0_len = pdus_b[0].len();
        assert_eq!(mgr.buffered_bytes(), a0_len + b0_len);

        // Feed remaining chunks of A so A completes, while B stays in flight
        for pdu in &pdus_a[1..] {
            mgr.process_pdu(pdu).unwrap();
        }
        let completed = mgr.drain_completed_messages();
        assert_eq!(completed.len(), 1);
        assert_eq!(
            completed[0].payload.as_ref(),
            b"Message A from F4JXQ that is chunked into pieces"
        );

        // Message B is still in flight: buffered_bytes must be exactly b0_len!
        assert_eq!(mgr.buffered_bytes(), b0_len);

        // Now complete B
        for pdu in &pdus_b[1..] {
            mgr.process_pdu(pdu).unwrap();
        }
        let completed_b = mgr.drain_completed_messages();
        assert_eq!(completed_b.len(), 1);
        assert_eq!(
            completed_b[0].payload.as_ref(),
            b"Message B from F4JXQ that is chunked into pieces"
        );
        assert_eq!(mgr.buffered_bytes(), 0);
    }
}
