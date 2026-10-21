//! Deterministic timer management for sans-I/O LTP sessions.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::types::SessionId;

/// Key identifying a specific timer in the LTP engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimerKey {
    /// Sender timer awaiting report for an issued checkpoint (RFC 5326 §6.7).
    Checkpoint {
        /// Session ID.
        session: SessionId,
        /// Checkpoint serial number.
        serial: u64,
    },
    /// Receiver timer awaiting report acknowledgment for an issued report (RFC 5326 §6.8).
    Report {
        /// Session ID.
        session: SessionId,
        /// Report serial number.
        serial: u64,
    },
    /// Cancellation timer awaiting cancel acknowledgment (RFC 5326 §6.9, §6.10).
    Cancel {
        /// Session ID.
        session: SessionId,
        /// True if sender-initiated (awaiting CAS), false if receiver-initiated (awaiting CAR).
        is_sender: bool,
    },
}

impl TimerKey {
    /// Returns the session ID associated with this timer.
    #[must_use]
    pub fn session(&self) -> SessionId {
        match *self {
            Self::Checkpoint { session, .. }
            | Self::Report { session, .. }
            | Self::Cancel { session, .. } => session,
        }
    }
}

/// Table of active timers indexed by key with monotonic deadline timestamps.
///
/// Uses dual indexing: a map by key for O(1) updates/cancellations and an ordered set
/// by `(deadline, key)` for O(1) earliest-deadline inspection and O(log N) expired polling.
#[derive(Debug, Clone, Default)]
pub struct TimerTable {
    by_key: BTreeMap<TimerKey, u64>,
    by_deadline: BTreeSet<(u64, TimerKey)>,
}

impl TimerTable {
    /// Creates an empty timer table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets or updates a timer deadline.
    pub fn set(&mut self, key: TimerKey, deadline: u64) {
        if let Some(old_deadline) = self.by_key.insert(key, deadline) {
            self.by_deadline.remove(&(old_deadline, key));
        }
        self.by_deadline.insert((deadline, key));
    }

    /// Cancels a specific timer.
    pub fn cancel(&mut self, key: &TimerKey) {
        if let Some(deadline) = self.by_key.remove(key) {
            self.by_deadline.remove(&(deadline, *key));
        }
    }

    /// Cancels all timers associated with a specific session.
    pub fn cancel_session(&mut self, session: SessionId) {
        let keys_to_remove: Vec<TimerKey> = self
            .by_key
            .keys()
            .filter(|k| k.session() == session)
            .copied()
            .collect();

        for key in keys_to_remove {
            self.cancel(&key);
        }
    }

    /// Returns the first expired timer if its deadline is less than or equal to `now`.
    pub fn poll_expired(&mut self, now: u64) -> Option<TimerKey> {
        if let Some(&(deadline, key)) = self.by_deadline.first()
            && deadline <= now
        {
            self.by_deadline.pop_first();
            self.by_key.remove(&key);
            return Some(key);
        }
        None
    }

    /// Returns the earliest deadline among active timers, if any.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.by_deadline.first().map(|&(d, _)| d)
    }
}
