//! Deterministic timer management for sans-I/O LTP sessions.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::types::SessionId;

/// Key identifying a specific timer in the LTP engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerKey {
    /// Session ID. This is the first field so TimerKeys order by session first!
    pub session: SessionId,
    /// Specific timer kind for this session.
    pub kind: TimerKind,
}

/// The specific timer kind within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimerKind {
    /// Inactivity timer awaiting progress on the session.
    Inactivity {
        /// True if sender, false if receiver.
        is_sender: bool,
    },
    /// Sender timer awaiting report for an issued checkpoint (RFC 5326 §6.7).
    Checkpoint(u64),
    /// Receiver timer awaiting report acknowledgment for an issued report (RFC 5326 §6.8).
    Report(u64),
    /// Cancellation timer awaiting cancel acknowledgment (RFC 5326 §6.9, §6.10).
    Cancel {
        /// True if sender-initiated (awaiting CAS), false if receiver-initiated (awaiting CAR).
        is_sender: bool,
    },
}

impl TimerKey {
    /// Constructs a checkpoint timer key.
    #[must_use]
    pub const fn checkpoint(session: SessionId, serial: u64) -> Self {
        Self {
            session,
            kind: TimerKind::Checkpoint(serial),
        }
    }

    /// Constructs a report timer key.
    #[must_use]
    pub const fn report(session: SessionId, serial: u64) -> Self {
        Self {
            session,
            kind: TimerKind::Report(serial),
        }
    }

    /// Constructs a cancel timer key.
    #[must_use]
    pub const fn cancel(session: SessionId, is_sender: bool) -> Self {
        Self {
            session,
            kind: TimerKind::Cancel { is_sender },
        }
    }

    /// Constructs an inactivity timer key.
    #[must_use]
    pub const fn inactivity(session: SessionId, is_sender: bool) -> Self {
        Self {
            session,
            kind: TimerKind::Inactivity { is_sender },
        }
    }

    /// Returns the session ID associated with this timer.
    #[must_use]
    pub fn session(&self) -> SessionId {
        self.session
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

    /// Cancels all timers associated with a specific session in O(log N + K).
    pub fn cancel_session(&mut self, session: SessionId) {
        let min_key = TimerKey {
            session,
            kind: TimerKind::Inactivity { is_sender: false },
        };
        let max_key = TimerKey {
            session,
            kind: TimerKind::Cancel { is_sender: true },
        };

        let keys_to_remove: Vec<TimerKey> = self
            .by_key
            .range(min_key..=max_key)
            .map(|(&k, _)| k)
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
