//! Core protocol identifiers for LTP (RFC 5326 §3.1, §3.2.4).

use core::fmt::{Display, Formatter, Result as FmtResult};

/// An LTP engine identifier (RFC 5326 §3.1; IANA "LTP Engine Numbers" registry).
///
/// Engine numbers are SDNV integers identifying an LTP engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EngineId(pub u64);

impl Display for EngineId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

/// A session identifier: originating engine ID + session number (RFC 5326 §3.1).
///
/// Uniquely identifies a transmission session initiated by the originator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionId {
    /// The engine that initiated the session (block sender).
    pub originator: EngineId,
    /// Originator-assigned session number.
    pub number: u64,
}

impl Display for SessionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}/{}", self.originator, self.number)
    }
}

/// Cancellation reason codes (RFC 5326 §3.2.4).
///
/// Codes `0x06`–`0xFF` are reserved by RFC 5326; segments carrying them are
/// treated as malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum CancelReason {
    /// `00 USR_CNCLD` — Client service canceled session.
    UsrCncld = 0,
    /// `01 UNREACH` — Unreachable client service.
    Unreach = 1,
    /// `02 RLEXC` — Retransmission limit exceeded.
    Rlexc = 2,
    /// `03 MISCOLORED` — Red/green ordering violation (§6.21).
    Miscolored = 3,
    /// `04 SYS_CNCLD` — System error caused termination.
    SysCncld = 4,
    /// `05 RXMTCYCEXC` — Retransmission-cycles limit exceeded (§6.22).
    RxmtCycExc = 5,
}

impl CancelReason {
    /// Decodes a wire reason code; returns `None` for reserved codes (`0x06`–`0xFF`).
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::UsrCncld),
            1 => Some(Self::Unreach),
            2 => Some(Self::Rlexc),
            3 => Some(Self::Miscolored),
            4 => Some(Self::SysCncld),
            5 => Some(Self::RxmtCycExc),
            _ => None,
        }
    }

    /// Returns the wire byte representation of this reason code.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }
}

impl Display for CancelReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(match self {
            Self::UsrCncld => "USR_CNCLD",
            Self::Unreach => "UNREACH",
            Self::Rlexc => "RLEXC",
            Self::Miscolored => "MISCOLORED",
            Self::SysCncld => "SYS_CNCLD",
            Self::RxmtCycExc => "RXMTCYCEXC",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_codes_roundtrip() {
        for code in 0..=5u8 {
            let r = CancelReason::from_code(code).expect("valid code");
            assert_eq!(r.code(), code);
        }
        for code in 6..=255u8 {
            assert_eq!(CancelReason::from_code(code), None);
        }
    }
}
