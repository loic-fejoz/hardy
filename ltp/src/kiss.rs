//! KISS framing protocol codec (RFC KISS / Mike Chepponis 1986).
//!
//! Provides `no_std` framing, byte-escaping, and frame parsing for
//! communicating with hardware or software TNCs (e.g. Direwolf) over TCP
//! or serial connections.

use alloc::vec::Vec;

use thiserror::Error;

/// Frame End delimiter (`0xC0`).
pub const FEND: u8 = 0xC0;

/// Frame Escape marker (`0xDB`).
pub const FESC: u8 = 0xDB;

/// Transposed Frame End (`0xDC`). Replaces `FEND` in escaped data.
pub const TFEND: u8 = 0xDC;

/// Transposed Frame Escape (`0xDD`). Replaces `FESC` in escaped data.
pub const TFESC: u8 = 0xDD;

/// Specialized Result for KISS operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors encountered when decoding KISS frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Error {
    /// An unexpected byte followed a `FESC` escape octet.
    #[error("invalid escape sequence in KISS frame: FESC followed by 0x{0:02x}")]
    InvalidEscape(u8),

    /// A `FESC` escape octet was found immediately before the end of the frame.
    #[error("truncated escape sequence at end of KISS frame")]
    TruncatedEscape,

    /// A frame contained no data (not even a command byte).
    #[error("empty KISS frame")]
    EmptyFrame,
}

/// Standard KISS command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Data frame containing higher-layer payload (e.g. an LTP segment).
    Data,
    /// Transmitter keyup delay in 10ms units.
    TxDelay,
    /// Persistence parameter `P = p * 256 - 1`.
    Persistence,
    /// Slot time in 10ms units.
    SlotTime,
    /// Time to hold transmitter on after transmission in 10ms units.
    TxTail,
    /// Full-duplex mode indicator (0 = half duplex, non-zero = full duplex).
    FullDuplex,
    /// Hardware-specific configuration.
    SetHardware,
    /// Exit KISS mode and return to standard command mode.
    Return,
    /// Unknown or vendor-specific command code.
    Unknown(u8),
}

impl From<u8> for Command {
    fn from(code: u8) -> Self {
        match code & 0x0F {
            0x00 => Command::Data,
            0x01 => Command::TxDelay,
            0x02 => Command::Persistence,
            0x03 => Command::SlotTime,
            0x04 => Command::TxTail,
            0x05 => Command::FullDuplex,
            0x06 => Command::SetHardware,
            0x0F => Command::Return,
            other => Command::Unknown(other),
        }
    }
}

impl From<Command> for u8 {
    fn from(cmd: Command) -> Self {
        match cmd {
            Command::Data => 0x00,
            Command::TxDelay => 0x01,
            Command::Persistence => 0x02,
            Command::SlotTime => 0x03,
            Command::TxTail => 0x04,
            Command::FullDuplex => 0x05,
            Command::SetHardware => 0x06,
            Command::Return => 0x0F,
            Command::Unknown(code) => code & 0x0F,
        }
    }
}

/// A parsed KISS frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Target or originating TNC port (0..=15).
    pub port: u8,
    /// Frame command.
    pub command: Command,
    /// Unescaped frame payload.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Creates a new data frame on the specified port.
    #[must_use]
    pub fn new_data(port: u8, payload: Vec<u8>) -> Self {
        Self {
            port: port & 0x0F,
            command: Command::Data,
            payload,
        }
    }
}

/// Escapes a slice of bytes according to the KISS protocol rules and appends
/// the result to `out`.
///
/// Uses `memchr::memchr2` SIMD-accelerated scanning on runs of unescaped bytes,
/// bulk-copying them via vector `extend_from_slice`.
pub fn escape(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut start = 0;
    while start < input.len() {
        match memchr::memchr2(FEND, FESC, &input[start..]) {
            Some(rel_idx) => {
                let pos = start + rel_idx;
                out.extend_from_slice(&input[start..pos]);
                if input[pos] == FEND {
                    out.extend_from_slice(&[FESC, TFEND]);
                } else {
                    out.extend_from_slice(&[FESC, TFESC]);
                }
                start = pos + 1;
            }
            None => {
                out.extend_from_slice(&input[start..]);
                break;
            }
        }
    }
}

/// Unescapes an escaped byte slice.
///
/// Uses `memchr::memchr` SIMD-accelerated scanning to find escape characters (`FESC`),
/// bulk-copying unescaped runs.
///
/// # Errors
///
/// Returns [`Error::InvalidEscape`] if `FESC` is followed by an invalid byte.
/// Returns [`Error::TruncatedEscape`] if `FESC` is the last byte in the slice.
pub fn unescape(input: &[u8]) -> Result<Vec<u8>> {
    // Fast path: if there are no escape characters, copy the slice directly (SIMD memcpy).
    if !input.contains(&FESC) {
        return Ok(input.to_vec());
    }

    let mut out = Vec::with_capacity(input.len());
    let mut start = 0;

    while start < input.len() {
        match memchr::memchr(FESC, &input[start..]) {
            Some(rel_idx) => {
                let pos = start + rel_idx;
                out.extend_from_slice(&input[start..pos]);
                let next_idx = pos + 1;
                if next_idx >= input.len() {
                    return Err(Error::TruncatedEscape);
                }
                match input[next_idx] {
                    TFEND => out.push(FEND),
                    TFESC => out.push(FESC),
                    other => return Err(Error::InvalidEscape(other)),
                }
                start = next_idx + 1;
            }
            None => {
                out.extend_from_slice(&input[start..]);
                break;
            }
        }
    }

    Ok(out)
}

/// Encodes a complete KISS frame into `out`, bounded by `FEND` delimiters.
pub fn encode_frame(port: u8, command: Command, payload: &[u8], out: &mut Vec<u8>) {
    let cmd_byte = ((port & 0x0F) << 4) | (u8::from(command) & 0x0F);
    // Pre-reserve enough capacity for delimiters, command, and payload.
    out.reserve(4 + payload.len() + (payload.len() >> 6));
    out.push(FEND);
    escape(&[cmd_byte], out);
    escape(payload, out);
    out.push(FEND);
}

/// Attempts to decode one KISS frame from a byte buffer.
///
/// Returns `Ok(Some((frame, consumed_bytes)))` if a complete frame is decoded,
/// or `Ok(None)` if more bytes are needed.
///
/// Leading `FEND` bytes or empty/corrupted frames are automatically skipped and consumed
/// to ensure stream resynchronization over noisy links.
///
/// # Errors
///
/// Returns [`Error`] only on unrecoverable framing invariants.
pub fn decode_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>> {
    let mut base = 0;
    while base < buf.len() {
        let cur = &buf[base..];
        // Find the first FEND start delimiter
        let mut start_idx = 0;
        while start_idx < cur.len() && cur[start_idx] == FEND {
            start_idx += 1;
        }

        if start_idx >= cur.len() {
            return Ok(None);
        }

        // Find the ending FEND delimiter with SIMD memchr
        let remaining = &cur[start_idx..];
        let end_offset = match memchr::memchr(FEND, remaining) {
            Some(pos) => pos,
            None => return Ok(None),
        };

        let total_consumed = base + start_idx + end_offset + 1;
        let frame_slice = &remaining[..end_offset];

        if frame_slice.is_empty() {
            base += start_idx + end_offset + 1;
            continue;
        }

        let unescaped = match unescape(frame_slice) {
            Ok(u) => u,
            Err(_) => {
                // Radio noise / corrupted escape sequence between FEND delimiters:
                // Consume and discard this corrupted frame so subsequent valid frames are not blocked.
                base += start_idx + end_offset + 1;
                continue;
            }
        };

        if unescaped.is_empty() {
            base += start_idx + end_offset + 1;
            continue;
        }

        let cmd_byte = unescaped[0];
        let port = (cmd_byte >> 4) & 0x0F;
        let command = Command::from(cmd_byte & 0x0F);
        let payload = unescaped[1..].to_vec();

        return Ok(Some((
            Frame {
                port,
                command,
                payload,
            },
            total_consumed,
        )));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_and_unescape_roundtrip() {
        let original = alloc::vec![0x00, FEND, 0x12, FESC, 0x34, TFEND, TFESC, FEND];
        let mut escaped = Vec::new();
        escape(&original, &mut escaped);

        // FEND and FESC must not appear unescaped
        assert!(!escaped.contains(&FEND));

        let unescaped = unescape(&escaped).expect("valid unescape");
        assert_eq!(unescaped, original);
    }

    #[test]
    fn invalid_escapes() {
        assert_eq!(unescape(&[FESC]), Err(Error::TruncatedEscape));
        assert_eq!(unescape(&[FESC, 0x00]), Err(Error::InvalidEscape(0x00)));
    }

    #[test]
    fn encode_and_decode_frame() {
        let payload = alloc::vec![0x01, 0x02, FEND, 0x03, FESC, 0x04];
        let mut encoded = Vec::new();
        encode_frame(2, Command::Data, &payload, &mut encoded);

        let (frame, consumed) = decode_frame(&encoded)
            .expect("valid decode")
            .expect("complete frame");

        assert_eq!(consumed, encoded.len());
        assert_eq!(frame.port, 2);
        assert_eq!(frame.command, Command::Data);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn skip_leading_fend_and_partial_frames() {
        let mut buf = alloc::vec![FEND, FEND, FEND];
        assert_eq!(decode_frame(&buf).unwrap(), None);

        let payload = alloc::vec![0x42];
        let mut frame_bytes = Vec::new();
        encode_frame(0, Command::Data, &payload, &mut frame_bytes);

        buf.extend_from_slice(&frame_bytes);
        let (frame, consumed) = decode_frame(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn skip_corrupted_escape_frames_and_recover() {
        // Frame 1 is corrupted with an invalid escape sequence (FESC followed by 0x00)
        let mut buf = alloc::vec![FEND, 0x00, FESC, 0x00, FEND];

        // Frame 2 is a valid frame
        let valid_payload = alloc::vec![0xAA, 0xBB, 0xCC];
        let mut valid_frame = Vec::new();
        encode_frame(1, Command::Data, &valid_payload, &mut valid_frame);
        buf.extend_from_slice(&valid_frame);

        // decode_frame must skip the corrupted frame and successfully decode Frame 2
        let (frame, consumed) = decode_frame(&buf).unwrap().expect("must recover Frame 2");
        assert_eq!(consumed, buf.len());
        assert_eq!(frame.port, 1);
        assert_eq!(frame.payload, valid_payload);
    }
}
