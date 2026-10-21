//! Segment parser (RFC 5326 §3).

use alloc::vec::Vec;
use core::num::NonZeroU64;

use super::{
    Checkpoint, DataSegKind, DataSegment, Extension, ReceptionClaim, ReportSegment, Segment,
    SegmentBody, error::ParseError,
};
use crate::sdnv;
use crate::types::{CancelReason, EngineId, SessionId};

/// Maximum accepted claim count per report segment as a denial-of-service guard.
pub const MAX_PARSED_CLAIMS: u64 = 65_536;

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Result<u8, ParseError> {
        let b = *self.buf.get(self.pos).ok_or(ParseError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn sdnv(&mut self) -> Result<u64, ParseError> {
        let (val, consumed) = sdnv::decode(&self.buf[self.pos..])?;
        self.pos += consumed;
        Ok(val)
    }

    fn bytes(&mut self, len: u64) -> Result<&'a [u8], ParseError> {
        let len_usize = usize::try_from(len).map_err(|_| ParseError::Truncated)?;
        let end = self
            .pos
            .checked_add(len_usize)
            .ok_or(ParseError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(ParseError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

impl<'a> Segment<'a> {
    /// Parses an LTP segment from `buf`.
    ///
    /// Returns the parsed segment and the exact number of bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the segment is malformed or truncated.
    pub fn parse(buf: &'a [u8]) -> Result<(Self, usize), ParseError> {
        let mut cursor = Cursor { buf, pos: 0 };

        let control_byte = cursor.u8()?;
        let version = control_byte >> 4;
        if version != 0 {
            return Err(ParseError::BadVersion(version));
        }

        let type_code = control_byte & 0x0F;
        if matches!(type_code, 5 | 6 | 10 | 11) {
            return Err(ParseError::UndefinedType(type_code));
        }

        let originator = EngineId(cursor.sdnv()?);
        let session_num = cursor.sdnv()?;
        let session = SessionId {
            originator,
            number: session_num,
        };

        let ext_counts = cursor.u8()?;
        let header_ext = parse_extensions(&mut cursor, ext_counts >> 4)?;

        let body = parse_body(&mut cursor, type_code)?;

        let trailer_ext = parse_extensions(&mut cursor, ext_counts & 0x0F)?;

        Ok((
            Self {
                session,
                header_ext,
                trailer_ext,
                body,
            },
            cursor.pos,
        ))
    }

    /// Quickly inspects an LTP segment's SessionId from `buf` without allocating any vectors.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the control byte or session SDNVs are malformed.
    pub fn peek_session(buf: &[u8]) -> Result<SessionId, ParseError> {
        let mut cursor = Cursor { buf, pos: 0 };
        let control_byte = cursor.u8()?;
        let version = control_byte >> 4;
        if version != 0 {
            return Err(ParseError::BadVersion(version));
        }
        let type_code = control_byte & 0x0F;
        if matches!(type_code, 5 | 6 | 10 | 11) {
            return Err(ParseError::UndefinedType(type_code));
        }
        let originator = EngineId(cursor.sdnv()?);
        let session_num = cursor.sdnv()?;
        Ok(SessionId {
            originator,
            number: session_num,
        })
    }
}

fn parse_extensions<'a>(
    cursor: &mut Cursor<'a>,
    count: u8,
) -> Result<Vec<Extension<'a>>, ParseError> {
    let mut out = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let tag = cursor.u8()?;
        let len = cursor.sdnv()?;
        let value = cursor.bytes(len)?;
        out.push(Extension { tag, value });
    }
    Ok(out)
}

fn parse_body<'a>(cursor: &mut Cursor<'a>, type_code: u8) -> Result<SegmentBody<'a>, ParseError> {
    match type_code {
        0..=4 | 7 => parse_data(cursor, type_code).map(SegmentBody::Data),
        8 => parse_report(cursor).map(SegmentBody::Report),
        9 => Ok(SegmentBody::ReportAck {
            report_serial: cursor.sdnv()?,
        }),
        12 => Ok(SegmentBody::CancelSender {
            reason: parse_reason(cursor)?,
        }),
        13 => Ok(SegmentBody::CancelAckSender),
        14 => Ok(SegmentBody::CancelReceiver {
            reason: parse_reason(cursor)?,
        }),
        15 => Ok(SegmentBody::CancelAckReceiver),
        _ => Err(ParseError::UndefinedType(type_code)),
    }
}

fn parse_data<'a>(cursor: &mut Cursor<'a>, type_code: u8) -> Result<DataSegment<'a>, ParseError> {
    let client_service = cursor.sdnv()?;
    let offset = cursor.sdnv()?;
    let length = cursor.sdnv()?;

    let kind = match type_code {
        0 => DataSegKind::Red,
        1 => DataSegKind::RedCp(parse_checkpoint(cursor)?),
        2 => DataSegKind::RedCpEorp(parse_checkpoint(cursor)?),
        3 => DataSegKind::RedCpEorpEob(parse_checkpoint(cursor)?),
        4 => DataSegKind::Green,
        7 => DataSegKind::GreenEob,
        _ => return Err(ParseError::UndefinedType(type_code)),
    };

    let data = cursor.bytes(length)?;
    Ok(DataSegment {
        client_service,
        offset,
        kind,
        data,
    })
}

fn parse_checkpoint(cursor: &mut Cursor<'_>) -> Result<Checkpoint, ParseError> {
    let raw_serial = cursor.sdnv()?;
    let serial = NonZeroU64::new(raw_serial).ok_or(ParseError::ZeroSerial)?;
    let report_serial = cursor.sdnv()?;
    Ok(Checkpoint {
        serial,
        report_serial,
    })
}

fn parse_report(cursor: &mut Cursor<'_>) -> Result<ReportSegment, ParseError> {
    let raw_report_serial = cursor.sdnv()?;
    let report_serial = NonZeroU64::new(raw_report_serial).ok_or(ParseError::ZeroSerial)?;
    let checkpoint_serial = cursor.sdnv()?;
    let upper_bound = cursor.sdnv()?;
    let lower_bound = cursor.sdnv()?;

    if lower_bound >= upper_bound {
        return Err(ParseError::BoundsInvariant);
    }

    let claim_count = cursor.sdnv()?;
    if claim_count > MAX_PARSED_CLAIMS
        || (claim_count > 0 && claim_count > (cursor.remaining() as u64) / 2)
    {
        return Err(ParseError::ClaimCountInvalid);
    }

    let scope = upper_bound - lower_bound;
    let capacity = usize::try_from(claim_count).map_err(|_| ParseError::ClaimCountInvalid)?;
    let mut claims = Vec::with_capacity(capacity);

    let mut prev_end: u64 = 0;
    for i in 0..claim_count {
        let offset = cursor.sdnv()?;
        let length = cursor.sdnv()?;

        if length == 0 {
            return Err(ParseError::ClaimInvariant);
        }
        if i > 0 && offset < prev_end {
            return Err(ParseError::ClaimInvariant);
        }
        let end = offset
            .checked_add(length)
            .ok_or(ParseError::ClaimInvariant)?;
        if end > scope {
            return Err(ParseError::ClaimInvariant);
        }
        prev_end = end;
        claims.push(ReceptionClaim { offset, length });
    }

    Ok(ReportSegment {
        report_serial,
        checkpoint_serial,
        upper_bound,
        lower_bound,
        claims,
    })
}

fn parse_reason(cursor: &mut Cursor<'_>) -> Result<CancelReason, ParseError> {
    let code = cursor.u8()?;
    CancelReason::from_code(code).ok_or(ParseError::ReservedReason(code))
}
