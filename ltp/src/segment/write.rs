//! Segment serializer (RFC 5326 §3).

use alloc::vec::Vec;

use super::{Extension, ReportSegment, Segment, SegmentBody};
use crate::sdnv;

impl Segment<'_> {
    /// Serializes this segment into its canonical wire binary format.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let header = &self.header_ext[..self.header_ext.len().min(15)];
        let trailer = &self.trailer_ext[..self.trailer_ext.len().min(15)];

        let mut out = Vec::with_capacity(self.exact_encoded_len(header, trailer));

        // Control byte: version 0 (bits 7..4 / RFC MSB bits 0..3) | type code (bits 3..0 / RFC bits 4..7)
        out.push(self.type_code());

        // Session ID
        sdnv::encode(self.session.originator.0, &mut out);
        sdnv::encode(self.session.number, &mut out);

        // Extensions count byte
        let header_count = (header.len() as u8) & 0x0F;
        let trailer_count = (trailer.len() as u8) & 0x0F;
        out.push((header_count << 4) | trailer_count);

        write_extensions(header, &mut out);
        write_body(&self.body, &mut out);
        write_extensions(trailer, &mut out);

        out
    }

    /// Computes the exact encoded wire length in octets.
    #[must_use]
    pub fn exact_encoded_len(&self, header: &[Extension<'_>], trailer: &[Extension<'_>]) -> usize {
        let mut len = 1; // Control byte
        len += sdnv::encoded_len(self.session.originator.0);
        len += sdnv::encoded_len(self.session.number);
        len += 1; // Extension counts byte

        for e in header.iter().chain(trailer) {
            len += 1 + sdnv::encoded_len(e.value.len() as u64) + e.value.len();
        }

        len += match &self.body {
            SegmentBody::Data(ds) => {
                let mut dlen = sdnv::encoded_len(ds.client_service)
                    + sdnv::encoded_len(ds.offset)
                    + sdnv::encoded_len(ds.data.len() as u64)
                    + ds.data.len();
                if let Some(cp) = ds.kind.checkpoint() {
                    dlen +=
                        sdnv::encoded_len(cp.serial.get()) + sdnv::encoded_len(cp.report_serial);
                }
                dlen
            }
            SegmentBody::Report(rs) => {
                let mut rlen = sdnv::encoded_len(rs.report_serial.get())
                    + sdnv::encoded_len(rs.checkpoint_serial)
                    + sdnv::encoded_len(rs.upper_bound)
                    + sdnv::encoded_len(rs.lower_bound)
                    + sdnv::encoded_len(rs.claims.len() as u64);
                for claim in &rs.claims {
                    rlen += sdnv::encoded_len(claim.offset) + sdnv::encoded_len(claim.length);
                }
                rlen
            }
            SegmentBody::ReportAck { report_serial } => sdnv::encoded_len(*report_serial),
            SegmentBody::CancelSender { .. } | SegmentBody::CancelReceiver { .. } => 1,
            SegmentBody::CancelAckSender | SegmentBody::CancelAckReceiver => 0,
        };

        len
    }
}

fn write_extensions(exts: &[Extension<'_>], out: &mut Vec<u8>) {
    for e in exts {
        out.push(e.tag);
        sdnv::encode(e.value.len() as u64, out);
        out.extend_from_slice(e.value);
    }
}

fn write_body(body: &SegmentBody<'_>, out: &mut Vec<u8>) {
    match body {
        SegmentBody::Data(ds) => {
            sdnv::encode(ds.client_service, out);
            sdnv::encode(ds.offset, out);
            sdnv::encode(ds.data.len() as u64, out);

            if let Some(cp) = ds.kind.checkpoint() {
                sdnv::encode(cp.serial.get(), out);
                sdnv::encode(cp.report_serial, out);
            }

            out.extend_from_slice(ds.data);
        }
        SegmentBody::Report(rs) => write_report(rs, out),
        SegmentBody::ReportAck { report_serial } => {
            sdnv::encode(*report_serial, out);
        }
        SegmentBody::CancelSender { reason } | SegmentBody::CancelReceiver { reason } => {
            out.push(reason.code());
        }
        SegmentBody::CancelAckSender | SegmentBody::CancelAckReceiver => {}
    }
}

fn write_report(rs: &ReportSegment, out: &mut Vec<u8>) {
    sdnv::encode(rs.report_serial.get(), out);
    sdnv::encode(rs.checkpoint_serial, out);
    sdnv::encode(rs.upper_bound, out);
    sdnv::encode(rs.lower_bound, out);
    sdnv::encode(rs.claims.len() as u64, out);

    for claim in &rs.claims {
        sdnv::encode(claim.offset, out);
        sdnv::encode(claim.length, out);
    }
}
