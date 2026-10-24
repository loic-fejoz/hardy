//! Address mapping between amateur radio callsigns and Hardy [`ClaAddress`].

use std::string::String;

use bytes::Bytes;

use hardy_bpa::cla::ClaAddress;

/// Canonical broadcast callsign identifier used when broadcasting bundles to all listening stations.
pub const BROADCAST_CALLSIGN: &str = "CQ";

/// Converts an amateur radio callsign (e.g. `"F4JXQ"`) into its canonical Hardy [`ClaAddress`].
#[must_use]
pub fn callsign_to_cla_address(callsign: &str) -> ClaAddress {
    ClaAddress::Private(Bytes::copy_from_slice(callsign.as_bytes()))
}

/// Attempts to parse an amateur radio callsign from a [`ClaAddress`].
#[must_use]
pub fn cla_address_to_callsign(cla_addr: &ClaAddress) -> Option<String> {
    match cla_addr {
        ClaAddress::Private(bytes) => String::from_utf8(bytes.to_vec()).ok(),
        _ => None,
    }
}

/// Checks whether a given callsign represents a broadcast destination (e.g. `"CQ"`, `""`).
#[must_use]
pub fn is_broadcast_callsign(callsign: &str) -> bool {
    let trimmed = callsign.trim();
    trimmed.is_empty() || trimmed.eq_ignore_ascii_case(BROADCAST_CALLSIGN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callsign_cla_address_roundtrip() {
        let callsign = "F4JXQ";
        let addr = callsign_to_cla_address(callsign);
        let parsed = cla_address_to_callsign(&addr);
        assert_eq!(parsed.as_deref(), Some(callsign));
    }

    #[test]
    fn test_broadcast_callsign_detection() {
        assert!(is_broadcast_callsign("CQ"));
        assert!(is_broadcast_callsign("cq"));
        assert!(is_broadcast_callsign(""));
        assert!(!is_broadcast_callsign("F4JXQ"));
    }
}
