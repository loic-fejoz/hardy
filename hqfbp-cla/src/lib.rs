//! Hamradio Quick File Broadcasting Protocol (HQFBP) Convergence Layer Adapter for Hardy BPv7.

pub mod address;
pub mod cla;
pub mod config;
pub mod driver;
pub mod encoding;
pub mod error;
pub mod session;

pub use address::{
    BROADCAST_CALLSIGN, callsign_to_cla_address, cla_address_to_callsign, is_broadcast_callsign,
};
pub use cla::HqfbpCla;
pub use config::{Config, PeerConfig, TransportMode};
pub use encoding::{
    ContentEncoding, DefaultEncodingSelector, DynamicEncodingSelector, parse_encodings_from_str,
};
pub use error::{Error, Result};
pub use session::{CompletedMessage, RxSessionManager};
