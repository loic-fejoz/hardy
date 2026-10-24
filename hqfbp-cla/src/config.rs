//! Configuration types for the HQFBP Convergence Layer Adapter.

use std::net::SocketAddr;
use std::string::String;
use std::time::Duration;
use std::vec::Vec;

use hardy_bpv7::eid::NodeId;

use crate::encoding::ContentEncoding;

#[allow(dead_code)]
fn default_tcp_port() -> u8 {
    0
}

#[allow(dead_code)]
fn default_baud_rate() -> u32 {
    9600
}

#[allow(dead_code)]
fn default_hailing_encodings() -> Vec<ContentEncoding> {
    vec![ContentEncoding::H, ContentEncoding::Crc32]
}

#[allow(dead_code)]
fn default_bundle_encodings() -> Vec<ContentEncoding> {
    vec![
        ContentEncoding::Chunk(240),
        ContentEncoding::H,
        ContentEncoding::Crc32,
    ]
}

#[allow(dead_code)]
const fn default_max_senders() -> usize {
    64
}

#[allow(dead_code)]
const fn default_max_in_flight_bytes() -> usize {
    16 * 1024 * 1024 // 16 MB
}

#[allow(dead_code)]
const fn default_session_ttl() -> Duration {
    Duration::from_secs(60)
}

#[allow(dead_code)]
const fn default_sweep_interval() -> Duration {
    Duration::from_secs(5)
}

#[allow(dead_code)]
const fn default_reconnect_initial() -> Duration {
    Duration::from_millis(500)
}

#[allow(dead_code)]
const fn default_reconnect_max() -> Duration {
    Duration::from_secs(30)
}

/// The underlying link transport utilized by the HQFBP CLA.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "kebab-case"))]
pub enum TransportMode {
    /// KISS over TCP framing for packet radio / TNC (e.g. Direwolf, soundmodem).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "kiss-tcp", rename_all = "kebab-case")
    )]
    KissTcp {
        /// Remote KISS TCP server socket address (e.g. `127.0.0.1:8001`).
        server_addr: SocketAddr,
        /// Optional local address to bind when connecting out.
        #[cfg_attr(feature = "serde", serde(default))]
        bind_addr: Option<SocketAddr>,
        /// KISS port nibble (0..15, default 0).
        #[cfg_attr(feature = "serde", serde(default = "default_tcp_port"))]
        port: u8,
        /// TxDelay in 10ms units (KISS Command 1).
        #[cfg_attr(feature = "serde", serde(default))]
        tx_delay: Option<u8>,
        /// P-persistence value (KISS Command 2).
        #[cfg_attr(feature = "serde", serde(default))]
        persistence: Option<u8>,
        /// SlotTime in 10ms units (KISS Command 3).
        #[cfg_attr(feature = "serde", serde(default))]
        slot_time: Option<u8>,
        /// TxTail in 10ms units (KISS Command 4).
        #[cfg_attr(feature = "serde", serde(default))]
        tx_tail: Option<u8>,
        /// Initial reconnect delay on connection loss (default 500ms).
        #[cfg_attr(
            feature = "serde",
            serde(default = "default_reconnect_initial", with = "humantime_duration")
        )]
        reconnect_initial: Duration,
        /// Maximum reconnect backoff delay (default 30s).
        #[cfg_attr(
            feature = "serde",
            serde(default = "default_reconnect_max", with = "humantime_duration")
        )]
        reconnect_max: Duration,
    },
    /// KISS over asynchronous serial/TTY port (e.g. `/dev/ttyUSB0`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "kiss-serial", rename_all = "kebab-case")
    )]
    KissSerial {
        /// Path to the serial device file (e.g. `"/dev/ttyUSB0"` or `"COM3"`).
        path: String,
        /// Baud rate for serial communication (default 9600).
        #[cfg_attr(feature = "serde", serde(default = "default_baud_rate"))]
        baud_rate: u32,
        /// KISS port nibble (0..15, default 0).
        #[cfg_attr(feature = "serde", serde(default = "default_tcp_port"))]
        port: u8,
        /// TxDelay in 10ms units (KISS Command 1).
        #[cfg_attr(feature = "serde", serde(default))]
        tx_delay: Option<u8>,
        /// P-persistence value (KISS Command 2).
        #[cfg_attr(feature = "serde", serde(default))]
        persistence: Option<u8>,
        /// SlotTime in 10ms units (KISS Command 3).
        #[cfg_attr(feature = "serde", serde(default))]
        slot_time: Option<u8>,
        /// TxTail in 10ms units (KISS Command 4).
        #[cfg_attr(feature = "serde", serde(default))]
        tx_tail: Option<u8>,
    },
    /// Direct UDP datagram transport (e.g. for GNURadio flowgraphs or raw packet broadcast).
    #[cfg_attr(feature = "serde", serde(rename = "udp", rename_all = "kebab-case"))]
    Udp {
        /// Local socket address to bind and listen on.
        bind_addr: SocketAddr,
        /// Remote destination socket address for outgoing broadcasts or peer transmission.
        #[cfg_attr(feature = "serde", serde(default))]
        peer_addr: Option<SocketAddr>,
    },
}

#[cfg(feature = "serde")]
mod humantime_duration {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&humantime::format_duration(*duration).to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        humantime::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

/// A configured remote peer mapping.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct PeerConfig {
    /// Remote amateur radio callsign (e.g. `"F4JXQ"`).
    pub callsign: String,
    /// Associated BPA Node ID.
    #[cfg_attr(feature = "serde", serde(default))]
    pub node_id: Option<NodeId>,
    /// Optional remote network address for IP-based transports.
    #[cfg_attr(feature = "serde", serde(default))]
    pub address: Option<SocketAddr>,
    /// Optional peer-specific encoding pipeline override.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "crate::encoding::serde_option_encodings")
    )]
    pub encodings: Option<Vec<ContentEncoding>>,
}

/// Top-level configuration for the HQFBP Convergence Layer Adapter.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct Config {
    /// Local amateur radio callsign (e.g. `"N0CALL"`).
    #[cfg_attr(feature = "serde", serde(default))]
    pub callsign: Option<String>,

    /// Underlying physical or network link transport.
    pub transport: TransportMode,

    /// Pipeline of content encodings for the hailing/announcement channel.
    #[cfg_attr(
        feature = "serde",
        serde(
            default = "default_hailing_encodings",
            with = "crate::encoding::serde_encodings"
        )
    )]
    pub hailing_encodings: Vec<ContentEncoding>,

    /// Default pipeline of content encodings applied to bundle payloads.
    #[cfg_attr(
        feature = "serde",
        serde(
            default = "default_bundle_encodings",
            with = "crate::encoding::serde_encodings"
        )
    )]
    pub default_bundle_encodings: Vec<ContentEncoding>,

    /// Initial message ID counter for HQFBP generation.
    #[cfg_attr(feature = "serde", serde(default = "default_msg_id"))]
    pub initial_msg_id: u32,

    /// Pre-configured peer entries.
    #[cfg_attr(feature = "serde", serde(default))]
    pub peers: Vec<PeerConfig>,

    /// Maximum number of concurrent sending stations tracked simultaneously.
    #[cfg_attr(feature = "serde", serde(default = "default_max_senders"))]
    pub max_concurrent_senders: usize,

    /// Maximum in-flight buffer memory in bytes allocated across all active sessions.
    #[cfg_attr(feature = "serde", serde(default = "default_max_in_flight_bytes"))]
    pub max_in_flight_bytes: usize,

    /// Inactivity timeout before purging an uncompleted reassembly session.
    #[cfg_attr(
        feature = "serde",
        serde(default = "default_session_ttl", with = "humantime_duration")
    )]
    pub session_ttl: Duration,

    /// Interval at which expired sessions and inactive senders are swept.
    #[cfg_attr(
        feature = "serde",
        serde(default = "default_sweep_interval", with = "humantime_duration")
    )]
    pub sweep_interval: Duration,
}

#[allow(dead_code)]
const fn default_msg_id() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let transport = TransportMode::Udp {
            bind_addr: "127.0.0.1:10042".parse().unwrap(),
            peer_addr: None,
        };
        let cfg = Config {
            callsign: Some("F4JXQ".to_string()),
            transport,
            hailing_encodings: default_hailing_encodings(),
            default_bundle_encodings: default_bundle_encodings(),
            initial_msg_id: default_msg_id(),
            peers: Vec::new(),
            max_concurrent_senders: default_max_senders(),
            max_in_flight_bytes: default_max_in_flight_bytes(),
            session_ttl: default_session_ttl(),
            sweep_interval: default_sweep_interval(),
        };

        assert_eq!(default_tcp_port(), 0);
        assert_eq!(default_baud_rate(), 9600);
        assert_eq!(default_msg_id(), 1);
        assert_eq!(default_max_in_flight_bytes(), 16 * 1024 * 1024);
        assert_eq!(cfg.max_concurrent_senders, 64);
        assert_eq!(cfg.session_ttl, Duration::from_secs(60));
        assert_eq!(cfg.max_in_flight_bytes, 16 * 1024 * 1024);
        assert_eq!(
            cfg.hailing_encodings,
            vec![ContentEncoding::H, ContentEncoding::Crc32]
        );
        assert_eq!(
            cfg.default_bundle_encodings,
            vec![
                ContentEncoding::Chunk(240),
                ContentEncoding::H,
                ContentEncoding::Crc32
            ]
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_defaults() {
        let json = r#"{
            "transport": {
                "type": "kiss-tcp",
                "server-addr": "127.0.0.1:8001"
            }
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.initial_msg_id, 1);
        assert_eq!(cfg.max_in_flight_bytes, 16 * 1024 * 1024);
        assert_eq!(cfg.session_ttl, Duration::from_secs(60));
        assert_eq!(
            cfg.hailing_encodings,
            vec![ContentEncoding::H, ContentEncoding::Crc32]
        );
        assert_eq!(
            cfg.default_bundle_encodings,
            vec![
                ContentEncoding::Chunk(240),
                ContentEncoding::H,
                ContentEncoding::Crc32
            ]
        );
        if let TransportMode::KissTcp {
            port,
            reconnect_initial,
            reconnect_max,
            ..
        } = cfg.transport
        {
            assert_eq!(port, 0);
            assert_eq!(reconnect_initial, Duration::from_millis(500));
            assert_eq!(reconnect_max, Duration::from_secs(30));
        } else {
            panic!("expected KissTcp");
        }

        let serial_json = r#"{
            "transport": {
                "type": "kiss-serial",
                "path": "/dev/ttyUSB0"
            },
            "session-ttl": "120s",
            "sweep-interval": "10s"
        }"#;
        let serial_cfg: Config = serde_json::from_str(serial_json).unwrap();
        assert_eq!(serial_cfg.session_ttl, Duration::from_secs(120));
        assert_eq!(serial_cfg.sweep_interval, Duration::from_secs(10));
        if let TransportMode::KissSerial {
            baud_rate, port, ..
        } = serial_cfg.transport
        {
            assert_eq!(baud_rate, 9600);
            assert_eq!(port, 0);
        } else {
            panic!("expected KissSerial");
        }
    }
}
