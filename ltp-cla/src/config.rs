//! Configuration for the LTP Convergence Layer Adapter.

use std::net::SocketAddr;
use std::time::Duration;
use std::vec::Vec;

use hardy_bpv7::eid::NodeId;
use hardy_ltp::types::EngineId;

fn default_udp_bind() -> SocketAddr {
    "0.0.0.0:1113".parse().expect("valid socket addr")
}

const fn default_mtu() -> usize {
    1400
}

const fn default_rtt() -> Duration {
    Duration::from_millis(500)
}

const fn default_ack_margin() -> Duration {
    Duration::from_millis(250)
}

const fn default_rtx_limit() -> u32 {
    10
}

const fn default_reconnect_initial() -> Duration {
    Duration::from_millis(500)
}

const fn default_reconnect_max() -> Duration {
    Duration::from_secs(30)
}

/// A configured remote peer mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct PeerEntry {
    /// Remote LTP Engine ID.
    pub engine_id: EngineId,
    /// Destination socket address for UDP or KISS connection.
    #[cfg_attr(feature = "serde", serde(default))]
    pub address: Option<SocketAddr>,
    /// Associated BPA Node ID.
    #[cfg_attr(feature = "serde", serde(default))]
    pub node_id: Option<NodeId>,
}

/// The underlying link transport utilized by the LTP CLA.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "kebab-case"))]
pub enum TransportMode {
    /// Standard UDP datagram transport (RFC 7122).
    #[cfg_attr(feature = "serde", serde(rename = "udp", rename_all = "kebab-case"))]
    Udp {
        /// Local socket address to bind and listen on (e.g. `0.0.0.0:1113`).
        #[cfg_attr(feature = "serde", serde(default = "default_udp_bind"))]
        bind_addr: SocketAddr,
    },
    /// KISS over TCP framing for packet radio / TNC (e.g. Direwolf).
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
        #[cfg_attr(feature = "serde", serde(default))]
        port: u8,
        /// Initial reconnect delay on connection loss (default 500ms).
        #[cfg_attr(
            feature = "serde",
            serde(default = "default_reconnect_initial", with = "humantime_duration")
        )]
        reconnect_initial_delay: Duration,
        /// Maximum reconnect delay with exponential backoff (default 30s).
        #[cfg_attr(
            feature = "serde",
            serde(default = "default_reconnect_max", with = "humantime_duration")
        )]
        reconnect_max_delay: Duration,
    },
}

impl TransportMode {
    /// Helper to create a KISS TCP transport mode with standard reconnect defaults.
    #[must_use]
    pub fn kiss_tcp(server_addr: SocketAddr, port: u8) -> Self {
        Self::KissTcp {
            server_addr,
            bind_addr: None,
            port,
            reconnect_initial_delay: default_reconnect_initial(),
            reconnect_max_delay: default_reconnect_max(),
        }
    }
}

/// Configuration settings for the LTP CLA.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case"))]
pub struct Config {
    /// Local LTP Engine ID.
    pub engine_id: EngineId,
    /// Link transport mode.
    pub transport: TransportMode,
    /// Maximum segment payload length in bytes (default 1400).
    #[cfg_attr(feature = "serde", serde(default = "default_mtu"))]
    pub max_segment_payload_len: usize,
    /// Estimated Round-Trip Time.
    #[cfg_attr(
        feature = "serde",
        serde(default = "default_rtt", with = "humantime_duration")
    )]
    pub rtt: Duration,
    /// Remote acknowledgement processing margin.
    #[cfg_attr(
        feature = "serde",
        serde(default = "default_ack_margin", with = "humantime_duration")
    )]
    pub ack_margin: Duration,
    /// Checkpoint retransmission limit before cancellation.
    #[cfg_attr(feature = "serde", serde(default = "default_rtx_limit"))]
    pub checkpoint_rtx_limit: u32,
    /// Report retransmission limit before cancellation.
    #[cfg_attr(feature = "serde", serde(default = "default_rtx_limit"))]
    pub report_rtx_limit: u32,
    /// Pre-configured peer entries.
    #[cfg_attr(feature = "serde", serde(default))]
    pub peers: Vec<PeerEntry>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            engine_id: EngineId(1),
            transport: TransportMode::Udp {
                bind_addr: default_udp_bind(),
            },
            max_segment_payload_len: default_mtu(),
            rtt: default_rtt(),
            ack_margin: default_ack_margin(),
            checkpoint_rtx_limit: default_rtx_limit(),
            report_rtx_limit: default_rtx_limit(),
            peers: Vec::new(),
        }
    }
}

#[cfg(feature = "serde")]
mod humantime_duration {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(duration: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&humantime::format_duration(*duration))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let text = String::deserialize(d)?;
        humantime::parse_duration(&text).map_err(serde::de::Error::custom)
    }
}
