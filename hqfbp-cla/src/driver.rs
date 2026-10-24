//! Background runtime driver coordinating HQFBP deframing, generation, and network/serial I/O.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use hardy_async::TaskPool;
use hardy_bpa::cla::{Acceptance, ForwardBundleResult, Sink};
use hardy_bpv7::bundle::Id;
use hardy_bpv7::eid::NodeId;
use hqfbp_rs::generator::PDUGenerator;
use hqfbp_rs::kiss::{FEND, KissDecoder, encode_kiss_frame};

use crate::address::callsign_to_cla_address;
use crate::config::{Config, TransportMode};
use crate::encoding::ContentEncoding;
use crate::error::{Error, Result};
use crate::session::RxSessionManager;

/// Commands sent to the HQFBP driver actor from the CLA interface.
pub enum DriverCommand {
    /// Initiate transmission of a forwarded bundle.
    Forward {
        /// Unique bundle identifier.
        bundle_id: Id,
        /// Target destination callsign, if known or resolved.
        dst_callsign: Option<String>,
        /// Resolved content encodings to apply.
        encodings: Vec<ContentEncoding>,
        /// Serialized raw bundle payload bytes.
        data: Bytes,
        /// Reply channel to report forwarding outcome.
        reply_tx: oneshot::Sender<Result<ForwardBundleResult>>,
    },
    /// Updates the default bundle encoding pipeline dynamically.
    SetDefaultEncodings {
        /// New default encodings.
        encodings: Vec<ContentEncoding>,
    },
    /// Configures or updates peer-specific encodings dynamically.
    SetPeerEncodings {
        /// Remote callsign.
        callsign: String,
        /// Encodings to associate with this peer.
        encodings: Vec<ContentEncoding>,
    },
    /// Registers a peer callsign with its network address and NodeId.
    RegisterPeer {
        /// Remote callsign.
        callsign: String,
        /// Network socket address if applicable.
        addr: Option<SocketAddr>,
        /// Associated BPA NodeId.
        node_id: Option<NodeId>,
    },
    /// Unregisters a remote peer.
    UnregisterPeer {
        /// Remote callsign.
        callsign: String,
    },
    /// Gracefully shutdown the driver task.
    Shutdown,
}

fn make_kiss_param_frame(port: u8, cmd: u8, val: u8) -> Vec<u8> {
    vec![FEND, (port << 4) | (cmd & 0x0F), val, FEND]
}

/// The background task running the HQFBP CLA engine.
struct KissTcpArgs {
    server_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    port: u8,
    params: (Option<u8>, Option<u8>, Option<u8>, Option<u8>),
    reconnect_initial: Duration,
    reconnect_max: Duration,
    addr_tx: oneshot::Sender<std::io::Result<SocketAddr>>,
}

pub struct Driver {
    config: Config,
    sink: Arc<dyn Sink>,
    cmd_rx: mpsc::Receiver<DriverCommand>,
    rx_manager: RxSessionManager,
    next_msg_id: u32,
    callsign_to_addr: HashMap<String, SocketAddr>,
    addr_to_callsign: HashMap<SocketAddr, String>,
    callsign_to_node: HashMap<String, NodeId>,
}

impl Driver {
    /// Spawns the driver task based on configuration.
    pub fn spawn(
        config: Config,
        sink: Arc<dyn Sink>,
        cmd_rx: mpsc::Receiver<DriverCommand>,
        addr_tx: oneshot::Sender<std::io::Result<SocketAddr>>,
        tasks: Arc<TaskPool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let initial_id = config.initial_msg_id;
            let mut rx_manager = RxSessionManager::new(
                config.max_concurrent_senders,
                config.max_in_flight_bytes,
                config.session_ttl,
            );

            let mut callsign_to_addr = HashMap::new();
            let mut addr_to_callsign = HashMap::new();
            let mut callsign_to_node = HashMap::new();

            // Populate pre-configured peer encodings and address mappings
            for peer in &config.peers {
                if let Some(ref encs) = peer.encodings {
                    rx_manager.register_peer_encodings(peer.callsign.clone(), encs.clone());
                }
                if let Some(addr) = peer.address {
                    callsign_to_addr.insert(peer.callsign.clone(), addr);
                    addr_to_callsign.insert(addr, peer.callsign.clone());
                }
                if let Some(ref node) = peer.node_id {
                    callsign_to_node.insert(peer.callsign.clone(), node.clone());
                }
            }

            let mut driver = Self {
                config,
                sink,
                cmd_rx,
                rx_manager,
                next_msg_id: initial_id,
                callsign_to_addr,
                addr_to_callsign,
                callsign_to_node,
            };

            driver.run(addr_tx, tasks).await;
        })
    }

    async fn run(
        &mut self,
        addr_tx: oneshot::Sender<std::io::Result<SocketAddr>>,
        tasks: Arc<TaskPool>,
    ) {
        match &self.config.transport {
            TransportMode::Udp {
                bind_addr,
                peer_addr,
            } => {
                let bind = *bind_addr;
                let default_peer = *peer_addr;
                self.run_udp(bind, default_peer, addr_tx, tasks).await;
            }
            TransportMode::KissTcp {
                server_addr,
                bind_addr,
                port,
                tx_delay,
                persistence,
                slot_time,
                tx_tail,
                reconnect_initial,
                reconnect_max,
            } => {
                let server = *server_addr;
                let bind = *bind_addr;
                let kiss_port = *port;
                let params = (*tx_delay, *persistence, *slot_time, *tx_tail);
                let rec_init = *reconnect_initial;
                let rec_max = *reconnect_max;
                let args = KissTcpArgs {
                    server_addr: server,
                    bind_addr: bind,
                    port: kiss_port,
                    params,
                    reconnect_initial: rec_init,
                    reconnect_max: rec_max,
                    addr_tx,
                };
                self.run_kiss_tcp(args, tasks).await;
            }
            TransportMode::KissSerial {
                path,
                baud_rate,
                port,
                tx_delay,
                persistence,
                slot_time,
                tx_tail,
            } => {
                let p = path.clone();
                let baud = *baud_rate;
                let kiss_port = *port;
                let params = (*tx_delay, *persistence, *slot_time, *tx_tail);
                self.run_kiss_serial(p, baud, kiss_port, params, addr_tx, tasks)
                    .await;
            }
        }
    }

    async fn run_udp(
        &mut self,
        bind_addr: SocketAddr,
        default_peer: Option<SocketAddr>,
        addr_tx: oneshot::Sender<std::io::Result<SocketAddr>>,
        _tasks: Arc<TaskPool>,
    ) {
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => {
                let local = s.local_addr().unwrap_or(bind_addr);
                let _ = addr_tx.send(Ok(local));
                Arc::new(s)
            }
            Err(e) => {
                let _ = addr_tx.send(Err(e));
                return;
            }
        };

        info!(
            "HQFBP CLA listening on UDP {}",
            socket.local_addr().unwrap_or(bind_addr)
        );

        let mut buf = vec![0u8; 65536];
        let mut sweep_timer = interval(self.config.sweep_interval);

        loop {
            tokio::select! {
                _ = sweep_timer.tick() => {
                    self.rx_manager.sweep_expired(self.config.session_ttl);
                }
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((n, src_addr)) => {
                            let packet = &buf[..n];
                            self.handle_incoming_packet(packet, Some(src_addr)).await;
                        }
                        Err(e) => {
                            error!("HQFBP UDP recv error: {e}");
                        }
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    let Some(cmd) = cmd else { break; };
                    match cmd {
                        DriverCommand::Shutdown => break,
                        DriverCommand::Forward { bundle_id: _, dst_callsign, encodings, data, reply_tx } => {
                            let target_addr = dst_callsign.as_ref()
                                .and_then(|c| self.callsign_to_addr.get(c).copied())
                                .or(default_peer);

                            let outcome = self.transmit_bundle_udp(&socket, target_addr, dst_callsign, encodings, &data).await;
                            let _ = reply_tx.send(outcome);
                        }
                        DriverCommand::SetDefaultEncodings { encodings } => {
                            self.config.default_bundle_encodings = encodings;
                        }
                        DriverCommand::SetPeerEncodings { callsign, encodings } => {
                            self.rx_manager.register_peer_encodings(callsign, encodings);
                        }
                        DriverCommand::RegisterPeer { callsign, addr, node_id } => {
                            if let Some(a) = addr {
                                self.callsign_to_addr.insert(callsign.clone(), a);
                                self.addr_to_callsign.insert(a, callsign.clone());
                            }
                            if let Some(node) = node_id {
                                self.callsign_to_node.insert(callsign, node);
                            }
                        }
                        DriverCommand::UnregisterPeer { callsign } => {
                            if let Some(addr) = self.callsign_to_addr.remove(&callsign) {
                                self.addr_to_callsign.remove(&addr);
                            }
                            self.callsign_to_node.remove(&callsign);
                            self.rx_manager.unregister_peer_encodings(&callsign);
                        }
                    }
                }
            }
        }
    }

    async fn transmit_bundle_udp(
        &mut self,
        socket: &UdpSocket,
        target_addr: Option<SocketAddr>,
        dst_callsign: Option<String>,
        encodings: Vec<ContentEncoding>,
        data: &[u8],
    ) -> Result<ForwardBundleResult> {
        let Some(addr) = target_addr else {
            return Ok(ForwardBundleResult::NoNeighbour);
        };

        let mut pdu_generator = PDUGenerator::new(
            self.config.callsign.clone(),
            dst_callsign,
            Some(encodings),
            Some(self.config.hailing_encodings.clone()),
            self.next_msg_id,
        );
        self.next_msg_id = self.next_msg_id.wrapping_add(10);

        let pdus = pdu_generator
            .generate(data, None)
            .map_err(|e| Error::Hqfbp(e.to_string()))?;
        for pdu in pdus {
            socket.send_to(&pdu, addr).await?;
        }

        Ok(ForwardBundleResult::Sent)
    }

    async fn handle_incoming_packet(&mut self, packet: &[u8], _from: Option<SocketAddr>) {
        // If the packet is a KISS frame (starts with FEND 0xC0), unwrap it
        let pdu_data = if packet.first().copied() == Some(FEND) {
            let mut decoder = KissDecoder::new();
            let mut decoded = None;
            for &b in packet {
                if let Some(frame) = decoder.process_byte(b)
                    && !frame.is_empty()
                    && (frame[0] & 0x0F == 0x00)
                {
                    decoded = Some(frame[1..].to_vec());
                    break;
                }
            }
            decoded.unwrap_or_else(|| packet.to_vec())
        } else {
            packet.to_vec()
        };

        if let Err(e) = self.rx_manager.process_pdu(&pdu_data) {
            warn!("HQFBP drop incoming PDU: {e}");
            return;
        }

        let completed = self.rx_manager.drain_completed_messages();
        for msg in completed {
            debug!(
                "Reassembled HQFBP bundle ({} bytes) from sender {:?}",
                msg.payload.len(),
                msg.src_callsign
            );
            let peer_addr = msg.src_callsign.as_deref().map(callsign_to_cla_address);
            let peer_node = msg
                .src_callsign
                .as_deref()
                .and_then(|c| self.callsign_to_node.get(c));
            let mut bundle_stream = msg.payload;
            match self
                .sink
                .dispatch(peer_node, peer_addr.as_ref(), &mut bundle_stream)
                .await
            {
                Ok(Acceptance::Accepted) => {}
                Ok(Acceptance::Refused) => {
                    warn!("HQFBP bundle from {:?} refused by BPA", msg.src_callsign);
                }
                Err(err) => {
                    error!("Dispatch to BPA failed: {err}");
                }
            }
        }
    }

    async fn run_kiss_tcp(&mut self, args: KissTcpArgs, _tasks: Arc<TaskPool>) {
        let KissTcpArgs {
            server_addr,
            bind_addr,
            port,
            params,
            reconnect_initial,
            reconnect_max,
            addr_tx,
        } = args;
        let mut backoff = reconnect_initial;
        let mut reported_addr = false;
        let mut addr_sender = Some(addr_tx);
        let mut sweep_timer = interval(self.config.sweep_interval);

        'reconnect: loop {
            let socket_res = if server_addr.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            };

            let Ok(socket) = socket_res else {
                if let Some(tx) = addr_sender.take() {
                    let _ = tx.send(Err(std::io::Error::other("failed to create TCP socket")));
                }
                return;
            };

            if let Some(bind) = bind_addr {
                let _ = socket.bind(bind);
            }

            info!("Connecting to KISS TCP server at {server_addr}...");
            let mut stream = match socket.connect(server_addr).await {
                Ok(s) => {
                    info!("Connected to KISS TCP server {server_addr}");
                    backoff = reconnect_initial;
                    if let Some(tx) = addr_sender.take() {
                        let _ = tx.send(s.local_addr());
                        reported_addr = true;
                    }
                    s
                }
                Err(e) => {
                    warn!(
                        "Failed to connect to KISS TCP {server_addr}: {e}; retrying in {backoff:?}"
                    );
                    if !reported_addr && let Some(tx) = addr_sender.take() {
                        let _ = tx.send(Err(e));
                        return;
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(reconnect_max);
                    continue 'reconnect;
                }
            };

            // Send initial KISS parameter frames if configured
            let (tx_delay, persistence, slot_time, tx_tail) = params;
            if let Some(v) = tx_delay {
                let _ = stream.write_all(&make_kiss_param_frame(port, 1, v)).await;
            }
            if let Some(v) = persistence {
                let _ = stream.write_all(&make_kiss_param_frame(port, 2, v)).await;
            }
            if let Some(v) = slot_time {
                let _ = stream.write_all(&make_kiss_param_frame(port, 3, v)).await;
            }
            if let Some(v) = tx_tail {
                let _ = stream.write_all(&make_kiss_param_frame(port, 4, v)).await;
            }

            let (mut reader, mut writer) = stream.into_split();
            let mut kiss_decoder = KissDecoder::new();
            let mut read_buf = [0u8; 4096];

            loop {
                tokio::select! {
                    _ = sweep_timer.tick() => {
                        self.rx_manager.sweep_expired(self.config.session_ttl);
                    }
                    read_res = reader.read(&mut read_buf) => {
                        match read_res {
                            Ok(0) => {
                                warn!("KISS TCP stream closed by remote; reconnecting");
                                break;
                            }
                            Ok(n) => {
                                for &byte in &read_buf[..n] {
                                    if let Some(frame) = kiss_decoder.process_byte(byte)
                                        && !frame.is_empty()
                                        && (frame[0] & 0x0F == 0x00)
                                    {
                                        let pdu = &frame[1..];
                                        self.handle_incoming_packet(pdu, Some(server_addr)).await;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("KISS TCP read error: {e}; reconnecting");
                                break;
                            }
                        }
                    }
                    cmd = self.cmd_rx.recv() => {
                        let Some(cmd) = cmd else { return; };
                        match cmd {
                            DriverCommand::Shutdown => return,
                            DriverCommand::Forward { bundle_id: _, dst_callsign, encodings, data, reply_tx } => {
                                let mut pdu_generator = PDUGenerator::new(
                                    self.config.callsign.clone(),
                                    dst_callsign,
                                    Some(encodings),
                                    Some(self.config.hailing_encodings.clone()),
                                    self.next_msg_id,
                                );
                                self.next_msg_id = self.next_msg_id.wrapping_add(10);

                                match pdu_generator.generate(&data, None) {
                                    Ok(pdus) => {
                                        let mut ok = true;
                                        for pdu in pdus {
                                            let kiss_frame = encode_kiss_frame(&pdu);
                                            if let Err(e) = writer.write_all(&kiss_frame).await {
                                                error!("Failed to write KISS TCP frame: {e}");
                                                ok = false;
                                                break;
                                            }
                                        }
                                        if ok {
                                            let _ = reply_tx.send(Ok(ForwardBundleResult::Sent));
                                        } else {
                                            let _ = reply_tx.send(Err(Error::Io(std::io::Error::other("KISS write failed"))));
                                        }
                                    }
                                    Err(e) => {
                                        let _ = reply_tx.send(Err(Error::Hqfbp(e.to_string())));
                                    }
                                }
                            }
                            DriverCommand::SetDefaultEncodings { encodings } => {
                                self.config.default_bundle_encodings = encodings;
                            }
                            DriverCommand::SetPeerEncodings { callsign, encodings } => {
                                self.rx_manager.register_peer_encodings(callsign, encodings);
                            }
                            DriverCommand::RegisterPeer { callsign, addr, node_id } => {
                                if let Some(a) = addr {
                                    self.callsign_to_addr.insert(callsign.clone(), a);
                                    self.addr_to_callsign.insert(a, callsign.clone());
                                }
                                if let Some(node) = node_id {
                                    self.callsign_to_node.insert(callsign, node);
                                }
                            }
                            DriverCommand::UnregisterPeer { callsign } => {
                                if let Some(addr) = self.callsign_to_addr.remove(&callsign) {
                                    self.addr_to_callsign.remove(&addr);
                                }
                                self.callsign_to_node.remove(&callsign);
                                self.rx_manager.unregister_peer_encodings(&callsign);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(feature = "serial")]
    async fn run_kiss_serial(
        &mut self,
        path: String,
        baud_rate: u32,
        port: u8,
        params: (Option<u8>, Option<u8>, Option<u8>, Option<u8>),
        addr_tx: oneshot::Sender<std::io::Result<SocketAddr>>,
        _tasks: Arc<TaskPool>,
    ) {
        use tokio_serial::SerialPortBuilderExt;

        let dummy_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut port_stream = match tokio_serial::new(&path, baud_rate).open_native_async() {
            Ok(s) => {
                let _ = addr_tx.send(Ok(dummy_addr));
                s
            }
            Err(e) => {
                let _ = addr_tx.send(Err(std::io::Error::other(format!("Serial error: {e}"))));
                return;
            }
        };

        info!("Opened KISS serial port {} at {} baud", path, baud_rate);

        // Send initial KISS parameter frames
        let (tx_delay, persistence, slot_time, tx_tail) = params;
        if let Some(v) = tx_delay {
            let _ = port_stream
                .write_all(&make_kiss_param_frame(port, 1, v))
                .await;
        }
        if let Some(v) = persistence {
            let _ = port_stream
                .write_all(&make_kiss_param_frame(port, 2, v))
                .await;
        }
        if let Some(v) = slot_time {
            let _ = port_stream
                .write_all(&make_kiss_param_frame(port, 3, v))
                .await;
        }
        if let Some(v) = tx_tail {
            let _ = port_stream
                .write_all(&make_kiss_param_frame(port, 4, v))
                .await;
        }

        let (mut reader, mut writer) = tokio::io::split(port_stream);
        let mut kiss_decoder = KissDecoder::new();
        let mut read_buf = [0u8; 1024];
        let mut sweep_timer = interval(self.config.sweep_interval);

        loop {
            tokio::select! {
                _ = sweep_timer.tick() => {
                    self.rx_manager.sweep_expired(self.config.session_ttl);
                }
                read_res = reader.read(&mut read_buf) => {
                    match read_res {
                        Ok(0) => break,
                        Ok(n) => {
                            for &byte in &read_buf[..n] {
                                if let Some(frame) = kiss_decoder.process_byte(byte)
                                    && !frame.is_empty()
                                    && (frame[0] & 0x0F == 0x00)
                                {
                                    let pdu = &frame[1..];
                                    self.handle_incoming_packet(pdu, None).await;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Serial read error: {e}");
                            break;
                        }
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    let Some(cmd) = cmd else { break; };
                    match cmd {
                        DriverCommand::Shutdown => break,
                        DriverCommand::Forward { bundle_id: _, dst_callsign, encodings, data, reply_tx } => {
                            let mut pdu_generator = PDUGenerator::new(
                                self.config.callsign.clone(),
                                dst_callsign,
                                Some(encodings),
                                Some(self.config.hailing_encodings.clone()),
                                self.next_msg_id,
                            );
                            self.next_msg_id = self.next_msg_id.wrapping_add(10);

                            match pdu_generator.generate(&data, None) {
                                Ok(pdus) => {
                                    let mut ok = true;
                                    for pdu in pdus {
                                        let kiss_frame = encode_kiss_frame(&pdu);
                                        if let Err(e) = writer.write_all(&kiss_frame).await {
                                            error!("Failed to write serial KISS frame: {e}");
                                            ok = false;
                                            break;
                                        }
                                    }
                                    if ok {
                                        let _ = reply_tx.send(Ok(ForwardBundleResult::Sent));
                                    } else {
                                        let _ = reply_tx.send(Err(Error::Serial("Serial write error".to_string())));
                                    }
                                }
                                Err(e) => {
                                    let _ = reply_tx.send(Err(Error::Hqfbp(e.to_string())));
                                }
                            }
                        }
                        DriverCommand::SetDefaultEncodings { encodings } => {
                            self.config.default_bundle_encodings = encodings;
                        }
                        DriverCommand::SetPeerEncodings { callsign, encodings } => {
                            self.rx_manager.register_peer_encodings(callsign, encodings);
                        }
                        DriverCommand::RegisterPeer { callsign, addr, node_id } => {
                            if let Some(a) = addr {
                                self.callsign_to_addr.insert(callsign.clone(), a);
                                self.addr_to_callsign.insert(a, callsign.clone());
                            }
                            if let Some(node) = node_id {
                                self.callsign_to_node.insert(callsign, node);
                            }
                        }
                        DriverCommand::UnregisterPeer { callsign } => {
                            if let Some(addr) = self.callsign_to_addr.remove(&callsign) {
                                self.addr_to_callsign.remove(&addr);
                            }
                            self.callsign_to_node.remove(&callsign);
                            self.rx_manager.unregister_peer_encodings(&callsign);
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(feature = "serial"))]
    async fn run_kiss_serial(
        &mut self,
        _path: String,
        _baud_rate: u32,
        _port: u8,
        _params: (Option<u8>, Option<u8>, Option<u8>, Option<u8>),
        addr_tx: oneshot::Sender<std::io::Result<SocketAddr>>,
        _tasks: Arc<TaskPool>,
    ) {
        let _ = addr_tx.send(Err(std::io::Error::other(
            "serial transport requested but 'serial' feature is disabled in this build",
        )));
    }
}
