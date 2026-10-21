//! Background runtime driver coordinating the LTP sans-I/O Engine with network I/O.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, trace, warn};

use hardy_bpa::cla::{Acceptance, ClaAddress, ForwardBundleResult, Sink, TransferOutcome};
use hardy_bpv7::bundle::Id;
use hardy_bpv7::eid::NodeId;
use hardy_ltp::engine::{Engine, EngineConfig, Notice};
use hardy_ltp::kiss::{decode_frame, encode_frame};
use hardy_ltp::types::{EngineId, SessionId};

use crate::config::{Config, TransportMode};
use crate::error::{Error, Result};

/// Commands sent to the driver actor from the CLA interface.
pub enum DriverCommand {
    /// Initiate block transmission for a forwarded bundle.
    Forward {
        bundle_id: Id,
        destination_engine: EngineId,
        data: Bytes,
        red_len: u64,
        reply_tx: oneshot::Sender<Result<ForwardBundleResult>>,
    },
    /// Register a mapping between a remote Engine ID, its network address, and BPA NodeId.
    RegisterPeer {
        engine_id: EngineId,
        addr: SocketAddr,
        node_id: Option<NodeId>,
    },
    /// Gracefully shutdown the driver task.
    Shutdown,
}

/// The background task running the LTP engine.
pub struct Driver {
    config: Config,
    engine: Engine,
    sink: Arc<dyn Sink>,
    cmd_rx: mpsc::Receiver<DriverCommand>,
    start_time: Instant,
    engine_to_addr: HashMap<EngineId, SocketAddr>,
    addr_to_engine: HashMap<SocketAddr, EngineId>,
    engine_to_node: HashMap<EngineId, NodeId>,
    pending_transfers: HashMap<SessionId, Id>,
}

impl Driver {
    /// Spawns the driver task based on configuration.
    pub fn spawn(
        config: Config,
        sink: Arc<dyn Sink>,
        cmd_rx: mpsc::Receiver<DriverCommand>,
        addr_tx: oneshot::Sender<std::io::Result<SocketAddr>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let start_time = Instant::now();
            let engine_cfg = EngineConfig {
                engine_id: config.engine_id,
                max_segment_payload_len: config.max_segment_payload_len,
                checkpoint_rtx_limit: config.checkpoint_rtx_limit,
                report_rtx_limit: config.report_rtx_limit,
                rtt_micros: config.rtt.as_micros() as u64,
                ack_margin_micros: config.ack_margin.as_micros() as u64,
                ..Default::default()
            };
            let engine = Engine::new(engine_cfg);

            let driver = Self {
                config,
                engine,
                sink,
                cmd_rx,
                start_time,
                engine_to_addr: HashMap::new(),
                addr_to_engine: HashMap::new(),
                engine_to_node: HashMap::new(),
                pending_transfers: HashMap::new(),
            };

            if let Err(err) = driver.run(addr_tx).await {
                error!("LTP driver exited with error: {err}");
            }
        })
    }

    fn now_micros(&self) -> u64 {
        self.start_time.elapsed().as_micros() as u64
    }

    async fn run(self, addr_tx: oneshot::Sender<std::io::Result<SocketAddr>>) -> Result<()> {
        match self.config.transport.clone() {
            TransportMode::Udp { bind_addr } => self.run_udp(bind_addr, addr_tx).await,
            TransportMode::KissTcp {
                server_addr,
                bind_addr,
                port,
                reconnect_initial_delay,
                reconnect_max_delay,
            } => {
                self.run_kiss_tcp(
                    server_addr,
                    bind_addr,
                    port,
                    reconnect_initial_delay,
                    reconnect_max_delay,
                    addr_tx,
                )
                .await
            }
        }
    }

    async fn run_udp(
        mut self,
        bind_addr: SocketAddr,
        addr_tx: oneshot::Sender<std::io::Result<SocketAddr>>,
    ) -> Result<()> {
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                let _ = addr_tx.send(Err(e));
                return Ok(());
            }
        };
        let local_addr = match socket.local_addr() {
            Ok(a) => a,
            Err(e) => {
                let _ = addr_tx.send(Err(e));
                return Ok(());
            }
        };
        let _ = addr_tx.send(Ok(local_addr));
        info!("LTP UDP transport listening on {local_addr}");

        let mut rx_buf = vec![0u8; 65536];

        loop {
            let now = self.now_micros();
            let next_timer = self.engine.next_timer_deadline();

            // Calculate duration to next deadline
            let timer_future = async {
                match next_timer {
                    Some(deadline) if deadline > now => {
                        tokio::time::sleep(tokio::time::Duration::from_micros(deadline - now))
                            .await;
                    }
                    Some(_) => {
                        // Expired or due immediately
                    }
                    None => {
                        // Indefinite sleep until interrupted by other events
                        std::future::pending::<()>().await;
                    }
                }
            };

            tokio::select! {
                // 1. Ingress UDP packet
                recv_res = socket.recv_from(&mut rx_buf) => {
                    let (len, peer_addr) = recv_res?;
                    let now = self.now_micros();

                    // Resolve peer engine ID
                    let peer_engine = if let Some(&id) = self.addr_to_engine.get(&peer_addr) {
                        id
                    } else if let Ok((seg, _)) = hardy_ltp::segment::Segment::parse(&rx_buf[..len]) {
                        let id = if seg.session.originator != self.config.engine_id {
                            seg.session.originator
                        } else if let Some(peer) = self.engine.peer_for_session(&seg.session) {
                            peer
                        } else if self.engine_to_addr.len() == 1 {
                            *self.engine_to_addr.keys().next().unwrap()
                        } else {
                            warn!("received packet from unregistered UDP peer {peer_addr}");
                            EngineId(peer_addr.port() as u64)
                        };
                        // Associate dynamic peer ephemeral port with known engine
                        if self.engine_to_addr.contains_key(&id) {
                            self.addr_to_engine.insert(peer_addr, id);
                        }
                        id
                    } else {
                        // Dynamic peer discovery from incoming address
                        warn!("received packet from unregistered UDP peer {peer_addr}");
                        EngineId(peer_addr.port() as u64)
                    };

                    if let Err(err) = self.engine.handle_incoming_segment(peer_engine, &rx_buf[..len], now) {
                        trace!("failed to parse LTP segment from {peer_addr}: {err}");
                    }
                }

                // 2. Timer expiration
                _ = timer_future => {
                    let now = self.now_micros();
                    self.engine.handle_timer_tick(now);
                }

                // 3. Command from CLA
                cmd = self.cmd_rx.recv() => {
                    let Some(cmd) = cmd else {
                        break;
                    };
                    if !self.handle_command(cmd).await? {
                        break;
                    }
                }
            }

            // Drain outputs and notices after any event
            self.drain_outputs_udp(&socket).await?;
            self.drain_notices().await?;
        }

        Ok(())
    }

    async fn run_kiss_tcp(
        mut self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        port: u8,
        reconnect_initial_delay: Duration,
        reconnect_max_delay: Duration,
        addr_tx: oneshot::Sender<std::io::Result<SocketAddr>>,
    ) -> Result<()> {
        // Signal server address immediately so on_register does not block
        let _ = addr_tx.send(Ok(server_addr));

        let mut current_delay = reconnect_initial_delay;
        let connect_timeout = Duration::from_secs(5);
        const MAX_KISS_ACCUMULATOR: usize = 2 * 1024 * 1024; // 2 MiB

        'reconnect_loop: loop {
            info!("connecting LTP CLA to KISS TCP server at {server_addr}");
            let connect_res =
                tokio::time::timeout(connect_timeout, TcpStream::connect(server_addr)).await;

            match connect_res {
                Ok(Ok(stream)) => {
                    info!("connected to KISS TCP server at {server_addr}");
                    // Reset backoff delay on successful connection
                    current_delay = reconnect_initial_delay;

                    // Disable Nagle's algorithm for timely transmission of small frames (ACKs/checkpoints)
                    let _ = stream.set_nodelay(true);

                    let (mut reader, mut writer) = stream.into_split();
                    let mut raw_rx_buf = vec![0u8; 4096];
                    let mut kiss_accumulator = Vec::with_capacity(8192);

                    // Drain any output segments queued while disconnected.
                    // Raw LTP segments are framed directly in KISS Command 0 (Data) frames
                    // without AX.25 headers to eliminate unnecessary overhead on radio links.
                    let mut write_err = false;
                    while let Some((_peer, bytes)) = self.engine.poll_output() {
                        let mut frame_buf = Vec::new();
                        encode_frame(port, hardy_ltp::kiss::Command::Data, &bytes, &mut frame_buf);
                        if let Err(e) = writer.write_all(&frame_buf).await {
                            warn!("KISS TCP initial write error to {server_addr}: {e}");
                            write_err = true;
                            break;
                        }
                    }

                    if !write_err {
                        let disconnect_reason = loop {
                            let now = self.now_micros();
                            let next_timer = self.engine.next_timer_deadline();

                            let timer_future = async {
                                match next_timer {
                                    Some(deadline) if deadline > now => {
                                        tokio::time::sleep(tokio::time::Duration::from_micros(
                                            deadline - now,
                                        ))
                                        .await;
                                    }
                                    Some(_) => {}
                                    None => {
                                        std::future::pending::<()>().await;
                                    }
                                }
                            };

                            tokio::select! {
                                read_res = reader.read(&mut raw_rx_buf) => {
                                    match read_res {
                                        Ok(0) => {
                                            warn!("KISS TCP server at {server_addr} closed connection (EOF)");
                                            break "server closed connection (EOF)";
                                        }
                                        Ok(n) => {
                                            if kiss_accumulator.len() + n > MAX_KISS_ACCUMULATOR {
                                                warn!(
                                                    "KISS accumulator exceeded {MAX_KISS_ACCUMULATOR} bytes, dropping corrupt buffer"
                                                );
                                                kiss_accumulator.clear();
                                            }
                                            kiss_accumulator.extend_from_slice(&raw_rx_buf[..n]);

                                            // Extract all complete KISS frames.
                                            // Frames encapsulate pure raw LTP wire segments directly (Command::Data).
                                            while let Ok(Some((frame, consumed))) = decode_frame(&kiss_accumulator) {
                                                kiss_accumulator.drain(..consumed);
                                                if frame.command == hardy_ltp::kiss::Command::Data {
                                                    let now = self.now_micros();
                                                    let peer_engine = self.engine_to_addr.keys().copied().next().unwrap_or(EngineId(2));
                                                    let _ = self.engine.handle_incoming_segment(peer_engine, &frame.payload, now);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("KISS TCP read error from {server_addr}: {e}");
                                            break "read error";
                                        }
                                    }
                                }

                                _ = timer_future => {
                                    let now = self.now_micros();
                                    self.engine.handle_timer_tick(now);
                                }

                                cmd = self.cmd_rx.recv() => {
                                    let Some(cmd) = cmd else {
                                        break 'reconnect_loop;
                                    };
                                    if !self.handle_command(cmd).await? {
                                        break 'reconnect_loop;
                                    }
                                }
                            }

                            // Drain outputs over KISS directly into Command 0 (Data) frames
                            let mut write_failed = false;
                            while let Some((_peer, bytes)) = self.engine.poll_output() {
                                let mut frame_buf = Vec::new();
                                encode_frame(
                                    port,
                                    hardy_ltp::kiss::Command::Data,
                                    &bytes,
                                    &mut frame_buf,
                                );
                                if let Err(e) = writer.write_all(&frame_buf).await {
                                    warn!("KISS TCP write error to {server_addr}: {e}");
                                    write_failed = true;
                                    break;
                                }
                            }
                            if write_failed {
                                break "write error";
                            }

                            self.drain_notices().await?;
                        };
                        debug!(
                            "KISS TCP session ended ({disconnect_reason}); will reconnect with backoff"
                        );
                    }
                }
                Ok(Err(e)) => {
                    warn!(
                        "Failed to connect to KISS TCP server at {server_addr}: {e}; retrying in {current_delay:?}"
                    );
                }
                Err(_) => {
                    warn!(
                        "Connection to KISS TCP server at {server_addr} timed out; retrying in {current_delay:?}"
                    );
                }
            }

            // Disconnected state: backoff sleep while still servicing commands and timers!
            let backoff_deadline = tokio::time::sleep(current_delay);
            tokio::pin!(backoff_deadline);

            // Compute next delay for exponential backoff (multiplier 2x, saturating, capped at reconnect_max_delay)
            current_delay = current_delay.saturating_mul(2).min(reconnect_max_delay);

            loop {
                let now = self.now_micros();
                let next_timer = self.engine.next_timer_deadline();

                let timer_future = async {
                    match next_timer {
                        Some(deadline) if deadline > now => {
                            tokio::time::sleep(tokio::time::Duration::from_micros(deadline - now))
                                .await;
                        }
                        Some(_) => {}
                        None => {
                            std::future::pending::<()>().await;
                        }
                    }
                };

                tokio::select! {
                    () = &mut backoff_deadline => {
                        // Backoff period elapsed: try reconnecting
                        break;
                    }

                    _ = timer_future => {
                        let now = self.now_micros();
                        self.engine.handle_timer_tick(now);
                        self.drain_notices().await?;
                    }

                    cmd = self.cmd_rx.recv() => {
                        let Some(cmd) = cmd else {
                            break 'reconnect_loop;
                        };
                        if !self.handle_command(cmd).await? {
                            break 'reconnect_loop;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_command(&mut self, cmd: DriverCommand) -> Result<bool> {
        match cmd {
            DriverCommand::Forward {
                bundle_id,
                destination_engine,
                data,
                red_len,
                reply_tx,
            } => {
                let now = self.now_micros();
                match self
                    .engine
                    .request_transmission(destination_engine, 1, data, red_len, now)
                {
                    Ok(session_id) => {
                        self.pending_transfers.insert(session_id, bundle_id);
                        let _ = reply_tx.send(Ok(ForwardBundleResult::Accepted));
                    }
                    Err(e) => {
                        let _ = reply_tx.send(Err(Error::Ltp(e)));
                    }
                }
                Ok(true)
            }
            DriverCommand::RegisterPeer {
                engine_id,
                addr,
                node_id,
            } => {
                self.engine_to_addr.insert(engine_id, addr);
                self.addr_to_engine.insert(addr, engine_id);
                if let Some(node) = node_id {
                    self.engine_to_node.insert(engine_id, node);
                }
                Ok(true)
            }
            DriverCommand::Shutdown => Ok(false),
        }
    }

    async fn drain_outputs_udp(&mut self, socket: &UdpSocket) -> Result<()> {
        while let Some((peer, bytes)) = self.engine.poll_output() {
            if let Some(&dest_addr) = self.engine_to_addr.get(&peer) {
                if let Err(err) = socket.send_to(&bytes, dest_addr).await {
                    warn!("failed to send LTP datagram to {dest_addr}: {err}");
                }
            } else {
                warn!("no destination socket address configured for Engine {peer:?}");
            }
        }
        Ok(())
    }

    async fn drain_notices(&mut self) -> Result<()> {
        while let Some(notice) = self.engine.poll_notice() {
            match notice {
                Notice::RedPartReceived {
                    session: _,
                    source,
                    client_service: _,
                    data,
                    eob: _,
                } => {
                    let peer_node = self.engine_to_node.get(&source);
                    let peer_addr = self
                        .engine_to_addr
                        .get(&source)
                        .map(|s| ClaAddress::Tcp(*s));

                    debug!(
                        "delivering received bundle ({} bytes) from Engine {:?}",
                        data.len(),
                        source
                    );
                    let mut bundle_stream = Bytes::from(data);
                    match self
                        .sink
                        .dispatch(peer_node, peer_addr.as_ref(), &mut bundle_stream)
                        .await
                    {
                        Ok(Acceptance::Accepted) => {}
                        Ok(Acceptance::Refused) => {
                            warn!("bundle from Engine {source:?} refused by BPA");
                        }
                        Err(err) => {
                            error!("dispatch to BPA failed: {err}");
                        }
                    }
                }
                Notice::TransmissionSessionCompleted { session } => {
                    if let Some(bundle_id) = self.pending_transfers.remove(&session) {
                        debug!("transmission session {session:?} completed for bundle {bundle_id}");
                        let _ = self
                            .sink
                            .transfer_outcome(&bundle_id, TransferOutcome::Completed)
                            .await;
                    }
                }
                Notice::TransmissionSessionCancelled { session, reason } => {
                    if let Some(bundle_id) = self.pending_transfers.remove(&session) {
                        warn!(
                            "transmission session {session:?} cancelled ({reason:?}) for bundle {bundle_id}"
                        );
                        let _ = self
                            .sink
                            .transfer_outcome(&bundle_id, TransferOutcome::Failed)
                            .await;
                    }
                }
                Notice::GreenSegmentArrived { .. } => {
                    // Unreliable green segments
                }
            }
        }
        Ok(())
    }
}
