//! BPA Convergence Layer Adapter implementation for LTP and KISS.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{RwLock, mpsc, oneshot};
use tracing::{debug, info};

use hardy_async::TaskPool;
use hardy_bpa::async_trait;
use hardy_bpa::cla::{
    Cla, ClaAddress, ClaInit, ForwardBundleResult, Result as ClaResult, Segment, Sink,
};
use hardy_bpa::stream::{Receiver, buffer_stream};
use hardy_bpv7::bundle::Id;
use hardy_bpv7::eid::NodeId;
use hardy_ltp::types::EngineId;

use crate::config::Config;
use crate::driver::{Driver, DriverCommand};
use crate::error::{Error, Result};

/// Inner state of the LTP CLA.
struct ClaInner {
    sink: Arc<dyn Sink>,
    tasks: Arc<TaskPool>,
    cmd_tx: mpsc::Sender<DriverCommand>,
    local_addr: SocketAddr,
    max_bundle_size: Option<NonZeroU64>,
    _driver_handle: tokio::task::JoinHandle<()>,
}

/// Converts an LTP [`EngineId`] into its canonical Hardy [`ClaAddress`].
#[must_use]
pub fn engine_id_to_cla_address(engine_id: EngineId) -> ClaAddress {
    ClaAddress::Private(Bytes::copy_from_slice(&engine_id.0.to_be_bytes()))
}

/// Attempts to parse an LTP [`EngineId`] from a [`ClaAddress`].
#[must_use]
pub fn cla_address_to_engine_id(cla_addr: &ClaAddress) -> Option<EngineId> {
    match cla_addr {
        ClaAddress::Private(b) if b.len() == 8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(b);
            Some(EngineId(u64::from_be_bytes(arr)))
        }
        _ => None,
    }
}

/// The Licklider Transmission Protocol Convergence Layer Adapter.
pub struct LtpCla {
    config: Config,
    inner: Arc<RwLock<Option<ClaInner>>>,
    peer_mappings: Arc<RwLock<HashMap<ClaAddress, EngineId>>>,
}

impl LtpCla {
    /// Creates a new LTP CLA instance with the given configuration.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            config,
            inner: Arc::new(RwLock::new(None)),
            peer_mappings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the local bound socket address once registered.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        let inner_guard = self.inner.read().await;
        let inner = inner_guard.as_ref().ok_or(Error::NotRegistered)?;
        Ok(inner.local_addr)
    }

    /// Returns the initialisation parameters for registering this CLA with the BPA.
    ///
    /// Declares 2 lanes:
    /// - Lane 0: Red data (reliable, fully acknowledged)
    /// - Lane 1: Green data (unreliable datagram, no acknowledgments)
    #[must_use]
    pub fn cla_init(&self) -> ClaInit {
        ClaInit {
            address_type: None,
            lane_count: NonZeroU32::new(2),
            max_bundle_size: None,
        }
    }

    /// Registers a peer address to Engine ID mapping and notifies the driver.
    pub async fn register_peer(
        &self,
        engine_id: EngineId,
        addr: SocketAddr,
        node_id: Option<NodeId>,
    ) -> Result<()> {
        let cla_addr = engine_id_to_cla_address(engine_id);
        {
            let mut mappings = self.peer_mappings.write().await;
            mappings.insert(cla_addr.clone(), engine_id);
            mappings.insert(ClaAddress::Tcp(addr), engine_id);
        }

        let inner_guard = self.inner.read().await;
        if let Some(inner) = inner_guard.as_ref() {
            if let Some(ref nid) = node_id {
                let _ = inner
                    .sink
                    .add_peer(cla_addr, std::slice::from_ref(nid))
                    .await;
            }
            inner
                .cmd_tx
                .send(DriverCommand::RegisterPeer {
                    engine_id,
                    addr,
                    node_id,
                })
                .await
                .map_err(|_| Error::DriverClosed)?;
        }

        Ok(())
    }

    /// Unregisters a peer and removes it from the BPA routing table.
    pub async fn unregister_peer(&self, engine_id: EngineId) -> Result<()> {
        let cla_addr = engine_id_to_cla_address(engine_id);
        self.peer_mappings.write().await.remove(&cla_addr);

        let inner_guard = self.inner.read().await;
        if let Some(inner) = inner_guard.as_ref() {
            let _ = inner.sink.remove_peer(&cla_addr).await;
            inner
                .cmd_tx
                .send(DriverCommand::UnregisterPeer { engine_id })
                .await
                .map_err(|_| Error::DriverClosed)?;
        }

        Ok(())
    }

    /// Unregisters this CLA from the BPA and shuts down the background driver.
    pub async fn unregister(&self) {
        let mut inner_guard = self.inner.write().await;
        if let Some(inner) = inner_guard.take() {
            inner.sink.unregister().await;
            let _ = inner.cmd_tx.send(DriverCommand::Shutdown).await;
            let _ = inner._driver_handle.await;
            inner.tasks.shutdown().await;
        }
    }
}

#[async_trait]
impl Cla for LtpCla {
    async fn on_register(
        &self,
        sink: Box<dyn Sink>,
        _node_ids: &[NodeId],
        max_bundle_size: Option<NonZeroU64>,
    ) {
        info!(
            "registering LTP CLA (Engine ID {}) with BPA",
            self.config.engine_id
        );
        let sink: Arc<dyn Sink> = sink.into();
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (addr_tx, addr_rx) = oneshot::channel();

        let tasks = Arc::new(TaskPool::new());
        let driver_handle = Driver::spawn(
            self.config.clone(),
            sink.clone(),
            cmd_rx,
            addr_tx,
            tasks.clone(),
        );
        let local_addr = match addr_rx.await {
            Ok(Ok(addr)) => addr,
            Ok(Err(e)) => {
                tracing::error!("LTP CLA driver failed to bind: {e}");
                return;
            }
            Err(_) => {
                tracing::error!("LTP CLA driver dropped address channel without reporting");
                return;
            }
        };

        // Pre-populate driver with configured peers from config
        let default_server_addr = match &self.config.transport {
            crate::config::TransportMode::KissTcp { server_addr, .. } => Some(*server_addr),
            crate::config::TransportMode::Udp { .. } => None,
        };

        for peer in &self.config.peers {
            let cla_addr = engine_id_to_cla_address(peer.engine_id);
            {
                let mut mappings = self.peer_mappings.write().await;
                mappings.insert(cla_addr.clone(), peer.engine_id);
                if let Some(addr) = peer.address {
                    mappings.insert(ClaAddress::Tcp(addr), peer.engine_id);
                }
            }
            if let Some(ref node_id) = peer.node_id {
                let _ = sink.add_peer(cla_addr, std::slice::from_ref(node_id)).await;
            }
            if let Some(addr) = peer.address.or(default_server_addr) {
                let _ = cmd_tx
                    .send(DriverCommand::RegisterPeer {
                        engine_id: peer.engine_id,
                        addr,
                        node_id: peer.node_id.clone(),
                    })
                    .await;
            }
        }

        // Pre-populate driver with any dynamically configured peer mappings
        let mappings = self.peer_mappings.read().await;
        for (cla_addr, &engine_id) in mappings.iter() {
            if let ClaAddress::Tcp(addr) = cla_addr {
                let _ = cmd_tx
                    .send(DriverCommand::RegisterPeer {
                        engine_id,
                        addr: *addr,
                        node_id: None,
                    })
                    .await;
            }
        }

        let mut inner_guard = self.inner.write().await;
        *inner_guard = Some(ClaInner {
            sink,
            tasks,
            cmd_tx,
            local_addr,
            max_bundle_size,
            _driver_handle: driver_handle,
        });
    }

    async fn on_unregister(&self) {
        info!("unregistering LTP CLA from BPA");
        let mut inner_guard = self.inner.write().await;
        if let Some(inner) = inner_guard.take() {
            let _ = inner.cmd_tx.send(DriverCommand::Shutdown).await;
            let _ = inner._driver_handle.await;
            inner.tasks.shutdown().await;
        }
    }

    async fn forward(
        &self,
        lane: Option<u32>,
        cla_addr: &ClaAddress,
        bundle_id: &Id,
        total_len: u64,
        stream: &mut dyn Receiver<Segment>,
    ) -> ClaResult<ForwardBundleResult> {
        let (cmd_tx, max_bundle_size) = {
            let inner_guard = self.inner.read().await;
            let inner = inner_guard
                .as_ref()
                .ok_or(hardy_bpa::cla::Error::Disconnected)?;
            (inner.cmd_tx.clone(), inner.max_bundle_size)
        };

        if let Some(cap) = max_bundle_size
            && total_len > cap.get()
        {
            return Err(hardy_bpa::cla::Error::PayloadTooLarge {
                size: total_len,
                max: cap.get(),
            });
        }

        // Resolve destination EngineId
        let destination_engine = {
            let mappings = self.peer_mappings.read().await;
            if let Some(&id) = mappings.get(cla_addr) {
                id
            } else if let Some(id) = cla_address_to_engine_id(cla_addr) {
                id
            } else {
                return Ok(ForwardBundleResult::NoNeighbour);
            }
        };

        // Reliability class mapping via lanes:
        // - Lane 1: Green data (unreliable datagram, red_len = 0)
        // - Lane 0 / None: Red data (reliable transfer, red_len = total_len)
        let red_len = match lane {
            Some(1) => 0,
            _ => total_len,
        };

        debug!(
            "buffering bundle {bundle_id} ({total_len} bytes, red_len {red_len}) for LTP transmission to {destination_engine:?}"
        );
        let bundle_bytes = buffer_stream(stream, total_len).await?;

        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx
            .send(DriverCommand::Forward {
                bundle_id: bundle_id.clone(),
                destination_engine,
                data: bundle_bytes,
                red_len,
                reply_tx,
            })
            .await
            .map_err(|_| hardy_bpa::cla::Error::from(crate::error::Error::DriverClosed))?;

        let outcome = reply_rx
            .await
            .map_err(|_| hardy_bpa::cla::Error::from(crate::error::Error::DriverClosed))?
            .map_err(hardy_bpa::cla::Error::from)?;

        Ok(outcome)
    }
}
