//! BPA Convergence Layer Adapter implementation for HQFBP (Hamradio Quick File Broadcasting Protocol).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;
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

use crate::address::{callsign_to_cla_address, cla_address_to_callsign, is_broadcast_callsign};
use crate::config::Config;
use crate::driver::{Driver, DriverCommand};
use crate::encoding::{ContentEncoding, DefaultEncodingSelector, DynamicEncodingSelector};
use crate::error::{Error, Result};

struct ClaInner {
    sink: Arc<dyn Sink>,
    tasks: Arc<TaskPool>,
    cmd_tx: mpsc::Sender<DriverCommand>,
    local_addr: SocketAddr,
    max_bundle_size: Option<NonZeroU64>,
    _driver_handle: tokio::task::JoinHandle<()>,
}

/// The Hamradio Quick File Broadcasting Protocol Convergence Layer Adapter.
pub struct HqfbpCla {
    config: Config,
    inner: Arc<RwLock<Option<ClaInner>>>,
    peer_mappings: Arc<RwLock<HashMap<ClaAddress, String>>>,
    peer_encodings: Arc<RwLock<HashMap<String, Vec<ContentEncoding>>>>,
    default_encodings: Arc<RwLock<Vec<ContentEncoding>>>,
    encoding_selector: Arc<RwLock<Box<dyn DynamicEncodingSelector>>>,
}

impl HqfbpCla {
    /// Creates a new HQFBP CLA instance with the given configuration.
    #[must_use]
    pub fn new(config: Config) -> Self {
        let mut peer_encodings = HashMap::new();
        for peer in &config.peers {
            if let Some(ref encs) = peer.encodings {
                peer_encodings.insert(peer.callsign.clone(), encs.clone());
            }
        }
        let default_encs = config.default_bundle_encodings.clone();

        Self {
            config,
            inner: Arc::new(RwLock::new(None)),
            peer_mappings: Arc::new(RwLock::new(HashMap::new())),
            peer_encodings: Arc::new(RwLock::new(peer_encodings)),
            default_encodings: Arc::new(RwLock::new(default_encs)),
            encoding_selector: Arc::new(RwLock::new(Box::new(DefaultEncodingSelector::new()))),
        }
    }

    /// Returns the local bound socket address once registered.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        let inner_guard = self.inner.read().await;
        let inner = inner_guard.as_ref().ok_or(Error::NotRegistered)?;
        Ok(inner.local_addr)
    }

    /// Returns the initialisation parameters for registering this CLA with the BPA.
    #[must_use]
    pub fn cla_init(&self) -> ClaInit {
        ClaInit {
            address_type: None,
            lane_count: NonZeroU32::new(4),
            max_bundle_size: None,
        }
    }

    /// Dynamically updates the default bundle encoding pipeline on the fly.
    pub async fn set_default_bundle_encodings(
        &self,
        encodings: Vec<ContentEncoding>,
    ) -> Result<()> {
        *self.default_encodings.write().await = encodings.clone();
        let inner_guard = self.inner.read().await;
        if let Some(inner) = inner_guard.as_ref() {
            inner
                .cmd_tx
                .send(DriverCommand::SetDefaultEncodings { encodings })
                .await
                .map_err(|_| Error::DriverClosed)?;
        }
        Ok(())
    }

    /// Associates custom content encodings with a specific remote callsign.
    pub async fn set_peer_encodings(
        &self,
        callsign: impl Into<String>,
        encodings: Vec<ContentEncoding>,
    ) -> Result<()> {
        let call = callsign.into();
        self.peer_encodings
            .write()
            .await
            .insert(call.clone(), encodings.clone());
        let inner_guard = self.inner.read().await;
        if let Some(inner) = inner_guard.as_ref() {
            inner
                .cmd_tx
                .send(DriverCommand::SetPeerEncodings {
                    callsign: call,
                    encodings,
                })
                .await
                .map_err(|_| Error::DriverClosed)?;
        }
        Ok(())
    }

    /// Replaces the active dynamic encoding selector engine.
    pub async fn set_encoding_selector(&self, selector: Box<dyn DynamicEncodingSelector>) {
        *self.encoding_selector.write().await = selector;
    }

    /// Registers a peer address/callsign mapping and notifies the BPA sink.
    pub async fn register_peer(
        &self,
        callsign: &str,
        addr: Option<SocketAddr>,
        node_id: Option<NodeId>,
    ) -> Result<()> {
        let cla_addr = callsign_to_cla_address(callsign);
        {
            let mut mappings = self.peer_mappings.write().await;
            mappings.insert(cla_addr.clone(), callsign.to_string());
            if let Some(a) = addr {
                mappings.insert(ClaAddress::Tcp(a), callsign.to_string());
            }
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
                    callsign: callsign.to_string(),
                    addr,
                    node_id,
                })
                .await
                .map_err(|_| Error::DriverClosed)?;
        }

        Ok(())
    }

    /// Unregisters a peer and removes it from the BPA routing table.
    pub async fn unregister_peer(&self, callsign: &str) -> Result<()> {
        let cla_addr = callsign_to_cla_address(callsign);
        self.peer_mappings.write().await.remove(&cla_addr);
        self.peer_encodings.write().await.remove(callsign);

        let inner_guard = self.inner.read().await;
        if let Some(inner) = inner_guard.as_ref() {
            let _ = inner.sink.remove_peer(&cla_addr).await;
            inner
                .cmd_tx
                .send(DriverCommand::UnregisterPeer {
                    callsign: callsign.to_string(),
                })
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
impl Cla for HqfbpCla {
    async fn on_register(
        &self,
        sink: Box<dyn Sink>,
        _node_ids: &[NodeId],
        max_bundle_size: Option<NonZeroU64>,
    ) {
        info!("Registering HQFBP CLA with BPA");
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
                tracing::error!("HQFBP CLA driver failed to bind: {e}");
                return;
            }
            Err(_) => {
                tracing::error!("HQFBP CLA driver dropped address channel without reporting");
                return;
            }
        };

        // Populate configured peers
        for peer in &self.config.peers {
            let cla_addr = callsign_to_cla_address(&peer.callsign);
            {
                let mut mappings = self.peer_mappings.write().await;
                mappings.insert(cla_addr.clone(), peer.callsign.clone());
                if let Some(addr) = peer.address {
                    mappings.insert(ClaAddress::Tcp(addr), peer.callsign.clone());
                }
            }
            if let Some(ref node_id) = peer.node_id {
                let _ = sink.add_peer(cla_addr, std::slice::from_ref(node_id)).await;
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
        info!("Unregistering HQFBP CLA from BPA");
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

        // Resolve destination callsign
        let dst_callsign = {
            let mappings = self.peer_mappings.read().await;
            if let Some(call) = mappings.get(cla_addr) {
                Some(call.clone())
            } else {
                cla_address_to_callsign(cla_addr).filter(|call| !is_broadcast_callsign(call))
            }
        };

        // Resolve dynamic encodings
        let encodings = {
            let peer_encs = self.peer_encodings.read().await;
            if let Some(call) = &dst_callsign
                && let Some(encs) = peer_encs.get(call)
            {
                encs.clone()
            } else {
                let default_encs = self.default_encodings.read().await;
                let selector = self.encoding_selector.read().await;
                selector.select_encodings(
                    dst_callsign.as_deref(),
                    lane,
                    bundle_id,
                    total_len,
                    &default_encs,
                )
            }
        };

        debug!(
            "Buffering bundle {bundle_id} ({total_len} bytes) for HQFBP broadcast to {dst_callsign:?}"
        );
        let bundle_bytes = buffer_stream(stream, total_len).await?;

        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx
            .send(DriverCommand::Forward {
                bundle_id: bundle_id.clone(),
                dst_callsign,
                encodings,
                data: bundle_bytes,
                reply_tx,
            })
            .await
            .map_err(|_| hardy_bpa::cla::Error::from(Error::DriverClosed))?;

        let outcome = reply_rx
            .await
            .map_err(|_| hardy_bpa::cla::Error::from(Error::DriverClosed))?
            .map_err(hardy_bpa::cla::Error::from)?;

        Ok(outcome)
    }
}
