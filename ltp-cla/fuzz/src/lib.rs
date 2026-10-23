use std::{net::SocketAddr, sync::Arc};

use hardy_bpa::{
    async_trait,
    cla::{Acceptance, Cla, ClaAddress, Result as ClaResult, Segment, Sink, TransferOutcome},
    stream::Receiver,
};
use hardy_bpv7::{bundle::Id, eid::NodeId};
use hardy_ltp_cla::{Config, LtpCla, TransportMode};

/// A mock CLA Sink that accepts dispatches and reports.
pub struct MockSink;

#[async_trait]
impl Sink for MockSink {
    async fn unregister(&self) {}

    async fn dispatch(
        &self,
        _peer_node: Option<&NodeId>,
        _peer_addr: Option<&ClaAddress>,
        _stream: &mut dyn Receiver<Segment>,
    ) -> ClaResult<Acceptance> {
        Ok(Acceptance::Accepted)
    }

    async fn add_peer(&self, _addr: ClaAddress, _nodes: &[NodeId]) -> ClaResult<bool> {
        Ok(true)
    }

    async fn remove_peer(&self, _addr: &ClaAddress) -> ClaResult<bool> {
        Ok(true)
    }

    async fn transfer_outcome(&self, _bundle_id: &Id, _outcome: TransferOutcome) -> ClaResult<()> {
        Ok(())
    }
}

/// Spawns an LTP CLA listener on an ephemeral UDP port.
pub async fn setup_udp_cla() -> (Arc<LtpCla>, SocketAddr) {
    let cfg = Config {
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        ..Default::default()
    };
    let cla = Arc::new(LtpCla::new(cfg));
    let sink = Box::new(MockSink);
    cla.on_register(sink, &[], None).await;
    let addr = cla.local_addr().await.expect("local_addr");
    (cla, addr)
}
