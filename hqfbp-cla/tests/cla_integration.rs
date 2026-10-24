//! End-to-end integration tests for the HQFBP Convergence Layer Adapter.

use std::time::Duration;
use std::vec::Vec;

use bytes::Bytes;
use tokio::sync::mpsc;

use hardy_bpa::async_trait;
use hardy_bpa::cla::{
    Acceptance, Cla, ClaAddress, ForwardBundleResult, Result as ClaResult, Segment, Sink,
    TransferOutcome,
};
use hardy_bpa::stream::Receiver;
use hardy_bpv7::bundle::Id;
use hardy_bpv7::eid::NodeId;
use hardy_hqfbp_cla::{Config, ContentEncoding, HqfbpCla, TransportMode, callsign_to_cla_address};

struct MockSink {
    dispatches: mpsc::Sender<(Option<NodeId>, Option<ClaAddress>, Bytes)>,
}

#[async_trait]
impl Sink for MockSink {
    async fn unregister(&self) {}

    async fn dispatch(
        &self,
        peer_node: Option<&NodeId>,
        peer_addr: Option<&ClaAddress>,
        stream: &mut dyn Receiver<Segment>,
    ) -> ClaResult<Acceptance> {
        let mut buf = Vec::new();
        while let Ok(segment) = stream.recv().await {
            match segment {
                Segment::Next(b) => buf.extend_from_slice(&b),
                Segment::Final(b) => {
                    buf.extend_from_slice(&b);
                    break;
                }
            }
        }
        let _ = self
            .dispatches
            .send((peer_node.cloned(), peer_addr.cloned(), Bytes::from(buf)))
            .await;
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

#[tokio::test]
async fn test_hqfbp_cla_udp_loopback_and_dynamic_encoding() {
    let (tx_a, _rx_a) = mpsc::channel(16);
    let (tx_b, mut rx_b) = mpsc::channel(16);

    let sink_a = Box::new(MockSink { dispatches: tx_a });
    let sink_b = Box::new(MockSink { dispatches: tx_b });

    // Station A
    let cfg_a = Config {
        callsign: Some("F4JXQ".to_string()),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            peer_addr: None,
        },
        hailing_encodings: vec![ContentEncoding::H, ContentEncoding::Crc32],
        default_bundle_encodings: vec![
            ContentEncoding::Chunk(128),
            ContentEncoding::H,
            ContentEncoding::Crc32,
        ],
        initial_msg_id: 1,
        peers: Vec::new(),
        max_concurrent_senders: 10,
        max_in_flight_bytes: 1024 * 1024,
        session_ttl: Duration::from_secs(60),
        sweep_interval: Duration::from_secs(1),
    };
    let cla_a = HqfbpCla::new(cfg_a);
    cla_a.on_register(sink_a, &[], None).await;
    let addr_a = cla_a.local_addr().await.unwrap();

    // Station B
    let cfg_b = Config {
        callsign: Some("ON4KST".to_string()),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            peer_addr: Some(addr_a),
        },
        hailing_encodings: vec![ContentEncoding::H, ContentEncoding::Crc32],
        default_bundle_encodings: vec![
            ContentEncoding::Chunk(128),
            ContentEncoding::H,
            ContentEncoding::Crc32,
        ],
        initial_msg_id: 100,
        peers: Vec::new(),
        max_concurrent_senders: 10,
        max_in_flight_bytes: 1024 * 1024,
        session_ttl: Duration::from_secs(60),
        sweep_interval: Duration::from_secs(1),
    };
    let cla_b = HqfbpCla::new(cfg_b);
    cla_b.on_register(sink_b, &[], None).await;
    let addr_b = cla_b.local_addr().await.unwrap();

    // Register station B with Station A
    cla_a
        .register_peer("ON4KST", Some(addr_b), None)
        .await
        .unwrap();

    // 1. Forward bundle from Station A to Station B using default encodings
    let bundle_data = Bytes::from_static(b"BPv7 bundle content payload test number 1");
    let bundle_id = Id::default();
    let dest_addr = callsign_to_cla_address("ON4KST");

    let mut stream = bundle_data.clone();
    let outcome = cla_a
        .forward(
            None,
            &dest_addr,
            &bundle_id,
            bundle_data.len() as u64,
            &mut stream,
        )
        .await
        .unwrap();

    assert!(matches!(outcome, ForwardBundleResult::Sent));

    // Wait for delivery at Station B
    let (_, _, received) = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .expect("timed out waiting for bundle")
        .expect("channel not closed");

    assert_eq!(received, bundle_data);

    // 2. Change bundle encodings dynamically on the fly to Reed-Solomon FEC with Chunk(64)
    let new_encodings = vec![
        ContentEncoding::Gzip,
        ContentEncoding::Chunk(64),
        ContentEncoding::H,
        ContentEncoding::ReedSolomon(255, 223),
    ];
    cla_a
        .set_default_bundle_encodings(new_encodings)
        .await
        .unwrap();

    let bundle_data_2 =
        Bytes::from_static(b"Second bundle transmitted with dynamic on-the-fly RS FEC encoding");
    let mut stream_2 = bundle_data_2.clone();
    let outcome_2 = cla_a
        .forward(
            None,
            &dest_addr,
            &bundle_id,
            bundle_data_2.len() as u64,
            &mut stream_2,
        )
        .await
        .unwrap();

    assert!(matches!(outcome_2, ForwardBundleResult::Sent));

    let (_, _, received_2) = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .expect("timed out waiting for second bundle")
        .expect("channel not closed");

    assert_eq!(received_2, bundle_data_2);

    // Clean unregister
    cla_a.unregister().await;
    cla_b.unregister().await;
}
