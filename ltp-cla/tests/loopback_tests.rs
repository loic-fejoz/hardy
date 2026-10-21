//! Niveau 4 : Loopback integration tests for the LTP Convergence Layer Adapter.
//!
//! Tests UDP datagram transport (RFC 7122) and KISS over TCP transport
//! using local loopback and mock BPA sinks.

use std::time::Duration;
use std::vec::Vec;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use hardy_bpa::async_trait;
use hardy_bpa::cla::{
    Acceptance, Cla, ClaAddress, ForwardBundleResult, Result as ClaResult, Segment, Sink,
    TransferOutcome,
};
use hardy_bpa::stream::Receiver;
use hardy_bpv7::bundle::Id;
use hardy_bpv7::eid::NodeId;
use hardy_ltp_cla::{Config, EngineId, LtpCla, PeerEntry, TransportMode};

/// Mock BPA sink capturing dispatches and transfer outcomes.
struct MockSink {
    dispatches: mpsc::Sender<(Option<NodeId>, Option<ClaAddress>, Bytes)>,
    outcomes: mpsc::Sender<(Id, TransferOutcome)>,
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

    async fn transfer_outcome(&self, bundle_id: &Id, outcome: TransferOutcome) -> ClaResult<()> {
        let _ = self.outcomes.send((bundle_id.clone(), outcome)).await;
        Ok(())
    }
}

fn create_test_bundle_id(source_name: &str) -> Id {
    Id {
        source: format!("dtn://{source_name}/test").parse().unwrap(),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_udp_cla_nominal_transfer() {
    let (disp_tx_1, _disp_rx_1) = mpsc::channel(16);
    let (outc_tx_1, mut outc_rx_1) = mpsc::channel(16);
    let sink_1 = Box::new(MockSink {
        dispatches: disp_tx_1,
        outcomes: outc_tx_1,
    });

    let (disp_tx_2, mut disp_rx_2) = mpsc::channel(16);
    let (outc_tx_2, _outc_rx_2) = mpsc::channel(16);
    let sink_2 = Box::new(MockSink {
        dispatches: disp_tx_2,
        outcomes: outc_tx_2,
    });

    // Node 1: Engine 1
    let cfg_1 = Config {
        engine_id: EngineId(1),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        max_segment_payload_len: 1024,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 5,
        report_rtx_limit: 5,
        peers: Vec::new(),
    };
    let cla_1 = LtpCla::new(cfg_1);
    cla_1.on_register(sink_1, &[], None).await;
    let addr_1 = cla_1.local_addr().await.expect("cla_1 local addr");

    // Node 2: Engine 2
    let cfg_2 = Config {
        engine_id: EngineId(2),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        max_segment_payload_len: 1024,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 5,
        report_rtx_limit: 5,
        peers: Vec::new(),
    };
    let cla_2 = LtpCla::new(cfg_2);
    cla_2.on_register(sink_2, &[], None).await;
    let addr_2 = cla_2.local_addr().await.expect("cla_2 local addr");

    let node_id_1: NodeId = "dtn://node-1/".parse().unwrap();
    let node_id_2: NodeId = "dtn://node-2/".parse().unwrap();

    // Cross-register peers
    cla_1
        .register_peer(EngineId(2), addr_2, Some(node_id_2.clone()))
        .await
        .unwrap();
    cla_2
        .register_peer(EngineId(1), addr_1, Some(node_id_1.clone()))
        .await
        .unwrap();

    // 20 KiB test payload (multi-segment transfer)
    let mut payload = vec![0u8; 20480];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 47) ^ 0x33) as u8;
    }
    let expected_hash = Sha256::digest(&payload);

    let bundle_id = create_test_bundle_id("node-1");
    let mut stream = Bytes::copy_from_slice(&payload);

    // Forward from Node 1 to Node 2
    let forward_res = cla_1
        .forward(
            None,
            &ClaAddress::Tcp(addr_2),
            &bundle_id,
            payload.len() as u64,
            &mut stream,
        )
        .await
        .expect("forward call succeeds");

    assert!(matches!(forward_res, ForwardBundleResult::Accepted));

    // Wait for Node 2 to dispatch the received bundle
    let (received_peer_node, received_peer_addr, received_bytes) =
        tokio::time::timeout(Duration::from_secs(5), disp_rx_2.recv())
            .await
            .expect("the timeout only bounds a regression")
            .expect("must receive dispatched bundle");

    assert_eq!(received_peer_node.as_ref(), Some(&node_id_1));
    assert_eq!(received_peer_addr, Some(ClaAddress::Tcp(addr_1)));
    assert_eq!(Sha256::digest(&received_bytes), expected_hash);

    // Wait for Node 1 to receive confirmation outcome
    let (outcome_bundle_id, outcome) =
        tokio::time::timeout(Duration::from_secs(5), outc_rx_1.recv())
            .await
            .expect("the timeout only bounds a regression")
            .expect("must receive transfer outcome");

    assert_eq!(outcome_bundle_id, bundle_id);
    assert_eq!(outcome, TransferOutcome::Completed);

    cla_1.unregister().await;
    cla_2.unregister().await;
}

#[tokio::test]
async fn test_kiss_tcp_cla_nominal_transfer() {
    // 1. Start a mock KISS bridge TCP server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // Spawn server bridge task accepting two clients and piping their streams
    tokio::spawn(async move {
        let (mut client_a, _) = listener.accept().await.unwrap();
        let (mut client_b, _) = listener.accept().await.unwrap();

        let (mut ra, mut wa) = client_a.split();
        let (mut rb, mut wb) = client_b.split();

        let a_to_b = async {
            let mut buf = [0u8; 4096];
            loop {
                let n = ra.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                wb.write_all(&buf[..n]).await.unwrap();
            }
        };

        let b_to_a = async {
            let mut buf = [0u8; 4096];
            loop {
                let n = rb.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                wa.write_all(&buf[..n]).await.unwrap();
            }
        };

        tokio::select! {
            _ = a_to_b => {}
            _ = b_to_a => {}
        }
    });

    let (disp_tx_1, _disp_rx_1) = mpsc::channel(16);
    let (outc_tx_1, mut outc_rx_1) = mpsc::channel(16);
    let sink_1 = Box::new(MockSink {
        dispatches: disp_tx_1,
        outcomes: outc_tx_1,
    });

    let (disp_tx_2, mut disp_rx_2) = mpsc::channel(16);
    let (outc_tx_2, _outc_rx_2) = mpsc::channel(16);
    let sink_2 = Box::new(MockSink {
        dispatches: disp_tx_2,
        outcomes: outc_tx_2,
    });

    let node_id_1: NodeId = "dtn://node-1/".parse().unwrap();
    let node_id_2: NodeId = "dtn://node-2/".parse().unwrap();

    // Node 1: Engine 1 over KISS TCP with pre-configured peer 2
    let cfg_1 = Config {
        engine_id: EngineId(1),
        transport: TransportMode::kiss_tcp(server_addr, 0),
        max_segment_payload_len: 1024,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 5,
        report_rtx_limit: 5,
        peers: vec![PeerEntry {
            engine_id: EngineId(2),
            address: Some(server_addr),
            node_id: Some(node_id_2.clone()),
        }],
    };
    let cla_1 = LtpCla::new(cfg_1);
    cla_1.on_register(sink_1, &[], None).await;

    // Node 2: Engine 2 over KISS TCP with pre-configured peer 1
    let cfg_2 = Config {
        engine_id: EngineId(2),
        transport: TransportMode::kiss_tcp(server_addr, 0),
        max_segment_payload_len: 1024,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 5,
        report_rtx_limit: 5,
        peers: vec![PeerEntry {
            engine_id: EngineId(1),
            address: Some(server_addr),
            node_id: Some(node_id_1.clone()),
        }],
    };
    let cla_2 = LtpCla::new(cfg_2);
    cla_2.on_register(sink_2, &[], None).await;

    // 15 KiB test payload
    let mut payload = vec![0u8; 15360];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 31) ^ 0x99) as u8;
    }
    let expected_hash = Sha256::digest(&payload);

    let bundle_id = create_test_bundle_id("node-1");
    let mut stream = Bytes::copy_from_slice(&payload);

    // Forward bundle from Node 1 to Node 2 over KISS
    let forward_res = cla_1
        .forward(
            None,
            &ClaAddress::Tcp(server_addr),
            &bundle_id,
            payload.len() as u64,
            &mut stream,
        )
        .await
        .expect("KISS forward call succeeds");

    assert!(matches!(forward_res, ForwardBundleResult::Accepted));

    // Wait for Node 2 to dispatch the received bundle
    let (_, _, received_bytes) = tokio::time::timeout(Duration::from_secs(5), disp_rx_2.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("must receive dispatched bundle over KISS");

    assert_eq!(Sha256::digest(&received_bytes), expected_hash);

    // Wait for Node 1 to receive transfer completed outcome
    let (outcome_bundle_id, outcome) =
        tokio::time::timeout(Duration::from_secs(5), outc_rx_1.recv())
            .await
            .expect("the timeout only bounds a regression")
            .expect("must receive transfer outcome over KISS");

    assert_eq!(outcome_bundle_id, bundle_id);
    assert_eq!(outcome, TransferOutcome::Completed);

    cla_1.unregister().await;
    cla_2.unregister().await;
}

#[tokio::test]
async fn test_kiss_tcp_reconnection_and_backoff() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let (conn2_signal_tx, mut conn2_signal_rx) = mpsc::channel(1);

    // Mock KISS server that drops connection 1 and accepts connection 2
    tokio::spawn(async move {
        // First connection: accept and immediately drop socket (simulating server crash)
        let (sock1, _) = listener.accept().await.unwrap();
        drop(sock1);

        // Second connection: accept after backoff retry and receive frame
        let (mut sock2, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = sock2.read(&mut buf).await.unwrap();
        assert!(n > 0, "must receive frame on reconnected socket");
        let _ = conn2_signal_tx.send(()).await;
    });

    let (disp_tx, _disp_rx) = mpsc::channel(16);
    let (outc_tx, _outc_rx) = mpsc::channel(16);
    let sink = Box::new(MockSink {
        dispatches: disp_tx,
        outcomes: outc_tx,
    });

    let cfg = Config {
        engine_id: EngineId(1),
        transport: TransportMode::KissTcp {
            server_addr,
            bind_addr: None,
            port: 0,
            reconnect_initial_delay: Duration::from_millis(50),
            reconnect_max_delay: Duration::from_millis(200),
        },
        max_segment_payload_len: 1024,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 5,
        report_rtx_limit: 5,
        peers: vec![PeerEntry {
            engine_id: EngineId(2),
            address: Some(server_addr),
            node_id: None,
        }],
    };

    let cla = LtpCla::new(cfg);
    cla.on_register(sink, &[], None).await;

    // Forward a bundle; the driver reconnects via backoff and transmits over connection 2
    let payload = vec![0xAB; 256];
    let bundle_id = create_test_bundle_id("node-1");
    let mut stream = Bytes::copy_from_slice(&payload);

    let forward_res = cla
        .forward(
            None,
            &ClaAddress::Tcp(server_addr),
            &bundle_id,
            payload.len() as u64,
            &mut stream,
        )
        .await
        .expect("forward succeeds");

    assert!(matches!(forward_res, ForwardBundleResult::Accepted));

    // Wait for the reconnected socket to receive the frame
    tokio::time::timeout(Duration::from_secs(5), conn2_signal_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("must successfully reconnect and send frame");

    cla.unregister().await;
}
