//! Niveau 4 : Loopback integration tests for the LTP Convergence Layer Adapter.
//!
//! Tests UDP datagram transport (RFC 7122) and KISS over TCP transport
//! using local loopback and mock BPA sinks.

use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;
use std::vec::Vec;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

use hardy_bpa::async_trait;
use hardy_bpa::cla::{
    Acceptance, Cla, ClaAddress, ForwardBundleResult, Result as ClaResult, Segment, Sink,
    TransferOutcome,
};
use hardy_bpa::stream::Receiver;
use hardy_bpv7::bundle::Id;
use hardy_bpv7::eid::NodeId;
use hardy_ltp::segment::{
    Checkpoint, DataSegKind, DataSegment, Segment as LtpSegment, SegmentBody,
};
use hardy_ltp::types::{CancelReason, SessionId};
use hardy_ltp_cla::{
    Config, EngineId, LtpCla, PeerEntry, TransportMode, cla_address_to_engine_id,
    engine_id_to_cla_address,
};

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
        peers: vec![PeerEntry {
            engine_id: EngineId(2),
            address: Some("127.0.0.1:9".parse().unwrap()),
            node_id: None,
        }],
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
        peers: vec![PeerEntry {
            engine_id: EngineId(2),
            address: Some("127.0.0.1:9".parse().unwrap()),
            node_id: None,
        }],
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
    assert_eq!(
        received_peer_addr,
        Some(engine_id_to_cla_address(EngineId(1)))
    );
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

#[tokio::test]
async fn test_s17_multi_station_kiss_tcp_peer_resolution() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let (frame_tx, mut frame_rx) = mpsc::channel(16);

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let mut accum = Vec::new();
        loop {
            let n = match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            accum.extend_from_slice(&buf[..n]);
            let mut offset = 0;
            while let Ok(Some((frame, consumed))) = hardy_ltp::kiss::decode_frame(&accum[offset..])
            {
                offset += consumed;
                if frame.command == hardy_ltp::kiss::Command::Data {
                    let _ = frame_tx.send(frame.payload).await;
                }
            }
            if offset > 0 {
                accum.drain(..offset);
            }
        }
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
        rtt: Duration::from_millis(100),
        ack_margin: Duration::from_millis(50),
        checkpoint_rtx_limit: 3,
        report_rtx_limit: 3,
        peers: vec![
            PeerEntry {
                engine_id: EngineId(2),
                address: None, // Defaults to server_addr
                node_id: Some("dtn://station2/".parse().unwrap()),
            },
            PeerEntry {
                engine_id: EngineId(3),
                address: None, // Defaults to server_addr
                node_id: Some("dtn://station3/".parse().unwrap()),
            },
        ],
    };

    let cla = LtpCla::new(cfg);
    cla.on_register(sink, &[], None).await;

    // Send bundle to station 2
    let payload2 = vec![0x22; 64];
    let bundle2 = create_test_bundle_id("bundle-to-station-2");
    let mut stream2 = Bytes::copy_from_slice(&payload2);
    let addr2 = ClaAddress::Private(Bytes::copy_from_slice(&2u64.to_be_bytes()));
    let res2 = cla
        .forward(None, &addr2, &bundle2, payload2.len() as u64, &mut stream2)
        .await
        .expect("forward to station 2 succeeds");
    assert!(matches!(res2, ForwardBundleResult::Accepted));

    // Send bundle to station 3
    let payload3 = vec![0x33; 64];
    let bundle3 = create_test_bundle_id("bundle-to-station-3");
    let mut stream3 = Bytes::copy_from_slice(&payload3);
    let addr3 = ClaAddress::Private(Bytes::copy_from_slice(&3u64.to_be_bytes()));
    let res3 = cla
        .forward(None, &addr3, &bundle3, payload3.len() as u64, &mut stream3)
        .await
        .expect("forward to station 3 succeeds");
    assert!(matches!(res3, ForwardBundleResult::Accepted));

    // Receive both frames over the single KISS TCP connection
    let f1 = tokio::time::timeout(Duration::from_secs(5), frame_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("must receive frame 1");
    let f2 = tokio::time::timeout(Duration::from_secs(5), frame_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("must receive frame 2");

    let (seg1, _) = hardy_ltp::segment::Segment::parse(&f1).unwrap();
    let (seg2, _) = hardy_ltp::segment::Segment::parse(&f2).unwrap();

    assert_eq!(seg1.session.originator, EngineId(1));
    assert_eq!(seg2.session.originator, EngineId(1));
    // Verify distinct session numbers for the two destinations
    assert_ne!(seg1.session.number, seg2.session.number);

    cla.unregister().await;
}

#[tokio::test]
async fn test_s18_driver_shutdown_notifies_pending_transfers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // Accept connection so driver is connected, but do not send LTP acknowledgments (keeps transfer pending)
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        while let Ok(n) = stream.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    });

    let (disp_tx, _disp_rx) = mpsc::channel(16);
    let (outc_tx, mut outc_rx) = mpsc::channel(16);
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
        rtt: Duration::from_secs(10), // Long RTT so it doesn't expire during test
        ack_margin: Duration::from_secs(5),
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

    let payload = vec![0xEE; 128];
    let bundle_id = create_test_bundle_id("pending-bundle");
    let mut stream = Bytes::copy_from_slice(&payload);

    let res = cla
        .forward(
            None,
            &ClaAddress::Tcp(server_addr),
            &bundle_id,
            payload.len() as u64,
            &mut stream,
        )
        .await
        .expect("forward succeeds");
    assert!(matches!(res, ForwardBundleResult::Accepted));

    // Unregister / shutdown the CLA while the transfer is still pending
    cla.unregister().await;

    // Driver shutdown MUST notify pending transfer with TransferOutcome::Failed
    let (notified_id, outcome) = tokio::time::timeout(Duration::from_secs(5), outc_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("must receive outcome notification");

    assert_eq!(notified_id, bundle_id);
    assert_eq!(outcome, TransferOutcome::Failed);
}

/// Scenario S37: UDP keep-alive packet of 4 zero octets (0x00000000) is discarded (RFC 7122 §3.3 & §3.4).
///
/// A peer sending a 4-octet zero keep-alive packet to preserve NAT/firewall pinholes
/// must not trigger any error, warning, table pollution, or spurious cancellation.
#[tokio::test]
async fn test_s37_udp_keepalive_packet_discarded() {
    let (disp_tx, mut disp_rx) = mpsc::channel(16);
    let (outc_tx, _outc_rx) = mpsc::channel(16);
    let sink = Box::new(MockSink {
        dispatches: disp_tx,
        outcomes: outc_tx,
    });

    let cfg = Config {
        engine_id: EngineId(1),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        max_segment_payload_len: 1024,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 5,
        report_rtx_limit: 5,
        peers: vec![PeerEntry {
            engine_id: EngineId(2),
            address: Some("127.0.0.1:9".parse().unwrap()),
            node_id: None,
        }],
    };
    let cla = LtpCla::new(cfg);
    cla.on_register(sink, &[], None).await;
    let local_addr = cla.local_addr().await.unwrap();

    let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 1. Send 4-octet zero keep-alive datagram (RFC 7122 §3.4)
    peer_socket
        .send_to(&[0x00, 0x00, 0x00, 0x00], local_addr)
        .await
        .unwrap();

    // 2. Send valid LTP Red segment from peer EngineId(2)
    let payload = b"Hello through LTP UDP after keepalive";
    let session_id = SessionId {
        originator: EngineId(2),
        number: 1,
    };
    let cp = Checkpoint {
        serial: NonZeroU64::new(1).unwrap(),
        report_serial: 0,
    };
    let seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::Data(DataSegment {
            client_service: 1,
            offset: 0,
            kind: DataSegKind::RedCpEorpEob(cp),
            data: payload,
        }),
    };
    peer_socket
        .send_to(&seg.encode_to_vec(), local_addr)
        .await
        .unwrap();

    // Peer receives ReportSegment from Node 1
    let mut rx_buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), peer_socket.recv_from(&mut rx_buf))
        .await
        .expect("the timeout only bounds a regression")
        .unwrap();
    let (rs_seg, _) = LtpSegment::parse(&rx_buf[..n]).unwrap();
    let rs_serial = match rs_seg.body {
        SegmentBody::Report(rs) => rs.report_serial.get(),
        other => panic!("expected Report segment, got {other:?}"),
    };

    // Peer replies with ReportAck
    let ra_seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::ReportAck {
            report_serial: rs_serial,
        },
    };
    peer_socket
        .send_to(&ra_seg.encode_to_vec(), local_addr)
        .await
        .unwrap();

    // Node 1 dispatches bundle to sink
    let (_, _, received_bytes) = tokio::time::timeout(Duration::from_secs(5), disp_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("bundle delivered");
    assert_eq!(&received_bytes[..], payload);

    cla.unregister().await;
}

/// Scenario S39: Dynamic UDP peer port migration (NAT rebinding) mid-session (RFC 7122 §3.2).
///
/// When a peer sends segment 1 from ephemeral port A, and segment 2 from port B,
/// the CLA updates the peer mapping and routes the ReportSegment back to port B.
#[tokio::test]
async fn test_s39_udp_peer_port_migration_dynamic_rebinding() {
    let (disp_tx, mut disp_rx) = mpsc::channel(16);
    let (outc_tx, _outc_rx) = mpsc::channel(16);
    let sink = Box::new(MockSink {
        dispatches: disp_tx,
        outcomes: outc_tx,
    });

    let cfg = Config {
        engine_id: EngineId(1),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        max_segment_payload_len: 1024,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 5,
        report_rtx_limit: 5,
        peers: vec![PeerEntry {
            engine_id: EngineId(2),
            address: Some("127.0.0.1:9".parse().unwrap()), // Dummy address updated dynamically
            node_id: None,
        }],
    };
    let cla = LtpCla::new(cfg);
    cla.on_register(sink, &[], None).await;
    let local_addr = cla.local_addr().await.unwrap();

    let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let session_id = SessionId {
        originator: EngineId(2),
        number: 39,
    };

    // Socket A sends segment 1: offset 0..500 Red (no CP)
    let seg1 = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::Data(DataSegment {
            client_service: 1,
            offset: 0,
            kind: DataSegKind::Red,
            data: &[0x11; 500],
        }),
    };
    socket_a
        .send_to(&seg1.encode_to_vec(), local_addr)
        .await
        .unwrap();

    // Socket B (migrated port) sends segment 2: offset 500..1000 RedCpEorpEob
    let cp = Checkpoint {
        serial: NonZeroU64::new(1).unwrap(),
        report_serial: 0,
    };
    let seg2 = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::Data(DataSegment {
            client_service: 1,
            offset: 500,
            kind: DataSegKind::RedCpEorpEob(cp),
            data: &[0x22; 500],
        }),
    };
    socket_b
        .send_to(&seg2.encode_to_vec(), local_addr)
        .await
        .unwrap();

    // Node 1 MUST dynamically route the ReportSegment to Socket B (the new peer port)
    let mut rx_buf = [0u8; 1024];
    let (n, from_addr) =
        tokio::time::timeout(Duration::from_secs(5), socket_b.recv_from(&mut rx_buf))
            .await
            .expect("the timeout only bounds a regression")
            .unwrap();
    assert_eq!(from_addr, local_addr);

    let (rs_seg, _) = LtpSegment::parse(&rx_buf[..n]).unwrap();
    let rs_serial = match rs_seg.body {
        SegmentBody::Report(rs) => rs.report_serial.get(),
        other => panic!("expected Report segment, got {other:?}"),
    };

    // Socket B acknowledges with RA
    let ra_seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::ReportAck {
            report_serial: rs_serial,
        },
    };
    socket_b
        .send_to(&ra_seg.encode_to_vec(), local_addr)
        .await
        .unwrap();

    // Delivery of complete 1000-byte bundle to sink
    let (_, _, received_bytes) = tokio::time::timeout(Duration::from_secs(5), disp_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("bundle delivered");
    assert_eq!(received_bytes.len(), 1000);
    assert_eq!(&received_bytes[..500], &[0x11; 500]);
    assert_eq!(&received_bytes[500..], &[0x22; 500]);

    cla.unregister().await;
}

/// Scenario S40: Eviction of addr_to_engine table (> 1024 addresses) maintains peer operations.
#[tokio::test]
async fn test_s40_udp_addr_to_engine_table_eviction() {
    let (disp_tx, mut disp_rx) = mpsc::channel(16);
    let (outc_tx, _outc_rx) = mpsc::channel(16);
    let sink = Box::new(MockSink {
        dispatches: disp_tx,
        outcomes: outc_tx,
    });

    let cfg = Config {
        engine_id: EngineId(1),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        max_segment_payload_len: 1024,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 5,
        report_rtx_limit: 5,
        peers: vec![PeerEntry {
            engine_id: EngineId(2),
            address: Some("127.0.0.1:9".parse().unwrap()),
            node_id: None,
        }],
    };
    let cla = LtpCla::new(cfg);
    cla.on_register(sink, &[], None).await;
    let local_addr = cla.local_addr().await.unwrap();

    let spammer = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Send 1050 packets from different simulated session originator IDs
    for i in 100..1150 {
        let session_id = SessionId {
            originator: EngineId(i),
            number: 1,
        };
        let seg = LtpSegment {
            session: session_id,
            header_ext: Vec::new(),
            trailer_ext: Vec::new(),
            body: SegmentBody::CancelAckSender,
        };
        spammer
            .send_to(&seg.encode_to_vec(), local_addr)
            .await
            .unwrap();
    }

    // Now send legitimate transfer from EngineId(2)
    let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let session_id = SessionId {
        originator: EngineId(2),
        number: 40,
    };
    let cp = Checkpoint {
        serial: NonZeroU64::new(1).unwrap(),
        report_serial: 0,
    };
    let seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::Data(DataSegment {
            client_service: 1,
            offset: 0,
            kind: DataSegKind::RedCpEorpEob(cp),
            data: b"Data after 1024 evictions",
        }),
    };
    peer_socket
        .send_to(&seg.encode_to_vec(), local_addr)
        .await
        .unwrap();

    // Node 1 responds with ReportSegment
    let mut rx_buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), peer_socket.recv_from(&mut rx_buf))
        .await
        .expect("the timeout only bounds a regression")
        .unwrap();
    let (rs_seg, _) = LtpSegment::parse(&rx_buf[..n]).unwrap();
    let rs_serial = match rs_seg.body {
        SegmentBody::Report(rs) => rs.report_serial.get(),
        other => panic!("expected Report, got {other:?}"),
    };

    // Acknowledge with RA
    let ra_seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::ReportAck {
            report_serial: rs_serial,
        },
    };
    peer_socket
        .send_to(&ra_seg.encode_to_vec(), local_addr)
        .await
        .unwrap();

    // Sink receives bundle without disruption
    let (_, _, received) = tokio::time::timeout(Duration::from_secs(5), disp_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("bundle delivered");
    assert_eq!(&received[..], b"Data after 1024 evictions");

    cla.unregister().await;
}

/// Scenario S41: KISS TCP extreme byte stream fragmentation across escape sequences (FESC / TFESC / TFEND).
#[tokio::test]
async fn test_s41_kiss_tcp_extreme_stream_fragmentation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let (disp_tx, mut disp_rx) = mpsc::channel(16);
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

    let (mut client_stream, _) = listener.accept().await.unwrap();

    // Payload containing embedded FEND (0xC0) and FESC (0xDB)
    let mut payload = vec![0x42u8; 100];
    payload[20] = 0xC0;
    payload[50] = 0xDB;
    payload[80] = 0xC0;

    let session_id = SessionId {
        originator: EngineId(2),
        number: 41,
    };
    let cp = Checkpoint {
        serial: NonZeroU64::new(1).unwrap(),
        report_serial: 0,
    };
    let seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::Data(DataSegment {
            client_service: 1,
            offset: 0,
            kind: DataSegKind::RedCpEorpEob(cp),
            data: &payload,
        }),
    };
    let mut framed = Vec::new();
    hardy_ltp::kiss::encode_frame(
        0,
        hardy_ltp::kiss::Command::Data,
        &seg.encode_to_vec(),
        &mut framed,
    );

    // Send the KISS frame byte-by-byte (chunks of 2-3 bytes) over TCP
    for chunk in framed.chunks(3) {
        client_stream.write_all(chunk).await.unwrap();
        client_stream.flush().await.unwrap();
    }

    // Read response RS frame from Node 1
    let mut rx_buf = vec![0u8; 1024];
    let n = client_stream.read(&mut rx_buf).await.unwrap();
    let (frame, _) = hardy_ltp::kiss::decode_frame(&rx_buf[..n])
        .unwrap()
        .expect("valid RS frame");
    assert_eq!(frame.command, hardy_ltp::kiss::Command::Data);
    let (rs_seg, _) = LtpSegment::parse(&frame.payload).unwrap();
    let rs_serial = match rs_seg.body {
        SegmentBody::Report(rs) => rs.report_serial.get(),
        other => panic!("expected Report, got {other:?}"),
    };

    // Send RA frame also in tiny 2-byte fragments
    let ra_seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::ReportAck {
            report_serial: rs_serial,
        },
    };
    let mut framed_ra = Vec::new();
    hardy_ltp::kiss::encode_frame(
        0,
        hardy_ltp::kiss::Command::Data,
        &ra_seg.encode_to_vec(),
        &mut framed_ra,
    );
    for chunk in framed_ra.chunks(2) {
        client_stream.write_all(chunk).await.unwrap();
        client_stream.flush().await.unwrap();
    }

    // Verify delivery
    let (_, _, received) = tokio::time::timeout(Duration::from_secs(5), disp_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("bundle delivered");
    assert_eq!(&received[..], &payload[..]);

    cla.unregister().await;
}

/// Scenario S42: MAX_KISS_ACCUMULATOR overflow recovery (> 2 MiB without FEND).
#[tokio::test]
async fn test_s42_kiss_tcp_accumulator_overflow_and_recovery() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let (disp_tx, mut disp_rx) = mpsc::channel(16);
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

    let (mut client_stream, _) = listener.accept().await.unwrap();

    // 1. Send 2 MiB + 16 KiB of garbage without 0xC0 (FEND) to trigger accumulator overflow
    let garbage = vec![0x77u8; 64 * 1024];
    for _ in 0..33 {
        client_stream.write_all(&garbage).await.unwrap();
    }
    client_stream.flush().await.unwrap();

    // 2. Now send a valid framed LTP segment
    let payload = b"Recovered bundle after 2MiB accumulator overflow";
    let session_id = SessionId {
        originator: EngineId(2),
        number: 42,
    };
    let cp = Checkpoint {
        serial: NonZeroU64::new(1).unwrap(),
        report_serial: 0,
    };
    let seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::Data(DataSegment {
            client_service: 1,
            offset: 0,
            kind: DataSegKind::RedCpEorpEob(cp),
            data: payload,
        }),
    };
    let mut framed = Vec::new();
    hardy_ltp::kiss::encode_frame(
        0,
        hardy_ltp::kiss::Command::Data,
        &seg.encode_to_vec(),
        &mut framed,
    );
    client_stream.write_all(&framed).await.unwrap();
    client_stream.flush().await.unwrap();

    // Read RS
    let mut rx_buf = vec![0u8; 1024];
    let n = client_stream.read(&mut rx_buf).await.unwrap();
    let (frame, _) = hardy_ltp::kiss::decode_frame(&rx_buf[..n])
        .unwrap()
        .expect("valid RS");
    let (rs_seg, _) = LtpSegment::parse(&frame.payload).unwrap();
    let rs_serial = match rs_seg.body {
        SegmentBody::Report(rs) => rs.report_serial.get(),
        other => panic!("expected Report, got {other:?}"),
    };

    // Reply with RA
    let ra_seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::ReportAck {
            report_serial: rs_serial,
        },
    };
    let mut framed_ra = Vec::new();
    hardy_ltp::kiss::encode_frame(
        0,
        hardy_ltp::kiss::Command::Data,
        &ra_seg.encode_to_vec(),
        &mut framed_ra,
    );
    client_stream.write_all(&framed_ra).await.unwrap();
    client_stream.flush().await.unwrap();

    // Verify delivery
    let (_, _, received) = tokio::time::timeout(Duration::from_secs(5), disp_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("bundle delivered");
    assert_eq!(&received[..], payload);

    cla.unregister().await;
}

/// Scenario S43: KISS non-Data commands (TxDelay, Persistence, Port != 0) are ignored.
#[tokio::test]
async fn test_s43_kiss_tcp_non_data_commands_ignored() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let (disp_tx, mut disp_rx) = mpsc::channel(16);
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

    let (mut client_stream, _) = listener.accept().await.unwrap();

    // Send TxDelay (cmd 1), Persistence (cmd 2), and Port 1 data frames
    let mut non_data_frames = Vec::new();
    hardy_ltp::kiss::encode_frame(
        0,
        hardy_ltp::kiss::Command::TxDelay,
        &[0x1E],
        &mut non_data_frames,
    );
    hardy_ltp::kiss::encode_frame(
        0,
        hardy_ltp::kiss::Command::Persistence,
        &[0x3F],
        &mut non_data_frames,
    );
    hardy_ltp::kiss::encode_frame(
        1,
        hardy_ltp::kiss::Command::Data,
        &[0xAA, 0xBB],
        &mut non_data_frames,
    );
    client_stream.write_all(&non_data_frames).await.unwrap();
    client_stream.flush().await.unwrap();

    // Now send valid Port 0 Data frame
    let payload = b"Valid bundle on port 0";
    let session_id = SessionId {
        originator: EngineId(2),
        number: 43,
    };
    let cp = Checkpoint {
        serial: NonZeroU64::new(1).unwrap(),
        report_serial: 0,
    };
    let seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::Data(DataSegment {
            client_service: 1,
            offset: 0,
            kind: DataSegKind::RedCpEorpEob(cp),
            data: payload,
        }),
    };
    let mut framed = Vec::new();
    hardy_ltp::kiss::encode_frame(
        0,
        hardy_ltp::kiss::Command::Data,
        &seg.encode_to_vec(),
        &mut framed,
    );
    client_stream.write_all(&framed).await.unwrap();
    client_stream.flush().await.unwrap();

    // Read RS
    let mut rx_buf = vec![0u8; 1024];
    let n = client_stream.read(&mut rx_buf).await.unwrap();
    let (frame, _) = hardy_ltp::kiss::decode_frame(&rx_buf[..n])
        .unwrap()
        .expect("valid RS");
    let (rs_seg, _) = LtpSegment::parse(&frame.payload).unwrap();
    let rs_serial = match rs_seg.body {
        SegmentBody::Report(rs) => rs.report_serial.get(),
        other => panic!("expected Report, got {other:?}"),
    };

    // Reply with RA
    let ra_seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::ReportAck {
            report_serial: rs_serial,
        },
    };
    let mut framed_ra = Vec::new();
    hardy_ltp::kiss::encode_frame(
        0,
        hardy_ltp::kiss::Command::Data,
        &ra_seg.encode_to_vec(),
        &mut framed_ra,
    );
    client_stream.write_all(&framed_ra).await.unwrap();
    client_stream.flush().await.unwrap();

    // Verify delivery
    let (_, _, received) = tokio::time::timeout(Duration::from_secs(5), disp_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("bundle delivered");
    assert_eq!(&received[..], payload);

    cla.unregister().await;
}

/// Scenario S44: Propagation of TransferOutcome::Failed when an LTP transmission is cancelled.
#[tokio::test]
async fn test_s44_transfer_outcome_failed_on_remote_cancellation_or_timeout() {
    let (disp_tx, _disp_rx) = mpsc::channel(16);
    let (outc_tx, mut outc_rx) = mpsc::channel(16);
    let sink = Box::new(MockSink {
        dispatches: disp_tx,
        outcomes: outc_tx,
    });

    let mock_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_receiver.local_addr().unwrap();

    let cfg = Config {
        engine_id: EngineId(1),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        max_segment_payload_len: 1024,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 2,
        report_rtx_limit: 2,
        peers: vec![PeerEntry {
            engine_id: EngineId(2),
            address: Some(mock_addr),
            node_id: None,
        }],
    };
    let cla = LtpCla::new(cfg);
    cla.on_register(sink, &[], None).await;

    let payload = vec![0x99; 100];
    let bundle_id = create_test_bundle_id("cancel-bundle");
    let mut stream = Bytes::copy_from_slice(&payload);

    let res = cla
        .forward(
            None,
            &ClaAddress::Tcp(mock_addr),
            &bundle_id,
            payload.len() as u64,
            &mut stream,
        )
        .await
        .expect("forward accepted");
    assert!(matches!(res, ForwardBundleResult::Accepted));

    // The mock receiver gets the data segment from Node 1
    let mut rx_buf = [0u8; 1024];
    let (n, from_addr) =
        tokio::time::timeout(Duration::from_secs(5), mock_receiver.recv_from(&mut rx_buf))
            .await
            .expect("the timeout only bounds a regression")
            .unwrap();

    let (decoded_seg, _) = LtpSegment::parse(&rx_buf[..n]).unwrap();

    // Mock receiver cancels the session with CancelReceiver { reason: CancelReason::Rlexc }
    let cr = LtpSegment {
        session: decoded_seg.session,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::CancelReceiver {
            reason: CancelReason::Rlexc,
        },
    };
    mock_receiver
        .send_to(&cr.encode_to_vec(), from_addr)
        .await
        .unwrap();

    // Node 1 receives CR, cancels session, and sink MUST receive TransferOutcome::Failed!
    let (notified_id, outcome) = tokio::time::timeout(Duration::from_secs(5), outc_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("outcome received");

    assert_eq!(notified_id, bundle_id);
    assert_eq!(outcome, TransferOutcome::Failed);

    cla.unregister().await;
}

/// Scenario S45: Non-bundle Client Service ID segments trigger CR(UNREACH) and are never dispatched (RFC 7122 §3.1).
#[tokio::test]
async fn test_s45_client_service_filtered_before_dispatch() {
    let (disp_tx, mut disp_rx) = mpsc::channel(16);
    let (outc_tx, _outc_rx) = mpsc::channel(16);
    let sink = Box::new(MockSink {
        dispatches: disp_tx,
        outcomes: outc_tx,
    });

    let cfg = Config {
        engine_id: EngineId(1),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        max_segment_payload_len: 1024,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 5,
        report_rtx_limit: 5,
        peers: vec![PeerEntry {
            engine_id: EngineId(2),
            address: Some("127.0.0.1:9".parse().unwrap()),
            node_id: None,
        }],
    };
    let cla = LtpCla::new(cfg);
    cla.on_register(sink, &[], None).await;
    let local_addr = cla.local_addr().await.unwrap();

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Send data segment with client_service = 99 (invalid: only 1 is BP)
    let session_id = SessionId {
        originator: EngineId(2),
        number: 45,
    };
    let cp = Checkpoint {
        serial: NonZeroU64::new(1).unwrap(),
        report_serial: 0,
    };
    let seg = LtpSegment {
        session: session_id,
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::Data(DataSegment {
            client_service: 99,
            offset: 0,
            kind: DataSegKind::RedCpEorpEob(cp),
            data: b"alien service payload",
        }),
    };
    peer.send_to(&seg.encode_to_vec(), local_addr)
        .await
        .unwrap();

    // Node 1 MUST reply with CancelReceiver { reason: CancelReason::Unreach }
    let mut rx_buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut rx_buf))
        .await
        .expect("the timeout only bounds a regression")
        .unwrap();
    let (reply, _) = LtpSegment::parse(&rx_buf[..n]).unwrap();
    assert_eq!(
        reply.body,
        SegmentBody::CancelReceiver {
            reason: CancelReason::Unreach
        }
    );

    // Verify sink never received any dispatch
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(disp_rx.try_recv().is_err());

    cla.unregister().await;
}

/// Scenario S46: Concurrent bidirectional multi-bundle stress over UDP loopback.
#[tokio::test]
async fn test_s46_concurrent_bidirectional_multi_bundle_stress() {
    let (disp_tx_1, mut disp_rx_1) = mpsc::channel(32);
    let (outc_tx_1, mut outc_rx_1) = mpsc::channel(32);
    let sink_1 = Box::new(MockSink {
        dispatches: disp_tx_1,
        outcomes: outc_tx_1,
    });

    let (disp_tx_2, mut disp_rx_2) = mpsc::channel(32);
    let (outc_tx_2, mut outc_rx_2) = mpsc::channel(32);
    let sink_2 = Box::new(MockSink {
        dispatches: disp_tx_2,
        outcomes: outc_tx_2,
    });

    // Node 1
    let cfg_1 = Config {
        engine_id: EngineId(1),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        max_segment_payload_len: 500,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 5,
        report_rtx_limit: 5,
        peers: vec![PeerEntry {
            engine_id: EngineId(2),
            address: Some("127.0.0.1:9".parse().unwrap()),
            node_id: None,
        }],
    };
    let cla_1 = LtpCla::new(cfg_1);
    cla_1.on_register(sink_1, &[], None).await;
    let addr_1 = cla_1.local_addr().await.unwrap();

    // Node 2
    let cfg_2 = Config {
        engine_id: EngineId(2),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        max_segment_payload_len: 500,
        rtt: Duration::from_millis(50),
        ack_margin: Duration::from_millis(25),
        checkpoint_rtx_limit: 5,
        report_rtx_limit: 5,
        peers: vec![PeerEntry {
            engine_id: EngineId(1),
            address: Some(addr_1),
            node_id: None,
        }],
    };
    let cla_2 = LtpCla::new(cfg_2);
    cla_2.on_register(sink_2, &[], None).await;
    let addr_2 = cla_2.local_addr().await.unwrap();

    // Register peer on Node 1 pointing to Node 2
    cla_1
        .register_peer(EngineId(2), addr_2, None)
        .await
        .expect("register peer 2 on cla 1");

    // Prepare 3 bundles from 1 -> 2, and 3 bundles from 2 -> 1
    let payloads_1_to_2 = [vec![0x11u8; 800], vec![0x22u8; 1500], vec![0x33u8; 2500]];
    let payloads_2_to_1 = [vec![0x44u8; 600], vec![0x55u8; 1800], vec![0x66u8; 3000]];

    let mut expected_hashes_at_2 = Vec::new();
    let mut fwd_futs_1 = Vec::new();
    for (i, p) in payloads_1_to_2.iter().enumerate() {
        expected_hashes_at_2.push(Sha256::digest(p));
        let bundle_id = create_test_bundle_id(&format!("b-1-to-2-{i}"));
        let mut stream = Bytes::copy_from_slice(p);
        let cla_ref = &cla_1;
        fwd_futs_1.push(async move {
            cla_ref
                .forward(
                    None,
                    &ClaAddress::Tcp(addr_2),
                    &bundle_id,
                    p.len() as u64,
                    &mut stream,
                )
                .await
                .expect("fwd 1->2 succeeds");
        });
    }

    let mut expected_hashes_at_1 = Vec::new();
    let mut fwd_futs_2 = Vec::new();
    for (i, p) in payloads_2_to_1.iter().enumerate() {
        expected_hashes_at_1.push(Sha256::digest(p));
        let bundle_id = create_test_bundle_id(&format!("b-2-to-1-{i}"));
        let mut stream = Bytes::copy_from_slice(p);
        let cla_ref = &cla_2;
        fwd_futs_2.push(async move {
            cla_ref
                .forward(
                    None,
                    &ClaAddress::Tcp(addr_1),
                    &bundle_id,
                    p.len() as u64,
                    &mut stream,
                )
                .await
                .expect("fwd 2->1 succeeds");
        });
    }

    // Launch all forward calls simultaneously
    let ((), ()) = tokio::join!(
        async {
            for fut in fwd_futs_1 {
                fut.await;
            }
        },
        async {
            for fut in fwd_futs_2 {
                fut.await;
            }
        }
    );

    // Collect 3 outcomes at Node 1 and 3 outcomes at Node 2
    for _ in 0..3 {
        let (_, outc) = tokio::time::timeout(Duration::from_secs(5), outc_rx_1.recv())
            .await
            .expect("the timeout only bounds a regression")
            .unwrap();
        assert_eq!(outc, TransferOutcome::Completed);
    }
    for _ in 0..3 {
        let (_, outc) = tokio::time::timeout(Duration::from_secs(5), outc_rx_2.recv())
            .await
            .expect("the timeout only bounds a regression")
            .unwrap();
        assert_eq!(outc, TransferOutcome::Completed);
    }

    // Verify dispatches at Node 2
    let mut received_hashes_at_2 = Vec::new();
    for _ in 0..3 {
        let (_, _, bytes) = tokio::time::timeout(Duration::from_secs(5), disp_rx_2.recv())
            .await
            .expect("the timeout only bounds a regression")
            .unwrap();
        received_hashes_at_2.push(Sha256::digest(&bytes));
    }
    assert_eq!(received_hashes_at_2, expected_hashes_at_2);

    // Verify dispatches at Node 1
    let mut received_hashes_at_1 = Vec::new();
    for _ in 0..3 {
        let (_, _, bytes) = tokio::time::timeout(Duration::from_secs(5), disp_rx_1.recv())
            .await
            .expect("the timeout only bounds a regression")
            .unwrap();
        received_hashes_at_1.push(Sha256::digest(&bytes));
    }
    assert_eq!(received_hashes_at_1, expected_hashes_at_1);

    cla_1.unregister().await;
    cla_2.unregister().await;
}

#[tokio::test]
async fn test_canonical_ltp_address_resolution() {
    let eid = EngineId(0x1234_5678_9ABC_DEF0);
    let cla_addr = engine_id_to_cla_address(eid);
    assert_eq!(cla_address_to_engine_id(&cla_addr), Some(eid));

    // Unknown address formats fail resolution
    let dummy_addr = ClaAddress::Tcp("127.0.0.1:9600".parse().unwrap());
    assert_eq!(cla_address_to_engine_id(&dummy_addr), None);
    let short_private = ClaAddress::Private(Bytes::from_static(&[1, 2, 3]));
    assert_eq!(cla_address_to_engine_id(&short_private), None);
}

#[tokio::test]
async fn test_ltp_cla_init_lane_count() {
    let cfg = Config {
        engine_id: EngineId(1),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        ..Default::default()
    };
    let cla = LtpCla::new(cfg);
    let init = cla.cla_init();
    assert_eq!(init.lane_count, NonZeroU32::new(2));
    assert_eq!(init.address_type, None);
}

#[tokio::test]
async fn test_udp_cla_green_data_transfer() {
    let (disp_tx_1, mut _disp_rx_1) = mpsc::channel(16);
    let (outc_tx_1, mut outc_rx_1) = mpsc::channel(16);
    let sink_1 = Box::new(MockSink {
        dispatches: disp_tx_1,
        outcomes: outc_tx_1,
    });

    let (disp_tx_2, mut disp_rx_2) = mpsc::channel(16);
    let (outc_tx_2, mut _outc_rx_2) = mpsc::channel(16);
    let sink_2 = Box::new(MockSink {
        dispatches: disp_tx_2,
        outcomes: outc_tx_2,
    });

    let cfg_1 = Config {
        engine_id: EngineId(1),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        max_segment_payload_len: 1024,
        ..Default::default()
    };
    let cla_1 = LtpCla::new(cfg_1);
    cla_1.on_register(sink_1, &[], None).await;
    let addr_1 = cla_1.local_addr().await.unwrap();

    let cfg_2 = Config {
        engine_id: EngineId(2),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        max_segment_payload_len: 1024,
        ..Default::default()
    };
    let cla_2 = LtpCla::new(cfg_2);
    cla_2.on_register(sink_2, &[], None).await;
    let addr_2 = cla_2.local_addr().await.unwrap();

    let node_id_1: NodeId = "dtn://node-1/".parse().unwrap();
    let node_id_2: NodeId = "dtn://node-2/".parse().unwrap();

    cla_1
        .register_peer(EngineId(2), addr_2, Some(node_id_2.clone()))
        .await
        .unwrap();
    cla_2
        .register_peer(EngineId(1), addr_1, Some(node_id_1.clone()))
        .await
        .unwrap();

    // 1. Single-segment green bundle (lane = Some(1))
    let single_payload = vec![0x42u8; 128];
    let single_hash = Sha256::digest(&single_payload);
    let bundle_id_single = create_test_bundle_id("green-single");
    let mut stream_single = Bytes::copy_from_slice(&single_payload);

    let res = cla_1
        .forward(
            Some(1), // Lane 1: Green data
            &engine_id_to_cla_address(EngineId(2)),
            &bundle_id_single,
            single_payload.len() as u64,
            &mut stream_single,
        )
        .await
        .expect("forward succeeds");
    assert!(matches!(res, ForwardBundleResult::Accepted));

    // Verify dispatch at Node 2
    let (_, _, received_single) = tokio::time::timeout(Duration::from_secs(5), disp_rx_2.recv())
        .await
        .expect("the timeout only bounds a regression")
        .unwrap();
    assert_eq!(Sha256::digest(&received_single), single_hash);

    // Verify immediate completion outcome at Node 1
    let (outcome_id, outcome) = tokio::time::timeout(Duration::from_secs(5), outc_rx_1.recv())
        .await
        .expect("the timeout only bounds a regression")
        .unwrap();
    assert_eq!(outcome_id, bundle_id_single);
    assert_eq!(outcome, TransferOutcome::Completed);

    // 2. Multi-segment green bundle (lane = Some(1), 5 KiB over 1024 MTU)
    let multi_payload = vec![0x77u8; 5120];
    let multi_hash = Sha256::digest(&multi_payload);
    let bundle_id_multi = create_test_bundle_id("green-multi");
    let mut stream_multi = Bytes::copy_from_slice(&multi_payload);

    let res = cla_1
        .forward(
            Some(1), // Lane 1: Green data
            &engine_id_to_cla_address(EngineId(2)),
            &bundle_id_multi,
            multi_payload.len() as u64,
            &mut stream_multi,
        )
        .await
        .expect("forward succeeds");
    assert!(matches!(res, ForwardBundleResult::Accepted));

    let (_, _, received_multi) = tokio::time::timeout(Duration::from_secs(5), disp_rx_2.recv())
        .await
        .expect("the timeout only bounds a regression")
        .unwrap();
    assert_eq!(Sha256::digest(&received_multi), multi_hash);

    let (outcome_id, outcome) = tokio::time::timeout(Duration::from_secs(5), outc_rx_1.recv())
        .await
        .expect("the timeout only bounds a regression")
        .unwrap();
    assert_eq!(outcome_id, bundle_id_multi);
    assert_eq!(outcome, TransferOutcome::Completed);

    // 3. Verify that Green data on Lane 1 completes immediately without waiting for any ACKs
    let dummy_rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dummy_addr = dummy_rx.local_addr().unwrap();
    cla_1
        .register_peer(EngineId(99), dummy_addr, None)
        .await
        .unwrap();

    let unacked_payload = vec![0x99u8; 64];
    let unacked_id = create_test_bundle_id("unacked-green");
    let mut unacked_stream = Bytes::copy_from_slice(&unacked_payload);

    let res = cla_1
        .forward(
            Some(1), // Lane 1: Green data
            &engine_id_to_cla_address(EngineId(99)),
            &unacked_id,
            unacked_payload.len() as u64,
            &mut unacked_stream,
        )
        .await
        .expect("forward succeeds");
    assert!(matches!(res, ForwardBundleResult::Accepted));

    // Must complete immediately without any remote acknowledgments
    let (out_id, out) = tokio::time::timeout(Duration::from_millis(500), outc_rx_1.recv())
        .await
        .expect("the timeout only bounds a regression")
        .unwrap();
    assert_eq!(out_id, unacked_id);
    assert_eq!(out, TransferOutcome::Completed);

    cla_1.unregister().await;
    cla_2.unregister().await;
}

#[tokio::test]
async fn test_max_bundle_size_enforcement() {
    let (disp_tx, _) = mpsc::channel(16);
    let (outc_tx, _) = mpsc::channel(16);
    let sink = Box::new(MockSink {
        dispatches: disp_tx,
        outcomes: outc_tx,
    });

    let cfg = Config {
        engine_id: EngineId(1),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        ..Default::default()
    };
    let cla = LtpCla::new(cfg);
    // Register with a cap of 1000 bytes
    cla.on_register(sink, &[], NonZeroU64::new(1000)).await;

    // 1. Bundle of 1500 bytes exceeds the cap -> rejected
    let big_payload = vec![0xEEu8; 1500];
    let big_bundle = create_test_bundle_id("too-big");
    let mut big_stream = Bytes::copy_from_slice(&big_payload);

    let err = match cla
        .forward(
            None,
            &engine_id_to_cla_address(EngineId(2)),
            &big_bundle,
            big_payload.len() as u64,
            &mut big_stream,
        )
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("expected forward to fail with PayloadTooLarge"),
    };

    match err {
        hardy_bpa::cla::Error::PayloadTooLarge { size, max } => {
            assert_eq!(size, 1500);
            assert_eq!(max, 1000);
        }
        other => panic!("expected PayloadTooLarge, got: {other:?}"),
    }

    // 2. Bundle of exactly 1000 bytes (boundary condition: total_len == cap) -> accepted
    let exact_payload = vec![0xDDu8; 1000];
    let exact_bundle = create_test_bundle_id("exact-cap");
    let mut exact_stream = Bytes::copy_from_slice(&exact_payload);

    let res = cla
        .forward(
            Some(1),
            &engine_id_to_cla_address(EngineId(2)),
            &exact_bundle,
            exact_payload.len() as u64,
            &mut exact_stream,
        )
        .await
        .expect("exact cap bundle must be accepted");
    assert!(matches!(res, ForwardBundleResult::Accepted));

    cla.unregister().await;
}

struct PeerTrackingSink {
    peers_added: mpsc::Sender<(ClaAddress, Vec<NodeId>)>,
}

#[async_trait]
impl Sink for PeerTrackingSink {
    async fn unregister(&self) {}
    async fn dispatch(
        &self,
        _: Option<&NodeId>,
        _: Option<&ClaAddress>,
        _: &mut dyn Receiver<Segment>,
    ) -> ClaResult<Acceptance> {
        Ok(Acceptance::Accepted)
    }
    async fn add_peer(&self, addr: ClaAddress, nodes: &[NodeId]) -> ClaResult<bool> {
        let _ = self.peers_added.send((addr, nodes.to_vec())).await;
        Ok(true)
    }
    async fn remove_peer(&self, _: &ClaAddress) -> ClaResult<bool> {
        Ok(true)
    }
    async fn transfer_outcome(&self, _: &Id, _: TransferOutcome) -> ClaResult<()> {
        Ok(())
    }
}

#[tokio::test]
async fn test_dynamic_peer_discovery_registers_with_sink() {
    let (peer_tx, mut peer_rx) = mpsc::channel(16);
    let sink = Box::new(PeerTrackingSink {
        peers_added: peer_tx,
    });

    let cfg = Config {
        engine_id: EngineId(1),
        transport: TransportMode::Udp {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
        },
        peers: Vec::new(), // No pre-configured peers
        ..Default::default()
    };
    let cla = LtpCla::new(cfg);
    cla.on_register(sink, &[], None).await;
    let local_addr = cla.local_addr().await.unwrap();

    // Unknown station (Engine 77) sends an LTP green segment to Node 1 via raw UDP socket
    let remote_engine = EngineId(77);
    let ltp_seg = LtpSegment {
        session: SessionId {
            originator: remote_engine,
            number: 1,
        },
        header_ext: Vec::new(),
        trailer_ext: Vec::new(),
        body: SegmentBody::Data(DataSegment {
            client_service: 1,
            offset: 0,
            kind: DataSegKind::GreenEob,
            data: &[0xAA; 32],
        }),
    };
    let raw_bytes = ltp_seg.encode_to_vec();

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.send_to(&raw_bytes, local_addr).await.unwrap();

    // Node 1 driver must dynamically discover Engine 77 and register it via sink.add_peer
    let (discovered_addr, nodes) = tokio::time::timeout(Duration::from_secs(5), peer_rx.recv())
        .await
        .expect("the timeout only bounds a regression")
        .expect("must discover and add peer");

    assert_eq!(discovered_addr, engine_id_to_cla_address(remote_engine));
    assert!(nodes.is_empty());

    cla.unregister().await;
}
