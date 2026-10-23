#![no_main]

use std::{net::SocketAddr, sync::OnceLock, time::Duration};

use libfuzzer_sys::fuzz_target;
use tokio::{net::UdpSocket, runtime::Runtime, time::timeout};

use hardy_ltp_cla_fuzz::setup_udp_cla;

static STATE: OnceLock<(Runtime, SocketAddr)> = OnceLock::new();

fn get_state() -> &'static (Runtime, SocketAddr) {
    STATE.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");

        let addr = rt.block_on(async {
            let (_cla, bound_addr) = setup_udp_cla().await;
            bound_addr
        });

        (rt, addr)
    })
}

fuzz_target!(|data: &[u8]| {
    let (rt, target_addr) = get_state();
    rt.block_on(async {
        let _ = timeout(Duration::from_millis(200), async {
            if let Ok(client) = UdpSocket::bind("127.0.0.1:0").await {
                let _ = client.send_to(data, target_addr).await;
            }
        })
        .await;
    });
});
