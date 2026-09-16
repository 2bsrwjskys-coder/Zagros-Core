//! G11 (§9 Redial) regresyonu: follower A, proposer B kapalıyken başlar; eski
//! davranışta tek deneme başarısız olup sonsuza dek sessiz kalırdı. Artık üstel
//! backoff ile inatla arar, B ayağa kalkınca bağlanıp proaktif senkronla yetişir.
mod common;

use common::{signed_transfer, test_network_config, test_node};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use std::time::Duration;
use zagros_network::behaviour::build_swarm;
use zagros_network::service;

#[tokio::test(flavor = "multi_thread")]
async fn a_node_started_while_its_bootstrap_peer_is_down_redials_and_catches_up() {
    // ---- B'nin kimliği ve SABİT adresi: önce dinle, portu öğren, KAPAT ----
    let key_b = libp2p::identity::Keypair::generate_ed25519();
    let peer_id_b = key_b.public().to_peer_id();
    let probe_cfg = test_network_config(0, Vec::new());
    let mut probe = build_swarm(key_b.clone(), &probe_cfg).expect("B probe swarm");
    let listen_addr = loop {
        match probe.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => break address,
            _ => continue,
        }
    };
    let port: u16 = listen_addr
        .iter()
        .find_map(|p| match p {
            libp2p::multiaddr::Protocol::Tcp(t) => Some(t),
            _ => None,
        })
        .expect("tcp portu");
    drop(probe); // B artık KAPALI — port serbest, adres biliniyor.
    let dial_addr = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer_id_b}");

    // ---- A: B kapalıyken başlar (açılış araması BAŞARISIZ olacak) ----
    let key_a = libp2p::identity::Keypair::generate_ed25519();
    let config_a = test_network_config(0, vec![dial_addr.clone()]);
    let swarm_a = build_swarm(key_a, &config_a).expect("A swarm");
    let node_a = test_node();
    let (_cancel_a, cancel_rx_a) = tokio::sync::watch::channel(false);
    let (_handle_a, rx_a) = service::channel();
    tokio::spawn(service::run(
        swarm_a,
        config_a.network_id,
        zagros_network::peer_book::parse_bootstrap(&config_a.bootstrap_nodes),
        node_a.mempool.clone(),
        node_a.runtime.clone(),
        node_a.state.clone(),
        500,
        rx_a,
        cancel_rx_a,
        None,
        None,
        zagros_network::service::PeerPolicy::open(50),
    ));

    // A'nın ilk denemesi + ilk backoff penceresi geçsin (B hâlâ kapalı).
    tokio::time::sleep(Duration::from_secs(3)).await;

    // ---- B ayağa kalkar: AYNI anahtar + AYNI port, 3 bloklu zincirle ----
    let node_b = test_node();
    let tx = signed_transfer(&node_b.mempool, 1, 0, 1_000);
    node_b
        .runtime
        .process_block(1, 1_000, std::slice::from_ref(&tx))
        .expect("B blok 1");
    for h in 2u64..=3 {
        node_b
            .runtime
            .process_block(h, h as u128 * 1_000, &[])
            .expect("B blok");
    }
    let config_b = test_network_config(port, Vec::new());
    let swarm_b = build_swarm(key_b, &config_b).expect("B swarm (restart)");
    let (_cancel_b, cancel_rx_b) = tokio::sync::watch::channel(false);
    let (_handle_b, rx_b) = service::channel();
    tokio::spawn(service::run(
        swarm_b,
        config_b.network_id,
        Vec::new(),
        node_b.mempool.clone(),
        node_b.runtime.clone(),
        node_b.state.clone(),
        500,
        rx_b,
        cancel_rx_b,
        None,
        None,
        zagros_network::service::PeerPolicy::open(50),
    ));

    // ---- A'nın redial'ı bağlanmalı ve bağlantı-tetikli sync A'yı 3'e getirmeli ----
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let h = node_a.runtime.current_block_height().expect("A yükseklik") as u64;
        if h >= 3 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "A, redial + catch-up ile 30 sn içinde yetişmeliydi (yükseklik={h}) — G11 regresyonu!"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let root_a = node_a.state.state_root().expect("A kök");
    let root_b = node_b.state.state_root().expect("B kök");
    assert_eq!(root_a, root_b, "yakalama sonrası kökler eşit olmalı");
}
