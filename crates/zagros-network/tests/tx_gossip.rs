//! İki gerçek libp2p swarm'ı loopback TCP üzerinden bağlanır; A'nın kabul edip
//! gossip'lediği işlem B'nin mempool'una ulaşmalı. mDNS kapalı (deterministik), bootstrap elle.

mod common;

use common::{signed_transfer, test_network_config, test_node};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use std::time::Duration;
use zagros_network::behaviour::build_swarm;
use zagros_network::service;

#[tokio::test]
async fn a_transaction_admitted_on_node_a_reaches_node_bs_mempool_via_gossip() {
    let key_a = libp2p::identity::Keypair::generate_ed25519();
    let config_a = test_network_config(0, Vec::new());
    let mut swarm_a = build_swarm(key_a, &config_a).expect("node A swarm kurulamadı");

    // Node A'nın GERÇEK (OS'in seçtiği) dinleme adresini öğren.
    let listen_addr = loop {
        match swarm_a.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => break address,
            _ => continue,
        }
    };
    let peer_id_a = *swarm_a.local_peer_id();
    let dial_addr = format!("{listen_addr}/p2p/{peer_id_a}");

    let key_b = libp2p::identity::Keypair::generate_ed25519();
    let config_b = test_network_config(0, vec![dial_addr]);
    let swarm_b = build_swarm(key_b, &config_b).expect("node B swarm kurulamadı (A'ya dial dahil)");

    let node_a = test_node();
    let node_b = test_node();

    let (handle_a, rx_a) = service::channel();
    let (_handle_b, rx_b) = service::channel();
    let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    tokio::spawn(service::run(
        swarm_a,
        config_a.network_id,
        Vec::new(),
        node_a.mempool.clone(),
        node_a.runtime.clone(),
        node_a.state.clone(),
        500,
        rx_a,
        cancel_rx.clone(),
        None,
        None,
        zagros_network::service::PeerPolicy::open(50),
    ));
    tokio::spawn(service::run(
        swarm_b,
        config_b.network_id,
        Vec::new(),
        node_b.mempool.clone(),
        node_b.runtime.clone(),
        node_b.state.clone(),
        500,
        rx_b,
        cancel_rx.clone(),
        None,
        None,
        zagros_network::service::PeerPolicy::open(50),
    ));

    // Bağlantı kurulup gossipsub mesh'i oluşana kadar (heartbeat aralığı +
    // explicit-peer graft'ı) kısa bir pay bırak.
    tokio::time::sleep(Duration::from_millis(800)).await;

    let tx = signed_transfer(&node_a.mempool, 1, 0, 1);
    let tx_id = node_a
        .mempool
        .admit_transaction(tx.clone())
        .expect("node A kendi RPC'sinden gelen tx'i kabul etmeli");
    handle_a.publish_transaction(tx);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if node_b.mempool.get_transaction(&tx_id).is_some() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("node B, 10 saniye içinde gossip'lenen işlemi mempool'una almadı");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
