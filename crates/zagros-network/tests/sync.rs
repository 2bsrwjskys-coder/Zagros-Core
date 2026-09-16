//! Node A, C bağlı değilken blok üretir; C sonradan katılıp boşluk görünce
//! `/zagros/sync/1` ile eksik aralığı isteyip sırayla uygulayarak yakalar.

mod common;

use common::{signed_transfer, test_network_config, test_node};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use std::time::Duration;
use zagros_network::behaviour::build_swarm;
use zagros_network::service;

#[tokio::test]
async fn a_late_joining_node_catches_up_via_request_response_sync() {
    let key_a = libp2p::identity::Keypair::generate_ed25519();
    let config_a = test_network_config(0, Vec::new());
    let mut swarm_a = build_swarm(key_a, &config_a).expect("node A swarm kurulamadı");

    let listen_addr = loop {
        match swarm_a.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => break address,
            _ => continue,
        }
    };
    let peer_id_a = *swarm_a.local_peer_id();
    let dial_addr = format!("{listen_addr}/p2p/{peer_id_a}");

    let node_a = test_node();
    let node_c = test_node();

    // 🕐 Node A, node C HENÜZ HİÇ BAĞLI DEĞİLKEN 3 blok üretiyor (boş, sadece
    // yükseklik ilerlesin diye), bu, C katıldığında GERÇEK bir boşluk yaratır.
    for height in 1u64..=3 {
        node_a
            .runtime
            .process_block(height, height as u128 * 1000, &[])
            .unwrap_or_else(|_| panic!("node A blok #{height} üretemedi"));
    }

    // `_cancel_tx_*` canlı tutuluyor, aksi halde alıcı taraf "gönderen
    // düştü" görüp `changed()`'i sürekli anında çözerdi (meşgul döngü).
    let (_cancel_tx_a, cancel_rx_a) = tokio::sync::watch::channel(false);
    let (handle_a, rx_a) = service::channel();
    tokio::spawn(service::run(
        swarm_a,
        config_a.network_id,
        Vec::new(),
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

    // Node C ŞİMDİ katılıyor, 0'da, node A ise 3'te.
    let key_c = libp2p::identity::Keypair::generate_ed25519();
    let config_c = test_network_config(0, vec![dial_addr]);
    let swarm_c = build_swarm(key_c, &config_c).expect("node C swarm kurulamadı (A'ya dial dahil)");
    let (_cancel_tx_c, cancel_rx_c) = tokio::sync::watch::channel(false);
    let (_handle_c, rx_c) = service::channel();
    tokio::spawn(service::run(
        swarm_c,
        config_c.network_id,
        Vec::new(),
        node_c.mempool.clone(),
        node_c.runtime.clone(),
        node_c.state.clone(),
        500,
        rx_c,
        cancel_rx_c,
        None,
        None,
        zagros_network::service::PeerPolicy::open(50),
    ));

    tokio::time::sleep(Duration::from_millis(800)).await;

    // Node A #4'ü üretip gossipliyor, node C bunu alınca #1..#3 boşluğunu
    // görüp senkronizasyonu TETİKLEMELİ.
    let block_timestamp = 4_000u128;
    let tx = signed_transfer(&node_a.mempool, 1, 0, block_timestamp);
    let expected_state_root = node_a
        .runtime
        .process_block(4, block_timestamp, std::slice::from_ref(&tx))
        .expect("node A blok #4'ü üretebilmeli");
    let header = zagros_types::ArchivedBlockHeader {
        number: 4,
        parent_hash: [0xAA; 32],
        state_root: expected_state_root,
        timestamp: block_timestamp,
        tx_hashes: vec![],
    };
    handle_a.publish_block(header, vec![tx], vec![]);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if node_c.runtime.current_block_height().unwrap_or(0) >= 4 {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "node C, 15 saniye içinde senkronizasyonla #4'e ULAŞAMADI (şu an #{})",
                node_c.runtime.current_block_height().unwrap_or(0)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(
        node_c.state.state_root().unwrap(),
        expected_state_root,
        "node C'nin senkronizasyonla ulaştığı state_root, node A'nınkiyle AYNI olmalı"
    );
}
