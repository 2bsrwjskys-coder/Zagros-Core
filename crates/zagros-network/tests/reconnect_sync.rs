//! Regresyon: senkron yalnız yeni gossip boşluğuyla tetiklenince, bağlandığı
//! anda geride olan peer sonraki gossip'e dek yakalayamıyordu. A, C bağlı değilken
//! blok üretir; C bağlanınca yeni gossip olmadan proaktif senkronla yetişmeli.

mod common;

use common::{signed_transfer, test_network_config, test_node};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use std::time::Duration;
use zagros_network::behaviour::build_swarm;
use zagros_network::service;

#[tokio::test]
async fn a_newly_connecting_peer_catches_up_without_waiting_for_a_new_gossip() {
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

    // 🕐 Node A, node C HENÜZ HİÇ BAĞLI DEĞİLKEN 3 blok üretiyor, biri gerçek
    // bir tx taşıyor, ikisi boş (sadece yükseklik ilerlesin diye).
    let block_timestamp = 1_000u128;
    let tx = signed_transfer(&node_a.mempool, 1, 0, block_timestamp);
    let expected_state_root = node_a
        .runtime
        .process_block(1, block_timestamp, std::slice::from_ref(&tx))
        .expect("node A blok #1'i üretemedi");
    for height in 2u64..=3 {
        node_a
            .runtime
            .process_block(height, height as u128 * 1000, &[])
            .unwrap_or_else(|_| panic!("node A blok #{height} üretemedi"));
    }

    let (_cancel_tx_a, cancel_rx_a) = tokio::sync::watch::channel(false);
    let (_handle_a, rx_a) = service::channel();
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

    // Node C ŞİMDİ bağlanıyor, bundan sonra node A ASLA yeni bir şey
    // gossiplemiyor (ne blok ne tx). Yakalama TAMAMEN bağlantının kendisinin
    // tetiklediği proaktif senkronizasyondan gelmeli.
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

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if node_c.runtime.current_block_height().unwrap_or(0) >= 3 {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "node C, YENİ bir gossip olmadan, bağlantının kendisiyle 10 saniye içinde #3'e ULAŞAMADI (şu an #{})",
                node_c.runtime.current_block_height().unwrap_or(0)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Blok #2/#3 boş (tx yok), trie'yi kirletmiyorlar (bkz. `set_account`'ın
    // sadece `0x`-prefiksli anahtarları trie'ye yazması), bu yüzden nihai
    // state_root hâlâ #1'in ürettiğiyle AYNI olmalı.
    assert_eq!(
        node_c.state.state_root().unwrap(),
        expected_state_root,
        "node C'nin proaktif senkronizasyonla ulaştığı state_root, node A'nınkiyle AYNI olmalı"
    );
}
