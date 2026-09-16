//! Node A gerçek blok üretip gossip'ler; node B `apply_external_block` ile
//! bağımsız yürütüp aynı `state_root`a ulaşır. `parent_hash`/`tx_hashes` bilerek
//! dummy: follower bunları kullanmaz.

mod common;

use common::{signed_transfer, test_network_config, test_node};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use std::time::Duration;
use zagros_network::behaviour::build_swarm;
use zagros_network::service;
use zagros_types::ArchivedBlockHeader;

#[tokio::test]
async fn a_block_produced_on_node_a_is_independently_replayed_by_node_b_with_matching_state_root() {
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

    tokio::time::sleep(Duration::from_millis(800)).await;

    // Node A: GERÇEK proposer akışı, `ConsensusEngine::produce_block`'un
    // sarmaladığı AYNI `Runtime::process_block`.
    let block_timestamp = 1_000u128;
    let tx = signed_transfer(&node_a.mempool, 1, 0, block_timestamp);
    let expected_state_root = node_a
        .runtime
        .process_block(1, block_timestamp, std::slice::from_ref(&tx))
        .expect("node A kendi bloğunu üretebilmeli");

    // `parent_hash`/`tx_hashes` BİLEREK dummy, follower bunları kullanmıyor
    // (bkz. `Runtime::apply_external_block`'un doc yorumu).
    let header = ArchivedBlockHeader {
        number: 1,
        parent_hash: [0xAA; 32],
        state_root: expected_state_root,
        timestamp: block_timestamp,
        tx_hashes: vec![],
    };
    handle_a.publish_block(header, vec![tx], vec![]);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if node_b.runtime.current_block_height().unwrap_or(0) >= 1 {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("node B, 10 saniye içinde gossip'lenen bloğu uygulamadı");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(
        node_b.state.state_root().unwrap(),
        expected_state_root,
        "node B'nin BAĞIMSIZ yürüttüğü blok, node A'nınkiyle AYNI state_root'a ulaşmalı"
    );
    // 🛡️ Kök eşleşmesi yetmez: tx `TransactionExpired` ile iki tarafta aynı
    // reddedilse kökler yine eşleşirdi. Nonce'un 0→1 ilerlemesi gerçek yürütmeyi kanıtlar.
    let sender = zagros_types::Transaction::address_from_secret_key(
        &secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
    );
    assert_eq!(
        node_b.state.get_nonce(&sender).unwrap(),
        1,
        "tx GERÇEKTEN uygulanmış olmalı (nonce 0->1), sessizce reddedilmemeli"
    );
}

/// Boşluk senaryosu: B'ye doğrudan #2 gelir, A'da #1 yoktur (`NotAvailable`);
/// B çökmemeli, #0'da beklemeli.
#[tokio::test]
async fn a_block_number_gap_is_skipped_not_crashed_without_sync() {
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

    let key_b = libp2p::identity::Keypair::generate_ed25519();
    let config_b = test_network_config(0, vec![dial_addr]);
    let swarm_b = build_swarm(key_b, &config_b).expect("node B swarm kurulamadı");

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
    let join_b = tokio::spawn(service::run(
        swarm_b,
        config_b.network_id,
        Vec::new(),
        node_b.mempool.clone(),
        node_b.runtime.clone(),
        node_b.state.clone(),
        500,
        rx_b,
        cancel_rx,
        None,
        None,
        zagros_network::service::PeerPolicy::open(50),
    ));

    tokio::time::sleep(Duration::from_millis(800)).await;

    // Doğrudan #2'yi gossipliyoruz, node B hâlâ #0'da, bu bir BOŞLUK.
    let header = ArchivedBlockHeader {
        number: 2,
        parent_hash: [0u8; 32],
        state_root: [0u8; 32],
        timestamp: 1,
        tx_hashes: vec![],
    };
    handle_a.publish_block(header, vec![], vec![]);

    // Panik atmadığını (görev canlı kaldığını) ve yüksekliğin 0'da
    // sabit kaldığını (boşluk uygulanmadan atlandığını) doğrula.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        !join_b.is_finished(),
        "node B'nin görevi boşluklu bloktan dolayı ÇÖKMEMELİ"
    );
    assert_eq!(
        node_b.runtime.current_block_height().unwrap_or(99),
        0,
        "boşluklu blok uygulanmamalı, node B #0'da beklemeli"
    );
}
