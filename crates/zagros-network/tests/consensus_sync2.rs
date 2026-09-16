//! G6, gerçek libp2p üzerinde `/zagros/sync/2` QC'li catch-up testleri:
//! geç katılan validator, crash/restart kurtarma, sahte-QC sunan peer.

mod common;

use common::{test_network_config, test_node, TestNode};
use libp2p::futures::StreamExt;
use libp2p::request_response;
use libp2p::swarm::SwarmEvent;
use std::time::{Duration, Instant};
use zagros_crypto::ConsensusKeypair;
use zagros_executor::{params, validator_set};
use zagros_network::behaviour::{build_swarm, ZagrosBehaviourEvent};
use zagros_network::consensus_driver::{load_consensus_tip, ConsensusDriver};
use zagros_network::messages::{Sync2Request, Sync2Response, Sync2Status};
use zagros_network::service;
use zagros_network::sync2;
use zagros_types::consensus::{ActiveValidatorSet, ChainParams, ValidatorMember};
use zagros_types::{AccountState, GENESIS_TIMESTAMP_KEY};

const GENESIS_HASH: [u8; 32] = [7u8; 32];

fn now_secs() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u128
}
fn test_params() -> ChainParams {
    let mut p = ChainParams::genesis_defaults();
    p.block_interval_ms = 100;
    p.t_base_ms = 400;
    p.idle_block_interval_s = 10;
    p.validate().unwrap();
    p
}
/// `common::signed_transfer` tüm tx'lere aynı `tx_id`'yi verir (eski testler
/// için yeterli); catch-up gövdeleri `tx_body_<id>` ile okunduğundan burada
/// üretimdeki gibi içerik-türevli benzersiz id kullanılır.
fn signed_transfer(
    mempool: &zagros_mempool::Mempool,
    seed: u8,
    nonce: u64,
    timestamp: u128,
) -> zagros_types::Transaction {
    let mut tx = common::signed_transfer(mempool, seed, nonce, timestamp);
    tx.tx_id = tx.hash();
    tx.sign(&common::test_secret_key(seed));
    tx
}

fn keypairs(n: usize) -> Vec<ConsensusKeypair> {
    (0..n)
        .map(|i| ConsensusKeypair::from_secret_bytes(&[(i as u8) + 31; 32]))
        .collect()
}
fn active_set(kps: &[ConsensusKeypair]) -> ActiveValidatorSet {
    ActiveValidatorSet {
        epoch: 0,
        members: kps
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorMember {
                address: format!("0x{:040x}", i + 1),
                consensus_pubkey: k.public_key(),
            })
            .collect(),
    }
}
/// Genesis zamanı tüm node'larda AYNI olmalı (üretimde genesis dosyasından
/// gelir); executor'ın zaman-bazlı hesapları köke girer.
fn genesis_ts() -> u128 {
    1_700_000_000
}

fn install_genesis(node: &TestNode, set: &ActiveValidatorSet) {
    let st = node.state.as_ref();
    params::store_chain_params(st, &test_params()).unwrap();
    params::store_genesis_hash(st, &GENESIS_HASH).unwrap();
    let ts = AccountState {
        balance: genesis_ts(),
        ..Default::default()
    };
    st.set_account(&GENESIS_TIMESTAMP_KEY.to_string(), ts)
        .unwrap();
    validator_set::store_active_set(st, set).unwrap();
    validator_set::store_active_set_epoch_snapshot(st, set).unwrap();
    st.flush().unwrap();
}

struct Running {
    node: TestNode,
    handle: service::NetworkHandle,
    cancel: tokio::sync::watch::Sender<bool>,
}

async fn listen_addr_of(
    swarm: &mut libp2p::Swarm<zagros_network::behaviour::ZagrosBehaviour>,
) -> String {
    let addr = loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => break address,
            _ => continue,
        }
    };
    format!("{addr}/p2p/{}", swarm.local_peer_id())
}

/// Tek validator node'u ayağa kaldırır (kendi cancel'ı ile; restart testi için).
async fn spawn_node(
    kp: &ConsensusKeypair,
    set: &ActiveValidatorSet,
    bootstrap: Vec<String>,
    node: Option<TestNode>,
) -> (Running, String) {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let config = test_network_config(0, bootstrap);
    let mut swarm = build_swarm(key, &config).expect("swarm");
    let dial_addr = listen_addr_of(&mut swarm).await;
    let node = match node {
        Some(n) => n,
        None => {
            let n = test_node();
            install_genesis(&n, set);
            n
        }
    };
    let (handle, rx) = service::channel();
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (driver, wiring) = ConsensusDriver::bootstrap_with(
        node.state.clone(),
        node.runtime.clone(),
        node.mempool.clone(),
        Some(ConsensusKeypair::from_secret_bytes(&kp.secret_bytes())),
        None,
        3, // küçük batch: çok turlu catch-up da test edilsin
    )
    .expect("driver bootstrap");
    tokio::spawn(service::run(
        swarm,
        config.network_id,
        Vec::new(),
        node.mempool.clone(),
        node.runtime.clone(),
        node.state.clone(),
        3,
        rx,
        cancel_rx.clone(),
        Some(wiring),
        None,
        zagros_network::service::PeerPolicy::open(50),
    ));
    tokio::spawn(driver.run(handle.clone(), cancel_rx));
    (
        Running {
            node,
            handle,
            cancel: cancel_tx,
        },
        dial_addr,
    )
}

fn heights(running: &[&Running]) -> Vec<u64> {
    running
        .iter()
        .map(|r| r.node.runtime.current_block_height().unwrap() as u64)
        .collect()
}

async fn drive_to_height(
    running: &[&Running],
    target: u64,
    timeout: Duration,
    nonce_start: u64,
) -> u64 {
    let start = Instant::now();
    let mut nonce = nonce_start;
    let mut injected_for = 0u64;
    loop {
        let hs = heights(running);
        let min_h = *hs.iter().min().unwrap();
        if min_h >= target {
            return nonce;
        }
        if injected_for <= min_h {
            let tx = signed_transfer(&running[0].node.mempool, 1, nonce, now_secs());
            running[0]
                .node
                .mempool
                .admit_transaction(tx.clone())
                .expect("mempool kabul");
            running[0].handle.publish_transaction(tx);
            nonce += 1;
            injected_for = min_h + 1;
        }
        assert!(
            start.elapsed() < timeout,
            "zaman asimi: yukseklikler {hs:?} (hedef {target})"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

async fn wait_height(node: &TestNode, target: u64, timeout: Duration) {
    let start = Instant::now();
    loop {
        let h = node.runtime.current_block_height().unwrap() as u64;
        if h >= target {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "zaman asimi: yukseklik {h} (hedef {target})"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

#[tokio::test]
async fn late_joining_validator_catches_up_via_sync2_then_participates() {
    let kps = keypairs(4);
    let set = active_set(&kps);
    // 3 validator (0,1,2) ilerler; 3 daha sonra katılır. h=4 proposer'ı = 3:
    // ilk 3 blok yalnız 0-2 ile (Q=3) commit edilebilir; sonra 3 gelir.
    let (a, addr_a) = spawn_node(&kps[0], &set, vec![], None).await;
    let (b, _) = spawn_node(&kps[1], &set, vec![addr_a.clone()], None).await;
    let (c, _) = spawn_node(&kps[2], &set, vec![addr_a.clone()], None).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let nonce = drive_to_height(&[&a, &b, &c], 3, Duration::from_secs(60), 0).await;

    // Geç katılan validator 3: sıfırdan (yalnız genesis) başlar → sync/2
    let (d, _) = spawn_node(&kps[3], &set, vec![addr_a.clone()], None).await;
    wait_height(&d.node, 3, Duration::from_secs(30)).await;
    // Catch-up ile gelen bloklar: konsensüs kayıtları + tip + aynı kök
    let (tip_d, qc_d, _) = load_consensus_tip(d.node.state.as_ref()).unwrap().unwrap();
    let (tip_a, _, _) = load_consensus_tip(a.node.state.as_ref()).unwrap().unwrap();
    assert_eq!(
        tip_d.header.hash(),
        sync2::load_consensus_record(d.node.state.as_ref(), tip_d.header.number)
            .unwrap()
            .unwrap()
            .0
            .header
            .hash()
    );
    assert_eq!(qc_d.block_hash, tip_d.header.hash());
    if tip_a.header.number == tip_d.header.number {
        assert_eq!(tip_a.header.hash(), tip_d.header.hash());
    }
    assert_eq!(
        a.node.state.state_root().unwrap(),
        d.node.state.state_root().unwrap()
    );

    // Artık 4 node birlikte ilerler; h=4/8 proposer'ı D, D katılmasaydı
    // timeout'la geçerdi, katıldığı için tur 0'da.
    let _ = drive_to_height(&[&a, &b, &c, &d], 6, Duration::from_secs(60), nonce).await;
    let roots: Vec<_> = [&a, &b, &c, &d]
        .iter()
        .map(|r| r.node.state.state_root().unwrap())
        .collect();
    assert!(roots.iter().all(|r| *r == roots[0]));
    for r in [&a, &b, &c, &d] {
        let _ = r.cancel.send(true);
    }
}

#[tokio::test]
async fn validator_restart_recovers_tip_and_qc_from_disk_and_continues() {
    let kps = keypairs(4);
    let set = active_set(&kps);
    let (a, addr_a) = spawn_node(&kps[0], &set, vec![], None).await;
    let (b, _) = spawn_node(&kps[1], &set, vec![addr_a.clone()], None).await;
    let (c, _) = spawn_node(&kps[2], &set, vec![addr_a.clone()], None).await;
    let (d, _) = spawn_node(&kps[3], &set, vec![addr_a.clone()], None).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let nonce = drive_to_height(&[&a, &b, &c, &d], 2, Duration::from_secs(60), 0).await;

    // D "çöker": görevleri iptal, aynı disk (state) ile yeniden kurulur.
    let _ = d.cancel.send(true);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let h_before = d.node.runtime.current_block_height().unwrap() as u64;
    let (tip_before, _, _) = load_consensus_tip(d.node.state.as_ref()).unwrap().unwrap();
    assert_eq!(tip_before.header.number, h_before);
    let Running { node: d_node, .. } = d;
    let (d2, _) = spawn_node(&kps[3], &set, vec![addr_a.clone()], Some(d_node)).await;
    // Restart sonrası motor tip'ten devam eder (ChainTip = disk kaydı)
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let _ = drive_to_height(
        &[&a, &b, &c, &d2],
        h_before + 3,
        Duration::from_secs(60),
        nonce,
    )
    .await;
    let roots: Vec<_> = [&a, &b, &c, &d2]
        .iter()
        .map(|r| r.node.state.state_root().unwrap())
        .collect();
    assert!(roots.iter().all(|r| *r == roots[0]));
    for r in [&a, &b, &c, &d2] {
        let _ = r.cancel.send(true);
    }
}

#[tokio::test]
async fn malicious_sync2_server_with_forged_qc_is_rejected_and_honest_peer_is_used() {
    let kps = keypairs(4);
    let set = active_set(&kps);
    let (a, addr_a) = spawn_node(&kps[0], &set, vec![], None).await;
    let (b, _) = spawn_node(&kps[1], &set, vec![addr_a.clone()], None).await;
    let (c, _) = spawn_node(&kps[2], &set, vec![addr_a.clone()], None).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let _ = drive_to_height(&[&a, &b, &c], 2, Duration::from_secs(60), 0).await;

    // Kötü sunucu: gerçek blokları A'nın diskinden okur ama QC imzalarını bozar
    // ve tip'ini abartır (Status: 100).
    let evil_key = libp2p::identity::Keypair::generate_ed25519();
    let evil_cfg = test_network_config(0, vec![]);
    let mut evil = build_swarm(evil_key, &evil_cfg).expect("evil swarm");
    let evil_addr = listen_addr_of(&mut evil).await;
    let a_state = a.node.state.clone();
    tokio::spawn(async move {
        loop {
            if let SwarmEvent::Behaviour(ZagrosBehaviourEvent::Sync2(
                request_response::Event::Message {
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) = evil.select_next_some().await
            {
                let resp = match request {
                    Sync2Request::GetStatus => Sync2Response::Status(Sync2Status {
                        tip_height: 100,
                        tip_hash: [0xEE; 32],
                        epoch: 0,
                        validator_set_hash: [0; 32],
                    }),
                    other => match sync2::build_response(&a_state, other, 3) {
                        Sync2Response::Blocks(mut blocks) => {
                            for b in &mut blocks {
                                for sig in &mut b.qc.sigs {
                                    sig[0] ^= 0xFF; // sahte QC
                                }
                            }
                            Sync2Response::Blocks(blocks)
                        }
                        r => r,
                    },
                };
                let _ = evil.behaviour_mut().sync2.send_response(channel, resp);
            }
        }
    });

    // Geç katılan D: ÖNCE kötü sunucuya, sonra A'ya bağlanır.
    let (d, _) = spawn_node(&kps[3], &set, vec![evil_addr, addr_a.clone()], None).await;
    wait_height(&d.node, 2, Duration::from_secs(40)).await;
    // Sahte QC'li bloklar asla yazılmadı: D'nin kayıtları A ile aynı
    let (tip_d, qc_d, _) = load_consensus_tip(d.node.state.as_ref()).unwrap().unwrap();
    let (rec_a, _, _) = sync2::load_consensus_record(a.node.state.as_ref(), tip_d.header.number)
        .unwrap()
        .unwrap();
    assert_eq!(tip_d.header.hash(), rec_a.header.hash());
    zagros_crypto::verify_qc(
        &qc_d,
        &zagros_types::consensus::ConsensusDomain::new(zagros_types::CHAIN_ID, GENESIS_HASH),
        &set,
    )
    .unwrap();
    assert_eq!(
        a.node.state.state_root().unwrap(),
        d.node.state.state_root().unwrap()
    );
    for r in [&a, &b, &c, &d] {
        let _ = r.cancel.send(true);
    }
}
