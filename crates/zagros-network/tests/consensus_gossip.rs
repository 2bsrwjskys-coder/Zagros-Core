//! G5, gerçek libp2p (TCP/Noise/gossipsub) üzerinde BFT uçtan uca testleri:
//! 4 validator + sahte (validator olmayan) peer; 3/4 ile sessiz validator'ın
//! timeout/view-change ile atlanması.

mod common;

use common::{signed_transfer, test_network_config, test_node, TestNode};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zagros_consensus::engine::Message;
use zagros_crypto::{sign_vote, ConsensusKeypair};
use zagros_executor::{params, validator_set};
use zagros_network::behaviour::build_swarm;
use zagros_network::consensus_driver::{load_consensus_tip, ConsensusDriver};
use zagros_network::consensus_wire::WireEnvelope;
use zagros_network::messages::consensus_topic;
use zagros_network::service;
use zagros_types::consensus::{
    ActiveValidatorSet, ChainParams, ConsensusDomain, ValidatorMember, Vote, VotePhase,
};
use zagros_types::{AccountState, CHAIN_ID, GENESIS_TIMESTAMP_KEY};

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

fn keypairs(n: usize) -> Vec<ConsensusKeypair> {
    (0..n)
        .map(|i| ConsensusKeypair::from_secret_bytes(&[(i as u8) + 11; 32]))
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

/// Genesis kayıtlarını (ChainParams, genesis_hash, zaman, aktif küme) yazar.
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
}

/// `n` validator'dan `run_drivers` kadarını (ilk k) tam node olarak ayağa
/// kaldırır; dönen vektör aynı sırada. Star topoloji: herkes node 0'a bağlanır.
async fn spawn_cluster(
    kps: &[ConsensusKeypair],
    run_drivers: usize,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> (Vec<Running>, String) {
    let set = active_set(kps);
    let mut running = Vec::new();
    let mut dial_addr = String::new();
    for (i, kp) in kps.iter().enumerate().take(run_drivers) {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let bootstrap = if i == 0 {
            Vec::new()
        } else {
            vec![dial_addr.clone()]
        };
        let config = test_network_config(0, bootstrap);
        let mut swarm = build_swarm(key, &config).expect("swarm");
        if i == 0 {
            let listen_addr = loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => break address,
                    _ => continue,
                }
            };
            dial_addr = format!("{listen_addr}/p2p/{}", swarm.local_peer_id());
        }
        let node = test_node();
        install_genesis(&node, &set);
        let (handle, rx) = service::channel();
        let (driver, wiring) = ConsensusDriver::bootstrap(
            node.state.clone(),
            node.runtime.clone(),
            node.mempool.clone(),
            Some(ConsensusKeypair::from_secret_bytes(&kp.secret_bytes())),
        )
        .expect("driver bootstrap");
        assert_eq!(driver.engine().my_idx(), Some(i as u16));
        tokio::spawn(service::run(
            swarm,
            config.network_id,
            Vec::new(),
            node.mempool.clone(),
            node.runtime.clone(),
            node.state.clone(),
            500,
            rx,
            cancel_rx.clone(),
            Some(wiring),
            None,
            zagros_network::service::PeerPolicy::open(50),
        ));
        tokio::spawn(driver.run(handle.clone(), cancel_rx.clone()));
        running.push(Running { node, handle });
    }
    (running, dial_addr)
}

fn heights(running: &[Running]) -> Vec<u64> {
    running
        .iter()
        .map(|r| r.node.runtime.current_block_height().unwrap() as u64)
        .collect()
}

/// Node 0'a sırayla işlem enjekte ederek zinciri `target` yüksekliğe sürer.
async fn drive_to_height(running: &[Running], target: u64, timeout: Duration) {
    let start = Instant::now();
    let mut nonce = 0u64;
    let mut injected_for = 0u64;
    loop {
        let hs = heights(running);
        let min_h = *hs.iter().min().unwrap();
        if min_h >= target {
            return;
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

fn assert_identical_chains(running: &[Running], expect_height: u64) {
    let roots: Vec<_> = running
        .iter()
        .map(|r| r.node.state.state_root().unwrap())
        .collect();
    assert!(roots.iter().all(|r| *r == roots[0]), "state kokleri farkli");
    let tips: Vec<_> = running
        .iter()
        .map(|r| {
            load_consensus_tip(r.node.state.as_ref())
                .unwrap()
                .expect("tip kaydi")
        })
        .collect();
    for (sh, qc, _) in &tips {
        let h = &sh.header;
        assert!(h.number >= expect_height);
        assert_eq!(qc.block_hash, h.hash());
        assert_eq!(h.number, qc.height);
    }
    // Aynı yükseklikteki tip'ler aynı hash
    let min_h = tips
        .iter()
        .map(|(sh, _, _)| sh.header.number)
        .min()
        .unwrap();
    let at_min: Vec<_> = tips
        .iter()
        .filter(|(sh, _, _)| sh.header.number == min_h)
        .map(|(sh, _, _)| sh.header.hash())
        .collect();
    assert!(at_min.iter().all(|x| *x == at_min[0]));
}

#[tokio::test]
async fn four_validators_commit_identical_chain_over_real_gossip_despite_rogue_peer() {
    let kps = keypairs(4);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (running, dial_addr) = spawn_cluster(&kps, 4, cancel_rx.clone()).await;

    // Sahte peer: validator değil; konsensüs topic'ine çöp + sahte oy basar.
    let rogue_key = libp2p::identity::Keypair::generate_ed25519();
    let rogue_cfg = test_network_config(0, vec![dial_addr]);
    let mut rogue = build_swarm(rogue_key, &rogue_cfg).expect("rogue swarm");
    let domain = ConsensusDomain::new(CHAIN_ID, GENESIS_HASH);
    let forged_kp = ConsensusKeypair::from_secret_bytes(&[99u8; 32]);
    tokio::spawn(async move {
        let topic = consensus_topic(CHAIN_ID);
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        let mut n = 0u64;
        loop {
            tokio::select! {
                _ = rogue.select_next_some() => {}
                _ = tick.tick() => {
                    n += 1;
                    let mut v = Vote { height: 1 + n % 3, round: 0, phase: VotePhase::Precommit, block_hash: [0xAB; 32], validator_idx: 0, shadow: false, sig: vec![] };
                    sign_vote(&forged_kp, &domain, 0, &mut v);
                    let forged = WireEnvelope::new(&domain, 0, Message::Vote(v)).encode().unwrap();
                    let _ = rogue.behaviour_mut().gossipsub.publish(topic.clone(), forged);
                    let _ = rogue.behaviour_mut().gossipsub.publish(topic.clone(), vec![0xFF; 64]);
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(1500)).await; // mesh kurulsun
    drive_to_height(&running, 3, Duration::from_secs(40)).await;
    assert_identical_chains(&running, 3);
    let sender = common::test_address(1);
    for r in &running {
        assert!(
            r.node.state.get_nonce(&sender).unwrap() >= 3,
            "islemler her node'da yurudu"
        );
    }
    let _ = cancel_tx.send(true);
}

#[tokio::test]
async fn three_of_four_validators_progress_past_silent_proposer_via_view_change() {
    let kps = keypairs(4);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    // Validator 3 hiç ayağa kalkmaz (sessiz). h=3 proposer'ı = 3 → timeout → r=1.
    let (running, _) = spawn_cluster(&kps, 3, cancel_rx.clone()).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    drive_to_height(&running, 4, Duration::from_secs(60)).await;
    assert_identical_chains(&running, 4);
    // h=3 (sessiz proposer) tur ≥ 1'de commit edildi
    let (_, _, _) = load_consensus_tip(running[0].node.state.as_ref())
        .unwrap()
        .unwrap();
    let block3_round = {
        // Tip h≥4; h=3 QC'si 4. bloğun last_qc'sinde
        let (sh4, _, _) = load_consensus_tip(running[0].node.state.as_ref())
            .unwrap()
            .unwrap();
        let h4 = &sh4.header;
        if h4.number == 4 {
            h4.last_qc.as_ref().unwrap().round
        } else {
            u32::MAX
        }
    };
    if block3_round != u32::MAX {
        assert!(
            block3_round >= 1,
            "h=3 sessiz proposer'da tur 0'da commit olamaz"
        );
    }
    let _ = cancel_tx.send(true);
}

#[tokio::test]
async fn driver_bootstrap_is_fail_closed_without_genesis_records_but_allows_non_active_keys_as_observer(
) {
    let node = test_node();
    // Genesis kayıtları yok → Err (BU kısım hâlâ fail-closed)
    assert!(ConsensusDriver::bootstrap(
        node.state.clone(),
        node.runtime.clone(),
        node.mempool.clone(),
        None
    )
    .is_err());
    let kps = keypairs(4);
    install_genesis(&node, &active_set(&kps));
    // G8: kümede olmayan (kayıtlı bile olmayan) bir anahtar ARTIK hata değil
    // — operatör node'unu Active olmadan ÖNCE başlatabilmeli (Candidate/
    // Probation onboarding). Gözlemci olarak başlar, güvenlik gevşemez
    // (yalnızca oy/öneri ÜRETMEZ).
    let stranger = ConsensusKeypair::from_secret_bytes(&[200u8; 32]);
    let (d, _) = ConsensusDriver::bootstrap(
        node.state.clone(),
        node.runtime.clone(),
        node.mempool.clone(),
        Some(stranger),
    )
    .unwrap();
    assert_eq!(
        d.engine().my_idx(),
        None,
        "kumede olmayan anahtar gozlemciye duser"
    );
    assert_eq!(
        d.probation_identity(),
        None,
        "kayitli bile olmayan anahtar Probation da degildir"
    );
    // Gözlemci (anahtarsız) → Ok
    let (d, _) = ConsensusDriver::bootstrap(
        node.state.clone(),
        node.runtime.clone(),
        node.mempool.clone(),
        None,
    )
    .unwrap();
    assert_eq!(d.engine().my_idx(), None);
    // Yükseklik > 0 ama tip kaydı yok → Err (G6 catch-up gerekir), BU da hâlâ fail-closed
    node.runtime.set_block_height(5).unwrap();
    assert!(ConsensusDriver::bootstrap(
        node.state.clone(),
        node.runtime.clone(),
        node.mempool.clone(),
        None
    )
    .is_err());
    let _ = Arc::clone(&node.state);
}
