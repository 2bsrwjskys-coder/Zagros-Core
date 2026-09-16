//! G8: validator lifecycle uçtan uca (gerçek libp2p + epoch geçişi): Probation
//! validator ShadowVote yayınlar, proposer bloğa gömer, her node liveness'a
//! işler, epoch sınırında Active'e terfi eder. Genesis zamanı bilinçli geçmişe
//! alınır (`epoch_at >= probation_epochs`), gerçek zaman beklenmez.

mod common;

use common::{signed_transfer, test_network_config, test_node, TestNode};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use std::time::{Duration, Instant};
use zagros_crypto::ConsensusKeypair;
use zagros_executor::{params, validator_set};
use zagros_network::behaviour::build_swarm;
use zagros_network::consensus_driver::ConsensusDriver;
use zagros_network::service;
use zagros_types::consensus::{ActiveValidatorSet, ChainParams, ValidatorMember, ValidatorStatus};
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
    // epoch_seconds regülasyon alt sınırı (300s), "genesis zamanını geçmişe
    // al" hilesiyle gerçek zaman beklemeden test ediyoruz (bkz. dosya başı).
    p.epoch_seconds = 300;
    p.validate().unwrap();
    p
}

fn keypairs(n: usize) -> Vec<ConsensusKeypair> {
    (0..n)
        .map(|i| ConsensusKeypair::from_secret_bytes(&[(i as u8) + 51; 32]))
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

/// Probation validator adresi (5. keypair, kümede DEĞİL).
fn probation_address() -> String {
    "0x000000000000000000000000000000000000ff01".to_string() // 40 hex karakter
}

/// Genesis kayıtları + 1 Probation validator hesabı. `epochs_in_the_past`:
/// genesis zamanı `now - epochs_in_the_past*epoch_seconds` olarak yazılır —
/// ilk BFT bloğu işlendiğinde `advance_epoch_if_due` DOĞRUDAN o kadar epoch
/// ileriye "atlar" (gerçek zaman beklemeden).
fn install_genesis(
    node: &TestNode,
    set: &ActiveValidatorSet,
    probation_kp: &ConsensusKeypair,
    genesis_ts: u128,
) {
    let st = node.state.as_ref();
    let p = test_params();
    params::store_chain_params(st, &p).unwrap();
    params::store_genesis_hash(st, &GENESIS_HASH).unwrap();
    let ts = AccountState {
        balance: genesis_ts,
        ..Default::default()
    };
    st.set_account(&GENESIS_TIMESTAMP_KEY.to_string(), ts)
        .unwrap();
    validator_set::store_active_set(st, set).unwrap();
    validator_set::store_active_set_epoch_snapshot(st, set).unwrap();

    // `advance_epoch_if_due` kümeyi hesapların `validator_status`undan hesaplar;
    // genesis validatörlerin Active AccountState kaydı olmalı, yoksa küme MIN altına düşer.
    for m in &set.members {
        let acc = AccountState {
            consensus_pubkey: m.consensus_pubkey,
            validator_status: Some(ValidatorStatus::Active),
            validator_status_epoch: 0,
            staked_balance: params::min_validator_stake_zagros(st, &p).unwrap(),
            is_registered_validator: true,
            ..Default::default()
        };
        st.set_account(&m.address, acc).unwrap();
    }

    let probation_acc = AccountState {
        consensus_pubkey: probation_kp.public_key(),
        validator_status: Some(ValidatorStatus::Probation),
        validator_status_epoch: 0,
        staked_balance: params::min_validator_stake_zagros(st, &p).unwrap(),
        is_registered_validator: true,
        ..Default::default()
    };
    st.set_account(&probation_address(), probation_acc).unwrap();
    st.flush().unwrap();
}

struct Running {
    node: TestNode,
    handle: service::NetworkHandle,
}

async fn spawn_node(
    kp_for_engine: Option<&ConsensusKeypair>,
    set: &ActiveValidatorSet,
    probation_kp: &ConsensusKeypair,
    genesis_ts: u128,
    bootstrap: Vec<String>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> (Running, String, ConsensusDriver) {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let config = test_network_config(0, bootstrap);
    let mut swarm = build_swarm(key, &config).expect("swarm");
    let listen_addr = loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => break address,
            _ => continue,
        }
    };
    let dial_addr = format!("{listen_addr}/p2p/{}", swarm.local_peer_id());
    let node = test_node();
    install_genesis(&node, set, probation_kp, genesis_ts);
    let (handle, rx) = service::channel();
    let (driver, wiring) = ConsensusDriver::bootstrap(
        node.state.clone(),
        node.runtime.clone(),
        node.mempool.clone(),
        kp_for_engine.map(|k| ConsensusKeypair::from_secret_bytes(&k.secret_bytes())),
    )
    .expect("driver bootstrap");
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
    let running = Running { node, handle };
    (running, dial_addr, driver)
}

fn heights(running: &[&Running]) -> Vec<u64> {
    running
        .iter()
        .map(|r| r.node.runtime.current_block_height().unwrap() as u64)
        .collect()
}

/// `drive_to_height` gibi ama bir hedef yukseklige DEGIL, sabit bir gercek
/// sure boyunca tx enjekte ederek blok uretimini canli tutar, epoch sinirini
/// GERCEK zamanla (tampon suresiyle) beklerken ayni zamanda ShadowVote
/// gossip'inin en az bir kac tur tamamlanmasina izin vermek icin kullanilir.
async fn drive_for(running: &[&Running], duration: Duration, nonce_start: u64) {
    let start = Instant::now();
    let mut nonce = nonce_start;
    let mut injected_for = 0u64;
    while start.elapsed() < duration {
        let hs = heights(running);
        let min_h = *hs.iter().min().unwrap();
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
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// G8 ana senaryo: 4 Active + 1 Probation, hepsi gerçek node. Probation
/// gözlemci olarak başlar, her commit'te ShadowVote yayınlar, proposer gömer,
/// her node liveness'a işler, epoch geçişinde Active'e terfi eder ve motoru
/// sonraki commit'te tam validatör kimliğine yükselir.
#[tokio::test]
async fn probation_validator_receives_real_shadow_gossip_and_is_promoted_to_active_at_epoch_boundary(
) {
    let kps = keypairs(4);
    let probation_kp = ConsensusKeypair::from_secret_bytes(&[200u8; 32]);
    let set = active_set(&kps);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    // Tüm node'lar aynı genesis zamanını kullanmalı. Genesis 3*epoch geriye
    // alınır ama BUFFER_SECS tampon bırakılır: canlı ShadowVote gossip'i epoch
    // sınırından önce birkaç tur tamamlansın, yoksa terfi kapısı liveness boşken değerlendirilip kaçırılır.
    const BUFFER_SECS: u128 = 25;
    let genesis_ts =
        now_secs().saturating_sub(3 * test_params().epoch_seconds as u128 - BUFFER_SECS);

    let (a, addr_a, driver_a) = spawn_node(
        Some(&kps[0]),
        &set,
        &probation_kp,
        genesis_ts,
        vec![],
        cancel_rx.clone(),
    )
    .await;
    let (b, _, driver_b) = spawn_node(
        Some(&kps[1]),
        &set,
        &probation_kp,
        genesis_ts,
        vec![addr_a.clone()],
        cancel_rx.clone(),
    )
    .await;
    let (c, _, driver_c) = spawn_node(
        Some(&kps[2]),
        &set,
        &probation_kp,
        genesis_ts,
        vec![addr_a.clone()],
        cancel_rx.clone(),
    )
    .await;
    let (d, _, driver_d) = spawn_node(
        Some(&kps[3]),
        &set,
        &probation_kp,
        genesis_ts,
        vec![addr_a.clone()],
        cancel_rx.clone(),
    )
    .await;
    // Probation node: motoru GÖZLEMCİ olarak kurulur (kümede değil), ama
    // `probation_kp` ile bootstrap edilir, driver kendi hesabını
    // `refresh_probation_view` ile bulup canlı ShadowVote yayınlayacak.
    let (p, _, driver_p) = spawn_node(
        Some(&probation_kp),
        &set,
        &probation_kp,
        genesis_ts,
        vec![addr_a.clone()],
        cancel_rx.clone(),
    )
    .await;

    assert_eq!(driver_a.engine().my_idx(), Some(0));
    assert_eq!(
        driver_p.engine().my_idx(),
        None,
        "Probation validator motora GOZLEMCI olarak baslar"
    );
    assert_eq!(
        driver_p.probation_identity(),
        Some(&probation_address()),
        "driver KENDI Probation kimligini bootstrap'te coz"
    );

    let handle_p = p.handle.clone();
    tokio::spawn(driver_a.run(a.handle.clone(), cancel_rx.clone()));
    tokio::spawn(driver_b.run(b.handle.clone(), cancel_rx.clone()));
    tokio::spawn(driver_c.run(c.handle.clone(), cancel_rx.clone()));
    tokio::spawn(driver_d.run(d.handle.clone(), cancel_rx.clone()));
    tokio::spawn(driver_p.run(handle_p, cancel_rx.clone()));

    tokio::time::sleep(Duration::from_millis(1500)).await; // mesh kurulsun

    // BUFFER_SECS (25s) boyunca bloklari canli tutup ShadowVote gossip'inin
    // (en az bir kac turu) gerceklesmesine izin ver, epoch HALA
    // probation_epochs'in ALTINDA kalir bu sure boyunca (bkz. genesis_ts).
    // 10s marj ile toplam 35s: sinir kesinlikle bu pencere icinde gecilir.
    let running: Vec<&Running> = vec![&a, &b, &c, &d];
    drive_for(&running, Duration::from_secs(35), 0).await;

    // Terfi kararının canlı ShadowVote'tan geldiğini kanıtlamak için yoklama
    // boyunca görülen EN YÜKSEK `participated` biriktirilir; tek anı yakalamak
    // CPU yükünde kaçırılıyor, sonraki epoch sıfırlaması (G7, doğru davranış) kanıtı siliyordu.
    let mut promoted = false;
    let mut acc_at_promotion = None;
    let mut max_participated_seen: u64 = 0;
    for _ in 0..1_600 {
        let acc = a
            .node
            .state
            .get_account(&probation_address())
            .unwrap()
            .unwrap();
        max_participated_seen = max_participated_seen.max(acc.liveness.participated);
        if acc.validator_status == Some(ValidatorStatus::Active) {
            promoted = true;
            acc_at_promotion = Some(acc);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        promoted,
        "Probation validator epoch sinirinda Active'e terfi ETMELI"
    );
    let acc_at_promotion = acc_at_promotion.unwrap();

    // 🚨 Kararsızlığa karşı geçici sayaç yerine KALICI kanıt: zincire yazılmış
    // konsensüs kayıtlarındaki gerçek ShadowVote attestation'ları.
    let probation_addr = probation_address();
    let tip_height = a
        .node
        .state
        .get_account(&probation_addr)
        .unwrap()
        .map(|_| ())
        .and(Some(()))
        .map(|_| ())
        .map_or(0u64, |_| 0);
    let _ = tip_height;
    let mut shadow_votes_on_chain = 0usize;
    let mut scanned = 0u64;
    for height in 1..=600u64 {
        match zagros_network::sync2::load_consensus_record(a.node.state.as_ref(), height) {
            Ok(Some((_signed, _qc, shadow_votes))) => {
                scanned += 1;
                shadow_votes_on_chain += shadow_votes
                    .iter()
                    .filter(|sv| sv.address.eq_ignore_ascii_case(&probation_addr))
                    .count();
            }
            _ => break,
        }
    }
    assert!(
        shadow_votes_on_chain > 0,
        "terfi kararini besleyen liveness GERCEK canli ShadowVote'tan gelmeli: \
         {scanned} blok tarandi, probation validatorun ({probation_addr}) zincire \
         yazilmis TEK bir ShadowVote attestation'i yok (terfi anindaki liveness={:?}, \
         yoklama boyunca gorulen en yuksek participated={})",
        acc_at_promotion.liveness,
        max_participated_seen
    );

    // 🛡️ Node'lar epoch sınırını aynı anda işlemez; aynı karara varmaları beklenir
    // ama gözlem için BEKLEMEK gerekir (konsensüs sorunu değil, zamanlama).
    for r in [&a, &b, &c, &d] {
        let mut agreed = false;
        let mut last = None;
        for _ in 0..400 {
            let acc = r
                .node
                .state
                .get_account(&probation_address())
                .unwrap()
                .unwrap();
            last = acc.validator_status;
            if last == Some(ValidatorStatus::Active) {
                agreed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            agreed,
            "TUM node'lar AYNI terfi kararina varmali (bu node hala {last:?})"
        );
    }

    // Yeni kümenin `__ACTIVE_VALIDATOR_SET__`'e girdiğini doğrula (liveness'in
    // GERÇEK ShadowVote'tan geldiği zaten terfi ANINDA, yukarıda kanıtlandı).
    let final_set = validator_set::load_active_set(a.node.state.as_ref()).unwrap();
    assert!(
        final_set
            .members
            .iter()
            .any(|m| m.address.eq_ignore_ascii_case(&probation_address())),
        "terfi eden validator YENİ ActiveValidatorSet'te olmali"
    );

    // Kökler karşılaştırılmadan önce tüm node'lar aynı yüksekliğe beklenir;
    // farklı yükseklik yanlış pozitif "sapma" verir (saf zamanlama).
    let all: Vec<&Running> = vec![&a, &b, &c, &d, &p];
    let mut converged = false;
    for _ in 0..75 {
        let hs = heights(&all);
        if hs.iter().all(|h| *h == hs[0]) {
            converged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        converged,
        "node'lar ayni yukseklikte bulusamadi - kok karsilastirmasi yanlis-pozitif olurdu"
    );
    // Kökleri OKUMADAN önce tüm node'ları durdur, aksi halde yukarida
    // "yakalanan" eşitlik anı ile asagidaki 5 ayrı `state_root()` okuması
    // arasında (hâlâ canlı çalışan node'lar nedeniyle) yeni bir blok daha
    // committed olup AYNI yarışı tekrar yaratabilir.
    let _ = cancel_tx.send(true);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // State kökleri hâlâ tüm node'larda eşit (deterministik ShadowVote
    // gömme/doğrulama + epoch geçişi TÜM node'larda AYNI sonucu verdi).
    let roots: Vec<_> = [&a, &b, &c, &d]
        .iter()
        .map(|r| r.node.state.state_root().unwrap())
        .collect();
    assert!(
        roots.iter().all(|r| *r == roots[0]),
        "epoch gecisi + shadow-vote sonrasi state kokleri SAPMAMALI"
    );
    assert_eq!(
        p.node.state.state_root().unwrap(),
        roots[0],
        "Probation (gozlemci) node'un koku da AYNI olmali"
    );
}
