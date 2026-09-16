//! Ana P2P olay döngüsü: tx gossip, blok gossip/follower uygulama ve
//! request-response senkronizasyonu; CLI'nin JoinSet + `watch` iptal deseniyle spawn edilir.

use libp2p::futures::StreamExt;
use libp2p::request_response;
use libp2p::swarm::SwarmEvent;
use libp2p::{mdns, PeerId, Swarm};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use zagros_mempool::{AdmissionError, Mempool};
use zagros_runtime::Runtime;
use zagros_state::State;
use zagros_types::{ArchivedBlockHeader, Transaction};

use crate::behaviour::{ZagrosBehaviour, ZagrosBehaviourEvent};
use crate::consensus_driver::{ConsensusWiring, DriverInput};
use crate::consensus_wire::{
    InboundGate, PeerLedger, Verdict, WireEnvelope, DEFAULT_BAN_THRESHOLD,
};
use crate::messages::{
    block_topic, consensus_topic, peers_topic, tx_topic, GossipMessage, PeerAnnouncement,
    SyncResponse,
};
use crate::messages::{Sync2Request, Sync2Response};
use crate::sync::{self, PendingSync};
use crate::sync2;
use libp2p::gossipsub::MessageAcceptance;
use zagros_consensus::engine::Message as ConsensusMessage;
use zagros_types::consensus::ConsensusDomain;

/// 🛡️ P2P koruma politikası, `NetworkConfig`'in
/// ağ-katmanı alanlarının servis döngüsüne taşınan, çözümlenmiş hali.
/// Konsensüs-dışı: hiçbir alanı state geçişini etkilemez.
pub struct PeerPolicy {
    /// `private_peers` PeerId'leri. Doluysa düğüm "kapalı" (validatör) moddadır.
    pub private_peers: Vec<PeerId>,
    pub sentry_mode: bool,
    pub max_peers: usize,
    pub max_peers_per_ip: u32,
    /// Duyurulmuş validatör sentry'leri için ayrılmış slot (kapalı modda 0).
    pub reserved_slots: u32,
    /// Bu düğüm bir validatörse ve sentry'lerini duyuracaksa.
    pub announce: Option<AnnounceConfig>,
}

impl PeerPolicy {
    pub fn open(max_peers: usize) -> Self {
        PeerPolicy {
            private_peers: Vec::new(),
            sentry_mode: false,
            max_peers,
            max_peers_per_ip: 4,
            reserved_slots: 32,
            announce: None,
        }
    }
    fn is_private(&self) -> bool {
        !self.private_peers.is_empty()
    }
}

/// Validatörün sentry duyurusu için gerekenler (konsensüs anahtarı + adres).
pub struct AnnounceConfig {
    pub keypair: Arc<zagros_crypto::ConsensusKeypair>,
    /// Validatörün hesap adresi (zincirde `consensus_pubkey`'i bu anahtar olan hesap).
    pub validator: String,
    pub sentry_addrs: Vec<String>,
    pub domain: ConsensusDomain,
}

/// Duyuru yayın aralığı (yeniden imzalama). TTL'in (3 sa) çok altında.
const ANNOUNCE_INTERVAL_SECS: u64 = 10 * 60;
/// Duyurunun gelecekten gelmesine izin verilen pay (saat kayması).
const ANNOUNCE_FUTURE_SKEW_SECS: u64 = 300;

/// Servis döngüsüne dışarıdan (RPC handler'ı / blok-üretici görevi gibi)
/// komut göndermek için.
pub enum ServiceCommand {
    /// Yerel kabul edilen işlemi gossip'le; gossip'ten gelenler yeniden yayınlanmaz (mesh iletir).
    PublishTransaction(Transaction),
    /// Bu node PROPOSER ise, az önce ürettiği bloğu ağa gossiple. Follower
    /// node'lar bunu asla göndermemeli (`is_proposer` kapısı main.rs'te).
    PublishBlock {
        header: ArchivedBlockHeader,
        transactions: Vec<Transaction>,
        /// 🛡️ Follower senkronu için zorunlu; `transactions` ile aynı state görünümünden toplanmalı.
        bridge_proposals: Vec<zagros_executor::bridge::BridgeProposal>,
    },
    /// G5: BFT sürücüsünün yayınlayacağı konsensüs mesajı (zarf hazır).
    PublishConsensus(Vec<u8>),
    /// G6: sürücünün `/zagros/sync/2` isteği. `peer: None` → bağlı, yasaklı
    /// olmayan ve `exclude`'da olmayan herhangi bir peer.
    Sync2Request {
        peer: Option<PeerId>,
        exclude: Vec<PeerId>,
        request: Sync2Request,
    },
    /// G6: sürücü bir peer'ı kötü ilan etti (geçersiz blok/QC, NotAvailable).
    PenalizePeer(PeerId),
}

/// `ServiceCommand` göndermek için ucuz, klonlanabilir bir tutamaç.
#[derive(Clone)]
pub struct NetworkHandle {
    command_tx: mpsc::UnboundedSender<ServiceCommand>,
}

impl NetworkHandle {
    /// Kanal kapalıysa (servis görevi durmuşsa) sessizce yok sayar, bir tx'in
    /// gossiplenememesi RPC'nin kendi kabul yanıtını asla ETKİLEMEMELİ,
    /// mempool kabulü zaten tamamlanmış olur.
    pub fn publish_transaction(&self, tx: Transaction) {
        let _ = self.command_tx.send(ServiceCommand::PublishTransaction(tx));
    }

    /// Kanal kapalıysa yok sayar; blok yerelde kalıcı, follower'lar senkronla yakalar.
    pub fn publish_block(
        &self,
        header: ArchivedBlockHeader,
        transactions: Vec<Transaction>,
        bridge_proposals: Vec<zagros_executor::bridge::BridgeProposal>,
    ) {
        let _ = self.command_tx.send(ServiceCommand::PublishBlock {
            header,
            transactions,
            bridge_proposals,
        });
    }
}

impl NetworkHandle {
    /// G5: konsensüs mesajını zarflayıp yayınlar. Kanal kapalıysa sessizce
    /// yok sayar (motor kendi kopyasını zaten işledi).
    pub fn publish_consensus(&self, domain: &ConsensusDomain, epoch: u64, msg: ConsensusMessage) {
        match WireEnvelope::new(domain, epoch, msg).encode() {
            Ok(bytes) => {
                let _ = self
                    .command_tx
                    .send(ServiceCommand::PublishConsensus(bytes));
            }
            Err(e) => tracing::warn!("⚠️ konsensus zarfi serilestirilemedi: {e:?}"),
        }
    }
    pub fn sync2_request(&self, peer: Option<PeerId>, exclude: Vec<PeerId>, request: Sync2Request) {
        let _ = self.command_tx.send(ServiceCommand::Sync2Request {
            peer,
            exclude,
            request,
        });
    }
    pub fn penalize_peer(&self, peer: PeerId) {
        let _ = self.command_tx.send(ServiceCommand::PenalizePeer(peer));
    }
}

pub fn channel() -> (NetworkHandle, mpsc::UnboundedReceiver<ServiceCommand>) {
    let (command_tx, command_rx) = mpsc::unbounded_channel();
    (NetworkHandle { command_tx }, command_rx)
}

/// Olay döngüsü boyunca yaşayan, iterasyonlar arası değişken durum, ayrı
/// parametreler yerine tek bir `&mut` alan grubu (bağlı peer listesi +
/// bekleyen TEK senkronizasyon isteği).
struct LoopState {
    connected_peers: HashSet<PeerId>,
    /// G11 (§9 Redial): bilinen adres defteri + backoff — kopan/kurulamayan
    /// bağlantılar döngüdeki 2 sn'lik zamanlayıcıyla İNATLA yeniden aranır.
    peer_book: crate::peer_book::PeerBook,
    pending_sync: Option<PendingSync>,
    /// G5: konsensüs giriş kapısı + sürücü kanalı (BFT modu kapalıysa None:
    /// konsensüs topic'indeki her mesaj Ignore ile düşürülür).
    consensus: Option<ConsensusIo>,
    peer_ledger: PeerLedger,
    /// 🛡️ tx/blok gossip'i için decode öncesi boyut tavanı (konsensüs topic'i
    /// bunu `InboundGate` ile zaten uygular). Taşıma tavanı 16 MiB olduğundan
    /// kontrolsüz deserialize her sahte mesajda tam maliyet ödettirirdi.
    max_gossip_bytes: usize,
    /// 🛡️ Tx/blok konularında eş başına saniyelik sayaç; konsensüs kapalıyken de işler.
    inbound_gossip_rate: std::collections::HashMap<PeerId, (u64, u32)>,
    /// 🛡️ D14 (denetim B5/7): eş-duyuru (`/peers/1`) konusu ve eski
    /// senkron (`/sync/1`) istekleri için AYRI, düşük tavanlı sayaç.
    inbound_peers_rate: std::collections::HashMap<PeerId, (u64, u32)>,
    /// G14: /metrics // /health için peers_connected sayacı (None = kablosuz).
    metrics: Option<Arc<zagros_metrics::NodeMetrics>>,
    /// 🛡️ Sentry mimarisi.
    policy: PeerPolicy,
    /// Bağlantı → uzak IP (kapanışta sayacı düşürmek için).
    conn_ip: std::collections::HashMap<libp2p::swarm::ConnectionId, std::net::IpAddr>,
    /// IP başına açık bağlantı sayısı (kota).
    ip_counts: std::collections::HashMap<std::net::IpAddr, u32>,
    /// Doğrulanmış sentry duyuruları: validatör adresi → duyuru.
    announcements: std::collections::HashMap<String, PeerAnnouncement>,
    /// Duyurulardan öğrenilen sentry PeerId'leri (ayrılmış kota + IP kotasından muaf).
    announced_peers: HashSet<PeerId>,
}

impl LoopState {
    fn publish_peer_count(&self) {
        let n = self.connected_peers.len() as u64;
        if let Some(m) = &self.metrics {
            m.peers_connected
                .store(n, std::sync::atomic::Ordering::Relaxed);
        }
        // 🛡️ Bkz. `zagros_metrics::GLOBAL_PEERS_CONNECTED` doc yorumu.
        zagros_metrics::GLOBAL_PEERS_CONNECTED.store(n, std::sync::atomic::Ordering::Relaxed);
        self.publish_network_snapshot();
    }

    /// RPC `zagros_getNetworkPeers` için JSON anlık görüntü (zagros_metrics
    /// üzerinden; RPC bu crate'e bağımlı değil). Yalnız görünürlük.
    fn publish_network_snapshot(&self) {
        let mut ann: Vec<serde_json::Value> = self
            .announcements
            .values()
            .map(|a| {
                serde_json::json!({
                    "validator": a.validator,
                    "sentries": a.sentries,
                    "epoch": a.epoch,
                    "issued_at": a.issued_at,
                })
            })
            .collect();
        ann.sort_by(|a, b| a["validator"].as_str().cmp(&b["validator"].as_str()));
        let snap = serde_json::json!({
            "peers_connected": self.connected_peers.len(),
            "peers": self.connected_peers.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            "mode": if self.policy.is_private() { "private" } else if self.policy.sentry_mode { "sentry" } else { "open" },
            "private_peers": self.policy.private_peers.len(),
            "max_peers": self.policy.max_peers,
            "reserved_validator_slots": self.policy.reserved_slots,
            "max_peers_per_ip": self.policy.max_peers_per_ip,
            "announced_sentries": self.announced_peers.len(),
            "announcements": ann,
            "announcing": self.policy.announce.as_ref().map(|a| serde_json::json!({"validator": a.validator, "sentries": a.sentry_addrs})),
        });
        zagros_metrics::set_network_snapshot(snap.to_string());
    }

    fn is_privileged(&self, peer: &PeerId) -> bool {
        self.policy.private_peers.contains(peer) || self.announced_peers.contains(peer)
    }
}

/// Bağlantı kabul mü (saf): ayrıcalıklı peer'lar IP kotası ve tavandan muaf,
/// diğerleri ikisine de tabi.
fn admit_connection(
    privileged: bool,
    ip_count_after: u32,
    max_per_ip: u32,
    open_count_after: usize,
    max_open: usize,
) -> Result<(), &'static str> {
    if privileged {
        return Ok(());
    }
    if ip_count_after > max_per_ip {
        return Err("ip kotasi asildi");
    }
    if open_count_after > max_open {
        return Err("acik slotlar dolu (ayrilmis slot yalniz duyurulmus sentry'lere)");
    }
    Ok(())
}

fn remote_ip(addr: &libp2p::Multiaddr) -> Option<std::net::IpAddr> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => Some(std::net::IpAddr::V4(ip)),
        libp2p::multiaddr::Protocol::Ip6(ip) => Some(std::net::IpAddr::V6(ip)),
        _ => None,
    })
}

/// Duyuru doğrulama (saf): yapı + zaman penceresi + imza. `pubkey_of`
/// zincirden validatörün `consensus_pubkey`'ini verir (kayıtlı değilse None).
fn verify_announcement(
    a: &PeerAnnouncement,
    domain: &ConsensusDomain,
    now_secs: u64,
    pubkey_of: impl Fn(&str) -> Option<[u8; 32]>,
) -> Result<(), String> {
    a.validate_shape()?;
    if a.issued_at > now_secs + ANNOUNCE_FUTURE_SKEW_SECS {
        return Err("duyuru gelecek tarihli".into());
    }
    if now_secs.saturating_sub(a.issued_at) > PeerAnnouncement::TTL_SECS {
        return Err("duyuru suresi dolmus".into());
    }
    let pk = pubkey_of(&a.validator).ok_or("validator zincirde kayitli degil / anahtarsiz")?;
    zagros_crypto::verify_digest(&pk, &a.signing_digest(domain), &a.sig)
        .map_err(|e| format!("imza gecersiz: {e:?}"))
}

fn now_secs() -> u64 {
    wall_ms() / 1000
}

struct ConsensusIo {
    gate: InboundGate,
    inbound_tx: mpsc::UnboundedSender<DriverInput>,
    /// Sürücünün bekleyen TEK sync/2 aralık isteği (peer, request_id).
    pending_sync2: Option<(PeerId, request_response::OutboundRequestId)>,
    /// Peer başına gelen sync/2 istek sayacı (flood sınırı): (pencere başı ms, sayı).
    inbound_sync2_rate: std::collections::HashMap<PeerId, (u64, u32)>,
    /// Peer başına gelen konsensüs gossip mesajı sayacı: (pencere başı ms, sayı).
    inbound_consensus_rate: std::collections::HashMap<PeerId, (u64, u32)>,
}

/// Duvar saati (ms), YALNIZ redial backoff zamanlaması için (konsensüs-dışı).
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Peer başına saniyede kabul edilen azami sync/2 isteği.
const SYNC2_INBOUND_PER_SEC: u32 = 10;
/// D14: eş-duyuru konusunda eş başına saniyelik mesaj tavanı.
const PEERS_INBOUND_PER_SEC: u32 = 5;

/// Peer başına saniyede azami konsensüs mesajı; tekrar mesajlar `Ignore` dönüp
/// sayaç artırmadığından sel kapanmalı. Meşru üst sınır ≈ 1616, cömert.
const CONSENSUS_INBOUND_PER_SEC: u32 = 2_048;

/// 🛡️ Tx/blok konularında tek komşudan saniyede azami mesaj; meşru üst sınır
/// `max_block_bytes` ile düşük binler/sn, tx seli mertebelerce yüksek.
/// Aşım → `Reject` → 8 hatada ban.
const GOSSIP_INBOUND_PER_SEC: u32 = 4_096;

/// Sync/2 hız sayacında aynı anda izlenecek azami peer sayısı, bkz. kullanım
/// yerindeki gerekçe (sınırsız `PeerId`-anahtarlı harita = uzaktan tetiklenen
/// bellek büyümesi).
const MAX_TRACKED_SYNC_PEERS: usize = 4_096;

/// Ana servis döngüsü (`JoinSet`te); iptal sinyalinde zarifçe döner, panic atmaz.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    mut swarm: Swarm<ZagrosBehaviour>,
    network_id: u64,
    bootstrap: Vec<libp2p::Multiaddr>,
    mempool: Arc<Mempool>,
    runtime: Arc<Runtime>,
    state: Arc<dyn State>,
    sync_batch_size: u64,
    mut command_rx: mpsc::UnboundedReceiver<ServiceCommand>,
    mut cancel_rx: watch::Receiver<bool>,
    consensus: Option<ConsensusWiring>,
    metrics: Option<Arc<zagros_metrics::NodeMetrics>>,
    policy: PeerPolicy,
) {
    let tx_topic_ = tx_topic(network_id);
    let block_topic_ = block_topic(network_id);
    let consensus_topic_ = consensus_topic(network_id);
    let peers_topic_ = peers_topic(network_id);
    // Konsensüs sarmalayıcısı `map` içinde TÜKETİLDİĞİ için tavanı ÖNCE al.
    // BFT kapalıysa (konsensüs yok) genesis varsayılanına düşülür, o da
    // zincirin `max_block_bytes`'ıyla aynı türetmeyi kullanır.
    let consensus_max_wire_bytes =
        consensus
            .as_ref()
            .map(|w| w.max_wire_bytes)
            .unwrap_or_else(|| {
                crate::consensus_wire::max_wire_bytes(
                    &zagros_types::consensus::ChainParams::genesis_defaults(),
                )
            });
    let mut loop_state = LoopState {
        connected_peers: HashSet::new(),
        peer_book: crate::peer_book::PeerBook::new(bootstrap),
        pending_sync: None,
        consensus: consensus.map(|w| ConsensusIo {
            gate: InboundGate::new(w.gate_view, w.max_wire_bytes),
            inbound_tx: w.inbound_tx,
            pending_sync2: None,
            inbound_sync2_rate: std::collections::HashMap::new(),
            inbound_consensus_rate: std::collections::HashMap::new(),
        }),
        peer_ledger: PeerLedger::new(DEFAULT_BAN_THRESHOLD),
        max_gossip_bytes: consensus_max_wire_bytes,
        inbound_gossip_rate: std::collections::HashMap::new(),
        inbound_peers_rate: std::collections::HashMap::new(),
        metrics,
        policy,
        conn_ip: std::collections::HashMap::new(),
        ip_counts: std::collections::HashMap::new(),
        announcements: std::collections::HashMap::new(),
        announced_peers: HashSet::new(),
    };
    if loop_state.policy.is_private() {
        tracing::info!(
            "🛡️ P2P kapalı mod: yalnız {} özel eşle konuşulur, dinleme adresi ilan edilmez, duyurulan sentry'ler aranmaz.",
            loop_state.policy.private_peers.len()
        );
    } else {
        tracing::info!(
            "🌐 P2P açık mod{}: IP başına ≤{} bağlantı, açık {} + ayrılmış {} slot.",
            if loop_state.policy.sentry_mode {
                " (sentry)"
            } else {
                ""
            },
            loop_state.policy.max_peers_per_ip,
            loop_state.policy.max_peers,
            loop_state.policy.reserved_slots
        );
    }
    loop_state.publish_network_snapshot();

    let mut redial_tick = tokio::time::interval(std::time::Duration::from_secs(2));
    redial_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Sentry duyurusu: ilk tick 15 sn sonra (peer'lar bağlansın), sonra her 10 dk.
    let mut announce_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(ANNOUNCE_INTERVAL_SECS),
    );
    announce_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = announce_tick.tick() => {
                publish_announcement(&mut swarm, &peers_topic_, &state, &loop_state);
                // Süresi dolmuş duyuruları düşür (TTL); sentry'leri kota listesinden çıkar.
                let now = now_secs();
                let expired: Vec<String> = loop_state.announcements.iter()
                    .filter(|(_, a)| now.saturating_sub(a.issued_at) > PeerAnnouncement::TTL_SECS)
                    .map(|(k, _)| k.clone()).collect();
                if !expired.is_empty() {
                    for k in &expired { loop_state.announcements.remove(k); }
                    loop_state.announced_peers = loop_state.announcements.values()
                        .flat_map(|a| crate::behaviour::peer_ids_of(&a.sentries)).collect();
                    loop_state.publish_network_snapshot();
                }
            }
            _ = redial_tick.tick() => {
                // G11: sırası gelen KOPUK adresleri yeniden ara (banlılar hariç).
                // 🛡️ Zaten bağlı peer'a yeniden dial gereksiz TCP + "Failed to
                // negotiate" log gürültüsü üretiyordu; bağlıysa hiç arama.
                let LoopState { peer_book, peer_ledger, connected_peers, .. } = &mut loop_state;
                for addr in peer_book.due(wall_ms(), |p| peer_ledger.is_banned(p)) {
                    let already_connected = addr.iter().any(|p| match p {
                        libp2p::multiaddr::Protocol::P2p(id) => connected_peers.contains(&id),
                        _ => false,
                    });
                    if already_connected {
                        tracing::debug!("🔁 yeniden-arama atlandı (zaten bağlı): {addr}");
                        continue;
                    }
                    tracing::info!("🔁 Peer yeniden aranıyor: {addr}");
                    if let Err(e) = swarm.dial(addr) {
                        tracing::debug!("yeniden arama başlatılamadı: {e}");
                    }
                }
            }
            event = swarm.select_next_some() => {
                handle_swarm_event(&mut swarm, event, &mempool, &runtime, &state, sync_batch_size, &mut loop_state);
            }
            Some(cmd) = command_rx.recv() => {
                handle_command(&mut swarm, &tx_topic_, &block_topic_, &consensus_topic_, cmd, &mut loop_state);
            }
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    tracing::info!("🌐 P2P görevi zarifçe durduruluyor.");
                    break;
                }
            }
        }
    }
}

fn handle_command(
    swarm: &mut Swarm<ZagrosBehaviour>,
    tx_topic: &libp2p::gossipsub::IdentTopic,
    block_topic: &libp2p::gossipsub::IdentTopic,
    consensus_topic: &libp2p::gossipsub::IdentTopic,
    cmd: ServiceCommand,
    loop_state: &mut LoopState,
) {
    match cmd {
        ServiceCommand::PublishConsensus(bytes) => {
            if let Err(e) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(consensus_topic.clone(), bytes)
            {
                tracing::debug!("konsensus mesaji yayinlanamadi (muhtemelen henuz peer yok): {e}");
            }
            return;
        }
        ServiceCommand::Sync2Request {
            peer,
            exclude,
            request,
        } => {
            let chosen = peer
                .filter(|p| {
                    loop_state.connected_peers.contains(p) && !loop_state.peer_ledger.is_banned(p)
                })
                .or_else(|| {
                    loop_state
                        .connected_peers
                        .iter()
                        .find(|p| !loop_state.peer_ledger.is_banned(p) && !exclude.contains(p))
                        .copied()
                });
            let Some(io) = loop_state.consensus.as_mut() else {
                return;
            };
            match chosen {
                Some(p) => {
                    let id = swarm.behaviour_mut().sync2.send_request(&p, request);
                    io.pending_sync2 = Some((p, id));
                }
                None => {
                    let _ = io.inbound_tx.send(DriverInput::SyncNoPeer);
                }
            }
            return;
        }
        ServiceCommand::PenalizePeer(p) => {
            if loop_state.peer_ledger.record_reject(p) {
                tracing::warn!("⛔ Peer yasaklandi (sync/2 kotu davranis): {p}");
                swarm.behaviour_mut().gossipsub.blacklist_peer(&p);
                let _ = swarm.disconnect_peer_id(p);
            }
            return;
        }
        _ => {}
    }
    let (topic, msg) = match cmd {
        ServiceCommand::PublishConsensus(_)
        | ServiceCommand::Sync2Request { .. }
        | ServiceCommand::PenalizePeer(_) => unreachable!("yukarida ele alindi"),
        ServiceCommand::PublishTransaction(tx) => (tx_topic, GossipMessage::NewTransaction(tx)),
        ServiceCommand::PublishBlock {
            header,
            transactions,
            bridge_proposals,
        } => (
            block_topic,
            GossipMessage::NewBlock {
                header,
                transactions,
                bridge_proposals,
            },
        ),
    };
    match bincode::serialize(&msg) {
        Ok(bytes) => {
            // `InsufficientPeers` (henüz hiç peer/mesh yok) BEKLENEN bir
            // durumdur (ör. tek node modunda), hata olarak loglanmaz.
            if let Err(e) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), bytes)
            {
                tracing::debug!("gossip yayınlanamadı (muhtemelen henüz peer yok): {e}");
            }
        }
        Err(e) => tracing::warn!("⚠️ gossip mesajı serileştirilemedi: {e}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_swarm_event(
    swarm: &mut Swarm<ZagrosBehaviour>,
    event: SwarmEvent<ZagrosBehaviourEvent>,
    mempool: &Arc<Mempool>,
    runtime: &Arc<Runtime>,
    state: &Arc<dyn State>,
    sync_batch_size: u64,
    loop_state: &mut LoopState,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            let peer_id = *swarm.local_peer_id();
            tracing::info!("🌐 P2P dinleniyor: {address}/p2p/{peer_id}");
        }
        SwarmEvent::ConnectionEstablished {
            peer_id,
            endpoint,
            connection_id,
            ..
        } => {
            // 🛡️ Kabul kapısı: IP kotası + ayrılmış slot. libp2p'nin
            // connection_limits'i toplam tavanı transport'ta uygular; burada
            // "kim" olduğuna göre ince kural işler (özel/duyurulmuş peer muaf).
            let ip = remote_ip(endpoint.get_remote_address());
            let privileged = loop_state.is_privileged(&peer_id);
            let ip_after = ip
                .map(|i| loop_state.ip_counts.get(&i).copied().unwrap_or(0) + 1)
                .unwrap_or(0);
            let open_after = loop_state
                .connected_peers
                .iter()
                .filter(|p| !loop_state.is_privileged(p))
                .count()
                + usize::from(!privileged && !loop_state.connected_peers.contains(&peer_id));
            if let Err(why) = admit_connection(
                privileged,
                ip_after,
                loop_state.policy.max_peers_per_ip,
                open_after,
                loop_state.policy.max_peers,
            ) {
                tracing::warn!("🚫 Bağlantı düşürüldü ({peer_id} @ {:?}): {why}", ip);
                let _ = swarm.close_connection(connection_id);
                return;
            }
            if let Some(i) = ip {
                *loop_state.ip_counts.entry(i).or_insert(0) += 1;
                loop_state.conn_ip.insert(connection_id, i);
            }
            tracing::info!(
                "🤝 Peer bağlandı: {peer_id}{}",
                if privileged {
                    " (özel/duyurulmuş)"
                } else {
                    ""
                }
            );
            loop_state
                .peer_book
                .connected(peer_id, endpoint.get_remote_address());
            // Küçük bilinen kümede garantili gossip: bağlanan her peer mesh'e katılır.
            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
            loop_state.connected_peers.insert(peer_id);
            loop_state.publish_peer_count();
            // G6: BFT modunda her yeni bağlantıda peer'ın QC'li tip'i sorulur
            // (restart/geride kalma tetiği, spec §9).
            if loop_state.consensus.is_some() && !loop_state.peer_ledger.is_banned(&peer_id) {
                swarm
                    .behaviour_mut()
                    .sync2
                    .send_request(&peer_id, Sync2Request::GetStatus);
            }

            // 🔄 Her yeni bağlantıda (yeniden bağlanma dahil) proaktif senkron:
            // yalnız gossip boşluğuyla tetiklenseydi çevrimdışıyken üretilen
            // bloklar sonraki gossip'e dek yakalanamazdı. Peer geride/eşitse
            // boş yanıt (zararsız). G6: BFT modunda QC'siz `/sync/1` istemcisi
            // kullanılmaz (catch-up yalnız `/sync/2`); sunucu tarafı değişmedi.
            if loop_state.pending_sync.is_none() && loop_state.consensus.is_none() {
                let current = runtime.current_block_height().unwrap_or(0) as u64;
                let target = current.saturating_add(sync_batch_size);
                let request = sync::request_missing_range(current, target);
                let request_id = swarm.behaviour_mut().sync.send_request(&peer_id, request);
                tracing::debug!(
                    "🔄 Yeni bağlantı ({peer_id}) - proaktif senkronizasyon denemesi: #{}..#{}",
                    current + 1,
                    target
                );
                loop_state.pending_sync = Some(PendingSync {
                    peer: peer_id,
                    request_id,
                    target,
                });
            }
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            ..
        } => {
            if let Some(ip) = loop_state.conn_ip.remove(&connection_id) {
                if let Some(c) = loop_state.ip_counts.get_mut(&ip) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        loop_state.ip_counts.remove(&ip);
                    }
                }
            }
            tracing::info!("👋 Peer ayrıldı: {peer_id}");
            loop_state.peer_book.disconnected(&peer_id, wall_ms());
            swarm
                .behaviour_mut()
                .gossipsub
                .remove_explicit_peer(&peer_id);
            loop_state.connected_peers.remove(&peer_id);
            loop_state.publish_peer_count();
            if let Some(io) = loop_state.consensus.as_mut() {
                if io.pending_sync2.map(|(p, _)| p) == Some(peer_id) {
                    io.pending_sync2 = None;
                }
                // 🛡️ Hız sayacı peer ile gider; asıl temizlik yeri burası.
                io.inbound_sync2_rate.remove(&peer_id);
                let _ = io.inbound_tx.send(DriverInput::PeerGone { peer: peer_id });
            }
        }
        // 🛡️ `max_peers` transport seviyesinde uygulanır; burada yalnız loglanır.
        SwarmEvent::IncomingConnectionError {
            error,
            send_back_addr,
            ..
        } => {
            tracing::warn!("⚠️ Gelen bağlantı reddedildi ({send_back_addr}): {error}");
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            tracing::debug!("giden bağlantı denemesi başarısız (peer={peer_id:?}): {error}");
            loop_state
                .peer_book
                .dial_failed(peer_id.as_ref(), wall_ms());
        }
        SwarmEvent::Behaviour(ZagrosBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
            for (peer_id, addr) in peers {
                tracing::debug!("🔎 mDNS ile peer bulundu: {peer_id} @ {addr}");
                if let Err(e) = swarm.dial(addr) {
                    tracing::debug!("mDNS peer'ı aranamadı: {e}");
                }
            }
        }
        SwarmEvent::Behaviour(ZagrosBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
            for (peer_id, _addr) in peers {
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .remove_explicit_peer(&peer_id);
            }
        }
        SwarmEvent::Behaviour(ZagrosBehaviourEvent::Gossipsub(
            libp2p::gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            },
        )) => {
            // G5: `validate_messages` açık, her mesaj için karar bildirilir.
            let acceptance = if message.topic
                == consensus_topic(network_id_of(&message.topic)).hash()
            {
                handle_consensus_gossip(&message.data, propagation_source, loop_state)
            } else if message.topic == peers_topic(network_id_of(&message.topic)).hash() {
                // 🛡️ D14 (denetim B5/7): bu konuda hız sınırı ve ban kontrolü
                // şart; yoksa her mesaj disk okuması + imza doğrulaması tetikler.
                if loop_state.peer_ledger.is_banned(&propagation_source) {
                    MessageAcceptance::Ignore
                } else {
                    let now = crate::consensus_driver::now_ms();
                    if loop_state.inbound_peers_rate.len() > MAX_TRACKED_SYNC_PEERS {
                        loop_state
                            .inbound_peers_rate
                            .retain(|_, (ws, _)| now.saturating_sub(*ws) < 1_000);
                        if loop_state.inbound_peers_rate.len() > MAX_TRACKED_SYNC_PEERS {
                            loop_state.inbound_peers_rate.clear();
                        }
                    }
                    if bump_and_check_rate(
                        &mut loop_state.inbound_peers_rate,
                        propagation_source,
                        now,
                        PEERS_INBOUND_PER_SEC,
                    ) {
                        tracing::warn!("⛔ eş-duyuru seli ({propagation_source}): saniyede sinir {PEERS_INBOUND_PER_SEC} asildi");
                        MessageAcceptance::Reject
                    } else {
                        handle_peer_announcement(&message.data, swarm, state, loop_state)
                    }
                }
            } else {
                handle_gossip_message(
                    &message.data,
                    propagation_source,
                    swarm,
                    mempool,
                    runtime,
                    loop_state,
                )
            };
            if let MessageAcceptance::Reject = acceptance {
                if loop_state.peer_ledger.record_reject(propagation_source) {
                    tracing::warn!(
                        "⛔ Peer yasaklandi (tekrarlayan gecersiz mesaj): {propagation_source}"
                    );
                    swarm
                        .behaviour_mut()
                        .gossipsub
                        .blacklist_peer(&propagation_source);
                    let _ = swarm.disconnect_peer_id(propagation_source);
                }
            } else if let MessageAcceptance::Accept = acceptance {
                loop_state.peer_ledger.record_accept(&propagation_source);
            }
            swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &propagation_source, acceptance);
        }
        SwarmEvent::Behaviour(ZagrosBehaviourEvent::Sync(request_response::Event::Message {
            peer,
            message,
            ..
        })) => {
            handle_sync_message(
                swarm,
                peer,
                message,
                runtime,
                state,
                sync_batch_size,
                loop_state,
            );
        }
        SwarmEvent::Behaviour(ZagrosBehaviourEvent::Sync2(request_response::Event::Message {
            peer,
            message,
            ..
        })) => {
            handle_sync2_message(swarm, peer, message, state, sync_batch_size, loop_state);
        }
        SwarmEvent::Behaviour(ZagrosBehaviourEvent::Sync2(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            if let Some(io) = loop_state.consensus.as_mut() {
                if io.pending_sync2 == Some((peer, request_id)) {
                    tracing::warn!("⚠️ sync/2 istegi basarisiz (peer={peer}): {error}");
                    io.pending_sync2 = None;
                    let _ = io.inbound_tx.send(DriverInput::SyncFailed { peer });
                }
            }
        }
        SwarmEvent::Behaviour(ZagrosBehaviourEvent::Sync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) if loop_state.pending_sync.as_ref().map(|p| p.request_id) == Some(request_id) => {
            // Tek bir peer'ın cevapsız kalması akışı durdurmaz; bir sonraki
            // boşlukta yeniden denenir. Bu yüzden `info` seviyesi yeterli.
            tracing::info!("Senkronizasyon isteği yanıtsız kaldı (peer={peer}): {error}. Bir sonraki boşlukta tekrar denenecek.");
            loop_state.pending_sync = None;
        }
        _ => {}
    }
}

/// Validatör, sentry adreslerini imzalayıp `/peers/1` topic'inde yayınlar.
/// network_id topic adından (`/zagros/{id}/consensus/1`) okunur.
fn publish_announcement(
    swarm: &mut Swarm<ZagrosBehaviour>,
    topic: &libp2p::gossipsub::IdentTopic,
    state: &Arc<dyn State>,
    loop_state: &LoopState,
) {
    let Some(cfg) = loop_state.policy.announce.as_ref() else {
        return;
    };
    let epoch = zagros_executor::validator_set::load_active_set(state.as_ref())
        .map(|s| s.epoch)
        .unwrap_or(0);
    let mut a = PeerAnnouncement {
        validator: cfg.validator.to_ascii_lowercase(),
        sentries: cfg.sentry_addrs.clone(),
        epoch,
        issued_at: now_secs(),
        sig: Vec::new(),
    };
    a.sig = cfg.keypair.sign_digest(&a.signing_digest(&cfg.domain));
    if let Err(e) = a.validate_shape() {
        tracing::warn!("⚠️ Sentry duyurusu yayınlanmadı (yapı): {e}");
        return;
    }
    match bincode::serialize(&a) {
        Ok(bytes) => match swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), bytes)
        {
            Ok(_) => tracing::info!(
                "📣 Sentry duyurusu yayınlandı: {} sentry, epoch {}",
                a.sentries.len(),
                epoch
            ),
            Err(e) => tracing::debug!("sentry duyurusu şimdilik yayınlanamadı (peer yok?): {e}"),
        },
        Err(e) => tracing::warn!("⚠️ Sentry duyurusu kodlanamadı: {e}"),
    }
}

/// `/peers/1` topic'inden gelen duyuru: doğrula, sakla, (açık modda) sentry'leri ara.
fn handle_peer_announcement(
    data: &[u8],
    swarm: &mut Swarm<ZagrosBehaviour>,
    state: &Arc<dyn State>,
    loop_state: &mut LoopState,
) -> MessageAcceptance {
    if data.len() > 4096 {
        return MessageAcceptance::Reject;
    }
    let a: PeerAnnouncement = match bincode::deserialize(data) {
        Ok(a) => a,
        Err(_) => return MessageAcceptance::Reject,
    };
    let domain = match zagros_executor::params::consensus_domain(state.as_ref()) {
        Ok(d) => d,
        Err(_) => return MessageAcceptance::Ignore,
    };
    let pubkey_of = |addr: &str| -> Option<[u8; 32]> {
        let acc = state
            .get_account(&addr.to_ascii_lowercase())
            .ok()
            .flatten()?;
        if !acc.is_registered_validator || acc.consensus_pubkey == [0u8; 32] {
            return None;
        }
        Some(acc.consensus_pubkey)
    };
    if let Err(e) = verify_announcement(&a, &domain, now_secs(), pubkey_of) {
        tracing::debug!("sentry duyurusu reddedildi: {e}");
        // İmza/yapı hatası ceza sayar; süre/gelecek hatası yalnız yok sayılır.
        return if e.contains("imza") || e.contains("gecersiz") || e.contains("olmali") {
            MessageAcceptance::Reject
        } else {
            MessageAcceptance::Ignore
        };
    }
    let key = a.validator.to_ascii_lowercase();
    if let Some(prev) = loop_state.announcements.get(&key) {
        if prev.issued_at >= a.issued_at {
            // Eski/aynı duyuru: yayma, ceza da yok.
            return MessageAcceptance::Ignore;
        }
    }
    tracing::info!(
        "📣 Sentry duyurusu alındı: {} → {} sentry (epoch {})",
        key,
        a.sentries.len(),
        a.epoch
    );
    let ids = crate::behaviour::peer_ids_of(&a.sentries);
    loop_state.announcements.insert(key, a.clone());
    loop_state.announced_peers.extend(ids.iter().copied());
    // Kapalı (validatör) mod yabancı sentry aramaz; açık/sentry düğüm arar
    // ve yeniden-arama defterine kalıcı ekler.
    if !loop_state.policy.is_private() {
        for addr in &a.sentries {
            if let Ok(m) = addr.parse::<libp2p::Multiaddr>() {
                let my_id = *swarm.local_peer_id();
                if m.iter()
                    .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(id) if id == my_id))
                {
                    continue; // kendi adresimiz
                }
                loop_state.peer_book.add_known(m.clone());
                if let Err(e) = swarm.dial(m) {
                    tracing::debug!("duyurulan sentry aranamadı: {e}");
                }
            }
        }
    }
    loop_state.publish_network_snapshot();
    MessageAcceptance::Accept
}

fn network_id_of(topic: &libp2p::gossipsub::TopicHash) -> u64 {
    topic
        .as_str()
        .split('/')
        .nth(2)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Saniyelik pencere sayacı: sayacı artırır ve sınırın AŞILDIĞINI döner.
/// Ayrı fonksiyon, çünkü doğruluğu (pencere sıfırlama, sınır sınırı) tek
/// başına test edilebilmeli.
fn bump_and_check_rate(
    map: &mut std::collections::HashMap<PeerId, (u64, u32)>,
    peer: PeerId,
    now_ms: u64,
    limit: u32,
) -> bool {
    let counter = map.entry(peer).or_insert((now_ms, 0));
    if now_ms.saturating_sub(counter.0) >= 1_000 {
        *counter = (now_ms, 0);
    }
    counter.1 += 1;
    counter.1 > limit
}

/// G5: konsensüs topic'i, `InboundGate` kararı. Kapı yoksa (BFT modu
/// kapalı) Ignore: yayılmaz ama peer cezalandırılmaz.
fn handle_consensus_gossip(
    data: &[u8],
    from: PeerId,
    loop_state: &mut LoopState,
) -> MessageAcceptance {
    if loop_state.peer_ledger.is_banned(&from) {
        return MessageAcceptance::Ignore;
    }
    let Some(io) = loop_state.consensus.as_mut() else {
        return MessageAcceptance::Ignore;
    };
    // Hız sınırı kapıdan ÖNCE: amaç, `Ignore` dönen (dolayısıyla peer defterini
    // hiç işletmeyen) geçerli-ama-tekrar mesaj selini de durdurmak.
    let now = crate::consensus_driver::now_ms();
    // Harita `PeerId` ile anahtarlı ve `PeerId` üretmek bedava, sync/2
    // sayacındaki aynı disiplin: penceresi geçmiş girdiler ölüdür, budanır.
    if io.inbound_consensus_rate.len() > MAX_TRACKED_SYNC_PEERS {
        io.inbound_consensus_rate
            .retain(|_, (window_start, _)| now.saturating_sub(*window_start) < 1_000);
        if io.inbound_consensus_rate.len() > MAX_TRACKED_SYNC_PEERS {
            io.inbound_consensus_rate.clear();
        }
    }
    if bump_and_check_rate(
        &mut io.inbound_consensus_rate,
        from,
        now,
        CONSENSUS_INBOUND_PER_SEC,
    ) {
        tracing::warn!(
            "⛔ konsensus mesaj seli ({from}): saniyede sinir {CONSENSUS_INBOUND_PER_SEC} asildi"
        );
        // `Reject` → çağıran `record_reject` işletir → 8 hatada ban + blacklist.
        return MessageAcceptance::Reject;
    }
    match io.gate.check(data) {
        Verdict::Accept(msg) => {
            if io.inbound_tx.send(DriverInput::Consensus(*msg)).is_err() {
                tracing::warn!("⚠️ BFT surucusu kanali kapali; konsensus mesaji dusuruldu");
                return MessageAcceptance::Ignore;
            }
            MessageAcceptance::Accept
        }
        Verdict::Ignore(reason) => {
            // G6 tetiği: "çok ileri yükseklik" → sürücüye ipucu (peer zaten
            // bizden ilerideyse Status ile doğrulanır; sahte ipucu zararsız:
            // catch-up yalnız QC'li bloklarla ilerler).
            if let Some(h) = reason
                .strip_prefix("cok ileri yukseklik ")
                .and_then(|r| r.split(' ').next())
                .and_then(|n| n.parse::<u64>().ok())
            {
                let _ = io.inbound_tx.send(DriverInput::AheadHint { height: h });
            }
            tracing::trace!("konsensus mesaji yok sayildi ({from}): {reason}");
            MessageAcceptance::Ignore
        }
        Verdict::Reject(reason) => {
            tracing::debug!("⛔ konsensus mesaji reddedildi ({from}): {reason}");
            MessageAcceptance::Reject
        }
    }
}

/// tx/blok topic'leri: çözülebiliyorsa Accept (gossipsub'ın otomatik yayma
/// davranışı korunur), çözülemiyorsa Reject.
fn handle_gossip_message(
    data: &[u8],
    from: PeerId,
    swarm: &mut Swarm<ZagrosBehaviour>,
    mempool: &Arc<Mempool>,
    runtime: &Arc<Runtime>,
    loop_state: &mut LoopState,
) -> MessageAcceptance {
    if loop_state.peer_ledger.is_banned(&from) {
        return MessageAcceptance::Ignore;
    }
    // 🛡️ Hız sınırı decode'dan ÖNCE: geçerli-ama-sel tx'ler de (her biri
    // mempool kabul yolunda imza/nonce maliyeti öder) burada kesilir.
    let now = crate::consensus_driver::now_ms();
    if loop_state.inbound_gossip_rate.len() > MAX_TRACKED_SYNC_PEERS {
        loop_state
            .inbound_gossip_rate
            .retain(|_, (window_start, _)| now.saturating_sub(*window_start) < 1_000);
        if loop_state.inbound_gossip_rate.len() > MAX_TRACKED_SYNC_PEERS {
            loop_state.inbound_gossip_rate.clear();
        }
    }
    if bump_and_check_rate(
        &mut loop_state.inbound_gossip_rate,
        from,
        now,
        GOSSIP_INBOUND_PER_SEC,
    ) {
        tracing::warn!(
            "⛔ tx/blok gossip seli ({from}): saniyede sinir {GOSSIP_INBOUND_PER_SEC} asildi"
        );
        return MessageAcceptance::Reject;
    }
    // 🛡️ Decode öncesi boyut kapısı (`InboundGate` ile aynı kural); sığmayan mesaj çözülmez.
    if data.len() > loop_state.max_gossip_bytes {
        tracing::debug!(
            "⚠️ Aşırı büyük gossip mesajı reddedildi: {} bayt > tavan {}",
            data.len(),
            loop_state.max_gossip_bytes
        );
        return MessageAcceptance::Reject;
    }
    let msg: GossipMessage = match bincode::deserialize(data) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!("⚠️ Çözülemeyen gossip mesajı (reddediliyor): {e}");
            return MessageAcceptance::Reject;
        }
    };

    match msg {
        GossipMessage::NewTransaction(tx) => {
            // 🛡️ Tek giriş kapısı `admit_transaction`; kötü gossip tx'i fatal değil,
            // reddedilir. 🚨 Sessiz kayıp görünsün: her 5 sn'de en fazla bir WARN (sayaçla).
            let sender_short = tx.sender.chars().take(10).collect::<String>();
            let nonce = tx.nonce;
            match mempool.admit_transaction(tx) {
                Ok(_) => {}
                Err(AdmissionError::Full) => {
                    log_gossip_reject(format_args!("mempool dolu ({sender_short} n={nonce})"));
                }
                Err(AdmissionError::InvalidNonce { expected, got }) => {
                    log_gossip_reject(format_args!(
                        "geçersiz nonce ({sender_short}: beklenen={expected}, gelen={got})"
                    ));
                }
                Err(AdmissionError::Rejected(e)) => {
                    // "zaten bekleme odasında" = yeniden yayın kopyası, normal.
                    let msg = format!("{e:?}");
                    if msg.contains("zaten bekleme") {
                        tracing::debug!("gossip tx yinelenen ({sender_short} n={nonce})");
                    } else {
                        log_gossip_reject(format_args!("{msg} ({sender_short} n={nonce})"));
                        // 🛡️ D14: imzası/biçimi geçersiz tx hiçbir görüşte geçerli olamaz,
                        // mesh'e yayılmaz, gönderen cezalandırılır (Reject). Zamanlamaya
                        // bağlı retler (dolu havuz, nonce yarışı) dürüst eşlerde de görülür.
                        if msg.contains("InvalidSignature") || msg.contains("chain_id") {
                            return MessageAcceptance::Reject;
                        }
                    }
                }
            }
        }
        GossipMessage::NewBlock {
            header,
            transactions,
            bridge_proposals,
        } => {
            if loop_state.consensus.is_some() {
                // G6: BFT modunda QC'siz blok gossip'i state'e UYGULANMAZ
                // (commit yalnız QC ile: motor ya da /sync/2). Yayılmaya devam
                // eder (eski node'lar için), bu node için Ignore değil Accept.
                tracing::debug!(
                    "BFT modu: QC'siz blok gossip'i #{} uygulanmadi",
                    header.number
                );
            } else {
                handle_gossip_block(
                    header,
                    transactions,
                    bridge_proposals,
                    swarm,
                    runtime,
                    loop_state,
                );
            }
        }
    }
    MessageAcceptance::Accept
}

/// 🛡️ Tek proposer modelinde fork yok: yalnız TAM sonraki blok uygulanır,
/// bayat/yinelenen bloklar yok sayılır; boşluk (`> current + 1`) varsa ve
/// bekleyen istek yoksa peer'dan eksik aralık istenir (`sync.rs`).
fn handle_gossip_block(
    header: ArchivedBlockHeader,
    transactions: Vec<Transaction>,
    bridge_proposals: Vec<zagros_executor::bridge::BridgeProposal>,
    swarm: &mut Swarm<ZagrosBehaviour>,
    runtime: &Arc<Runtime>,
    loop_state: &mut LoopState,
) {
    // 🚨 BFT açıkken blok yalnız konsensüsten ya da QC'li `/sync/2`den; eski gossip
    // yolu `last_qc`/`proposer` almadan farklı kök üretirdi (canlıda yakalandı).
    if loop_state.consensus.is_some() {
        return;
    }
    let current = runtime.current_block_height().unwrap_or(0) as u64;

    if header.number <= current {
        tracing::debug!(
            "gossip blok #{} yok sayıldı (bayat/yinelenen, mevcut yükseklik={current})",
            header.number
        );
        return;
    }
    if header.number > current + 1 {
        if loop_state.pending_sync.is_some() {
            tracing::debug!(
                "⚠️ Blok boşluğu: gelen #{}, mevcut #{} - zaten bekleyen bir senkronizasyon isteği var, atlanıyor",
                header.number,
                current
            );
            return;
        }
        let Some(&peer) = loop_state.connected_peers.iter().next() else {
            tracing::warn!(
                "⚠️ Blok boşluğu: gelen #{}, mevcut #{} - senkronize olunacak bağlı bir peer yok",
                header.number,
                current
            );
            return;
        };
        let request = sync::request_missing_range(current, header.number);
        let request_id = swarm.behaviour_mut().sync.send_request(&peer, request);
        tracing::info!(
            "🔄 Blok boşluğu tespit edildi (gelen #{}, mevcut #{}) - {peer}'dan #{}..#{} isteniyor",
            header.number,
            current,
            current + 1,
            header.number
        );
        loop_state.pending_sync = Some(PendingSync {
            peer,
            request_id,
            target: header.number,
        });
        return;
    }

    apply_block_or_panic(runtime, header, transactions, bridge_proposals);
}

/// 🛑 FATAL (bilerek): state_root uyuşmazlığı kötü peer ya da gerçek yürütme
/// farkıdır; sessizce ayrışmak yerine durup operatör beklenir. `panic!`
/// JoinSet denetimiyle denetimli kapanışı tetikler.
fn apply_block_or_panic(
    runtime: &Arc<Runtime>,
    header: ArchivedBlockHeader,
    transactions: Vec<Transaction>,
    bridge_proposals: Vec<zagros_executor::bridge::BridgeProposal>,
) {
    if let Err(e) = runtime.apply_external_block(
        header.number,
        header.timestamp,
        &transactions,
        &bridge_proposals,
        header.state_root,
    ) {
        panic!(
            "🛑 Blok #{} REDDEDİLDİ (state_root uyuşmazlığı veya yürütme hatası) - node durduruluyor: {e:?}",
            header.number
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_sync_message(
    swarm: &mut Swarm<ZagrosBehaviour>,
    peer: PeerId,
    message: request_response::Message<crate::messages::SyncRequest, SyncResponse>,
    runtime: &Arc<Runtime>,
    state: &Arc<dyn State>,
    sync_batch_size: u64,
    loop_state: &mut LoopState,
) {
    match message {
        request_response::Message::Request {
            request, channel, ..
        } => {
            // 🛡️ D14: eski senkron kanalı da sync/2 korumalarını taşır (banlıya
            // hizmet yok + eş başına saniyelik tavan); yoksa tek IP yüzlerce
            // bloğu diskten okutup olay döngüsünü kilitleyebilirdi.
            if loop_state.peer_ledger.is_banned(&peer) {
                return;
            }
            let now = crate::consensus_driver::now_ms();
            if loop_state.inbound_peers_rate.len() > MAX_TRACKED_SYNC_PEERS {
                loop_state
                    .inbound_peers_rate
                    .retain(|_, (ws, _)| now.saturating_sub(*ws) < 1_000);
                if loop_state.inbound_peers_rate.len() > MAX_TRACKED_SYNC_PEERS {
                    loop_state.inbound_peers_rate.clear();
                }
            }
            if bump_and_check_rate(
                &mut loop_state.inbound_peers_rate,
                peer,
                now,
                SYNC2_INBOUND_PER_SEC,
            ) {
                if loop_state.peer_ledger.record_reject(peer) {
                    tracing::warn!("⛔ Peer yasaklandi (sync/1 istek seli): {peer}");
                    swarm.behaviour_mut().gossipsub.blacklist_peer(&peer);
                    let _ = swarm.disconnect_peer_id(peer);
                }
                return;
            }
            let response = sync::build_response(state, request, sync_batch_size);
            if swarm
                .behaviour_mut()
                .sync
                .send_response(channel, response)
                .is_err()
            {
                tracing::debug!(
                    "senkronizasyon yanıtı gönderilemedi (peer bağlantıyı kesmiş olabilir)"
                );
            }
        }
        request_response::Message::Response {
            request_id,
            response,
        } => {
            let Some(pending) = &loop_state.pending_sync else {
                return;
            };
            if pending.request_id != request_id || pending.peer != peer {
                return;
            }
            let target = pending.target;
            match response {
                SyncResponse::BlockRange(blocks) => {
                    let block_count = blocks.len();
                    match sync::apply_synced_blocks(runtime, blocks) {
                        Ok(_) => {
                            let new_height = runtime.current_block_height().unwrap_or(0) as u64;
                            tracing::info!(
                                "🔄 Senkronizasyon: {} blok uygulandı, şu an #{}(hedef #{})",
                                block_count,
                                new_height,
                                target
                            );
                            if new_height >= target {
                                loop_state.pending_sync = None;
                            } else {
                                // `sync_batch_size` ile kırpılmış bir yanıttı,
                                // kalan aralık için AYNI peer'a devam isteği.
                                let request = sync::request_missing_range(new_height, target);
                                let new_request_id =
                                    swarm.behaviour_mut().sync.send_request(&peer, request);
                                loop_state.pending_sync = Some(PendingSync {
                                    peer,
                                    request_id: new_request_id,
                                    target,
                                });
                            }
                        }
                        Err(e) => {
                            panic!("🛑 Senkronizasyon sırasında blok reddedildi - node durduruluyor: {e}");
                        }
                    }
                }
                SyncResponse::NotAvailable => {
                    // Normal durum: proaktif senkron zincir ucunu hedefler, uca varınca
                    // istenen aralık peer'da yoktur; `warn!` operatörü yanıltıyordu.
                    tracing::debug!(
                        "{peer} zincir ucunda: istenen aralık henüz üretilmemiş, senkronizasyon tamamlandı"
                    );
                    loop_state.pending_sync = None;
                }
                SyncResponse::Status { .. } => {
                    // Şu an `GetStatus` hiçbir yerden tetiklenmiyor, protokolün
                    // ileride genişleyebilmesi için tanımlı (bkz. messages.rs).
                }
            }
        }
    }
}

/// G6: `/zagros/sync/2`, istekler diskten cevaplanır (flood sınırıyla);
/// yanıtlar yalnız sürücünün beklediği (peer, request_id) eşleşiyorsa ya da
/// `Status` ise sürücüye iletilir.
fn handle_sync2_message(
    swarm: &mut Swarm<ZagrosBehaviour>,
    peer: PeerId,
    message: request_response::Message<Sync2Request, Sync2Response>,
    state: &Arc<dyn State>,
    sync_batch_size: u64,
    loop_state: &mut LoopState,
) {
    match message {
        request_response::Message::Request {
            request, channel, ..
        } => {
            if loop_state.peer_ledger.is_banned(&peer) {
                return;
            }
            // Flood sınırı: peer başına saniyede SYNC2_INBOUND_PER_SEC istek.
            let now = crate::consensus_driver::now_ms();
            let over_limit = if let Some(io) = loop_state.consensus.as_mut() {
                // 🛡️ Sınırlı tut: `PeerId` üretmek bedava, temizlenmezse saldırgan
                // her istekte yeni kimlikle belleği sınırsız büyütür. Penceresi geçmiş girdi ölüdür.
                if io.inbound_sync2_rate.len() > MAX_TRACKED_SYNC_PEERS {
                    io.inbound_sync2_rate
                        .retain(|_, (window_start, _)| now.saturating_sub(*window_start) < 1_000);
                    // Hepsi tazeyse (gerçek bir sel) en sert önlem: sıfırla.
                    // Sayaç kaybı en fazla bir saniyelik hoşgörü demektir,
                    // sınırsız bellek büyümesine tercih edilir.
                    if io.inbound_sync2_rate.len() > MAX_TRACKED_SYNC_PEERS {
                        io.inbound_sync2_rate.clear();
                    }
                }
                let e = io.inbound_sync2_rate.entry(peer).or_insert((now, 0));
                if now.saturating_sub(e.0) >= 1_000 {
                    *e = (now, 0);
                }
                e.1 += 1;
                e.1 > SYNC2_INBOUND_PER_SEC
            } else {
                false
            };
            let response = if over_limit {
                if loop_state.peer_ledger.record_reject(peer) {
                    tracing::warn!("⛔ Peer yasaklandi (sync/2 istek seli): {peer}");
                    swarm.behaviour_mut().gossipsub.blacklist_peer(&peer);
                    let _ = swarm.disconnect_peer_id(peer);
                }
                Sync2Response::NotAvailable
            } else {
                sync2::build_response(state, request, sync_batch_size)
            };
            if swarm
                .behaviour_mut()
                .sync2
                .send_response(channel, response)
                .is_err()
            {
                tracing::debug!("sync/2 yaniti gonderilemedi (peer baglantiyi kesmis olabilir)");
            }
        }
        request_response::Message::Response {
            request_id,
            response,
        } => {
            let Some(io) = loop_state.consensus.as_mut() else {
                return;
            };
            match response {
                Sync2Response::Status(status) => {
                    let _ = io.inbound_tx.send(DriverInput::PeerStatus { peer, status });
                }
                other => {
                    if io.pending_sync2 == Some((peer, request_id)) {
                        io.pending_sync2 = None;
                        let _ = io.inbound_tx.send(DriverInput::SyncBlocks {
                            peer,
                            response: other,
                        });
                    } else {
                        tracing::debug!("beklenmeyen sync/2 yaniti ({peer}) yok sayildi");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;

    fn peer(n: u8) -> PeerId {
        PeerId::from_multihash(libp2p::multihash::Multihash::wrap(0x00, &[n; 32]).unwrap()).unwrap()
    }

    #[test]
    fn rate_counter_allows_up_to_the_limit_then_trips() {
        let mut map = std::collections::HashMap::new();
        let p = peer(1);
        for i in 1..=5 {
            assert!(
                !bump_and_check_rate(&mut map, p, 1_000, 5),
                "{i}. mesaj sinirin altinda"
            );
        }
        assert!(
            bump_and_check_rate(&mut map, p, 1_000, 5),
            "6. mesaj siniri asmali"
        );
    }

    #[test]
    fn rate_counter_resets_after_the_window() {
        let mut map = std::collections::HashMap::new();
        let p = peer(2);
        for _ in 0..6 {
            bump_and_check_rate(&mut map, p, 1_000, 5);
        }
        assert!(
            !bump_and_check_rate(&mut map, p, 2_000, 5),
            "yeni pencerede sayac sifirlanmali"
        );
    }

    /// Sel, peer BAŞINA sayılmalı: dürüst bir komşu, saldırgan yüzünden
    /// cezalandırılmamalı.
    #[test]
    fn rate_counter_is_per_peer() {
        let mut map = std::collections::HashMap::new();
        for _ in 0..6 {
            bump_and_check_rate(&mut map, peer(3), 1_000, 5);
        }
        assert!(
            !bump_and_check_rate(&mut map, peer(4), 1_000, 5),
            "baska peer etkilenmemeli"
        );
    }
}

/// Gossip tx reti: her olay debug'a, 5 sn'de en fazla bir WARN (aradaki
/// olayların sayısıyla). Tek node'daki tek ret zincirleme kayba dönüşebilir;
/// operatör görmeli.
fn log_gossip_reject(args: std::fmt::Arguments<'_>) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST_WARN_SECS: AtomicU64 = AtomicU64::new(0);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    tracing::debug!("gossip tx reddedildi: {args}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST_WARN_SECS.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= 5 {
        LAST_WARN_SECS.store(now, Ordering::Relaxed);
        let hidden = SUPPRESSED.swap(0, Ordering::Relaxed);
        tracing::warn!("⚠️ gossip tx reddedildi: {args} (+{hidden} benzer, son 5 sn)");
    } else {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod sentry_tests {
    use super::*;

    #[test]
    fn admit_connection_applies_ip_quota_and_open_slots_but_exempts_privileged_peers() {
        // Sıradan peer: IP kotası (4) ve açık slot (50) sınırları uygulanır.
        assert!(admit_connection(false, 4, 4, 10, 50).is_ok());
        assert_eq!(
            admit_connection(false, 5, 4, 10, 50),
            Err("ip kotasi asildi")
        );
        assert!(
            admit_connection(false, 1, 4, 51, 50).is_err(),
            "acik slot tavani"
        );
        // Özel/duyurulmuş peer: ikisinden de muaf (ayrılmış slotlar onun için).
        assert!(admit_connection(true, 99, 4, 999, 50).is_ok());
    }

    #[test]
    fn announcement_sign_verify_roundtrip_and_tampering_is_rejected() {
        let kp = zagros_crypto::ConsensusKeypair::generate();
        let domain = ConsensusDomain::new(21072026, [7u8; 32]);
        let validator = "0x00000005668becb40d7eaafdae73ed6347932d49".to_string();
        let now = 1_788_700_000u64;
        let mut a = PeerAnnouncement {
            validator: validator.clone(),
            sentries: vec!["/ip4/18.158.145.210/tcp/30303/p2p/12D3KooWQuPAZdnhENsAQ8GjRUAVR4hVmEpB8onx6GKiF2XYdCmY".to_string()],
            epoch: 60,
            issued_at: now,
            sig: Vec::new(),
        };
        a.sig = kp.sign_digest(&a.signing_digest(&domain));
        let pk = kp.public_key();
        let lookup = |addr: &str| if addr == validator { Some(pk) } else { None };
        assert!(
            verify_announcement(&a, &domain, now + 10, lookup).is_ok(),
            "gecerli duyuru gecmeli"
        );

        // Kayıtlı olmayan validatör → ret.
        assert!(verify_announcement(&a, &domain, now + 10, |_| None).is_err());
        // Sentry listesi değişirse imza tutmaz.
        let mut t = a.clone();
        t.sentries.push(
            "/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWQuPAZdnhENsAQ8GjRUAVR4hVmEpB8onx6GKiF2XYdCmY"
                .to_string(),
        );
        assert!(verify_announcement(&t, &domain, now + 10, lookup).is_err());
        // Farklı zincir (domain) → imza tutmaz.
        assert!(
            verify_announcement(&a, &ConsensusDomain::new(1, [7u8; 32]), now + 10, lookup).is_err()
        );
        // Süresi dolmuş ve gelecekten gelen duyurular reddedilir.
        assert!(
            verify_announcement(&a, &domain, now + PeerAnnouncement::TTL_SECS + 1, lookup).is_err()
        );
        assert!(
            verify_announcement(&a, &domain, now - ANNOUNCE_FUTURE_SKEW_SECS - 1, lookup).is_err()
        );
        // Yapı: /p2p/ olmayan adres ve boş liste ret.
        let mut bad = a.clone();
        bad.sentries = vec!["/ip4/1.2.3.4/tcp/30303".to_string()];
        assert!(bad.validate_shape().is_err());
        bad.sentries.clear();
        assert!(bad.validate_shape().is_err());
    }

    #[test]
    fn peer_ids_of_extracts_only_addresses_with_p2p_component() {
        let ids = crate::behaviour::peer_ids_of(&[
            "/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWQuPAZdnhENsAQ8GjRUAVR4hVmEpB8onx6GKiF2XYdCmY"
                .to_string(),
            "/ip4/1.2.3.4/tcp/30303".to_string(),
            "bozuk".to_string(),
        ]);
        assert_eq!(ids.len(), 1);
    }
}
