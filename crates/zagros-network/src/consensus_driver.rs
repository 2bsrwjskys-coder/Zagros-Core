//! `BftEngine` host'u (sürücü): `now_ms` duvar saatinden, gossip mesajları
//! `InboundGate`ten motora, çıktılar uygulanır (`Broadcast` → gossip,
//! `NeedProposal` → mempool + `propose()`/`heartbeat()`, `Commit` → konsensüs
//! kayıtları + `Runtime::commit_block` (kök uyuşmazlığı FATAL)).
//! G6 catch-up (`/zagros/sync/2`): tetik = gossip ipucu, peer tip'i ileride,
//! QC var gövde yok, bağlantı/restart; tek peer, tek bekleyen istek, her blok
//! `sync2::validate_block` → `persist_and_commit`; bitince motor state'ten
//! yeniden kurulur, catch-up sırasında motor donar. Başlatma FAIL-CLOSED.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::PeerId;
use tokio::sync::{mpsc, watch};
use zagros_consensus::engine::{
    BftEngine, ChainTip, Message, NodeIdentity, Output, RuntimeVerifier, Step,
};
use zagros_crypto::sign_vote;
use zagros_crypto::ConsensusKeypair;
use zagros_executor::bridge::{BridgeManager, BridgeProposal};
use zagros_executor::{params, validator_set};
use zagros_mempool::Mempool;
use zagros_primitives::{Result, ZagrosError};
use zagros_runtime::Runtime;
use zagros_state::State;
use zagros_types::consensus::{
    keccak256, ActiveValidatorSet, ChainParams, ConsensusDomain, QuorumCertificate,
    ShadowVoteAttestation, SignedHeader, Vote, VotePhase,
};
use zagros_types::{Address, Transaction, MAX_BLOCK_TX_LIMIT};

use crate::consensus_wire::{max_wire_bytes, GateView, SharedGateView};
use crate::messages::{Sync2Request, Sync2Response, Sync2Status};
use crate::service::NetworkHandle;
use crate::sync2::{self, SyncContext, TrustedCheckpoint};

pub use crate::sync2::{load_consensus_tip, store_consensus_records};

/// Ağır (EVM) işlem tavanı, mevcut üretici döngüsüyle aynı değer (main.rs).
const MAX_HEAVY_PER_BLOCK: usize = 500;
/// "QC var, gövde yok" tetiği: `4 × T_base` (spec §9).
const PENDING_QC_TIMEOUT_MULTIPLIER: u64 = 4;
/// Bir catch-up isteğine yanıt bekleme süresi (ms); aşılırsa peer değiştirilir.
/// Es yuksekliklerini duzenli ogrenmek icin `GetStatus` araligi.
const STATUS_POLL_INTERVAL_MS: u64 = 10_000;
const SYNC_REQUEST_TIMEOUT_MS: u64 = 10_000;

/// Servis döngüsünden sürücüye giren olaylar.
pub enum DriverInput {
    /// Giriş kapısını geçmiş konsensüs mesajı.
    Consensus(Message),
    /// Kapı "çok ileri yükseklik" gördü (gossip'te `height > local+1`).
    AheadHint {
        height: u64,
    },
    /// Bir peer'ın `GetStatus` yanıtı (bağlantıda otomatik ya da istekle).
    PeerStatus {
        peer: PeerId,
        status: Sync2Status,
    },
    /// Bizim gönderdiğimiz aralık isteğine yanıt (servis yalnız beklenen
    /// peer/istekten gelenleri iletir).
    SyncBlocks {
        peer: PeerId,
        response: Sync2Response,
    },
    /// İsteğimiz taşıma düzeyinde başarısız oldu.
    SyncFailed {
        peer: PeerId,
    },
    /// Servis isteği gönderemedi (bağlı uygun peer yok).
    SyncNoPeer,
    PeerGone {
        peer: PeerId,
    },
}

/// Servis döngüsünün sürücüyle konuşmak için ihtiyaç duyduğu uçlar.
pub struct ConsensusWiring {
    pub inbound_tx: mpsc::UnboundedSender<DriverInput>,
    pub gate_view: SharedGateView,
    pub max_wire_bytes: usize,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct CatchUp {
    peer: PeerId,
    target: u64,
    requested_at_ms: u64,
    /// Bu peer'dan beklenen ilk yükseklik (yanıt şekli kontrolü).
    expected_first: u64,
}

pub struct ConsensusDriver {
    engine: BftEngine,
    runtime: Arc<Runtime>,
    mempool: Arc<Mempool>,
    state: Arc<dyn State>,
    params: ChainParams,
    domain: ConsensusDomain,
    keypair: Option<ConsensusKeypair>,
    verifier: RuntimeVerifier,
    gate_view: SharedGateView,
    inbound_rx: mpsc::UnboundedReceiver<DriverInput>,
    last_commit_at_ms: u64,
    /// Boşta lider: bir sonraki heartbeat / yeniden-değerlendirme anı.
    next_heartbeat_at: Option<u64>,
    /// 🚨 Periyodik `GetStatus`: follower'lar eş yüksekliğini yalnız bağlantı
    /// anında öğreniyordu, o an eşitse sonsuza dek geride kalıyordu (genesis'te
    /// canlı yakalandı). Gossip mesh sağlığından bağımsız çalışır.
    next_status_poll_at: Option<u64>,
    checkpoint: Option<TrustedCheckpoint>,
    sync_batch_size: u64,
    /// Bilinen peer tip yükseklikleri (Status yanıtlarından).
    peer_tips: HashMap<PeerId, u64>,
    catch_up: Option<CatchUp>,
    /// "QC var gövde yok" ilk görülme anı.
    pending_qc_since: Option<u64>,
    /// Bu oturumda catch-up ile reddedilen peer'lar (yeniden seçilmez).
    bad_peers: Vec<PeerId>,
    /// G8: gossip'ten toplanan, henüz bloğa gömülmemiş ShadowVote adayları —
    /// (adres, height, round) → giriş. Her commit'te `tip.height`'in gerisinde
    /// kalanlar budanır (sınırlı bellek).
    shadow_vote_pool: HashMap<(Address, u64, u32), ShadowVoteAttestation>,
    /// 🚨 Equivocation kanıtlarının yerel dosyası (zincire yazmak determinizmi bozar);
    /// operatör hazır payload ile `ReportMalicious` gönderir.
    evidence_log: Option<std::path::PathBuf>,
    /// Restart-güvenli çift-imza koruması durum dosyası (bkz. engine
    /// `DoubleSignProtector`). `None` = koruma kapalı. Motor her commit'te
    /// yeniden kurulduğundan bu yol `build_engine`'de tekrar tekrar verilir.
    double_sign_state: Option<std::path::PathBuf>,
    /// Bu node'un KENDİ `keypair`'i şu an Probation ise hesap adresi (canlı
    /// gölge oy yayınlamak için), her commit'te yeniden çözülür.
    probation_identity: Option<Address>,
    /// G14: /metrics // /health için süreç-içi sayaçlar (None = kablosuz;
    /// gözlemlenebilirlik verisi, konsensüse GİRMEZ).
    metrics: Option<Arc<zagros_metrics::NodeMetrics>>,
}

/// Kanıt günlüğü satırı (JSONL). Ayrı ve saf: içeriğinin operatör tarafından
/// DOĞRUDAN kullanılabilir olması (geçerli payload + doğru alıcı) testle
/// güvence altına alınmalı, kanıtın zincire ulaşan tek yolu bu satır.
pub fn evidence_log_line(
    ev: &zagros_types::consensus::Evidence,
    accused: &str,
    observed_at_ms: u64,
) -> String {
    let payload = zagros_types::EquivocationReport::ConsensusEvidence(ev.clone()).to_bytes();
    format!(
        "{{\"height\":{},\"validator_idx\":{},\"accused\":\"{}\",\"observed_at_ms\":{},\"tx_type\":\"ReportMalicious\",\"receiver\":\"{}\",\"payload_hex\":\"{}\"}}\n",
        ev.height(),
        ev.validator_idx(),
        accused,
        observed_at_ms,
        accused,
        hex::encode(&payload)
    )
}

impl ConsensusDriver {
    /// State'ten motoru kurar. `keypair: None` = gözlemci. Anahtar verilmiş
    /// ama aktif kümede değilse `Err` (fail-closed).
    /// Kanıt günlüğü dosyasını ayarlar (CLI, config'ten geçirir).
    pub fn with_evidence_log(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.evidence_log = path;
        self
    }

    /// Restart-güvenli çift-imza korumasını ayarlar (CLI, config'ten geçirir).
    /// Yolu saklar VE mevcut motora hemen uygular (bootstrap motoru da korunsun);
    /// sonraki `build_engine` yeniden-kurulumları da bu yolu kullanır.
    pub fn with_double_sign_state(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.double_sign_state = path;
        if let Some(p) = self.double_sign_state.as_deref() {
            self.engine.set_double_sign_protector(p);
        }
        self
    }

    /// Görülen kanıtı hem log'a hem (ayarlıysa) yerel dosyaya yazar. Dosya
    /// satırı, operatörün doğrudan kullanabileceği `ReportMalicious` payload'ını
    /// ve suçlanan adresi içerir, kanıtın zincire ulaşan tek yolu bugün budur.
    fn record_evidence(&self, ev: &zagros_types::consensus::Evidence) {
        let idx = ev.validator_idx();
        let accused = self
            .engine
            .validator_set()
            .members
            .get(idx as usize)
            .map(|m| m.address.clone())
            .unwrap_or_else(|| "<bilinmeyen>".to_string());
        tracing::warn!(
            "🚨 Equivocation kaniti: h={} validator_idx={} adres={} - ReportMalicious ile cezalandirilabilir",
            ev.height(),
            idx,
            accused
        );
        let Some(path) = self.evidence_log.as_ref() else {
            return;
        };
        let line = evidence_log_line(ev, &accused, now_ms());
        use std::io::Write;
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(line.as_bytes()) {
                    tracing::error!("kanit dosyasina yazilamadi ({}): {e}", path.display());
                }
            }
            Err(e) => tracing::error!("kanit dosyasi acilamadi ({}): {e}", path.display()),
        }
    }

    pub fn bootstrap(
        state: Arc<dyn State>,
        runtime: Arc<Runtime>,
        mempool: Arc<Mempool>,
        keypair: Option<ConsensusKeypair>,
    ) -> Result<(Self, ConsensusWiring)> {
        Self::bootstrap_with(state, runtime, mempool, keypair, None, 500)
    }

    pub fn bootstrap_with(
        state: Arc<dyn State>,
        runtime: Arc<Runtime>,
        mempool: Arc<Mempool>,
        keypair: Option<ConsensusKeypair>,
        checkpoint: Option<TrustedCheckpoint>,
        sync_batch_size: u64,
    ) -> Result<(Self, ConsensusWiring)> {
        let (engine, domain, params) =
            Self::build_engine(state.as_ref(), runtime.as_ref(), keypair.as_ref(), None)?;
        let probation = Self::scan_probation(state.as_ref()).unwrap_or_default();
        let initial_probation_identity = keypair.as_ref().and_then(|kp| {
            let pk = kp.public_key();
            probation
                .iter()
                .find(|(_, cpk, _)| *cpk == pk)
                .map(|(addr, _, _)| addr.clone())
        });
        let gate_view: SharedGateView = Arc::new(RwLock::new(GateView {
            last_qc: None,
            domain,
            set: engine.validator_set().clone(),
            height: engine.height(),
            probation: probation
                .iter()
                .map(|(a, pk, _)| (a.clone(), *pk))
                .collect(),
        }));
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let wiring = ConsensusWiring {
            inbound_tx,
            gate_view: gate_view.clone(),
            max_wire_bytes: max_wire_bytes(&params),
        };
        let driver = Self {
            evidence_log: None,
            double_sign_state: None,
            engine,
            verifier: RuntimeVerifier(runtime.clone()),
            runtime,
            mempool,
            state,
            params,
            domain,
            keypair,
            gate_view,
            inbound_rx,
            last_commit_at_ms: 0,
            next_heartbeat_at: None,
            next_status_poll_at: None,
            checkpoint,
            sync_batch_size: sync_batch_size.max(1),
            peer_tips: HashMap::new(),
            catch_up: None,
            pending_qc_since: None,
            bad_peers: Vec::new(),
            shadow_vote_pool: HashMap::new(),
            probation_identity: initial_probation_identity,
            metrics: None,
        };
        Ok((driver, wiring))
    }

    /// G14: sayaçları bağlar (RPC'nin /metrics // /health uçları okur).
    pub fn with_metrics(mut self, metrics: Arc<zagros_metrics::NodeMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// G14: motor istatistiklerini ve sürücü bağlamını atomik sayaçlara yazar.
    /// Her olay döngüsü turunda çağrılır, ucuz (Relaxed store'lar).
    fn publish_metrics(&self) {
        let Some(m) = &self.metrics else { return };
        use std::sync::atomic::Ordering::Relaxed;
        let s = self.engine.stats();
        m.view_changes_total.store(s.view_changes_total, Relaxed);
        m.timeouts_total.store(s.timeouts_total, Relaxed);
        m.round_skips.store(s.round_skips, Relaxed);
        m.commits_total.store(s.commits_total, Relaxed);
        m.last_commit_round
            .store(s.last_commit_round as u64, Relaxed);
        m.last_commit_height
            .store(self.engine.tip().height, Relaxed);
        m.last_commit_unix_ms.store(self.last_commit_at_ms, Relaxed);
        m.catch_up_active
            .store(self.catch_up.is_some() as u64, Relaxed);
        // D14: eth_syncing'in okuduğu süreç-çapında bayrak (RPC NodeMetrics almıyor).
        zagros_metrics::GLOBAL_CATCH_UP_ACTIVE.store(self.catch_up.is_some() as u64, Relaxed);
    }

    /// Motoru state'teki tip'ten kurar (bootstrap + catch-up sonrası yeniden kurulum).
    fn build_engine(
        state: &dyn State,
        runtime: &Runtime,
        keypair: Option<&ConsensusKeypair>,
        double_sign_path: Option<&std::path::Path>,
    ) -> Result<(BftEngine, ConsensusDomain, ChainParams)> {
        let (domain, params, set) = sync2::load_chain_context(state)?;
        // §23 (G10) FAIL-CLOSED açılış: zincir bu binary'nin bilmediği bir kural
        // setine geçmişse sürücü HİÇ kurulmaz, "yarım anlayan" node yoktur.
        if params.active_ruleset > zagros_types::consensus::SUPPORTED_RULESET {
            return Err(ZagrosError::Other(format!(
                "🔄🛑 zincir active_ruleset={} bu yazılımın desteklediği {}'i aşıyor — binary'yi güncelleyin (§23)",
                params.active_ruleset,
                zagros_types::consensus::SUPPORTED_RULESET
            )));
        }
        let height = runtime.current_block_height()? as u64;
        let tip = Self::load_tip(state, height)?;
        // G8: anahtar kümede değilse hata değil, gözlemci (`identity: None`);
        // henüz Active olmamış operatör node'unu önceden başlatabilsin. Probation
        // gölge oy kimliği `refresh_probation_view` ile çözülür; doğrulama gevşemez.
        let identity = keypair.as_ref().and_then(|kp| {
            let pk = kp.public_key();
            set.members
                .iter()
                .position(|m| m.consensus_pubkey == pk)
                .map(|idx| NodeIdentity {
                    idx: idx as u16,
                    keypair: ConsensusKeypair::from_secret_bytes(&kp.secret_bytes()),
                })
        });
        // G8: `tip.qc` tip'in kesinleştiği epoch'un kümesine karşı doğrulanır,
        // güncel `set`e değil. Anlık görüntü eksikse fail-closed: motor kurulmaz.
        let tip_set = match &tip.qc {
            Some(qc) => Some(validator_set::load_validator_set_at_epoch(state, qc.epoch)?),
            None => None,
        };
        let mut engine = BftEngine::new(domain, params.clone(), set, identity, tip, tip_set)?;
        if let Some(p) = double_sign_path {
            engine.set_double_sign_protector(p);
        }
        // ⏱️ QC kapanış toleransı: state (yönetişim) → motor; sınır doğrulanır,
        // sığmıyorsa (t_base yönetişimle küçülmüş olabilir) tavana kırpılır ve uyarılır.
        {
            let grace = zagros_executor::params::load_qc_grace_ms(state)?;
            let cap = zagros_types::consensus::qc_grace_cap_ms(params.t_base_ms);
            let eff = if grace > cap {
                tracing::warn!("⚠️ qc_grace_ms {grace} > t_base/4 = {cap}; {cap} ms'e kirpildi");
                cap
            } else {
                grace
            };
            engine.set_qc_grace_ms(eff);
        }
        Ok((engine, domain, params))
    }

    /// Tip: h=0 → genesis; h>0 → `__CONSENSUS_TIP__`, yoksa per-height kayıt
    /// (crash/restart kurtarma); ikisi de yoksa / yükseklik uyuşmuyorsa Err.
    fn load_tip(state: &dyn State, height: u64) -> Result<ChainTip> {
        if height == 0 {
            let hash = match state.get_genesis_block_0_bytes()? {
                Some(bytes) => keccak256(&bytes),
                None => [0u8; 32],
            };
            let ts = params::genesis_timestamp(state).unwrap_or(0) as u64;
            return Ok(ChainTip {
                height: 0,
                hash,
                qc: None,
                timestamp_ms: ts.saturating_mul(1000),
            });
        }
        let rec = match load_consensus_tip(state)? {
            Some((sh, qc, sv)) if sh.header.number == height => Some((sh, qc, sv)),
            _ => sync2::load_consensus_record(state, height)?,
        };
        let (signed, qc, _shadow_votes) = rec.ok_or_else(|| {
            ZagrosError::ConfigError(format!(
                "yukseklik {height} icin konsensus kaydi yok — BFT modu baslatilamaz (G6: sync/2 ile yetisen bir peer gerekli ya da eski zincir)"
            ))
        })?;
        if signed.header.number != height || qc.block_hash != signed.header.hash() {
            return Err(ZagrosError::ConfigError(
                "konsensus tip kaydi tutarsiz".into(),
            ));
        }
        Ok(ChainTip {
            height,
            hash: signed.header.hash(),
            qc: Some(qc),
            timestamp_ms: signed.header.timestamp_ms,
        })
    }

    pub fn engine(&self) -> &BftEngine {
        &self.engine
    }
    pub fn is_syncing(&self) -> bool {
        self.catch_up.is_some()
    }
    /// G8: KENDİ hesabımızın şu an Probation olarak tanındığı adres (varsa).
    /// Yalnız gözlemlenebilirlik/test amaçlı.
    pub fn probation_identity(&self) -> Option<&Address> {
        self.probation_identity.as_ref()
    }

    /// Ana döngü. `cancel_rx` `true` olunca döner.
    pub async fn run(mut self, handle: NetworkHandle, mut cancel_rx: watch::Receiver<bool>) {
        let now = now_ms();
        // 🛡️ Restart'ta `now`a sıfırlanmaz: `idle_block_due` gerçek son commit
        // zamanını (`engine.tip()`) referans almalı, yoksa boşta blok aralığı
        // sıfırdan sayılır. h=0 hariç (genesis damgası duvar saati olmayabilir).
        self.last_commit_at_ms = if self.engine.tip().height == 0 {
            now
        } else {
            self.engine.tip().timestamp_ms
        };
        let outs = self.engine.start(now, &self.verifier);
        self.apply_outputs(outs, &handle);
        tracing::info!(
            "⚖️ BFT sürücüsü başladı: h={} N={} idx={:?}",
            self.engine.height(),
            self.engine.validator_set().len(),
            self.engine.my_idx()
        );

        // 🚨 Baslangicta da kurulur: alan `None` ile baslıyordu ve ilk kurulum
        // motorun tur son tarihine bagliydi. O da bos donerse lider hic
        // uyanmaz, zincir daha ilk blogu uretmeden dururdu.
        self.next_heartbeat_at = Some(now_ms().saturating_add((self.params.t_base_ms / 2).max(50)));
        self.next_status_poll_at = Some(now_ms().saturating_add(STATUS_POLL_INTERVAL_MS));

        loop {
            let sync_deadline = self
                .catch_up
                .as_ref()
                .map(|c| c.requested_at_ms + SYNC_REQUEST_TIMEOUT_MS);
            let engine_deadline = if self.catch_up.is_some() {
                None
            } else {
                self.engine.next_deadline()
            };
            let pending_qc_deadline = self.pending_qc_since.map(|t| {
                t + self
                    .params
                    .t_base_ms
                    .saturating_mul(PENDING_QC_TIMEOUT_MULTIPLIER)
            });
            let next = [
                engine_deadline,
                self.next_heartbeat_at,
                sync_deadline,
                pending_qc_deadline,
                self.next_status_poll_at,
            ]
            .into_iter()
            .flatten()
            .min();
            let sleep_for = match next {
                Some(at) => Duration::from_millis(at.saturating_sub(now_ms())),
                None => Duration::from_secs(3600),
            };
            tokio::select! {
                Some(input) = self.inbound_rx.recv() => {
                    self.on_input(input, &handle);
                }
                _ = tokio::time::sleep(sleep_for) => {
                    self.on_timer(&handle);
                }
                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        tracing::info!("⚖️ BFT sürücüsü zarifçe durduruluyor.");
                        break;
                    }
                }
            }
            self.publish_metrics();
        }
    }

    fn on_timer(&mut self, handle: &NetworkHandle) {
        let now = now_ms();
        if let Some(c) = &self.catch_up {
            if now >= c.requested_at_ms + SYNC_REQUEST_TIMEOUT_MS {
                let peer = c.peer;
                tracing::warn!("⚠️ sync/2 yanit zaman asimi ({peer}); peer degistiriliyor");
                self.mark_bad_peer(peer, handle);
                self.continue_catch_up(handle);
            }
            return;
        }
        if self.next_status_poll_at.map(|t| now >= t).unwrap_or(false) {
            self.next_status_poll_at = Some(now.saturating_add(STATUS_POLL_INTERVAL_MS));
            if self.catch_up.is_none() {
                handle.sync2_request(None, Vec::new(), Sync2Request::GetStatus);
            }
        }
        let mut outs = self.engine.tick(now, &self.verifier);
        if self.next_heartbeat_at.map(|t| now >= t).unwrap_or(false) {
            self.next_heartbeat_at = None;
            outs.extend(self.leader_idle_tick(now));
        }
        self.apply_outputs(outs, handle);
        // QC var, gövde yok → 4×T_base sonra bu yüksekliği bir peer'dan iste.
        match self.engine.pending_qc_hash() {
            Some(_) => {
                let since = *self.pending_qc_since.get_or_insert(now);
                if now
                    >= since
                        + self
                            .params
                            .t_base_ms
                            .saturating_mul(PENDING_QC_TIMEOUT_MULTIPLIER)
                {
                    let h = self.engine.height();
                    tracing::warn!(
                        "🔄 h={h}: QC var, govde yok ({}ms) — sync/2 ile isteniyor",
                        now - since
                    );
                    self.pending_qc_since = None;
                    self.begin_catch_up(h, handle);
                }
            }
            None => self.pending_qc_since = None,
        }
    }

    fn on_input(&mut self, input: DriverInput, handle: &NetworkHandle) {
        match input {
            DriverInput::Consensus(Message::ShadowVote(sv)) => {
                // G8: gölge oylar motora HİÇ gitmez (INV-L4), yalnız
                // sonraki önerimize gömülecek adaylar havuzuna girer.
                self.ingest_shadow_vote(sv);
            }
            DriverInput::Consensus(msg) => {
                if self.catch_up.is_some() {
                    return; // motor donuk; yetişince yeniden kurulacak
                }
                let outs = self.engine.handle(msg, now_ms(), &self.verifier);
                self.apply_outputs(outs, handle);
            }
            DriverInput::AheadHint { height } => {
                if height > self.engine.height() && self.catch_up.is_none() {
                    self.begin_catch_up(height.saturating_sub(1), handle);
                }
            }
            DriverInput::PeerStatus { peer, status } => {
                self.peer_tips.insert(peer, status.tip_height);
                if status.tip_height > self.engine.tip().height && self.catch_up.is_none() {
                    self.begin_catch_up(status.tip_height, handle);
                }
            }
            DriverInput::SyncBlocks { peer, response } => {
                self.on_sync_response(peer, response, handle)
            }
            DriverInput::SyncFailed { peer } => {
                if self.catch_up.as_ref().map(|c| c.peer) == Some(peer) {
                    self.mark_bad_peer(peer, handle);
                    self.continue_catch_up(handle);
                }
            }
            DriverInput::SyncNoPeer => {
                if self.catch_up.is_some() {
                    tracing::warn!("⚠️ sync/2: uygun peer yok; catch-up ertelendi");
                    self.finish_catch_up(handle);
                }
            }
            DriverInput::PeerGone { peer } => {
                self.peer_tips.remove(&peer);
                if self.catch_up.as_ref().map(|c| c.peer) == Some(peer) {
                    self.continue_catch_up(handle);
                }
            }
        }
    }

    // ---- catch-up ----

    fn choose_peer(&self) -> Option<PeerId> {
        let local = self.engine.tip().height;
        self.peer_tips
            .iter()
            .filter(|(p, tip)| **tip > local && !self.bad_peers.contains(p))
            .max_by_key(|(_, tip)| **tip)
            .map(|(p, _)| *p)
    }

    fn begin_catch_up(&mut self, target: u64, handle: &NetworkHandle) {
        let local = self.engine.tip().height;
        if target <= local {
            return;
        }
        // 🚨 `bad_peers` her catch-up turunda temizlenir: geçici sync hatası
        // peer'ı kalıcı damgalasa zamanla hepsi elenir ve node sonsuza dek
        // senkron olamazdı. Damga yalnız bir tur yaşar.
        self.bad_peers.clear();
        let target = target.max(self.peer_tips.values().copied().max().unwrap_or(0));
        tracing::info!(
            "🔄 sync/2 catch-up basliyor: h={} → hedef {}",
            local,
            target
        );
        self.catch_up = Some(CatchUp {
            peer: PeerId::random(),
            target,
            requested_at_ms: now_ms(),
            expected_first: local + 1,
        });
        self.continue_catch_up(handle);
    }

    /// Bir sonraki aralığı ister; peer yoksa servisten herhangi birini ister.
    fn continue_catch_up(&mut self, handle: &NetworkHandle) {
        let local = self.engine.tip().height;
        let Some(target) = self.catch_up.as_ref().map(|c| c.target) else {
            return;
        };
        if local >= target {
            self.finish_catch_up(handle);
            return;
        }
        let from = local + 1;
        let to = target.min(from + self.sync_batch_size - 1);
        let peer = self.choose_peer();
        if peer.is_none()
            && self.peer_tips.keys().all(|p| self.bad_peers.contains(p))
            && !self.peer_tips.is_empty()
        {
            tracing::error!(
                "🚨 state_root_mismatch / kotu peer: catch-up icin guvenilir peer kalmadi (h={}, hedef {}) — catch-up durduruldu, motor mevcut yukseklikte devam ediyor",
                local, target
            );
            self.finish_catch_up(handle);
            return;
        }
        if let Some(c) = self.catch_up.as_mut() {
            c.requested_at_ms = now_ms();
            c.expected_first = from;
            if let Some(p) = peer {
                c.peer = p;
            }
        }
        handle.sync2_request(
            peer,
            self.bad_peers.clone(),
            Sync2Request::GetBlockRange { from, to },
        );
    }

    fn mark_bad_peer(&mut self, peer: PeerId, handle: &NetworkHandle) {
        if !self.bad_peers.contains(&peer) {
            self.bad_peers.push(peer);
        }
        self.peer_tips.remove(&peer);
        handle.penalize_peer(peer);
    }

    fn on_sync_response(&mut self, peer: PeerId, response: Sync2Response, handle: &NetworkHandle) {
        let Some(c) = self.catch_up.as_mut() else {
            return;
        };
        // Servis yalnız beklenen peer'dan iletir; yine de kaydı güncelle.
        c.peer = peer;
        let expected_first = c.expected_first;
        match response {
            Sync2Response::Blocks(blocks) => {
                if let Err(e) =
                    sync2::validate_batch_shape(&blocks, expected_first, self.sync_batch_size)
                {
                    tracing::warn!("⛔ sync/2 yanit sekli gecersiz ({peer}): {e:?}");
                    self.mark_bad_peer(peer, handle);
                    self.continue_catch_up(handle);
                    return;
                }
                for block in blocks {
                    match self.apply_synced_block(&block) {
                        Ok(()) => {}
                        Err(e) => {
                            tracing::warn!("⛔ sync/2 blok reddedildi ({peer}): {e:?}");
                            self.mark_bad_peer(peer, handle);
                            self.continue_catch_up(handle);
                            return;
                        }
                    }
                }
                self.continue_catch_up(handle);
            }
            Sync2Response::BlocksV2(blocks) => {
                let plain: Vec<crate::messages::Sync2Block> =
                    blocks.iter().map(|b| b.block.clone()).collect();
                if let Err(e) =
                    sync2::validate_batch_shape(&plain, expected_first, self.sync_batch_size)
                {
                    tracing::warn!("⛔ sync/2 (v2) yanit sekli gecersiz ({peer}): {e:?}");
                    self.mark_bad_peer(peer, handle);
                    self.continue_catch_up(handle);
                    return;
                }
                for b in &blocks {
                    if !b.missing.is_empty() {
                        tracing::warn!(
                            "🧩 sync/2: blok #{} {} islem govdesi hicbir peer'da yok (yurutmede dusmus, arsivlenmemis) — mevcut govdelerle yurutulup state_root ile dogrulanacak",
                            b.block.signed.header.number, b.missing.len()
                        );
                    }
                    match self.apply_synced_block_with_missing(&b.block, &b.missing) {
                        Ok(()) => {}
                        Err(e) => {
                            let msg = format!("{e:?}");
                            if !b.missing.is_empty() && msg.contains("yeniden yurutme koku") {
                                // 🧩 Bilinen sınır: blok < 811 düşen işlemli bloklar birebir
                                // oynatılamaz; peer dürüst. Çözüm: ≥ 811 snapshot.
                                tracing::error!(
                                    "🧩 sync/2: blok #{} eksik govdeli ve yeniden oynatilamiyor (eski scheduler kurali donemi).                                      Bu zincir tarihi genesis'ten oynatilamaz: node'u SNAPSHOT'tan baslatin —                                      validator-package/bootstrap-from-snapshot.sh (rpc.zagros.network/snapshots/). Peer yasaklanmadi.",
                                    b.block.signed.header.number
                                );
                                self.finish_catch_up(handle);
                                return;
                            }
                            tracing::warn!("⛔ sync/2 (v2) blok reddedildi ({peer}): {msg}");
                            self.mark_bad_peer(peer, handle);
                            self.continue_catch_up(handle);
                            return;
                        }
                    }
                }
                self.continue_catch_up(handle);
            }
            Sync2Response::NotAvailable => {
                tracing::warn!(
                    "⚠️ sync/2: {peer} istenen araliga sahip degil (budanmis?) — baska peer"
                );
                self.mark_bad_peer(peer, handle);
                self.continue_catch_up(handle);
            }
            Sync2Response::Status(st) => {
                self.peer_tips.insert(peer, st.tip_height);
            }
        }
    }

    /// Tek bloğu doğrular ve uygular. Doğrulama hatası → Err (peer cezası);
    /// yeniden yürütme kök uyuşmazlığı → INV-P3, FATAL (panic).
    fn apply_synced_block(&mut self, block: &crate::messages::Sync2Block) -> Result<()> {
        self.apply_synced_block_with_missing(block, &[])
    }

    fn apply_synced_block_with_missing(
        &mut self,
        block: &crate::messages::Sync2Block,
        missing: &[(u32, zagros_types::Hash)],
    ) -> Result<()> {
        let (_, _, set) = sync2::load_chain_context(self.state.as_ref())?;
        let tip = self.engine.tip().clone();
        let tip_set = self.tip_set_for_sync()?;
        let ctx = SyncContext {
            domain: &self.domain,
            params: &self.params,
            set: &set,
            tip_set: &tip_set,
            tip_height: tip.height,
            tip_hash: tip.hash,
            tip_timestamp_ms: tip.timestamp_ms,
            now_ms: now_ms(),
            checkpoint: self.checkpoint.as_ref(),
        };
        if let Err(e) = sync2::validate_block_with_missing(&ctx, block, missing) {
            let msg = format!("{e:?}");
            if msg.contains("CHECKPOINT") {
                panic!("🛑 {msg} - node durduruluyor");
            }
            return Err(e);
        }
        // Yeniden yürütme kök eşitliği ÖNCE yan etkisiz simülasyonla (overlay):
        // uyuşmazlık = peer gövdeyi değiştirmiş (tx_root yalnız tx_id'leri
        // bağlar) → peer hatası (FM-Y1), state'e hiçbir şey yazılmaz, halt yok.
        let hdr = &block.signed.header;
        let simulated = self.runtime.simulate_block(
            hdr.number,
            (hdr.timestamp_ms / 1000) as u128,
            &block.transactions,
            &block.bridge_proposals,
            hdr.last_qc.as_ref(),
            &block.shadow_votes,
            Some((hdr.epoch, hdr.proposer_idx, hdr.max_ruleset)),
        )?;
        if simulated != hdr.state_root {
            if let Some(m) = &self.metrics {
                zagros_metrics::NodeMetrics::incr(&m.state_root_mismatch_total);
            }
            return Err(ZagrosError::Other(format!(
                "sync2 blok #{}: yeniden yurutme koku 0x{} != baslik 0x{} (peer govdesi guvenilmez)",
                hdr.number,
                hex_prefix(&simulated),
                hex_prefix(&hdr.state_root)
            )));
        }
        let full_ids = if missing.is_empty() {
            None
        } else {
            sync2::merged_tx_ids(&block.transactions, missing)
        };
        self.persist_and_commit_archiving(
            &block.signed,
            &block.qc,
            &block.transactions,
            &block.bridge_proposals,
            &block.shadow_votes,
            full_ids.as_deref(),
        );
        // Motor tip'ini ilerlet (tam yeniden kurulum catch-up sonunda).
        self.engine_tip_advance(&block.signed, &block.qc);
        Ok(())
    }

    /// `validate_block`ın `tip.qc`yi doğrulayacağı küme: tip'in kesinleştiği
    /// epoch'unki (`build_engine` ilkesi; güncel küme catch-up'ta ileride olabilir).
    fn tip_set_for_sync(&self) -> Result<ActiveValidatorSet> {
        match &self.engine.tip().qc {
            Some(qc) => validator_set::load_validator_set_at_epoch(self.state.as_ref(), qc.epoch),
            None => Ok(self.engine.validator_set().clone()),
        }
    }

    /// Catch-up sırasında motorun tip'ini geçici olarak ilerletmek için motoru
    /// state'ten yeniden kurar (ucuz: yalnız tip + küme okuması).
    fn engine_tip_advance(&mut self, _signed: &SignedHeader, _qc: &QuorumCertificate) {
        match Self::build_engine(
            self.state.as_ref(),
            self.runtime.as_ref(),
            self.keypair.as_ref(),
            self.double_sign_state.as_deref(),
        ) {
            Ok((engine, _, _)) => self.engine = engine,
            Err(e) => panic!("🛑 catch-up sonrasi motor kurulamadi - node durduruluyor: {e:?}"),
        }
    }

    fn finish_catch_up(&mut self, handle: &NetworkHandle) {
        self.catch_up = None;
        self.pending_qc_since = None;
        match Self::build_engine(
            self.state.as_ref(),
            self.runtime.as_ref(),
            self.keypair.as_ref(),
            self.double_sign_state.as_deref(),
        ) {
            Ok((engine, _, _)) => self.engine = engine,
            Err(e) => {
                panic!("🛑 catch-up sonrasi motor yeniden kurulamadi - node durduruluyor: {e:?}")
            }
        }
        self.refresh_probation_view();
        // 🛡️ `run()`'daki aynı kural: gerçek tip zaman damgasını
        // kullan, `now_ms()` değil (bkz. oradaki doc yorumu).
        self.last_commit_at_ms = self.engine.tip().timestamp_ms;
        tracing::info!(
            "✅ catch-up bitti: motor h={} ile yeniden basladi",
            self.engine.height()
        );
        let outs = self.engine.start(now_ms(), &self.verifier);
        self.apply_outputs(outs, handle);
    }

    // ---- öneri / commit ----

    fn leader_idle_tick(&mut self, now: u64) -> Vec<Output> {
        if !self.engine.is_proposer() || self.engine.step() != Step::Propose {
            return Vec::new();
        }
        self.try_propose_or_heartbeat(now)
    }

    fn idle_block_due(&self, now: u64) -> bool {
        now >= self
            .last_commit_at_ms
            .saturating_add(self.params.idle_block_interval_s.saturating_mul(1000))
    }

    fn try_propose_or_heartbeat(&mut self, now: u64) -> Vec<Output> {
        // 🚨 CANLILIK: zamanlayıcı boşta blok dalında da kurulur; yoksa lider
        // bir daha uyanmaz, döngü 1 saat uyur (mempool sürücüye haber vermez),
        // kullanıcı işlemi bekler (blok 1 sonrası 20 dk sessizlik yaşandı).
        self.next_heartbeat_at = Some(now.saturating_add((self.params.t_base_ms / 2).max(50)));
        let txs = self.mempool.get_transactions_for_block_bounded(
            MAX_BLOCK_TX_LIMIT,
            MAX_HEAVY_PER_BLOCK,
            self.params.max_block_bytes,
        );
        // Mint filtresi YOK: öneri payload'da taşındığından her üretici bloğa
        // koyabilir; filtre olsaydı kullanıcı 40 dakikaya kadar boşuna beklerdi.
        if txs.is_empty() && !self.idle_block_due(now) {
            return match self.engine.heartbeat(now) {
                Ok(o) => o,
                Err(e) => {
                    tracing::debug!("heartbeat gonderilemedi: {e:?}");
                    Vec::new()
                }
            };
        }
        let bridge_proposals =
            BridgeManager::collect_proposals_for_relay(self.state.as_ref(), &txs);
        let shadow_votes: Vec<ShadowVoteAttestation> =
            self.shadow_vote_pool.values().cloned().collect();
        match self
            .engine
            .propose(now, txs, bridge_proposals, shadow_votes, &self.verifier)
        {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!("⚠️ oneri olusturulamadi: {e:?}");
                Vec::new()
            }
        }
    }

    fn apply_outputs(&mut self, outs: Vec<Output>, handle: &NetworkHandle) {
        let mut pending = outs;
        while !pending.is_empty() {
            let mut next = Vec::new();
            for out in pending {
                match out {
                    Output::Broadcast(msg) => handle.publish_consensus(
                        &self.domain,
                        self.engine.validator_set().epoch,
                        msg,
                    ),
                    Output::NeedProposal { .. } => {
                        let now = now_ms();
                        next.extend(self.try_propose_or_heartbeat(now));
                    }
                    Output::Commit(block) => {
                        next.extend(self.commit(*block));
                    }
                    Output::Evidence(ev) => self.record_evidence(&ev),
                    Output::ViewChange {
                        height,
                        from_round,
                        to_round,
                        reason,
                    } => {
                        tracing::warn!(
                            "🔁 View change h={height} r{from_round}→r{to_round} ({reason:?})"
                        );
                    }
                    Output::Dropped(reason) => {
                        tracing::debug!("konsensus mesaji dusuruldu: {reason}")
                    }
                }
            }
            pending = next;
        }
    }

    /// Konsensüs kayıtları + `Runtime::commit_block` (tek atomik flush) +
    /// mempool temizliği. Hata = FATAL (INV-P3 / disk).
    fn persist_and_commit(
        &mut self,
        signed: &SignedHeader,
        qc: &QuorumCertificate,
        txs: &[Transaction],
        bridge: &[BridgeProposal],
        shadow_votes: &[ShadowVoteAttestation],
    ) {
        self.persist_and_commit_archiving(signed, qc, txs, bridge, shadow_votes, None)
    }

    /// `persist_and_commit` + arşiv `tx_hashes` (eksik gövdeli sync2 bloğu için TAM liste).
    fn persist_and_commit_archiving(
        &mut self,
        signed: &SignedHeader,
        qc: &QuorumCertificate,
        txs: &[Transaction],
        bridge: &[BridgeProposal],
        shadow_votes: &[ShadowVoteAttestation],
        archived_tx_hashes: Option<&[zagros_types::Hash]>,
    ) {
        let header = &signed.header;
        if let Err(e) = store_consensus_records(self.state.as_ref(), signed, qc, shadow_votes) {
            panic!("🛑 konsensus kaydi yazilamadi - node durduruluyor: {e:?}");
        }
        if let Err(e) = self.runtime.commit_block_archiving(
            header.number,
            (header.timestamp_ms / 1000) as u128,
            txs,
            bridge,
            header.last_qc.as_ref(),
            shadow_votes,
            Some((header.epoch, header.proposer_idx, header.max_ruleset)),
            header.state_root,
            archived_tx_hashes,
        ) {
            panic!(
                "🛑 Blok #{} commit REDDEDILDI (state_root uyusmazligi / yurutme hatasi, INV-P3) - node durduruluyor: {e:?}",
                header.number
            );
        }
        for tx in txs {
            self.mempool.remove_transaction(&tx.tx_id);
        }
        // 🧹 Bu bloktaki göndericilerin tüketilmiş nonce'lu bekleyenleri süpürülür;
        // yoksa adres sayacı şişip göndericiyi kilitliyordu.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut purged = 0usize;
        for tx in txs {
            let key = tx.sender.to_ascii_lowercase();
            if !seen.insert(key.clone()) {
                continue;
            }
            let state_nonce = self.state.get_nonce(&tx.sender).unwrap_or(0);
            purged += self.mempool.purge_below_nonce(&tx.sender, state_nonce);
        }
        if purged > 0 {
            tracing::info!(
                "🧹 commit h={}: {} bayat bekleyen işlem süpürüldü",
                header.number,
                purged
            );
        }
        self.last_commit_at_ms = now_ms();
        // 🚨 Commit'ten sonra zamanlayici SIFIRLANMAZ, yeniden kurulur. `None`
        // birakmak liderin bir daha uyanmamasina ve zincirin durmasina yol
        // aciyordu (yukaridaki nota bak).
        self.next_heartbeat_at = Some(
            self.last_commit_at_ms
                .saturating_add((self.params.t_base_ms / 2).max(50)),
        );
        tracing::info!(
            "✅ commit h={} r={} tx={} imzaci={} kok=0x{}",
            header.number,
            qc.round,
            txs.len(),
            qc.signer_indices().len(),
            hex_prefix(&header.state_root)
        );
    }

    fn commit(&mut self, block: zagros_consensus::engine::CommittedBlock) -> Vec<Output> {
        self.persist_and_commit(
            &block.proposal.signed,
            &block.qc,
            &block.proposal.txs,
            &block.proposal.bridge_proposals,
            &block.proposal.shadow_votes,
        );
        // G8: küme/epoch değişimi `advance_epoch_if_due`dan gelebilir; motor HER
        // commit'te state'ten tam yeniden kurulur, gözlemci→validator terfisi de
        // (`self.keypair`den) doğru ele alınır.
        match Self::build_engine(
            self.state.as_ref(),
            self.runtime.as_ref(),
            self.keypair.as_ref(),
            self.double_sign_state.as_deref(),
        ) {
            Ok((engine, _, _)) => self.engine = engine,
            Err(e) => {
                panic!("🛑 commit sonrasi motor yeniden kurulamadi - node durduruluyor: {e:?}")
            }
        }
        self.refresh_probation_view();
        // ⏱️ ÖLÇÜM: QC'nin kapandığı an + imzacılar → kapı, sonradan
        // gelen precommit'lerin gecikmesini ölçer (grace_ms kararı için veri).
        {
            let formed = now_ms();
            let signers = block.qc.signer_indices();
            let members: Vec<String> = self
                .engine
                .validator_set()
                .members
                .iter()
                .map(|m| m.address.clone())
                .collect();
            let close = match block.qc_close {
                zagros_consensus::engine::QcClose::Immediate => "immediate",
                zagros_consensus::engine::QcClose::Full => "full",
                zagros_consensus::engine::QcClose::GraceExpired => "grace_expired",
                zagros_consensus::engine::QcClose::Clamped => "clamped",
            };
            zagros_metrics::record_qc_formed(&members, &signers, formed);
            zagros_metrics::record_qc_close(close, self.engine.qc_grace_ms());
            if let Ok(mut v) = self.gate_view.write() {
                v.last_qc = Some(crate::consensus_wire::LastQc {
                    height: block.qc.height,
                    round: block.qc.round,
                    block_hash: block.qc.block_hash,
                    formed_at_ms: formed,
                    signers,
                });
            }
        }
        self.prune_shadow_vote_pool();
        let mut out = self.engine.start(now_ms(), &self.verifier);
        out.extend(
            self.emit_shadow_vote_if_probation(&block.proposal.signed.header, block.qc.round),
        );
        out
    }

    /// G8: tek sınırlı taramayla Probation üyeleri (adres, pubkey, hesap).
    fn scan_probation(state: &dyn State) -> Result<Vec<(Address, [u8; 32], Address)>> {
        let accounts = validator_set::registered_validator_accounts(state)?;
        Ok(accounts
            .into_iter()
            .filter(|(_, acc)| {
                acc.validator_status == Some(zagros_types::consensus::ValidatorStatus::Probation)
            })
            .map(|(addr, acc)| (addr.clone(), acc.consensus_pubkey, addr))
            .collect())
    }

    /// `gate_view.probation`ı ve `probation_identity`yi tazeler (ShadowVote `State`siz doğrulansın).
    fn refresh_probation_view(&mut self) {
        let scanned = Self::scan_probation(self.state.as_ref()).unwrap_or_default();
        self.probation_identity = self.keypair.as_ref().and_then(|kp| {
            let pk = kp.public_key();
            scanned
                .iter()
                .find(|(_, cpk, _)| *cpk == pk)
                .map(|(addr, _, _)| addr.clone())
        });
        if let Ok(mut v) = self.gate_view.write() {
            v.set = self.engine.validator_set().clone();
            v.height = self.engine.height();
            v.probation = scanned.into_iter().map(|(a, pk, _)| (a, pk)).collect();
        }
    }

    /// Şu an Probation isek, az önce kesinleşen `header`'ı (height, round)
    /// için imzalı bir ShadowVote üretip hem YAYINLAR hem KENDİ havuzumuza
    /// (bir sonraki öneriye gömülsün diye) ekler.
    fn emit_shadow_vote_if_probation(
        &mut self,
        header: &zagros_types::consensus::BlockHeaderV2,
        round: u32,
    ) -> Vec<Output> {
        let (Some(address), Some(kp)) = (self.probation_identity.clone(), self.keypair.as_ref())
        else {
            return Vec::new();
        };
        let mut vote = Vote {
            height: header.number,
            round,
            phase: VotePhase::Prevote,
            block_hash: header.hash(),
            validator_idx: 0, // Probation icin anlamsiz; ShadowVote adres ile kimliklenir
            shadow: true,
            sig: Vec::new(),
        };
        sign_vote(
            kp,
            &self.domain,
            self.engine.validator_set().epoch,
            &mut vote,
        );
        let attestation = ShadowVoteAttestation { address, vote };
        self.ingest_shadow_vote(attestation.clone());
        vec![Output::Broadcast(Message::ShadowVote(attestation))]
    }

    fn ingest_shadow_vote(&mut self, sv: ShadowVoteAttestation) {
        let tip_height = self.engine.tip().height;
        if sv.vote.height <= tip_height.saturating_sub(4.min(tip_height)) {
            return; // zaten kesinlesmis/cok eski - havuza almaya gerek yok
        }
        let key = (
            sv.address.to_ascii_lowercase(),
            sv.vote.height,
            sv.vote.round,
        );
        self.shadow_vote_pool.entry(key).or_insert(sv);
    }

    fn prune_shadow_vote_pool(&mut self) {
        let tip_height = self.engine.tip().height;
        self.shadow_vote_pool.retain(|(_, h, _), _| *h > tip_height);
    }
}

fn hex_prefix(h: &[u8; 32]) -> String {
    h.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod evidence_log_tests {
    use super::*;
    use zagros_types::consensus::{Evidence, Vote, VotePhase};

    fn vote(hash: u8) -> Vote {
        Vote {
            height: 42,
            round: 3,
            phase: VotePhase::Precommit,
            block_hash: [hash; 32],
            validator_idx: 2,
            shadow: false,
            sig: vec![7u8; 64],
        }
    }

    /// 🚨 Log satırındaki `payload_hex` gerçek `EquivocationReport` olarak çözülmeli;
    /// bozuksa ceza uygulanamaz.
    #[test]
    fn evidence_line_carries_a_directly_usable_report_payload() {
        let ev = Evidence::DoubleVote {
            a: vote(1),
            b: vote(2),
        };
        let line = evidence_log_line(&ev, "0x00000000000000000000000000000000000000ab", 1_700);

        assert!(line.ends_with('\n'), "JSONL satiri yeni satirla bitmeli");
        assert!(line.contains("\"height\":42"));
        assert!(line.contains("\"validator_idx\":2"));
        assert!(line.contains("\"tx_type\":\"ReportMalicious\""));
        assert!(
            line.contains("\"receiver\":\"0x00000000000000000000000000000000000000ab\""),
            "alici, suclanan validator adresi olmali: {line}"
        );

        let hex_part = line
            .split("\"payload_hex\":\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .expect("payload_hex alani");
        let bytes = hex::decode(hex_part).expect("payload gecerli hex olmali");
        match zagros_types::EquivocationReport::from_bytes(&bytes).expect("payload cozulmeli") {
            zagros_types::EquivocationReport::ConsensusEvidence(back) => {
                assert_eq!(back.height(), 42);
                assert_eq!(back.validator_idx(), 2);
                assert!(matches!(back, Evidence::DoubleVote { .. }));
            }
            zagros_types::EquivocationReport::Legacy(_) => {
                panic!("legacy yol kapali - ConsensusEvidence bekleniyordu")
            }
        }
    }
}
